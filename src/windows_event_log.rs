//! Windows Event Log streaming via `wevtutil`.
//!
//! This mirrors the existing journald fallback shape: spawn the platform CLI,
//! parse resume metadata, enqueue each event before advancing the checkpoint.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event as XmlEvent;
use quick_xml::reader::Reader;
use serde_json::{Map, Value, json};
use tokio::process::Command;
use tokio::sync::{Semaphore, watch};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use crate::config::MultilineConfig;
use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::{StreamingEmit, StreamingEntryAssembler};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const QUERY_LIMIT: usize = 100;
const CHECKPOINT_INTERVAL: u64 = 100;

/// Bounds concurrent `wevtutil` sample spawns. Each call is a process spawn plus
/// a render — the discovery cost center — so sampling many channels never
/// fans out into an unbounded pile of `wevtutil` processes.
static WEVTUTIL_SAMPLE_SEM: Semaphore = Semaphore::const_new(4);

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventLogRecord {
    record_id: u64,
    json: Vec<u8>,
}

/// Stream Windows Event Log records into the streaming pipeline actor.
///
/// Resume semantics are exact by EventRecordID. With no checkpoint we start at
/// the current tail so enabling a source does not backfill the whole channel.
pub async fn stream_event_log(
    handle: &StreamHandle,
    channel: &str,
    source_id: &str,
    resume_record_id: Option<u64>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let started_from_tail = resume_record_id.is_none();
    let mut last_record_id = match resume_record_id {
        Some(record_id) => {
            info!(
                channel,
                source_id, record_id, "resuming Windows Event Log stream"
            );
            record_id
        }
        None => {
            let tail = latest_record_id(channel).await.unwrap_or(0);
            info!(
                channel,
                source_id,
                record_id = tail,
                "starting Windows Event Log stream from tail"
            );
            tail
        }
    };

    if started_from_tail
        && !handle
            .set_checkpoint(StreamingCheckpoint::windows_event_log(
                source_id,
                channel,
                last_record_id,
            ))
            .await
    {
        warn!(
            channel,
            source_id, "streaming pipeline actor gone, stopping Windows Event Log stream"
        );
        return;
    }

    let mut assembler = match StreamingEntryAssembler::new(multiline) {
        Ok(assembler) => assembler,
        Err(error) => {
            warn!(channel, source_id, error = %error, "invalid Windows Event Log multiline pattern");
            return;
        }
    };
    let mut assembler_tick = tokio::time::interval(POLL_INTERVAL);
    assembler_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    assembler_tick.tick().await;

    let mut entries_processed = 0u64;
    let mut last_checkpoint = Some(StreamingCheckpoint::windows_event_log(
        source_id,
        channel,
        last_record_id,
    ));

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!(channel, source_id, "Windows Event Log stream shutdown signal");
                break;
            }
            _ = assembler_tick.tick() => {
                match assembler.check_timeout(handle).await {
                    Ok(emit) => {
                        if !record_emit(
                            handle,
                            channel,
                            source_id,
                            &mut entries_processed,
                            &mut last_checkpoint,
                            &mut last_record_id,
                            emit,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(_) => {
                        warn!(channel, "streaming pipeline actor gone, stopping Windows Event Log stream");
                        return;
                    }
                }
            }
            _ = tokio::time::sleep(POLL_INTERVAL) => {
                let records = match query_records_after(channel, last_record_id, QUERY_LIMIT).await {
                    Ok(records) => records,
                    Err(error) => {
                        warn!(channel, source_id, error = %error, "Windows Event Log query failed");
                        continue;
                    }
                };

                for record in records {
                    let now_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as i64;

                    let checkpoint = StreamingCheckpoint::windows_event_log(
                        source_id,
                        channel,
                        record.record_id,
                    );

                    match assembler
                        .process_line(handle, record.json, now_ns, Some(checkpoint))
                        .await
                    {
                        Ok(emit) => {
                            last_record_id = last_record_id.max(record.record_id);
                            if !record_emit(
                                handle,
                                channel,
                                source_id,
                                &mut entries_processed,
                                &mut last_checkpoint,
                                &mut last_record_id,
                                emit,
                            )
                            .await
                            {
                                return;
                            }
                        }
                        Err(_) => {
                            warn!(channel, "streaming pipeline actor gone, stopping Windows Event Log stream");
                            if let Some(checkpoint) = last_checkpoint {
                                handle.set_final_checkpoint(checkpoint).await;
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    match assembler.flush(handle).await {
        Ok(emit) => {
            if !record_emit(
                handle,
                channel,
                source_id,
                &mut entries_processed,
                &mut last_checkpoint,
                &mut last_record_id,
                emit,
            )
            .await
            {
                return;
            }
        }
        Err(_) => {
            warn!(
                channel,
                "streaming pipeline actor gone, stopping Windows Event Log stream"
            );
            return;
        }
    }

    if let Some(checkpoint) = last_checkpoint {
        handle.set_final_checkpoint(checkpoint).await;
    }

    info!(
        channel,
        source_id,
        total_entries = entries_processed,
        "Windows Event Log streaming stopped"
    );
}

async fn record_emit(
    handle: &StreamHandle,
    channel: &str,
    source_id: &str,
    entries_processed: &mut u64,
    last_checkpoint: &mut Option<StreamingCheckpoint>,
    last_record_id: &mut u64,
    emit: Option<StreamingEmit>,
) -> bool {
    let Some(emit) = emit else {
        return true;
    };

    *entries_processed += 1;

    if let Some(checkpoint) = emit.checkpoint {
        if let Some(record_id) = checkpoint.windows_event_record_id(channel) {
            *last_record_id = (*last_record_id).max(record_id);
        }
        *last_checkpoint = Some(checkpoint);
    }

    if entries_processed.is_multiple_of(CHECKPOINT_INTERVAL) {
        if let Some(checkpoint) = last_checkpoint.clone()
            && !handle.set_checkpoint(checkpoint).await
        {
            warn!(
                channel,
                "streaming pipeline actor gone, stopping Windows Event Log stream"
            );
            return false;
        }
        debug!(
            channel,
            source_id,
            entries = *entries_processed,
            record_id = *last_record_id,
            "Windows Event Log stream progress"
        );
    }

    true
}

/// Sample up to `max_lines` events from a channel for Rails discovery + the
/// review queue, newest-first, as JSON.
///
/// Event Logs are structured records, never free text, so a sample is the same
/// flat-JSON shape the streaming collection ships (`query_records` below) — the
/// screener previews exactly what will be collected. Whether a JSON source needs
/// schema analysis at all is a control-plane decision, not the agent's.
pub async fn sample_channel_lines(channel: &str, max_lines: usize) -> Result<Vec<String>, String> {
    // wevtutil is a heavy per-call spawn; cap how many run at once.
    let _permit = WEVTUTIL_SAMPLE_SEM
        .acquire()
        .await
        .map_err(|_| "wevtutil sample semaphore closed".to_string())?;

    let limit = max_lines.clamp(1, QUERY_LIMIT);
    let records = query_records(channel, None, limit, true).await?;
    let lines: Vec<String> = records
        .iter()
        .take(max_lines)
        .map(|record| String::from_utf8_lossy(&record.json).into_owned())
        .collect();
    Ok(lines)
}

async fn latest_record_id(channel: &str) -> Result<u64, String> {
    let records = query_records(channel, None, 1, true).await?;
    Ok(records.first().map(|record| record.record_id).unwrap_or(0))
}

async fn query_records_after(
    channel: &str,
    record_id: u64,
    limit: usize,
) -> Result<Vec<EventLogRecord>, String> {
    query_records(channel, Some(record_id), limit, false).await
}

async fn query_records(
    channel: &str,
    after_record_id: Option<u64>,
    limit: usize,
    newest_first: bool,
) -> Result<Vec<EventLogRecord>, String> {
    let mut args = vec!["qe".to_string(), channel.to_string(), format!("/c:{limit}")];

    if let Some(record_id) = after_record_id {
        args.push(format!("/q:*[System[(EventRecordID>{record_id})]]"));
    }

    args.push(
        if newest_first {
            "/rd:true"
        } else {
            "/rd:false"
        }
        .to_string(),
    );
    args.push("/f:xml".to_string());

    let output = Command::new("wevtutil")
        .args(&args)
        .output()
        .await
        .map_err(|error| format!("wevtutil spawn failed for {channel}: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "wevtutil exit {} for {channel}: {stderr}",
            output.status
        ));
    }

    Ok(parse_event_xml_batch(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_event_xml_batch(xml: &str) -> Vec<EventLogRecord> {
    let mut records = Vec::new();
    let mut rest = xml;

    while let Some(start) = rest.find("<Event ") {
        rest = &rest[start..];
        let Some(end) = rest.find("</Event>") else {
            break;
        };
        let event_xml = &rest[..end + "</Event>".len()];
        if let Some(record) = event_to_record(event_xml) {
            records.push(record);
        }
        rest = &rest[end + "</Event>".len()..];
    }

    records
}

/// Parse one `<Event>…</Event>` blob into a structured JSON object.
///
/// Returns `None` when the event carries no EventRecordID — the field is the
/// resume anchor for the wevtutil checkpoint, so an event we cannot resume past
/// is dropped rather than enqueued.
///
/// `wevtutil /f:xml` emits the raw event schema only; the rendered, localized
/// Message is not present (it needs EvtFormatMessage against a provider DLL) and
/// is deliberately out of scope here.
fn event_to_record(event_xml: &str) -> Option<EventLogRecord> {
    let parsed = parse_event(event_xml)?;
    let record_id = parsed
        .get("EventRecordID")
        .and_then(Value::as_str)
        .and_then(|value| value.trim().parse().ok())?;
    let json = serde_json::to_vec(&parsed).ok()?;
    Some(EventLogRecord { record_id, json })
}

/// Map the Windows Event XML schema to a flat JSON object.
///
/// `<System>` carries the well-known envelope fields (most as element text, but
/// `Provider`/`TimeCreated` hold their value in an attribute). `<EventData>`
/// contributes a `EventData` object of `Name`-keyed `<Data>` values plus an
/// `EventDataUnnamed` array for positional `<Data>` entries.
fn parse_event(event_xml: &str) -> Option<Value> {
    // No `trim_text`: we only buffer character content inside leaf elements
    // (System fields, <Data>), which have no child elements and thus no
    // inter-element indentation to strip — and trimming would corrupt EventData
    // values that carry meaningful surrounding whitespace. Whitespace between
    // elements arrives while no field is active and is ignored.
    let mut reader = Reader::from_str(event_xml);

    let mut object = Map::new();
    let mut event_data = Map::new();
    let mut event_data_unnamed: Vec<Value> = Vec::new();
    let mut in_event_data = false;

    // The element whose character content we are accumulating, and the buffer it
    // collects into. quick-xml emits an element's content as several events — one
    // `Text` per literal run plus a `GeneralRef` per entity (`&amp;` etc.) — so we
    // gather them all and commit the joined value on the matching `End`.
    let mut field: Option<Field> = None;
    let mut buffer = String::new();

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Start(element)) => {
                let name = local_name(element.name().as_ref());
                match name.as_str() {
                    // Provider/TimeCreated carry their value in an attribute, not
                    // in text. They usually arrive self-closing (Empty), but a
                    // non-self-closing form is handled the same way here.
                    "Provider" | "TimeCreated" => {
                        capture_attribute(&mut object, &reader, &element, &name)
                    }
                    "EventID" | "Level" | "Computer" | "Channel" | "EventRecordID" => {
                        field = Some(Field::System(name));
                        buffer.clear();
                    }
                    "EventData" => in_event_data = true,
                    "Data" if in_event_data => {
                        field = Some(Field::Data(attribute(&reader, &element, b"Name")));
                        buffer.clear();
                    }
                    _ => {}
                }
            }
            // Self-closing Provider/TimeCreated arrive as Empty; their values live
            // in attributes (Provider Name=…, TimeCreated SystemTime=…).
            Ok(XmlEvent::Empty(element)) => {
                let name = local_name(element.name().as_ref());
                if matches!(name.as_str(), "Provider" | "TimeCreated") {
                    capture_attribute(&mut object, &reader, &element, &name);
                }
            }
            Ok(XmlEvent::Text(text)) if field.is_some() => {
                buffer.push_str(&decode_text(&text));
            }
            // An entity reference inside content (e.g. &amp;, &lt;, &#65;) is its
            // own event in quick-xml; resolve it back into the value buffer.
            Ok(XmlEvent::GeneralRef(reference)) => {
                if field.is_some()
                    && let Ok(name) = reference.decode()
                {
                    if let Some(resolved) = resolve_predefined_entity(&name) {
                        buffer.push_str(resolved);
                    } else if let Ok(Some(ch)) = reference.resolve_char_ref() {
                        buffer.push(ch);
                    }
                }
            }
            Ok(XmlEvent::End(element)) => {
                let name = local_name(element.name().as_ref());
                if name == "EventData" {
                    in_event_data = false;
                } else if let Some(field) = field.take() {
                    let value = Value::String(std::mem::take(&mut buffer));
                    match field {
                        Field::System(key) => {
                            object.insert(key, value);
                        }
                        Field::Data(Some(key)) => {
                            event_data.insert(key, value);
                        }
                        Field::Data(None) => event_data_unnamed.push(value),
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(error) => {
                // Drop the malformed event but say so — a silently missing event
                // during a pilot is a "why is this gone?" mystery otherwise.
                warn!(error = %error, "skipping unparseable Windows Event Log XML");
                return None;
            }
            _ => {}
        }
    }

    if !event_data.is_empty() {
        object.insert("EventData".to_string(), Value::Object(event_data));
    }
    if !event_data_unnamed.is_empty() {
        object.insert("EventDataUnnamed".to_string(), json!(event_data_unnamed));
    }

    Some(Value::Object(object))
}

/// The destination for the character content currently being accumulated.
enum Field {
    /// A `<System>` envelope field, keyed by element name (e.g. "EventID").
    System(String),
    /// An `<EventData>` `<Data>` entry: `Some(name)` keyed, `None` positional.
    Data(Option<String>),
}

/// Insert the value-bearing attribute of an attribute-only `<System>` element
/// (`Provider Name=…`, `TimeCreated SystemTime=…`) into the JSON object under the
/// element's own name.
fn capture_attribute(
    object: &mut Map<String, Value>,
    reader: &Reader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
    name: &str,
) {
    let key = match name {
        "Provider" => b"Name".as_slice(),
        "TimeCreated" => b"SystemTime".as_slice(),
        _ => return,
    };
    if let Some(value) = attribute(reader, element, key) {
        object.insert(name.to_string(), Value::String(value));
    }
}

/// Strip any XML namespace prefix, returning the local element name.
fn local_name(raw: &[u8]) -> String {
    let name = raw.rsplit(|byte| *byte == b':').next().unwrap_or(raw);
    String::from_utf8_lossy(name).into_owned()
}

/// Decode a literal text run: bytes -> str with XML 1.0 EOL normalization. Entity
/// references are delivered separately as `GeneralRef` events, so a `Text` run
/// never carries an unresolved entity of its own.
fn decode_text(text: &quick_xml::events::BytesText<'_>) -> String {
    text.xml10_content().unwrap_or_default().into_owned()
}

fn attribute(
    reader: &Reader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
    key: &[u8],
) -> Option<String> {
    element.attributes().flatten().find_map(|attr| {
        (attr.key.as_ref() == key)
            .then(|| {
                attr.decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                    .ok()
            })
            .flatten()
            .map(|value| value.into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_json(record: &EventLogRecord) -> Value {
        serde_json::from_slice(&record.json).expect("record JSON is valid")
    }

    #[test]
    fn parses_concatenated_wevtutil_xml_events() {
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><EventRecordID>41</EventRecordID><Channel>Application</Channel></System><EventData><Data>one</Data></EventData></Event>\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>2</EventID><EventRecordID>42</EventRecordID><Channel>Application</Channel></System><EventData><Data>two</Data></EventData></Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 2);

        let first = parsed_json(&records[0]);
        assert_eq!(records[0].record_id, 41);
        assert_eq!(first["EventID"], "1");
        assert_eq!(first["Channel"], "Application");
        assert_eq!(first["EventDataUnnamed"], json!(["one"]));

        let second = parsed_json(&records[1]);
        assert_eq!(records[1].record_id, 42);
        assert_eq!(second["EventID"], "2");
        assert_eq!(second["EventDataUnnamed"], json!(["two"]));
    }

    #[test]
    fn skips_events_without_record_id() {
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID></System></Event>\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventRecordID>9</EventRecordID></System></Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, 9);
    }

    #[test]
    fn maps_system_envelope_and_named_event_data() {
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
<System>\
<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>\
<EventID>4624</EventID>\
<Level>0</Level>\
<TimeCreated SystemTime='2026-06-29T10:00:00.000000000Z'/>\
<EventRecordID>9876</EventRecordID>\
<Channel>Security</Channel>\
<Computer>DESKTOP-ABC</Computer>\
</System>\
<EventData>\
<Data Name='SubjectUserName'>SYSTEM</Data>\
<Data Name='TargetUserName'>alice</Data>\
<Data>positional</Data>\
</EventData>\
</Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, 9876);

        let event = parsed_json(&records[0]);
        assert_eq!(event["Provider"], "Microsoft-Windows-Security-Auditing");
        assert_eq!(event["EventID"], "4624");
        assert_eq!(event["Level"], "0");
        assert_eq!(event["TimeCreated"], "2026-06-29T10:00:00.000000000Z");
        assert_eq!(event["EventRecordID"], "9876");
        assert_eq!(event["Channel"], "Security");
        assert_eq!(event["Computer"], "DESKTOP-ABC");
        assert_eq!(event["EventData"]["SubjectUserName"], "SYSTEM");
        assert_eq!(event["EventData"]["TargetUserName"], "alice");
        assert_eq!(event["EventDataUnnamed"], json!(["positional"]));
    }

    #[test]
    fn escapes_special_characters_in_event_data() {
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
<System><EventRecordID>5</EventRecordID></System>\
<EventData><Data Name='Path'>C:\\Temp &amp; &lt;logs&gt;</Data></EventData>\
</Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 1);
        let event = parsed_json(&records[0]);
        assert_eq!(event["EventData"]["Path"], "C:\\Temp & <logs>");
    }

    #[test]
    fn resolves_numeric_character_references() {
        // Decimal &#65; and hex &#x41; both denote 'A'; the value also mixes
        // literal text with the references to exercise multi-segment buffering.
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
<System><EventRecordID>7</EventRecordID></System>\
<EventData><Data Name='Code'>x&#65;y&#x41;z</Data></EventData>\
</Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 1);
        let event = parsed_json(&records[0]);
        assert_eq!(event["EventData"]["Code"], "xAyAz");
    }

    #[test]
    fn concatenates_text_split_across_entities() {
        // quick-xml emits this value as several events (Text / GeneralRef / Text);
        // the joined result must preserve every literal segment and its spacing.
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
<System><EventRecordID>8</EventRecordID></System>\
<EventData><Data Name='Msg'>start &amp; middle &lt;end&gt; done</Data></EventData>\
</Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 1);
        let event = parsed_json(&records[0]);
        assert_eq!(event["EventData"]["Msg"], "start & middle <end> done");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn queries_latest_application_record() {
        let latest = latest_record_id("Application").await.unwrap();
        assert!(latest > 0);

        let records = query_records_after("Application", latest.saturating_sub(1), 1)
            .await
            .unwrap();
        assert!(records.iter().all(|record| record.record_id >= latest));
    }
}
