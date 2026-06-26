//! Windows Event Log streaming via `wevtutil`.
//!
//! This mirrors the existing journald fallback shape: spawn the platform CLI,
//! parse resume metadata, enqueue each event before advancing the checkpoint.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::process::Command;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const QUERY_LIMIT: usize = 100;
const CHECKPOINT_INTERVAL: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventLogRecord {
    record_id: u64,
    xml: String,
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

    let mut entries_processed = 0u64;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!(channel, source_id, "Windows Event Log stream shutdown signal");
                break;
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

                    if !handle.enqueue(record.xml.into_bytes(), now_ns).await {
                        warn!(channel, "streaming pipeline actor gone, stopping Windows Event Log stream");
                        handle
                            .set_final_checkpoint(StreamingCheckpoint::windows_event_log(
                                source_id,
                                channel,
                                last_record_id,
                            ))
                            .await;
                        return;
                    }

                    last_record_id = last_record_id.max(record.record_id);
                    entries_processed += 1;

                    if entries_processed.is_multiple_of(CHECKPOINT_INTERVAL) {
                        let _ = handle
                            .set_checkpoint(StreamingCheckpoint::windows_event_log(
                                source_id,
                                channel,
                                last_record_id,
                            ))
                            .await;
                        debug!(
                            channel,
                            source_id,
                            entries = entries_processed,
                            record_id = last_record_id,
                            "Windows Event Log stream progress"
                        );
                    }
                }
            }
        }
    }

    handle
        .set_final_checkpoint(StreamingCheckpoint::windows_event_log(
            source_id,
            channel,
            last_record_id,
        ))
        .await;

    info!(
        channel,
        source_id,
        total_entries = entries_processed,
        "Windows Event Log streaming stopped"
    );
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
        if let Some(record_id) = extract_record_id(event_xml) {
            records.push(EventLogRecord {
                record_id,
                xml: event_xml.to_string(),
            });
        }
        rest = &rest[end + "</Event>".len()..];
    }

    records
}

fn extract_record_id(xml: &str) -> Option<u64> {
    let start = xml.find("<EventRecordID>")? + "<EventRecordID>".len();
    let end = xml[start..].find("</EventRecordID>")? + start;
    xml[start..end].trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_concatenated_wevtutil_xml_events() {
        let xml = "\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><EventRecordID>41</EventRecordID><Channel>Application</Channel></System><EventData><Data>one</Data></EventData></Event>\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>2</EventID><EventRecordID>42</EventRecordID><Channel>Application</Channel></System><EventData><Data>two</Data></EventData></Event>";

        let records = parse_event_xml_batch(xml);

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_id, 41);
        assert!(records[0].xml.contains("<Data>one</Data>"));
        assert_eq!(records[1].record_id, 42);
        assert!(records[1].xml.contains("<Data>two</Data>"));
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
