//! Journald access — sdjournal primary, journalctl fallback.
//!
//! Shared adapter for sampling (`sampler`) and streaming (`journald_stream`).
//! On Linux, reads journal files via `sdjournal` (musl-compatible). Falls back to
//! `journalctl` when sdjournal open/read fails.
//!
//! Both backends funnel every entry through one seam — `normalize_entry` turns a
//! backend's raw `(MESSAGE bytes, realtime µs, cursor)` into a [`StreamEntry`],
//! and `enqueue_stream_entry` / `record_emit` drive it into the pipeline — so the
//! two paths deliver identical message text, timestamps, and checkpoints. The one
//! residual difference is the entry match-set: the native backend matches
//! `_SYSTEMD_UNIT` exactly, while `journalctl -u` also surfaces manager and
//! coredump messages for the unit. `canonical_unit` aligns the queried unit name;
//! the broader `journalctl` match-set is a known, documented divergence.

mod fallback;
mod unit;

#[cfg(target_os = "linux")]
mod native;

use tokio::sync::watch;

use crate::config::MultilineConfig;
use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::{StreamingEmit, StreamingEntryAssembler};

#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::time::MissedTickBehavior;

pub use unit::is_systemd_unit;

/// Checkpoint every N emitted entries. One definition, shared by both backends.
const CHECKPOINT_INTERVAL: u64 = 100;

/// One normalized journal entry. Both backends build this through
/// `normalize_entry`, so message decoding, the blank-line predicate, and the
/// µs→ns timestamp conversion live in exactly one place.
struct StreamEntry {
    message: String,
    cursor: Option<String>,
    timestamp_ns: i64,
}

/// The shared blank-line predicate: an entry whose message is empty or
/// whitespace-only is dropped, on both backends and on both the sample and
/// stream paths.
fn is_blank(message: &str) -> bool {
    message.trim().is_empty()
}

/// Decode raw MESSAGE bytes exactly as the native backend does — lossy UTF-8 —
/// and drop blanks. `None` means "skip this entry".
fn decode_message(message_bytes: &[u8]) -> Option<String> {
    let message = String::from_utf8_lossy(message_bytes).into_owned();
    if is_blank(&message) {
        None
    } else {
        Some(message)
    }
}

/// The normalizer seam: a backend's raw entry fields become a [`StreamEntry`].
/// `None` when MESSAGE is blank after trimming. `realtime_usec` is microseconds
/// since the epoch (systemd's native unit for `__REALTIME_TIMESTAMP` and
/// `realtime_usec()`); it is converted to nanoseconds here so both backends
/// agree bit-for-bit.
fn normalize_entry(
    message_bytes: &[u8],
    realtime_usec: u64,
    cursor: Option<String>,
) -> Option<StreamEntry> {
    let message = decode_message(message_bytes)?;
    Some(StreamEntry {
        message,
        cursor,
        timestamp_ns: (realtime_usec as i64) * 1_000,
    })
}

/// Push one normalized entry through the multiline assembler and into the
/// pipeline. Returns `false` when the pipeline actor is gone and the stream
/// should stop.
async fn enqueue_stream_entry(
    handle: &StreamHandle,
    source_id: &str,
    entries_processed: &mut u64,
    last_cursor: &mut Option<String>,
    assembler: &mut StreamingEntryAssembler,
    entry: StreamEntry,
) -> bool {
    let checkpoint = entry
        .cursor
        .as_deref()
        .map(|cursor| StreamingCheckpoint::journald(source_id, cursor));
    match assembler
        .process_line(
            handle,
            entry.message.into_bytes(),
            entry.timestamp_ns,
            checkpoint,
        )
        .await
    {
        Ok(emit) => record_emit(handle, source_id, entries_processed, last_cursor, emit).await,
        Err(_) => false,
    }
}

/// Advance the emit bookkeeping for one assembled entry: count it, remember its
/// cursor, and periodically persist a checkpoint. Returns `false` when the
/// pipeline actor is gone.
async fn record_emit(
    handle: &StreamHandle,
    source_id: &str,
    entries_processed: &mut u64,
    last_cursor: &mut Option<String>,
    emit: Option<StreamingEmit>,
) -> bool {
    let Some(emit) = emit else {
        return true;
    };

    *entries_processed += 1;

    if let Some(checkpoint) = emit.checkpoint
        && let Some(cursor) = checkpoint.journald_cursor()
    {
        *last_cursor = Some(cursor.to_string());
    }

    if entries_processed.is_multiple_of(CHECKPOINT_INTERVAL)
        && let Some(cursor) = last_cursor.as_deref()
        && !handle
            .set_checkpoint(StreamingCheckpoint::journald(source_id, cursor))
            .await
    {
        return false;
    }
    true
}

/// Read up to `max_lines` of bare log text from a systemd unit.
pub fn sample_unit_lines(unit: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let unit = unit::canonical_unit(unit);
    let unit = unit.as_str();

    #[cfg(target_os = "linux")]
    {
        match native::sample_unit_lines(unit, max_lines) {
            Ok(lines) => return Ok(lines),
            Err(e) => {
                tracing::debug!(unit, error = %e, "sdjournal sample failed, falling back to journalctl");
            }
        }
    }

    fallback::sample_unit_lines(unit, max_lines)
}

/// Stream logs from a systemd unit into the bulletproof delivery pipeline.
pub async fn stream_unit_logs(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    resume_cursor: Option<&str>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let unit = unit::canonical_unit(unit);
    let unit = unit.as_str();

    #[cfg(target_os = "linux")]
    {
        stream_unit_logs_native(handle, unit, source_id, resume_cursor, multiline, shutdown).await;
    }

    #[cfg(not(target_os = "linux"))]
    fallback::stream_unit_logs(handle, unit, source_id, resume_cursor, multiline, shutdown).await;
}

#[cfg(target_os = "linux")]
async fn stream_unit_logs_native(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    resume_cursor: Option<&str>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<StreamEntry, String>>(256);
    let unit_owned = unit.to_string();
    let source_id_owned = source_id.to_string();
    let resume_owned = resume_cursor.map(|s| s.to_string());
    let shutdown_thread = shutdown.clone();

    let mut assembler = match StreamingEntryAssembler::new(multiline) {
        Ok(assembler) => assembler,
        Err(error) => {
            tracing::error!(unit, source_id, error = %error, "invalid journald multiline pattern");
            return;
        }
    };
    let mut assembler_tick = tokio::time::interval(Duration::from_secs(1));
    assembler_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    assembler_tick.tick().await;

    let reader = std::thread::spawn(move || {
        native::stream_unit_blocking(&unit_owned, resume_owned.as_deref(), tx, shutdown_thread);
    });

    let mut entries_processed: u64 = 0;
    let mut last_cursor: Option<String> = None;
    let mut use_fallback = false;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            _ = assembler_tick.tick() => {
                match assembler.check_timeout(handle).await {
                    Ok(emit) => {
                        if !record_emit(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            emit,
                        )
                        .await
                        {
                            tracing::warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                            break;
                        }
                    }
                    Err(_) => {
                        tracing::warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                        break;
                    }
                }
            }
            entry = rx.recv() => {
                match entry {
                    Some(Ok(entry)) => {
                        if !enqueue_stream_entry(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            &mut assembler,
                            entry,
                        )
                        .await
                        {
                            tracing::warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!(unit, error = %e, "sdjournal stream failed, falling back to journalctl");
                        use_fallback = true;
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    let _ = reader.join();

    if use_fallback {
        fallback::stream_unit_logs(
            handle,
            unit,
            &source_id_owned,
            resume_cursor,
            multiline,
            shutdown,
        )
        .await;
        return;
    }

    match assembler.flush(handle).await {
        Ok(emit) => {
            if !record_emit(
                handle,
                source_id,
                &mut entries_processed,
                &mut last_cursor,
                emit,
            )
            .await
            {
                tracing::warn!(
                    unit,
                    "streaming pipeline actor gone, stopping journald stream"
                );
                return;
            }
        }
        Err(_) => {
            tracing::warn!(
                unit,
                "streaming pipeline actor gone, stopping journald stream"
            );
            return;
        }
    }

    native::finalize_stream(
        handle,
        unit,
        source_id,
        entries_processed,
        last_cursor.as_deref(),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-backend parity: for a logical entry, the native backend extracts
    // `(MESSAGE bytes, realtime µs, cursor)` and feeds them to `normalize_entry`.
    // These tests reconstruct the SAME raw fields from the journalctl JSON the
    // fallback backend parses, feed them through the SAME `normalize_entry`, and
    // assert the resulting `StreamEntry` matches — proving the fallback recovers
    // exactly what native would deliver.

    fn native_side(message_bytes: &[u8], realtime_usec: u64, cursor: &str) -> StreamEntry {
        normalize_entry(message_bytes, realtime_usec, Some(cursor.to_string()))
            .expect("native entry should normalize")
    }

    fn fallback_side(json_line: &str) -> Option<StreamEntry> {
        let parsed = fallback::parse_journald_json(json_line);
        normalize_entry(
            &parsed.message_bytes,
            parsed
                .realtime_usec
                .expect("fixture carries __REALTIME_TIMESTAMP"),
            parsed.cursor,
        )
    }

    #[test]
    fn fallback_utf8_message_matches_native() {
        let native = native_side(b"hello world", 1_600_000_000_000_000, "s=abc;i=1");
        let line = r#"{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1600000000000000","MESSAGE":"hello world"}"#;
        let fallback = fallback_side(line).expect("fallback entry should normalize");

        assert_eq!(fallback.message, native.message);
        assert_eq!(fallback.timestamp_ns, native.timestamp_ns);
        assert_eq!(fallback.cursor, native.cursor);
    }

    #[test]
    fn fallback_binary_message_matches_native() {
        // Non-UTF8 MESSAGE: systemd emits it as an array of byte-valued ints.
        // Native reads the raw bytes and delivers `from_utf8_lossy`; the fallback
        // must recover the same bytes (0xFF is invalid UTF-8 → U+FFFD).
        let raw = [104u8, 105, 255, 33]; // "hi\u{FFFD}!"
        let native = native_side(&raw, 1_600_000_000_000_000, "s=abc;i=2");
        let line = r#"{"__CURSOR":"s=abc;i=2","__REALTIME_TIMESTAMP":"1600000000000000","MESSAGE":[104,105,255,33]}"#;
        let fallback = fallback_side(line).expect("fallback entry should normalize");

        assert_eq!(fallback.message, "hi\u{FFFD}!");
        assert_eq!(fallback.message, native.message);
        assert_eq!(fallback.timestamp_ns, native.timestamp_ns);
    }

    #[test]
    fn fallback_carries_historical_timestamp_not_now() {
        // Resume-backfill: a replayed entry must keep its own realtime, not the
        // wall clock at read time.
        let historical_usec = 1_600_000_000_000_000u64;
        let line = r#"{"__CURSOR":"s=abc;i=3","__REALTIME_TIMESTAMP":"1600000000000000","MESSAGE":"backfilled"}"#;
        let parsed = fallback::parse_journald_json(line);

        assert_eq!(parsed.realtime_usec, Some(historical_usec));
        let entry = fallback_side(line).unwrap();
        assert_eq!(entry.timestamp_ns, (historical_usec as i64) * 1_000);

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        // The fixture is 2020-09-13; any test run is years later. If the entry
        // had been stamped now() (the bug), this gap would be ~0.
        let one_year_ns = 365i64 * 86_400 * 1_000_000_000;
        assert!(now_ns - entry.timestamp_ns > one_year_ns);
    }

    #[test]
    fn whitespace_only_message_dropped_on_both_backends() {
        // Native drops via `decode_message`; the fallback drops the same input by
        // normalizing through the same seam.
        assert!(decode_message(b"   ").is_none());
        assert!(decode_message(b"\t\n ").is_none());

        let line =
            r#"{"__CURSOR":"s=abc;i=4","__REALTIME_TIMESTAMP":"1600000000000000","MESSAGE":"   "}"#;
        assert!(fallback_side(line).is_none());
    }
}
