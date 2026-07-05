//! Native journal reading via `sdjournal` (pure Rust, musl-compatible).
//!
//! Reads systemd journal files directly — no `journalctl` subprocess, no `libsystemd`.
//! Validated by the journald integration path and local Linux smoke runs.

use std::thread;
use std::time::Duration;

use sdjournal::{Cursor, Journal, SubscriptionOptions};
use tokio::sync::watch;
use tracing::info;

use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::{StreamingEmit, StreamingEntryAssembler};

use super::StreamEntry;

fn open_journal() -> Result<Journal, String> {
    Journal::open_default().map_err(|e| format!("sdjournal open_default: {e}"))
}

fn message_from_entry(entry: &sdjournal::EntryOwned) -> Option<String> {
    let bytes = entry.get("MESSAGE")?;
    let message = String::from_utf8_lossy(bytes).into_owned();
    if message.trim().is_empty() {
        None
    } else {
        Some(message)
    }
}

fn entry_to_stream(entry: &sdjournal::LiveEntry) -> Result<StreamEntry, String> {
    let message_bytes = entry
        .get("MESSAGE")
        .ok_or_else(|| "entry missing MESSAGE".to_string())?;
    let message = String::from_utf8_lossy(message_bytes).into_owned();
    if message.trim().is_empty() {
        return Err("empty MESSAGE".into());
    }

    let cursor = entry
        .cursor()
        .map_err(|e| format!("entry cursor: {e}"))?
        .to_string();

    let timestamp_ns = (entry.realtime_usec() as i64) * 1_000;

    Ok(StreamEntry {
        message,
        cursor,
        timestamp_ns,
    })
}

/// Sample the most recent lines for a unit using sdjournal.
pub fn sample_unit_lines(unit: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let journal = open_journal()?;
    let mut query = journal.query();
    query
        .match_unit(unit)
        .seek_tail()
        .reverse(true)
        .limit(max_lines);

    let entries = query
        .collect_owned()
        .map_err(|e| format!("sdjournal sample for {unit}: {e}"))?;

    let mut lines: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| message_from_entry(&entry))
        .collect();
    lines.reverse();
    Ok(lines)
}

pub fn stream_unit_blocking(
    unit: &str,
    resume_cursor: Option<&str>,
    tx: tokio::sync::mpsc::Sender<Result<StreamEntry, String>>,
    shutdown: watch::Receiver<bool>,
) {
    let journal = match open_journal() {
        Ok(j) => j,
        Err(e) => {
            let _ = tx.blocking_send(Err(e));
            return;
        }
    };

    let mut live = match journal.live() {
        Ok(l) => l,
        Err(e) => {
            let _ = tx.blocking_send(Err(format!("sdjournal live() for {unit}: {e}")));
            return;
        }
    };

    let mut filter = live.filter();
    filter.match_unit(unit);

    let subscription = match if let Some(cursor) = resume_cursor {
        let parsed = match Cursor::parse(cursor) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.blocking_send(Err(format!("sdjournal Cursor::parse for {unit}: {e}")));
                return;
            }
        };
        info!(
            unit,
            cursor, "resuming journald stream from cursor (sdjournal)"
        );
        let mut options = SubscriptionOptions::new(filter);
        options.after_cursor(parsed);
        live.subscribe_with_options(options)
    } else {
        info!(unit, "starting journald stream from end (sdjournal)");
        live.subscribe(filter)
    } {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.blocking_send(Err(format!("sdjournal subscribe for {unit}: {e}")));
            return;
        }
    };

    let engine = thread::spawn(move || {
        let _ = live.run();
    });

    loop {
        if *shutdown.borrow() {
            break;
        }

        match subscription.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(entry)) => {
                if let Ok(stream_entry) = entry_to_stream(&entry)
                    && tx.blocking_send(Ok(stream_entry)).is_err()
                {
                    break;
                }
            }
            Ok(Err(e)) => {
                let _ = tx.blocking_send(Err(format!("sdjournal live entry for {unit}: {e}")));
                break;
            }
            Err(_) => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    drop(subscription);
    let _ = engine.join();
}

/// Enqueue one journal entry via the pipeline actor. Backpressure is the
/// bounded channel — the await suspends until the actor has room. Returns
/// `false` when the actor is gone and the stream should stop.
pub async fn enqueue_stream_entry(
    handle: &StreamHandle,
    source_id: &str,
    entries_processed: &mut u64,
    last_cursor: &mut Option<String>,
    checkpoint_interval: u64,
    assembler: &mut StreamingEntryAssembler,
    entry: StreamEntry,
) -> bool {
    let checkpoint = StreamingCheckpoint::journald(source_id, &entry.cursor);
    match assembler
        .process_line(
            handle,
            entry.message.into_bytes(),
            entry.timestamp_ns,
            Some(checkpoint),
        )
        .await
    {
        Ok(emit) => {
            record_emit(
                handle,
                source_id,
                entries_processed,
                last_cursor,
                checkpoint_interval,
                emit,
            )
            .await
        }
        Err(_) => false,
    }
}

pub async fn record_emit(
    handle: &StreamHandle,
    source_id: &str,
    entries_processed: &mut u64,
    last_cursor: &mut Option<String>,
    checkpoint_interval: u64,
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

    if entries_processed.is_multiple_of(checkpoint_interval)
        && let Some(cursor) = last_cursor.as_deref()
        && !handle
            .set_checkpoint(StreamingCheckpoint::journald(source_id, cursor))
            .await
    {
        return false;
    }
    true
}

pub async fn finalize_stream(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    entries_processed: u64,
    last_cursor: Option<&str>,
) {
    if let Some(cursor) = last_cursor {
        handle
            .set_final_checkpoint(StreamingCheckpoint::journald(source_id, cursor))
            .await;
    }

    info!(
        unit,
        source_id,
        total_entries = entries_processed,
        backend = "sdjournal",
        "journald log streaming stopped"
    );
}
