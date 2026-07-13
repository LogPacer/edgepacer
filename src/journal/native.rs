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

use super::StreamEntry;

fn open_journal() -> Result<Journal, String> {
    Journal::open_default().map_err(|e| format!("sdjournal open_default: {e}"))
}

fn message_from_entry(entry: &sdjournal::EntryOwned) -> Option<String> {
    super::decode_message(entry.get("MESSAGE")?)
}

fn entry_to_stream(entry: &sdjournal::LiveEntry) -> Option<StreamEntry> {
    let message_bytes = entry.get("MESSAGE")?;
    let cursor = entry.cursor().ok()?.to_string();
    super::normalize_entry(message_bytes, entry.realtime_usec(), Some(cursor))
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
                if let Some(stream_entry) = entry_to_stream(&entry)
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
