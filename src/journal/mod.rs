//! Journald access — sdjournal primary, journalctl fallback.
//!
//! Shared adapter for sampling (`sampler`) and streaming (`journald_stream`).
//! On Linux, reads journal files via `sdjournal` (musl-compatible). Falls back to
//! `journalctl` when sdjournal open/read fails.

mod fallback;
mod unit;

#[cfg(target_os = "linux")]
mod native;

use tokio::sync::watch;

use crate::config::MultilineConfig;
use crate::streaming_actor::StreamHandle;

#[cfg(target_os = "linux")]
use crate::streaming_multiline::StreamingEntryAssembler;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::time::MissedTickBehavior;

pub use unit::is_systemd_unit;

/// One streamed journal entry. Constructed only by the Linux `native` backend;
/// on other targets it survives as the journald channel's item type but is never
/// built, so its fields read as dead there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct StreamEntry {
    message: String,
    cursor: String,
    timestamp_ns: i64,
}

/// Read up to `max_lines` of bare log text from a systemd unit.
pub fn sample_unit_lines(unit: &str, max_lines: usize) -> Result<Vec<String>, String> {
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
    let checkpoint_interval = 100u64;
    let mut use_fallback = false;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            _ = assembler_tick.tick() => {
                match assembler.check_timeout(handle).await {
                    Ok(emit) => {
                        if !native::record_emit(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            checkpoint_interval,
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
                        if !native::enqueue_stream_entry(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            checkpoint_interval,
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
            if !native::record_emit(
                handle,
                source_id,
                &mut entries_processed,
                &mut last_cursor,
                checkpoint_interval,
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
