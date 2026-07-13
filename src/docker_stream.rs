//! Docker container log streaming via the Docker API (bollard).
//!
//! Streams logs from running Docker containers and enqueues them to the
//! `StreamingDeliveryPipeline` for guaranteed at-least-once delivery.
//!
//! Resume semantics: timestamp-based. On reconnect, passes `since=last_timestamp`
//! to the Docker API. Duplicates around the resume point are accepted — this is
//! the at-least-once contract, not exactly-once.

use bollard::query_parameters::LogsOptions;
use futures_util::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::config::MultilineConfig;
use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::{StreamingEmit, StreamingEntryAssembler};

const CHECKPOINT_INTERVAL: u64 = 100;
const ASSEMBLER_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Stream logs from a Docker container into the streaming pipeline actor.
///
/// Runs until the container stops or shutdown is signaled.
/// Updates the pipeline's pending checkpoint after each batch of lines.
pub async fn stream_container_logs(
    handle: &StreamHandle,
    container_id: &str,
    source_id: &str,
    since: Option<&str>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let docker = match crate::discovery::docker::connect_docker() {
        Ok(Some(d)) => d,
        Ok(None) => {
            error!(
                container_id,
                "failed to connect to Docker: no Docker socket found"
            );
            return;
        }
        Err(e) => {
            error!(container_id, error = %e, "failed to connect to Docker");
            return;
        }
    };

    // Build log options with optional resume timestamp.
    let since_str = since.unwrap_or("0");

    info!(
        container_id,
        source_id,
        since = since_str,
        "starting Docker log stream"
    );

    // Docker's API types `since` as a 32-bit epoch; on overflow fall back to a
    // full replay (0), which the at-least-once contract absorbs as duplicates.
    let options = LogsOptions {
        follow: true,
        stdout: true,
        stderr: true,
        since: i32::try_from(parse_since_timestamp(since_str)).unwrap_or(0),
        timestamps: true,
        ..Default::default()
    };

    let mut stream = docker.logs(container_id, Some(options));
    let mut assembler = match StreamingEntryAssembler::new(multiline) {
        Ok(assembler) => assembler,
        Err(error) => {
            error!(container_id, source_id, error = %error, "invalid Docker multiline pattern");
            return;
        }
    };
    let mut assembler_tick = tokio::time::interval(ASSEMBLER_CHECK_INTERVAL);
    assembler_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    assembler_tick.tick().await;

    let mut last_checkpoint =
        since.map(|timestamp| StreamingCheckpoint::docker(source_id, container_id, timestamp));
    let mut lines_streamed: u64 = 0;

    loop {
        tokio::select! {
            item = stream.next() => {
                match item {
                    Some(Ok(output)) => {
                        let raw = output.to_string();
                        let (timestamp, line) = parse_docker_log_line(&raw);

                        if line.is_empty() {
                            continue;
                        }

                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as i64;

                        let checkpoint = timestamp.map(|ts| {
                            StreamingCheckpoint::docker(source_id, container_id, ts)
                        });

                        match assembler
                            .process_line(handle, line.as_bytes().to_vec(), now_ns, checkpoint)
                            .await
                        {
                            Ok(emit) => {
                                if !record_emit(
                                    handle,
                                    container_id,
                                    &mut lines_streamed,
                                    &mut last_checkpoint,
                                    emit,
                                )
                                .await
                                {
                                    return;
                                }
                            }
                            Err(_) => {
                                warn!(container_id, "streaming pipeline actor gone, stopping Docker stream");
                                return;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(container_id, error = %e, "Docker log stream error");
                        // Transient error — break to reconnect.
                        break;
                    }
                    None => {
                        // Stream ended (container stopped or detached).
                        info!(container_id, lines = lines_streamed, "Docker log stream ended");
                        break;
                    }
                }
            }
            _ = assembler_tick.tick() => {
                match assembler.check_timeout(handle).await {
                    Ok(emit) => {
                        if !record_emit(
                            handle,
                            container_id,
                            &mut lines_streamed,
                            &mut last_checkpoint,
                            emit,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(_) => {
                        warn!(container_id, "streaming pipeline actor gone, stopping Docker stream");
                        return;
                    }
                }
            }
            _ = shutdown.changed() => {
                info!(container_id, "Docker stream shutdown signal");
                break;
            }
        }
    }

    match assembler.flush(handle).await {
        Ok(emit) => {
            if !record_emit(
                handle,
                container_id,
                &mut lines_streamed,
                &mut last_checkpoint,
                emit,
            )
            .await
            {
                return;
            }
        }
        Err(_) => {
            warn!(
                container_id,
                "streaming pipeline actor gone, stopping Docker stream"
            );
            return;
        }
    }

    // Final checkpoint update with last seen timestamp (bounded — a
    // backpressured actor must not wedge reader shutdown).
    if let Some(checkpoint) = last_checkpoint {
        handle.set_final_checkpoint(checkpoint).await;
    }

    info!(
        container_id,
        source_id,
        total_lines = lines_streamed,
        "Docker log streaming stopped"
    );
}

async fn record_emit(
    handle: &StreamHandle,
    container_id: &str,
    lines_streamed: &mut u64,
    last_checkpoint: &mut Option<StreamingCheckpoint>,
    emit: Option<StreamingEmit>,
) -> bool {
    let Some(emit) = emit else {
        return true;
    };

    *lines_streamed += 1;

    if let Some(checkpoint) = emit.checkpoint {
        *last_checkpoint = Some(checkpoint);
    }

    if lines_streamed.is_multiple_of(CHECKPOINT_INTERVAL) {
        if let Some(checkpoint) = last_checkpoint.clone()
            && !handle.set_checkpoint(checkpoint).await
        {
            warn!(
                container_id,
                "streaming pipeline actor gone, stopping Docker stream"
            );
            return false;
        }
        debug!(
            container_id,
            lines = *lines_streamed,
            "Docker stream progress"
        );
    }

    true
}

/// Parse a Docker log line with timestamp prefix.
///
/// Docker log format with timestamps: "2026-04-05T10:30:00.123456789Z actual log line"
/// Returns (optional_timestamp, line_content).
///
/// Shared with the sampler (`sampler::read_docker_lines`) so a sampled Docker
/// API line strips the timestamp and trailing whitespace exactly as the wire
/// does — no divergent trimming.
pub(crate) fn parse_docker_log_line(raw: &str) -> (Option<&str>, &str) {
    // Docker timestamps are RFC3339Nano, always 30+ chars with 'T' and 'Z'.
    // Search bytes, not a str slice: byte 35 can fall inside a multibyte char
    // (log lines are arbitrary UTF-8) and str slicing there panics. The space
    // is ASCII, so a byte position is always a char boundary.
    if raw.len() > 31
        && raw.as_bytes()[4] == b'-'
        && raw.as_bytes()[10] == b'T'
        && let Some(space_pos) = raw.as_bytes()[..35.min(raw.len())]
            .iter()
            .position(|&b| b == b' ')
    {
        let timestamp = &raw[..space_pos];
        let line = raw[space_pos + 1..].trim_end();
        return (Some(timestamp), line);
    }
    (None, raw.trim_end())
}

/// Parse a `since` timestamp string to a Unix epoch integer for Docker API.
///
/// Docker API accepts `since` as seconds since epoch (integer) or RFC3339.
/// We convert RFC3339Nano to epoch seconds for the API.
fn parse_since_timestamp(since: &str) -> i64 {
    if since == "0" {
        return 0;
    }
    // Try parsing as RFC3339
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(since) {
        return dt.timestamp();
    }
    // Try parsing as epoch seconds
    since.parse::<i64>().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_docker_line_with_timestamp() {
        let raw = "2026-04-05T10:30:00.123456789Z hello world";
        let (ts, line) = parse_docker_log_line(raw);
        assert_eq!(ts, Some("2026-04-05T10:30:00.123456789Z"));
        assert_eq!(line, "hello world");
    }

    #[test]
    fn parse_docker_line_without_timestamp() {
        let raw = "just a plain log line";
        let (ts, line) = parse_docker_log_line(raw);
        assert!(ts.is_none());
        assert_eq!(line, "just a plain log line");
    }

    #[test]
    fn parse_docker_line_multibyte_at_probe_boundary_does_not_panic() {
        // Passes the cheap date-shape guard, has no space in the first 35
        // bytes, and the second emoji spans bytes 32..36 — the old str slice
        // at ..35 panicked inside it (seen live: docker_stream.rs:256 on a
        // U+FE0F in a container log).
        let raw = "2026-07-11T00:00:00.00000000🙂🙂🙂";
        assert_eq!(raw.as_bytes()[4], b'-');
        assert_eq!(raw.as_bytes()[10], b'T');
        let (ts, line) = parse_docker_log_line(raw);
        assert!(ts.is_none());
        assert_eq!(line, raw);
    }

    #[test]
    fn parse_since_rfc3339() {
        let ts = parse_since_timestamp("2026-04-05T10:30:00Z");
        assert!(ts > 0);
    }

    #[test]
    fn parse_since_zero() {
        assert_eq!(parse_since_timestamp("0"), 0);
    }

    #[test]
    fn parse_since_epoch() {
        assert_eq!(parse_since_timestamp("1700000000"), 1700000000);
    }
}
