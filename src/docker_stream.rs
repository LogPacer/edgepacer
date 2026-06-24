//! Docker container log streaming via the Docker API (bollard).
//!
//! Streams logs from running Docker containers and enqueues them to the
//! `StreamingDeliveryPipeline` for guaranteed at-least-once delivery.
//!
//! Resume semantics: timestamp-based. On reconnect, passes `since=last_timestamp`
//! to the Docker API. Duplicates around the resume point are accepted — this is
//! the at-least-once contract, not exactly-once.

use bollard::container::LogsOptions;
use futures_util::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;

/// Stream logs from a Docker container into the streaming pipeline actor.
///
/// Runs until the container stops or shutdown is signaled.
/// Updates the pipeline's pending checkpoint after each batch of lines.
pub async fn stream_container_logs(
    handle: &StreamHandle,
    container_id: &str,
    source_id: &str,
    since: Option<&str>,
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

    let options = LogsOptions::<String> {
        follow: true,
        stdout: true,
        stderr: true,
        since: parse_since_timestamp(since_str),
        timestamps: true,
        ..Default::default()
    };

    let mut stream = docker.logs(container_id, Some(options));
    let mut last_timestamp = since.map(|s| s.to_string());
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

                        // Backpressure is the bounded channel: this awaits
                        // until the actor has room. False means the actor is
                        // gone — stop streaming.
                        if !handle.enqueue(line.as_bytes().to_vec(), now_ns).await {
                            warn!(container_id, "streaming pipeline actor gone, stopping Docker stream");
                            return;
                        }

                        // Update last seen timestamp for checkpoint.
                        if let Some(ts) = timestamp {
                            last_timestamp = Some(ts.to_string());
                        }

                        lines_streamed += 1;

                        // Set pending checkpoint periodically (every 100 lines).
                        if lines_streamed.is_multiple_of(100) {
                            if let Some(ref ts) = last_timestamp {
                                let _ = handle
                                    .set_checkpoint(StreamingCheckpoint::docker(
                                        source_id,
                                        container_id,
                                        ts,
                                    ))
                                    .await;
                            }
                            debug!(
                                container_id,
                                lines = lines_streamed,
                                "Docker stream progress"
                            );
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
            _ = shutdown.changed() => {
                info!(container_id, "Docker stream shutdown signal");
                break;
            }
        }
    }

    // Final checkpoint update with last seen timestamp (bounded — a
    // backpressured actor must not wedge reader shutdown).
    if let Some(ref ts) = last_timestamp {
        handle
            .set_final_checkpoint(StreamingCheckpoint::docker(source_id, container_id, ts))
            .await;
    }

    info!(
        container_id,
        source_id,
        total_lines = lines_streamed,
        "Docker log streaming stopped"
    );
}

/// Parse a Docker log line with timestamp prefix.
///
/// Docker log format with timestamps: "2026-04-05T10:30:00.123456789Z actual log line"
/// Returns (optional_timestamp, line_content).
fn parse_docker_log_line(raw: &str) -> (Option<&str>, &str) {
    // Docker timestamps are RFC3339Nano, always 30+ chars with 'T' and 'Z'.
    if raw.len() > 31
        && raw.as_bytes()[4] == b'-'
        && raw.as_bytes()[10] == b'T'
        && let Some(space_pos) = raw[..35.min(raw.len())].find(' ')
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
