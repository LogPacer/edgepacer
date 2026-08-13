//! Docker container log streaming via the Docker API (bollard).
//!
//! Streams logs from running Docker containers and enqueues them to the
//! `StreamingDeliveryPipeline` for guaranteed at-least-once delivery.
//!
//! Resume semantics: timestamp-based. Docker accepts `since` only as an epoch
//! second, so reconnects replay that whole second. An exact timestamp +
//! same-timestamp occurrence fence suppresses only lines already enqueued while
//! preserving distinct lines that share the boundary timestamp.

use bollard::query_parameters::LogsOptions;
use futures_util::StreamExt;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::config::MultilineConfig;
use crate::cri::LogStream;
use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::{StreamingEmit, StreamingEntryAssembler};

const CHECKPOINT_INTERVAL: u64 = 100;
const ASSEMBLER_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Why a Docker stream loop exited — tells the reconnect loop
/// (`streaming_runner`) a transient disconnect (retry on the normal backoff)
/// from a container that no longer exists (candidate for parking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DockerStreamEnd {
    /// Stream ended or errored for any other reason — reconnect as usual.
    Disconnected,
    /// A clean EOF was followed by an inspect showing the container is stopped.
    ContainerStopped,
    /// The Docker API returned 404 for this container: it's gone.
    ContainerNotFound,
}

/// Which container output stream a Docker API frame came from. The API keeps
/// stdout and stderr in separate frames; keeping the tag is what lets a stack
/// trace on stderr assemble while stdout lines arrive between its frames.
fn log_output_stream(output: &bollard::container::LogOutput) -> LogStream {
    use bollard::container::LogOutput;

    match output {
        LogOutput::StdOut { .. } => LogStream::Stdout,
        LogOutput::StdErr { .. } => LogStream::Stderr,
        LogOutput::StdIn { .. } | LogOutput::Console { .. } => LogStream::Unspecified,
    }
}

/// True for the 404 the Docker API returns when a container id no longer
/// exists (removed, or never existed) — as opposed to a transient stream
/// error that a normal reconnect should just retry.
fn is_container_not_found(error: &bollard::errors::Error) -> bool {
    matches!(
        error,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

/// Classify a clean follow-stream EOF from the inspected Docker state.
///
/// Missing or active state fails open to reconnect. Every concrete inactive
/// state parks the reader; it keeps re-probing while source reconciliation can
/// replace it when the configured container changes.
fn classify_clean_eof_state(state: Option<&bollard::models::ContainerState>) -> DockerStreamEnd {
    use bollard::models::ContainerStateStatusEnum;

    match state.and_then(|state| state.status) {
        Some(
            ContainerStateStatusEnum::RUNNING
            | ContainerStateStatusEnum::PAUSED
            | ContainerStateStatusEnum::RESTARTING,
        )
        | Some(ContainerStateStatusEnum::EMPTY)
        | None => DockerStreamEnd::Disconnected,
        Some(_) => DockerStreamEnd::ContainerStopped,
    }
}

async fn classify_clean_eof(docker: &bollard::Docker, container_id: &str) -> DockerStreamEnd {
    match docker.inspect_container(container_id, None).await {
        Ok(inspect) => {
            let outcome = classify_clean_eof_state(inspect.state.as_ref());
            if outcome == DockerStreamEnd::ContainerStopped {
                info!(
                    container_id,
                    status = ?inspect.state.and_then(|state| state.status),
                    "Docker log stream ended for stopped container"
                );
            }
            outcome
        }
        Err(error) if is_container_not_found(&error) => {
            info!(
                container_id,
                "Docker container not found after log stream ended"
            );
            DockerStreamEnd::ContainerNotFound
        }
        Err(error) => {
            warn!(
                container_id,
                error = %error,
                "failed to inspect container after Docker log stream ended"
            );
            DockerStreamEnd::Disconnected
        }
    }
}

/// Filters the replay caused by Docker's second-precision `since` without
/// turning a same-timestamp group into a lossy `timestamp + 1ns` cursor.
struct DockerResumeBoundary {
    resume: Option<(chrono::DateTime<chrono::FixedOffset>, u64)>,
    observed_timestamp: Option<chrono::DateTime<chrono::FixedOffset>>,
    observed_occurrence: u64,
}

impl DockerResumeBoundary {
    fn new(resume: Option<(&str, u64)>) -> Self {
        Self {
            resume: resume.and_then(|(timestamp, occurrence)| {
                chrono::DateTime::parse_from_rfc3339(timestamp)
                    .ok()
                    .map(|timestamp| (timestamp, occurrence))
            }),
            observed_timestamp: None,
            observed_occurrence: 0,
        }
    }

    fn should_skip(&mut self, timestamp: &str) -> bool {
        let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
            self.observed_timestamp = None;
            self.observed_occurrence = 1;
            return false;
        };

        if self.observed_timestamp == Some(timestamp) {
            self.observed_occurrence += 1;
        } else {
            self.observed_timestamp = Some(timestamp);
            self.observed_occurrence = 1;
        }

        let Some((resume_timestamp, resume_occurrence)) = self.resume.as_ref() else {
            return false;
        };

        match timestamp.cmp(resume_timestamp) {
            Ordering::Less => true,
            Ordering::Equal => self.observed_occurrence <= *resume_occurrence,
            Ordering::Greater => {
                self.resume = None;
                false
            }
        }
    }

    fn observed_occurrence(&self) -> u64 {
        self.observed_occurrence
    }
}

/// Stream logs from a Docker container into the streaming pipeline actor.
///
/// Runs until the container stops or shutdown is signaled.
/// Updates the pipeline's pending checkpoint after each batch of lines.
pub async fn stream_container_logs(
    handle: &StreamHandle,
    container_id: &str,
    source_id: &str,
    resume: Option<(&str, u64)>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) -> DockerStreamEnd {
    let docker = match crate::discovery::docker::connect_docker() {
        Ok(Some(d)) => d,
        Ok(None) => {
            error!(
                container_id,
                "failed to connect to Docker: no Docker socket found"
            );
            return DockerStreamEnd::Disconnected;
        }
        Err(e) => {
            error!(container_id, error = %e, "failed to connect to Docker");
            return DockerStreamEnd::Disconnected;
        }
    };

    // Build log options with optional resume timestamp.
    let since_str = resume.map_or("0", |(timestamp, _)| timestamp);

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
    let mut resume_boundary = DockerResumeBoundary::new(resume);
    let mut assembler = match StreamingEntryAssembler::new(multiline) {
        Ok(assembler) => assembler,
        Err(error) => {
            error!(container_id, source_id, error = %error, "invalid Docker multiline pattern");
            return DockerStreamEnd::Disconnected;
        }
    };
    let mut assembler_tick = tokio::time::interval(ASSEMBLER_CHECK_INTERVAL);
    assembler_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    assembler_tick.tick().await;

    let mut last_checkpoint = resume.map(|(timestamp, occurrence)| {
        StreamingCheckpoint::docker_at_occurrence(source_id, container_id, timestamp, occurrence)
    });
    let mut lines_streamed: u64 = 0;
    let mut stream_end = DockerStreamEnd::Disconnected;

    loop {
        tokio::select! {
            item = stream.next() => {
                match item {
                    Some(Ok(output)) => {
                        let stream = log_output_stream(&output);
                        let raw = output.to_string();
                        let (timestamp, line) = parse_docker_log_line(&raw);
                        let line = crate::ansi::strip_str(line);

                        if line.is_empty() {
                            continue;
                        }

                        if timestamp.is_some_and(|timestamp| {
                            resume_boundary.should_skip(timestamp)
                        }) {
                            continue;
                        }

                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as i64;

                        let checkpoint = timestamp.map(|ts| {
                            StreamingCheckpoint::docker_at_occurrence(
                                source_id,
                                container_id,
                                ts,
                                resume_boundary.observed_occurrence(),
                            )
                        });

                        match assembler
                            .process_stream_line(
                                handle,
                                stream,
                                line.as_bytes().to_vec(),
                                now_ns,
                                checkpoint,
                            )
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
                                    return DockerStreamEnd::Disconnected;
                                }
                            }
                            Err(_) => {
                                warn!(container_id, "streaming pipeline actor gone, stopping Docker stream");
                                return DockerStreamEnd::Disconnected;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        if is_container_not_found(&e) {
                            info!(container_id, "Docker container not found (404), likely removed");
                            stream_end = DockerStreamEnd::ContainerNotFound;
                        } else {
                            warn!(container_id, error = %e, "Docker log stream error");
                        }
                        // Break to reconnect (or park, if not found — see streaming_runner).
                        break;
                    }
                    None => {
                        // A clean EOF can mean either a stopped container or a
                        // dropped follow connection. Inspect before deciding
                        // whether the reader is terminal or reconnectable.
                        info!(container_id, lines = lines_streamed, "Docker log stream ended");
                        stream_end = classify_clean_eof(&docker, container_id).await;
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
                            return DockerStreamEnd::Disconnected;
                        }
                    }
                    Err(_) => {
                        warn!(container_id, "streaming pipeline actor gone, stopping Docker stream");
                        return DockerStreamEnd::Disconnected;
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
                return DockerStreamEnd::Disconnected;
            }
        }
        Err(_) => {
            warn!(
                container_id,
                "streaming pipeline actor gone, stopping Docker stream"
            );
            return DockerStreamEnd::Disconnected;
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

    stream_end
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
    fn not_found_is_only_the_404_status() {
        assert!(is_container_not_found(
            &bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                message: "No such container".to_string(),
            }
        ));
    }

    #[test]
    fn other_statuses_are_not_container_not_found() {
        // Negative control: a different server status must not be mistaken
        // for "container gone" — it would wrongly start the parking streak.
        assert!(!is_container_not_found(
            &bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: "internal error".to_string(),
            }
        ));
        assert!(!is_container_not_found(
            &bollard::errors::Error::RequestTimeoutError
        ));
    }

    #[test]
    fn clean_eof_from_exited_container_requests_parking() {
        let state = bollard::models::ContainerState {
            status: Some(bollard::models::ContainerStateStatusEnum::EXITED),
            ..Default::default()
        };

        assert_eq!(
            classify_clean_eof_state(Some(&state)),
            DockerStreamEnd::ContainerStopped
        );
    }

    #[test]
    fn clean_eof_from_running_container_is_a_disconnect() {
        let state = bollard::models::ContainerState {
            status: Some(bollard::models::ContainerStateStatusEnum::RUNNING),
            ..Default::default()
        };

        assert_eq!(
            classify_clean_eof_state(Some(&state)),
            DockerStreamEnd::Disconnected
        );
    }

    #[test]
    fn clean_eof_with_unknown_state_is_a_disconnect() {
        assert_eq!(
            classify_clean_eof_state(None),
            DockerStreamEnd::Disconnected
        );
        assert_eq!(
            classify_clean_eof_state(Some(&bollard::models::ContainerState::default())),
            DockerStreamEnd::Disconnected
        );
    }

    #[test]
    fn resume_boundary_skips_only_delivered_same_timestamp_occurrences() {
        let boundary_timestamp = "2026-07-09T00:09:14.107595876Z";
        let checkpoint = StreamingCheckpoint::docker_at_occurrence(
            "service-4",
            "e0eab7b5c0d9",
            boundary_timestamp,
            2,
        );
        let mut boundary =
            DockerResumeBoundary::new(checkpoint.docker_resume_boundary("e0eab7b5c0d9"));

        assert!(boundary.should_skip("2026-07-09T00:09:14.100000000Z"));
        assert!(boundary.should_skip(boundary_timestamp));
        assert!(boundary.should_skip(boundary_timestamp));
        assert!(
            !boundary.should_skip(boundary_timestamp),
            "a distinct third line sharing the boundary timestamp must be delivered"
        );
        assert!(!boundary.should_skip("2026-07-09T00:09:14.200000000Z"));
        assert!(boundary.resume.is_none(), "past-boundary fence must retire");
        assert!(!boundary.should_skip("2026-07-09T00:09:14.200000000Z"));
        assert_eq!(
            boundary.observed_occurrence(),
            2,
            "same-timestamp occurrence tracking continues after fence retirement"
        );
    }

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
