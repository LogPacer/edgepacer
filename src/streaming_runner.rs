//! Streaming source reader — reconnect loop feeding the pipeline actor.
//!
//! The drain side lives in `streaming_actor`: one task per source owns the
//! pipeline, and this reader reaches it only through a [`StreamHandle`].

use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{StreamAccessMethod, StreamingSourceConfig};
use crate::docker_stream;
use crate::journald_stream;
use crate::streaming_actor::StreamHandle;
use crate::windows_event_log;

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Consecutive Docker "container not found" (404) reconnects before a source
/// is parked. A container mid-restart reconnects a handful of times and
/// never approaches this; a container that was actually removed hits it
/// within minutes at the ~30s backoff cap.
const PARK_AFTER_CONSECUTIVE_NOT_FOUND: u32 = 20;

/// How often a parked source re-probes. Bookmarks are never reset — parked
/// means "not polled every ~30s", not "forgotten": if the container comes
/// back, resume picks up from the last known `since=`.
const PARKED_REPROBE_INTERVAL: Duration = Duration::from_secs(3600);

/// Tracks a Docker source's consecutive not-found reconnects and turns that
/// into the sleep duration the reader should use before its next attempt.
/// Kept separate from the I/O loop so the parking threshold is unit-testable
/// without a Docker daemon.
#[derive(Default)]
struct NotFoundStreak(u32);

impl NotFoundStreak {
    /// Record an outcome, returning the sleep to use before the next
    /// reconnect: `backoff` normally, or — once
    /// `PARK_AFTER_CONSECUTIVE_NOT_FOUND` consecutive not-found results have
    /// been seen — the parked re-probe interval instead. Any non-not-found
    /// outcome resets the streak immediately.
    fn record(&mut self, outcome: docker_stream::DockerStreamEnd, backoff: Duration) -> Duration {
        match outcome {
            docker_stream::DockerStreamEnd::ContainerNotFound => self.0 += 1,
            docker_stream::DockerStreamEnd::Disconnected => self.0 = 0,
        }
        if self.0 >= PARK_AFTER_CONSECUTIVE_NOT_FOUND {
            PARKED_REPROBE_INTERVAL
        } else {
            backoff
        }
    }

    /// True on the exact call that crossed the parking threshold — the cue
    /// to log the transition once, not on every subsequent hourly re-probe.
    fn just_parked(&self) -> bool {
        self.0 == PARK_AFTER_CONSECUTIVE_NOT_FOUND
    }
}

/// Run a streaming reader with exponential backoff reconnect.
pub async fn run_streaming_reader(
    handle: StreamHandle,
    config: StreamingSourceConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut not_found_streak = NotFoundStreak::default();

    loop {
        if *shutdown.borrow() {
            return;
        }

        let checkpoint = match handle.checkpoint().await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                warn!(
                    log_source_id = %config.log_source_id,
                    "streaming pipeline actor gone, stopping reader"
                );
                return;
            }
        };

        info!(log_source_id = %config.log_source_id, "starting streaming reader");

        let sleep_duration = match &config.access_method {
            StreamAccessMethod::DockerApi { container_id } => {
                let since = checkpoint.as_ref().and_then(|cp| cp.docker_since());
                let outcome = docker_stream::stream_container_logs(
                    &handle,
                    container_id,
                    &config.log_source_id,
                    since,
                    config.multiline.as_ref(),
                    &mut shutdown,
                )
                .await;

                let sleep_duration = not_found_streak.record(outcome, backoff);
                if not_found_streak.just_parked() {
                    warn!(
                        log_source_id = %config.log_source_id,
                        container_id,
                        reprobe_secs = PARKED_REPROBE_INTERVAL.as_secs(),
                        "container not found after repeated reconnects, parking source (bookmark kept)"
                    );
                }
                sleep_duration
            }
            StreamAccessMethod::Journald { unit } => {
                let cursor = checkpoint.as_ref().and_then(|cp| cp.journald_cursor());
                journald_stream::stream_journald_logs(
                    &handle,
                    unit,
                    &config.log_source_id,
                    cursor,
                    config.multiline.as_ref(),
                    &mut shutdown,
                )
                .await;
                backoff
            }
            StreamAccessMethod::WindowsEventLog { channel } => {
                let record_id = checkpoint
                    .as_ref()
                    .and_then(|cp| cp.windows_event_record_id(channel));
                windows_event_log::stream_event_log(
                    &handle,
                    channel,
                    &config.log_source_id,
                    record_id,
                    config.multiline.as_ref(),
                    &mut shutdown,
                )
                .await;
                backoff
            }
        };

        if *shutdown.borrow() {
            return;
        }

        warn!(
            log_source_id = %config.log_source_id,
            sleep_secs = sleep_duration.as_secs(),
            "streaming reader disconnected, reconnecting"
        );

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = shutdown.changed() => return,
        }

        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parks_after_threshold_consecutive_not_found() {
        let mut streak = NotFoundStreak::default();
        let backoff = Duration::from_secs(30);

        for i in 1..PARK_AFTER_CONSECUTIVE_NOT_FOUND {
            let sleep = streak.record(docker_stream::DockerStreamEnd::ContainerNotFound, backoff);
            assert_eq!(sleep, backoff, "not parked yet at streak {i}");
            assert!(!streak.just_parked());
        }

        let sleep = streak.record(docker_stream::DockerStreamEnd::ContainerNotFound, backoff);
        assert_eq!(sleep, PARKED_REPROBE_INTERVAL);
        assert!(streak.just_parked());

        // Stays parked (re-probing hourly) on further not-found results,
        // without re-triggering the transition log.
        let sleep = streak.record(docker_stream::DockerStreamEnd::ContainerNotFound, backoff);
        assert_eq!(sleep, PARKED_REPROBE_INTERVAL);
        assert!(!streak.just_parked());
    }

    #[test]
    fn transient_single_not_found_keeps_normal_retry() {
        // Negative control: one not-found followed by a normal disconnect
        // (container back, or another transient condition) must not park —
        // the streak resets and the reader keeps its ~30s cadence.
        let mut streak = NotFoundStreak::default();
        let backoff = Duration::from_secs(4);

        let sleep = streak.record(docker_stream::DockerStreamEnd::ContainerNotFound, backoff);
        assert_eq!(sleep, backoff);

        let sleep = streak.record(docker_stream::DockerStreamEnd::Disconnected, backoff);
        assert_eq!(sleep, backoff);
        assert_eq!(streak.0, 0);
    }
}
