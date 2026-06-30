//! File sampling — reads sample lines from discovered log sources for Rails analysis.
//!
//! Two-step poll-then-upload flow, decoupled from census:
//! 1. Poll `GET /api/v1/agents/sample_requests` → list of identifiers needing samples
//! 2. For each: read lines from file, `POST /api/v1/agents/loggables/samples`
//!
//! Rails uses samples for LLM-based log format detection and parsing schema generation.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use bollard::container::LogsOptions;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::discovery::SharedDiscoveryCache;
use crate::discovery::cache::AccessMethod;
use crate::journal;
use crate::sender::Client;

/// Response from GET /api/v1/agents/sample_requests.
#[derive(Debug, Deserialize)]
pub struct SampleRequestsResponse {
    pub identifiers: Vec<SampleRequestIdentifier>,
}

#[derive(Debug, Deserialize)]
pub struct SampleRequestIdentifier {
    pub identifier: String,
    /// Minimum lines to sample (from Rails). Falls back to default if absent.
    pub min_lines: Option<usize>,
    /// Maximum lines to sample (from Rails). Falls back to default if absent.
    pub max_lines: Option<usize>,
}

/// Default sample line count when Rails doesn't specify bounds.
const DEFAULT_MAX_LINES: usize = 1000;
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(90);
const SAMPLE_FETCH_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Response from POST /api/v1/agents/loggables/samples.
#[derive(Debug, Deserialize)]
pub struct SampleUploadResponse {
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SampleCycleSummary {
    requested: usize,
    uploaded: usize,
    empty: usize,
    unreadable: usize,
    upload_failed: usize,
    outcome_report_failed: usize,
    unreadable_reasons: BTreeMap<&'static str, usize>,
}

/// Run the sample polling loop.
pub async fn run(
    client: &Client,
    discovery_cache: SharedDiscoveryCache,
    poll_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(
        interval_secs = poll_interval.as_secs(),
        "sample poller started"
    );

    let mut next_poll_delay = poll_interval;
    let mut fetch_failures = 0u32;
    let mut last_no_progress_summary: Option<SampleCycleSummary> = None;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(next_poll_delay) => {}
            _ = shutdown.changed() => {
                info!("sample poller shutting down");
                return;
            }
        }

        // Step 1: Poll for sample requests.
        let identifiers = match client.fetch_sample_requests().await {
            Ok(resp) => {
                fetch_failures = 0;
                next_poll_delay = poll_interval;
                resp.identifiers
            }
            Err(e) => {
                fetch_failures = fetch_failures.saturating_add(1);
                next_poll_delay = sample_fetch_retry_delay(fetch_failures, poll_interval);
                warn!(
                    error = %e,
                    failures = fetch_failures,
                    retry_in_secs = next_poll_delay.as_secs(),
                    "failed to fetch sample requests"
                );
                continue;
            }
        };

        if identifiers.is_empty() {
            continue;
        }

        debug!(count = identifiers.len(), "sample requests received");

        // Step 2: Upload samples for each identifier.
        let mut uploaded = 0usize;
        let mut empty = 0usize;
        let mut unreadable = 0usize;
        let mut upload_failed = 0usize;
        let mut outcome_report_failed = 0usize;
        let mut unreadable_reasons = BTreeMap::new();

        for req in &identifiers {
            let max_lines = req.max_lines.unwrap_or(DEFAULT_MAX_LINES);
            match read_sample_lines_for_identifier(&req.identifier, max_lines, &discovery_cache)
                .await
            {
                Ok(lines) if lines.is_empty() => {
                    empty += 1;
                    debug!(identifier = %req.identifier, "no lines to sample");
                    if let Err(e) = client
                        .report_sample_outcome(&req.identifier, "empty", None)
                        .await
                    {
                        outcome_report_failed += 1;
                        warn!(
                            identifier = %req.identifier,
                            error = %e,
                            "failed to report empty sample outcome"
                        );
                    }
                }
                Ok(lines) => {
                    let line_count = lines.len();
                    match client.upload_sample(&req.identifier, &lines).await {
                        Ok(resp) => {
                            uploaded += 1;
                            info!(
                                identifier = %req.identifier,
                                lines = line_count,
                                status = %resp.status,
                                "sample uploaded"
                            );
                        }
                        Err(e) => {
                            upload_failed += 1;
                            warn!(
                                identifier = %req.identifier,
                                error = %e,
                                "failed to upload sample"
                            );
                        }
                    }
                }
                Err(e) => {
                    unreadable += 1;
                    let reason = sample_error_reason(&e);
                    *unreadable_reasons.entry(reason).or_insert(0usize) += 1;
                    debug!(
                        identifier = %req.identifier,
                        error = %e,
                        "failed to read sample lines"
                    );
                    if let Err(report_err) = client
                        .report_sample_outcome(&req.identifier, "unreadable", Some(reason))
                        .await
                    {
                        outcome_report_failed += 1;
                        warn!(
                            identifier = %req.identifier,
                            error = %report_err,
                            "failed to report unreadable sample outcome"
                        );
                    }
                }
            }
        }

        let summary = SampleCycleSummary {
            requested: identifiers.len(),
            uploaded,
            empty,
            unreadable,
            upload_failed,
            outcome_report_failed,
            unreadable_reasons,
        };

        if summary.uploaded > 0 || summary.upload_failed > 0 {
            last_no_progress_summary = None;
            info!(
                requested = summary.requested,
                uploaded = summary.uploaded,
                empty = summary.empty,
                unreadable = summary.unreadable,
                upload_failed = summary.upload_failed,
                outcome_report_failed = summary.outcome_report_failed,
                "sample request cycle completed"
            );
        } else if last_no_progress_summary.as_ref() != Some(&summary) {
            info!(
                requested = summary.requested,
                uploaded = summary.uploaded,
                empty = summary.empty,
                unreadable = summary.unreadable,
                upload_failed = summary.upload_failed,
                outcome_report_failed = summary.outcome_report_failed,
                unreadable_reasons = ?summary.unreadable_reasons,
                "sample request cycle completed"
            );
            last_no_progress_summary = Some(summary);
        } else {
            debug!(
                requested = summary.requested,
                uploaded = summary.uploaded,
                empty = summary.empty,
                unreadable = summary.unreadable,
                upload_failed = summary.upload_failed,
                outcome_report_failed = summary.outcome_report_failed,
                unreadable_reasons = ?summary.unreadable_reasons,
                "sample request cycle completed"
            );
        }
    }
}

async fn read_sample_lines_for_identifier(
    identifier: &str,
    max_lines: usize,
    discovery_cache: &SharedDiscoveryCache,
) -> Result<Vec<String>, String> {
    let resolved = {
        let cache = discovery_cache.read().await;
        cache.resolve_access_method(identifier, "")
    };

    match resolved {
        Some((AccessMethod::File | AccessMethod::Kubernetes, locator)) => {
            read_file_lines(&locator, max_lines)
        }
        Some((AccessMethod::Journald, unit)) => journal::sample_unit_lines(&unit, max_lines),
        Some((AccessMethod::DockerApi, container_id)) => {
            read_docker_lines(&container_id, max_lines).await
        }
        Some((AccessMethod::WindowsEventLog, channel)) => {
            crate::windows_event_log::sample_channel_lines(&channel, max_lines).await
        }
        None => read_sample_lines(identifier, max_lines),
    }
}

/// Read up to `max_lines` of sample content for a raw identifier fallback.
///
/// Rails sends two flavors of identifier in sample requests:
///   * file paths      — "/var/log/auth.log"
///   * systemd units   — "pacer_proxy.service", "logrelay.socket", "atd.timer"
///
/// We dispatch on shape, not on an extra type field, because the wire format
/// is just a string today. Adding journald units here is what unblocks the
/// majority of loggables on a typical Linux host (file logs are the
/// minority once journald is the default sink).
fn read_sample_lines(path: &str, max_lines: usize) -> Result<Vec<String>, String> {
    if journal::is_systemd_unit(path) {
        return journal::sample_unit_lines(path, max_lines);
    }

    read_file_lines(path, max_lines)
}

fn sample_error_reason(error: &str) -> &'static str {
    let normalized = error.to_ascii_lowercase();

    if normalized.starts_with("file not found:") {
        "file_not_found"
    } else if normalized.contains("permission denied") {
        "permission_denied"
    } else if normalized.contains("docker connect failed") {
        "docker_connect_failed"
    } else if normalized.contains("no docker-compatible endpoint") {
        "docker_unavailable"
    } else if normalized.contains("docker logs failed") {
        "docker_logs_failed"
    } else if normalized.starts_with("failed to open ") {
        "file_open_failed"
    } else if normalized.contains("access is denied") || normalized.contains("error 5") {
        // wevtutil rejects a channel the agent's account can't read (e.g.
        // Security under a restricted service account).
        "access_denied"
    } else if normalized.contains("wevtutil") {
        "wevtutil_failed"
    } else {
        "other"
    }
}

async fn read_docker_lines(container_id: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let docker = match crate::discovery::docker::connect_docker() {
        Ok(Some(docker)) => docker,
        Ok(None) => return Err("no Docker-compatible endpoint configured".to_string()),
        Err(error) => return Err(format!("docker connect failed: {error}")),
    };

    let options = LogsOptions::<String> {
        follow: false,
        stdout: true,
        stderr: true,
        tail: max_lines.to_string(),
        timestamps: false,
        ..Default::default()
    };

    let mut stream = docker.logs(container_id, Some(options));
    let mut lines = Vec::new();

    while let Some(item) = stream.next().await {
        let raw = item
            .map_err(|error| format!("docker logs failed for {container_id}: {error}"))?
            .to_string();

        lines.extend(
            raw.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string),
        );
    }

    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
}

/// Read up to `max_lines` from a file for sampling.
///
/// Reads from the END of the file (most recent lines are most useful for
/// format detection). Falls back to reading from start if the file is small.
fn read_file_lines(path: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("file not found: {path}"));
    }

    let file = std::fs::File::open(file_path).map_err(|e| format!("failed to open {path}: {e}"))?;

    let reader = BufReader::new(file);
    let all_lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    // Take the last N lines (most recent).
    let start = all_lines.len().saturating_sub(max_lines);
    Ok(all_lines[start..].to_vec())
}

fn sample_fetch_retry_delay(failures: u32, poll_interval: Duration) -> Duration {
    let multiplier = 1u32 << failures.saturating_sub(1).min(4);
    poll_interval
        .saturating_mul(multiplier)
        .min(SAMPLE_FETCH_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_sample_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "line1\nline2\nline3\nline4\nline5\n").unwrap();

        let lines = read_sample_lines(path.to_str().unwrap(), 3).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line3"); // last 3 lines
        assert_eq!(lines[2], "line5");
    }

    #[test]
    fn read_sample_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.log");
        std::fs::write(&path, "only\ntwo\n").unwrap();

        let lines = read_sample_lines(path.to_str().unwrap(), 20).unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn read_sample_missing_file() {
        let result = read_sample_lines("/nonexistent/path.log", 10);
        assert!(result.is_err());
    }

    #[test]
    fn sample_error_reason_groups_common_failures() {
        assert_eq!(
            sample_error_reason("file not found: /var/log/system.log"),
            "file_not_found"
        );
        assert_eq!(
            sample_error_reason("failed to open /var/log/private.log: Permission denied"),
            "permission_denied"
        );
        assert_eq!(
            sample_error_reason("no Docker-compatible endpoint configured"),
            "docker_unavailable"
        );
        assert_eq!(
            sample_error_reason("docker connect failed: bad socket"),
            "docker_connect_failed"
        );
        assert_eq!(
            sample_error_reason("wevtutil exit 1 for Security: Access is denied."),
            "access_denied"
        );
        assert_eq!(
            sample_error_reason("wevtutil spawn failed for Application: not found"),
            "wevtutil_failed"
        );
    }

    #[test]
    fn sample_fetch_retry_delay_backs_off_and_caps() {
        let poll_interval = Duration::from_secs(30);

        assert_eq!(
            sample_fetch_retry_delay(1, poll_interval),
            Duration::from_secs(30)
        );
        assert_eq!(
            sample_fetch_retry_delay(2, poll_interval),
            Duration::from_secs(60)
        );
        assert_eq!(
            sample_fetch_retry_delay(4, poll_interval),
            Duration::from_secs(240)
        );
        assert_eq!(
            sample_fetch_retry_delay(5, poll_interval),
            SAMPLE_FETCH_BACKOFF_MAX
        );
    }
}
