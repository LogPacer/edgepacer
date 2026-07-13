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

use bollard::query_parameters::LogsOptions;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::{self, MultilineConfig, StreamAccessMethod};
use crate::discovery::SharedDiscoveryCache;
use crate::discovery::cache::AccessMethod;
use crate::entry_assembler::assemble_batch;
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

/// Resolved sampling bounds for one request.
///
/// `min_lines` is Rails' desired floor: we never withhold a short sample, but we
/// keep the field (Rails owns the sufficiency policy) instead of silently
/// dropping it, and log when a sample lands under the floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SampleBounds {
    min_lines: Option<usize>,
    max_lines: usize,
}

/// Map a wire request's optional bounds to the concrete bounds used for reading.
/// `min_lines` is preserved verbatim; `max_lines` falls back to the default.
fn sample_bounds(req: &SampleRequestIdentifier) -> SampleBounds {
    SampleBounds {
        min_lines: req.min_lines,
        max_lines: req.max_lines.unwrap_or(DEFAULT_MAX_LINES),
    }
}
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
    shared_config: config::SharedConfig,
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

        // Snapshot the active config once per cycle so per-source multiline
        // resolution mirrors the shipping pipeline without holding the config
        // lock across the network uploads below.
        let unified = shared_config.read().await.clone();

        // Step 2: Upload samples for each identifier.
        let mut uploaded = 0usize;
        let mut empty = 0usize;
        let mut unreadable = 0usize;
        let mut upload_failed = 0usize;
        let mut outcome_report_failed = 0usize;
        let mut unreadable_reasons = BTreeMap::new();

        for req in &identifiers {
            let bounds = sample_bounds(req);
            match read_sample_lines_for_identifier(
                &req.identifier,
                bounds,
                &discovery_cache,
                unified.as_ref(),
            )
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
                    if let Some(min_lines) = bounds.min_lines
                        && line_count < min_lines
                    {
                        debug!(
                            identifier = %req.identifier,
                            line_count,
                            min_lines,
                            "sample under requested floor; uploading available lines (Rails owns sufficiency)"
                        );
                    }
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
    bounds: SampleBounds,
    discovery_cache: &SharedDiscoveryCache,
    unified: Option<&config::UnifiedConfig>,
) -> Result<Vec<String>, String> {
    let max_lines = bounds.max_lines;

    // Resolve the access method and the source's multiline config under a single
    // read guard, so the sampler's extraction matches the shipping pipeline's.
    let (resolved, multiline) = {
        let cache = discovery_cache.read().await;
        let resolved = cache.resolve_access_method(identifier, "");
        let multiline = match (&resolved, unified) {
            (Some((access_method, locator)), Some(config)) => {
                resolve_multiline(config, &cache, access_method.clone(), locator)
            }
            _ => None,
        };
        (resolved, multiline)
    };

    // The sampler is one shape for every source: the shared reader seam, then
    // the same optional multiline assembler the shipper composes, then the tail
    // window (`finalize_sample`) — so the window covers whole assembled entries.
    // File-backed readers return every extracted line; streaming readers
    // (journald/docker/event-log) cap at the source since their history is not
    // rewindable, and the final tail is then a no-op for them.
    let lines = match resolved {
        Some((AccessMethod::File, locator)) => read_file_lines(&locator)?,
        Some((AccessMethod::Kubernetes, locator)) => read_kubernetes_lines(&locator)?,
        Some((AccessMethod::DockerJsonFile, locator)) => read_docker_json_file_lines(&locator)?,
        Some((AccessMethod::Journald, unit)) => journal::sample_unit_lines(&unit, max_lines)?,
        Some((AccessMethod::DockerApi, container_id)) => {
            read_docker_lines(&container_id, max_lines).await?
        }
        Some((AccessMethod::WindowsEventLog, channel)) => {
            crate::windows_event_log::sample_channel_lines(&channel, max_lines).await?
        }
        None => read_sample_lines(identifier, max_lines)?,
    };

    Ok(finalize_sample(lines, multiline.as_ref(), max_lines))
}

/// Resolve the source's multiline configuration from the active collect config,
/// matching the collect directive that resolves to the same access method and
/// locator the pipeline would tail. Returns `None` when the source is not being
/// collected (the common sample-before-collect case) or has no multiline set.
fn resolve_multiline(
    config: &config::UnifiedConfig,
    cache: &crate::discovery::cache::DiscoveryCache,
    access_method: AccessMethod,
    locator: &str,
) -> Option<MultilineConfig> {
    let streams = config::all_collect_streams(config);
    let resolved = config::resolve_collect_streams(&streams, cache);

    match access_method {
        AccessMethod::File | AccessMethod::DockerJsonFile | AccessMethod::Kubernetes => resolved
            .file_streams
            .into_iter()
            .find(|stream| stream.path == locator)
            .and_then(|stream| stream.multiline),
        AccessMethod::DockerApi => {
            resolved
                .streaming_sources
                .into_iter()
                .find_map(|stream| match stream.access_method {
                    StreamAccessMethod::DockerApi { container_id } if container_id == locator => {
                        stream.multiline
                    }
                    _ => None,
                })
        }
        AccessMethod::Journald => {
            resolved
                .streaming_sources
                .into_iter()
                .find_map(|stream| match stream.access_method {
                    StreamAccessMethod::Journald { unit } if unit == locator => stream.multiline,
                    _ => None,
                })
        }
        AccessMethod::WindowsEventLog => None,
    }
}

/// Compose the multiline assembler stage on top of the reader output, then take
/// the tail window — the sampler's counterpart to how the shipper assembles a
/// source's lines before shipping.
///
/// Assembly runs before the tail so the window covers whole assembled entries,
/// never a fragment split at the window edge. When `multiline` is `None` the
/// lines are untouched, so a non-multiline source (the negative-control plain
/// file among them) is byte-identical to a plain last-`max_lines` read. A bad
/// multiline pattern would also stop the shipping pipeline, so dropping the
/// sample there keeps the two paths consistent.
fn finalize_sample(
    lines: Vec<String>,
    multiline: Option<&MultilineConfig>,
    max_lines: usize,
) -> Vec<String> {
    let assembled = match multiline {
        None => lines,
        Some(config) => {
            let bytes: Vec<Vec<u8>> = lines.into_iter().map(String::into_bytes).collect();
            match assemble_batch(bytes, Some(config)) {
                Ok(events) => events
                    .into_iter()
                    .map(|event| String::from_utf8_lossy(&event).into_owned())
                    .collect(),
                Err(error) => {
                    warn!(%error, "invalid sample multiline pattern; skipping assembly");
                    return Vec::new();
                }
            }
        }
    };

    let start = assembled.len().saturating_sub(max_lines);
    assembled[start..].to_vec()
}

/// Read the assembled CRI messages from a Kubernetes container log directory,
/// reusing the streaming tailer's parse + partial reassembly so samples equal
/// the bare messages shipped on the wire (not raw CRI lines).
fn read_kubernetes_lines(dir: &str) -> Result<Vec<String>, String> {
    let raw = crate::container_reader::sample_lines(Path::new(dir)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("file not found: {dir}")
        } else {
            format!("failed to open {dir}: {e}")
        }
    })?;

    Ok(raw
        .into_iter()
        .map(|line| String::from_utf8_lossy(&line).into_owned())
        .collect())
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

    // Raw fallback with no resolved source has no multiline config, so it owns
    // its own tail window here rather than deferring to `finalize_sample`.
    let mut lines = read_file_lines(path)?;
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines.split_off(start))
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

    // `timestamps: true` + `parse_docker_log_line` mirrors the shipping path
    // (`docker_stream`) exactly: strip the RFC3339 prefix and only trailing
    // whitespace. The old sampler used `timestamps: false` + a full `trim`,
    // which diverged from the bytes actually shipped.
    let options = LogsOptions {
        follow: false,
        stdout: true,
        stderr: true,
        tail: max_lines.to_string(),
        timestamps: true,
        ..Default::default()
    };

    let mut stream = docker.logs(container_id, Some(options));
    let mut lines = Vec::new();

    while let Some(item) = stream.next().await {
        let raw = item
            .map_err(|error| format!("docker logs failed for {container_id}: {error}"))?
            .to_string();

        let (_, line) = crate::docker_stream::parse_docker_log_line(&raw);
        if line.is_empty() {
            continue;
        }
        lines.push(line.to_string());
    }

    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
}

/// Read every non-empty line from a file for sampling.
///
/// Reader seam only — no tail window. The caller composes the optional multiline
/// assembler and then takes the tail (`finalize_sample`), so an assembled entry
/// is never split at the window edge.
fn read_file_lines(path: &str) -> Result<Vec<String>, String> {
    read_file_lines_with(path, |line| line.to_string())
}

fn read_docker_json_file_lines(path: &str) -> Result<Vec<String>, String> {
    // Count lines that are NOT Docker-wrapped and reach the sample raw. A raw
    // line here can misclassify a plaintext app as JSON downstream, so it is a
    // signal worth surfacing rather than silently swallowing.
    let raw_fallbacks = std::cell::Cell::new(0usize);
    let lines = read_file_lines_with(path, |line| {
        match crate::cri::parse_docker_json_line(line.as_bytes()) {
            Some((payload, _)) => String::from_utf8_lossy(&payload).into_owned(),
            None => {
                raw_fallbacks.set(raw_fallbacks.get() + 1);
                line.to_string()
            }
        }
    })?;

    let raw_fallbacks = raw_fallbacks.get();
    if raw_fallbacks > 0 {
        warn!(
            path,
            raw_fallbacks,
            "docker json-file sample contained raw (non-Docker-wrapped) lines; a plaintext app here can be misclassified as JSON"
        );
    }

    Ok(lines)
}

fn read_file_lines_with(
    path: &str,
    transform: impl Fn(&str) -> String,
) -> Result<Vec<String>, String> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("file not found: {path}"));
    }

    let file = std::fs::File::open(file_path).map_err(|e| format!("failed to open {path}: {e}"))?;

    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .map_while(Result::ok)
        .map(|line| transform(&line))
        .filter(|l| !l.trim().is_empty())
        .collect())
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
    fn read_docker_json_file_sample_strips_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container-json.log");
        std::fs::write(
            &path,
            concat!(
                r#"{"log":"first\n","stream":"stdout","time":"2026-07-04T23:35:08Z"}"#,
                "\n",
                r#"{"log":"{\"level\":\"INFO\",\"msg\":\"second\"}\n","stream":"stdout","time":"2026-07-04T23:35:09Z"}"#,
                "\n",
            ),
        )
        .unwrap();

        let lines = read_docker_json_file_lines(path.to_str().unwrap()).unwrap();

        assert_eq!(lines, vec!["first", r#"{"level":"INFO","msg":"second"}"#]);
    }

    /// Kill-test extension: the docker json-file sample must strip the wrapper
    /// to exactly the bytes the shipping pipeline ships (`docker_json_wire_payload`).
    #[test]
    fn kt_docker_json_sample_matches_wire_payload() {
        let raw_lines = [
            r#"{"log":"plain line\n","stream":"stdout","time":"2026-07-04T23:35:08Z"}"#,
            r#"{"log":"{\"level\":\"INFO\",\"msg\":\"structured\"}\n","stream":"stderr","time":"2026-07-04T23:35:09Z"}"#,
        ];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container-json.log");
        std::fs::write(&path, format!("{}\n{}\n", raw_lines[0], raw_lines[1])).unwrap();

        let sample = read_docker_json_file_lines(path.to_str().unwrap()).unwrap();

        let wire: Vec<String> = raw_lines
            .iter()
            .map(|raw| {
                let payload = crate::pipeline::docker_json_wire_payload(raw.as_bytes().to_vec());
                String::from_utf8_lossy(&payload).into_owned()
            })
            .collect();

        assert_eq!(sample, wire, "sample payload must equal the wire payload");
    }

    #[test]
    fn finalize_sample_without_multiline_is_byte_identical() {
        // Negative control: a plain source with no multiline config is untouched
        // (the whole batch fits inside the window).
        let lines = vec![
            "2026-07-13 first".to_string(),
            "    indented body".to_string(),
            "2026-07-13 second".to_string(),
        ];
        assert_eq!(finalize_sample(lines.clone(), None, 1000), lines);
    }

    /// Drive the shipper's assembler (`EntryAssembler`, the component both the
    /// streaming wrapper and the pipeline wrap) over `lines`, exactly as the wire
    /// does. The multiline kill-test asserts the sample against THIS, not against
    /// hand-written strings, so any drift in joining semantics is caught.
    fn shipper_assembled(cfg: &MultilineConfig, lines: &[String]) -> Vec<String> {
        use crate::entry_assembler::{DEFAULT_TIMEOUT, EntryAssembler, LineContext};

        let mut asm =
            EntryAssembler::new(&cfg.start_pattern, cfg.max_lines as usize, DEFAULT_TIMEOUT)
                .unwrap();
        let mut events = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let ctx = LineContext {
                start_offset: i as u64,
                end_offset: i as u64 + 1,
                inode: 0,
            };
            if let Some((event, _)) = asm.process(line.clone().into_bytes(), ctx) {
                events.push(String::from_utf8_lossy(&event).into_owned());
            }
        }
        if let Some((event, _)) = asm.flush() {
            events.push(String::from_utf8_lossy(&event).into_owned());
        }
        events
    }

    /// Kill-test: a source with multiline config yields assembled entries in the
    /// sample, byte-identical to what the shipper's assembler produces for the
    /// same reader lines. Before the fix the sampler had no assembly, so the
    /// sample shipped the raw split lines the analyzer chokes on.
    #[test]
    fn kt_multiline_source_samples_assembled_entries() {
        let cfg = MultilineConfig {
            start_pattern: r"^\d{4}-\d{2}-\d{2}".to_string(),
            max_lines: 500,
            timeout_secs: 5,
        };
        let lines = vec![
            "2026-07-13 INFO request received".to_string(),
            "    header: value".to_string(),
            "    body line".to_string(),
            "2026-07-13 INFO request done".to_string(),
        ];

        let sample = finalize_sample(lines.clone(), Some(&cfg), 1000);

        assert_eq!(sample, shipper_assembled(&cfg, &lines));
    }

    /// The tail window covers whole assembled entries: assembly runs before the
    /// tail, so a `max_lines` cap keeps the last N complete events — never the
    /// last N raw lines that would split an event at the window edge.
    #[test]
    fn finalize_sample_tails_assembled_entries_not_raw_lines() {
        let cfg = MultilineConfig {
            start_pattern: r"^\d{4}-\d{2}-\d{2}".to_string(),
            max_lines: 500,
            timeout_secs: 5,
        };
        // Three events, each a header plus one continuation line.
        let lines = vec![
            "2026-07-13 one".to_string(),
            "    body one".to_string(),
            "2026-07-13 two".to_string(),
            "    body two".to_string(),
            "2026-07-13 three".to_string(),
            "    body three".to_string(),
        ];

        let sample = finalize_sample(lines, Some(&cfg), 2);

        assert_eq!(
            sample,
            vec![
                "2026-07-13 two\n    body two".to_string(),
                "2026-07-13 three\n    body three".to_string(),
            ],
            "tail keeps the last 2 complete events, not the last 2 raw lines"
        );
    }

    #[test]
    fn sample_bounds_round_trips_min_lines() {
        // min_lines used to be deserialized and never read; it must now reach the
        // sampling call verbatim, with max defaulting when Rails omits it.
        let with_both = SampleRequestIdentifier {
            identifier: "x".to_string(),
            min_lines: Some(25),
            max_lines: Some(400),
        };
        assert_eq!(
            sample_bounds(&with_both),
            SampleBounds {
                min_lines: Some(25),
                max_lines: 400,
            }
        );

        let min_only = SampleRequestIdentifier {
            identifier: "y".to_string(),
            min_lines: Some(10),
            max_lines: None,
        };
        assert_eq!(
            sample_bounds(&min_only),
            SampleBounds {
                min_lines: Some(10),
                max_lines: DEFAULT_MAX_LINES,
            }
        );
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
