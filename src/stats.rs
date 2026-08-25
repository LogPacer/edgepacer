//! Stats collection and reporting — periodic heartbeat to Rails.
//!
//! Reports liveness, eBPF state, and per-source collection status to
//! `POST /api/v1/agents/stats`. Host and agent metrics ship on the subbox
//! metrics stream, not in this heartbeat.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::{SharedConfig, effective_stats_interval, stats_reporting_enabled};
use crate::counters::{BodyVariantRegistry, BodyVariantSplit, PipelineLiveness};
use crate::discovery::cache::CollectMatch;
const DEFAULT_STATS_INTERVAL: Duration = Duration::from_secs(60);

// --- Top-level report ---

/// Stats report sent to Rails.
#[derive(Debug, Clone, Serialize)]
pub struct StatsReport {
    /// Unix timestamp in milliseconds.
    pub logtime: i64,
    /// Resource identifier (agent key).
    pub resource_id: String,
    /// Per-stream collection status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<Vec<StreamConfigStatus>>,
    // eBPF fields — defaults, present for Rails compatibility.
    #[serde(default)]
    pub ebpf_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf_kernel_version: Option<String>,
    #[serde(default)]
    pub ebpf_has_btf: bool,
    #[serde(default)]
    pub ebpf_has_cap_bpf: bool,
    #[serde(default)]
    pub ebpf_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf_last_error: Option<String>,
    #[serde(default)]
    pub ebpf_build_support: bool,
    #[serde(default)]
    pub ebpf_pids_targeted: usize,
    #[serde(default)]
    pub ebpf_cgroups_targeted: usize,
}

// --- Stream config status ---

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    #[default]
    NotStarted,
    Running,
    Failed,
}

impl PipelineStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamConfigStatus {
    pub log_source_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_via: Option<String>,
    /// How durable the match key is (explicit/strong/weak) — lets Rails tell a
    /// rock-solid match from a volatile one. Omitted when unmatched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether this matched source has a live pipeline. Additive to `status`,
    /// which retains its discovery-match meaning for existing consumers.
    pub pipeline: PipelineStatus,
    pub last_checked: String,
    /// How this stream's shipped entries split across the wire body variants,
    /// cumulative since the source started. Omitted while the source has no
    /// running pipeline (its shipper registers the counters at start).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_variants: Option<BodyVariantSplit>,
}

impl StreamConfigStatus {
    /// A status for `stream` with the given state and timestamp; match fields
    /// start empty and are filled by the caller.
    fn new(stream: &crate::config::CollectStreamConfig, status: &str, last_checked: &str) -> Self {
        Self {
            log_source_id: stream.log_source_id.clone(),
            status: status.to_string(),
            matched_via: None,
            confidence: None,
            reason: None,
            pipeline: PipelineStatus::NotStarted,
            last_checked: last_checked.to_string(),
            body_variants: None,
        }
    }
}

/// Tracks the last *delivered* stream-status snapshot so the reporter sends the
/// full array only when something actually changed — not the same miss list
/// every interval. The per-report `last_checked` timestamp is excluded from the
/// comparison so a heartbeat alone never looks like a change.
#[derive(Default)]
struct StreamStatusReporter {
    last_signature: Option<String>,
}

impl StreamStatusReporter {
    /// Plan this interval's report: the snapshot to send (None = unchanged, so
    /// omit and let Rails keep the last-known set) paired with the signature to
    /// [`commit`](Self::commit) once delivery succeeds. The signature is only
    /// committed after a successful send, so a transient failure re-sends the
    /// change next interval instead of silently dropping it.
    fn plan(
        &self,
        statuses: Option<Vec<StreamConfigStatus>>,
    ) -> (Option<Vec<StreamConfigStatus>>, Option<String>) {
        let signature = statuses.as_ref().map(|s| status_signature(s));
        if signature == self.last_signature {
            (None, signature)
        } else {
            (statuses, signature)
        }
    }

    /// Record the signature of a snapshot that was successfully delivered.
    fn commit(&mut self, signature: Option<String>) {
        self.last_signature = signature;
    }
}

/// Order-independent fingerprint of the meaningful status fields, excluding the
/// per-report `last_checked` timestamp (which always changes). The body-variant
/// counts are part of the fingerprint on purpose: a count change makes the next
/// interval's report carry the fresh split, so the control plane observes it
/// within one reporting interval — sends still only happen on the interval
/// tick, never per increment.
fn status_signature(statuses: &[StreamConfigStatus]) -> String {
    let mut lines: Vec<String> = statuses
        .iter()
        .map(|s| {
            let variants = s
                .body_variants
                .map(|v| format!("{}/{}/{}", v.entry_json, v.raw_text, v.raw_bytes))
                .unwrap_or_default();
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                s.log_source_id,
                s.status,
                s.matched_via.as_deref().unwrap_or(""),
                s.confidence.as_deref().unwrap_or(""),
                s.reason.as_deref().unwrap_or(""),
                s.pipeline.as_str(),
                variants,
            )
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

// --- Reporter loop ---

/// Run the stats reporter loop — periodically sends liveness/status to Rails.
pub async fn run(
    client: &crate::sender::Client,
    resource_id: &str,
    shared_config: SharedConfig,
    discovery_cache: crate::discovery::SharedDiscoveryCache,
    body_variants: BodyVariantRegistry,
    ebpf_status: crate::ebpf::SharedEbpfStatus,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = effective_stats_interval(&shared_config, DEFAULT_STATS_INTERVAL).await;

    info!(interval_secs = interval.as_secs(), "stats reporter started");

    let mut status_reporter = StreamStatusReporter::default();

    loop {
        let interval = effective_stats_interval(&shared_config, DEFAULT_STATS_INTERVAL).await;

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("stats reporter shutting down");
                return;
            }
        }

        if !stats_reporting_enabled(&shared_config).await {
            debug!("stats reporting disabled by config");
            continue;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let last_checked = chrono::Utc::now().to_rfc3339();
        let collected = collect_stream_status(
            &shared_config,
            &discovery_cache,
            &body_variants,
            &last_checked,
        )
        .await;
        let (stream_status, pending_signature) = status_reporter.plan(collected);

        let ebpf = ebpf_status.read().await.clone();

        let report = StatsReport {
            logtime: now_ms,
            resource_id: resource_id.to_string(),
            stream_status,
            ebpf_available: ebpf.capability.available,
            ebpf_kernel_version: ebpf.capability.kernel_version.clone(),
            ebpf_has_btf: ebpf.capability.has_btf,
            ebpf_has_cap_bpf: ebpf.capability.has_cap_bpf,
            ebpf_running: ebpf.running,
            ebpf_last_error: reported_ebpf_error(&ebpf),
            ebpf_build_support: ebpf.build_support,
            ebpf_pids_targeted: ebpf.pids_targeted,
            ebpf_cgroups_targeted: ebpf.cgroups_targeted,
        };

        // Report to Rails. Only advance the dedup signature once the snapshot is
        // actually delivered, so a transient failure re-sends it next interval.
        match client.report_stats(&report).await {
            Ok(()) => {
                status_reporter.commit(pending_signature);
                debug!("stats reported");
            }
            Err(e) => {
                warn!(error = %e, "failed to report stats");
                // Non-fatal — will retry next interval.
            }
        }
    }
}

fn reported_ebpf_error(status: &crate::ebpf::EbpfStatus) -> Option<String> {
    status
        .last_error
        .clone()
        .or_else(|| status.capability.failure_reason.clone())
}

async fn collect_stream_status(
    shared_config: &SharedConfig,
    discovery_cache: &crate::discovery::SharedDiscoveryCache,
    body_variants: &BodyVariantRegistry,
    last_checked: &str,
) -> Option<Vec<StreamConfigStatus>> {
    let collect_streams = {
        let config = shared_config.read().await;
        let config = config.as_ref()?;
        crate::config::all_collect_streams(config)
    };

    if collect_streams.is_empty() {
        return None;
    }

    let cache = discovery_cache.read().await;
    Some(
        collect_streams
            .into_iter()
            .map(|stream| {
                let mut status = stream_status_for_collect_stream(&stream, &cache, last_checked);
                let (variants, liveness) = body_variants.stream_snapshot_for(&stream.log_source_id);
                status.body_variants = variants;
                match liveness {
                    Some(PipelineLiveness::Running) => status.pipeline = PipelineStatus::Running,
                    Some(PipelineLiveness::Failed { reason }) => {
                        status.pipeline = PipelineStatus::Failed;
                        status.reason = Some(reason);
                    }
                    None => {}
                }
                status
            })
            .collect(),
    )
}

fn stream_status_for_collect_stream(
    stream: &crate::config::CollectStreamConfig,
    cache: &crate::discovery::DiscoveryCache,
    last_checked: &str,
) -> StreamConfigStatus {
    let identifier = if stream.container_identifier.is_empty() {
        stream.locator.as_str()
    } else {
        stream.container_identifier.as_str()
    };

    if stream.matching_strategy == "file_path" {
        return file_path_stream_status(stream, identifier, last_checked);
    }

    let loggable_type = crate::discovery::cache::infer_loggable_type(&stream.matching_strategy);
    status_from_match(
        stream,
        &cache.resolve(identifier, loggable_type),
        last_checked,
    )
}

fn status_from_match(
    stream: &crate::config::CollectStreamConfig,
    matched: &CollectMatch,
    last_checked: &str,
) -> StreamConfigStatus {
    match matched {
        CollectMatch::Matched(access) => StreamConfigStatus {
            matched_via: Some(access.matched_via.as_str().to_string()),
            confidence: Some(access.confidence().as_str().to_string()),
            ..StreamConfigStatus::new(stream, "collecting", last_checked)
        },
        CollectMatch::Ambiguous { candidates } => StreamConfigStatus {
            confidence: Some("weak".to_string()),
            reason: Some(format!(
                "{candidates} discovered sources matched {} ambiguously",
                stream.matching_strategy
            )),
            ..StreamConfigStatus::new(stream, "ambiguous", last_checked)
        },
        CollectMatch::NotFound => StreamConfigStatus {
            reason: Some(format!(
                "No discovered log source matched {}",
                stream.matching_strategy
            )),
            ..StreamConfigStatus::new(stream, "not_found", last_checked)
        },
    }
}

fn file_path_stream_status(
    stream: &crate::config::CollectStreamConfig,
    path: &str,
    last_checked: &str,
) -> StreamConfigStatus {
    // A file's stable identity is its path, so an exact-path check is a strong
    // match when present.
    if std::path::Path::new(path).is_file() {
        return StreamConfigStatus {
            matched_via: Some("file_path".to_string()),
            confidence: Some("strong".to_string()),
            ..StreamConfigStatus::new(stream, "collecting", last_checked)
        };
    }

    StreamConfigStatus {
        matched_via: Some("file_path".to_string()),
        reason: Some(format!("File not found: {path}")),
        ..StreamConfigStatus::new(stream, "not_found", last_checked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_stats_interval_remains_sixty_seconds() {
        assert_eq!(DEFAULT_STATS_INTERVAL, Duration::from_secs(60));
    }

    #[test]
    fn stats_report_omits_metrics_and_serializes_stream_status() {
        let report = StatsReport {
            logtime: 1_700_000_000_000,
            resource_id: "lp_test".to_string(),
            stream_status: Some(vec![StreamConfigStatus {
                log_source_id: "loggable_42".to_string(),
                status: "collecting".to_string(),
                matched_via: Some("stable_id".to_string()),
                confidence: Some("explicit".to_string()),
                reason: None,
                pipeline: PipelineStatus::Running,
                last_checked: "2026-06-22T19:30:00Z".to_string(),
                body_variants: Some(BodyVariantSplit {
                    entry_json: 12,
                    raw_text: 3,
                    raw_bytes: 1,
                }),
            }]),
            ebpf_available: false,
            ebpf_kernel_version: None,
            ebpf_has_btf: false,
            ebpf_has_cap_bpf: false,
            ebpf_running: false,
            ebpf_last_error: None,
            ebpf_build_support: false,
            ebpf_pids_targeted: 0,
            ebpf_cgroups_targeted: 2,
        };

        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            v.get("metrics").is_none(),
            "heartbeat must not carry metrics"
        );
        assert_eq!(v["stream_status"][0]["log_source_id"], "loggable_42");
        assert_eq!(v["stream_status"][0]["status"], "collecting");
        assert_eq!(v["stream_status"][0]["matched_via"], "stable_id");
        assert_eq!(v["stream_status"][0]["confidence"], "explicit");
        assert_eq!(v["stream_status"][0]["pipeline"], "running");
        assert_eq!(v["stream_status"][0]["body_variants"]["entry_json"], 12);
        assert_eq!(v["stream_status"][0]["body_variants"]["raw_text"], 3);
        assert_eq!(v["stream_status"][0]["body_variants"]["raw_bytes"], 1);
        assert_eq!(
            v["stream_status"][0]["last_checked"],
            "2026-06-22T19:30:00Z"
        );
        assert!(
            v["stream_status"][0].get("reason").is_none(),
            "empty stream status reason should be omitted"
        );

        // ebpf_kernel_version omitted when None.
        assert!(
            v.get("ebpf_kernel_version").is_none(),
            "ebpf_kernel_version should be omitted when None"
        );

        // ebpf_available:false is present (not omitted).
        assert!(
            !v["ebpf_available"].as_bool().unwrap(),
            "ebpf_available:false should be present"
        );
        assert_eq!(v["ebpf_cgroups_targeted"], 2);
    }

    #[test]
    fn report_serializes_to_json() {
        let report = StatsReport {
            logtime: 1_700_000_000_000,
            resource_id: "test".to_string(),
            stream_status: None,
            ebpf_available: false,
            ebpf_kernel_version: None,
            ebpf_has_btf: false,
            ebpf_has_cap_bpf: false,
            ebpf_running: false,
            ebpf_last_error: None,
            ebpf_build_support: false,
            ebpf_pids_targeted: 0,
            ebpf_cgroups_targeted: 0,
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"resource_id\":\"test\""));
        assert!(!json.contains("\"metrics\""));
        assert!(!json.contains("\"stream_status\""));
    }

    #[test]
    fn capability_failure_is_reported_when_capture_has_no_runtime_error() {
        let status = crate::ebpf::EbpfStatus {
            capability: crate::ebpf::EbpfCapability {
                failure_reason: Some(
                    "cgroup v2 unified mode required for eBPF capture scoping".to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            reported_ebpf_error(&status).as_deref(),
            Some("cgroup v2 unified mode required for eBPF capture scoping")
        );
    }

    #[test]
    fn runtime_error_takes_precedence_over_capability_failure() {
        let status = crate::ebpf::EbpfStatus {
            capability: crate::ebpf::EbpfCapability {
                failure_reason: Some("capability unavailable".to_string()),
                ..Default::default()
            },
            last_error: Some("listener drain failed".to_string()),
            ..Default::default()
        };

        assert_eq!(
            reported_ebpf_error(&status).as_deref(),
            Some("listener drain failed")
        );
    }

    #[test]
    fn stream_status_reports_file_path_collecting_and_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let active_path = dir.path().join("active.log");
        std::fs::write(&active_path, "line\n").unwrap();

        let config = crate::config::UnifiedConfig::new(
            json!({
                "collect": {
                    "active-file": {
                        "locator": active_path,
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "https://s/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    },
                    "missing-file": {
                        "locator": "/definitely/missing.log",
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "https://s/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    }
                }
            }),
            "etag".to_string(),
        );
        let streams = crate::config::all_collect_streams(&config);
        let cache = crate::discovery::DiscoveryCache::new();

        let statuses = streams
            .iter()
            .map(|stream| stream_status_for_collect_stream(stream, &cache, "checked"))
            .collect::<Vec<_>>();

        assert_eq!(statuses[0].status, "collecting");
        assert_eq!(statuses[0].matched_via.as_deref(), Some("file_path"));
        assert_eq!(statuses[0].confidence.as_deref(), Some("strong"));
        assert!(statuses[0].reason.is_none());
        assert_eq!(statuses[1].status, "not_found");
        assert_eq!(statuses[1].matched_via.as_deref(), Some("file_path"));
        assert!(statuses[1].confidence.is_none());
        assert_eq!(
            statuses[1].reason.as_deref(),
            Some("File not found: /definitely/missing.log")
        );
    }

    fn collect_stream(matching_strategy: &str) -> crate::config::CollectStreamConfig {
        let config = crate::config::UnifiedConfig::new(
            json!({
                "collect": {
                    "src-1": {
                        "locator": "whatever",
                        "matching_strategy": matching_strategy,
                        "subbox_endpoint": "https://s/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    }
                }
            }),
            "etag".to_string(),
        );
        crate::config::all_collect_streams(&config).pop().unwrap()
    }

    #[test]
    fn ambiguous_match_reports_weak_confidence_and_reason() {
        let stream = collect_stream("container_id");
        let status = status_from_match(&stream, &CollectMatch::Ambiguous { candidates: 3 }, "now");

        assert_eq!(status.status, "ambiguous");
        assert!(status.matched_via.is_none());
        assert_eq!(status.confidence.as_deref(), Some("weak"));
        assert!(status.reason.unwrap().contains("3 discovered sources"));
    }

    #[test]
    fn not_found_match_reports_no_confidence() {
        let stream = collect_stream("container_name");
        let status = status_from_match(&stream, &CollectMatch::NotFound, "now");

        assert_eq!(status.status, "not_found");
        assert!(status.matched_via.is_none());
        assert!(status.confidence.is_none());
    }

    fn status(id: &str, state: &str, last_checked: &str) -> StreamConfigStatus {
        StreamConfigStatus {
            log_source_id: id.to_string(),
            status: state.to_string(),
            matched_via: None,
            confidence: None,
            reason: None,
            pipeline: PipelineStatus::NotStarted,
            last_checked: last_checked.to_string(),
            body_variants: None,
        }
    }

    /// Plan a snapshot and immediately confirm delivery, returning whether the
    /// snapshot would have been sent this interval.
    fn send_ok(
        reporter: &mut StreamStatusReporter,
        statuses: Option<Vec<StreamConfigStatus>>,
    ) -> bool {
        let (payload, signature) = reporter.plan(statuses);
        let sent = payload.is_some();
        reporter.commit(signature);
        sent
    }

    #[test]
    fn reporter_sends_only_when_status_changes() {
        let mut reporter = StreamStatusReporter::default();

        // First snapshot is always sent.
        assert!(send_ok(
            &mut reporter,
            Some(vec![status("a", "not_found", "t1")])
        ));

        // Same statuses, new last_checked → unchanged → omitted.
        assert!(
            !send_ok(&mut reporter, Some(vec![status("a", "not_found", "t2")])),
            "an unchanged miss must not be resent every interval"
        );

        // A real status change → sent again.
        assert!(send_ok(
            &mut reporter,
            Some(vec![status("a", "collecting", "t3")])
        ));

        // Sources removed entirely → nothing to send, and the signature resets.
        assert!(!send_ok(&mut reporter, None));
        assert!(
            send_ok(&mut reporter, Some(vec![status("a", "collecting", "t4")])),
            "re-adding a source after it cleared must resend"
        );
    }

    #[test]
    fn reporter_sends_when_only_pipeline_liveness_changes() {
        let mut reporter = StreamStatusReporter::default();
        assert!(send_ok(
            &mut reporter,
            Some(vec![status("a", "collecting", "t1")])
        ));

        let mut running = status("a", "collecting", "t2");
        running.pipeline = PipelineStatus::Running;
        assert!(
            send_ok(&mut reporter, Some(vec![running])),
            "a pipeline transition must not be hidden by status deduplication"
        );
    }

    #[test]
    fn reporter_resends_until_delivery_is_confirmed() {
        let mut reporter = StreamStatusReporter::default();
        let snapshot = || Some(vec![status("a", "collecting", "t")]);

        // First send is planned, but delivery fails so we do NOT commit.
        let (payload, _signature) = reporter.plan(snapshot());
        assert!(payload.is_some());

        // The same snapshot must be offered again, not silently dropped.
        let (payload, signature) = reporter.plan(snapshot());
        assert!(
            payload.is_some(),
            "an unconfirmed snapshot must be retried on the next interval"
        );
        reporter.commit(signature);

        // Now that it is confirmed, an unchanged snapshot is omitted.
        let (payload, _) = reporter.plan(snapshot());
        assert!(payload.is_none());
    }

    /// Each stream's status carries its OWN split from the registry — keyed by
    /// log_source_id — and a stream that never shipped carries none.
    #[tokio::test]
    async fn collect_stream_status_attaches_each_sources_own_split() {
        let config = crate::config::UnifiedConfig::new(
            json!({
                "collect": {
                    "src-shipped": {
                        "locator": "/var/log/a.log",
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "https://s/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    },
                    "src-quiet": {
                        "locator": "/var/log/b.log",
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "https://s/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    }
                }
            }),
            "etag".to_string(),
        );
        let shared_config: SharedConfig =
            std::sync::Arc::new(tokio::sync::RwLock::new(Some(config)));
        let discovery_cache = crate::discovery::shared_discovery_cache();

        let registry = BodyVariantRegistry::default();
        registry
            .counters_for("src-shipped")
            .record(BodyVariantSplit {
                entry_json: 4,
                raw_text: 2,
                raw_bytes: 0,
            });
        registry.mark_pipeline_running("src-shipped");

        let statuses = collect_stream_status(&shared_config, &discovery_cache, &registry, "now")
            .await
            .expect("configured streams produce statuses");

        let by_id = |id: &str| {
            statuses
                .iter()
                .find(|s| s.log_source_id == id)
                .unwrap()
                .body_variants
        };
        assert_eq!(
            by_id("src-shipped"),
            Some(BodyVariantSplit {
                entry_json: 4,
                raw_text: 2,
                raw_bytes: 0,
            })
        );
        assert_eq!(
            by_id("src-quiet"),
            None,
            "a stream that never shipped reports no split — and never another stream's"
        );
    }

    #[tokio::test]
    async fn collect_stream_status_distinguishes_pipeline_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let running_path = dir.path().join("running.log");
        let failed_path = dir.path().join("failed.log");
        let never_started_path = dir.path().join("never-started.log");
        for path in [&running_path, &failed_path, &never_started_path] {
            std::fs::write(path, "line\n").unwrap();
        }

        let config = crate::config::UnifiedConfig::new(
            json!({
                "collect": {
                    "src-running": {
                        "locator": running_path,
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "http://127.0.0.1:9/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    },
                    "src-failed": {
                        "locator": failed_path,
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "http://127.0.0.1:9/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    },
                    "src-never-started": {
                        "locator": never_started_path,
                        "matching_strategy": "file_path",
                        "subbox_endpoint": "http://127.0.0.1:9/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    },
                    "src-windows": {
                        "locator": "Application",
                        "matching_strategy": "windows_event_log",
                        "subbox_endpoint": "http://127.0.0.1:9/wire",
                        "archive_id": "arc",
                        "repo_id": "repo"
                    }
                }
            }),
            "etag".to_string(),
        );
        let discovery_cache = crate::discovery::shared_discovery_cache();
        let resolved = {
            let cache = discovery_cache.read().await;
            crate::config::resolved_collect_from_config(&config, &cache)
        };

        // Force the second pipeline's state directory creation to fail after
        // discovery has successfully matched its source file.
        std::fs::write(dir.path().join("src-failed"), "not a directory").unwrap();

        let counters = crate::counters::AgentCounters::new();
        let mut orchestrator = crate::orchestrator::Orchestrator::new(
            dir.path(),
            crate::identity::AgentIdentity::new("test-agent".to_string()),
        )
        .with_monitoring(
            counters.clone(),
            std::sync::Arc::new(crate::error_collector::ErrorCollector::new()),
        );
        let attempted = resolved
            .file_streams
            .iter()
            .filter(|stream| stream.log_source_id != "src-never-started")
            .cloned()
            .collect::<Vec<_>>();
        orchestrator.reconcile(&attempted, &[], &[]).await;
        counters
            .body_variants()
            .mark_pipeline_failed("src-windows", "event log unavailable");
        let recorded_failure = match counters.body_variants().stream_snapshot_for("src-failed").1 {
            Some(PipelineLiveness::Failed { reason }) => reason,
            state => panic!("expected recorded pipeline failure, got {state:?}"),
        };

        let shared_config: SharedConfig =
            std::sync::Arc::new(tokio::sync::RwLock::new(Some(config)));
        let statuses = collect_stream_status(
            &shared_config,
            &discovery_cache,
            counters.body_variants(),
            "now",
        )
        .await
        .expect("configured streams produce statuses");
        let payload = serde_json::to_value(statuses).unwrap();
        let by_id = |id: &str| {
            payload
                .as_array()
                .unwrap()
                .iter()
                .find(|status| status["log_source_id"] == id)
                .unwrap()
                .clone()
        };

        let running = by_id("src-running");
        assert_eq!(running["status"], "collecting");
        assert_eq!(running["pipeline"], "running");
        assert!(running.get("reason").is_none());

        let failed = by_id("src-failed");
        assert_eq!(failed["status"], "collecting");
        assert_eq!(failed["pipeline"], "failed");
        assert_eq!(
            failed["reason"], recorded_failure,
            "the exact startup failure recorded by the orchestrator must reach stream_status"
        );

        let never_started = by_id("src-never-started");
        assert_eq!(never_started["status"], "collecting");
        assert_eq!(never_started["pipeline"], "not_started");
        assert!(never_started.get("reason").is_none());

        let windows = by_id("src-windows");
        assert_eq!(windows["status"], "not_found");
        assert_eq!(windows["pipeline"], "failed");
        assert_eq!(windows["reason"], "event log unavailable");

        orchestrator.shutdown_all().await;
    }

    /// Freshness contract: a body-variant count change must be observable in
    /// the next reporting interval — the change re-fingerprints the snapshot,
    /// so the periodic plan sends it. Increments between plans never trigger a
    /// send of their own; they coalesce into that one interval report.
    #[test]
    fn count_change_is_sent_on_the_next_interval_without_per_increment_resends() {
        let with_counts = |entry_json: u64, last_checked: &str| {
            let mut s = status("a", "collecting", last_checked);
            s.body_variants = Some(BodyVariantSplit {
                entry_json,
                raw_text: 0,
                raw_bytes: 0,
            });
            vec![s]
        };

        let mut reporter = StreamStatusReporter::default();
        assert!(send_ok(&mut reporter, Some(with_counts(10, "t1"))));

        // No count movement → the next interval omits the snapshot.
        assert!(
            !send_ok(&mut reporter, Some(with_counts(10, "t2"))),
            "unchanged counts must not resend every interval"
        );

        // Many increments land between plans; the single next plan carries
        // the fresh split — one send per interval, not one per increment.
        assert!(
            send_ok(&mut reporter, Some(with_counts(25, "t3"))),
            "a count change must be observable in the next reporting interval"
        );
        assert!(!send_ok(&mut reporter, Some(with_counts(25, "t4"))));
    }

    #[test]
    fn status_signature_ignores_last_checked_and_order() {
        let a = vec![
            status("x", "collecting", "t1"),
            status("y", "not_found", "t1"),
        ];
        let b = vec![
            status("y", "not_found", "t9"),
            status("x", "collecting", "t9"),
        ];
        assert_eq!(status_signature(&a), status_signature(&b));
    }
}
