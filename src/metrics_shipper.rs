//! Metrics shipper — encodes metric snapshots and POSTs them to LogRelay.
//!
//! Ships both series in one snapshot via the routed logpacer-wire protocol:
//! `host_*` (the machine) and `agent_*` (edgepacer's own footprint), explicitly
//! prefixed. Collection and durable buffering live in `metrics_pipeline.rs`;
//! this module handles encode + HTTP transport.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use logpacer_wire::{WireMetricBatch, routed_batch};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::common::EdgepacerError;
use crate::config::{self, MetricsStreamConfig, SharedConfig};
use crate::counters::{AgentCounters, CountersSnapshot};
use crate::host_metrics::{HostMetrics, MetricsCollector};
use crate::identity::AgentIdentity;
use crate::metrics_pipeline::{MetricsPipeline, MetricsPipelineConfig};
use crate::retry::RetryPolicy;
use crate::shipper::{
    WireTransport, WireTransportPolicy, checked_wire_count, encode_single_batch,
    unix_epoch_millis_i64,
};
pub type MetricsShipResult = crate::shipper::ShipResult;

/// Ships host metrics snapshots to LogRelay as protobuf.
pub struct MetricsShipper {
    transport: WireTransport,
    archive_id: String,
    repo_id: String,
    /// Host metrics always carry the agent's identity (read live from the shared
    /// cell at snapshot time), so a logpacer re-pin is reflected on the next
    /// snapshot. Unlike logs, metrics have no opt-in flag — identity is mandatory.
    identity: AgentIdentity,
    retry_policy: RetryPolicy,
}

impl MetricsShipper {
    pub fn new(
        subbox_endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        identity: AgentIdentity,
    ) -> Result<Self, EdgepacerError> {
        Ok(Self {
            transport: WireTransport::new(subbox_endpoint, repo_id)?,
            archive_id: archive_id.to_string(),
            repo_id: repo_id.to_string(),
            identity,
            retry_policy: RetryPolicy {
                max_attempts: 5,
                ..Default::default()
            },
        })
    }

    pub fn with_counters(
        subbox_endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        identity: AgentIdentity,
        counters: Arc<AgentCounters>,
    ) -> Result<Self, EdgepacerError> {
        let mut shipper = Self::new(subbox_endpoint, archive_id, repo_id, identity)?;
        shipper.transport = shipper.transport.with_counters(counters);
        Ok(shipper)
    }

    /// Flatten a prebuilt metrics map (host_* + agent_*) into JSON bytes for
    /// buffering/shipping.
    pub fn snapshot_bytes(
        &self,
        metrics: &HashMap<String, f64>,
    ) -> Result<Vec<u8>, EdgepacerError> {
        let now_ms = unix_epoch_millis_i64();
        Ok(flatten_metrics_snapshot(now_ms, &self.identity.current(), metrics)?.into_bytes())
    }

    /// Encode buffered JSON snapshots into a routed WireRequest payload.
    pub fn encode_batch(
        &self,
        entries_json: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, u32), EdgepacerError> {
        if entries_json.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let count = checked_wire_count("metrics snapshots", entries_json.len())?;
        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Metrics(WireMetricBatch { entries_json }),
        )?;

        debug!(
            entries = count,
            bytes = encoded.len(),
            "encoded metrics batch"
        );
        Ok((encoded, count))
    }

    /// Ship a metrics snapshot directly (encode + send). Prefer buffering via
    /// `MetricsPipeline` for durable delivery.
    pub async fn ship_metrics(&self, metrics: &HashMap<String, f64>) -> Result<(), EdgepacerError> {
        let entry = self.snapshot_bytes(metrics)?;
        let (encoded, _) = self.encode_batch(vec![entry])?;
        self.send_with_retry(&encoded).await.map(|_| ())
    }

    /// Send pre-encoded bytes with retry policy.
    pub async fn send_with_retry(
        &self,
        encoded: &[u8],
    ) -> Result<MetricsShipResult, EdgepacerError> {
        self.transport
            .send_with_retry(
                encoded,
                self.retry_policy,
                WireTransportPolicy::metrics_batches(),
            )
            .await
    }
}

/// Flatten a metrics snapshot into LogPacer ingest-compatible flat JSON bytes.
fn flatten_metrics_snapshot(
    logtime: i64,
    resource_id: &str,
    metrics: &HashMap<String, f64>,
) -> Result<String, EdgepacerError> {
    let mut map = serde_json::Map::new();
    map.insert(
        "logtime".to_string(),
        serde_json::Value::Number(logtime.into()),
    );
    map.insert(
        "resource_id".to_string(),
        serde_json::Value::String(resource_id.to_string()),
    );
    for (key, value) in metrics {
        map.insert(
            key.clone(),
            serde_json::Number::from_f64(*value)
                .map(serde_json::Value::Number)
                .ok_or_else(|| EdgepacerError::InvalidMetricValue {
                    metric: key.clone(),
                })?,
        );
    }
    Ok(serde_json::Value::Object(map).to_string())
}

/// Largest integer an `f64` can represent without loss (2^53). A
/// file-descriptor ceiling above this isn't a real limit: modern Linux reports
/// an effectively-unlimited `fs.file-max` as `i64::MAX`, which casts to a
/// ~9.2e18 float that downstream columnar float encoders reject as a bad
/// decimal. Anything past this threshold is treated as "unlimited".
const FD_LIMIT_F64_MAX_EXACT: i64 = 1 << 53;

/// Normalize a raw `fd_max` into an encoder-safe metric value.
///
/// The "unlimited" sentinel collapses to `0` (the conventional "no limit"
/// marker) so the `fd_limit` column stays present and finite on every
/// collection rather than emitting a 19-digit magnitude that breaks the
/// downstream float page-column encoder.
fn fd_limit_metric(fd_max: i64) -> f64 {
    if fd_max > FD_LIMIT_F64_MAX_EXACT {
        0.0
    } else {
        fd_max as f64
    }
}

/// Flatten host metrics into `host_*`-prefixed keys for the unified metrics
/// snapshot. The agent's own footprint ships in the same snapshot under `agent_*`
/// (see [`agent_metrics_to_map`]), so both series are explicit and unambiguous on
/// the subbox: `host_cpu_percent` is the machine, `agent_cpu_percent` is edgepacer
/// itself. logpacer's charts subscribe to these prefixed keys.
pub(crate) fn host_metrics_to_map(host: &HostMetrics) -> HashMap<String, f64> {
    [
        // CPU + load
        ("cpu_percent", host.cpu_percent),
        ("load_avg_1", host.load_avg_1),
        ("load_avg_5", host.load_avg_5),
        ("load_avg_15", host.load_avg_15),
        // Memory
        ("memory_used_mb", host.memory_used_mb as f64),
        ("memory_total_mb", host.memory_total_mb as f64),
        ("memory_percent", host.memory_percent),
        // Disk usage
        ("disk_used_gb", host.disk_used_gb),
        ("disk_total_gb", host.disk_total_gb),
        ("disk_used_percent", host.disk_used_percent),
        // Disk I/O
        ("disk_read_bytes_per_sec", host.disk_read_bytes_per_sec),
        ("disk_write_bytes_per_sec", host.disk_write_bytes_per_sec),
        ("disk_read_ops_per_sec", host.disk_read_ops_per_sec),
        ("disk_write_ops_per_sec", host.disk_write_ops_per_sec),
        // Network I/O
        ("net_recv_bytes_per_sec", host.net_recv_bytes_per_sec),
        ("net_sent_bytes_per_sec", host.net_sent_bytes_per_sec),
        ("net_recv_pkts_per_sec", host.net_recv_packets_per_sec),
        ("net_sent_pkts_per_sec", host.net_sent_packets_per_sec),
        // Process stats
        ("process_total", host.processes_total as f64),
        ("process_running", host.processes_running as f64),
        ("process_sleeping", host.processes_sleeping as f64),
        ("process_zombie", host.processes_zombie as f64),
        // TCP stats
        ("tcp_established", host.tcp_established as f64),
        ("tcp_time_wait", host.tcp_time_wait as f64),
        ("tcp_close_wait", host.tcp_close_wait as f64),
        // File descriptors
        ("fd_open", host.fd_open as f64),
        ("fd_limit", fd_limit_metric(host.fd_max)),
    ]
    .into_iter()
    .map(|(key, value)| (format!("host_{key}"), value))
    .collect()
}

/// Flatten edgepacer's own footprint into `agent_*`-prefixed keys, shipped in the
/// same snapshot as the host metrics so the subbox carries both series. Values
/// come from the shared counters, the process collector, and agent uptime — not
/// from `HostMetrics`.
pub(crate) fn agent_metrics_to_map(
    counters: &CountersSnapshot,
    errors_last_hour: u32,
    process_cpu_percent: f64,
    process_memory_mb: u64,
    uptime_secs: u64,
) -> HashMap<String, f64> {
    [
        ("cpu_percent", process_cpu_percent),
        ("memory_mb", process_memory_mb as f64),
        ("uptime_seconds", uptime_secs as f64),
        ("queue_depth_bytes", counters.queue_depth_bytes as f64),
        ("bytes_sent", counters.bytes_sent as f64),
        ("streams_active", counters.streams_active as f64),
        ("samples_pending", counters.samples_pending as f64),
        ("samples_completed", counters.samples_completed as f64),
        ("errors_last_hour", errors_last_hour as f64),
    ]
    .into_iter()
    .map(|(key, value)| (format!("agent_{key}"), value))
    .collect()
}

fn sanitize_id(id: &str) -> String {
    id.replace(['/', '\\', ':', '.'], "_")
}

fn open_pipelines(
    configs: &[MetricsStreamConfig],
    identity: &AgentIdentity,
    data_dir: &Path,
    counters: Arc<AgentCounters>,
) -> Vec<MetricsPipeline> {
    configs
        .iter()
        .filter_map(|cfg| {
            let shipper = match MetricsShipper::with_counters(
                &cfg.subbox_endpoint,
                &cfg.archive_id,
                &cfg.repo_id,
                identity.clone(),
                counters.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        metric_source_id = %cfg.metric_source_id,
                        error = %e,
                        "failed to create metrics shipper"
                    );
                    return None;
                }
            };

            let source_dir = data_dir.join(sanitize_id(&cfg.metric_source_id));
            match MetricsPipeline::open(
                &cfg.metric_source_id,
                &source_dir,
                shipper,
                MetricsPipelineConfig::default(),
            ) {
                Ok(mut p) => {
                    p.set_queue_gauge(counters.queue_depth_gauge());
                    Some(p)
                }
                Err(e) => {
                    warn!(
                        metric_source_id = %cfg.metric_source_id,
                        error = %e,
                        "failed to open metrics pipeline"
                    );
                    None
                }
            }
        })
        .collect()
}

/// Run the metrics loop — collects host metrics, buffers durably, drains to LogRelay.
pub async fn run(
    shared_config: SharedConfig,
    identity: AgentIdentity,
    data_dir: &Path,
    counters: Arc<AgentCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let configs = loop {
        let streams = {
            let guard = shared_config.read().await;
            guard.as_ref().map(config::all_metrics_streams)
        };

        match streams {
            Some(s) if !s.is_empty() => break s,
            Some(_) => {
                info!("no metrics streams configured, metrics shipper idle");
                return;
            }
            None => {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => continue,
                    _ = shutdown.changed() => return,
                }
            }
        }
    };

    info!(
        count = configs.len(),
        "metrics pipeline starting for {} stream(s)",
        configs.len()
    );

    let mut collector = MetricsCollector::new();
    let _ = collector.collect();
    let start_time = Instant::now();

    let mut pipelines = open_pipelines(&configs, &identity, data_dir, counters.clone());
    if pipelines.is_empty() {
        warn!("no metrics pipelines could be created");
        return;
    }

    let collect_interval = configs
        .iter()
        .map(|cfg| cfg.send_interval_secs)
        .min()
        .unwrap_or(10);

    let pipeline_config = MetricsPipelineConfig::default();
    let mut collect_tick = tokio::time::interval(Duration::from_secs(collect_interval));
    let mut drain_tick = tokio::time::interval(pipeline_config.drain_interval);
    collect_tick.tick().await;
    drain_tick.tick().await;

    loop {
        tokio::select! {
            _ = collect_tick.tick() => {
                // One snapshot carries both series: host_* (the machine) and
                // agent_* (edgepacer's own footprint), explicitly prefixed.
                let host = collector.collect();
                let (agent_cpu, agent_mem_mb) = collector.collect_process_metrics();
                let mut metrics = host_metrics_to_map(&host);
                metrics.extend(agent_metrics_to_map(
                    &counters.snapshot(),
                    counters.errors_last_hour(),
                    agent_cpu,
                    agent_mem_mb,
                    start_time.elapsed().as_secs(),
                ));
                for pipeline in &mut pipelines {
                    match pipeline.enqueue_metrics(&metrics) {
                        Ok(false) => {
                            warn!("metrics snapshot dropped due to buffer backpressure");
                        }
                        Err(e) => {
                            counters.increment_errors();
                            warn!(error = %e, "failed to buffer metrics snapshot");
                        }
                        Ok(true) => {}
                    }
                }
            }
            _ = drain_tick.tick() => {
                for pipeline in &mut pipelines {
                    pipeline.drain_cycle().await;
                }
            }
            _ = shutdown.changed() => {
                info!("metrics pipeline shutting down");
                for pipeline in &mut pipelines {
                    pipeline.shutdown_drain().await;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logpacer_wire::{WireRequest, WireResponse, routed_batch};
    use prost::Message;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn encoded_wire_response(accepted: u32, rejected: u32, error_message: &str) -> Vec<u8> {
        let response = WireResponse {
            accepted,
            rejected,
            error_message: error_message.to_string(),
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn host_metrics_to_map_includes_all_fields() {
        let host = HostMetrics {
            cpu_percent: 42.5,
            memory_used_mb: 8192,
            memory_total_mb: 16384,
            memory_percent: 50.0,
            load_avg_1: 1.5,
            load_avg_5: 1.2,
            load_avg_15: 0.9,
            disk_used_gb: 100.0,
            disk_total_gb: 500.0,
            disk_used_percent: 20.0,
            disk_read_bytes_per_sec: 1024.0,
            disk_write_bytes_per_sec: 2048.0,
            disk_read_ops_per_sec: 10.0,
            disk_write_ops_per_sec: 20.0,
            net_recv_bytes_per_sec: 5000.0,
            net_sent_bytes_per_sec: 3000.0,
            net_recv_packets_per_sec: 100.0,
            net_sent_packets_per_sec: 80.0,
            processes_total: 200,
            processes_running: 5,
            processes_sleeping: 190,
            processes_idle: 3,
            processes_zombie: 2,
            tcp_established: 50,
            tcp_time_wait: 10,
            tcp_close_wait: 2,
            fd_open: 1000,
            fd_max: 65536,
        };

        let map = host_metrics_to_map(&host);

        assert_eq!(map.len(), 27);
        assert!(map.keys().all(|k| k.starts_with("host_")));
        assert_eq!(map["host_cpu_percent"], 42.5);
        assert_eq!(map["host_memory_used_mb"], 8192.0);
        assert_eq!(map["host_memory_total_mb"], 16384.0);
        assert_eq!(map["host_load_avg_1"], 1.5);
        assert_eq!(map["host_fd_open"], 1000.0);
        assert_eq!(map["host_fd_limit"], 65536.0);
        assert_eq!(map["host_process_zombie"], 2.0);
        assert_eq!(map["host_tcp_established"], 50.0);
    }

    #[test]
    fn agent_metrics_to_map_prefixes_footprint() {
        let counters = CountersSnapshot {
            bytes_sent: 5000,
            errors_total: 2,
            queue_depth_bytes: 1024,
            streams_active: 3,
            samples_pending: 1,
            samples_completed: 4,
        };

        let map = agent_metrics_to_map(&counters, 7, 12.5, 64, 300);

        assert_eq!(map.len(), 9);
        assert!(map.keys().all(|k| k.starts_with("agent_")));
        assert_eq!(map["agent_cpu_percent"], 12.5);
        assert_eq!(map["agent_memory_mb"], 64.0);
        assert_eq!(map["agent_uptime_seconds"], 300.0);
        assert_eq!(map["agent_bytes_sent"], 5000.0);
        assert_eq!(map["agent_errors_last_hour"], 7.0);
    }

    #[test]
    fn fd_limit_metric_normalizes_unlimited_sentinel() {
        // A real, finite limit passes through unchanged.
        assert_eq!(fd_limit_metric(65536), 65536.0);
        // The "unlimited" sentinel (i64::MAX, e.g. fs.file-max on modern Linux)
        // would cast to ~9.2e18 and break the downstream float column encoder —
        // it must normalize to 0.
        assert_eq!(fd_limit_metric(i64::MAX), 0.0);
        // Boundary: the largest f64-exact integer is still treated as a real limit.
        assert_eq!(
            fd_limit_metric(FD_LIMIT_F64_MAX_EXACT),
            FD_LIMIT_F64_MAX_EXACT as f64
        );
        // Just past it collapses to the unlimited marker.
        assert_eq!(fd_limit_metric(FD_LIMIT_F64_MAX_EXACT + 1), 0.0);
    }

    #[test]
    fn flatten_metrics_snapshot_rejects_non_finite_values_by_variant() {
        let metrics = HashMap::from([("bad_metric".to_string(), f64::NAN)]);
        let error = flatten_metrics_snapshot(1, "host-1", &metrics).unwrap_err();

        assert!(matches!(
            error,
            EdgepacerError::InvalidMetricValue { metric } if metric == "bad_metric"
        ));
    }

    #[test]
    fn encode_wire_request_with_metrics_payload() {
        let shipper = MetricsShipper::new(
            "http://localhost:8080",
            "arc_test",
            "repo_test",
            crate::identity::AgentIdentity::new("agent-123".into()),
        )
        .unwrap();

        let mut metrics = HashMap::new();
        metrics.insert("cpu_percent".into(), 42.5);
        let entry_json =
            flatten_metrics_snapshot(1_700_000_000_000, "agent-123", &metrics).unwrap();

        let (buf, count) = shipper.encode_batch(vec![entry_json.into_bytes()]).unwrap();
        assert_eq!(count, 1);
        assert!(!buf.is_empty());

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.batches[0].archive_id, "arc_test");
        let Some(routed_batch::Payload::Metrics(metrics_batch)) = &decoded.batches[0].payload
        else {
            panic!("expected routed metrics payload");
        };
        let value: serde_json::Value =
            serde_json::from_slice(&metrics_batch.entries_json[0]).unwrap();
        assert_eq!(value["resource_id"], "agent-123");
        assert_eq!(value["cpu_percent"], 42.5);
    }

    #[tokio::test]
    async fn send_with_retry_returns_rejected_for_partial_wire_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                encoded_wire_response(1, 1, "one metrics snapshot rejected"),
                "application/x-protobuf",
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let shipper = MetricsShipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_test",
            "repo_test",
            crate::identity::AgentIdentity::new("agent-123".into()),
        )
        .unwrap();

        let result = shipper.send_with_retry(b"encoded payload").await.unwrap();

        let MetricsShipResult::Rejected {
            accepted,
            rejected,
            message,
        } = result
        else {
            panic!("expected rejected metrics result");
        };
        assert_eq!(accepted, 1);
        assert_eq!(rejected, 1);
        assert_eq!(message, "one metrics snapshot rejected");
    }

    #[tokio::test]
    async fn send_with_retry_attaches_cached_upload_token() {
        crate::upload_token_store::store().replace(HashMap::from([
            ("repo_shipper_auth".to_string(), "jwt-log".to_string()),
            ("repo_metrics_auth".to_string(), "jwt-metrics".to_string()),
            ("repo_trace_auth".to_string(), "jwt-trace".to_string()),
        ]));

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .and(header("authorization", "Bearer jwt-metrics"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let shipper = MetricsShipper::new(
            &format!("{}/wire", server.uri()),
            "arc_metrics_auth",
            "repo_metrics_auth",
            crate::identity::AgentIdentity::new("agent-123".into()),
        )
        .unwrap();
        let mut metrics = HashMap::new();
        metrics.insert("cpu_percent".into(), 42.5);
        let entry_json =
            flatten_metrics_snapshot(1_700_000_000_000, "agent-123", &metrics).unwrap();
        let (encoded, _) = shipper.encode_batch(vec![entry_json.into_bytes()]).unwrap();

        let result = shipper.send_with_retry(&encoded).await.unwrap();

        match result {
            MetricsShipResult::Accepted { count } => assert_eq!(count, 1),
            other => panic!("expected Accepted, got {:?}", other),
        }
    }
}
