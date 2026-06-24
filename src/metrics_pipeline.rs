//! Guaranteed delivery pipeline for host metrics snapshots.
//!
//! Flow: collect → enqueue to disk buffer → drain loop ships → delete on ack
//!
//! The buffer is the replay authority — snapshots are persisted before the
//! collect cycle returns. On crash, unacked entries are replayed on restart.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, error, info, warn};

use crate::buffer::DiskBuffer;
use crate::common::EdgepacerError;
use crate::host_metrics::HostMetrics;
use crate::metrics_shipper::{MetricsShipResult, MetricsShipper};

/// Configuration for the metrics delivery pipeline.
pub struct MetricsPipelineConfig {
    /// How often to drain the buffer and ship batches.
    pub drain_interval: Duration,
    /// Maximum snapshots to ship per drain cycle.
    pub ship_batch_size: usize,
    /// Maximum buffer size in MB.
    pub buffer_max_mb: u64,
}

impl Default for MetricsPipelineConfig {
    fn default() -> Self {
        Self {
            drain_interval: Duration::from_millis(50),
            ship_batch_size: 10,
            buffer_max_mb: 50,
        }
    }
}

/// Disk-backed metrics pipeline for a single metrics stream.
pub struct MetricsPipeline {
    buffer: DiskBuffer,
    shipper: MetricsShipper,
    config: MetricsPipelineConfig,
    metric_source_id: String,
    blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetricsDrainOutcome {
    Delivered {
        count: usize,
    },
    Rejected {
        accepted: u32,
        rejected: u32,
        message: String,
    },
    Deferred {
        reason: MetricsDeferredReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetricsDeferredReason {
    AcceptedCountMismatch { accepted: u32, requested: usize },
    ShipFailed(String),
}

/// Errors from the metrics pipeline.
#[derive(Debug, thiserror::Error)]
pub enum MetricsPipelineError {
    #[error("buffer: {0}")]
    Buffer(#[from] crate::buffer::BufferError),
    #[error("shipper: {0}")]
    Shipper(#[from] crate::common::EdgepacerError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl MetricsPipeline {
    /// Open a metrics pipeline for a stream.
    pub fn open(
        metric_source_id: &str,
        data_dir: &Path,
        shipper: MetricsShipper,
        config: MetricsPipelineConfig,
    ) -> Result<Self, MetricsPipelineError> {
        std::fs::create_dir_all(data_dir)?;

        let buf_path = data_dir.join("metrics_buffer.sqlite");
        let buffer = DiskBuffer::open(&buf_path, config.buffer_max_mb)?;

        let buffered = buffer.count().unwrap_or(0);
        if buffered > 0 {
            info!(
                metric_source_id,
                buffered, "replaying unacked metrics snapshots from previous session"
            );
        }

        Ok(Self {
            buffer,
            shipper,
            config,
            metric_source_id: metric_source_id.to_string(),
            blocked: false,
        })
    }

    /// Attach the shared queue-depth gauge to this pipeline's durable buffer.
    pub fn set_queue_gauge(&mut self, gauge: crate::counters::QueueDepthGauge) {
        self.buffer.set_gauge(gauge);
    }

    /// Persist a metrics snapshot (host_* + agent_*) to the disk buffer.
    ///
    /// Returns `true` if enqueued, `false` if blocked due to backpressure.
    pub fn enqueue_metrics(
        &mut self,
        metrics: &HashMap<String, f64>,
    ) -> Result<bool, MetricsPipelineError> {
        if self.blocked {
            return Ok(false);
        }

        let entry = self.shipper.snapshot_bytes(metrics)?;
        let timestamp_ns = now_nanos();

        match self.buffer.enqueue_batch(&[entry], timestamp_ns) {
            Ok(_) => {
                debug!(metric_source_id = %self.metric_source_id, "metrics snapshot buffered");
                Ok(true)
            }
            Err(crate::buffer::BufferError::Full { .. }) => {
                warn!(
                    metric_source_id = %self.metric_source_id,
                    "metrics buffer full, pausing collection"
                );
                self.blocked = true;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Persist a host-only snapshot (`host_*`-prefixed). Convenience over
    /// [`Self::enqueue_metrics`] for callers holding a `HostMetrics` directly.
    pub fn enqueue_host_metrics(
        &mut self,
        host: &HostMetrics,
    ) -> Result<bool, MetricsPipelineError> {
        self.enqueue_metrics(&crate::metrics_shipper::host_metrics_to_map(host))
    }

    /// Drain buffered snapshots: peek → encode → ship → delete on ack.
    pub async fn drain_cycle(&mut self) {
        let entries = match self.buffer.peek(self.config.ship_batch_size) {
            Ok(e) if e.is_empty() => {
                if self.blocked {
                    info!(
                        metric_source_id = %self.metric_source_id,
                        "metrics buffer drained, resuming collection"
                    );
                    self.blocked = false;
                }
                return;
            }
            Ok(e) => e,
            Err(e) => {
                error!(
                    metric_source_id = %self.metric_source_id,
                    error = %e,
                    "metrics buffer peek failed"
                );
                return;
            }
        };

        let (payloads, sequences): (Vec<Vec<u8>>, Vec<u64>) =
            entries.into_iter().map(|e| (e.data, e.sequence)).unzip();

        let (encoded, count) = match self.shipper.encode_batch(payloads) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    metric_source_id = %self.metric_source_id,
                    error = %e,
                    "failed to encode metrics batch"
                );
                return;
            }
        };

        match self.ship_encoded_batch(&encoded, count as usize).await {
            MetricsDrainOutcome::Delivered { count } => {
                if let Err(e) = self.buffer.delete_sequences(&sequences[..count]) {
                    error!(
                        metric_source_id = %self.metric_source_id,
                        error = %e,
                        "failed to delete acked metrics snapshots"
                    );
                    return;
                }

                if self.blocked && self.buffer.pressure() < 0.9 {
                    info!(
                        metric_source_id = %self.metric_source_id,
                        "metrics buffer pressure released, resuming collection"
                    );
                    self.blocked = false;
                }
            }
            MetricsDrainOutcome::Rejected {
                accepted,
                rejected,
                message,
            } => {
                warn!(
                    metric_source_id = %self.metric_source_id,
                    accepted,
                    rejected,
                    error = %message,
                    "metrics batch rejected, will retry on next drain cycle"
                );
            }
            MetricsDrainOutcome::Deferred { reason } => {
                warn!(
                    metric_source_id = %self.metric_source_id,
                    reason = ?reason,
                    "metrics ship deferred, will retry on next drain cycle"
                );
            }
        }
    }

    async fn ship_encoded_batch(&self, encoded: &[u8], requested: usize) -> MetricsDrainOutcome {
        match self.shipper.send_with_retry(encoded).await {
            Ok(MetricsShipResult::Accepted { count }) if count as usize == requested => {
                MetricsDrainOutcome::Delivered { count: requested }
            }
            Ok(MetricsShipResult::Accepted { count }) => MetricsDrainOutcome::Deferred {
                reason: MetricsDeferredReason::AcceptedCountMismatch {
                    accepted: count,
                    requested,
                },
            },
            Ok(MetricsShipResult::Rejected {
                accepted,
                rejected,
                message,
            }) => MetricsDrainOutcome::Rejected {
                accepted,
                rejected,
                message,
            },
            Err(e) => self.metrics_ship_failed(e),
        }
    }

    fn metrics_ship_failed(&self, error: EdgepacerError) -> MetricsDrainOutcome {
        error!(
            metric_source_id = %self.metric_source_id,
            error = %error,
            "metrics ship failed"
        );
        MetricsDrainOutcome::Deferred {
            reason: MetricsDeferredReason::ShipFailed(error.to_string()),
        }
    }

    /// Drain remaining buffered snapshots on shutdown.
    pub async fn shutdown_drain(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        while !self.buffer.is_empty().unwrap_or(true) {
            if tokio::time::Instant::now() >= deadline {
                let remaining = self.buffer.count().unwrap_or(0);
                warn!(
                    metric_source_id = %self.metric_source_id,
                    remaining,
                    "metrics shutdown deadline, unshipped snapshots remain"
                );
                break;
            }
            self.drain_cycle().await;
        }

        info!(
            metric_source_id = %self.metric_source_id,
            "metrics pipeline stopped"
        );
    }

    /// Approximate bytes currently buffered (for stats queue_depth).
    pub fn buffer_bytes(&self) -> u64 {
        self.buffer.current_bytes()
    }
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_metrics::HostMetrics;
    use logpacer_wire::WireResponse;
    use prost::Message;
    use wiremock::matchers::{method, path};
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

    fn sample_host() -> HostMetrics {
        HostMetrics {
            cpu_percent: 10.0,
            memory_used_mb: 1024,
            memory_total_mb: 4096,
            memory_percent: 25.0,
            load_avg_1: 0.5,
            load_avg_5: 0.4,
            load_avg_15: 0.3,
            disk_used_gb: 50.0,
            disk_total_gb: 200.0,
            disk_used_percent: 25.0,
            disk_read_bytes_per_sec: 0.0,
            disk_write_bytes_per_sec: 0.0,
            disk_read_ops_per_sec: 0.0,
            disk_write_ops_per_sec: 0.0,
            net_recv_bytes_per_sec: 0.0,
            net_sent_bytes_per_sec: 0.0,
            net_recv_packets_per_sec: 0.0,
            net_sent_packets_per_sec: 0.0,
            processes_total: 100,
            processes_running: 2,
            processes_sleeping: 98,
            processes_idle: 0,
            processes_zombie: 0,
            tcp_established: 10,
            tcp_time_wait: 1,
            tcp_close_wait: 0,
            fd_open: 500,
            fd_max: 65536,
        }
    }

    #[test]
    fn enqueue_persists_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let shipper = MetricsShipper::new(
            "http://localhost:8080",
            "arc",
            "repo",
            crate::identity::AgentIdentity::new("agent-1".into()),
        )
        .unwrap();
        let mut pipeline = MetricsPipeline::open(
            "metrics-1",
            dir.path(),
            shipper,
            MetricsPipelineConfig::default(),
        )
        .unwrap();

        assert!(pipeline.enqueue_host_metrics(&sample_host()).unwrap());
        assert_eq!(pipeline.buffer.count().unwrap(), 1);
        assert!(pipeline.buffer_bytes() > 0);
    }

    #[test]
    fn survives_reopen_with_pending_snapshots() {
        let dir = tempfile::tempdir().unwrap();

        {
            let shipper = MetricsShipper::new(
                "http://localhost:8080",
                "arc",
                "repo",
                crate::identity::AgentIdentity::new("agent-1".into()),
            )
            .unwrap();
            let mut pipeline = MetricsPipeline::open(
                "metrics-1",
                dir.path(),
                shipper,
                MetricsPipelineConfig::default(),
            )
            .unwrap();
            pipeline.enqueue_host_metrics(&sample_host()).unwrap();
        }

        {
            let shipper = MetricsShipper::new(
                "http://localhost:8080",
                "arc",
                "repo",
                crate::identity::AgentIdentity::new("agent-1".into()),
            )
            .unwrap();
            let pipeline = MetricsPipeline::open(
                "metrics-1",
                dir.path(),
                shipper,
                MetricsPipelineConfig::default(),
            )
            .unwrap();
            assert_eq!(pipeline.buffer.count().unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn drain_cycle_deletes_snapshots_after_full_acceptance() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let shipper = MetricsShipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc",
            "repo",
            crate::identity::AgentIdentity::new("agent-1".into()),
        )
        .unwrap();
        let mut pipeline = MetricsPipeline::open(
            "metrics-1",
            dir.path(),
            shipper,
            MetricsPipelineConfig::default(),
        )
        .unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn drain_cycle_keeps_snapshots_rejected_by_relay() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                encoded_wire_response(0, 1, "invalid metrics"),
                "application/x-protobuf",
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let shipper = MetricsShipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc",
            "repo",
            crate::identity::AgentIdentity::new("agent-1".into()),
        )
        .unwrap();
        let mut pipeline = MetricsPipeline::open(
            "metrics-1",
            dir.path(),
            shipper,
            MetricsPipelineConfig::default(),
        )
        .unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn drain_cycle_keeps_snapshots_partially_rejected_by_relay() {
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

        let dir = tempfile::tempdir().unwrap();
        let shipper = MetricsShipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc",
            "repo",
            crate::identity::AgentIdentity::new("agent-1".into()),
        )
        .unwrap();
        let mut pipeline = MetricsPipeline::open(
            "metrics-1",
            dir.path(),
            shipper,
            MetricsPipelineConfig::default(),
        )
        .unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 2);
    }

    #[tokio::test]
    async fn drain_cycle_keeps_snapshots_on_accepted_count_mismatch() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let shipper = MetricsShipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc",
            "repo",
            crate::identity::AgentIdentity::new("agent-1".into()),
        )
        .unwrap();
        let mut pipeline = MetricsPipeline::open(
            "metrics-1",
            dir.path(),
            shipper,
            MetricsPipelineConfig::default(),
        )
        .unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();
        pipeline.enqueue_host_metrics(&sample_host()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 2);
    }
}
