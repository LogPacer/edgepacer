//! Self-telemetry — tracing Layer → durable buffer → WireLogBatch via logpacer-wire.
//!
//! Mirrors Go's customer-context fields embedded in each record body. Rust ships
//! via the routed wire protocol (not OTLP) for parity with other producers.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

use crate::buffer::DiskBuffer;
use crate::common::EdgepacerError;
use crate::config::{self, SharedConfig, TelemetryContext};
use crate::counters::AgentCounters;
use crate::retry::RetryPolicy;
use crate::shipper::{ShipResult, Shipper};

const DRAIN_INTERVAL: Duration = Duration::from_millis(100);
const SHIP_BATCH_SIZE: usize = 100;
const BUFFER_MAX_MB: u64 = 50;
const TELEMETRY_SHIP_MAX_ATTEMPTS: u32 = 3;

/// Capacity of the in-flight telemetry event channel. Bounded so a log storm
/// during an outage (when the durable buffer's own backpressure isn't yet in
/// play) can't grow memory without limit — self-telemetry is best-effort, so
/// the producer drops events when this fills rather than blocking the tracing
/// layer or queueing unboundedly.
pub const TELEMETRY_CHANNEL_CAPACITY: usize = 8192;

/// Shared tracing layer control — toggled when telemetry config changes.
#[derive(Clone)]
pub struct TelemetryLayer {
    tx: mpsc::Sender<Vec<u8>>,
    enabled: Arc<AtomicBool>,
    min_level: Arc<std::sync::atomic::AtomicU8>,
}

impl TelemetryLayer {
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            enabled: Arc::new(AtomicBool::new(false)),
            min_level: Arc::new(std::sync::atomic::AtomicU8::new(level_to_u8(Level::INFO))),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_min_level(&self, level: Level) {
        self.min_level.store(level_to_u8(level), Ordering::Relaxed);
    }
}

impl<S> Layer<S> for TelemetryLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let min = u8_to_level(self.min_level.load(Ordering::Relaxed));
        if *event.metadata().level() > min {
            return;
        }

        let mut visitor = JsonEventVisitor::default();
        event.record(&mut visitor);

        let mut value = serde_json::Map::new();
        value.insert(
            "level".into(),
            serde_json::Value::String(event.metadata().level().to_string()),
        );
        if let Some(msg) = visitor.message {
            value.insert("msg".into(), serde_json::Value::String(msg));
        }
        value.insert(
            "target".into(),
            serde_json::Value::String(event.metadata().target().to_string()),
        );
        for (k, v) in visitor.fields {
            value.insert(k, v);
        }

        if let Ok(json) = serde_json::to_vec(&serde_json::Value::Object(value)) {
            // Best-effort, non-blocking: drop on a full channel rather than
            // stall the tracing layer or grow memory during a log storm.
            let _ = self.tx.try_send(json);
        }
    }
}

#[derive(Default)]
struct JsonEventVisitor {
    message: Option<String>,
    fields: Vec<(String, serde_json::Value)>,
}

impl Visit for JsonEventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}").trim_matches('"').to_string());
        } else {
            self.fields.push((
                field.name().to_string(),
                serde_json::Value::String(format!("{value:?}").trim_matches('"').to_string()),
            ));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push((
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            ));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.push((field.name().to_string(), value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push((field.name().to_string(), value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.push((field.name().to_string(), value.into()));
    }
}

struct TelemetryPipeline {
    buffer: DiskBuffer,
    shipper: Shipper,
    retry_policy: RetryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TelemetryDrainOutcome {
    Delivered {
        count: usize,
    },
    Rejected {
        accepted: u32,
        rejected: u32,
        message: String,
    },
    Deferred {
        reason: TelemetryDeferredReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TelemetryDeferredReason {
    AcceptedCountMismatch { accepted: u32, requested: usize },
    ShipFailed(String),
}

impl TelemetryPipeline {
    fn open(data_dir: &Path, shipper: Shipper) -> Result<Self, crate::buffer::BufferError> {
        let _ = std::fs::create_dir_all(data_dir);
        let buf_path = data_dir.join("telemetry_buffer.sqlite");
        let buffer = DiskBuffer::open(&buf_path, BUFFER_MAX_MB)?;
        Ok(Self {
            buffer,
            shipper,
            retry_policy: RetryPolicy {
                max_attempts: TELEMETRY_SHIP_MAX_ATTEMPTS,
                ..Default::default()
            },
        })
    }

    /// Attach the shared queue-depth gauge to this pipeline's durable buffer.
    fn set_queue_gauge(&mut self, gauge: crate::counters::QueueDepthGauge) {
        self.buffer.set_gauge(gauge);
    }

    fn enqueue(&mut self, line: Vec<u8>) -> Result<(), crate::buffer::BufferError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        self.buffer.enqueue_batch(&[line], ts)?;
        Ok(())
    }

    async fn drain_cycle(&mut self) {
        let entries = match self.buffer.peek(SHIP_BATCH_SIZE) {
            Ok(e) if e.is_empty() => return,
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "telemetry buffer peek failed");
                return;
            }
        };

        let (payloads, sequences): (Vec<Vec<u8>>, Vec<u64>) =
            entries.into_iter().map(|e| (e.data, e.sequence)).unzip();

        let (encoded, count) = match self.shipper.encode_entry_json_batch(payloads) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "telemetry encode failed");
                return;
            }
        };

        match self.ship_encoded_batch(&encoded, count as usize).await {
            TelemetryDrainOutcome::Delivered { count } => {
                if let Err(e) = self.buffer.delete_sequences(&sequences[..count]) {
                    tracing::warn!(
                        error = %e,
                        "failed to delete shipped telemetry entries (will re-ship)"
                    );
                }
            }
            TelemetryDrainOutcome::Rejected {
                accepted,
                rejected,
                message,
            } => {
                tracing::warn!(
                    accepted,
                    rejected,
                    error = %message,
                    "telemetry batch rejected, will retry on next drain cycle"
                );
            }
            TelemetryDrainOutcome::Deferred { reason } => {
                tracing::warn!(
                    reason = ?reason,
                    "telemetry ship deferred, will retry on next drain cycle"
                );
            }
        }
    }

    async fn ship_encoded_batch(&self, encoded: &[u8], requested: usize) -> TelemetryDrainOutcome {
        match self
            .shipper
            .send_with_retry_policy(encoded, self.retry_policy)
            .await
        {
            Ok(ShipResult::Accepted { count }) if count as usize == requested => {
                TelemetryDrainOutcome::Delivered { count: requested }
            }
            Ok(ShipResult::Accepted { count }) => TelemetryDrainOutcome::Deferred {
                reason: TelemetryDeferredReason::AcceptedCountMismatch {
                    accepted: count,
                    requested,
                },
            },
            Ok(ShipResult::Rejected {
                accepted,
                rejected,
                message,
            }) => TelemetryDrainOutcome::Rejected {
                accepted,
                rejected,
                message,
            },
            Err(e) => self.telemetry_ship_failed(e),
        }
    }

    fn telemetry_ship_failed(&self, error: EdgepacerError) -> TelemetryDrainOutcome {
        tracing::warn!(error = %error, "telemetry ship failed");
        TelemetryDrainOutcome::Deferred {
            reason: TelemetryDeferredReason::ShipFailed(error.to_string()),
        }
    }

    async fn shutdown_drain(&mut self) {
        for _ in 0..100 {
            let before = self.buffer.count().unwrap_or(0);
            if before == 0 {
                break;
            }
            self.drain_cycle().await;
            if self.buffer.count().unwrap_or(0) >= before {
                break;
            }
        }
    }
}

/// Run self-telemetry: watch config, enrich events, buffer durably, ship to staff repo.
pub async fn run(
    shared_config: SharedConfig,
    data_dir: &Path,
    identity: crate::identity::AgentIdentity,
    layer: TelemetryLayer,
    mut event_rx: mpsc::Receiver<Vec<u8>>,
    counters: Arc<AgentCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let telemetry_dir = data_dir.join("_telemetry");
    let mut pipeline: Option<TelemetryPipeline> = None;
    let mut active_hash = String::new();
    let mut context = TelemetryContext::default();
    let mut drain_tick = tokio::time::interval(DRAIN_INTERVAL);
    drain_tick.tick().await;

    loop {
        tokio::select! {
            _ = drain_tick.tick() => {
                if let Some(p) = pipeline.as_mut() {
                    p.drain_cycle().await;
                }
            }
            Some(raw) = event_rx.recv() => {
                if let Some(p) = pipeline.as_mut() {
                    let enriched = enrich_event(&raw, &context, &identity.current());
                    if p.enqueue(enriched).is_err() {
                        counters.increment_errors();
                    }
                }
            }
            _ = shutdown.changed() => {
                if let Some(mut p) = pipeline.take() {
                    p.shutdown_drain().await;
                }
                layer.set_enabled(false);
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }

        let cfg = {
            let guard = shared_config.read().await;
            guard.as_ref().and_then(config::telemetry_config)
        };

        match cfg {
            Some(tele) if tele.config_hash != active_hash => {
                active_hash = tele.config_hash.clone();
                context = tele.context.clone();

                if tele.enabled {
                    match Shipper::with_counters(
                        &tele.subbox_endpoint,
                        &tele.archive_id,
                        &tele.repo_id,
                        Some(identity.clone()),
                        counters.clone(),
                    ) {
                        Ok(shipper) => match TelemetryPipeline::open(&telemetry_dir, shipper) {
                            Ok(mut p) => {
                                p.set_queue_gauge(counters.queue_depth_gauge());
                                pipeline = Some(p);
                                layer.set_enabled(true);
                                layer.set_min_level(parse_min_level(&tele.min_level));
                                tracing::info!(
                                    subbox_endpoint = %tele.subbox_endpoint,
                                    archive_id = %tele.archive_id,
                                    "self-telemetry enabled"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to open telemetry pipeline");
                                pipeline = None;
                                layer.set_enabled(false);
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to create telemetry shipper");
                            pipeline = None;
                            layer.set_enabled(false);
                        }
                    }
                } else {
                    if let Some(mut p) = pipeline.take() {
                        p.shutdown_drain().await;
                    }
                    layer.set_enabled(false);
                }
            }
            None if !active_hash.is_empty() => {
                active_hash.clear();
                if let Some(mut p) = pipeline.take() {
                    p.shutdown_drain().await;
                }
                layer.set_enabled(false);
            }
            _ => {}
        }
    }
}

fn enrich_event(raw: &[u8], context: &TelemetryContext, resource_identifier: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(raw)
        .unwrap_or_else(|_| serde_json::json!({ "msg": String::from_utf8_lossy(raw) }));

    let obj = value.as_object_mut();
    if let Some(map) = obj {
        map.entry("component")
            .or_insert_with(|| serde_json::Value::String("edgepacer".into()));
        map.entry("resource_identifier")
            .or_insert_with(|| serde_json::Value::String(resource_identifier.to_string()));
        if !context.tenant_id.is_empty() {
            map.entry("tenant_id")
                .or_insert_with(|| serde_json::Value::String(context.tenant_id.clone()));
        }
        if !context.tenant_name.is_empty() {
            map.entry("tenant_name")
                .or_insert_with(|| serde_json::Value::String(context.tenant_name.clone()));
        }
        if !context.customer_archive_id.is_empty() {
            map.entry("customer_archive_id")
                .or_insert_with(|| serde_json::Value::String(context.customer_archive_id.clone()));
        }
    }

    serde_json::to_vec(&value).unwrap_or_else(|_| raw.to_vec())
}

fn parse_min_level(s: &str) -> Level {
    match s.to_ascii_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

fn level_to_u8(level: Level) -> u8 {
    match level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

fn u8_to_level(n: u8) -> Level {
    match n {
        1 => Level::ERROR,
        2 => Level::WARN,
        4 => Level::DEBUG,
        5 => Level::TRACE,
        _ => Level::INFO,
    }
}

/// Initialize tracing with fmt output and optional self-telemetry layer.
pub fn init_tracing(log_level: &str, layer: TelemetryLayer) {
    let filter = tracing_subscriber::EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_writer(std::io::stderr)
                // ANSI only on a real terminal — under the manager (or any
                // pipe into journald) escape codes become log garbage.
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
        )
        .with(layer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn enrich_adds_customer_context() {
        let raw = br#"{"level":"info","msg":"hello"}"#;
        let ctx = TelemetryContext {
            tenant_id: "t1".into(),
            tenant_name: "Acme".into(),
            customer_archive_id: "arc-c".into(),
        };
        let out = enrich_event(raw, &ctx, "host-a");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["component"], "edgepacer");
        assert_eq!(v["tenant_id"], "t1");
        assert_eq!(v["resource_identifier"], "host-a");
    }

    #[test]
    fn parse_min_level_variants() {
        assert_eq!(parse_min_level("debug"), Level::DEBUG);
        assert_eq!(parse_min_level(""), Level::INFO);
    }

    #[tokio::test]
    async fn telemetry_drain_deletes_entries_after_full_acceptance() {
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
        let shipper =
            Shipper::new(&format!("{}/wire", mock_server.uri()), "arc", "repo", None).unwrap();
        let mut pipeline = TelemetryPipeline::open(dir.path(), shipper).unwrap();
        pipeline.enqueue(br#"{"msg":"accepted"}"#.to_vec()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn telemetry_drain_keeps_rejected_entries() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                encoded_wire_response(0, 1, "invalid telemetry"),
                "application/x-protobuf",
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let shipper =
            Shipper::new(&format!("{}/wire", mock_server.uri()), "arc", "repo", None).unwrap();
        let mut pipeline = TelemetryPipeline::open(dir.path(), shipper).unwrap();
        pipeline.enqueue(br#"{"msg":"rejected"}"#.to_vec()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn telemetry_drain_keeps_entries_when_retry_exhausts() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let shipper =
            Shipper::new(&format!("{}/wire", mock_server.uri()), "arc", "repo", None).unwrap();
        let mut pipeline = TelemetryPipeline::open(dir.path(), shipper).unwrap();
        pipeline.retry_policy = RetryPolicy {
            max_attempts: 1,
            ..Default::default()
        };
        pipeline.enqueue(br#"{"msg":"retry"}"#.to_vec()).unwrap();

        pipeline.drain_cycle().await;

        assert_eq!(pipeline.buffer.count().unwrap(), 1);
    }
}
