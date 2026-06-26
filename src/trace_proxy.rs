//! OTLP Trace Proxy — receives traces on localhost and ships them over
//! pacer_wire to a single Subbox wire endpoint with retry-aware buffering.
//!
//! Data flow:
//! POST /v1/traces (protobuf body, <=10MB)
//!   -> deserialize ExportTraceServiceRequest
//!   -> for each span: serialize to a JSON object (the Sublogger contract)
//!   -> pack the JSON objects into a WireTraceBatch, encode the WireRequest
//!   -> ship the encoded bytes VERBATIM to subbox_endpoint (the wire URL)
//!   -> on retryable failure: buffer the encoded bytes to disk for replay
//!   -> always return 200 OK for accepted requests
//!
//! This mirrors how host metrics ship (`metrics_shipper` + `shipper`): the wire
//! endpoint is the full `/v1/logpacer-wire` URL — logs, metrics, and traces all
//! POST to it verbatim with the repo's upload-token bearer JWT.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use prost14::Message as OtelMessage;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::trace_buffer::{TraceBuffer, TraceBufferError};
use crate::common::EdgepacerError;
use crate::rate_limiter::RateLimiter;
use crate::retry::RetryPolicy;
use crate::shipper::{ShipResult, WireTransport, WireTransportPolicy, encode_single_batch};
use crate::trace_wire::{self, service_name_from_attrs};
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueKind;

const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Upper bound on a decompressed OTLP body, guarding against gzip bombs — a
/// small compressed payload that expands without limit.
const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024; // 64 MB
pub const DEFAULT_TRACE_BUFFER_MAX_MB: u64 = 100;

type ExportTraceServiceRequest =
    opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
type ResourceSpans = opentelemetry_proto::tonic::trace::v1::ResourceSpans;
type Resource = opentelemetry_proto::tonic::resource::v1::Resource;
type KeyValue = opentelemetry_proto::tonic::common::v1::KeyValue;
type AnyValue = opentelemetry_proto::tonic::common::v1::AnyValue;

/// In the single-repo trace model `service.name` is the only field that
/// distinguishes services, so a span without it collapses into every other
/// unnamed service. We guarantee its presence with a host-scoped fallback.
const SERVICE_NAME_KEY: &str = "service.name";

#[derive(Debug, Clone)]
pub struct TraceProxyConfig {
    pub listen_address: SocketAddr,
    pub subbox_endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    /// Host/agent identifier, used to build the per-host `service.name` fallback.
    pub resource_identifier: String,
    /// Reject resource spans that do not carry a non-empty `service.name`.
    pub require_service_name: bool,
    /// Optional consent gate for DaemonSet mode. Empty means any explicit
    /// `service.name` is accepted; non-empty means only listed names are.
    pub allowed_service_names: BTreeSet<String>,
    pub buffer_path: PathBuf,
    pub buffer_max_mb: u64,
}

struct ProxyState {
    config: TraceProxyConfig,
    /// Shared wire transport — POSTs already-encoded `WireRequest` bytes to the
    /// subbox wire endpoint verbatim, attaching the repo's upload-token JWT and
    /// handling auth-refresh/retry exactly as logs and metrics do.
    transport: WireTransport,
    retry_policy: RetryPolicy,
    buffer: Mutex<TraceBuffer>,
    /// `unknown:<resource_identifier>` — injected as `service.name` for spans
    /// that arrive without one, so they bucket per-host instead of collapsing.
    service_name_fallback: String,
    /// Spans we had to backfill; surfaced via the rate-limited warn so a
    /// misconfigured exporter is visible without a per-span log flood.
    missing_service_name_total: AtomicU64,
    missing_service_name_warn: RateLimiter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardOutcome {
    Delivered,
    Retryable,
    NonRetryable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceNamePolicyRejection {
    Missing,
    NotAllowed(String),
}

fn existing_service_name(resource_span: &ResourceSpans) -> Option<&str> {
    resource_span
        .resource
        .as_ref()?
        .attributes
        .iter()
        .find_map(|kv| {
            if kv.key != SERVICE_NAME_KEY {
                return None;
            }

            match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
                Some(AnyValueKind::StringValue(name)) if !name.is_empty() => Some(name.as_str()),
                _ => None,
            }
        })
}

/// Encode the spans of a single `ResourceSpans` into a wire `WireRequest`
/// carrying a `WireTraceBatch`. Each span becomes one JSON object
/// (`entries_json[i]`) under the resource's attributes + `service.name`.
///
/// Returns `Ok(None)` when the resource carries no spans (nothing to ship).
fn encode_resource_span_batch(
    resource_span: &ResourceSpans,
    archive_id: &str,
    repo_id: &str,
) -> Result<Option<Vec<u8>>, EdgepacerError> {
    use logpacer_wire::{WireTraceBatch, routed_batch};

    let resource_attrs = resource_span
        .resource
        .as_ref()
        .map(|r| trace_wire::attrs_to_json(&r.attributes))
        .unwrap_or_else(|| serde_json::json!({}));
    let service_name = resource_span
        .resource
        .as_ref()
        .map(|r| service_name_from_attrs(&r.attributes))
        .unwrap_or_default();

    let mut entries_json: Vec<Vec<u8>> = Vec::new();
    for scope_span in &resource_span.scope_spans {
        for span in &scope_span.spans {
            let value = trace_wire::span_to_json_value(span, &service_name, &resource_attrs);
            let bytes =
                serde_json::to_vec(&value).map_err(|source| EdgepacerError::JsonEncode {
                    context: "trace span",
                    source,
                })?;
            entries_json.push(bytes);
        }
    }

    if entries_json.is_empty() {
        return Ok(None);
    }

    encode_single_batch(
        archive_id,
        repo_id,
        routed_batch::Payload::Traces(WireTraceBatch { entries_json }),
    )
    .map(Some)
}

/// Ensure `resource_span`'s resource carries a non-empty `service.name`,
/// injecting `fallback` when it is missing, empty, or a non-string value.
/// Returns true when a fallback was injected. See [`SERVICE_NAME_KEY`].
fn ensure_service_name(resource_span: &mut ResourceSpans, fallback: &str) -> bool {
    if existing_service_name(resource_span).is_some() {
        return false;
    }

    let resource = resource_span.resource.get_or_insert_with(Resource::default);

    // Drop any empty/non-string service.name before inserting the fallback so we
    // never leave a duplicate key behind.
    resource.attributes.retain(|kv| kv.key != SERVICE_NAME_KEY);
    resource.attributes.push(KeyValue {
        key: SERVICE_NAME_KEY.to_string(),
        key_strindex: 0,
        value: Some(AnyValue {
            value: Some(AnyValueKind::StringValue(fallback.to_string())),
        }),
    });
    true
}

fn apply_service_name_policy(
    resource_span: &mut ResourceSpans,
    fallback: &str,
    require_service_name: bool,
    allowed_service_names: &BTreeSet<String>,
) -> Result<bool, ServiceNamePolicyRejection> {
    if let Some(service_name) = existing_service_name(resource_span) {
        if !allowed_service_names.is_empty() && !allowed_service_names.contains(service_name) {
            return Err(ServiceNamePolicyRejection::NotAllowed(
                service_name.to_string(),
            ));
        }
        return Ok(false);
    }

    if require_service_name || !allowed_service_names.is_empty() {
        return Err(ServiceNamePolicyRejection::Missing);
    }

    Ok(ensure_service_name(resource_span, fallback))
}

/// Ship an already-encoded `WireRequest` payload over pacer_wire.
///
/// Used by both the request path and the drain loop. The bytes are POSTed
/// verbatim to the subbox wire endpoint — the auth, token-refresh, and retry
/// behavior is whatever `WireTransport` provides, the same path logs/metrics
/// use. The `WireTransport` result is mapped onto [`ForwardOutcome`] so the
/// disk-buffer retry decision is unchanged: rejected/failed payloads are kept
/// for replay, delivered payloads are dropped.
async fn ship_payload(
    transport: &WireTransport,
    retry_policy: RetryPolicy,
    payload: &[u8],
) -> ForwardOutcome {
    match transport
        .send_with_retry(payload, retry_policy, WireTransportPolicy::traces_batches())
        .await
    {
        Ok(ShipResult::Accepted { .. }) => {
            debug!("shipped trace batch over wire");
            ForwardOutcome::Delivered
        }
        Ok(ShipResult::Rejected {
            accepted,
            rejected,
            message,
        }) => {
            // A partial/total relay rejection is non-retryable (the receiver
            // parsed the payload and refused entries) — don't replay it.
            warn!(accepted, rejected, error = %message, "trace batch rejected by relay");
            ForwardOutcome::NonRetryable
        }
        // The transport handles auth (401/403) internally — it refreshes the
        // upload token and retries, then surfaces the exhausted failure as a
        // retryable error — so a retryable error here means "keep buffered for
        // the next drain cycle" rather than dropping spans.
        Err(e) if e.is_retryable() => {
            warn!(error = %e, "retryable trace ship failure; buffering for retry");
            ForwardOutcome::Retryable
        }
        Err(e) => {
            warn!(error = %e, "non-retryable trace ship failure; dropping payload");
            ForwardOutcome::NonRetryable
        }
    }
}

async fn forward_payload(state: &ProxyState, payload: &[u8]) -> ForwardOutcome {
    ship_payload(&state.transport, state.retry_policy, payload).await
}

async fn buffer_for_retry(state: &ProxyState, payload: &[u8]) {
    let mut buffer = state.buffer.lock().await;
    match buffer.enqueue(&state.config.archive_id, &state.config.repo_id, payload) {
        Ok(sequence) => {
            debug!(
                archive_id = %state.config.archive_id,
                repo_id = %state.config.repo_id,
                sequence,
                "buffered trace payload for retry"
            );
        }
        Err(TraceBufferError::Full {
            current_bytes,
            max_bytes,
        }) => {
            error!(
                archive_id = %state.config.archive_id,
                repo_id = %state.config.repo_id,
                current_bytes,
                max_bytes,
                "trace buffer full, dropping payload"
            );
        }
        Err(err) => {
            error!(
                archive_id = %state.config.archive_id,
                repo_id = %state.config.repo_id,
                error = %err,
                "failed to buffer trace payload"
            );
        }
    }
}

const DRAIN_TICK_MS: u64 = 200;
const DRAIN_BATCH_SIZE: usize = 50;

/// Background drain loop — replays buffered traces in FIFO order.
///
/// Ticks every 200ms, peeks up to 50 entries, forwards each in sequence order.
/// Stops on the first retryable failure per cycle to preserve ordering.
/// Deletes only entries that were confirmed delivered.
async fn drain_loop(state: Arc<ProxyState>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(DRAIN_TICK_MS));
    tick.tick().await; // skip immediate

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => {
                info!("trace drain loop shutting down");
                return;
            }
        }

        let entries = {
            let mut buffer = state.buffer.lock().await;
            loop {
                match buffer.peek(DRAIN_BATCH_SIZE) {
                    Ok(entries) => break entries,
                    Err(TraceBufferError::Corrupt { sequence }) => {
                        warn!(sequence, "corrupt trace buffer entry, dropping");
                        if let Err(err) = buffer.delete_sequences(&[sequence]) {
                            error!(
                                sequence,
                                error = %err,
                                "failed to delete corrupt trace buffer entry"
                            );
                            break Vec::new();
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "trace drain peek failed");
                        break Vec::new();
                    }
                }
            }
        };

        if entries.is_empty() {
            continue;
        }

        debug!(count = entries.len(), "trace drain cycle starting");

        let mut delivered_sequences = Vec::new();

        for entry in &entries {
            // Buffered entries are already-encoded `WireRequest` bytes — ship
            // them verbatim through the same transport the request path uses.
            let outcome = ship_payload(&state.transport, state.retry_policy, &entry.payload).await;

            match outcome {
                ForwardOutcome::Delivered => {
                    delivered_sequences.push(entry.sequence);
                }
                ForwardOutcome::Retryable => {
                    debug!(
                        sequence = entry.sequence,
                        outcome = ?outcome,
                        "drain stopped on retriable trace forward failure, will retry next cycle"
                    );
                    break;
                }
                ForwardOutcome::NonRetryable => {
                    warn!(
                        sequence = entry.sequence,
                        archive_id = %entry.archive_id,
                        repo_id = %entry.repo_id,
                        outcome = ?outcome,
                        "dropping non-retryable buffered trace"
                    );
                    delivered_sequences.push(entry.sequence);
                }
            }
        }

        if !delivered_sequences.is_empty() {
            let mut buffer = state.buffer.lock().await;
            if let Err(err) = buffer.delete_sequences(&delivered_sequences) {
                error!(error = %err, "failed to delete drained trace entries");
            } else {
                debug!(
                    deleted = delivered_sequences.len(),
                    "trace drain cycle completed"
                );
            }
        }
    }
}

/// Return the request body, gunzipping first when the client advertised
/// `Content-Encoding: gzip` (every OTEL SDK gzips OTLP by default). Bounded to
/// [`MAX_DECOMPRESSED_SIZE`] so a small payload can't expand without limit.
fn decode_request_body(headers: &HeaderMap, body: Bytes) -> Option<Vec<u8>> {
    let gzipped = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("gzip"));

    if !gzipped {
        return Some(body.to_vec());
    }

    use std::io::Read;
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(&body[..])
        .take(MAX_DECOMPRESSED_SIZE as u64 + 1)
        .read_to_end(&mut decoded)
        .ok()?;
    (decoded.len() <= MAX_DECOMPRESSED_SIZE).then_some(decoded)
}

async fn handle_traces(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if body.len() > MAX_REQUEST_SIZE {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    // OTLP clients gzip the body by default; decompress before decoding protobuf.
    let Some(body) = decode_request_body(&headers, body) else {
        return StatusCode::BAD_REQUEST;
    };

    let mut request = match ExportTraceServiceRequest::decode(body.as_slice()) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    for resource_span in &mut request.resource_spans {
        match apply_service_name_policy(
            resource_span,
            &state.service_name_fallback,
            state.config.require_service_name,
            &state.config.allowed_service_names,
        ) {
            Ok(true) => {
                let total = state
                    .missing_service_name_total
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                if state.missing_service_name_warn.try_acquire() {
                    warn!(
                        fallback = %state.service_name_fallback,
                        missing_total = total,
                        "trace resource span missing service.name; injected host-scoped fallback"
                    );
                }
            }
            Ok(false) => {}
            Err(ServiceNamePolicyRejection::Missing) => {
                warn!("trace resource span rejected: service.name is required");
                return StatusCode::FORBIDDEN;
            }
            Err(ServiceNamePolicyRejection::NotAllowed(service_name)) => {
                warn!(
                    service_name = %service_name,
                    "trace resource span rejected: service.name is not in the configured allow-list"
                );
                return StatusCode::FORBIDDEN;
            }
        }
    }

    for resource_span in &request.resource_spans {
        let payload = match encode_resource_span_batch(
            resource_span,
            &state.config.archive_id,
            &state.config.repo_id,
        ) {
            Ok(Some(payload)) => payload,
            // No spans in this resource — nothing to ship.
            Ok(None) => continue,
            Err(err) => {
                warn!(error = %err, "failed to encode trace resource span batch");
                continue;
            }
        };

        let outcome = forward_payload(state.as_ref(), &payload).await;
        if matches!(outcome, ForwardOutcome::Retryable) {
            buffer_for_retry(state.as_ref(), &payload).await;
        }
    }

    StatusCode::OK
}

pub struct TraceProxy {
    config: TraceProxyConfig,
    shutdown_tx: Option<watch::Sender<bool>>,
    server_handle: Option<JoinHandle<()>>,
    drain_handle: Option<JoinHandle<()>>,
}

impl TraceProxy {
    pub fn new(config: TraceProxyConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
            server_handle: None,
            drain_handle: None,
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let buffer = TraceBuffer::open(&self.config.buffer_path, self.config.buffer_max_mb)?;

        let transport = WireTransport::new(&self.config.subbox_endpoint, &self.config.repo_id)
            .map_err(|e| anyhow::anyhow!("failed to build trace wire transport: {e}"))?;

        let state = Arc::new(ProxyState {
            service_name_fallback: format!("unknown:{}", self.config.resource_identifier),
            missing_service_name_total: AtomicU64::new(0),
            // At most one warn per minute — enough to flag a misconfigured
            // exporter without flooding the log on every span.
            missing_service_name_warn: RateLimiter::new(1, Duration::from_secs(60)),
            config: self.config.clone(),
            transport,
            retry_policy: RetryPolicy {
                max_attempts: 5,
                ..Default::default()
            },
            buffer: Mutex::new(buffer),
        });

        let app = Router::new()
            .route("/v1/traces", post(handle_traces))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind(self.config.listen_address).await?;
        info!(address = %self.config.listen_address, "trace proxy listening");

        self.shutdown_tx = Some(shutdown_tx);

        let mut server_shutdown_rx = shutdown_rx.clone();
        self.server_handle = Some(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = server_shutdown_rx.changed().await;
                })
                .await
                .ok();
        }));

        self.drain_handle = Some(tokio::spawn(drain_loop(state, shutdown_rx)));

        Ok(())
    }

    /// Stop the proxy gracefully — signals shutdown and awaits both server and
    /// drain tasks with a timeout.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        let timeout = std::time::Duration::from_secs(10);

        if let Some(handle) = self.server_handle.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(error = %e, "trace proxy server task panicked"),
                Err(_) => warn!("trace proxy server stop timed out"),
            }
        }

        if let Some(handle) = self.drain_handle.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(error = %e, "trace drain task panicked"),
                Err(_) => warn!("trace drain stop timed out"),
            }
        }

        info!("trace proxy stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    use logpacer_wire::{WireRequest, WireResponse, routed_batch};
    use opentelemetry_proto::tonic::trace::v1::{ScopeSpans, Span};
    use prost::Message as WireMessage;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Wire endpoint path the proxy POSTs to verbatim — the test subbox endpoint
    /// is `{server.uri}{WIRE_PATH}`, mirroring the real `/v1/logpacer-wire` URL.
    const WIRE_PATH: &str = "/v1/logpacer-wire";

    /// Encode a protobuf `WireResponse` body for a mock 200 — the transport
    /// decodes this to decide accepted/rejected.
    fn wire_response(accepted: u32, rejected: u32, error_message: &str) -> Vec<u8> {
        let response = WireResponse {
            accepted,
            rejected,
            error_message: error_message.to_string(),
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        buf
    }

    fn encode_trace_request(resource_spans: Vec<ResourceSpans>) -> Bytes {
        let request = ExportTraceServiceRequest { resource_spans };
        let mut buf = Vec::with_capacity(request.encoded_len());
        request.encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    /// A resource span carrying exactly one span — so the wire encoder produces a
    /// non-empty batch (an empty `ResourceSpans` ships nothing).
    fn sample_resource_span() -> ResourceSpans {
        ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "sample".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// A pre-encoded wire batch suitable for seeding the durable buffer.
    fn sample_wire_payload() -> Vec<u8> {
        encode_resource_span_batch(&sample_resource_span(), "arc_test", "repo_test")
            .unwrap()
            .expect("sample resource span has a span")
    }

    fn test_config(endpoint: String, buffer_path: &Path) -> TraceProxyConfig {
        TraceProxyConfig {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            subbox_endpoint: endpoint,
            archive_id: "arc_test".into(),
            repo_id: "repo_test".into(),
            resource_identifier: "host-test".into(),
            require_service_name: false,
            allowed_service_names: BTreeSet::new(),
            buffer_path: buffer_path.to_path_buf(),
            buffer_max_mb: 10,
        }
    }

    fn test_config_with_policy(
        endpoint: String,
        buffer_path: &Path,
        require_service_name: bool,
        allowed_service_names: BTreeSet<String>,
    ) -> TraceProxyConfig {
        let mut config = test_config(endpoint, buffer_path);
        config.require_service_name = require_service_name;
        config.allowed_service_names = allowed_service_names;
        config
    }

    async fn test_state(endpoint: String, buffer_path: &Path) -> Arc<ProxyState> {
        let config = test_config(endpoint, buffer_path);
        test_state_from_config(config).await
    }

    async fn test_state_from_config(config: TraceProxyConfig) -> Arc<ProxyState> {
        let buffer = TraceBuffer::open(&config.buffer_path, config.buffer_max_mb).unwrap();
        let transport = WireTransport::new(&config.subbox_endpoint, &config.repo_id).unwrap();

        Arc::new(ProxyState {
            service_name_fallback: format!("unknown:{}", config.resource_identifier),
            missing_service_name_total: AtomicU64::new(0),
            missing_service_name_warn: RateLimiter::new(1, Duration::from_secs(60)),
            config,
            transport,
            // One attempt per drain pass keeps the failure tests fast; the drain
            // loop re-attempts across cycles.
            retry_policy: RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
            buffer: Mutex::new(buffer),
        })
    }

    #[test]
    fn encode_resource_span_batch_omits_empty_resource() {
        let empty = ResourceSpans::default();
        let encoded = encode_resource_span_batch(&empty, "arc_test", "repo_test").unwrap();
        assert!(encoded.is_none(), "a resource with no spans ships nothing");
    }

    #[test]
    fn encode_resource_span_batch_produces_decodable_traces_payload() {
        let rs = ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: SERVICE_NAME_KEY.to_string(),
                    key_strindex: 0,
                    value: Some(AnyValue {
                        value: Some(AnyValueKind::StringValue("checkout".into())),
                    }),
                }],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans: vec![
                    Span {
                        trace_id: vec![0xaa; 16],
                        span_id: vec![0xbb; 8],
                        name: "root".into(),
                        ..Default::default()
                    },
                    Span {
                        trace_id: vec![0xaa; 16],
                        span_id: vec![0xcc; 8],
                        parent_span_id: vec![0xbb; 8],
                        name: "child".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let encoded = encode_resource_span_batch(&rs, "arc_test", "repo_app")
            .unwrap()
            .expect("two spans present");
        let decoded = WireRequest::decode(&encoded[..]).unwrap();
        assert_eq!(decoded.batches.len(), 1);
        assert_eq!(decoded.batches[0].archive_id, "arc_test");
        assert_eq!(decoded.batches[0].repo_id, "repo_app");
        assert_eq!(decoded.batches[0].schema_version, 1);

        let Some(routed_batch::Payload::Traces(traces)) = &decoded.batches[0].payload else {
            panic!("expected routed traces payload");
        };
        assert_eq!(traces.entries_json.len(), 2);

        // Each entry is one span JSON object carrying the resource service name.
        let root: serde_json::Value = serde_json::from_slice(&traces.entries_json[0]).unwrap();
        assert_eq!(root["name"], serde_json::json!("root"));
        assert_eq!(root["service_name"], serde_json::json!("checkout"));
        assert_eq!(
            root["resource_attributes"]["service.name"],
            serde_json::json!("checkout")
        );
        assert!(
            root.get("parent_span_id").is_none(),
            "root span omits parent_span_id"
        );

        let child: serde_json::Value = serde_json::from_slice(&traces.entries_json[1]).unwrap();
        assert_eq!(child["parent_span_id"], serde_json::json!("bb".repeat(8)));
    }

    #[tokio::test]
    async fn forward_payload_attaches_cached_upload_token() {
        crate::upload_token_store::store().replace(HashMap::from([
            ("repo_shipper_auth".to_string(), "jwt-log".to_string()),
            ("repo_metrics_auth".to_string(), "jwt-metrics".to_string()),
            ("repo_trace_auth".to_string(), "jwt-trace".to_string()),
        ]));

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .and(header("authorization", "Bearer jwt-trace"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let transport =
            WireTransport::new(&format!("{}{WIRE_PATH}", server.uri()), "repo_trace_auth").unwrap();
        let outcome = ship_payload(&transport, RetryPolicy::default(), b"trace-payload").await;

        assert_eq!(outcome, ForwardOutcome::Delivered);
    }

    #[tokio::test]
    async fn retryable_upstream_failure_buffers_trace_and_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;
        let body = encode_trace_request(vec![sample_resource_span()]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn auth_upstream_failure_buffers_trace_and_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;
        let body = encode_trace_request(vec![sample_resource_span()]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn non_retryable_upstream_failure_does_not_buffer_trace() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;
        let body = encode_trace_request(vec![sample_resource_span()]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn relay_rejection_does_not_buffer_trace() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                wire_response(0, 1, "span rejected"),
                "application/x-protobuf",
            ))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;
        let body = encode_trace_request(vec![sample_resource_span()]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        let buffer = state.buffer.lock().await;
        assert_eq!(
            buffer.count().unwrap(),
            0,
            "a relay-rejected batch is non-retryable and must not be buffered"
        );
    }

    #[tokio::test]
    async fn network_failure_buffers_trace_and_returns_ok() {
        let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let dir = tempfile::tempdir().unwrap();
        let endpoint = format!("http://{address}{WIRE_PATH}");
        let state = test_state(endpoint, &dir.path().join("trace-buffer.sqlite")).await;
        let body = encode_trace_request(vec![sample_resource_span()]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn proxy_starts_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let config = TraceProxyConfig {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            subbox_endpoint: "http://localhost:9999/v1/logpacer-wire".into(),
            archive_id: "arc_test".into(),
            repo_id: "repo_test".into(),
            resource_identifier: "host-test".into(),
            require_service_name: false,
            allowed_service_names: BTreeSet::new(),
            buffer_path: dir.path().join("trace-buffer.sqlite"),
            buffer_max_mb: DEFAULT_TRACE_BUFFER_MAX_MB,
        };

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        proxy.stop().await;
    }

    #[tokio::test]
    async fn proxy_accepts_otlp_and_forwards_wire_traces() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap();
        drop(listener);

        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        );
        config.listen_address = listen_address;

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");

        let body = encode_trace_request(vec![resource_span_with_service(Some("checkout"))]);
        let url = format!("http://{listen_address}/v1/traces");
        let client = reqwest::Client::new();
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match client
                    .post(&url)
                    .header("content-type", "application/x-protobuf")
                    .body(body.clone())
                    .send()
                    .await
                {
                    Ok(response) => break response,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .expect("trace proxy should accept the OTLP request before timeout");

        let requests = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let requests = server.received_requests().await.unwrap();
                if !requests.is_empty() {
                    break requests;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("wire relay should receive forwarded traces before timeout");

        proxy.stop().await;

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(requests.len(), 1, "exactly one payload should be forwarded");

        let forwarded =
            WireRequest::decode(&requests[0].body[..]).expect("forwarded body decodes as wire");
        assert_eq!(forwarded.batches.len(), 1);
        assert_eq!(forwarded.batches[0].archive_id, "arc_test");
        assert_eq!(forwarded.batches[0].repo_id, "repo_test");

        let Some(routed_batch::Payload::Traces(traces)) = &forwarded.batches[0].payload else {
            panic!("expected routed traces payload");
        };
        assert_eq!(traces.entries_json.len(), 1);

        let span: serde_json::Value = serde_json::from_slice(&traces.entries_json[0]).unwrap();
        assert_eq!(span["name"], serde_json::json!("sample"));
        assert_eq!(span["service_name"], serde_json::json!("checkout"));
    }

    #[tokio::test]
    async fn drain_loop_replays_buffered_entries_after_recovery() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let buffer_path = dir.path().join("trace-buffer.sqlite");
        let config = test_config(format!("{}{WIRE_PATH}", server.uri()), &buffer_path);

        // Pre-populate buffer with encoded wire batches.
        {
            let mut buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
            let payload = sample_wire_payload();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
        }

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");

        // Give drain loop time to process
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        proxy.stop().await;

        // Buffer should be drained
        let buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
        assert_eq!(
            buffer.count().unwrap(),
            0,
            "drain should have replayed all entries"
        );
    }

    #[tokio::test]
    async fn drain_drops_corrupt_entry_and_replays_later_valid_entry() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let buffer_path = dir.path().join("trace-buffer.sqlite");
        let config = test_config(format!("{}{WIRE_PATH}", server.uri()), &buffer_path);

        {
            let _ = TraceBuffer::open(&buffer_path, 10).unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&buffer_path).unwrap();
            conn.execute(
                "INSERT INTO buffer(data) VALUES (?1)",
                rusqlite::params![&vec![0u8; 3]],
            )
            .unwrap();
        }
        {
            let mut buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
            let payload = sample_wire_payload();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
        }

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        proxy.stop().await;

        let buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
        assert_eq!(
            buffer.count().unwrap(),
            0,
            "corrupt entry should be dropped and later valid entry should drain"
        );
    }

    #[tokio::test]
    async fn drain_stops_on_first_retryable_failure() {
        let server = MockServer::start().await;

        // All requests fail with 503
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let buffer_path = dir.path().join("trace-buffer.sqlite");
        let config = test_config(format!("{}{WIRE_PATH}", server.uri()), &buffer_path);

        // Pre-populate buffer
        {
            let mut buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
            let payload = sample_wire_payload();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
        }

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");

        // Give drain loop a few cycles
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        proxy.stop().await;

        // All entries should still be buffered (retryable failure stops drain)
        let buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
        assert_eq!(
            buffer.count().unwrap(),
            3,
            "retryable failures should preserve all entries"
        );
    }

    #[tokio::test]
    async fn drain_stops_on_auth_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let buffer_path = dir.path().join("trace-buffer.sqlite");
        let config = test_config(format!("{}{WIRE_PATH}", server.uri()), &buffer_path);

        {
            let mut buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
            let payload = sample_wire_payload();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
            buffer.enqueue("arc_test", "repo_test", &payload).unwrap();
        }

        let mut proxy = TraceProxy::new(config);
        proxy.start().await.expect("proxy should start");

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        proxy.stop().await;

        let buffer = TraceBuffer::open(&buffer_path, 10).unwrap();
        assert_eq!(
            buffer.count().unwrap(),
            3,
            "auth failures should preserve buffered traces for retry"
        );
    }

    fn resource_span_with_service(name: Option<&str>) -> ResourceSpans {
        // Carry one span so the wire encoder produces a non-empty batch — the
        // ship-path test relies on bytes reaching the mock server.
        let mut rs = sample_resource_span();
        if let Some(name) = name {
            rs.resource = Some(Resource {
                attributes: vec![KeyValue {
                    key: SERVICE_NAME_KEY.to_string(),
                    key_strindex: 0,
                    value: Some(AnyValue {
                        value: Some(AnyValueKind::StringValue(name.to_string())),
                    }),
                }],
                ..Default::default()
            });
        }
        rs
    }

    fn service_name_of(rs: &ResourceSpans) -> Option<String> {
        rs.resource
            .as_ref()?
            .attributes
            .iter()
            .find(|kv| kv.key == SERVICE_NAME_KEY)
            .and_then(|kv| kv.value.as_ref())
            .and_then(|v| v.value.as_ref())
            .and_then(|v| match v {
                AnyValueKind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
    }

    #[test]
    fn ensure_service_name_injects_when_resource_absent() {
        let mut rs = resource_span_with_service(None);
        assert!(ensure_service_name(&mut rs, "unknown:host-1"));
        assert_eq!(service_name_of(&rs).as_deref(), Some("unknown:host-1"));
    }

    #[test]
    fn ensure_service_name_injects_when_empty() {
        let mut rs = resource_span_with_service(Some(""));
        assert!(ensure_service_name(&mut rs, "unknown:host-1"));
        assert_eq!(service_name_of(&rs).as_deref(), Some("unknown:host-1"));
        // No duplicate service.name key left behind.
        let count = rs
            .resource
            .unwrap()
            .attributes
            .iter()
            .filter(|kv| kv.key == SERVICE_NAME_KEY)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn ensure_service_name_preserves_existing() {
        let mut rs = resource_span_with_service(Some("checkout"));
        assert!(!ensure_service_name(&mut rs, "unknown:host-1"));
        assert_eq!(service_name_of(&rs).as_deref(), Some("checkout"));
    }

    #[test]
    fn ensure_service_name_injects_when_non_string() {
        // A non-string service.name (e.g. an IntValue, which sublog-rs could
        // theoretically emit) is not a valid name and must be replaced by the
        // string fallback — leaving exactly one string-valued key behind.
        let mut rs = ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: SERVICE_NAME_KEY.to_string(),
                    key_strindex: 0,
                    value: Some(AnyValue {
                        value: Some(AnyValueKind::IntValue(0)),
                    }),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(ensure_service_name(&mut rs, "unknown:host-1"));
        assert_eq!(service_name_of(&rs).as_deref(), Some("unknown:host-1"));
        // The non-string value was replaced, not duplicated.
        let count = rs
            .resource
            .unwrap()
            .attributes
            .iter()
            .filter(|kv| kv.key == SERVICE_NAME_KEY)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn service_name_policy_rejects_missing_when_required() {
        let mut rs = resource_span_with_service(None);
        let result = apply_service_name_policy(&mut rs, "unknown:host-1", true, &BTreeSet::new());

        assert_eq!(result, Err(ServiceNamePolicyRejection::Missing));
        assert_eq!(service_name_of(&rs), None);
    }

    #[test]
    fn service_name_policy_rejects_missing_when_allowlist_is_set() {
        let mut rs = resource_span_with_service(None);
        let result = apply_service_name_policy(
            &mut rs,
            "unknown:host-1",
            false,
            &BTreeSet::from(["checkout".to_string()]),
        );

        assert_eq!(result, Err(ServiceNamePolicyRejection::Missing));
        assert_eq!(service_name_of(&rs), None);
    }

    #[test]
    fn service_name_policy_rejects_unlisted_service_name() {
        let mut rs = resource_span_with_service(Some("payments"));
        let result = apply_service_name_policy(
            &mut rs,
            "unknown:host-1",
            false,
            &BTreeSet::from(["checkout".to_string()]),
        );

        assert_eq!(
            result,
            Err(ServiceNamePolicyRejection::NotAllowed("payments".into()))
        );
    }

    #[test]
    fn service_name_policy_accepts_allowed_service_name() {
        let mut rs = resource_span_with_service(Some("checkout"));
        let result = apply_service_name_policy(
            &mut rs,
            "unknown:host-1",
            false,
            &BTreeSet::from(["checkout".to_string()]),
        );

        assert_eq!(result, Ok(false));
        assert_eq!(service_name_of(&rs).as_deref(), Some("checkout"));
    }

    #[tokio::test]
    async fn handle_traces_injects_fallback_for_missing_service_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;
        let body = encode_trace_request(vec![resource_span_with_service(None)]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(state.missing_service_name_total.load(Ordering::Relaxed), 1);

        // End-to-end: the injected fallback must reach the wire, not merely bump
        // the counter. Decode the WireRequest the mock server actually received
        // and confirm the fallback is baked into the span JSON — this would catch
        // an encode of the pre-mutation span.
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "exactly one payload should be forwarded");
        let forwarded =
            WireRequest::decode(&requests[0].body[..]).expect("forwarded body decodes as wire");
        let Some(routed_batch::Payload::Traces(traces)) = &forwarded.batches[0].payload else {
            panic!("expected routed traces payload");
        };
        assert_eq!(traces.entries_json.len(), 1);
        let span: serde_json::Value = serde_json::from_slice(&traces.entries_json[0]).unwrap();
        assert_eq!(span["service_name"], serde_json::json!("unknown:host-test"));
        assert_eq!(
            span["resource_attributes"]["service.name"],
            serde_json::json!("unknown:host-test")
        );
    }

    #[tokio::test]
    async fn handle_traces_rejects_missing_service_name_when_required() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config = test_config_with_policy(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
            true,
            BTreeSet::new(),
        );
        let state = test_state_from_config(config).await;
        let body = encode_trace_request(vec![resource_span_with_service(None)]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(state.missing_service_name_total.load(Ordering::Relaxed), 0);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "policy rejection must not forward a partial trace payload"
        );
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn handle_traces_rejects_unlisted_service_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config = test_config_with_policy(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
            false,
            BTreeSet::from(["checkout".to_string()]),
        );
        let state = test_state_from_config(config).await;
        let body = encode_trace_request(vec![resource_span_with_service(Some("payments"))]);

        let status = handle_traces(State(state.clone()), HeaderMap::new(), body).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "unlisted service.name must fail before forwarding"
        );
        let buffer = state.buffer.lock().await;
        assert_eq!(buffer.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn handle_traces_gunzips_content_encoding_gzip() {
        use std::io::Write;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WIRE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            format!("{}{WIRE_PATH}", server.uri()),
            &dir.path().join("trace-buffer.sqlite"),
        )
        .await;

        // OTEL SDKs gzip OTLP bodies by default; the receiver must gunzip them.
        let raw = encode_trace_request(vec![resource_span_with_service(Some("checkout"))]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let gzipped = Bytes::from(encoder.finish().unwrap());

        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let status = handle_traces(State(state.clone()), headers, gzipped).await;

        assert_eq!(status, StatusCode::OK);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "gunzipped spans must reach the wire");
    }
}
