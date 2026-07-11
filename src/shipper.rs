//! LogPacer Wire shipper — encodes log lines as WireRequest and POSTs to the configured wire endpoint.
//!
//! This is the critical M2 delivery path: file tailer → logpacer_wire → HTTP POST.
//! Content-Type: application/x-protobuf (matching what logrelay expects).

use crate::common::EdgepacerError;
use crate::counters::AgentCounters;
use crate::identity::AgentIdentity;
use crate::retry::RetryPolicy;

use std::sync::Arc;

use logpacer_wire::{
    EbpfEventKind, EventEnvelope, NetworkFlow, RequestSignal, RoutedBatch, WireEbpfBatch,
    WireEbpfEvent, WireGraphBatch, WireJsonEvent, WireLogBatch, WireLogEvent, WireRequest,
    WireResponse, routed_batch, wire_ebpf_event, wire_log_event,
};
use prost::Message;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

/// Estimated per-entry wire overhead (envelope + metadata + protobuf framing)
/// added to each line when byte-capping a batch. Deliberately generous so the
/// cap under-fills rather than over-fills relative to the receiver's limit.
const ENTRY_WIRE_OVERHEAD: usize = 128;

pub(crate) fn checked_wire_count(field: &'static str, len: usize) -> Result<u32, EdgepacerError> {
    u32::try_from(len).map_err(|_| EdgepacerError::WireCountTooLarge { field, len })
}

pub(crate) fn unix_epoch_millis_i64() -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(duration.as_millis()).unwrap_or(0)
}

pub(crate) fn encode_single_batch(
    archive_id: &str,
    repo_id: &str,
    payload: routed_batch::Payload,
) -> Result<Vec<u8>, EdgepacerError> {
    let request = WireRequest {
        batches: vec![RoutedBatch {
            archive_id: archive_id.to_string(),
            repo_id: repo_id.to_string(),
            schema_version: 1,
            payload: Some(payload),
        }],
    };

    let mut encoded = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut encoded)
        .map_err(|source| EdgepacerError::WireEncode {
            context: "wire request",
            source,
        })?;
    Ok(encoded)
}

/// Number of leading entries to ship, bounded by `max_bytes` (each entry costed
/// as its line length plus [`ENTRY_WIRE_OVERHEAD`]). Always at least 1 for a
/// non-empty slice, so a single entry larger than the cap still goes out — the
/// shrink path then handles a real payload-too-large rejection.
#[must_use]
fn byte_capped_take(lines: &[Vec<u8>], max_bytes: usize) -> usize {
    let mut total = 0usize;
    let mut take = 0usize;
    for line in lines {
        let cost = line.len() + ENTRY_WIRE_OVERHEAD;
        // The first entry is always taken (the `take > 0` guard skips the cap
        // check for it) so a lone over-cap entry still ships.
        if take > 0 && total + cost > max_bytes {
            break;
        }
        total += cost;
        take += 1;
    }
    take
}

fn log_line_body(body: &[u8]) -> wire_log_event::Body {
    if is_json_object(body) {
        return wire_log_event::Body::EntryJson(body.to_vec());
    }

    match std::str::from_utf8(body) {
        Ok(text) => wire_log_event::Body::RawText(text.to_string()),
        Err(_) => wire_log_event::Body::RawBytes(body.to_vec()),
    }
}

fn is_json_object(body: &[u8]) -> bool {
    let trimmed = body.trim_ascii();
    if !trimmed.starts_with(b"{") {
        return false;
    }

    matches!(
        serde_json::from_slice::<serde_json::Value>(trimmed),
        Ok(serde_json::Value::Object(_))
    )
}

/// Ship log batches via the routed logpacer-wire protocol.
///
/// Cheap to clone — `reqwest::Client` and the counters are reference-counted —
/// so a drain loop can hold a `Shipper` handle outside its pipeline lock.
#[derive(Clone)]
pub struct Shipper {
    transport: WireTransport,
    archive_id: String,
    repo_id: String,
    /// When `Some`, every event envelope is stamped with the live agent identity
    /// (`resource_identifier`), read at encode time so a logpacer re-pin takes
    /// effect on the next batch without restarting the pipeline. `None` — the
    /// default, set per the collectable's `stamp_resource_identifier` flag — emits an
    /// empty metadata object and adds no per-line identity bytes.
    identity: Option<AgentIdentity>,
    retry_policy: RetryPolicy,
}

/// Result of a ship attempt.
#[derive(Debug)]
pub enum ShipResult {
    /// All entries accepted.
    Accepted { count: u32 },
    /// Some or all entries rejected (non-retryable).
    Rejected {
        accepted: u32,
        rejected: u32,
        message: String,
    },
}

/// Outcome of shipping a byte-capped prefix from a durable buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedShipOutcome {
    /// A prefix was accepted by the receiver and may be deleted from the buffer.
    Delivered { count: usize },
    /// A single oversized record was rejected even after shrink-to-one and must
    /// be deleted to let later durable records make progress.
    DroppedOversized { count: usize },
    /// Nothing was safely handled; keep the full buffer prefix for a later retry.
    Deferred { reason: CappedShipDeferredReason },
}

/// Why a capped ship attempt left the buffered prefix untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedShipDeferredReason {
    EmptyBatch,
    EncodeFailed,
    AcceptedCountMismatch,
    RelayRejected,
    ShipFailed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PayloadTooLargeMode {
    PreserveForShrink,
    ClassifyAsHttpStatus,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WireTransportPolicy {
    operation: &'static str,
    request_error: &'static str,
    status_context: &'static str,
    auth_rejected: &'static str,
    read_error: &'static str,
    decode_error: &'static str,
    payload_too_large: PayloadTooLargeMode,
    count_rejected_bytes: bool,
}

impl WireTransportPolicy {
    pub(crate) const fn log_batches() -> Self {
        Self {
            operation: "log",
            request_error: "ship request failed",
            status_context: "ship error",
            auth_rejected: "ship auth rejected",
            read_error: "failed to read response",
            decode_error: "failed to decode response",
            payload_too_large: PayloadTooLargeMode::PreserveForShrink,
            count_rejected_bytes: true,
        }
    }

    pub(crate) const fn metrics_batches() -> Self {
        Self {
            operation: "metrics",
            request_error: "metrics ship failed",
            status_context: "metrics ship error",
            auth_rejected: "metrics ship auth rejected",
            read_error: "failed to read metrics response",
            decode_error: "failed to decode metrics response",
            payload_too_large: PayloadTooLargeMode::ClassifyAsHttpStatus,
            count_rejected_bytes: false,
        }
    }

    pub(crate) const fn traces_batches() -> Self {
        Self {
            operation: "traces",
            request_error: "traces ship failed",
            status_context: "traces ship error",
            auth_rejected: "traces ship auth rejected",
            read_error: "failed to read traces response",
            decode_error: "failed to decode traces response",
            payload_too_large: PayloadTooLargeMode::ClassifyAsHttpStatus,
            count_rejected_bytes: false,
        }
    }
}

/// Shared transport for already-encoded logpacer-wire protobuf payloads.
#[derive(Clone)]
pub(crate) struct WireTransport {
    http: reqwest::Client,
    endpoint: String,
    /// Repo the payloads belong to — keys the cached subbox upload token
    /// attached as `Authorization: Bearer` on every request.
    repo_id: String,
    counters: Option<Arc<AgentCounters>>,
}

impl WireTransport {
    pub(crate) fn new(endpoint: &str, repo_id: &str) -> Result<Self, EdgepacerError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        Ok(Self {
            http,
            endpoint: endpoint.to_string(),
            repo_id: repo_id.to_string(),
            counters: None,
        })
    }

    pub(crate) fn with_counters(mut self, counters: Arc<AgentCounters>) -> Self {
        self.counters = Some(counters);
        self
    }

    pub(crate) async fn send_with_retry(
        &self,
        encoded: &[u8],
        retry_policy: RetryPolicy,
        policy: WireTransportPolicy,
    ) -> Result<ShipResult, EdgepacerError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.send_request(encoded, policy).await {
                Ok(result) => {
                    self.record_sent_bytes(encoded.len(), &result, policy);
                    return Ok(result);
                }
                Err(e) if e.is_retryable() => {
                    if let Some(delay) = retry_policy.delay_for(attempt) {
                        warn!(
                            operation = policy.operation,
                            attempt,
                            delay_ms = delay.as_millis() as u64,
                            error = %e,
                            "retrying logpacer-wire request"
                        );
                        tokio::time::sleep(delay).await;
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn record_sent_bytes(
        &self,
        encoded_len: usize,
        result: &ShipResult,
        policy: WireTransportPolicy,
    ) {
        let Some(counters) = &self.counters else {
            return;
        };
        if matches!(result, ShipResult::Accepted { .. }) || policy.count_rejected_bytes {
            counters.add_bytes_sent(encoded_len as u64);
        }
    }

    async fn send_request(
        &self,
        data: &[u8],
        policy: WireTransportPolicy,
    ) -> Result<ShipResult, EdgepacerError> {
        let mut req = self
            .http
            .post(&self.endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-protobuf"),
            )
            .body(data.to_vec());

        // Attach the subbox upload token (JWT) for this repo if one is cached;
        // the ingress gate verifies it via JWKS. Absent a token the gate 401s
        // and we trigger a refresh below.
        if let Some(token) = crate::upload_token_store::store().get(&self.repo_id)
            && let Some(auth) = crate::common::bearer_header(&token)
        {
            req = req.header(AUTHORIZATION, auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| EdgepacerError::Retryable(format!("{}: {e}", policy.request_error)))?;

        let status = resp.status();

        // Upload token missing/expired/rejected at the gate → refresh + retry.
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            crate::upload_token_store::store().request_refresh();
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            return Err(EdgepacerError::Retryable(format!(
                "{} ({status}); refreshing upload token - {body}",
                policy.auth_rejected
            )));
        }

        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE
            && matches!(
                policy.payload_too_large,
                PayloadTooLargeMode::PreserveForShrink
            )
        {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            return Err(EdgepacerError::PayloadTooLarge(format!(
                "{} payload too large: {status} - {body}",
                policy.operation
            )));
        }

        if status.is_client_error() || status.is_server_error() {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            return Err(EdgepacerError::from_http_status(
                status.as_u16(),
                policy.status_context,
                &body,
            ));
        }

        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| EdgepacerError::Retryable(format!("{}: {e}", policy.read_error)))?;

        let wire_resp =
            WireResponse::decode(body_bytes).map_err(|source| EdgepacerError::WireDecode {
                context: policy.decode_error,
                source,
            })?;

        if wire_resp.rejected > 0 {
            warn!(
                operation = policy.operation,
                accepted = wire_resp.accepted,
                rejected = wire_resp.rejected,
                error = %wire_resp.error_message,
                "logpacer-wire response rejected entries"
            );
            return Ok(ShipResult::Rejected {
                accepted: wire_resp.accepted,
                rejected: wire_resp.rejected,
                message: wire_resp.error_message,
            });
        }

        debug!(
            operation = policy.operation,
            accepted = wire_resp.accepted,
            rejected = wire_resp.rejected,
            "logpacer-wire response accepted"
        );
        Ok(ShipResult::Accepted {
            count: wire_resp.accepted,
        })
    }
}

impl Shipper {
    pub fn new(
        endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        identity: Option<AgentIdentity>,
    ) -> Result<Self, EdgepacerError> {
        Ok(Self {
            transport: WireTransport::new(endpoint, repo_id)?,
            archive_id: archive_id.to_string(),
            repo_id: repo_id.to_string(),
            identity,
            retry_policy: RetryPolicy::default(),
        })
    }

    /// Create a shipper that tracks bytes_sent via shared counters.
    pub fn with_counters(
        endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        identity: Option<AgentIdentity>,
        counters: Arc<AgentCounters>,
    ) -> Result<Self, EdgepacerError> {
        let mut shipper = Self::new(endpoint, archive_id, repo_id, identity)?;
        shipper.transport = shipper.transport.with_counters(counters);
        Ok(shipper)
    }

    /// Envelope metadata bytes for a batch. `{}` when this shipper doesn't stamp
    /// identity; otherwise `{"resource_identifier": <live value>}`, read from the
    /// shared cell at encode time. Built once per batch — the bytes are then
    /// cloned into each event envelope.
    fn envelope_metadata_bytes(&self) -> Vec<u8> {
        match &self.identity {
            None => b"{}".to_vec(),
            // Wire key stays `resource_identifier` (the relay's field name).
            Some(identity) => serde_json::json!({ "resource_identifier": identity.current() })
                .to_string()
                .into_bytes(),
        }
    }

    /// Ship a batch of log lines — convenience wrapper that encodes + sends with retry.
    pub async fn ship(&self, lines: &[Vec<u8>]) -> Result<ShipResult, EdgepacerError> {
        if lines.is_empty() {
            return Ok(ShipResult::Accepted { count: 0 });
        }
        let (encoded, _) = self.encode_batch(lines)?;
        self.send_with_retry(&encoded).await
    }

    /// Ship the byte-capped leading prefix of `lines`, shrinking the batch on a
    /// 413 until it fits. Returns the exact prefix outcome so callers delete
    /// only records that were delivered, or the one record proven impossible to
    /// deliver because the receiver rejects it even by itself.
    ///
    /// Shared by both delivery pipelines so the receiver-limit handling is
    /// identical regardless of source type.
    pub async fn ship_capped_with_shrink(
        &self,
        lines: &[Vec<u8>],
        max_bytes: usize,
    ) -> CappedShipOutcome {
        if lines.is_empty() {
            return CappedShipOutcome::Deferred {
                reason: CappedShipDeferredReason::EmptyBatch,
            };
        }
        let mut n = byte_capped_take(lines, max_bytes);
        loop {
            let encoded = match self.encode_batch(&lines[..n]) {
                Ok((bytes, _)) => bytes,
                Err(e) => {
                    error!(error = %e, "failed to encode batch");
                    return CappedShipOutcome::Deferred {
                        reason: CappedShipDeferredReason::EncodeFailed,
                    };
                }
            };

            match self.send_with_retry(&encoded).await {
                Ok(ShipResult::Accepted { count }) if count as usize == n => {
                    return CappedShipOutcome::Delivered { count: n };
                }
                Ok(ShipResult::Accepted { count }) => {
                    warn!(
                        accepted = count,
                        requested = n,
                        "relay accepted count did not match request size, will retry"
                    );
                    return CappedShipOutcome::Deferred {
                        reason: CappedShipDeferredReason::AcceptedCountMismatch,
                    };
                }
                Ok(ShipResult::Rejected {
                    accepted,
                    rejected,
                    message,
                }) => {
                    warn!(accepted, rejected, error = %message, "batch rejected by relay, will retry");
                    return CappedShipOutcome::Deferred {
                        reason: CappedShipDeferredReason::RelayRejected,
                    };
                }
                Err(EdgepacerError::PayloadTooLarge(msg)) => {
                    if n > 1 {
                        let next = n / 2;
                        warn!(from = n, to = next, error = %msg, "payload too large, shrinking batch");
                        n = next;
                        continue;
                    }
                    error!(
                        error = %msg,
                        bytes = lines[0].len(),
                        "dropping a single entry the receiver rejects as too large (cannot ship)"
                    );
                    return CappedShipOutcome::DroppedOversized { count: 1 };
                }
                Err(e) => {
                    error!(error = %e, "non-retryable ship error");
                    return CappedShipOutcome::Deferred {
                        reason: CappedShipDeferredReason::ShipFailed,
                    };
                }
            }
        }
    }

    /// Encode a batch of log lines into protobuf.
    ///
    /// Borrows the lines so a caller can re-encode sub-slices (e.g. shrinking a
    /// batch on a payload-too-large rejection) without cloning the outer Vec.
    /// JSON object entries are reported as `EntryJson`, other valid UTF-8 as
    /// `RawText`, and rare non-UTF-8 lines as `RawBytes`.
    pub fn encode_batch(&self, lines: &[Vec<u8>]) -> Result<(Vec<u8>, u32), EdgepacerError> {
        let count = checked_wire_count("log entries", lines.len())?;
        let now_ms = unix_epoch_millis_i64();

        let metadata = self.envelope_metadata_bytes();
        let entries: Vec<WireLogEvent> = lines
            .iter()
            .map(|body| WireLogEvent {
                envelope: Some(EventEnvelope {
                    source_at_ms: Some(now_ms),
                    logtime_ms: None,
                    metadata_json: metadata.clone(),
                }),
                body: Some(log_line_body(body)),
            })
            .collect();

        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Logs(WireLogBatch { entries }),
        )?;

        debug!(
            lines = count,
            bytes = encoded.len(),
            "encoded logpacer-wire batch"
        );

        Ok((encoded, count))
    }

    /// Encode JSON log entries (self-telemetry) as EntryJson wire events.
    pub fn encode_entry_json_batch(
        &self,
        json_lines: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, u32), EdgepacerError> {
        let count = checked_wire_count("json log entries", json_lines.len())?;
        let now_ms = unix_epoch_millis_i64();

        let metadata = self.envelope_metadata_bytes();
        let entries: Vec<WireLogEvent> = json_lines
            .into_iter()
            .map(|body| WireLogEvent {
                envelope: Some(EventEnvelope {
                    source_at_ms: Some(now_ms),
                    logtime_ms: None,
                    metadata_json: metadata.clone(),
                }),
                body: Some(wire_log_event::Body::EntryJson(body)),
            })
            .collect();

        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Logs(WireLogBatch { entries }),
        )?;

        Ok((encoded, count))
    }

    /// Encode aggregated service-map edges as a `WireGraphBatch` (the graph
    /// arm). One `WireJsonEvent` per edge; mirrors `encode_entry_json_batch`
    /// but routes via `RoutedBatch::Payload::Graph` so LogRelay lands them in
    /// the account graph repo. Pair with `send_with_retry`.
    pub fn encode_graph_json_batch(
        &self,
        json_lines: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, u32), EdgepacerError> {
        let count = checked_wire_count("service-map edges", json_lines.len())?;
        let now_ms = unix_epoch_millis_i64();

        let metadata = self.envelope_metadata_bytes();
        let entries: Vec<WireJsonEvent> = json_lines
            .into_iter()
            .map(|body| WireJsonEvent {
                envelope: Some(EventEnvelope {
                    source_at_ms: Some(now_ms),
                    logtime_ms: None,
                    metadata_json: metadata.clone(),
                }),
                entry_json: body,
                embeds_json: Vec::new(),
            })
            .collect();

        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Graph(WireGraphBatch { entries }),
        )?;

        Ok((encoded, count))
    }

    /// Encode network flows as a `WireEbpfBatch` (the typed eBPF arm). Mirrors
    /// `encode_batch` but routes via `RoutedBatch::Payload::Ebpf`, one
    /// `WireEbpfEvent` per flow (`kind = NETWORK_FLOW`). Pair with `send_with_retry`.
    pub fn encode_ebpf_batch(
        &self,
        flows: Vec<NetworkFlow>,
    ) -> Result<(Vec<u8>, u32), EdgepacerError> {
        let count = checked_wire_count("network flows", flows.len())?;
        let now_ms = unix_epoch_millis_i64();

        let metadata = self.envelope_metadata_bytes();
        let entries: Vec<WireEbpfEvent> = flows
            .into_iter()
            .map(|flow| WireEbpfEvent {
                envelope: Some(EventEnvelope {
                    source_at_ms: Some(now_ms),
                    logtime_ms: None,
                    metadata_json: metadata.clone(),
                }),
                kind: EbpfEventKind::NetworkFlow as i32,
                event: Some(wire_ebpf_event::Event::Flow(flow)),
            })
            .collect();

        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Ebpf(WireEbpfBatch { entries }),
        )?;

        debug!(
            flows = count,
            bytes = encoded.len(),
            "encoded logpacer-wire ebpf batch"
        );

        Ok((encoded, count))
    }

    /// Encode L7 request spans as a `WireEbpfBatch` (the typed eBPF arm), one
    /// `WireEbpfEvent` per span (`kind = REQUEST`). Mirrors `encode_ebpf_batch`.
    /// Pair with `send_with_retry`.
    pub fn encode_request_signal_batch(
        &self,
        signals: Vec<RequestSignal>,
    ) -> Result<(Vec<u8>, u32), EdgepacerError> {
        let count = checked_wire_count("request signals", signals.len())?;
        let now_ms = unix_epoch_millis_i64();

        let metadata = self.envelope_metadata_bytes();
        let entries: Vec<WireEbpfEvent> = signals
            .into_iter()
            .map(|signal| WireEbpfEvent {
                envelope: Some(EventEnvelope {
                    source_at_ms: Some(now_ms),
                    logtime_ms: None,
                    metadata_json: metadata.clone(),
                }),
                kind: EbpfEventKind::Request as i32,
                event: Some(wire_ebpf_event::Event::Request(signal)),
            })
            .collect();

        let encoded = encode_single_batch(
            &self.archive_id,
            &self.repo_id,
            routed_batch::Payload::Ebpf(WireEbpfBatch { entries }),
        )?;

        debug!(
            spans = count,
            bytes = encoded.len(),
            "encoded logpacer-wire L7 span batch"
        );

        Ok((encoded, count))
    }

    /// Send an already-encoded protobuf payload with retry.
    ///
    /// This is the retry loop — call `encode_batch` once, then pass the
    /// encoded bytes here. Retries re-send the same bytes without re-encoding.
    pub async fn send_with_retry(&self, encoded: &[u8]) -> Result<ShipResult, EdgepacerError> {
        self.send_with_retry_policy(encoded, self.retry_policy)
            .await
    }

    /// Send an already-encoded payload with an explicit retry policy.
    pub(crate) async fn send_with_retry_policy(
        &self,
        encoded: &[u8],
        retry_policy: RetryPolicy,
    ) -> Result<ShipResult, EdgepacerError> {
        self.transport
            .send_with_retry(encoded, retry_policy, WireTransportPolicy::log_batches())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logpacer_wire::routed_batch;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn encoded_log_body(line: Vec<u8>) -> wire_log_event::Body {
        let shipper = Shipper::new("http://localhost:8080", "arc_test", "repo_app", None).unwrap();
        let lines = vec![line];
        let (buf, count) = shipper.encode_batch(&lines).unwrap();
        assert_eq!(count, 1);

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        let Some(routed_batch::Payload::Logs(logs)) = &decoded.batches[0].payload else {
            panic!("expected routed log payload");
        };
        logs.entries[0].body.clone().unwrap()
    }

    #[test]
    fn byte_cap_limits_batch_and_always_takes_one() {
        // Four 100-byte lines; with overhead each costs 228 bytes.
        let lines: Vec<Vec<u8>> = (0..4).map(|_| vec![b'x'; 100]).collect();

        // Budget for ~2 entries (2 * 228 = 456) → exactly 2 taken.
        assert_eq!(byte_capped_take(&lines, 500), 2);
        // Generous budget → all four.
        assert_eq!(byte_capped_take(&lines, 10_000), 4);
        // Budget smaller than a single entry → still takes 1 (guarantees progress).
        assert_eq!(byte_capped_take(&lines, 1), 1);
    }

    #[test]
    fn byte_cap_on_empty_is_zero() {
        assert_eq!(byte_capped_take(&[], 1024), 0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn checked_wire_count_rejects_oversized_batches() {
        let len = u32::MAX as usize + 1;
        let error = checked_wire_count("log entries", len).unwrap_err();

        assert!(matches!(
            error,
            EdgepacerError::WireCountTooLarge {
                field: "log entries",
                len: actual
            } if actual == len
        ));
    }

    #[test]
    fn encode_batch_reports_json_objects_as_entry_json() {
        let line = br#"{"time":"2026-07-04T23:35:09Z","level":"INFO","msg":"hello"}"#.to_vec();

        assert_eq!(
            encoded_log_body(line.clone()),
            wire_log_event::Body::EntryJson(line)
        );
    }

    #[test]
    fn encode_batch_keeps_non_object_json_as_raw_text() {
        assert_eq!(
            encoded_log_body(br#"[{"msg":"array payload"}]"#.to_vec()),
            wire_log_event::Body::RawText(r#"[{"msg":"array payload"}]"#.into())
        );
    }

    #[test]
    fn encode_batch_keeps_plain_text_as_raw_text() {
        assert_eq!(
            encoded_log_body(b"hello world".to_vec()),
            wire_log_event::Body::RawText("hello world".into())
        );
    }

    #[test]
    fn encode_wire_request_with_raw_text_logs() {
        let request = WireRequest {
            batches: vec![RoutedBatch {
                archive_id: "arc_test".into(),
                repo_id: "repo_app".into(),
                schema_version: 1,
                payload: Some(routed_batch::Payload::Logs(WireLogBatch {
                    entries: vec![WireLogEvent {
                        envelope: Some(EventEnvelope {
                            source_at_ms: Some(1000),
                            logtime_ms: None,
                            metadata_json: br#"{"resource_identifier":"host-1"}"#.to_vec(),
                        }),
                        body: Some(wire_log_event::Body::RawText("hello world".into())),
                    }],
                })),
            }],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        let Some(routed_batch::Payload::Logs(logs)) = &decoded.batches[0].payload else {
            panic!("expected routed log payload");
        };
        assert_eq!(decoded.batches[0].archive_id, "arc_test");
        assert_eq!(
            logs.entries[0].body.as_ref().unwrap(),
            &wire_log_event::Body::RawText("hello world".into())
        );
    }

    #[test]
    fn encode_graph_json_batch_routes_to_graph_payload() {
        let shipper =
            Shipper::new("http://localhost:8080", "arc_map", "service-map", None).unwrap();
        let edge =
            br#"{"ebpf_kind":"service_map_edge","src_service":"web","peer":"10.0.0.5:5432"}"#;

        let (buf, count) = shipper
            .encode_graph_json_batch(vec![edge.to_vec()])
            .unwrap();
        assert_eq!(count, 1);

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.batches[0].archive_id, "arc_map");
        assert_eq!(decoded.batches[0].repo_id, "service-map");
        let Some(routed_batch::Payload::Graph(graph)) = &decoded.batches[0].payload else {
            panic!("expected routed graph payload");
        };
        assert_eq!(graph.entries.len(), 1);
        assert_eq!(graph.entries[0].entry_json, edge.to_vec());
    }

    #[test]
    fn encode_wire_request_with_ebpf_flow_payload() {
        let shipper = Shipper::new("http://localhost:8080", "arc_test", "repo_app", None).unwrap();
        let flow = NetworkFlow {
            saddr: vec![127, 0, 0, 1],
            daddr: vec![10, 0, 0, 5],
            sport: 443,
            dport: 51_234,
            protocol: 6,
            bytes_tx: 100,
            bytes_rx: 200,
            packets_tx: 3,
            packets_rx: 4,
            pid: 42,
            cgroup_id: 99,
            netns_ino: 7,
            direction: 1,
        };

        let (buf, count) = shipper.encode_ebpf_batch(vec![flow.clone()]).unwrap();
        assert_eq!(count, 1);

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.batches[0].archive_id, "arc_test");
        assert_eq!(decoded.batches[0].repo_id, "repo_app");
        assert_eq!(decoded.batches[0].schema_version, 1);
        let Some(routed_batch::Payload::Ebpf(ebpf)) = &decoded.batches[0].payload else {
            panic!("expected routed ebpf payload");
        };
        assert_eq!(ebpf.entries.len(), 1);
        assert_eq!(ebpf.entries[0].kind, EbpfEventKind::NetworkFlow as i32);
        let Some(wire_ebpf_event::Event::Flow(decoded_flow)) = &ebpf.entries[0].event else {
            panic!("expected network flow event");
        };
        assert_eq!(decoded_flow, &flow);
    }

    #[test]
    fn encode_wire_request_with_request_signal_payload() {
        let shipper = Shipper::new("http://localhost:8080", "arc_test", "repo_app", None).unwrap();
        let signal = RequestSignal {
            trace_id: vec![0x11; 16],
            span_id: vec![0x22; 8],
            service_name: "checkout".into(),
            operation: "GET /cart".into(),
            status_code: 200,
            attributes: std::collections::HashMap::from([("http.method".into(), "GET".into())]),
            ..Default::default()
        };

        let (buf, count) = shipper
            .encode_request_signal_batch(vec![signal.clone()])
            .unwrap();
        assert_eq!(count, 1);

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.batches[0].archive_id, "arc_test");
        assert_eq!(decoded.batches[0].repo_id, "repo_app");
        assert_eq!(decoded.batches[0].schema_version, 1);
        let Some(routed_batch::Payload::Ebpf(ebpf)) = &decoded.batches[0].payload else {
            panic!("expected routed ebpf payload");
        };
        assert_eq!(ebpf.entries.len(), 1);
        assert_eq!(ebpf.entries[0].kind, EbpfEventKind::Request as i32);
        let Some(wire_ebpf_event::Event::Request(decoded_signal)) = &ebpf.entries[0].event else {
            panic!("expected request signal event");
        };
        assert_eq!(decoded_signal, &signal);
    }

    #[tokio::test]
    async fn log_transport_preserves_payload_too_large_for_shrink() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_test",
            "repo_test",
            None,
        )
        .unwrap();
        let error = shipper
            .send_with_retry_policy(
                b"encoded payload",
                RetryPolicy {
                    max_attempts: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(error, EdgepacerError::PayloadTooLarge(_)));
    }

    #[tokio::test]
    async fn transport_returns_typed_wire_decode_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(vec![0xff], "application/x-protobuf"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_test",
            "repo_test",
            None,
        )
        .unwrap();
        let error = shipper
            .send_with_retry_policy(
                b"encoded payload",
                RetryPolicy {
                    max_attempts: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EdgepacerError::WireDecode {
                context: "failed to decode response",
                ..
            }
        ));
    }

    #[test]
    fn stamps_resource_identifier_only_when_identity_present() {
        // Default (no identity): empty metadata object, no per-line identity bytes.
        let off = Shipper::new("http://x/wire", "arc", "repo", None).unwrap();
        assert_eq!(off.envelope_metadata_bytes(), b"{}");

        // Opted in: the live identity is stamped under the relay's field name.
        let on = Shipper::new(
            "http://x/wire",
            "arc",
            "repo",
            Some(AgentIdentity::new("host-1".into())),
        )
        .unwrap();
        assert_eq!(
            on.envelope_metadata_bytes(),
            br#"{"resource_identifier":"host-1"}"#.to_vec()
        );
    }

    #[test]
    fn stamped_metadata_tracks_live_identity_repin() {
        // A re-pin via the shared cell is visible on the next encoded batch — no
        // shipper reconstruction — because metadata is built at encode time.
        let identity = AgentIdentity::new("before".into());
        let shipper = Shipper::new("http://x/wire", "arc", "repo", Some(identity.clone())).unwrap();
        assert_eq!(
            shipper.envelope_metadata_bytes(),
            br#"{"resource_identifier":"before"}"#.to_vec()
        );
        identity.apply_config("after");
        assert_eq!(
            shipper.envelope_metadata_bytes(),
            br#"{"resource_identifier":"after"}"#.to_vec()
        );
    }
}
