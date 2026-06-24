//! Map a reconstructed [`L7Record`] to a `logpacer_wire::RequestSignal` — the
//! span-like record the server renders as a trace span (the `EBPF_EVENT_KIND_REQUEST`
//! arm; L7 is a new *producer* of an existing wire type, not a new contract).
//!
//! v1 emits **spanlets**: each request is its own root span. `trace_id`/`span_id`
//! are minted by the wiring layer (which owns the RNG + timing); `parent_span_id`
//! is empty until trace-context propagation (a later GAP) stitches hops.

use logpacer_wire::RequestSignal;

use super::L7Record;

/// Per-request context the parsed record can't supply — provided by the wiring
/// layer from PID→service routing and minted span ids. Timing, operation, and
/// status all live on the [`L7Record`].
#[derive(Debug, Clone)]
pub struct SpanContext {
    pub service_name: String,
    pub pid: u32,
    pub cgroup_id: u64,
    pub trace_id: Vec<u8>,
    pub span_id: Vec<u8>,
    /// The connection's peer endpoint `"ip:port"` — the service-map edge's other
    /// node (the destination of an outbound call / the source of an inbound one).
    /// `None` when it couldn't be resolved (e.g. a TLS ssl-derived fd).
    pub peer: Option<String>,
}

/// Build a `RequestSignal` from a parsed record + its context.
pub fn to_request_signal(record: &L7Record, ctx: &SpanContext) -> RequestSignal {
    RequestSignal {
        trace_id: ctx.trace_id.clone(),
        span_id: ctx.span_id.clone(),
        parent_span_id: Vec::new(),
        service_name: ctx.service_name.clone(),
        operation: record.operation.clone(),
        start_unix_nano: record.start_unix_nano,
        duration_nano: record.duration_nano,
        status_code: u32::from(record.status_code),
        pid: ctx.pid,
        cgroup_id: ctx.cgroup_id,
        attributes: span_attributes(record, ctx),
    }
}

/// Span attributes carrying the service-map facts the bare fields don't: the wire
/// `protocol` (the edge's protocol label) and `peer.address` (the edge's other
/// node). LogPacer draws `service_name -> peer.address` edges labelled by these.
fn span_attributes(
    record: &L7Record,
    ctx: &SpanContext,
) -> std::collections::HashMap<String, String> {
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("protocol".to_string(), record.protocol.name().to_string());
    if let Some(peer) = &ctx.peer {
        attributes.insert("peer.address".to_string(), peer.clone());
    }
    // Protocol-specific enrichment the parser attached (HTTP host, llm.model, …).
    for (key, value) in &record.attributes {
        attributes.insert(key.clone(), value.clone());
    }
    attributes
}

/// Mint a span/trace id without a crypto RNG: spread a monotonic `seed` with a
/// splitmix64 finalizer, repeated to fill `len` bytes. v1 emits spanlets, so ids
/// only need to be unique per agent run; cryptographic randomness + propagated
/// trace ids arrive with trace-context (a later GAP).
pub fn mint_id(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::l7::Protocol;

    fn record() -> L7Record {
        L7Record {
            protocol: Protocol::Http1,
            attributes: Vec::new(),
            operation: "GET /api/users".into(),
            status_code: 503,
            error: true,
            start_unix_nano: 1_000,
            duration_nano: 250,
        }
    }

    fn ctx() -> SpanContext {
        SpanContext {
            service_name: "checkout".into(),
            pid: 4242,
            cgroup_id: 99,
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            peer: Some("10.0.0.5:5432".to_string()),
        }
    }

    #[test]
    fn maps_record_and_context_onto_request_signal() {
        let sig = to_request_signal(&record(), &ctx());
        assert_eq!(sig.operation, "GET /api/users");
        assert_eq!(sig.status_code, 503);
        assert_eq!(sig.service_name, "checkout");
        assert_eq!(sig.pid, 4242);
        assert_eq!(sig.cgroup_id, 99);
        assert_eq!(sig.duration_nano, 250);
        assert_eq!(sig.start_unix_nano, 1_000);
        assert_eq!(sig.trace_id.len(), 16);
        assert_eq!(sig.span_id.len(), 8);
        assert!(sig.parent_span_id.is_empty()); // spanlet — no parent yet
        // Service-map attributes: the protocol label + the peer (edge's other node).
        assert_eq!(
            sig.attributes.get("protocol").map(String::as_str),
            Some("http")
        );
        assert_eq!(
            sig.attributes.get("peer.address").map(String::as_str),
            Some("10.0.0.5:5432")
        );
    }

    #[test]
    fn mint_id_has_length_and_varies_by_seed() {
        assert_eq!(mint_id(16, 1).len(), 16);
        assert_eq!(mint_id(8, 1).len(), 8);
        assert_ne!(mint_id(16, 1), mint_id(16, 2));
        assert_ne!(mint_id(8, 42), mint_id(8, 43));
    }
}
