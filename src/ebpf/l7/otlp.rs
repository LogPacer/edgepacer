//! Map a reconstructed [`L7Record`] to an OTLP `Span` rendered through
//! `trace_wire::span_to_json_value` — the same ingest contract SDK spans use
//! (the `Traces` arm). Successor to the `RequestSignal` producer in `span.rs`,
//! dual-shipped alongside it until that arm is retired.
//!
//! The acceptance tests below are the standing definition of "near-native
//! fidelity": field-set parity with an SDK-built span rendered through the
//! same serializer. They are owned by the reviewer; any change to their
//! expectations needs reviewer sign-off.

use opentelemetry_proto::tonic::common::v1::{
    AnyValue, KeyValue, any_value::Value as AnyValueKind,
};
use opentelemetry_proto::tonic::trace::v1::{Span, Status, span::SpanKind, status::StatusCode};

use super::L7Record;
use super::Protocol;
use super::span::SpanContext;

/// Build an OTLP `Span` from a parsed record + its context.
///
/// `kind` is the wiring layer's client/server verdict, derived where the
/// port-hint flip is computed: `Some(Client)` when the flip marked the
/// monitored process as the client, `Some(Server)` when a hint was present
/// without a flip, and `None` for unhinted signature-detected flows — which
/// must render as `UNSPECIFIED`, never as a guessed `SERVER`.
pub fn to_otlp_span(record: &L7Record, ctx: &SpanContext, kind: Option<SpanKind>) -> Span {
    // Propagated requests join the caller's trace: the runner adopts the
    // propagated trace id into ctx (so BOTH arms carry it identically), and
    // here the remote parent + raw tracestate attach. `trace_id` stays
    // ctx-owned — the builder must not second-guess ctx. Un-propagated
    // requests stay root spans with no trace_state.
    let (parent_span_id, trace_state) = match record.propagated.as_ref() {
        Some(p) => (p.parent_span_id.to_vec(), p.trace_state.clone()),
        None => (Vec::new(), String::new()),
    };
    Span {
        trace_id: ctx.trace_id.clone(),
        span_id: ctx.span_id.clone(),
        parent_span_id,
        name: record.operation.clone(),
        // Unhinted flows stay UNSPECIFIED — the kind is never guessed.
        kind: kind.unwrap_or(SpanKind::Unspecified) as i32,
        start_time_unix_nano: record.start_unix_nano as u64,
        end_time_unix_nano: (record.start_unix_nano + record.duration_nano) as u64,
        attributes: span_attributes(record, ctx),
        // Errors surface as an ERROR status; success leaves status UNSET —
        // the contract here is UNSET-or-ERROR, never OK.
        status: record.error.then(|| Status {
            code: StatusCode::Error as i32,
            message: String::new(),
        }),
        trace_state,
        ..Default::default()
    }
}

/// Typed span attributes: the service-map facts the bare fields don't carry
/// (the wire `protocol` label and `peer.address`, the same facts
/// `span::to_request_signal` ships), the parser's enrichment pairs as
/// strings, plus the HTTP status code as a typed int — http family only;
/// other protocols get no status-code attribute.
fn span_attributes(record: &L7Record, ctx: &SpanContext) -> Vec<KeyValue> {
    let mut attributes = Vec::with_capacity(record.attributes.len() + 3);
    attributes.push(KeyValue {
        key: "protocol".to_string(),
        key_strindex: 0,
        value: Some(AnyValue {
            value: Some(AnyValueKind::StringValue(
                record.protocol.name().to_string(),
            )),
        }),
    });
    if let Some(peer) = &ctx.peer {
        attributes.push(KeyValue {
            key: "peer.address".to_string(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::StringValue(peer.clone())),
            }),
        });
    }
    // Protocol-specific enrichment the parser attached (HTTP host, llm.model, …).
    for (key, value) in &record.attributes {
        attributes.push(KeyValue {
            key: key.clone(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::StringValue(value.clone())),
            }),
        });
    }
    if matches!(record.protocol, Protocol::Http1 | Protocol::Http2) {
        attributes.push(KeyValue {
            key: "http.response.status_code".to_string(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::IntValue(i64::from(record.status_code))),
            }),
        });
    }
    attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::l7::Protocol;
    use crate::trace_wire::span_to_json_value;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, KeyValue, any_value::Value as AnyValueKind,
    };
    use opentelemetry_proto::tonic::trace::v1::{Status, status::StatusCode};
    use serde_json::json;

    fn str_attr(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::StringValue(value.to_string())),
            }),
        }
    }

    fn int_attr(key: &str, value: i64) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::IntValue(value)),
            }),
        }
    }

    fn record() -> L7Record {
        L7Record {
            protocol: Protocol::Http1,
            attributes: vec![("http.host".to_string(), "api.internal".to_string())],
            operation: "GET /api/users".into(),
            status_code: 503,
            error: true,
            start_unix_nano: 5_000_000_000,
            duration_nano: 250_000_000,
            propagated: None,
        }
    }

    fn ctx() -> SpanContext {
        SpanContext {
            service_name: "checkout".into(),
            pid: 4242,
            cgroup_id: 99,
            trace_id: vec![0xab; 16],
            span_id: vec![0xcd; 8],
            peer: Some("10.0.0.5:8080".to_string()),
        }
    }

    fn resource_attrs() -> serde_json::Value {
        json!({"service.name": "checkout"})
    }

    /// The SDK-built twin of [`record`]: what an OTel SDK would have produced
    /// for the same request. The eBPF builder's output must be
    /// indistinguishable from this at the ingest JSON, modulo provenance
    /// resource attributes (held equal here by passing the same resource
    /// object to both renders).
    fn sdk_twin() -> Span {
        Span {
            trace_id: vec![0xab; 16],
            span_id: vec![0xcd; 8],
            name: "GET /api/users".into(),
            kind: SpanKind::Server as i32,
            start_time_unix_nano: 5_000_000_000,
            end_time_unix_nano: 5_250_000_000,
            attributes: vec![
                str_attr("protocol", "http"),
                str_attr("peer.address", "10.0.0.5:8080"),
                str_attr("http.host", "api.internal"),
                int_attr("http.response.status_code", 503),
            ],
            status: Some(Status {
                code: StatusCode::Error as i32,
                message: String::new(),
            }),
            ..Default::default()
        }
    }

    /// §3 acceptance: same top-level field set, same kind/status encodings,
    /// same attribute object (typed values included) as the SDK twin.
    #[test]
    fn parity_with_sdk_built_span_at_the_ingest_json() {
        let ebpf = span_to_json_value(
            &to_otlp_span(&record(), &ctx(), Some(SpanKind::Server)),
            "checkout",
            &resource_attrs(),
        );
        let sdk = span_to_json_value(&sdk_twin(), "checkout", &resource_attrs());

        let keys = |v: &serde_json::Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&ebpf), keys(&sdk), "top-level field sets must match");
        assert_eq!(ebpf["kind"], json!("SERVER"));
        assert_eq!(ebpf["status"], sdk["status"], "error must encode as ERROR");
        assert_eq!(
            ebpf["attributes"], sdk["attributes"],
            "attribute object must match, typed status code included"
        );
        assert_eq!(ebpf["duration_ms"], json!(250));
        assert!(
            ebpf.get("parent_span_id").is_none(),
            "spanlet stays a root span until propagation/hierarchy"
        );
    }

    /// Kind is tri-state and never guessed: flip → CLIENT, hinted no-flip →
    /// SERVER, unhinted → UNSPECIFIED.
    #[test]
    fn kind_is_tri_state_and_never_guessed() {
        for (kind, expected) in [
            (Some(SpanKind::Client), "CLIENT"),
            (Some(SpanKind::Server), "SERVER"),
            (None, "UNSPECIFIED"),
        ] {
            let value = span_to_json_value(
                &to_otlp_span(&record(), &ctx(), kind),
                "checkout",
                &resource_attrs(),
            );
            assert_eq!(value["kind"], json!(expected));
        }
    }

    /// OTel convention: no error → status omitted entirely (UNSET), never OK;
    /// error → status present. Both halves asserted so the omission half can't
    /// pass vacuously against a builder that never sets status at all.
    #[test]
    fn status_present_on_error_and_omitted_entirely_on_success() {
        let ok = L7Record {
            status_code: 200,
            error: false,
            ..record()
        };
        let ok_value = span_to_json_value(
            &to_otlp_span(&ok, &ctx(), Some(SpanKind::Server)),
            "checkout",
            &resource_attrs(),
        );
        assert!(
            ok_value.get("status").is_none(),
            "UNSET must omit the status object — emitting OK is a contract violation"
        );

        let err_value = span_to_json_value(
            &to_otlp_span(&record(), &ctx(), Some(SpanKind::Server)),
            "checkout",
            &resource_attrs(),
        );
        assert_eq!(
            err_value["status"]["code"],
            json!("ERROR"),
            "record.error must surface as status ERROR"
        );
    }

    /// The typed status code is http-family enrichment: Http1 and Http2 carry
    /// it as an int, every other protocol's span omits it in this slice.
    #[test]
    fn status_code_attribute_is_http_family_only_and_typed() {
        for protocol in [Protocol::Http1, Protocol::Http2] {
            let span = to_otlp_span(
                &L7Record {
                    protocol,
                    ..record()
                },
                &ctx(),
                Some(SpanKind::Server),
            );
            let kv = span
                .attributes
                .iter()
                .find(|kv| kv.key == "http.response.status_code")
                .expect("http family carries the status code attribute");
            assert_eq!(
                kv.value.as_ref().and_then(|v| v.value.as_ref()),
                Some(&AnyValueKind::IntValue(503)),
                "the status code ships as a typed int, not a string"
            );
        }

        let span = to_otlp_span(
            &L7Record {
                protocol: Protocol::Postgres,
                ..record()
            },
            &ctx(),
            Some(SpanKind::Server),
        );
        assert!(
            span.attributes
                .iter()
                .all(|kv| kv.key != "http.response.status_code"),
            "non-http records get no status-code attribute in this slice"
        );
    }

    /// Attribute order is ingest-shaped: service-map facts first, parser
    /// enrichment in record order, typed status code last.
    #[test]
    fn attribute_order_is_protocol_peer_enrichment_then_status_code() {
        let span = to_otlp_span(&record(), &ctx(), Some(SpanKind::Server));
        let keys: Vec<&str> = span.attributes.iter().map(|kv| kv.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "protocol",
                "peer.address",
                "http.host",
                "http.response.status_code",
            ]
        );
    }

    /// `peer.address` comes from the connection peer; when it couldn't be
    /// resolved the attribute is omitted, not emitted empty.
    #[test]
    fn missing_peer_omits_peer_address_attribute() {
        let no_peer = SpanContext {
            peer: None,
            ..ctx()
        };
        let span = to_otlp_span(&record(), &no_peer, None);
        assert!(
            span.attributes.iter().all(|kv| kv.key != "peer.address"),
            "an unresolved peer must omit the attribute entirely"
        );
    }

    /// Slice 2 acceptance (reviewer-owned): a record carrying a propagated
    /// context yields a span whose `parent_span_id` and `trace_state` come
    /// from it — while a record without one keeps today's exact root-span
    /// shape. Both halves in one test so neither can pass vacuously. The
    /// span's `trace_id` intentionally stays `ctx.trace_id`: the runner
    /// adopts the propagated trace id where it builds the context, so BOTH
    /// arms carry it identically — `to_otlp_span` must not second-guess ctx.
    #[test]
    fn propagated_context_sets_parent_and_trace_state_and_absence_changes_nothing() {
        let propagated = crate::ebpf::l7::PropagatedContext {
            trace_id: [0x4b; 16],
            parent_span_id: [0xf0; 8],
            trace_flags: 0x01,
            trace_state: "vendor=opaque".to_string(),
        };
        let with = L7Record {
            propagated: Some(propagated),
            ..record()
        };
        let span = to_otlp_span(&with, &ctx(), Some(SpanKind::Server));
        assert_eq!(
            span.parent_span_id,
            vec![0xf0; 8],
            "propagated parent becomes the span's remote parent"
        );
        assert_eq!(
            span.trace_state, "vendor=opaque",
            "raw tracestate passes through onto the span"
        );
        assert_eq!(
            span.trace_id,
            ctx().trace_id,
            "trace id stays ctx-owned — the runner adopts it for both arms"
        );

        let without = to_otlp_span(&record(), &ctx(), Some(SpanKind::Server));
        assert!(
            without.parent_span_id.is_empty(),
            "no propagation → still a root span"
        );
        assert!(
            without.trace_state.is_empty(),
            "no propagation → no trace_state"
        );
    }
}
