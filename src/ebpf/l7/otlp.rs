//! Map a reconstructed [`L7Record`] to an OTLP `Span` rendered through
//! `trace_wire::span_to_json_value` — the same ingest contract SDK spans use
//! (the `Traces` arm). Successor to the `RequestSignal` producer in `span.rs`,
//! dual-shipped alongside it until that arm is retired.
//!
//! The `#[ignore]`d acceptance tests below are the standing definition of
//! "near-native fidelity": field-set parity with an SDK-built span rendered
//! through the same serializer. They are owned by the reviewer — implement
//! until they pass with the `#[ignore]` attributes removed; any change to
//! their expectations needs reviewer sign-off.

use opentelemetry_proto::tonic::trace::v1::{Span, span::SpanKind};

use super::L7Record;
use super::span::SpanContext;

/// Build an OTLP `Span` from a parsed record + its context.
///
/// `kind` is the wiring layer's client/server verdict, derived where the
/// port-hint flip is computed: `Some(Client)` when the flip marked the
/// monitored process as the client, `Some(Server)` when a hint was present
/// without a flip, and `None` for unhinted signature-detected flows — which
/// must render as `UNSPECIFIED`, never as a guessed `SERVER`.
#[allow(dead_code)] // wired into the runner's flush path later in Slice 1 (dual-ship)
pub fn to_otlp_span(record: &L7Record, ctx: &SpanContext, kind: Option<SpanKind>) -> Span {
    // Slice 1 stub: identity + timing only, so the acceptance tests compile
    // and fail. Kind, status, and the attribute set are the work.
    let _ = kind;
    Span {
        trace_id: ctx.trace_id.clone(),
        span_id: ctx.span_id.clone(),
        name: record.operation.clone(),
        start_time_unix_nano: record.start_unix_nano as u64,
        end_time_unix_nano: (record.start_unix_nano + record.duration_nano) as u64,
        ..Default::default()
    }
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
    #[ignore = "Slice 1 acceptance — implement to_otlp_span, then remove this ignore"]
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
    #[ignore = "Slice 1 acceptance — implement to_otlp_span, then remove this ignore"]
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
    #[ignore = "Slice 1 acceptance — implement to_otlp_span, then remove this ignore"]
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
}
