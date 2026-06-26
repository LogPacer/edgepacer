//! Trace → wire JSON encoding.
//!
//! Converts OTLP spans into the JSON-object shape LogPacer ingest accepts, packed
//! into a `WireTraceBatch` (the traces arm of the routed logpacer-wire
//! protocol). Each span becomes one `entries_json[i]` byte string, mirroring
//! how host metrics ship opaque JSON via `WireMetricBatch`.
//!
//! The JSON field set and the `kind`/`status` string mappings match logrelay's
//! `span_to_json` field-for-field — logrelay decodes these objects and logpacer
//! queries them, so the shape is a contract, not an implementation detail.

use opentelemetry_proto::tonic::common::v1::{
    AnyValue, KeyValue, any_value::Value as AnyValueKind,
};
use opentelemetry_proto::tonic::trace::v1::{Span, Status, span::SpanKind, status::StatusCode};
use serde_json::{Map, Value, json};

/// Wire field name carrying a span's owning service, mirrored from the resource
/// attribute `service.name`.
const SERVICE_NAME_KEY: &str = "service.name";

/// Convert an OTLP span to the JSON object LogPacer ingest accepts.
///
/// `resource_attributes` is the already-computed JSON object of the owning
/// `ResourceSpans` resource attributes (built once per resource and shared
/// across its spans). `service_name` is the resolved `service.name` for that
/// resource (empty when absent — the field is then omitted).
///
/// Field set and `kind`/`status` mappings match logrelay's `span_to_json`.
pub fn span_to_json_value(span: &Span, service_name: &str, resource_attributes: &Value) -> Value {
    let mut obj = Map::new();

    // Trace and span IDs (lowercase hex).
    obj.insert("trace_id".into(), json!(hex::encode(&span.trace_id)));
    obj.insert("span_id".into(), json!(hex::encode(&span.span_id)));

    // Root spans omit the field entirely.
    if !span.parent_span_id.is_empty() {
        obj.insert(
            "parent_span_id".into(),
            json!(hex::encode(&span.parent_span_id)),
        );
    }

    obj.insert("name".into(), json!(span.name));
    obj.insert("kind".into(), json!(span_kind_str(span.kind)));

    // Timestamps: nanos → millis.
    let start_ms = span.start_time_unix_nano / 1_000_000;
    let end_ms = span.end_time_unix_nano / 1_000_000;
    obj.insert("start_time".into(), json!(start_ms));
    obj.insert("end_time".into(), json!(end_ms));
    obj.insert("duration_ms".into(), json!(end_ms.saturating_sub(start_ms)));

    // Attributes: always present, `{}` when none.
    obj.insert("attributes".into(), attrs_to_json(&span.attributes));

    // Resource attributes: the shared, precomputed object.
    obj.insert("resource_attributes".into(), resource_attributes.clone());

    // Events: omit when none.
    if !span.events.is_empty() {
        let events: Vec<Value> = span
            .events
            .iter()
            .map(|event| {
                let mut e = Map::new();
                e.insert("time".into(), json!(event.time_unix_nano / 1_000_000));
                e.insert("name".into(), json!(event.name));
                if !event.attributes.is_empty() {
                    e.insert("attributes".into(), attrs_to_json(&event.attributes));
                }
                Value::Object(e)
            })
            .collect();
        obj.insert("events".into(), Value::Array(events));
    }

    // Links: omit when none.
    if !span.links.is_empty() {
        let links: Vec<Value> = span
            .links
            .iter()
            .map(|link| {
                let mut l = Map::new();
                l.insert("trace_id".into(), json!(hex::encode(&link.trace_id)));
                l.insert("span_id".into(), json!(hex::encode(&link.span_id)));
                if !link.attributes.is_empty() {
                    l.insert("attributes".into(), attrs_to_json(&link.attributes));
                }
                Value::Object(l)
            })
            .collect();
        obj.insert("links".into(), Value::Array(links));
    }

    // Status: omit when absent.
    if let Some(status) = span.status.as_ref() {
        obj.insert("status".into(), status_to_json(status));
    }

    // Service name: omit when empty.
    if !service_name.is_empty() {
        obj.insert("service_name".into(), json!(service_name));
    }

    Value::Object(obj)
}

/// Resolve the `service.name` string attribute from a resource's attributes.
///
/// Returns an empty string when absent or not a string value, matching the
/// "omit `service_name`" contract.
pub fn service_name_from_attrs(attrs: &[KeyValue]) -> String {
    attrs
        .iter()
        .find(|kv| kv.key == SERVICE_NAME_KEY)
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| match v.value.as_ref() {
            Some(AnyValueKind::StringValue(s)) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Map an OTLP `SpanKind` enum value to its wire string.
fn span_kind_str(kind: i32) -> &'static str {
    match SpanKind::try_from(kind) {
        Ok(SpanKind::Internal) => "INTERNAL",
        Ok(SpanKind::Server) => "SERVER",
        Ok(SpanKind::Client) => "CLIENT",
        Ok(SpanKind::Producer) => "PRODUCER",
        Ok(SpanKind::Consumer) => "CONSUMER",
        _ => "UNSPECIFIED",
    }
}

/// Serialize a span `Status` to `{"code":...,"message"?:...}`.
fn status_to_json(status: &Status) -> Value {
    let code = match StatusCode::try_from(status.code) {
        Ok(StatusCode::Ok) => "OK",
        Ok(StatusCode::Error) => "ERROR",
        _ => "UNSET",
    };
    let mut obj = Map::new();
    obj.insert("code".into(), json!(code));
    if !status.message.is_empty() {
        obj.insert("message".into(), json!(status.message));
    }
    Value::Object(obj)
}

/// Convert a list of OTLP `KeyValue` attributes to a JSON object.
pub fn attrs_to_json(attrs: &[KeyValue]) -> Value {
    let mut obj = Map::new();
    for kv in attrs {
        obj.insert(kv.key.clone(), anyvalue_to_json(kv.value.as_ref()));
    }
    Value::Object(obj)
}

/// Convert an optional OTLP `AnyValue` to JSON.
///
/// string→string, int→number, double→number (NaN/Inf→null), bool→bool,
/// bytes→lossy UTF-8 string, array/kvlist→nested. Absent → null.
fn anyvalue_to_json(value: Option<&AnyValue>) -> Value {
    match value.and_then(|v| v.value.as_ref()) {
        Some(AnyValueKind::StringValue(s)) => json!(s),
        Some(AnyValueKind::IntValue(i)) => json!(i),
        Some(AnyValueKind::DoubleValue(d)) => serde_json::Number::from_f64(*d)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some(AnyValueKind::BoolValue(b)) => json!(b),
        Some(AnyValueKind::BytesValue(b)) => json!(String::from_utf8_lossy(b)),
        Some(AnyValueKind::ArrayValue(arr)) => Value::Array(
            arr.values
                .iter()
                .map(|v| anyvalue_to_json(Some(v)))
                .collect(),
        ),
        Some(AnyValueKind::KvlistValue(kv)) => attrs_to_json(&kv.values),
        Some(AnyValueKind::StringValueStrindex(_)) => Value::Null,
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, KeyValue, KeyValueList};
    use opentelemetry_proto::tonic::trace::v1::{Span, Status, span};

    fn str_attr(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            key_strindex: 0,
            value: Some(AnyValue {
                value: Some(AnyValueKind::StringValue(value.to_string())),
            }),
        }
    }

    fn any(kind: AnyValueKind) -> AnyValue {
        AnyValue { value: Some(kind) }
    }

    #[test]
    fn span_with_parent_attributes_and_status_serializes_expected_shape() {
        let span = Span {
            trace_id: vec![0xab; 16],
            span_id: vec![0xcd; 8],
            parent_span_id: vec![0xef; 8],
            name: "GET /checkout".into(),
            kind: span::SpanKind::Server as i32,
            start_time_unix_nano: 5_000_000_000,
            end_time_unix_nano: 5_250_000_000,
            attributes: vec![
                str_attr("http.method", "GET"),
                KeyValue {
                    key: "http.status_code".into(),
                    key_strindex: 0,
                    value: Some(any(AnyValueKind::IntValue(200))),
                },
            ],
            status: Some(Status {
                code: super::StatusCode::Error as i32,
                message: "boom".into(),
            }),
            ..Default::default()
        };

        let resource_attrs = attrs_to_json(&[str_attr("service.name", "checkout")]);
        let value = span_to_json_value(&span, "checkout", &resource_attrs);

        assert_eq!(value["trace_id"], json!("ab".repeat(16)));
        assert_eq!(value["span_id"], json!("cd".repeat(8)));
        assert_eq!(value["parent_span_id"], json!("ef".repeat(8)));
        assert_eq!(value["name"], json!("GET /checkout"));
        assert_eq!(value["kind"], json!("SERVER"));
        // 5_000_000_000 ns → 5000 ms; 5_250_000_000 ns → 5250 ms.
        assert_eq!(value["start_time"], json!(5000));
        assert_eq!(value["end_time"], json!(5250));
        assert_eq!(value["duration_ms"], json!(250));
        assert_eq!(value["attributes"]["http.method"], json!("GET"));
        assert_eq!(value["attributes"]["http.status_code"], json!(200));
        assert_eq!(
            value["resource_attributes"]["service.name"],
            json!("checkout")
        );
        assert_eq!(value["status"]["code"], json!("ERROR"));
        assert_eq!(value["status"]["message"], json!("boom"));
        assert_eq!(value["service_name"], json!("checkout"));
    }

    #[test]
    fn root_span_omits_parent_and_empty_collections() {
        let span = Span {
            trace_id: vec![0x01; 16],
            span_id: vec![0x02; 8],
            // parent_span_id left empty → root span.
            name: "root".into(),
            kind: span::SpanKind::Internal as i32,
            start_time_unix_nano: 1_000_000,
            end_time_unix_nano: 1_000_000,
            ..Default::default()
        };

        let value = span_to_json_value(&span, "", &json!({}));
        let obj = value.as_object().unwrap();

        assert!(
            !obj.contains_key("parent_span_id"),
            "root span omits parent_span_id"
        );
        assert!(!obj.contains_key("events"), "no events → omitted");
        assert!(!obj.contains_key("links"), "no links → omitted");
        assert!(!obj.contains_key("status"), "no status → omitted");
        assert!(
            !obj.contains_key("service_name"),
            "empty service_name → omitted"
        );
        // Attributes are always present, even when empty.
        assert_eq!(value["attributes"], json!({}));
        assert_eq!(value["kind"], json!("INTERNAL"));
        assert_eq!(value["duration_ms"], json!(0));
    }

    #[test]
    fn anyvalue_mapping_covers_all_arms() {
        assert_eq!(anyvalue_to_json(None), Value::Null);
        assert_eq!(
            anyvalue_to_json(Some(&any(AnyValueKind::BoolValue(true)))),
            json!(true)
        );
        assert_eq!(
            anyvalue_to_json(Some(&any(AnyValueKind::DoubleValue(1.5)))),
            json!(1.5)
        );
        // NaN/Inf are not representable in JSON → null.
        assert_eq!(
            anyvalue_to_json(Some(&any(AnyValueKind::DoubleValue(f64::NAN)))),
            Value::Null
        );
        assert_eq!(
            anyvalue_to_json(Some(&any(AnyValueKind::BytesValue(b"hi".to_vec())))),
            json!("hi")
        );

        let nested = any(AnyValueKind::ArrayValue(ArrayValue {
            values: vec![
                any(AnyValueKind::IntValue(1)),
                any(AnyValueKind::StringValue("x".into())),
            ],
        }));
        assert_eq!(anyvalue_to_json(Some(&nested)), json!([1, "x"]));

        let kvlist = any(AnyValueKind::KvlistValue(KeyValueList {
            values: vec![str_attr("k", "v")],
        }));
        assert_eq!(anyvalue_to_json(Some(&kvlist)), json!({ "k": "v" }));
    }

    #[test]
    fn service_name_from_attrs_reads_string_or_empties() {
        assert_eq!(
            service_name_from_attrs(&[str_attr("service.name", "api")]),
            "api"
        );
        assert_eq!(service_name_from_attrs(&[]), "");
        // A non-string service.name is not a usable name.
        assert_eq!(
            service_name_from_attrs(&[KeyValue {
                key: "service.name".into(),
                key_strindex: 0,
                value: Some(any(AnyValueKind::IntValue(0))),
            }]),
            ""
        );
    }
}
