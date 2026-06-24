//! RED metrics (Rate / Errors / Duration) aggregated per `(service, endpoint)`.
//! The endpoint is normalised — numeric and UUID/hex path segments collapse to
//! `{}` — so `/users/1`, `/users/2`, … become one low-cardinality series instead
//! of a new series per id (the classic RED cardinality blow-up).
//!
//! Pure + unit-tested. Each flush tick `drain`s the accumulated series into JSON
//! entries that ride the existing metrics arm (`MetricsShipper`/`WireMetricBatch`,
//! `entries_json`); the server-side RED schema is still TBD, so the entry shape
//! below is the proposed contract, not a frozen one.

use std::collections::HashMap;

use super::L7Record;

/// One accumulated `(service, endpoint)` series over a flush window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedEntry {
    pub service: String,
    pub endpoint: String,
    pub requests: u64,
    pub errors: u64,
    /// Sum of observed durations (ns). With `requests` this gives mean latency;
    /// a bucketed histogram for percentiles is a refinement.
    pub duration_nano_sum: i64,
}

impl RedEntry {
    /// Encode as a flat JSON metric entry for `WireMetricBatch.entries_json`.
    pub fn to_json(&self) -> Vec<u8> {
        let v = serde_json::json!({
            "metric": "ebpf_red",
            "service": self.service,
            "endpoint": self.endpoint,
            "requests": self.requests,
            "errors": self.errors,
            "duration_nano_sum": self.duration_nano_sum,
        });
        serde_json::to_vec(&v).unwrap_or_default()
    }
}

#[derive(Debug, Default)]
struct RedStat {
    requests: u64,
    errors: u64,
    duration_nano_sum: i64,
}

/// Accumulates RED series across a flush window.
#[derive(Debug, Default)]
pub struct RedAggregator {
    series: HashMap<(String, String), RedStat>,
}

impl RedAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one completed request into its `(service, normalised endpoint)` series.
    pub fn observe(&mut self, service: &str, record: &L7Record) {
        let endpoint = normalize_endpoint(&record.operation);
        let stat = self
            .series
            .entry((service.to_string(), endpoint))
            .or_default();
        stat.requests += 1;
        if record.error {
            stat.errors += 1;
        }
        stat.duration_nano_sum += record.duration_nano;
    }

    /// Snapshot the current series (without clearing).
    pub fn snapshot(&self) -> Vec<RedEntry> {
        self.series
            .iter()
            .map(|((service, endpoint), stat)| RedEntry {
                service: service.clone(),
                endpoint: endpoint.clone(),
                requests: stat.requests,
                errors: stat.errors,
                duration_nano_sum: stat.duration_nano_sum,
            })
            .collect()
    }

    /// Snapshot and reset — call each flush tick.
    pub fn drain(&mut self) -> Vec<RedEntry> {
        let out = self.snapshot();
        self.series.clear();
        out
    }
}

/// Collapse variable path segments to `{}` to bound series cardinality. Strips
/// the query string; normalises each `/`-separated segment that is all-digits or
/// UUID/hex-like.
fn normalize_endpoint(operation: &str) -> String {
    let (method, rest) = operation.split_once(' ').unwrap_or(("", operation));
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    let normalized = path
        .split('/')
        .map(|seg| if is_variable_segment(seg) { "{}" } else { seg })
        .collect::<Vec<_>>()
        .join("/");
    if method.is_empty() {
        normalized
    } else {
        format!("{method} {normalized}")
    }
}

fn is_variable_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    if seg.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // UUID/long-hex ids: >= 16 hex digits once dashes are removed.
    let hex_len = seg.chars().filter(|c| *c != '-').count();
    hex_len >= 16 && seg.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::l7::Protocol;

    fn rec(operation: &str, status: u16, duration: i64) -> L7Record {
        L7Record {
            protocol: Protocol::Http1,
            attributes: Vec::new(),
            operation: operation.into(),
            status_code: status,
            error: status >= 500,
            start_unix_nano: 0,
            duration_nano: duration,
        }
    }

    #[test]
    fn numeric_ids_collapse_to_one_series() {
        let mut agg = RedAggregator::new();
        for id in 0..100 {
            agg.observe("svc", &rec(&format!("GET /users/{id}"), 200, 10));
        }
        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].endpoint, "GET /users/{}");
        assert_eq!(snap[0].requests, 100);
        assert_eq!(snap[0].errors, 0);
        assert_eq!(snap[0].duration_nano_sum, 1_000);
    }

    #[test]
    fn uuid_segments_collapse_and_query_is_stripped() {
        assert_eq!(
            normalize_endpoint("GET /orders/550e8400-e29b-41d4-a716-446655440000/items?page=2"),
            "GET /orders/{}/items"
        );
        // Short non-id segments are kept.
        assert_eq!(
            normalize_endpoint("POST /api/v1/login"),
            "POST /api/v1/login"
        );
    }

    #[test]
    fn errors_are_counted_per_series() {
        let mut agg = RedAggregator::new();
        agg.observe("svc", &rec("GET /x", 200, 5));
        agg.observe("svc", &rec("GET /x", 503, 7));
        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].requests, 2);
        assert_eq!(snap[0].errors, 1);
        assert_eq!(snap[0].duration_nano_sum, 12);
    }

    #[test]
    fn distinct_services_and_endpoints_are_separate_series() {
        let mut agg = RedAggregator::new();
        agg.observe("a", &rec("GET /x", 200, 1));
        agg.observe("b", &rec("GET /x", 200, 1));
        agg.observe("a", &rec("GET /y", 200, 1));
        assert_eq!(agg.snapshot().len(), 3);
    }

    #[test]
    fn drain_clears_the_window() {
        let mut agg = RedAggregator::new();
        agg.observe("svc", &rec("GET /x", 200, 1));
        assert_eq!(agg.drain().len(), 1);
        assert!(agg.snapshot().is_empty());
    }

    #[test]
    fn entry_encodes_to_json() {
        let e = RedEntry {
            service: "svc".into(),
            endpoint: "GET /x".into(),
            requests: 3,
            errors: 1,
            duration_nano_sum: 30,
        };
        let v: serde_json::Value = serde_json::from_slice(&e.to_json()).unwrap();
        assert_eq!(v["metric"], "ebpf_red");
        assert_eq!(v["service"], "svc");
        assert_eq!(v["endpoint"], "GET /x");
        assert_eq!(v["requests"], 3);
        assert_eq!(v["errors"], 1);
    }
}
