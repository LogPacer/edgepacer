//! Service-map edges aggregated per `(src_service, peer, protocol)` over a flush
//! window. Each edge is a directed link `src_service → peer` labelled with
//! protocol + RED — the compact topology the account service map is drawn from,
//! never per-request rows (those stay in the per-target span repos).
//!
//! Latency percentiles come from a bounded reservoir of observed durations per
//! edge (cap `MAX_SAMPLES`), so memory is bounded even under a burst; the flush
//! `host` / window bounds are stamped by the caller when serialising, since the
//! aggregator itself is host- and clock-agnostic (pure + unit-tested).

use std::collections::HashMap;

use super::L7Record;

/// Cap on retained duration samples per edge per window. p50/p95 over a few
/// hundred samples is plenty for a topology view; a real burst just samples the
/// head of the window.
const MAX_SAMPLES: usize = 256;

/// One accumulated directed edge over a flush window.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeEntry {
    pub src_service: String,
    pub peer: String,
    pub protocol: String,
    pub count: u64,
    pub errors: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
}

impl EdgeEntry {
    /// Encode as a flat JSON edge for `WireGraphBatch`. `host` and the window
    /// bounds are stamped here by the caller so "which host observed this part
    /// of the shared map" is a filter, not a join.
    pub fn to_json(&self, host: &str, window_start_ms: i64, window_end_ms: i64) -> Vec<u8> {
        let v = serde_json::json!({
            "ebpf_kind": "service_map_edge",
            "src_service": self.src_service,
            "peer": self.peer,
            "protocol": self.protocol,
            "count": self.count,
            "errors": self.errors,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "window_start_ms": window_start_ms,
            "window_end_ms": window_end_ms,
            "host": host,
        });
        serde_json::to_vec(&v).unwrap_or_default()
    }
}

#[derive(Debug, Default)]
struct EdgeStat {
    count: u64,
    errors: u64,
    /// Durations (ns), capped at `MAX_SAMPLES`, for percentile estimation.
    durations_nano: Vec<i64>,
}

/// Accumulates directed service-map edges across a flush window.
#[derive(Debug, Default)]
pub struct EdgeAggregator {
    edges: HashMap<(String, String, String), EdgeStat>,
}

impl EdgeAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one completed request into its `(src_service, peer, protocol)` edge.
    /// A record with no resolved peer can't be an edge — it's dropped (the deep
    /// span still ships to the per-target repo).
    pub fn observe(&mut self, src_service: &str, peer: Option<&str>, record: &L7Record) {
        let Some(peer) = peer else {
            return;
        };
        let key = (
            src_service.to_string(),
            peer.to_string(),
            record.protocol.name().to_string(),
        );
        let stat = self.edges.entry(key).or_default();
        stat.count += 1;
        if record.error {
            stat.errors += 1;
        }
        if stat.durations_nano.len() < MAX_SAMPLES {
            stat.durations_nano.push(record.duration_nano.max(0));
        }
    }

    /// Snapshot and reset — call each flush tick.
    pub fn drain(&mut self) -> Vec<EdgeEntry> {
        let edges = std::mem::take(&mut self.edges);
        edges
            .into_iter()
            .map(|((src_service, peer, protocol), stat)| {
                let (p50, p95) = percentiles_ms(stat.durations_nano);
                EdgeEntry {
                    src_service,
                    peer,
                    protocol,
                    count: stat.count,
                    errors: stat.errors,
                    p50_ms: p50,
                    p95_ms: p95,
                }
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

/// Nearest-rank p50/p95 of the sample set, in milliseconds. Empty → (0, 0).
fn percentiles_ms(mut durations_nano: Vec<i64>) -> (f64, f64) {
    if durations_nano.is_empty() {
        return (0.0, 0.0);
    }
    durations_nano.sort_unstable();
    let at = |q: f64| -> f64 {
        let rank = (q * durations_nano.len() as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(durations_nano.len() - 1);
        durations_nano[idx] as f64 / 1_000_000.0
    };
    (at(0.50), at(0.95))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::l7::{L7Record, Protocol};

    fn record(duration_nano: i64, error: bool) -> L7Record {
        L7Record {
            protocol: Protocol::Http1,
            operation: "GET /x".to_string(),
            status_code: if error { 500 } else { 200 },
            error,
            start_unix_nano: 0,
            duration_nano,
            attributes: Vec::new(),
        }
    }

    #[test]
    fn drain_groups_by_service_peer_protocol_and_clears() {
        let mut agg = EdgeAggregator::new();
        agg.observe("web", Some("10.0.0.5:5432"), &record(1_000_000, false));
        agg.observe("web", Some("10.0.0.5:5432"), &record(3_000_000, true));
        agg.observe("web", Some("10.0.0.9:80"), &record(2_000_000, false));

        let mut edges = agg.drain();
        edges.sort_by(|a, b| a.peer.cmp(&b.peer));
        assert_eq!(edges.len(), 2);

        let db = &edges[0];
        assert_eq!(db.src_service, "web");
        assert_eq!(db.peer, "10.0.0.5:5432");
        assert_eq!(db.protocol, "http");
        assert_eq!(db.count, 2);
        assert_eq!(db.errors, 1);

        assert!(agg.is_empty(), "drain clears the window");
    }

    #[test]
    fn records_without_a_peer_are_not_edges() {
        let mut agg = EdgeAggregator::new();
        agg.observe("web", None, &record(1_000_000, false));
        assert!(agg.drain().is_empty());
    }

    #[test]
    fn percentiles_are_milliseconds() {
        let mut agg = EdgeAggregator::new();
        for ms in [1, 2, 3, 4, 100] {
            agg.observe("web", Some("peer:1"), &record(ms * 1_000_000, false));
        }
        let edge = agg.drain().pop().unwrap();
        assert_eq!(edge.count, 5);
        assert!((edge.p50_ms - 3.0).abs() < 0.001, "p50 = {}", edge.p50_ms);
        assert!((edge.p95_ms - 100.0).abs() < 0.001, "p95 = {}", edge.p95_ms);
    }
}
