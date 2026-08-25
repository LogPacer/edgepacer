//! Shared atomic counters for agent metrics — wired into shipper, orchestrator, sampler.
//!
//! All fields use relaxed ordering because exact consistency isn't needed —
//! stats are sampled periodically and slight lag is acceptable.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::warn;

/// Rolling window of error timestamps for `errors_last_hour` stats.
pub struct ErrorWindow {
    timestamps: Mutex<VecDeque<Instant>>,
}

impl Default for ErrorWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorWindow {
    pub fn new() -> Self {
        Self {
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    fn timestamps(&self) -> MutexGuard<'_, VecDeque<Instant>> {
        match self.timestamps.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("error window lock poisoned; recovering timestamp state");
                self.timestamps.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    pub fn record(&self) {
        let mut ts = self.timestamps();
        ts.push_back(Instant::now());
    }

    pub fn count_last_hour(&self) -> u32 {
        let cutoff = Duration::from_secs(3600);
        let mut ts = self.timestamps();
        while ts.front().is_some_and(|t| t.elapsed() > cutoff) {
            ts.pop_front();
        }
        ts.len() as u32
    }
}

/// Shared gauge of bytes sitting in running pipelines' durable buffers,
/// maintained by the buffers themselves: open seeds it with the replayed
/// backlog, enqueue adds, confirmed-delivery deletes subtract, and dropping
/// a buffer (pipeline stopped) removes its remaining bytes — they re-enter
/// when a pipeline reopens the file. Cheap to clone; all handles share one
/// atomic, so no summation pass is ever needed.
#[derive(Clone, Default)]
pub struct QueueDepthGauge(Arc<AtomicU64>);

impl QueueDepthGauge {
    pub fn add(&self, bytes: u64) {
        self.0.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Saturating subtract — accounting bugs must never wrap the gauge to
    /// astronomically large values in the stats heartbeat.
    pub fn sub(&self, bytes: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(bytes))
            });
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// How a stream's shipped entries split across the wire body variants
/// (`EntryJson` / `RawText` / `RawBytes`). Also the per-batch tally the
/// shipper records once a batch settles.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct BodyVariantSplit {
    pub entry_json: u64,
    pub raw_text: u64,
    pub raw_bytes: u64,
}

/// Per-source counters of the body-variant split, incremented by that
/// source's shipper as batches settle and read by the stats reporter.
#[derive(Default)]
pub struct BodyVariantCounters {
    entry_json: AtomicU64,
    raw_text: AtomicU64,
    raw_bytes: AtomicU64,
}

impl BodyVariantCounters {
    pub fn record(&self, split: BodyVariantSplit) {
        self.entry_json
            .fetch_add(split.entry_json, Ordering::Relaxed);
        self.raw_text.fetch_add(split.raw_text, Ordering::Relaxed);
        self.raw_bytes.fetch_add(split.raw_bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> BodyVariantSplit {
        BodyVariantSplit {
            entry_json: self.entry_json.load(Ordering::Relaxed),
            raw_text: self.raw_text.load(Ordering::Relaxed),
            raw_bytes: self.raw_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PipelineLiveness {
    /// The source pipeline was constructed and spawned successfully.
    Running,
    /// The most recent attempt to construct the source pipeline failed.
    Failed { reason: String },
}

#[derive(Default)]
struct BodyVariantEntry {
    counters: Option<Arc<BodyVariantCounters>>,
    pipeline: Option<PipelineLiveness>,
}

/// Registry of per-source pipeline state and [`BodyVariantCounters`], keyed by
/// `log_source_id`. The orchestrator updates liveness as starts settle and
/// hands each source's shipper its counters; the stats reporter snapshots both
/// per stream each interval.
#[derive(Clone, Default)]
pub struct BodyVariantRegistry(Arc<Mutex<HashMap<String, BodyVariantEntry>>>);

impl BodyVariantRegistry {
    fn entries(&self) -> MutexGuard<'_, HashMap<String, BodyVariantEntry>> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("body variant registry lock poisoned; recovering state");
                self.0.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    /// The counters for a source, created on first sight.
    pub fn counters_for(&self, log_source_id: &str) -> Arc<BodyVariantCounters> {
        let mut entries = self.entries();
        entries
            .entry(log_source_id.to_string())
            .or_default()
            .counters
            .get_or_insert_with(Default::default)
            .clone()
    }

    /// The current split for a source, `None` when it has never shipped.
    pub fn snapshot_for(&self, log_source_id: &str) -> Option<BodyVariantSplit> {
        self.entries()
            .get(log_source_id)
            .and_then(|entry| entry.counters.as_ref())
            .map(|counters| counters.snapshot())
    }

    /// Record that a source pipeline started successfully.
    pub(crate) fn mark_pipeline_running(&self, log_source_id: &str) {
        self.entries()
            .entry(log_source_id.to_string())
            .or_default()
            .pipeline = Some(PipelineLiveness::Running);
    }

    /// Record the reason the most recent source pipeline start failed.
    pub(crate) fn mark_pipeline_failed(&self, log_source_id: &str, reason: &str) {
        self.entries()
            .entry(log_source_id.to_string())
            .or_default()
            .pipeline = Some(PipelineLiveness::Failed {
            reason: reason.to_string(),
        });
    }

    /// Snapshot one source's counters and liveness under the same registry lock.
    pub(crate) fn stream_snapshot_for(
        &self,
        log_source_id: &str,
    ) -> (Option<BodyVariantSplit>, Option<PipelineLiveness>) {
        let entries = self.entries();
        let Some(entry) = entries.get(log_source_id) else {
            return (None, None);
        };
        (
            entry.counters.as_ref().map(|counters| counters.snapshot()),
            entry.pipeline.clone(),
        )
    }

    pub(crate) fn retain_sources(&self, mut keep: impl FnMut(&str) -> bool) {
        self.entries().retain(|id, _| keep(id));
    }
}

/// Shared counters incremented by pipeline components, read by stats reporter.
pub struct AgentCounters {
    pub bytes_sent: AtomicU64,
    pub errors_total: AtomicU64,
    queue_depth: QueueDepthGauge,
    pub streams_active: AtomicU32,
    pub samples_pending: AtomicU32,
    pub samples_completed: AtomicU32,
    pub entries_overflowed: AtomicU64,
    pub spans_built: AtomicU64,
    pub spans_ship_failed: AtomicU64,
    pub spans_propagated: AtomicU64,
    pub spans_minted: AtomicU64,
    pub spans_parented: AtomicU64,
    pub spans_cross_linked: AtomicU64,
    pub spans_kind_from_bytes: AtomicU64,
    pub ebpf_capture_read_faults: AtomicU64,
    error_window: ErrorWindow,
    body_variants: BodyVariantRegistry,
}

impl AgentCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_sent: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            queue_depth: QueueDepthGauge::default(),
            streams_active: AtomicU32::new(0),
            samples_pending: AtomicU32::new(0),
            samples_completed: AtomicU32::new(0),
            entries_overflowed: AtomicU64::new(0),
            spans_built: AtomicU64::new(0),
            spans_ship_failed: AtomicU64::new(0),
            spans_propagated: AtomicU64::new(0),
            spans_minted: AtomicU64::new(0),
            spans_parented: AtomicU64::new(0),
            spans_cross_linked: AtomicU64::new(0),
            spans_kind_from_bytes: AtomicU64::new(0),
            ebpf_capture_read_faults: AtomicU64::new(0),
            error_window: ErrorWindow::new(),
            body_variants: BodyVariantRegistry::default(),
        })
    }

    /// The per-source body-variant registry shared between the orchestrator's
    /// shippers and the stats reporter.
    pub fn body_variants(&self) -> &BodyVariantRegistry {
        &self.body_variants
    }

    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
        self.error_window.record();
    }

    pub fn errors_last_hour(&self) -> u32 {
        self.error_window.count_last_hour()
    }

    /// Handle for a durable buffer to maintain the shared queue-depth gauge.
    pub fn queue_depth_gauge(&self) -> QueueDepthGauge {
        self.queue_depth.clone()
    }

    pub fn set_streams_active(&self, n: u32) {
        self.streams_active.store(n, Ordering::Relaxed);
    }

    pub fn increment_entries_overflowed(&self, n: u64) {
        self.entries_overflowed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn increment_samples_completed(&self) {
        self.samples_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_spans_built(&self, n: u64) {
        self.spans_built.fetch_add(n, Ordering::Relaxed);
    }

    pub fn increment_spans_ship_failed(&self) {
        self.spans_ship_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_spans_propagated(&self) {
        self.spans_propagated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_spans_minted(&self) {
        self.spans_minted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_spans_parented(&self, n: u64) {
        self.spans_parented.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_spans_cross_linked(&self, n: u64) {
        self.spans_cross_linked.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_spans_kind_from_bytes(&self, n: u64) {
        self.spans_kind_from_bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_ebpf_capture_read_faults(&self, n: u64) {
        self.ebpf_capture_read_faults
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            queue_depth_bytes: self.queue_depth.get(),
            streams_active: self.streams_active.load(Ordering::Relaxed),
            samples_pending: self.samples_pending.load(Ordering::Relaxed),
            samples_completed: self.samples_completed.load(Ordering::Relaxed),
            spans_built: self.spans_built.load(Ordering::Relaxed),
            spans_ship_failed: self.spans_ship_failed.load(Ordering::Relaxed),
            spans_propagated: self.spans_propagated.load(Ordering::Relaxed),
            spans_minted: self.spans_minted.load(Ordering::Relaxed),
            spans_parented: self.spans_parented.load(Ordering::Relaxed),
            spans_cross_linked: self.spans_cross_linked.load(Ordering::Relaxed),
            spans_kind_from_bytes: self.spans_kind_from_bytes.load(Ordering::Relaxed),
            ebpf_capture_read_faults: self.ebpf_capture_read_faults.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time read of all counters (non-atomic across fields, but close enough).
#[derive(Debug, Clone)]
pub struct CountersSnapshot {
    pub bytes_sent: u64,
    pub errors_total: u64,
    pub queue_depth_bytes: u64,
    pub streams_active: u32,
    pub samples_pending: u32,
    pub samples_completed: u32,
    pub spans_built: u64,
    pub spans_ship_failed: u64,
    pub spans_propagated: u64,
    pub spans_minted: u64,
    pub spans_parented: u64,
    pub spans_cross_linked: u64,
    pub spans_kind_from_bytes: u64,
    pub ebpf_capture_read_faults: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_window_counts_last_hour() {
        let counters = AgentCounters::new();
        counters.increment_errors();
        counters.increment_errors();
        assert_eq!(counters.errors_last_hour(), 2);
        assert_eq!(counters.snapshot().errors_total, 2);
    }

    #[test]
    fn counters_increment_and_snapshot() {
        let counters = AgentCounters::new();
        counters.add_bytes_sent(1000);
        counters.add_bytes_sent(500);
        counters.increment_errors();
        counters.set_streams_active(3);
        counters.increment_samples_completed();

        let snap = counters.snapshot();
        assert_eq!(snap.bytes_sent, 1500);
        assert_eq!(snap.errors_total, 1);
        assert_eq!(snap.streams_active, 3);
        assert_eq!(snap.samples_completed, 1);
        assert_eq!(snap.samples_pending, 0);
    }

    #[test]
    fn otlp_span_counters_increment_and_snapshot() {
        let counters = AgentCounters::new();
        counters.add_spans_built(3);
        counters.add_spans_built(2);
        counters.increment_spans_ship_failed();

        let snap = counters.snapshot();
        assert_eq!(snap.spans_built, 5);
        assert_eq!(snap.spans_ship_failed, 1);
    }

    #[test]
    fn span_id_origin_counters_increment_and_snapshot() {
        let counters = AgentCounters::new();
        counters.increment_spans_propagated();
        counters.increment_spans_minted();
        counters.increment_spans_minted();

        let snap = counters.snapshot();
        assert_eq!(snap.spans_propagated, 1);
        assert_eq!(snap.spans_minted, 2);
    }

    #[test]
    fn spans_parented_counter_increments_and_snapshots() {
        let counters = AgentCounters::new();
        counters.add_spans_parented(2);
        counters.add_spans_parented(1);

        assert_eq!(counters.snapshot().spans_parented, 3);
    }

    #[test]
    fn spans_cross_linked_counter_increments_and_snapshots() {
        let counters = AgentCounters::new();
        counters.add_spans_cross_linked(1);
        counters.add_spans_cross_linked(2);

        assert_eq!(counters.snapshot().spans_cross_linked, 3);
    }

    #[test]
    fn spans_kind_from_bytes_counter_increments_and_snapshots() {
        let counters = AgentCounters::new();
        counters.add_spans_kind_from_bytes(4);
        counters.add_spans_kind_from_bytes(2);

        assert_eq!(counters.snapshot().spans_kind_from_bytes, 6);
    }

    #[test]
    fn ebpf_capture_read_faults_counter_increments_and_snapshots() {
        let counters = AgentCounters::new();
        counters.add_ebpf_capture_read_faults(2);
        counters.add_ebpf_capture_read_faults(3);

        assert_eq!(counters.snapshot().ebpf_capture_read_faults, 5);
    }

    #[test]
    fn counters_shared_across_threads() {
        let counters = AgentCounters::new();
        let c1 = counters.clone();
        let c2 = counters.clone();

        let t1 = std::thread::spawn(move || {
            for _ in 0..1000 {
                c1.add_bytes_sent(1);
            }
        });
        let t2 = std::thread::spawn(move || {
            for _ in 0..1000 {
                c2.add_bytes_sent(1);
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(counters.snapshot().bytes_sent, 2000);
    }

    #[test]
    fn queue_depth_gauge_adds_subtracts_and_saturates() {
        let counters = AgentCounters::new();
        let gauge = counters.queue_depth_gauge();

        gauge.add(1000);
        gauge.sub(400);
        assert_eq!(gauge.get(), 600);
        assert_eq!(counters.snapshot().queue_depth_bytes, 600);

        // All clones share the same atomic.
        let other = counters.queue_depth_gauge();
        other.add(100);
        assert_eq!(gauge.get(), 700);

        // Saturating: an accounting bug must never wrap the heartbeat value.
        gauge.sub(10_000);
        assert_eq!(gauge.get(), 0);
    }

    #[test]
    fn body_variant_counters_accumulate_recorded_splits() {
        let counters = BodyVariantCounters::default();
        counters.record(BodyVariantSplit {
            entry_json: 2,
            raw_text: 1,
            raw_bytes: 0,
        });
        counters.record(BodyVariantSplit {
            entry_json: 1,
            raw_text: 0,
            raw_bytes: 3,
        });

        assert_eq!(
            counters.snapshot(),
            BodyVariantSplit {
                entry_json: 3,
                raw_text: 1,
                raw_bytes: 3,
            }
        );
    }

    /// The split is per-stream, not agent-wide: two sources' counters must
    /// never bleed into each other, and a source that never shipped has none.
    #[test]
    fn body_variant_registry_keeps_sources_apart() {
        let registry = BodyVariantRegistry::default();

        registry.counters_for("src-a").record(BodyVariantSplit {
            entry_json: 5,
            raw_text: 0,
            raw_bytes: 0,
        });
        registry.counters_for("src-b").record(BodyVariantSplit {
            entry_json: 0,
            raw_text: 7,
            raw_bytes: 0,
        });

        assert_eq!(registry.snapshot_for("src-a").unwrap().entry_json, 5);
        assert_eq!(registry.snapshot_for("src-a").unwrap().raw_text, 0);
        assert_eq!(registry.snapshot_for("src-b").unwrap().raw_text, 7);
        assert!(registry.snapshot_for("src-never-shipped").is_none());

        // Handing out the same source's counters twice shares one instance.
        let again = registry.counters_for("src-a");
        again.record(BodyVariantSplit {
            entry_json: 1,
            raw_text: 0,
            raw_bytes: 0,
        });
        assert_eq!(registry.snapshot_for("src-a").unwrap().entry_json, 6);

        assert!(registry.stream_snapshot_for("src-a").1.is_none());
        registry.mark_pipeline_running("src-a");
        assert_eq!(
            registry.stream_snapshot_for("src-a").1,
            Some(PipelineLiveness::Running)
        );
        registry.mark_pipeline_failed("src-a", "buffer unavailable");
        assert_eq!(
            registry.stream_snapshot_for("src-a").1,
            Some(PipelineLiveness::Failed {
                reason: "buffer unavailable".to_string()
            })
        );

        registry.retain_sources(|id| id != "src-a");
        assert!(registry.snapshot_for("src-a").is_none());
        assert!(registry.stream_snapshot_for("src-a").1.is_none());
    }

    #[test]
    fn error_window_recovers_from_poisoned_lock() {
        let window = ErrorWindow::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = window.timestamps.lock().unwrap();
            panic!("poison error window");
        }));

        window.record();

        assert_eq!(window.count_last_hour(), 1);
    }
}
