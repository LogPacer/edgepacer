//! Shared atomic counters for agent metrics — wired into shipper, orchestrator, sampler.
//!
//! All fields use relaxed ordering because exact consistency isn't needed —
//! stats are sampled periodically and slight lag is acceptable.

use std::collections::VecDeque;
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

/// Shared counters incremented by pipeline components, read by stats reporter.
pub struct AgentCounters {
    pub bytes_sent: AtomicU64,
    pub errors_total: AtomicU64,
    queue_depth: QueueDepthGauge,
    pub streams_active: AtomicU32,
    pub samples_pending: AtomicU32,
    pub samples_completed: AtomicU32,
    pub entries_overflowed: AtomicU64,
    error_window: ErrorWindow,
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
            error_window: ErrorWindow::new(),
        })
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

    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            queue_depth_bytes: self.queue_depth.get(),
            streams_active: self.streams_active.load(Ordering::Relaxed),
            samples_pending: self.samples_pending.load(Ordering::Relaxed),
            samples_completed: self.samples_completed.load(Ordering::Relaxed),
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
