//! Stream error collector — aggregates pipeline failures and reports to Rails.
//!
//! Mirrors legacy EdgePacer's `internal/config/error_collector.go`.
//! Deduplicates by `(section, stream_id)` and reports on a fixed interval.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tokio::sync::watch;
use tracing::{debug, warn};

/// Payload for `POST /api/v1/agents/errors`.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorReport {
    pub config_version: String,
    pub errors: Vec<StreamErrorEntry>,
}

/// A single stream failure in an error report.
#[derive(Debug, Clone, Serialize)]
pub struct StreamErrorEntry {
    pub section: String,
    pub stream_id: String,
    pub error: String,
    pub destination: String,
    pub since: String,
    pub count: i32,
}

struct StreamErrorState {
    section: String,
    stream_id: String,
    last_error: String,
    destination: String,
    since: Instant,
    count: i32,
}

/// Accumulates stream errors and periodically reports them to Rails.
pub struct ErrorCollector {
    inner: Mutex<Inner>,
    report_interval: Duration,
}

struct Inner {
    errors: HashMap<String, StreamErrorState>,
    config_version: String,
}

impl Default for ErrorCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorCollector {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                errors: HashMap::new(),
                config_version: String::new(),
            }),
            report_interval: Duration::from_secs(60),
        }
    }

    pub fn set_config_version(&self, version: &str) {
        let mut inner = self.inner();
        inner.config_version = version.to_string();
    }

    pub fn record_error(&self, section: &str, stream_id: &str, destination: &str, err_msg: &str) {
        let mut inner = self.inner();
        let key = format!("{section}:{stream_id}");
        if let Some(existing) = inner.errors.get_mut(&key) {
            existing.last_error = err_msg.to_string();
            existing.destination = destination.to_string();
            existing.count += 1;
        } else {
            inner.errors.insert(
                key,
                StreamErrorState {
                    section: section.to_string(),
                    stream_id: stream_id.to_string(),
                    last_error: err_msg.to_string(),
                    destination: destination.to_string(),
                    since: Instant::now(),
                    count: 1,
                },
            );
        }
    }

    pub fn clear_error(&self, section: &str, stream_id: &str) {
        let mut inner = self.inner();
        inner.errors.remove(&format!("{section}:{stream_id}"));
    }

    fn build_report(&self) -> Option<ErrorReport> {
        let inner = self.inner();
        if inner.errors.is_empty() {
            return None;
        }

        let errors = inner
            .errors
            .values()
            .map(|state| StreamErrorEntry {
                section: state.section.clone(),
                stream_id: state.stream_id.clone(),
                error: state.last_error.clone(),
                destination: state.destination.clone(),
                since: rfc3339_from_instant(state.since),
                count: state.count,
            })
            .collect();

        Some(ErrorReport {
            config_version: inner.config_version.clone(),
            errors,
        })
    }

    fn clear_after_success(&self) {
        let mut inner = self.inner();
        inner.errors.clear();
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("error collector lock poisoned; recovering buffered error state");
                self.inner.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    /// Run the periodic reporting loop until shutdown.
    pub async fn run(
        self: std::sync::Arc<Self>,
        client: std::sync::Arc<crate::sender::Client>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut tick = tokio::time::interval(self.report_interval);
        tick.tick().await;

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Some(report) = self.build_report() {
                        debug!(count = report.errors.len(), "reporting stream errors to Rails");
                        match client.report_errors(&report).await {
                            Ok(()) => self.clear_after_success(),
                            Err(e) => warn!(error = %e, "failed to report stream errors"),
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if let Some(report) = self.build_report() {
                        let _ = client.report_errors(&report).await;
                    }
                    return;
                }
            }
        }
    }
}

fn rfc3339_from_instant(instant: Instant) -> String {
    let elapsed = instant.elapsed();
    let now = SystemTime::now();
    let since = now.checked_sub(elapsed).unwrap_or(now);
    let datetime: chrono::DateTime<chrono::Utc> = since.into();
    datetime.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_deduplicate_errors() {
        let collector = ErrorCollector::new();
        collector.record_error("collect", "src-1", "https://relay", "first");
        collector.record_error("collect", "src-1", "https://relay", "second");

        let report = collector.build_report().unwrap();
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].error, "second");
        assert_eq!(report.errors[0].count, 2);
    }

    #[test]
    fn clear_error_removes_entry() {
        let collector = ErrorCollector::new();
        collector.record_error("collect", "src-1", "https://relay", "err");
        collector.clear_error("collect", "src-1");
        assert!(collector.build_report().is_none());
    }

    #[test]
    fn recovers_from_poisoned_lock() {
        let collector = ErrorCollector::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = collector.inner.lock().unwrap();
            panic!("poison error collector");
        }));

        collector.record_error("collect", "src-1", "https://relay", "err");

        let report = collector.build_report().unwrap();
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].stream_id, "src-1");
    }
}
