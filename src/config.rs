//! Configuration management for EdgePacer.
//!
//! Handles CLI arguments, environment variables, and dynamic config from Rails.
//! Mirrors legacy EdgePacer's `internal/config/` package.

use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

mod app;
mod buffer;
mod cadence;
mod ebpf;
mod fields;
mod logs;
mod metrics;
mod services;
mod streaming;
mod telemetry;
mod trace_proxy;

pub use app::{AppConfig, Cli};
pub use buffer::BufferTuning;
pub use cadence::{effective_poll_interval, effective_stats_interval, stats_reporting_enabled};
pub use ebpf::{EbpfSectionConfig, EbpfTargetConfig, ServiceMapDestination, ebpf_section};
pub use logs::{
    CollectDiagnostic, CollectStreamConfig, FileSourceFormat, LogStreamConfig, MultilineConfig,
    ResolvedCollectStreams, all_collect_streams, resolve_collect_streams,
    resolved_collect_from_config,
};
pub use metrics::{MetricsStreamConfig, all_metrics_streams};
pub use services::{
    CheckpointAdoption, ServiceDescription, all_service_descriptions, selector_matches,
};
pub use streaming::{StreamAccessMethod, StreamingSourceConfig};
pub use telemetry::{TelemetryConfig, TelemetryContext, telemetry_config};
pub use trace_proxy::{TraceProxyStreamConfig, all_trace_proxies};

/// Dynamic config from Rails with per-section change detection via SHA256 checksums.
/// Thread-safe via Arc<RwLock<>>.
#[derive(Debug, Clone)]
pub struct UnifiedConfig {
    pub raw: serde_json::Value,
    pub checksum: String,
    pub etag: String,
}

impl UnifiedConfig {
    /// Create from raw JSON response
    pub fn new(raw: serde_json::Value, etag: String) -> Self {
        let checksum = compute_checksum(&raw);
        Self {
            raw,
            checksum,
            etag,
        }
    }

    /// Check if config has changed by comparing checksums
    #[must_use]
    pub fn has_changed(&self, other: &Self) -> bool {
        self.checksum != other.checksum
    }

    /// Extract a section's JSON value
    pub fn section(&self, name: &str) -> Option<&serde_json::Value> {
        self.raw.get(name)
    }

    /// The agent's logpacer-pinned identity (`server.name`): a **top-level**
    /// `resource_identifier`. Agent-scoped, not per-collectable — every wire path
    /// stamps this one value, gated per source by `stamp_resource_identifier`.
    ///
    /// logpacer MUST fold the identity into the top-level unified_config etag.
    /// That etag hashes the section sub-etags, so a top-level field that is not
    /// itself an etag input 304s on every poll after the first and never reaches a
    /// running agent — a rename would silently fail to propagate. `None` when
    /// absent or pre-rollout → the agent falls back per
    /// [`crate::identity::AgentIdentity::seed`].
    pub fn resource_identifier(&self) -> Option<&str> {
        self.raw
            .get("resource_identifier")?
            .as_str()
            .filter(|value| !value.is_empty())
    }
}

/// Compute SHA256 checksum of a JSON value (for change detection)
pub fn compute_checksum(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// Shared config state — thread-safe, hot-reloadable
pub type SharedConfig = Arc<RwLock<Option<UnifiedConfig>>>;

/// Create a new shared config container
pub fn shared_config() -> SharedConfig {
    Arc::new(RwLock::new(None))
}

/// Config poller — periodically fetches config from Rails and detects changes
pub async fn poll_config(
    client: &crate::sender::Client,
    shared: SharedConfig,
    fallback_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut etag: Option<String> = None;
    let fallback = tokio::time::Duration::from_secs(fallback_secs);

    loop {
        let interval = cadence::effective_poll_interval(&shared, fallback).await;

        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = shutdown.changed() => {
                info!("config poller shutting down");
                return;
            }
        }

        match client.fetch_unified_config(etag.as_deref()).await {
            Ok(Some((new_etag, raw_config))) => {
                let new_config = UnifiedConfig::new(raw_config, new_etag.clone());

                let changed = {
                    let current = shared.read().await;
                    current
                        .as_ref()
                        .map(|c| c.has_changed(&new_config))
                        .unwrap_or(true)
                };

                if changed {
                    info!(checksum = %new_config.checksum, "config changed, applying");
                    *shared.write().await = Some(new_config);
                } else {
                    debug!("config unchanged (same checksum)");
                }

                etag = Some(new_etag);
            }
            Ok(None) => {
                debug!("config unchanged (304)");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch config");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resource_identifier_reads_top_level_key() {
        let cfg = UnifiedConfig::new(json!({ "resource_identifier": "mhl.local" }), "etag".into());
        assert_eq!(cfg.resource_identifier(), Some("mhl.local"));
    }

    #[test]
    fn resource_identifier_absent_falls_through() {
        // Absent or empty → None; the agent falls back to persisted/-r/hostname
        // rather than stamping empty.
        assert_eq!(
            UnifiedConfig::new(json!({}), "e".into()).resource_identifier(),
            None
        );
        assert_eq!(
            UnifiedConfig::new(json!({ "resource_identifier": "" }), "e".into())
                .resource_identifier(),
            None
        );
    }
}
