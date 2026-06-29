//! Trace proxy manager — lifecycle management for trace proxies based on config.
//!
//! Mirrors the orchestrator pattern: watches shared config for changes,
//! reconciles running proxies by log_source_id, restarts on config_hash change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info};

use crate::config::{self, SharedConfig, TraceProxyStreamConfig};
use crate::trace_proxy::{DEFAULT_TRACE_BUFFER_MAX_MB, TraceProxy, TraceProxyConfig};

/// A running proxy tracked by its config hash.
struct ManagedProxy {
    config_hash: String,
    proxy: TraceProxy,
}

/// Manages trace proxy lifecycle in response to config changes.
pub struct TraceProxyManager {
    proxies: HashMap<String, ManagedProxy>,
    data_dir: PathBuf,
    resource_id: String,
}

impl TraceProxyManager {
    pub fn new(data_dir: &Path, resource_id: String) -> Self {
        Self {
            proxies: HashMap::new(),
            data_dir: data_dir.to_path_buf(),
            resource_id,
        }
    }

    /// Reconcile running proxies against desired config.
    ///
    /// Keyed by `log_source_id`. Detects three cases:
    /// 1. New proxy (in config, not running) → start
    /// 2. Removed proxy (running, not in config) → stop
    /// 3. Changed proxy (config_hash differs) → restart
    pub async fn reconcile(&mut self, configs: &[TraceProxyStreamConfig]) {
        let desired: HashMap<&str, &TraceProxyStreamConfig> = configs
            .iter()
            .map(|c| (c.log_source_id.as_str(), c))
            .collect();

        // Phase 1: identify removed and changed proxies.
        let mut to_remove: Vec<String> = Vec::new();
        let mut to_restart: Vec<String> = Vec::new();

        for (id, managed) in &self.proxies {
            match desired.get(id.as_str()) {
                None => to_remove.push(id.clone()),
                Some(new_cfg) => {
                    if managed.config_hash != new_cfg.config_hash {
                        to_restart.push(id.clone());
                    }
                }
            }
        }

        // Phase 2: stop removed proxies.
        for id in &to_remove {
            info!(log_source_id = %id, "stopping removed trace proxy");
            self.stop_proxy(id).await;
        }

        // Phase 3: restart changed proxies (stop old first).
        for id in &to_restart {
            info!(log_source_id = %id, "restarting trace proxy (config changed)");
            self.stop_proxy(id).await;
        }

        // Phase 4: start new and restarted proxies.
        for cfg in configs {
            if !self.proxies.contains_key(&cfg.log_source_id) {
                self.start_proxy(cfg).await;
            }
        }
    }

    async fn start_proxy(&mut self, cfg: &TraceProxyStreamConfig) {
        let buffer_path = self.data_dir.join(format!(
            "trace-buffer-{}.sqlite",
            sanitize_id(&cfg.log_source_id)
        ));

        let proxy_config = TraceProxyConfig {
            listen_address: cfg.listen_address,
            grpc_listen_address: cfg.grpc_listen_address,
            subbox_endpoint: cfg.subbox_endpoint.clone(),
            archive_id: cfg.archive_id.clone(),
            repo_id: cfg.repo_id.clone(),
            resource_identifier: self.resource_id.clone(),
            require_service_name: cfg.require_service_name,
            allowed_service_names: cfg.allowed_service_names.clone(),
            buffer_path,
            buffer_max_mb: DEFAULT_TRACE_BUFFER_MAX_MB,
        };

        let mut proxy = TraceProxy::new(proxy_config);
        if let Err(e) = proxy.start().await {
            error!(
                log_source_id = %cfg.log_source_id,
                error = %e,
                "failed to start trace proxy"
            );
            return;
        }

        info!(
            log_source_id = %cfg.log_source_id,
            listen_address = %cfg.listen_address,
            "trace proxy started"
        );

        self.proxies.insert(
            cfg.log_source_id.clone(),
            ManagedProxy {
                config_hash: cfg.config_hash.clone(),
                proxy,
            },
        );
    }

    async fn stop_proxy(&mut self, id: &str) {
        let Some(mut managed) = self.proxies.remove(id) else {
            return;
        };
        managed.proxy.stop().await;
        info!(log_source_id = %id, "trace proxy stopped");
    }

    pub async fn shutdown_all(&mut self) {
        let ids: Vec<String> = self.proxies.keys().cloned().collect();
        info!(count = ids.len(), "shutting down all trace proxies");
        for id in &ids {
            self.stop_proxy(id).await;
        }
    }
}

/// Watch shared config and reconcile trace proxies on changes.
pub async fn run(
    shared_config: SharedConfig,
    data_dir: &Path,
    resource_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut manager = TraceProxyManager::new(data_dir, resource_id);
    let mut last_checksum = String::new();

    info!("trace proxy manager started, watching for config changes");

    let poll_interval = Duration::from_secs(2);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = shutdown.changed() => {
                info!("trace proxy manager shutting down");
                manager.shutdown_all().await;
                return;
            }
        }

        let configs = {
            let cfg = shared_config.read().await;
            match cfg.as_ref() {
                Some(unified) if unified.checksum != last_checksum => {
                    last_checksum = unified.checksum.clone();
                    config::all_trace_proxies(unified)
                }
                _ => continue,
            }
        };

        info!(
            proxies = configs.len(),
            "config changed, reconciling trace proxies"
        );
        manager.reconcile(&configs).await;
    }
}

fn sanitize_id(id: &str) -> String {
    id.replace(['/', '\\', ':', '.', ' '], "_")
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_trace_proxy_ids() {
        assert_eq!(
            sanitize_id("traces-proxy-agent-123"),
            "traces-proxy-agent-123"
        );
        assert_eq!(sanitize_id("src/path.log"), "src_path_log");
    }

    #[tokio::test]
    async fn reconcile_starts_and_stops_proxies() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = TraceProxyManager::new(dir.path(), "host-test".into());

        // Empty reconcile — no proxies.
        manager.reconcile(&[]).await;
        assert!(manager.proxies.is_empty());

        // Shutdown empty — safe.
        manager.shutdown_all().await;
        assert!(manager.proxies.is_empty());
    }
}
