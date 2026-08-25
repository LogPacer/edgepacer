//! Trace proxy manager — lifecycle management for trace proxies based on config.
//!
//! Mirrors the orchestrator pattern: watches shared config for changes,
//! reconciles running proxies by log_source_id, restarts on config_hash change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info};

use crate::config::{self, SharedConfig, TraceProxyStreamConfig};
use crate::counters::AgentCounters;
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
    counters: Option<Arc<AgentCounters>>,
}

impl TraceProxyManager {
    pub fn new(data_dir: &Path, resource_id: String) -> Self {
        Self {
            proxies: HashMap::new(),
            data_dir: data_dir.to_path_buf(),
            resource_id,
            counters: None,
        }
    }

    pub fn with_counters(mut self, counters: Arc<AgentCounters>) -> Self {
        self.counters = Some(counters);
        self
    }

    /// Reconcile running proxies against desired config.
    ///
    /// Keyed by `log_source_id`. Detects three cases:
    /// 1. New proxy (in config, not running) → start
    /// 2. Removed proxy (running, not in config) → stop
    /// 3. Changed proxy (config_hash differs) → restart
    pub async fn reconcile(&mut self, configs: &[TraceProxyStreamConfig]) -> bool {
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

        // Phase 2: remove every affected proxy from manager state, then stop
        // them concurrently before starting replacements.
        for id in &to_remove {
            info!(log_source_id = %id, "stopping removed trace proxy");
        }
        for id in &to_restart {
            info!(log_source_id = %id, "restarting trace proxy (config changed)");
        }
        let stops = to_remove.iter().chain(&to_restart).filter_map(|id| {
            self.proxies
                .remove(id)
                .map(|managed| Self::stop_managed(id.clone(), managed))
        });
        futures_util::future::join_all(stops).await;

        // Phase 3: start new and restarted proxies.
        for cfg in configs {
            if !self.proxies.contains_key(&cfg.log_source_id) {
                self.start_proxy(cfg).await;
            }
        }

        self.is_converged(configs)
    }

    fn is_converged(&self, configs: &[TraceProxyStreamConfig]) -> bool {
        self.proxies.len() == configs.len()
            && configs.iter().all(|cfg| {
                self.proxies
                    .get(&cfg.log_source_id)
                    .is_some_and(|managed| managed.config_hash == cfg.config_hash)
            })
    }

    fn build_proxy(&self, cfg: &TraceProxyStreamConfig) -> TraceProxy {
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

        let proxy = TraceProxy::new(proxy_config);
        match &self.counters {
            Some(counters) => proxy.with_counters(counters.clone()),
            None => proxy,
        }
    }

    async fn start_proxy(&mut self, cfg: &TraceProxyStreamConfig) {
        let mut proxy = self.build_proxy(cfg);
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

    async fn stop_managed(id: String, mut managed: ManagedProxy) {
        managed.proxy.stop().await;
        info!(log_source_id = %id, "trace proxy stopped");
    }

    /// Stop every proxy concurrently. Each proxy owns a shared end-to-end
    /// deadline and aborts and reaps any child task that exceeds it.
    pub async fn shutdown_all(&mut self) {
        info!(
            count = self.proxies.len(),
            "shutting down all trace proxies"
        );
        let stops = self
            .proxies
            .drain()
            .map(|(id, managed)| Self::stop_managed(id, managed));
        futures_util::future::join_all(stops).await;
    }
}

/// Watch shared config and reconcile trace proxies on changes.
pub async fn run(
    shared_config: SharedConfig,
    data_dir: &Path,
    resource_id: String,
    shutdown: watch::Receiver<bool>,
) {
    run_with_counters(
        shared_config,
        data_dir,
        resource_id,
        AgentCounters::new(),
        shutdown,
    )
    .await;
}

pub async fn run_with_counters(
    shared_config: SharedConfig,
    data_dir: &Path,
    resource_id: String,
    counters: Arc<AgentCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut manager = TraceProxyManager::new(data_dir, resource_id).with_counters(counters);
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

        let (checksum, configs) = {
            let cfg = shared_config.read().await;
            let Some(unified) = cfg.as_ref() else {
                continue;
            };
            (unified.checksum.clone(), config::all_trace_proxies(unified))
        };

        if checksum == last_checksum && manager.is_converged(&configs) {
            continue;
        }

        info!(proxies = configs.len(), "reconciling trace proxies");
        if manager.reconcile(&configs).await {
            last_checksum = checksum;
        }
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
    use serde_json::json;

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

    #[test]
    fn manager_builds_counted_trace_transports() {
        let dir = tempfile::tempdir().unwrap();
        let counters = AgentCounters::new();
        let manager =
            TraceProxyManager::new(dir.path(), "host-test".into()).with_counters(counters.clone());
        let config = TraceProxyStreamConfig {
            log_source_id: "trace-source".into(),
            listen_address: "127.0.0.1:0".parse().unwrap(),
            grpc_listen_address: Some("127.0.0.1:0".parse().unwrap()),
            subbox_endpoint: "http://relay/wire".into(),
            archive_id: "arc".into(),
            repo_id: "repo".into(),
            require_service_name: false,
            allowed_service_names: Default::default(),
            config_hash: "hash".into(),
        };

        assert!(manager.build_proxy(&config).uses_counters(&counters));
    }

    #[tokio::test]
    async fn unchanged_config_retries_a_failed_proxy_start() {
        let held_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = held_listener.local_addr().unwrap();
        let shared_config = config::shared_config();
        *shared_config.write().await = Some(config::UnifiedConfig::new(
            json!({
                "traces": {
                    "retry-source": {
                        "listen_address": listen_address.to_string(),
                        "subbox_endpoint": "http://127.0.0.1:9/v1/logpacer-wire",
                        "archive_id": "arc",
                        "repo_id": "repo",
                        "require_service_name": false
                    }
                }
            }),
            "unchanged".into(),
        ));

        let dir = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let manager = tokio::spawn({
            let shared_config = shared_config.clone();
            let data_dir = dir.path().to_path_buf();
            async move {
                run_with_counters(
                    shared_config,
                    &data_dir,
                    "host-test".into(),
                    AgentCounters::new(),
                    shutdown_rx,
                )
                .await;
            }
        });

        tokio::time::sleep(Duration::from_millis(2_100)).await;
        drop(held_listener);

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(listen_address).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the unchanged desired proxy must retry after its port becomes free");

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), manager)
            .await
            .expect("trace proxy manager should stop")
            .unwrap();
    }

    #[tokio::test]
    async fn rollback_reconciles_when_the_previous_checksum_is_no_longer_running() {
        let reserve_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address_a = reserve_a.local_addr().unwrap();
        drop(reserve_a);
        let held_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address_b = held_b.local_addr().unwrap();
        let unified = |address: std::net::SocketAddr, checksum: &str| {
            config::UnifiedConfig::new(
                json!({
                    "traces": {
                        "rollback-source": {
                            "listen_address": address.to_string(),
                            "subbox_endpoint": "http://127.0.0.1:9/v1/logpacer-wire",
                            "archive_id": "arc",
                            "repo_id": "repo",
                            "require_service_name": false
                        }
                    }
                }),
                checksum.into(),
            )
        };

        let shared_config = config::shared_config();
        *shared_config.write().await = Some(unified(address_a, "a"));
        let dir = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let manager = tokio::spawn({
            let shared_config = shared_config.clone();
            let data_dir = dir.path().to_path_buf();
            async move {
                run_with_counters(
                    shared_config,
                    &data_dir,
                    "host-test".into(),
                    AgentCounters::new(),
                    shutdown_rx,
                )
                .await;
            }
        });

        wait_for_listener(address_a).await;
        *shared_config.write().await = Some(unified(address_b, "b"));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(address_a).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("failed replacement should first stop the previous listener");

        *shared_config.write().await = Some(unified(address_a, "a"));
        wait_for_listener(address_a).await;

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), manager)
            .await
            .expect("trace proxy manager should stop")
            .unwrap();
        drop(held_b);
    }

    async fn wait_for_listener(address: std::net::SocketAddr) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("trace proxy listener should bind");
    }
}
