use edgepacer::{
    agent, auth_session, common, config, counters, discovery, ebpf, error_collector, identity,
    metrics_shipper, orchestrator, sampler, self_telemetry, sender, stats, trace_proxy_manager,
    upload_token_store,
};

use config::AppConfig;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const STANDARD_SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);
const ORCHESTRATOR_SHUTDOWN_BUDGET: Duration = Duration::from_secs(25);

pub(crate) async fn run(app_config: AppConfig) -> anyhow::Result<()> {
    let (telemetry_layer, telemetry_rx) = initialize_telemetry(&app_config);

    if app_config.local_mode {
        return run_local_mode(app_config).await;
    }

    run_agent(app_config, telemetry_layer, telemetry_rx).await
}

fn initialize_telemetry(
    app_config: &AppConfig,
) -> (self_telemetry::TelemetryLayer, mpsc::Receiver<Vec<u8>>) {
    let (telemetry_tx, telemetry_rx) = mpsc::channel(self_telemetry::TELEMETRY_CHANNEL_CAPACITY);
    let telemetry_layer = self_telemetry::TelemetryLayer::new(telemetry_tx);
    self_telemetry::init_tracing(&app_config.log_level, telemetry_layer.clone());

    (telemetry_layer, telemetry_rx)
}

async fn run_agent(
    app_config: AppConfig,
    telemetry_layer: self_telemetry::TelemetryLayer,
    telemetry_rx: mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    info!(
        version = common::VERSION,
        resource_id = %app_config.resource_id,
        rails_url = %app_config.rails_url,
        "edgepacer starting"
    );

    let mut client = sender::Client::new(&app_config)?;
    let auth_resp = auth_session::authenticate(&mut client, &app_config).await?;
    let token_expires_in = auth_resp.expires_in;

    info!(
        "authenticated with Rails, token expires in {}s",
        token_expires_in
    );

    let shared_config = config::shared_config();
    let discovery_cache = discovery::shared_discovery_cache();
    load_initial_config(&client, shared_config.clone()).await?;

    let identity = seed_identity(&shared_config, &app_config).await;
    write_readiness_file(app_config.readiness_file.as_deref());

    let shutdown = SharedShutdown::new();
    let counters = counters::AgentCounters::new();

    let ebpf_status = ebpf::shared_status();
    ebpf::probe(&ebpf_status).await;

    let shared_token = client.shared_token();
    let agent_client = sender::Client::with_shared_token(&app_config, shared_token.clone())?;
    let stats_client = sender::Client::with_shared_token(&app_config, shared_token.clone())?;
    let data_dir = prepare_runtime_data_dir()?;

    let error_collector = Arc::new(error_collector::ErrorCollector::new());
    if let Some(checksum) = shared_config
        .read()
        .await
        .as_ref()
        .map(|c| c.checksum.clone())
    {
        error_collector.set_config_version(&checksum);
    }

    let tasks = AgentTasks::spawn(AgentTaskConfig {
        app_config: &app_config,
        client,
        agent_client,
        stats_client,
        shared_token,
        token_expires_in,
        shared_config,
        discovery_cache,
        counters,
        ebpf_status,
        identity,
        error_collector,
        telemetry_layer,
        telemetry_rx,
        data_dir,
        shutdown: &shutdown,
    })?;

    info!("edgepacer running, press Ctrl+C to stop");
    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");

    shutdown.signal();
    tasks.wait(ShutdownBudgets::agent()).await;

    info!("edgepacer stopped");
    Ok(())
}

async fn load_initial_config(
    client: &sender::Client,
    shared_config: config::SharedConfig,
) -> anyhow::Result<()> {
    match client.fetch_unified_config(None).await? {
        Some((etag, raw)) => {
            let unified = config::UnifiedConfig::new(raw, etag);
            info!(checksum = %unified.checksum, "initial config loaded");
            *shared_config.write().await = Some(unified);
            Ok(())
        }
        None => {
            error!("no config returned on initial fetch");
            anyhow::bail!("failed to fetch initial config");
        }
    }
}

async fn seed_identity(
    shared_config: &config::SharedConfig,
    app_config: &AppConfig,
) -> identity::AgentIdentity {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let cfg = shared_config.read().await;
    let from_config = cfg
        .as_ref()
        .and_then(config::UnifiedConfig::resource_identifier);

    identity::AgentIdentity::seed(from_config, &app_config.resource_id, &hostname)
}

fn write_readiness_file(path: Option<&str>) {
    if let Some(path) = path
        && let Err(e) = std::fs::write(path, "")
    {
        warn!(path, error = %e, "failed to write readiness file");
    }
}

struct AgentTaskConfig<'a> {
    app_config: &'a AppConfig,
    client: sender::Client,
    agent_client: sender::Client,
    stats_client: sender::Client,
    shared_token: Arc<RwLock<String>>,
    token_expires_in: i64,
    shared_config: config::SharedConfig,
    discovery_cache: discovery::SharedDiscoveryCache,
    counters: Arc<counters::AgentCounters>,
    ebpf_status: ebpf::SharedEbpfStatus,
    identity: identity::AgentIdentity,
    error_collector: Arc<error_collector::ErrorCollector>,
    telemetry_layer: self_telemetry::TelemetryLayer,
    telemetry_rx: mpsc::Receiver<Vec<u8>>,
    data_dir: PathBuf,
    shutdown: &'a SharedShutdown,
}

struct AgentTasks {
    poller: JoinHandle<()>,
    agent: JoinHandle<()>,
    orchestrator: JoinHandle<()>,
    stats: JoinHandle<()>,
    metrics: JoinHandle<()>,
    errors: JoinHandle<()>,
    telemetry: JoinHandle<()>,
    trace: JoinHandle<()>,
    sampler: JoinHandle<()>,
    refresh: JoinHandle<()>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    ebpf: JoinHandle<()>,
}

impl AgentTasks {
    fn spawn(config: AgentTaskConfig<'_>) -> anyhow::Result<Self> {
        let AgentTaskConfig {
            app_config,
            client,
            agent_client,
            stats_client,
            shared_token,
            token_expires_in,
            shared_config,
            discovery_cache,
            counters,
            ebpf_status,
            identity,
            error_collector,
            telemetry_layer,
            telemetry_rx,
            data_dir,
            shutdown,
        } = config;

        let poller = spawn_config_poller(
            client,
            shared_config.clone(),
            app_config.poll_interval_secs,
            shutdown.subscribe(),
        );
        let agent = spawn_discovery_agent(
            agent_client,
            shared_config.clone(),
            discovery_cache.clone(),
            Duration::from_secs(app_config.poll_interval_secs),
            shutdown.subscribe(),
        );

        let orchestrator_data_dir = data_dir.clone();
        let metrics_data_dir = data_dir.clone();
        let telemetry_data_dir = data_dir.clone();
        let trace_data_dir = data_dir.clone();

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let ebpf_data_dir = data_dir;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let ebpf_identity = identity.clone();

        let orchestrator = spawn_orchestrator(
            shared_config.clone(),
            discovery_cache.clone(),
            orchestrator_data_dir,
            identity.clone(),
            counters.clone(),
            error_collector.clone(),
            shutdown.subscribe(),
        );
        let stats = spawn_stats(
            stats_client,
            identity.current(),
            shared_config.clone(),
            discovery_cache.clone(),
            ebpf_status.clone(),
            shutdown.subscribe(),
        );
        let metrics = spawn_metrics_pipeline(
            shared_config.clone(),
            identity.clone(),
            metrics_data_dir,
            counters.clone(),
            shutdown.subscribe(),
        );
        let errors = spawn_error_collector(
            Arc::new(sender::Client::with_shared_token(
                app_config,
                shared_token.clone(),
            )?),
            error_collector,
            shutdown.subscribe(),
        );
        let telemetry = spawn_self_telemetry(
            shared_config.clone(),
            telemetry_data_dir,
            identity.clone(),
            telemetry_layer,
            telemetry_rx,
            counters,
            shutdown.subscribe(),
        );
        let trace = spawn_trace_proxy_manager(
            shared_config.clone(),
            trace_data_dir,
            identity.current(),
            shutdown.subscribe(),
        );

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let ebpf = spawn_ebpf_manager(
            shared_config.clone(),
            discovery_cache.clone(),
            ebpf_status,
            ebpf_data_dir,
            ebpf_identity,
            shutdown.subscribe(),
        );

        let sampler_client = sender::Client::with_shared_token(app_config, shared_token.clone())?;
        let sampler = spawn_sampler(
            sampler_client,
            discovery_cache,
            shared_config.clone(),
            sampler::DEFAULT_POLL_INTERVAL,
            shutdown.subscribe(),
        );

        let upload_token_client =
            sender::Client::with_shared_token(app_config, shared_token.clone())?;
        upload_token_store::spawn_refresh(upload_token_client);

        let refresh_client = sender::Client::with_shared_token(app_config, shared_token)?;
        let refresh = spawn_token_refresh(refresh_client, token_expires_in, shutdown.subscribe());

        Ok(Self {
            poller,
            agent,
            orchestrator,
            stats,
            metrics,
            errors,
            telemetry,
            trace,
            sampler,
            refresh,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            ebpf,
        })
    }

    async fn wait(self, budgets: ShutdownBudgets) {
        let Self {
            poller,
            agent,
            orchestrator,
            stats,
            metrics,
            errors,
            telemetry,
            trace,
            sampler,
            refresh,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            ebpf,
        } = self;

        let common_tasks = async {
            tokio::join!(
                wait_task(orchestrator, budgets.orchestrator),
                wait_task(poller, budgets.standard),
                wait_task(agent, budgets.standard),
                wait_task(stats, budgets.standard),
                wait_task(metrics, budgets.standard),
                wait_task(errors, budgets.standard),
                wait_task(telemetry, budgets.standard),
                wait_task(trace, budgets.standard),
                wait_task(sampler, budgets.standard),
                wait_task(refresh, budgets.standard),
            );
        };

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            tokio::join!(common_tasks, wait_task(ebpf, budgets.standard));
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        common_tasks.await;
    }
}

fn spawn_config_poller(
    client: sender::Client,
    shared_config: config::SharedConfig,
    fallback_poll_secs: u64,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        config::poll_config(&client, shared_config, fallback_poll_secs, shutdown).await;
    })
}

fn spawn_discovery_agent(
    client: sender::Client,
    shared_config: config::SharedConfig,
    discovery_cache: discovery::SharedDiscoveryCache,
    fallback_poll_interval: Duration,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        agent::run(
            &client,
            shared_config,
            discovery_cache,
            fallback_poll_interval,
            shutdown,
        )
        .await;
    })
}

fn spawn_orchestrator(
    shared_config: config::SharedConfig,
    discovery_cache: discovery::SharedDiscoveryCache,
    data_dir: PathBuf,
    identity: identity::AgentIdentity,
    counters: Arc<counters::AgentCounters>,
    error_collector: Arc<error_collector::ErrorCollector>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        orchestrator::run(
            shared_config,
            discovery_cache,
            &data_dir,
            identity,
            counters,
            error_collector,
            shutdown,
        )
        .await;
    })
}

fn spawn_stats(
    client: sender::Client,
    resource_id: String,
    shared_config: config::SharedConfig,
    discovery_cache: discovery::SharedDiscoveryCache,
    ebpf_status: ebpf::SharedEbpfStatus,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        stats::run(
            &client,
            &resource_id,
            shared_config,
            discovery_cache,
            ebpf_status,
            shutdown,
        )
        .await;
    })
}

fn spawn_metrics_pipeline(
    shared_config: config::SharedConfig,
    identity: identity::AgentIdentity,
    data_dir: PathBuf,
    counters: Arc<counters::AgentCounters>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        metrics_shipper::run(shared_config, identity, &data_dir, counters, shutdown).await;
    })
}

fn spawn_error_collector(
    client: Arc<sender::Client>,
    error_collector: Arc<error_collector::ErrorCollector>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        error_collector.run(client, shutdown).await;
    })
}

fn spawn_self_telemetry(
    shared_config: config::SharedConfig,
    data_dir: PathBuf,
    identity: identity::AgentIdentity,
    telemetry_layer: self_telemetry::TelemetryLayer,
    telemetry_rx: mpsc::Receiver<Vec<u8>>,
    counters: Arc<counters::AgentCounters>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        self_telemetry::run(
            shared_config,
            &data_dir,
            identity,
            telemetry_layer,
            telemetry_rx,
            counters,
            shutdown,
        )
        .await;
    })
}

fn spawn_trace_proxy_manager(
    shared_config: config::SharedConfig,
    data_dir: PathBuf,
    resource_id: String,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        trace_proxy_manager::run(shared_config, &data_dir, resource_id, shutdown).await;
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn spawn_ebpf_manager(
    shared_config: config::SharedConfig,
    discovery_cache: discovery::SharedDiscoveryCache,
    ebpf_status: ebpf::SharedEbpfStatus,
    data_dir: PathBuf,
    identity: identity::AgentIdentity,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        ebpf::run(
            shared_config,
            discovery_cache,
            ebpf_status,
            &data_dir,
            &identity,
            shutdown,
        )
        .await;
    })
}

fn spawn_sampler(
    client: sender::Client,
    discovery_cache: discovery::SharedDiscoveryCache,
    shared_config: config::SharedConfig,
    fallback_poll_interval: Duration,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        sampler::run(
            &client,
            discovery_cache,
            shared_config,
            fallback_poll_interval,
            shutdown,
        )
        .await;
    })
}

fn spawn_token_refresh(
    client: sender::Client,
    token_expires_in: i64,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        auth_session::run_token_refresh_loop(client, token_expires_in, shutdown).await;
    })
}

async fn run_local_mode(app_config: AppConfig) -> anyhow::Result<()> {
    let directive_file = app_config
        .directive_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--directive-file is required when --local-mode is set"))?;

    info!(
        version = common::VERSION,
        directive = %directive_file.display(),
        "edgepacer starting in local mode"
    );

    let raw_json = std::fs::read_to_string(directive_file)
        .map_err(|e| anyhow::anyhow!("failed to read directive file: {e}"))?;
    let raw: serde_json::Value = serde_json::from_str(&raw_json)
        .map_err(|e| anyhow::anyhow!("failed to parse directive file: {e}"))?;

    let shared_config = config::shared_config();
    let discovery_cache = discovery::shared_discovery_cache();
    let unified = config::UnifiedConfig::new(raw, "local".to_string());
    info!(checksum = %unified.checksum, "local config loaded");

    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let identity = identity::AgentIdentity::seed(
        unified.resource_identifier(),
        &app_config.resource_id,
        &hostname,
    );
    *shared_config.write().await = Some(unified);

    let shutdown = SharedShutdown::new();
    let data_dir = prepare_runtime_data_dir()?;
    let orchestrator = spawn_orchestrator(
        shared_config,
        discovery_cache,
        data_dir,
        identity,
        counters::AgentCounters::new(),
        Arc::new(error_collector::ErrorCollector::new()),
        shutdown.subscribe(),
    );

    info!("edgepacer local mode running, press Ctrl+C to stop");
    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");

    shutdown.signal();
    wait_task(orchestrator, ShutdownBudgets::local().orchestrator).await;

    info!("edgepacer stopped");
    Ok(())
}

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[derive(Clone)]
struct SharedShutdown {
    tx: watch::Sender<bool>,
}

impl SharedShutdown {
    fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    fn signal(&self) {
        let _ = self.tx.send(true);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShutdownBudgets {
    orchestrator: Duration,
    standard: Duration,
}

impl ShutdownBudgets {
    const fn agent() -> Self {
        Self {
            orchestrator: ORCHESTRATOR_SHUTDOWN_BUDGET,
            standard: STANDARD_SHUTDOWN_BUDGET,
        }
    }

    const fn local() -> Self {
        Self {
            orchestrator: ORCHESTRATOR_SHUTDOWN_BUDGET,
            standard: STANDARD_SHUTDOWN_BUDGET,
        }
    }
}

async fn wait_task(handle: JoinHandle<()>, budget: Duration) {
    let _ = tokio::time::timeout(budget, handle).await;
}

fn prepare_runtime_data_dir() -> anyhow::Result<PathBuf> {
    let data_dir = edgepacer_data_dir_from(dirs::cache_dir());
    prepare_data_dir(&data_dir)?;
    Ok(data_dir)
}

fn edgepacer_data_dir_from(cache_root: Option<PathBuf>) -> PathBuf {
    cache_root
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("edgepacer")
}

fn prepare_data_dir(data_dir: &Path) -> anyhow::Result<()> {
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        error!(error = %e, "failed to create data directory");
        anyhow::bail!("failed to create data directory: {e}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_uses_edgepacer_child_under_cache_root() {
        let root = PathBuf::from("/tmp/cache-root");

        assert_eq!(
            edgepacer_data_dir_from(Some(root.clone())),
            root.join("edgepacer")
        );
    }

    #[test]
    fn data_dir_falls_back_to_tmp_when_cache_root_is_absent() {
        assert_eq!(
            edgepacer_data_dir_from(None),
            PathBuf::from("/tmp").join("edgepacer")
        );
    }

    #[test]
    fn prepare_data_dir_creates_the_shared_runtime_directory() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = edgepacer_data_dir_from(Some(root.path().to_path_buf()));

        prepare_data_dir(&data_dir).unwrap();

        assert!(data_dir.is_dir());
    }

    #[test]
    fn local_and_agent_shutdown_use_the_same_orchestrator_budget() {
        assert_eq!(
            ShutdownBudgets::local().orchestrator,
            ShutdownBudgets::agent().orchestrator
        );
        assert_eq!(ShutdownBudgets::agent().standard, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn shared_shutdown_notifies_subscribers_once_signaled() {
        let shutdown = SharedShutdown::new();
        let mut subscriber = shutdown.subscribe();

        shutdown.signal();
        subscriber.changed().await.unwrap();

        assert!(*subscriber.borrow());
    }
}
