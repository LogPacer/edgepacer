//! EdgePacer Manager — supervisor binary that wraps the agent.
//!
//! Handles bootstrap token persistence, process lifecycle (start/stop/restart),
//! auto-updates with rollback, and health monitoring.
//!
//! Mirrors Go edgepacer's `cmd/edgepacer-manager/main.go`.

use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use edgepacer::manager::{
    auth::ManagerAuth,
    process::ProcessManager,
    updater::Updater,
    windows_service::{self, InstallConfig},
};
use edgepacer::token_store;

/// CLI arguments for edgepacer-manager.
#[derive(Parser, Debug)]
#[command(
    name = "edgepacer-manager",
    version,
    about = "EdgePacer supervisor — manages agent lifecycle and updates"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<ManagerCommand>,

    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Path to the edgepacer binary
    #[arg(long, default_value = "edgepacer", env = "EDGEPACER_PATH")]
    edgepacer: PathBuf,

    /// Rails control-plane URL
    #[arg(long, env = "EDGEPACER_RAILS_URL")]
    rails: Option<String>,

    /// Account bootstrap token (for initial setup)
    #[arg(long, env = "EDGEPACER_ACCOUNT_TOKEN")]
    account_token: Option<String>,

    /// Platform identifier (auto-detected if not set)
    #[arg(long, default_value_t = detect_platform())]
    platform: String,

    /// Update check interval in seconds
    #[arg(long, default_value = "30", env = "EDGEPACER_CHECK_INTERVAL")]
    check_interval: u64,

    /// Health check timeout in seconds
    #[arg(long, default_value = "60", env = "EDGEPACER_HEALTH_TIMEOUT")]
    health_timeout: u64,

    /// Hex-encoded Ed25519 public key used to verify downloaded updates
    #[arg(long, env = "EDGEPACER_UPDATE_PUBLIC_KEY")]
    update_public_key: Option<String>,

    /// Enable debug logging in the agent child process
    #[arg(long)]
    debug: bool,

    /// Always download latest on startup (development mode)
    #[arg(long)]
    force_update: bool,

    /// Keep the manager binary itself up to date. Only safe under a supervisor
    /// that restarts the process on exit (systemd/launchd/Windows service): the
    /// manager swaps its own binary and exits for the supervisor to relaunch the
    /// new version.
    #[arg(long, env = "EDGEPACER_SELF_UPDATE")]
    self_update: bool,
}

#[derive(Subcommand, Debug)]
enum ManagerCommand {
    /// Install, remove, and control the Windows Service wrapper
    Service(ServiceArgs),
}

#[derive(Args, Debug)]
struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceCommand {
    /// Register edgepacer-manager as a Windows Service
    Install(ServiceInstallArgs),
    /// Delete the Windows Service registration
    Uninstall(ServiceNameArgs),
    /// Start the Windows Service
    Start(ServiceNameArgs),
    /// Stop the Windows Service
    Stop(ServiceNameArgs),
    /// Query Windows Service status
    Status(ServiceNameArgs),
}

#[derive(Args, Debug)]
struct ServiceInstallArgs {
    /// Windows Service name
    #[arg(long, default_value = windows_service::DEFAULT_SERVICE_NAME)]
    name: String,

    /// Windows Service display name
    #[arg(long, default_value = windows_service::DEFAULT_DISPLAY_NAME)]
    display_name: String,

    /// Path to the edgepacer-manager binary registered in the service binPath
    #[arg(long)]
    manager_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ServiceNameArgs {
    /// Windows Service name
    #[arg(long, default_value = windows_service::DEFAULT_SERVICE_NAME)]
    name: String,
}

fn detect_platform() -> String {
    go_platform_name(std::env::consts::OS, std::env::consts::ARCH)
}

fn go_platform_name(os: &str, arch: &str) -> String {
    let os = match os {
        "macos" => "darwin",
        other => other,
    };

    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    format!("{os}-{arch}")
}

/// Resolve the agent binary path. A relative path (the `edgepacer` default) is
/// anchored to the manager executable's own directory, so the agent always lands
/// in a writable location next to the manager regardless of the process CWD.
fn resolve_edgepacer_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    match std::env::current_exe() {
        Ok(exe) => match exe.parent() {
            Some(dir) => dir.join(&path),
            None => path,
        },
        Err(_) => path,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut run = cli.run;
    // Anchor a relative agent path to the manager's own directory rather than the
    // process CWD. Services and `iex`-piped installs run with CWD=system32, where
    // writing the agent at "./edgepacer" fails with "Access is denied".
    run.edgepacer = resolve_edgepacer_path(run.edgepacer);

    // Initialize logging
    let filter = EnvFilter::try_new("info").unwrap();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    if let Some(command) = cli.command {
        handle_manager_command(command, &run).await?;
        return Ok(());
    }

    let rails = required_arg(run.rails.as_deref(), "--rails / EDGEPACER_RAILS_URL")?;
    let account_token = required_arg(
        run.account_token.as_deref(),
        "--account-token / EDGEPACER_ACCOUNT_TOKEN",
    )?;

    info!(
        version = edgepacer::common::VERSION,
        platform = %run.platform,
        edgepacer_path = %run.edgepacer.display(),
        "[manager] edgepacer-manager starting"
    );

    // Step 1: Ensure bootstrap token
    edgepacer::common::validate_control_plane_url(rails)?;
    let mut auth = ManagerAuth::new(rails, account_token);
    auth.ensure_bootstrap_token().await?;

    // Step 2: Ensure edgepacer binary exists
    let installation_id = token_store::load_or_create_installation_id().unwrap_or_default();
    let updater = Updater::new(
        rails,
        auth.token(),
        &run.platform,
        &installation_id,
        run.update_public_key.as_deref(),
    )?;

    if !run.edgepacer.exists() || run.force_update {
        info!("[manager] downloading edgepacer binary");
        let current_version = if run.edgepacer.exists() {
            get_binary_version(&run.edgepacer).await.unwrap_or_default()
        } else {
            String::new()
        };

        if let Some(update) = updater.check_for_update(&current_version).await? {
            let new_path = updater.download_and_verify(&update, &run.edgepacer).await?;
            Updater::install_new(&new_path, &run.edgepacer)?;
            info!(version = %update.version, "[manager] edgepacer binary installed");
        } else if !run.edgepacer.exists() {
            anyhow::bail!(
                "edgepacer binary not found at {} and no update available",
                run.edgepacer.display()
            );
        }
    }

    // Step 3: Start the agent
    let mut process = ProcessManager::new(&run.edgepacer, rails, run.debug);
    process.start(auth.token()).await?;

    // Step 4: Wait for health check
    let health_timeout = Duration::from_secs(run.health_timeout);
    process.wait_healthy(health_timeout).await?;

    // Step 5: Set up signal handling
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    // Step 6: Enter update check loop
    let check_interval = Duration::from_secs(run.check_interval);
    info!(
        interval_secs = check_interval.as_secs(),
        "[manager] entering update check loop"
    );

    let mut tick = tokio::time::interval(check_interval);
    tick.tick().await; // skip immediate

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown_rx.changed() => {
                info!("[manager] shutdown signal received");
                break;
            }
        }

        // Check if process crashed — auto-restart
        if !process.is_running() {
            warn!("[manager] edgepacer process died, restarting");
            process.start(auth.token()).await?;
            if let Err(e) = process.wait_healthy(health_timeout).await {
                error!(error = %e, "[manager] restarted edgepacer failed health check");
                continue;
            }
        }

        // Self-heal: if the Server was deleted in Rails the persisted bootstrap
        // token now fails auth. Re-validate it; a definitive rejection re-onboards
        // (recreating the Server by installation_id) and rotates the token. Only
        // restart the agent when the token actually changed — a 200 or a transient
        // ping error leaves the running agent untouched.
        match auth.revalidate_bootstrap_token().await {
            Ok(true) => {
                info!(
                    "[manager] bootstrap token rotated after re-onboarding, restarting edgepacer"
                );
                process.start(auth.token()).await?;
                if let Err(e) = process.wait_healthy(health_timeout).await {
                    error!(error = %e, "[manager] re-onboarded edgepacer failed health check");
                    continue;
                }
            }
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "[manager] bootstrap token re-validation failed");
            }
        }

        // Manager self-update: keep our own binary current when supervised.
        // Check our version against the manager channel; on a newer release, swap
        // our binary and break so the post-loop shutdown stops the agent and the
        // supervisor relaunches the new manager. Gated behind --self-update
        // because exiting only self-heals under a restarting supervisor
        // (systemd/launchd today; Windows once the service supervisor lands).
        if run.self_update {
            match updater
                .check_for_self_update(edgepacer::common::VERSION)
                .await
            {
                Ok(Some(update)) => {
                    info!(
                        from = edgepacer::common::VERSION,
                        to = %update.version,
                        "[manager] manager self-update available; installing"
                    );
                    match perform_self_update(&updater, &update).await {
                        Ok(()) => {
                            info!(
                                "[manager] self-update installed; exiting for supervisor restart"
                            );
                            break;
                        }
                        Err(e) => error!(error = %e, "[manager] self-update failed"),
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(error = %e, "[manager] self-update check failed"),
            }
        }

        // Check for updates
        let current_version = match process.get_version().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "[manager] failed to get current version");
                continue;
            }
        };

        match updater.check_for_update(&current_version).await {
            Ok(Some(update)) => {
                info!(
                    from = %current_version,
                    to = %update.version,
                    "[manager] update available, performing update"
                );
                if let Err(e) = perform_update(
                    &mut process,
                    &updater,
                    &update,
                    &run.edgepacer,
                    &current_version,
                    auth.token(),
                    health_timeout,
                )
                .await
                {
                    error!(error = %e, "[manager] update failed");
                }
            }
            Ok(None) => {
                // Up to date
            }
            Err(e) => {
                warn!(error = %e, "[manager] update check failed");
            }
        }
    }

    // Graceful shutdown
    info!("[manager] stopping edgepacer");
    process.stop().await?;
    info!("[manager] edgepacer-manager stopped");

    Ok(())
}

fn required_arg<'a>(value: Option<&'a str>, name: &str) -> anyhow::Result<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

async fn handle_manager_command(command: ManagerCommand, run: &RunArgs) -> anyhow::Result<()> {
    match command {
        ManagerCommand::Service(args) => handle_service_command(args.command, run).await,
    }
}

async fn handle_service_command(command: ServiceCommand, run: &RunArgs) -> anyhow::Result<()> {
    let output = match command {
        ServiceCommand::Install(args) => {
            let config = service_install_config(args, run)?;
            windows_service::install_service(&config).await?
        }
        ServiceCommand::Uninstall(args) => windows_service::uninstall_service(&args.name).await?,
        ServiceCommand::Start(args) => windows_service::start_service(&args.name).await?,
        ServiceCommand::Stop(args) => windows_service::stop_service(&args.name).await?,
        ServiceCommand::Status(args) => windows_service::status_service(&args.name).await?,
    };

    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

fn service_install_config(
    args: ServiceInstallArgs,
    run: &RunArgs,
) -> anyhow::Result<InstallConfig> {
    let rails = required_arg(run.rails.as_deref(), "--rails / EDGEPACER_RAILS_URL")?;
    let account_token = required_arg(
        run.account_token.as_deref(),
        "--account-token / EDGEPACER_ACCOUNT_TOKEN",
    )?;
    let manager_path = match args.manager_path {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|e| anyhow::anyhow!("failed to detect current manager path: {e}"))?,
    };

    Ok(InstallConfig {
        service_name: args.name,
        display_name: args.display_name,
        manager_path,
        edgepacer_path: run.edgepacer.clone(),
        rails_url: rails.to_string(),
        account_token: account_token.to_string(),
        platform: run.platform.clone(),
        check_interval: run.check_interval,
        health_timeout: run.health_timeout,
        update_public_key: run.update_public_key.clone(),
        debug: run.debug,
        force_update: run.force_update,
    })
}

/// Perform a full update with rollback on failure.
async fn perform_update(
    process: &mut ProcessManager,
    updater: &Updater,
    update: &edgepacer::manager::updater::UpdateInfo,
    edgepacer_path: &Path,
    current_version: &str,
    server_token: &str,
    health_timeout: Duration,
) -> anyhow::Result<()> {
    let start = Instant::now();

    // Download and verify
    let new_path = updater.download_and_verify(update, edgepacer_path).await?;

    // Backup current
    let backup_path = Updater::backup_current(edgepacer_path)?;

    // Stop current process
    process.stop().await?;

    // Install new binary
    if let Err(e) = Updater::install_new(&new_path, edgepacer_path) {
        Updater::restore_backup(&backup_path, edgepacer_path)?;
        let result = updater.build_result(
            current_version,
            &update.version,
            false,
            start.elapsed(),
            Some(format!("install failed: {e}")),
            true,
        );
        let _ = updater.report_update_result(&result).await;
        anyhow::bail!("install failed: {e}");
    }

    // Start new version
    if let Err(e) = process.start(server_token).await {
        warn!(error = %e, "[manager] new version failed to start, rolling back");
        Updater::restore_backup(&backup_path, edgepacer_path)?;
        process.start(server_token).await?;
        let result = updater.build_result(
            current_version,
            &update.version,
            false,
            start.elapsed(),
            Some(format!("start failed: {e}")),
            true,
        );
        let _ = updater.report_update_result(&result).await;
        anyhow::bail!("new version failed to start: {e}");
    }

    // Health check
    if let Err(e) = process.wait_healthy(health_timeout).await {
        warn!(error = %e, "[manager] new version failed health check, rolling back");
        process.stop().await?;
        Updater::restore_backup(&backup_path, edgepacer_path)?;
        process.start(server_token).await?;
        let result = updater.build_result(
            current_version,
            &update.version,
            false,
            start.elapsed(),
            Some(format!("health check failed: {e}")),
            true,
        );
        let _ = updater.report_update_result(&result).await;
        anyhow::bail!("health check failed: {e}");
    }

    // Success
    Updater::cleanup_backup(&backup_path);
    let result = updater.build_result(
        current_version,
        &update.version,
        true,
        start.elapsed(),
        None,
        false,
    );
    let _ = updater.report_update_result(&result).await;

    info!(
        from = current_version,
        to = %update.version,
        duration_secs = start.elapsed().as_secs(),
        "[manager] update completed successfully"
    );

    Ok(())
}

/// Download, verify, and swap the manager's own binary, with rollback on
/// failure. The caller exits afterward so the supervisor relaunches the new
/// binary; the running image keeps executing until then.
async fn perform_self_update(
    updater: &Updater,
    update: &edgepacer::manager::updater::UpdateInfo,
) -> anyhow::Result<()> {
    let manager_exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("resolve manager executable path: {e}"))?;
    let new_path = updater.download_and_verify(update, &manager_exe).await?;
    let backup = Updater::backup_current(&manager_exe)?;
    if let Err(e) = Updater::install_new(&new_path, &manager_exe) {
        Updater::restore_backup(&backup, &manager_exe)?;
        anyhow::bail!("self-update install failed: {e}");
    }
    Updater::cleanup_backup(&backup);
    Ok(())
}

/// Get the version of a binary by running it with --version.
async fn get_binary_version(path: &PathBuf) -> anyhow::Result<String> {
    let output = tokio::process::Command::new(path)
        .arg("--version")
        .output()
        .await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::{Cli, ServiceCommand, detect_platform, go_platform_name, service_install_config};
    use clap::{CommandFactory, Parser};

    #[test]
    fn self_update_flag_defaults_off_and_parses() {
        let off = Cli::parse_from(["edgepacer-manager"]);
        assert!(!off.run.self_update);
        let on = Cli::parse_from(["edgepacer-manager", "--self-update"]);
        assert!(on.run.self_update);
    }

    #[test]
    fn detect_platform_uses_go_style_names_on_current_host() {
        let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-amd64",
            ("linux", "aarch64") => "linux-arm64",
            ("macos", "x86_64") => "darwin-amd64",
            ("macos", "aarch64") => "darwin-arm64",
            ("windows", "x86_64") => "windows-amd64",
            (os, arch) => panic!("unexpected host platform for test: {os}-{arch}"),
        };

        assert_eq!(detect_platform(), expected);
    }

    #[test]
    fn go_platform_name_maps_supported_platform_pairs() {
        let cases = [
            (("linux", "x86_64"), "linux-amd64"),
            (("linux", "aarch64"), "linux-arm64"),
            (("macos", "x86_64"), "darwin-amd64"),
            (("macos", "aarch64"), "darwin-arm64"),
            (("windows", "x86_64"), "windows-amd64"),
        ];

        for ((os, arch), expected) in cases {
            assert_eq!(go_platform_name(os, arch), expected);
        }
    }

    #[test]
    fn cli_exposes_version_flag() {
        assert!(Cli::command().get_version().is_some());
    }

    #[test]
    fn cli_parses_service_status_without_run_credentials() {
        let cli = Cli::try_parse_from(["edgepacer-manager", "service", "status"]).unwrap();

        let Some(super::ManagerCommand::Service(service)) = cli.command else {
            panic!("expected service command");
        };
        let ServiceCommand::Status(args) = service.command else {
            panic!("expected service status command");
        };
        assert_eq!(
            args.name,
            edgepacer::manager::windows_service::DEFAULT_SERVICE_NAME
        );
    }

    #[test]
    fn service_install_requires_run_credentials() {
        let run = super::RunArgs {
            edgepacer: "./edgepacer".into(),
            rails: None,
            account_token: Some("account-token".into()),
            platform: "windows-amd64".into(),
            check_interval: 30,
            health_timeout: 60,
            update_public_key: None,
            debug: false,
            force_update: false,
            self_update: false,
        };
        let args = super::ServiceInstallArgs {
            name: "EdgePacerTest".into(),
            display_name: "EdgePacer Test".into(),
            manager_path: Some("./edgepacer-manager".into()),
        };

        let err = service_install_config(args, &run).unwrap_err();
        assert!(err.to_string().contains("--rails"));
    }

    #[test]
    fn required_arg_trims_secret_file_newline() {
        let value = super::required_arg(Some("account-token\n"), "--account-token").unwrap();

        assert_eq!(value, "account-token");
    }
}
