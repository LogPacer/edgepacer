//! EdgePacer Manager — supervisor binary that wraps the agent.
//!
//! Handles bootstrap token persistence, process lifecycle (start/stop/restart),
//! auto-updates with rollback, and health monitoring.
//!
//! Mirrors legacy EdgePacer's `cmd/edgepacer-manager/main.go`.

use clap::Parser;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use edgepacer::manager::{auth::ManagerAuth, process::ProcessManager, updater::Updater};
use edgepacer::token_store;

/// CLI arguments for edgepacer-manager.
#[derive(Parser, Debug)]
#[command(
    name = "edgepacer-manager",
    version,
    about = "EdgePacer supervisor — manages agent lifecycle and updates"
)]
struct Cli {
    /// Path to the edgepacer binary
    #[arg(long, default_value = "./edgepacer", env = "EDGEPACER_PATH")]
    edgepacer: PathBuf,

    /// Rails control-plane URL
    #[arg(long, env = "EDGEPACER_RAILS_URL")]
    rails: String,

    /// Account bootstrap token (for initial setup)
    #[arg(long, env = "EDGEPACER_ACCOUNT_TOKEN")]
    account_token: String,

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_new("info").unwrap();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        platform = %cli.platform,
        edgepacer_path = %cli.edgepacer.display(),
        "[manager] edgepacer-manager starting"
    );

    // Step 1: Ensure bootstrap token
    edgepacer::common::validate_control_plane_url(&cli.rails)?;
    let mut auth = ManagerAuth::new(&cli.rails, &cli.account_token);
    auth.ensure_bootstrap_token().await?;

    // Step 2: Ensure edgepacer binary exists
    let installation_id = token_store::load_or_create_installation_id().unwrap_or_default();
    let updater = Updater::new(
        &cli.rails,
        auth.token(),
        &cli.platform,
        &installation_id,
        cli.update_public_key.as_deref(),
    )?;

    if !cli.edgepacer.exists() || cli.force_update {
        info!("[manager] downloading edgepacer binary");
        let current_version = if cli.edgepacer.exists() {
            get_binary_version(&cli.edgepacer).await.unwrap_or_default()
        } else {
            String::new()
        };

        if let Some(update) = updater.check_for_update(&current_version).await? {
            let new_path = updater.download_and_verify(&update, &cli.edgepacer).await?;
            Updater::install_new(&new_path, &cli.edgepacer)?;
            info!(version = %update.version, "[manager] edgepacer binary installed");
        } else if !cli.edgepacer.exists() {
            anyhow::bail!(
                "edgepacer binary not found at {} and no update available",
                cli.edgepacer.display()
            );
        }
    }

    // Step 3: Start the agent
    let mut process = ProcessManager::new(&cli.edgepacer, &cli.rails, cli.debug);
    process.start(auth.token()).await?;

    // Step 4: Wait for health check
    let health_timeout = Duration::from_secs(cli.health_timeout);
    process.wait_healthy(health_timeout).await?;

    // Step 5: Set up signal handling
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    // Step 6: Enter update check loop
    let check_interval = Duration::from_secs(cli.check_interval);
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
                    &cli.edgepacer,
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
    use super::{Cli, detect_platform, go_platform_name};
    use clap::CommandFactory;

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
}
