//! Cross-platform supervisor lifecycle for the manager.
//!
//! `install` sets up the OS service that keeps `edgepacer-manager` running
//! (systemd on Linux, launchd on macOS, a Scheduled Task on Windows) and starts
//! it. `uninstall` reports to the control plane, then stops + removes the
//! service and deletes local state. Moving this into the manager keeps the
//! install scripts thin and makes uninstall remove exactly what install created.
//!
//! Not exercisable from a dev Mac for Linux/Windows — `cross check` validates
//! that it compiles per-target; behaviour must be validated on each host.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// OS service / task name (and launchd label suffix).
pub const SERVICE_NAME: &str = "EdgePacer";

/// What `install` needs to render the supervisor + the manager's env.
#[derive(Debug, Clone)]
pub struct InstallConfig {
    /// Absolute path to the installed manager binary (the supervisor runs this).
    pub manager_path: PathBuf,
    pub rails_url: String,
    pub account_token: String,
    pub update_public_key: Option<String>,
}

/// Set up the OS supervisor for the manager and start it.
pub async fn install(cfg: &InstallConfig) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        install_systemd(cfg).await
    }
    #[cfg(target_os = "macos")]
    {
        install_launchd(cfg).await
    }
    #[cfg(target_os = "windows")]
    {
        install_scheduled_task(cfg).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = cfg;
        anyhow::bail!("`install` is not supported on this platform")
    }
}

/// Report the uninstall to the control plane (best-effort), then stop + remove
/// the supervisor and delete local state (config + persisted tokens).
pub async fn uninstall(rails_url: &str) -> Result<String> {
    report_uninstall(rails_url).await;

    let mut log = String::new();
    #[cfg(target_os = "linux")]
    {
        log.push_str(&uninstall_systemd().await?);
    }
    #[cfg(target_os = "macos")]
    {
        log.push_str(&uninstall_launchd().await?);
    }
    #[cfg(target_os = "windows")]
    {
        log.push_str(&uninstall_scheduled_task().await?);
    }

    // Local state common to every platform: the persisted bootstrap token +
    // installation_id live in the token_store dir.
    let state_dir = crate::token_store::token_dir();
    if state_dir.exists() {
        let _ = std::fs::remove_dir_all(&state_dir);
        log.push_str(&format!("\nremoved state dir {}", state_dir.display()));
    }
    Ok(log)
}

/// Best-effort POST /api/v1/edgepacer/uninstall so the control plane knows this
/// install is gone. Authenticated with the persisted server bootstrap token;
/// silently skipped if we have no token or the request fails — uninstall must
/// never be blocked by the network.
async fn report_uninstall(rails_url: &str) {
    let Some(token) = crate::token_store::load_token("server_bootstrap_token") else {
        return;
    };
    let installation_id = crate::token_store::load_or_create_installation_id().unwrap_or_default();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let Ok(client) = client else { return };

    let url = format!(
        "{}/api/v1/edgepacer/uninstall",
        rails_url.trim_end_matches('/')
    );
    let mut req = client
        .post(&url)
        .json(&serde_json::json!({ "installation_id": installation_id, "reason": "uninstall" }));
    if let Some(auth) = crate::common::bearer_header(&token) {
        req = req.header(reqwest::header::AUTHORIZATION, auth);
    }
    match req.send().await {
        Ok(resp) => info!(status = %resp.status(), "[manager] reported uninstall to control plane"),
        Err(e) => warn!(error = %e, "[manager] uninstall report failed (continuing)"),
    }
}

// ── Linux (systemd) ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/edgepacer.service";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const UNIX_CONFIG_DIR: &str = "/etc/edgepacer";

#[cfg(target_os = "linux")]
async fn install_systemd(cfg: &InstallConfig) -> Result<String> {
    write_unix_env_file(cfg)?;
    let unit = format!(
        "[Unit]\n\
         Description=EdgePacer Log Agent\n\
         After=network.target\n\n\
         [Service]\n\
         Type=simple\n\
         EnvironmentFile={UNIX_CONFIG_DIR}/edgepacer.env\n\
         ExecStart={manager}\n\
         Restart=always\n\
         RestartSec=10\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SupplementaryGroups=systemd-journal\n\
         AmbientCapabilities=CAP_BPF CAP_PERFMON\n\
         CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW\n\
         LimitMEMLOCK=infinity\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        manager = cfg.manager_path.display(),
    );
    std::fs::write(SYSTEMD_UNIT_PATH, unit)
        .with_context(|| format!("write {SYSTEMD_UNIT_PATH}"))?;
    run("systemctl", &["daemon-reload"]).await?;
    run("systemctl", &["enable", "--now", "edgepacer"]).await?;
    Ok(format!(
        "installed + started systemd service (unit {SYSTEMD_UNIT_PATH})"
    ))
}

#[cfg(target_os = "linux")]
async fn uninstall_systemd() -> Result<String> {
    let _ = run("systemctl", &["disable", "--now", "edgepacer"]).await;
    let _ = std::fs::remove_file(SYSTEMD_UNIT_PATH);
    let _ = run("systemctl", &["daemon-reload"]).await;
    let _ = std::fs::remove_dir_all(UNIX_CONFIG_DIR);
    Ok("removed systemd service + config".to_string())
}

// ── macOS (launchd) ─────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.logpacer.edgepacer.plist";

#[cfg(target_os = "macos")]
async fn install_launchd(cfg: &InstallConfig) -> Result<String> {
    let key = cfg.update_public_key.clone().unwrap_or_default();
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>com.logpacer.edgepacer</string>\n\
         <key>ProgramArguments</key><array><string>{manager}</string></array>\n\
         <key>EnvironmentVariables</key><dict>\n\
         <key>EDGEPACER_ACCOUNT_TOKEN</key><string>{token}</string>\n\
         <key>EDGEPACER_RAILS_URL</key><string>{rails}</string>\n\
         <key>EDGEPACER_UPDATE_PUBLIC_KEY</key><string>{key}</string>\n\
         </dict>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         <key>StandardOutPath</key><string>/var/log/edgepacer.log</string>\n\
         <key>StandardErrorPath</key><string>/var/log/edgepacer.err.log</string>\n\
         </dict></plist>\n",
        manager = cfg.manager_path.display(),
        token = cfg.account_token,
        rails = cfg.rails_url,
    );
    std::fs::write(LAUNCHD_PLIST_PATH, plist)
        .with_context(|| format!("write {LAUNCHD_PLIST_PATH}"))?;
    run("launchctl", &["load", LAUNCHD_PLIST_PATH]).await?;
    run("launchctl", &["start", "com.logpacer.edgepacer"]).await?;
    Ok(format!(
        "installed + started launchd daemon ({LAUNCHD_PLIST_PATH})"
    ))
}

#[cfg(target_os = "macos")]
async fn uninstall_launchd() -> Result<String> {
    let _ = run("launchctl", &["unload", LAUNCHD_PLIST_PATH]).await;
    let _ = std::fs::remove_file(LAUNCHD_PLIST_PATH);
    Ok("removed launchd daemon".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_unix_env_file(cfg: &InstallConfig) -> Result<()> {
    std::fs::create_dir_all(UNIX_CONFIG_DIR)?;
    let path = Path::new(UNIX_CONFIG_DIR).join("edgepacer.env");
    let body = format!(
        "EDGEPACER_ACCOUNT_TOKEN={}\nEDGEPACER_RAILS_URL={}\nEDGEPACER_UPDATE_PUBLIC_KEY={}\n",
        cfg.account_token,
        cfg.rails_url,
        cfg.update_public_key.clone().unwrap_or_default(),
    );
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// ── Windows (Scheduled Task + loop wrapper) ─────────────────────────────────

#[cfg(target_os = "windows")]
async fn install_scheduled_task(cfg: &InstallConfig) -> Result<String> {
    let dir = cfg
        .manager_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let env_path = dir.join("edgepacer.env");
    let body = format!(
        "EDGEPACER_ACCOUNT_TOKEN={}\r\nEDGEPACER_RAILS_URL={}\r\nEDGEPACER_UPDATE_PUBLIC_KEY={}\r\n",
        cfg.account_token,
        cfg.rails_url,
        cfg.update_public_key.clone().unwrap_or_default(),
    );
    std::fs::write(&env_path, body).with_context(|| format!("write {}", env_path.display()))?;

    // Loop wrapper: load env, run the manager, relaunch on any exit (5s backoff).
    let wrapper_path = dir.join("edgepacer-service.cmd");
    let wrapper = format!(
        "@echo off\r\n\
         for /f \"usebackq eol=# tokens=1,* delims==\" %%a in (\"{env}\") do if not \"%%a\"==\"\" set \"%%a=%%b\"\r\n\
         :loop\r\n\
         \"{manager}\" >> \"{log}\" 2>&1\r\n\
         ping -n 6 127.0.0.1 >nul\r\n\
         goto loop\r\n",
        env = env_path.display(),
        manager = cfg.manager_path.display(),
        log = dir.join("edgepacer.log").display(),
    );
    std::fs::write(&wrapper_path, wrapper)
        .with_context(|| format!("write {}", wrapper_path.display()))?;

    // Built-in Scheduled Task (At startup, SYSTEM) that runs the wrapper.
    let ps = format!(
        "$ErrorActionPreference='Stop'; \
         Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue; \
         $a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c \"{wrapper}\"'; \
         $t=New-ScheduledTaskTrigger -AtStartup; \
         $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; \
         $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero); \
         Register-ScheduledTask -TaskName '{name}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; \
         Start-ScheduledTask -TaskName '{name}'",
        name = SERVICE_NAME,
        wrapper = wrapper_path.display(),
    );
    run("powershell", &["-NoProfile", "-Command", &ps]).await?;
    Ok(format!(
        "registered + started Scheduled Task '{SERVICE_NAME}'"
    ))
}

#[cfg(target_os = "windows")]
async fn uninstall_scheduled_task() -> Result<String> {
    let ps = format!(
        "Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue",
        name = SERVICE_NAME,
    );
    let _ = run("powershell", &["-NoProfile", "-Command", &ps]).await;
    Ok(format!("removed Scheduled Task '{SERVICE_NAME}'"))
}

// ── shared ──────────────────────────────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{program} {args:?} failed: {}", stderr.trim());
    }
    Ok(())
}
