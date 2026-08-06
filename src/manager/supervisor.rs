//! Cross-platform supervisor lifecycle for the manager.
//!
//! `install` sets up the OS service that keeps `edgepacer-manager` running
//! (systemd on Linux, launchd on macOS, a Scheduled Task on Windows) and starts
//! it. `uninstall` reports to the control plane, then stops + removes the
//! service and deletes local state and binaries. Moving this into the manager keeps the
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
    // These values are written into line-oriented env files and the launchd
    // plist, so a control character in (e.g.) the token could inject extra env
    // lines or plist content. Reject them before writing anything.
    ensure_single_line("account token", &cfg.account_token)?;
    ensure_single_line("rails URL", &cfg.rails_url)?;
    if let Some(key) = &cfg.update_public_key {
        ensure_single_line("update public key", key)?;
    }

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
        anyhow::bail!("`install` is not supported on this platform")
    }
}

/// Reject control characters (newline / CR / NUL) in operator-supplied values
/// that get written into env files or the launchd plist — defends against
/// injecting extra env lines or plist content via a malformed token.
fn ensure_single_line(label: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        anyhow::bail!(
            "{label} contains a control character; refusing to write it to a config file"
        );
    }
    Ok(())
}

/// Report the uninstall to the control plane (best-effort), then stop + remove
/// the supervisor and delete local state (config + persisted tokens) and the
/// installed binaries (agent + update leftovers + the manager itself on Unix).
pub async fn uninstall(rails_url: &str, agent_path: &Path) -> Result<String> {
    // `uninstall` normally runs from an interactive shell where
    // EDGEPACER_RAILS_URL is unset (it lives in the supervisor's env file /
    // plist), so recover the URL install wrote before that config is deleted —
    // reporting against an empty URL just fails with a reqwest builder error.
    let rails_url = if rails_url.trim().is_empty() {
        stored_rails_url()
    } else {
        Some(rails_url.to_string())
    };
    match &rails_url {
        Some(url) => report_uninstall(url).await,
        None => info!("[manager] no control-plane URL found; skipping uninstall report"),
    }

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

    remove_agent_binaries(agent_path, &mut log);
    remove_manager_binary(&mut log);
    Ok(log)
}

/// Delete the agent binary the manager downloaded, plus update leftovers
/// (`.backup` from a rollback point, `.new` from an interrupted download).
fn remove_agent_binaries(agent_path: &Path, log: &mut String) {
    for path in [
        agent_path.to_path_buf(),
        agent_path.with_extension("backup"),
        agent_path.with_extension("new"),
    ] {
        if std::fs::remove_file(&path).is_ok() {
            log.push_str(&format!("\nremoved {}", path.display()));
        }
    }
}

/// Delete the manager's own binary. On Unix a running executable can unlink
/// itself (the mapped image stays valid until exit); Windows locks a running
/// .exe, so there the binary is left for the operator to delete. Either way,
/// clear a `.old` left behind by a prior self-update's rename-aside.
fn remove_manager_binary(log: &mut String) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = std::fs::remove_file(exe.with_extension("old"));
    #[cfg(not(target_os = "windows"))]
    if std::fs::remove_file(&exe).is_ok() {
        log.push_str(&format!("\nremoved {}", exe.display()));
    }
    #[cfg(target_os = "windows")]
    log.push_str(&format!(
        "\nmanager binary left at {} (a running exe cannot delete itself); delete it manually",
        exe.display()
    ));
}

/// Recover the control-plane URL that `install` persisted for the supervisor:
/// the env file on Linux/Windows, the launchd plist on macOS.
fn stored_rails_url() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let env = std::fs::read_to_string(Path::new(UNIX_CONFIG_DIR).join("edgepacer.env")).ok()?;
        rails_url_from_env_file(&env)
    }
    #[cfg(target_os = "macos")]
    {
        let plist = std::fs::read_to_string(LAUNCHD_PLIST_PATH).ok()?;
        rails_url_from_plist(&plist)
    }
    #[cfg(target_os = "windows")]
    {
        let env_path = std::env::current_exe()
            .ok()?
            .parent()?
            .join("edgepacer.env");
        let env = std::fs::read_to_string(env_path).ok()?;
        rails_url_from_env_file(&env)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn rails_url_from_env_file(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("EDGEPACER_RAILS_URL="))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(any(target_os = "macos", test))]
fn rails_url_from_plist(plist: &str) -> Option<String> {
    let after = plist
        .split("<key>EDGEPACER_RAILS_URL</key><string>")
        .nth(1)?;
    let value = after.split("</string>").next()?;
    // Reverse of `xml_escape` (applied when the plist was written); `&amp;`
    // must be unescaped last so it can't create new entities.
    let value = value
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&");
    (!value.is_empty()).then_some(value)
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
#[cfg(target_os = "linux")]
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
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_os = "macos")]
async fn install_launchd(cfg: &InstallConfig) -> Result<String> {
    // XML-escape every interpolated value so a token containing `<` / `&` / `"`
    // can't break out of its <string> and inject plist content.
    let manager = xml_escape(&cfg.manager_path.display().to_string());
    let token = xml_escape(&cfg.account_token);
    let rails = xml_escape(&cfg.rails_url);
    let key = xml_escape(&cfg.update_public_key.clone().unwrap_or_default());
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
    );
    std::fs::write(LAUNCHD_PLIST_PATH, plist)
        .with_context(|| format!("write {LAUNCHD_PLIST_PATH}"))?;
    // The plist embeds the bootstrap token (EnvironmentVariables) -> root-only.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(LAUNCHD_PLIST_PATH, std::fs::Permissions::from_mode(0o600))?;
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

#[cfg(target_os = "linux")]
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
    // The env file holds the bootstrap token -> restrict to SYSTEM + Administrators
    // (remove inherited ACEs so non-admins on the box can't read it).
    let env_str = env_path.display().to_string();
    run(
        "icacls",
        &[
            env_str.as_str(),
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:F",
            "Administrators:F",
        ],
    )
    .await?;

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
    // Stop a running instance first, then remove the task definition.
    let ps = format!(
        "Stop-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue; \
         Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue",
        name = SERVICE_NAME,
    );
    let _ = run("powershell", &["-NoProfile", "-Command", &ps]).await;

    // Remove the config we wrote next to the manager binary: the env file holds
    // the bootstrap token (must not linger after uninstall), and the wrapper +
    // log are install artifacts. The running .exe can't delete itself, so the
    // binary is left for the caller to remove.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::remove_file(dir.join("edgepacer.env"));
            let _ = std::fs::remove_file(dir.join("edgepacer-service.cmd"));
            let _ = std::fs::remove_file(dir.join("edgepacer.log"));
        }
    }
    Ok(format!("removed Scheduled Task '{SERVICE_NAME}' + config"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rails_url_from_env_file_extracts_value() {
        let body = "EDGEPACER_ACCOUNT_TOKEN=tok\nEDGEPACER_RAILS_URL=https://app.logpacer.com\nEDGEPACER_UPDATE_PUBLIC_KEY=abc\n";
        assert_eq!(
            rails_url_from_env_file(body).as_deref(),
            Some("https://app.logpacer.com")
        );
    }

    #[test]
    fn rails_url_from_env_file_handles_crlf_and_missing() {
        let crlf =
            "EDGEPACER_ACCOUNT_TOKEN=tok\r\nEDGEPACER_RAILS_URL=https://app.logpacer.com\r\n";
        assert_eq!(
            rails_url_from_env_file(crlf).as_deref(),
            Some("https://app.logpacer.com")
        );
        assert_eq!(
            rails_url_from_env_file("EDGEPACER_ACCOUNT_TOKEN=tok\n"),
            None
        );
        assert_eq!(rails_url_from_env_file("EDGEPACER_RAILS_URL=\n"), None);
    }

    #[test]
    fn rails_url_from_plist_extracts_and_unescapes() {
        let plist = "<dict>\n\
             <key>EDGEPACER_RAILS_URL</key><string>https://app.logpacer.com/?a=1&amp;b=2</string>\n\
             </dict>";
        assert_eq!(
            rails_url_from_plist(plist).as_deref(),
            Some("https://app.logpacer.com/?a=1&b=2")
        );
        assert_eq!(rails_url_from_plist("<dict></dict>"), None);
    }

    #[test]
    fn remove_agent_binaries_deletes_agent_and_update_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("edgepacer");
        let backup = dir.path().join("edgepacer.backup");
        let new = dir.path().join("edgepacer.new");
        for p in [&agent, &backup, &new] {
            std::fs::write(p, b"bin").unwrap();
        }

        let mut log = String::new();
        remove_agent_binaries(&agent, &mut log);

        for p in [&agent, &backup, &new] {
            assert!(!p.exists(), "{} should be removed", p.display());
        }
        assert!(log.contains("removed"));
    }

    #[test]
    fn remove_agent_binaries_is_quiet_when_nothing_exists() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = String::new();
        remove_agent_binaries(&dir.path().join("edgepacer"), &mut log);
        assert!(log.is_empty());
    }
}
