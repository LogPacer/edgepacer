//! Systemd service discovery via `systemctl` CLI.
//!
//! Discovers ALL systemd services with their state — EdgePacer reports raw data
//! and Rails handles categorization (which services are interesting, what log
//! sources to create, etc.).
//!
//! Uses `systemctl list-units --type=service --all --no-pager --no-legend`
//! matching legacy EdgePacer's systemd discovery approach.
//!
//! Swappable: the `systemctl` subprocess is the adapter detail. A native
//! D-Bus/systemd crate could replace it without changing the `SystemdService`
//! output shape.

use std::path::Path;
use std::process::Command;

use tracing::debug;

use super::SystemdService;

/// Discover all systemd services on the host.
///
/// Returns an empty vec on non-Linux or if systemctl is unavailable (best-effort).
pub async fn discover_services() -> Result<Vec<SystemdService>, String> {
    if !systemd_discovery_supported() {
        debug!("systemd discovery skipped on non-systemd host");
        return Ok(Vec::new());
    }

    // Run in a blocking task since Command::output() is synchronous.
    tokio::task::spawn_blocking(discover_services_sync)
        .await
        .map_err(|e| format!("systemd discovery task failed: {e}"))?
}

fn systemd_discovery_supported() -> bool {
    systemd_discovery_supported_for(
        std::env::consts::OS,
        Path::new("/run/systemd/system").exists(),
    )
}

fn systemd_discovery_supported_for(os: &str, runtime_present: bool) -> bool {
    os == "linux" && runtime_present
}

fn discover_services_sync() -> Result<Vec<SystemdService>, String> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
        ])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("systemctl failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let services: Vec<SystemdService> = stdout
        .lines()
        .filter_map(parse_systemctl_line)
        .filter(is_reportable)
        .collect();

    debug!(count = services.len(), "discovered systemd services");
    Ok(services)
}

/// Whether a unit belongs in the census at all.
///
/// Inactive/dead units have no log output and no operational presence —
/// reporting them creates loggables born stopped that churn through the
/// lifecycle forever (a log platform inventories things that LOG, not things
/// that merely exist as unit files). Failed units stay: they usually wrote
/// diagnostics on the way down, which is exactly when someone wants logs.
/// A unit that later goes inactive simply vanishes from the scan and the
/// ChangeTracker emits the stopped delta.
fn is_reportable(service: &SystemdService) -> bool {
    !matches!(service.active_state.as_str(), "inactive" | "dead")
}

/// Parse a single line from `systemctl list-units --no-legend` output.
///
/// Format: "  unit.service  loaded  active  running  Description text"
/// Fields are whitespace-separated (possibly multiple spaces), with description
/// being everything after the fourth field.
fn parse_systemctl_line(line: &str) -> Option<SystemdService> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Split on whitespace, collecting non-empty tokens.
    let mut tokens = trimmed.split_whitespace();

    let name = tokens.next()?;
    if !name.ends_with(".service") {
        return None;
    }

    let load_state = tokens.next().unwrap_or_default();
    let active_state = tokens.next().unwrap_or_default();
    let sub_state = tokens.next().unwrap_or_default();
    // Description is the remainder.
    let description: String = tokens.collect::<Vec<&str>>().join(" ");

    let service_name = name.strip_suffix(".service").unwrap_or(name);

    Some(SystemdService {
        name: name.to_string(),
        load_state: load_state.to_string(),
        active_state: active_state.to_string(),
        sub_state: sub_state.to_string(),
        description,
        service_name: service_name.to_string(),
        main_pid: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_service_line() {
        let line =
            "  nginx.service                loaded active running  A high performance web server";
        let svc = parse_systemctl_line(line).unwrap();
        assert_eq!(svc.name, "nginx.service");
        assert_eq!(svc.service_name, "nginx");
        assert_eq!(svc.load_state, "loaded");
        assert_eq!(svc.active_state, "active");
        assert_eq!(svc.sub_state, "running");
    }

    #[test]
    fn parse_inactive_service() {
        let line = "  bluetooth.service            loaded inactive dead    Bluetooth service";
        let svc = parse_systemctl_line(line).unwrap();
        assert_eq!(svc.name, "bluetooth.service");
        assert_eq!(svc.active_state, "inactive");
        assert_eq!(svc.sub_state, "dead");
    }

    #[test]
    fn skip_non_service_units() {
        let line = "  basic.target                 loaded active active   Basic System";
        assert!(parse_systemctl_line(line).is_none());
    }

    #[test]
    fn skip_empty_lines() {
        assert!(parse_systemctl_line("").is_none());
        assert!(parse_systemctl_line("   ").is_none());
    }

    #[test]
    fn reportable_filters_inactive_and_dead_keeps_active_and_failed() {
        let mk = |active: &str| SystemdService {
            name: "x.service".into(),
            load_state: "loaded".into(),
            active_state: active.into(),
            sub_state: String::new(),
            description: String::new(),
            service_name: "x".into(),
            main_pid: 0,
        };

        assert!(is_reportable(&mk("active")));
        assert!(is_reportable(&mk("activating")));
        assert!(is_reportable(&mk("reloading")));
        assert!(
            is_reportable(&mk("failed")),
            "failed units wrote diagnostics on the way down — keep them"
        );
        assert!(!is_reportable(&mk("inactive")));
        assert!(!is_reportable(&mk("dead")));
    }

    #[test]
    fn systemd_discovery_requires_linux_systemd_runtime() {
        assert!(systemd_discovery_supported_for("linux", true));
        assert!(!systemd_discovery_supported_for("linux", false));
        assert!(!systemd_discovery_supported_for("macos", true));
        assert!(!systemd_discovery_supported_for("windows", true));
    }
}
