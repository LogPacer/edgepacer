//! Windows service discovery via `sc queryex`.
//!
//! This is an inventory adapter, not a log reader. Windows service logs are
//! collected through the Event Log source; discovered services are reported so
//! LogPacer can understand host inventory and lifecycle changes.

use std::process::Command;

use tracing::debug;

use super::SystemdService;

/// Discover Windows services on the host.
///
/// Returns an empty vec on non-Windows hosts. Failures on Windows are reported
/// to the caller so the census can carry the backend error.
pub async fn discover_services() -> Result<Vec<SystemdService>, String> {
    if !windows_service_discovery_supported() {
        debug!("windows service discovery skipped on non-Windows host");
        return Ok(Vec::new());
    }

    tokio::task::spawn_blocking(discover_services_sync)
        .await
        .map_err(|e| format!("windows service discovery task failed: {e}"))?
}

fn windows_service_discovery_supported() -> bool {
    windows_service_discovery_supported_for(std::env::consts::OS)
}

fn windows_service_discovery_supported_for(os: &str) -> bool {
    os == "windows"
}

fn discover_services_sync() -> Result<Vec<SystemdService>, String> {
    let output = Command::new("sc")
        .args(["queryex", "type=", "service", "state=", "all"])
        .output()
        .map_err(|e| format!("failed to run sc queryex: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sc queryex failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let services = parse_sc_queryex_output(&stdout);

    debug!(count = services.len(), "discovered windows services");
    Ok(services)
}

fn parse_sc_queryex_output(output: &str) -> Vec<SystemdService> {
    let mut services = Vec::new();
    let mut current = ServiceDraft::default();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("SERVICE_NAME:") {
            if let Some(service) = current.finish() {
                services.push(service);
            }
            current = ServiceDraft {
                name: Some(name.trim().to_string()),
                ..ServiceDraft::default()
            };
            continue;
        }

        if let Some(display_name) = trimmed.strip_prefix("DISPLAY_NAME:") {
            current.display_name = Some(display_name.trim().to_string());
            continue;
        }

        if let Some(value) = field_value(trimmed, "TYPE") {
            current.service_type = Some(parse_sc_named_value(value).to_ascii_lowercase());
            continue;
        }

        if let Some(value) = field_value(trimmed, "STATE") {
            current.state = Some(parse_sc_named_value(value).to_ascii_lowercase());
            continue;
        }

        if let Some(value) = field_value(trimmed, "PID") {
            current.pid = value.parse::<u32>().unwrap_or(0);
        }
    }

    if let Some(service) = current.finish() {
        services.push(service);
    }

    services
}

fn field_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    (key.trim() == field).then(|| value.trim())
}

fn parse_sc_named_value(value: &str) -> String {
    let mut parts = value.split_whitespace();
    let _code = parts.next();
    parts.collect::<Vec<_>>().join(" ")
}

#[derive(Default)]
struct ServiceDraft {
    name: Option<String>,
    display_name: Option<String>,
    service_type: Option<String>,
    state: Option<String>,
    pid: u32,
}

impl ServiceDraft {
    fn finish(&mut self) -> Option<SystemdService> {
        let name = self.name.take()?.trim().to_string();
        if name.is_empty() {
            return None;
        }

        let description = self
            .display_name
            .take()
            .filter(|display_name| !display_name.is_empty())
            .unwrap_or_else(|| name.clone());
        let active_state = self
            .state
            .take()
            .filter(|state| !state.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let sub_state = self.service_type.take().unwrap_or_default();

        Some(SystemdService {
            name: name.clone(),
            load_state: "installed".into(),
            active_state,
            sub_state,
            description,
            service_name: name,
            main_pid: self.pid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sc_queryex_services() {
        let output = r#"
SERVICE_NAME: EventLog
DISPLAY_NAME: Windows Event Log
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 2112
        FLAGS              :

SERVICE_NAME: ALG
DISPLAY_NAME: Application Layer Gateway Service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
"#;

        let services = parse_sc_queryex_output(output);

        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "EventLog");
        assert_eq!(services[0].description, "Windows Event Log");
        assert_eq!(services[0].load_state, "installed");
        assert_eq!(services[0].active_state, "running");
        assert_eq!(services[0].sub_state, "win32");
        assert_eq!(services[0].main_pid, 2112);

        assert_eq!(services[1].name, "ALG");
        assert_eq!(services[1].active_state, "stopped");
        assert_eq!(services[1].main_pid, 0);
    }

    #[test]
    fn display_name_falls_back_to_service_name() {
        let services = parse_sc_queryex_output(
            r#"
SERVICE_NAME: EventLog
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
        PID                : 2112
"#,
        );

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].description, "EventLog");
    }

    #[test]
    fn windows_service_discovery_requires_windows() {
        assert!(windows_service_discovery_supported_for("windows"));
        assert!(!windows_service_discovery_supported_for("linux"));
        assert!(!windows_service_discovery_supported_for("macos"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn discovers_event_log_service_on_windows() {
        let services = discover_services().await.unwrap();
        let event_log = services
            .iter()
            .find(|service| service.name == "EventLog")
            .expect("EventLog service should be discovered");

        assert_eq!(event_log.description, "Windows Event Log");
        assert_eq!(event_log.active_state, "running");
        assert!(event_log.main_pid > 0);
    }
}
