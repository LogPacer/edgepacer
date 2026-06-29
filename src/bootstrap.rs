//! Host metadata collection — runs once at startup.
//!
//! Mirrors legacy EdgePacer's `internal/bootstrap/` package.
//! Collects system facts for initial registration and resource identification.

use serde::Serialize;
use tracing::info;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeContext {
    pub in_container: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_runtime: Option<String>,
    pub deployment_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
}

/// Host metadata collected at startup.
#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu_cores: usize,
    pub memory_mb: u64,
    pub in_container: bool,
    pub collected_at: String,
}

/// Collect host metadata. Best-effort — returns partial data on failure.
pub fn collect() -> Metadata {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    let os = std::env::consts::OS.to_string();
    let architecture = std::env::consts::ARCH.to_string();

    let os_version = read_os_version();
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let memory_mb = read_memory_mb();
    let in_container = detect_container();

    let metadata = Metadata {
        hostname,
        os,
        os_version,
        architecture,
        cpu_cores,
        memory_mb,
        in_container,
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    info!(
        hostname = %metadata.hostname,
        os = %metadata.os,
        arch = %metadata.architecture,
        cores = metadata.cpu_cores,
        memory_mb = metadata.memory_mb,
        in_container = metadata.in_container,
        "collected host metadata"
    );

    metadata
}

pub fn collect_runtime_context() -> RuntimeContext {
    let in_kubernetes =
        kubernetes_service_account_exists() || std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
    runtime_context_from_parts(
        detect_container(),
        detect_container_runtime(),
        in_kubernetes,
        |key| std::env::var(key).ok(),
    )
}

/// Read OS version from /etc/os-release or equivalent.
fn read_os_version() -> String {
    // Try /etc/os-release (Linux)
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(version) = line.strip_prefix("PRETTY_NAME=") {
                return version.trim_matches('"').to_string();
            }
        }
    }

    // macOS: use sw_vers
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !version.is_empty() {
                return format!("macOS {}", version);
            }
        }
    }

    "unknown".to_string()
}

/// Read total memory in MB.
fn read_memory_mb() -> u64 {
    // Linux: /proc/meminfo
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if let Some(kb_str) = parts.first()
                    && let Ok(kb) = kb_str.parse::<u64>()
                {
                    return kb / 1024;
                }
            }
        }
    }

    // macOS: sysctl hw.memsize
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(bytes) = s.parse::<u64>() {
                return bytes / (1024 * 1024);
            }
        }
    }

    // Windows: sysinfo wraps GlobalMemoryStatusEx for total physical RAM
    // (same source host_metrics.rs uses; returns bytes).
    #[cfg(target_os = "windows")]
    {
        use sysinfo::System;
        let mut sys = System::new();
        sys.refresh_memory();
        let total = sys.total_memory();
        if total > 0 {
            return total / (1024 * 1024);
        }
    }

    0
}

/// Detect if running inside a container.
fn detect_container() -> bool {
    detect_container_runtime().is_some() || kubernetes_service_account_exists()
}

fn detect_container_runtime() -> Option<String> {
    if std::path::Path::new("/.dockerenv").exists() {
        return Some("docker".into());
    }

    if let Ok(content) = std::fs::read_to_string("/proc/1/cgroup") {
        if content.contains("docker") {
            return Some("docker".into());
        }
        if content.contains("containerd") || content.contains("kubepods") {
            return Some("containerd".into());
        }
    }

    if kubernetes_service_account_exists() {
        return Some("containerd".into());
    }

    None
}

fn kubernetes_service_account_exists() -> bool {
    std::path::Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists()
        || std::path::Path::new("/var/run/secrets/kubernetes.io").exists()
}

fn runtime_context_from_parts<F>(
    in_container: bool,
    container_runtime: Option<String>,
    in_kubernetes: bool,
    env_var: F,
) -> RuntimeContext
where
    F: Fn(&str) -> Option<String>,
{
    RuntimeContext {
        in_container,
        container_runtime,
        deployment_type: if in_kubernetes {
            "kubernetes".into()
        } else if in_container {
            "container".into()
        } else {
            "host".into()
        },
        namespace: env_var("POD_NAMESPACE"),
        deployment: env_var("DEPLOYMENT_NAME"),
        pod_name: env_var("POD_NAME"),
        node_name: env_var("NODE_NAME"),
        container: env_var("CONTAINER_NAME"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_succeeds() {
        let metadata = collect();
        assert!(!metadata.hostname.is_empty());
        assert!(!metadata.os.is_empty());
        assert!(!metadata.architecture.is_empty());
        assert!(metadata.cpu_cores > 0);
    }

    #[test]
    fn runtime_context_defaults_to_host() {
        let context = runtime_context_from_parts(false, None, false, |_| None);

        assert!(!context.in_container);
        assert_eq!(context.deployment_type, "host");
        assert_eq!(context.container_runtime, None);
        assert_eq!(context.namespace, None);
    }

    #[test]
    fn runtime_context_includes_kubernetes_fields() {
        let context =
            runtime_context_from_parts(true, Some("containerd".into()), true, |key| match key {
                "KUBERNETES_SERVICE_HOST" => Some("10.0.0.1".into()),
                "POD_NAMESPACE" => Some("observability".into()),
                "DEPLOYMENT_NAME" => Some("edgepacer".into()),
                "POD_NAME" => Some("edgepacer-abc".into()),
                "NODE_NAME" => Some("node-1".into()),
                "CONTAINER_NAME" => Some("agent".into()),
                _ => None,
            });

        assert!(context.in_container);
        assert_eq!(context.container_runtime.as_deref(), Some("containerd"));
        assert_eq!(context.deployment_type, "kubernetes");
        assert_eq!(context.namespace.as_deref(), Some("observability"));
        assert_eq!(context.deployment.as_deref(), Some("edgepacer"));
        assert_eq!(context.pod_name.as_deref(), Some("edgepacer-abc"));
        assert_eq!(context.node_name.as_deref(), Some("node-1"));
        assert_eq!(context.container.as_deref(), Some("agent"));
    }

    #[test]
    fn runtime_context_stays_host_when_kubernetes_probe_is_false() {
        let context = runtime_context_from_parts(false, None, false, |_| None);

        assert_eq!(context.deployment_type, "host");
        assert_eq!(context.namespace, None);
    }
}
