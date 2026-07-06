//! CRI container discovery via crictl CLI.
//!
//! Discovers containers on nodes using containerd/CRI-O runtime.
//! Uses `crictl ps -a -o json` for structured output (better than Go's table parsing).
//! Falls back when Docker API is unavailable (typical on K8s nodes with containerd).

use serde::Deserialize;
use std::collections::HashMap;

const CRI_SOCKET_PATHS: &[&str] = &[
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/cri-dockerd.sock",
];

/// Check if a CRI runtime is available (socket exists or CONTAINER_RUNTIME_ENDPOINT is set).
pub fn is_cri_available() -> bool {
    if let Ok(endpoint) = std::env::var("CONTAINER_RUNTIME_ENDPOINT") {
        let path = endpoint.strip_prefix("unix://").unwrap_or(&endpoint);
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    CRI_SOCKET_PATHS
        .iter()
        .any(|p| std::path::Path::new(p).exists())
}

/// Discover containers via `crictl ps -a -o json`.
///
/// Returns `Ok(vec![])` when no CRI runtime is detected — normal for Docker-only hosts.
pub async fn discover_cri_containers() -> Result<Vec<crate::discovery::Container>, String> {
    if !is_cri_available() {
        return Ok(vec![]);
    }

    let output = tokio::process::Command::new("crictl")
        .args(["ps", "-a", "-o", "json"])
        .output()
        .await
        .map_err(|e| format!("crictl not available: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("crictl failed: {stderr}"));
    }

    let crictl_output: CrictlOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse crictl output: {e}"))?;

    let sandboxes = discover_pod_sandboxes().await.unwrap_or_default();
    let sandbox_map: HashMap<String, PodSandboxInfo> =
        sandboxes.into_iter().map(|s| (s.id.clone(), s)).collect();

    let containers = crictl_output
        .containers
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let sandbox = c
                .pod_sandbox_id
                .as_deref()
                .and_then(|id| sandbox_map.get(id));

            let (namespace, pod_name, pod_uid) = sandbox
                .map(|s| (s.namespace.clone(), s.pod_name.clone(), s.pod_uid.clone()))
                .unwrap_or_default();

            let name = c
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .unwrap_or_default();

            let labels = c.labels.unwrap_or_default();

            let explicit_service_name = labels.get("LOGPACER_SERVICE_NAME").cloned();
            let service_name_explicit = explicit_service_name
                .as_deref()
                .is_some_and(|v| !v.is_empty());
            let service_name = explicit_service_name
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| name.clone());

            let id = c.id.unwrap_or_default();
            let log_format = super::files::detect_container_log_format("containerd", &labels, "");

            crate::discovery::Container {
                id: id.clone(),
                name: name.clone(),
                service_name,
                service_name_explicit,
                image: c.image_ref.unwrap_or_default(),
                state: map_cri_state(&c.state.unwrap_or_default()),
                labels,
                env: vec![],
                runtime: "containerd".into(),
                log_path: String::new(),
                log_format,
                pod_uid,
                pod_name,
                namespace,
                node_name: String::new(),
                deployment: String::new(),
                workload_kind: String::new(),
                container_id: id,
                container_name: name.clone(),
            }
        })
        .collect();

    Ok(containers)
}

/// Discover pod sandboxes for metadata enrichment.
async fn discover_pod_sandboxes() -> Result<Vec<PodSandboxInfo>, String> {
    let output = tokio::process::Command::new("crictl")
        .args(["pods", "-o", "json"])
        .output()
        .await
        .map_err(|e| format!("crictl pods failed: {e}"))?;

    if !output.status.success() {
        return Err("crictl pods failed".into());
    }

    let parsed: CrictlPodsOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse crictl pods: {e}"))?;

    Ok(parsed
        .items
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            let metadata = s.metadata.unwrap_or_default();
            PodSandboxInfo {
                id: s.id.unwrap_or_default(),
                namespace: metadata.namespace.unwrap_or_default(),
                pod_name: metadata.name.unwrap_or_default(),
                pod_uid: metadata.uid.unwrap_or_default(),
            }
        })
        .collect())
}

fn map_cri_state(state: &str) -> String {
    match state.to_uppercase().as_str() {
        "CONTAINER_RUNNING" | "RUNNING" => "running".into(),
        "CONTAINER_EXITED" | "EXITED" => "exited".into(),
        "CONTAINER_CREATED" | "CREATED" => "created".into(),
        "CONTAINER_UNKNOWN" | "UNKNOWN" => "unknown".into(),
        _ => state.to_lowercase(),
    }
}

// --- Deserialization types for crictl JSON output ---

#[derive(Debug, Deserialize)]
struct CrictlOutput {
    containers: Option<Vec<CrictlContainer>>,
}

#[derive(Debug, Deserialize)]
struct CrictlContainer {
    id: Option<String>,
    #[serde(rename = "podSandboxId")]
    pod_sandbox_id: Option<String>,
    metadata: Option<CrictlContainerMetadata>,
    #[serde(rename = "imageRef")]
    image_ref: Option<String>,
    state: Option<String>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CrictlContainerMetadata {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrictlPodsOutput {
    items: Option<Vec<CrictlPodSandbox>>,
}

#[derive(Debug, Deserialize)]
struct CrictlPodSandbox {
    id: Option<String>,
    metadata: Option<CrictlPodMetadata>,
}

#[derive(Debug, Deserialize, Default)]
struct CrictlPodMetadata {
    namespace: Option<String>,
    name: Option<String>,
    uid: Option<String>,
}

struct PodSandboxInfo {
    id: String,
    namespace: String,
    pod_name: String,
    pod_uid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_cri_state() {
        assert_eq!(map_cri_state("CONTAINER_RUNNING"), "running");
        assert_eq!(map_cri_state("RUNNING"), "running");
        assert_eq!(map_cri_state("CONTAINER_EXITED"), "exited");
        assert_eq!(map_cri_state("EXITED"), "exited");
        assert_eq!(map_cri_state("CONTAINER_CREATED"), "created");
        assert_eq!(map_cri_state("CREATED"), "created");
        assert_eq!(map_cri_state("CONTAINER_UNKNOWN"), "unknown");
        assert_eq!(map_cri_state("UNKNOWN"), "unknown");
        assert_eq!(map_cri_state("SomethingElse"), "somethingelse");
    }

    #[test]
    fn test_parse_crictl_output() {
        let json = r#"{
            "containers": [
                {
                    "id": "abc123def456",
                    "podSandboxId": "pod-sandbox-1",
                    "metadata": {"name": "nginx"},
                    "imageRef": "docker.io/library/nginx:latest",
                    "state": "CONTAINER_RUNNING",
                    "labels": {"app": "web"}
                }
            ]
        }"#;

        let output: CrictlOutput = serde_json::from_str(json).unwrap();
        let containers = output.containers.unwrap();
        assert_eq!(containers.len(), 1);

        let c = &containers[0];
        assert_eq!(c.id.as_deref(), Some("abc123def456"));
        assert_eq!(c.pod_sandbox_id.as_deref(), Some("pod-sandbox-1"));
        assert_eq!(
            c.metadata.as_ref().and_then(|m| m.name.as_deref()),
            Some("nginx")
        );
        assert_eq!(
            c.image_ref.as_deref(),
            Some("docker.io/library/nginx:latest")
        );
        assert_eq!(c.state.as_deref(), Some("CONTAINER_RUNNING"));
        assert_eq!(
            c.labels
                .as_ref()
                .and_then(|l| l.get("app"))
                .map(|s| s.as_str()),
            Some("web")
        );
    }

    #[test]
    fn test_parse_crictl_pods_output() {
        let json = r#"{
            "items": [
                {
                    "id": "pod-sandbox-1",
                    "metadata": {
                        "name": "nginx-pod",
                        "namespace": "default",
                        "uid": "uid-123"
                    }
                }
            ]
        }"#;

        let output: CrictlPodsOutput = serde_json::from_str(json).unwrap();
        let items = output.items.unwrap();
        assert_eq!(items.len(), 1);

        let pod = &items[0];
        assert_eq!(pod.id.as_deref(), Some("pod-sandbox-1"));
        let metadata = pod.metadata.as_ref().unwrap();
        assert_eq!(metadata.name.as_deref(), Some("nginx-pod"));
        assert_eq!(metadata.namespace.as_deref(), Some("default"));
        assert_eq!(metadata.uid.as_deref(), Some("uid-123"));
    }

    #[test]
    fn test_not_available() {
        // On a dev machine without CRI sockets, is_cri_available should return false.
        // Clear env to ensure no stale CONTAINER_RUNTIME_ENDPOINT
        // SAFETY: test-only, single-threaded access to this env var.
        unsafe { std::env::remove_var("CONTAINER_RUNTIME_ENDPOINT") };
        // Unless running on a K8s node, no CRI socket should exist
        if !CRI_SOCKET_PATHS
            .iter()
            .any(|p| std::path::Path::new(p).exists())
        {
            assert!(!is_cri_available());
        }
    }

    #[tokio::test]
    async fn test_discover_returns_empty_when_unavailable() {
        // SAFETY: test-only, single-threaded access to this env var.
        unsafe { std::env::remove_var("CONTAINER_RUNTIME_ENDPOINT") };
        if !CRI_SOCKET_PATHS
            .iter()
            .any(|p| std::path::Path::new(p).exists())
        {
            let result = discover_cri_containers().await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }
    }
}
