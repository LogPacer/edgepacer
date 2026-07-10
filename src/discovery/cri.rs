//! CRI container discovery via crictl CLI.
//!
//! Discovers containers on nodes using containerd/CRI-O runtime.
//! Uses `crictl ps -a -o json` for structured output (better than Go's table parsing).
//! Falls back when Docker API is unavailable (typical on K8s nodes with containerd).

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use futures_util::{StreamExt, stream};
use serde::Deserialize;
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
use serde_json::Value;
use std::collections::HashMap;
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
use std::collections::HashSet;
use std::path::Path;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::time::Duration;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use tracing::warn;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use super::RuntimeProcessIdentity;

const CRI_SOCKET_PATHS: &[&str] = &[
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/cri-dockerd.sock",
];
#[cfg(all(target_os = "linux", feature = "ebpf"))]
const CRI_INSPECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(target_os = "linux", feature = "ebpf"))]
const CRI_INSPECT_FALLBACK_CONCURRENCY: usize = 8;

/// Check if a local Unix CRI runtime is available. Remote endpoints cannot
/// safely supply host PIDs for `/proc`-backed identity, so every invocation is
/// pinned to the exact socket selected here.
pub fn is_cri_available() -> bool {
    local_cri_endpoint().is_some()
}

fn local_cri_endpoint() -> Option<String> {
    let configured = std::env::var("CONTAINER_RUNTIME_ENDPOINT").ok();
    resolve_local_cri_endpoint(configured.as_deref(), is_local_unix_socket)
}

fn resolve_local_cri_endpoint(
    configured: Option<&str>,
    is_socket: impl Fn(&Path) -> bool,
) -> Option<String> {
    if let Some(endpoint) = configured {
        let endpoint = endpoint.trim();
        let path = endpoint
            .strip_prefix("unix://")
            .or_else(|| endpoint.starts_with('/').then_some(endpoint))?;
        let path = Path::new(path);
        return (path.is_absolute() && is_socket(path))
            .then(|| format!("unix://{}", path.display()));
    }

    CRI_SOCKET_PATHS
        .iter()
        .map(Path::new)
        .find(|path| is_socket(path))
        .map(|path| format!("unix://{}", path.display()))
}

#[cfg(unix)]
fn is_local_unix_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(not(unix))]
fn is_local_unix_socket(_path: &Path) -> bool {
    false
}

fn crictl_command(endpoint: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("crictl");
    command.arg("--runtime-endpoint").arg(endpoint);
    command
}

/// Discover containers via `crictl ps -a -o json`.
///
/// Returns `Ok(vec![])` when no CRI runtime is detected — normal for Docker-only hosts.
pub async fn discover_cri_containers() -> Result<Vec<crate::discovery::Container>, String> {
    discover_cri_containers_with_runtime_processes(false).await
}

pub(crate) async fn discover_cri_containers_with_runtime_processes(
    include_runtime_processes: bool,
) -> Result<Vec<crate::discovery::Container>, String> {
    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    let _ = include_runtime_processes;

    let Some(endpoint) = local_cri_endpoint() else {
        return Ok(vec![]);
    };

    let output = match crictl_command(&endpoint)
        .args(["ps", "-a", "-o", "json"])
        .output()
        .await
    {
        Ok(output) => output,
        // Docker's embedded containerd exposes /run/containerd/containerd.sock
        // on every Docker host, but without crictl installed there is no CRI
        // runtime to speak to. That's CRI-absent (like the k8s lane), not a
        // failed backend — a "cri" census error fail-closes the eBPF ownership
        // gate for the whole host.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("crictl not available: {e}")),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("crictl failed: {stderr}"));
    }

    let crictl_output: CrictlOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse crictl output: {e}"))?;

    let raw_containers = crictl_output.containers.unwrap_or_default();
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    let runtime_processes = if include_runtime_processes {
        let running_ids: Vec<String> = raw_containers
            .iter()
            .filter(|container| {
                container
                    .state
                    .as_deref()
                    .is_some_and(|state| map_cri_state(state) == "running")
            })
            .filter_map(|container| container.id.clone().filter(|id| !id.is_empty()))
            .collect();
        match inspect_running_container_processes(&endpoint, &running_ids).await {
            Ok(processes) => processes,
            Err(error) => {
                warn!(%error, "failed to inspect running CRI container processes");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    let sandboxes = discover_pod_sandboxes(&endpoint).await.unwrap_or_default();
    let sandbox_map: HashMap<String, PodSandboxInfo> =
        sandboxes.into_iter().map(|s| (s.id.clone(), s)).collect();

    let containers = raw_containers
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
            let state = map_cri_state(&c.state.unwrap_or_default());
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            let runtime_process = (state == "running")
                .then(|| runtime_processes.get(&id).copied())
                .flatten();
            #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
            let runtime_process = None;
            let log_format = super::files::detect_container_log_format("containerd", &labels, "");

            crate::discovery::Container {
                id: id.clone(),
                name: name.clone(),
                service_name,
                service_name_explicit,
                image: c.image_ref.unwrap_or_default(),
                state,
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
                runtime_process,
            }
        })
        .collect();

    Ok(containers)
}

/// Fetch verbose status for all currently-running containers. Modern crictl
/// supports one multi-ID process; older releases and races with exited IDs are
/// recovered by bounded per-ID inspection so one failure cannot erase every
/// healthy runtime identity.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn inspect_running_container_processes(
    endpoint: &str,
    container_ids: &[String],
) -> Result<HashMap<String, RuntimeProcessIdentity>, String> {
    if container_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let batch = inspect_cri_pids(endpoint, container_ids).await;
    let mut pids = batch.as_ref().cloned().unwrap_or_default();
    let missing_ids: Vec<String> = container_ids
        .iter()
        .filter(|id| !pids.contains_key(id.as_str()))
        .cloned()
        .collect();

    let fallback_results = stream::iter(missing_ids.into_iter().map(|id| async move {
        let result = inspect_cri_pids(endpoint, std::slice::from_ref(&id)).await;
        (id, result)
    }))
    .buffer_unordered(CRI_INSPECT_FALLBACK_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut fallback_failures = 0usize;
    for (id, result) in fallback_results {
        match result {
            Ok(mut inspected) => {
                if let Some(pid) = inspected.remove(&id) {
                    pids.insert(id, pid);
                }
            }
            Err(_) => fallback_failures += 1,
        }
    }

    let processes: HashMap<String, RuntimeProcessIdentity> = pids
        .into_iter()
        .filter_map(|(id, pid)| RuntimeProcessIdentity::capture(pid).map(|identity| (id, identity)))
        .collect();

    if fallback_failures == container_ids.len() && processes.is_empty() {
        return Err(batch.err().unwrap_or_else(|| {
            format!("crictl inspect failed for all {fallback_failures} container IDs")
        }));
    }

    if fallback_failures != 0 {
        warn!(
            failed = fallback_failures,
            total = container_ids.len(),
            "some running CRI containers could not be inspected"
        );
    }

    Ok(processes)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn inspect_cri_pids(
    endpoint: &str,
    container_ids: &[String],
) -> Result<HashMap<String, u32>, String> {
    let mut command = crictl_command(endpoint);
    command
        .args(["inspect", "-o", "json"])
        .args(container_ids)
        .kill_on_drop(true);
    let output = tokio::time::timeout(CRI_INSPECT_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("crictl inspect timed out after {CRI_INSPECT_TIMEOUT:?}"))?
        .map_err(|e| format!("crictl inspect failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("crictl inspect failed: {stderr}"));
    }

    parse_cri_init_pids(&output.stdout)
        .map_err(|e| format!("failed to parse crictl inspect output: {e}"))
}

#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
fn parse_cri_init_pids(output: &[u8]) -> serde_json::Result<HashMap<String, u32>> {
    let mut records = Vec::new();
    for root in serde_json::Deserializer::from_slice(output).into_iter::<Value>() {
        match root? {
            Value::Array(values) => records.extend(values),
            value @ Value::Object(_) => records.push(value),
            _ => {}
        }
    }

    let mut pids = HashMap::new();
    let mut ambiguous_ids = HashSet::new();

    for record in &records {
        let Some(id) = record
            .pointer("/status/id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let Some(state) = record.pointer("/status/state").and_then(Value::as_str) else {
            continue;
        };
        if map_cri_state(state) != "running" {
            continue;
        }
        let Some(pid) = init_pid_from_inspect_record(record) else {
            continue;
        };

        if ambiguous_ids.contains(id) {
            continue;
        }
        if pids.get(id).is_some_and(|existing| *existing != pid) {
            pids.remove(id);
            ambiguous_ids.insert(id.to_string());
            continue;
        }

        pids.insert(id.to_string(), pid);
    }

    Ok(pids)
}

#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
fn init_pid_from_inspect_record(record: &Value) -> Option<u32> {
    let values = [record.pointer("/info/pid"), record.get("pid")];
    let mut pid = None;

    for value in values
        .into_iter()
        .flatten()
        .filter(|value| !value.is_null())
    {
        let candidate = parse_pid_value(value)?;
        if pid.is_some_and(|existing| existing != candidate) {
            return None;
        }
        pid = Some(candidate);
    }

    pid
}

#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
fn parse_pid_value(value: &Value) -> Option<u32> {
    match value {
        Value::Number(number) => u32::try_from(number.as_u64()?).ok(),
        Value::String(pid) => pid.trim().parse::<u32>().ok(),
        _ => None,
    }
    .filter(|pid| *pid != 0)
}

/// Discover pod sandboxes for metadata enrichment.
async fn discover_pod_sandboxes(endpoint: &str) -> Result<Vec<PodSandboxInfo>, String> {
    let output = crictl_command(endpoint)
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
    fn configured_local_endpoint_is_pinned_and_remote_configuration_never_falls_back() {
        let is_socket = |path: &Path| {
            path == Path::new("/custom/runtime.sock") || path == Path::new(CRI_SOCKET_PATHS[0])
        };

        assert_eq!(
            resolve_local_cri_endpoint(Some("unix:///custom/runtime.sock"), is_socket).as_deref(),
            Some("unix:///custom/runtime.sock")
        );
        for endpoint in [
            "tcp://runtime.example:1234",
            "npipe:////./pipe/containerd",
            "relative/runtime.sock",
            "unix:///missing/runtime.sock",
        ] {
            assert_eq!(
                resolve_local_cri_endpoint(Some(endpoint), is_socket),
                None,
                "configured endpoint {endpoint:?} must not fall back"
            );
        }
    }

    #[test]
    fn default_endpoint_selection_is_deterministic() {
        let selected = Path::new(CRI_SOCKET_PATHS[1]);
        assert_eq!(
            resolve_local_cri_endpoint(None, |path| path == selected).as_deref(),
            Some("unix:///run/crio/crio.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_requires_an_actual_unix_socket() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("runtime.sock");
        let file_path = dir.path().join("regular-file");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::write(&file_path, b"not a socket").unwrap();

        assert!(is_local_unix_socket(&socket_path));
        assert!(!is_local_unix_socket(&file_path));
        assert!(!is_local_unix_socket(&dir.path().join("missing")));
    }

    #[test]
    fn crictl_runtime_endpoint_flag_precedes_the_subcommand() {
        let mut command = crictl_command("unix:///run/containerd/containerd.sock");
        command.args(["inspect", "-o", "json", "container-id"]);
        let args: Vec<_> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            args,
            [
                "--runtime-endpoint",
                "unix:///run/containerd/containerd.sock",
                "inspect",
                "-o",
                "json",
                "container-id"
            ]
        );
    }

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
    fn parses_standard_and_legacy_cri_init_pid_shapes() {
        let json = br#"[
            {
                "status": {"id": "containerd-id", "state": "CONTAINER_RUNNING"},
                "info": {"pid": 4102}
            },
            {
                "status": {"id": "crio-id", "state": "RUNNING"},
                "pid": " 5103 "
            }
        ]"#;

        let pids = parse_cri_init_pids(json).unwrap();

        assert_eq!(pids.get("containerd-id"), Some(&4102));
        assert_eq!(pids.get("crio-id"), Some(&5103));
    }

    #[test]
    fn parses_single_cri_inspect_record() {
        let json = br#"{
            "status": {"id": "only-id", "state": "CONTAINER_RUNNING"},
            "info": {"pid": "6123"}
        }"#;

        assert_eq!(
            parse_cri_init_pids(json).unwrap().get("only-id"),
            Some(&6123)
        );
    }

    #[test]
    fn parses_pre_v1_31_concatenated_cri_inspect_records() {
        let json = br#"
            {
                "status": {"id": "first-id", "state": "CONTAINER_RUNNING"},
                "info": {"pid": 7101}
            }
            {
                "status": {"id": "second-id", "state": "CONTAINER_RUNNING"},
                "info": {"pid": 7102}
            }
        "#;

        let pids = parse_cri_init_pids(json).unwrap();

        assert_eq!(pids.get("first-id"), Some(&7101));
        assert_eq!(pids.get("second-id"), Some(&7102));
    }

    #[test]
    fn one_conflicting_cri_record_does_not_erase_healthy_ids() {
        let json = br#"[
            {"status": {"id": "healthy", "state": "CONTAINER_RUNNING"}, "info": {"pid": 7201}},
            {"status": {"id": "conflict", "state": "CONTAINER_RUNNING"}, "info": {"pid": 7202}},
            {"status": {"id": "conflict", "state": "CONTAINER_RUNNING"}, "info": {"pid": 7203}}
        ]"#;

        let pids = parse_cri_init_pids(json).unwrap();

        assert_eq!(pids.get("healthy"), Some(&7201));
        assert!(!pids.contains_key("conflict"));
    }

    #[test]
    fn malformed_or_ambiguous_cri_pids_fail_closed() {
        let json = br#"[
            {"status": {"id": "zero", "state": "CONTAINER_RUNNING"}, "info": {"pid": 0}},
            {"status": {"id": "negative", "state": "CONTAINER_RUNNING"}, "info": {"pid": -1}},
            {"status": {"id": "fraction", "state": "CONTAINER_RUNNING"}, "info": {"pid": 12.5}},
            {"status": {"id": "text", "state": "CONTAINER_RUNNING"}, "info": {"pid": "twelve"}},
            {"status": {"id": "missing", "state": "CONTAINER_RUNNING"}, "info": {}},
            {"status": {"id": "exited", "state": "CONTAINER_EXITED"}, "info": {"pid": 99}},
            {
                "status": {"id": "conflicting-locations", "state": "CONTAINER_RUNNING"},
                "info": {"pid": 100},
                "pid": 101
            },
            {"status": {"id": "duplicate", "state": "CONTAINER_RUNNING"}, "info": {"pid": 200}},
            {"status": {"id": "duplicate", "state": "CONTAINER_RUNNING"}, "info": {"pid": 201}}
        ]"#;

        assert!(parse_cri_init_pids(json).unwrap().is_empty());
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
            .any(|p| is_local_unix_socket(Path::new(p)))
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
            .any(|p| is_local_unix_socket(Path::new(p)))
        {
            let result = discover_cri_containers().await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }
    }
}
