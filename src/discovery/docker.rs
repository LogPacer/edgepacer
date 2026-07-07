//! Docker container discovery via bollard.
//!
//! Mirrors Go edgepacer's Docker discovery surface:
//! 1. List all containers (running + stopped)
//! 2. Inspect running containers for log path, env vars
//! 3. Extract service name from labels (compose/swarm/k8s priority)
//! 4. Filter env vars to LOGPACER_ prefix

use super::Container;
use crate::rate_limiter::docker_limiter;
use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions};
use bollard::{API_DEFAULT_VERSION, Docker};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

const DOCKER_TIMEOUT_SECS: u64 = 120;
#[cfg(unix)]
const DEFAULT_UNIX_DOCKER_HOST: &str = "unix:///var/run/docker.sock";
#[cfg(unix)]
const DEFAULT_UNIX_DOCKER_SOCKET: &str = "/var/run/docker.sock";
#[cfg(windows)]
const DEFAULT_WINDOWS_DOCKER_HOST: &str = "npipe:////./pipe/docker_engine";

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerConnectionTarget {
    Environment(&'static str),
    Host(String),
}

#[derive(Debug, Deserialize)]
struct DockerCliConfig {
    #[serde(rename = "currentContext")]
    current_context: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DockerContextMeta {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Endpoints")]
    endpoints: HashMap<String, DockerContextEndpoint>,
}

#[derive(Debug, Deserialize)]
struct DockerContextEndpoint {
    #[serde(rename = "Host")]
    host: Option<String>,
}

/// Discover all Docker-compatible containers through the configured endpoint.
pub async fn discover_containers() -> anyhow::Result<Vec<Container>> {
    let Some(docker) = connect_docker()? else {
        debug!("docker discovery skipped: no Docker-compatible endpoint configured");
        return Ok(Vec::new());
    };

    // List all containers (running + stopped)
    let list_opts = ListContainersOptions {
        all: true,
        ..Default::default()
    };
    docker_limiter().wait().await;
    let raw_containers = docker.list_containers(Some(list_opts)).await?;

    let mut result = Vec::with_capacity(raw_containers.len());

    for raw in &raw_containers {
        let id = raw.id.as_deref().unwrap_or("");
        let short_id = if id.len() > 12 { &id[..12] } else { id };

        let names = raw.names.as_deref().unwrap_or(&[]);
        let raw_name = names.first().map_or(short_id, |s| s.as_str());
        let name = clean_name(raw_name);

        let image = raw.image.as_deref().unwrap_or("unknown").to_string();
        let state = raw
            .state
            .as_ref()
            .map_or_else(|| "unknown".to_string(), ToString::to_string);
        let labels = raw.labels.clone().unwrap_or_default();

        let label_service_name = extract_service_name(&labels, &name);

        // Inspect running containers for log path and env
        let (log_path, env) = if state == "running" {
            docker_limiter().wait().await;
            match docker
                .inspect_container(id, None::<InspectContainerOptions>)
                .await
            {
                Ok(detail) => {
                    let log_path = detail.log_path.clone().unwrap_or_default();
                    let resolved_log_path = if log_path.is_empty() {
                        format!("/var/lib/docker/containers/{}/{}-json.log", id, id)
                    } else {
                        log_path
                    };

                    let env = detail
                        .config
                        .as_ref()
                        .and_then(|c| c.env.as_ref())
                        .map(|e| filter_env(e))
                        .unwrap_or_default();

                    (resolved_log_path, env)
                }
                Err(e) => {
                    warn!(container = %name, error = %e, "failed to inspect container");
                    (String::new(), Vec::new())
                }
            }
        } else {
            (String::new(), Vec::new())
        };

        // Priority 1: the literal LOGPACER_SERVICE_NAME env var — the only
        // signal that counts as explicit opt-in. Labels/name fallbacks fill
        // service_name for display and grouping but are not consent.
        let env_service_name = explicit_service_name_from_env(&env);
        let service_name_explicit = env_service_name.is_some();
        let service_name = env_service_name.unwrap_or(label_service_name);
        let log_format = super::files::detect_container_log_format("docker", &labels, &log_path);

        debug!(name = %name, state = %state, service = %service_name, explicit = service_name_explicit, "discovered container");

        result.push(Container {
            id: short_id.to_string(),
            name,
            service_name,
            service_name_explicit,
            image,
            state,
            labels,
            env,
            runtime: "docker".to_string(),
            log_path,
            log_format,
            // K8s fields empty for plain Docker
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: id.to_string(),
            container_name: String::new(),
        });
    }

    Ok(result)
}

pub(crate) fn connect_docker() -> anyhow::Result<Option<Docker>> {
    let docker_host = std::env::var("DOCKER_HOST").ok();
    let container_host = std::env::var("CONTAINER_HOST").ok();
    let context_host = docker_config_dir().and_then(|dir| read_current_docker_context_host(&dir));
    let default_host = default_docker_host();
    let target = resolve_docker_connection_target(
        docker_host.as_deref(),
        container_host.as_deref(),
        context_host.as_deref(),
        default_host.as_deref(),
    );

    match target {
        Some(DockerConnectionTarget::Environment(var_name)) => Docker::connect_with_defaults()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("docker connect failed via {var_name}: {e}")),
        Some(DockerConnectionTarget::Host(host)) => connect_with_host(&host)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("docker connect failed via {host}: {e}")),
        None => Ok(None),
    }
}

fn connect_with_host(host: &str) -> anyhow::Result<Docker> {
    let host = host.trim();

    if host.starts_with("unix://") || host.starts_with("npipe://") || host.starts_with('/') {
        return Docker::connect_with_socket(host, DOCKER_TIMEOUT_SECS, API_DEFAULT_VERSION)
            .map_err(Into::into);
    }

    if host.starts_with("tcp://") || host.starts_with("http://") {
        return Docker::connect_with_http(host, DOCKER_TIMEOUT_SECS, API_DEFAULT_VERSION)
            .map_err(Into::into);
    }

    Err(anyhow::anyhow!("unsupported Docker host URI scheme"))
}

fn docker_config_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("DOCKER_CONFIG")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .map(|home| home.join(".docker"))
        })
}

fn read_current_docker_context_host(config_dir: &Path) -> Option<String> {
    let config_json = fs::read_to_string(config_dir.join("config.json")).ok()?;
    let current_context = parse_current_context(&config_json)?;

    if current_context == "default" {
        return None;
    }

    let contexts_dir = config_dir.join("contexts/meta");
    for entry in fs::read_dir(contexts_dir).ok()? {
        let meta_json = fs::read_to_string(entry.ok()?.path().join("meta.json")).ok()?;

        if let Some(host) = docker_context_host_from_meta(&meta_json, &current_context) {
            return Some(host);
        }
    }

    None
}

fn parse_current_context(config_json: &str) -> Option<String> {
    let config: DockerCliConfig = serde_json::from_str(config_json).ok()?;
    non_empty(config.current_context?)
}

fn docker_context_host_from_meta(meta_json: &str, context_name: &str) -> Option<String> {
    let meta: DockerContextMeta = serde_json::from_str(meta_json).ok()?;

    if meta.name != context_name {
        return None;
    }

    non_empty(meta.endpoints.get("docker")?.host.clone()?)
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_docker_connection_target(
    docker_host: Option<&str>,
    container_host: Option<&str>,
    context_host: Option<&str>,
    default_host: Option<&str>,
) -> Option<DockerConnectionTarget> {
    if docker_host.is_some_and(|host| !host.trim().is_empty()) {
        return Some(DockerConnectionTarget::Environment("DOCKER_HOST"));
    }

    if let Some(host) = container_host.and_then(non_empty_str) {
        return Some(DockerConnectionTarget::Host(host.to_string()));
    }

    if let Some(host) = context_host.and_then(non_empty_str) {
        return Some(DockerConnectionTarget::Host(host.to_string()));
    }

    default_host
        .and_then(non_empty_str)
        .map(str::to_string)
        .map(DockerConnectionTarget::Host)
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(unix)]
fn default_docker_host() -> Option<String> {
    Path::new(DEFAULT_UNIX_DOCKER_SOCKET)
        .exists()
        .then(|| DEFAULT_UNIX_DOCKER_HOST.to_string())
}

#[cfg(windows)]
fn default_docker_host() -> Option<String> {
    Some(DEFAULT_WINDOWS_DOCKER_HOST.to_string())
}

/// Extract service name from container labels (the non-explicit sources).
/// Priority matches Go edgepacer; the LOGPACER_SERVICE_NAME env var is
/// applied by the caller after inspect and overrides all of these:
/// 1. com.docker.compose.service
/// 2. com.docker.swarm.service.name
/// 3. io.kubernetes.container.name
/// 4. Fallback to container name
fn extract_service_name(labels: &HashMap<String, String>, fallback_name: &str) -> String {
    if let Some(name) = labels.get("com.docker.compose.service") {
        return name.clone();
    }
    if let Some(name) = labels.get("com.docker.swarm.service.name") {
        return name.clone();
    }
    if let Some(name) = labels.get("io.kubernetes.container.name") {
        return name.clone();
    }
    fallback_name.to_string()
}

/// Filter environment variables to LOGPACER_ prefix only (security: avoid leaking secrets).
fn filter_env(env: &[String]) -> Vec<String> {
    env.iter()
        .filter(|e| e.starts_with("LOGPACER_"))
        .cloned()
        .collect()
}

/// The explicit opt-in: a non-empty LOGPACER_SERVICE_NAME env var.
fn explicit_service_name_from_env(env: &[String]) -> Option<String> {
    env.iter()
        .find_map(|e| e.strip_prefix("LOGPACER_SERVICE_NAME="))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Clean container name (remove leading /).
fn clean_name(name: &str) -> String {
    name.strip_prefix('/').unwrap_or(name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const PLATFORM_DEFAULT_DOCKER_HOST: &str = DEFAULT_UNIX_DOCKER_HOST;
    #[cfg(windows)]
    const PLATFORM_DEFAULT_DOCKER_HOST: &str = DEFAULT_WINDOWS_DOCKER_HOST;

    #[test]
    fn service_name_priority() {
        let mut labels = HashMap::new();
        assert_eq!(extract_service_name(&labels, "fallback"), "fallback");

        labels.insert("io.kubernetes.container.name".into(), "k8s-name".into());
        assert_eq!(extract_service_name(&labels, "fallback"), "k8s-name");

        labels.insert("com.docker.swarm.service.name".into(), "swarm-name".into());
        assert_eq!(extract_service_name(&labels, "fallback"), "swarm-name");

        labels.insert("com.docker.compose.service".into(), "compose-name".into());
        assert_eq!(extract_service_name(&labels, "fallback"), "compose-name");
    }

    #[test]
    fn env_filtering() {
        let env = vec![
            "PATH=/usr/bin".into(),
            "LOGPACER_SERVICE_NAME=myapp".into(),
            "SECRET_KEY=abc123".into(),
            "LOGPACER_DEBUG=true".into(),
        ];
        let filtered = filter_env(&env);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"LOGPACER_SERVICE_NAME=myapp".to_string()));
        assert!(filtered.contains(&"LOGPACER_DEBUG=true".to_string()));
    }

    #[test]
    fn clean_container_name() {
        assert_eq!(clean_name("/mycontainer"), "mycontainer");
        assert_eq!(clean_name("noprefix"), "noprefix");
    }

    #[test]
    fn env_var_is_the_only_explicit_opt_in() {
        // Env var present → explicit, overrides labels
        let env = vec!["LOGPACER_SERVICE_NAME=api".to_string()];
        assert_eq!(explicit_service_name_from_env(&env).as_deref(), Some("api"));

        // Empty value is not an opt-in
        let empty = vec!["LOGPACER_SERVICE_NAME=".to_string()];
        assert_eq!(explicit_service_name_from_env(&empty), None);

        // Compose labels alone are not consent
        let no_env: Vec<String> = vec!["LOGPACER_DEBUG=true".to_string()];
        assert_eq!(explicit_service_name_from_env(&no_env), None);
    }

    #[test]
    fn docker_connection_prefers_docker_host_when_set() {
        let target = resolve_docker_connection_target(
            Some("unix:///tmp/docker.sock"),
            Some("unix:///tmp/podman.sock"),
            Some("unix:///tmp/context.sock"),
            Some(PLATFORM_DEFAULT_DOCKER_HOST),
        );

        assert_eq!(
            target,
            Some(DockerConnectionTarget::Environment("DOCKER_HOST"))
        );
    }

    #[test]
    fn docker_connection_uses_container_host_before_context() {
        let target = resolve_docker_connection_target(
            None,
            Some("unix:///tmp/podman.sock"),
            Some("unix:///tmp/context.sock"),
            Some(PLATFORM_DEFAULT_DOCKER_HOST),
        );

        assert_eq!(
            target,
            Some(DockerConnectionTarget::Host(
                "unix:///tmp/podman.sock".into()
            ))
        );
    }

    #[test]
    fn docker_connection_uses_docker_context_before_default() {
        let target = resolve_docker_connection_target(
            None,
            None,
            Some("unix:///tmp/context.sock"),
            Some(PLATFORM_DEFAULT_DOCKER_HOST),
        );

        assert_eq!(
            target,
            Some(DockerConnectionTarget::Host(
                "unix:///tmp/context.sock".into()
            ))
        );
    }

    #[test]
    fn docker_connection_returns_none_without_configured_endpoint() {
        let target = resolve_docker_connection_target(None, None, None, None);

        assert_eq!(target, None);
    }

    #[test]
    fn parses_current_docker_context_host() {
        let config = r#"{"currentContext":"colima"}"#;
        let meta = r#"{
            "Name": "colima",
            "Endpoints": {
                "docker": {
                    "Host": "unix:///Users/tester/.colima/default/docker.sock"
                }
            }
        }"#;

        assert_eq!(parse_current_context(config).as_deref(), Some("colima"));
        assert_eq!(
            docker_context_host_from_meta(meta, "colima").as_deref(),
            Some("unix:///Users/tester/.colima/default/docker.sock")
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable Docker-compatible daemon"]
    async fn live_docker_discovery_lists_containers() {
        let containers = discover_containers()
            .await
            .expect("live Docker discovery should succeed");

        assert!(
            !containers.is_empty(),
            "live Docker discovery should list at least one container"
        );
        assert!(
            containers
                .iter()
                .all(|container| container.runtime == "docker"),
            "live Docker discovery should tag discovered containers as docker runtime"
        );
        assert!(
            containers
                .iter()
                .any(|container| !container.id.is_empty() && !container.name.is_empty()),
            "live Docker discovery should populate stable container identity fields"
        );
    }
}
