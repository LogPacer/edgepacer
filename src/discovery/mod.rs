//! System discovery — enumerates containers, log files, services, and ports.
//!
//! Mirrors Go edgepacer's `internal/discovery/` package.
//! Each backend runs in parallel; failures are best-effort (recorded in Census.errors).

use std::sync::Arc;
use tokio::sync::RwLock;

pub mod cache;
pub mod cri;
pub mod docker;
pub mod event_log;
pub mod files;
pub mod kubernetes;
pub mod packages;
pub mod ports;
pub mod processes;
pub mod systemd;
// Retained for a future service→Event-Log-provider mapping; no longer feeds the
// discovery census (Windows services are not log sources — Event Log channels are).
#[allow(dead_code)]
pub mod windows_services;

use serde::Serialize;
use std::collections::HashMap;
use tracing::{debug, warn};

pub use cache::DiscoveryCache;

/// Thread-safe discovery cache shared between agent and orchestrator.
pub type SharedDiscoveryCache = Arc<RwLock<DiscoveryCache>>;

pub fn shared_discovery_cache() -> SharedDiscoveryCache {
    Arc::new(RwLock::new(DiscoveryCache::new()))
}

/// Census — the output of a discovery scan.
/// Contains everything found on the system, categorized by type.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Census {
    pub os: String,
    pub architecture: String,
    pub containers: Vec<Container>,
    pub log_files: Vec<LogFile>,
    pub systemd_services: Vec<SystemdService>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub event_log_channels: Vec<EventLogChannel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<processes::Process>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listening_ports: Vec<ports::ListeningPort>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub installed_packages: Vec<packages::Package>,
    pub errors: HashMap<String, String>,
    pub collected_at: String,
}

/// A discovered container (Docker, K8s, containerd).
#[derive(Debug, Clone, Serialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub service_name: String,
    /// True only when service_name came from an explicit LogPacer opt-in:
    /// literal LOGPACER_SERVICE_NAME env, CRI label, or Kubernetes pod metadata.
    /// Compose labels and workload-name fallbacks fill service_name too, but
    /// are not consent.
    pub service_name_explicit: bool,
    pub image: String,
    pub state: String,
    pub labels: HashMap<String, String>,
    pub env: Vec<String>,
    pub runtime: String,
    pub log_path: String,
    // K8s fields (empty when not K8s)
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
    pub deployment: String,
    /// K8s workload owner kind ("statefulset"/"daemonset"/"deployment"/"job"/
    /// "cronjob"/"replicaset"/"unknown"), empty for non-K8s. Drives per-instance
    /// identity: a StatefulSet pod has a stable ordinal, a DaemonSet pod is
    /// pinned to a node, a Deployment pod is fungible.
    pub workload_kind: String,
    pub container_id: String,
    /// K8s container name from pod spec (empty for non-K8s).
    pub container_name: String,
}

impl Container {
    /// Stable identifier for change tracking — matches Go's Container.ComputeStableIdentifier().
    ///
    /// The identity must survive restarts/rescheduling:
    /// - K8s: namespace/deployment/container_name (survives pod restarts)
    /// - Compose: project/service
    /// - Swarm: stack/service
    /// - Kamal: service-destination (role-agnostic; web + rpc share one workload)
    /// - Standalone Docker: container name
    pub fn stable_id(&self) -> String {
        // Kubernetes: namespace/deployment/container_name (spec name, not pod-prefixed)
        if !self.namespace.is_empty() && !self.deployment.is_empty() {
            let cn = if !self.container_name.is_empty() {
                self.container_name.as_str()
            } else {
                self.name.as_str()
            };
            return format!("{}/{}/{}", self.namespace, self.deployment, cn);
        }

        // Docker Compose: project/service
        if let (Some(project), Some(service)) = (
            self.labels.get("com.docker.compose.project"),
            self.labels.get("com.docker.compose.service"),
        ) {
            return format!("{}/{}", project, service);
        }
        if let Some(service) = self.labels.get("com.docker.compose.service") {
            return service.clone();
        }

        // Docker Swarm: stack/service
        if let (Some(stack), Some(service)) = (
            self.labels.get("com.docker.stack.namespace"),
            self.labels.get("com.docker.swarm.service.name"),
        ) {
            return format!("{}/{}", stack, service);
        }
        if let Some(service) = self.labels.get("com.docker.swarm.service.name") {
            return service.clone();
        }

        // Kamal: service-destination. Kamal always sets `service` + `destination`,
        // and the identity is role-agnostic so web + rpc collapse to one workload.
        // The container name embeds the deploy git SHA, so it can't be the id.
        if let (Some(service), Some(destination)) =
            (self.labels.get("service"), self.labels.get("destination"))
        {
            return format!("{}-{}", service, destination);
        }

        // Standalone Docker / other: container name
        self.name.clone()
    }

    /// Stable identity at instance/replica granularity. Where `stable_id` names
    /// the *workload*, this names the *instance* — and it must survive a
    /// redeploy, so a new container id / pod uid never crosses the wire as
    /// identity. EdgePacer is the source of truth for the runtime, so it
    /// computes this; Rails keys instance tracking and per-instance collect
    /// directives on it.
    ///
    /// The K8s forms extend the workload `stable_id` (which already carries the
    /// container/spec name) with a replica discriminator, so sidecar containers
    /// sharing a pod never collide on one id:
    /// - K8s StatefulSet: `stable_id/<ordinal>` (ordinal from the stable pod name `<workload>-<N>`)
    /// - K8s DaemonSet: `stable_id/<node_name>` (one pod pinned per node)
    /// - K8s Deployment/Job/CronJob/other: pods are fungible — no stable per-pod
    ///   identity, so this is just the workload `stable_id`
    /// - Docker Compose: `project/service/<ordinal>` (compose container-number,
    ///   else parsed from the container name `project-service-N`)
    /// - Docker Swarm: `stack/service/<slot>` (slot from the swarm task name
    ///   `service.slot.taskid`)
    /// - Kamal: `service-role-destination` — stable across deploys (the container
    ///   name embeds the git SHA); falls back to `service-destination` without a role
    /// - Standalone Docker / other: the container name (a single instance)
    pub fn stable_instance_id(&self) -> String {
        // Kubernetes. The per-instance id extends stable_id (namespace/workload/
        // container_name) with the replica discriminator, so two containers in
        // the same pod (e.g. a sidecar) never share one stable_instance_id.
        if !self.namespace.is_empty() && !self.deployment.is_empty() {
            return match self.workload_kind.as_str() {
                "statefulset" => match pod_ordinal(&self.pod_name, &self.deployment) {
                    Some(ordinal) => format!("{}/{}", self.stable_id(), ordinal),
                    None => self.stable_id(),
                },
                "daemonset" if !self.node_name.is_empty() => {
                    format!("{}/{}", self.stable_id(), self.node_name)
                }
                // Deployment, Job, CronJob, bare pods, daemonset-without-node:
                // the pod is fungible, so the workload identity is all that's stable.
                _ => self.stable_id(),
            };
        }

        // Docker Compose: project/service/<ordinal>
        if let (Some(project), Some(service)) = (
            self.labels.get("com.docker.compose.project"),
            self.labels.get("com.docker.compose.service"),
        ) {
            if let Some(ordinal) = self
                .labels
                .get("com.docker.compose.container-number")
                .filter(|n| is_numeric(n))
                .cloned()
                .or_else(|| compose_ordinal(&self.name, project, service))
            {
                return format!("{}/{}/{}", project, service, ordinal);
            }
            return format!("{}/{}", project, service);
        }

        // Docker Swarm: stack/service/<slot>
        if let Some(service) = self.labels.get("com.docker.swarm.service.name") {
            let stack = self.labels.get("com.docker.stack.namespace");
            if let Some(slot) = self
                .labels
                .get("com.docker.swarm.task.name")
                .and_then(|task| swarm_slot(task))
            {
                return match stack {
                    Some(stack) => format!("{}/{}/{}", stack, service, slot),
                    None => format!("{}/{}", service, slot),
                };
            }
            return match stack {
                Some(stack) => format!("{}/{}", stack, service),
                None => service.clone(),
            };
        }

        // Kamal: service-role-destination — a per-role instance that survives a
        // redeploy, since the container name embeds the deploy git SHA. `service`
        // + `destination` are always set; `role` separates web from rpc, and when
        // it's absent the instance collapses to the `service-destination` workload.
        if let (Some(service), Some(destination)) =
            (self.labels.get("service"), self.labels.get("destination"))
        {
            return match self.labels.get("role") {
                Some(role) => format!("{}-{}-{}", service, role, destination),
                None => format!("{}-{}", service, destination),
            };
        }

        // Standalone Docker / other: the container name is the single instance.
        self.name.clone()
    }

    /// Whether this container has a LOGPACER_SERVICE_NAME (makes it a "collecting service").
    pub fn has_service_name(&self) -> bool {
        !self.service_name.is_empty()
    }

    /// Whether this container explicitly opted into collection via a LogPacer
    /// service-name gate. Only these take the services census lane;
    /// everything else is server-sourced inventory for the screener.
    pub fn explicit_service(&self) -> bool {
        self.service_name_explicit && self.has_service_name()
    }

    /// Access method for log collection — EdgePacer Knows Best.
    pub fn determine_access_method(&self) -> cache::AccessMethod {
        match self.runtime.as_str() {
            "kubernetes" => cache::AccessMethod::Kubernetes,
            "docker" => {
                if locally_readable_log_path(&self.log_path) {
                    cache::AccessMethod::File
                } else {
                    cache::AccessMethod::DockerApi
                }
            }
            "containerd" | "cri-o" | "podman" => cache::AccessMethod::File,
            _ => {
                if !self.log_path.is_empty() {
                    cache::AccessMethod::File
                } else {
                    cache::AccessMethod::DockerApi
                }
            }
        }
    }

    /// Concrete locator for the resolved access method.
    pub fn log_locator(&self) -> String {
        match self.determine_access_method() {
            cache::AccessMethod::Kubernetes | cache::AccessMethod::File => self.log_path.clone(),
            cache::AccessMethod::DockerApi => {
                if self.container_id.is_empty() {
                    self.name.clone()
                } else {
                    self.container_id.clone()
                }
            }
            cache::AccessMethod::Journald => String::new(),
            // A container never resolves to the Windows Event Log access method
            // (determine_access_method only yields File/DockerApi/Journald/
            // Kubernetes); this arm just keeps the match exhaustive.
            cache::AccessMethod::WindowsEventLog => String::new(),
        }
    }
}

fn locally_readable_log_path(path: &str) -> bool {
    !path.is_empty() && std::path::Path::new(path).is_file()
}

/// Non-empty and all ASCII digits — a usable replica ordinal/slot.
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Ordinal of a StatefulSet pod: `pod_ordinal("postgres-0", "postgres") == Some("0")`.
/// StatefulSet pod names are `<workload>-<ordinal>` and survive restarts.
fn pod_ordinal(pod_name: &str, workload: &str) -> Option<String> {
    let ordinal = pod_name.strip_prefix(workload)?.strip_prefix('-')?;
    is_numeric(ordinal).then(|| ordinal.to_string())
}

/// Ordinal of a Compose replica from its container name. Compose v2 uses
/// hyphens (`shop-web-2`), v1 used underscores (`shop_web_2`); try both.
fn compose_ordinal(name: &str, project: &str, service: &str) -> Option<String> {
    let ordinal = name
        .strip_prefix(&format!("{project}-{service}-"))
        .or_else(|| name.strip_prefix(&format!("{project}_{service}_")))?;
    is_numeric(ordinal).then(|| ordinal.to_string())
}

/// Slot of a Swarm task from `com.docker.swarm.task.name` = `service.slot.taskid`:
/// `swarm_slot("web.2.abc123") == Some("2")`.
fn swarm_slot(task_name: &str) -> Option<String> {
    let slot = task_name.split('.').nth(1)?;
    is_numeric(slot).then(|| slot.to_string())
}

/// A discovered log file.
#[derive(Debug, Clone, Serialize)]
pub struct LogFile {
    pub path: String,
    pub size: u64,
    pub modified: String,
    pub readable: bool,
    pub permissions: String,
    pub format: String, // "ndjson" or "plain_text"
    /// Approximate line count (for Rails decision-making on sampling priority).
    pub line_count: u64,
}

impl LogFile {
    /// Identity for change tracking — the file path.
    pub fn identifier(&self) -> &str {
        &self.path
    }
}

/// A discovered systemd service (Linux only).
#[derive(Debug, Clone, Serialize)]
pub struct SystemdService {
    pub name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
    pub service_name: String,
    pub main_pid: u32,
}

impl SystemdService {
    pub fn identifier(&self) -> &str {
        &self.name
    }
}

/// A discovered Windows Event Log channel (Windows only). Curated to the
/// records-bearing set so the review queue is not flooded with the ~1000
/// mostly-empty channels `wevtutil el` lists.
#[derive(Debug, Clone, Serialize)]
pub struct EventLogChannel {
    pub channel: String,
    /// Records observed at discovery — drives the records-bearing curation and
    /// is surfaced to Rails for the review queue.
    pub record_count: u64,
}

impl EventLogChannel {
    pub fn identifier(&self) -> &str {
        &self.channel
    }
}

/// Run a full discovery scan. Backends run in parallel; failures are best-effort.
pub async fn discover() -> Census {
    let mut census = Census {
        os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        collected_at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };

    // No config scan paths: fall back to OS-aware defaults and the default
    // `.log`-only extension allowlist.
    let scan_paths = files::default_scan_paths();

    // Run discovery backends in parallel
    let (
        docker_result,
        files_result,
        systemd_result,
        k8s_result,
        cri_result,
        processes_result,
        ports_result,
        packages_result,
        event_log_result,
    ) = tokio::join!(
        docker::discover_containers(),
        files::discover_log_files(scan_paths, files::DEFAULT_LOG_EXTENSIONS),
        systemd::discover_services(),
        kubernetes::discover_kubernetes_pods(),
        cri::discover_cri_containers(),
        processes::discover_processes(),
        ports::discover_ports(),
        packages::discover_packages(),
        event_log::discover_channels(),
    );

    match docker_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered containers");
            census.containers = containers;
        }
        Err(e) => {
            warn!(error = %e, "docker discovery failed");
            census.errors.insert("docker".into(), e.to_string());
        }
    }

    match k8s_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered kubernetes pods");
            census.containers.extend(containers);
        }
        Err(e) => {
            warn!(error = %e, "kubernetes discovery failed");
            census.errors.insert("kubernetes".into(), e.to_string());
        }
    }

    match cri_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered CRI containers");
            census.containers.extend(containers);
        }
        Err(e) => {
            warn!(error = %e, "CRI discovery failed");
            census.errors.insert("cri".into(), e.to_string());
        }
    }

    match files_result {
        Ok(files) => {
            debug!(count = files.len(), "discovered log files");
            census.log_files = files;
        }
        Err(e) => {
            warn!(error = %e, "file discovery failed");
            census.errors.insert("files".into(), e.to_string());
        }
    }

    match systemd_result {
        Ok(services) => {
            debug!(count = services.len(), "discovered systemd services");
            census.systemd_services = services;
        }
        Err(e) => {
            warn!(error = %e, "systemd discovery failed");
            census.errors.insert("systemd".into(), e.to_string());
        }
    }

    match event_log_result {
        Ok(channels) => {
            debug!(
                count = channels.len(),
                "discovered windows event log channels"
            );
            census.event_log_channels = channels;
        }
        Err(e) => {
            warn!(error = %e, "windows event log discovery failed");
            census
                .errors
                .insert("event_log_channels".into(), e.to_string());
        }
    }

    match processes_result {
        Ok(procs) => {
            debug!(count = procs.len(), "discovered processes");
            census.processes = procs;
        }
        Err(e) => {
            warn!(error = %e, "process discovery failed");
            census.errors.insert("processes".into(), e.to_string());
        }
    }

    match ports_result {
        Ok(ports) => {
            debug!(count = ports.len(), "discovered listening ports");
            census.listening_ports = ports;
        }
        Err(e) => {
            warn!(error = %e, "port discovery failed");
            census.errors.insert("ports".into(), e.to_string());
        }
    }

    match packages_result {
        Ok(pkgs) => {
            debug!(count = pkgs.len(), "discovered installed packages");
            census.installed_packages = pkgs;
        }
        Err(e) => {
            warn!(error = %e, "package discovery failed");
            census.errors.insert("packages".into(), e.to_string());
        }
    }

    census
}

/// Run discovery with custom scan paths and extension allowlist for log files.
pub async fn discover_with_paths(scan_paths: &[&str], log_extensions: &[&str]) -> Census {
    let mut census = Census {
        os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        collected_at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };

    let (
        docker_result,
        files_result,
        systemd_result,
        k8s_result,
        cri_result,
        processes_result,
        ports_result,
        packages_result,
        event_log_result,
    ) = tokio::join!(
        docker::discover_containers(),
        files::discover_log_files(scan_paths, log_extensions),
        systemd::discover_services(),
        kubernetes::discover_kubernetes_pods(),
        cri::discover_cri_containers(),
        processes::discover_processes(),
        ports::discover_ports(),
        packages::discover_packages(),
        event_log::discover_channels(),
    );

    match docker_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered containers");
            census.containers = containers;
        }
        Err(e) => {
            warn!(error = %e, "docker discovery failed");
            census.errors.insert("docker".into(), e.to_string());
        }
    }

    match k8s_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered kubernetes pods");
            census.containers.extend(containers);
        }
        Err(e) => {
            warn!(error = %e, "kubernetes discovery failed");
            census.errors.insert("kubernetes".into(), e.to_string());
        }
    }

    match cri_result {
        Ok(containers) => {
            debug!(count = containers.len(), "discovered CRI containers");
            census.containers.extend(containers);
        }
        Err(e) => {
            warn!(error = %e, "CRI discovery failed");
            census.errors.insert("cri".into(), e.to_string());
        }
    }

    match files_result {
        Ok(files) => {
            debug!(count = files.len(), "discovered log files");
            census.log_files = files;
        }
        Err(e) => {
            warn!(error = %e, "file discovery failed");
            census.errors.insert("files".into(), e.to_string());
        }
    }

    match systemd_result {
        Ok(services) => {
            debug!(count = services.len(), "discovered systemd services");
            census.systemd_services = services;
        }
        Err(e) => {
            warn!(error = %e, "systemd discovery failed");
            census.errors.insert("systemd".into(), e.to_string());
        }
    }

    match event_log_result {
        Ok(channels) => {
            debug!(
                count = channels.len(),
                "discovered windows event log channels"
            );
            census.event_log_channels = channels;
        }
        Err(e) => {
            warn!(error = %e, "windows event log discovery failed");
            census
                .errors
                .insert("event_log_channels".into(), e.to_string());
        }
    }

    match processes_result {
        Ok(procs) => {
            debug!(count = procs.len(), "discovered processes");
            census.processes = procs;
        }
        Err(e) => {
            warn!(error = %e, "process discovery failed");
            census.errors.insert("processes".into(), e.to_string());
        }
    }

    match ports_result {
        Ok(ports) => {
            debug!(count = ports.len(), "discovered listening ports");
            census.listening_ports = ports;
        }
        Err(e) => {
            warn!(error = %e, "port discovery failed");
            census.errors.insert("ports".into(), e.to_string());
        }
    }

    match packages_result {
        Ok(pkgs) => {
            debug!(count = pkgs.len(), "discovered installed packages");
            census.installed_packages = pkgs;
        }
        Err(e) => {
            warn!(error = %e, "package discovery failed");
            census.errors.insert("packages".into(), e.to_string());
        }
    }

    census
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_container(name: &str) -> Container {
        Container {
            id: "abc123".into(),
            name: name.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: "running".into(),
            labels: HashMap::new(),
            env: vec![],
            runtime: "docker".into(),
            log_path: String::new(),
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: "abc123".into(),
            container_name: String::new(),
        }
    }

    #[test]
    fn stable_id_standalone_docker() {
        let c = make_container("my-nginx");
        assert_eq!(c.stable_id(), "my-nginx");
    }

    #[test]
    fn explicit_service_requires_the_env_var_flag() {
        // Plain docker: service_name fallback = container name, NOT explicit
        let mut c = make_container("web");
        c.service_name = "web".into();
        assert!(c.has_service_name());
        assert!(
            !c.explicit_service(),
            "inferred service names are not consent — only LOGPACER_SERVICE_NAME is"
        );

        c.service_name_explicit = true;
        assert!(c.explicit_service());

        // Flag without a name is meaningless
        c.service_name = String::new();
        assert!(!c.explicit_service());
    }

    #[test]
    fn stable_id_compose() {
        let mut c = make_container("myapp-web-1");
        c.labels
            .insert("com.docker.compose.project".into(), "myapp".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_id(), "myapp/web");
    }

    #[test]
    fn stable_id_swarm() {
        let mut c = make_container("web.1.abc");
        c.labels
            .insert("com.docker.stack.namespace".into(), "production".into());
        c.labels
            .insert("com.docker.swarm.service.name".into(), "web".into());
        assert_eq!(c.stable_id(), "production/web");
    }

    #[test]
    fn stable_id_kubernetes() {
        let mut c = make_container("nginx");
        c.namespace = "default".into();
        c.deployment = "nginx".into();
        assert_eq!(c.stable_id(), "default/nginx/nginx");
    }

    #[test]
    fn stable_id_k8s_takes_priority_over_compose_labels() {
        let mut c = make_container("nginx");
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        // K8s should win
        assert_eq!(c.stable_id(), "prod/api/nginx");
    }

    #[test]
    fn stable_instance_id_standalone_docker_is_the_name() {
        let c = make_container("my-nginx");
        assert_eq!(c.stable_instance_id(), "my-nginx");
    }

    #[test]
    fn stable_instance_id_compose_appends_container_number_label() {
        let mut c = make_container("shop-web-2");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        c.labels
            .insert("com.docker.compose.container-number".into(), "2".into());
        assert_eq!(c.stable_instance_id(), "shop/web/2");
        // Workload-level identity is unchanged — replicas share it.
        assert_eq!(c.stable_id(), "shop/web");
    }

    #[test]
    fn stable_instance_id_compose_parses_ordinal_from_name_without_label() {
        let mut c = make_container("shop-web-3");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_instance_id(), "shop/web/3");
    }

    #[test]
    fn stable_instance_id_compose_without_ordinal_falls_back_to_workload() {
        let mut c = make_container("weird-name");
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        assert_eq!(c.stable_instance_id(), "shop/web");
    }

    #[test]
    fn stable_instance_id_swarm_uses_task_slot() {
        let mut c = make_container("web.2.abc123xyz");
        c.labels
            .insert("com.docker.stack.namespace".into(), "production".into());
        c.labels
            .insert("com.docker.swarm.service.name".into(), "web".into());
        c.labels.insert(
            "com.docker.swarm.task.name".into(),
            "web.2.abc123xyz".into(),
        );
        assert_eq!(c.stable_instance_id(), "production/web/2");
    }

    #[test]
    fn stable_instance_id_statefulset_uses_pod_ordinal_per_container() {
        let mut db = make_container("postgres-0-db");
        db.runtime = "kubernetes".into();
        db.namespace = "default".into();
        db.deployment = "postgres".into();
        db.workload_kind = "statefulset".into();
        db.container_name = "db".into();
        db.pod_name = "postgres-0".into();
        assert_eq!(db.stable_instance_id(), "default/postgres/db/0");

        // A sidecar in the SAME pod (same ordinal) must get a DISTINCT id, or
        // both would collide on one key on the wire and in the cache.
        let mut metrics = db.clone();
        metrics.container_name = "metrics".into();
        metrics.name = "postgres-0-metrics".into();
        assert_eq!(metrics.stable_instance_id(), "default/postgres/metrics/0");
        assert_ne!(db.stable_instance_id(), metrics.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_daemonset_uses_node_name() {
        let mut c = make_container("fluentbit-abc");
        c.runtime = "kubernetes".into();
        c.namespace = "logging".into();
        c.deployment = "fluentbit".into();
        c.workload_kind = "daemonset".into();
        c.container_name = "agent".into();
        c.pod_name = "fluentbit-abc".into();
        c.node_name = "node-7".into();
        assert_eq!(c.stable_instance_id(), "logging/fluentbit/agent/node-7");
    }

    #[test]
    fn stable_instance_id_deployment_is_fungible_workload_identity() {
        // Deployment pods are fungible — no stable per-pod identity, so the
        // instance id collapses to the workload stable_id.
        let mut c = make_container("api-7b4f9c8d5-xyz");
        c.runtime = "kubernetes".into();
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.workload_kind = "deployment".into();
        c.container_name = "api".into();
        c.pod_name = "api-7b4f9c8d5-xyz".into();
        assert_eq!(c.stable_instance_id(), "prod/api/api");
        assert_eq!(c.stable_instance_id(), c.stable_id());
    }

    fn make_kamal_container(role: &str, name: &str) -> Container {
        let mut c = make_container(name);
        c.labels.insert("service".into(), "logpacer".into());
        c.labels.insert("role".into(), role.into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    #[test]
    fn stable_id_kamal_is_service_destination() {
        let c = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        assert_eq!(c.stable_id(), "logpacer-prod");
    }

    #[test]
    fn stable_instance_id_kamal_is_service_role_destination() {
        let c = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        assert_eq!(c.stable_instance_id(), "logpacer-web-prod");
    }

    #[test]
    fn stable_kamal_ids_survive_a_redeploy_to_a_new_sha() {
        // Same labels, new container name (the git SHA moved) — ids must not move.
        let before = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let after = make_kamal_container("web", "logpacer-web-prod-9f8e7d6");
        assert_eq!(before.stable_id(), after.stable_id());
        assert_eq!(before.stable_instance_id(), after.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_kamal_rpc_role() {
        let c = make_kamal_container("rpc", "logpacer-rpc-prod-1a2b3c4");
        assert_eq!(c.stable_instance_id(), "logpacer-rpc-prod");
    }

    #[test]
    fn kamal_web_and_rpc_share_workload_but_differ_per_role() {
        let web = make_kamal_container("web", "logpacer-web-prod-1a2b3c4");
        let rpc = make_kamal_container("rpc", "logpacer-rpc-prod-1a2b3c4");
        // Same workload — web + rpc collapse to one stable_id.
        assert_eq!(web.stable_id(), rpc.stable_id());
        // Distinct per-role instances.
        assert_ne!(web.stable_instance_id(), rpc.stable_instance_id());
    }

    #[test]
    fn stable_instance_id_kamal_without_role_falls_back_to_workload() {
        let mut c = make_kamal_container("web", "logpacer-prod-1a2b3c4");
        c.labels.remove("role");
        assert_eq!(c.stable_instance_id(), "logpacer-prod");
        assert_eq!(c.stable_instance_id(), c.stable_id());
    }
}
