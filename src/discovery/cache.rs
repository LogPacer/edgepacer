//! In-memory discovery cache for "EdgePacer Knows Best" access resolution.
//!
//! Populated after each discovery scan; used by the orchestrator to map Rails
//! collect directives (locator + matching_strategy) to concrete readers.

use std::collections::HashMap;

use super::{Census, Container, EventLogChannel, LogFile, SystemdService};

/// Resolved access method for a log source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessMethod {
    File,
    DockerJsonFile,
    DockerApi,
    Journald,
    Kubernetes,
    WindowsEventLog,
}

/// Confidence that the matched key is a *durable* source identity rather than
/// volatile evidence. A container id changes on every restart; a service name,
/// stable workload id, file path, or systemd unit survives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The logical service/workload identity the directive named — a
    /// `LOGPACER_SERVICE_NAME` service or the computed stable workload id.
    Explicit,
    /// A stable concrete key that survives restarts: file path, systemd unit,
    /// or container name.
    Strong,
    /// Volatile evidence only — a container id / id prefix. Valid right now,
    /// brittle as identity.
    Weak,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Explicit => "explicit",
            Confidence::Strong => "strong",
            Confidence::Weak => "weak",
        }
    }
}

/// Which identity key resolved a collect directive. `as_str` returns the
/// on-wire `matched_via` strings shared with Rails, so existing values stay
/// byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchVia {
    StableInstanceId,
    StableId,
    ServiceName,
    ContainerName,
    ContainerId,
    SystemdUnit,
    FilePath,
    WindowsEventLog,
}

impl MatchVia {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchVia::StableInstanceId => "stable_instance_id",
            MatchVia::StableId => "stable_id",
            MatchVia::ServiceName => "service_name",
            MatchVia::ContainerName => "container_name",
            MatchVia::ContainerId => "container_id",
            MatchVia::SystemdUnit => "systemd_unit",
            MatchVia::FilePath => "file_path",
            MatchVia::WindowsEventLog => "windows_event_log",
        }
    }

    /// How durable this key is as a source identity. Kept next to the variants
    /// so adding a new match key forces a confidence decision.
    pub fn confidence(self) -> Confidence {
        match self {
            MatchVia::StableInstanceId | MatchVia::StableId | MatchVia::ServiceName => {
                Confidence::Explicit
            }
            MatchVia::ContainerName
            | MatchVia::SystemdUnit
            | MatchVia::FilePath
            | MatchVia::WindowsEventLog => Confidence::Strong,
            MatchVia::ContainerId => Confidence::Weak,
        }
    }
}

/// Outcome of resolving one collect directive against discovered loggables.
///
/// EdgePacer is the source of truth for what is on the host, so resolution
/// reports not just "found/missing" but *how* the match was made — letting
/// Rails and EdgePacer share a language for "same logical source, new locator"
/// versus "this source is actually gone."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectMatch {
    /// Resolved to exactly one source.
    Matched(ResolvedAccess),
    /// A weak match resolved to more than one distinct source; EdgePacer
    /// refuses to guess which one Rails meant.
    Ambiguous { candidates: usize },
    /// No discovered loggable matched.
    NotFound,
}

/// The concrete reader EdgePacer will use plus the durable identity it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccess {
    pub access_method: AccessMethod,
    pub matched_via: MatchVia,
    /// The durable, restart-surviving identity for this source: the file path
    /// for files, the stable workload id for containers, the unit for systemd.
    pub stable_identity: String,
    /// The concrete locator to tail/stream right now. May change across
    /// restarts (new container id, rotated path) even when `stable_identity`
    /// does not.
    pub access_locator: String,
}

impl ResolvedAccess {
    pub fn confidence(&self) -> Confidence {
        self.matched_via.confidence()
    }
}

/// The coarse outcome of resolution, independent of which concrete source
/// matched. Cheap to copy and compare, so callers use it to dedup
/// status-transition logging and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStatus {
    Matched,
    Ambiguous,
    NotFound,
}

impl MatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchStatus::Matched => "matched",
            MatchStatus::Ambiguous => "ambiguous",
            MatchStatus::NotFound => "not_found",
        }
    }
}

impl CollectMatch {
    pub fn status(&self) -> MatchStatus {
        match self {
            CollectMatch::Matched(_) => MatchStatus::Matched,
            CollectMatch::Ambiguous { .. } => MatchStatus::Ambiguous,
            CollectMatch::NotFound => MatchStatus::NotFound,
        }
    }
}

/// In-memory index of discovered loggables.
#[derive(Debug, Default)]
pub struct DiscoveryCache {
    containers: HashMap<String, Container>,
    files: HashMap<String, LogFile>,
    systemd_services: HashMap<String, SystemdService>,
    event_log_channels: HashMap<String, EventLogChannel>,
    /// Monotonic count of applied census scans. The orchestrator reconciles
    /// when this moves, so directive resolution re-runs on discovery changes,
    /// not only on config changes. Advanced under the same write lock as the
    /// entries, so an observed epoch always matches the cached contents.
    epoch: u64,
    /// Container backends must all complete before their union can be used as
    /// authorization evidence. `None` means the latest applied scan was
    /// complete; `epoch == 0` still means no scan has completed at all.
    container_inventory_error: Option<String>,
}

/// Complete container inventory pinned to the cache epoch it came from.
#[derive(Debug, Clone)]
pub struct CompleteContainerSnapshot {
    pub epoch: u64,
    pub containers: Vec<Container>,
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The discovery epoch as of the last applied scan.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Replace all cache entries from a census scan.
    pub fn update_all(&mut self, census: &Census) {
        self.update_containers(&census.containers);
        self.update_files(&census.log_files);
        self.update_systemd_services(&census.systemd_services);
        self.update_event_log_channels(&census.event_log_channels);
        let failed_backends: Vec<_> = ["docker", "kubernetes", "cri"]
            .into_iter()
            .filter(|backend| census.errors.contains_key(*backend))
            .collect();
        self.container_inventory_error = (!failed_backends.is_empty())
            .then(|| format!("container discovery failed: {}", failed_backends.join(", ")));
        self.epoch += 1;
    }

    // Kubernetes containers are cached whether or not they carry the explicit
    // opt-in: a selector match is consent too, and it can only resolve against
    // a cached container. Collection consent survives at the directive layer —
    // no selector match and no explicit opt-in means no directive, and no
    // directive means no pipeline.
    fn update_containers(&mut self, containers: &[Container]) {
        self.containers.clear();
        for container in containers {
            let c = container.clone();
            let spec_name = if !c.container_name.is_empty() {
                c.container_name.clone()
            } else {
                c.name.clone()
            };

            self.containers.insert(c.id.clone(), c.clone());

            if !c.name.is_empty() {
                self.containers.insert(c.name.clone(), c.clone());
            }

            if c.runtime == "kubernetes" && !c.namespace.is_empty() && !c.deployment.is_empty() {
                let k8s_stable = format!("{}/{}/{}", c.namespace, c.deployment, spec_name);
                self.containers.insert(k8s_stable, c.clone());

                let k8s_short = format!("{}/{}", c.namespace, c.deployment);
                self.containers.insert(k8s_short, c.clone());
            }

            if !c.service_name.is_empty() {
                self.containers.insert(c.service_name.clone(), c.clone());
            }

            let stable = c.stable_id();
            if stable != c.name {
                self.containers.insert(stable.clone(), c.clone());
            }

            // Per-instance identity (Compose replica, StatefulSet ordinal,
            // DaemonSet node…). Differs from stable_id only for genuine
            // multi-instance workloads; index it so a directive keyed on the
            // stable_instance_id resolves to this exact container.
            let instance = c.stable_instance_id();
            if instance != stable && instance != c.name {
                self.containers.insert(instance, c.clone());
            }

            if !c.log_path.is_empty() {
                self.containers.insert(c.log_path.clone(), c.clone());
            }

            if !c.container_id.is_empty() && c.container_id != c.id {
                self.containers.insert(c.container_id.clone(), c.clone());
            }
        }
    }

    fn update_files(&mut self, files: &[LogFile]) {
        self.files.clear();
        for file in files {
            self.files.insert(file.path.clone(), file.clone());
        }
    }

    fn update_systemd_services(&mut self, services: &[SystemdService]) {
        self.systemd_services.clear();
        for service in services {
            self.systemd_services
                .insert(service.name.clone(), service.clone());
            if !service.service_name.is_empty() {
                self.systemd_services
                    .insert(service.service_name.clone(), service.clone());
            }
        }
    }

    fn update_event_log_channels(&mut self, channels: &[EventLogChannel]) {
        self.event_log_channels.clear();
        for channel in channels {
            self.event_log_channels
                .insert(channel.channel.clone(), channel.clone());
        }
    }

    /// Every distinct discovered container (the alias map indexes each one
    /// under many keys), ordered by per-instance identity so selector
    /// evaluation and source synthesis are deterministic across scans.
    pub fn distinct_containers(&self) -> Vec<&Container> {
        let mut seen = std::collections::HashSet::new();
        let mut containers: Vec<&Container> = self
            .containers
            .values()
            .filter(|c| seen.insert(c.id.as_str()))
            .collect();
        containers.sort_by_cached_key(|c| (c.stable_instance_id(), c.id.clone()));
        containers
    }

    /// Owned, point-in-time container inventory suitable for security
    /// decisions. Initial or backend-partial scans fail closed.
    pub fn complete_container_snapshot(&self) -> Result<CompleteContainerSnapshot, String> {
        if self.epoch == 0 {
            return Err("container discovery has not completed an initial scan".to_string());
        }
        if let Some(error) = &self.container_inventory_error {
            return Err(error.clone());
        }
        Ok(CompleteContainerSnapshot {
            epoch: self.epoch,
            containers: self.distinct_containers().into_iter().cloned().collect(),
        })
    }

    /// Revalidate a snapshot immediately before it becomes authorization
    /// evidence. The caller holds the cache read lock through application, so
    /// a concurrent discovery update cannot slip between this check and commit.
    pub fn verify_complete_container_epoch(&self, expected_epoch: u64) -> Result<(), String> {
        if self.epoch != expected_epoch {
            return Err(format!(
                "container discovery changed during listener snapshot ({expected_epoch} -> {})",
                self.epoch
            ));
        }
        if let Some(error) = &self.container_inventory_error {
            return Err(error.clone());
        }
        Ok(())
    }

    /// Resolve a collect directive (identifier + type hint) to a concrete
    /// reader, reporting how the match was made and how durable it is.
    pub fn resolve(&self, identifier: &str, loggable_type: &str) -> CollectMatch {
        match loggable_type {
            "container" => self.resolve_container(identifier),
            "file" => self.resolve_file(identifier),
            "systemd_service" | "journald" => self.resolve_systemd(identifier),
            "windows_event_log" => self.resolve_windows_event_log(identifier),
            _ => {
                // Unknown hint: try each lane in priority order. A container
                // result (including an Ambiguous refusal) wins over file/systemd.
                let container = self.resolve_container(identifier);
                if !matches!(container, CollectMatch::NotFound) {
                    return container;
                }
                let file = self.resolve_file(identifier);
                if !matches!(file, CollectMatch::NotFound) {
                    return file;
                }
                let systemd = self.resolve_systemd(identifier);
                if !matches!(systemd, CollectMatch::NotFound) {
                    return systemd;
                }
                // Windows Event Log sample requests carry no type hint (the wire
                // is just an identifier), so the empty-hint path lands here.
                // Gated on the discovered channel set, so this never
                // over-matches a stray file path or unit name.
                self.resolve_windows_event_log(identifier)
            }
        }
    }

    /// Back-compat resolver for callers that only need the access method and
    /// locator of a single match (e.g. on-demand sampling). Ambiguous and
    /// missing both collapse to `None`.
    pub fn resolve_access_method(
        &self,
        identifier: &str,
        loggable_type: &str,
    ) -> Option<(AccessMethod, String)> {
        match self.resolve(identifier, loggable_type) {
            CollectMatch::Matched(access) => Some((access.access_method, access.access_locator)),
            CollectMatch::Ambiguous { .. } | CollectMatch::NotFound => None,
        }
    }

    fn resolve_container(&self, identifier: &str) -> CollectMatch {
        // Exact alias hit: the cache indexes each container under id, name,
        // k8s stable forms, service name, stable_id, log path, and container id.
        if let Some(container) = self.containers.get(identifier) {
            return container_match(container, classify_container_match(container, identifier));
        }

        // Weak fallback: match on runtime id or 12-char id prefix. One
        // container is indexed under many alias keys, so `values()` yields it
        // repeatedly — dedup by `id` before deciding, or a single container
        // would look ambiguous.
        let mut seen = std::collections::HashSet::new();
        let candidates: Vec<&Container> = self
            .containers
            .values()
            .filter(|c| matches_by_id(c, identifier))
            .filter(|c| seen.insert(c.id.as_str()))
            .collect();

        match candidates.as_slice() {
            [] => CollectMatch::NotFound,
            [container] => container_match(container, MatchVia::ContainerId),
            many => CollectMatch::Ambiguous {
                candidates: many.len(),
            },
        }
    }

    fn resolve_file(&self, identifier: &str) -> CollectMatch {
        match self.files.get(identifier) {
            Some(file) if file.readable => CollectMatch::Matched(ResolvedAccess {
                access_method: AccessMethod::File,
                matched_via: MatchVia::FilePath,
                stable_identity: file.path.clone(),
                access_locator: file.path.clone(),
            }),
            _ => CollectMatch::NotFound,
        }
    }

    fn resolve_systemd(&self, identifier: &str) -> CollectMatch {
        match self.systemd_services.get(identifier) {
            Some(service)
                if service.load_state == "loaded" && service.name.ends_with(".service") =>
            {
                CollectMatch::Matched(ResolvedAccess {
                    access_method: AccessMethod::Journald,
                    matched_via: MatchVia::SystemdUnit,
                    stable_identity: service.name.clone(),
                    access_locator: service.name.clone(),
                })
            }
            _ => CollectMatch::NotFound,
        }
    }

    /// Resolve a Windows Event Log channel by name. Gated on the discovered
    /// channel set — a channel EdgePacer has not enumerated does not resolve,
    /// so the empty-hint sampler fallback can't mistake a file/unit for one.
    fn resolve_windows_event_log(&self, identifier: &str) -> CollectMatch {
        match self.event_log_channels.get(identifier) {
            Some(channel) => CollectMatch::Matched(ResolvedAccess {
                access_method: AccessMethod::WindowsEventLog,
                matched_via: MatchVia::WindowsEventLog,
                stable_identity: channel.channel.clone(),
                access_locator: channel.channel.clone(),
            }),
            None => CollectMatch::NotFound,
        }
    }

    pub fn stats(&self) -> DiscoveryCacheStats {
        let mut seen = std::collections::HashSet::new();
        for c in self.containers.values() {
            seen.insert(c.id.clone());
        }
        DiscoveryCacheStats {
            containers: seen.len(),
            files: self.files.len(),
            systemd_services: self.systemd_services.len(),
            event_log_channels: self.event_log_channels.len(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryCacheStats {
    pub containers: usize,
    pub files: usize,
    pub systemd_services: usize,
    pub event_log_channels: usize,
}

impl DiscoveryCacheStats {
    pub fn total(&self) -> usize {
        self.containers + self.files + self.systemd_services + self.event_log_channels
    }
}

/// Infer loggable type from Rails matching_strategy.
pub fn infer_loggable_type(matching_strategy: &str) -> &'static str {
    match matching_strategy {
        "env_var" | "container_name" | "container_id" | "stable_id" | "stable_instance_id"
        | "log_path" | "image" => "container",
        "systemd_unit" => "systemd_service",
        "file_path" => "file",
        "windows_event_log" => "windows_event_log",
        _ => "",
    }
}

/// A container whose runtime id shares a 12-char prefix with the identifier.
/// Prefix matching mirrors Docker's short-id convention. Bytes, not `str`, so a
/// non-ASCII identifier can't panic on a char boundary.
///
/// An exact `container_id` match is always caught by the alias-map lookup in
/// `resolve_container` before this fallback runs (every non-empty `container_id`
/// is indexed as a key), so only prefix hits are checked here.
fn matches_by_id(container: &Container, identifier: &str) -> bool {
    let (id, ident) = (container.id.as_bytes(), identifier.as_bytes());
    ident.len() >= 12 && id.len() >= 12 && id[..12] == ident[..12]
}

/// Build a match for a discovered container, or `NotFound` if it has no
/// readable locator (discovered, but nothing to tail yet).
fn container_match(container: &Container, matched_via: MatchVia) -> CollectMatch {
    let access_locator = container.log_locator();
    if access_locator.is_empty() {
        return CollectMatch::NotFound;
    }
    // When matched on the per-instance id, that *is* this source's durable
    // identity; otherwise the workload-level stable_id is.
    let stable_identity = if matched_via == MatchVia::StableInstanceId {
        container.stable_instance_id()
    } else {
        container.stable_id()
    };
    CollectMatch::Matched(ResolvedAccess {
        access_method: container.determine_access_method(),
        matched_via,
        stable_identity,
        access_locator,
    })
}

fn classify_container_match(container: &Container, identifier: &str) -> MatchVia {
    let stable = container.stable_id();
    // A genuine per-instance id (one that differs from the workload stable_id)
    // takes precedence. For single-instance workloads the two coincide, so this
    // stays a plain stable_id match and existing behavior is unchanged.
    let instance = container.stable_instance_id();
    if instance != stable && instance == identifier {
        return MatchVia::StableInstanceId;
    }
    if stable == identifier {
        return MatchVia::StableId;
    }
    if container.id == identifier || container.container_id == identifier {
        return MatchVia::ContainerId;
    }
    if container.name == identifier {
        return MatchVia::ContainerName;
    }
    if container.service_name == identifier {
        return MatchVia::ServiceName;
    }
    if identifier.contains('/') {
        return MatchVia::StableId;
    }
    MatchVia::ContainerName
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Census;
    use std::collections::HashMap;

    fn docker_container(name: &str, log_path: &str) -> Container {
        container_with_id("abc123def456", name, log_path)
    }

    fn container_with_id(id: &str, name: &str, log_path: &str) -> Container {
        Container {
            id: id.into(),
            name: name.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: "running".into(),
            labels: HashMap::new(),
            env: vec![],
            runtime: "docker".into(),
            log_path: log_path.into(),
            log_format: "plain_text".into(),
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: id.into(),
            container_name: String::new(),
            runtime_process: None,
        }
    }

    fn compose_replica(id: &str, project: &str, service: &str, ordinal: &str) -> Container {
        let mut c = container_with_id(id, &format!("{project}-{service}-{ordinal}"), "");
        c.labels
            .insert("com.docker.compose.project".into(), project.into());
        c.labels
            .insert("com.docker.compose.service".into(), service.into());
        c.labels
            .insert("com.docker.compose.container-number".into(), ordinal.into());
        c
    }

    fn cache_with(containers: Vec<Container>) -> DiscoveryCache {
        let census = Census {
            containers,
            ..Default::default()
        };
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);
        cache
    }

    #[test]
    fn epoch_advances_on_every_applied_scan() {
        let mut cache = DiscoveryCache::new();
        assert_eq!(cache.epoch(), 0, "no scan applied yet");

        cache.update_all(&Census::default());
        assert_eq!(cache.epoch(), 1);

        // Identical census content still advances the epoch: the epoch marks
        // "a scan was applied", and reconcile cost for an unchanged scan is a
        // cheap no-op re-resolve.
        cache.update_all(&Census::default());
        assert_eq!(cache.epoch(), 2);
    }

    #[test]
    fn authorization_snapshot_requires_initialized_complete_container_discovery() {
        let mut cache = DiscoveryCache::new();
        assert!(cache.complete_container_snapshot().is_err());

        let mut partial = Census::default();
        partial
            .errors
            .insert("docker".to_string(), "daemon unavailable".to_string());
        cache.update_all(&partial);
        assert_eq!(
            cache.complete_container_snapshot().unwrap_err(),
            "container discovery failed: docker"
        );

        cache.update_all(&Census::default());
        let snapshot = cache.complete_container_snapshot().unwrap();
        assert_eq!(snapshot.epoch, 2);
        assert!(snapshot.containers.is_empty());

        cache.update_all(&Census::default());
        assert_eq!(
            cache
                .verify_complete_container_epoch(snapshot.epoch)
                .unwrap_err(),
            "container discovery changed during listener snapshot (2 -> 3)"
        );
    }

    fn kubernetes_container(service_name_explicit: bool) -> Container {
        Container {
            id: "default/test-pod/app".into(),
            name: "test-pod-app".into(),
            service_name: "checkout".into(),
            service_name_explicit,
            image: "nginx:latest".into(),
            state: "running".into(),
            labels: HashMap::new(),
            env: vec![],
            runtime: "kubernetes".into(),
            log_path: "/var/log/pods/default_test-pod_uid/app".into(),
            log_format: "plain_text".into(),
            pod_uid: "uid".into(),
            pod_name: "test-pod".into(),
            namespace: "default".into(),
            node_name: "node-1".into(),
            deployment: "checkout".into(),
            workload_kind: "deployment".into(),
            container_id: "containerd://abc123def456".into(),
            container_name: "app".into(),
            runtime_process: None,
        }
    }

    #[test]
    fn resolves_file_by_path() {
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        census.log_files.push(LogFile {
            path: "/var/log/app.log".into(),
            size: 100,
            modified: String::new(),
            readable: true,
            permissions: "644".into(),
            format: "plain_text".into(),
            line_count: 10,
        });
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("/var/log/app.log", "file")
            .unwrap();
        assert_eq!(method, AccessMethod::File);
        assert_eq!(loc, "/var/log/app.log");
    }

    #[test]
    fn resolves_docker_json_file_when_log_path_present() {
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("container.log");
        std::fs::write(&log_path, "line\n").unwrap();

        census
            .containers
            .push(docker_container("my-nginx", log_path.to_str().unwrap()));
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("my-nginx", "container")
            .unwrap();
        assert_eq!(method, AccessMethod::DockerJsonFile);
        assert_eq!(loc, log_path.to_str().unwrap());
    }

    #[test]
    fn resolves_docker_api_without_log_path() {
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        census.containers.push(docker_container("my-nginx", ""));
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("my-nginx", "container")
            .unwrap();
        assert_eq!(method, AccessMethod::DockerApi);
        assert_eq!(loc, "abc123def456");
    }

    #[test]
    fn resolves_docker_api_when_reported_log_path_is_not_local() {
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        census
            .containers
            .push(docker_container("my-nginx", "/var/lib/docker/missing.log"));
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("my-nginx", "container")
            .unwrap();
        assert_eq!(method, AccessMethod::DockerApi);
        assert_eq!(loc, "abc123def456");
    }

    #[test]
    fn resolves_non_explicit_kubernetes_container() {
        // A selector match is consent, and it can only resolve against a cached
        // container — so k8s containers are cached without the explicit opt-in.
        // Consent survives at the directive layer: no selector match and no
        // opt-in means no directive, and no directive means no pipeline.
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        census.containers.push(kubernetes_container(false));
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("default/checkout/app", "container")
            .unwrap();
        assert_eq!(method, AccessMethod::Kubernetes);
        assert_eq!(loc, "/var/log/pods/default_test-pod_uid/app");
        assert_eq!(cache.stats().containers, 1);
    }

    #[test]
    fn resolves_explicit_kubernetes_container() {
        let mut cache = DiscoveryCache::new();
        let mut census = Census::default();
        census.containers.push(kubernetes_container(true));
        cache.update_all(&census);

        let (method, loc) = cache
            .resolve_access_method("default/checkout/app", "container")
            .unwrap();

        assert_eq!(method, AccessMethod::Kubernetes);
        assert_eq!(loc, "/var/log/pods/default_test-pod_uid/app");
        assert_eq!(cache.stats().containers, 1);
    }

    #[test]
    fn infer_loggable_type_maps_strategies() {
        assert_eq!(infer_loggable_type("file_path"), "file");
        assert_eq!(infer_loggable_type("stable_id"), "container");
        assert_eq!(infer_loggable_type("systemd_unit"), "systemd_service");
    }

    fn matched(m: CollectMatch) -> ResolvedAccess {
        match m {
            CollectMatch::Matched(access) => access,
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn file_match_identity_is_the_path_and_strong() {
        let mut census = Census::default();
        census.log_files.push(LogFile {
            path: "/var/log/app.log".into(),
            size: 100,
            modified: String::new(),
            readable: true,
            permissions: "644".into(),
            format: "plain_text".into(),
            line_count: 10,
        });
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);

        let access = matched(cache.resolve("/var/log/app.log", "file"));
        assert_eq!(access.matched_via, MatchVia::FilePath);
        assert_eq!(access.confidence(), Confidence::Strong);
        // A file's durable identity is its path on disk — and so is its locator.
        assert_eq!(access.stable_identity, "/var/log/app.log");
        assert_eq!(access.access_locator, "/var/log/app.log");
    }

    #[test]
    fn missing_file_is_not_found() {
        let cache = DiscoveryCache::new();
        assert_eq!(
            cache.resolve("/no/such.log", "file"),
            CollectMatch::NotFound
        );
    }

    #[test]
    fn windows_service_inventory_does_not_resolve_to_journald() {
        let mut census = Census::default();
        census.systemd_services.push(SystemdService {
            name: "EventLog".into(),
            load_state: "installed".into(),
            active_state: "running".into(),
            sub_state: "win32".into(),
            description: "Windows Event Log".into(),
            service_name: "EventLog".into(),
            main_pid: 2112,
        });
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);

        assert_eq!(cache.stats().systemd_services, 1);
        assert_eq!(
            cache.resolve("EventLog", "systemd_service"),
            CollectMatch::NotFound
        );
    }

    #[test]
    fn resolves_discovered_event_log_channel_by_name() {
        let mut census = Census::default();
        census.event_log_channels.push(EventLogChannel {
            channel: "Application".into(),
            record_count: 1234,
        });
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);

        // Explicit type hint resolves to the wevtutil access method.
        let access = matched(cache.resolve("Application", "windows_event_log"));
        assert_eq!(access.access_method, AccessMethod::WindowsEventLog);
        assert_eq!(access.matched_via, MatchVia::WindowsEventLog);
        assert_eq!(access.confidence(), Confidence::Strong);
        assert_eq!(access.access_locator, "Application");

        // The empty-hint sampler path also resolves a *discovered* channel.
        let (method, loc) = cache.resolve_access_method("Application", "").unwrap();
        assert_eq!(method, AccessMethod::WindowsEventLog);
        assert_eq!(loc, "Application");

        // An undiscovered channel name does not resolve (no over-matching).
        assert_eq!(
            cache.resolve("Microsoft-Windows-Nope/Operational", "windows_event_log"),
            CollectMatch::NotFound
        );
        assert!(cache.resolve_access_method("Nope", "").is_none());
        assert_eq!(cache.stats().event_log_channels, 1);
    }

    #[test]
    fn explicit_service_name_match_is_explicit_confidence() {
        let mut c = docker_container("web", "");
        c.service_name = "billing".into();
        c.service_name_explicit = true;
        let cache = cache_with(vec![c]);

        let access = matched(cache.resolve("billing", "container"));
        assert_eq!(access.matched_via, MatchVia::ServiceName);
        assert_eq!(access.confidence(), Confidence::Explicit);
    }

    #[test]
    fn standalone_container_name_is_its_stable_id() {
        // A standalone Docker container's stable identity *is* its name, so
        // matching the name is an Explicit stable-id match, not a weaker one.
        let cache = cache_with(vec![docker_container("my-nginx", "")]);
        let access = matched(cache.resolve("my-nginx", "container"));
        assert_eq!(access.matched_via, MatchVia::StableId);
        assert_eq!(access.confidence(), Confidence::Explicit);
        assert_eq!(access.stable_identity, "my-nginx");
    }

    #[test]
    fn container_name_match_is_strong_when_distinct_from_stable_id() {
        // A Compose container's stable id is project/service, so matching by its
        // raw container name (which differs) is a Strong match, not Explicit.
        let mut c = docker_container("myapp-web-1", "");
        c.labels
            .insert("com.docker.compose.project".into(), "myapp".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        let cache = cache_with(vec![c]);

        let access = matched(cache.resolve("myapp-web-1", "container"));
        assert_eq!(access.matched_via, MatchVia::ContainerName);
        assert_eq!(access.confidence(), Confidence::Strong);
        // The durable identity is still the stable workload id, not the name.
        assert_eq!(access.stable_identity, "myapp/web");
    }

    #[test]
    fn weak_id_prefix_single_match_is_weak() {
        // A 12-char short id matches one container by prefix — valid now, but a
        // volatile key, so confidence is Weak.
        let cache = cache_with(vec![container_with_id("abc123def456aa", "svc", "")]);
        let access = matched(cache.resolve("abc123def456", "container"));
        assert_eq!(access.matched_via, MatchVia::ContainerId);
        assert_eq!(access.confidence(), Confidence::Weak);
    }

    #[test]
    fn ambiguous_id_prefix_refuses_to_pick() {
        // Two distinct containers share a 12-char id prefix. A weak prefix
        // match must refuse rather than silently grab the first one.
        let cache = cache_with(vec![
            container_with_id("abc123def456aa", "svc-a", ""),
            container_with_id("abc123def456bb", "svc-b", ""),
        ]);
        assert_eq!(
            cache.resolve("abc123def456zz", "container"),
            CollectMatch::Ambiguous { candidates: 2 }
        );
    }

    #[test]
    fn container_resolves_by_stable_id_across_id_and_argv_drift() {
        // The same Compose workload restarts with a new container id and a new
        // log path (its launch argv is irrelevant to identity). Resolving by
        // the stable workload id must still match, keep the same durable
        // identity, and only the access locator moves.
        let compose = |id: &str, locator: &str| {
            let mut c = container_with_id(id, "shop-web-1", locator);
            c.labels
                .insert("com.docker.compose.project".into(), "shop".into());
            c.labels
                .insert("com.docker.compose.service".into(), "web".into());
            c
        };

        let before =
            matched(cache_with(vec![compose("id-old", "")]).resolve("shop/web", "container"));
        let after =
            matched(cache_with(vec![compose("id-new", "")]).resolve("shop/web", "container"));

        assert_eq!(before.matched_via, MatchVia::StableId);
        assert_eq!(after.matched_via, MatchVia::StableId);
        assert_eq!(before.stable_identity, "shop/web");
        assert_eq!(after.stable_identity, "shop/web");
        // Same logical source, new access locator (the restarted container id).
        assert_eq!(before.access_locator, "id-old");
        assert_eq!(after.access_locator, "id-new");
    }

    #[test]
    fn infer_loggable_type_maps_stable_instance_id_to_container() {
        assert_eq!(infer_loggable_type("stable_instance_id"), "container");
    }

    #[test]
    fn resolves_compose_replicas_by_their_stable_instance_ids() {
        // Two replicas of the same Compose service share a workload stable_id
        // but each has its own stable_instance_id, so a per-instance directive
        // resolves to the right container — and the volatile container id stays
        // a local-only access locator.
        let cache = cache_with(vec![
            compose_replica("id-web-1", "shop", "web", "1"),
            compose_replica("id-web-2", "shop", "web", "2"),
        ]);

        let one = matched(cache.resolve("shop/web/1", "container"));
        assert_eq!(one.matched_via, MatchVia::StableInstanceId);
        assert_eq!(one.confidence(), Confidence::Explicit);
        assert_eq!(one.stable_identity, "shop/web/1");
        assert_eq!(one.access_locator, "id-web-1");

        let two = matched(cache.resolve("shop/web/2", "container"));
        assert_eq!(two.matched_via, MatchVia::StableInstanceId);
        assert_eq!(two.access_locator, "id-web-2");
    }

    #[test]
    fn distinct_containers_dedups_aliases_in_stable_order() {
        // Each container is indexed under many alias keys; enumeration must
        // yield it once, ordered by per-instance identity so selector
        // evaluation is deterministic across scans.
        let cache = cache_with(vec![
            compose_replica("id-web-2", "shop", "web", "2"),
            compose_replica("id-web-1", "shop", "web", "1"),
        ]);

        let ids: Vec<&str> = cache
            .distinct_containers()
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids, vec!["id-web-1", "id-web-2"]);
    }

    #[test]
    fn stable_instance_id_resolves_across_container_id_drift() {
        // A replica is redeployed with a brand-new container id. Resolving by
        // the stable per-instance id still matches: same durable identity, only
        // the access locator (the new container id) moves. This is the churn the
        // de-volatilize change removes.
        let before = matched(
            cache_with(vec![compose_replica("id-old", "shop", "web", "1")])
                .resolve("shop/web/1", "container"),
        );
        let after = matched(
            cache_with(vec![compose_replica("id-new", "shop", "web", "1")])
                .resolve("shop/web/1", "container"),
        );

        assert_eq!(before.matched_via, MatchVia::StableInstanceId);
        assert_eq!(after.matched_via, MatchVia::StableInstanceId);
        assert_eq!(before.stable_identity, "shop/web/1");
        assert_eq!(after.stable_identity, "shop/web/1");
        assert_eq!(before.access_locator, "id-old");
        assert_eq!(after.access_locator, "id-new");
    }
}
