//! Inventory change tracker — commit/rollback state machine.
//!
//! Mirrors legacy EdgePacer's `internal/tracker/` package.
//! Tracks discovered resources across discovery cycles and produces
//! diff-based inventory reports (new, changed, stopped).
//!
//! Identity model:
//! - Containers: stable_id (container ID or pod_uid/name for K8s)
//! - Log files: file path
//! - Systemd services: unit name

use crate::discovery::{Census, Container, LogFile, SystemdService, packages::Package};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{debug, info};

const CENSUS_SCHEMA_VERSION: u16 = 1;
const PACKAGE_LANE: &str = "packages";
const UNKNOWN_AGENT_ID: &str = "unknown-agent";

type PackageState = BTreeMap<String, Package>;

/// Categorized inventory report produced by comparing current scan to committed state.
#[derive(Debug, Default)]
pub struct InventoryReport {
    pub new_containers: Vec<Container>,
    pub changed_containers: Vec<Container>,
    pub stopped_containers: Vec<StoppedItem>,
    pub new_files: Vec<LogFile>,
    pub stopped_files: Vec<StoppedItem>,
    pub new_services: Vec<SystemdService>,
    pub stopped_services: Vec<StoppedItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageLaneReport {
    pub schema_version: u16,
    pub lane: &'static str,
    pub agent_sequence: u64,
    pub cycle_id: String,
    pub baseline_id: String,
    pub lane_digest: String,
    pub full_snapshot: bool,
    pub item_count: usize,
    pub upsert_count: usize,
    pub delete_count: usize,
    #[serde(rename = "package_events")]
    pub events: Vec<PackageInventoryEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub installed_packages: Vec<Package>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEventOperation {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageInventoryEvent {
    pub event_id: String,
    pub operation: PackageEventOperation,
    pub item_id: String,
    pub item_version_hash: String,
    pub tombstone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
}

impl InventoryReport {
    pub fn is_empty(&self) -> bool {
        self.new_containers.is_empty()
            && self.changed_containers.is_empty()
            && self.stopped_containers.is_empty()
            && self.new_files.is_empty()
            && self.stopped_files.is_empty()
            && self.new_services.is_empty()
            && self.stopped_services.is_empty()
    }
}

/// A resource that was present in the previous scan but not the current one.
#[derive(Debug, Clone)]
pub struct StoppedItem {
    pub identifier: String,
    pub item_type: String, // "container", "file", "service"
    /// For containers: whether the (previously committed) container was an
    /// explicit LOGPACER_SERVICE_NAME service. Routes the stop delta to the
    /// services census instead of the containers census. Always false for
    /// files and systemd services.
    pub explicit_service: bool,
}

/// Tracks inventory state across discovery cycles.
pub struct ChangeTracker {
    /// Committed container state (after Rails ack), grouped by lane key: one
    /// entry per explicit-service instance, one per screener workload. A
    /// group carries every live replica, so change detection covers replica
    /// roster moves and per-replica atom drift, not just the representative.
    committed_containers: HashMap<String, Vec<Container>>,
    /// Committed file state.
    committed_files: HashMap<String, LogFile>,
    /// Committed service state.
    committed_services: HashMap<String, SystemdService>,
    /// Committed package lane state.
    committed_packages: PackageState,
    /// Pending state (before commit/rollback).
    pending_containers: Option<HashMap<String, Vec<Container>>>,
    pending_files: Option<HashMap<String, LogFile>>,
    pending_services: Option<HashMap<String, SystemdService>>,
    pending_packages: Option<PackageState>,
    next_package_sequence: u64,
    force_package_full_snapshot: bool,
    /// True until the next committed inventory report: the tracker holds no
    /// acked baseline (fresh start or post-`require_full_resync`), so that
    /// report re-emits the world and its lane payloads carry `full_report`,
    /// telling Rails absence-implies-stopped semantics are safe.
    full_inventory_report: bool,
    /// Identifiers rejected by Rails (don't re-report).
    rejected: HashSet<String>,
}

impl Default for ChangeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeTracker {
    pub fn new() -> Self {
        Self {
            committed_containers: HashMap::new(),
            committed_files: HashMap::new(),
            committed_services: HashMap::new(),
            committed_packages: BTreeMap::new(),
            pending_containers: None,
            pending_files: None,
            pending_services: None,
            pending_packages: None,
            next_package_sequence: 1,
            force_package_full_snapshot: true,
            full_inventory_report: true,
            rejected: HashSet::new(),
        }
    }

    /// Whether the next inventory report re-emits the world (no acked
    /// baseline). Lane payloads built from such a report carry `full_report`.
    pub fn full_report(&self) -> bool {
        self.full_inventory_report
    }

    /// Compare current census against committed state and produce a diff report.
    /// Stores pending state for commit/rollback.
    pub fn update_from_scan(&mut self, census: &Census) -> InventoryReport {
        let mut report = InventoryReport::default();

        // --- Containers ---
        let mut current_containers: HashMap<String, Vec<Container>> = HashMap::new();
        let mut seen_container_ids = HashSet::new();
        // Census order of first sighting, so report order stays deterministic.
        let mut container_order: Vec<String> = Vec::new();

        for container in &census.containers {
            // Explicit-service containers are tracked per INSTANCE, so every
            // replica of a multi-instance service (a StatefulSet, a scaled
            // Compose service) reaches the services census and logpacer can key
            // a ContainerInstance + directive on each. Screener inventory stays
            // at WORKLOAD granularity (stable_id): its loggable is workload-level
            // and its stopped-detection matches on the workload id, so keeping
            // it coarse avoids both redundant reports and a stopped-match miss.
            let id = if container.explicit_service() {
                container.stable_instance_id()
            } else {
                container.stable_id()
            };
            if self.rejected.contains(&id) {
                continue;
            }
            if seen_container_ids.insert(id.clone()) {
                container_order.push(id.clone());
            }
            current_containers
                .entry(id)
                .or_default()
                .push(container.clone());
        }

        for id in &container_order {
            let replicas = current_containers
                .get_mut(id)
                .expect("every ordered id was inserted");
            // Deterministic replica order: comparisons and the workload
            // representative must not depend on runtime enumeration order.
            replicas.sort_by(|a, b| {
                a.stable_instance_id()
                    .cmp(&b.stable_instance_id())
                    .then_with(|| a.id.cmp(&b.id))
            });

            // Kamal (and other orchestrators) leave prior-deploy containers
            // exited on the host; they share the SHA-free stable_instance_id
            // with the live one and only differ by the container.name SHA. A
            // workload with any running replica is represented by its running
            // replicas alone, so a leftover exited container can't become the
            // representative and report a live workload as stopped. A workload
            // with no running replica keeps them, so a genuine stop still
            // surfaces as a state change.
            if replicas.iter().any(|c| c.state == "running") {
                replicas.retain(|c| c.state == "running");
            }

            match self.committed_containers.get(id) {
                None => report_container_group(&mut report.new_containers, replicas),
                Some(prev) if containers_changed(prev, replicas) => {
                    report_container_group(&mut report.changed_containers, replicas);
                }
                _ => {} // No change
            }
        }

        // Detect stopped containers
        for (id, prev) in &self.committed_containers {
            if !seen_container_ids.contains(id) {
                report.stopped_containers.push(StoppedItem {
                    identifier: id.clone(),
                    item_type: "container".into(),
                    explicit_service: prev.iter().any(Container::explicit_service),
                });
            }
        }

        // --- Log Files ---
        let mut current_files = HashMap::new();
        let mut seen_file_ids = HashSet::new();

        for file in &census.log_files {
            let id = file.identifier().to_string();
            if self.rejected.contains(&id) {
                continue;
            }
            seen_file_ids.insert(id.clone());
            current_files.insert(id.clone(), file.clone());

            if !self.committed_files.contains_key(&id) {
                report.new_files.push(file.clone());
            }
        }

        for id in self.committed_files.keys() {
            if !seen_file_ids.contains(id) {
                report.stopped_files.push(StoppedItem {
                    identifier: id.clone(),
                    item_type: "file".into(),
                    explicit_service: false,
                });
            }
        }

        // --- Systemd Services ---
        let mut current_services = HashMap::new();
        let mut seen_service_ids = HashSet::new();

        for service in &census.systemd_services {
            let id = service.identifier().to_string();
            if self.rejected.contains(&id) {
                continue;
            }
            seen_service_ids.insert(id.clone());
            current_services.insert(id.clone(), service.clone());

            if !self.committed_services.contains_key(&id) {
                report.new_services.push(service.clone());
            }
        }

        for id in self.committed_services.keys() {
            if !seen_service_ids.contains(id) {
                report.stopped_services.push(StoppedItem {
                    identifier: id.clone(),
                    item_type: "service".into(),
                    explicit_service: false,
                });
            }
        }

        // Store pending state
        self.pending_containers = Some(current_containers);
        self.pending_files = Some(current_files);
        self.pending_services = Some(current_services);

        if !report.is_empty() {
            info!(
                new_containers = report.new_containers.len(),
                changed_containers = report.changed_containers.len(),
                stopped_containers = report.stopped_containers.len(),
                new_files = report.new_files.len(),
                stopped_files = report.stopped_files.len(),
                "inventory changes detected"
            );
        } else {
            debug!("no inventory changes");
        }

        report
    }

    /// Commit pending state after successful Rails reporting.
    pub fn commit_scan(&mut self) {
        if let Some(containers) = self.pending_containers.take() {
            self.committed_containers = containers;
            // The acked report established a baseline; later reports are
            // deltas. A late commit after `require_full_resync` never lands
            // here (pending was dropped), so the marker survives it.
            self.full_inventory_report = false;
        }
        if let Some(files) = self.pending_files.take() {
            self.committed_files = files;
        }
        if let Some(services) = self.pending_services.take() {
            self.committed_services = services;
        }
        debug!("inventory state committed");
    }

    /// Rollback pending state on reporting failure.
    pub fn rollback_scan(&mut self) {
        self.pending_containers = None;
        self.pending_files = None;
        self.pending_services = None;
        debug!("inventory state rolled back");
    }

    /// Mark an identifier as rejected by Rails (won't re-report).
    pub fn mark_rejected(&mut self, identifier: &str) {
        self.rejected.insert(identifier.to_string());
    }

    pub fn update_packages_from_scan(
        &mut self,
        agent_identity: &str,
        packages: &[Package],
    ) -> PackageLaneReport {
        let current_packages = package_state(packages);
        let current_digest = package_state_digest(&current_packages);
        let previous_digest = package_state_digest(&self.committed_packages);
        let full_snapshot = self.force_package_full_snapshot;

        let mut events = package_events(
            agent_identity,
            full_snapshot,
            &self.committed_packages,
            &current_packages,
        );
        events.sort_by(|left, right| {
            left.item_id
                .cmp(&right.item_id)
                .then(operation_rank(left.operation).cmp(&operation_rank(right.operation)))
        });

        let upsert_count = events
            .iter()
            .filter(|event| event.operation == PackageEventOperation::Upsert)
            .count();
        let delete_count = events.len() - upsert_count;
        let item_count = current_packages.len();
        let installed_packages = if full_snapshot {
            current_packages.values().cloned().collect()
        } else {
            Vec::new()
        };

        self.pending_packages = Some(current_packages);

        PackageLaneReport {
            schema_version: CENSUS_SCHEMA_VERSION,
            lane: PACKAGE_LANE,
            agent_sequence: self.next_package_sequence,
            cycle_id: package_cycle_id(agent_identity, self.next_package_sequence, &current_digest),
            baseline_id: package_baseline_id(if full_snapshot {
                &current_digest
            } else {
                &previous_digest
            }),
            lane_digest: current_digest,
            full_snapshot,
            item_count,
            upsert_count,
            delete_count,
            events,
            installed_packages,
        }
    }

    pub fn commit_package_scan(&mut self) {
        if let Some(packages) = self.pending_packages.take() {
            self.committed_packages = packages;
            self.force_package_full_snapshot = false;
            self.next_package_sequence += 1;
            debug!("package lane state committed");
        }
    }

    pub fn rollback_package_scan(&mut self) {
        self.pending_packages = None;
        debug!("package lane state rolled back");
    }

    pub fn require_package_full_resync(&mut self) {
        self.pending_packages = None;
        self.force_package_full_snapshot = true;
        debug!("package lane full resync requested");
    }

    /// Force a full re-report of every inventory lane on the next cycle.
    ///
    /// The control plane sets this one-shot when a lane's rows have drifted from
    /// the agent's committed view — an orphaned row that delta census never
    /// re-mentions and so only heals on agent restart. Clearing the committed
    /// container/file/service maps makes the next `update_from_scan` re-emit
    /// every entry as `new_*`; `require_package_full_resync` forces the next
    /// package report to a full snapshot.
    ///
    /// Pending state is dropped so a `commit_scan` later in the same cycle can't
    /// silently repopulate the maps we just cleared. Idempotent: safe to call
    /// for every lane response that carries the flag within one cycle.
    pub fn require_full_resync(&mut self) {
        self.committed_containers.clear();
        self.committed_files.clear();
        self.committed_services.clear();
        self.pending_containers = None;
        self.pending_files = None;
        self.pending_services = None;
        self.full_inventory_report = true;
        self.require_package_full_resync();
        debug!("full inventory resync requested");
    }
}

/// Whether a tracked container group must re-report: runtime state, image,
/// log format, identifier atoms, or the replica roster moved. Atom equality is
/// what re-reports an in-place label edit — Rails evaluates service selectors
/// over these atoms, so a drifted set means drifted membership. Both sides are
/// sorted by (stable_instance_id, id), so replica pairing is deterministic.
fn containers_changed(prev: &[Container], current: &[Container]) -> bool {
    prev.len() != current.len()
        || prev.iter().zip(current).any(|(p, c)| {
            p.state != c.state
                || p.image != c.image
                || p.log_format != c.log_format
                || p.identifier_set() != c.identifier_set()
        })
}

/// Push a tracked group into a report bucket. Explicit services stay
/// per-instance entries; a screener workload reports one representative (its
/// replicas ride in the census entry's `active_instances`).
fn report_container_group(bucket: &mut Vec<Container>, replicas: &[Container]) {
    if replicas.iter().any(Container::explicit_service) {
        bucket.extend(replicas.iter().cloned());
    } else if let Some(representative) = replicas.first() {
        bucket.push(representative.clone());
    }
}

fn package_events(
    agent_identity: &str,
    full_snapshot: bool,
    previous: &PackageState,
    current: &PackageState,
) -> Vec<PackageInventoryEvent> {
    if full_snapshot {
        return current
            .iter()
            .map(|(item_id, package)| package_upsert_event(agent_identity, item_id, package))
            .collect();
    }

    let mut events = Vec::new();

    for (item_id, package) in current {
        if previous.get(item_id) != Some(package) {
            events.push(package_upsert_event(agent_identity, item_id, package));
        }
    }

    for (item_id, package) in previous {
        if !current.contains_key(item_id) {
            events.push(package_delete_event(agent_identity, item_id, package));
        }
    }

    events
}

fn package_upsert_event(
    agent_identity: &str,
    item_id: &str,
    package: &Package,
) -> PackageInventoryEvent {
    let item_version_hash = package_item_version_hash(package);

    PackageInventoryEvent {
        event_id: package_event_id(agent_identity, item_id, &item_version_hash),
        operation: PackageEventOperation::Upsert,
        item_id: item_id.to_string(),
        item_version_hash,
        tombstone: false,
        package: Some(package.clone()),
    }
}

fn package_delete_event(
    agent_identity: &str,
    item_id: &str,
    package: &Package,
) -> PackageInventoryEvent {
    let item_version_hash = package_tombstone_version_hash(item_id, package);

    PackageInventoryEvent {
        event_id: package_event_id(agent_identity, item_id, &item_version_hash),
        operation: PackageEventOperation::Delete,
        item_id: item_id.to_string(),
        item_version_hash,
        tombstone: true,
        package: None,
    }
}

fn package_state(packages: &[Package]) -> PackageState {
    packages
        .iter()
        .map(|package| (package_item_id(package), package.clone()))
        .collect()
}

fn package_item_id(package: &Package) -> String {
    format!("{}:{}", package.manager, package.name)
}

fn package_state_digest(packages: &PackageState) -> String {
    let mut hasher = Sha256::new();
    for (item_id, package) in packages {
        hash_part(&mut hasher, item_id);
        hash_part(&mut hasher, &package.manager);
        hash_part(&mut hasher, &package.name);
        hash_part(&mut hasher, &package.version);
    }
    hex::encode(hasher.finalize())
}

fn package_item_version_hash(package: &Package) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, PACKAGE_LANE);
    hash_part(&mut hasher, &package.manager);
    hash_part(&mut hasher, &package.name);
    hash_part(&mut hasher, &package.version);
    hex::encode(hasher.finalize())
}

fn package_tombstone_version_hash(item_id: &str, package: &Package) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, PACKAGE_LANE);
    hash_part(&mut hasher, "delete");
    hash_part(&mut hasher, item_id);
    hash_part(&mut hasher, &package_item_version_hash(package));
    hex::encode(hasher.finalize())
}

fn package_baseline_id(digest: &str) -> String {
    format!("{PACKAGE_LANE}:{digest}")
}

fn package_cycle_id(agent_identity: &str, sequence: u64, digest: &str) -> String {
    format!(
        "{}:{PACKAGE_LANE}:{sequence}:{digest}",
        normalized_agent_identity(agent_identity)
    )
}

fn package_event_id(agent_identity: &str, item_id: &str, item_version_hash: &str) -> String {
    format!(
        "{}:{PACKAGE_LANE}:{item_id}:{item_version_hash}",
        normalized_agent_identity(agent_identity)
    )
}

fn normalized_agent_identity(agent_identity: &str) -> &str {
    if agent_identity.is_empty() {
        UNKNOWN_AGENT_ID
    } else {
        agent_identity
    }
}

fn hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn operation_rank(operation: PackageEventOperation) -> u8 {
    match operation {
        PackageEventOperation::Upsert => 0,
        PackageEventOperation::Delete => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_container(id: &str, state: &str) -> Container {
        Container {
            id: id.into(),
            name: id.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: state.into(),
            labels: Default::default(),
            env: vec![],
            runtime: "docker".into(),
            log_path: String::new(),
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

    fn make_log_file(path: &str) -> LogFile {
        LogFile {
            path: path.into(),
            size: 1024,
            modified: "2026-04-05T00:00:00Z".into(),
            readable: true,
            permissions: "644".into(),
            format: "plain_text".into(),
            line_count: 100,
        }
    }

    fn make_service(name: &str) -> SystemdService {
        SystemdService {
            name: name.into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: String::new(),
            service_name: String::new(),
            main_pid: 0,
        }
    }

    fn make_package(manager: &str, name: &str, version: &str) -> Package {
        Package {
            manager: manager.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    fn package_event_summary(report: &PackageLaneReport) -> Vec<(String, PackageEventOperation)> {
        report
            .events
            .iter()
            .map(|event| (event.item_id.clone(), event.operation))
            .collect()
    }

    #[test]
    fn package_lane_first_scan_reports_full_snapshot() {
        let mut tracker = ChangeTracker::new();
        let packages = vec![
            make_package("apt", "nginx", "1.18.0"),
            make_package("apt", "libssl3", "3.0.2"),
        ];

        let report = tracker.update_packages_from_scan("agent-1", &packages);
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.lane, "packages");
        assert_eq!(report.agent_sequence, 1);
        assert_eq!(
            report.cycle_id,
            format!("agent-1:packages:1:{}", report.lane_digest)
        );
        assert!(report.full_snapshot);
        assert_eq!(report.item_count, 2);
        assert_eq!(report.upsert_count, 2);
        assert_eq!(report.delete_count, 0);
        assert_eq!(report.events.len(), 2);
        assert_eq!(report.installed_packages.len(), 2);

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["lane"], "packages");
        assert_eq!(json["full_snapshot"], true);
        assert_eq!(json["package_events"][0]["operation"], "upsert");
        assert!(json["installed_packages"].is_array());

        let first_event = &report.events[0];
        assert_eq!(
            first_event.event_id,
            format!(
                "agent-1:packages:{}:{}",
                first_event.item_id, first_event.item_version_hash
            )
        );
    }

    #[test]
    fn package_lane_unchanged_scan_sends_digest_only_report() {
        let mut tracker = ChangeTracker::new();
        let packages = vec![make_package("apt", "nginx", "1.18.0")];

        let first = tracker.update_packages_from_scan("agent-1", &packages);
        tracker.commit_package_scan();

        let second = tracker.update_packages_from_scan("agent-1", &packages);

        assert!(!second.full_snapshot);
        assert_eq!(second.agent_sequence, 2);
        assert_eq!(second.item_count, 1);
        assert_eq!(second.lane_digest, first.lane_digest);
        assert_eq!(
            second.baseline_id,
            format!("packages:{}", first.lane_digest)
        );
        assert!(second.events.is_empty());
        assert!(second.installed_packages.is_empty());
    }

    #[test]
    fn package_lane_delta_reports_add_update_and_delete_events() {
        let mut tracker = ChangeTracker::new();
        let initial = vec![
            make_package("apt", "nginx", "1.18.0"),
            make_package("apt", "libssl3", "3.0.2"),
        ];
        let changed = vec![
            make_package("apt", "nginx", "1.24.0"),
            make_package("apt", "curl", "8.0.0"),
        ];

        let first = tracker.update_packages_from_scan("agent-1", &initial);
        tracker.commit_package_scan();
        let report = tracker.update_packages_from_scan("agent-1", &changed);

        assert!(!report.full_snapshot);
        assert_eq!(report.agent_sequence, 2);
        assert_eq!(
            report.baseline_id,
            format!("packages:{}", first.lane_digest)
        );
        assert_eq!(report.item_count, 2);
        assert_eq!(report.upsert_count, 2);
        assert_eq!(report.delete_count, 1);
        assert_eq!(
            package_event_summary(&report),
            vec![
                ("apt:curl".into(), PackageEventOperation::Upsert),
                ("apt:libssl3".into(), PackageEventOperation::Delete),
                ("apt:nginx".into(), PackageEventOperation::Upsert),
            ]
        );

        let delete_event = report
            .events
            .iter()
            .find(|event| event.operation == PackageEventOperation::Delete)
            .unwrap();
        assert!(delete_event.tombstone);
        assert!(delete_event.package.is_none());

        let nginx_event = report
            .events
            .iter()
            .find(|event| event.item_id == "apt:nginx")
            .unwrap();
        assert_eq!(
            nginx_event
                .package
                .as_ref()
                .map(|package| package.version.as_str()),
            Some("1.24.0")
        );
    }

    #[test]
    fn package_lane_rollback_retries_same_full_snapshot_sequence() {
        let mut tracker = ChangeTracker::new();
        let packages = vec![make_package("apt", "nginx", "1.18.0")];

        let first = tracker.update_packages_from_scan("agent-1", &packages);
        tracker.rollback_package_scan();
        let retry = tracker.update_packages_from_scan("agent-1", &packages);

        assert!(retry.full_snapshot);
        assert_eq!(retry.agent_sequence, 1);
        assert_eq!(retry.lane_digest, first.lane_digest);
        assert_eq!(retry.events, first.events);
    }

    #[test]
    fn package_lane_resync_request_forces_next_full_snapshot() {
        let mut tracker = ChangeTracker::new();
        let packages = vec![make_package("apt", "nginx", "1.18.0")];

        let _ = tracker.update_packages_from_scan("agent-1", &packages);
        tracker.commit_package_scan();
        tracker.require_package_full_resync();

        let report = tracker.update_packages_from_scan("agent-1", &packages);

        assert!(report.full_snapshot);
        assert_eq!(report.agent_sequence, 2);
        assert_eq!(report.upsert_count, 1);
        assert_eq!(report.delete_count, 0);
        assert_eq!(report.installed_packages.len(), 1);
    }

    #[test]
    fn first_scan_reports_all_new() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![make_container("abc123", "running")],
            log_files: vec![make_log_file("/var/log/app.log")],
            ..Default::default()
        };

        let report = tracker.update_from_scan(&census);
        assert_eq!(report.new_containers.len(), 1);
        assert_eq!(report.new_files.len(), 1);
        assert!(report.stopped_containers.is_empty());
    }

    #[test]
    fn second_scan_no_changes() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![make_container("abc123", "running")],
            log_files: vec![make_log_file("/var/log/app.log")],
            ..Default::default()
        };

        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();

        // Same scan again — no changes
        let report = tracker.update_from_scan(&census);
        assert!(report.is_empty());
    }

    #[test]
    fn detects_stopped_container() {
        let mut tracker = ChangeTracker::new();

        // First scan: container present
        let census1 = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census1);
        tracker.commit_scan();

        // Second scan: container gone
        let census2 = Census::default();
        let report = tracker.update_from_scan(&census2);
        assert_eq!(report.stopped_containers.len(), 1);
        assert_eq!(report.stopped_containers[0].identifier, "abc123");
        assert!(
            !report.stopped_containers[0].explicit_service,
            "plain containers route their stop to the containers census"
        );
    }

    #[test]
    fn stopped_explicit_service_routes_to_services_census() {
        let mut tracker = ChangeTracker::new();

        let mut svc = make_container("opted-in", "running");
        svc.service_name = "api".into();
        svc.service_name_explicit = true;

        let census1 = Census {
            containers: vec![svc],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census1);
        tracker.commit_scan();

        let report = tracker.update_from_scan(&Census::default());
        assert_eq!(report.stopped_containers.len(), 1);
        assert!(
            report.stopped_containers[0].explicit_service,
            "explicit services route their stop to the services census"
        );
    }

    #[test]
    fn detects_state_change() {
        let mut tracker = ChangeTracker::new();

        let census1 = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census1);
        tracker.commit_scan();

        let census2 = Census {
            containers: vec![make_container("abc123", "exited")],
            ..Default::default()
        };
        let report = tracker.update_from_scan(&census2);
        assert_eq!(report.changed_containers.len(), 1);
    }

    // Kamal leaves prior-deploy containers exited on the host, sharing the
    // SHA-free stable id with the live one. The live workload must report
    // running via its running replica — not stopped via a leftover exited one.
    fn kamal_replica(container_id: &str, state: &str) -> Container {
        let mut c = make_container(container_id, state);
        c.name = format!("web-{container_id}");
        c.labels.insert("service".into(), "docpacer".into());
        c.labels.insert("role".into(), "web".into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    #[test]
    fn exited_prior_deploy_containers_do_not_mask_the_live_replica() {
        let mut tracker = ChangeTracker::new();
        // One live container plus four exited leftovers, all one kamal workload.
        let census = Census {
            containers: vec![
                kamal_replica("ef6a884c", "exited"),
                kamal_replica("188183d1", "exited"),
                kamal_replica("dcd2cf76", "running"),
                kamal_replica("f7306ef5", "exited"),
                kamal_replica("ff2064e2", "exited"),
            ],
            ..Default::default()
        };

        let report = tracker.update_from_scan(&census);

        // One workload entry, reported RUNNING, represented by the live SHA.
        assert_eq!(report.new_containers.len(), 1);
        let rep = &report.new_containers[0];
        assert_eq!(rep.state, "running");
        assert_eq!(rep.id, "dcd2cf76");
    }

    #[test]
    fn detects_container_log_format_change() {
        let mut tracker = ChangeTracker::new();
        let mut before = make_container("abc123", "running");
        before.log_format = "plain_text".into();

        let census1 = Census {
            containers: vec![before],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census1);
        tracker.commit_scan();

        let mut after = make_container("abc123", "running");
        after.log_format = "ndjson".into();
        let census2 = Census {
            containers: vec![after],
            ..Default::default()
        };

        let report = tracker.update_from_scan(&census2);
        assert_eq!(report.changed_containers.len(), 1);
        assert_eq!(report.changed_containers[0].log_format, "ndjson");
    }

    #[test]
    fn rollback_preserves_previous_state() {
        let mut tracker = ChangeTracker::new();

        let census1 = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census1);
        tracker.commit_scan();

        // New scan, but rollback
        let census2 = Census {
            containers: vec![
                make_container("abc123", "running"),
                make_container("def456", "running"),
            ],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census2);
        tracker.rollback_scan();

        // Next scan should still see def456 as new (rollback preserved old state)
        let report = tracker.update_from_scan(&census2);
        assert_eq!(report.new_containers.len(), 1);
        assert_eq!(report.new_containers[0].id, "def456");
    }

    #[test]
    fn rejected_identifiers_skipped() {
        let mut tracker = ChangeTracker::new();
        tracker.mark_rejected("abc123");

        let census = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let report = tracker.update_from_scan(&census);
        assert!(report.new_containers.is_empty());
    }

    fn compose_replica(ordinal: &str, explicit: bool) -> Container {
        let mut c = make_container(&format!("shop-web-{ordinal}"), "running");
        c.service_name = "web".into();
        c.service_name_explicit = explicit;
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        c.labels
            .insert("com.docker.compose.container-number".into(), ordinal.into());
        c
    }

    #[test]
    fn explicit_service_replicas_are_tracked_per_instance() {
        // Two replicas of one explicit service share a stable_id ("shop/web") but
        // have distinct stable_instance_ids. Scaling one away must report exactly
        // that replica as stopped — proving each instance is tracked, not the
        // workload as a whole.
        let mut tracker = ChangeTracker::new();
        tracker.update_from_scan(&Census {
            containers: vec![compose_replica("1", true), compose_replica("2", true)],
            ..Default::default()
        });
        tracker.commit_scan();

        let report = tracker.update_from_scan(&Census {
            containers: vec![compose_replica("2", true)],
            ..Default::default()
        });

        assert_eq!(report.stopped_containers.len(), 1);
        assert_eq!(report.stopped_containers[0].identifier, "shop/web/1");
        assert!(report.stopped_containers[0].explicit_service);
    }

    #[test]
    fn screener_inventory_replicas_stay_workload_level() {
        // Non-explicit (screener) replicas share the workload stable_id, so the
        // tracker stays coarse: scaling one replica away while the workload
        // remains reports no stop, and its loggable/stopped-match stay
        // workload-level (no per-replica churn).
        let mut tracker = ChangeTracker::new();
        tracker.update_from_scan(&Census {
            containers: vec![compose_replica("1", false), compose_replica("2", false)],
            ..Default::default()
        });
        tracker.commit_scan();

        let report = tracker.update_from_scan(&Census {
            containers: vec![compose_replica("2", false)],
            ..Default::default()
        });

        assert!(report.stopped_containers.is_empty());
    }

    #[test]
    fn require_full_resync_re_emits_every_lane_as_new() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![make_container("abc123", "running")],
            log_files: vec![make_log_file("/var/log/app.log")],
            systemd_services: vec![make_service("nginx.service")],
            installed_packages: vec![make_package("apt", "nginx", "1.18.0")],
            ..Default::default()
        };

        // Establish a committed baseline for every lane.
        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();
        let _ = tracker.update_packages_from_scan("agent-1", &census.installed_packages);
        tracker.commit_package_scan();

        // Steady state: an unchanged scan reports nothing new.
        assert!(tracker.update_from_scan(&census).is_empty());
        tracker.commit_scan();

        tracker.require_full_resync();

        // A commit that lands after the resync must not repopulate the cleared
        // maps — the next unchanged scan re-emits every entry as new.
        let report = tracker.update_from_scan(&census);
        assert_eq!(report.new_containers.len(), 1);
        assert_eq!(report.new_files.len(), 1);
        assert_eq!(report.new_services.len(), 1);
        assert!(report.stopped_containers.is_empty());
        assert!(report.stopped_files.is_empty());
        assert!(report.stopped_services.is_empty());

        let package_report =
            tracker.update_packages_from_scan("agent-1", &census.installed_packages);
        assert!(package_report.full_snapshot);
        assert_eq!(package_report.upsert_count, 1);
    }

    #[test]
    fn require_full_resync_is_idempotent_within_a_cycle() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();

        // Multiple lane responses can carry the flag in one cycle; repeating the
        // call must stay harmless.
        tracker.require_full_resync();
        tracker.require_full_resync();
        // A late commit is a no-op because pending was dropped.
        tracker.commit_scan();

        let report = tracker.update_from_scan(&census);
        assert_eq!(report.new_containers.len(), 1);
    }

    fn kamal_container(name: &str) -> Container {
        let mut c = make_container(name, "running");
        c.labels.insert("service".into(), "logpacer".into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    #[test]
    fn label_edit_with_unchanged_state_and_image_re_emits() {
        // A Kamal container gains a `role` label in place: state, image, and
        // log format are untouched, but the identifier atoms moved — census
        // must re-report or selector membership goes stale.
        let mut tracker = ChangeTracker::new();
        let _ = tracker.update_from_scan(&Census {
            containers: vec![kamal_container("logpacer-prod-1a2b3c4")],
            ..Default::default()
        });
        tracker.commit_scan();

        let mut edited = kamal_container("logpacer-prod-1a2b3c4");
        edited.labels.insert("role".into(), "web".into());
        let report = tracker.update_from_scan(&Census {
            containers: vec![edited],
            ..Default::default()
        });

        assert_eq!(report.changed_containers.len(), 1);
        assert_eq!(
            report.changed_containers[0]
                .identifier_set()
                .get("kamal.role")
                .map(String::as_str),
            Some("web")
        );
    }

    #[test]
    fn unchanged_identifier_atoms_do_not_re_emit() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![kamal_container("logpacer-prod-1a2b3c4")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();

        assert!(tracker.update_from_scan(&census).is_empty());
    }

    #[test]
    fn gaining_explicit_service_name_re_emits_and_re_routes() {
        // In-place opt-in: the container gains LOGPACER_SERVICE_NAME with
        // state/image unchanged. The atoms gain `service_name`, so the entry
        // re-emits — and the partition in agent.rs routes it to the services
        // census because it is now explicit.
        let mut tracker = ChangeTracker::new();
        let _ = tracker.update_from_scan(&Census {
            containers: vec![make_container("api-1", "running")],
            ..Default::default()
        });
        tracker.commit_scan();

        let mut opted_in = make_container("api-1", "running");
        opted_in.service_name = "api".into();
        opted_in.service_name_explicit = true;
        let report = tracker.update_from_scan(&Census {
            containers: vec![opted_in],
            ..Default::default()
        });

        assert_eq!(report.changed_containers.len(), 1);
        assert!(report.changed_containers[0].explicit_service());
    }

    #[test]
    fn multi_replica_screener_workload_reports_one_entry_without_churn() {
        // Three screener replicas share one workload key, so census gets ONE
        // entry (replicas ride in active_instances). Replica names differ —
        // container.name is an atom — so the comparison must pair replicas
        // deterministically or every scan would falsely re-emit.
        let mut tracker = ChangeTracker::new();
        let replicas = || {
            vec![
                compose_replica("1", false),
                compose_replica("2", false),
                compose_replica("3", false),
            ]
        };
        let report = tracker.update_from_scan(&Census {
            containers: replicas(),
            ..Default::default()
        });
        assert_eq!(report.new_containers.len(), 1);
        assert_eq!(report.new_containers[0].stable_id(), "shop/web");
        tracker.commit_scan();

        // Same replicas, reversed enumeration order: no change.
        let mut reversed = replicas();
        reversed.reverse();
        assert!(
            tracker
                .update_from_scan(&Census {
                    containers: reversed,
                    ..Default::default()
                })
                .is_empty()
        );
        tracker.commit_scan();

        // The replica roster is part of the census entry: scaling 3 → 2
        // re-emits the workload (as changed, not stopped — it still runs).
        let report = tracker.update_from_scan(&Census {
            containers: vec![compose_replica("1", false), compose_replica("2", false)],
            ..Default::default()
        });
        assert_eq!(report.changed_containers.len(), 1);
        assert!(report.stopped_containers.is_empty());
    }

    #[test]
    fn single_replica_drift_re_emits_the_workload() {
        let mut tracker = ChangeTracker::new();
        let _ = tracker.update_from_scan(&Census {
            containers: vec![compose_replica("1", false), compose_replica("2", false)],
            ..Default::default()
        });
        tracker.commit_scan();

        // Replica 2 rolls to a new image while replica 1 is untouched.
        let mut rolled = compose_replica("2", false);
        rolled.image = "nginx:1.29".into();
        let report = tracker.update_from_scan(&Census {
            containers: vec![compose_replica("1", false), rolled],
            ..Default::default()
        });

        assert_eq!(report.changed_containers.len(), 1);
    }

    #[test]
    fn full_report_marks_first_report_until_committed() {
        let mut tracker = ChangeTracker::new();
        // A fresh tracker has no acked baseline: its first report IS full.
        assert!(tracker.full_report());

        let census = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census);
        // Still full while the report is in flight; a failed POST (rollback)
        // must retry as a full report.
        assert!(tracker.full_report());
        tracker.rollback_scan();
        assert!(tracker.full_report());

        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();
        assert!(!tracker.full_report(), "acked baseline makes deltas");
    }

    #[test]
    fn full_report_marks_first_report_after_resync_clear() {
        let mut tracker = ChangeTracker::new();
        let census = Census {
            containers: vec![make_container("abc123", "running")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();
        assert!(!tracker.full_report());

        tracker.require_full_resync();
        assert!(tracker.full_report());
        // The late commit of the same cycle is a no-op (pending dropped) and
        // must not consume the marker before the full re-emit is acked.
        tracker.commit_scan();
        assert!(tracker.full_report());

        let report = tracker.update_from_scan(&census);
        assert_eq!(report.new_containers.len(), 1);
        tracker.commit_scan();
        assert!(!tracker.full_report(), "subsequent deltas are not full");
    }
}
