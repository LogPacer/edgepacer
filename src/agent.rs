//! Discovery agent loop — runs periodic discovery, tracks changes, reports to Rails.
//!
//! Mirrors legacy EdgePacer's `internal/agent/` package.
//! Orchestrates: bootstrap → discovery → tracker → type-specific reporting.

use crate::config::{SharedConfig, effective_poll_interval};
use crate::discovery::{self, Container, SharedDiscoveryCache};
use crate::sender::Client;
use crate::tracker::{ChangeTracker, InventoryReport, PackageLaneReport};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Run the discovery agent loop until shutdown.
pub async fn run(
    client: &Client,
    shared_config: SharedConfig,
    discovery_cache: SharedDiscoveryCache,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tracker = ChangeTracker::new();

    // Bootstrap: collect host metadata
    let metadata = crate::bootstrap::collect();

    let initial_poll_interval = effective_poll_interval(&shared_config, poll_interval).await;

    info!(
        hostname = %metadata.hostname,
        poll_secs = initial_poll_interval.as_secs(),
        "discovery agent starting"
    );

    // Initial discovery immediately, then poll
    loop {
        // Read scan_paths and the extension allowlist from config (dynamic —
        // changes on hot-reload). Both fall back to OS-aware defaults when unset.
        let scan_paths = extract_scan_paths(&shared_config).await;
        let scan_refs: Vec<&str> = scan_paths.iter().map(|s| s.as_str()).collect();
        let log_extensions = extract_log_extensions(&shared_config).await;
        let ext_refs: Vec<&str> = log_extensions.iter().map(|s| s.as_str()).collect();

        debug!(paths = ?scan_refs, extensions = ?ext_refs, "using scan paths");
        let include_runtime_processes = runtime_process_discovery_enabled(&shared_config).await;
        let census = discovery::discover_with_paths_and_runtime_processes(
            &scan_refs,
            &ext_refs,
            include_runtime_processes,
        )
        .await;
        let report = tracker.update_from_scan(&census);
        let package_report = if census.errors.contains_key("packages") {
            None
        } else {
            Some(
                tracker.update_packages_from_scan(client.resource_id(), &census.installed_packages),
            )
        };

        {
            let mut cache = discovery_cache.write().await;
            cache.update_all(&census);
            let stats = cache.stats();
            if stats.total() > 0 {
                debug!(
                    containers = stats.containers,
                    files = stats.files,
                    systemd = stats.systemd_services,
                    event_log = stats.event_log_channels,
                    "discovery cache updated"
                );
            }
        }

        if !report.is_empty() {
            match report_inventory(client, &mut tracker, &report, &census.containers).await {
                Ok(()) => tracker.commit_scan(),
                Err(e) => {
                    error!(error = %e, "failed to report inventory");
                    tracker.rollback_scan();
                }
            }
        } else {
            tracker.commit_scan();
        }

        // Report volatile snapshot data separately from compacted inventory lanes.
        report_snapshot_data(client, &mut tracker, &census).await;
        if let Some(package_report) = package_report {
            report_package_lane(client, &mut tracker, &package_report).await;
        }

        // Wait for next poll or shutdown.
        let interval = effective_poll_interval(&shared_config, poll_interval).await;
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = shutdown.changed() => {
                info!("discovery agent shutting down");
                return;
            }
        }
    }
}

async fn runtime_process_discovery_enabled(shared_config: &SharedConfig) -> bool {
    if !cfg!(all(target_os = "linux", feature = "ebpf")) {
        return false;
    }
    let config = shared_config.read().await;
    config
        .as_ref()
        .and_then(crate::config::ebpf_section)
        .is_some_and(|section| section.enabled)
}

/// Service-lane census entry. Stable identity only — the volatile container_id
/// / pod_uid are local-only handles EdgePacer resolves via DiscoveryCache and
/// never put on the wire.
fn service_census_entry(c: &Container) -> serde_json::Value {
    json!({
        "service_name": c.service_name,
        "service_name_explicit": true,
        "stable_instance_id": c.stable_instance_id(),
        "container_name": c.name,
        "image": c.image,
        "state": c.state,
        "namespace": c.namespace,
        "deployment": c.deployment,
        "format": c.log_format,
        "labels": c.labels,
        "identifiers": c.identifier_set(),
    })
}

/// Plain-container (screener) census entry. Stable identity only — the volatile
/// container_id / pod_name never cross the wire. The entry is workload-keyed;
/// each live replica rides in `active_instances` with its own per-instance
/// identity and atoms (a scaled Compose service, a Kamal web/rpc pair).
fn container_census_entry(c: &Container, active_instances: &[&Container]) -> serde_json::Value {
    json!({
        "identifier": c.stable_id(),
        "stable_instance_id": c.stable_instance_id(),
        "container_name": c.name,
        "image": c.image,
        "state": c.state,
        "namespace": c.namespace,
        "deployment": c.deployment,
        "service_name": c.service_name,
        "format": c.log_format,
        "labels": c.labels,
        "identifiers": c.identifier_set(),
        "active_instances": active_instances.iter().map(|i| json!({
            "stable_instance_id": i.stable_instance_id(),
            "state": i.state,
            "log_path": i.log_path,
            "identifiers": i.identifier_set(),
        })).collect::<Vec<_>>(),
    })
}

/// Every live replica of the workload a screener census entry stands for —
/// the tracker reports one representative per workload, so the replicas are
/// re-enumerated from the same scan's discovered containers.
fn workload_instances<'a>(entry: &Container, discovered: &'a [Container]) -> Vec<&'a Container> {
    let workload = entry.stable_id();
    let mut instances: Vec<&Container> = discovered
        .iter()
        // Running only: leftover exited containers from prior kamal deploys
        // share this workload's stable id but are not live replicas, so they
        // must not inflate the instance roster the control plane counts.
        .filter(|c| !c.explicit_service() && c.state == "running" && c.stable_id() == workload)
        .collect();
    instances.sort_by_key(|c| c.stable_instance_id());
    instances
}

/// Stamp the post-resync marker on a lane payload. A full report re-emits the
/// agent's whole world, so Rails may treat absent identifiers as stopped;
/// delta payloads stay unmarked (and byte-identical to before the marker).
fn stamp_full_report(mut payload: serde_json::Value, full_report: bool) -> serde_json::Value {
    if full_report {
        payload["full_report"] = json!(true);
    }
    payload
}

/// Report inventory changes to Rails via type-specific endpoints.
async fn report_inventory(
    client: &Client,
    tracker: &mut ChangeTracker,
    report: &InventoryReport,
    discovered_containers: &[Container],
) -> Result<(), crate::common::EdgepacerError> {
    // Server identity comes from the access token, not the request body.
    // Rails census controllers use AgentAuthentication to identify the server.

    // Captured once per cycle: a mid-cycle resync response sets the tracker's
    // marker for the NEXT cycle and must not stamp the remaining lane payloads
    // of this delta cycle.
    let full_report = tracker.full_report();

    // Report containers — ONLY explicit LogPacer service-name opt-ins take the
    // services census lane; everything else is server-sourced inventory for
    // the screener. (service_name alone is not consent: docker/CRI fill it
    // from compose labels / container names for every container.)
    // Non-explicit k8s containers ride the containers lane like docker ones:
    // the tracker keys screener containers per stable_id, so volume stays
    // workload-bounded, and their atoms make them selector-composable.
    let (services, containers): (Vec<&Container>, Vec<&Container>) = report
        .new_containers
        .iter()
        .chain(report.changed_containers.iter())
        .partition(|c| c.explicit_service());

    // Stop deltas split the same way: explicit services report to the services
    // census, plain containers to the containers census.
    let (stopped_services, stopped_containers): (Vec<_>, Vec<_>) = report
        .stopped_containers
        .iter()
        .partition(|s| s.explicit_service);

    // Services: containers explicitly opted in via a LogPacer service-name gate.
    if !services.is_empty() || !stopped_services.is_empty() {
        let payload = stamp_full_report(
            json!({
                            "services": services.iter().map(|&c| service_census_entry(c)).collect::<Vec<_>>(),
                "stopped_services": stopped_services.iter()
                    .map(|s| json!({ "identifier": s.identifier }))
                    .collect::<Vec<_>>(),
            }),
            full_report,
        );

        match client.report_service_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = services.len(),
                    status = ?resp.status,
                    "reported service inventory"
                );
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report service inventory");
                return Err(e);
            }
        }
    }

    // Plain containers (no explicit opt-in) — the screener's inventory
    if !containers.is_empty() || !stopped_containers.is_empty() {
        let payload = stamp_full_report(
            json!({
                            "containers": containers.iter()
                    .map(|&c| container_census_entry(c, &workload_instances(c, discovered_containers)))
                    .collect::<Vec<_>>(),
                "stopped_containers": stopped_containers.iter()
                    .map(|s| json!({ "identifier": s.identifier, "stable_identifier": s.identifier }))
                    .collect::<Vec<_>>(),
            }),
            full_report,
        );

        match client.report_container_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = containers.len(),
                    status = ?resp.status,
                    "reported container inventory"
                );
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report container inventory");
                return Err(e);
            }
        }
    }

    // Files
    if !report.new_files.is_empty() {
        let payload = json!({
                        "files": report.new_files.iter().map(|f| json!({
                "identifier": f.identifier(),
                "name": f.path.rsplit('/').next().unwrap_or(&f.path),
                "path": f.path,
                "size": f.size,
                "format": f.format,
                "permissions": f.permissions,
                "modified": f.modified,
                "line_count": f.line_count,
                "state": "active",
            })).collect::<Vec<_>>(),
        });

        match client.report_file_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = report.new_files.len(),
                    status = ?resp.status,
                    "reported file inventory"
                );
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report file inventory");
                return Err(e);
            }
        }
    }

    // Systemd services → journald
    if !report.new_services.is_empty() || !report.stopped_services.is_empty() {
        let payload = json!({
                        "units": report.new_services.iter().map(|s| json!({
                "identifier": s.identifier(),
                "unit_name": s.name,
                "active_state": s.active_state,
                "sub_state": s.sub_state,
                "load_state": s.load_state,
            })).collect::<Vec<_>>(),
            "stopped_units": report.stopped_services.iter()
                .map(|s| json!({ "identifier": s.identifier }))
                .collect::<Vec<_>>(),
        });

        match client.report_journald_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = report.new_services.len(),
                    status = ?resp.status,
                    "reported journald inventory"
                );
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report journald inventory");
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Report volatile snapshot inventory (processes, ports) — full replacement, no delta tracking.
///
/// These lanes POST every cycle regardless of whether the delta lanes changed,
/// so they are the reliable channel for the control plane to hand a quiet agent
/// its one-shot `full_resync_required` — the delta lanes in `report_inventory`
/// are skipped entirely when nothing changed, which is exactly when orphaned
/// rows persist. Honoring the flag here resets every delta lane.
async fn report_snapshot_data(
    client: &Client,
    tracker: &mut ChangeTracker,
    census: &discovery::Census,
) {
    // Processes
    if !census.processes.is_empty() {
        let payload = json!({
            "processes": census.processes,
        });
        match client.report_process_inventory(&payload).await {
            Ok(resp) => {
                debug!(count = census.processes.len(), status = ?resp.status, "reported process inventory");
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report process inventory");
            }
        }
    }

    // Listening ports
    if !census.listening_ports.is_empty() {
        let payload = json!({
            "listening_ports": census.listening_ports,
        });
        match client.report_port_inventory(&payload).await {
            Ok(resp) => {
                debug!(count = census.listening_ports.len(), status = ?resp.status, "reported port inventory");
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report port inventory");
            }
        }
    }

    // Windows Event Log channels — re-asserted each scan (Rails upserts
    // idempotently). Snapshot, not delta: channels rarely churn, and re-posting
    // keeps last_seen_at fresh so reviewable channels don't age into "quiet"
    // and drop out of the screener.
    if !census.event_log_channels.is_empty() {
        let payload = json!({
            "channels": census.event_log_channels.iter().map(|c| json!({
                "identifier": c.channel,
                "channel": c.channel,
                "record_count": c.record_count,
            })).collect::<Vec<_>>(),
        });
        match client.report_event_log_inventory(&payload).await {
            Ok(resp) => {
                debug!(
                    count = census.event_log_channels.len(),
                    status = ?resp.status,
                    "reported windows event log inventory"
                );
                if resp.full_resync_required.unwrap_or(false) {
                    tracker.require_full_resync();
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to report windows event log inventory");
            }
        }
    }
}

async fn report_package_lane(
    client: &Client,
    tracker: &mut ChangeTracker,
    report: &PackageLaneReport,
) {
    let payload = match serde_json::to_value(report) {
        Ok(payload) => payload,
        Err(e) => {
            warn!(error = %e, "failed to encode package inventory report");
            tracker.rollback_package_scan();
            return;
        }
    };

    match client.report_package_inventory(&payload).await {
        Ok(resp) => {
            debug!(
                item_count = report.item_count,
                events = report.events.len(),
                full_snapshot = report.full_snapshot,
                agent_sequence = report.agent_sequence,
                status = ?resp.status,
                "reported package inventory"
            );

            if resp.full_resync_required.unwrap_or(false) {
                // Any lane's flag clears every lane, not just packages — the
                // control plane sets one one-shot and can stamp it on whichever
                // census response reaches the agent first.
                tracker.require_full_resync();
            } else {
                tracker.commit_package_scan();
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to report package inventory");
            tracker.rollback_package_scan();
        }
    }
}

/// OS-aware default scan paths, used when config sets none.
fn default_scan_paths() -> Vec<String> {
    discovery::files::default_scan_paths()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Extract scan_paths from the unified config's discovery section, falling back
/// to OS-aware defaults when unset.
async fn extract_scan_paths(shared_config: &SharedConfig) -> Vec<String> {
    let cfg = shared_config.read().await;
    let Some(unified) = cfg.as_ref() else {
        return default_scan_paths();
    };

    let configured: Vec<String> = unified
        .raw
        .get("discovery")
        .and_then(|d| d.get("scan_paths"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if configured.is_empty() {
        default_scan_paths()
    } else {
        configured
    }
}

/// Extract the file-extension allowlist from the unified config's discovery
/// section, falling back to the default `.log`-only allowlist when unset.
async fn extract_log_extensions(shared_config: &SharedConfig) -> Vec<String> {
    let default = || -> Vec<String> {
        discovery::files::DEFAULT_LOG_EXTENSIONS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    let cfg = shared_config.read().await;
    let Some(unified) = cfg.as_ref() else {
        return default();
    };

    let configured: Vec<String> = unified
        .raw
        .get("discovery")
        .and_then(|d| d.get("log_extensions"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if configured.is_empty() {
        default()
    } else {
        configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::discovery::packages::Package;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_app_config(rails_url: String) -> AppConfig {
        AppConfig {
            resource_id: "agent-123".into(),
            rails_url,
            token: Some("bootstrap-1".into()),
            is_account_token: false,
            poll_interval_secs: 30,
            log_level: "info".into(),
            readiness_file: None,
            local_mode: false,
            directive_file: None,
            host_mode: true,
        }
    }

    fn package() -> Package {
        Package {
            manager: "apt".into(),
            name: "nginx".into(),
            version: "1.18.0".into(),
        }
    }

    #[tokio::test]
    async fn runtime_process_discovery_requires_runtime_ebpf_enablement() {
        let config = crate::config::shared_config();
        assert!(!runtime_process_discovery_enabled(&config).await);

        *config.write().await = Some(crate::config::UnifiedConfig::new(
            serde_json::json!({ "ebpf": { "enabled": false } }),
            "disabled".to_string(),
        ));
        assert!(!runtime_process_discovery_enabled(&config).await);

        *config.write().await = Some(crate::config::UnifiedConfig::new(
            serde_json::json!({ "ebpf": { "enabled": true } }),
            "enabled".to_string(),
        ));
        assert_eq!(
            runtime_process_discovery_enabled(&config).await,
            cfg!(all(target_os = "linux", feature = "ebpf"))
        );
    }

    #[tokio::test]
    async fn package_lane_success_commits_baseline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/census/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let packages = vec![package()];
        let mut tracker = ChangeTracker::new();

        let first = tracker.update_packages_from_scan(client.resource_id(), &packages);
        report_package_lane(&client, &mut tracker, &first).await;
        let second = tracker.update_packages_from_scan(client.resource_id(), &packages);

        assert!(!second.full_snapshot);
        assert_eq!(second.agent_sequence, 2);
        assert!(second.events.is_empty());
    }

    #[tokio::test]
    async fn package_lane_full_resync_response_keeps_full_snapshot_pending() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/census/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted",
                "full_resync_required": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let packages = vec![package()];
        let mut tracker = ChangeTracker::new();

        let first = tracker.update_packages_from_scan(client.resource_id(), &packages);
        report_package_lane(&client, &mut tracker, &first).await;
        let retry = tracker.update_packages_from_scan(client.resource_id(), &packages);

        assert!(retry.full_snapshot);
        assert_eq!(retry.agent_sequence, 1);
        assert_eq!(retry.upsert_count, 1);
    }

    fn k8s_statefulset_container() -> Container {
        Container {
            id: "default/postgres-0/db".into(),
            name: "postgres-0-db".into(),
            service_name: "postgres".into(),
            service_name_explicit: true,
            image: "postgres:17".into(),
            state: "running".into(),
            labels: Default::default(),
            env: vec![],
            runtime: "kubernetes".into(),
            log_path: "/var/log/pods/default_postgres-0_uid/db".into(),
            log_format: "plain_text".into(),
            pod_uid: "pod-uid-xyz".into(),
            pod_name: "postgres-0".into(),
            namespace: "default".into(),
            node_name: "node-1".into(),
            deployment: "postgres".into(),
            workload_kind: "statefulset".into(),
            container_id: "containerd://abc123".into(),
            container_name: "db".into(),
            runtime_process: None,
        }
    }

    #[test]
    fn census_entries_carry_stable_identity_and_never_volatile_handles() {
        let mut c = k8s_statefulset_container();
        c.log_format = "ndjson".into();
        c.runtime_process = Some(crate::discovery::RuntimeProcessIdentity {
            pid: 4242,
            start_time_ticks: 1234,
        });

        // Both lanes: the stable per-instance id is present, and no volatile
        // runtime handle (container_id / pod_uid / pod_name) crosses the wire.
        for entry in [service_census_entry(&c), container_census_entry(&c, &[])] {
            let obj = entry.as_object().expect("census entry is a JSON object");
            assert_eq!(
                obj.get("stable_instance_id").and_then(|v| v.as_str()),
                Some("default/postgres/db/0")
            );
            assert!(
                obj.get("container_id").is_none(),
                "container_id must never be reported"
            );
            assert!(
                obj.get("pod_id").is_none(),
                "pod_uid must never be reported"
            );
            assert!(
                obj.get("pod_name").is_none(),
                "pod_name must never be reported"
            );
            assert!(
                obj.get("runtime_process").is_none(),
                "runtime process identity must never be reported"
            );
            assert_eq!(obj.get("format").and_then(|v| v.as_str()), Some("ndjson"));
        }
    }

    #[test]
    fn census_entries_carry_identifier_atoms() {
        let c = k8s_statefulset_container();

        for entry in [service_census_entry(&c), container_census_entry(&c, &[])] {
            let atoms = entry
                .get("identifiers")
                .and_then(|v| v.as_object())
                .expect("census entry carries an identifiers object");
            assert_eq!(
                atoms.get("service_name").and_then(|v| v.as_str()),
                Some("postgres")
            );
            assert_eq!(
                atoms.get("k8s.namespace").and_then(|v| v.as_str()),
                Some("default")
            );
            assert_eq!(
                atoms.get("k8s.workload").and_then(|v| v.as_str()),
                Some("postgres")
            );
            assert_eq!(
                atoms.get("image.repo").and_then(|v| v.as_str()),
                Some("postgres")
            );
            // Volatile handles are never atoms.
            assert!(atoms.keys().all(|k| k != "container_id" && k != "pod_uid"));
        }
    }

    fn plain_container(id: &str) -> Container {
        Container {
            id: id.into(),
            name: id.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: "running".into(),
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

    #[tokio::test]
    async fn container_census_full_resync_response_forces_re_report() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/census/containers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted",
                "full_resync_required": true
            })))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let mut tracker = ChangeTracker::new();

        let census = discovery::Census {
            containers: vec![plain_container("abc123")],
            ..Default::default()
        };

        // First cycle: report the new container; the server demands a resync.
        let report = tracker.update_from_scan(&census);
        assert!(!report.is_empty());
        report_inventory(&client, &mut tracker, &report, &census.containers)
            .await
            .unwrap();
        // The caller commits on success — the resync must survive it.
        tracker.commit_scan();

        // The unchanged next scan re-emits the container as new.
        let next = tracker.update_from_scan(&census);
        assert_eq!(next.new_containers.len(), 1);
    }

    #[tokio::test]
    async fn process_snapshot_full_resync_response_resets_delta_lanes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/census/processes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted",
                "full_resync_required": true
            })))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let mut tracker = ChangeTracker::new();

        // Commit a container baseline, then confirm the lane is quiet.
        let census = discovery::Census {
            containers: vec![plain_container("abc123")],
            ..Default::default()
        };
        let _ = tracker.update_from_scan(&census);
        tracker.commit_scan();
        assert!(tracker.update_from_scan(&census).is_empty());
        tracker.commit_scan();

        // A quiet agent skips the delta lanes but still POSTs processes every
        // cycle — the flag rides that response and must reset the delta lanes.
        let snapshot = discovery::Census {
            processes: vec![crate::discovery::processes::Process {
                pid: 1,
                user: "root".into(),
                cpu: "0.0".into(),
                mem: "0.0".into(),
                command: "init".into(),
            }],
            ..Default::default()
        };
        report_snapshot_data(&client, &mut tracker, &snapshot).await;

        let next = tracker.update_from_scan(&census);
        assert_eq!(next.new_containers.len(), 1);
    }

    fn compose_replica(ordinal: &str) -> Container {
        let mut c = plain_container(&format!("shop-web-{ordinal}"));
        c.labels
            .insert("com.docker.compose.project".into(), "shop".into());
        c.labels
            .insert("com.docker.compose.service".into(), "web".into());
        c.labels
            .insert("com.docker.compose.container-number".into(), ordinal.into());
        c.log_path = format!("/var/lib/docker/containers/{ordinal}/{ordinal}-json.log");
        c
    }

    #[test]
    fn screener_census_entry_lists_every_replica_in_active_instances() {
        let discovered = vec![
            compose_replica("2"),
            compose_replica("1"),
            compose_replica("3"),
        ];
        let entry = container_census_entry(
            &discovered[0],
            &workload_instances(&discovered[0], &discovered),
        );

        // One workload-keyed entry; the replicas ride inside it, in stable order.
        assert_eq!(entry["identifier"], "shop/web");
        let instances = entry["active_instances"].as_array().unwrap();
        assert_eq!(instances.len(), 3);
        assert_eq!(
            instances
                .iter()
                .map(|i| i["stable_instance_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["shop/web/1", "shop/web/2", "shop/web/3"]
        );

        // Each instance ships its own log path and atom set; shared atoms
        // agree while container.name varies per replica.
        assert_eq!(
            instances[0]["log_path"],
            "/var/lib/docker/containers/1/1-json.log"
        );
        assert_eq!(instances[0]["identifiers"]["compose.project"], "shop");
        assert_eq!(instances[0]["identifiers"]["container.name"], "shop-web-1");
        assert_eq!(instances[2]["identifiers"]["container.name"], "shop-web-3");
    }

    fn kamal_replica(role: &str) -> Container {
        let mut c = plain_container(&format!("logpacer-{role}-prod-1a2b3c4"));
        c.labels.insert("service".into(), "logpacer".into());
        c.labels.insert("role".into(), role.into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    #[test]
    fn active_instances_carry_role_varying_atoms() {
        // Kamal web + rpc share one workload; the census entry stays single
        // but each instance carries its own kamal.role atom.
        let discovered = vec![kamal_replica("web"), kamal_replica("rpc")];
        let entry = container_census_entry(
            &discovered[0],
            &workload_instances(&discovered[0], &discovered),
        );

        assert_eq!(entry["identifier"], "logpacer-prod");
        let instances = entry["active_instances"].as_array().unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0]["identifiers"]["kamal.role"], "rpc");
        assert_eq!(instances[1]["identifiers"]["kamal.role"], "web");
    }

    fn k8s_deployment_pod(pod: &str) -> Container {
        Container {
            id: format!("prod/{pod}/api"),
            name: format!("{pod}-api"),
            // Derived label echo, NOT the explicit LOGPACER opt-in.
            service_name: "api".into(),
            service_name_explicit: false,
            image: "ghcr.io/logpacer/api:v1.4.3".into(),
            state: "running".into(),
            labels: Default::default(),
            env: vec![],
            runtime: "kubernetes".into(),
            log_path: format!("/var/log/pods/prod_{pod}_uid/api"),
            log_format: "plain_text".into(),
            pod_uid: format!("{pod}-uid"),
            pod_name: pod.into(),
            namespace: "prod".into(),
            node_name: "node-1".into(),
            deployment: "api".into(),
            workload_kind: "deployment".into(),
            container_id: format!("containerd://{pod}"),
            container_name: "api".into(),
            runtime_process: None,
        }
    }

    /// Non-explicit k8s containers ride the containers census lane like docker
    /// ones — at workload granularity, with their atoms — so they are
    /// selector-composable without a LOGPACER_SERVICE_NAME redeploy.
    #[tokio::test]
    async fn non_explicit_k8s_workload_reports_once_on_the_containers_lane() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/census/containers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted"
            })))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let mut tracker = ChangeTracker::new();

        let census = discovery::Census {
            containers: vec![
                k8s_deployment_pod("api-7b4f9c8d5-aaaaa"),
                k8s_deployment_pod("api-7b4f9c8d5-bbbbb"),
            ],
            ..Default::default()
        };
        let report = tracker.update_from_scan(&census);
        report_inventory(&client, &mut tracker, &report, &census.containers)
            .await
            .unwrap();

        let bodies: Vec<serde_json::Value> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        // Only the containers (screener) lane posts — no explicit opt-in means
        // no services-lane traffic.
        assert_eq!(bodies.len(), 1);
        let containers = bodies[0]["containers"].as_array().unwrap();
        assert_eq!(
            containers.len(),
            1,
            "replicas coarsen to one workload entry"
        );

        let entry = &containers[0];
        assert_eq!(entry["identifier"], "prod/api/api");
        assert_eq!(entry["identifiers"]["k8s.namespace"], "prod");
        assert_eq!(entry["identifiers"]["k8s.workload"], "api");
        assert_eq!(entry["identifiers"]["k8s.container"], "api");
        assert_eq!(entry["identifiers"]["image.repo"], "ghcr.io/logpacer/api");
        // Each live pod rides inside the workload entry, never as its own entry.
        let instances = entry["active_instances"].as_array().unwrap();
        assert_eq!(instances.len(), 2);
    }

    /// Explicit LOGPACER_SERVICE_NAME k8s containers keep their services-lane
    /// routing — the gate lift only adds the screener lane for the rest.
    #[tokio::test]
    async fn explicit_k8s_container_still_reports_on_the_services_lane() {
        let server = MockServer::start().await;
        for lane in ["containers", "services"] {
            Mock::given(method("POST"))
                .and(path(format!("/api/v1/census/{lane}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "accepted"
                })))
                .mount(&server)
                .await;
        }

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let mut tracker = ChangeTracker::new();

        let census = discovery::Census {
            containers: vec![k8s_statefulset_container()],
            ..Default::default()
        };
        let report = tracker.update_from_scan(&census);
        report_inventory(&client, &mut tracker, &report, &census.containers)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].url.path().ends_with("/census/services"));
    }

    #[tokio::test]
    async fn census_lanes_stamp_full_report_only_on_full_re_emits() {
        let server = MockServer::start().await;
        for lane in ["containers", "services"] {
            Mock::given(method("POST"))
                .and(path(format!("/api/v1/census/{lane}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "accepted"
                })))
                .mount(&server)
                .await;
        }

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");
        let mut tracker = ChangeTracker::new();

        let mut service = plain_container("api-1");
        service.service_name = "api".into();
        service.service_name_explicit = true;
        let census = discovery::Census {
            containers: vec![plain_container("web-1"), service],
            ..Default::default()
        };

        // Cycle 1: a fresh tracker's first report is a full re-emit.
        let report = tracker.update_from_scan(&census);
        report_inventory(&client, &mut tracker, &report, &census.containers)
            .await
            .unwrap();
        tracker.commit_scan();

        // Cycle 2: a state change is a delta.
        let mut changed = census.clone();
        changed.containers[0].state = "exited".into();
        changed.containers[1].state = "exited".into();
        let report = tracker.update_from_scan(&changed);
        report_inventory(&client, &mut tracker, &report, &changed.containers)
            .await
            .unwrap();
        tracker.commit_scan();

        // Cycle 3: the control plane demanded a resync — full again.
        tracker.require_full_resync();
        let report = tracker.update_from_scan(&changed);
        report_inventory(&client, &mut tracker, &report, &changed.containers)
            .await
            .unwrap();

        let bodies: Vec<serde_json::Value> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        assert_eq!(bodies.len(), 6, "two lanes over three cycles");
        // Full re-emits (start + post-resync) are marked on both lanes...
        for body in [&bodies[0], &bodies[1], &bodies[4], &bodies[5]] {
            assert_eq!(body["full_report"], true);
        }
        // ...deltas carry no marker at all (absent, not false).
        for body in [&bodies[2], &bodies[3]] {
            assert!(body.get("full_report").is_none());
        }
    }
}
