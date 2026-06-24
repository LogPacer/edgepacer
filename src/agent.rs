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
        // Read scan_paths from config (dynamic — changes on hot-reload).
        let scan_paths = extract_scan_paths(&shared_config).await;
        let scan_refs: Vec<&str> = scan_paths.iter().map(|s| s.as_str()).collect();

        let census = if scan_refs.is_empty() {
            discovery::discover().await
        } else {
            debug!(paths = ?scan_refs, "using config-driven scan paths");
            discovery::discover_with_paths(&scan_refs).await
        };
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
                    "discovery cache updated"
                );
            }
        }

        if !report.is_empty() {
            match report_inventory(client, &report).await {
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
        report_snapshot_data(client, &census).await;
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
        "labels": c.labels,
    })
}

/// Plain-container (screener) census entry. Stable identity only — the volatile
/// container_id / pod_name never cross the wire.
fn container_census_entry(c: &Container) -> serde_json::Value {
    json!({
        "identifier": c.stable_id(),
        "stable_instance_id": c.stable_instance_id(),
        "container_name": c.name,
        "image": c.image,
        "state": c.state,
        "namespace": c.namespace,
        "deployment": c.deployment,
        "service_name": c.service_name,
        "labels": c.labels,
    })
}

/// Report inventory changes to Rails via type-specific endpoints.
async fn report_inventory(
    client: &Client,
    report: &InventoryReport,
) -> Result<(), crate::common::EdgepacerError> {
    // Server identity comes from the access token, not the request body.
    // Rails census controllers use AgentAuthentication to identify the server.

    // Report containers — ONLY explicit LogPacer service-name opt-ins take the
    // services census lane; everything else is server-sourced inventory for
    // the screener. (service_name alone is not consent: docker/CRI fill it
    // from compose labels / container names for every container.)
    // K8s containers without explicit service-name opt-in stay skipped from
    // the container census — matches Go agent behavior.
    let (services, containers): (Vec<&Container>, Vec<&Container>) = report
        .new_containers
        .iter()
        .chain(report.changed_containers.iter())
        .partition(|c| c.explicit_service());

    let containers: Vec<&Container> = containers
        .into_iter()
        .filter(|c| c.runtime != "kubernetes")
        .collect();

    // Stop deltas split the same way: explicit services report to the services
    // census, plain containers to the containers census.
    let (stopped_services, stopped_containers): (Vec<_>, Vec<_>) = report
        .stopped_containers
        .iter()
        .partition(|s| s.explicit_service);

    // Services: containers explicitly opted in via a LogPacer service-name gate.
    if !services.is_empty() || !stopped_services.is_empty() {
        let payload = json!({
                        "services": services.iter().map(|&c| service_census_entry(c)).collect::<Vec<_>>(),
            "stopped_services": stopped_services.iter()
                .map(|s| json!({ "identifier": s.identifier }))
                .collect::<Vec<_>>(),
        });

        match client.report_service_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = services.len(),
                    status = ?resp.status,
                    "reported service inventory"
                );
            }
            Err(e) => {
                warn!(error = %e, "failed to report service inventory");
                return Err(e);
            }
        }
    }

    // Plain containers (no explicit opt-in) — the screener's inventory
    if !containers.is_empty() || !stopped_containers.is_empty() {
        let payload = json!({
                        "containers": containers.iter().map(|&c| container_census_entry(c)).collect::<Vec<_>>(),
            "stopped_containers": stopped_containers.iter()
                .map(|s| json!({ "identifier": s.identifier, "stable_identifier": s.identifier }))
                .collect::<Vec<_>>(),
        });

        match client.report_container_inventory(&payload).await {
            Ok(resp) => {
                info!(
                    count = containers.len(),
                    status = ?resp.status,
                    "reported container inventory"
                );
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
async fn report_snapshot_data(client: &Client, census: &discovery::Census) {
    // Processes
    if !census.processes.is_empty() {
        let payload = json!({
            "processes": census.processes,
        });
        match client.report_process_inventory(&payload).await {
            Ok(resp) => {
                debug!(count = census.processes.len(), status = ?resp.status, "reported process inventory");
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
            }
            Err(e) => {
                warn!(error = %e, "failed to report port inventory");
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
                tracker.require_package_full_resync();
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

/// Extract scan_paths from the unified config's discovery section.
async fn extract_scan_paths(shared_config: &SharedConfig) -> Vec<String> {
    let cfg = shared_config.read().await;
    let Some(unified) = cfg.as_ref() else {
        return Vec::new();
    };

    unified
        .raw
        .get("discovery")
        .and_then(|d| d.get("scan_paths"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
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
            pod_uid: "pod-uid-xyz".into(),
            pod_name: "postgres-0".into(),
            namespace: "default".into(),
            node_name: "node-1".into(),
            deployment: "postgres".into(),
            workload_kind: "statefulset".into(),
            container_id: "containerd://abc123".into(),
            container_name: "db".into(),
        }
    }

    #[test]
    fn census_entries_carry_stable_identity_and_never_volatile_handles() {
        let c = k8s_statefulset_container();

        // Both lanes: the stable per-instance id is present, and no volatile
        // runtime handle (container_id / pod_uid / pod_name) crosses the wire.
        for entry in [service_census_entry(&c), container_census_entry(&c)] {
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
        }
    }
}
