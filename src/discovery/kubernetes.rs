//! Kubernetes pod discovery — in-cluster enumeration via kube-rs.
//!
//! When running as a DaemonSet inside a K8s cluster, discovers all pods on the
//! local node via the Kubernetes API. Gracefully returns an empty vec when not
//! running in-cluster.

use crate::discovery::Container;
use k8s_openapi::api::core::v1::{Container as PodContainer, Pod, PodSpec};
use kube::{
    Client,
    api::{Api, ListParams},
};
use std::collections::{BTreeMap, HashMap};
use tracing::info;

const LOGPACER_SERVICE_NAME_ENV: &str = "LOGPACER_SERVICE_NAME";
const LOGPACER_SERVICE_NAME_METADATA_KEY: &str = "logpacer.com/service-name";

/// Check if we're running inside a Kubernetes cluster by looking for the
/// service account token that kubelet mounts into every pod.
pub fn is_running_in_kubernetes() -> bool {
    std::path::Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists()
}

/// Discover all pods on the current node (DaemonSet pattern).
///
/// Returns `Ok(vec![])` when not running in-cluster — this is normal for
/// bare-metal or Docker-only hosts.
pub async fn discover_kubernetes_pods() -> Result<Vec<Container>, String> {
    if !is_running_in_kubernetes() {
        return Ok(vec![]);
    }

    let client = Client::try_default()
        .await
        .map_err(|e| format!("kube client creation failed: {}", e))?;

    let node = std::env::var("NODE_NAME").map_err(|_| {
        "NODE_NAME env var not set — required for DaemonSet pod discovery".to_string()
    })?;

    let pods: Api<Pod> = Api::all(client);
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node));

    let pod_list = pods
        .list(&lp)
        .await
        .map_err(|e| format!("pod listing failed: {}", e))?;

    let pod_logs_dir = resolve_pod_logs_dir();
    let mut containers = Vec::new();

    for pod in &pod_list.items {
        containers.extend(process_pod(pod, &pod_logs_dir));
    }

    info!(count = containers.len(), node = %node, "discovered kubernetes pods");
    Ok(containers)
}

/// Extract containers from a pod, mapping to the shared `Container` struct.
pub fn process_pod(pod: &Pod, pod_logs_dir: &str) -> Vec<Container> {
    let mut containers = Vec::new();

    let metadata = &pod.metadata;
    let pod_uid = metadata.uid.as_deref().unwrap_or("");
    let pod_name = metadata.name.as_deref().unwrap_or("");
    let namespace = metadata.namespace.as_deref().unwrap_or("default");
    let labels = metadata.labels.clone().unwrap_or_default();

    let Some(spec) = &pod.spec else {
        return containers;
    };

    let node_name = spec.node_name.as_deref().unwrap_or("");
    let (workload_name, workload_kind, _replica_set) = get_workload_owner(pod);

    let pod_phase = pod
        .status
        .as_ref()
        .and_then(|s| s.phase.as_deref())
        .unwrap_or("Unknown");
    let pod_state = map_pod_phase(pod_phase);

    let Some(service_name) = explicit_service_name_for_pod(pod, spec) else {
        return containers;
    };

    // Convert BTreeMap labels to HashMap
    let labels_map: HashMap<String, String> = labels.into_iter().collect();

    for container in &spec.containers {
        let (mut state, container_id) = get_container_state(pod, &container.name);
        if state == "unknown" {
            state = pod_state.to_string();
        }

        let log_path = format!(
            "{}/{}_{}_{}/{}",
            pod_logs_dir, namespace, pod_name, pod_uid, container.name
        );

        containers.push(Container {
            id: format!("{}/{}/{}", namespace, pod_name, container.name),
            name: format!("{}-{}", pod_name, container.name),
            container_name: container.name.clone(),
            service_name: service_name.clone(),
            service_name_explicit: true,
            image: container.image.clone().unwrap_or_default(),
            state,
            labels: labels_map.clone(),
            runtime: "kubernetes".into(),
            log_path,
            pod_uid: pod_uid.to_string(),
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
            node_name: node_name.to_string(),
            deployment: workload_name.clone(),
            workload_kind: workload_kind.clone(),
            container_id: container_id.unwrap_or_default(),
            env: vec![],
        });
    }

    containers
}

fn explicit_service_name_for_pod(pod: &Pod, spec: &PodSpec) -> Option<String> {
    let metadata_service_name = metadata_service_name(
        pod.metadata.annotations.as_ref(),
        pod.metadata.labels.as_ref(),
    )?;
    let env_service_name = env_service_name(&spec.containers)?;

    match (metadata_service_name, env_service_name) {
        (Some(metadata), Some(env)) if metadata == env => Some(metadata),
        (Some(_), Some(_)) => None,
        (Some(metadata), None) => Some(metadata),
        (None, Some(env)) => Some(env),
        (None, None) => None,
    }
}

fn metadata_service_name(
    annotations: Option<&BTreeMap<String, String>>,
    labels: Option<&BTreeMap<String, String>>,
) -> Option<Option<String>> {
    let annotation = annotations
        .and_then(|map| map.get(LOGPACER_SERVICE_NAME_METADATA_KEY))
        .and_then(|value| non_empty_service_name(value));
    let label = labels
        .and_then(|map| map.get(LOGPACER_SERVICE_NAME_METADATA_KEY))
        .and_then(|value| non_empty_service_name(value));

    match (annotation, label) {
        (Some(annotation), Some(label)) if annotation == label => Some(Some(annotation)),
        (Some(_), Some(_)) => None,
        (Some(annotation), None) => Some(Some(annotation)),
        (None, Some(label)) => Some(Some(label)),
        (None, None) => Some(None),
    }
}

fn env_service_name(containers: &[PodContainer]) -> Option<Option<String>> {
    let mut service_name: Option<String> = None;

    for container in containers {
        let Some(env) = &container.env else {
            continue;
        };

        for var in env {
            if var.name != LOGPACER_SERVICE_NAME_ENV {
                continue;
            }

            // `valueFrom` only names another K8s source; it does not expose the
            // resolved value in the pod spec. Use the metadata opt-in when the
            // runtime env value comes from a Secret or ConfigMap.
            let Some(value) = var.value.as_deref().and_then(non_empty_service_name) else {
                continue;
            };

            match &service_name {
                Some(existing) if existing != &value => return None,
                Some(_) => {}
                None => service_name = Some(value),
            }
        }
    }

    Some(service_name)
}

fn non_empty_service_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Extract workload owner from pod owner references.
///
/// Traverses owner refs to find the top-level workload:
/// - ReplicaSet → strip hash suffix → Deployment name
/// - StatefulSet, DaemonSet, Job, CronJob → use directly
/// - Fallback: `app` or `app.kubernetes.io/name` label, then pod name
pub fn get_workload_owner(pod: &Pod) -> (String, String, String) {
    if let Some(owner_refs) = &pod.metadata.owner_references {
        for owner in owner_refs {
            match owner.kind.as_str() {
                "ReplicaSet" => {
                    let rs_name = owner.name.clone();
                    // Deployment creates ReplicaSets named <deployment>-<hash>
                    if let Some(idx) = rs_name.rfind('-') {
                        return (rs_name[..idx].to_string(), "deployment".into(), rs_name);
                    }
                    return (rs_name.clone(), "replicaset".into(), rs_name);
                }
                "StatefulSet" => return (owner.name.clone(), "statefulset".into(), String::new()),
                "DaemonSet" => return (owner.name.clone(), "daemonset".into(), String::new()),
                "Job" => return (owner.name.clone(), "job".into(), String::new()),
                "CronJob" => return (owner.name.clone(), "cronjob".into(), String::new()),
                _ => {}
            }
        }
    }

    // Fallback to labels
    if let Some(labels) = &pod.metadata.labels {
        if let Some(app) = labels.get("app") {
            return (app.clone(), "unknown".into(), String::new());
        }
        if let Some(app) = labels.get("app.kubernetes.io/name") {
            return (app.clone(), "unknown".into(), String::new());
        }
    }

    let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");
    (pod_name.to_string(), "unknown".into(), String::new())
}

/// Get container state from pod status — checks container_statuses for
/// running/waiting/terminated, falls back to pod phase.
pub fn get_container_state(pod: &Pod, container_name: &str) -> (String, Option<String>) {
    if let Some(status) = &pod.status
        && let Some(container_statuses) = &status.container_statuses
    {
        for cs in container_statuses {
            if cs.name == container_name {
                let container_id = cs.container_id.clone().unwrap_or_default();
                if let Some(state) = &cs.state {
                    if state.running.is_some() {
                        return ("running".into(), Some(container_id));
                    }
                    if state.waiting.is_some() {
                        return ("waiting".into(), Some(container_id));
                    }
                    if state.terminated.is_some() {
                        return ("terminated".into(), Some(container_id));
                    }
                }
                return ("unknown".into(), Some(container_id));
            }
        }
    }
    ("unknown".into(), None)
}

/// Map Kubernetes pod phase to a normalized state string.
fn map_pod_phase(phase: &str) -> &str {
    match phase {
        "Running" => "running",
        "Pending" => "pending",
        "Succeeded" => "succeeded",
        "Failed" => "failed",
        _ => "unknown",
    }
}

/// Resolve the pod logs directory — checks `POD_LOGS_DIR` env var,
/// defaults to `/var/log/pods`.
pub fn resolve_pod_logs_dir() -> String {
    std::env::var("POD_LOGS_DIR").unwrap_or_else(|_| "/var/log/pods".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{EnvFromSource, EnvVar, EnvVarSource, Pod, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
    use std::collections::BTreeMap;

    fn service_name_env(value: &str) -> EnvVar {
        EnvVar {
            name: LOGPACER_SERVICE_NAME_ENV.into(),
            value: Some(value.into()),
            ..Default::default()
        }
    }

    fn make_pod_with_owner(kind: &str, name: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("test-pod".into()),
                namespace: Some("default".into()),
                uid: Some("test-uid".into()),
                owner_references: Some(vec![OwnerReference {
                    kind: kind.into(),
                    name: name.into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "app".into(),
                    image: Some("nginx:latest".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn set_service_annotation(pod: &mut Pod, value: &str) {
        let mut annotations = BTreeMap::new();
        annotations.insert(LOGPACER_SERVICE_NAME_METADATA_KEY.into(), value.into());
        pod.metadata.annotations = Some(annotations);
    }

    fn set_service_label(pod: &mut Pod, value: &str) {
        let mut labels = pod.metadata.labels.clone().unwrap_or_default();
        labels.insert(LOGPACER_SERVICE_NAME_METADATA_KEY.into(), value.into());
        pod.metadata.labels = Some(labels);
    }

    #[test]
    fn log_path_includes_namespace_prefix() {
        let mut pod = make_pod_with_owner("ReplicaSet", "nginx-deploy-7b4f9c8d5");
        set_service_annotation(&mut pod, "nginx");
        let containers = process_pod(&pod, "/var/log/pods");
        assert_eq!(containers.len(), 1);
        assert_eq!(
            containers[0].log_path,
            "/var/log/pods/default_test-pod_test-uid/app"
        );
        assert_eq!(containers[0].container_name, "app");
    }

    #[test]
    fn pod_annotation_opts_in_service_name() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        set_service_annotation(&mut pod, "checkout-api");

        let containers = process_pod(&pod, "/var/log/pods");

        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].service_name, "checkout-api");
        assert!(containers[0].service_name_explicit);
    }

    #[test]
    fn pod_label_opts_in_service_name() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        set_service_label(&mut pod, "checkout-worker");

        let containers = process_pod(&pod, "/var/log/pods");

        assert_eq!(containers[0].service_name, "checkout-worker");
        assert!(containers[0].service_name_explicit);
    }

    #[test]
    fn matching_annotation_and_label_opt_in() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        set_service_annotation(&mut pod, "checkout-api");
        set_service_label(&mut pod, "checkout-api");

        let containers = process_pod(&pod, "/var/log/pods");

        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].service_name, "checkout-api");
        assert!(containers[0].service_name_explicit);
    }

    #[test]
    fn direct_env_remains_compatibility_opt_in() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        let spec = pod.spec.as_mut().unwrap();
        spec.containers[0].env = Some(vec![service_name_env("checkout-env")]);

        let containers = process_pod(&pod, "/var/log/pods");

        assert_eq!(containers[0].service_name, "checkout-env");
        assert!(containers[0].service_name_explicit);
    }

    #[test]
    fn pod_without_opt_in_is_ignored() {
        let pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");

        let containers = process_pod(&pod, "/var/log/pods");

        assert!(containers.is_empty());
    }

    #[test]
    fn env_from_only_is_not_explicit_opt_in() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        let spec = pod.spec.as_mut().unwrap();
        spec.containers[0].env_from = Some(vec![EnvFromSource::default()]);

        let containers = process_pod(&pod, "/var/log/pods");

        assert!(containers.is_empty());
    }

    #[test]
    fn value_from_only_is_not_explicit_opt_in() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        let spec = pod.spec.as_mut().unwrap();
        spec.containers[0].env = Some(vec![EnvVar {
            name: LOGPACER_SERVICE_NAME_ENV.into(),
            value_from: Some(EnvVarSource::default()),
            ..Default::default()
        }]);

        let containers = process_pod(&pod, "/var/log/pods");

        assert!(containers.is_empty());
    }

    #[test]
    fn conflicting_metadata_and_env_fail_closed() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        set_service_annotation(&mut pod, "checkout-api");
        let spec = pod.spec.as_mut().unwrap();
        spec.containers[0].env = Some(vec![service_name_env("checkout-worker")]);

        let containers = process_pod(&pod, "/var/log/pods");

        assert!(containers.is_empty());
    }

    #[test]
    fn conflicting_annotation_and_label_fail_closed() {
        let mut pod = make_pod_with_owner("ReplicaSet", "checkout-7b4f9c8d5");
        set_service_annotation(&mut pod, "checkout-api");
        set_service_label(&mut pod, "checkout-worker");

        let containers = process_pod(&pod, "/var/log/pods");

        assert!(containers.is_empty());
    }

    #[test]
    fn test_workload_owner_from_replicaset() {
        let pod = make_pod_with_owner("ReplicaSet", "nginx-deploy-7b4f9c8d5");
        let (name, kind, rs) = get_workload_owner(&pod);
        assert_eq!(name, "nginx-deploy");
        assert_eq!(kind, "deployment");
        assert_eq!(rs, "nginx-deploy-7b4f9c8d5");
    }

    #[test]
    fn test_workload_owner_from_statefulset() {
        let pod = make_pod_with_owner("StatefulSet", "postgres");
        let (name, kind, rs) = get_workload_owner(&pod);
        assert_eq!(name, "postgres");
        assert_eq!(kind, "statefulset");
        assert_eq!(rs, "");
    }

    #[test]
    fn test_workload_owner_from_daemonset() {
        let pod = make_pod_with_owner("DaemonSet", "fluentbit");
        let (name, kind, rs) = get_workload_owner(&pod);
        assert_eq!(name, "fluentbit");
        assert_eq!(kind, "daemonset");
        assert_eq!(rs, "");
    }

    #[test]
    fn test_workload_owner_fallback_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "my-service".into());

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("test-pod".into()),
                namespace: Some("default".into()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "app".into(),
                    image: Some("nginx:latest".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let (name, kind, _) = get_workload_owner(&pod);
        assert_eq!(name, "my-service");
        assert_eq!(kind, "unknown");
    }

    #[test]
    fn test_pod_logs_dir_default() {
        // Clear env var to test default
        // SAFETY: This test runs single-threaded; no other thread reads POD_LOGS_DIR.
        unsafe { std::env::remove_var("POD_LOGS_DIR") };
        assert_eq!(resolve_pod_logs_dir(), "/var/log/pods");
    }

    #[test]
    fn test_not_in_kubernetes() {
        // On a dev machine, the service account token won't exist
        assert!(!is_running_in_kubernetes());
    }
}
