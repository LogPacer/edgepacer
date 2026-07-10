//! Service descriptions — selector-backed collection from unified config.
//!
//! The `services` section is an ORDERED array: order is match priority and the
//! first description whose selector matches a container claims it. A selector
//! is an AND-set of atom equalities evaluated against the container's
//! `identifier_set()` — no patterns, no semantics. The `collect` payload reuses
//! the legacy V3 stream shape, carrying the legacy `log_source_id` so the
//! orchestrator can adopt its checkpoint state dir at the env-var→selector
//! cutover.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, HashSet};

use tracing::warn;

use super::UnifiedConfig;
use super::fields::{
    ArchiveId, ConfigFieldError, FieldContext, LogSourceId, RepoId, WireEndpoint, bool_field_or,
    optional_string_field, required_config_string, warn_config_field_error,
};
use super::logs::{
    CollectDiagnostic, CollectStreamConfig, ResolvedCollectStreams, parse_multiline_config,
    route_source,
};
use crate::discovery::Container;
use crate::discovery::cache::{DiscoveryCache, MatchStatus};

/// One service description from the unified config `services` array.
#[derive(Debug, Clone)]
pub struct ServiceDescription {
    pub service_slug: String,
    /// AND-set of atom equalities; empty never matches.
    pub selector: BTreeMap<String, String>,
    /// The reused legacy V3 stream config. Its `log_source_id` is the LEGACY
    /// id — synthesized per-container ids extend it, and checkpoint adoption
    /// keys on it.
    pub collect: CollectStreamConfig,
}

impl ServiceDescription {
    /// The per-container stream this description drives. The `config_hash`
    /// stays the collect payload's — selector content never feeds it, so a
    /// criteria edit that still matches the same containers is a pipeline
    /// no-op and checkpoints survive.
    fn stream_for(&self, log_source_id: String) -> CollectStreamConfig {
        CollectStreamConfig {
            log_source_id,
            ..self.collect.clone()
        }
    }
}

/// A legacy→synthesized state-dir adoption candidate: the description's legacy
/// stream id and the synthesized source that replaces it for one container.
/// The orchestrator renames the legacy checkpoint dir when the swap happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointAdoption {
    pub legacy_log_source_id: String,
    pub log_source_id: String,
}

/// Parse unified config `services` array entries. Absent or empty is a no-op;
/// a malformed entry is skipped with a warning and the rest still applies;
/// unknown fields are ignored.
pub fn all_service_descriptions(config: &UnifiedConfig) -> Vec<ServiceDescription> {
    let Some(services) = config.raw.get("services").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    services
        .iter()
        .enumerate()
        .filter_map(|(position, entry)| {
            let slug = optional_string_field(entry, "service_slug").unwrap_or_default();
            let entry_label = if slug.is_empty() {
                format!("#{position}")
            } else {
                slug.clone()
            };
            let ctx = FieldContext::entry("services", &entry_label);

            let selector = parse_selector(entry.get("selector"), ctx)?;
            let Some(collect_value) = entry.get("collect") else {
                warn_config_field_error(&ConfigFieldError::invalid_field(
                    ctx,
                    "collect",
                    "collect stream object",
                ));
                return None;
            };
            let collect = parse_collect(collect_value, ctx)?;

            Some(ServiceDescription {
                service_slug: slug,
                selector,
                collect,
            })
        })
        .collect()
}

/// Whether a selector matches a container's identifier atoms: every selector
/// pair equals the atom of the same kind (pure subset equality — no patterns,
/// no semantics). An empty selector never matches. Shared truth table with
/// Rails: `tests/fixtures/matcher_parity.json`.
pub fn selector_matches<K>(selector: &BTreeMap<String, String>, atoms: &BTreeMap<K, String>) -> bool
where
    K: Borrow<str> + Ord,
{
    !selector.is_empty()
        && selector
            .iter()
            .all(|(kind, value)| atoms.get(kind.as_str()) == Some(value))
}

/// Evaluate descriptions in array order against every discovered container —
/// first match claims the container — and synthesize one source per claimed
/// container into the existing pipeline lanes. Returns the claimed containers'
/// access locators so legacy directive resolution can skip them: one pipeline
/// per container, even while Rails dual-emits legacy streams.
pub(super) fn resolve_service_descriptions(
    descriptions: &[ServiceDescription],
    cache: &DiscoveryCache,
    resolved: &mut ResolvedCollectStreams,
) -> HashSet<String> {
    let mut claimed_locators = HashSet::new();
    if descriptions.is_empty() {
        return claimed_locators;
    }

    let containers = cache.distinct_containers();
    let mut claimed_ids: HashSet<&str> = HashSet::new();
    // Synthesis-time uniqueness over the state-dir key: sanitize_id folds
    // `/ \ : . space` to `_`, so two distinct synthesized ids could otherwise
    // share one checkpoint/buffer dir.
    let mut state_dir_keys: HashMap<String, String> = HashMap::new();

    for description in descriptions {
        for container in &containers {
            if claimed_ids.contains(container.id.as_str()) {
                continue;
            }
            if !selector_matches(&description.selector, &container.identifier_set()) {
                continue;
            }
            claimed_ids.insert(container.id.as_str());

            let log_source_id =
                synthesized_source_id(&description.collect.log_source_id, container);
            let dir_key = sanitize_id(&log_source_id);
            if let Some(existing) = state_dir_keys.get(&dir_key) {
                warn!(
                    log_source_id = %log_source_id,
                    collides_with = %existing,
                    "synthesized source ids collide after sanitization, skipping source"
                );
                continue;
            }
            state_dir_keys.insert(dir_key, log_source_id.clone());

            let locator = container.log_locator();
            if locator.is_empty() {
                resolved.diagnostics.push(CollectDiagnostic {
                    log_source_id,
                    status: MatchStatus::NotFound,
                    detail: format!(
                        "matched container {} has no readable log locator",
                        container.stable_instance_id()
                    ),
                });
                continue;
            }
            claimed_locators.insert(locator.clone());

            let stream = description.stream_for(log_source_id.clone());
            route_source(
                resolved,
                &stream,
                container.determine_access_method(),
                locator,
            );
            resolved.diagnostics.push(CollectDiagnostic {
                log_source_id: log_source_id.clone(),
                status: MatchStatus::Matched,
                detail: format!("via selector (service {})", description.service_slug),
            });
            resolved.checkpoint_adoptions.push(CheckpointAdoption {
                legacy_log_source_id: description.collect.log_source_id.clone(),
                log_source_id,
            });
        }
    }

    claimed_locators
}

/// Source id for one matched container: `{collect.log_source_id}/{stable_instance_id}`.
/// Fungible k8s replicas — per-instance identity degenerates to the workload id
/// (Deployment/Job/CronJob pods, DaemonSet without a node) — get the pod name
/// appended so two same-node replicas synthesize distinct sources; their
/// checkpoint continuity is per-pod-lifetime by nature (the log file dies with
/// the pod).
fn synthesized_source_id(collect_log_source_id: &str, container: &Container) -> String {
    let instance = container.stable_instance_id();
    if container.runtime == "kubernetes"
        && instance == container.stable_id()
        && !container.pod_name.is_empty()
    {
        return format!("{collect_log_source_id}/{instance}/{}", container.pod_name);
    }
    format!("{collect_log_source_id}/{instance}")
}

fn parse_selector(
    value: Option<&serde_json::Value>,
    ctx: FieldContext<'_>,
) -> Option<BTreeMap<String, String>> {
    let Some(criteria) = value.and_then(|v| v.as_object()) else {
        warn_config_field_error(&ConfigFieldError::invalid_field(
            ctx,
            "selector",
            "object of atom equalities",
        ));
        return None;
    };

    let mut selector = BTreeMap::new();
    for (kind, value) in criteria {
        let Some(value) = value.as_str() else {
            // Dropping just the pair would WIDEN the match, so the whole
            // description is skipped instead.
            warn_config_field_error(&ConfigFieldError::invalid_field(
                ctx,
                "selector",
                "string atom values",
            ));
            return None;
        };
        selector.insert(kind.clone(), value.to_string());
    }
    Some(selector)
}

/// Parse a description's `collect` payload — the same shape as a legacy
/// `collect` map entry, with `log_source_id` as a field instead of the map key.
fn parse_collect(entry: &serde_json::Value, ctx: FieldContext<'_>) -> Option<CollectStreamConfig> {
    let log_source_id = required_config_string::<LogSourceId>(entry, "log_source_id", ctx)?;
    let subbox_endpoint = required_config_string::<WireEndpoint>(entry, "subbox_endpoint", ctx)?;
    let archive_id = required_config_string::<ArchiveId>(entry, "archive_id", ctx)?;
    let repo_id = required_config_string::<RepoId>(entry, "repo_id", ctx)?;
    let matching_strategy = optional_string_field(entry, "matching_strategy")
        .or_else(|| optional_string_field(entry, "access_method"))
        .unwrap_or_default();
    let locator = optional_string_field(entry, "locator").unwrap_or_default();
    let container_identifier =
        optional_string_field(entry, "container_identifier").unwrap_or_default();
    let stamp_resource_identifier = bool_field_or(entry, "stamp_resource_identifier", false);

    let multiline = parse_multiline_config(entry.get("multiline"), ctx);
    // Hash of the collect payload only — never selector content — so a
    // criteria edit that still matches is a pipeline no-op.
    let config_hash = CollectStreamConfig::compute_hash(
        &locator,
        &matching_strategy,
        subbox_endpoint.0.as_str(),
        archive_id.0.as_str(),
        repo_id.0.as_str(),
        multiline.as_ref(),
        stamp_resource_identifier,
    );

    Some(CollectStreamConfig {
        log_source_id: log_source_id.0,
        locator,
        matching_strategy,
        container_identifier,
        subbox_endpoint: subbox_endpoint.0,
        archive_id: archive_id.0,
        repo_id: repo_id.0,
        stamp_resource_identifier,
        multiline,
        config_hash,
    })
}

/// Mirrors the orchestrator's state-dir sanitizer, so the synthesis-time
/// collision check guards the dirs pipelines actually open.
fn sanitize_id(id: &str) -> String {
    id.replace(['/', '\\', ':', '.', ' '], "_")
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StreamAccessMethod, UnifiedConfig, resolved_collect_from_config};
    use crate::discovery::Census;
    use serde_json::json;
    use std::collections::HashMap as StdHashMap;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag-1".into())
    }

    fn docker_container(id: &str, name: &str, log_path: &str) -> Container {
        Container {
            id: id.into(),
            name: name.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: "running".into(),
            labels: StdHashMap::new(),
            env: Vec::new(),
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

    fn kamal_container(id: &str, role: &str, name: &str) -> Container {
        let mut c = docker_container(id, name, "");
        c.labels.insert("service".into(), "logpacer".into());
        c.labels.insert("role".into(), role.into());
        c.labels.insert("destination".into(), "prod".into());
        c
    }

    fn k8s_deployment_pod(pod: &str) -> Container {
        let mut c = docker_container(&format!("prod/{pod}/api"), &format!("{pod}-api"), "");
        c.runtime = "kubernetes".into();
        c.namespace = "prod".into();
        c.deployment = "api".into();
        c.workload_kind = "deployment".into();
        c.container_name = "api".into();
        c.pod_name = pod.into();
        c.node_name = "node-1".into();
        c.pod_uid = format!("{pod}-uid");
        c.log_path = format!("/var/log/pods/prod_{pod}_uid/api");
        c.service_name = "checkout".into();
        c.service_name_explicit = true;
        c
    }

    fn cache_with(containers: Vec<Container>) -> DiscoveryCache {
        let mut cache = DiscoveryCache::new();
        cache.update_all(&Census {
            containers,
            ..Default::default()
        });
        cache
    }

    fn service_entry(selector: serde_json::Value) -> serde_json::Value {
        json!({
            "service_slug": "opted-api",
            "selector": selector,
            "collect": {
                "log_source_id": "service-42",
                "locator": "Opted.API",
                "container_identifier": "Opted.API",
                "matching_strategy": "env_var",
                "subbox_endpoint": "https://1.subbox.example.com/wire",
                "archive_id": "arc",
                "repo_id": "repo",
                "metadata": { "service_name": "Opted.API", "kind": "container" },
                "forwarding_enabled": false
            }
        })
    }

    #[test]
    fn matcher_agrees_with_shared_parity_fixture() {
        // Byte-identical mirror of logpacer's test/fixtures/files/matcher_parity.json —
        // both suites assert every case so Rails previews and agent matching
        // can never disagree.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/matcher_parity.json"))
                .expect("parity fixture parses");

        let cases = fixture["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let to_map = |value: &serde_json::Value| -> BTreeMap<String, String> {
                value
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            };
            let atoms = to_map(&case["atoms"]);
            let criteria = to_map(&case["criteria"]);
            assert_eq!(
                selector_matches(&criteria, &atoms),
                case["matches"].as_bool().unwrap(),
                "parity case failed: {name}"
            );
        }
    }

    #[test]
    fn parses_service_descriptions_ignoring_unknown_fields() {
        let config = unified(json!({
            "services": [service_entry(json!({"service_name": "Opted.API"}))]
        }));

        let descriptions = all_service_descriptions(&config);

        assert_eq!(descriptions.len(), 1);
        let description = &descriptions[0];
        assert_eq!(description.service_slug, "opted-api");
        assert_eq!(
            description.selector.get("service_name").map(String::as_str),
            Some("Opted.API")
        );
        assert_eq!(description.collect.log_source_id, "service-42");
        assert_eq!(
            description.collect.subbox_endpoint,
            "https://1.subbox.example.com/wire"
        );
        assert_eq!(description.collect.matching_strategy, "env_var");
    }

    #[test]
    fn absent_or_empty_services_block_is_a_noop() {
        assert!(all_service_descriptions(&unified(json!({}))).is_empty());
        assert!(all_service_descriptions(&unified(json!({ "services": [] }))).is_empty());
        // Wrong shape (object, not array) parses as absent rather than erroring.
        assert!(all_service_descriptions(&unified(json!({ "services": {} }))).is_empty());
    }

    #[test]
    fn malformed_description_is_skipped_and_the_rest_still_applies() {
        let valid = service_entry(json!({"kamal.service": "logpacer"}));
        let config = unified(json!({
            "services": [
                { "service_slug": "no-selector", "collect": valid["collect"] },
                { "service_slug": "non-string-atom", "selector": {"kamal.service": 7}, "collect": valid["collect"] },
                { "service_slug": "no-collect", "selector": {"kamal.service": "x"} },
                { "service_slug": "no-endpoint", "selector": {"kamal.service": "x"},
                  "collect": {"log_source_id": "service-9", "archive_id": "arc", "repo_id": "repo"} },
                "not-an-object",
                valid,
            ]
        }));

        let descriptions = all_service_descriptions(&config);

        assert_eq!(descriptions.len(), 1);
        assert_eq!(descriptions[0].service_slug, "opted-api");
    }

    #[test]
    fn kamal_container_matches_and_synthesizes_expected_source_id() {
        let config = unified(json!({
            "services": [service_entry(
                json!({"kamal.service": "logpacer", "kamal.destination": "prod"})
            )]
        }));
        let cache = cache_with(vec![kamal_container(
            "aaa111",
            "web",
            "logpacer-web-prod-1a2b3c4",
        )]);

        let resolved = resolved_collect_from_config(&config, &cache);

        // No local json log file → Docker API streaming lane, exactly like a
        // resolved legacy directive for the same container.
        assert!(resolved.file_streams.is_empty());
        assert_eq!(resolved.streaming_sources.len(), 1);
        let source = &resolved.streaming_sources[0];
        assert_eq!(source.log_source_id, "service-42/logpacer-web-prod");
        assert_eq!(
            source.access_method,
            StreamAccessMethod::DockerApi {
                container_id: "aaa111".into()
            }
        );
        assert_eq!(source.endpoint, "https://1.subbox.example.com/wire");

        // The adoption pair carries the legacy id the collect payload rides on.
        assert_eq!(
            resolved.checkpoint_adoptions,
            vec![CheckpointAdoption {
                legacy_log_source_id: "service-42".into(),
                log_source_id: "service-42/logpacer-web-prod".into(),
            }]
        );
    }

    #[test]
    fn earlier_description_position_wins() {
        let mut first = service_entry(json!({"kamal.service": "logpacer"}));
        first["service_slug"] = json!("first");
        first["collect"]["log_source_id"] = json!("service-1");
        let mut second = service_entry(json!({"kamal.destination": "prod"}));
        second["service_slug"] = json!("second");
        second["collect"]["log_source_id"] = json!("service-2");

        let config = unified(json!({ "services": [first, second] }));
        let cache = cache_with(vec![kamal_container(
            "aaa111",
            "web",
            "logpacer-web-prod-1a2b3c4",
        )]);

        let resolved = resolved_collect_from_config(&config, &cache);

        // Both selectors match, but array order is match priority: the first
        // description claims the container and the second gets nothing.
        assert_eq!(resolved.streaming_sources.len(), 1);
        assert_eq!(
            resolved.streaming_sources[0].log_source_id,
            "service-1/logpacer-web-prod"
        );
    }

    #[test]
    fn description_and_legacy_directive_yield_one_pipeline() {
        // Dual emission: the same service arrives as a legacy V3 collect entry
        // AND a selector-backed description. The claimed container must feed
        // exactly one pipeline.
        let config = unified(json!({
            "services": [service_entry(json!({"kamal.service": "logpacer"}))],
            "collect": {
                "service-42": {
                    "locator": "logpacer-web-prod-1a2b3c4",
                    "matching_strategy": "container_name",
                    "subbox_endpoint": "https://1.subbox.example.com/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                }
            }
        }));
        let cache = cache_with(vec![kamal_container(
            "aaa111",
            "web",
            "logpacer-web-prod-1a2b3c4",
        )]);

        let resolved = resolved_collect_from_config(&config, &cache);

        assert!(resolved.file_streams.is_empty());
        assert_eq!(
            resolved.streaming_sources.len(),
            1,
            "one pipeline per container"
        );
        assert_eq!(
            resolved.streaming_sources[0].log_source_id,
            "service-42/logpacer-web-prod"
        );

        // The suppressed legacy directive stays visible as a healthy (matched)
        // diagnostic so transition logging never warns about it.
        let legacy = resolved
            .diagnostics
            .iter()
            .find(|d| d.log_source_id == "service-42")
            .expect("legacy directive diagnostic");
        assert_eq!(legacy.status, MatchStatus::Matched);
        assert!(legacy.detail.contains("claimed"));
    }

    #[test]
    fn criteria_edit_with_same_match_set_is_a_pipeline_noop() {
        let narrow = unified(json!({
            "services": [service_entry(json!({"kamal.service": "logpacer"}))]
        }));
        let widened = unified(json!({
            "services": [service_entry(
                json!({"kamal.service": "logpacer", "kamal.destination": "prod", "kamal.role": "web"})
            )]
        }));
        let cache = cache_with(vec![kamal_container(
            "aaa111",
            "web",
            "logpacer-web-prod-1a2b3c4",
        )]);

        let before = resolved_collect_from_config(&narrow, &cache);
        let after = resolved_collect_from_config(&widened, &cache);

        // config_hash derives from the collect payload only — never selector
        // content — so the same match set yields identical source ids and
        // hashes and the reconciliation plan no-ops (no restart).
        let key = |r: &ResolvedCollectStreams| {
            r.streaming_sources
                .iter()
                .map(|s| (s.log_source_id.clone(), s.config_hash.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(key(&before), key(&after));
        assert_eq!(before.streaming_sources.len(), 1);
    }

    #[test]
    fn empty_selector_never_matches() {
        let config = unified(json!({
            "services": [service_entry(json!({}))]
        }));
        let cache = cache_with(vec![kamal_container(
            "aaa111",
            "web",
            "logpacer-web-prod-1a2b3c4",
        )]);

        let resolved = resolved_collect_from_config(&config, &cache);

        assert!(resolved.file_streams.is_empty());
        assert!(resolved.streaming_sources.is_empty());
    }

    #[test]
    fn fungible_k8s_replicas_synthesize_distinct_ids() {
        // Deployment pods are fungible (stable_instance_id degenerates to the
        // workload id), so the pod name is the per-pod discriminator.
        let one = k8s_deployment_pod("api-7b4f9c8d5-aaaaa");
        let two = k8s_deployment_pod("api-7b4f9c8d5-bbbbb");
        assert_eq!(one.stable_instance_id(), one.stable_id());
        assert_eq!(
            synthesized_source_id("service-42", &one),
            "service-42/prod/api/api/api-7b4f9c8d5-aaaaa"
        );
        assert_ne!(
            synthesized_source_id("service-42", &one),
            synthesized_source_id("service-42", &two)
        );

        // A StatefulSet pod already carries a stable ordinal — no pod suffix.
        let mut stateful = k8s_deployment_pod("postgres-0");
        stateful.deployment = "postgres".into();
        stateful.workload_kind = "statefulset".into();
        stateful.container_name = "db".into();
        assert_eq!(
            synthesized_source_id("service-7", &stateful),
            "service-7/prod/postgres/db/0"
        );

        // Non-k8s single instances stay at the instance id.
        let docker = docker_container("aaa", "my-nginx", "");
        assert_eq!(
            synthesized_source_id("service-9", &docker),
            "service-9/my-nginx"
        );
    }

    #[test]
    fn two_same_node_fungible_replicas_collect_as_two_sources() {
        let config = unified(json!({
            "services": [service_entry(json!({"service_name": "checkout"}))]
        }));
        let cache = cache_with(vec![
            k8s_deployment_pod("api-7b4f9c8d5-aaaaa"),
            k8s_deployment_pod("api-7b4f9c8d5-bbbbb"),
        ]);

        let resolved = resolved_collect_from_config(&config, &cache);

        assert_eq!(resolved.file_streams.len(), 2);
        let ids: Vec<&str> = resolved
            .file_streams
            .iter()
            .map(|s| s.log_source_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "service-42/prod/api/api/api-7b4f9c8d5-aaaaa",
                "service-42/prod/api/api/api-7b4f9c8d5-bbbbb",
            ]
        );
        // Same collect payload, different tailed paths — distinct pipelines.
        assert_ne!(resolved.file_streams[0].path, resolved.file_streams[1].path);
    }

    #[test]
    fn sanitized_state_dir_collision_keeps_first_source_and_skips_second() {
        // "web.1" and "web_1" sanitize to the same state-dir key; starting both
        // would share one checkpoint/buffer dir, so the second is skipped.
        let config = unified(json!({
            "services": [service_entry(json!({"image.repo": "nginx"}))]
        }));
        let cache = cache_with(vec![
            docker_container("aaa111", "web.1", ""),
            docker_container("bbb222", "web_1", ""),
        ]);

        let resolved = resolved_collect_from_config(&config, &cache);

        assert_eq!(resolved.streaming_sources.len(), 1);
        assert_eq!(
            resolved.streaming_sources[0].log_source_id,
            "service-42/web.1"
        );
    }

    #[test]
    fn non_explicit_k8s_workload_collects_only_via_selector() {
        // The selector IS the consent for k8s: a workload that never opted in
        // via LOGPACER_SERVICE_NAME collects when a description matches its
        // atoms...
        let mut pod = k8s_deployment_pod("api-7b4f9c8d5-aaaaa");
        pod.service_name = String::new();
        pod.service_name_explicit = false;
        let cache = cache_with(vec![pod]);

        let matching = unified(json!({
            "services": [service_entry(
                json!({"k8s.namespace": "prod", "k8s.workload": "api"})
            )]
        }));
        let resolved = resolved_collect_from_config(&matching, &cache);
        assert_eq!(resolved.file_streams.len(), 1);
        let stream = &resolved.file_streams[0];
        assert_eq!(
            stream.log_source_id,
            "service-42/prod/api/api/api-7b4f9c8d5-aaaaa"
        );
        assert_eq!(
            stream.source_format,
            crate::config::FileSourceFormat::KubernetesCri
        );

        // ...and stays resolvable-but-uncollected without one: no matching
        // description and no opt-in means no directive, hence no pipeline.
        let no_descriptions = unified(json!({}));
        let resolved = resolved_collect_from_config(&no_descriptions, &cache);
        assert!(resolved.file_streams.is_empty());
        assert!(resolved.streaming_sources.is_empty());
    }
}
