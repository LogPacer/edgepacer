//! Explicit workload cgroup resolution for eBPF capture.
//!
//! Listener evidence is only a presence gate. Authorization comes from the
//! verified runtime init process of a running container that explicitly opted
//! into the configured service name; listener socket cgroups are never copied
//! into the allow-set.

use std::collections::{BTreeMap, HashSet};

use edgepacer_ebpf_common::MAX_ALLOWED_CGROUPS;

use super::cgroup_v2;
#[cfg(test)]
use super::listener_state::ForeignListenerCandidate;
use super::listener_state::{
    ForeignRuntimeIdentity, ListenerState, NetworkNamespaceToken, PortEvidence,
};
use crate::config::EbpfTargetConfig;
use crate::discovery::{Container, RuntimeProcessIdentity};

pub(crate) use super::cgroup_v2::CgroupAnchor;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupRoute {
    anchor: CgroupAnchor,
    log_source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuntimeAttestation {
    container_id: String,
    process: RuntimeProcessIdentity,
    anchor: CgroupAnchor,
    network_namespace: NetworkNamespaceToken,
}

/// Resolved cgroup anchor to service routing for one authoritative container
/// revision. The same anchors seed the kernel allow-set and route captured
/// events by their kernel-selected `scope_cgroup_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CgroupRouting {
    by_id: BTreeMap<u64, CgroupRoute>,
    runtime_attestations: Vec<RuntimeAttestation>,
    authorization_revision: Option<u64>,
    policy_generation: Option<u64>,
}

impl CgroupRouting {
    /// Construct validated routing, primarily for manager/runner tests and
    /// other control-plane producers. Duplicate identical entries collapse;
    /// any conflicting ownership fails closed.
    pub(crate) fn from_entries<I, S>(
        authorization_revision: u64,
        entries: I,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (CgroupAnchor, S)>,
        S: Into<String>,
    {
        let mut routing = Self::default();
        for (anchor, log_source_id) in entries {
            routing.insert(anchor, log_source_id.into())?;
        }
        if !routing.by_id.is_empty() {
            if authorization_revision == 0 {
                return Err("cgroup routing authorization revision is zero".to_string());
            }
            routing.authorization_revision = Some(authorization_revision);
            routing.policy_generation = Some(authorization_revision);
        }
        Ok(routing)
    }

    /// Workload anchors to seed into the kernel's cgroup policy maps.
    pub(crate) fn allowed_cgroups(&self) -> impl Iterator<Item = CgroupAnchor> + '_ {
        self.by_id.values().map(|route| route.anchor)
    }

    /// Route the kernel-selected workload scope to its configured log source.
    pub(crate) fn service_for(&self, scope_cgroup_id: u64) -> Option<&str> {
        self.by_id
            .get(&scope_cgroup_id)
            .map(|route| route.log_source_id.as_str())
    }

    pub(crate) fn authorization_revision(&self) -> Option<u64> {
        self.authorization_revision
    }

    /// Generation stamped into kernel events for this exact policy instance.
    /// The runner replaces the authorization-revision default with its monotonic
    /// sequence before committing a live policy.
    pub(crate) fn policy_generation(&self) -> Option<u64> {
        self.policy_generation
    }

    pub(crate) fn assign_policy_generation(&mut self, generation: u64) -> Result<(), String> {
        if self.by_id.is_empty() {
            if generation != 0 {
                return Err("empty cgroup routing must use policy generation zero".to_string());
            }
            self.policy_generation = None;
        } else {
            if generation == 0 {
                return Err("nonempty cgroup routing requires a policy generation".to_string());
            }
            self.policy_generation = Some(generation);
        }
        Ok(())
    }

    pub(crate) fn same_authorization_as(&self, other: &Self) -> bool {
        self.by_id == other.by_id && self.authorization_revision == other.authorization_revision
    }

    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Re-read the exact runtime identities used to build this routing. The
    /// discovery revision cannot detect a same-process cgroup or namespace
    /// move, so publication must bind to a fresh runtime observation too.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn revalidate_runtime_identities(&self) -> Result<(), String> {
        self.revalidate_runtime_identities_with(|attestation| {
            observe_runtime_identity(&attestation.container_id, attestation.process)
        })
    }

    fn revalidate_runtime_identities_with<F>(&self, mut observe: F) -> Result<(), String>
    where
        F: FnMut(&RuntimeAttestation) -> Result<ResolvedRuntimeIdentity, String>,
    {
        if self.by_id.is_empty() {
            return Ok(());
        }
        if self.runtime_attestations.len() > MAX_ALLOWED_CGROUPS as usize {
            return Err(format!(
                "cgroup routing exceeds runtime attestation capacity of {MAX_ALLOWED_CGROUPS}"
            ));
        }
        if self.runtime_attestations.is_empty()
            || self.by_id.values().any(|route| {
                !self
                    .runtime_attestations
                    .iter()
                    .any(|attestation| attestation.anchor == route.anchor)
            })
        {
            return Err("nonempty cgroup routing has no complete runtime attestation".to_string());
        }

        for attestation in &self.runtime_attestations {
            let current = observe(attestation)?;
            if current.anchor != attestation.anchor
                || current.network_namespace != attestation.network_namespace
            {
                return Err(format!(
                    "runtime container {:?} changed cgroup or network namespace before policy publication",
                    attestation.container_id
                ));
            }
        }
        Ok(())
    }

    fn insert(&mut self, anchor: CgroupAnchor, log_source_id: String) -> Result<(), String> {
        cgroup_v2::CgroupAnchor::new(anchor.id, anchor.level).map_err(|error| error.to_string())?;
        if log_source_id.is_empty() {
            return Err(format!(
                "cgroup anchor {} has an empty log source id",
                anchor.id
            ));
        }

        if let Some(existing) = self.by_id.get(&anchor.id) {
            if existing.anchor.level != anchor.level {
                return Err(format!(
                    "cgroup anchor {} resolved at conflicting hierarchy levels {} and {}",
                    anchor.id, existing.anchor.level, anchor.level
                ));
            }
            if existing.log_source_id != log_source_id {
                return Err(format!(
                    "cgroup anchor {} ambiguously maps to log sources {:?} and {:?}",
                    anchor.id, existing.log_source_id, log_source_id
                ));
            }
            return Ok(());
        }

        if self.by_id.len() >= MAX_ALLOWED_CGROUPS as usize {
            return Err(format!(
                "cgroup routing exceeds kernel allow-set capacity of {MAX_ALLOWED_CGROUPS} distinct anchors"
            ));
        }

        self.by_id.insert(
            anchor.id,
            CgroupRoute {
                anchor,
                log_source_id,
            },
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedRuntimeIdentity {
    anchor: CgroupAnchor,
    uses_host_network_namespace: bool,
    network_namespace: NetworkNamespaceToken,
    attestation: Option<RuntimeAttestation>,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn observe_runtime_identity(
    container_id: &str,
    process: RuntimeProcessIdentity,
) -> Result<ResolvedRuntimeIdentity, String> {
    let network_namespace_before =
        super::listener_snapshot::runtime_process_network_namespace(container_id, process)
            .map_err(|error| error.to_string())?;
    let anchor = cgroup_v2::cgroup_anchor_for_pid(process.pid(), container_id)
        .map_err(|error| error.to_string())?;
    let network_namespace_after =
        super::listener_snapshot::runtime_process_network_namespace(container_id, process)
            .map_err(|error| error.to_string())?;
    if network_namespace_after != network_namespace_before {
        return Err(format!(
            "runtime container {container_id:?} changed network namespace while resolving cgroup identity"
        ));
    }

    Ok(ResolvedRuntimeIdentity {
        anchor,
        uses_host_network_namespace: network_namespace_before.uses_host_namespace(),
        network_namespace: network_namespace_before.token(),
        attestation: None,
    })
}

/// Resolve cgroup authorization from explicit runtime identity and the current
/// authoritative listener state.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) fn resolve_from_listener_state(
    containers: &[Container],
    targets: &[EbpfTargetConfig],
    state: &ListenerState,
    authorization_revision: u64,
) -> Result<CgroupRouting, String> {
    resolve_with_runtime_identity(
        containers,
        targets,
        state,
        authorization_revision,
        |container| {
            let process = container.runtime_process.ok_or_else(|| {
                format!(
                    "running explicit service {:?} has no verified local runtime process",
                    container.service_name
                )
            })?;
            if container.container_id.is_empty() {
                return Err(format!(
                    "running explicit service {:?} has no full runtime container ID",
                    container.service_name
                ));
            }

            let mut identity = observe_runtime_identity(&container.container_id, process)?;
            identity.attestation = Some(RuntimeAttestation {
                container_id: container.container_id.clone(),
                process,
                anchor: identity.anchor,
                network_namespace: identity.network_namespace,
            });
            Ok(identity)
        },
    )
}

fn resolve_with_runtime_identity<F>(
    containers: &[Container],
    targets: &[EbpfTargetConfig],
    state: &ListenerState,
    authorization_revision: u64,
    mut resolve_runtime: F,
) -> Result<CgroupRouting, String>
where
    F: FnMut(&Container) -> Result<ResolvedRuntimeIdentity, String>,
{
    if !state.is_ready() {
        return Ok(CgroupRouting::default());
    }

    let mut entries = Vec::new();
    let mut runtime_attestations = Vec::new();
    for container in containers
        .iter()
        .filter(|container| container.state == "running" && container.explicit_service())
    {
        let matching_targets: Vec<_> = targets
            .iter()
            .filter(|target| target.service_name == container.service_name)
            .filter(|target| {
                target.open_ports.iter().any(|port| {
                    matches!(state.evidence_for_port(*port), PortEvidence::Present { .. })
                })
            })
            .collect();
        if matching_targets.is_empty() {
            continue;
        }

        let runtime = resolve_runtime(container)?;
        for target in matching_targets {
            let listener_is_authoritative = target.open_ports.iter().try_fold(
                false,
                |authorized, port| -> Result<bool, String> {
                    let port_is_authoritative = match state.evidence_for_port(*port) {
                        PortEvidence::Present { socket_cgroups, .. }
                            if runtime.uses_host_network_namespace =>
                        {
                            Ok(!socket_cgroups.is_empty())
                        }
                        PortEvidence::Present {
                            foreign_runtime_candidates,
                            ..
                        } => foreign_listener_matches_runtime(
                            &foreign_runtime_candidates,
                            &runtime,
                            *port,
                        ),
                        PortEvidence::NotReady | PortEvidence::Absent => Ok(false),
                    }?;
                    Ok(authorized || port_is_authoritative)
                },
            )?;
            if listener_is_authoritative {
                entries.push((runtime.anchor, target.log_source_id.clone()));
                if let Some(attestation) = runtime.attestation.clone() {
                    runtime_attestations.push(attestation);
                }
            }
        }
    }

    let mut routing = CgroupRouting::from_entries(authorization_revision, entries)?;
    runtime_attestations.sort_unstable();
    runtime_attestations.dedup();
    routing.runtime_attestations = runtime_attestations;
    Ok(routing)
}

fn foreign_listener_matches_runtime(
    candidates: &HashSet<ForeignRuntimeIdentity>,
    runtime: &ResolvedRuntimeIdentity,
    port: u16,
) -> Result<bool, String> {
    let mut namespace_candidates = candidates
        .iter()
        .filter(|candidate| candidate.network_namespace == runtime.network_namespace);
    let Some(candidate) = namespace_candidates.next() else {
        return Ok(false);
    };
    if namespace_candidates.next().is_some() {
        return Err(format!(
            "foreign listener port {port} maps to multiple runtime cgroups in network namespace {:?}",
            runtime.network_namespace
        ));
    }
    Ok(candidate.cgroup_id == runtime.anchor.id)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::discovery::RuntimeProcessIdentity;
    use crate::ebpf::listener_state::{ListenerAssociation, ListenerSnapshot};

    fn container(id: &str, service_name: &str, explicit: bool) -> Container {
        Container {
            id: id.to_string(),
            name: id.to_string(),
            service_name: service_name.to_string(),
            service_name_explicit: explicit,
            image: "image".to_string(),
            state: "running".to_string(),
            labels: HashMap::new(),
            env: Vec::new(),
            runtime: "docker".to_string(),
            log_path: String::new(),
            log_format: "plain_text".to_string(),
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: format!("{id:0<64}"),
            container_name: String::new(),
            runtime_process: Some(RuntimeProcessIdentity {
                pid: 100,
                start_time_ticks: 200,
            }),
        }
    }

    fn target(log_source_id: &str, service_name: &str, ports: &[u16]) -> EbpfTargetConfig {
        EbpfTargetConfig {
            log_source_id: log_source_id.to_string(),
            service_name: service_name.to_string(),
            open_ports: ports.to_vec(),
            archive_id: "archive".to_string(),
            repo_id: "repo".to_string(),
            protocols: Vec::new(),
            subbox_endpoint: "dest".to_string(),
        }
    }

    fn ready_state(
        host: impl IntoIterator<Item = (u16, u64)>,
        foreign: impl IntoIterator<Item = (u16, u64)>,
    ) -> ListenerState {
        let associations = host
            .into_iter()
            .map(|(port, cgroup_id)| ListenerAssociation {
                family: libc::AF_INET as u16,
                port,
                cgroup_id,
            });
        let foreign = foreign
            .into_iter()
            .map(|(port, cgroup_id)| ForeignListenerCandidate {
                port,
                cgroup_id,
                network_namespace: foreign_namespace(cgroup_id),
            });
        let snapshot = ListenerSnapshot::new(1, associations, foreign).unwrap();
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 100).unwrap());
        state
    }

    fn resolve(
        containers: &[Container],
        targets: &[EbpfTargetConfig],
        state: &ListenerState,
        epoch: u64,
        identities: &HashMap<String, ResolvedRuntimeIdentity>,
    ) -> Result<CgroupRouting, String> {
        resolve_with_runtime_identity(containers, targets, state, epoch, |container| {
            identities
                .get(&container.id)
                .cloned()
                .ok_or_else(|| format!("missing injected identity for {}", container.id))
        })
    }

    fn identity(id: u64, level: u32, host: bool) -> ResolvedRuntimeIdentity {
        let network_namespace = if host {
            NetworkNamespaceToken::new(1, 100).unwrap()
        } else {
            foreign_namespace(id)
        };
        ResolvedRuntimeIdentity {
            anchor: CgroupAnchor { id, level },
            uses_host_network_namespace: host,
            network_namespace,
            attestation: None,
        }
    }

    fn attested_identity(
        container: &Container,
        id: u64,
        level: u32,
        host: bool,
    ) -> ResolvedRuntimeIdentity {
        let mut identity = identity(id, level, host);
        identity.attestation = Some(RuntimeAttestation {
            container_id: container.container_id.clone(),
            process: container.runtime_process.unwrap(),
            anchor: identity.anchor,
            network_namespace: identity.network_namespace,
        });
        identity
    }

    fn foreign_namespace(id: u64) -> NetworkNamespaceToken {
        NetworkNamespaceToken::new(2, id.saturating_add(100)).unwrap()
    }

    #[test]
    fn not_ready_or_absent_listener_state_authorizes_nothing() {
        let containers = [container("one", "api", true)];
        let targets = [target("source", "api", &[8080])];
        let identities = HashMap::from([("one".to_string(), identity(42, 3, true))]);

        let not_ready = resolve(
            &containers,
            &targets,
            &ListenerState::default(),
            7,
            &identities,
        )
        .unwrap();
        assert!(not_ready.is_empty());
        assert_eq!(not_ready.authorization_revision(), None);

        let absent = resolve(&containers, &targets, &ready_state([], []), 7, &identities).unwrap();
        assert!(absent.is_empty());
    }

    #[test]
    fn host_listener_presence_gates_explicit_runtime_anchor_not_socket_owner() {
        let containers = [container("one", "api", true)];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([(8080, 900)], []);
        let identities = HashMap::from([("one".to_string(), identity(42, 3, true))]);

        let routing = resolve(&containers, &targets, &state, 7, &identities).unwrap();
        assert_eq!(routing.service_for(42), Some("source"));
        assert_eq!(routing.service_for(900), None);
        assert_eq!(routing.authorization_revision(), Some(7));
    }

    #[test]
    fn foreign_listener_requires_exact_runtime_anchor_intersection() {
        let containers = [
            container("match", "api", true),
            container("mismatch", "api", true),
        ];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([], [(8080, 42)]);
        let identities = HashMap::from([
            ("match".to_string(), identity(42, 3, false)),
            ("mismatch".to_string(), identity(43, 3, false)),
        ]);

        let routing = resolve(&containers, &targets, &state, 7, &identities).unwrap();
        assert_eq!(routing.service_for(42), Some("source"));
        assert_eq!(routing.service_for(43), None);
    }

    #[test]
    fn shared_foreign_namespace_with_multiple_cgroups_fails_closed() {
        let containers = [
            container("app", "api", true),
            container("sidecar", "api", true),
        ];
        let targets = [target("source", "api", &[8080])];
        let network_namespace = foreign_namespace(42);
        let snapshot = ListenerSnapshot::new(
            1,
            [],
            [
                ForeignListenerCandidate {
                    port: 8080,
                    cgroup_id: 42,
                    network_namespace,
                },
                ForeignListenerCandidate {
                    port: 8080,
                    cgroup_id: 43,
                    network_namespace,
                },
            ],
        )
        .unwrap();
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 100).unwrap());

        let mut app = identity(42, 3, false);
        app.network_namespace = network_namespace;
        let mut sidecar = identity(43, 3, false);
        sidecar.network_namespace = network_namespace;
        let identities =
            HashMap::from([("app".to_string(), app), ("sidecar".to_string(), sidecar)]);

        let error = resolve(&containers, &targets, &state, 7, &identities).unwrap_err();

        assert!(error.contains("multiple runtime cgroups"), "{error}");
    }

    #[test]
    fn foreign_namespace_ambiguity_is_independent_of_target_port_order() {
        let containers = [container("app", "api", true)];
        let network_namespace = foreign_namespace(42);
        let snapshot = ListenerSnapshot::new(
            1,
            [],
            [
                ForeignListenerCandidate {
                    port: 8080,
                    cgroup_id: 42,
                    network_namespace,
                },
                ForeignListenerCandidate {
                    port: 9090,
                    cgroup_id: 42,
                    network_namespace,
                },
                ForeignListenerCandidate {
                    port: 9090,
                    cgroup_id: 43,
                    network_namespace,
                },
            ],
        )
        .unwrap();
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 100).unwrap());

        let mut app = identity(42, 3, false);
        app.network_namespace = network_namespace;
        let identities = HashMap::from([("app".to_string(), app)]);

        for ports in [[8080, 9090], [9090, 8080]] {
            let targets = [target("source", "api", &ports)];
            let error = resolve(&containers, &targets, &state, 7, &identities).unwrap_err();
            assert!(error.contains("multiple runtime cgroups"), "{error}");
        }
    }

    #[test]
    fn foreign_listener_evidence_cannot_follow_runtime_to_another_namespace() {
        let containers = [container("moved", "api", true)];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([], [(8080, 42)]);
        let mut moved = identity(42, 3, false);
        moved.network_namespace = foreign_namespace(99);
        let identities = HashMap::from([("moved".to_string(), moved)]);

        let routing = resolve(&containers, &targets, &state, 7, &identities).unwrap();

        assert!(routing.is_empty());
    }

    #[test]
    fn replicas_of_one_explicit_service_each_receive_an_anchor() {
        let containers = [
            container("replica-a", "api", true),
            container("replica-b", "api", true),
        ];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([(8080, 900)], []);
        let identities = HashMap::from([
            ("replica-a".to_string(), identity(42, 3, true)),
            ("replica-b".to_string(), identity(43, 3, true)),
        ]);

        let routing = resolve(&containers, &targets, &state, 9, &identities).unwrap();
        assert_eq!(routing.len(), 2);
        assert_eq!(routing.service_for(42), Some("source"));
        assert_eq!(routing.service_for(43), Some("source"));
        assert_eq!(routing.authorization_revision(), Some(9));
    }

    #[test]
    fn non_explicit_or_non_running_service_is_ignored() {
        let mut stopped = container("stopped", "api", true);
        stopped.state = "exited".to_string();
        let containers = [
            container("derived", "api", false),
            stopped,
            container("other", "worker", true),
        ];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([(8080, 900)], []);

        let routing = resolve_with_runtime_identity(&containers, &targets, &state, 7, |_| {
            panic!("ignored containers must not resolve runtime identity")
        })
        .unwrap();
        assert!(routing.is_empty());
    }

    #[test]
    fn invalid_anchor_depth_fails_closed() {
        let containers = [container("one", "api", true)];
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([(8080, 900)], []);
        let identities = HashMap::from([("one".to_string(), identity(42, 33, true))]);

        let error = resolve(&containers, &targets, &state, 7, &identities).unwrap_err();
        assert!(error.contains("outside the supported range"), "{error}");
    }

    #[test]
    fn ambiguous_anchor_ownership_fails_instead_of_using_config_order() {
        let containers = [container("one", "api", true)];
        let targets = [
            target("source-a", "api", &[8080]),
            target("source-b", "api", &[8080]),
        ];
        let state = ready_state([(8080, 900)], []);
        let identities = HashMap::from([("one".to_string(), identity(42, 3, true))]);

        let error = resolve(&containers, &targets, &state, 7, &identities).unwrap_err();
        assert!(error.contains("ambiguously maps"), "{error}");
    }

    #[test]
    fn allowed_cgroups_are_copyable_validated_anchors() {
        let routing = CgroupRouting::from_entries(
            11,
            [
                (CgroupAnchor { id: 42, level: 3 }, "source"),
                (CgroupAnchor { id: 43, level: 4 }, "source"),
            ],
        )
        .unwrap();
        let anchors: HashSet<_> = routing.allowed_cgroups().collect();
        assert_eq!(
            anchors,
            HashSet::from([
                CgroupAnchor { id: 42, level: 3 },
                CgroupAnchor { id: 43, level: 4 }
            ])
        );
        assert_eq!(routing.authorization_revision(), Some(11));
    }

    #[test]
    fn routing_accepts_map_capacity_and_rejects_the_next_distinct_anchor() {
        let entries = |count| {
            (0..count).map(|index| {
                (
                    CgroupAnchor {
                        id: u64::from(index) + 2,
                        level: 3,
                    },
                    "source",
                )
            })
        };

        let routing = CgroupRouting::from_entries(11, entries(MAX_ALLOWED_CGROUPS)).unwrap();
        assert_eq!(routing.len(), MAX_ALLOWED_CGROUPS as usize);

        let error = CgroupRouting::from_entries(11, entries(MAX_ALLOWED_CGROUPS + 1)).unwrap_err();
        assert_eq!(
            error,
            format!(
                "cgroup routing exceeds kernel allow-set capacity of {MAX_ALLOWED_CGROUPS} distinct anchors"
            )
        );
    }

    #[test]
    fn runtime_revalidation_is_bounded_by_kernel_policy_capacity() {
        let anchor = CgroupAnchor { id: 42, level: 3 };
        let mut routing = CgroupRouting::from_entries(11, [(anchor, "source")]).unwrap();
        let container = container("one", "api", true);
        let attestation = RuntimeAttestation {
            container_id: container.container_id,
            process: container.runtime_process.unwrap(),
            anchor,
            network_namespace: NetworkNamespaceToken::new(1, 100).unwrap(),
        };
        routing.runtime_attestations = vec![attestation; MAX_ALLOWED_CGROUPS as usize + 1];

        let error = routing
            .revalidate_runtime_identities_with(|_| {
                panic!("over-capacity routing must fail before filesystem validation")
            })
            .unwrap_err();

        assert_eq!(
            error,
            format!("cgroup routing exceeds runtime attestation capacity of {MAX_ALLOWED_CGROUPS}")
        );
    }

    #[test]
    fn runtime_attestation_rejects_same_process_moved_to_another_cgroup() {
        let container = container("one", "api", true);
        let targets = [target("source", "api", &[8080])];
        let state = ready_state([(8080, 900)], []);
        let identities = HashMap::from([(
            "one".to_string(),
            attested_identity(&container, 42, 3, true),
        )]);
        let routing = resolve(&[container], &targets, &state, 7, &identities).unwrap();

        routing
            .revalidate_runtime_identities_with(|attestation| {
                Ok(ResolvedRuntimeIdentity {
                    anchor: attestation.anchor,
                    uses_host_network_namespace: true,
                    network_namespace: attestation.network_namespace,
                    attestation: None,
                })
            })
            .unwrap();

        let error = routing
            .revalidate_runtime_identities_with(|attestation| {
                Ok(ResolvedRuntimeIdentity {
                    anchor: CgroupAnchor {
                        id: attestation.anchor.id + 1,
                        level: attestation.anchor.level,
                    },
                    uses_host_network_namespace: true,
                    network_namespace: attestation.network_namespace,
                    attestation: None,
                })
            })
            .unwrap_err();
        assert!(
            error.contains("changed cgroup or network namespace"),
            "{error}"
        );
    }

    #[test]
    fn nonempty_routing_without_runtime_attestation_fails_revalidation() {
        let routing =
            CgroupRouting::from_entries(11, [(CgroupAnchor { id: 42, level: 3 }, "source")])
                .unwrap();

        let error = routing
            .revalidate_runtime_identities_with(|_| panic!("missing attestation must fail first"))
            .unwrap_err();

        assert!(error.contains("no complete runtime attestation"), "{error}");
    }

    #[test]
    fn live_policy_generation_is_independent_of_authorization_identity() {
        let mut routing =
            CgroupRouting::from_entries(11, [(CgroupAnchor { id: 42, level: 3 }, "source")])
                .unwrap();
        let same_authorization = routing.clone();

        routing.assign_policy_generation(99).unwrap();

        assert_eq!(routing.authorization_revision(), Some(11));
        assert_eq!(routing.policy_generation(), Some(99));
        assert!(routing.same_authorization_as(&same_authorization));

        let mut empty = CgroupRouting::default();
        assert!(empty.assign_policy_generation(1).is_err());
        empty.assign_policy_generation(0).unwrap();
        assert_eq!(empty.policy_generation(), None);
    }
}
