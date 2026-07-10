//! Race-safe listener ownership state.
//!
//! Live BPF events are deltas, not an inventory: they cannot recover listeners
//! that predate program attachment and they do not announce closes. A periodic
//! authoritative snapshot therefore replaces the ownership set. Live events
//! lack network-namespace provenance, so they invalidate ownership and force a
//! fresh snapshot instead of being replayed into the host inventory.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerAssociation {
    pub family: u16,
    pub port: u16,
    pub cgroup_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NetworkNamespaceToken {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl NetworkNamespaceToken {
    pub(crate) fn new(device: u64, inode: u64) -> Result<Self, String> {
        if device == 0 || inode == 0 {
            return Err("network namespace token contains zero".to_string());
        }
        Ok(Self { device, inode })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ForeignListenerCandidate {
    pub(crate) port: u16,
    pub(crate) cgroup_id: u64,
    pub(crate) network_namespace: NetworkNamespaceToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ForeignRuntimeIdentity {
    pub(crate) cgroup_id: u64,
    pub(crate) network_namespace: NetworkNamespaceToken,
}

#[derive(Debug, Clone)]
pub struct ListenerSnapshot {
    root_cgroup_id: u64,
    associations: HashSet<ListenerAssociation>,
    foreign_candidates: HashMap<u16, HashSet<ForeignRuntimeIdentity>>,
}

impl ListenerSnapshot {
    pub fn new(
        root_cgroup_id: u64,
        associations: impl IntoIterator<Item = ListenerAssociation>,
        foreign_candidates: impl IntoIterator<Item = ForeignListenerCandidate>,
    ) -> Result<Self, String> {
        if root_cgroup_id == 0 {
            return Err("root cgroup id is zero".to_string());
        }

        let associations: HashSet<_> = associations.into_iter().collect();
        for association in &associations {
            validate_association(*association, root_cgroup_id)?;
        }
        let mut candidates_by_port: HashMap<u16, HashSet<ForeignRuntimeIdentity>> = HashMap::new();
        for candidate in foreign_candidates {
            validate_candidate(candidate.port, candidate.cgroup_id, root_cgroup_id)?;
            NetworkNamespaceToken::new(
                candidate.network_namespace.device,
                candidate.network_namespace.inode,
            )?;
            candidates_by_port
                .entry(candidate.port)
                .or_default()
                .insert(ForeignRuntimeIdentity {
                    cgroup_id: candidate.cgroup_id,
                    network_namespace: candidate.network_namespace,
                });
        }

        Ok(Self {
            root_cgroup_id,
            associations,
            foreign_candidates: candidates_by_port,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaOutcome {
    /// A live listener change has no trustworthy network-namespace provenance,
    /// so it invalidated previously authoritative ownership.
    Invalidated,
    /// The change was observed while ownership was already unavailable. A
    /// snapshot that started before it must be discarded and retried.
    Quarantined,
    IgnoredBeforeCut,
    IgnoredInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortEvidence {
    NotReady,
    Absent,
    Present {
        /// Socket-creation cgroups observed by the current-namespace sock_diag
        /// snapshot. These are exact socket facts, not proof of which cgroup
        /// consumes traffic.
        socket_cgroups: HashSet<u64>,
        /// Runtime cgroup plus exact foreign-network-namespace tokens that
        /// contained the port. Target resolution must intersect both with
        /// current explicit runtime/service identity before authorizing.
        foreign_runtime_candidates: HashSet<ForeignRuntimeIdentity>,
    },
}

#[derive(Debug, Clone)]
struct InFlightSnapshot {
    generation: u64,
    cut_ns: u64,
    listener_drop_counts: Vec<u64>,
    unclassified_delta_observed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListenerState {
    owners: HashMap<(u16, u16), HashSet<u64>>,
    foreign_candidates: HashMap<u16, HashSet<ForeignRuntimeIdentity>>,
    association_count: usize,
    root_cgroup_id: Option<u64>,
    applied_cut_ns: u64,
    applied_generation: Option<u64>,
    applied_drop_counts: Option<Vec<u64>>,
    authorization_revision: u64,
    ready: bool,
    generation: u64,
    in_flight: Option<InFlightSnapshot>,
}

impl ListenerState {
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn association_count(&self) -> usize {
        self.association_count
    }

    pub fn snapshot_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    pub fn snapshot_is_current(&self, generation: u64) -> bool {
        self.in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.generation == generation)
    }

    /// Generation of the last applied snapshot that remains valid authorization
    /// evidence. A same-revision replacement snapshot does not create a gap;
    /// observed listener change or loss clears `ready` and therefore this value.
    pub fn authorization_generation(&self) -> Option<u64> {
        if !self.ready {
            return None;
        }
        self.applied_generation
    }

    /// Revision of the material listener evidence behind the active policy.
    /// Applying an identical replacement advances its snapshot generation but
    /// deliberately preserves this revision and the existing kernel policy.
    pub fn authorization_revision(&self) -> Option<u64> {
        self.ready.then_some(self.authorization_revision)
    }

    /// Generation a background resolution result may publish for. Starting a
    /// newer snapshot keeps the old applied policy available but makes the older
    /// worker result stale until that replacement is applied and resolved.
    pub fn publishable_authorization_generation(&self) -> Option<u64> {
        if self.in_flight.is_some() {
            return None;
        }
        self.authorization_generation()
    }

    /// Revalidate a background resolver result against the listener snapshot
    /// and loss vector observed after its final publication fence.
    pub fn validate_authorization(
        &mut self,
        generation: u64,
        listener_drop_counts: &[u64],
    ) -> Result<(), String> {
        if self.publishable_authorization_generation() != Some(generation) {
            return Err("listener authorization changed while resolving cgroups".to_string());
        }
        if self.applied_drop_counts.as_deref() != Some(listener_drop_counts) {
            self.clear_ownership();
            return Err("listener discovery lost events while resolving cgroups".to_string());
        }
        Ok(())
    }

    /// Start a snapshot at `cut_ns`. Returns `None` when another snapshot is
    /// already running; snapshots must never overlap.
    pub fn begin_snapshot_with_loss(
        &mut self,
        cut_ns: u64,
        listener_drop_counts: Vec<u64>,
    ) -> Option<u64> {
        if self.in_flight.is_some() || cut_ns == 0 {
            return None;
        }

        if self.ready
            && self
                .applied_drop_counts
                .as_ref()
                .is_some_and(|applied| applied != &listener_drop_counts)
        {
            self.clear_ownership();
        }

        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        self.in_flight = Some(InFlightSnapshot {
            generation,
            cut_ns,
            listener_drop_counts,
            unclassified_delta_observed: false,
        });
        Some(generation)
    }

    #[cfg(test)]
    pub fn begin_snapshot(&mut self, cut_ns: u64) -> Option<u64> {
        self.begin_snapshot_with_loss(cut_ns, vec![0])
    }

    pub fn record_delta(
        &mut self,
        association: ListenerAssociation,
        observed_at_ns: u64,
    ) -> DeltaOutcome {
        if observed_at_ns == 0
            || association.port == 0
            || !matches!(association.family, 2 | 10)
            || association.cgroup_id == 0
            || self.root_cgroup_id == Some(association.cgroup_id)
        {
            return DeltaOutcome::IgnoredInvalid;
        }

        if self.ready && observed_at_ns < self.applied_cut_ns {
            return DeltaOutcome::IgnoredBeforeCut;
        }

        if let Some(in_flight) = self.in_flight.as_mut()
            && observed_at_ns >= in_flight.cut_ns
        {
            in_flight.unclassified_delta_observed = true;
        }

        if self.ready {
            // Listener events are host-wide but carry no network-namespace
            // identity. Never merge one into the host sock_diag inventory: an
            // isolated namespace could otherwise authorize a host target that
            // happens to use the same port. Treat it only as invalidation and
            // require the next authoritative snapshot to classify the listener.
            self.clear_ownership();
            DeltaOutcome::Invalidated
        } else {
            DeltaOutcome::Quarantined
        }
    }

    /// Replace ownership with an authoritative snapshot only when no
    /// namespace-unclassified live listener event occurred after its cut.
    /// `Ok(false)` means a stale result arrived after reset or a newer
    /// generation and was ignored.
    pub fn apply_snapshot_with_loss(
        &mut self,
        generation: u64,
        snapshot: ListenerSnapshot,
        listener_drop_counts: Vec<u64>,
        association_limit: usize,
    ) -> Result<bool, String> {
        let Some(in_flight) = self.in_flight.take() else {
            return Ok(false);
        };
        if in_flight.generation != generation {
            self.in_flight = Some(in_flight);
            return Ok(false);
        }
        if in_flight.listener_drop_counts != listener_drop_counts {
            self.clear_ownership();
            return Err(format!(
                "listener discovery lost events during snapshot ({:?} -> {listener_drop_counts:?})",
                in_flight.listener_drop_counts
            ));
        }
        if in_flight.unclassified_delta_observed {
            self.clear_ownership();
            return Err(
                "unclassified listener change occurred during snapshot; retry required".to_string(),
            );
        }
        let snapshot_evidence_count = snapshot
            .associations
            .len()
            .saturating_add(candidate_count(&snapshot.foreign_candidates));
        if snapshot_evidence_count > association_limit {
            self.clear_ownership();
            return Err(format!(
                "listener snapshot contains {snapshot_evidence_count} evidence records (limit {association_limit})"
            ));
        }

        let root_cgroup_id = snapshot.root_cgroup_id;
        let associations = snapshot.associations;
        let foreign_candidates = snapshot.foreign_candidates;
        let mut owners: HashMap<(u16, u16), HashSet<u64>> = HashMap::new();
        for association in associations {
            owners
                .entry((association.family, association.port))
                .or_default()
                .insert(association.cgroup_id);
        }

        let authorization_is_unchanged = self.ready
            && self.root_cgroup_id == Some(root_cgroup_id)
            && self.owners == owners
            && self.foreign_candidates == foreign_candidates
            && self.applied_drop_counts.as_ref() == Some(&listener_drop_counts);
        if !authorization_is_unchanged {
            self.authorization_revision = self.authorization_revision.wrapping_add(1).max(1);
        }

        self.clear_ownership();
        self.association_count = owners.values().map(HashSet::len).sum();
        self.owners = owners;
        self.foreign_candidates = foreign_candidates;
        self.root_cgroup_id = Some(root_cgroup_id);
        self.applied_cut_ns = in_flight.cut_ns;
        self.applied_generation = Some(generation);
        self.applied_drop_counts = Some(listener_drop_counts);
        self.ready = true;
        Ok(true)
    }

    #[cfg(test)]
    pub fn apply_snapshot(
        &mut self,
        generation: u64,
        snapshot: ListenerSnapshot,
        association_limit: usize,
    ) -> Result<bool, String> {
        self.apply_snapshot_with_loss(generation, snapshot, vec![0], association_limit)
    }

    /// Fail closed when an authoritative snapshot cannot be completed.
    pub fn fail_snapshot(&mut self, generation: u64) -> bool {
        if self
            .in_flight
            .as_ref()
            .is_none_or(|in_flight| in_flight.generation != generation)
        {
            return false;
        }
        self.in_flight = None;
        self.clear_ownership();
        true
    }

    /// Invalidate both current ownership and any eventual result from a task
    /// started under an old/disabled configuration.
    pub fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1).max(1);
        self.in_flight = None;
        self.root_cgroup_id = None;
        self.applied_cut_ns = 0;
        self.applied_generation = None;
        self.applied_drop_counts = None;
        self.clear_ownership();
    }

    // The additive cgroup-scoping slice consumes this typed lookup. Socket
    // cgroups and foreign runtime candidates deliberately remain separate so a
    // caller cannot mistake namespace-level presence for socket ownership.
    #[allow(dead_code)]
    pub fn evidence_for_port(&self, port: u16) -> PortEvidence {
        if !self.ready {
            return PortEvidence::NotReady;
        }
        let socket_cgroups: HashSet<_> = self
            .owners
            .iter()
            .filter(|((_, candidate_port), _)| *candidate_port == port)
            .flat_map(|(_, cgroups)| cgroups.iter().copied())
            .collect();
        let foreign_runtime_candidates = self
            .foreign_candidates
            .get(&port)
            .cloned()
            .unwrap_or_default();
        if socket_cgroups.is_empty() && foreign_runtime_candidates.is_empty() {
            PortEvidence::Absent
        } else {
            PortEvidence::Present {
                socket_cgroups,
                foreign_runtime_candidates,
            }
        }
    }

    #[cfg(test)]
    pub fn cgroups_for_port(&self, port: u16) -> HashSet<u64> {
        match self.evidence_for_port(port) {
            PortEvidence::Present { socket_cgroups, .. } => socket_cgroups,
            PortEvidence::NotReady | PortEvidence::Absent => HashSet::new(),
        }
    }

    fn clear_ownership(&mut self) {
        self.owners.clear();
        self.foreign_candidates.clear();
        self.association_count = 0;
        self.applied_generation = None;
        self.ready = false;
    }
}

fn validate_association(
    association: ListenerAssociation,
    root_cgroup_id: u64,
) -> Result<(), String> {
    validate_candidate(association.port, association.cgroup_id, root_cgroup_id)?;
    validate_port(association.family, association.port)
}

fn validate_candidate(port: u16, cgroup_id: u64, root_cgroup_id: u64) -> Result<(), String> {
    if cgroup_id == 0 {
        return Err("listener cgroup id is zero".to_string());
    }
    if cgroup_id == root_cgroup_id {
        return Err("listener belongs to the root cgroup".to_string());
    }
    if port == 0 {
        return Err("listener port is zero".to_string());
    }
    Ok(())
}

fn candidate_count<T>(candidates: &HashMap<u16, HashSet<T>>) -> usize {
    candidates.values().map(HashSet::len).sum()
}

fn validate_port(family: u16, port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("listener port is zero".to_string());
    }
    if !matches!(family, 2 | 10) {
        return Err(format!("unsupported listener address family {family}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u64 = 1;
    const LIMIT: usize = 8;

    fn listener(cgroup_id: u64, port: u16) -> ListenerAssociation {
        ListenerAssociation {
            family: 2,
            port,
            cgroup_id,
        }
    }

    fn foreign(port: u16, cgroup_id: u64) -> ForeignListenerCandidate {
        ForeignListenerCandidate {
            port,
            cgroup_id,
            network_namespace: NetworkNamespaceToken::new(2, cgroup_id.saturating_add(100))
                .unwrap(),
        }
    }

    fn snapshot(associations: impl IntoIterator<Item = ListenerAssociation>) -> ListenerSnapshot {
        ListenerSnapshot::new(ROOT, associations, []).unwrap()
    }

    #[test]
    fn pre_cut_change_is_left_to_the_authoritative_snapshot() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert!(state.snapshot_in_flight());

        assert_eq!(
            state.record_delta(listener(10, 8080), 99),
            DeltaOutcome::Quarantined
        );

        assert!(
            state
                .apply_snapshot(generation, snapshot([listener(30, 3000)]), LIMIT)
                .unwrap()
        );
        assert!(state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
        assert_eq!(state.cgroups_for_port(3000), HashSet::from([30]));
    }

    #[test]
    fn post_cut_unclassified_change_discards_snapshot() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();

        assert_eq!(
            state.record_delta(listener(20, 9090), 100),
            DeltaOutcome::Quarantined
        );
        let error = state
            .apply_snapshot(generation, snapshot([listener(30, 3000)]), LIMIT)
            .unwrap_err();

        assert!(error.contains("unclassified listener change"), "{error}");
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(3000).is_empty());
    }

    #[test]
    fn replacement_snapshot_garbage_collects_closed_listeners() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();

        let second = state.begin_snapshot(200).unwrap();
        state
            .apply_snapshot(second, snapshot([listener(20, 9090)]), LIMIT)
            .unwrap();

        assert!(state.cgroups_for_port(8080).is_empty());
        assert_eq!(state.cgroups_for_port(9090), HashSet::from([20]));
    }

    #[test]
    fn identical_replacement_preserves_listener_authorization_revision() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot_with_loss(100, vec![7]).unwrap();
        state
            .apply_snapshot_with_loss(first, snapshot([listener(10, 8080)]), vec![7], LIMIT)
            .unwrap();
        let revision = state.authorization_revision().unwrap();

        let replacement = state.begin_snapshot_with_loss(200, vec![7]).unwrap();
        assert_eq!(state.authorization_revision(), Some(revision));
        state
            .apply_snapshot_with_loss(replacement, snapshot([listener(10, 8080)]), vec![7], LIMIT)
            .unwrap();

        assert_eq!(state.authorization_revision(), Some(revision));
        assert_eq!(state.authorization_generation(), Some(replacement));

        let changed = state.begin_snapshot_with_loss(300, vec![7]).unwrap();
        state
            .apply_snapshot_with_loss(changed, snapshot([listener(20, 9090)]), vec![7], LIMIT)
            .unwrap();
        assert_ne!(state.authorization_revision(), Some(revision));
    }

    #[test]
    fn live_delta_invalidates_ready_state_and_periodic_snapshot() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();

        let second = state.begin_snapshot(200).unwrap();
        assert_eq!(
            state.record_delta(listener(20, 9090), 201),
            DeltaOutcome::Invalidated
        );
        assert!(!state.is_ready());
        assert!(
            state
                .apply_snapshot(second, snapshot([listener(10, 8080)]), LIMIT)
                .is_err()
        );

        assert!(state.cgroups_for_port(8080).is_empty());
        assert!(state.cgroups_for_port(9090).is_empty());
    }

    #[test]
    fn delayed_pre_cut_delta_cannot_resurrect_snapshot_state() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(generation, snapshot(std::iter::empty()), LIMIT)
            .unwrap();

        assert_eq!(
            state.record_delta(listener(10, 8080), 99),
            DeltaOutcome::IgnoredBeforeCut
        );
        assert!(state.cgroups_for_port(8080).is_empty());
    }

    #[test]
    fn snapshot_failure_clears_previous_ownership() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();
        let second = state.begin_snapshot(200).unwrap();

        assert!(state.fail_snapshot(second));
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
    }

    #[test]
    fn reset_invalidates_an_in_flight_result() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert!(state.snapshot_is_current(generation));
        state.reset();
        assert!(!state.snapshot_is_current(generation));

        assert!(
            !state
                .apply_snapshot(generation, snapshot([listener(10, 8080)]), LIMIT)
                .unwrap()
        );
        assert!(!state.is_ready());
    }

    #[test]
    fn root_and_zero_cgroups_are_rejected() {
        assert!(ListenerSnapshot::new(ROOT, [listener(0, 8080)], []).is_err());
        assert!(ListenerSnapshot::new(ROOT, [listener(ROOT, 8080)], []).is_err());
    }

    #[test]
    fn families_are_distinct_but_port_lookup_unions_them() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let ipv4 = listener(10, 8080);
        let ipv6 = ListenerAssociation {
            family: 10,
            cgroup_id: 20,
            ..ipv4
        };
        state
            .apply_snapshot(generation, snapshot([ipv4, ipv6]), LIMIT)
            .unwrap();

        assert_eq!(state.association_count(), 2);
        assert_eq!(state.cgroups_for_port(8080), HashSet::from([10, 20]));
    }

    #[test]
    fn repeated_post_cut_changes_keep_snapshot_quarantined() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert_eq!(
            state.record_delta(listener(10, 8080), 101),
            DeltaOutcome::Quarantined
        );
        assert_eq!(
            state.record_delta(listener(10, 8080), 102),
            DeltaOutcome::Quarantined
        );

        assert!(
            state
                .apply_snapshot(generation, snapshot([]), LIMIT)
                .is_err()
        );
        assert!(!state.is_ready());
    }

    #[test]
    fn unclassified_live_change_invalidates_ready_state_immediately() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();

        assert_eq!(
            state.record_delta(listener(20, 9090), 101),
            DeltaOutcome::Invalidated
        );
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
        assert!(state.cgroups_for_port(9090).is_empty());
    }

    #[test]
    fn kernel_listener_loss_across_snapshot_fails_closed() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot_with_loss(100, vec![7]).unwrap();

        let error = state
            .apply_snapshot_with_loss(generation, snapshot([listener(10, 8080)]), vec![8], LIMIT)
            .unwrap_err();

        assert!(error.contains("lost events"));
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
    }

    #[test]
    fn kernel_listener_loss_between_snapshots_invalidates_previous_ownership() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot_with_loss(100, vec![7]).unwrap();
        state
            .apply_snapshot_with_loss(first, snapshot([listener(10, 8080)]), vec![7], LIMIT)
            .unwrap();
        assert!(state.is_ready());

        let repair = state.begin_snapshot_with_loss(200, vec![8]).unwrap();
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());

        state
            .apply_snapshot_with_loss(repair, snapshot([listener(20, 9090)]), vec![8], LIMIT)
            .unwrap();
        assert!(state.is_ready());
        assert_eq!(state.cgroups_for_port(9090), HashSet::from([20]));
    }

    #[test]
    fn kernel_listener_loss_during_cgroup_resolution_invalidates_authorization() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot_with_loss(100, vec![7]).unwrap();
        state
            .apply_snapshot_with_loss(generation, snapshot([listener(10, 8080)]), vec![7], LIMIT)
            .unwrap();

        assert_eq!(state.authorization_generation(), Some(generation));
        let error = state.validate_authorization(generation, &[8]).unwrap_err();

        assert!(error.contains("lost events"), "{error}");
        assert!(!state.is_ready());
        assert_eq!(state.authorization_generation(), None);
    }

    #[test]
    fn foreign_candidates_stay_distinct_from_socket_cgroups() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot = ListenerSnapshot::new(
            ROOT,
            [listener(10, 8080), listener(20, 9090)],
            [foreign(8080, 30)],
        )
        .unwrap();

        state.apply_snapshot(generation, snapshot, LIMIT).unwrap();

        assert_eq!(
            state.evidence_for_port(8080),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([10]),
                foreign_runtime_candidates: HashSet::from([ForeignRuntimeIdentity {
                    cgroup_id: 30,
                    network_namespace: foreign(8080, 30).network_namespace,
                }]),
            }
        );
        assert_eq!(
            state.evidence_for_port(9090),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([20]),
                foreign_runtime_candidates: HashSet::new(),
            }
        );
    }

    #[test]
    fn unclassified_live_delta_cannot_merge_into_snapshot_evidence() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot = ListenerSnapshot::new(ROOT, [], [foreign(8080, 10)]).unwrap();
        state.apply_snapshot(generation, snapshot, LIMIT).unwrap();

        assert_eq!(
            state.record_delta(listener(30, 8080), 101),
            DeltaOutcome::Invalidated
        );
        assert_eq!(state.evidence_for_port(8080), PortEvidence::NotReady);
    }

    #[test]
    fn replacement_snapshot_rejects_post_cut_unclassified_delta() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(
                first,
                ListenerSnapshot::new(ROOT, [], [foreign(8080, 10)]).unwrap(),
                LIMIT,
            )
            .unwrap();

        let second = state.begin_snapshot(200).unwrap();
        assert_eq!(
            state.record_delta(listener(30, 8080), 201),
            DeltaOutcome::Invalidated
        );
        assert!(
            state
                .apply_snapshot(second, ListenerSnapshot::new(ROOT, [], []).unwrap(), LIMIT)
                .is_err()
        );

        assert_eq!(state.evidence_for_port(8080), PortEvidence::NotReady);
    }

    #[test]
    fn foreign_candidate_evidence_counts_toward_capacity_and_is_validated() {
        assert!(ListenerSnapshot::new(ROOT, [], [foreign(0, 10)]).is_err());
        assert!(ListenerSnapshot::new(ROOT, [], [foreign(8080, 0)]).is_err());
        assert!(ListenerSnapshot::new(ROOT, [], [foreign(8080, ROOT)]).is_err());

        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot =
            ListenerSnapshot::new(ROOT, [], [foreign(8080, 10), foreign(9090, 20)]).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 1).is_err());
        assert!(!state.is_ready());
    }
}
