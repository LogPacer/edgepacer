//! Race-safe listener ownership state.
//!
//! Live BPF events are deltas, not an inventory: they cannot recover listeners
//! that predate program attachment and they do not announce closes. A periodic
//! authoritative snapshot therefore replaces the ownership set, while events
//! observed at or after the snapshot's monotonic cut are replayed over it.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerAssociation {
    pub family: u16,
    pub port: u16,
    pub cgroup_id: u64,
}

#[derive(Debug, Clone)]
pub struct ListenerSnapshot {
    root_cgroup_id: u64,
    associations: HashSet<ListenerAssociation>,
    foreign_candidates: HashMap<u16, HashSet<u64>>,
}

impl ListenerSnapshot {
    pub fn new(
        root_cgroup_id: u64,
        associations: impl IntoIterator<Item = ListenerAssociation>,
        foreign_candidates: impl IntoIterator<Item = (u16, u64)>,
    ) -> Result<Self, String> {
        if root_cgroup_id == 0 {
            return Err("root cgroup id is zero".to_string());
        }

        let associations: HashSet<_> = associations.into_iter().collect();
        for association in &associations {
            validate_association(*association, root_cgroup_id)?;
        }
        let mut candidates_by_port: HashMap<u16, HashSet<u64>> = HashMap::new();
        for (port, cgroup_id) in foreign_candidates {
            validate_candidate(port, cgroup_id, root_cgroup_id)?;
            candidates_by_port
                .entry(port)
                .or_default()
                .insert(cgroup_id);
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
    Inserted,
    AlreadyPresent,
    Buffered,
    IgnoredBeforeCut,
    IgnoredInvalid,
    AtCapacity { should_warn: bool },
    BufferAtCapacity { should_warn: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortEvidence {
    NotReady,
    Absent,
    Present {
        /// Socket-creation cgroups observed by sock_diag or live BPF. These are
        /// exact socket facts, not proof of which cgroup consumes traffic.
        socket_cgroups: HashSet<u64>,
        /// Runtime cgroups whose foreign network namespace contained the port.
        /// Target resolution must intersect these candidates with explicit
        /// runtime/service identity before authorizing anything.
        foreign_runtime_cgroups: HashSet<u64>,
    },
}

#[derive(Debug)]
struct InFlightSnapshot {
    generation: u64,
    cut_ns: u64,
    listener_drop_counts: Vec<u64>,
    deltas: HashMap<ListenerAssociation, u64>,
    overflowed: bool,
    overflow_warning_emitted: bool,
}

#[derive(Debug, Default)]
pub struct ListenerState {
    owners: HashMap<(u16, u16), HashSet<u64>>,
    foreign_candidates: HashMap<u16, HashSet<u64>>,
    foreign_candidate_count: usize,
    association_count: usize,
    capacity_warning_emitted: bool,
    root_cgroup_id: Option<u64>,
    applied_cut_ns: u64,
    applied_drop_counts: Option<Vec<u64>>,
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
            deltas: HashMap::new(),
            overflowed: false,
            overflow_warning_emitted: false,
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
        association_limit: usize,
        delta_limit: usize,
    ) -> DeltaOutcome {
        if observed_at_ns == 0
            || association.port == 0
            || !matches!(association.family, 2 | 10)
            || association.cgroup_id == 0
            || self.root_cgroup_id == Some(association.cgroup_id)
        {
            return DeltaOutcome::IgnoredInvalid;
        }

        let mut outcome = if self.ready {
            if observed_at_ns < self.applied_cut_ns {
                DeltaOutcome::IgnoredBeforeCut
            } else {
                self.insert(association, association_limit)
            }
        } else {
            DeltaOutcome::Buffered
        };

        if let Some(in_flight) = self.in_flight.as_mut()
            && observed_at_ns >= in_flight.cut_ns
        {
            if let Some(timestamp) = in_flight.deltas.get_mut(&association) {
                *timestamp = (*timestamp).max(observed_at_ns);
            } else if in_flight.deltas.len() < delta_limit {
                in_flight.deltas.insert(association, observed_at_ns);
            } else {
                in_flight.overflowed = true;
                let should_warn = !in_flight.overflow_warning_emitted;
                in_flight.overflow_warning_emitted = true;
                outcome = DeltaOutcome::BufferAtCapacity { should_warn };
            }
        }

        // Once either bounded set drops an association, ownership is no longer
        // authoritative. Invalidate it in the same call; waiting for the
        // snapshot worker would leave a partial allow-set usable meanwhile.
        if matches!(
            outcome,
            DeltaOutcome::AtCapacity { .. } | DeltaOutcome::BufferAtCapacity { .. }
        ) {
            self.clear_ownership();
        }

        outcome
    }

    /// Replace ownership with an authoritative snapshot and replay every live
    /// delta at or after its cut. `Ok(false)` means a stale result arrived after
    /// reset or a newer generation and was ignored.
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
        if in_flight.overflowed {
            self.clear_ownership();
            return Err("listener deltas exceeded the snapshot replay limit".to_string());
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
        let mut associations = snapshot.associations;
        let foreign_candidates = snapshot.foreign_candidates;
        for (association, observed_at_ns) in in_flight.deltas {
            if observed_at_ns < in_flight.cut_ns
                || validate_association(association, root_cgroup_id).is_err()
            {
                continue;
            }
            associations.insert(association);
        }
        let foreign_candidate_count = candidate_count(&foreign_candidates);
        let replayed_evidence_count = associations.len().saturating_add(foreign_candidate_count);
        if replayed_evidence_count > association_limit {
            self.clear_ownership();
            return Err(format!(
                "snapshot plus replay contains {replayed_evidence_count} listener evidence records (limit {association_limit})"
            ));
        }

        let mut owners: HashMap<(u16, u16), HashSet<u64>> = HashMap::new();
        for association in associations {
            owners
                .entry((association.family, association.port))
                .or_default()
                .insert(association.cgroup_id);
        }

        self.clear_ownership();
        self.association_count = owners.values().map(HashSet::len).sum();
        self.owners = owners;
        self.foreign_candidates = foreign_candidates;
        self.foreign_candidate_count = foreign_candidate_count;
        self.root_cgroup_id = Some(root_cgroup_id);
        self.applied_cut_ns = in_flight.cut_ns;
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
        let foreign_runtime_cgroups = self
            .foreign_candidates
            .get(&port)
            .cloned()
            .unwrap_or_default();
        if socket_cgroups.is_empty() && foreign_runtime_cgroups.is_empty() {
            PortEvidence::Absent
        } else {
            PortEvidence::Present {
                socket_cgroups,
                foreign_runtime_cgroups,
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

    fn insert(&mut self, association: ListenerAssociation, limit: usize) -> DeltaOutcome {
        let key = (association.family, association.port);
        if self
            .owners
            .get(&key)
            .is_some_and(|owners| owners.contains(&association.cgroup_id))
        {
            return DeltaOutcome::AlreadyPresent;
        }
        if self
            .association_count
            .saturating_add(self.foreign_candidate_count)
            >= limit
        {
            let should_warn = !self.capacity_warning_emitted;
            self.capacity_warning_emitted = true;
            return DeltaOutcome::AtCapacity { should_warn };
        }

        self.owners
            .entry(key)
            .or_default()
            .insert(association.cgroup_id);
        self.association_count += 1;
        DeltaOutcome::Inserted
    }

    fn clear_ownership(&mut self) {
        self.owners.clear();
        self.foreign_candidates.clear();
        self.foreign_candidate_count = 0;
        self.association_count = 0;
        self.capacity_warning_emitted = false;
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

fn candidate_count(candidates: &HashMap<u16, HashSet<u64>>) -> usize {
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

    fn snapshot(associations: impl IntoIterator<Item = ListenerAssociation>) -> ListenerSnapshot {
        ListenerSnapshot::new(ROOT, associations, []).unwrap()
    }

    #[test]
    fn first_snapshot_replays_only_deltas_at_or_after_the_cut() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert!(state.snapshot_in_flight());

        assert_eq!(
            state.record_delta(listener(10, 8080), 99, LIMIT, LIMIT),
            DeltaOutcome::Buffered
        );
        assert_eq!(
            state.record_delta(listener(20, 9090), 100, LIMIT, LIMIT),
            DeltaOutcome::Buffered
        );

        assert!(
            state
                .apply_snapshot(generation, snapshot([listener(30, 3000)]), LIMIT)
                .unwrap()
        );
        assert!(state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
        assert_eq!(state.cgroups_for_port(9090), HashSet::from([20]));
        assert_eq!(state.cgroups_for_port(3000), HashSet::from([30]));
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
    fn live_delta_survives_a_periodic_snapshot_race() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();

        let second = state.begin_snapshot(200).unwrap();
        assert_eq!(
            state.record_delta(listener(20, 9090), 201, LIMIT, LIMIT),
            DeltaOutcome::Inserted
        );
        state
            .apply_snapshot(second, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();

        assert_eq!(state.cgroups_for_port(9090), HashSet::from([20]));
    }

    #[test]
    fn delayed_pre_cut_delta_cannot_resurrect_snapshot_state() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(generation, snapshot(std::iter::empty()), LIMIT)
            .unwrap();

        assert_eq!(
            state.record_delta(listener(10, 8080), 99, LIMIT, LIMIT),
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
    fn replay_buffer_overflow_fails_closed() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert_eq!(
            state.record_delta(listener(10, 8080), 101, LIMIT, 1),
            DeltaOutcome::Buffered
        );
        assert_eq!(
            state.record_delta(listener(20, 9090), 102, LIMIT, 1),
            DeltaOutcome::BufferAtCapacity { should_warn: true }
        );

        assert!(
            state
                .apply_snapshot(generation, snapshot([]), LIMIT)
                .is_err()
        );
        assert!(!state.is_ready());
    }

    #[test]
    fn repeated_delta_does_not_exhaust_the_replay_buffer() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        assert_eq!(
            state.record_delta(listener(10, 8080), 101, LIMIT, 1),
            DeltaOutcome::Buffered
        );
        assert_eq!(
            state.record_delta(listener(10, 8080), 102, LIMIT, 1),
            DeltaOutcome::Buffered
        );

        assert!(
            state
                .apply_snapshot(generation, snapshot([]), LIMIT)
                .unwrap()
        );
        assert_eq!(state.cgroups_for_port(8080), HashSet::from([10]));
    }

    #[test]
    fn replay_overflow_invalidates_ready_state_immediately() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), LIMIT)
            .unwrap();
        state.begin_snapshot(200).unwrap();

        assert_eq!(
            state.record_delta(listener(20, 9090), 201, LIMIT, 0),
            DeltaOutcome::BufferAtCapacity { should_warn: true }
        );
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
        assert!(state.cgroups_for_port(9090).is_empty());
    }

    #[test]
    fn live_association_overflow_invalidates_ready_state_immediately() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(first, snapshot([listener(10, 8080)]), 1)
            .unwrap();

        assert_eq!(
            state.record_delta(listener(20, 9090), 101, 1, LIMIT),
            DeltaOutcome::AtCapacity { should_warn: true }
        );
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
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
    fn foreign_candidates_stay_distinct_from_socket_cgroups() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot =
            ListenerSnapshot::new(ROOT, [listener(10, 8080), listener(20, 9090)], [(8080, 30)])
                .unwrap();

        state.apply_snapshot(generation, snapshot, LIMIT).unwrap();

        assert_eq!(
            state.evidence_for_port(8080),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([10]),
                foreign_runtime_cgroups: HashSet::from([30]),
            }
        );
        assert_eq!(
            state.evidence_for_port(9090),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([20]),
                foreign_runtime_cgroups: HashSet::new(),
            }
        );
    }

    #[test]
    fn live_delta_is_preserved_alongside_foreign_candidates() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot = ListenerSnapshot::new(ROOT, [], [(8080, 10)]).unwrap();
        state.apply_snapshot(generation, snapshot, LIMIT).unwrap();

        assert_eq!(
            state.record_delta(listener(30, 8080), 101, LIMIT, LIMIT),
            DeltaOutcome::Inserted
        );
        assert_eq!(
            state.evidence_for_port(8080),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([30]),
                foreign_runtime_cgroups: HashSet::from([10]),
            }
        );
    }

    #[test]
    fn replacement_snapshot_can_clear_foreign_candidates_and_replay_a_live_delta() {
        let mut state = ListenerState::default();
        let first = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(
                first,
                ListenerSnapshot::new(ROOT, [], [(8080, 10)]).unwrap(),
                LIMIT,
            )
            .unwrap();

        let second = state.begin_snapshot(200).unwrap();
        assert_eq!(
            state.record_delta(listener(30, 8080), 201, LIMIT, LIMIT),
            DeltaOutcome::Inserted
        );
        state
            .apply_snapshot(second, ListenerSnapshot::new(ROOT, [], []).unwrap(), LIMIT)
            .unwrap();

        assert_eq!(
            state.evidence_for_port(8080),
            PortEvidence::Present {
                socket_cgroups: HashSet::from([30]),
                foreign_runtime_cgroups: HashSet::new(),
            }
        );
    }

    #[test]
    fn foreign_candidate_evidence_counts_toward_capacity_and_is_validated() {
        assert!(ListenerSnapshot::new(ROOT, [], [(0, 10)]).is_err());
        assert!(ListenerSnapshot::new(ROOT, [], [(8080, 0)]).is_err());
        assert!(ListenerSnapshot::new(ROOT, [], [(8080, ROOT)]).is_err());

        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let snapshot = ListenerSnapshot::new(ROOT, [], [(8080, 10), (9090, 20)]).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 1).is_err());
        assert!(!state.is_ready());
    }

    #[test]
    fn foreign_candidates_reduce_the_remaining_live_association_capacity() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(
                generation,
                ListenerSnapshot::new(ROOT, [], [(8080, 10)]).unwrap(),
                2,
            )
            .unwrap();

        assert_eq!(
            state.record_delta(listener(20, 9090), 101, 2, LIMIT),
            DeltaOutcome::Inserted
        );
        assert_eq!(
            state.record_delta(listener(30, 3000), 102, 2, LIMIT),
            DeltaOutcome::AtCapacity { should_warn: true }
        );
        assert!(!state.is_ready());
    }
}
