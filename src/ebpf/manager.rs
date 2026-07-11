//! eBPF capture manager — owns the loaded program(s) and drives them toward the
//! desired `config::ebpf_section()` with Start/Reconcile/Stop on the section
//! `config_hash`, mirroring `trace_proxy_manager.rs`.
//!
//! Unlike the trace proxy manager (one proxy per `log_source_id`), eBPF capture
//! is one kernel program serving many workloads. This manager owns its singleton
//! lifecycle, refreshes the temporary PID fallback from the live port census,
//! and atomically replaces the cgroup allow-set built from authoritative
//! listener and runtime identity.
//!
//! The kernel side sits behind [`CaptureProgram`] so the reconcile orchestration
//! is unit-tested on every platform with a fake; the real aya-backed
//! implementation is the single Linux+`ebpf` boundary filled once the BPF object
//! is embedded.

use tokio::sync::oneshot;
use tracing::{debug, info};

use super::cgroup_resolver::CgroupRouting;
use super::pid_resolver::{PidRouting, resolve_from_ports};
use crate::config::EbpfSectionConfig;
use crate::discovery::ports::ListeningPort;

/// Identity and loss epoch of the currently-running mandatory listener drain.
/// A capture restart changes `generation`, so stale health from an aborted
/// predecessor cannot validate or tear down its replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerObservation {
    pub generation: u64,
    pub drop_counts: Vec<u64>,
    pub published_counts: Vec<u64>,
}

/// The kernel-program side of eBPF capture — the single boundary the manager
/// drives. The real implementation loads/attaches aya programs and writes the
/// `TARGET_PIDS` map; it is Linux+`ebpf`-only. Tests substitute a fake.
pub trait CaptureProgram {
    /// Load and attach the capture program(s) for `section`. Called only from
    /// the `Stopped` state.
    fn start(&mut self, section: &EbpfSectionConfig) -> Result<(), String>;

    /// Detach and unload. Called only from the `Running` state.
    fn stop(&mut self);

    /// Make the kernel `TARGET_PIDS` filter reflect exactly `routing`. Called
    /// each tick while running so newly-started and exited PIDs track the census.
    fn set_target_pids(&mut self, routing: &PidRouting) -> Result<(), String>;

    /// Atomically replace the kernel cgroup allow-set with `routing`. Called
    /// only while running, after userspace has established an authoritative
    /// workload identity snapshot.
    fn set_allowed_cgroups(&mut self, routing: &CgroupRouting) -> Result<(), String>;

    /// Current listener-drain generation and per-CPU monotonic counts of events
    /// published or lost. This fails if the mandatory drain died.
    #[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
    fn listener_observation(&self) -> Result<ListenerObservation, String>;

    /// Request an acknowledgement after the mandatory drain has forwarded all
    /// listener records through every sampled per-CPU publication count.
    #[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
    fn listener_fence(
        &self,
        published_counts: Vec<u64>,
    ) -> Result<oneshot::Receiver<Result<(), String>>, String>;
}

/// Whether the capture program is loaded, and under which section `config_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagerState {
    Stopped,
    Running { config_hash: String },
}

/// The lifecycle change a reconcile tick implies — derived purely from the
/// current state and the desired section.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReconcileAction {
    /// Converged: no load/unload this tick.
    Noop,
    /// Not loaded and wanted → load + attach.
    Start,
    /// Loaded and no longer wanted → detach + unload.
    Stop,
    /// Loaded under a stale `config_hash` → unload, then load the new config.
    Restart,
}

/// Decide the lifecycle action for a reconcile tick. Pure: the manager's
/// decision logic, independent of the kernel side.
fn decide(current: &ManagerState, desired: &EbpfSectionConfig) -> ReconcileAction {
    match (current, desired.enabled) {
        (ManagerState::Stopped, false) => ReconcileAction::Noop,
        (ManagerState::Stopped, true) => ReconcileAction::Start,
        (ManagerState::Running { .. }, false) => ReconcileAction::Stop,
        (ManagerState::Running { config_hash }, true) => {
            if *config_hash == desired.config_hash {
                ReconcileAction::Noop
            } else {
                ReconcileAction::Restart
            }
        }
    }
}

/// The result of a reconcile tick, for publishing into `SharedEbpfStatus`.
///
/// `running` is a **runtime truth** (decision 2): it is true only when the
/// program is loaded *and* this tick completed cleanly. A load/attach or
/// PID-seed failure reports `running: false` with the error. Seed failure also
/// unloads the program so a stale kernel filter cannot keep capturing while
/// userspace reports the subsystem stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub running: bool,
    pub last_error: Option<String>,
    /// The PID→service routing seeded this tick (empty when not running). The
    /// runner reuses it to route drained `CapturedLine`s to the right target.
    pub routing: PidRouting,
}

/// Owns the capture program and tracks its lifecycle state.
pub struct EbpfManager<P: CaptureProgram> {
    program: P,
    state: ManagerState,
    active_pid_routing: PidRouting,
    next_pid_policy_generation: u64,
}

impl<P: CaptureProgram> EbpfManager<P> {
    pub fn new(program: P) -> Self {
        Self {
            program,
            state: ManagerState::Stopped,
            active_pid_routing: PidRouting::default(),
            next_pid_policy_generation: 0,
        }
    }

    /// Drive the program toward `section`, then (while running) refresh the
    /// kernel PID filter from `census`.
    pub fn reconcile(
        &mut self,
        section: &EbpfSectionConfig,
        census: &[ListeningPort],
    ) -> ReconcileOutcome {
        let mut error = match decide(&self.state, section) {
            ReconcileAction::Noop => None,
            ReconcileAction::Stop => {
                self.program.stop();
                self.state = ManagerState::Stopped;
                self.active_pid_routing = PidRouting::default();
                info!("eBPF capture stopped (disabled)");
                None
            }
            ReconcileAction::Start => self.start(section).err(),
            ReconcileAction::Restart => {
                self.program.stop();
                self.state = ManagerState::Stopped;
                self.active_pid_routing = PidRouting::default();
                info!("eBPF capture restarting (config changed)");
                self.start(section).err()
            }
        };

        let mut routing = PidRouting::default();
        if error.is_none() && matches!(self.state, ManagerState::Running { .. }) {
            routing = resolve_from_ports(census, &section.targets);
            if !routing.is_empty() {
                let generation = if routing.same_authorization_as(&self.active_pid_routing) {
                    self.active_pid_routing
                        .policy_generation()
                        .unwrap_or_else(|| self.next_pid_generation())
                } else {
                    self.next_pid_generation()
                };
                if let Err(e) = routing.assign_policy_generation(generation) {
                    self.program.stop();
                    self.state = ManagerState::Stopped;
                    self.active_pid_routing = PidRouting::default();
                    routing = PidRouting::default();
                    error = Some(e);
                }
            }
            if error.is_none()
                && let Err(e) = self.program.set_target_pids(&routing)
            {
                self.program.stop();
                self.state = ManagerState::Stopped;
                self.active_pid_routing = PidRouting::default();
                routing = PidRouting::default();
                error = Some(e);
            } else if error.is_none() {
                self.active_pid_routing = routing.clone();
                debug!(pids = routing.len(), "refreshed eBPF target PIDs");
            }
        }

        ReconcileOutcome {
            running: matches!(self.state, ManagerState::Running { .. }) && error.is_none(),
            last_error: error,
            routing,
        }
    }

    /// Stop the program if running. Idempotent.
    pub fn shutdown(&mut self) {
        if matches!(self.state, ManagerState::Running { .. }) {
            self.program.stop();
            self.state = ManagerState::Stopped;
            self.active_pid_routing = PidRouting::default();
            info!("eBPF capture shut down");
        }
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
    pub fn listener_observation(&self) -> Result<ListenerObservation, String> {
        if !matches!(self.state, ManagerState::Running { .. }) {
            return Err("listener observation requested while capture is stopped".to_string());
        }
        self.program.listener_observation()
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
    pub fn listener_fence(
        &self,
        published_counts: Vec<u64>,
    ) -> Result<oneshot::Receiver<Result<(), String>>, String> {
        if !matches!(self.state, ManagerState::Running { .. }) {
            return Err("listener fence requested while capture is stopped".to_string());
        }
        self.program.listener_fence(published_counts)
    }

    /// Replace the active cgroup policy while capture is running. A failed map
    /// update makes the kernel's effective policy uncertain, so fail closed by
    /// unloading the entire capture program and returning to `Stopped`.
    pub fn set_allowed_cgroups(&mut self, routing: &CgroupRouting) -> Result<(), String> {
        if !matches!(self.state, ManagerState::Running { .. }) {
            return Err("set_allowed_cgroups requested while capture is stopped".to_string());
        }
        if let Err(error) = self.program.set_allowed_cgroups(routing) {
            self.program.stop();
            self.state = ManagerState::Stopped;
            return Err(error);
        }
        Ok(())
    }

    /// Load + attach, advancing to `Running` only on success — so `running`
    /// never reports true for a program that failed to attach.
    fn start(&mut self, section: &EbpfSectionConfig) -> Result<(), String> {
        self.program.start(section)?;
        self.active_pid_routing = PidRouting::default();
        self.state = ManagerState::Running {
            config_hash: section.config_hash.clone(),
        };
        info!(config_hash = %section.config_hash, "eBPF capture started");
        Ok(())
    }

    fn next_pid_generation(&mut self) -> u64 {
        self.next_pid_policy_generation = self.next_pid_policy_generation.wrapping_add(1).max(1);
        self.next_pid_policy_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EbpfTargetConfig;
    use crate::ebpf::cgroup_resolver::CgroupAnchor;

    #[derive(Default)]
    struct FakeProgram {
        started: usize,
        stopped: usize,
        seeded: Vec<PidRouting>,
        seeded_cgroups: Vec<CgroupRouting>,
        fail_start: bool,
        fail_seed: bool,
        fail_cgroup_seed: bool,
    }

    impl CaptureProgram for FakeProgram {
        fn start(&mut self, _section: &EbpfSectionConfig) -> Result<(), String> {
            self.started += 1;
            if self.fail_start {
                Err("load failed".to_string())
            } else {
                Ok(())
            }
        }

        fn stop(&mut self) {
            self.stopped += 1;
        }

        fn set_target_pids(&mut self, routing: &PidRouting) -> Result<(), String> {
            if self.fail_seed {
                return Err("seed failed".to_string());
            }
            self.seeded.push(routing.clone());
            Ok(())
        }

        fn set_allowed_cgroups(&mut self, routing: &CgroupRouting) -> Result<(), String> {
            if self.fail_cgroup_seed {
                return Err("cgroup seed failed".to_string());
            }
            self.seeded_cgroups.push(routing.clone());
            Ok(())
        }

        fn listener_observation(&self) -> Result<ListenerObservation, String> {
            Ok(ListenerObservation {
                generation: 1,
                drop_counts: vec![0],
                published_counts: vec![0],
            })
        }

        fn listener_fence(
            &self,
            _published_counts: Vec<u64>,
        ) -> Result<oneshot::Receiver<Result<(), String>>, String> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Ok(()));
            Ok(rx)
        }
    }

    fn section(
        enabled: bool,
        config_hash: &str,
        targets: Vec<EbpfTargetConfig>,
    ) -> EbpfSectionConfig {
        EbpfSectionConfig {
            enabled,
            receiver_port: 4318,
            network_flows_enabled: false,
            network_cidrs: Vec::new(),
            targets,
            service_map: None,
            config_hash: config_hash.to_string(),
        }
    }

    fn target(log_source_id: &str, ports: &[u16]) -> EbpfTargetConfig {
        EbpfTargetConfig {
            log_source_id: log_source_id.to_string(),
            service_name: "service".to_string(),
            systemd_unit: None,
            open_ports: ports.to_vec(),
            archive_id: "archive".to_string(),
            repo_id: "repo".to_string(),
            protocols: Vec::new(),
            subbox_endpoint: "dest".to_string(),
        }
    }

    fn listening(port: u16, pid: u32) -> ListeningPort {
        ListeningPort {
            port,
            protocol: "tcp".to_string(),
            process: "proc".to_string(),
            pid,
        }
    }

    #[test]
    fn disabled_from_stopped_is_noop() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        let outcome = manager.reconcile(&section(false, "h1", vec![]), &[]);
        assert!(!outcome.running);
        assert_eq!(outcome.last_error, None);
        assert_eq!(manager.program.started, 0);
    }

    #[test]
    fn enabled_from_stopped_starts() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        let outcome = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(outcome.running);
        assert_eq!(manager.program.started, 1);
        assert_eq!(
            manager.state,
            ManagerState::Running {
                config_hash: "h1".to_string()
            }
        );
    }

    #[test]
    fn disabled_while_running_stops() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.reconcile(&section(true, "h1", vec![]), &[]);
        let outcome = manager.reconcile(&section(false, "h1", vec![]), &[]);
        assert!(!outcome.running);
        assert_eq!(manager.program.stopped, 1);
        assert_eq!(manager.state, ManagerState::Stopped);
    }

    #[test]
    fn config_hash_change_restarts() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.reconcile(&section(true, "h1", vec![]), &[]);
        let outcome = manager.reconcile(&section(true, "h2", vec![]), &[]);
        assert!(outcome.running);
        assert_eq!(manager.program.started, 2);
        assert_eq!(manager.program.stopped, 1);
        assert_eq!(
            manager.state,
            ManagerState::Running {
                config_hash: "h2".to_string()
            }
        );
    }

    #[test]
    fn same_hash_keeps_running_and_refreshes_pids() {
        let targets = vec![target("src-a", &[8080])];
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.reconcile(
            &section(true, "h1", targets.clone()),
            &[listening(8080, 100)],
        );
        let outcome = manager.reconcile(&section(true, "h1", targets), &[listening(8080, 200)]);
        assert!(outcome.running);
        assert_eq!(manager.program.started, 1); // not restarted
        assert_eq!(manager.program.stopped, 0);
        // Seeded once per tick; the second tick reflects the new census PID.
        assert_eq!(manager.program.seeded.len(), 2);
        assert_eq!(manager.program.seeded[1].service_for(200), Some("src-a"));
        assert_ne!(
            manager.program.seeded[0].policy_generation(),
            manager.program.seeded[1].policy_generation()
        );

        let stable_generation = manager.program.seeded[1].policy_generation();
        manager.reconcile(
            &section(true, "h1", vec![target("src-a", &[8080])]),
            &[listening(8080, 200)],
        );
        assert_eq!(
            manager.program.seeded[2].policy_generation(),
            stable_generation
        );
    }

    #[test]
    fn start_failure_surfaces_error_and_stays_stopped() {
        let program = FakeProgram {
            fail_start: true,
            ..FakeProgram::default()
        };
        let mut manager = EbpfManager::new(program);
        let outcome = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(!outcome.running);
        assert_eq!(outcome.last_error.as_deref(), Some("load failed"));
        assert_eq!(manager.state, ManagerState::Stopped);
        // No PID seed attempted when the program never loaded.
        assert!(manager.program.seeded.is_empty());
    }

    #[test]
    fn pid_seed_failure_unloads_and_restarts_cleanly_on_retry() {
        let program = FakeProgram {
            fail_seed: true,
            ..FakeProgram::default()
        };
        let mut manager = EbpfManager::new(program);
        let outcome = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(!outcome.running);
        assert_eq!(outcome.last_error.as_deref(), Some("seed failed"));
        assert!(outcome.routing.is_empty());
        assert_eq!(manager.state, ManagerState::Stopped);
        assert_eq!(manager.program.stopped, 1);

        manager.program.fail_seed = false;
        let retry = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(retry.running);
        assert_eq!(manager.program.started, 2);
    }

    #[test]
    fn seeds_resolved_pids_from_census() {
        let targets = vec![target("src-a", &[8080])];
        let mut manager = EbpfManager::new(FakeProgram::default());
        let outcome = manager.reconcile(&section(true, "h1", targets), &[listening(8080, 4242)]);
        assert!(outcome.running);
        assert_eq!(manager.program.seeded.len(), 1);
        assert_eq!(manager.program.seeded[0].service_for(4242), Some("src-a"));
        // The runner reuses this routing to deliver drained lines.
        assert_eq!(outcome.routing.service_for(4242), Some("src-a"));
    }

    #[test]
    fn shutdown_stops_a_running_program() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.reconcile(&section(true, "h1", vec![]), &[]);
        manager.shutdown();
        assert_eq!(manager.program.stopped, 1);
        assert_eq!(manager.state, ManagerState::Stopped);
    }

    #[test]
    fn shutdown_when_stopped_is_a_noop() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.shutdown();
        assert_eq!(manager.program.stopped, 0);
    }

    #[test]
    fn allowed_cgroup_policy_can_be_set_and_cleared_while_running() {
        let mut manager = EbpfManager::new(FakeProgram::default());
        manager.reconcile(&section(true, "h1", vec![]), &[]);

        let routing =
            CgroupRouting::from_entries(7, [(CgroupAnchor { id: 42, level: 3 }, "src-a")]).unwrap();
        manager.set_allowed_cgroups(&routing).unwrap();

        manager
            .set_allowed_cgroups(&CgroupRouting::default())
            .unwrap();

        assert_eq!(manager.program.seeded_cgroups.len(), 2);
        assert_eq!(
            manager.program.seeded_cgroups[0].service_for(42),
            Some("src-a")
        );
        assert!(manager.program.seeded_cgroups[1].is_empty());
        assert!(matches!(manager.state, ManagerState::Running { .. }));
    }

    #[test]
    fn allowed_cgroup_seed_failure_unloads_and_restarts_cleanly() {
        let program = FakeProgram {
            fail_cgroup_seed: true,
            ..FakeProgram::default()
        };
        let mut manager = EbpfManager::new(program);
        manager.reconcile(&section(true, "h1", vec![]), &[]);

        let error = manager
            .set_allowed_cgroups(&CgroupRouting::default())
            .unwrap_err();

        assert_eq!(error, "cgroup seed failed");
        assert_eq!(manager.state, ManagerState::Stopped);
        assert_eq!(manager.program.stopped, 1);

        manager.program.fail_cgroup_seed = false;
        let retry = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(retry.running);
        assert_eq!(manager.program.started, 2);
        assert_eq!(manager.program.stopped, 1);
    }

    #[test]
    fn allowed_cgroup_policy_cannot_be_set_while_stopped() {
        let mut manager = EbpfManager::new(FakeProgram::default());

        let error = manager
            .set_allowed_cgroups(&CgroupRouting::default())
            .unwrap_err();

        assert_eq!(
            error,
            "set_allowed_cgroups requested while capture is stopped"
        );
        assert!(manager.program.seeded_cgroups.is_empty());
        assert_eq!(manager.program.stopped, 0);
    }
}
