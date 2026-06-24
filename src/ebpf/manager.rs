//! eBPF capture manager — owns the loaded program(s) and drives them toward the
//! desired `config::ebpf_section()` with Start/Reconcile/Stop on the section
//! `config_hash`, mirroring `trace_proxy_manager.rs`.
//!
//! Unlike the trace proxy manager (one proxy per `log_source_id`), eBPF capture
//! is **one** kernel program serving **many** PIDs, so this manager is a
//! singleton lifecycle keyed on the whole section's `config_hash`, plus a
//! per-tick refresh of the kernel `TARGET_PIDS` filter from the live ports
//! census.
//!
//! The kernel side sits behind [`CaptureProgram`] so the reconcile orchestration
//! is unit-tested on every platform with a fake; the real aya-backed
//! implementation is the single Linux+`ebpf` boundary filled once the BPF object
//! is embedded.

use tracing::{debug, info};

use super::pid_resolver::{PidRouting, resolve_from_ports};
use crate::config::EbpfSectionConfig;
use crate::discovery::ports::ListeningPort;

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
/// PID-seed failure reports `running: false` with the error, even though the
/// program may remain loaded for the next tick to retry the seed.
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
}

impl<P: CaptureProgram> EbpfManager<P> {
    pub fn new(program: P) -> Self {
        Self {
            program,
            state: ManagerState::Stopped,
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
                info!("eBPF capture stopped (disabled)");
                None
            }
            ReconcileAction::Start => self.start(section).err(),
            ReconcileAction::Restart => {
                self.program.stop();
                self.state = ManagerState::Stopped;
                info!("eBPF capture restarting (config changed)");
                self.start(section).err()
            }
        };

        let mut routing = PidRouting::default();
        if error.is_none() && matches!(self.state, ManagerState::Running { .. }) {
            routing = resolve_from_ports(census, &section.targets);
            if let Err(e) = self.program.set_target_pids(&routing) {
                error = Some(e);
            } else {
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
            info!("eBPF capture shut down");
        }
    }

    /// Load + attach, advancing to `Running` only on success — so `running`
    /// never reports true for a program that failed to attach.
    fn start(&mut self, section: &EbpfSectionConfig) -> Result<(), String> {
        self.program.start(section)?;
        self.state = ManagerState::Running {
            config_hash: section.config_hash.clone(),
        };
        info!(config_hash = %section.config_hash, "eBPF capture started");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EbpfTargetConfig;

    #[derive(Default)]
    struct FakeProgram {
        started: usize,
        stopped: usize,
        seeded: Vec<PidRouting>,
        fail_start: bool,
        fail_seed: bool,
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
            config_hash: config_hash.to_string(),
        }
    }

    fn target(log_source_id: &str, ports: &[u16]) -> EbpfTargetConfig {
        EbpfTargetConfig {
            log_source_id: log_source_id.to_string(),
            service_name: "service".to_string(),
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
    fn pid_seed_failure_reports_not_running_but_stays_loaded() {
        let program = FakeProgram {
            fail_seed: true,
            ..FakeProgram::default()
        };
        let mut manager = EbpfManager::new(program);
        let outcome = manager.reconcile(&section(true, "h1", vec![]), &[]);
        assert!(!outcome.running);
        assert_eq!(outcome.last_error.as_deref(), Some("seed failed"));
        // The program stays loaded so the next tick retries the seed without reload.
        assert_eq!(
            manager.state,
            ManagerState::Running {
                config_hash: "h1".to_string()
            }
        );
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
}
