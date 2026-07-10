//! PID resolution for eBPF capture — maps configured targets to the live PIDs
//! the kernel program must filter on, and back-maps each PID to the target that
//! owns it (so a captured event can be routed to that target's destination/repo).
//!
//! Today the only PID source is the listening-ports census
//! ([`crate::discovery::ports`]): an operator declares a service's `open_ports`,
//! and the census resolves those ports to their owning PIDs (procfs inode map on
//! Linux). An OBI-style process-event feed is the planned alternative source —
//! it is the same open-ports signal with a latency accelerator and richer
//! process attributes, not a different signal. Both produce a [`PidRouting`],
//! which is the stable seam between PID sourcing and the manager: a future feed
//! adds a sibling `resolve_from_*` without touching the manager.

use std::collections::HashMap;

use crate::config::EbpfTargetConfig;
use crate::discovery::ports::ListeningPort;

/// Resolved PID → service routing for eBPF capture: the currency type every PID
/// source produces. It seeds the kernel `TARGET_PIDS` filter
/// ([`target_pids`](Self::target_pids)) and routes each captured event back to
/// the owning target ([`service_for`](Self::service_for)).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PidRouting {
    /// pid → owning target's `log_source_id`.
    by_pid: HashMap<u32, String>,
    policy_generation: Option<u64>,
}

// `service_for` (event routing) gets its consumer in the capture-routing slice,
// and `len`/`is_empty` are used by callers and the unit tests; on the linux+ebpf
// build (where tests don't compile) they read as unused, so allow the staged
// accessor surface rather than churn it in and out. `target_pids` is used now.
#[allow(dead_code)]
impl PidRouting {
    /// Construct routing from already-resolved PID ownership. Identical
    /// duplicate entries collapse; conflicting ownership fails closed so test
    /// seams and future PID sources cannot silently select config order.
    pub(crate) fn from_entries<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (u32, S)>,
        S: Into<String>,
    {
        let mut by_pid = HashMap::new();
        for (pid, service) in entries {
            if pid == 0 {
                return Err("PID routing cannot contain PID 0".to_string());
            }
            let service = service.into();
            if service.is_empty() {
                return Err(format!("PID {pid} has an empty log source id"));
            }
            if let Some(existing) = by_pid.get(&pid) {
                if existing != &service {
                    return Err(format!(
                        "PID {pid} ambiguously maps to log sources {existing:?} and {service:?}"
                    ));
                }
                continue;
            }
            by_pid.insert(pid, service);
        }
        let policy_generation = (!by_pid.is_empty()).then_some(1);
        Ok(Self {
            by_pid,
            policy_generation,
        })
    }

    /// The PIDs to seed into the kernel `TARGET_PIDS` map.
    pub fn target_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.by_pid.keys().copied()
    }

    /// The `log_source_id` of the target that owns `pid`, or `None` if `pid` is
    /// not a capture target.
    pub fn service_for(&self, pid: u32) -> Option<&str> {
        self.by_pid.get(&pid).map(String::as_str)
    }

    pub(crate) fn policy_generation(&self) -> Option<u64> {
        self.policy_generation
    }

    pub(crate) fn assign_policy_generation(&mut self, generation: u64) -> Result<(), String> {
        if self.by_pid.is_empty() {
            if generation != 0 {
                return Err("empty PID routing must use policy generation zero".to_string());
            }
            self.policy_generation = None;
        } else {
            if generation == 0 {
                return Err("nonempty PID routing requires a policy generation".to_string());
            }
            self.policy_generation = Some(generation);
        }
        Ok(())
    }

    pub(crate) fn same_authorization_as(&self, other: &Self) -> bool {
        self.by_pid == other.by_pid
    }

    /// Number of distinct PIDs being captured.
    pub fn len(&self) -> usize {
        self.by_pid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pid.is_empty()
    }
}

/// Resolve PID routing by matching a listening-ports census against each
/// target's `open_ports`.
///
/// One port may be served by several PIDs at once (a `SO_REUSEPORT` worker pool)
/// — every such PID is captured. Census entries with an unresolved owner
/// (`pid == 0`, the sentinel for "inode→PID lookup failed") are skipped: the
/// kernel filter cannot key on PID 0. If two targets list the same port (a
/// server-side misconfig), the first target in config order claims it.
pub fn resolve_from_ports(census: &[ListeningPort], targets: &[EbpfTargetConfig]) -> PidRouting {
    let mut by_pid: HashMap<u32, String> = HashMap::new();

    for port in census {
        if port.pid == 0 {
            continue;
        }
        let Some(owner) = targets.iter().find(|t| t.open_ports.contains(&port.port)) else {
            continue;
        };
        by_pid
            .entry(port.pid)
            .or_insert_with(|| owner.log_source_id.clone());
    }

    let policy_generation = (!by_pid.is_empty()).then_some(1);
    PidRouting {
        by_pid,
        policy_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn no_targets_capture_nothing() {
        let routing = resolve_from_ports(&[listening(8080, 1234)], &[]);
        assert!(routing.is_empty());
        assert_eq!(routing.service_for(1234), None);
    }

    #[test]
    fn maps_listener_pid_to_owning_target() {
        let targets = [target("src-a", &[8080])];
        let routing = resolve_from_ports(&[listening(8080, 1234)], &targets);
        assert_eq!(routing.service_for(1234), Some("src-a"));
        assert_eq!(routing.len(), 1);
    }

    #[test]
    fn skips_unresolved_pid_zero() {
        let targets = [target("src-a", &[8080])];
        let routing = resolve_from_ports(&[listening(8080, 0)], &targets);
        assert!(routing.is_empty());
    }

    #[test]
    fn ignores_ports_no_target_claims() {
        let targets = [target("src-a", &[8080])];
        let routing = resolve_from_ports(&[listening(9999, 1234)], &targets);
        assert!(routing.is_empty());
    }

    #[test]
    fn attributes_each_port_to_its_own_target() {
        let targets = [target("src-a", &[8080]), target("src-b", &[9090])];
        let census = [listening(8080, 1), listening(9090, 2)];
        let routing = resolve_from_ports(&census, &targets);
        assert_eq!(routing.service_for(1), Some("src-a"));
        assert_eq!(routing.service_for(2), Some("src-b"));
    }

    #[test]
    fn reuseport_captures_every_pid_on_the_port() {
        // A SO_REUSEPORT worker pool: many PIDs share one listening port.
        let targets = [target("src-a", &[8080])];
        let census = [
            listening(8080, 10),
            listening(8080, 11),
            listening(8080, 12),
        ];
        let routing = resolve_from_ports(&census, &targets);
        assert_eq!(routing.len(), 3);
        for pid in [10, 11, 12] {
            assert_eq!(routing.service_for(pid), Some("src-a"));
        }
    }

    #[test]
    fn target_with_no_ports_matches_nothing() {
        let targets = [target("src-a", &[])];
        let routing = resolve_from_ports(&[listening(8080, 1234)], &targets);
        assert!(routing.is_empty());
    }

    #[test]
    fn target_pids_lists_all_seeded_pids() {
        let targets = [target("src-a", &[8080]), target("src-b", &[9090])];
        let census = [listening(8080, 1), listening(9090, 2)];
        let routing = resolve_from_ports(&census, &targets);
        let mut pids: Vec<u32> = routing.target_pids().collect();
        pids.sort_unstable();
        assert_eq!(pids, vec![1, 2]);
    }

    #[test]
    fn conflicting_targets_resolve_to_config_order() {
        // Two targets claim port 8080 (misconfig); the first in config order wins.
        let targets = [target("src-first", &[8080]), target("src-second", &[8080])];
        let routing = resolve_from_ports(&[listening(8080, 1234)], &targets);
        assert_eq!(routing.service_for(1234), Some("src-first"));
    }

    #[test]
    fn direct_entries_dedupe_agreement_and_reject_conflict() {
        let routing = PidRouting::from_entries([(42, "src-a"), (42, "src-a")]).unwrap();
        assert_eq!(routing.service_for(42), Some("src-a"));

        let error = PidRouting::from_entries([(42, "src-a"), (42, "src-b")]).unwrap_err();
        assert!(error.contains("ambiguously maps"), "{error}");
        assert!(PidRouting::from_entries([(0, "src-a")]).is_err());
    }
}
