//! Exact systemd-unit cgroup resolution for eBPF capture.
//!
//! Listener state is only a host-namespace presence gate. Authorization comes
//! from an exact, loaded, active systemd service identity whose ControlGroup is
//! resolved on the verified host cgroup-v2 hierarchy. Identity is observed on
//! both sides of the cgroup lookup so a concurrent restart fails closed.

use std::collections::BTreeMap;
use std::path::Path;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::process::Command;

use super::cgroup_v2::{self, CgroupAnchor};
use super::listener_state::{ListenerState, PortEvidence};
use crate::config::EbpfTargetConfig;

const SYSTEMD_UNIT_MAX_BYTES: usize = 255;
const SYSTEMD_SHOW_PROPERTIES: [&str; 5] =
    ["Id", "LoadState", "ActiveState", "MainPID", "ControlGroup"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SystemdUnitIdentity {
    pub(crate) unit: String,
    pub(crate) main_pid: u32,
    pub(crate) control_group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SystemdAttestation {
    pub(crate) identity: SystemdUnitIdentity,
    pub(crate) anchor: CgroupAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedSystemdTarget {
    pub(crate) anchor: CgroupAnchor,
    pub(crate) log_source_id: String,
    pub(crate) attestation: SystemdAttestation,
}

fn validate_configured_unit(unit: &str) -> Result<(), String> {
    if unit.is_empty()
        || unit.len() > SYSTEMD_UNIT_MAX_BYTES
        || !unit.ends_with(".service")
        || unit.contains('/')
        || unit
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!("invalid configured systemd service unit {unit:?}"));
    }
    Ok(())
}

fn parse_systemctl_show(expected_unit: &str, output: &str) -> Result<SystemdUnitIdentity, String> {
    validate_configured_unit(expected_unit)?;

    let mut properties = BTreeMap::new();
    for line in output.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!("systemctl show for {expected_unit:?} returned malformed property {line:?}")
        })?;
        if !SYSTEMD_SHOW_PROPERTIES.contains(&key) {
            return Err(format!(
                "systemctl show for {expected_unit:?} returned unexpected property {key:?}"
            ));
        }
        if properties.insert(key, value).is_some() {
            return Err(format!(
                "systemctl show for {expected_unit:?} returned duplicate property {key:?}"
            ));
        }
    }

    let required = |key| {
        properties
            .get(key)
            .copied()
            .ok_or_else(|| format!("systemctl show for {expected_unit:?} omitted property {key}"))
    };
    let unit = required("Id")?;
    if unit != expected_unit {
        return Err(format!(
            "configured systemd unit {expected_unit:?} resolved as inexact Id {unit:?}"
        ));
    }
    if required("LoadState")? != "loaded" {
        return Err(format!("systemd unit {expected_unit:?} is not loaded"));
    }
    if required("ActiveState")? != "active" {
        return Err(format!("systemd unit {expected_unit:?} is not active"));
    }

    let main_pid = required("MainPID")?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| format!("systemd unit {expected_unit:?} has no nonzero MainPID"))?;
    let control_group = required("ControlGroup")?;
    if control_group == "/" {
        return Err(format!(
            "systemd unit {expected_unit:?} resolved to the root cgroup"
        ));
    }
    cgroup_v2::join_cgroup_mount(Path::new("/sys/fs/cgroup"), control_group)
        .map_err(|error| error.to_string())?;

    Ok(SystemdUnitIdentity {
        unit: unit.to_string(),
        main_pid,
        control_group: control_group.to_string(),
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn observe_systemd_unit(unit: &str) -> Result<SystemdUnitIdentity, String> {
    validate_configured_unit(unit)?;
    let output = Command::new("systemctl")
        .args([
            "show",
            "--no-pager",
            "--property=Id",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
            "--",
            unit,
        ])
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("failed to run systemctl show for {unit:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemctl show for {unit:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("systemctl show for {unit:?} returned invalid UTF-8: {error}"))?;
    parse_systemctl_show(unit, stdout)
}

fn attest_unit_with<Observe, Resolve>(
    unit: &str,
    mut observe: Observe,
    mut resolve_control_group: Resolve,
) -> Result<SystemdAttestation, String>
where
    Observe: FnMut(&str) -> Result<SystemdUnitIdentity, String>,
    Resolve: FnMut(&str) -> Result<CgroupAnchor, String>,
{
    validate_configured_unit(unit)?;
    let before = observe(unit)?;
    if before.unit != unit {
        return Err(format!(
            "configured systemd unit {unit:?} resolved as inexact Id {:?}",
            before.unit
        ));
    }
    let anchor = resolve_control_group(&before.control_group)?;
    CgroupAnchor::new(anchor.id, anchor.level).map_err(|error| error.to_string())?;
    let after = observe(unit)?;
    if after != before {
        return Err(format!(
            "systemd unit {unit:?} changed while resolving cgroup identity"
        ));
    }

    Ok(SystemdAttestation {
        identity: after,
        anchor,
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn attest_unit(unit: &str) -> Result<SystemdAttestation, String> {
    attest_unit_with(unit, observe_systemd_unit, |control_group| {
        cgroup_v2::cgroup_anchor_for_host_path(control_group).map_err(|error| error.to_string())
    })
}

fn host_listener_present(state: &ListenerState, port: u16) -> bool {
    matches!(
        state.evidence_for_port(port),
        PortEvidence::Present { socket_cgroups, .. } if !socket_cgroups.is_empty()
    )
}

fn resolve_with<Attest>(
    targets: &[EbpfTargetConfig],
    state: &ListenerState,
    mut attest: Attest,
) -> Result<Vec<ResolvedSystemdTarget>, String>
where
    Attest: FnMut(&str) -> Result<SystemdAttestation, String>,
{
    if !state.is_ready() {
        return Ok(Vec::new());
    }

    let mut resolved = Vec::new();
    for target in targets {
        let Some(unit) = target.systemd_unit.as_deref() else {
            continue;
        };
        validate_configured_unit(unit)?;
        if !target
            .open_ports
            .iter()
            .any(|port| host_listener_present(state, *port))
        {
            continue;
        }

        let attestation = attest(unit)?;
        resolved.push(ResolvedSystemdTarget {
            anchor: attestation.anchor,
            log_source_id: target.log_source_id.clone(),
            attestation,
        });
    }
    Ok(resolved)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) fn resolve_from_listener_state(
    targets: &[EbpfTargetConfig],
    state: &ListenerState,
) -> Result<Vec<ResolvedSystemdTarget>, String> {
    resolve_with(targets, state, attest_unit)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) fn revalidate(attestation: &SystemdAttestation) -> Result<(), String> {
    let current = attest_unit(&attestation.identity.unit)?;
    if current != *attestation {
        return Err(format!(
            "systemd unit {:?} changed identity before cgroup policy publication",
            attestation.identity.unit
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::HashSet;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    use std::path::PathBuf;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    use std::process::Command;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::ebpf::listener_state::{
        ForeignListenerCandidate, ListenerAssociation, ListenerSnapshot, NetworkNamespaceToken,
    };

    fn target(systemd_unit: Option<&str>, ports: &[u16]) -> EbpfTargetConfig {
        EbpfTargetConfig {
            log_source_id: "source".to_string(),
            service_name: "nginx".to_string(),
            systemd_unit: systemd_unit.map(str::to_string),
            open_ports: ports.to_vec(),
            archive_id: "archive".to_string(),
            repo_id: "repo".to_string(),
            protocols: Vec::new(),
            subbox_endpoint: "dest".to_string(),
        }
    }

    fn show(main_pid: u32, control_group: &str) -> String {
        format!(
            "Id=nginx.service\nLoadState=loaded\nActiveState=active\nMainPID={main_pid}\nControlGroup={control_group}\n"
        )
    }

    fn identity(main_pid: u32, control_group: &str) -> SystemdUnitIdentity {
        parse_systemctl_show("nginx.service", &show(main_pid, control_group)).unwrap()
    }

    fn ready_state(host_ports: &[u16], foreign_ports: &[u16]) -> ListenerState {
        let associations = host_ports.iter().map(|port| ListenerAssociation {
            family: libc::AF_INET as u16,
            port: *port,
            // Deliberately differs from the resolved service cgroup (42): a
            // systemd socket unit may own the listener while the configured
            // service unit remains the exact capture identity.
            cgroup_id: 99,
        });
        let foreign = foreign_ports.iter().map(|port| ForeignListenerCandidate {
            port: *port,
            cgroup_id: 43,
            network_namespace: NetworkNamespaceToken::new(2, 100).unwrap(),
        });
        let snapshot = ListenerSnapshot::new(1, associations, foreign).unwrap();
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        assert!(state.apply_snapshot(generation, snapshot, 100).unwrap());
        state
    }

    #[test]
    fn parses_exact_loaded_active_service_identity() {
        let parsed =
            parse_systemctl_show("nginx.service", &show(1234, "/system.slice/nginx.service"))
                .unwrap();

        assert_eq!(parsed.unit, "nginx.service");
        assert_eq!(parsed.main_pid, 1234);
        assert_eq!(parsed.control_group, "/system.slice/nginx.service");
    }

    #[test]
    fn rejects_inexact_or_unusable_systemd_identity() {
        for (label, expected_unit, output) in [
            (
                "alias",
                "alias.service",
                show(1234, "/system.slice/nginx.service"),
            ),
            (
                "not loaded",
                "nginx.service",
                show(1234, "/system.slice/nginx.service").replace("loaded", "not-found"),
            ),
            (
                "not active",
                "nginx.service",
                show(1234, "/system.slice/nginx.service").replace("active", "inactive"),
            ),
            (
                "no main pid",
                "nginx.service",
                show(0, "/system.slice/nginx.service"),
            ),
            ("root cgroup", "nginx.service", show(1234, "/")),
            (
                "unsafe cgroup",
                "nginx.service",
                show(1234, "/system.slice/../user.slice"),
            ),
        ] {
            assert!(
                parse_systemctl_show(expected_unit, &output).is_err(),
                "accepted {label}"
            );
        }
    }

    #[test]
    fn rejects_missing_and_duplicate_show_properties() {
        let missing = show(1234, "/system.slice/nginx.service").replace("MainPID=1234\n", "");
        assert!(parse_systemctl_show("nginx.service", &missing).is_err());

        let duplicate = format!(
            "{}MainPID=5678\n",
            show(1234, "/system.slice/nginx.service")
        );
        assert!(parse_systemctl_show("nginx.service", &duplicate).is_err());
    }

    #[test]
    fn attestation_rejects_identity_change_around_cgroup_lookup() {
        let observations = Cell::new(0usize);
        let error = attest_unit_with(
            "nginx.service",
            |_| {
                let index = observations.get();
                observations.set(index + 1);
                Ok(identity(
                    if index == 0 { 1234 } else { 5678 },
                    "/system.slice/nginx.service",
                ))
            },
            |_| Ok(CgroupAnchor { id: 42, level: 2 }),
        )
        .unwrap_err();

        assert!(error.contains("changed while resolving"), "{error}");
    }

    #[test]
    fn only_exact_systemd_targets_with_host_listener_evidence_resolve() {
        let targets = [target(None, &[80]), target(Some("nginx.service"), &[80])];
        let calls = Cell::new(0usize);
        let resolved = resolve_with(&targets, &ready_state(&[80], &[]), |_unit| {
            calls.set(calls.get() + 1);
            Ok(SystemdAttestation {
                identity: identity(1234, "/system.slice/nginx.service"),
                anchor: CgroupAnchor { id: 42, level: 2 },
            })
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].log_source_id, "source");
        assert_eq!(resolved[0].attestation.identity.unit, "nginx.service");

        let calls = Cell::new(0usize);
        let resolved = resolve_with(&targets, &ready_state(&[], &[80]), |_| {
            calls.set(calls.get() + 1);
            unreachable!("foreign-only listener evidence must not authorize systemd")
        })
        .unwrap();
        assert!(resolved.is_empty());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn configured_unit_validation_rejects_non_service_or_path_like_names() {
        for unit in ["", "nginx", "../nginx.service", "nginx service.service"] {
            assert!(validate_configured_unit(unit).is_err(), "accepted {unit:?}");
        }
        assert!(validate_configured_unit("nginx@tenant.service").is_ok());
    }

    #[test]
    fn host_listener_gate_ignores_foreign_candidates_when_host_is_present() {
        let state = ready_state(&[80], &[80]);
        let evidence = state.evidence_for_port(80);
        let PortEvidence::Present {
            socket_cgroups,
            foreign_runtime_candidates,
        } = evidence
        else {
            panic!("expected present listener evidence");
        };
        assert_eq!(socket_cgroups, HashSet::from([99]));
        assert_eq!(foreign_runtime_candidates.len(), 1);
        assert!(host_listener_present(&state, 80));
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    struct TransientSystemdService {
        unit: String,
        port_file: PathBuf,
        stopped: bool,
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    impl TransientSystemdService {
        fn start() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let unit = format!(
                "edgepacer-ebpf-cgroup-{}-{nonce}.service",
                std::process::id()
            );
            let port_file = PathBuf::from(format!("/run/{unit}.port"));
            let python = r#"
import os
import socket
import sys
import time

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(16)
with open(sys.argv[1], "w", encoding="ascii") as handle:
    handle.write(str(listener.getsockname()[1]))
    handle.flush()
    os.fsync(handle.fileno())
while True:
    time.sleep(60)
"#;
            let output = Command::new("systemd-run")
                .args([
                    "--collect",
                    "--property=Type=exec",
                    "--unit",
                    &unit,
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    python,
                    port_file.to_str().unwrap(),
                ])
                .output()
                .expect("run transient systemd service");
            assert!(
                output.status.success(),
                "systemd-run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let service = Self {
                unit,
                port_file,
                stopped: false,
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if service.port().is_some()
                    && Command::new("systemctl")
                        .args(["is-active", "--quiet", "--", &service.unit])
                        .status()
                        .is_ok_and(|status| status.success())
                {
                    return service;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!(
                "transient systemd service {:?} did not publish a listening port",
                service.unit
            );
        }

        fn port(&self) -> Option<u16> {
            std::fs::read_to_string(&self.port_file)
                .ok()
                .and_then(|contents| contents.trim().parse().ok())
        }

        fn stop(&mut self) {
            let status = Command::new("systemctl")
                .args(["stop", "--", &self.unit])
                .status()
                .expect("stop transient systemd service");
            assert!(status.success(), "failed to stop {:?}", self.unit);
            self.stopped = true;
            let _ = std::fs::remove_file(&self.port_file);
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    impl Drop for TransientSystemdService {
        fn drop(&mut self) {
            if !self.stopped {
                let _ = Command::new("systemctl")
                    .args(["stop", "--", &self.unit])
                    .status();
            }
            let _ = std::fs::remove_file(&self.port_file);
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    #[ignore = "requires root on a systemd host with unified cgroup v2"]
    fn live_exact_systemd_unit_resolves_and_revalidation_rejects_stop() {
        let mut service = TransientSystemdService::start();
        let port = service.port().expect("transient listener port");
        let snapshot = crate::ebpf::listener_snapshot::collect(
            &[],
            Instant::now() + Duration::from_secs(10),
            16_384,
        )
        .unwrap();
        let mut listener_state = ListenerState::default();
        let generation = listener_state.begin_snapshot(1).unwrap();
        assert!(
            listener_state
                .apply_snapshot(generation, snapshot, 16_384)
                .unwrap()
        );

        let targets = [target(Some(&service.unit), &[port])];
        let routing = crate::ebpf::cgroup_resolver::resolve_from_listener_state(
            &[],
            &targets,
            &listener_state,
            11,
        )
        .unwrap();
        let identity = observe_systemd_unit(&service.unit).unwrap();
        let expected = cgroup_v2::cgroup_anchor_for_host_path(&identity.control_group).unwrap();
        let anchors: Vec<_> = routing.allowed_cgroups().collect();

        assert_eq!(anchors, vec![expected]);
        assert_eq!(routing.service_for(expected.id), Some("source"));
        routing.revalidate_identities().unwrap();

        service.stop();
        let error = routing.revalidate_identities().unwrap_err();
        assert!(error.contains(&service.unit), "{error}");
    }
}
