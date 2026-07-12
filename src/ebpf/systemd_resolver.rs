//! Exact systemd-unit cgroup resolution for eBPF capture.
//!
//! Listener state is only a host-namespace presence gate. Authorization comes
//! from an exact, loaded, active systemd service identity whose ControlGroup is
//! resolved on the verified host cgroup-v2 hierarchy. Identity is observed on
//! both sides of the cgroup lookup so a concurrent restart fails closed.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::io::Read;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::process::{Command, Output, Stdio};
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::time::{Duration, Instant};

use super::cgroup_v2::{self, CgroupAnchor};
use super::listener_state::{ListenerState, PortEvidence};
use crate::config::EbpfTargetConfig;
use crate::discovery::RuntimeProcessIdentity;

const SYSTEMD_UNIT_MAX_BYTES: usize = 255;
const SYSTEMD_SHOW_PROPERTIES: [&str; 5] =
    ["Id", "LoadState", "ActiveState", "MainPID", "ControlGroup"];
// Linux assigns this fixed inode to the initial PID namespace. See
// include/linux/proc_ns.h (PROC_PID_INIT_INO).
const INITIAL_PID_NAMESPACE_INO: u64 = 0xEFFF_FFFC;
// Same idea for the initial network namespace, but the net ns has NO
// proc_ns.h constant — init_net takes the FIRST dynamically allocated ns
// inum, 0xF0000000, deterministic since Linux 3.8 because init_net registers
// before any other netns can exist (verified 4026531840 on the 6.8 fleet).
// Checking our own ns inode against it proves host-netns membership without
// touching /proc/1/ns/net, whose stat is ptrace-gated (init is non-dumpable)
// — the exact capability this resolver exists to avoid.
const INITIAL_NET_NAMESPACE_INO: u64 = 0xF000_0000;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
const SYSTEMCTL_SHOW_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(all(target_os = "linux", feature = "ebpf"))]
const SYSTEMCTL_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
    pub(crate) main_process: RuntimeProcessIdentity,
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

fn validate_host_systemd_context(
    uses_initial_cgroup_namespace: bool,
    pid_namespace_inode: u64,
    net_namespace_inode: u64,
    init_comm: &str,
) -> Result<(), String> {
    if !uses_initial_cgroup_namespace {
        return Err("systemd cgroup targeting requires the initial cgroup namespace".to_string());
    }
    if pid_namespace_inode != INITIAL_PID_NAMESPACE_INO {
        return Err(format!(
            "systemd cgroup targeting requires the initial PID namespace (found inode {pid_namespace_inode})"
        ));
    }
    if net_namespace_inode != INITIAL_NET_NAMESPACE_INO {
        return Err(format!(
            "systemd cgroup targeting requires the initial network namespace (found inode {net_namespace_inode})"
        ));
    }
    if init_comm.trim() != "systemd" {
        return Err(format!(
            "systemd cgroup targeting requires host PID 1 to be systemd (found {init_comm:?})"
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn namespace_inode(path: &Path) -> Result<u64, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("failed to inspect namespace {}: {error}", path.display()))?;
    Ok(metadata.ino())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn require_host_systemd_context() -> Result<(), String> {
    let uses_initial_cgroup_namespace = cgroup_v2::uses_initial_cgroup_namespace()
        .map_err(|error| format!("failed to verify systemd cgroup namespace: {error}"))?;
    let pid_namespace_inode = namespace_inode(Path::new("/proc/self/ns/pid"))?;
    let net_namespace_inode = namespace_inode(Path::new("/proc/self/ns/net"))?;
    let init_comm = std::fs::read_to_string("/proc/1/comm")
        .map_err(|error| format!("failed to identify host PID 1: {error}"))?;

    validate_host_systemd_context(
        uses_initial_cgroup_namespace,
        pid_namespace_inode,
        net_namespace_inode,
        &init_comm,
    )
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn spawn_pipe_reader<R>(mut pipe: R) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut contents = Vec::new();
        pipe.read_to_end(&mut contents)?;
        Ok(contents)
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn finish_pipe_reader(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    description: &str,
    stream: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("{stream} reader for {description} panicked"))?
        .map_err(|error| format!("failed to read {stream} from {description}: {error}"))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn command_output_with_timeout(
    mut command: Command,
    description: &str,
    timeout: Duration,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run {description}: {error}"))?;
    let stdout_reader = spawn_pipe_reader(
        child
            .stdout
            .take()
            .expect("piped child stdout is always available"),
    );
    let stderr_reader = spawn_pipe_reader(
        child
            .stderr
            .take()
            .expect("piped child stderr is always available"),
    );
    let started = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = finish_pipe_reader(stdout_reader, description, "stdout")?;
                let stderr = finish_pipe_reader(stderr_reader, description, "stderr")?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if started.elapsed() < timeout => {
                let remaining = timeout.saturating_sub(started.elapsed());
                std::thread::sleep(SYSTEMCTL_POLL_INTERVAL.min(remaining));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("{description} timed out after {timeout:?}"));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("failed while waiting for {description}: {error}"));
            }
        }
    }
}

fn cgroup_path_is_at_or_below(path: &str, ancestor: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn read_process_cgroup_path(pid: u32) -> Result<String, String> {
    let path = format!("/proc/{pid}/cgroup");
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {path}: {error}"))?;
    cgroup_v2::parse_unified_cgroup_path(&contents).map_err(|error| error.to_string())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn bind_systemd_main_process_in_host_context(
    identity: &SystemdUnitIdentity,
) -> Result<(CgroupAnchor, RuntimeProcessIdentity), String> {
    let process = RuntimeProcessIdentity::capture(identity.main_pid).ok_or_else(|| {
        format!(
            "systemd unit {:?} MainPID {} is not a current process",
            identity.unit, identity.main_pid
        )
    })?;
    let before = read_process_cgroup_path(identity.main_pid)?;
    if !cgroup_path_is_at_or_below(&before, &identity.control_group) {
        return Err(format!(
            "systemd unit {:?} MainPID {} is in cgroup {before:?}, outside reported ControlGroup {:?}",
            identity.unit, identity.main_pid, identity.control_group
        ));
    }

    let anchor = cgroup_v2::cgroup_anchor_for_host_path(&identity.control_group)
        .map_err(|error| error.to_string())?;
    let after = read_process_cgroup_path(identity.main_pid)?;
    if after != before || !process.is_current() {
        return Err(format!(
            "systemd unit {:?} MainPID {} changed identity while resolving its cgroup",
            identity.unit, identity.main_pid
        ));
    }
    Ok((anchor, process))
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

fn parse_systemctl_show_many(
    expected_units: &BTreeSet<String>,
    output: &str,
) -> Result<BTreeMap<String, SystemdUnitIdentity>, String> {
    let mut identities = BTreeMap::new();
    for block in output
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
    {
        let mut reported_id = None;
        for line in block.lines().filter(|line| !line.is_empty()) {
            let (key, value) = line.split_once('=').ok_or_else(|| {
                format!("batched systemctl show returned malformed property {line:?}")
            })?;
            if key == "Id" && reported_id.replace(value).is_some() {
                return Err(format!(
                    "batched systemctl show returned duplicate Id property for {value:?}"
                ));
            }
        }
        let unit = reported_id
            .ok_or_else(|| "batched systemctl show omitted an Id property".to_string())?;
        if !expected_units.contains(unit) {
            return Err(format!(
                "batched systemctl show returned unexpected or inexact Id {unit:?}"
            ));
        }
        let identity = parse_systemctl_show(unit, block)?;
        if identities.insert(unit.to_string(), identity).is_some() {
            return Err(format!(
                "batched systemctl show returned duplicate unit {unit:?}"
            ));
        }
    }

    let missing: Vec<_> = expected_units
        .iter()
        .filter(|unit| !identities.contains_key(*unit))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "batched systemctl show omitted configured units {missing:?}"
        ));
    }
    Ok(identities)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn observe_systemd_units(
    units: &BTreeSet<String>,
) -> Result<BTreeMap<String, SystemdUnitIdentity>, String> {
    if units.is_empty() {
        return Ok(BTreeMap::new());
    }
    for unit in units {
        validate_configured_unit(unit)?;
    }

    let mut command = Command::new("systemctl");
    command
        .args([
            "show",
            "--no-pager",
            "--no-ask-password",
            "--property=Id",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
            "--",
        ])
        .args(units.iter().map(String::as_str))
        .env("LC_ALL", "C")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_PATH");
    let description = format!("systemctl show for {} exact units", units.len());
    let output = command_output_with_timeout(command, &description, SYSTEMCTL_SHOW_TIMEOUT)?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("{description} returned invalid UTF-8: {error}"))?;
    parse_systemctl_show_many(units, stdout)
}

#[cfg(all(test, target_os = "linux", feature = "ebpf"))]
fn observe_systemd_unit(unit: &str) -> Result<SystemdUnitIdentity, String> {
    let units = BTreeSet::from([unit.to_string()]);
    observe_systemd_units(&units)?
        .remove(unit)
        .ok_or_else(|| format!("systemctl show omitted configured unit {unit:?}"))
}

fn attest_units_with<Observe, Resolve>(
    units: &BTreeSet<String>,
    mut observe: Observe,
    mut resolve_identity: Resolve,
) -> Result<BTreeMap<String, SystemdAttestation>, String>
where
    Observe: FnMut(&BTreeSet<String>) -> Result<BTreeMap<String, SystemdUnitIdentity>, String>,
    Resolve: FnMut(&SystemdUnitIdentity) -> Result<(CgroupAnchor, RuntimeProcessIdentity), String>,
{
    if units.is_empty() {
        return Ok(BTreeMap::new());
    }
    let before = observe(units)?;
    let mut bindings = BTreeMap::new();
    for (unit, identity) in &before {
        let binding = resolve_identity(identity)?;
        bindings.insert(unit.clone(), binding);
    }
    let after = observe(units)?;

    let mut attestations = BTreeMap::new();
    for unit in units {
        let initial = before
            .get(unit)
            .ok_or_else(|| format!("missing initial systemd identity for {unit:?}"))?;
        let current = after
            .get(unit)
            .ok_or_else(|| format!("missing final systemd identity for {unit:?}"))?;
        if current != initial {
            return Err(format!(
                "systemd unit {unit:?} changed while resolving cgroup identity"
            ));
        }
        let (anchor, main_process) = bindings
            .remove(unit)
            .ok_or_else(|| format!("missing systemd cgroup binding for {unit:?}"))?;
        CgroupAnchor::new(anchor.id, anchor.level).map_err(|error| error.to_string())?;
        attestations.insert(
            unit.clone(),
            SystemdAttestation {
                identity: current.clone(),
                anchor,
                main_process,
            },
        );
    }
    Ok(attestations)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn attest_units(units: &BTreeSet<String>) -> Result<BTreeMap<String, SystemdAttestation>, String> {
    if !units.is_empty() {
        require_host_systemd_context()?;
    }
    attest_units_with(
        units,
        observe_systemd_units,
        bind_systemd_main_process_in_host_context,
    )
}

fn host_listener_present(state: &ListenerState, port: u16) -> bool {
    matches!(
        state.evidence_for_port(port),
        PortEvidence::Present { socket_cgroups, .. } if !socket_cgroups.is_empty()
    )
}

fn eligible_systemd_units(
    targets: &[EbpfTargetConfig],
    state: &ListenerState,
) -> Result<BTreeSet<String>, String> {
    if !state.is_ready() {
        return Ok(BTreeSet::new());
    }

    let mut units = BTreeSet::new();
    for target in targets {
        let Some(unit) = target.systemd_unit.as_deref() else {
            continue;
        };
        validate_configured_unit(unit)?;
        if target
            .open_ports
            .iter()
            .any(|port| host_listener_present(state, *port))
        {
            units.insert(unit.to_string());
        }
    }
    Ok(units)
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
    let units = eligible_systemd_units(targets, state)?;
    let attestations = attest_units(&units)?;
    resolve_with(targets, state, |unit| {
        attestations
            .get(unit)
            .cloned()
            .ok_or_else(|| format!("missing batched systemd attestation for {unit:?}"))
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) fn revalidate(attestations: &[SystemdAttestation]) -> Result<(), String> {
    let units: BTreeSet<_> = attestations
        .iter()
        .map(|attestation| attestation.identity.unit.clone())
        .collect();
    let current = attest_units(&units)?;
    for attestation in attestations {
        if current.get(&attestation.identity.unit) != Some(attestation) {
            return Err(format!(
                "systemd unit {:?} changed identity before cgroup policy publication",
                attestation.identity.unit
            ));
        }
    }
    Ok(())
}

/// Final pre/post-publication check that avoids invoking systemctl on the async
/// runner. The blocking resolver already attested the exact loaded, active unit;
/// this bracket only has to prove that the same MainPID token still resides
/// beneath the same host cgroup anchor while the kernel map is replaced.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) fn revalidate_for_publication(
    attestations: &[SystemdAttestation],
) -> Result<(), String> {
    if attestations.is_empty() {
        return Ok(());
    }
    require_host_systemd_context()?;
    for attestation in attestations {
        let (anchor, main_process) =
            bind_systemd_main_process_in_host_context(&attestation.identity)?;
        if anchor != attestation.anchor || main_process != attestation.main_process {
            return Err(format!(
                "systemd unit {:?} changed kernel identity before cgroup policy publication",
                attestation.identity.unit
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
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

    fn process(pid: u32, start_time_ticks: u64) -> RuntimeProcessIdentity {
        RuntimeProcessIdentity {
            pid,
            start_time_ticks,
        }
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
    fn parses_one_exact_identity_per_batched_unit() {
        let redis =
            show(4321, "/system.slice/redis.service").replace("nginx.service", "redis.service");
        let output = format!("{}\n{redis}", show(1234, "/system.slice/nginx.service"));
        let expected = BTreeSet::from(["nginx.service".to_string(), "redis.service".to_string()]);
        let parsed = parse_systemctl_show_many(&expected, &output).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["nginx.service"].main_pid, 1234);
        assert_eq!(parsed["redis.service"].main_pid, 4321);

        let missing =
            parse_systemctl_show_many(&expected, &show(1234, "/system.slice/nginx.service"))
                .unwrap_err();
        assert!(missing.contains("redis.service"), "{missing}");
        let duplicate = format!(
            "{}\n{}",
            show(1234, "/system.slice/nginx.service"),
            show(1234, "/system.slice/nginx.service")
        );
        assert!(parse_systemctl_show_many(&expected, &duplicate).is_err());
    }

    #[test]
    fn attestation_rejects_identity_change_around_cgroup_lookup() {
        let units = BTreeSet::from(["nginx.service".to_string()]);
        let observations = Cell::new(0usize);
        let events = RefCell::new(Vec::new());
        let error = attest_units_with(
            &units,
            |_| {
                events.borrow_mut().push("observe");
                let index = observations.get();
                observations.set(index + 1);
                Ok(BTreeMap::from([(
                    "nginx.service".to_string(),
                    identity(
                        if index == 0 { 1234 } else { 5678 },
                        "/system.slice/nginx.service",
                    ),
                )]))
            },
            |_| {
                events.borrow_mut().push("resolve");
                Ok((CgroupAnchor { id: 42, level: 2 }, process(1234, 99)))
            },
        )
        .unwrap_err();

        assert!(error.contains("changed while resolving"), "{error}");
        assert_eq!(*events.borrow(), ["observe", "resolve", "observe"]);
    }

    #[test]
    fn only_exact_systemd_targets_with_host_listener_evidence_resolve() {
        let targets = [target(None, &[80]), target(Some("nginx.service"), &[80])];
        let calls = Cell::new(0usize);
        let resolved = resolve_with(&targets, &ready_state(&[80], &[80]), |_unit| {
            calls.set(calls.get() + 1);
            Ok(SystemdAttestation {
                identity: identity(1234, "/system.slice/nginx.service"),
                anchor: CgroupAnchor { id: 42, level: 2 },
                main_process: process(1234, 99),
            })
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].anchor, CgroupAnchor { id: 42, level: 2 });
        assert_ne!(resolved[0].anchor.id, 99);
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
    fn eligible_systemd_units_are_deduplicated_before_observation() {
        let targets = [
            target(Some("nginx.service"), &[80]),
            target(Some("nginx.service"), &[443]),
        ];
        let units = eligible_systemd_units(&targets, &ready_state(&[80, 443], &[])).unwrap();

        assert_eq!(units, BTreeSet::from(["nginx.service".to_string()]));
    }

    #[test]
    fn full_capacity_attestation_uses_two_batched_observations() {
        let units: BTreeSet<_> = (0..1024)
            .map(|index| format!("service-{index}.service"))
            .collect();
        let observations = Cell::new(0usize);
        let bindings = Cell::new(0usize);
        let attestations = attest_units_with(
            &units,
            |requested| {
                observations.set(observations.get() + 1);
                Ok(requested
                    .iter()
                    .enumerate()
                    .map(|(index, unit)| {
                        (
                            unit.clone(),
                            SystemdUnitIdentity {
                                unit: unit.clone(),
                                main_pid: u32::try_from(index + 10).unwrap(),
                                control_group: format!("/system.slice/{unit}"),
                            },
                        )
                    })
                    .collect())
            },
            |identity| {
                bindings.set(bindings.get() + 1);
                Ok((
                    CgroupAnchor {
                        id: u64::from(identity.main_pid) + 1000,
                        level: 2,
                    },
                    process(identity.main_pid, u64::from(identity.main_pid) + 2000),
                ))
            },
        )
        .unwrap();

        assert_eq!(attestations.len(), 1024);
        assert_eq!(observations.get(), 2);
        assert_eq!(bindings.get(), 1024);
    }

    #[test]
    fn configured_unit_validation_rejects_non_service_or_path_like_names() {
        for unit in ["", "nginx", "../nginx.service", "nginx service.service"] {
            assert!(validate_configured_unit(unit).is_err(), "accepted {unit:?}");
        }
        assert!(validate_configured_unit("nginx@tenant.service").is_ok());
    }

    #[test]
    fn systemd_targeting_requires_host_pid_cgroup_and_network_namespaces() {
        assert!(
            validate_host_systemd_context(
                true,
                INITIAL_PID_NAMESPACE_INO,
                INITIAL_NET_NAMESPACE_INO,
                "systemd\n",
            )
            .is_ok()
        );

        for (label, initial_cgroup, pid_inode, net_inode, init_comm) in [
            (
                "private cgroup",
                false,
                INITIAL_PID_NAMESPACE_INO,
                INITIAL_NET_NAMESPACE_INO,
                "systemd\n",
            ),
            (
                "private pid",
                true,
                INITIAL_PID_NAMESPACE_INO + 1,
                INITIAL_NET_NAMESPACE_INO,
                "systemd\n",
            ),
            (
                "private network",
                true,
                INITIAL_PID_NAMESPACE_INO,
                INITIAL_NET_NAMESPACE_INO + 1,
                "systemd\n",
            ),
            (
                "non-systemd init",
                true,
                INITIAL_PID_NAMESPACE_INO,
                INITIAL_NET_NAMESPACE_INO,
                "tini\n",
            ),
        ] {
            assert!(
                validate_host_systemd_context(initial_cgroup, pid_inode, net_inode, init_comm,)
                    .is_err(),
                "accepted {label} context"
            );
        }
    }

    #[test]
    fn main_process_must_remain_beneath_reported_control_group() {
        assert!(cgroup_path_is_at_or_below(
            "/system.slice/nginx.service",
            "/system.slice/nginx.service"
        ));
        assert!(cgroup_path_is_at_or_below(
            "/system.slice/nginx.service/worker",
            "/system.slice/nginx.service"
        ));
        assert!(!cgroup_path_is_at_or_below(
            "/system.slice/nginx.service-other",
            "/system.slice/nginx.service"
        ));
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn command_timeout_kills_and_reaps_a_wedged_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do :; done"]);
        let started = Instant::now();
        let error =
            command_output_with_timeout(command, "wedged test child", Duration::from_millis(25))
                .unwrap_err();

        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn command_output_drains_batch_sized_stdout_without_pipe_deadlock() {
        let mut command = Command::new("head");
        command.args(["-c", "131072", "/dev/zero"]);
        let output =
            command_output_with_timeout(command, "large-output test child", Duration::from_secs(2))
                .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 131_072);
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
        routing.revalidate_publication_identities().unwrap();

        service.stop();
        let error = routing.revalidate_identities().unwrap_err();
        assert!(error.contains(&service.unit), "{error}");
        let error = routing.revalidate_publication_identities().unwrap_err();
        assert!(error.contains(&service.unit), "{error}");
    }
}
