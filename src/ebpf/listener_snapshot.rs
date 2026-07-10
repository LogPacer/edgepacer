//! Authoritative TCP listener inventory.
//!
//! `NETLINK_SOCK_DIAG` provides exact socket→cgroup ownership in EdgePacer's
//! current network namespace. The API cannot inspect another namespace without
//! `setns(2)`/`CAP_SYS_ADMIN`, so isolated runtime namespaces use their init
//! PID's `/proc/<pid>/net/tcp{,6}` tables. Those tables prove only that a port
//! exists in that namespace, not which cgroup owns or handles its socket, so
//! foreign evidence is retained but quarantined per port.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;
use std::io::BufRead;
#[cfg(test)]
use std::io::Cursor;
#[cfg(target_os = "linux")]
use std::io::{BufReader, Read};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::time::Instant;

use thiserror::Error;

use super::cgroup_v2;
#[cfg(target_os = "linux")]
use super::listener_state::{ListenerAssociation, ListenerSnapshot};
use super::sock_diag;
use crate::discovery::{Container, RuntimeProcessIdentity};

#[cfg(target_os = "linux")]
const MAX_PROC_NETWORK_TABLE_ROWS: usize = 262_144;
#[cfg(target_os = "linux")]
const MAX_PROC_NETWORK_TABLE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum ListenerSnapshotError {
    #[error(transparent)]
    Cgroup(#[from] cgroup_v2::CgroupV2Error),
    #[error(transparent)]
    SockDiag(#[from] sock_diag::SnapshotError),
    #[error("running container {0:?} has no runtime identity")]
    MissingRuntimeIdentity(String),
    #[error("running container {0:?} has no runtime init PID")]
    MissingInitPid(String),
    #[error("runtime container {container:?} has conflicting process identities: {processes:?}")]
    ConflictingRuntimeProcesses {
        container: String,
        processes: BTreeSet<(u32, u64)>,
    },
    #[cfg(target_os = "linux")]
    #[error("runtime container {container:?} init PID {pid} is stale")]
    StaleRuntimeProcess { container: String, pid: u32 },
    #[cfg(target_os = "linux")]
    #[error(
        "runtime container {container:?} init PID {pid} changed network namespace during snapshot"
    )]
    NetworkNamespaceChanged { container: String, pid: u32 },
    #[cfg(target_os = "linux")]
    #[error("network table identity changed while reading {0}")]
    NetworkTableChanged(PathBuf),
    #[cfg(target_os = "linux")]
    #[error(
        "runtime container {container:?} init PID {pid} changed cgroup during snapshot ({before} -> {after})"
    )]
    CgroupChanged {
        container: String,
        pid: u32,
        before: u64,
        after: u64,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid {source_name} row {line}: {reason}")]
    InvalidProcTable {
        source_name: String,
        line: usize,
        reason: String,
    },
    #[cfg(target_os = "linux")]
    #[error("invalid authoritative listener snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("authoritative listener snapshot exceeded its deadline while {0}")]
    Deadline(&'static str),
    #[error("authoritative listener snapshot exceeded its {0}-evidence limit")]
    Capacity(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuntimeSource {
    runtime_id: String,
    process: RuntimeProcessIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NetworkTableIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct NamespaceSources {
    sources: BTreeMap<RuntimeSource, u64>,
}

/// Collect one all-or-nothing listener snapshot. Any missing identity or
/// partially readable namespace fails the whole result so a caller can clear
/// its authorization state rather than seed from incomplete evidence.
#[cfg(target_os = "linux")]
pub fn collect(
    containers: &[Container],
    deadline: Instant,
    evidence_limit: usize,
) -> Result<ListenerSnapshot, ListenerSnapshotError> {
    check_deadline(deadline, "starting")?;
    let root_cgroup_id = cgroup_v2::root_cgroup_id()?;
    let mut associations = HashSet::new();
    let mut foreign_candidates = HashSet::new();

    for listener in sock_diag::snapshot_tcp_listeners(deadline, evidence_limit)? {
        insert_unique_evidence(
            &mut associations,
            foreign_candidates.len(),
            ListenerAssociation {
                family: listener.family,
                port: listener.port,
                cgroup_id: listener.cgroup_id,
            },
            evidence_limit,
        )?;
    }

    let self_netns = network_table_identity(Path::new("/proc/self/net/tcp"))?;
    let mut namespaces: BTreeMap<NetworkTableIdentity, NamespaceSources> = BTreeMap::new();
    for source in runtime_sources(containers)? {
        check_deadline(deadline, "identifying runtime namespaces")?;
        let pid = source.process.pid();
        ensure_current_runtime_process(&source)?;
        let table_path = PathBuf::from(format!("/proc/{pid}/net/tcp"));
        let netns = network_table_identity(&table_path)?;
        let cgroup_id = cgroup_v2::cgroup_id_for_pid(pid, &source.runtime_id)?;
        ensure_current_runtime_process(&source)?;
        let namespace = namespaces.entry(netns).or_insert_with(|| NamespaceSources {
            sources: BTreeMap::new(),
        });
        namespace.sources.insert(source, cgroup_id);
    }

    for (netns, sources) in namespaces {
        check_deadline(deadline, "reading runtime namespaces")?;
        if netns == self_netns {
            continue;
        }

        let (reader, _) = sources
            .sources
            .first_key_value()
            .expect("a namespace source always has one process");
        let pid = reader.process.pid();
        let mut namespace_ports = BTreeSet::new();
        for (table, family) in [("tcp", libc::AF_INET), ("tcp6", libc::AF_INET6)] {
            let path = PathBuf::from(format!("/proc/{pid}/net/{table}"));
            let expected_identity = (table == "tcp").then_some(netns);
            for port in read_network_table(&path, expected_identity, deadline)? {
                namespace_ports.insert((family as u16, port));
            }
        }

        for (source, before_cgroup_id) in &sources.sources {
            check_deadline(deadline, "revalidating runtime namespaces")?;
            ensure_current_runtime_process(source)?;
            let pid = source.process.pid();
            let table_path = PathBuf::from(format!("/proc/{pid}/net/tcp"));
            if network_table_identity(&table_path)? != netns {
                return Err(ListenerSnapshotError::NetworkNamespaceChanged {
                    container: source.runtime_id.clone(),
                    pid,
                });
            }
            let after_cgroup_id = cgroup_v2::cgroup_id_for_pid(pid, &source.runtime_id)?;
            if after_cgroup_id != *before_cgroup_id {
                return Err(ListenerSnapshotError::CgroupChanged {
                    container: source.runtime_id.clone(),
                    pid,
                    before: *before_cgroup_id,
                    after: after_cgroup_id,
                });
            }
            ensure_current_runtime_process(source)?;
        }

        // `/proc/<pid>/net/tcp*` is network-namespace scoped. It proves the
        // listener exists, but does not expose the listener socket's cgroup or
        // the cgroup that will consume accepted traffic. Preserve every known
        // runtime cgroup as a typed candidate; target resolution must later
        // intersect it with explicit service identity.
        for (_, port) in namespace_ports {
            for cgroup_id in sources.sources.values().copied() {
                check_deadline(deadline, "expanding runtime namespace evidence")?;
                insert_unique_evidence(
                    &mut foreign_candidates,
                    associations.len(),
                    (port, cgroup_id),
                    evidence_limit,
                )?;
            }
        }
    }

    ListenerSnapshot::new(root_cgroup_id, associations, foreign_candidates)
        .map_err(ListenerSnapshotError::InvalidSnapshot)
}

fn insert_unique_evidence<T: Eq + Hash>(
    evidence: &mut HashSet<T>,
    other_evidence_count: usize,
    value: T,
    limit: usize,
) -> Result<(), ListenerSnapshotError> {
    if evidence.contains(&value) {
        return Ok(());
    }
    if other_evidence_count.saturating_add(evidence.len()) >= limit {
        return Err(ListenerSnapshotError::Capacity(limit));
    }
    evidence.insert(value);
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_deadline(deadline: Instant, operation: &'static str) -> Result<(), ListenerSnapshotError> {
    if Instant::now() >= deadline {
        Err(ListenerSnapshotError::Deadline(operation))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn read_network_table(
    path: &Path,
    expected_identity: Option<NetworkTableIdentity>,
    deadline: Instant,
) -> Result<Vec<u16>, ListenerSnapshotError> {
    check_deadline(deadline, "opening a runtime network table")?;
    let file = std::fs::File::open(path).map_err(|source| ListenerSnapshotError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    if expected_identity.is_some_and(|expected| {
        file.metadata()
            .ok()
            .and_then(|metadata| network_table_identity_from_metadata(&metadata))
            != Some(expected)
    }) {
        return Err(ListenerSnapshotError::NetworkTableChanged(
            path.to_path_buf(),
        ));
    }
    let mut reader = BufReader::new(file.take((MAX_PROC_NETWORK_TABLE_BYTES + 1) as u64));
    parse_proc_net_tcp_reader(
        &mut reader,
        &path.display().to_string(),
        Some(deadline),
        MAX_PROC_NETWORK_TABLE_ROWS,
        MAX_PROC_NETWORK_TABLE_BYTES,
    )
}

fn runtime_sources(containers: &[Container]) -> Result<Vec<RuntimeSource>, ListenerSnapshotError> {
    let mut by_runtime_id: BTreeMap<String, BTreeSet<RuntimeProcessIdentity>> = BTreeMap::new();

    for container in containers
        .iter()
        .filter(|container| container.state == "running")
    {
        let raw_id = if container.container_id.is_empty() {
            container.id.as_str()
        } else {
            container.container_id.as_str()
        };
        let runtime_id = normalize_runtime_id(raw_id);
        if runtime_id.is_empty() {
            return Err(ListenerSnapshotError::MissingRuntimeIdentity(
                container.name.clone(),
            ));
        }

        let processes = by_runtime_id.entry(runtime_id.to_string()).or_default();
        if let Some(process) = container.runtime_process {
            processes.insert(process);
        }
    }

    by_runtime_id
        .into_iter()
        .map(|(runtime_id, processes)| match processes.len() {
            0 => Err(ListenerSnapshotError::MissingInitPid(runtime_id)),
            1 => Ok(RuntimeSource {
                runtime_id,
                process: *processes
                    .first()
                    .expect("one process identity was required above"),
            }),
            _ => Err(ListenerSnapshotError::ConflictingRuntimeProcesses {
                container: runtime_id,
                processes: processes
                    .into_iter()
                    .map(|process| (process.pid, process.start_time_ticks))
                    .collect(),
            }),
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn ensure_current_runtime_process(source: &RuntimeSource) -> Result<(), ListenerSnapshotError> {
    if source.process.is_current() {
        Ok(())
    } else {
        Err(ListenerSnapshotError::StaleRuntimeProcess {
            container: source.runtime_id.clone(),
            pid: source.process.pid(),
        })
    }
}

fn normalize_runtime_id(id: &str) -> &str {
    id.split_once("://")
        .filter(|(scheme, _)| !scheme.is_empty())
        .map_or(id, |(_, id)| id)
}

#[cfg(target_os = "linux")]
fn network_table_identity(path: &Path) -> Result<NetworkTableIdentity, ListenerSnapshotError> {
    let metadata = std::fs::metadata(path).map_err(|source| ListenerSnapshotError::Io {
        operation: "stat",
        path: path.to_path_buf(),
        source,
    })?;
    let Some(identity) = network_table_identity_from_metadata(&metadata) else {
        return Err(ListenerSnapshotError::Io {
            operation: "stat",
            path: path.to_path_buf(),
            source: std::io::Error::other("network table identity is zero"),
        });
    };
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn network_table_identity_from_metadata(
    metadata: &std::fs::Metadata,
) -> Option<NetworkTableIdentity> {
    use std::os::unix::fs::MetadataExt;

    let identity = NetworkTableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    (identity.device != 0 && identity.inode != 0).then_some(identity)
}

/// Strict parser for the kernel-generated `/proc/<pid>/net/tcp{,6}` format.
/// A malformed row makes the snapshot incomplete, so unlike best-effort census
/// parsing this returns an error rather than silently dropping it.
#[cfg(test)]
fn parse_proc_net_tcp(table: &str, source_name: &str) -> Result<Vec<u16>, ListenerSnapshotError> {
    let mut reader = Cursor::new(table.as_bytes());
    parse_proc_net_tcp_reader(&mut reader, source_name, None, usize::MAX, usize::MAX)
}

fn parse_proc_net_tcp_reader<R: BufRead>(
    reader: &mut R,
    source_name: &str,
    deadline: Option<Instant>,
    row_limit: usize,
    byte_limit: usize,
) -> Result<Vec<u16>, ListenerSnapshotError> {
    let mut line = String::new();
    let mut bytes_read = read_proc_line(reader, &mut line, source_name, 1)?;
    if bytes_read == 0 {
        return Err(invalid_proc_row(source_name, 1, "missing header"));
    }
    ensure_proc_table_bytes(source_name, 1, bytes_read, byte_limit)?;
    let header = line.trim_end_matches(['\r', '\n']);
    if !header.contains("local_address") || !header.contains("st") || !header.contains("inode") {
        return Err(invalid_proc_row(source_name, 1, "unexpected header"));
    }

    let mut ports = Vec::new();
    let mut row_count = 0usize;
    loop {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ListenerSnapshotError::Deadline(
                "streaming a runtime network table",
            ));
        }
        line.clear();
        let line_number = row_count.saturating_add(2);
        let line_bytes = read_proc_line(reader, &mut line, source_name, line_number)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ListenerSnapshotError::Deadline(
                "streaming a runtime network table",
            ));
        }
        if line_bytes == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(line_bytes);
        ensure_proc_table_bytes(source_name, line_number, bytes_read, byte_limit)?;
        if row_count >= row_limit {
            return Err(invalid_proc_row(
                source_name,
                line_number,
                format!("table exceeds {row_limit} rows"),
            ));
        }
        row_count += 1;
        if let Some(port) = parse_proc_net_tcp_row(&line, source_name, line_number)? {
            ports.push(port);
        }
    }
    Ok(ports)
}

fn read_proc_line<R: BufRead>(
    reader: &mut R,
    line: &mut String,
    source_name: &str,
    line_number: usize,
) -> Result<usize, ListenerSnapshotError> {
    reader.read_line(line).map_err(|error| {
        invalid_proc_row(source_name, line_number, format!("read failed: {error}"))
    })
}

fn ensure_proc_table_bytes(
    source_name: &str,
    line_number: usize,
    bytes_read: usize,
    byte_limit: usize,
) -> Result<(), ListenerSnapshotError> {
    if bytes_read > byte_limit {
        return Err(invalid_proc_row(
            source_name,
            line_number,
            format!("table exceeds {byte_limit} bytes"),
        ));
    }
    Ok(())
}

fn parse_proc_net_tcp_row(
    line: &str,
    source_name: &str,
    line_number: usize,
) -> Result<Option<u16>, ListenerSnapshotError> {
    let columns: Vec<_> = line.split_whitespace().collect();
    if columns.len() < 10 {
        return Err(invalid_proc_row(
            source_name,
            line_number,
            "expected at least 10 columns",
        ));
    }
    if columns[3] != "0A" {
        return Ok(None);
    }
    let port_hex = columns[1]
        .rsplit_once(':')
        .map(|(_, port)| port)
        .ok_or_else(|| invalid_proc_row(source_name, line_number, "invalid local address"))?;
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|_| invalid_proc_row(source_name, line_number, "invalid local port"))?;
    if port == 0 {
        return Err(invalid_proc_row(
            source_name,
            line_number,
            "listener port is zero",
        ));
    }
    columns[9]
        .parse::<u64>()
        .map_err(|_| invalid_proc_row(source_name, line_number, "invalid socket inode"))?;
    Ok(Some(port))
}

fn invalid_proc_row(
    source_name: &str,
    line: usize,
    reason: impl Into<String>,
) -> ListenerSnapshotError {
    ListenerSnapshotError::InvalidProcTable {
        source_name: source_name.to_string(),
        line,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn process(pid: u32, start_time_ticks: u64) -> RuntimeProcessIdentity {
        RuntimeProcessIdentity {
            pid,
            start_time_ticks,
        }
    }

    fn container(id: &str, runtime_process: Option<RuntimeProcessIdentity>) -> Container {
        Container {
            id: id.to_string(),
            name: id.to_string(),
            service_name: String::new(),
            service_name_explicit: false,
            image: String::new(),
            state: "running".to_string(),
            labels: HashMap::new(),
            env: Vec::new(),
            runtime: "containerd".to_string(),
            log_path: String::new(),
            log_format: String::new(),
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: id.to_string(),
            container_name: String::new(),
            runtime_process,
        }
    }

    #[test]
    fn runtime_aliases_merge_when_one_has_the_pid() {
        let mut kubernetes = container("containerd://abc", None);
        kubernetes.runtime = "kubernetes".to_string();
        let cri = container("abc", Some(process(42, 100)));

        assert_eq!(
            runtime_sources(&[kubernetes, cri]).unwrap(),
            vec![RuntimeSource {
                runtime_id: "abc".to_string(),
                process: process(42, 100),
            }]
        );
    }

    #[test]
    fn incomplete_or_conflicting_runtime_identity_fails_closed() {
        assert!(matches!(
            runtime_sources(&[container("abc", None)]),
            Err(ListenerSnapshotError::MissingInitPid(_))
        ));
        assert!(matches!(
            runtime_sources(&[
                container("abc", Some(process(42, 100))),
                container("abc", Some(process(43, 200)))
            ]),
            Err(ListenerSnapshotError::ConflictingRuntimeProcesses { .. })
        ));
    }

    #[test]
    fn stopped_containers_do_not_require_a_runtime_process() {
        let mut stopped = container("abc", None);
        stopped.state = "exited".to_string();
        assert!(runtime_sources(&[stopped]).unwrap().is_empty());
    }

    #[test]
    fn proc_tcp_parser_returns_only_listeners() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 424242\n   1: 0100007F:2382 0100007F:C350 01 00000000:00000000 00:00000000 00000000 0 0 424243\n";
        assert_eq!(parse_proc_net_tcp(table, "fixture").unwrap(), vec![8080]);
    }

    #[test]
    fn proc_tcp_parser_rejects_partial_rows_and_zero_ports() {
        let header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        assert!(parse_proc_net_tcp(&format!("{header}broken\n"), "fixture").is_err());
        let zero = format!("{header}0: 0100007F:0000 00000000:0000 0A 0:0 00:0 0 0 0 42\n");
        assert!(parse_proc_net_tcp(&zero, "fixture").is_err());
    }

    #[test]
    fn proc_tcp_stream_enforces_row_byte_and_deadline_bounds() {
        let header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        let row = "0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 42\n";
        let table = format!("{header}{row}{row}");

        let mut reader = Cursor::new(table.as_bytes());
        assert!(
            parse_proc_net_tcp_reader(&mut reader, "fixture", None, 1, usize::MAX)
                .unwrap_err()
                .to_string()
                .contains("exceeds 1 rows")
        );

        let mut reader = Cursor::new(table.as_bytes());
        assert!(
            parse_proc_net_tcp_reader(&mut reader, "fixture", None, usize::MAX, header.len() - 1)
                .unwrap_err()
                .to_string()
                .contains("bytes")
        );

        let mut reader = Cursor::new(table.as_bytes());
        assert!(matches!(
            parse_proc_net_tcp_reader(
                &mut reader,
                "fixture",
                Some(Instant::now()),
                usize::MAX,
                usize::MAX,
            ),
            Err(ListenerSnapshotError::Deadline(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn expired_snapshot_deadline_fails_before_work() {
        assert!(matches!(
            check_deadline(Instant::now(), "testing"),
            Err(ListenerSnapshotError::Deadline("testing"))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an initial cgroup-v2 namespace and INET_DIAG_CGROUP_ID"]
    fn live_snapshot_contains_a_current_namespace_listener() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let snapshot = collect(
            &[],
            Instant::now() + std::time::Duration::from_secs(20),
            100_000,
        )
        .unwrap();
        let mut state = super::super::listener_state::ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        state.apply_snapshot(generation, snapshot, 100_000).unwrap();

        assert!(!state.cgroups_for_port(port).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run via scripts/test-ebpf-no-ptrace.sh as root on cgroup v2"]
    fn live_snapshot_reads_a_cross_uid_runtime_namespace_without_ptrace() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Child, Command, Stdio};

        const RUNTIME_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        assert_effective_capability_absent(19, "CAP_SYS_PTRACE");

        struct Cleanup {
            child: Child,
            cgroup: PathBuf,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_dir(&self.cgroup);
            }
        }

        let cgroup = PathBuf::from(format!(
            "/sys/fs/cgroup/edgepacer-snapshot-{}-{RUNTIME_ID}",
            std::process::id()
        ));
        std::fs::create_dir(&cgroup).unwrap();

        let script = r#"
import socket, time
input()
s = socket.socket()
s.bind(('0.0.0.0', 0))
s.listen()
print(s.getsockname()[1], flush=True)
time.sleep(30)
"#;
        let child = Command::new("unshare")
            .args([
                "-n",
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "python3",
                "-u",
                "-c",
                script,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut cleanup = Cleanup { child, cgroup };
        let pid = cleanup.child.id();
        std::fs::write(cleanup.cgroup.join("cgroup.procs"), pid.to_string()).unwrap();
        cleanup
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(b"\n")
            .unwrap();

        let mut line = String::new();
        BufReader::new(cleanup.child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line.trim().parse::<u16>().unwrap();
        let process = RuntimeProcessIdentity::capture(pid).unwrap();
        let expected_cgroup = cgroup_v2::cgroup_id_for_pid(pid, RUNTIME_ID).unwrap();

        let snapshot = collect(
            &[container(RUNTIME_ID, Some(process))],
            Instant::now() + std::time::Duration::from_secs(20),
            100_000,
        )
        .unwrap();
        let mut state = super::super::listener_state::ListenerState::default();
        let generation = state.begin_snapshot(1).unwrap();
        state.apply_snapshot(generation, snapshot, 100_000).unwrap();

        assert_eq!(
            state.evidence_for_port(port),
            super::super::listener_state::PortEvidence::Present {
                socket_cgroups: std::collections::HashSet::new(),
                foreign_runtime_cgroups: std::collections::HashSet::from([expected_cgroup]),
            }
        );
    }

    #[cfg(target_os = "linux")]
    fn assert_effective_capability_absent(capability: u32, name: &str) {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            .expect("/proc/self/status contains a hexadecimal CapEff field");
        assert_eq!(
            effective & (1_u64 << capability),
            0,
            "collector still has {name}; run this test through scripts/test-ebpf-no-ptrace.sh"
        );
    }

    #[test]
    fn listener_evidence_limit_is_unique_and_combined() {
        let mut associations = HashSet::new();
        let mut foreign = HashSet::new();

        insert_unique_evidence(&mut associations, foreign.len(), (8080, 10), 2).unwrap();
        insert_unique_evidence(&mut associations, foreign.len(), (8080, 10), 2).unwrap();
        insert_unique_evidence(&mut foreign, associations.len(), (9090, 20), 2).unwrap();

        assert!(matches!(
            insert_unique_evidence(&mut foreign, associations.len(), (3000, 30), 2),
            Err(ListenerSnapshotError::Capacity(2))
        ));
        assert_eq!(associations.len() + foreign.len(), 2);
    }
}
