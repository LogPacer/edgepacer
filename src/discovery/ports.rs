//! Listening port discovery — enumerates network sockets in LISTEN state.
//!
//! Linux: native procfs-based enumeration (tcp/tcp6/udp/udp6 + inode→PID mapping).
//! macOS: shells out to `lsof -i -P -n` and parses output.
//! Both paths produce the same `ListeningPort` struct matching legacy EdgePacer's JSON shape.

use serde::Serialize;
use tracing::debug;

/// A discovered listening network port.
#[derive(Debug, Clone, Serialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    pub process: String,
    pub pid: u32,
}

/// Discover listening ports on the host.
pub async fn discover_ports() -> Result<Vec<ListeningPort>, String> {
    tokio::task::spawn_blocking(discover_ports_sync)
        .await
        .map_err(|e| format!("port discovery task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Linux native: procfs-based port enumeration
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn discover_ports_native() -> Result<Vec<ListeningPort>, String> {
    use procfs::net::{TcpState, tcp, tcp6, udp, udp6};
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    // Step 1: Build inode → (pid, process_name) map by scanning /proc/[pid]/fd/
    let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read process name from /proc/[pid]/comm
            let comm_path = format!("/proc/{pid}/comm");
            let comm = fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .to_string();

            // Scan /proc/[pid]/fd/ for socket inodes
            let fd_dir = format!("/proc/{pid}/fd");
            let fd_path = Path::new(&fd_dir);
            if let Ok(fds) = fs::read_dir(fd_path) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy().to_string();
                        // Socket links look like "socket:[12345]"
                        if let Some(inode_str) = link_str
                            .strip_prefix("socket:[")
                            .and_then(|s| s.strip_suffix(']'))
                            && let Ok(inode) = inode_str.parse::<u64>()
                        {
                            inode_map.insert(inode, (pid, comm.clone()));
                        }
                    }
                }
            }
        }
    }

    let mut ports = Vec::new();

    // Step 2: Read TCP sockets in LISTEN state
    let tcp_entries = tcp().unwrap_or_default();
    let tcp6_entries = tcp6().unwrap_or_default();

    for entry in tcp_entries.into_iter().chain(tcp6_entries) {
        if entry.state != TcpState::Listen {
            continue;
        }
        let local_port = entry.local_address.port();
        let inode = entry.inode;
        let (pid, process) = inode_map.get(&inode).cloned().unwrap_or((0, String::new()));

        ports.push(ListeningPort {
            port: local_port,
            protocol: "tcp".to_string(),
            process,
            pid,
        });
    }

    // Step 3: Read UDP bound sockets (UDP has no LISTEN state — all bound sockets count)
    let udp_entries = udp().unwrap_or_default();
    let udp6_entries = udp6().unwrap_or_default();

    for entry in udp_entries.into_iter().chain(udp6_entries) {
        let local_port = entry.local_address.port();
        if local_port == 0 {
            continue; // skip unbound
        }
        let inode = entry.inode;
        let (pid, process) = inode_map.get(&inode).cloned().unwrap_or((0, String::new()));

        ports.push(ListeningPort {
            port: local_port,
            protocol: "udp".to_string(),
            process,
            pid,
        });
    }

    // Deduplicate (same port may appear in both v4 and v6)
    ports.sort_by_key(|p| (p.port, p.protocol.clone()));
    ports.dedup_by_key(|p| (p.port, p.protocol.clone()));

    debug!(count = ports.len(), "discovered listening ports via procfs");
    Ok(ports)
}

/// Shell-out fallback: parse `lsof -i -P -n` output.
#[cfg(not(target_os = "windows"))]
fn discover_ports_shellout() -> Result<Vec<ListeningPort>, String> {
    let output = std::process::Command::new("lsof")
        .args(["-i", "-P", "-n"])
        .output()
        .map_err(|e| format!("failed to run lsof: {e}"))?;

    // lsof may exit non-zero if some files couldn't be accessed (normal without root)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ports = parse_lsof_output(&stdout);
    debug!(count = ports.len(), "discovered listening ports via lsof");
    Ok(ports)
}

/// Parse `lsof -i -P -n` output for LISTEN sockets.
///
/// Sample lines:
/// ```text
/// COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
/// sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)
/// postgres   1234   morten  5u  IPv6 0x67890      0t0  TCP [::1]:5432 (LISTEN)
/// dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53
/// ```
#[cfg(any(not(target_os = "windows"), test))]
fn parse_lsof_output(output: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();

    for line in output.lines().skip(1) {
        // Only include LISTEN for TCP, all bound for UDP
        let is_listen = line.contains("(LISTEN)");
        let is_udp = line.contains(" UDP ");

        if !is_listen && !is_udp {
            continue;
        }

        if let Some(port) = parse_lsof_line(line) {
            ports.push(port);
        }
    }

    // Deduplicate
    ports.sort_by_key(|p| (p.port, p.protocol.clone()));
    ports.dedup_by_key(|p| (p.port, p.protocol.clone()));

    ports
}

#[cfg(any(not(target_os = "windows"), test))]
fn parse_lsof_line(line: &str) -> Option<ListeningPort> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        return None;
    }

    let process = parts[0].to_string();
    let pid: u32 = parts[1].parse().ok()?;

    // NODE is the protocol (TCP/UDP), NAME contains host:port
    let protocol = parts[7].to_lowercase(); // "tcp" or "udp"
    if protocol != "tcp" && protocol != "udp" {
        return None;
    }

    let name = parts[8]; // e.g., "*:22" or "[::1]:5432" or "127.0.0.1:8080"

    // Extract port: everything after the last ':'
    let port_str = name.rsplit(':').next()?;
    let port: u16 = port_str.parse().ok()?;

    Some(ListeningPort {
        port,
        protocol,
        process,
        pid,
    })
}

#[cfg(target_os = "linux")]
fn discover_ports_sync() -> Result<Vec<ListeningPort>, String> {
    discover_ports_native().or_else(|e| {
        tracing::warn!(error = %e, "procfs port discovery failed, falling back to lsof");
        discover_ports_shellout()
    })
}

/// Windows: `netstat -ano` for listening sockets + owner PID, names from `sysinfo`.
/// (`netstat` is the sanctioned Windows shell-out — already used for TCP stats in
/// `host_metrics_windows.rs`. `lsof` does not exist on Windows.)
#[cfg(target_os = "windows")]
fn discover_ports_sync() -> Result<Vec<ListeningPort>, String> {
    use sysinfo::{Pid, ProcessesToUpdate, System};

    let output = std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|e| format!("failed to run netstat: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "netstat failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut ports = parse_netstat_ano(&String::from_utf8_lossy(&output.stdout));

    // netstat -ano gives the PID but not the process name — resolve it via sysinfo.
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    for port in &mut ports {
        if let Some(proc) = system.process(Pid::from_u32(port.pid)) {
            port.process = proc.name().to_string_lossy().into_owned();
        }
    }

    debug!(
        count = ports.len(),
        "discovered listening ports via netstat"
    );
    Ok(ports)
}

/// Parse `netstat -ano` output. Columns: `Proto  Local  Foreign  [State]  PID`
/// — TCP has a State column, UDP does not. Keep listening TCP and all bound UDP,
/// mirroring the lsof path's `(LISTEN)`/all-UDP filter.
#[cfg(any(target_os = "windows", test))]
fn parse_netstat_ano(output: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let (protocol, local_addr, pid_str) = match parts[0].to_lowercase().as_str() {
            "tcp" if parts.len() >= 5 => {
                if parts[3] != "LISTENING" {
                    continue;
                }
                ("tcp", parts[1], parts[4])
            }
            "udp" => ("udp", parts[1], parts[3]),
            _ => continue,
        };

        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        // Local address: "0.0.0.0:135", "[::]:445", "127.0.0.1:8080" — port is after the last ':'.
        let Some(port) = local_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
        else {
            continue;
        };

        ports.push(ListeningPort {
            port,
            protocol: protocol.to_string(),
            process: String::new(),
            pid,
        });
    }

    ports.sort_by_key(|p| (p.port, p.protocol.clone()));
    ports.dedup_by_key(|p| (p.port, p.protocol.clone()));
    ports
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn discover_ports_sync() -> Result<Vec<ListeningPort>, String> {
    discover_ports_shellout()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LSOF: &str = r#"COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)
sshd        843   root    4u  IPv6 0x12346      0t0  TCP [::]:22 (LISTEN)
postgres   1234   morten  5u  IPv6 0x67890      0t0  TCP [::1]:5432 (LISTEN)
node       5678   morten  18u IPv4 0xabc12      0t0  TCP 127.0.0.1:3000 (LISTEN)
dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53
chrome     9999   morten  42u IPv4 0xdeadb      0t0  TCP 192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
"#;

    #[test]
    fn parse_lsof_listen_ports() {
        let ports = parse_lsof_output(SAMPLE_LSOF);

        // Should find: SSH(22/tcp), postgres(5432/tcp), node(3000/tcp), dnsmasq(53/udp)
        // SSH appears twice (v4+v6) but dedup keeps one
        // chrome ESTABLISHED should be excluded
        assert!(ports.iter().any(|p| p.port == 22 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 5432 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 3000 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 53 && p.protocol == "udp"));

        // ESTABLISHED should not appear
        assert!(!ports.iter().any(|p| p.port == 54321));
    }

    #[test]
    fn parse_lsof_line_tcp_listen() {
        let line = "sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 22);
        assert_eq!(port.protocol, "tcp");
        assert_eq!(port.process, "sshd");
        assert_eq!(port.pid, 843);
    }

    #[test]
    fn parse_lsof_line_udp() {
        let line = "dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 53);
        assert_eq!(port.protocol, "udp");
        assert_eq!(port.process, "dnsmasq");
        assert_eq!(port.pid, 567);
    }

    #[test]
    fn parse_lsof_ipv6_brackets() {
        let line = "postgres   1234   morten  5u  IPv6 0x67890      0t0  TCP [::1]:5432 (LISTEN)";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 5432);
        assert_eq!(port.protocol, "tcp");
    }

    #[test]
    fn parse_netstat_ano_listen_and_udp() {
        let output = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    127.0.0.1:51000        127.0.0.1:443          ESTABLISHED     5000
  UDP    0.0.0.0:5353           *:*                                    777
";
        let ports = parse_netstat_ano(output);

        // Listening TCP kept (incl. IPv6 [::] form), with owner PID.
        assert!(
            ports
                .iter()
                .any(|p| p.port == 135 && p.protocol == "tcp" && p.pid == 1234)
        );
        assert!(
            ports
                .iter()
                .any(|p| p.port == 445 && p.protocol == "tcp" && p.pid == 4)
        );
        // Bound UDP kept (no state column).
        assert!(
            ports
                .iter()
                .any(|p| p.port == 5353 && p.protocol == "udp" && p.pid == 777)
        );
        // Non-listening (ESTABLISHED) TCP excluded.
        assert!(!ports.iter().any(|p| p.port == 51000));
    }

    #[tokio::test]
    async fn discover_ports_runs_without_panic() {
        // Best-effort: lsof may find ports or may not, but shouldn't error fatally.
        let result = discover_ports().await;
        // On macOS without root, lsof still works but may return fewer results.
        assert!(result.is_ok());
    }
}
