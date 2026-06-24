//! Resolve a captured TCP connection's protocol-relevant peer port from `/proc`,
//! to disambiguate the binary L7 parsers (Postgres/MySQL/Mongo/Kafka detect only
//! weakly from bytes). A `(pid, fd)` maps via `/proc/<pid>/fd/<fd>` (the socket
//! inode) and `/proc/<pid>/net/tcp[6]` to its local + remote ports; a well-known
//! port on either end names the protocol, and which end carries it tells client
//! vs server (so the reassembler knows which direction is the request).
//!
//! Pure parsing + classification are unit-tested on every platform; the `/proc`
//! read is Linux + `ebpf` only.

/// A resolved protocol hint for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortHint {
    /// The wire protocol's module key (matches `l7/<key>.rs`).
    pub protocol: &'static str,
    /// True if the monitored process connected OUT to the protocol port (it is the
    /// client): its *outbound* bytes are requests, so the reassembler flips which
    /// direction it parses as the request.
    pub client: bool,
}

/// A resolved connection: the port-derived protocol hint (for detection) and the
/// peer endpoint `"ip:port"` — the service-map edge's other node.
pub struct ResolvedConn {
    pub hint: Option<PortHint>,
    pub peer: String,
}

/// Well-known TCP port → wire protocol. Only ports with an unambiguous default
/// service; HTTP ports (80/8080/…) are intentionally absent (byte detection is
/// reliable for HTTP and the port is not).
fn protocol_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        5432 => "postgres",
        3306 => "mysql",
        27017 => "mongodb",
        9092 => "kafka",
        9042 => "cassandra",
        5672 => "amqp",
        6379 => "redis",
        11211 => "memcached",
        1883 => "mqtt", // 8883 is MQTT-over-TLS (the uprobe decrypts it)
        1433 => "tds",  // SQL Server
        6650 => "pulsar",
        9000 => "clickhouse", // native TCP (port-hint-only — undocumented bytes)
        25 | 587 => "smtp",
        _ => return None,
    })
}

/// Classify a connection from its `(local, remote)` ports. A known *remote* port
/// means the process is a client of that service (flip direction); a known
/// *local* port means it is the server (normal direction). Remote wins ties —
/// being a client of a DB/cache is the common APM case.
pub fn hint_from_ports(local: u16, remote: u16) -> Option<PortHint> {
    if let Some(protocol) = protocol_for_port(remote) {
        return Some(PortHint {
            protocol,
            client: true,
        });
    }
    if let Some(protocol) = protocol_for_port(local) {
        return Some(PortHint {
            protocol,
            client: false,
        });
    }
    None
}

/// Parse a `/proc/net/tcp[6]` hex address: IPv4 = 8 hex of a little-endian u32;
/// IPv6 = 32 hex of four little-endian u32 words.
fn parse_hex_ip(hex: &str) -> Option<String> {
    match hex.len() {
        8 => {
            let b = u32::from_str_radix(hex, 16).ok()?.to_le_bytes();
            Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, word) in hex.as_bytes().chunks(8).enumerate() {
                let w = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let groups: Vec<String> = bytes
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            Some(groups.join(":"))
        }
        _ => None,
    }
}

/// Parse `(local_port, remote_ip, remote_port)` of the row with `inode` from a
/// `/proc/net/tcp(6)` table. Columns: `sl local_address rem_address st … inode`;
/// addresses are `HEXIP:HEXPORT`, the inode is column 9.
fn endpoints_for_inode(table: &str, inode: &str) -> Option<(u16, String, u16)> {
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 || cols[9] != inode {
            continue;
        }
        let local_port = u16::from_str_radix(cols[1].split(':').nth(1)?, 16).ok()?;
        let (rip, rport) = cols[2].split_once(':')?;
        let remote_ip = parse_hex_ip(rip)?;
        let remote_port = u16::from_str_radix(rport, 16).ok()?;
        return Some((local_port, remote_ip, remote_port));
    }
    None
}

/// Resolve a live `(pid, fd)` socket to its protocol hint + peer endpoint, or
/// `None` if it isn't a socket or can't be read. Best-effort.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub fn resolve(pid: u32, fd: u32) -> Option<ResolvedConn> {
    let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    // "socket:[12345]"
    let inode = link
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .to_string();
    for table in ["tcp", "tcp6"] {
        let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue;
        };
        if let Some((local, remote_ip, remote)) = endpoints_for_inode(&content, &inode) {
            return Some(ResolvedConn {
                hint: hint_from_ports(local, remote),
                peer: format!("{remote_ip}:{remote}"),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1538 0100007F:E4D2 01 00000000:00000000 00:00000000 00000000  1000        0 98765 1
   1: 0100007F:A1B2 0100007F:0050 06 00000000:00000000 00:00000000 00000000     0        0 11223 1";

    #[test]
    fn parses_endpoints_for_a_matching_inode() {
        // local 0x1538=5432 (postgres); remote 127.0.0.1 (0100007F LE) : 0xE4D2.
        assert_eq!(
            endpoints_for_inode(SAMPLE, "98765"),
            Some((0x1538, "127.0.0.1".to_string(), 0xE4D2))
        );
    }

    #[test]
    fn no_match_for_unknown_inode() {
        assert_eq!(endpoints_for_inode(SAMPLE, "00000"), None);
    }

    #[test]
    fn parses_hex_ipv4_little_endian() {
        // 0100007F is 127.0.0.1 (the u32's little-endian bytes are 7F 00 00 01).
        assert_eq!(parse_hex_ip("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(parse_hex_ip("0F00A8C0").as_deref(), Some("192.168.0.15"));
        assert_eq!(parse_hex_ip("zz"), None);
    }

    #[test]
    fn remote_known_port_is_a_client_hint() {
        // remote 5432 -> the process is a postgres client (flip direction).
        let h = hint_from_ports(54321, 5432).unwrap();
        assert_eq!(h.protocol, "postgres");
        assert!(h.client);
    }

    #[test]
    fn local_known_port_is_a_server_hint() {
        let h = hint_from_ports(3306, 44556).unwrap();
        assert_eq!(h.protocol, "mysql");
        assert!(!h.client);
    }

    #[test]
    fn no_known_port_yields_no_hint() {
        assert_eq!(hint_from_ports(44556, 54321), None);
    }
}
