//! Authoritative TCP listener snapshots for the caller's current network
//! namespace via `NETLINK_SOCK_DIAG`.
//!
//! Linux's `inet_diag_msg_attrs_fill()` emits `INET_DIAG_CGROUP_ID` for every
//! full socket when `CONFIG_SOCK_CGROUP_DATA` is enabled. It is deliberately
//! outside the `idiag_ext` and `CAP_NET_ADMIN` checks: attribute 21 cannot fit
//! in the request's eight-bit extension mask and needs no request flag. A
//! missing or zero cgroup ID makes the whole snapshot unusable for
//! authorization, so this module fails the request instead of returning a
//! partial result.

use std::io;
use std::time::{Duration, Instant};

const NLMSG_HEADER_LEN: usize = 16;
const INET_DIAG_MSG_LEN: usize = 72;
const NLA_HEADER_LEN: usize = 4;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_CGROUP_ID: u16 = 21;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_MULTI: u16 = 0x02;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const TCP_LISTEN: u8 = 10;
const TCPF_LISTEN: u32 = 1 << TCP_LISTEN;
const NLA_TYPE_MASK: u16 = 0x3fff;
const RECEIVE_BUFFER_LEN: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const RECEIVE_TIMEOUT_SECS: libc::time_t = 5;

/// A TCP listening socket visible in the caller's current network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpListenerSocket {
    /// `AF_INET` or `AF_INET6`.
    pub family: u16,
    /// Local TCP port in host byte order.
    pub port: u16,
    pub inode: u32,
    /// Cgroup v2 ID reported by the kernel. Always nonzero.
    pub cgroup_id: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotError {
    #[error("TCP listener snapshots via NETLINK_SOCK_DIAG are unsupported on {0}")]
    Unsupported(&'static str),
    #[error("NETLINK_SOCK_DIAG I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid NETLINK_SOCK_DIAG response: {0}")]
    Protocol(String),
    #[error("NETLINK_SOCK_DIAG snapshot exceeded its {0}-row limit")]
    Capacity(usize),
    #[error("NETLINK_SOCK_DIAG snapshot exceeded its deadline")]
    Deadline,
}

/// Snapshot all IPv4 and IPv6 TCP listeners in the caller's current network
/// namespace. Either both family dumps complete successfully or no rows are
/// returned.
#[cfg(target_os = "linux")]
pub(crate) fn snapshot_tcp_listeners(
    deadline: Instant,
    row_limit: usize,
) -> Result<Vec<TcpListenerSocket>, SnapshotError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    bind_netlink_socket(socket.as_raw_fd())?;

    let mut listeners = dump_family(
        socket.as_raw_fd(),
        libc::AF_INET as u8,
        1,
        deadline,
        row_limit,
    )?;
    listeners.extend(dump_family(
        socket.as_raw_fd(),
        libc::AF_INET6 as u8,
        2,
        deadline,
        row_limit.saturating_sub(listeners.len()),
    )?);
    listeners.sort_unstable_by_key(|row| (row.family, row.port, row.inode, row.cgroup_id));
    Ok(listeners)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn snapshot_tcp_listeners(
    _deadline: Instant,
    _row_limit: usize,
) -> Result<Vec<TcpListenerSocket>, SnapshotError> {
    Err(SnapshotError::Unsupported(std::env::consts::OS))
}

#[cfg(target_os = "linux")]
fn set_receive_timeout(fd: std::os::fd::RawFd, remaining: Duration) -> Result<(), SnapshotError> {
    let timeout = remaining.min(Duration::from_secs(RECEIVE_TIMEOUT_SECS as u64));
    let seconds = timeout.as_secs() as libc::time_t;
    let mut microseconds = libc::suseconds_t::from(timeout.subsec_micros());
    if seconds == 0 && microseconds == 0 {
        microseconds = 1;
    }
    let timeout = libc::timeval {
        tv_sec: seconds,
        tv_usec: microseconds,
    };
    // SAFETY: `timeout` is a fully initialized timeval and its pointer is valid
    // for the supplied length. The kernel copies it during this call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_netlink_socket(fd: std::os::fd::RawFd) -> Result<(), SnapshotError> {
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;

    let result = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn dump_family(
    fd: std::os::fd::RawFd,
    family: u8,
    sequence: u32,
    deadline: Instant,
    row_limit: usize,
) -> Result<Vec<TcpListenerSocket>, SnapshotError> {
    ensure_before_deadline(deadline)?;
    send_dump_request(fd, family, sequence)?;

    let mut listeners = Vec::new();
    loop {
        let datagram = receive_datagram(fd, deadline)?;
        let parsed = parse_datagram(&datagram, sequence, family)?;
        if parsed.listeners.len() > row_limit.saturating_sub(listeners.len()) {
            return Err(SnapshotError::Capacity(row_limit));
        }
        listeners.extend(parsed.listeners);
        if parsed.done {
            return Ok(listeners);
        }
    }
}

#[cfg(target_os = "linux")]
fn send_dump_request(
    fd: std::os::fd::RawFd,
    family: u8,
    sequence: u32,
) -> Result<(), SnapshotError> {
    let request = dump_request(family, sequence);
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;

    let sent = loop {
        let result = unsafe {
            libc::sendto(
                fd,
                request.as_ptr().cast(),
                request.len(),
                0,
                std::ptr::from_ref(&kernel).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result >= 0 {
            break result as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    };

    if sent != request.len() {
        return Err(SnapshotError::Protocol(format!(
            "short request write: sent {sent} of {} bytes",
            request.len()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn receive_datagram(fd: std::os::fd::RawFd, deadline: Instant) -> Result<Vec<u8>, SnapshotError> {
    ensure_before_deadline(deadline)?;
    set_receive_timeout(fd, deadline.saturating_duration_since(Instant::now()))?;
    let mut buffer = vec![0u8; RECEIVE_BUFFER_LEN];
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = std::ptr::from_mut(&mut sender).cast();
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    message.msg_iov = std::ptr::from_mut(&mut iovec);
    message.msg_iovlen = 1;

    let received = loop {
        let result = unsafe { libc::recvmsg(fd, &mut message, 0) };
        if result >= 0 {
            break result as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            if Instant::now() >= deadline {
                return Err(SnapshotError::Deadline);
            }
            return Err(error.into());
        }
    };

    if received == 0 {
        return Err(SnapshotError::Protocol(
            "kernel closed the netlink socket before NLMSG_DONE".to_string(),
        ));
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(SnapshotError::Protocol(
            "truncated netlink datagram".to_string(),
        ));
    }
    if sender.nl_pid != 0 {
        return Err(SnapshotError::Protocol(format!(
            "response came from non-kernel netlink port {}",
            sender.nl_pid
        )));
    }

    buffer.truncate(received);
    Ok(buffer)
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), SnapshotError> {
    if Instant::now() >= deadline {
        Err(SnapshotError::Deadline)
    } else {
        Ok(())
    }
}

fn dump_request(family: u8, sequence: u32) -> Vec<u8> {
    // nlmsghdr (16) + inet_diag_req_v2 (56). The request contains no attrs.
    const REQUEST_LEN: usize = NLMSG_HEADER_LEN + 56;
    let mut request = vec![0u8; REQUEST_LEN];
    put_u32(&mut request, 0, REQUEST_LEN as u32);
    put_u16(&mut request, 4, SOCK_DIAG_BY_FAMILY);
    put_u16(&mut request, 6, NLM_F_REQUEST | NLM_F_DUMP);
    put_u32(&mut request, 8, sequence);
    request[NLMSG_HEADER_LEN] = family;
    request[NLMSG_HEADER_LEN + 1] = libc_ipproto_tcp();
    put_u32(&mut request, NLMSG_HEADER_LEN + 4, TCPF_LISTEN);
    request
}

const fn libc_ipproto_tcp() -> u8 {
    6
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedDatagram {
    listeners: Vec<TcpListenerSocket>,
    done: bool,
}

fn parse_datagram(
    bytes: &[u8],
    expected_sequence: u32,
    expected_family: u8,
) -> Result<ParsedDatagram, SnapshotError> {
    if bytes.is_empty() {
        return Err(SnapshotError::Protocol(
            "empty netlink datagram".to_string(),
        ));
    }

    let mut listeners = Vec::new();
    let mut offset = 0;
    let mut done = false;

    while offset < bytes.len() {
        if bytes.len() - offset < NLMSG_HEADER_LEN {
            return Err(SnapshotError::Protocol(
                "truncated netlink message header".to_string(),
            ));
        }

        let message_len = get_u32(bytes, offset)? as usize;
        if message_len < NLMSG_HEADER_LEN {
            return Err(SnapshotError::Protocol(format!(
                "invalid netlink message length {message_len}"
            )));
        }
        let message_end = offset.checked_add(message_len).ok_or_else(|| {
            SnapshotError::Protocol("netlink message length overflow".to_string())
        })?;
        if message_end > bytes.len() {
            return Err(SnapshotError::Protocol(
                "truncated netlink message payload".to_string(),
            ));
        }
        let aligned_end = offset
            .checked_add(align4(message_len)?)
            .ok_or_else(|| SnapshotError::Protocol("netlink alignment overflow".to_string()))?;
        if aligned_end > bytes.len() {
            return Err(SnapshotError::Protocol(
                "truncated netlink message padding".to_string(),
            ));
        }

        let message_type = get_u16(bytes, offset + 4)?;
        let flags = get_u16(bytes, offset + 6)?;
        let sequence = get_u32(bytes, offset + 8)?;
        if sequence != expected_sequence {
            return Err(SnapshotError::Protocol(format!(
                "response sequence {sequence} did not match request {expected_sequence}"
            )));
        }
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(SnapshotError::Protocol(
                "kernel interrupted the socket dump".to_string(),
            ));
        }

        let payload = &bytes[offset + NLMSG_HEADER_LEN..message_end];
        match message_type {
            NLMSG_NOOP => {}
            NLMSG_ERROR => parse_netlink_error(payload)?,
            NLMSG_DONE => {
                parse_done(payload)?;
                done = true;
                if aligned_end != bytes.len() {
                    return Err(SnapshotError::Protocol(
                        "netlink message followed NLMSG_DONE".to_string(),
                    ));
                }
            }
            NLMSG_OVERRUN => {
                return Err(SnapshotError::Protocol(
                    "kernel reported a netlink overrun".to_string(),
                ));
            }
            SOCK_DIAG_BY_FAMILY => {
                if flags & NLM_F_MULTI == 0 {
                    return Err(SnapshotError::Protocol(
                        "socket row was not marked as multipart".to_string(),
                    ));
                }
                listeners.push(parse_listener(payload, expected_family)?);
            }
            other => {
                return Err(SnapshotError::Protocol(format!(
                    "unexpected netlink message type {other}"
                )));
            }
        }

        offset = aligned_end;
    }

    Ok(ParsedDatagram { listeners, done })
}

fn parse_netlink_error(payload: &[u8]) -> Result<(), SnapshotError> {
    if payload.len() < 4 {
        return Err(SnapshotError::Protocol(
            "truncated NLMSG_ERROR payload".to_string(),
        ));
    }
    let error = i32::from_ne_bytes(payload[..4].try_into().expect("four-byte slice"));
    if error == 0 {
        return Ok(());
    }
    if error == i32::MIN || error > 0 {
        return Err(SnapshotError::Protocol(format!(
            "invalid NLMSG_ERROR code {error}"
        )));
    }
    Err(io::Error::from_raw_os_error(-error).into())
}

fn parse_done(payload: &[u8]) -> Result<(), SnapshotError> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() < 4 {
        return Err(SnapshotError::Protocol(
            "truncated NLMSG_DONE status".to_string(),
        ));
    }
    let status = i32::from_ne_bytes(payload[..4].try_into().expect("four-byte slice"));
    if status == 0 {
        Ok(())
    } else if status < 0 && status != i32::MIN {
        Err(io::Error::from_raw_os_error(-status).into())
    } else {
        Err(SnapshotError::Protocol(format!(
            "invalid NLMSG_DONE status {status}"
        )))
    }
}

fn parse_listener(payload: &[u8], expected_family: u8) -> Result<TcpListenerSocket, SnapshotError> {
    if payload.len() < INET_DIAG_MSG_LEN {
        return Err(SnapshotError::Protocol(
            "truncated inet_diag_msg".to_string(),
        ));
    }

    let family = payload[0];
    if family != expected_family {
        return Err(SnapshotError::Protocol(format!(
            "socket family {family} did not match request {expected_family}"
        )));
    }
    if family != af_inet() && family != af_inet6() {
        return Err(SnapshotError::Protocol(format!(
            "unexpected TCP socket family {family}"
        )));
    }
    if payload[1] != TCP_LISTEN {
        return Err(SnapshotError::Protocol(format!(
            "unexpected TCP state {} in listener dump",
            payload[1]
        )));
    }

    let port = u16::from_be_bytes([payload[4], payload[5]]);
    if port == 0 {
        return Err(SnapshotError::Protocol(
            "listener row contained port zero".to_string(),
        ));
    }
    let inode = get_u32(payload, 68)?;
    let cgroup_id = parse_cgroup_id(&payload[INET_DIAG_MSG_LEN..])?;

    Ok(TcpListenerSocket {
        family: u16::from(family),
        port,
        inode,
        cgroup_id,
    })
}

fn parse_cgroup_id(attributes: &[u8]) -> Result<u64, SnapshotError> {
    let mut cgroup_id = None;
    let mut offset = 0;

    while offset < attributes.len() {
        if attributes.len() - offset < NLA_HEADER_LEN {
            return Err(SnapshotError::Protocol(
                "truncated inet_diag attribute header".to_string(),
            ));
        }
        let attribute_len = get_u16(attributes, offset)? as usize;
        if attribute_len < NLA_HEADER_LEN {
            return Err(SnapshotError::Protocol(format!(
                "invalid inet_diag attribute length {attribute_len}"
            )));
        }
        let attribute_end = offset.checked_add(attribute_len).ok_or_else(|| {
            SnapshotError::Protocol("inet_diag attribute length overflow".to_string())
        })?;
        if attribute_end > attributes.len() {
            return Err(SnapshotError::Protocol(
                "truncated inet_diag attribute payload".to_string(),
            ));
        }
        let aligned_end = offset
            .checked_add(align4(attribute_len)?)
            .ok_or_else(|| SnapshotError::Protocol("attribute alignment overflow".to_string()))?;
        if aligned_end > attributes.len() {
            return Err(SnapshotError::Protocol(
                "truncated inet_diag attribute padding".to_string(),
            ));
        }

        let attribute_type = get_u16(attributes, offset + 2)? & NLA_TYPE_MASK;
        if attribute_type == INET_DIAG_CGROUP_ID {
            if attribute_len != NLA_HEADER_LEN + 8 {
                return Err(SnapshotError::Protocol(format!(
                    "INET_DIAG_CGROUP_ID had {} data bytes, expected 8",
                    attribute_len - NLA_HEADER_LEN
                )));
            }
            if cgroup_id.is_some() {
                return Err(SnapshotError::Protocol(
                    "duplicate INET_DIAG_CGROUP_ID attribute".to_string(),
                ));
            }
            cgroup_id = Some(u64::from_ne_bytes(
                attributes[offset + NLA_HEADER_LEN..attribute_end]
                    .try_into()
                    .expect("validated eight-byte cgroup ID"),
            ));
        }

        offset = aligned_end;
    }

    match cgroup_id {
        Some(0) => Err(SnapshotError::Protocol(
            "INET_DIAG_CGROUP_ID was zero".to_string(),
        )),
        Some(id) => Ok(id),
        None => Err(SnapshotError::Protocol(
            "listener row omitted INET_DIAG_CGROUP_ID".to_string(),
        )),
    }
}

fn align4(length: usize) -> Result<usize, SnapshotError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| SnapshotError::Protocol("alignment overflow".to_string()))
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, SnapshotError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| SnapshotError::Protocol("truncated native-endian u16".to_string()))?;
    Ok(u16::from_ne_bytes(
        value.try_into().expect("validated two-byte slice"),
    ))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, SnapshotError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| SnapshotError::Protocol("truncated native-endian u32".to_string()))?;
    Ok(u32::from_ne_bytes(
        value.try_into().expect("validated four-byte slice"),
    ))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

const fn af_inet() -> u8 {
    2
}

const fn af_inet6() -> u8 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn netlink_message(message_type: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let message_len = NLMSG_HEADER_LEN + payload.len();
        let mut message = vec![0u8; (message_len + 3) & !3];
        put_u32(&mut message, 0, message_len as u32);
        put_u16(&mut message, 4, message_type);
        put_u16(&mut message, 6, flags);
        put_u32(&mut message, 8, sequence);
        message[NLMSG_HEADER_LEN..message_len].copy_from_slice(payload);
        message
    }

    fn cgroup_attribute(cgroup_id: u64) -> Vec<u8> {
        let mut attribute = vec![0u8; 12];
        put_u16(&mut attribute, 0, 12);
        put_u16(&mut attribute, 2, INET_DIAG_CGROUP_ID);
        attribute[4..12].copy_from_slice(&cgroup_id.to_ne_bytes());
        attribute
    }

    fn listener_payload(family: u8, port: u16, inode: u32, cgroup_id: Option<u64>) -> Vec<u8> {
        let mut payload = vec![0u8; INET_DIAG_MSG_LEN];
        payload[0] = family;
        payload[1] = TCP_LISTEN;
        payload[4..6].copy_from_slice(&port.to_be_bytes());
        put_u32(&mut payload, 68, inode);
        if let Some(cgroup_id) = cgroup_id {
            payload.extend(cgroup_attribute(cgroup_id));
        }
        payload
    }

    #[test]
    fn builds_a_tcp_listen_dump_request() {
        let request = dump_request(af_inet(), 42);
        assert_eq!(request.len(), 72);
        assert_eq!(get_u32(&request, 0).unwrap(), 72);
        assert_eq!(get_u16(&request, 4).unwrap(), SOCK_DIAG_BY_FAMILY);
        assert_eq!(get_u16(&request, 6).unwrap(), NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(get_u32(&request, 8).unwrap(), 42);
        assert_eq!(request[16], af_inet());
        assert_eq!(request[17], 6);
        // CGROUP_ID is a response-only attribute emitted independently of the
        // eight-bit extension mask, so no impossible bit for attr 21 is set.
        assert_eq!(request[18], 0);
        assert_eq!(get_u32(&request, 20).unwrap(), TCPF_LISTEN);
    }

    #[test]
    fn parses_ipv4_listener_fields_and_host_order_port() {
        let payload = listener_payload(af_inet(), 4318, 123_456, Some(987_654));
        let datagram = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 7, &payload);
        let parsed = parse_datagram(&datagram, 7, af_inet()).unwrap();

        assert_eq!(
            parsed.listeners,
            vec![TcpListenerSocket {
                family: 2,
                port: 4318,
                inode: 123_456,
                cgroup_id: 987_654,
            }]
        );
        assert!(!parsed.done);
    }

    #[test]
    fn parses_ipv6_listener_and_done_messages() {
        let payload = listener_payload(af_inet6(), 443, 55, Some(66));
        let mut datagram = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 9, &payload);
        datagram.extend(netlink_message(
            NLMSG_DONE,
            NLM_F_MULTI,
            9,
            &0i32.to_ne_bytes(),
        ));

        let parsed = parse_datagram(&datagram, 9, af_inet6()).unwrap();
        assert_eq!(parsed.listeners[0].family, 10);
        assert_eq!(parsed.listeners[0].port, 443);
        assert!(parsed.done);
    }

    #[test]
    fn rejects_missing_or_zero_cgroup_ids() {
        for cgroup_id in [None, Some(0)] {
            let payload = listener_payload(af_inet(), 80, 1, cgroup_id);
            let datagram = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 1, &payload);
            let error = parse_datagram(&datagram, 1, af_inet()).unwrap_err();
            assert!(error.to_string().contains("CGROUP_ID"));
        }
    }

    #[test]
    fn rejects_mismatched_sequence_and_interrupted_dump() {
        let payload = listener_payload(af_inet(), 80, 1, Some(2));
        let wrong_sequence = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 2, &payload);
        assert!(
            parse_datagram(&wrong_sequence, 1, af_inet())
                .unwrap_err()
                .to_string()
                .contains("sequence")
        );

        let interrupted = netlink_message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI | NLM_F_DUMP_INTR,
            1,
            &payload,
        );
        assert!(
            parse_datagram(&interrupted, 1, af_inet())
                .unwrap_err()
                .to_string()
                .contains("interrupted")
        );
    }

    #[test]
    fn rejects_truncated_messages_and_attributes() {
        assert!(parse_datagram(&[0; 15], 1, af_inet()).is_err());

        let mut truncated_message = netlink_message(NLMSG_DONE, NLM_F_MULTI, 1, &[]);
        put_u32(&mut truncated_message, 0, 100);
        assert!(parse_datagram(&truncated_message, 1, af_inet()).is_err());

        let mut payload = listener_payload(af_inet(), 80, 1, None);
        payload.extend([12, 0, INET_DIAG_CGROUP_ID as u8, 0, 1, 2, 3]);
        let truncated_attribute = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 1, &payload);
        assert!(parse_datagram(&truncated_attribute, 1, af_inet()).is_err());
    }

    #[test]
    fn rejects_kernel_errors_and_overruns() {
        let error = netlink_message(NLMSG_ERROR, 0, 3, &(-libc_einval()).to_ne_bytes());
        assert!(matches!(
            parse_datagram(&error, 3, af_inet()).unwrap_err(),
            SnapshotError::Io(_)
        ));

        let overrun = netlink_message(NLMSG_OVERRUN, 0, 3, &[]);
        assert!(
            parse_datagram(&overrun, 3, af_inet())
                .unwrap_err()
                .to_string()
                .contains("overrun")
        );
    }

    const fn libc_einval() -> i32 {
        22
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn live_snapshot_is_explicitly_unsupported_off_linux() {
        assert!(matches!(
            snapshot_tcp_listeners(Instant::now() + Duration::from_secs(20), 100_000).unwrap_err(),
            SnapshotError::Unsupported(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a Linux kernel with INET_DIAG_CGROUP_ID"]
    fn live_snapshot_contains_a_local_listener() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let snapshot =
            snapshot_tcp_listeners(Instant::now() + Duration::from_secs(20), 100_000).unwrap();
        assert!(snapshot.iter().any(|row| {
            row.family == libc::AF_INET as u16 && row.port == port && row.cgroup_id != 0
        }));
    }
}
