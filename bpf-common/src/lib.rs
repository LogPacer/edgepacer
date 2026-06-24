//! Shared event layout between the kernel BPF program and the userspace loader.
//!
//! `#[repr(C)]` keeps the byte layout identical on both sides so the loader can
//! cast ring-buffer bytes straight back into this struct. Keep it POD: no
//! pointers, no padding surprises, no `Drop`.

#![no_std]

pub const COMM_LEN: usize = 16;

/// One `sched_process_exec` observation: the post-exec PID and command name.
///
/// Mirrors what ADR-002 Level 1 ("Observe") calls process lifecycle — the
/// minimal signal that proves the kernel→userspace data path end to end.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub comm: [u8; COMM_LEN],
}

/// Max captured bytes per write(2) — small enough for a BPF stack-free copy
/// through the ring buffer, large enough to carry a typical log line prefix.
pub const CHUNK_LEN: usize = 128;

/// A captured `write(2)` payload (ADR-002 Level 1 log capture). `len` is the
/// real write size (may exceed CHUNK_LEN); `data[..min(len, CHUNK_LEN)]` is the
/// captured prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogChunk {
    pub pid: u32,
    pub fd: u32,
    pub len: u32,
    pub data: [u8; CHUNK_LEN],
}

/// An outbound IPv4 connect(2) — the service-dependency / network-flow signal
/// (ADR-002 Level 2). `daddr` is the destination IPv4 in wire (network) byte
/// order; `dport` is host order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub daddr: [u8; 4],
    pub dport: u16,
    pub family: u16,
}

/// Max captured socket payload per L7 (APM) event. 1 KiB holds a typical HTTP
/// head (request line + headers); a longer head is truncated, so the userspace
/// parser sees a fragment, waits for more, and eventually drops the connection.
pub const L7_CHUNK_LEN: usize = 1024;

/// `L7Chunk.direction`, from the monitored server's view.
pub const L7_DIR_INBOUND: u8 = 0; // read/recv — request bytes
pub const L7_DIR_OUTBOUND: u8 = 1; // write/send — response bytes

/// A captured socket payload for L7 protocol parsing (the zero-code APM path,
/// ADR-002 Level 3). `len` is the real I/O size (may exceed L7_CHUNK_LEN);
/// `data[..min(len, L7_CHUNK_LEN)]` is the captured prefix. `direction` tags
/// request vs response bytes so userspace can reassemble each side of a connection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct L7Chunk {
    pub pid: u32,
    pub fd: u32,
    pub len: u32,
    pub direction: u8,
    pub data: [u8; L7_CHUNK_LEN],
}

/// A captured TLS plaintext payload, tapped at the OpenSSL `SSL_read`/`SSL_write`
/// boundary (uprobes) so the L7 parsers see plaintext on encrypted connections.
/// Keyed by the `SSL*` pointer (a stable per-connection id) — not an fd — so we
/// needn't walk the version-specific SSL struct to find the socket. `direction`
/// reuses the L7 constants (Inbound = SSL_read plaintext, Outbound = SSL_write).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsChunk {
    pub ssl: u64,
    pub pid: u32,
    pub len: u32,
    pub direction: u8,
    pub data: [u8; L7_CHUNK_LEN],
}
