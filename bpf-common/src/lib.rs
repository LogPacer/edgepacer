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

/// One successful TCP listener transition — the event-driven port→cgroup
/// discovery signal. Pairing the listening port with the task's cgroup id lets
/// userspace resolve "watch port P" → the owning cgroup(s) with no
/// `/proc/<pid>/fd` readlink (and so no `CAP_SYS_PTRACE`). cgroup id is the
/// container dimension, so two containers on the same port stay distinct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenerEvent {
    pub cgroup_id: u64,
    /// `bpf_ktime_get_ns()` at successful `listen(2)` completion. Userspace
    /// uses the monotonic timestamp to replay live deltas across a snapshot
    /// cut without resurrecting listeners observed before that cut.
    pub observed_at_ns: u64,
    /// Per-CPU publication sequence. Userspace advances one contiguous
    /// watermark per CPU so a snapshot fence cannot substitute another CPU's
    /// event for one that has not reached the ring yet.
    pub sequence: u64,
    pub tgid: u32,
    pub cpu_id: u32,
    pub port: u16,
    pub family: u16,
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
    /// The capturing task's v2 cgroup id (`bpf_get_current_cgroup_id`) — the
    /// tamper-proof container/service key, joined to identity in userspace.
    pub cgroup_id: u64,
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
    /// The connecting task's v2 cgroup id — see `LogChunk::cgroup_id`.
    pub cgroup_id: u64,
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
    /// The capturing task's v2 cgroup id — see `LogChunk::cgroup_id`.
    pub cgroup_id: u64,
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
    /// The capturing task's v2 cgroup id — see `LogChunk::cgroup_id`.
    pub cgroup_id: u64,
    pub ssl: u64,
    pub pid: u32,
    pub len: u32,
    pub direction: u8,
    pub data: [u8; L7_CHUNK_LEN],
}
