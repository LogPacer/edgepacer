//! Shared event layout between the kernel BPF program and the userspace loader.
//!
//! `#[repr(C)]` keeps the byte layout identical on both sides so the loader can
//! cast ring-buffer bytes straight back into this struct. Keep it POD: no
//! pointers, no padding surprises, no `Drop`.

#![no_std]

pub const COMM_LEN: usize = 16;

/// Maximum distinct workload anchors accepted by one cgroup policy slot.
pub const MAX_ALLOWED_CGROUPS: u32 = 1024;
/// Maximum absolute cgroup-v2 hierarchy level inspected by the kernel policy.
pub const MAX_CGROUP_ANCESTOR_LEVEL: u32 = 32;
/// Low bits in the packed level policy, one per supported absolute level.
pub const CGROUP_LEVEL_MASK: u64 = u32::MAX as u64;
pub const CGROUP_MIN_LEVEL_SHIFT: u32 = 32;
pub const CGROUP_MAX_LEVEL_SHIFT: u32 = 40;
pub const CGROUP_LEVEL_FIELD_MASK: u64 = u8::MAX as u64;
/// The active policy map stores its double-buffer slot in the high bit and the
/// policy generation in the remaining bits, so one array update publishes both
/// values atomically to BPF readers.
pub const CGROUP_SELECTOR_SLOT_SHIFT: u32 = 63;
pub const CGROUP_SELECTOR_GENERATION_MASK: u64 = u64::MAX >> 1;

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

/// One successful TCP listener transition. This host-wide event is a change
/// signal, not direct authorization evidence: it has no network-namespace
/// identity, so userspace invalidates its authoritative snapshot and rebuilds
/// ownership before changing the cgroup allow-set.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenerEvent {
    pub cgroup_id: u64,
    /// `bpf_ktime_get_ns()` at successful `listen(2)` completion. Userspace
    /// compares it with the snapshot cut to reject a snapshot crossed by an
    /// unclassified listener change.
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
    /// The configured workload cgroup anchor that authorized capture. This is
    /// zero while the additive PID fallback is what authorized the event.
    pub scope_cgroup_id: u64,
    /// Atomically selected cgroup or PID authorization-policy generation. Zero
    /// is invalid and fails closed in userspace.
    pub policy_generation: u64,
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
    /// The workload anchor that authorized capture — see
    /// `LogChunk::scope_cgroup_id`.
    pub scope_cgroup_id: u64,
    /// The authorization-policy generation — see `LogChunk::policy_generation`.
    pub policy_generation: u64,
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
    /// The workload anchor that authorized capture — see
    /// `LogChunk::scope_cgroup_id`.
    pub scope_cgroup_id: u64,
    /// The authorization-policy generation — see `LogChunk::policy_generation`.
    pub policy_generation: u64,
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
    /// The workload anchor that authorized capture — see
    /// `LogChunk::scope_cgroup_id`.
    pub scope_cgroup_id: u64,
    /// The authorization-policy generation — see `LogChunk::policy_generation`.
    pub policy_generation: u64,
    pub ssl: u64,
    pub pid: u32,
    pub len: u32,
    pub direction: u8,
    pub data: [u8; L7_CHUNK_LEN],
}
