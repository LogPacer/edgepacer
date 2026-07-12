//! Kernel-side BPF program: attach to the `sched_process_exec` tracepoint and
//! push one `ExecEvent` (pid + comm) per exec into a ring buffer.
//!
//! This is the minimal real program that proves the data path: kernel event →
//! BPF map → userspace. ADR-002 Level 1 "Observe" (process lifecycle).

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_TCP_LISTEN,
    helpers::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use edgepacer_ebpf_common::{
    CGROUP_LEVEL_FIELD_MASK, CGROUP_LEVEL_MASK, CGROUP_MAX_LEVEL_SHIFT, CGROUP_MIN_LEVEL_SHIFT,
    CGROUP_SELECTOR_GENERATION_MASK, CGROUP_SELECTOR_SLOT_SHIFT, CHUNK_LEN, ConnectEvent,
    ExecEvent, L7_CHUNK_LEN, L7_DIR_INBOUND, L7_DIR_OUTBOUND, L7Chunk, ListenerEvent, LogChunk,
    MAX_ALLOWED_CGROUPS, MAX_CGROUP_ANCESTOR_LEVEL, TlsChunk,
};

// 256 KiB ring buffer (power of two, page-aligned) shared with userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Temporary additive fallback for workloads still resolved by PID.
#[map]
static TARGET_PIDS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

// Workload cgroup policy is populated in the inactive slot and atomically
// activated only after both the anchor set and its level mask are complete.
// Each value repeats the slot generation so a partially rewritten slot cannot
// satisfy a lookup from another policy instance.
#[map]
static ALLOWED_CGROUPS_A: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ALLOWED_CGROUPS, 0);

#[map]
static ALLOWED_CGROUPS_B: HashMap<u64, u64> = HashMap::with_max_entries(MAX_ALLOWED_CGROUPS, 0);

// Packed level policy: bits 0..31 are the absolute-level mask, bits 32..39
// carry the minimum configured level, and bits 40..47 carry the maximum.
#[map]
static ALLOWED_CGROUP_LEVELS_A: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static ALLOWED_CGROUP_LEVELS_B: Array<u64> = Array::with_max_entries(1, 0);

// One atomic selector carries both the active slot (high bit) and policy
// generation (remaining bits). Zero selects an empty initial policy in slot A.
#[map]
static ACTIVE_CGROUP_SLOT: Array<u64> = Array::with_max_entries(1, 0);

#[derive(Clone, Copy)]
struct CaptureScope {
    cgroup_id: u64,
    scope_cgroup_id: u64,
    policy_generation: u64,
}

#[derive(Clone, Copy)]
struct CgroupLevelPolicy {
    mask: u64,
    min: i32,
    max: i32,
}

/// Authorize the current task and return the same cgroup id used for event
/// attribution. Cgroup policy wins over the temporary additive PID fallback.
#[inline(always)]
fn capture_scope(pid: u32) -> Option<CaptureScope> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some((scope_cgroup_id, policy_generation)) = matched_cgroup_scope(cgroup_id) {
        return Some(CaptureScope {
            cgroup_id,
            scope_cgroup_id,
            policy_generation,
        });
    }

    if let Some(policy_generation) = unsafe { TARGET_PIDS.get(&pid) } {
        if *policy_generation != 0 {
            return Some(CaptureScope {
                cgroup_id,
                scope_cgroup_id: 0,
                policy_generation: *policy_generation,
            });
        }
    }

    None
}

#[inline(always)]
fn capture_scopes_match(left: CaptureScope, right: CaptureScope) -> bool {
    left.cgroup_id == right.cgroup_id
        && left.scope_cgroup_id == right.scope_cgroup_id
        && left.policy_generation == right.policy_generation
}

#[inline(always)]
fn matched_cgroup_scope(cgroup_id: u64) -> Option<(u64, u64)> {
    if cgroup_id == 0 {
        return None;
    }

    let selector = ACTIVE_CGROUP_SLOT.get(0).copied()?;
    let slot = (selector >> CGROUP_SELECTOR_SLOT_SHIFT) as u32;
    let generation = selector & CGROUP_SELECTOR_GENERATION_MASK;
    if generation == 0 {
        return None;
    }
    let levels = configured_cgroup_levels(slot)?;
    let exact_match = cgroup_allowed(slot, cgroup_id, generation);

    // A missing root id makes it impossible to prove that an allow-set entry
    // is not the root cgroup, so cgroup authorization fails closed.
    let root_cgroup_id = unsafe { bpf_get_current_ancestor_cgroup_id(0) };
    if root_cgroup_id == 0 {
        return None;
    }
    if exact_match && cgroup_id != root_cgroup_id && cgroup_policy_is_current(selector) {
        return Some((cgroup_id, generation));
    }

    // A workload anchor can be an ancestor of the process leaf. Inspect only
    // levels represented by the active policy, deepest first, with a constant
    // verifier-visible bound.
    let mut level = levels.max;
    let mut remaining = MAX_CGROUP_ANCESTOR_LEVEL as i32;
    while remaining > 0 && level >= levels.min {
        let level_bit = 1_u64 << ((level - 1) as u32);
        if levels.mask & level_bit != 0 {
            let ancestor_id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
            if ancestor_id != 0
                && ancestor_id != root_cgroup_id
                && cgroup_allowed(slot, ancestor_id, generation)
                && cgroup_policy_is_current(selector)
            {
                return Some((ancestor_id, generation));
            }
        }
        level -= 1;
        remaining -= 1;
    }

    None
}

#[inline(always)]
fn cgroup_allowed(slot: u32, cgroup_id: u64, generation: u64) -> bool {
    let stored_generation = match slot {
        0 => unsafe { ALLOWED_CGROUPS_A.get(&cgroup_id) }.copied(),
        1 => unsafe { ALLOWED_CGROUPS_B.get(&cgroup_id) }.copied(),
        _ => None,
    };
    stored_generation == Some(generation)
}

#[inline(always)]
fn configured_cgroup_levels(slot: u32) -> Option<CgroupLevelPolicy> {
    let packed = match slot {
        0 => ALLOWED_CGROUP_LEVELS_A.get(0).copied().unwrap_or(0),
        1 => ALLOWED_CGROUP_LEVELS_B.get(0).copied().unwrap_or(0),
        _ => 0,
    };
    let mask = packed & CGROUP_LEVEL_MASK;
    let min = ((packed >> CGROUP_MIN_LEVEL_SHIFT) & CGROUP_LEVEL_FIELD_MASK) as i32;
    let max = ((packed >> CGROUP_MAX_LEVEL_SHIFT) & CGROUP_LEVEL_FIELD_MASK) as i32;
    if mask == 0 || min < 1 || max > MAX_CGROUP_ANCESTOR_LEVEL as i32 || min > max {
        return None;
    }

    let min_bit = 1_u64 << ((min - 1) as u32);
    let max_bit = 1_u64 << ((max - 1) as u32);
    let below_min = min_bit - 1;
    let through_max = if max == MAX_CGROUP_ANCESTOR_LEVEL as i32 {
        CGROUP_LEVEL_MASK
    } else {
        (1_u64 << (max as u32)) - 1
    };
    if mask & min_bit == 0
        || mask & max_bit == 0
        || mask & below_min != 0
        || mask & !through_max != 0
    {
        return None;
    }

    Some(CgroupLevelPolicy { mask, min, max })
}

#[inline(always)]
fn cgroup_policy_is_current(selector: u64) -> bool {
    ACTIVE_CGROUP_SLOT.get(0).copied() == Some(selector)
}

// Captured log payloads, drained by the userspace loader.
#[map]
static LOG_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Outbound connect(2) events, drained by the userspace loader.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Successful TCP listener discovery events (port→cgroup), drained by the
// userspace loader. Unfiltered by capture policy: discovery must see every
// listener host-wide to resolve which cgroup owns a targeted port. Listener
// transitions are rare, so the volume is negligible.
#[map]
static LISTENER_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Per-CPU count of listener discovery events that could not be staged or
// published. Userspace compares the complete vector across a snapshot.
#[map]
static LISTENER_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Per-CPU successful-listen publication sequence. Each event carries its CPU
// and sequence, so userspace fences a vector of contiguous per-CPU watermarks
// without relying on newer BPF_FETCH atomics or BTF spin-lock map values.
#[map]
static LISTENER_PUBLISHED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// inet_sock_set_state announces TCP_LISTEN before listen(2) has completed.
// Stage the candidate per calling thread; sys_exit_listen emits it only when
// the syscall succeeds and removes it on every exit.
#[map]
static LISTEN_CANDIDATES: HashMap<u64, ListenerEvent> = HashMap::with_max_entries(1024, 0);

// L7 (APM) socket payloads — both directions, drained separately from LOG_EVENTS.
#[map]
static L7_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// sys_enter_read/recvfrom stash a thread's (buf, fd) here, keyed by pid_tgid;
// sys_exit_read/recvfrom reads the syscall return (bytes read) and consumes it.
#[map]
static L7_READ_ARGS: HashMap<u64, ReadArgs> = HashMap::with_max_entries(10240, 0);

/// In-flight read args carried from a syscall's enter tracepoint to its exit.
#[repr(C)]
#[derive(Clone, Copy)]
struct ReadArgs {
    buf: u64,
    fd: u64,
    scope: CaptureScope,
}

// TLS plaintext payloads tapped at the SSL_read/SSL_write uprobe boundary, drained
// separately from L7_EVENTS so userspace knows they're already decrypted.
#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// SSL_read uprobe stashes a thread's (ssl, buf) here, keyed by pid_tgid; the
// SSL_read uretprobe reads the return (plaintext bytes) and consumes it.
#[map]
static TLS_READ_ARGS: HashMap<u64, TlsReadArgs> = HashMap::with_max_entries(10240, 0);

/// In-flight `SSL_read`/`SSL_read_ex` args carried from the uprobe (entry) to the
/// uretprobe. `readbytes` is the `*readbytes` out-pointer for the `_ex` variant
/// (the byte count lands there, not in the return value); 0 for plain `SSL_read`.
#[repr(C)]
#[derive(Clone, Copy)]
struct TlsReadArgs {
    ssl: u64,
    buf: u64,
    readbytes: u64,
    scope: CaptureScope,
}

#[tracepoint]
pub fn edgepacer_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    // Gather everything fallible BEFORE reserving: the verifier requires that a
    // reserved ring-buffer entry is submitted/discarded on every path, so no
    // early return may happen while one is held.
    // tgid() is the userspace-visible PID; command() is the post-exec comm.
    let pid = ctx.tgid();
    let comm = ctx.command().map_err(|_| 1_i64)?;

    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        return Err(0);
    };
    entry.write(ExecEvent { pid, comm });
    entry.submit(0);
    Ok(())
}

/// Capture authorized `write(2)` payloads (ADR-002 Level 1 log capture).
///
/// Note on mechanism: this hooks the `sys_enter_write` tracepoint, which is the
/// simplest verifiable capture. A broader kprobe strategy can also cover
/// `tty_write`/`pipe_write`/`ksys_write` paths; matching
/// that is a refinement, not a blocker for the current capture path.
#[tracepoint]
pub fn capture_write(ctx: TracePointContext) -> u32 {
    match try_capture(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_capture(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };

    // sys_enter_write tracepoint args (from .../events/syscalls/sys_enter_write/format):
    // fd @ offset 16, const char *buf @ 24, size_t count @ 32.
    let buf: *const u8 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_i64)? };
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };

    let Some(mut entry) = LOG_EVENTS.reserve::<LogChunk>(0) else {
        return Err(0);
    };

    // The 128-byte payload is too large for the 512-byte BPF stack, so fields
    // are written straight through the ring-buffer pointer.
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).cgroup_id = scope.cgroup_id;
        (*record).scope_cgroup_id = scope.scope_cgroup_id;
        (*record).policy_generation = scope.policy_generation;
        (*record).pid = pid;
        (*record).fd = fd as u32;
        (*record).len = if count > CHUNK_LEN as u64 {
            CHUNK_LEN as u32
        } else {
            count as u32
        };
        // Fixed-size read keeps the verifier happy; a short user buffer near a
        // page boundary can fault, in which case we drop this event.
        if bpf_probe_read_user_buf(buf, &mut (*record).data).is_err() {
            entry.discard(0);
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

/// Capture authorized `writev(2)` payloads (decision 5: close the
/// writev-to-stdout gap that the `sys_enter_write` hook misses — containerized
/// and buffered loggers emit via `writev`). Captures the first iovec segment
/// with a fixed-size read, mirroring `capture_write`; a line split across
/// multiple iovecs captures only the first segment for now.
#[tracepoint]
pub fn capture_writev(ctx: TracePointContext) -> u32 {
    match try_capture_writev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_capture_writev(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };

    // sys_enter_writev args: fd @ 16, const struct iovec *vec @ 24, unsigned long vlen @ 32.
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let vec: u64 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let vlen: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_i64)? };
    if vlen == 0 {
        return Ok(());
    }

    // Read the first iovec { void *iov_base; size_t iov_len } (16 bytes on 64-bit).
    let mut iov = [0u8; 16];
    if unsafe { bpf_probe_read_user_buf(vec as *const u8, &mut iov) }.is_err() {
        return Ok(());
    }
    let iov_base = u64::from_ne_bytes([
        iov[0], iov[1], iov[2], iov[3], iov[4], iov[5], iov[6], iov[7],
    ]);
    let iov_len = u64::from_ne_bytes([
        iov[8], iov[9], iov[10], iov[11], iov[12], iov[13], iov[14], iov[15],
    ]);

    let Some(mut entry) = LOG_EVENTS.reserve::<LogChunk>(0) else {
        return Err(0);
    };
    // Gather all fields before the (fallible) buffer read; discard on fault.
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).cgroup_id = scope.cgroup_id;
        (*record).scope_cgroup_id = scope.scope_cgroup_id;
        (*record).policy_generation = scope.policy_generation;
        (*record).pid = pid;
        (*record).fd = fd as u32;
        (*record).len = if iov_len > CHUNK_LEN as u64 {
            CHUNK_LEN as u32
        } else {
            iov_len as u32
        };
        if bpf_probe_read_user_buf(iov_base as *const u8, &mut (*record).data).is_err() {
            entry.discard(0);
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

/// Capture authorized outbound IPv4 `connect(2)` (ADR-002 Level 2:
/// service-dependency / network-flow signal). Reads the destination sockaddr
/// from the syscall argument.
#[tracepoint]
pub fn capture_connect(ctx: TracePointContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };

    // sys_enter_connect args: fd @ 16, struct sockaddr *uservaddr @ 24, addrlen @ 32.
    let uservaddr: *const u8 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };

    // sockaddr_in: sa_family (host order) @0, sin_port (BE) @2, sin_addr @4.
    let mut raw = [0u8; 8];
    if unsafe { bpf_probe_read_user_buf(uservaddr, &mut raw) }.is_err() {
        return Ok(());
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != 2 {
        return Ok(()); // AF_INET only for this capture path
    }
    let event = ConnectEvent {
        cgroup_id: scope.cgroup_id,
        scope_cgroup_id: scope.scope_cgroup_id,
        policy_generation: scope.policy_generation,
        pid,
        daddr: [raw[4], raw[5], raw[6], raw[7]],
        dport: u16::from_be_bytes([raw[2], raw[3]]),
        family,
    };

    let Some(mut entry) = CONNECT_EVENTS.reserve::<ConnectEvent>(0) else {
        return Err(0);
    };
    entry.write(event);
    entry.submit(0);
    Ok(())
}

/// Stage a listener's `port → cgroup` when TCP enters LISTEN (event-driven,
/// host-wide, NOT filtered by capture policy). `capture_listen_exit` publishes the
/// candidate only after listen(2) succeeds.
#[tracepoint]
pub fn capture_listen(ctx: TracePointContext) -> u32 {
    match try_listen(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_listen(ctx: &TracePointContext) -> Result<(), i64> {
    // sock:inet_sock_set_state tracepoint layout on the supported 64-bit Linux
    // kernels: newstate @20, sport @24, family @28, protocol @30. `sport` is
    // already host-order. IPPROTO_TCP=6.
    let new_state: i32 = unsafe { ctx.read_at(20).map_err(|_| 1_i64)? };
    if new_state != BPF_TCP_LISTEN as i32 {
        return Ok(());
    }
    let protocol: u16 = unsafe { ctx.read_at(30).map_err(|_| 1_i64)? };
    if protocol != 6 {
        return Ok(());
    }
    let port: u16 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let family: u16 = unsafe { ctx.read_at(28).map_err(|_| 1_i64)? };
    if port == 0 || (family != 2 && family != 10) {
        return Ok(());
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id == 0 {
        return Ok(());
    }

    let event = ListenerEvent {
        cgroup_id,
        observed_at_ns: 0,
        sequence: 0,
        tgid: ctx.tgid(),
        cpu_id: 0,
        port,
        family,
    };
    let key = bpf_get_current_pid_tgid();
    if LISTEN_CANDIDATES.insert(&key, &event, 0).is_err() {
        record_listener_drop();
        return Err(1);
    }
    Ok(())
}

/// Publish a staged listener only when listen(2) returns success. The candidate
/// is removed before reading the return value so every exit path cleans it up.
#[tracepoint]
pub fn capture_listen_exit(ctx: TracePointContext) -> u32 {
    match try_listen_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_listen_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let mut event = match unsafe { LISTEN_CANDIDATES.get(&key) } {
        Some(event) => *event,
        None => return Ok(()),
    };
    let _ = LISTEN_CANDIDATES.remove(&key);

    // sys_exit tracepoint layout: syscall return value is a signed long @16.
    let ret: i64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    if ret != 0 {
        return Ok(());
    }

    // Reserve before advancing this CPU's publication sequence so every
    // sampled sequence has a ring-buffer record that the drain can consume.
    // Any failure changes only the drop epoch and invalidates the snapshot.
    let Some(mut entry) = LISTENER_EVENTS.reserve::<ListenerEvent>(0) else {
        record_listener_drop();
        return Err(0);
    };

    let Some(sequence) = increment_listener_counter(&LISTENER_PUBLISHED) else {
        entry.discard(0);
        record_listener_drop();
        return Err(0);
    };

    event.observed_at_ns = unsafe { bpf_ktime_get_ns() };
    event.sequence = sequence;
    event.cpu_id = unsafe { bpf_get_smp_processor_id() };

    entry.write(event);
    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn record_listener_drop() {
    let _ = increment_listener_counter(&LISTENER_DROPS);
}

#[inline(always)]
fn increment_listener_counter(counter: &PerCpuArray<u64>) -> Option<u64> {
    let Some(value) = counter.get_ptr_mut(0) else {
        return None;
    };
    // SAFETY: each CPU has exclusive access to its own array cell.
    unsafe {
        *value = (*value).wrapping_add(1);
        Some(*value)
    }
}

// ── L7 socket capture (ADR-002 Level 3, the zero-code APM path) ──────────────
//
// Both directions of an authorized workload's socket I/O are tapped and emitted as
// `L7Chunk`s; userspace reassembles + parses them. Arg offsets line up so one
// program covers two syscalls each: write+sendto (outbound, count known at
// enter) and read+recvfrom (inbound, count only known at the exit return value,
// so the buffer pointer is stashed on enter). Socket-vs-file fd filtering is a
// refinement — the userspace parser drops non-HTTP connections via detection.

/// Reserve an `L7Chunk` and fill it from a user buffer. Mirrors `try_capture`'s
/// verifier-safe shape: write through the ring pointer (the payload is too big
/// for the 512-byte BPF stack), discard on a faulting user read.
fn emit_l7(
    scope: CaptureScope,
    pid: u32,
    fd: u32,
    direction: u8,
    buf: *const u8,
    count: u64,
) -> Result<(), i64> {
    let Some(mut entry) = L7_EVENTS.reserve::<L7Chunk>(0) else {
        return Err(0);
    };
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).cgroup_id = scope.cgroup_id;
        (*record).scope_cgroup_id = scope.scope_cgroup_id;
        (*record).policy_generation = scope.policy_generation;
        (*record).pid = pid;
        (*record).fd = fd;
        (*record).direction = direction;
        (*record).len = if count > L7_CHUNK_LEN as u64 {
            L7_CHUNK_LEN as u32
        } else {
            count as u32
        };
        if bpf_probe_read_user_buf(buf, &mut (*record).data).is_err() {
            entry.discard(0);
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

/// Outbound: authorized `write(2)` / `sendto(2)`. Both share the arg
/// layout fd@16, buf@24, count@32, and the byte count is known at enter.
#[tracepoint]
pub fn l7_io_write(ctx: TracePointContext) -> u32 {
    match try_l7_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_l7_write(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let buf: *const u8 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_i64)? };
    emit_l7(scope, pid, fd as u32, L7_DIR_OUTBOUND, buf, count)
}

/// Outbound: authorized `writev(2)`. hyper-class runtimes emit framed HTTP
/// responses through vectored writes, which the `write`/`sendto` hook never
/// sees — without this the response half of every pair is invisible and no
/// L7 record ever completes (#99). Captures the first iovec segment (status
/// line + headers); multi-iovec reassembly is the known refinement.
#[tracepoint]
pub fn l7_io_writev(ctx: TracePointContext) -> u32 {
    match try_l7_writev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_l7_writev(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    // sys_enter_writev args: fd @ 16, const struct iovec *vec @ 24, unsigned long vlen @ 32.
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let vec: u64 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let vlen: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_i64)? };
    if vlen == 0 {
        return Ok(());
    }

    // Read the first iovec { void *iov_base; size_t iov_len } (16 bytes on 64-bit).
    let mut iov = [0u8; 16];
    if unsafe { bpf_probe_read_user_buf(vec as *const u8, &mut iov) }.is_err() {
        return Ok(());
    }
    let iov_base = u64::from_ne_bytes([
        iov[0], iov[1], iov[2], iov[3], iov[4], iov[5], iov[6], iov[7],
    ]);
    let iov_len = u64::from_ne_bytes([
        iov[8], iov[9], iov[10], iov[11], iov[12], iov[13], iov[14], iov[15],
    ]);
    emit_l7(
        scope,
        pid,
        fd as u32,
        L7_DIR_OUTBOUND,
        iov_base as *const u8,
        iov_len,
    )
}

/// Inbound enter: `read(2)` / `recvfrom(2)` (fd@16, buf@24). Stash the buffer
/// pointer; the byte count is only known at the exit return value.
#[tracepoint]
pub fn l7_io_read_enter(ctx: TracePointContext) -> u32 {
    match try_l7_read_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_l7_read_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let buf: u64 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let key = bpf_get_current_pid_tgid();
    let _ = L7_READ_ARGS.insert(&key, &ReadArgs { buf, fd, scope }, 0);
    Ok(())
}

/// Inbound exit: `read(2)` / `recvfrom(2)` (ret@16 = bytes read). Consume the
/// stashed buffer pointer and emit the captured prefix.
#[tracepoint]
pub fn l7_io_read_exit(ctx: TracePointContext) -> u32 {
    match try_l7_read_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_l7_read_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let args = match unsafe { L7_READ_ARGS.get(&key) } {
        Some(a) => *a,
        None => return Ok(()),
    };
    let _ = L7_READ_ARGS.remove(&key);
    let ret: i64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    if ret <= 0 {
        return Ok(());
    }
    let pid = (key >> 32) as u32;
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    if !capture_scopes_match(scope, args.scope) {
        return Ok(());
    }
    emit_l7(
        scope,
        pid,
        args.fd as u32,
        L7_DIR_INBOUND,
        args.buf as *const u8,
        ret as u64,
    )
}

// ── TLS plaintext capture (SSL_read/SSL_write uprobes) ───────────────────────
//
// On encrypted connections the read/write tracepoints see ciphertext (which the
// L7 parsers drop). Tapping OpenSSL's SSL_read/SSL_write — the plaintext boundary
// — recovers the real protocol bytes. The function ARGS are the stable public ABI
// (SSL_write(SSL*, const void*, int) / SSL_read(SSL*, void*, int)), so no
// version-specific struct walking is needed; we key the connection by the SSL*.

/// Reserve a `TlsChunk` and fill it from a user buffer (verifier-safe shape).
fn emit_tls(
    scope: CaptureScope,
    pid: u32,
    ssl: u64,
    direction: u8,
    buf: *const u8,
    count: u64,
) -> Result<(), i64> {
    let Some(mut entry) = TLS_EVENTS.reserve::<TlsChunk>(0) else {
        return Err(0);
    };
    let record = entry.as_mut_ptr();
    unsafe {
        (*record).cgroup_id = scope.cgroup_id;
        (*record).scope_cgroup_id = scope.scope_cgroup_id;
        (*record).policy_generation = scope.policy_generation;
        (*record).ssl = ssl;
        (*record).pid = pid;
        (*record).direction = direction;
        (*record).len = if count > L7_CHUNK_LEN as u64 {
            L7_CHUNK_LEN as u32
        } else {
            count as u32
        };
        if bpf_probe_read_user_buf(buf, &mut (*record).data).is_err() {
            entry.discard(0);
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

/// `SSL_write(SSL *ssl, const void *buf, int num)` — the plaintext is in `buf` on
/// entry (before encryption). Outbound from the monitored process.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let num: i32 = ctx.arg(2).ok_or(1_i64)?;
    if num <= 0 {
        return Ok(());
    }
    emit_tls(
        scope,
        pid,
        ssl,
        L7_DIR_OUTBOUND,
        buf as *const u8,
        num as u64,
    )
}

/// `SSL_read(SSL *ssl, void *buf, int num)` entry — the buffer is filled on
/// return, so stash (ssl, buf) and read the plaintext at the uretprobe.
#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let key = bpf_get_current_pid_tgid();
    let _ = TLS_READ_ARGS.insert(
        &key,
        &TlsReadArgs {
            ssl,
            buf,
            readbytes: 0,
            scope,
        },
        0,
    );
    Ok(())
}

/// `SSL_read` return — the return value is the plaintext byte count. Inbound.
#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let args = match unsafe { TLS_READ_ARGS.get(&key) } {
        Some(a) => *a,
        None => return Ok(()),
    };
    let _ = TLS_READ_ARGS.remove(&key);
    let ret: i32 = ctx.ret().ok_or(1_i64)?;
    if ret <= 0 {
        return Ok(());
    }
    let pid = (key >> 32) as u32;
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    if !capture_scopes_match(scope, args.scope) {
        return Ok(());
    }
    emit_tls(
        scope,
        pid,
        args.ssl,
        L7_DIR_INBOUND,
        args.buf as *const u8,
        ret as u64,
    )
}

/// `SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)` — the
/// OpenSSL 3.0 API that modern runtimes link (e.g. Python 3.12). Plaintext is in
/// `buf` on entry; `num` (arg2) is the size_t length.
#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    match try_ssl_write_ex(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write_ex(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let num: u64 = ctx.arg(2).ok_or(1_i64)?;
    if num == 0 {
        return Ok(());
    }
    emit_tls(scope, pid, ssl, L7_DIR_OUTBOUND, buf as *const u8, num)
}

/// `SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)` entry — the
/// plaintext byte count lands in `*readbytes` (arg3), not the return value, so
/// stash that out-pointer along with the buffer.
#[uprobe]
pub fn ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_ex_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_ex_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = ctx.tgid();
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let readbytes: u64 = ctx.arg(3).ok_or(1_i64)?;
    let key = bpf_get_current_pid_tgid();
    let _ = TLS_READ_ARGS.insert(
        &key,
        &TlsReadArgs {
            ssl,
            buf,
            readbytes,
            scope,
        },
        0,
    );
    Ok(())
}

/// `SSL_read_ex` return — returns 1 on success; the byte count is at `*readbytes`.
/// Deref that out-pointer and emit the captured plaintext prefix. Inbound.
#[uretprobe]
pub fn ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ex_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_ex_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let args = match unsafe { TLS_READ_ARGS.get(&key) } {
        Some(a) => *a,
        None => return Ok(()),
    };
    let _ = TLS_READ_ARGS.remove(&key);
    let ret: i32 = ctx.ret().ok_or(1_i64)?;
    if ret != 1 {
        return Ok(());
    }
    let bytes: u64 =
        unsafe { bpf_probe_read_user(args.readbytes as *const u64).map_err(|_| 1_i64)? };
    if bytes == 0 {
        return Ok(());
    }
    let pid = (key >> 32) as u32;
    let Some(scope) = capture_scope(pid) else {
        return Ok(());
    };
    if !capture_scopes_match(scope, args.scope) {
        return Ok(());
    }
    emit_tls(
        scope,
        pid,
        args.ssl,
        L7_DIR_INBOUND,
        args.buf as *const u8,
        bytes,
    )
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
