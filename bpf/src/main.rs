//! Kernel-side BPF program: attach to the `sched_process_exec` tracepoint and
//! push one `ExecEvent` (pid + comm) per exec into a ring buffer.
//!
//! This is the minimal real program that proves the data path: kernel event →
//! BPF map → userspace. ADR-002 Level 1 "Observe" (process lifecycle).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
    EbpfContext,
};
use edgepacer_ebpf_common::{
    ConnectEvent, ExecEvent, LogChunk, L7Chunk, TlsChunk, CHUNK_LEN, L7_CHUNK_LEN, L7_DIR_INBOUND,
    L7_DIR_OUTBOUND,
};

// 256 KiB ring buffer (power of two, page-aligned) shared with userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Userspace seeds this with the PIDs whose write(2)s should be captured.
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Captured log payloads, drained by the userspace loader.
#[map]
static LOG_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Outbound connect(2) events, drained by the userspace loader.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

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

/// Capture `write(2)` payloads from targeted PIDs (ADR-002 Level 1 log capture).
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
    // Only capture writes from PIDs userspace explicitly targeted.
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }

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

/// Capture `writev(2)` payloads from targeted PIDs (decision 5: close the
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }

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

/// Capture outbound IPv4 `connect(2)` from targeted PIDs (ADR-002 Level 2:
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }

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

// ── L7 socket capture (ADR-002 Level 3, the zero-code APM path) ──────────────
//
// Both directions of a targeted PID's socket I/O are tapped and emitted as
// `L7Chunk`s; userspace reassembles + parses them. Arg offsets line up so one
// program covers two syscalls each: write+sendto (outbound, count known at
// enter) and read+recvfrom (inbound, count only known at the exit return value,
// so the buffer pointer is stashed on enter). Socket-vs-file fd filtering is a
// refinement — the userspace parser drops non-HTTP connections via detection.

/// Reserve an `L7Chunk` and fill it from a user buffer. Mirrors `try_capture`'s
/// verifier-safe shape: write through the ring pointer (the payload is too big
/// for the 512-byte BPF stack), discard on a faulting user read.
fn emit_l7(pid: u32, fd: u32, direction: u8, buf: *const u8, count: u64) -> Result<(), i64> {
    let Some(mut entry) = L7_EVENTS.reserve::<L7Chunk>(0) else {
        return Err(0);
    };
    let record = entry.as_mut_ptr();
    unsafe {
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

/// Outbound: `write(2)` / `sendto(2)` from a targeted PID. Both share the arg
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let buf: *const u8 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let count: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_i64)? };
    emit_l7(pid, fd as u32, L7_DIR_OUTBOUND, buf, count)
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| 1_i64)? };
    let buf: u64 = unsafe { ctx.read_at(24).map_err(|_| 1_i64)? };
    let key = bpf_get_current_pid_tgid();
    let _ = L7_READ_ARGS.insert(&key, &ReadArgs { buf, fd }, 0);
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
    emit_l7(
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
fn emit_tls(pid: u32, ssl: u64, direction: u8, buf: *const u8, count: u64) -> Result<(), i64> {
    let Some(mut entry) = TLS_EVENTS.reserve::<TlsChunk>(0) else {
        return Err(0);
    };
    let record = entry.as_mut_ptr();
    unsafe {
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let num: i32 = ctx.arg(2).ok_or(1_i64)?;
    if num <= 0 {
        return Ok(());
    }
    emit_tls(pid, ssl, L7_DIR_OUTBOUND, buf as *const u8, num as u64)
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let key = bpf_get_current_pid_tgid();
    let _ = TLS_READ_ARGS.insert(&key, &TlsReadArgs { ssl, buf, readbytes: 0 }, 0);
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
    emit_tls(pid, args.ssl, L7_DIR_INBOUND, args.buf as *const u8, ret as u64)
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let num: u64 = ctx.arg(2).ok_or(1_i64)?;
    if num == 0 {
        return Ok(());
    }
    emit_tls(pid, ssl, L7_DIR_OUTBOUND, buf as *const u8, num)
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
    if unsafe { TARGET_PIDS.get(&pid) }.is_none() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(1_i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1_i64)?;
    let readbytes: u64 = ctx.arg(3).ok_or(1_i64)?;
    let key = bpf_get_current_pid_tgid();
    let _ = TLS_READ_ARGS.insert(&key, &TlsReadArgs { ssl, buf, readbytes }, 0);
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
    emit_tls(pid, args.ssl, L7_DIR_INBOUND, args.buf as *const u8, bytes)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
