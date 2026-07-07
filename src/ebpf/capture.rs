//! Aya-backed [`CaptureProgram`] + the ring drains — the single boundary between
//! the manager and the kernel. Loads the embedded BPF object, attaches the
//! capture tracepoints, mirrors the resolved [`PidRouting`] into the kernel
//! `TARGET_PIDS` filter, and forwards captured write payloads as [`CapturedLine`]s
//! and (when network flows are enabled) outbound connects as [`CapturedFlow`]s
//! over mpsc channels the runner routes by PID → service.
//!
//! Linux + `ebpf` only (it links aya). The reconcile orchestration that drives
//! it lives in `manager.rs` and is tested on every platform via a fake.

use std::collections::HashSet;
use std::num::NonZeroU32;

use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{TracePoint, UProbe};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

use edgepacer_ebpf_common::{
    CHUNK_LEN, ConnectEvent, L7_CHUNK_LEN, L7_DIR_INBOUND, L7Chunk, LogChunk, TlsChunk,
};

use super::l7::{CapturedSegment, Direction};
use super::manager::CaptureProgram;
use super::pid_resolver::PidRouting;
use super::tls_libs;
use crate::config::EbpfSectionConfig;

/// The embedded BPF object, built from the top-level `bpf/` crate via
/// `scripts/regen-bpf-object.sh` and checked in so the agent's musl/cross build
/// needs no BPF toolchain.
static BPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/ebpf/programs/edgepacer.bpf.o"
));

/// (program name, tracepoint category, tracepoint event) in the embedded object.
const CAPTURE_WRITE: (&str, &str, &str) = ("capture_write", "syscalls", "sys_enter_write");
const CAPTURE_WRITEV: (&str, &str, &str) = ("capture_writev", "syscalls", "sys_enter_writev");
const CAPTURE_CONNECT: (&str, &str, &str) = ("capture_connect", "syscalls", "sys_enter_connect");

/// L7 capture programs (the zero-code APM path). Each attaches to two syscall
/// tracepoints whose arg offsets match, so one program covers both:
/// (program name, &[(category, event), …]).
const L7_WRITE: (&str, &[(&str, &str)]) = (
    "l7_io_write",
    &[
        ("syscalls", "sys_enter_write"),
        ("syscalls", "sys_enter_sendto"),
    ],
);
const L7_READ_ENTER: (&str, &[(&str, &str)]) = (
    "l7_io_read_enter",
    &[
        ("syscalls", "sys_enter_read"),
        ("syscalls", "sys_enter_recvfrom"),
    ],
);
const L7_READ_EXIT: (&str, &[(&str, &str)]) = (
    "l7_io_read_exit",
    &[
        ("syscalls", "sys_exit_read"),
        ("syscalls", "sys_exit_recvfrom"),
    ],
);

// `LogChunk`, `ConnectEvent`, and `CHUNK_LEN` are imported from the shared eBPF
// layout crate that the kernel BPF program (bpf/) also uses, so the ring-buffer wire
// layout has a single source of truth and can't drift from a hand-mirrored copy.

/// One captured `write(2)` payload, routed to a service by `pid` downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedLine {
    pub pid: u32,
    pub fd: u32,
    pub bytes: Vec<u8>,
}

/// One captured outbound `connect(2)` (network-flow signal), routed by `pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFlow {
    pub pid: u32,
    pub daddr: [u8; 4],
    pub dport: u16,
    pub family: u16,
}

/// Live aya state held while capture is loaded.
struct Loaded {
    // Held for its `Drop`: dropping the `Ebpf` detaches every attached program.
    #[allow(dead_code)]
    ebpf: Ebpf,
    target_pids: AyaHashMap<MapData, u32, u8>,
    /// PIDs currently written into the kernel filter, to diff on the next refresh.
    seeded: HashSet<u32>,
    /// The LOG_EVENTS drain task; aborted on `stop()`.
    drain: JoinHandle<()>,
    /// The CONNECT_EVENTS drain task (present only when network flows are on).
    flow_drain: Option<JoinHandle<()>>,
    /// The L7_EVENTS drain task; aborted on `stop()`.
    l7_drain: JoinHandle<()>,
    /// The TLS_EVENTS drain task (present only when libssl uprobes attached).
    tls_drain: Option<JoinHandle<()>>,
}

/// Loads the embedded BPF object, drives the kernel `TARGET_PIDS` filter, drains
/// `LOG_EVENTS` into `captured_tx`, and (when network flows are enabled)
/// `CONNECT_EVENTS` into `flow_tx`.
pub struct AyaCaptureProgram {
    captured_tx: mpsc::Sender<CapturedLine>,
    flow_tx: mpsc::Sender<CapturedFlow>,
    l7_tx: mpsc::Sender<CapturedSegment>,
    loaded: Option<Loaded>,
}

impl AyaCaptureProgram {
    pub fn new(
        captured_tx: mpsc::Sender<CapturedLine>,
        flow_tx: mpsc::Sender<CapturedFlow>,
        l7_tx: mpsc::Sender<CapturedSegment>,
    ) -> Self {
        Self {
            captured_tx,
            flow_tx,
            l7_tx,
            loaded: None,
        }
    }
}

impl CaptureProgram for AyaCaptureProgram {
    fn start(&mut self, section: &EbpfSectionConfig) -> Result<(), String> {
        let mut ebpf = Ebpf::load(BPF_OBJECT).map_err(|e| format!("load BPF object: {e}"))?;

        attach_tracepoint(&mut ebpf, CAPTURE_WRITE)?;
        attach_tracepoint(&mut ebpf, CAPTURE_WRITEV)?;

        let log_events = ebpf
            .take_map("LOG_EVENTS")
            .ok_or("BPF map LOG_EVENTS not found")?;
        let ring =
            RingBuf::try_from(log_events).map_err(|e| format!("open LOG_EVENTS ring: {e}"))?;
        let drain = spawn_drain(ring, self.captured_tx.clone());

        // Network flows are an independent sub-toggle: attach + drain only then.
        let flow_drain = if section.network_flows_enabled {
            attach_tracepoint(&mut ebpf, CAPTURE_CONNECT)?;
            let connect_events = ebpf
                .take_map("CONNECT_EVENTS")
                .ok_or("BPF map CONNECT_EVENTS not found")?;
            let flow_ring = RingBuf::try_from(connect_events)
                .map_err(|e| format!("open CONNECT_EVENTS ring: {e}"))?;
            Some(spawn_flow_drain(flow_ring, self.flow_tx.clone()))
        } else {
            None
        };

        // L7 socket capture (APM): tap both directions of targeted PIDs' socket
        // I/O. Always-on for now; gating on per-target `protocols` is a refinement.
        attach_tracepoint_multi(&mut ebpf, L7_WRITE.0, L7_WRITE.1)?;
        attach_tracepoint_multi(&mut ebpf, L7_READ_ENTER.0, L7_READ_ENTER.1)?;
        attach_tracepoint_multi(&mut ebpf, L7_READ_EXIT.0, L7_READ_EXIT.1)?;
        let l7_events = ebpf
            .take_map("L7_EVENTS")
            .ok_or("BPF map L7_EVENTS not found")?;
        let l7_ring =
            RingBuf::try_from(l7_events).map_err(|e| format!("open L7_EVENTS ring: {e}"))?;
        let l7_drain = spawn_l7_drain(l7_ring, self.l7_tx.clone());

        // TLS plaintext capture: SSL_read/SSL_write uprobes on OpenSSL recover the
        // protocol bytes on encrypted connections. Best-effort — if libssl can't be
        // resolved (static OpenSSL, or non-OpenSSL TLS like Go/Java), skip without
        // failing the whole capture. Plaintext drains into the same L7 pipeline.
        let tls_drain = match attach_tls_uprobes(&mut ebpf) {
            Ok(()) => {
                let tls_events = ebpf
                    .take_map("TLS_EVENTS")
                    .ok_or("BPF map TLS_EVENTS not found")?;
                let tls_ring = RingBuf::try_from(tls_events)
                    .map_err(|e| format!("open TLS_EVENTS ring: {e}"))?;
                Some(spawn_tls_drain(tls_ring, self.l7_tx.clone()))
            }
            Err(e) => {
                warn!(error = %e, "eBPF: TLS uprobe attach skipped");
                None
            }
        };

        let target_map = ebpf
            .take_map("TARGET_PIDS")
            .ok_or("BPF map TARGET_PIDS not found")?;
        let target_pids =
            AyaHashMap::try_from(target_map).map_err(|e| format!("open TARGET_PIDS map: {e}"))?;

        self.loaded = Some(Loaded {
            ebpf,
            target_pids,
            seeded: HashSet::new(),
            drain,
            flow_drain,
            l7_drain,
            tls_drain,
        });
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(loaded) = self.loaded.take() {
            loaded.drain.abort();
            if let Some(flow_drain) = loaded.flow_drain {
                flow_drain.abort();
            }
            loaded.l7_drain.abort();
            if let Some(tls_drain) = loaded.tls_drain {
                tls_drain.abort();
            }
            // Dropping `loaded` drops the `Ebpf` (detaches programs) and the rings.
        }
    }

    fn set_target_pids(&mut self, routing: &PidRouting) -> Result<(), String> {
        let Some(loaded) = self.loaded.as_mut() else {
            return Err("set_target_pids called while capture is stopped".to_string());
        };

        let desired: HashSet<u32> = routing.target_pids().collect();
        let to_add: Vec<u32> = desired.difference(&loaded.seeded).copied().collect();
        let to_remove: Vec<u32> = loaded.seeded.difference(&desired).copied().collect();

        for pid in to_add {
            loaded
                .target_pids
                .insert(pid, 0u8, 0)
                .map_err(|e| format!("seed pid {pid}: {e}"))?;
            // Per-target TLS: attach the uprobes to this process's bundled TLS libs
            // (Node static OpenSSL, Java BoringSSL) that the system-wide libssl
            // attach misses — the zero-config win for native-Java + Node TLS.
            for lib in tls_libs::discover(pid) {
                attach_tls_to_lib(&mut loaded.ebpf, &lib, pid as i32);
            }
        }
        for pid in to_remove {
            // Best-effort: the PID may already have exited and been reaped.
            let _ = loaded.target_pids.remove(&pid);
        }
        loaded.seeded = desired;
        Ok(())
    }
}

/// Poll the `LOG_EVENTS` ring async, decode each `LogChunk`, and forward a
/// `CapturedLine`. Exits when the consumer drops the channel or the task is
/// aborted (on `stop()`).
fn spawn_drain(ring: RingBuf<MapData>, tx: mpsc::Sender<CapturedLine>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(error = %e, "eBPF: cannot poll LOG_EVENTS ring");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    warn!(error = %e, "eBPF: LOG_EVENTS poll failed");
                    return;
                }
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<LogChunk>() {
                    continue;
                }
                // SAFETY: LogChunk is repr(C) POD written by the kernel;
                // read_unaligned tolerates the ring record alignment.
                let chunk = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const LogChunk) };
                let n = (chunk.len as usize).min(CHUNK_LEN);
                let line = CapturedLine {
                    pid: chunk.pid,
                    fd: chunk.fd,
                    bytes: chunk.data[..n].to_vec(),
                };
                if tx.send(line).await.is_err() {
                    return; // consumer gone
                }
            }
            guard.clear_ready();
        }
    })
}

/// Poll the `CONNECT_EVENTS` ring async, decode each `ConnectEvent`, and forward
/// a `CapturedFlow`. Exits when the consumer drops the channel or the task is
/// aborted (on `stop()`).
fn spawn_flow_drain(ring: RingBuf<MapData>, tx: mpsc::Sender<CapturedFlow>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(error = %e, "eBPF: cannot poll CONNECT_EVENTS ring");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    warn!(error = %e, "eBPF: CONNECT_EVENTS poll failed");
                    return;
                }
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<ConnectEvent>() {
                    continue;
                }
                // SAFETY: ConnectEvent is repr(C) POD written by the kernel.
                let ev = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const ConnectEvent) };
                let flow = CapturedFlow {
                    pid: ev.pid,
                    daddr: ev.daddr,
                    dport: ev.dport,
                    family: ev.family,
                };
                if tx.send(flow).await.is_err() {
                    return; // consumer gone
                }
            }
            guard.clear_ready();
        }
    })
}

/// Poll the `L7_EVENTS` ring async, decode each `L7Chunk`, and forward a
/// direction-tagged `CapturedSegment` for userspace L7 reassembly + parsing.
fn spawn_l7_drain(ring: RingBuf<MapData>, tx: mpsc::Sender<CapturedSegment>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(error = %e, "eBPF: cannot poll L7_EVENTS ring");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    warn!(error = %e, "eBPF: L7_EVENTS poll failed");
                    return;
                }
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<L7Chunk>() {
                    continue;
                }
                // SAFETY: L7Chunk is repr(C) POD written by the kernel.
                let chunk = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const L7Chunk) };
                let n = (chunk.len as usize).min(L7_CHUNK_LEN);
                let direction = if chunk.direction == L7_DIR_INBOUND {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };
                let timestamp_nano = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                let seg = CapturedSegment {
                    pid: chunk.pid,
                    fd: chunk.fd,
                    direction,
                    timestamp_nano,
                    bytes: chunk.data[..n].to_vec(),
                };
                if tx.send(seg).await.is_err() {
                    return; // consumer gone
                }
            }
            guard.clear_ready();
        }
    })
}

/// Poll the `TLS_EVENTS` ring async, decode each `TlsChunk` (plaintext tapped at
/// the SSL_read/SSL_write boundary), and forward it as a `CapturedSegment` into
/// the same L7 pipeline. The connection is keyed by a stable id derived from the
/// `SSL*` pointer — real fds are small ints and never collide with it.
fn spawn_tls_drain(ring: RingBuf<MapData>, tx: mpsc::Sender<CapturedSegment>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(error = %e, "eBPF: cannot poll TLS_EVENTS ring");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    warn!(error = %e, "eBPF: TLS_EVENTS poll failed");
                    return;
                }
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<TlsChunk>() {
                    continue;
                }
                // SAFETY: TlsChunk is repr(C) POD written by the kernel.
                let chunk = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const TlsChunk) };
                let n = (chunk.len as usize).min(L7_CHUNK_LEN);
                let direction = if chunk.direction == L7_DIR_INBOUND {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };
                let timestamp_nano = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                let seg = CapturedSegment {
                    pid: chunk.pid,
                    // Stable per-connection id from the SSL* pointer (drop alignment
                    // bits); real fds are small ints, so there's no collision.
                    fd: (chunk.ssl >> 4) as u32,
                    direction,
                    timestamp_nano,
                    bytes: chunk.data[..n].to_vec(),
                };
                if tx.send(seg).await.is_err() {
                    return; // consumer gone
                }
            }
            guard.clear_ready();
        }
    })
}

fn attach_tracepoint(ebpf: &mut Ebpf, prog: (&str, &str, &str)) -> Result<(), String> {
    let (name, category, event) = prog;
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("BPF program {name} not found"))?
        .try_into()
        .map_err(|e| format!("{name} is not a tracepoint: {e}"))?;
    program
        .load()
        .map_err(|e| format!("{name} verifier load: {e}"))?;
    program
        .attach(category, event)
        .map_err(|e| format!("attach {category}:{event}: {e}"))?;
    Ok(())
}

/// Like [`attach_tracepoint`] but loads the program once and attaches it to
/// several tracepoints — used for L7 programs that cover two syscalls each
/// (write+sendto, read+recvfrom) whose arg layouts match.
fn attach_tracepoint_multi(
    ebpf: &mut Ebpf,
    name: &str,
    events: &[(&str, &str)],
) -> Result<(), String> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("BPF program {name} not found"))?
        .try_into()
        .map_err(|e| format!("{name} is not a tracepoint: {e}"))?;
    program
        .load()
        .map_err(|e| format!("{name} verifier load: {e}"))?;
    for &(category, event) in events {
        program
            .attach(category, event)
            .map_err(|e| format!("attach {category}:{event}: {e}"))?;
    }
    Ok(())
}

/// Candidate libssl targets, tried in order — covers aya's name resolution plus
/// the common distro SONAME/paths. The first that attaches wins.
const LIBSSL_TARGETS: [&str; 4] = [
    "ssl",
    "libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/aarch64-linux-gnu/libssl.so.3",
];

/// Attach the TLS uprobes to OpenSSL. Both the classic (`SSL_read`/`SSL_write`)
/// and the OpenSSL 3.0 (`_ex`) APIs are hooked — a runtime links one or the other
/// (Python 3.12 uses the `_ex` variants). Best-effort per symbol: a missing or
/// unused symbol simply never fires. Errors only if nothing attached at all.
/// The TLS uprobe programs + their OpenSSL symbols (classic + OpenSSL-3.0 `_ex`).
const TLS_PROBES: [(&str, &str); 6] = [
    ("ssl_write", "SSL_write"),
    ("ssl_write_ex", "SSL_write_ex"),
    ("ssl_read_enter", "SSL_read"),
    ("ssl_read_exit", "SSL_read"),
    ("ssl_read_ex_enter", "SSL_read_ex"),
    ("ssl_read_ex_exit", "SSL_read_ex"),
];

fn attach_tls_uprobes(ebpf: &mut Ebpf) -> Result<(), String> {
    let mut attached = 0;
    let mut last_err = String::new();
    for (name, symbol) in TLS_PROBES {
        match attach_uprobe(ebpf, name, symbol) {
            Ok(()) => attached += 1,
            Err(e) => last_err = e,
        }
    }
    if attached == 0 {
        return Err(format!(
            "no TLS uprobes attached (no OpenSSL libssl?): {last_err}"
        ));
    }
    Ok(())
}

fn attach_uprobe(ebpf: &mut Ebpf, name: &str, symbol: &str) -> Result<(), String> {
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("BPF program {name} not found"))?
        .try_into()
        .map_err(|e| format!("{name} is not a uprobe: {e}"))?;
    program
        .load()
        .map_err(|e| format!("{name} verifier load: {e}"))?;
    let mut last_err = String::new();
    for target in LIBSSL_TARGETS {
        match program.attach(symbol, target, UProbeScope::AllProcesses) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = format!("{target}: {e}"),
        }
    }
    Err(format!("attach {name} -> {symbol} (no libssl): {last_err}"))
}

/// Attach the (already-loaded) TLS uprobes to one library for one pid — for the
/// per-target bundled-TLS libs (Node's static OpenSSL, Java Conscrypt/netty-tcnative
/// BoringSSL) found in `/proc/<pid>/maps` that the system-wide libssl attach
/// misses. Best-effort; feeds the same TLS drain. The programs are already loaded
/// by `attach_tls_uprobes` in `start()`, so this only attaches.
fn attach_tls_to_lib(ebpf: &mut Ebpf, lib: &str, pid: i32) {
    let Some(pid) = u32::try_from(pid).ok().and_then(NonZeroU32::new) else {
        return;
    };
    for (name, symbol) in TLS_PROBES {
        let Some(program) = ebpf.program_mut(name) else {
            continue;
        };
        let uprobe: &mut UProbe = match program.try_into() {
            Ok(uprobe) => uprobe,
            Err(_) => continue,
        };
        let _ = uprobe.attach(symbol, lib, UProbeScope::OneProcess(pid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EbpfTargetConfig;
    use crate::discovery::ports::ListeningPort;
    use std::time::Duration;

    fn enabled_section() -> EbpfSectionConfig {
        EbpfSectionConfig {
            enabled: true,
            receiver_port: 4318,
            network_flows_enabled: true,
            network_cidrs: Vec::new(),
            targets: Vec::new(),
            config_hash: "capture-test".to_string(),
        }
    }

    fn routing_for(pid: u32) -> PidRouting {
        let target = EbpfTargetConfig {
            log_source_id: "capture-test".to_string(),
            service_name: "capture-test".to_string(),
            open_ports: vec![65000],
            archive_id: String::new(),
            repo_id: String::new(),
            protocols: Vec::new(),
            subbox_endpoint: String::new(),
        };
        let census = vec![ListeningPort {
            port: 65000,
            protocol: "tcp".to_string(),
            process: "capture-test".to_string(),
            pid,
        }];
        super::super::pid_resolver::resolve_from_ports(&census, &[target])
    }

    /// A program wired with both channels; tests that ignore one drop its receiver.
    fn program() -> (
        AyaCaptureProgram,
        mpsc::Receiver<CapturedLine>,
        mpsc::Receiver<CapturedFlow>,
        mpsc::Receiver<CapturedSegment>,
    ) {
        let (tx, rx) = mpsc::channel(256);
        let (flow_tx, flow_rx) = mpsc::channel(256);
        let (l7_tx, l7_rx) = mpsc::channel(256);
        (
            AyaCaptureProgram::new(tx, flow_tx, l7_tx),
            rx,
            flow_rx,
            l7_rx,
        )
    }

    /// End-to-end L7 capture: a targeted PID does a real HTTP request/response
    /// over a socket; the captured bytes reassemble + parse into a span. Exercises
    /// the read+write tracepoints, the verifier accepting the L7 programs, the
    /// `L7_EVENTS` ring, and the userspace parser end to end. Requires CAP_BPF +
    /// python3.
    #[tokio::test]
    #[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
    async fn captures_a_targeted_l7_request() {
        use super::super::l7::ConnRegistry;

        let (mut program, _rx, _flow_rx, mut l7_rx) = program();
        program
            .start(&enabled_section())
            .expect("load + attach capture programs (incl. L7) from the embedded object");

        // A process acting as an HTTP server over a socketpair: it recv()s a
        // request and send()s a response. The other end injects the request and
        // reads the response — those land on a different fd whose stream the parser
        // drops (a request parsed as a response is invalid), so only the server
        // fd yields a record.
        let script = "\
import socket, time
time.sleep(1)
a, b = socket.socketpair()
a.sendall(b'GET /l7test HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')
b.recv(4096)
b.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n')
a.recv(4096)
";
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .spawn()
            .expect("spawn python3 http exchange");
        let pid = child.id();

        program
            .set_target_pids(&routing_for(pid))
            .expect("seed TARGET_PIDS with the child PID");

        // Feed captured segments into the reassembler until the request/response
        // round-trip parses into the expected record (or we time out). Other fds
        // (the client side, and fds reused from earlier file reads) yield no
        // matching record, so we filter by operation rather than taking the first.
        let mut conns = ConnRegistry::new();
        let record = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let seg = l7_rx.recv().await.expect("L7 channel closed");
                if let Some(rec) = conns
                    .on_segment(&seg)
                    .into_iter()
                    .find(|r| r.operation == "GET /l7test")
                {
                    return rec;
                }
            }
        })
        .await
        .expect("timed out waiting for the parsed L7 record");

        assert_eq!(record.status_code, 200);
        assert!(!record.error);

        let _ = child.wait();
    }

    /// End-to-end TLS capture: a targeted PID does an HTTPS exchange over OpenSSL;
    /// the SSL_read/SSL_write uprobes recover the plaintext, which reassembles +
    /// parses into a span — proving we see inside encryption. Requires CAP_BPF +
    /// python3 + openssl.
    #[tokio::test]
    #[ignore = "requires CAP_BPF/root + python3 + openssl; run under sudo on the ebpf-spike VM"]
    async fn captures_a_targeted_tls_request() {
        use super::super::l7::ConnRegistry;

        let (mut program, _rx, _flow_rx, mut l7_rx) = program();
        program
            .start(&enabled_section())
            .expect("load + attach capture programs (incl. TLS uprobes)");

        // One process acting as both TLS server + client over a socketpair (both
        // OpenSSL-wrapped). The server side SSL_read's the request and SSL_write's
        // the response — the uprobes tap that plaintext before/after encryption.
        let script = r#"
import socket, ssl, threading, subprocess, tempfile, os, time
d = tempfile.mkdtemp()
cert = os.path.join(d, 'c.pem'); key = os.path.join(d, 'k.pem')
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-keyout',key,'-out',cert,
                '-days','1','-nodes','-subj','/CN=localhost'], check=True, capture_output=True)
time.sleep(1)
c, s = socket.socketpair()
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(cert, key)
cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.load_verify_locations(cert)
def server():
    ss = sctx.wrap_socket(s, server_side=True)
    ss.recv(4096)
    ss.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    time.sleep(0.5)
t = threading.Thread(target=server); t.start()
cs = cctx.wrap_socket(c, server_side=False, server_hostname='localhost')
cs.sendall(b'GET /tls HTTP/1.1\r\nHost: x\r\n\r\n')
cs.recv(4096)
t.join()
"#;
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .spawn()
            .expect("spawn python3 TLS exchange");
        let pid = child.id();

        program
            .set_target_pids(&routing_for(pid))
            .expect("seed TARGET_PIDS with the child PID");

        // The server side's SSL* stream reassembles the decrypted request +
        // response into a record; the client SSL* stream and the raw ciphertext
        // fds yield no "GET /tls" match.
        let mut conns = ConnRegistry::new();
        let record = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let seg = l7_rx.recv().await.expect("L7 channel closed");
                if let Some(rec) = conns
                    .on_segment(&seg)
                    .into_iter()
                    .find(|r| r.operation == "GET /tls")
                {
                    return rec;
                }
            }
        })
        .await
        .expect("timed out waiting for the decrypted TLS L7 record");

        assert_eq!(record.status_code, 200);
        assert!(!record.error);

        let _ = child.wait();
    }

    /// End-to-end validation on real hardware: the embedded `.o` loads, the verifier
    /// accepts the programs, attach succeeds, the target PID seeds, and a real
    /// `write(2)` from that PID is drained as a `CapturedLine`. Requires CAP_BPF.
    #[tokio::test]
    #[ignore = "requires CAP_BPF/root; run under sudo on the ebpf-spike VM"]
    async fn captures_a_targeted_write() {
        let (mut program, mut rx, _flow_rx, _l7_rx) = program();
        program
            .start(&enabled_section())
            .expect("load + attach capture programs from the embedded object");

        let marker = "EDGEPACER_INAGENT_CAPTURE_OK";
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 1; printf '%s\\n' '{marker}'"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn marker child");
        let pid = child.id();

        program
            .set_target_pids(&routing_for(pid))
            .expect("seed TARGET_PIDS with the child PID");

        let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for a captured write")
            .expect("capture channel closed");

        assert_eq!(line.pid, pid, "captured the targeted PID's write");
        assert!(
            String::from_utf8_lossy(&line.bytes).contains(marker),
            "captured bytes contain the marker: {:?}",
            String::from_utf8_lossy(&line.bytes)
        );

        let _ = child.wait();
        program.stop();
    }

    /// Same validation via `writev(2)` (python3's `os.writev`), exercising the
    /// `capture_writev` tracepoint that closes the writev gap (decision 5).
    #[tokio::test]
    #[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
    async fn captures_a_targeted_writev() {
        let (mut program, mut rx, _flow_rx, _l7_rx) = program();
        program
            .start(&enabled_section())
            .expect("load + attach capture programs from the embedded object");

        let marker = "EDGEPACER_WRITEV_OK";
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "import os,time; time.sleep(1); os.writev(1, [b'{marker}\\n'])"
            ))
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn writev child (python3)");
        let pid = child.id();

        program
            .set_target_pids(&routing_for(pid))
            .expect("seed TARGET_PIDS with the child PID");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let line = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("timed out waiting for a captured writev")
                .expect("capture channel closed");
            if line.pid == pid && String::from_utf8_lossy(&line.bytes).contains(marker) {
                break;
            }
        }

        let _ = child.wait();
        program.stop();
    }

    /// Proves the `CONNECT_EVENTS` drain: a targeted child's outbound `connect(2)`
    /// is captured as a `CapturedFlow`. The connect to a refused local port still
    /// fires `sys_enter_connect`. Requires CAP_BPF + python3 on the VM.
    #[tokio::test]
    #[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
    async fn captures_a_targeted_connect() {
        let (mut program, _rx, mut flow_rx, _l7_rx) = program();
        program
            .start(&enabled_section())
            .expect("load + attach capture programs (incl. connect)");

        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg("import socket,time; time.sleep(1); socket.socket().connect(('127.0.0.1', 9999))")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn connect child (python3)");
        let pid = child.id();

        program
            .set_target_pids(&routing_for(pid))
            .expect("seed TARGET_PIDS with the child PID");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let flow = loop {
            let flow = tokio::time::timeout_at(deadline, flow_rx.recv())
                .await
                .expect("timed out waiting for a captured connect")
                .expect("flow channel closed");
            if flow.pid == pid {
                break flow;
            }
        };

        assert_eq!(flow.daddr, [127, 0, 0, 1], "captured destination IPv4");
        assert_eq!(flow.dport, 9999, "captured destination port");

        let _ = child.wait();
        program.stop();
    }
}
