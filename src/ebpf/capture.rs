//! Aya-backed [`CaptureProgram`] + the ring drains — the single boundary between
//! the manager and the kernel. Loads the embedded BPF object, attaches the
//! capture tracepoints, mirrors the resolved [`PidRouting`] into the kernel
//! `TARGET_PIDS` filter, and forwards captured write payloads as [`CapturedLine`]s
//! and (when network flows are enabled) outbound connects as [`CapturedFlow`]s
//! over mpsc channels the runner routes by PID → service.
//!
//! Linux + `ebpf` only (it links aya). The reconcile orchestration that drives
//! it lives in `manager.rs` and is tested on every platform via a fake.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::{TracePoint, UProbe};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use edgepacer_ebpf_common::{
    CHUNK_LEN, ConnectEvent, L7_CHUNK_LEN, L7_DIR_INBOUND, L7Chunk, ListenerEvent, LogChunk,
    TlsChunk,
};

use super::l7::{CapturedSegment, Direction};
use super::manager::{CaptureProgram, ListenerObservation};
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
const CAPTURE_LISTEN: (&str, &str, &str) = ("capture_listen", "sock", "inet_sock_set_state");
const CAPTURE_LISTEN_EXIT: (&str, &str, &str) =
    ("capture_listen_exit", "syscalls", "sys_exit_listen");

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
    pub cgroup_id: u64,
    pub fd: u32,
    pub bytes: Vec<u8>,
}

/// One captured outbound `connect(2)` (network-flow signal), routed by `pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFlow {
    pub pid: u32,
    pub cgroup_id: u64,
    pub daddr: [u8; 4],
    pub dport: u16,
    pub family: u16,
}

/// One successful TCP listener transition — the event-driven port→cgroup
/// discovery signal. Userspace combines these live events with an authoritative
/// snapshot before using listener ownership for capture scoping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedListener {
    pub cgroup_id: u64,
    pub observed_at_ns: u64,
    pub tgid: u32,
    pub port: u16,
    pub family: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListenerDrainHealth {
    pub generation: u64,
    pub running: bool,
}

impl ListenerDrainHealth {
    pub const fn stopped() -> Self {
        Self {
            generation: 0,
            running: false,
        }
    }
}

const MAX_OUT_OF_ORDER_LISTENER_SEQUENCES: usize = 16_384;
const MAX_LISTENER_SEQUENCE_CPUS: usize = 4_096;

/// Live aya state held while capture is loaded.
struct Loaded {
    // Held for its `Drop`: dropping the `Ebpf` detaches every attached program.
    #[allow(dead_code)]
    ebpf: Ebpf,
    target_pids: AyaHashMap<MapData, u32, u8>,
    listener_drops: PerCpuArray<MapData, u64>,
    listener_published: PerCpuArray<MapData, u64>,
    listener_generation: u64,
    listener_fence_tx: mpsc::Sender<ListenerFence>,
    /// PIDs currently written into the kernel filter, to diff on the next refresh.
    seeded: HashSet<u32>,
    /// Cleared if the mandatory listener drain exits after start-up.
    listener_drain_running: Arc<AtomicBool>,
    /// Active ring drains, all sharing the same stop lifecycle.
    drains: Vec<JoinHandle<()>>,
}

struct ListenerFence {
    published_counts: Vec<u64>,
    ack: oneshot::Sender<Result<(), String>>,
}

#[derive(Default)]
struct PerCpuListenerSequence {
    contiguous: u64,
    out_of_order: BTreeSet<u64>,
}

#[derive(Default)]
struct ListenerSequences {
    by_cpu: HashMap<u32, PerCpuListenerSequence>,
    outstanding: usize,
}

struct ListenerDrainGuard {
    running: Arc<AtomicBool>,
    health_tx: watch::Sender<ListenerDrainHealth>,
    generation: u64,
}

impl Drop for ListenerDrainGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        self.health_tx.send_if_modified(|health| {
            if health.generation != self.generation {
                return false;
            }
            health.running = false;
            true
        });
    }
}

/// Loads the embedded BPF object, drives the kernel `TARGET_PIDS` filter, drains
/// `LOG_EVENTS` into `captured_tx`, and (when network flows are enabled)
/// `CONNECT_EVENTS` into `flow_tx`.
pub struct AyaCaptureProgram {
    captured_tx: mpsc::Sender<CapturedLine>,
    flow_tx: mpsc::Sender<CapturedFlow>,
    l7_tx: mpsc::Sender<CapturedSegment>,
    listener_tx: mpsc::Sender<CapturedListener>,
    listener_health_tx: watch::Sender<ListenerDrainHealth>,
    next_listener_generation: u64,
    loaded: Option<Loaded>,
}

impl AyaCaptureProgram {
    pub fn new(
        captured_tx: mpsc::Sender<CapturedLine>,
        flow_tx: mpsc::Sender<CapturedFlow>,
        l7_tx: mpsc::Sender<CapturedSegment>,
        listener_tx: mpsc::Sender<CapturedListener>,
        listener_health_tx: watch::Sender<ListenerDrainHealth>,
    ) -> Self {
        Self {
            captured_tx,
            flow_tx,
            l7_tx,
            listener_tx,
            listener_health_tx,
            next_listener_generation: 0,
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

        // Port→cgroup discovery: always on when capture is enabled — it feeds
        // target resolution (which cgroup owns a directive's port), so it must
        // run independently of the network-flows toggle.
        // Attach the exit side first. If a listen races the attach window, an
        // exit without a staged candidate is harmless; the reverse order can
        // strand a candidate forever and eventually fill the bounded map.
        attach_tracepoint(&mut ebpf, CAPTURE_LISTEN_EXIT)?;
        attach_tracepoint(&mut ebpf, CAPTURE_LISTEN)?;
        let listener_events = ebpf
            .take_map("LISTENER_EVENTS")
            .ok_or("BPF map LISTENER_EVENTS not found")?;
        let listener_ring = RingBuf::try_from(listener_events)
            .map_err(|e| format!("open LISTENER_EVENTS ring: {e}"))?;
        let listener_drops = ebpf
            .take_map("LISTENER_DROPS")
            .ok_or("BPF map LISTENER_DROPS not found")?;
        let listener_drops = PerCpuArray::try_from(listener_drops)
            .map_err(|e| format!("open LISTENER_DROPS map: {e}"))?;
        let listener_published = ebpf
            .take_map("LISTENER_PUBLISHED")
            .ok_or("BPF map LISTENER_PUBLISHED not found")?;
        let listener_published = PerCpuArray::try_from(listener_published)
            .map_err(|e| format!("open LISTENER_PUBLISHED map: {e}"))?;

        // Network flows are an independent sub-toggle: attach + open only then.
        let flow_ring = if section.network_flows_enabled {
            attach_tracepoint(&mut ebpf, CAPTURE_CONNECT)?;
            let connect_events = ebpf
                .take_map("CONNECT_EVENTS")
                .ok_or("BPF map CONNECT_EVENTS not found")?;
            Some(
                RingBuf::try_from(connect_events)
                    .map_err(|e| format!("open CONNECT_EVENTS ring: {e}"))?,
            )
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

        // TLS plaintext capture: SSL_read/SSL_write uprobes on OpenSSL recover the
        // protocol bytes on encrypted connections. Best-effort — if libssl can't be
        // resolved (static OpenSSL, or non-OpenSSL TLS like Go/Java), skip without
        // failing the whole capture. Plaintext drains into the same L7 pipeline.
        let tls_ring = match attach_tls_uprobes(&mut ebpf) {
            Ok(()) => {
                let tls_events = ebpf
                    .take_map("TLS_EVENTS")
                    .ok_or("BPF map TLS_EVENTS not found")?;
                Some(
                    RingBuf::try_from(tls_events)
                        .map_err(|e| format!("open TLS_EVENTS ring: {e}"))?,
                )
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

        // Start drains only after every required program and map is ready. If a
        // later attach/open fails, returning here must not leave orphan tasks
        // polling rings that `self.loaded` never took ownership of.
        let listener_drain_running = Arc::new(AtomicBool::new(false));
        self.next_listener_generation = self.next_listener_generation.wrapping_add(1).max(1);
        let listener_generation = self.next_listener_generation;
        let (listener_fence_tx, listener_fence_rx) = mpsc::channel(4);
        let listener_drain = spawn_listener_drain(
            listener_ring,
            self.listener_tx.clone(),
            Arc::clone(&listener_drain_running),
            self.listener_health_tx.clone(),
            listener_generation,
            listener_fence_rx,
        )?;
        let mut drains = Vec::with_capacity(5);
        drains.push(spawn_drain(ring, self.captured_tx.clone()));
        drains.push(listener_drain);
        if let Some(ring) = flow_ring {
            drains.push(spawn_flow_drain(ring, self.flow_tx.clone()));
        }
        drains.push(spawn_l7_drain(l7_ring, self.l7_tx.clone()));
        if let Some(ring) = tls_ring {
            drains.push(spawn_tls_drain(ring, self.l7_tx.clone()));
        }

        self.loaded = Some(Loaded {
            ebpf,
            target_pids,
            listener_drops,
            listener_published,
            listener_generation,
            listener_fence_tx,
            seeded: HashSet::new(),
            listener_drain_running,
            drains,
        });
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(loaded) = self.loaded.take() {
            for drain in &loaded.drains {
                drain.abort();
            }
            // Dropping `loaded` drops the `Ebpf` (detaches programs) and the rings.
        }
    }

    fn set_target_pids(&mut self, routing: &PidRouting) -> Result<(), String> {
        let Some(loaded) = self.loaded.as_mut() else {
            return Err("set_target_pids called while capture is stopped".to_string());
        };
        ensure_listener_drain_running(&loaded.listener_drain_running)?;

        let desired: HashSet<u32> = routing.target_pids().collect();
        let to_add: Vec<u32> = desired.difference(&loaded.seeded).copied().collect();
        let to_remove: Vec<u32> = loaded.seeded.difference(&desired).copied().collect();

        // Remove stale scope before adding new scope. If either syscall fails,
        // the manager unloads the whole program; ordering therefore minimizes
        // the interval in which a superseded PID could still be captured.
        for pid in to_remove {
            match loaded.target_pids.remove(&pid) {
                Ok(()) | Err(MapError::KeyNotFound) => {}
                Err(error) => return Err(format!("remove pid {pid}: {error}")),
            }
        }
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
        loaded.seeded = desired;
        Ok(())
    }

    fn listener_observation(&self) -> Result<ListenerObservation, String> {
        let loaded = self
            .loaded
            .as_ref()
            .ok_or_else(|| "listener observation requested while capture is stopped".to_string())?;
        ensure_listener_drain_running(&loaded.listener_drain_running)?;
        let drop_counts = loaded
            .listener_drops
            .get(&0, 0)
            .map_err(|error| format!("read LISTENER_DROPS: {error}"))?
            .iter()
            .copied()
            .collect();
        let published_counts = loaded
            .listener_published
            .get(&0, 0)
            .map_err(|error| format!("read LISTENER_PUBLISHED: {error}"))?
            .iter()
            .copied()
            .collect();
        Ok(ListenerObservation {
            generation: loaded.listener_generation,
            drop_counts,
            published_counts,
        })
    }

    fn listener_fence(
        &self,
        published_counts: Vec<u64>,
    ) -> Result<oneshot::Receiver<Result<(), String>>, String> {
        let loaded = self
            .loaded
            .as_ref()
            .ok_or_else(|| "listener fence requested while capture is stopped".to_string())?;
        ensure_listener_drain_running(&loaded.listener_drain_running)?;
        let (ack, receiver) = oneshot::channel();
        loaded
            .listener_fence_tx
            .try_send(ListenerFence {
                published_counts,
                ack,
            })
            .map_err(|error| format!("request listener drain fence: {error}"))?;
        Ok(receiver)
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
                    cgroup_id: chunk.cgroup_id,
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
                    cgroup_id: ev.cgroup_id,
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

/// Poll the `LISTENER_EVENTS` ring async, decode each `ListenerEvent`, and
/// forward a `CapturedListener` (port→cgroup discovery). Exits when the consumer drops the
/// channel or the task is aborted (on `stop()`).
fn spawn_listener_drain(
    ring: RingBuf<MapData>,
    tx: mpsc::Sender<CapturedListener>,
    running: Arc<AtomicBool>,
    health_tx: watch::Sender<ListenerDrainHealth>,
    generation: u64,
    mut fence_rx: mpsc::Receiver<ListenerFence>,
) -> Result<JoinHandle<()>, String> {
    let mut async_fd =
        AsyncFd::new(ring).map_err(|e| format!("cannot poll LISTENER_EVENTS ring: {e}"))?;
    running.store(true, Ordering::Release);
    health_tx.send_replace(ListenerDrainHealth {
        generation,
        running: true,
    });
    let health_guard = ListenerDrainGuard {
        running,
        health_tx,
        generation,
    };

    Ok(tokio::spawn(async move {
        let _health_guard = health_guard;
        let mut sequences = ListenerSequences::default();
        let mut pending_fences = Vec::new();

        loop {
            tokio::select! {
                command = fence_rx.recv() => {
                    let Some(command) = command else {
                        return;
                    };
                    pending_fences.push(command);
                    acknowledge_listener_fences(&mut pending_fences, &sequences);
                }
                readiness = async_fd.readable_mut() => {
                    let mut guard = match readiness {
                        Ok(guard) => guard,
                        Err(e) => {
                            warn!(error = %e, "eBPF: LISTENER_EVENTS poll failed");
                            return;
                        }
                    };
                    let ring = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        let bytes: &[u8] = &item;
                        if bytes.len() < std::mem::size_of::<ListenerEvent>() {
                            continue;
                        }
                        // SAFETY: ListenerEvent is repr(C) POD written by the kernel.
                        let ev = unsafe {
                            std::ptr::read_unaligned(bytes.as_ptr() as *const ListenerEvent)
                        };
                        let listener = CapturedListener {
                            cgroup_id: ev.cgroup_id,
                            observed_at_ns: ev.observed_at_ns,
                            tgid: ev.tgid,
                            port: ev.port,
                            family: ev.family,
                        };
                        if tx.send(listener).await.is_err() {
                            return; // consumer gone
                        }
                        if let Err(error) = advance_listener_sequence(
                            &mut sequences,
                            ev.cpu_id,
                            ev.sequence,
                        ) {
                            warn!(%error, "eBPF: invalid LISTENER_EVENTS publication sequence");
                            return;
                        }
                        acknowledge_listener_fences(&mut pending_fences, &sequences);
                    }
                    guard.clear_ready();
                }
            }
        }
    }))
}

fn acknowledge_listener_fences(pending: &mut Vec<ListenerFence>, sequences: &ListenerSequences) {
    let mut index = 0;
    while index < pending.len() {
        let ready = pending[index]
            .published_counts
            .iter()
            .enumerate()
            .all(|(cpu_id, target)| {
                sequences
                    .by_cpu
                    .get(&(cpu_id as u32))
                    .map_or(0, |state| state.contiguous)
                    >= *target
            });
        if ready {
            let fence = pending.swap_remove(index);
            let _ = fence.ack.send(Ok(()));
        } else {
            index += 1;
        }
    }
}

fn advance_listener_sequence(
    sequences: &mut ListenerSequences,
    cpu_id: u32,
    sequence: u64,
) -> Result<(), String> {
    if !sequences.by_cpu.contains_key(&cpu_id)
        && sequences.by_cpu.len() >= MAX_LISTENER_SEQUENCE_CPUS
    {
        return Err(format!(
            "listener publication sequence referenced more than {MAX_LISTENER_SEQUENCE_CPUS} CPUs"
        ));
    }
    let state = sequences.by_cpu.entry(cpu_id).or_default();
    let next = state
        .contiguous
        .checked_add(1)
        .ok_or_else(|| "listener publication sequence overflowed".to_string())?;
    if sequence < next || !state.out_of_order.insert(sequence) {
        return Err(format!(
            "listener publication sequence {sequence} repeated on CPU {cpu_id} after {}",
            state.contiguous
        ));
    }
    sequences.outstanding = sequences
        .outstanding
        .checked_add(1)
        .ok_or_else(|| "listener publication gap count overflowed".to_string())?;
    while let Some(next) = state.contiguous.checked_add(1) {
        if !state.out_of_order.remove(&next) {
            break;
        }
        sequences.outstanding = sequences
            .outstanding
            .checked_sub(1)
            .ok_or_else(|| "listener publication gap count underflowed".to_string())?;
        state.contiguous = next;
    }
    if sequences.outstanding > MAX_OUT_OF_ORDER_LISTENER_SEQUENCES {
        return Err(format!(
            "listener publication sequence gaps exceeded {MAX_OUT_OF_ORDER_LISTENER_SEQUENCES} records"
        ));
    }
    Ok(())
}

fn ensure_listener_drain_running(running: &AtomicBool) -> Result<(), String> {
    if running.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err("LISTENER_EVENTS drain stopped after capture start".to_string())
    }
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
                    cgroup_id: chunk.cgroup_id,
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
                    cgroup_id: chunk.cgroup_id,
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
        match program.attach(Some(symbol), 0, target, None) {
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
    for (name, symbol) in TLS_PROBES {
        let Some(program) = ebpf.program_mut(name) else {
            continue;
        };
        let uprobe: &mut UProbe = match program.try_into() {
            Ok(uprobe) => uprobe,
            Err(_) => continue,
        };
        let _ = uprobe.attach(Some(symbol), 0, lib, Some(pid));
    }
}

#[cfg(test)]
mod tests;
