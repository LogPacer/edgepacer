//! eBPF manager run loop — mirrors `trace_proxy_manager::run`, but eBPF capture
//! is one kernel program serving many PIDs. It reconciles the singleton kernel
//! lifecycle on the section `config_hash`, refreshes the kernel `TARGET_PIDS`
//! filter from the ports census each tick, owns one durable
//! `StreamingDeliveryPipeline` per target for captured log lines, and routes
//! captured connects to that target's repo as `WireEbpfBatch` (the ebpf arm).
//!
//! Delivery is owned here, not modelled as a `StreamAccessMethod::Ebpf` streaming
//! source: one program serves many services, which the per-source streaming model
//! cannot route (decision 124). Log lines ride the durable pipeline (logs arm);
//! network flows are batched per tick and shipped best-effort (the ebpf arm) —
//! durable flow buffering is a refinement.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use logpacer_wire::{NetworkFlow, RequestSignal};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::SharedEbpfStatus;
use super::capture::{
    AyaCaptureProgram, CapturedFlow, CapturedLine, CapturedListener, ListenerDrainHealth,
};
use super::l7::{
    CapturedSegment, ConnRegistry, RedAggregator, SpanContext, mint_id, to_request_signal,
};
use super::listener_snapshot;
use super::listener_state::{DeltaOutcome, ListenerAssociation, ListenerSnapshot, ListenerState};
use super::manager::EbpfManager;
use super::pid_resolver::PidRouting;
use super::socket_port;
use crate::config::{self, EbpfTargetConfig, SharedConfig};
use crate::discovery::SharedDiscoveryCache;
use crate::discovery::ports::discover_ports;
use crate::shipper::Shipper;
use crate::streaming_actor::{StreamHandle, spawn_streaming_actor};
use crate::streaming_pipeline::{StreamingDeliveryPipeline, StreamingPipelineConfig};

/// PID-filter refresh + delivery reconcile + flow-flush cadence.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// Upper bound for both authoritative and live listener ownership state.
const MAX_PORT_CGROUP_ASSOCIATIONS: usize = 16_384;
/// Live events accumulated while a blocking snapshot runs. Overflow makes the
/// snapshot unusable and clears readiness rather than applying a partial replay.
const MAX_BUFFERED_LISTENER_DELTAS: usize = 16_384;
/// Overall wall-clock bound for one blocking listener snapshot. Late worker
/// completion is discarded by generation after this timeout fails readiness.
const LISTENER_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(20);
/// A published-count fence should normally complete immediately; bound it so a
/// dead or wedged drain fails readiness instead of blocking the runner.
const LISTENER_DRAIN_FENCE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on in-flight captured records awaiting routing; backpressures the drain.
const CAPTURE_CHANNEL_DEPTH: usize = 256;
/// IPPROTO_TCP — connect(2) to an AF_INET endpoint (the capture's domain).
const IPPROTO_TCP: u32 = 6;
/// NetworkFlow.direction = egress (an outbound connect).
const DIRECTION_EGRESS: u32 = 1;

/// Per-target delivery: the durable log pipeline actor and a shipper for the
/// typed eBPF arm (network flows). Keyed by `log_source_id`.
struct TargetDelivery {
    /// Handle to the pipeline actor; dropping it tells the actor to flush
    /// and exit on its own.
    handle: StreamHandle,
    // Kept so dropping `TargetDelivery` detaches the actor task after it flushes.
    #[allow(dead_code)]
    actor: JoinHandle<()>,
    /// Ships `WireEbpfBatch` (flows) to this target's repo.
    flow_shipper: Arc<Shipper>,
    // Routing identity, to rebuild the pipeline when a target's repo changes.
    archive_id: String,
    repo_id: String,
    subbox_endpoint: String,
}

struct ListenerSnapshotResult {
    state_generation: u64,
    discovery_epoch: u64,
    capture_generation: u64,
    result: Result<ListenerSnapshot, String>,
}

struct SnapshotWorkerReservation(Arc<AtomicBool>);

impl Drop for SnapshotWorkerReservation {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn reserve_snapshot_worker(
    worker_running: Arc<AtomicBool>,
) -> Result<SnapshotWorkerReservation, String> {
    worker_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "listener snapshot worker is still running".to_string())?;
    Ok(SnapshotWorkerReservation(worker_running))
}

impl TargetDelivery {
    fn matches(&self, target: &EbpfTargetConfig) -> bool {
        self.archive_id == target.archive_id
            && self.repo_id == target.repo_id
            && self.subbox_endpoint == target.subbox_endpoint
    }

    /// Dropping the handle signals the actor to flush and exit; the detached
    /// task finishes on its own.
    fn stop(self) {}
}

pub async fn run(
    shared_config: SharedConfig,
    discovery_cache: SharedDiscoveryCache,
    status: SharedEbpfStatus,
    data_dir: &Path,
    identity: &crate::identity::AgentIdentity,
    mut shutdown: watch::Receiver<bool>,
) {
    let (captured_tx, mut captured_rx) = mpsc::channel::<CapturedLine>(CAPTURE_CHANNEL_DEPTH);
    let (flow_tx, mut flow_rx) = mpsc::channel::<CapturedFlow>(CAPTURE_CHANNEL_DEPTH);
    let (l7_tx, mut l7_rx) = mpsc::channel::<CapturedSegment>(CAPTURE_CHANNEL_DEPTH);
    let (listener_tx, mut listener_rx) = mpsc::channel::<CapturedListener>(CAPTURE_CHANNEL_DEPTH);
    let (listener_health_tx, mut listener_health_rx) =
        watch::channel(ListenerDrainHealth::stopped());
    let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<ListenerSnapshotResult>(1);
    let snapshot_worker_running = Arc::new(AtomicBool::new(false));
    let mut manager = EbpfManager::new(AyaCaptureProgram::new(
        captured_tx,
        flow_tx,
        l7_tx,
        listener_tx,
        listener_health_tx,
    ));
    // Routing seeded on the last reconcile, reused to route drained records.
    let mut routing = PidRouting::default();
    let mut deliveries: HashMap<String, TargetDelivery> = HashMap::new();
    // Flows accumulated since the last tick, keyed by service (log_source_id).
    let mut pending_flows: HashMap<String, Vec<NetworkFlow>> = HashMap::new();
    // L7 (APM): per-connection reassembly → spans + RED, accumulated per service
    // and flushed each tick (best-effort, like flows). `span_seq` seeds spanlet id
    // minting; cgroup enrichment, durable buffering, and real trace ids (vs. v1
    // spanlets) are refinements.
    let mut l7_conns = ConnRegistry::new();
    let mut pending_spans: HashMap<String, Vec<RequestSignal>> = HashMap::new();
    let mut l7_red = RedAggregator::new();
    let mut span_seq: u64 = 0;
    // Per-(pid, fd) port→protocol hint, resolved once via /proc and cached so the
    // binary parsers bind by port instead of their weak byte signatures.
    let mut port_hints: HashMap<(u32, u32), Option<socket_port::ResolvedConn>> = HashMap::new();
    // Event deltas are usable only after an authoritative snapshot has supplied
    // cold-start state. Periodic replacement snapshots garbage-collect closes.
    let mut listener_state = ListenerState::default();
    let mut listener_config_hash: Option<String> = None;
    let mut active_listener_generation: Option<u64> = None;
    let mut reconcile_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + RECONCILE_INTERVAL,
        RECONCILE_INTERVAL,
    );
    reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!("eBPF manager started");

    loop {
        tokio::select! {
            _ = reconcile_interval.tick() => {
                let section = {
                    let cfg = shared_config.read().await;
                    cfg.as_ref().and_then(config::ebpf_section)
                };

                // An absent `ebpf` section (older server) means "disabled" — tear down.
                let Some(section) = section else {
                    manager.shutdown();
                    routing = PidRouting::default();
                    stop_all_deliveries(&mut deliveries);
                    pending_flows.clear();
                    pending_spans.clear();
                    l7_red = RedAggregator::new();
                    l7_conns = ConnRegistry::new();
                    port_hints.clear();
                    listener_state.reset();
                    listener_config_hash = None;
                    active_listener_generation = None;
                    let mut guard = status.write().await;
                    guard.running = false;
                    guard.last_error = None;
                    guard.pids_targeted = 0;
                    continue;
                };

                // Discovery failure must not preserve ownership authorized by
                // a disabled or superseded configuration. The kernel allow-set
                // slice consumes this state, so invalidate it before the
                // fallible PID census rather than after a successful reconcile.
                if !section.enabled
                    || listener_config_hash
                        .as_deref()
                        .is_some_and(|hash| hash != section.config_hash)
                {
                    listener_state.reset();
                    listener_config_hash = None;
                }

                let census = if section.enabled {
                    match discover_ports().await {
                        Ok(census) => census,
                        Err(e) => {
                            // A stale PID filter can capture a recycled process.
                            // Reconcile with no targets so a transient census
                            // failure loses coverage rather than scope.
                            warn!(error = %e, "eBPF: port census failed; clearing PID targets this tick");
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };

                let mut outcome = manager.reconcile(&section, &census);
                routing = outcome.routing;

                if outcome.running {
                    match manager.listener_observation() {
                        Ok(observation) => {
                            active_listener_generation = Some(observation.generation);
                        }
                        Err(error) => {
                            manager.shutdown();
                            routing = PidRouting::default();
                            outcome.running = false;
                            outcome.last_error = Some(error);
                            outcome.routing = PidRouting::default();
                            active_listener_generation = None;
                        }
                    }
                } else {
                    active_listener_generation = None;
                }

                if outcome.running && section.enabled {
                    if listener_config_hash.as_deref() != Some(section.config_hash.as_str()) {
                        listener_state.reset();
                        listener_config_hash = Some(section.config_hash.clone());
                    }
                    if !listener_state.snapshot_in_flight()
                        && !snapshot_worker_running.load(Ordering::Acquire)
                    {
                        let start_result = start_listener_snapshot(
                            &mut listener_state,
                            &manager,
                            discovery_cache.clone(),
                            snapshot_tx.clone(),
                            Arc::clone(&snapshot_worker_running),
                        )
                        .await;
                        if let Err(error) = start_result {
                            listener_state.reset();
                            warn!(%error, "eBPF: listener snapshot could not start; ownership is not ready");
                        }
                    }
                } else {
                    listener_state.reset();
                    listener_config_hash = None;
                    active_listener_generation = None;
                }

                // Delivery pipelines track configured targets (independent of the
                // kernel program's transient running state, so a hiccup never
                // discards buffered-but-undelivered lines).
                if section.enabled {
                    reconcile_deliveries(&mut deliveries, &section.targets, data_dir, identity);
                } else {
                    stop_all_deliveries(&mut deliveries);
                }

                flush_flows(&mut pending_flows, &deliveries);
                flush_spans(&mut pending_spans, &deliveries);
                flush_red(&mut l7_red, &deliveries);

                let mut guard = status.write().await;
                guard.running = outcome.running;
                guard.last_error = outcome.last_error;
                guard.pids_targeted = routing.len();
            }

            Some(line) = captured_rx.recv() => {
                let Some(service) = routing.service_for(line.pid) else {
                    continue; // PID no longer targeted (raced with removal)
                };
                let Some(delivery) = deliveries.get(service) else {
                    continue; // no pipeline yet for this service
                };
                // try_enqueue: the eBPF capture loop must never stall behind
                // a slow pipeline — drop with a warning instead.
                if !delivery.handle.try_enqueue(line.bytes, now_ns()) {
                    warn!(service, "eBPF: delivery channel full; dropping captured line");
                }
            }

            Some(flow) = flow_rx.recv() => {
                if let Some(service) = routing.service_for(flow.pid) {
                    pending_flows
                        .entry(service.to_string())
                        .or_default()
                        .push(to_network_flow(&flow));
                }
            }

            Some(listener) = listener_rx.recv() => {
                record_listener_delta(&mut listener_state, listener);
            }

            Some(snapshot_result) = snapshot_rx.recv() => {
                let ListenerSnapshotResult {
                    state_generation,
                    discovery_epoch,
                    capture_generation,
                    result,
                } = snapshot_result;
                if !listener_state.snapshot_is_current(state_generation) {
                    debug!(generation = state_generation, "eBPF: ignored stale listener snapshot result");
                    continue;
                }
                match result {
                    Ok(snapshot) => {
                        let cache_verification = {
                            let cache = discovery_cache.read().await;
                            cache.verify_complete_container_epoch(discovery_epoch)
                        };
                        if let Err(error) = cache_verification {
                            listener_state.fail_snapshot(state_generation);
                            warn!(%error, "eBPF: container inventory changed during listener snapshot; ownership is not ready");
                            continue;
                        }

                        let observation = match manager.listener_observation() {
                            Ok(observation) => observation,
                            Err(error) => {
                                fail_listener_capture(
                                    &mut manager,
                                    &mut routing,
                                    &mut listener_state,
                                    &mut listener_config_hash,
                                    &mut active_listener_generation,
                                    &status,
                                    error,
                                )
                                .await;
                                continue;
                            }
                        };
                        if observation.generation != capture_generation {
                            listener_state.fail_snapshot(state_generation);
                            listener_config_hash = None;
                            warn!(
                                before = capture_generation,
                                after = observation.generation,
                                "eBPF: listener capture restarted during snapshot; ownership is not ready"
                            );
                            continue;
                        }

                        let fence = match manager.listener_fence(observation.published_counts) {
                            Ok(fence) => fence,
                            Err(error) => {
                                fail_listener_capture(
                                    &mut manager,
                                    &mut routing,
                                    &mut listener_state,
                                    &mut listener_config_hash,
                                    &mut active_listener_generation,
                                    &status,
                                    error,
                                )
                                .await;
                                continue;
                            }
                        };
                        let fence_result = tokio::time::timeout(
                            LISTENER_DRAIN_FENCE_TIMEOUT,
                            drain_listener_until_fence(
                                fence,
                                &mut listener_rx,
                                &mut listener_state,
                            ),
                        )
                        .await
                        .map_err(|_| {
                            format!(
                                "listener drain fence timed out after {LISTENER_DRAIN_FENCE_TIMEOUT:?}"
                            )
                        })
                        .and_then(|result| result);
                        if let Err(error) = fence_result {
                            fail_listener_capture(
                                &mut manager,
                                &mut routing,
                                &mut listener_state,
                                &mut listener_config_hash,
                                &mut active_listener_generation,
                                &status,
                                error,
                            )
                            .await;
                            continue;
                        }

                        let observation = match manager.listener_observation() {
                            Ok(observation) => observation,
                            Err(error) => {
                                fail_listener_capture(
                                    &mut manager,
                                    &mut routing,
                                    &mut listener_state,
                                    &mut listener_config_hash,
                                    &mut active_listener_generation,
                                    &status,
                                    error,
                                )
                                .await;
                                continue;
                            }
                        };
                        if observation.generation != capture_generation {
                            listener_state.fail_snapshot(state_generation);
                            listener_config_hash = None;
                            warn!(
                                before = capture_generation,
                                after = observation.generation,
                                "eBPF: listener capture restarted during drain fence; ownership is not ready"
                            );
                            continue;
                        }

                        // Hold the read lock through application so a discovery
                        // writer cannot advance the revalidated epoch in the
                        // final check→commit gap.
                        let cache = discovery_cache.read().await;
                        if let Err(error) = cache.verify_complete_container_epoch(discovery_epoch) {
                            listener_state.fail_snapshot(state_generation);
                            warn!(%error, "eBPF: container inventory changed during listener drain fence; ownership is not ready");
                            continue;
                        }
                        match listener_state.apply_snapshot_with_loss(
                            state_generation,
                            snapshot,
                            observation.drop_counts,
                            MAX_PORT_CGROUP_ASSOCIATIONS,
                        ) {
                            Ok(true) => {
                                debug_assert!(listener_state.is_ready());
                                debug!(
                                    associations = listener_state.association_count(),
                                    "eBPF: listener ownership snapshot ready"
                                );
                            }
                            Ok(false) => {
                                debug!(generation = state_generation, "eBPF: ignored stale listener snapshot result");
                            }
                            Err(error) => {
                                warn!(%error, "eBPF: listener snapshot replay failed; ownership is not ready");
                            }
                        }
                    }
                    Err(error) => {
                        if listener_state.fail_snapshot(state_generation) {
                            warn!(%error, "eBPF: authoritative listener snapshot failed; ownership is not ready");
                        } else {
                            debug!(generation = state_generation, %error, "eBPF: ignored stale listener snapshot failure");
                        }
                    }
                }
            }

            changed = listener_health_rx.changed() => {
                let health = *listener_health_rx.borrow_and_update();
                if changed.is_ok()
                    && listener_health_failed(health, active_listener_generation)
                    && listener_config_hash.is_some()
                {
                    let error = "mandatory listener drain stopped after capture start".to_string();
                    manager.shutdown();
                    routing = PidRouting::default();
                    listener_state.reset();
                    listener_config_hash = None;
                    active_listener_generation = None;
                    let mut guard = status.write().await;
                    guard.running = false;
                    guard.last_error = Some(error.clone());
                    guard.pids_targeted = 0;
                    warn!(%error, "eBPF: capture unloaded after listener drain failure");
                }
            }

            Some(seg) = l7_rx.recv() => {
                let pid = seg.pid;
                let ts = seg.timestamp_nano;
                // Resolve the connection's protocol from its port once (cached). TLS
                // segments carry an SSL*-derived fd that won't resolve → None, so
                // they fall back to byte detection (fine for HTTP-in-TLS).
                let resolved = port_hints
                    .entry((pid, seg.fd))
                    .or_insert_with(|| socket_port::resolve(pid, seg.fd));
                let (proto, flip) = match resolved.as_ref().and_then(|r| r.hint) {
                    Some(h) => (Some(h.protocol), h.client),
                    None => (None, false),
                };
                // The connection's peer endpoint — the service-map edge's other node.
                let peer = resolved.as_ref().map(|r| r.peer.clone());
                for record in l7_conns.on_segment_hinted(&seg, proto, flip) {
                    let Some(service) = routing.service_for(pid) else {
                        continue; // PID no longer targeted (raced with removal)
                    };
                    l7_red.observe(service, &record);
                    span_seq = span_seq.wrapping_add(1);
                    let ctx = SpanContext {
                        service_name: service.to_string(),
                        pid,
                        cgroup_id: seg.cgroup_id,
                        trace_id: mint_id(16, span_seq ^ ((pid as u64) << 32) ^ ts as u64),
                        span_id: mint_id(8, span_seq.wrapping_mul(0x100_0000_01b3) ^ pid as u64),
                        peer: peer.clone(),
                    };
                    pending_spans
                        .entry(service.to_string())
                        .or_default()
                        .push(to_request_signal(&record, &ctx));
                }
            }

            _ = shutdown.changed() => {
                manager.shutdown();
                stop_all_deliveries(&mut deliveries);
                info!("eBPF manager stopped");
                return;
            }
        }
    }
}

fn record_listener_delta(state: &mut ListenerState, listener: CapturedListener) {
    let association = ListenerAssociation {
        family: listener.family,
        port: listener.port,
        cgroup_id: listener.cgroup_id,
    };
    match state.record_delta(
        association,
        listener.observed_at_ns,
        MAX_PORT_CGROUP_ASSOCIATIONS,
        MAX_BUFFERED_LISTENER_DELTAS,
    ) {
        DeltaOutcome::Inserted => {
            debug!(
                port = listener.port,
                family = listener.family,
                cgroup_id = listener.cgroup_id,
                tgid = listener.tgid,
                "eBPF: discovered listener (port→cgroup)"
            );
        }
        DeltaOutcome::IgnoredInvalid => {
            warn!(
                port = listener.port,
                family = listener.family,
                cgroup_id = listener.cgroup_id,
                tgid = listener.tgid,
                "eBPF: ignored invalid listener ownership delta"
            );
        }
        DeltaOutcome::AtCapacity { should_warn: true } => {
            warn!(
                limit = MAX_PORT_CGROUP_ASSOCIATIONS,
                "eBPF: listener ownership capacity reached; dropping new associations until the next snapshot"
            );
        }
        DeltaOutcome::BufferAtCapacity { should_warn: true } => {
            warn!(
                limit = MAX_BUFFERED_LISTENER_DELTAS,
                "eBPF: listener snapshot replay capacity reached; snapshot will fail closed"
            );
        }
        DeltaOutcome::AlreadyPresent
        | DeltaOutcome::Buffered
        | DeltaOutcome::IgnoredBeforeCut
        | DeltaOutcome::AtCapacity { should_warn: false }
        | DeltaOutcome::BufferAtCapacity { should_warn: false } => {}
    }
}

async fn drain_listener_until_fence(
    mut fence: oneshot::Receiver<Result<(), String>>,
    listener_rx: &mut mpsc::Receiver<CapturedListener>,
    state: &mut ListenerState,
) -> Result<(), String> {
    loop {
        tokio::select! {
            result = &mut fence => {
                result
                    .map_err(|_| "listener drain stopped before fence acknowledgement".to_string())??;
                // The drain increments its consumed count only after sending
                // into this FIFO. Once the fence is acknowledged, every record
                // through the sampled publication count is therefore queued;
                // consume that queue synchronously before readiness can commit.
                let queued = listener_rx.len();
                for _ in 0..queued {
                    let Ok(listener) = listener_rx.try_recv() else {
                        break;
                    };
                    record_listener_delta(state, listener);
                }
                return Ok(());
            }
            listener = listener_rx.recv() => {
                let Some(listener) = listener else {
                    return Err("listener event channel closed before fence acknowledgement".to_string());
                };
                record_listener_delta(state, listener);
            }
        }
    }
}

async fn fail_listener_capture(
    manager: &mut EbpfManager<AyaCaptureProgram>,
    routing: &mut PidRouting,
    listener_state: &mut ListenerState,
    listener_config_hash: &mut Option<String>,
    active_listener_generation: &mut Option<u64>,
    status: &SharedEbpfStatus,
    error: String,
) {
    manager.shutdown();
    *routing = PidRouting::default();
    listener_state.reset();
    *listener_config_hash = None;
    *active_listener_generation = None;
    let mut guard = status.write().await;
    guard.running = false;
    guard.last_error = Some(error.clone());
    guard.pids_targeted = 0;
    warn!(%error, "eBPF: listener snapshot verification failed; capture unloaded");
}

async fn start_listener_snapshot(
    state: &mut ListenerState,
    manager: &EbpfManager<AyaCaptureProgram>,
    discovery_cache: SharedDiscoveryCache,
    tx: mpsc::Sender<ListenerSnapshotResult>,
    worker_running: Arc<AtomicBool>,
) -> Result<(), String> {
    let reservation = reserve_snapshot_worker(worker_running)?;

    let container_snapshot = {
        let cache = discovery_cache.read().await;
        cache.complete_container_snapshot()?
    };
    let observation = manager.listener_observation()?;
    let capture_generation = observation.generation;
    let cut_ns = monotonic_ns()?;
    let state_generation = state
        .begin_snapshot_with_loss(cut_ns, observation.drop_counts)
        .ok_or_else(|| "listener snapshot already running".to_string())?;
    let discovery_epoch = container_snapshot.epoch;
    let containers = container_snapshot.containers;
    let deadline = std::time::Instant::now() + LISTENER_SNAPSHOT_TIMEOUT;

    tokio::spawn(async move {
        let _reservation = reservation;
        let mut worker = tokio::task::spawn_blocking(move || {
            listener_snapshot::collect(&containers, deadline, MAX_PORT_CGROUP_ASSOCIATIONS)
        });
        let result = tokio::select! {
            result = &mut worker => Some(match result {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(error) => Err(format!("listener snapshot worker failed: {error}")),
            }),
            _ = tokio::time::sleep(LISTENER_SNAPSHOT_TIMEOUT) => None,
        };

        if let Some(result) = result {
            let _ = tx
                .send(ListenerSnapshotResult {
                    state_generation,
                    discovery_epoch,
                    capture_generation,
                    result,
                })
                .await;
        } else {
            let _ = tx
                .send(ListenerSnapshotResult {
                    state_generation,
                    discovery_epoch,
                    capture_generation,
                    result: Err(format!(
                        "listener snapshot timed out after {LISTENER_SNAPSHOT_TIMEOUT:?}"
                    )),
                })
                .await;
            // `spawn_blocking` cannot be cancelled once started. The collector
            // is deadline-aware, and this reservation deliberately stays held
            // until it exits so a timeout can never accumulate overlapping
            // workers.
            let _ = worker.await;
        }
    });
    Ok(())
}

fn listener_health_failed(health: ListenerDrainHealth, active_generation: Option<u64>) -> bool {
    !health.running && active_generation == Some(health.generation)
}

fn monotonic_ns() -> Result<u64, String> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `timestamp` points to writable storage for one `timespec`; the
    // kernel initializes it fully on success and does not retain the pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return Err(format!(
            "read CLOCK_MONOTONIC: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the successful call above initialized the complete value.
    let timestamp = unsafe { timestamp.assume_init() };
    let seconds = u64::try_from(timestamp.tv_sec)
        .map_err(|_| "CLOCK_MONOTONIC returned negative seconds".to_string())?;
    let nanoseconds = u64::try_from(timestamp.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or_else(|| "CLOCK_MONOTONIC returned invalid nanoseconds".to_string())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "CLOCK_MONOTONIC nanoseconds overflowed u64".to_string())
}

/// Map a captured connect into the wire `NetworkFlow`. The capture yields the
/// destination IPv4 + port + pid + cgroup id; `saddr`/`sport`/byte+packet counts
/// stay zero until the capture is enriched.
fn to_network_flow(flow: &CapturedFlow) -> NetworkFlow {
    NetworkFlow {
        daddr: flow.daddr.to_vec(),
        dport: flow.dport as u32,
        pid: flow.pid,
        cgroup_id: flow.cgroup_id,
        protocol: IPPROTO_TCP,
        direction: DIRECTION_EGRESS,
        ..Default::default()
    }
}

/// Ship each service's accumulated flows to its repo as a `WireEbpfBatch`
/// (best-effort, fire-and-forget). Drains `pending`.
fn flush_flows(
    pending: &mut HashMap<String, Vec<NetworkFlow>>,
    deliveries: &HashMap<String, TargetDelivery>,
) {
    for (service, flows) in pending.drain() {
        if flows.is_empty() {
            continue;
        }
        let Some(delivery) = deliveries.get(&service) else {
            continue; // no target for this service (raced with removal)
        };
        let shipper = delivery.flow_shipper.clone();
        tokio::spawn(async move {
            match shipper.encode_ebpf_batch(flows) {
                Ok((encoded, count)) => match shipper.send_with_retry(&encoded).await {
                    Ok(_) => debug!(service, flows = count, "eBPF: shipped flow batch"),
                    Err(e) => {
                        warn!(service, error = %e, "eBPF: flow batch ship failed (best-effort)")
                    }
                },
                Err(e) => warn!(service, error = %e, "eBPF: flow batch encode failed"),
            }
        });
    }
}

/// Ship each service's accumulated L7 spans to its repo as a `WireEbpfBatch`
/// (`kind = REQUEST`, best-effort, fire-and-forget). Drains `pending`. Durable
/// buffering (like log lines) is a refinement.
fn flush_spans(
    pending: &mut HashMap<String, Vec<RequestSignal>>,
    deliveries: &HashMap<String, TargetDelivery>,
) {
    for (service, spans) in pending.drain() {
        if spans.is_empty() {
            continue;
        }
        let Some(delivery) = deliveries.get(&service) else {
            continue; // no target for this service (raced with removal)
        };
        let shipper = delivery.flow_shipper.clone();
        tokio::spawn(async move {
            match shipper.encode_request_signal_batch(spans) {
                Ok((encoded, count)) => match shipper.send_with_retry(&encoded).await {
                    Ok(_) => debug!(service, spans = count, "eBPF L7: shipped span batch"),
                    Err(e) => {
                        warn!(service, error = %e, "eBPF L7: span batch ship failed (best-effort)")
                    }
                },
                Err(e) => warn!(service, error = %e, "eBPF L7: span batch encode failed"),
            }
        });
    }
}

/// Ship the RED series accumulated this window as JSON metric entries, grouped by
/// service (best-effort). Drains the aggregator. The server-side RED schema is
/// still TBD, so these ride the entry-json arm for now.
fn flush_red(agg: &mut RedAggregator, deliveries: &HashMap<String, TargetDelivery>) {
    let mut by_service: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for entry in agg.drain() {
        by_service
            .entry(entry.service.clone())
            .or_default()
            .push(entry.to_json());
    }
    for (service, entries) in by_service {
        let Some(delivery) = deliveries.get(&service) else {
            continue;
        };
        let shipper = delivery.flow_shipper.clone();
        tokio::spawn(async move {
            match shipper.encode_entry_json_batch(entries) {
                Ok((encoded, count)) => match shipper.send_with_retry(&encoded).await {
                    Ok(_) => debug!(service, series = count, "eBPF L7: shipped RED batch"),
                    Err(e) => {
                        warn!(service, error = %e, "eBPF L7: RED batch ship failed (best-effort)")
                    }
                },
                Err(e) => warn!(service, error = %e, "eBPF L7: RED batch encode failed"),
            }
        });
    }
}

/// Create/rebuild/drop per-target delivery so `deliveries` matches `targets`.
fn reconcile_deliveries(
    deliveries: &mut HashMap<String, TargetDelivery>,
    targets: &[EbpfTargetConfig],
    data_dir: &Path,
    identity: &crate::identity::AgentIdentity,
) {
    let desired: HashMap<&str, &EbpfTargetConfig> = targets
        .iter()
        .map(|t| (t.log_source_id.as_str(), t))
        .collect();

    // Drop delivery for removed targets and stale ones whose repo changed.
    let to_remove: Vec<String> = deliveries
        .iter()
        .filter(|(id, delivery)| match desired.get(id.as_str()) {
            None => true,
            Some(target) => !delivery.matches(target),
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in to_remove {
        if let Some(delivery) = deliveries.remove(&id) {
            delivery.stop();
        }
    }

    // Create delivery for new (and just-dropped-stale) targets.
    for target in targets {
        if deliveries.contains_key(&target.log_source_id) {
            continue;
        }
        match create_delivery(target, data_dir, identity) {
            Ok(delivery) => {
                deliveries.insert(target.log_source_id.clone(), delivery);
            }
            Err(e) => error!(
                log_source_id = %target.log_source_id,
                error = %e,
                "eBPF: cannot start target delivery"
            ),
        }
    }
}

fn stop_all_deliveries(deliveries: &mut HashMap<String, TargetDelivery>) {
    for (_, delivery) in deliveries.drain() {
        delivery.stop();
    }
}

fn create_delivery(
    target: &EbpfTargetConfig,
    data_dir: &Path,
    identity: &crate::identity::AgentIdentity,
) -> Result<TargetDelivery, String> {
    let shipper = Shipper::new(
        &target.subbox_endpoint,
        &target.archive_id,
        &target.repo_id,
        Some(identity.clone()),
    )
    .map_err(|e| format!("shipper: {e}"))?;

    let flow_shipper = Arc::new(
        Shipper::new(
            &target.subbox_endpoint,
            &target.archive_id,
            &target.repo_id,
            Some(identity.clone()),
        )
        .map_err(|e| format!("flow shipper: {e}"))?,
    );

    let dir = data_dir
        .join("ebpf")
        .join(sanitize_id(&target.log_source_id));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let pipeline = StreamingDeliveryPipeline::open(
        &target.log_source_id,
        &dir,
        shipper,
        StreamingPipelineConfig::default(),
        None,
    )
    .map_err(|e| format!("open pipeline: {e}"))?;

    let (handle, actor) = spawn_streaming_actor(pipeline);

    Ok(TargetDelivery {
        handle,
        actor,
        flow_shipper,
        archive_id: target.archive_id.clone(),
        repo_id: target.repo_id.clone(),
        subbox_endpoint: target.subbox_endpoint.clone(),
    })
}

fn now_ns() -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(duration.as_nanos()).unwrap_or(0)
}

fn sanitize_id(id: &str) -> String {
    id.replace(['/', '\\', ':', '.', ' '], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_listener_health_cannot_fail_a_replacement_generation() {
        assert!(!listener_health_failed(
            ListenerDrainHealth {
                generation: 7,
                running: false,
            },
            Some(8),
        ));
        assert!(listener_health_failed(
            ListenerDrainHealth {
                generation: 8,
                running: false,
            },
            Some(8),
        ));
    }

    #[test]
    fn snapshot_worker_reservation_prevents_overlap_until_the_worker_exits() {
        let running = Arc::new(AtomicBool::new(false));
        let reservation = reserve_snapshot_worker(Arc::clone(&running)).unwrap();
        assert!(reserve_snapshot_worker(Arc::clone(&running)).is_err());

        drop(reservation);

        assert!(reserve_snapshot_worker(running).is_ok());
    }

    #[tokio::test]
    async fn fence_ack_consumes_already_queued_listener_before_readiness() {
        let mut state = ListenerState::default();
        let generation = state.begin_snapshot(100).unwrap();
        let (listener_tx, mut listener_rx) = mpsc::channel(1);
        listener_tx
            .send(CapturedListener {
                cgroup_id: 42,
                observed_at_ns: 101,
                tgid: 7,
                port: 8080,
                family: 2,
            })
            .await
            .unwrap();
        let (fence_tx, fence_rx) = oneshot::channel();
        fence_tx.send(Ok(())).unwrap();

        drain_listener_until_fence(fence_rx, &mut listener_rx, &mut state)
            .await
            .unwrap();
        state
            .apply_snapshot(
                generation,
                ListenerSnapshot::new(1, [], []).unwrap(),
                MAX_PORT_CGROUP_ASSOCIATIONS,
            )
            .unwrap();

        assert_eq!(
            state.cgroups_for_port(8080),
            std::collections::HashSet::from([42])
        );
    }
}
