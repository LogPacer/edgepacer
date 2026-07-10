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
use super::cgroup_resolver::{self, CgroupRouting};
use super::l7::{
    CapturedConnectionIdentity, CapturedSegment, ConnRegistry, RedAggregator, SpanContext, mint_id,
    to_request_signal,
};
use super::listener_snapshot;
use super::listener_state::{DeltaOutcome, ListenerAssociation, ListenerSnapshot, ListenerState};
use super::manager::{EbpfManager, ListenerObservation};
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
/// Overall wall-clock bound for one blocking listener snapshot. Late worker
/// completion is discarded by generation after this timeout fails readiness.
const LISTENER_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(20);
/// Cgroup filesystem identity resolution runs off-loop, but it must still
/// produce a fail-closed result within a bounded interval.
const CGROUP_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(20);
/// A published-count fence should normally complete immediately; bound it so a
/// dead or wedged drain fails readiness instead of blocking the runner.
const LISTENER_DRAIN_FENCE_TIMEOUT: Duration = Duration::from_secs(5);
/// Re-sample and fence late publications a bounded number of times. A busy
/// listener stream fails closed instead of letting snapshot commit starve the
/// runner indefinitely.
const MAX_LISTENER_FENCE_PASSES: usize = 8;
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
    authorization_revision: u64,
    capture_generation: u64,
    result: Result<ListenerSnapshot, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CgroupResolutionKey {
    listener_generation: u64,
    authorization_revision: u64,
    capture_generation: u64,
}

struct CgroupResolutionResult {
    key: CgroupResolutionKey,
    result: Result<CgroupRouting, String>,
}

#[derive(Debug, PartialEq, Eq)]
enum StableListenerFenceError {
    CaptureRestarted { before: u64, after: u64 },
    Fatal(String),
}

struct WorkerReservation(Arc<AtomicBool>);

impl Drop for WorkerReservation {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn reserve_worker(worker_running: Arc<AtomicBool>) -> Result<WorkerReservation, String> {
    worker_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "authorization worker is still running".to_string())?;
    Ok(WorkerReservation(worker_running))
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
    let (cgroup_resolution_tx, mut cgroup_resolution_rx) =
        mpsc::channel::<CgroupResolutionResult>(1);
    let cgroup_resolution_worker_running = Arc::new(AtomicBool::new(false));
    let mut pending_cgroup_resolution: Option<CgroupResolutionKey> = None;
    let mut manager = EbpfManager::new(AyaCaptureProgram::new(
        captured_tx,
        flow_tx,
        l7_tx,
        listener_tx,
        listener_health_tx,
    ));
    // Routing seeded on the last reconcile, reused to route drained records.
    let mut pid_routing = PidRouting::default();
    let mut cgroup_routing = CgroupRouting::default();
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
    let mut port_hints: HashMap<CapturedConnectionIdentity, Option<socket_port::ResolvedConn>> =
        HashMap::new();
    // Event deltas are usable only after an authoritative snapshot has supplied
    // cold-start state. Periodic replacement snapshots garbage-collect closes.
    let mut listener_state = ListenerState::default();
    let mut listener_config_hash: Option<String> = None;
    let mut listener_targets: Vec<EbpfTargetConfig> = Vec::new();
    let mut active_listener_generation: Option<u64> = None;
    let mut next_cgroup_policy_generation = 0u64;
    let mut reconcile_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + RECONCILE_INTERVAL,
        RECONCILE_INTERVAL,
    );
    macro_rules! authorization_refs {
        () => {
            CaptureAuthorizationRefs {
                pid_routing: &mut pid_routing,
                cgroup_routing: &mut cgroup_routing,
                listener_state: &mut listener_state,
                listener_config_hash: &mut listener_config_hash,
                listener_targets: &mut listener_targets,
                active_listener_generation: &mut active_listener_generation,
                l7_conns: &mut l7_conns,
                port_hints: &mut port_hints,
            }
        };
    }
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
                    pid_routing = PidRouting::default();
                    cgroup_routing = CgroupRouting::default();
                    stop_all_deliveries(&mut deliveries);
                    pending_flows.clear();
                    pending_spans.clear();
                    l7_red = RedAggregator::new();
                    l7_conns = ConnRegistry::new();
                    port_hints.clear();
                    listener_state.reset();
                    listener_config_hash = None;
                    listener_targets.clear();
                    active_listener_generation = None;
                    let mut guard = status.write().await;
                    guard.running = false;
                    guard.last_error = None;
                    guard.pids_targeted = 0;
                    guard.cgroups_targeted = 0;
                    continue;
                };

                // Discovery/config churn must not preserve an allow-set built
                // from older listener or runtime identity. Clear it before the
                // fallible PID census so no await extends stale authorization.
                let authorization_revision = discovery_cache
                    .read()
                    .await
                    .container_authorization_revision();
                let cgroup_authorization_changed = cgroup_routing
                    .authorization_revision()
                    .is_some_and(|revision| revision != authorization_revision);
                if !section.enabled
                    || cgroup_authorization_changed
                    || listener_config_hash
                        .as_deref()
                        .is_some_and(|hash| hash != section.config_hash)
                {
                    if let Err(error) = clear_cgroup_authorization_and_l7(
                        &mut manager,
                        &mut cgroup_routing,
                        &mut l7_conns,
                        &mut port_hints,
                    )
                    {
                        manager.shutdown();
                        pid_routing = PidRouting::default();
                        listener_state.reset();
                        listener_config_hash = None;
                        listener_targets.clear();
                        active_listener_generation = None;
                        let mut guard = status.write().await;
                        guard.running = false;
                        guard.last_error = Some(error.clone());
                        guard.pids_targeted = 0;
                        guard.cgroups_targeted = 0;
                        warn!(%error, "eBPF: capture unloaded after cgroup allow-set clear failed");
                        continue;
                    }
                    status.write().await.cgroups_targeted = 0;
                    listener_state.reset();
                    listener_config_hash = None;
                    listener_targets.clear();
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

                let previous_capture_generation = active_listener_generation;
                let previous_pid_policy_generation = pid_routing.policy_generation();
                let mut outcome = manager.reconcile(&section, &census);
                pid_routing = outcome.routing;
                if !outcome.running {
                    cgroup_routing = CgroupRouting::default();
                }

                if outcome.running {
                    match manager.listener_observation() {
                        Ok(observation) => {
                            active_listener_generation = Some(observation.generation);
                        }
                        Err(error) => {
                            manager.shutdown();
                            pid_routing = PidRouting::default();
                            cgroup_routing = CgroupRouting::default();
                            outcome.running = false;
                            outcome.last_error = Some(error);
                            outcome.routing = PidRouting::default();
                            active_listener_generation = None;
                        }
                    }
                } else {
                    active_listener_generation = None;
                }
                if authorization_generation_changed(
                    previous_capture_generation,
                    active_listener_generation,
                    previous_pid_policy_generation,
                    pid_routing.policy_generation(),
                ) {
                    l7_conns = ConnRegistry::new();
                    port_hints.clear();
                }

                if outcome.running && section.enabled {
                    if listener_config_hash.as_deref() != Some(section.config_hash.as_str()) {
                        listener_state.reset();
                        listener_config_hash = Some(section.config_hash.clone());
                        listener_targets = section.targets.clone();
                    }
                    if !listener_state.snapshot_in_flight()
                        && !snapshot_worker_running.load(Ordering::Acquire)
                        && !cgroup_resolution_worker_running.load(Ordering::Acquire)
                        && pending_cgroup_resolution.is_none()
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
                            if let Err(clear_error) = clear_cgroup_authorization_and_l7(
                                &mut manager,
                                &mut cgroup_routing,
                                &mut l7_conns,
                                &mut port_hints,
                            )
                            {
                                manager.shutdown();
                                pid_routing = PidRouting::default();
                                outcome.running = false;
                                outcome.last_error = Some(clear_error.clone());
                                active_listener_generation = None;
                                warn!(error = %clear_error, "eBPF: capture unloaded after cgroup allow-set clear failed");
                            }
                            warn!(%error, "eBPF: listener snapshot could not start; ownership is not ready");
                        } else if !listener_authorization_is_available(&listener_state)
                            && let Err(error) = clear_cgroup_authorization_and_l7(
                                &mut manager,
                                &mut cgroup_routing,
                                &mut l7_conns,
                                &mut port_hints,
                            )
                        {
                            manager.shutdown();
                            pid_routing = PidRouting::default();
                            listener_state.reset();
                            listener_config_hash = None;
                            listener_targets.clear();
                            outcome.running = false;
                            outcome.last_error = Some(error.clone());
                            active_listener_generation = None;
                            warn!(%error, "eBPF: capture unloaded after cgroup allow-set clear failed");
                        }
                    }
                } else {
                    listener_state.reset();
                    listener_config_hash = None;
                    listener_targets.clear();
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
                guard.pids_targeted = pid_routing.len();
                guard.cgroups_targeted = cgroup_routing.len();
            }

            Some(line) = captured_rx.recv() => {
                if !capture_generation_is_current(line.capture_generation, active_listener_generation) {
                    continue;
                }
                let Some(service) = route_captured_event(
                    &pid_routing,
                    &cgroup_routing,
                    line.pid,
                    line.scope_cgroup_id,
                    line.policy_generation,
                ) else {
                    continue; // scope no longer targeted (raced with replacement)
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
                if !capture_generation_is_current(flow.capture_generation, active_listener_generation) {
                    continue;
                }
                if let Some(service) = route_captured_event(
                    &pid_routing,
                    &cgroup_routing,
                    flow.pid,
                    flow.scope_cgroup_id,
                    flow.policy_generation,
                ) {
                    pending_flows
                        .entry(service.to_string())
                        .or_default()
                        .push(to_network_flow(&flow));
                }
            }

            Some(listener) = listener_rx.recv() => {
                if record_listener_delta(&mut listener_state, listener) {
                    reconcile_interval.reset_immediately();
                }
                if clear_unready_cgroup_authorization(
                    &mut manager,
                    authorization_refs!(),
                    &status,
                )
                .await
                {
                    continue;
                }
            }

            Some(snapshot_result) = snapshot_rx.recv() => {
                let ListenerSnapshotResult {
                    state_generation,
                    authorization_revision,
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
                            cache.verify_complete_container_authorization_revision(
                                authorization_revision,
                            )
                        };
                        if let Err(error) = cache_verification {
                            listener_state.fail_snapshot(state_generation);
                            clear_unready_cgroup_authorization(
                                &mut manager,
                                authorization_refs!(),
                                &status,
                            )
                            .await;
                            warn!(%error, "eBPF: container inventory changed during listener snapshot; ownership is not ready");
                            continue;
                        }

                        let observation = match manager.listener_observation() {
                            Ok(observation) => observation,
                            Err(error) => {
                                fail_listener_capture(
                                    &mut manager,
                                    authorization_refs!(),
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
                            listener_targets.clear();
                            clear_unready_cgroup_authorization(
                                &mut manager,
                                authorization_refs!(),
                                &status,
                            )
                            .await;
                            warn!(
                                before = capture_generation,
                                after = observation.generation,
                                "eBPF: listener capture restarted during snapshot; ownership is not ready"
                            );
                            continue;
                        }

                        let observation = match drain_listener_until_publication_stable(
                            capture_generation,
                            observation,
                            || manager.listener_observation(),
                            |published_counts| manager.listener_fence(published_counts),
                            &mut listener_rx,
                            &mut listener_state,
                        )
                        .await
                        {
                            Ok(observation) => observation,
                            Err(StableListenerFenceError::Fatal(error)) => {
                                fail_listener_capture(
                                    &mut manager,
                                    authorization_refs!(),
                                    &status,
                                    error,
                                )
                                .await;
                                continue;
                            }
                            Err(StableListenerFenceError::CaptureRestarted { before, after }) => {
                                listener_state.fail_snapshot(state_generation);
                                listener_config_hash = None;
                                listener_targets.clear();
                                clear_unready_cgroup_authorization(
                                    &mut manager,
                                    authorization_refs!(),
                                    &status,
                                )
                                .await;
                                warn!(
                                    before,
                                    after,
                                    "eBPF: listener capture restarted during drain fence; ownership is not ready"
                                );
                                continue;
                            }
                        };

                        let container_snapshot = {
                            let cache = discovery_cache.read().await;
                            if let Err(error) = cache
                                .verify_complete_container_authorization_revision(
                                    authorization_revision,
                                )
                            {
                                listener_state.fail_snapshot(state_generation);
                                drop(cache);
                                clear_unready_cgroup_authorization(
                                    &mut manager,
                                    authorization_refs!(),
                                    &status,
                                )
                                .await;
                                warn!(%error, "eBPF: container inventory changed during listener drain fence; ownership is not ready");
                                continue;
                            }
                            match cache.complete_container_snapshot() {
                                Ok(snapshot) => snapshot,
                                Err(error) => {
                                    listener_state.fail_snapshot(state_generation);
                                    drop(cache);
                                    clear_unready_cgroup_authorization(
                                        &mut manager,
                                        authorization_refs!(),
                                        &status,
                                    )
                                    .await;
                                    warn!(%error, "eBPF: container inventory became incomplete during listener drain fence; ownership is not ready");
                                    continue;
                                }
                            }
                        };
                        let previous_listener_authorization_revision =
                            listener_state.authorization_revision();
                        let applied = listener_state.apply_snapshot_with_loss(
                            state_generation,
                            snapshot,
                            observation.drop_counts,
                            MAX_PORT_CGROUP_ASSOCIATIONS,
                        );
                        match applied {
                            Ok(true) => {
                                debug_assert_eq!(
                                    listener_state.authorization_generation(),
                                    Some(state_generation)
                                );
                                let listener_authorization_changed =
                                    previous_listener_authorization_revision
                                        != listener_state.authorization_revision();
                                if listener_authorization_changed {
                                    // A close is visible only in replacement
                                    // snapshots. Clear a materially changed old
                                    // policy before resolving its replacement;
                                    // byte-identical evidence keeps the validated
                                    // policy active through off-loop resolution.
                                    if let Err(error) = clear_cgroup_authorization_and_l7(
                                        &mut manager,
                                        &mut cgroup_routing,
                                        &mut l7_conns,
                                        &mut port_hints,
                                    ) {
                                        fail_listener_capture(
                                            &mut manager,
                                            authorization_refs!(),
                                            &status,
                                            error,
                                        )
                                        .await;
                                        continue;
                                    }
                                    status.write().await.cgroups_targeted = 0;
                                }
                                let key = CgroupResolutionKey {
                                    listener_generation: state_generation,
                                    authorization_revision,
                                    capture_generation,
                                };
                                if let Err(error) = start_cgroup_resolution(
                                    key,
                                    container_snapshot.containers,
                                    listener_targets.clone(),
                                    listener_state.clone(),
                                    cgroup_resolution_tx.clone(),
                                    Arc::clone(&cgroup_resolution_worker_running),
                                ) {
                                    fail_listener_capture(
                                        &mut manager,
                                        authorization_refs!(),
                                        &status,
                                        error,
                                    )
                                    .await;
                                    continue;
                                }
                                pending_cgroup_resolution = Some(key);
                                debug!(
                                    associations = listener_state.association_count(),
                                    authorization_revision,
                                    "eBPF: listener ownership snapshot ready; resolving cgroup policy"
                                );
                            }
                            Ok(false) => {
                                debug!(generation = state_generation, "eBPF: ignored stale listener snapshot result");
                            }
                            Err(error) => {
                                clear_unready_cgroup_authorization(
                                    &mut manager,
                                    authorization_refs!(),
                                    &status,
                                )
                                .await;
                                warn!(%error, "eBPF: listener snapshot commit failed; ownership is not ready");
                            }
                        }
                    }
                    Err(error) => {
                        if listener_state.fail_snapshot(state_generation) {
                            clear_unready_cgroup_authorization(
                                &mut manager,
                                authorization_refs!(),
                                &status,
                            )
                            .await;
                            warn!(%error, "eBPF: authoritative listener snapshot failed; ownership is not ready");
                        } else {
                            debug!(generation = state_generation, %error, "eBPF: ignored stale listener snapshot failure");
                        }
                    }
                }
            }

            Some(resolution) = cgroup_resolution_rx.recv() => {
                let CgroupResolutionResult { key, result } = resolution;
                if pending_cgroup_resolution == Some(key) {
                    pending_cgroup_resolution = None;
                }
                let current_authorization_revision = discovery_cache
                    .read()
                    .await
                    .container_authorization_revision();
                if key.authorization_revision != current_authorization_revision {
                    listener_state.reset();
                    clear_unready_cgroup_authorization(
                        &mut manager,
                        authorization_refs!(),
                        &status,
                    )
                    .await;
                    debug!(
                        worker_revision = key.authorization_revision,
                        current_revision = current_authorization_revision,
                        "eBPF: ignored cgroup resolution from stale container authorization"
                    );
                    continue;
                }
                if !cgroup_resolution_is_current(
                    key,
                    &listener_state,
                    active_listener_generation,
                    current_authorization_revision,
                ) {
                    debug!(?key, "eBPF: ignored stale cgroup resolution result");
                    continue;
                }

                let mut desired_cgroups = match result {
                    Ok(routing) => routing,
                    Err(error) => {
                        listener_state.reset();
                        if let Err(clear_error) = clear_cgroup_authorization_and_l7(
                            &mut manager,
                            &mut cgroup_routing,
                            &mut l7_conns,
                            &mut port_hints,
                        ) {
                            fail_listener_capture(
                                &mut manager,
                                authorization_refs!(),
                                &status,
                                clear_error,
                            )
                            .await;
                        } else {
                            let mut guard = status.write().await;
                            guard.last_error = Some(error.clone());
                            guard.cgroups_targeted = 0;
                            warn!(%error, "eBPF: cgroup resolution failed; PID fallback remains active");
                        }
                        continue;
                    }
                };

                let observation = match manager.listener_observation() {
                    Ok(observation) => observation,
                    Err(error) => {
                        fail_listener_capture(
                            &mut manager,
                            authorization_refs!(),
                            &status,
                            error,
                        )
                        .await;
                        continue;
                    }
                };
                if observation.generation != key.capture_generation {
                    listener_state.reset();
                    clear_unready_cgroup_authorization(
                        &mut manager,
                        authorization_refs!(),
                        &status,
                    )
                    .await;
                    warn!(
                        before = key.capture_generation,
                        after = observation.generation,
                        "eBPF: listener capture restarted during cgroup resolution; policy was not published"
                    );
                    continue;
                }

                let observation = match drain_listener_until_publication_stable(
                    key.capture_generation,
                    observation,
                    || manager.listener_observation(),
                    |published_counts| manager.listener_fence(published_counts),
                    &mut listener_rx,
                    &mut listener_state,
                )
                .await
                {
                    Ok(observation) => observation,
                    Err(StableListenerFenceError::Fatal(error)) => {
                        fail_listener_capture(
                            &mut manager,
                            authorization_refs!(),
                            &status,
                            error,
                        )
                        .await;
                        continue;
                    }
                    Err(StableListenerFenceError::CaptureRestarted { before, after }) => {
                        listener_state.reset();
                        clear_unready_cgroup_authorization(
                            &mut manager,
                            authorization_refs!(),
                            &status,
                        )
                        .await;
                        warn!(
                            before,
                            after,
                            "eBPF: listener capture restarted during cgroup publication fence; policy was not published"
                        );
                        continue;
                    }
                };
                if let Err(error) = listener_state.validate_authorization(
                    key.listener_generation,
                    &observation.drop_counts,
                ) {
                    clear_unready_cgroup_authorization(
                        &mut manager,
                        authorization_refs!(),
                        &status,
                    )
                    .await;
                    warn!(%error, "eBPF: listener authorization changed during cgroup resolution; policy was not published");
                    continue;
                }

                // Hold the read lock across the final authorization revision
                // check and active-slot publication. Filesystem resolution ran
                // off-loop and without this lock.
                let cache = discovery_cache.read().await;
                if let Err(error) = cache.verify_complete_container_authorization_revision(
                    key.authorization_revision,
                ) {
                    listener_state.reset();
                    drop(cache);
                    clear_unready_cgroup_authorization(
                        &mut manager,
                        authorization_refs!(),
                        &status,
                    )
                    .await;
                    warn!(%error, "eBPF: container authorization changed before cgroup policy publication");
                    continue;
                }

                let cgroup_authorization_unchanged =
                    !cgroup_publication_is_required(&cgroup_routing, &desired_cgroups);
                if !desired_cgroups.is_empty() {
                    let generation = if cgroup_authorization_unchanged {
                        cgroup_routing.policy_generation().unwrap_or_else(|| {
                            next_cgroup_policy_generation = next_cgroup_policy_generation
                                .wrapping_add(1)
                                .max(1);
                            next_cgroup_policy_generation
                        })
                    } else {
                        next_cgroup_policy_generation =
                            next_cgroup_policy_generation.wrapping_add(1).max(1);
                        next_cgroup_policy_generation
                    };
                    if let Err(error) = desired_cgroups.assign_policy_generation(generation) {
                        drop(cache);
                        fail_listener_capture(
                            &mut manager,
                            authorization_refs!(),
                            &status,
                            error,
                        )
                        .await;
                        continue;
                    }
                }
                if !cgroup_authorization_unchanged {
                    // The blocking resolver already did the potentially
                    // unbounded environment discovery and a whole-routing
                    // freshness pass. A changed kernel policy still needs a
                    // strict pre/post TOCTOU bracket around the active-slot
                    // flip. This bounded critical section re-reads at most
                    // MAX_ALLOWED_CGROUPS (1024) runtime attestations. Stable
                    // authorization skips both these reads and the Aya rewrite.
                    match publish_revalidated_cgroups(
                        &desired_cgroups,
                        |routing| routing.revalidate_runtime_identities(),
                        |routing| manager.set_allowed_cgroups(routing),
                    ) {
                        Ok(()) => {}
                        Err(CgroupPublicationError::BeforeMap(error)) => {
                            listener_state.reset();
                            drop(cache);
                            if let Err(clear_error) = clear_cgroup_authorization_and_l7(
                                &mut manager,
                                &mut cgroup_routing,
                                &mut l7_conns,
                                &mut port_hints,
                            ) {
                                fail_listener_capture(
                                    &mut manager,
                                    authorization_refs!(),
                                    &status,
                                    clear_error,
                                )
                                .await;
                            } else {
                                let mut guard = status.write().await;
                                guard.last_error = Some(error.clone());
                                guard.cgroups_targeted = 0;
                                warn!(%error, "eBPF: runtime identity changed before cgroup policy publication; PID fallback remains active");
                            }
                            continue;
                        }
                        Err(CgroupPublicationError::MapMayBeMutated(error)) => {
                            drop(cache);
                            fail_listener_capture(
                                &mut manager,
                                authorization_refs!(),
                                &status,
                                error,
                            )
                            .await;
                            continue;
                        }
                    }
                }
                drop(cache);
                if cgroup_routing.policy_generation() != desired_cgroups.policy_generation() {
                    l7_conns = ConnRegistry::new();
                    port_hints.clear();
                }
                cgroup_routing = desired_cgroups;
                status.write().await.cgroups_targeted = cgroup_routing.len();
                debug!(
                    associations = listener_state.association_count(),
                    cgroups = cgroup_routing.len(),
                    "eBPF: cgroup policy published from current listener ownership"
                );
            }

            changed = listener_health_rx.changed() => {
                let health = *listener_health_rx.borrow_and_update();
                if changed.is_ok()
                    && listener_health_failed(health, active_listener_generation)
                    && listener_config_hash.is_some()
                {
                    let error = "mandatory listener drain stopped after capture start".to_string();
                    manager.shutdown();
                    pid_routing = PidRouting::default();
                    cgroup_routing = CgroupRouting::default();
                    listener_state.reset();
                    listener_config_hash = None;
                    listener_targets.clear();
                    active_listener_generation = None;
                    l7_conns = ConnRegistry::new();
                    port_hints.clear();
                    let mut guard = status.write().await;
                    guard.running = false;
                    guard.last_error = Some(error.clone());
                    guard.pids_targeted = 0;
                    guard.cgroups_targeted = 0;
                    warn!(%error, "eBPF: capture unloaded after listener drain failure");
                }
            }

            Some(seg) = l7_rx.recv() => {
                if !capture_generation_is_current(seg.capture_generation, active_listener_generation) {
                    continue;
                }
                let pid = seg.pid;
                let ts = seg.timestamp_nano;
                let Some(service) = route_captured_event(
                    &pid_routing,
                    &cgroup_routing,
                    pid,
                    seg.scope_cgroup_id,
                    seg.policy_generation,
                ) else {
                    continue;
                };
                // Resolve the connection's protocol from its port once (cached). TLS
                // segments carry an SSL*-derived fd that won't resolve → None, so
                // they fall back to byte detection (fine for HTTP-in-TLS).
                let resolved = port_hints
                    .entry(seg.connection_identity())
                    .or_insert_with(|| socket_port::resolve(pid, seg.fd));
                let (proto, flip) = match resolved.as_ref().and_then(|r| r.hint) {
                    Some(h) => (Some(h.protocol), h.client),
                    None => (None, false),
                };
                // The connection's peer endpoint — the service-map edge's other node.
                let peer = resolved.as_ref().map(|r| r.peer.clone());
                for record in l7_conns.on_segment_hinted(&seg, proto, flip) {
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

fn record_listener_delta(state: &mut ListenerState, listener: CapturedListener) -> bool {
    let was_ready = state.is_ready();
    let association = ListenerAssociation {
        family: listener.family,
        port: listener.port,
        cgroup_id: listener.cgroup_id,
    };
    match state.record_delta(association, listener.observed_at_ns) {
        DeltaOutcome::Invalidated => {
            warn!(
                port = listener.port,
                family = listener.family,
                cgroup_id = listener.cgroup_id,
                tgid = listener.tgid,
                "eBPF: unclassified listener change invalidated ownership until the next snapshot"
            );
        }
        DeltaOutcome::Quarantined => {
            debug!(
                port = listener.port,
                family = listener.family,
                cgroup_id = listener.cgroup_id,
                tgid = listener.tgid,
                "eBPF: quarantined unclassified listener change pending an authoritative snapshot"
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
        DeltaOutcome::IgnoredBeforeCut => {}
    }
    was_ready && !state.is_ready()
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
                    if record_listener_delta(state, listener) {
                        return Err(
                            "listener ownership invalidated while draining the publication fence"
                                .to_string(),
                        );
                    }
                }
                return Ok(());
            }
            listener = listener_rx.recv() => {
                let Some(listener) = listener else {
                    return Err("listener event channel closed before fence acknowledgement".to_string());
                };
                if record_listener_delta(state, listener) {
                    return Err(
                        "listener ownership invalidated while draining the publication fence"
                            .to_string(),
                    );
                }
            }
        }
    }
}

async fn drain_listener_until_publication_stable<Observe, Fence>(
    capture_generation: u64,
    mut observation: ListenerObservation,
    mut observe: Observe,
    mut fence: Fence,
    listener_rx: &mut mpsc::Receiver<CapturedListener>,
    state: &mut ListenerState,
) -> Result<ListenerObservation, StableListenerFenceError>
where
    Observe: FnMut() -> Result<ListenerObservation, String>,
    Fence: FnMut(Vec<u64>) -> Result<oneshot::Receiver<Result<(), String>>, String>,
{
    for _ in 0..MAX_LISTENER_FENCE_PASSES {
        let sampled_counts = observation.published_counts.clone();
        let receiver = fence(sampled_counts.clone()).map_err(StableListenerFenceError::Fatal)?;
        tokio::time::timeout(
            LISTENER_DRAIN_FENCE_TIMEOUT,
            drain_listener_until_fence(receiver, listener_rx, state),
        )
        .await
        .map_err(|_| {
            StableListenerFenceError::Fatal(format!(
                "listener drain fence timed out after {LISTENER_DRAIN_FENCE_TIMEOUT:?}"
            ))
        })?
        .map_err(StableListenerFenceError::Fatal)?;

        let next = observe().map_err(StableListenerFenceError::Fatal)?;
        if next.generation != capture_generation {
            return Err(StableListenerFenceError::CaptureRestarted {
                before: capture_generation,
                after: next.generation,
            });
        }
        if listener_publication_counts_are_stable(&sampled_counts, &next.published_counts)
            .map_err(StableListenerFenceError::Fatal)?
        {
            return Ok(next);
        }
        observation = next;
    }

    Err(StableListenerFenceError::Fatal(format!(
        "listener publications did not quiesce after {MAX_LISTENER_FENCE_PASSES} drain fences"
    )))
}

fn listener_publication_counts_are_stable(
    sampled: &[u64],
    observed: &[u64],
) -> Result<bool, String> {
    if sampled.len() != observed.len() {
        return Err(format!(
            "listener publication CPU count changed from {} to {}",
            sampled.len(),
            observed.len()
        ));
    }
    if let Some((cpu, (before, after))) = sampled
        .iter()
        .zip(observed)
        .enumerate()
        .find(|(_, (before, after))| after < before)
    {
        return Err(format!(
            "listener publication count regressed on CPU {cpu} from {before} to {after}"
        ));
    }
    Ok(sampled == observed)
}

struct CaptureAuthorizationRefs<'a> {
    pid_routing: &'a mut PidRouting,
    cgroup_routing: &'a mut CgroupRouting,
    listener_state: &'a mut ListenerState,
    listener_config_hash: &'a mut Option<String>,
    listener_targets: &'a mut Vec<EbpfTargetConfig>,
    active_listener_generation: &'a mut Option<u64>,
    l7_conns: &'a mut ConnRegistry,
    port_hints: &'a mut HashMap<CapturedConnectionIdentity, Option<socket_port::ResolvedConn>>,
}

async fn fail_listener_capture(
    manager: &mut EbpfManager<AyaCaptureProgram>,
    authorization: CaptureAuthorizationRefs<'_>,
    status: &SharedEbpfStatus,
    error: String,
) {
    manager.shutdown();
    *authorization.pid_routing = PidRouting::default();
    *authorization.cgroup_routing = CgroupRouting::default();
    authorization.listener_state.reset();
    *authorization.listener_config_hash = None;
    authorization.listener_targets.clear();
    *authorization.active_listener_generation = None;
    *authorization.l7_conns = ConnRegistry::new();
    authorization.port_hints.clear();
    let mut guard = status.write().await;
    guard.running = false;
    guard.last_error = Some(error.clone());
    guard.pids_targeted = 0;
    guard.cgroups_targeted = 0;
    warn!(%error, "eBPF: listener snapshot verification failed; capture unloaded");
}

fn clear_cgroup_authorization(
    manager: &mut EbpfManager<AyaCaptureProgram>,
    routing: &mut CgroupRouting,
) -> Result<(), String> {
    if routing.is_empty() {
        return Ok(());
    }

    let empty = CgroupRouting::default();
    let result = manager.set_allowed_cgroups(&empty);
    *routing = empty;
    result
}

fn clear_cgroup_authorization_and_l7(
    manager: &mut EbpfManager<AyaCaptureProgram>,
    routing: &mut CgroupRouting,
    l7_conns: &mut ConnRegistry,
    port_hints: &mut HashMap<CapturedConnectionIdentity, Option<socket_port::ResolvedConn>>,
) -> Result<(), String> {
    let result = clear_cgroup_authorization(manager, routing);
    *l7_conns = ConnRegistry::new();
    port_hints.clear();
    result
}

#[derive(Debug, PartialEq, Eq)]
enum CgroupPublicationError {
    BeforeMap(String),
    MapMayBeMutated(String),
}

fn publish_revalidated_cgroups<Validate, Publish>(
    routing: &CgroupRouting,
    mut revalidate: Validate,
    publish: Publish,
) -> Result<(), CgroupPublicationError>
where
    Validate: FnMut(&CgroupRouting) -> Result<(), String>,
    Publish: FnOnce(&CgroupRouting) -> Result<(), String>,
{
    revalidate(routing).map_err(CgroupPublicationError::BeforeMap)?;
    publish(routing).map_err(CgroupPublicationError::MapMayBeMutated)?;
    revalidate(routing).map_err(CgroupPublicationError::MapMayBeMutated)
}

fn cgroup_publication_is_required(active: &CgroupRouting, desired: &CgroupRouting) -> bool {
    !desired.same_authorization_as(active)
}

async fn clear_unready_cgroup_authorization(
    manager: &mut EbpfManager<AyaCaptureProgram>,
    authorization: CaptureAuthorizationRefs<'_>,
    status: &SharedEbpfStatus,
) -> bool {
    if listener_authorization_is_available(authorization.listener_state)
        || authorization.cgroup_routing.is_empty()
    {
        return false;
    }

    let result = clear_cgroup_authorization_and_l7(
        manager,
        &mut *authorization.cgroup_routing,
        &mut *authorization.l7_conns,
        &mut *authorization.port_hints,
    );
    let Err(error) = result else {
        status.write().await.cgroups_targeted = 0;
        return false;
    };
    fail_listener_capture(manager, authorization, status, error).await;
    true
}

async fn start_listener_snapshot(
    state: &mut ListenerState,
    manager: &EbpfManager<AyaCaptureProgram>,
    discovery_cache: SharedDiscoveryCache,
    tx: mpsc::Sender<ListenerSnapshotResult>,
    worker_running: Arc<AtomicBool>,
) -> Result<(), String> {
    let reservation = reserve_worker(worker_running)?;

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
    let authorization_revision = container_snapshot.authorization_revision;
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
                    authorization_revision,
                    capture_generation,
                    result,
                })
                .await;
        } else {
            let _ = tx
                .send(ListenerSnapshotResult {
                    state_generation,
                    authorization_revision,
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

fn start_cgroup_resolution(
    key: CgroupResolutionKey,
    containers: Vec<crate::discovery::Container>,
    targets: Vec<EbpfTargetConfig>,
    listener_state: ListenerState,
    tx: mpsc::Sender<CgroupResolutionResult>,
    worker_running: Arc<AtomicBool>,
) -> Result<(), String> {
    let reservation = reserve_worker(worker_running)?;
    tokio::spawn(async move {
        let _reservation = reservation;
        let mut worker = tokio::task::spawn_blocking(move || {
            let routing = cgroup_resolver::resolve_from_listener_state(
                &containers,
                &targets,
                &listener_state,
                key.authorization_revision,
            )?;
            // Refresh the complete attestation set at the end of the blocking
            // work. The common unchanged-policy path can then keep the active
            // map without doing filesystem I/O on the runner loop.
            routing.revalidate_runtime_identities()?;
            Ok(routing)
        });
        let result = tokio::select! {
            result = &mut worker => Some(
                result
                    .map_err(|error| format!("cgroup resolution worker failed: {error}"))
                    .and_then(|result| result),
            ),
            _ = tokio::time::sleep(CGROUP_RESOLUTION_TIMEOUT) => None,
        };

        if let Some(result) = result {
            let _ = tx.send(CgroupResolutionResult { key, result }).await;
        } else {
            let _ = tx
                .send(CgroupResolutionResult {
                    key,
                    result: Err(format!(
                        "cgroup resolution timed out after {CGROUP_RESOLUTION_TIMEOUT:?}"
                    )),
                })
                .await;
            // `spawn_blocking` cannot cancel a running filesystem walk. Keep
            // the reservation until it exits so timeouts cannot accumulate
            // overlapping authorization workers.
            let _ = worker.await;
        }
    });
    Ok(())
}

fn listener_authorization_is_available(state: &ListenerState) -> bool {
    state.authorization_generation().is_some()
}

fn cgroup_resolution_is_current(
    key: CgroupResolutionKey,
    listener_state: &ListenerState,
    active_capture_generation: Option<u64>,
    current_authorization_revision: u64,
) -> bool {
    key.authorization_revision == current_authorization_revision
        && active_capture_generation == Some(key.capture_generation)
        && listener_state.publishable_authorization_generation() == Some(key.listener_generation)
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

fn route_captured_event<'a>(
    pid_routing: &'a PidRouting,
    cgroup_routing: &'a CgroupRouting,
    pid: u32,
    scope_cgroup_id: u64,
    policy_generation: u64,
) -> Option<&'a str> {
    let pid_service = pid_routing.service_for(pid);
    if scope_cgroup_id == 0 {
        if policy_generation == 0 || pid_routing.policy_generation() != Some(policy_generation) {
            warn!(
                pid,
                policy_generation,
                current_policy_generation = ?pid_routing.policy_generation(),
                "eBPF: PID-authorized event has a stale policy generation; dropping captured event"
            );
            return None;
        }
        return pid_service;
    }

    if policy_generation == 0 || cgroup_routing.policy_generation() != Some(policy_generation) {
        warn!(
            pid,
            scope_cgroup_id,
            policy_generation,
            current_policy_generation = ?cgroup_routing.policy_generation(),
            "eBPF: cgroup-authorized event has a stale policy generation; dropping captured event"
        );
        return None;
    }

    let cgroup_service = cgroup_routing.service_for(scope_cgroup_id);

    match (pid_service, cgroup_service) {
        (Some(pid_service), Some(cgroup_service)) if pid_service != cgroup_service => {
            warn!(
                pid,
                scope_cgroup_id,
                pid_service,
                cgroup_service,
                "eBPF: conflicting PID and cgroup routing; dropping captured event"
            );
            None
        }
        (Some(service), Some(_)) | (None, Some(service)) => Some(service),
        (Some(_), None) => {
            warn!(
                pid,
                scope_cgroup_id,
                "eBPF: cgroup-authorized event has no current scope routing; dropping captured event"
            );
            None
        }
        (None, None) => None,
    }
}

fn capture_generation_is_current(record_generation: u64, active_generation: Option<u64>) -> bool {
    record_generation != 0 && active_generation == Some(record_generation)
}

fn authorization_generation_changed(
    previous_capture: Option<u64>,
    current_capture: Option<u64>,
    previous_pid_policy: Option<u64>,
    current_pid_policy: Option<u64>,
) -> bool {
    previous_capture != current_capture || previous_pid_policy != current_pid_policy
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
    use crate::ebpf::cgroup_resolver::CgroupAnchor;

    fn cgroup_routing(service: &str) -> CgroupRouting {
        CgroupRouting::from_entries(7, [(CgroupAnchor { id: 42, level: 3 }, service)]).unwrap()
    }

    #[test]
    fn captured_event_routes_by_whichever_authorized_identity_is_present() {
        let pid = PidRouting::from_entries([(11, "source")]).unwrap();
        let cgroup = cgroup_routing("source");

        assert_eq!(
            route_captured_event(&pid, &CgroupRouting::default(), 11, 0, 1),
            Some("source")
        );
        assert_eq!(
            route_captured_event(&PidRouting::default(), &cgroup, 99, 42, 7),
            Some("source")
        );
        assert_eq!(
            route_captured_event(&pid, &cgroup, 11, 42, 7),
            Some("source")
        );
        assert_eq!(route_captured_event(&pid, &cgroup, 11, 999, 7), None);
        assert_eq!(
            route_captured_event(&PidRouting::default(), &CgroupRouting::default(), 99, 0, 0),
            None
        );
    }

    #[test]
    fn captured_event_drops_conflicting_pid_and_cgroup_attribution() {
        let pid = PidRouting::from_entries([(11, "pid-source")]).unwrap();
        let cgroup = cgroup_routing("cgroup-source");

        assert_eq!(route_captured_event(&pid, &cgroup, 11, 42, 7), None);
    }

    #[test]
    fn captured_event_drops_stale_or_malformed_policy_generation() {
        let pid = PidRouting::from_entries([(11, "source")]).unwrap();
        let cgroup = cgroup_routing("source");

        assert_eq!(route_captured_event(&pid, &cgroup, 11, 42, 6), None);
        assert_eq!(route_captured_event(&pid, &cgroup, 11, 42, 0), None);
        assert_eq!(route_captured_event(&pid, &cgroup, 11, 0, 7), None);
        assert_eq!(route_captured_event(&pid, &cgroup, 11, 0, 0), None);
    }

    #[test]
    fn capture_generation_must_match_the_current_loaded_program() {
        assert!(capture_generation_is_current(7, Some(7)));
        assert!(!capture_generation_is_current(6, Some(7)));
        assert!(!capture_generation_is_current(0, Some(7)));
        assert!(!capture_generation_is_current(7, None));
    }

    #[test]
    fn l7_state_resets_when_capture_or_pid_authorization_generation_changes() {
        assert!(!authorization_generation_changed(
            Some(7),
            Some(7),
            Some(11),
            Some(11)
        ));
        assert!(authorization_generation_changed(
            Some(7),
            Some(7),
            Some(11),
            Some(12)
        ));
        assert!(authorization_generation_changed(
            Some(7),
            Some(8),
            Some(11),
            Some(11)
        ));
        assert!(authorization_generation_changed(
            Some(7),
            Some(7),
            Some(11),
            None
        ));
    }

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
        let reservation = reserve_worker(Arc::clone(&running)).unwrap();
        assert!(reserve_worker(Arc::clone(&running)).is_err());

        drop(reservation);

        assert!(reserve_worker(running).is_ok());
    }

    #[test]
    fn cgroup_resolution_result_requires_current_listener_capture_and_inventory() {
        let mut state = ListenerState::default();
        let listener_generation = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(
                listener_generation,
                ListenerSnapshot::new(1, [], []).unwrap(),
                MAX_PORT_CGROUP_ASSOCIATIONS,
            )
            .unwrap();
        let key = CgroupResolutionKey {
            listener_generation,
            authorization_revision: 11,
            capture_generation: 7,
        };

        assert!(cgroup_resolution_is_current(key, &state, Some(7), 11));
        assert!(!cgroup_resolution_is_current(key, &state, Some(8), 11));
        assert!(!cgroup_resolution_is_current(key, &state, Some(7), 12));

        assert_eq!(
            state.record_delta(
                ListenerAssociation {
                    family: libc::AF_INET as u16,
                    port: 8080,
                    cgroup_id: 42,
                },
                101,
            ),
            DeltaOutcome::Invalidated
        );
        assert!(!cgroup_resolution_is_current(key, &state, Some(7), 11));
    }

    #[test]
    fn replacement_snapshot_preserves_policy_but_makes_prior_resolution_stale() {
        let mut state = ListenerState::default();
        let listener_generation = state.begin_snapshot(100).unwrap();
        state
            .apply_snapshot(
                listener_generation,
                ListenerSnapshot::new(1, [], []).unwrap(),
                MAX_PORT_CGROUP_ASSOCIATIONS,
            )
            .unwrap();
        let key = CgroupResolutionKey {
            listener_generation,
            authorization_revision: 11,
            capture_generation: 7,
        };
        let listener_revision = state.authorization_revision().unwrap();

        assert!(listener_authorization_is_available(&state));

        let replacement = state.begin_snapshot(200).unwrap();

        assert!(
            listener_authorization_is_available(&state),
            "the last applied policy remains valid while its replacement is collected"
        );
        assert!(!cgroup_resolution_is_current(key, &state, Some(7), 11));

        state
            .apply_snapshot(
                replacement,
                ListenerSnapshot::new(1, [], []).unwrap(),
                MAX_PORT_CGROUP_ASSOCIATIONS,
            )
            .unwrap();
        assert_eq!(state.authorization_revision(), Some(listener_revision));
        assert!(listener_authorization_is_available(&state));
        assert!(cgroup_resolution_is_current(
            CgroupResolutionKey {
                listener_generation: replacement,
                ..key
            },
            &state,
            Some(7),
            11,
        ));
    }

    #[test]
    fn cgroup_publication_rejects_runtime_move_before_map_write() {
        let routing = cgroup_routing("source");
        let mut published = false;

        let error = publish_revalidated_cgroups(
            &routing,
            |_| Err("runtime moved before publication".to_string()),
            |_| {
                published = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(!published);
        assert_eq!(
            error,
            CgroupPublicationError::BeforeMap("runtime moved before publication".to_string())
        );
    }

    #[test]
    fn cgroup_publication_rejects_runtime_move_after_map_write() {
        let routing = cgroup_routing("source");
        let mut validations = 0;
        let mut published = false;

        let error = publish_revalidated_cgroups(
            &routing,
            |_| {
                validations += 1;
                if validations == 2 {
                    Err("runtime moved after publication".to_string())
                } else {
                    Ok(())
                }
            },
            |_| {
                published = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(published);
        assert_eq!(validations, 2);
        assert_eq!(
            error,
            CgroupPublicationError::MapMayBeMutated("runtime moved after publication".to_string())
        );
    }

    #[test]
    fn cgroup_publication_treats_map_errors_as_potential_mutation() {
        let routing = cgroup_routing("source");
        let mut validations = 0;

        let error = publish_revalidated_cgroups(
            &routing,
            |_| {
                validations += 1;
                Ok(())
            },
            |_| Err("map update failed".to_string()),
        )
        .unwrap_err();

        assert_eq!(validations, 1);
        assert_eq!(
            error,
            CgroupPublicationError::MapMayBeMutated("map update failed".to_string())
        );
    }

    #[test]
    fn unchanged_cgroup_authorization_skips_map_publication() {
        let mut active = cgroup_routing("source");
        active.assign_policy_generation(99).unwrap();
        let desired = cgroup_routing("source");

        assert!(!cgroup_publication_is_required(&active, &desired));
        assert!(cgroup_publication_is_required(
            &active,
            &cgroup_routing("other-source")
        ));
    }

    #[tokio::test]
    async fn fence_ack_quarantines_already_queued_unclassified_listener() {
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
        let error = state
            .apply_snapshot(
                generation,
                ListenerSnapshot::new(1, [], []).unwrap(),
                MAX_PORT_CGROUP_ASSOCIATIONS,
            )
            .unwrap_err();

        assert!(error.contains("unclassified listener change"), "{error}");
        assert!(!state.is_ready());
        assert!(state.cgroups_for_port(8080).is_empty());
    }

    #[tokio::test]
    async fn late_listener_publication_requires_another_drain_fence() {
        let observations = std::cell::RefCell::new(std::collections::VecDeque::from([
            ListenerObservation {
                generation: 7,
                drop_counts: vec![0],
                published_counts: vec![2],
            },
            ListenerObservation {
                generation: 7,
                drop_counts: vec![0],
                published_counts: vec![2],
            },
        ]));
        let fenced_counts = std::cell::RefCell::new(Vec::new());
        let (_listener_tx, mut listener_rx) = mpsc::channel(1);
        let mut state = ListenerState::default();

        let stable = drain_listener_until_publication_stable(
            7,
            ListenerObservation {
                generation: 7,
                drop_counts: vec![0],
                published_counts: vec![1],
            },
            || {
                observations
                    .borrow_mut()
                    .pop_front()
                    .ok_or_else(|| "missing scripted listener observation".to_string())
            },
            |counts| {
                fenced_counts.borrow_mut().push(counts);
                let (ack, receiver) = oneshot::channel();
                ack.send(Ok(())).unwrap();
                Ok(receiver)
            },
            &mut listener_rx,
            &mut state,
        )
        .await
        .unwrap();

        assert_eq!(stable.published_counts, vec![2]);
        assert_eq!(*fenced_counts.borrow(), vec![vec![1], vec![2]]);
    }
}
