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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use logpacer_wire::{NetworkFlow, RequestSignal};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::SharedEbpfStatus;
use super::capture::{AyaCaptureProgram, CapturedFlow, CapturedLine, CapturedListener};
use super::l7::{
    CapturedSegment, ConnRegistry, RedAggregator, SpanContext, mint_id, to_request_signal,
};
use super::manager::EbpfManager;
use super::pid_resolver::PidRouting;
use super::socket_port;
use crate::config::{self, EbpfTargetConfig, SharedConfig};
use crate::discovery::ports::discover_ports;
use crate::shipper::Shipper;
use crate::streaming_actor::{StreamHandle, spawn_streaming_actor};
use crate::streaming_pipeline::{StreamingDeliveryPipeline, StreamingPipelineConfig};

/// PID-filter refresh + delivery reconcile + flow-flush cadence.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// Temporary Phase 2 backstop until an authoritative listener snapshot + GC
/// replaces the append-only live-delta cache.
const MAX_PORT_CGROUP_ASSOCIATIONS: usize = 16_384;
/// Bound on in-flight captured records awaiting routing; backpressures the drain.
const CAPTURE_CHANNEL_DEPTH: usize = 256;
/// IPPROTO_TCP — connect(2) to an AF_INET endpoint (the capture's domain).
const IPPROTO_TCP: u32 = 6;
/// NetworkFlow.direction = egress (an outbound connect).
const DIRECTION_EGRESS: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerAssociationInsert {
    Inserted,
    AlreadyPresent,
    AtCapacity { should_warn: bool },
}

#[derive(Default)]
struct ListenerDiscovery {
    port_cgroups: HashMap<u16, HashSet<u64>>,
    association_count: usize,
    capacity_warning_emitted: bool,
}

impl ListenerDiscovery {
    fn insert(&mut self, port: u16, cgroup_id: u64, limit: usize) -> ListenerAssociationInsert {
        if self
            .port_cgroups
            .get(&port)
            .is_some_and(|cgroups| cgroups.contains(&cgroup_id))
        {
            return ListenerAssociationInsert::AlreadyPresent;
        }

        if self.association_count >= limit {
            let should_warn = !self.capacity_warning_emitted;
            self.capacity_warning_emitted = true;
            return ListenerAssociationInsert::AtCapacity { should_warn };
        }

        self.port_cgroups.entry(port).or_default().insert(cgroup_id);
        self.association_count += 1;
        ListenerAssociationInsert::Inserted
    }

    fn clear(&mut self) {
        self.port_cgroups.clear();
        self.association_count = 0;
        self.capacity_warning_emitted = false;
    }
}

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
    status: SharedEbpfStatus,
    data_dir: &Path,
    identity: &crate::identity::AgentIdentity,
    mut shutdown: watch::Receiver<bool>,
) {
    let (captured_tx, mut captured_rx) = mpsc::channel::<CapturedLine>(CAPTURE_CHANNEL_DEPTH);
    let (flow_tx, mut flow_rx) = mpsc::channel::<CapturedFlow>(CAPTURE_CHANNEL_DEPTH);
    let (l7_tx, mut l7_rx) = mpsc::channel::<CapturedSegment>(CAPTURE_CHANNEL_DEPTH);
    let (listener_tx, mut listener_rx) = mpsc::channel::<CapturedListener>(CAPTURE_CHANNEL_DEPTH);
    let mut manager = EbpfManager::new(AyaCaptureProgram::new(
        captured_tx,
        flow_tx,
        l7_tx,
        listener_tx,
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
    // Event-driven port→cgroup discovery from successful TCP listener
    // transitions, built from LISTENER_EVENTS.
    // A future slice combines these live deltas with an authoritative snapshot
    // + GC before resolving directive ports and seeding cgroup scoping.
    let mut listener_discovery = ListenerDiscovery::default();
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
                    listener_discovery.clear();
                    let mut guard = status.write().await;
                    guard.running = false;
                    guard.last_error = None;
                    guard.pids_targeted = 0;
                    continue;
                };

                let census = match discover_ports().await {
                    Ok(census) => census,
                    Err(e) => {
                        warn!(error = %e, "eBPF: port census failed; skipping refresh this tick");
                        continue;
                    }
                };

                let outcome = manager.reconcile(&section, &census);
                routing = outcome.routing;

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
                // Record which cgroup owns this listening port. Logged on first
                // sighting so the discovered topology is observable; a later slice
                // resolves directive ports → these cgroups to seed cgroup scoping.
                if listener.cgroup_id == 0 {
                    warn!(
                        port = listener.port,
                        tgid = listener.tgid,
                        "eBPF: ignored listener with zero cgroup id"
                    );
                } else {
                    match listener_discovery.insert(
                        listener.port,
                        listener.cgroup_id,
                        MAX_PORT_CGROUP_ASSOCIATIONS,
                    ) {
                        ListenerAssociationInsert::Inserted => {
                            debug!(
                                port = listener.port,
                                cgroup_id = listener.cgroup_id,
                                tgid = listener.tgid,
                                "eBPF: discovered listener (port→cgroup)"
                            );
                        }
                        ListenerAssociationInsert::AtCapacity { should_warn: true } => {
                            warn!(
                                limit = MAX_PORT_CGROUP_ASSOCIATIONS,
                                "eBPF: listener discovery capacity reached; dropping new associations until reset"
                            );
                        }
                        ListenerAssociationInsert::AlreadyPresent
                        | ListenerAssociationInsert::AtCapacity { should_warn: false } => {}
                    }
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
    fn listener_associations_are_bounded_without_counting_duplicates() {
        let mut discovery = ListenerDiscovery::default();

        assert_eq!(
            discovery.insert(8080, 11, 2),
            ListenerAssociationInsert::Inserted
        );
        assert_eq!(
            discovery.insert(8080, 11, 2),
            ListenerAssociationInsert::AlreadyPresent
        );
        assert_eq!(
            discovery.insert(8080, 12, 2),
            ListenerAssociationInsert::Inserted
        );
        assert_eq!(
            discovery.insert(9090, 13, 2),
            ListenerAssociationInsert::AtCapacity { should_warn: true }
        );
        assert_eq!(
            discovery.insert(9090, 14, 2),
            ListenerAssociationInsert::AtCapacity { should_warn: false }
        );

        assert_eq!(discovery.association_count, 2);
        assert_eq!(discovery.port_cgroups.get(&8080).unwrap().len(), 2);
        assert!(!discovery.port_cgroups.contains_key(&9090));
    }

    #[test]
    fn clearing_listener_associations_resets_capacity_warning() {
        let mut discovery = ListenerDiscovery::default();

        assert_eq!(
            discovery.insert(8080, 11, 1),
            ListenerAssociationInsert::Inserted
        );
        assert_eq!(
            discovery.insert(9090, 12, 1),
            ListenerAssociationInsert::AtCapacity { should_warn: true }
        );

        discovery.clear();

        assert_eq!(discovery.association_count, 0);
        assert!(discovery.port_cgroups.is_empty());
        assert_eq!(
            discovery.insert(9090, 12, 1),
            ListenerAssociationInsert::Inserted
        );
        assert_eq!(
            discovery.insert(10_000, 13, 1),
            ListenerAssociationInsert::AtCapacity { should_warn: true }
        );
    }
}
