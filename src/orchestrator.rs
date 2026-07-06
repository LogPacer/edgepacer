//! Multi-source orchestrator — manages concurrent file-backed and streaming pipelines.
//!
//! On config hot-reload:
//! 1. Compare new sources against running pipelines (by log_source_id)
//! 2. Start pipelines for new sources
//! 3. Drain and stop pipelines for removed sources
//! 4. Restart pipelines whose config hash changed
//!
//! File sources use `DeliveryPipeline` (tailer → buffer → shipper → checkpoint).
//! Streaming sources (Docker, journald) use `StreamingDeliveryPipeline` with a
//! concurrent reader + drain loop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{
    self, BufferTuning, CollectDiagnostic, FileSourceFormat, LogStreamConfig, SharedConfig,
    StreamingSourceConfig,
};
use crate::counters::AgentCounters;
use crate::discovery::SharedDiscoveryCache;
use crate::discovery::cache::MatchStatus;
use crate::error_collector::ErrorCollector;
use crate::identity::AgentIdentity;
use crate::overflow::SharedOverflow;
use crate::pipeline::{DeliveryPipeline, PipelineConfig, PipelineError, PipelineSourceOptions};
use crate::shipper::Shipper;
use crate::streaming_actor;
use crate::streaming_pipeline::{StreamingDeliveryPipeline, StreamingPipelineConfig};
use crate::streaming_runner;

/// A running file pipeline with its config hash and shutdown handle.
struct ManagedPipeline {
    config_hash: String,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// A running streaming source: the reader task and the pipeline actor task.
///
/// The reader owns the only `StreamHandle`; when it exits (on the shutdown
/// watch) and drops the handle, the actor flushes and exits on its own.
struct ManagedStreamingSource {
    config_hash: String,
    shutdown_tx: watch::Sender<bool>,
    reader: JoinHandle<()>,
    actor: JoinHandle<()>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ReconcilePlan {
    to_remove: Vec<String>,
    to_restart: Vec<String>,
}

fn plan_source_reconciliation<'a>(
    managed_sources: impl IntoIterator<Item = (&'a str, &'a str)>,
    desired_sources: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> ReconcilePlan {
    let desired_by_id: HashMap<&str, &str> = desired_sources.into_iter().collect();

    let mut plan = ReconcilePlan::default();

    for (id, managed_hash) in managed_sources {
        match desired_by_id.get(id) {
            None => plan.to_remove.push(id.to_string()),
            Some(desired_hash) if managed_hash != *desired_hash => {
                plan.to_restart.push(id.to_string());
            }
            _ => {}
        }
    }

    plan
}

/// What to log for a collect directive given its previous and current status.
/// Unchanged statuses are silent — this is what stops the per-reconcile warning
/// spam for a path/loggable that is simply still missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolutionTransition {
    Silent,
    Warn,
    Recovered,
}

fn classify_transition(
    previous: Option<MatchStatus>,
    current: MatchStatus,
) -> ResolutionTransition {
    match (previous, current) {
        (Some(prev), now) if prev == now => ResolutionTransition::Silent,
        (_, MatchStatus::NotFound | MatchStatus::Ambiguous) => ResolutionTransition::Warn,
        (Some(_), MatchStatus::Matched) => ResolutionTransition::Recovered,
        (None, MatchStatus::Matched) => ResolutionTransition::Silent,
    }
}

/// Log collect-resolution outcomes, but only when a source's status changes: a
/// fresh miss/ambiguity warns once, a recovery is noted, and an unchanged
/// status stays silent. `last` is retained across reconciles, so churning
/// config never reprints the same warning.
fn log_collect_resolution(
    last: &mut HashMap<String, MatchStatus>,
    diagnostics: &[CollectDiagnostic],
) {
    let current: std::collections::HashSet<&str> = diagnostics
        .iter()
        .map(|d| d.log_source_id.as_str())
        .collect();
    // Forget sources no longer configured so a later re-add warns afresh.
    last.retain(|id, _| current.contains(id.as_str()));

    for diagnostic in diagnostics {
        let previous = last.get(&diagnostic.log_source_id).copied();
        match classify_transition(previous, diagnostic.status) {
            ResolutionTransition::Silent => {}
            ResolutionTransition::Warn => warn!(
                log_source_id = %diagnostic.log_source_id,
                status = diagnostic.status.as_str(),
                detail = %diagnostic.detail,
                "collect target unresolved"
            ),
            ResolutionTransition::Recovered => info!(
                log_source_id = %diagnostic.log_source_id,
                detail = %diagnostic.detail,
                "collect target resolved"
            ),
        }
        last.insert(diagnostic.log_source_id.clone(), diagnostic.status);
    }
}

/// Abort a hung task and wait (bounded) until it has actually terminated.
///
/// `abort()` only queues cancellation — the task's resources (notably redb's
/// file locks) are not released until the runtime drops the task at its next
/// poll. Returning before that lets a restart of the same source race the old
/// instance's open and fail `DatabaseAlreadyOpen`. The reap wait is bounded:
/// a task wedged inside a synchronous section can't be cancelled mid-poll,
/// and correctness doesn't depend on the wait (redb is crash-safe; the
/// source is retried on the next config change).
async fn abort_and_reap(id: &str, mut handle: JoinHandle<()>, task: &'static str) {
    handle.abort();
    if tokio::time::timeout(Duration::from_secs(2), &mut handle)
        .await
        .is_err()
    {
        warn!(
            log_source_id = %id,
            task,
            "aborted task has not terminated; restarting this source may fail until it does"
        );
    }
}

/// Multi-source orchestrator for file and streaming log sources.
pub struct Orchestrator {
    pipelines: HashMap<String, ManagedPipeline>,
    streaming_sources: HashMap<String, ManagedStreamingSource>,
    data_dir: PathBuf,
    /// Shared agent identity stamped into shipped metadata for sources that opt
    /// in via `stamp_resource_identifier`. Read live at ship time, so a logpacer re-pin
    /// (applied in [`run`]) propagates without restarting pipelines.
    identity: AgentIdentity,
    counters: Option<Arc<AgentCounters>>,
    error_collector: Option<Arc<ErrorCollector>>,
    overflow: Option<Arc<SharedOverflow>>,
    /// Buffer/delivery tuning applied to every pipeline this orchestrator opens.
    /// Resolved from dynamic config (else env/default) and updated on config
    /// reload via [`set_tuning`]; a change triggers a pipeline restart.
    ///
    /// [`set_tuning`]: Self::set_tuning
    tuning: BufferTuning,
}

impl Orchestrator {
    pub fn new(data_dir: &Path, identity: AgentIdentity) -> Self {
        Self {
            pipelines: HashMap::new(),
            streaming_sources: HashMap::new(),
            data_dir: data_dir.to_path_buf(),
            identity,
            counters: None,
            error_collector: None,
            overflow: None,
            tuning: BufferTuning::default(),
        }
    }

    /// Update the buffer/delivery tuning applied to pipelines opened from now on.
    /// Existing pipelines keep their settings until restarted — callers that need
    /// the new values to take effect immediately must restart them (see [`run`]).
    ///
    /// [`run`]: run
    pub fn set_tuning(&mut self, tuning: BufferTuning) {
        self.tuning = tuning;
    }

    fn pipeline_config(&self) -> PipelineConfig {
        PipelineConfig {
            cache_size_bytes: self.tuning.cache_size_bytes,
            ship_batch_max_bytes: self.tuning.ship_batch_max_bytes,
            ..PipelineConfig::default()
        }
    }

    fn streaming_pipeline_config(&self) -> StreamingPipelineConfig {
        StreamingPipelineConfig {
            cache_size_bytes: self.tuning.cache_size_bytes,
            ship_batch_max_bytes: self.tuning.ship_batch_max_bytes,
            ..StreamingPipelineConfig::default()
        }
    }

    /// Per-source state directory — keyed by `log_source_id` (the durable
    /// source identity), never by the access locator. A path or container-id
    /// change for one source therefore reuses its own buffer/checkpoint and
    /// never disturbs another source's persisted state.
    fn source_data_dir(&self, log_source_id: &str) -> PathBuf {
        self.data_dir.join(sanitize_id(log_source_id))
    }

    pub fn with_overflow(mut self, overflow: Option<Arc<SharedOverflow>>) -> Self {
        self.overflow = overflow;
        self
    }

    pub fn with_monitoring(
        mut self,
        counters: Arc<AgentCounters>,
        error_collector: Arc<ErrorCollector>,
    ) -> Self {
        self.counters = Some(counters);
        self.error_collector = Some(error_collector);
        self
    }

    fn record_pipeline_error(&self, stream_id: &str, destination: &str, err: &str) {
        if let Some(ref ec) = self.error_collector {
            ec.record_error("collect", stream_id, destination, err);
        }
        if let Some(ref c) = self.counters {
            c.increment_errors();
        }
    }

    fn clear_pipeline_error(&self, stream_id: &str) {
        if let Some(ref ec) = self.error_collector {
            ec.clear_error("collect", stream_id);
        }
    }

    // queue_depth_bytes needs no periodic refresh: each pipeline's buffer
    // maintains the shared QueueDepthGauge itself (wired at start below).
    pub fn update_operational_stats(&self) {
        if let Some(ref c) = self.counters {
            c.set_streams_active(self.active_count() as u32);
        }
    }

    pub async fn reconcile(
        &mut self,
        file_streams: &[LogStreamConfig],
        streaming_sources: &[StreamingSourceConfig],
    ) {
        self.reconcile_file_streams(file_streams).await;
        self.reconcile_streaming_sources(streaming_sources).await;
    }

    async fn reconcile_file_streams(&mut self, streams: &[LogStreamConfig]) {
        let plan = plan_source_reconciliation(
            self.pipelines
                .iter()
                .map(|(id, source)| (id.as_str(), source.config_hash.as_str())),
            streams
                .iter()
                .map(|source| (source.log_source_id.as_str(), source.config_hash.as_str())),
        );

        for id in &plan.to_remove {
            info!(log_source_id = %id, "stopping removed file pipeline");
        }
        for id in &plan.to_restart {
            info!(log_source_id = %id, "restarting file pipeline (config changed)");
        }
        // All stops complete (concurrently) BEFORE the start loop: a restarted
        // pipeline must not open redb files the old instance still flocks.
        let mut to_stop = plan.to_remove;
        to_stop.extend(plan.to_restart);
        self.stop_file_pipelines(&to_stop).await;

        for stream in streams {
            if !self.pipelines.contains_key(&stream.log_source_id) {
                match self.start_file_pipeline(stream) {
                    Ok(()) => {
                        self.clear_pipeline_error(&stream.log_source_id);
                        info!(
                            log_source_id = %stream.log_source_id,
                            path = %stream.path,
                            "file pipeline started"
                        );
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        error!(
                            log_source_id = %stream.log_source_id,
                            path = %stream.path,
                            error = %msg,
                            "failed to start file pipeline"
                        );
                        self.record_pipeline_error(&stream.log_source_id, &stream.endpoint, &msg);
                    }
                }
            }
        }
    }

    async fn reconcile_streaming_sources(&mut self, streams: &[StreamingSourceConfig]) {
        let plan = plan_source_reconciliation(
            self.streaming_sources
                .iter()
                .map(|(id, source)| (id.as_str(), source.config_hash.as_str())),
            streams
                .iter()
                .map(|source| (source.log_source_id.as_str(), source.config_hash.as_str())),
        );

        for id in &plan.to_remove {
            info!(log_source_id = %id, "stopping removed streaming source");
        }
        for id in &plan.to_restart {
            info!(log_source_id = %id, "restarting streaming source (config changed)");
        }
        // All stops complete (concurrently) BEFORE the start loop: a restarted
        // source must not open redb files the old instance still flocks.
        let mut to_stop = plan.to_remove;
        to_stop.extend(plan.to_restart);
        self.stop_streaming_sources(&to_stop).await;

        for stream in streams {
            if !self.streaming_sources.contains_key(&stream.log_source_id) {
                match self.start_streaming_source(stream) {
                    Ok(()) => {
                        self.clear_pipeline_error(&stream.log_source_id);
                        info!(
                            log_source_id = %stream.log_source_id,
                            "streaming source started"
                        );
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        error!(
                            log_source_id = %stream.log_source_id,
                            error = %msg,
                            "failed to start streaming source"
                        );
                        self.record_pipeline_error(&stream.log_source_id, &stream.endpoint, &msg);
                    }
                }
            }
        }
    }

    fn start_file_pipeline(&mut self, stream: &LogStreamConfig) -> Result<(), PipelineError> {
        let shipper = Shipper::new(
            &stream.endpoint,
            &stream.archive_id,
            &stream.repo_id,
            stream
                .stamp_resource_identifier
                .then(|| self.identity.clone()),
        )
        .map_err(|e| PipelineError::Io(std::io::Error::other(e.to_string())))?;

        let source_dir = self.source_data_dir(&stream.log_source_id);
        std::fs::create_dir_all(&source_dir)?;

        let mut pipeline = if stream.source_format == FileSourceFormat::KubernetesCri {
            DeliveryPipeline::open_kubernetes(
                &stream.path,
                &source_dir,
                shipper,
                self.pipeline_config(),
                stream.multiline.as_ref(),
                &stream.log_source_id,
                self.overflow.clone(),
            )?
        } else {
            DeliveryPipeline::open_file_source(
                &stream.path,
                &source_dir,
                shipper,
                self.pipeline_config(),
                PipelineSourceOptions {
                    multiline: stream.multiline.as_ref(),
                    source_id: &stream.log_source_id,
                    overflow: self.overflow.clone(),
                    source_format: stream.source_format,
                },
            )?
        };

        if let Some(ref counters) = self.counters {
            pipeline.set_queue_gauge(counters.queue_depth_gauge());
        }

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            pipeline.run(&mut shutdown_rx).await;
        });

        self.pipelines.insert(
            stream.log_source_id.clone(),
            ManagedPipeline {
                config_hash: stream.config_hash.clone(),
                shutdown_tx,
                handle,
            },
        );

        Ok(())
    }

    fn start_streaming_source(
        &mut self,
        stream: &StreamingSourceConfig,
    ) -> Result<(), StreamingPipelineStartError> {
        let shipper = Shipper::new(
            &stream.endpoint,
            &stream.archive_id,
            &stream.repo_id,
            stream
                .stamp_resource_identifier
                .then(|| self.identity.clone()),
        )?;

        let source_dir = self.source_data_dir(&stream.log_source_id);
        std::fs::create_dir_all(&source_dir)?;

        let mut pipeline = StreamingDeliveryPipeline::open(
            &stream.log_source_id,
            &source_dir,
            shipper,
            self.streaming_pipeline_config(),
            self.overflow.clone(),
        )?;

        // Wire the gauge before the actor takes ownership — afterwards the
        // pipeline is unreachable from outside.
        if let Some(ref counters) = self.counters {
            pipeline.set_queue_gauge(counters.queue_depth_gauge());
        }

        let (handle, actor) = streaming_actor::spawn_streaming_actor(pipeline);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        // The reader task takes sole ownership of the StreamHandle — the
        // actor's shutdown signal is the reader dropping it, so no copy may
        // be retained here.
        let reader_config = stream.clone();
        let reader_shutdown = shutdown_tx.subscribe();
        let reader = tokio::spawn(async move {
            streaming_runner::run_streaming_reader(handle, reader_config, reader_shutdown).await;
        });

        self.streaming_sources.insert(
            stream.log_source_id.clone(),
            ManagedStreamingSource {
                config_hash: stream.config_hash.clone(),
                shutdown_tx,
                reader,
                actor,
            },
        );

        Ok(())
    }

    /// Stop one file pipeline task. Owns the managed entry, so the futures
    /// can run concurrently without borrowing the orchestrator. On timeout
    /// the task is aborted — a leaked task keeps redb's flock on the buffer
    /// and checkpoint files, and a restart of the same id would then fail
    /// `DatabaseAlreadyOpen` with no retry until the next config change.
    async fn stop_file(id: String, managed: ManagedPipeline) {
        let _ = managed.shutdown_tx.send(true);

        let mut handle = managed.handle;
        match tokio::time::timeout(Duration::from_secs(10), &mut handle).await {
            Ok(Ok(())) => info!(log_source_id = %id, "file pipeline stopped cleanly"),
            Ok(Err(e)) => error!(log_source_id = %id, error = %e, "file pipeline task panicked"),
            Err(_) => {
                warn!(log_source_id = %id, "file pipeline stop timed out after 10s, aborting");
                abort_and_reap(&id, handle, "file pipeline").await;
            }
        }
    }

    /// Stop one streaming source: reader first (its exit drops the only
    /// StreamHandle, which is what tells the actor to flush and stop), then
    /// the actor. Hung tasks are aborted — see [`stop_file`] for why leaking
    /// them wedges restarts.
    ///
    /// [`stop_file`]: Self::stop_file
    async fn stop_streaming(id: String, managed: ManagedStreamingSource) {
        let _ = managed.shutdown_tx.send(true);

        let mut reader = managed.reader;
        match tokio::time::timeout(Duration::from_secs(10), &mut reader).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(log_source_id = %id, error = %e, "streaming reader panicked"),
            Err(_) => {
                warn!(log_source_id = %id, "streaming reader stop timed out after 10s, aborting");
                abort_and_reap(&id, reader, "streaming reader").await;
            }
        }

        let mut actor = managed.actor;
        match tokio::time::timeout(Duration::from_secs(10), &mut actor).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(log_source_id = %id, error = %e, "streaming actor panicked"),
            Err(_) => {
                warn!(log_source_id = %id, "streaming actor stop timed out after 10s, aborting");
                abort_and_reap(&id, actor, "streaming actor").await;
            }
        }

        info!(log_source_id = %id, "streaming source stopped");
    }

    /// Stop the given file pipelines concurrently.
    async fn stop_file_pipelines(&mut self, ids: &[String]) {
        let stops: Vec<_> = ids
            .iter()
            .filter_map(|id| {
                self.pipelines
                    .remove(id)
                    .map(|managed| Self::stop_file(id.clone(), managed))
            })
            .collect();
        futures_util::future::join_all(stops).await;
    }

    /// Stop the given streaming sources concurrently.
    async fn stop_streaming_sources(&mut self, ids: &[String]) {
        let stops: Vec<_> = ids
            .iter()
            .filter_map(|id| {
                self.streaming_sources
                    .remove(id)
                    .map(|managed| Self::stop_streaming(id.clone(), managed))
            })
            .collect();
        futures_util::future::join_all(stops).await;
    }

    /// Stop every pipeline and streaming source, all concurrently. Wall time
    /// is the slowest single source, not the sum.
    pub async fn shutdown_all(&mut self) {
        info!(
            file_count = self.pipelines.len(),
            streaming_count = self.streaming_sources.len(),
            "shutting down all pipelines"
        );

        let file_stops: Vec<_> = self
            .pipelines
            .drain()
            .map(|(id, managed)| Self::stop_file(id, managed))
            .collect();
        let stream_stops: Vec<_> = self
            .streaming_sources
            .drain()
            .map(|(id, managed)| Self::stop_streaming(id, managed))
            .collect();

        tokio::join!(
            futures_util::future::join_all(file_stops),
            futures_util::future::join_all(stream_stops),
        );
    }

    pub fn active_count(&self) -> usize {
        self.pipelines.len() + self.streaming_sources.len()
    }

    pub fn active_ids(&self) -> Vec<&str> {
        self.pipelines
            .keys()
            .chain(self.streaming_sources.keys())
            .map(|s| s.as_str())
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
enum StreamingPipelineStartError {
    #[error("shipper: {0}")]
    Shipper(#[from] crate::common::EdgepacerError),
    #[error("pipeline: {0}")]
    Pipeline(#[from] crate::streaming_pipeline::StreamingPipelineError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn run(
    shared_config: SharedConfig,
    discovery_cache: SharedDiscoveryCache,
    data_dir: &Path,
    identity: AgentIdentity,
    counters: Arc<AgentCounters>,
    error_collector: Arc<ErrorCollector>,
    mut shutdown: watch::Receiver<bool>,
) {
    let overflow_dir = data_dir.join("overflow");
    let overflow = match SharedOverflow::new(&overflow_dir, 2048) {
        Ok(writer) => {
            info!(path = %overflow_dir.display(), "overflow writer enabled (2GB budget)");
            Some(Arc::new(writer))
        }
        Err(e) => {
            warn!(error = %e, "overflow writer disabled");
            None
        }
    };

    let mut orchestrator = Orchestrator::new(data_dir, identity.clone())
        .with_monitoring(counters, error_collector.clone())
        .with_overflow(overflow);
    let mut last_checksum = String::new();
    let mut last_tuning: Option<BufferTuning> = None;
    // Per-source last-logged resolution status, so unchanged misses don't
    // re-warn every reconcile (see [`log_collect_resolution`]).
    let mut resolution_log: HashMap<String, MatchStatus> = HashMap::new();

    info!("orchestrator started, watching for config changes");

    let poll_interval = Duration::from_secs(2);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = shutdown.changed() => {
                info!("orchestrator shutting down");
                orchestrator.shutdown_all().await;
                return;
            }
        }

        orchestrator.update_operational_stats();

        let reconcile = {
            let cfg = shared_config.read().await;
            match cfg.as_ref() {
                Some(unified) if unified.checksum != last_checksum => {
                    last_checksum = unified.checksum.clone();
                    // Apply any re-pinned identity before reconciling. This only
                    // updates the shared cell (read live at ship time), so it does
                    // not restart pipelines — a stamp-flag change does, via the
                    // per-source config hash.
                    if let Some(resource_identifier) = unified.resource_identifier() {
                        identity.apply_config(resource_identifier);
                    }
                    let cache = discovery_cache.read().await;
                    let resolved = config::resolved_collect_from_config(unified, &cache);
                    Some((
                        resolved.file_streams,
                        resolved.streaming_sources,
                        resolved.diagnostics,
                        BufferTuning::resolve(Some(unified)),
                    ))
                }
                _ => None,
            }
        };

        if let Some((file_streams, streaming_sources, diagnostics, tuning)) = reconcile {
            log_collect_resolution(&mut resolution_log, &diagnostics);

            // Changed buffer/delivery tuning requires reopening every buffer
            // (redb fixes the cache size at open). Drop all managed pipelines so
            // the reconcile below re-creates them with the new settings.
            if last_tuning != Some(tuning) {
                info!(
                    cache_bytes = tuning.cache_size_bytes,
                    ship_batch_max_bytes = tuning.ship_batch_max_bytes,
                    "buffer tuning changed, restarting pipelines to apply"
                );
                orchestrator.set_tuning(tuning);
                orchestrator.shutdown_all().await;
                last_tuning = Some(tuning);
            }

            if let Some(checksum) = shared_config
                .read()
                .await
                .as_ref()
                .map(|c| c.checksum.clone())
            {
                error_collector.set_config_version(&checksum);
            }

            info!(
                file_streams = file_streams.len(),
                streaming_sources = streaming_sources.len(),
                "config changed, reconciling pipelines"
            );
            orchestrator
                .reconcile(&file_streams, &streaming_sources)
                .await;
            orchestrator.update_operational_stats();
        }
    }
}

fn sanitize_id(id: &str) -> String {
    id.replace(['/', '\\', ':', '.', ' '], "_")
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogStreamConfig;

    fn test_identity() -> AgentIdentity {
        AgentIdentity::new("test-host".into())
    }

    fn sorted(mut values: Vec<String>) -> Vec<String> {
        values.sort();
        values
    }

    #[test]
    fn sanitize_source_ids() {
        assert_eq!(sanitize_id("source-123"), "source-123");
        assert_eq!(sanitize_id("src/path.log"), "src_path_log");
        assert_eq!(sanitize_id("a:b\\c"), "a_b_c");
    }

    #[test]
    fn config_hash_changes_on_endpoint() {
        let hash1 = LogStreamConfig::compute_hash(
            "/var/log/a.log",
            "http://relay:4317",
            "arc1",
            "repo1",
            None,
            FileSourceFormat::Plain,
            false,
        );
        let hash2 = LogStreamConfig::compute_hash(
            "/var/log/a.log",
            "http://relay:4318",
            "arc1",
            "repo1",
            None,
            FileSourceFormat::Plain,
            false,
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn reconcile_plan_noops_for_matching_sources() {
        let plan = plan_source_reconciliation(
            [("file-a", "hash-a"), ("stream-b", "hash-b")],
            [("file-a", "hash-a"), ("stream-b", "hash-b")],
        );

        assert!(plan.to_remove.is_empty());
        assert!(plan.to_restart.is_empty());
    }

    #[test]
    fn reconcile_plan_marks_removed_sources() {
        let plan = plan_source_reconciliation(
            [("removed", "hash-1"), ("kept", "hash-2")],
            [("kept", "hash-2")],
        );

        assert_eq!(sorted(plan.to_remove), vec!["removed"]);
        assert!(plan.to_restart.is_empty());
    }

    #[test]
    fn reconcile_plan_marks_config_changed_sources_for_restart() {
        let plan = plan_source_reconciliation(
            [("changed", "old-hash"), ("same", "hash-2")],
            [("changed", "new-hash"), ("same", "hash-2")],
        );

        assert!(plan.to_remove.is_empty());
        assert_eq!(sorted(plan.to_restart), vec!["changed"]);
    }

    #[tokio::test]
    async fn reconcile_starts_new_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        let mut orch = Orchestrator::new(dir.path(), test_identity());

        assert_eq!(orch.active_count(), 0);
        orch.reconcile(&[], &[]).await;
        assert_eq!(orch.active_count(), 0);
    }

    #[tokio::test]
    async fn shutdown_all_on_empty_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let mut orch = Orchestrator::new(dir.path(), test_identity());
        orch.reconcile(&[], &[]).await;
        orch.shutdown_all().await;
        assert_eq!(orch.active_count(), 0);
    }

    /// Stops must run concurrently: each fake pipeline task parks on a
    /// 3-party barrier, so sequential stops would deadlock until the first
    /// 10s stop-timeout fires, while concurrent stops complete immediately.
    #[tokio::test]
    async fn shutdown_all_stops_pipelines_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let mut orch = Orchestrator::new(dir.path(), test_identity());

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        for i in 0..3 {
            let barrier = barrier.clone();
            let (shutdown_tx, _) = watch::channel(false);
            orch.pipelines.insert(
                format!("barrier-{i}"),
                ManagedPipeline {
                    config_hash: "hash".into(),
                    shutdown_tx,
                    handle: tokio::spawn(async move {
                        barrier.wait().await;
                    }),
                },
            );
        }

        tokio::time::timeout(Duration::from_secs(5), orch.shutdown_all())
            .await
            .expect("concurrent shutdown must not serialize on the barrier");
        assert_eq!(orch.active_count(), 0);
    }

    /// A config-hash change must stop the old pipeline BEFORE starting the
    /// replacement in the same reconcile pass: redb flocks its files, so a
    /// still-running old instance makes the new open fail DatabaseAlreadyOpen
    /// (and reconcile only retries on the next checksum change).
    #[tokio::test]
    async fn reconcile_restart_replaces_pipeline_in_one_pass() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        std::fs::write(&log_path, "line\n").unwrap();

        let stream = |endpoint: &str| {
            let path = log_path.to_str().unwrap().to_string();
            LogStreamConfig {
                log_source_id: "restart-me".into(),
                path: path.clone(),
                endpoint: endpoint.to_string(),
                archive_id: "arc".into(),
                repo_id: "repo".into(),
                stamp_resource_identifier: false,
                source_format: FileSourceFormat::Plain,
                multiline: None,
                config_hash: LogStreamConfig::compute_hash(
                    &path,
                    endpoint,
                    "arc",
                    "repo",
                    None,
                    FileSourceFormat::Plain,
                    false,
                ),
            }
        };

        let mut orch = Orchestrator::new(dir.path(), test_identity());
        orch.reconcile(&[stream("http://127.0.0.1:9/old")], &[])
            .await;
        assert_eq!(orch.active_count(), 1);

        // Endpoint change → hash change → stop + start in one pass. If the
        // old instance still held the redb flocks, the new start would fail
        // and the source would vanish from the active set.
        orch.reconcile(&[stream("http://127.0.0.1:9/new")], &[])
            .await;
        assert_eq!(orch.active_count(), 1, "restarted pipeline must be running");

        orch.shutdown_all().await;
    }

    fn diag(id: &str, status: MatchStatus) -> CollectDiagnostic {
        CollectDiagnostic {
            log_source_id: id.into(),
            status,
            detail: String::new(),
        }
    }

    #[test]
    fn resolution_transitions_log_only_on_change() {
        use ResolutionTransition::{Recovered, Silent, Warn};

        // First sighting of a miss warns; an unchanged miss stays silent — this
        // is what kills the per-reconcile warning spam.
        assert_eq!(classify_transition(None, MatchStatus::NotFound), Warn);
        assert_eq!(
            classify_transition(Some(MatchStatus::NotFound), MatchStatus::NotFound),
            Silent
        );
        // Recovery after a miss is noted; a first-time match is normal (silent).
        assert_eq!(
            classify_transition(Some(MatchStatus::NotFound), MatchStatus::Matched),
            Recovered
        );
        assert_eq!(classify_transition(None, MatchStatus::Matched), Silent);
        // Ambiguity warns, and so does a fresh degrade from matched to missing.
        assert_eq!(classify_transition(None, MatchStatus::Ambiguous), Warn);
        assert_eq!(
            classify_transition(Some(MatchStatus::Matched), MatchStatus::NotFound),
            Warn
        );
        assert_eq!(
            classify_transition(Some(MatchStatus::Matched), MatchStatus::Matched),
            Silent
        );
    }

    #[test]
    fn resolution_log_forgets_removed_sources() {
        let mut log = HashMap::new();
        log_collect_resolution(&mut log, &[diag("a", MatchStatus::NotFound)]);
        assert_eq!(log.get("a"), Some(&MatchStatus::NotFound));

        // 'a' is gone from config and 'b' appears: 'a' is forgotten so that a
        // later re-add of 'a' warns afresh rather than being silently deduped.
        log_collect_resolution(&mut log, &[diag("b", MatchStatus::Matched)]);
        assert!(!log.contains_key("a"));
        assert_eq!(log.get("b"), Some(&MatchStatus::Matched));
    }

    #[test]
    fn source_state_dir_follows_source_id_across_locator_change() {
        let dir = tempfile::tempdir().unwrap();
        let orch = Orchestrator::new(dir.path(), test_identity());

        let with_path = |path: &str| LogStreamConfig {
            log_source_id: "collectable-9".into(),
            path: path.into(),
            endpoint: "http://relay/wire".into(),
            archive_id: "arc".into(),
            repo_id: "repo".into(),
            stamp_resource_identifier: false,
            source_format: FileSourceFormat::Plain,
            multiline: None,
            config_hash: String::new(),
        };

        let before = with_path("/var/log/app.log");
        let after = with_path("/data/relocated/app.log");

        // A rotated/relocated path keeps the same persisted-state dir, so the
        // buffer and checkpoint are reused rather than reset.
        assert_eq!(
            orch.source_data_dir(&before.log_source_id),
            orch.source_data_dir(&after.log_source_id),
        );
        // And the dir is derived from the id, never from the locator.
        assert_eq!(
            orch.source_data_dir(&before.log_source_id),
            dir.path().join("collectable-9"),
        );
        // Distinct sources never share a state dir, so one never resets another.
        assert_ne!(
            orch.source_data_dir("collectable-9"),
            orch.source_data_dir("collectable-10"),
        );
    }
}
