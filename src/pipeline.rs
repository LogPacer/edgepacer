//! Guaranteed delivery pipeline for file-backed log sources.
//!
//! Integrates the M4 components into a single pipeline:
//!   tailer → disk buffer → shipper → checkpoint
//!
//! The pipeline decouples reading from shipping:
//! - **Read loop**: tailer reads lines, enqueues to disk buffer
//! - **Drain loop**: peeks from buffer, ships with retry, deletes on ack
//! - **Checkpoint loop**: advances checkpoint through consecutive acked batches
//!
//! On crash: buffer entries survive, checkpoint is at last confirmed position.
//! On restart: drain unacked buffer entries first, then resume reading from checkpoint.
//!
//! Invariants:
//! 1. Checkpoint only advances through consecutive confirmed deliveries (BatchTracker)
//! 2. Buffer entries deleted ONLY after confirmed delivery (peek-send-delete)
//! 3. Backpressure propagates: buffer full → stop reading
//! 4. Checkpoint advancement and source read continuation are separate concerns

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, error, info, warn};

use crate::batch_tracker::BatchTracker;
use crate::buffer::{DiskBuffer, Durability};
use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::config::{FileSourceFormat, MultilineConfig};
use crate::container_reader::ContainerReader;
use crate::entry_assembler::{EntryAssembler, EventMetadata, LineContext};
use crate::overflow::SharedOverflow;
use crate::shipper::{CappedShipOutcome, Shipper};
use crate::tailer::FileTailer;

/// Default per-batch byte cap, in MiB. Keeps the encoded payload comfortably
/// under common receiver request-size limits while staying large enough not to
/// fragment throughput. See [`ship_batch_max_bytes_for`].
const DEFAULT_SHIP_BATCH_MAX_MB: u64 = 4;
const MIN_SHIP_BATCH_MAX_MB: u64 = 1;

/// Resolve the per-batch byte cap. Precedence: explicit config override >
/// `EDGEPACER_SHIP_BATCH_MAX_MB` env var > [`DEFAULT_SHIP_BATCH_MAX_MB`], floored
/// at [`MIN_SHIP_BATCH_MAX_MB`] so a bad value can't stall delivery.
pub(crate) fn ship_batch_max_bytes_for(override_mb: Option<u64>) -> usize {
    let mb = override_mb
        .or_else(|| {
            std::env::var("EDGEPACER_SHIP_BATCH_MAX_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(DEFAULT_SHIP_BATCH_MAX_MB)
        .max(MIN_SHIP_BATCH_MAX_MB);
    (mb * 1024 * 1024) as usize
}

/// File-backed reader used by the delivery pipeline.
enum LogTailer {
    File(FileTailer),
    DockerJson(FileTailer),
    Kubernetes(ContainerReader),
}

struct TailedLine {
    payload: Vec<u8>,
    source_len: u64,
}

impl LogTailer {
    fn read_lines(&mut self, max_lines: usize) -> std::io::Result<Vec<TailedLine>> {
        match self {
            Self::File(t) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .map(line_with_payload_as_source)
                .collect()),
            Self::DockerJson(t) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .map(docker_json_payload_line)
                .collect()),
            Self::Kubernetes(t) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .map(line_with_payload_as_source)
                .collect()),
        }
    }

    fn position(&self) -> crate::tailer::ReadPosition {
        match self {
            Self::File(t) | Self::DockerJson(t) => t.position(),
            Self::Kubernetes(t) => t.position(),
        }
    }
}

fn line_with_payload_as_source(payload: Vec<u8>) -> TailedLine {
    TailedLine {
        source_len: payload.len() as u64 + 1,
        payload,
    }
}

fn docker_json_payload_line(raw: Vec<u8>) -> TailedLine {
    let source_len = raw.len() as u64 + 1;
    let payload = crate::cri::parse_docker_json_line(&raw)
        .map(|(payload, _)| payload)
        .unwrap_or(raw);
    TailedLine {
        payload,
        source_len,
    }
}

fn file_tailer_for_format(source_format: FileSourceFormat, tailer: FileTailer) -> LogTailer {
    match source_format {
        FileSourceFormat::Plain => LogTailer::File(tailer),
        FileSourceFormat::DockerJson => LogTailer::DockerJson(tailer),
        FileSourceFormat::KubernetesCri => {
            unreachable!("Kubernetes CRI sources use ContainerReader")
        }
    }
}

/// Configuration for the delivery pipeline.
pub struct PipelineConfig {
    /// How often to poll the file for new lines.
    pub read_interval: Duration,
    /// How often to drain the buffer and ship batches.
    pub drain_interval: Duration,
    /// Maximum lines per read batch.
    pub batch_size: usize,
    /// Minimum entries to ship per drain cycle (used when buffer pressure is low).
    pub ship_batch_size: usize,
    /// Maximum entries to ship per drain cycle (used under backpressure).
    pub ship_batch_max: usize,
    /// Soft cap on the raw bytes shipped per batch. Bounds the encoded payload
    /// so it stays under the receiver's request-size limit — without it, the
    /// adaptive batch can grow past the limit and the receiver rejects it (413),
    /// which would otherwise retry the same oversized payload forever.
    pub ship_batch_max_bytes: usize,
    /// How often to flush checkpoint to disk.
    pub checkpoint_interval: Duration,
    /// How often the multiline assembler's idle timeout is checked.
    /// Ignored when aggregation is disabled.
    pub assembler_check_interval: Duration,
    /// Maximum buffer size in MB.
    pub buffer_max_mb: u64,
    /// redb page-cache cap for this pipeline's buffer, in bytes. Defaults to the
    /// env/compile-time value; the orchestrator overrides it from dynamic config.
    pub cache_size_bytes: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            read_interval: Duration::from_millis(200),
            drain_interval: Duration::from_millis(50),
            batch_size: 50_000,
            ship_batch_size: 1000,
            ship_batch_max: 50_000,
            ship_batch_max_bytes: ship_batch_max_bytes_for(None),
            checkpoint_interval: Duration::from_millis(500),
            assembler_check_interval: Duration::from_secs(1),
            buffer_max_mb: 500,
            cache_size_bytes: crate::buffer::cache_size_bytes(),
        }
    }
}

/// The guaranteed delivery pipeline.
pub struct DeliveryPipeline {
    tailer: LogTailer,
    buffer: DiskBuffer,
    checkpoint_store: CheckpointStore,
    tracker: BatchTracker,
    shipper: Shipper,
    config: PipelineConfig,
    file_path: String,
    source_id: String,
    overflow: Option<Arc<SharedOverflow>>,
    /// Whether reads are paused due to backpressure.
    blocked: bool,
    /// Optional multi-line assembler. When present, raw tailed lines are
    /// fed through it and only complete events are enqueued to the buffer.
    assembler: Option<EntryAssembler>,
    /// Running estimate of the current tailer file offset used to assign
    /// per-line byte ranges to EntryAssembler. Updated after each read
    /// cycle from the tailer's authoritative `position()`.
    running_offset: u64,
}

/// Grouped inputs for opening a pipeline. Keeps the internal open path to a
/// single cohesive parameter (clippy::too_many_arguments) while the public
/// `open*` methods stay ergonomic.
struct PipelineOpenParams<'a> {
    file_path: &'a str,
    data_dir: &'a Path,
    shipper: Shipper,
    config: PipelineConfig,
    source: PipelineSourceOptions<'a>,
}

pub(crate) struct PipelineSourceOptions<'a> {
    pub(crate) multiline: Option<&'a MultilineConfig>,
    pub(crate) source_id: &'a str,
    pub(crate) overflow: Option<Arc<SharedOverflow>>,
    pub(crate) source_format: FileSourceFormat,
}

impl<'a> PipelineSourceOptions<'a> {
    fn plain(source_id: &'a str) -> Self {
        Self {
            multiline: None,
            source_id,
            overflow: None,
            source_format: FileSourceFormat::Plain,
        }
    }
}

impl Default for PipelineSourceOptions<'_> {
    fn default() -> Self {
        Self {
            multiline: None,
            source_id: "",
            overflow: None,
            source_format: FileSourceFormat::Plain,
        }
    }
}

impl<'a> PipelineOpenParams<'a> {
    fn new(
        file_path: &'a str,
        data_dir: &'a Path,
        shipper: Shipper,
        config: PipelineConfig,
    ) -> Self {
        Self {
            file_path,
            data_dir,
            shipper,
            config,
            source: PipelineSourceOptions::plain(file_path),
        }
    }

    fn with_source(mut self, source: PipelineSourceOptions<'a>) -> Self {
        self.source = source;
        self
    }
}

impl DeliveryPipeline {
    /// Create a new pipeline, resuming from checkpoint if one exists.
    pub fn open(
        file_path: &str,
        data_dir: &Path,
        shipper: Shipper,
        config: PipelineConfig,
    ) -> Result<Self, PipelineError> {
        Self::open_with_multiline_inner(PipelineOpenParams::new(
            file_path, data_dir, shipper, config,
        ))
    }

    /// Attach the shared queue-depth gauge to this pipeline's durable buffer.
    pub fn set_queue_gauge(&mut self, gauge: crate::counters::QueueDepthGauge) {
        self.buffer.set_gauge(gauge);
    }

    /// Create a pipeline that tails a K8s container log directory (CRI format).
    pub fn open_kubernetes(
        container_dir: &str,
        data_dir: &Path,
        shipper: Shipper,
        config: PipelineConfig,
        multiline: Option<&MultilineConfig>,
        source_id: &str,
        overflow: Option<Arc<SharedOverflow>>,
    ) -> Result<Self, PipelineError> {
        Self::open_with_multiline_inner(
            PipelineOpenParams::new(container_dir, data_dir, shipper, config).with_source(
                PipelineSourceOptions {
                    multiline,
                    source_id,
                    overflow,
                    source_format: FileSourceFormat::KubernetesCri,
                },
            ),
        )
    }

    /// Create a new pipeline with optional multi-line aggregation.
    pub(crate) fn open_file_source(
        file_path: &str,
        data_dir: &Path,
        shipper: Shipper,
        config: PipelineConfig,
        source: PipelineSourceOptions<'_>,
    ) -> Result<Self, PipelineError> {
        Self::open_with_multiline_inner(PipelineOpenParams {
            file_path,
            data_dir,
            shipper,
            config,
            source,
        })
    }

    fn open_with_multiline_inner(params: PipelineOpenParams<'_>) -> Result<Self, PipelineError> {
        let PipelineOpenParams {
            file_path,
            data_dir,
            shipper,
            config,
            source:
                PipelineSourceOptions {
                    multiline,
                    source_id,
                    overflow,
                    source_format,
                },
        } = params;
        let cp_path = data_dir.join("checkpoints.sqlite");
        let buf_path = data_dir.join(format!("buffer_{}.sqlite", sanitize_filename(file_path)));

        let checkpoint_store = CheckpointStore::open(&cp_path)?;
        let buffer = DiskBuffer::open_with_cache(
            &buf_path,
            config.buffer_max_mb,
            config.cache_size_bytes,
            // File source is the replay authority — NORMAL is durable enough
            // and far faster than fsync-per-commit.
            Durability::Normal,
        )?;

        // Resume tailer from checkpoint if one exists.
        let tailer = if source_format == FileSourceFormat::KubernetesCri {
            match checkpoint_store.load(file_path)? {
                Some(cp) => {
                    info!(
                        path = file_path,
                        offset = cp.offset,
                        "resuming K8s container reader from checkpoint"
                    );
                    LogTailer::Kubernetes(ContainerReader::open_with_checkpoint(
                        Path::new(file_path),
                        &cp,
                    )?)
                }
                None => {
                    info!(path = file_path, "no checkpoint, tailing K8s logs from end");
                    LogTailer::Kubernetes(ContainerReader::open(Path::new(file_path))?)
                }
            }
        } else {
            match checkpoint_store.load(file_path)? {
                Some(cp) => {
                    info!(
                        path = file_path,
                        offset = cp.offset,
                        inode = cp.inode,
                        "resuming from checkpoint"
                    );
                    file_tailer_for_format(
                        source_format,
                        FileTailer::open_with_checkpoint(Path::new(file_path), &cp)?,
                    )
                }
                None => {
                    info!(path = file_path, "no checkpoint, tailing from end");
                    file_tailer_for_format(source_format, FileTailer::open(Path::new(file_path))?)
                }
            }
        };

        let assembler = match multiline {
            Some(cfg) => {
                let timeout = Duration::from_secs(cfg.timeout_secs.max(1) as u64);
                Some(
                    EntryAssembler::new(&cfg.start_pattern, cfg.max_lines as usize, timeout)
                        .map_err(PipelineError::InvalidMultilinePattern)?,
                )
            }
            None => None,
        };

        let starting_offset = tailer.position().offset;

        Ok(Self {
            tailer,
            buffer,
            checkpoint_store,
            tracker: BatchTracker::new(),
            shipper,
            config,
            file_path: file_path.to_string(),
            source_id: source_id.to_string(),
            overflow,
            blocked: false,
            assembler,
            running_offset: starting_offset,
        })
    }

    /// Run the pipeline until shutdown.
    pub async fn run(&mut self, shutdown: &mut tokio::sync::watch::Receiver<bool>) {
        info!(path = %self.file_path, "delivery pipeline started");

        let buffered = self.buffer.count().unwrap_or(0);
        if buffered > 0 {
            info!(buffered, "replaying unacked entries from previous session");
        }

        let mut read_tick = tokio::time::interval(self.config.read_interval);
        let mut drain_tick = tokio::time::interval(self.config.drain_interval);
        let mut cp_tick = tokio::time::interval(self.config.checkpoint_interval);
        let mut asm_tick = tokio::time::interval(self.config.assembler_check_interval);

        // Skip immediate ticks
        read_tick.tick().await;
        drain_tick.tick().await;
        cp_tick.tick().await;
        asm_tick.tick().await;

        loop {
            tokio::select! {
                _ = read_tick.tick() => self.read_cycle(),
                _ = drain_tick.tick() => self.drain_cycle().await,
                _ = cp_tick.tick() => self.checkpoint_cycle(),
                _ = asm_tick.tick() => self.assembler_check_cycle(),
                _ = shutdown.changed() => {
                    info!("pipeline shutting down");
                    self.shutdown().await;
                    return;
                }
            }
        }
    }

    /// Read new lines from tailer, enqueue to buffer.
    ///
    /// When a multi-line assembler is configured, raw lines are fed through
    /// it and only completed events are enqueued. The batch's end_offset
    /// comes from the LAST emitted event's metadata — not from the tailer's
    /// current position — so the checkpoint cannot advance past lines still
    /// buffered in the assembler's in-progress event.
    fn read_cycle(&mut self) {
        if self.blocked {
            return;
        }

        // Blocking-pool bound: a backlogged file yields up to a full batch
        // (50k lines) of cold reads in one cycle.
        let batch_size = self.config.batch_size;
        let lines = match crate::common::run_blocking(|| self.tailer.read_lines(batch_size)) {
            Ok(l) if l.is_empty() => return,
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "tailer read failed");
                return;
            }
        };

        let pos = self.tailer.position();
        let now_ns = now_nanos();

        if self.assembler.is_none() {
            // Fast path: no aggregation, enqueue raw lines as before.
            let count = lines.len();
            let batch_bytes: u64 = lines.iter().map(|l| l.source_len).sum();
            let start_offset = pos.offset.saturating_sub(batch_bytes);

            self.enqueue_batch(lines, start_offset, pos.offset, pos.inode, now_ns, count);
            self.running_offset = pos.offset;
            return;
        }

        // Aggregation path: feed each line through the assembler, collecting
        // any events it emits. Per-line byte ranges are approximated using
        // `line.len() + 1` for the trailing newline — matches the rest of
        // pipeline.rs's offset arithmetic.
        let mut running = self.running_offset;
        let mut emitted: Vec<(Vec<u8>, EventMetadata)> = Vec::new();
        for line in lines {
            let line_len = line.source_len;
            let ctx = LineContext {
                start_offset: running,
                end_offset: running + line_len,
                inode: pos.inode,
            };
            running += line_len;
            if let Some(event) = self
                .assembler
                .as_mut()
                .expect("assembler checked above")
                .process(line.payload, ctx)
            {
                emitted.push(event);
            }
        }
        self.running_offset = pos.offset;

        if emitted.is_empty() {
            return;
        }

        self.enqueue_events(emitted, pos.inode, now_ns);
    }

    /// Enqueue a batch of raw (non-aggregated) lines.
    fn enqueue_batch(
        &mut self,
        records: Vec<TailedLine>,
        start_offset: u64,
        end_offset: u64,
        inode: u64,
        now_ns: i64,
        count: usize,
    ) {
        let source_lengths: Vec<u64> = records.iter().map(|line| line.source_len).collect();
        let lines: Vec<Vec<u8>> = records.into_iter().map(|line| line.payload).collect();

        match self.buffer.enqueue_batch(&lines, now_ns) {
            Ok((buf_first, buf_last)) => {
                debug_assert_eq!(buf_last - buf_first + 1, lines.len() as u64);
                let mut line_start_offset = start_offset;
                for (index, source_len) in source_lengths.iter().enumerate() {
                    let line_end_offset = line_start_offset + *source_len;
                    let buffer_sequence = buf_first + index as u64;
                    self.tracker.track(
                        line_start_offset,
                        line_end_offset,
                        inode,
                        buffer_sequence,
                        buffer_sequence,
                    );
                    line_start_offset = line_end_offset;
                }
                debug!(lines = count, offset = end_offset, "lines buffered");
            }
            Err(crate::buffer::BufferError::Full { .. }) => {
                let spilled = self.spill_to_overflow(&lines, now_ns);
                if spilled > 0 {
                    warn!(
                        spilled,
                        total = lines.len(),
                        "buffer full, spilled lines to overflow"
                    );
                }
                if spilled < lines.len() {
                    warn!("buffer full, pausing reads");
                    self.blocked = true;
                }
            }
            Err(e) => {
                error!(error = %e, "buffer enqueue failed");
            }
        }
    }

    /// Enqueue a batch of multi-line events. The batch's start/end offsets
    /// span from the first event's first-line start to the last event's
    /// last-line end — NOT the tailer's current position, which may already
    /// be past lines still buffered in the assembler.
    fn enqueue_events(&mut self, events: Vec<(Vec<u8>, EventMetadata)>, inode: u64, now_ns: i64) {
        let count = events.len();
        let start_offset = events
            .first()
            .map(|(_, m)| m.first.start_offset)
            .unwrap_or(0);
        let end_offset = events
            .last()
            .map(|(_, m)| m.last.end_offset)
            .unwrap_or(start_offset);
        let event_ranges: Vec<(u64, u64)> = events
            .iter()
            .map(|(_, m)| (m.first.start_offset, m.last.end_offset))
            .collect();
        let bytes: Vec<Vec<u8>> = events.into_iter().map(|(e, _)| e).collect();

        match self.buffer.enqueue_batch(&bytes, now_ns) {
            Ok((buf_first, buf_last)) => {
                debug_assert_eq!(buf_last - buf_first + 1, event_ranges.len() as u64);
                for (index, (event_start_offset, event_end_offset)) in
                    event_ranges.into_iter().enumerate()
                {
                    let buffer_sequence = buf_first + index as u64;
                    self.tracker.track(
                        event_start_offset,
                        event_end_offset,
                        inode,
                        buffer_sequence,
                        buffer_sequence,
                    );
                }
                debug!(
                    events = count,
                    offset = end_offset,
                    "multiline events buffered"
                );
            }
            Err(crate::buffer::BufferError::Full { .. }) => {
                let spilled = self.spill_to_overflow(&bytes, now_ns);
                if spilled > 0 {
                    warn!(
                        spilled,
                        total = bytes.len(),
                        "buffer full, spilled events to overflow"
                    );
                }
                if spilled < bytes.len() {
                    warn!("buffer full, pausing reads");
                    self.blocked = true;
                }
            }
            Err(e) => {
                error!(error = %e, "buffer enqueue failed");
            }
        }
    }

    /// Periodic idle-timeout check for the multi-line assembler. Flushes
    /// the in-progress event if no new line has arrived within
    /// `timeout_secs`, so idle events don't sit buffered forever.
    fn assembler_check_cycle(&mut self) {
        let Some(asm) = self.assembler.as_mut() else {
            return;
        };
        if let Some(event) = asm.check_timeout() {
            let pos = self.tailer.position();
            self.enqueue_events(vec![event], pos.inode, now_nanos());
        }
    }

    fn spill_to_overflow(&self, lines: &[Vec<u8>], now_ns: i64) -> usize {
        let Some(ref overflow) = self.overflow else {
            return 0;
        };
        // Outer wrap: one core handoff for the whole loop — the per-line
        // inner wraps hit run_blocking's free nested path.
        crate::common::run_blocking(|| {
            let mut spilled = 0usize;
            for line in lines {
                if overflow.write(&self.source_id, line, now_ns).is_ok() {
                    spilled += 1;
                }
            }
            spilled
        })
    }

    fn replay_overflow_into_buffer(&mut self) {
        let Some(ref overflow) = self.overflow else {
            return;
        };
        if !overflow.has_overflow(&self.source_id) {
            return;
        }
        let batch = match overflow.replay_batch(&self.source_id, 1000) {
            Ok(b) if b.is_empty() => return,
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "overflow replay failed");
                return;
            }
        };
        // Outer wrap: this re-enqueues up to 1000 entries, each currently a
        // separate fsync'd commit.
        // TODO: batch into one commit — needs a per-line-timestamp
        // enqueue_batch (timestamps differ per replayed entry).
        crate::common::run_blocking(|| {
            for (ts, data) in batch {
                if self.buffer.enqueue_batch(&[data], ts).is_err() {
                    break;
                }
            }
        })
    }

    /// Adaptive batch size based on buffer pressure.
    fn adaptive_batch_size(&self) -> usize {
        let pressure = self.buffer.pressure();
        let min = self.config.ship_batch_size;
        let max = self.config.ship_batch_max;

        if pressure < 0.1 {
            min
        } else {
            // Linear scale: 10% pressure → min, 100% pressure → max
            let t = ((pressure - 0.1) / 0.9).min(1.0);
            min + ((max - min) as f64 * t) as usize
        }
    }

    /// Drain buffer: peek → byte-cap → ship (shrinking on 413) → delete on ack.
    async fn drain_cycle(&mut self) {
        let batch_size = self.adaptive_batch_size();
        let entries = match self.buffer.peek(batch_size) {
            Ok(e) if e.is_empty() => {
                if self.blocked {
                    info!("buffer drained, resuming reads");
                    self.blocked = false;
                }
                return;
            }
            Ok(e) => e,
            Err(e) => {
                error!(error = %e, "buffer peek failed");
                return;
            }
        };

        // Move data out of entries — no clone. The buffer still has the
        // authoritative copy (peek doesn't delete), so we can consume these.
        let (lines, sequences): (Vec<Vec<u8>>, Vec<u64>) =
            entries.into_iter().map(|e| (e.data, e.sequence)).unzip();

        // Ship a byte-capped prefix, shrinking if the receiver rejects it as too
        // large. `handled` is how many leading entries went out (delivered, or a
        // lone over-limit entry dropped); entries beyond it stay buffered for the
        // next cycle (peek didn't delete them). 0 means a transient failure.
        let outcome = self
            .shipper
            .ship_capped_with_shrink(&lines, self.config.ship_batch_max_bytes)
            .await;
        if !self.apply_drain_outcome(outcome, &sequences) {
            return;
        }
        if self.blocked && self.buffer.pressure() < 0.9 {
            info!("buffer pressure released, resuming reads");
            self.blocked = false;
        }
        if self.buffer.is_empty().unwrap_or(false) {
            self.replay_overflow_into_buffer();
        }
    }

    fn apply_drain_outcome(&mut self, outcome: CappedShipOutcome, sequences: &[u64]) -> bool {
        match outcome {
            CappedShipOutcome::Delivered { count } => self.delete_and_ack_prefix(sequences, count),
            CappedShipOutcome::DroppedOversized { count } => {
                let deleted = self.delete_and_ack_prefix(sequences, count);
                warn!(
                    dropped = count,
                    "dropped oversized buffered entries after receiver 413"
                );
                deleted
            }
            CappedShipOutcome::Deferred { reason } => {
                warn!(reason = ?reason, "ship attempt deferred, will retry on next drain cycle");
                false
            }
        }
    }

    fn delete_and_ack_prefix(&mut self, sequences: &[u64], count: usize) -> bool {
        if let Err(e) = self.buffer.delete_sequences(&sequences[..count]) {
            error!(error = %e, "failed to delete acked entries");
            return false;
        }
        self.ack_handled_prefix(count);
        true
    }

    fn ack_handled_prefix(&mut self, handled: usize) {
        for _ in 0..handled {
            if let Some(seq) = self.tracker.oldest_pending_sequence() {
                self.tracker.ack(seq);
            }
        }
    }

    /// Flush checkpoint if consecutive-ack rule allows advancement.
    fn checkpoint_cycle(&mut self) {
        let Some(safe_cp) = self.tracker.safe_checkpoint() else {
            return;
        };

        let checkpoint = Checkpoint {
            path: self.file_path.clone(),
            offset: safe_cp.offset,
            inode: safe_cp.inode,
            updated_at: SystemTime::now(),
            streaming: None,
        };

        if let Err(e) = self.checkpoint_store.save(&checkpoint) {
            error!(error = %e, "checkpoint save failed");
            return;
        }

        debug!(
            offset = safe_cp.offset,
            inode = safe_cp.inode,
            "checkpoint advanced"
        );
        self.tracker.drain_acked();
    }

    /// Graceful shutdown: drain remaining, then checkpoint.
    async fn shutdown(&mut self) {
        self.read_cycle(); // capture trailing lines

        // Flush any in-progress multi-line event so it isn't lost.
        if let Some(asm) = self.assembler.as_mut()
            && let Some(event) = asm.flush()
        {
            let pos = self.tailer.position();
            self.enqueue_events(vec![event], pos.inode, now_nanos());
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.buffer.is_empty().unwrap_or(true) {
            if tokio::time::Instant::now() >= deadline {
                let remaining = self.buffer.count().unwrap_or(0);
                warn!(remaining, "shutdown deadline, unshipped entries remain");
                break;
            }
            self.drain_cycle().await;
        }

        self.checkpoint_cycle();
        info!(path = %self.file_path, "pipeline stopped");
    }
}

/// Pipeline errors.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("checkpoint: {0}")]
    Checkpoint(#[from] crate::checkpoint::CheckpointError),
    #[error("buffer: {0}")]
    Buffer(#[from] crate::buffer::BufferError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid multiline start_pattern regex: {0}")]
    InvalidMultilinePattern(#[from] regex::Error),
}

/// Current wall-clock time as nanoseconds since UNIX_EPOCH.
fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

/// Sanitize a file path for use as a filename component.
fn sanitize_filename(path: &str) -> String {
    path.replace(['/', '\\', ':', '.'], "_")
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use logpacer_wire::WireResponse;
    use prost::Message;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn encoded_wire_response(accepted: u32, rejected: u32, error_message: &str) -> Vec<u8> {
        let response = WireResponse {
            accepted,
            rejected,
            error_message: error_message.to_string(),
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        buf
    }

    fn tailed_lines(lines: Vec<Vec<u8>>) -> Vec<TailedLine> {
        lines.into_iter().map(line_with_payload_as_source).collect()
    }

    #[test]
    fn sanitize_paths() {
        assert_eq!(sanitize_filename("/var/log/app.log"), "var_log_app_log");
        assert_eq!(sanitize_filename("C:\\logs\\app.log"), "C__logs_app_log");
    }

    #[test]
    fn docker_json_payload_strips_wrapper_and_keeps_source_length() {
        let raw = br#"{"log":"http: TLS handshake error\n","stream":"stdout","time":"2026-07-04T23:35:09.566698461Z"}"#.to_vec();

        let line = docker_json_payload_line(raw.clone());

        assert_eq!(line.payload, b"http: TLS handshake error");
        assert_eq!(line.source_len, raw.len() as u64 + 1);
    }

    #[tokio::test]
    async fn drain_cycle_deletes_and_checkpoints_only_delivered_prefix_after_shrink() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(2, 0, ""), "application/x-protobuf"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        std::fs::write(&log_path, "").unwrap();
        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_file",
            "repo_file",
            None,
        )
        .unwrap();
        let config = PipelineConfig {
            ship_batch_size: 10,
            ship_batch_max: 10,
            ship_batch_max_bytes: usize::MAX,
            ..Default::default()
        };
        let mut pipeline =
            DeliveryPipeline::open(log_path.to_str().unwrap(), dir.path(), shipper, config)
                .unwrap();

        let lines = vec![
            b"a".to_vec(),
            b"bb".to_vec(),
            b"ccc".to_vec(),
            b"dddd".to_vec(),
        ];
        let end_offset = lines.iter().map(|line| line.len() as u64 + 1).sum();
        pipeline.enqueue_batch(tailed_lines(lines), 0, end_offset, 42, now_nanos(), 4);

        pipeline.drain_cycle().await;

        let remaining: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(remaining, vec![b"ccc".to_vec(), b"dddd".to_vec()]);

        let safe_checkpoint = pipeline
            .tracker
            .safe_checkpoint()
            .expect("delivered prefix produces a checkpoint");
        assert_eq!(
            safe_checkpoint.offset, 5,
            "only 'a\\n' and 'bb\\n' were delivered"
        );

        pipeline.checkpoint_cycle();
        let checkpoint = pipeline
            .checkpoint_store
            .load(&pipeline.file_path)
            .unwrap()
            .expect("checkpoint saved");
        assert_eq!(checkpoint.offset, 5);
        assert_eq!(checkpoint.inode, 42);
    }

    #[tokio::test]
    async fn drain_cycle_drops_only_single_oversized_prefix() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
            .expect(2)
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        std::fs::write(&log_path, "").unwrap();
        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_file",
            "repo_file",
            None,
        )
        .unwrap();
        let config = PipelineConfig {
            ship_batch_size: 10,
            ship_batch_max: 10,
            ship_batch_max_bytes: usize::MAX,
            ..Default::default()
        };
        let mut pipeline =
            DeliveryPipeline::open(log_path.to_str().unwrap(), dir.path(), shipper, config)
                .unwrap();

        let lines = vec![b"oversized".to_vec(), b"next".to_vec()];
        let end_offset = lines.iter().map(|line| line.len() as u64 + 1).sum();
        pipeline.enqueue_batch(tailed_lines(lines), 0, end_offset, 42, now_nanos(), 2);

        pipeline.drain_cycle().await;

        let remaining: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(remaining, vec![b"next".to_vec()]);

        let safe_checkpoint = pipeline
            .tracker
            .safe_checkpoint()
            .expect("dropped prefix produces a checkpoint");
        assert_eq!(
            safe_checkpoint.offset, 10,
            "only the impossible oversized record was dropped"
        );
    }
}
