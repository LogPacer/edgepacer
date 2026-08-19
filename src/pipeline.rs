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
use crate::cri::{DockerJsonReassembler, LogStream};
use crate::entry_assembler::{EntryAssembler, EventMetadata, LineContext};
use crate::overflow::SharedOverflow;
use crate::shipper::{CappedShipOutcome, ShipEntry, Shipper};
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
    DockerJson(FileTailer, DockerJsonReassembler),
    Kubernetes(ContainerReader),
}

struct TailedLine {
    payload: Vec<u8>,
    source_len: u64,
    /// Which container output stream produced the line. Plain files are
    /// single-stream and always `Unspecified`.
    stream: LogStream,
}

/// The exact Docker json-file payload the wire ships for a raw line — the
/// wrapper-stripped bytes. Exposed so the sampler's parity test can assert its
/// extraction equals the shipping path's byte-for-byte.
#[cfg(test)]
pub(crate) fn docker_json_wire_payload(raw: Vec<u8>) -> Vec<u8> {
    DockerJsonReassembler::default()
        .push(raw)
        .map(docker_json_tailed_line)
        .expect("a newline-terminated record is a complete line")
        .payload
}

impl LogTailer {
    fn read_lines(&mut self, max_lines: usize) -> std::io::Result<Vec<TailedLine>> {
        match self {
            Self::File(t) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .map(line_with_payload_as_source)
                .collect()),
            Self::DockerJson(t, reassembler) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .filter_map(|raw| reassembler.push(raw))
                .map(docker_json_tailed_line)
                .collect()),
            Self::Kubernetes(t) => Ok(t
                .read_lines(max_lines)?
                .into_iter()
                .map(container_tailed_line)
                .collect()),
        }
    }

    fn position(&self) -> crate::tailer::ReadPosition {
        match self {
            Self::File(t) | Self::DockerJson(t, _) => t.position(),
            Self::Kubernetes(t) => t.position(),
        }
    }

    /// Raw bytes the reader has consumed for fragments that have not yet
    /// completed a line. They sit inside `position().offset` but no emitted
    /// line spans them, so byte accounting must stay behind them.
    fn pending_partial_bytes(&self) -> u64 {
        match self {
            Self::File(_) => 0,
            Self::DockerJson(_, reassembler) => reassembler.pending_bytes(),
            Self::Kubernetes(t) => t.pending_partial_bytes(),
        }
    }
}

fn line_with_payload_as_source(payload: Vec<u8>) -> TailedLine {
    TailedLine {
        source_len: payload.len() as u64 + 1,
        payload: crate::ansi::strip_owned(payload),
        stream: LogStream::Unspecified,
    }
}

fn docker_json_tailed_line(line: crate::cri::DockerJsonLine) -> TailedLine {
    TailedLine {
        payload: crate::ansi::strip_owned(line.payload),
        source_len: line.source_len,
        stream: line.stream,
    }
}

fn container_tailed_line(line: crate::container_reader::ContainerLine) -> TailedLine {
    TailedLine {
        payload: line.message,
        source_len: line.source_len,
        stream: line.stream,
    }
}

fn file_tailer_for_format(source_format: FileSourceFormat, tailer: FileTailer) -> LogTailer {
    match source_format {
        FileSourceFormat::Plain => LogTailer::File(tailer),
        FileSourceFormat::DockerJson => {
            LogTailer::DockerJson(tailer, DockerJsonReassembler::default())
        }
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
    /// Optional multi-line assembly. When present, raw tailed lines are fed
    /// through the assembler for their stream and only complete events are
    /// enqueued to the buffer.
    assemblers: Option<StreamAssemblers>,
    /// Running estimate of the current tailer file offset used to assign
    /// per-line byte ranges to EntryAssembler. Updated after each read
    /// cycle from the tailer's authoritative `position()`.
    running_offset: u64,
}

/// An event drained from one assembler, before its stream is attached.
type AssembledEvent = (Vec<u8>, EventMetadata);
/// The same event, tagged with the stream whose assembler produced it.
type StreamEvent = (LogStream, Vec<u8>, EventMetadata);

/// One multi-line assembler per container output stream.
///
/// stdout and stderr are separate conversations that happen to share a file. A
/// single assembler would let a request logged on stdout land in the middle of
/// a stack trace on stderr and close it early — or worse, become one of its
/// lines. Each stream buffers its own in-progress event; assemblers are created
/// on first sight of a stream, so a plain file only ever owns one.
struct StreamAssemblers {
    patterns: Vec<String>,
    max_lines: usize,
    timeout: Duration,
    per_stream: Vec<(LogStream, EntryAssembler)>,
}

impl StreamAssemblers {
    /// Compile the pattern set once up front, so an invalid regex fails the
    /// pipeline at open rather than on the first line of a second stream.
    fn new(cfg: &MultilineConfig) -> Result<Self, regex::Error> {
        let timeout = Duration::from_secs(cfg.timeout_secs.max(1) as u64);
        let max_lines = cfg.max_lines as usize;
        let patterns = cfg.patterns().to_vec();
        let first = EntryAssembler::new(&patterns, max_lines, timeout)?;

        Ok(Self {
            patterns,
            max_lines,
            timeout,
            per_stream: vec![(LogStream::Unspecified, first)],
        })
    }

    fn for_stream(&mut self, stream: LogStream) -> &mut EntryAssembler {
        if let Some(index) = self
            .per_stream
            .iter()
            .position(|(candidate, _)| *candidate == stream)
        {
            return &mut self.per_stream[index].1;
        }

        let assembler = EntryAssembler::new(&self.patterns, self.max_lines, self.timeout)
            .expect("pattern set already compiled at pipeline open");
        self.per_stream.push((stream, assembler));
        &mut self
            .per_stream
            .last_mut()
            .expect("just pushed an assembler for this stream")
            .1
    }

    /// Drain every stream's assembler with `drain`, keeping each emitted
    /// event tagged with the stream whose assembler produced it.
    fn collect_ready(
        &mut self,
        drain: fn(&mut EntryAssembler) -> Option<AssembledEvent>,
    ) -> Vec<StreamEvent> {
        self.per_stream
            .iter_mut()
            .filter_map(|(stream, assembler)| {
                drain(assembler).map(|(event, meta)| (*stream, event, meta))
            })
            .collect()
    }

    /// The lowest start offset still buffered across every stream, or `None`
    /// when all streams are idle. The checkpoint may never pass it: an event
    /// completing on one stream says nothing about the lines another stream is
    /// still holding, and those lines have not been shipped.
    fn buffered_start_offset(&self) -> Option<u64> {
        self.per_stream
            .iter()
            .filter_map(|(_, assembler)| assembler.buffered_start_offset())
            .min()
    }
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

        let assemblers = match multiline {
            Some(cfg) => {
                Some(StreamAssemblers::new(cfg).map_err(PipelineError::InvalidMultilinePattern)?)
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
            assemblers,
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

        // Fragments the reader consumed but has not yet turned into a line sit
        // inside `pos.offset`; the line spanning them is still to come, so byte
        // accounting resumes behind them.
        let next_offset = pos
            .offset
            .saturating_sub(self.tailer.pending_partial_bytes());

        if self.assemblers.is_none() {
            // Fast path: no aggregation, enqueue raw lines as before.
            let count = lines.len();
            let batch_bytes: u64 = lines.iter().map(|l| l.source_len).sum();
            let start_offset = next_offset.saturating_sub(batch_bytes);

            self.enqueue_batch(lines, start_offset, next_offset, pos.inode, now_ns, count);
            self.running_offset = next_offset;
            return;
        }

        // Aggregation path: feed each line through its stream's assembler,
        // collecting any events they emit. An assembler only ever holds one
        // stream's lines, so the emitted event carries that stream.
        let mut running = self.running_offset;
        let mut emitted: Vec<StreamEvent> = Vec::new();
        for line in lines {
            let line_len = line.source_len;
            let ctx = LineContext {
                start_offset: running,
                end_offset: running + line_len,
                inode: pos.inode,
            };
            running += line_len;
            if let Some((event, meta)) = self
                .assemblers
                .as_mut()
                .expect("assemblers checked above")
                .for_stream(line.stream)
                .process(line.payload, ctx)
            {
                emitted.push((line.stream, event, meta));
            }
        }
        self.running_offset = next_offset;

        if emitted.is_empty() {
            return;
        }

        self.enqueue_events(emitted, pos.inode, now_ns);
    }

    /// Enqueue a batch of raw (non-aggregated) lines.
    ///
    /// Blank lines (e.g. the empty lines inside a multi-line Rails exception
    /// dump, when no multiline assembler is configured) are dropped here
    /// rather than buffered: the relay rejects them per-entry with "empty
    /// raw_text body", and shipping one forever re-adjudicates a rejected
    /// batch (see `shipper::ship_capped_with_shrink`). Offsets still advance
    /// across skipped lines so the tailer position and the tracked byte
    /// ranges of the lines that ARE kept stay correct.
    fn enqueue_batch(
        &mut self,
        records: Vec<TailedLine>,
        start_offset: u64,
        end_offset: u64,
        inode: u64,
        now_ns: i64,
        count: usize,
    ) {
        let mut lines: Vec<(Vec<u8>, LogStream)> = Vec::with_capacity(records.len());
        let mut kept_offsets: Vec<(u64, u64)> = Vec::with_capacity(records.len());
        let mut skipped = 0usize;
        let mut line_start_offset = start_offset;
        for line in records {
            let line_end_offset = line_start_offset + line.source_len;
            if crate::common::is_blank_log_line(&line.payload) {
                skipped += 1;
            } else {
                kept_offsets.push((line_start_offset, line_end_offset));
                lines.push((line.payload, line.stream));
            }
            line_start_offset = line_end_offset;
        }

        if lines.is_empty() {
            if skipped > 0 {
                debug!(
                    skipped,
                    offset = end_offset,
                    "all lines in batch were blank, none buffered"
                );
            }
            return;
        }

        match self.buffer.enqueue_stream_batch(&lines, now_ns) {
            Ok((buf_first, buf_last)) => {
                debug_assert_eq!(buf_last - buf_first + 1, lines.len() as u64);
                for (index, (line_start_offset, line_end_offset)) in
                    kept_offsets.into_iter().enumerate()
                {
                    let buffer_sequence = buf_first + index as u64;
                    self.tracker.track(
                        line_start_offset,
                        line_end_offset,
                        inode,
                        buffer_sequence,
                        buffer_sequence,
                    );
                }
                debug!(
                    lines = count,
                    skipped,
                    offset = end_offset,
                    "lines buffered"
                );
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
    fn enqueue_events(&mut self, events: Vec<StreamEvent>, inode: u64, now_ns: i64) {
        let count = events.len();
        let start_offset = events
            .first()
            .map(|(_, _, m)| m.first.start_offset)
            .unwrap_or(0);
        let end_offset = events
            .last()
            .map(|(_, _, m)| m.last.end_offset)
            .unwrap_or(start_offset);
        let event_ranges: Vec<(u64, u64)> = events
            .iter()
            .map(|(_, _, m)| (m.first.start_offset, m.last.end_offset))
            .collect();
        let bytes: Vec<(Vec<u8>, LogStream)> = events
            .into_iter()
            .map(|(stream, event, _)| (event, stream))
            .collect();

        match self.buffer.enqueue_stream_batch(&bytes, now_ns) {
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
        let Some(assemblers) = self.assemblers.as_mut() else {
            return;
        };
        let timed_out = assemblers.collect_ready(EntryAssembler::check_timeout);
        if timed_out.is_empty() {
            return;
        }
        let pos = self.tailer.position();
        self.enqueue_events(timed_out, pos.inode, now_nanos());
    }

    fn spill_to_overflow(&self, lines: &[(Vec<u8>, LogStream)], now_ns: i64) -> usize {
        let Some(ref overflow) = self.overflow else {
            return 0;
        };
        // Outer wrap: one core handoff for the whole loop — the per-line
        // inner wraps hit run_blocking's free nested path. The overflow store
        // keeps only the bytes; a replayed spill ships without its stream tag.
        crate::common::run_blocking(|| {
            let mut spilled = 0usize;
            for (line, _) in lines {
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
        let (lines, sequences): (Vec<ShipEntry>, Vec<u64>) = entries
            .into_iter()
            .map(|e| (ShipEntry::new(e.data, e.stream), e.sequence))
            .unzip();

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
            CappedShipOutcome::RejectedAdjudicated { accepted, rejected } => {
                let deleted = self.delete_and_ack_prefix(sequences, accepted + rejected);
                warn!(
                    accepted,
                    rejected,
                    "dropped permanently-rejected buffered entries after full relay adjudication"
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

    /// The furthest offset a checkpoint may reach right now.
    ///
    /// Delivering an event proves nothing about lines another stream is still
    /// buffering: with stdout and stderr interleaved, a stdout event can
    /// complete and be acked while an earlier stderr line sits unshipped in its
    /// assembler. Checkpointing past it would skip it on restart, so the
    /// checkpoint is capped at the oldest buffered line across all streams.
    fn checkpoint_ceiling(&self) -> Option<u64> {
        self.assemblers
            .as_ref()
            .and_then(StreamAssemblers::buffered_start_offset)
    }

    /// Flush checkpoint if consecutive-ack rule allows advancement.
    fn checkpoint_cycle(&mut self) {
        let Some(safe_cp) = self.tracker.safe_checkpoint() else {
            return;
        };

        let offset = match self.checkpoint_ceiling() {
            Some(ceiling) => safe_cp.offset.min(ceiling),
            None => safe_cp.offset,
        };

        let checkpoint = Checkpoint {
            path: self.file_path.clone(),
            offset,
            inode: safe_cp.inode,
            updated_at: SystemTime::now(),
            streaming: None,
        };

        if let Err(e) = self.checkpoint_store.save(&checkpoint) {
            error!(error = %e, "checkpoint save failed");
            return;
        }

        debug!(offset, inode = safe_cp.inode, "checkpoint advanced");
        self.tracker.drain_acked();
    }

    /// Graceful shutdown: drain remaining, then checkpoint.
    async fn shutdown(&mut self) {
        self.read_cycle(); // capture trailing lines

        // Flush every stream's in-progress event so none is lost.
        if let Some(assemblers) = self.assemblers.as_mut() {
            let remaining = assemblers.collect_ready(EntryAssembler::flush);
            if !remaining.is_empty() {
                let pos = self.tailer.position();
                self.enqueue_events(remaining, pos.inode, now_nanos());
            }
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

    /// One complete json-file line, as the Docker lane produces it.
    fn docker_json_line(raw: Vec<u8>) -> TailedLine {
        DockerJsonReassembler::default()
            .push(raw)
            .map(docker_json_tailed_line)
            .expect("a newline-terminated record is a complete line")
    }

    #[test]
    fn sanitize_paths() {
        assert_eq!(sanitize_filename("/var/log/app.log"), "var_log_app_log");
        assert_eq!(sanitize_filename("C:\\logs\\app.log"), "C__logs_app_log");
    }

    #[test]
    fn docker_json_payload_strips_wrapper_and_keeps_source_length() {
        let raw = br#"{"log":"http: TLS handshake error\n","stream":"stdout","time":"2026-07-04T23:35:09.566698461Z"}"#.to_vec();

        let line = docker_json_line(raw.clone());

        assert_eq!(line.payload, b"http: TLS handshake error");
        assert_eq!(line.source_len, raw.len() as u64 + 1);
    }

    /// Kill-test: a colourised source must reach the assembler as plain text.
    /// Before stripping, the leading SGR code sat in front of the timestamp, so
    /// a pattern mined from the source's plain text matched nothing and the
    /// whole stream folded into one event.
    #[test]
    fn coloured_lines_are_stripped_before_assembly_and_shipping() {
        let anchor = regex::Regex::new(r"^\d{4}-").unwrap();

        let coloured = "\x1b[2m2026-08-06T15:03:17Z\x1b[0m \x1b[32m INFO\x1b[0m msg";
        let plain = line_with_payload_as_source(coloured.as_bytes().to_vec());
        assert_eq!(plain.payload, b"2026-08-06T15:03:17Z  INFO msg");
        assert!(anchor.is_match(&String::from_utf8_lossy(&plain.payload)));
        assert_eq!(
            plain.source_len,
            coloured.len() as u64 + 1,
            "offsets still span the raw bytes read from the file"
        );

        // Docker escapes the ESC byte as \u001b inside the json-file wrapper.
        let raw = br#"{"log":"\u001b[36m2026-08-06T15:03:17Z\u001b[0m boot\n","stream":"stdout","time":"2026-08-06T15:03:17Z"}"#.to_vec();
        let source_len = raw.len() as u64 + 1;
        let wrapped = docker_json_line(raw);
        assert_eq!(wrapped.payload, b"2026-08-06T15:03:17Z boot");
        assert!(anchor.is_match(&String::from_utf8_lossy(&wrapped.payload)));
        assert_eq!(wrapped.source_len, source_len);
    }

    /// Kill-test: a container writing two programs' output into one json-file.
    /// Each stream must assemble on its own, and — the harder half — a stdout
    /// event completing and being delivered must NOT carry the checkpoint past
    /// a stderr line still buffered behind it. With one shared assembler the
    /// stdout line joined the stderr event; with per-stream assemblers but no
    /// checkpoint ceiling, the resume point skipped the buffered stderr line.
    #[tokio::test]
    async fn per_stream_assembly_keeps_the_checkpoint_behind_a_buffered_line() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("container-json.log");
        std::fs::write(&log_path, "").unwrap();

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_stream",
            "repo_stream",
            None,
        )
        .unwrap();
        let multiline =
            MultilineConfig::from_patterns(vec![r"^\d{4}-\d{2}-\d{2}".to_string()], 500, 5);
        let mut pipeline = DeliveryPipeline::open_file_source(
            log_path.to_str().unwrap(),
            dir.path(),
            shipper,
            PipelineConfig {
                // One entry per request keeps the mock's accepted count exact.
                ship_batch_size: 1,
                ship_batch_max: 1,
                ship_batch_max_bytes: usize::MAX,
                ..Default::default()
            },
            PipelineSourceOptions {
                multiline: Some(&multiline),
                source_id: "container-src",
                overflow: None,
                source_format: FileSourceFormat::DockerJson,
            },
        )
        .unwrap();

        // The tailer opened at end-of-file, so append the fixture now. stderr
        // opens an event, then stdout's two lines interleave with it.
        let record = |stream: &str, text: &str| {
            format!(
                "{}\n",
                serde_json::json!({
                    "log": format!("{text}\n"),
                    "stream": stream,
                    "time": "2026-08-06T15:03:17Z",
                })
            )
        };
        let records = [
            record("stderr", "2026-08-06 ERROR boom"),
            record("stdout", "2026-08-06 INFO one"),
            record("stdout", "2026-08-06 INFO two"),
        ];
        std::fs::write(&log_path, records.concat()).unwrap();
        let stderr_line_start = 0u64;
        let total_bytes: u64 = records.iter().map(|r| r.len() as u64).sum();

        pipeline.read_cycle();

        let buffered: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(
            buffered,
            vec![b"2026-08-06 INFO one".to_vec()],
            "the stdout event closes on the next stdout line and excludes the stderr line"
        );

        pipeline.drain_cycle().await;
        pipeline.checkpoint_cycle();

        let checkpoint = pipeline
            .checkpoint_store
            .load(&pipeline.file_path)
            .unwrap()
            .expect("checkpoint saved");
        assert_eq!(
            checkpoint.offset, stderr_line_start,
            "the delivered stdout event must not carry the checkpoint past the buffered stderr line"
        );

        // Shutdown flushes both streams; with nothing buffered the checkpoint
        // is free to reach the end of the file.
        pipeline.shutdown().await;

        let shipped: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert!(shipped.is_empty(), "shutdown drains the buffer");

        let checkpoint = pipeline
            .checkpoint_store
            .load(&pipeline.file_path)
            .unwrap()
            .expect("checkpoint saved");
        assert_eq!(
            checkpoint.offset, total_bytes,
            "once every stream is flushed the checkpoint reaches the file end"
        );
    }

    /// The wire envelope must say which container output stream wrote each
    /// entry: a stderr json-file record ships with `"stream":"stderr"` in
    /// metadata_json, while a plain-file line keeps the bare `{}` envelope.
    #[tokio::test]
    async fn wire_envelope_carries_the_stream_that_wrote_the_entry() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("container-json.log");
        std::fs::write(&log_path, "").unwrap();

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_env",
            "repo_env",
            None,
        )
        .unwrap();
        let mut pipeline = DeliveryPipeline::open_file_source(
            log_path.to_str().unwrap(),
            dir.path(),
            shipper,
            PipelineConfig {
                ship_batch_size: 1,
                ship_batch_max: 1,
                ship_batch_max_bytes: usize::MAX,
                ..Default::default()
            },
            PipelineSourceOptions {
                multiline: None,
                source_id: "envelope-src",
                overflow: None,
                source_format: FileSourceFormat::DockerJson,
            },
        )
        .unwrap();

        std::fs::write(
            &log_path,
            "{\"log\":\"boom\\n\",\"stream\":\"stderr\",\"time\":\"2026-08-19T09:00:00Z\"}\n",
        )
        .unwrap();
        pipeline.read_cycle();
        pipeline.drain_cycle().await;

        let request = &mock_server.received_requests().await.unwrap()[0];
        let shipped = crate::test_support::decode_gzip_wire_request(request);
        let metadata: Vec<Vec<u8>> = shipped
            .batches
            .iter()
            .filter_map(|batch| match batch.payload.as_ref()? {
                logpacer_wire::routed_batch::Payload::Logs(logs) => Some(logs),
                _ => None,
            })
            .flat_map(|logs| logs.entries.iter())
            .map(|entry| entry.envelope.as_ref().unwrap().metadata_json.clone())
            .collect();
        assert_eq!(
            metadata,
            vec![br#"{"stream":"stderr"}"#.to_vec()],
            "a stderr json-file record must ship with its stream in the envelope"
        );
    }

    /// A CRI message reassembled from `P` fragments ships as one entry tagged
    /// with its frames' stream — every fragment of a message shares it, so the
    /// first frame's tag is the entry's tag.
    #[tokio::test]
    async fn cri_reassembled_entry_ships_with_its_frames_stream() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let container_dir = dir.path().join("pod-logs");
        std::fs::create_dir_all(&container_dir).unwrap();
        std::fs::write(container_dir.join("0.log"), "").unwrap();

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_cri",
            "repo_cri",
            None,
        )
        .unwrap();
        let mut pipeline = DeliveryPipeline::open_kubernetes(
            container_dir.to_str().unwrap(),
            dir.path(),
            shipper,
            PipelineConfig {
                ship_batch_size: 1,
                ship_batch_max: 1,
                ship_batch_max_bytes: usize::MAX,
                ..Default::default()
            },
            None,
            "cri-src",
            None,
        )
        .unwrap();

        std::fs::write(
            container_dir.join("0.log"),
            "2026-08-19T09:00:00.000000000Z stdout P Hello, \n\
             2026-08-19T09:00:00.100000000Z stdout F world\n",
        )
        .unwrap();
        pipeline.read_cycle();
        pipeline.drain_cycle().await;

        let request = &mock_server.received_requests().await.unwrap()[0];
        let shipped = crate::test_support::decode_gzip_wire_request(request);
        let entries: Vec<&logpacer_wire::WireLogEvent> = shipped
            .batches
            .iter()
            .filter_map(|batch| match batch.payload.as_ref()? {
                logpacer_wire::routed_batch::Payload::Logs(logs) => Some(logs),
                _ => None,
            })
            .flat_map(|logs| logs.entries.iter())
            .collect();
        assert_eq!(entries.len(), 1, "the fragments rejoin into one entry");
        assert_eq!(
            entries[0].body,
            Some(logpacer_wire::wire_log_event::Body::RawText(
                "Hello, world".to_string()
            ))
        );
        assert_eq!(
            entries[0].envelope.as_ref().unwrap().metadata_json,
            br#"{"stream":"stdout"}"#.to_vec()
        );
    }

    /// Negative control for the stream envelope: a plain-file line has no
    /// container output stream and must keep the bare `{}` metadata exactly.
    #[tokio::test]
    async fn plain_file_entries_ship_without_a_stream_key() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        std::fs::write(&log_path, "").unwrap();
        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_plain",
            "repo_plain",
            None,
        )
        .unwrap();
        let mut pipeline = DeliveryPipeline::open(
            log_path.to_str().unwrap(),
            dir.path(),
            shipper,
            PipelineConfig {
                ship_batch_size: 1,
                ship_batch_max: 1,
                ship_batch_max_bytes: usize::MAX,
                ..Default::default()
            },
        )
        .unwrap();

        pipeline.enqueue_batch(
            tailed_lines(vec![b"plain line".to_vec()]),
            0,
            11,
            42,
            now_nanos(),
            1,
        );
        pipeline.drain_cycle().await;

        let request = &mock_server.received_requests().await.unwrap()[0];
        let shipped = crate::test_support::decode_gzip_wire_request(request);
        let entry = shipped
            .batches
            .iter()
            .filter_map(|batch| match batch.payload.as_ref()? {
                logpacer_wire::routed_batch::Payload::Logs(logs) => Some(logs),
                _ => None,
            })
            .flat_map(|logs| logs.entries.iter())
            .next()
            .unwrap();
        assert_eq!(
            entry.envelope.as_ref().unwrap().metadata_json,
            b"{}".to_vec(),
            "no stream and no identity stamping must keep the empty envelope"
        );
    }

    /// Kill-test: Docker chunks a line longer than 16K into several json
    /// records, only the last of which ends in a newline. The chunks must
    /// rejoin into one entry, and the bytes consumed by a chunk still waiting
    /// for its terminator must not count toward the checkpoint — otherwise the
    /// rejoined entry's range starts too late and the resume point overshoots
    /// the end of the file.
    #[tokio::test]
    async fn docker_json_split_line_rejoins_without_overshooting_the_checkpoint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
            )
            .mount(&mock_server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("chunked-json.log");
        std::fs::write(&log_path, "").unwrap();

        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_chunk",
            "repo_chunk",
            None,
        )
        .unwrap();
        let multiline =
            MultilineConfig::from_patterns(vec![r"^\d{4}-\d{2}-\d{2}".to_string()], 500, 5);
        let mut pipeline = DeliveryPipeline::open_file_source(
            log_path.to_str().unwrap(),
            dir.path(),
            shipper,
            PipelineConfig {
                ship_batch_size: 1,
                ship_batch_max: 1,
                ship_batch_max_bytes: usize::MAX,
                ..Default::default()
            },
            PipelineSourceOptions {
                multiline: Some(&multiline),
                source_id: "chunked-src",
                overflow: None,
                source_format: FileSourceFormat::DockerJson,
            },
        )
        .unwrap();

        let first = "{\"log\":\"2026-08-06 ERROR first half \",\"stream\":\"stdout\",\"time\":\"2026-08-06T15:03:17Z\"}\n";
        let second = "{\"log\":\"second half\\n\",\"stream\":\"stdout\",\"time\":\"2026-08-06T15:03:17Z\"}\n";

        std::fs::write(&log_path, first).unwrap();
        pipeline.read_cycle();
        assert!(
            pipeline.buffer.peek(10).unwrap().is_empty(),
            "a chunk without its terminating record is not a line yet"
        );

        std::fs::write(&log_path, format!("{first}{second}")).unwrap();
        pipeline.read_cycle();
        pipeline.shutdown().await;

        let checkpoint = pipeline
            .checkpoint_store
            .load(&pipeline.file_path)
            .unwrap()
            .expect("checkpoint saved");
        assert_eq!(
            checkpoint.offset,
            (first.len() + second.len()) as u64,
            "the rejoined entry spans both records and stops at the end of the file"
        );

        let request = &mock_server.received_requests().await.unwrap()[0];
        let shipped = crate::test_support::decode_gzip_wire_request(request);
        assert_eq!(
            shipped
                .batches
                .iter()
                .filter_map(|batch| match batch.payload.as_ref()? {
                    logpacer_wire::routed_batch::Payload::Logs(logs) => Some(logs),
                    _ => None,
                })
                .flat_map(|logs| logs.entries.iter())
                .map(|entry| match entry.body.as_ref().unwrap() {
                    logpacer_wire::wire_log_event::Body::RawText(text) => text.clone(),
                    other => panic!("expected raw text, got {other:?}"),
                })
                .collect::<Vec<String>>(),
            vec!["2026-08-06 ERROR first half second half".to_string()],
            "the chunks ship as one entry, not two"
        );
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

    #[tokio::test]
    async fn drain_cycle_advances_past_fully_adjudicated_rejection() {
        // Regression test for the reject-poison livelock: when the relay
        // fully adjudicates a batch (accepted + rejected == the batch size),
        // both the accepted and the permanently-rejected entries must leave
        // the buffer — otherwise the accepted entry re-ships every drain
        // cycle forever.
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                encoded_wire_response(1, 1, "one entry rejected"),
                "application/x-protobuf",
            ))
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

        let lines = vec![b"one".to_vec(), b"two".to_vec()];
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
        assert!(
            remaining.is_empty(),
            "both the accepted and rejected entries were adjudicated; buffer must be empty"
        );

        let safe_checkpoint = pipeline
            .tracker
            .safe_checkpoint()
            .expect("fully adjudicated batch produces a checkpoint");
        assert_eq!(
            safe_checkpoint.offset, end_offset,
            "checkpoint advances past the whole adjudicated batch"
        );

        // A second drain cycle must not re-ship anything: the buffer is
        // empty, so drain_cycle returns before sending a request. The mock's
        // `expect(1)` above enforces this — a second POST would fail the
        // test on drop.
        pipeline.drain_cycle().await;
    }

    #[tokio::test]
    async fn drain_cycle_skips_blank_lines_and_checkpoints_true_offset() {
        // Regression test: blank lines between multi-line exception frames
        // never enter the buffer (the relay rejects them with "empty
        // raw_text body"), and the checkpoint still lands at the TRUE
        // tailer offset — including the skipped blank lines' bytes — so a
        // restart doesn't re-read them.
        let mock_server = MockServer::start().await;

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
            "arc_blank",
            "repo_blank",
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
            b"first".to_vec(),
            b"".to_vec(),
            b"   ".to_vec(),
            b"second".to_vec(),
        ];
        let end_offset: u64 = lines.iter().map(|line| line.len() as u64 + 1).sum();
        pipeline.enqueue_batch(tailed_lines(lines), 0, end_offset, 7, now_nanos(), 4);

        let buffered: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(
            buffered,
            vec![b"first".to_vec(), b"second".to_vec()],
            "blank lines never enter the buffer"
        );

        pipeline.drain_cycle().await;

        let safe_checkpoint = pipeline
            .tracker
            .safe_checkpoint()
            .expect("delivered lines produce a checkpoint");
        assert_eq!(
            safe_checkpoint.offset, end_offset,
            "checkpoint reaches the true tailer offset, including skipped blank lines"
        );
    }
}
