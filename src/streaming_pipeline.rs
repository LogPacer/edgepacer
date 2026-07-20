//! Streaming delivery pipeline — guaranteed delivery for non-replayable sources.
//!
//! Unlike `DeliveryPipeline` (file sources), streaming sources (Docker API, journald)
//! cannot replay from an arbitrary position. The durability model is different:
//!
//! **File source (M4)**: source is the replay authority. On crash, resume from checkpoint.
//! **Streaming source (M6)**: buffer is the replay authority. Data must be persisted to
//! disk BEFORE returning to the caller. On crash, drain unacked buffer entries.
//!
//! Flow: stream → enqueue to disk buffer → return Buffered → drain loop ships →
//!       delete on ack → checkpoint ONLY when buffer empty
//!
//! The "checkpoint only when buffer empty" invariant is critical:
//! A single `pending_checkpoint` slot can be overwritten by later batches. If we
//! persisted while entries remain, a crash could advance the checkpoint past
//! undelivered data. When the buffer is empty, ALL entries have been delivered,
//! so the latest checkpoint is safe to persist.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::buffer::{DiskBuffer, Durability};
use crate::checkpoint::{CheckpointError, CheckpointStore};
use crate::overflow::SharedOverflow;
use crate::shipper::{CappedShipOutcome, Shipper};
use crate::streaming_checkpoint::StreamingCheckpoint;

/// Result of [`StreamingDeliveryPipeline::prepare_drain`] — what the actor's
/// drain step should do next.
pub(crate) enum DrainPrep {
    /// Nothing to ship; idle housekeeping already ran.
    Idle,
    /// Lines peeked from the buffer, ready to encode + ship as an in-flight
    /// future, with their buffer sequences to delete once delivery is confirmed.
    Batch {
        lines: Vec<Vec<u8>>,
        sequences: Vec<u64>,
    },
}

/// Configuration for the streaming delivery pipeline.
pub struct StreamingPipelineConfig {
    /// How often to drain the buffer and ship batches.
    pub drain_interval: Duration,
    /// Maximum entries to ship per drain cycle.
    pub ship_batch_size: usize,
    /// Maximum buffer size in MB.
    pub buffer_max_mb: u64,
    /// redb page-cache cap for this pipeline's buffer, in bytes. Defaults to the
    /// env/compile-time value; the orchestrator overrides it from dynamic config.
    pub cache_size_bytes: usize,
    /// Soft cap on raw bytes shipped per batch, bounding the encoded payload
    /// under the receiver's request-size limit (shared with the file pipeline).
    pub ship_batch_max_bytes: usize,
    /// How long the shutdown drain may keep shipping before abandoning the
    /// remaining buffered entries (they replay on next start).
    pub shutdown_deadline: Duration,
}

impl Default for StreamingPipelineConfig {
    fn default() -> Self {
        Self {
            drain_interval: Duration::from_millis(100),
            ship_batch_size: 100,
            buffer_max_mb: 500,
            cache_size_bytes: crate::buffer::cache_size_bytes(),
            ship_batch_max_bytes: crate::pipeline::ship_batch_max_bytes_for(None),
            shutdown_deadline: Duration::from_secs(5),
        }
    }
}

/// Streaming delivery pipeline — enqueue-to-disk-first with buffer-empty checkpoint.
///
/// This type is intentionally separate from `DeliveryPipeline` (file sources).
/// The durability models are fundamentally different and should not be unified
/// behind a generic trait.
pub struct StreamingDeliveryPipeline {
    buffer: DiskBuffer,
    checkpoint_store: CheckpointStore,
    shipper: Shipper,
    config: StreamingPipelineConfig,
    source_id: String,
    overflow: Option<Arc<SharedOverflow>>,
    /// The most recent checkpoint to persist (written only when buffer is empty).
    /// This is the single-slot model matching Go's `pendingCheckpoint`.
    pending_checkpoint: Option<StreamingCheckpoint>,
}

/// Errors from the streaming pipeline.
#[derive(Debug, thiserror::Error)]
pub enum StreamingPipelineError {
    #[error("checkpoint: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("buffer: {0}")]
    Buffer(#[from] crate::buffer::BufferError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl StreamingDeliveryPipeline {
    /// Open a streaming pipeline for a source.
    pub fn open(
        source_id: &str,
        data_dir: &Path,
        shipper: Shipper,
        config: StreamingPipelineConfig,
        overflow: Option<Arc<SharedOverflow>>,
    ) -> Result<Self, StreamingPipelineError> {
        let cp_path = data_dir.join("streaming_checkpoints.sqlite");
        let buf_path = data_dir.join("streaming_buffer.sqlite");

        let checkpoint_store = CheckpointStore::open(&cp_path)?;
        let buffer = DiskBuffer::open_with_cache(
            &buf_path,
            config.buffer_max_mb,
            config.cache_size_bytes,
            // Non-replayable source — this buffer is the sole copy, so fsync
            // every commit.
            Durability::Full,
        )?;

        let buffered = buffer.count().unwrap_or(0);
        if buffered > 0 {
            info!(source_id, buffered, "replaying unacked streaming entries");
        }

        Ok(Self {
            buffer,
            checkpoint_store,
            shipper,
            config,
            source_id: source_id.to_string(),
            overflow,
            pending_checkpoint: None,
        })
    }

    /// Load the last persisted streaming checkpoint (for resume on reconnect).
    pub fn load_streaming_checkpoint(&self) -> Option<StreamingCheckpoint> {
        self.checkpoint_store
            .load_streaming(&self.source_id)
            .ok()
            .flatten()
    }

    /// Resume point for a reconnecting reader: the pending checkpoint when one
    /// is set, else the persisted one. The pending slot only ever covers lines
    /// that are durably in the buffer (commands are FIFO per sender), so
    /// resuming from it is crash-safe and avoids re-fetching lines we already
    /// hold; after a crash the pending slot is gone and resume falls back to
    /// the persisted checkpoint, exactly as before.
    pub(crate) fn resume_checkpoint(&self) -> Option<StreamingCheckpoint> {
        self.pending_checkpoint
            .clone()
            .or_else(|| self.load_streaming_checkpoint())
    }

    /// How often the actor's drain tick fires.
    pub(crate) fn drain_interval(&self) -> Duration {
        self.config.drain_interval
    }

    /// Enqueue a log line to the disk buffer. Returns immediately after persistence.
    ///
    /// This is the core streaming guarantee: data is durable in the buffer before
    /// this method returns. The caller can proceed knowing the line won't be lost.
    ///
    /// A blank line (empty or all-whitespace — e.g. between frames of a
    /// multi-line stack trace) is dropped here instead of buffered: the relay
    /// rejects it per-entry with "empty raw_text body", and shipping one
    /// forever re-adjudicates a rejected batch (see
    /// `shipper::ship_capped_with_shrink`). Treated as handled, not
    /// backpressure, so the caller's resume checkpoint still advances past it.
    ///
    /// Returns `true` if enqueued (or dropped as blank), `false` if buffer is
    /// full (backpressure).
    pub fn enqueue(&mut self, line: &[u8], timestamp_ns: i64) -> bool {
        if crate::common::is_blank_log_line(line) {
            return true;
        }
        match self.buffer.enqueue_batch(&[line.to_vec()], timestamp_ns) {
            Ok(_) => true,
            Err(crate::buffer::BufferError::Full { .. }) => {
                if self.spill_to_overflow(&[line.to_vec()], timestamp_ns) > 0 {
                    return true;
                }
                warn!(source_id = %self.source_id, "streaming buffer full, backpressure");
                false
            }
            Err(e) => {
                error!(source_id = %self.source_id, error = %e, "buffer enqueue failed");
                false
            }
        }
    }

    /// Enqueue a batch of log lines atomically. Blank lines are filtered out
    /// first — see [`Self::enqueue`].
    pub fn enqueue_batch(&mut self, lines: &[Vec<u8>], timestamp_ns: i64) -> bool {
        let lines: Vec<Vec<u8>> = lines
            .iter()
            .filter(|line| !crate::common::is_blank_log_line(line))
            .cloned()
            .collect();
        if lines.is_empty() {
            return true;
        }
        match self.buffer.enqueue_batch(&lines, timestamp_ns) {
            Ok(_) => true,
            Err(crate::buffer::BufferError::Full { .. }) => {
                if self.spill_to_overflow(&lines, timestamp_ns) > 0 {
                    return true;
                }
                warn!(source_id = %self.source_id, "streaming buffer full, backpressure");
                false
            }
            Err(e) => {
                error!(source_id = %self.source_id, error = %e, "buffer enqueue failed");
                false
            }
        }
    }

    fn spill_to_overflow(&self, lines: &[Vec<u8>], timestamp_ns: i64) -> usize {
        let Some(ref overflow) = self.overflow else {
            return 0;
        };
        // Outer wrap: one core handoff for the whole loop — the per-line
        // inner wraps hit run_blocking's free nested path.
        crate::common::run_blocking(|| {
            let mut spilled = 0usize;
            for line in lines {
                if overflow.write(&self.source_id, line, timestamp_ns).is_ok() {
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
                warn!(error = %e, "streaming overflow replay failed");
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

    /// Set the pending checkpoint. Will be persisted ONLY when buffer is empty.
    ///
    /// This overwrites any previous pending checkpoint (single-slot model).
    /// That's safe because we only persist when ALL entries have been delivered.
    pub fn set_pending_checkpoint(&mut self, checkpoint: StreamingCheckpoint) {
        self.pending_checkpoint = Some(checkpoint);
    }

    /// Cheap shipper handle for sending outside the pipeline lock.
    pub(crate) fn shipper_handle(&self) -> Shipper {
        self.shipper.clone()
    }

    /// The per-batch byte cap, for the lock-free ship step.
    pub(crate) fn ship_batch_max_bytes(&self) -> usize {
        self.config.ship_batch_max_bytes
    }

    /// Phase 1 of a drain: peek the next batch of lines. When the buffer is
    /// empty, runs idle housekeeping (overflow replay + checkpoint) and
    /// returns [`DrainPrep::Idle`]. Encoding + the network ship run as an
    /// in-flight future inside the actor so enqueue commands keep being
    /// processed while a slow destination is being retried — see
    /// [`confirm_drained`].
    ///
    /// [`confirm_drained`]: Self::confirm_drained
    pub(crate) fn prepare_drain(&mut self) -> DrainPrep {
        let entries = match self.buffer.peek(self.config.ship_batch_size) {
            Ok(e) if e.is_empty() => {
                self.replay_overflow_into_buffer();
                self.save_checkpoint_if_pending();
                return DrainPrep::Idle;
            }
            Ok(e) => e,
            Err(e) => {
                error!(error = %e, "streaming buffer peek failed");
                return DrainPrep::Idle;
            }
        };

        // Move the data out — the buffer still holds the authoritative copy
        // (peek doesn't delete), so no clone is needed.
        let (lines, sequences): (Vec<Vec<u8>>, Vec<u64>) =
            entries.into_iter().map(|e| (e.data, e.sequence)).unzip();
        DrainPrep::Batch { lines, sequences }
    }

    /// Phase 3 of a drain: after confirmed delivery, delete the shipped
    /// sequences and run buffer-empty housekeeping.
    pub(crate) fn confirm_drained(&mut self, sequences: &[u64]) -> bool {
        if let Err(e) = self.buffer.delete_sequences(sequences) {
            error!(error = %e, "failed to delete acked streaming entries");
            return false;
        }
        if self.buffer.is_empty().unwrap_or(false) {
            self.replay_overflow_into_buffer();
            self.save_checkpoint_if_pending();
        }
        true
    }

    /// Apply a completed ship attempt to the durable buffer.
    pub(crate) fn apply_drain_outcome(
        &mut self,
        outcome: CappedShipOutcome,
        sequences: &[u64],
    ) -> bool {
        match outcome {
            CappedShipOutcome::Delivered { count } => self.confirm_drained(&sequences[..count]),
            CappedShipOutcome::DroppedOversized { count } => {
                let deleted = self.confirm_drained(&sequences[..count]);
                warn!(
                    dropped = count,
                    "dropped oversized streaming entries after receiver 413"
                );
                deleted
            }
            CappedShipOutcome::RejectedAdjudicated { accepted, rejected } => {
                let deleted = self.confirm_drained(&sequences[..accepted + rejected]);
                warn!(
                    accepted,
                    rejected,
                    "dropped permanently-rejected streaming entries after full relay adjudication"
                );
                deleted
            }
            CappedShipOutcome::Deferred { reason } => {
                warn!(reason = ?reason, "streaming ship deferred, will retry");
                false
            }
        }
    }

    /// Single inline drain cycle — used by the shutdown drain, where blocking
    /// the actor on the ship is fine. The steady-state actor loop uses the
    /// [`prepare_drain`]/[`apply_drain_outcome`] split with an in-flight ship
    /// future instead.
    ///
    /// [`prepare_drain`]: Self::prepare_drain
    /// [`apply_drain_outcome`]: Self::apply_drain_outcome
    pub(crate) async fn drain_cycle(&mut self) {
        if let DrainPrep::Batch { lines, sequences } = self.prepare_drain() {
            let outcome = self
                .shipper
                .ship_capped_with_shrink(&lines, self.config.ship_batch_max_bytes)
                .await;
            self.apply_drain_outcome(outcome, &sequences);
        }
    }

    /// Persist the pending checkpoint — ONLY when buffer is confirmed empty.
    ///
    /// This is the buffer-empty checkpoint gating invariant. The API enforces it:
    /// this method is private and only called after confirming `buffer.is_empty()`.
    fn save_checkpoint_if_pending(&mut self) {
        let Some(checkpoint) = self.pending_checkpoint.take() else {
            return;
        };

        // Double-check: buffer must be empty.
        if !self.buffer.is_empty().unwrap_or(false) {
            // Put it back — not safe to persist yet.
            self.pending_checkpoint = Some(checkpoint);
            return;
        }

        // Persist under stream:{source_id} — only when buffer is empty.
        if let Err(e) = self
            .checkpoint_store
            .save_streaming(&self.source_id, &checkpoint)
        {
            error!(error = %e, "failed to save streaming checkpoint");
            self.pending_checkpoint = Some(checkpoint);
            return;
        }

        debug!(
            source_id = %self.source_id,
            "streaming checkpoint persisted (buffer was empty)"
        );
    }

    /// Drain remaining entries on shutdown with a deadline.
    ///
    /// Each cycle is bounded by the remaining deadline: the ship retries
    /// transient errors indefinitely, so without the timeout a dead relay
    /// would hang shutdown forever. An interrupted ship is safe to abandon —
    /// nothing is deleted until delivery is confirmed, so the entries replay
    /// on next start.
    pub(crate) async fn shutdown_drain(&mut self) {
        let deadline = tokio::time::Instant::now() + self.config.shutdown_deadline;

        while !self.buffer.is_empty().unwrap_or(true) {
            let now = tokio::time::Instant::now();
            if now >= deadline
                || tokio::time::timeout_at(deadline, self.drain_cycle())
                    .await
                    .is_err()
            {
                let remaining = self.buffer.count().unwrap_or(0);
                warn!(
                    source_id = %self.source_id,
                    remaining,
                    "streaming shutdown deadline, unshipped entries remain"
                );
                break;
            }
        }

        // Final checkpoint attempt.
        self.save_checkpoint_if_pending();

        info!(source_id = %self.source_id, "streaming pipeline stopped");
    }

    /// Attach the shared queue-depth gauge to this pipeline's durable buffer.
    pub fn set_queue_gauge(&mut self, gauge: crate::counters::QueueDepthGauge) {
        self.buffer.set_gauge(gauge);
    }

    /// Buffer pressure (0.0–1.0) for backpressure decisions.
    pub fn pressure(&self) -> f64 {
        self.buffer.pressure()
    }

    /// Whether the buffer is full.
    pub fn is_full(&self) -> bool {
        self.buffer.pressure() >= 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logpacer_wire::WireResponse;
    use prost::Message;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Note: full pipeline tests require a mock shipper and are in the integration test file.
    // Unit tests here cover the checkpoint gating logic.

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

    #[test]
    fn streaming_pipeline_config_defaults() {
        let cfg = StreamingPipelineConfig::default();
        assert_eq!(cfg.drain_interval, Duration::from_millis(100));
        assert_eq!(cfg.ship_batch_size, 100);
        assert_eq!(cfg.buffer_max_mb, 500);
    }

    #[test]
    fn confirm_drained_deletes_only_confirmed_prefix_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let shipper =
            Shipper::new("http://127.0.0.1:9", "arc_stream", "repo_stream", None).unwrap();
        let config = StreamingPipelineConfig {
            ship_batch_size: 3,
            ..Default::default()
        };
        let mut pipeline =
            StreamingDeliveryPipeline::open("stream-source", dir.path(), shipper, config, None)
                .unwrap();
        let input = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        assert!(pipeline.enqueue_batch(&input, 1000));

        let DrainPrep::Batch { lines, sequences } = pipeline.prepare_drain() else {
            panic!("expected buffered batch");
        };
        assert_eq!(lines, input);
        assert_eq!(sequences.len(), 3);

        pipeline.confirm_drained(&sequences[..2]);

        let remaining: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(remaining, vec![b"three".to_vec()]);
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
        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_stream",
            "repo_stream",
            None,
        )
        .unwrap();
        let config = StreamingPipelineConfig {
            ship_batch_size: 10,
            ship_batch_max_bytes: usize::MAX,
            ..Default::default()
        };
        let mut pipeline =
            StreamingDeliveryPipeline::open("stream-source", dir.path(), shipper, config, None)
                .unwrap();
        let input = vec![b"oversized".to_vec(), b"next".to_vec()];
        assert!(pipeline.enqueue_batch(&input, 1000));

        pipeline.drain_cycle().await;

        let remaining: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(remaining, vec![b"next".to_vec()]);
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
        let shipper = Shipper::new(
            &format!("{}/wire", mock_server.uri()),
            "arc_stream",
            "repo_stream",
            None,
        )
        .unwrap();
        let config = StreamingPipelineConfig {
            ship_batch_size: 10,
            ship_batch_max_bytes: usize::MAX,
            ..Default::default()
        };
        let mut pipeline =
            StreamingDeliveryPipeline::open("stream-source", dir.path(), shipper, config, None)
                .unwrap();
        let input = vec![b"one".to_vec(), b"two".to_vec()];
        assert!(pipeline.enqueue_batch(&input, 1000));

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

        // A second drain cycle must not re-ship anything: the buffer is
        // empty, so it runs idle housekeeping instead. The mock's
        // `expect(1)` above enforces this — a second POST would fail the
        // test on drop.
        pipeline.drain_cycle().await;
    }

    #[test]
    fn enqueue_skips_blank_lines_but_reports_them_as_handled() {
        // Regression test: a blank/whitespace-only line (e.g. between frames
        // of a multi-line stack trace) is dropped here instead of buffered —
        // the relay rejects it per-entry with "empty raw_text body". It must
        // report `true` (handled), not `false` (backpressure), so the
        // caller's resume checkpoint still advances past it.
        let dir = tempfile::tempdir().unwrap();
        let shipper = Shipper::new("http://127.0.0.1:9", "arc_blank", "repo_blank", None).unwrap();
        let mut pipeline = StreamingDeliveryPipeline::open(
            "stream-blank",
            dir.path(),
            shipper,
            StreamingPipelineConfig::default(),
            None,
        )
        .unwrap();

        assert!(pipeline.enqueue(b"real line", 1000));
        assert!(pipeline.enqueue(b"", 1000));
        assert!(pipeline.enqueue(b"   \t  ", 1000));
        assert!(pipeline.enqueue(b"another real line", 1000));

        let buffered: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(
            buffered,
            vec![b"real line".to_vec(), b"another real line".to_vec()],
            "blank lines never enter the buffer"
        );
    }

    #[test]
    fn enqueue_batch_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let shipper = Shipper::new(
            "http://127.0.0.1:9",
            "arc_blank_batch",
            "repo_blank_batch",
            None,
        )
        .unwrap();
        let mut pipeline = StreamingDeliveryPipeline::open(
            "stream-blank-batch",
            dir.path(),
            shipper,
            StreamingPipelineConfig::default(),
            None,
        )
        .unwrap();

        let input = vec![b"one".to_vec(), b"".to_vec(), b"two".to_vec()];
        assert!(pipeline.enqueue_batch(&input, 1000));

        let buffered: Vec<Vec<u8>> = pipeline
            .buffer
            .peek(10)
            .unwrap()
            .into_iter()
            .map(|entry| entry.data)
            .collect();
        assert_eq!(buffered, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn enqueue_batch_of_only_blank_lines_is_a_noop_not_backpressure() {
        // Negative control alongside the two tests above: an all-blank batch
        // still reports success (nothing to retry) and the buffer stays
        // empty rather than receiving any entries.
        let dir = tempfile::tempdir().unwrap();
        let shipper = Shipper::new(
            "http://127.0.0.1:9",
            "arc_all_blank",
            "repo_all_blank",
            None,
        )
        .unwrap();
        let mut pipeline = StreamingDeliveryPipeline::open(
            "stream-all-blank",
            dir.path(),
            shipper,
            StreamingPipelineConfig::default(),
            None,
        )
        .unwrap();

        let input = vec![b"".to_vec(), b"   ".to_vec()];
        assert!(pipeline.enqueue_batch(&input, 1000));
        assert!(pipeline.buffer.is_empty().unwrap());
    }
}
