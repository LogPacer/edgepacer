//! Streaming pipeline actor — single-owner task replacing the shared mutex.
//!
//! One actor task per streaming source OWNS its `StreamingDeliveryPipeline`;
//! producers (Docker/journald readers, the eBPF runner) talk to it through a
//! bounded mpsc [`StreamHandle`]. No lock anywhere on the streaming path.
//!
//! The ship runs as an **in-flight future inside the actor's select loop**, so
//! enqueue commands keep being processed while a slow or flapping destination
//! is being retried — the ship's retry policy is unlimited, and if it blocked
//! the loop, the channel (not the disk buffer) would become the backpressure
//! point. This preserves the property the previous narrow-lock design existed
//! for.
//!
//! Correctness hinges on per-sender FIFO: the task that enqueues lines must be
//! the task that sets the checkpoints covering them. A `SetCheckpoint` is then
//! always processed after every `Enqueue` it covers, so the pending checkpoint
//! never points past a line that is not yet durably in the buffer. Lines lost
//! from the channel on a crash are strictly after the last persisted
//! checkpoint and are re-fetched on resume (Docker `since` / journald cursor).
//!
//! Shutdown is channel closure: when every `StreamHandle` is dropped, the
//! actor drains the remaining commands (mpsc yields them before reporting
//! closed), settles any in-flight ship, and runs the deadline-bounded
//! shutdown drain.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::shipper::CappedShipOutcome;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_pipeline::{DrainPrep, StreamingDeliveryPipeline};

/// Commands a producer can send to the pipeline actor.
pub(crate) enum StreamCommand {
    /// Persist one log line to the disk buffer.
    Enqueue { line: Vec<u8>, timestamp_ns: i64 },
    /// Set the pending resume checkpoint (persisted only when buffer empty).
    SetCheckpoint(StreamingCheckpoint),
    /// Query the resume point: pending checkpoint, else persisted.
    GetCheckpoint(oneshot::Sender<Option<StreamingCheckpoint>>),
}

/// How many commands may queue between a producer and the actor. Small on
/// purpose: lines waiting here are not yet durable, so this bounds the
/// crash-loss window (which resume re-fetches from the source anyway).
pub const STREAM_CHANNEL_CAPACITY: usize = 128;

/// How long the actor waits for an in-flight ship to settle at shutdown.
/// Bounded because the ship retries transient errors indefinitely.
const SHUTDOWN_INFLIGHT_DEADLINE: Duration = Duration::from_secs(3);

/// How long a blocked line may gate intake after every handle is gone before
/// the actor gives up waiting for the in-flight ship to free space and forces
/// the bounded shutdown path. Together with the in-flight settle cap and the
/// shutdown drain deadline this keeps worst-case actor exit inside the
/// orchestrator's stop budget.
const WEDGED_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Maximum wait for the final checkpoint command a reader sends on its way
/// out — a backpressured actor must not wedge reader shutdown. Losing it only
/// costs duplicates on the next resume, never data.
pub const FINAL_CHECKPOINT_SEND_DEADLINE: Duration = Duration::from_secs(1);

/// The actor is gone (its task exited or panicked); the source should stop.
#[derive(Debug)]
pub struct StreamingActorGone;

/// Producer-side handle to a streaming pipeline actor.
///
/// Cloneable, but checkpoint ordering is per-sender: the task that enqueues
/// lines MUST be the task that sets the checkpoints covering them.
#[derive(Clone)]
pub struct StreamHandle {
    tx: mpsc::Sender<StreamCommand>,
}

impl StreamHandle {
    /// Persist a line via the actor. Awaits channel capacity — this is the
    /// backpressure point for readers. Returns `false` only when the actor is
    /// gone; the caller should stop streaming.
    pub async fn enqueue(&self, line: Vec<u8>, timestamp_ns: i64) -> bool {
        self.tx
            .send(StreamCommand::Enqueue { line, timestamp_ns })
            .await
            .is_ok()
    }

    /// Non-blocking enqueue for producers that must never stall (eBPF capture
    /// loop). Returns `false` when the channel is full or the actor is gone.
    pub fn try_enqueue(&self, line: Vec<u8>, timestamp_ns: i64) -> bool {
        self.tx
            .try_send(StreamCommand::Enqueue { line, timestamp_ns })
            .is_ok()
    }

    /// Set the pending resume checkpoint. Returns `false` when the actor is gone.
    pub async fn set_checkpoint(&self, checkpoint: StreamingCheckpoint) -> bool {
        self.tx
            .send(StreamCommand::SetCheckpoint(checkpoint))
            .await
            .is_ok()
    }

    /// Best-effort final checkpoint on the producer's way out, bounded by
    /// [`FINAL_CHECKPOINT_SEND_DEADLINE`].
    pub async fn set_final_checkpoint(&self, checkpoint: StreamingCheckpoint) {
        let _ = tokio::time::timeout(
            FINAL_CHECKPOINT_SEND_DEADLINE,
            self.set_checkpoint(checkpoint),
        )
        .await;
    }

    /// The resume point for a (re)connecting reader: the actor's pending
    /// checkpoint when one is set, else the persisted one.
    pub async fn checkpoint(&self) -> Result<Option<StreamingCheckpoint>, StreamingActorGone> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(StreamCommand::GetCheckpoint(reply_tx))
            .await
            .is_err()
        {
            return Err(StreamingActorGone);
        }
        reply_rx.await.map_err(|_| StreamingActorGone)
    }
}

/// Spawn the single-owner actor task for a streaming pipeline.
///
/// The returned [`StreamHandle`] is the only way to reach the pipeline; when
/// the last clone is dropped the actor flushes (bounded) and exits.
pub fn spawn_streaming_actor(
    pipeline: StreamingDeliveryPipeline,
) -> (StreamHandle, JoinHandle<()>) {
    spawn_with_capacity(pipeline, STREAM_CHANNEL_CAPACITY)
}

pub(crate) fn spawn_with_capacity(
    pipeline: StreamingDeliveryPipeline,
    capacity: usize,
) -> (StreamHandle, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(capacity);
    let task = tokio::spawn(run_actor(pipeline, rx));
    (StreamHandle { tx }, task)
}

type ShipFuture = Pin<Box<dyn Future<Output = CappedShipOutcome> + Send>>;

async fn run_actor(mut pipeline: StreamingDeliveryPipeline, mut rx: mpsc::Receiver<StreamCommand>) {
    // Shipper handle + byte cap are stable for the pipeline's life — capture
    // once so each batch's ship future is independent of the pipeline.
    let shipper = pipeline.shipper_handle();
    let max_bytes = pipeline.ship_batch_max_bytes();

    let mut tick = tokio::time::interval(pipeline.drain_interval());
    // An in-flight ship can outlast many ticks; don't burst-fire afterwards.
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // The ship for the currently peeked batch, with the sequences to delete
    // on confirmation. While `Some`, the drain tick is gated off so the same
    // sequences are never peeked twice.
    let mut inflight: Option<ShipFuture> = None;
    let mut inflight_sequences: Vec<u64> = Vec::new();

    // A line the buffer (and overflow) had no room for. While `Some`, command
    // intake is gated off, so the bounded channel backpressures the reader —
    // stall, never drop.
    let mut blocked: Option<(Vec<u8>, i64)> = None;

    // When the channel is closed but a blocked line gates intake, `recv()` is
    // never polled and closure can't end the loop. If the wedge outlasts the
    // grace (the in-flight ship isn't freeing space — e.g. relay down), force
    // the bounded shutdown path instead of hanging forever.
    let mut wedged_since: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            cmd = rx.recv(), if blocked.is_none() => match cmd {
                Some(StreamCommand::Enqueue { line, timestamp_ns }) => {
                    if !pipeline.enqueue(&line, timestamp_ns) {
                        blocked = Some((line, timestamp_ns));
                    }
                }
                Some(StreamCommand::SetCheckpoint(checkpoint)) => {
                    pipeline.set_pending_checkpoint(checkpoint);
                }
                Some(StreamCommand::GetCheckpoint(reply)) => {
                    let _ = reply.send(pipeline.resume_checkpoint());
                }
                // All handles dropped and the channel is drained: shutdown.
                None => break,
            },
            outcome = poll_inflight(&mut inflight), if inflight.is_some() => {
                inflight = None;
                pipeline.apply_drain_outcome(outcome, &inflight_sequences);
                retry_blocked(&mut pipeline, &mut blocked);
            }
            _ = tick.tick() => {
                retry_blocked(&mut pipeline, &mut blocked);
                if inflight.is_none()
                    && let DrainPrep::Batch { lines, sequences } = pipeline.prepare_drain()
                {
                    let shipper = shipper.clone();
                    inflight_sequences = sequences;
                    inflight = Some(Box::pin(async move {
                        shipper.ship_capped_with_shrink(&lines, max_bytes).await
                    }));
                }
                if blocked.is_some() && rx.is_closed() {
                    let since = *wedged_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= WEDGED_SHUTDOWN_GRACE {
                        warn!("blocked with all handles gone; forcing bounded shutdown");
                        break;
                    }
                } else {
                    wedged_since = None;
                }
            }
        }
    }

    // Settle any in-flight ship before the shutdown drain — a completed but
    // unapplied delivery would otherwise be re-shipped (duplicates). Bounded:
    // the ship retries indefinitely, and an abandoned attempt is safe (the
    // undeleted entries replay on next start).
    if let Some(future) = inflight.take() {
        match tokio::time::timeout(SHUTDOWN_INFLIGHT_DEADLINE, future).await {
            Ok(outcome) => {
                pipeline.apply_drain_outcome(outcome, &inflight_sequences);
            }
            Err(_) => info!("abandoning in-flight ship at shutdown"),
        }
    }
    retry_blocked(&mut pipeline, &mut blocked);
    if blocked.is_none() {
        drain_remaining_commands(&mut pipeline, &mut rx);
    }
    pipeline.shutdown_drain().await;
    if blocked.is_some() {
        warn!("dropping one blocked line at shutdown (buffer and overflow full)");
    }
}

/// Process commands left in the channel when the actor exited via the
/// blocked-line escape (the normal exit path only fires once the channel is
/// already empty). Stops at the first line the buffer cannot take: every
/// later checkpoint may cover that dropped line, and persisting one would
/// skip the line on resume — so nothing after the drop may be applied.
fn drain_remaining_commands(
    pipeline: &mut StreamingDeliveryPipeline,
    rx: &mut mpsc::Receiver<StreamCommand>,
) {
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            StreamCommand::Enqueue { line, timestamp_ns } => {
                if !pipeline.enqueue(&line, timestamp_ns) {
                    warn!("dropping remaining commands at shutdown (buffer and overflow full)");
                    return;
                }
            }
            StreamCommand::SetCheckpoint(checkpoint) => {
                pipeline.set_pending_checkpoint(checkpoint);
            }
            StreamCommand::GetCheckpoint(reply) => {
                let _ = reply.send(pipeline.resume_checkpoint());
            }
        }
    }
}

/// Await the in-flight ship without consuming it: when another select branch
/// wins, the partially polled future (with its retry state) stays parked.
///
/// Lazy on purpose — the body only runs once polled, which the `is_some()`
/// branch precondition guarantees.
async fn poll_inflight(inflight: &mut Option<ShipFuture>) -> CappedShipOutcome {
    inflight
        .as_mut()
        .expect("poll_inflight guarded by is_some")
        .as_mut()
        .await
}

/// Re-attempt the stashed line once; un-gates command intake on success.
fn retry_blocked(pipeline: &mut StreamingDeliveryPipeline, blocked: &mut Option<(Vec<u8>, i64)>) {
    if let Some((line, timestamp_ns)) = blocked.take()
        && !pipeline.enqueue(&line, timestamp_ns)
    {
        *blocked = Some((line, timestamp_ns));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointStore;
    use crate::shipper::Shipper;
    use crate::streaming_pipeline::StreamingPipelineConfig;
    use logpacer_wire::WireResponse;
    use prost::Message;
    use std::path::Path;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn encoded_wire_response(accepted: u32) -> Vec<u8> {
        let response = WireResponse {
            accepted,
            rejected: 0,
            error_message: String::new(),
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        buf
    }

    fn accept_all(server_delay: Option<Duration>) -> ResponseTemplate {
        // The relay echoes accepted == requested; our batches are small, so a
        // large constant covers every test batch.
        let template = ResponseTemplate::new(200)
            .set_body_raw(encoded_wire_response(1), "application/x-protobuf");
        match server_delay {
            Some(delay) => template.set_delay(delay),
            None => template,
        }
    }

    fn test_pipeline(
        relay_uri: &str,
        dir: &Path,
        config: StreamingPipelineConfig,
    ) -> StreamingDeliveryPipeline {
        let shipper = Shipper::new(relay_uri, "arc_stream", "repo_stream", None).unwrap();
        StreamingDeliveryPipeline::open("stream-actor-test", dir, shipper, config, None).unwrap()
    }

    fn fast_config() -> StreamingPipelineConfig {
        StreamingPipelineConfig {
            drain_interval: Duration::from_millis(10),
            shutdown_deadline: Duration::from_millis(300),
            ..Default::default()
        }
    }

    fn wire_uri(server: &MockServer) -> String {
        format!("{}/wire", server.uri())
    }

    fn persisted_checkpoint(dir: &Path) -> Option<StreamingCheckpoint> {
        CheckpointStore::open(&dir.join("streaming_checkpoints.sqlite"))
            .unwrap()
            .load_streaming("stream-actor-test")
            .unwrap()
    }

    /// Lines are delivered (accepted == batch size), and a checkpoint set
    /// after them is persisted once the buffer empties; dropping the handle
    /// drains and exits the actor.
    #[tokio::test]
    async fn ships_lines_and_persists_checkpoint_when_buffer_empties() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(2), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        assert!(handle.enqueue(b"one".to_vec(), 100).await);
        assert!(handle.enqueue(b"two".to_vec(), 200).await);
        assert!(
            handle
                .set_checkpoint(StreamingCheckpoint::journald("stream-actor-test", "c-2"))
                .await
        );

        drop(handle);
        actor.await.unwrap();

        let checkpoint = persisted_checkpoint(dir.path()).expect("checkpoint persisted");
        assert_eq!(checkpoint.journald_cursor(), Some("c-2"));
    }

    /// With the relay down, nothing is ever confirmed: the checkpoint must not
    /// persist, and the enqueued lines must survive on disk for replay.
    #[tokio::test]
    async fn checkpoint_not_persisted_while_relay_down() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        assert!(handle.enqueue(b"undelivered".to_vec(), 100).await);
        assert!(
            handle
                .set_checkpoint(StreamingCheckpoint::journald("stream-actor-test", "c-1"))
                .await
        );

        drop(handle);
        actor.await.unwrap();

        assert!(persisted_checkpoint(dir.path()).is_none());

        // The line is still on disk for replay on next start.
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        assert!(pipeline.pressure() > 0.0);
    }

    /// THE regression test for the old narrow-lock property: while a slow ship
    /// is in flight, enqueue commands keep being accepted promptly.
    #[tokio::test]
    async fn enqueue_not_blocked_by_inflight_ship() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(accept_all(Some(Duration::from_secs(2))))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        // First line; give the drain tick time to start the (2s-delayed) ship.
        assert!(handle.enqueue(b"slow batch".to_vec(), 100).await);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The ship is now in flight for ~2s; enqueues must not wait on it.
        for i in 0..10 {
            let enqueued = tokio::time::timeout(
                Duration::from_millis(100),
                handle.enqueue(format!("during-ship-{i}").into_bytes(), 200 + i),
            )
            .await;
            assert!(
                enqueued.is_ok_and(|ok| ok),
                "enqueue {i} stalled behind the in-flight ship"
            );
        }

        drop(handle);
        actor.await.unwrap();
    }

    /// A ship that completes around shutdown must have its outcome applied
    /// before the shutdown drain, or the same batch would be shipped twice.
    #[tokio::test]
    async fn inflight_outcome_applied_before_shutdown_drain() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(accept_all(Some(Duration::from_millis(500))))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        assert!(handle.enqueue(b"once only".to_vec(), 100).await);
        // Let the drain tick start the delayed ship, then shut down while it
        // is still in flight.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(handle);
        actor.await.unwrap();

        // MockServer verifies expect(1) on drop: exactly one ship request.
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        assert_eq!(pipeline.pressure(), 0.0, "buffer should be empty");
    }

    /// `checkpoint()` returns the pending checkpoint (not yet persisted) when
    /// one is set, so reconnects don't re-fetch lines already buffered.
    #[tokio::test]
    async fn checkpoint_query_prefers_pending_over_persisted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        // Relay is down: this checkpoint stays pending, never persisted.
        assert!(handle.enqueue(b"line".to_vec(), 100).await);
        assert!(
            handle
                .set_checkpoint(StreamingCheckpoint::journald(
                    "stream-actor-test",
                    "pending"
                ))
                .await
        );

        let resume = handle.checkpoint().await.expect("actor alive");
        assert_eq!(
            resume.as_ref().and_then(|cp| cp.journald_cursor()),
            Some("pending")
        );

        drop(handle);
        actor.await.unwrap();
    }

    /// When buffer (no overflow configured) fills, the actor stalls the
    /// producer instead of dropping: every line eventually lands.
    #[tokio::test]
    async fn full_buffer_stalls_producer_without_dropping() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(accept_all(None))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config = StreamingPipelineConfig {
            buffer_max_mb: 1,
            ship_batch_size: 1,
            ..fast_config()
        };
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), config);
        // Tiny channel so the stall is observable without huge payloads.
        let (handle, actor) = spawn_with_capacity(pipeline, 2);

        // ~600 KiB lines: one fits in the 1 MiB buffer, the next blocks.
        let line = vec![b'x'; 600 * 1024];
        for i in 0..6 {
            assert!(
                handle.enqueue(line.clone(), i).await,
                "enqueue {i} failed — actor gone"
            );
        }

        drop(handle);
        actor.await.unwrap();

        // Everything was eventually shipped — nothing dropped, buffer empty.
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), fast_config());
        assert_eq!(pipeline.pressure(), 0.0);
        assert!(server.received_requests().await.unwrap().len() >= 6);
    }

    /// The pathological corner: disk full (blocked line gates intake) AND
    /// relay down (in-flight ship retries forever). The actor must still
    /// notice all handles are gone and exit instead of hanging forever.
    #[tokio::test]
    async fn blocked_actor_exits_when_handles_drop() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config = StreamingPipelineConfig {
            buffer_max_mb: 1,
            ship_batch_size: 1,
            ..fast_config()
        };
        let pipeline = test_pipeline(&wire_uri(&server), dir.path(), config);
        let (handle, actor) = spawn_with_capacity(pipeline, 2);

        // Line 1 fills the buffer, line 2 becomes the blocked line gating
        // intake, lines 3-4 sit in the channel. Nothing can ever ship.
        let line = vec![b'x'; 600 * 1024];
        for i in 0..4 {
            assert!(handle.enqueue(line.clone(), i).await);
        }

        drop(handle);
        // Budget: in-flight settle cap (3s) + shutdown deadline + slack.
        tokio::time::timeout(Duration::from_secs(8), actor)
            .await
            .expect("blocked actor must exit once all handles are dropped")
            .unwrap();
    }
}
