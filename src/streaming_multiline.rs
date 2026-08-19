//! Multiline assembly for streaming sources, with the checkpoint bookkeeping
//! that keeps a resume point honest.
//!
//! Container sources are several conversations sharing one connection: stdout
//! and stderr are copied concurrently, so a request logged on stdout can land
//! between two frames of a stack trace on stderr. Each stream therefore gets
//! its own assembler.
//!
//! That splits event completion from stream order, which the checkpoint has to
//! respect. Lines are recorded in arrival order and marked finished when the
//! event containing them is emitted; the resume point is released only through
//! the consecutive finished prefix. An event completing on one stream never
//! moves the checkpoint past a line another stream is still buffering — that
//! line has not shipped, and a reconnect would skip it.

use std::collections::VecDeque;
use std::time::Duration;

use crate::config::MultilineConfig;
use crate::cri::LogStream;
use crate::entry_assembler::{EntryAssembler, EventMetadata, LineContext};
use crate::streaming_actor::{StreamHandle, StreamingActorGone};
use crate::streaming_checkpoint::StreamingCheckpoint;

#[derive(Debug)]
pub(crate) struct StreamingEmit {
    pub checkpoint: Option<StreamingCheckpoint>,
}

#[derive(Debug)]
struct PendingLine {
    stream: LogStream,
    timestamp_ns: i64,
    checkpoint: Option<StreamingCheckpoint>,
    /// Set once the event containing this line has been emitted.
    finished: bool,
}

/// An event drained from one assembler, before its pending lines are settled.
type AssembledEvent = (Vec<u8>, EventMetadata);
/// The same event, tagged with the stream whose assembler produced it.
type StreamEvent = (LogStream, Vec<u8>, EventMetadata);

/// How to build an assembler for a stream seen for the first time.
struct AssemblerSpec {
    patterns: Vec<String>,
    max_lines: usize,
    timeout: Duration,
}

pub(crate) struct StreamingEntryAssembler {
    /// `None` when the source has no multiline config — lines pass straight
    /// through to the pipeline, one entry each.
    spec: Option<AssemblerSpec>,
    per_stream: Vec<(LogStream, EntryAssembler)>,
    next_offset: u64,
    pending: VecDeque<PendingLine>,
}

impl StreamingEntryAssembler {
    pub fn new(multiline: Option<&MultilineConfig>) -> Result<Self, regex::Error> {
        let (spec, per_stream) = match multiline {
            Some(cfg) => {
                let spec = AssemblerSpec {
                    patterns: cfg.patterns().to_vec(),
                    max_lines: cfg.max_lines as usize,
                    timeout: Duration::from_secs(cfg.timeout_secs.max(1) as u64),
                };
                // Compile once here so an invalid pattern fails the stream at
                // startup rather than on the first line of a second stream.
                let first = EntryAssembler::new(&spec.patterns, spec.max_lines, spec.timeout)?;
                (Some(spec), vec![(LogStream::Unspecified, first)])
            }
            None => (None, Vec::new()),
        };

        Ok(Self {
            spec,
            per_stream,
            next_offset: 0,
            pending: VecDeque::new(),
        })
    }

    /// Feed a line from a single-stream source (journald, an event log, a
    /// plain file).
    pub async fn process_line(
        &mut self,
        handle: &StreamHandle,
        line: Vec<u8>,
        timestamp_ns: i64,
        checkpoint: Option<StreamingCheckpoint>,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        self.process_stream_line(
            handle,
            LogStream::Unspecified,
            line,
            timestamp_ns,
            checkpoint,
        )
        .await
    }

    /// Feed a line tagged with the container output stream that wrote it.
    pub async fn process_stream_line(
        &mut self,
        handle: &StreamHandle,
        stream: LogStream,
        line: Vec<u8>,
        timestamp_ns: i64,
        checkpoint: Option<StreamingCheckpoint>,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        if self.spec.is_none() {
            return enqueue(handle, line, timestamp_ns, checkpoint, stream).await;
        }

        let start_offset = self.next_offset;
        self.next_offset += 1;
        let ctx = LineContext {
            start_offset,
            end_offset: self.next_offset,
            inode: 0,
        };
        self.pending.push_back(PendingLine {
            stream,
            timestamp_ns,
            checkpoint,
            finished: false,
        });

        match self.assembler_for(stream).process(line, ctx) {
            Some((event, meta)) => self.emit_assembled(handle, stream, event, meta).await,
            None => Ok(None),
        }
    }

    pub async fn check_timeout(
        &mut self,
        handle: &StreamHandle,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let ready = self.collect_ready(EntryAssembler::check_timeout);
        self.emit_all(handle, ready).await
    }

    pub async fn flush(
        &mut self,
        handle: &StreamHandle,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let ready = self.collect_ready(EntryAssembler::flush);
        self.emit_all(handle, ready).await
    }

    fn assembler_for(&mut self, stream: LogStream) -> &mut EntryAssembler {
        if let Some(index) = self
            .per_stream
            .iter()
            .position(|(candidate, _)| *candidate == stream)
        {
            return &mut self.per_stream[index].1;
        }

        let spec = self
            .spec
            .as_ref()
            .expect("assembler spec present whenever streams are tracked");
        let assembler = EntryAssembler::new(&spec.patterns, spec.max_lines, spec.timeout)
            .expect("pattern set already compiled at stream startup");
        self.per_stream.push((stream, assembler));
        &mut self
            .per_stream
            .last_mut()
            .expect("just pushed an assembler for this stream")
            .1
    }

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

    /// Enqueue every drained event and report the last emit. Each stream's
    /// event is enqueued in turn; the last emit carries the furthest resume
    /// point, since the prefix only ever releases forward.
    async fn emit_all(
        &mut self,
        handle: &StreamHandle,
        ready: Vec<StreamEvent>,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let mut last = None;
        for (stream, event, meta) in ready {
            last = self.emit_assembled(handle, stream, event, meta).await?;
        }
        Ok(last)
    }

    async fn emit_assembled(
        &mut self,
        handle: &StreamHandle,
        stream: LogStream,
        event: Vec<u8>,
        meta: EventMetadata,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let (timestamp_ns, checkpoint) = self.consume_pending(stream, meta.line_count);
        enqueue(handle, event, timestamp_ns, checkpoint, stream).await
    }

    /// Mark this event's lines finished and release whatever resume point the
    /// consecutive finished prefix now covers.
    fn consume_pending(
        &mut self,
        stream: LogStream,
        line_count: usize,
    ) -> (i64, Option<StreamingCheckpoint>) {
        let mut timestamp_ns = None;
        let mut marked = 0;

        for pending in self.pending.iter_mut() {
            if marked == line_count {
                break;
            }
            if pending.finished || pending.stream != stream {
                continue;
            }
            pending.finished = true;
            timestamp_ns.get_or_insert(pending.timestamp_ns);
            marked += 1;
        }
        debug_assert_eq!(
            marked, line_count,
            "assembler emitted more lines than were pending for this stream"
        );

        let mut checkpoint = None;
        while self.pending.front().is_some_and(|pending| pending.finished) {
            let released = self
                .pending
                .pop_front()
                .expect("front was just checked as finished");
            if released.checkpoint.is_some() {
                checkpoint = released.checkpoint;
            }
        }

        (timestamp_ns.unwrap_or(0), checkpoint)
    }
}

async fn enqueue(
    handle: &StreamHandle,
    line: Vec<u8>,
    timestamp_ns: i64,
    checkpoint: Option<StreamingCheckpoint>,
    stream: LogStream,
) -> Result<Option<StreamingEmit>, StreamingActorGone> {
    if !handle.enqueue_from_stream(line, timestamp_ns, stream).await {
        return Err(StreamingActorGone);
    }
    Ok(Some(StreamingEmit { checkpoint }))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use logpacer_wire::{WireRequest, WireResponse, routed_batch, wire_log_event};
    use prost::Message;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::checkpoint::CheckpointStore;
    use crate::shipper::Shipper;
    use crate::streaming_actor::spawn_streaming_actor;
    use crate::streaming_pipeline::{StreamingDeliveryPipeline, StreamingPipelineConfig};

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

    /// Accept exactly the entries a request carries, so a test does not have to
    /// predict how the drain loop batches them.
    struct AcceptEveryEntry;

    impl wiremock::Respond for AcceptEveryEntry {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let decoded = crate::test_support::decode_gzip_wire_request(request);
            let accepted = log_texts(&decoded).len() as u32;
            ResponseTemplate::new(200)
                .set_body_raw(encoded_wire_response(accepted), "application/x-protobuf")
        }
    }

    fn fast_config() -> StreamingPipelineConfig {
        StreamingPipelineConfig {
            drain_interval: Duration::from_millis(10),
            shutdown_deadline: Duration::from_millis(300),
            ..Default::default()
        }
    }

    fn test_pipeline(
        relay_uri: &str,
        dir: &Path,
        config: StreamingPipelineConfig,
    ) -> StreamingDeliveryPipeline {
        let shipper = Shipper::new(relay_uri, "arc_stream", "repo_stream", None).unwrap();
        StreamingDeliveryPipeline::open("streaming-multiline-test", dir, shipper, config, None)
            .unwrap()
    }

    fn persisted_checkpoint(dir: &Path) -> Option<StreamingCheckpoint> {
        CheckpointStore::open(&dir.join("streaming_checkpoints.sqlite"))
            .unwrap()
            .load_streaming("streaming-multiline-test")
            .unwrap()
    }

    fn log_texts(request: &WireRequest) -> Vec<String> {
        request
            .batches
            .iter()
            .filter_map(|batch| match batch.payload.as_ref()? {
                routed_batch::Payload::Logs(logs) => Some(logs),
                _ => None,
            })
            .flat_map(|logs| logs.entries.iter())
            .map(|entry| match entry.body.as_ref().unwrap() {
                wire_log_event::Body::RawText(text) => text.clone(),
                wire_log_event::Body::RawBytes(bytes) => String::from_utf8_lossy(bytes).into(),
                other => panic!("expected raw log body, got {other:?}"),
            })
            .collect()
    }

    /// The streaming lane (Docker API) keeps the stream tag all the way to the
    /// wire: a stderr line — passed through with no multiline config — ships
    /// with `"stream":"stderr"` in its envelope, an untagged line with `{}`.
    #[tokio::test]
    async fn streamed_lines_ship_with_their_stream_in_the_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(AcceptEveryEntry)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&format!("{}/wire", server.uri()), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        let mut assembler = StreamingEntryAssembler::new(None).unwrap();
        assembler
            .process_stream_line(&handle, LogStream::Stderr, b"boom".to_vec(), 100, None)
            .await
            .unwrap();
        assembler
            .process_line(&handle, b"untagged".to_vec(), 200, None)
            .await
            .unwrap();

        drop(handle);
        actor.await.unwrap();

        let metadata: Vec<(String, Vec<u8>)> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .flat_map(|request| {
                let decoded = crate::test_support::decode_gzip_wire_request(request);
                decoded
                    .batches
                    .iter()
                    .filter_map(|batch| match batch.payload.as_ref()? {
                        routed_batch::Payload::Logs(logs) => Some(logs.clone()),
                        _ => None,
                    })
                    .flat_map(|logs| logs.entries.into_iter())
                    .map(|entry| {
                        let body = match entry.body.as_ref().unwrap() {
                            wire_log_event::Body::RawText(text) => text.clone(),
                            other => panic!("expected raw text, got {other:?}"),
                        };
                        (body, entry.envelope.as_ref().unwrap().metadata_json.clone())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        assert_eq!(
            metadata,
            vec![
                ("boom".to_string(), br#"{"stream":"stderr"}"#.to_vec()),
                ("untagged".to_string(), b"{}".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn assembles_streaming_continuations_before_checkpointing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(encoded_wire_response(1), "application/x-protobuf"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&format!("{}/wire", server.uri()), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        let multiline =
            MultilineConfig::from_patterns(vec![r"^\d{4}-\d{2}-\d{2}".to_string()], 500, 5);
        let mut assembler = StreamingEntryAssembler::new(Some(&multiline)).unwrap();

        let first_checkpoint = StreamingCheckpoint::docker(
            "streaming-multiline-test",
            "pg-pacer",
            "2026-07-05T01:50:29.378000000Z",
        );
        let continuation_checkpoint = StreamingCheckpoint::docker(
            "streaming-multiline-test",
            "pg-pacer",
            "2026-07-05T01:50:29.379000000Z",
        );

        assert!(
            assembler
                .process_line(
                    &handle,
                    b"2026-07-05 01:50:29.378 UTC [136138] LOG: automatic analyze".to_vec(),
                    100,
                    Some(first_checkpoint),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            handle
                .checkpoint()
                .await
                .expect("actor should answer checkpoint query")
                .is_none(),
            "checkpoint must not advance while the event is still buffered in the assembler"
        );
        assert!(
            assembler
                .process_line(
                    &handle,
                    b"    avg read rate: 0.000 MB/s, avg write rate: 0.000 MB/s".to_vec(),
                    200,
                    Some(continuation_checkpoint),
                )
                .await
                .unwrap()
                .is_none()
        );

        let emit = assembler
            .flush(&handle)
            .await
            .unwrap()
            .expect("flush emits the assembled entry");
        handle.set_checkpoint(emit.checkpoint.unwrap()).await;

        drop(handle);
        actor.await.unwrap();

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let request = crate::test_support::decode_gzip_wire_request(&received[0]);
        assert_eq!(
            log_texts(&request),
            vec![
                "2026-07-05 01:50:29.378 UTC [136138] LOG: automatic analyze\n    avg read rate: 0.000 MB/s, avg write rate: 0.000 MB/s"
                    .to_string()
            ]
        );

        let checkpoint = persisted_checkpoint(dir.path()).expect("checkpoint persisted");
        assert_eq!(
            checkpoint.docker_since(),
            Some("2026-07-05T01:50:29.379000000Z")
        );
    }

    /// Kill-test: stdout and stderr interleaved on one container stream. Each
    /// assembles on its own, and the resume point may not jump to a delivered
    /// stdout event while an older stderr line is still buffered — a reconnect
    /// from there would skip it. The checkpoint is released only once the
    /// stderr line's own event ships.
    #[tokio::test]
    async fn interleaved_streams_assemble_apart_and_release_the_checkpoint_in_order() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wire"))
            .respond_with(AcceptEveryEntry)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let pipeline = test_pipeline(&format!("{}/wire", server.uri()), dir.path(), fast_config());
        let (handle, actor) = spawn_streaming_actor(pipeline);

        let multiline =
            MultilineConfig::from_patterns(vec![r"^\d{4}-\d{2}-\d{2}".to_string()], 500, 5);
        let mut assembler = StreamingEntryAssembler::new(Some(&multiline)).unwrap();

        let at = |nanos: &str| {
            StreamingCheckpoint::docker(
                "streaming-multiline-test",
                "web",
                &format!("2026-08-06T15:03:17.{nanos}Z"),
            )
        };

        // stderr opens an event and keeps it open.
        assert!(
            assembler
                .process_stream_line(
                    &handle,
                    LogStream::Stderr,
                    b"2026-08-06 ERROR boom".to_vec(),
                    100,
                    Some(at("100000000")),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            assembler
                .process_stream_line(
                    &handle,
                    LogStream::Stdout,
                    b"2026-08-06 INFO one".to_vec(),
                    200,
                    Some(at("200000000")),
                )
                .await
                .unwrap()
                .is_none()
        );

        // The second stdout line closes the first stdout event.
        let emit = assembler
            .process_stream_line(
                &handle,
                LogStream::Stdout,
                b"2026-08-06 INFO two".to_vec(),
                300,
                Some(at("300000000")),
            )
            .await
            .unwrap()
            .expect("the stdout event is emitted");
        assert!(
            emit.checkpoint.is_none(),
            "the stderr line arrived first and is still buffered, so nothing is safe to resume from"
        );

        let emit = assembler
            .flush(&handle)
            .await
            .unwrap()
            .expect("flush emits both streams' remaining events");
        assert_eq!(
            emit.checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.docker_since()),
            Some("2026-08-06T15:03:17.300000000Z"),
            "with every line shipped the resume point reaches the newest line"
        );
        handle.set_checkpoint(emit.checkpoint.unwrap()).await;

        drop(handle);
        actor.await.unwrap();

        let texts: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .flat_map(|request| log_texts(&crate::test_support::decode_gzip_wire_request(request)))
            .collect();
        assert_eq!(
            texts,
            vec![
                "2026-08-06 INFO one".to_string(),
                "2026-08-06 ERROR boom".to_string(),
                "2026-08-06 INFO two".to_string(),
            ],
            "no stdout line is glued onto the stderr event, or the other way round"
        );

        let checkpoint = persisted_checkpoint(dir.path()).expect("checkpoint persisted");
        assert_eq!(
            checkpoint.docker_since(),
            Some("2026-08-06T15:03:17.300000000Z")
        );
    }
}
