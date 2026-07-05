use std::collections::VecDeque;
use std::time::Duration;

use crate::config::MultilineConfig;
use crate::entry_assembler::{EntryAssembler, EventMetadata, LineContext};
use crate::streaming_actor::{StreamHandle, StreamingActorGone};
use crate::streaming_checkpoint::StreamingCheckpoint;

#[derive(Debug)]
pub(crate) struct StreamingEmit {
    pub checkpoint: Option<StreamingCheckpoint>,
}

#[derive(Debug)]
struct PendingLine {
    timestamp_ns: i64,
    checkpoint: Option<StreamingCheckpoint>,
}

pub(crate) struct StreamingEntryAssembler {
    assembler: Option<EntryAssembler>,
    next_offset: u64,
    pending: VecDeque<PendingLine>,
}

impl StreamingEntryAssembler {
    pub fn new(multiline: Option<&MultilineConfig>) -> Result<Self, regex::Error> {
        let assembler = match multiline {
            Some(cfg) => {
                let timeout = Duration::from_secs(cfg.timeout_secs.max(1) as u64);
                Some(EntryAssembler::new(
                    &cfg.start_pattern,
                    cfg.max_lines as usize,
                    timeout,
                )?)
            }
            None => None,
        };

        Ok(Self {
            assembler,
            next_offset: 0,
            pending: VecDeque::new(),
        })
    }

    pub async fn process_line(
        &mut self,
        handle: &StreamHandle,
        line: Vec<u8>,
        timestamp_ns: i64,
        checkpoint: Option<StreamingCheckpoint>,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let Some(assembler) = self.assembler.as_mut() else {
            return enqueue(handle, line, timestamp_ns, checkpoint).await;
        };

        let start_offset = self.next_offset;
        self.next_offset += 1;
        let ctx = LineContext {
            start_offset,
            end_offset: self.next_offset,
            inode: 0,
        };
        self.pending.push_back(PendingLine {
            timestamp_ns,
            checkpoint,
        });

        match assembler.process(line, ctx) {
            Some((event, meta)) => self.emit_assembled(handle, event, meta).await,
            None => Ok(None),
        }
    }

    pub async fn check_timeout(
        &mut self,
        handle: &StreamHandle,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let Some(assembler) = self.assembler.as_mut() else {
            return Ok(None);
        };

        match assembler.check_timeout() {
            Some((event, meta)) => self.emit_assembled(handle, event, meta).await,
            None => Ok(None),
        }
    }

    pub async fn flush(
        &mut self,
        handle: &StreamHandle,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let Some(assembler) = self.assembler.as_mut() else {
            return Ok(None);
        };

        match assembler.flush() {
            Some((event, meta)) => self.emit_assembled(handle, event, meta).await,
            None => Ok(None),
        }
    }

    async fn emit_assembled(
        &mut self,
        handle: &StreamHandle,
        event: Vec<u8>,
        meta: EventMetadata,
    ) -> Result<Option<StreamingEmit>, StreamingActorGone> {
        let (timestamp_ns, checkpoint) = self.consume_pending(meta.line_count);
        enqueue(handle, event, timestamp_ns, checkpoint).await
    }

    fn consume_pending(&mut self, line_count: usize) -> (i64, Option<StreamingCheckpoint>) {
        let mut timestamp_ns = None;
        let mut checkpoint = None;

        for _ in 0..line_count {
            let pending = self
                .pending
                .pop_front()
                .expect("assembler emitted more lines than were pending");
            timestamp_ns.get_or_insert(pending.timestamp_ns);
            if pending.checkpoint.is_some() {
                checkpoint = pending.checkpoint;
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
) -> Result<Option<StreamingEmit>, StreamingActorGone> {
    if !handle.enqueue(line, timestamp_ns).await {
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

        let multiline = MultilineConfig {
            start_pattern: r"^\d{4}-\d{2}-\d{2}".to_string(),
            max_lines: 500,
            timeout_secs: 5,
        };
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
        let request = WireRequest::decode(&received[0].body[..]).unwrap();
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
}
