use super::*;

use logpacer_wire::{WireRequest, WireResponse, routed_batch, wire_log_event};
use prost::Message;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct AcceptEveryEntry;

impl wiremock::Respond for AcceptEveryEntry {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let decoded = crate::test_support::decode_gzip_wire_request(request);
        let accepted = wire_log_texts(&decoded).len() as u32;
        let mut body = Vec::new();
        WireResponse {
            accepted,
            rejected: 0,
            error_message: String::new(),
        }
        .encode(&mut body)
        .unwrap();
        ResponseTemplate::new(200).set_body_raw(body, "application/x-protobuf")
    }
}

fn wire_log_texts(request: &WireRequest) -> Vec<String> {
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

fn interleaved_lines() -> Vec<SampleLine> {
    vec![
        SampleLine::new("2026-08-25 stdout first".into(), LogStream::Stdout),
        SampleLine::new("2026-08-25 stderr first".into(), LogStream::Stderr),
        SampleLine::new("    stderr detail".into(), LogStream::Stderr),
        SampleLine::new("    stdout detail".into(), LogStream::Stdout),
        SampleLine::new("2026-08-25 stdout second".into(), LogStream::Stdout),
        SampleLine::new("2026-08-25 stderr second".into(), LogStream::Stderr),
    ]
}

#[test]
fn docker_json_file_sample_omits_blank_payloads_without_multiline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("container-json.log");
    std::fs::write(
        &path,
        concat!(
            r#"{"log":"first\n","stream":"stdout","time":"2026-08-25T10:00:00Z"}"#,
            "\n",
            r#"{"log":"\n","stream":"stderr","time":"2026-08-25T10:00:01Z"}"#,
            "\n",
            r#"{"log":"second\n","stream":"stderr","time":"2026-08-25T10:00:02Z"}"#,
            "\n",
        ),
    )
    .unwrap();

    let lines = read_docker_json_file_lines(path.to_str().unwrap()).unwrap();

    assert_eq!(finalize_sample(lines, None, 2), vec!["first", "second"]);
}

#[test]
fn finalize_sample_with_zero_max_lines_is_empty() {
    let cfg = MultilineConfig::from_patterns(vec![r"^2026-".to_string()], 500, 5);
    let lines = vec!["2026-08-25 first".to_string()];

    assert!(finalize_sample(untagged(lines.clone()), None, 0).is_empty());
    assert!(finalize_sample(untagged(lines), Some(&cfg), 0).is_empty());
}

#[test]
fn container_sample_assembles_interleaved_streams_independently() {
    let cfg = MultilineConfig::from_patterns(vec![r"^2026-".to_string()], 500, 5);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("container-json.log");
    std::fs::write(
        &path,
        concat!(
            r#"{"log":"2026-08-25 stdout first\n","stream":"stdout","time":"2026-08-25T10:00:00Z"}"#,
            "\n",
            r#"{"log":"2026-08-25 stderr first\n","stream":"stderr","time":"2026-08-25T10:00:01Z"}"#,
            "\n",
            r#"{"log":"    stderr detail\n","stream":"stderr","time":"2026-08-25T10:00:02Z"}"#,
            "\n",
            r#"{"log":"    stdout detail\n","stream":"stdout","time":"2026-08-25T10:00:03Z"}"#,
            "\n",
            r#"{"log":"2026-08-25 stdout second\n","stream":"stdout","time":"2026-08-25T10:00:04Z"}"#,
            "\n",
            r#"{"log":"2026-08-25 stderr second\n","stream":"stderr","time":"2026-08-25T10:00:05Z"}"#,
            "\n",
        ),
    )
    .unwrap();

    let lines = read_docker_json_file_lines(path.to_str().unwrap()).unwrap();
    let sample = finalize_sample(lines, Some(&cfg), 1000);

    assert_eq!(
        sample,
        vec![
            "2026-08-25 stdout first\n    stdout detail".to_string(),
            "2026-08-25 stderr first\n    stderr detail".to_string(),
            "2026-08-25 stdout second".to_string(),
            "2026-08-25 stderr second".to_string(),
        ]
    );
}

#[tokio::test]
async fn container_sample_matches_streaming_pipeline_for_interleaved_streams() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(AcceptEveryEntry)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let shipper =
        crate::shipper::Shipper::new(&format!("{}/wire", server.uri()), "arc", "repo", None)
            .unwrap();
    let pipeline = crate::streaming_pipeline::StreamingDeliveryPipeline::open(
        "sampler-parity",
        dir.path(),
        shipper,
        crate::streaming_pipeline::StreamingPipelineConfig {
            drain_interval: Duration::from_millis(10),
            shutdown_deadline: Duration::from_millis(300),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let (handle, actor) = crate::streaming_actor::spawn_streaming_actor(pipeline);

    let cfg = MultilineConfig::from_patterns(vec![r"^2026-".to_string()], 500, 5);
    let lines = interleaved_lines();
    let sample = finalize_sample(lines.clone(), Some(&cfg), 1000);
    let mut assembler =
        crate::streaming_multiline::StreamingEntryAssembler::new(Some(&cfg)).unwrap();
    for (index, line) in lines.into_iter().enumerate() {
        assembler
            .process_stream_line(
                &handle,
                line.stream,
                line.content.into_bytes(),
                index as i64,
                None,
            )
            .await
            .unwrap();
    }
    assembler.flush(&handle).await.unwrap();
    drop(handle);
    actor.await.unwrap();

    let shipped = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .flat_map(|request| wire_log_texts(&crate::test_support::decode_gzip_wire_request(request)))
        .collect::<Vec<_>>();

    assert_eq!(sample, shipped);
}

#[test]
fn container_sample_tail_window_uses_global_emission_order() {
    let cfg = MultilineConfig::from_patterns(vec![r"^2026-".to_string()], 500, 5);

    assert_eq!(
        finalize_sample(interleaved_lines(), Some(&cfg), 3),
        vec![
            "2026-08-25 stderr first\n    stderr detail".to_string(),
            "2026-08-25 stdout second".to_string(),
            "2026-08-25 stderr second".to_string(),
        ]
    );
}
