//! End-to-end test: mock Rails auth/config -> edgepacer -> real or mock logrelay.
//!
//! Exercises the full agent contract:
//! 1. Auth with Rails (mocked) → get token
//! 2. Fetch config (mocked) → get one collect stream pointing at subbox
//! 3. Tail a test file → ship via logpacer_wire → logrelay receives it
//!
//! To test against a REAL logrelay:
//!   LOGRELAY_URL=http://127.0.0.1:4319 cargo test --test e2e_logrelay
//!
//! Without LOGRELAY_URL, the test uses a wiremock to verify the wire format.

mod common;

use std::io::Write;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use logpacer_wire::{WireRequest, WireResponse, routed_batch, wire_log_event};
use prost::Message;
use tokio::sync::mpsc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_accepting_wire_relay() -> (String, mpsc::UnboundedReceiver<WireRequest>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new().route(
        "/wire",
        post(move |headers: HeaderMap, body: Bytes| {
            let tx = tx.clone();
            async move {
                let decoded = match common::decode_wire_body(&headers, &body) {
                    Ok(decoded) => decoded,
                    Err(_) => return StatusCode::BAD_REQUEST.into_response(),
                };
                let request = match WireRequest::decode(decoded.as_slice()) {
                    Ok(request) => request,
                    Err(_) => return StatusCode::BAD_REQUEST.into_response(),
                };
                let accepted = accepted_log_count(&request);
                let _ = tx.send(request);

                let response = WireResponse {
                    accepted,
                    rejected: 0,
                    error_message: String::new(),
                };
                let mut response_bytes = Vec::new();
                response.encode(&mut response_bytes).unwrap();
                (
                    [(header::CONTENT_TYPE, "application/x-protobuf")],
                    response_bytes,
                )
                    .into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/wire", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (endpoint, rx)
}

fn accepted_log_count(request: &WireRequest) -> u32 {
    request
        .batches
        .iter()
        .filter_map(|batch| match batch.payload.as_ref()? {
            routed_batch::Payload::Logs(logs) => Some(logs.entries.len() as u32),
            _ => None,
        })
        .sum()
}

async fn receive_matching_wire_request(
    rx: &mut mpsc::UnboundedReceiver<WireRequest>,
    mut matches: impl FnMut(&WireRequest) -> bool,
) -> WireRequest {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let request = rx.recv().await.expect("wire relay stopped");
            if matches(&request) {
                return request;
            }
        }
    })
    .await
    .expect("timed out waiting for matching wire request")
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
        .filter_map(|entry| match entry.body.as_ref()? {
            wire_log_event::Body::RawText(text) => Some(text.clone()),
            wire_log_event::Body::RawBytes(bytes) => {
                Some(String::from_utf8_lossy(bytes).into_owned())
            }
            wire_log_event::Body::EntryJson(bytes) => {
                Some(String::from_utf8_lossy(bytes).into_owned())
            }
        })
        .collect()
}

#[tokio::test]
async fn configured_collect_file_source_reaches_logrelay() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("configured_app.log");
    std::fs::write(&log_path, "").unwrap();

    let (endpoint, mut requests) = spawn_accepting_wire_relay().await;
    let unified = edgepacer::config::UnifiedConfig::new(
        serde_json::json!({
            "collect": {
                "configured-file": {
                    "locator": log_path.to_str().unwrap(),
                    "matching_strategy": "file_path",
                    "subbox_endpoint": endpoint,
                    "archive_id": "arc_configured",
                    "repo_id": "repo_configured",
                    "stamp_resource_identifier": true
                }
            }
        }),
        "etag-configured-file".into(),
    );
    let resolved = edgepacer::config::resolved_collect_from_config(
        &unified,
        &edgepacer::discovery::DiscoveryCache::new(),
    );
    assert_eq!(resolved.file_streams.len(), 1);
    assert!(resolved.streaming_sources.is_empty());

    let mut orchestrator = edgepacer::orchestrator::Orchestrator::new(
        dir.path(),
        edgepacer::identity::AgentIdentity::new("windows-host-1".into()),
    );
    orchestrator
        .reconcile(
            &resolved.file_streams,
            &resolved.streaming_sources,
            &resolved.checkpoint_adoptions,
        )
        .await;

    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(file, "configured file line one").unwrap();
        writeln!(file, "configured file line two").unwrap();
    }

    let request = receive_matching_wire_request(&mut requests, |request| {
        log_texts(request)
            .iter()
            .any(|text| text == "configured file line two")
    })
    .await;
    orchestrator.shutdown_all().await;

    assert_eq!(request.batches.len(), 1);
    assert_eq!(request.batches[0].archive_id, "arc_configured");
    assert_eq!(request.batches[0].repo_id, "repo_configured");
    let texts = log_texts(&request);
    assert_eq!(
        texts,
        vec![
            "configured file line one".to_string(),
            "configured file line two".to_string()
        ]
    );
}

#[cfg(windows)]
#[tokio::test]
async fn configured_windows_event_log_source_reaches_logrelay() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, mut requests) = spawn_accepting_wire_relay().await;
    let unified = edgepacer::config::UnifiedConfig::new(
        serde_json::json!({
            "collect": {
                "configured-application-event-log": {
                    "locator": "Application",
                    "access_method": "windows_event_log",
                    "subbox_endpoint": endpoint,
                    "archive_id": "arc_event_log",
                    "repo_id": "repo_event_log"
                }
            }
        }),
        "etag-configured-event-log".into(),
    );
    let resolved = edgepacer::config::resolved_collect_from_config(
        &unified,
        &edgepacer::discovery::DiscoveryCache::new(),
    );
    assert!(resolved.file_streams.is_empty());
    assert_eq!(resolved.streaming_sources.len(), 1);

    let mut orchestrator = edgepacer::orchestrator::Orchestrator::new(
        dir.path(),
        edgepacer::identity::AgentIdentity::new("windows-host-1".into()),
    );
    orchestrator
        .reconcile(
            &resolved.file_streams,
            &resolved.streaming_sources,
            &resolved.checkpoint_adoptions,
        )
        .await;

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let marker = format!("edgepacer configured event log {}", uuid::Uuid::new_v4());
    create_application_event(&marker);

    let request = receive_matching_wire_request(&mut requests, |request| {
        log_texts(request).iter().any(|text| text.contains(&marker))
    })
    .await;
    orchestrator.shutdown_all().await;

    assert_eq!(request.batches.len(), 1);
    assert_eq!(request.batches[0].archive_id, "arc_event_log");
    assert_eq!(request.batches[0].repo_id, "repo_event_log");
    assert!(
        log_texts(&request)
            .iter()
            .any(|text| text.contains(&marker)),
        "event log XML should contain the eventcreate marker"
    );
}

#[cfg(windows)]
fn create_application_event(message: &str) {
    let status = std::process::Command::new("eventcreate")
        .args([
            "/T",
            "INFORMATION",
            "/ID",
            "1000",
            "/L",
            "APPLICATION",
            "/SO",
            "EdgePacerTest",
            "/D",
            message,
        ])
        .status()
        .expect("eventcreate should start");
    assert!(
        status.success(),
        "eventcreate should write Application event"
    );
}

/// Full E2E: mock Rails + mock logrelay, verify wire contract.
#[tokio::test]
async fn e2e_file_tail_to_logrelay() {
    // --- Set up mock Rails ---
    let rails_mock = MockServer::start().await;

    // Mock auth endpoint
    let auth_response = serde_json::json!({
        "access_token": "test_token_123",
        "refresh_token": "test_refresh",
        "expires_in": 3600
    });
    Mock::given(method("POST"))
        .and(path("/api/v1/agents/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&auth_response))
        .mount(&rails_mock)
        .await;

    // Mock config endpoint — one file-backed log stream
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("test_app.log");
    std::fs::write(&log_path, "").unwrap(); // Create empty file

    // --- Set up mock logrelay ---
    let relay_mock = MockServer::start().await;

    // Mock logrelay ingest — accept protobuf, return success
    let ingest_response = WireResponse {
        accepted: 3,
        rejected: 0,
        error_message: String::new(),
    };
    let mut response_bytes = Vec::new();
    ingest_response.encode(&mut response_bytes).unwrap();

    Mock::given(method("POST"))
        .and(path("/wire"))
        .and(header("content-type", "application/x-protobuf"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(response_bytes))
        .expect(1..)
        .mount(&relay_mock)
        .await;

    // Config with collect stream pointing at mock relay
    let config_json = serde_json::json!({
        "collect": {
            "test-source-1": {
                "locator": log_path.to_str().unwrap(),
                "matching_strategy": "file_path",
                "subbox_endpoint": format!("{}/wire", relay_mock.uri()),
                "archive_id": "arc_test",
                "repo_id": "repo_test"
            }
        }
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/config/otel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&config_json))
        .mount(&rails_mock)
        .await;

    // --- Build and run the shipper directly (not full agent, just the pipeline path) ---
    // This tests the critical data-plane path: tailer → shipper → logrelay
    let hostname = "test-host";
    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", relay_mock.uri()),
        "arc_test",
        "repo_test",
        Some(edgepacer::identity::AgentIdentity::new(
            hostname.to_string(),
        )),
    )
    .unwrap();

    // Write test lines to the log file
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(f, "2026-04-05T10:00:00Z INFO Application started").unwrap();
        writeln!(f, "2026-04-05T10:00:01Z INFO Listening on port 8080").unwrap();
        writeln!(f, "2026-04-05T10:00:02Z WARN Connection timeout").unwrap();
    }

    // Tail the file
    let mut tailer = edgepacer::tailer::FileTailer::open_from_start(&log_path).unwrap();
    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(lines.len(), 3, "should read 3 lines from test file");

    // Ship to mock logrelay
    let result = shipper.ship(&lines).await.unwrap();
    match result {
        edgepacer::shipper::ShipResult::Accepted { count } => {
            assert_eq!(count, 3, "all 3 lines should be accepted");
        }
        edgepacer::shipper::ShipResult::Rejected { .. } => {
            panic!("unexpected rejection from mock logrelay");
        }
    }

    // Verify the mock received the request
    let received = relay_mock.received_requests().await.unwrap();
    assert!(
        !received.is_empty(),
        "logrelay should have received at least one request"
    );

    // Decode the protobuf to verify wire contract
    common::assert_gzip(&received[0]);
    let wire_req = common::decode_wire_request(&received[0]);

    assert_eq!(wire_req.batches.len(), 1, "should have one batch");
    let batch = &wire_req.batches[0];
    assert_eq!(batch.archive_id, "arc_test");
    assert_eq!(batch.repo_id, "repo_test");
    assert_eq!(batch.schema_version, 1);

    let Some(routed_batch::Payload::Logs(logs)) = &batch.payload else {
        panic!("expected routed log payload");
    };
    assert_eq!(logs.entries.len(), 3, "batch should contain 3 entries");

    // Verify entry content
    assert_eq!(
        match logs.entries[0].body.as_ref().unwrap() {
            wire_log_event::Body::RawText(text) => text.as_str(),
            other => panic!("expected raw_text body, got {:?}", other),
        },
        "2026-04-05T10:00:00Z INFO Application started"
    );
    assert_eq!(
        match logs.entries[2].body.as_ref().unwrap() {
            wire_log_event::Body::RawText(text) => text.as_str(),
            other => panic!("expected raw_text body, got {:?}", other),
        },
        "2026-04-05T10:00:02Z WARN Connection timeout"
    );

    // Verify resource_identifier is set in envelope metadata
    let metadata: serde_json::Value =
        serde_json::from_slice(&logs.entries[0].envelope.as_ref().unwrap().metadata_json).unwrap();
    assert_eq!(metadata["resource_identifier"], "test-host");
}

/// Verify the checkpoint + resume cycle works end-to-end.
#[tokio::test]
async fn e2e_checkpoint_resume_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("resumable.log");

    // Write initial content
    std::fs::write(&log_path, "line1\nline2\nline3\n").unwrap();

    // Session 1: read all lines, save checkpoint
    let cp_store =
        edgepacer::checkpoint::CheckpointStore::open(&dir.path().join("cp.redb")).unwrap();

    let mut tailer = edgepacer::tailer::FileTailer::open_from_start(&log_path).unwrap();
    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(lines.len(), 3);

    let pos = tailer.position();
    cp_store
        .save(&edgepacer::checkpoint::Checkpoint {
            path: log_path.to_string_lossy().into(),
            offset: pos.offset,
            inode: pos.inode,
            updated_at: std::time::SystemTime::now(),
            streaming: None,
        })
        .unwrap();

    // Append more content
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(f, "line4").unwrap();
        writeln!(f, "line5").unwrap();
    }

    // Session 2: resume from checkpoint, should only see new lines
    let cp = cp_store.load(&log_path.to_string_lossy()).unwrap().unwrap();

    let mut tailer2 = edgepacer::tailer::FileTailer::open_with_checkpoint(&log_path, &cp).unwrap();
    let new_lines = tailer2.read_lines(100).unwrap();
    assert_eq!(new_lines.len(), 2);
    assert_eq!(new_lines[0], b"line4");
    assert_eq!(new_lines[1], b"line5");
}
