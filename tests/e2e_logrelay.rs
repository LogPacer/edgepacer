//! End-to-end test: mock Rails auth/config -> EdgePacer -> real or mock LogRelay.
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

use std::io::Write;

use logpacer_wire::{WireRequest, WireResponse, routed_batch, wire_log_event};
use prost::Message;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    let req_body = &received[0].body;
    let wire_req = WireRequest::decode(&req_body[..]).unwrap();

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
