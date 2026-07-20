//! Integration test: tail a file → encode logpacer_wire → ship to mock logrelay → verify.

mod common;

use edgepacer::shipper::{CappedShipDeferredReason, CappedShipOutcome};
use logpacer_wire::{WireResponse, routed_batch, wire_log_event};
use prost::Message;
use std::collections::HashMap;
use std::io::Write;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn decode_log_bodies(request: &wiremock::Request) -> (String, String, u32, Vec<String>) {
    let request = common::decode_wire_request(request);
    assert_eq!(request.batches.len(), 1);

    let batch = &request.batches[0];
    let Some(routed_batch::Payload::Logs(logs)) = &batch.payload else {
        panic!("expected routed log payload");
    };

    let bodies: Vec<String> = logs
        .entries
        .iter()
        .map(|entry| match entry.body.as_ref().expect("body present") {
            wire_log_event::Body::RawText(text) => text.clone(),
            wire_log_event::Body::RawBytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            wire_log_event::Body::EntryJson(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        })
        .collect();

    (
        batch.archive_id.clone(),
        batch.repo_id.clone(),
        batch.schema_version,
        bodies,
    )
}

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

/// Simulate the full M2 path: read lines from file, encode, POST to mock logrelay.
#[tokio::test]
async fn tail_encode_ship_roundtrip() {
    // Start mock logrelay
    let mock_server = MockServer::start().await;

    // Set up mock to accept logpacer-wire requests and return success response
    let success_response = WireResponse {
        accepted: 3,
        rejected: 0,
        error_message: String::new(),
    };
    let mut response_buf = Vec::new();
    success_response.encode(&mut response_buf).unwrap();

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(response_buf, "application/x-protobuf"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // Write a test log file
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("app.log");
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "2026-04-05 INFO Starting up").unwrap();
        writeln!(f, "2026-04-05 INFO Request handled in 42ms").unwrap();
        writeln!(f, "2026-04-05 WARN Slow query detected").unwrap();
    }

    // Create tailer from start (catch-up mode for test)
    let mut tailer = edgepacer::tailer::FileTailer::open_from_start(&log_path).unwrap();
    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(lines.len(), 3);

    // Create shipper pointed at mock server
    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_test_tenant",
        "repo_app",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-integration-test".to_string(),
        )),
    )
    .unwrap();

    // Ship the batch
    let result = shipper.ship(&lines).await.unwrap();
    match result {
        edgepacer::shipper::ShipResult::Accepted { count } => {
            assert_eq!(count, 3);
        }
        other => panic!("expected Accepted, got {:?}", other),
    }

    // Verify the mock received exactly 1 request
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    common::assert_gzip(&requests[0]);

    // Decode what was sent and verify field mapping
    let (archive_id, repo_id, schema_version, bodies) = decode_log_bodies(&requests[0]);
    assert_eq!(archive_id, "arc_test_tenant");
    assert_eq!(repo_id, "repo_app");
    assert_eq!(schema_version, 1);
    assert_eq!(bodies.len(), 3);

    // Verify entry content
    assert_eq!(bodies[0], "2026-04-05 INFO Starting up");
    assert_eq!(bodies[1], "2026-04-05 INFO Request handled in 42ms");
    assert_eq!(bodies[2], "2026-04-05 WARN Slow query detected");

    // Verify resource_identifier is carried in envelope metadata
    let request = common::decode_wire_request(&requests[0]);
    let Some(routed_batch::Payload::Logs(logs)) = &request.batches[0].payload else {
        panic!("expected routed log payload");
    };
    for entry in &logs.entries {
        let metadata = entry.envelope.as_ref().expect("envelope present");
        let value: serde_json::Value = serde_json::from_slice(&metadata.metadata_json).unwrap();
        assert_eq!(value["resource_identifier"], "host-integration-test");
        assert!(metadata.source_at_ms.unwrap() > 0);
    }
}

#[tokio::test]
async fn shipper_attaches_cached_upload_token() {
    edgepacer::upload_token_store::store().replace(HashMap::from([
        ("repo_shipper_auth".to_string(), "jwt-log".to_string()),
        ("repo_metrics_auth".to_string(), "jwt-metrics".to_string()),
        ("repo_trace_auth".to_string(), "jwt-trace".to_string()),
    ]));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/wire"))
        .and(header("authorization", "Bearer jwt-log"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_shipper_auth",
        "repo_shipper_auth",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-auth".to_string(),
        )),
    )
    .unwrap();

    let result = shipper.ship(&[b"line".to_vec()]).await.unwrap();

    match result {
        edgepacer::shipper::ShipResult::Accepted { count } => assert_eq!(count, 1),
        other => panic!("expected Accepted, got {:?}", other),
    }
}

/// Verify retry behavior on 503 then success.
#[tokio::test]
async fn retries_on_server_error() {
    let mock_server = MockServer::start().await;

    let success_response = WireResponse {
        accepted: 1,
        rejected: 0,
        error_message: String::new(),
    };
    let mut response_buf = Vec::new();
    success_response.encode(&mut response_buf).unwrap();

    // First request: 503, second: 200
    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(response_buf, "application/x-protobuf"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_retry",
        "repo_retry",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-retry".to_string(),
        )),
    )
    .unwrap();

    let lines = vec![b"test line".to_vec()];
    let result = shipper.ship(&lines).await.unwrap();
    match result {
        edgepacer::shipper::ShipResult::Accepted { count } => assert_eq!(count, 1),
        other => panic!("expected Accepted after retry, got {:?}", other),
    }
}

/// Verify 400 is not retried (terminal failure).
#[tokio::test]
async fn no_retry_on_client_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .expect(1) // exactly 1 attempt, no retry
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_bad",
        "repo_bad",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-bad".to_string(),
        )),
    )
    .unwrap();

    let lines = vec![b"bad line".to_vec()];
    let result = shipper.ship(&lines).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn capped_ship_shrinks_after_payload_too_large() {
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

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_shrink",
        "repo_shrink",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-shrink".to_string(),
        )),
    )
    .unwrap();
    let lines = vec![
        b"one".to_vec(),
        b"two".to_vec(),
        b"three".to_vec(),
        b"four".to_vec(),
    ];

    let outcome = shipper.ship_capped_with_shrink(&lines, usize::MAX).await;
    assert_eq!(outcome, CappedShipOutcome::Delivered { count: 2 });

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let (_, _, _, first_bodies) = decode_log_bodies(&requests[0]);
    let (_, _, _, second_bodies) = decode_log_bodies(&requests[1]);
    assert_eq!(first_bodies, vec!["one", "two", "three", "four"]);
    assert_eq!(second_bodies, vec!["one", "two"]);
}

#[tokio::test]
async fn capped_ship_drops_single_entry_rejected_as_payload_too_large() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_drop",
        "repo_drop",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-drop".to_string(),
        )),
    )
    .unwrap();

    let outcome = shipper
        .ship_capped_with_shrink(&[b"oversized".to_vec()], usize::MAX)
        .await;
    assert_eq!(outcome, CappedShipOutcome::DroppedOversized { count: 1 });

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn capped_ship_drops_fully_adjudicated_rejection() {
    // accepted + rejected == the requested batch size (2): the relay fully
    // resolved every entry, so the poison fix must advance past the whole
    // prefix rather than re-shipping the accepted entry forever (the
    // duplication livelock this fix closes).
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            encoded_wire_response(1, 1, "second rejected"),
            "application/x-protobuf",
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_partial",
        "repo_partial",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-partial".to_string(),
        )),
    )
    .unwrap();
    let lines = vec![b"one".to_vec(), b"two".to_vec()];

    let outcome = shipper.ship_capped_with_shrink(&lines, usize::MAX).await;
    assert_eq!(
        outcome,
        CappedShipOutcome::RejectedAdjudicated {
            accepted: 1,
            rejected: 1,
        }
    );
}

#[tokio::test]
async fn capped_ship_defers_partial_adjudication() {
    // Negative control: accepted + rejected (2) is LESS than the requested
    // batch size (3) — the relay hasn't resolved the whole batch, so the
    // normal retry/defer behavior must still apply (nothing dropped).
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            encoded_wire_response(1, 1, "partial adjudication"),
            "application/x-protobuf",
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_partial_adjudication",
        "repo_partial_adjudication",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-partial-adjudication".to_string(),
        )),
    )
    .unwrap();
    let lines = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];

    let outcome = shipper.ship_capped_with_shrink(&lines, usize::MAX).await;
    assert_eq!(
        outcome,
        CappedShipOutcome::Deferred {
            reason: CappedShipDeferredReason::RelayRejected,
        }
    );
}

#[tokio::test]
async fn capped_ship_defers_ambiguous_accepted_count() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wire"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(encoded_wire_response(1, 0, ""), "application/x-protobuf"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        "arc_mismatch",
        "repo_mismatch",
        Some(edgepacer::identity::AgentIdentity::new(
            "host-mismatch".to_string(),
        )),
    )
    .unwrap();
    let lines = vec![b"one".to_vec(), b"two".to_vec()];

    let outcome = shipper.ship_capped_with_shrink(&lines, usize::MAX).await;
    assert_eq!(
        outcome,
        CappedShipOutcome::Deferred {
            reason: CappedShipDeferredReason::AcceptedCountMismatch,
        }
    );
}
