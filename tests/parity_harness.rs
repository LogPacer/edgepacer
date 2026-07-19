//! M2 Parity Harness — proves Rust native path produces equivalent logrelay input
//! to what Go's DirectBatchExporter→OTLP path would produce for the same log lines.
//!
//! This is the M2 acceptance gate. It verifies that both paths carry the same
//! routing-critical and payload-critical information to logrelay.
//!
//! What this proves:
//! - Native handoff spine produces correct field mapping
//! - archive_id, repo_id routing is equivalent
//! - body content is preserved byte-for-byte
//! - resource_identifier is set identically
//! - timestamp semantics are equivalent (both capture-time for M2)
//!
//! What this does NOT prove (deferred to M4):
//! - Delivery parity (disk-backed buffering, DLQ, checkpoint-on-ack)
//! - Original timestamp parsing (source_at_ms from log line vs capture time)
//!
//! Go reference: internal/exporter/direct_batch_exporter.go

mod common;

use logpacer_wire::{WireResponse, routed_batch, wire_log_event};
use prost::Message;
use std::io::Write;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What the Go DirectBatchExporter would set for the same input.
/// Extracted from reading Go's buildLogs() method.
// clippy: this struct documents the full Go reference contract; `service_name`
// and `severity_text` are recorded for parity even though the current
// assertions don't compare them yet.
#[allow(dead_code)]
struct GoEquivalentFields {
    // Resource attributes (set on ResourceLogs)
    service_name: String,
    archive_id: String,
    repo_id: String,
    resource_identifier: String,
    // Per-record fields
    bodies: Vec<String>,   // body as UTF-8 string
    severity_text: String, // "INFO"
}

/// What our Rust shipper actually produces.
struct RustNativeFields {
    archive_id: String,
    repo_id: String,
    resource_identifier: String,
    bodies: Vec<Vec<u8>>,
    schema_version: u32,
}

/// Extract semantic fields from a captured Rust WireRequest.
fn extract_rust_fields(request: &wiremock::Request) -> RustNativeFields {
    let request = common::decode_wire_request(request);
    assert_eq!(request.batches.len(), 1, "expected exactly 1 batch");

    let batch = &request.batches[0];
    let Some(routed_batch::Payload::Logs(logs)) = &batch.payload else {
        panic!("expected routed log payload");
    };

    let bodies: Vec<Vec<u8>> = logs
        .entries
        .iter()
        .map(|entry| match entry.body.as_ref().expect("body present") {
            wire_log_event::Body::RawText(text) => text.as_bytes().to_vec(),
            wire_log_event::Body::RawBytes(bytes) => bytes.clone(),
            wire_log_event::Body::EntryJson(bytes) => bytes.clone(),
        })
        .collect();

    let metadata = logs.entries[0].envelope.as_ref().expect("envelope present");
    let metadata_value: serde_json::Value =
        serde_json::from_slice(&metadata.metadata_json).expect("metadata json");
    let ri = metadata_value["resource_identifier"]
        .as_str()
        .expect("resource_identifier in metadata")
        .to_string();

    for entry in &logs.entries {
        let entry_metadata = entry.envelope.as_ref().expect("envelope present");
        let value: serde_json::Value =
            serde_json::from_slice(&entry_metadata.metadata_json).unwrap();
        assert_eq!(
            value["resource_identifier"].as_str().unwrap(),
            ri.as_str(),
            "resource_identifier must be consistent"
        );
    }

    RustNativeFields {
        archive_id: batch.archive_id.clone(),
        repo_id: batch.repo_id.clone(),
        resource_identifier: ri,
        bodies,
        schema_version: batch.schema_version,
    }
}

/// Define what Go's DirectBatchExporter would produce for the same input.
fn go_equivalent(
    archive_id: &str,
    repo_id: &str,
    resource_identifier: &str,
    lines: &[&str],
) -> GoEquivalentFields {
    GoEquivalentFields {
        service_name: "edgepacer".to_string(),
        archive_id: archive_id.to_string(),
        repo_id: repo_id.to_string(),
        resource_identifier: resource_identifier.to_string(),
        bodies: lines.iter().map(|l| l.to_string()).collect(),
        severity_text: "INFO".to_string(),
    }
}

/// Assert that the Rust native path and Go OTLP path produce equivalent
/// semantic content for logrelay routing and processing.
fn assert_parity(rust: &RustNativeFields, go: &GoEquivalentFields) {
    // Routing parity: archive_id and repo_id must match exactly
    assert_eq!(
        rust.archive_id, go.archive_id,
        "archive_id routing mismatch"
    );
    assert_eq!(rust.repo_id, go.repo_id, "repo_id routing mismatch");

    // Identity parity: resource_identifier must match
    assert_eq!(
        rust.resource_identifier, go.resource_identifier,
        "resource_identifier mismatch"
    );

    // Body parity: content must be byte-equivalent
    assert_eq!(rust.bodies.len(), go.bodies.len(), "entry count mismatch");
    for (i, (rust_body, go_body)) in rust.bodies.iter().zip(go.bodies.iter()).enumerate() {
        assert_eq!(rust_body, go_body.as_bytes(), "body mismatch at entry {i}");
    }

    // Schema version must be set
    assert_eq!(rust.schema_version, 1, "schema_version must be 1");
}

/// The parity test: same input through both paths, compare at logrelay boundary.
#[tokio::test]
async fn m2_parity_native_vs_otlp_path() {
    // === Input ===
    let log_lines = [
        "2026-04-05T10:00:00Z INFO  Starting application server",
        "2026-04-05T10:00:01Z INFO  Listening on 0.0.0.0:8080",
        "2026-04-05T10:00:02Z WARN  Connection pool nearly full (47/50)",
    ];
    let archive_id = "arc_parity_tenant";
    let repo_id = "repo_parity_app";
    let resource_identifier = "host-parity-test";

    // === Path 1: Rust native (what our shipper produces) ===
    let mock_server = MockServer::start().await;

    let success_response = WireResponse {
        accepted: log_lines.len() as u32,
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

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        archive_id,
        repo_id,
        Some(edgepacer::identity::AgentIdentity::new(
            resource_identifier.to_string(),
        )),
    )
    .unwrap();

    let lines: Vec<Vec<u8>> = log_lines.iter().map(|l| l.as_bytes().to_vec()).collect();
    let result = shipper.ship(&lines).await.unwrap();
    match &result {
        edgepacer::shipper::ShipResult::Accepted { count } => {
            assert_eq!(*count, log_lines.len() as u32);
        }
        other => panic!("expected Accepted, got {:?}", other),
    }

    // Capture what was sent
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    common::assert_gzip(&requests[0]);
    let rust_fields = extract_rust_fields(&requests[0]);

    // === Path 2: Go equivalent (what DirectBatchExporter would produce) ===
    let go_fields = go_equivalent(archive_id, repo_id, resource_identifier, &log_lines);

    // === Parity assertion ===
    assert_parity(&rust_fields, &go_fields);

    // === Additional M2-specific checks ===

    // Timestamps: source_at_ms should be recent (capture-time)
    let decoded = common::decode_wire_request(&requests[0]);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let Some(routed_batch::Payload::Logs(logs)) = &decoded.batches[0].payload else {
        panic!("expected routed log payload");
    };

    for entry in &logs.entries {
        let source_at_ms = entry
            .envelope
            .as_ref()
            .and_then(|e| e.source_at_ms)
            .expect("source_at_ms present");
        assert!(
            (now_ms - source_at_ms).abs() < 5000,
            "source_at_ms too far from now: {} vs {}",
            source_at_ms,
            now_ms
        );
    }
}

/// Verify parity holds when shipping from a tailed file (full end-to-end).
#[tokio::test]
async fn m2_parity_from_file_tail() {
    let archive_id = "arc_file_parity";
    let repo_id = "repo_file_parity";
    let resource_identifier = "host-file-parity";

    let log_lines = [
        "nginx: 192.168.1.1 - - [05/Apr/2026:10:00:00 +0000] \"GET /api/health HTTP/1.1\" 200 15",
        "nginx: 192.168.1.2 - - [05/Apr/2026:10:00:01 +0000] \"POST /api/data HTTP/1.1\" 201 42",
    ];

    // Write test log file
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nginx.log");
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        for line in &log_lines {
            writeln!(f, "{}", line).unwrap();
        }
    }

    // Tail the file
    let mut tailer = edgepacer::tailer::FileTailer::open_from_start(&log_path).unwrap();
    let tailed_lines = tailer.read_lines(100).unwrap();
    assert_eq!(tailed_lines.len(), log_lines.len());

    // Verify tailed content matches original (no corruption in the tail path)
    for (tailed, original) in tailed_lines.iter().zip(log_lines.iter()) {
        assert_eq!(
            tailed,
            original.as_bytes(),
            "tailed content must match original"
        );
    }

    // Ship via mock
    let mock_server = MockServer::start().await;
    let success_response = WireResponse {
        accepted: log_lines.len() as u32,
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

    let shipper = edgepacer::shipper::Shipper::new(
        &format!("{}/wire", mock_server.uri()),
        archive_id,
        repo_id,
        Some(edgepacer::identity::AgentIdentity::new(
            resource_identifier.to_string(),
        )),
    )
    .unwrap();

    shipper.ship(&tailed_lines).await.unwrap();

    // Verify parity
    let requests = mock_server.received_requests().await.unwrap();
    common::assert_gzip(&requests[0]);
    let rust_fields = extract_rust_fields(&requests[0]);
    let go_fields = go_equivalent(archive_id, repo_id, resource_identifier, &log_lines);
    assert_parity(&rust_fields, &go_fields);
}
