//! Live logrelay smoke test — ships real protobuf to a running logrelay instance.
//!
//! SKIPPED by default (requires a running logrelay). Run with:
//!   cargo test --test live_relay_smoke -- --ignored
//!
//! Prerequisites:
//!   1. Logrelay running at http://127.0.0.1:4318
//!   2. Tenant config created:
//!
//! ```sh
//! curl -X POST http://127.0.0.1:8090/repos/arc_test/repo_test/config \
//!   -H "Content-Type: application/json" \
//!   -d '{"logrelay": {"format": "json", "use_resource_identifier": true}}'
//! ```

use edgepacer::shipper::{ShipResult, Shipper};

#[tokio::test]
#[ignore] // Requires running logrelay
async fn live_ship_to_logrelay() {
    let shipper = Shipper::new(
        "http://127.0.0.1:4318",
        "arc_test",
        "repo_test",
        Some(edgepacer::identity::AgentIdentity::new(
            "edgepacer-rust-live-test".to_string(),
        )),
    )
    .unwrap();

    let lines: Vec<Vec<u8>> = vec![
        b"2026-04-05T19:00:00Z INFO EdgePacer Rust rewrite - first real log to logrelay!".to_vec(),
        b"2026-04-05T19:00:01Z INFO Shipping via logpacer_wire protocol".to_vec(),
        b"2026-04-05T19:00:02Z INFO All 10 milestones complete, 101 tests passing".to_vec(),
    ];

    let result = shipper.ship(&lines).await.unwrap();

    match result {
        ShipResult::Accepted { count } => {
            println!("SUCCESS: logrelay accepted {count} entries via logpacer_wire");
            assert_eq!(count, 3);
        }
        ShipResult::Rejected {
            accepted,
            rejected,
            message,
        } => {
            panic!("REJECTED: accepted={accepted}, rejected={rejected}, message={message}");
        }
    }
}

#[tokio::test]
#[ignore]
async fn live_file_tail_and_ship() {
    use std::io::Write;

    // Create a temp log file and write test data
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("live_test.log");

    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "2026-04-05T19:01:00Z INFO Live tail test line 1").unwrap();
        writeln!(f, "2026-04-05T19:01:01Z INFO Live tail test line 2").unwrap();
        writeln!(f, "2026-04-05T19:01:02Z WARN Live tail test line 3").unwrap();
    }

    // Tail the file
    let mut tailer = edgepacer::tailer::FileTailer::open_from_start(&log_path).unwrap();
    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(lines.len(), 3);

    // Ship to real logrelay
    let shipper = Shipper::new(
        "http://127.0.0.1:4318",
        "arc_test",
        "repo_test",
        Some(edgepacer::identity::AgentIdentity::new(
            "edgepacer-rust-live-tail".to_string(),
        )),
    )
    .unwrap();

    let result = shipper.ship(&lines).await.unwrap();
    match result {
        ShipResult::Accepted { count } => {
            println!("SUCCESS: tailed {count} lines from file and shipped to live logrelay");
            assert_eq!(count, 3);
        }
        ShipResult::Rejected {
            accepted,
            rejected,
            message,
        } => {
            panic!("REJECTED: accepted={accepted}, rejected={rejected}, message={message}");
        }
    }
}
