#![cfg(unix)]

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use logpacer_wire::WireResponse;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use tokio::process::{Child, Command};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(directive_file: &std::path::Path, isolation_dir: &std::path::Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_edgepacer"))
            .args([
                "--local-mode",
                "--directive-file",
                directive_file.to_str().unwrap(),
                "--log-level",
                "warn",
            ])
            .env("EDGEPACER_STATE_DIR", isolation_dir.join("state"))
            .env("XDG_CACHE_HOME", isolation_dir.join("cache"))
            .env_remove("EDGEPACER_ACCOUNT_TOKEN")
            .env_remove("EDGEPACER_SERVER_TOKEN")
            .env_remove("EDGEPACER_RESOURCE_ID")
            .env_remove("EDGEPACER_RAILS_URL")
            .env_remove("EDGEPACER_HOST_MODE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to launch edgepacer");

        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child already consumed")
    }

    async fn interrupt_and_wait(mut self) {
        let mut child = self.child.take().expect("child already consumed");
        let signal_result = unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGINT) };
        assert_eq!(signal_result, 0, "failed to signal edgepacer");

        let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(result) => result.expect("failed to wait for edgepacer"),
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                panic!("edgepacer did not shut down after SIGINT");
            }
        };
        assert!(status.success(), "edgepacer exited with {status}");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

#[tokio::test]
async fn local_mode_entrypoint_runs_and_stops_trace_proxy() {
    let relay = MockServer::start().await;
    let mut wire_response = Vec::new();
    WireResponse {
        accepted: 1,
        rejected: 0,
        error_message: String::new(),
    }
    .encode(&mut wire_response)
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/logpacer-wire"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(wire_response, "application/x-protobuf"),
        )
        .expect(1)
        .mount(&relay)
        .await;

    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_address = reserved.local_addr().unwrap();
    drop(reserved);

    let isolation = tempfile::tempdir().unwrap();
    let directive_file = isolation.path().join("directive.json");
    std::fs::write(
        &directive_file,
        serde_json::to_vec(&serde_json::json!({
            "resource_identifier": "entrypoint-test",
            "traces": {
                "entrypoint-traces": {
                    "listen_address": listen_address.to_string(),
                    "subbox_endpoint": format!("{}/v1/logpacer-wire", relay.uri()),
                    "archive_id": "arc_test",
                    "repo_id": "repo_test",
                    "require_service_name": false
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let mut child = ChildGuard::spawn(&directive_file, isolation.path());
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "entrypoint-span".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let mut body = Vec::new();
    request.encode(&mut body).unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let url = format!("http://{listen_address}/v1/traces");

    let response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.child_mut().try_wait().unwrap() {
                panic!("edgepacer exited before accepting traces: {status}");
            }
            match client
                .post(&url)
                .header("content-type", "application/x-protobuf")
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => break response,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("local mode did not start the configured trace proxy");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    relay.verify().await;

    child.interrupt_and_wait().await;
    TcpListener::bind(listen_address)
        .expect("local-mode shutdown must release the trace proxy listener");
}
