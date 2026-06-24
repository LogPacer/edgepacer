//! LogPacer Wire Protocol
//!
//! Shared wire format for communication between EdgePacer and LogPacer ingest
//! services. OTLP is retained by the ingest layer for optional third-party
//! compatibility, but EdgePacer uses this native routed protocol.
//!
//! Endpoint: POST /v1/logpacer-wire
//!
//! # Routing Hierarchy
//!
//! - `archive_id` — tenant-level (all logs for one customer)
//! - `repo_id` — log source separation within tenant (proxy vs app vs DB)
//! - event metadata — per-entry downstream gating/correlation context

/// Generated protobuf types from `proto/logpacer_wire.proto`
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/logpacer.wire.v1.rs"));
}

// Re-export main types at crate root for ergonomic imports
pub use proto::EbpfEventKind;
pub use proto::EventEnvelope;
pub use proto::NetworkFlow;
pub use proto::RequestSignal;
pub use proto::RoutedBatch;
pub use proto::SecurityEvent;
pub use proto::SecurityKind;
pub use proto::WireEbpfBatch;
pub use proto::WireEbpfEvent;
pub use proto::WireGraphBatch;
pub use proto::WireJsonEvent;
pub use proto::WireLogBatch;
pub use proto::WireLogEvent;
pub use proto::WireMetricBatch;
pub use proto::WireRequest;
pub use proto::WireResponse;
pub use proto::WireTraceBatch;
pub use proto::routed_batch;
pub use proto::wire_ebpf_event;
pub use proto::wire_log_event;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn wire_response_roundtrip() {
        let response = WireResponse {
            accepted: 42,
            rejected: 0,
            error_message: String::new(),
        };

        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();

        let decoded = WireResponse::decode(&buf[..]).unwrap();
        assert_eq!(decoded.accepted, 42);
        assert_eq!(decoded.rejected, 0);
    }

    #[test]
    fn roundtrip_wire_request_with_routed_log_event() {
        let request = WireRequest {
            batches: vec![RoutedBatch {
                archive_id: "arc_customer1".into(),
                repo_id: "repo_proxy".into(),
                schema_version: 1,
                payload: Some(routed_batch::Payload::Logs(WireLogBatch {
                    entries: vec![WireLogEvent {
                        envelope: Some(EventEnvelope {
                            logtime_ms: Some(1712275200000),
                            source_at_ms: Some(1712275199000),
                            metadata_json: br#"{"trace_id":"abc","tenant_role":"prod"}"#.to_vec(),
                        }),
                        body: Some(wire_log_event::Body::EntryJson(
                            br#"{"level":"info","msg":"request handled"}"#.to_vec(),
                        )),
                    }],
                })),
            }],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.batches.len(), 1);
        let batch = &decoded.batches[0];
        assert_eq!(batch.archive_id, "arc_customer1");
        assert_eq!(batch.repo_id, "repo_proxy");

        let Some(routed_batch::Payload::Logs(logs)) = &batch.payload else {
            panic!("expected routed log payload");
        };
        assert_eq!(logs.entries.len(), 1);
        assert_eq!(
            logs.entries[0].envelope.as_ref().unwrap().logtime_ms,
            Some(1712275200000)
        );
    }

    #[test]
    fn roundtrip_wire_request_with_graph_event() {
        let request = WireRequest {
            batches: vec![RoutedBatch {
                archive_id: "arc_customer1".into(),
                repo_id: "repo_graph".into(),
                schema_version: 1,
                payload: Some(routed_batch::Payload::Graph(WireGraphBatch {
                    entries: vec![WireJsonEvent {
                        envelope: Some(EventEnvelope {
                            logtime_ms: Some(1712275200000),
                            source_at_ms: Some(1712275199000),
                            metadata_json: br#"{"grant_scope":"tenant"}"#.to_vec(),
                        }),
                        entry_json: br#"{"subject":"repo","predicate":"has_log","object":"line"}"#
                            .to_vec(),
                        embeds_json: br#"{"text":"repo has_log line"}"#.to_vec(),
                    }],
                })),
            }],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        let Some(routed_batch::Payload::Graph(graph)) = &decoded.batches[0].payload else {
            panic!("expected routed graph payload");
        };
        assert_eq!(graph.entries.len(), 1);
        assert_eq!(
            graph.entries[0].envelope.as_ref().unwrap().logtime_ms,
            Some(1712275200000)
        );
        assert_eq!(
            graph.entries[0].embeds_json,
            br#"{"text":"repo has_log line"}"#
        );
    }

    #[test]
    fn roundtrip_wire_json_event_without_embeds() {
        let event = WireJsonEvent {
            envelope: Some(EventEnvelope {
                logtime_ms: Some(1712275200000),
                source_at_ms: None,
                metadata_json: b"{}".to_vec(),
            }),
            entry_json: br#"{"kind":"edge","from":"a","to":"b"}"#.to_vec(),
            embeds_json: vec![],
        };

        let mut buf = Vec::new();
        event.encode(&mut buf).unwrap();

        let decoded = WireJsonEvent::decode(&buf[..]).unwrap();
        assert!(decoded.embeds_json.is_empty());
    }

    #[test]
    fn roundtrip_wire_request_with_metrics_payload() {
        let request = WireRequest {
            batches: vec![RoutedBatch {
                archive_id: "arc_customer1".into(),
                repo_id: "repo_metrics".into(),
                schema_version: 1,
                payload: Some(routed_batch::Payload::Metrics(WireMetricBatch {
                    entries_json: vec![
                        br#"{"logtime":1712275200000,"resource_id":"host-1","host_cpu_percent":42.5}"#
                            .to_vec(),
                    ],
                })),
            }],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        let Some(routed_batch::Payload::Metrics(metrics)) = &decoded.batches[0].payload else {
            panic!("expected routed metrics payload");
        };
        assert_eq!(metrics.entries_json.len(), 1);
    }

    #[test]
    fn roundtrip_wire_request_with_ebpf_network_flow() {
        let request = WireRequest {
            batches: vec![RoutedBatch {
                archive_id: "arc_customer1".into(),
                repo_id: "repo_ebpf".into(),
                schema_version: 1,
                payload: Some(routed_batch::Payload::Ebpf(WireEbpfBatch {
                    entries: vec![WireEbpfEvent {
                        envelope: Some(EventEnvelope {
                            logtime_ms: Some(1712275200000),
                            source_at_ms: None,
                            metadata_json: br#"{"resource_identifier":"host-1"}"#.to_vec(),
                        }),
                        kind: EbpfEventKind::NetworkFlow as i32,
                        event: Some(wire_ebpf_event::Event::Flow(NetworkFlow {
                            saddr: vec![10, 0, 1, 5],
                            daddr: vec![10, 0, 2, 9],
                            sport: 54321,
                            dport: 5432,
                            protocol: 6, // TCP
                            bytes_tx: 1024,
                            bytes_rx: 4096,
                            packets_tx: 8,
                            packets_rx: 12,
                            pid: 4242,
                            cgroup_id: 9999,
                            netns_ino: 4026531840,
                            direction: 1, // egress
                        })),
                    }],
                })),
            }],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let decoded = WireRequest::decode(&buf[..]).unwrap();
        let Some(routed_batch::Payload::Ebpf(batch)) = &decoded.batches[0].payload else {
            panic!("expected routed ebpf payload");
        };
        assert_eq!(batch.entries.len(), 1);
        let event = &batch.entries[0];
        assert_eq!(event.kind, EbpfEventKind::NetworkFlow as i32);
        let Some(wire_ebpf_event::Event::Flow(flow)) = &event.event else {
            panic!("expected network flow event");
        };
        assert_eq!(flow.dport, 5432);
        assert_eq!(flow.saddr, vec![10, 0, 1, 5]);
        assert_eq!(flow.protocol, 6);
    }

    #[test]
    fn roundtrip_ebpf_security_and_request_events() {
        let batch = WireEbpfBatch {
            entries: vec![
                WireEbpfEvent {
                    envelope: None,
                    kind: EbpfEventKind::Security as i32,
                    event: Some(wire_ebpf_event::Event::Security(SecurityEvent {
                        kind: SecurityKind::Exec as i32,
                        pid: 7659,
                        ppid: 1,
                        uid: 0,
                        cgroup_id: 1234,
                        comm: "edgepacer-ebpf".into(),
                        filename: "/usr/local/bin/edgepacer".into(),
                        argv: vec!["edgepacer".into(), "-r".into(), "agent-1".into()],
                        syscall_nr: 59,
                        ret: 0,
                    })),
                },
                WireEbpfEvent {
                    envelope: None,
                    kind: EbpfEventKind::Request as i32,
                    event: Some(wire_ebpf_event::Event::Request(RequestSignal {
                        trace_id: vec![0u8; 16],
                        span_id: vec![1u8; 8],
                        parent_span_id: vec![],
                        service_name: "api-gateway".into(),
                        operation: "GET /api/users".into(),
                        start_unix_nano: 1_712_275_200_000_000_000,
                        duration_nano: 4_200_000,
                        status_code: 200,
                        pid: 4242,
                        cgroup_id: 9999,
                        attributes: std::collections::HashMap::from([(
                            "http.method".to_string(),
                            "GET".to_string(),
                        )]),
                    })),
                },
            ],
        };

        let mut buf = Vec::new();
        batch.encode(&mut buf).unwrap();
        let decoded = WireEbpfBatch::decode(&buf[..]).unwrap();
        assert_eq!(decoded.entries.len(), 2);

        let Some(wire_ebpf_event::Event::Security(sec)) = &decoded.entries[0].event else {
            panic!("expected security event");
        };
        assert_eq!(sec.comm, "edgepacer-ebpf");
        assert_eq!(sec.argv.len(), 3);
        assert_eq!(sec.kind, SecurityKind::Exec as i32);

        let Some(wire_ebpf_event::Event::Request(req)) = &decoded.entries[1].event else {
            panic!("expected request signal");
        };
        assert_eq!(req.status_code, 200);
        assert_eq!(
            req.attributes.get("http.method").map(String::as_str),
            Some("GET")
        );
    }
}
