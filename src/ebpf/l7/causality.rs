//! Intra-process span hierarchy — tid-window causality. A CLIENT record whose
//! window nests inside a SERVER record's window on the same (pid, tid) was
//! caused by that request (thread-per-request runtimes; async runtimes
//! degrade to today's flat behavior — never a guessed parent). Parenting is
//! expressed by synthesizing the same [`PropagatedContext`] wire extraction
//! produces, so local causality and W3C propagation flow through one
//! adoption path: `ctx_trace_id`, `to_otlp_span`, both arms, identical ids.
//!
//! The `#[ignore]`d acceptance tests below are the standing definition of the
//! matching contract. They are owned by the reviewer — implement until they
//! pass with the `#[ignore]` attributes removed; any change to their
//! expectations needs reviewer sign-off.

use opentelemetry_proto::tonic::trace::v1::span::SpanKind;

use super::span::SpanContext;
use super::{L7Record, PropagatedContext};

/// One pending span awaiting flush: the parsed record, its context, the
/// wiring layer's kind verdict, and the completing segment's thread id — the
/// causality key. The runner's flush batch holds these.
#[derive(Debug, Clone)]
pub struct LocalSpan {
    pub record: L7Record,
    pub ctx: SpanContext,
    pub kind: Option<SpanKind>,
    pub tid: u32,
}

/// Assign local parents within one flush batch: every CLIENT span whose
/// window nests inside a SERVER span's window on the same (pid, tid) adopts
/// that server's trace — the innermost containing window when several nest.
/// Adoption synthesizes `record.propagated` (parent = the server's span id,
/// trace id / flags / trace_state inherited from the server) and rewrites
/// `ctx.trace_id` so BOTH arms carry the shared id. A client that already
/// carries a wire-extracted context is never overwritten, UNSPECIFIED spans
/// never participate, and servers are never modified.
#[allow(dead_code)] // wired into the runner's flush path later in this slice
pub fn assign_local_parents(entries: &mut [LocalSpan]) {
    // Slice H1 stub: the acceptance tests below define the contract and stay
    // #[ignore]d red until this is implemented.
    let _ = entries;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::l7::Protocol;

    fn record(start: i64, end: i64) -> L7Record {
        L7Record {
            protocol: Protocol::Http1,
            operation: "GET /x".into(),
            status_code: 200,
            error: false,
            start_unix_nano: start,
            duration_nano: end - start,
            attributes: Vec::new(),
            propagated: None,
        }
    }

    fn ctx(trace_seed: u8, span_seed: u8) -> SpanContext {
        SpanContext {
            service_name: "checkout".into(),
            pid: 4242,
            cgroup_id: 99,
            trace_id: vec![trace_seed; 16],
            span_id: vec![span_seed; 8],
            peer: None,
        }
    }

    fn server(start: i64, end: i64, tid: u32, trace_seed: u8, span_seed: u8) -> LocalSpan {
        LocalSpan {
            record: record(start, end),
            ctx: ctx(trace_seed, span_seed),
            kind: Some(SpanKind::Server),
            tid,
        }
    }

    fn client(start: i64, end: i64, tid: u32, trace_seed: u8, span_seed: u8) -> LocalSpan {
        LocalSpan {
            record: record(start, end),
            ctx: ctx(trace_seed, span_seed),
            kind: Some(SpanKind::Client),
            tid,
        }
    }

    /// The core adoption: a nested client joins its server's trace — shared
    /// trace id on ctx (both arms), server's span id as the remote parent —
    /// while the server itself is untouched.
    #[test]
    #[ignore = "Slice H1 acceptance — implement assign_local_parents, then remove this ignore"]
    fn nested_client_adopts_server_trace_and_parent() {
        let mut batch = vec![
            server(100, 500, 7, 0xaa, 0xa1),
            client(200, 300, 7, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut batch);

        let (srv, cli) = (&batch[0], &batch[1]);
        assert_eq!(cli.ctx.trace_id, srv.ctx.trace_id, "both arms share the id");
        let p = cli
            .record
            .propagated
            .as_ref()
            .expect("adoption synthesizes a propagated context");
        assert_eq!(p.parent_span_id.to_vec(), srv.ctx.span_id);
        assert_eq!(p.trace_id.to_vec(), srv.ctx.trace_id);
        assert!(
            srv.record.propagated.is_none() && srv.ctx.trace_id == vec![0xaa; 16],
            "the server is never modified"
        );
    }

    /// No guessed parents: tid mismatch, pid mismatch, or a window that is
    /// not fully contained all leave the client untouched. The leading
    /// nested-valid pair keeps this from passing vacuously against a matcher
    /// that never assigns.
    #[test]
    #[ignore = "Slice H1 acceptance — implement assign_local_parents, then remove this ignore"]
    fn no_parent_without_same_thread_and_full_nesting() {
        let mut sane = vec![
            server(100, 500, 7, 0xaa, 0xa1),
            client(200, 300, 7, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut sane);
        assert!(
            sane[1].record.propagated.is_some(),
            "contract sanity: the valid pair must adopt before rejection rows mean anything"
        );

        // tid mismatch.
        let mut batch = vec![
            server(100, 500, 7, 0xaa, 0xa1),
            client(200, 300, 8, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut batch);
        assert!(batch[1].record.propagated.is_none(), "different thread");

        // pid mismatch (different process entirely).
        let mut other_pid = server(100, 500, 7, 0xaa, 0xa1);
        other_pid.ctx.pid = 1;
        let mut batch = vec![other_pid, client(200, 300, 7, 0xbb, 0xb1)];
        assign_local_parents(&mut batch);
        assert!(batch[1].record.propagated.is_none(), "different process");

        // Straddles the server's end — not contained.
        let mut batch = vec![
            server(100, 500, 7, 0xaa, 0xa1),
            client(400, 600, 7, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut batch);
        assert!(batch[1].record.propagated.is_none(), "not nested");
    }

    /// Several containing windows on one thread: the innermost (tightest)
    /// server is the parent.
    #[test]
    #[ignore = "Slice H1 acceptance — implement assign_local_parents, then remove this ignore"]
    fn innermost_containing_server_wins() {
        let mut batch = vec![
            server(0, 1_000, 7, 0xaa, 0xa1),
            server(100, 500, 7, 0xcc, 0xc1),
            client(200, 300, 7, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut batch);
        let p = batch[2].record.propagated.as_ref().expect("adopted");
        assert_eq!(
            p.parent_span_id.to_vec(),
            vec![0xc1; 8],
            "the tighter window is the causal parent"
        );
    }

    /// A server that itself joined a wire-propagated trace passes that trace
    /// on: the nested client inherits the SAME trace id, flags, and
    /// trace_state — an SDK caller's trace continues through the zero-code
    /// server INTO its downstream calls.
    #[test]
    #[ignore = "Slice H1 acceptance — implement assign_local_parents, then remove this ignore"]
    fn propagated_server_extends_its_wire_trace_to_nested_clients() {
        let mut srv = server(100, 500, 7, 0x4b, 0xa1);
        srv.record.propagated = Some(PropagatedContext {
            trace_id: [0x4b; 16],
            parent_span_id: [0xf0; 8],
            trace_flags: 0x01,
            trace_state: "vendor=opaque".to_string(),
        });
        // Slice 2's runner adoption already set ctx.trace_id to the wire id.
        let mut batch = vec![srv, client(200, 300, 7, 0xbb, 0xb1)];
        assign_local_parents(&mut batch);

        let p = batch[1].record.propagated.as_ref().expect("adopted");
        assert_eq!(p.trace_id, [0x4b; 16], "the wire trace continues");
        assert_eq!(p.trace_flags, 0x01, "flags inherited from the server");
        assert_eq!(p.trace_state, "vendor=opaque", "trace_state inherited");
        assert_eq!(p.parent_span_id.to_vec(), vec![0xa1; 8]);
        assert_eq!(batch[1].ctx.trace_id, vec![0x4b; 16]);
    }

    /// A client that already carries wire-extracted context keeps it — local
    /// causality must never clobber real propagation. The valid pair first,
    /// so a matcher that never assigns fails here instead of passing.
    #[test]
    #[ignore = "Slice H1 acceptance — implement assign_local_parents, then remove this ignore"]
    fn wire_extracted_context_is_never_overwritten() {
        let mut sane = vec![
            server(100, 500, 7, 0xaa, 0xa1),
            client(200, 300, 7, 0xbb, 0xb1),
        ];
        assign_local_parents(&mut sane);
        assert!(sane[1].record.propagated.is_some(), "contract sanity");

        let wire = PropagatedContext {
            trace_id: [0x11; 16],
            parent_span_id: [0x22; 8],
            trace_flags: 0x00,
            trace_state: String::new(),
        };
        let mut cli = client(200, 300, 7, 0xbb, 0xb1);
        cli.record.propagated = Some(wire.clone());
        let mut batch = vec![server(100, 500, 7, 0xaa, 0xa1), cli];
        assign_local_parents(&mut batch);
        assert_eq!(
            batch[1].record.propagated.as_ref(),
            Some(&wire),
            "wire context wins over local causality"
        );
    }
}
