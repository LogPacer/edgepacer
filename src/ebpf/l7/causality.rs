//! Intra-process span hierarchy — tid-window causality. A CLIENT record whose
//! window nests inside a SERVER record's window on the same (pid, tid) was
//! caused by that request (thread-per-request runtimes; async runtimes
//! degrade to today's flat behavior — never a guessed parent). Parenting is
//! expressed by synthesizing the same [`PropagatedContext`] wire extraction
//! produces, so local causality and W3C propagation flow through one
//! adoption path: `ctx_trace_id`, `to_otlp_span`, both arms, identical ids.
//!
//! The acceptance tests below are the standing definition of the matching
//! contract. They are owned by the reviewer; any change to their
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
    /// The connection's two endpoints as the capturing process saw them —
    /// the same-host cross-process key: monitored A's outbound connection is
    /// monitored B's inbound with local/remote exactly reversed. `None` when
    /// socket resolution couldn't name both ends (TLS pseudo-fds,
    /// cross-uid /proc gating) — such spans never cross-link.
    pub conn: Option<ConnEndpoints>,
}

/// A connection's `"ip:port"` endpoints from the capturing process's view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnEndpoints {
    pub local: String,
    pub remote: String,
}

/// Assign local parents within one flush batch: every CLIENT span whose
/// window nests inside a SERVER span's window on the same (pid, tid) adopts
/// that server's trace — the innermost containing window when several nest.
/// Adoption synthesizes `record.propagated` (parent = the server's span id,
/// trace id / flags / trace_state inherited from the server) and rewrites
/// `ctx.trace_id` so BOTH arms carry the shared id. A client that already
/// carries a wire-extracted context is never overwritten, UNSPECIFIED spans
/// never participate, and servers are never modified.
pub fn assign_local_parents(entries: &mut [LocalSpan]) {
    for i in 0..entries.len() {
        // Only bare CLIENT spans adopt: servers are never modified, a
        // wire-extracted context is never overwritten, and UNSPECIFIED spans
        // never participate.
        if entries[i].kind != Some(SpanKind::Client) || entries[i].record.propagated.is_some() {
            continue;
        }
        let pid = entries[i].ctx.pid;
        let tid = entries[i].tid;
        let (c_start, c_end) = window(&entries[i].record);

        // The innermost containing server window on the same (pid, tid): the
        // tightest window is the direct cause when several nest.
        let mut best: Option<usize> = None;
        for j in 0..entries.len() {
            if j == i || entries[j].kind != Some(SpanKind::Server) {
                continue;
            }
            if entries[j].ctx.pid != pid || entries[j].tid != tid {
                continue;
            }
            let (s_start, s_end) = window(&entries[j].record);
            // Full containment, inclusive at both ends — a window that
            // straddles either bound is not causality, it's overlap.
            if c_start < s_start || c_end > s_end {
                continue;
            }
            match best {
                None => best = Some(j),
                Some(b) => {
                    let (b_start, b_end) = window(&entries[b].record);
                    if s_end - s_start < b_end - b_start {
                        best = Some(j);
                    }
                }
            }
        }
        let Some(j) = best else {
            continue;
        };

        // Read the server's facts, then rewrite the client — adoption
        // synthesizes the same PropagatedContext wire extraction produces,
        // so one path carries local causality and W3C propagation alike.
        let inherited = entries[j].record.propagated.as_ref();
        let Ok(trace_id) = <[u8; 16]>::try_from(entries[j].ctx.trace_id.as_slice()) else {
            continue; // malformed ids never parent
        };
        let Ok(parent_span_id) = <[u8; 8]>::try_from(entries[j].ctx.span_id.as_slice()) else {
            continue;
        };
        let trace_flags = inherited.map(|p| p.trace_flags).unwrap_or(0x01);
        let trace_state = inherited.map(|p| p.trace_state.clone()).unwrap_or_default();

        entries[i].ctx.trace_id = trace_id.to_vec();
        entries[i].record.propagated = Some(PropagatedContext {
            trace_id,
            parent_span_id,
            trace_flags,
            trace_state,
        });
    }
}

/// A record's observation window, inclusive at both ends.
fn window(record: &L7Record) -> (i64, i64) {
    (
        record.start_unix_nano,
        record.start_unix_nano + record.duration_nano,
    )
}

/// The whole-batch hierarchy pass the runner calls once per flush tick, over
/// every service's entries together: intra-process parenting
/// ([`assign_local_parents`]), same-host cross-process linking (a SERVER span
/// whose connection endpoints exactly reverse a CLIENT span's, with the
/// server's window nested in the client's, adopts that client as its remote
/// parent — deterministic or nothing: NAT'd or unresolved endpoints never
/// match), and a transitive trace refresh so a whole causal chain
/// (SERVER → its CLIENT → the callee's SERVER → its CLIENT …) reports ONE
/// trace id end to end. Sequential requests multiplexed on one connection
/// disambiguate by window containment. All [`assign_local_parents`]
/// invariants hold throughout: wire-extracted context on the ADOPTING side
/// is never overwritten and nothing is ever guessed.
#[allow(dead_code)] // wired into the runner's flush path later in this slice
pub fn assign_batch_hierarchy(entries: &mut [LocalSpan]) {
    // Slice H2 stub: intra-process parenting already works; the cross-process
    // link + transitive refresh are the work, pinned by the #[ignore]d
    // acceptance tests below.
    assign_local_parents(entries);
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
            conn: None,
        }
    }

    fn client(start: i64, end: i64, tid: u32, trace_seed: u8, span_seed: u8) -> LocalSpan {
        LocalSpan {
            record: record(start, end),
            ctx: ctx(trace_seed, span_seed),
            kind: Some(SpanKind::Client),
            tid,
            conn: None,
        }
    }

    /// The core adoption: a nested client joins its server's trace — shared
    /// trace id on ctx (both arms), server's span id as the remote parent —
    /// while the server itself is untouched.
    #[test]
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

    // ── Slice H2: same-host cross-process linking ───────────────────────────

    fn conn(local: &str, remote: &str) -> Option<ConnEndpoints> {
        Some(ConnEndpoints {
            local: local.to_string(),
            remote: remote.to_string(),
        })
    }

    /// Monitored A calls monitored B on the same host: one agent sees both
    /// sides, the endpoints reverse exactly, and B's SERVER span (window
    /// nested in A's CLIENT window) adopts A as its remote parent — both of
    /// B's arms carrying A's trace id.
    #[test]
    #[ignore = "Slice H2 acceptance — implement cross-process linking in assign_batch_hierarchy, then remove this ignore"]
    fn same_host_pair_links_across_processes() {
        let mut a_cli = client(100, 500, 7, 0xaa, 0xa1);
        a_cli.conn = conn("127.0.0.1:51000", "127.0.0.1:8080");
        let mut b_srv = server(150, 400, 9, 0xbb, 0xb1);
        b_srv.ctx.pid = 5151;
        b_srv.conn = conn("127.0.0.1:8080", "127.0.0.1:51000");

        let mut batch = vec![a_cli, b_srv];
        assign_batch_hierarchy(&mut batch);

        let p = batch[1]
            .record
            .propagated
            .as_ref()
            .expect("the reversed pair links");
        assert_eq!(p.parent_span_id.to_vec(), vec![0xa1; 8]);
        assert_eq!(p.trace_id.to_vec(), batch[0].ctx.trace_id);
        assert_eq!(batch[1].ctx.trace_id, batch[0].ctx.trace_id);
        assert!(
            batch[0].record.propagated.is_none(),
            "the client side is never modified by the link"
        );
    }

    /// Deterministic or nothing: mismatched ports, same-direction endpoints,
    /// missing resolution, or a server window not nested in the client's all
    /// refuse to link. The leading valid pair keeps this self-controlling.
    #[test]
    #[ignore = "Slice H2 acceptance — implement cross-process linking in assign_batch_hierarchy, then remove this ignore"]
    fn no_link_without_exact_endpoint_reversal_and_nesting() {
        let valid = |a_conn: Option<ConnEndpoints>,
                     b_conn: Option<ConnEndpoints>,
                     b_start: i64,
                     b_end: i64| {
            let mut a = client(100, 500, 7, 0xaa, 0xa1);
            a.conn = a_conn;
            let mut b = server(b_start, b_end, 9, 0xbb, 0xb1);
            b.ctx.pid = 5151;
            b.conn = b_conn;
            let mut batch = vec![a, b];
            assign_batch_hierarchy(&mut batch);
            batch[1].record.propagated.is_some()
        };

        assert!(
            valid(
                conn("127.0.0.1:51000", "127.0.0.1:8080"),
                conn("127.0.0.1:8080", "127.0.0.1:51000"),
                150,
                400
            ),
            "contract sanity: the reversed nested pair must link"
        );
        assert!(
            !valid(
                conn("127.0.0.1:51000", "127.0.0.1:8080"),
                conn("127.0.0.1:9090", "127.0.0.1:51000"),
                150,
                400
            ),
            "mismatched port must not link"
        );
        assert!(
            !valid(
                conn("127.0.0.1:51000", "127.0.0.1:8080"),
                conn("127.0.0.1:51000", "127.0.0.1:8080"),
                150,
                400
            ),
            "same-direction endpoints (not reversed) must not link"
        );
        assert!(
            !valid(conn("127.0.0.1:51000", "127.0.0.1:8080"), None, 150, 400),
            "unresolved endpoints must not link"
        );
        assert!(
            !valid(
                conn("127.0.0.1:51000", "127.0.0.1:8080"),
                conn("127.0.0.1:8080", "127.0.0.1:51000"),
                400,
                600
            ),
            "a server window straddling the client's end must not link"
        );
    }

    /// Keep-alive: several sequential request pairs multiplex one connection
    /// — identical endpoints — and each server span pairs with the client
    /// span whose window contains it.
    #[test]
    #[ignore = "Slice H2 acceptance — implement cross-process linking in assign_batch_hierarchy, then remove this ignore"]
    fn sequential_requests_on_one_connection_pair_by_containment() {
        let ab = conn("127.0.0.1:51000", "127.0.0.1:8080");
        let ba = conn("127.0.0.1:8080", "127.0.0.1:51000");
        let mut a1 = client(100, 200, 7, 0xa0, 0xa1);
        a1.conn = ab.clone();
        let mut a2 = client(300, 400, 7, 0xa0, 0xa2);
        a2.conn = ab;
        let mut b1 = server(120, 180, 9, 0xb0, 0xb1);
        b1.ctx.pid = 5151;
        b1.conn = ba.clone();
        let mut b2 = server(320, 380, 9, 0xb0, 0xb2);
        b2.ctx.pid = 5151;
        b2.conn = ba;

        let mut batch = vec![a1, a2, b1, b2];
        assign_batch_hierarchy(&mut batch);

        let p1 = batch[2].record.propagated.as_ref().expect("first pair");
        let p2 = batch[3].record.propagated.as_ref().expect("second pair");
        assert_eq!(p1.parent_span_id.to_vec(), vec![0xa1; 8]);
        assert_eq!(p2.parent_span_id.to_vec(), vec![0xa2; 8]);
    }

    /// The capstone: an SDK caller's wire trace flows through a zero-code
    /// chain — A's SERVER (wire-propagated) → A's CLIENT (intra-process) →
    /// B's SERVER (cross-process) → B's CLIENT (intra-process) — and every
    /// span reports the ONE wire trace id with parents chaining correctly.
    #[test]
    #[ignore = "Slice H2 acceptance — implement cross-process linking in assign_batch_hierarchy, then remove this ignore"]
    fn full_chain_shares_one_wire_trace() {
        let wire_trace = [0x4b; 16];
        let mut a_srv = server(0, 1_000, 7, 0x4b, 0xa1);
        a_srv.record.propagated = Some(PropagatedContext {
            trace_id: wire_trace,
            parent_span_id: [0xf0; 8],
            trace_flags: 0x01,
            trace_state: "vendor=opaque".to_string(),
        });
        let mut a_cli = client(100, 500, 7, 0xaa, 0xa2);
        a_cli.conn = conn("127.0.0.1:51000", "127.0.0.1:8080");
        let mut b_srv = server(150, 400, 9, 0xbb, 0xb1);
        b_srv.ctx.pid = 5151;
        b_srv.conn = conn("127.0.0.1:8080", "127.0.0.1:51000");
        let mut b_cli = client(200, 300, 9, 0xcc, 0xb2);
        b_cli.ctx.pid = 5151;

        let mut batch = vec![a_srv, a_cli, b_srv, b_cli];
        assign_batch_hierarchy(&mut batch);

        for (i, name) in ["a_srv", "a_cli", "b_srv", "b_cli"].iter().enumerate() {
            assert_eq!(
                batch[i].ctx.trace_id,
                wire_trace.to_vec(),
                "{name} must carry the one wire trace id"
            );
        }
        let parent = |i: usize| {
            batch[i]
                .record
                .propagated
                .as_ref()
                .map(|p| p.parent_span_id.to_vec())
        };
        assert_eq!(parent(1), Some(vec![0xa1; 8]), "a_cli under a_srv");
        assert_eq!(parent(2), Some(vec![0xa2; 8]), "b_srv under a_cli");
        assert_eq!(parent(3), Some(vec![0xb1; 8]), "b_cli under b_srv");
    }
}
