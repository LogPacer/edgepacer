//! W3C Trace Context extraction — parse an inbound `traceparent` header so an
//! eBPF-captured server span can join the distributed trace an instrumented
//! client started. Read-only: extraction never rewrites application bytes.
//!
//! The `#[ignore]`d acceptance tests below are the standing definition of the
//! validation contract (W3C Trace Context, version-00 form). They are owned by
//! the reviewer — implement until they pass with the `#[ignore]` attributes
//! removed; any change to their expectations needs reviewer sign-off.

/// Trace context propagated from an instrumented caller: the ids to adopt in
/// place of minted ones, the sampling flags, and the raw `tracestate` value
/// passed through untouched (never parsed, never trusted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagatedContext {
    pub trace_id: [u8; 16],
    pub parent_span_id: [u8; 8],
    pub trace_flags: u8,
    pub trace_state: String,
}

/// Parse a `traceparent` header value (version-00 form:
/// `00-{32 lowercase hex}-{16 lowercase hex}-{2 hex flags}`). Malformed input
/// of any kind returns `None` — a bad header must never poison the span, it
/// just falls back to minted ids. `trace_state` is left empty; the caller
/// attaches the raw `tracestate` header separately when present.
#[allow(dead_code)] // wired into the http parsers later in this slice
pub fn parse_traceparent(value: &str) -> Option<PropagatedContext> {
    // Slice 2 stub: the acceptance tests below define the contract and stay
    // #[ignore]d red until this is implemented.
    let _ = value;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SAMPLED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    /// The happy path: ids land as bytes, the sampled bit is preserved, and
    /// `trace_state` stays empty (the caller attaches `tracestate` itself).
    #[test]
    #[ignore = "Slice 2 acceptance — implement parse_traceparent, then remove this ignore"]
    fn valid_header_yields_ids_and_flags() {
        let ctx = parse_traceparent(VALID_SAMPLED).expect("valid header must parse");
        assert_eq!(
            ctx.trace_id,
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(
            ctx.parent_span_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
        assert_eq!(ctx.trace_flags, 0x01, "sampled bit preserved");
        assert!(ctx.trace_state.is_empty());

        let unsampled =
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
                .expect("unsampled header must parse");
        assert_eq!(unsampled.trace_flags, 0x00);
    }

    /// Every malformed shape falls back to `None` — never a partial parse,
    /// never a panic. Each row is a distinct W3C invalidity class. The leading
    /// sanity assertion keeps this test self-controlling: a parser that
    /// rejects everything (like the stub) fails here instead of passing
    /// vacuously.
    #[test]
    #[ignore = "Slice 2 acceptance — implement parse_traceparent, then remove this ignore"]
    fn malformed_headers_never_poison_the_span() {
        assert!(
            parse_traceparent(VALID_SAMPLED).is_some(),
            "contract sanity: the valid vector must parse before rejection rows mean anything"
        );
        for (case, header) in [
            (
                "version ff is forbidden",
                "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
            (
                "all-zero trace id",
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            ),
            (
                "all-zero parent id",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            ),
            (
                "short trace id",
                "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            ),
            (
                "trailing garbage on version 00",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            ),
            (
                "uppercase hex is invalid per spec",
                "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            ),
            (
                "non-hex version",
                "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
            ("empty", ""),
            ("garbage", "not-a-traceparent"),
        ] {
            assert!(
                parse_traceparent(header).is_none(),
                "{case}: {header:?} must not parse"
            );
        }
    }
}
