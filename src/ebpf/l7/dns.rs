//! DNS wire parser: extracts the span fields (`operation`, `status_code`,
//! `error`, timing) from DNS query/response datagrams captured off
//! `recvfrom`/`sendto` (UDP) syscalls. Mirrors [`super::http1`]'s shape — buffer
//! each direction, parse complete messages, pair request to response, emit one
//! [`L7Record`] — but DNS framing is different in one decisive way: over UDP each
//! message is exactly one datagram, so a captured segment IS a whole message. We
//! therefore do NOT stream-reassemble UDP: a short/garbled datagram is dropped,
//! not buffered for a "rest" that will never come on its own framing boundary.
//!
//! Pairing is by the DNS transaction id (the header's first u16), not FIFO order:
//! a resolver multiplexes many in-flight queries on one socket and answers can
//! arrive out of order. `operation = "<QTYPE> <qname>"` (e.g. `"A example.com"`)
//! from the first question; `status_code` = RCODE; `error` = RCODE != 0.
//!
//! Hand-rolled — no dependency. The header is a fixed 12 bytes and QNAME parsing
//! (length-prefixed labels, 0x00-terminated, with bounded compression-pointer
//! following) is a small routine; a full DNS crate would be dead weight against
//! the agent's leanness moat. The parser NEVER panics or loops on malformed or
//! maliciously-compressed names: every read is bounds-checked and pointer jumps
//! are capped.
//!
//! TCP DNS (a 2-byte length prefix ahead of each message, enabling true stream
//! framing) is the common-case follow-up; this slice handles UDP, the dominant
//! transport.

use std::collections::HashMap;

use super::{L7Parser, L7Record, Protocol};

/// DNS header is a fixed 12 bytes: id, flags, then four u16 section counts.
const HEADER_LEN: usize = 12;

/// QR bit (flags bit 15): 0 = query, 1 = response.
const QR_RESPONSE: u16 = 0x8000;

/// RCODE occupies the low 4 bits of the flags word.
const RCODE_MASK: u16 = 0x000F;

/// Max QNAME bytes we'll assemble — DNS caps a name at 255 octets, so a
/// well-formed name never exceeds this. A hard stop against a crafted name that
/// chains compression pointers to inflate output.
const MAX_NAME_LEN: usize = 255;

/// Max compression-pointer jumps while resolving one name. Each jump must move
/// strictly backward, but capping the count is the simplest loop-proof bound.
const MAX_POINTER_JUMPS: usize = 16;

/// Outcome of parsing one DNS datagram into the fields a span needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    /// A query: its transaction id and `"<QTYPE> <qname>"` operation label.
    Query { id: u16, operation: String },
    /// A response: its transaction id and RCODE.
    Response { id: u16, rcode: u16 },
    /// Not a parseable DNS message (too short, malformed counts, bad name).
    Invalid,
}

/// Map a QTYPE number to its mnemonic for the operation label, covering the
/// record types that dominate real traffic. Unknown types render as `TYPE<n>`
/// (the RFC 3597 generic form), so the label is always meaningful.
fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        43 => "DS".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

/// Read a big-endian u16 at `off`, or `None` if it runs past the buffer.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Parse the QNAME starting at `start`, following compression pointers within the
/// whole datagram. Returns the dotted name and the offset of the byte just past
/// the name *in the question section* (i.e. after the terminating 0x00 or the
/// first pointer — pointers don't advance the question cursor beyond their two
/// bytes). `None` on any malformed or out-of-bounds name. Never loops: jumps are
/// capped and the assembled length is bounded.
fn parse_qname(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    // Where the question cursor lands: set the first time we follow a pointer,
    // because after a pointer the question's own bytes end at the pointer.
    let mut end_after: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xC0 {
            // 0b00: a normal label of `len` bytes (0 terminates the name).
            0x00 => {
                if len == 0 {
                    let consumed = end_after.unwrap_or(pos + 1);
                    return Some((name, consumed));
                }
                let label_start = pos + 1;
                let label_end = label_start + len;
                let label = msg.get(label_start..label_end)?;
                if name.len() + label.len() + 1 > MAX_NAME_LEN {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                // DNS labels are bytes; render the printable ASCII faithfully and
                // keep parsing regardless (we only need a stable label, not a
                // validated hostname).
                name.push_str(&String::from_utf8_lossy(label));
                pos = label_end;
            }
            // 0b11: a compression pointer — a 14-bit offset into the message.
            0xC0 => {
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                let b2 = *msg.get(pos + 1)? as usize;
                let target = ((len & 0x3F) << 8) | b2;
                // The question cursor ends just past these two pointer bytes.
                end_after.get_or_insert(pos + 2);
                // A pointer must point strictly backward; forward/self pointers
                // are the loop trap we refuse.
                if target >= pos {
                    return None;
                }
                pos = target;
            }
            // 0b01 / 0b10 are reserved label types — reject rather than guess.
            _ => return None,
        }
    }
}

/// Parse one captured DNS datagram into the span fields. Pure + bounds-checked.
fn parse_message(msg: &[u8]) -> Parsed {
    if msg.len() < HEADER_LEN {
        return Parsed::Invalid;
    }
    let Some(id) = read_u16(msg, 0) else {
        return Parsed::Invalid;
    };
    let Some(flags) = read_u16(msg, 2) else {
        return Parsed::Invalid;
    };
    let Some(qdcount) = read_u16(msg, 4) else {
        return Parsed::Invalid;
    };

    let is_response = flags & QR_RESPONSE != 0;

    if is_response {
        return Parsed::Response {
            id,
            rcode: flags & RCODE_MASK,
        };
    }

    // A query with no question carries no operation label — nothing to span.
    if qdcount == 0 {
        return Parsed::Invalid;
    }

    // First question: QNAME, then QTYPE (u16), QCLASS (u16).
    let Some((qname, after_name)) = parse_qname(msg, HEADER_LEN) else {
        return Parsed::Invalid;
    };
    let Some(qtype) = read_u16(msg, after_name) else {
        return Parsed::Invalid;
    };

    // The root domain (".") parses as an empty name; render it explicitly so the
    // label is never a bare type.
    let label = if qname.is_empty() { "." } else { &qname };
    Parsed::Query {
        id,
        operation: format!("{} {}", qtype_name(qtype), label),
    }
}

/// A query awaiting its response: the operation label and observation time.
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// DNS [`L7Parser`]: each inbound segment is a query datagram, each outbound a
/// response datagram. Queries are held by transaction id until the matching
/// response arrives (resolvers multiplex and reorder, so id — not FIFO — pairs
/// them). Malformed datagrams are dropped, never fatal: UDP sockets carry many
/// independent datagrams, so one bad packet must not kill the connection.
#[derive(Debug, Default)]
pub(crate) struct DnsParser {
    pending: HashMap<u16, Pending>,
    records: Vec<L7Record>,
}

impl DnsParser {
    pub fn new() -> Self {
        Self::default()
    }
}

impl L7Parser for DnsParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if let Parsed::Query { id, operation } = parse_message(bytes) {
            // A repeated id (retransmit, or wrap) overwrites the older query —
            // the latest send is the one the response will be measured against.
            self.pending.insert(
                id,
                Pending {
                    operation,
                    start_unix_nano: ts,
                },
            );
        }
        // Anything else (response on the inbound side, or garbage) is ignored:
        // we only span query->response observed from the client's socket.
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if let Parsed::Response { id, rcode } = parse_message(bytes) {
            // A response with no matching query is dropped — we attached after
            // the query was sent and missed it.
            if let Some(req) = self.pending.remove(&id) {
                self.records.push(L7Record {
                    protocol: Protocol::Dns,
                    attributes: Vec::new(),
                    operation: req.operation,
                    status_code: rcode,
                    error: rcode != 0,
                    start_unix_nano: req.start_unix_nano,
                    // Clamp to zero: `saturating_sub` on i64 saturates at i64::MIN,
                    // not at zero, so a response observed *before* its query
                    // (clock skew, segment reordering) would otherwise emit a
                    // negative duration and poison the latency histograms.
                    duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
                });
            }
        }
    }

    fn take_records(&mut self) -> Vec<L7Record> {
        std::mem::take(&mut self.records)
    }

    fn is_dead(&self) -> bool {
        // UDP DNS has no stream to corrupt: a bad datagram is dropped, not fatal.
        // The parser stays alive for the socket's life.
        false
    }
}

/// True if the inbound prefix is a plausible DNS *query* datagram. A positive
/// signature: full 12-byte header, QR bit clear (query), a standard/notify/update
/// opcode, and at least one question whose first QNAME parses cleanly with a
/// readable QTYPE. Recognising on a parsed first question (not just the header)
/// keeps the false-positive rate near zero against arbitrary binary streams.
pub(crate) fn detect_dns(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if inbound.len() < HEADER_LEN {
        return None;
    }
    let flags = read_u16(inbound, 2)?;
    // Must be a query.
    if flags & QR_RESPONSE != 0 {
        return None;
    }
    // Opcode = bits 11..14. Standard query (0), Notify (4), Update (5) are the
    // real-world values; reject the rest so random bytes with the QR bit happening
    // to be clear don't masquerade as DNS.
    let opcode = (flags >> 11) & 0x0F;
    if !matches!(opcode, 0 | 4 | 5) {
        return None;
    }
    // Positive confirmation: the first question parses to a query operation.
    match parse_message(inbound) {
        Parsed::Query { .. } => Some(Box::new(DnsParser::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS message: header + one question (labels + qtype/qclass).
    /// `flags` carries QR/opcode/RCODE; `name_labels` are the dotted labels.
    fn message(id: u16, flags: u16, name_labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&0u16.to_be_bytes()); // ancount
        m.extend_from_slice(&0u16.to_be_bytes()); // nscount
        m.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in name_labels {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0); // root terminator
        m.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        m
    }

    fn query(id: u16, name: &[&str], qtype: u16) -> Vec<u8> {
        message(id, 0x0100, name, qtype) // RD set, QR=0 (query)
    }

    /// A response datagram is just the header with QR set and an RCODE; the
    /// parser reads RCODE from flags and never touches the answer section.
    fn response(id: u16, rcode: u16) -> Vec<u8> {
        let flags = QR_RESPONSE | 0x0100 | (rcode & RCODE_MASK);
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount echoed
        m.extend_from_slice(&1u16.to_be_bytes()); // ancount
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m
    }

    #[test]
    fn detects_dns_query_by_positive_signature() {
        let q = query(0x1234, &["example", "com"], 1);
        assert!(detect_dns(&q).is_some());
        // A response is not a query — detection is query-only.
        assert!(detect_dns(&response(0x1234, 0)).is_none());
        // Too short to hold a header.
        assert!(detect_dns(b"\x12\x34").is_none());
        // QR bit happens to be clear but the rest is noise (bad opcode / no
        // parseable question).
        assert!(detect_dns(b"\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00").is_none());
        // An HTTP request must not be mistaken for DNS.
        assert!(detect_dns(b"GET /x HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn query_response_yields_one_record_with_operation_and_status() {
        let mut p = DnsParser::new();
        p.on_inbound(&query(0xABCD, &["example", "com"], 1), 1_000);
        assert!(p.take_records().is_empty()); // query seen, no response yet
        p.on_outbound(&response(0xABCD, 0), 1_750);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "A example.com");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 750);
    }

    #[test]
    fn aaaa_qtype_renders_in_operation_label() {
        let mut p = DnsParser::new();
        p.on_inbound(&query(0x0001, &["ipv6", "test"], 28), 0);
        p.on_outbound(&response(0x0001, 0), 10);
        let recs = p.take_records();
        assert_eq!(recs[0].operation, "AAAA ipv6.test");
    }

    #[test]
    fn nxdomain_response_is_an_error_with_rcode_status() {
        let mut p = DnsParser::new();
        p.on_inbound(&query(0x0042, &["no", "such", "host"], 1), 0);
        p.on_outbound(&response(0x0042, 3), 5); // RCODE 3 = NXDOMAIN
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "A no.such.host");
        assert_eq!(recs[0].status_code, 3);
        assert!(recs[0].error);
    }

    #[test]
    fn multiple_queries_pair_by_transaction_id_not_arrival_order() {
        let mut p = DnsParser::new();
        p.on_inbound(&query(0x1111, &["a", "com"], 1), 100);
        p.on_inbound(&query(0x2222, &["b", "com"], 28), 200);
        // Responses arrive in the OPPOSITE order — pairing is by id.
        p.on_outbound(&response(0x2222, 0), 250); // pairs the b.com AAAA query
        p.on_outbound(&response(0x1111, 2), 400); // pairs the a.com A query, SERVFAIL
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "AAAA b.com");
        assert_eq!(recs[0].status_code, 0);
        assert_eq!(recs[0].duration_nano, 50);
        assert_eq!(recs[1].operation, "A a.com");
        assert_eq!(recs[1].status_code, 2); // SERVFAIL
        assert!(recs[1].error);
        assert_eq!(recs[1].duration_nano, 300); // 400 - 100, by id not arrival
    }

    #[test]
    fn truncated_datagram_is_dropped_not_buffered() {
        let mut p = DnsParser::new();
        // Half a query datagram. UDP framing means this is a malformed datagram,
        // not a fragment to reassemble: it must NOT register a pending query.
        let full = query(0x5555, &["partial", "example"], 1);
        p.on_inbound(&full[..HEADER_LEN + 3], 0);
        assert!(p.take_records().is_empty());
        // The real response now arrives but there is no pending query to pair —
        // confirming the truncated datagram was dropped, not half-buffered.
        p.on_outbound(&response(0x5555, 0), 100);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // a bad datagram never kills a UDP "connection"
    }

    #[test]
    fn compression_pointer_in_qname_is_followed_safely() {
        // Compression points strictly backward, so the target name must sit
        // earlier in the message than the name that references it. Exercise
        // `parse_qname` directly on a buffer holding an earlier "isp.net" suffix
        // and a later name "www" + pointer-back to it.
        let mut buf = vec![0u8; 0];
        // Offset 0: the suffix the pointer will target — "isp.net".
        let suffix_off = buf.len();
        buf.push(3);
        buf.extend_from_slice(b"isp");
        buf.push(3);
        buf.extend_from_slice(b"net");
        buf.push(0);
        // The name we parse: "www" then a backward pointer to `suffix_off`.
        let name_off = buf.len();
        buf.push(3);
        buf.extend_from_slice(b"www");
        buf.push(0xC0 | ((suffix_off >> 8) as u8 & 0x3F));
        buf.push((suffix_off & 0xFF) as u8);

        let (name, consumed) = parse_qname(&buf, name_off).expect("name parses");
        assert_eq!(name, "www.isp.net");
        // The question cursor lands just past the 2 pointer bytes (len+"www" = 4
        // bytes, then the 2 pointer bytes), not at the far end of the suffix.
        assert_eq!(consumed, name_off + 6);
    }

    #[test]
    fn forward_pointer_is_rejected_without_looping() {
        // A name that is a single pointer to offset 12 (itself) — a self/forward
        // reference. Must be rejected, never loop.
        let mut m = Vec::new();
        m.extend_from_slice(&0x0001u16.to_be_bytes());
        m.extend_from_slice(&0x0100u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // QNAME at offset 12 is a pointer back to offset 12 (not strictly backward).
        m.push(0xC0);
        m.push(12);
        assert_eq!(parse_message(&m), Parsed::Invalid);
    }

    #[test]
    fn orphan_response_is_dropped() {
        let mut p = DnsParser::new();
        p.on_outbound(&response(0x9999, 0), 0); // no pending query
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn unknown_qtype_renders_generic_type_label() {
        let mut p = DnsParser::new();
        p.on_inbound(&query(0x000A, &["weird"], 999), 0);
        p.on_outbound(&response(0x000A, 0), 1);
        assert_eq!(p.take_records()[0].operation, "TYPE999 weird");
    }

    #[test]
    fn response_before_query_never_yields_negative_duration() {
        // Clock skew or segment reordering can hand us a response observed at a
        // timestamp *earlier* than its query. `i64::saturating_sub` does NOT
        // clamp to zero (it saturates at i64::MIN), so the duration must be
        // floored explicitly — a negative latency is an invalid span that would
        // poison the RED histograms downstream.
        let mut p = DnsParser::new();
        p.on_inbound(&query(0xAAAA, &["z"], 1), 1_000);
        p.on_outbound(&response(0xAAAA, 0), 900); // 100ns *before* the query
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duration_nano, 0);
        assert!(recs[0].duration_nano >= 0);
    }

    #[test]
    fn root_domain_query_renders_dot_through_full_pipeline() {
        // A root-hint query ("." / NS) — qdcount=1 with a name that is a single
        // 0x00 terminator. The empty name must render as "." in the operation,
        // not as a bare type, end to end (query -> pair -> record).
        let mut m = Vec::new();
        m.extend_from_slice(&0x0099u16.to_be_bytes());
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD, query
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
        m.push(0); // root name
        m.extend_from_slice(&2u16.to_be_bytes()); // QTYPE NS
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        let mut p = DnsParser::new();
        p.on_inbound(&m, 0);
        p.on_outbound(&response(0x0099, 0), 1);
        assert_eq!(p.take_records()[0].operation, "NS .");
    }

    #[test]
    fn qtype_truncated_after_qname_is_invalid() {
        // The QNAME is complete but the QTYPE that must follow it is cut short
        // (only its high byte present). A complete name does not imply a complete
        // question: the QTYPE read must fail closed, not read past the name into
        // whatever bytes happen to follow.
        let mut m = Vec::new();
        m.extend_from_slice(&0x0001u16.to_be_bytes());
        m.extend_from_slice(&0x0100u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        m.push(2);
        m.extend_from_slice(b"ab");
        m.push(0); // name complete
        m.push(0x00); // only the high half of QTYPE; low half missing
        assert_eq!(parse_message(&m), Parsed::Invalid);

        // And the same datagram registers no pending query on the parser.
        let mut p = DnsParser::new();
        p.on_inbound(&m, 0);
        p.on_outbound(&response(0x0001, 0), 1);
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn backward_pointer_chain_exceeding_jump_cap_is_rejected() {
        // A chain of compression pointers, each strictly backward (so the
        // single-step "strictly backward" guard passes every hop), but longer
        // than MAX_POINTER_JUMPS. Only the jump *count* cap stops it — proving
        // we never loop on a long legal-looking backward chain, distinct from the
        // self/forward-pointer trap.
        let mut buf = vec![0u8]; // offset 0: a 0x00 the chain could terminate at
        let mut prev_target = 0usize;
        for _ in 0..(MAX_POINTER_JUMPS + 4) {
            let off = buf.len();
            buf.push(0xC0 | ((prev_target >> 8) as u8 & 0x3F));
            buf.push((prev_target & 0xFF) as u8);
            prev_target = off;
        }
        let last_ptr = buf.len() - 2;
        assert_eq!(parse_qname(&buf, last_ptr), None);
    }

    #[test]
    fn never_panics_on_hostile_or_truncated_bytes() {
        // Hard requirement: no input — however malformed, truncated, or
        // adversarially compressed — may panic. Exhaust every short buffer over a
        // structurally-loaded alphabet, then sweep a large deterministic random
        // corpus through every entry point including the stateful parser.
        let alphabet = [
            0x00u8, 0x01, 0x02, 0x03, 0x0C, 0x3F, 0x40, 0x80, 0xC0, 0xC1, 0xFF,
        ];
        fn walk(buf: &mut Vec<u8>, alpha: &[u8], depth: usize) {
            if depth == 0 {
                let _ = parse_message(buf);
                let _ = parse_qname(buf, 0);
                if buf.len() >= HEADER_LEN {
                    let _ = parse_qname(buf, HEADER_LEN);
                }
                let _ = detect_dns(buf);
                return;
            }
            for &b in alpha {
                buf.push(b);
                walk(buf, alpha, depth - 1);
                buf.pop();
            }
        }
        let mut buf = Vec::new();
        walk(&mut buf, &alphabet, 5);

        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..200_000 {
            let len = (next() % 400) as usize;
            let mut m = Vec::with_capacity(len);
            for _ in 0..len {
                m.push((next() & 0xFF) as u8);
            }
            let _ = parse_message(&m);
            let _ = parse_qname(&m, (next() as usize) % (len + 1));
            let _ = detect_dns(&m);
            let mut p = DnsParser::new();
            p.on_inbound(&m, next() as i64);
            p.on_outbound(&m, next() as i64);
            let _ = p.take_records();
        }
    }
}
