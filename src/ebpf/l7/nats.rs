//! NATS wire parser — implements [`super::L7Parser`].
//!
//! NATS is a plain-text, line-oriented protocol: every control message is an
//! ASCII verb, optional space-separated arguments, terminated by `\r\n`. Two
//! verbs (`PUB`/`HPUB` client→server, `MSG`/`HMSG` server→client) carry a
//! byte-counted payload after the control line: the line ends in a `<#bytes>`
//! field, then exactly that many payload bytes follow, then a trailing `\r\n`.
//!
//! Unlike Redis/HTTP, NATS is **not** request-then-response. It is pub/sub: a
//! client streams `CONNECT`/`PUB`/`SUB`/`UNSUB` independently, the server pushes
//! `MSG`/`HMSG` deliveries whenever a matching message arrives, and only a few
//! verbs form pairs. So we do NOT FIFO-pair every inbound verb against an
//! outbound reply (that would misalign instantly the first time a `MSG` push or
//! an out-of-order `+OK` showed up). Instead:
//!   * Each **client verb** (`CONNECT`/`PUB`/`HPUB`/`SUB`/`UNSUB`) emits its own
//!     record the moment it is fully framed — a fire-and-forget operation with no
//!     paired response, so `duration_nano = 0`.
//!   * `PING` (client→server) is queued and paired with the matching `PONG`
//!     (server→client) so the round-trip latency of a health check is captured.
//!   * `-ERR '<reason>'` (server→client) is an error record — the one protocol
//!     failure verdict. Everything else server-side (`INFO`/`MSG`/`HMSG`/`+OK`,
//!     server-initiated `PING`) is framed-and-skipped: out-of-band deliveries and
//!     acks that answer no client request, so they never produce or steal a
//!     record (the Redis-push lesson, applied here).
//!
//! Hand-rolled framing, no dependency: the grammar is "a line, sometimes with a
//! trailing counted payload". The byte-counted payloads are skipped via the
//! shared [`DirBuf`] skip mechanism — we never materialise message bodies, only
//! the span fields (operation, error verdict, timing).

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Protocol tag stamped on every record this parser mints.
const PROTOCOL: Protocol = Protocol::Nats;

/// Client→server control verbs. A connection whose inbound prefix opens with one
/// of these (delimited) is NATS. `PING`/`PONG` are bidirectional and included so
/// a connection opened with a bare keep-alive is still recognised.
const CLIENT_VERBS: [&[u8]; 7] = [
    b"CONNECT", b"PUB", b"HPUB", b"SUB", b"UNSUB", b"PING", b"PONG",
];

/// Outcome of framing one control line (plus any counted payload) at the front of
/// a direction buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    /// A complete message: the parsed verb-info plus how many bytes it occupied
    /// (control line + any counted payload + its trailing CRLF).
    Complete { msg: Msg, total_len: usize },
    /// A complete control line, but its counted payload isn't all buffered yet.
    /// `skip` bytes (payload + trailing CRLF) must be dropped before the next
    /// head; `total_len` covers what's framed here (the control line).
    NeedsSkip {
        msg: Msg,
        line_len: usize,
        skip: usize,
    },
    /// Valid-so-far but the control line isn't terminated yet — wait.
    Partial,
    /// Not well-formed NATS — drop the connection.
    Invalid,
}

/// The span-relevant shape of one framed message: its operation label and, for an
/// outbound message, its pairing/error role.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Msg {
    /// A client verb that stands alone as an operation (`PUB orders.created`).
    ClientOp(String),
    /// A client `PING` — queued to pair with the server's `PONG`.
    Ping,
    /// A server `PONG` — pairs with the oldest pending client `PING`.
    Pong,
    /// A server `-ERR` line — an error record.
    Err,
    /// Anything else framed off the wire that produces no record: server `INFO`,
    /// `MSG`/`HMSG` pushes, `+OK` acks, server-initiated `PING`.
    Ignored,
}

/// Find the index just past the next CRLF in `buf` starting at `from` (the offset
/// of the byte after `\n`). `None` if no complete line is buffered yet. A lone
/// `\r` or `\n` is not a terminator — NATS lines end in `\r\n`.
fn line_end(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

/// Split a control line (the bytes up to but excluding its CRLF) into the
/// uppercased verb token and the remaining argument bytes. `None` if the line has
/// no verb token (all-whitespace or empty).
fn split_verb(line: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let start = line.iter().position(|&b| !is_space(b))?;
    let rest = &line[start..];
    let end = rest.iter().position(|&b| is_space(b)).unwrap_or(rest.len());
    let verb = rest[..end].to_ascii_uppercase();
    let args = rest[end..].trim_ascii_start();
    Some((verb, args))
}

/// NATS argument fields are space/tab separated.
fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Parse a trailing `<#bytes>` count field (the last whitespace-delimited token of
/// a `PUB`/`HPUB`/`MSG`/`HMSG` control line). Returns the byte count, or `None` if
/// it isn't a valid non-negative integer that fits.
fn parse_byte_count(field: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(field).ok()?;
    s.parse::<usize>().ok()
}

/// The first argument token (subject/sid), as a UTF-8 string slice owned out, for
/// building the operation label. Empty if there is no argument.
fn first_token(args: &[u8]) -> String {
    let end = args.iter().position(|&b| is_space(b)).unwrap_or(args.len());
    String::from_utf8_lossy(&args[..end]).into_owned()
}

/// The last whitespace-delimited token of an argument slice — the `<#bytes>` count
/// on a payload-bearing line.
fn last_token(args: &[u8]) -> &[u8] {
    args.rsplit(|&b| is_space(b))
        .find(|t| !t.is_empty())
        .unwrap_or(&[])
}

/// Frame one message at the front of an inbound (client→server) buffer.
fn frame_inbound(buf: &[u8]) -> Frame {
    let Some(end) = line_end(buf, 0) else {
        // No complete line yet. Guard against an unbounded junk line that will
        // never terminate: once a very long run has no CRLF it isn't NATS.
        return if buf.len() > MAX_LINE_LEN {
            Frame::Invalid
        } else {
            Frame::Partial
        };
    };
    let line = &buf[..end - 2];
    let Some((verb, args)) = split_verb(line) else {
        return Frame::Invalid;
    };

    match verb.as_slice() {
        // Payload-bearing: the control line ends in a byte count; that many payload
        // bytes plus a trailing CRLF follow and are skipped.
        b"PUB" | b"HPUB" => frame_payload_line(buf, end, args, &verb),
        b"SUB" => complete(buf, end, Msg::ClientOp(label(b"SUB", first_token(args)))),
        // UNSUB's argument is a sid, not a subject — per spec use the bare verb.
        b"UNSUB" => complete(buf, end, Msg::ClientOp("UNSUB".to_string())),
        b"CONNECT" => complete(buf, end, Msg::ClientOp("CONNECT".to_string())),
        b"PING" => complete(buf, end, Msg::Ping),
        b"PONG" => complete(buf, end, Msg::Ignored),
        _ => Frame::Invalid,
    }
}

/// Frame one message at the front of an outbound (server→client) buffer.
fn frame_outbound(buf: &[u8]) -> Frame {
    let Some(end) = line_end(buf, 0) else {
        return if buf.len() > MAX_LINE_LEN {
            Frame::Invalid
        } else {
            Frame::Partial
        };
    };
    let line = &buf[..end - 2];
    let Some((verb, args)) = split_verb(line) else {
        return Frame::Invalid;
    };

    match verb.as_slice() {
        // Server deliveries carry a counted payload, like PUB/HPUB.
        b"MSG" | b"HMSG" => frame_payload_line(buf, end, args, &verb),
        b"-ERR" => complete(buf, end, Msg::Err),
        b"PONG" => complete(buf, end, Msg::Pong),
        // Server acks / banner / its own keep-alive: framed, no record.
        b"+OK" | b"INFO" | b"PING" => complete(buf, end, Msg::Ignored),
        _ => Frame::Invalid,
    }
}

/// Frame a payload-bearing control line (`PUB`/`HPUB`/`MSG`/`HMSG`). The byte count
/// is the line's last token. The payload (count bytes) plus its trailing CRLF are
/// either fully present (→ `Complete`) or must be skipped as they arrive
/// (→ `NeedsSkip`). For `HPUB`/`HMSG` the line has two counts (header-len then
/// total-len); the total is the last token, which is the count we skip.
fn frame_payload_line(buf: &[u8], line_end: usize, args: &[u8], verb: &[u8]) -> Frame {
    let subject = first_token(args);
    let Some(count) = parse_byte_count(last_token(args)) else {
        return Frame::Invalid;
    };
    let msg = match verb {
        // Server-side deliveries produce no client-operation record.
        b"MSG" | b"HMSG" => Msg::Ignored,
        _ => Msg::ClientOp(label(verb, subject)),
    };
    // A hostile count near `usize::MAX` parses as a valid `usize` but cannot be a
    // real message — `count + 2` (and `line_end + payload_total`) would overflow
    // and panic in debug builds. A count that can't fit the address space is not
    // NATS: reject it as malformed rather than crash. (`checked_add` covers both
    // adds; either overflowing ⇒ `Invalid`.)
    let Some(full_len) = count
        .checked_add(2)
        .and_then(|payload_total| line_end.checked_add(payload_total))
    else {
        return Frame::Invalid;
    };
    let payload_total = full_len - line_end; // payload + trailing CRLF
    if buf.len() >= full_len {
        Frame::Complete {
            msg,
            total_len: full_len,
        }
    } else {
        // Drop only the control line now; the whole payload+CRLF is the skip. Any
        // payload bytes already buffered after the line stay put and are consumed
        // by `DirBuf::drain_skip` — so the skip is the full payload, not net of
        // what's buffered (double-subtracting those bytes would under-skip).
        Frame::NeedsSkip {
            msg,
            line_len: line_end,
            skip: payload_total,
        }
    }
}

/// Build the operation label: `"<VERB> <subject>"`, or the bare verb when the
/// subject is empty.
fn label(verb: &[u8], subject: String) -> String {
    let verb = String::from_utf8_lossy(verb);
    if subject.is_empty() {
        verb.into_owned()
    } else {
        format!("{verb} {subject}")
    }
}

/// A complete single-line message helper.
fn complete(_buf: &[u8], end: usize, msg: Msg) -> Frame {
    Frame::Complete {
        msg,
        total_len: end,
    }
}

/// A control line longer than this with no CRLF is not NATS (real control lines
/// are short; even a fat `CONNECT` JSON option set stays well under this). Caps
/// buffering on a stream of junk so we fail closed instead of growing forever.
const MAX_LINE_LEN: usize = 64 * 1024;

/// True if `buf` begins with a known NATS verb followed by the delimiter that verb
/// requires — a positive signature, never a guess. The delimiter check stops
/// `PUBLISHER` matching `PUB` or `SUBSCRIBE` matching `SUB`.
///
/// The arg-bearing verbs (`CONNECT`/`PUB`/`HPUB`/`SUB`/`UNSUB`) ALWAYS carry a
/// mandatory argument in real NATS, so they are only NATS when followed by a
/// space/tab — a verb directly followed by CRLF (`PUB\r\n`, `CONNECT\r\n`) is never
/// valid NATS and is rejected. Only `PING`/`PONG` are valid bare, so they alone may
/// be CR-delimited. This refusal of the bare CRLF form removes a false-positive on
/// other line-oriented text protocols whose first frame is a bare verb + CRLF (e.g.
/// a STOMP `CONNECT\r\n`). Conservative: NATS shares no magic-number framing with
/// binary protocols, so an exact verb token plus its required delimiter is the
/// strongest signal a text protocol offers; when the prefix is too short to delimit
/// a verb we wait rather than guess.
pub(crate) fn looks_like_request(buf: &[u8]) -> bool {
    CLIENT_VERBS.iter().any(|verb| {
        if buf.len() < verb.len() || !buf[..verb.len()].eq_ignore_ascii_case(verb) {
            return false;
        }
        // `PING`/`PONG` are the only verbs valid with no argument, so only they may
        // be CR-delimited; every other verb requires a space/tab before its args.
        let bare_ok = matches!(*verb, b"PING" | b"PONG");
        match buf.get(verb.len()) {
            Some(b' ') | Some(b'\t') => true,
            Some(b'\r') => bare_ok,
            _ => false,
        }
    })
}

/// Recognise NATS from a connection's inbound prefix and return a fresh boxed
/// parser, or `None` if these bytes aren't a NATS control message. Phase 4 wires
/// this into `super::conn::detect`.
pub(crate) fn detect_nats(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if looks_like_request(inbound) {
        Some(Box::new(NatsParser::new()))
    } else {
        None
    }
}

/// A client `PING` awaiting its `PONG`, with the time it was observed (for the
/// round-trip latency of the health check).
#[derive(Debug)]
struct PendingPing {
    start_unix_nano: i64,
}

/// NATS [`L7Parser`]: reassembles each direction, frames control lines (skipping
/// counted payloads), emits one record per client verb at the time it is seen,
/// pairs `PING`→`PONG` for latency, and marks `-ERR` lines as errors.
#[derive(Debug, Default)]
pub(crate) struct NatsParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending_pings: VecDeque<PendingPing>,
    records: Vec<L7Record>,
    dead: bool,
}

impl NatsParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a fire-and-forget operation record (no paired response).
    fn push_op(&mut self, operation: String, ts: i64) {
        self.records.push(L7Record {
            protocol: PROTOCOL,
            attributes: Vec::new(),
            operation,
            status_code: 0,
            error: false,
            start_unix_nano: ts,
            duration_nano: 0,
        });
    }

    /// Frame as many complete client messages as the inbound buffer holds.
    fn drain_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() {
                return;
            }
            if self.inbound.buf.is_empty() {
                return;
            }
            match frame_inbound(&self.inbound.buf) {
                Frame::Complete { msg, total_len } => {
                    self.apply_inbound(msg, ts);
                    self.inbound.advance(total_len);
                }
                Frame::NeedsSkip {
                    msg,
                    line_len,
                    skip,
                } => {
                    self.apply_inbound(msg, ts);
                    // Drop the control line now; remember the payload+CRLF to skip.
                    self.inbound.advance(line_len);
                    self.inbound.skip = skip;
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Act on one framed client message.
    fn apply_inbound(&mut self, msg: Msg, ts: i64) {
        match msg {
            Msg::ClientOp(operation) => self.push_op(operation, ts),
            Msg::Ping => self.pending_pings.push_back(PendingPing {
                start_unix_nano: ts,
            }),
            // A client `PONG` (answering a server PING) produces no record.
            Msg::Pong | Msg::Err | Msg::Ignored => {}
        }
    }

    /// Frame as many complete server messages as the outbound buffer holds.
    fn drain_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() {
                return;
            }
            if self.outbound.buf.is_empty() {
                return;
            }
            match frame_outbound(&self.outbound.buf) {
                Frame::Complete { msg, total_len } => {
                    self.apply_outbound(msg, ts);
                    self.outbound.advance(total_len);
                }
                Frame::NeedsSkip {
                    msg,
                    line_len,
                    skip,
                } => {
                    self.apply_outbound(msg, ts);
                    self.outbound.advance(line_len);
                    self.outbound.skip = skip;
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Act on one framed server message.
    fn apply_outbound(&mut self, msg: Msg, ts: i64) {
        match msg {
            // `PONG` answers the oldest pending client `PING`: emit the round-trip.
            Msg::Pong => {
                if let Some(ping) = self.pending_pings.pop_front() {
                    self.records.push(L7Record {
                        protocol: PROTOCOL,
                        attributes: Vec::new(),
                        operation: "PING".to_string(),
                        status_code: 0,
                        error: false,
                        start_unix_nano: ping.start_unix_nano,
                        duration_nano: ts.saturating_sub(ping.start_unix_nano).max(0),
                    });
                }
            }
            // `-ERR '<reason>'` is the protocol failure verdict.
            Msg::Err => self.records.push(L7Record {
                protocol: PROTOCOL,
                attributes: Vec::new(),
                operation: "-ERR".to_string(),
                status_code: 1,
                error: true,
                start_unix_nano: ts,
                duration_nano: 0,
            }),
            // Server deliveries / acks / banner: out-of-band, no record.
            Msg::ClientOp(_) | Msg::Ping | Msg::Ignored => {}
        }
    }
}

impl L7Parser for NatsParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.inbound.buf.extend_from_slice(bytes);
        self.drain_inbound(ts);
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.outbound.buf.extend_from_slice(bytes);
        self.drain_outbound(ts);
    }

    fn take_records(&mut self) -> Vec<L7Record> {
        std::mem::take(&mut self.records)
    }

    fn is_dead(&self) -> bool {
        self.dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nats_verbs_by_positive_signature() {
        assert!(looks_like_request(b"CONNECT {}\r\n"));
        assert!(looks_like_request(b"PUB orders.created 5\r\n"));
        assert!(looks_like_request(b"SUB events.* 1\r\n"));
        assert!(looks_like_request(b"PING\r\n"));
        assert!(looks_like_request(b"PONG\r\n"));
        assert!(looks_like_request(b"HPUB a 1 2\r\n"));
        // Not NATS: undelimited longer tokens, other protocols, raw binary.
        assert!(!looks_like_request(b"PUBLISHER x\r\n")); // verb must be delimited
        assert!(!looks_like_request(b"SUBSCRIBE x\r\n"));
        assert!(!looks_like_request(b"GET /x HTTP/1.1\r\n"));
        assert!(!looks_like_request(b"*2\r\n$3\r\nGET\r\n")); // RESP
        assert!(!looks_like_request(b"\x16\x03\x01\x02")); // TLS hello
        assert!(!looks_like_request(b"PU")); // too short to delimit — wait
    }

    #[test]
    fn arg_bearing_verbs_require_a_space_not_a_bare_crlf() {
        // CONNECT/PUB/HPUB/SUB/UNSUB always carry a mandatory argument in real
        // NATS, so a bare verb + CRLF is never valid NATS and must NOT detect — this
        // is the false-positive a sibling line-protocol (e.g. STOMP `CONNECT\r\n`)
        // would otherwise trip. Tab is a valid arg delimiter too.
        assert!(!looks_like_request(b"CONNECT\r\n"));
        assert!(!looks_like_request(b"PUB\r\n"));
        assert!(!looks_like_request(b"HPUB\r\n"));
        assert!(!looks_like_request(b"SUB\r\n"));
        assert!(!looks_like_request(b"UNSUB\r\n"));
        assert!(looks_like_request(b"PUB\tfoo 1\r\n")); // tab-delimited args are fine
        // PING/PONG are the only verbs valid bare, so they alone may be CR-delimited.
        assert!(looks_like_request(b"PING\r\n"));
        assert!(looks_like_request(b"PONG\r\n"));
        // detect_nats follows the same rule: a bare CONNECT\r\n is not a NATS parser.
        assert!(detect_nats(b"CONNECT\r\n").is_none());
        assert!(detect_nats(b"PING\r\n").is_some());
    }

    #[test]
    fn detect_nats_returns_a_parser_only_on_a_match() {
        assert!(detect_nats(b"CONNECT {\"verbose\":false}\r\n").is_some());
        assert!(detect_nats(b"PING\r\n").is_some());
        assert!(detect_nats(b"not nats at all").is_none());
    }

    #[test]
    fn pub_with_payload_yields_one_op_record_with_subject() {
        let mut p = NatsParser::new();
        p.on_inbound(b"PUB orders.created 5\r\nhello\r\n", 1_000);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUB orders.created");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 0);
    }

    #[test]
    fn pub_with_reply_subject_uses_first_token_as_subject() {
        // PUB <subject> <reply-to> <#bytes> — the subject is the first token, the
        // count is the last token; the reply-to in between is not the subject.
        let mut p = NatsParser::new();
        p.on_inbound(b"PUB req.svc _INBOX.42 3\r\nhey\r\n", 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUB req.svc");
    }

    #[test]
    fn sub_uses_subject_unsub_uses_bare_verb() {
        let mut p = NatsParser::new();
        p.on_inbound(b"SUB events.* 7\r\n", 1);
        p.on_inbound(b"UNSUB 7 10\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SUB events.*");
        assert_eq!(recs[1].operation, "UNSUB"); // sid, not a subject
    }

    #[test]
    fn connect_is_an_operation_record() {
        let mut p = NatsParser::new();
        p.on_inbound(b"CONNECT {\"verbose\":false,\"name\":\"c\"}\r\n", 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
        assert!(!recs[0].error);
    }

    #[test]
    fn hpub_two_counts_skips_total_and_labels_subject() {
        // HPUB <subject> <#hdr> <#total>\r\n<hdr><payload>\r\n — the total (last
        // token) is the byte count to skip; the subject is the first token.
        let mut p = NatsParser::new();
        // header "NATS/1.0\r\nK:V\r\n\r\n" is 17 bytes, payload "hi" 2 bytes → total 19.
        p.on_inbound(b"HPUB greet 17 19\r\nNATS/1.0\r\nK:V\r\n\r\nhi\r\n", 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "HPUB greet");
        assert!(!p.is_dead());
    }

    #[test]
    fn ping_pairs_with_pong_for_latency() {
        let mut p = NatsParser::new();
        p.on_inbound(b"PING\r\n", 1_000);
        // No record yet — PING awaits its PONG.
        assert!(p.take_records().is_empty());
        p.on_outbound(b"PONG\r\n", 1_250);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PING");
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 250);
    }

    #[test]
    fn server_err_line_is_an_error_record() {
        let mut p = NatsParser::new();
        p.on_inbound(b"PUB bad.subject 0\r\n\r\n", 1);
        p.on_outbound(
            b"-ERR 'Permissions Violation for Publish to bad.subject'\r\n",
            2,
        );
        let recs = p.take_records();
        // One op record for PUB, one error record for -ERR.
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "PUB bad.subject");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "-ERR");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 1);
    }

    #[test]
    fn server_msg_delivery_produces_no_record_and_is_skipped() {
        // A server MSG push answers no client request — it must frame and skip its
        // payload without minting a record, and not consume a pending PING.
        let mut p = NatsParser::new();
        p.on_inbound(b"SUB foo 1\r\n", 1);
        p.on_inbound(b"PING\r\n", 2);
        // Server pushes a message, then answers the PING.
        p.on_outbound(b"MSG foo 1 5\r\nhello\r\nPONG\r\n", 3);
        let recs = p.take_records();
        // SUB op (from inbound) + PING/PONG pair — but NOT a record for MSG.
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SUB foo");
        assert_eq!(recs[1].operation, "PING");
    }

    #[test]
    fn info_and_ok_are_framed_without_records() {
        let mut p = NatsParser::new();
        p.on_outbound(b"INFO {\"server_id\":\"x\",\"max_payload\":1048576}\r\n", 1);
        p.on_inbound(b"CONNECT {}\r\n", 2);
        p.on_outbound(b"+OK\r\n", 3);
        let recs = p.take_records();
        // Only the CONNECT op; INFO and +OK mint nothing.
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
    }

    #[test]
    fn pipelined_client_verbs_each_emit_a_record() {
        let mut p = NatsParser::new();
        // CONNECT, SUB, then a PUB with payload, all in one inbound segment.
        p.on_inbound(
            b"CONNECT {}\r\nSUB orders 1\r\nPUB orders.new 2\r\nhi\r\n",
            10,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "CONNECT");
        assert_eq!(recs[1].operation, "SUB orders");
        assert_eq!(recs[2].operation, "PUB orders.new");
    }

    #[test]
    fn fragmented_control_line_waits_instead_of_misparsing() {
        let mut p = NatsParser::new();
        // The control line is split mid-way — no CRLF yet, must wait.
        p.on_inbound(b"PUB orders.cre", 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_inbound(b"ated 5\r\nhello\r\n", 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUB orders.created");
    }

    #[test]
    fn fragmented_payload_is_skipped_across_segments() {
        let mut p = NatsParser::new();
        // Control line + only part of the 5-byte payload arrives first.
        p.on_inbound(b"PUB sub 5\r\nhel", 1);
        let recs = p.take_records();
        // The op record is emitted as soon as the control line frames.
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUB sub");
        assert!(!p.is_dead());
        // Remainder of the payload + CRLF, then a pipelined PUB must parse cleanly,
        // proving the skip consumed exactly the payload and its trailing CRLF.
        p.on_inbound(b"lo\r\nPUB next 1\r\nx\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUB next");
    }

    #[test]
    fn orphan_pong_with_no_pending_ping_is_dropped_not_dead() {
        let mut p = NatsParser::new();
        p.on_outbound(b"PONG\r\n", 1); // attached mid-connection, missed the PING
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn unknown_verb_marks_the_parser_dead() {
        let mut p = NatsParser::new();
        p.on_inbound(b"BOGUS something\r\n", 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn pub_with_non_numeric_count_is_invalid() {
        let mut p = NatsParser::new();
        p.on_inbound(b"PUB subject notanumber\r\n", 1);
        assert!(p.is_dead());
    }

    #[test]
    fn pub_count_at_usize_max_is_invalid_not_a_panic() {
        // A count that parses as a valid `usize` but is so large that `count + 2`
        // (and `line_end + payload_total`) overflows must be rejected as malformed,
        // never panic. `99999999999999999999` overflows the *parse* (covered
        // elsewhere); this is the value that parses fine yet overflows the *math*.
        let max = usize::MAX.to_string();
        let line = format!("PUB x {max}\r\n");
        let mut p = NatsParser::new();
        p.on_inbound(line.as_bytes(), 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn server_msg_count_at_usize_max_is_invalid_not_a_panic() {
        // Same overflow guard on the outbound (server) framing path: a hostile
        // `MSG`/`HMSG` byte count near `usize::MAX` must not panic the parser.
        let max = usize::MAX.to_string();
        let line = format!("MSG foo 1 {max}\r\n");
        let mut p = NatsParser::new();
        p.on_outbound(line.as_bytes(), 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Feed hostile/truncated payloads at every byte boundary, both directions,
        // in both orders. The hard requirement is no panic, ever — a wrong verdict
        // is acceptable, a crash is not.
        let payloads: &[&[u8]] = &[
            b"PUB\r\n",                          // PUB with no args
            b"PUB  \r\n",                        // PUB with only spaces
            b"PUB x\r\n",                        // PUB missing the byte count
            b"PUB x -1\r\n",                     // negative count
            b"PUB x 99999999999999999999\r\n",   // count overflows usize parse
            b"PUB x 18446744073709551615\r\n",   // count = usize::MAX: parses, math overflows
            b"MSG y 1 18446744073709551615\r\n", // same overflow on the server framing path
            b"HPUB a\r\n",                       // HPUB missing counts
            b"SUB\r\n",                          // SUB no subject
            b"UNSUB\r\n",                        // UNSUB no sid
            b"PING",                             // verb, no CRLF
            b"\r\n\r\n\r\n",                     // only CRLFs
            b"-ERR\r\n",                         // bare error
            b"MSG x 1 5\r\nhi",                  // truncated payload
            b"\x00\x01\x02\x03",                 // raw binary
            b"CONNECT",                          // verb prefix, no delimiter/CRLF
            b"PUB x 5\r\nab",                    // body shorter than declared
            &[b' '; 1024],                       // many spaces, no verb, no CRLF
            &[b'A'; 1024],                       // long junk line, no CRLF
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // inbound side
                let mut p = NatsParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                // outbound side, with a pending PING to exercise pairing paths
                let mut q = NatsParser::new();
                q.on_inbound(b"PING\r\n", 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
            }
        }
    }

    #[test]
    fn long_junk_line_without_crlf_is_rejected_not_buffered_forever() {
        let mut p = NatsParser::new();
        // A run far past MAX_LINE_LEN with no CRLF must fail closed.
        let junk = vec![b'A'; MAX_LINE_LEN + 16];
        p.on_inbound(&junk, 1);
        assert!(p.is_dead());
    }
}
