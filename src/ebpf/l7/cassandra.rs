//! Cassandra native CQL **envelope** wire parser — implements [`super::L7Parser`],
//! the zero-code APM producer for connections speaking the DataStax/Apache native
//! protocol.
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every CQL **envelope** is a fixed **9-byte header** followed by a body:
//!
//! ```text
//! [version:1][flags:1][stream:i16 BE][opcode:1][length:i32 BE][body: length bytes]
//! ```
//!
//! - **version**: `0x04`/`0x05` on a request, the high bit set on the matching
//!   response (`0x84`/`0x85`). The low 7 bits are the protocol version (4 or 5).
//! - **stream**: the correlation id. Cassandra *multiplexes* — a client may have
//!   many requests in flight on one connection and responses can return in any
//!   order — so requests and responses are paired by matching `stream`, NOT FIFO.
//!   (Server-pushed EVENTs carry stream id `-1` and answer no request.)
//! - **opcode**: the message kind (QUERY/EXECUTE/RESULT/ERROR/…).
//! - **length**: body byte count (BE i32, always ≥ 0 on the wire).
//!
//! A 9-byte BE read; pulling a CQL driver crate for that would betray the leanness
//! moat, so it's hand-rolled.
//!
//! ## v4 vs v5 scope (IMPORTANT — read before "adding v5 support")
//!
//! This parser handles the **bare CQL envelope** above. That is the *entire* v4
//! wire format, and it is also exactly what a v5 connection speaks **during the
//! initial handshake** — the v5 spec (§2.3.1) keeps `STARTUP`/`OPTIONS` and their
//! `READY`/`AUTHENTICATE`/`SUPPORTED` replies *unframed*.
//!
//! After the server answers `STARTUP` with `READY`/`AUTHENTICATE`, a v5 connection
//! switches to the **modern framing layer**: each envelope is wrapped in a frame
//! with a 6-byte *little-endian* header (`payload length:17b | self-contained flag
//! | CRC24`), a payload of up to 128 KiB, and a CRC32 trailer (§2 of the v5 spec).
//! Those wrapper bytes are NOT a CQL envelope — the wrapper's first byte is the low
//! byte of a length, not a `0x05`/`0x85` version byte — so the moment a v5
//! connection starts modern framing this parser can no longer read it.
//!
//! We do **not** implement modern framing / LZ4 / CRC here (that surface — checksum
//! verification, segment reassembly, decompression — is large and out of this
//! slice's lean scope). When a v5 connection starts modern framing, the wrapper's
//! leading bytes fail the bare-envelope version-byte check, so [`parse_header`]
//! returns [`Head::Invalid`] and the connection is marked dead — the same terminal
//! "stop, don't guess" outcome used for any desync. The v4 handshake spans and any
//! v5-handshake spans already emitted survive; only post-handshake v5 application
//! traffic is dropped. This is a deliberate, tested boundary (see
//! `v5_modern_framing_is_dropped_cleanly_not_mis_parsed`), not an accident — do not
//! "fix" it by loosening the version-byte check, which would mis-frame the wrapper.
//!
//! ## What we extract (and only this)
//!
//! - `operation`: for QUERY, the CQL verb (`SELECT`/`INSERT`/…) decoded from the
//!   `[long string]` at the body start — never the bound values or the full text
//!   beyond the leading keyword; for EXECUTE/PREPARE/BATCH/STARTUP/… the opcode
//!   name. We decode only the QUERY string head.
//! - `status_code`: `0` on success; on an `ERROR` response the CQL error code (the
//!   BE i32 at the body start, e.g. `0x2200` = Invalid) as a `u16`.
//! - `error`: true iff the response opcode is `ERROR`.
//! - timing: request `ts` -> response `ts` (saturating, floored at 0), per the
//!   trait — negative durations from clock skew would poison RED.

use std::collections::HashMap;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// CQL frame header length: version(1) + flags(1) + stream(2) + opcode(1) + length(4).
const HEADER_LEN: usize = 9;

/// Request opcodes (subset we label; the rest fall back to a generic label).
const OP_STARTUP: u8 = 0x01;
const OP_OPTIONS: u8 = 0x05;
const OP_QUERY: u8 = 0x07;
const OP_PREPARE: u8 = 0x09;
const OP_EXECUTE: u8 = 0x0A;
const OP_REGISTER: u8 = 0x0B;
const OP_BATCH: u8 = 0x0D;

/// Response opcodes we act on. `ERROR` is the failure verdict; `RESULT` is the
/// success terminator. Other responses (READY/AUTHENTICATE/SUPPORTED/EVENT/…) are
/// framed past — only the request<->response pairing on `stream` matters.
const OP_ERROR: u8 = 0x00;
const OP_RESULT: u8 = 0x08;

/// Protocol versions this parser recognises (the low 7 bits of the version byte).
/// v4 and v5 are the supported native-protocol generations.
const CQL_V4: u8 = 0x04;
const CQL_V5: u8 = 0x05;

/// High bit of the version byte: set on responses, clear on requests.
const RESPONSE_BIT: u8 = 0x80;

/// Sanity bound on a single frame body: a length beyond this on a "Cassandra"
/// stream means we mis-detected or desynced — bail rather than buffer unboundedly.
/// CQL bodies are usually small; large result sets are paged. Rejects an absurd
/// length field. NOTE: we never *buffer* a whole body of this size — large bodies
/// are framed past via [`DirBuf::skip`] (see [`drain_for`]); this only caps the
/// declared length we'll believe before calling the stream a desync.
const MAX_BODY_LEN: usize = 256 * 1024 * 1024;

/// How many body bytes we wait for before framing a request/response past. We only
/// ever read a small head of any body — the QUERY verb (after a 4-byte `[long
/// string]` length) or the ERROR code (the first 4 body bytes) — so this bounds
/// per-connection buffering to a small constant regardless of the real body size.
/// 64 bytes covers `[len:4] + leading whitespace + the longest CQL verb`; a verb
/// that doesn't fit degrades safely to the generic `"QUERY"` label.
const MAX_BODY_PREFIX: usize = 64;

/// Read a big-endian i16 (the stream id) from `b[0..2]` (caller guarantees len).
fn be_i16(b: &[u8]) -> i16 {
    i16::from_be_bytes([b[0], b[1]])
}

/// Read a big-endian u32 from `b[0..4]` (caller guarantees len).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The protocol version (low 7 bits) of a frame's version byte.
fn proto_version(version_byte: u8) -> u8 {
    version_byte & !RESPONSE_BIT
}

/// Is this a request version byte: high bit clear, version v4 or v5.
fn is_request_version(version_byte: u8) -> bool {
    version_byte & RESPONSE_BIT == 0 && matches!(proto_version(version_byte), CQL_V4 | CQL_V5)
}

/// Is this a response version byte: high bit set, version v4 or v5.
fn is_response_version(version_byte: u8) -> bool {
    version_byte & RESPONSE_BIT != 0 && matches!(proto_version(version_byte), CQL_V4 | CQL_V5)
}

/// One CQL frame header, parsed from a 9-byte prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHeader {
    version: u8,
    stream: i16,
    opcode: u8,
    /// Total bytes the whole frame occupies: header + body.
    total_len: usize,
}

impl FrameHeader {
    /// Body byte count (`total_len - HEADER_LEN`). Non-negative by construction:
    /// [`parse_header`] only builds a header once `HEADER_LEN` bytes are present and
    /// sets `total_len = HEADER_LEN + length`.
    fn body_len(&self) -> usize {
        self.total_len - HEADER_LEN
    }
}

/// How many *body* bytes we must have buffered to label a request frame, capped at
/// the frame's real body length. Only QUERY reads its body (the verb prefix); every
/// other request opcode is labelled from the opcode alone, so needs 0 body bytes.
/// The rest of the body is framed past via `skip`, never buffered.
fn request_label_prefix(h: FrameHeader) -> usize {
    match h.opcode {
        OP_QUERY => MAX_BODY_PREFIX.min(h.body_len()),
        _ => 0,
    }
}

/// How many *body* bytes we must have buffered to read a response's status. Only an
/// ERROR carries a code (the first 4 body bytes); a RESULT (and every other
/// response) needs 0. Capped at the frame's real body length so a malformed short
/// ERROR still frames rather than waiting forever.
fn response_code_prefix(h: FrameHeader) -> usize {
    if h.opcode == OP_ERROR {
        4.min(h.body_len())
    } else {
        0
    }
}

/// Outcome of trying to read one frame header off a direction buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed message head: the parsed header (`total_len` = 9 + body length).
    Framed(FrameHeader),
    /// A valid prefix but not enough bytes for the 9-byte header yet — wait.
    Partial,
    /// Not CQL framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Parse one frame header from a buffer prefix. `want_response` selects which
/// version-byte polarity is valid for this direction; the opposite polarity (or an
/// unknown version, or an out-of-bound length) is the desync signal.
fn parse_header(buf: &[u8], want_response: bool) -> Head {
    if buf.len() < HEADER_LEN {
        return Head::Partial;
    }
    let version = buf[0];
    let valid = if want_response {
        is_response_version(version)
    } else {
        is_request_version(version)
    };
    if !valid {
        return Head::Invalid;
    }
    let stream = be_i16(&buf[2..4]);
    let opcode = buf[4];
    let length = be_u32(&buf[5..9]) as usize;
    if length > MAX_BODY_LEN {
        return Head::Invalid;
    }
    Head::Framed(FrameHeader {
        version,
        stream,
        opcode,
        total_len: HEADER_LEN + length,
    })
}

/// The operation label for a request frame, from its opcode and body. Only QUERY
/// decodes its body (the `[long string]` CQL text -> verb); the rest map to a
/// fixed opcode name. The body slice is whatever is buffered for this frame.
fn request_label(opcode: u8, body: &[u8]) -> String {
    match opcode {
        OP_QUERY => query_verb(body),
        OP_EXECUTE => "EXECUTE".to_string(),
        OP_PREPARE => "PREPARE".to_string(),
        OP_BATCH => "BATCH".to_string(),
        OP_STARTUP => "STARTUP".to_string(),
        OP_OPTIONS => "OPTIONS".to_string(),
        OP_REGISTER => "REGISTER".to_string(),
        // Any other request opcode (AUTH_RESPONSE 0x0F, CREDENTIALS, …): a generic
        // hex label keeps the span without pretending to know the verb.
        other => format!("OPCODE_{other:#04x}"),
    }
}

/// Decode the leading CQL verb from a QUERY body. The body begins with a
/// `[long string]`: a 4-byte BE length followed by that many UTF-8 bytes of CQL.
/// We read only the first whitespace-delimited token, uppercased — never the bound
/// values, never the full statement. Falls back to `"QUERY"` when the string is
/// absent/empty/unrecoverable (a partial body that doesn't yet hold the verb).
fn query_verb(body: &[u8]) -> String {
    if body.len() < 4 {
        return "QUERY".to_string();
    }
    let str_len = be_u32(&body[0..4]) as usize;
    const START: usize = 4;
    // We may only have a prefix of the CQL text buffered; the verb is the first
    // token, so reading the available head is enough — no need for the whole string.
    let end = START.saturating_add(str_len).min(body.len());
    let cql = &body[START..end];
    let token = cql
        .split(|&b| b.is_ascii_whitespace())
        .find(|t| !t.is_empty());
    match token {
        Some(t) => String::from_utf8_lossy(t).to_ascii_uppercase(),
        None => "QUERY".to_string(),
    }
}

/// The CQL error code from an ERROR response body. The body begins with a 4-byte
/// BE `int` error code (e.g. `0x2200` = Invalid query), then a `[string]` message.
/// Truncated to a `u16` — all defined CQL error codes fit (max `0x2500`). Returns
/// `0` when the body is too short to hold the code.
fn error_code(body: &[u8]) -> u16 {
    if body.len() < 4 {
        return 0;
    }
    be_u32(&body[0..4]) as u16
}

/// A request awaiting its reply, keyed by stream id, with the observation time.
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// Cassandra CQL [`L7Parser`]: frames both directions on the 9-byte header, labels
/// requests, pairs each with its response by **stream id** (CQL multiplexes, so
/// responses can return out of order), and frames past every other message. A
/// version-byte polarity mismatch or an insane length marks it dead.
#[derive(Debug, Default)]
pub(crate) struct CassandraParser {
    request: DirBuf,
    response: DirBuf,
    /// Outstanding requests keyed by stream id. Bounded by the wire: a client can
    /// only have so many streams in flight (v4: 32768), and each response removes
    /// its entry. A hostile peer that opens streams without ever replying is capped
    /// by `MAX_INFLIGHT` below.
    pending: HashMap<i16, Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

/// Cap on outstanding (unanswered) requests. The v4 protocol allows up to 32768
/// concurrent streams; we bound a touch above that so a legitimate fully-saturated
/// connection still works, but a stream-leaking hostile peer can't grow the map
/// without limit. Beyond it the parser dies (the stream is desynced/abusive).
const MAX_INFLIGHT: usize = 40_000;

impl CassandraParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain_request(&mut self, ts: i64) {
        loop {
            if !self.request.drain_skip() {
                return;
            }
            if self.request.buf.is_empty() {
                return;
            }
            match parse_header(&self.request.buf, false) {
                Head::Framed(h) => {
                    // A request label needs only a small body *prefix* (the QUERY
                    // verb); the rest of the body is framed past via `skip`, so we
                    // never buffer a large statement. Wait until that prefix has
                    // arrived — advancing earlier would skip the verb as framing and
                    // mislabel the request (and pair a response against a request we
                    // hadn't yet labelled).
                    let need = HEADER_LEN + request_label_prefix(h);
                    if self.request.buf.len() < need {
                        return;
                    }
                    // Read only the buffered prefix of the body (capped at `need`);
                    // `request_label` already tolerates a partial QUERY string.
                    let body_end = need.min(self.request.buf.len());
                    let body = &self.request.buf[HEADER_LEN..body_end];
                    let operation = request_label(h.opcode, body);
                    // Last writer wins on a reused stream id (the prior request on it
                    // must already have been answered for the client to reuse it).
                    self.pending.insert(
                        h.stream,
                        Pending {
                            operation,
                            start_unix_nano: ts,
                        },
                    );
                    if self.pending.len() > MAX_INFLIGHT {
                        self.dead = true;
                        return;
                    }
                    // Frame past the whole body (header + length) — `advance` skips
                    // any unbuffered tail as it arrives, bounding memory.
                    self.request.advance(h.total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    fn drain_response(&mut self, ts: i64) {
        loop {
            if !self.response.drain_skip() {
                return;
            }
            if self.response.buf.is_empty() {
                return;
            }
            match parse_header(&self.response.buf, true) {
                Head::Framed(h) => {
                    let is_error = h.opcode == OP_ERROR;
                    // We pair (and stamp the completion time) once the head and the
                    // few body bytes we read have arrived — an ERROR needs its first
                    // 4 body bytes (the code); a RESULT needs none. The body tail is
                    // framed past via `skip`, so a large result page never buffers.
                    // Completion is stamped at head/prefix arrival, consistent with
                    // the sibling kafka/nats parsers (segment-arrival approximation,
                    // per the `L7Record::duration_nano` contract).
                    let need = HEADER_LEN + response_code_prefix(h);
                    if self.response.buf.len() < need {
                        return;
                    }
                    let body_end = need.min(self.response.buf.len());
                    let body = &self.response.buf[HEADER_LEN..body_end];
                    let status_code = if is_error { error_code(body) } else { 0 };
                    // Server-pushed EVENT frames (REGISTER subscriptions) answer no
                    // request and carry a stream id of -1; only pair frames whose
                    // stream matches an outstanding request.
                    if h.opcode == OP_RESULT || is_error {
                        self.complete(h.stream, is_error, status_code, ts);
                    }
                    self.response.advance(h.total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Pair a response with the request on its stream id, emitting one record. A
    /// response whose stream has no pending request is dropped (we attached
    /// mid-connection and missed its request, or it's a server push).
    fn complete(&mut self, stream: i16, error: bool, status_code: u16, ts: i64) {
        if let Some(req) = self.pending.remove(&stream) {
            self.records.push(L7Record {
                protocol: Protocol::Cassandra,
                attributes: Vec::new(),
                operation: req.operation,
                status_code,
                error,
                start_unix_nano: req.start_unix_nano,
                duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
            });
        }
    }
}

impl L7Parser for CassandraParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.request.buf.extend_from_slice(bytes);
        self.drain_request(ts);
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.response.buf.extend_from_slice(bytes);
        self.drain_response(ts);
    }

    fn take_records(&mut self) -> Vec<L7Record> {
        std::mem::take(&mut self.records)
    }

    fn is_dead(&self) -> bool {
        self.dead
    }
}

/// Recognise Cassandra (CQL v4/v5) from a connection's inbound prefix via a
/// POSITIVE signature and return a fresh boxed parser, or `None` if these bytes
/// aren't a CQL request head.
///
/// Conservative, byte-only (no port available at this layer): a binary protocol
/// without a port hint must not false-positive on other traffic. We require the
/// full 9-byte header AND:
///   * a **request** version byte (`0x04`/`0x05`, high bit clear),
///   * a **known request opcode** (an opcode a client actually sends), and
///   * a **sane body length** (within the memory bound).
///
/// A fresh CQL connection opens with STARTUP (or OPTIONS), so the very first
/// inbound frame is always a request opcode we know. Demanding a known opcode +
/// sane length on the exact request-version bytes makes a collision with arbitrary
/// binary traffic improbable. When unsure (fewer than 9 bytes, wrong polarity,
/// unknown opcode, insane length) we return `None`. A port hint (9042) would make
/// this airtight; the byte sniff is the fallback.
pub(crate) fn detect_cassandra(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    match parse_header(inbound, false) {
        Head::Framed(h) if is_known_request_opcode(h.opcode) => {
            Some(Box::new(CassandraParser::new()))
        }
        _ => None,
    }
}

/// Opcodes a CQL *client* sends. Detection demands one of these on the first frame
/// so we don't bind to a stream whose request-version byte collided by chance.
fn is_known_request_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_STARTUP | OP_OPTIONS | OP_QUERY | OP_PREPARE | OP_EXECUTE | OP_REGISTER | OP_BATCH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CQL frame: `[version][flags=0][stream:i16][opcode][len:i32][body]`.
    fn frame(version: u8, stream: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN + body.len());
        v.push(version);
        v.push(0); // flags
        v.extend_from_slice(&stream.to_be_bytes());
        v.push(opcode);
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A v4 request frame.
    fn req(stream: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
        frame(0x04, stream, opcode, body)
    }

    /// A v4 response frame (high bit set on the version byte).
    fn resp(stream: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
        frame(0x84, stream, opcode, body)
    }

    /// A QUERY body: `[long string]` = 4-byte BE length + UTF-8 CQL text.
    fn query_body(cql: &str) -> Vec<u8> {
        let mut b = (cql.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(cql.as_bytes());
        // (Real QUERY bodies also carry consistency + flags after the string; we
        // never read past the string, so omit them for brevity.)
        b
    }

    /// An ERROR body: `[int error_code]` + a `[string]` message.
    fn error_body(code: u32, message: &str) -> Vec<u8> {
        let mut b = code.to_be_bytes().to_vec();
        b.extend_from_slice(&(message.len() as u16).to_be_bytes());
        b.extend_from_slice(message.as_bytes());
        b
    }

    #[test]
    fn detects_a_query_request_head() {
        assert!(detect_cassandra(&req(0, OP_QUERY, &query_body("SELECT * FROM t"))).is_some());
    }

    #[test]
    fn detects_startup_and_options_opens() {
        assert!(detect_cassandra(&req(0, OP_STARTUP, b"")).is_some());
        assert!(detect_cassandra(&req(1, OP_OPTIONS, b"")).is_some());
    }

    #[test]
    fn detects_v5() {
        assert!(detect_cassandra(&frame(0x05, 0, OP_QUERY, &query_body("SELECT 1"))).is_some());
    }

    #[test]
    fn rejects_response_polarity_and_unknown_opcode_and_garbage() {
        // A response-version byte is not a request open.
        assert!(detect_cassandra(&resp(0, OP_RESULT, b"")).is_none());
        // A request-version byte but an opcode a client never sends as an open.
        assert!(detect_cassandra(&req(0, OP_RESULT, b"")).is_none());
        // Unsupported protocol version.
        assert!(detect_cassandra(&frame(0x03, 0, OP_QUERY, &query_body("SELECT 1"))).is_none());
        // Not Cassandra at all.
        assert!(detect_cassandra(b"GET /x HTTP/1.1\r\n").is_none());
        assert!(detect_cassandra(b"\x16\x03\x01\x02").is_none());
        // Too short for a full header — never guess.
        assert!(detect_cassandra(&req(0, OP_QUERY, b"")[..8]).is_none());
    }

    #[test]
    fn query_verb_decodes_the_leading_keyword_uppercased() {
        assert_eq!(query_verb(&query_body("select * from users")), "SELECT");
        assert_eq!(
            query_verb(&query_body("INSERT INTO t (a) VALUES (1)")),
            "INSERT"
        );
        assert_eq!(query_verb(&query_body("  update t set x=1")), "UPDATE");
        // Empty / too-short bodies fall back to QUERY, never panic.
        assert_eq!(query_verb(b""), "QUERY");
        assert_eq!(query_verb(&query_body("")), "QUERY");
        assert_eq!(query_verb(b"\x00\x00"), "QUERY");
    }

    #[test]
    fn one_query_response_yields_one_record() {
        let mut p = CassandraParser::new();
        p.on_inbound(
            &req(7, OP_QUERY, &query_body("SELECT id FROM users")),
            1_000,
        );
        assert!(p.take_records().is_empty()); // no response yet
        // RESULT body: a 4-byte result kind (2 = Rows); we never read it.
        p.on_outbound(&resp(7, OP_RESULT, &[0, 0, 0, 2]), 1_500);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 500);
    }

    #[test]
    fn execute_and_prepare_use_the_opcode_label() {
        let mut p = CassandraParser::new();
        // PREPARE then EXECUTE on distinct streams.
        p.on_inbound(
            &req(1, OP_PREPARE, &query_body("SELECT * FROM t WHERE id=?")),
            10,
        );
        p.on_inbound(&req(2, OP_EXECUTE, &[0, 4, 1, 2, 3, 4]), 11); // id + bound vals
        p.on_outbound(&resp(1, OP_RESULT, &[0, 0, 0, 4]), 12); // prepared
        p.on_outbound(&resp(2, OP_RESULT, &[0, 0, 0, 2]), 14); // rows
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "PREPARE");
        assert_eq!(recs[1].operation, "EXECUTE");
        assert!(!recs[0].error && !recs[1].error);
    }

    #[test]
    fn error_response_sets_the_failure_verdict_and_code() {
        let mut p = CassandraParser::new();
        p.on_inbound(&req(3, OP_QUERY, &query_body("SELECT * FROM missing")), 0);
        // 0x2200 = Invalid query.
        p.on_outbound(
            &resp(
                3,
                OP_ERROR,
                &error_body(0x2200, "unconfigured table missing"),
            ),
            5,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 0x2200);
        assert_eq!(recs[0].duration_nano, 5);
    }

    #[test]
    fn responses_pair_by_stream_id_out_of_order() {
        // The defining CQL trait: two requests in flight, responses returning in the
        // OPPOSITE order. FIFO pairing would mislabel both; stream-id pairing is
        // correct. Stream 10 = SELECT (errors), stream 20 = INSERT (ok).
        let mut p = CassandraParser::new();
        p.on_inbound(&req(10, OP_QUERY, &query_body("SELECT * FROM a")), 100);
        p.on_inbound(
            &req(20, OP_QUERY, &query_body("INSERT INTO b (x) VALUES (1)")),
            101,
        );
        // Stream 20's response comes back FIRST, then stream 10's.
        p.on_outbound(&resp(20, OP_RESULT, &[0, 0, 0, 1]), 110);
        p.on_outbound(&resp(10, OP_ERROR, &error_body(0x2200, "boom")), 120);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        // First completed record is stream 20 (INSERT, ok) — proves not-FIFO.
        assert_eq!(recs[0].operation, "INSERT");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 9);
        // Second is stream 10 (SELECT, error).
        assert_eq!(recs[1].operation, "SELECT");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 0x2200);
        assert_eq!(recs[1].duration_nano, 20);
        assert!(p.pending.is_empty());
    }

    #[test]
    fn fragmented_request_waits_then_completes() {
        let mut p = CassandraParser::new();
        let q = req(5, OP_QUERY, &query_body("SELECT * FROM orders"));
        // Header + first few body bytes only — verb not yet fully arrived.
        let split = HEADER_LEN + 4;
        p.on_inbound(&q[..split], 10);
        assert!(p.take_records().is_empty());
        // A response now would have no pending request to pair with (we never pushed
        // a truncated request's op).
        p.on_outbound(&resp(5, OP_RESULT, &[0, 0, 0, 1]), 20);
        assert!(
            p.take_records().is_empty(),
            "must not pair against a truncated request"
        );
        // Deliver the rest of the request, then its real response.
        p.on_inbound(&q[split..], 30);
        p.on_outbound(&resp(5, OP_RESULT, &[0, 0, 0, 1]), 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn fragmented_error_response_waits_for_full_body_then_classifies() {
        // REGRESSION-shape: a fragmented ERROR must WAIT for its full body, else the
        // pair is emitted at the head's time with status 0 instead of the real code.
        let mut p = CassandraParser::new();
        p.on_inbound(&req(8, OP_QUERY, &query_body("SELECT * FROM t")), 0);
        let err = resp(8, OP_ERROR, &error_body(0x1100, "write timeout")); // 0x1100
        // Deliver only the 9-byte header first; the body straddles.
        p.on_outbound(&err[..HEADER_LEN], 5);
        assert!(
            p.take_records().is_empty(),
            "must not complete on a partial head"
        );
        // Now the body arrives at a later time.
        p.on_outbound(&err[HEADER_LEN..], 9);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 0x1100); // survives fragmentation (was 0 before)
        assert_eq!(recs[0].duration_nano, 9); // stamped at full-message arrival
    }

    #[test]
    fn pipelined_requests_in_one_segment_each_pair() {
        let mut p = CassandraParser::new();
        // Two requests back-to-back in a single inbound segment, distinct streams.
        let mut reqs = req(1, OP_QUERY, &query_body("SELECT 1"));
        reqs.extend(req(2, OP_QUERY, &query_body("DELETE FROM x")));
        p.on_inbound(&reqs, 100);
        // Two responses back-to-back, matching streams, in order.
        let mut resps = resp(1, OP_RESULT, &[0, 0, 0, 1]);
        resps.extend(resp(2, OP_RESULT, &[0, 0, 0, 1]));
        p.on_outbound(&resps, 200);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SELECT");
        assert_eq!(recs[1].operation, "DELETE");
    }

    #[test]
    fn orphan_response_with_no_pending_stream_is_dropped_not_dead() {
        let mut p = CassandraParser::new();
        // A response for a stream we never saw a request on (attached mid-conn).
        p.on_outbound(&resp(99, OP_RESULT, &[0, 0, 0, 1]), 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn server_event_push_answers_no_request() {
        // An EVENT (opcode 0x0C) is server-pushed on stream -1; it must frame past
        // without pairing, leaving any real pending request untouched.
        const OP_EVENT: u8 = 0x0C;
        let mut p = CassandraParser::new();
        p.on_inbound(&req(4, OP_QUERY, &query_body("SELECT 1")), 1);
        // Event arrives before the real RESULT.
        p.on_outbound(&resp(-1, OP_EVENT, &[0, 4, b'a', b'b', b'c', b'd']), 2);
        assert!(p.take_records().is_empty(), "event must not pair");
        p.on_outbound(&resp(4, OP_RESULT, &[0, 0, 0, 1]), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
    }

    #[test]
    fn wrong_polarity_marks_dead() {
        // A response-version byte arriving on the REQUEST side is a desync.
        let mut p = CassandraParser::new();
        p.on_inbound(&resp(0, OP_RESULT, &[0, 0, 0, 1]), 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn insane_body_length_marks_dead() {
        let mut p = CassandraParser::new();
        // Request-version header but a body length beyond the memory bound.
        let mut bad = vec![0x04, 0x00, 0x00, 0x00, OP_QUERY];
        bad.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // ~4 GiB body
        p.on_inbound(&bad, 1);
        assert!(p.is_dead());
    }

    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        // Header + body delivered one byte at a time, both directions, must yield
        // exactly one correct record — never a duplicate or an early emission.
        let mut p = CassandraParser::new();
        let q = req(6, OP_QUERY, &query_body("SELECT id FROM users"));
        for byte in q.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let r = resp(6, OP_ERROR, &error_body(0x2200, "nope"));
        for (i, byte) in r.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 0x2200);
        // Completion is stamped when the bytes we actually read have arrived: an
        // ERROR needs the header (9) + the 4-byte code, i.e. the byte at index 12.
        // The trailing message string is framed past via `skip` and does not delay
        // completion (this is the resource fix: we never wait for a body tail we
        // don't read). ts at index 12 = 2_000 + 12.
        let code_complete_ts = 2_000 + (HEADER_LEN + 4 - 1) as i64;
        assert_eq!(recs[0].duration_nano, code_complete_ts - 1_000);
    }

    #[test]
    fn large_result_body_is_framed_past_not_buffered() {
        // RESOURCE BUG (was: waited for the whole frame before pairing): a RESULT
        // body is never read, so a large result page must be FRAMED PAST via `skip`
        // — paired as soon as the 9-byte head arrives, never buffered. Previously a
        // 256 MiB-capped body would have to be fully resident before the pair (and
        // any pipelined reply behind it) was emitted.
        let mut p = CassandraParser::new();
        p.on_inbound(&req(1, OP_QUERY, &query_body("SELECT * FROM big")), 100);

        // A RESULT whose declared body is 50 MiB, delivered as: the 9-byte head
        // (only), then a tiny first slice of the body. The pair must complete on the
        // head alone, and the buffer must NOT grow toward the body size.
        let body_len = 50 * 1024 * 1024usize;
        let mut head = Vec::new();
        head.push(0x84); // response v4
        head.push(0x00); // flags
        head.extend_from_slice(&1i16.to_be_bytes()); // stream 1
        head.push(OP_RESULT);
        head.extend_from_slice(&(body_len as u32).to_be_bytes());
        p.on_outbound(&head, 200);

        // Completed on the head — before a single body byte arrived.
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 100);
        assert!(p.pending.is_empty());

        // The body is now being skipped, not buffered: a chunk of it leaves the
        // buffer empty (consumed by `skip`) and never accumulates.
        p.on_outbound(&vec![0u8; 4096], 300);
        assert!(
            p.response.buf.len() < 4096,
            "response body must be framed past via skip, not buffered (buf grew to {})",
            p.response.buf.len()
        );
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn large_query_body_labels_from_prefix_and_frames_past_the_rest() {
        // RESOURCE BUG (request side): a QUERY with a huge CQL string must be
        // labelled from a bounded *prefix* (the verb) and the rest framed past —
        // never buffered whole. A pipelined request behind it must still pair.
        let mut p = CassandraParser::new();

        // A 10 MiB QUERY string: "SELECT " + filler. Only the verb prefix is needed.
        let big = format!("SELECT {}", "x".repeat(10 * 1024 * 1024));
        let mut seg = req(1, OP_QUERY, &query_body(&big));
        // A second, small pipelined request right behind it on a distinct stream.
        seg.extend(req(
            2,
            OP_QUERY,
            &query_body("INSERT INTO t (a) VALUES (1)"),
        ));
        p.on_inbound(&seg, 10);

        // Buffer must not hold the 10 MiB body: it was framed past via skip and the
        // pipelined INSERT was consumed too.
        assert!(
            p.request.buf.len() < MAX_BODY_PREFIX + HEADER_LEN + 64,
            "request body must be framed past, buf is {}",
            p.request.buf.len()
        );

        // Both requests were labelled (verb from the prefix) and are pending.
        p.on_outbound(&resp(1, OP_RESULT, &[0, 0, 0, 1]), 20);
        p.on_outbound(&resp(2, OP_RESULT, &[0, 0, 0, 1]), 21);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SELECT"); // recovered from the prefix
        assert_eq!(recs[1].operation, "INSERT"); // pipelined request not lost
        assert!(!p.is_dead());
    }

    #[test]
    fn large_error_body_reads_code_from_prefix_and_frames_past_the_message() {
        // RESOURCE BUG (error side): the error code is the first 4 body bytes; an
        // arbitrarily long error message must be framed past, not buffered. The code
        // and verdict must survive, and the pair completes once the code is in hand.
        let mut p = CassandraParser::new();
        p.on_inbound(&req(3, OP_QUERY, &query_body("SELECT * FROM t")), 0);

        // Declare a 20 MiB error body; deliver only the head + the 4-byte code.
        let body_len = 20 * 1024 * 1024usize;
        let mut head = Vec::new();
        head.push(0x84);
        head.push(0x00);
        head.extend_from_slice(&3i16.to_be_bytes());
        head.push(OP_ERROR);
        head.extend_from_slice(&(body_len as u32).to_be_bytes());
        head.extend_from_slice(&0x2200u32.to_be_bytes()); // the code, but no message
        p.on_outbound(&head, 5);

        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 0x2200);
        assert_eq!(recs[0].duration_nano, 5);

        // The 20 MiB message is skipped, not buffered.
        p.on_outbound(&vec![b'x'; 8192], 6);
        assert!(p.response.buf.len() < 8192, "message tail must be skipped");
        assert!(!p.is_dead());
    }

    #[test]
    fn v5_modern_framing_is_dropped_cleanly_not_mis_parsed() {
        // FRAMING BUG (the v5 claim): after a v5 STARTUP->READY handshake the wire
        // switches to the modern framing layer — a 6-byte LITTLE-ENDIAN header
        // (payload length:17b | self-contained | CRC24) wrapping the CQL envelope,
        // plus a CRC32 trailer. Those wrapper bytes are NOT a CQL envelope: the
        // leading byte is the low byte of a length, not a 0x05/0x85 version byte.
        // The parser must NOT mis-frame them into garbage spans; it stops (dead).
        let mut p = CassandraParser::new();

        // v5 handshake, bare-envelope (unframed per spec §2.3.1) — parsed fine.
        p.on_inbound(&frame(0x05, 0, OP_STARTUP, b""), 1);
        p.on_outbound(&frame(0x85, 0, 0x02 /* READY */, b""), 2);
        assert!(!p.is_dead(), "handshake is bare-envelope and must parse");
        // STARTUP/READY are not RESULT/ERROR, so no record — but no death either.
        assert!(p.take_records().is_empty());

        // Now a modern v5 frame on the response side. Build a realistic-looking
        // wrapper: 3-byte LE (payload len=20, self-contained bit) + 3-byte CRC24,
        // then an opaque payload + 4-byte CRC32. Its first byte is 0x14 (len low
        // byte), never a CQL response version byte.
        let payload_len = 20u32;
        let header_int: u32 = payload_len | (1 << 17); // self-contained flag = bit 17
        let mut modern = Vec::new();
        modern.extend_from_slice(&header_int.to_le_bytes()[..3]); // 3-byte LE length+flag
        modern.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // CRC24 of header
        modern.extend_from_slice(&[0x07; 20]); // opaque payload
        modern.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // CRC32 trailer
        assert_ne!(
            modern[0] & RESPONSE_BIT,
            RESPONSE_BIT,
            "not a response version byte"
        );

        p.on_outbound(&modern, 3);
        // The honest outcome: drop the connection rather than emit a garbage span.
        assert!(
            p.is_dead(),
            "modern v5 framing must be detected as unparseable"
        );
        assert!(
            p.take_records().is_empty(),
            "must never emit a record from wrapper bytes"
        );
    }

    /// HARD REQUIREMENT: never panic on adversarial bytes, in any framing, on
    /// either direction, at any fragmentation split. The only acceptable outcomes
    /// are "dead", "waiting", or a (possibly wrong-but-bounded) record — never a
    /// panic or unbounded buffering.
    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x04],
            vec![0x84],
            vec![0x04, 0x00, 0x00, 0x00, OP_QUERY], // header missing length
            vec![0x04, 0x00, 0x00, 0x00, OP_QUERY, 0xff, 0xff, 0xff, 0xff], // ~4 GiB body
            vec![0x04, 0x00, 0x00, 0x00, OP_QUERY, 0x00, 0x00, 0x00, 0x00], // empty body, no verb
            req(0, OP_QUERY, &[0xff, 0xff, 0xff, 0xff]), // string len > body
            req(0, OP_QUERY, &[0x00, 0x00, 0x00, 0x05, b'h', b'i']), // declared 5, only 2 present
            req(0, OP_ERROR, b""),                  // error opcode on req side
            resp(0, OP_ERROR, &[0x00]),             // error body too short for code
            resp(0, OP_RESULT, &[]),                // empty result
            frame(0x03, 0, OP_QUERY, &query_body("SELECT 1")), // wrong proto version
            frame(0xff, 0, 0xff, b"\xff\xff\xff\xff"), // all-bits header
            (0u8..=255).collect(),                  // every byte value
            vec![0x04; 1024],                       // many request-version bytes
            b"GET /x HTTP/1.1\r\n\r\n".to_vec(),    // HTTP on a CQL parser
            // A v5 modern-framing wrapper (6-byte LE header + payload + CRC32) —
            // post-handshake v5 bytes must never panic at any split.
            {
                let mut m = vec![0x14, 0x00, 0x02, 0xAB, 0xCD, 0xEF]; // len=20|flag + CRC24
                m.extend_from_slice(&[0x07; 20]);
                m.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                m
            },
            // A modern header whose low byte happens to equal a CQL version byte
            // (0x84) — the parser may mis-read it but must stay bounded, never panic.
            vec![
                0x84, 0x00, 0x02, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x05, 0x07, 0x07,
            ],
        ];
        for payload in &payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // Request side, split into two segments.
                let mut p = CassandraParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();
                // Response side, with a real outstanding request first.
                let mut q = CassandraParser::new();
                q.on_inbound(&req(7, OP_QUERY, &query_body("SELECT 1")), 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
                // Detection must never panic either.
                let _ = detect_cassandra(payload);
            }
        }
    }
}
