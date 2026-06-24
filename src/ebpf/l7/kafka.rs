//! Kafka wire parser — implements [`super::L7Parser`], the zero-code APM producer
//! for connections speaking the Kafka binary protocol (the agent monitors a
//! *client* process, so the request side carries the bytes the client writes and
//! the response side what it reads, but the [`super::L7Parser`] contract is
//! direction-agnostic: the side whose frames carry a request header is the request
//! side, the side whose frames carry a response header is the response side).
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every message, both directions, is length-prefixed and BIG-ENDIAN:
//! `[messageSize: i32][payload]`, where `messageSize` counts the payload but NOT
//! the 4-byte size field itself, so `total_len = 4 + messageSize`. This is a
//! 4-byte BE read plus a request-header walk; pulling a Kafka client crate for
//! that would betray the leanness moat, so it's hand-rolled.
//!
//! ### Request header
//!
//! The payload begins with a `RequestHeader`:
//! `apiKey: i16`, `apiVersion: i16`, `correlationId: i32`,
//! `clientId: nullable string` (`i16` length, then bytes; `-1` = null). Newer
//! "flexible" header versions append tagged fields after `clientId`, but we only
//! read up to `correlationId` (a fixed offset) so header-version drift never moves
//! the fields we need. `apiKey` -> the operation label (`Produce`, `Fetch`, …).
//!
//! ### Response header
//!
//! The payload begins with `correlationId: i32` — at byte offset 0, stable across
//! every response-header version (v0 = bare correlationId; flexible versions only
//! *append* tagged fields). We pair a response to its request by this id.
//!
//! ## Pairing — by correlationId, not FIFO
//!
//! Unlike a strictly request-ordered protocol, Kafka stamps each request with a
//! `correlationId` and the broker echoes it; replies for one connection do come
//! back in request order in practice, but the id is the authoritative key, so we
//! pair on it (a map id -> pending request) rather than assuming FIFO.
//!
//! ## What we extract (and only this)
//!
//! - `operation`: the API name from `apiKey` (`Produce`/`Fetch`/…), fallback
//!   `ApiKey<N>` for keys we don't name. We never decode the request body past the
//!   header.
//! - `status_code`: `0`. The per-API error code lives deep in the response body and
//!   its position varies by `apiVersion` per API — out of scope (see the module
//!   note below). A stable top-level error_code does not exist across APIs, so we
//!   do not guess one.
//! - `error`: `false`, for the same reason — full per-API error decode is out of
//!   scope for this slice; the goal is operation labelling + correlation pairing.
//! - timing: request `ts` -> response `ts` (saturating, floored at 0), per the
//!   trait.

use std::collections::HashMap;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Protocol tag stamped on every record this parser mints.
const KAFKA_PROTOCOL: Protocol = Protocol::Kafka;

/// Sanity bound on a single message. The protocol permits larger (a big `Fetch`
/// response can run to MBs), but for span extraction we only ever read the small
/// fixed header prefix, and a length beyond this on a "Kafka" stream means we
/// mis-detected or desynced — bail rather than buffer unboundedly. We still *frame*
/// past large bodies via `DirBuf::skip`; this only rejects absurd size fields.
const MAX_MSG_LEN: usize = 100 * 1024 * 1024;

/// Highest `apiKey` we treat as plausibly Kafka for detection. The protocol grows
/// new keys over time; this is a generous ceiling well above the assigned range,
/// kept deliberately conservative so a random binary stream's first i16 is unlikely
/// to land inside it.
const MAX_DETECT_API_KEY: i16 = 68;

/// Highest `apiVersion` we treat as plausible for detection. Real versions are
/// small single digits today; 20 is generous headroom while still rejecting the
/// large values a non-Kafka stream's bytes would usually present.
const MAX_DETECT_API_VERSION: i16 = 20;

/// Generous ceiling on `clientId` length for detection. A real client id is a short
/// human string; an implausibly long one is a desync/false-positive signal.
const MAX_DETECT_CLIENT_ID_LEN: i16 = 256;

/// Request-header bytes the *detector* inspects: apiKey(2) + apiVersion(2) +
/// correlationId(4) + clientId length(2) = 10. Detection validates the clientId
/// length field as part of the signature, so it reads two bytes past what the
/// parser extracts (`MIN_REQUEST_HEADER`). Kept separate so neither concern can
/// silently shrink the other's bounds check into an out-of-range read.
const DETECT_HEADER_PREFIX: usize = 10;

/// Minimum request-header bytes needed to read the fields we extract:
/// apiKey(2) + apiVersion(2) + correlationId(4). We never read `clientId` (or its
/// length), so the prefix we require is exactly the bytes up to `correlationId`.
const MIN_REQUEST_HEADER: usize = 8;

/// Cap on outstanding (unanswered) requests held in `pending`. A correlationId is a
/// client-chosen i32, so a peer that floods one-directional requests (or whose
/// replies we never see — the documented "attached mid-connection" case) would grow
/// the map without limit. Kafka's in-flight ceiling is `max.in.flight.requests.per.
/// connection` (default 5, rarely tuned past a few thousand), so this is generous
/// headroom for any legitimate connection while still capping a leaking/hostile one.
/// Beyond it the parser dies (the stream is desynced or abusive) — same discipline
/// as the per-message size bound: bail rather than buffer unboundedly.
const MAX_INFLIGHT: usize = 40_000;

/// Read a big-endian i32 from the first four bytes of `b` (caller guarantees len).
fn be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Read a big-endian i16 from the first two bytes of `b` (caller guarantees len).
fn be_i16(b: &[u8]) -> i16 {
    i16::from_be_bytes([b[0], b[1]])
}

/// Map an `apiKey` to its operation label. Common keys are named; anything else
/// falls back to `ApiKey<N>` so the span is still labelled rather than dropped.
fn api_name(api_key: i16) -> String {
    let name = match api_key {
        0 => "Produce",
        1 => "Fetch",
        2 => "ListOffsets",
        3 => "Metadata",
        8 => "OffsetCommit",
        9 => "OffsetFetch",
        10 => "FindCoordinator",
        11 => "JoinGroup",
        12 => "Heartbeat",
        14 => "SyncGroup",
        18 => "ApiVersions",
        19 => "CreateTopics",
        22 => "InitProducerId",
        _ => return format!("ApiKey{api_key}"),
    };
    name.to_string()
}

/// Outcome of trying to read one length-prefixed message head off a buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed message of `total_len` bytes (`4 + messageSize`).
    Framed { total_len: usize },
    /// A valid prefix but not enough bytes for the size field yet — wait.
    Partial,
    /// Not Kafka framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Frame one message: read the 4-byte BE `messageSize`, validate it, return the
/// total byte length the message occupies. The body itself is not required to be
/// buffered (large bodies are framed past via `DirBuf::skip`); only the size field
/// must be present to frame.
fn message_head(buf: &[u8]) -> Head {
    if buf.len() < 4 {
        return Head::Partial;
    }
    let size = be_i32(&buf[0..4]);
    // messageSize counts the payload (a non-empty header at minimum), so it must be
    // positive and within the memory bound. <= 0 or absurd = desync.
    if size <= 0 || size as usize > MAX_MSG_LEN {
        return Head::Invalid;
    }
    Head::Framed {
        total_len: 4 + size as usize,
    }
}

/// The correlationId of a request, plus the operation label its header decoded to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestHeader {
    correlation_id: i32,
    operation: String,
}

/// Decode the `RequestHeader` fields a span needs from a message *payload* (the
/// bytes after the 4-byte size field). Returns `None` if the payload is too short
/// to hold the fixed prefix — the caller waits for the rest of the message.
fn parse_request_header(payload: &[u8]) -> Option<RequestHeader> {
    if payload.len() < MIN_REQUEST_HEADER {
        return None;
    }
    let api_key = be_i16(&payload[0..2]);
    // apiVersion at [2..4] and clientId beyond are not needed to label or pair.
    let correlation_id = be_i32(&payload[4..8]);
    Some(RequestHeader {
        correlation_id,
        operation: api_name(api_key),
    })
}

/// Read the `correlationId` from a response *payload* (bytes after the size field).
/// It sits at offset 0 in every response-header version. `None` if fewer than 4
/// payload bytes are buffered (wait).
fn parse_response_correlation_id(payload: &[u8]) -> Option<i32> {
    if payload.len() < 4 {
        return None;
    }
    Some(be_i32(&payload[0..4]))
}

/// A request awaiting its reply, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// Kafka [`L7Parser`]: frames both directions by length prefix, decodes each
/// request header to a `(correlationId, operation)` pair, and matches each response
/// to its request by `correlationId`. Desync (an absurd size field) marks it dead.
#[derive(Debug, Default)]
pub(crate) struct KafkaParser {
    request: DirBuf,
    response: DirBuf,
    /// Outstanding requests keyed by correlationId, awaiting their reply.
    pending: HashMap<i32, Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl KafkaParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frame as many complete request messages as the buffer holds, recording each
    /// `(correlationId -> operation)` to await its reply. A request label needs the
    /// fixed header prefix; if the message frames but the header prefix hasn't all
    /// arrived, we still advance past the (large) body and record whatever header
    /// fields are present — the prefix is the first 8 payload bytes, always present
    /// once the message frames at all (messageSize >= header size).
    fn drain_request(&mut self, ts: i64) {
        loop {
            if !self.request.drain_skip() {
                return;
            }
            if self.request.buf.is_empty() {
                return;
            }
            match message_head(&self.request.buf) {
                Head::Framed { total_len } => {
                    // The header prefix (first 8 payload bytes) must be buffered to
                    // read apiKey + correlationId. If the message frames but those
                    // bytes still straddle the segment boundary, wait — advancing now
                    // would skip the header as framing and lose the request.
                    let header_end = 4 + MIN_REQUEST_HEADER;
                    if self.request.buf.len() < header_end.min(total_len) {
                        return;
                    }
                    let payload = &self.request.buf[4..total_len.min(self.request.buf.len())];
                    if let Some(header) = parse_request_header(payload) {
                        self.pending.insert(
                            header.correlation_id,
                            Pending {
                                operation: header.operation,
                                start_unix_nano: ts,
                            },
                        );
                        // A correlationId is a client-chosen i32; if replies never
                        // arrive (we attached mid-connection, or the peer floods
                        // one-directionally) `pending` would grow without bound. Cap
                        // it and die past the ceiling — bail rather than buffer
                        // unboundedly, the same discipline as the per-message size
                        // bound. Advancing the buffer first keeps memory bounded even
                        // on the fatal segment.
                        self.request.advance(total_len);
                        if self.pending.len() > MAX_INFLIGHT {
                            self.dead = true;
                            return;
                        }
                        continue;
                    }
                    self.request.advance(total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Frame as many complete response messages as the buffer holds, pairing each
    /// with the pending request carrying its `correlationId`. A response whose id
    /// has no pending request is dropped — we attached mid-connection and missed it.
    fn drain_response(&mut self, ts: i64) {
        loop {
            if !self.response.drain_skip() {
                return;
            }
            if self.response.buf.is_empty() {
                return;
            }
            match message_head(&self.response.buf) {
                Head::Framed { total_len } => {
                    // Need the 4-byte correlationId at the payload front to pair. If
                    // the message frames but those 4 bytes straddle, wait.
                    let id_end = 4 + 4;
                    if self.response.buf.len() < id_end.min(total_len) {
                        return;
                    }
                    let payload = &self.response.buf[4..total_len.min(self.response.buf.len())];
                    if let Some(id) = parse_response_correlation_id(payload)
                        && let Some(req) = self.pending.remove(&id)
                    {
                        self.records.push(L7Record {
                            protocol: KAFKA_PROTOCOL,
                            attributes: Vec::new(),
                            operation: req.operation,
                            // Per-API error codes are body-position-dependent on
                            // apiVersion — out of scope this slice. See module note.
                            status_code: 0,
                            error: false,
                            start_unix_nano: req.start_unix_nano,
                            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
                        });
                    }
                    self.response.advance(total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }
}

impl L7Parser for KafkaParser {
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

/// Recognise Kafka from a connection's request-side prefix via a POSITIVE,
/// CONSERVATIVE signature and return a fresh boxed parser, or `None`.
///
/// Kafka has no magic bytes — the wire is bare big-endian integers — so a byte-only
/// sniff is inherently weak and we err hard toward `None`. The signature validates
/// the whole fixed request-header shape against narrow plausibility windows:
///
///   * `messageSize` (i32) positive and within the memory bound, AND at least the
///     fixed header it claims to contain;
///   * `apiKey` (i16) in the assigned range `0..=68`;
///   * `apiVersion` (i16) small (`0..=20`);
///   * `clientId` length (i16) either `-1` (null) or a plausible short length.
///
/// All four must hold. A random binary stream rarely satisfies the conjunction (a
/// small apiKey *and* a small apiVersion *and* a sane clientId length *and* a sane
/// size, all big-endian, in sequence). A port hint (9092) from the connection tuple
/// would make this reliable; this byte sniff is the fallback when the tuple isn't
/// threaded through. When unsure (header prefix not yet buffered), return `None`.
pub(crate) fn detect_kafka(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    // Need the size field (4) + the fixed request-header prefix (apiKey 2 +
    // apiVersion 2 + correlationId 4 + clientId length 2 = 10).
    if inbound.len() < 4 + DETECT_HEADER_PREFIX {
        return None;
    }

    let size = be_i32(&inbound[0..4]);
    if size <= 0 || size as usize > MAX_MSG_LEN {
        return None;
    }
    // The claimed message must be large enough to hold the header we're about to
    // read — otherwise the size field disagrees with the body, i.e. not Kafka.
    if (size as usize) < DETECT_HEADER_PREFIX {
        return None;
    }

    let payload = &inbound[4..];
    let api_key = be_i16(&payload[0..2]);
    if !(0..=MAX_DETECT_API_KEY).contains(&api_key) {
        return None;
    }
    let api_version = be_i16(&payload[2..4]);
    if !(0..=MAX_DETECT_API_VERSION).contains(&api_version) {
        return None;
    }
    // correlationId [4..8] — any i32 is valid, no constraint to apply.
    let client_id_len = be_i16(&payload[8..10]);
    // -1 (null) or a plausibly short length. A large/odd length is a desync signal.
    if !(-1..=MAX_DETECT_CLIENT_ID_LEN).contains(&client_id_len) {
        return None;
    }

    Some(Box::new(KafkaParser::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a request message: `[size:4 BE][apiKey:2][apiVersion:2][corr:4]`
    /// `[clientIdLen:2][clientId bytes]`, size = payload length.
    fn request(api_key: i16, api_version: i16, corr: i32, client_id: Option<&str>) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&api_key.to_be_bytes());
        payload.extend_from_slice(&api_version.to_be_bytes());
        payload.extend_from_slice(&corr.to_be_bytes());
        match client_id {
            Some(s) => {
                payload.extend_from_slice(&(s.len() as i16).to_be_bytes());
                payload.extend_from_slice(s.as_bytes());
            }
            None => payload.extend_from_slice(&(-1i16).to_be_bytes()),
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    /// Build a response message: `[size:4 BE][corr:4][body...]`, size = payload len.
    fn response(corr: i32, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&corr.to_be_bytes());
        payload.extend_from_slice(body);
        let mut msg = Vec::new();
        msg.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    #[test]
    fn api_name_maps_common_keys_and_falls_back() {
        assert_eq!(api_name(0), "Produce");
        assert_eq!(api_name(1), "Fetch");
        assert_eq!(api_name(3), "Metadata");
        assert_eq!(api_name(18), "ApiVersions");
        assert_eq!(api_name(22), "InitProducerId");
        // Unmapped key -> fallback label, never dropped.
        assert_eq!(api_name(60), "ApiKey60");
    }

    #[test]
    fn detects_a_well_formed_request_header() {
        // Fetch v11 with a client id.
        assert!(detect_kafka(&request(1, 11, 7, Some("rdkafka"))).is_some());
        // Produce v9 with a null client id.
        assert!(detect_kafka(&request(0, 9, 1, None)).is_some());
        // ApiVersions v0 — the typical first request on a fresh connection.
        assert!(detect_kafka(&request(18, 0, 0, Some("client"))).is_some());
    }

    #[test]
    fn detection_is_conservative_about_non_kafka_bytes() {
        // HTTP request — not Kafka.
        assert!(detect_kafka(b"GET /x HTTP/1.1\r\nHost: y\r\n\r\n").is_none());
        // Too short to hold the header prefix.
        assert!(detect_kafka(b"\x00\x00\x00\x10").is_none());
        // Sane size but apiKey out of range (0x7fff).
        let mut bad_key = request(1, 1, 1, Some("c"));
        bad_key[4] = 0x7f;
        bad_key[5] = 0xff;
        assert!(detect_kafka(&bad_key).is_none());
        // Sane size + key but apiVersion absurd (0x7fff).
        let mut bad_ver = request(1, 1, 1, Some("c"));
        bad_ver[6] = 0x7f;
        bad_ver[7] = 0xff;
        assert!(detect_kafka(&bad_ver).is_none());
        // Sane otherwise but clientId length implausibly large. The length field is
        // the two header bytes before the id bytes: payload offset 8..10 = message
        // offset 12..14.
        let mut bad_cid = request(1, 1, 1, Some("c"));
        bad_cid[12] = 0x7f;
        bad_cid[13] = 0xff;
        assert!(detect_kafka(&bad_cid).is_none());
        // Negative messageSize.
        let neg = {
            let mut v = Vec::new();
            v.extend_from_slice(&(-5i32).to_be_bytes());
            v.extend_from_slice(&[0u8; 12]);
            v
        };
        assert!(detect_kafka(&neg).is_none());
        // All zeros: size 0 -> rejected.
        assert!(detect_kafka(&[0u8; 16]).is_none());
    }

    #[test]
    fn normal_request_response_yields_one_record() {
        let mut p = KafkaParser::new();
        p.on_inbound(&request(1, 11, 42, Some("app")), 1_000);
        assert!(p.take_records().is_empty()); // no response yet
        // Response body is opaque to us; any bytes after correlationId frame past.
        p.on_outbound(&response(42, b"\x00\x00\x00\x01arbitrary body"), 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn unmapped_api_key_still_labels_via_fallback() {
        let mut p = KafkaParser::new();
        p.on_inbound(&request(60, 0, 5, Some("c")), 10);
        p.on_outbound(&response(5, b""), 12);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "ApiKey60");
        assert_eq!(recs[0].duration_nano, 2);
    }

    #[test]
    fn pairs_by_correlation_id_not_arrival_order() {
        // Two requests; the broker replies out of request order. correlationId, not
        // FIFO, must pair each reply to its own request.
        let mut p = KafkaParser::new();
        p.on_inbound(&request(0, 9, 100, Some("c")), 10); // Produce, id 100
        p.on_inbound(&request(1, 11, 200, Some("c")), 20); // Fetch, id 200
        // Reply to 200 (Fetch) arrives FIRST, then 100 (Produce).
        p.on_outbound(&response(200, b"fetchbody"), 30);
        p.on_outbound(&response(100, b"prodbody"), 40);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        // First record pairs with id 200 = Fetch, requested at ts 20, replied at 30.
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[0].start_unix_nano, 20);
        assert_eq!(recs[0].duration_nano, 10);
        // Second pairs with id 100 = Produce, requested at 10, replied at 40.
        assert_eq!(recs[1].operation, "Produce");
        assert_eq!(recs[1].start_unix_nano, 10);
        assert_eq!(recs[1].duration_nano, 30);
    }

    #[test]
    fn pipelined_requests_then_responses_all_pair() {
        let mut p = KafkaParser::new();
        // Three requests back-to-back in one segment.
        let mut reqs = Vec::new();
        reqs.extend(request(3, 9, 1, Some("c"))); // Metadata
        reqs.extend(request(12, 4, 2, Some("c"))); // Heartbeat
        reqs.extend(request(18, 0, 3, None)); // ApiVersions
        p.on_inbound(&reqs, 100);
        // Three responses in order in one segment.
        let mut resps = Vec::new();
        resps.extend(response(1, b"m"));
        resps.extend(response(2, b"h"));
        resps.extend(response(3, b"a"));
        p.on_outbound(&resps, 200);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "Metadata");
        assert_eq!(recs[1].operation, "Heartbeat");
        assert_eq!(recs[2].operation, "ApiVersions");
    }

    #[test]
    fn fragmented_request_header_waits_then_completes() {
        let mut p = KafkaParser::new();
        let req = request(1, 11, 77, Some("rdkafka"));
        // Feed the size field + only the first 4 header bytes (apiKey+apiVersion);
        // correlationId hasn't arrived, so no pending request may be recorded.
        p.on_inbound(&req[..8], 10);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // A response now would have nothing to pair with.
        p.on_outbound(&response(77, b"body"), 20);
        assert!(
            p.take_records().is_empty(),
            "must not pair against an unparsed request"
        );
        // Deliver the rest of the request, then the real reply.
        p.on_inbound(&req[8..], 30);
        p.on_outbound(&response(77, b"body"), 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn fragmented_response_correlation_id_waits() {
        let mut p = KafkaParser::new();
        p.on_inbound(&request(0, 9, 5, Some("c")), 1);
        let resp = response(5, b"a big body that streams in pieces");
        // Size field + only 2 of the 4 correlationId bytes: must wait.
        p.on_outbound(&resp[..6], 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // Rest arrives; now it pairs.
        p.on_outbound(&resp[6..], 9);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Produce");
        assert_eq!(recs[0].duration_nano, 8);
    }

    #[test]
    fn large_response_body_split_across_segments_frames_past() {
        // A Fetch reply whose body is far larger than a single segment must be
        // framed past via DirBuf::skip, then the next pipelined reply still pairs.
        let mut p = KafkaParser::new();
        p.on_inbound(&request(1, 11, 1, Some("c")), 1); // Fetch, id 1
        p.on_inbound(&request(3, 9, 2, Some("c")), 2); // Metadata, id 2
        let big = response(1, &vec![0xab; 5000]);
        // Deliver the first reply in two chunks straddling the body.
        p.on_outbound(&big[..1000], 10);
        p.on_outbound(&big[1000..], 11);
        // Then the second reply.
        p.on_outbound(&response(2, b"meta"), 12);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[1].operation, "Metadata");
    }

    #[test]
    fn orphan_response_with_unknown_correlation_id_is_dropped() {
        let mut p = KafkaParser::new();
        // Reply for an id we never saw a request for (attached mid-connection).
        p.on_outbound(&response(999, b"body"), 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn insane_message_size_marks_dead() {
        let mut p = KafkaParser::new();
        // A negative/absurd size field is a desync signal -> dead.
        let mut bad = Vec::new();
        bad.extend_from_slice(&(-1i32).to_be_bytes());
        bad.extend_from_slice(&[0u8; 12]);
        p.on_inbound(&bad, 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn oversized_message_size_marks_dead() {
        let mut p = KafkaParser::new();
        let mut bad = Vec::new();
        bad.extend_from_slice(&(i32::MAX).to_be_bytes()); // > MAX_MSG_LEN
        bad.extend_from_slice(&[0u8; 12]);
        p.on_inbound(&bad, 1);
        assert!(p.is_dead());
    }

    /// HARD REQUIREMENT: never panic on adversarial bytes, in any framing, on either
    /// direction, at any fragmentation. The only acceptable outcomes are "dead",
    /// "waiting", or a (possibly wrong-but-bounded) record — never a panic or
    /// unbounded buffering.
    #[test]
    fn never_panics_on_hostile_bytes() {
        let hostile: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff],
            vec![0x00, 0x00, 0x00],                   // size field truncated
            vec![0x00, 0x00, 0x00, 0x00],             // size 0
            vec![0xff, 0xff, 0xff, 0xff],             // size -1
            vec![0x7f, 0xff, 0xff, 0xff],             // size huge
            vec![0x00, 0x00, 0x00, 0x0a],             // size 10, no body
            vec![0x00, 0x00, 0x00, 0x0a, 0x00, 0x01], // size 10, header straddles
            request(1, 11, 5, Some("c")),             // a valid one, for split coverage
            response(5, b"body"),
            {
                // size claims fewer bytes than a header — header reads must stay in bounds.
                let mut v = Vec::new();
                v.extend_from_slice(&3i32.to_be_bytes());
                v.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
                v
            },
            (0u8..=255).collect(),
            vec![0x00; 1024],
        ];

        for seed in &hostile {
            // Detection must never panic.
            let _ = detect_kafka(seed);

            // Whole-buffer, both directions.
            let mut p = KafkaParser::new();
            p.on_inbound(seed, 1);
            p.on_outbound(seed, 2);
            let _ = p.take_records();
            let _ = p.is_dead();

            // Split at every boundary, both directions, both orders.
            for split in 0..=seed.len() {
                let (a, b) = seed.split_at(split);

                let mut q = KafkaParser::new();
                q.on_inbound(a, 1);
                q.on_inbound(b, 2);
                let _ = q.take_records();

                let mut r = KafkaParser::new();
                // Prime a pending request so response framing exercises pairing too.
                r.on_inbound(&request(1, 11, 5, Some("c")), 0);
                r.on_outbound(a, 1);
                r.on_outbound(b, 2);
                let _ = r.take_records();
                let _ = r.is_dead();
            }
        }
    }

    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        let mut p = KafkaParser::new();
        let req = request(1, 11, 314, Some("client"));
        for byte in req.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let resp = response(314, b"some response body bytes");
        for (i, byte) in resp.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[0].start_unix_nano, 1_000);
        // A Kafka reply is identified the instant its correlationId (payload bytes
        // 0..4 = message bytes 4..8) is buffered — byte index 7 here. The opaque
        // body after it is framed past, but the pair is already complete, so the
        // response is stamped at the correlationId-complete moment (ts 2_007), the
        // earliest faithful response-observation point. Unlike Postgres, nothing a
        // span needs lives in the body, so there is no reason to wait for it.
        assert_eq!(recs[0].duration_nano, (2_000 + 7) - 1_000);
    }

    /// Wrap a raw payload in the 4-byte BE size frame (size = payload length).
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        msg.extend_from_slice(payload);
        msg
    }

    /// REGRESSION (request-header read/require mismatch): a request whose payload is
    /// exactly the 8 bytes we read — `apiKey`(2) + `apiVersion`(2) + `correlationId`(4),
    /// with no `clientId` field at all — must still be recorded and pair with its
    /// reply. The old code required 10 payload bytes (`clientId` length included) even
    /// though it only *reads* the first 8, so it silently dropped this request and its
    /// response could never pair.
    #[test]
    fn request_with_only_the_read_prefix_still_pairs() {
        let mut p = KafkaParser::new();
        // apiKey=1 (Fetch), apiVersion=11, correlationId=55 — exactly 8 payload bytes.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&11i16.to_be_bytes());
        payload.extend_from_slice(&55i32.to_be_bytes());
        assert_eq!(payload.len(), 8);
        p.on_inbound(&frame(&payload), 100);
        // The request was recorded (not dropped), so its reply pairs.
        p.on_outbound(&response(55, b"body"), 140);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "8-byte-prefix request must be recorded");
        assert_eq!(recs[0].operation, "Fetch");
        assert_eq!(recs[0].duration_nano, 40);
    }

    /// REGRESSION (unbounded `pending` growth): a peer that sends requests whose
    /// replies never arrive — the documented "attached mid-connection" case, or a
    /// one-directional flood — must not grow `pending` without limit. Past
    /// `MAX_INFLIGHT` outstanding requests the parser dies rather than buffering
    /// unboundedly, the same discipline as the per-message size bound.
    #[test]
    fn unanswered_request_flood_is_bounded_and_dies() {
        let mut p = KafkaParser::new();
        // One segment packed with many distinct-correlationId requests, no replies —
        // just past the cap so the guard trips while draining.
        let mut flood = Vec::new();
        for corr in 0..(MAX_INFLIGHT as i32 + 50) {
            flood.extend(request(0, 9, corr, Some("c")));
        }
        p.on_inbound(&flood, 1);
        assert!(
            p.is_dead(),
            "pending must be capped; an unanswered-request flood must mark the parser dead"
        );
        // Bounded: never grew past the cap (+1, the insert that tripped the guard).
        assert!(
            p.pending.len() <= MAX_INFLIGHT + 1,
            "pending grew past the cap: {}",
            p.pending.len()
        );
        // Dead parsers ignore further input.
        p.on_inbound(&request(1, 11, i32::MAX, Some("c")), 2);
        assert!(p.take_records().is_empty());
    }

    /// A connection legitimately saturated up to (but not past) the in-flight cap must
    /// keep working — the bound must not kill a busy-but-valid pipeline.
    #[test]
    fn busy_pipeline_under_the_cap_survives() {
        let mut p = KafkaParser::new();
        // A modest pipeline well under the cap: many in-flight, then drain them.
        let n = 1_000i32;
        let mut reqs = Vec::new();
        for corr in 0..n {
            reqs.extend(request(1, 11, corr, Some("c")));
        }
        p.on_inbound(&reqs, 10);
        assert!(!p.is_dead());
        let mut resps = Vec::new();
        for corr in 0..n {
            resps.extend(response(corr, b"r"));
        }
        p.on_outbound(&resps, 20);
        let recs = p.take_records();
        assert_eq!(recs.len(), n as usize);
        assert!(!p.is_dead());
    }

    /// A large *request* body (a big Produce) split across segments must frame past on
    /// the request side via `DirBuf::skip`, then the next pipelined request still pairs
    /// — the symmetric counterpart to the large-response test, previously uncovered.
    #[test]
    fn large_request_body_split_across_segments_frames_past() {
        let mut p = KafkaParser::new();
        // A Produce request whose record batch dwarfs a single segment.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i16.to_be_bytes()); // Produce
        payload.extend_from_slice(&9i16.to_be_bytes()); // v9
        payload.extend_from_slice(&7i32.to_be_bytes()); // correlationId 7
        payload.extend_from_slice(&(-1i16).to_be_bytes()); // null clientId
        payload.extend(vec![0xcd; 6000]); // big record batch
        let big = frame(&payload);
        // Deliver in two chunks straddling the body.
        p.on_inbound(&big[..500], 10);
        p.on_inbound(&big[500..], 11);
        // A second, small request right after.
        p.on_inbound(&request(3, 9, 8, Some("c")), 12); // Metadata, id 8
        // Replies in order.
        p.on_outbound(&response(7, b"prod"), 20);
        p.on_outbound(&response(8, b"meta"), 21);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "Produce");
        assert_eq!(recs[0].start_unix_nano, 10);
        assert_eq!(recs[1].operation, "Metadata");
    }
}
