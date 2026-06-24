//! AMQP 0-9-1 (RabbitMQ) wire parser — implements [`super::L7Parser`], the
//! zero-code APM producer for AMQP connections.
//!
//! ## What AMQP is, for span purposes
//!
//! AMQP 0-9-1 is **asynchronous**, not request/response. A connection opens with
//! an 8-byte protocol header (`"AMQP" 0x00 0x00 0x09 0x01`), then a stream of
//! frames flows both ways independently. There is no per-request reply to pair:
//! a publisher streams `Basic.Publish`, the broker streams `Basic.Deliver`, and
//! lifecycle methods (`Connection.Start`, `Channel.Open`, …) interleave on either
//! side. So — unlike the FIFO-pairing parsers (HTTP/Redis/Postgres) — we emit one
//! [`L7Record`] **per METHOD frame**, on whichever direction it arrives, labelled
//! `Class.Method`. There is no pending queue and no latency between two messages;
//! `duration_nano` is 0 (the frame is observed in one moment), `start_unix_nano`
//! is its arrival time.
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! A frame is `[type:1][channel:2 BE][size:4 BE][payload:size][frame-end:1=0xCE]`,
//! so `total_len = 7 + size + 1`. `type` is METHOD=1, HEADER=2, BODY=3,
//! HEARTBEAT=8. Only METHOD frames carry a class/method id pair (`[class:2 BE]
//! [method:2 BE]` at the head of the payload) and produce a record; HEADER/BODY/
//! HEARTBEAT frames are framed past, unread. This is a fixed-offset binary grammar
//! — a 7-byte BE read plus a frame-end check — so pulling an AMQP crate would
//! betray the leanness moat. Hand-rolled.
//!
//! ## What we extract (and only this)
//!
//! - `operation`: `"<Class>.<Method>"` from the id pair (e.g. `"Basic.Publish"`).
//!   Unknown ids degrade to numeric (`"Class60.Method200"`) rather than dropping
//!   the frame — the verb is still a useful span label.
//! - `error` / `status_code`: only `Connection.Close` and `Channel.Close` carry a
//!   reply-code (the first u16 argument). A reply-code `>= 300` is the protocol's
//!   failure verdict: `error = true`, `status_code = reply-code`. Everything else
//!   is `error = false`, `status_code = 0`. We decode no other argument bytes.

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Frame type octets (the first byte of every frame).
const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;

/// The mandatory final octet of every frame. Its presence at the computed offset
/// is both a framing checksum and a positive detection signal.
const FRAME_END: u8 = 0xCE;

/// Bytes before the payload: `type:1 + channel:2 + size:4`.
const FRAME_HEADER_LEN: usize = 7;

/// The 8-byte protocol header a fresh connection opens with: `"AMQP"` then the
/// version quad `0x00 0x00 0x09 0x01` (major=0, minor=9, revision=1 in the 0-9-1
/// layout RabbitMQ uses). A clear, unambiguous detection signature.
const PROTOCOL_HEADER: [u8; 8] = [b'A', b'M', b'Q', b'P', 0x00, 0x00, 0x09, 0x01];

/// Sanity bound on a single frame payload. AMQP's negotiated frame-max is
/// typically 128 KiB; beyond a generous cap a "AMQP" stream is mis-detected or
/// desynced, so we bail rather than buffer unboundedly on hostile bytes.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// The class ids we recognise. A METHOD frame whose class is one of these (with a
/// well-formed frame-end) is a strong positive AMQP signal.
const KNOWN_CLASSES: [u16; 7] = [10, 20, 40, 50, 60, 90, 30];

/// Reply-code threshold for the protocol's failure verdict. AMQP reply codes below
/// 300 are success/informational; `>= 300` (e.g. 403 access-refused, 404 not-found,
/// 320 connection-forced, 541 internal-error) are failures.
const ERROR_REPLY_CODE: u16 = 300;

/// Read a big-endian u16 from the first two bytes of `b` (caller guarantees len).
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Read a big-endian u32 from the first four bytes of `b` (caller guarantees len).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The human label for a class id. Falls back to `ClassNNN` for ids we don't name
/// so an unrecognised-but-well-framed method still yields a useful span verb.
fn class_name(class_id: u16) -> String {
    match class_id {
        10 => "Connection".to_string(),
        20 => "Channel".to_string(),
        30 => "Access".to_string(),
        40 => "Exchange".to_string(),
        50 => "Queue".to_string(),
        60 => "Basic".to_string(),
        90 => "Tx".to_string(),
        other => format!("Class{other}"),
    }
}

/// The human label for a method id within a class. Falls back to `MethodNNN` for
/// ids we don't name. Only the methods listed in the wire spec are named; the rest
/// degrade numerically rather than being dropped.
fn method_name(class_id: u16, method_id: u16) -> String {
    let name = match (class_id, method_id) {
        (10, 10) => "Start",
        (10, 11) => "StartOk",
        (10, 40) => "Open",
        (10, 50) => "Close",
        (10, 51) => "CloseOk",
        (20, 10) => "Open",
        (20, 40) => "Close",
        (40, 10) => "Declare",
        (50, 10) => "Declare",
        (50, 20) => "Bind",
        (60, 10) => "Qos",
        (60, 20) => "Consume",
        (60, 40) => "Publish",
        (60, 60) => "Deliver",
        (60, 70) => "Get",
        (60, 80) => "Ack",
        (60, 90) => "Reject",
        (60, 120) => "Nack",
        (90, 10) => "Select",
        (90, 20) => "Commit",
        _ => return format!("Method{method_id}"),
    };
    name.to_string()
}

/// The `Class.Method` operation label for a method-frame id pair.
fn operation_label(class_id: u16, method_id: u16) -> String {
    format!(
        "{}.{}",
        class_name(class_id),
        method_name(class_id, method_id)
    )
}

/// True for the two close methods that carry a reply-code first argument:
/// `Connection.Close` (10,50) and `Channel.Close` (20,40).
fn is_close_method(class_id: u16, method_id: u16) -> bool {
    (class_id, method_id) == (10, 50) || (class_id, method_id) == (20, 40)
}

/// The failure verdict for a method frame. Only close methods carry a reply-code;
/// the code is the first u16 argument, immediately after the class+method ids in
/// the payload. A code `>= 300` is an error. Non-close methods, and close frames
/// whose body is too short to hold the code, are non-errors.
fn close_verdict(class_id: u16, method_id: u16, args: &[u8]) -> (bool, u16) {
    if is_close_method(class_id, method_id) && args.len() >= 2 {
        let reply_code = be_u16(args);
        if reply_code >= ERROR_REPLY_CODE {
            return (true, reply_code);
        }
    }
    (false, 0)
}

/// Outcome of framing one AMQP frame off a direction-buffer prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    /// A complete, well-formed frame. `record` is `Some` only for METHOD frames
    /// (the ones that produce a span); HEADER/BODY/HEARTBEAT yield `None`.
    Complete {
        record: Option<MethodFrame>,
        total_len: usize,
    },
    /// A valid prefix but the whole frame (header + payload + frame-end) isn't
    /// buffered yet — wait for more bytes.
    Partial,
    /// Not AMQP framing — bad type, oversized payload, or a missing frame-end
    /// octet means desync/garbage; drop the connection.
    Invalid,
}

/// The span-relevant fields decoded from one METHOD frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MethodFrame {
    operation: String,
    error: bool,
    status_code: u16,
}

/// Frame one AMQP frame at the front of `buf`. Validates the type, the payload
/// size bound, and the mandatory `0xCE` frame-end at the computed offset; only
/// METHOD frames are decoded into a [`MethodFrame`].
fn frame(buf: &[u8]) -> Frame {
    if buf.len() < FRAME_HEADER_LEN {
        return Frame::Partial;
    }
    let frame_type = buf[0];
    let size = be_u32(&buf[3..7]) as usize;
    if size > MAX_FRAME_SIZE {
        return Frame::Invalid;
    }
    let total_len = FRAME_HEADER_LEN + size + 1; // + frame-end octet
    if buf.len() < total_len {
        return Frame::Partial;
    }
    // The frame-end octet is mandatory and fixed — its absence is the desync
    // signal that keeps us from running off corrupt/garbage bytes.
    if buf[total_len - 1] != FRAME_END {
        return Frame::Invalid;
    }

    let payload = &buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + size];
    match frame_type {
        FRAME_METHOD => Frame::Complete {
            record: decode_method(payload),
            total_len,
        },
        // HEADER/BODY/HEARTBEAT and any other well-framed type carry nothing a span
        // needs — frame past them. (A heartbeat has size 0; this still validates.)
        FRAME_HEADER | FRAME_BODY | FRAME_HEARTBEAT => Frame::Complete {
            record: None,
            total_len,
        },
        // An unknown type byte with an otherwise-valid frame-end is tolerated as a
        // skipped frame rather than killing the connection — newer method classes
        // ride existing frame types, and a stray type with a correct 0xCE at the
        // right offset is overwhelmingly more likely a frame we don't model than
        // garbage. Garbage is caught by the frame-end check above.
        _ => Frame::Complete {
            record: None,
            total_len,
        },
    }
}

/// Decode a METHOD frame payload into its span fields. The payload begins with
/// `[class:2 BE][method:2 BE]`; the remaining bytes are the method arguments, of
/// which we read only a leading reply-code for the two close methods. A payload
/// too short to hold the id pair is not a valid method frame (`None`).
fn decode_method(payload: &[u8]) -> Option<MethodFrame> {
    if payload.len() < 4 {
        return None;
    }
    let class_id = be_u16(&payload[0..2]);
    let method_id = be_u16(&payload[2..4]);
    let args = &payload[4..];
    let (error, status_code) = close_verdict(class_id, method_id, args);
    Some(MethodFrame {
        operation: operation_label(class_id, method_id),
        error,
        status_code,
    })
}

/// AMQP 0-9-1 [`L7Parser`]: frames both directions, emits one record per METHOD
/// frame (AMQP is async — no request/response pairing), and frames past HEADER/
/// BODY/HEARTBEAT frames unread. A bad type/size/frame-end marks it dead.
#[derive(Debug, Default)]
pub(crate) struct AmqpParser {
    inbound: DirBuf,
    outbound: DirBuf,
    /// Per-direction: set once that direction's leading 8-byte protocol header has
    /// been resolved (stripped if present, or ruled out), so a header arriving in
    /// its own segment is handled before frame parsing begins. The header rides the
    /// inbound (client→server) direction, but capture ordering can deliver an
    /// outbound frame first — a shared flag would let that outbound resolution
    /// suppress the real inbound header strip and desync the stream, so each
    /// direction tracks its own state.
    saw_inbound_header: bool,
    saw_outbound_header: bool,
    records: Vec<L7Record>,
    dead: bool,
}

impl AmqpParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain as many complete frames as `dir` holds, emitting a record per METHOD
    /// frame. Stops on a partial (waits) or invalid (dies). The protocol header,
    /// if present at the very front of either direction, is stripped first.
    fn drain(&mut self, inbound: bool, ts: i64) {
        // Strip this direction's leading 8-byte protocol header if present. It only
        // ever appears once, at connection open, and isn't a frame. State is tracked
        // per direction so a frame resolved on the other direction can't suppress it.
        let saw_header = if inbound {
            self.saw_inbound_header
        } else {
            self.saw_outbound_header
        };
        if !saw_header {
            let buf = if inbound {
                &self.inbound.buf
            } else {
                &self.outbound.buf
            };
            if buf.len() >= PROTOCOL_HEADER.len() {
                if buf[..PROTOCOL_HEADER.len()] == PROTOCOL_HEADER {
                    let b = if inbound {
                        &mut self.inbound
                    } else {
                        &mut self.outbound
                    };
                    b.advance(PROTOCOL_HEADER.len());
                }
                if inbound {
                    self.saw_inbound_header = true
                } else {
                    self.saw_outbound_header = true
                }
            } else if buf.starts_with(&PROTOCOL_HEADER[..buf.len()]) {
                // A proper prefix of the header is still arriving — wait, rather
                // than try to frame "AMQP" as a frame head.
                return;
            } else {
                // Not a protocol header (attached mid-stream): proceed to framing.
                if inbound {
                    self.saw_inbound_header = true
                } else {
                    self.saw_outbound_header = true
                }
            }
        }

        loop {
            let buf = if inbound {
                &self.inbound.buf
            } else {
                &self.outbound.buf
            };
            if !if inbound {
                self.inbound.skip == 0
            } else {
                self.outbound.skip == 0
            } {
                // A pending body skip from a frame larger than was buffered: drain
                // it against the new bytes before attempting to read a head.
                let drained = if inbound {
                    self.inbound.drain_skip()
                } else {
                    self.outbound.drain_skip()
                };
                if !drained {
                    return;
                }
                continue;
            }
            if buf.is_empty() {
                return;
            }
            match frame(buf) {
                Frame::Complete { record, total_len } => {
                    if let Some(m) = record {
                        self.records.push(L7Record {
                            protocol: Protocol::Amqp,
                            attributes: Vec::new(),
                            operation: m.operation,
                            status_code: m.status_code,
                            error: m.error,
                            start_unix_nano: ts,
                            duration_nano: 0,
                        });
                    }
                    if inbound {
                        self.inbound.advance(total_len);
                    } else {
                        self.outbound.advance(total_len);
                    }
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }
}

impl L7Parser for AmqpParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.inbound.buf.extend_from_slice(bytes);
        self.drain(true, ts);
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.outbound.buf.extend_from_slice(bytes);
        self.drain(false, ts);
    }

    fn take_records(&mut self) -> Vec<L7Record> {
        std::mem::take(&mut self.records)
    }

    fn is_dead(&self) -> bool {
        self.dead
    }
}

/// Recognise AMQP 0-9-1 from a connection's inbound prefix via a POSITIVE
/// signature and return a fresh boxed parser, or `None` if it isn't (yet)
/// recognisable. Phase 4 wires this into `super::conn::detect`.
///
/// Two positive signatures:
/// 1. **Protocol header** — `"AMQP" 0x00 0x00 0x09 0x01`. Unambiguous; nothing
///    else opens a stream with those 8 bytes. The strong signal.
/// 2. **Method frame** — a `type=1` frame whose channel is plausible, whose size
///    is sane, whose class id is one we know, AND whose `0xCE` frame-end sits at
///    the computed offset. The frame-end-at-offset check is what makes this safe:
///    a random binary stream won't coincidentally place `0xCE` exactly there with
///    a known class id in front of it.
///
/// Conservative by construction: a binary protocol with no port hint must not
/// false-positive on other traffic, so signature 2 demands a *known* class id and
/// a verified frame-end before claiming the connection; when unsure, we return
/// `None` and let detection wait for more bytes or fall through to another parser.
pub(crate) fn detect_amqp(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    // Signature 1: the protocol header (whole, or a proper prefix still arriving).
    if inbound.len() >= PROTOCOL_HEADER.len() {
        if inbound[..PROTOCOL_HEADER.len()] == PROTOCOL_HEADER {
            return Some(Box::new(AmqpParser::new()));
        }
    } else if !inbound.is_empty() && PROTOCOL_HEADER.starts_with(inbound) {
        // A partial header (e.g. just "AMQP") — not yet decidable, so don't claim
        // it, but it also isn't a method frame; return None so detection waits.
        return None;
    }

    // Signature 2: a well-formed, known-class METHOD frame with a verified
    // frame-end at the computed offset.
    if looks_like_method_frame(inbound) {
        return Some(Box::new(AmqpParser::new()));
    }

    None
}

/// True iff `buf` begins a METHOD frame (type 1) with a sane size, a known class
/// id, and the mandatory `0xCE` frame-end at the computed offset. The combination
/// — a known class id behind a correctly-placed frame-end — is the conservative
/// signature that won't fire on arbitrary binary. Returns false while the frame is
/// still partial (caller waits), never a guess.
fn looks_like_method_frame(buf: &[u8]) -> bool {
    // Need at least the header + the class/method id pair to inspect the class.
    if buf.len() < FRAME_HEADER_LEN + 4 {
        return false;
    }
    if buf[0] != FRAME_METHOD {
        return false;
    }
    let size = be_u32(&buf[3..7]) as usize;
    // A method frame's payload holds at least the 4-byte class/method ids.
    if !(4..=MAX_FRAME_SIZE).contains(&size) {
        return false;
    }
    let total_len = FRAME_HEADER_LEN + size + 1;
    if buf.len() < total_len {
        // The whole frame hasn't arrived; we can't verify the frame-end yet, so we
        // can't safely claim it. Detection waits for more bytes.
        return false;
    }
    if buf[total_len - 1] != FRAME_END {
        return false;
    }
    let class_id = be_u16(&buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 2]);
    KNOWN_CLASSES.contains(&class_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a METHOD frame: `[1][channel:2][size:4][class:2][method:2][args][0xCE]`.
    fn method_frame(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&class_id.to_be_bytes());
        payload.extend_from_slice(&method_id.to_be_bytes());
        payload.extend_from_slice(args);
        let mut v = vec![FRAME_METHOD];
        v.extend_from_slice(&channel.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(&payload);
        v.push(FRAME_END);
        v
    }

    /// Build a non-method frame (HEADER/BODY/HEARTBEAT) with an opaque payload.
    fn other_frame(frame_type: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![frame_type];
        v.extend_from_slice(&channel.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v.push(FRAME_END);
        v
    }

    /// A Connection.Close / Channel.Close frame carrying a reply-code first arg.
    fn close_frame(class_id: u16, method_id: u16, reply_code: u16) -> Vec<u8> {
        let mut args = reply_code.to_be_bytes().to_vec();
        // A short reply-text shortstr + class/method id, as a real Close carries —
        // we don't decode it, but include it so the frame is realistic.
        args.push(4);
        args.extend_from_slice(b"boom");
        args.extend_from_slice(&0u16.to_be_bytes()); // failing class
        args.extend_from_slice(&0u16.to_be_bytes()); // failing method
        method_frame(0, class_id, method_id, &args)
    }

    #[test]
    fn detects_protocol_header() {
        assert!(detect_amqp(&PROTOCOL_HEADER).is_some());
        // Header followed by the first frame still detects.
        let mut buf = PROTOCOL_HEADER.to_vec();
        buf.extend(method_frame(0, 10, 11, b"")); // Connection.StartOk
        assert!(detect_amqp(&buf).is_some());
    }

    #[test]
    fn detects_bare_method_frame_with_known_class_and_frame_end() {
        // A client that attached mid-session: first bytes are a method frame.
        let frame = method_frame(1, 60, 40, b"some-publish-args"); // Basic.Publish
        assert!(detect_amqp(&frame).is_some());
    }

    #[test]
    fn detection_is_conservative_about_non_amqp_binary() {
        // HTTP, TLS ClientHello, random binary, an unknown class id, and a method
        // frame with the frame-end octet wrong must all NOT detect as AMQP.
        assert!(detect_amqp(b"GET /x HTTP/1.1\r\n").is_none());
        assert!(detect_amqp(b"\x16\x03\x01\x02\x00\x01\x00").is_none());
        assert!(detect_amqp(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09").is_none());
        // type=1, sane size, but class id 999 is unknown.
        assert!(detect_amqp(&method_frame(0, 999, 10, b"xx")).is_none());
        // type=1, known class, but the trailing octet isn't 0xCE.
        let mut bad = method_frame(0, 60, 40, b"args");
        let last = bad.len() - 1;
        bad[last] = 0x00;
        assert!(detect_amqp(&bad).is_none());
    }

    #[test]
    fn partial_protocol_header_does_not_detect_yet() {
        // "AMQP" alone is a proper prefix — not yet decidable.
        assert!(detect_amqp(b"AMQP").is_none());
        assert!(detect_amqp(b"AM").is_none());
    }

    #[test]
    fn one_method_frame_yields_one_record_with_class_dot_method() {
        let mut p = AmqpParser::new();
        let mut stream = PROTOCOL_HEADER.to_vec();
        stream.extend(method_frame(1, 60, 40, b"exchange/routing-key/etc"));
        p.on_inbound(&stream, 1_000);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Basic.Publish");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 0); // async: no pairing latency
    }

    #[test]
    fn all_named_methods_label_correctly() {
        let cases: &[(u16, u16, &str)] = &[
            (10, 10, "Connection.Start"),
            (10, 11, "Connection.StartOk"),
            (10, 40, "Connection.Open"),
            (10, 50, "Connection.Close"),
            (10, 51, "Connection.CloseOk"),
            (20, 10, "Channel.Open"),
            (20, 40, "Channel.Close"),
            (40, 10, "Exchange.Declare"),
            (50, 10, "Queue.Declare"),
            (50, 20, "Queue.Bind"),
            (60, 10, "Basic.Qos"),
            (60, 20, "Basic.Consume"),
            (60, 40, "Basic.Publish"),
            (60, 60, "Basic.Deliver"),
            (60, 70, "Basic.Get"),
            (60, 80, "Basic.Ack"),
            (60, 90, "Basic.Reject"),
            (60, 120, "Basic.Nack"),
            (90, 10, "Tx.Select"),
            (90, 20, "Tx.Commit"),
        ];
        for &(class_id, method_id, expected) in cases {
            // Use enough args that a Close's reply-code slot exists but is < 300.
            let args = 200u16.to_be_bytes();
            let frame = method_frame(0, class_id, method_id, &args);
            let mut p = AmqpParser::new();
            p.on_inbound(&PROTOCOL_HEADER, 0);
            p.on_inbound(&frame, 1);
            let recs = p.take_records();
            assert_eq!(recs.len(), 1, "{expected} should emit one record");
            assert_eq!(recs[0].operation, expected);
            assert!(!recs[0].error, "{expected} with code 200 is not an error");
        }
    }

    #[test]
    fn unknown_ids_degrade_to_numeric_label_not_dropped() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // Known class (Basic=60) with an unmodelled method id.
        p.on_inbound(&method_frame(0, 60, 200, b"xx"), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Basic.Method200");
    }

    #[test]
    fn connection_close_with_error_reply_code_sets_error_verdict() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // 403 ACCESS_REFUSED on a Connection.Close.
        p.on_inbound(&close_frame(10, 50, 403), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Connection.Close");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 403);
    }

    #[test]
    fn channel_close_with_error_reply_code_sets_error_verdict() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // 404 NOT_FOUND on a Channel.Close.
        p.on_inbound(&close_frame(20, 40, 404), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Channel.Close");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 404);
    }

    #[test]
    fn close_with_success_reply_code_is_not_an_error() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // 200 REPLY_SUCCESS on a clean Connection.Close.
        p.on_inbound(&close_frame(10, 50, 200), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Connection.Close");
        assert!(!recs[0].error);
        assert_eq!(recs[0].status_code, 0);
    }

    #[test]
    fn header_body_heartbeat_frames_produce_no_records() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // A real publish flow: METHOD (Basic.Publish), then HEADER, then BODY, then
        // a HEARTBEAT keepalive. Only the METHOD frame produces a record.
        let mut stream = Vec::new();
        stream.extend(method_frame(1, 60, 40, b"pub"));
        stream.extend(other_frame(
            FRAME_HEADER,
            1,
            b"\x00\x3c\x00\x00content-props",
        ));
        stream.extend(other_frame(FRAME_BODY, 1, b"the message body bytes"));
        stream.extend(other_frame(FRAME_HEARTBEAT, 0, b"")); // size 0
        p.on_inbound(&stream, 10);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "only the METHOD frame yields a record");
        assert_eq!(recs[0].operation, "Basic.Publish");
    }

    #[test]
    fn pipelined_method_frames_each_yield_a_record_in_order() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // Three method frames back-to-back in one segment.
        let mut stream = Vec::new();
        stream.extend(method_frame(1, 50, 10, b"q")); // Queue.Declare
        stream.extend(method_frame(1, 50, 20, b"b")); // Queue.Bind
        stream.extend(method_frame(1, 60, 20, b"c")); // Basic.Consume
        p.on_inbound(&stream, 100);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "Queue.Declare");
        assert_eq!(recs[1].operation, "Queue.Bind");
        assert_eq!(recs[2].operation, "Basic.Consume");
    }

    #[test]
    fn method_frames_on_both_directions_are_each_emitted() {
        // AMQP is async: a publish goes out, a deliver comes back, independently.
        let mut p = AmqpParser::new();
        // Inbound carries the protocol header + a Basic.Publish.
        let mut req = PROTOCOL_HEADER.to_vec();
        req.extend(method_frame(1, 60, 40, b"pub"));
        p.on_inbound(&req, 1);
        // Outbound carries a Basic.Deliver (no header on this side).
        p.on_outbound(&method_frame(1, 60, 60, b"del"), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "Basic.Publish");
        assert_eq!(recs[0].start_unix_nano, 1);
        assert_eq!(recs[1].operation, "Basic.Deliver");
        assert_eq!(recs[1].start_unix_nano, 2);
    }

    #[test]
    fn outbound_frame_before_inbound_header_does_not_kill_the_header() {
        // Capture can deliver the server's first frame (outbound Connection.Start)
        // before the client's inbound protocol header is processed. The header-strip
        // state is per-direction, so a header arriving on inbound after an outbound
        // frame must still be stripped — not mis-framed as a method frame and killed.
        let mut p = AmqpParser::new();
        // Server speaks an outbound Connection.Start first.
        p.on_outbound(&method_frame(0, 10, 10, b"server-props"), 1);
        // Then the client's inbound protocol header + a method frame arrive.
        let mut req = PROTOCOL_HEADER.to_vec();
        req.extend(method_frame(0, 10, 11, b"client-props")); // Connection.StartOk
        p.on_inbound(&req, 2);
        assert!(
            !p.is_dead(),
            "inbound protocol header must not desync the parser"
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "Connection.Start");
        assert_eq!(recs[1].operation, "Connection.StartOk");
    }

    #[test]
    fn fragmented_frame_waits_instead_of_misparsing() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let frame = method_frame(1, 60, 40, b"a-decently-long-publish-arg-blob");
        // Feed the header + class/method ids but stop before the frame-end.
        let split = FRAME_HEADER_LEN + 6;
        p.on_inbound(&frame[..split], 1);
        assert!(p.take_records().is_empty(), "partial frame must not emit");
        assert!(!p.is_dead(), "partial is not garbage");
        // The remainder arrives — now the frame completes.
        p.on_inbound(&frame[split..], 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Basic.Publish");
        // Stamped at the segment that completed the frame.
        assert_eq!(recs[0].start_unix_nano, 2);
    }

    #[test]
    fn protocol_header_split_across_segments_reassembles() {
        let mut p = AmqpParser::new();
        // The 8-byte header arrives in three dribbles, then a method frame.
        p.on_inbound(&PROTOCOL_HEADER[..3], 0);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_inbound(&PROTOCOL_HEADER[3..6], 1);
        assert!(p.take_records().is_empty());
        p.on_inbound(&PROTOCOL_HEADER[6..], 2);
        p.on_inbound(&method_frame(0, 10, 10, b"server-props"), 3); // Connection.Start
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Connection.Start");
    }

    #[test]
    fn frame_larger_than_buffer_skips_the_straddling_body() {
        // A large BODY frame whose payload spans several segments: the parser must
        // frame past it (DirBuf skip) and resume at the next frame head, not lose
        // sync. Followed by a method frame to prove resync.
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let big = other_frame(FRAME_BODY, 1, &[0x42u8; 50]);
        // Feed only the first 20 bytes; the rest of the body straddles.
        p.on_inbound(&big[..20], 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // Rest of the big frame, then a Basic.Ack.
        p.on_inbound(&big[20..], 2);
        p.on_inbound(&method_frame(1, 60, 80, b"ack"), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Basic.Ack");
    }

    #[test]
    fn missing_frame_end_marks_the_parser_dead() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let mut frame = method_frame(1, 60, 40, b"args");
        let last = frame.len() - 1;
        frame[last] = 0x00; // not 0xCE -> desync
        p.on_inbound(&frame, 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn oversized_frame_marks_the_parser_dead() {
        let mut p = AmqpParser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // A frame head claiming a payload far beyond MAX_FRAME_SIZE.
        let mut buf = vec![FRAME_METHOD, 0x00, 0x01];
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        p.on_inbound(&buf, 1);
        assert!(p.is_dead());
    }

    #[test]
    fn byte_at_a_time_delivery_yields_one_record() {
        let mut p = AmqpParser::new();
        let mut stream = PROTOCOL_HEADER.to_vec();
        stream.extend(method_frame(1, 60, 40, b"basic-publish-args-here"));
        for (i, byte) in stream.iter().enumerate() {
            p.on_inbound(std::slice::from_ref(byte), i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "Basic.Publish");
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: hostile/truncated payloads fed at every byte boundary, both
        // directions, both orders. The hard requirement is no panic, ever.
        let payloads: &[&[u8]] = &[
            &PROTOCOL_HEADER,
            b"AMQP\x00\x00\x09\x01\x01\x00\x00", // header + partial frame
            b"\x01\x00\x00\xff\xff\xff\xff",     // method type, ~4G size
            b"\x01\x00\x00\x00\x00\x00\x04\x00\x3c\x00\x28\xce", // valid Basic.Publish, no args
            b"\x01\x00\x00\x00\x00\x00\x02\x00\x3c\xce", // payload too short for id pair
            b"\x08\x00\x00\x00\x00\x00\x00\xce", // heartbeat (size 0)
            b"\x02\x00\x01\x00\x00\x00\x00\xce", // header frame, empty payload
            b"\xff\xff\xff\xff\xff\xff\xff\xff", // garbage type/size
            b"\x01\x00\x00\x00\x00\x00\x04\x03\xe7\x00\x0a\xce", // unknown class 999
            b"\x01\x00\x00\x00\x00\x00\x04\x00\x0a\x00\x32\x01\x48", // Close, code 328, wrong end
            &[0xCE; 64],                         // a wall of frame-end octets
            &[0x01; 256],                        // many method-type bytes, no end
            b"",                                 // empty
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // Inbound, in two segments.
                let mut p = AmqpParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();
                // Outbound, in two segments.
                let mut q = AmqpParser::new();
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
                // Detection must never panic either.
                let _ = detect_amqp(a);
                let _ = detect_amqp(payload);
                // Byte-at-a-time, alternating directions.
                let mut r = AmqpParser::new();
                for (i, byte) in payload.iter().enumerate() {
                    let one = std::slice::from_ref(byte);
                    if i % 2 == 0 {
                        r.on_inbound(one, i as i64);
                    } else {
                        r.on_outbound(one, i as i64);
                    }
                }
                let _ = r.take_records();
            }
        }
    }
}
