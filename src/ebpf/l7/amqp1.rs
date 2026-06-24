//! AMQP 1.0 (OASIS) wire parser — implements [`super::L7Parser`], the zero-code
//! APM producer for AMQP 1.0 connections.
//!
//! This is the OASIS AMQP **1.0** protocol, a different wire format from the
//! AMQP **0-9-1** RabbitMQ dialect handled by [`super::amqp`]. They share TCP port
//! 5672 and the `"AMQP"` magic, and are told apart only by the protocol-header
//! version quad (0-9-1 = `00 00 09 01`, this 1.0 = `00 01 00 00`).
//!
//! ## What AMQP 1.0 is, for span purposes
//!
//! Like 0-9-1, AMQP 1.0 is **asynchronous**, not request/response. A connection
//! opens with an 8-byte protocol header, then performative frames flow both ways
//! independently — `open`/`begin`/`attach` set the session up, `transfer` carries
//! a message (a send or a delivery), `disposition` settles it, `detach`/`end`/
//! `close` tear it down. There is no per-request reply to pair, so — as in the
//! 0-9-1 parser — we emit one [`L7Record`] **per performative frame**, on whichever
//! direction it arrives, labelled by the performative name (`OPEN`/`TRANSFER`/…).
//! `duration_nano` is 0 (a frame is observed in one moment); `start_unix_nano` is
//! the frame's arrival time.
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! A frame is `[size:u32 BE][DOFF:1][type:1][channel:2 BE][extended-header]
//! [body]`. `size` counts the whole frame including these 8 header bytes, so
//! `total_len = size`. `DOFF` ("data offset") is the body offset in 4-byte words,
//! so the body begins at `DOFF * 4` and any bytes between byte 8 and there are an
//! extended header we skip. `type` is `0x00` for an AMQP frame, `0x01` for a SASL
//! frame. An empty frame (`size == 8`) is a heartbeat — framed past, no record.
//!
//! ## What we extract (and only this)
//!
//! The frame body is a "performative": a *described type* = a descriptor + a list.
//! The descriptor is a small ulong naming the performative (`open=0x10`,
//! `transfer=0x14`, `close=0x18`, …). AMQP 1.0's full type system (described
//! types, lists, maps, every primitive width) is intentionally **not** decoded —
//! we read only the descriptor code to name the operation, and, for the three
//! teardown performatives that carry an `error{}` field, a bounded scan for a
//! non-null error described type. That descriptor read is the v1 win; the rest of
//! the type system would betray the leanness moat for no span value.
//!
//! - `operation`: the performative name (`OPEN`, `BEGIN`, `ATTACH`, `TRANSFER`,
//!   `DISPOSITION`, `DETACH`, `END`, `CLOSE`). SASL frames label `SASL`. Unknown
//!   descriptor codes degrade to `PERFORMATIVE_<code>` rather than dropping the
//!   frame — the verb is still a useful span label.
//! - `error` / `status_code`: a `close`/`end`/`detach` whose body carries a
//!   non-null `error{}` (descriptor code `0x1d`) is the protocol's failure
//!   verdict — `error = true`, `status_code = 1`. Everything else is `error =
//!   false`, `status_code = 0`. We decode no condition symbol text.

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// The 8-byte frame header: `size:4 + DOFF:1 + type:1 + channel:2`.
const FRAME_HEADER_LEN: usize = 8;

/// Frame `type` octets. `0x00` is an AMQP frame (carries a performative); `0x01`
/// is a SASL frame (carries a SASL performative). Other types are framed past.
const FRAME_TYPE_AMQP: u8 = 0x00;
const FRAME_TYPE_SASL: u8 = 0x01;

/// Sanity bound on a single frame. AMQP 1.0's negotiated `max-frame-size` has a
/// floor of 512 and is typically tens of KiB to a few MiB; beyond a generous cap
/// an "AMQP" stream is mis-detected or desynced, so we bail rather than buffer
/// unboundedly on hostile bytes.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Performative descriptor codes (the small-ulong value after the `0x00` described-
/// type constructor). These name the frame's operation.
const PERF_OPEN: u64 = 0x10;
const PERF_BEGIN: u64 = 0x11;
const PERF_ATTACH: u64 = 0x12;
const PERF_FLOW: u64 = 0x13;
const PERF_TRANSFER: u64 = 0x14;
const PERF_DISPOSITION: u64 = 0x15;
const PERF_DETACH: u64 = 0x16;
const PERF_END: u64 = 0x17;
const PERF_CLOSE: u64 = 0x18;

/// The descriptor code of the `error{}` described type. Its presence (non-null)
/// inside a teardown performative is the protocol's failure verdict.
const DESCRIPTOR_ERROR: u64 = 0x1d;

/// The 8-byte protocol header an AMQP 1.0 connection opens with: `"AMQP"` then the
/// version quad `protocol-id=0, major=1, minor=0, revision=0`. The protocol-id 0
/// distinguishes it from a SASL (id 1) or TLS (id 2) header, and the version quad
/// distinguishes 1.0 from the 0-9-1 dialect (`00 00 09 01`). Unambiguous magic.
const PROTOCOL_HEADER: [u8; 8] = [b'A', b'M', b'Q', b'P', 0x00, 0x01, 0x00, 0x00];

/// The SASL-layer protocol header (`protocol-id=3`). A 1.0 connection that
/// negotiates SASL opens with this header *before* the AMQP one. We recognise it
/// as the same connection family so SASL setup doesn't desync detection.
const SASL_HEADER: [u8; 8] = [b'A', b'M', b'Q', b'P', 0x03, 0x01, 0x00, 0x00];

/// Read a big-endian u32 from the first four bytes of `b` (caller guarantees len).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// True iff `header` is one of the AMQP 1.0 protocol headers (AMQP or SASL layer).
/// Both share the `"AMQP"` magic and the `01 00 00` version tail; they differ only
/// in the protocol-id byte (0 = AMQP, 3 = SASL).
fn is_protocol_header(header: &[u8]) -> bool {
    header == PROTOCOL_HEADER || header == SASL_HEADER
}

/// True iff `prefix` (shorter than 8 bytes) is a proper prefix of either protocol
/// header — i.e. a header still arriving across segments. Lets the drainer wait
/// instead of trying to frame `"AMQP"` as a frame head.
fn is_partial_protocol_header(prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && prefix.len() < FRAME_HEADER_LEN
        && (PROTOCOL_HEADER.starts_with(prefix) || SASL_HEADER.starts_with(prefix))
}

/// The human label for a performative descriptor code. Falls back to
/// `PERFORMATIVE_<code>` for codes we don't name so an unrecognised-but-well-framed
/// performative still yields a useful span verb.
fn performative_name(code: u64) -> String {
    let name = match code {
        PERF_OPEN => "OPEN",
        PERF_BEGIN => "BEGIN",
        PERF_ATTACH => "ATTACH",
        PERF_FLOW => "FLOW",
        PERF_TRANSFER => "TRANSFER",
        PERF_DISPOSITION => "DISPOSITION",
        PERF_DETACH => "DETACH",
        PERF_END => "END",
        PERF_CLOSE => "CLOSE",
        _ => return format!("PERFORMATIVE_{code}"),
    };
    name.to_string()
}

/// True for the three teardown performatives that can carry an `error{}` field:
/// `close` (0x18), `end` (0x17), `detach` (0x16).
fn carries_error_field(code: u64) -> bool {
    matches!(code, PERF_CLOSE | PERF_END | PERF_DETACH)
}

/// Read an AMQP 1.0 *ulong* descriptor value at the front of `body`, returning the
/// code and the number of bytes it occupied. Only the encodings a performative (or
/// nested error) descriptor actually uses are decoded:
///   * `0x44` ulong0 — the value 0, no following bytes;
///   * `0x53 <u8>` smallulong — a one-byte value (the common case);
///   * `0x80 <8 bytes BE>` ulong — a full 8-byte value (rare, but legal).
///
/// Any other constructor is not a ulong descriptor we model → `None`.
fn read_ulong(body: &[u8]) -> Option<(u64, usize)> {
    match body.first()? {
        0x44 => Some((0, 1)),
        0x53 => body.get(1).map(|&v| (v as u64, 2)),
        0x80 => {
            let bytes = body.get(1..9)?;
            let mut be = [0u8; 8];
            be.copy_from_slice(bytes);
            Some((u64::from_be_bytes(be), 9))
        }
        _ => None,
    }
}

/// Read the performative descriptor code from a frame body. A performative is a
/// described type: `0x00` (described-type constructor) then the descriptor (a
/// ulong) then the described list. We read only the descriptor code. Returns
/// `None` if the body isn't a `0x00`-led described type with a ulong descriptor —
/// e.g. an empty body, or a constructor we don't model.
fn read_performative_code(body: &[u8]) -> Option<u64> {
    if body.first()? != &0x00 {
        return None;
    }
    read_ulong(&body[1..]).map(|(code, _)| code)
}

/// The list-value constructors a described type's value can use: `list0` (`0x45`,
/// the empty list), `list8` (`0xc0`) and `list32` (`0xd0`). The `error{}` described
/// type is `amqp:error:list` — its value is *always* one of these.
const LIST_CONSTRUCTORS: [u8; 3] = [0x45, 0xc0, 0xd0];

/// The failure verdict for a teardown performative body. `close`/`end`/`detach`
/// carry an optional `error{}` (descriptor code `0x1d`) inside their described
/// list; an error is signalled by the *presence* of a non-null error described
/// type. We scan the body bytes for the `0x00`-led error descriptor rather than
/// fully decoding the list — a non-null error is `0x00`, a ulong descriptor equal
/// to `0x1d`, then the error's `list`-typed value. A bounded scan keeps a hostile
/// body from spinning.
///
/// This deliberately does not parse list layout: a list whose `error` slot is null
/// encodes that slot as `0x40` (the null primitive), which carries no error
/// descriptor, so a null error isn't found.
///
/// The descriptor code alone (`0x00 …1d`) is *not* sufficient — `detach` carries a
/// `handle` (a `uint`) and `closed` (a `boolean`) *before* its `error` slot, and a
/// handle whose four big-endian octets happen to be `00 53 1d xx` would otherwise
/// be mis-read as an error descriptor, falsely flagging a clean detach. So we
/// additionally require the byte *after* the descriptor to be a `list` constructor:
/// `amqp:error:list` is a list-valued described type, so a genuine error descriptor
/// is always followed by `0x45`/`0xc0`/`0xd0`. That guard turns a byte coincidence
/// into a structural match without decoding the surrounding list.
fn has_error_descriptor(body: &[u8]) -> bool {
    // Walk every position where a described type could begin (`0x00`), and check
    // whether its descriptor is the error code followed by a list value. Bounded by
    // the body length; we read at most a few bytes per candidate, so this is linear
    // and panic-free.
    let mut i = 0;
    while i + 1 < body.len() {
        if body[i] == 0x00
            && let Some((code, used)) = read_ulong(&body[i + 1..])
            && code == DESCRIPTOR_ERROR
            && let Some(&value_ctor) = body.get(i + 1 + used)
            && LIST_CONSTRUCTORS.contains(&value_ctor)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// The span-relevant fields decoded from one performative frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Performative {
    operation: String,
    error: bool,
    status_code: u16,
}

/// Outcome of framing one AMQP 1.0 frame off a direction-buffer prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    /// A complete, well-formed frame. `record` is `Some` only for frames that carry
    /// a performative (the ones that produce a span); a heartbeat (empty body)
    /// yields `None`.
    Complete {
        record: Option<Performative>,
        total_len: usize,
    },
    /// A valid prefix but the whole frame isn't buffered yet — wait for more bytes.
    Partial,
    /// Not AMQP 1.0 framing — an insane size or a DOFF that runs past the frame
    /// means desync/garbage; drop the connection.
    Invalid,
}

/// Frame one AMQP 1.0 frame at the front of `buf`. Validates the size bound and
/// the data-offset (DOFF), then reads the performative descriptor from the body.
fn frame(buf: &[u8]) -> Frame {
    if buf.len() < FRAME_HEADER_LEN {
        return Frame::Partial;
    }
    let size = be_u32(&buf[0..4]) as usize;
    // `size` counts the whole frame including the 8-byte header; below that is
    // impossible framing, above the cap is a desync/hostile claim.
    if !(FRAME_HEADER_LEN..=MAX_FRAME_SIZE).contains(&size) {
        return Frame::Invalid;
    }
    if buf.len() < size {
        return Frame::Partial;
    }
    let doff = buf[4] as usize;
    let frame_type = buf[5];
    let body_start = doff * 4;
    // DOFF must point at or past the fixed 8-byte header (so DOFF >= 2) and within
    // the frame — a body offset outside the frame is desync.
    if doff < 2 || body_start > size {
        return Frame::Invalid;
    }

    let body = &buf[body_start..size];
    let record = match frame_type {
        FRAME_TYPE_AMQP => decode_performative(body),
        // SASL frames carry SASL performatives (mechanisms/init/challenge/response/
        // outcome). We don't enumerate their codes — a single `SASL` label is the
        // useful span verb for the auth handshake. An empty SASL body (shouldn't
        // happen) degrades to no record.
        FRAME_TYPE_SASL if read_performative_code(body).is_some() => Some(Performative {
            operation: "SASL".to_string(),
            error: false,
            status_code: 0,
        }),
        // An empty body is a heartbeat (AMQP frame, size == 8) or an unmodelled
        // empty frame — framed past, no record. Any other type with a well-formed
        // size is tolerated as a skipped frame rather than killing the connection.
        _ => None,
    };
    Frame::Complete {
        record,
        total_len: size,
    }
}

/// Decode an AMQP frame body into its performative span fields, or `None` if the
/// body is empty / not a described-type performative (e.g. a heartbeat).
fn decode_performative(body: &[u8]) -> Option<Performative> {
    let code = read_performative_code(body)?;
    let error = carries_error_field(code) && has_error_descriptor(body);
    Some(Performative {
        operation: performative_name(code),
        error,
        status_code: if error { 1 } else { 0 },
    })
}

/// AMQP 1.0 [`L7Parser`]: frames both directions, emits one record per performative
/// frame (AMQP is async — no request/response pairing), and frames past heartbeats.
/// The leading protocol header(s) on either direction are stripped first. A bad
/// size/DOFF marks it dead.
#[derive(Debug, Default)]
pub(crate) struct Amqp1Parser {
    inbound: DirBuf,
    outbound: DirBuf,
    /// Per-direction: how many leading protocol headers have been resolved. A 1.0
    /// connection can open with up to two 8-byte headers back-to-back (a SASL
    /// header, then the AMQP header after the SASL handshake), so we strip each one
    /// as it appears at the front rather than assuming exactly one. State is
    /// per-direction because capture ordering can deliver an outbound frame before
    /// the inbound header — a shared flag would let that suppress the real header
    /// strip and desync the stream (the 0-9-1 parser has the same hazard).
    saw_inbound_header: bool,
    saw_outbound_header: bool,
    records: Vec<L7Record>,
    dead: bool,
}

impl Amqp1Parser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Strip any leading protocol header(s) on `dir`'s buffer. Returns `false` if a
    /// partial header is still arriving (caller must wait), `true` once the front of
    /// the buffer is positioned at a frame (or is empty). A SASL header followed by
    /// the AMQP header (two stacked headers at connection open) are both stripped.
    fn strip_headers(&mut self, inbound: bool) -> bool {
        let saw = if inbound {
            self.saw_inbound_header
        } else {
            self.saw_outbound_header
        };
        if saw {
            return true;
        }
        loop {
            let buf = if inbound {
                &self.inbound.buf
            } else {
                &self.outbound.buf
            };
            if buf.len() >= FRAME_HEADER_LEN {
                if is_protocol_header(&buf[..FRAME_HEADER_LEN]) {
                    let b = if inbound {
                        &mut self.inbound
                    } else {
                        &mut self.outbound
                    };
                    b.advance(FRAME_HEADER_LEN);
                    // Another header may follow (SASL then AMQP); loop to strip it.
                    continue;
                }
                // Front is a frame, not a header — header phase is over.
                break;
            } else if is_partial_protocol_header(buf) {
                // A proper prefix of a header is still arriving — wait.
                return false;
            } else {
                // Fewer than 8 bytes and not a header prefix: either a (short) frame
                // head still arriving, or mid-stream attach. Let framing decide.
                break;
            }
        }
        if inbound {
            self.saw_inbound_header = true;
        } else {
            self.saw_outbound_header = true;
        }
        true
    }

    /// Drain as many complete frames as `dir` holds, emitting a record per
    /// performative frame. Stops on a partial (waits) or invalid (dies).
    fn drain(&mut self, inbound: bool, ts: i64) {
        if !self.strip_headers(inbound) {
            return;
        }
        loop {
            // Drain any pending oversized-body skip against the new bytes first.
            let drained = if inbound {
                self.inbound.drain_skip()
            } else {
                self.outbound.drain_skip()
            };
            if !drained {
                return;
            }
            let buf = if inbound {
                &self.inbound.buf
            } else {
                &self.outbound.buf
            };
            if buf.is_empty() {
                return;
            }
            match frame(buf) {
                Frame::Complete { record, total_len } => {
                    if let Some(p) = record {
                        self.records.push(L7Record {
                            // The L7Record protocol tag has a single AMQP family
                            // variant; 1.0 records carry it (the 0-9-1 parser does
                            // too). Detection still separates the two dialects.
                            protocol: Protocol::Amqp,
                            attributes: Vec::new(),
                            operation: p.operation,
                            status_code: p.status_code,
                            error: p.error,
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

impl L7Parser for Amqp1Parser {
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

/// Construct an AMQP 1.0 parser unconditionally — for the port-hint path (port 5672
/// names AMQP) where byte detection is bypassed. The shared 5672 port between 1.0
/// and 0-9-1 means a port hint alone can't pick the dialect; this is the 1.0 binder
/// for callers that have already decided on 1.0.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(Amqp1Parser::new())
}

/// Recognise AMQP 1.0 from a connection's inbound prefix via a POSITIVE signature
/// and return a fresh boxed parser, or `None` if it isn't (yet) recognisable.
///
/// Two positive signatures, both deliberately CONSERVATIVE — a binary protocol with
/// no port hint must not false-positive on other traffic, and AMQP 1.0 shares port
/// 5672 + the `"AMQP"` magic with 0-9-1, so the version quad is load-bearing:
///
/// 1. **Protocol header** — `"AMQP" 0x00 0x01 0x00 0x00` (the AMQP layer) or the
///    SASL-layer header `… 0x03 0x01 0x00 0x00`. The `0x01 0x00 0x00` version tail
///    is what tells 1.0 apart from 0-9-1's `0x00 0x09 0x01`; nothing else opens a
///    stream with these 8 bytes. The strong signal. A proper prefix still arriving
///    returns `None` so detection waits rather than guessing.
/// 2. **Performative frame** — a `type=0x00` AMQP frame whose `size` is sane, whose
///    `DOFF` is in range, AND whose body is a `0x00`-led described type with a
///    *known* performative descriptor code. The combination — a known performative
///    behind a structurally valid frame header — is what suppresses collisions on
///    arbitrary binary. A mid-stream attach (first bytes are a frame, not the
///    header) is recognised this way.
pub(crate) fn detect_amqp1(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    // Signature 1: a protocol header (whole, or a proper prefix still arriving).
    if inbound.len() >= FRAME_HEADER_LEN {
        if is_protocol_header(&inbound[..FRAME_HEADER_LEN]) {
            return Some(Box::new(Amqp1Parser::new()));
        }
    } else if is_partial_protocol_header(inbound) {
        // A partial header (e.g. just "AMQP") — not yet decidable; wait.
        return None;
    }

    // Signature 2: a well-formed performative frame with a known descriptor code.
    if looks_like_performative_frame(inbound) {
        return Some(Box::new(Amqp1Parser::new()));
    }

    None
}

/// True iff `buf` begins a `type=0x00` AMQP 1.0 frame with a sane size, an in-range
/// DOFF, and a body that decodes to a *known* performative descriptor code. The
/// conjunction is the conservative signature that won't fire on arbitrary binary.
/// Returns false while the frame is still partial (caller waits), never a guess.
fn looks_like_performative_frame(buf: &[u8]) -> bool {
    if buf.len() < FRAME_HEADER_LEN {
        return false;
    }
    let size = be_u32(&buf[0..4]) as usize;
    if !(FRAME_HEADER_LEN..=MAX_FRAME_SIZE).contains(&size) {
        return false;
    }
    if buf.len() < size {
        // The whole frame hasn't arrived; we can't read the body yet, so we can't
        // safely claim it. Detection waits for more bytes.
        return false;
    }
    let doff = buf[4] as usize;
    let frame_type = buf[5];
    if frame_type != FRAME_TYPE_AMQP {
        return false;
    }
    let body_start = doff * 4;
    if doff < 2 || body_start > size {
        return false;
    }
    // The body must be a described-type performative whose descriptor is one of the
    // codes we model — a random binary stream won't place that exact shape here.
    match read_performative_code(&buf[body_start..size]) {
        Some(code) => is_known_performative(code),
        None => false,
    }
}

/// True for the nine performative descriptor codes the spec defines. Detection
/// demands a *known* code (not just any ulong) so an arbitrary `0x00 0x53 <byte>`
/// in a non-AMQP stream can't pass the signature.
fn is_known_performative(code: u64) -> bool {
    matches!(
        code,
        PERF_OPEN
            | PERF_BEGIN
            | PERF_ATTACH
            | PERF_FLOW
            | PERF_TRANSFER
            | PERF_DISPOSITION
            | PERF_DETACH
            | PERF_END
            | PERF_CLOSE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an AMQP 1.0 frame: `[size:4 BE][DOFF:1][type:1][channel:2 BE][body]`,
    /// with DOFF = 2 (body immediately after the 8-byte header). `size` counts the
    /// whole frame.
    fn frame_bytes(channel: u16, frame_type: u8, body: &[u8]) -> Vec<u8> {
        let size = (FRAME_HEADER_LEN + body.len()) as u32;
        let mut v = size.to_be_bytes().to_vec();
        v.push(2); // DOFF: body at byte 8
        v.push(frame_type);
        v.extend_from_slice(&channel.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A performative body: `0x00` described-type constructor, then a smallulong
    /// descriptor (`0x53 <code>`), then the described list bytes (`args`).
    fn performative_body(code: u8, args: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x53, code];
        v.extend_from_slice(args);
        v
    }

    /// A complete AMQP performative frame on the given channel.
    fn perf_frame(channel: u16, code: u8, args: &[u8]) -> Vec<u8> {
        frame_bytes(channel, FRAME_TYPE_AMQP, &performative_body(code, args))
    }

    /// A `close`/`end`/`detach` body whose error slot holds a non-null `error{}`
    /// described type (`0x00 0x53 0x1d` + an opaque list). The presence of the error
    /// descriptor is the failure verdict.
    fn perf_body_with_error(code: u8) -> Vec<u8> {
        // performative list opening (a list8 with some count) then a nested error
        // described type. We don't decode the list layout, so any plausible bytes
        // around the `0x00 0x53 0x1d` error descriptor exercise the scan.
        let mut args = vec![0xc0, 0x10, 0x01]; // list8, size, count (opaque to us)
        args.extend_from_slice(&[0x00, 0x53, 0x1d]); // error{} descriptor
        args.extend_from_slice(&[0xc0, 0x04, 0x01, 0xa3, 0x01, b'x']); // condition symbol-ish
        performative_body(code, &args)
    }

    fn err_frame(channel: u16, code: u8) -> Vec<u8> {
        frame_bytes(channel, FRAME_TYPE_AMQP, &perf_body_with_error(code))
    }

    #[test]
    fn detects_protocol_header() {
        assert!(detect_amqp1(&PROTOCOL_HEADER).is_some());
        // Header followed by the first frame still detects.
        let mut buf = PROTOCOL_HEADER.to_vec();
        buf.extend(perf_frame(0, PERF_OPEN as u8, b""));
        assert!(detect_amqp1(&buf).is_some());
        // The SASL-layer header is recognised too.
        assert!(detect_amqp1(&SASL_HEADER).is_some());
    }

    #[test]
    fn detects_bare_performative_frame_with_known_code() {
        // A client that attached mid-session: first bytes are an OPEN performative.
        assert!(detect_amqp1(&perf_frame(0, PERF_OPEN as u8, b"\x45")).is_some());
        // TRANSFER too.
        assert!(detect_amqp1(&perf_frame(0, PERF_TRANSFER as u8, b"\x45")).is_some());
    }

    #[test]
    fn detection_distinguishes_1_0_from_0_9_1_header() {
        // The 0-9-1 protocol header (`AMQP 00 00 09 01`) must NOT detect as 1.0 —
        // the version quad is the only thing telling them apart on shared port 5672.
        let amqp091 = [b'A', b'M', b'Q', b'P', 0x00, 0x00, 0x09, 0x01];
        assert!(detect_amqp1(&amqp091).is_none());
    }

    #[test]
    fn detection_is_conservative_about_non_amqp_binary() {
        // HTTP, TLS ClientHello, random binary, and an AMQP-shaped frame with an
        // unknown descriptor code must all NOT detect as AMQP 1.0.
        assert!(detect_amqp1(b"GET /x HTTP/1.1\r\n").is_none());
        assert!(detect_amqp1(b"\x16\x03\x01\x02\x00\x01\x00").is_none());
        assert!(detect_amqp1(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09").is_none());
        // type=0x00, sane size+DOFF, but descriptor code 0x99 is not a performative.
        assert!(detect_amqp1(&perf_frame(0, 0x99, b"")).is_none());
        // type=0x00 with a body that isn't a `0x00`-led described type.
        let not_described = frame_bytes(0, FRAME_TYPE_AMQP, b"\x53\x10");
        assert!(detect_amqp1(&not_described).is_none());
    }

    #[test]
    fn partial_protocol_header_does_not_detect_yet() {
        assert!(detect_amqp1(b"AMQP").is_none());
        assert!(detect_amqp1(b"AM").is_none());
    }

    #[test]
    fn new_parser_constructs_an_amqp1_parser() {
        // The port-hint binder constructs unconditionally and parses a 1.0 frame.
        let mut p = new_parser();
        p.on_inbound(&perf_frame(0, PERF_OPEN as u8, b""), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "OPEN");
        assert_eq!(recs[0].protocol, Protocol::Amqp);
    }

    #[test]
    fn one_performative_frame_yields_one_record() {
        let mut p = Amqp1Parser::new();
        let mut stream = PROTOCOL_HEADER.to_vec();
        stream.extend(perf_frame(0, PERF_TRANSFER as u8, b"some-transfer-args"));
        p.on_inbound(&stream, 1_000);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "TRANSFER");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 0); // async: no pairing latency
    }

    #[test]
    fn all_named_performatives_label_correctly() {
        let cases: &[(u64, &str)] = &[
            (PERF_OPEN, "OPEN"),
            (PERF_BEGIN, "BEGIN"),
            (PERF_ATTACH, "ATTACH"),
            (PERF_FLOW, "FLOW"),
            (PERF_TRANSFER, "TRANSFER"),
            (PERF_DISPOSITION, "DISPOSITION"),
            (PERF_DETACH, "DETACH"),
            (PERF_END, "END"),
            (PERF_CLOSE, "CLOSE"),
        ];
        for &(code, expected) in cases {
            let mut p = Amqp1Parser::new();
            p.on_inbound(&PROTOCOL_HEADER, 0);
            p.on_inbound(&perf_frame(0, code as u8, b"\x45"), 1);
            let recs = p.take_records();
            assert_eq!(recs.len(), 1, "{expected} should emit one record");
            assert_eq!(recs[0].operation, expected);
            assert!(
                !recs[0].error,
                "{expected} without an error field is not an error"
            );
        }
    }

    #[test]
    fn unknown_performative_code_degrades_to_numeric_label() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // A `0x00`-led described type with descriptor 0x42 — not a known performative
        // but still a frame we label numerically rather than dropping.
        p.on_inbound(&perf_frame(0, 0x42, b""), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PERFORMATIVE_66"); // 0x42 = 66
    }

    #[test]
    fn close_with_error_field_sets_error_verdict() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        p.on_inbound(&err_frame(0, PERF_CLOSE as u8), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CLOSE");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn end_and_detach_with_error_field_set_error_verdict() {
        for &(code, name) in &[(PERF_END, "END"), (PERF_DETACH, "DETACH")] {
            let mut p = Amqp1Parser::new();
            p.on_inbound(&PROTOCOL_HEADER, 0);
            p.on_inbound(&err_frame(0, code as u8), 5);
            let recs = p.take_records();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].operation, name);
            assert!(recs[0].error, "{name} with an error field is an error");
            assert_eq!(recs[0].status_code, 1);
        }
    }

    #[test]
    fn clean_close_with_null_error_is_not_an_error() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // close{} with a null error slot: list8 holding a single null primitive
        // (0x40). No error descriptor present → not an error.
        let body = performative_body(PERF_CLOSE as u8, &[0xc0, 0x02, 0x01, 0x40]);
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CLOSE");
        assert!(!recs[0].error);
        assert_eq!(recs[0].status_code, 0);
    }

    #[test]
    fn transfer_carrying_error_bytes_is_not_an_error() {
        // Only close/end/detach carry an error verdict. A TRANSFER whose opaque
        // message payload happens to contain `0x00 0x53 0x1d` must NOT be flagged —
        // the error scan is gated on the performative being a teardown method.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let body = performative_body(PERF_TRANSFER as u8, &[0x00, 0x53, 0x1d, 0xaa]);
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "TRANSFER");
        assert!(!recs[0].error, "TRANSFER never carries the error verdict");
    }

    #[test]
    fn clean_detach_whose_handle_bytes_collide_with_error_descriptor_is_not_an_error() {
        // BUG: `detach(handle, closed, error)` carries a `handle` (uint) and `closed`
        // (boolean) *before* its `error` slot. A clean detach with a NULL error whose
        // handle's four big-endian octets happen to be `00 53 1d xx` puts the byte
        // sequence `0x00 0x53 0x1d` into the body without any error being present. A
        // descriptor-code-only scan mis-reads it as an `error{}` and falsely flags the
        // detach. The verdict must be no-error: the only true error is a `0x1d`
        // descriptor whose value is a `list` constructor, which a uint field is not.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // detach list8: handle = uint(0x70) 0x00 0x53 0x1d 0x99, closed = false(0x42),
        // error = null(0x40). The handle's bytes collide with the error descriptor.
        let fields = [0x70, 0x00, 0x53, 0x1d, 0x99, 0x42, 0x40];
        let mut body = vec![
            0x00,
            0x53,
            PERF_DETACH as u8,
            0xc0,
            (fields.len() + 1) as u8,
            0x03,
        ];
        body.extend_from_slice(&fields);
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "DETACH");
        assert!(
            !recs[0].error,
            "a clean detach whose handle bytes alias the error descriptor is not an error"
        );
        assert_eq!(recs[0].status_code, 0);
    }

    #[test]
    fn error_with_empty_list0_value_still_sets_the_verdict() {
        // The strict scan requires the `0x1d` descriptor be followed by a list
        // constructor. The empty `list0` (0x45) is a valid error value — an `error{}`
        // with all fields defaulted — and must still register as the failure verdict.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // close{} list8 count1, error = error{} described type with a list0 value.
        let body = performative_body(
            PERF_CLOSE as u8,
            &[0xc0, 0x05, 0x01, 0x00, 0x53, 0x1d, 0x45],
        );
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CLOSE");
        assert!(
            recs[0].error,
            "an error{{}} with an empty (list0) value is still an error"
        );
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn error_descriptor_encoded_as_full_ulong_still_sets_the_verdict() {
        // The error descriptor may be encoded as a full 8-byte ulong (0x80 …1d), not
        // just a smallulong (0x53 0x1d). The scan must follow that 9-byte descriptor to
        // the list value and still flag the error.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // close{} list8 count1, error = error{} via full-ulong descriptor + list8 value.
        let mut args = vec![0xc0, 0x10, 0x01, 0x00, 0x80];
        args.extend_from_slice(&DESCRIPTOR_ERROR.to_be_bytes()); // 8-byte BE 0x1d
        args.extend_from_slice(&[0xc0, 0x01, 0x00]); // list8 value, count 0
        let body = performative_body(PERF_CLOSE as u8, &args);
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CLOSE");
        assert!(
            recs[0].error,
            "a full-ulong error descriptor still sets the verdict"
        );
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn ulong0_and_full_ulong_descriptors_decode() {
        // 0x44 (ulong0) descriptor → code 0, labelled numerically.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let body0 = vec![0x00, 0x44]; // described type, ulong0 descriptor
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body0), 1);
        // 0x80 (full ulong) descriptor encoding OPEN (0x10).
        let mut body8 = vec![0x00, 0x80];
        body8.extend_from_slice(&(PERF_OPEN).to_be_bytes()); // 8-byte BE 0x10
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_AMQP, &body8), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "PERFORMATIVE_0");
        assert_eq!(recs[1].operation, "OPEN");
    }

    #[test]
    fn sasl_frame_labels_as_sasl() {
        let mut p = Amqp1Parser::new();
        // SASL handshake opens with the SASL-layer header, then SASL frames (type 1).
        p.on_inbound(&SASL_HEADER, 0);
        // sasl-mechanisms performative (descriptor 0x40) on a type-1 frame.
        let body = performative_body(0x40, b"\x45");
        p.on_inbound(&frame_bytes(0, FRAME_TYPE_SASL, &body), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SASL");
        assert!(!recs[0].error);
    }

    #[test]
    fn stacked_sasl_then_amqp_headers_are_both_stripped() {
        // A real 1.0 connection with SASL negotiates: SASL header, SASL frames, then
        // the AMQP header and AMQP frames. Two headers can land back-to-back at the
        // front; both must be stripped so the following OPEN frames cleanly.
        let mut p = Amqp1Parser::new();
        let mut stream = SASL_HEADER.to_vec();
        stream.extend_from_slice(&PROTOCOL_HEADER);
        stream.extend(perf_frame(0, PERF_OPEN as u8, b""));
        p.on_inbound(&stream, 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "OPEN");
    }

    #[test]
    fn heartbeat_empty_frame_produces_no_record() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // An empty frame (size == 8, no body) is a heartbeat.
        let heartbeat = frame_bytes(0, FRAME_TYPE_AMQP, b"");
        p.on_inbound(&heartbeat, 1);
        // Followed by a real OPEN to prove resync past the heartbeat.
        p.on_inbound(&perf_frame(0, PERF_OPEN as u8, b""), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "heartbeat yields no record");
        assert_eq!(recs[0].operation, "OPEN");
    }

    #[test]
    fn extended_header_is_skipped_via_doff() {
        // DOFF > 2 means an extended header sits between the fixed header and the
        // body. The performative must be read from `DOFF*4`, not byte 8.
        let body = performative_body(PERF_BEGIN as u8, b"");
        // DOFF = 3 → body at byte 12; 4 bytes of extended header between 8 and 12.
        let ext = [0xde, 0xad, 0xbe, 0xef];
        let size = (FRAME_HEADER_LEN + ext.len() + body.len()) as u32;
        let mut frame = size.to_be_bytes().to_vec();
        frame.push(3); // DOFF
        frame.push(FRAME_TYPE_AMQP);
        frame.extend_from_slice(&0u16.to_be_bytes()); // channel
        frame.extend_from_slice(&ext);
        frame.extend_from_slice(&body);
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        p.on_inbound(&frame, 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "BEGIN");
    }

    #[test]
    fn pipelined_performative_frames_each_yield_a_record_in_order() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let mut stream = Vec::new();
        stream.extend(perf_frame(0, PERF_OPEN as u8, b""));
        stream.extend(perf_frame(0, PERF_BEGIN as u8, b""));
        stream.extend(perf_frame(1, PERF_ATTACH as u8, b""));
        p.on_inbound(&stream, 100);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "OPEN");
        assert_eq!(recs[1].operation, "BEGIN");
        assert_eq!(recs[2].operation, "ATTACH");
    }

    #[test]
    fn performatives_on_both_directions_are_each_emitted() {
        // AMQP is async: a TRANSFER goes out, a DISPOSITION comes back, independently.
        let mut p = Amqp1Parser::new();
        let mut req = PROTOCOL_HEADER.to_vec();
        req.extend(perf_frame(0, PERF_TRANSFER as u8, b"msg"));
        p.on_inbound(&req, 1);
        // Outbound carries a DISPOSITION (its own protocol header on this side too).
        let mut resp = PROTOCOL_HEADER.to_vec();
        resp.extend(perf_frame(0, PERF_DISPOSITION as u8, b"settle"));
        p.on_outbound(&resp, 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "TRANSFER");
        assert_eq!(recs[0].start_unix_nano, 1);
        assert_eq!(recs[1].operation, "DISPOSITION");
        assert_eq!(recs[1].start_unix_nano, 2);
    }

    #[test]
    fn outbound_frame_before_inbound_header_does_not_kill_the_header() {
        // Capture can deliver the server's first frame before the client's inbound
        // protocol header is processed. Header-strip state is per-direction, so an
        // inbound header arriving after an outbound frame must still be stripped.
        let mut p = Amqp1Parser::new();
        // Server speaks an outbound OPEN first (with its own header).
        let mut srv = PROTOCOL_HEADER.to_vec();
        srv.extend(perf_frame(0, PERF_OPEN as u8, b""));
        p.on_outbound(&srv, 1);
        // Then the client's inbound header + a BEGIN.
        let mut cli = PROTOCOL_HEADER.to_vec();
        cli.extend(perf_frame(0, PERF_BEGIN as u8, b""));
        p.on_inbound(&cli, 2);
        assert!(!p.is_dead(), "inbound header must not desync the parser");
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "OPEN");
        assert_eq!(recs[1].operation, "BEGIN");
    }

    #[test]
    fn fragmented_frame_waits_instead_of_misparsing() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let frame = perf_frame(0, PERF_TRANSFER as u8, b"a-decently-long-transfer-arg-blob");
        // Feed the header + a few body bytes, but stop short of the full frame.
        let split = FRAME_HEADER_LEN + 4;
        p.on_inbound(&frame[..split], 1);
        assert!(p.take_records().is_empty(), "partial frame must not emit");
        assert!(!p.is_dead(), "partial is not garbage");
        // The remainder arrives — now the frame completes.
        p.on_inbound(&frame[split..], 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "TRANSFER");
        assert_eq!(recs[0].start_unix_nano, 2);
    }

    #[test]
    fn protocol_header_split_across_segments_reassembles() {
        let mut p = Amqp1Parser::new();
        // The 8-byte header arrives in three dribbles, then a performative frame.
        p.on_inbound(&PROTOCOL_HEADER[..3], 0);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_inbound(&PROTOCOL_HEADER[3..6], 1);
        assert!(p.take_records().is_empty());
        p.on_inbound(&PROTOCOL_HEADER[6..], 2);
        p.on_inbound(&perf_frame(0, PERF_OPEN as u8, b""), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "OPEN");
    }

    #[test]
    fn frame_larger_than_buffer_skips_the_straddling_body() {
        // A large frame whose body spans several segments: the parser must frame past
        // it (DirBuf skip) and resume at the next frame head. We use an unknown
        // descriptor so the big frame yields no record, then a known one to prove
        // resync.
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        let big = perf_frame(0, 0x42, &[0x55u8; 50]); // unknown code, large body
        // Feed only the first 20 bytes; the rest of the body straddles.
        p.on_inbound(&big[..20], 1);
        let _ = p.take_records();
        assert!(!p.is_dead());
        // Rest of the big frame, then a known FLOW.
        p.on_inbound(&big[20..], 2);
        p.on_inbound(&perf_frame(0, PERF_FLOW as u8, b""), 3);
        let recs = p.take_records();
        // The big frame (unknown code 0x42) labels numerically; the FLOW follows.
        let ops: Vec<&str> = recs.iter().map(|r| r.operation.as_str()).collect();
        assert!(
            ops.contains(&"FLOW"),
            "must resync to FLOW after the big frame: {ops:?}"
        );
    }

    #[test]
    fn insane_size_marks_the_parser_dead() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // A size below the 8-byte header minimum is invalid framing.
        let mut buf = 4u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // DOFF, type, channel
        p.on_inbound(&buf, 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn oversized_size_marks_the_parser_dead() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // A size far beyond MAX_FRAME_SIZE.
        let mut buf = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        p.on_inbound(&buf, 1);
        assert!(p.is_dead());
    }

    #[test]
    fn bad_doff_marks_the_parser_dead() {
        let mut p = Amqp1Parser::new();
        p.on_inbound(&PROTOCOL_HEADER, 0);
        // DOFF = 1 → body offset 4, inside the fixed header — desync.
        let body = performative_body(PERF_OPEN as u8, b"");
        let size = (FRAME_HEADER_LEN + body.len()) as u32;
        let mut frame = size.to_be_bytes().to_vec();
        frame.push(1); // DOFF too small
        frame.push(FRAME_TYPE_AMQP);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&body);
        p.on_inbound(&frame, 1);
        assert!(p.is_dead());
    }

    #[test]
    fn byte_at_a_time_delivery_yields_one_record() {
        let mut p = Amqp1Parser::new();
        let mut stream = PROTOCOL_HEADER.to_vec();
        stream.extend(perf_frame(0, PERF_TRANSFER as u8, b"transfer-args-here"));
        for (i, byte) in stream.iter().enumerate() {
            p.on_inbound(std::slice::from_ref(byte), i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "TRANSFER");
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: hostile/truncated payloads fed at every byte boundary, both
        // directions, both orders. The hard requirement is no panic, ever.
        let close_err = err_frame(0, PERF_CLOSE as u8);
        let payloads: &[&[u8]] = &[
            &PROTOCOL_HEADER,
            &SASL_HEADER,
            b"AMQP\x00\x01\x00\x00\x00\x00\x00", // header + partial frame
            b"AMQP\x00\x00\x09\x01",             // the 0-9-1 header (wrong dialect)
            b"\x00\x00\x00\xff\x02\x00\x00\x00", // sane-ish head, no body
            b"\xff\xff\xff\xff\x02\x00\x00\x00", // ~4G size
            b"\x00\x00\x00\x08\x02\x00\x00\x00", // empty heartbeat frame
            b"\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x53", // described-type, no code byte
            b"\x00\x00\x00\x09\x02\x00\x00\x00\x00", // 1-byte body, just 0x00
            b"\x00\x00\x00\x0b\xff\x00\x00\x00\x00\x53\x14", // DOFF=255 (body past frame)
            &close_err,                          // a real CLOSE-with-error frame
            b"\x00\x00\x00\x0b\x02\x00\x00\x00\x00\x53\x14", // valid TRANSFER, no args
            &[0x00; 64],                         // a wall of zeroes
            &[0xff; 256],                        // a wall of 0xff
            b"",                                 // empty
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // Inbound, in two segments.
                let mut p = Amqp1Parser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();
                // Outbound, in two segments.
                let mut q = Amqp1Parser::new();
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
                // Detection must never panic either.
                let _ = detect_amqp1(a);
                let _ = detect_amqp1(payload);
                // Byte-at-a-time, alternating directions.
                let mut r = Amqp1Parser::new();
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
