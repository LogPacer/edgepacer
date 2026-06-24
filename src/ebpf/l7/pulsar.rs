//! Apache Pulsar wire parser — implements [`super::L7Parser`], the zero-code APM
//! producer for connections speaking Pulsar's custom binary protocol (broker ⇄
//! producers/consumers). The monitored process is usually the *client*, so the
//! request side carries the frames it writes and the response side what it reads;
//! the [`super::L7Parser`] contract is direction-agnostic (inbound = request,
//! outbound = response — the registry flips a client connection for us).
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Pulsar prepends every frame with a 4-byte BIG-ENDIAN total size, then a 4-byte
//! BE command size, then a protobuf-encoded `BaseCommand`, then (for "payload"
//! commands like `Send`/`Message`) an opaque message payload:
//!
//! ```text
//! [ totalSize: u32 BE ][ commandSize: u32 BE ][ BaseCommand: commandSize bytes ][ payload… ]
//!   \__ counts everything after itself __/
//! ```
//!
//! `totalSize` counts every byte *after* the totalSize field, so
//! `total_len = 4 + totalSize`, and `commandSize` is the protobuf length of the
//! `BaseCommand` only (the payload, when present, is `totalSize - 4 - commandSize`
//! bytes we never decode). The protocol caps a frame at 5 MB. This is a couple of
//! big-endian reads plus a *minimal* protobuf varint scan — pulling a protobuf
//! crate for that would betray the leanness moat, so it is hand-rolled.
//!
//! ## Minimal protobuf scan
//!
//! `BaseCommand`'s first field is `required Type type = 1` — a protobuf varint at
//! tag byte `0x08`. Reading just that one field yields the command name (`CONNECT`,
//! `PRODUCER`, `SEND`, `SUBSCRIBE`, …) — the operation label. For the few request
//! commands that carry a `topic` (it is field 1 of `CommandProducer` /
//! `CommandSubscribe` / `CommandLookupTopic`, nested at the BaseCommand field whose
//! number equals the `type` value), we cheaply read that one string and append it.
//! For pairing we read a single scalar field (`request_id`, or a SEND's
//! `producer_id`+`sequence_id`) out of the nested command. We never fully decode a
//! protobuf message — a bounded field walk that stops at the field it wants.
//!
//! ## Pairing — by request_id (interleaved), not FIFO
//!
//! Per the spec, "commands for different producers and consumers can be interleaved
//! and sent through the same connection without restriction", so FIFO request order
//! does NOT hold. Pulsar correlates with a client-chosen `request_id` echoed in the
//! response. We pair on it. The exception is `Send`, which carries no request_id —
//! it is correlated by `(producer_id, sequence_id)` and answered by `SendReceipt`
//! or `SendError`. The handful of request/response pairs that carry neither key
//! (`Connect` ⇄ `Connected`) fall back to FIFO over the keyless pending queue.
//!
//! ## What we extract (and only this)
//!
//! - `operation`: the `BaseCommand` type name, plus a topic when one is cheaply
//!   present (`PRODUCER <topic>`, `SUBSCRIBE <topic>`, `LOOKUP <topic>`).
//! - `error`: true for an `ERROR` (`CommandError`) or `SEND_ERROR`
//!   (`CommandSendError`) response. Those are Pulsar's failure verdicts.
//! - `status_code`: `1` on error, else `0` (Pulsar has no numeric status on the
//!   wire; `ServerError` is an enum buried in the error command — out of scope).
//! - timing: request `ts` → response `ts` (saturating, floored at 0), per the trait.
//!
//! ### Reference
//! Enum values are the authoritative `PulsarApi.proto` `BaseCommand.Type` (not the
//! illustrative values in some summaries): `CONNECT=2`, `SUBSCRIBE=4`,
//! `PRODUCER=5`, `SEND=6`, `SEND_RECEIPT=7`, `SEND_ERROR=8`, `ERROR=14`, …

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// The 4-byte BE `totalSize` + 4-byte BE `commandSize` prefix before the protobuf.
const FRAME_HEADER_LEN: usize = 8;

/// Protocol-mandated maximum frame size (5 MB). A "Pulsar" stream claiming more
/// than this means we mis-detected or desynced — bail rather than buffer forever.
/// We still frame past large payloads via `DirBuf::skip`; this only rejects absurd
/// size fields.
const MAX_FRAME_LEN: usize = 5 * 1024 * 1024;

/// Cap on outstanding (unanswered) requests. A peer whose replies we never see (we
/// attached mid-connection) or that floods one-directional requests would grow the
/// pending set without bound. Pulsar's practical in-flight ceiling is small; this
/// is generous headroom while still capping a leaking/hostile stream. Past it the
/// parser dies — the same discipline as the per-frame size bound.
const MAX_INFLIGHT: usize = 40_000;

/// `BaseCommand.Type` values we name (the authoritative `PulsarApi.proto` set). Any
/// other value still labels via a `TYPE<N>` fallback rather than being dropped.
mod cmd {
    pub const CONNECT: u64 = 2;
    pub const CONNECTED: u64 = 3;
    pub const SUBSCRIBE: u64 = 4;
    pub const PRODUCER: u64 = 5;
    pub const SEND: u64 = 6;
    pub const SEND_RECEIPT: u64 = 7;
    pub const SEND_ERROR: u64 = 8;
    pub const SUCCESS: u64 = 13;
    pub const ERROR: u64 = 14;
    pub const PRODUCER_SUCCESS: u64 = 17;
    pub const PARTITIONED_METADATA: u64 = 21;
    pub const PARTITIONED_METADATA_RESPONSE: u64 = 22;
    pub const LOOKUP: u64 = 23;
    pub const LOOKUP_RESPONSE: u64 = 24;
    pub const GET_SCHEMA: u64 = 34;
    pub const GET_SCHEMA_RESPONSE: u64 = 35;

    /// Highest assigned `Type` value (`WATCH_TC_ASSIGNMENTS_CLOSE = 81`). A larger
    /// value in the `type` field is not a real Pulsar command — a detection signal.
    pub const MAX_KNOWN: u64 = 81;
}

/// Map a `BaseCommand.Type` value to its operation label. Common types are named;
/// anything else falls back to `TYPE<N>` so the span is still labelled, never
/// dropped.
fn type_name(t: u64) -> &'static str {
    match t {
        cmd::CONNECT => "CONNECT",
        cmd::CONNECTED => "CONNECTED",
        cmd::SUBSCRIBE => "SUBSCRIBE",
        cmd::PRODUCER => "PRODUCER",
        cmd::SEND => "SEND",
        cmd::SEND_RECEIPT => "SEND_RECEIPT",
        cmd::SEND_ERROR => "SEND_ERROR",
        9 => "MESSAGE",
        10 => "ACK",
        11 => "FLOW",
        12 => "UNSUBSCRIBE",
        cmd::SUCCESS => "SUCCESS",
        cmd::ERROR => "ERROR",
        15 => "CLOSE_PRODUCER",
        16 => "CLOSE_CONSUMER",
        cmd::PRODUCER_SUCCESS => "PRODUCER_SUCCESS",
        18 => "PING",
        19 => "PONG",
        20 => "REDELIVER_UNACKNOWLEDGED_MESSAGES",
        cmd::PARTITIONED_METADATA => "PARTITIONED_METADATA",
        cmd::PARTITIONED_METADATA_RESPONSE => "PARTITIONED_METADATA_RESPONSE",
        cmd::LOOKUP => "LOOKUP",
        cmd::LOOKUP_RESPONSE => "LOOKUP_RESPONSE",
        cmd::GET_SCHEMA => "GET_SCHEMA",
        cmd::GET_SCHEMA_RESPONSE => "GET_SCHEMA_RESPONSE",
        _ => "OTHER",
    }
}

/// Read a big-endian u32 from the first four bytes of `b` (caller guarantees len).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------------------
// Minimal protobuf scanning
// ---------------------------------------------------------------------------

/// Protobuf wire types we recognise while scanning a `BaseCommand`. We only ever
/// read varint (the `type` field, scalar ids) and length-delimited (the nested
/// command message, the topic string) fields; the rest are skipped by wire type.
const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

/// Decode a base-128 varint at `buf[*pos..]`, advancing `pos` past it. Returns the
/// value, or `None` if the buffer ends mid-varint or the varint exceeds 10 bytes
/// (a u64's maximum) — a malformed/hostile encoding we refuse to chase.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

/// Decode one protobuf field tag at `buf[*pos..]`, advancing past the tag varint.
/// Returns `(field_number, wire_type)`, or `None` on a truncated/zero tag.
fn read_tag(buf: &[u8], pos: &mut usize) -> Option<(u64, u8)> {
    let tag = read_varint(buf, pos)?;
    let field = tag >> 3;
    let wire = (tag & 0x7) as u8;
    if field == 0 {
        return None; // field number 0 is invalid — desync/garbage
    }
    Some((field, wire))
}

/// Advance `pos` past a field of `wire` type whose tag was already consumed,
/// WITHOUT interpreting its value. Returns `false` if the field's bytes run past
/// the buffer (truncated) — the scan stops there rather than reading out of bounds.
fn skip_field(buf: &[u8], pos: &mut usize, wire: u8) -> bool {
    match wire {
        WIRE_VARINT => read_varint(buf, pos).is_some(),
        WIRE_I64 => advance(pos, 8, buf.len()),
        WIRE_I32 => advance(pos, 4, buf.len()),
        WIRE_LEN => match read_varint(buf, pos) {
            Some(len) => advance(pos, len as usize, buf.len()),
            None => false,
        },
        // Groups (deprecated, wire types 3/4) and any unknown wire type: we cannot
        // frame them cheaply, so we stop the scan rather than guess.
        _ => false,
    }
}

/// Advance `pos` by `n`, but only if `n` bytes remain before `len`. Guards every
/// length-delimited / fixed-width skip against a truncated or hostile length.
fn advance(pos: &mut usize, n: usize, len: usize) -> bool {
    match pos.checked_add(n) {
        Some(end) if end <= len => {
            *pos = end;
            true
        }
        _ => false,
    }
}

/// Read the `type` (field 1, varint) of a `BaseCommand`. Returns `None` if the
/// first field isn't a varint field-1 tag — i.e. these bytes are not a Pulsar
/// `BaseCommand` (the central detection guard). We do not require field 1 to be the
/// literal first byte run, but a genuine `BaseCommand` always serialises
/// `required Type type = 1` first.
fn base_command_type(cmd_bytes: &[u8]) -> Option<u64> {
    let mut pos = 0;
    let (field, wire) = read_tag(cmd_bytes, &mut pos)?;
    if field != 1 || wire != WIRE_VARINT {
        return None;
    }
    read_varint(cmd_bytes, &mut pos)
}

/// Find a length-delimited (wire type 2) sub-message at `field_number` within a
/// `BaseCommand`, returning its byte slice. The nested command for a `type` value
/// `T` is always at BaseCommand field number `T` (the proto assigns
/// `optional CommandX x = T`), so this locates e.g. `CommandProducer` at field 5.
/// A bounded walk that stops at the first match or the end of the buffer.
fn nested_message(cmd_bytes: &[u8], field_number: u64) -> Option<&[u8]> {
    let mut pos = 0;
    // Bound the field walk; a real BaseCommand has a handful of fields.
    for _ in 0..64 {
        let (field, wire) = read_tag(cmd_bytes, &mut pos)?;
        if wire == WIRE_LEN {
            let len = read_varint(cmd_bytes, &mut pos)? as usize;
            let start = pos;
            let end = start.checked_add(len)?;
            if end > cmd_bytes.len() {
                return None;
            }
            if field == field_number {
                return Some(&cmd_bytes[start..end]);
            }
            pos = end;
        } else if !skip_field(cmd_bytes, &mut pos, wire) {
            return None;
        }
    }
    None
}

/// Read a varint scalar field (`field_number`, wire type 0) out of a nested command
/// message. Used to pull `request_id` / `producer_id` / `sequence_id`. A bounded
/// walk that returns the field's value or `None` if absent/malformed.
fn varint_field(msg: &[u8], field_number: u64) -> Option<u64> {
    let mut pos = 0;
    for _ in 0..64 {
        let (field, wire) = read_tag(msg, &mut pos)?;
        if field == field_number && wire == WIRE_VARINT {
            return read_varint(msg, &mut pos);
        }
        if !skip_field(msg, &mut pos, wire) {
            return None;
        }
    }
    None
}

/// Read a length-delimited string field (`field_number`, wire type 2) out of a
/// nested command, as a lossy-UTF8 `String`. Used to pull the `topic` (field 1) for
/// the operation label. Bounded; returns `None` if absent/malformed.
fn string_field(msg: &[u8], field_number: u64) -> Option<String> {
    let mut pos = 0;
    for _ in 0..64 {
        let (field, wire) = read_tag(msg, &mut pos)?;
        if wire == WIRE_LEN {
            let len = read_varint(msg, &mut pos)? as usize;
            let start = pos;
            let end = start.checked_add(len)?;
            if end > msg.len() {
                return None;
            }
            if field == field_number {
                return Some(String::from_utf8_lossy(&msg[start..end]).into_owned());
            }
            pos = end;
        } else if !skip_field(msg, &mut pos, wire) {
            return None;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Command interpretation
// ---------------------------------------------------------------------------

/// How a response correlates back to its request. Pulsar interleaves freely, so
/// FIFO order does not hold; we key on the client-chosen id the broker echoes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    /// Correlated by the `request_id` most commands carry.
    Request(u64),
    /// A `Send`/`SendReceipt`/`SendError` correlated by `(producer_id, sequence_id)`.
    Send(u64, u64),
    /// `Connect` ⇄ `Connected`: no usable id, so paired FIFO over keyless pending.
    Fifo,
}

/// The role a `BaseCommand` plays in request/response pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    /// A request to record and await a reply: its operation label and pairing key.
    Request { operation: String, key: Key },
    /// A response that completes a pending request: its pairing key and whether it
    /// is a failure verdict (`ERROR` / `SEND_ERROR`).
    Response { key: Key, error: bool },
    /// A command that neither opens nor closes a pairing (heartbeats, server pushes
    /// like `MESSAGE`, acks, closes): framed past without touching `pending`.
    Oneway,
}

/// Classify a `BaseCommand` (already isolated from its frame) into a [`Role`],
/// reading only the fields a span needs. `None` means the command bytes are not a
/// well-formed `BaseCommand` (no field-1 varint `type`) — a desync signal.
fn classify(cmd_bytes: &[u8]) -> Option<Role> {
    let t = base_command_type(cmd_bytes)?;
    Some(match t {
        cmd::PRODUCER | cmd::SUBSCRIBE | cmd::LOOKUP => {
            // topic is field 1; request_id is field 3 (PRODUCER) / 5 (SUBSCRIBE) /
            // 2 (LOOKUP) of the nested command at BaseCommand field `t`.
            let nested = nested_message(cmd_bytes, t);
            let topic = nested.and_then(|m| string_field(m, 1));
            let rid_field = match t {
                cmd::PRODUCER => 3,
                cmd::SUBSCRIBE => 5,
                _ => 2, // LOOKUP
            };
            let key = nested
                .and_then(|m| varint_field(m, rid_field))
                .map(Key::Request)
                .unwrap_or(Key::Fifo);
            Role::Request {
                operation: label(type_name(t), topic.as_deref()),
                key,
            }
        }
        cmd::PARTITIONED_METADATA | cmd::GET_SCHEMA => {
            // request_id is field 2 of CommandPartitionedTopicMetadata but field 1 of
            // CommandGetSchema (per PulsarApi.proto), so read the right one per type.
            let rid_field = if t == cmd::GET_SCHEMA { 1 } else { 2 };
            let key = nested_message(cmd_bytes, t)
                .and_then(|m| varint_field(m, rid_field))
                .map(Key::Request)
                .unwrap_or(Key::Fifo);
            Role::Request {
                operation: type_name(t).to_string(),
                key,
            }
        }
        cmd::CONNECT => Role::Request {
            operation: "CONNECT".to_string(),
            key: Key::Fifo,
        },
        cmd::SEND => {
            // CommandSend: producer_id = field 1, sequence_id = field 2.
            let nested = nested_message(cmd_bytes, cmd::SEND);
            let key = match (
                nested.and_then(|m| varint_field(m, 1)),
                nested.and_then(|m| varint_field(m, 2)),
            ) {
                (Some(pid), Some(seq)) => Key::Send(pid, seq),
                _ => Key::Fifo,
            };
            Role::Request {
                operation: "SEND".to_string(),
                key,
            }
        }
        // Responses echo request_id, but its field number varies by command (per
        // PulsarApi.proto): SUCCESS / PRODUCER_SUCCESS / GET_SCHEMA_RESPONSE / ERROR
        // carry it at field 1, PARTITIONED_METADATA_RESPONSE at field 2 (field 1 is
        // `partitions`), and LOOKUP_RESPONSE at field 4 (field 1 is a string URL).
        cmd::SUCCESS | cmd::PRODUCER_SUCCESS | cmd::GET_SCHEMA_RESPONSE => {
            response_by_request_id(cmd_bytes, t, 1, false)
        }
        cmd::PARTITIONED_METADATA_RESPONSE => response_by_request_id(cmd_bytes, t, 2, false),
        cmd::LOOKUP_RESPONSE => response_by_request_id(cmd_bytes, t, 4, false),
        cmd::ERROR => response_by_request_id(cmd_bytes, t, 1, true),
        cmd::CONNECTED => Role::Response {
            key: Key::Fifo,
            error: false,
        },
        cmd::SEND_RECEIPT | cmd::SEND_ERROR => {
            // producer_id = field 1, sequence_id = field 2 of both commands.
            let nested = nested_message(cmd_bytes, t);
            let key = match (
                nested.and_then(|m| varint_field(m, 1)),
                nested.and_then(|m| varint_field(m, 2)),
            ) {
                (Some(pid), Some(seq)) => Key::Send(pid, seq),
                _ => Key::Fifo,
            };
            Role::Response {
                key,
                error: t == cmd::SEND_ERROR,
            }
        }
        // Everything else (PING/PONG, MESSAGE, ACK, FLOW, closes, txn, watch, …) is
        // out-of-band relative to the request/response pairs we surface: framed past.
        _ => Role::Oneway,
    })
}

/// Build a `Response` role keyed on the `request_id` read from `rid_field` of the
/// nested response command (the field number differs per command — see caller),
/// falling back to FIFO if it can't be read.
fn response_by_request_id(cmd_bytes: &[u8], t: u64, rid_field: u64, error: bool) -> Role {
    let key = nested_message(cmd_bytes, t)
        .and_then(|m| varint_field(m, rid_field))
        .map(Key::Request)
        .unwrap_or(Key::Fifo);
    Role::Response { key, error }
}

/// Compose the operation label: the type name, plus a non-empty topic when present.
fn label(name: &str, topic: Option<&str>) -> String {
    match topic {
        Some(t) if !t.is_empty() => format!("{name} {t}"),
        _ => name.to_string(),
    }
}

/// Outcome of trying to read one length-prefixed frame off a buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed message: total bytes it occupies and the command-bytes sub-range
    /// `[cmd_start, cmd_end)` within the buffer (the protobuf `BaseCommand`).
    Framed {
        total_len: usize,
        cmd_start: usize,
        cmd_end: usize,
    },
    /// A valid prefix but not enough bytes yet — wait.
    Partial,
    /// Not Pulsar framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Frame one message: read `totalSize` + `commandSize`, validate them, and locate
/// the `BaseCommand` byte range. The payload after the command (if any) is framed
/// past unread. The command bytes must be fully buffered to classify; if the frame
/// is sane but the command still straddles the segment boundary we report `Partial`
/// (wait) rather than advancing past a half-read command.
fn frame_head(buf: &[u8]) -> Head {
    if buf.len() < FRAME_HEADER_LEN {
        return Head::Partial;
    }
    let total_size = be_u32(&buf[0..4]) as usize;
    let command_size = be_u32(&buf[4..8]) as usize;
    // totalSize counts everything after itself: the 4-byte commandSize + the command
    // + any payload. So it must be at least 4 + commandSize, and within the bound.
    if total_size < 4 + command_size || total_size > MAX_FRAME_LEN {
        return Head::Invalid;
    }
    let total_len = 4 + total_size;
    let cmd_start = FRAME_HEADER_LEN;
    let cmd_end = cmd_start + command_size;
    // The command bytes must be present to classify the frame.
    if buf.len() < cmd_end {
        return Head::Partial;
    }
    Head::Framed {
        total_len,
        cmd_start,
        cmd_end,
    }
}

/// A request awaiting its reply: its operation label, pairing key, and the time it
/// was observed (for latency).
#[derive(Debug)]
struct Pending {
    operation: String,
    key: Key,
    start_unix_nano: i64,
}

/// Pulsar [`L7Parser`]: frames both directions by the 8-byte size prefix, decodes
/// each `BaseCommand`'s `type` (and, cheaply, its topic / pairing ids), and matches
/// each response to its request by `request_id` (or a `Send`'s
/// `(producer_id, sequence_id)`, or FIFO for `Connect`). Desync (an absurd size or a
/// non-`BaseCommand` command) marks it dead.
#[derive(Debug, Default)]
pub(crate) struct PulsarParser {
    request: DirBuf,
    response: DirBuf,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl PulsarParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frame as many complete request frames as the buffer holds, recording each as
    /// a pending request keyed for correlation. Stops on a partial (waits) or a
    /// desync (dies).
    fn drain_request(&mut self, ts: i64) {
        loop {
            if !self.request.drain_skip() {
                return;
            }
            if self.request.buf.is_empty() {
                return;
            }
            match frame_head(&self.request.buf) {
                Head::Framed {
                    total_len,
                    cmd_start,
                    cmd_end,
                } => {
                    match classify(&self.request.buf[cmd_start..cmd_end]) {
                        Some(Role::Request { operation, key }) => {
                            self.pending.push_back(Pending {
                                operation,
                                key,
                                start_unix_nano: ts,
                            });
                            self.request.advance(total_len);
                            if self.pending.len() > MAX_INFLIGHT {
                                self.dead = true;
                                return;
                            }
                            continue;
                        }
                        // A response/oneway on the request side, or an
                        // unrecognised-but-well-formed command: frame past it.
                        Some(_) => self.request.advance(total_len),
                        // Not a BaseCommand at all — the stream is desynced/garbage.
                        None => {
                            self.dead = true;
                            return;
                        }
                    }
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Frame as many complete response frames as the buffer holds, pairing each with
    /// its pending request by key. A response with no matching pending request is
    /// dropped — we attached mid-connection and missed its request.
    fn drain_response(&mut self, ts: i64) {
        loop {
            if !self.response.drain_skip() {
                return;
            }
            if self.response.buf.is_empty() {
                return;
            }
            match frame_head(&self.response.buf) {
                Head::Framed {
                    total_len,
                    cmd_start,
                    cmd_end,
                } => {
                    match classify(&self.response.buf[cmd_start..cmd_end]) {
                        Some(Role::Response { key, error }) => {
                            self.complete(key, error, ts);
                            self.response.advance(total_len);
                        }
                        // A request/oneway on the response side, or an
                        // unrecognised-but-well-formed command: frame past it.
                        Some(_) => self.response.advance(total_len),
                        None => {
                            self.dead = true;
                            return;
                        }
                    }
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Pair a response with its pending request. A keyed response (`Request(id)` or
    /// `Send(pid, seq)`) matches that exact pending entry, and if none matches the
    /// response is DROPPED — never steal an unrelated in-flight request's slot. A
    /// `Fifo` response (`Connected`, or a response whose id we couldn't read) pairs
    /// with the oldest pending request that is itself keyless/FIFO.
    fn complete(&mut self, key: Key, error: bool, ts: i64) {
        let idx = match key {
            Key::Request(_) | Key::Send(..) => {
                match self.pending.iter().position(|p| p.key == key) {
                    Some(i) => i,
                    None => return, // no matching request — drop, don't steal
                }
            }
            Key::Fifo => match self.pending.iter().position(|p| p.key == Key::Fifo) {
                Some(i) => i,
                None => return,
            },
        };
        if let Some(req) = self.pending.remove(idx) {
            self.records.push(L7Record {
                protocol: Protocol::Pulsar,
                attributes: Vec::new(),
                operation: req.operation,
                status_code: if error { 1 } else { 0 },
                error,
                start_unix_nano: req.start_unix_nano,
                duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
            });
        }
    }
}

impl L7Parser for PulsarParser {
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

/// Construct a Pulsar parser unconditionally — the port-hint path (well-known port
/// 6650) binds by port, where byte detection's conservatism would otherwise miss
/// this magic-less binary protocol.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(PulsarParser::new())
}

/// Recognise Pulsar from a connection's request-side prefix via a POSITIVE,
/// CONSERVATIVE signature and return a fresh boxed parser, or `None`.
///
/// Pulsar has no magic bytes — the wire is two big-endian sizes then a protobuf — so
/// a byte-only sniff is inherently weak and we err hard toward `None`. The signature
/// validates the whole frame shape against the protocol's own rules:
///
///   * `totalSize` + `commandSize` buffered, with `totalSize ≥ 4 + commandSize` and
///     `≤ 5 MB` (the protocol's framing invariant + frame cap);
///   * `commandSize ≥ 2` (the smallest `BaseCommand` is the 2-byte `type` field);
///   * the command bytes fully buffered and parsing as a `BaseCommand`: its first
///     field is the `required Type type = 1` varint, and that type value is a known
///     command (`≤ 81`). Requiring a structurally valid `BaseCommand` — not just a
///     plausible size header — is what suppresses collisions on the eight
///     big-endian bytes any binary stream might present.
///
/// While the size header is buffered but the command hasn't fully arrived we return
/// `None` (the registry keeps buffering and retries) rather than guess.
pub(crate) fn detect_pulsar(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if inbound.len() < FRAME_HEADER_LEN {
        return None;
    }
    let total_size = be_u32(&inbound[0..4]) as usize;
    let command_size = be_u32(&inbound[4..8]) as usize;
    if total_size < 4 + command_size || total_size > MAX_FRAME_LEN {
        return None;
    }
    // The smallest real BaseCommand is `type` alone: tag(1) + varint(≥1) = 2 bytes.
    if command_size < 2 {
        return None;
    }
    let cmd_end = FRAME_HEADER_LEN + command_size;
    if inbound.len() < cmd_end {
        return None; // size header plausible but command not fully buffered yet
    }
    let cmd_bytes = &inbound[FRAME_HEADER_LEN..cmd_end];
    match base_command_type(cmd_bytes) {
        // A real BaseCommand's type is within the assigned enum range. An arbitrary
        // binary stream that happens to land a field-1 varint tag almost never also
        // lands a value in 2..=81 with a self-consistent frame size.
        Some(t) if (2..=cmd::MAX_KNOWN).contains(&t) => Some(Box::new(PulsarParser::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a base-128 varint.
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    /// Encode a protobuf field tag.
    fn tag(field: u64, wire: u8) -> Vec<u8> {
        varint((field << 3) | u64::from(wire))
    }

    /// Encode a varint field: `[tag][value]`.
    fn pb_varint(field: u64, value: u64) -> Vec<u8> {
        let mut v = tag(field, WIRE_VARINT);
        v.extend(varint(value));
        v
    }

    /// Encode a length-delimited string field: `[tag][len][bytes]`.
    fn pb_string(field: u64, s: &str) -> Vec<u8> {
        let mut v = tag(field, WIRE_LEN);
        v.extend(varint(s.len() as u64));
        v.extend_from_slice(s.as_bytes());
        v
    }

    /// Encode a length-delimited sub-message field: `[tag][len][bytes]`.
    fn pb_message(field: u64, body: &[u8]) -> Vec<u8> {
        let mut v = tag(field, WIRE_LEN);
        v.extend(varint(body.len() as u64));
        v.extend_from_slice(body);
        v
    }

    /// Build a `BaseCommand`: `type` (field 1) then the nested command (field = type
    /// value), matching the proto's `optional CommandX x = <type>` layout.
    fn base_command(type_value: u64, nested: &[u8]) -> Vec<u8> {
        let mut cmd = pb_varint(1, type_value);
        if !nested.is_empty() {
            cmd.extend(pb_message(type_value, nested));
        }
        cmd
    }

    /// Wrap a `BaseCommand` (and optional opaque payload) in the Pulsar frame:
    /// `[totalSize:4 BE][commandSize:4 BE][command][payload]`.
    fn frame(command: &[u8], payload: &[u8]) -> Vec<u8> {
        let total_size = (4 + command.len() + payload.len()) as u32;
        let mut v = total_size.to_be_bytes().to_vec();
        v.extend_from_slice(&(command.len() as u32).to_be_bytes());
        v.extend_from_slice(command);
        v.extend_from_slice(payload);
        v
    }

    /// A simple (payload-free) command frame for a given type + nested body.
    fn simple_frame(type_value: u64, nested: &[u8]) -> Vec<u8> {
        frame(&base_command(type_value, nested), &[])
    }

    /// CommandProducer nested body: topic(1), producer_id(2), request_id(3).
    fn producer(topic: &str, producer_id: u64, request_id: u64) -> Vec<u8> {
        let mut m = pb_string(1, topic);
        m.extend(pb_varint(2, producer_id));
        m.extend(pb_varint(3, request_id));
        m
    }

    /// CommandSubscribe nested body: topic(1), subscription(2), … request_id(5).
    fn subscribe(topic: &str, request_id: u64) -> Vec<u8> {
        let mut m = pb_string(1, topic);
        m.extend(pb_string(2, "sub"));
        m.extend(pb_varint(3, 0)); // subType
        m.extend(pb_varint(4, 7)); // consumer_id
        m.extend(pb_varint(5, request_id));
        m
    }

    /// CommandSend nested body: producer_id(1), sequence_id(2).
    fn send(producer_id: u64, sequence_id: u64) -> Vec<u8> {
        let mut m = pb_varint(1, producer_id);
        m.extend(pb_varint(2, sequence_id));
        m
    }

    /// CommandSendReceipt / CommandSendError nested body: producer_id(1), sequence_id(2).
    fn send_ack(producer_id: u64, sequence_id: u64) -> Vec<u8> {
        send(producer_id, sequence_id)
    }

    /// A response command echoing request_id at field 1 (SUCCESS / PRODUCER_SUCCESS /
    /// *_RESPONSE / ERROR all carry request_id first).
    fn response_with_request_id(request_id: u64) -> Vec<u8> {
        pb_varint(1, request_id)
    }

    fn record(
        p: &mut PulsarParser,
        req: &[u8],
        req_ts: i64,
        resp: &[u8],
        resp_ts: i64,
    ) -> Vec<L7Record> {
        p.on_inbound(req, req_ts);
        p.on_outbound(resp, resp_ts);
        p.take_records()
    }

    #[test]
    fn type_name_maps_known_types_and_falls_back() {
        assert_eq!(type_name(cmd::CONNECT), "CONNECT");
        assert_eq!(type_name(cmd::PRODUCER), "PRODUCER");
        assert_eq!(type_name(cmd::SEND), "SEND");
        assert_eq!(type_name(cmd::SUBSCRIBE), "SUBSCRIBE");
        assert_eq!(type_name(cmd::ERROR), "ERROR");
        // Unmapped-but-valid type still labels (never dropped).
        assert_eq!(type_name(81), "OTHER");
    }

    #[test]
    fn detects_a_well_formed_producer_frame() {
        let f = simple_frame(cmd::PRODUCER, &producer("persistent://x/y/z", 1, 1));
        assert!(detect_pulsar(&f).is_some());
    }

    #[test]
    fn detects_a_connect_frame() {
        // CommandConnect: client_version is field 1 (string) — type alone suffices.
        let f = simple_frame(cmd::CONNECT, &pb_string(1, "Pulsar-Java-v3"));
        assert!(detect_pulsar(&f).is_some());
    }

    #[test]
    fn detection_is_conservative_about_non_pulsar_bytes() {
        // HTTP request — not Pulsar.
        assert!(detect_pulsar(b"GET /x HTTP/1.1\r\nHost: y\r\n\r\n").is_none());
        // Too short to hold the 8-byte size header.
        assert!(detect_pulsar(b"\x00\x00\x00\x10").is_none());
        // totalSize smaller than 4 + commandSize (framing invariant violated).
        let mut bad = Vec::new();
        bad.extend_from_slice(&5u32.to_be_bytes()); // totalSize 5
        bad.extend_from_slice(&100u32.to_be_bytes()); // commandSize 100 > 5-4
        bad.extend_from_slice(&[0u8; 8]);
        assert!(detect_pulsar(&bad).is_none());
        // totalSize beyond the 5 MB cap.
        let mut huge = Vec::new();
        huge.extend_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes());
        huge.extend_from_slice(&2u32.to_be_bytes());
        huge.extend_from_slice(&[0x08, 0x02]);
        assert!(detect_pulsar(&huge).is_none());
        // Well-framed sizes but the command is not a BaseCommand (first field isn't a
        // field-1 varint type): a field-2 length-delimited tag instead.
        let not_base = frame(&[tag(2, WIRE_LEN), vec![0x01, 0x00]].concat(), &[]);
        assert!(detect_pulsar(&not_base).is_none());
        // Field-1 varint but type value out of the assigned range (> 81).
        let bad_type = simple_frame(200, &[]);
        assert!(detect_pulsar(&bad_type).is_none());
        // type value 0/1 are not assigned commands either.
        assert!(detect_pulsar(&simple_frame(0, &[]).clone()).is_none());
        assert!(detect_pulsar(&simple_frame(1, &[]).clone()).is_none());
    }

    #[test]
    fn new_parser_constructs_unconditionally_for_port_hint() {
        // The port-hint path must yield a parser without any bytes to sniff.
        let mut p = new_parser();
        // It behaves like a fresh parser: feeding a real exchange yields a record.
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("t", 1, 9)), 1);
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(9)),
            2,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PRODUCER t");
    }

    #[test]
    fn producer_request_response_yields_one_record_with_topic() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::PRODUCER, &producer("persistent://t/n/topic", 4, 42));
        let resp = simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(42));
        let recs = record(&mut p, &req, 1_000, &resp, 1_400);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PRODUCER persistent://t/n/topic");
        assert_eq!(recs[0].protocol, Protocol::Pulsar);
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn subscribe_labels_with_topic_and_pairs_by_request_id() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::SUBSCRIBE, &subscribe("my-topic", 7));
        let resp = simple_frame(cmd::SUCCESS, &response_with_request_id(7));
        let recs = record(&mut p, &req, 10, &resp, 25);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE my-topic");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 15);
    }

    #[test]
    fn send_pairs_by_producer_id_and_sequence_id() {
        let mut p = PulsarParser::new();
        // Send carries an opaque payload after the command; it must frame past.
        let req = frame(
            &base_command(cmd::SEND, &send(3, 100)),
            b"\x00\x01\x02opaque-message-bytes",
        );
        let resp = simple_frame(cmd::SEND_RECEIPT, &send_ack(3, 100));
        let recs = record(&mut p, &req, 5, &resp, 9);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SEND");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 4);
    }

    #[test]
    fn send_error_sets_the_failure_verdict() {
        let mut p = PulsarParser::new();
        let req = frame(&base_command(cmd::SEND, &send(1, 50)), b"payload");
        // CommandSendError: producer_id(1), sequence_id(2), error(3), message(4).
        let mut err = send(1, 50);
        err.extend(pb_varint(3, 7)); // ServerError enum
        err.extend(pb_string(4, "PersistenceError"));
        let resp = simple_frame(cmd::SEND_ERROR, &err);
        let recs = record(&mut p, &req, 1, &resp, 3);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SEND");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn error_response_sets_failure_verdict_for_request_id_pair() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::LOOKUP, &{
            // CommandLookupTopic: topic(1), request_id(2).
            let mut m = pb_string(1, "t");
            m.extend(pb_varint(2, 99));
            m
        });
        // CommandError: request_id(1), error(2), message(3).
        let mut err = pb_varint(1, 99);
        err.extend(pb_varint(2, 3));
        err.extend(pb_string(3, "TopicNotFound"));
        let resp = simple_frame(cmd::ERROR, &err);
        let recs = record(&mut p, &req, 0, &resp, 4);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "LOOKUP t");
        assert!(recs[0].error);
    }

    #[test]
    fn get_schema_pairs_by_request_id_at_field_one() {
        // CommandGetSchema carries request_id at field 1 (topic is field 2) — NOT
        // field 2 like CommandPartitionedTopicMetadata. Reading the wrong field made
        // GET_SCHEMA fall back to FIFO and steal a keyless slot or never pair.
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::GET_SCHEMA, &{
            // request_id(1) = 55, topic(2) = "t".
            let mut m = pb_varint(1, 55);
            m.extend(pb_string(2, "persistent://x/y/z"));
            m
        });
        let resp = simple_frame(cmd::GET_SCHEMA_RESPONSE, &response_with_request_id(55));
        let recs = record(&mut p, &req, 100, &resp, 160);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET_SCHEMA");
        assert_eq!(recs[0].duration_nano, 60);
    }

    #[test]
    fn lookup_response_pairs_by_request_id_at_field_four() {
        // CommandLookupTopicResponse carries request_id at field 4 (field 1 is a
        // string brokerServiceUrl). Reading field 1 returned None → FIFO, so the
        // genuine LOOKUP reply silently failed to pair by id.
        let mut p = PulsarParser::new();
        // Two LOOKUPs in flight; reply for id 200 must pair with the id-200 request.
        p.on_inbound(
            &simple_frame(cmd::LOOKUP, &{
                let mut m = pb_string(1, "a");
                m.extend(pb_varint(2, 100));
                m
            }),
            10,
        );
        p.on_inbound(
            &simple_frame(cmd::LOOKUP, &{
                let mut m = pb_string(1, "b");
                m.extend(pb_varint(2, 200));
                m
            }),
            20,
        );
        // CommandLookupTopicResponse: brokerServiceUrl(1), response(3), request_id(4).
        let resp = simple_frame(cmd::LOOKUP_RESPONSE, &{
            let mut m = pb_string(1, "pulsar://broker:6650");
            m.extend(pb_varint(3, 0)); // LookupType.Connect
            m.extend(pb_varint(4, 200)); // request_id
            m
        });
        p.on_outbound(&resp, 35);
        let recs = p.take_records();
        assert_eq!(
            recs.len(),
            1,
            "field-4 request_id must pair, not fall to FIFO"
        );
        assert_eq!(recs[0].operation, "LOOKUP b");
        assert_eq!(recs[0].start_unix_nano, 20);
        assert_eq!(recs[0].duration_nano, 15);
    }

    #[test]
    fn partitioned_metadata_response_pairs_by_request_id_at_field_two() {
        // CommandPartitionedTopicMetadataResponse carries request_id at field 2;
        // field 1 is `partitions` (a varint!). Reading field 1 would have mis-keyed
        // on the partition count — here partitions=4, request_id=300, and the request
        // uses id 300, so a field-1 read would NOT pair (and a field-1 read of value 4
        // could steal an unrelated id-4 request). Prove it pairs on 300.
        let mut p = PulsarParser::new();
        // A decoy request whose id equals the partition count (4) must NOT be stolen.
        p.on_inbound(
            &simple_frame(cmd::PARTITIONED_METADATA, &{
                let mut m = pb_string(1, "decoy");
                m.extend(pb_varint(2, 4)); // request_id 4 == the response's partitions
                m
            }),
            5,
        );
        p.on_inbound(
            &simple_frame(cmd::PARTITIONED_METADATA, &{
                let mut m = pb_string(1, "real");
                m.extend(pb_varint(2, 300)); // request_id 300
                m
            }),
            10,
        );
        let resp = simple_frame(cmd::PARTITIONED_METADATA_RESPONSE, &{
            let mut m = pb_varint(1, 4); // partitions = 4 (must NOT be used as the key)
            m.extend(pb_varint(2, 300)); // request_id = 300
            m
        });
        p.on_outbound(&resp, 18);
        let recs = p.take_records();
        assert_eq!(
            recs.len(),
            1,
            "must pair on field-2 request_id, not field-1 partitions"
        );
        assert_eq!(
            recs[0].start_unix_nano, 10,
            "paired the id-300 request, not the id-4 decoy"
        );
        assert_eq!(recs[0].duration_nano, 8);
        // The decoy (id 4) is still outstanding — never stolen by the partitions=4 value.
        assert_eq!(p.pending.len(), 1);
    }

    #[test]
    fn connect_pairs_connected_by_fifo() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::CONNECT, &pb_string(1, "client-v1"));
        let resp = simple_frame(cmd::CONNECTED, &pb_string(1, "broker-v1"));
        let recs = record(&mut p, &req, 100, &resp, 130);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 30);
    }

    #[test]
    fn interleaved_responses_pair_by_request_id_not_arrival_order() {
        // Two requests; the broker replies out of request order. request_id, not
        // FIFO, must pair each reply to its own request.
        let mut p = PulsarParser::new();
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("a", 1, 100)), 10);
        p.on_inbound(&simple_frame(cmd::SUBSCRIBE, &subscribe("b", 200)), 20);
        // Reply to 200 (SUBSCRIBE) FIRST, then 100 (PRODUCER).
        p.on_outbound(
            &simple_frame(cmd::SUCCESS, &response_with_request_id(200)),
            30,
        );
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(100)),
            40,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SUBSCRIBE b");
        assert_eq!(recs[0].start_unix_nano, 20);
        assert_eq!(recs[0].duration_nano, 10);
        assert_eq!(recs[1].operation, "PRODUCER a");
        assert_eq!(recs[1].start_unix_nano, 10);
        assert_eq!(recs[1].duration_nano, 30);
    }

    #[test]
    fn pipelined_requests_then_responses_all_pair() {
        let mut p = PulsarParser::new();
        let mut reqs = simple_frame(cmd::PRODUCER, &producer("p", 1, 1));
        reqs.extend(simple_frame(cmd::SUBSCRIBE, &subscribe("s", 2)));
        reqs.extend(simple_frame(cmd::LOOKUP, &{
            let mut m = pb_string(1, "l");
            m.extend(pb_varint(2, 3));
            m
        }));
        p.on_inbound(&reqs, 100);
        let mut resps = simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(1));
        resps.extend(simple_frame(cmd::SUCCESS, &response_with_request_id(2)));
        // CommandLookupTopicResponse carries request_id at field 4, not field 1.
        resps.extend(simple_frame(cmd::LOOKUP_RESPONSE, &{
            let mut m = pb_string(1, "pulsar://broker:6650");
            m.extend(pb_varint(4, 3));
            m
        }));
        p.on_outbound(&resps, 200);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "PRODUCER p");
        assert_eq!(recs[1].operation, "SUBSCRIBE s");
        assert_eq!(recs[2].operation, "LOOKUP l");
    }

    #[test]
    fn oneway_commands_are_framed_past_not_paired() {
        // A PING (oneway) on the response side must not consume a pending request.
        let mut p = PulsarParser::new();
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("t", 1, 5)), 1);
        // PING has no nested body to read; it frames past.
        p.on_outbound(&simple_frame(18, &[]), 2); // PING
        assert!(p.take_records().is_empty());
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(5)),
            3,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PRODUCER t");
    }

    #[test]
    fn fragmented_request_waits_then_completes() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::PRODUCER, &producer("topicX", 1, 77));
        // Feed the size header + only part of the command: must wait (no pending yet).
        let split = FRAME_HEADER_LEN + 2;
        p.on_inbound(&req[..split], 10);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // A reply now would have nothing to pair with.
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(77)),
            20,
        );
        assert!(
            p.take_records().is_empty(),
            "must not pair against an unparsed request"
        );
        // Deliver the rest of the request, then the real reply.
        p.on_inbound(&req[split..], 30);
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(77)),
            50,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PRODUCER topicX");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn fragmented_response_waits_for_full_command() {
        let mut p = PulsarParser::new();
        p.on_inbound(&simple_frame(cmd::SUBSCRIBE, &subscribe("t", 8)), 1);
        let resp = simple_frame(cmd::SUCCESS, &response_with_request_id(8));
        // Only the size header + 1 command byte: must wait.
        p.on_outbound(&resp[..FRAME_HEADER_LEN + 1], 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_outbound(&resp[FRAME_HEADER_LEN + 1..], 9);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE t");
        assert_eq!(recs[0].duration_nano, 8);
    }

    #[test]
    fn large_send_payload_split_across_segments_frames_past() {
        // A Send whose message payload dwarfs a single segment must frame past via
        // DirBuf::skip, then the next pipelined request still pairs.
        let mut p = PulsarParser::new();
        let big = frame(&base_command(cmd::SEND, &send(1, 1)), &vec![0xab; 6000]);
        p.on_inbound(&big[..1000], 10);
        p.on_inbound(&big[1000..], 11);
        // A second request right after.
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("t", 2, 2)), 12);
        // Replies: SEND_RECEIPT for the send, PRODUCER_SUCCESS for the producer.
        p.on_outbound(&simple_frame(cmd::SEND_RECEIPT, &send_ack(1, 1)), 20);
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(2)),
            21,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SEND");
        assert_eq!(recs[1].operation, "PRODUCER t");
    }

    #[test]
    fn orphan_response_with_unknown_request_id_is_dropped() {
        let mut p = PulsarParser::new();
        // Reply for an id we never saw a request for (attached mid-connection).
        p.on_outbound(
            &simple_frame(cmd::SUCCESS, &response_with_request_id(999)),
            5,
        );
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn unmatched_request_id_does_not_steal_another_pending() {
        // Two requests in flight (ids 10, 20). A response carrying request_id 999
        // matches neither and must be DROPPED — not paired against the oldest.
        let mut p = PulsarParser::new();
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("a", 1, 10)), 1);
        p.on_inbound(&simple_frame(cmd::SUBSCRIBE, &subscribe("b", 20)), 2);
        p.on_outbound(
            &simple_frame(cmd::SUCCESS, &response_with_request_id(999)),
            3,
        );
        assert!(
            p.take_records().is_empty(),
            "unmatched request_id must drop, not steal"
        );
        // The genuine replies still pair correctly.
        p.on_outbound(
            &simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(10)),
            4,
        );
        p.on_outbound(
            &simple_frame(cmd::SUCCESS, &response_with_request_id(20)),
            5,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "PRODUCER a");
        assert_eq!(recs[0].duration_nano, 3); // 4 - 1, not stolen by the 999 reply at ts 3
        assert_eq!(recs[1].operation, "SUBSCRIBE b");
    }

    #[test]
    fn garbage_command_marks_parser_dead() {
        let mut p = PulsarParser::new();
        // A well-sized frame whose command's first field is NOT a field-1 varint
        // type — the stream is desynced.
        let bad = frame(&[tag(2, WIRE_LEN), vec![0x01, 0xff]].concat(), &[]);
        p.on_inbound(&bad, 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn insane_frame_size_marks_dead() {
        let mut p = PulsarParser::new();
        // totalSize < 4 + commandSize: framing invariant violated.
        let mut bad = Vec::new();
        bad.extend_from_slice(&3u32.to_be_bytes()); // totalSize 3
        bad.extend_from_slice(&50u32.to_be_bytes()); // commandSize 50
        bad.extend_from_slice(&[0u8; 8]);
        p.on_inbound(&bad, 1);
        assert!(p.is_dead());
    }

    #[test]
    fn unanswered_request_flood_is_bounded_and_dies() {
        let mut p = PulsarParser::new();
        // Many distinct-request_id producers, no replies — past the cap.
        let mut flood = Vec::new();
        for rid in 0..(MAX_INFLIGHT as u64 + 50) {
            flood.extend(simple_frame(cmd::PRODUCER, &producer("t", rid, rid)));
        }
        p.on_inbound(&flood, 1);
        assert!(
            p.is_dead(),
            "an unanswered-request flood must mark the parser dead"
        );
        assert!(p.pending.len() <= MAX_INFLIGHT + 1);
        // Dead parsers ignore further input.
        p.on_inbound(&simple_frame(cmd::PRODUCER, &producer("t", 0, 0)), 2);
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        let mut p = PulsarParser::new();
        let req = simple_frame(cmd::PRODUCER, &producer("topic", 1, 314));
        for byte in req.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let resp = simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(314));
        let last = (resp.len() - 1) as i64;
        for (i, byte) in resp.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PRODUCER topic");
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, (2_000 + last) - 1_000);
    }

    /// HARD REQUIREMENT: never panic on adversarial bytes, in any framing, on either
    /// direction, at any fragmentation. The only acceptable outcomes are "dead",
    /// "waiting", or a (possibly wrong-but-bounded) record — never a panic or
    /// unbounded buffering.
    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        let valid_req = simple_frame(cmd::PRODUCER, &producer("t", 1, 5));
        let valid_resp = simple_frame(cmd::PRODUCER_SUCCESS, &response_with_request_id(5));
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff],
            vec![0x00, 0x00, 0x00],       // size field truncated
            vec![0x00, 0x00, 0x00, 0x00], // totalSize 0
            vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02], // huge totalSize
            {
                // valid sizes, but command claims 2 bytes and only 1 present
                let mut v = 6u32.to_be_bytes().to_vec();
                v.extend_from_slice(&2u32.to_be_bytes());
                v.push(0x08);
                v
            },
            {
                // commandSize huge relative to totalSize
                let mut v = 8u32.to_be_bytes().to_vec();
                v.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
                v
            },
            {
                // BaseCommand whose nested message length overruns the command
                let mut cmd = pb_varint(1, cmd::PRODUCER);
                cmd.extend(tag(cmd::PRODUCER, WIRE_LEN));
                cmd.extend(varint(1_000_000)); // claims a megabyte nested
                cmd.push(0x0a);
                frame(&cmd, &[])
            },
            {
                // type varint that never terminates (all continuation bits)
                let mut cmd = tag(1, WIRE_VARINT);
                cmd.extend_from_slice(&[0x80; 12]);
                frame(&cmd, &[])
            },
            {
                // a producer whose topic length field overruns
                let mut m = tag(1, WIRE_LEN);
                m.extend(varint(1_000_000));
                m.extend_from_slice(b"short");
                simple_frame(cmd::PRODUCER, &m)
            },
            valid_req.clone(),
            valid_resp.clone(),
            simple_frame(cmd::SEND, &send(1, 1)),
            simple_frame(cmd::CONNECT, &pb_string(1, "v")),
            (0u8..=255).collect(),
            vec![0x00; 64],
            vec![0x08; 256], // many field-1 varint tags
        ];

        for payload in &payloads {
            // Detection must never panic.
            let _ = detect_pulsar(payload);

            // Whole-buffer, both directions.
            let mut p = PulsarParser::new();
            p.on_inbound(payload, 1);
            p.on_outbound(payload, 2);
            let _ = p.take_records();
            let _ = p.is_dead();

            // Split at every boundary, both directions, both orders.
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                let _ = detect_pulsar(a);

                let mut q = PulsarParser::new();
                q.on_inbound(a, 1);
                q.on_inbound(b, 2);
                let _ = q.take_records();
                let _ = q.is_dead();

                // Response side with a real request outstanding (exercise pairing).
                let mut r = PulsarParser::new();
                r.on_inbound(&valid_req, 0);
                r.on_outbound(a, 1);
                r.on_outbound(b, 2);
                let _ = r.take_records();
                let _ = r.is_dead();
            }
        }
    }
}
