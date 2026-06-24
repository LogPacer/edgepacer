//! Memcached wire parser — implements [`super::L7Parser`].
//!
//! Memcached speaks two protocols on the same port, and a connection commits to
//! one with its first request, so we sniff the opening bytes and frame only that
//! dialect for the connection's life:
//!
//!   * **Text** — a request is a command line `get <key>\r\n`, `set <key> <flags>
//!     <exptime> <bytes>\r\n<data>\r\n`, `delete <key>\r\n`, … The verb is the
//!     first token, uppercased, and becomes the span operation. Storage commands
//!     (`set`/`add`/`replace`/`append`/`prepend`/`cas`) carry a `<bytes>`-long data
//!     block + CRLF after the command line, which we frame past via [`DirBuf`]
//!     without decoding. Responses are status lines (`STORED`, `DELETED`,
//!     `NOT_FOUND`, `END`, …) or a `VALUE <key> <flags> <bytes>\r\n<data>\r\nEND`
//!     block. The failure verdict is `ERROR` / `CLIENT_ERROR` / `SERVER_ERROR`.
//!     Text is strictly request-then-response, so a FIFO queue pairs them.
//!
//!   * **Binary** — a 24-byte header: magic (`0x80` request, `0x81` response),
//!     opcode, `keylen` (u16 BE), `extlen` (u8), datatype, status/reserved (u16),
//!     `totalBodyLen` (u32 BE), `opaque` (u32), `cas` (u64), then a `totalBodyLen`
//!     body. The opcode names the operation; a non-zero response `status` is the
//!     failure verdict. Binary replies may be reordered and the client correlates
//!     by `opaque`, so we pair on `opaque` rather than FIFO.
//!
//! Hand-rolled framing, no crate: both dialects are a trivial line / fixed-header
//! grammar and leanness is the agent's moat. We decode only the span fields — the
//! operation label, the error verdict, and timing — never keys or payload bytes.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Protocol tag stamped on every record this parser mints.
const PROTOCOL: Protocol = Protocol::Memcached;

/// Fixed size of a binary-protocol header (magic … cas), before the body.
const BINARY_HEADER_LEN: usize = 24;

/// Request / response magic bytes that open every binary-protocol frame.
const MAGIC_REQUEST: u8 = 0x80;
const MAGIC_RESPONSE: u8 = 0x81;

/// Text command verbs we recognise as a positive detection signature. The full
/// command set is larger, but these are the verbs a connection realistically
/// opens with; an unrecognised opener returns `None` (we'd rather miss than
/// mis-claim another protocol's bytes).
const TEXT_VERBS: [&str; 13] = [
    "get", "gets", "set", "add", "replace", "append", "prepend", "cas", "delete", "incr", "decr",
    "touch", "stats",
];

/// Storage verbs whose command line is followed by a `<bytes>`-long data block and
/// a trailing CRLF. `<bytes>` is the 5th token (`verb key flags exptime bytes …`);
/// `cas` appends `<cas-unique>` and either may end with an optional `noreply` — see
/// [`storage_data_len`], which indexes `<bytes>` from the front, never the end.
const STORAGE_VERBS: [&str; 6] = ["set", "add", "replace", "append", "prepend", "cas"];

/// Verbs that accept a trailing optional `noreply` token suppressing the server
/// reply. Only these may treat a final `noreply` as the suppress flag; for any
/// other verb (`get`, `gets`, `stats`, …) a trailing `noreply` is just an argument
/// (e.g. a key literally named `noreply`) and the server still replies.
const NOREPLY_VERBS: [&str; 10] = [
    "set", "add", "replace", "append", "prepend", "cas", "delete", "incr", "decr", "touch",
];

/// Opcode → operation label for the binary protocol. Only the common opcodes are
/// named; anything else falls back to `OP_0x<hex>` so the stream still frames and
/// pairs cleanly (we never need the name to advance, only to label the span).
fn binary_opcode_label(opcode: u8) -> String {
    match opcode {
        0x00 => "GET".to_string(),
        0x01 => "SET".to_string(),
        0x02 => "ADD".to_string(),
        0x03 => "REPLACE".to_string(),
        0x04 => "DELETE".to_string(),
        0x05 => "INCREMENT".to_string(),
        0x06 => "DECREMENT".to_string(),
        0x07 => "QUIT".to_string(),
        0x08 => "FLUSH".to_string(),
        0x09 => "GETQ".to_string(),
        0x0a => "NOOP".to_string(),
        0x0b => "VERSION".to_string(),
        0x0c => "GETK".to_string(),
        0x0d => "GETKQ".to_string(),
        0x0e => "APPEND".to_string(),
        0x0f => "PREPEND".to_string(),
        0x10 => "STAT".to_string(),
        0x11 => "SETQ".to_string(),
        0x1c => "TOUCH".to_string(),
        other => format!("OP_0x{other:02x}"),
    }
}

// ---------------------------------------------------------------------------
// Framing primitives
// ---------------------------------------------------------------------------

/// Outcome of framing one message at the front of a direction buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame<T> {
    /// A complete message: its extracted value plus how many bytes it occupies.
    Complete { value: T, total_len: usize },
    /// Valid-so-far but the buffer doesn't hold the whole message yet — wait.
    Partial,
    /// Not well-formed for this dialect — drop the connection.
    Invalid,
}

/// Index just past the next CRLF at or after `from`, i.e. the offset of the byte
/// after `\n`. `None` if no complete line is buffered yet.
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

/// A u16 read big-endian from `bytes[at..at+2]`, or `None` if out of range.
fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// A u32 read big-endian from `bytes[at..at+4]`, or `None` if out of range.
fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

// ---------------------------------------------------------------------------
// Text dialect
// ---------------------------------------------------------------------------

/// The first whitespace-delimited token of a command line, lowercased for lookups.
/// Empty when the line is blank.
fn first_token(line: &[u8]) -> &[u8] {
    line.split(|&b| b == b' ' || b == b'\t')
        .find(|t| !t.is_empty())
        .unwrap_or(&[])
}

/// True when a command line ends with the optional `noreply` token, which tells
/// the server to suppress the reply. Only meaningful for the verbs in
/// [`NOREPLY_VERBS`]; the caller gates on that so a key literally named `noreply`
/// on a non-mutating verb isn't mistaken for the flag. A `noreply` request must be
/// framed but never enqueued for pairing — no response will ever arrive to pop it,
/// and FIFO pairing would otherwise shift every later request onto the wrong reply.
fn is_noreply(line: &[u8]) -> bool {
    line.split(|&b| b == b' ' || b == b'\t')
        .rfind(|t| !t.is_empty())
        == Some(&b"noreply"[..])
}

/// For a storage command line (`set <key> <flags> <exptime> <bytes> [noreply]` /
/// `cas <key> <flags> <exptime> <bytes> <cas-unique> [noreply]`), the declared
/// `<bytes>` length of the data block that follows. `None` if the line is malformed
/// (too few tokens or a non-numeric byte count) — the caller treats that as invalid.
///
/// `<bytes>` is always the 5th token (index 4) counted from the front: `verb key
/// flags exptime bytes …`. We index from the front, never from the end, because an
/// optional trailing `noreply` token (and, for `cas`, the `<cas-unique>` token) sit
/// after `<bytes>` — end-relative indexing would read those and desync the body.
fn storage_data_len(line: &[u8], is_cas: bool) -> Option<usize> {
    let tokens: Vec<&[u8]> = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|t| !t.is_empty())
        .collect();
    // verb key flags exptime bytes [cas-unique] [noreply]
    let min_tokens = if is_cas { 6 } else { 5 };
    if tokens.len() < min_tokens {
        return None;
    }
    // <bytes> is positional: token index 4, the same slot for set and cas.
    std::str::from_utf8(tokens[4])
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()
}

/// A framed text request: its operation label and whether the server will reply.
/// A `noreply` request is framed past the wire but emits no pending pairing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TextRequest {
    label: String,
    expects_reply: bool,
}

/// Frame one text request at the front of `buf`: the command line, plus (for
/// storage verbs) the trailing `<bytes>`-long data block and its CRLF. Returns the
/// verb uppercased, whether a reply is expected (`noreply` suppresses it), and the
/// total byte length to advance.
fn frame_text_request(buf: &[u8]) -> Frame<TextRequest> {
    let Some(line_stop) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let line = &buf[..line_stop - 2];
    let token = first_token(line);
    if token.is_empty() {
        return Frame::Invalid;
    }
    let verb_lower = token.to_ascii_lowercase();
    let verb = String::from_utf8_lossy(token).to_ascii_uppercase();
    // Only noreply-capable verbs let a trailing `noreply` suppress the reply; for
    // `get`/`gets`/`stats` it would just be an argument, so they always expect one.
    let accepts_noreply = NOREPLY_VERBS
        .iter()
        .any(|v| v.as_bytes() == verb_lower.as_slice());
    let expects_reply = !(accepts_noreply && is_noreply(line));

    let is_storage = STORAGE_VERBS
        .iter()
        .any(|v| v.as_bytes() == verb_lower.as_slice());
    if !is_storage {
        return Frame::Complete {
            value: TextRequest {
                label: verb,
                expects_reply,
            },
            total_len: line_stop,
        };
    }

    let is_cas = verb_lower == b"cas";
    let Some(data_len) = storage_data_len(line, is_cas) else {
        return Frame::Invalid;
    };
    // command line + <data> + trailing CRLF. `checked_add` so a hostile <bytes>
    // (up to usize::MAX) can never overflow; an absurd length just waits forever.
    let Some(total_len) = line_stop
        .checked_add(data_len)
        .and_then(|n| n.checked_add(2))
    else {
        return Frame::Partial;
    };
    if buf.len() < total_len {
        return Frame::Partial;
    }
    Frame::Complete {
        value: TextRequest {
            label: verb,
            expects_reply,
        },
        total_len,
    }
}

/// The verdict a text response renders for the paired span: its error flag and the
/// total byte length so the stream advances past the whole reply (including a
/// `VALUE … <bytes>\r\n<data>\r\nEND\r\n` block).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TextVerdict {
    is_error: bool,
}

/// Frame one text response at the front of `buf`. A `VALUE` line opens a value
/// block whose `<data>` body and terminating `END` line are framed past; every
/// other reply is a single status line. The failure verdict is `ERROR`,
/// `CLIENT_ERROR`, or `SERVER_ERROR`.
fn frame_text_response(buf: &[u8]) -> Frame<TextVerdict> {
    let Some(line_stop) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let line = &buf[..line_stop - 2];
    let token = first_token(line);

    if token == b"VALUE" {
        return frame_value_block(buf, line_stop);
    }
    // A `stats` reply is many `STAT <name> <value>\r\n` lines closed by `END\r\n`.
    // Frame the whole block as one response, or the trailing STAT lines and END
    // would pop later requests and desync pairing.
    if token == b"STAT" {
        return frame_stat_block(buf, line_stop);
    }

    let is_error = matches!(token, b"ERROR" | b"CLIENT_ERROR" | b"SERVER_ERROR");
    Frame::Complete {
        value: TextVerdict { is_error },
        total_len: line_stop,
    }
}

/// Frame a `stats` reply: a run of `STAT <name> <value>\r\n` lines terminated by an
/// `END\r\n` line. `first_line_stop` is the offset past the first `STAT` line's
/// CRLF. Lines carry no body length, so we just scan line-by-line until `END`,
/// waiting (`Partial`) if the terminator isn't buffered yet.
fn frame_stat_block(buf: &[u8], first_line_stop: usize) -> Frame<TextVerdict> {
    let mut line_stop = first_line_stop;
    loop {
        let Some(next) = line_end(buf, line_stop) else {
            return Frame::Partial;
        };
        let token = first_token(&buf[line_stop..next - 2]);
        match token {
            b"STAT" => line_stop = next,
            b"END" => {
                return Frame::Complete {
                    value: TextVerdict { is_error: false },
                    total_len: next,
                };
            }
            _ => return Frame::Invalid,
        }
    }
}

/// Frame a `get`/`gets` value block: one or more `VALUE <key> <flags> <bytes>\r\n
/// <data>\r\n` entries terminated by an `END\r\n` line. `first_line_stop` is the
/// offset past the first `VALUE` line's CRLF. We never decode `<data>`; we only
/// read each `<bytes>` to skip the body, then look for the next `VALUE` or `END`.
fn frame_value_block(buf: &[u8], first_line_stop: usize) -> Frame<TextVerdict> {
    let mut pos = 0usize;
    loop {
        // Frame the current line (the first iteration reuses the already-found
        // VALUE line; later iterations re-scan).
        let line_stop = if pos == 0 {
            first_line_stop
        } else {
            match line_end(buf, pos) {
                Some(end) => end,
                None => return Frame::Partial,
            }
        };
        let line = &buf[pos..line_stop - 2];
        let token = first_token(line);
        match token {
            b"END" => {
                return Frame::Complete {
                    value: TextVerdict { is_error: false },
                    total_len: line_stop,
                };
            }
            b"VALUE" => {
                let Some(data_len) = value_line_data_len(line) else {
                    return Frame::Invalid;
                };
                // <data> + trailing CRLF after the VALUE line. `checked_add` so a
                // hostile <bytes> can never overflow; an absurd length just waits.
                let Some(next) = line_stop
                    .checked_add(data_len)
                    .and_then(|n| n.checked_add(2))
                else {
                    return Frame::Partial;
                };
                if buf.len() < next {
                    return Frame::Partial;
                }
                pos = next;
            }
            // Anything else between VALUE entries is malformed.
            _ => return Frame::Invalid,
        }
    }
}

/// The `<bytes>` field of a `VALUE <key> <flags> <bytes>` line (the 4th token, or
/// 4th-of-5 when a `gets` cas-unique trails). `None` if malformed.
fn value_line_data_len(line: &[u8]) -> Option<usize> {
    let tokens: Vec<&[u8]> = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|t| !t.is_empty())
        .collect();
    // VALUE key flags bytes [cas-unique]
    if tokens.len() < 4 {
        return None;
    }
    std::str::from_utf8(tokens[3])
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()
}

// ---------------------------------------------------------------------------
// Binary dialect
// ---------------------------------------------------------------------------

/// A framed binary request: opcode label, correlation opaque, and total length.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryRequest {
    label: String,
    opaque: u32,
}

/// A framed binary response: correlation opaque, status code, and total length.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryResponse {
    opaque: u32,
    status: u16,
}

/// Validate the shared header invariant: `keylen + extlen <= totalBodyLen`. A
/// header that violates it isn't a real binary frame (the key+extras can't be
/// larger than the whole body). Returns `(total_body_len, opaque)` when sane.
fn binary_body_fields(buf: &[u8]) -> Option<(usize, u32)> {
    let keylen = be_u16(buf, 2)? as usize;
    let extlen = *buf.get(4)? as usize;
    let total_body = be_u32(buf, 8)? as usize;
    let opaque = be_u32(buf, 12)?;
    if keylen + extlen > total_body {
        return None;
    }
    Some((total_body, opaque))
}

/// Frame one binary request (magic `0x80`) at the front of `buf`.
fn frame_binary_request(buf: &[u8]) -> Frame<BinaryRequest> {
    if buf.len() < BINARY_HEADER_LEN {
        return Frame::Partial;
    }
    if buf[0] != MAGIC_REQUEST {
        return Frame::Invalid;
    }
    let Some((total_body, opaque)) = binary_body_fields(buf) else {
        return Frame::Invalid;
    };
    let total_len = BINARY_HEADER_LEN + total_body;
    if buf.len() < total_len {
        return Frame::Partial;
    }
    Frame::Complete {
        value: BinaryRequest {
            label: binary_opcode_label(buf[1]),
            opaque,
        },
        total_len,
    }
}

/// Frame one binary response (magic `0x81`) at the front of `buf`. The 2-byte
/// field at offset 6 is the response `status` (non-zero = error).
fn frame_binary_response(buf: &[u8]) -> Frame<BinaryResponse> {
    if buf.len() < BINARY_HEADER_LEN {
        return Frame::Partial;
    }
    if buf[0] != MAGIC_RESPONSE {
        return Frame::Invalid;
    }
    let Some((total_body, opaque)) = binary_body_fields(buf) else {
        return Frame::Invalid;
    };
    let Some(status) = be_u16(buf, 6) else {
        return Frame::Invalid;
    };
    let total_len = BINARY_HEADER_LEN + total_body;
    if buf.len() < total_len {
        return Frame::Partial;
    }
    Frame::Complete {
        value: BinaryResponse { opaque, status },
        total_len,
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// The dialect a connection committed to, decided once from its opening request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Text,
    Binary,
}

/// True if `buf` opens with a recognised text command verb delimited by a space,
/// tab, or CRLF (`get foo\r\n`). The delimiter check stops `getter` matching `get`.
///
/// One unavoidable collision: `GET `/`get ` opens both an HTTP request and a
/// Memcached `get`, so this returns true for an HTTP `GET` line too. A byte-only
/// signature can't separate them; the detector resolves it by trying HTTP first or
/// using the connection's port hint. Every other text verb here is Memcached-only.
fn looks_like_text(buf: &[u8]) -> bool {
    TEXT_VERBS.iter().any(|verb| {
        let vb = verb.as_bytes();
        buf.len() >= vb.len()
            && buf[..vb.len()].eq_ignore_ascii_case(vb)
            && matches!(
                buf.get(vb.len()),
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')
            )
    })
}

/// True if `buf` opens with a plausible binary request header: the `0x80` magic
/// and the `keylen + extlen <= totalBodyLen` invariant. Conservative: a binary
/// protocol with no port hint must not false-positive, so we require the full
/// 24-byte header before deciding (a shorter prefix waits — see [`detect_memcached`]).
fn looks_like_binary(buf: &[u8]) -> bool {
    // Detection also requires datatype (byte 5) == 0x00 (RAW_BYTES). The classic
    // binary protocol never sets any other datatype on the wire, so demanding it
    // sharply cuts false-positives on other protocols whose first byte is 0x80
    // without rejecting any real frame. This is a detection-only guard — framing
    // (binary_body_fields) stays lenient once a connection has committed.
    buf.len() >= BINARY_HEADER_LEN
        && buf[0] == MAGIC_REQUEST
        && buf[5] == 0x00
        && binary_body_fields(buf).is_some()
}

/// Recognise Memcached from a connection's inbound prefix and return a fresh boxed
/// parser, or `None` if these bytes aren't a Memcached request. A positive
/// signature, never a guess. Phase 4 wires this into `super::conn::detect`.
///
/// Conservative by construction: the text path requires a known verb followed by a
/// real delimiter; the binary path requires the `0x80` magic *and* a self-
/// consistent header (`keylen + extlen <= totalBodyLen`). When the prefix is too
/// short to confirm the binary header we return `None` rather than guess — the
/// detector re-runs as more inbound bytes arrive.
pub(crate) fn detect_memcached(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if looks_like_text(inbound) {
        Some(Box::new(MemcachedParser::with_dialect(Dialect::Text)))
    } else if looks_like_binary(inbound) {
        Some(Box::new(MemcachedParser::with_dialect(Dialect::Binary)))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// A request awaiting its reply, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    label: String,
    start_unix_nano: i64,
}

/// Memcached [`L7Parser`]: reassembles each direction, frames the connection's
/// committed dialect, pairs requests to replies (text FIFO, binary by `opaque`),
/// and emits one [`L7Record`] per pair. Unrecoverable bytes mark it dead so the
/// connection is dropped.
///
/// `dialect` is `None` only for a [`Default`]-constructed parser (used by tests
/// and the derive); it is committed on the first inbound bytes if still unset. In
/// production [`detect_memcached`] always sets it before the parser is bound.
#[derive(Debug, Default)]
pub(crate) struct MemcachedParser {
    dialect: Option<Dialect>,
    inbound: DirBuf,
    outbound: DirBuf,
    /// Text pairing: oldest-first queue of unanswered requests.
    pending: VecDeque<Pending>,
    /// Binary pairing: requests keyed by `opaque` (replies may reorder).
    pending_by_opaque: Vec<(u32, Pending)>,
    records: Vec<L7Record>,
    dead: bool,
}

impl MemcachedParser {
    fn with_dialect(dialect: Dialect) -> Self {
        Self {
            dialect: Some(dialect),
            ..Self::default()
        }
    }

    /// Commit the dialect from the first inbound bytes if it isn't set yet (covers
    /// a `Default`-constructed parser). Leaves it unset — waiting — if the prefix
    /// is too short to decide.
    fn ensure_dialect(&mut self) {
        if self.dialect.is_some() {
            return;
        }
        if looks_like_text(&self.inbound.buf) {
            self.dialect = Some(Dialect::Text);
        } else if looks_like_binary(&self.inbound.buf) {
            self.dialect = Some(Dialect::Binary);
        }
    }

    fn drain_inbound(&mut self, ts: i64) {
        match self.dialect {
            Some(Dialect::Text) => self.drain_text_inbound(ts),
            Some(Dialect::Binary) => self.drain_binary_inbound(ts),
            None => {}
        }
    }

    fn drain_outbound(&mut self, ts: i64) {
        match self.dialect {
            Some(Dialect::Text) => self.drain_text_outbound(ts),
            Some(Dialect::Binary) => self.drain_binary_outbound(ts),
            None => {}
        }
    }

    fn drain_text_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() || self.inbound.buf.is_empty() {
                return;
            }
            match frame_text_request(&self.inbound.buf) {
                Frame::Complete { value, total_len } => {
                    // `noreply` requests get no response — frame past them but never
                    // enqueue, or FIFO pairing would pop them against a later reply.
                    if value.expects_reply {
                        self.pending.push_back(Pending {
                            label: value.label,
                            start_unix_nano: ts,
                        });
                    }
                    self.inbound.advance(total_len);
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    fn drain_text_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() || self.outbound.buf.is_empty() {
                return;
            }
            match frame_text_response(&self.outbound.buf) {
                Frame::Complete { value, total_len } => {
                    if let Some(req) = self.pending.pop_front() {
                        self.emit(req, value.is_error, value.is_error as u16, ts);
                    }
                    self.outbound.advance(total_len);
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    fn drain_binary_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() || self.inbound.buf.is_empty() {
                return;
            }
            match frame_binary_request(&self.inbound.buf) {
                Frame::Complete { value, total_len } => {
                    self.pending_by_opaque.push((
                        value.opaque,
                        Pending {
                            label: value.label,
                            start_unix_nano: ts,
                        },
                    ));
                    self.inbound.advance(total_len);
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    fn drain_binary_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() || self.outbound.buf.is_empty() {
                return;
            }
            match frame_binary_response(&self.outbound.buf) {
                Frame::Complete { value, total_len } => {
                    if let Some(idx) = self
                        .pending_by_opaque
                        .iter()
                        .position(|(op, _)| *op == value.opaque)
                    {
                        let (_, req) = self.pending_by_opaque.remove(idx);
                        self.emit(req, value.status != 0, value.status, ts);
                    }
                    self.outbound.advance(total_len);
                }
                Frame::Partial => return,
                Frame::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Emit one paired record, flooring the duration at 0 so clock skew can't
    /// produce a negative latency that poisons RED.
    fn emit(&mut self, req: Pending, error: bool, status_code: u16, ts: i64) {
        self.records.push(L7Record {
            protocol: PROTOCOL,
            attributes: Vec::new(),
            operation: req.label,
            status_code,
            error,
            start_unix_nano: req.start_unix_nano,
            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
        });
    }
}

impl L7Parser for MemcachedParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.inbound.buf.extend_from_slice(bytes);
        self.ensure_dialect();
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

    /// Build a binary frame: magic, opcode, key+extras+value sized to `body`,
    /// status (responses) or 0 (requests), and `opaque`.
    fn binary_frame(
        magic: u8,
        opcode: u8,
        keylen: u16,
        extlen: u8,
        status: u16,
        opaque: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(BINARY_HEADER_LEN + body.len());
        v.push(magic);
        v.push(opcode);
        v.extend_from_slice(&keylen.to_be_bytes());
        v.push(extlen);
        v.push(0); // datatype
        v.extend_from_slice(&status.to_be_bytes()); // status (resp) / reserved (req)
        v.extend_from_slice(&(body.len() as u32).to_be_bytes()); // totalBodyLen
        v.extend_from_slice(&opaque.to_be_bytes());
        v.extend_from_slice(&0u64.to_be_bytes()); // cas
        v.extend_from_slice(body);
        v
    }

    // -- detection -----------------------------------------------------------

    #[test]
    fn detects_text_verbs_by_positive_signature() {
        assert!(looks_like_text(b"get foo\r\n"));
        assert!(looks_like_text(b"GET foo\r\n")); // case-insensitive
        assert!(looks_like_text(b"set k 0 0 3\r\nabc\r\n"));
        assert!(looks_like_text(b"delete k\r\n"));
        assert!(looks_like_text(b"stats\r\n"));
        // Not text: unknown verb, undelimited verb, random binary.
        assert!(!looks_like_text(b"getter foo\r\n")); // delimiter check
        assert!(!looks_like_text(b"FOO bar\r\n"));
        assert!(!looks_like_text(b"\x16\x03\x01\x02"));
        // KNOWN COLLISION: `GET ` opens both an HTTP request and a Memcached `get`.
        // A byte-only signature cannot tell them apart, so this DOES match here —
        // disambiguation is the detector's job (try HTTP first, or use the port
        // hint). Documented so a future reader doesn't "tighten" this and break it.
        assert!(looks_like_text(b"GET /x HTTP/1.1\r\n"));
    }

    #[test]
    fn detects_binary_magic_with_a_sane_header() {
        let req = binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 1, b"key");
        assert!(looks_like_binary(&req));
        // Wrong magic, or an inconsistent header (keylen > body), must not match.
        let mut bad_magic = req.clone();
        bad_magic[0] = 0x99;
        assert!(!looks_like_binary(&bad_magic));
        let lying = binary_frame(MAGIC_REQUEST, 0x00, 50, 0, 0, 1, b"key"); // keylen 50 > body 3
        assert!(!looks_like_binary(&lying));
        // A short prefix can't confirm the header — conservative miss.
        assert!(!looks_like_binary(&req[..10]));
        // A non-zero datatype (byte 5) is never the classic protocol — reject, so
        // another 0x80-leading binary stream with a self-consistent length field
        // (keylen+extlen <= total_body holds trivially when both are 0) can't be
        // mis-claimed as memcached on detection.
        let mut wrong_datatype = req.clone();
        wrong_datatype[5] = 0x04;
        assert!(!looks_like_binary(&wrong_datatype));
        // Concretely: 0x80 + zeroed length fields + a junk datatype must NOT match.
        let mut decoy = vec![0u8; BINARY_HEADER_LEN];
        decoy[0] = MAGIC_REQUEST;
        decoy[5] = 0x07; // datatype the classic protocol never uses
        assert!(!looks_like_binary(&decoy));
        assert!(detect_memcached(&decoy).is_none());
    }

    #[test]
    fn detect_memcached_returns_a_parser_only_on_a_match() {
        assert!(detect_memcached(b"get foo\r\n").is_some());
        assert!(
            detect_memcached(&binary_frame(
                MAGIC_REQUEST,
                0x01,
                3,
                8,
                0,
                7,
                b"keyXXXXXXXXX"
            ))
            .is_some()
        );
        assert!(detect_memcached(b"not memcached at all").is_none());
        assert!(detect_memcached(b"\x00\x01\x02\x03").is_none());
    }

    // -- text framing --------------------------------------------------------

    #[test]
    fn text_get_request_response_yields_one_record() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get foo\r\n", 1_000);
        p.on_outbound(b"VALUE foo 0 3\r\nbar\r\nEND\r\n", 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn text_get_miss_returns_end_only() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get missing\r\n", 1);
        p.on_outbound(b"END\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(!recs[0].error);
    }

    #[test]
    fn text_set_frames_past_the_data_block() {
        // The data block (3 bytes "abc" + CRLF) must be skipped, not parsed as a
        // second command. STORED is the success reply.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"set k 0 0 3\r\nabc\r\n", 10);
        p.on_outbound(b"STORED\r\n", 25);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SET");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 15);
        assert!(p.pending.is_empty());
    }

    #[test]
    fn text_cas_reads_bytes_from_the_correct_token() {
        // cas <key> <flags> <exptime> <bytes> <cas-unique> — <bytes>=3 is the 5th
        // token (index 4). Reading the trailing cas-unique (42) as the byte count
        // would frame a 42-byte block and desync the stream.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"cas k 0 0 3 42\r\nabc\r\n", 1);
        p.on_outbound(b"STORED\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CAS");
        assert!(p.pending.is_empty());
    }

    #[test]
    fn text_set_noreply_frames_without_desync() {
        // `set <key> <flags> <exptime> <bytes> noreply\r\n<data>\r\n` — the optional
        // trailing `noreply` token means <bytes> is NOT the last token. Reading the
        // last token would parse "noreply" as the byte count (or kill the connection),
        // desyncing the data block. <bytes> is positional (index 4), not last.
        // With noreply the server sends no reply for the set, so the only response
        // here is END for the following get, which must pair with the get.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"set k 0 0 3 noreply\r\nabc\r\n", 1);
        p.on_inbound(b"get k\r\n", 2);
        p.on_outbound(b"END\r\n", 3);
        let recs = p.take_records();
        assert!(!p.is_dead(), "noreply storage line must frame, not die");
        // The set's data block was framed past cleanly, so the get's reply pairs
        // with the get — not with a mis-framed remnant.
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
    }

    #[test]
    fn text_cas_noreply_reads_bytes_not_cas_unique() {
        // `cas <key> <flags> <exptime> <bytes> <cas-unique> noreply\r\n<data>\r\n` —
        // with noreply the last token is "noreply" and the second-to-last is the
        // cas-unique. <bytes>=3 is positional (index 4). End-relative indexing would
        // read the cas-unique (or noreply) and desync the 3-byte data block.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"cas k 0 0 3 42 noreply\r\nabc\r\n", 1);
        p.on_inbound(b"get k\r\n", 2);
        p.on_outbound(b"END\r\n", 3);
        let recs = p.take_records();
        assert!(!p.is_dead(), "cas noreply line must frame, not die");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
    }

    #[test]
    fn text_delete_noreply_is_not_queued() {
        // `delete k noreply\r\n` gets no reply. If we queued it, the next request's
        // reply would pop the delete and shift pairing. Only the get must pair here.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"delete k noreply\r\n", 1);
        p.on_inbound(b"get k\r\n", 2);
        p.on_outbound(b"END\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(p.pending.is_empty());
    }

    #[test]
    fn text_get_of_key_named_noreply_still_pairs() {
        // `get` does NOT accept noreply, so a key literally named "noreply" must not
        // be mistaken for the suppress flag — the server still replies and we pair.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get noreply\r\n", 1);
        p.on_outbound(b"END\r\n", 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[0].duration_nano, 3); // it really did pair with the reply
        assert!(p.pending.is_empty());
    }

    #[test]
    fn text_delete_and_incr_label_by_verb() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"delete k\r\n", 1);
        p.on_inbound(b"incr k 5\r\n", 2);
        p.on_outbound(b"DELETED\r\n", 3);
        p.on_outbound(b"6\r\n", 4); // incr returns the new value
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "DELETE");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "INCR");
        assert!(!recs[1].error);
    }

    #[test]
    fn text_error_replies_set_the_failure_verdict() {
        for (reply, _label) in [
            (&b"ERROR\r\n"[..], "ERROR"),
            (&b"CLIENT_ERROR bad data chunk\r\n"[..], "CLIENT_ERROR"),
            (&b"SERVER_ERROR out of memory\r\n"[..], "SERVER_ERROR"),
        ] {
            let mut p = MemcachedParser::with_dialect(Dialect::Text);
            p.on_inbound(b"get foo\r\n", 0);
            p.on_outbound(reply, 5);
            let recs = p.take_records();
            assert_eq!(recs.len(), 1);
            assert!(recs[0].error, "{reply:?} must be an error");
            assert_eq!(recs[0].status_code, 1);
        }
    }

    #[test]
    fn text_not_stored_and_not_found_are_not_errors() {
        // NOT_STORED / NOT_FOUND are protocol-level "no" answers, not failures —
        // RED must not count a cache miss as an error.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"add k 0 0 1\r\nx\r\n", 1);
        p.on_inbound(b"delete gone\r\n", 2);
        p.on_outbound(b"NOT_STORED\r\n", 3);
        p.on_outbound(b"NOT_FOUND\r\n", 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert!(!recs[0].error);
        assert!(!recs[1].error);
    }

    #[test]
    fn text_fragmented_request_waits_instead_of_misparsing() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        // Storage command line arrived but the data block hasn't.
        p.on_inbound(b"set k 0 0 3\r\nab", 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // partial, not garbage
        assert!(p.pending.is_empty(), "must not queue a half-framed request");
        p.on_inbound(b"c\r\n", 1);
        p.on_outbound(b"STORED\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SET");
    }

    #[test]
    fn text_fragmented_value_block_waits_for_the_full_body() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get foo\r\n", 1);
        // VALUE header says 5 bytes but only 2 are here, and no END yet — wait.
        p.on_outbound(b"VALUE foo 0 5\r\nhe", 2);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_outbound(b"llo\r\nEND\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[0].duration_nano, 2);
    }

    #[test]
    fn text_stats_multiline_reply_is_one_response() {
        // `stats\r\n` answers with many `STAT <name> <value>\r\n` lines terminated by
        // `END\r\n`. Treating the first STAT line as a complete single-line response
        // would pop the stats request early, then frame each remaining STAT line +
        // END as separate responses that pop later requests — desyncing all pairing.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"stats\r\n", 1);
        p.on_inbound(b"get after\r\n", 2);
        p.on_outbound(
            b"STAT pid 123\r\nSTAT uptime 456\r\nSTAT version 1.6.0\r\nEND\r\n",
            3,
        );
        p.on_outbound(b"END\r\n", 5); // the get's miss reply, observed at ts=5
        let recs = p.take_records();
        assert_eq!(
            recs.len(),
            2,
            "stats block + get must be exactly two records"
        );
        assert_eq!(recs[0].operation, "STATS");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 2); // stats: req ts=1, reply ts=3
        // The get pairs with its OWN END (ts=5), not a stray STAT line from the
        // stats block (ts=3). A desync would give the get duration 1, not 3.
        assert_eq!(recs[1].operation, "GET");
        assert!(!recs[1].error);
        assert_eq!(recs[1].duration_nano, 3); // get: req ts=2, reply ts=5
        assert!(p.pending.is_empty());
    }

    #[test]
    fn text_fragmented_stats_block_waits_for_end() {
        // A STAT block split before its END must WAIT, not pair half a reply.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"stats\r\n", 1);
        p.on_outbound(b"STAT pid 123\r\nSTAT uptime 4", 2); // mid-line, no END
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_outbound(b"56\r\nEND\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "STATS");
    }

    #[test]
    fn text_pipelined_requests_pair_in_arrival_order() {
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get a\r\nget b\r\n", 100);
        p.on_outbound(b"END\r\nVALUE b 0 1\r\nx\r\nEND\r\n", 130);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[1].operation, "GET");
        assert!(!recs[0].error);
        assert!(!recs[1].error);
    }

    #[test]
    fn text_multi_value_block_frames_all_entries() {
        // `get a b` can return two VALUE entries before END; all must be framed past
        // as one logical reply paired with the single multi-get request.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"gets a b\r\n", 1);
        p.on_outbound(b"VALUE a 0 1 11\r\nx\r\nVALUE b 0 1 12\r\ny\r\nEND\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GETS");
        assert!(!recs[0].error);
    }

    // -- binary framing ------------------------------------------------------

    #[test]
    fn binary_request_response_yields_one_record() {
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        let req = binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 42, b"foo");
        let resp = binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0, 42, b"bar");
        p.on_inbound(&req, 1_000);
        p.on_outbound(&resp, 1_700);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 700);
    }

    #[test]
    fn binary_nonzero_status_is_an_error() {
        // status 0x0001 = "key not found".
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        p.on_inbound(&binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 7, b"foo"), 1);
        p.on_outbound(
            &binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0x0001, 7, b"Not found"),
            2,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn binary_pairs_by_opaque_not_arrival_order() {
        // Two requests outstanding; replies arrive REORDERED. FIFO pairing would
        // mislabel; opaque correlation must keep each reply on its own request.
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        p.on_inbound(&binary_frame(MAGIC_REQUEST, 0x00, 1, 0, 0, 100, b"a"), 1); // GET opaque 100
        p.on_inbound(
            &binary_frame(MAGIC_REQUEST, 0x01, 1, 8, 0, 200, b"bXXXXXXXXX"),
            2,
        ); // SET opaque 200
        // SET's reply (200) comes back first, then GET's (100) with an error.
        p.on_outbound(&binary_frame(MAGIC_RESPONSE, 0x01, 0, 0, 0, 200, b""), 3);
        p.on_outbound(
            &binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0x0001, 100, b"x"),
            4,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        // First emitted is the SET reply (opaque 200), success.
        assert_eq!(recs[0].operation, "SET");
        assert!(!recs[0].error);
        // Second is the GET reply (opaque 100), error.
        assert_eq!(recs[1].operation, "GET");
        assert!(recs[1].error);
        assert!(p.pending_by_opaque.is_empty());
    }

    #[test]
    fn binary_fragmented_header_waits() {
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        let req = binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 1, b"foo");
        // Feed less than the 24-byte header.
        p.on_inbound(&req[..12], 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        assert!(p.pending_by_opaque.is_empty());
        // Rest of the request, then its reply.
        p.on_inbound(&req[12..], 1);
        p.on_outbound(&binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0, 1, b"v"), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
    }

    #[test]
    fn binary_fragmented_body_waits() {
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        let req = binary_frame(MAGIC_REQUEST, 0x01, 3, 8, 0, 1, b"keyXXXXXXXXXvalue");
        let split = BINARY_HEADER_LEN + 5; // mid-body
        p.on_inbound(&req[..split], 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        assert!(
            p.pending_by_opaque.is_empty(),
            "body incomplete: must not queue"
        );
        p.on_inbound(&req[split..], 1);
        p.on_outbound(&binary_frame(MAGIC_RESPONSE, 0x01, 0, 0, 0, 1, b""), 2);
        assert_eq!(p.take_records().len(), 1);
    }

    #[test]
    fn binary_invalid_magic_marks_dead() {
        let mut p = MemcachedParser::with_dialect(Dialect::Binary);
        let mut req = binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 1, b"foo");
        req[0] = 0x55; // not a request magic
        p.on_inbound(&req, 1);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    // -- shared ---------------------------------------------------------------

    #[test]
    fn orphan_response_with_no_pending_request_is_dropped() {
        // Text: attached mid-connection, missed the request.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_outbound(b"STORED\r\n", 0);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // Binary: a reply whose opaque matches nothing pending is dropped.
        let mut q = MemcachedParser::with_dialect(Dialect::Binary);
        q.on_outbound(&binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0, 999, b""), 0);
        assert!(q.take_records().is_empty());
        assert!(!q.is_dead());
    }

    #[test]
    fn default_parser_commits_dialect_from_first_inbound() {
        // A Default-constructed parser (no detector) sniffs its first inbound bytes.
        let mut p = MemcachedParser::default();
        p.on_inbound(b"get foo\r\n", 1);
        p.on_outbound(b"END\r\n", 2);
        assert_eq!(p.take_records()[0].operation, "GET");

        let mut q = MemcachedParser::default();
        q.on_inbound(&binary_frame(MAGIC_REQUEST, 0x00, 3, 0, 0, 5, b"foo"), 1);
        q.on_outbound(&binary_frame(MAGIC_RESPONSE, 0x00, 0, 0, 0, 5, b"v"), 2);
        assert_eq!(q.take_records()[0].operation, "GET");
    }

    #[test]
    fn negative_clock_skew_is_floored_to_zero() {
        // Response observed BEFORE the request (clock skew) must yield duration 0,
        // never a negative that would poison RED.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get foo\r\n", 1_000);
        p.on_outbound(b"END\r\n", 900); // earlier than the request
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duration_nano, 0);
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: feed hostile/truncated payloads at every byte boundary, both
        // directions, in both dialects. The hard requirement is no panic, ever — a
        // wrong verdict is acceptable, a crash is not.
        let payloads: &[&[u8]] = &[
            b"get\r\n",                                 // verb with no key
            b"set k 0 0\r\n",                           // storage line missing <bytes>
            b"set k 0 0 notanumber\r\n",                // non-numeric byte count
            b"set k 0 0 99999999\r\nx\r\n",             // body shorter than declared
            b"cas k 0 0 3\r\nabc\r\n",                  // cas missing cas-unique token
            b"VALUE\r\n",                               // value line with no fields
            b"VALUE k 0 5\r\n",                         // value header, no body or END
            b"\r\n\r\n",                                // only CRLFs
            b"\x80",                                    // lone binary magic
            b"\x80\x00\xff\xff",                        // binary magic + huge keylen, truncated
            b"\x81\x00\x00\x00\x00\x00\xff\xff",        // response, truncated header
            &[0x80; 24],                                // all-magic 24 bytes (huge bodylen)
            &[0xff; 48],                                // raw binary
            b"\x00\x01\x02\x03",                        // junk
            b"incr\r\n",                                // incr no value
            b"stats\r\n",                               // bare stats
            b"set k 0 0 noreply\r\n",                   // noreply where <bytes> belongs
            b"set k 0 0 18446744073709551615\r\nx\r\n", // <bytes> = usize::MAX
            b"cas k 0 0 18446744073709551615 1\r\n",    // cas <bytes> = usize::MAX
            b"STAT a 1\r\nSTAT b 2\r\n",                // stats block, never terminated
            b"STAT a 1\r\nGARBAGE\r\nEND\r\n",          // junk line inside a stats block
            b"VALUE k 0 18446744073709551615\r\n",      // value <bytes> = usize::MAX
            b"delete k noreply\r\n",                    // noreply delete (no reply expected)
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                for dialect in [Dialect::Text, Dialect::Binary] {
                    // request side
                    let mut p = MemcachedParser::with_dialect(dialect);
                    p.on_inbound(a, 1);
                    p.on_inbound(b, 2);
                    let _ = p.take_records();
                    // response side (prime a request so pairing paths run)
                    let mut q = MemcachedParser::with_dialect(dialect);
                    q.on_inbound(b"get x\r\n", 0);
                    q.on_outbound(a, 1);
                    q.on_outbound(b, 2);
                    let _ = q.take_records();
                }
                // dialect-undecided path: Default parser sniffing hostile bytes.
                let mut d = MemcachedParser::default();
                d.on_inbound(a, 1);
                d.on_inbound(b, 2);
                let _ = d.take_records();
            }
        }
    }

    #[test]
    fn binary_huge_bodylen_waits_never_overflows() {
        // A header declaring a body far larger than buffered must frame as Partial
        // (we never have that many bytes), not panic on `24 + total_body`.
        let mut buf = vec![MAGIC_REQUEST, 0x00];
        buf.extend_from_slice(&0u16.to_be_bytes()); // keylen 0
        buf.push(0); // extlen
        buf.push(0); // datatype
        buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
        buf.extend_from_slice(&u32::MAX.to_be_bytes()); // totalBodyLen = 4 GiB
        buf.extend_from_slice(&1u32.to_be_bytes()); // opaque
        buf.extend_from_slice(&0u64.to_be_bytes()); // cas
        assert_eq!(frame_binary_request(&buf), Frame::Partial);
    }

    #[test]
    fn text_storage_bytes_near_usize_max_never_overflows() {
        // A hostile `<bytes>` of usize::MAX must frame as Partial (we never hold that
        // many bytes), not panic computing `line_stop + data_len + 2`.
        let line = format!("set k 0 0 {}\r\n", usize::MAX);
        assert_eq!(frame_text_request(line.as_bytes()), Frame::Partial);
        // Drive it through the parser too: hostile length must not panic or desync.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(line.as_bytes(), 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // waiting for an impossible body, not garbage
    }

    #[test]
    fn text_value_block_bytes_near_usize_max_never_overflows() {
        // Same overflow guard on the response VALUE-block body length.
        let mut p = MemcachedParser::with_dialect(Dialect::Text);
        p.on_inbound(b"get k\r\n", 1);
        let reply = format!("VALUE k 0 {}\r\n", usize::MAX);
        p.on_outbound(reply.as_bytes(), 2);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }
}
