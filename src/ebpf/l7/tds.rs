//! SQL Server (TDS — Tabular Data Stream) wire parser — implements
//! [`super::L7Parser`], the zero-code APM producer for SQL Server connections.
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every TDS message rides one or more *packets*, each prefixed by an 8-byte
//! header: `[type:1][status:1][length:u16 BE][SPID:u16][PacketID:1][Window:1]`.
//! `length` is the TOTAL packet size *including* the 8-byte header (big-endian —
//! the one big-endian field in an otherwise little-endian protocol). So
//! `total_len = length`, `payload = packet[8..length]`.
//!
//! A logical message can span several packets: the header `status` bit `0x01`
//! ("EOM", end-of-message) marks the last packet of a message; intermediate
//! packets clear it. We reassemble a request message's payload across packets
//! until EOM, then label it.
//!
//! ## What we extract (and only this)
//!
//!   * **SQLBatch (type `0x01`)** — payload is (after an optional ALL_HEADERS
//!     block in TDS 7.2+) a UCS-2 / UTF-16LE SQL string. `operation` = the SQL
//!     verb (`SELECT`/`INSERT`/…), uppercased, plus the first referenced table
//!     when cleanly recoverable (`SELECT users`) — exactly the Postgres/MySQL
//!     label scheme, so spans read uniformly across SQL engines.
//!   * **RPC (type `0x03`)** — a stored-procedure call. The payload begins with an
//!     ALL_HEADERS block then `NameLenProcID`: either a `us_varchar` proc name
//!     (UTF-16LE, `u16` char count prefix) or the special form `0xFFFF` followed
//!     by a `u16` well-known proc id. `operation` = `EXEC <ProcName>` (or
//!     `EXEC #<id>` for the well-known form).
//!   * **Login7 (`0x10`) / PreLogin (`0x12`)** — handshake messages. We frame past
//!     them (label `LOGIN` / `PRELOGIN`) so the stream stays aligned; they pair
//!     with their response token streams like any other exchange.
//!
//! Responses are a *token stream*. We scan top-level tokens only for the error
//! verdict: an **ERROR** token (`0xAA`) carries a 4-byte error `Number` → `error =
//! true`, `status_code = (Number & 0xFFFF)`. A **DONE/DONEPROC/DONEINPROC** token
//! (`0xFD`/`0xFE`/`0xFF`) carries a `Status` whose `0x0002` ("Error") or `0x0100`
//! ("SrvError" — sent in place of Error for severe failures) bit is also treated as a
//! failure. The scan stops at the first DONE-family token *without* the `0x0001`
//! ("More") bit — that is the final DONE of the response; bytes past it belong to a
//! later exchange. We do not decode result-set rows — only the tokens whose length we
//! can compute to advance, stopping the (best-effort) scan otherwise.
//!
//! NOTE: TDS 7.x is plaintext on the wire after the PreLogin/TLS handshake; TDS
//! 8.0 wraps everything in TLS, which our TLS uprobe decrypts before it reaches
//! us — either way we parse plaintext TDS packets here.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Packet header is fixed at 8 bytes.
const HEADER_LEN: usize = 8;

/// Packet `type` byte values we recognise. Requests are SQLBatch / RPC / Login7 /
/// PreLogin; everything else (TransactionManager `0x0E`, BulkLoad `0x07`, …) is
/// framed past unlabelled but still pairs as a request.
const TYPE_SQL_BATCH: u8 = 0x01;
const TYPE_RPC: u8 = 0x03;
const TYPE_LOGIN7: u8 = 0x10;
const TYPE_PRELOGIN: u8 = 0x12;

/// Packet `status` bit set on the final packet of a multi-packet message ("EOM",
/// end-of-message). Intermediate packets of a long request clear it.
const STATUS_EOM: u8 = 0x01;

/// Response token type bytes we act on. ERROR carries the error number; the DONE
/// family carries a status word whose Error bit is a second failure signal.
const TOKEN_ERROR: u8 = 0xAA;
const TOKEN_INFO: u8 = 0xAB;
const TOKEN_LOGINACK: u8 = 0xAD;
const TOKEN_ENVCHANGE: u8 = 0xE3;
const TOKEN_DONE: u8 = 0xFD;
const TOKEN_DONEPROC: u8 = 0xFE;
const TOKEN_DONEINPROC: u8 = 0xFF;

/// DONE-token `Status` flags. `MORE` marks a non-final DONE in a multi-statement
/// response (more token streams follow); the final DONE of the response clears it.
/// `ERROR` and the severe `SRVERROR` (sent *in place of* `ERROR` when the failure
/// is severe enough to discard the result set) both mean the command failed.
const DONE_STATUS_MORE: u16 = 0x0001;
const DONE_STATUS_ERROR: u16 = 0x0002;
const DONE_STATUS_SRVERROR: u16 = 0x0100;
/// Either error bit signals a failed command.
const DONE_STATUS_FAILED: u16 = DONE_STATUS_ERROR | DONE_STATUS_SRVERROR;

/// The `NameLenProcID` sentinel marking a well-known (numeric) stored procedure
/// instead of an inline UTF-16 name.
const RPC_PROCID_SENTINEL: u16 = 0xFFFF;

/// Sanity bound on a single reassembled message. A genuine TDS packet's `length`
/// is a `u16` (≤ 65535) so one packet is tiny, but a long batch can span many
/// packets; we cap the reassembled total to bound memory on a hostile/desynced
/// stream that never sets EOM. SQL we care about for a span label lives in the
/// first few KB; 16 MB is generous and still a hard ceiling.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// Read a big-endian u16 from the first two bytes of `b` (caller guarantees len).
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Read a little-endian u16 from the first two bytes of `b` (caller guarantees len).
fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// Read a little-endian u32 from the first four bytes of `b` (caller guarantees len).
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// A parsed packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacketHeader {
    packet_type: u8,
    eom: bool,
    total_len: usize,
}

/// Outcome of reading one packet head off a direction buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed packet header and the total bytes the packet occupies.
    Framed(PacketHeader),
    /// A valid prefix but not enough bytes yet — wait.
    Partial,
    /// Not TDS framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Is this a packet `type` byte we recognise as a valid TDS message type? Used
/// both to frame (any recognised type frames) and as the detection signature.
fn is_known_type(t: u8) -> bool {
    matches!(
        t,
        TYPE_SQL_BATCH
            | TYPE_RPC
            | 0x04 // TabularResult (response)
            | 0x06 // Attention
            | TYPE_LOGIN7
            | 0x0E // TransactionManagerRequest
            | TYPE_PRELOGIN
            | 0x07 // BulkLoad / Federated-auth token
            | 0x08 // SSPI
            | 0x0F // FeatureExtAck-bearing / TDS 7.4 SQLBatch w/ headers variant
            | 0x11 // SSPI handshake (pre-TDS7)
    )
}

/// Parse one packet head from a buffer prefix. Any header with a known type and a
/// sane length frames; an unknown type or a length below the header size is the
/// desync signal (`Invalid`).
fn parse_head(buf: &[u8]) -> Head {
    if buf.len() < HEADER_LEN {
        return Head::Partial;
    }
    let packet_type = buf[0];
    if !is_known_type(packet_type) {
        return Head::Invalid;
    }
    let status = buf[1];
    let length = be_u16(&buf[2..4]) as usize;
    // `length` counts the 8-byte header; below that is impossible framing.
    if length < HEADER_LEN {
        return Head::Invalid;
    }
    Head::Framed(PacketHeader {
        packet_type,
        eom: status & STATUS_EOM != 0,
        total_len: length,
    })
}

/// Decode a UTF-16LE byte slice (an even number of bytes) to a `String`, lossily.
/// Odd trailing byte is ignored. Unpaired surrogates become the replacement char.
fn decode_utf16le(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Strip the optional ALL_HEADERS block that prefixes a SQLBatch / RPC payload in
/// TDS 7.2+. Per MS-TDS its layout is `ALL_HEADERS = TotalLength 1*Header`, where
/// `TotalLength` is a `u32 LE` counting itself and each `Header` is
/// `[HeaderLength:u32 LE (incl. itself, ≥ 6)][HeaderType:u16 LE][data]`. We only
/// need to skip it.
///
/// A SQLBatch from a pre-7.2 client (or one that omits the block) has no such
/// prefix — its first bytes are the UTF-16 SQL text. We must NOT mis-read those as
/// a length and skip real query bytes. So we accept the prefix as ALL_HEADERS only
/// when it *structurally validates*: `TotalLength` lands inside the payload (leaving
/// content after it) AND its sub-headers tile `[4, TotalLength)` exactly — each
/// header well-formed and summing to the declared total. Arbitrary SQL text whose
/// first four bytes merely look like a plausible length essentially never satisfies
/// the full sub-header tiling, which is what the old length-only check missed.
///
/// Returns the offset of the SQL/RPC content proper (0 when there is no valid block).
fn skip_all_headers(payload: &[u8]) -> usize {
    if !all_headers_valid(payload) {
        return 0;
    }
    le_u32(&payload[0..4]) as usize
}

/// True when `payload` begins with a structurally valid TDS ALL_HEADERS block whose
/// content leaves at least one byte of SQL/RPC body after it. Walks the sub-headers
/// and requires they tile the declared `TotalLength` exactly (no panics on any
/// malformed/truncated/hostile length).
fn all_headers_valid(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let total = le_u32(&payload[0..4]) as usize;
    // Must cover its own 4-byte TotalLength plus ≥1 header, and leave body after it.
    if total < 4 + 6 || total >= payload.len() {
        return false;
    }
    let mut pos = 4;
    while pos < total {
        // Each header needs at least HeaderLength(4) + HeaderType(2).
        if pos + 6 > total {
            return false;
        }
        let header_len = le_u32(&payload[pos..pos + 4]) as usize;
        if header_len < 6 {
            return false;
        }
        // The header must fit within the declared total without overflowing it.
        match pos.checked_add(header_len) {
            Some(next) if next <= total => pos = next,
            _ => return false,
        }
    }
    // Sub-headers must tile [4, total) exactly — landing past `total` is malformed.
    pos == total
}

/// Extract the operation label from a fully reassembled request message.
fn label_for(packet_type: u8, payload: &[u8]) -> String {
    match packet_type {
        TYPE_SQL_BATCH => sql_batch_label(payload),
        TYPE_RPC => rpc_label(payload),
        TYPE_LOGIN7 => "LOGIN".to_string(),
        TYPE_PRELOGIN => "PRELOGIN".to_string(),
        _ => "BATCH".to_string(),
    }
}

/// Label a SQLBatch: decode the UTF-16LE SQL text (after any ALL_HEADERS block)
/// and build the verb/table label.
fn sql_batch_label(payload: &[u8]) -> String {
    let off = skip_all_headers(payload);
    let sql = decode_utf16le(&payload[off..]);
    label_from_sql(&sql)
}

/// Label an RPC call: `EXEC <ProcName>`. The payload is `[ALL_HEADERS]
/// [NameLenProcID]…`, where `NameLenProcID` is either `[len:u16 LE][name UTF-16LE]`
/// or the sentinel `0xFFFF` followed by a `[procId:u16 LE]` well-known id.
fn rpc_label(payload: &[u8]) -> String {
    let off = skip_all_headers(payload);
    let rest = &payload[off..];
    if rest.len() < 2 {
        return "EXEC".to_string();
    }
    let name_len = le_u16(&rest[0..2]);
    if name_len == RPC_PROCID_SENTINEL {
        // Well-known stored proc by numeric id.
        if rest.len() >= 4 {
            let proc_id = le_u16(&rest[2..4]);
            return format!("EXEC #{proc_id}");
        }
        return "EXEC".to_string();
    }
    // Inline UTF-16LE name of `name_len` *characters* (2 bytes each).
    let bytes = name_len as usize * 2;
    let start = 2;
    let name = rest
        .get(start..start + bytes)
        .map(decode_utf16le)
        .unwrap_or_default();
    if name.is_empty() {
        "EXEC".to_string()
    } else {
        format!("EXEC {name}")
    }
}

/// Build the operation label from raw SQL text: the verb, plus the first table
/// name for the verbs where it's unambiguous. Mirrors the Postgres/MySQL scheme so
/// spans read uniformly across SQL engines.
fn label_from_sql(sql: &str) -> String {
    let mut tokens = sql.split_whitespace();
    let Some(verb_raw) = tokens.next() else {
        return "BATCH".to_string();
    };
    let verb = verb_raw.to_ascii_uppercase();
    if let Some(table) = first_table(&verb, sql) {
        format!("{verb} {table}")
    } else {
        verb
    }
}

/// Find the first table referenced after the verb's table keyword. Conservative:
/// only the keywords whose next token is reliably a table name, with trailing
/// punctuation stripped. Returns `None` when nothing clean is found (label = verb).
fn first_table(verb: &str, sql: &str) -> Option<String> {
    let keyword: &str = match verb {
        "SELECT" | "DELETE" => "from",
        "INSERT" => "into",
        "UPDATE" => "update",
        _ => return None,
    };
    let lower = sql.to_ascii_lowercase();
    let lower_tokens: Vec<&str> = lower.split_whitespace().collect();
    let raw_tokens: Vec<&str> = sql.split_whitespace().collect();
    let idx = if verb == "UPDATE" {
        1
    } else {
        lower_tokens.iter().position(|&t| t == keyword)? + 1
    };
    let raw = raw_tokens.get(idx)?;
    let cleaned: String = raw
        .trim_matches(|c: char| {
            c == '(' || c == ')' || c == ';' || c == ',' || c == '"' || c == '[' || c == ']'
        })
        .to_string();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// The error verdict of a response token stream. We scan top-level tokens, sizing
/// each so we can advance to the next, until we hit an ERROR token, a DONE-family
/// token with the Error status bit, or run out of decodable tokens. A token we
/// cannot size ends the (best-effort) scan with whatever verdict we have so far.
///
/// Returns `(error, status_code)`. `status_code` is the ERROR token's `Number`
/// (low 16 bits) when present, else 0.
fn response_verdict(buf: &[u8]) -> (bool, u16) {
    let mut pos = 0usize;
    // Bound the walk against a hostile stream that never terminates a token.
    for _ in 0..4096 {
        let Some(&token) = buf.get(pos) else {
            return (false, 0);
        };
        match token {
            TOKEN_ERROR => {
                // ERROR token: [0xAA][Length:u16 LE][Number:u32 LE][State:1]…
                // The Length covers everything after the length field. The Number
                // is the SQL Server error number (e.g. 208 = invalid object name).
                let len = match buf.get(pos + 1..pos + 3) {
                    Some(b) => le_u16(b) as usize,
                    None => return (true, 0),
                };
                let number = buf
                    .get(pos + 3..pos + 7)
                    .map(|b| (le_u32(b) & 0xFFFF) as u16)
                    .unwrap_or(0);
                // An ERROR token is a definitive failure verdict; stop here.
                let _ = len;
                return (true, number);
            }
            TOKEN_INFO => {
                // INFO token shares ERROR's layout but is NOT a failure. Skip it.
                let Some(len) = buf.get(pos + 1..pos + 3).map(|b| le_u16(b) as usize) else {
                    return (false, 0);
                };
                pos += 3 + len;
            }
            TOKEN_DONE | TOKEN_DONEPROC | TOKEN_DONEINPROC => {
                // DONE family: [token][Status:u16 LE][CurCmd:u16 LE][RowCount].
                // (RowCount is u64 in TDS 7.2+, u32 before — we never read it, only
                // Status, so its width is irrelevant.) Either error bit fails the
                // command. We stop at the FIRST DONE without the MORE bit: that is the
                // final DONE of *this* response. Continuing past it would let a later
                // statement's clean DONE, or — in a coalesced buffer — the next
                // response's tokens, flip the verdict; and guessing the RowCount width
                // to skip ahead would desync the walk. The final DONE is the boundary.
                let status = match buf.get(pos + 1..pos + 3) {
                    Some(b) => le_u16(b),
                    None => return (false, 0),
                };
                let failed = status & DONE_STATUS_FAILED != 0;
                if failed || status & DONE_STATUS_MORE == 0 {
                    return (failed, 0);
                }
                // A non-final (MORE) DONE: advance over it and keep scanning. RowCount
                // is u64 in the TDS versions we parse (7.2+ plaintext), so the token is
                // token(1) + Status(2) + CurCmd(2) + RowCount(8) = 13 bytes.
                pos += 13;
            }
            TOKEN_ENVCHANGE => {
                // ENVCHANGE: [0xE3][Length:u16 LE][payload]. Skip by its length.
                let Some(len) = buf.get(pos + 1..pos + 3).map(|b| le_u16(b) as usize) else {
                    return (false, 0);
                };
                pos += 3 + len;
            }
            TOKEN_LOGINACK => {
                // LOGINACK: [0xAD][Length:u16 LE][payload]. Length-prefixed.
                let Some(len) = buf.get(pos + 1..pos + 3).map(|b| le_u16(b) as usize) else {
                    return (false, 0);
                };
                pos += 3 + len;
            }
            // Any token we don't know how to size: stop the best-effort scan. We
            // never guess a length, which would risk reading a bogus error verdict.
            _ => return (false, 0),
        }
    }
    (false, 0)
}

/// A request awaiting its response token stream, with the observation time.
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// SQL Server (TDS) [`L7Parser`]: reassembles request packets into messages (across
/// EOM), labels SQLBatch/RPC/handshake requests, pairs each with its response token
/// stream FIFO, and yields one [`L7Record`] per pair. Desync marks it dead.
#[derive(Debug, Default)]
pub(crate) struct TdsParser {
    request: DirBuf,
    response: DirBuf,
    /// Bytes of the in-progress (multi-packet) request message accumulated so far,
    /// plus the type of its first packet and the time the first packet arrived.
    msg_payload: Vec<u8>,
    msg_type: Option<u8>,
    msg_started_nano: i64,
    /// Accumulated response-packet payload for the in-progress response message.
    resp_payload: Vec<u8>,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl TdsParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reassemble request packets into messages. Each request packet's payload is
    /// appended to the current message; on EOM the message is labelled and queued.
    fn drain_request(&mut self, ts: i64) {
        loop {
            if !self.request.drain_skip() {
                return;
            }
            if self.request.buf.is_empty() {
                return;
            }
            match parse_head(&self.request.buf) {
                Head::Framed(h) => {
                    // We need the whole packet to read its payload. If it straddles,
                    // wait — advancing would skip the body as framing and lose data.
                    if h.total_len > self.request.buf.len() {
                        return;
                    }
                    if self.msg_type.is_none() {
                        self.msg_type = Some(h.packet_type);
                        self.msg_started_nano = ts;
                    }
                    let payload = &self.request.buf[HEADER_LEN..h.total_len];
                    if self.msg_payload.len() + payload.len() <= MAX_MESSAGE_LEN {
                        self.msg_payload.extend_from_slice(payload);
                    } else {
                        // Runaway message (no EOM) — desync.
                        self.dead = true;
                        return;
                    }
                    self.request.advance(h.total_len);
                    if h.eom {
                        let packet_type = self.msg_type.take().unwrap_or(TYPE_SQL_BATCH);
                        let operation = label_for(packet_type, &self.msg_payload);
                        self.pending.push_back(Pending {
                            operation,
                            start_unix_nano: self.msg_started_nano,
                        });
                        self.msg_payload.clear();
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

    /// Reassemble response packets into a token stream. On EOM we scan the stream
    /// for the error verdict and pair it with the oldest pending request.
    fn drain_response(&mut self, ts: i64) {
        loop {
            if !self.response.drain_skip() {
                return;
            }
            if self.response.buf.is_empty() {
                return;
            }
            match parse_head(&self.response.buf) {
                Head::Framed(h) => {
                    if h.total_len > self.response.buf.len() {
                        return;
                    }
                    let payload = &self.response.buf[HEADER_LEN..h.total_len];
                    if self.resp_payload.len() + payload.len() <= MAX_MESSAGE_LEN {
                        self.resp_payload.extend_from_slice(payload);
                    } else {
                        self.dead = true;
                        return;
                    }
                    self.response.advance(h.total_len);
                    if h.eom {
                        let (error, status_code) = response_verdict(&self.resp_payload);
                        self.resp_payload.clear();
                        self.complete(error, status_code, ts);
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

    /// Pair a completed response with the oldest pending request and emit a record.
    /// A response with no pending request is dropped (we attached mid-connection).
    fn complete(&mut self, error: bool, status_code: u16, ts: i64) {
        if let Some(req) = self.pending.pop_front() {
            self.records.push(L7Record {
                protocol: Protocol::Tds,
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

impl L7Parser for TdsParser {
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

/// Recognise SQL Server (TDS) from a connection's inbound prefix via a POSITIVE
/// signature and return a fresh boxed parser, or `None` if it isn't (yet)
/// recognisable.
///
/// Byte-only detection of a binary protocol is inherently weak — TDS has no magic
/// number — so this is deliberately CONSERVATIVE to avoid false positives on other
/// binary traffic (a TCP port hint of 1433 makes it reliable and should gate this
/// detector when a port is known; see [`new_parser`]). We require, all of:
///   * a full 8-byte header buffered;
///   * a `type` byte that is a *request* type (`0x01` SQLBatch / `0x03` RPC /
///     `0x10` Login7 / `0x12` PreLogin) — not just any known type, which would
///     admit response packets and collide more readily;
///   * the big-endian `length` ≥ 8 (covers the header) and, once that first packet
///     is fully buffered, the packet must be the EOM (single-packet) opener AND its
///     payload must *structurally validate* for its type — a SQLBatch whose UTF-16
///     text yields a recognised SQL verb, an RPC whose name field is well-formed,
///     or a Login7/PreLogin handshake. Requiring a parseable body (not just a
///     plausible header) is what suppresses collisions on the two length bytes any
///     binary stream presents, the same guard MongoDB's detector uses.
///
/// While the header is buffered but the packet hasn't fully arrived we return
/// `None` (the registry keeps buffering and retries) rather than guess. A coalesced
/// first segment carrying the opener packet plus pipelined bytes still binds — only
/// the first packet must validate.
pub(crate) fn detect_tds(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if inbound.len() < HEADER_LEN {
        return None;
    }
    let packet_type = inbound[0];
    let is_request_type = matches!(
        packet_type,
        TYPE_SQL_BATCH | TYPE_RPC | TYPE_LOGIN7 | TYPE_PRELOGIN
    );
    if !is_request_type {
        return None;
    }
    let length = be_u16(&inbound[2..4]) as usize;
    if length < HEADER_LEN {
        return None;
    }
    if inbound.len() < length {
        // Header plausible but the first packet hasn't fully arrived — don't commit.
        return None;
    }
    // A genuine opener is a single EOM packet: the handshake/first batch fits one
    // packet. (A first request larger than 4 KB that spans packets loses byte
    // detection here, which is acceptable — that's the port-hint path's job.)
    if inbound[1] & STATUS_EOM == 0 {
        return None;
    }
    let payload = &inbound[HEADER_LEN..length];
    // Handshakes are accepted on their type alone; data messages must yield a real
    // label so we don't bind on arbitrary binary that lands a request-type byte.
    let validates = match packet_type {
        TYPE_LOGIN7 | TYPE_PRELOGIN => true,
        TYPE_SQL_BATCH => is_known_sql_verb(&sql_batch_label(payload)),
        TYPE_RPC => rpc_label(payload) != "EXEC",
        _ => false,
    };
    if !validates {
        return None;
    }
    Some(Box::new(TdsParser::new()))
}

/// Is the first token of a label one of the common SQL verbs? The detection guard
/// for a SQLBatch opener — a parseable UTF-16 query starts with one of these, which
/// arbitrary binary decoded as UTF-16 essentially never does.
fn is_known_sql_verb(label: &str) -> bool {
    const VERBS: [&str; 12] = [
        "SELECT", "INSERT", "UPDATE", "DELETE", "EXEC", "EXECUTE", "WITH", "CREATE", "ALTER",
        "DROP", "BEGIN", "SET",
    ];
    let verb = label.split_whitespace().next().unwrap_or("");
    VERBS.contains(&verb)
}

/// Construct a TDS parser unconditionally — for the port-hint path (remote/local
/// port 1433 names the protocol, so byte sniffing is skipped). Mirrors the
/// `*Parser::default()` constructors the other binary parsers expose for
/// `conn::parser_for_protocol`.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(TdsParser::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a UTF-16LE byte vector from a `&str`.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Build one TDS packet: header + payload. `eom` sets the end-of-message bit.
    fn packet(packet_type: u8, eom: bool, payload: &[u8]) -> Vec<u8> {
        let total = HEADER_LEN + payload.len();
        assert!(total <= u16::MAX as usize, "test packet too large");
        let mut v = Vec::with_capacity(total);
        v.push(packet_type);
        v.push(if eom { STATUS_EOM } else { 0x00 });
        v.extend_from_slice(&(total as u16).to_be_bytes()); // length: BIG-ENDIAN
        v.extend_from_slice(&0u16.to_be_bytes()); // SPID
        v.push(0); // PacketID
        v.push(0); // Window
        v.extend_from_slice(payload);
        v
    }

    /// A single-packet SQLBatch request carrying `sql` (no ALL_HEADERS block).
    fn sql_batch(sql: &str) -> Vec<u8> {
        packet(TYPE_SQL_BATCH, true, &utf16le(sql))
    }

    /// A single-packet SQLBatch request with a leading ALL_HEADERS block.
    fn sql_batch_with_headers(sql: &str) -> Vec<u8> {
        let text = utf16le(sql);
        // ALL_HEADERS: [TotalLength:u32 LE][one header: len:u32 + type:u16 + data]
        let header_data = [0xAAu8, 0xBB]; // arbitrary 2-byte header payload
        let one_header_len = 4 + 2 + header_data.len();
        let total = 4 + one_header_len;
        let mut payload = (total as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(&(one_header_len as u32).to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes()); // header type
        payload.extend_from_slice(&header_data);
        payload.extend_from_slice(&text);
        packet(TYPE_SQL_BATCH, true, &payload)
    }

    /// An RPC request calling a named stored proc (no ALL_HEADERS).
    fn rpc_named(proc_name: &str) -> Vec<u8> {
        let name = utf16le(proc_name);
        let char_count = proc_name.encode_utf16().count() as u16;
        let mut payload = char_count.to_le_bytes().to_vec();
        payload.extend_from_slice(&name);
        packet(TYPE_RPC, true, &payload)
    }

    /// A response token stream packet: a single DONE token (success).
    fn done_ok() -> Vec<u8> {
        let mut tokens = vec![TOKEN_DONE];
        tokens.extend_from_slice(&0x0000u16.to_le_bytes()); // Status: final, no error
        tokens.extend_from_slice(&0x0000u16.to_le_bytes()); // CurCmd
        tokens.extend_from_slice(&0u64.to_le_bytes()); // RowCount
        packet(0x04, true, &tokens)
    }

    /// A response with an ERROR token carrying `number`, then a DONE with the
    /// error status bit set.
    fn error_response(number: u32) -> Vec<u8> {
        let mut err = vec![TOKEN_ERROR];
        // ERROR body: Number(4) State(1) Class(1) MsgText(us_varchar:len u16 + text)
        // ServerName(b_varchar) ProcName(b_varchar) LineNumber(4). We give a minimal
        // well-formed body; the parser only reads Number, but Length must cover it.
        let msg = utf16le("err");
        let mut body = Vec::new();
        body.extend_from_slice(&number.to_le_bytes()); // Number
        body.push(16); // State
        body.push(1); // Class
        body.extend_from_slice(&(3u16).to_le_bytes()); // MsgText char count
        body.extend_from_slice(&msg); // MsgText
        body.push(0); // ServerName len (b_varchar, chars)
        body.push(0); // ProcName len
        body.extend_from_slice(&1u32.to_le_bytes()); // LineNumber
        err.extend_from_slice(&(body.len() as u16).to_le_bytes()); // Length
        err.extend_from_slice(&body);
        // Trailing DONE with error bit.
        let mut done = vec![TOKEN_DONE];
        done.extend_from_slice(&DONE_STATUS_ERROR.to_le_bytes());
        done.extend_from_slice(&0u16.to_le_bytes());
        done.extend_from_slice(&0u64.to_le_bytes());
        let mut tokens = err;
        tokens.extend_from_slice(&done);
        packet(0x04, true, &tokens)
    }

    fn record(
        p: &mut TdsParser,
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
    fn detects_sql_batch_by_positive_signature() {
        assert!(detect_tds(&sql_batch("SELECT 1")).is_some());
        assert!(detect_tds(&rpc_named("sp_who")).is_some());
        // Login7 / PreLogin openers also detect.
        assert!(detect_tds(&packet(TYPE_LOGIN7, true, &[0u8; 16])).is_some());
        assert!(detect_tds(&packet(TYPE_PRELOGIN, true, &[0u8; 4])).is_some());
    }

    #[test]
    fn rejects_non_tds_prefixes() {
        // Too short to hold a header.
        assert!(detect_tds(b"\x01\x01\x00").is_none());
        // HTTP request — type byte 'G' is not a TDS request type.
        assert!(detect_tds(b"GET / HTTP/1.1\r\n\r\n").is_none());
        // A response-type packet (0x04 TabularResult) is not a request opener.
        assert!(detect_tds(&done_ok()).is_none());
        // Request type byte but the declared length doesn't match the buffer (a
        // length-shaped value in arbitrary binary).
        let mut junk = sql_batch("SELECT 1");
        junk[3] = junk[3].wrapping_add(40); // corrupt the BE length low byte
        assert!(detect_tds(&junk).is_none());
        // Length below the 8-byte header is impossible framing.
        assert!(detect_tds(&[0x01, 0x01, 0x00, 0x04, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn new_parser_constructs_unconditionally_for_port_hint() {
        // The port-hint path binds without byte detection. The constructed parser
        // then parses a real exchange.
        let mut p = TdsParser::new();
        let _boxed = new_parser(); // smoke: constructs without panicking
        let recs = record(&mut p, &sql_batch("SELECT 1"), 1, &done_ok(), 2);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn sql_batch_label_is_verb_and_table() {
        assert_eq!(
            sql_batch_label(&utf16le("SELECT * FROM users WHERE id = 1")),
            "SELECT users"
        );
        assert_eq!(
            sql_batch_label(&utf16le("insert into orders values (1)")),
            "INSERT orders"
        );
        assert_eq!(
            sql_batch_label(&utf16le("UPDATE accounts SET x = 1")),
            "UPDATE accounts"
        );
        assert_eq!(
            sql_batch_label(&utf16le("DELETE FROM sessions")),
            "DELETE sessions"
        );
        // A verb with no clean table -> bare verb.
        assert_eq!(sql_batch_label(&utf16le("BEGIN TRANSACTION")), "BEGIN");
        // Bracketed identifier (T-SQL) -> brackets stripped.
        assert_eq!(
            sql_batch_label(&utf16le("SELECT * FROM [dbo].[Users]")),
            "SELECT dbo].[Users"
        );
    }

    #[test]
    fn sql_batch_with_all_headers_block_is_skipped() {
        let mut p = TdsParser::new();
        let recs = record(
            &mut p,
            &sql_batch_with_headers("SELECT 1 FROM dual"),
            10,
            &done_ok(),
            20,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT dual");
        assert_eq!(recs[0].duration_nano, 10);
    }

    #[test]
    fn one_request_response_yields_one_record() {
        let mut p = TdsParser::new();
        let recs = record(
            &mut p,
            &sql_batch("SELECT name FROM users"),
            1_000,
            &done_ok(),
            1_400,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT users");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn rpc_request_labels_as_exec_proc() {
        let mut p = TdsParser::new();
        let recs = record(&mut p, &rpc_named("sp_executesql"), 1, &done_ok(), 3);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "EXEC sp_executesql");
    }

    #[test]
    fn rpc_well_known_procid_labels_by_id() {
        // NameLenProcID sentinel 0xFFFF then proc id 4 (Sp_ExecuteSql well-known).
        let mut payload = RPC_PROCID_SENTINEL.to_le_bytes().to_vec();
        payload.extend_from_slice(&10u16.to_le_bytes());
        let req = packet(TYPE_RPC, true, &payload);
        let mut p = TdsParser::new();
        let recs = record(&mut p, &req, 1, &done_ok(), 2);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "EXEC #10");
    }

    #[test]
    fn error_token_sets_failure_verdict_and_status() {
        let mut p = TdsParser::new();
        // Error 208: "Invalid object name".
        let recs = record(
            &mut p,
            &sql_batch("SELECT * FROM missing"),
            0,
            &error_response(208),
            5,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT missing");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 208);
    }

    #[test]
    fn done_error_bit_without_error_token_still_fails() {
        let mut p = TdsParser::new();
        // A DONE with the error status bit but no preceding ERROR token.
        let mut done = vec![TOKEN_DONEPROC];
        done.extend_from_slice(&DONE_STATUS_ERROR.to_le_bytes());
        done.extend_from_slice(&0u16.to_le_bytes());
        done.extend_from_slice(&0u64.to_le_bytes());
        let resp = packet(0x04, true, &done);
        let recs = record(&mut p, &sql_batch("UPDATE t SET x = 1"), 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 0); // no ERROR token => no number
    }

    /// A DONE-family token (token byte + Status + CurCmd + RowCount:u64) with a
    /// chosen `status` word — the raw token bytes, no packet wrapper.
    fn done_token(token: u8, status: u16) -> Vec<u8> {
        let mut t = vec![token];
        t.extend_from_slice(&status.to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes()); // CurCmd
        t.extend_from_slice(&0u64.to_le_bytes()); // RowCount (u64, TDS 7.2+)
        t
    }

    #[test]
    fn done_srverror_bit_alone_is_a_failure() {
        // BUG (missed error verdict): SQL Server sends DONE_SRVERROR (0x0100) *in
        // place of* DONE_ERROR (0x0002) when a failure is severe enough to discard
        // the result set. The old mask only checked 0x0002, so a severe error with
        // only 0x0100 set was reported as success. It must be a failure.
        let mut p = TdsParser::new();
        let resp = packet(0x04, true, &done_token(TOKEN_DONE, DONE_STATUS_SRVERROR));
        let recs = record(&mut p, &sql_batch("SELECT 1"), 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(
            recs[0].error,
            "DONE_SRVERROR (0x0100) must verdict as failure"
        );
    }

    #[test]
    fn scan_stops_at_final_done_and_ignores_following_bytes() {
        // BUG (over-scan past end-of-response): the verdict walk used to advance past
        // the final DONE and keep scanning. In a coalesced response buffer the bytes
        // after this request's final clean DONE belong to the NEXT response — here an
        // ERROR token. The verdict for THIS request must be success: the scan stops at
        // the first DONE without the MORE bit.
        let mut p = TdsParser::new();
        let mut tokens = done_token(TOKEN_DONE, 0x0000); // final, clean (no MORE, no error)
        // Trailing bytes that, if scanned, parse as a fully-formed ERROR token (0xAA).
        tokens.push(TOKEN_ERROR);
        tokens.extend_from_slice(&8u16.to_le_bytes()); // Length
        tokens.extend_from_slice(&5060u32.to_le_bytes()); // Number
        tokens.push(16); // State
        tokens.push(16); // Class
        tokens.extend_from_slice(&0u16.to_le_bytes()); // padding to satisfy Length
        let resp = packet(0x04, true, &tokens);
        let recs = record(&mut p, &sql_batch("SELECT 1"), 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(
            !recs[0].error,
            "a clean final DONE ends the verdict; trailing ERROR bytes are the next response"
        );
        assert_eq!(recs[0].status_code, 0);
    }

    #[test]
    fn non_final_done_with_error_then_clean_done_still_fails() {
        // A multi-statement response: first statement errors (DONE with ERROR+MORE),
        // a later statement is clean (final DONE). The failure must survive — we must
        // not require the error to sit on the FINAL done, and must still scan past a
        // MORE done correctly (13-byte stride) to reach it.
        let mut p = TdsParser::new();
        let mut tokens = done_token(TOKEN_DONEINPROC, DONE_STATUS_MORE | DONE_STATUS_ERROR);
        tokens.extend_from_slice(&done_token(TOKEN_DONE, 0x0000)); // final clean done
        let resp = packet(0x04, true, &tokens);
        let recs = record(&mut p, &sql_batch("SELECT 1"), 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(
            recs[0].error,
            "an error on a non-final DONE is still a failure"
        );
    }

    #[test]
    fn payload_resembling_a_length_is_not_skipped_as_all_headers() {
        // BUG (false ALL_HEADERS skip): the old skip only checked `total>=4 &&
        // total<len`, never the documented structural guard. A real SQLBatch/RPC
        // payload whose first 4 bytes happen to form a plausible-but-invalid
        // ALL_HEADERS TotalLength was mis-skipped, eating real content bytes.
        //
        // Here TotalLength = 16 (in range, so the OLD code skips 16 bytes), but the
        // bytes at offset 4 do NOT describe a valid sub-header tiling of [4, 16). The
        // structural check must reject it and skip nothing.
        let mut payload = 16u32.to_le_bytes().to_vec();
        payload.extend_from_slice(b"SELECT 1 FROM accounts more text");
        assert!(payload.len() > 16);
        assert_eq!(
            skip_all_headers(&payload),
            0,
            "a payload whose leading u32 only LOOKS like a length must not be skipped"
        );
    }

    #[test]
    fn all_headers_with_overrunning_subheader_is_rejected() {
        // TotalLength is in range but the single sub-header's HeaderLength runs past
        // the declared total (would not tile). Must reject (skip 0), never panic.
        let total = 14u32; // 4 (TotalLength) + 10 claimed for one header
        let mut payload = total.to_le_bytes().to_vec();
        payload.extend_from_slice(&100u32.to_le_bytes()); // HeaderLength 100 >> total
        payload.extend_from_slice(&2u16.to_le_bytes()); // HeaderType
        payload.extend_from_slice(b"trailing content");
        assert_eq!(skip_all_headers(&payload), 0);
    }

    #[test]
    fn valid_all_headers_block_still_skipped() {
        // Guard the other direction: a genuinely valid ALL_HEADERS block (the helper
        // builds a well-formed one) must still be skipped so the SQL is found.
        let off = skip_all_headers(&{
            // Reuse the same construction the with-headers helper uses, payload only.
            let text = utf16le("SELECT 1 FROM dual");
            let header_data = [0xAAu8, 0xBB];
            let one_header_len = 4 + 2 + header_data.len();
            let total = 4 + one_header_len;
            let mut payload = (total as u32).to_le_bytes().to_vec();
            payload.extend_from_slice(&(one_header_len as u32).to_le_bytes());
            payload.extend_from_slice(&2u16.to_le_bytes());
            payload.extend_from_slice(&header_data);
            payload.extend_from_slice(&text);
            payload
        });
        assert_eq!(
            off, 12,
            "a structurally valid ALL_HEADERS block must be skipped"
        );
    }

    #[test]
    fn info_token_is_not_an_error() {
        let mut p = TdsParser::new();
        // INFO token (0xAB) shares ERROR's shape but is informational. Followed by a
        // clean DONE. Verdict must be success.
        let msg = utf16le("info");
        let mut body = Vec::new();
        body.extend_from_slice(&50u32.to_le_bytes()); // Number
        body.push(0); // State
        body.push(0); // Class
        body.extend_from_slice(&(4u16).to_le_bytes());
        body.extend_from_slice(&msg);
        body.push(0); // ServerName
        body.push(0); // ProcName
        body.extend_from_slice(&1u32.to_le_bytes()); // LineNumber
        let mut tokens = vec![TOKEN_INFO];
        tokens.extend_from_slice(&(body.len() as u16).to_le_bytes());
        tokens.extend_from_slice(&body);
        // clean DONE
        tokens.push(TOKEN_DONE);
        tokens.extend_from_slice(&0u16.to_le_bytes());
        tokens.extend_from_slice(&0u16.to_le_bytes());
        tokens.extend_from_slice(&0u64.to_le_bytes());
        let resp = packet(0x04, true, &tokens);
        let recs = record(&mut p, &sql_batch("SELECT 1"), 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].error);
    }

    #[test]
    fn fragmented_request_waits_then_completes() {
        let mut p = TdsParser::new();
        let req = sql_batch("SELECT id FROM events");
        // Header + part of the body, then a premature response, then the rest.
        let split = HEADER_LEN + 6;
        p.on_inbound(&req[..split], 10);
        assert!(p.take_records().is_empty());
        // A response now must NOT pair — the request isn't fully reassembled.
        p.on_outbound(&done_ok(), 20);
        assert!(
            p.take_records().is_empty(),
            "must not pair against a partial request"
        );
        p.on_inbound(&req[split..], 30);
        p.on_outbound(&done_ok(), 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT events");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn multi_packet_request_reassembles_across_eom() {
        let mut p = TdsParser::new();
        // A long SQL batch split across two packets: first NOT EOM, second EOM.
        let sql = "SELECT a FROM big_table";
        let text = utf16le(sql);
        let half = text.len() / 2;
        let pkt1 = packet(TYPE_SQL_BATCH, false, &text[..half]);
        let pkt2 = packet(TYPE_SQL_BATCH, true, &text[half..]);
        p.on_inbound(&pkt1, 1);
        assert!(
            p.take_records().is_empty(),
            "no EOM yet -> no request queued"
        );
        p.on_inbound(&pkt2, 2);
        p.on_outbound(&done_ok(), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT big_table");
        // start time is the FIRST packet's timestamp.
        assert_eq!(recs[0].start_unix_nano, 1);
    }

    #[test]
    fn fragmented_response_waits_for_full_packet() {
        let mut p = TdsParser::new();
        p.on_inbound(&sql_batch("SELECT 1"), 1);
        let resp = error_response(4060);
        // Only part of the response packet arrives.
        let split = resp.len() - 4;
        p.on_outbound(&resp[..split], 2);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_outbound(&resp[split..], 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 4060);
        assert_eq!(recs[0].duration_nano, 2);
    }

    #[test]
    fn pipelined_requests_pair_fifo() {
        let mut p = TdsParser::new();
        // Two requests back-to-back, then two responses in order.
        let mut reqs = sql_batch("SELECT a FROM t1");
        reqs.extend(rpc_named("sp_two"));
        p.on_inbound(&reqs, 100);
        let mut resps = done_ok();
        resps.extend(error_response(2627)); // violation of unique constraint
        p.on_outbound(&resps, 200);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SELECT t1");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "EXEC sp_two");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 2627);
    }

    #[test]
    fn unknown_packet_type_marks_dead() {
        let mut p = TdsParser::new();
        // 0x99 is not a known TDS type -> desync -> dead.
        let mut bad = vec![0x99, 0x01];
        bad.extend_from_slice(&12u16.to_be_bytes());
        bad.extend_from_slice(&[0u8; 8]);
        p.on_inbound(&bad, 0);
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn length_below_header_marks_dead() {
        let mut p = TdsParser::new();
        // A SQLBatch type but length 4 (< 8-byte header) is impossible framing.
        let bad = [TYPE_SQL_BATCH, 0x01, 0x00, 0x04, 0, 0, 0, 0];
        p.on_inbound(&bad, 0);
        assert!(p.is_dead());
    }

    #[test]
    fn orphan_response_is_dropped_not_dead() {
        let mut p = TdsParser::new();
        p.on_outbound(&done_ok(), 5); // attached mid-connection, missed the request
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        let mut p = TdsParser::new();
        let req = sql_batch("SELECT * FROM users");
        for byte in req.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let resp = done_ok();
        let last = (resp.len() - 1) as i64;
        for (i, byte) in resp.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT users");
        assert_eq!(recs[0].duration_nano, 2_000 + last - 1_000);
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Feed hostile/truncated payloads at every byte boundary, both directions,
        // in both orders. The hard requirement is no panic, ever — a wrong verdict
        // is acceptable, a crash is not.
        let valid_req = sql_batch("SELECT 1 FROM t");
        let valid_resp = error_response(0xFFFFFFFF);
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x01],
            vec![0x01, 0x01],
            vec![0x01, 0x01, 0x00],                   // header truncated
            vec![0x01, 0x01, 0xFF, 0xFF, 0, 0, 0, 0], // huge length, no body
            vec![0x03, 0x01, 0x00, 0x08, 0, 0, 0, 0], // RPC header, empty payload
            vec![0xAA, 0xFF, 0xFF],                   // lone ERROR token, short
            vec![0xFD, 0x02],                         // lone DONE, truncated status
            packet(TYPE_SQL_BATCH, true, &[0x00]),    // odd-length UTF-16 payload
            packet(TYPE_SQL_BATCH, true, &[0xFF; 3]), // odd, non-UTF16 bytes
            packet(TYPE_RPC, true, &0xFFFFu16.to_le_bytes()), // RPC sentinel, no id
            packet(TYPE_RPC, true, &[0xFF, 0x7F]),    // RPC huge name len, no name
            {
                // SQLBatch with an ALL_HEADERS length that overruns the payload.
                let mut pl = 1_000_000u32.to_le_bytes().to_vec();
                pl.extend_from_slice(b"junk");
                packet(TYPE_SQL_BATCH, true, &pl)
            },
            {
                // ENVCHANGE token claiming a huge length.
                let mut t = vec![TOKEN_ENVCHANGE];
                t.extend_from_slice(&0xFFFFu16.to_le_bytes());
                packet(0x04, true, &t)
            },
            valid_req.clone(),
            valid_resp.clone(),
            (0u8..=255).collect(),
            vec![0x00; 64],
            vec![0xFF; 64],
        ];

        for payload in &payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // detection must never panic
                let _ = detect_tds(a);
                let _ = detect_tds(payload);

                // request side, split in two
                let mut p = TdsParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();

                // response side, split (with a real request outstanding)
                let mut q = TdsParser::new();
                q.on_inbound(&valid_req, 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
            }
        }
    }
}
