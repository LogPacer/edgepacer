//! MongoDB wire parser — implements [`super::L7Parser`], the zero-code APM
//! producer for MongoDB connections.
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every message is `[messageLength:i32 LE][requestID:i32 LE][responseTo:i32 LE]
//! [opCode:i32 LE][body]`, where `messageLength` counts itself + the body (so the
//! 16-byte header is included). `total_len = messageLength`. We only act on two op
//! codes; everything else is framed past unread.
//!
//!   * **OP_MSG (2013)** — the modern op. Body = `flagBits:u32` then sections. A
//!     kind-`0x00` section is a single BSON document (the command). The command
//!     name is that BSON doc's *first key* (`find`/`insert`/…); the collection is
//!     that key's string value. `operation = "<command> <collection>"`.
//!   * **OP_QUERY (2004)** — legacy. Body = `flags:i32` + `fullCollectionName`
//!     (cstring) + `numberToSkip:i32` + `numberToReturn:i32` + a BSON query whose
//!     first key is the command.
//!
//! Responses are OP_MSG (server) or OP_REPLY (1, legacy), each carrying a BSON
//! doc. `error` is true iff that doc has `ok: 0` (or `0.0`) OR contains an
//! `errmsg`/`code` field. Requests pair with responses by `requestID ==
//! responseTo`; a non-zero `responseTo` is authoritative (no match ⇒ drop the
//! reply, never steal an unrelated in-flight request). Only a `responseTo` of 0
//! (a mid-stream-attach reply with no usable id) falls back to the oldest pending.
//!
//! We never fully decode BSON: a minimal scan reads the first element's name +
//! (string) value, and looks up `ok`/`errmsg`/`code` in a response — nothing else.
//! Pulling the `bson` crate for that would betray the leanness moat.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Wire header is four i32 fields, little-endian.
const HEADER_LEN: usize = 16;

/// Op codes we recognise. Requests are OP_MSG or OP_QUERY; responses are OP_MSG or
/// the legacy OP_REPLY. Anything else is framed past without interpretation.
const OP_REPLY: i32 = 1;
const OP_QUERY: i32 = 2004;
const OP_MSG: i32 = 2013;

/// Sanity bound on a single message. The wire protocol caps a message at 48 MB
/// (`maxMessageSizeBytes`, typically 48000000); a "MongoDB" stream claiming more
/// than this means we mis-detected or desynced — bail rather than buffer forever.
const MAX_MSG_LEN: i32 = 48 * 1024 * 1024;

/// OP_MSG section kinds. Kind 0 is the body document (the command); kind 1 is a
/// "document sequence" (bulk payload) which we frame past, never decode.
const SECTION_BODY: u8 = 0x00;
const SECTION_DOC_SEQUENCE: u8 = 0x01;

/// BSON element type bytes we care about. We only ever read a string value (the
/// collection name) for the first element and probe `ok`'s numeric value.
const BSON_DOUBLE: u8 = 0x01;
const BSON_STRING: u8 = 0x02;
const BSON_INT32: u8 = 0x10;
const BSON_INT64: u8 = 0x12;
const BSON_BOOL: u8 = 0x08;

/// Read a little-endian i32 from the first four bytes of `b` (caller guarantees len).
fn le_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Read a little-endian u32 from the first four bytes of `b` (caller guarantees len).
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// A parsed message header: the four i32 fields plus the total bytes it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    request_id: i32,
    response_to: i32,
    op_code: i32,
    total_len: usize,
}

/// Outcome of reading one message head off a direction-buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed header — its fields and the total bytes the message occupies.
    Framed(Header),
    /// A valid prefix but not enough bytes yet — wait.
    Partial,
    /// Not MongoDB framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Is this a sane `messageLength`? It counts the 16-byte header + body, so it must
/// be at least the header and within our memory bound.
fn sane_len(message_length: i32) -> bool {
    message_length >= HEADER_LEN as i32 && message_length <= MAX_MSG_LEN
}

/// Parse one message head from a buffer prefix. Any op code frames (so we can skip
/// messages we don't act on); only an insane `messageLength` is `Invalid` — the
/// desync signal.
fn parse_head(buf: &[u8]) -> Head {
    if buf.len() < HEADER_LEN {
        return Head::Partial;
    }
    let message_length = le_i32(&buf[0..4]);
    if !sane_len(message_length) {
        return Head::Invalid;
    }
    Head::Framed(Header {
        request_id: le_i32(&buf[4..8]),
        response_to: le_i32(&buf[8..12]),
        op_code: le_i32(&buf[12..16]),
        total_len: message_length as usize,
    })
}

/// Borrow a NUL-terminated C-string from `body` as UTF-8 (lossless on the ASCII
/// keys/collection names we read). Returns the string and the offset just past its
/// NUL terminator, or `None` if no terminator is present in the slice.
fn read_cstr(body: &[u8]) -> Option<(&str, usize)> {
    let nul = body.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&body[..nul]).unwrap_or("");
    Some((s, nul + 1))
}

/// The first element of a BSON document: its key name and, when the value is a
/// string, that string. The command name is the key; the collection is the value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstElement {
    key: String,
    string_value: Option<String>,
}

/// Read the first element's key (and string value, if it is a string) from a BSON
/// document at the front of `doc`. A BSON doc is `[len:i32 LE][elements][0x00]`;
/// each element is `[type:1][key:cstr][value]`. We only need the first element, so
/// we never walk the rest. Returns `None` on any malformed prefix (never panics).
fn bson_first_element(doc: &[u8]) -> Option<FirstElement> {
    // [len:i32][type:1][key cstr][value...]. Need at least len + a type byte; an
    // empty doc is `[len=5][0x00]`.
    if doc.len() < 5 {
        return None;
    }
    let elem_type = doc[4];
    if elem_type == 0 {
        return None; // empty document, no first element
    }
    let (key, after_key) = read_cstr(&doc[5..])?;
    let value_off = 5 + after_key;
    let string_value = if elem_type == BSON_STRING {
        // string value = [len:i32 LE][bytes incl trailing NUL]
        if doc.len() < value_off + 4 {
            None
        } else {
            let slen = le_i32(&doc[value_off..value_off + 4]);
            // slen counts the trailing NUL; the actual chars are slen-1.
            if slen >= 1 {
                let start = value_off + 4;
                let chars = (slen - 1) as usize;
                doc.get(start..start + chars)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
            } else {
                None
            }
        }
    } else {
        None
    };
    Some(FirstElement {
        key: key.to_string(),
        string_value,
    })
}

/// The error verdict of a response BSON doc: true iff `ok` is 0 (or 0.0), or the
/// doc carries an `errmsg` or `code` field. We scan top-level element keys only —
/// never recurse into sub-documents. Bounded by the element count we can walk
/// before the buffer runs out; a malformed doc yields `false` (no panic).
fn response_is_error(doc: &[u8]) -> bool {
    if doc.len() < 5 {
        return false;
    }
    let mut pos = 4; // skip the i32 length
    // Bound the walk: at minimum each element is type(1)+key(2: 1 char + NUL).
    for _ in 0..1024 {
        match doc.get(pos) {
            None | Some(0) => return false, // end of document or truncated
            Some(&elem_type) => {
                let Some((key, after_key)) = read_cstr(&doc[pos + 1..]) else {
                    return false;
                };
                let value_off = pos + 1 + after_key;
                if key == "errmsg" || key == "code" {
                    return true;
                }
                if key == "ok" && ok_is_failure(elem_type, &doc[value_off..]) {
                    return true;
                }
                let Some(skip) = bson_value_len(elem_type, &doc[value_off..]) else {
                    return false;
                };
                pos = value_off + skip;
            }
        }
    }
    false
}

/// Is the `ok` field a failure value (0 / 0.0 / false)? `ok` is conventionally a
/// double, but drivers/servers also send int32/int64/bool — handle all faithfully.
fn ok_is_failure(elem_type: u8, value: &[u8]) -> bool {
    match elem_type {
        BSON_DOUBLE if value.len() >= 8 => {
            f64::from_le_bytes(value[0..8].try_into().unwrap()) == 0.0
        }
        BSON_INT32 if value.len() >= 4 => le_i32(value) == 0,
        BSON_INT64 if value.len() >= 8 => i64::from_le_bytes(value[0..8].try_into().unwrap()) == 0,
        BSON_BOOL if !value.is_empty() => value[0] == 0,
        _ => false,
    }
}

/// Byte length of a BSON value of `elem_type` at the front of `value`, so the scan
/// can advance to the next element. Only the types that can plausibly precede `ok`
/// in a response are sized precisely; an unknown/over-long-prefix type returns
/// `None`, ending the (already best-effort) scan rather than guessing.
fn bson_value_len(elem_type: u8, value: &[u8]) -> Option<usize> {
    match elem_type {
        BSON_DOUBLE | BSON_INT64 => Some(8),
        BSON_INT32 => Some(4),
        BSON_BOOL => Some(1),
        0x0A => Some(0), // null
        BSON_STRING | 0x0D | 0x0E => {
            // string / JS code / symbol: [len:i32 LE][bytes]
            if value.len() < 4 {
                return None;
            }
            let slen = le_i32(value);
            if slen < 0 {
                return None;
            }
            Some(4 + slen as usize)
        }
        // embedded document / array: [len:i32 LE][...]; len counts itself.
        0x03 | 0x04 => {
            if value.len() < 4 {
                return None;
            }
            let dlen = le_i32(value);
            if dlen < 0 {
                return None;
            }
            Some(dlen as usize)
        }
        0x07 => Some(12),       // ObjectId
        0x09 | 0x11 => Some(8), // datetime / timestamp
        _ => None,
    }
}

/// Extract the command label from an OP_MSG body: `flagBits:u32` then sections. We
/// find the first kind-0 (body) section and read its BSON first element. The
/// command is the key; the collection (when present) is its string value.
fn op_msg_label(body: &[u8]) -> Option<String> {
    let doc = op_msg_body_doc(body)?;
    Some(label_from_doc(&bson_first_element(doc)?))
}

/// Locate the kind-0 body document inside an OP_MSG body, framing past any leading
/// kind-1 document sequences. Returns the BSON doc slice, or `None` if not present
/// / malformed (never panics).
fn op_msg_body_doc(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 4 {
        return None;
    }
    let mut pos = 4; // skip flagBits:u32
    // Bound the section walk against a hostile body.
    for _ in 0..256 {
        let kind = *body.get(pos)?;
        match kind {
            SECTION_BODY => {
                let doc = body.get(pos + 1..)?;
                if doc.len() < 4 {
                    return None;
                }
                let dlen = le_i32(&doc[0..4]);
                if dlen < 5 {
                    return None;
                }
                return doc.get(..dlen as usize);
            }
            SECTION_DOC_SEQUENCE => {
                // [kind:1][size:i32 LE incl. these 4 bytes][cstr identifier][docs]
                let size_at = pos + 1;
                let size = le_i32(body.get(size_at..size_at + 4)?);
                if size < 4 {
                    return None;
                }
                pos = size_at + size as usize;
            }
            _ => return None,
        }
    }
    None
}

/// Extract the command label from an OP_QUERY body: `flags:i32` +
/// `fullCollectionName` (cstring) + `numberToSkip:i32` + `numberToReturn:i32` +
/// the BSON query whose first key is the command.
fn op_query_label(body: &[u8]) -> Option<String> {
    // flags:i32, then the cstring collection name.
    let (_full_collection, after) = read_cstr(body.get(4..)?)?;
    // skip numberToSkip:i32 + numberToReturn:i32 to reach the query doc.
    let query_off = 4 + after + 8;
    let doc = body.get(query_off..)?;
    Some(label_from_doc(&bson_first_element(doc)?))
}

/// Build the operation label from a parsed first element: `"<command>
/// <collection>"` when the value is a (non-empty) string, else just `"<command>"`.
/// Admin commands like `isMaster`/`ping` have a numeric `1` value, so they label
/// as the bare command — which is exactly right.
fn label_from_doc(first: &FirstElement) -> String {
    match &first.string_value {
        Some(collection) if !collection.is_empty() => {
            format!("{} {}", first.key, collection)
        }
        _ => first.key.clone(),
    }
}

/// A request awaiting its reply: the op label, the `requestID` a reply's
/// `responseTo` must match, and the observation time (for latency).
#[derive(Debug)]
struct Pending {
    operation: String,
    request_id: i32,
    start_unix_nano: i64,
}

/// MongoDB [`L7Parser`]: frames both directions, labels OP_MSG/OP_QUERY requests,
/// pairs each with its reply by `requestID == responseTo` (FIFO fallback), and
/// frames past everything else. Desync (insane length) marks it dead.
#[derive(Debug, Default)]
pub(crate) struct MongoParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl MongoParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() {
                return;
            }
            if self.inbound.buf.is_empty() {
                return;
            }
            match parse_head(&self.inbound.buf) {
                Head::Framed(h) => {
                    let is_request = h.op_code == OP_MSG || h.op_code == OP_QUERY;
                    if is_request {
                        // A request label needs the whole body. If it hasn't all
                        // arrived, wait — advancing would skip the straddling body
                        // bytes as framing and lose the request (no pending op to
                        // pair the reply with).
                        if h.total_len > self.inbound.buf.len() {
                            return;
                        }
                        let body = &self.inbound.buf[HEADER_LEN..h.total_len];
                        let operation = match h.op_code {
                            OP_MSG => op_msg_label(body),
                            OP_QUERY => op_query_label(body),
                            _ => None,
                        }
                        .unwrap_or_else(|| "UNKNOWN".to_string());
                        self.pending.push_back(Pending {
                            operation,
                            request_id: h.request_id,
                            start_unix_nano: ts,
                        });
                    }
                    self.inbound.advance(h.total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    fn drain_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() {
                return;
            }
            if self.outbound.buf.is_empty() {
                return;
            }
            match parse_head(&self.outbound.buf) {
                Head::Framed(h) => {
                    let is_reply = h.op_code == OP_MSG || h.op_code == OP_REPLY;
                    if is_reply {
                        // We need the whole reply to read its BSON for the error
                        // verdict and to stamp the real completion time, not a
                        // fragment's. Wait if the body still straddles.
                        if h.total_len > self.outbound.buf.len() {
                            return;
                        }
                        let body = &self.outbound.buf[HEADER_LEN..h.total_len];
                        let error = reply_is_error(h.op_code, body);
                        self.complete(h.response_to, error, ts);
                    }
                    self.outbound.advance(h.total_len);
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Pair a reply with its request. A genuine MongoDB reply stamps the request's
    /// `requestID` into `responseTo`, so a non-zero `responseTo` is authoritative:
    /// pair with that exact pending request, and if none matches, DROP the reply —
    /// it answers a request we never saw (mid-stream attach), or it is a duplicate /
    /// exhaust / stray reply. Falling back to the oldest pending there would steal an
    /// unrelated in-flight request's slot and mis-pair it. Only a `responseTo` of 0
    /// (no usable id — a mid-stream-attach reply) uses the FIFO fallback to the
    /// oldest pending. A reply with no pairable request is dropped.
    fn complete(&mut self, response_to: i32, error: bool, ts: i64) {
        let idx = if response_to != 0 {
            // Authoritative id: match exactly or drop — never steal the oldest.
            match self
                .pending
                .iter()
                .position(|p| p.request_id == response_to)
            {
                Some(i) => i,
                None => return,
            }
        } else {
            // No usable id: pair FIFO with the oldest pending request, if any.
            0
        };
        if let Some(req) = self.pending.remove(idx) {
            self.records.push(L7Record {
                protocol: Protocol::Mongodb,
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

/// Error verdict for a reply body. OP_MSG replies wrap the result doc in
/// `flagBits:u32` + a kind-0 section; OP_REPLY puts the doc after a 20-byte fixed
/// header (`responseFlags:i32 + cursorID:i64 + startingFrom:i32 + numberReturned:i32`).
fn reply_is_error(op_code: i32, body: &[u8]) -> bool {
    let doc = match op_code {
        OP_MSG => op_msg_body_doc(body),
        OP_REPLY => body.get(20..),
        _ => None,
    };
    doc.map(response_is_error).unwrap_or(false)
}

impl L7Parser for MongoParser {
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

/// Recognise MongoDB from a connection's inbound prefix via a POSITIVE signature
/// and return a fresh boxed parser, or `None` if it isn't (yet) recognisable.
///
/// Byte-only detection of a binary protocol is inherently weak — there is no magic
/// number in the MongoDB header — so this is deliberately CONSERVATIVE to avoid
/// false positives on other binary traffic (a TCP port hint of 27017 would make it
/// reliable and should gate this detector when a port is known). We require, all
/// of:
///   * a full 16-byte header buffered;
///   * `opCode` in {2013 OP_MSG, 2004 OP_QUERY} (the request op codes);
///   * a sane `messageLength` (≥ 16, ≤ 48 MB) — and, once the whole message is
///     buffered, the body must *parse* into a command label (a kind-0 OP_MSG
///     section with a non-empty BSON first key, or an OP_QUERY collection cstring +
///     query doc). Requiring a structurally valid body — not just a plausible
///     header — is what suppresses collisions on the four little-endian length
///     bytes that any binary stream might present.
///
/// While the header is buffered but the body has not all arrived we return `None`
/// (the registry keeps buffering and retries) rather than guess.
pub(crate) fn detect_mongodb(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if inbound.len() < HEADER_LEN {
        return None;
    }
    let message_length = le_i32(&inbound[0..4]);
    if !sane_len(message_length) {
        return None;
    }
    let response_to = le_i32(&inbound[8..12]);
    let op_code = le_i32(&inbound[12..16]);
    if op_code != OP_MSG && op_code != OP_QUERY {
        return None;
    }
    // A fresh request never answers anything; demanding responseTo == 0 rejects a
    // huge swath of binary streams that happen to land 2013/2004 in the op-code
    // slot. (A mid-stream attach loses detection here, which is acceptable — the
    // strong-signature path is for a connection observed from its first bytes.)
    if response_to != 0 {
        return None;
    }
    let total_len = message_length as usize;
    if inbound.len() < total_len {
        // Header is plausible but the body hasn't fully arrived — don't commit yet.
        return None;
    }
    let body = &inbound[HEADER_LEN..total_len];
    let label = match op_code {
        OP_MSG => op_msg_label(body),
        OP_QUERY => op_query_label(body),
        _ => None,
    };
    // Require a structurally valid command body (non-empty label) — the real guard
    // against false positives on arbitrary little-endian bytes.
    match label {
        Some(l) if !l.is_empty() => Some(Box::new(MongoParser::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BSON document from already-encoded elements: `[len:i32][elems][0x00]`.
    fn bson_doc(elements: &[u8]) -> Vec<u8> {
        let len = (4 + elements.len() + 1) as i32;
        let mut v = len.to_le_bytes().to_vec();
        v.extend_from_slice(elements);
        v.push(0x00);
        v
    }

    /// A BSON string element: `[0x02][key\0][len:i32][value\0]`.
    fn bson_string(key: &str, value: &str) -> Vec<u8> {
        let mut v = vec![BSON_STRING];
        v.extend_from_slice(key.as_bytes());
        v.push(0);
        let slen = (value.len() + 1) as i32;
        v.extend_from_slice(&slen.to_le_bytes());
        v.extend_from_slice(value.as_bytes());
        v.push(0);
        v
    }

    /// A BSON double element: `[0x01][key\0][f64 LE]`.
    fn bson_double(key: &str, value: f64) -> Vec<u8> {
        let mut v = vec![BSON_DOUBLE];
        v.extend_from_slice(key.as_bytes());
        v.push(0);
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// A BSON int32 element: `[0x10][key\0][i32 LE]`.
    fn bson_int32(key: &str, value: i32) -> Vec<u8> {
        let mut v = vec![BSON_INT32];
        v.extend_from_slice(key.as_bytes());
        v.push(0);
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// Frame a wire message: header (LE) + body, messageLength = 16 + body.
    fn message(request_id: i32, response_to: i32, op_code: i32, body: &[u8]) -> Vec<u8> {
        let message_length = (HEADER_LEN + body.len()) as i32;
        let mut v = message_length.to_le_bytes().to_vec();
        v.extend_from_slice(&request_id.to_le_bytes());
        v.extend_from_slice(&response_to.to_le_bytes());
        v.extend_from_slice(&op_code.to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    /// An OP_MSG request whose body command doc has first element `command:
    /// collection` (a string), optionally followed by extra elements.
    fn op_msg_request(request_id: i32, command: &str, collection: &str, extra: &[u8]) -> Vec<u8> {
        let mut elems = bson_string(command, collection);
        elems.extend_from_slice(extra);
        let doc = bson_doc(&elems);
        let mut body = 0u32.to_le_bytes().to_vec(); // flagBits
        body.push(SECTION_BODY);
        body.extend_from_slice(&doc);
        message(request_id, 0, OP_MSG, &body)
    }

    /// An OP_MSG reply (`responseTo` set) carrying `reply_doc` as its body section.
    fn op_msg_reply(response_to: i32, reply_elems: &[u8]) -> Vec<u8> {
        let doc = bson_doc(reply_elems);
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(SECTION_BODY);
        body.extend_from_slice(&doc);
        message(9999, response_to, OP_MSG, &body)
    }

    fn record(
        p: &mut MongoParser,
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
    fn detects_op_msg_request_by_positive_signature() {
        let req = op_msg_request(1, "find", "users", &[]);
        assert!(detect_mongodb(&req).is_some());
    }

    #[test]
    fn detects_op_query_request() {
        // OP_QUERY: flags:i32, fullCollectionName cstr, skip:i32, return:i32, query.
        let mut body = 0i32.to_le_bytes().to_vec();
        body.extend_from_slice(b"db.$cmd\0");
        body.extend_from_slice(&0i32.to_le_bytes()); // numberToSkip
        body.extend_from_slice(&(-1i32).to_le_bytes()); // numberToReturn
        body.extend_from_slice(&bson_doc(&bson_int32("isMaster", 1)));
        let req = message(1, 0, OP_QUERY, &body);
        assert!(detect_mongodb(&req).is_some());
    }

    #[test]
    fn rejects_non_mongodb_prefixes() {
        // HTTP, too short, wrong op code, and a structurally-plausible header with
        // garbage body must all be rejected.
        assert!(detect_mongodb(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(detect_mongodb(b"\x10\x00\x00\x00").is_none()); // header not buffered
        // Sane length + 16 bytes but opCode is not a request op code.
        let not_a_request = message(1, 0, 2005, &bson_doc(&bson_int32("x", 1)));
        assert!(detect_mongodb(&not_a_request).is_none());
        // OP_MSG header but body is random bytes (no parseable command doc).
        let mut junk_body = 0u32.to_le_bytes().to_vec();
        junk_body.push(SECTION_BODY);
        junk_body.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f, 0xaa, 0xbb]);
        let junk = message(1, 0, OP_MSG, &junk_body);
        assert!(detect_mongodb(&junk).is_none());
    }

    #[test]
    fn detect_requires_response_to_zero() {
        // A "request" op code but responseTo != 0 is not a fresh request — reject,
        // since random binary lands 2013/2004 in the slot far more often than a
        // genuine fresh MongoDB request with a non-zero responseTo (which can't
        // happen).
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(SECTION_BODY);
        body.extend_from_slice(&bson_doc(&bson_string("find", "users")));
        let bad = message(1, 42, OP_MSG, &body);
        assert!(detect_mongodb(&bad).is_none());
    }

    #[test]
    fn op_msg_label_is_command_and_collection() {
        let req = op_msg_request(7, "find", "orders", &[]);
        let h = match parse_head(&req) {
            Head::Framed(h) => h,
            other => panic!("expected framed head, got {other:?}"),
        };
        let body = &req[HEADER_LEN..h.total_len];
        assert_eq!(op_msg_label(body), Some("find orders".to_string()));
    }

    #[test]
    fn admin_command_with_numeric_value_labels_as_bare_command() {
        // {isMaster: 1} — first value is an int, not a collection string.
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(SECTION_BODY);
        body.extend_from_slice(&bson_doc(&bson_int32("isMaster", 1)));
        let req = message(1, 0, OP_MSG, &body);
        let h = match parse_head(&req) {
            Head::Framed(h) => h,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            op_msg_label(&req[HEADER_LEN..h.total_len]),
            Some("isMaster".to_string())
        );
    }

    #[test]
    fn one_request_response_yields_one_record() {
        let mut p = MongoParser::new();
        let req = op_msg_request(100, "insert", "events", &[]);
        let resp = op_msg_reply(100, &bson_double("ok", 1.0));
        let recs = record(&mut p, &req, 1_000, &resp, 1_400);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "insert events");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn pairs_by_request_id_even_out_of_order() {
        // Two requests; replies come back in REVERSE order. Pairing by
        // requestID==responseTo must still match each reply to its request.
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(11, "find", "a", &[]), 10);
        p.on_inbound(&op_msg_request(22, "find", "b", &[]), 20);
        // reply to 22 first, then 11.
        p.on_outbound(&op_msg_reply(22, &bson_double("ok", 1.0)), 30);
        p.on_outbound(&op_msg_reply(11, &bson_double("ok", 1.0)), 40);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "find b"); // reply to 22 arrived first
        assert_eq!(recs[0].duration_nano, 10);
        assert_eq!(recs[1].operation, "find a");
        assert_eq!(recs[1].duration_nano, 30);
    }

    #[test]
    fn error_reply_with_ok_zero_sets_failure_verdict() {
        let mut p = MongoParser::new();
        let req = op_msg_request(5, "update", "users", &[]);
        // {ok: 0.0, errmsg: "...", code: 11000}
        let mut elems = bson_double("ok", 0.0);
        elems.extend_from_slice(&bson_string("errmsg", "E11000 duplicate key"));
        elems.extend_from_slice(&bson_int32("code", 11000));
        let resp = op_msg_reply(5, &elems);
        let recs = record(&mut p, &req, 0, &resp, 5);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "update users");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn errmsg_without_ok_zero_still_errors() {
        // A doc with ok:1 but an errmsg present (write errors do this) — error.
        let mut p = MongoParser::new();
        let req = op_msg_request(6, "delete", "sessions", &[]);
        let mut elems = bson_double("ok", 1.0);
        elems.extend_from_slice(&bson_string("errmsg", "partial failure"));
        let resp = op_msg_reply(6, &elems);
        let recs = record(&mut p, &req, 0, &resp, 1);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
    }

    #[test]
    fn fragmented_request_waits_then_completes() {
        let mut p = MongoParser::new();
        let req = op_msg_request(1, "aggregate", "metrics", &[]);
        // Feed the header + part of the body, then a (premature) reply, then rest.
        let split = HEADER_LEN + 6;
        p.on_inbound(&req[..split], 10);
        assert!(p.take_records().is_empty());
        // A reply now must NOT pair — the request isn't fully parsed yet.
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 1.0)), 20);
        assert!(
            p.take_records().is_empty(),
            "must not pair against a truncated request"
        );
        // Deliver the rest of the request, then a real reply.
        p.on_inbound(&req[split..], 30);
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 1.0)), 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "aggregate metrics");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn fragmented_reply_waits_for_full_body() {
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(3, "find", "x", &[]), 1);
        let resp = op_msg_reply(3, &bson_double("ok", 0.0));
        // Only the header arrives; the BSON body straddles.
        p.on_outbound(&resp[..HEADER_LEN], 5);
        assert!(
            p.take_records().is_empty(),
            "must not complete on a partial reply head"
        );
        p.on_outbound(&resp[HEADER_LEN..], 9);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        // The error verdict survives fragmentation (ok:0).
        assert!(recs[0].error);
        assert_eq!(recs[0].duration_nano, 8);
    }

    #[test]
    fn pipelined_requests_pair_fifo_when_ids_match() {
        let mut p = MongoParser::new();
        let mut reqs = op_msg_request(1, "find", "a", &[]);
        reqs.extend(op_msg_request(2, "insert", "b", &[]));
        p.on_inbound(&reqs, 100);
        let mut resps = op_msg_reply(1, &bson_double("ok", 1.0));
        resps.extend(op_msg_reply(2, &bson_double("ok", 0.0)));
        p.on_outbound(&resps, 200);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "find a");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "insert b");
        assert!(recs[1].error);
    }

    #[test]
    fn op_msg_with_doc_sequence_section_is_framed_past() {
        // OP_MSG carrying a kind-1 document-sequence section BEFORE the kind-0 body
        // (bulk insert shape). The label must still come from the kind-0 body doc.
        let mut body = 0u32.to_le_bytes().to_vec(); // flagBits
        // kind-1 section: [1][size:i32][identifier cstr][docs]
        let identifier = b"documents\0";
        let inner_doc = bson_doc(&bson_int32("a", 1));
        let seq_payload_len = 4 + identifier.len() + inner_doc.len();
        body.push(SECTION_DOC_SEQUENCE);
        body.extend_from_slice(&(seq_payload_len as i32).to_le_bytes());
        body.extend_from_slice(identifier);
        body.extend_from_slice(&inner_doc);
        // kind-0 body section with the command.
        body.push(SECTION_BODY);
        body.extend_from_slice(&bson_doc(&bson_string("insert", "events")));
        let req = message(50, 0, OP_MSG, &body);

        assert!(detect_mongodb(&req).is_some());
        let mut p = MongoParser::new();
        let recs = record(
            &mut p,
            &req,
            1,
            &op_msg_reply(50, &bson_double("ok", 1.0)),
            2,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "insert events");
    }

    #[test]
    fn unknown_op_code_is_framed_past_not_paired() {
        // A request, then an OP_COMPRESSED-like (2012) message that isn't a reply we
        // read: it must frame past without consuming the pending request, so the
        // real reply still pairs.
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(1, "find", "x", &[]), 1);
        // opCode 2012 on the response side — framed past, not a reply.
        p.on_outbound(&message(8, 0, 2012, &[0xaa, 0xbb, 0xcc, 0xdd]), 2);
        assert!(p.take_records().is_empty());
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 1.0)), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "find x");
    }

    #[test]
    fn orphan_reply_is_dropped() {
        let mut p = MongoParser::new();
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 1.0)), 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn insane_length_marks_dead() {
        let mut p = MongoParser::new();
        // messageLength below the 16-byte header minimum is invalid framing.
        let mut bad = 4i32.to_le_bytes().to_vec();
        bad.extend_from_slice(&[0u8; 12]);
        p.on_inbound(&bad, 0);
        assert!(p.is_dead());
    }

    #[test]
    fn op_reply_legacy_response_error_verdict() {
        // Legacy OP_REPLY: 20-byte fixed header then the BSON doc.
        let mut p = MongoParser::new();
        // Request via OP_QUERY isMaster.
        let mut qbody = 0i32.to_le_bytes().to_vec();
        qbody.extend_from_slice(b"db.$cmd\0");
        qbody.extend_from_slice(&0i32.to_le_bytes());
        qbody.extend_from_slice(&(-1i32).to_le_bytes());
        qbody.extend_from_slice(&bson_doc(&bson_int32("isMaster", 1)));
        let req = message(77, 0, OP_QUERY, &qbody);

        // OP_REPLY body: responseFlags:i32 + cursorID:i64 + startingFrom:i32 +
        // numberReturned:i32 (20 bytes) then the doc with ok:0.
        let mut rbody = vec![0u8; 20];
        rbody.extend_from_slice(&bson_doc(&bson_double("ok", 0.0)));
        let resp = message(8, 77, OP_REPLY, &rbody);

        let recs = record(&mut p, &req, 1, &resp, 4);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "isMaster");
        assert!(recs[0].error);
        assert_eq!(recs[0].duration_nano, 3);
    }

    #[test]
    fn bson_first_element_handles_empty_and_malformed() {
        // Empty doc -> no first element.
        assert_eq!(bson_first_element(&bson_doc(&[])), None);
        // Too short -> None, no panic.
        assert_eq!(bson_first_element(&[1, 2, 3]), None);
        // String element with a truncated length field -> None.
        let mut truncated = vec![BSON_STRING, b'k', 0]; // type + key + NUL, no len
        let doc_len = (4 + truncated.len() + 1) as i32;
        let mut d = doc_len.to_le_bytes().to_vec();
        d.append(&mut truncated);
        d.push(0);
        // first element parses key but string value is absent -> Some with no value.
        let fe = bson_first_element(&d).unwrap();
        assert_eq!(fe.key, "k");
        assert_eq!(fe.string_value, None);
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Feed hostile/truncated payloads at every byte boundary, both directions,
        // in both orders. The hard requirement is no panic, ever.
        let valid_req = op_msg_request(1, "find", "users", &[]);
        let valid_reply = op_msg_reply(1, &bson_double("ok", 0.0));
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff],
            vec![0xff, 0xff, 0xff, 0x7f], // length ~2G in the length slot
            0i32.to_le_bytes().to_vec(),  // length 0
            {
                // valid header, opCode OP_MSG, then no body
                let mut v = 16i32.to_le_bytes().to_vec();
                v.extend_from_slice(&1i32.to_le_bytes());
                v.extend_from_slice(&0i32.to_le_bytes());
                v.extend_from_slice(&OP_MSG.to_le_bytes());
                v
            },
            {
                // OP_MSG header claiming a huge body
                let mut v = 1_000_000i32.to_le_bytes().to_vec();
                v.extend_from_slice(&1i32.to_le_bytes());
                v.extend_from_slice(&0i32.to_le_bytes());
                v.extend_from_slice(&OP_MSG.to_le_bytes());
                v.extend_from_slice(&[0xaa; 8]);
                v
            },
            {
                // OP_MSG with a kind-1 section claiming a negative/short size
                let mut body = 0u32.to_le_bytes().to_vec();
                body.push(SECTION_DOC_SEQUENCE);
                body.extend_from_slice(&(-5i32).to_le_bytes());
                message(1, 0, OP_MSG, &body)
            },
            {
                // BSON first string element whose declared length overruns the doc
                let mut elems = vec![BSON_STRING];
                elems.extend_from_slice(b"find\0");
                elems.extend_from_slice(&1_000_000i32.to_le_bytes());
                elems.extend_from_slice(b"x");
                let doc = bson_doc(&elems);
                let mut body = 0u32.to_le_bytes().to_vec();
                body.push(SECTION_BODY);
                body.extend_from_slice(&doc);
                message(1, 0, OP_MSG, &body)
            },
            valid_req.clone(),
            valid_reply.clone(),
            (0u8..=255).collect(),
            vec![0x00; 64],
        ];

        for payload in &payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // detection must never panic
                let _ = detect_mongodb(a);
                let _ = detect_mongodb(payload);

                // request side, split
                let mut p = MongoParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();

                // response side, split (with a real request outstanding)
                let mut q = MongoParser::new();
                q.on_inbound(&valid_req, 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
            }
        }
    }

    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        let mut p = MongoParser::new();
        let req = op_msg_request(42, "find", "users", &[]);
        for byte in req.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let resp = op_msg_reply(42, &bson_double("ok", 0.0));
        let last = (resp.len() - 1) as i64;
        for (i, byte) in resp.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "find users");
        assert!(recs[0].error);
        assert_eq!(recs[0].duration_nano, 2_000 + last - 1_000);
    }

    #[test]
    fn unmatched_nonzero_response_to_does_not_steal_oldest_pending() {
        // Two requests in flight (ids 10, 20). A reply carrying a *non-zero*
        // responseTo that matches NEITHER (a stray/duplicate/exhaust reply, or a
        // reply to a request that attached mid-stream) must be DROPPED — not paired
        // against the oldest pending. Stealing "find a" here would mis-label it with
        // the wrong reply's verdict/timing and orphan the genuine reply to id 10.
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(10, "find", "a", &[]), 1);
        p.on_inbound(&op_msg_request(20, "find", "b", &[]), 2);
        // responseTo 999 matches nothing — must produce NO record.
        p.on_outbound(&op_msg_reply(999, &bson_double("ok", 0.0)), 3);
        assert!(
            p.take_records().is_empty(),
            "a non-zero responseTo with no matching request must be dropped, not paired"
        );
        // The genuine replies still pair correctly and carry their own verdicts.
        p.on_outbound(&op_msg_reply(10, &bson_double("ok", 1.0)), 4);
        p.on_outbound(&op_msg_reply(20, &bson_double("ok", 0.0)), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "find a");
        assert!(
            !recs[0].error,
            "find a must take its OWN reply's ok:1 verdict"
        );
        assert_eq!(recs[0].duration_nano, 3); // 4 - 1, not stolen by the 999 reply at ts 3
        assert_eq!(recs[1].operation, "find b");
        assert!(recs[1].error);
    }

    #[test]
    fn duplicate_reply_does_not_mispair_a_later_request() {
        // Exhaust/moreToCome shape: request 1 gets its reply, then the SERVER sends a
        // second reply also stamped responseTo=1 while request 2 is still in flight.
        // The duplicate must be dropped (id 1 no longer pending) rather than steal
        // request 2's slot.
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(1, "find", "a", &[]), 1);
        p.on_inbound(&op_msg_request(2, "insert", "b", &[]), 2);
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 1.0)), 3); // pairs id 1
        p.on_outbound(&op_msg_reply(1, &bson_double("ok", 0.0)), 4); // DUPLICATE -> drop
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "find a");
        assert!(!recs[0].error);
        // Request 2 is untouched and pairs with its real reply.
        p.on_outbound(&op_msg_reply(2, &bson_double("ok", 1.0)), 5);
        let recs2 = p.take_records();
        assert_eq!(recs2.len(), 1);
        assert_eq!(recs2[0].operation, "insert b");
        assert!(!recs2[0].error);
    }

    #[test]
    fn zero_response_to_reply_uses_fifo_fallback() {
        // A mid-stream-attach reply that carries no usable id (responseTo == 0) still
        // pairs FIFO with the oldest pending request — the one legitimate fallback.
        let mut p = MongoParser::new();
        p.on_inbound(&op_msg_request(7, "find", "a", &[]), 1);
        p.on_outbound(&op_msg_reply(0, &bson_double("ok", 1.0)), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "find a");
        assert_eq!(recs[0].duration_nano, 1);
    }
}
