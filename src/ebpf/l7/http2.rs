//! HTTP/2 + gRPC wire parser — implements [`super::L7Parser`].
//!
//! HTTP/2 multiplexes many request/response streams over one connection, so this
//! parser is structured very differently from the FIFO HTTP/1 one: it frames the
//! byte stream (9-byte frame headers), reassembles HPACK header blocks (HEADERS +
//! CONTINUATION), decodes them, and pairs request to response **by stream id** —
//! never by arrival order.
//!
//! ## What a span needs (and nothing more)
//! - **request**  : `:method` + `:path` pseudo-headers → operation `":method :path"`,
//!   e.g. `"POST /pkg.Svc/Method"`. (For gRPC, `:path` is `/Service/Method`.)
//! - **response** : `:status` pseudo-header → `status_code`.
//! - **gRPC**     : `grpc-status` arrives as a *trailer* in a second END_STREAM
//!   HEADERS frame; `grpc-status != 0` is an application error.
//! - **error**    : `:status >= 500` OR `grpc-status != 0`.
//!
//! DATA payloads, SETTINGS, WINDOW_UPDATE, PING, PRIORITY, RST_STREAM and GOAWAY
//! carry nothing a span needs, so their payloads are skipped (we only honour the
//! END_STREAM flag where it closes a response stream).
//!
//! ## HPACK is stateful — one decoder per direction
//! HPACK header blocks share a dynamic table that every block mutates, so a frame
//! cannot be decoded in isolation: blocks must be fed to the decoder in order, and
//! the request side and response side keep **separate** tables (RFC 7541 §2.2).
//! We hand-roll the framing + stream-id pairing and use `httlib-hpack` purely for
//! the HPACK codec (Huffman + dynamic table) — the one genuinely hard part.
//!
//! ## Detection seam (Phase 4 wires this into `super::conn::detect`)
//! HTTP/2 opens with a fixed 24-byte client preface,
//! `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`. The connection seam rules a connection
//! `Unknown` once 8 non-HTTP/1 bytes arrive — *before* the 24-byte preface
//! completes — so we expose two helpers:
//! - [`looks_like_preface_prefix`] — true while the inbound buffer is a non-empty
//!   prefix of the preface; `detect` returns `NeedMore` (keep waiting) instead of
//!   `Unknown` until the full preface is buffered.
//! - [`detect_http2`] — `Some(parser)` once the full 24-byte preface is present.
//!
//! Nothing here panics on malformed frames or HPACK: bad bytes set an internal
//! dead flag (surfaced by [`super::L7Parser::is_dead`]) and the connection is
//! dropped by the registry.

use std::collections::HashMap;

use httlib_hpack::decoder::{Decoder, DecoderError};

use super::{L7Parser, L7Record, Protocol};

/// The HTTP/2 client connection preface. The client sends exactly these 24 bytes
/// before any frame (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame header length: 3-byte length + 1-byte type + 1-byte flags + 4-byte
/// stream id (RFC 9113 §4.1).
const FRAME_HEADER_LEN: usize = 9;

/// Largest frame payload we'll buffer toward before declaring corruption. The
/// 3-byte length field tops out at 16 MiB-1; the HTTP/2 default
/// SETTINGS_MAX_FRAME_SIZE is 16 KiB and a peer may negotiate up to 16 MiB. A
/// passive tap can't reliably track that negotiation, so we accept generously but
/// bound memory: anything past 1 MiB on a frame is treated as a corrupt length and
/// kills the stream rather than buffering toward it. (HEADERS/CONTINUATION blocks
/// — the only payloads we retain — are far smaller in practice.)
const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Cap on concurrently half-open streams tracked per connection. HTTP/2 caps
/// concurrency via SETTINGS_MAX_CONCURRENT_STREAMS, but a passive observer can't
/// rely on it, so we bound the map ourselves against runaway cardinality.
const MAX_OPEN_STREAMS: usize = 1024;

// Frame type codes (RFC 9113 §6).
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_CONTINUATION: u8 = 0x9;

// Frame flags.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// One parsed frame header plus the payload slice boundaries within a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHeader {
    length: usize,
    kind: u8,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    /// Parse a 9-byte frame header. Returns `None` if fewer than 9 bytes are
    /// buffered (need more); the caller treats an over-large length as fatal.
    fn parse(buf: &[u8]) -> Option<FrameHeader> {
        if buf.len() < FRAME_HEADER_LEN {
            return None;
        }
        let length = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
        let kind = buf[3];
        let flags = buf[4];
        // Top bit of the stream id is reserved (R) — mask it off (RFC 9113 §4.1).
        let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        Some(FrameHeader {
            length,
            kind,
            flags,
            stream_id,
        })
    }
}

/// True while `inbound` is a non-empty prefix of the 24-byte HTTP/2 client
/// preface — i.e. it *could* still grow into a preface. Used by the connection
/// seam to return `NeedMore` instead of `Unknown` before the preface completes.
///
/// Returns false once the bytes diverge from the preface, or once a full preface
/// (or more) is present — at that point [`detect_http2`] gives the verdict.
pub(crate) fn looks_like_preface_prefix(inbound: &[u8]) -> bool {
    !inbound.is_empty() && inbound.len() < PREFACE.len() && PREFACE.starts_with(inbound)
}

/// Recognise HTTP/2 from a connection's inbound prefix via its positive signature
/// (the 24-byte client preface). Returns a fresh boxed parser once the full
/// preface is buffered, else `None` (not yet enough bytes, or not HTTP/2).
///
/// Phase 4 calls this from `super::conn::detect` once `pre_inbound` is long
/// enough; pair it with [`looks_like_preface_prefix`] to keep the connection
/// alive (`NeedMore`) while the preface is still arriving.
pub(crate) fn detect_http2(inbound: &[u8]) -> Option<Box<dyn L7Parser>> {
    if inbound.starts_with(PREFACE) {
        Some(Box::new(Http2Parser::new()))
    } else {
        None
    }
}

/// A request awaiting its response, keyed by stream id.
#[derive(Debug)]
struct PendingRequest {
    operation: String,
    /// Service-map / classification span attributes (`http.host`, `http.target`).
    attributes: Vec<(String, String)>,
    start_unix_nano: i64,
}

/// Response-side accumulation for one stream: the `:status` from the initial
/// HEADERS, plus any `grpc-status` trailer from a later END_STREAM HEADERS.
#[derive(Debug, Default)]
struct PendingResponse {
    status: Option<u16>,
    grpc_status: Option<i64>,
}

/// Per-direction HPACK + header-block reassembly. HEADERS/CONTINUATION fragments
/// are concatenated here before a single in-order HPACK decode, because a block
/// spanning frames is one HPACK unit and the dynamic table must see blocks in
/// order.
#[derive(Debug, Default)]
struct HeaderAssembly {
    decoder: Decoder<'static>,
    /// Buffered header-block fragment + the stream it belongs to, while a
    /// CONTINUATION run is still open (END_HEADERS not yet seen).
    open: Option<OpenBlock>,
}

#[derive(Debug)]
struct OpenBlock {
    stream_id: u32,
    /// True if the originating HEADERS frame carried END_STREAM (a trailers-only
    /// or empty-body close) — remembered across CONTINUATION frames.
    end_stream: bool,
    fragment: Vec<u8>,
}

/// One decoded header field. `:status`/`:method`/`:path` are pseudo-headers; the
/// rest are regular fields (only `grpc-status` matters to us).
type DecodedHeaders = Vec<(Vec<u8>, Vec<u8>)>;

/// Bounds-check that an HPACK block is fully framed before it reaches the
/// decoder. `httlib-hpack` 0.1.3 reads past the end of a *truncated* block in
/// two spots — `decode_integer` indexes `buf[total - 1]` after only testing
/// `buf.is_empty()`, and `decode_string` reads `buf[0]` for the Huffman flag
/// with no emptiness check — so a HEADERS frame whose block ends mid-field
/// (e.g. a literal with a name but no value-length octet) panics the decoder.
/// Under the release profile's `panic = "abort"` that aborts the whole agent on
/// a single hostile frame, so we must keep the panic *unreachable*, not merely
/// catch it. This walker mirrors the decoder's per-octet field framing with
/// every read bounds-checked and returns `false` the moment the block would
/// underflow, letting the caller mark the stream dead instead of decoding.
///
/// It validates framing only (lengths line up), not HPACK semantics — invalid
/// indices, bad Huffman, and oversized dynamic-size updates are still left for
/// the real decoder to reject as `Err`.
fn hpack_block_is_framed(block: &[u8]) -> bool {
    // Decode one HPACK integer with `prefix` payload bits starting at `buf[0]`.
    // Returns the byte length consumed, or `None` if the encoding runs off the
    // end or exceeds the decoder's 5-octet limit (mirrors `decode_integer`).
    fn int_len(buf: &[u8], prefix: u8) -> Option<usize> {
        let first = *buf.first()?;
        let mask = ((1u16 << prefix) - 1) as u8;
        if first & mask != mask {
            return Some(1); // value fits in the prefix bits
        }
        let mut total = 1;
        loop {
            let byte = *buf.get(total)?;
            total += 1;
            if byte & 0x80 == 0 {
                return Some(total);
            }
            if total == 5 {
                return None; // > 5 octets: decoder errors (no panic), reject here too
            }
        }
    }

    // Decode one HPACK string (length-prefixed, prefix 7) at `buf[0]`. The
    // decoder reads `buf[0]` for the Huffman flag *before* the length, so an
    // empty slice here is the panic trigger — `int_len`'s `buf.first()?` guards
    // it. Returns total bytes (length octets + data), or `None` if truncated.
    fn str_len(buf: &[u8]) -> Option<usize> {
        let hdr = int_len(buf, 7)?;
        // Re-decode the length value to know how many data bytes follow.
        let first = *buf.first()?;
        let mut len = (first & 0x7f) as usize;
        if len == 0x7f {
            let mut shift = 0;
            let mut idx = 1;
            loop {
                let byte = *buf.get(idx)?;
                len += ((byte & 0x7f) as usize) << shift;
                shift += 7;
                idx += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        let total = hdr.checked_add(len)?;
        if total <= buf.len() {
            Some(total)
        } else {
            None
        }
    }

    let mut pos = 0;
    while pos < block.len() {
        let rest = &block[pos..];
        let octet = rest[0];
        let consumed = if octet & 0x80 != 0 {
            // Indexed header field: a single integer, prefix 7.
            int_len(rest, 7)
        } else if octet & 0x40 != 0 {
            // Literal with incremental indexing: integer(prefix 6) + name? + value.
            literal_len(rest, 6)
        } else if octet & 0x20 != 0 {
            // Dynamic table size update: a single integer, prefix 5.
            int_len(rest, 5)
        } else {
            // Literal without / never indexed: integer(prefix 4) + name? + value.
            literal_len(rest, 4)
        };
        match consumed {
            Some(0) | None => return false, // truncated or non-advancing → unsafe to decode
            Some(n) => pos += n,
        }
    }
    return true;

    // A literal field: index integer; if index == 0 a name string follows; then
    // a value string. Shares the bounded helpers above.
    fn literal_len(buf: &[u8], prefix: u8) -> Option<usize> {
        let idx_len = int_len(buf, prefix)?;
        let first = buf[0];
        let mask = ((1u16 << prefix) - 1) as u8;
        let mut total = idx_len;
        let index_is_zero = (first & mask) == 0;
        if index_is_zero {
            total = total.checked_add(str_len(buf.get(total..)?)?)?;
        }
        total = total.checked_add(str_len(buf.get(total..)?)?)?;
        Some(total)
    }
}

impl HeaderAssembly {
    /// Decode a fully-assembled header block in order against this direction's
    /// dynamic table. Returns the decoded (name, value) pairs, or an error if the
    /// HPACK is malformed (fatal: the table is now desynchronised).
    fn decode_block(&mut self, block: &[u8]) -> Result<DecodedHeaders, DecoderError> {
        // Reject truncated/over-long blocks up front: the 0.1.3 decoder panics
        // (not errors) on those, which `panic = "abort"` turns into a process
        // kill. A block that fails the framing check is treated as malformed.
        if !hpack_block_is_framed(block) {
            return Err(DecoderError::InvalidInput);
        }
        // `decode` consumes from the buffer it's given and appends to `dst`. We
        // hand it an owned copy so the per-direction state lives in the decoder,
        // not the caller. One call drains the whole block (looping internally over
        // each field); we loop defensively in case a build decodes field-by-field.
        let mut buf = block.to_vec();
        let mut dst: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
        while !buf.is_empty() {
            let before = buf.len();
            self.decoder.decode(&mut buf, &mut dst)?;
            // A decode that consumed nothing would loop forever — treat as malformed.
            if buf.len() == before {
                return Err(DecoderError::InvalidInput);
            }
        }
        Ok(dst.into_iter().map(|(n, v, _flags)| (n, v)).collect())
    }
}

/// HTTP/2 + gRPC [`L7Parser`]: frames each direction, reassembles + HPACK-decodes
/// header blocks, and pairs requests to responses by stream id. Unrecoverable
/// framing or HPACK marks it dead so the connection is dropped.
#[derive(Debug)]
pub(crate) struct Http2Parser {
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    /// True until the 24-byte client preface has been stripped from `inbound`.
    awaiting_preface: bool,
    /// Per-direction HPACK decoder + CONTINUATION reassembly.
    req_headers: HeaderAssembly,
    resp_headers: HeaderAssembly,
    /// Open requests keyed by stream id, awaiting their response.
    pending: HashMap<u32, PendingRequest>,
    /// Response status/trailers accumulating per stream until END_STREAM.
    responses: HashMap<u32, PendingResponse>,
    records: Vec<L7Record>,
    dead: bool,
}

impl Default for Http2Parser {
    fn default() -> Self {
        Self {
            inbound: Vec::new(),
            outbound: Vec::new(),
            awaiting_preface: true,
            req_headers: HeaderAssembly::default(),
            resp_headers: HeaderAssembly::default(),
            pending: HashMap::new(),
            responses: HashMap::new(),
            records: Vec::new(),
            dead: false,
        }
    }
}

impl Http2Parser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Strip leading padding/priority bytes a HEADERS frame may carry, returning
    /// the header-block fragment slice. Returns `None` if the declared padding is
    /// inconsistent with the payload (malformed → fatal upstream).
    fn header_block_fragment(flags: u8, payload: &[u8]) -> Option<&[u8]> {
        let mut rest = payload;
        let mut pad_len = 0usize;
        if flags & FLAG_PADDED != 0 {
            let (&first, tail) = rest.split_first()?;
            pad_len = first as usize;
            rest = tail;
        }
        if flags & FLAG_PRIORITY != 0 {
            // 4-byte stream dependency + 1-byte weight.
            if rest.len() < 5 {
                return None;
            }
            rest = &rest[5..];
        }
        if pad_len > rest.len() {
            return None;
        }
        Some(&rest[..rest.len() - pad_len])
    }

    /// Decode one direction's reassembled buffer, framing forward until it runs
    /// out of complete frames. `inbound` selects request vs response semantics.
    fn drain(&mut self, inbound: bool, ts: i64) {
        if inbound && self.awaiting_preface {
            if self.inbound.len() < PREFACE.len() {
                return; // wait for the full preface before framing
            }
            if !self.inbound.starts_with(PREFACE) {
                self.dead = true;
                return;
            }
            self.inbound.drain(0..PREFACE.len());
            self.awaiting_preface = false;
        }

        loop {
            let buf = if inbound {
                &self.inbound
            } else {
                &self.outbound
            };
            let Some(header) = FrameHeader::parse(buf) else {
                return; // < 9 bytes: need more
            };
            if header.length > MAX_FRAME_PAYLOAD {
                self.dead = true;
                return;
            }
            let total = FRAME_HEADER_LEN + header.length;
            if buf.len() < total {
                return; // full frame not buffered yet
            }
            // Copy the payload out, then advance, so we drop the borrow on `buf`.
            let payload = buf[FRAME_HEADER_LEN..total].to_vec();
            if inbound {
                self.inbound.drain(0..total);
            } else {
                self.outbound.drain(0..total);
            }
            self.handle_frame(inbound, header, &payload, ts);
            if self.dead {
                return;
            }
        }
    }

    /// Dispatch one fully-buffered frame. Only HEADERS/CONTINUATION carry span
    /// data; DATA contributes its END_STREAM flag to response completion; the rest
    /// are ignored.
    fn handle_frame(&mut self, inbound: bool, header: FrameHeader, payload: &[u8], ts: i64) {
        match header.kind {
            FRAME_HEADERS => self.on_headers(inbound, header, payload, ts),
            FRAME_CONTINUATION => self.on_continuation(inbound, header, payload, ts),
            FRAME_DATA if !inbound && header.flags & FLAG_END_STREAM != 0 => {
                // A response whose body closes on a DATA frame (e.g. plain HTTP/2
                // with no trailers) completes here.
                self.complete_response(header.stream_id, ts);
            }
            _ => {} // SETTINGS / WINDOW_UPDATE / PING / PRIORITY / RST_STREAM / GOAWAY / DATA
        }
    }

    fn on_headers(&mut self, inbound: bool, header: FrameHeader, payload: &[u8], ts: i64) {
        let Some(fragment) = Self::header_block_fragment(header.flags, payload) else {
            self.dead = true;
            return;
        };
        let asm = if inbound {
            &mut self.req_headers
        } else {
            &mut self.resp_headers
        };
        // A new HEADERS while a CONTINUATION run is open is a framing violation.
        if asm.open.is_some() {
            self.dead = true;
            return;
        }
        let end_stream = header.flags & FLAG_END_STREAM != 0;
        if header.flags & FLAG_END_HEADERS != 0 {
            self.finish_block(inbound, header.stream_id, end_stream, fragment.to_vec(), ts);
        } else {
            asm.open = Some(OpenBlock {
                stream_id: header.stream_id,
                end_stream,
                fragment: fragment.to_vec(),
            });
        }
    }

    fn on_continuation(&mut self, inbound: bool, header: FrameHeader, payload: &[u8], ts: i64) {
        let asm = if inbound {
            &mut self.req_headers
        } else {
            &mut self.resp_headers
        };
        let Some(open) = asm.open.as_mut() else {
            // CONTINUATION with no open block is a framing violation.
            self.dead = true;
            return;
        };
        if open.stream_id != header.stream_id {
            self.dead = true;
            return;
        }
        open.fragment.extend_from_slice(payload);
        if header.flags & FLAG_END_HEADERS != 0 {
            let OpenBlock {
                stream_id,
                end_stream,
                fragment,
            } = asm.open.take().expect("open checked above");
            self.finish_block(inbound, stream_id, end_stream, fragment, ts);
        }
    }

    /// A complete header block is assembled — HPACK-decode it (always, to keep the
    /// dynamic table in sync) and extract the span fields.
    fn finish_block(
        &mut self,
        inbound: bool,
        stream_id: u32,
        end_stream: bool,
        block: Vec<u8>,
        ts: i64,
    ) {
        let asm = if inbound {
            &mut self.req_headers
        } else {
            &mut self.resp_headers
        };
        let headers = match asm.decode_block(&block) {
            Ok(h) => h,
            Err(_) => {
                self.dead = true;
                return;
            }
        };

        if inbound {
            self.on_request_headers(stream_id, &headers, ts);
        } else {
            self.on_response_headers(stream_id, end_stream, &headers, ts);
        }
    }

    fn on_request_headers(&mut self, stream_id: u32, headers: &DecodedHeaders, ts: i64) {
        let mut method: Option<String> = None;
        let mut path: Option<String> = None;
        let mut authority: Option<String> = None;
        for (name, value) in headers {
            match name.as_slice() {
                b":method" => method = Some(String::from_utf8_lossy(value).into_owned()),
                b":path" => path = Some(String::from_utf8_lossy(value).into_owned()),
                b":authority" => authority = Some(String::from_utf8_lossy(value).into_owned()),
                _ => {}
            }
        }
        // Trailers on the request side carry no pseudo-headers; ignore blocks
        // without :method (they don't open a new logical request).
        let (Some(method), Some(path)) = (method, path) else {
            return;
        };
        if self.pending.len() < MAX_OPEN_STREAMS {
            // :authority is HTTP/2's Host — the service-map edge's destination.
            let mut attributes = Vec::new();
            if let Some(authority) = authority.filter(|a| !a.is_empty()) {
                attributes.push(("http.host".to_string(), authority));
            }
            attributes.push(("http.target".to_string(), path.clone()));
            self.pending.insert(
                stream_id,
                PendingRequest {
                    operation: format!("{method} {path}"),
                    attributes,
                    start_unix_nano: ts,
                },
            );
        }
    }

    fn on_response_headers(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        headers: &DecodedHeaders,
        ts: i64,
    ) {
        // Bound response-side cardinality the same way `on_request_headers`
        // bounds `pending`. A peer streaming response HEADERS on a flood of
        // distinct stream ids (e.g. never sending END_STREAM, or for streams we
        // never saw a request on) would otherwise grow `responses` without
        // limit. New stream ids past the cap are dropped; ids already tracked
        // still accumulate their status/trailers so in-flight responses finish.
        if !self.responses.contains_key(&stream_id) && self.responses.len() >= MAX_OPEN_STREAMS {
            return;
        }
        let entry = self.responses.entry(stream_id).or_default();
        for (name, value) in headers {
            match name.as_slice() {
                b":status" => {
                    entry.status = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
                }
                b"grpc-status" => {
                    entry.grpc_status =
                        std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
                }
                _ => {}
            }
        }
        if end_stream {
            self.complete_response(stream_id, ts);
        }
    }

    /// Pair a finished response stream to its pending request and emit one record.
    /// A response with no pending request is dropped (we attached mid-connection
    /// and missed the request).
    fn complete_response(&mut self, stream_id: u32, ts: i64) {
        let Some(req) = self.pending.remove(&stream_id) else {
            self.responses.remove(&stream_id);
            return;
        };
        let resp = self.responses.remove(&stream_id).unwrap_or_default();
        let status = resp.status.unwrap_or(0);
        let grpc_error = matches!(resp.grpc_status, Some(code) if code != 0);
        self.records.push(L7Record {
            protocol: Protocol::Http2,
            attributes: req.attributes,
            operation: req.operation,
            status_code: status,
            error: status >= 500 || grpc_error,
            start_unix_nano: req.start_unix_nano,
            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
        });
    }
}

impl L7Parser for Http2Parser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.inbound.extend_from_slice(bytes);
        self.drain(true, ts);
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead {
            return;
        }
        self.outbound.extend_from_slice(bytes);
        self.drain(false, ts);
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
    use httlib_hpack::encoder::Encoder;

    /// Encode a list of (name, value) headers into one HPACK block using the
    /// crate's own encoder, so request/response fixtures stay in sync with the
    /// decoder under test. Flag `0x4` = incremental indexing: each field is added
    /// to the *encoder's* dynamic table, so the matching decoder must keep its own
    /// table in lockstep — exactly the per-direction state this parser owns.
    fn hpack(headers: &[(&[u8], &[u8])], encoder: &mut Encoder<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in headers {
            encoder
                .encode((name.to_vec(), value.to_vec(), 0x4), &mut out)
                .expect("encode");
        }
        out
    }

    /// Build a frame: 9-byte header + payload.
    fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        let len = payload.len();
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn preface() -> Vec<u8> {
        PREFACE.to_vec()
    }

    // --- detection ---------------------------------------------------------

    #[test]
    fn preface_prefix_waits_then_detects() {
        // Non-empty proper prefixes are "still could be a preface".
        assert!(looks_like_preface_prefix(b"PRI * HTTP"));
        assert!(looks_like_preface_prefix(&PREFACE[..1]));
        assert!(looks_like_preface_prefix(&PREFACE[..PREFACE.len() - 1]));
        // Empty is not a prefix (nothing to wait on yet).
        assert!(!looks_like_preface_prefix(b""));
        // Divergence from the preface is a hard no.
        assert!(!looks_like_preface_prefix(b"PRX"));
        assert!(!looks_like_preface_prefix(b"GET / HTTP/1.1"));
        // A full preface is no longer a *prefix*: detect_http2 decides instead.
        assert!(!looks_like_preface_prefix(PREFACE));

        assert!(detect_http2(PREFACE).is_some());
        assert!(detect_http2(&PREFACE[..10]).is_none()); // incomplete
        assert!(detect_http2(b"GET / HTTP/1.1\r\n").is_none());
    }

    // --- request/response pairing -----------------------------------------

    #[test]
    fn normal_request_response_yields_one_record() {
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        let req_block = hpack(
            &[
                (b":method", b"POST"),
                (b":path", b"/api/orders"),
                (b":scheme", b"https"),
                (b":authority", b"x"),
            ],
            &mut enc,
        );
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req_block,
        ));
        parser.on_inbound(&inbound, 1_000);
        assert!(parser.take_records().is_empty()); // request seen, no response yet

        let mut renc = Encoder::default();
        let resp_block = hpack(&[(b":status", b"200")], &mut renc);
        let outbound = frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &resp_block,
        );
        parser.on_outbound(&outbound, 1_400);

        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "POST /api/orders");
        assert_eq!(recs[0].status_code, 200);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
        // :authority + :path ride along as span attributes (service-map edge facts).
        assert!(
            recs[0]
                .attributes
                .contains(&("http.host".to_string(), "x".to_string()))
        );
        assert!(
            recs[0]
                .attributes
                .contains(&("http.target".to_string(), "/api/orders".to_string()))
        );
        assert!(!parser.is_dead());
    }

    #[test]
    fn fragmented_frame_waits_then_parses() {
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let req_block = hpack(&[(b":method", b"GET"), (b":path", b"/health")], &mut enc);
        let mut full = preface();
        full.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req_block,
        ));

        // Feed the inbound stream one byte short of a complete frame: no request
        // recorded yet, and crucially not mis-parsed or marked dead.
        parser.on_inbound(&full[..full.len() - 1], 1_000);
        assert!(parser.take_records().is_empty());
        assert!(!parser.is_dead());

        // The final byte completes the HEADERS frame; still awaiting the response.
        parser.on_inbound(&full[full.len() - 1..], 1_000);
        assert!(parser.take_records().is_empty());
        assert!(!parser.is_dead());

        let mut renc = Encoder::default();
        let resp_block = hpack(&[(b":status", b"204")], &mut renc);
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &resp_block,
            ),
            1_500,
        );
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /health");
        assert_eq!(recs[0].status_code, 204);
    }

    #[test]
    fn multiplexed_streams_pair_by_stream_id_not_arrival_order() {
        // Two requests open on streams 1 and 3; responses come back 3-then-1.
        // FIFO pairing would mis-attribute them — stream-id pairing must not.
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        let b1 = hpack(&[(b":method", b"GET"), (b":path", b"/a")], &mut enc);
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &b1,
        ));
        let b3 = hpack(&[(b":method", b"GET"), (b":path", b"/b")], &mut enc);
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &b3,
        ));
        parser.on_inbound(&inbound, 100);
        assert!(parser.take_records().is_empty());

        let mut renc = Encoder::default();
        // Response for stream 3 arrives first.
        let r3 = hpack(&[(b":status", b"500")], &mut renc);
        parser.on_outbound(
            &frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &r3),
            200,
        );
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /b"); // stream 3, not the FIFO-oldest /a
        assert_eq!(recs[0].status_code, 500);
        assert!(recs[0].error); // 5xx

        // Then stream 1.
        let r1 = hpack(&[(b":status", b"200")], &mut renc);
        parser.on_outbound(
            &frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &r1),
            300,
        );
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /a");
        assert_eq!(recs[0].status_code, 200);
        assert!(!recs[0].error);
    }

    #[test]
    fn grpc_trailer_status_is_the_error_verdict() {
        // gRPC: :status 200 but grpc-status != 0 (in a second END_STREAM HEADERS
        // trailer) is an error. The HTTP status alone would say success.
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        let req = hpack(
            &[
                (b":method", b"POST"),
                (b":path", b"/pkg.Svc/Method"),
                (b"content-type", b"application/grpc"),
            ],
            &mut enc,
        );
        // Request body would follow as DATA; END_STREAM here keeps the fixture lean.
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req,
        ));
        parser.on_inbound(&inbound, 0);

        let mut renc = Encoder::default();
        // Initial response HEADERS (no END_STREAM — a DATA frame + trailers follow).
        let resp = hpack(
            &[(b":status", b"200"), (b"content-type", b"application/grpc")],
            &mut renc,
        );
        parser.on_outbound(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &resp), 10);
        assert!(parser.take_records().is_empty()); // stream still open

        // Trailers: a second HEADERS frame with END_STREAM carrying grpc-status 13.
        let trailer = hpack(&[(b"grpc-status", b"13")], &mut renc);
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &trailer,
            ),
            20,
        );

        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "POST /pkg.Svc/Method");
        assert_eq!(recs[0].status_code, 200); // HTTP status says OK ...
        assert!(recs[0].error); // ... but grpc-status 13 is the real verdict
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn grpc_status_zero_is_success() {
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        let req = hpack(
            &[(b":method", b"POST"), (b":path", b"/pkg.Svc/Ok")],
            &mut enc,
        );
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req,
        ));
        parser.on_inbound(&inbound, 0);

        let mut renc = Encoder::default();
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                1,
                &hpack(&[(b":status", b"200")], &mut renc),
            ),
            5,
        );
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &hpack(&[(b"grpc-status", b"0")], &mut renc),
            ),
            6,
        );
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].error); // grpc-status 0 = OK
    }

    #[test]
    fn continuation_frames_reassemble_a_split_header_block() {
        // Split one request header block across HEADERS (no END_HEADERS) +
        // CONTINUATION (END_HEADERS). The HPACK block must be decoded as a whole.
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let block = hpack(
            &[
                (b":method", b"GET"),
                (b":path", b"/split"),
                (b":scheme", b"https"),
            ],
            &mut enc,
        );
        let mid = block.len() / 2;

        let mut inbound = preface();
        // HEADERS with END_STREAM but NOT END_HEADERS — the block continues.
        inbound.extend(frame(FRAME_HEADERS, FLAG_END_STREAM, 1, &block[..mid]));
        inbound.extend(frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS,
            1,
            &block[mid..],
        ));
        parser.on_inbound(&inbound, 0);
        assert!(!parser.is_dead());

        let mut renc = Encoder::default();
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &hpack(&[(b":status", b"200")], &mut renc),
            ),
            1,
        );
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /split");
    }

    #[test]
    fn settings_and_window_update_frames_are_ignored() {
        // Non-span frames before/around the HEADERS must not produce records or
        // desync the parser.
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        inbound.extend(frame(0x4, 0x0, 0, b"\x00\x03\x00\x00\x00\x64")); // SETTINGS
        let req = hpack(&[(b":method", b"GET"), (b":path", b"/x")], &mut enc);
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req,
        ));
        inbound.extend(frame(0x8, 0x0, 0, b"\x00\x00\x10\x00")); // WINDOW_UPDATE
        parser.on_inbound(&inbound, 0);
        assert!(!parser.is_dead());

        let mut renc = Encoder::default();
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &hpack(&[(b":status", b"200")], &mut renc),
            ),
            1,
        );
        assert_eq!(parser.take_records().len(), 1);
    }

    #[test]
    fn response_closing_on_a_data_frame_completes_the_stream() {
        // A non-gRPC HTTP/2 response: HEADERS (status, no END_STREAM) then a DATA
        // frame carrying END_STREAM. The record completes on the DATA close.
        let mut enc = Encoder::default();
        let mut parser = Http2Parser::new();

        let mut inbound = preface();
        let req = hpack(&[(b":method", b"GET"), (b":path", b"/file")], &mut enc);
        inbound.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &req,
        ));
        parser.on_inbound(&inbound, 0);

        let mut renc = Encoder::default();
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                1,
                &hpack(&[(b":status", b"200")], &mut renc),
            ),
            1,
        );
        assert!(parser.take_records().is_empty()); // not closed yet
        parser.on_outbound(&frame(FRAME_DATA, FLAG_END_STREAM, 1, b"body-bytes"), 2);
        let recs = parser.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /file");
        assert_eq!(recs[0].status_code, 200);
    }

    #[test]
    fn malformed_preface_marks_dead() {
        let mut parser = Http2Parser::new();
        // 24 bytes that are not the preface.
        parser.on_inbound(b"NOT-A-VALID-HTTP2-PREFACE", 0);
        assert!(parser.is_dead());
        assert!(parser.take_records().is_empty());
    }

    #[test]
    fn oversized_frame_length_marks_dead_without_buffering() {
        let mut parser = Http2Parser::new();
        let mut inbound = preface();
        // Frame header declaring a 0xFFFFFF (~16 MiB) payload — past the 1 MiB cap.
        inbound.extend_from_slice(&[0xff, 0xff, 0xff, FRAME_HEADERS, 0, 0, 0, 0, 1]);
        parser.on_inbound(&inbound, 0);
        assert!(parser.is_dead());
    }

    #[test]
    fn orphan_response_is_dropped() {
        // Response on a stream we never saw a request for (attached mid-connection).
        let mut parser = Http2Parser::new();
        // Skip the inbound preface path: drive the response side directly. The
        // parser only frames outbound after some inbound, so prime the preface.
        parser.on_inbound(&preface(), 0);

        let mut renc = Encoder::default();
        parser.on_outbound(
            &frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                7,
                &hpack(&[(b":status", b"200")], &mut renc),
            ),
            1,
        );
        assert!(parser.take_records().is_empty());
        assert!(!parser.is_dead());
    }

    // --- hostile / truncated HPACK (never-panic) ---------------------------

    /// A HEADERS frame whose block ends mid-field is the classic panic trigger
    /// in `httlib-hpack` 0.1.3 (`decode_string` reads `buf[0]` for the Huffman
    /// flag on an empty slice). Under the release `panic = "abort"` that kills
    /// the agent on one hostile frame. The framing pre-check must turn every such
    /// block into a clean dead-flag, never a panic.
    #[test]
    fn truncated_hpack_block_marks_dead_without_panicking() {
        // Each of these is a fully-framed HTTP/2 HEADERS frame (END_HEADERS set)
        // carrying a *truncated* HPACK block that the raw decoder panics on.
        let hostile_blocks: &[&[u8]] = &[
            // literal-with-indexing, new name "x", value-length octet missing.
            &[0x40, 0x01, b'x'],
            // literal-with-indexing, new name, nothing after the prefix octet.
            &[0x40],
            // literal-with-indexing, indexed name (idx 2), value string missing.
            &[0x42],
            // dynamic-table-size-update with a continuation byte then truncation.
            &[0x3f, 0xff],
            // literal, new name, name length 5 but only 2 name bytes present.
            &[0x40, 0x05, b'a', b'b'],
        ];
        for block in hostile_blocks {
            let mut parser = Http2Parser::new();
            let mut inbound = preface();
            inbound.extend(frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                block,
            ));
            // Must return (mark dead), never panic/abort.
            parser.on_inbound(&inbound, 0);
            assert!(
                parser.is_dead(),
                "hostile block {block:?} should mark the parser dead"
            );
            assert!(parser.take_records().is_empty());
        }
    }

    /// The framing pre-check must not reject *valid* truncation-free blocks: a
    /// well-formed block that happens to look unusual (size-update prefix, then
    /// a normal indexed field) still decodes.
    #[test]
    fn framing_precheck_accepts_valid_blocks() {
        // 0x20 = dynamic-table-size-update to 0; 0x82 = indexed field (:method GET).
        assert!(hpack_block_is_framed(&[0x20, 0x82]));
        // A real encoder block must pass the framing check unchanged.
        let mut enc = Encoder::default();
        let block = hpack(
            &[
                (b":method", b"POST"),
                (b":path", b"/ok"),
                (b"x-h", b"vvvvv"),
            ],
            &mut enc,
        );
        assert!(hpack_block_is_framed(&block));
        // And the truncated tail of that same block must be rejected, proving the
        // check is sensitive to the exact boundary (not trivially permissive).
        assert!(!hpack_block_is_framed(&block[..block.len() - 1]));
    }

    /// A truncated block split across HEADERS + CONTINUATION must also be caught
    /// at reassembly time, not panic — the pre-check runs on the *joined* block.
    #[test]
    fn truncated_block_across_continuation_marks_dead() {
        let mut parser = Http2Parser::new();
        let mut inbound = preface();
        // HEADERS (no END_HEADERS) holding a half-literal, CONTINUATION
        // (END_HEADERS) that does not complete it: joined block ends mid-field.
        inbound.extend(frame(FRAME_HEADERS, 0, 1, &[0x40, 0x01]));
        inbound.extend(frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, b"x"));
        parser.on_inbound(&inbound, 0);
        assert!(parser.is_dead());
        assert!(parser.take_records().is_empty());
    }

    // --- response-side cardinality bound -----------------------------------

    /// `pending` is capped at `MAX_OPEN_STREAMS`, but `responses` was not: a peer
    /// streaming response HEADERS on a flood of distinct stream ids (never
    /// END_STREAM, no matching request) grew the map without bound. The cap must
    /// apply symmetrically so memory can't run away.
    #[test]
    fn response_side_streams_are_bounded() {
        let mut parser = Http2Parser::new();
        parser.on_inbound(&preface(), 0);

        // Send MAX_OPEN_STREAMS + 200 response HEADERS, each on a unique stream,
        // with no END_STREAM so nothing is ever completed/evicted. Without the
        // cap, `responses` would hold one entry per stream id.
        for i in 0..(MAX_OPEN_STREAMS as u32 + 200) {
            let stream_id = i * 2 + 1; // odd ids, distinct per frame
            let mut renc = Encoder::default();
            let block = hpack(&[(b":status", b"200")], &mut renc);
            parser.on_outbound(
                &frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, &block),
                i as i64,
            );
        }
        assert!(!parser.is_dead());
        assert!(
            parser.responses.len() <= MAX_OPEN_STREAMS,
            "responses map must stay bounded by MAX_OPEN_STREAMS, was {}",
            parser.responses.len()
        );
    }
}
