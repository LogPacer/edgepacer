//! Redis (RESP2/3) wire parser — implements [`super::L7Parser`].
//!
//! Redis speaks RESP: a request is an array of bulk strings
//! `*<n>\r\n$<len>\r\n<arg>\r\n...`, the first element being the command verb
//! (`GET`/`SET`/`HSET`/…). Inline commands (`PING\r\n`, no leading `*`) also
//! exist. Responses are one of the RESP value types: simple string (`+OK\r\n`),
//! error (`-ERR ...\r\n`), integer (`:42\r\n`), bulk string (`$5\r\nhello\r\n`),
//! array (`*<n>\r\n...`), plus the RESP3 additions (`_` null, `#` bool, `,`
//! double, `(` big-number, `=` verbatim, `%` map, `~` set, `>` push, `|`
//! attribute). The exchange is request-then-response per connection — even
//! pipelined, replies come back in request order — so a FIFO queue pairs them.
//!
//! Hand-rolled framing (no crate): RESP is a trivial length-prefixed grammar and
//! leanness is the moat. We only decode what a span needs — the request's command
//! verb and the response's error verdict — never key names or payload bytes.
//! Every value type is framed (its byte length computed) so the stream advances
//! cleanly past replies we don't otherwise care about, including nested arrays.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Recursion bound when framing a nested aggregate reply (array/map/set/push).
/// A reply nested deeper than this is treated as unparseable rather than risking
/// a stack blow-up on a hostile or corrupt stream.
const MAX_DEPTH: usize = 32;

/// Inline commands we recognise as a positive detection signature. Not the full
/// command set — just enough common verbs that a connection opened with an inline
/// command (rare, but `redis-cli` and health checks do it) is still identified.
const INLINE_VERBS: [&str; 6] = ["PING", "QUIT", "INFO", "AUTH", "HELLO", "COMMAND"];

/// Outcome of framing one RESP value (or request) at the front of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame<T> {
    /// A complete value was framed: its payload plus how many bytes it occupied.
    Complete { value: T, total_len: usize },
    /// Valid-so-far but the buffer doesn't hold the whole value yet — wait.
    Partial,
    /// Not well-formed RESP — drop the connection.
    Invalid,
}

/// Find the index just past the next CRLF in `buf` starting at `from`, i.e. the
/// offset of the byte after `\n`. `None` if no complete line is buffered yet.
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

/// Parse the integer length/count argument on a type line, e.g. the `5` in
/// `$5\r\n` or the `3` in `*3\r\n`. The slice is the bytes between the type byte
/// and the CRLF. Negative values (`-1` = RESP2 null) yield `None` as a length.
fn parse_len(slice: &[u8]) -> Result<Option<usize>, ()> {
    let s = std::str::from_utf8(slice).map_err(|_| ())?;
    let n: i64 = s.trim().parse().map_err(|_| ())?;
    if n < 0 {
        Ok(None)
    } else {
        Ok(Some(n as usize))
    }
}

/// The command verb of a request: the first array element, uppercased. The span's
/// operation label. Key names and arguments are deliberately not retained.
type Verb = String;

/// Frame a RESP request at the front of `buf`, returning the command verb and the
/// request's total byte length. Handles both the array form
/// (`*<n>\r\n$<len>\r\n<arg>\r\n...`) and the bare inline form (`PING\r\n`).
fn frame_request(buf: &[u8]) -> Frame<Verb> {
    match buf.first() {
        None => Frame::Partial,
        Some(b'*') => frame_request_array(buf),
        Some(_) => frame_inline(buf),
    }
}

/// Frame a multi-bulk request array. The verb is the first bulk string's bytes,
/// uppercased; remaining elements are framed (length-skipped) but not decoded.
fn frame_request_array(buf: &[u8]) -> Frame<Verb> {
    let Some(head) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let count = match parse_len(&buf[1..head - 2]) {
        Ok(Some(n)) if n >= 1 => n,
        // An empty (`*0`) or null (`*-1`) array is not a command — malformed here.
        _ => return Frame::Invalid,
    };

    let mut pos = head;
    let mut verb: Option<Verb> = None;
    for _ in 0..count {
        match frame_bulk_string(&buf[pos..]) {
            Frame::Complete { value, total_len } => {
                if verb.is_none() {
                    verb = Some(value.to_ascii_uppercase());
                }
                pos += total_len;
            }
            Frame::Partial => return Frame::Partial,
            Frame::Invalid => return Frame::Invalid,
        }
    }
    match verb {
        Some(value) => Frame::Complete {
            value,
            total_len: pos,
        },
        None => Frame::Invalid,
    }
}

/// Frame one `$<len>\r\n<bytes>\r\n` bulk string, returning its raw bytes (as a
/// lossy UTF-8 string — verbs are ASCII) and total length. A null bulk (`$-1`)
/// has no body and yields an empty string.
fn frame_bulk_string(buf: &[u8]) -> Frame<String> {
    if buf.first() != Some(&b'$') {
        return Frame::Invalid;
    }
    let Some(head) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let len = match parse_len(&buf[1..head - 2]) {
        Ok(Some(n)) => n,
        Ok(None) => {
            // Null bulk string: header only, no body, no trailing CRLF.
            return Frame::Complete {
                value: String::new(),
                total_len: head,
            };
        }
        Err(()) => return Frame::Invalid,
    };
    let total_len = head + len + 2; // body + trailing CRLF
    if buf.len() < total_len {
        return Frame::Partial;
    }
    let body = &buf[head..head + len];
    Frame::Complete {
        value: String::from_utf8_lossy(body).into_owned(),
        total_len,
    }
}

/// Frame an inline command: a bare line of space-separated tokens terminated by
/// CRLF (`PING\r\n`). The verb is the first token, uppercased.
fn frame_inline(buf: &[u8]) -> Frame<Verb> {
    let Some(end) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let line = &buf[..end - 2];
    let token = line
        .split(|&b| b == b' ')
        .find(|t| !t.is_empty())
        .unwrap_or(&[]);
    if token.is_empty() {
        return Frame::Invalid;
    }
    Frame::Complete {
        value: String::from_utf8_lossy(token).to_ascii_uppercase(),
        total_len: end,
    }
}

/// The error verdict of a response: `is_error` is true only for a RESP error
/// (`-...`). The total byte length lets the stream advance past the whole reply.
/// `pairs` is false for out-of-band data (RESP3 push `>`) that frames off the
/// wire but does NOT answer a pending request — pairing it would steal a real
/// command's reply slot and misalign every subsequent request/response pair.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResponseVerdict {
    is_error: bool,
    pairs: bool,
}

/// Frame one RESP reply at the front of `buf`, returning its error verdict, total
/// byte length, and whether it pairs with a pending request.
///
/// Two RESP3 framing subtleties handled here that a naive "frame one value" does
/// not:
///   * **Attributes** (`|<n>`) are a *prefix*, not a reply. Per the spec they
///     "precede a valid part of the protocol identifying a given type" and supply
///     auxiliary data about the value that immediately follows. So we strip any
///     stacked attribute maps and fold their bytes into the reply that follows —
///     they are not a standalone reply and must not consume a pending request.
///   * **Pushes** (`>`) are out-of-band (pub/sub, client tracking, monitor). They
///     "may appear before or after a command's reply, as well as by itself". They
///     frame off the wire but do not answer a request, so `pairs` is false.
fn frame_response(buf: &[u8]) -> Frame<ResponseVerdict> {
    // Strip any leading attribute prefixes; their bytes belong to the reply that
    // follows. Bounded by MAX_DEPTH so a stream of attributes can't spin forever.
    let mut consumed = 0usize;
    for _ in 0..=MAX_DEPTH {
        match buf.get(consumed) {
            None => return Frame::Partial,
            Some(b'|') => match frame_value(&buf[consumed..], 0) {
                Frame::Complete { total_len, .. } => consumed += total_len,
                Frame::Partial => return Frame::Partial,
                Frame::Invalid => return Frame::Invalid,
            },
            // First non-attribute byte: this is the reply proper.
            Some(&b'>') => {
                return match frame_value(&buf[consumed..], 0) {
                    Frame::Complete { total_len, .. } => Frame::Complete {
                        value: ResponseVerdict {
                            is_error: false,
                            pairs: false,
                        },
                        total_len: consumed + total_len,
                    },
                    Frame::Partial => Frame::Partial,
                    Frame::Invalid => Frame::Invalid,
                };
            }
            Some(_) => {
                return match frame_value(&buf[consumed..], 0) {
                    Frame::Complete { value, total_len } => Frame::Complete {
                        value: ResponseVerdict {
                            pairs: true,
                            ..value
                        },
                        total_len: consumed + total_len,
                    },
                    Frame::Partial => Frame::Partial,
                    Frame::Invalid => Frame::Invalid,
                };
            }
        }
    }
    // More than MAX_DEPTH stacked attributes with no terminating value: hostile.
    Frame::Invalid
}

/// Frame a single RESP value (`depth` guards aggregate nesting). Returns whether
/// the value is a top-level RESP error and the value's total byte length.
fn frame_value(buf: &[u8], depth: usize) -> Frame<ResponseVerdict> {
    if depth > MAX_DEPTH {
        return Frame::Invalid;
    }
    let Some(&type_byte) = buf.first() else {
        return Frame::Partial;
    };
    match type_byte {
        // Bulk string / verbatim string: length-prefixed body + CRLF.
        b'$' | b'=' => match frame_bulk_string_typed(buf) {
            Frame::Complete { total_len, .. } => ok(false, total_len),
            Frame::Partial => Frame::Partial,
            Frame::Invalid => Frame::Invalid,
        },
        // Aggregates: a count line, then `count` nested values. Maps/attributes
        // count key+value pairs, so element count is `2 * n`.
        b'*' | b'~' | b'>' => frame_aggregate(buf, 1, depth),
        b'%' | b'|' => frame_aggregate(buf, 2, depth),
        // Error reply — the one type that sets the failure verdict.
        b'-' => single_line(buf, true),
        // Single-line scalar types: simple string, integer, null, bool, double,
        // big number. All terminate at the first CRLF.
        b'+' | b':' | b'_' | b'#' | b',' | b'(' => single_line(buf, false),
        // Unknown leading byte — not RESP we recognise.
        _ => Frame::Invalid,
    }
}

/// A single-line RESP value: everything up to and including the next CRLF.
fn single_line(buf: &[u8], is_error: bool) -> Frame<ResponseVerdict> {
    match line_end(buf, 0) {
        Some(end) => ok(is_error, end),
        None => Frame::Partial,
    }
}

/// Frame a `$`/`=` reply (bulk or verbatim string) for the response path; we only
/// need its total length, so the body bytes are skipped, not materialised.
fn frame_bulk_string_typed(buf: &[u8]) -> Frame<()> {
    let Some(head) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let len = match parse_len(&buf[1..head - 2]) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return Frame::Complete {
                value: (),
                total_len: head,
            };
        } // null bulk
        Err(()) => return Frame::Invalid,
    };
    let total_len = head + len + 2;
    if buf.len() < total_len {
        return Frame::Partial;
    }
    Frame::Complete {
        value: (),
        total_len,
    }
}

/// Frame an aggregate reply (array/set/push/map/attribute): a count line followed
/// by `count * elems_per_item` nested values. A null aggregate (`*-1`) is just the
/// header line. The whole aggregate inherits no error verdict (only `-` does).
fn frame_aggregate(buf: &[u8], elems_per_item: usize, depth: usize) -> Frame<ResponseVerdict> {
    let Some(head) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let count = match parse_len(&buf[1..head - 2]) {
        Ok(Some(n)) => n,
        Ok(None) => return ok(false, head), // null aggregate, header only
        Err(()) => return Frame::Invalid,
    };
    let mut pos = head;
    for _ in 0..(count * elems_per_item) {
        match frame_value(&buf[pos..], depth + 1) {
            Frame::Complete { total_len, .. } => pos += total_len,
            Frame::Partial => return Frame::Partial,
            Frame::Invalid => return Frame::Invalid,
        }
    }
    ok(false, pos)
}

/// Build a `Complete` response verdict — small helper to keep call sites terse.
/// `pairs` defaults true; `frame_response` overrides it for out-of-band pushes.
fn ok(is_error: bool, total_len: usize) -> Frame<ResponseVerdict> {
    Frame::Complete {
        value: ResponseVerdict {
            is_error,
            pairs: true,
        },
        total_len,
    }
}

/// True if `buf` begins a recognisable RESP request: a multi-bulk array
/// (`*<digit>`) or a known inline command verb followed by a space or CRLF. A
/// positive signature, never a guess — random bytes that happen to start with a
/// digit don't match. Returns `false` while still ambiguous (caller waits).
pub(crate) fn looks_like_request(buf: &[u8]) -> bool {
    matches!(buf, [b'*', d, ..] if d.is_ascii_digit()) || looks_like_inline(buf)
}

/// True if `buf` starts with a known inline command verb delimited by a space or
/// CRLF (`PING\r\n`, `INFO\r\n`). The delimiter check stops `PINGER` matching.
fn looks_like_inline(buf: &[u8]) -> bool {
    INLINE_VERBS.iter().any(|verb| {
        let vb = verb.as_bytes();
        buf.len() >= vb.len()
            && buf[..vb.len()].eq_ignore_ascii_case(vb)
            && matches!(
                buf.get(vb.len()),
                None | Some(b' ') | Some(b'\r') | Some(b'\n')
            )
    })
}

/// Recognise Redis from a connection's inbound prefix and return a fresh boxed
/// parser, or `None` if these bytes aren't a RESP request. Phase 4 wires this into
/// `super::conn::detect`.
pub(crate) fn detect_redis(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if looks_like_request(inbound) {
        Some(Box::new(RedisParser::new()))
    } else {
        None
    }
}

/// A request awaiting its reply, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    verb: Verb,
    start_unix_nano: i64,
}

/// Redis [`L7Parser`]: reassembles each direction, frames RESP requests/replies,
/// pairs them FIFO, and emits one [`L7Record`] per pair. Unrecoverable bytes mark
/// it dead so the connection is dropped.
#[derive(Debug, Default)]
pub(crate) struct RedisParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl RedisParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frame as many complete requests as the inbound buffer holds, queueing each
    /// verb to await its reply. Stops on a partial (waits) or invalid (dies).
    fn drain_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() {
                return;
            }
            if self.inbound.buf.is_empty() {
                return;
            }
            match frame_request(&self.inbound.buf) {
                Frame::Complete { value, total_len } => {
                    self.pending.push_back(Pending {
                        verb: value,
                        start_unix_nano: ts,
                    });
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

    /// Frame as many complete replies as the outbound buffer holds, pairing each
    /// with the oldest unanswered request. A reply with no pending request is
    /// dropped — we attached mid-connection and missed its request.
    fn drain_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() {
                return;
            }
            if self.outbound.buf.is_empty() {
                return;
            }
            match frame_response(&self.outbound.buf) {
                Frame::Complete { value, total_len } => {
                    // Out-of-band data (RESP3 push) frames off the wire but answers
                    // no request — advance past it without consuming a pending one.
                    if value.pairs
                        && let Some(req) = self.pending.pop_front()
                    {
                        self.records.push(L7Record {
                            protocol: Protocol::Redis,
                            attributes: Vec::new(),
                            operation: req.verb,
                            status_code: if value.is_error { 1 } else { 0 },
                            error: value.is_error,
                            start_unix_nano: req.start_unix_nano,
                            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
                        });
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
}

impl L7Parser for RedisParser {
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

    fn record(
        parser: &mut RedisParser,
        req: &[u8],
        req_ts: i64,
        resp: &[u8],
        resp_ts: i64,
    ) -> Vec<L7Record> {
        parser.on_inbound(req, req_ts);
        parser.on_outbound(resp, resp_ts);
        parser.take_records()
    }

    #[test]
    fn detects_resp_array_and_inline_by_positive_signature() {
        assert!(looks_like_request(b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n"));
        assert!(looks_like_request(b"PING\r\n"));
        assert!(looks_like_request(b"INFO\r\n"));
        assert!(looks_like_request(b"AUTH secret\r\n"));
        // Not Redis: array marker not followed by a digit, unknown inline verb,
        // an HTTP request, or random binary.
        assert!(!looks_like_request(b"*X\r\n"));
        assert!(!looks_like_request(b"PINGER\r\n")); // verb must be delimited
        assert!(!looks_like_request(b"GET /x HTTP/1.1\r\n"));
        assert!(!looks_like_request(b"\x16\x03\x01\x02"));
    }

    #[test]
    fn detect_redis_returns_a_parser_only_on_a_match() {
        assert!(detect_redis(b"*1\r\n$4\r\nPING\r\n").is_some());
        assert!(detect_redis(b"PING\r\n").is_some());
        assert!(detect_redis(b"not redis at all").is_none());
    }

    #[test]
    fn frames_a_request_array_with_the_verb_uppercased() {
        // Lowercase verb on the wire must normalise to GET.
        let buf = b"*3\r\n$3\r\nget\r\n$1\r\nk\r\n$1\r\nv\r\n";
        match frame_request(buf) {
            Frame::Complete { value, total_len } => {
                assert_eq!(value, "GET");
                assert_eq!(total_len, buf.len());
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn frames_an_inline_command() {
        match frame_request(b"PING\r\n") {
            Frame::Complete { value, total_len } => {
                assert_eq!(value, "PING");
                assert_eq!(total_len, 6);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        // Inline with an argument: verb is the first token only.
        match frame_request(b"GET foo\r\n") {
            Frame::Complete { value, .. } => assert_eq!(value, "GET"),
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn one_request_response_yields_one_record() {
        let mut p = RedisParser::new();
        let recs = record(
            &mut p,
            b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
            1_000,
            b"+OK\r\n",
            1_400,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SET");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn bulk_string_reply_pairs_with_its_request() {
        // GET returns a bulk string value; we frame past the body without decoding.
        let mut p = RedisParser::new();
        let recs = record(
            &mut p,
            b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n",
            10,
            b"$5\r\nhello\r\n",
            25,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 15);
    }

    #[test]
    fn error_reply_sets_the_failure_verdict() {
        let mut p = RedisParser::new();
        let recs = record(
            &mut p,
            b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n",
            0,
            b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
            5,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn fragmented_request_waits_instead_of_misparsing() {
        let mut p = RedisParser::new();
        // First half of a SET — header + verb only, value not yet arrived.
        p.on_inbound(b"*3\r\n$3\r\nSET\r\n$3\r\nfoo", 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // partial, not garbage
        // Remainder arrives, then the reply.
        p.on_inbound(b"\r\n$3\r\nbar\r\n", 1);
        p.on_outbound(b"+OK\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SET");
    }

    #[test]
    fn fragmented_reply_waits_for_the_full_bulk_body() {
        let mut p = RedisParser::new();
        p.on_inbound(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n", 1);
        // Bulk reply header says 5 bytes but only 2 are here — must wait.
        p.on_outbound(b"$5\r\nhe", 2);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        p.on_outbound(b"llo\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert_eq!(recs[0].duration_nano, 2);
    }

    #[test]
    fn pipelined_requests_pair_in_arrival_order() {
        let mut p = RedisParser::new();
        // Two requests pipelined in one inbound segment.
        p.on_inbound(b"*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$1\r\nx\r\n", 100);
        // Two replies come back in order: +PONG then an error.
        p.on_outbound(b"+PONG\r\n-ERR boom\r\n", 130);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "PING");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "GET");
        assert!(recs[1].error);
    }

    #[test]
    fn integer_and_array_replies_frame_cleanly() {
        // An integer reply (INCR) then an array reply (MGET) on the same conn,
        // proving multi-element aggregate framing advances past nested values.
        let mut p = RedisParser::new();
        p.on_inbound(b"*2\r\n$4\r\nINCR\r\n$1\r\nn\r\n", 1);
        p.on_inbound(b"*3\r\n$4\r\nMGET\r\n$1\r\na\r\n$1\r\nb\r\n", 2);
        p.on_outbound(b":7\r\n", 3);
        p.on_outbound(b"*2\r\n$1\r\nx\r\n$-1\r\n", 4); // array with a value + a null
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "INCR");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "MGET");
        assert!(!recs[1].error);
    }

    #[test]
    fn resp3_map_reply_is_framed_gracefully() {
        // RESP3 HELLO returns a map (`%`); ensure we frame it without misreading.
        let mut p = RedisParser::new();
        p.on_inbound(b"*1\r\n$5\r\nHELLO\r\n", 1);
        p.on_outbound(b"%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "HELLO");
        assert!(!recs[0].error);
    }

    #[test]
    fn resp3_push_is_out_of_band_and_does_not_steal_a_reply() {
        // Two commands outstanding, with a pub/sub push (`>`) interleaved between
        // their replies. Per spec a push answers no request. If it wrongly consumed
        // a pending request, GET would steal SET's slot and INCR's reply (the error)
        // would land on GET — every later pair misaligned. Correct framing yields
        // SET→+OK (ok) and INCR→-ERR (error), with the push consuming nothing.
        let mut p = RedisParser::new();
        p.on_inbound(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", 10);
        p.on_inbound(b"*2\r\n$4\r\nINCR\r\n$1\r\nn\r\n", 11);
        p.on_outbound(
            b"+OK\r\n>3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n-ERR overflow\r\n",
            20,
        );
        let recs = p.take_records();
        assert_eq!(recs.len(), 2, "push must not produce or steal a record");
        assert_eq!(recs[0].operation, "SET");
        assert!(
            !recs[0].error,
            "SET reply (+OK) must not inherit the push/error"
        );
        assert_eq!(recs[1].operation, "INCR");
        assert!(recs[1].error, "INCR must pair with the -ERR after the push");
        assert!(p.pending.is_empty());
    }

    #[test]
    fn standalone_push_with_no_pending_request_is_dropped_not_dead() {
        // A push can appear by itself (server-initiated, no command outstanding).
        // It must frame and be skipped, leaving the parser alive with no records.
        let mut p = RedisParser::new();
        p.on_outbound(b">2\r\n$7\r\nmessage\r\n$5\r\nhello\r\n", 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn resp3_attribute_prefix_is_folded_into_the_following_reply() {
        // An attribute (`|`) is a PREFIX to the reply, not a reply itself. A naive
        // value-framer treats it as a standalone value: the attribute pops SET, then
        // the trailing +OK pops GET — leaving GET's real reply to misalign onto the
        // next request. Two outstanding commands make that corruption visible.
        let mut p = RedisParser::new();
        p.on_inbound(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", 1);
        p.on_inbound(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n", 2);
        // SET's reply carries a |1<ttl:3600> attribute prefix, then GET's $3 bar.
        p.on_outbound(b"|1\r\n+ttl\r\n:3600\r\n+OK\r\n$3\r\nbar\r\n", 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2, "attribute must not consume an extra request");
        assert_eq!(recs[0].operation, "SET");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "GET");
        assert!(!recs[1].error);
        assert!(p.pending.is_empty());
    }

    #[test]
    fn attribute_prefixing_an_error_keeps_the_error_verdict() {
        // The error verdict must come from the value AFTER the attribute, not be
        // swallowed by framing the attribute as the reply.
        let mut p = RedisParser::new();
        p.on_inbound(b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n", 0);
        p.on_outbound(b"|1\r\n+key\r\n+popularity\r\n-ERR nope\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET");
        assert!(
            recs[0].error,
            "verdict must reflect the post-attribute error"
        );
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn attribute_then_incomplete_reply_waits() {
        // Attribute fully buffered but the trailing reply has not arrived: the whole
        // logical reply must WAIT (Partial), not pair with the attribute alone.
        let mut p = RedisParser::new();
        p.on_inbound(b"*1\r\n$4\r\nPING\r\n", 1);
        p.on_outbound(b"|1\r\n+ttl\r\n:3600\r\n", 2); // attribute only, reply pending
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        assert_eq!(p.pending.len(), 1, "request still awaits its reply");
        p.on_outbound(b"+PONG\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PING");
    }

    #[test]
    fn garbage_outbound_marks_the_parser_dead() {
        let mut p = RedisParser::new();
        p.on_inbound(b"*1\r\n$4\r\nPING\r\n", 1);
        p.on_outbound(b"\x00not a resp reply\r\n", 2); // unknown type byte
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn orphan_reply_with_no_pending_request_is_dropped() {
        let mut p = RedisParser::new();
        p.on_outbound(b"+OK\r\n", 0); // attached mid-connection, missed the request
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn huge_length_headers_never_overflow_or_panic() {
        // i64::MAX length/count fields must frame as Partial (we never have that
        // many bytes), not panic on `head + len + 2` / `count * elems` arithmetic.
        assert_eq!(
            frame_request(b"*3\r\n$9223372036854775807\r\n"),
            Frame::Partial
        );
        assert_eq!(frame_response(b"$9223372036854775807\r\n"), Frame::Partial);
        assert_eq!(frame_response(b"=9223372036854775807\r\n"), Frame::Partial);
        assert_eq!(frame_response(b"*9223372036854775807\r\n"), Frame::Partial);
        assert_eq!(frame_response(b"%9223372036854775807\r\n"), Frame::Partial);
        assert_eq!(frame_response(b">9223372036854775807\r\n"), Frame::Partial);
        // A length beyond i64 must be rejected, not silently wrapped.
        assert_eq!(
            frame_response(b"$99999999999999999999999\r\n"),
            Frame::Invalid
        );
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: feed hostile/truncated payloads at every byte boundary, both
        // directions, in both orders. The hard requirement is no panic, ever — a
        // wrong verdict is acceptable, a crash is not.
        let payloads: &[&[u8]] = &[
            b"*-1\r\n",                      // null array as request
            b"*0\r\n",                       // empty array
            b"$-1\r\n",                      // null bulk
            b"*1\r\n$-5\r\n",                // negative bulk len inside array
            b"*\r\n",                        // missing count
            b"*1\r\n$\r\n",                  // missing bulk len
            b"|1\r\n",                       // bare attribute, no following value
            b">",                            // lone push marker
            b"%1\r\n$3\r\nfoo\r\n",          // truncated map (only key)
            b"*2\r\n$3\r\nGET\r\n+trailing", // mixed types under array
            b"\r\n\r\n\r\n",                 // only CRLFs
            b":not-a-number\r\n",            // scalar with junk
            b"\x00\x01\x02\x03",             // raw binary
            b"-",                            // lone error marker
            b"$5\r\nhi\r\n",                 // body shorter than declared len
            &[b'*'; 1024],                   // many array markers, no CRLF
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // request side
                let mut p = RedisParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                // response side
                let mut q = RedisParser::new();
                q.on_inbound(b"*1\r\n$4\r\nPING\r\n", 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
            }
        }
    }

    #[test]
    fn deeply_nested_aggregate_is_rejected_not_overflowed() {
        // A reply nested past MAX_DEPTH must be rejected (parser dies), never blow
        // the stack. Build *1*1*1... deeper than the bound, capped off with a scalar.
        let mut buf = Vec::new();
        for _ in 0..(MAX_DEPTH + 5) {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":1\r\n");
        assert_eq!(frame_response(&buf), Frame::Invalid);

        // Just under the bound must still frame cleanly.
        let mut ok_buf = Vec::new();
        for _ in 0..(MAX_DEPTH - 1) {
            ok_buf.extend_from_slice(b"*1\r\n");
        }
        ok_buf.extend_from_slice(b":1\r\n");
        assert!(matches!(frame_response(&ok_buf), Frame::Complete { .. }));
    }
}
