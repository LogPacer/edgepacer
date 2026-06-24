//! PostgreSQL v3 wire parser — implements [`super::L7Parser`], the zero-code APM
//! producer for Postgres connections (the agent monitors a *client* process, so
//! "inbound" here is the bytes the app reads from the socket on the request side
//! and "outbound" is what it writes — see the trait doc; for a client, the
//! frontend->backend `Query` rides on the write side and the backend's reply on
//! the read side, but the [`super::L7Parser`] contract is direction-agnostic: we
//! treat the side carrying `Q`/`P` tags as the request side and the side carrying
//! `C`/`E`/`Z` tags as the response side, and pair them FIFO).
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every v3 message is `[1-byte type tag][4-byte BE length][body]`, where the
//! length counts itself + the body but NOT the tag, so `total_len = 1 + length`.
//! The one exception is the *first* frontend message (`StartupMessage` /
//! `SSLRequest` / `CancelRequest`): it has NO tag — just `[4-byte BE length][body]`
//! whose first body word is a protocol/request code. We recognise it, skip it, and
//! resume tagged framing. Framing is a 5-byte BE read; pulling a Postgres driver
//! crate for that would betray the leanness moat, so it's hand-rolled.
//!
//! ## What we extract (and only this)
//!
//! - `operation`: the SQL verb (`SELECT`/`INSERT`/…), plus the first referenced
//!   table when cleanly recoverable (`SELECT users`). We decode only the `Q`/`P`
//!   SQL text — never row data, never `Bind` parameters.
//! - `status_code`: `0` on success; on `ErrorResponse` the SQLSTATE *class* (the
//!   first two chars of the 5-char `C` field, e.g. `42` of `42P01`) as a `u16`,
//!   or `0` if absent/non-numeric. SQLSTATE is alphanumeric, so the class is the
//!   only faithful numeric projection.
//! - `error`: true iff the response terminator was `ErrorResponse`.
//! - timing: request `ts` -> response `ts` (saturating), per the trait.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Frontend (request-side) message tags we act on.
const TAG_QUERY: u8 = b'Q'; // simple query: body = NUL-terminated SQL
const TAG_PARSE: u8 = b'P'; // extended-protocol prepared-statement parse

/// Backend (response-side) terminator tags. A query completes on the first of
/// these; everything between (RowDescription/DataRow/…) is framed past, unread.
const TAG_COMMAND_COMPLETE: u8 = b'C';
const TAG_ERROR_RESPONSE: u8 = b'E';

/// `StartupMessage` protocol version (major 3, minor 0) — the first body word of
/// an untagged startup frame. `SSLRequest` (80877103) and `CancelRequest`
/// (80877102) use distinct codes; we treat any untagged frame with a sane length
/// as a startup-class message to skip.
const PROTOCOL_V3: u32 = 0x0003_0000;

/// Sanity bound on a single message: lengths beyond this on a "Postgres" stream
/// mean we mis-detected or desynced — bail rather than buffer unboundedly. The
/// protocol allows larger messages, but for span extraction nothing useful lives
/// past this, and it caps memory on a hostile/garbage stream.
const MAX_MSG_LEN: usize = 4 * 1024 * 1024;

/// Minimum bytes to read a message head: tag (1) + length (4). The untagged
/// startup frame needs only the 4-byte length, handled separately.
const HEAD_LEN: usize = 5;

/// Read a big-endian u32 from the first four bytes of `b` (caller guarantees len).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Does this tag begin a frontend message we know how to label?
fn is_request_tag(tag: u8) -> bool {
    tag == TAG_QUERY || tag == TAG_PARSE
}

/// Is this a sane tagged-message length field? `length` counts itself + body, so
/// it must be at least 4 (the length word) and within our memory bound.
fn sane_len(length: u32) -> bool {
    length >= 4 && (length as usize) <= MAX_MSG_LEN
}

/// Outcome of trying to read one message head off a direction buffer prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A framed message: its tag (`None` for the untagged startup frame) and the
    /// total bytes it occupies (`tag? + length`).
    Framed { tag: Option<u8>, total_len: usize },
    /// A valid prefix but not enough bytes yet — wait.
    Partial,
    /// Not Postgres framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Parse one message head from a request-side buffer. `expect_startup` lets the
/// very first frontend frame be the untagged `StartupMessage`.
fn request_head(buf: &[u8], expect_startup: bool) -> Head {
    if expect_startup {
        // Untagged startup frame: [len:4][code:4][...]. Disambiguate from a tagged
        // message by validating the protocol/request code in the body.
        if buf.len() < 8 {
            return Head::Partial;
        }
        let length = be_u32(&buf[0..4]);
        let code = be_u32(&buf[4..8]);
        let is_startup = code == PROTOCOL_V3 || (0x0400_0000..0x0500_0000).contains(&code);
        if is_startup && sane_len(length) {
            return Head::Framed {
                tag: None,
                total_len: length as usize, // untagged: total == length
            };
        }
        // Not a startup frame after all — fall through to tagged parsing (a client
        // that attached mid-stream sends a tagged Query first).
    }
    tagged_head(buf)
}

/// Parse one tagged message head: `[tag:1][length:4 BE]`. Any tag is framed (so
/// we can skip messages we don't act on); only a length that fails the sanity
/// bound is `Invalid` — that's the desync signal.
fn tagged_head(buf: &[u8]) -> Head {
    if buf.len() < HEAD_LEN {
        return Head::Partial;
    }
    let tag = buf[0];
    let length = be_u32(&buf[1..5]);
    if !sane_len(length) {
        return Head::Invalid;
    }
    Head::Framed {
        tag: Some(tag),
        total_len: 1 + length as usize,
    }
}

/// Extract the operation label from a simple-query (`Q`) or parse (`P`) body.
/// `Q` body = NUL-terminated SQL. `P` body = destination name (NUL) then the SQL
/// (NUL) then param types — we read up to the SQL's terminator. Returns the SQL
/// verb uppercased, plus the first table when cleanly recoverable.
fn operation_label(tag: u8, body: &[u8]) -> String {
    let sql = match tag {
        TAG_QUERY => cstr(body),
        TAG_PARSE => {
            // Skip the statement-name C-string, then take the query C-string.
            let after_name = body.iter().position(|&b| b == 0).map(|i| i + 1);
            after_name.map(|i| cstr(&body[i..])).unwrap_or("")
        }
        _ => "",
    };
    label_from_sql(sql)
}

/// Borrow the leading NUL-terminated string from `body` as UTF-8 (lossless on the
/// ASCII SQL keywords we read; we only ever inspect ASCII tokens).
fn cstr(body: &[u8]) -> &str {
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    std::str::from_utf8(&body[..end]).unwrap_or("")
}

/// Build the operation label from raw SQL text: the verb, plus the first table
/// name for the verbs where it's unambiguous (`from`/`into`/`update`/`join`).
fn label_from_sql(sql: &str) -> String {
    let mut tokens = sql.split_whitespace();
    let Some(verb_raw) = tokens.next() else {
        return "QUERY".to_string();
    };
    let verb = verb_raw.to_ascii_uppercase();
    if let Some(table) = first_table(&verb, sql) {
        format!("{verb} {table}")
    } else {
        verb
    }
}

/// Find the first table referenced after the verb's table keyword. Conservative:
/// only the four keywords whose next token is reliably a table name, and we strip
/// trailing punctuation. Returns `None` when nothing clean is found (label = verb).
fn first_table(verb: &str, sql: &str) -> Option<String> {
    let keyword: &str = match verb {
        "SELECT" | "DELETE" => "from",
        "INSERT" => "into",
        "UPDATE" => "update",
        _ => return None,
    };
    let lower = sql.to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let raw_tokens: Vec<&str> = sql.split_whitespace().collect();
    // For UPDATE the table is the token right after the verb; for the rest, the
    // token after the keyword.
    let idx = if verb == "UPDATE" {
        1
    } else {
        tokens.iter().position(|&t| t == keyword)? + 1
    };
    let raw = raw_tokens.get(idx)?;
    let cleaned: String = raw
        .trim_matches(|c: char| c == '(' || c == ')' || c == ';' || c == ',' || c == '"')
        .to_string();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// SQLSTATE *class* (first two chars) as a u16, or 0. SQLSTATE rides the `C`
/// field of an `ErrorResponse`: a sequence of `[field-type:1][value:cstr]` pairs
/// terminated by a NUL. The class digits (`42` of `42P01`) are the only faithful
/// numeric projection of an otherwise-alphanumeric code.
fn sqlstate_class(body: &[u8]) -> u16 {
    let mut i = 0;
    while i < body.len() {
        let field = body[i];
        if field == 0 {
            break; // end of fields
        }
        let value = cstr(&body[i + 1..]);
        if field == b'C' {
            return value
                .get(0..2)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
        }
        // advance past field byte + value + its NUL terminator
        i += 1 + value.len() + 1;
    }
    0
}

/// A request awaiting its terminator, with the observation time (for latency).
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// PostgreSQL [`L7Parser`]: frames both directions, labels `Q`/`P` requests,
/// pairs each with its terminating `CommandComplete`/`ErrorResponse` FIFO, and
/// frames past every other backend message unread. Desync marks it dead.
#[derive(Debug, Default)]
pub(crate) struct PostgresParser {
    request: DirBuf,
    response: DirBuf,
    /// The first request-side frame is the untagged StartupMessage; once skipped,
    /// all subsequent frames are tagged.
    saw_startup: bool,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    dead: bool,
}

impl PostgresParser {
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
            let expect_startup = !self.saw_startup;
            match request_head(&self.request.buf, expect_startup) {
                Head::Framed { tag, total_len } => {
                    match tag {
                        None => {
                            // Untagged StartupMessage: skip, then expect tags.
                            self.saw_startup = true;
                        }
                        Some(t) => {
                            if is_request_tag(t) {
                                // A request label needs the whole SQL body. If it
                                // hasn't all arrived, wait — don't advance, or the
                                // straddling body bytes get skipped as framing and
                                // the query is lost (no pending op to pair).
                                if total_len > self.request.buf.len() {
                                    return;
                                }
                                self.saw_startup = true;
                                let body = &self.request.buf[HEAD_LEN..total_len];
                                let op = operation_label(t, body);
                                self.pending.push_back(Pending {
                                    operation: op,
                                    start_unix_nano: ts,
                                });
                            } else {
                                // Non-request tags on the request side (Bind 'B',
                                // Sync 'S', Terminate 'X', …) carry nothing a span
                                // needs — frame past them, even when they straddle.
                                self.saw_startup = true;
                            }
                        }
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

    fn drain_response(&mut self, ts: i64) {
        loop {
            if !self.response.drain_skip() {
                return;
            }
            if self.response.buf.is_empty() {
                return;
            }
            match tagged_head(&self.response.buf) {
                Head::Framed { tag, total_len } => {
                    match tag {
                        Some(TAG_ERROR_RESPONSE) => {
                            // A terminator pairs with a pending request and stamps
                            // the response time. We must see the WHOLE message first:
                            // ErrorResponse needs its full body for the SQLSTATE
                            // class, and both terminators need the real completion
                            // time, not a fragment's arrival time. If the body is
                            // still straddling, wait — don't pop a pending op early.
                            if total_len > self.response.buf.len() {
                                return;
                            }
                            let status = sqlstate_class(&self.response.buf[HEAD_LEN..total_len]);
                            self.complete(true, status, ts);
                        }
                        Some(TAG_COMMAND_COMPLETE) => {
                            if total_len > self.response.buf.len() {
                                return;
                            }
                            self.complete(false, 0, ts);
                        }
                        // RowDescription/DataRow/ReadyForQuery/… carry nothing a
                        // span needs — frame past them, even when they straddle.
                        _ => {}
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

    /// Pair a terminator with the oldest unanswered request, emitting one record.
    /// A terminator with no pending request is dropped (attached mid-query).
    fn complete(&mut self, error: bool, status_code: u16, ts: i64) {
        if let Some(req) = self.pending.pop_front() {
            self.records.push(L7Record {
                protocol: Protocol::Postgres,
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

impl L7Parser for PostgresParser {
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

/// Recognise PostgreSQL from a request-side prefix via a POSITIVE signature and
/// return a fresh boxed parser, or `None` if it isn't (yet) recognisable.
///
/// Two positive signatures, byte-only (no port available at this layer):
/// 1. **Tagged simple-query/parse**: a `Q` or `P` tag + a sane BE length, and for
///    `Q` a body that is printable-ish text ending in NUL — what a client that
///    attached mid-session sends first.
/// 2. **StartupMessage**: `[len:4][0x00030000]` — the very first frontend frame of
///    a fresh connection.
///
/// Byte-only Postgres detection is inherently weak: a `Q`/`P` first byte is a
/// common ASCII letter, so a non-Postgres binary stream can collide. We require a
/// sane length *and* (for `Q`) text-shaped, NUL-terminated SQL to suppress most
/// false positives, and prefer returning `None` when unsure. A port hint (5432)
/// from the connection tuple would make this reliable; the byte sniff is the
/// fallback for when the tuple isn't threaded through.
pub(crate) fn detect_postgres(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    // Signature 2: untagged StartupMessage — strongest signal.
    if inbound.len() >= 8 {
        let length = be_u32(&inbound[0..4]);
        let code = be_u32(&inbound[4..8]);
        if code == PROTOCOL_V3 && sane_len(length) && (length as usize) <= MAX_MSG_LEN {
            return Some(Box::new(PostgresParser::new()));
        }
    }

    // Signature 1: tagged Query/Parse head.
    if inbound.len() >= HEAD_LEN {
        let tag = inbound[0];
        if is_request_tag(tag) {
            let length = be_u32(&inbound[1..5]);
            if sane_len(length) {
                // For 'Q' demand text-shaped, NUL-terminated SQL within the
                // buffered prefix to suppress binary collisions on the 'Q' byte.
                if tag == TAG_QUERY {
                    let body = &inbound[HEAD_LEN..];
                    if looks_like_sql(body) {
                        return Some(Box::new(PostgresParser::new()));
                    }
                } else {
                    // 'P' (Parse) — the statement-name + SQL shape is harder to
                    // validate cheaply; the sane length on a 'P' tag is accepted.
                    return Some(Box::new(PostgresParser::new()));
                }
            }
        }
    }

    None
}

/// Heuristic: does this `Q` body look like a NUL-terminated SQL string? We want
/// printable ASCII up to a NUL, no embedded control bytes. Empty/un-terminated
/// prefixes return false (wait for more / not Postgres).
fn looks_like_sql(body: &[u8]) -> bool {
    let Some(nul) = body.iter().position(|&b| b == 0) else {
        // No terminator buffered yet. If everything so far is printable, it could
        // still be Postgres — but to avoid false positives we only accept once the
        // terminator is visible.
        return false;
    };
    if nul == 0 {
        return false; // empty query string is not a useful positive signal
    }
    body[..nul]
        .iter()
        .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tagged v3 message: `[tag][len:4 BE][body]`, len = 4 + body.len().
    fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        let length = (4 + body.len()) as u32;
        let mut v = vec![tag];
        v.extend_from_slice(&length.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A simple-query frame: NUL-terminated SQL.
    fn query(sql: &str) -> Vec<u8> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        msg(TAG_QUERY, &body)
    }

    /// An untagged StartupMessage: `[len:4][0x00030000][params...]`.
    fn startup() -> Vec<u8> {
        let params = b"user\0postgres\0\0";
        let length = (4 + 4 + params.len()) as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_be_bytes());
        v.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
        v.extend_from_slice(params);
        v
    }

    /// A CommandComplete: tag 'C', NUL-terminated command tag (e.g. "SELECT 1").
    fn command_complete(tag_text: &str) -> Vec<u8> {
        let mut body = tag_text.as_bytes().to_vec();
        body.push(0);
        msg(TAG_COMMAND_COMPLETE, &body)
    }

    /// An ErrorResponse carrying a single SQLSTATE `C` field (`code`).
    fn error_response(sqlstate: &str) -> Vec<u8> {
        let mut body = vec![b'C'];
        body.extend_from_slice(sqlstate.as_bytes());
        body.push(0); // end the C field value
        body.push(0); // end the field list
        msg(TAG_ERROR_RESPONSE, &body)
    }

    #[test]
    fn detects_startup_message() {
        assert!(detect_postgres(&startup()).is_some());
    }

    #[test]
    fn detects_tagged_query_with_textual_sql() {
        assert!(detect_postgres(&query("SELECT 1")).is_some());
    }

    #[test]
    fn rejects_query_tag_with_binary_body() {
        // 'Q' tag + sane length but a non-text, un-terminated body: not Postgres.
        let mut buf = vec![TAG_QUERY];
        buf.extend_from_slice(&12u32.to_be_bytes());
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0x00]);
        assert!(detect_postgres(&buf).is_none());
    }

    #[test]
    fn rejects_non_postgres_prefix() {
        assert!(detect_postgres(b"GET /x HTTP/1.1\r\n").is_none());
        assert!(detect_postgres(b"\x00\x00\x00").is_none()); // too short
    }

    #[test]
    fn operation_label_extracts_verb_and_table() {
        assert_eq!(
            label_from_sql("SELECT * FROM users WHERE id = 1"),
            "SELECT users"
        );
        assert_eq!(
            label_from_sql("insert into orders (a) values (1)"),
            "INSERT orders"
        );
        assert_eq!(
            label_from_sql("UPDATE accounts SET x = 1"),
            "UPDATE accounts"
        );
        assert_eq!(label_from_sql("DELETE FROM sessions"), "DELETE sessions");
        // Verb-only fallback when no clean table keyword applies.
        assert_eq!(label_from_sql("BEGIN"), "BEGIN");
        assert_eq!(label_from_sql("COMMIT"), "COMMIT");
    }

    #[test]
    fn sqlstate_class_parses_leading_digits() {
        // 42P01 = undefined_table -> class 42.
        let body = {
            let mut b = vec![b'C'];
            b.extend_from_slice(b"42P01");
            b.push(0);
            b.push(0);
            b
        };
        assert_eq!(sqlstate_class(&body), 42);
        // No C field -> 0.
        let only_message = {
            let mut b = vec![b'M'];
            b.extend_from_slice(b"boom");
            b.push(0);
            b.push(0);
            b
        };
        assert_eq!(sqlstate_class(&only_message), 0);
    }

    #[test]
    fn normal_query_then_command_complete_yields_one_record() {
        let mut p = PostgresParser::new();
        // Startup, then a query, on the request side.
        p.on_inbound(&startup(), 1_000);
        p.on_inbound(&query("SELECT id FROM users"), 1_000);
        assert!(p.take_records().is_empty()); // no response yet
        // RowDescription + DataRow + CommandComplete + ReadyForQuery on the response.
        let mut resp = Vec::new();
        resp.extend(msg(b'T', b"\x00\x00")); // RowDescription (framed past)
        resp.extend(msg(b'D', b"\x00\x01\x00\x00\x00\x012")); // DataRow (framed past)
        resp.extend(command_complete("SELECT 1"));
        resp.extend(msg(b'Z', b"I")); // ReadyForQuery (framed past)
        p.on_outbound(&resp, 1_500);

        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT users");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 500);
    }

    #[test]
    fn fragmented_query_waits_then_completes() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 10);
        let q = query("SELECT * FROM orders");
        // Feed the query head + first half of the body, then the rest.
        let split = HEAD_LEN + 4;
        p.on_inbound(&q[..split], 10);
        assert!(p.take_records().is_empty());
        // No pending op should have been pushed from the truncated body — a
        // CommandComplete now would have nothing to pair with.
        p.on_outbound(&command_complete("SELECT 0"), 20);
        assert!(
            p.take_records().is_empty(),
            "must not pair against a truncated request"
        );
        // Deliver the rest of the query, then its real terminator.
        p.on_inbound(&q[split..], 30);
        p.on_outbound(&command_complete("SELECT 5"), 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT orders");
        assert_eq!(recs[0].start_unix_nano, 30);
        assert_eq!(recs[0].duration_nano, 20);
    }

    #[test]
    fn pipelined_queries_pair_fifo() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        // Two queries back-to-back in one segment.
        let mut reqs = Vec::new();
        reqs.extend(query("SELECT 1 FROM a"));
        reqs.extend(query("DELETE FROM b"));
        p.on_inbound(&reqs, 100);
        // Two terminators back-to-back, in order.
        let mut resps = Vec::new();
        resps.extend(command_complete("SELECT 1"));
        resps.extend(error_response("23505")); // unique_violation -> class 23
        p.on_outbound(&resps, 200);

        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SELECT a");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "DELETE b");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 23);
    }

    #[test]
    fn error_response_sets_error_and_status() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        p.on_inbound(&query("SELECT * FROM missing_table"), 1);
        p.on_outbound(&error_response("42P01"), 9); // undefined_table
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT missing_table");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 42);
        assert_eq!(recs[0].duration_nano, 8);
    }

    #[test]
    fn orphan_terminator_is_dropped() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        p.on_outbound(&command_complete("SELECT 0"), 5); // no pending request
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn insane_length_marks_dead() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        // A tagged frame with a 0-length field (< 4) is invalid framing.
        let mut bad = vec![TAG_QUERY];
        bad.extend_from_slice(&1u32.to_be_bytes()); // length 1, below the 4 minimum
        p.on_inbound(&bad, 0);
        assert!(p.is_dead());
    }

    /// REGRESSION: a fragmented ErrorResponse terminator must WAIT for its full
    /// body before completing — otherwise the pair is emitted at the head's
    /// arrival time with status_code 0 instead of the real SQLSTATE class.
    #[test]
    fn fragmented_error_response_waits_for_full_body_then_classifies() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        p.on_inbound(&query("SELECT * FROM missing_table"), 1);

        let err = error_response("42P01"); // undefined_table -> class 42
        // Deliver only the 5-byte head (tag + length) first. The body straddles.
        p.on_outbound(&err[..HEAD_LEN], 5);
        assert!(
            p.take_records().is_empty(),
            "must not complete on a partial terminator head"
        );
        // Now the rest of the body arrives at a later observation time.
        p.on_outbound(&err[HEAD_LEN..], 9);

        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        // The SQLSTATE class survives fragmentation (was 0 before the fix).
        assert_eq!(recs[0].status_code, 42);
        // Completion time is the full-message arrival, not the head fragment.
        assert_eq!(recs[0].duration_nano, 8);
    }

    /// REGRESSION: a fragmented CommandComplete must likewise wait, so latency is
    /// stamped at message completion, not at the head fragment's arrival.
    #[test]
    fn fragmented_command_complete_waits_for_full_body() {
        let mut p = PostgresParser::new();
        p.on_inbound(&startup(), 0);
        p.on_inbound(&query("SELECT 1 FROM t"), 100);

        let cc = command_complete("SELECT 1");
        p.on_outbound(&cc[..HEAD_LEN], 150);
        assert!(
            p.take_records().is_empty(),
            "must not complete on a partial CommandComplete head"
        );
        p.on_outbound(&cc[HEAD_LEN..], 300);

        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].error);
        assert_eq!(recs[0].status_code, 0);
        assert_eq!(recs[0].duration_nano, 200);
    }

    /// REGRESSION: byte-at-a-time delivery of a real query/response exchange must
    /// yield exactly one correct record — never a duplicate or an early emission
    /// from a partially-buffered terminator.
    #[test]
    fn byte_at_a_time_exchange_yields_one_record() {
        let mut p = PostgresParser::new();
        for (b, byte) in startup().iter().enumerate() {
            p.on_inbound(std::slice::from_ref(byte), b as i64);
        }
        for byte in query("SELECT id FROM users").iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());

        let mut resp = Vec::new();
        resp.extend(msg(b'T', b"\x00\x00"));
        resp.extend(msg(b'D', b"\x00\x01\x00\x00\x00\x012"));
        resp.extend(error_response("23505")); // unique_violation -> class 23
        let last = (resp.len() - 1) as i64;
        for (i, byte) in resp.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }

        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT users");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 23);
        // Stamped at the final byte of the terminator, not an earlier fragment.
        assert_eq!(recs[0].duration_nano, 2_000 + last - 1_000);
    }

    #[test]
    fn sqlstate_class_survives_truncated_error_body() {
        // 'C' field whose value is cut off mid-string with no NUL terminator.
        let mut b = vec![b'C'];
        b.extend_from_slice(b"42P0"); // truncated, no NUL
        assert_eq!(sqlstate_class(&b), 42); // leading digits still recovered
        // A bare field byte with nothing after it must not panic.
        assert_eq!(sqlstate_class(b"C"), 0);
        assert_eq!(sqlstate_class(b"S"), 0);
        assert_eq!(sqlstate_class(b""), 0);
        // 'C' value with non-numeric class -> 0, not a panic.
        let mut nn = vec![b'C'];
        nn.extend_from_slice(b"XX001");
        nn.push(0);
        nn.push(0);
        assert_eq!(sqlstate_class(&nn), 0);
    }

    /// HARD REQUIREMENT: never panic on adversarial bytes, in any framing, on
    /// either direction, at any fragmentation. Drive a spread of hostile inputs
    /// through a fresh parser and through detection; the only acceptable outcomes
    /// are "dead", "waiting", or a (possibly wrong-but-bounded) record — never a
    /// panic or unbounded buffering.
    #[test]
    fn never_panics_on_hostile_bytes() {
        let hostile: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff],
            vec![TAG_QUERY],
            vec![TAG_QUERY, 0xff, 0xff, 0xff, 0xff], // length ~4G -> insane
            vec![TAG_QUERY, 0x00, 0x00, 0x00, 0x00], // length 0 -> invalid
            vec![TAG_QUERY, 0x00, 0x00, 0x00, 0x04], // length exactly 4, empty body
            vec![TAG_ERROR_RESPONSE, 0x00, 0x00, 0x00, 0x05, b'C'], // C field, no value/NUL
            vec![TAG_PARSE, 0x00, 0x00, 0x00, 0x05, 0x00], // P, no name NUL/sql
            vec![b'E', 0x7f, 0xff, 0xff, 0xff],      // E, near-max length head only
            vec![0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00], // bare startup
            vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00], // startup len < 8
            (0u8..=255).collect(),
            b"\x00\x00\x00\x10garbage\xff\xfe\xfd".to_vec(),
        ];

        for seed in &hostile {
            // Detection must never panic.
            let _ = detect_postgres(seed);

            // Full parser, both directions, whole-buffer.
            let mut p = PostgresParser::new();
            p.on_inbound(seed, 1);
            p.on_outbound(seed, 2);
            let _ = p.take_records();
            let _ = p.is_dead();

            // Same bytes fed one at a time, alternating directions.
            let mut q = PostgresParser::new();
            for (i, byte) in seed.iter().enumerate() {
                let one = std::slice::from_ref(byte);
                if i % 2 == 0 {
                    q.on_inbound(one, i as i64);
                } else {
                    q.on_outbound(one, i as i64);
                }
            }
            let _ = q.take_records();
        }
    }
}
