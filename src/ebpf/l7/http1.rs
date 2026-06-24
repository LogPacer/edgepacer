//! HTTP/1.1 parsing: request line (method + path) and response status from
//! captured byte buffers, with the framing length needed to advance a streaming
//! connection past each message (head + Content-Length body), paired FIFO in
//! arrival order. HTTP/1.x is request-then-response per connection — even
//! pipelined, responses come back in request order — so a FIFO queue pairs them.
//!
//! Built on `httparse` (incremental, `Partial`-aware): a buffer that doesn't yet
//! hold a full head returns `Partial` ("need more bytes") rather than mis-parsing
//! a fragment.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Header slots scanned while parsing a head. Headers aren't retained beyond
/// Content-Length; this only bounds how many `httparse` walks before `\r\n\r\n`.
const MAX_HEADERS: usize = 32;

/// A parsed request head — method + path, plus the `Host` header (the service-map
/// edge's destination authority and the API-classification key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub host: String,
}

/// A parsed message plus the framing length the stream tracker uses to advance
/// past it: `total_len` = head bytes (`httparse`) + Content-Length body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed<T> {
    pub value: T,
    pub total_len: usize,
}

/// Outcome of parsing one direction's buffer prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome<T> {
    /// A complete head parsed (the body may not be buffered yet — `total_len`
    /// says how many bytes the whole message occupies).
    Complete(Framed<T>),
    /// Valid-so-far but incomplete head — wait for more bytes.
    Partial,
    /// Not valid HTTP/1.x — drop the connection.
    Invalid,
}

/// True if the buffer starts with a plausible HTTP/1.x request line: a known
/// method token followed by a space. A positive signature, never a guess.
pub fn looks_like_request(buf: &[u8]) -> bool {
    const METHODS: [&str; 9] = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m.as_bytes()))
}

fn content_length(headers: &[httparse::Header<'_>]) -> usize {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn host(headers: &[httparse::Header<'_>]) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Parse an HTTP/1.x request head from `buf`.
pub fn parse_request(buf: &[u8]) -> ParseOutcome<RequestHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(head_len)) => ParseOutcome::Complete(Framed {
            value: RequestHead {
                method: req.method.unwrap_or_default().to_string(),
                path: req.path.unwrap_or_default().to_string(),
                host: host(req.headers),
            },
            total_len: head_len + content_length(req.headers),
        }),
        Ok(httparse::Status::Partial) => ParseOutcome::Partial,
        Err(_) => ParseOutcome::Invalid,
    }
}

/// Parse an HTTP/1.x response status code from `buf`.
pub fn parse_response(buf: &[u8]) -> ParseOutcome<u16> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(head_len)) => match resp.code {
            Some(code) => ParseOutcome::Complete(Framed {
                value: code,
                total_len: head_len + content_length(resp.headers),
            }),
            None => ParseOutcome::Invalid,
        },
        Ok(httparse::Status::Partial) => ParseOutcome::Partial,
        Err(_) => ParseOutcome::Invalid,
    }
}

/// Span attributes the HTTP head supplies for service maps + API classification:
/// the destination authority (`http.host`) and the raw request target
/// (`http.target`). Empty host (HTTP/1.0, absolute-form, or stripped) is omitted.
fn http_attributes(head: &RequestHead) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    if !head.host.is_empty() {
        attrs.push(("http.host".to_string(), head.host.clone()));
    }
    attrs.push(("http.target".to_string(), head.path.clone()));
    attrs
}

/// A request awaiting its response, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    head: RequestHead,
    start_unix_nano: i64,
}

/// Per-connection HTTP/1.x request/response pairing. Requests are matched to
/// responses FIFO in arrival order.
#[derive(Debug, Default)]
pub struct Http1Conn {
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
}

impl Http1Conn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fully parsed request observed at `ts` (unix nanos), awaiting its
    /// response.
    pub fn on_request(&mut self, head: RequestHead, ts: i64) {
        self.pending.push_back(Pending {
            head,
            start_unix_nano: ts,
        });
    }

    /// Match a response (observed at `ts`) to the oldest unanswered request,
    /// emitting one record with its server latency. A response with no pending
    /// request is dropped — we attached mid-connection and missed its request.
    pub fn on_response(&mut self, status: u16, ts: i64) {
        if let Some(req) = self.pending.pop_front() {
            self.records.push(L7Record {
                protocol: Protocol::Http1,
                attributes: http_attributes(&req.head),
                operation: format!("{} {}", req.head.method, req.head.path),
                status_code: status,
                error: status >= 500,
                start_unix_nano: req.start_unix_nano,
                duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
            });
        }
    }

    /// Drain the records completed since the last call.
    pub fn take_records(&mut self) -> Vec<L7Record> {
        std::mem::take(&mut self.records)
    }
}

/// HTTP/1.x [`L7Parser`]: reassembles each direction past `head + Content-Length`,
/// parses request lines + response statuses, and pairs them FIFO. Unrecoverable
/// bytes mark it dead so the connection is dropped.
#[derive(Debug, Default)]
pub(crate) struct Http1Parser {
    inbound: DirBuf,
    outbound: DirBuf,
    conn: Http1Conn,
    dead: bool,
}

impl Http1Parser {
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
            match parse_request(&self.inbound.buf) {
                ParseOutcome::Complete(Framed { value, total_len }) => {
                    self.conn.on_request(value, ts);
                    self.inbound.advance(total_len);
                }
                ParseOutcome::Partial => return,
                ParseOutcome::Invalid => {
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
            match parse_response(&self.outbound.buf) {
                ParseOutcome::Complete(Framed { value, total_len }) => {
                    self.conn.on_response(value, ts);
                    self.outbound.advance(total_len);
                }
                ParseOutcome::Partial => return,
                ParseOutcome::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }
}

impl L7Parser for Http1Parser {
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
        self.conn.take_records()
    }

    fn is_dead(&self) -> bool {
        self.dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http_request_by_positive_signature() {
        assert!(looks_like_request(b"GET /x HTTP/1.1\r\n"));
        assert!(looks_like_request(b"POST /y HTTP/1.1\r\n"));
        assert!(!looks_like_request(b"\x16\x03\x01\x02")); // TLS ClientHello prefix
        assert!(!looks_like_request(b"random bytes"));
        assert!(!looks_like_request(b"GETX /x")); // method must be followed by a space
    }

    #[test]
    fn parses_request_line_and_frames_a_bodyless_get() {
        let buf = b"GET /api/users?q=1 HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Complete(Framed { value, total_len }) => {
                assert_eq!(value.method, "GET");
                assert_eq!(value.path, "/api/users?q=1");
                assert_eq!(value.host, "x");
                assert_eq!(total_len, buf.len()); // no body
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn frames_a_post_with_content_length_body() {
        let buf = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        match parse_request(buf) {
            ParseOutcome::Complete(Framed { value, total_len }) => {
                assert_eq!(value.method, "POST");
                assert_eq!(total_len, buf.len()); // head + 5-byte body
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn partial_request_waits_for_more() {
        assert_eq!(
            parse_request(b"GET /api/users HTTP/1.1\r\nHo"),
            ParseOutcome::Partial
        );
    }

    #[test]
    fn invalid_request_is_rejected() {
        assert_eq!(
            parse_request(b"\x00\x01\x02 not http\r\n\r\n"),
            ParseOutcome::Invalid
        );
    }

    #[test]
    fn parses_response_status() {
        let buf = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response(buf),
            ParseOutcome::Complete(Framed {
                value: 503,
                total_len: buf.len()
            })
        );
    }

    #[test]
    fn pairs_request_with_response_and_measures_latency() {
        let mut conn = Http1Conn::new();
        conn.on_request(
            RequestHead {
                method: "GET".into(),
                path: "/api/users".into(),
                host: "checkout.io".into(),
            },
            1_000,
        );
        conn.on_response(200, 1_500);
        let recs = conn.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "GET /api/users");
        assert_eq!(recs[0].status_code, 200);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 500);
        // The Host + target ride along as span attributes (service-map edge facts).
        assert!(
            recs[0]
                .attributes
                .contains(&("http.host".to_string(), "checkout.io".to_string()))
        );
        assert!(
            recs[0]
                .attributes
                .contains(&("http.target".to_string(), "/api/users".to_string()))
        );
    }

    #[test]
    fn pipelined_requests_pair_in_arrival_order() {
        let mut conn = Http1Conn::new();
        conn.on_request(
            RequestHead {
                method: "GET".into(),
                path: "/a".into(),
                host: String::new(),
            },
            10,
        );
        conn.on_request(
            RequestHead {
                method: "POST".into(),
                path: "/b".into(),
                host: String::new(),
            },
            20,
        );
        conn.on_response(200, 15); // pairs with /a
        conn.on_response(500, 40); // pairs with /b
        let recs = conn.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "GET /a");
        assert_eq!(recs[0].status_code, 200);
        assert_eq!(recs[1].operation, "POST /b");
        assert!(recs[1].error); // 5xx
        assert_eq!(recs[1].duration_nano, 20);
    }

    #[test]
    fn orphan_response_is_dropped() {
        let mut conn = Http1Conn::new();
        conn.on_response(200, 0); // no pending request
        assert!(conn.take_records().is_empty());
    }
}
