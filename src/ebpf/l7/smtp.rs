//! SMTP wire parser — implements [`super::L7Parser`].
//!
//! SMTP is a CRLF-line text protocol. The client issues a command line — a verb
//! plus arguments (`EHLO mail.example.com`, `MAIL FROM:<a@b>`, `RCPT TO:<c@d>`,
//! `DATA`, `QUIT`, `AUTH …`, `STARTTLS`, `RSET`, `NOOP`) — and the server answers
//! with a reply: a 3-digit status code and text. A reply may span several lines,
//! each line `<code>-<text>` until a final `<code> <text>` (space after the code)
//! closes it (`250-PIPELINING\r\n250 8BITMIME\r\n`). The exchange is lockstep —
//! request then reply, in command order even when pipelined — so a FIFO queue
//! pairs them.
//!
//! Two framing subtleties a naive line-pairer gets wrong:
//!   * **`DATA`** elicits an *intermediate* `354` reply ("start mail input"), then
//!     the client streams the message body terminated by a line containing only
//!     `.`, then the server sends the *final* reply (`250` accepted / `5xx`
//!     rejected). We pair `DATA` with that final reply and frame past the `354`
//!     and the whole body — the body is opaque and must not be parsed as commands.
//!   * **`STARTTLS`** upgrades the connection to TLS after its `220` reply. The
//!     post-handshake bytes are TLS records, not SMTP; a TLS uprobe decrypts and
//!     re-feeds the inner plaintext as its own stream, so here we simply stop
//!     framing this connection once the `220` to `STARTTLS` is seen — the cleartext
//!     SMTP stream has ended.
//!
//! The greeting (`220 <host> ESMTP\r\n`) is server-initiated with no client
//! command behind it; on the outbound side it frames as a reply with nothing
//! pending and is dropped, exactly like an orphan reply.
//!
//! Hand-rolled framing (no crate): the grammar is line-oriented ASCII and leanness
//! is the agent's moat. We decode only the span fields — the command verb (the
//! operation label), the reply code (the error verdict), and timing — never the
//! envelope addresses or message body.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Protocol tag stamped on every record this parser mints.
const PROTOCOL: Protocol = Protocol::Smtp;

/// Client command verbs we recognise as a positive detection signature and as
/// operation labels. Not every ESMTP verb (extensions add more), but the core set
/// a session is built from; an unrecognised opener returns `None` from detection
/// rather than mis-claiming another protocol's bytes. The verb is also the span
/// operation, so any verb that frames is labelled by its own uppercased text — the
/// list only gates *detection*, never which commands the parser will track.
const COMMAND_VERBS: [&str; 12] = [
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "QUIT", "AUTH", "STARTTLS", "RSET", "NOOP", "VRFY",
    "EXPN",
];

/// Outcome of framing one message (command line or reply) at the front of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame<T> {
    /// A complete message: its extracted value plus how many bytes it occupies.
    Complete { value: T, total_len: usize },
    /// Valid-so-far but the buffer doesn't hold the whole message yet — wait.
    Partial,
    /// Not well-formed SMTP — drop the connection.
    Invalid,
}

/// Index just past the next CRLF at or after `from`, i.e. the offset of the byte
/// after `\n`. `None` if no complete line is buffered yet. SMTP lines are strictly
/// CRLF-terminated; a bare LF is tolerated by many servers, but we frame on CRLF to
/// stay conservative and let an LF-only stream simply wait (it never desyncs).
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

/// The first whitespace-delimited token of a command line, uppercased. Empty when
/// the line is blank. SMTP verbs are case-insensitive on the wire (`ehlo`/`EHLO`).
fn command_verb(line: &[u8]) -> String {
    let token = line
        .split(|&b| b == b' ' || b == b'\t')
        .find(|t| !t.is_empty())
        .unwrap_or(&[]);
    String::from_utf8_lossy(token).to_ascii_uppercase()
}

/// True if `line`'s first token is one of the recognised command verbs — the
/// detection gate. Argument-bearing forms like `MAIL FROM:<a@b>` match on the
/// `MAIL` token; `STARTTLS\r\n` (no args) matches on the bare verb.
fn is_command_line(line: &[u8]) -> bool {
    let verb = command_verb(line);
    COMMAND_VERBS.iter().any(|v| *v == verb)
}

/// Frame one client command line at the front of `buf`, returning the verb (its
/// first token, uppercased — the operation label) and the byte length. A command is
/// a single CRLF-terminated line. The `DATA` body is NOT framed here — `DATA` only
/// elicits the `354` go-ahead; the body and its terminating `.` line are framed
/// separately once that `354` is seen (see [`SmtpParser::drain_inbound`]).
fn frame_command(buf: &[u8]) -> Frame<String> {
    let Some(stop) = line_end(buf, 0) else {
        return Frame::Partial;
    };
    let line = &buf[..stop - 2];
    let verb = command_verb(line);
    if verb.is_empty() {
        return Frame::Invalid;
    }
    Frame::Complete {
        value: verb,
        total_len: stop,
    }
}

/// A framed server reply: its 3-digit status code, whether it's intermediate
/// (`3xx`, e.g. `354` to `DATA` / a multi-step `AUTH`), and the byte length so the
/// stream advances past the whole (possibly multi-line) reply.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    /// `3xx` — the server is mid-command, expecting more client input (`DATA`
    /// body, next `AUTH` step). Such a reply does not conclude its command.
    intermediate: bool,
}

/// Frame one server reply at the front of `buf`. A reply is one or more lines:
/// each `<code>-<text>` line continues, the first `<code> <text>` line (space, not
/// hyphen, after the 3-digit code) ends it. All lines of a well-formed reply carry
/// the same code; we read the final line's code as the verdict. A line whose first
/// three bytes aren't ASCII digits, or whose 4th byte is neither space nor hyphen,
/// is not a reply — invalid.
fn frame_reply(buf: &[u8]) -> Frame<Reply> {
    let mut pos = 0usize;
    loop {
        let Some(stop) = line_end(buf, pos) else {
            return Frame::Partial;
        };
        let line = &buf[pos..stop - 2];
        // A reply line is `DDD` then a separator: `-` continues, ` ` (or nothing,
        // a bare `DDD\r\n`) ends. Fewer than 3 bytes can't carry a code.
        if line.len() < 3 || !line[..3].iter().all(|b| b.is_ascii_digit()) {
            return Frame::Invalid;
        }
        let code = parse_code(&line[..3]);
        match line.get(3) {
            // Continuation line — keep scanning for the terminating line.
            Some(b'-') => pos = stop,
            // Final line: `DDD text` or a bare `DDD`.
            Some(b' ') | None => {
                return Frame::Complete {
                    value: Reply {
                        code,
                        intermediate: (300..400).contains(&code),
                    },
                    total_len: stop,
                };
            }
            // Anything else after the code (e.g. `250x…`) is malformed.
            Some(_) => return Frame::Invalid,
        }
    }
}

/// Parse a validated 3-ASCII-digit code into its numeric value. The caller has
/// already checked the bytes are digits, so this can't fail.
fn parse_code(digits: &[u8]) -> u16 {
    u16::from(digits[0] - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0')
}

/// True if `buf` begins a recognised SMTP session: a client command verb delimited
/// by a space/tab/CR (the monitored process is the client), OR a server greeting
/// `220 ` / `220-` (the monitored process is the server). A positive signature,
/// never a guess — random text that isn't a known verb or a `220` greeting won't
/// match. Returns `false` while still ambiguous so the caller waits.
pub(crate) fn looks_like_request(buf: &[u8]) -> bool {
    looks_like_command(buf) || looks_like_greeting(buf)
}

/// True if `buf` opens with a known command verb followed by a real delimiter. The
/// delimiter check stops `MAILER` matching `MAIL` and `DATABASE` matching `DATA`.
fn looks_like_command(buf: &[u8]) -> bool {
    COMMAND_VERBS.iter().any(|verb| {
        let vb = verb.as_bytes();
        buf.len() >= vb.len()
            && buf[..vb.len()].eq_ignore_ascii_case(vb)
            && matches!(
                buf.get(vb.len()),
                // `STARTTLS\r\n` / `QUIT\r\n` end at CRLF with no args; the rest take
                // a space-delimited argument. A bare end-of-buffer is still ambiguous
                // (more bytes may follow), so it does NOT match — we wait.
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')
            )
    })
}

/// True if `buf` opens with a server greeting: `220` then a space or hyphen
/// (`220 host ESMTP` / `220-host`). The greeting is the one server-initiated
/// opener; recognising it lets us bind on a connection captured server-side where
/// the first bytes seen are the banner, not a client command.
fn looks_like_greeting(buf: &[u8]) -> bool {
    matches!(buf, [b'2', b'2', b'0', sep, ..] if *sep == b' ' || *sep == b'-')
}

/// Recognise SMTP from a connection's inbound prefix and return a fresh boxed
/// parser, or `None` if these bytes aren't an SMTP command / greeting. A positive
/// signature, never a guess.
pub(crate) fn detect_smtp(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if looks_like_request(inbound) {
        Some(Box::new(SmtpParser::new()))
    } else {
        None
    }
}

/// Construct an SMTP parser unconditionally — the port-hint path (25/587/465) binds
/// by port without byte sniffing, mirroring the other parsers' `Default`-built
/// construction in `conn::parser_for_protocol`.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(SmtpParser::new())
}

/// A request awaiting its reply, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    verb: String,
    start_unix_nano: i64,
}

/// SMTP [`L7Parser`]: reassembles each direction, frames command lines and (multi-
/// line) replies, pairs them FIFO, and emits one [`L7Record`] per command/reply
/// pair. `DATA` is paired with its final reply (the `354` and the message body are
/// framed past). Unrecoverable bytes mark it dead so the connection is dropped.
#[derive(Debug, Default)]
pub(crate) struct SmtpParser {
    inbound: DirBuf,
    outbound: DirBuf,
    /// Commands awaiting their reply, oldest first.
    pending: VecDeque<Pending>,
    /// Set once `DATA`'s `354` go-ahead is seen: the inbound stream is now the
    /// message body, framed until the lone `.` line, not parsed as commands.
    in_data_body: bool,
    /// Set once a `220` reply pairs with a pending `STARTTLS`: the cleartext SMTP
    /// stream has ended and every following byte (either direction) is a TLS record,
    /// not SMTP. We stop framing this connection entirely — a TLS uprobe decrypts and
    /// re-feeds the inner plaintext as its own stream. Without this, TLS handshake
    /// bytes (which routinely contain `\r\n` pairs) get mis-framed as commands and
    /// desync pairing or pollute records with garbage operations.
    tls_upgraded: bool,
    records: Vec<L7Record>,
    dead: bool,
}

impl SmtpParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frame as many complete commands as the inbound buffer holds, queueing each
    /// verb to await its reply. While inside a `DATA` body, frame past the body to
    /// its terminating `.` line instead of parsing commands. Stops on a partial
    /// (waits) or invalid (dies).
    fn drain_inbound(&mut self, ts: i64) {
        loop {
            if !self.inbound.drain_skip() || self.inbound.buf.is_empty() {
                return;
            }
            if self.in_data_body {
                // Body runs until a line containing exactly `.`; that terminator is
                // itself a command-position line that elicits the final DATA reply.
                match self.frame_data_terminator() {
                    Some(total_len) => {
                        self.in_data_body = false;
                        self.inbound.advance(total_len);
                    }
                    None => return, // terminator not buffered yet — wait
                }
                continue;
            }
            match frame_command(&self.inbound.buf) {
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

    /// Scan the buffered message body for its terminating line — a line containing
    /// only `.` (`\r\n.\r\n`, or `.\r\n` if the body opened at a line boundary).
    /// Returns the byte length up to and including that terminator's CRLF, or
    /// `None` if it isn't fully buffered yet. The body content is never decoded.
    fn frame_data_terminator(&self) -> Option<usize> {
        let buf = &self.inbound.buf;
        let mut pos = 0usize;
        loop {
            let stop = line_end(buf, pos)?;
            if &buf[pos..stop - 2] == b"." {
                return Some(stop);
            }
            pos = stop;
        }
    }

    /// Frame as many complete replies as the outbound buffer holds, pairing each
    /// with the oldest unanswered command. An intermediate `3xx` reply does not
    /// conclude its command: for `DATA` it opens the body-framing state and leaves
    /// the command pending for its *final* reply; for other commands (multi-step
    /// `AUTH`) it is consumed without popping. A reply with nothing pending (the
    /// server greeting, or a mid-stream attach) is dropped.
    fn drain_outbound(&mut self, ts: i64) {
        loop {
            if !self.outbound.drain_skip() || self.outbound.buf.is_empty() {
                return;
            }
            match frame_reply(&self.outbound.buf) {
                Frame::Complete { value, total_len } => {
                    self.handle_reply(value, ts);
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

    /// Apply one framed reply to the pending queue. Final replies pop and emit;
    /// intermediate `3xx` replies stay attached to their command (DATA opens the
    /// body; other intermediates are passed over).
    fn handle_reply(&mut self, reply: Reply, ts: i64) {
        let Some(front) = self.pending.front() else {
            // Greeting or orphan reply — no command to pair with. Dropped.
            return;
        };

        if reply.intermediate {
            // `354` to DATA: don't pop; switch the inbound stream to body framing so
            // the message content isn't parsed as commands. The command stays pending
            // for its final (post-body) reply. For a non-DATA intermediate (e.g. a
            // multi-step AUTH `334`), just leave the command pending; the next reply
            // concludes it.
            if front.verb == "DATA" {
                self.in_data_body = true;
                // The body may already be buffered ahead of the 354 (pipelined or
                // batched capture) — drain it now so framing doesn't stall.
                self.drain_inbound(ts);
            }
            return;
        }

        let req = self
            .pending
            .pop_front()
            .expect("front() was Some above, so pop_front() yields it");
        let error = reply.code >= 400;
        // STARTTLS accepted (RFC 3207: `220` = ready to start TLS). The cleartext
        // stream ends here; flip to TLS-upgraded so no further bytes are framed. A
        // rejection (`454`/`501`) leaves the connection in cleartext, so only `220`
        // upgrades.
        let upgrades_tls = req.verb == "STARTTLS" && reply.code == 220;
        self.records.push(L7Record {
            protocol: PROTOCOL,
            attributes: Vec::new(),
            operation: req.verb,
            status_code: reply.code,
            error,
            start_unix_nano: req.start_unix_nano,
            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
        });
        if upgrades_tls {
            self.tls_upgraded = true;
        }
    }
}

impl L7Parser for SmtpParser {
    fn on_inbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead || self.tls_upgraded {
            // Post-STARTTLS bytes are TLS records, not SMTP — drop them silently
            // (the cleartext stream has ended; a TLS uprobe re-feeds the plaintext).
            return;
        }
        self.inbound.buf.extend_from_slice(bytes);
        self.drain_inbound(ts);
    }

    fn on_outbound(&mut self, bytes: &[u8], ts: i64) {
        if self.dead || self.tls_upgraded {
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

    // -- detection -----------------------------------------------------------

    #[test]
    fn detects_command_verbs_and_greeting_by_positive_signature() {
        assert!(looks_like_request(b"EHLO mail.example.com\r\n"));
        assert!(looks_like_request(b"helo host\r\n")); // case-insensitive
        assert!(looks_like_request(b"MAIL FROM:<a@b.com>\r\n"));
        assert!(looks_like_request(b"RCPT TO:<c@d.com>\r\n"));
        assert!(looks_like_request(b"DATA\r\n"));
        assert!(looks_like_request(b"QUIT\r\n"));
        assert!(looks_like_request(b"STARTTLS\r\n"));
        assert!(looks_like_request(b"AUTH LOGIN\r\n"));
        // Server greeting (monitored process is the server).
        assert!(looks_like_request(b"220 mx.example.com ESMTP\r\n"));
        assert!(looks_like_request(b"220-mx.example.com\r\n"));
        // Not SMTP: undelimited verb, unknown verb, an HTTP request, random binary,
        // a non-220 reply opener (could be any digits — too weak to claim).
        assert!(!looks_like_request(b"MAILER daemon\r\n")); // delimiter check
        assert!(!looks_like_request(b"DATABASE\r\n")); // DATA + more letters
        assert!(!looks_like_request(b"FOO bar\r\n"));
        assert!(!looks_like_request(b"GET /x HTTP/1.1\r\n"));
        assert!(!looks_like_request(b"\x16\x03\x01\x02"));
        assert!(!looks_like_request(b"250 OK\r\n")); // a reply, not a greeting
    }

    #[test]
    fn detect_smtp_returns_a_parser_only_on_a_match() {
        assert!(detect_smtp(b"EHLO host\r\n").is_some());
        assert!(detect_smtp(b"220 mx ESMTP\r\n").is_some());
        assert!(detect_smtp(b"not smtp at all").is_none());
        assert!(detect_smtp(b"\x00\x01\x02\x03").is_none());
    }

    #[test]
    fn new_parser_builds_unconditionally_for_the_port_hint() {
        // The port-hint path constructs without sniffing; it must yield a working
        // parser that pairs a command with its reply.
        let mut p = new_parser();
        p.on_inbound(b"EHLO host\r\n", 1);
        p.on_outbound(b"250 OK\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "EHLO");
        assert_eq!(recs[0].protocol, Protocol::Smtp);
    }

    // -- framing -------------------------------------------------------------

    #[test]
    fn one_command_response_yields_one_record() {
        let mut p = SmtpParser::new();
        p.on_inbound(b"MAIL FROM:<a@b.com>\r\n", 1_000);
        p.on_outbound(b"250 2.1.0 Ok\r\n", 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "MAIL");
        assert_eq!(recs[0].status_code, 250);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn multiline_ehlo_reply_is_one_response() {
        // EHLO answers with a multi-line `250-…` block closed by `250 …`. Treating
        // each line as a separate reply would pop later commands and desync pairing.
        let mut p = SmtpParser::new();
        p.on_inbound(b"EHLO mail.example.com\r\n", 1);
        p.on_inbound(b"MAIL FROM:<a@b>\r\n", 2);
        p.on_outbound(
            b"250-mx.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250 8BITMIME\r\n",
            3,
        );
        p.on_outbound(b"250 2.1.0 Ok\r\n", 4);
        let recs = p.take_records();
        assert_eq!(
            recs.len(),
            2,
            "EHLO block + MAIL must be exactly two records"
        );
        assert_eq!(recs[0].operation, "EHLO");
        assert_eq!(recs[0].status_code, 250);
        assert_eq!(recs[0].duration_nano, 2); // EHLO: req ts=1, reply ts=3
        assert_eq!(recs[1].operation, "MAIL");
        assert_eq!(recs[1].duration_nano, 2); // MAIL: req ts=2, reply ts=4
        assert!(p.pending.is_empty());
    }

    #[test]
    fn greeting_with_nothing_pending_is_dropped() {
        // The server banner is server-initiated; on the outbound side it frames as a
        // reply with no command behind it and must be dropped, not panic or queue.
        let mut p = SmtpParser::new();
        p.on_outbound(b"220 mx.example.com ESMTP Postfix\r\n", 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        // A following real exchange still pairs correctly after the dropped greeting.
        p.on_inbound(b"EHLO host\r\n", 2);
        p.on_outbound(b"250 OK\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "EHLO");
    }

    #[test]
    fn data_pairs_with_final_reply_and_skips_the_body() {
        // DATA → 354 (intermediate, body opens) → body → final 250. The command pairs
        // with the FINAL reply (ts of the 250), and the body — which contains lines
        // that look like commands ("MAIL FROM spoof") and a dot-stuffed line — must
        // be framed past, not parsed.
        let mut p = SmtpParser::new();
        p.on_inbound(b"DATA\r\n", 10);
        p.on_outbound(b"354 End data with <CR><LF>.<CR><LF>\r\n", 11);
        // The body: a header, a line that mimics a command, a dot-stuffed line, then
        // the lone-dot terminator.
        p.on_inbound(
            b"Subject: hi\r\nMAIL FROM:<evil> not a command\r\n..stuffed line\r\n.\r\n",
            12,
        );
        p.on_outbound(b"250 2.0.0 Ok: queued as ABC123\r\n", 20);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "DATA must yield exactly one record");
        assert_eq!(recs[0].operation, "DATA");
        assert_eq!(recs[0].status_code, 250);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 10); // DATA's own request time
        assert_eq!(recs[0].duration_nano, 10); // req ts=10, final reply ts=20
        assert!(p.pending.is_empty());
        assert!(!p.in_data_body);
    }

    #[test]
    fn data_followed_by_pipelined_command_parses_after_the_body() {
        // After the DATA body terminates, a following RSET command must parse as a
        // command again (body framing turned off), pairing with its own reply.
        let mut p = SmtpParser::new();
        p.on_inbound(b"DATA\r\n", 1);
        p.on_outbound(b"354 go\r\n", 2);
        p.on_inbound(b"body line\r\n.\r\nRSET\r\n", 3);
        p.on_outbound(b"250 queued\r\n", 4); // DATA final
        p.on_outbound(b"250 reset\r\n", 5); // RSET
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "DATA");
        assert_eq!(recs[1].operation, "RSET");
        assert!(p.pending.is_empty());
    }

    #[test]
    fn data_body_drains_when_the_354_arrives_while_body_is_buffered() {
        // The 354 reply is what switches the inbound stream into body-framing mode.
        // If the body bytes are already buffered when the 354 is processed (a single
        // capture batch delivering reply-then-inbound), the 354 handler must drain
        // the buffered body immediately (via its inner `drain_inbound`), not leave it
        // stalled until the next inbound segment.
        let mut p = SmtpParser::new();
        p.on_inbound(b"DATA\r\n", 1);
        // The 354 turns on body framing; the body + terminator + final reply all land
        // in the outbound/inbound segments processed right after. The lone-dot body is
        // framed past inside the 354's drain, so the final 250 pairs with DATA.
        p.on_outbound(b"354 go\r\n", 2);
        p.on_inbound(b"line one\r\nline two\r\n.\r\n", 3);
        p.on_outbound(b"250 ok\r\n", 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "DATA");
        assert!(!p.in_data_body);
    }

    #[test]
    fn error_replies_set_the_failure_verdict() {
        // 4xx transient and 5xx permanent both flag error; the exact code is kept.
        let mut p = SmtpParser::new();
        p.on_inbound(b"RCPT TO:<nope@x>\r\n", 1);
        p.on_inbound(b"MAIL FROM:<a@b>\r\n", 2);
        p.on_outbound(b"550 5.1.1 No such user\r\n", 3); // permanent
        p.on_outbound(b"450 4.2.0 Mailbox busy\r\n", 4); // transient
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "RCPT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 550);
        assert_eq!(recs[1].operation, "MAIL");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 450);
    }

    #[test]
    fn error_threshold_is_exactly_400() {
        // Boundary: the error verdict is code >= 400. A final 2xx is not an error; a
        // 4xx is. (A 3xx is *intermediate* — it never concludes a command, so it
        // can't be a final verdict; see `auth_multistep_intermediate_334_…`.) Use
        // 299 / 400 — both final (non-3xx) — to pin the threshold exactly.
        let mut p = SmtpParser::new();
        p.on_inbound(b"NOOP\r\n", 1);
        p.on_outbound(b"299 borderline\r\n", 2); // final, below the error line
        let r = p.take_records();
        assert_eq!(r.len(), 1);
        assert!(!r[0].error);
        assert_eq!(r[0].status_code, 299);

        let mut q = SmtpParser::new();
        q.on_inbound(b"NOOP\r\n", 1);
        q.on_outbound(b"400 borderline\r\n", 2); // first error code
        let r = q.take_records();
        assert_eq!(r.len(), 1);
        assert!(r[0].error);
        assert_eq!(r[0].status_code, 400);
    }

    #[test]
    fn fragmented_command_waits_instead_of_misparsing() {
        let mut p = SmtpParser::new();
        // Command line split mid-way — no CRLF yet.
        p.on_inbound(b"MAIL FROM:<a@", 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // partial, not garbage
        assert!(p.pending.is_empty(), "must not queue a half-framed command");
        // Remainder arrives, then the reply.
        p.on_inbound(b"b.com>\r\n", 1);
        p.on_outbound(b"250 Ok\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "MAIL");
    }

    #[test]
    fn fragmented_multiline_reply_waits_for_the_terminator() {
        // A multi-line reply split before its terminating ` `-line must WAIT, not
        // pair half a reply.
        let mut p = SmtpParser::new();
        p.on_inbound(b"EHLO host\r\n", 1);
        p.on_outbound(b"250-mx Hello\r\n250-PIPELINING\r\n", 2); // no final line yet
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        assert_eq!(p.pending.len(), 1, "command still awaits its reply");
        p.on_outbound(b"250 8BITMIME\r\n", 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "EHLO");
        assert_eq!(recs[0].duration_nano, 2);
    }

    #[test]
    fn fragmented_data_body_waits_for_the_dot_terminator() {
        let mut p = SmtpParser::new();
        p.on_inbound(b"DATA\r\n", 1);
        p.on_outbound(b"354 go\r\n", 2);
        // Body without its terminating dot line — must wait.
        p.on_inbound(b"line one\r\nline two\r\n", 3);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
        assert!(p.in_data_body, "still inside the body");
        p.on_inbound(b".\r\n", 4);
        p.on_outbound(b"250 queued\r\n", 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "DATA");
        assert!(!p.in_data_body);
    }

    #[test]
    fn pipelined_commands_pair_in_arrival_order() {
        // ESMTP PIPELINING batches MAIL+RCPT+DATA; replies come back in order. A FIFO
        // queue must keep each reply on its own command.
        let mut p = SmtpParser::new();
        p.on_inbound(
            b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nRCPT TO:<e@f>\r\n",
            100,
        );
        p.on_outbound(b"250 Ok\r\n250 Accepted\r\n550 No such user\r\n", 130);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "MAIL");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "RCPT");
        assert!(!recs[1].error);
        assert_eq!(recs[2].operation, "RCPT");
        assert!(recs[2].error); // the second RCPT was rejected
        assert_eq!(recs[2].status_code, 550);
    }

    #[test]
    fn quit_command_pairs_with_its_221_bye() {
        let mut p = SmtpParser::new();
        p.on_inbound(b"QUIT\r\n", 1);
        p.on_outbound(b"221 2.0.0 Bye\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "QUIT");
        assert_eq!(recs[0].status_code, 221);
        assert!(!recs[0].error);
    }

    #[test]
    fn auth_multistep_intermediate_334_does_not_pop_early() {
        // AUTH LOGIN: server sends 334 (intermediate, base64 prompt), client sends the
        // credential line, server sends the final 235/535. The 334 must NOT pop AUTH;
        // only the final reply concludes it. The intermediate credential line is a
        // bare token (not a known verb) and frames as its own "command" — we accept a
        // stray record for it rather than mis-pairing AUTH, which is the priority.
        let mut p = SmtpParser::new();
        p.on_inbound(b"AUTH LOGIN\r\n", 1);
        p.on_outbound(b"334 VXNlcm5hbWU6\r\n", 2); // intermediate
        p.on_outbound(b"235 2.7.0 Authentication successful\r\n", 4); // final
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "AUTH pairs once, with its final 235");
        assert_eq!(recs[0].operation, "AUTH");
        assert_eq!(recs[0].status_code, 235);
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 3); // AUTH req ts=1, final reply ts=4
        assert!(p.pending.is_empty());
    }

    #[test]
    fn orphan_reply_with_no_pending_command_is_dropped() {
        let mut p = SmtpParser::new();
        p.on_outbound(b"250 OK\r\n", 0); // attached mid-connection, missed the command
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn malformed_reply_marks_the_parser_dead() {
        // A reply whose first three bytes aren't digits is not SMTP — die rather than
        // silently desync.
        let mut p = SmtpParser::new();
        p.on_inbound(b"NOOP\r\n", 1);
        p.on_outbound(b"OK fine\r\n", 2); // not a 3-digit code
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn blank_command_line_marks_dead() {
        // An empty command line (just CRLF) is not a command — invalid.
        let mut p = SmtpParser::new();
        p.on_inbound(b"\r\n", 1);
        assert!(p.is_dead());
    }

    #[test]
    fn negative_clock_skew_is_floored_to_zero() {
        // Reply observed BEFORE the command (clock skew) must yield duration 0.
        let mut p = SmtpParser::new();
        p.on_inbound(b"NOOP\r\n", 1_000);
        p.on_outbound(b"250 Ok\r\n", 900); // earlier than the request
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duration_nano, 0);
    }

    #[test]
    fn starttls_stops_framing_so_tls_bytes_are_not_parsed_as_smtp() {
        // RFC 3207: after a `220` reply to STARTTLS the connection upgrades to TLS;
        // every following byte is a TLS record, NOT SMTP. The cleartext stream has
        // ended (a TLS uprobe re-feeds the inner plaintext as its own stream). Before
        // the fix, the parser kept framing: TLS handshake bytes — which routinely
        // contain `\r\n` byte pairs — were sliced into bogus "command" lines, queued
        // as pending, and desynced pairing or polluted records with garbage ops.
        let mut p = SmtpParser::new();
        p.on_inbound(b"STARTTLS\r\n", 1);
        p.on_outbound(b"220 Go ahead\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "STARTTLS itself pairs with its 220");
        assert_eq!(recs[0].operation, "STARTTLS");
        assert_eq!(recs[0].status_code, 220);
        assert!(!recs[0].error);
        assert!(
            p.tls_upgraded,
            "the 220 to STARTTLS upgrades the connection"
        );

        // Now feed a TLS ClientHello whose body contains a CRLF and a non-empty token
        // — exactly the shape that used to frame as a bogus command and desync.
        p.on_inbound(b"\x16\x03\x01\x00\x0ejunk\r\nmore tls\r\n", 3);
        // And a TLS server record on the outbound side that contains a digit-led
        // CRLF line — the shape that used to frame as a bogus reply.
        p.on_outbound(b"\x16\x03\x03\x00\x10250 fake reply\r\n", 4);

        assert!(!p.is_dead(), "TLS bytes must not kill the parser");
        assert!(
            p.pending.is_empty(),
            "no TLS bytes may be queued as a pending command"
        );
        assert!(
            p.take_records().is_empty(),
            "no records may be minted from post-upgrade TLS bytes"
        );
    }

    #[test]
    fn rejected_starttls_keeps_framing_cleartext() {
        // A STARTTLS rejection (RFC 3207: `454` TLS not available / `501`) leaves the
        // connection in cleartext — framing MUST continue. Only a `220` upgrades.
        let mut p = SmtpParser::new();
        p.on_inbound(b"STARTTLS\r\n", 1);
        p.on_outbound(b"454 4.7.0 TLS not available\r\n", 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "STARTTLS");
        assert!(recs[0].error, "454 is a failure verdict");
        assert!(!p.tls_upgraded, "a rejected STARTTLS does not upgrade");

        // The cleartext SMTP session continues and still pairs normally.
        p.on_inbound(b"QUIT\r\n", 3);
        p.on_outbound(b"221 Bye\r\n", 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "QUIT");
        assert_eq!(recs[0].status_code, 221);
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: feed hostile/truncated payloads at every byte boundary, both
        // directions, in both orders. The hard requirement is no panic, ever — a
        // wrong verdict is acceptable, a crash is not.
        let payloads: &[&[u8]] = &[
            b"DATA\r\n",                              // command with no args
            b"MAIL\r\n",                              // verb, no FROM
            b"\r\n",                                  // bare CRLF (blank command)
            b"\r\n\r\n\r\n",                          // only CRLFs
            b"250",                                   // code, no separator, no CRLF
            b"25\r\n",                                // two-digit "code"
            b"2x0 OK\r\n",                            // non-digit in code
            b"250",                                   // truncated reply
            b"250-only continuation\r\n",             // continuation with no terminator
            b"354 go\r\n",                            // lone intermediate reply
            b".\r\n",                                 // lone dot outside a body
            b"DATA\r\n.\r\n",                         // DATA then immediate dot (no 354)
            b"EHLO\r\n",                              // EHLO no host
            b"\x00\x01\x02\x03",                      // raw binary
            b"\xff\xfe\xfd",                          // high bytes
            &[b'2'; 1024],                            // many digits, no CRLF
            &[b'.'; 512],                             // many dots, no CRLF
            b"AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=\r\n",   // auth with base64 arg
            b"MAIL FROM:<a@b> SIZE=1000000\r\n",      // command with extension params
            b"220-multi\r\n220-line\r\n220 done\r\n", // multiline greeting
            b"500 5.5.1 Command unrecognized\r\n",    // error reply
            b"DATA\r\n354 x\r\nbody\r\n",             // DATA, 354, body without terminator
        ];
        for payload in payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // request side
                let mut p = SmtpParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                // response side (prime a command so pairing paths run)
                let mut q = SmtpParser::new();
                q.on_inbound(b"MAIL FROM:<a@b>\r\n", 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
                // data-body path: open a DATA body, then feed hostile bytes as body.
                let mut d = SmtpParser::new();
                d.on_inbound(b"DATA\r\n", 0);
                d.on_outbound(b"354 go\r\n", 0);
                d.on_inbound(a, 1);
                d.on_inbound(b, 2);
                let _ = d.take_records();
                // post-STARTTLS path: upgrade to TLS, then feed hostile bytes as TLS
                // records on both directions (they must be dropped, never framed).
                let mut t = SmtpParser::new();
                t.on_inbound(b"STARTTLS\r\n", 0);
                t.on_outbound(b"220 go\r\n", 0);
                t.on_inbound(a, 1);
                t.on_outbound(b, 2);
                let _ = t.take_records();
            }
        }
    }
}
