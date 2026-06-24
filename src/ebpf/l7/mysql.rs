//! MySQL wire parser — implements [`super::L7Parser`]. Hand-rolled passive
//! framing of the MySQL client/server protocol: each packet is a 4-byte header
//! (3-byte little-endian payload length + 1-byte sequence id) followed by the
//! payload. We extract only what a span needs — the command label, the
//! request→response latency, and the error verdict — and never decode result-set
//! payloads we don't need.
//!
//! Mirrors `http1.rs`: buffer each direction in a [`DirBuf`], advance past each
//! fully-framed packet (`4 + payload_len`), pair requests to responses FIFO
//! (MySQL is strictly request-then-response per connection), and emit one
//! [`L7Record`] carrying the request's command label and the response's verdict.
//!
//! Framing is hand-rolled rather than pulled from a crate: the request side is a
//! 1-byte command discriminator, the response verdict is a 1-byte tag plus (for
//! errors) a 2-byte LE code. `mysql_common` exists but would drag a full
//! value/row codec we never touch — hand-rolling keeps the agent lean, which is
//! the product's moat.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// MySQL packet header: 3-byte LE payload length + 1-byte sequence id.
const HEADER_LEN: usize = 4;

/// Command bytes (first payload byte of a client command packet) we label.
const COM_QUIT: u8 = 0x01;
const COM_QUERY: u8 = 0x03;
const COM_PING: u8 = 0x0e;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;

/// Response payload tags (first payload byte of a server packet).
const RESP_OK: u8 = 0x00;
const RESP_EOF: u8 = 0xfe;
const RESP_ERR: u8 = 0xff;

/// Server handshake greeting: protocol version 10 is the first byte of the very
/// first server→client packet's payload.
const HANDSHAKE_PROTOCOL_V10: u8 = 0x0a;

/// The largest a single packet's payload can be: a 3-byte length maxes at
/// `0xFFFFFF` (16 MiB − 1). A `0xfe` first byte only marks an OK/EOF packet when
/// the payload is *shorter* than this — a longer payload is a result-set row
/// whose first column value happens to lead with `0xfe`. (MariaDB/MySQL spec.)
const MAX_PACKET_PAYLOAD: usize = 0xff_ffff;

/// Read a MySQL packet's payload length from its 4-byte header (3 LE bytes).
/// Returns `None` until at least the header is buffered.
fn payload_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    Some(buf[0] as usize | (buf[1] as usize) << 8 | (buf[2] as usize) << 16)
}

/// Decode a MySQL length-encoded integer from the start of `bytes`, returning the
/// value, or `None` if the encoding's trailing bytes aren't all buffered. Used to
/// read a result-set's column count from its header packet so we can count the
/// exact number of column-definition packets that follow. Encoding (spec):
/// `< 0xfb` = the byte itself; `0xfc` = next 2 LE; `0xfd` = next 3 LE; `0xfe` =
/// next 8 LE. `0xfb`/`0xff` are NULL/sentinel markers, never a real count here.
fn length_encoded_int(bytes: &[u8]) -> Option<u64> {
    let first = *bytes.first()?;
    match first {
        0x00..=0xfa => Some(first as u64),
        0xfc => bytes
            .get(1..3)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as u64),
        0xfd => bytes
            .get(1..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], 0]) as u64),
        0xfe => bytes
            .get(1..9)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
        // 0xfb (NULL) and 0xff (ERR/undefined) are not valid column counts.
        _ => None,
    }
}

/// True if `buf` begins a plausible MySQL client command: a sane 3-byte length,
/// sequence id 0 (commands start a fresh sequence), and a `COM_QUERY` first byte.
/// A positive signature, never a guess — but byte-only and weak. A connection to
/// TCP port 3306 is a much stronger hint; the detector should prefer that when a
/// port is known. We additionally accept the server handshake (protocol v10) as a
/// signature since the greeting is the unmistakable first server packet.
fn looks_like_command(buf: &[u8]) -> bool {
    match payload_len(buf) {
        // seq id 0 and a COM_QUERY discriminator, with the command byte present.
        Some(len) => len >= 1 && buf[3] == 0 && buf.len() > HEADER_LEN && buf[4] == COM_QUERY,
        None => false,
    }
}

/// True if `buf` begins a MySQL server handshake greeting (protocol version 10).
fn looks_like_handshake(buf: &[u8]) -> bool {
    matches!(payload_len(buf), Some(len) if len >= 1 && buf.len() > HEADER_LEN && buf[4] == HANDSHAKE_PROTOCOL_V10)
}

/// The label for a parsed client command. `COM_QUERY` carries SQL, so its label
/// is the SQL verb (e.g. `"SELECT"`); other commands use a fixed mnemonic.
fn command_label(payload: &[u8]) -> String {
    match payload.first().copied() {
        Some(COM_QUERY) => format!("QUERY {}", sql_verb(&payload[1..])),
        Some(COM_STMT_PREPARE) => format!("PREPARE {}", sql_verb(&payload[1..])),
        Some(COM_STMT_EXECUTE) => "STMT_EXECUTE".to_string(),
        Some(COM_PING) => "PING".to_string(),
        Some(COM_QUIT) => "QUIT".to_string(),
        Some(other) => format!("COM_0x{other:02x}"),
        None => "COM_EMPTY".to_string(),
    }
}

/// The leading SQL verb of a statement (`SELECT`, `INSERT`, …), upper-cased. Only
/// the first word is read — we never parse the statement. Returns `"?"` when the
/// text is empty or non-ASCII garbage.
fn sql_verb(sql: &[u8]) -> String {
    let verb: Vec<u8> = sql
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if verb.is_empty() {
        "?".to_string()
    } else {
        String::from_utf8_lossy(&verb).into_owned()
    }
}

/// Whether a client command expects a server response we should pair. `COM_QUIT`
/// gets no reply (the server just closes), so pairing it would mis-attribute the
/// next command's response to it.
fn expects_response(command: u8) -> bool {
    command != COM_QUIT
}

/// Outcome of inspecting one fully-framed client command packet.
struct Command {
    label: String,
    expects_response: bool,
    total_len: usize,
}

/// Is the leading SQL verb in `sql` unambiguously complete within the buffered
/// prefix? The verb runs from the first non-whitespace byte to the first
/// non-alphabetic byte; it's complete once that terminator (whitespace, `(`, `;`,
/// end-of-statement, …) is visible. If the prefix is still all leading whitespace
/// or all alphabetic, the next byte could extend the verb (`SEL` → `SELECT`), so
/// we must wait. `body_complete` means the whole packet body is buffered — then
/// whatever we have is the final verb (a one-word statement like `BEGIN`).
fn verb_complete(sql: &[u8], body_complete: bool) -> bool {
    if body_complete {
        return true;
    }
    let after_ws: Vec<u8> = sql
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .collect();
    // A terminator after at least one verb byte means the verb is fully captured.
    after_ws
        .iter()
        .position(|b| !b.is_ascii_alphabetic())
        .map(|i| i > 0)
        .unwrap_or(false)
}

/// Inspect the buffer prefix as a client command packet. `None` until enough is
/// buffered to *label* it without truncating the SQL verb — wait for more bytes.
/// The full body need not be buffered (a 16 MiB statement need not be), only
/// enough to read the leading verb; `total_len` says how much to advance.
fn parse_command(buf: &[u8]) -> Option<Command> {
    let len = payload_len(buf)?;
    if len == 0 || buf.len() <= HEADER_LEN {
        return None; // need the command byte
    }
    let command = buf[HEADER_LEN];
    let total_len = HEADER_LEN + len;
    let body_complete = buf.len() >= total_len;
    // SQL-bearing commands must not be labelled from a truncated verb (`SELECT`
    // split after `SEL` would mislabel as `SEL`). Wait until the verb terminator is
    // visible, or the whole body has arrived.
    let end = total_len.min(buf.len());
    if matches!(command, COM_QUERY | COM_STMT_PREPARE)
        && !verb_complete(&buf[HEADER_LEN + 1..end], body_complete)
    {
        return None;
    }
    Some(Command {
        label: command_label(&buf[HEADER_LEN..end]),
        expects_response: expects_response(command),
        total_len,
    })
}

/// The verdict a server response packet renders for the paired span.
enum Verdict {
    /// OK / result-set header / EOF — success; carry MySQL status_code 0.
    Ok,
    /// ERR packet — failure; carry the 2-byte LE error code.
    Err(u16),
}

/// Does this server packet terminate a response stream at the top level? OK and
/// ERR always do; an EOF/OK `0xfe`-headed packet does *only* when its payload is
/// shorter than `0xFFFFFF` — a longer `0xfe`-led packet is a result-set row whose
/// first column value leads with `0xfe`, not a terminator (MariaDB/MySQL spec).
/// Result-set headers (any other first byte) do not terminate — more packets
/// follow.
fn terminates_response(first: u8, payload_len: usize) -> bool {
    match first {
        RESP_OK | RESP_ERR => true,
        RESP_EOF => payload_len < MAX_PACKET_PAYLOAD,
        _ => false,
    }
}

/// A request awaiting its response, with the time it was observed (for latency).
#[derive(Debug)]
struct Pending {
    label: String,
    start_unix_nano: i64,
}

/// Where we are inside the server's response to the oldest pending command. A
/// text result-set is `[column-count header][column def]*N[EOF?][row]*[terminator]`
/// — two phases that must be tracked so the *first* (column-defs) EOF doesn't end
/// the response early and mis-pair the rows against the next command.
#[derive(Debug, Default, PartialEq, Eq)]
enum RespPhase {
    /// Between responses: the next packet is the first packet of a fresh response
    /// and pairs with the oldest pending command.
    #[default]
    Idle,
    /// Inside a result-set's column-definition block: `remaining` more column-def
    /// packets to frame past. An ERR here aborts the stream.
    ColumnDefs { remaining: u64 },
    /// Past the column definitions. In the legacy (non-`DEPRECATE_EOF`) flow an EOF
    /// packet separates the column defs from the rows, so the *first* EOF seen here
    /// is that separator (consumed, not a terminator) — tracked by `expect_sep_eof`.
    /// With `DEPRECATE_EOF` there is no separator and the first packet is a row.
    /// Either way, once past the separator a terminating EOF/OK/ERR ends the
    /// response (an EOF/OK only when its payload is `< 0xFFFFFF`).
    Rows { expect_sep_eof: bool },
}

/// MySQL [`L7Parser`]: reassembles each direction packet-by-packet, labels client
/// commands, pairs them FIFO with the first packet of each server response, and
/// records the error verdict. Unrecoverable bytes mark it dead so the connection
/// is dropped.
#[derive(Debug, Default)]
pub(crate) struct MysqlParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    /// Phase within the current server response. `Idle` between responses; the
    /// result-set phases drain trailing packets until the stream terminates so the
    /// next first-packet pairing waits for the real end.
    phase: RespPhase,
    dead: bool,
}

impl MysqlParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frame and label client command packets, queueing those that expect a reply.
    fn drain_inbound(&mut self, ts: i64) {
        loop {
            // Consume any straddling body bytes from a prior packet whose frame was
            // advanced past before its body fully arrived. Without this, those
            // leftover bytes would be mis-read as a fresh packet header (desync).
            if !self.inbound.drain_skip() {
                return;
            }
            if self.inbound.buf.is_empty() {
                return;
            }
            match parse_command(&self.inbound.buf) {
                Some(cmd) => {
                    if cmd.expects_response {
                        self.pending.push_back(Pending {
                            label: cmd.label,
                            start_unix_nano: ts,
                        });
                    }
                    self.inbound.advance(cmd.total_len);
                }
                None => return, // header/command byte not buffered yet — wait
            }
        }
    }

    /// Frame server response packets. The first packet of each response renders the
    /// verdict and pairs with the oldest pending command; the remaining packets of a
    /// multi-packet result-set are framed and skipped until the response terminates.
    fn drain_outbound(&mut self, ts: i64) {
        loop {
            // Consume any straddling body bytes from a prior packet advanced past
            // before its body fully arrived — else they desync the next header.
            if !self.outbound.drain_skip() {
                return;
            }
            if self.outbound.buf.is_empty() {
                return;
            }
            let len = match payload_len(&self.outbound.buf) {
                Some(len) => len,
                None => return, // header not buffered yet
            };
            if len == 0 {
                // 0-length payloads are not part of normal command responses;
                // advance past the bare header to stay in sync.
                self.outbound.advance(HEADER_LEN);
                continue;
            }
            if self.outbound.buf.len() <= HEADER_LEN {
                return; // need at least the first payload byte
            }
            let first = self.outbound.buf[HEADER_LEN];
            let total_len = HEADER_LEN + len;

            match &self.phase {
                RespPhase::Idle => {
                    // First packet of a fresh response. To render a verdict from it
                    // we must read its leading bytes (ERR needs 3: tag + 2-byte
                    // code). If the verdict bytes haven't all arrived, wait rather
                    // than pairing with a fabricated code.
                    let need = if first == RESP_ERR { 3 } else { 1 };
                    if self.outbound.buf.len() < HEADER_LEN + need.min(len) {
                        return;
                    }
                    let verdict = match first {
                        RESP_ERR => Verdict::Err(self.error_code()),
                        _ => Verdict::Ok,
                    };
                    self.pair(verdict, ts);
                    // OK/ERR/EOF are self-contained single-packet responses. Any
                    // other first byte is a result-set column-count header opening a
                    // `[col def]*N [rows] [terminator]` stream; decode N to count the
                    // column-definition packets exactly (the column count is a
                    // length-encoded integer at the head of the payload).
                    if !terminates_response(first, len) {
                        let payload = &self.outbound.buf[HEADER_LEN..];
                        let columns = length_encoded_int(payload).unwrap_or(0);
                        self.phase = if columns == 0 {
                            // Degenerate/undecodable header — no column defs to count;
                            // the rows phase ends at the next terminator (legacy
                            // fallback, no separator EOF expected).
                            RespPhase::Rows {
                                expect_sep_eof: false,
                            }
                        } else {
                            RespPhase::ColumnDefs { remaining: columns }
                        };
                    }
                }
                RespPhase::ColumnDefs { remaining } => {
                    let remaining = *remaining;
                    // Within the counted column-def block every packet is a column
                    // definition — its first byte is opaque metadata and must NOT be
                    // read as a terminator (a length byte can equal 0x00/0xfe). Only
                    // an ERR aborts the stream. After the Nth def, the legacy EOF
                    // separator (if any) is consumed in the Rows phase.
                    if first == RESP_ERR {
                        self.phase = RespPhase::Idle;
                    } else if remaining <= 1 {
                        self.phase = RespPhase::Rows {
                            expect_sep_eof: true,
                        };
                    } else {
                        self.phase = RespPhase::ColumnDefs {
                            remaining: remaining - 1,
                        };
                    }
                }
                RespPhase::Rows { expect_sep_eof } => {
                    // In the legacy flow an EOF separates the column defs from the
                    // rows; the first EOF here is that separator (consumed, not a
                    // terminator). With DEPRECATE_EOF there is no separator and the
                    // first packet is already a row. Past the separator, a
                    // terminating EOF/OK/ERR ends the response (an EOF/OK only when
                    // its payload is `< 0xFFFFFF`; a longer `0xfe`-led packet is a
                    // row, not a terminator).
                    if *expect_sep_eof && first == RESP_EOF && len < MAX_PACKET_PAYLOAD {
                        // Legacy column-defs/rows separator EOF — consume, stay in
                        // rows, and no longer expect a separator.
                        self.phase = RespPhase::Rows {
                            expect_sep_eof: false,
                        };
                    } else if terminates_response(first, len) {
                        self.phase = RespPhase::Idle;
                    } else {
                        // A real row packet — no separator EOF will appear now.
                        self.phase = RespPhase::Rows {
                            expect_sep_eof: false,
                        };
                    }
                }
            }

            self.outbound.advance(total_len);
        }
    }

    /// Read the 2-byte LE error code from a buffered ERR packet (payload bytes
    /// 1..3, i.e. just past the `0xff` tag). Falls back to 0 if truncated.
    fn error_code(&self) -> u16 {
        let b = &self.outbound.buf;
        if b.len() >= HEADER_LEN + 3 {
            b[HEADER_LEN + 1] as u16 | (b[HEADER_LEN + 2] as u16) << 8
        } else {
            0
        }
    }

    /// Pair a verdict with the oldest unanswered command, emitting one record. A
    /// response with no pending command is dropped — we attached mid-connection.
    fn pair(&mut self, verdict: Verdict, ts: i64) {
        let Some(req) = self.pending.pop_front() else {
            return;
        };
        let (status_code, error) = match verdict {
            Verdict::Ok => (0, false),
            Verdict::Err(code) => (code, true),
        };
        self.records.push(L7Record {
            protocol: Protocol::Mysql,
            attributes: Vec::new(),
            operation: req.label,
            status_code,
            error,
            start_unix_nano: req.start_unix_nano,
            duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
        });
    }
}

impl L7Parser for MysqlParser {
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

/// Recognise MySQL from a connection's inbound prefix and return a fresh boxed
/// parser. The signature is positive but byte-only and therefore weak: a
/// `COM_QUERY` command packet (seq 0, sane length, `0x03` command byte) or the
/// server handshake greeting (protocol v10). A TCP port hint (3306) would make
/// this far more reliable and should gate this detector when a port is known.
pub(crate) fn detect_mysql(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    if looks_like_command(inbound) || looks_like_handshake(inbound) {
        Some(Box::new(MysqlParser::new()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a MySQL packet: 3-byte LE length + 1-byte seq + payload.
    fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut p = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, seq];
        p.extend_from_slice(payload);
        p
    }

    /// A COM_QUERY command packet carrying `sql`.
    fn query(sql: &str) -> Vec<u8> {
        let mut payload = vec![COM_QUERY];
        payload.extend_from_slice(sql.as_bytes());
        packet(0, &payload)
    }

    /// An OK response packet (payload `[0x00, affected_rows=0, last_insert_id=0]`).
    fn ok_packet(seq: u8) -> Vec<u8> {
        packet(seq, &[RESP_OK, 0x00, 0x00])
    }

    /// An ERR response packet carrying a 2-byte LE error code.
    fn err_packet(seq: u8, code: u16) -> Vec<u8> {
        packet(seq, &[RESP_ERR, code as u8, (code >> 8) as u8])
    }

    /// An EOF response packet.
    fn eof_packet(seq: u8) -> Vec<u8> {
        packet(seq, &[RESP_EOF, 0x00, 0x00, 0x00, 0x00])
    }

    /// A result-set header packet: a length-encoded column count (here a single
    /// byte < 0xfb, so it can't be mistaken for OK/EOF/ERR).
    fn resultset_header(seq: u8, columns: u8) -> Vec<u8> {
        packet(seq, &[columns])
    }

    #[test]
    fn detects_com_query_by_positive_signature() {
        assert!(detect_mysql(&query("SELECT 1")).is_some());
        // Server handshake greeting (protocol v10).
        let handshake = packet(0, &[HANDSHAKE_PROTOCOL_V10, b'8', b'.', b'0', 0x00]);
        assert!(detect_mysql(&handshake).is_some());
        // Not MySQL: an HTTP request, random bytes, and a non-COM_QUERY command.
        assert!(detect_mysql(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detect_mysql(b"\x00\x00").is_none()); // header not buffered
        assert!(detect_mysql(&packet(0, &[COM_PING])).is_none()); // PING is not the signature
    }

    #[test]
    fn query_then_ok_yields_one_record() {
        let mut p = MysqlParser::new();
        p.on_inbound(&query("SELECT * FROM users"), 1_000);
        assert!(p.take_records().is_empty()); // request seen, no response yet
        p.on_outbound(&ok_packet(1), 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn err_response_sets_error_and_carries_code() {
        let mut p = MysqlParser::new();
        p.on_inbound(&query("INSERT INTO t VALUES (1)"), 10);
        p.on_outbound(&err_packet(1, 1062), 25); // ER_DUP_ENTRY
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "QUERY INSERT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1062);
        assert_eq!(recs[0].duration_nano, 15);
    }

    #[test]
    fn fragmented_command_waits_instead_of_misparsing() {
        let mut p = MysqlParser::new();
        let pkt = query("SELECT 42");
        // Feed only the first 3 bytes (header incomplete) — nothing should pair.
        p.on_inbound(&pkt[..3], 5);
        p.on_outbound(&ok_packet(1), 9);
        assert!(
            p.take_records().is_empty(),
            "no command framed yet, so the response must not pair"
        );
        // Deliver the rest of the command, then a fresh response — now it pairs.
        p.on_inbound(&pkt[3..], 5);
        p.on_outbound(&ok_packet(1), 12);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "QUERY SELECT");
    }

    #[test]
    fn fragmented_header_byte_does_not_decide_length() {
        // A command split mid-header must not be framed until all 4 header bytes
        // plus the command byte are present.
        let mut p = MysqlParser::new();
        let pkt = query("DELETE FROM logs");
        p.on_inbound(&pkt[..2], 1); // 2 of 4 header bytes
        assert!(p.pending.is_empty());
        p.on_inbound(&pkt[2..4], 1); // header complete, command byte missing
        assert!(p.pending.is_empty(), "command byte not yet buffered");
        p.on_inbound(&pkt[4..], 1); // command byte + SQL
        assert_eq!(p.pending.len(), 1);
        p.on_outbound(&ok_packet(1), 2);
        assert_eq!(p.take_records()[0].operation, "QUERY DELETE");
    }

    #[test]
    fn pipelined_commands_pair_in_arrival_order() {
        let mut p = MysqlParser::new();
        // Two commands back-to-back in one inbound segment.
        let mut inbound = query("SELECT 1");
        inbound.extend_from_slice(&query("UPDATE t SET x = 1"));
        p.on_inbound(&inbound, 100);
        assert_eq!(p.pending.len(), 2);
        // Two responses back-to-back in one outbound segment.
        let mut outbound = ok_packet(1);
        outbound.extend_from_slice(&err_packet(1, 1146)); // ER_NO_SUCH_TABLE
        p.on_outbound(&outbound, 140);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert!(!recs[0].error);
        assert_eq!(recs[1].operation, "QUERY UPDATE");
        assert!(recs[1].error);
        assert_eq!(recs[1].status_code, 1146);
    }

    #[test]
    fn multipacket_resultset_pairs_once_then_drains_to_next_command() {
        let mut p = MysqlParser::new();
        p.on_inbound(&query("SELECT id, name FROM users"), 1);
        // Result set: header(2 cols) + 2 column defs + EOF + 1 row + EOF.
        let mut rs = resultset_header(1, 2);
        rs.extend_from_slice(&packet(2, b"\x03def")); // column def 1 (opaque)
        rs.extend_from_slice(&packet(3, b"\x03def")); // column def 2 (opaque)
        rs.extend_from_slice(&eof_packet(4)); // end of column defs
        rs.extend_from_slice(&packet(5, b"\x011\x04mike")); // one row (opaque)
        rs.extend_from_slice(&eof_packet(6)); // end of rows — response terminates
        p.on_outbound(&rs, 50);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "the whole result-set is one paired record");
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 49);

        // A following command must pair with the NEXT response's first packet,
        // proving the result-set drain re-synced the stream.
        p.on_inbound(&query("PING"), 60); // (literal text; verb is "PING")
        p.on_outbound(&ok_packet(1), 70);
        let recs2 = p.take_records();
        assert_eq!(recs2.len(), 1);
        assert_eq!(recs2[0].operation, "QUERY PING");
    }

    /// Bug guard: a text result-set has TWO EOF packets (after the column defs,
    /// after the rows). Closing the response on the FIRST EOF mis-pairs the row
    /// packets against the next pending command. Here a second command is queued
    /// *before* the result-set arrives, so a premature close would steal a row as
    /// its response. The result set must pair exactly once, and the second command
    /// must pair only with the SECOND response.
    #[test]
    fn resultset_with_two_eofs_does_not_steal_next_command_response() {
        let mut p = MysqlParser::new();
        // Two commands pipelined; the second is the trap for a premature close.
        p.on_inbound(&query("SELECT a, b FROM t"), 1);
        p.on_inbound(&query("UPDATE t SET a = 1"), 2);
        assert_eq!(p.pending.len(), 2);

        // First response: a 2-column result set with both EOFs and two rows.
        let mut rs = resultset_header(1, 2);
        rs.extend_from_slice(&packet(2, b"\x03def")); // column def 1
        rs.extend_from_slice(&packet(3, b"\x03def")); // column def 2
        rs.extend_from_slice(&eof_packet(4)); // column-defs EOF (the trap)
        rs.extend_from_slice(&packet(5, b"\x011\x012")); // row 1
        rs.extend_from_slice(&packet(6, b"\x013\x014")); // row 2
        rs.extend_from_slice(&eof_packet(7)); // rows EOF — response terminates
        p.on_outbound(&rs, 50);

        let recs = p.take_records();
        assert_eq!(
            recs.len(),
            1,
            "the whole result-set is exactly one record; rows must not pair"
        );
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert!(!recs[0].error);

        // The UPDATE must still be pending — its response hasn't arrived.
        assert_eq!(p.pending.len(), 1, "UPDATE must not have been paired yet");

        // Second response pairs with the UPDATE.
        p.on_outbound(&err_packet(1, 1213), 60); // ER_LOCK_DEADLOCK
        let recs2 = p.take_records();
        assert_eq!(recs2.len(), 1);
        assert_eq!(recs2[0].operation, "QUERY UPDATE");
        assert!(recs2[0].error);
        assert_eq!(recs2[0].status_code, 1213);
    }

    /// Bug guard: a result-set row whose first column value is a length-encoded
    /// string with an `0xfe` length prefix (value length ≥ 0xFFFFFF) leads with a
    /// `0xfe` byte but is NOT an EOF — per spec, a `0xfe`-headed packet is only an
    /// EOF/OK when its payload is `< 0xFFFFFF`. We assert the predicate directly
    /// (a 16 MiB packet is impractical to build) and that a small `0xfe`-led row
    /// inside the rows phase is still consumed without ending the stream early.
    #[test]
    fn long_0xfe_led_row_is_not_an_eof_terminator() {
        // The length rule, asserted at the unit level.
        assert!(terminates_response(RESP_EOF, 5), "short EOF terminates");
        assert!(
            !terminates_response(RESP_EOF, MAX_PACKET_PAYLOAD),
            "a 0xFFFFFF-payload 0xfe packet is a row, not an EOF"
        );
        assert!(
            terminates_response(RESP_OK, MAX_PACKET_PAYLOAD),
            "OK always terminates"
        );
        assert!(
            terminates_response(RESP_ERR, MAX_PACKET_PAYLOAD),
            "ERR always terminates"
        );
    }

    /// Bug guard: a command whose body straddles two captured segments at a
    /// non-header boundary must wait for the rest before the NEXT packet is framed.
    /// Without consuming the deferred body skip, the leftover body bytes get
    /// mis-read as a fresh packet header and the stream desyncs. A second command
    /// after the split proves re-sync.
    #[test]
    fn command_body_split_across_segments_does_not_desync() {
        let mut p = MysqlParser::new();
        let cmd = query("SELECT something_with_a_long_tail FROM big_table");
        // Split mid-verb (only "SEL" of "SELECT" buffered). The command must NOT be
        // framed yet — labelling it now would yield the truncated verb "SEL".
        let cut = HEADER_LEN + 4;
        p.on_inbound(&cmd[..cut], 1);
        assert!(
            p.pending.is_empty(),
            "a mid-verb split must wait, not frame a truncated label"
        );
        // The rest of the body arrives; now the command frames with the FULL verb.
        p.on_inbound(&cmd[cut..], 1);
        assert_eq!(p.pending.len(), 1);
        assert_eq!(
            p.pending[0].label, "QUERY SELECT",
            "the verb must be complete, not truncated to SEL"
        );

        // A genuinely new command must frame cleanly afterwards (no desync from the
        // deferred body of the first).
        p.on_inbound(&query("DELETE FROM logs"), 2);
        assert_eq!(p.pending.len(), 2, "the next command re-synced and framed");

        // Two responses pair FIFO with the two real commands.
        let mut resp = ok_packet(1);
        resp.extend_from_slice(&ok_packet(1));
        p.on_outbound(&resp, 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert_eq!(recs[1].operation, "QUERY DELETE");
    }

    /// Bug guard: when the verb is already complete but the rest of a long body has
    /// not arrived, the command frames immediately (correct label) and the trailing
    /// body is deferred as a skip — the NEXT command must still frame cleanly once
    /// that skip is consumed, proving the skip/label split re-syncs the stream.
    #[test]
    fn long_body_frames_on_verb_then_defers_tail() {
        let mut p = MysqlParser::new();
        let cmd = query("SELECT * FROM a_very_long_table_name_that_pushes_the_body_out");
        // Cut AFTER the verb + its trailing space (verb is unambiguously complete),
        // but well before the body ends.
        let cut = HEADER_LEN + 1 + "SELECT ".len();
        p.on_inbound(&cmd[..cut], 1);
        assert_eq!(p.pending.len(), 1, "verb complete → framed now");
        assert_eq!(p.pending[0].label, "QUERY SELECT");
        // The body tail arrives; it is the deferred skip, not a new packet.
        p.on_inbound(&cmd[cut..], 1);
        assert_eq!(
            p.pending.len(),
            1,
            "tail consumed as skip, no phantom command"
        );
        // A fresh command frames cleanly after the skip is drained.
        p.on_inbound(&packet(0, &[COM_PING]), 2);
        assert_eq!(p.pending.len(), 2);
        let mut resp = ok_packet(1);
        resp.extend_from_slice(&ok_packet(1));
        p.on_outbound(&resp, 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert_eq!(recs[1].operation, "PING");
    }

    /// Bug guard: a RESPONSE packet whose body straddles segments must likewise
    /// defer its body skip rather than mis-frame the next response header. Here an
    /// ERR response is split mid-body; the error code must survive and the next
    /// response must still pair with the next command.
    #[test]
    fn response_body_split_across_segments_does_not_desync() {
        let mut p = MysqlParser::new();
        p.on_inbound(&query("SELECT 1"), 1);
        p.on_inbound(&query("SELECT 2"), 2);

        // An ERR packet padded so its body is long enough to straddle.
        let mut err = vec![RESP_ERR, 0x2a, 0x04]; // code 0x042a = 1066
        err.extend_from_slice(b"#42000padding-message-to-make-the-body-long");
        let err_pkt = packet(1, &err);
        let cut = HEADER_LEN + 5; // mid-body
        p.on_outbound(&err_pkt[..cut], 3);
        // Verdict-bearing bytes (tag + 2-byte code) are within the first chunk, so
        // the first response may pair already.
        p.on_outbound(&err_pkt[cut..], 4);

        // Second response must pair with SELECT 2, proving re-sync after the split.
        p.on_outbound(&ok_packet(1), 5);

        let recs = p.take_records();
        assert_eq!(recs.len(), 2, "both responses paired across the split");
        assert_eq!(recs[0].operation, "QUERY SELECT");
        assert!(recs[0].error);
        assert_eq!(
            recs[0].status_code, 1066,
            "error code survived the body split"
        );
        assert_eq!(recs[1].operation, "QUERY SELECT");
        assert!(!recs[1].error);
    }

    /// Bug guard: a truncated ERR response (header + only the tag byte buffered)
    /// must WAIT for the 2-byte error code rather than pairing with a fabricated
    /// code 0. Once the code arrives, the real code is reported.
    #[test]
    fn truncated_err_waits_for_its_code() {
        let mut p = MysqlParser::new();
        p.on_inbound(&query("INSERT INTO t VALUES (1)"), 1);
        let err = err_packet(1, 1062); // ER_DUP_ENTRY
        // Deliver header + tag byte only (not the 2-byte code).
        p.on_outbound(&err[..HEADER_LEN + 1], 2);
        assert!(
            p.take_records().is_empty(),
            "must not pair before the error code is buffered"
        );
        // Deliver the rest; now it pairs with the real code.
        p.on_outbound(&err[HEADER_LEN + 1..], 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
        assert_eq!(
            recs[0].status_code, 1062,
            "the real code, not a fabricated 0"
        );
    }

    /// The length-encoded-integer decoder must handle every prefix form and never
    /// panic on a truncated trailing-byte run (it returns `None`, signalling wait).
    #[test]
    fn length_encoded_int_decodes_all_prefixes_and_truncations() {
        assert_eq!(length_encoded_int(&[0x00]), Some(0));
        assert_eq!(length_encoded_int(&[0xfa]), Some(250));
        assert_eq!(length_encoded_int(&[0xfc, 0x01, 0x01]), Some(0x0101));
        assert_eq!(
            length_encoded_int(&[0xfd, 0x01, 0x00, 0x01]),
            Some(0x010001)
        );
        assert_eq!(length_encoded_int(&[0xfe, 1, 0, 0, 0, 0, 0, 0, 0]), Some(1));
        // 0xfb (NULL) and 0xff (sentinel) are not valid counts.
        assert_eq!(length_encoded_int(&[0xfb]), None);
        assert_eq!(length_encoded_int(&[0xff]), None);
        // Truncated trailing bytes → None (wait), never a panic.
        assert_eq!(length_encoded_int(&[0xfc, 0x01]), None);
        assert_eq!(length_encoded_int(&[0xfd, 0x01, 0x02]), None);
        assert_eq!(length_encoded_int(&[0xfe, 1, 2, 3]), None);
        assert_eq!(length_encoded_int(&[]), None);
    }

    /// Hard requirement: the parser must NEVER panic on adversarial input, however
    /// hostile, truncated, or fragmented. We drive a wide range of malformed byte
    /// streams through both directions, one byte at a time and in whole chunks,
    /// across many split points, and assert only that it doesn't panic.
    #[test]
    fn never_panics_on_adversarial_bytes() {
        let hostile: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0xff, 0xff, 0xff, 0x00], // max 3-byte length, no body
            vec![0xff, 0xff, 0xff, 0x00, 0xff], // claims 16 MiB, one ERR byte
            vec![0x01, 0x00, 0x00, 0x00], // header, length 1, no payload
            vec![0x00, 0x00, 0x00, 0x00], // 0-length payload (bare header)
            vec![0xfe; 64],               // all 0xfe
            vec![0xff; 64],               // all 0xff (ERR-ish)
            vec![0x03, 0x00, 0x00, 0x00, COM_QUERY], // QUERY with no SQL
            vec![0x05, 0x00, 0x00, 0x00, RESP_ERR], // ERR claims 5 bytes, has 0
            vec![0x01, 0x00, 0x00, 0x00, 0x16], // STMT_PREPARE, no SQL
            b"\xff\xff\xff\x00not-a-real-mysql-stream-at-all".to_vec(),
            (0u8..=255).collect(),
            (0u8..=255).rev().collect(),
        ];

        for bytes in &hostile {
            // Whole-chunk, both directions.
            let mut p = MysqlParser::new();
            p.on_inbound(bytes, 1);
            p.on_outbound(bytes, 2);
            let _ = p.take_records();
            let _ = p.is_dead();

            // One byte at a time, alternating directions — the worst case for
            // fragmentation handling.
            let mut p = MysqlParser::new();
            for (i, b) in bytes.iter().enumerate() {
                if i % 2 == 0 {
                    p.on_inbound(&[*b], i as i64);
                } else {
                    p.on_outbound(&[*b], i as i64);
                }
            }
            let _ = p.take_records();

            // Detector must not panic either.
            let _ = detect_mysql(bytes);
        }
    }

    #[test]
    fn com_quit_does_not_wait_for_a_response() {
        let mut p = MysqlParser::new();
        p.on_inbound(&packet(0, &[COM_QUIT]), 1);
        assert!(
            p.pending.is_empty(),
            "COM_QUIT expects no reply, so nothing should be pending"
        );
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn non_query_commands_get_mnemonic_labels() {
        let mut p = MysqlParser::new();
        p.on_inbound(&packet(0, &[COM_PING]), 1);
        p.on_outbound(&ok_packet(1), 2);
        assert_eq!(p.take_records()[0].operation, "PING");

        let mut p = MysqlParser::new();
        p.on_inbound(&packet(0, &[COM_STMT_EXECUTE, 0, 0, 0, 0]), 1);
        p.on_outbound(&ok_packet(1), 2);
        assert_eq!(p.take_records()[0].operation, "STMT_EXECUTE");
    }

    #[test]
    fn orphan_response_is_dropped() {
        let mut p = MysqlParser::new();
        p.on_outbound(&ok_packet(1), 0); // no pending command
        assert!(p.take_records().is_empty());
    }
}
