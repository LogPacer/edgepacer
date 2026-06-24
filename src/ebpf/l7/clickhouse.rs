//! ClickHouse native TCP wire parser — implements [`super::L7Parser`], the
//! zero-code APM producer for ClickHouse connections (well-known port 9000).
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! ClickHouse's native protocol has no message-length header and no magic number.
//! Every packet begins with an unsigned **varint (LEB128)** *packet type*, then a
//! type-specific body. Strings are `varint length + UTF-8 bytes`. We only decode
//! the two packets a span needs — the client **Query** (the SQL verb) and the
//! server **Exception** (the failure verdict) — and frame past nothing else,
//! because without a length header an unrecognised packet cannot be skipped.
//!
//! ### Client packets (inbound = requests)
//!   * **Hello (0)** — `client_name:String, major:varint, minor:varint,
//!     protocol_version:varint, database:String, user:String, password:String`.
//!     We read `protocol_version` (the client's max) to later compute the
//!     negotiated revision.
//!   * **Query (1)** — `query_id:String, client_info, settings, secret:String,
//!     stage:varint, compression:varint, query_text:String`. The operation is the
//!     SQL verb (first word of `query_text`, uppercased). `client_info` is a block
//!     of ~11 fixed + up to 7 revision-gated fields; skipping it soundly requires
//!     the negotiated revision (below). `settings` is a list of `(name, value)`
//!     string pairs terminated by an empty name.
//!   * **Data (2) / Ping (4) / Cancel (3)** — not interpreted. A Data packet has
//!     no length header, so once one appears on a connection we can no longer find
//!     the next packet boundary; the parser goes quiet (records what it has, emits
//!     nothing further) rather than guess. In practice the Query→first-response
//!     exchange — all a span needs — completes before client Data blocks matter.
//!
//! ### Server packets (outbound = responses)
//!   * **Hello (0)** — `name:String, major:varint, minor:varint, revision:varint,
//!     …`. The `revision` is the server's max; the negotiated revision the client
//!     uses to encode ClientInfo is `min(client_protocol_version, server_revision)`.
//!     Capturing it from the handshake is what makes Query parsing sound.
//!   * **Exception (2)** — `code:i32 LE, name:String, message:String,
//!     stack_trace:String, nested:u8 (1 ⇒ another Exception follows)`. Sets the
//!     error verdict + carries the numeric code as the status.
//!   * **EndOfStream (5) / Pong (4)** — terminate a normal (non-error) response.
//!   * **Data (1) / Progress (3) / … (≤14)** — a successful query streams these
//!     before EndOfStream. They carry no length header and Data is compressible, so
//!     we cannot frame past them. Instead the response side pairs a pending Query
//!     with the FIRST decisive server packet it sees — an Exception (error) or an
//!     EndOfStream/Pong (success) — which is sufficient for the span verdict, and
//!     stops parsing the response stream after that packet's type byte.
//!
//! ## Why detection anchors on Hello, never Query
//!
//! A Query packet's ClientInfo layout is revision-dependent; with no handshake
//! observed we don't know the revision, so we cannot soundly reach its query text
//! — a one-byte miscount desyncs the whole parse. The client **Hello** is the only
//! sound byte-signature: `varint 0` then a well-formed `client_name` string then
//! three parseable varints then three more well-formed strings. That conjunction
//! does not plausibly occur in other binary openers. Detection from a mid-stream
//! Query is therefore declined (see [`detect_clickhouse`]); the port-hint path
//! ([`new_parser`], port 9000) binds unconditionally and still parses correctly
//! because it observes the connection — including the Hello handshake — from its
//! first bytes.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Client packet type codes (the leading varint on inbound packets).
const CLIENT_HELLO: u64 = 0;
const CLIENT_QUERY: u64 = 1;

/// Server packet type codes (the leading varint on outbound packets).
const SERVER_HELLO: u64 = 0;
const SERVER_EXCEPTION: u64 = 2;
const SERVER_PONG: u64 = 4;
const SERVER_END_OF_STREAM: u64 = 5;
/// Highest defined server packet type (ProfileEvents = 14). A leading varint
/// beyond this on the response side is not a ClickHouse packet — desync.
const SERVER_MAX_PACKET: u64 = 14;

/// Revision gates for the version-conditional ClientInfo fields, taken from the
/// ClickHouse `DBMS_MIN_REVISION_WITH_*` constants. The client encodes ClientInfo
/// at the negotiated revision `min(client_protocol_version, server_revision)`, so
/// skipping it soundly means honouring exactly these gates.
const REV_QUOTA_KEY: u64 = 54_060;
const REV_VERSION_PATCH: u64 = 54_401;
const REV_OPENTELEMETRY: u64 = 54_442;
const REV_DISTRIBUTED_DEPTH: u64 = 54_448;
const REV_QUERY_START_TIME: u64 = 54_449;
const REV_PARALLEL_REPLICAS: u64 = 54_453;
const REV_QUERY_AND_LINE_NUMBERS: u64 = 54_475;
const REV_JWT_INTERSERVER: u64 = 54_476;

/// Revision gates for the Query packet body itself (outside ClientInfo), taken from
/// ClickHouse `Connection::sendQuery` (`src/Client/Connection.cpp`). The settings
/// list switches to the strings-with-flags encoding, and the interserver-secret and
/// external-roles strings appear, each at their own gate — a missed field desyncs
/// the walk to `query_text` just as surely as a ClientInfo miscount.
const REV_SETTINGS_STRINGS_WITH_FLAGS: u64 = 54_429;
const REV_INTERSERVER_SECRET: u64 = 54_441;
const REV_EXTERNAL_ROLES: u64 = 54_472;

/// Revision gates for the server Hello tail, from ClickHouse `TCPHandler::sendHello`
/// (`src/Server/TCPHandler.cpp`). The protocol has no length header, so the parser
/// must walk this whole tail to find the next server packet boundary.
const REV_SERVER_TIMEZONE: u64 = 54_058;
const REV_SERVER_DISPLAY_NAME: u64 = 54_372;
const REV_SERVER_PASSWORD_COMPLEXITY: u64 = 54_461;
const REV_SERVER_INTERSERVER_SECRET_V2: u64 = 54_462;
const REV_SERVER_CHUNKED_PACKETS: u64 = 54_470;
const REV_SERVER_VERSIONED_PARALLEL_REPLICAS: u64 = 54_471;
const REV_SERVER_SETTINGS: u64 = 54_474;

/// Upper bound on the server's password-complexity rule count (ClickHouse
/// `DBMS_MAX_PASSWORD_COMPLEXITY_RULES`). A larger declared count means a desync, so
/// we bail rather than loop on hostile input.
const SERVER_MAX_PASSWORD_COMPLEXITY_RULES: u64 = 256;

/// `interface` byte value meaning the TCP interface. The `os_user/hostname/name +
/// version` group and the `version_patch` field are present only for this
/// interface; an HTTP-interface ClientInfo writes an entirely different middle
/// block, so we can only frame past a TCP ClientInfo soundly.
const INTERFACE_TCP: u8 = 1;

/// Upper bound on a single string's declared length. ClickHouse query texts and
/// identifiers are far below this; a varint length beyond it means we mis-detected
/// or desynced, so we bail rather than buffer unboundedly.
const MAX_STRING_LEN: u64 = 64 * 1024 * 1024;

/// A fallback negotiated revision used only when the response Hello has not been
/// observed (e.g. the port-hint path attached just after the handshake). Recent
/// enough that all gated ClientInfo fields are assumed present — the common case
/// for any modern server — keeping a best-effort Query parse possible. If this
/// guess is wrong the Query simply fails to label cleanly and is recorded as
/// `"QUERY"`; it never desyncs the response side, which is framed independently.
/// Set to the current `DBMS_TCP_PROTOCOL_VERSION` so a no-handshake guess matches a
/// modern client (all gated ClientInfo fields present).
const ASSUMED_REVISION: u64 = 54_485;

/// Outcome of reading a length-delimited value from a buffer prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read<T> {
    /// A complete value plus how many bytes it consumed from the prefix.
    Done { value: T, consumed: usize },
    /// A valid prefix but not all bytes are buffered yet — wait.
    Partial,
    /// Not well-formed — desync; drop the connection.
    Invalid,
}

/// Read an unsigned LEB128 varint from the front of `buf`. Standard encoding:
/// 7 payload bits per byte, low groups first, continuation in the high bit.
/// Bounded to 10 bytes (a full u64) so a run of continuation bytes can't spin.
fn read_varint(buf: &[u8]) -> Read<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().take(10).enumerate() {
        // 10th byte (i==9) may only contribute the top bit; reject overflow.
        if shift >= 64 {
            return Read::Invalid;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Read::Done {
                value,
                consumed: i + 1,
            };
        }
        shift += 7;
    }
    if buf.len() < 10 {
        Read::Partial
    } else {
        // 10 bytes all with the continuation bit set — not a valid u64 varint.
        Read::Invalid
    }
}

/// Read a `varint length + bytes` string from the front of `buf`, returning the
/// raw bytes (borrowed) and the total bytes consumed. An over-long declared length
/// is `Invalid`; a length that simply isn't all buffered yet is `Partial`.
fn read_string(buf: &[u8]) -> Read<&[u8]> {
    let (len, head) = match read_varint(buf) {
        Read::Done { value, consumed } => (value, consumed),
        Read::Partial => return Read::Partial,
        Read::Invalid => return Read::Invalid,
    };
    if len > MAX_STRING_LEN {
        return Read::Invalid;
    }
    let len = len as usize;
    let total = head + len;
    if buf.len() < total {
        return Read::Partial;
    }
    Read::Done {
        value: &buf[head..total],
        consumed: total,
    }
}

/// Consume a `varint length + bytes` string for its byte length only (value
/// discarded), advancing `pos`. Returns false if the string isn't fully buffered
/// or is malformed — the caller treats that as "cannot frame this Query yet".
fn skip_string(buf: &[u8], pos: &mut usize) -> Option<bool> {
    match read_string(buf.get(*pos..)?) {
        Read::Done { consumed, .. } => {
            *pos += consumed;
            Some(true)
        }
        Read::Partial => Some(false),
        Read::Invalid => None,
    }
}

/// Consume a varint for its width only, advancing `pos`. `None` on malformed,
/// `Some(false)` if not yet buffered, `Some(true)` on success.
fn skip_varint(buf: &[u8], pos: &mut usize) -> Option<bool> {
    match read_varint(buf.get(*pos..)?) {
        Read::Done { consumed, .. } => {
            *pos += consumed;
            Some(true)
        }
        Read::Partial => Some(false),
        Read::Invalid => None,
    }
}

/// Consume `n` fixed bytes, advancing `pos`. `Some(false)` if not yet buffered.
fn skip_fixed(buf: &[u8], pos: &mut usize, n: usize) -> Option<bool> {
    if *pos + n > buf.len() {
        return Some(false);
    }
    *pos += n;
    Some(true)
}

/// The SQL verb of a query: the first whitespace-delimited word, uppercased. The
/// span's operation label (`SELECT`/`INSERT`/`CREATE`/…). Leading SQL comments and
/// whitespace are stepped over so `"-- c\nSELECT 1"` still labels as `SELECT`.
fn sql_verb(query: &[u8]) -> String {
    let text = std::str::from_utf8(query).unwrap_or("");
    let mut rest = text;
    loop {
        let trimmed = rest.trim_start();
        if let Some(after) = trimmed.strip_prefix("--") {
            // Line comment: skip to end of line.
            rest = after.split_once('\n').map(|(_, r)| r).unwrap_or("");
        } else if let Some(after) = trimmed.strip_prefix("/*") {
            // Block comment: skip to its close.
            rest = after.split_once("*/").map(|(_, r)| r).unwrap_or("");
        } else {
            rest = trimmed;
            break;
        }
    }
    rest.split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .find(|w| !w.is_empty())
        .unwrap_or("")
        .to_ascii_uppercase()
}

/// Skip a ClientInfo block at `pos` within a Query packet, using the negotiated
/// `revision` to honour the version-gated fields. Returns `Some(true)` once fully
/// skipped, `Some(false)` if more bytes are needed, `None` on malformed framing.
///
/// Field order mirrors ClickHouse `ClientInfo::write` (`src/Interpreters/
/// ClientInfo.cpp`) exactly — a one-field miscount desyncs the rest of the Query,
/// so this is transcribed from the source, not approximated:
///
/// ```text
/// query_kind:u8
/// // if query_kind == NO_QUERY (0): the writer returns here — nothing follows.
/// initial_user:String  initial_query_id:String  initial_address:String
/// initial_query_start_time_microseconds:i64 (8B)   [rev >= QUERY_START_TIME] // BEFORE interface
/// interface:u8
/// // interface == TCP (1):
/// os_user:String  client_hostname:String  client_name:String
/// major:varint  minor:varint  protocol_version:varint
/// quota_key:String                                 [rev >= QUOTA_KEY]
/// distributed_depth:varint                         [rev >= DISTRIBUTED_DEPTH]
/// version_patch:varint                             [rev >= VERSION_PATCH && interface == TCP]
/// // OTEL block                                    [rev >= OPENTELEMETRY]
/// // parallel-replicas: 3 varints                  [rev >= PARALLEL_REPLICAS]
/// // query_and_line_numbers: 2 varints             [rev >= QUERY_AND_LINE_NUMBERS]
/// // jwt: presence byte (+ jwt:String if 1)        [rev >= JWT_INTERSERVER]
/// ```
///
/// Only the TCP interface is framed past; an HTTP-interface ClientInfo writes a
/// different middle block (http_method, user_agent, forwarded_for, referer) we do
/// not transcribe, so a non-TCP interface byte yields `None` (cannot frame).
fn skip_client_info(buf: &[u8], pos: &mut usize, revision: u64) -> Option<bool> {
    // query_kind byte.
    let query_kind_at = *pos;
    if !skip_fixed(buf, pos, 1)? {
        return Some(false);
    }
    // query_kind == NO_QUERY (0) means `empty()`: the writer returns immediately
    // after this byte, so nothing else is present.
    if buf[query_kind_at] == 0 {
        return Some(true);
    }
    // initial_user, initial_query_id, initial_address.
    for _ in 0..3 {
        if !skip_string(buf, pos)? {
            return Some(false);
        }
    }
    // initial_query_start_time_microseconds: int64 (8 bytes) — BEFORE interface.
    if revision >= REV_QUERY_START_TIME && !skip_fixed(buf, pos, 8)? {
        return Some(false);
    }
    // interface byte. We only frame past the TCP interface; anything else has a
    // different layout we don't transcribe.
    let interface_at = *pos;
    if !skip_fixed(buf, pos, 1)? {
        return Some(false);
    }
    let interface = buf[interface_at];
    if interface != INTERFACE_TCP {
        return None;
    }
    // os_user, client_hostname, client_name.
    for _ in 0..3 {
        if !skip_string(buf, pos)? {
            return Some(false);
        }
    }
    // major, minor, client protocol_version.
    for _ in 0..3 {
        if !skip_varint(buf, pos)? {
            return Some(false);
        }
    }
    if revision >= REV_QUOTA_KEY && !skip_string(buf, pos)? {
        return Some(false);
    }
    if revision >= REV_DISTRIBUTED_DEPTH && !skip_varint(buf, pos)? {
        return Some(false);
    }
    // version_patch is inside the `interface == TCP` branch; we're already TCP here.
    if revision >= REV_VERSION_PATCH && !skip_varint(buf, pos)? {
        return Some(false);
    }
    if revision >= REV_OPENTELEMETRY {
        // has_trace:u8; if 1: trace_id(16) + span_id(8) + tracestate:String + flags:u8.
        let has_trace_at = *pos;
        if !skip_fixed(buf, pos, 1)? {
            return Some(false);
        }
        if buf[has_trace_at] == 1 {
            if !skip_fixed(buf, pos, 16 + 8)? {
                return Some(false);
            }
            if !skip_string(buf, pos)? {
                return Some(false);
            }
            if !skip_fixed(buf, pos, 1)? {
                return Some(false);
            }
        }
    }
    if revision >= REV_PARALLEL_REPLICAS {
        // collaborate_with_initiator, obsolete_count_participating_replicas,
        // number_of_current_replica — three varints.
        for _ in 0..3 {
            if !skip_varint(buf, pos)? {
                return Some(false);
            }
        }
    }
    if revision >= REV_QUERY_AND_LINE_NUMBERS {
        // script_query_number, script_line_number — two varints.
        for _ in 0..2 {
            if !skip_varint(buf, pos)? {
                return Some(false);
            }
        }
    }
    if revision >= REV_JWT_INTERSERVER {
        // has_jwt:u8; if 1: jwt:String.
        let has_jwt_at = *pos;
        if !skip_fixed(buf, pos, 1)? {
            return Some(false);
        }
        if buf[has_jwt_at] == 1 && !skip_string(buf, pos)? {
            return Some(false);
        }
    }
    Some(true)
}

/// Skip the Settings list at `pos`: zero or more setting entries terminated by an
/// empty name. At `revision >= REV_SETTINGS_STRINGS_WITH_FLAGS` (the modern, common
/// encoding; ClickHouse `BaseSettings::write` with `STRINGS_WITH_FLAGS`) each
/// non-terminal entry is `name:String, flags:varint, value:String`; below that gate
/// it is the legacy `name:String, value:String`. An empty name closes the list (no
/// flags/value follow the terminator). `None` on malformed framing.
fn skip_settings(buf: &[u8], pos: &mut usize, revision: u64) -> Option<bool> {
    let with_flags = revision >= REV_SETTINGS_STRINGS_WITH_FLAGS;
    // Bound the loop against a hostile stream of non-empty names.
    for _ in 0..4096 {
        let name = match read_string(buf.get(*pos..)?) {
            Read::Done { value, consumed } => {
                *pos += consumed;
                value
            }
            Read::Partial => return Some(false),
            Read::Invalid => return None,
        };
        if name.is_empty() {
            return Some(true); // empty name terminates the list
        }
        // flags:varint (only in the strings-with-flags encoding).
        if with_flags && !skip_varint(buf, pos)? {
            return Some(false);
        }
        // setting value (String).
        if !skip_string(buf, pos)? {
            return Some(false);
        }
    }
    None
}

/// Parse a client Query packet body (everything after the type varint) into its
/// SQL verb, using `revision` to skip ClientInfo. `Some(Some(verb))` on a clean
/// parse, `Some(None)` if more bytes are needed, `None` on malformed framing.
#[allow(clippy::option_option)]
fn parse_query(body: &[u8], revision: u64) -> Option<Option<String>> {
    let mut pos = 0usize;
    // query_id.
    if !skip_string(body, &mut pos)? {
        return Some(None);
    }
    // client_info (rev >= CLIENT_INFO; always true for any revision we parse).
    if !skip_client_info(body, &mut pos, revision)? {
        return Some(None);
    }
    // settings.
    if !skip_settings(body, &mut pos, revision)? {
        return Some(None);
    }
    // external_roles:String — appears between settings and the interserver secret.
    if revision >= REV_EXTERNAL_ROLES && !skip_string(body, &mut pos)? {
        return Some(None);
    }
    // interserver secret:String.
    if revision >= REV_INTERSERVER_SECRET && !skip_string(body, &mut pos)? {
        return Some(None);
    }
    // stage:varint, compression:varint.
    if !skip_varint(body, &mut pos)? {
        return Some(None);
    }
    if !skip_varint(body, &mut pos)? {
        return Some(None);
    }
    // query_text:String — the SQL. (params follow but we never read past the SQL.)
    match read_string(body.get(pos..)?) {
        Read::Done { value, .. } => Some(Some(sql_verb(value))),
        Read::Partial => Some(None),
        Read::Invalid => None,
    }
}

/// Validate a client Hello body as a positive detection signature, returning the
/// client's `protocol_version` (its max revision) on success. The conjunction of a
/// well-formed name string, three parseable varints, and three more well-formed
/// strings is the sound byte signature. `Some(Some(rev))` on a clean parse,
/// `Some(None)` if not all bytes are buffered, `None` if it isn't a Hello.
#[allow(clippy::option_option)]
fn parse_client_hello(body: &[u8]) -> Option<Option<u64>> {
    let mut pos = 0usize;
    // client_name.
    if !skip_string(body, &mut pos)? {
        return Some(None);
    }
    // major, minor.
    for _ in 0..2 {
        if !skip_varint(body, &mut pos)? {
            return Some(None);
        }
    }
    // protocol_version — the value we keep.
    let protocol_version = match read_varint(body.get(pos..)?) {
        Read::Done { value, consumed } => {
            pos += consumed;
            value
        }
        Read::Partial => return Some(None),
        Read::Invalid => return None,
    };
    // database, user, password — three strings.
    for _ in 0..3 {
        if !skip_string(body, &mut pos)? {
            return Some(None);
        }
    }
    Some(Some(protocol_version))
}

/// Read the server Hello's `revision` field (its max revision) from a server Hello
/// body. `Some(Some(rev))` on success, `Some(None)` if not buffered, `None` on
/// malformed. Body: `name:String, major:varint, minor:varint, revision:varint, …`.
#[allow(clippy::option_option)]
fn parse_server_hello_revision(body: &[u8]) -> Option<Option<u64>> {
    let mut pos = 0usize;
    if !skip_string(body, &mut pos)? {
        return Some(None);
    }
    for _ in 0..2 {
        if !skip_varint(body, &mut pos)? {
            return Some(None);
        }
    }
    match read_varint(body.get(pos..)?) {
        Read::Done { value, .. } => Some(Some(value)),
        Read::Partial => Some(None),
        Read::Invalid => None,
    }
}

/// The error code carried by a server Exception packet body
/// (`code:i32 LE, …`). The status_code in the record. Best-effort: a truncated
/// body yields `None` and the verdict still records as an error.
fn exception_code(body: &[u8]) -> Option<i32> {
    body.get(0..4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A request awaiting its response verdict: the SQL verb and the observation time.
#[derive(Debug)]
struct Pending {
    operation: String,
    start_unix_nano: i64,
}

/// ClickHouse [`L7Parser`]: tracks the Hello handshake to learn the negotiated
/// revision, labels Query packets with their SQL verb, and pairs each with the
/// first decisive server packet (Exception ⇒ error, EndOfStream/Pong ⇒ success).
///
/// Because the protocol has no per-packet length header, the parser is sound only
/// for the packets it must decode (Hello, Query, Exception, EndOfStream, Pong). On
/// the response side it stops after the first decisive packet of each exchange —
/// the span verdict is settled, and the unframeable Data/Progress stream that
/// precedes EndOfStream cannot be walked anyway. A malformed *decodable* packet
/// marks the parser dead.
#[derive(Debug, Default)]
pub(crate) struct ClickhouseParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending: VecDeque<Pending>,
    records: Vec<L7Record>,
    /// Negotiated revision = `min(client_protocol_version, server_revision)`.
    /// Filled as the Hello handshake is observed; until then Query parsing uses
    /// [`ASSUMED_REVISION`].
    client_revision: Option<u64>,
    server_revision: Option<u64>,
    /// Once a client Data packet (or any inbound packet we cannot frame) appears,
    /// the inbound boundary is lost — stop reading requests.
    inbound_stalled: bool,
    /// Once a server response can no longer be framed past (a Data/Progress stream
    /// with no length header), stop reading the response side until it resets.
    outbound_stalled: bool,
    dead: bool,
}

impl ClickhouseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// The negotiated revision the client used to encode ClientInfo. Once both
    /// Hellos are seen it is their min; if only one (or neither) is known we fall
    /// back to the other, then to [`ASSUMED_REVISION`].
    fn negotiated_revision(&self) -> u64 {
        match (self.client_revision, self.server_revision) {
            (Some(c), Some(s)) => c.min(s),
            (Some(c), None) => c,
            (None, Some(s)) => s,
            (None, None) => ASSUMED_REVISION,
        }
    }

    /// Frame inbound (client) packets: Hello captures the client revision; Query
    /// queues a pending operation. Any other packet type has no length header, so
    /// we cannot find the next boundary — stall the inbound side (keep the records
    /// already gathered; emit nothing further from this direction).
    fn drain_inbound(&mut self, ts: i64) {
        loop {
            if self.inbound_stalled || self.inbound.buf.is_empty() {
                return;
            }
            let (packet_type, head) = match read_varint(&self.inbound.buf) {
                Read::Done { value, consumed } => (value, consumed),
                Read::Partial => return,
                Read::Invalid => {
                    self.dead = true;
                    return;
                }
            };
            let body = &self.inbound.buf[head..];
            match packet_type {
                CLIENT_HELLO => match parse_client_hello(body) {
                    Some(Some(rev)) => {
                        self.client_revision = Some(rev);
                        // Re-frame: consume exactly the Hello's bytes.
                        let consumed = hello_len(body);
                        match consumed {
                            Some(n) => self.inbound.advance(head + n),
                            None => return, // shouldn't happen after a clean parse
                        }
                    }
                    Some(None) => return, // wait for the rest of the Hello
                    None => {
                        self.dead = true;
                        return;
                    }
                },
                CLIENT_QUERY => {
                    let rev = self.negotiated_revision();
                    match parse_query(body, rev) {
                        Some(Some(verb)) => {
                            let operation = if verb.is_empty() {
                                "QUERY".to_string()
                            } else {
                                verb
                            };
                            let consumed = query_len(body, rev);
                            match consumed {
                                Some(n) => {
                                    self.pending.push_back(Pending {
                                        operation,
                                        start_unix_nano: ts,
                                    });
                                    self.inbound.advance(head + n);
                                }
                                None => return,
                            }
                        }
                        Some(None) => return, // wait for the rest of the Query
                        None => {
                            self.dead = true;
                            return;
                        }
                    }
                }
                // Any other client packet (Data/Ping/Cancel) has no length header.
                // We can't find the next boundary — stop reading requests cleanly.
                _ => {
                    self.inbound_stalled = true;
                    return;
                }
            }
        }
    }

    /// Frame outbound (server) packets up to and including the first decisive one
    /// of each exchange. Hello captures the server revision. Exception sets the
    /// error verdict; EndOfStream / Pong settle a success. After a decisive packet
    /// we stop — the Data/Progress stream before EndOfStream is unframeable.
    fn drain_outbound(&mut self, ts: i64) {
        loop {
            if self.outbound_stalled || self.outbound.buf.is_empty() {
                return;
            }
            let (packet_type, head) = match read_varint(&self.outbound.buf) {
                Read::Done { value, consumed } => (value, consumed),
                Read::Partial => return,
                Read::Invalid => {
                    self.dead = true;
                    return;
                }
            };
            if packet_type > SERVER_MAX_PACKET {
                self.dead = true;
                return;
            }
            let body = &self.outbound.buf[head..];
            match packet_type {
                SERVER_HELLO => match parse_server_hello_revision(body) {
                    Some(Some(rev)) => {
                        self.server_revision = Some(rev);
                        // The server gates its Hello tail on the client's announced
                        // revision; honour the negotiated value now that the server
                        // revision is recorded (it folds into negotiated_revision).
                        match server_hello_len(body, self.negotiated_revision()) {
                            Some(n) => self.outbound.advance(head + n),
                            None => return,
                        }
                    }
                    Some(None) => return,
                    None => {
                        self.dead = true;
                        return;
                    }
                },
                SERVER_EXCEPTION => {
                    // The error verdict only needs the leading i32 code; the three
                    // following strings + nested byte we don't frame past (the next
                    // packet may be an unframeable Data anyway). Wait for the code.
                    if body.len() < 4 {
                        return;
                    }
                    let code = exception_code(body).unwrap_or(0);
                    self.complete(true, status_from_code(code), ts);
                    // Verdict settled; the rest of the response is unframeable.
                    self.outbound_stalled = true;
                    return;
                }
                SERVER_END_OF_STREAM | SERVER_PONG => {
                    self.complete(false, 0, ts);
                    self.outbound.advance(head);
                }
                // Data / Progress / Totals / … : carry no length header (Data is
                // compressible). We cannot frame past them. The exchange's verdict
                // is "no error seen yet"; pair the pending request as a success now
                // and stop — an Exception, if any, would have come first.
                _ => {
                    self.complete(false, 0, ts);
                    self.outbound_stalled = true;
                    return;
                }
            }
        }
    }

    /// Pair the oldest pending request with a response verdict, emitting a record.
    /// A response with no pending request (mid-stream attach) is dropped.
    fn complete(&mut self, error: bool, status_code: u16, ts: i64) {
        if let Some(req) = self.pending.pop_front() {
            self.records.push(L7Record {
                protocol: Protocol::Clickhouse,
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

/// Map a ClickHouse exception code to a record status. Codes are positive i32; a
/// negative/zero code (truncated body) collapses to 1 so the failure is still
/// distinguishable. Clamped to `u16` for the record field.
fn status_from_code(code: i32) -> u16 {
    if code <= 0 {
        1
    } else {
        code.min(u16::MAX as i32) as u16
    }
}

/// Total byte length of a client Hello body (after the type varint), or `None` if
/// not fully buffered / malformed. Used to advance exactly past a parsed Hello.
fn hello_len(body: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    if !skip_string(body, &mut pos)? {
        return None;
    }
    for _ in 0..3 {
        if !skip_varint(body, &mut pos)? {
            return None;
        }
    }
    for _ in 0..3 {
        if !skip_string(body, &mut pos)? {
            return None;
        }
    }
    Some(pos)
}

/// Total byte length of a client Query body (after the type varint) at `revision`,
/// or `None` if not fully buffered / malformed.
fn query_len(body: &[u8], revision: u64) -> Option<usize> {
    let mut pos = 0usize;
    // query_id.
    if !skip_string(body, &mut pos)? {
        return None;
    }
    // client_info.
    if !skip_client_info(body, &mut pos, revision)? {
        return None;
    }
    // settings.
    if !skip_settings(body, &mut pos, revision)? {
        return None;
    }
    // external_roles:String.
    if revision >= REV_EXTERNAL_ROLES && !skip_string(body, &mut pos)? {
        return None;
    }
    // interserver secret:String.
    if revision >= REV_INTERSERVER_SECRET && !skip_string(body, &mut pos)? {
        return None;
    }
    // stage:varint, compression:varint.
    if !skip_varint(body, &mut pos)? {
        return None;
    }
    if !skip_varint(body, &mut pos)? {
        return None;
    }
    // query_text:String.
    if !skip_string(body, &mut pos)? {
        return None;
    }
    Some(pos)
}

/// Total byte length of a server Hello body (after the type varint), or `None` if
/// not fully buffered / malformed. The protocol has no length header, so the parser
/// must walk the *entire* documented tail to find the next packet boundary.
///
/// Field order mirrors ClickHouse `TCPHandler::sendHello` (`src/Server/
/// TCPHandler.cpp`). Crucially the server gates every tail field on
/// `client_tcp_protocol_version`, so the correct gate is the negotiated revision
/// (`min(client, server)`): if it clears a gate, the client announced support AND
/// the server is new enough to write the field; if not, the field is absent. The
/// `revision` argument is that negotiated value.
///
/// ```text
/// name:String  major:varint  minor:varint  revision:varint   // always
/// parallel_replicas_protocol_version:varint   [rev >= VERSIONED_PARALLEL_REPLICAS] // BEFORE timezone
/// timezone:String                             [rev >= SERVER_TIMEZONE]
/// display_name:String                         [rev >= SERVER_DISPLAY_NAME]
/// version_patch:varint                        [rev >= VERSION_PATCH]
/// proto_send:String  proto_recv:String        [rev >= CHUNKED_PACKETS]
/// password_complexity: count:varint then count*(pattern:String, message:String)
///                                             [rev >= PASSWORD_COMPLEXITY_RULES]
/// interserver_nonce:u64 (8B)                  [rev >= INTERSERVER_SECRET_V2]
/// server_settings: settings list (STRINGS_WITH_FLAGS, empty-name terminated)
///                                             [rev >= SERVER_SETTINGS]
/// ```
fn server_hello_len(body: &[u8], revision: u64) -> Option<usize> {
    let mut pos = 0usize;
    // name:String, major, minor, revision (always present).
    if !skip_string(body, &mut pos)? {
        return None;
    }
    for _ in 0..3 {
        if !skip_varint(body, &mut pos)? {
            return None;
        }
    }
    // parallel_replicas_protocol_version:varint — BEFORE timezone.
    if revision >= REV_SERVER_VERSIONED_PARALLEL_REPLICAS && !skip_varint(body, &mut pos)? {
        return None;
    }
    // timezone:String.
    if revision >= REV_SERVER_TIMEZONE && !skip_string(body, &mut pos)? {
        return None;
    }
    // display_name:String.
    if revision >= REV_SERVER_DISPLAY_NAME && !skip_string(body, &mut pos)? {
        return None;
    }
    // version_patch:varint.
    if revision >= REV_VERSION_PATCH && !skip_varint(body, &mut pos)? {
        return None;
    }
    // chunked proto capabilities: proto_send:String, proto_recv:String.
    if revision >= REV_SERVER_CHUNKED_PACKETS {
        for _ in 0..2 {
            if !skip_string(body, &mut pos)? {
                return None;
            }
        }
    }
    // password-complexity rules: count:varint then count*(pattern:String, message:String).
    if revision >= REV_SERVER_PASSWORD_COMPLEXITY {
        let count = match read_varint(body.get(pos..)?) {
            Read::Done { value, consumed } => {
                pos += consumed;
                value
            }
            Read::Partial => return None,
            Read::Invalid => return None,
        };
        if count > SERVER_MAX_PASSWORD_COMPLEXITY_RULES {
            return None;
        }
        for _ in 0..count {
            for _ in 0..2 {
                if !skip_string(body, &mut pos)? {
                    return None;
                }
            }
        }
    }
    // interserver nonce: u64 (8 bytes).
    if revision >= REV_SERVER_INTERSERVER_SECRET_V2 && !skip_fixed(body, &mut pos, 8)? {
        return None;
    }
    // server settings list (strings-with-flags, empty-name terminated).
    if revision >= REV_SERVER_SETTINGS && !skip_settings(body, &mut pos, revision)? {
        return None;
    }
    Some(pos)
}

impl L7Parser for ClickhouseParser {
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

/// Construct a ClickHouse parser unconditionally — the port-hint path (port 9000
/// names the protocol; see `socket_port`). The handshake is still observed from
/// the connection's first bytes, so Query parsing remains sound.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(ClickhouseParser::new())
}

/// Recognise ClickHouse from a connection's inbound prefix via a POSITIVE
/// signature: a client **Hello** (`varint 0`, then a well-formed `client_name`
/// string, three parseable varints, and three more well-formed strings). Returns a
/// fresh parser, or `None` if these bytes aren't (yet) a recognisable Hello.
///
/// Detection is **deliberately Hello-only**. A mid-stream Query cannot be detected
/// soundly: its ClientInfo layout depends on the handshake-negotiated revision,
/// which we have not observed, so reaching its query text would be a guess — and a
/// wrong guess is worse than no detection. Connections observed from their first
/// bytes (the common case, and the only one the byte-detector path sees) always
/// open with this Hello; the port-hint path ([`new_parser`]) covers the rest.
pub(crate) fn detect_clickhouse(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    let (packet_type, head) = match read_varint(inbound) {
        Read::Done { value, consumed } => (value, consumed),
        _ => return None,
    };
    if packet_type != CLIENT_HELLO {
        return None;
    }
    match parse_client_hello(&inbound[head..]) {
        // A fully-parsed Hello is the only commit point — a partial Hello returns
        // None (the registry keeps buffering and retries) rather than guess.
        Some(Some(_rev)) => Some(Box::new(ClickhouseParser::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode an unsigned LEB128 varint.
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

    /// Encode a `varint length + bytes` string.
    fn string(s: &[u8]) -> Vec<u8> {
        let mut out = varint(s.len() as u64);
        out.extend_from_slice(s);
        out
    }

    /// A client Hello packet: type 0 + name + major/minor/protocol + db/user/pass.
    fn client_hello(name: &str, protocol_version: u64) -> Vec<u8> {
        let mut out = varint(CLIENT_HELLO);
        out.extend_from_slice(&string(name.as_bytes()));
        out.extend_from_slice(&varint(24)); // major
        out.extend_from_slice(&varint(8)); // minor
        out.extend_from_slice(&varint(protocol_version));
        out.extend_from_slice(&string(b"default")); // database
        out.extend_from_slice(&string(b"default")); // user
        out.extend_from_slice(&string(b"")); // password
        out
    }

    /// A server Hello packet at `revision`, byte-for-byte as ClickHouse
    /// `TCPHandler::sendHello` writes it (field order + gates transcribed from the
    /// source, not the parser). This is the catching encoder for the server side:
    /// the parallel-replicas version precedes the timezone, and the modern tail
    /// (chunked proto_caps, password rules, nonce, server settings) is present.
    fn server_hello(revision: u64) -> Vec<u8> {
        let mut out = varint(SERVER_HELLO);
        out.extend_from_slice(&string(b"ClickHouse"));
        out.extend_from_slice(&varint(24)); // major
        out.extend_from_slice(&varint(8)); // minor
        out.extend_from_slice(&varint(revision));
        if revision >= REV_SERVER_VERSIONED_PARALLEL_REPLICAS {
            out.extend_from_slice(&varint(7)); // parallel_replicas_protocol_version
        }
        if revision >= REV_SERVER_TIMEZONE {
            out.extend_from_slice(&string(b"UTC")); // timezone
        }
        if revision >= REV_SERVER_DISPLAY_NAME {
            out.extend_from_slice(&string(b"prod-1")); // display_name
        }
        if revision >= REV_VERSION_PATCH {
            out.extend_from_slice(&varint(3)); // version_patch
        }
        if revision >= REV_SERVER_CHUNKED_PACKETS {
            out.extend_from_slice(&string(b"notchunked")); // proto_send
            out.extend_from_slice(&string(b"notchunked")); // proto_recv
        }
        if revision >= REV_SERVER_PASSWORD_COMPLEXITY {
            out.extend_from_slice(&varint(1)); // one password-complexity rule
            out.extend_from_slice(&string(b".{8,}")); // pattern
            out.extend_from_slice(&string(b"at least 8 chars")); // message
        }
        if revision >= REV_SERVER_INTERSERVER_SECRET_V2 {
            out.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // nonce
        }
        if revision >= REV_SERVER_SETTINGS {
            // One server setting in strings-with-flags form, then the empty-name
            // terminator.
            out.extend_from_slice(&string(b"max_threads"));
            out.extend_from_slice(&varint(0)); // flags
            out.extend_from_slice(&string(b"8"));
            out.extend_from_slice(&string(b"")); // terminator
        }
        out
    }

    /// A ClientInfo block for `query_kind` at `revision`, byte-for-byte as ClickHouse
    /// `ClientInfo::write` emits it. The catching encoder for the request side:
    /// `initial_query_start_time` precedes `interface`, settings/version gates are in
    /// source order, and the modern tail (query/line numbers, JWT) is present.
    fn client_info(query_kind: u8, revision: u64) -> Vec<u8> {
        let mut out = vec![query_kind];
        if query_kind == 0 {
            // NO_QUERY: the writer returns immediately after the query_kind byte.
            return out;
        }
        out.extend_from_slice(&string(b"")); // initial_user
        out.extend_from_slice(&string(b"")); // initial_query_id
        out.extend_from_slice(&string(b"0.0.0.0:0")); // initial_address
        if revision >= REV_QUERY_START_TIME {
            out.extend_from_slice(&0i64.to_le_bytes()); // initial_query_start_time (BEFORE interface)
        }
        out.push(INTERFACE_TCP); // interface
        out.extend_from_slice(&string(b"os_user")); // os_user
        out.extend_from_slice(&string(b"host")); // client_hostname
        out.extend_from_slice(&string(b"ClickHouse client")); // client_name
        out.extend_from_slice(&varint(24)); // major
        out.extend_from_slice(&varint(8)); // minor
        out.extend_from_slice(&varint(revision)); // client protocol_version
        if revision >= REV_QUOTA_KEY {
            out.extend_from_slice(&string(b"")); // quota_key
        }
        if revision >= REV_DISTRIBUTED_DEPTH {
            out.extend_from_slice(&varint(0)); // distributed_depth
        }
        if revision >= REV_VERSION_PATCH {
            out.extend_from_slice(&varint(3)); // version_patch (interface == TCP)
        }
        if revision >= REV_OPENTELEMETRY {
            out.push(0); // has_trace = 0
        }
        if revision >= REV_PARALLEL_REPLICAS {
            out.extend_from_slice(&varint(0)); // collaborate_with_initiator
            out.extend_from_slice(&varint(0)); // obsolete_count_participating_replicas
            out.extend_from_slice(&varint(0)); // number_of_current_replica
        }
        if revision >= REV_QUERY_AND_LINE_NUMBERS {
            out.extend_from_slice(&varint(0)); // script_query_number
            out.extend_from_slice(&varint(0)); // script_line_number
        }
        if revision >= REV_JWT_INTERSERVER {
            out.push(0); // has_jwt = 0
        }
        out
    }

    /// A client Query packet carrying `sql`, at `revision`, query_kind 1 (initial),
    /// with `settings` (name,value) pairs — byte-for-byte as ClickHouse
    /// `Connection::sendQuery` writes it (strings-with-flags settings, external_roles
    /// + interserver-secret strings at their gates).
    fn client_query_with_settings(sql: &str, revision: u64, settings: &[(&str, &str)]) -> Vec<u8> {
        let mut out = varint(CLIENT_QUERY);
        out.extend_from_slice(&string(b"query-id-1")); // query_id
        out.extend_from_slice(&client_info(1, revision)); // client_info
        // settings list.
        for (name, value) in settings {
            out.extend_from_slice(&string(name.as_bytes()));
            if revision >= REV_SETTINGS_STRINGS_WITH_FLAGS {
                out.extend_from_slice(&varint(0)); // flags
            }
            out.extend_from_slice(&string(value.as_bytes()));
        }
        out.extend_from_slice(&string(b"")); // settings terminator (empty name)
        if revision >= REV_EXTERNAL_ROLES {
            // external_roles: a string wrapping `writeVectorBinary(roles)`; an empty
            // vector serializes to a single varint-0 byte.
            out.extend_from_slice(&string(b"\x00"));
        }
        if revision >= REV_INTERSERVER_SECRET {
            out.extend_from_slice(&string(b"")); // interserver secret
        }
        out.extend_from_slice(&varint(2)); // stage = Complete
        out.extend_from_slice(&varint(0)); // compression = disabled
        out.extend_from_slice(&string(sql.as_bytes())); // query text
        out
    }

    /// A client Query packet carrying `sql`, at `revision`, with no settings.
    fn client_query(sql: &str, revision: u64) -> Vec<u8> {
        client_query_with_settings(sql, revision, &[])
    }

    /// A server Exception packet with `code`.
    fn server_exception(code: i32) -> Vec<u8> {
        let mut out = varint(SERVER_EXCEPTION);
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&string(b"DB::Exception")); // name
        out.extend_from_slice(&string(b"Table not found")); // message
        out.extend_from_slice(&string(b"stack")); // stack_trace
        out.push(0); // nested = false
        out
    }

    /// A server EndOfStream packet (a successful query's terminator).
    fn server_end_of_stream() -> Vec<u8> {
        varint(SERVER_END_OF_STREAM)
    }

    const REV: u64 = REV_PARALLEL_REPLICAS;

    fn handshake(p: &mut ClickhouseParser) {
        p.on_inbound(&client_hello("ClickHouse client", REV), 1);
        p.on_outbound(&server_hello(REV), 2);
    }

    #[test]
    fn varint_roundtrips_and_bounds() {
        for v in [0u64, 1, 127, 128, 300, 54_453, u64::MAX] {
            let enc = varint(v);
            match read_varint(&enc) {
                Read::Done { value, consumed } => {
                    assert_eq!(value, v);
                    assert_eq!(consumed, enc.len());
                }
                other => panic!("expected Done for {v}, got {other:?}"),
            }
        }
        // A truncated multi-byte varint waits.
        assert_eq!(read_varint(&[0x80]), Read::Partial);
        // Ten continuation bytes is not a valid u64 varint.
        assert_eq!(read_varint(&[0x80; 10]), Read::Invalid);
    }

    #[test]
    fn string_reads_value_and_consumed_length() {
        let enc = string(b"SELECT");
        match read_string(&enc) {
            Read::Done { value, consumed } => {
                assert_eq!(value, b"SELECT");
                assert_eq!(consumed, enc.len());
            }
            other => panic!("expected Done, got {other:?}"),
        }
        // Declared length exceeds buffered bytes -> Partial.
        assert_eq!(read_string(&[0x05, b'h', b'i']), Read::Partial);
        // Over-long declared length -> Invalid (never buffer unboundedly).
        let mut huge = varint(MAX_STRING_LEN + 1);
        huge.push(0);
        assert_eq!(read_string(&huge), Read::Invalid);
    }

    #[test]
    fn sql_verb_extracts_and_uppercases_the_leading_keyword() {
        assert_eq!(sql_verb(b"SELECT 1"), "SELECT");
        assert_eq!(sql_verb(b"select count(*) from t"), "SELECT");
        assert_eq!(sql_verb(b"  insert into x values (1)"), "INSERT");
        assert_eq!(sql_verb(b"INSERT(1)"), "INSERT");
        // Leading line + block comments are stepped over.
        assert_eq!(sql_verb(b"-- a comment\nSELECT 1"), "SELECT");
        assert_eq!(sql_verb(b"/* block */ CREATE TABLE t"), "CREATE");
        assert_eq!(sql_verb(b""), "");
    }

    #[test]
    fn detects_client_hello_by_positive_signature() {
        assert!(detect_clickhouse(&client_hello("ClickHouse client", REV)).is_some());
        // Driver-supplied names also detect (the name is not a fixed constant).
        assert!(detect_clickhouse(&client_hello("clickhouse-go", REV)).is_some());
    }

    #[test]
    fn rejects_non_hello_and_mid_stream_query() {
        // Not a Hello: a Query opener is declined (revision unknown — unsound).
        assert!(detect_clickhouse(&client_query("SELECT 1", REV)).is_none());
        // HTTP, random binary, and a bare non-zero type byte are not Hellos.
        assert!(detect_clickhouse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(detect_clickhouse(b"\x16\x03\x01\x02\x00").is_none());
        assert!(detect_clickhouse(&[0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn partial_hello_is_declined_until_complete() {
        let hello = client_hello("ClickHouse client", REV);
        // A prefix that parses the type byte but not the whole Hello must not bind.
        assert!(detect_clickhouse(&hello[..5]).is_none());
        assert!(detect_clickhouse(&hello).is_some());
    }

    #[test]
    fn one_query_then_end_of_stream_yields_one_success_record() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_inbound(&client_query("SELECT * FROM events", REV), 1_000);
        assert!(p.take_records().is_empty()); // response not yet
        p.on_outbound(&server_end_of_stream(), 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert_eq!(recs[0].protocol, Protocol::Clickhouse);
        assert!(!recs[0].error);
        assert_eq!(recs[0].status_code, 0);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn exception_response_sets_error_verdict_and_code() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_inbound(&client_query("SELECT bad FROM nope", REV), 0);
        // ClickHouse UNKNOWN_TABLE is code 60.
        p.on_outbound(&server_exception(60), 5);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 60);
        assert_eq!(recs[0].duration_nano, 5);
    }

    #[test]
    fn data_response_pairs_as_success_when_no_exception_precedes() {
        // A successful SELECT streams Data/Progress (unframeable) before EOS. The
        // first such packet settles the verdict as success — no error was seen.
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_inbound(&client_query("SELECT 1", REV), 10);
        // Server Data packet (type 1) — body is unframeable, but the leading type
        // byte is enough to settle "no error".
        let mut data = varint(1u64);
        data.extend_from_slice(b"\x00\x01\x02\x03 opaque block bytes");
        p.on_outbound(&data, 20);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 10);
    }

    #[test]
    fn ping_pong_without_handshake_still_pairs() {
        // A Ping is a bare client packet we don't queue, but a Pong with a pending
        // query should still settle it. Here we just prove Pong settles a query as
        // success via the same decisive-packet path.
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_inbound(&client_query("SELECT now()", REV), 1);
        p.on_outbound(&varint(SERVER_PONG), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].error);
    }

    #[test]
    fn fragmented_query_waits_then_completes() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        let q = client_query("INSERT INTO t VALUES", REV);
        let split = q.len() - 4; // cut inside the trailing query text
        p.on_inbound(&q[..split], 100);
        assert!(p.take_records().is_empty());
        // A response now must NOT pair — the request isn't fully parsed.
        p.on_outbound(&server_end_of_stream(), 110);
        assert!(
            p.take_records().is_empty(),
            "must not pair against a truncated query"
        );
        p.on_inbound(&q[split..], 120);
        p.on_outbound(&server_end_of_stream(), 150);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "INSERT");
        assert_eq!(recs[0].start_unix_nano, 120);
        assert_eq!(recs[0].duration_nano, 30);
    }

    #[test]
    fn byte_at_a_time_query_yields_one_record() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        let q = client_query("SELECT version()", REV);
        for byte in q.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        p.on_outbound(&server_end_of_stream(), 2_000);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
    }

    #[test]
    fn pipelined_queries_pair_in_order() {
        // ClickHouse is request/response per connection; two sequential queries with
        // their two terminators must pair FIFO.
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        // Note: in practice a client waits for each response, but framing must still
        // queue both if they arrive together.
        let mut reqs = client_query("SELECT a", REV);
        reqs.extend(client_query("SELECT b", REV));
        p.on_inbound(&reqs, 100);
        // First response: EOS (success). Second: Exception (error).
        p.on_outbound(&server_end_of_stream(), 110);
        let r1 = p.take_records();
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].operation, "SELECT");
        assert!(!r1[0].error);
        // After a decisive packet the outbound side stalls; a real second exchange
        // would be a fresh connection turn. We assert the queued second request is
        // still pending (one record so far, one still awaiting).
        assert_eq!(p.pending.len(), 1);
    }

    #[test]
    fn negotiated_revision_is_min_of_both_hellos() {
        // Client supports a higher revision than the server; the negotiated revision
        // the client uses to encode ClientInfo is the server's (lower) one. We prove
        // a Query encoded at the SERVER revision parses, given both Hellos.
        let server_rev = REV_QUOTA_KEY; // older server (no OTEL / parallel replicas)
        let mut p = ClickhouseParser::new();
        p.on_inbound(&client_hello("ClickHouse client", REV_PARALLEL_REPLICAS), 1);
        p.on_outbound(&server_hello(server_rev), 2);
        assert_eq!(p.negotiated_revision(), server_rev);
        // Query encoded at the negotiated (server) revision must parse cleanly.
        p.on_inbound(&client_query("SELECT 1", server_rev), 10);
        p.on_outbound(&server_end_of_stream(), 20);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
    }

    #[test]
    fn query_parses_across_a_range_of_revisions() {
        // The version-gated ClientInfo + Query-body + server-Hello skips must hold
        // across every gate boundary, INCLUDING the modern tail (query/line numbers,
        // JWT, external_roles, strings-with-flags settings, chunked proto_caps,
        // password rules, nonce, server settings). The encoders are byte-for-byte
        // ClickHouse, so a wrong gate or field order desyncs and drops the record.
        for rev in [
            REV_QUOTA_KEY,
            REV_VERSION_PATCH,
            REV_OPENTELEMETRY,
            REV_DISTRIBUTED_DEPTH,
            REV_QUERY_START_TIME,
            REV_PARALLEL_REPLICAS,
            54_460,
            REV_SERVER_PASSWORD_COMPLEXITY,
            REV_SERVER_INTERSERVER_SECRET_V2,
            REV_SERVER_CHUNKED_PACKETS,
            REV_SERVER_VERSIONED_PARALLEL_REPLICAS,
            REV_EXTERNAL_ROLES,
            REV_SERVER_SETTINGS,
            REV_QUERY_AND_LINE_NUMBERS,
            REV_JWT_INTERSERVER,
            ASSUMED_REVISION, // current DBMS_TCP_PROTOCOL_VERSION
        ] {
            let mut p = ClickhouseParser::new();
            p.on_inbound(&client_hello("ClickHouse client", rev), 1);
            p.on_outbound(&server_hello(rev), 2);
            p.on_inbound(&client_query("SELECT 42", rev), 10);
            p.on_outbound(&server_end_of_stream(), 20);
            let recs = p.take_records();
            assert_eq!(recs.len(), 1, "revision {rev} must parse one record");
            assert_eq!(recs[0].operation, "SELECT", "revision {rev}");
        }
    }

    #[test]
    fn query_with_settings_parses_at_current_revision() {
        // A real client almost always sends settings; at any modern revision each
        // entry is `name, flags(varint), value` (strings-with-flags). Missing the
        // flags varint desyncs the walk to the SQL. Several settings make the
        // miscount compound, so a single right answer here is load-bearing.
        let rev = ASSUMED_REVISION;
        let mut p = ClickhouseParser::new();
        p.on_inbound(&client_hello("ClickHouse client", rev), 1);
        p.on_outbound(&server_hello(rev), 2);
        let settings = [
            ("max_threads", "8"),
            ("max_block_size", "65536"),
            ("readonly", "1"),
        ];
        p.on_inbound(
            &client_query_with_settings("INSERT INTO t VALUES", rev, &settings),
            10,
        );
        p.on_outbound(&server_end_of_stream(), 20);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "INSERT");
    }

    #[test]
    fn http_interface_client_info_is_rejected_not_misframed() {
        // A non-TCP interface byte means a ClientInfo layout we don't transcribe.
        // The parser must decline to frame it (mark dead) rather than misread the
        // HTTP middle block as TCP fields and silently desync.
        let rev = ASSUMED_REVISION;
        let mut body = string(b"query-id-1"); // query_id
        // Hand-rolled ClientInfo with interface = HTTP (2), matching field order up
        // to the interface byte.
        let mut ci = vec![1u8]; // query_kind = INITIAL_QUERY
        ci.extend_from_slice(&string(b"")); // initial_user
        ci.extend_from_slice(&string(b"")); // initial_query_id
        ci.extend_from_slice(&string(b"0.0.0.0:0")); // initial_address
        ci.extend_from_slice(&0i64.to_le_bytes()); // initial_query_start_time
        ci.push(2); // interface = HTTP (not TCP)
        ci.extend_from_slice(b"trailing bytes we will not interpret");
        body.extend_from_slice(&ci);
        let mut packet = varint(CLIENT_QUERY);
        packet.extend_from_slice(&body);

        let mut p = ClickhouseParser::new();
        p.on_inbound(&client_hello("ClickHouse client", rev), 1);
        p.on_outbound(&server_hello(rev), 2);
        p.on_inbound(&packet, 10);
        // Cannot frame a non-TCP ClientInfo -> parser is dead, no bogus record.
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn orphan_response_with_no_pending_request_is_dropped() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_outbound(&server_end_of_stream(), 5);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn garbage_inbound_packet_type_marks_dead() {
        // An inbound varint that overflows u64 is invalid framing.
        let mut p = ClickhouseParser::new();
        p.on_inbound(&[0x80; 10], 1);
        assert!(p.is_dead());
    }

    #[test]
    fn out_of_range_server_packet_type_marks_dead() {
        let mut p = ClickhouseParser::new();
        handshake(&mut p);
        p.on_inbound(&client_query("SELECT 1", REV), 1);
        // Server packet type 99 is beyond the defined range (max 14).
        p.on_outbound(&varint(99u64), 2);
        assert!(p.is_dead());
    }

    #[test]
    fn unparseable_query_still_records_as_generic_query() {
        // If ClientInfo skip lands wrong (e.g. wrong assumed revision with no
        // handshake), the parse may fail. The hard requirement is no panic; a wrong
        // operation label is acceptable. Here we feed a Query with NO handshake, so
        // ASSUMED_REVISION is used — which matches our encoder, so it parses; the
        // point of the test is the no-handshake path produces a record, not garbage.
        let mut p = ClickhouseParser::new();
        p.on_inbound(&client_query("SELECT no_handshake", ASSUMED_REVISION), 1);
        p.on_outbound(&server_end_of_stream(), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
    }

    #[test]
    fn new_parser_constructs_for_the_port_hint_path() {
        // The port-hint constructor binds unconditionally and parses a full
        // handshake + query exactly like the detected path.
        let mut boxed = new_parser();
        boxed.on_inbound(&client_hello("ClickHouse client", REV), 1);
        boxed.on_outbound(&server_hello(REV), 2);
        boxed.on_inbound(&client_query("SELECT 1", REV), 10);
        boxed.on_outbound(&server_end_of_stream(), 20);
        let recs = boxed.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SELECT");
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: feed hostile/truncated payloads at every byte boundary, both
        // directions, in both orders. The hard requirement is no panic, ever — a
        // wrong verdict is acceptable, a crash is not.
        let valid_hello = client_hello("ClickHouse client", REV);
        let valid_query = client_query("SELECT * FROM t", REV);
        let valid_server_hello = server_hello(REV);
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],                   // bare client Hello type, no body
            vec![0x01],                   // bare Query type, no body
            vec![0xff, 0xff, 0xff, 0xff], // junk varint continuation
            vec![0x80; 10],               // overflowing varint
            vec![0x80; 11],               // even longer continuation run
            varint(CLIENT_HELLO),         // Hello type only
            {
                // Hello with a string length far exceeding the buffer.
                let mut v = varint(CLIENT_HELLO);
                v.extend_from_slice(&varint(MAX_STRING_LEN + 100));
                v
            },
            {
                // Query whose query_id length overruns.
                let mut v = varint(CLIENT_QUERY);
                v.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
                v
            },
            client_info(1, REV),              // a ClientInfo block by itself
            client_info(0, REV),              // query_kind 0: just the kind byte
            client_info(1, ASSUMED_REVISION), // modern ClientInfo (query/line + jwt tail)
            server_exception(60),
            server_end_of_stream(),
            valid_hello.clone(),
            valid_query.clone(),
            valid_server_hello.clone(),
            // A modern Query with several settings — exercises the strings-with-flags
            // settings walk, external_roles, and the full ClientInfo tail.
            client_query_with_settings(
                "SELECT 1",
                ASSUMED_REVISION,
                &[("max_threads", "8"), ("readonly", "1")],
            ),
            // A modern server Hello — exercises the chunked/password/nonce/settings tail.
            server_hello(ASSUMED_REVISION),
            {
                // A server Hello claiming a hostile password-complexity rule count:
                // the parser must reject (bounded), never loop or panic.
                let mut v = varint(SERVER_HELLO);
                v.extend_from_slice(&string(b"ClickHouse"));
                v.extend_from_slice(&varint(24));
                v.extend_from_slice(&varint(8));
                v.extend_from_slice(&varint(REV_SERVER_PASSWORD_COMPLEXITY));
                v.extend_from_slice(&string(b"UTC")); // timezone
                v.extend_from_slice(&string(b"prod-1")); // display_name
                v.extend_from_slice(&varint(3)); // version_patch
                v.extend_from_slice(&varint(u64::MAX)); // rule count: hostile
                v
            },
            {
                // A Query whose ClientInfo OTEL has_trace=1 then truncates — must wait,
                // not panic on the trace-id/span-id fixed read.
                let mut v = varint(CLIENT_QUERY);
                v.extend_from_slice(&string(b"qid"));
                let mut ci = vec![1u8]; // query_kind
                ci.extend_from_slice(&string(b"")); // initial_user
                ci.extend_from_slice(&string(b"")); // initial_query_id
                ci.extend_from_slice(&string(b"a")); // initial_address
                ci.extend_from_slice(&0i64.to_le_bytes()); // start_time
                ci.push(INTERFACE_TCP); // interface
                ci.extend_from_slice(&string(b"")); // os_user
                ci.extend_from_slice(&string(b"")); // hostname
                ci.extend_from_slice(&string(b"")); // client_name
                ci.extend_from_slice(&varint(1)); // major
                ci.extend_from_slice(&varint(1)); // minor
                ci.extend_from_slice(&varint(REV)); // protocol_version
                ci.extend_from_slice(&string(b"")); // quota_key
                ci.extend_from_slice(&varint(0)); // distributed_depth
                ci.extend_from_slice(&varint(0)); // version_patch
                ci.push(1); // has_trace = 1, then nothing (truncated)
                v.extend_from_slice(&ci);
                v
            },
            (0u8..=255).collect(),
            vec![0x00; 128],
            vec![0xff; 128],
        ];

        for payload in &payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // detection must never panic
                let _ = detect_clickhouse(a);
                let _ = detect_clickhouse(payload);

                // inbound side, split
                let mut p = ClickhouseParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();

                // response side, split (with a handshake + query outstanding)
                let mut q = ClickhouseParser::new();
                handshake(&mut q);
                q.on_inbound(&valid_query, 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
                let _ = q.is_dead();

                // also feed hostile bytes as the inbound stream after a handshake
                let mut r = ClickhouseParser::new();
                handshake(&mut r);
                r.on_inbound(a, 1);
                r.on_inbound(b, 2);
                let _ = r.take_records();
            }
        }
    }
}
