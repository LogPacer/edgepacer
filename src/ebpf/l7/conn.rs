//! Per-connection stream reassembly. The kernel delivers captured bytes as
//! arbitrary segments (one per `read`/`write`), so a single request or response
//! can span several segments and several can share one. This layer keys state by
//! `(pid, fd)`, reassembles each direction's byte stream, detects the protocol
//! once, and drives the per-protocol parser — advancing past each message
//! (head + Content-Length body) so pipelined messages on a kept-alive connection
//! parse cleanly.
//!
//! Pure userspace + unit-tested with synthetic segments; the read-side BPF
//! capture that produces real [`CapturedSegment`]s is a follow-on slice.

use std::collections::HashMap;

use super::{Direction, L7Parser, L7Record};
use super::{
    amqp, amqp1, cassandra, clickhouse, dns, http1, http2, kafka, memcached, mongodb, mqtt, mysql,
    nats, postgres, pulsar, redis, smtp, tds,
};

/// Longest `"METHOD "` token (`"CONNECT "`). Until the inbound buffer holds this
/// many bytes we can't yet rule out an HTTP request, so detection waits.
const MAX_METHOD_PREFIX: usize = 8;

/// Cap on concurrently tracked connections — a guard against cardinality blow-up
/// from connection-per-request clients or scanners. Beyond it, new connections
/// are dropped (counted), never the kernel ring. Real LRU eviction is a refinement.
const MAX_TRACKED_CONNS: usize = 16_384;

/// One captured socket segment — the read-side BPF capture (a follow-on slice)
/// produces these: a slice of bytes seen on `fd`, tagged with its direction.
#[derive(Debug, Clone)]
pub struct CapturedSegment {
    pub pid: u32,
    /// The capturing task's v2 cgroup id — the container/service identity key.
    pub cgroup_id: u64,
    pub fd: u32,
    pub direction: Direction,
    /// When the segment was observed in userspace (unix nanos) — the timing source
    /// for span start + duration until the kernel stamps ktime (a refinement).
    pub timestamp_nano: i64,
    pub bytes: Vec<u8>,
}

/// Outcome of trying to identify a connection's protocol from its inbound prefix.
enum Detect {
    /// Recognised — bind this parser and replay the buffered bytes into it.
    Parser(Box<dyn L7Parser>),
    /// Enough bytes seen without a match — not a supported protocol; drop it.
    Unknown,
    /// Inconclusive so far — wait for more inbound bytes.
    NeedMore,
}

/// Construct a parser for a protocol named by a port hint, bypassing byte
/// detection — the port already identifies it (e.g. 5432 ⇒ PostgreSQL), which the
/// binary parsers' deliberately conservative byte signatures would often miss.
/// Keys match the `l7/<key>.rs` module names (see `socket_port::PortHint`).
fn parser_for_protocol(key: &str) -> Option<Box<dyn L7Parser>> {
    Some(match key {
        "postgres" => Box::new(postgres::PostgresParser::default()),
        "mysql" => Box::new(mysql::MysqlParser::default()),
        "mongodb" => Box::new(mongodb::MongoParser::default()),
        "kafka" => Box::new(kafka::KafkaParser::default()),
        "cassandra" => Box::new(cassandra::CassandraParser::default()),
        "redis" => Box::new(redis::RedisParser::default()),
        "amqp" => Box::new(amqp::AmqpParser::default()),
        "memcached" => Box::new(memcached::MemcachedParser::default()),
        // Long-tail (wave 3) — `new_parser()` already returns the boxed parser.
        "mqtt" => mqtt::new_parser(),
        "tds" => tds::new_parser(),
        "pulsar" => pulsar::new_parser(),
        "clickhouse" => clickhouse::new_parser(),
        "smtp" => smtp::new_parser(),
        _ => return None,
    })
}

/// Identify the protocol from a connection's inbound prefix. Each supported
/// protocol contributes one positive signature; add a branch per new protocol.
///
/// Ordering is load-bearing and sorted by signature SPECIFICITY: an unambiguous
/// magic-number signature must run before a weaker one it could otherwise shadow,
/// and no detector may false-positive on another's real traffic.
///
///  1. **HTTP/1** — the most common, text-prefix signature.
///  2. **HTTP/2** — its 24-byte client preface (`"PRI * HTTP/2.0…"`) shares the
///     `PRI ` prefix with no HTTP/1 method, so it can't be confused with HTTP/1,
///     but it is longer than `MAX_METHOD_PREFIX` (8). It MUST be checked before
///     the 8-byte `Unknown` cutoff: while the preface is still arriving we return
///     `NeedMore`, else the cutoff would kill HTTP/2 before its preface completes.
///  3. **AMQP** — the `"AMQP\x00\x00\x09\x01"` protocol header is an unambiguous
///     magic; the method-frame fallback demands a known class id + the `0xCE`
///     frame-end. The strongest binary signature here, so it runs first.
///  4. **Cassandra** — request-version byte (`0x04`/`0x05`) + a known client
///     opcode + a sane frame length: a tight conjunction that won't fire on the
///     other binary openers.
///  5. **NATS** — an exact client verb (`CONNECT`/`PUB`/`SUB`/…) plus its required
///     delimiter. Text, so it can't collide with the binary signatures; checked
///     here (after HTTP/1, which legitimately owns the shared `CONNECT ` opener).
///  6. **Binary protocols** (redis/postgres/mysql) — positive byte signatures,
///     specific enough not to collide with HTTP/1 text or the above.
///  7. **MongoDB** — full 16-byte header, request `opCode` (2013/2004),
///     `responseTo == 0`, and a body that parses to a command label. Fairly
///     specific, but weaker than the magic-number protocols, so it runs after the
///     established binary block.
///  8. **DNS** — datagram-oriented; a positive query-shaped signature.
///  9. **Kafka** — bare big-endian integers, no magic. The signature conjunction
///     of a sane size, a small apiKey, a small apiVersion, and a sane clientId
///     length is the only guard, so it is among the most ambiguous: checked late.
///  10. **Memcached** — `0x80` binary magic or a text verb. Its text `get ` opener
///      overlaps HTTP `GET ` (HTTP/1 above already claims it), and the binary path
///      is a single magic byte + self-consistency, so it runs last of the parsers.
///  11. **Fallback** — once `MAX_METHOD_PREFIX` bytes are seen with no match, the
///      connection is `Unknown`; otherwise `NeedMore`.
fn detect(inbound: &[u8], protocol_hint: Option<&str>) -> Detect {
    // A port hint names the protocol up front (binary DB/cache parsers detect only
    // weakly from bytes) — bind it directly, skipping the byte sniffing below.
    if let Some(parser) = protocol_hint.and_then(parser_for_protocol) {
        return Detect::Parser(parser);
    }

    if http1::looks_like_request(inbound) {
        return Detect::Parser(Box::new(http1::Http1Parser::new()));
    }

    // HTTP/2: wait for the full 24-byte preface before deciding. This branch must
    // precede the `MAX_METHOD_PREFIX` cutoff below, or a partial preface (> 8
    // bytes, not yet 24) would be ruled Unknown and the connection dropped.
    if http2::looks_like_preface_prefix(inbound) {
        return Detect::NeedMore;
    }
    if let Some(parser) = http2::detect_http2(inbound) {
        return Detect::Parser(parser);
    }

    // Unambiguous magic-number signatures first — AMQP's header / known-class frame
    // and Cassandra's version+opcode+length conjunction can't be confused with the
    // weaker binary openers below.
    if let Some(parser) = amqp::detect_amqp(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = cassandra::detect_cassandra(inbound) {
        return Detect::Parser(parser);
    }

    // NATS — a text verb + its required delimiter. Binary detectors can't shadow it
    // and it can't shadow them; the one byte-only overlap (`CONNECT `) is owned by
    // HTTP/1 above.
    if let Some(parser) = nats::detect_nats(inbound) {
        return Detect::Parser(parser);
    }

    // Established binary protocols — positive signatures. See each `detect_*` for the
    // (weak, byte-only) signature and the port-hint follow-up it would benefit from.
    if let Some(parser) = redis::detect_redis(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = postgres::detect_postgres(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = mysql::detect_mysql(inbound) {
        return Detect::Parser(parser);
    }

    // MongoDB — fairly specific (request op-code + responseTo==0 + parseable body),
    // but no magic number, so it runs after the established binary block.
    if let Some(parser) = mongodb::detect_mongodb(inbound) {
        return Detect::Parser(parser);
    }

    // DNS — datagram-oriented; a query-shaped first datagram.
    if let Some(parser) = dns::detect_dns(inbound) {
        return Detect::Parser(parser);
    }

    // Long-tail (wave 3): AMQP 1.0's `"AMQP\x00\x01\x00\x00"` magic, SMTP text verbs,
    // MQTT's CONNECT name + typed header, TDS's 8-byte typed header, and Pulsar's
    // size+protobuf framing — each a positive signature specific enough not to
    // shadow (or be shadowed by) the protocols above. ClickHouse is port-hint-only
    // (its native protocol is undocumented; a byte signature would risk false
    // positives), so it is bound via `parser_for_protocol`, not here.
    if let Some(parser) = amqp1::detect_amqp1(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = smtp::detect_smtp(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = mqtt::detect_mqtt(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = tds::detect_tds(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = pulsar::detect_pulsar(inbound) {
        return Detect::Parser(parser);
    }

    // Most ambiguous binary signatures last — Kafka (bare big-endian ints) and
    // Memcached (single magic byte / `get `-overlapping text verbs) are the weakest
    // sniffs, so they run only after every more-specific detector has declined.
    if let Some(parser) = kafka::detect_kafka(inbound) {
        return Detect::Parser(parser);
    }
    if let Some(parser) = memcached::detect_memcached(inbound) {
        return Detect::Parser(parser);
    }

    if inbound.len() >= MAX_METHOD_PREFIX {
        Detect::Unknown
    } else {
        Detect::NeedMore
    }
}

/// True if the bytes begin a fresh request for any supported protocol — used to
/// restart a dead connection whose fd was reused (see [`ConnTracker::on_segment`]).
/// Each arm is the same positive signature `detect` keys on; HTTP/2 uses the full
/// 24-byte preface (a partial preface isn't yet a complete fresh-request signal).
fn looks_like_any_request(bytes: &[u8]) -> bool {
    http1::looks_like_request(bytes)
        || redis::looks_like_request(bytes)
        || nats::looks_like_request(bytes)
        || http2::detect_http2(bytes).is_some()
        || postgres::detect_postgres(bytes).is_some()
        || mysql::detect_mysql(bytes).is_some()
        || amqp::detect_amqp(bytes).is_some()
        || cassandra::detect_cassandra(bytes).is_some()
        || mongodb::detect_mongodb(bytes).is_some()
        || dns::detect_dns(bytes).is_some()
        || kafka::detect_kafka(bytes).is_some()
        || memcached::detect_memcached(bytes).is_some()
        || amqp1::detect_amqp1(bytes).is_some()
        || smtp::detect_smtp(bytes).is_some()
        || mqtt::detect_mqtt(bytes).is_some()
        || tds::detect_tds(bytes).is_some()
        || pulsar::detect_pulsar(bytes).is_some()
}

/// State for one `(pid, fd)` connection: buffers the inbound prefix until the
/// protocol is recognised, then delegates each direction to the bound parser.
#[derive(Debug, Default)]
struct ConnTracker {
    /// Bound once the protocol is detected; `None` while still buffering the prefix.
    parser: Option<Box<dyn L7Parser>>,
    /// Unknown protocol or a parse error — ignore all further bytes.
    dead: bool,
    /// Bytes seen before detection, replayed into the parser once it binds.
    pre_inbound: Vec<u8>,
    pre_outbound: Vec<u8>,
}

impl ConnTracker {
    fn on_segment(
        &mut self,
        dir: Direction,
        bytes: &[u8],
        ts: i64,
        protocol_hint: Option<&str>,
        flip: bool,
    ) {
        // When the monitored process is the client of a known service (a remote
        // protocol port), its writes are the requests — flip so the parser still
        // sees inbound = request, outbound = response.
        let dir = if flip { dir.opposite() } else { dir };

        if self.dead {
            // fd reuse / mid-stream resync: a fresh inbound request on a dead
            // connection restarts it. The prior stream killed it — e.g. a file
            // closed on the same fd, then reopened as a socket, or corrupt bytes.
            // Eviction on close(2) is the cleaner fix and a planned refinement.
            if dir == Direction::Inbound && looks_like_any_request(bytes) {
                *self = ConnTracker::default();
            } else {
                return;
            }
        }

        if let Some(parser) = self.parser.as_mut() {
            match dir {
                Direction::Inbound => parser.on_inbound(bytes, ts),
                Direction::Outbound => parser.on_outbound(bytes, ts),
            }
            if parser.is_dead() {
                self.kill();
            }
            return;
        }

        // Pre-detection: buffer each direction, then try to recognise the protocol
        // from the inbound prefix.
        match dir {
            Direction::Inbound => self.pre_inbound.extend_from_slice(bytes),
            Direction::Outbound => self.pre_outbound.extend_from_slice(bytes),
        }
        match detect(&self.pre_inbound, protocol_hint) {
            Detect::Parser(mut parser) => {
                let inbound = std::mem::take(&mut self.pre_inbound);
                let outbound = std::mem::take(&mut self.pre_outbound);
                parser.on_inbound(&inbound, ts);
                parser.on_outbound(&outbound, ts);
                if parser.is_dead() {
                    self.kill();
                } else {
                    self.parser = Some(parser);
                }
            }
            Detect::Unknown => self.kill(),
            Detect::NeedMore => {}
        }
    }

    fn kill(&mut self) {
        self.dead = true;
        self.parser = None;
        self.pre_inbound = Vec::new();
        self.pre_outbound = Vec::new();
    }

    fn take_records(&mut self) -> Vec<L7Record> {
        self.parser
            .as_mut()
            .map(|p| p.take_records())
            .unwrap_or_default()
    }
}

/// Registry of live connections, keyed `(pid, fd)`. Feed it captured segments;
/// it returns the request/response records each segment completes.
#[derive(Debug, Default)]
pub struct ConnRegistry {
    conns: HashMap<(u32, u32), ConnTracker>,
    dropped_conns: u64,
}

impl ConnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one captured segment (no port hint — byte detection only); returns any
    /// records it completed.
    pub fn on_segment(&mut self, seg: &CapturedSegment) -> Vec<L7Record> {
        self.on_segment_hinted(seg, None, false)
    }

    /// Feed one captured segment with a port-derived protocol hint: `protocol_hint`
    /// binds that parser directly (the port names it, vs the binary parsers' weak
    /// byte signatures), and `flip` swaps request/response sense for a client-side
    /// connection (its writes are requests).
    pub fn on_segment_hinted(
        &mut self,
        seg: &CapturedSegment,
        protocol_hint: Option<&str>,
        flip: bool,
    ) -> Vec<L7Record> {
        let key = (seg.pid, seg.fd);
        if !self.conns.contains_key(&key) && self.conns.len() >= MAX_TRACKED_CONNS {
            self.dropped_conns += 1;
            return Vec::new();
        }
        let tracker = self.conns.entry(key).or_default();
        tracker.on_segment(
            seg.direction,
            &seg.bytes,
            seg.timestamp_nano,
            protocol_hint,
            flip,
        );
        tracker.take_records()
    }

    /// Evict a connection (called on `close(2)` in the real wiring, and on a
    /// fatal parse error so the slot frees immediately).
    pub fn on_close(&mut self, pid: u32, fd: u32) {
        self.conns.remove(&(pid, fd));
    }

    pub fn tracked(&self) -> usize {
        self.conns.len()
    }

    pub fn dropped_conns(&self) -> u64 {
        self.dropped_conns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(pid: u32, fd: u32, direction: Direction, bytes: &[u8]) -> CapturedSegment {
        CapturedSegment {
            pid,
            cgroup_id: 0,
            fd,
            direction,
            timestamp_nano: 0,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn port_hint_binds_a_parser_and_flips_client_direction() {
        let mut reg = ConnRegistry::new();
        // A Redis CLIENT WRITES the command (raw outbound) and READS the reply (raw
        // inbound). With the "redis" hint + flip, the command is parsed as the
        // request even though detection is hint-driven and the raw direction is
        // outbound — proving both port-hint binding and the client direction flip.
        assert!(
            reg.on_segment_hinted(
                &seg(7, 3, Direction::Outbound, b"*1\r\n$4\r\nPING\r\n"),
                Some("redis"),
                true,
            )
            .is_empty()
        );
        let r = reg.on_segment_hinted(
            &seg(7, 3, Direction::Inbound, b"+PONG\r\n"),
            Some("redis"),
            true,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].operation, "PING");
    }

    #[test]
    fn record_carries_request_to_response_latency() {
        let mut reg = ConnRegistry::new();
        let mut req = seg(1, 9, Direction::Inbound, b"GET /t HTTP/1.1\r\n\r\n");
        req.timestamp_nano = 1_000;
        let mut resp = seg(1, 9, Direction::Outbound, b"HTTP/1.1 200 OK\r\n\r\n");
        resp.timestamp_nano = 3_500;
        assert!(reg.on_segment(&req).is_empty());
        let r = reg.on_segment(&resp);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].start_unix_nano, 1_000);
        assert_eq!(r[0].duration_nano, 2_500);
    }

    #[test]
    fn one_request_response_yields_one_record() {
        let mut reg = ConnRegistry::new();
        let r1 = reg.on_segment(&seg(
            1,
            9,
            Direction::Inbound,
            b"GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n",
        ));
        assert!(r1.is_empty()); // request seen, response not yet
        let r2 = reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ));
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].operation, "GET /api/users");
        assert_eq!(r2[0].status_code, 200);
        assert!(!r2[0].error);
    }

    #[test]
    fn request_head_split_across_segments_reassembles() {
        let mut reg = ConnRegistry::new();
        assert!(
            reg.on_segment(&seg(1, 9, Direction::Inbound, b"GET /a HTTP/1.1\r\nHo"))
                .is_empty()
        );
        assert!(
            reg.on_segment(&seg(1, 9, Direction::Inbound, b"st: x\r\n\r\n"))
                .is_empty()
        );
        let r = reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"HTTP/1.1 204 No Content\r\n\r\n",
        ));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].operation, "GET /a");
        assert_eq!(r[0].status_code, 204);
    }

    #[test]
    fn post_body_is_skipped_then_pipelined_request_parses() {
        let mut reg = ConnRegistry::new();
        // POST with a 5-byte body, immediately followed (pipelined) by a GET.
        reg.on_segment(&seg(
            1,
            9,
            Direction::Inbound,
            b"POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\n\r\n",
        ));
        // Two responses come back in order.
        let mut recs = Vec::new();
        recs.extend(reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
        )));
        recs.extend(reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )));
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "POST /submit");
        assert_eq!(recs[0].status_code, 201);
        assert_eq!(recs[1].operation, "GET /next");
        assert_eq!(recs[1].status_code, 200);
    }

    #[test]
    fn response_body_split_across_segments_is_skipped() {
        let mut reg = ConnRegistry::new();
        reg.on_segment(&seg(1, 9, Direction::Inbound, b"GET /x HTTP/1.1\r\n\r\n"));
        // Response head + start of a 10-byte body in one segment, rest in the next.
        let r1 = reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nHELLO",
        ));
        assert_eq!(r1.len(), 1); // status known once the head parsed
        assert_eq!(r1[0].status_code, 200);
        // Tail of the body + a second pipelined request/response round-trips cleanly.
        reg.on_segment(&seg(1, 9, Direction::Inbound, b"GET /y HTTP/1.1\r\n\r\n"));
        let r2 = reg.on_segment(&seg(
            1,
            9,
            Direction::Outbound,
            b"WORLDHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ));
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].operation, "GET /y");
    }

    #[test]
    fn unknown_protocol_is_dropped_and_stays_dead() {
        let mut reg = ConnRegistry::new();
        let r = reg.on_segment(&seg(
            1,
            9,
            Direction::Inbound,
            b"\x12\x34\x56\x78\x9a\xbc\xde\xf0 binary",
        ));
        assert!(r.is_empty());
        // Further bytes (even valid HTTP) on a dead connection produce nothing.
        let r2 = reg.on_segment(&seg(1, 9, Direction::Outbound, b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(r2.is_empty());
    }

    #[test]
    fn short_non_matching_prefix_waits_before_deciding() {
        let mut reg = ConnRegistry::new();
        // "GE" is a proper prefix of "GET " — don't decide Unknown yet.
        assert!(
            reg.on_segment(&seg(1, 9, Direction::Inbound, b"GE"))
                .is_empty()
        );
        assert!(
            reg.on_segment(&seg(1, 9, Direction::Inbound, b"T /a HTTP/1.1\r\n\r\n"))
                .is_empty()
        );
        let r = reg.on_segment(&seg(1, 9, Direction::Outbound, b"HTTP/1.1 200 OK\r\n\r\n"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].operation, "GET /a");
    }

    #[test]
    fn distinct_connections_are_isolated() {
        let mut reg = ConnRegistry::new();
        reg.on_segment(&seg(1, 9, Direction::Inbound, b"GET /a HTTP/1.1\r\n\r\n"));
        reg.on_segment(&seg(2, 9, Direction::Inbound, b"GET /b HTTP/1.1\r\n\r\n")); // same fd, different pid
        let ra = reg.on_segment(&seg(1, 9, Direction::Outbound, b"HTTP/1.1 200 OK\r\n\r\n"));
        let rb = reg.on_segment(&seg(2, 9, Direction::Outbound, b"HTTP/1.1 500 Err\r\n\r\n"));
        assert_eq!(ra[0].operation, "GET /a");
        assert_eq!(rb[0].operation, "GET /b");
        assert!(rb[0].error);
        assert_eq!(reg.tracked(), 2);
    }

    #[test]
    fn dead_connection_restarts_on_a_fresh_request() {
        let mut reg = ConnRegistry::new();
        // Garbage inbound (e.g. a file read on an fd later reused as a socket)
        // kills the connection.
        assert!(
            reg.on_segment(&seg(
                1,
                9,
                Direction::Inbound,
                b"\xde\xad\xbe\xef binary noise"
            ))
            .is_empty()
        );
        // A fresh HTTP request on the same (reused) fd restarts it.
        assert!(
            reg.on_segment(&seg(
                1,
                9,
                Direction::Inbound,
                b"GET /after HTTP/1.1\r\n\r\n"
            ))
            .is_empty()
        );
        let r = reg.on_segment(&seg(1, 9, Direction::Outbound, b"HTTP/1.1 200 OK\r\n\r\n"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].operation, "GET /after");
    }

    #[test]
    fn close_evicts_the_connection() {
        let mut reg = ConnRegistry::new();
        reg.on_segment(&seg(1, 9, Direction::Inbound, b"GET /a HTTP/1.1\r\n\r\n"));
        assert_eq!(reg.tracked(), 1);
        reg.on_close(1, 9);
        assert_eq!(reg.tracked(), 0);
    }

    /// `Detect::Parser` if these inbound bytes bind a parser, else not. Used by the
    /// integration-ordering tests below to assert which detectors do (and, just as
    /// importantly, do not) claim a given opener.
    fn binds(inbound: &[u8]) -> bool {
        matches!(detect(inbound, None), Detect::Parser(_))
    }

    /// A NATS client verb emits a record on inbound alone (`ClientOp`), so a single
    /// inbound segment proves the connection bound to NATS and stamped its own
    /// protocol — the integration wiring for a detector that runs *before* the
    /// established binary block.
    #[test]
    fn nats_opener_binds_and_stamps_its_own_protocol() {
        let mut reg = ConnRegistry::new();
        let r = reg.on_segment(&seg(1, 9, Direction::Inbound, b"SUB foo 1\r\n"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].protocol, super::super::Protocol::Nats);
    }

    /// An AMQP METHOD frame emits a record on inbound alone, proving the AMQP
    /// detector (the strongest binary signature, run first) binds and stamps
    /// `Protocol::Amqp`. Frame: `[0x01][channel:2][size:4][class:2][method:2][0xCE]`,
    /// class 60 / method 40 = `Basic.Publish`.
    #[test]
    fn amqp_method_frame_binds_and_stamps_its_own_protocol() {
        let frame = {
            let mut payload = Vec::new();
            payload.extend_from_slice(&60u16.to_be_bytes()); // class
            payload.extend_from_slice(&40u16.to_be_bytes()); // method
            let mut v = vec![1u8]; // FRAME_METHOD
            v.extend_from_slice(&0u16.to_be_bytes()); // channel
            v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            v.extend_from_slice(&payload);
            v.push(0xCE); // FRAME_END
            v
        };
        let mut reg = ConnRegistry::new();
        let r = reg.on_segment(&seg(1, 9, Direction::Inbound, &frame));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].protocol, super::super::Protocol::Amqp);
        assert_eq!(r[0].operation, "Basic.Publish");
    }

    /// The load-bearing ordering guarantee: the detectors that run *before* the
    /// established binary block (AMQP, Cassandra, NATS) must not claim the existing
    /// protocols' real openers, and the ambiguous late detectors (Kafka, Memcached)
    /// must not shadow earlier ones. We assert positively (each opener still binds)
    /// and rely on the per-protocol record protocol (above + each module's tests)
    /// for the "binds to the *right* parser" half.
    #[test]
    fn existing_protocol_openers_are_not_shadowed_by_new_detectors() {
        // HTTP/1 — still owns the shared `CONNECT ` and `GET ` openers.
        assert!(binds(b"GET /a HTTP/1.1\r\n\r\n"));
        assert!(binds(b"CONNECT host:443 HTTP/1.1\r\n\r\n"));
        // None of the new specific detectors claims an HTTP request.
        assert!(amqp::detect_amqp(b"GET /a HTTP/1.1\r\n\r\n").is_none());
        assert!(cassandra::detect_cassandra(b"GET /a HTTP/1.1\r\n\r\n").is_none());
        assert!(nats::detect_nats(b"GET /a HTTP/1.1\r\n\r\n").is_none());

        // Redis RESP opener — claimed by redis, not by the new detectors.
        let redis_open = b"*1\r\n$4\r\nPING\r\n";
        assert!(binds(redis_open));
        assert!(amqp::detect_amqp(redis_open).is_none());
        assert!(cassandra::detect_cassandra(redis_open).is_none());
        assert!(nats::detect_nats(redis_open).is_none());
        assert!(kafka::detect_kafka(redis_open).is_none());
        assert!(memcached::detect_memcached(redis_open).is_none());

        // Postgres StartupMessage `[len:4][196608][user\0postgres\0\0]`. Its loose
        // big-endian shape can satisfy Kafka's conjunction, so Kafka MUST run after
        // postgres in `detect` — assert postgres claims it and that the registry
        // does too (i.e. postgres wins the ordering, not Kafka).
        let pg_startup = {
            let params: &[u8] = b"user\0postgres\0\0";
            let len = (4 + 4 + params.len()) as u32;
            let mut v = len.to_be_bytes().to_vec();
            v.extend_from_slice(&196_608u32.to_be_bytes());
            v.extend_from_slice(params);
            v
        };
        assert!(postgres::detect_postgres(&pg_startup).is_some());
        assert!(binds(&pg_startup));
    }
}
