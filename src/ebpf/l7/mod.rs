//! L7 protocol parsing — userspace reconstruction of request/response pairs from
//! captured socket bytes. This is the producer of `RequestSignal` spans + RED
//! metrics: the zero-code APM wedge (Pixie/Beyla/Coroot class). The kernel side
//! stays a dumb byte tap; all protocol parsing happens here in userspace.
//! See `docs/parity/ebpf-apm-roadmap.md` (GAP 2).
//!
//! This slice lands protocol detection + the HTTP/1.1 parser, fully unit-tested
//! on every platform via `cargo test`. The read-side BPF capture, per-connection
//! stream reassembly (`ConnRegistry`), and the `RequestSignal` / RED emission are
//! follow-on slices that wire this core into `capture.rs` / `runner.rs`.

mod amqp;
mod amqp1;
mod cassandra;
mod clickhouse;
mod conn;
mod dns;
mod http1;
mod http2;
mod kafka;
mod memcached;
mod mongodb;
mod mqtt;
mod mysql;
mod nats;
mod postgres;
mod pulsar;
mod red;
mod redis;
mod smtp;
mod span;
mod tds;

#[cfg(test)]
mod exports_demo;

pub(crate) use conn::CapturedConnectionIdentity;
pub use conn::{CapturedSegment, ConnRegistry};
pub use red::RedAggregator;
pub use span::{SpanContext, mint_id, to_request_signal};

/// Direction of a captured socket segment, from the monitored server's view:
/// `Inbound` = bytes it read (requests), `Outbound` = bytes it wrote (responses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    /// The other direction — flips request/response sense for a connection whose
    /// monitored process is the client (its writes are the requests).
    pub(crate) fn opposite(self) -> Direction {
        match self {
            Direction::Inbound => Direction::Outbound,
            Direction::Outbound => Direction::Inbound,
        }
    }
}

/// The wire protocol carried by a connection, decided once from its first bytes
/// and cached for the connection's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
    Redis,
    Dns,
    Postgres,
    Mysql,
    Mongodb,
    Kafka,
    Cassandra,
    Nats,
    Amqp,
    Memcached,
    Smtp,
    Mqtt,
    Pulsar,
    Clickhouse,
    Tds,
    Amqp1,
    Unknown,
}

impl Protocol {
    /// The protocol's wire name — the `protocol` span attribute and the
    /// service-map edge's protocol label.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Protocol::Http1 => "http",
            Protocol::Http2 => "http2",
            Protocol::Redis => "redis",
            Protocol::Dns => "dns",
            Protocol::Postgres => "postgres",
            Protocol::Mysql => "mysql",
            Protocol::Mongodb => "mongodb",
            Protocol::Kafka => "kafka",
            Protocol::Cassandra => "cassandra",
            Protocol::Nats => "nats",
            Protocol::Amqp => "amqp",
            Protocol::Memcached => "memcached",
            Protocol::Smtp => "smtp",
            Protocol::Mqtt => "mqtt",
            Protocol::Pulsar => "pulsar",
            Protocol::Clickhouse => "clickhouse",
            Protocol::Tds => "tds",
            Protocol::Amqp1 => "amqp1",
            Protocol::Unknown => "unknown",
        }
    }
}

/// One reconstructed request/response pair — the protocol-agnostic record the
/// span + RED layers consume. `operation` is the call label (e.g.
/// `"GET /api/users"`); `error` is the protocol's failure verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7Record {
    pub protocol: Protocol,
    pub operation: String,
    pub status_code: u16,
    pub error: bool,
    /// When the request was received (unix nanos). The span's start time.
    pub start_unix_nano: i64,
    /// Server latency: response-observed minus request-observed (unix-nano diff).
    /// Approximate (segment arrival times, not kernel ktime) — a refinement.
    pub duration_nano: i64,
    /// Protocol-specific span enrichment (e.g. HTTP `host`, `llm.model`) merged
    /// into the exported `RequestSignal.attributes`. Empty for parsers that encode
    /// everything in `operation`.
    pub attributes: Vec<(String, String)>,
}

/// Per-direction reassembly buffer: captured bytes plus how many body bytes still
/// need to be dropped before the next message head can be parsed. A shared
/// reassembly primitive for the framed parsers (HTTP/1 Content-Length bodies,
/// length-prefixed binary protocols, …).
#[derive(Debug, Default)]
pub(crate) struct DirBuf {
    pub buf: Vec<u8>,
    pub skip: usize,
}

impl DirBuf {
    /// Drop a fully-framed message of `total_len` bytes. If its body isn't all
    /// buffered yet, drop what's here and remember the rest to skip as it arrives.
    pub fn advance(&mut self, total_len: usize) {
        if total_len <= self.buf.len() {
            self.buf.drain(0..total_len);
        } else {
            self.skip = total_len - self.buf.len();
            self.buf.clear();
        }
    }

    /// Consume any pending body skip against buffered bytes. Returns true once the
    /// skip is satisfied (ready to parse a head), false if more bytes are needed.
    pub fn drain_skip(&mut self) -> bool {
        if self.skip == 0 {
            return true;
        }
        let n = self.skip.min(self.buf.len());
        self.buf.drain(0..n);
        self.skip -= n;
        self.skip == 0
    }
}

/// A wire-protocol parser bound to one connection: fed each direction's captured
/// bytes with the observation time (unix nanos), it reassembles + pairs requests
/// with responses and yields [`L7Record`]s. One impl per supported protocol;
/// `detect` (in `conn`) binds one once a connection's protocol is recognised.
pub(crate) trait L7Parser: Send + std::fmt::Debug {
    /// Feed request-side bytes (the monitored server reads these).
    fn on_inbound(&mut self, bytes: &[u8], ts: i64);
    /// Feed response-side bytes (the monitored server writes these).
    fn on_outbound(&mut self, bytes: &[u8], ts: i64);
    /// Drain the records completed since the last call.
    fn take_records(&mut self) -> Vec<L7Record>;
    /// True once the stream is unrecoverable garbage — drop the connection.
    fn is_dead(&self) -> bool;
}
