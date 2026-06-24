//! MQTT 3.1.1 / 5.0 wire parser — implements [`super::L7Parser`], the zero-code
//! APM producer for MQTT connections (default broker port 1883, 8883 over TLS —
//! the TLS uprobe decrypts, so we parse the plaintext either way).
//!
//! ## Framing (hand-rolled — no dependency)
//!
//! Every control packet is `[byte0][Remaining Length][variable header + payload]`.
//! `byte0`'s high nibble is the packet TYPE, its low nibble the per-type FLAGS.
//! Remaining Length is a 1–4 byte big-endian-ish varint (7 bits/byte, top bit =
//! "more bytes follow"), counting only the bytes AFTER it — so a packet occupies
//! `1 + varint_len + remaining_length` bytes. That is the whole framing: a trivial
//! length-prefixed grammar, so a crate would only betray the leanness moat.
//!
//! ## What we extract (span fields only)
//!
//! MQTT is pub/sub — not strictly request/response — so, like NATS, we mostly emit
//! one record per CLIENT packet at the moment it frames, fire-and-forget. The two
//! exceptions pair with their server ack so the ack's failure verdict and the
//! round-trip latency land on the right record:
//!   * **CONNECT** (client) is held pending and completed by **CONNACK** (server),
//!     whose return code / reason code (≠ 0) is the error verdict. One CONNECT per
//!     connection, so it pairs as a singleton.
//!   * **SUBSCRIBE** (client) is held pending keyed by its packet id and completed
//!     by **SUBACK**, which errors if any per-topic return code is `0x80` (failure)
//!     or an MQTT5 reason code ≥ `0x80`.
//!   * **PUBLISH** (client → inbound) emits immediately, fire-and-forget
//!     (`duration_nano = 0`): QoS-0 has no ack and the QoS>0 PUBACK carries no
//!     useful verdict in 3.1.1. `operation = "PUBLISH <topic>"`.
//!   * **UNSUBSCRIBE / PINGREQ / DISCONNECT** (client) emit immediately as their
//!     bare type name.
//!   * A server → client **PUBLISH** (broker delivering to a subscriber, on the
//!     outbound side) is framed-and-skipped: it answers no client request, so it
//!     never mints or steals a record (the Redis-push / NATS-MSG lesson). Likewise
//!     PINGRESP, UNSUBACK, PUBACK/PUBREC/… are framed past.
//!
//! `operation = "<TYPE> <topic>"` for PUBLISH/SUBSCRIBE (the pub/sub subject), else
//! the bare packet-type name. The MQTT version (3.1.1 vs 5.0) learned from CONNECT's
//! protocol-level byte tells SUBSCRIBE framing whether a property block precedes the
//! topic filters; PUBLISH puts its topic first, so it needs no version knowledge.

use std::collections::VecDeque;

use super::{DirBuf, L7Parser, L7Record, Protocol};

/// Protocol tag stamped on every record this parser mints.
const PROTOCOL: Protocol = Protocol::Mqtt;

/// Packet types (the high nibble of `byte0`).
const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const UNSUBSCRIBE: u8 = 10;
const PINGREQ: u8 = 12;
const DISCONNECT: u8 = 14;

/// Largest legal Remaining Length: a 4-byte varint maxes at 268_435_455 (256 MB).
/// A stream claiming more than this in one packet has desynced or was mis-detected
/// — bail rather than buffer forever.
const MAX_REMAINING_LEN: usize = 268_435_455;

/// Operational ceiling on a single packet's framed size. The protocol permits a
/// 256 MB Remaining Length, but on an observability tap a packet that large is a
/// desynced or hostile stream, not a real publish — buffering toward 256 MB while
/// the body trickles in is a memory-DoS. Mark the stream dead past this, the same
/// discipline as Postgres `MAX_MSG_LEN` (4 MB) / Kafka `MAX_MSG_LEN` (100 MB):
/// bail rather than buffer unboundedly. 16 MB is generous headroom for any
/// legitimate MQTT control packet (the Maximum-Packet-Size property a broker
/// advertises is typically far smaller).
const MAX_PACKET_LEN: usize = 16 * 1024 * 1024;

/// Ceiling on SUBSCRIBEs held awaiting a SUBACK. A peer that pipelines subscribes
/// whose acks we never see (attached mid-connection, or a one-directional flood)
/// would grow the pending deque without bound. Past this the stream is desynced or
/// abusive — die rather than buffer unboundedly, mirroring Kafka's `MAX_INFLIGHT`.
const MAX_PENDING_SUBSCRIBES: usize = 40_000;

/// A SUBACK per-topic byte of `0x80` is the 3.1.1 "failure" return code; in MQTT5
/// every reason code ≥ `0x80` is a failure. The same threshold serves both.
const REASON_FAILURE: u8 = 0x80;

/// Outcome of decoding the Remaining Length varint at `byte1..`.
enum VarInt {
    /// A complete varint: its value and how many bytes it occupied (1–4).
    Done { value: usize, len: usize },
    /// A valid-so-far prefix (every byte had the continuation bit) but the buffer
    /// ends before the terminating byte — wait for more.
    Partial,
    /// Five+ continuation bytes, or a value past the legal max — malformed.
    Invalid,
}

/// Decode the MQTT Remaining Length varint starting at `buf` (caller passes the
/// slice AFTER `byte0`). 7 data bits per byte, top bit = continuation; at most 4
/// bytes. Never panics, never overflows (the 4-byte bound caps the shift).
fn decode_varint(buf: &[u8]) -> VarInt {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for i in 0..4 {
        let Some(&byte) = buf.get(i) else {
            return VarInt::Partial;
        };
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            return if value > MAX_REMAINING_LEN {
                VarInt::Invalid
            } else {
                VarInt::Done { value, len: i + 1 }
            };
        }
        multiplier *= 128;
    }
    // Four bytes all had the continuation bit set — a 5th byte would exceed the
    // varint's 4-byte cap, so this is not legal MQTT framing.
    VarInt::Invalid
}

/// A framed fixed header: packet type, flags, and the byte offsets of the variable
/// header start and the whole packet's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    packet_type: u8,
    flags: u8,
    /// Offset where the variable header / payload begins (after byte0 + varint).
    var_start: usize,
    /// Total bytes this packet occupies (`1 + varint_len + remaining_length`).
    total_len: usize,
}

/// Outcome of reading one fixed header off a direction-buffer prefix.
enum Head {
    /// A framed header whose whole packet is buffered.
    Framed(Header),
    /// A valid prefix, but the full packet (or even its varint) isn't here yet.
    Partial,
    /// Not MQTT framing — desynced/garbage; drop the connection.
    Invalid,
}

/// Parse one fixed header from a buffer prefix. The packet TYPE must be in 1..=15
/// (0 is reserved/forbidden); the Remaining Length must be a sane varint. We only
/// report `Framed` once the WHOLE packet is buffered, so callers can read the
/// variable header without bounds juggling. A reserved type 0 or an over-long
/// varint is the desync signal (`Invalid`); a not-yet-complete packet is `Partial`.
fn parse_head(buf: &[u8]) -> Head {
    let Some(&byte0) = buf.first() else {
        return Head::Partial;
    };
    let packet_type = byte0 >> 4;
    let flags = byte0 & 0x0F;
    // Type 0 is forbidden; 1..=15 are the defined control packet types.
    if packet_type == 0 {
        return Head::Invalid;
    }
    match decode_varint(&buf[1..]) {
        VarInt::Done { value, len } => {
            let var_start = 1 + len;
            let total_len = var_start + value;
            if total_len > MAX_PACKET_LEN {
                // A legal varint but an operationally absurd packet size: treat it as
                // desync/hostile rather than buffer toward it. (See MAX_PACKET_LEN.)
                Head::Invalid
            } else if buf.len() < total_len {
                Head::Partial
            } else {
                Head::Framed(Header {
                    packet_type,
                    flags,
                    var_start,
                    total_len,
                })
            }
        }
        VarInt::Partial => Head::Partial,
        VarInt::Invalid => Head::Invalid,
    }
}

/// Read a u16-length-prefixed UTF-8 string at the front of `field` (MQTT strings
/// and the PUBLISH/SUBSCRIBE topic are `[len:u16 BE][bytes]`). Returns the string
/// and the offset just past it, or `None` if the slice is too short (never panics).
fn read_str(field: &[u8]) -> Option<(String, usize)> {
    if field.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([field[0], field[1]]) as usize;
    let end = 2 + len;
    let bytes = field.get(2..end)?;
    Some((String::from_utf8_lossy(bytes).into_owned(), end))
}

/// Skip an MQTT5 property block: a Remaining-Length-style varint giving the block's
/// byte length, then that many property bytes. Returns the offset just past the
/// block, or `None` if it runs off the slice. Only called when the connection is
/// known to be MQTT5 (protocol level 5 from CONNECT).
fn skip_properties(field: &[u8]) -> Option<usize> {
    match decode_varint(field) {
        VarInt::Done { value, len } => {
            let end = len + value;
            if field.len() >= end { Some(end) } else { None }
        }
        _ => None,
    }
}

/// The PUBLISH topic — the first thing in a PUBLISH variable header, before the
/// (QoS>0) packet id and any MQTT5 properties. Needs no version knowledge.
fn publish_topic(var: &[u8]) -> String {
    match read_str(var) {
        Some((topic, _)) if !topic.is_empty() => topic,
        _ => String::new(),
    }
}

/// The first topic filter of a SUBSCRIBE. Variable header is `[packet id:u16]`, then
/// (MQTT5 only) a property block, then the payload of `[topic:str][options:u8]`
/// filters. We read just the first filter's topic. `mqtt5` selects whether the
/// property block is present. Best-effort: any short read yields an empty topic
/// (the record still flows with a bare "SUBSCRIBE" label), never a panic.
fn subscribe_topic(var: &[u8], mqtt5: bool) -> String {
    // packet id is the first two bytes.
    let Some(after_id) = var.get(2..) else {
        return String::new();
    };
    let payload = if mqtt5 {
        match skip_properties(after_id) {
            Some(off) => &after_id[off..],
            None => return String::new(),
        }
    } else {
        after_id
    };
    match read_str(payload) {
        Some((topic, _)) if !topic.is_empty() => topic,
        _ => String::new(),
    }
}

/// The packet id of a SUBSCRIBE/SUBACK — the first two bytes of their variable
/// header. `None` if not enough bytes are present.
fn packet_id(var: &[u8]) -> Option<u16> {
    if var.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([var[0], var[1]]))
}

/// Build a `"<TYPE> <topic>"` label, or the bare type name when the topic is empty.
fn label(type_name: &str, topic: &str) -> String {
    if topic.is_empty() {
        type_name.to_string()
    } else {
        format!("{type_name} {topic}")
    }
}

/// CONNACK error verdict: the second byte of the variable header is the return code
/// (3.1.1) / reason code (MQTT5); non-zero is a connection failure. The first byte
/// is the acknowledge-flags (session-present) byte. A short body ⇒ no verdict.
fn connack_is_error(var: &[u8]) -> bool {
    var.get(1).is_some_and(|&code| code != 0)
}

/// SUBACK error verdict: the payload after the `[packet id:u16]` (and, for MQTT5, a
/// property block) is one return/reason code per subscribed topic. Any byte ≥ 0x80
/// is a failure (`0x80` in 3.1.1; any high-bit reason code in MQTT5). A short body
/// ⇒ no verdict.
fn suback_is_error(var: &[u8], mqtt5: bool) -> bool {
    let Some(after_id) = var.get(2..) else {
        return false;
    };
    let codes = if mqtt5 {
        match skip_properties(after_id) {
            Some(off) => &after_id[off..],
            None => return false,
        }
    } else {
        after_id
    };
    codes.iter().any(|&c| c >= REASON_FAILURE)
}

/// A CONNECT awaiting its CONNACK, with the time it was observed (for latency).
#[derive(Debug)]
struct PendingConnect {
    start_unix_nano: i64,
}

/// A SUBSCRIBE awaiting its SUBACK, keyed by packet id so an out-of-order SUBACK
/// still pairs with the right subscription.
#[derive(Debug)]
struct PendingSubscribe {
    packet_id: u16,
    operation: String,
    start_unix_nano: i64,
}

/// MQTT [`L7Parser`]: reassembles each direction, frames fixed headers (skipping
/// past packet bodies via [`DirBuf`]), emits a record per client operation, pairs
/// CONNECT→CONNACK and SUBSCRIBE→SUBACK for the error verdict + latency, and frames
/// server-side deliveries/acks past without minting records. Desync marks it dead.
#[derive(Debug, Default)]
pub(crate) struct MqttParser {
    inbound: DirBuf,
    outbound: DirBuf,
    pending_connect: Option<PendingConnect>,
    pending_subscribes: VecDeque<PendingSubscribe>,
    /// Learned from CONNECT's protocol-level byte (5 ⇒ MQTT5). Governs whether a
    /// property block precedes SUBSCRIBE/SUBACK payloads. Defaults to 3.1.1.
    mqtt5: bool,
    records: Vec<L7Record>,
    dead: bool,
}

impl MqttParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a fire-and-forget operation record (no paired response).
    fn push_op(&mut self, operation: String, ts: i64) {
        self.records.push(L7Record {
            protocol: PROTOCOL,
            attributes: Vec::new(),
            operation,
            status_code: 0,
            error: false,
            start_unix_nano: ts,
            duration_nano: 0,
        });
    }

    /// Frame as many complete client packets as the inbound buffer holds.
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
                    self.apply_inbound(&h, ts);
                    self.inbound.advance(h.total_len);
                    // apply_inbound may have tripped a resource ceiling — stop draining
                    // rather than keep buffering past it.
                    if self.dead {
                        return;
                    }
                }
                Head::Partial => return,
                Head::Invalid => {
                    self.dead = true;
                    return;
                }
            }
        }
    }

    /// Act on one framed client (inbound) packet.
    fn apply_inbound(&mut self, h: &Header, ts: i64) {
        let var = &self.inbound.buf[h.var_start..h.total_len];
        match h.packet_type {
            CONNECT => {
                // Protocol level follows the protocol-name string; level 5 = MQTT5.
                if let Some((_, after_name)) = read_str(var)
                    && let Some(&level) = var.get(after_name)
                {
                    self.mqtt5 = level >= 5;
                }
                // Held pending: CONNACK supplies its verdict + completion time.
                self.pending_connect = Some(PendingConnect {
                    start_unix_nano: ts,
                });
            }
            PUBLISH => {
                let topic = publish_topic(var);
                self.push_op(label("PUBLISH", &topic), ts);
            }
            SUBSCRIBE => {
                let topic = subscribe_topic(var, self.mqtt5);
                let operation = label("SUBSCRIBE", &topic);
                match packet_id(var) {
                    // Held pending: SUBACK supplies its verdict + completion time.
                    Some(id) => {
                        self.pending_subscribes.push_back(PendingSubscribe {
                            packet_id: id,
                            operation,
                            start_unix_nano: ts,
                        });
                        // Acks we never see (mid-connection attach / flood) would grow
                        // this without bound — die past the ceiling rather than buffer
                        // unboundedly (mirrors Kafka's MAX_INFLIGHT).
                        if self.pending_subscribes.len() > MAX_PENDING_SUBSCRIBES {
                            self.dead = true;
                        }
                    }
                    // Malformed (no packet id) — record it fire-and-forget so the
                    // operation is still observed rather than silently dropped.
                    None => self.push_op(operation, ts),
                }
            }
            UNSUBSCRIBE => self.push_op("UNSUBSCRIBE".to_string(), ts),
            PINGREQ => self.push_op("PINGREQ".to_string(), ts),
            DISCONNECT => self.push_op("DISCONNECT".to_string(), ts),
            // PUBACK/PUBREC/PUBREL/PUBCOMP (QoS handshake acks the client may send)
            // and anything else: framed past, no record.
            _ => {}
        }
    }

    /// Frame as many complete server packets as the outbound buffer holds.
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
                    self.apply_outbound(&h, ts);
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

    /// Act on one framed server (outbound) packet — complete a pending client
    /// operation, or frame the delivery/ack past without a record.
    fn apply_outbound(&mut self, h: &Header, ts: i64) {
        let var = &self.outbound.buf[h.var_start..h.total_len];
        match h.packet_type {
            CONNACK => {
                let error = connack_is_error(var);
                if let Some(req) = self.pending_connect.take() {
                    self.records.push(L7Record {
                        protocol: PROTOCOL,
                        attributes: Vec::new(),
                        operation: "CONNECT".to_string(),
                        status_code: u16::from(error),
                        error,
                        start_unix_nano: req.start_unix_nano,
                        duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
                    });
                }
            }
            SUBACK => {
                let error = suback_is_error(var, self.mqtt5);
                // Pair by packet id; an unmatched SUBACK is dropped (mid-stream
                // attach / stray), never steals an unrelated pending subscribe.
                if let Some(id) = packet_id(var)
                    && let Some(pos) = self
                        .pending_subscribes
                        .iter()
                        .position(|p| p.packet_id == id)
                    && let Some(req) = self.pending_subscribes.remove(pos)
                {
                    self.records.push(L7Record {
                        protocol: PROTOCOL,
                        attributes: Vec::new(),
                        operation: req.operation,
                        status_code: u16::from(error),
                        error,
                        start_unix_nano: req.start_unix_nano,
                        duration_nano: ts.saturating_sub(req.start_unix_nano).max(0),
                    });
                }
            }
            // Server PUBLISH (broker → subscriber), PINGRESP, UNSUBACK, PUBACK/…:
            // out-of-band deliveries / acks that answer no client request — framed
            // past, no record (the Redis-push / NATS-MSG lesson).
            _ => {}
        }
    }
}

impl L7Parser for MqttParser {
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

/// Construct an MQTT parser unconditionally — the port-hint path (1883/8883 ⇒ MQTT)
/// names the protocol up front, so no byte signature is needed.
pub(crate) fn new_parser() -> Box<dyn super::L7Parser> {
    Box::new(MqttParser::new())
}

/// Recognise MQTT from a connection's inbound prefix via a POSITIVE, conservative
/// signature and return a fresh boxed parser, or `None` if it isn't (yet)
/// recognisable.
///
/// A fresh MQTT connection's first client packet is ALWAYS a CONNECT, whose variable
/// header opens with a length-prefixed protocol-name string — a real magic value
/// (`"MQTT"` for 3.1.1/5.0, `"MQIsdp"` for 3.1). We require, all of:
///   * `byte0` high nibble == CONNECT (1) and low nibble (flags) == 0 (CONNECT's
///     flags are reserved-zero);
///   * a sane Remaining Length varint whose whole packet is buffered;
///   * the variable header begins with `[len:u16][protocol name]` where the name is
///     exactly `"MQTT"` or `"MQIsdp"`.
///
/// That magic-string conjunction is what keeps a binary protocol without a port hint
/// from false-positiving on arbitrary traffic. While the packet is still arriving we
/// return `None` (the registry keeps buffering and retries) rather than guess.
pub(crate) fn detect_mqtt(inbound: &[u8]) -> Option<Box<dyn super::L7Parser>> {
    let &byte0 = inbound.first()?;
    // Must be a CONNECT with reserved-zero flags.
    if byte0 >> 4 != CONNECT || byte0 & 0x0F != 0 {
        return None;
    }
    let Head::Framed(h) = parse_head(inbound) else {
        // Header plausible but the whole packet hasn't arrived — don't commit yet.
        return None;
    };
    let var = &inbound[h.var_start..h.total_len];
    match read_str(var) {
        Some((name, _)) if name == "MQTT" || name == "MQIsdp" => Some(Box::new(MqttParser::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a Remaining Length varint (the inverse of [`decode_varint`]).
    fn encode_varint(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value % 128) as u8;
            value /= 128;
            if value > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    /// Frame a control packet: `[byte0][remaining length varint][body]`.
    fn packet(packet_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let byte0 = (packet_type << 4) | (flags & 0x0F);
        let mut v = vec![byte0];
        v.extend_from_slice(&encode_varint(body.len()));
        v.extend_from_slice(body);
        v
    }

    /// A `[len:u16 BE][bytes]` MQTT string.
    fn mqtt_str(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    /// A CONNECT packet body: protocol name + level + flags + keep-alive + a
    /// minimal payload (client id). `level` 4 = 3.1.1, 5 = MQTT5.
    fn connect_body(name: &str, level: u8) -> Vec<u8> {
        let mut v = mqtt_str(name);
        v.push(level); // protocol level
        v.push(0x02); // connect flags (clean session)
        v.extend_from_slice(&60u16.to_be_bytes()); // keep alive
        if level >= 5 {
            v.push(0x00); // MQTT5 properties: zero-length block
        }
        v.extend_from_slice(&mqtt_str("client-1")); // payload: client id
        v
    }

    fn connect(name: &str, level: u8) -> Vec<u8> {
        packet(CONNECT, 0, &connect_body(name, level))
    }

    /// A CONNACK body: `[ack flags:u8][return/reason code:u8]` (+ MQTT5 props).
    fn connack(code: u8, mqtt5: bool) -> Vec<u8> {
        let mut body = vec![0x00, code];
        if mqtt5 {
            body.push(0x00); // properties: zero-length
        }
        packet(CONNACK, 0, &body)
    }

    /// A PUBLISH packet with the given topic and QoS (controls the flags + packet
    /// id presence). QoS 0 = no packet id.
    fn publish(topic: &str, qos: u8) -> Vec<u8> {
        let mut body = mqtt_str(topic);
        if qos > 0 {
            body.extend_from_slice(&1u16.to_be_bytes()); // packet id
        }
        let flags = (qos & 0x03) << 1;
        packet(PUBLISH, flags, &body)
    }

    /// A SUBSCRIBE packet (`flags` are reserved `0x02`): `[packet id:u16]` (+ MQTT5
    /// props) then one `[topic][options:u8]` filter.
    fn subscribe(packet_id: u16, topic: &str, mqtt5: bool) -> Vec<u8> {
        let mut body = packet_id.to_be_bytes().to_vec();
        if mqtt5 {
            body.push(0x00); // properties: zero-length
        }
        body.extend_from_slice(&mqtt_str(topic));
        body.push(0x00); // subscription options (QoS 0)
        packet(SUBSCRIBE, 0x02, &body)
    }

    /// A SUBACK packet: `[packet id:u16]` (+ MQTT5 props) then one return code per
    /// topic. `0x80` = failure; `0x00`/`0x01`/`0x02` = granted QoS.
    fn suback(packet_id: u16, codes: &[u8], mqtt5: bool) -> Vec<u8> {
        let mut body = packet_id.to_be_bytes().to_vec();
        if mqtt5 {
            body.push(0x00); // properties: zero-length
        }
        body.extend_from_slice(codes);
        packet(SUBACK, 0, &body)
    }

    #[test]
    fn varint_round_trips_at_boundaries() {
        for value in [
            0usize,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            MAX_REMAINING_LEN,
        ] {
            let enc = encode_varint(value);
            match decode_varint(&enc) {
                VarInt::Done { value: got, len } => {
                    assert_eq!(got, value);
                    assert_eq!(len, enc.len());
                }
                _ => panic!("expected Done for {value}"),
            }
        }
    }

    #[test]
    fn varint_partial_and_invalid() {
        // Continuation bit set but no following byte — wait.
        assert!(matches!(decode_varint(&[0x80]), VarInt::Partial));
        // Five continuation bytes exceed the 4-byte cap — malformed.
        assert!(matches!(
            decode_varint(&[0x80, 0x80, 0x80, 0x80, 0x01]),
            VarInt::Invalid
        ));
    }

    #[test]
    fn detects_connect_by_protocol_name_magic() {
        assert!(detect_mqtt(&connect("MQTT", 4)).is_some()); // 3.1.1
        assert!(detect_mqtt(&connect("MQTT", 5)).is_some()); // 5.0
        assert!(detect_mqtt(&connect("MQIsdp", 3)).is_some()); // 3.1
    }

    #[test]
    fn rejects_non_mqtt_and_wrong_shaped_prefixes() {
        // HTTP, RESP, TLS hello, raw binary: none are a CONNECT-with-magic.
        assert!(detect_mqtt(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(detect_mqtt(b"*1\r\n$4\r\nPING\r\n").is_none());
        assert!(detect_mqtt(b"\x16\x03\x01\x02\x00").is_none());
        assert!(detect_mqtt(b"\x00\x01\x02\x03").is_none());
        // A CONNECT byte0 but the protocol name is not the magic string.
        let bogus = packet(CONNECT, 0, &{
            let mut b = mqtt_str("XXXX");
            b.push(4);
            b
        });
        assert!(detect_mqtt(&bogus).is_none());
        // Right magic but non-zero (reserved) CONNECT flags — reject.
        let mut bad_flags = connect("MQTT", 4);
        bad_flags[0] |= 0x01;
        assert!(detect_mqtt(&bad_flags).is_none());
    }

    #[test]
    fn detect_waits_until_whole_connect_is_buffered() {
        // Header byte + varint but the body straddles — don't commit yet.
        let full = connect("MQTT", 4);
        assert!(detect_mqtt(&full[..4]).is_none());
        assert!(detect_mqtt(&full).is_some());
    }

    #[test]
    fn new_parser_constructs_unconditionally_for_port_hint() {
        // The port-hint path needs a parser with no byte signature.
        let mut p = new_parser();
        p.on_inbound(&publish("sensors/temp", 0), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH sensors/temp");
    }

    #[test]
    fn connect_pairs_with_connack_for_verdict_and_latency() {
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 4), 1_000);
        // No record yet — CONNECT awaits its CONNACK.
        assert!(p.take_records().is_empty());
        p.on_outbound(&connack(0, false), 1_400);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
        assert_eq!(recs[0].status_code, 0);
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 1_000);
        assert_eq!(recs[0].duration_nano, 400);
    }

    #[test]
    fn connack_nonzero_return_code_is_an_error() {
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 4), 1);
        // Return code 5 = "not authorized" (3.1.1).
        p.on_outbound(&connack(5, false), 2);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn publish_emits_immediately_with_topic_fire_and_forget() {
        let mut p = MqttParser::new();
        p.on_inbound(&publish("sensors/temp", 0), 5_000);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH sensors/temp");
        assert!(!recs[0].error);
        assert_eq!(recs[0].start_unix_nano, 5_000);
        assert_eq!(recs[0].duration_nano, 0); // fire-and-forget
    }

    #[test]
    fn qos1_publish_topic_read_before_packet_id() {
        // QoS>0 PUBLISH carries a packet id AFTER the topic; the topic must still be
        // read correctly (topic is first in the variable header).
        let mut p = MqttParser::new();
        p.on_inbound(&publish("orders/new", 1), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH orders/new");
    }

    #[test]
    fn subscribe_pairs_with_suback_by_packet_id() {
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(42, "events/#", false), 100);
        assert!(p.take_records().is_empty()); // awaits SUBACK
        p.on_outbound(&suback(42, &[0x01], false), 160); // granted QoS 1
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE events/#");
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 60);
    }

    #[test]
    fn suback_failure_code_marks_error() {
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(7, "denied/topic", false), 1);
        p.on_outbound(&suback(7, &[REASON_FAILURE], false), 3); // 0x80 = failure
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE denied/topic");
        assert!(recs[0].error);
        assert_eq!(recs[0].status_code, 1);
    }

    #[test]
    fn suback_pairs_out_of_order_by_packet_id() {
        // Two subscribes in flight; SUBACKs return in REVERSE order. Pairing by
        // packet id must match each ack to its subscribe.
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(1, "a/x", false), 10);
        p.on_inbound(&subscribe(2, "b/y", false), 20);
        p.on_outbound(&suback(2, &[0x00], false), 30);
        p.on_outbound(&suback(1, &[REASON_FAILURE], false), 40);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SUBSCRIBE b/y"); // ack 2 arrived first
        assert!(!recs[0].error);
        assert_eq!(recs[0].duration_nano, 10);
        assert_eq!(recs[1].operation, "SUBSCRIBE a/x");
        assert!(recs[1].error);
        assert_eq!(recs[1].duration_nano, 30); // ack 1 at ts 40, subscribe at ts 10
    }

    #[test]
    fn mqtt5_subscribe_topic_read_past_property_block() {
        // MQTT5 SUBSCRIBE has a property block between packet id and the filters; the
        // version learned from CONNECT(level 5) must make us skip it to read the topic.
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 5), 1); // learns mqtt5 = true
        p.on_outbound(&connack(0, true), 2);
        let _ = p.take_records();
        p.on_inbound(&subscribe(9, "v5/topic", true), 3);
        p.on_outbound(&suback(9, &[0x02], true), 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE v5/topic");
        assert!(!recs[0].error);
    }

    #[test]
    fn mqtt5_suback_high_reason_code_is_error() {
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 5), 1);
        p.on_outbound(&connack(0, true), 2);
        let _ = p.take_records();
        p.on_inbound(&subscribe(3, "x/y", true), 3);
        // 0x97 = "Quota exceeded" (MQTT5), a reason code ≥ 0x80.
        p.on_outbound(&suback(3, &[0x97], true), 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error);
    }

    #[test]
    fn unsubscribe_ping_disconnect_emit_bare_type_names() {
        let mut p = MqttParser::new();
        // UNSUBSCRIBE body: packet id + one topic filter.
        let mut unsub_body = 5u16.to_be_bytes().to_vec();
        unsub_body.extend_from_slice(&mqtt_str("events/#"));
        p.on_inbound(&packet(UNSUBSCRIBE, 0x02, &unsub_body), 1);
        p.on_inbound(&packet(PINGREQ, 0, &[]), 2);
        p.on_inbound(&packet(DISCONNECT, 0, &[]), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].operation, "UNSUBSCRIBE");
        assert_eq!(recs[1].operation, "PINGREQ");
        assert_eq!(recs[2].operation, "DISCONNECT");
    }

    #[test]
    fn server_publish_delivery_produces_no_record() {
        // A broker → subscriber PUBLISH (outbound) answers no client request: framed
        // past, no record, and it must not steal a pending CONNECT/SUBSCRIBE.
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(1, "feed", false), 1);
        p.on_outbound(&publish("feed", 0), 2); // server delivery
        assert!(
            p.take_records().is_empty(),
            "server PUBLISH must not mint or steal a record"
        );
        // The genuine SUBACK still pairs the subscribe.
        p.on_outbound(&suback(1, &[0x00], false), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE feed");
    }

    #[test]
    fn pipelined_client_packets_each_resolve() {
        // CONNECT + a QoS0 PUBLISH + a SUBSCRIBE pipelined in one inbound segment.
        let mut p = MqttParser::new();
        let mut seg = connect("MQTT", 4);
        seg.extend(publish("telemetry", 0));
        seg.extend(subscribe(11, "cmd/#", false));
        p.on_inbound(&seg, 100);
        // PUBLISH emits immediately; CONNECT + SUBSCRIBE await their acks.
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH telemetry");
        // Acks come back; CONNECT then SUBSCRIBE complete.
        p.on_outbound(&connack(0, false), 110);
        p.on_outbound(&suback(11, &[0x00], false), 120);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "CONNECT");
        assert_eq!(recs[1].operation, "SUBSCRIBE cmd/#");
    }

    #[test]
    fn fragmented_publish_waits_then_completes() {
        let mut p = MqttParser::new();
        let pkt = publish("sensors/humidity", 0);
        // Feed all but the last 3 bytes — the packet isn't fully buffered.
        let split = pkt.len() - 3;
        p.on_inbound(&pkt[..split], 1);
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead()); // partial, not garbage
        p.on_inbound(&pkt[split..], 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH sensors/humidity");
    }

    #[test]
    fn fragmented_connack_waits_for_full_packet() {
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 4), 1);
        let ack = connack(5, false);
        // Only byte0 of the CONNACK arrives — must not complete on a partial.
        p.on_outbound(&ack[..1], 5);
        assert!(p.take_records().is_empty());
        p.on_outbound(&ack[1..], 9);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].error); // the error verdict survives fragmentation
        assert_eq!(recs[0].duration_nano, 8);
    }

    #[test]
    fn byte_at_a_time_connect_connack_yields_one_record() {
        let mut p = MqttParser::new();
        let req = connect("MQTT", 4);
        for byte in req.iter() {
            p.on_inbound(std::slice::from_ref(byte), 1_000);
        }
        assert!(p.take_records().is_empty());
        let ack = connack(0, false);
        let last = (ack.len() - 1) as i64;
        for (i, byte) in ack.iter().enumerate() {
            p.on_outbound(std::slice::from_ref(byte), 2_000 + i as i64);
        }
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "CONNECT");
        assert_eq!(recs[0].duration_nano, 2_000 + last - 1_000);
    }

    #[test]
    fn orphan_connack_with_no_pending_connect_is_dropped_not_dead() {
        let mut p = MqttParser::new();
        p.on_outbound(&connack(0, false), 1); // attached mid-connection
        assert!(p.take_records().is_empty());
        assert!(!p.is_dead());
    }

    #[test]
    fn unmatched_suback_does_not_steal_a_pending_subscribe() {
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(10, "a", false), 1);
        // SUBACK for a packet id we never subscribed to — drop, don't steal.
        p.on_outbound(&suback(999, &[0x00], false), 2);
        assert!(p.take_records().is_empty());
        // The real SUBACK still pairs.
        p.on_outbound(&suback(10, &[0x00], false), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "SUBSCRIBE a");
    }

    #[test]
    fn reserved_packet_type_zero_marks_dead() {
        let mut p = MqttParser::new();
        p.on_inbound(&[0x00, 0x00], 1); // type 0 is forbidden
        assert!(p.is_dead());
        assert!(p.take_records().is_empty());
    }

    #[test]
    fn oversized_remaining_length_marks_dead() {
        let mut p = MqttParser::new();
        // A 5-byte run of continuation bits is an illegal varint (> 4 bytes).
        p.on_inbound(&[0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 1);
        assert!(p.is_dead());
    }

    #[test]
    fn detect_does_not_read_protocol_name_past_packet() {
        // CONNECT whose declared protocol-name length overruns the variable header,
        // but the bytes that complete the string happen to live in a FOLLOWING
        // pipelined packet. detect_mqtt slices `&inbound[var_start..total_len]`, so
        // read_str must NOT see past total_len. Construct: a CONNECT with body
        // "[len=6]MQ" (only 2 bytes present in-body, but remaining-length covers just
        // those), pipelined with a packet whose bytes spell "Tsdp..". If read_str were
        // given the whole `inbound` it could read "MQIsdp"; bounded to var it cannot.
        let mut body = 6u16.to_be_bytes().to_vec(); // claims 6-byte name
        body.extend_from_slice(b"MQ"); // only 2 bytes actually in this packet's body
        let mut wire = packet(CONNECT, 0, &body);
        wire.extend_from_slice(b"Isdp!!"); // next bytes on the wire spell the rest
        // If detection is correctly bounded to this packet, the 6-byte string can't be
        // satisfied within var -> None. A leak would return Some.
        let got = detect_mqtt(&wire);
        assert!(
            got.is_none(),
            "detect must not read protocol name past the packet"
        );
    }

    #[test]
    fn suback_pairs_fifo_on_duplicate_packet_ids() {
        // Two SUBSCRIBEs reuse the SAME packet id (legal: id is free once its SUBACK
        // returns; a fast client could even pipeline a reuse). The first SUBACK must
        // pair the FIRST pending subscribe (FIFO), the second the second.
        let mut p = MqttParser::new();
        p.on_inbound(&subscribe(5, "first", false), 10);
        p.on_inbound(&subscribe(5, "second", false), 20);
        p.on_outbound(&suback(5, &[0x00], false), 30);
        p.on_outbound(&suback(5, &[0x00], false), 40);
        let recs = p.take_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].operation, "SUBSCRIBE first");
        assert_eq!(recs[0].duration_nano, 20); // 30 - 10
        assert_eq!(recs[1].operation, "SUBSCRIBE second");
        assert_eq!(recs[1].duration_nano, 20); // 40 - 20
    }

    #[test]
    fn second_connect_does_not_double_pair() {
        // Two CONNECTs (protocol violation, but hostile input). pending_connect is a
        // singleton Option, so the second overwrites the first. One CONNACK pairs one.
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 4), 1);
        p.on_inbound(&connect("MQTT", 4), 2);
        p.on_outbound(&connack(0, false), 3);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1, "one CONNACK pairs at most one CONNECT");
    }

    #[test]
    fn publish_zero_remaining_length_empty_topic() {
        // A PUBLISH with remaining length 0 (no topic at all) — malformed per spec
        // (topic is mandatory) but must frame past without panic and not desync.
        let mut p = MqttParser::new();
        p.on_inbound(&packet(PUBLISH, 0, &[]), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH"); // bare label, empty topic
        assert!(!p.is_dead());
    }

    #[test]
    fn mqtt5_suback_property_overrun_no_false_error() {
        // MQTT5 SUBACK with a property-length varint that claims MORE bytes than the
        // packet holds. skip_properties returns None -> suback_is_error returns false
        // (no verdict), and pairing still proceeds. Must not panic, must not slice OOB.
        let mut p = MqttParser::new();
        p.on_inbound(&connect("MQTT", 5), 1);
        p.on_outbound(&connack(0, true), 2);
        let _ = p.take_records();
        p.on_inbound(&subscribe(8, "v5", true), 3);
        // Build a SUBACK whose property length says 50 but no property bytes follow.
        let mut body = 8u16.to_be_bytes().to_vec();
        body.push(50); // property length varint = 50 (overruns)
        // no property bytes, no reason codes
        p.on_outbound(&packet(SUBACK, 0, &body), 4);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].error, "unreadable props -> no false error verdict");
    }

    #[test]
    fn publish_topic_read_before_packet_id_qos2() {
        // QoS 2 PUBLISH: topic first, then packet id. Reading just the topic string
        // must stop at the declared length and not swallow the packet id bytes.
        let mut p = MqttParser::new();
        p.on_inbound(&publish("a/b", 2), 1);
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH a/b");
    }

    #[test]
    fn huge_remaining_length_marks_dead_not_buffered() {
        // A single PUBLISH header claiming a near-max (still legal-varint) Remaining
        // Length whose body never arrives. Without an operational cap this buffers
        // toward 256 MB forever (a memory-DoS); the MAX_PACKET_LEN guard must instead
        // mark the stream dead the moment the header frames, before any body is held.
        let mut p = MqttParser::new();
        let mut header = vec![PUBLISH << 4];
        header.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]); // 268_435_455 remaining
        p.on_inbound(&header, 1);
        assert!(
            p.is_dead(),
            "an absurd packet size bails rather than buffers"
        );
        // A dead parser ignores further bytes, so the buffer never grows toward 256 MB.
        let before = p.inbound.buf.len();
        p.on_inbound(&vec![0u8; 1024 * 1024], 2);
        assert_eq!(
            p.inbound.buf.len(),
            before,
            "dead parser buffers nothing more"
        );
    }

    #[test]
    fn just_under_packet_cap_still_frames() {
        // A packet whose framed size is exactly at the cap must still parse — the
        // guard rejects only what EXCEEDS the ceiling, not legitimate large packets.
        // Use a PUBLISH whose body is one byte under the cap's remaining-length room.
        let remaining = MAX_PACKET_LEN - 5; // 1 byte0 + 4 varint bytes of overhead
        let mut header = vec![PUBLISH << 4];
        header.extend_from_slice(&encode_varint(remaining));
        assert_eq!(header.len(), 5, "remaining needs the full 4-byte varint");
        let mut wire = header;
        wire.extend_from_slice(&mqtt_str("at/cap"));
        wire.resize(MAX_PACKET_LEN, 0); // pad the body out to exactly the cap
        let mut p = MqttParser::new();
        p.on_inbound(&wire, 1);
        assert!(!p.is_dead(), "a packet exactly at the cap is legal");
        let recs = p.take_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].operation, "PUBLISH at/cap");
    }

    #[test]
    fn pending_subscribe_flood_marks_dead() {
        // A peer that pipelines SUBSCRIBEs whose SUBACKs never match would grow
        // pending_subscribes without bound. Past MAX_PENDING_SUBSCRIBES the parser
        // must die rather than buffer unboundedly (mirrors Kafka's MAX_INFLIGHT), and
        // the pending deque must not exceed the ceiling by more than the trip packet.
        let mut p = MqttParser::new();
        for id in 0..(MAX_PENDING_SUBSCRIBES as u32 + 50) {
            p.on_inbound(&subscribe((id & 0xFFFF) as u16, "t", false), id as i64);
            if p.is_dead() {
                break;
            }
        }
        assert!(p.is_dead(), "a subscribe flood bails rather than buffers");
        assert!(
            p.pending_subscribes.len() <= MAX_PENDING_SUBSCRIBES + 1,
            "pending deque capped at the ceiling, not growing past it"
        );
    }

    #[test]
    fn publish_qos3_malformed_does_not_panic() {
        // QoS 3 (both QoS bits set) is malformed per [MQTT-3.3.1-4]; a broker MUST
        // close the connection. Does the parser frame it without panicking? It should
        // at least not panic. (Verdict correctness is secondary to no-crash.)
        let mut p = MqttParser::new();
        let body = mqtt_str("t");
        p.on_inbound(&packet(PUBLISH, 0b0110, &body), 1); // flags qos=3
        let _ = p.take_records();
        let _ = p.is_dead();
    }

    #[test]
    fn adversarial_bytes_never_panic_on_any_split() {
        // Fuzz-think: feed hostile/truncated payloads at every byte boundary, both
        // directions, in both orders. The hard requirement is no panic, ever — a
        // wrong verdict is acceptable, a crash is not.
        let big_varint = {
            // A valid 4-byte varint claiming a huge body that never arrives.
            let mut v = vec![(PUBLISH << 4)];
            v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]); // 268_435_455
            v.extend_from_slice(b"\x00\x04topi");
            v
        };
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],                          // reserved type 0
            vec![0x10],                          // CONNECT byte0, nothing else
            vec![0x10, 0x80],                    // varint continuation, no end
            vec![0x10, 0xFF, 0xFF, 0xFF, 0xFF],  // illegal 5-byte varint start
            packet(CONNECT, 0, &mqtt_str("MQ")), // truncated magic
            packet(PUBLISH, 0, &[0xFF, 0xFF]),   // PUBLISH topic len overruns body
            packet(PUBLISH, 0, &mqtt_str("")),   // empty topic
            packet(SUBSCRIBE, 0x02, &[0x00]),    // SUBSCRIBE, only half a packet id
            packet(SUBACK, 0, &[0x00]),          // SUBACK, half a packet id
            connect("MQTT", 5),                  // valid MQTT5 connect
            connack(0x87, true),                 // MQTT5 connack, not-authorized
            subscribe(1, "x", true),             // MQTT5 subscribe (props present)
            big_varint,
            (0u8..=255).collect(),
            vec![0xFF; 64],
        ];
        for payload in &payloads {
            for split in 0..=payload.len() {
                let (a, b) = payload.split_at(split);
                // detection must never panic
                let _ = detect_mqtt(a);
                let _ = detect_mqtt(payload);

                // request side, split
                let mut p = MqttParser::new();
                p.on_inbound(a, 1);
                p.on_inbound(b, 2);
                let _ = p.take_records();
                let _ = p.is_dead();

                // response side, split, with a real CONNECT + SUBSCRIBE outstanding
                let mut q = MqttParser::new();
                q.on_inbound(&connect("MQTT", 4), 0);
                q.on_inbound(&subscribe(1, "feed", false), 0);
                q.on_outbound(a, 1);
                q.on_outbound(b, 2);
                let _ = q.take_records();
            }
        }
    }
}
