//! Golden-output demonstration: runs a representative request/response exchange
//! per protocol through the REAL pipeline (`ConnRegistry` → `L7Record` →
//! `RequestSignal` + RED) and prints the exact bytes that would be exported, so
//! the actual on-the-wire output can be inspected. Test-only; also guards that
//! every wired protocol still produces a span. Run with:
//!   cargo test --lib l7::exports_demo -- --nocapture

use super::{
    CapturedSegment, ConnRegistry, Direction, L7Record, RedAggregator, SpanContext, mint_id,
    to_request_signal,
};

const REQ_TS: i64 = 1_000_000_000; // 2001-09-09T01:46:40Z (unix nanos)
const RESP_TS: i64 = 1_002_500_000; // +2.5 ms

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A readable one-line preview: control bytes shown as visible glyphs, truncated.
fn preview(b: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(b)
        .chars()
        .take(96)
        .map(|c| match c {
            '\r' => '␍',
            '\n' => '␊',
            c if c.is_control() || c == '\u{fffd}' => '·',
            c => c,
        })
        .collect();
    if b.len() > 96 {
        format!("{s}…  ({} bytes)", b.len())
    } else {
        s
    }
}

/// Run a request (inbound) + response (outbound) through the pipeline, emit the
/// RequestSignal + RED entry that would be exported, and append a report block.
fn demo(out: &mut String, name: &str, key: Option<&str>, req: &[u8], resp: &[u8], seed: u64) {
    let mut reg = ConnRegistry::new();
    let inbound = CapturedSegment {
        pid: 4242,
        cgroup_id: 0,
        fd: 7,
        direction: Direction::Inbound,
        timestamp_nano: REQ_TS,
        bytes: req.to_vec(),
    };
    let outbound = CapturedSegment {
        pid: 4242,
        cgroup_id: 0,
        fd: 7,
        direction: Direction::Outbound,
        timestamp_nano: RESP_TS,
        bytes: resp.to_vec(),
    };
    let mut recs = Vec::new();
    match key {
        Some(k) => {
            recs.extend(reg.on_segment_hinted(&inbound, Some(k), false));
            recs.extend(reg.on_segment_hinted(&outbound, Some(k), false));
        }
        None => {
            recs.extend(reg.on_segment(&inbound));
            recs.extend(reg.on_segment(&outbound));
        }
    }
    let record: L7Record = recs
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{name}: pipeline produced no record for the sample exchange"));

    let ctx = SpanContext {
        service_name: "checkout".into(),
        pid: 4242,
        cgroup_id: 0,
        trace_id: mint_id(16, seed),
        span_id: mint_id(8, seed ^ 0xA5A5_A5A5),
        // A representative resolved peer — the service-map edge's destination.
        peer: Some("10.0.0.5:5432".to_string()),
    };
    let signal = to_request_signal(&record, &ctx);

    let mut red = RedAggregator::new();
    red.observe("checkout", &record);
    let red_json = red
        .drain()
        .first()
        .map(|e| String::from_utf8_lossy(&e.to_json()).into_owned())
        .unwrap_or_default();

    out.push_str(&format!("\n### {name}\n"));
    out.push_str(&format!("  captured  request : {}\n", preview(req)));
    if !resp.is_empty() {
        out.push_str(&format!("  captured response : {}\n", preview(resp)));
    }
    out.push_str("  RequestSignal (span):\n");
    out.push_str(&format!(
        "    trace_id        = {}\n",
        hexs(&signal.trace_id)
    ));
    out.push_str(&format!(
        "    span_id         = {}\n",
        hexs(&signal.span_id)
    ));
    out.push_str(&format!(
        "    parent_span_id  = {} (spanlet — empty until trace-context)\n",
        hexs(&signal.parent_span_id)
    ));
    out.push_str(&format!(
        "    service_name    = {:?}\n",
        signal.service_name
    ));
    out.push_str(&format!("    operation       = {:?}\n", signal.operation));
    out.push_str(&format!(
        "    start_unix_nano = {}\n",
        signal.start_unix_nano
    ));
    out.push_str(&format!(
        "    duration_nano   = {} ({} ms)\n",
        signal.duration_nano,
        signal.duration_nano as f64 / 1e6
    ));
    out.push_str(&format!("    status_code     = {}\n", signal.status_code));
    out.push_str(&format!("    pid             = {}\n", signal.pid));
    out.push_str(&format!("    cgroup_id       = {}\n", signal.cgroup_id));
    out.push_str(&format!("    attributes      = {:?}\n", signal.attributes));
    out.push_str(&format!("  RED metric entry  : {red_json}\n"));
}

// ── protocol byte builders (mirroring each parser's own test construction) ──────

fn pg_msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = (4 + body.len()) as u32;
    let mut v = vec![tag];
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(body);
    v
}
fn pg_query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    pg_msg(b'Q', &body)
}
fn pg_command_complete(tag: &str) -> Vec<u8> {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    pg_msg(b'C', &body)
}

fn my_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, seq];
    p.extend_from_slice(payload);
    p
}
fn my_query(sql: &str) -> Vec<u8> {
    let mut payload = vec![0x03]; // COM_QUERY
    payload.extend_from_slice(sql.as_bytes());
    my_packet(0, &payload)
}
fn my_ok() -> Vec<u8> {
    my_packet(1, &[0x00, 0x00, 0x00]) // OK packet
}

fn cass_frame(version: u8, stream: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![version, 0];
    v.extend_from_slice(&stream.to_be_bytes());
    v.push(opcode);
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}
fn cass_query_body(cql: &str) -> Vec<u8> {
    let mut b = (cql.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(cql.as_bytes());
    b
}

fn dns_message(id: u16, flags: u16, labels: &[&str], qtype: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&0u16.to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes()); // nscount
    m.extend_from_slice(&0u16.to_be_bytes()); // arcount
    for l in labels {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    m
}

fn amqp_method(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = class_id.to_be_bytes().to_vec();
    payload.extend_from_slice(&method_id.to_be_bytes());
    payload.extend_from_slice(args);
    let mut v = vec![1u8]; // FRAME_METHOD
    v.extend_from_slice(&channel.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(&payload);
    v.push(0xCE); // FRAME_END
    v
}

fn bson_doc(elems: &[u8]) -> Vec<u8> {
    let len = (4 + elems.len() + 1) as i32;
    let mut v = len.to_le_bytes().to_vec();
    v.extend_from_slice(elems);
    v.push(0);
    v
}
fn bson_string(key: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x02];
    v.extend_from_slice(key.as_bytes());
    v.push(0);
    v.extend_from_slice(&((value.len() + 1) as i32).to_le_bytes());
    v.extend_from_slice(value.as_bytes());
    v.push(0);
    v
}
fn bson_double(key: &str, value: f64) -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend_from_slice(key.as_bytes());
    v.push(0);
    v.extend_from_slice(&value.to_le_bytes());
    v
}
fn mongo_message(request_id: i32, response_to: i32, body: &[u8]) -> Vec<u8> {
    let len = (16 + body.len()) as i32;
    let mut v = len.to_le_bytes().to_vec();
    v.extend_from_slice(&request_id.to_le_bytes());
    v.extend_from_slice(&response_to.to_le_bytes());
    v.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    v.extend_from_slice(body);
    v
}
fn mongo_op_msg(request_id: i32, response_to: i32, elems: &[u8]) -> Vec<u8> {
    let doc = bson_doc(elems);
    let mut body = 0u32.to_le_bytes().to_vec(); // flagBits
    body.push(0x00); // SECTION_BODY
    body.extend_from_slice(&doc);
    mongo_message(request_id, response_to, &body)
}

fn kafka_request(api_key: i16, api_version: i16, corr: i32, client_id: &str) -> Vec<u8> {
    let mut payload = api_key.to_be_bytes().to_vec();
    payload.extend_from_slice(&api_version.to_be_bytes());
    payload.extend_from_slice(&corr.to_be_bytes());
    payload.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    payload.extend_from_slice(client_id.as_bytes());
    let mut msg = (payload.len() as i32).to_be_bytes().to_vec();
    msg.extend_from_slice(&payload);
    msg
}
fn kafka_response(corr: i32, body: &[u8]) -> Vec<u8> {
    let mut payload = corr.to_be_bytes().to_vec();
    payload.extend_from_slice(body);
    let mut msg = (payload.len() as i32).to_be_bytes().to_vec();
    msg.extend_from_slice(&payload);
    msg
}

fn mqtt_varint(mut v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}
fn mqtt_packet(ptype: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![ptype << 4];
    v.extend_from_slice(&mqtt_varint(body.len()));
    v.extend_from_slice(body);
    v
}
fn mqtt_str(s: &str) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}
fn mqtt_connect() -> Vec<u8> {
    let mut body = mqtt_str("MQTT");
    body.push(4); // protocol level
    body.push(0x02); // clean session
    body.extend_from_slice(&60u16.to_be_bytes()); // keep-alive
    body.extend_from_slice(&mqtt_str("client-1"));
    mqtt_packet(1, &body) // CONNECT
}
fn mqtt_connack() -> Vec<u8> {
    mqtt_packet(2, &[0x00, 0x00]) // CONNACK, return code 0
}

fn amqp1_perf(channel: u16, code: u8, args: &[u8]) -> Vec<u8> {
    let mut perf = vec![0x00, 0x53, code]; // described-type performative descriptor
    perf.extend_from_slice(args);
    let size = (8 + perf.len()) as u32;
    let mut v = size.to_be_bytes().to_vec();
    v.push(2); // DOFF
    v.push(0x00); // FRAME_TYPE_AMQP
    v.extend_from_slice(&channel.to_be_bytes());
    v.extend_from_slice(&perf);
    v
}

fn tds_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
fn tds_packet(ptype: u8, payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u16;
    let mut v = vec![ptype, 0x01]; // type, status = EOM
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // SPID
    v.push(0); // PacketID
    v.push(0); // Window
    v.extend_from_slice(payload);
    v
}
fn tds_sql_batch(sql: &str) -> Vec<u8> {
    tds_packet(0x01, &tds_utf16le(sql)) // TYPE_SQL_BATCH
}
fn tds_done_ok() -> Vec<u8> {
    let mut tokens = vec![0xFD]; // TOKEN_DONE
    tokens.extend_from_slice(&0u16.to_le_bytes()); // status: final, no error
    tokens.extend_from_slice(&0u16.to_le_bytes()); // CurCmd
    tokens.extend_from_slice(&0u64.to_le_bytes()); // RowCount
    tds_packet(0x04, &tokens)
}

#[test]
fn golden_output_per_protocol() {
    let mut out = String::from("\n# EdgePacer eBPF L7 — Raw Exported Data (per protocol)\n");

    out.push_str("\n## HTTP / RPC\n");
    demo(
        &mut out,
        "HTTP/1.1",
        None,
        b"GET /api/users?page=2 HTTP/1.1\r\nHost: checkout\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        1,
    );

    out.push_str("\n## Databases\n");
    demo(
        &mut out,
        "PostgreSQL",
        Some("postgres"),
        &pg_query("SELECT * FROM users WHERE id = 1"),
        &pg_command_complete("SELECT 1"),
        2,
    );
    demo(
        &mut out,
        "MySQL",
        Some("mysql"),
        &my_query("SELECT * FROM users"),
        &my_ok(),
        3,
    );
    demo(
        &mut out,
        "Cassandra (CQL)",
        Some("cassandra"),
        &cass_frame(0x04, 0, 0x07, &cass_query_body("SELECT * FROM events")),
        &cass_frame(0x84, 0, 0x08, &[0, 0, 0, 1]),
        4,
    );
    demo(
        &mut out,
        "MongoDB",
        Some("mongodb"),
        &mongo_op_msg(100, 0, &bson_string("insert", "events")),
        &mongo_op_msg(9999, 100, &bson_double("ok", 1.0)),
        5,
    );
    demo(
        &mut out,
        "SQL Server (TDS)",
        Some("tds"),
        &tds_sql_batch("SELECT name FROM users"),
        &tds_done_ok(),
        12,
    );

    out.push_str("\n## Caches\n");
    demo(
        &mut out,
        "Redis (RESP)",
        Some("redis"),
        b"*2\r\n$3\r\nGET\r\n$7\r\nuser:42\r\n",
        b"$5\r\nAlice\r\n",
        6,
    );
    demo(
        &mut out,
        "Memcached",
        Some("memcached"),
        b"get user:42\r\n",
        b"VALUE user:42 0 5\r\nAlice\r\nEND\r\n",
        7,
    );

    out.push_str("\n## Messaging\n");
    demo(
        &mut out,
        "AMQP 0-9-1 (RabbitMQ)",
        Some("amqp"),
        &{
            let mut s = vec![b'A', b'M', b'Q', b'P', 0x00, 0x00, 0x09, 0x01];
            s.extend(amqp_method(1, 60, 40, b"\x00\x06orders"));
            s
        },
        b"",
        8,
    );
    demo(
        &mut out,
        "NATS",
        None,
        b"PUB orders.created 11\r\n{\"id\":\"o1\"}\r\n",
        b"",
        9,
    );
    demo(
        &mut out,
        "Kafka",
        Some("kafka"),
        &kafka_request(1, 11, 42, "checkout"),
        &kafka_response(42, b"\x00\x00\x00\x01arbitrary body"),
        13,
    );
    demo(
        &mut out,
        "MQTT",
        Some("mqtt"),
        &mqtt_connect(),
        &mqtt_connack(),
        14,
    );
    demo(
        &mut out,
        "AMQP 1.0",
        None,
        &{
            let mut s = vec![b'A', b'M', b'Q', b'P', 0x00, 0x01, 0x00, 0x00];
            s.extend(amqp1_perf(0, 0x14, b"transfer-args"));
            s
        },
        b"",
        15,
    );

    out.push_str("\n## Naming\n");
    demo(
        &mut out,
        "DNS",
        None,
        &dns_message(0xABCD, 0x0100, &["example", "com"], 1),
        &dns_message(0xABCD, 0x8180, &["example", "com"], 1),
        10,
    );

    out.push_str("\n## Mail\n");
    demo(
        &mut out,
        "SMTP",
        Some("smtp"),
        b"MAIL FROM:<orders@checkout.io>\r\n",
        b"250 2.1.0 Ok\r\n",
        11,
    );

    eprintln!("{out}");
}
