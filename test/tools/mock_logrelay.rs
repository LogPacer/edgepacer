//! Mock LogRelay — accepts logpacer_wire protobuf and tracks delivery stats.
//!
//! Used by the profiling harness as a sink endpoint. Accepts WireRequest
//! on POST /v1/logpacer-wire, responds with WireResponse, and serves
//! cumulative stats on GET /stats.

use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use logpacer_wire::{WireRequest, WireResponse, routed_batch, wire_log_event};
use prost::Message;

struct Stats {
    total_batches: AtomicU64,
    total_records: AtomicU64,
    total_bytes: AtomicU64,
    body_limit_bytes: usize,
    start_time: Instant,
    /// When set (MOCK_RELAY_DUMP=path), every received log line is appended
    /// here — lets a smoke test verify sequence coverage (gaps/duplicates).
    dump: Option<Mutex<std::fs::File>>,
}

fn dump_log_lines(stats: &Stats, request: &WireRequest) {
    let Some(ref dump) = stats.dump else {
        return;
    };
    let mut file = dump.lock().expect("dump file lock");
    for batch in &request.batches {
        let Some(routed_batch::Payload::Logs(logs)) = &batch.payload else {
            continue;
        };
        for entry in &logs.entries {
            if let Some(wire_log_event::Body::RawText(text)) = &entry.body {
                let _ = writeln!(file, "{text}");
            }
        }
    }
}

fn count_records(request: &WireRequest) -> u32 {
    request
        .batches
        .iter()
        .map(|batch| match &batch.payload {
            Some(routed_batch::Payload::Logs(logs)) => logs.entries.len() as u32,
            Some(routed_batch::Payload::Metrics(metrics)) => metrics.entries_json.len() as u32,
            Some(routed_batch::Payload::Graph(graph)) => graph.entries.len() as u32,
            Some(routed_batch::Payload::Traces(traces)) => traces.entries_json.len() as u32,
            Some(routed_batch::Payload::Ebpf(ebpf)) => ebpf.entries.len() as u32,
            None => 0,
        })
        .sum()
}

fn decode_wire_body<'a>(
    headers: &HeaderMap,
    body: &'a [u8],
    body_limit_bytes: usize,
) -> Result<Cow<'a, [u8]>, StatusCode> {
    match headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    {
        None => Ok(Cow::Borrowed(body)),
        Some(value) if value.eq_ignore_ascii_case("gzip") => {
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(body)
                .take(body_limit_bytes as u64 + 1)
                .read_to_end(&mut decoded)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            if decoded.len() > body_limit_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(Cow::Owned(decoded))
        }
        Some(_) => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }
}

async fn handle_ingest(
    State(stats): State<Arc<Stats>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Bytes, StatusCode> {
    let body_len = body.len() as u64;
    stats.total_bytes.fetch_add(body_len, Ordering::Relaxed);

    let decoded = decode_wire_body(&headers, &body, stats.body_limit_bytes)?;
    let request = WireRequest::decode(decoded.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let record_count = count_records(&request);
    dump_log_lines(&stats, &request);

    stats.total_batches.fetch_add(1, Ordering::Relaxed);
    stats
        .total_records
        .fetch_add(record_count as u64, Ordering::Relaxed);

    let response = WireResponse {
        accepted: record_count,
        rejected: 0,
        error_message: String::new(),
    };

    let mut buf = Vec::with_capacity(response.encoded_len());
    response.encode(&mut buf).unwrap();

    Ok(Bytes::from(buf))
}

async fn handle_stats(State(stats): State<Arc<Stats>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "total_batches": stats.total_batches.load(Ordering::Relaxed),
        "total_records": stats.total_records.load(Ordering::Relaxed),
        "total_bytes": stats.total_bytes.load(Ordering::Relaxed),
        "uptime_seconds": stats.start_time.elapsed().as_secs(),
    }))
}

async fn handle_health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4317);

    let body_limit_bytes: usize = std::env::var("MOCK_RELAY_BODY_LIMIT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        * 1024
        * 1024;

    let dump = std::env::var("MOCK_RELAY_DUMP").ok().map(|path| {
        eprintln!("  dumping received log lines to {path}");
        Mutex::new(
            std::fs::File::create(&path).unwrap_or_else(|e| panic!("create dump {path}: {e}")),
        )
    });

    let stats = Arc::new(Stats {
        total_batches: AtomicU64::new(0),
        total_records: AtomicU64::new(0),
        total_bytes: AtomicU64::new(0),
        body_limit_bytes,
        start_time: Instant::now(),
        dump,
    });

    let app = Router::new()
        .route("/v1/logpacer-wire", post(handle_ingest))
        .route("/stats", get(handle_stats))
        .route("/health", get(handle_health))
        // EdgePacer's adaptive batch scales to tens of thousands of entries
        // under backlog pressure, well past axum's 2 MB default body limit.
        // Default to a generous cap so the sink measures EdgePacer's drain rate,
        // not its own request-size policy; override via MOCK_RELAY_BODY_LIMIT_MB
        // to exercise EdgePacer's 413 shrink path against a constrained receiver.
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .with_state(stats);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("mock-logrelay listening on {addr}");
    eprintln!("  POST /v1/logpacer-wire  - Receive logpacer-wire protobuf");
    eprintln!("  GET  /stats             - Delivery statistics (JSON)");
    eprintln!("  GET  /health            - Health check");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    eprintln!("  body limit: {body_limit_bytes} bytes");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    #[test]
    fn wire_body_decoder_accepts_raw_and_gzip() {
        let encoded = b"wire body".to_vec();
        assert_eq!(
            decode_wire_body(&HeaderMap::new(), &encoded, encoded.len()).unwrap(),
            encoded
        );

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&encoded).unwrap();
        let gzip = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());

        assert_eq!(
            decode_wire_body(&headers, &gzip, encoded.len()).unwrap(),
            encoded
        );
        assert_eq!(
            decode_wire_body(&headers, &gzip, encoded.len() - 1),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }
}
