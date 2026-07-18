//! Reproducible raw-vs-gzip benchmark for the logpacer-wire transport.
//!
//! Run `mock-logrelay` as a separate process, then run this tool on each
//! rollout host class. The gzip lane uses EdgePacer's production `Shipper`;
//! the raw lane is the pre-gzip baseline. Both replay the same deterministic
//! corpus at the same fixed request rate.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use edgepacer::counters::AgentCounters;
use edgepacer::retry::RetryPolicy;
use edgepacer::shipper::{ShipResult, Shipper};
use logpacer_wire::{
    EbpfEventKind, EventEnvelope, NetworkFlow, RoutedBatch, WireEbpfBatch, WireEbpfEvent,
    WireLogBatch, WireLogEvent, WireMetricBatch, WireRequest, WireResponse, WireTraceBatch,
    routed_batch, wire_ebpf_event, wire_log_event,
};
use prost::Message;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;

const CORPUS_VERSION: &str = "wire-gzip-v1";
const MEDIAN_TARGET_BYTES: usize = 256 * 1024;
const NEAR_CAP_TARGET_BYTES: usize = 15 * 1024 * 1024 / 4;

const MIN_EGRESS_REDUCTION_PERCENT: f64 = 20.0;
const MAX_P95_LATENCY_REGRESSION_PERCENT: f64 = 10.0;
const MAX_CPU_INCREASE_PERCENTAGE_POINTS: f64 = 0.5;

// Match the Linux agent binary's allocator and decay policy so the CPU result
// covers the same allocation path used for production gzip bodies.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
static malloc_conf: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0\0";

#[derive(Parser)]
#[command(about = "Replay the versioned logpacer-wire corpus through raw and gzip transports")]
struct Args {
    /// Dual-accept LogRelay-compatible endpoint.
    #[arg(long, default_value = "http://127.0.0.1:4317/v1/logpacer-wire")]
    endpoint: String,

    /// Fleet host class represented by this run (recorded verbatim).
    #[arg(long)]
    host_class: String,

    /// Number of complete 12-case corpus replays per transport.
    #[arg(long, default_value_t = 10)]
    cycles: u32,

    /// Fixed interval between request starts, shared by raw and gzip.
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SignalKind {
    Log,
    Metric,
    Trace,
    Ebpf,
}

impl SignalKind {
    const ALL: [Self; 4] = [Self::Log, Self::Metric, Self::Trace, Self::Ebpf];

    fn name(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Metric => "metric",
            Self::Trace => "trace",
            Self::Ebpf => "ebpf",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SizeClass {
    Tiny,
    Median,
    NearCap,
}

impl SizeClass {
    const ALL: [Self; 3] = [Self::Tiny, Self::Median, Self::NearCap];

    fn target_bytes(self) -> Option<usize> {
        match self {
            Self::Tiny => None,
            Self::Median => Some(MEDIAN_TARGET_BYTES),
            Self::NearCap => Some(NEAR_CAP_TARGET_BYTES),
        }
    }
}

struct CorpusCase {
    signal: SignalKind,
    size: SizeClass,
    records: u32,
    body: Vec<u8>,
}

#[derive(Serialize)]
struct CorpusCaseReport {
    signal: SignalKind,
    size: SizeClass,
    records: u32,
    logical_protobuf_bytes: usize,
    gzip_body_bytes: usize,
    egress_reduction_percent: f64,
}

#[derive(Serialize)]
struct ModeReport {
    requests: usize,
    logical_protobuf_bytes: u64,
    request_body_bytes: u64,
    p95_ship_latency_ms: f64,
    process_cpu_percent: f64,
}

#[derive(Serialize)]
struct Thresholds {
    min_egress_reduction_percent: f64,
    max_p95_latency_regression_percent: f64,
    max_cpu_increase_percentage_points: f64,
}

#[derive(Serialize)]
struct Verdict {
    egress_reduction_percent: f64,
    p95_latency_regression_percent: f64,
    cpu_increase_percentage_points: f64,
    egress_pass: bool,
    latency_pass: bool,
    cpu_pass: bool,
    pass: bool,
}

#[derive(Serialize)]
struct Report {
    corpus_version: &'static str,
    host_class: String,
    architecture: &'static str,
    cycles: u32,
    request_interval_ms: u64,
    corpus: Vec<CorpusCaseReport>,
    raw: ModeReport,
    gzip: ModeReport,
    thresholds: Thresholds,
    verdict: Verdict,
}

#[derive(Clone, Copy)]
enum Lane<'a> {
    Raw {
        client: &'a reqwest::Client,
        endpoint: &'a str,
    },
    Gzip {
        shipper: &'a Shipper,
        counters: &'a AgentCounters,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.cycles == 0 {
        bail!("--cycles must be greater than zero");
    }
    if args.interval_ms == 0 {
        bail!("--interval-ms must be greater than zero");
    }

    let corpus = build_corpus()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(2)
        .build()
        .context("build raw benchmark HTTP client")?;
    let warmup_counters = AgentCounters::new();
    let warmup_shipper = Shipper::with_counters(
        &args.endpoint,
        "benchmark-archive",
        "benchmark-repo",
        None,
        warmup_counters.clone(),
    )
    .context("build warmup gzip shipper")?;

    let corpus_gzip_body_bytes = warm_up(
        &client,
        &warmup_shipper,
        &warmup_counters,
        &args.endpoint,
        &corpus,
    )
    .await?;

    let interval = Duration::from_millis(args.interval_ms);
    let raw = run_mode(
        Lane::Raw {
            client: &client,
            endpoint: &args.endpoint,
        },
        &corpus,
        args.cycles,
        interval,
    )
    .await?;

    let gzip_counters = AgentCounters::new();
    let gzip_shipper = Shipper::with_counters(
        &args.endpoint,
        "benchmark-archive",
        "benchmark-repo",
        None,
        gzip_counters.clone(),
    )
    .context("build production gzip shipper")?;
    let gzip = run_mode(
        Lane::Gzip {
            shipper: &gzip_shipper,
            counters: &gzip_counters,
        },
        &corpus,
        args.cycles,
        interval,
    )
    .await?;

    let counted_gzip_bytes = gzip_counters.snapshot().bytes_sent;
    if counted_gzip_bytes != gzip.request_body_bytes {
        bail!(
            "production compressed-byte counter mismatch: counter={counted_gzip_bytes}, measured={}",
            gzip.request_body_bytes
        );
    }

    let verdict = evaluate_verdict(&raw, &gzip);

    let report = Report {
        corpus_version: CORPUS_VERSION,
        host_class: args.host_class,
        architecture: std::env::consts::ARCH,
        cycles: args.cycles,
        request_interval_ms: args.interval_ms,
        corpus: corpus
            .iter()
            .zip(corpus_gzip_body_bytes)
            .map(|(case, gzip_body_bytes)| case_report(case, gzip_body_bytes))
            .collect(),
        raw,
        gzip,
        thresholds: Thresholds {
            min_egress_reduction_percent: MIN_EGRESS_REDUCTION_PERCENT,
            max_p95_latency_regression_percent: MAX_P95_LATENCY_REGRESSION_PERCENT,
            max_cpu_increase_percentage_points: MAX_CPU_INCREASE_PERCENTAGE_POINTS,
        },
        verdict,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize benchmark report")?
    );

    if !report.verdict.pass {
        bail!("wire gzip net-benefit thresholds failed");
    }
    Ok(())
}

async fn warm_up(
    client: &reqwest::Client,
    gzip_shipper: &Shipper,
    gzip_counters: &AgentCounters,
    endpoint: &str,
    corpus: &[CorpusCase],
) -> Result<Vec<usize>> {
    for case in corpus {
        send_raw(client, endpoint, case).await?;
    }
    let mut gzip_body_bytes = Vec::with_capacity(corpus.len());
    for case in corpus {
        gzip_body_bytes.push(
            usize::try_from(send_gzip(gzip_shipper, gzip_counters, case).await?)
                .context("compressed corpus body length exceeds usize")?,
        );
    }
    Ok(gzip_body_bytes)
}

async fn run_mode(
    lane: Lane<'_>,
    corpus: &[CorpusCase],
    cycles: u32,
    interval: Duration,
) -> Result<ModeReport> {
    let request_count = corpus.len() * cycles as usize;
    let logical_bytes_per_cycle: u64 = corpus.iter().map(|case| case.body.len() as u64).sum();
    let mut body_bytes = 0u64;
    let mut latencies = Vec::with_capacity(request_count);
    let started = Instant::now();
    let cpu_started = process_cpu_seconds()?;

    for ordinal in 0..request_count {
        let scheduled = started + interval * ordinal as u32;
        tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled)).await;

        let case = &corpus[ordinal % corpus.len()];
        let request_started = Instant::now();
        body_bytes += match lane {
            Lane::Raw { client, endpoint } => send_raw(client, endpoint, case).await?,
            Lane::Gzip { shipper, counters } => send_gzip(shipper, counters, case).await?,
        };
        latencies.push(request_started.elapsed());
    }

    tokio::time::sleep_until(tokio::time::Instant::from_std(
        started + interval * request_count as u32,
    ))
    .await;
    let wall_seconds = started.elapsed().as_secs_f64();
    let cpu_seconds = process_cpu_seconds()? - cpu_started;

    Ok(ModeReport {
        requests: request_count,
        logical_protobuf_bytes: logical_bytes_per_cycle * u64::from(cycles),
        request_body_bytes: body_bytes,
        p95_ship_latency_ms: percentile_95_ms(&mut latencies),
        process_cpu_percent: cpu_seconds / wall_seconds * 100.0,
    })
}

async fn send_raw(client: &reqwest::Client, endpoint: &str, case: &CorpusCase) -> Result<u64> {
    let response = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(case.body.clone())
        .send()
        .await
        .with_context(|| format!("send raw {} corpus request", case.signal.name()))?;
    let status = response.status();
    let bytes = response.bytes().await.context("read raw wire response")?;
    if !status.is_success() {
        bail!(
            "raw {} corpus request returned {status}: {}",
            case.signal.name(),
            String::from_utf8_lossy(&bytes)
        );
    }
    let response = WireResponse::decode(bytes).context("decode raw wire response")?;
    validate_raw_acceptance(case, response)?;
    Ok(case.body.len() as u64)
}

async fn send_gzip(shipper: &Shipper, counters: &AgentCounters, case: &CorpusCase) -> Result<u64> {
    let bytes_before = counters.snapshot().bytes_sent;
    let result = shipper
        .send_with_retry_policy(
            &case.body,
            RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .await
        .with_context(|| format!("send gzip {} corpus request", case.signal.name()))?;
    match result {
        ShipResult::Accepted { count } if count == case.records => {}
        ShipResult::Accepted { count } => bail!(
            "gzip {} corpus request accepted {count}, expected {}",
            case.signal.name(),
            case.records
        ),
        ShipResult::Rejected {
            accepted,
            rejected,
            message,
        } => bail!(
            "gzip {} corpus request rejected: accepted={accepted}, rejected={rejected}, message={message}",
            case.signal.name()
        ),
    }
    counters
        .snapshot()
        .bytes_sent
        .checked_sub(bytes_before)
        .context("production compressed-byte counter moved backwards")
}

fn validate_raw_acceptance(case: &CorpusCase, response: WireResponse) -> Result<()> {
    if response.accepted != case.records || response.rejected != 0 {
        bail!(
            "raw {} corpus request returned accepted={}, rejected={}, expected accepted={}",
            case.signal.name(),
            response.accepted,
            response.rejected,
            case.records
        );
    }
    Ok(())
}

fn build_corpus() -> Result<Vec<CorpusCase>> {
    let mut corpus = Vec::with_capacity(12);
    for signal in SignalKind::ALL {
        for size in SizeClass::ALL {
            corpus.push(build_case(signal, size)?);
        }
    }
    Ok(corpus)
}

fn build_case(signal: SignalKind, size: SizeClass) -> Result<CorpusCase> {
    let records = match size.target_bytes() {
        None => 1,
        Some(target) => {
            let sample_records = 128;
            let sample_len = encode_request(signal, sample_records)?.len();
            let initial = (target.saturating_mul(sample_records) / sample_len).max(1);
            let initial_len = encode_request(signal, initial)?.len();
            (initial.saturating_mul(target) / initial_len).max(1)
        }
    };
    let body = encode_request(signal, records)?;
    let records = u32::try_from(records).context("corpus record count exceeds u32")?;
    Ok(CorpusCase {
        signal,
        size,
        records,
        body,
    })
}

fn encode_request(signal: SignalKind, records: usize) -> Result<Vec<u8>> {
    let payload = match signal {
        SignalKind::Log => routed_batch::Payload::Logs(WireLogBatch {
            entries: (0..records).map(log_entry).collect(),
        }),
        SignalKind::Metric => routed_batch::Payload::Metrics(WireMetricBatch {
            entries_json: (0..records).map(metric_entry).collect(),
        }),
        SignalKind::Trace => routed_batch::Payload::Traces(WireTraceBatch {
            entries_json: (0..records).map(trace_entry).collect(),
        }),
        SignalKind::Ebpf => routed_batch::Payload::Ebpf(WireEbpfBatch {
            entries: (0..records).map(ebpf_entry).collect(),
        }),
    };
    let request = WireRequest {
        batches: vec![RoutedBatch {
            archive_id: "benchmark-archive".to_string(),
            repo_id: format!("benchmark-{}", signal.name()),
            schema_version: 1,
            payload: Some(payload),
        }],
    };
    Ok(request.encode_to_vec())
}

fn envelope(index: usize) -> EventEnvelope {
    EventEnvelope {
        logtime_ms: Some(1_752_835_200_000 + index as i64),
        source_at_ms: Some(1_752_835_199_900 + index as i64),
        metadata_json: format!(
            r#"{{"resource_identifier":"canary-{:03}","environment":"production"}}"#,
            index % 32
        )
        .into_bytes(),
    }
}

fn log_entry(index: usize) -> WireLogEvent {
    let body = format!(
        r#"{{"level":"info","service":"checkout","route":"/api/orders/{{id}}","request_id":"req-{index:08}","tenant":"customer-{:03}","status":200,"duration_ms":{},"message":"order request completed after database and cache lookup"}}"#,
        index % 128,
        8 + index % 41
    )
    .into_bytes();
    WireLogEvent {
        envelope: Some(envelope(index)),
        body: Some(wire_log_event::Body::EntryJson(body)),
    }
}

fn metric_entry(index: usize) -> Vec<u8> {
    format!(
        r#"{{"logtime":{},"resource_id":"canary-{:03}","host_cpu_percent":{:.1},"host_memory_used_bytes":{},"agent_cpu_percent":{:.2},"agent_memory_rss_bytes":{},"agent_bytes_sent_total":{},"service":"edgepacer"}}"#,
        1_752_835_200_000usize + index,
        index % 32,
        20.0 + (index % 500) as f64 / 10.0,
        1_500_000_000usize + index * 4096,
        0.5 + (index % 100) as f64 / 100.0,
        38_000_000usize + index * 128,
        index * 16_384
    )
    .into_bytes()
}

fn trace_entry(index: usize) -> Vec<u8> {
    format!(
        r#"{{"trace_id":"{index:032x}","span_id":"{index:016x}","parent_span_id":"{:016x}","service_name":"checkout-api","name":"POST /api/orders","start_time_unix_nano":{},"end_time_unix_nano":{},"status":{{"code":"OK"}},"attributes":{{"http.request.method":"POST","http.response.status_code":200,"server.address":"api.internal","deployment.environment":"production","customer.id":"customer-{:03}"}}}}"#,
        index.saturating_sub(1),
        1_752_835_200_000_000_000usize + index * 1_000_000,
        1_752_835_200_008_000_000usize + index * 1_000_000,
        index % 128
    )
    .into_bytes()
}

fn ebpf_entry(index: usize) -> WireEbpfEvent {
    WireEbpfEvent {
        envelope: Some(envelope(index)),
        kind: EbpfEventKind::NetworkFlow as i32,
        event: Some(wire_ebpf_event::Event::Flow(NetworkFlow {
            saddr: vec![10, 0, (index / 256) as u8, index as u8],
            daddr: vec![10, 1, (index / 128) as u8, (index * 3) as u8],
            sport: 32_768 + (index % 24_000) as u32,
            dport: [443, 5432, 6379, 8080][index % 4],
            protocol: 6,
            bytes_tx: 1_024 + (index * 97) as u64,
            bytes_rx: 4_096 + (index * 193) as u64,
            packets_tx: 8 + (index % 256) as u64,
            packets_rx: 12 + (index % 512) as u64,
            pid: 1_000 + (index % 4_000) as u32,
            cgroup_id: 9_000_000 + (index % 256) as u64,
            netns_ino: 4_026_531_840 + (index % 1_024) as u32,
            direction: 1 + (index % 2) as u32,
        })),
    }
}

fn case_report(case: &CorpusCase, gzip_body_bytes: usize) -> CorpusCaseReport {
    CorpusCaseReport {
        signal: case.signal,
        size: case.size,
        records: case.records,
        logical_protobuf_bytes: case.body.len(),
        gzip_body_bytes,
        egress_reduction_percent: percent_reduction(case.body.len() as u64, gzip_body_bytes as u64),
    }
}

fn evaluate_verdict(raw: &ModeReport, gzip: &ModeReport) -> Verdict {
    let egress_reduction_percent =
        percent_reduction(raw.request_body_bytes, gzip.request_body_bytes);
    let p95_latency_regression_percent =
        percent_change(raw.p95_ship_latency_ms, gzip.p95_ship_latency_ms);
    let cpu_increase_percentage_points = gzip.process_cpu_percent - raw.process_cpu_percent;

    // Compare the source measurements directly so exact allowed boundaries do
    // not fail because the derived percentage rounded a few ulps upward/downward.
    let egress_pass = gzip.request_body_bytes as f64
        <= raw.request_body_bytes as f64 * (1.0 - MIN_EGRESS_REDUCTION_PERCENT / 100.0);
    let latency_pass = gzip.p95_ship_latency_ms
        <= raw.p95_ship_latency_ms * (1.0 + MAX_P95_LATENCY_REGRESSION_PERCENT / 100.0);
    let cpu_pass = cpu_increase_percentage_points <= MAX_CPU_INCREASE_PERCENTAGE_POINTS;

    Verdict {
        egress_reduction_percent,
        p95_latency_regression_percent,
        cpu_increase_percentage_points,
        egress_pass,
        latency_pass,
        cpu_pass,
        pass: egress_pass && latency_pass && cpu_pass,
    }
}

fn percentile_95_ms(values: &mut [Duration]) -> f64 {
    values.sort_unstable();
    let index = (values.len() * 95).div_ceil(100).saturating_sub(1);
    values[index].as_secs_f64() * 1_000.0
}

fn percent_reduction(before: u64, after: u64) -> f64 {
    (1.0 - after as f64 / before as f64) * 100.0
}

fn percent_change(before: f64, after: f64) -> f64 {
    (after / before - 1.0) * 100.0
}

#[cfg(unix)]
fn process_cpu_seconds() -> Result<f64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the pointed-to rusage on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("read process CPU usage");
    }
    // SAFETY: a successful getrusage call initialized usage.
    let usage = unsafe { usage.assume_init() };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    Ok(user + system)
}

#[cfg(not(unix))]
fn process_cpu_seconds() -> Result<f64> {
    bail!("wire-gzip-bench CPU sampling currently supports Unix rollout hosts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mode(body_bytes: u64, p95_ms: f64, cpu_percent: f64) -> ModeReport {
        ModeReport {
            requests: 1,
            logical_protobuf_bytes: 1_000,
            request_body_bytes: body_bytes,
            p95_ship_latency_ms: p95_ms,
            process_cpu_percent: cpu_percent,
        }
    }

    #[test]
    fn exact_release_thresholds_pass() {
        let verdict = evaluate_verdict(&mode(1_000, 100.0, 1.0), &mode(800, 110.0, 1.5));

        assert!(verdict.egress_pass);
        assert!(verdict.latency_pass);
        assert!(verdict.cpu_pass);
        assert!(verdict.pass);
    }

    #[test]
    fn each_release_threshold_fails_independently() {
        let raw = mode(1_000, 100.0, 1.0);

        let egress = evaluate_verdict(&raw, &mode(801, 100.0, 1.0));
        assert!(!egress.egress_pass);
        assert!(egress.latency_pass);
        assert!(egress.cpu_pass);
        assert!(!egress.pass);

        let latency = evaluate_verdict(&raw, &mode(800, 110.01, 1.0));
        assert!(latency.egress_pass);
        assert!(!latency.latency_pass);
        assert!(latency.cpu_pass);
        assert!(!latency.pass);

        let cpu = evaluate_verdict(&raw, &mode(800, 100.0, 1.500_001));
        assert!(cpu.egress_pass);
        assert!(cpu.latency_pass);
        assert!(!cpu.cpu_pass);
        assert!(!cpu.pass);
    }

    #[test]
    fn percentile_95_uses_the_nearest_rank() {
        let mut values = (1..=100).map(Duration::from_millis).collect::<Vec<_>>();

        assert_eq!(percentile_95_ms(&mut values), 95.0);
    }

    #[test]
    fn corpus_has_every_signal_and_size_combination() {
        let corpus = build_corpus().unwrap();

        assert_eq!(corpus.len(), 12);
        for signal in SignalKind::ALL {
            assert_eq!(
                corpus
                    .iter()
                    .filter(|case| case.signal == signal)
                    .map(|case| case.size)
                    .collect::<Vec<_>>(),
                vec![SizeClass::Tiny, SizeClass::Median, SizeClass::NearCap]
            );
        }
    }

    #[tokio::test]
    async fn gzip_lane_fails_on_first_retryable_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let counters = AgentCounters::new();
        let shipper = Shipper::with_counters(
            &server.uri(),
            "benchmark-archive",
            "benchmark-repo",
            None,
            counters.clone(),
        )
        .unwrap();
        let case = build_case(SignalKind::Log, SizeClass::Tiny).unwrap();

        assert!(send_gzip(&shipper, &counters, &case).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(counters.snapshot().bytes_sent, 0);
    }
}
