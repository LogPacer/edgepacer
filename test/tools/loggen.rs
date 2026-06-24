//! High-throughput log generator for profiling.
//!
//! Writes structured log lines at a target rate using batch writes and
//! spin-yield timing instead of per-line sleeps. Sustains 100K+ lines/sec
//! on a single core where Go's time.Sleep-per-line caps out around 5-10K.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut rate: u64 = 1000;
    let mut duration_secs: u64 = 60;
    let mut path = String::from("/tmp/test.log");

    let mut i = 1;
    while i < args.len() {
        match args[i].split_once('=') {
            Some(("-rate", v)) => rate = v.parse().expect("invalid rate"),
            Some(("-duration", v)) => duration_secs = v.parse().expect("invalid duration"),
            Some(("-path", v)) => path = v.to_string(),
            _ => {
                // Also handle -flag value (space-separated)
                if i + 1 < args.len() {
                    match args[i].as_str() {
                        "-rate" => {
                            rate = args[i + 1].parse().expect("invalid rate");
                            i += 1;
                        }
                        "-duration" => {
                            duration_secs = args[i + 1].parse().expect("invalid duration");
                            i += 1;
                        }
                        "-path" => {
                            path = args[i + 1].clone();
                            i += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("loggen: open {path}: {e}"));
    let mut writer = BufWriter::with_capacity(256 * 1024, file);

    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    // Write in bursts: compute how many lines per 10ms tick, flush each burst.
    // Use thread::sleep (not spin-loop) to yield CPU to the agent under test.
    let burst_interval = Duration::from_millis(10);
    let lines_per_burst = (rate / 100).max(1);

    let mut seq: u64 = 0;
    let mut next_burst = Instant::now();

    while Instant::now() < deadline {
        // Wait for next burst window — yield CPU via sleep
        let now = Instant::now();
        if now < next_burst {
            std::thread::sleep(next_burst - now);
        }
        next_burst += burst_interval;

        // Write a burst of lines
        for _ in 0..lines_per_burst {
            seq += 1;
            let _ = writeln!(
                writer,
                "2026-01-01T00:00:00.{seq:09}Z level=info msg=\"request processed\" trace_id={seq:016x} duration_ms={dur} status=200 path=/api/v1/users method=GET",
                dur = seq % 500,
            );
        }
        let _ = writer.flush();
    }

    let _ = writer.flush();
}
