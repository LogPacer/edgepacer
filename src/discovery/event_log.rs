//! Windows Event Log channel discovery via `wevtutil`.
//!
//! Enumerates channels (`wevtutil el`) and curates to the **records-bearing**
//! set plus the classic channels, so the review queue surfaces real log sources
//! instead of the ~1000 mostly-empty channels Windows defines. Surfacing all of
//! them is the 266-services mistake again — an un-triageable queue.
//!
//! "Records-bearing" needs a per-channel count probe (`wevtutil gli`) — the cost
//! center — so probes are concurrency-capped with a short timeout and a
//! candidate cap; the classics are always included without depending on a probe.
//! Operators can still collect any channel by name even if discovery didn't
//! surface it (the collect path takes an arbitrary channel).

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use tokio::process::Command;
use tracing::{debug, warn};

use super::EventLogChannel;

/// Channels always surfaced even when quiet — the ones an operator expects.
const CLASSIC_CHANNELS: &[&str] = &[
    "Application",
    "System",
    "Security",
    "Setup",
    "ForwardedEvents",
];
/// Bound on concurrent `wevtutil gli` probes (each is a process spawn).
const PROBE_CONCURRENCY: usize = 8;
/// Per-probe timeout — a wedged channel never stalls the whole scan.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Cap on non-classic candidates probed per scan. The rest are skipped (and
/// logged — never silently dropped). The classics are always probed on top.
const MAX_PROBED_CANDIDATES: usize = 400;

/// Discover curated Windows Event Log channels.
///
/// Returns an empty vec on non-Windows hosts. Failures on Windows are reported
/// to the caller so the census can carry the backend error.
pub async fn discover_channels() -> Result<Vec<EventLogChannel>, String> {
    if std::env::consts::OS != "windows" {
        debug!("windows event log discovery skipped on non-windows host");
        return Ok(Vec::new());
    }

    let all = list_channels().await?;

    // Drop high-volume trace channels (Debug/Analytic) by name — usually
    // disabled, never useful in the review queue.
    let candidates: Vec<String> = all.into_iter().filter(|c| !is_trace_channel(c)).collect();

    // Always probe the classics; probe up to a cap of the remaining candidates.
    let (mut probe_set, others): (Vec<String>, Vec<String>) =
        candidates.into_iter().partition(|c| is_classic(c));

    let mut skipped = 0usize;
    for (i, channel) in others.into_iter().enumerate() {
        if i < MAX_PROBED_CANDIDATES {
            probe_set.push(channel);
        } else {
            skipped += 1;
        }
    }
    if skipped > 0 {
        warn!(
            skipped,
            probed = probe_set.len(),
            "event log channel probe capped; un-probed candidates skipped this scan"
        );
    }

    let counts = probe_record_counts(&probe_set).await;
    let channels = select_channels(&probe_set, &counts);
    debug!(
        count = channels.len(),
        "discovered windows event log channels"
    );
    Ok(channels)
}

/// Keep a probed channel when it is a classic (always) or has records.
/// Pure so the curation rule is unit-testable without spawning `wevtutil`.
fn select_channels(probed: &[String], counts: &BTreeMap<String, u64>) -> Vec<EventLogChannel> {
    let mut channels: Vec<EventLogChannel> = probed
        .iter()
        .filter_map(|channel| {
            let record_count = counts.get(channel).copied().unwrap_or(0);
            (is_classic(channel) || record_count > 0).then(|| EventLogChannel {
                channel: channel.clone(),
                record_count,
            })
        })
        .collect();
    channels.sort_by(|a, b| a.channel.cmp(&b.channel));
    channels
}

async fn list_channels() -> Result<Vec<String>, String> {
    let output = Command::new("wevtutil")
        .arg("el")
        .output()
        .await
        .map_err(|error| format!("wevtutil el spawn failed: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("wevtutil el exit {}: {stderr}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

async fn probe_record_counts(channels: &[String]) -> BTreeMap<String, u64> {
    stream::iter(channels.iter().cloned())
        .map(|channel| async move {
            let count = probe_record_count(&channel).await.unwrap_or(0);
            (channel, count)
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect::<BTreeMap<String, u64>>()
        .await
}

async fn probe_record_count(channel: &str) -> Option<u64> {
    let output = tokio::time::timeout(
        PROBE_TIMEOUT,
        Command::new("wevtutil").args(["gli", channel]).output(),
    )
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    parse_record_count(&String::from_utf8_lossy(&output.stdout))
}

/// `wevtutil gli <channel>` prints `numberOfLogRecords: <N>` among its fields.
fn parse_record_count(gli_output: &str) -> Option<u64> {
    gli_output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("numberOfLogRecords:")
            .and_then(|value| value.trim().parse().ok())
    })
}

fn is_trace_channel(channel: &str) -> bool {
    channel.ends_with("/Debug") || channel.ends_with("/Analytic")
}

fn is_classic(channel: &str) -> bool {
    CLASSIC_CHANNELS
        .iter()
        .any(|classic| classic.eq_ignore_ascii_case(channel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_number_of_log_records() {
        let gli =
            "name: Application\nenabled: true\nnumberOfLogRecords: 12345\noldestRecordNumber: 1\n";
        assert_eq!(parse_record_count(gli), Some(12345));
        assert_eq!(parse_record_count("name: Empty\nenabled: true\n"), None);
    }

    #[test]
    fn drops_debug_and_analytic_trace_channels() {
        assert!(is_trace_channel("Microsoft-Windows-WinRM/Debug"));
        assert!(is_trace_channel("Microsoft-Windows-Kernel-WHEA/Analytic"));
        assert!(!is_trace_channel("Microsoft-Windows-WinRM/Operational"));
        assert!(!is_trace_channel("Application"));
    }

    #[test]
    fn classics_are_recognized_case_insensitively() {
        assert!(is_classic("Application"));
        assert!(is_classic("security"));
        assert!(!is_classic("Microsoft-Windows-WinRM/Operational"));
    }

    #[test]
    fn select_keeps_classics_always_and_others_only_with_records() {
        let probed = vec![
            "Application".to_string(), // classic, 0 records → kept
            "Microsoft-Windows-WinRM/Operational".to_string(), // non-classic, has records → kept
            "Microsoft-Windows-Idle/Operational".to_string(), // non-classic, 0 records → dropped
        ];
        let mut counts = BTreeMap::new();
        counts.insert("Microsoft-Windows-WinRM/Operational".to_string(), 42u64);
        // Application intentionally absent from counts (probe miss) → defaults 0.

        let selected = select_channels(&probed, &counts);
        let names: Vec<&str> = selected.iter().map(|c| c.channel.as_str()).collect();

        assert_eq!(
            names,
            vec!["Application", "Microsoft-Windows-WinRM/Operational"]
        );
        assert_eq!(selected[0].record_count, 0); // classic kept despite no records
        assert_eq!(selected[1].record_count, 42);
    }
}
