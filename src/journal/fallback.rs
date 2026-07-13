//! journalctl shell-out — fallback when sdjournal is unavailable.

use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::MultilineConfig;
use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;
use crate::streaming_multiline::StreamingEntryAssembler;

const ASSEMBLER_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Raw fields of one journal entry as parsed from journalctl's JSON output,
/// before normalization. Mirrors what the native backend reads from sdjournal:
/// cursor, MESSAGE bytes, and the entry's own realtime timestamp.
pub(crate) struct ParsedEntry {
    pub cursor: Option<String>,
    pub message_bytes: Vec<u8>,
    pub realtime_usec: Option<u64>,
}

/// Pull the most recent `max_lines` from journald for a systemd unit via journalctl.
///
/// Uses `--output=json` (not `--output=cat`) so each entry is one JSON object on
/// one physical line: a multi-line MESSAGE stays a single sample entry, matching
/// the native backend's one-string-per-entry behavior. Extraction goes through
/// the same seam as streaming, so a non-UTF8 MESSAGE is recovered rather than
/// dropped.
pub fn sample_unit_lines(unit: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("journalctl")
        .args([
            "-u",
            unit,
            "-n",
            &max_lines.to_string(),
            "--no-pager",
            "--output=json",
        ])
        .output()
        .map_err(|e| format!("journalctl spawn failed for {unit}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "journalctl exit {} for {unit}: {stderr}",
            output.status
        ));
    }

    Ok(extract_sample_lines(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Turn journalctl `--output=json` stdout into one message string per entry,
/// dropping blanks with the shared predicate. One entry → one string (embedded
/// newlines preserved), so `-n max_lines` bounds entries, not physical lines.
fn extract_sample_lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| super::decode_message(&parse_journald_json(line).message_bytes))
        .collect()
}

/// Stream logs from a systemd unit via journalctl into the streaming pipeline.
pub async fn stream_unit_logs(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    resume_cursor: Option<&str>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut args = vec![
        "-u".to_string(),
        unit.to_string(),
        "-f".to_string(),
        "--output=json".to_string(),
        "--no-pager".to_string(),
    ];

    if let Some(cursor) = resume_cursor {
        args.push(format!("--after-cursor={cursor}"));
        info!(
            unit,
            source_id, cursor, "resuming journald stream from cursor (journalctl)"
        );
    } else {
        args.push("-n".to_string());
        args.push("0".to_string());
        info!(
            unit,
            source_id, "starting journald stream from end (journalctl)"
        );
    }

    let mut child = match Command::new("journalctl")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!(unit, error = %e, "failed to spawn journalctl");
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            error!(unit, "journalctl stdout not captured");
            return;
        }
    };

    let mut reader = BufReader::new(stdout).lines();
    let mut assembler = match StreamingEntryAssembler::new(multiline) {
        Ok(assembler) => assembler,
        Err(error) => {
            error!(unit, source_id, error = %error, "invalid journald multiline pattern");
            return;
        }
    };
    let mut assembler_tick = tokio::time::interval(ASSEMBLER_CHECK_INTERVAL);
    assembler_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    assembler_tick.tick().await;

    let mut entries_processed: u64 = 0;
    let mut last_cursor: Option<String> = None;

    loop {
        tokio::select! {
            line_result = reader.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let parsed = parse_journald_json(&line);
                        // Malformed lines (no JSON, thus no timestamp) fall back to
                        // now(); every real journalctl JSON entry carries its own
                        // __REALTIME_TIMESTAMP and keeps its historical time.
                        let realtime_usec = parsed.realtime_usec.unwrap_or_else(now_usec);
                        let Some(entry) = super::normalize_entry(
                            &parsed.message_bytes,
                            realtime_usec,
                            parsed.cursor,
                        ) else {
                            continue;
                        };

                        if !super::enqueue_stream_entry(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            &mut assembler,
                            entry,
                        )
                        .await
                        {
                            warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                            break;
                        }
                    }
                    Ok(None) => {
                        info!(unit, entries = entries_processed, "journalctl stream ended");
                        break;
                    }
                    Err(e) => {
                        warn!(unit, error = %e, "journalctl read error");
                        break;
                    }
                }
            }
            _ = assembler_tick.tick() => {
                match assembler.check_timeout(handle).await {
                    Ok(emit) => {
                        if !super::record_emit(
                            handle,
                            source_id,
                            &mut entries_processed,
                            &mut last_cursor,
                            emit,
                        )
                        .await
                        {
                            warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                            break;
                        }
                    }
                    Err(_) => {
                        warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                        break;
                    }
                }
            }
            _ = shutdown.changed() => {
                info!(unit, "journald stream shutdown signal");
                break;
            }
        }
    }

    match assembler.flush(handle).await {
        Ok(emit) => {
            if !super::record_emit(
                handle,
                source_id,
                &mut entries_processed,
                &mut last_cursor,
                emit,
            )
            .await
            {
                return;
            }
        }
        Err(_) => {
            warn!(
                unit,
                "streaming pipeline actor gone, stopping journald stream"
            );
            return;
        }
    }

    if let Some(ref cursor) = last_cursor {
        handle
            .set_final_checkpoint(StreamingCheckpoint::journald(source_id, cursor))
            .await;
    }

    let _ = child.kill().await;

    info!(
        unit,
        source_id,
        total_entries = entries_processed,
        backend = "journalctl",
        "journald log streaming stopped"
    );
}

fn now_usec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Parse one journalctl `--output=json` line into the raw fields the shared
/// normalizer consumes: `__CURSOR`, `MESSAGE`, and `__REALTIME_TIMESTAMP`
/// (microseconds since the epoch, emitted as a string). A line that is not
/// valid JSON is treated as a raw message with no cursor or timestamp.
pub(crate) fn parse_journald_json(line: &str) -> ParsedEntry {
    let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
        return ParsedEntry {
            cursor: None,
            message_bytes: line.as_bytes().to_vec(),
            realtime_usec: None,
        };
    };

    let cursor = obj
        .get("__CURSOR")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let message_bytes = obj
        .get("MESSAGE")
        .map(message_field_bytes)
        .unwrap_or_default();

    let realtime_usec = obj
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok());

    ParsedEntry {
        cursor,
        message_bytes,
        realtime_usec,
    }
}

/// Recover MESSAGE bytes from either shape systemd's JSON export uses: a string
/// when the payload is valid UTF-8, or an array of byte-valued integers when it
/// is not. The normalizer then applies `from_utf8_lossy`, exactly as native does.
fn message_field_bytes(value: &serde_json::Value) -> Vec<u8> {
    match value {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_journald_json() {
        let line = r#"{"__CURSOR":"s=abc123;i=1","MESSAGE":"hello world","__REALTIME_TIMESTAMP":"1600000000000000","PRIORITY":"6","_SYSTEMD_UNIT":"nginx.service"}"#;
        let parsed = parse_journald_json(line);
        assert_eq!(parsed.cursor, Some("s=abc123;i=1".to_string()));
        assert_eq!(parsed.message_bytes, b"hello world");
        assert_eq!(parsed.realtime_usec, Some(1_600_000_000_000_000));
    }

    #[test]
    fn parse_json_without_cursor() {
        let line = r#"{"MESSAGE":"no cursor here"}"#;
        let parsed = parse_journald_json(line);
        assert!(parsed.cursor.is_none());
        assert_eq!(parsed.message_bytes, b"no cursor here");
        assert!(parsed.realtime_usec.is_none());
    }

    #[test]
    fn parse_invalid_json_returns_raw() {
        let line = "not json at all";
        let parsed = parse_journald_json(line);
        assert!(parsed.cursor.is_none());
        assert_eq!(parsed.message_bytes, b"not json at all");
        assert!(parsed.realtime_usec.is_none());
    }

    #[test]
    fn parse_binary_message_as_byte_array() {
        // systemd emits a non-UTF8 MESSAGE as an array of ints, not a string.
        let line = r#"{"__CURSOR":"s=x;i=1","MESSAGE":[104,105,255,33]}"#;
        let parsed = parse_journald_json(line);
        assert_eq!(parsed.message_bytes, vec![104, 105, 255, 33]);
    }

    #[test]
    fn sample_multiline_entry_counts_as_one_line() {
        // Two journalctl JSON entries; the first MESSAGE spans three lines.
        // Native returns one string per entry — the fallback sample must too,
        // so `-n max_lines` bounds entries, not physical lines.
        let stdout = concat!(
            r#"{"__CURSOR":"s=x;i=1","MESSAGE":"line1\nline2\nline3"}"#,
            "\n",
            r#"{"__CURSOR":"s=x;i=2","MESSAGE":"single"}"#,
            "\n",
        );
        let lines = extract_sample_lines(stdout);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "line1\nline2\nline3");
        assert_eq!(lines[1], "single");
    }

    #[test]
    fn sample_drops_blank_message_entries() {
        let stdout = concat!(r#"{"MESSAGE":"kept"}"#, "\n", r#"{"MESSAGE":"   "}"#, "\n",);
        let lines = extract_sample_lines(stdout);
        assert_eq!(lines, vec!["kept".to_string()]);
    }
}
