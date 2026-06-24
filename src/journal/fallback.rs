//! journalctl shell-out — fallback when sdjournal is unavailable.

use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::streaming_actor::StreamHandle;
use crate::streaming_checkpoint::StreamingCheckpoint;

/// Pull the most recent `max_lines` from journald for a systemd unit via journalctl.
pub fn sample_unit_lines(unit: &str, max_lines: usize) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("journalctl")
        .args([
            "-u",
            unit,
            "-n",
            &max_lines.to_string(),
            "--no-pager",
            "--output=cat",
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

    let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();

    Ok(lines)
}

/// Stream logs from a systemd unit via journalctl into the streaming pipeline.
pub async fn stream_unit_logs(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    resume_cursor: Option<&str>,
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
    let mut entries_processed: u64 = 0;
    let mut last_cursor: Option<String> = None;
    let checkpoint_interval = 100u64;

    loop {
        tokio::select! {
            line_result = reader.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let (cursor, message) = parse_journald_json(&line);
                        if message.is_empty() {
                            continue;
                        }

                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as i64;

                        // Backpressure is the bounded channel: this awaits
                        // until the actor has room. False means the actor is
                        // gone — stop streaming.
                        if !handle.enqueue(message.into_bytes(), now_ns).await {
                            warn!(unit, "streaming pipeline actor gone, stopping journald stream");
                            break;
                        }

                        if let Some(c) = cursor {
                            last_cursor = Some(c);
                        }

                        entries_processed += 1;

                        if entries_processed.is_multiple_of(checkpoint_interval) {
                            if let Some(ref cursor) = last_cursor {
                                let _ = handle
                                    .set_checkpoint(StreamingCheckpoint::journald(
                                        source_id, cursor,
                                    ))
                                    .await;
                            }
                            debug!(unit, entries = entries_processed, "journald stream progress");
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
            _ = shutdown.changed() => {
                info!(unit, "journald stream shutdown signal");
                break;
            }
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

/// Parse a journald JSON entry to extract `__CURSOR` and `MESSAGE`.
pub(crate) fn parse_journald_json(line: &str) -> (Option<String>, String) {
    let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
        return (None, line.to_string());
    };

    let cursor = obj
        .get("__CURSOR")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let message = obj
        .get("MESSAGE")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    (cursor, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_journald_json() {
        let line = r#"{"__CURSOR":"s=abc123;i=1","MESSAGE":"hello world","PRIORITY":"6","_SYSTEMD_UNIT":"nginx.service"}"#;
        let (cursor, message) = parse_journald_json(line);
        assert_eq!(cursor, Some("s=abc123;i=1".to_string()));
        assert_eq!(message, "hello world");
    }

    #[test]
    fn parse_json_without_cursor() {
        let line = r#"{"MESSAGE":"no cursor here"}"#;
        let (cursor, message) = parse_journald_json(line);
        assert!(cursor.is_none());
        assert_eq!(message, "no cursor here");
    }

    #[test]
    fn parse_invalid_json_returns_raw() {
        let line = "not json at all";
        let (cursor, message) = parse_journald_json(line);
        assert!(cursor.is_none());
        assert_eq!(message, "not json at all");
    }
}
