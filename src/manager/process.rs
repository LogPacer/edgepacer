//! Process lifecycle management — start, stop, health check for the edgepacer agent.
//!
//! Mirrors legacy EdgePacer's `internal/manager/process_unix.go`.
//! Unix-only for MVP (Windows support deferred).

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, error, info, warn};

/// Manages the edgepacer child process.
pub struct ProcessManager {
    binary_path: PathBuf,
    rails_url: String,
    child: Option<Child>,
    readiness_file: PathBuf,
    start_time: Option<Instant>,
    debug_mode: bool,
}

impl ProcessManager {
    pub fn new(binary_path: &Path, rails_url: &str, debug_mode: bool) -> Self {
        let readiness_file = std::env::temp_dir().join(format!(
            "edgepacer-ready-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        Self {
            binary_path: binary_path.to_path_buf(),
            rails_url: rails_url.to_string(),
            child: None,
            readiness_file,
            start_time: None,
            debug_mode,
        }
    }

    /// Start the edgepacer agent as a child process.
    ///
    /// Tokens are passed via environment variables (not CLI args) to avoid
    /// exposure in /proc/PID/cmdline.
    pub async fn start(&mut self, server_token: &str) -> anyhow::Result<()> {
        // Clean up stale readiness file
        let _ = std::fs::remove_file(&self.readiness_file);

        let mut cmd = Command::new(&self.binary_path);
        // No CLI args — the agent reads its config from env vars
        // (EDGEPACER_RAILS_URL, EDGEPACER_SERVER_TOKEN, EDGEPACER_LOG_LEVEL,
        // etc.) and its default mode is Rails-connected. Earlier versions of
        // the manager passed --host-mode / --log-format / --debug, but those
        // were removed/renamed in the agent (see src/config.rs). Passing
        // them now causes "unexpected argument" and a fatal exit.
        if self.debug_mode {
            cmd.env("EDGEPACER_LOG_LEVEL", "debug");
        }

        // Pass tokens via env vars (security: not visible in cmdline)
        cmd.env("EDGEPACER_SERVER_TOKEN", server_token);
        cmd.env("EDGEPACER_RAILS_URL", &self.rails_url);
        cmd.env(
            "EDGEPACER_READINESS_FILE",
            self.readiness_file.to_string_lossy().as_ref(),
        );

        // Filter out account token from inherited env
        cmd.env_remove("EDGEPACER_ACCOUNT_TOKEN");

        // Capture stdout/stderr for log forwarding
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Unix: set process group for clean shutdown
        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!(
                "failed to start edgepacer at {}: {e}",
                self.binary_path.display()
            )
        })?;

        info!(
            binary = %self.binary_path.display(),
            pid = child.id().unwrap_or(0),
            "[manager] edgepacer child process started"
        );

        // Spawn log forwarding tasks
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(forward_child_logs(BufReader::new(stdout)));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(forward_child_logs(BufReader::new(stderr)));
        }

        self.child = Some(child);
        self.start_time = Some(Instant::now());

        Ok(())
    }

    /// Stop the edgepacer agent gracefully (SIGTERM then wait, force kill on timeout).
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };

        let pid = child.id().unwrap_or(0);
        info!(pid, "[manager] stopping edgepacer child process");

        // Send SIGTERM on Unix, kill on other platforms
        #[cfg(unix)]
        {
            if pid > 0 {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill().await;
        }

        // Wait up to 30s for graceful exit
        match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
            Ok(Ok(status)) => {
                info!(pid, status = %status, "[manager] edgepacer stopped gracefully");
            }
            Ok(Err(e)) => {
                warn!(pid, error = %e, "[manager] error waiting for edgepacer to stop");
            }
            Err(_) => {
                warn!(
                    pid,
                    "[manager] edgepacer did not stop within 30s, force killing"
                );
                let _ = child.kill().await;
            }
        }

        self.child = None;
        self.start_time = None;
        let _ = std::fs::remove_file(&self.readiness_file);

        Ok(())
    }

    /// Check if the child process is still running.
    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => child.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    /// Wait for the agent to become healthy (readiness file appears).
    pub async fn wait_healthy(&self, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut interval = tokio::time::interval(Duration::from_millis(500));

        info!(
            readiness_file = %self.readiness_file.display(),
            timeout_secs = timeout.as_secs(),
            "[manager] waiting for edgepacer to become healthy"
        );

        loop {
            interval.tick().await;

            if self.readiness_file.exists() {
                info!("[manager] edgepacer is healthy (readiness file present)");
                return Ok(());
            }

            if Instant::now() > deadline {
                anyhow::bail!(
                    "health check timeout: readiness file not created within {}s",
                    timeout.as_secs()
                );
            }

            // Check process hasn't died
            if let Some(ref child) = self.child
                && child.id().is_none()
            {
                anyhow::bail!("edgepacer process died during health check");
            }
        }
    }

    /// Get the version of the edgepacer binary.
    ///
    /// Runs `./edgepacer --version` and parses out the bare version. clap's
    /// default --version handler prints `edgepacer X.Y.Z` (one line). If the
    /// binary doesn't support --version (older builds without the `version`
    /// command attribute) it exits non-zero with garbage on stderr — return
    /// Err so the caller logs a real warning instead of silently treating
    /// an empty current-version as "infinitely outdated" and looping the
    /// update on every tick.
    pub async fn get_version(&self) -> anyhow::Result<String> {
        let output = Command::new(&self.binary_path)
            .arg("--version")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            anyhow::bail!(
                "edgepacer --version exited with {}: {}",
                output.status,
                crate::common::truncate_body(&stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // clap prints "edgepacer X.Y.Z" — strip the "edgepacer " prefix so
        // the caller can compare directly against Rails' version string.
        let version = stdout
            .strip_prefix("edgepacer ")
            .unwrap_or(&stdout)
            .trim()
            .to_string();

        if version.is_empty() {
            anyhow::bail!("edgepacer --version returned empty output");
        }

        Ok(version)
    }

    /// Path to the readiness file.
    pub fn readiness_file(&self) -> &Path {
        &self.readiness_file
    }
}

/// Forward child process output lines to the manager's tracing logger.
async fn forward_child_logs<R: tokio::io::AsyncRead + Unpin>(reader: BufReader<R>) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let (level, msg) = normalize_child_log_line(&line);
        log_agent_line(level, msg.as_ref());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildLogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

fn normalize_child_log_line(line: &str) -> (ChildLogLevel, Cow<'_, str>) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
        let level = json
            .get("level")
            .and_then(|v| v.as_str())
            .map(parse_child_log_level)
            .unwrap_or(ChildLogLevel::Info);
        let msg = json
            .get("message")
            .or_else(|| json.get("msg"))
            .and_then(|v| v.as_str())
            .map(|v| Cow::Owned(v.to_string()))
            .unwrap_or_else(|| Cow::Borrowed(line));
        return (level, msg);
    }

    if let Some((level, msg)) = parse_tracing_fmt_line(line) {
        return (level, Cow::Borrowed(msg));
    }

    (ChildLogLevel::Info, Cow::Borrowed(line))
}

fn parse_tracing_fmt_line(line: &str) -> Option<(ChildLogLevel, &str)> {
    let trimmed = line.trim_start();
    let timestamp_end = trimmed.find(char::is_whitespace)?;
    let timestamp = &trimmed[..timestamp_end];
    if !timestamp.contains('T') {
        return None;
    }

    let after_timestamp = trimmed[timestamp_end..].trim_start();
    let level_end = after_timestamp
        .find(char::is_whitespace)
        .unwrap_or(after_timestamp.len());
    let level = parse_child_log_level(&after_timestamp[..level_end]);
    let msg = after_timestamp[level_end..].trim_start();
    if msg.is_empty() {
        return None;
    }

    Some((level, msg))
}

fn parse_child_log_level(level: &str) -> ChildLogLevel {
    match level.to_uppercase().as_str() {
        "ERROR" => ChildLogLevel::Error,
        "WARN" => ChildLogLevel::Warn,
        "DEBUG" | "TRACE" => ChildLogLevel::Debug,
        _ => ChildLogLevel::Info,
    }
}

fn log_agent_line(level: ChildLogLevel, msg: &str) {
    match level {
        ChildLogLevel::Error => error!("[agent] {msg}"),
        ChildLogLevel::Warn => warn!("[agent] {msg}"),
        ChildLogLevel::Info => info!("[agent] {msg}"),
        ChildLogLevel::Debug => debug!("[agent] {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_tracing_timestamp_and_level_from_child_line() {
        let (level, msg) = normalize_child_log_line(
            "2026-06-17T00:14:33.069599Z  INFO discovered processes count=1468",
        );

        assert_eq!(level, ChildLogLevel::Info);
        assert_eq!(msg, "discovered processes count=1468");
    }

    #[test]
    fn preserves_plain_child_line_without_tracing_prefix() {
        let (level, msg) = normalize_child_log_line("raw startup text");

        assert_eq!(level, ChildLogLevel::Info);
        assert_eq!(msg, "raw startup text");
    }

    #[test]
    fn maps_json_child_level_and_message() {
        let (level, msg) =
            normalize_child_log_line(r#"{"level":"WARN","message":"retrying ship"}"#);

        assert_eq!(level, ChildLogLevel::Warn);
        assert_eq!(msg, "retrying ship");
    }
}
