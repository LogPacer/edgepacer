//! Log file discovery — walks configured paths for .log files.
//!
//! Mirrors legacy EdgePacer's file discovery surface.
//! Finds all .log files in scan paths, records size/modified/format.

use super::LogFile;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use tracing::debug;

pub(crate) const FORMAT_NDJSON: &str = "ndjson";
pub(crate) const FORMAT_PLAIN_TEXT: &str = "plain_text";
const FORMAT_SAMPLE_MAX_LINES: usize = 20;
const FORMAT_SAMPLE_MAX_BYTES: u64 = 64 * 1024;

/// Default file extension allowlist — bare `.log` only. `.txt` is opt-in per
/// host via the `discovery.log_extensions` config key.
pub const DEFAULT_LOG_EXTENSIONS: &[&str] = &["log"];

/// OS-aware default scan paths, used when no config scan_paths are set.
/// Windows has no `/var/log`, so fall back to the common server log roots.
pub fn default_scan_paths() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            r"C:\inetpub\logs\LogFiles",
            r"C:\Windows\Logs",
            r"C:\ProgramData",
        ]
    } else {
        &["/var/log"]
    }
}

/// Discover log files in the given scan paths, keeping files whose extension is
/// in `allowed_extensions` (e.g. `["log"]`, or `["log", "txt"]` to opt in `.txt`).
pub async fn discover_log_files(
    scan_paths: &[&str],
    allowed_extensions: &[&str],
) -> anyhow::Result<Vec<LogFile>> {
    let paths: Vec<String> = scan_paths.iter().map(|s| s.to_string()).collect();
    let allowed: Vec<String> = allowed_extensions.iter().map(|s| s.to_string()).collect();

    // Run blocking I/O on a thread pool
    tokio::task::spawn_blocking(move || discover_log_files_sync(&paths, &allowed))
        .await
        .map_err(|e| anyhow::anyhow!("file discovery task failed: {e}"))?
}

fn discover_log_files_sync(
    scan_paths: &[String],
    allowed_extensions: &[String],
) -> anyhow::Result<Vec<LogFile>> {
    let mut files = Vec::new();

    for base_path in scan_paths {
        let base = std::path::Path::new(base_path);
        if !base.exists() {
            debug!(path = %base_path, "scan path does not exist, skipping");
            continue;
        }

        walk_directory(base, &mut files, allowed_extensions)?;
    }

    Ok(files)
}

fn walk_directory(
    dir: &std::path::Path,
    files: &mut Vec<LogFile>,
    allowed_extensions: &[String],
) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!(path = %dir.display(), error = %e, "cannot read directory");
            return Ok(()); // Best-effort: skip unreadable dirs
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            // Recurse but limit depth to avoid traversing huge trees
            walk_directory(&path, files, allowed_extensions)?;
        } else if metadata.is_file() && is_log_file(&path, allowed_extensions) {
            let readable = is_readable(&path);
            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            let format = detect_format(&path);
            let permissions = permissions_string(&metadata);

            let line_count = count_lines(&path);

            files.push(LogFile {
                path: path.to_string_lossy().to_string(),
                size: metadata.len(),
                modified,
                readable,
                permissions,
                format,
                line_count,
            });
        }
    }

    Ok(())
}

/// Check if a file looks like a log file, given the allowed extension set
/// (e.g. `["log"]`). Matches a bare allowed extension, and rotated logs
/// (`app.log.gz`, `app.log.1`) whose inner stem extension is itself allowed.
fn is_log_file(path: &std::path::Path, allowed: &[String]) -> bool {
    let ext_allowed = |ext: &str| allowed.iter().any(|a| a == ext);

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext_allowed(ext) => true,
        // Rotated logs: the outer suffix is a compression marker (`app.log.gz`)
        // or a numeric rotation index (`app.log.1`), so the inner stem extension
        // is what must be allowed.
        Some(ext) if is_rotation_suffix(ext) => path
            .file_stem()
            .and_then(|s| std::path::Path::new(s).extension())
            .and_then(|e| e.to_str())
            .map(ext_allowed)
            .unwrap_or(false),
        _ => false,
    }
}

/// A rotation/compression suffix that wraps an inner log file: a known
/// compression extension (`app.log.gz`) or a numeric index (`app.log.1`).
fn is_rotation_suffix(ext: &str) -> bool {
    matches!(ext, "gz" | "xz" | "zst" | "bz2") || is_numeric(ext)
}

/// Non-empty and all ASCII digits — a logrotate-style numeric rotation suffix
/// (`app.log.1`, `app.log.42`).
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(unix)]
fn permissions_string(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;

    format!("{:o}", metadata.permissions().mode())
}

#[cfg(not(unix))]
fn permissions_string(metadata: &std::fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "readonly".to_string()
    } else {
        "readwrite".to_string()
    }
}

/// Check if a file is readable by the current process.
fn is_readable(path: &std::path::Path) -> bool {
    std::fs::File::open(path).is_ok()
}

/// Count lines in a file (approximate — counts newlines).
/// Returns 0 if file can't be read.
fn count_lines(path: &std::path::Path) -> u64 {
    use std::io::{BufRead, BufReader};
    match std::fs::File::open(path) {
        Ok(file) => BufReader::new(file).lines().count() as u64,
        Err(_) => 0,
    }
}

/// Detect log format from a bounded prefix of non-empty lines.
pub(crate) fn detect_format(path: &std::path::Path) -> String {
    if is_ndjson_log(path, |line| Some(line.to_vec())) {
        FORMAT_NDJSON.to_string()
    } else {
        FORMAT_PLAIN_TEXT.to_string()
    }
}

/// Detect the application payload format inside Docker's json-file storage
/// wrapper. The outer JSON object is runtime metadata; only the inner `log`
/// field describes the source format LogPacer should use.
pub(crate) fn detect_docker_json_file_format(path: &std::path::Path) -> String {
    if is_ndjson_log(path, |line| {
        crate::cri::parse_docker_json_line(line).map(|(payload, _)| payload)
    }) {
        FORMAT_NDJSON.to_string()
    } else {
        FORMAT_PLAIN_TEXT.to_string()
    }
}

/// Detect the application payload format inside CRI log records. `path` may be
/// a direct log file or a Kubernetes container log directory containing numbered
/// `*.log` files.
pub(crate) fn detect_cri_log_format(path: &std::path::Path) -> String {
    let log_path = if path.is_dir() {
        match active_cri_log_file(path) {
            Some(path) => path,
            None => return FORMAT_PLAIN_TEXT.to_string(),
        }
    } else {
        path.to_path_buf()
    };

    if is_ndjson_log(&log_path, |line| {
        let (payload, _, _, parsed) = crate::cri::parse_line(line);
        parsed.then_some(payload)
    }) {
        FORMAT_NDJSON.to_string()
    } else {
        FORMAT_PLAIN_TEXT.to_string()
    }
}

fn active_cri_log_file(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut best_num = -1i32;
    let mut best_path = None;

    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        if !entry.file_type().ok()?.is_file() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(num) = name
            .strip_suffix(".log")
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };

        if num > best_num {
            best_num = num;
            best_path = Some(entry.path());
        }
    }

    best_path
}

pub(crate) fn detect_container_log_format(
    runtime: &str,
    labels: &HashMap<String, String>,
    log_path: &str,
) -> String {
    if let Some(format) = format_from_labels(labels) {
        return format.to_string();
    }

    if log_path.is_empty() {
        return FORMAT_PLAIN_TEXT.to_string();
    }

    let path = std::path::Path::new(log_path);
    match runtime {
        "docker" => detect_docker_json_file_format(path),
        "kubernetes" | "containerd" | "cri-o" | "podman" => detect_cri_log_format(path),
        _ => detect_format(path),
    }
}

fn format_from_labels(labels: &HashMap<String, String>) -> Option<&'static str> {
    labels
        .get("log.format")
        .and_then(|value| normalize_log_format(value))
}

fn normalize_log_format(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "json" => Some("json"),
        "ndjson" => Some(FORMAT_NDJSON),
        "plain_text" | "text" => Some(FORMAT_PLAIN_TEXT),
        _ => None,
    }
}

fn is_ndjson_log<F>(path: &std::path::Path, mut payload_for_line: F) -> bool
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut reader = BufReader::new(file.take(FORMAT_SAMPLE_MAX_BYTES));
    let mut line = Vec::new();
    let mut checked_lines = 0usize;

    loop {
        line.clear();
        let bytes_read = match reader.read_until(b'\n', &mut line) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        if bytes_read == 0 {
            break;
        }

        let Some(payload) = payload_for_line(&line) else {
            return false;
        };

        let trimmed = payload.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }

        if !is_json_object_line(trimmed) {
            return false;
        }

        checked_lines += 1;
        if checked_lines >= FORMAT_SAMPLE_MAX_LINES {
            break;
        }
    }

    checked_lines > 0
}

pub(crate) fn is_json_object_line(line: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(line).is_ok_and(|value| value.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ext(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_log_files() {
        let allowed = ext(DEFAULT_LOG_EXTENSIONS);
        assert!(is_log_file(
            std::path::Path::new("/var/log/syslog.log"),
            &allowed
        ));
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.log.gz"),
            &allowed
        ));
        assert!(!is_log_file(
            std::path::Path::new("/var/log/syslog"),
            &allowed
        ));
        assert!(!is_log_file(
            std::path::Path::new("/var/log/data.csv"),
            &allowed
        ));
    }

    #[test]
    fn default_allowlist_matches_log_only() {
        let allowed = ext(DEFAULT_LOG_EXTENSIONS);
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.log"),
            &allowed
        ));
        // .txt is opt-in — rejected under the default allowlist.
        assert!(!is_log_file(
            std::path::Path::new("/var/log/app.txt"),
            &allowed
        ));
    }

    #[test]
    fn txt_matches_when_opted_in() {
        let allowed = ext(&["log", "txt"]);
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.txt"),
            &allowed
        ));
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.log"),
            &allowed
        ));
    }

    #[test]
    fn rotated_logs_match_under_default_allowlist() {
        let allowed = ext(DEFAULT_LOG_EXTENSIONS);
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.log.gz"),
            &allowed
        ));
        assert!(is_log_file(
            std::path::Path::new("/var/log/app.log.1"),
            &allowed
        ));
        // A rotated non-log extension stays out under the default allowlist.
        assert!(!is_log_file(
            std::path::Path::new("/var/log/app.csv.1"),
            &allowed
        ));
    }

    #[test]
    fn default_scan_paths_are_os_aware() {
        let paths = default_scan_paths();
        if cfg!(windows) {
            assert_eq!(
                paths,
                &[
                    r"C:\inetpub\logs\LogFiles",
                    r"C:\Windows\Logs",
                    r"C:\ProgramData",
                ]
            );
        } else {
            assert_eq!(paths, &["/var/log"]);
        }
    }

    #[tokio::test]
    async fn discovers_files_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.log"), "line1\nline2\n").unwrap();
        std::fs::write(dir.path().join("other.txt"), "not a log").unwrap();

        // Create a subdirectory with another log
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("nested.log"), "nested\n").unwrap();

        let path_str = dir.path().to_str().unwrap();
        let files = discover_log_files(&[path_str], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        assert_eq!(files.len(), 2);

        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("app.log")));
        assert!(paths.iter().any(|p| p.ends_with("nested.log")));
    }

    #[tokio::test]
    async fn detects_ndjson_format() {
        let dir = tempfile::tempdir().unwrap();
        let json_log = dir.path().join("json.log");
        {
            let mut f = std::fs::File::create(&json_log).unwrap();
            writeln!(f, r#"{{"level":"info","msg":"hello"}}"#).unwrap();
            writeln!(f, r#"{{"level":"warn","msg":"again"}}"#).unwrap();
        }
        let plain_log = dir.path().join("plain.log");
        std::fs::write(&plain_log, "2026-04-05 INFO hello\n").unwrap();

        let path_str = dir.path().to_str().unwrap();
        let files = discover_log_files(&[path_str], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        assert_eq!(files.len(), 2);

        let json_file = files.iter().find(|f| f.path.ends_with("json.log")).unwrap();
        assert_eq!(json_file.format, "ndjson");

        let plain_file = files
            .iter()
            .find(|f| f.path.ends_with("plain.log"))
            .unwrap();
        assert_eq!(plain_file.format, "plain_text");
    }

    #[test]
    fn detects_docker_json_file_inner_payload_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container-json.log");
        std::fs::write(
            &path,
            concat!(
                r#"{"log":"{\"level\":\"info\",\"msg\":\"hello\"}\n","stream":"stdout","time":"2026-07-04T23:35:09Z"}"#,
                "\n",
                r#"{"log":"{\"level\":\"warn\",\"msg\":\"again\"}\n","stream":"stderr","time":"2026-07-04T23:35:10Z"}"#,
                "\n"
            ),
        )
        .unwrap();

        assert_eq!(detect_docker_json_file_format(&path), "ndjson");
    }

    #[test]
    fn docker_json_file_with_plain_inner_payload_is_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container-json.log");
        std::fs::write(
            &path,
            concat!(
                r#"{"log":"INFO hello\n","stream":"stdout","time":"2026-07-04T23:35:09Z"}"#,
                "\n"
            ),
        )
        .unwrap();

        assert_eq!(detect_docker_json_file_format(&path), "plain_text");
    }

    #[test]
    fn detects_cri_inner_payload_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("0.log");
        std::fs::write(
            &path,
            concat!(
                r#"2026-07-04T23:35:09Z stdout F {"level":"info","msg":"hello"}"#,
                "\n",
                r#"2026-07-04T23:35:10Z stderr F {"level":"warn","msg":"again"}"#,
                "\n"
            ),
        )
        .unwrap();

        assert_eq!(detect_cri_log_format(dir.path()), "ndjson");
    }

    #[test]
    fn container_format_prefers_label_hint() {
        let labels = HashMap::from([("log.format".to_string(), "json".to_string())]);

        assert_eq!(detect_container_log_format("docker", &labels, ""), "json");
    }

    #[tokio::test]
    async fn malformed_brace_wrapped_line_is_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bracey.log");
        std::fs::write(&path, "{not json}\n").unwrap();

        let files = discover_log_files(&[dir.path().to_str().unwrap()], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        let file = files
            .iter()
            .find(|f| f.path.ends_with("bracey.log"))
            .unwrap();

        assert_eq!(file.format, "plain_text");
    }

    #[tokio::test]
    async fn mixed_json_and_plain_lines_are_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.log");
        std::fs::write(&path, "{\"level\":\"info\"}\nnot json\n").unwrap();

        let files = discover_log_files(&[dir.path().to_str().unwrap()], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        let file = files
            .iter()
            .find(|f| f.path.ends_with("mixed.log"))
            .unwrap();

        assert_eq!(file.format, "plain_text");
    }

    #[tokio::test]
    async fn json_array_line_is_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("array.log");
        std::fs::write(&path, "[{\"level\":\"info\"}]\n").unwrap();

        let files = discover_log_files(&[dir.path().to_str().unwrap()], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        let file = files
            .iter()
            .find(|f| f.path.ends_with("array.log"))
            .unwrap();

        assert_eq!(file.format, "plain_text");
    }

    #[tokio::test]
    async fn non_utf8_line_is_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.log");
        std::fs::write(&path, [0xff, 0xfe, b'{', b'}']).unwrap();

        let files = discover_log_files(&[dir.path().to_str().unwrap()], DEFAULT_LOG_EXTENSIONS)
            .await
            .unwrap();
        let file = files
            .iter()
            .find(|f| f.path.ends_with("binary.log"))
            .unwrap();

        assert_eq!(file.format, "plain_text");
    }
}
