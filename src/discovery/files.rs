//! Log file discovery — walks configured paths for .log files.
//!
//! Mirrors legacy EdgePacer's file discovery surface.
//! Finds all .log files in scan paths, records size/modified/format.

use super::LogFile;
use std::io::{BufRead, BufReader, Read};
use tracing::debug;

const FORMAT_NDJSON: &str = "ndjson";
const FORMAT_PLAIN_TEXT: &str = "plain_text";
const FORMAT_SAMPLE_MAX_LINES: usize = 20;
const FORMAT_SAMPLE_MAX_BYTES: u64 = 64 * 1024;

/// Discover log files in the given scan paths.
pub async fn discover_log_files(scan_paths: &[&str]) -> anyhow::Result<Vec<LogFile>> {
    let paths: Vec<String> = scan_paths.iter().map(|s| s.to_string()).collect();

    // Run blocking I/O on a thread pool
    tokio::task::spawn_blocking(move || discover_log_files_sync(&paths))
        .await
        .map_err(|e| anyhow::anyhow!("file discovery task failed: {e}"))?
}

fn discover_log_files_sync(scan_paths: &[String]) -> anyhow::Result<Vec<LogFile>> {
    let mut files = Vec::new();

    for base_path in scan_paths {
        let base = std::path::Path::new(base_path);
        if !base.exists() {
            debug!(path = %base_path, "scan path does not exist, skipping");
            continue;
        }

        walk_directory(base, &mut files)?;
    }

    Ok(files)
}

fn walk_directory(dir: &std::path::Path, files: &mut Vec<LogFile>) -> anyhow::Result<()> {
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
            walk_directory(&path, files)?;
        } else if metadata.is_file() && is_log_file(&path) {
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

/// Check if a file looks like a log file.
fn is_log_file(path: &std::path::Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("log") => true,
        Some("gz" | "xz" | "zst" | "bz2") => {
            // Compressed log files: check if the stem also ends in .log
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.ends_with(".log"))
                .unwrap_or(false)
        }
        _ => false,
    }
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
fn detect_format(path: &std::path::Path) -> String {
    if is_ndjson_log(path) {
        FORMAT_NDJSON.to_string()
    } else {
        FORMAT_PLAIN_TEXT.to_string()
    }
}

fn is_ndjson_log(path: &std::path::Path) -> bool {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut reader = BufReader::new(file.take(FORMAT_SAMPLE_MAX_BYTES));
    let mut line = String::new();
    let mut checked_lines = 0usize;

    loop {
        line.clear();
        let bytes_read = match reader.read_line(&mut line) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
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

fn is_json_object_line(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line).is_ok_and(|value| value.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_log_files() {
        assert!(is_log_file(std::path::Path::new("/var/log/syslog.log")));
        assert!(is_log_file(std::path::Path::new("/var/log/app.log.gz")));
        assert!(!is_log_file(std::path::Path::new("/var/log/syslog")));
        assert!(!is_log_file(std::path::Path::new("/var/log/data.csv")));
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
        let files = discover_log_files(&[path_str]).await.unwrap();
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
        let files = discover_log_files(&[path_str]).await.unwrap();
        assert_eq!(files.len(), 2);

        let json_file = files.iter().find(|f| f.path.ends_with("json.log")).unwrap();
        assert_eq!(json_file.format, "ndjson");

        let plain_file = files
            .iter()
            .find(|f| f.path.ends_with("plain.log"))
            .unwrap();
        assert_eq!(plain_file.format, "plain_text");
    }

    #[tokio::test]
    async fn malformed_brace_wrapped_line_is_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bracey.log");
        std::fs::write(&path, "{not json}\n").unwrap();

        let files = discover_log_files(&[dir.path().to_str().unwrap()])
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

        let files = discover_log_files(&[dir.path().to_str().unwrap()])
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

        let files = discover_log_files(&[dir.path().to_str().unwrap()])
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

        let files = discover_log_files(&[dir.path().to_str().unwrap()])
            .await
            .unwrap();
        let file = files
            .iter()
            .find(|f| f.path.ends_with("binary.log"))
            .unwrap();

        assert_eq!(file.format, "plain_text");
    }
}
