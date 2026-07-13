//! CRI log line parsing — containerd/CRI-O text format and Docker JSON fallback.

use regex::Regex;
use std::sync::LazyLock;

static LOG_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) (\S+) ([FP]) ",
    )
    .expect("valid CRI log regex")
});

#[derive(Debug, serde::Deserialize)]
struct DockerJsonLog {
    log: String,
    stream: String,
}

/// Parse a container log line and extract the message.
/// Returns (message, stream, is_partial, is_cri_format).
pub fn parse_line(line: &[u8]) -> (Vec<u8>, String, bool, bool) {
    let line_str = match std::str::from_utf8(line) {
        Ok(s) => s,
        Err(_) => return (line.to_vec(), String::new(), false, false),
    };

    if let Some(caps) = LOG_PATTERN.captures(line_str) {
        let stream = caps.get(2).map_or("", |m| m.as_str()).to_string();
        let flag = caps.get(3).map_or("F", |m| m.as_str());
        let message = line[caps.get(0).unwrap().end()..].to_vec();
        return (message, stream, flag == "P", true);
    }

    if let Some((msg, stream)) = parse_docker_json_line(line) {
        return (msg, stream, false, true);
    }

    (line.to_vec(), String::new(), false, false)
}

/// Reassemble a raw CRI log line into a complete logical message.
///
/// CRI splits long lines into `P` (partial) fragments terminated by a single
/// `F` (full) fragment; a complete message is the concatenation of the partials
/// with the terminating full line. This is the shared reassembly seam used by
/// both the streaming Kubernetes tailer (`ContainerReader::read_lines`) and the
/// batch sampler (`ContainerReader::sample_lines`), so a sampled message is
/// byte-identical to what the wire ships.
///
/// Returns `Some(message)` when a complete logical line is ready, or `None`
/// while a `P` fragment is still buffering in `partial_buffer`. A dangling
/// partial at end-of-input is intentionally left in `partial_buffer` and never
/// emitted — the wire has not shipped it yet either.
pub fn reassemble_partial(raw: &[u8], partial_buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (message, _, is_partial, is_cri) = parse_line(raw);

    if is_cri && is_partial {
        partial_buffer.extend_from_slice(&message);
        return None;
    }

    if partial_buffer.is_empty() {
        Some(message)
    } else {
        partial_buffer.extend_from_slice(&message);
        Some(std::mem::take(partial_buffer))
    }
}

/// Parse Docker's json-file log wrapper and return only the application payload.
pub fn parse_docker_json_line(line: &[u8]) -> Option<(Vec<u8>, String)> {
    if line.first() != Some(&b'{') || !line.windows(5).any(|w| w == b"\"log\"") {
        return None;
    }

    let parsed = serde_json::from_slice::<DockerJsonLog>(line).ok()?;
    let mut msg = parsed.log.into_bytes();
    if msg.last() == Some(&b'\n') {
        msg.pop();
    }
    if msg.last() == Some(&b'\r') {
        msg.pop();
    }
    Some((msg, parsed.stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cri_full_line() {
        let line = b"2024-01-15T10:30:45.123456789Z stdout F Hello world";
        let (msg, stream, partial, ok) = parse_line(line);
        assert!(ok);
        assert_eq!(msg, b"Hello world");
        assert_eq!(stream, "stdout");
        assert!(!partial);
    }

    #[test]
    fn parses_cri_partial_line() {
        let line = b"2024-01-15T10:30:45Z stderr P partial";
        let (_, _, partial, ok) = parse_line(line);
        assert!(ok);
        assert!(partial);
    }

    #[test]
    fn reassemble_partial_joins_p_fragments_then_full() {
        let mut buf = Vec::new();
        assert_eq!(
            reassemble_partial(b"2024-01-15T10:30:45Z stdout P chunk-one ", &mut buf),
            None
        );
        assert_eq!(
            reassemble_partial(b"2024-01-15T10:30:45Z stdout P chunk-two ", &mut buf),
            None
        );
        let out = reassemble_partial(b"2024-01-15T10:30:45Z stdout F chunk-three", &mut buf)
            .expect("full line flushes the reassembled message");
        assert_eq!(out, b"chunk-one chunk-two chunk-three");
        assert!(buf.is_empty(), "buffer drained after full line");
    }

    #[test]
    fn reassemble_partial_passes_through_full_lines() {
        let mut buf = Vec::new();
        let out = reassemble_partial(b"2024-01-15T10:30:45Z stdout F solo", &mut buf).unwrap();
        assert_eq!(out, b"solo");
        assert!(buf.is_empty());
    }

    #[test]
    fn reassemble_partial_leaves_dangling_partial_buffered() {
        let mut buf = Vec::new();
        assert_eq!(
            reassemble_partial(b"2024-01-15T10:30:45Z stdout P not-yet-complete", &mut buf),
            None
        );
        // A trailing partial with no terminating F is never emitted — matches
        // the wire, which has not shipped it either.
        assert_eq!(buf, b"not-yet-complete");
    }

    #[test]
    fn parses_docker_json_file_line() {
        let line = br#"{"log":"{\"level\":\"INFO\",\"msg\":\"hello\"}\n","stream":"stdout","time":"2026-07-04T23:35:09.566698461Z"}"#;
        let (msg, stream) = parse_docker_json_line(line).unwrap();
        assert_eq!(msg, br#"{"level":"INFO","msg":"hello"}"#);
        assert_eq!(stream, "stdout");
    }
}
