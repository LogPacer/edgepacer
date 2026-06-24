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

    if line.first() == Some(&b'{')
        && line.windows(5).any(|w| w == b"\"log\"")
        && let Ok(parsed) = serde_json::from_slice::<DockerJsonLog>(line)
        && !parsed.log.is_empty()
    {
        let mut msg = parsed.log.into_bytes();
        if msg.last() == Some(&b'\n') {
            msg.pop();
        }
        return (msg, parsed.stream, false, true);
    }

    (line.to_vec(), String::new(), false, false)
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
}
