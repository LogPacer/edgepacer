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

/// Which output stream a container record came from.
///
/// A container runtime tags every record it writes. Two programs in one
/// container interleave their records — a request log on stdout landing
/// between the frames of a stack trace on stderr — so the tag is what lets
/// each stream be assembled into events on its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
    /// No stream tag: a plain file, journald, an event log, or a container
    /// record whose runtime left the tag unset.
    #[default]
    Unspecified,
}

impl LogStream {
    pub fn from_tag(tag: &str) -> Self {
        match tag {
            "stdout" => Self::Stdout,
            "stderr" => Self::Stderr,
            _ => Self::Unspecified,
        }
    }
}

/// Parse a container log line and extract the message.
/// Returns (message, stream, is_partial, is_cri_format).
pub fn parse_line(line: &[u8]) -> (Vec<u8>, LogStream, bool, bool) {
    let line_str = match std::str::from_utf8(line) {
        Ok(s) => s,
        Err(_) => return (line.to_vec(), LogStream::Unspecified, false, false),
    };

    if let Some(caps) = LOG_PATTERN.captures(line_str) {
        let stream = LogStream::from_tag(caps.get(2).map_or("", |m| m.as_str()));
        let flag = caps.get(3).map_or("F", |m| m.as_str());
        let message = line[caps.get(0).unwrap().end()..].to_vec();
        return (message, stream, flag == "P", true);
    }

    if let Some(record) = parse_docker_json_line(line) {
        return (record.payload, record.stream, record.partial, true);
    }

    (line.to_vec(), LogStream::Unspecified, false, false)
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
/// Returns the complete message and its stream when one is ready, or `None`
/// while a `P` fragment is still buffering in `partial_buffer`. A dangling
/// partial at end-of-input is intentionally left in `partial_buffer` and never
/// emitted — the wire has not shipped it yet either. One buffer suffices here
/// because a runtime writes a message's fragments consecutively.
pub fn reassemble_partial(
    raw: &[u8],
    partial_buffer: &mut Vec<u8>,
) -> Option<(Vec<u8>, LogStream)> {
    let (message, stream, is_partial, is_cri) = parse_line(raw);

    if is_cri && is_partial {
        partial_buffer.extend_from_slice(&message);
        return None;
    }

    if partial_buffer.is_empty() {
        Some((message, stream))
    } else {
        partial_buffer.extend_from_slice(&message);
        Some((std::mem::take(partial_buffer), stream))
    }
}

/// One record from Docker's json-file log: the application payload with the
/// wrapper and trailing newline removed, the stream that wrote it, and whether
/// the record is a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerJsonRecord {
    pub payload: Vec<u8>,
    pub stream: LogStream,
    /// Docker chunks a long line at 16K and writes each chunk as its own
    /// record; only the last chunk's `log` value carries the newline. A record
    /// without one is therefore the middle of a line, not a line.
    pub partial: bool,
}

/// Parse Docker's json-file log wrapper and return only the application payload.
pub fn parse_docker_json_line(line: &[u8]) -> Option<DockerJsonRecord> {
    if line.first() != Some(&b'{') || !line.windows(5).any(|w| w == b"\"log\"") {
        return None;
    }

    let parsed = serde_json::from_slice::<DockerJsonLog>(line).ok()?;
    let mut payload = parsed.log.into_bytes();
    let partial = payload.last() != Some(&b'\n');
    if payload.last() == Some(&b'\n') {
        payload.pop();
    }
    if payload.last() == Some(&b'\r') {
        payload.pop();
    }
    Some(DockerJsonRecord {
        payload,
        stream: LogStream::from_tag(&parsed.stream),
        partial,
    })
}

/// One complete json-file line: the payload, the stream that wrote it, and the
/// raw file bytes consumed to produce it — every rejoined record, each with
/// its terminating newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerJsonLine {
    pub payload: Vec<u8>,
    pub stream: LogStream,
    pub source_len: u64,
}

#[derive(Debug, Default)]
struct PartialRecord {
    payload: Vec<u8>,
    source_len: u64,
}

/// Rejoins the json-file records Docker split apart.
///
/// Buffers per stream rather than globally: Docker copies stdout and stderr
/// concurrently, so one stream's chunks can be interleaved with the other's
/// records, and a shared buffer would splice the two together.
#[derive(Debug, Default)]
pub struct DockerJsonReassembler {
    partials: Vec<(LogStream, PartialRecord)>,
}

impl DockerJsonReassembler {
    /// Feed one raw json-file line. Returns the complete line once its final
    /// record arrives, or `None` while fragments are still buffering. A line
    /// that is not a Docker wrapper passes straight through.
    pub fn push(&mut self, raw: Vec<u8>) -> Option<DockerJsonLine> {
        let source_len = raw.len() as u64 + 1;

        let Some(record) = parse_docker_json_line(&raw) else {
            return Some(DockerJsonLine {
                payload: raw,
                stream: LogStream::Unspecified,
                source_len,
            });
        };

        let buffered = self.buffer_for(record.stream);
        buffered.payload.extend_from_slice(&record.payload);
        buffered.source_len += source_len;

        if record.partial {
            return None;
        }

        let joined = std::mem::take(buffered);
        Some(DockerJsonLine {
            payload: joined.payload,
            stream: record.stream,
            source_len: joined.source_len,
        })
    }

    /// Raw bytes consumed by fragments that are still waiting for their final
    /// record. The pipeline holds its read offset back by this much so the
    /// rejoined line's byte range starts where its first fragment did.
    pub fn pending_bytes(&self) -> u64 {
        self.partials
            .iter()
            .map(|(_, partial)| partial.source_len)
            .sum()
    }

    fn buffer_for(&mut self, stream: LogStream) -> &mut PartialRecord {
        if let Some(index) = self
            .partials
            .iter()
            .position(|(candidate, _)| *candidate == stream)
        {
            return &mut self.partials[index].1;
        }
        self.partials.push((stream, PartialRecord::default()));
        &mut self
            .partials
            .last_mut()
            .expect("just pushed a buffer for this stream")
            .1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassembled(raw: &[u8], buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        reassemble_partial(raw, buf).map(|(message, _)| message)
    }

    #[test]
    fn parses_cri_full_line() {
        let line = b"2024-01-15T10:30:45.123456789Z stdout F Hello world";
        let (msg, stream, partial, ok) = parse_line(line);
        assert!(ok);
        assert_eq!(msg, b"Hello world");
        assert_eq!(stream, LogStream::Stdout);
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
            reassembled(b"2024-01-15T10:30:45Z stdout P chunk-one ", &mut buf),
            None
        );
        assert_eq!(
            reassembled(b"2024-01-15T10:30:45Z stdout P chunk-two ", &mut buf),
            None
        );
        let (out, stream) =
            reassemble_partial(b"2024-01-15T10:30:45Z stdout F chunk-three", &mut buf)
                .expect("full line flushes the reassembled message");
        assert_eq!(out, b"chunk-one chunk-two chunk-three");
        assert_eq!(stream, LogStream::Stdout);
        assert!(buf.is_empty(), "buffer drained after full line");
    }

    #[test]
    fn reassemble_partial_passes_through_full_lines() {
        let mut buf = Vec::new();
        let (out, stream) =
            reassemble_partial(b"2024-01-15T10:30:45Z stderr F solo", &mut buf).unwrap();
        assert_eq!(out, b"solo");
        assert_eq!(stream, LogStream::Stderr);
        assert!(buf.is_empty());
    }

    #[test]
    fn reassemble_partial_leaves_dangling_partial_buffered() {
        let mut buf = Vec::new();
        assert_eq!(
            reassembled(b"2024-01-15T10:30:45Z stdout P not-yet-complete", &mut buf),
            None
        );
        // A trailing partial with no terminating F is never emitted — matches
        // the wire, which has not shipped it either.
        assert_eq!(buf, b"not-yet-complete");
    }

    #[test]
    fn parses_docker_json_file_line() {
        let line = br#"{"log":"{\"level\":\"INFO\",\"msg\":\"hello\"}\n","stream":"stdout","time":"2026-07-04T23:35:09.566698461Z"}"#;
        let record = parse_docker_json_line(line).unwrap();
        assert_eq!(record.payload, br#"{"level":"INFO","msg":"hello"}"#);
        assert_eq!(record.stream, LogStream::Stdout);
        assert!(!record.partial, "a newline-terminated record is complete");
    }

    #[test]
    fn docker_json_record_without_newline_is_a_fragment() {
        let line = br#"{"log":"first half of a very long ","stream":"stdout","time":"2026-07-04T23:35:09Z"}"#;
        let record = parse_docker_json_line(line).unwrap();
        assert_eq!(record.payload, b"first half of a very long ");
        assert!(record.partial);
    }

    /// Kill-test: Docker chunks a long line at 16K into several records. Before
    /// rejoining, each chunk shipped as its own entry — and with multiline
    /// aggregation on, the tail chunks became continuations of the wrong event.
    #[test]
    fn rejoins_a_split_line_and_spans_every_consumed_record() {
        let first = br#"{"log":"2026-08-06 ERROR first half ","stream":"stdout","time":"2026-08-06T15:03:17Z"}"#.to_vec();
        let second =
            br#"{"log":"second half\n","stream":"stdout","time":"2026-08-06T15:03:17Z"}"#.to_vec();
        let expected_len = first.len() as u64 + 1 + second.len() as u64 + 1;

        let mut reassembler = DockerJsonReassembler::default();
        assert!(
            reassembler.push(first).is_none(),
            "a fragment emits nothing"
        );
        assert_eq!(
            reassembler.pending_bytes(),
            expected_len - (second.len() as u64 + 1),
            "the fragment's bytes are held back until the line completes"
        );

        let line = reassembler
            .push(second)
            .expect("the newline-terminated record completes the line");
        assert_eq!(line.payload, b"2026-08-06 ERROR first half second half");
        assert_eq!(line.stream, LogStream::Stdout);
        assert_eq!(
            line.source_len, expected_len,
            "byte accounting spans both consumed records"
        );
        assert_eq!(reassembler.pending_bytes(), 0);
    }

    #[test]
    fn rejoins_fragments_per_stream_when_the_other_stream_interleaves() {
        let mut reassembler = DockerJsonReassembler::default();

        assert!(
            reassembler
                .push(
                    br#"{"log":"stderr head ","stream":"stderr","time":"2026-08-06T15:03:17Z"}"#
                        .to_vec()
                )
                .is_none()
        );
        // A complete stdout record lands between the stderr fragments; it must
        // come out whole rather than being spliced into the stderr line.
        let interleaved = reassembler
            .push(
                br#"{"log":"stdout line\n","stream":"stdout","time":"2026-08-06T15:03:17Z"}"#
                    .to_vec(),
            )
            .expect("the stdout record is complete on its own");
        assert_eq!(interleaved.payload, b"stdout line");
        assert_eq!(interleaved.stream, LogStream::Stdout);

        let joined = reassembler
            .push(
                br#"{"log":"stderr tail\n","stream":"stderr","time":"2026-08-06T15:03:17Z"}"#
                    .to_vec(),
            )
            .expect("the stderr line completes");
        assert_eq!(joined.payload, b"stderr head stderr tail");
        assert_eq!(joined.stream, LogStream::Stderr);
    }

    #[test]
    fn non_docker_line_passes_through_the_reassembler() {
        let mut reassembler = DockerJsonReassembler::default();
        let raw = b"plain text line".to_vec();
        let line = reassembler.push(raw.clone()).expect("passed through");

        assert_eq!(line.payload, raw);
        assert_eq!(line.stream, LogStream::Unspecified);
        assert_eq!(line.source_len, raw.len() as u64 + 1);
    }
}
