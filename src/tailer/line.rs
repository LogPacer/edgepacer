use std::io::{self, BufRead};

/// Outcome of a single-line read from the underlying reader.
pub(super) struct LineReadOutcome {
    /// Total bytes advanced past in the underlying reader, including any
    /// overflow bytes that were truncated from `line_buf`. The caller adds
    /// this to the tailer's current-file offset.
    pub(super) consumed: usize,
    /// True if the line exceeded the cap and bytes after `max_bytes` were
    /// discarded from `line_buf` (but still consumed from the reader).
    pub(super) truncated: bool,
}

/// Read one line (bytes up to and including the terminating `\n`) into
/// `line_buf`, capturing at most `max_bytes` bytes. If the line is longer
/// than the cap, captures the first `max_bytes` bytes and keeps draining
/// until `\n` so subsequent reads start at a fresh logical line. Works on
/// arbitrary bytes -- does not assume UTF-8.
pub(super) fn read_one_line<R: BufRead>(
    reader: &mut R,
    line_buf: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<LineReadOutcome> {
    let mut consumed = 0;
    let mut truncated = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(LineReadOutcome {
                consumed,
                truncated,
            });
        }
        let (end, saw_newline) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        let remaining_cap = max_bytes.saturating_sub(line_buf.len());
        let take_n = remaining_cap.min(end);
        if take_n < end {
            truncated = true;
        }
        line_buf.extend_from_slice(&chunk[..take_n]);
        reader.consume(end);
        consumed += end;
        if saw_newline {
            return Ok(LineReadOutcome {
                consumed,
                truncated,
            });
        }
    }
}

/// Strip a trailing `\n` and optionally a preceding `\r` from the buffer.
/// Leaves empty buffers empty; a buffer containing only line terminators
/// becomes empty (emitted as an empty log line).
pub(super) fn trim_line_ending(buf: &mut Vec<u8>) {
    if buf.last().copied() == Some(b'\n') {
        buf.pop();
        if buf.last().copied() == Some(b'\r') {
            buf.pop();
        }
    }
}
