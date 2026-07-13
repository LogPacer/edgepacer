//! Multiline entry aggregator — stitches continuation lines into a single
//! logical event based on a start-pattern regex.
//!
//! Mirrors legacy EdgePacer's `internal/exporter/entry_assembler.go`. Each
//! configured source optionally owns an assembler. Lines that match the
//! start pattern begin a new event; lines that don't match are continuations
//! of the current in-progress event.
//!
//! Flush triggers (any of the three emits the buffered event):
//! 1. A new line matches `start_pattern` AND the buffer is non-empty.
//! 2. The buffered line count reaches `max_lines`.
//! 3. More than `timeout` has passed since the last line was received.
//!    This is Vector-style: the timeout resets on every line, so it
//!    measures idle time since the last line, NOT total event duration.
//!
//! The in-progress buffer only flushes when one of those triggers fires;
//! otherwise continuation lines accumulate. `flush()` is called on stream
//! shutdown to emit whatever is left; `check_timeout()` is called
//! periodically by the owning pipeline to emit idle events even when no
//! new line has arrived.
//!
//! Per-event offset bookkeeping: `EventMetadata` carries the start offset
//! of the first constituent line and the end offset of the last. The
//! pipeline uses `end_offset` as the checkpoint position after
//! confirmed delivery — so checkpoints never advance past lines still
//! buffered in the assembler.

use std::time::{Duration, Instant};

use regex::Regex;

use crate::config::MultilineConfig;

/// Assemble a batch of already-extracted lines into multi-line events, matching
/// the streaming wire path.
///
/// This is the batch counterpart of the streaming `StreamingEntryAssembler`: it
/// drives the same [`EntryAssembler`], so the joined event bytes are identical
/// to what the wire ships for the same input. Used by the sampler, whose input
/// is a finite batch rather than a live stream — every line is fed through
/// `process`, then `flush` drains the final in-progress event. There are no idle
/// timeouts in a batch, so `timeout_secs` is irrelevant here.
///
/// When `multiline` is `None`, the lines pass through unchanged (each line is
/// its own event), so a non-multiline source's bytes are untouched.
pub fn assemble_batch(
    lines: Vec<Vec<u8>>,
    multiline: Option<&MultilineConfig>,
) -> Result<Vec<Vec<u8>>, regex::Error> {
    let Some(cfg) = multiline else {
        return Ok(lines);
    };

    let timeout = Duration::from_secs(u64::from(cfg.timeout_secs.max(1)));
    let mut assembler = EntryAssembler::new(&cfg.start_pattern, cfg.max_lines as usize, timeout)?;

    let mut events = Vec::new();
    for (offset, line) in lines.into_iter().enumerate() {
        let start = offset as u64;
        let ctx = LineContext {
            start_offset: start,
            end_offset: start + 1,
            inode: 0,
        };
        if let Some((event, _)) = assembler.process(line, ctx) {
            events.push(event);
        }
    }
    if let Some((event, _)) = assembler.flush() {
        events.push(event);
    }

    Ok(events)
}

/// Default max-lines cap for an assembled event. Matches Go (`entry_assembler.go:114`).
pub const DEFAULT_MAX_LINES: usize = 500;

/// Default idle timeout before a buffered event is force-flushed.
/// Matches Go (`entry_assembler.go:117`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Position information for a single constituent line in an aggregated event.
#[derive(Debug, Clone)]
pub struct LineContext {
    /// Byte offset of the line's first byte in the source file.
    pub start_offset: u64,
    /// Byte offset immediately after the line's terminating `\n`.
    pub end_offset: u64,
    /// Inode of the file this line came from.
    pub inode: u64,
}

/// Metadata describing an emitted multi-line event.
///
/// Carries the first and last `LineContext` so the pipeline can:
/// - Use `last.end_offset` as the checkpoint position once the event
///   is confirmed delivered by the relay.
/// - Use `first.start_offset` as the batch start for tracking purposes.
#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub first: LineContext,
    pub last: LineContext,
    pub line_count: usize,
}

/// Aggregates consecutive log lines into multi-line events.
pub struct EntryAssembler {
    start_pattern: Regex,
    max_lines: usize,
    timeout: Duration,
    buffer: Vec<Vec<u8>>,
    contexts: Vec<LineContext>,
    last_line_at: Option<Instant>,
}

impl EntryAssembler {
    /// Compile `start_pattern` and build an assembler with the given cap
    /// and idle timeout. Zero values fall back to `DEFAULT_MAX_LINES` /
    /// `DEFAULT_TIMEOUT`, matching Go's NewEntryAssembler behavior.
    pub fn new(
        start_pattern: &str,
        max_lines: usize,
        timeout: Duration,
    ) -> Result<Self, regex::Error> {
        let max_lines = if max_lines == 0 {
            DEFAULT_MAX_LINES
        } else {
            max_lines
        };
        let timeout = if timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };

        Ok(Self {
            start_pattern: Regex::new(start_pattern)?,
            max_lines,
            timeout,
            buffer: Vec::new(),
            contexts: Vec::new(),
            last_line_at: None,
        })
    }

    /// Process a single line with its byte-offset context.
    ///
    /// If the line triggers a flush (start-match + non-empty buffer, or
    /// buffer full, or idle timeout), returns the previous event. The
    /// new line begins the next in-progress event.
    ///
    /// Returns `None` when the line is buffered as a continuation without
    /// emitting anything.
    pub fn process(&mut self, line: Vec<u8>, ctx: LineContext) -> Option<(Vec<u8>, EventMetadata)> {
        let now = Instant::now();
        let is_start = self.start_pattern.is_match(&lossy(&line));
        let timed_out = self
            .last_line_at
            .is_some_and(|t| now.duration_since(t) > self.timeout)
            && !self.buffer.is_empty();
        let buffer_full = self.buffer.len() >= self.max_lines;

        let should_flush = (is_start && !self.buffer.is_empty()) || buffer_full || timed_out;

        if should_flush {
            let emitted = self.drain_current();
            self.buffer.push(line);
            self.contexts.push(ctx);
            self.last_line_at = Some(now);
            return Some(emitted);
        }

        self.buffer.push(line);
        self.contexts.push(ctx);
        self.last_line_at = Some(now);
        None
    }

    /// Check whether the buffered event has been idle longer than `timeout`.
    /// Called periodically by the owning pipeline to emit stale events even
    /// when no new line has arrived.
    pub fn check_timeout(&mut self) -> Option<(Vec<u8>, EventMetadata)> {
        let last = self.last_line_at?;
        if self.buffer.is_empty() {
            return None;
        }
        if Instant::now().duration_since(last) <= self.timeout {
            return None;
        }
        Some(self.drain_current())
    }

    /// Emit whatever is currently buffered. Used on shutdown so no
    /// in-progress event is lost.
    pub fn flush(&mut self) -> Option<(Vec<u8>, EventMetadata)> {
        if self.buffer.is_empty() {
            return None;
        }
        Some(self.drain_current())
    }

    /// True when no lines are currently buffered.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn drain_current(&mut self) -> (Vec<u8>, EventMetadata) {
        let lines = std::mem::take(&mut self.buffer);
        let contexts = std::mem::take(&mut self.contexts);
        self.last_line_at = None;

        let first = contexts
            .first()
            .cloned()
            .expect("drain_current on empty buffer");
        let last = contexts
            .last()
            .cloned()
            .expect("drain_current on empty buffer");
        let line_count = contexts.len();

        let event = join_with_newline(lines);
        (
            event,
            EventMetadata {
                first,
                last,
                line_count,
            },
        )
    }
}

/// Join line byte slices with `\n` separators, no trailing newline. Matches
/// Go's `strings.Join(buffer, "\n")` contract.
fn join_with_newline(lines: Vec<Vec<u8>>) -> Vec<u8> {
    if lines.is_empty() {
        return Vec::new();
    }
    let sep_count = lines.len() - 1;
    let total: usize = lines.iter().map(|l| l.len()).sum::<usize>() + sep_count;
    let mut out = Vec::with_capacity(total);
    for (i, line) in lines.into_iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(&line);
    }
    out
}

/// Render bytes lossily as UTF-8 for regex matching. Invalid bytes become
/// replacement characters — safe because the regex only cares about the
/// start pattern; the original bytes in `line` are preserved for emission.
fn lossy(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(start: u64, end: u64) -> LineContext {
        LineContext {
            start_offset: start,
            end_offset: end,
            inode: 42,
        }
    }

    #[test]
    fn starts_new_event_flushes_previous() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, DEFAULT_TIMEOUT).unwrap();

        // First line — starts an event, buffered.
        assert!(
            asm.process(b"2026-04-21 INFO hello".to_vec(), ctx(0, 22))
                .is_none()
        );

        // Continuation line — appended without emission.
        assert!(
            asm.process(b"    at line 1".to_vec(), ctx(22, 36))
                .is_none()
        );

        // Another start line — flushes the previous event.
        let emitted = asm.process(b"2026-04-21 ERROR boom".to_vec(), ctx(36, 58));
        let (event, meta) = emitted.expect("start line must flush the prior event");
        assert_eq!(event, b"2026-04-21 INFO hello\n    at line 1");
        assert_eq!(meta.line_count, 2);
        assert_eq!(meta.first.start_offset, 0);
        assert_eq!(meta.last.end_offset, 36);
    }

    #[test]
    fn buffer_full_flushes() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 3, DEFAULT_TIMEOUT).unwrap();

        // Start event.
        assert!(
            asm.process(b"2026-04-21 start".to_vec(), ctx(0, 17))
                .is_none()
        );
        // Continuations fill the cap.
        assert!(asm.process(b"cont 1".to_vec(), ctx(17, 24)).is_none());
        assert!(asm.process(b"cont 2".to_vec(), ctx(24, 31)).is_none());

        // Fourth line — cap of 3 reached, flushes.
        let emitted = asm.process(b"cont 3".to_vec(), ctx(31, 38));
        let (event, meta) = emitted.expect("max_lines must flush");
        assert_eq!(event, b"2026-04-21 start\ncont 1\ncont 2");
        assert_eq!(meta.line_count, 3);
    }

    #[test]
    fn idle_timeout_flushes_via_check_timeout() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, Duration::from_millis(50)).unwrap();

        assert!(
            asm.process(b"2026-04-21 alone".to_vec(), ctx(0, 17))
                .is_none()
        );
        assert!(asm.check_timeout().is_none(), "not yet timed out");

        std::thread::sleep(Duration::from_millis(80));

        let (event, meta) = asm.check_timeout().expect("timeout must flush");
        assert_eq!(event, b"2026-04-21 alone");
        assert_eq!(meta.line_count, 1);

        // After check_timeout emits, buffer is empty — another check_timeout
        // call returns None.
        assert!(asm.check_timeout().is_none());
    }

    #[test]
    fn timeout_resets_on_every_line_vector_style() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, Duration::from_millis(100)).unwrap();

        assert!(
            asm.process(b"2026-04-21 start".to_vec(), ctx(0, 17))
                .is_none()
        );

        // Sleep less than timeout, feed a continuation — timer resets.
        std::thread::sleep(Duration::from_millis(60));
        assert!(asm.process(b"cont 1".to_vec(), ctx(17, 24)).is_none());

        // Sleep again less than timeout — total elapsed > 100ms, but since
        // the last line the elapsed is only ~60ms, so no timeout.
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            asm.check_timeout().is_none(),
            "timeout must reset on each line"
        );

        // Now sleep past the timeout.
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            asm.check_timeout().is_some(),
            "idle past timeout must flush"
        );
    }

    #[test]
    fn flush_emits_remaining_event_on_shutdown() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, DEFAULT_TIMEOUT).unwrap();

        assert!(
            asm.process(b"2026-04-21 lone".to_vec(), ctx(0, 16))
                .is_none()
        );
        assert!(asm.process(b"continuation".to_vec(), ctx(16, 29)).is_none());

        let (event, meta) = asm.flush().expect("flush must emit buffered event");
        assert_eq!(event, b"2026-04-21 lone\ncontinuation");
        assert_eq!(meta.line_count, 2);
        assert!(asm.is_empty());

        // Flush on empty buffer returns None.
        assert!(asm.flush().is_none());
    }

    #[test]
    fn blank_lines_become_continuations() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, DEFAULT_TIMEOUT).unwrap();

        assert!(
            asm.process(b"2026-04-21 header".to_vec(), ctx(0, 18))
                .is_none()
        );
        assert!(asm.process(b"".to_vec(), ctx(18, 19)).is_none()); // blank line
        assert!(asm.process(b"after blank".to_vec(), ctx(19, 31)).is_none());

        let (event, meta) = asm.flush().expect("flush emits");
        assert_eq!(event, b"2026-04-21 header\n\nafter blank");
        assert_eq!(meta.line_count, 3);
    }

    #[test]
    fn invalid_utf8_line_does_not_panic() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, DEFAULT_TIMEOUT).unwrap();

        // Start line is valid UTF-8 and matches.
        assert!(
            asm.process(b"2026-04-21 start".to_vec(), ctx(0, 17))
                .is_none()
        );
        // Continuation with lone high bytes — must still be buffered without error.
        assert!(
            asm.process(vec![0xC0, 0xFF, 0xFE, 0x80], ctx(17, 22))
                .is_none()
        );

        let (event, meta) = asm.flush().unwrap();
        assert_eq!(&event[..17], b"2026-04-21 start\n");
        assert_eq!(&event[17..], &[0xC0, 0xFF, 0xFE, 0x80]);
        assert_eq!(meta.line_count, 2);
    }

    #[test]
    fn zero_max_lines_uses_default() {
        let asm = EntryAssembler::new(r"^x", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(asm.max_lines, DEFAULT_MAX_LINES);
    }

    #[test]
    fn zero_timeout_uses_default() {
        let asm = EntryAssembler::new(r"^x", 10, Duration::ZERO).unwrap();
        assert_eq!(asm.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn invalid_regex_is_rejected() {
        assert!(EntryAssembler::new("[unclosed", 500, DEFAULT_TIMEOUT).is_err());
    }

    #[test]
    fn assemble_batch_without_multiline_passes_lines_through() {
        let lines = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        let out = assemble_batch(lines.clone(), None).unwrap();
        assert_eq!(out, lines, "no multiline config leaves bytes untouched");
    }

    /// Kill-test: the batch assembler used by the sampler must produce the exact
    /// same events as driving the streaming `EntryAssembler` line-by-line — that
    /// is the assembler the wire uses, so this proves sample==wire for multiline.
    #[test]
    fn assemble_batch_matches_streaming_assembler() {
        let cfg = MultilineConfig {
            start_pattern: r"^\d{4}-\d{2}-\d{2}".to_string(),
            max_lines: 500,
            timeout_secs: 5,
        };
        let lines = vec![
            b"2026-07-13 INFO starting up".to_vec(),
            b"    with a continuation".to_vec(),
            b"    and another".to_vec(),
            b"2026-07-13 ERROR boom".to_vec(),
            b"    stack frame 1".to_vec(),
        ];

        // Wire reference: drive EntryAssembler directly, exactly like the
        // streaming path, then flush the trailing event.
        let mut wire =
            EntryAssembler::new(&cfg.start_pattern, cfg.max_lines as usize, DEFAULT_TIMEOUT)
                .unwrap();
        let mut wire_events = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let ctx = ctx(i as u64, i as u64 + 1);
            if let Some((event, _)) = wire.process(line.clone(), ctx) {
                wire_events.push(event);
            }
        }
        if let Some((event, _)) = wire.flush() {
            wire_events.push(event);
        }

        let batch_events = assemble_batch(lines, Some(&cfg)).unwrap();

        assert_eq!(batch_events, wire_events);
        assert_eq!(
            batch_events,
            vec![
                b"2026-07-13 INFO starting up\n    with a continuation\n    and another".to_vec(),
                b"2026-07-13 ERROR boom\n    stack frame 1".to_vec(),
            ]
        );
    }

    #[test]
    fn empty_buffer_check_timeout_returns_none() {
        let mut asm = EntryAssembler::new(r"^\d{4}", 500, Duration::from_millis(10)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(asm.check_timeout().is_none());
    }
}
