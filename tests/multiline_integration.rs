//! Integration tests for multi-line aggregation in the delivery pipeline.
//!
//! These tests exercise the assembler → buffer → checkpoint path without
//! actually starting a relay. They focus on:
//!   - A Java-style stack trace is aggregated into a single buffered event.
//!   - Checkpoint never advances past lines that are still sitting in the
//!     assembler's in-progress buffer.
//!   - Idle timeout flushes incomplete events.

use std::time::Duration;

use edgepacer::batch_tracker::BatchTracker;
use edgepacer::buffer::DiskBuffer;
use edgepacer::entry_assembler::{EntryAssembler, LineContext};

/// The canonical multiline scenario: a 4-line Java-style stack trace
/// followed by a new header line — flushes the stack trace as ONE event.
#[test]
fn stack_trace_aggregates_into_single_buffered_event() {
    let mut asm = EntryAssembler::new(r"^\d{4}-\d{2}-\d{2}", 500, Duration::from_secs(5))
        .expect("regex compiles");

    let lines: Vec<(&[u8], u64, u64)> = vec![
        (b"2026-04-21 10:00:00 ERROR request failed", 0, 42),
        (b"java.lang.NullPointerException", 42, 74),
        (b"    at com.example.Foo.bar(Foo.java:12)", 74, 115),
        (b"    at com.example.Main.main(Main.java:5)", 115, 158),
        (b"2026-04-21 10:00:01 INFO recovered", 158, 194),
    ];

    let mut emitted: Vec<(Vec<u8>, edgepacer::entry_assembler::EventMetadata)> = Vec::new();
    for (line, start, end) in lines {
        let ctx = LineContext {
            start_offset: start,
            end_offset: end,
            inode: 42,
        };
        if let Some(ev) = asm.process(line.to_vec(), ctx) {
            emitted.push(ev);
        }
    }

    // Should have emitted ONE event — the stack trace. The last header
    // line is still buffered until either the next header, a timeout, or
    // a shutdown flush.
    assert_eq!(emitted.len(), 1, "only the stack trace flushes so far");
    let (event, meta) = &emitted[0];
    let expected: Vec<u8> = [
        "2026-04-21 10:00:00 ERROR request failed",
        "java.lang.NullPointerException",
        "    at com.example.Foo.bar(Foo.java:12)",
        "    at com.example.Main.main(Main.java:5)",
    ]
    .join("\n")
    .into_bytes();
    assert_eq!(event, &expected);
    assert_eq!(meta.line_count, 4);
    assert_eq!(meta.first.start_offset, 0);
    assert_eq!(
        meta.last.end_offset, 158,
        "emitted event covers bytes 0..158 — the next header (158..194) stays buffered"
    );

    // Flush on shutdown should emit the final buffered header.
    let (final_event, final_meta) = asm.flush().expect("flush emits the tail");
    assert_eq!(final_event, b"2026-04-21 10:00:01 INFO recovered");
    assert_eq!(final_meta.first.start_offset, 158);
    assert_eq!(final_meta.last.end_offset, 194);
}

/// The critical checkpoint invariant under aggregation: the pipeline must
/// checkpoint only to the END of the last-emitted event, NEVER to the end
/// of lines that are still buffered in the assembler. This test asserts
/// that the aggregator's returned metadata preserves that boundary.
#[test]
fn checkpoint_cannot_advance_past_buffered_lines() {
    let dir = tempfile::tempdir().unwrap();
    let buf_path = dir.path().join("buf.redb");

    let mut asm = EntryAssembler::new(r"^HEAD", 500, Duration::from_secs(5)).unwrap();
    let mut buffer = DiskBuffer::open(&buf_path, 10).unwrap();
    let mut tracker = BatchTracker::new();

    // Two headers with one continuation each. After feeding all 4 lines,
    // the aggregator emits the first event; the second is still buffered.
    let lines: Vec<(&[u8], u64, u64)> = vec![
        (b"HEAD one", 0, 9),
        (b"  cont", 9, 16),
        (b"HEAD two", 16, 25),
        (b"  cont", 25, 32),
    ];

    let mut emitted_events: Vec<Vec<u8>> = Vec::new();
    let mut last_event_end: u64 = 0;

    for (line, start, end) in lines {
        let ctx = LineContext {
            start_offset: start,
            end_offset: end,
            inode: 1,
        };
        if let Some((event, meta)) = asm.process(line.to_vec(), ctx) {
            last_event_end = meta.last.end_offset;
            emitted_events.push(event);
        }
    }

    assert_eq!(emitted_events.len(), 1);
    assert_eq!(
        last_event_end, 16,
        "first event's end_offset must stop at line 'HEAD one\\n  cont\\n' boundary (16), \
         not extend into the still-buffered 'HEAD two' content"
    );

    // Enqueue into buffer; track with the LAST-EVENT end offset.
    let (seq_first, seq_last) = buffer.enqueue_batch(&emitted_events, 1000).unwrap();
    tracker.track(0, last_event_end, 1, seq_first, seq_last);

    // Simulate ack of this batch — safe_checkpoint must be at 16, NOT 32.
    tracker.ack(seq_last);
    let safe = tracker.safe_checkpoint().expect("ack produces a safe cp");
    assert_eq!(
        safe.offset, 16,
        "checkpoint must NOT advance past the end of the emitted event — \
         the still-buffered 'HEAD two' + continuation sit in 16..32"
    );

    // Now flush the assembler (simulating shutdown) — gets the second event.
    let (tail_event, tail_meta) = asm.flush().unwrap();
    assert_eq!(tail_meta.last.end_offset, 32);
    let (tail_first, tail_last) = buffer.enqueue_batch(&[tail_event], 2000).unwrap();
    tracker.track(16, 32, 1, tail_first, tail_last);
    tracker.ack(tail_last);

    // Now the consecutive-ack rule advances checkpoint to the full 32.
    let safe = tracker.safe_checkpoint().expect("tail batch acked");
    assert_eq!(safe.offset, 32);
}

/// Idle timeout flushes an incomplete event, so stalled producers don't
/// keep lines stuck in the aggregator indefinitely.
#[test]
fn idle_timeout_emits_buffered_event() {
    let mut asm = EntryAssembler::new(r"^START", 500, Duration::from_millis(40)).unwrap();

    let ctx = LineContext {
        start_offset: 0,
        end_offset: 10,
        inode: 1,
    };
    assert!(asm.process(b"START once".to_vec(), ctx).is_none());

    // Below the timeout — nothing to flush.
    std::thread::sleep(Duration::from_millis(15));
    assert!(asm.check_timeout().is_none());

    // Past the timeout — flush.
    std::thread::sleep(Duration::from_millis(40));
    let (event, _meta) = asm
        .check_timeout()
        .expect("idle past timeout must emit the buffered event");
    assert_eq!(event, b"START once");
}
