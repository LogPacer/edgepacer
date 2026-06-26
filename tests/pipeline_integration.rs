//! Integration tests for the M4 guaranteed delivery pipeline.
//!
//! Tests the full flow: tailer → buffer → shipper → checkpoint
//! with crash recovery and the consecutive-ack invariant.

use std::time::SystemTime;

use edgepacer::batch_tracker::BatchTracker;
use edgepacer::buffer::DiskBuffer;
use edgepacer::checkpoint::{Checkpoint, CheckpointStore};

/// Test the full checkpoint → resume cycle simulating a crash.
#[test]
fn crash_recovery_preserves_buffered_entries() {
    let dir = tempfile::tempdir().unwrap();
    let buf_path = dir.path().join("buffer.redb");
    let cp_path = dir.path().join("checkpoints.redb");

    let file_path = "/var/log/test.log";

    // Session 1: enqueue some data, checkpoint partially, then "crash".
    {
        let mut buffer = DiskBuffer::open(&buf_path, 10).unwrap();
        let cp_store = CheckpointStore::open(&cp_path).unwrap();
        let mut tracker = BatchTracker::new();

        // Enqueue two batches.
        let (f1, l1) = buffer
            .enqueue_batch(&[b"line1".to_vec(), b"line2".to_vec()], 1000)
            .unwrap();
        tracker.track(0, 12, 42, f1, l1);

        let (f2, l2) = buffer
            .enqueue_batch(&[b"line3".to_vec(), b"line4".to_vec()], 2000)
            .unwrap();
        tracker.track(12, 24, 42, f2, l2);

        // Only ack the first batch.
        tracker.ack(1);

        // Checkpoint should be at batch 1's end (12), not batch 2.
        let safe_cp = tracker.safe_checkpoint().unwrap();
        assert_eq!(safe_cp.offset, 12);

        cp_store
            .save(&Checkpoint {
                path: file_path.into(),
                offset: safe_cp.offset,
                inode: safe_cp.inode,
                updated_at: SystemTime::now(),
                streaming: None,
            })
            .unwrap();

        // Delete acked entries from buffer.
        buffer
            .delete_sequences(&safe_cp.acked_buffer_sequences)
            .unwrap();

        // "Crash" — drop everything without acking batch 2.
    }

    // Session 2: recover — buffer should still have batch 2's entries.
    {
        let buffer = DiskBuffer::open(&buf_path, 10).unwrap();
        let cp_store = CheckpointStore::open(&cp_path).unwrap();

        // Checkpoint should be at offset 12 (batch 1 only).
        let cp = cp_store.load(file_path).unwrap().unwrap();
        assert_eq!(cp.offset, 12);
        assert_eq!(cp.inode, 42);

        // Buffer should still have batch 2's entries.
        let entries = buffer.peek(100).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"line3");
        assert_eq!(entries[1].data, b"line4");
    }
}

/// Test that the consecutive-ack rule prevents checkpoint advancement past gaps.
#[test]
fn consecutive_ack_rule_prevents_gap_advancement() {
    let mut tracker = BatchTracker::new();

    // Track 5 batches.
    for i in 0..5 {
        tracker.track(i * 100, (i + 1) * 100, 1, i * 10 + 1, (i + 1) * 10);
    }

    // Ack batches 1, 2, 4, 5 (skip 3).
    tracker.ack(1);
    tracker.ack(2);
    tracker.ack(4);
    tracker.ack(5);

    // Checkpoint should be at batch 2's end (200), not 4 or 5.
    let safe_cp = tracker.safe_checkpoint().unwrap();
    assert_eq!(safe_cp.offset, 200);

    // Now ack batch 3 — checkpoint should jump to batch 5.
    tracker.ack(3);
    let safe_cp = tracker.safe_checkpoint().unwrap();
    assert_eq!(safe_cp.offset, 500);
}

/// Test that buffer survives process restart and sequences continue.
#[test]
fn buffer_sequence_continuity_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let buf_path = dir.path().join("buffer.redb");

    // Session 1: enqueue entries 1-3.
    {
        let mut buffer = DiskBuffer::open(&buf_path, 10).unwrap();
        let (first, last) = buffer
            .enqueue_batch(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()], 1000)
            .unwrap();
        assert_eq!(first, 1);
        assert_eq!(last, 3);

        // Ack first two.
        buffer.delete_sequences(&[1, 2]).unwrap();
    }

    // Session 2: sequences should continue from 4, not 1.
    {
        let mut buffer = DiskBuffer::open(&buf_path, 10).unwrap();

        // Entry 3 should still be there.
        let entries = buffer.peek(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 3);
        assert_eq!(entries[0].data, b"c");

        // New entries should start from 4.
        let (first, last) = buffer.enqueue_batch(&[b"d".to_vec()], 2000).unwrap();
        assert_eq!(first, 4);
        assert_eq!(last, 4);
    }
}

/// Test tailer checkpoint resume with rotation detection.
#[test]
fn tailer_checkpoint_resume_detects_rotation() {
    use edgepacer::tailer::FileTailer;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("app.log");

    // Write initial content and get the platform file identity.
    std::fs::write(&log_path, "line1\nline2\nline3\n").unwrap();
    let original_inode = FileTailer::open_from_start(&log_path)
        .unwrap()
        .position()
        .inode;

    // Create checkpoint at offset 12 (after "line1\nline2\n").
    let cp = Checkpoint {
        path: log_path.to_string_lossy().into(),
        offset: 12,
        inode: original_inode,
        updated_at: SystemTime::now(),
        streaming: None,
    };

    // Normal resume: same file, same inode.
    {
        let mut tailer = FileTailer::open_with_checkpoint(&log_path, &cp).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"line3");
    }

    // Simulate rotation: delete and recreate with new content.
    #[cfg(unix)]
    {
        let rotated = dir.path().join("app.log.1");
        std::fs::rename(&log_path, &rotated).unwrap();
        std::fs::write(&log_path, "new_line1\nnew_line2\n").unwrap();

        // Resume with old checkpoint — should detect inode change and read from start.
        let mut tailer = FileTailer::open_with_checkpoint(&log_path, &cp).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"new_line1");
        assert_eq!(lines[1], b"new_line2");
    }
}

/// Test backpressure: buffer full stops reads.
#[test]
fn buffer_full_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let buf_path = dir.path().join("buffer.redb");

    // Buffer with 0 MB max — immediately full.
    let mut buffer = DiskBuffer::open(&buf_path, 0).unwrap();

    let result = buffer.enqueue_batch(&[b"data".to_vec()], 1000);
    assert!(result.is_err());

    match result {
        Err(edgepacer::buffer::BufferError::Full { .. }) => {} // Expected
        other => panic!("expected BufferError::Full, got {:?}", other),
    }
}
