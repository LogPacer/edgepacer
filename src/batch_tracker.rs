//! Batch tracker — tracks in-flight batches for safe checkpoint advancement.
//!
//! Implements legacy EdgePacer's consecutive-ack rule from
//! `internal/delivery/batch_tracker.go`:
//!
//! The checkpoint can only advance through CONSECUTIVE acked batches from the
//! oldest. If batch sequence is [1:acked, 2:acked, 3:pending, 4:acked], the
//! safe checkpoint is batch 2's end offset. Batch 4's ack doesn't help because
//! batch 3 hasn't been confirmed yet.
//!
//! This prevents checkpoint advancement past undelivered data — the core
//! correctness invariant for guaranteed delivery.

use std::collections::BTreeMap;

use tracing::{debug, warn};

/// Status of a tracked batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchStatus {
    /// Submitted, in-flight or queued for delivery.
    Pending,
    /// Delivery confirmed by endpoint.
    Acked,
    /// Permanently failed after max retries (moved to DLQ).
    Failed,
}

/// A tracked batch with its delivery state and file position.
#[derive(Debug, Clone)]
pub struct TrackedBatch {
    /// Monotonic sequence number (ordering key).
    pub sequence: u64,
    /// File offset at the START of this batch's data.
    pub start_offset: u64,
    /// File offset at the END of this batch's data.
    /// This is the checkpoint position if all batches up to and including
    /// this one are acked.
    pub end_offset: u64,
    /// Inode of the file when this batch was read.
    pub inode: u64,
    /// Buffer sequence range (for delete-on-ack).
    pub buffer_first_seq: u64,
    pub buffer_last_seq: u64,
    /// Current delivery status.
    pub status: BatchStatus,
}

/// Batch tracker — the consecutive-ack rule engine.
///
/// Maintains an ordered map of in-flight batches and computes the safe
/// checkpoint position.
pub struct BatchTracker {
    /// Batches ordered by sequence number (BTreeMap guarantees ordering).
    batches: BTreeMap<u64, TrackedBatch>,
    /// Next sequence number to assign.
    next_sequence: u64,
}

impl Default for BatchTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchTracker {
    pub fn new() -> Self {
        Self {
            batches: BTreeMap::new(),
            next_sequence: 1,
        }
    }

    /// Track a new batch. Returns the assigned sequence number.
    ///
    /// Call this when a batch is read from the tailer and enqueued to the buffer.
    pub fn track(
        &mut self,
        start_offset: u64,
        end_offset: u64,
        inode: u64,
        buffer_first_seq: u64,
        buffer_last_seq: u64,
    ) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        self.batches.insert(
            seq,
            TrackedBatch {
                sequence: seq,
                start_offset,
                end_offset,
                inode,
                buffer_first_seq,
                buffer_last_seq,
                status: BatchStatus::Pending,
            },
        );

        debug!(batch_seq = seq, start_offset, end_offset, "batch tracked");

        seq
    }

    /// Mark a batch as successfully delivered.
    pub fn ack(&mut self, sequence: u64) {
        if let Some(batch) = self.batches.get_mut(&sequence) {
            batch.status = BatchStatus::Acked;
            debug!(batch_seq = sequence, "batch acked");
        } else {
            warn!(batch_seq = sequence, "ack for unknown batch");
        }
    }

    /// Mark a batch as permanently failed (will be moved to DLQ).
    pub fn fail(&mut self, sequence: u64) {
        if let Some(batch) = self.batches.get_mut(&sequence) {
            batch.status = BatchStatus::Failed;
            warn!(batch_seq = sequence, "batch failed permanently");
        }
    }

    /// Compute the safe checkpoint offset using the consecutive-ack rule.
    ///
    /// Iterates from the oldest batch. Advances the checkpoint through
    /// consecutive acked batches. Stops at the first pending or failed batch.
    ///
    /// Returns `None` if no batches have been acked from the start, or if
    /// the tracker is empty.
    pub fn safe_checkpoint(&self) -> Option<SafeCheckpoint> {
        let mut checkpoint: Option<SafeCheckpoint> = None;

        for batch in self.batches.values() {
            match batch.status {
                BatchStatus::Acked => {
                    checkpoint = Some(SafeCheckpoint {
                        offset: batch.end_offset,
                        inode: batch.inode,
                        // Collect all consecutive acked buffer sequences for deletion.
                        acked_buffer_sequences: checkpoint
                            .map(|c| c.acked_buffer_sequences)
                            .unwrap_or_default()
                            .into_iter()
                            .chain(batch.buffer_first_seq..=batch.buffer_last_seq)
                            .collect(),
                    });
                }
                BatchStatus::Pending | BatchStatus::Failed => {
                    // Stop — can't advance past a pending or failed batch.
                    break;
                }
            }
        }

        checkpoint
    }

    /// Remove all acked batches that have been checkpointed.
    ///
    /// Call this after persisting the checkpoint and deleting buffer entries.
    /// Removes the consecutive acked prefix from the tracker.
    pub fn drain_acked(&mut self) -> usize {
        let mut drained = 0;

        // Collect keys of consecutive acked batches from the start.
        let to_remove: Vec<u64> = self
            .batches
            .iter()
            .take_while(|(_, b)| b.status == BatchStatus::Acked)
            .map(|(&seq, _)| seq)
            .collect();

        for seq in &to_remove {
            self.batches.remove(seq);
            drained += 1;
        }

        if drained > 0 {
            debug!(
                drained,
                remaining = self.batches.len(),
                "drained acked batches"
            );
        }

        drained
    }

    /// Whether any batches are still pending delivery.
    pub fn has_pending(&self) -> bool {
        self.batches
            .values()
            .any(|b| b.status == BatchStatus::Pending)
    }

    /// Whether any batches have permanently failed.
    pub fn has_failed(&self) -> bool {
        self.batches
            .values()
            .any(|b| b.status == BatchStatus::Failed)
    }

    /// Number of in-flight (pending) batches.
    pub fn pending_count(&self) -> usize {
        self.batches
            .values()
            .filter(|b| b.status == BatchStatus::Pending)
            .count()
    }

    /// Total tracked batches.
    pub fn total_count(&self) -> usize {
        self.batches.len()
    }

    /// Sequence number of the oldest pending batch, if any.
    ///
    /// Used by the pipeline to ack/fail the batch being drained.
    /// Since drain always processes in order (peek returns oldest first),
    /// the oldest pending batch is the one being shipped.
    pub fn oldest_pending_sequence(&self) -> Option<u64> {
        self.batches
            .iter()
            .find(|(_, b)| b.status == BatchStatus::Pending)
            .map(|(&seq, _)| seq)
    }
}

/// Result of `safe_checkpoint()` — the offset to persist and buffer sequences to delete.
#[derive(Debug, Clone)]
pub struct SafeCheckpoint {
    /// File offset safe to checkpoint.
    pub offset: u64,
    /// Inode of the file at this checkpoint.
    pub inode: u64,
    /// Buffer sequences that can be safely deleted (all consecutive-acked).
    pub acked_buffer_sequences: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_no_checkpoint() {
        let tracker = BatchTracker::new();
        assert!(tracker.safe_checkpoint().is_none());
        assert!(!tracker.has_pending());
        assert!(!tracker.has_failed());
    }

    #[test]
    fn single_acked_batch() {
        let mut tracker = BatchTracker::new();
        let seq = tracker.track(0, 100, 1, 1, 5);
        tracker.ack(seq);

        let cp = tracker.safe_checkpoint().unwrap();
        assert_eq!(cp.offset, 100);
        assert_eq!(cp.inode, 1);
        assert_eq!(cp.acked_buffer_sequences, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn consecutive_ack_rule_stops_at_pending() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 3);
        let _s2 = tracker.track(100, 200, 1, 4, 6); // pending
        let s3 = tracker.track(200, 300, 1, 7, 9);

        tracker.ack(s1);
        tracker.ack(s3); // acked but after a gap

        // Checkpoint should only be at batch 1's end (100), not batch 3 (300)
        let cp = tracker.safe_checkpoint().unwrap();
        assert_eq!(cp.offset, 100);
        assert_eq!(cp.acked_buffer_sequences, vec![1, 2, 3]);
    }

    #[test]
    fn consecutive_ack_rule_stops_at_failed() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 2);
        let s2 = tracker.track(100, 200, 1, 3, 4);
        let s3 = tracker.track(200, 300, 1, 5, 6);

        tracker.ack(s1);
        tracker.fail(s2); // failed permanently
        tracker.ack(s3);

        let cp = tracker.safe_checkpoint().unwrap();
        assert_eq!(cp.offset, 100); // stops at batch 1
    }

    #[test]
    fn all_pending_no_checkpoint() {
        let mut tracker = BatchTracker::new();
        tracker.track(0, 100, 1, 1, 5);
        tracker.track(100, 200, 1, 6, 10);

        assert!(tracker.safe_checkpoint().is_none());
        assert!(tracker.has_pending());
    }

    #[test]
    fn drain_acked_removes_prefix() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 2);
        let s2 = tracker.track(100, 200, 1, 3, 4);
        let _s3 = tracker.track(200, 300, 1, 5, 6); // pending

        tracker.ack(s1);
        tracker.ack(s2);

        let drained = tracker.drain_acked();
        assert_eq!(drained, 2);
        assert_eq!(tracker.total_count(), 1); // only s3 remains
    }

    #[test]
    fn drain_stops_at_pending() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 2);
        let _s2 = tracker.track(100, 200, 1, 3, 4); // pending
        let s3 = tracker.track(200, 300, 1, 5, 6);

        tracker.ack(s1);
        tracker.ack(s3);

        let drained = tracker.drain_acked();
        assert_eq!(drained, 1); // only s1 drained, s2 blocks s3
        assert_eq!(tracker.total_count(), 2);
    }

    #[test]
    fn pending_and_failed_counts() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 2);
        tracker.track(100, 200, 1, 3, 4);
        tracker.track(200, 300, 1, 5, 6);

        tracker.fail(s1);

        assert_eq!(tracker.pending_count(), 2);
        assert!(tracker.has_failed());
        assert!(tracker.has_pending());
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let mut tracker = BatchTracker::new();
        let s1 = tracker.track(0, 100, 1, 1, 1);
        let s2 = tracker.track(100, 200, 1, 2, 2);
        let s3 = tracker.track(200, 300, 1, 3, 3);

        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }
}
