//! Disk-backed buffer for crash-safe trace delivery.
//!
//! Implements the same peek-send-delete pattern as the log delivery buffer,
//! but stores OTLP trace payloads together with their archive/repo destination.

use std::path::Path;

use crate::sqlite_sequence_buffer::{
    Durability, SqliteSequenceBuffer, SqliteSequenceBufferConfig, SqliteSequenceBufferError,
};
use tracing::{debug, info};

/// A single buffered trace payload with its sequence number and destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedTraceEntry {
    pub sequence: u64,
    pub archive_id: String,
    pub repo_id: String,
    pub payload: Vec<u8>,
}

/// Disk-backed buffer using SQLite.
pub struct TraceBuffer {
    core: SqliteSequenceBuffer,
}

/// Errors specific to trace buffer operations.
#[derive(Debug, thiserror::Error)]
pub enum TraceBufferError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("buffer full ({current_bytes} bytes, max {max_bytes})")]
    Full { current_bytes: u64, max_bytes: u64 },
    #[error("{field} identifier too long ({len} bytes, max 65535)")]
    IdentifierTooLong { field: &'static str, len: usize },
    #[error("corrupt entry at sequence {sequence}")]
    Corrupt { sequence: u64 },
}

impl From<SqliteSequenceBufferError> for TraceBufferError {
    fn from(err: SqliteSequenceBufferError) -> Self {
        match err {
            SqliteSequenceBufferError::Sqlite(err) => Self::Sqlite(err),
            SqliteSequenceBufferError::Full {
                current_bytes,
                max_bytes,
            } => Self::Full {
                current_bytes,
                max_bytes,
            },
        }
    }
}

fn checked_u16_len(field: &'static str, value: &str) -> Result<u16, TraceBufferError> {
    u16::try_from(value.len()).map_err(|_| TraceBufferError::IdentifierTooLong {
        field,
        len: value.len(),
    })
}

fn encode_entry(
    archive_id: &str,
    repo_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, TraceBufferError> {
    let archive_len = checked_u16_len("archive_id", archive_id)?;
    let repo_len = checked_u16_len("repo_id", repo_id)?;

    let mut buf = Vec::with_capacity(4 + archive_id.len() + repo_id.len() + payload.len());
    buf.extend_from_slice(&archive_len.to_be_bytes());
    buf.extend_from_slice(archive_id.as_bytes());
    buf.extend_from_slice(&repo_len.to_be_bytes());
    buf.extend_from_slice(repo_id.as_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

fn decode_entry(sequence: u64, raw: &[u8]) -> Option<BufferedTraceEntry> {
    if raw.len() < 4 {
        return None;
    }

    let archive_len = u16::from_be_bytes(raw[0..2].try_into().ok()?) as usize;
    if raw.len() < 2 + archive_len + 2 {
        return None;
    }

    let archive_start = 2;
    let archive_end = archive_start + archive_len;
    let archive_id = std::str::from_utf8(&raw[archive_start..archive_end])
        .ok()?
        .to_string();

    let repo_len = u16::from_be_bytes(raw[archive_end..archive_end + 2].try_into().ok()?) as usize;
    let repo_start = archive_end + 2;
    let repo_end = repo_start + repo_len;
    if raw.len() < repo_end {
        return None;
    }

    let repo_id = std::str::from_utf8(&raw[repo_start..repo_end])
        .ok()?
        .to_string();
    let payload = raw[repo_end..].to_vec();

    Some(BufferedTraceEntry {
        sequence,
        archive_id,
        repo_id,
        payload,
    })
}

impl TraceBuffer {
    /// Open or create a trace buffer at the given path.
    ///
    /// `max_mb` sets the approximate maximum buffer size in megabytes.
    pub fn open(path: &Path, max_mb: u64) -> Result<Self, TraceBufferError> {
        let core = SqliteSequenceBuffer::open(
            path,
            SqliteSequenceBufferConfig {
                max_mb,
                cache_ceiling_bytes: crate::buffer::cache_size_bytes(),
                // Trace payloads are the sole copy until shipped — fsync each commit.
                durability: Durability::Full,
            },
        )?;

        info!(
            path = %path.display(),
            max_mb,
            current_bytes = core.current_bytes(),
            "trace buffer opened"
        );

        Ok(Self { core })
    }

    /// Enqueue a single serialized trace payload atomically.
    pub fn enqueue(
        &mut self,
        archive_id: &str,
        repo_id: &str,
        payload: &[u8],
    ) -> Result<u64, TraceBufferError> {
        let encoded = encode_entry(archive_id, repo_id, payload)?;
        let entries = [encoded];
        let appended = self.core.append(&entries)?;

        debug!(
            sequence = appended.first_sequence,
            archive_id,
            repo_id,
            bytes = appended.bytes_written,
            "trace payload enqueued to buffer"
        );

        Ok(appended.first_sequence)
    }

    /// Peek at the oldest `count` entries WITHOUT deleting them.
    pub fn peek(&self, count: usize) -> Result<Vec<BufferedTraceEntry>, TraceBufferError> {
        let raw_entries = self.core.peek_raw(count)?;
        let mut entries = Vec::with_capacity(count);

        for raw_entry in raw_entries {
            let entry = decode_entry(raw_entry.sequence, &raw_entry.bytes).ok_or(
                TraceBufferError::Corrupt {
                    sequence: raw_entry.sequence,
                },
            )?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Delete entries by sequence numbers after confirmed delivery.
    pub fn delete_sequences(&mut self, sequences: &[u64]) -> Result<(), TraceBufferError> {
        if sequences.is_empty() {
            return Ok(());
        }

        let freed_bytes = self.core.delete_sequences(sequences)?;

        debug!(
            deleted = sequences.len(),
            freed_bytes,
            remaining_bytes = self.core.current_bytes(),
            "trace buffer entries deleted after confirmed delivery"
        );

        Ok(())
    }

    /// Check if the buffer is empty (no unacked entries).
    pub fn is_empty(&self) -> Result<bool, TraceBufferError> {
        Ok(self.core.is_empty()?)
    }

    /// Number of entries in the buffer.
    pub fn count(&self) -> Result<u64, TraceBufferError> {
        Ok(self.core.count()?)
    }

    /// Approximate buffer pressure as a ratio 0.0–1.0.
    pub fn pressure(&self) -> f64 {
        self.core.pressure()
    }

    /// Current approximate size in bytes.
    pub fn current_bytes(&self) -> u64 {
        self.core.current_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_buffer(max_mb: u64) -> (tempfile::TempDir, TraceBuffer) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("trace-buffer.sqlite");
        let buf = TraceBuffer::open(&db_path, max_mb).unwrap();
        (dir, buf)
    }

    #[test]
    fn enqueue_and_peek_round_trip() {
        let (_dir, mut buf) = temp_buffer(10);

        let seq = buf
            .enqueue("arc_123", "repo_456", b"trace-payload")
            .unwrap();
        assert_eq!(seq, 1);

        let entries = buf.peek(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].archive_id, "arc_123");
        assert_eq!(entries[0].repo_id, "repo_456");
        assert_eq!(entries[0].payload, b"trace-payload");
    }

    #[test]
    fn preserves_fifo_ordering_across_enqueues() {
        let (_dir, mut buf) = temp_buffer(10);

        buf.enqueue("arc_1", "repo_1", b"first").unwrap();
        buf.enqueue("arc_2", "repo_2", b"second").unwrap();

        let entries = buf.peek(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].payload, b"first");
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[1].payload, b"second");
    }

    #[test]
    fn delete_after_ack_removes_only_selected_entries() {
        let (_dir, mut buf) = temp_buffer(10);

        buf.enqueue("arc_1", "repo_1", b"first").unwrap();
        buf.enqueue("arc_2", "repo_2", b"second").unwrap();
        buf.enqueue("arc_3", "repo_3", b"third").unwrap();
        let before_delete = buf.current_bytes();
        assert!(before_delete > 0);

        buf.delete_sequences(&[1, 2]).unwrap();

        let remaining = buf.peek(10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sequence, 3);
        assert_eq!(remaining[0].archive_id, "arc_3");
        assert_eq!(remaining[0].repo_id, "repo_3");
        assert_eq!(remaining[0].payload, b"third");
        assert!(buf.current_bytes() < before_delete);
    }

    #[test]
    fn is_empty_and_count() {
        let (_dir, mut buf) = temp_buffer(10);

        assert!(buf.is_empty().unwrap());
        assert_eq!(buf.count().unwrap(), 0);

        buf.enqueue("arc_1", "repo_1", b"payload").unwrap();
        assert!(!buf.is_empty().unwrap());
        assert_eq!(buf.count().unwrap(), 1);

        buf.delete_sequences(&[1]).unwrap();
        assert!(buf.is_empty().unwrap());
        assert_eq!(buf.count().unwrap(), 0);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("trace-buffer.sqlite");

        {
            let mut buf = TraceBuffer::open(&db_path, 10).unwrap();
            buf.enqueue("arc_123", "repo_456", b"persist-me").unwrap();
        }

        {
            let buf = TraceBuffer::open(&db_path, 10).unwrap();
            let entries = buf.peek(10).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].archive_id, "arc_123");
            assert_eq!(entries[0].repo_id, "repo_456");
            assert_eq!(entries[0].payload, b"persist-me");
        }
    }

    #[test]
    fn sequence_continues_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("trace-buffer.sqlite");

        {
            let mut buf = TraceBuffer::open(&db_path, 10).unwrap();
            assert_eq!(buf.enqueue("arc_1", "repo_1", b"first").unwrap(), 1);
        }

        {
            let mut buf = TraceBuffer::open(&db_path, 10).unwrap();
            assert_eq!(buf.enqueue("arc_2", "repo_2", b"second").unwrap(), 2);
            let entries = buf.peek(10).unwrap();
            assert_eq!(entries[0].sequence, 1);
            assert_eq!(entries[1].sequence, 2);
        }
    }

    #[test]
    fn rejects_writes_when_buffer_is_full() {
        let (_dir, mut buf) = temp_buffer(1);

        let large_payload = vec![0u8; 800_000];
        buf.enqueue("arc_1", "repo_1", &large_payload).unwrap();

        let result = buf.enqueue("arc_2", "repo_2", &large_payload);
        assert!(matches!(result, Err(TraceBufferError::Full { .. })));
    }

    #[test]
    fn pressure_increases_with_usage() {
        let (_dir, mut buf) = temp_buffer(1);

        assert_eq!(buf.pressure(), 0.0);

        buf.enqueue("arc_1", "repo_1", &[0u8; 1000]).unwrap();

        assert!(buf.pressure() > 0.0);
        assert!(buf.pressure() < 0.01);
    }

    #[test]
    fn destination_metadata_survives_decode() {
        let (_dir, mut buf) = temp_buffer(10);

        buf.enqueue("arc_destination", "repo_destination", b"payload")
            .unwrap();

        let entry = buf.peek(1).unwrap().pop().unwrap();
        assert_eq!(entry.archive_id, "arc_destination");
        assert_eq!(entry.repo_id, "repo_destination");
    }

    #[test]
    fn decode_rejects_truncated_data() {
        assert!(decode_entry(1, &[0; 1]).is_none());
        assert!(decode_entry(1, &[0; 3]).is_none());
    }

    #[test]
    fn peek_returns_typed_corrupt_error_for_bad_entry() {
        let (_dir, mut buf) = temp_buffer(10);
        let bad_entry = vec![0; 3];

        let appended = buf.core.append(&[bad_entry]).unwrap();
        let result = buf.peek(10);

        assert!(matches!(
            result,
            Err(TraceBufferError::Corrupt { sequence }) if sequence == appended.first_sequence
        ));
    }
}
