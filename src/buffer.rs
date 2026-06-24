//! Disk-backed buffer for crash-safe log delivery.
//!
//! Implements the peek-send-delete pattern matching legacy EdgePacer's
//! `internal/buffer/disk_buffer.go`:
//!
//! 1. **Enqueue**: persist log batch to disk (crash-safe after return)
//! 2. **Peek**: read oldest unacked batches WITHOUT deleting
//! 3. **Ack**: delete batch after confirmed delivery
//!
//! Uses SQLite (WAL journal, `synchronous=FULL`) for crash-safe durability.
//! Entries are binary-encoded with a 12-byte header (8B timestamp + 4B length)
//! matching Go's format.
//!
//! Invariant: data is never deleted before confirmed delivery. On crash,
//! all unacked entries survive and are replayed on restart.

use std::path::Path;

pub use crate::sqlite_sequence_buffer::Durability;
use crate::sqlite_sequence_buffer::{
    SqliteSequenceBuffer, SqliteSequenceBufferConfig, SqliteSequenceBufferError,
};
use tracing::{debug, info};

/// Default per-buffer page-cache **ceiling**, in MiB.
///
/// The buffer no longer pins a fixed slab: it sizes `PRAGMA cache_size` to the
/// live backlog (its working set) and only climbs toward this ceiling when a
/// source backs up. So this bounds the *peak* a backed-up, high-volume source
/// can reach — an idle or caught-up source sits near the ~256 KiB floor, and N
/// of them no longer multiply into a fixed RSS floor (the failure mode that the
/// redb→SQLite cutover, then this adaptive sizing, each chipped away at).
/// Profiling (50 streams × 10k lines/s) showed 8 MiB is enough headroom for
/// drain throughput under sustained load.
const DEFAULT_CACHE_MB: u64 = 8;
const MIN_CACHE_MB: u64 = 1;

/// Resolve the per-buffer cache cap (bytes) from `EDGEPACER_BUFFER_CACHE_MB`,
/// falling back to [`DEFAULT_CACHE_MB`]. Read once at process start so the value
/// is a stable, host-tunable knob — set it lower on memory-constrained edge
/// hosts, higher where drain throughput matters more than footprint.
///
/// This is the static (env/default) layer. A Rails-pushed config value, when
/// present, overrides it via [`cache_bytes_for`].
pub(crate) fn cache_size_bytes() -> usize {
    static CACHE_BYTES: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        let mb = std::env::var("EDGEPACER_BUFFER_CACHE_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CACHE_MB)
            .max(MIN_CACHE_MB);
        (mb * 1024 * 1024) as usize
    });
    *CACHE_BYTES
}

/// Resolve the effective cache cap (bytes) given an optional override from
/// dynamic (Rails) config. Precedence: explicit config override > env var >
/// compile-time default. The override is floored at [`MIN_CACHE_MB`] so a bad
/// value can't starve the write cache.
pub(crate) fn cache_bytes_for(override_mb: Option<u64>) -> usize {
    match override_mb {
        Some(mb) => (mb.max(MIN_CACHE_MB) * 1024 * 1024) as usize,
        None => cache_size_bytes(),
    }
}

/// A single buffered entry with its sequence number.
#[derive(Debug)]
pub struct BufferedEntry {
    /// Monotonically increasing sequence number (ordering key).
    pub sequence: u64,
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: i64,
    /// Raw log line data.
    pub data: Vec<u8>,
}

/// Binary entry encoding: [8B timestamp_ns (big-endian i64)][4B data_len (big-endian u32)][data]
/// Matches Go's `guaranteed_delivery_exporter.go` encoding with 12-byte overhead.
fn checked_data_len(len: usize) -> Result<u32, BufferError> {
    u32::try_from(len).map_err(|_| BufferError::EntryTooLarge { len })
}

fn encode_entry(timestamp_ns: i64, data: &[u8]) -> Result<Vec<u8>, BufferError> {
    let data_len = checked_data_len(data.len())?;
    let mut buf = Vec::with_capacity(12 + data.len());
    buf.extend_from_slice(&timestamp_ns.to_be_bytes());
    buf.extend_from_slice(&data_len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

fn decode_entry(sequence: u64, raw: &[u8]) -> Option<BufferedEntry> {
    if raw.len() < 12 {
        return None;
    }
    let timestamp_ns = i64::from_be_bytes(raw[0..8].try_into().ok()?);
    let data_len = u32::from_be_bytes(raw[8..12].try_into().ok()?) as usize;
    if raw.len() < 12 + data_len {
        return None;
    }
    Some(BufferedEntry {
        sequence,
        timestamp_ns,
        data: raw[12..12 + data_len].to_vec(),
    })
}

/// Disk-backed buffer using SQLite.
pub struct DiskBuffer {
    core: SqliteSequenceBuffer,
}

/// Errors specific to buffer operations.
#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("buffer full ({current_bytes} bytes, max {max_bytes})")]
    Full { current_bytes: u64, max_bytes: u64 },
    #[error("buffer entry too large ({len} bytes, max 4294967295)")]
    EntryTooLarge { len: usize },
    #[error("corrupt entry at sequence {sequence}")]
    Corrupt { sequence: u64 },
}

impl From<SqliteSequenceBufferError> for BufferError {
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

impl DiskBuffer {
    /// Open or create a disk buffer at the given path.
    ///
    /// `max_mb` sets the approximate maximum buffer size in megabytes. The redb
    /// page cache uses the env/default cap; use [`open_with_cache`] to override.
    ///
    /// [`open_with_cache`]: Self::open_with_cache
    pub fn open(path: &Path, max_mb: u64) -> Result<Self, BufferError> {
        // Replayable default (file source / regenerated metrics+telemetry); the
        // streaming pipeline opts into Durability::Full via open_with_cache.
        Self::open_with_cache(path, max_mb, cache_size_bytes(), Durability::Normal)
    }

    /// Like [`open`] but with an explicit redb page-cache cap in bytes, used by
    /// the orchestrator to apply a Rails-pushed buffer-cache setting.
    ///
    /// [`open`]: Self::open
    pub fn open_with_cache(
        path: &Path,
        max_mb: u64,
        cache_bytes: usize,
        durability: Durability,
    ) -> Result<Self, BufferError> {
        let core = SqliteSequenceBuffer::open(
            path,
            SqliteSequenceBufferConfig {
                max_mb,
                cache_ceiling_bytes: cache_bytes,
                durability,
            },
        )?;

        info!(
            path = %path.display(),
            max_mb,
            current_bytes = core.current_bytes(),
            "disk buffer opened"
        );

        Ok(Self { core })
    }

    /// Enqueue a batch of log lines atomically.
    ///
    /// All entries are persisted in a single transaction. Returns the sequence
    /// range (first, last) assigned to the batch.
    ///
    /// Returns `BufferError::Full` if the buffer would exceed `max_bytes`.
    pub fn enqueue_batch(
        &mut self,
        lines: &[Vec<u8>],
        timestamp_ns: i64,
    ) -> Result<(u64, u64), BufferError> {
        if lines.is_empty() {
            return Ok((0, 0));
        }

        let encoded_entries: Vec<Vec<u8>> = lines
            .iter()
            .map(|line| encode_entry(timestamp_ns, line))
            .collect::<Result<_, _>>()?;
        let appended = self.core.append(&encoded_entries)?;

        debug!(
            first_seq = appended.first_sequence,
            last_seq = appended.last_sequence,
            entries = lines.len(),
            bytes = appended.bytes_written,
            "batch enqueued to disk buffer"
        );

        Ok((appended.first_sequence, appended.last_sequence))
    }

    /// Peek at the oldest `count` entries WITHOUT deleting them.
    ///
    /// Returns entries in sequence order. The caller ships these, then calls
    /// `delete_sequences()` only after confirmed delivery.
    pub fn peek(&self, count: usize) -> Result<Vec<BufferedEntry>, BufferError> {
        let raw_entries = self.core.peek_raw(count)?;
        let mut entries = Vec::with_capacity(count);

        for raw_entry in raw_entries {
            let entry =
                decode_entry(raw_entry.sequence, &raw_entry.bytes).ok_or(BufferError::Corrupt {
                    sequence: raw_entry.sequence,
                })?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Delete entries by sequence numbers after confirmed delivery.
    ///
    /// Only call this after the delivery endpoint has acknowledged receipt.
    /// This is the "delete" part of peek-send-delete.
    pub fn delete_sequences(&mut self, sequences: &[u64]) -> Result<(), BufferError> {
        if sequences.is_empty() {
            return Ok(());
        }

        let freed_bytes = self.core.delete_sequences(sequences)?;

        debug!(
            deleted = sequences.len(),
            freed_bytes,
            remaining_bytes = self.core.current_bytes(),
            "buffer entries deleted after confirmed delivery"
        );

        Ok(())
    }

    /// Check if the buffer is empty (no unacked entries).
    pub fn is_empty(&self) -> Result<bool, BufferError> {
        Ok(self.core.is_empty()?)
    }

    /// Number of entries in the buffer.
    pub fn count(&self) -> Result<u64, BufferError> {
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

    /// Attach the shared queue-depth gauge (seeds it with the current
    /// backlog; kept in lockstep with enqueue/delete and drained on drop).
    pub fn set_gauge(&mut self, gauge: crate::counters::QueueDepthGauge) {
        self.core.set_gauge(gauge);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_buffer(max_mb: u64) -> (tempfile::TempDir, DiskBuffer) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");
        let buf = DiskBuffer::open(&db_path, max_mb).unwrap();
        (dir, buf)
    }

    #[test]
    fn cache_bytes_for_override_wins_and_is_floored() {
        assert_eq!(cache_bytes_for(Some(4)), 4 * 1024 * 1024);
        // A zero/garbage override is floored, never zero.
        assert_eq!(
            cache_bytes_for(Some(0)),
            MIN_CACHE_MB as usize * 1024 * 1024
        );
        // No override falls back to the env/default layer.
        assert_eq!(cache_bytes_for(None), cache_size_bytes());
    }

    #[test]
    fn open_with_cache_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");
        let mut buf =
            DiskBuffer::open_with_cache(&db_path, 10, 2 * 1024 * 1024, Durability::Normal).unwrap();
        buf.enqueue_batch(&[b"line".to_vec()], 1).unwrap();
        assert_eq!(buf.peek(10).unwrap().len(), 1);
    }

    #[test]
    fn enqueue_and_peek() {
        let (_dir, mut buf) = temp_buffer(10);

        let lines = vec![b"hello".to_vec(), b"world".to_vec()];
        let (first, last) = buf.enqueue_batch(&lines, 1000).unwrap();
        assert_eq!(first, 1);
        assert_eq!(last, 2);

        let entries = buf.peek(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[0].timestamp_ns, 1000);
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[1].data, b"world");
    }

    #[test]
    fn peek_does_not_delete() {
        let (_dir, mut buf) = temp_buffer(10);

        buf.enqueue_batch(&[b"line1".to_vec()], 1000).unwrap();

        // Peek twice — should get same entry both times
        let e1 = buf.peek(10).unwrap();
        let e2 = buf.peek(10).unwrap();
        assert_eq!(e1.len(), 1);
        assert_eq!(e2.len(), 1);
        assert_eq!(e1[0].sequence, e2[0].sequence);
    }

    #[test]
    fn delete_after_ack() {
        let (_dir, mut buf) = temp_buffer(10);

        buf.enqueue_batch(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()], 1000)
            .unwrap();

        // Delete first two
        buf.delete_sequences(&[1, 2]).unwrap();

        let remaining = buf.peek(10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].data, b"c");
        assert_eq!(remaining[0].sequence, 3);
    }

    #[test]
    fn is_empty_and_count() {
        let (_dir, mut buf) = temp_buffer(10);

        assert!(buf.is_empty().unwrap());
        assert_eq!(buf.count().unwrap(), 0);

        buf.enqueue_batch(&[b"x".to_vec()], 1000).unwrap();
        assert!(!buf.is_empty().unwrap());
        assert_eq!(buf.count().unwrap(), 1);

        buf.delete_sequences(&[1]).unwrap();
        assert!(buf.is_empty().unwrap());
    }

    #[test]
    fn respects_max_size() {
        // Buffer with 1 byte max (will reject any write)
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");
        let mut buf = DiskBuffer::open(&db_path, 0).unwrap();

        let result = buf.enqueue_batch(&[b"data".to_vec()], 1000);
        assert!(matches!(result, Err(BufferError::Full { .. })));
    }

    #[test]
    fn pressure_increases_with_usage() {
        let (_dir, mut buf) = temp_buffer(1); // 1 MB max

        assert_eq!(buf.pressure(), 0.0);

        // Enqueue some data
        let line = vec![0u8; 1000]; // ~1KB per entry
        buf.enqueue_batch(&[line], 1000).unwrap();

        assert!(buf.pressure() > 0.0);
        assert!(buf.pressure() < 0.01); // ~1KB out of 1MB
    }

    #[test]
    fn sequence_numbers_monotonic_across_batches() {
        let (_dir, mut buf) = temp_buffer(10);

        let (_, last1) = buf.enqueue_batch(&[b"a".to_vec()], 1000).unwrap();
        let (first2, _) = buf.enqueue_batch(&[b"b".to_vec()], 2000).unwrap();

        assert_eq!(first2, last1 + 1);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");

        // Write with first instance
        {
            let mut buf = DiskBuffer::open(&db_path, 10).unwrap();
            buf.enqueue_batch(&[b"survive".to_vec()], 1000).unwrap();
        }

        // Reopen — simulates crash recovery
        {
            let buf = DiskBuffer::open(&db_path, 10).unwrap();
            let entries = buf.peek(10).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].data, b"survive");
        }
    }

    #[test]
    fn sequence_continues_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");

        // Write batch 1
        {
            let mut buf = DiskBuffer::open(&db_path, 10).unwrap();
            buf.enqueue_batch(&[b"a".to_vec()], 1000).unwrap(); // seq 1
        }

        // Reopen and write batch 2 — sequence should continue
        {
            let mut buf = DiskBuffer::open(&db_path, 10).unwrap();
            let (first, _) = buf.enqueue_batch(&[b"b".to_vec()], 2000).unwrap();
            assert_eq!(first, 2); // not 1 again
        }
    }

    #[test]
    fn binary_encoding_roundtrip() {
        let data = b"test log line with unicode: \xc3\xa9\xc3\xa0\xc3\xbc";
        let ts = 1_700_000_000_000_000_000i64;

        let encoded = encode_entry(ts, data).unwrap();
        assert_eq!(encoded.len(), 12 + data.len());

        let decoded = decode_entry(42, &encoded).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.timestamp_ns, ts);
        assert_eq!(decoded.data, data);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn checked_data_len_rejects_oversized_length() {
        let too_large = u32::MAX as usize + 1;

        assert!(matches!(
            checked_data_len(too_large),
            Err(BufferError::EntryTooLarge { len }) if len == too_large
        ));
    }

    #[test]
    fn decode_rejects_truncated_data() {
        assert!(decode_entry(1, &[0; 5]).is_none()); // too short for header
        assert!(decode_entry(1, &[0; 12]).is_some()); // header only, 0 data length
    }

    #[test]
    fn peek_returns_typed_corrupt_error_for_bad_entry() {
        let (_dir, mut buf) = temp_buffer(10);
        let bad_entry = vec![0; 5];

        let appended = buf.core.append(&[bad_entry]).unwrap();
        let result = buf.peek(10);

        assert!(matches!(
            result,
            Err(BufferError::Corrupt { sequence }) if sequence == appended.first_sequence
        ));
    }

    /// The full gauge lifecycle: enqueue adds, confirmed delete subtracts,
    /// drop drains the remainder (stopped pipeline), and reopening seeds the
    /// gauge with the persisted backlog.
    #[test]
    fn queue_depth_gauge_tracks_buffer_lifecycle() {
        let counters = crate::counters::AgentCounters::new();
        let gauge = counters.queue_depth_gauge();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("buffer.redb");

        {
            let mut buf = DiskBuffer::open(&db_path, 10).unwrap();
            buf.set_gauge(gauge.clone());
            assert_eq!(gauge.get(), 0, "fresh buffer seeds nothing");

            let (first, _) = buf
                .enqueue_batch(&[b"aaaa".to_vec(), b"bbbb".to_vec()], 100)
                .unwrap();
            let after_enqueue = gauge.get();
            assert_eq!(after_enqueue, buf.current_bytes());
            assert!(after_enqueue > 0);

            buf.delete_sequences(&[first]).unwrap();
            assert_eq!(gauge.get(), buf.current_bytes());
            assert!(gauge.get() < after_enqueue);
        }
        // Dropped (pipeline stopped): its remaining bytes leave the gauge.
        assert_eq!(gauge.get(), 0);

        // Reopen with a gauge: the persisted backlog re-enters.
        let mut buf = DiskBuffer::open(&db_path, 10).unwrap();
        buf.set_gauge(gauge.clone());
        assert_eq!(gauge.get(), buf.current_bytes());
        assert!(gauge.get() > 0, "backlog survives on disk and seeds gauge");
    }
}
