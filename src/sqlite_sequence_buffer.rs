//! SQLite-backed durable sequence buffer for crash-safe log delivery.
//!
//! The single-file SQLite `seq -> bytes` FIFO backing
//! [`crate::buffer::DiskBuffer`] and [`crate::trace_buffer::TraceBuffer`], with
//! the same peek-send-delete semantics, but with a near-zero idle floor: an
//! empty/drained database is ~8 KiB (vs redb's fixed ~1–3.5 MiB), and the file
//! tracks the live backlog rather than a fixed page-cache slab.
//!
//! Durability: WAL journal with `synchronous=FULL` fsyncs every commit, so a
//! committed batch survives process crash and power loss — the bar required for
//! streaming sources where this buffer is the sole replay authority.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::counters::QueueDepthGauge;

/// Per-buffer durability, mapped to SQLite `PRAGMA synchronous`.
#[derive(Clone, Copy, Debug)]
pub enum Durability {
    /// `synchronous=FULL` — fsync every commit. For sole-copy buffers (streaming,
    /// trace) where the buffer is the only record of un-shipped data.
    Full,
    /// `synchronous=NORMAL` — fsync at WAL checkpoint, not on every commit. For
    /// replayable buffers (the file source is the replay authority; metrics and
    /// telemetry regenerate): durable across an app crash, at-least-once on power
    /// loss, and far higher write throughput.
    Normal,
}

impl Durability {
    fn pragma(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
        }
    }
}

/// Floor for the adaptive page cache. A source that is caught up or idle holds
/// only this much resident — 256 KiB (64 pages at the default 4 KiB page size),
/// enough for a FIFO's head/tail working set without pinning a burst-sized slab.
const MIN_CACHE_BYTES: usize = 256 * 1024;

pub(crate) struct SqliteSequenceBufferConfig {
    /// Approximate maximum backlog in megabytes; appends past this return `Full`.
    pub(crate) max_mb: u64,
    /// Upper bound on the adaptive page cache, in bytes. The buffer sizes its
    /// actual `PRAGMA cache_size` to the live backlog (its working set) between
    /// [`MIN_CACHE_BYTES`] and this ceiling, so an idle source holds almost
    /// nothing while a backed-up, high-volume one gets room to drain.
    pub(crate) cache_ceiling_bytes: usize,
    /// fsync policy — `Full` for sole-copy buffers, `Normal` for replayable ones.
    pub(crate) durability: Durability,
}

#[derive(Debug)]
pub(crate) struct RawSequenceEntry {
    pub(crate) sequence: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct AppendResult {
    pub(crate) first_sequence: u64,
    pub(crate) last_sequence: u64,
    pub(crate) bytes_written: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SqliteSequenceBufferError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("buffer full ({current_bytes} bytes, max {max_bytes})")]
    Full { current_bytes: u64, max_bytes: u64 },
}

/// Single-file SQLite FIFO shared by the durable buffers
/// ([`crate::buffer::DiskBuffer`] / [`crate::trace_buffer::TraceBuffer`]), keeping
/// each backend-agnostic. `current_bytes` and `count` are tracked in memory and
/// kept in lockstep with the table so the hot `is_empty`/`count`/`pressure`
/// checks never touch disk.
pub(crate) struct SqliteSequenceBuffer {
    /// `rusqlite::Connection` is `Send` but not `Sync` (interior `RefCell`s).
    /// Pipeline run-loops are `tokio::spawn`'d and hold a shared `&buffer` across
    /// `.await`, which requires the buffer to be `Sync` (as redb's `Database`
    /// was). The buffer has a single owning task, so this `Mutex` is always
    /// uncontended — it exists to restore `Sync`, not to arbitrate access.
    conn: Mutex<Connection>,
    max_bytes: u64,
    current_bytes: u64,
    count: u64,
    /// Upper bound on the page cache (from config); the live cache is sized to the
    /// backlog within `[MIN_CACHE_BYTES, cache_ceiling_bytes]`.
    cache_ceiling_bytes: usize,
    /// Last value pushed to `PRAGMA cache_size`, in bytes. Lets the hot
    /// append/delete paths skip re-issuing the pragma until the working set has
    /// crossed a 2× band (hysteresis), so resizing stays cheap.
    applied_cache_bytes: usize,
    /// Shared queue-depth gauge, kept in lockstep with `current_bytes`: seeded on
    /// `set_gauge`, adjusted on append/delete, and drained by Drop so a stopped
    /// pipeline's bytes leave the gauge (they re-enter when a pipeline reopens).
    gauge: Option<QueueDepthGauge>,
}

impl Drop for SqliteSequenceBuffer {
    fn drop(&mut self) {
        if let Some(ref gauge) = self.gauge {
            gauge.sub(self.current_bytes);
        }
    }
}

impl SqliteSequenceBuffer {
    /// Open or create the database. Blocking-pool bound: creation fsyncs and the
    /// size scan reads the entire entries table.
    pub(crate) fn open(
        path: &Path,
        config: SqliteSequenceBufferConfig,
    ) -> Result<Self, SqliteSequenceBufferError> {
        crate::common::run_blocking(|| {
            let conn = Connection::open(path)?;
            // WAL journal; `synchronous` is per-buffer — FULL for sole-copy
            // buffers, NORMAL for replayable ones (see Durability).
            // auto_vacuum=INCREMENTAL lets a drained buffer reclaim pages toward
            // the ~8 KiB floor; it must be set before the table exists on a fresh
            // database, so it leads the batch. The cache opens at the floor and is
            // sized to the live backlog below (see `resize_cache`).
            let min_kib = (MIN_CACHE_BYTES / 1024) as i64;
            let sync = config.durability.pragma();
            conn.execute_batch(&format!(
                "PRAGMA auto_vacuum=INCREMENTAL;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous={sync};
                 PRAGMA busy_timeout=5000;
                 PRAGMA cache_size=-{min_kib};
                 CREATE TABLE IF NOT EXISTS buffer(
                     seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                     data BLOB NOT NULL
                 );"
            ))?;

            let (count, current_bytes) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM buffer",
                [],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
            )?;

            let mut buffer = Self {
                conn: Mutex::new(conn),
                max_bytes: config.max_mb * 1024 * 1024,
                current_bytes,
                count,
                cache_ceiling_bytes: config.cache_ceiling_bytes.max(MIN_CACHE_BYTES),
                applied_cache_bytes: MIN_CACHE_BYTES,
                gauge: None,
            };
            // Size the cache to any replayed backlog so a reopen that drains
            // immediately isn't scanning a large B-tree through the floor.
            buffer.resize_cache();
            Ok(buffer)
        })
    }

    /// Attach the shared queue-depth gauge, seeding it with the bytes already on
    /// disk (the replayed backlog of a reopened buffer).
    pub(crate) fn set_gauge(&mut self, gauge: QueueDepthGauge) {
        gauge.add(self.current_bytes);
        self.gauge = Some(gauge);
    }

    /// Size the page cache to the live backlog — the buffer's working set. A
    /// source that is caught up or idle sits at [`MIN_CACHE_BYTES`]; a backed-up,
    /// high-volume one grows toward `cache_ceiling_bytes` so its drain scan stays
    /// in memory. This is what gives a high-volume source a big cache and a low
    /// mover a small one, without a fixed per-source slab: the page cache only
    /// pays off when the B-tree has many pages, which is exactly when the buffer
    /// is backed up.
    ///
    /// Only re-issues `PRAGMA cache_size` when the working set crosses a 2× band,
    /// so the hot append/delete callers pay just a few integer ops most of the
    /// time. A downsize also runs `shrink_memory`, handing the freed slab back to
    /// the allocator (jemalloc's background thread then purges it to the OS) so
    /// RSS tracks the backlog instead of pinning the burst high-water.
    fn resize_cache(&mut self) {
        let backlog = self.current_bytes as usize;
        let desired = backlog
            .saturating_add(backlog / 8) // headroom for B-tree interior pages
            .clamp(MIN_CACHE_BYTES, self.cache_ceiling_bytes);

        // Hysteresis: leave the cache alone while the working set stays within a
        // 2× band of what's applied, so a source hovering at a size doesn't churn
        // the pragma on every append/delete.
        let low = self.applied_cache_bytes / 2;
        let high = self.applied_cache_bytes.saturating_mul(2);
        if desired >= low && desired <= high {
            return;
        }

        let shrinking = desired < self.applied_cache_bytes;
        let kib = (desired / 1024).max(1) as i64;
        crate::common::run_blocking(|| {
            let conn = self.conn.lock().expect("buffer connection mutex poisoned");
            let sql = if shrinking {
                format!("PRAGMA cache_size=-{kib}; PRAGMA shrink_memory;")
            } else {
                format!("PRAGMA cache_size=-{kib};")
            };
            let _ = conn.execute_batch(&sql);
        });
        self.applied_cache_bytes = desired;
    }

    pub(crate) fn append(
        &mut self,
        entries: &[Vec<u8>],
    ) -> Result<AppendResult, SqliteSequenceBufferError> {
        if entries.is_empty() {
            return Ok(AppendResult {
                first_sequence: 0,
                last_sequence: 0,
                bytes_written: 0,
            });
        }

        let bytes_written: u64 = entries.iter().map(|entry| entry.len() as u64).sum();
        if self.current_bytes + bytes_written > self.max_bytes {
            return Err(SqliteSequenceBufferError::Full {
                current_bytes: self.current_bytes,
                max_bytes: self.max_bytes,
            });
        }

        // Blocking-pool bound: the commit fsyncs (synchronous=FULL). AUTOINCREMENT
        // gives monotonic sequences that never reuse a value, even after the table
        // is fully drained and reopened (matches the redb meta-counter semantics).
        let (first_sequence, last_sequence) = crate::common::run_blocking(|| {
            let mut conn = self.conn.lock().expect("buffer connection mutex poisoned");
            let tx = conn.transaction()?;
            let range = {
                let mut stmt = tx.prepare_cached("INSERT INTO buffer(data) VALUES (?1)")?;
                let mut first = 0i64;
                let mut last = 0i64;
                for (i, entry) in entries.iter().enumerate() {
                    stmt.execute(rusqlite::params![entry.as_slice()])?;
                    let id = tx.last_insert_rowid();
                    if i == 0 {
                        first = id;
                    }
                    last = id;
                }
                (first as u64, last as u64)
            };
            tx.commit()?;
            Ok::<_, SqliteSequenceBufferError>(range)
        })?;

        self.current_bytes += bytes_written;
        self.count += entries.len() as u64;
        if let Some(ref gauge) = self.gauge {
            gauge.add(bytes_written);
        }
        // Backlog grew — grow the cache toward the ceiling if it crossed a band.
        self.resize_cache();

        Ok(AppendResult {
            first_sequence,
            last_sequence,
            bytes_written,
        })
    }

    pub(crate) fn peek_raw(
        &self,
        count: usize,
    ) -> Result<Vec<RawSequenceEntry>, SqliteSequenceBufferError> {
        // Idle fast path: drain loops poll this every 50-100ms per pipeline.
        if self.current_bytes == 0 {
            return Ok(Vec::new());
        }

        // Blocking-pool bound: a cold peek reads up to a full batch from disk.
        crate::common::run_blocking(|| {
            let conn = self.conn.lock().expect("buffer connection mutex poisoned");
            let mut stmt =
                conn.prepare_cached("SELECT seq, data FROM buffer ORDER BY seq LIMIT ?1")?;
            let rows = stmt.query_map([count as i64], |row| {
                Ok(RawSequenceEntry {
                    sequence: row.get::<_, i64>(0)? as u64,
                    bytes: row.get::<_, Vec<u8>>(1)?,
                })
            })?;
            let mut entries = Vec::with_capacity(count);
            for row in rows {
                entries.push(row?);
            }
            Ok(entries)
        })
    }

    pub(crate) fn delete_sequences(
        &mut self,
        sequences: &[u64],
    ) -> Result<u64, SqliteSequenceBufferError> {
        if sequences.is_empty() {
            return Ok(0);
        }

        // SQLite caps bound parameters per statement (`SQLITE_MAX_VARIABLE_NUMBER`,
        // 999 on pre-3.32 builds). Chunk the `IN (…)` list so a large ack set never
        // overflows the limit, which would error the DELETE and silently strand
        // acked entries in the buffer until a restart rebuilds `current_bytes`.
        const DELETE_SEQUENCE_CHUNK: usize = 500;
        let current_bytes = self.current_bytes;

        // Blocking-pool bound: the commit fsyncs.
        let (freed_bytes, deleted) = crate::common::run_blocking(|| {
            let mut conn = self.conn.lock().expect("buffer connection mutex poisoned");
            let tx = conn.transaction()?;
            // All chunks share one transaction, so the delete stays atomic.
            let mut freed = 0u64;
            let mut deleted = 0u64;
            for chunk in sequences.chunks(DELETE_SEQUENCE_CHUNK) {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "DELETE FROM buffer WHERE seq IN ({placeholders}) RETURNING LENGTH(data)"
                );
                let mut stmt = tx.prepare(&sql)?;
                let params = rusqlite::params_from_iter(chunk.iter().map(|s| *s as i64));
                let rows = stmt.query_map(params, |row| row.get::<_, i64>(0))?;
                for row in rows {
                    freed += row? as u64;
                    deleted += 1;
                }
            }
            tx.commit()?;

            // Reclaim freed pages back toward the floor once fully drained, so a
            // streaming buffer that burst then drained doesn't pin its high-water
            // size on disk. Gated on the drain-to-empty edge to keep it cheap.
            if current_bytes.saturating_sub(freed) == 0 {
                let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
            }

            Ok::<_, SqliteSequenceBufferError>((freed, deleted))
        })?;

        self.current_bytes = self.current_bytes.saturating_sub(freed_bytes);
        self.count = self.count.saturating_sub(deleted);
        if let Some(ref gauge) = self.gauge {
            gauge.sub(freed_bytes);
        }
        // Backlog shrank — release cache back toward the floor if it dropped a band.
        self.resize_cache();
        Ok(freed_bytes)
    }

    pub(crate) fn is_empty(&self) -> Result<bool, SqliteSequenceBufferError> {
        Ok(self.count == 0)
    }

    pub(crate) fn count(&self) -> Result<u64, SqliteSequenceBufferError> {
        Ok(self.count)
    }

    pub(crate) fn pressure(&self) -> f64 {
        if self.max_bytes == 0 {
            return 1.0;
        }
        (self.current_bytes as f64 / self.max_bytes as f64).min(1.0)
    }

    pub(crate) fn current_bytes(&self) -> u64 {
        self.current_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &std::path::Path, max_mb: u64) -> SqliteSequenceBuffer {
        SqliteSequenceBuffer::open(
            &dir.join("seq.sqlite"),
            SqliteSequenceBufferConfig {
                max_mb,
                cache_ceiling_bytes: 1024 * 1024,
                durability: Durability::Full,
            },
        )
        .unwrap()
    }

    fn pragma_i64(buf: &SqliteSequenceBuffer, pragma: &str) -> i64 {
        buf.conn
            .lock()
            .unwrap()
            .query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn durability_pragmas_are_set() {
        let dir = tempfile::tempdir().unwrap();
        let buf = open(dir.path(), 10);

        let journal: String = buf
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();

        assert_eq!(journal.to_lowercase(), "wal");
        assert_eq!(
            pragma_i64(&buf, "synchronous"),
            2,
            "synchronous must be FULL (=2) for power-loss durability"
        );
    }

    #[test]
    fn normal_durability_sets_synchronous_normal() {
        let dir = tempfile::tempdir().unwrap();
        let buf = SqliteSequenceBuffer::open(
            &dir.path().join("seq.sqlite"),
            SqliteSequenceBufferConfig {
                max_mb: 10,
                cache_ceiling_bytes: 1024 * 1024,
                durability: Durability::Normal,
            },
        )
        .unwrap();
        assert_eq!(
            pragma_i64(&buf, "synchronous"),
            1,
            "Normal must map to synchronous=NORMAL (=1)"
        );
    }

    #[test]
    fn committed_data_is_durable_to_an_independent_connection() {
        // A committed batch must be visible to a *separate* connection opened on
        // the same file — proving durability lives in the WAL/db, not in-process
        // state. This is the crash-survival guarantee a replay authority needs.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seq.sqlite");
        {
            let mut buf = SqliteSequenceBuffer::open(
                &path,
                SqliteSequenceBufferConfig {
                    max_mb: 10,
                    cache_ceiling_bytes: 1024 * 1024,
                    durability: Durability::Full,
                },
            )
            .unwrap();
            buf.append(&[b"durable".to_vec()]).unwrap();
        }

        let other = Connection::open(&path).unwrap();
        let count: i64 = other
            .query_row("SELECT COUNT(*) FROM buffer", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn drained_buffer_reclaims_pages() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = open(dir.path(), 100);

        let line = vec![b'x'; 500];
        let mut seqs = Vec::new();
        for _ in 0..5000 {
            let r = buf.append(std::slice::from_ref(&line)).unwrap();
            seqs.push(r.first_sequence);
        }
        let pages_full = pragma_i64(&buf, "page_count");

        buf.delete_sequences(&seqs).unwrap();
        assert!(buf.is_empty().unwrap());
        let pages_drained = pragma_i64(&buf, "page_count");

        assert!(
            pages_drained < pages_full,
            "incremental_vacuum should reclaim pages on drain: {pages_drained} !< {pages_full}"
        );
    }

    #[test]
    fn sequences_are_monotonic_across_full_drain() {
        // AUTOINCREMENT must not reuse a sequence even after the table empties —
        // otherwise a reopened-and-drained buffer could collide keys.
        let dir = tempfile::tempdir().unwrap();
        let mut buf = open(dir.path(), 10);

        let r1 = buf.append(&[b"a".to_vec()]).unwrap();
        buf.delete_sequences(&[r1.first_sequence]).unwrap();
        assert!(buf.is_empty().unwrap());

        let r2 = buf.append(&[b"b".to_vec()]).unwrap();
        assert!(
            r2.first_sequence > r1.first_sequence,
            "sequence reused after drain: {} !> {}",
            r2.first_sequence,
            r1.first_sequence
        );
    }

    #[test]
    fn cache_size_tracks_backlog() {
        // The page cache must grow with the backlog (a high-volume source that
        // backs up) and fall back toward the floor once drained (a low mover),
        // rather than pinning a fixed per-source slab.
        let dir = tempfile::tempdir().unwrap();
        // Ceiling well above the burst so the cap doesn't mask the adaptation.
        let mut buf = SqliteSequenceBuffer::open(
            &dir.path().join("seq.sqlite"),
            SqliteSequenceBufferConfig {
                max_mb: 100,
                cache_ceiling_bytes: 16 * 1024 * 1024,
                durability: Durability::Full,
            },
        )
        .unwrap();

        // `cache_size` is stored as negative KiB, so a bigger cache reads as a
        // larger magnitude. An empty buffer sits at the floor.
        let idle = pragma_i64(&buf, "cache_size").abs();

        // Append a multi-MB backlog; the working set — and the cache — should grow.
        let line = vec![b'x'; 4096];
        let mut seqs = Vec::new();
        for _ in 0..1000 {
            let r = buf.append(std::slice::from_ref(&line)).unwrap();
            seqs.push(r.first_sequence);
        }
        let loaded = pragma_i64(&buf, "cache_size").abs();

        // Drain fully; the cache should drop back toward the floor.
        buf.delete_sequences(&seqs).unwrap();
        assert!(buf.is_empty().unwrap());
        let drained = pragma_i64(&buf, "cache_size").abs();

        assert!(
            loaded > idle,
            "cache should grow under backlog: {idle} -> {loaded}"
        );
        assert!(
            drained < loaded,
            "cache should shrink after drain: {loaded} -> {drained}"
        );
    }
}
