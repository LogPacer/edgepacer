//! One-shot migration of legacy redb buffers/checkpoints to SQLite.
//!
//! Earlier phases moved the disk buffer, checkpoint store, and trace buffer from
//! redb onto SQLite and renamed `*.redb` -> `*.sqlite`. Without this pass an
//! upgrading agent would orphan the redb files: file pipelines would re-tail from
//! offset 0 (mass duplicate re-ship) and the streaming/trace buffers — the *sole
//! copy* of un-shipped data — would be lost.
//!
//! This scans the cache dir once at startup, before any pipeline opens its
//! store, applying a correctness-forced policy per artifact:
//!   - `checkpoints.redb` / `streaming_checkpoints.redb` -> migrate to `.sqlite`
//!   - `streaming_buffer.redb` (sole copy)               -> drain to `.sqlite`
//!   - `trace-buffer-*.redb` (sole copy)                 -> drain to `.sqlite`
//!   - `buffer_*.redb` / `metrics_buffer` / `telemetry`  -> discard (replayable)
//!
//! Idempotent (acts only when the `.redb` exists, skips when the `.sqlite`
//! target is already present, and deletes the `.redb` after) and best-effort (a
//! per-file failure removes its partial target, logs, and degrades to a re-tail
//! for that source — never blocking startup). redb survives as a dependency only
//! for this read side; remove the module — and the dep — once the fleet is past
//! this revision.

use std::path::{Path, PathBuf};

use anyhow::Result;
use redb::{Database, ReadableTable, TableDefinition};
use tracing::{info, warn};

use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::sqlite_sequence_buffer::{Durability, SqliteSequenceBuffer, SqliteSequenceBufferConfig};

/// Legacy redb table layouts (must match the pre-migration `buffer.rs` /
/// `trace_buffer.rs` / `checkpoint.rs` definitions exactly, for the read side).
const LEGACY_BUFFER: TableDefinition<'static, u64, &'static [u8]> = TableDefinition::new("buffer");
const LEGACY_TRACE_BUFFER: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("trace_buffer");
const LEGACY_CHECKPOINTS: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("checkpoints");

/// Scan `root` recursively and migrate/clean any legacy redb artifacts.
/// Never panics; logs a summary when anything was touched.
pub fn migrate_redb_to_sqlite(root: &Path) {
    let mut redb_files = Vec::new();
    collect_redb_files(root, &mut redb_files);

    let (mut migrated, mut discarded, mut failed) = (0usize, 0usize, 0usize);
    for path in redb_files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let durable = if name == "checkpoints.redb" || name == "streaming_checkpoints.redb" {
            Some(migrate_checkpoints(&path))
        } else if name == "streaming_buffer.redb" {
            Some(drain_buffer(&path, LEGACY_BUFFER))
        } else if name.starts_with("trace-buffer-") {
            // Trace payloads are pushed to the proxy and buffered when the
            // ingest is down — the buffer is their sole copy, so drain it.
            Some(drain_buffer(&path, LEGACY_TRACE_BUFFER))
        } else {
            // buffer_*.redb, metrics_buffer.redb, telemetry_buffer.redb: the
            // source file (or next metrics cycle) is the replay authority.
            None
        };

        match durable {
            Some(Err(e)) => {
                failed += 1;
                warn!(path = %path.display(), error = %format!("{e:#}"), "legacy migration failed; source will re-tail");
                continue; // leave the .redb in place for a retry next boot
            }
            Some(Ok(())) => migrated += 1,
            None => discarded += 1,
        }

        if let Err(e) = std::fs::remove_file(&path) {
            warn!(path = %path.display(), error = %e, "legacy migration: could not remove redb file");
        }
    }

    if migrated + discarded + failed > 0 {
        info!(
            migrated,
            discarded, failed, "legacy redb -> sqlite migration complete"
        );
    }
}

fn migrate_checkpoints(redb_path: &Path) -> Result<()> {
    let target = redb_path.with_extension("sqlite");
    if target.exists() {
        return Ok(()); // already migrated on a prior boot
    }

    let result = (|| -> Result<()> {
        let db = Database::open(redb_path)?;
        let store = CheckpointStore::open(&target)?;
        let txn = db.begin_read()?;
        let table = txn.open_table(LEGACY_CHECKPOINTS)?;
        for row in table.iter()? {
            let (_key, value) = row?;
            let cp: Checkpoint = serde_json::from_slice(value.value())?;
            store.save(&cp)?;
        }
        Ok(())
    })();

    if result.is_err() {
        // Drop the partial target so the retry re-reads the (still-present) redb.
        remove_sqlite(&target);
    }
    result
}

/// Drain a legacy redb buffer (streaming or trace) into its `.sqlite` sibling.
fn drain_buffer(redb_path: &Path, table_def: TableDefinition<'_, u64, &[u8]>) -> Result<()> {
    let target = redb_path.with_extension("sqlite");
    if target.exists() {
        return Ok(());
    }

    let result = (|| -> Result<()> {
        let db = Database::open(redb_path)?;
        // Stored values are already framed entries; copy them verbatim in key
        // order. The sequence buffer stores bytes as-is (framing is the owning
        // buffer's job), so re-appending does not double-encode; AUTOINCREMENT
        // preserves FIFO order. A generous cap keeps the drain off `Full`.
        let entries = {
            let txn = db.begin_read()?;
            let table = txn.open_table(table_def)?;
            let mut out = Vec::new();
            for row in table.iter()? {
                let (_key, value) = row?;
                out.push(value.value().to_vec());
            }
            out
        };
        let mut buf = SqliteSequenceBuffer::open(
            &target,
            SqliteSequenceBufferConfig {
                max_mb: 1_000_000,
                cache_ceiling_bytes: 8 * 1024 * 1024,
                // One-time migration write; the pipeline reopens it with the real
                // per-source policy afterward.
                durability: Durability::Full,
            },
        )?;
        if !entries.is_empty() {
            buf.append(&entries)?;
        }
        Ok(())
    })();

    if result.is_err() {
        remove_sqlite(&target);
    }
    result
}

fn collect_redb_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_redb_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("redb") {
            out.push(path);
        }
    }
}

/// Remove a SQLite database and its WAL/SHM sidecars (best effort).
fn remove_sqlite(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sidecar));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::SystemTime;

    fn write_legacy_checkpoint(path: &Path, key: &str, offset: u64) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(LEGACY_CHECKPOINTS).unwrap();
            let cp = Checkpoint {
                path: key.into(),
                offset,
                inode: 1,
                updated_at: SystemTime::now(),
                streaming: None,
            };
            t.insert(key, serde_json::to_vec(&cp).unwrap().as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
    }

    fn write_legacy_buffer(
        path: &Path,
        table_def: TableDefinition<'_, u64, &[u8]>,
        entries: &[&[u8]],
    ) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(table_def).unwrap();
            for (i, e) in entries.iter().enumerate() {
                t.insert(i as u64 + 1, *e).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    fn peek_all(path: &Path) -> Vec<Vec<u8>> {
        let buf = SqliteSequenceBuffer::open(
            path,
            SqliteSequenceBufferConfig {
                max_mb: 10,
                cache_ceiling_bytes: 1024 * 1024,
                durability: Durability::Normal,
            },
        )
        .unwrap();
        buf.peek_raw(100)
            .unwrap()
            .into_iter()
            .map(|e| e.bytes)
            .collect()
    }

    #[test]
    fn migrates_checkpoints_drains_buffers_and_discards_replayable() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("collectable-1");
        fs::create_dir_all(&src).unwrap();

        write_legacy_checkpoint(&src.join("checkpoints.redb"), "/var/log/x.log", 4242);
        write_legacy_buffer(
            &src.join("streaming_buffer.redb"),
            LEGACY_BUFFER,
            &[b"entry-one", b"entry-two"],
        );
        // Trace buffers use the `trace_buffer` table and are the sole copy.
        write_legacy_buffer(
            &src.join("trace-buffer-svc.redb"),
            LEGACY_TRACE_BUFFER,
            &[b"trace-entry"],
        );
        write_legacy_buffer(
            &src.join("buffer_var_log_x.redb"),
            LEGACY_BUFFER,
            &[b"replayable"],
        );

        migrate_redb_to_sqlite(dir.path());

        // checkpoint migrated, redb gone
        assert!(!src.join("checkpoints.redb").exists());
        let store = CheckpointStore::open(&src.join("checkpoints.sqlite")).unwrap();
        assert_eq!(store.load("/var/log/x.log").unwrap().unwrap().offset, 4242);

        // streaming buffer drained verbatim, in order, redb gone
        assert!(!src.join("streaming_buffer.redb").exists());
        assert_eq!(
            peek_all(&src.join("streaming_buffer.sqlite")),
            vec![b"entry-one".to_vec(), b"entry-two".to_vec()]
        );

        // trace buffer drained (read from the `trace_buffer` table), redb gone
        assert!(!src.join("trace-buffer-svc.redb").exists());
        assert_eq!(
            peek_all(&src.join("trace-buffer-svc.sqlite")),
            vec![b"trace-entry".to_vec()]
        );

        // replayable buffer discarded (no sqlite created, redb gone)
        assert!(!src.join("buffer_var_log_x.redb").exists());
        assert!(!src.join("buffer_var_log_x.sqlite").exists());
    }

    #[test]
    fn skips_and_removes_redb_when_sqlite_target_exists() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("collectable-9");
        fs::create_dir_all(&src).unwrap();

        // Already-migrated sqlite checkpoint with the data we must keep.
        {
            let store = CheckpointStore::open(&src.join("checkpoints.sqlite")).unwrap();
            store
                .save(&Checkpoint {
                    path: "/keep".into(),
                    offset: 111,
                    inode: 1,
                    updated_at: SystemTime::now(),
                    streaming: None,
                })
                .unwrap();
        }
        // Stale legacy redb with conflicting data that must NOT clobber/merge.
        write_legacy_checkpoint(&src.join("checkpoints.redb"), "/stale", 999);

        migrate_redb_to_sqlite(dir.path());

        assert!(!src.join("checkpoints.redb").exists(), "stale redb removed");
        let store = CheckpointStore::open(&src.join("checkpoints.sqlite")).unwrap();
        assert_eq!(store.load("/keep").unwrap().unwrap().offset, 111);
        assert!(
            store.load("/stale").unwrap().is_none(),
            "must not merge an already-migrated target"
        );
    }
}
