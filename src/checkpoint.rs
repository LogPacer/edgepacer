//! Checkpoint store — persists file tailing positions for crash-safe resume.
//!
//! Uses SQLite (WAL journal, `synchronous=FULL`) matching the durability
//! guarantees of legacy EdgePacer's BoltDB-backed `internal/buffer/checkpoint_store.go`.
//!
//! Invariant: a checkpoint is only advanced after confirmed delivery of all data
//! up to that position. Checkpoint advance is derived from consecutive confirmed
//! delivery, never from enqueue or optimistic assumptions.

use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension};
use tracing::{debug, info, warn};

use crate::streaming_checkpoint::StreamingCheckpoint;

/// A persisted file tailing position.
///
/// Matches Go's `buffer.Checkpoint` with the fields relevant to file sources.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Log file path (the key).
    pub path: String,
    /// Byte offset in the file — how far we've read and durably shipped.
    pub offset: u64,
    /// Inode number — detects file rotation (new file at same path).
    pub inode: u64,
    /// When this checkpoint was last persisted.
    pub updated_at: SystemTime,
    /// Resume token for streaming sources (`stream:{source_id}` keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<StreamingCheckpoint>,
}

/// Persistent checkpoint store backed by SQLite.
pub struct CheckpointStore {
    /// `rusqlite::Connection` is `Send` but not `Sync`; pipelines hold a shared
    /// `&CheckpointStore` across `.await` in `tokio::spawn`'d loops, which needs
    /// `Sync` (as redb's `Database` was). Single owner → always uncontended.
    conn: Mutex<Connection>,
}

/// Errors specific to checkpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl CheckpointStore {
    /// Open or create a checkpoint store at the given path.
    pub fn open(path: &Path) -> Result<Self, CheckpointError> {
        // Blocking-pool bound: creation + table setup fsync.
        let conn = crate::common::run_blocking(|| {
            let conn = Connection::open(path)?;
            // WAL + synchronous=FULL = power-loss durable on commit. Checkpoints
            // are tiny and overwritten in place, so a small cache and incremental
            // vacuum (after prune) keep the file at its ~8 KiB floor.
            conn.execute_batch(
                "PRAGMA auto_vacuum=INCREMENTAL;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA busy_timeout=5000;
                 PRAGMA cache_size=-256;
                 CREATE TABLE IF NOT EXISTS checkpoints(
                     path TEXT PRIMARY KEY,
                     data BLOB NOT NULL
                 );",
            )?;
            Ok::<_, CheckpointError>(conn)
        })?;

        info!(path = %path.display(), "checkpoint store opened");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Save a checkpoint atomically.
    ///
    /// Only call this after all data up to `checkpoint.offset` has been confirmed
    /// delivered (consecutive-ack rule satisfied).
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        let serialized = serde_json::to_vec(checkpoint)?;

        // Blocking-pool bound: the commit fsyncs (synchronous=FULL).
        crate::common::run_blocking(|| {
            let conn = self
                .conn
                .lock()
                .expect("checkpoint connection mutex poisoned");
            conn.execute(
                "INSERT OR REPLACE INTO checkpoints(path, data) VALUES (?1, ?2)",
                rusqlite::params![checkpoint.path.as_str(), serialized.as_slice()],
            )?;
            Ok::<_, CheckpointError>(())
        })?;

        debug!(
            path = %checkpoint.path,
            offset = checkpoint.offset,
            inode = checkpoint.inode,
            "checkpoint saved"
        );
        Ok(())
    }

    /// Load a checkpoint for a given file path.
    pub fn load(&self, path: &str) -> Result<Option<Checkpoint>, CheckpointError> {
        let conn = self
            .conn
            .lock()
            .expect("checkpoint connection mutex poisoned");
        let data: Option<Vec<u8>> = conn
            .query_row(
                "SELECT data FROM checkpoints WHERE path = ?1",
                [path],
                |row| row.get(0),
            )
            .optional()?;

        match data {
            Some(bytes) => {
                let cp: Checkpoint = serde_json::from_slice(&bytes)?;
                debug!(
                    path,
                    offset = cp.offset,
                    inode = cp.inode,
                    "checkpoint loaded"
                );
                Ok(Some(cp))
            }
            None => Ok(None),
        }
    }

    /// Delete a checkpoint (e.g., when a log source is removed).
    pub fn delete(&self, path: &str) -> Result<(), CheckpointError> {
        // Blocking-pool bound: the commit fsyncs.
        crate::common::run_blocking(|| {
            let conn = self
                .conn
                .lock()
                .expect("checkpoint connection mutex poisoned");
            conn.execute("DELETE FROM checkpoints WHERE path = ?1", [path])?;
            Ok::<_, CheckpointError>(())
        })?;

        debug!(path, "checkpoint deleted");
        Ok(())
    }

    /// Save a streaming checkpoint under `stream:{source_id}`.
    pub fn save_streaming(
        &self,
        source_id: &str,
        checkpoint: &StreamingCheckpoint,
    ) -> Result<(), CheckpointError> {
        let key = format!("stream:{source_id}");
        self.save(&Checkpoint {
            path: key,
            offset: 0,
            inode: 0,
            updated_at: checkpoint.updated_at,
            streaming: Some(checkpoint.clone()),
        })
    }

    /// Move a streaming checkpoint to a new source id. Checkpoint rows are
    /// keyed by source id, so adopting a legacy source's state dir is not
    /// enough — the row itself must follow, or the successor source misses
    /// its resume point and replays from zero. Returns whether a row moved.
    pub fn rekey_streaming(
        &self,
        old_source_id: &str,
        new_source_id: &str,
    ) -> Result<bool, CheckpointError> {
        let old_key = format!("stream:{old_source_id}");
        let new_key = format!("stream:{new_source_id}");
        let conn = self.conn.lock().expect("checkpoint store mutex poisoned");
        let moved = conn.execute(
            "UPDATE OR REPLACE checkpoints SET path = ?1 WHERE path = ?2",
            rusqlite::params![new_key, old_key],
        )?;
        Ok(moved > 0)
    }

    /// Load a streaming checkpoint for a source.
    pub fn load_streaming(
        &self,
        source_id: &str,
    ) -> Result<Option<StreamingCheckpoint>, CheckpointError> {
        let key = format!("stream:{source_id}");
        Ok(self.load(&key)?.and_then(|cp| cp.streaming))
    }

    /// Prune checkpoints for paths not in the active set.
    ///
    /// Called periodically to clean up state for files that no longer exist
    /// or are no longer being tailed.
    pub fn prune_stale(&self, active_paths: &[&str]) -> Result<usize, CheckpointError> {
        // Blocking-pool bound: fsync'd commit.
        let pruned = crate::common::run_blocking(|| {
            let conn = self
                .conn
                .lock()
                .expect("checkpoint connection mutex poisoned");
            let pruned = if active_paths.is_empty() {
                conn.execute("DELETE FROM checkpoints", [])?
            } else {
                let placeholders = vec!["?"; active_paths.len()].join(",");
                let sql = format!("DELETE FROM checkpoints WHERE path NOT IN ({placeholders})");
                conn.execute(
                    &sql,
                    rusqlite::params_from_iter(active_paths.iter().copied()),
                )?
            };

            // Reclaim pages from the deleted rows back toward the floor.
            if pruned > 0 {
                let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
            }
            Ok::<_, CheckpointError>(pruned)
        })?;

        if pruned > 0 {
            warn!(pruned, "pruned stale checkpoints");
        }
        Ok(pruned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, CheckpointStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("checkpoints.sqlite");
        let store = CheckpointStore::open(&db_path).unwrap();
        (dir, store)
    }

    #[test]
    fn save_and_load() {
        let (_dir, store) = temp_store();

        let cp = Checkpoint {
            path: "/var/log/app.log".into(),
            offset: 4096,
            inode: 12345,
            updated_at: SystemTime::now(),
            streaming: None,
        };

        store.save(&cp).unwrap();

        let loaded = store.load("/var/log/app.log").unwrap().unwrap();
        assert_eq!(loaded.offset, 4096);
        assert_eq!(loaded.inode, 12345);
    }

    #[test]
    fn load_missing_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.load("/nonexistent").unwrap().is_none());
    }

    #[test]
    fn save_overwrites() {
        let (_dir, store) = temp_store();

        let cp1 = Checkpoint {
            path: "/var/log/app.log".into(),
            offset: 1000,
            inode: 1,
            updated_at: SystemTime::now(),
            streaming: None,
        };
        store.save(&cp1).unwrap();

        let cp2 = Checkpoint {
            path: "/var/log/app.log".into(),
            offset: 5000,
            inode: 1,
            updated_at: SystemTime::now(),
            streaming: None,
        };
        store.save(&cp2).unwrap();

        let loaded = store.load("/var/log/app.log").unwrap().unwrap();
        assert_eq!(loaded.offset, 5000);
    }

    #[test]
    fn delete_checkpoint() {
        let (_dir, store) = temp_store();

        let cp = Checkpoint {
            path: "/var/log/app.log".into(),
            offset: 100,
            inode: 1,
            updated_at: SystemTime::now(),
            streaming: None,
        };
        store.save(&cp).unwrap();
        store.delete("/var/log/app.log").unwrap();
        assert!(store.load("/var/log/app.log").unwrap().is_none());
    }

    #[test]
    fn prune_stale_checkpoints() {
        let (_dir, store) = temp_store();

        for path in ["/var/log/a.log", "/var/log/b.log", "/var/log/c.log"] {
            store
                .save(&Checkpoint {
                    path: path.into(),
                    offset: 0,
                    inode: 1,
                    updated_at: SystemTime::now(),
                    streaming: None,
                })
                .unwrap();
        }

        // Only a.log is still active
        let pruned = store.prune_stale(&["/var/log/a.log"]).unwrap();
        assert_eq!(pruned, 2);

        assert!(store.load("/var/log/a.log").unwrap().is_some());
        assert!(store.load("/var/log/b.log").unwrap().is_none());
        assert!(store.load("/var/log/c.log").unwrap().is_none());
    }

    #[test]
    fn prune_stale_empty_active_set_clears_all() {
        let (_dir, store) = temp_store();
        store
            .save(&Checkpoint {
                path: "/var/log/a.log".into(),
                offset: 0,
                inode: 1,
                updated_at: SystemTime::now(),
                streaming: None,
            })
            .unwrap();

        let pruned = store.prune_stale(&[]).unwrap();
        assert_eq!(pruned, 1);
        assert!(store.load("/var/log/a.log").unwrap().is_none());
    }

    #[test]
    fn save_streaming_checkpoint_roundtrip() {
        let (_dir, store) = temp_store();
        let cp = StreamingCheckpoint::journald("src-1", "s=abc123");

        store.save_streaming("src-1", &cp).unwrap();
        let loaded = store.load_streaming("src-1").unwrap().unwrap();
        assert_eq!(loaded.journald_cursor(), Some("s=abc123"));
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("checkpoints.sqlite");

        // Write with first store instance
        {
            let store = CheckpointStore::open(&db_path).unwrap();
            store
                .save(&Checkpoint {
                    path: "/var/log/app.log".into(),
                    offset: 9999,
                    inode: 42,
                    updated_at: SystemTime::now(),
                    streaming: None,
                })
                .unwrap();
        }

        // Reopen — simulates crash recovery
        {
            let store = CheckpointStore::open(&db_path).unwrap();
            let cp = store.load("/var/log/app.log").unwrap().unwrap();
            assert_eq!(cp.offset, 9999);
            assert_eq!(cp.inode, 42);
        }
    }
}
