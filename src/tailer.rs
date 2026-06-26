//! File tailer with rotation detection and checkpoint-aware resume.
//!
//! M4 upgrade from the simple M2 tailer:
//! - Inode tracking for rotation detection (logrotate, copytruncate)
//! - Truncation detection (file size < last offset)
//! - Resume from persisted checkpoint on startup
//! - Reports read position for downstream checkpoint advancement
//!
//! Bulletproofness guarantees (goal 60):
//! - On rotation, the previous fd is kept alive and drained to EOF before
//!   the new file becomes active. No unread bytes in the rotated file are lost.
//! - Rotation is detected via three signals: inode change (Unix), mtime moving
//!   backwards, or size shrinking by >50% with an mtime bump. Covers non-Unix
//!   where inode is unavailable.
//! - Startup seeks to end and then reads back the post-seek position as the
//!   authoritative starting offset — writes that race `open()` are not skipped.
//! - `self.offset` advances by every byte consumed from the underlying reader,
//!   including empty lines. Checkpoints never drift behind the reader position.
//!
//! Content handling (goal 61):
//! - Lines are read as raw bytes from a `BufRead` source, not through
//!   `String`. Non-UTF-8 content (Latin-1, binary, corrupted bytes)
//!   passes through unmodified — matches Go's byte-reader behavior.
//! - Individual lines are bounded by `DEFAULT_MAX_LINE_BYTES` (1 MiB). Lines
//!   exceeding the cap are truncated with a warn log; the tail is drained from
//!   the reader so the next read starts on a fresh logical line.
//! - Empty lines are emitted as empty `Vec<u8>` (matches Go, which appends
//!   blank entries unconditionally) so downstream parsers that treat blanks
//!   as record separators behave identically.
//!
//! Resilience (goal 62):
//! - Tailer can be constructed on a non-existent path. The underlying fd is
//!   opened lazily on the first `read_lines` call after the file appears.
//!   Previously, `FileTailer::open` propagated NotFound; now it returns a
//!   "pending" tailer that polls via `try_upgrade_pending()`.
//! - `PermissionDenied` on `File::open` or `std::fs::metadata` is treated the
//!   same as `NotFound`: log and keep polling. All other IO errors propagate.
//! - Rotation where the new file doesn't exist at path yet (brief window
//!   during rename-then-create) does not error. The old reader stays active;
//!   once the new file appears, the usual drain-then-switch flow triggers.

mod line;
mod state;

use std::io;
use std::path::{Path, PathBuf};

#[cfg(test)]
use state::identity_of_path;
use state::{PendingOpen, TailerState};

use crate::checkpoint::Checkpoint;

/// Default cap on the bytes captured for a single log line.
///
/// Matches Go edgepacer's practical `bufio.Reader` behavior and keeps a
/// single pathological line without a trailing newline from exhausting
/// memory. Over-cap lines are truncated in the output; the reader advances
/// past the full on-disk line so the next read starts fresh.
pub const DEFAULT_MAX_LINE_BYTES: usize = 1_048_576;

/// Metadata about the current file state — used by the delivery pipeline
/// to know what offset to checkpoint after confirmed delivery.
#[derive(Debug, Clone)]
pub struct ReadPosition {
    /// Byte offset in the file after reading.
    pub offset: u64,
    /// Inode of the file we're reading.
    pub inode: u64,
}

/// A file tailer with rotation detection.
///
/// Detects three rotation scenarios:
/// 1. **Inode change** — file was renamed/moved and a new file created at the same path
///    (classic logrotate on Unix). Triggers drain-then-switch.
/// 2. **mtime backwards / size halved** — rotation detectable without inode (non-Unix,
///    or copy-rename schemes where inode stayed the same). Triggers drain-then-switch.
/// 3. **Truncation** — file was truncated in-place (copytruncate). Reopens from start.
///    No draining possible; prior bytes are inherently lost by copytruncate.
pub struct FileTailer {
    path: PathBuf,
    state: TailerState,
    /// Maximum bytes captured per emitted line. Bytes beyond this cap are
    /// still consumed from the reader (so line framing is preserved for the
    /// next line) but not included in the output.
    max_line_bytes: usize,
}

impl FileTailer {
    /// Open a file and seek to the end (only tail new content).
    ///
    /// If the file doesn't exist or can't be read at construction time
    /// (NotFound / PermissionDenied), the tailer returns in a "pending"
    /// state — subsequent `read_lines` calls retry the open and transition
    /// to active once the file becomes available. Other IO errors propagate.
    ///
    /// When the file IS available (either now or on later upgrade), the
    /// authoritative starting offset is the position `seek(End)` lands at,
    /// not the size observed via a separate `metadata()` call — so any writes
    /// that race this open are picked up on the next `read_lines` instead of
    /// being silently skipped.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut tailer = Self::pending(path, PendingOpen::TailFromEnd);
        tailer.state.try_upgrade_pending(&tailer.path)?;
        Ok(tailer)
    }

    /// Open a file and read from the beginning (for testing / catch-up).
    ///
    /// Tolerates file-absent and permission-denied at construction; upgrades
    /// lazily on the next `read_lines` when the file becomes accessible.
    pub fn open_from_start(path: &Path) -> io::Result<Self> {
        let mut tailer = Self::pending(path, PendingOpen::FromStart);
        tailer.state.try_upgrade_pending(&tailer.path)?;
        Ok(tailer)
    }

    /// Resume tailing from a persisted checkpoint.
    ///
    /// If the checkpoint's inode matches the current file, seeks to the checkpoint offset.
    /// If the inode changed (rotation) or the file is smaller than the checkpoint (truncation),
    /// starts from the beginning. If the file doesn't exist yet at construction, the
    /// checkpoint is applied lazily when the file first appears.
    pub fn open_with_checkpoint(path: &Path, checkpoint: &Checkpoint) -> io::Result<Self> {
        let mut tailer = Self::pending(path, PendingOpen::Checkpoint(checkpoint.clone()));
        tailer.state.try_upgrade_pending(&tailer.path)?;
        Ok(tailer)
    }

    /// Build a tailer in the "pending open" state with no reader yet.
    fn pending(path: &Path, mode: PendingOpen) -> Self {
        Self {
            path: path.to_path_buf(),
            state: TailerState::pending(mode),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }

    /// Read up to `max_lines` new lines. Returns empty vec if no new data.
    ///
    /// Lines are read as raw bytes (no UTF-8 requirement) and capped at
    /// `self.max_line_bytes`. Empty lines are emitted as empty `Vec<u8>`.
    ///
    /// Before reading, checks for rotation/truncation and parks the old reader
    /// as `draining` if needed. Drained lines are delivered to the caller
    /// before any new-file lines; this preserves bytes still in flight in the
    /// rotated file at the moment rotation was detected.
    pub fn read_lines(&mut self, max_lines: usize) -> io::Result<Vec<Vec<u8>>> {
        // If we're in pending-open state, try to upgrade. Silently no-ops
        // when the file still isn't accessible — next poll retries.
        self.state.try_upgrade_pending(&self.path)?;
        self.state.check_rotation(&self.path)?;
        self.state
            .read_lines(&self.path, max_lines, self.max_line_bytes)
    }

    /// Current read position — used by the delivery pipeline for checkpointing.
    pub fn position(&self) -> ReadPosition {
        ReadPosition {
            offset: self.state.offset(),
            inode: self.state.inode(),
        }
    }

    /// Current file offset.
    pub fn offset(&self) -> u64 {
        self.state.offset()
    }

    /// Path being tailed.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tail_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");

        // Write initial content
        std::fs::write(&path, "line1\nline2\n").unwrap();

        // Open from end — should see nothing
        let mut tailer = FileTailer::open(&path).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert!(lines.is_empty());

        // Append new content
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "line3").unwrap();
        writeln!(f, "line4").unwrap();
        drop(f);

        // Should see the new lines
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"line3");
        assert_eq!(lines[1], b"line4");
    }

    #[test]
    fn open_from_start_reads_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "a\nb\nc\n").unwrap();

        let mut tailer = FileTailer::open_from_start(&path).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"a");
        assert_eq!(lines[1], b"b");
        assert_eq!(lines[2], b"c");
    }

    #[test]
    fn respects_max_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "1\n2\n3\n4\n5\n").unwrap();

        let mut tailer = FileTailer::open_from_start(&path).unwrap();
        let lines = tailer.read_lines(2).unwrap();
        assert_eq!(lines.len(), 2);

        // Next read picks up where we left off
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn position_tracks_offset_and_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "hello\nworld\n").unwrap();

        let mut tailer = FileTailer::open_from_start(&path).unwrap();
        assert_eq!(tailer.position().offset, 0);

        tailer.read_lines(1).unwrap();
        assert!(tailer.position().offset > 0);
        assert!(tailer.position().inode > 0 || !cfg!(unix));
    }

    #[test]
    fn detects_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");

        // Write initial content and read it
        std::fs::write(&path, "aaaa\nbbbb\ncccc\n").unwrap();
        let mut tailer = FileTailer::open_from_start(&path).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 3);
        let offset_before = tailer.offset();

        // Truncate and write smaller content
        std::fs::write(&path, "new\n").unwrap();

        // Next read should detect truncation and read from start
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"new");
        assert!(tailer.offset() < offset_before);
    }

    #[cfg(unix)]
    #[test]
    fn detects_inode_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");

        // Write and read initial content
        std::fs::write(&path, "original\n").unwrap();
        let mut tailer = FileTailer::open_from_start(&path).unwrap();
        tailer.read_lines(100).unwrap();

        // Simulate logrotate: rename old, create new at same path
        let rotated = dir.path().join("test.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "rotated\n").unwrap();

        // Next read should detect rotation and read new file
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"rotated");
    }

    #[test]
    fn open_with_checkpoint_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "line1\nline2\nline3\n").unwrap();

        // Get the inode
        let inode = identity_of_path(&path).unwrap();

        // Checkpoint at offset after "line1\n" (6 bytes)
        let cp = Checkpoint {
            path: path.to_string_lossy().into(),
            offset: 6,
            inode,
            updated_at: std::time::SystemTime::now(),
            streaming: None,
        };

        let mut tailer = FileTailer::open_with_checkpoint(&path, &cp).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"line2");
        assert_eq!(lines[1], b"line3");
    }

    #[test]
    fn checkpoint_with_different_inode_starts_from_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "new_content\n").unwrap();

        // Checkpoint with a different inode (simulates file rotation before restart)
        let cp = Checkpoint {
            path: path.to_string_lossy().into(),
            offset: 5000,
            inode: 99999999, // wrong inode
            updated_at: std::time::SystemTime::now(),
            streaming: None,
        };

        let mut tailer = FileTailer::open_with_checkpoint(&path, &cp).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        // Should read from start since inode doesn't match
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"new_content");
    }

    #[test]
    fn checkpoint_with_truncated_file_starts_from_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "short\n").unwrap();

        let inode = identity_of_path(&path).unwrap();

        // Checkpoint at offset way past current file size
        let cp = Checkpoint {
            path: path.to_string_lossy().into(),
            offset: 50000,
            inode,
            updated_at: std::time::SystemTime::now(),
            streaming: None,
        };

        let mut tailer = FileTailer::open_with_checkpoint(&path, &cp).unwrap();
        let lines = tailer.read_lines(100).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"short");
    }
}
