use std::io::{self, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};

use crate::checkpoint::Checkpoint;

use super::line::{read_one_line, trim_line_ending};

#[derive(Debug, Clone, Copy)]
struct ObservedFileState {
    inode: u64,
    size: u64,
    modtime: SystemTime,
}

impl ObservedFileState {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            inode: inode_of(meta),
            size: meta.len(),
            modtime: meta.modified().unwrap_or(UNIX_EPOCH),
        }
    }
}

/// Deferred-open policy for a `FileTailer` that can't yet access its path.
///
/// Each variant encodes the seek behavior the tailer should apply once the
/// file becomes openable. Stored on the tailer so reopens across a long
/// file-absent window still honor the original intent.
#[derive(Debug, Clone)]
pub(super) enum PendingOpen {
    /// Seek to end of file on open -- only tail new content.
    TailFromEnd,
    /// Read from the beginning of the file on open.
    FromStart,
    /// Resume from a persisted checkpoint. Inode match -> seek to offset;
    /// otherwise start from byte 0 of the newly-appearing file.
    Checkpoint(Checkpoint),
}

pub(super) struct TailerState {
    /// `None` means we don't currently have an fd for the path -- either
    /// because the file didn't exist at construction, a permissions error
    /// blocked the open, or rotation was detected before the replacement file
    /// appeared. `read_lines` calls `try_upgrade_pending` to retry lazily.
    reader: Option<BufReader<std::fs::File>>,
    offset: u64,
    inode: u64,
    modtime: SystemTime,
    size: u64,
    /// When rotation is detected, the previous reader is parked here so its
    /// remaining bytes can be drained to EOF before the new file is read.
    draining: Option<BufReader<std::fs::File>>,
    pending_open: Option<PendingOpen>,
}

impl TailerState {
    pub(super) fn pending(mode: PendingOpen) -> Self {
        Self {
            reader: None,
            offset: 0,
            inode: 0,
            modtime: UNIX_EPOCH,
            size: 0,
            draining: None,
            pending_open: Some(mode),
        }
    }

    pub(super) fn try_upgrade_pending(&mut self, path: &Path) -> io::Result<()> {
        let Some(mode) = self.pending_open.as_ref().cloned() else {
            return Ok(());
        };
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if is_retryable_io_error(&e) => {
                debug!(
                    path = %path.display(),
                    error = %e,
                    "file not yet accessible, staying in pending-open state"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let inode = inode_of(&meta);
        let modtime = meta.modified().unwrap_or(UNIX_EPOCH);
        let current_size = meta.len();

        let mut reader = BufReader::new(file);
        let (offset, size, description) = match mode {
            PendingOpen::TailFromEnd => {
                let pos = reader.seek(SeekFrom::End(0))?;
                (pos, pos, "tailing from end")
            }
            PendingOpen::FromStart => (0, current_size, "tailing from start"),
            PendingOpen::Checkpoint(ref cp) => {
                let (resume_offset, reason) = if inode != cp.inode {
                    (0, "inode changed (rotation)")
                } else if current_size < cp.offset {
                    (0, "file truncated")
                } else {
                    (cp.offset, "resuming from checkpoint")
                };
                let pos = reader.seek(SeekFrom::Start(resume_offset))?;
                info!(
                    path = %path.display(),
                    checkpoint_offset = cp.offset,
                    checkpoint_inode = cp.inode,
                    current_inode = inode,
                    current_size,
                    resume_offset = pos,
                    reason,
                    "opened with checkpoint"
                );
                (pos, current_size, "resumed with checkpoint")
            }
        };
        info!(path = %path.display(), offset, inode, mode = description, "tailer upgraded to active");

        self.reader = Some(reader);
        self.offset = offset;
        self.inode = inode;
        self.modtime = modtime;
        self.size = size;
        self.pending_open = None;
        Ok(())
    }

    pub(super) fn read_lines(
        &mut self,
        path: &Path,
        max_lines: usize,
        max_line_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        let mut lines = Vec::new();
        let mut line_buf: Vec<u8> = Vec::with_capacity(512);
        let path_display = path.display().to_string();

        while lines.len() < max_lines {
            let Some(drain) = self.draining.as_mut() else {
                break;
            };
            line_buf.clear();
            let outcome = read_one_line(drain, &mut line_buf, max_line_bytes)?;
            if outcome.consumed == 0 {
                info!(path = %path_display, "finished draining rotated file");
                self.draining = None;
                break;
            }
            if outcome.truncated {
                warn!(
                    path = %path_display,
                    cap = max_line_bytes,
                    consumed = outcome.consumed,
                    "oversize line truncated during drain"
                );
            }
            trim_line_ending(&mut line_buf);
            lines.push(std::mem::take(&mut line_buf));
        }

        if let Some(reader) = self.reader.as_mut() {
            while lines.len() < max_lines {
                line_buf.clear();
                let outcome = read_one_line(reader, &mut line_buf, max_line_bytes)?;
                if outcome.consumed == 0 {
                    break;
                }
                self.offset += outcome.consumed as u64;
                if outcome.truncated {
                    warn!(
                        path = %path_display,
                        cap = max_line_bytes,
                        consumed = outcome.consumed,
                        "oversize line truncated"
                    );
                }
                trim_line_ending(&mut line_buf);
                lines.push(std::mem::take(&mut line_buf));
            }
        }

        if !lines.is_empty() {
            debug!(lines = lines.len(), offset = self.offset, "read new lines");
        }

        Ok(lines)
    }

    pub(super) fn check_rotation(&mut self, path: &Path) -> io::Result<()> {
        if self.reader.is_none() {
            return Ok(());
        }

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if is_retryable_io_error(&e) => {
                debug!(
                    path = %path.display(),
                    kind = ?e.kind(),
                    "metadata unavailable, keeping existing reader and waiting"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let current = ObservedFileState::from_metadata(&meta);

        let inode_changed = current.inode != 0 && self.inode != 0 && current.inode != self.inode;
        let mtime_went_back = current.modtime < self.modtime;
        let shrunk_substantially = current.size < self.size / 2 && current.modtime != self.modtime;

        let rotation_reason = if inode_changed {
            Some("inode changed")
        } else if mtime_went_back {
            Some("mtime went backwards (file replaced)")
        } else if shrunk_substantially {
            Some("size shrunk substantially with new mtime")
        } else {
            None
        };

        if let Some(reason) = rotation_reason {
            warn!(
                path = %path.display(),
                reason,
                old_inode = self.inode,
                new_inode = current.inode,
                old_size = self.size,
                new_size = current.size,
                "file rotated, draining old reader before switch"
            );
            self.begin_rotation(path, current)?;
            return Ok(());
        }

        if current.size < self.offset {
            warn!(
                path = %path.display(),
                old_offset = self.offset,
                new_size = current.size,
                "file truncated, seeking to start"
            );
            if let Some(reader) = self.reader.as_mut() {
                reader.seek(SeekFrom::Start(0))?;
            }
            self.offset = 0;
        }

        self.size = current.size;
        self.modtime = current.modtime;
        Ok(())
    }

    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    pub(super) fn inode(&self) -> u64 {
        self.inode
    }

    fn begin_rotation(&mut self, path: &Path, new_file_state: ObservedFileState) -> io::Result<()> {
        let new_file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if is_retryable_io_error(&e) => {
                debug!(
                    path = %path.display(),
                    kind = ?e.kind(),
                    "new file not yet accessible at rotation, will retry"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let new_reader = BufReader::new(new_file);

        if self.draining.is_some() {
            warn!(
                path = %path.display(),
                "rotation detected while previous drain still in flight, dropping intermediate reader"
            );
        }

        let old_reader = self.reader.replace(new_reader);
        if self.draining.is_none() {
            self.draining = old_reader;
        }

        self.offset = 0;
        self.inode = new_file_state.inode;
        self.size = new_file_state.size;
        self.modtime = new_file_state.modtime;
        Ok(())
    }
}

fn is_retryable_io_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

#[cfg(unix)]
pub(super) fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
pub(super) fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}
