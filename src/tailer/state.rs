use std::io::{self, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};

use crate::checkpoint::Checkpoint;

use super::line::{LineEncoding, decode_line, detect_encoding, read_one_line, trim_line_ending};

#[derive(Debug, Clone, Copy)]
struct ObservedFileState {
    inode: u64,
    size: u64,
    modtime: SystemTime,
}

impl ObservedFileState {
    #[cfg(not(windows))]
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            inode: inode_of(meta),
            size: meta.len(),
            modtime: meta.modified().unwrap_or(UNIX_EPOCH),
        }
    }

    fn from_file(file: &std::fs::File) -> io::Result<Self> {
        let meta = file.metadata()?;
        Ok(Self {
            inode: file_identity(file, &meta),
            size: meta.len(),
            modtime: meta.modified().unwrap_or(UNIX_EPOCH),
        })
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
    /// Source-byte encoding, sniffed from a leading BOM at open. Drives line
    /// splitting (terminator width) and per-line decode to UTF-8. The BOM bytes
    /// stay part of the source stream and count toward `offset`, so a checkpoint
    /// offset remains a valid source position across restarts.
    encoding: LineEncoding,
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
            encoding: LineEncoding::default(),
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
        let observed = ObservedFileState::from_file(&file)?;
        let inode = observed.inode;
        let modtime = observed.modtime;
        let current_size = observed.size;

        // Sniff a leading BOM for the line encoding. Read up to the first 3
        // bytes, then rewind to byte 0 -- the seek branches below all use
        // absolute seeks, so the BOM bytes stay part of the source stream and
        // keep counting toward `offset`.
        let mut file = file;
        let encoding = sniff_encoding(&mut file)?;

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
        self.encoding = encoding;
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
            let outcome = read_one_line(drain, &mut line_buf, max_line_bytes, self.encoding)?;
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
            // Draining resumes the tail of an already-partially-read rotated
            // file, so these are never the first (BOM-bearing) line.
            decode_line(&mut line_buf, self.encoding, false);
            trim_line_ending(&mut line_buf);
            lines.push(std::mem::take(&mut line_buf));
        }

        if let Some(reader) = self.reader.as_mut() {
            while lines.len() < max_lines {
                line_buf.clear();
                // The first line of the file is the only one carrying a BOM.
                // It is read exactly when we start at source offset 0 -- a
                // checkpoint resume from offset > 0 already consumed the BOM in
                // a prior run, so the flag is naturally false there.
                let is_first_line = self.offset == 0;
                let outcome = read_one_line(reader, &mut line_buf, max_line_bytes, self.encoding)?;
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
                decode_line(&mut line_buf, self.encoding, is_first_line);
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

        let current = match observed_path_state(path) {
            Ok(state) => state,
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

/// Read up to the first 3 bytes of `file` to detect a leading BOM, then rewind
/// to byte 0. The caller's subsequent absolute seek (TailFromEnd / FromStart /
/// Checkpoint) sets the real read position; the BOM bytes remain part of the
/// source stream so offsets stay source-relative.
fn sniff_encoding(file: &mut std::fs::File) -> io::Result<LineEncoding> {
    use std::io::Read;
    let mut head = [0u8; 3];
    let n = file.read(&mut head)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(detect_encoding(&head[..n]))
}

fn is_retryable_io_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

#[cfg(windows)]
fn observed_path_state(path: &Path) -> io::Result<ObservedFileState> {
    let file = std::fs::File::open(path)?;
    ObservedFileState::from_file(&file)
}

#[cfg(not(windows))]
fn observed_path_state(path: &Path) -> io::Result<ObservedFileState> {
    let meta = std::fs::metadata(path)?;
    Ok(ObservedFileState::from_metadata(&meta))
}

#[cfg(test)]
pub(super) fn identity_of_path(path: &Path) -> io::Result<u64> {
    Ok(observed_path_state(path)?.inode)
}

#[cfg(unix)]
pub(super) fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(windows)]
pub(super) fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    meta.creation_time()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(windows)]
fn file_identity(file: &std::fs::File, meta: &std::fs::Metadata) -> u64 {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;

    // Stable Rust exposes Windows creation time, but not the file index. Use
    // the handle API so rename-create rotation has a true file identity signal.
    let mut info = MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return inode_of(meta);
    }

    let info = unsafe { info.assume_init() };
    let index = ((info.file_index_high as u64) << 32) | info.file_index_low as u64;
    if index == 0 { inode_of(meta) } else { index }
}

#[cfg(not(windows))]
fn file_identity(_file: &std::fs::File, meta: &std::fs::Metadata) -> u64 {
    inode_of(meta)
}

#[cfg(windows)]
#[repr(C)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[cfg(windows)]
#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        file_information: *mut ByHandleFileInformation,
    ) -> i32;
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn utf16be_bytes(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }

    /// Write `bytes` to a temp file, open it from start, and read all lines.
    /// Returns the lines and the tailer's final source-byte offset. All reads
    /// complete here, so the temp dir can drop on return.
    fn read_from_start(bytes: &[u8]) -> (Vec<Vec<u8>>, u64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encoded.txt");
        std::fs::write(&path, bytes).unwrap();

        let mut state = TailerState::pending(PendingOpen::FromStart);
        state.try_upgrade_pending(&path).unwrap();
        let lines = state.read_lines(&path, 1024, 1 << 20).unwrap();
        (lines, state.offset())
    }

    #[test]
    fn utf16le_bom_ships_clean_utf8() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&utf16le_bytes("æøå\nsecond\n"));
        let (lines, offset) = read_from_start(&bytes);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "æøå".as_bytes());
        assert_eq!(lines[1], b"second");
        assert!(!lines[0].contains(&0), "no interleaved NUL byte");
        assert!(
            std::str::from_utf8(&lines[0]).is_ok(),
            "valid UTF-8 -> RawText"
        );
        // (f) offset stays in SOURCE bytes -- the resume guarantee.
        assert_eq!(offset, bytes.len() as u64);
    }

    #[test]
    fn utf16be_bom_ships_clean_utf8() {
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend_from_slice(&utf16be_bytes("æøå\nsecond\n"));
        let (lines, offset) = read_from_start(&bytes);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "æøå".as_bytes());
        assert_eq!(lines[1], b"second");
        assert!(!lines[0].contains(&0), "no interleaved NUL byte");
        assert_eq!(offset, bytes.len() as u64);
    }

    #[test]
    fn plain_utf8_is_byte_identical_passthrough() {
        let bytes = b"hello\nverden\n".to_vec();
        let (lines, offset) = read_from_start(&bytes);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"hello");
        assert_eq!(lines[1], b"verden");
        assert_eq!(offset, bytes.len() as u64);
    }

    #[test]
    fn utf8_bom_stripped_from_first_line_only() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"first\nsecond\n");
        let (lines, offset) = read_from_start(&bytes);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"first", "BOM stripped from line 1");
        assert_eq!(lines[1], b"second", "line 2 untouched");
        // Offset still counts the 3 BOM bytes as source bytes.
        assert_eq!(offset, bytes.len() as u64);
    }

    #[test]
    fn utf16le_crlf_leaves_no_stray_cr() {
        // BOM required: detection is BOM-based, so a BOM-less UTF-16 stream is
        // (by design) read as UTF-8. Prepend FF FE like the other UTF-16 tests.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&utf16le_bytes("line\r\nnext\r\n"));
        let (lines, offset) = read_from_start(&bytes);

        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0], b"line",
            "decoded \\r\\n then trimmed -> no stray CR"
        );
        assert_eq!(lines[1], b"next");
        assert_eq!(offset, bytes.len() as u64);
    }

    #[test]
    fn utf16le_offset_equals_full_source_length() {
        // Two-line UTF-16LE file (with BOM so the encoding is detected). The
        // resume guarantee: after a full read the offset is the SOURCE byte
        // length, not the shorter decoded length -- so a checkpoint offset
        // remains a valid byte position to seek back to.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&utf16le_bytes("one\ntwo\n"));
        let (lines, offset) = read_from_start(&bytes);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"one");
        assert_eq!(lines[1], b"two");
        assert_eq!(offset, bytes.len() as u64);
        // Decoded total is far shorter than source -- proves offset is NOT in
        // decoded bytes (a whole-reader transcoder would have broken this).
        let decoded_total: usize = lines.iter().map(|l| l.len()).sum();
        assert!(offset as usize > decoded_total);
    }
}
