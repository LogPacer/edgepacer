//! Kubernetes pod log tailer — reads CRI-format logs from /var/log/pods/.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use regex::Regex;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

use crate::checkpoint::Checkpoint;
use crate::cri;
use crate::tailer::{DEFAULT_MAX_LINE_BYTES, ReadPosition};

static LOG_FILE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d+)\.log$").expect("valid log file pattern"));

/// Tails numbered CRI log files inside a K8s container log directory.
pub struct ContainerReader {
    container_dir: PathBuf,
    current_file: String,
    reader: Option<BufReader<File>>,
    offset: u64,
    inode: u64,
    partial_buffer: Vec<u8>,
}

impl ContainerReader {
    pub fn open(container_dir: &Path) -> io::Result<Self> {
        let mut reader = Self {
            container_dir: container_dir.to_path_buf(),
            current_file: String::new(),
            reader: None,
            offset: 0,
            inode: 0,
            partial_buffer: Vec::new(),
        };
        reader.find_and_open_active_log()?;
        Ok(reader)
    }

    pub fn open_with_checkpoint(container_dir: &Path, checkpoint: &Checkpoint) -> io::Result<Self> {
        let mut reader = Self {
            container_dir: container_dir.to_path_buf(),
            current_file: String::new(),
            reader: None,
            offset: checkpoint.offset,
            inode: checkpoint.inode,
            partial_buffer: Vec::new(),
        };
        reader.find_and_open_active_log()?;
        Ok(reader)
    }

    pub fn read_lines(&mut self, max_lines: usize) -> io::Result<Vec<Vec<u8>>> {
        self.check_rotation()?;

        let Some(reader) = self.reader.as_mut() else {
            return Ok(Vec::new());
        };

        let mut lines = Vec::new();

        for _ in 0..max_lines {
            let mut raw = Vec::new();
            match reader.read_until(b'\n', &mut raw) {
                Ok(0) => break,
                Ok(n) => {
                    self.offset += n as u64;
                    if raw.last() == Some(&b'\n') {
                        raw.pop();
                    }
                    if raw.last() == Some(&b'\r') {
                        raw.pop();
                    }

                    let Some(mut out) = cri::reassemble_partial(&raw, &mut self.partial_buffer)
                    else {
                        continue;
                    };

                    if out.len() > DEFAULT_MAX_LINE_BYTES {
                        warn!(
                            dir = %self.container_dir.display(),
                            len = out.len(),
                            "truncating oversized CRI log line"
                        );
                        out.truncate(DEFAULT_MAX_LINE_BYTES);
                    }

                    lines.push(out);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(lines)
    }

    pub fn position(&self) -> ReadPosition {
        ReadPosition {
            offset: self.offset,
            inode: self.inode,
        }
    }

    fn find_and_open_active_log(&mut self) -> io::Result<()> {
        let active = find_highest_log_file(&self.container_dir)?;
        self.open_file(&self.container_dir.join(&active))?;
        self.current_file = active;
        Ok(())
    }

    fn open_file(&mut self, path: &Path) -> io::Result<()> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        self.inode = inode_of(&meta);

        if self.offset == 0 {
            file.seek(SeekFrom::End(0))?;
            self.offset = file.stream_position()?;
        } else {
            file.seek(SeekFrom::Start(self.offset))?;
        }

        self.reader = Some(BufReader::new(file));

        debug!(
            path = %path.display(),
            offset = self.offset,
            inode = self.inode,
            "opened K8s container log file"
        );

        Ok(())
    }

    fn check_rotation(&mut self) -> io::Result<()> {
        let highest = match find_highest_log_file(&self.container_dir) {
            Ok(name) => name,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.reader = None;
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        if highest != self.current_file {
            info!(
                dir = %self.container_dir.display(),
                old = %self.current_file,
                new = %highest,
                "K8s log rotation detected"
            );
            self.offset = 0;
            self.open_file(&self.container_dir.join(&highest))?;
            self.current_file = highest;
        } else if let Some(reader) = self.reader.as_ref()
            && let Ok(meta) = reader.get_ref().metadata()
            && meta.len() < self.offset
        {
            warn!(
                file = %self.current_file,
                offset = self.offset,
                size = meta.len(),
                "K8s log file truncated, rewinding"
            );
            self.offset = 0;
            self.open_file(&self.container_dir.join(&self.current_file))?;
        }

        Ok(())
    }
}

fn find_highest_log_file(dir: &Path) -> io::Result<String> {
    let mut best_num = -1i32;
    let mut best_name = String::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(caps) = LOG_FILE_PATTERN.captures(&name) {
            let num: i32 = caps[1].parse().unwrap_or(-1);
            if num > best_num {
                best_num = num;
                best_name = name;
            }
        }
    }

    if best_name.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no log files in {}", dir.display()),
        ))
    } else {
        Ok(best_name)
    }
}

#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Read all assembled CRI messages from a container log directory for sampling.
///
/// Batch, read-only counterpart to [`ContainerReader::read_lines`]: it reuses
/// the exact same [`cri::reassemble_partial`] parse + `P`/`F` reassembly and the
/// same oversized-line truncation, so a sampled message is byte-identical to the
/// bare message the streaming tailer ships on the wire. Reads the active
/// (highest-numbered) log file from the start; a dangling partial at EOF is left
/// unemitted, matching the wire.
///
/// This is the reader seam only — it does not apply a tail window. The sampler
/// composes the optional multiline assembler on top and then takes the tail, so
/// the window covers whole assembled entries, matching the shipping pipeline.
pub fn sample_lines(container_dir: &Path) -> io::Result<Vec<Vec<u8>>> {
    let active = find_highest_log_file(container_dir)?;
    let file = File::open(container_dir.join(&active))?;
    let mut reader = BufReader::new(file);
    let mut partial_buffer = Vec::new();
    let mut lines = Vec::new();

    loop {
        let mut raw = Vec::new();
        match reader.read_until(b'\n', &mut raw) {
            Ok(0) => break,
            Ok(_) => {
                if raw.last() == Some(&b'\n') {
                    raw.pop();
                }
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }

                if let Some(mut out) = cri::reassemble_partial(&raw, &mut partial_buffer) {
                    if out.len() > DEFAULT_MAX_LINE_BYTES {
                        out.truncate(DEFAULT_MAX_LINE_BYTES);
                    }
                    lines.push(out);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(lines)
}

/// Whether `path` looks like a K8s container log directory under /var/log/pods/.
pub fn is_kubernetes_log_path(path: &Path) -> bool {
    let Some(s) = path.to_str() else {
        return false;
    };
    if !s.contains("/pods/") {
        return false;
    }
    find_highest_log_file(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kill-test: a Kubernetes sample must be byte-identical to the bare
    /// messages the streaming tailer ships — CRI prefix stripped and `P`/`F`
    /// partials reassembled. On the pre-fix sampler (raw `read_file_lines`) the
    /// sample kept the CRI timestamp/stream/flag prefix and split partials, so
    /// this comparison failed.
    #[test]
    fn kt_k8s_sample_lines_equal_wire_messages() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("0.log");
        std::fs::write(&log_path, b"").unwrap();

        // Open the wire reader first (it seeks to end), then append the fixture
        // so read_lines observes exactly what sample_lines reads from the start.
        let mut wire_reader = ContainerReader::open(dir.path()).unwrap();

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(
            f,
            "2026-07-13T10:30:45.000000000Z stdout F plain message one"
        )
        .unwrap();
        writeln!(f, "2026-07-13T10:30:45.100000000Z stdout P Hello, ").unwrap();
        writeln!(f, "2026-07-13T10:30:45.200000000Z stdout F world").unwrap();
        writeln!(
            f,
            "2026-07-13T10:30:45.300000000Z stdout F {{\"level\":\"info\",\"msg\":\"json body\"}}"
        )
        .unwrap();
        f.flush().unwrap();

        let wire_messages = wire_reader.read_lines(100).unwrap();
        let sample_messages = sample_lines(dir.path()).unwrap();

        assert_eq!(
            wire_messages, sample_messages,
            "k8s sample must equal the wire's bare CRI-parsed messages"
        );
        assert_eq!(
            sample_messages,
            vec![
                b"plain message one".to_vec(),
                b"Hello, world".to_vec(),
                br#"{"level":"info","msg":"json body"}"#.to_vec(),
            ],
            "partials reassembled, prefixes stripped, JSON body starts with '{{'"
        );
    }

    #[test]
    fn reads_cri_lines_from_active_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("0.log");
        std::fs::write(&log_path, b"").unwrap();

        let mut reader = ContainerReader::open(dir.path()).unwrap();

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        use std::io::Write;
        writeln!(f, "2024-01-15T10:30:45.123456789Z stdout F line one").unwrap();
        writeln!(f, "2024-01-15T10:30:46.123456789Z stdout F line two").unwrap();

        let lines = reader.read_lines(10).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"line one");
        assert_eq!(lines[1], b"line two");
    }
}
