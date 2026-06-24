//! Disk spill when delivery buffers are full — mirrors Go `internal/overflow/writer.go`.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tracing::{debug, warn};

const DEFAULT_MAX_FILE_BYTES: i64 = 10 * 1024 * 1024;
const FILE_SUFFIX: &str = ".bin.gz";

#[derive(Debug, thiserror::Error)]
pub enum OverflowError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

struct SourceWriter {
    file: File,
    gz: GzEncoder<File>,
    bytes_written: i64,
    file_path: PathBuf,
}

pub struct Writer {
    base_dir: PathBuf,
    budget_bytes: i64,
    max_file_bytes: i64,
    total_bytes: i64,
    writers: HashMap<String, SourceWriter>,
}

impl Writer {
    pub fn new(base_dir: &Path, budget_mb: u64) -> Result<Self, OverflowError> {
        fs::create_dir_all(base_dir)?;
        let mut writer = Self {
            base_dir: base_dir.to_path_buf(),
            budget_bytes: (budget_mb as i64) * 1024 * 1024,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            total_bytes: 0,
            writers: HashMap::new(),
        };
        writer.scan_existing_files()?;
        Ok(writer)
    }

    pub fn write(
        &mut self,
        source_id: &str,
        line: &[u8],
        timestamp_ns: i64,
    ) -> Result<(), OverflowError> {
        let record = encode_record(line, timestamp_ns);

        if !self.writers.contains_key(source_id) {
            let sw = self.open_new_file(source_id)?;
            self.writers.insert(source_id.to_string(), sw);
        }

        let need_rotate = {
            let sw = self.writers.get_mut(source_id).expect("writer");
            sw.gz.write_all(&record)?;
            sw.bytes_written += record.len() as i64;
            sw.bytes_written >= self.max_file_bytes
        };

        if need_rotate {
            self.rotate_source(source_id)?;
        }

        while self.total_bytes > self.budget_bytes {
            if !self.evict_oldest()? {
                break;
            }
        }

        Ok(())
    }

    pub fn has_overflow(&self, source_id: &str) -> bool {
        let source_dir = self.base_dir.join(source_id);
        let Ok(entries) = fs::read_dir(&source_dir) else {
            return false;
        };
        let current = self.writers.get(source_id).map(|sw| sw.file_path.clone());
        for entry in entries.flatten() {
            let path = entry.path();
            if is_overflow_file(&path) && current.as_ref() != Some(&path) {
                return true;
            }
        }
        false
    }

    pub fn replay_batch(
        &mut self,
        source_id: &str,
        batch_size: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>, OverflowError> {
        self.finalize_active(source_id)?;
        let source_dir = self.base_dir.join(source_id);
        let current = self.writers.get(source_id).map(|sw| sw.file_path.clone());
        let mut files = list_overflow_files(&source_dir)?;
        files.retain(|p| current.as_ref() != Some(p));

        let mut out = Vec::new();
        for file_path in files {
            let entries = read_entire_file(&file_path)?;
            out.extend(entries);
            let size = fs::metadata(&file_path)
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            fs::remove_file(&file_path)?;
            self.total_bytes = (self.total_bytes - size).max(0);
            debug!(path = %file_path.display(), "removed replayed overflow file");
            if out.len() >= batch_size {
                out.truncate(batch_size);
                break;
            }
        }
        Ok(out)
    }

    fn finalize_active(&mut self, source_id: &str) -> Result<(), OverflowError> {
        let should_rotate = self
            .writers
            .get(source_id)
            .is_some_and(|sw| sw.bytes_written > 0);
        if should_rotate {
            self.rotate_source(source_id)?;
        }
        Ok(())
    }

    fn rotate_source(&mut self, source_id: &str) -> Result<(), OverflowError> {
        let Some(sw) = self.writers.remove(source_id) else {
            return Ok(());
        };
        sw.gz.finish()?;
        sw.file.sync_all()?;
        let size = fs::metadata(&sw.file_path)
            .map(|m| m.len() as i64)
            .unwrap_or(0);
        self.total_bytes += size;
        self.writers
            .insert(source_id.to_string(), self.open_new_file(source_id)?);
        Ok(())
    }

    fn open_new_file(&self, source_id: &str) -> Result<SourceWriter, OverflowError> {
        let source_dir = self.base_dir.join(source_id);
        fs::create_dir_all(&source_dir)?;
        let name = format!(
            "{}{FILE_SUFFIX}",
            chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.9fZ")
        );
        let path = source_dir.join(name);
        let file = File::create(&path)?;
        let gz = GzEncoder::new(file.try_clone()?, Compression::default());
        Ok(SourceWriter {
            file,
            gz,
            bytes_written: 0,
            file_path: path,
        })
    }

    fn evict_oldest(&mut self) -> Result<bool, OverflowError> {
        let mut oldest: Option<(PathBuf, i64, String)> = None;

        for entry in fs::read_dir(&self.base_dir)?.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let source_id = entry.file_name().to_string_lossy().to_string();
            let current = self.writers.get(&source_id).map(|sw| sw.file_path.clone());
            for file in fs::read_dir(entry.path())?.flatten() {
                let path = file.path();
                if !is_overflow_file(&path) || current.as_ref() == Some(&path) {
                    continue;
                }
                let name = file.file_name().to_string_lossy().to_string();
                if oldest.as_ref().is_none_or(|(_, _, n)| name < *n) {
                    let size = file.metadata().map_or(0, |m| m.len() as i64);
                    oldest = Some((path, size, name));
                }
            }
        }

        let Some((path, size, _)) = oldest else {
            return Ok(false);
        };
        fs::remove_file(&path)?;
        self.total_bytes = (self.total_bytes - size).max(0);
        Ok(true)
    }

    /// Abandon all active per-source encoders. Called after lock-poison
    /// recovery: a panic while the lock was held may have left an encoder
    /// mid-frame, and writing further into it would corrupt the stream.
    /// Each abandoned file keeps its flushed prefix and becomes a historical
    /// file (replayable, evictable); the next write opens a fresh file.
    fn reset_active_writers(&mut self) {
        let abandoned: Vec<(String, SourceWriter)> = self.writers.drain().collect();
        for (source_id, sw) in abandoned {
            warn!(
                source_id = %source_id,
                path = %sw.file_path.display(),
                "abandoning active overflow file after poison recovery"
            );
            let SourceWriter {
                file,
                gz,
                file_path,
                ..
            } = sw;
            // Best-effort: the trailer makes records written before the
            // panic decodable. A damaged tail is salvaged around on replay.
            let _ = gz.finish();
            let _ = file.sync_all();
            self.total_bytes += fs::metadata(&file_path).map_or(0, |m| m.len() as i64);
        }
    }

    fn scan_existing_files(&mut self) -> Result<(), OverflowError> {
        let Ok(entries) = fs::read_dir(&self.base_dir) else {
            return Ok(());
        };
        let mut total = 0i64;
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            for file in fs::read_dir(entry.path())?.flatten() {
                if is_overflow_file(&file.path()) {
                    total += file.metadata().map_or(0, |m| m.len() as i64);
                }
            }
        }
        self.total_bytes = total;
        Ok(())
    }
}

pub struct SharedOverflow {
    inner: Mutex<Writer>,
}

impl SharedOverflow {
    pub fn new(base_dir: &Path, budget_mb: u64) -> Result<Self, OverflowError> {
        Ok(Self {
            inner: Mutex::new(Writer::new(base_dir, budget_mb)?),
        })
    }

    // `write` and `replay_batch` are blocking-pool bound — gz encode, file
    // I/O, and (for replay) decompressing whole spill files — and include the
    // mutex acquisition so a contended lock doesn't park an async worker
    // either. `has_overflow` stays unwrapped: it's a directory listing (one
    // ENOENT syscall in the common no-overflow case), polled every idle drain
    // cycle, where the run_blocking core handoff would cost more than the op.

    pub fn write(
        &self,
        source_id: &str,
        line: &[u8],
        timestamp_ns: i64,
    ) -> Result<(), OverflowError> {
        crate::common::run_blocking(|| self.inner().write(source_id, line, timestamp_ns))
    }

    pub fn has_overflow(&self, source_id: &str) -> bool {
        self.inner().has_overflow(source_id)
    }

    pub fn replay_batch(
        &self,
        source_id: &str,
        batch_size: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>, OverflowError> {
        crate::common::run_blocking(|| self.inner().replay_batch(source_id, batch_size))
    }

    fn inner(&self) -> MutexGuard<'_, Writer> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("overflow lock poisoned; recovering writer state");
                self.inner.clear_poison();
                let mut guard = poisoned.into_inner();
                guard.reset_active_writers();
                guard
            }
        }
    }
}

fn encode_record(line: &[u8], timestamp_ns: i64) -> Vec<u8> {
    let record_len = (8 + line.len()) as u32;
    let mut buf = Vec::with_capacity(4 + 8 + line.len());
    buf.extend_from_slice(&record_len.to_be_bytes());
    buf.extend_from_slice(&(timestamp_ns as u64).to_be_bytes());
    buf.extend_from_slice(line);
    buf
}

fn is_overflow_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(FILE_SUFFIX) || n.ends_with(".ndjson.gz"))
}

fn list_overflow_files(dir: &Path) -> Result<Vec<PathBuf>, OverflowError> {
    let mut paths = Vec::new();
    if !dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(dir)?.flatten() {
        if is_overflow_file(&entry.path()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Decode every complete record in an overflow file. A truncated or corrupt
/// tail (crash mid-write, encoder abandoned after poison recovery) ends the
/// file early: complete records before the damage are salvaged and the rest
/// is dropped with a warning, so the caller can remove the file and replay
/// is never wedged on it.
fn read_entire_file(path: &Path) -> Result<Vec<(i64, Vec<u8>)>, OverflowError> {
    let file = File::open(path)?;
    let mut gz = GzDecoder::new(file);
    let mut out = Vec::new();
    let mut header = [0u8; 4];

    loop {
        match gz.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    salvaged = out.len(),
                    error = %e,
                    "overflow file damaged, salvaging complete records"
                );
                break;
            }
        }

        let record_len = u32::from_be_bytes(header) as usize;
        if record_len < 8 {
            warn!(
                path = %path.display(),
                salvaged = out.len(),
                record_len,
                "corrupt overflow record framing, salvaging complete records"
            );
            break;
        }
        let mut record = vec![0u8; record_len];
        if let Err(e) = gz.read_exact(&mut record) {
            warn!(
                path = %path.display(),
                salvaged = out.len(),
                error = %e,
                "truncated overflow record, salvaging complete records"
            );
            break;
        }

        let ts = i64::from_be_bytes(record[0..8].try_into().unwrap());
        out.push((ts, record[8..].to_vec()));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_replay_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let overflow = SharedOverflow::new(dir.path(), 64).unwrap();

        overflow.write("src-1", b"line-a", 100).unwrap();
        overflow.write("src-1", b"line-b", 200).unwrap();

        let batch = overflow.replay_batch("src-1", 100).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].1, b"line-a");
        assert_eq!(batch[1].1, b"line-b");
        assert!(!overflow.has_overflow("src-1"));
    }

    #[test]
    fn shared_overflow_recovers_from_poisoned_lock() {
        let dir = tempfile::tempdir().unwrap();
        let overflow = SharedOverflow::new(dir.path(), 64).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = overflow.inner.lock().unwrap();
            panic!("poison overflow");
        }));

        overflow.write("src-1", b"line-a", 100).unwrap();

        let batch = overflow.replay_batch("src-1", 100).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1, b"line-a");
    }

    /// Poison recovery must not keep writing into an encoder that was live
    /// when the panic happened: the active file is abandoned (its records
    /// salvageable) and the next write opens a fresh file.
    #[test]
    fn poison_recovery_abandons_active_writer_without_losing_records() {
        let dir = tempfile::tempdir().unwrap();
        let overflow = SharedOverflow::new(dir.path(), 64).unwrap();

        overflow.write("src-1", b"line-a", 100).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = overflow.inner.lock().unwrap();
            panic!("poison overflow");
        }));

        overflow.write("src-1", b"line-b", 200).unwrap();

        // The abandoned file and the fresh file are distinct.
        assert_eq!(
            list_overflow_files(&dir.path().join("src-1"))
                .unwrap()
                .len(),
            2
        );

        let batch = overflow.replay_batch("src-1", 100).unwrap();
        let lines: Vec<&[u8]> = batch.iter().map(|(_, l)| l.as_slice()).collect();
        assert_eq!(lines, [b"line-a".as_slice(), b"line-b".as_slice()]);
        assert!(!overflow.has_overflow("src-1"));
    }

    /// A damaged file must not wedge replay: complete records are salvaged,
    /// the file is removed, and later files still replay.
    #[test]
    fn replay_salvages_truncated_file_and_moves_on() {
        let dir = tempfile::tempdir().unwrap();
        let overflow = SharedOverflow::new(dir.path(), 64).unwrap();
        let source_dir = dir.path().join("src-1");
        fs::create_dir_all(&source_dir).unwrap();

        // Oldest file (sorts first): one complete record, then a record
        // whose header promises more bytes than the stream holds.
        let damaged = source_dir.join("2000-01-01T00-00-00.000000000Z.bin.gz");
        let mut gz = GzEncoder::new(File::create(&damaged).unwrap(), Compression::default());
        gz.write_all(&encode_record(b"salvaged", 100)).unwrap();
        gz.write_all(&encode_record(b"torn", 200)[..6]).unwrap();
        gz.finish().unwrap();

        overflow.write("src-1", b"line-after", 300).unwrap();

        let batch = overflow.replay_batch("src-1", 100).unwrap();
        let lines: Vec<&[u8]> = batch.iter().map(|(_, l)| l.as_slice()).collect();
        assert_eq!(lines, [b"salvaged".as_slice(), b"line-after".as_slice()]);
        assert!(!damaged.exists());
        assert!(!overflow.has_overflow("src-1"));
    }
}
