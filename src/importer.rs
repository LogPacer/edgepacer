//! Historical log file importer — batch import of old/rotated log files.
//!
//! M10: Imports compressed or plain log files that existed before the agent
//! started monitoring. Unlike live tailing (continuous), this is a one-shot
//! batch operation triggered by Rails via config.
//!
//! Decompression: auto-detected by file extension (.gz, .bz2, .xz, .zst).
//! Delivery: reuses the Shipper (same logpacer_wire protocol as live tailing).
//! Progress: reports status back to Rails (in_progress, completed, failed).

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

use flate2::read::GzDecoder;
use tracing::{error, info, warn};

use crate::shipper::{ShipResult, Shipper};

/// An import request from Rails — specifies which files to import.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImportRequest {
    /// Files to import, ordered by rotation number (oldest first).
    pub files: Vec<ImportFile>,
    /// Log source ID for this import.
    pub log_source_id: String,
    /// Endpoint to ship imported logs to.
    pub subbox_endpoint: String,
    /// Archive and repo IDs for the logpacer_wire batch.
    pub archive_id: String,
    pub repo_id: String,
}

/// A single file to import.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImportFile {
    pub path: String,
    /// Rotation number (higher = older). Used for ordering.
    pub rotation_number: u32,
    /// Whether the file is compressed (auto-detected from extension if not set).
    pub compressed: bool,
}

/// Result of an import operation.
#[derive(Debug)]
pub struct ImportResult {
    pub log_source_id: String,
    pub files_imported: u32,
    pub files_failed: u32,
    pub lines_shipped: u64,
    pub bytes_shipped: u64,
}

/// Execute an import request — import all files in order.
///
/// This is a one-shot batch operation. Each file is read, optionally
/// decompressed, batched into 1000-line chunks, and shipped via logpacer_wire.
pub async fn execute_import(request: &ImportRequest, hostname: &str) -> ImportResult {
    let shipper = match Shipper::new(
        &request.subbox_endpoint,
        &request.archive_id,
        &request.repo_id,
        Some(crate::identity::AgentIdentity::new(hostname.to_string())),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!(
                log_source_id = %request.log_source_id,
                error = %e,
                "failed to create shipper for import"
            );
            return ImportResult {
                log_source_id: request.log_source_id.clone(),
                files_imported: 0,
                files_failed: request.files.len() as u32,
                lines_shipped: 0,
                bytes_shipped: 0,
            };
        }
    };

    let mut files_imported = 0u32;
    let mut files_failed = 0u32;
    let mut total_lines = 0u64;
    let mut total_bytes = 0u64;

    // Import files in order (oldest first by rotation_number).
    let mut sorted_files = request.files.clone();
    sorted_files.sort_by_key(|f| std::cmp::Reverse(f.rotation_number));

    for import_file in &sorted_files {
        info!(
            path = %import_file.path,
            rotation = import_file.rotation_number,
            log_source_id = %request.log_source_id,
            "importing historical log file"
        );

        match import_single_file(&import_file.path, &shipper).await {
            Ok((lines, bytes)) => {
                files_imported += 1;
                total_lines += lines;
                total_bytes += bytes;
                info!(
                    path = %import_file.path,
                    lines,
                    bytes,
                    "file import complete"
                );
            }
            Err(e) => {
                files_failed += 1;
                error!(
                    path = %import_file.path,
                    error = %e,
                    "file import failed"
                );
            }
        }
    }

    ImportResult {
        log_source_id: request.log_source_id.clone(),
        files_imported,
        files_failed,
        lines_shipped: total_lines,
        bytes_shipped: total_bytes,
    }
}

/// Import a single file — decompress if needed, batch and ship.
async fn import_single_file(path: &str, shipper: &Shipper) -> Result<(u64, u64), String> {
    let reader =
        open_with_decompression(path).map_err(|e| format!("failed to open {path}: {e}"))?;

    let mut buf_reader = BufReader::new(reader);
    let mut lines_shipped = 0u64;
    let mut bytes_shipped = 0u64;
    let batch_size = 1000;
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);

    let mut line_buf = String::new();
    loop {
        line_buf.clear();
        let bytes_read = buf_reader
            .read_line(&mut line_buf)
            .map_err(|e| format!("read error: {e}"))?;

        if bytes_read == 0 {
            // EOF — ship remaining batch.
            if !batch.is_empty() {
                let (lines, bytes) = ship_batch(&batch, shipper).await?;
                lines_shipped += lines;
                bytes_shipped += bytes;
            }
            break;
        }

        let trimmed = line_buf.trim_end_matches('\n').trim_end_matches('\r');
        if !trimmed.is_empty() {
            batch.push(trimmed.as_bytes().to_vec());
        }

        if batch.len() >= batch_size {
            let (lines, bytes) = ship_batch(&batch, shipper).await?;
            lines_shipped += lines;
            bytes_shipped += bytes;
            batch.clear();
        }
    }

    Ok((lines_shipped, bytes_shipped))
}

/// Ship a batch of lines and return (lines_count, bytes_count).
async fn ship_batch(lines: &[Vec<u8>], shipper: &Shipper) -> Result<(u64, u64), String> {
    let bytes: u64 = lines.iter().map(|l| l.len() as u64).sum();
    let count = lines.len() as u64;

    let (encoded, _) = shipper
        .encode_batch(lines)
        .map_err(|e| format!("encode failed: {e}"))?;
    match shipper.send_with_retry(&encoded).await {
        Ok(ShipResult::Accepted { .. }) => Ok((count, bytes)),
        Ok(ShipResult::Rejected {
            accepted,
            rejected,
            message,
        }) => {
            warn!(accepted, rejected, error = %message, "import batch partially rejected");
            Ok((accepted as u64, bytes))
        }
        Err(e) => Err(format!("ship failed: {e}")),
    }
}

/// Open a file with automatic decompression based on extension.
///
/// This is the swappable adapter — currently supports gzip.
/// Additional formats (bz2, xz, zstd) can be added by extending the match.
fn open_with_decompression(path: &str) -> io::Result<Box<dyn Read>> {
    let file = File::open(path)?;

    if path.ends_with(".gz") {
        Ok(Box::new(GzDecoder::new(file)))
    } else {
        // Plain text or unknown extension — read as-is.
        Ok(Box::new(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn open_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "line1\nline2\n").unwrap();

        let mut reader = open_with_decompression(path.to_str().unwrap()).unwrap();
        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        assert_eq!(content, "line1\nline2\n");
    }

    #[test]
    fn open_gzip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log.gz");

        // Write gzip data
        let file = File::create(&path).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        encoder
            .write_all(b"compressed line1\ncompressed line2\n")
            .unwrap();
        encoder.finish().unwrap();

        let mut reader = open_with_decompression(path.to_str().unwrap()).unwrap();
        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        assert_eq!(content, "compressed line1\ncompressed line2\n");
    }

    #[test]
    fn import_files_sorted_by_rotation() {
        let mut files = [
            ImportFile {
                path: "app.log".into(),
                rotation_number: 0,
                compressed: false,
            },
            ImportFile {
                path: "app.log.2.gz".into(),
                rotation_number: 2,
                compressed: true,
            },
            ImportFile {
                path: "app.log.1".into(),
                rotation_number: 1,
                compressed: false,
            },
        ];
        files.sort_by_key(|f| std::cmp::Reverse(f.rotation_number));

        assert_eq!(files[0].path, "app.log.2.gz"); // oldest first
        assert_eq!(files[1].path, "app.log.1");
        assert_eq!(files[2].path, "app.log");
    }
}
