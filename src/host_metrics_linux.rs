//! Linux-specific host metrics — /proc parsers for load averages,
//! TCP connection states, file descriptor limits, and disk I/O counters.

use tracing::warn;

/// Parse load averages from `/proc/loadavg`.
///
/// Format: "1.23 2.34 3.45 2/150 12345"
pub fn collect_load_avg() -> (f64, f64, f64) {
    match std::fs::read_to_string("/proc/loadavg") {
        Ok(contents) => {
            let parts: Vec<&str> = contents.split_whitespace().collect();
            if parts.len() >= 3 {
                let l1 = parts[0].parse::<f64>().unwrap_or(-1.0);
                let l5 = parts[1].parse::<f64>().unwrap_or(-1.0);
                let l15 = parts[2].parse::<f64>().unwrap_or(-1.0);
                (l1, l5, l15)
            } else {
                warn!("unexpected /proc/loadavg format");
                (-1.0, -1.0, -1.0)
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to read /proc/loadavg");
            (-1.0, -1.0, -1.0)
        }
    }
}

/// Parse TCP connection states from `/proc/net/tcp` and `/proc/net/tcp6`.
///
/// State field (index 3, hex): 01=ESTABLISHED, 06=TIME_WAIT, 08=CLOSE_WAIT.
/// Returns (established, time_wait, close_wait).
pub fn collect_tcp_stats() -> (i64, i64, i64) {
    let mut established: i64 = 0;
    let mut time_wait: i64 = 0;
    let mut close_wait: i64 = 0;

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in contents.lines().skip(1) {
            // skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            match parts[3] {
                "01" => established += 1,
                "06" => time_wait += 1,
                "08" => close_wait += 1,
                _ => {}
            }
        }
    }

    (established, time_wait, close_wait)
}

/// Parse file descriptor stats from `/proc/sys/fs/file-nr`.
///
/// Format: "open\tunused\tmax" — returns (open, max).
pub fn collect_fd_stats() -> (i64, i64) {
    match std::fs::read_to_string("/proc/sys/fs/file-nr") {
        Ok(contents) => {
            let parts: Vec<&str> = contents.split_whitespace().collect();
            if parts.len() >= 3 {
                let open = parts[0].parse::<i64>().unwrap_or(-1);
                let max = parts[2].parse::<i64>().unwrap_or(-1);
                (open, max)
            } else {
                warn!("unexpected /proc/sys/fs/file-nr format");
                (-1, -1)
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to read /proc/sys/fs/file-nr");
            (-1, -1)
        }
    }
}

/// Parse disk I/O counters from `/proc/diskstats`.
///
/// Skips loop, ram, and partition devices. Sums across real block devices.
/// Fields: [3]=reads_completed, [5]=sectors_read, [7]=writes_completed, [9]=sectors_written.
/// Sectors are 512 bytes each.
///
/// Returns (read_bytes, write_bytes, read_ops, write_ops).
pub fn collect_disk_io_counters() -> (u64, u64, u64, u64) {
    let contents = match std::fs::read_to_string("/proc/diskstats") {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read /proc/diskstats");
            return (0, 0, 0, 0);
        }
    };

    let mut read_bytes: u64 = 0;
    let mut write_bytes: u64 = 0;
    let mut read_ops: u64 = 0;
    let mut write_ops: u64 = 0;

    for line in contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let device = parts[2];

        // Skip loop devices, ram devices, and partitions (devices ending in digits
        // that have a letter-prefix base, e.g., sda1, nvme0n1p1).
        if device.starts_with("loop") || device.starts_with("ram") {
            continue;
        }
        // Skip partitions: if the device name ends with a digit and contains
        // a 'p' followed by digits (nvme partitions) or letters followed by digits (sd partitions).
        if is_partition(device) {
            continue;
        }

        let reads = parts[3].parse::<u64>().unwrap_or(0);
        let sectors_read = parts[5].parse::<u64>().unwrap_or(0);
        let writes = parts[7].parse::<u64>().unwrap_or(0);
        let sectors_written = parts[9].parse::<u64>().unwrap_or(0);

        read_ops += reads;
        write_ops += writes;
        read_bytes += sectors_read * 512;
        write_bytes += sectors_written * 512;
    }

    (read_bytes, write_bytes, read_ops, write_ops)
}

/// Heuristic: a device is a partition if it looks like "sda1", "vdb2", "nvme0n1p1", etc.
/// Whole-disk devices: "sda", "vdb", "nvme0n1", "xvda".
fn is_partition(device: &str) -> bool {
    // NVMe partitions: contain "p" after "n" followed by digits, e.g., nvme0n1p1
    if device.starts_with("nvme") {
        // nvme0n1 = disk, nvme0n1p1 = partition
        if let Some(pos) = device.rfind('p') {
            // Check there's a digit after the 'p' and 'n' before it
            if pos + 1 < device.len() && device[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
        return false;
    }

    // sd/vd/xvd partitions: letters followed by digits, e.g., sda1
    if device.starts_with("sd") || device.starts_with("vd") || device.starts_with("xvd") {
        return device.chars().last().is_some_and(|c| c.is_ascii_digit());
    }

    false
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[test]
    fn load_avg_returns_positive() {
        let (l1, l5, l15) = collect_load_avg();
        assert!(l1 >= 0.0, "load_avg_1 should be non-negative on Linux");
        assert!(l5 >= 0.0, "load_avg_5 should be non-negative on Linux");
        assert!(l15 >= 0.0, "load_avg_15 should be non-negative on Linux");
    }

    #[test]
    fn tcp_stats_returns_non_negative() {
        let (est, tw, cw) = collect_tcp_stats();
        assert!(est >= 0, "established should be non-negative");
        assert!(tw >= 0, "time_wait should be non-negative");
        assert!(cw >= 0, "close_wait should be non-negative");
    }

    #[test]
    fn fd_stats_returns_positive() {
        let (open, max) = collect_fd_stats();
        assert!(open > 0, "fd_open should be positive on Linux");
        assert!(max > 0, "fd_max should be positive on Linux");
    }

    #[test]
    fn disk_io_counters_returns_non_negative() {
        let (rb, wb, ro, wo) = collect_disk_io_counters();
        // Just verify no panics and values are reasonable.
        let _ = (rb, wb, ro, wo);
    }

    #[test]
    fn is_partition_detection() {
        assert!(!is_partition("sda"));
        assert!(is_partition("sda1"));
        assert!(!is_partition("nvme0n1"));
        assert!(is_partition("nvme0n1p1"));
        assert!(!is_partition("vdb"));
        assert!(is_partition("vdb1"));
    }
}
