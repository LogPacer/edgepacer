//! macOS-specific host metrics — sysctl/netstat parsers for load averages,
//! TCP connection states, file descriptor limits, and disk I/O counters.

use std::process::Command;
use tracing::warn;

/// Parse load averages from `sysctl -n vm.loadavg`.
///
/// Output format: "{ 1.23 2.34 3.45 }"
pub fn collect_load_avg() -> (f64, f64, f64) {
    let output = match Command::new("sysctl").args(["-n", "vm.loadavg"]).output() {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "failed to run sysctl vm.loadavg");
            return (-1.0, -1.0, -1.0);
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    // Strip braces and parse: "{ 1.23 2.34 3.45 }" -> ["1.23", "2.34", "3.45"]
    let cleaned = text.replace(['{', '}'], "");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();

    if parts.len() >= 3 {
        let l1 = parts[0].parse::<f64>().unwrap_or(-1.0);
        let l5 = parts[1].parse::<f64>().unwrap_or(-1.0);
        let l15 = parts[2].parse::<f64>().unwrap_or(-1.0);
        (l1, l5, l15)
    } else {
        warn!(raw = %text.trim(), "unexpected vm.loadavg format");
        (-1.0, -1.0, -1.0)
    }
}

/// Parse TCP connection states from `netstat -an -p tcp`.
///
/// Looks for ESTABLISHED, TIME_WAIT, CLOSE_WAIT in the state column.
/// Returns (established, time_wait, close_wait).
pub fn collect_tcp_stats() -> (i64, i64, i64) {
    let output = match Command::new("netstat").args(["-an", "-p", "tcp"]).output() {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "failed to run netstat");
            return (-1, -1, -1);
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut established: i64 = 0;
    let mut time_wait: i64 = 0;
    let mut close_wait: i64 = 0;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        // State is typically the last field in netstat output.
        let state = parts[parts.len() - 1];
        match state {
            "ESTABLISHED" => established += 1,
            "TIME_WAIT" => time_wait += 1,
            "CLOSE_WAIT" => close_wait += 1,
            _ => {}
        }
    }

    (established, time_wait, close_wait)
}

/// Parse file descriptor stats from sysctl.
///
/// `kern.num_files` = currently open, `kern.maxfiles` = system limit.
/// Returns (open, max).
pub fn collect_fd_stats() -> (i64, i64) {
    let open = sysctl_i64("kern.num_files");
    let max = sysctl_i64("kern.maxfiles");
    (open, max)
}

/// Disk I/O counters — not easily available on macOS without IOKit.
///
/// legacy EdgePacer returns zeros here too. Returns (0, 0, 0, 0).
pub fn collect_disk_io_counters() -> (u64, u64, u64, u64) {
    (0, 0, 0, 0)
}

/// Helper: read a single integer from `sysctl -n <key>`.
fn sysctl_i64(key: &str) -> i64 {
    let output = match Command::new("sysctl").args(["-n", key]).output() {
        Ok(o) => o,
        Err(e) => {
            warn!(key, error = %e, "failed to run sysctl");
            return -1;
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse::<i64>().unwrap_or(-1)
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn load_avg_returns_positive() {
        let (l1, l5, l15) = collect_load_avg();
        assert!(l1 >= 0.0, "load_avg_1 should be non-negative on macOS");
        assert!(l5 >= 0.0, "load_avg_5 should be non-negative on macOS");
        assert!(l15 >= 0.0, "load_avg_15 should be non-negative on macOS");
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
        assert!(open > 0, "fd_open should be positive on macOS");
        assert!(max > 0, "fd_max should be positive on macOS");
    }

    #[test]
    fn disk_io_counters_returns_zeros() {
        let (rb, wb, ro, wo) = collect_disk_io_counters();
        assert_eq!((rb, wb, ro, wo), (0, 0, 0, 0));
    }
}
