//! Windows-specific host metrics.
//!
//! `sysinfo` already covers CPU, memory, disk capacity, network totals, and
//! process counts on Windows. This module fills the platform-specific counters
//! that `host_metrics.rs` plugs into the shared rate/snapshot machinery.

use std::mem::size_of;
use std::process::Command;

use sysinfo::Disks;
use tracing::warn;
use windows_sys::Win32::System::ProcessStatus::{K32GetPerformanceInfo, PERFORMANCE_INFORMATION};

/// Windows has no Unix-style 1/5/15 minute load average.
pub fn collect_load_avg() -> (f64, f64, f64) {
    (-1.0, -1.0, -1.0)
}

/// Parse TCP connection states from `netstat -an -p tcp`.
///
/// Returns (established, time_wait, close_wait).
pub fn collect_tcp_stats() -> (i64, i64, i64) {
    let output = match Command::new("netstat").args(["-an", "-p", "tcp"]).output() {
        Ok(output) => output,
        Err(error) => {
            warn!(error = %error, "failed to run netstat");
            return (-1, -1, -1);
        }
    };

    if !output.status.success() {
        warn!(status = %output.status, "netstat exited unsuccessfully");
        return (-1, -1, -1);
    }

    tcp_state_counts(&String::from_utf8_lossy(&output.stdout))
}

/// Windows exposes system handles, not a Unix fd table. Report the global
/// handle count in the existing `fd_open` slot; keep `fd_max` at -1 because
/// there is no comparable global descriptor limit.
pub fn collect_fd_stats() -> (i64, i64) {
    match collect_system_handle_count() {
        Some(handle_count) => (handle_count, -1),
        None => (-1, -1),
    }
}

/// Sum Windows disk I/O counters exposed by `sysinfo`.
pub fn collect_disk_io_counters() -> (u64, u64, u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    let mut read_bytes = 0;
    let mut write_bytes = 0;

    for disk in disks.list() {
        let usage = disk.usage();
        read_bytes += usage.total_read_bytes;
        write_bytes += usage.total_written_bytes;
    }

    // sysinfo 0.33 exposes byte counters for Windows disks, not operation counts.
    (read_bytes, write_bytes, 0, 0)
}

fn tcp_state_counts(text: &str) -> (i64, i64, i64) {
    let mut established = 0;
    let mut time_wait = 0;
    let mut close_wait = 0;

    for line in text.lines() {
        let state = line.split_whitespace().last();
        match state {
            Some("ESTABLISHED") => established += 1,
            Some("TIME_WAIT") => time_wait += 1,
            Some("CLOSE_WAIT") => close_wait += 1,
            _ => {}
        }
    }

    (established, time_wait, close_wait)
}

fn collect_system_handle_count() -> Option<i64> {
    let cb = size_of::<PERFORMANCE_INFORMATION>() as u32;
    let mut info = PERFORMANCE_INFORMATION {
        cb,
        ..Default::default()
    };

    // SAFETY: `info` is a valid, initialized PERFORMANCE_INFORMATION buffer
    // and `cb` is its exact size, as required by K32GetPerformanceInfo.
    let ok = unsafe { K32GetPerformanceInfo(&mut info, cb) };
    if ok == 0 {
        warn!("failed to query Windows performance information");
        return None;
    }

    Some(i64::from(info.HandleCount))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_state_counts_parses_netstat_output() {
        let output = "\
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:51111        127.0.0.1:443          ESTABLISHED
  TCP    127.0.0.1:51112        127.0.0.1:443          TIME_WAIT
  TCP    127.0.0.1:51113        127.0.0.1:443          CLOSE_WAIT
  TCP    127.0.0.1:51114        127.0.0.1:443          LISTENING
";

        assert_eq!(tcp_state_counts(output), (1, 1, 1));
    }

    #[test]
    fn windows_load_average_returns_sentinels() {
        assert_eq!(collect_load_avg(), (-1.0, -1.0, -1.0));
    }

    #[test]
    fn windows_fd_stats_reports_system_handle_count() {
        let (fd_open, fd_max) = collect_fd_stats();
        assert!(
            fd_open > 0,
            "Windows fd_open should carry the system handle count"
        );
        assert_eq!(
            fd_max, -1,
            "Windows has no Unix-style global descriptor limit"
        );
    }
}
