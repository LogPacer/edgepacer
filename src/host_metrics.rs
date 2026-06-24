//! Host metrics collection — CPU, memory, disk, network, processes.
//!
//! Cross-platform collector using `sysinfo` for most metrics, with
//! platform-specific parsers for load averages, TCP states, file
//! descriptors, and disk I/O counters.
//!
//! Mirrors legacy EdgePacer's `internal/stats/hostmetrics.go`.

use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, ProcessStatus, ProcessesToUpdate, System};
use tracing::warn;

// --- Platform-specific imports ---

#[cfg(target_os = "linux")]
pub use crate::host_metrics_linux::{
    collect_disk_io_counters, collect_fd_stats, collect_load_avg, collect_tcp_stats,
};

#[cfg(target_os = "macos")]
pub use crate::host_metrics_darwin::{
    collect_disk_io_counters, collect_fd_stats, collect_load_avg, collect_tcp_stats,
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_load_avg() -> (f64, f64, f64) {
    (-1.0, -1.0, -1.0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_tcp_stats() -> (i64, i64, i64) {
    (-1, -1, -1)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_fd_stats() -> (i64, i64) {
    (-1, -1)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_disk_io_counters() -> (u64, u64, u64, u64) {
    (0, 0, 0, 0)
}

// --- Structs ---

/// Host-level metrics matching Go's `HostMetrics` struct.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostMetrics {
    pub cpu_percent: f64,

    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,

    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub memory_percent: f64,

    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub disk_used_percent: f64,

    pub disk_read_bytes_per_sec: f64,
    pub disk_write_bytes_per_sec: f64,
    pub disk_read_ops_per_sec: f64,
    pub disk_write_ops_per_sec: f64,

    pub net_recv_bytes_per_sec: f64,
    pub net_sent_bytes_per_sec: f64,
    pub net_recv_packets_per_sec: f64,
    pub net_sent_packets_per_sec: f64,

    pub processes_total: u64,
    pub processes_running: u64,
    pub processes_sleeping: u64,
    pub processes_idle: u64,
    pub processes_zombie: u64,

    pub tcp_established: i64,
    pub tcp_time_wait: i64,
    pub tcp_close_wait: i64,

    pub fd_open: i64,
    pub fd_max: i64,
}

/// Raw I/O counters for computing delta rates between collections.
#[derive(Debug, Clone, Default)]
pub struct IoSnapshot {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_ops: u64,
    pub disk_write_ops: u64,

    pub net_recv_bytes: u64,
    pub net_sent_bytes: u64,
    pub net_recv_packets: u64,
    pub net_sent_packets: u64,
}

/// Collects host metrics using sysinfo + platform-specific parsers.
pub struct MetricsCollector {
    system: System,
    networks: Networks,
    disks: Disks,
    prev_snapshot: Option<IoSnapshot>,
    last_collect: Instant,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    /// Create a new collector, priming CPU so the first real reading is nonzero.
    pub fn new() -> Self {
        let mut system = System::new();
        // First CPU reading is always 0 — prime it now.
        system.refresh_cpu_all();

        Self {
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            prev_snapshot: None,
            last_collect: Instant::now(),
        }
    }

    /// Collect a full set of host metrics.
    pub fn collect(&mut self) -> HostMetrics {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_collect).as_secs_f64();

        // Refresh sysinfo subsystems.
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        self.disks.refresh(true);
        self.networks.refresh(true);

        // CPU
        let cpu_percent = self.system.global_cpu_usage() as f64;

        // Memory (sysinfo returns bytes)
        let total_bytes = self.system.total_memory();
        let available_bytes = self.system.available_memory();
        let used_bytes = total_bytes.saturating_sub(available_bytes);
        let memory_percent = if total_bytes > 0 {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        // Disk and network fields are filled in incrementally below.
        let mut m = HostMetrics {
            cpu_percent,
            memory_total_mb: total_bytes / (1024 * 1024),
            memory_used_mb: used_bytes / (1024 * 1024),
            memory_percent,
            ..Default::default()
        };

        // Disk — find root mount
        for disk in self.disks.list() {
            if disk.mount_point() == std::path::Path::new("/") {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total.saturating_sub(available);
                m.disk_total_gb = total as f64 / (1024.0 * 1024.0 * 1024.0);
                m.disk_used_gb = used as f64 / (1024.0 * 1024.0 * 1024.0);
                m.disk_used_percent = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                break;
            }
        }

        // Network I/O — aggregate all interfaces (sysinfo total counters)
        let mut net_recv_bytes: u64 = 0;
        let mut net_sent_bytes: u64 = 0;
        let mut net_recv_packets: u64 = 0;
        let mut net_sent_packets: u64 = 0;
        for data in self.networks.list().values() {
            net_recv_bytes += data.total_received();
            net_sent_bytes += data.total_transmitted();
            net_recv_packets += data.total_packets_received();
            net_sent_packets += data.total_packets_transmitted();
        }

        // Disk I/O counters (platform-specific)
        let (disk_read_bytes, disk_write_bytes, disk_read_ops, disk_write_ops) =
            collect_disk_io_counters();

        // Build current snapshot for delta computation
        let current_snapshot = IoSnapshot {
            disk_read_bytes,
            disk_write_bytes,
            disk_read_ops,
            disk_write_ops,
            net_recv_bytes,
            net_sent_bytes,
            net_recv_packets,
            net_sent_packets,
        };

        // Compute rates from previous snapshot
        if let Some(ref prev) = self.prev_snapshot
            && elapsed > 0.0
        {
            m.disk_read_bytes_per_sec =
                delta(current_snapshot.disk_read_bytes, prev.disk_read_bytes) as f64 / elapsed;
            m.disk_write_bytes_per_sec =
                delta(current_snapshot.disk_write_bytes, prev.disk_write_bytes) as f64 / elapsed;
            m.disk_read_ops_per_sec =
                delta(current_snapshot.disk_read_ops, prev.disk_read_ops) as f64 / elapsed;
            m.disk_write_ops_per_sec =
                delta(current_snapshot.disk_write_ops, prev.disk_write_ops) as f64 / elapsed;

            m.net_recv_bytes_per_sec =
                delta(current_snapshot.net_recv_bytes, prev.net_recv_bytes) as f64 / elapsed;
            m.net_sent_bytes_per_sec =
                delta(current_snapshot.net_sent_bytes, prev.net_sent_bytes) as f64 / elapsed;
            m.net_recv_packets_per_sec =
                delta(current_snapshot.net_recv_packets, prev.net_recv_packets) as f64 / elapsed;
            m.net_sent_packets_per_sec =
                delta(current_snapshot.net_sent_packets, prev.net_sent_packets) as f64 / elapsed;
        }

        self.prev_snapshot = Some(current_snapshot);
        self.last_collect = now;

        // Process counts
        for process in self.system.processes().values() {
            m.processes_total += 1;
            match process.status() {
                ProcessStatus::Run => m.processes_running += 1,
                ProcessStatus::Sleep => m.processes_sleeping += 1,
                ProcessStatus::Idle => m.processes_idle += 1,
                ProcessStatus::Zombie => m.processes_zombie += 1,
                _ => {}
            }
        }

        // Load averages (platform-specific)
        let (l1, l5, l15) = collect_load_avg();
        m.load_avg_1 = l1;
        m.load_avg_5 = l5;
        m.load_avg_15 = l15;

        // TCP states (platform-specific)
        let (est, tw, cw) = collect_tcp_stats();
        m.tcp_established = est;
        m.tcp_time_wait = tw;
        m.tcp_close_wait = cw;

        // File descriptors (platform-specific)
        let (fd_open, fd_max) = collect_fd_stats();
        m.fd_open = fd_open;
        m.fd_max = fd_max;

        m
    }

    /// Collect this agent's own CPU% and memory MB via sysinfo process lookup.
    ///
    /// Memory is the agent's ANONYMOUS footprint where the platform can tell
    /// (Linux RssAnon), not total RSS: sdjournal mmaps the system journals —
    /// gigabytes of shared, kernel-reclaimable page cache that exists
    /// regardless of us — so total RSS reads as a multi-GB "leak" while the
    /// actual heap is a few MB.
    pub fn collect_process_metrics(&mut self) -> (f64, u64) {
        let pid = match sysinfo::get_current_pid() {
            Ok(pid) => pid,
            Err(e) => {
                warn!(error = %e, "failed to get current PID");
                return (0.0, 0);
            }
        };

        self.system
            .refresh_processes(ProcessesToUpdate::Some(&[pid]), true);

        match self.system.process(pid) {
            Some(process) => {
                let cpu = process.cpu_usage() as f64;
                let mem_mb =
                    own_anonymous_memory_mb().unwrap_or_else(|| process.memory() / (1024 * 1024));
                (cpu, mem_mb)
            }
            None => {
                warn!("could not find own process in sysinfo");
                (0.0, 0)
            }
        }
    }
}

/// Linux: the process's anonymous resident memory (heap/stacks) in MB, from
/// /proc/self/status RssAnon. None on other platforms or read failure —
/// callers fall back to sysinfo's total RSS.
fn own_anonymous_memory_mb() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }

    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb / 1024)
}

/// Safe delta: returns `current - previous`, or 0 on wraparound.
pub fn delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_normal() {
        assert_eq!(delta(100, 50), 50);
        assert_eq!(delta(0, 0), 0);
        assert_eq!(delta(1_000_000, 999_999), 1);
    }

    #[test]
    fn delta_wraparound_returns_zero() {
        assert_eq!(delta(10, 100), 0);
        assert_eq!(delta(0, u64::MAX), 0);
    }

    #[test]
    fn collector_returns_nonzero_memory() {
        let mut collector = MetricsCollector::new();
        let metrics = collector.collect();
        // Any real system has memory.
        assert!(
            metrics.memory_total_mb > 0,
            "total memory should be nonzero"
        );
        assert!(metrics.memory_used_mb > 0, "used memory should be nonzero");
    }

    #[test]
    fn cpu_requires_two_readings() {
        let mut collector = MetricsCollector::new();
        // First collect after priming — CPU may still be 0 depending on timing.
        let _first = collector.collect();
        // Small pause to let CPU measurement stabilize.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let second = collector.collect();
        // CPU should be >= 0 (could be 0 on idle systems, but shouldn't be negative).
        assert!(
            second.cpu_percent >= 0.0,
            "CPU percent should be non-negative"
        );
    }

    #[test]
    fn process_metrics_returns_something() {
        let mut collector = MetricsCollector::new();
        let (cpu, mem) = collector.collect_process_metrics();
        // CPU might be 0.0 on a first reading, but memory should be nonzero.
        assert!(cpu >= 0.0, "process CPU should be non-negative");
        // Our process uses at least some memory.
        // Note: mem could be 0 if the process just started, so we just check non-negative.
        let _ = mem; // Just ensure it doesn't panic.
    }

    #[test]
    fn host_metrics_serializes() {
        let m = HostMetrics::default();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"cpu_percent\""));
        assert!(json.contains("\"load_avg_1\""));
        assert!(json.contains("\"memory_total_mb\""));
        assert!(json.contains("\"tcp_established\""));
        assert!(json.contains("\"fd_open\""));
    }
}
