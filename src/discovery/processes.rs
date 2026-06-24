//! Process discovery — enumerates running processes with resource usage.
//!
//! Linux: native procfs-based enumeration via the `procfs` crate.
//! macOS: shells out to `ps aux` and parses tabular output.
//! Both paths produce the same `Process` struct matching legacy EdgePacer's JSON shape.

use serde::Serialize;
use tracing::debug;

/// A discovered running process.
#[derive(Debug, Clone, Serialize)]
pub struct Process {
    pub pid: u32,
    pub user: String,
    pub cpu: String,
    pub mem: String,
    pub command: String,
}

/// Discover running processes on the host.
pub async fn discover_processes() -> Result<Vec<Process>, String> {
    tokio::task::spawn_blocking(discover_processes_sync)
        .await
        .map_err(|e| format!("process discovery task failed: {e}"))?
}

/// Linux native: read /proc directly via procfs crate.
#[cfg(target_os = "linux")]
fn discover_processes_native() -> Result<Vec<Process>, String> {
    use procfs::process::all_processes;

    let procs = all_processes().map_err(|e| format!("failed to read /proc: {e}"))?;
    let page_size = procfs::page_size();
    let mut result = Vec::new();

    for entry in procs {
        let proc = match entry {
            Ok(p) => p,
            Err(_) => continue, // process exited between listing and reading
        };

        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let pid = stat.pid as u32;
        let uid = proc.uid().unwrap_or(0);
        let user = uid.to_string();

        // Command: prefer cmdline, fall back to stat comm
        let command = match proc.cmdline() {
            Ok(args) if !args.is_empty() => args.join(" "),
            _ => format!("[{}]", stat.comm),
        };

        // RSS in MB: rss is in pages
        let rss_mb = (stat.rss as f64 * page_size as f64) / (1024.0 * 1024.0);
        let mem = format!("{:.1}", rss_mb);

        // CPU as snapshot — "0.0" (matching Go's point-in-time `ps aux` behavior)
        let cpu = "0.0".to_string();

        result.push(Process {
            pid,
            user,
            cpu,
            mem,
            command,
        });
    }

    debug!(count = result.len(), "discovered processes via procfs");
    Ok(result)
}

/// Shell-out fallback: parse `ps aux` output.
fn discover_processes_shellout() -> Result<Vec<Process>, String> {
    let output = std::process::Command::new("ps")
        .args(["aux"])
        .output()
        .map_err(|e| format!("failed to run ps aux: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ps aux failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let processes = parse_ps_aux(&stdout);
    debug!(count = processes.len(), "discovered processes via ps aux");
    Ok(processes)
}

/// Parse `ps aux` tabular output into Process structs.
///
/// Fields: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
/// Command is everything after field 10 (index 10+), preserving spaces.
fn parse_ps_aux(output: &str) -> Vec<Process> {
    output
        .lines()
        .skip(1) // skip header
        .filter_map(parse_ps_aux_line)
        .collect()
}

fn parse_ps_aux_line(line: &str) -> Option<Process> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // ps aux columns: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
    // We need the first 10 whitespace-delimited tokens, then everything remaining is COMMAND.
    let mut tokens = trimmed.split_whitespace();

    let user = tokens.next()?.to_string();
    let pid: u32 = tokens.next()?.parse().ok()?;
    let cpu = tokens.next()?.to_string();
    let mem = tokens.next()?.to_string();
    let _vsz = tokens.next()?;
    let _rss = tokens.next()?;
    let _tt = tokens.next()?;
    let _stat = tokens.next()?;
    let _started = tokens.next()?;
    let _time = tokens.next()?;

    // Command is everything remaining — reconstruct from the remainder of the iterator.
    let command: String = tokens.collect::<Vec<&str>>().join(" ");
    if command.is_empty() {
        return None;
    }

    Some(Process {
        pid,
        user,
        cpu,
        mem,
        command,
    })
}

#[cfg(target_os = "linux")]
fn discover_processes_sync() -> Result<Vec<Process>, String> {
    // Try native procfs first, fall back to shell-out.
    discover_processes_native().or_else(|e| {
        tracing::warn!(error = %e, "procfs discovery failed, falling back to ps aux");
        discover_processes_shellout()
    })
}

#[cfg(not(target_os = "linux"))]
fn discover_processes_sync() -> Result<Vec<Process>, String> {
    discover_processes_shellout()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PS_AUX: &str = r#"USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1  4853248  32768   ??  Ss   Mon09AM   3:42.07 /sbin/launchd
_windowserver      312   3.2  0.5  8147820 164352   ??  Ss   Mon09AM  98:14.51 /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer -daemon
morten            1042   0.1  1.2 438762240 392400   ??  S    Mon09AM  12:05.83 /Applications/Firefox.app/Contents/MacOS/firefox -foreground
root               143   0.0  0.0  4341520   2048   ??  Ss   Mon09AM   0:03.19 /usr/sbin/syslogd
"#;

    #[test]
    fn parse_ps_aux_output() {
        let procs = parse_ps_aux(SAMPLE_PS_AUX);
        assert_eq!(procs.len(), 4);

        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[0].user, "root");
        assert_eq!(procs[0].cpu, "0.0");
        assert_eq!(procs[0].command, "/sbin/launchd");

        // Verify command with spaces preserved
        assert_eq!(procs[1].pid, 312);
        assert!(procs[1].command.contains("WindowServer"));

        // Verify command with args
        assert_eq!(procs[2].pid, 1042);
        assert!(procs[2].command.contains("firefox"));
        assert!(procs[2].command.contains("-foreground"));
    }

    #[test]
    fn parse_ps_aux_empty_lines() {
        let output = "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n\n";
        let procs = parse_ps_aux(output);
        assert!(procs.is_empty());
    }

    #[tokio::test]
    async fn discover_processes_finds_something() {
        // On any platform, there should be at least one process running.
        let procs = discover_processes().await.unwrap();
        assert!(!procs.is_empty(), "should find at least one process");

        // Our own process should be in there
        // Every discovered process should have a valid PID.
        assert!(procs.iter().all(|p| p.pid > 0));
    }
}
