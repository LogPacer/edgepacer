# EdgePacer Windows Support — Gap Inventory & Fix Plan

Status: in progress · 2026-06-29 · derived from a live Windows VM (Parallels) install against local dev.

The agent installs, bootstraps, signs-updates, and runs on Windows. Discovery + a few
metrics are the gaps. The codebase is already largely Windows-aware (token store, signals,
permissions, inode/file-identity, readiness file, paths are all correctly `#[cfg]`-gated).
This is the complete list of what's NOT, ranked.

## P0 — blocking, observed on the VM

1. **Self-update rename race** — `src/manager/updater.rs:215` `install_new()` does a bare
   `std::fs::rename(new → target)`. Windows holds the image lock on the running (or just-killed)
   `edgepacer.exe` → `Access is denied (os error 5)`, intermittently (succeeds only once the old
   process is fully dead). Drives a restart/update churn.
   **Fix:** Windows rename-aside — Windows *allows* renaming a running exe, just not overwriting
   in place. Move `target → .old`, move `new → target`, best-effort delete `.old`, with
   retry-with-backoff. No `unsafe`. (First-install case: target absent → just move new in.)

2. **`memory_mb=0` in host metadata** — `src/bootstrap.rs read_memory_mb()` (~119–150) tries
   `/proc/meminfo`, then macOS `sysctl`, then returns `0` — no Windows path.
   **Fix:** Windows branch via `GlobalMemoryStatusEx().ullTotalPhys`. (`host_metrics.rs` memory is
   fine — it calls `refresh_memory()` at :147 before `total_memory()`.)

## P1 — discovery (user priority: "detect containers and such")

3. **Process discovery** — `src/discovery/processes.rs`: non-Linux falls to
   `discover_processes_shellout()` (:79 `ps aux`) → `program not found` on Windows.
   **Fix:** `#[cfg(windows)]` `discover_processes_sync()` via `sysinfo` (already a dep; used in
   `host_metrics.rs`). Map → `Process{pid,user,cpu,mem,command}`.

4. **Port discovery** — `src/discovery/ports.rs`: non-Linux falls to `discover_ports_shellout()`
   (:129 `lsof`) → `program not found`.
   **Fix:** `#[cfg(windows)]` `discover_ports_sync()` via `netstat -ano` (netstat is the sanctioned
   Windows shell-out already used in `host_metrics_windows.rs`); parse `LISTENING` rows → port +
   PID, resolve PID→name from the process list.

5. **Docker container discovery** — `src/discovery/docker.rs` is **already correct** for Windows
   named pipes (`npipe:////./pipe/docker_engine`). The VM's `Socket not found` = Docker Desktop not
   running, NOT a code bug. No change; document the prerequisite. (Windows Service discovery via
   `sc queryex` and graceful systemd/CRI/packages skips are all already correct.)

## P2 — metrics completeness (nice-to-have for pilot)

6. **`os_version` = "unknown"** on Windows — `bootstrap.rs` (~91–116). Fix: registry
   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (ProductName/DisplayVersion/CurrentBuild).
7. **`disk_read/write_ops_per_sec` = 0** — `host_metrics_windows.rs:62` hardcodes ops (sysinfo 0.33
   exposes bytes, not ops, on Windows). Fix: PDH `\PhysicalDisk(_Total)\Disk Transfers/sec`, or leave 0.
8. **Process states** (`processes_running/sleeping/idle`) may be 0 — `host_metrics.rs:245-247`
   matches `ProcessStatus` that sysinfo may not populate on Windows. Verify; if empty, fall back to
   `running = total`.

## P3 — cleanups (explicitness, not bugs)

9. `bootstrap.rs` reads `/etc/os-release` (:93), `/proc/meminfo` (:121), `/proc/1/cgroup` (:162),
   `/var/run/secrets/...` (:179) unguarded — fail-silent on Windows but should be `#[cfg]`-explicit.

## Correct as-is — do NOT "fix"
- `load_avg = -1.0`, `fd_limit = -1`, `processes_zombie = 0` are intentional Windows sentinels.
- Token store, signals (SIGTERM/kill), `0o7xx` perms, inode/file-identity, readiness file, all path
  construction — already correctly `#[cfg]`-gated.

## Build sequence
P0 (updater rename-aside, bootstrap memory) → P1 (process, port) → `Cargo.toml` windows-sys
`Win32_System_Memory` feature → cross-build `windows-amd64` → re-vendor/register/sign → reinstall.
Pair with `docs/windows-pilot-test-plan.md`.
