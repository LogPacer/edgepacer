//! eBPF subsystem — capability detection, status reporting, and (behind the
//! `ebpf` feature) kernel program loading.
//!
//! Mirrors legacy EdgePacer's `internal/ebpf/`. This module is always compiled so
//! capability detection and the stats contract work on every platform; the
//! actual program-loading paths are gated behind `#[cfg(all(target_os =
//! "linux", feature = "ebpf"))]` and pulled in by later pillars (log capture,
//! network flows).

mod capability;
// Cgroup-v2 process identity. Parsing is host-tested; the filesystem lookup is
// Linux + ebpf only.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
mod cgroup_resolver;
#[cfg(any(test, target_os = "linux"))]
#[allow(dead_code)]
mod cgroup_v2;
// Pure control-plane logic, used by the (Linux-only) manager and exercised by
// `cargo test` on every platform — so it compiles where it is used or tested,
// not under a bare `target_os = "linux"` gate that macOS would never build.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
mod listener_snapshot;
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
mod listener_state;
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
mod manager;
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
mod pid_resolver;
// L7 protocol parsing (the zero-code APM wedge, GAP 2). Pure userspace parser
// core, exercised by `cargo test` on every platform. Wired into capture/runner in
// the read-side-capture slice, so its API is dead in the non-test build until then.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
#[allow(dead_code, unused_imports)]
mod l7;
// /proc-based connection→port resolution (port-hinted detection). Pure parsing is
// host-tested; the `/proc` read is Linux + ebpf only.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
#[allow(dead_code)]
mod socket_port;
// Authoritative TCP LISTEN snapshot for the caller's network namespace via
// NETLINK_SOCK_DIAG. The binary parser is host-tested; the live query is Linux-only.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
#[allow(dead_code)]
mod sock_diag;
// /proc/<pid>/maps scan for a target's loaded TLS libs (Node static OpenSSL, Java
// Conscrypt/netty-tcnative BoringSSL) — uprobe targets the system libssl misses,
// so we cover native-backed Java + Node TLS zero-config. Pure scan host-tested.
#[cfg(any(test, all(target_os = "linux", feature = "ebpf")))]
#[allow(dead_code)]
mod tls_libs;
// The aya-backed executor and run loop link aya, so they compile only on Linux
// with the feature on (never in the macOS test build).
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod capture;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod runner;

pub use capability::{EbpfCapability, detect};
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub use runner::run;

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Whether this binary was compiled with eBPF program-loading support (the
/// `ebpf` cargo feature, Linux only). Reported to Rails as `ebpf_build_support`
/// so the server can distinguish "host could run eBPF" from "this build can".
pub const BUILD_SUPPORT: bool = cfg!(all(target_os = "linux", feature = "ebpf"));

/// eBPF state surfaced in the agent's stats heartbeat. `capability` is the
/// static host probe; `running`/`last_error` reflect live program state once
/// the capture pillars attach.
#[derive(Debug, Clone, Default)]
pub struct EbpfStatus {
    pub capability: EbpfCapability,
    pub build_support: bool,
    pub running: bool,
    pub last_error: Option<String>,
    /// PIDs seeded into the temporary additive fallback this tick.
    pub pids_targeted: usize,
    /// Workload cgroup anchors in the active kernel allow-set. Together with
    /// `pids_targeted`, this distinguishes healthy capture from an empty scope.
    pub cgroups_targeted: usize,
}

/// Shared, hot-readable eBPF status. The stats reporter reads it each tick.
pub type SharedEbpfStatus = Arc<RwLock<EbpfStatus>>;

/// Create a shared status seeded with this build's `build_support`. Capability
/// is filled by [`probe`].
pub fn shared_status() -> SharedEbpfStatus {
    Arc::new(RwLock::new(EbpfStatus {
        build_support: BUILD_SUPPORT,
        ..Default::default()
    }))
}

/// Probe host capability once and publish it into `status`. Cheap, read-only;
/// call at startup. The capture pillars later update `running`/`last_error`.
pub async fn probe(status: &SharedEbpfStatus) {
    let capability = detect();

    if capability.available {
        info!(
            kernel = capability.kernel_version.as_deref().unwrap_or("unknown"),
            cgroup_v2 = capability.has_cgroup_v2,
            cap_perfmon = capability.has_cap_perfmon,
            lockdown = capability.lockdown.as_deref().unwrap_or("none"),
            build_support = BUILD_SUPPORT,
            "eBPF capability available"
        );
    } else if BUILD_SUPPORT {
        // Built with eBPF support but the host doesn't grant it (no CAP_BPF,
        // older kernel, …) — actionable, so warn. Reported up to Rails.
        warn!(
            reason = capability.failure_reason.as_deref().unwrap_or("unknown"),
            kernel = capability.kernel_version.as_deref().unwrap_or("unknown"),
            "eBPF capability unavailable"
        );
    } else {
        // This build can't run eBPF at all (non-Linux, or built without the
        // `ebpf` feature). Expected by design — don't warn on every start.
        debug!(
            reason = capability.failure_reason.as_deref().unwrap_or("unknown"),
            "eBPF not supported by this build; skipping"
        );
    }

    let mut guard = status.write().await;
    guard.capability = capability;
    guard.build_support = BUILD_SUPPORT;
}
