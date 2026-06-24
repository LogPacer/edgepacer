//! eBPF capability detection.
//!
//! Mirrors legacy EdgePacer's `internal/ebpf/capability_linux.go`: the host can run
//! eBPF when the kernel is >= 5.8 (BTF/CO-RE and CAP_BPF both landed in 5.8),
//! `/sys/kernel/btf/vmlinux` exists, and the process holds CAP_BPF (or is root).
//!
//! This is EdgePacer's own gate, which is correct for read-only capture. OBI's
//! stricter `SupportsLogInjection` gate (kernel >= 6, CAP_SYS_ADMIN, lockdown
//! None/Integrity) guards log *injection* (`bpf_probe_write_user`), which this
//! agent does not do — so we do not adopt it wholesale. We add only the kernel
//! lockdown check, because `confidentiality` mode blocks `bpf_probe_read` and so
//! stops even read-only capture. CAP_PERFMON is probed and reported for a future
//! de-privileged deployment (it gates perf-event attach) but does not gate
//! availability today, since production runs as root.

/// Minimum kernel for the BTF/CO-RE + CAP_BPF path. Referenced by the Linux
/// probe and the cross-platform unit tests.
#[cfg(any(target_os = "linux", test))]
pub const MIN_KERNEL_MAJOR: u32 = 5;
#[cfg(any(target_os = "linux", test))]
pub const MIN_KERNEL_MINOR: u32 = 8;

/// Result of probing the host for eBPF support. Mirrors Go's `ebpf.Capability`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EbpfCapability {
    pub available: bool,
    pub kernel_version: Option<String>,
    pub has_btf: bool,
    pub has_cap_bpf: bool,
    /// CAP_PERFMON: needed to attach kprobes/tracepoints when de-privileged.
    /// Informational today (production runs as root); does not gate `available`.
    pub has_cap_perfmon: bool,
    /// Active kernel lockdown mode (`none`/`integrity`/`confidentiality`), or
    /// `None` when lockdown is not configured. `confidentiality` blocks capture.
    pub lockdown: Option<String>,
    pub failure_reason: Option<String>,
}

/// Probe the host. On non-Linux this is always unavailable (matches the Go stub).
pub fn detect() -> EbpfCapability {
    #[cfg(target_os = "linux")]
    {
        detect_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        EbpfCapability {
            available: false,
            failure_reason: Some("eBPF only available on Linux".to_string()),
            ..Default::default()
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_linux() -> EbpfCapability {
    use std::fs;

    let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string());
    let kernel_ok = kernel_version
        .as_deref()
        .map(kernel_meets_minimum)
        .unwrap_or(false);
    let has_btf = fs::metadata("/sys/kernel/btf/vmlinux").is_ok();
    let has_cap_bpf = has_effective_capability(CAP_BPF);
    let has_cap_perfmon = has_effective_capability(CAP_PERFMON);

    // An absent lockdown file means lockdown is not enabled → capture allowed.
    let lockdown = fs::read_to_string("/sys/kernel/security/lockdown")
        .ok()
        .and_then(|s| parse_lockdown_mode(&s));
    let lockdown_ok = lockdown
        .as_deref()
        .map(|mode| !lockdown_blocks_capture(mode))
        .unwrap_or(true);

    // First unmet precondition becomes the reason, so the stats report explains
    // exactly why eBPF is unavailable on a given host.
    let failure_reason = if !kernel_ok {
        Some(format!(
            "kernel {} below minimum {}.{}",
            kernel_version.as_deref().unwrap_or("unknown"),
            MIN_KERNEL_MAJOR,
            MIN_KERNEL_MINOR
        ))
    } else if !has_btf {
        Some("BTF not available (/sys/kernel/btf/vmlinux missing)".to_string())
    } else if !has_cap_bpf {
        Some("CAP_BPF not held (run with CAP_BPF or as root)".to_string())
    } else if !lockdown_ok {
        Some(format!(
            "kernel lockdown={} blocks bpf_probe_read",
            lockdown.as_deref().unwrap_or("confidentiality")
        ))
    } else {
        None
    };

    EbpfCapability {
        available: kernel_ok && has_btf && has_cap_bpf && lockdown_ok,
        kernel_version,
        has_btf,
        has_cap_bpf,
        has_cap_perfmon,
        lockdown,
        failure_reason,
    }
}

/// `true` if the uname release string is >= MIN_KERNEL_MAJOR.MIN_KERNEL_MINOR.
/// Compiled in tests on every platform and in the real probe on Linux.
#[cfg(any(target_os = "linux", test))]
fn kernel_meets_minimum(release: &str) -> bool {
    match parse_major_minor(release) {
        Some((major, minor)) => {
            major > MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR)
        }
        None => false,
    }
}

/// Parse `major.minor` from a uname release like `6.8.0-107-generic`.
#[cfg(any(target_os = "linux", test))]
fn parse_major_minor(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Active kernel lockdown mode from `/sys/kernel/security/lockdown`, whose
/// content lists the modes with the active one bracketed, e.g.
/// `[none] integrity confidentiality`. Returns the active mode lowercased, or
/// `None` when there is no bracketed token.
#[cfg(any(target_os = "linux", test))]
fn parse_lockdown_mode(content: &str) -> Option<String> {
    let open = content.find('[')?;
    let close = content[open + 1..].find(']')? + open + 1;
    Some(content[open + 1..close].trim().to_lowercase())
}

/// `confidentiality` lockdown blocks `bpf_probe_read` (and most of BPF), so even
/// read-only capture cannot run. `integrity` only blocks write-back
/// (`bpf_probe_write_user`), which capture does not use, so it is allowed.
#[cfg(any(target_os = "linux", test))]
fn lockdown_blocks_capture(mode: &str) -> bool {
    mode == "confidentiality"
}

/// CAP_BPF (39) gates program load; CAP_PERFMON (38) gates perf-event attach
/// (kprobes/tracepoints) when de-privileged.
#[cfg(target_os = "linux")]
const CAP_BPF: u32 = 39;
#[cfg(target_os = "linux")]
const CAP_PERFMON: u32 = 38;

/// `true` if `cap` is in the process's effective set, or the process is root.
///
/// Direct port of Go's `checkBPFCapability`, generalized to any capability:
/// euid==0 short-circuit, else `capget(LINUX_CAPABILITY_VERSION_3)` and test the
/// bit in the matching 32-bit effective word. Uses the already-present `libc`.
#[cfg(target_os = "linux")]
fn has_effective_capability(cap: u32) -> bool {
    // SAFETY: geteuid is always safe; it has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 = the calling process
    };
    // Version 3 returns two 32-bit words (caps 0-31 and 32-63).
    let mut data = [CapData::default(); 2];

    // SAFETY: header is a valid initialized struct; data has room for the two
    // words the v3 ABI writes. capget does not retain the pointers.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &header as *const CapHeader,
            data.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return false;
    }

    let word = (cap / 32) as usize;
    let bit = cap % 32;
    data.get(word)
        .is_some_and(|w| (w.effective & (1u32 << bit)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_release_strings() {
        assert_eq!(parse_major_minor("6.8.0-107-generic"), Some((6, 8)));
        assert_eq!(parse_major_minor("5.8.0"), Some((5, 8)));
        assert_eq!(parse_major_minor("5.15.0-91-generic"), Some((5, 15)));
        assert_eq!(parse_major_minor("4.19.0"), Some((4, 19)));
    }

    #[test]
    fn rejects_unparseable_release_strings() {
        assert_eq!(parse_major_minor(""), None);
        assert_eq!(parse_major_minor("garbage"), None);
        assert_eq!(parse_major_minor("6"), None);
    }

    #[test]
    fn kernel_floor_is_5_8() {
        assert!(kernel_meets_minimum("6.8.0-107-generic"));
        assert!(kernel_meets_minimum("5.8.0"));
        assert!(kernel_meets_minimum("5.15.0-91-generic"));
        assert!(kernel_meets_minimum("7.0.0"));
        assert!(!kernel_meets_minimum("5.7.0"));
        assert!(!kernel_meets_minimum("5.4.0-generic"));
        assert!(!kernel_meets_minimum("4.19.0"));
        assert!(!kernel_meets_minimum("not-a-version"));
    }

    #[test]
    fn parses_active_lockdown_mode() {
        assert_eq!(
            parse_lockdown_mode("[none] integrity confidentiality\n").as_deref(),
            Some("none")
        );
        assert_eq!(
            parse_lockdown_mode("none [integrity] confidentiality").as_deref(),
            Some("integrity")
        );
        assert_eq!(
            parse_lockdown_mode("none integrity [confidentiality]").as_deref(),
            Some("confidentiality")
        );
    }

    #[test]
    fn rejects_lockdown_without_active_marker() {
        assert_eq!(parse_lockdown_mode(""), None);
        assert_eq!(parse_lockdown_mode("none integrity confidentiality"), None);
        assert_eq!(parse_lockdown_mode("no brackets here"), None);
    }

    #[test]
    fn only_confidentiality_lockdown_blocks_capture() {
        assert!(lockdown_blocks_capture("confidentiality"));
        assert!(!lockdown_blocks_capture("none"));
        assert!(!lockdown_blocks_capture("integrity"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unavailable_off_linux() {
        let cap = detect();
        assert!(!cap.available);
        assert_eq!(
            cap.failure_reason.as_deref(),
            Some("eBPF only available on Linux")
        );
    }
}
