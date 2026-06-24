//! Heuristics for systemd unit identifiers on the agent wire.

/// Heuristic: identifier is a systemd unit when it has a known unit suffix
/// and no path separators. Mirrors the agent's discovery taxonomy
/// (loggable_type=systemd_service in Rails).
pub fn is_systemd_unit(identifier: &str) -> bool {
    const UNIT_SUFFIXES: &[&str] = &[
        ".service",
        ".socket",
        ".timer",
        ".target",
        ".mount",
        ".automount",
        ".path",
        ".slice",
        ".scope",
    ];

    if identifier.contains('/') {
        return false;
    }

    UNIT_SUFFIXES.iter().any(|sfx| identifier.ends_with(sfx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_detection() {
        assert!(is_systemd_unit("pacer_proxy.service"));
        assert!(is_systemd_unit("logrelay.socket"));
        assert!(is_systemd_unit("backup.timer"));
        assert!(is_systemd_unit("multi-user.target"));

        assert!(!is_systemd_unit("/var/log/pacer_proxy.service"));
        assert!(!is_systemd_unit("/var/log/auth.log"));
        assert!(!is_systemd_unit("auth.log"));
    }
}
