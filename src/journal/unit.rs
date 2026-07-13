//! Heuristics for systemd unit identifiers on the agent wire.

/// The systemd unit-type suffixes. A name ending in one of these already names
/// its type; a name without one defaults to `.service` (see `canonical_unit`).
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

/// Heuristic: identifier is a systemd unit when it has a known unit suffix
/// and no path separators. Mirrors the agent's discovery taxonomy
/// (loggable_type=systemd_service in Rails).
pub fn is_systemd_unit(identifier: &str) -> bool {
    if identifier.contains('/') {
        return false;
    }

    UNIT_SUFFIXES.iter().any(|sfx| identifier.ends_with(sfx))
}

/// Resolve a unit name to the form both backends must query.
///
/// systemd treats a unit name with no recognized type suffix as a `.service`.
/// Applied once at dispatch so the sdjournal backend's exact `_SYSTEMD_UNIT`
/// match and `journalctl -u` resolve the same unit: `journalctl` auto-appends
/// `.service` to a bare name, but sdjournal's exact match does not, so a bare
/// name would otherwise return data on the fallback and nothing on native.
pub fn canonical_unit(unit: &str) -> String {
    if UNIT_SUFFIXES.iter().any(|sfx| unit.ends_with(sfx)) {
        unit.to_string()
    } else {
        format!("{unit}.service")
    }
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

    #[test]
    fn canonical_unit_defaults_bare_name_to_service() {
        // A bare name gains `.service`, matching journalctl's auto-suffix so the
        // native exact `_SYSTEMD_UNIT` match sees the same effective unit.
        assert_eq!(canonical_unit("nginx"), "nginx.service");
        assert_eq!(canonical_unit("foo@bar"), "foo@bar.service");
    }

    #[test]
    fn canonical_unit_preserves_explicit_type() {
        for unit in [
            "nginx.service",
            "logrelay.socket",
            "backup.timer",
            "multi-user.target",
        ] {
            assert_eq!(canonical_unit(unit), unit);
        }
    }
}
