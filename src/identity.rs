//! The agent's stable wire identity (`resource_identifier`).
//!
//! logpacer owns the identifier — `server.name`, pinned from the first reported
//! hostname and admin-renameable — and delivers it as a **top-level**
//! `resource_identifier` in unified_config (see
//! [`crate::config::UnifiedConfig::resource_identifier`]; logpacer must fold it
//! into the top-level config etag or a rename won't propagate). The agent reports
//! facts up (hostname at bootstrap) but never derives identity itself; it echoes
//! whatever Rails returns. Held in a shared cell so a re-pin takes effect on the
//! next shipped batch without restarting pipelines, and persisted so a restart
//! before the first config poll keeps the last-known value.

use std::sync::{Arc, RwLock};

use tracing::warn;

/// Filename (under the token-store dir) holding the last-known identifier, so a
/// restart before the first config poll still ships with the right value.
const IDENTITY_FILE: &str = "resource_identifier";

/// Where the seeded identity came from — drives a one-time warn when logpacer
/// hasn't supplied one yet, and lets the precedence be unit-tested.
#[derive(Debug, PartialEq, Eq)]
enum IdentitySource {
    Config,
    Persisted,
    CliOverride,
    Hostname,
}

/// Resolve the startup identity. Precedence: live config value > last persisted
/// value > `-r` override > hostname. Pure, so the precedence is testable.
fn choose<'a>(
    config_value: Option<&'a str>,
    persisted: Option<&'a str>,
    cli_resource: &'a str,
    hostname: &'a str,
) -> (&'a str, IdentitySource) {
    if let Some(value) = config_value.filter(|v| !v.is_empty()) {
        (value, IdentitySource::Config)
    } else if let Some(value) = persisted.filter(|v| !v.is_empty()) {
        (value, IdentitySource::Persisted)
    } else if !cli_resource.is_empty() {
        (cli_resource, IdentitySource::CliOverride)
    } else {
        (hostname, IdentitySource::Hostname)
    }
}

/// Shared, hot-reloadable agent identity. Cheap to clone (`Arc`); the stamping
/// ship path reads it once per batch.
#[derive(Clone)]
pub struct AgentIdentity {
    inner: Arc<RwLock<String>>,
}

impl AgentIdentity {
    pub fn new(initial: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Seed the identity at startup and persist the choice so the next start has
    /// it before the first poll. Falling through to `-r` or hostname means
    /// logpacer hasn't sent a `resource_identifier` yet (old Rails, or a fresh
    /// install mid-rollout) — the agent ships with a usable identity rather than
    /// an empty one, and the first poll carrying the field replaces it via
    /// [`apply_config`](Self::apply_config).
    pub fn seed(config_value: Option<&str>, cli_resource: &str, hostname: &str) -> Self {
        let persisted = crate::token_store::load_token(IDENTITY_FILE);
        let (chosen, source) = choose(config_value, persisted.as_deref(), cli_resource, hostname);
        match source {
            IdentitySource::CliOverride => {
                warn!("no resource_identifier from logpacer yet; using -r override as identity")
            }
            IdentitySource::Hostname => warn!(
                %hostname,
                "no resource_identifier from logpacer or -r; falling back to hostname as identity"
            ),
            IdentitySource::Config | IdentitySource::Persisted => {}
        }

        let chosen = chosen.to_string();
        if let Err(e) = crate::token_store::persist_token(IDENTITY_FILE, &chosen) {
            warn!(error = %e, "failed to persist resource_identifier");
        }
        Self::new(chosen)
    }

    /// Current identifier. Clones the short string; called once per shipped batch
    /// on the stamping path.
    pub fn current(&self) -> String {
        self.inner.read().expect("identity lock poisoned").clone()
    }

    /// Replace the value if it changed; returns whether it changed. Pure — no
    /// persistence — so it is cheap and side-effect-free on the steady-state poll.
    fn set(&self, value: &str) -> bool {
        let mut guard = self.inner.write().expect("identity lock poisoned");
        if *guard != value {
            *guard = value.to_string();
            true
        } else {
            false
        }
    }

    /// Apply a config-delivered identifier, persisting only on change. A no-op
    /// when the value is empty or unchanged, so the steady-state poll costs
    /// nothing. Never restarts pipelines — shippers read the cell live at ship
    /// time — so a re-pin propagates without bouncing streams.
    pub fn apply_config(&self, value: &str) {
        if value.is_empty() || !self.set(value) {
            return;
        }
        if let Err(e) = crate::token_store::persist_token(IDENTITY_FILE, value) {
            warn!(error = %e, "failed to persist updated resource_identifier");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_value_wins_over_everything() {
        let (chosen, source) = choose(Some("cfg"), Some("persisted"), "cli", "host");
        assert_eq!(chosen, "cfg");
        assert_eq!(source, IdentitySource::Config);
    }

    #[test]
    fn persisted_wins_when_config_absent_or_empty() {
        let (chosen, source) = choose(None, Some("persisted"), "cli", "host");
        assert_eq!((chosen, source), ("persisted", IdentitySource::Persisted));
        // An empty config value is treated as absent.
        let (chosen, source) = choose(Some(""), Some("persisted"), "cli", "host");
        assert_eq!((chosen, source), ("persisted", IdentitySource::Persisted));
    }

    #[test]
    fn falls_back_to_cli_then_hostname() {
        let (chosen, source) = choose(None, None, "cli", "host");
        assert_eq!((chosen, source), ("cli", IdentitySource::CliOverride));

        let (chosen, source) = choose(None, None, "", "host");
        assert_eq!((chosen, source), ("host", IdentitySource::Hostname));
    }

    #[test]
    fn set_reports_change_and_current_reflects_it() {
        let id = AgentIdentity::new("a".into());
        assert_eq!(id.current(), "a");
        assert!(id.set("b"), "changing the value reports a change");
        assert_eq!(id.current(), "b");
        assert!(!id.set("b"), "re-setting the same value is not a change");
    }

    #[test]
    fn apply_config_ignores_empty() {
        let id = AgentIdentity::new("keep".into());
        id.apply_config("");
        assert_eq!(id.current(), "keep");
    }
}
