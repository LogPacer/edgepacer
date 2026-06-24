use clap::Parser;

use crate::token_store;

/// CLI arguments - mirrors legacy EdgePacer's cobra flags.
#[derive(Parser, Debug, Clone)]
#[command(name = "edgepacer", version, about = "LogPacer edge agent")]
pub struct Cli {
    /// Resource identifier (agent_key from Rails, not required in --local-mode)
    #[arg(short = 'r', long, env = "EDGEPACER_RESOURCE_ID", default_value = "")]
    pub resource: String,

    /// Rails control-plane URL (not required in --local-mode)
    #[arg(long, env = "EDGEPACER_RAILS_URL", default_value = "")]
    pub rails: String,

    /// Server bootstrap token (normal operation, persisted between runs)
    #[arg(long, env = "EDGEPACER_SERVER_TOKEN")]
    pub server_token: Option<String>,

    /// Account bootstrap token (first-time setup only)
    #[arg(long, env = "EDGEPACER_ACCOUNT_TOKEN")]
    pub account_token: Option<String>,

    /// Config poll interval in seconds
    #[arg(long, default_value = "30", env = "EDGEPACER_POLL_INTERVAL")]
    pub poll_interval: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "EDGEPACER_LOG_LEVEL")]
    pub log_level: String,

    /// Readiness file path (set by manager for health checks)
    #[arg(long, env = "EDGEPACER_READINESS_FILE", hide = true)]
    pub readiness_file: Option<String>,

    /// Run without Rails - load config from a local JSON file and skip authentication.
    /// Used for profiling and isolated testing.
    #[arg(long)]
    pub local_mode: bool,

    /// Path to unified config JSON file (required when --local-mode is set)
    #[arg(long)]
    pub directive_file: Option<std::path::PathBuf>,

    // Legacy flags passed unconditionally by manager <= 0.1.x. Accepted and
    // ignored so a new agent can start under an old manager — agent
    // auto-updates roll independently of the manager binary, so rejecting
    // these turns every update under an old manager into a crash loop.
    #[arg(long, hide = true)]
    pub host_mode: bool,
    #[arg(long, hide = true)]
    pub log_format: Option<String>,
    #[arg(long, hide = true)]
    pub debug: bool,
}

/// Application config derived from CLI args + environment.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub resource_id: String,
    pub rails_url: String,
    pub token: Option<String>,
    pub is_account_token: bool,
    pub poll_interval_secs: u64,
    pub log_level: String,
    pub readiness_file: Option<String>,
    pub local_mode: bool,
    pub directive_file: Option<std::path::PathBuf>,
}

impl AppConfig {
    fn try_from_with_loader<F>(cli: Cli, load_token: F) -> anyhow::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let (token, is_account_token) = resolve_bootstrap_token(&cli, load_token)?;
        if !cli.local_mode {
            crate::common::validate_control_plane_url(&cli.rails)?;
        }

        Ok(Self {
            resource_id: cli.resource,
            rails_url: cli.rails,
            token,
            is_account_token,
            poll_interval_secs: cli.poll_interval,
            log_level: cli.log_level,
            readiness_file: cli.readiness_file,
            local_mode: cli.local_mode,
            directive_file: cli.directive_file,
        })
    }
}

impl TryFrom<Cli> for AppConfig {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        Self::try_from_with_loader(cli, token_store::load_token)
    }
}

fn resolve_bootstrap_token<F>(cli: &Cli, load_token: F) -> anyhow::Result<(Option<String>, bool)>
where
    F: Fn(&str) -> Option<String>,
{
    if cli.account_token.is_some() && cli.server_token.is_some() {
        anyhow::bail!(
            "cannot set both account and server bootstrap tokens; use only one of EDGEPACER_ACCOUNT_TOKEN or EDGEPACER_SERVER_TOKEN"
        );
    }

    if let Some(token) = cli.account_token.clone() {
        return Ok((Some(token), true));
    }

    if let Some(token) = cli.server_token.clone() {
        return Ok((Some(token), false));
    }

    if cli.local_mode {
        return Ok((None, false));
    }

    if let Some(token) = load_token("server_bootstrap_token") {
        return Ok((Some(token), false));
    }

    anyhow::bail!(
        "no bootstrap token available; set EDGEPACER_ACCOUNT_TOKEN or EDGEPACER_SERVER_TOKEN, or persist server_bootstrap_token to disk"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cli() -> Cli {
        Cli {
            resource: "agent-123".into(),
            rails: "https://rails.example".into(),
            server_token: None,
            account_token: None,
            poll_interval: 30,
            log_level: "info".into(),
            readiness_file: None,
            local_mode: false,
            directive_file: None,
            host_mode: false,
            log_format: None,
            debug: false,
        }
    }

    #[test]
    fn accepts_legacy_manager_flags() {
        // Manager <= 0.1.x spawns the agent with exactly these args; they
        // must parse (and stay no-ops) or the agent dies before startup.
        let cli = Cli::try_parse_from([
            "edgepacer",
            "--host-mode",
            "--log-format",
            "json",
            "--debug",
        ])
        .expect("legacy manager invocation must keep parsing");

        assert!(!cli.local_mode, "legacy flags must not imply local mode");
    }

    #[test]
    fn prefers_account_token_and_marks_config() {
        let mut cli = base_cli();
        cli.account_token = Some("account-token".into());

        let config = AppConfig::try_from_with_loader(cli, |_| None).unwrap();

        assert_eq!(config.token.as_deref(), Some("account-token"));
        assert!(config.is_account_token);
    }

    #[test]
    fn uses_server_token_when_present() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token".into());

        let config = AppConfig::try_from_with_loader(cli, |_| None).unwrap();

        assert_eq!(config.token.as_deref(), Some("server-token"));
        assert!(!config.is_account_token);
    }

    #[test]
    fn rejects_both_account_and_server_tokens() {
        let mut cli = base_cli();
        cli.account_token = Some("account-token".into());
        cli.server_token = Some("server-token".into());

        let err = AppConfig::try_from_with_loader(cli, |_| None).unwrap_err();

        assert!(err.to_string().contains("cannot set both"));
    }

    #[test]
    fn falls_back_to_persisted_server_bootstrap_token() {
        let cli = base_cli();

        let config = AppConfig::try_from_with_loader(cli, |name| {
            (name == "server_bootstrap_token").then(|| "persisted-server-token".into())
        })
        .unwrap();

        assert_eq!(config.token.as_deref(), Some("persisted-server-token"));
        assert!(!config.is_account_token);
    }

    #[test]
    fn allows_missing_token_in_local_mode() {
        let mut cli = base_cli();
        cli.local_mode = true;

        let config = AppConfig::try_from_with_loader(cli, |_| None).unwrap();

        assert!(config.token.is_none());
    }

    #[test]
    fn accepts_loopback_http_control_plane_url() {
        let mut cli = base_cli();
        cli.rails = "http://localhost:3000".into();
        cli.server_token = Some("server-token".into());

        let config = AppConfig::try_from_with_loader(cli, |_| None).unwrap();

        assert_eq!(config.rails_url, "http://localhost:3000");
    }

    #[test]
    fn rejects_remote_http_control_plane_url() {
        let mut cli = base_cli();
        cli.rails = "http://app.logpacer.com".into();
        cli.server_token = Some("server-token".into());

        let err = AppConfig::try_from_with_loader(cli, |_| None).unwrap_err();

        assert!(err.to_string().contains("must use HTTPS"));
    }

    #[test]
    fn errors_when_no_token_source_exists() {
        let cli = base_cli();

        let err = AppConfig::try_from_with_loader(cli, |_| None).unwrap_err();

        assert!(err.to_string().contains("bootstrap token"));
    }
}
