use clap::Parser;

use crate::token_store;

/// CLI arguments - mirrors legacy EdgePacer's cobra flags.
#[derive(Parser, Debug, Clone)]
#[command(name = "edgepacer", version = crate::common::VERSION, about = "LogPacer edge agent")]
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
    // treated as host-mode so a new agent can start under an old manager —
    // agent auto-updates roll independently of the manager binary, so rejecting
    // this turns every update under an old manager into a crash loop. Use
    // EDGEPACER_HOST_MODE=false for sidecar/service-mode containers.
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
    pub host_mode: bool,
}

impl AppConfig {
    fn try_from_with_loader<F>(cli: Cli, load_token: F) -> anyhow::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        Self::try_from_with_loader_and_host_mode_env(
            cli,
            load_token,
            std::env::var("EDGEPACER_HOST_MODE").ok(),
        )
    }

    fn try_from_with_loader_and_host_mode_env<F>(
        cli: Cli,
        load_token: F,
        host_mode_env: Option<String>,
    ) -> anyhow::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let (token, is_account_token) = resolve_bootstrap_token(&cli, load_token)?;
        let host_mode = resolve_host_mode(host_mode_env.as_deref())?;
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
            host_mode,
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

    if let Some(token) = normalize_configured_token(cli.account_token.as_deref(), "account")? {
        return Ok((Some(token), true));
    }

    if let Some(token) = normalize_configured_token(cli.server_token.as_deref(), "server")? {
        return Ok((Some(token), false));
    }

    if cli.local_mode {
        return Ok((None, false));
    }

    if let Some(token) =
        load_token("server_bootstrap_token").and_then(|token| normalize_stored_token(&token))
    {
        return Ok((Some(token), false));
    }

    anyhow::bail!(
        "no bootstrap token available; set EDGEPACER_ACCOUNT_TOKEN or EDGEPACER_SERVER_TOKEN, or persist server_bootstrap_token to disk"
    )
}

fn normalize_configured_token(token: Option<&str>, source: &str) -> anyhow::Result<Option<String>> {
    let Some(token) = token else {
        return Ok(None);
    };

    normalize_stored_token(token)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{source} bootstrap token cannot be empty"))
}

fn normalize_stored_token(token: &str) -> Option<String> {
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

fn resolve_host_mode(host_mode_env: Option<&str>) -> anyhow::Result<bool> {
    if let Some(value) = host_mode_env.and_then(non_empty_str) {
        return parse_host_mode(value);
    }

    Ok(true)
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn parse_host_mode(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("EDGEPACER_HOST_MODE must be true/false, 1/0, yes/no, or on/off"),
    }
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

    fn config_with_host_mode_env(
        cli: Cli,
        host_mode_env: Option<&str>,
    ) -> anyhow::Result<AppConfig> {
        AppConfig::try_from_with_loader_and_host_mode_env(
            cli,
            |_| None,
            host_mode_env.map(str::to_string),
        )
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
        assert!(config.host_mode);
    }

    #[test]
    fn trims_account_token_secret_file_newline() {
        let mut cli = base_cli();
        cli.account_token = Some("account-token\n".into());

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
    fn host_mode_defaults_to_true() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token".into());

        let config = config_with_host_mode_env(cli, None).unwrap();

        assert!(config.host_mode);
    }

    #[test]
    fn host_mode_can_be_disabled_by_environment() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token".into());

        let config = config_with_host_mode_env(cli, Some("false")).unwrap();

        assert!(!config.host_mode);
    }

    #[test]
    fn host_mode_environment_overrides_legacy_flag() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token".into());
        cli.host_mode = true;

        let config = config_with_host_mode_env(cli, Some("0")).unwrap();

        assert!(!config.host_mode);
    }

    #[test]
    fn host_mode_rejects_invalid_environment_value() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token".into());

        let err = config_with_host_mode_env(cli, Some("sometimes")).unwrap_err();

        assert!(err.to_string().contains("EDGEPACER_HOST_MODE"));
    }

    #[test]
    fn trims_server_token_secret_file_newline() {
        let mut cli = base_cli();
        cli.server_token = Some("server-token\n".into());

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
    fn rejects_blank_configured_token() {
        let mut cli = base_cli();
        cli.account_token = Some(" \n".into());

        let err = AppConfig::try_from_with_loader(cli, |_| None).unwrap_err();

        assert!(err.to_string().contains("cannot be empty"));
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
    fn trims_persisted_server_bootstrap_token() {
        let cli = base_cli();

        let config = AppConfig::try_from_with_loader(cli, |name| {
            (name == "server_bootstrap_token").then(|| "persisted-server-token\n".into())
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
