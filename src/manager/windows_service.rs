//! Windows Service registration and control helpers for `edgepacer-manager`.

use std::ffi::OsStr;
use std::path::PathBuf;

use tokio::process::Command;

pub const DEFAULT_SERVICE_NAME: &str = "EdgePacerManager";
pub const DEFAULT_DISPLAY_NAME: &str = "EdgePacer Manager";

#[derive(Debug, Clone)]
pub struct InstallConfig {
    pub service_name: String,
    pub display_name: String,
    pub manager_path: PathBuf,
    pub edgepacer_path: PathBuf,
    pub rails_url: String,
    pub account_token: String,
    pub platform: String,
    pub check_interval: u64,
    pub health_timeout: u64,
    pub update_public_key: Option<String>,
    pub debug: bool,
    pub force_update: bool,
}

pub async fn install_service(config: &InstallConfig) -> anyhow::Result<String> {
    ensure_windows()?;
    run_sc(&install_args(config)).await
}

pub async fn uninstall_service(service_name: &str) -> anyhow::Result<String> {
    ensure_windows()?;
    run_sc(&["delete".to_string(), service_name.to_string()]).await
}

pub async fn start_service(service_name: &str) -> anyhow::Result<String> {
    ensure_windows()?;
    run_sc(&["start".to_string(), service_name.to_string()]).await
}

pub async fn stop_service(service_name: &str) -> anyhow::Result<String> {
    ensure_windows()?;
    run_sc(&["stop".to_string(), service_name.to_string()]).await
}

pub async fn status_service(service_name: &str) -> anyhow::Result<String> {
    ensure_windows()?;
    run_sc(&["queryex".to_string(), service_name.to_string()]).await
}

fn ensure_windows() -> anyhow::Result<()> {
    if std::env::consts::OS == "windows" {
        Ok(())
    } else {
        anyhow::bail!("Windows service control is only supported on Windows")
    }
}

pub(crate) fn install_args(config: &InstallConfig) -> Vec<String> {
    vec![
        "create".to_string(),
        config.service_name.clone(),
        "binPath=".to_string(),
        service_command_line(config),
        "DisplayName=".to_string(),
        config.display_name.clone(),
        "start=".to_string(),
        "auto".to_string(),
    ]
}

fn service_command_line(config: &InstallConfig) -> String {
    let mut parts = vec![quote_windows_arg(config.manager_path.as_os_str())];
    parts.extend(
        run_args(config)
            .into_iter()
            .map(|arg| quote_windows_arg(OsStr::new(&arg))),
    );
    parts.join(" ")
}

fn run_args(config: &InstallConfig) -> Vec<String> {
    let mut args = vec![
        "--edgepacer".to_string(),
        config.edgepacer_path.to_string_lossy().into_owned(),
        "--rails".to_string(),
        config.rails_url.clone(),
        "--account-token".to_string(),
        config.account_token.clone(),
        "--platform".to_string(),
        config.platform.clone(),
        "--check-interval".to_string(),
        config.check_interval.to_string(),
        "--health-timeout".to_string(),
        config.health_timeout.to_string(),
    ];

    if let Some(update_public_key) = &config.update_public_key {
        args.extend([
            "--update-public-key".to_string(),
            update_public_key.to_string(),
        ]);
    }
    if config.debug {
        args.push("--debug".to_string());
    }
    if config.force_update {
        args.push("--force-update".to_string());
    }

    args
}

fn quote_windows_arg(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\\'))
    {
        return value.into_owned();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

async fn run_sc(args: &[String]) -> anyhow::Result<String> {
    let output = Command::new("sc").args(args).output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        let detail = if stderr.is_empty() { stdout } else { stderr };
        anyhow::bail!("{}", format_sc_failure(args, &detail));
    }

    Ok(if stderr.is_empty() {
        stdout
    } else if stdout.is_empty() {
        stderr
    } else {
        format!("{stdout}\n{stderr}")
    })
}

fn format_sc_failure(args: &[String], detail: &str) -> String {
    format!("sc {} failed: {detail}", redact_sc_args(args).join(" "))
}

fn redact_sc_args(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| redact_following_arg(arg, "--account-token"))
        .collect()
}

fn redact_following_arg(text: &str, flag: &str) -> String {
    let Some(flag_start) = text.find(flag) else {
        return text.to_string();
    };

    let after_flag = flag_start + flag.len();
    let Some(relative_value_start) = text[after_flag..].find(|ch: char| !ch.is_whitespace()) else {
        return text.to_string();
    };
    let value_start = after_flag + relative_value_start;
    let value_end = command_line_arg_end(text, value_start);

    format!("{}<redacted>{}", &text[..value_start], &text[value_end..])
}

fn command_line_arg_end(text: &str, start: usize) -> usize {
    let Some(first) = text[start..].chars().next() else {
        return start;
    };

    if first != '"' {
        return text[start..]
            .char_indices()
            .find_map(|(index, ch)| ch.is_whitespace().then_some(start + index))
            .unwrap_or(text.len());
    }

    let mut backslashes = 0usize;
    for (relative_index, ch) in text[start + 1..].char_indices() {
        match ch {
            '\\' => backslashes += 1,
            '"' if backslashes.is_multiple_of(2) => return start + 1 + relative_index + 1,
            _ => backslashes = 0,
        }
    }

    text.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> InstallConfig {
        InstallConfig {
            service_name: DEFAULT_SERVICE_NAME.into(),
            display_name: DEFAULT_DISPLAY_NAME.into(),
            manager_path: PathBuf::from(r"C:\Program Files\EdgePacer\edgepacer-manager.exe"),
            edgepacer_path: PathBuf::from(r"C:\Program Files\EdgePacer\edgepacer.exe"),
            rails_url: "https://logpacer.test".into(),
            account_token: "account-token".into(),
            platform: "windows-amd64".into(),
            check_interval: 30,
            health_timeout: 60,
            update_public_key: Some("abc123".into()),
            debug: true,
            force_update: false,
        }
    }

    #[test]
    fn install_args_build_sc_create_command() {
        let args = install_args(&config());

        assert_eq!(args[0], "create");
        assert_eq!(args[1], DEFAULT_SERVICE_NAME);
        assert_eq!(args[2], "binPath=");
        assert!(args[3].contains("--edgepacer"));
        assert!(args[3].contains("--rails https://logpacer.test"));
        assert!(args[3].contains("--platform windows-amd64"));
        assert!(args[3].contains("--update-public-key abc123"));
        assert!(args[3].contains("--debug"));
        assert_eq!(args[4], "DisplayName=");
        assert_eq!(args[5], DEFAULT_DISPLAY_NAME);
        assert_eq!(args[6], "start=");
        assert_eq!(args[7], "auto");
    }

    #[test]
    fn service_command_line_quotes_paths_with_spaces() {
        let command_line = service_command_line(&config());

        assert!(command_line.starts_with(
            r#""C:\Program Files\EdgePacer\edgepacer-manager.exe" --edgepacer "C:\Program Files\EdgePacer\edgepacer.exe""#
        ));
    }

    #[test]
    fn quote_windows_arg_escapes_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_arg(OsStr::new("plain")), "plain");
        assert_eq!(
            quote_windows_arg(OsStr::new(r#"C:\Program Files\App\"#)),
            r#""C:\Program Files\App\\""#
        );
        assert_eq!(
            quote_windows_arg(OsStr::new(r#"a "quoted" arg"#)),
            r#""a \"quoted\" arg""#
        );
    }

    #[test]
    fn sc_failure_message_redacts_account_token() {
        let mut config = config();
        config.account_token = "secret-bootstrap-token".into();
        let args = install_args(&config);

        let message = format_sc_failure(&args, "Access is denied.");

        assert!(message.contains("--account-token <redacted>"));
        assert!(!message.contains("secret-bootstrap-token"));
        assert!(message.contains("sc create EdgePacerManager"));
        assert!(message.contains("Access is denied."));
    }
}
