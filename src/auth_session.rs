//! Agent authentication and token refresh lifecycle.

use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::common::EdgepacerError;
use crate::config::AppConfig;
use crate::delivery::ErrorClass;
use crate::{sender, token_store};

/// Authenticate with Rails, preferring a persisted refresh token and falling
/// back to bootstrap authentication when the session cannot be resumed.
pub async fn authenticate(
    client: &mut sender::Client,
    app_config: &AppConfig,
) -> anyhow::Result<sender::AuthResponse> {
    if let Some(refresh_token) = token_store::load_token("refresh_token") {
        match client.refresh_access_token(&refresh_token).await {
            Ok(auth_resp) => {
                info!("resumed session from persisted refresh token");
                persist_refresh_token(&auth_resp, token_store::persist_token);
                return Ok(auth_resp);
            }
            Err(error @ EdgepacerError::AuthFailure(_))
            | Err(error @ EdgepacerError::ClientError(_))
            | Err(error @ EdgepacerError::PayloadTooLarge(_))
            | Err(
                error @ EdgepacerError::Http {
                    class: ErrorClass::Auth | ErrorClass::NonRetryable,
                    ..
                },
            ) => {
                debug_assert!(invalidates_persisted_refresh_token(&error));
                warn!(error = %error, "persisted refresh token invalid, falling back to bootstrap");
                token_store::remove_token("refresh_token");
            }
            Err(e @ EdgepacerError::Retryable(_))
            | Err(
                e @ EdgepacerError::Http {
                    class: ErrorClass::Retryable,
                    ..
                },
            ) => {
                warn!(error = %e, "refresh token check failed transiently, falling back to bootstrap without deleting refresh token");
            }
            Err(
                error @ (EdgepacerError::ConfigError(_) | EdgepacerError::MissingConfig { .. }),
            ) => {
                anyhow::bail!("refresh token config error: {error}");
            }
            Err(EdgepacerError::Other(e)) => {
                return Err(e);
            }
            Err(
                error @ (EdgepacerError::WireCountTooLarge { .. }
                | EdgepacerError::WireEncode { .. }
                | EdgepacerError::WireDecode { .. }
                | EdgepacerError::JsonEncode { .. }
                | EdgepacerError::InvalidMetricValue { .. }),
            ) => return Err(anyhow::anyhow!(error)),
        }
    }

    let auth_resp = client
        .exchange_token()
        .await
        .map_err(|e| anyhow::anyhow!("authentication failed: {e}"))?;

    persist_refresh_token(&auth_resp, token_store::persist_token);
    if let Err(e) =
        persist_server_bootstrap_token_if_needed(app_config, &auth_resp, token_store::persist_token)
    {
        warn!(error = %e, "failed to persist server bootstrap token");
    }

    Ok(auth_resp)
}

fn invalidates_persisted_refresh_token(error: &EdgepacerError) -> bool {
    matches!(
        error,
        EdgepacerError::AuthFailure(_)
            | EdgepacerError::ClientError(_)
            | EdgepacerError::PayloadTooLarge(_)
            | EdgepacerError::Http {
                class: ErrorClass::Auth | ErrorClass::NonRetryable,
                ..
            }
    )
}

fn persist_refresh_token<F>(auth_resp: &sender::AuthResponse, mut persist_token: F)
where
    F: FnMut(&str, &str) -> anyhow::Result<()>,
{
    if let Err(e) = persist_token("refresh_token", &auth_resp.refresh_token) {
        warn!(error = %e, "failed to persist refresh token");
    }
}

fn persist_server_bootstrap_token_if_needed<F>(
    app_config: &AppConfig,
    auth_resp: &sender::AuthResponse,
    mut persist_token: F,
) -> anyhow::Result<()>
where
    F: FnMut(&str, &str) -> anyhow::Result<()>,
{
    if !app_config.is_account_token {
        return Ok(());
    }

    match auth_resp.server_bootstrap_token.as_deref() {
        Some(server_bootstrap_token) => {
            persist_token("server_bootstrap_token", server_bootstrap_token)?;
            info!("persisted server bootstrap token from account auth");
        }
        None => {
            warn!("account token auth did not return server_bootstrap_token");
        }
    }

    Ok(())
}

enum RefreshDecision {
    Refreshed(sender::AuthResponse),
    Reauthenticate,
    RetryLater,
}

fn refresh_decision(
    refresh_result: Result<sender::AuthResponse, EdgepacerError>,
) -> anyhow::Result<RefreshDecision> {
    match refresh_result {
        Ok(auth_resp) => Ok(RefreshDecision::Refreshed(auth_resp)),
        Err(
            e @ (EdgepacerError::Retryable(_)
            | EdgepacerError::Http {
                class: ErrorClass::Retryable,
                ..
            }),
        ) => {
            warn!(error = %e, "token refresh failed, will retry next interval");
            Ok(RefreshDecision::RetryLater)
        }
        Err(
            e @ (EdgepacerError::AuthFailure(_)
            | EdgepacerError::ClientError(_)
            | EdgepacerError::PayloadTooLarge(_)
            | EdgepacerError::Http {
                class: ErrorClass::Auth | ErrorClass::NonRetryable,
                ..
            }),
        ) => {
            warn!(error = %e, "token refresh failed, re-authenticating with bootstrap token");
            Ok(RefreshDecision::Reauthenticate)
        }
        Err(error @ (EdgepacerError::ConfigError(_) | EdgepacerError::MissingConfig { .. })) => {
            Err(anyhow::anyhow!(error))
        }
        Err(EdgepacerError::Other(error)) => Err(error),
        Err(
            error @ (EdgepacerError::WireCountTooLarge { .. }
            | EdgepacerError::WireEncode { .. }
            | EdgepacerError::WireDecode { .. }
            | EdgepacerError::JsonEncode { .. }
            | EdgepacerError::InvalidMetricValue { .. }),
        ) => Err(anyhow::anyhow!(error)),
    }
}

async fn refresh_or_reauthenticate<F>(
    client: &mut sender::Client,
    refresh_token: &str,
    persist_token: F,
) -> anyhow::Result<()>
where
    F: FnMut(&str, &str) -> anyhow::Result<()>,
{
    match refresh_decision(client.refresh_access_token(refresh_token).await)? {
        RefreshDecision::Refreshed(auth_resp) => {
            info!("access token refreshed successfully");
            persist_refresh_token(&auth_resp, persist_token);
        }
        RefreshDecision::Reauthenticate => {
            let auth_resp = client
                .exchange_token()
                .await
                .map_err(|e| anyhow::anyhow!("bootstrap re-authentication failed: {e}"))?;
            persist_refresh_token(&auth_resp, persist_token);
            info!("re-authenticated with bootstrap token");
        }
        RefreshDecision::RetryLater => {}
    }
    Ok(())
}

/// Rotate the access token before it expires.
pub async fn run_token_refresh_loop(
    mut client: sender::Client,
    expires_in: i64,
    mut shutdown: watch::Receiver<bool>,
) {
    let refresh_secs = (expires_in as u64) * 4 / 5;
    let interval = Duration::from_secs(refresh_secs.max(60));

    info!(
        interval_secs = interval.as_secs(),
        "token refresh loop started"
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("token refresh loop shutting down");
                return;
            }
        }

        let refresh_token = match token_store::load_token("refresh_token") {
            Some(t) => t,
            None => {
                warn!("no refresh token on disk, skipping refresh cycle");
                continue;
            }
        };

        if let Err(e) =
            refresh_or_reauthenticate(&mut client, &refresh_token, token_store::persist_token).await
        {
            warn!(error = %e, "token refresh flow failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app_config(
        rails_url: String,
        token: Option<&str>,
        is_account_token: bool,
    ) -> AppConfig {
        AppConfig {
            resource_id: "agent-123".into(),
            rails_url,
            token: token.map(str::to_string),
            is_account_token,
            poll_interval_secs: 30,
            log_level: "info".into(),
            readiness_file: None,
            local_mode: false,
            directive_file: None,
        }
    }

    #[test]
    fn persists_server_bootstrap_token_when_account_token_used() {
        let app_config =
            test_app_config("https://rails.example".into(), Some("account-token"), true);
        let auth_response = sender::AuthResponse {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            expires_in: 3600,
            server_bootstrap_token: Some("server-bootstrap".into()),
            telemetry_config: None,
        };
        let persisted = std::sync::Mutex::new(Vec::new());

        persist_server_bootstrap_token_if_needed(&app_config, &auth_response, |name, value| {
            persisted
                .lock()
                .unwrap()
                .push((name.to_string(), value.to_string()));
            Ok(())
        })
        .unwrap();

        assert_eq!(
            persisted.lock().unwrap().as_slice(),
            [(
                "server_bootstrap_token".to_string(),
                "server-bootstrap".to_string()
            )]
        );
    }

    #[test]
    fn refresh_decision_reauthenticates_after_auth_failure() {
        let action = refresh_decision(Err(EdgepacerError::AuthFailure("expired".into()))).unwrap();
        assert!(matches!(action, RefreshDecision::Reauthenticate));
    }

    #[test]
    fn only_invalid_refresh_errors_delete_persisted_token() {
        assert!(invalidates_persisted_refresh_token(
            &EdgepacerError::AuthFailure("expired".into())
        ));
        assert!(invalidates_persisted_refresh_token(
            &EdgepacerError::ClientError("conflict".into())
        ));
        assert!(invalidates_persisted_refresh_token(&EdgepacerError::Http {
            status: 401,
            class: ErrorClass::Auth,
            context: "refresh token",
            body: "expired".into(),
        }));
        assert!(invalidates_persisted_refresh_token(&EdgepacerError::Http {
            status: 400,
            class: ErrorClass::NonRetryable,
            context: "refresh token",
            body: "bad request".into(),
        }));
        assert!(!invalidates_persisted_refresh_token(
            &EdgepacerError::Retryable("server error".into())
        ));
        assert!(!invalidates_persisted_refresh_token(
            &EdgepacerError::Http {
                status: 429,
                class: ErrorClass::Retryable,
                context: "refresh token",
                body: "rate limited".into(),
            }
        ));
    }

    #[test]
    fn refresh_decision_reauthenticates_after_client_error() {
        let action = refresh_decision(Err(EdgepacerError::ClientError("mismatch".into()))).unwrap();
        assert!(matches!(action, RefreshDecision::Reauthenticate));
    }

    #[test]
    fn refresh_decision_reauthenticates_after_auth_http_status() {
        let action = refresh_decision(Err(EdgepacerError::Http {
            status: 401,
            class: ErrorClass::Auth,
            context: "token refresh",
            body: "expired".into(),
        }))
        .unwrap();
        assert!(matches!(action, RefreshDecision::Reauthenticate));
    }

    #[test]
    fn refresh_decision_retries_after_server_error() {
        let action =
            refresh_decision(Err(EdgepacerError::Retryable("server error".into()))).unwrap();
        assert!(matches!(action, RefreshDecision::RetryLater));
    }

    #[test]
    fn refresh_decision_retries_after_rate_limit_http_status() {
        let action = refresh_decision(Err(EdgepacerError::Http {
            status: 429,
            class: ErrorClass::Retryable,
            context: "token refresh",
            body: "slow down".into(),
        }))
        .unwrap();
        assert!(matches!(action, RefreshDecision::RetryLater));
    }

    #[test]
    fn refresh_retryable_error_waits_for_next_interval() {
        let action = refresh_decision(Err(EdgepacerError::Retryable("network".into()))).unwrap();
        assert!(matches!(action, RefreshDecision::RetryLater));
    }

    #[test]
    fn refresh_decision_surfaces_missing_config() {
        let Err(error) = refresh_decision(Err(EdgepacerError::MissingConfig {
            field: "bootstrap_token",
        })) else {
            panic!("expected missing config to fail refresh decision");
        };

        assert!(error.to_string().contains("bootstrap_token"));
    }
}
