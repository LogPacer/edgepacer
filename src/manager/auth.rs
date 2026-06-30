//! Manager authentication — bootstrap token exchange and persistence.
//!
//! Mirrors legacy EdgePacer's `manager.ensureBootstrapToken()`.
//! Uses the manager-specific endpoints, not agent endpoints.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

use crate::delivery::ErrorClass;
use crate::token_store;

const SERVER_TOKEN_FILE: &str = "server_bootstrap_token";
const ACCOUNT_FINGERPRINT_FILE: &str = "account_token_fingerprint";

/// Fingerprint of the account token that seeded the persisted state.
/// Stored next to the server token so a reinstall with a *different*
/// account token is detectable as explicit operator intent — the env var
/// itself is ambient and looks identical on every boot.
fn account_token_fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Best-effort: losing the fingerprint only degrades change detection
/// (next boot resumes legacy persisted-first behavior), never auth.
fn record_fingerprint(fingerprint: &str) {
    if let Err(e) = token_store::persist_token(ACCOUNT_FINGERPRINT_FILE, fingerprint) {
        warn!(error = %e, "[manager] failed to record account token fingerprint");
    }
}

/// Response from POST /api/v1/managers/auth
///
/// `server_bootstrap_token` is optional because older Rails only includes it
/// when the server record was newly created; re-auth against an existing
/// installation_id got a response without it. Current Rails always returns
/// it, but a required field here would turn that omission into a crash loop.
#[derive(Debug, Deserialize)]
pub struct ManagerAuthResponse {
    pub server_bootstrap_token: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

/// Outcome of re-validating the persisted server token from the run loop.
///
/// Mirrors the `Auth` vs `Retryable` split used by
/// `auth_session::refresh_decision`: only a definitive auth rejection re-onboards;
/// a transient blip keeps the current token so a flaky network never churns it.
#[derive(Debug, PartialEq, Eq)]
enum PingOutcome {
    /// 2xx/3xx — the server still accepts the token. No-op.
    Valid,
    /// 401/403 (`ErrorClass::Auth`) — the Server was deleted/the token revoked;
    /// re-bootstrap against the account token to recreate it.
    AuthRejected,
    /// 5xx / network / timeout (`ErrorClass::Retryable`) — keep the current
    /// token and try again next interval.
    Retryable,
}

/// Classify a `managers/ping` HTTP status for the run-loop re-validate path.
///
/// Reuses the shared `classify_http_status` policy and its `ErrorClass::Auth`
/// vs `ErrorClass::Retryable` distinction (the same split `refresh_decision`
/// uses) so only a definitive auth rejection re-onboards: a 5xx (and, defensively,
/// any other non-auth status such as a transient 404) is retryable and leaves the
/// token alone. Pure, so it is unit-testable without a live control plane.
/// Transport failures never reach here — they are mapped to a no-op at the call
/// site, since a dropped connection is not an auth verdict.
fn classify_ping(status: reqwest::StatusCode) -> PingOutcome {
    if status.is_success() || status.is_redirection() {
        return PingOutcome::Valid;
    }
    match crate::delivery::classify_http_status(status.as_u16()) {
        ErrorClass::Auth => PingOutcome::AuthRejected,
        ErrorClass::Retryable | ErrorClass::NonRetryable => PingOutcome::Retryable,
    }
}

/// Manager authentication client.
pub struct ManagerAuth {
    http: reqwest::Client,
    rails_url: String,
    /// Current bearer token (account bootstrap → server bootstrap after auth).
    token: String,
    /// The configured account token, kept normalized for re-auth and change
    /// detection even after `token` becomes the server bootstrap token.
    account_token: String,
    installation_id: String,
}

impl ManagerAuth {
    pub fn new(rails_url: &str, account_token: &str) -> Self {
        let account_token = account_token.trim();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(format!(
                "edgepacer-manager/{} ({}/{})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
            ))
            .build()
            .expect("failed to create HTTP client");

        // Reuse installation_id from token_store directory
        let installation_id = token_store::load_or_create_installation_id()
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        Self {
            http,
            rails_url: rails_url.to_string(),
            token: account_token.to_string(),
            account_token: account_token.to_string(),
            installation_id,
        }
    }

    /// Current bearer token (server bootstrap token after auth).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Ensure we have a valid server bootstrap token, persisted to disk.
    ///
    /// Precedence:
    /// 1. If the configured account token differs from the one that seeded
    ///    the persisted state (recorded fingerprint), the operator changed it
    ///    deliberately — a reinstall takes precedence over stale state, so
    ///    re-bootstrap with it first.
    /// 2. Otherwise resume: validate the persisted server token with
    ///    GET /api/v1/managers/ping and keep using it.
    /// 3. Fall back to POST /api/v1/managers/auth and persist the result.
    pub async fn ensure_bootstrap_token(&mut self) -> anyhow::Result<()> {
        let fingerprint = account_token_fingerprint(&self.account_token);
        let recorded = token_store::load_token(ACCOUNT_FINGERPRINT_FILE);
        let account_token_changed = recorded.as_deref().is_some_and(|r| r != fingerprint);

        if account_token_changed {
            info!("[manager] account token changed since last bootstrap, re-authenticating");
            let err = match self.bootstrap(&fingerprint).await {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            // The new token may be a typo'd reinstall — keep the box alive on
            // the persisted token if it still validates. The fingerprint is
            // only updated on successful bootstrap, so the new token is
            // retried on every restart until it works.
            warn!(error = %err, "[manager] re-auth with changed account token failed, falling back to persisted token");
            if self.use_persisted_token(false, &fingerprint).await {
                return Ok(());
            }
            return Err(err);
        }

        if self
            .use_persisted_token(recorded.is_none(), &fingerprint)
            .await
        {
            return Ok(());
        }

        info!("[manager] authenticating with Rails (first-time bootstrap)");
        self.bootstrap(&fingerprint).await
    }

    /// Re-validate the current server bootstrap token while running, and
    /// re-onboard if the Server was deleted in Rails. Called once per check
    /// interval from the run loop.
    ///
    /// Only a definitive auth rejection (401/403 → `ErrorClass::Auth`) triggers
    /// a re-bootstrap, which re-resolves/recreates the Server by
    /// `installation_id` via the account token and rotates `self.token` to the
    /// fresh server bootstrap token. A 200 is a no-op; any transient failure
    /// (5xx, network, timeout) keeps the current token so a blip never churns
    /// it. The persisted token file is only overwritten by a successful
    /// re-bootstrap — never deleted on a transient failure.
    ///
    /// Returns `Ok(true)` only when the token actually changed (re-onboarded),
    /// so the caller restarts the supervised agent with the new token.
    pub async fn revalidate_bootstrap_token(&mut self) -> anyhow::Result<bool> {
        // A non-HTTP failure (bad header, transport error) is never an auth
        // rejection — keep the current token and try again next interval.
        let status = match self.ping(&self.token).await {
            Ok(resp) => resp.status(),
            Err(e) => {
                warn!(error = %e, "[manager] bootstrap token re-validation ping failed transiently, keeping current token");
                return Ok(false);
            }
        };

        match classify_ping(status) {
            PingOutcome::Valid => Ok(false),
            PingOutcome::Retryable => {
                warn!(
                    "[manager] server error during bootstrap token re-validation, keeping current token"
                );
                Ok(false)
            }
            PingOutcome::AuthRejected => {
                info!("[manager] server bootstrap token rejected (Server deleted?), re-onboarding");
                let fingerprint = account_token_fingerprint(&self.account_token);
                let previous = self.token.clone();
                self.bootstrap(&fingerprint).await?;
                // Signal a restart only when the re-bootstrap actually rotated
                // the token; a recreated Server with an identical token needs no
                // agent restart.
                Ok(self.token != previous)
            }
        }
    }

    /// Validate and adopt the persisted server token. Returns false if it is
    /// missing or rejected. The file is kept either way: a replacement is only
    /// secured by a successful bootstrap, which overwrites it — deleting
    /// earlier would burn the one credential that might still work next boot.
    async fn use_persisted_token(&mut self, backfill_fingerprint: bool, fingerprint: &str) -> bool {
        let Some(persisted) = token_store::load_token(SERVER_TOKEN_FILE) else {
            return false;
        };
        let persisted = persisted.trim();
        if persisted.is_empty() {
            return false;
        }

        match self.validate_token(persisted).await {
            Ok(()) => {
                info!("[manager] using persisted server bootstrap token");
                if backfill_fingerprint {
                    // Pre-fingerprint state dir: record which account token
                    // the current state is consistent with, so future changes
                    // are detected.
                    record_fingerprint(fingerprint);
                }
                self.token = persisted.to_string();
                true
            }
            Err(e) => {
                warn!(error = %e, "[manager] persisted bootstrap token invalid, re-authenticating");
                false
            }
        }
    }

    /// Exchange the account token for a server bootstrap token; persist both
    /// the token and the fingerprint of the account token that produced it.
    async fn bootstrap(&mut self, fingerprint: &str) -> anyhow::Result<()> {
        let auth_resp = self.authenticate().await?;
        let Some(server_token) = auth_resp.server_bootstrap_token else {
            anyhow::bail!(
                "Rails accepted the account token but returned no server_bootstrap_token \
                 (server already exists for this installation_id) — update Rails to always \
                 include it, or write the token to the state dir manually"
            );
        };
        let server_token = server_token.trim();
        if server_token.is_empty() {
            anyhow::bail!(
                "Rails accepted the account token but returned an empty server_bootstrap_token"
            );
        }

        token_store::persist_token(SERVER_TOKEN_FILE, server_token)?;
        record_fingerprint(fingerprint);
        info!("[manager] server bootstrap token persisted to disk");

        self.token = server_token.to_string();
        Ok(())
    }

    /// POST /api/v1/managers/auth — exchange account bootstrap for server bootstrap token.
    async fn authenticate(&self) -> anyhow::Result<ManagerAuthResponse> {
        let url = format!("{}/api/v1/managers/auth", self.rails_url);
        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        let payload = serde_json::json!({
            "installation_id": self.installation_id,
            "hostname": hostname,
        });

        let resp = self
            .http
            .post(&url)
            .headers(self.bearer_headers())
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            anyhow::bail!(
                "invalid bootstrap token (401) — get a fresh token from Rails settings: {body}"
            );
        }
        if !status.is_success() {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            anyhow::bail!("manager auth failed: {status} - {body}");
        }

        Ok(resp.json().await?)
    }

    /// GET /api/v1/managers/ping — validate a token is still accepted.
    async fn validate_token(&self, token: &str) -> anyhow::Result<()> {
        let resp = self.ping(token).await?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::NOT_FOUND
        {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            anyhow::bail!("token validation failed: {status} - {body}");
        }

        // Network errors or 5xx: don't invalidate the token
        if status.is_server_error() {
            warn!(status = %status, "[manager] server error during token validation, assuming token is still valid");
            return Ok(());
        }

        Ok(())
    }

    /// Send a single GET /api/v1/managers/ping with the given bearer token.
    /// Shared by the startup `validate_token` path and the run-loop
    /// `revalidate_bootstrap_token` path.
    async fn ping(&self, token: &str) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}/api/v1/managers/ping", self.rails_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth = crate::common::bearer_header(token)
            .ok_or_else(|| anyhow::anyhow!("token is not a valid HTTP header value"))?;
        headers.insert(AUTHORIZATION, auth);

        Ok(self.http.get(&url).headers(headers).send().await?)
    }

    /// Headers for /managers/auth — always the account token, regardless of
    /// what `self.token` currently holds.
    fn bearer_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(auth) = crate::common::bearer_header(&self.account_token) {
            headers.insert(AUTHORIZATION, auth);
        }
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // `EDGEPACER_STATE_DIR` is process-global, and the integration tests below
    // bootstrap into a private temp dir. Serialize them so concurrent tests in
    // this binary never observe each other's state dir.
    static STATE_DIR_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn classify_ping_treats_2xx_as_valid() {
        assert_eq!(classify_ping(reqwest::StatusCode::OK), PingOutcome::Valid);
        assert_eq!(
            classify_ping(reqwest::StatusCode::NO_CONTENT),
            PingOutcome::Valid
        );
    }

    #[test]
    fn classify_ping_treats_401_403_as_auth_rejected() {
        assert_eq!(
            classify_ping(reqwest::StatusCode::UNAUTHORIZED),
            PingOutcome::AuthRejected
        );
        assert_eq!(
            classify_ping(reqwest::StatusCode::FORBIDDEN),
            PingOutcome::AuthRejected
        );
    }

    #[test]
    fn classify_ping_treats_5xx_and_other_non_auth_as_retryable() {
        assert_eq!(
            classify_ping(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            PingOutcome::Retryable
        );
        assert_eq!(
            classify_ping(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            PingOutcome::Retryable
        );
        // A transient 404 must not be read as a deleted Server — only 401/403 is
        // a definitive auth verdict for the loop path.
        assert_eq!(
            classify_ping(reqwest::StatusCode::NOT_FOUND),
            PingOutcome::Retryable
        );
    }

    /// Build a `ManagerAuth` already holding a server bootstrap token, as if the
    /// startup `ensure_bootstrap_token` had adopted one.
    fn running_auth(rails_url: &str) -> ManagerAuth {
        let mut auth = ManagerAuth::new(rails_url, "account-token");
        auth.token = "old-server-token".to_string();
        auth
    }

    #[tokio::test]
    async fn revalidate_is_noop_when_ping_returns_200() {
        let _guard = STATE_DIR_GUARD.lock().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("EDGEPACER_STATE_DIR", state_dir.path()) };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/managers/ping"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        // No /managers/auth mount: if revalidate wrongly re-bootstrapped, that
        // POST would 404 and surface as an Err here instead of Ok(false).

        let mut auth = running_auth(&server.uri());
        let changed = auth.revalidate_bootstrap_token().await.unwrap();

        assert!(!changed, "200 ping must not signal a restart");
        assert_eq!(auth.token(), "old-server-token");

        unsafe { std::env::remove_var("EDGEPACER_STATE_DIR") };
    }

    #[tokio::test]
    async fn revalidate_rebootstraps_and_signals_restart_on_401() {
        let _guard = STATE_DIR_GUARD.lock().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("EDGEPACER_STATE_DIR", state_dir.path()) };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/managers/ping"))
            .respond_with(ResponseTemplate::new(401).set_body_string("server deleted"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/managers/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "server_bootstrap_token": "fresh-server-token",
            })))
            .mount(&server)
            .await;

        let mut auth = running_auth(&server.uri());
        let changed = auth.revalidate_bootstrap_token().await.unwrap();

        assert!(changed, "401 ping must re-onboard and signal a restart");
        assert_eq!(auth.token(), "fresh-server-token");
        // The rotated token is persisted so a manager restart resumes on it.
        assert_eq!(
            token_store::load_token(SERVER_TOKEN_FILE).as_deref(),
            Some("fresh-server-token")
        );

        unsafe { std::env::remove_var("EDGEPACER_STATE_DIR") };
    }

    #[tokio::test]
    async fn revalidate_keeps_token_on_5xx_ping_error() {
        let _guard = STATE_DIR_GUARD.lock().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("EDGEPACER_STATE_DIR", state_dir.path()) };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/managers/ping"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;
        // No /managers/auth mount: a transient blip must not re-bootstrap; if it
        // did, the POST would 404 and this would be an Err instead of Ok(false).

        let mut auth = running_auth(&server.uri());
        let changed = auth.revalidate_bootstrap_token().await.unwrap();

        assert!(!changed, "5xx ping must not re-bootstrap");
        assert_eq!(auth.token(), "old-server-token");

        unsafe { std::env::remove_var("EDGEPACER_STATE_DIR") };
    }
}
