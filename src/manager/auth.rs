//! Manager authentication — bootstrap token exchange and persistence.
//!
//! Mirrors legacy EdgePacer's `manager.ensureBootstrapToken()`.
//! Uses the manager-specific endpoints, not agent endpoints.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

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
        let url = format!("{}/api/v1/managers/ping", self.rails_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth = crate::common::bearer_header(token)
            .ok_or_else(|| anyhow::anyhow!("token is not a valid HTTP header value"))?;
        headers.insert(AUTHORIZATION, auth);

        let resp = self.http.get(&url).headers(headers).send().await?;

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
