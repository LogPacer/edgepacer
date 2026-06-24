//! Rails API client for EdgePacer.
//!
//! Handles authentication, config fetching, and inventory reporting.
//! Mirrors legacy EdgePacer's `internal/sender/client.go`.

use crate::common::{self, EdgepacerError};
use crate::config::AppConfig;
use crate::token_store;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Rails API client
pub struct Client {
    http: reqwest::Client,
    rails_url: String,
    resource_id: String,
    bearer_token: Arc<RwLock<String>>,
    bootstrap_token: String,
    installation_id: String,
}

/// Response from POST /api/v1/agents/auth (token exchange)
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub server_bootstrap_token: Option<String>,
    pub telemetry_config: Option<serde_json::Value>,
}

/// Response from POST /api/v1/agents/upload_token — one scoped RS256 upload
/// token per (archive, repo) the agent ships to (logpacer #238).
#[derive(Debug, Deserialize)]
struct UploadTokenBundle {
    tokens: Vec<UploadTokenEntry>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
struct UploadTokenEntry {
    repo_id: String,
    token: String,
}

/// Upload-token bundle fetched from Rails, preserving the server's expiry so
/// the refresh loop can adapt when Rails changes token lifetime.
#[derive(Debug)]
pub struct FetchedUploadTokens {
    pub tokens: HashMap<String, String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response from census reporting endpoints.
#[derive(Debug, Deserialize)]
pub struct InventoryResponse {
    pub status: Option<String>,
    pub message: Option<String>,
    pub rejected: Option<Vec<String>>,
    pub full_resync_required: Option<bool>,
}

/// Auth request payload
#[derive(Serialize)]
struct AuthPayload {
    hostname: String,
    installation_id: String,
    host_mode: bool,
    runtime_context: crate::bootstrap::RuntimeContext,
}

#[derive(Clone, Copy)]
struct RailsEndpoint {
    context: &'static str,
    request_failed: &'static str,
}

const AUTH_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "auth",
    request_failed: "auth request failed",
};
const TOKEN_REFRESH_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "token refresh",
    request_failed: "token refresh failed",
};
const UNIFIED_CONFIG_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "config fetch",
    request_failed: "config fetch failed",
};
const UPLOAD_TOKEN_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "upload_token fetch",
    request_failed: "upload_token fetch failed",
};
const CENSUS_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "census report",
    request_failed: "census report failed",
};
const SAMPLE_REQUESTS_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "sample requests",
    request_failed: "sample request fetch failed",
};
const SAMPLE_UPLOAD_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "sample upload",
    request_failed: "sample upload failed",
};
const SAMPLE_OUTCOME_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "sample outcome",
    request_failed: "sample outcome report failed",
};
const STATS_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "stats report",
    request_failed: "stats report failed",
};
const ERROR_REPORT_ENDPOINT: RailsEndpoint = RailsEndpoint {
    context: "error report",
    request_failed: "error report failed",
};

impl RailsEndpoint {
    fn request_error(self, error: reqwest::Error) -> EdgepacerError {
        EdgepacerError::Retryable(format!(
            "{}: {}",
            self.request_failed,
            error_chain_message(&error)
        ))
    }

    fn status_error(self, status: StatusCode, body: &str) -> EdgepacerError {
        EdgepacerError::from_http_status(status.as_u16(), self.context, body)
    }
}

async fn require_success(
    resp: Response,
    endpoint: RailsEndpoint,
) -> Result<Response, EdgepacerError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }

    let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
    Err(endpoint.status_error(status, &body))
}

fn build_auth_payload(
    hostname: String,
    installation_id: String,
    runtime_context: crate::bootstrap::RuntimeContext,
) -> AuthPayload {
    AuthPayload {
        hostname,
        installation_id,
        host_mode: true,
        runtime_context,
    }
}

impl Client {
    /// Create a new Rails API client
    pub fn new(config: &AppConfig) -> Result<Self, EdgepacerError> {
        let installation_id =
            token_store::load_or_create_installation_id().map_err(EdgepacerError::Other)?;
        Self::build(config, installation_id)
    }

    fn build(config: &AppConfig, installation_id: String) -> Result<Self, EdgepacerError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(common::user_agent())
            .build()
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        let bootstrap_token = config.token.clone().ok_or(EdgepacerError::MissingConfig {
            field: "bootstrap_token",
        })?;

        Ok(Self {
            http,
            rails_url: config.rails_url.clone(),
            resource_id: config.resource_id.clone(),
            bearer_token: Arc::new(RwLock::new(bootstrap_token.clone())),
            bootstrap_token,
            installation_id,
        })
    }

    /// Create a new client sharing an existing bearer token Arc.
    ///
    /// All clients created this way share the same token — when the refresh
    /// loop rotates the access token, every client sees the new value.
    pub fn with_shared_token(
        config: &AppConfig,
        token: Arc<RwLock<String>>,
    ) -> Result<Self, EdgepacerError> {
        let mut client = Self::new(config)?;
        client.bearer_token = token;
        Ok(client)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        config: &AppConfig,
        installation_id: &str,
    ) -> Result<Self, EdgepacerError> {
        Self::build(config, installation_id.to_string())
    }

    /// Return a handle to the shared bearer token for use by the refresh loop.
    pub fn shared_token(&self) -> Arc<RwLock<String>> {
        self.bearer_token.clone()
    }

    #[cfg(test)]
    pub(crate) fn set_bearer_token<T>(&self, token: T)
    where
        T: Into<String>,
    {
        self.replace_bearer_token(token.into());
    }

    #[cfg(test)]
    pub(crate) fn current_bearer_token(&self) -> String {
        self.bearer_token_snapshot()
    }

    /// Exchange bootstrap token for access/refresh tokens
    /// POST /api/v1/agents/auth
    pub async fn exchange_token(&mut self) -> Result<AuthResponse, EdgepacerError> {
        let url = format!("{}/api/v1/agents/auth", self.rails_url);
        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        let payload = build_auth_payload(
            hostname,
            self.installation_id.clone(),
            crate::bootstrap::collect_runtime_context(),
        );

        let resp = self
            .http
            .post(&url)
            .headers(self.bootstrap_auth_headers())
            .json(&payload)
            .send()
            .await
            .map_err(|e| AUTH_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, AUTH_ENDPOINT).await?;

        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        info!("exchanged bootstrap token for access token");

        // Store access token for subsequent authenticated requests
        self.replace_bearer_token(auth_resp.access_token.clone());

        Ok(auth_resp)
    }

    /// Refresh access token using a persisted refresh token.
    /// POST /api/v1/agents/auth/refresh
    ///
    /// Returns a new AuthResponse with rotated access_token and refresh_token.
    /// The caller should persist the new refresh_token for future restarts.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthResponse, EdgepacerError> {
        let url = format!("{}/api/v1/agents/auth/refresh", self.rails_url);

        let payload = serde_json::json!({
            "refresh_token": refresh_token,
        });

        let resp = self
            .http
            .post(&url)
            .headers(self.common_headers())
            .json(&payload)
            .send()
            .await
            .map_err(|e| TOKEN_REFRESH_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, TOKEN_REFRESH_ENDPOINT).await?;

        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        info!("refreshed access token");

        // Update shared bearer token for all clients
        self.replace_bearer_token(auth_resp.access_token.clone());

        Ok(auth_resp)
    }

    /// Fetch unified config from Rails
    /// GET /api/v1/agents/unified_config
    pub async fn fetch_unified_config(
        &self,
        etag: Option<&str>,
    ) -> Result<Option<(String, serde_json::Value)>, EdgepacerError> {
        let url = format!("{}/api/v1/agents/unified_config", self.rails_url);

        let mut req = self.http.get(&url).headers(self.auth_headers());

        // ETag for conditional request
        if let Some(etag) = etag {
            req = req.header("If-None-Match", etag);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| UNIFIED_CONFIG_ENDPOINT.request_error(e))?;

        let status = resp.status();

        // 304 Not Modified — config unchanged
        if status == StatusCode::NOT_MODIFIED {
            debug!("config unchanged (304)");
            return Ok(None);
        }
        let resp = require_success(resp, UNIFIED_CONFIG_ENDPOINT).await?;

        // Extract ETag from response
        let new_etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let config: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        info!("fetched unified config");

        Ok(Some((new_etag, config)))
    }

    /// Fetch scoped subbox upload tokens (RS256 JWTs) for this agent's repos.
    /// POST /api/v1/agents/upload_token, authed with the Rails bearer.
    /// The shippers attach the matching repo token as `Authorization: Bearer`
    /// when shipping to the subbox ingress.
    pub async fn fetch_upload_tokens(&self) -> Result<FetchedUploadTokens, EdgepacerError> {
        let url = format!("{}/api/v1/agents/upload_token", self.rails_url);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(|e| UPLOAD_TOKEN_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, UPLOAD_TOKEN_ENDPOINT).await?;

        let bundle: UploadTokenBundle = resp
            .json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        Ok(FetchedUploadTokens {
            tokens: bundle
                .tokens
                .into_iter()
                .map(|entry| (entry.repo_id, entry.token))
                .collect(),
            expires_at: bundle.expires_at,
        })
    }

    /// Resource ID for this agent.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    // ========================================================================
    // Inventory Reporting — Type-specific census endpoints
    // ========================================================================

    /// Report container inventory to Rails.
    /// POST /census/containers
    pub async fn report_container_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/containers", payload).await
    }

    /// Report service inventory (containers with LOGPACER_SERVICE_NAME).
    /// POST /census/services
    pub async fn report_service_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/services", payload).await
    }

    /// Report file inventory to Rails.
    /// POST /census/files
    pub async fn report_file_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/files", payload).await
    }

    /// Report process inventory to Rails.
    /// POST /api/v1/census/processes
    pub async fn report_process_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/processes", payload).await
    }

    /// Report listening port inventory to Rails.
    /// POST /api/v1/census/ports
    pub async fn report_port_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/ports", payload).await
    }

    /// Report installed package inventory to Rails.
    /// POST /api/v1/census/packages
    pub async fn report_package_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/packages", payload).await
    }

    /// Report journald/systemd unit inventory to Rails.
    /// POST /census/journald
    pub async fn report_journald_inventory(
        &self,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        self.post_census("/api/v1/census/journald", payload).await
    }

    /// Generic census POST helper.
    async fn post_census(
        &self,
        path: &str,
        payload: &serde_json::Value,
    ) -> Result<InventoryResponse, EdgepacerError> {
        let url = format!("{}{}", self.rails_url, path);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(payload)
            .send()
            .await
            .map_err(|e| CENSUS_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, CENSUS_ENDPOINT).await?;

        let inventory_resp: InventoryResponse = resp
            .json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))?;

        Ok(inventory_resp)
    }

    /// Fetch sample requests from Rails.
    /// GET /api/v1/agents/sample_requests
    pub async fn fetch_sample_requests(
        &self,
    ) -> Result<crate::sampler::SampleRequestsResponse, EdgepacerError> {
        let url = format!("{}/api/v1/agents/sample_requests", self.rails_url);

        let resp = self
            .http
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(|e| SAMPLE_REQUESTS_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, SAMPLE_REQUESTS_ENDPOINT).await?;

        resp.json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))
    }

    /// Upload sample lines for a loggable.
    /// POST /api/v1/agents/loggables/samples
    pub async fn upload_sample(
        &self,
        identifier: &str,
        lines: &[String],
    ) -> Result<crate::sampler::SampleUploadResponse, EdgepacerError> {
        let url = format!("{}/api/v1/agents/loggables/samples", self.rails_url);

        let payload = serde_json::json!({
            "identifier": identifier,
            "sample_lines": lines,
            "metadata": {
                "line_count": lines.len(),
                "sampled_at": chrono::Utc::now().to_rfc3339(),
            }
        });

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(&payload)
            .send()
            .await
            .map_err(|e| SAMPLE_UPLOAD_ENDPOINT.request_error(e))?;
        let resp = require_success(resp, SAMPLE_UPLOAD_ENDPOINT).await?;

        resp.json()
            .await
            .map_err(|e| EdgepacerError::Other(e.into()))
    }

    /// Report a terminal/negative sample outcome for a loggable Rails asked us
    /// to sample but we can't read (unreadable + reason) or that had no lines
    /// (empty). Rails records it and stops re-requesting until its retry window
    /// elapses — the mirror of `upload_sample` for the negative result.
    /// POST /api/v1/agents/loggables/sample_outcomes
    pub async fn report_sample_outcome(
        &self,
        identifier: &str,
        outcome: &str,
        reason: Option<&str>,
    ) -> Result<(), EdgepacerError> {
        let url = format!("{}/api/v1/agents/loggables/sample_outcomes", self.rails_url);

        let payload = serde_json::json!({
            "identifier": identifier,
            "outcome": outcome,
            "reason": reason,
        });

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(&payload)
            .send()
            .await
            .map_err(|e| SAMPLE_OUTCOME_ENDPOINT.request_error(e))?;
        require_success(resp, SAMPLE_OUTCOME_ENDPOINT).await?;

        Ok(())
    }

    /// Report agent stats/heartbeat to Rails.
    /// POST /api/v1/agents/stats
    pub async fn report_stats(
        &self,
        report: &crate::stats::StatsReport,
    ) -> Result<(), EdgepacerError> {
        let url = format!("{}/api/v1/agents/stats", self.rails_url);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(report)
            .send()
            .await
            .map_err(|e| STATS_ENDPOINT.request_error(e))?;
        require_success(resp, STATS_ENDPOINT).await?;

        Ok(())
    }

    /// Report stream errors to Rails.
    /// POST /api/v1/agents/errors
    pub async fn report_errors(
        &self,
        report: &crate::error_collector::ErrorReport,
    ) -> Result<(), EdgepacerError> {
        let url = format!("{}/api/v1/agents/errors", self.rails_url);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(report)
            .send()
            .await
            .map_err(|e| ERROR_REPORT_ENDPOINT.request_error(e))?;
        require_success(resp, ERROR_REPORT_ENDPOINT).await?;

        Ok(())
    }

    /// Build common headers (no auth)
    fn common_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(id) = HeaderValue::from_str(&common::new_request_id()) {
            headers.insert("X-EdgePacer-Request-Id", id);
        }
        headers
    }

    /// Build auth headers (bearer token)
    fn auth_headers(&self) -> HeaderMap {
        let mut headers = self.common_headers();
        let token = self.bearer_token_snapshot();
        if let Some(auth) = common::bearer_header(&token) {
            headers.insert(AUTHORIZATION, auth);
        }
        headers
    }

    pub(crate) fn bootstrap_auth_headers(&self) -> HeaderMap {
        let mut headers = self.common_headers();
        if let Some(auth) = common::bearer_header(&self.bootstrap_token) {
            headers.insert(AUTHORIZATION, auth);
        }
        headers
    }

    fn bearer_token_snapshot(&self) -> String {
        match self.bearer_token.read() {
            Ok(token) => token.clone(),
            Err(poisoned) => {
                warn!("Rails bearer token lock was poisoned while reading; recovering");
                self.bearer_token.clear_poison();
                poisoned.into_inner().clone()
            }
        }
    }

    fn replace_bearer_token(&self, token: String) {
        match self.bearer_token.write() {
            Ok(mut current) => *current = token,
            Err(poisoned) => {
                warn!("Rails bearer token lock was poisoned while replacing; recovering");
                self.bearer_token.clear_poison();
                *poisoned.into_inner() = token;
            }
        }
    }
}

fn error_chain_message(error: &(dyn StdError + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();

    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::RuntimeContext;
    use crate::delivery::ErrorClass;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_app_config(rails_url: String) -> AppConfig {
        AppConfig {
            resource_id: "agent-123".into(),
            rails_url,
            token: Some("bootstrap-1".into()),
            is_account_token: false,
            poll_interval_secs: 30,
            log_level: "info".into(),
            readiness_file: None,
            local_mode: false,
            directive_file: None,
        }
    }

    fn assert_status_class(endpoint: RailsEndpoint, status: StatusCode, expected: ErrorClass) {
        let error = endpoint.status_error(status, "response body");

        match error {
            EdgepacerError::Http {
                status: actual_status,
                class,
                context,
                body,
            } => {
                assert_eq!(actual_status, status.as_u16());
                assert_eq!(class, expected);
                assert_eq!(context, endpoint.context);
                assert_eq!(body, "response body");
            }
            other => panic!("expected classified HTTP error, got {other:?}"),
        }
    }

    #[test]
    fn inventory_response_accepts_full_resync_required() {
        let response: InventoryResponse = serde_json::from_str(
            r#"{"status":"accepted","full_resync_required":true,"rejected":["old"]}"#,
        )
        .unwrap();

        assert_eq!(response.status.as_deref(), Some("accepted"));
        assert_eq!(response.full_resync_required, Some(true));
        assert_eq!(response.rejected.unwrap(), vec!["old"]);
    }

    #[test]
    fn parses_upload_token_bundle_ignoring_extra_fields() {
        let json = r#"{"tokens":[
            {"archive_id":"a","repo_id":"r1","token":"jwt1","expires_at":"2026-01-01T00:00:00Z"},
            {"repo_id":"r2","token":"jwt2"}
        ],"expires_at":"2026-01-01T00:00:00Z"}"#;

        let bundle: UploadTokenBundle = serde_json::from_str(json).unwrap();

        assert_eq!(bundle.tokens.len(), 2);
        assert_eq!(bundle.tokens[0].repo_id, "r1");
        assert_eq!(bundle.tokens[0].token, "jwt1");
        assert_eq!(bundle.tokens[1].repo_id, "r2");
        assert_eq!(
            bundle.expires_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            )
        );
    }

    #[tokio::test]
    async fn fetch_upload_tokens_uses_rails_bearer_and_returns_bundle() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/upload_token"))
            .and(header("authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tokens": [
                    {
                        "archive_id": "arc-1",
                        "repo_id": "repo-1",
                        "token": "jwt-1",
                        "expires_at": "2026-01-01T00:00:00Z"
                    },
                    {
                        "repo_id": "repo-2",
                        "token": "jwt-2"
                    }
                ],
                "expires_at": "2026-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");

        let bundle = client.fetch_upload_tokens().await.unwrap();

        assert_eq!(
            bundle.tokens.get("repo-1").map(String::as_str),
            Some("jwt-1")
        );
        assert_eq!(
            bundle.tokens.get("repo-2").map(String::as_str),
            Some("jwt-2")
        );
        assert_eq!(
            bundle.expires_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            )
        );
    }

    #[tokio::test]
    async fn upload_token_server_errors_use_shared_retry_classification() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/upload_token"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();

        let error = client.fetch_upload_tokens().await.unwrap_err();

        assert!(error.is_retryable());
        assert_eq!(error.http_status(), Some(503));
    }

    #[test]
    fn error_chain_message_includes_nested_causes() {
        #[derive(Debug)]
        struct InnerError;

        impl std::fmt::Display for InnerError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "inner cause")
            }
        }

        impl std::error::Error for InnerError {}

        #[derive(Debug)]
        struct OuterError(InnerError);

        impl std::fmt::Display for OuterError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "outer failure")
            }
        }

        impl std::error::Error for OuterError {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        assert_eq!(
            error_chain_message(&OuterError(InnerError)),
            "outer failure: inner cause"
        );
    }

    #[test]
    fn auth_payload_serializes_runtime_context() {
        let payload = build_auth_payload(
            "host-1".into(),
            "installation-1".into(),
            RuntimeContext {
                in_container: true,
                container_runtime: Some("docker".into()),
                deployment_type: "host".into(),
                namespace: None,
                deployment: None,
                pod_name: None,
                node_name: None,
                container: None,
            },
        );

        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["hostname"], "host-1");
        assert_eq!(json["installation_id"], "installation-1");
        assert_eq!(json["runtime_context"]["in_container"], true);
        assert_eq!(json["runtime_context"]["container_runtime"], "docker");
        assert_eq!(json["runtime_context"]["deployment_type"], "host");
    }

    #[test]
    fn exchange_uses_bootstrap_token_even_after_bearer_rotation() {
        let config = test_app_config("https://rails.example".into());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");

        let headers = client.bootstrap_auth_headers();
        let auth_header = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();

        assert_eq!(auth_header, "Bearer bootstrap-1");
        assert_eq!(client.current_bearer_token(), "access-1");
    }

    #[test]
    fn missing_bootstrap_token_is_typed_config_error() {
        let mut config = test_app_config("https://rails.example".into());
        config.token = None;

        let Err(error) = Client::new_for_test(&config, "installation-1") else {
            panic!("expected missing bootstrap token to fail");
        };

        assert!(matches!(
            error,
            EdgepacerError::MissingConfig {
                field: "bootstrap_token"
            }
        ));
    }

    #[test]
    fn auth_headers_recovers_from_poisoned_bearer_token_lock() {
        let config = AppConfig {
            resource_id: "agent-123".into(),
            rails_url: "https://rails.example".into(),
            token: Some("bootstrap-1".into()),
            is_account_token: false,
            poll_interval_secs: 30,
            log_level: "info".into(),
            readiness_file: None,
            local_mode: false,
            directive_file: None,
        };
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        let shared_token = client.shared_token();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared_token.write().unwrap();
            panic!("poison bearer token");
        }));

        client.set_bearer_token("access-1");
        let headers = client.auth_headers();
        let auth_header = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();

        assert_eq!(auth_header, "Bearer access-1");
        assert_eq!(client.current_bearer_token(), "access-1");
    }

    #[test]
    fn sender_endpoints_share_status_classification() {
        let endpoints = [
            AUTH_ENDPOINT,
            TOKEN_REFRESH_ENDPOINT,
            UNIFIED_CONFIG_ENDPOINT,
            UPLOAD_TOKEN_ENDPOINT,
            CENSUS_ENDPOINT,
            SAMPLE_REQUESTS_ENDPOINT,
            SAMPLE_UPLOAD_ENDPOINT,
            STATS_ENDPOINT,
            ERROR_REPORT_ENDPOINT,
        ];

        for endpoint in endpoints {
            assert_status_class(endpoint, StatusCode::UNAUTHORIZED, ErrorClass::Auth);
            assert_status_class(endpoint, StatusCode::FORBIDDEN, ErrorClass::Auth);
            assert_status_class(
                endpoint,
                StatusCode::TOO_MANY_REQUESTS,
                ErrorClass::Retryable,
            );
            assert_status_class(endpoint, StatusCode::BAD_REQUEST, ErrorClass::NonRetryable);
            assert_status_class(endpoint, StatusCode::NOT_FOUND, ErrorClass::NonRetryable);
            assert_status_class(
                endpoint,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorClass::Retryable,
            );
        }
    }

    #[tokio::test]
    async fn refresh_rate_limit_is_retryable_without_invalidating_token_policy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/auth/refresh"))
            .respond_with(ResponseTemplate::new(429).set_body_string("slow down"))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();

        let error = client.refresh_access_token("refresh-1").await.unwrap_err();

        assert!(error.is_retryable());
        assert!(matches!(
            error,
            EdgepacerError::Http {
                status: 429,
                class: ErrorClass::Retryable,
                context: "token refresh",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn report_sample_outcome_posts_and_succeeds_on_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/loggables/sample_outcomes"))
            .and(header("authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "recorded",
                "sample_outcome": "permission_denied"
            })))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");

        let result = client
            .report_sample_outcome(
                "/var/log/protected.log",
                "unreadable",
                Some("permission_denied"),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn report_sample_outcome_surfaces_server_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/loggables/sample_outcomes"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");

        let error = client
            .report_sample_outcome("/var/log/x.log", "empty", None)
            .await
            .unwrap_err();

        assert!(error.is_retryable());
    }

    #[tokio::test]
    async fn unified_config_not_modified_is_not_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/unified_config"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let config = test_app_config(server.uri());
        let client = Client::new_for_test(&config, "installation-1").unwrap();
        client.set_bearer_token("access-1");

        let result = client.fetch_unified_config(Some("\"config-etag\"")).await;

        assert!(result.unwrap().is_none());
    }
}
