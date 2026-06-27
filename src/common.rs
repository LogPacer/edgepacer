//! Common types and utilities shared across EdgePacer modules.

use crate::delivery::ErrorClass;
use thiserror::Error;

/// EdgePacer version string. Set by build.rs via `cargo:rustc-env`: clean on
/// release builds (`EDGEPACER_RELEASE_VERSION`), `<version>-dev+<sha>[.dirty]`
/// on local/untagged builds. Falls back to the Cargo version if build.rs did
/// not run.
pub const VERSION: &str = match option_env!("EDGEPACER_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// User-Agent header value
pub fn user_agent() -> String {
    format!("edgepacer-rust/{}", VERSION)
}

/// Generate a unique request ID for tracing
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Build a `Bearer` `Authorization` header value from a token.
///
/// Leading/trailing whitespace is ignored so Kubernetes Secret files and
/// copied tokens with a final newline still authenticate. Returns `None` (and
/// warns) when the normalized token is empty or contains bytes that are invalid
/// in an HTTP header. A long-running agent must degrade to an unauthenticated
/// request (which surfaces as 401 → token refresh) rather than panic, so this
/// never unwraps. The value is marked sensitive so it is redacted from header
/// debug output.
pub fn bearer_header(token: &str) -> Option<reqwest::header::HeaderValue> {
    let token = token.trim();
    if token.is_empty() {
        tracing::warn!("empty bearer token, sending request without Authorization header");
        return None;
    }

    match reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(mut value) => {
            value.set_sensitive(true);
            Some(value)
        }
        Err(e) => {
            tracing::warn!(error = %e, "invalid bearer token, sending request without Authorization header");
            None
        }
    }
}

/// Require TLS for the control-plane URL while preserving loopback HTTP for
/// local development and tests.
pub fn validate_control_plane_url(raw: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(raw)?;
    let host = parsed.host_str().unwrap_or("");

    if parsed.scheme() == "https" {
        return Ok(());
    }

    if parsed.scheme() == "http" && is_loopback_host(host) {
        return Ok(());
    }

    anyhow::bail!("control-plane URL must use HTTPS except for localhost: {raw}")
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") || host.ends_with(".localhost")
}

/// Truncate an HTTP response body for safe inclusion in error messages /
/// log lines. Rails 404 / 5xx pages are full HTML documents — without
/// this they end up dumped line-by-line into journald and balloon the
/// log volume by orders of magnitude. 256 chars keeps short JSON errors
/// (the actually-useful case) intact.
pub fn truncate_body(body: &str) -> String {
    const MAX: usize = 256;
    let trimmed = body.trim();
    if trimmed.len() <= MAX {
        trimmed.replace('\n', " ")
    } else {
        let cut = trimmed
            .char_indices()
            .take(MAX)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(MAX);
        format!(
            "{}… ({} bytes total)",
            trimmed[..cut].replace('\n', " "),
            trimmed.len()
        )
    }
}

/// Run a blocking (fsync-bearing or bulk-I/O) operation without stalling the
/// async runtime's worker thread: on the multi-thread runtime the worker's
/// core is handed to the blocking pool for the duration of `f`.
///
/// Context behavior:
/// - Multi-thread runtime worker: `block_in_place` (other tasks migrate).
///   Nested calls are free — only the outermost pays the core handoff, so
///   per-item loops should wrap once at the loop level.
/// - `spawn_blocking` threads: `try_current()` is `Ok` there, and
///   `block_in_place` itself runs `f` inline (already off the workers).
/// - current_thread runtimes (`#[tokio::test]` default) and plain threads:
///   runs `f` inline — `block_in_place` would panic on current_thread.
/// - MUST NOT be called inside a `tokio::task::LocalSet`: `block_in_place`
///   panics there even on the multi-thread runtime. The crate uses none.
pub(crate) fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn control_plane_url_accepts_https() {
        assert!(validate_control_plane_url("https://app.logpacer.com").is_ok());
    }

    #[test]
    fn control_plane_url_accepts_loopback_http() {
        assert!(validate_control_plane_url("http://localhost:3000").is_ok());
        assert!(validate_control_plane_url("http://127.0.0.1:3000").is_ok());
        assert!(validate_control_plane_url("http://[::1]:3000").is_ok());
    }

    #[test]
    fn control_plane_url_rejects_remote_http() {
        assert!(validate_control_plane_url("http://app.logpacer.com").is_err());
    }

    #[test]
    fn bearer_header_trims_secret_file_newline() {
        let value = bearer_header("token-from-secret\n").unwrap();

        assert_eq!(value.to_str().unwrap(), "Bearer token-from-secret");
        assert!(value.is_sensitive());
    }

    #[test]
    fn bearer_header_rejects_blank_token() {
        assert!(bearer_header(" \n\t").is_none());
    }
}

/// Errors that can be retried (network failures, 5xx responses)
#[derive(Debug, Error)]
pub enum EdgepacerError {
    #[error("retryable: {0}")]
    Retryable(String),

    #[error("authentication failed: {0}")]
    AuthFailure(String),

    #[error("client error: {0}")]
    ClientError(String),

    /// The receiver rejected the request body as too large (HTTP 413). Not
    /// retryable as-is — the sender must shrink the batch before resending.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// A classified non-2xx HTTP response. Carries the status code so failures
    /// are countable by status (see [`http_status`]); the human-readable message
    /// is formatted lazily by `Display` instead of allocated on every failure.
    ///
    /// [`http_status`]: EdgepacerError::http_status
    #[error("{context}: {status} ({class:?}) - {body}")]
    Http {
        status: u16,
        class: ErrorClass,
        context: &'static str,
        body: String,
    },

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("missing required config field: {field}")]
    MissingConfig { field: &'static str },

    #[error("{field} count too large for wire u32: {len}")]
    WireCountTooLarge { field: &'static str, len: usize },

    #[error("failed to encode {context}: {source}")]
    WireEncode {
        context: &'static str,
        #[source]
        source: prost::EncodeError,
    },

    #[error("{context}: {source}")]
    WireDecode {
        context: &'static str,
        #[source]
        source: prost::DecodeError,
    },

    #[error("failed to encode {context} JSON: {source}")]
    JsonEncode {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("metric '{metric}' is not a finite number")]
    InvalidMetricValue { metric: String },

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl EdgepacerError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Retryable(_)
                | Self::Http {
                    class: ErrorClass::Retryable,
                    ..
                }
        )
    }

    /// HTTP status code, when this error came from a classified HTTP response.
    /// Lets callers count failures by status for observability. 413 reports as
    /// `Some(413)` even though it has its own variant.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            Self::PayloadTooLarge(_) => Some(413),
            _ => None,
        }
    }

    /// Build an error from a non-2xx HTTP status using the shared
    /// [`classify_http_status`] policy, so retry/auth semantics stay identical
    /// across every HTTP boundary (ship, sender, metrics). `context` labels the
    /// operation; `body` is the (already truncated) response body. The message
    /// is not formatted until the error is displayed.
    ///
    /// [`classify_http_status`]: crate::delivery::classify_http_status
    #[must_use]
    pub fn from_http_status(status: u16, context: &'static str, body: &str) -> Self {
        Self::Http {
            status,
            class: crate::delivery::classify_http_status(status),
            context,
            body: body.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_maps_to_retry_semantics() {
        // 429 must be retryable (rate limiting), not a permanent client error.
        let e = EdgepacerError::from_http_status(429, "ship", "slow down");
        assert!(e.is_retryable());
        assert_eq!(e.http_status(), Some(429));
        // 5xx retryable.
        assert!(EdgepacerError::from_http_status(503, "ship", "").is_retryable());
        // 401/403 classify as auth (not retryable) and stay countable by status.
        let e = EdgepacerError::from_http_status(401, "ship", "");
        assert!(!e.is_retryable());
        assert_eq!(e.http_status(), Some(401));
        assert!(matches!(
            e,
            EdgepacerError::Http {
                class: ErrorClass::Auth,
                ..
            }
        ));
        // Other 4xx stay non-retryable.
        let e = EdgepacerError::from_http_status(400, "ship", "bad");
        assert!(!e.is_retryable());
        assert_eq!(e.http_status(), Some(400));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_blocking_on_multi_thread_runtime() {
        assert_eq!(run_blocking(|| 41 + 1), 42);
    }

    // `#[tokio::test]` default flavor is current_thread, where block_in_place
    // panics — run_blocking must fall back to running inline.
    #[tokio::test]
    async fn run_blocking_on_current_thread_runtime() {
        assert_eq!(run_blocking(|| 41 + 1), 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_blocking_inside_spawn_blocking() {
        let value = tokio::task::spawn_blocking(|| run_blocking(|| 41 + 1))
            .await
            .unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn run_blocking_outside_any_runtime() {
        let value = std::thread::spawn(|| run_blocking(|| 41 + 1))
            .join()
            .unwrap();
        assert_eq!(value, 42);
    }
}
