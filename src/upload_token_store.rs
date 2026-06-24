//! Process-wide cache of short-lived subbox upload tokens (RS256 JWTs), keyed
//! by repo_id.
//!
//! Populated by a background refresh loop (`spawn_refresh`) that calls
//! `sender::Client::fetch_upload_tokens` (logpacer #238). Read by the shippers,
//! which attach the matching token as `Authorization: Bearer` when shipping to
//! the subbox ingress; the gate verifies it via JWKS and stamps `X-Pacer-*`.
//!
//! Decoupled from the ETag-cached unified_config on purpose: the credential
//! lifecycle is independent of the config lifecycle.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::sender::Client;

const RETRY_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
const MIN_SUCCESS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const REFRESH_RATIO_NUMERATOR: u64 = 4;
const REFRESH_RATIO_DENOMINATOR: u64 = 5;

pub struct UploadTokenStore {
    tokens: RwLock<HashMap<String, String>>,
    refresh: Notify,
}

impl UploadTokenStore {
    fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            refresh: Notify::new(),
        }
    }

    /// The cached token for a repo, if any.
    pub fn get(&self, repo_id: &str) -> Option<String> {
        match self.tokens.read() {
            Ok(tokens) => tokens.get(repo_id).cloned(),
            Err(poisoned) => {
                warn!("upload-token store lock was poisoned while reading; recovering");
                poisoned.into_inner().get(repo_id).cloned()
            }
        }
    }

    /// Replace the whole token set (one fetch returns all of the agent's repos).
    pub fn replace(&self, tokens: HashMap<String, String>) {
        match self.tokens.write() {
            Ok(mut current) => *current = tokens,
            Err(poisoned) => {
                warn!("upload-token store lock was poisoned while replacing; recovering");
                *poisoned.into_inner() = tokens;
            }
        }
    }

    /// Ask the refresh loop to fetch immediately (e.g. after a gate 401).
    pub fn request_refresh(&self) {
        self.refresh.notify_one();
    }

    async fn refresh_requested(&self) {
        self.refresh.notified().await;
    }
}

static STORE: OnceLock<Arc<UploadTokenStore>> = OnceLock::new();

/// The process-wide store (empty until the refresh loop has run once).
pub fn store() -> &'static Arc<UploadTokenStore> {
    STORE.get_or_init(|| Arc::new(UploadTokenStore::new()))
}

/// Spawn the loop that keeps `store()` populated: fetch once immediately, then
/// every `REFRESH_INTERVAL` or whenever a refresh is requested.
pub fn spawn_refresh(client: Client) {
    let store = store().clone();
    tokio::spawn(async move {
        loop {
            let refresh_interval = match client.fetch_upload_tokens().await {
                Ok(bundle) => {
                    let refresh_interval =
                        next_success_refresh_interval(bundle.expires_at, Utc::now());
                    debug!(
                        repos = bundle.tokens.len(),
                        expires_at = bundle.expires_at.map(|expires_at| expires_at.to_rfc3339()),
                        refresh_in_secs = refresh_interval.as_secs(),
                        "refreshed subbox upload tokens"
                    );
                    store.replace(bundle.tokens);
                    refresh_interval
                }
                Err(e) => {
                    warn!(error = %e, "failed to refresh subbox upload tokens");
                    RETRY_REFRESH_INTERVAL
                }
            };

            tokio::select! {
                _ = tokio::time::sleep(refresh_interval) => {}
                _ = store.refresh_requested() => debug!("on-demand upload-token refresh"),
            }
        }
    });
}

fn next_success_refresh_interval(
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Duration {
    let Some(expires_at) = expires_at else {
        return RETRY_REFRESH_INTERVAL;
    };

    let Ok(ttl) = expires_at.signed_duration_since(now).to_std() else {
        return MIN_SUCCESS_REFRESH_INTERVAL;
    };

    let refresh_secs =
        ttl.as_secs().saturating_mul(REFRESH_RATIO_NUMERATOR) / REFRESH_RATIO_DENOMINATOR;
    Duration::from_secs(refresh_secs).max(MIN_SUCCESS_REFRESH_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn get_returns_replaced_token() {
        let store = UploadTokenStore::new();
        assert!(store.get("repo-1").is_none());

        let mut tokens = HashMap::new();
        tokens.insert("repo-1".to_string(), "jwt-abc".to_string());
        store.replace(tokens);

        assert_eq!(store.get("repo-1").as_deref(), Some("jwt-abc"));
        assert!(store.get("repo-2").is_none());
    }

    #[test]
    fn replace_recovers_from_poisoned_store_lock() {
        let store = Arc::new(UploadTokenStore::new());
        let poison_target = store.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison_target.tokens.write().unwrap();
            panic!("poison upload-token store");
        })
        .join();

        let mut tokens = HashMap::new();
        tokens.insert("repo-1".to_string(), "jwt-after-poison".to_string());
        store.replace(tokens);

        assert_eq!(store.get("repo-1").as_deref(), Some("jwt-after-poison"));
    }

    #[tokio::test]
    async fn request_refresh_wakes_waiter() {
        let store = Arc::new(UploadTokenStore::new());
        let waiter = {
            let store = store.clone();
            tokio::spawn(async move { store.refresh_requested().await })
        };

        tokio::task::yield_now().await;
        store.request_refresh();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("refresh should wake the waiter")
            .unwrap();
    }

    #[test]
    fn success_refresh_interval_uses_eighty_percent_of_server_ttl() {
        let now = Utc.with_ymd_and_hms(2026, 6, 22, 12, 0, 0).unwrap();
        let expires_at = now + chrono::Duration::hours(24);

        assert_eq!(
            next_success_refresh_interval(Some(expires_at), now),
            Duration::from_secs(24 * 60 * 60 * 4 / 5)
        );
    }

    #[test]
    fn success_refresh_interval_stays_short_without_server_expiry() {
        let now = Utc.with_ymd_and_hms(2026, 6, 22, 12, 0, 0).unwrap();

        assert_eq!(
            next_success_refresh_interval(None, now),
            RETRY_REFRESH_INTERVAL
        );
    }

    #[test]
    fn success_refresh_interval_uses_minimum_when_expiry_is_stale() {
        let now = Utc.with_ymd_and_hms(2026, 6, 22, 12, 0, 0).unwrap();
        let expires_at = now - chrono::Duration::seconds(1);

        assert_eq!(
            next_success_refresh_interval(Some(expires_at), now),
            MIN_SUCCESS_REFRESH_INTERVAL
        );
    }
}
