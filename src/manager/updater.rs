//! Auto-updater — check for new versions, download, verify, install with rollback.
//!
//! Mirrors legacy EdgePacer's `internal/manager/updater.go`.

use anyhow::Context;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

/// Version information from Rails.
#[derive(Debug, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    #[serde(default)]
    pub signature: Option<String>,
    pub release_notes: Option<String>,
    pub released_at: Option<String>,
    #[serde(default)]
    pub up_to_date: bool,
}

/// Result of an update attempt, reported back to Rails.
#[derive(Debug, serde::Serialize)]
pub struct UpdateResult {
    pub installation_id: String,
    pub platform: String,
    pub from_version: String,
    pub to_version: String,
    pub success: bool,
    pub duration_seconds: u64,
    pub error_message: Option<String>,
    pub metadata: UpdateMetadata,
}

#[derive(Debug, serde::Serialize)]
pub struct UpdateMetadata {
    pub rollback_performed: bool,
    pub timestamp: String,
}

/// Handles version checking, downloading, and installing updates.
pub struct Updater {
    http: reqwest::Client,
    rails_url: String,
    token: String,
    platform: String,
    installation_id: String,
    update_public_key: Option<VerifyingKey>,
}

/// Trusted hosts for binary downloads.
const TRUSTED_HOSTS: &[&str] = &[
    "releases.logpacer.com",
    "github.com",
    "objects.githubusercontent.com",
];
const SHA256_HEX_LENGTH: usize = 64;
const ED25519_SIGNATURE_HEX_LENGTH: usize = 128;
pub const UPDATE_SIGNATURE_CONTEXT: &str = "edgepacer-update-v1";

impl Updater {
    pub fn new(
        rails_url: &str,
        token: &str,
        platform: &str,
        installation_id: &str,
        update_public_key: Option<&str>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(300)) // 5 min for downloads
            .connect_timeout(Duration::from_secs(10))
            .user_agent(format!(
                "edgepacer-manager/{} ({}/{})",
                crate::common::VERSION,
                std::env::consts::OS,
                std::env::consts::ARCH,
            ))
            .build()
            .expect("failed to create HTTP client");

        Ok(Self {
            http,
            rails_url: rails_url.to_string(),
            token: token.to_string(),
            platform: platform.to_string(),
            installation_id: installation_id.to_string(),
            update_public_key: parse_update_public_key(update_public_key)?,
        })
    }

    /// Update the bearer token (after bootstrap token exchange).
    pub fn set_token(&mut self, token: &str) {
        self.token = token.to_string();
    }

    /// Check if a newer agent version is available (the agent channel).
    /// GET /api/v1/edgepacer/agent/latest?platform=X&current_version=Y
    pub async fn check_for_update(
        &self,
        current_version: &str,
    ) -> anyhow::Result<Option<UpdateInfo>> {
        self.check("/api/v1/edgepacer/agent/latest", current_version)
            .await
    }

    /// Check if a newer *manager* version is available (the manual `update` path,
    /// resolved against the manager channel — decoupled from the agent's).
    /// GET /api/v1/edgepacer/manager/latest?platform=X&current_version=Y
    pub async fn check_for_self_update(
        &self,
        current_version: &str,
    ) -> anyhow::Result<Option<UpdateInfo>> {
        self.check("/api/v1/edgepacer/manager/latest", current_version)
            .await
    }

    async fn check(&self, path: &str, current_version: &str) -> anyhow::Result<Option<UpdateInfo>> {
        let url = format!(
            "{}{}?platform={}&current_version={}",
            self.rails_url, path, self.platform, current_version
        );

        let resp = self
            .http
            .get(&url)
            .headers(self.bearer_headers())
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            anyhow::bail!("version check failed: {body}");
        }

        let info: UpdateInfo = resp.json().await?;

        if info.up_to_date {
            return Ok(None);
        }

        if info.download_url.is_empty() || info.sha256.is_empty() {
            anyhow::bail!("update response missing download_url or sha256");
        }
        expected_sha256(&info.sha256)?;
        self.update_public_key
            .as_ref()
            .context("update signing key is not configured; set EDGEPACER_UPDATE_PUBLIC_KEY")?;
        expected_signature(info.signature.as_deref())?;

        Ok(Some(info))
    }

    /// Download a new binary and verify its SHA256 hash.
    ///
    /// Returns the path to the verified temp binary.
    pub async fn download_and_verify(
        &self,
        update: &UpdateInfo,
        edgepacer_path: &Path,
    ) -> anyhow::Result<PathBuf> {
        // Validate download URL against trusted hosts
        validate_download_url(&update.download_url, &self.rails_url)?;

        let new_path = edgepacer_path.with_extension("new");

        info!(
            version = %update.version,
            url = %update.download_url,
            "[manager] downloading update"
        );

        let resp = self.http.get(&update.download_url).send().await?;

        if !resp.status().is_success() {
            anyhow::bail!("download failed: {}", resp.status());
        }

        // Stream download while computing SHA256
        let mut hasher = Sha256::new();
        let mut file = tokio::fs::File::create(&new_path).await?;
        let mut stream = resp.bytes_stream();

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
        }

        // Verify SHA256
        let computed = hex::encode(hasher.finalize());
        let expected = expected_sha256(&update.sha256)?;
        if computed != expected {
            let _ = tokio::fs::remove_file(&new_path).await;
            anyhow::bail!("SHA256 mismatch: expected {expected}, got {computed}");
        }

        if let Err(error) = self.verify_update_signature(update, &computed) {
            let _ = tokio::fs::remove_file(&new_path).await;
            return Err(error);
        }

        // Set executable permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))?;
        }

        info!(version = %update.version, sha256 = %computed, "[manager] download verified");

        Ok(new_path)
    }

    /// Backup the current binary.
    pub fn backup_current(edgepacer_path: &Path) -> anyhow::Result<PathBuf> {
        let backup_path = edgepacer_path.with_extension("backup");
        std::fs::copy(edgepacer_path, &backup_path)?;
        info!(backup = %backup_path.display(), "[manager] backed up current binary");
        Ok(backup_path)
    }

    /// Install the new binary, replacing the current one.
    ///
    /// Unix: a single atomic rename — the running image keeps its open inode.
    /// Windows: the running (or just-killed) exe holds an image lock, so an
    /// in-place overwrite fails with "Access is denied (os error 5)". Windows
    /// *does* permit renaming a locked exe out of the way, so move the current
    /// binary aside (`target` → `.old`), move the new one into place, then
    /// best-effort delete `.old`. The move-aside is retried briefly because the
    /// child's file handle can lag its exit.
    pub fn install_new(new_path: &Path, target_path: &Path) -> anyhow::Result<()> {
        #[cfg(windows)]
        Self::install_new_windows(new_path, target_path)?;
        #[cfg(not(windows))]
        std::fs::rename(new_path, target_path)?;
        info!(target = %target_path.display(), "[manager] installed new binary");
        Ok(())
    }

    #[cfg(windows)]
    fn install_new_windows(new_path: &Path, target_path: &Path) -> anyhow::Result<()> {
        use std::time::{Duration, Instant};

        // First install (no current binary): nothing to move aside.
        if !target_path.exists() {
            return std::fs::rename(new_path, target_path).map_err(Into::into);
        }

        let old_path = target_path.with_extension("old");
        let _ = std::fs::remove_file(&old_path); // clear a leftover .old from a prior update

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::fs::rename(target_path, &old_path) {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(anyhow::anyhow!("failed to move current binary aside: {e}")),
            }
        }

        std::fs::rename(new_path, target_path)
            .map_err(|e| anyhow::anyhow!("failed to move new binary into place: {e}"))?;
        let _ = std::fs::remove_file(&old_path); // best-effort; harmless if it lingers
        Ok(())
    }

    /// Restore from backup.
    pub fn restore_backup(backup_path: &Path, target_path: &Path) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(target_path);
        std::fs::rename(backup_path, target_path)?;
        warn!(target = %target_path.display(), "[manager] restored from backup");
        Ok(())
    }

    /// Clean up backup file.
    pub fn cleanup_backup(backup_path: &Path) {
        let _ = std::fs::remove_file(backup_path);
    }

    /// Report update result to Rails.
    /// POST /api/v1/managers/update_result
    pub async fn report_update_result(&self, result: &UpdateResult) -> anyhow::Result<()> {
        let url = format!("{}/api/v1/managers/update_result", self.rails_url);

        let resp = self
            .http
            .post(&url)
            .headers(self.bearer_headers())
            .json(result)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = crate::common::truncate_body(&resp.text().await.unwrap_or_default());
            warn!(body, "[manager] failed to report update result");
        }

        Ok(())
    }

    /// Build an UpdateResult for reporting.
    pub fn build_result(
        &self,
        from: &str,
        to: &str,
        success: bool,
        duration: Duration,
        error_msg: Option<String>,
        rollback: bool,
    ) -> UpdateResult {
        UpdateResult {
            installation_id: self.installation_id.clone(),
            platform: self.platform.clone(),
            from_version: from.to_string(),
            to_version: to.to_string(),
            success,
            duration_seconds: duration.as_secs(),
            error_message: error_msg,
            metadata: UpdateMetadata {
                rollback_performed: rollback,
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        }
    }

    fn bearer_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(auth) = crate::common::bearer_header(&self.token) {
            headers.insert(AUTHORIZATION, auth);
        }
        headers
    }

    fn verify_update_signature(&self, update: &UpdateInfo, sha256: &str) -> anyhow::Result<()> {
        let public_key = self
            .update_public_key
            .as_ref()
            .context("update signing key is not configured; set EDGEPACER_UPDATE_PUBLIC_KEY")?;
        let signature = expected_signature(update.signature.as_deref())?;
        let signature_bytes = decode_hex_fixed::<64>(signature, "update signature")?;
        let signature = Signature::from_bytes(&signature_bytes);
        let payload = update_signature_payload(&update.version, &self.platform, sha256);

        public_key
            .verify(payload.as_bytes(), &signature)
            .context("update signature verification failed")
    }
}

/// Validate download URL against trusted hosts.
fn validate_download_url(url: &str, rails_url: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url)?;
    let host = parsed.host_str().unwrap_or("");

    // Localhost always allowed (development)
    if is_loopback_download_host(host) {
        return Ok(());
    }

    // Rails URL host is always trusted
    if let Ok(rails_parsed) = reqwest::Url::parse(rails_url)
        && Some(host) == rails_parsed.host_str()
    {
        if parsed.scheme() != "https" {
            anyhow::bail!("download URL must use HTTPS for non-localhost: {url}");
        }
        return Ok(());
    }

    // Check against trusted hosts
    for trusted in TRUSTED_HOSTS {
        if host == *trusted || host.ends_with(&format!(".{trusted}")) {
            // Non-localhost must use HTTPS
            if parsed.scheme() != "https" {
                anyhow::bail!("download URL must use HTTPS for non-localhost: {url}");
            }
            return Ok(());
        }
    }

    anyhow::bail!("download URL host not trusted: {host} (url: {url})")
}

fn is_loopback_download_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn expected_sha256(raw: &str) -> anyhow::Result<&str> {
    let digest = raw.split_whitespace().next().unwrap_or("");

    if digest.len() == SHA256_HEX_LENGTH && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(digest);
    }

    anyhow::bail!("update response has invalid sha256 value: {raw:?}")
}

fn expected_signature(raw: Option<&str>) -> anyhow::Result<&str> {
    let signature = raw.unwrap_or("").trim();

    if signature.len() == ED25519_SIGNATURE_HEX_LENGTH
        && signature.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Ok(signature);
    }

    anyhow::bail!("update response missing valid Ed25519 signature")
}

fn parse_update_public_key(raw: Option<&str>) -> anyhow::Result<Option<VerifyingKey>> {
    let Some(public_key) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let bytes = decode_hex_fixed::<32>(public_key, "update public key")?;
    VerifyingKey::from_bytes(&bytes)
        .context("update public key is not a valid Ed25519 public key")
        .map(Some)
}

fn decode_hex_fixed<const N: usize>(raw: &str, label: &str) -> anyhow::Result<[u8; N]> {
    if raw.len() != N * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{label} must be {} hex characters", N * 2);
    }

    let bytes = hex::decode(raw).with_context(|| format!("{label} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} decoded to the wrong length"))
}

pub fn update_signature_payload(version: &str, platform: &str, sha256: &str) -> String {
    format!("{UPDATE_SIGNATURE_CONTEXT}\nversion:{version}\nplatform:{platform}\nsha256:{sha256}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_update(version: &str, platform: &str, sha256: &str) -> (UpdateInfo, String) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature =
            signing_key.sign(update_signature_payload(version, platform, sha256).as_bytes());

        (
            UpdateInfo {
                version: version.to_string(),
                download_url: "https://releases.logpacer.com/edgepacer".to_string(),
                sha256: sha256.to_string(),
                signature: Some(hex::encode(signature.to_bytes())),
                release_notes: None,
                released_at: None,
                up_to_date: false,
            },
            hex::encode(signing_key.verifying_key().to_bytes()),
        )
    }

    #[test]
    fn validates_trusted_hosts() {
        assert!(
            validate_download_url(
                "https://github.com/LogPacer/edgepacer/releases/download/v1.0.0/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_ok()
        );

        assert!(
            validate_download_url(
                "https://releases.logpacer.com/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_ok()
        );

        assert!(
            validate_download_url("http://localhost:3000/download", "http://localhost:3000")
                .is_ok()
        );
    }

    #[test]
    fn rejects_untrusted_hosts() {
        assert!(
            validate_download_url(
                "https://evil.com/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_http_for_non_localhost() {
        assert!(
            validate_download_url(
                "http://github.com/LogPacer/edgepacer/releases/download/v1.0.0/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_err()
        );
    }

    #[test]
    fn trusts_rails_url_host() {
        assert!(
            validate_download_url(
                "https://app.logpacer.internal/releases/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_http_for_non_localhost_rails_host() {
        assert!(
            validate_download_url(
                "http://app.logpacer.internal/releases/edgepacer",
                "https://app.logpacer.internal"
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_bare_sha256_digest() {
        let digest = "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d";

        assert_eq!(expected_sha256(digest).unwrap(), digest);
    }

    #[test]
    fn accepts_sha256sum_sidecar_line() {
        let sidecar = "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d  dist/edgepacer-darwin-arm64\n";

        assert_eq!(
            expected_sha256(sidecar).unwrap(),
            "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d"
        );
    }

    #[test]
    fn rejects_invalid_sha256() {
        assert!(expected_sha256("not-a-digest dist/edgepacer").is_err());
        assert!(expected_sha256("").is_err());
    }

    #[test]
    fn verifies_update_signature_for_version_platform_and_digest() {
        let digest = "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d";
        let (update, public_key) = signed_update("1.2.3", "linux-amd64", digest);
        let updater = Updater::new(
            "https://app.logpacer.internal",
            "token",
            "linux-amd64",
            "installation",
            Some(&public_key),
        )
        .unwrap();

        assert!(updater.verify_update_signature(&update, digest).is_ok());
    }

    #[test]
    fn rejects_update_signature_for_wrong_platform() {
        let digest = "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d";
        let (update, public_key) = signed_update("1.2.3", "linux-amd64", digest);
        let updater = Updater::new(
            "https://app.logpacer.internal",
            "token",
            "linux-arm64",
            "installation",
            Some(&public_key),
        )
        .unwrap();

        assert!(updater.verify_update_signature(&update, digest).is_err());
    }

    #[test]
    fn rejects_update_signature_without_configured_public_key() {
        let digest = "fb4dda34d0a3166274a4b41a1c7ee2ee2ce6c0ccbe0e0f6478d0a4c1d997612d";
        let (update, _) = signed_update("1.2.3", "linux-amd64", digest);
        let updater = Updater::new(
            "https://app.logpacer.internal",
            "token",
            "linux-amd64",
            "installation",
            None,
        )
        .unwrap();

        assert!(updater.verify_update_signature(&update, digest).is_err());
    }
}
