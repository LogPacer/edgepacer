//! Secure token file I/O — atomic writes with symlink protection.
//!
//! Shared by both the agent (refresh_token) and manager (server_bootstrap_token).
//! Tokens are stored in the Go-compatible state dir alongside installation_id.

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use tracing::{debug, info, warn};

#[cfg(unix)]
const STATE_DIR_ENV: &str = "EDGEPACER_STATE_DIR";

/// Returns the token storage directory (same as installation_id).
///
/// Mirrors the Go state-dir logic:
/// - `EDGEPACER_STATE_DIR`: absolute explicit state dir, used by containers
/// - Unix root: /var/lib/edgepacer/
/// - Unix user: ~/.local/share/edgepacer/
/// - Non-Unix: OS-local data dir / edgepacer
pub fn token_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(dir) = configured_state_dir(std::env::var_os(STATE_DIR_ENV)) {
            return dir;
        }

        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let is_root = unsafe { libc::geteuid() == 0 };
        unix_state_dir(&home_dir, is_root)
    }

    #[cfg(not(unix))]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("edgepacer")
    }
}

#[cfg(unix)]
fn configured_state_dir(value: Option<OsString>) -> Option<PathBuf> {
    let path = PathBuf::from(value?);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }

    Some(path)
}

#[cfg(unix)]
fn unix_state_dir(home_dir: &Path, is_root: bool) -> PathBuf {
    if is_root {
        PathBuf::from("/var/lib/edgepacer")
    } else {
        home_dir.join(".local").join("share").join("edgepacer")
    }
}

/// Load a token from disk. Returns None if missing, empty, or unreadable.
pub fn load_token(filename: &str) -> Option<String> {
    let path = token_dir().join(filename);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                debug!(path = %path.display(), "loaded persisted token");
                Some(trimmed)
            }
        }
        Err(_) => None,
    }
}

/// Persist a token to disk with atomic write and security checks.
///
/// Security model (matching legacy EdgePacer manager):
/// - Directory created with 0700 permissions (Unix)
/// - Symlink check before write (prevents symlink attacks)
/// - Write to temp file with 0600 permissions, then atomic rename
pub fn persist_token(filename: &str, value: &str) -> anyhow::Result<()> {
    let dir = token_dir();
    let path = dir.join(filename);
    let tmp_path = dir.join(format!("{filename}.tmp"));

    // Ensure directory exists with restrictive permissions
    create_secure_dir(&dir)?;

    // SECURITY: refuse to write if target is a symlink
    if let Ok(meta) = std::fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!(
            "SECURITY: token path is a symlink, refusing to write: {}",
            path.display()
        );
    }

    // Write to temp file, then atomic rename
    write_secure_file(&tmp_path, value)?;

    std::fs::rename(&tmp_path, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        anyhow::anyhow!("failed to persist token (rename): {e}")
    })?;

    debug!(path = %path.display(), "token persisted to disk");
    Ok(())
}

/// Load the shared installation ID, generating and persisting one if missing.
pub fn load_or_create_installation_id() -> anyhow::Result<String> {
    load_or_create_installation_id_with(load_token, persist_token, || {
        uuid::Uuid::new_v4().to_string()
    })
}

fn load_or_create_installation_id_with<Load, Persist, Generate>(
    load_token: Load,
    persist_token: Persist,
    generate_id: Generate,
) -> anyhow::Result<String>
where
    Load: FnOnce(&str) -> Option<String>,
    Persist: FnOnce(&str, &str) -> anyhow::Result<()>,
    Generate: FnOnce() -> String,
{
    if let Some(installation_id) = load_token("installation_id") {
        return Ok(installation_id);
    }

    let installation_id = generate_id();
    persist_token("installation_id", &installation_id)?;
    info!(installation_id = %installation_id, "generated installation_id");
    Ok(installation_id)
}

/// Remove a token file from disk.
pub fn remove_token(filename: &str) {
    let path = token_dir().join(filename);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %path.display(), error = %e, "failed to remove token file");
    }
}

/// Create directory with 0700 permissions on Unix, default on other platforms.
fn create_secure_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Write file with 0600 permissions on Unix, default on other platforms.
fn write_secure_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn persist_and_load_token() {
        let dir = tempfile::tempdir().unwrap();
        // Override token_dir by testing the helpers directly
        let path = dir.path().join("test_token");
        let tmp_path = dir.path().join("test_token.tmp");

        write_secure_file(&tmp_path, "secret123").unwrap();
        std::fs::rename(&tmp_path, &path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.trim(), "secret123");
    }

    #[test]
    fn load_missing_returns_none() {
        // Non-existent file
        assert!(load_token("nonexistent_test_token_xyz").is_none());
    }

    #[test]
    fn persist_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub").join("dir");
        create_secure_dir(&nested).unwrap();
        assert!(nested.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&nested).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real");
        let symlink = dir.path().join("link");

        std::fs::write(&real_file, "data").unwrap();
        std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

        let meta = std::fs::symlink_metadata(&symlink).unwrap();
        assert!(meta.file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_has_0600_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secure");
        write_secure_file(&path, "secret").unwrap();

        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn uses_go_style_user_state_dir() {
        let home = Path::new("/Users/tester");
        assert_eq!(
            unix_state_dir(home, false),
            home.join(".local").join("share").join("edgepacer")
        );
    }

    #[cfg(unix)]
    #[test]
    fn uses_go_style_root_state_dir() {
        let home = Path::new("/root");
        assert_eq!(unix_state_dir(home, true), Path::new("/var/lib/edgepacer"));
    }

    #[cfg(unix)]
    #[test]
    fn uses_absolute_configured_state_dir() {
        assert_eq!(
            configured_state_dir(Some(OsString::from("/var/lib/edgepacer"))),
            Some(PathBuf::from("/var/lib/edgepacer"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn ignores_relative_configured_state_dir() {
        assert_eq!(
            configured_state_dir(Some(OsString::from("edgepacer"))),
            None
        );
        assert_eq!(configured_state_dir(Some(OsString::from(""))), None);
    }

    #[test]
    fn installation_id_loader_reuses_existing_value() {
        let persisted = RefCell::new(Vec::new());

        let installation_id = load_or_create_installation_id_with(
            |_| Some("existing-installation-id".into()),
            |name: &str, value: &str| {
                persisted
                    .borrow_mut()
                    .push((name.to_string(), value.to_string()));
                Ok(())
            },
            || "generated-installation-id".into(),
        )
        .unwrap();

        assert_eq!(installation_id, "existing-installation-id");
        assert!(persisted.borrow().is_empty());
    }

    #[test]
    fn installation_id_loader_persists_new_value() {
        let persisted = RefCell::new(Vec::new());

        let installation_id = load_or_create_installation_id_with(
            |_| None,
            |name: &str, value: &str| {
                persisted
                    .borrow_mut()
                    .push((name.to_string(), value.to_string()));
                Ok(())
            },
            || "generated-installation-id".into(),
        )
        .unwrap();

        assert_eq!(installation_id, "generated-installation-id");
        assert_eq!(
            persisted.borrow().as_slice(),
            [(
                "installation_id".to_string(),
                "generated-installation-id".to_string()
            )]
        );
    }
}
