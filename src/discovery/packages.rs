//! Installed package discovery — enumerates system packages and their versions.
//!
//! Linux (Debian/Ubuntu): parses `/var/lib/dpkg/status` natively (RFC822 format).
//! Linux (RHEL/CentOS): shells out to `rpm -qa`.
//! macOS: reads Homebrew Cellar directory structure natively.
//! Produces `Package` structs matching legacy EdgePacer's JSON shape.

use serde::Serialize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tracing::debug;

/// A discovered installed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub manager: String,
}

/// Discover installed packages on the host.
pub async fn discover_packages() -> Result<Vec<Package>, String> {
    tokio::task::spawn_blocking(discover_packages_sync)
        .await
        .map_err(|e| format!("package discovery task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// dpkg: parse /var/lib/dpkg/status (Debian/Ubuntu)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";

/// Parse dpkg status file — RFC822 format with blank-line-separated records.
///
/// Each record has fields like:
/// ```text
/// Package: nginx
/// Status: install ok installed
/// Version: 1.18.0-6ubuntu2
/// ```
///
/// We include records where Status contains "installed" and not "deinstall".
#[cfg(target_os = "linux")]
fn discover_dpkg() -> Result<Vec<Package>, String> {
    let content = std::fs::read_to_string(DPKG_STATUS_PATH)
        .map_err(|e| format!("failed to read {DPKG_STATUS_PATH}: {e}"))?;

    let packages = parse_dpkg_status(&content);
    debug!(count = packages.len(), "discovered packages via dpkg");
    Ok(packages)
}

#[cfg(any(target_os = "linux", test))]
fn parse_dpkg_status(content: &str) -> Vec<Package> {
    let mut packages = Vec::new();

    // Split on blank lines to get individual package records
    for record in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut status = None;

        for line in record.lines() {
            if let Some(val) = line.strip_prefix("Package: ") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version: ") {
                version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Status: ") {
                status = Some(val.trim().to_string());
            }
        }

        // Only include actually installed packages.
        // dpkg Status format: "want flag status", e.g. "install ok installed"
        // Exclude deinstalled ("deinstall ok config-files") and not-installed ("purge ok not-installed").
        if let (Some(name), Some(version), Some(status)) = (name, version, status) {
            let status_parts: Vec<&str> = status.split_whitespace().collect();
            // The third word is the install state: "installed", "not-installed", "config-files", etc.
            let is_installed = status_parts.last().is_some_and(|s| *s == "installed");
            // The first word is the desired action: "install", "deinstall", "purge", etc.
            let is_wanted = status_parts
                .first()
                .is_some_and(|s| *s == "install" || *s == "hold");
            if is_installed && is_wanted {
                packages.push(Package {
                    name,
                    version,
                    manager: "apt".to_string(),
                });
            }
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// rpm: shell out to rpm -qa (RHEL/CentOS/Fedora)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn discover_rpm() -> Result<Vec<Package>, String> {
    let output = std::process::Command::new("rpm")
        .args(["-qa", "--queryformat", "%{NAME}|%{VERSION}\n"])
        .output()
        .map_err(|e| format!("failed to run rpm: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("rpm -qa failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<Package> = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '|');
            let name = parts.next()?.trim().to_string();
            let version = parts.next()?.trim().to_string();
            if name.is_empty() {
                return None;
            }
            Some(Package {
                name,
                version,
                manager: "yum".to_string(),
            })
        })
        .collect();

    debug!(count = packages.len(), "discovered packages via rpm");
    Ok(packages)
}

// ---------------------------------------------------------------------------
// brew: read Cellar directory (macOS)
// ---------------------------------------------------------------------------

/// Discover Homebrew packages by reading Cellar directory structure.
///
/// Each package is a directory in Cellar, with version subdirectories:
/// ```text
/// /opt/homebrew/Cellar/
///   git/
///     2.43.0/
///   openssl@3/
///     3.2.0/
/// ```
#[cfg(target_os = "macos")]
fn discover_brew() -> Result<Vec<Package>, String> {
    let cellar_paths = ["/opt/homebrew/Cellar", "/usr/local/Cellar"];

    let cellar_path = cellar_paths
        .iter()
        .find(|p| std::path::Path::new(p).is_dir())
        .ok_or_else(|| "no Homebrew Cellar found".to_string())?;

    parse_brew_cellar(cellar_path)
}

#[cfg(target_os = "macos")]
fn parse_brew_cellar(cellar_path: &str) -> Result<Vec<Package>, String> {
    let entries =
        std::fs::read_dir(cellar_path).map_err(|e| format!("failed to read {cellar_path}: {e}"))?;

    let mut packages = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !entry.path().is_dir() {
            continue;
        }

        // Version is the first (usually only) subdirectory
        let version = match std::fs::read_dir(entry.path()) {
            Ok(versions) => versions
                .flatten()
                .filter(|v| v.path().is_dir())
                .map(|v| v.file_name().to_string_lossy().to_string())
                .max() // take highest version if multiple
                .unwrap_or_default(),
            Err(_) => continue,
        };

        packages.push(Package {
            name,
            version,
            manager: "brew".to_string(),
        });
    }

    debug!(
        count = packages.len(),
        "discovered packages via brew Cellar"
    );
    Ok(packages)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn discover_packages_sync() -> Result<Vec<Package>, String> {
    // Try dpkg first (Debian/Ubuntu), then rpm (RHEL/CentOS)
    if std::path::Path::new(DPKG_STATUS_PATH).exists() {
        return discover_dpkg();
    }
    discover_rpm()
}

#[cfg(target_os = "macos")]
fn discover_packages_sync() -> Result<Vec<Package>, String> {
    discover_brew()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn discover_packages_sync() -> Result<Vec<Package>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DPKG_STATUS: &str = r#"Package: nginx
Status: install ok installed
Priority: optional
Section: httpd
Installed-Size: 1234
Version: 1.18.0-6ubuntu2
Description: high-performance web server

Package: libssl3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 5678
Version: 3.0.2-0ubuntu1
Description: Secure Sockets Layer toolkit

Package: old-removed-pkg
Status: deinstall ok config-files
Priority: optional
Section: misc
Version: 0.1.0-1
Description: a package that was removed

Package: not-installed
Status: purge ok not-installed
Priority: optional
Section: misc
Version: 2.0.0
Description: never fully installed
"#;

    #[test]
    fn parse_dpkg_installed_packages() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert_eq!(packages.len(), 2);

        assert_eq!(packages[0].name, "nginx");
        assert_eq!(packages[0].version, "1.18.0-6ubuntu2");
        assert_eq!(packages[0].manager, "apt");

        assert_eq!(packages[1].name, "libssl3");
        assert_eq!(packages[1].version, "3.0.2-0ubuntu1");
    }

    #[test]
    fn parse_dpkg_excludes_deinstalled() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert!(
            !packages.iter().any(|p| p.name == "old-removed-pkg"),
            "deinstalled packages should be excluded"
        );
    }

    #[test]
    fn parse_dpkg_excludes_not_installed() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert!(
            !packages.iter().any(|p| p.name == "not-installed"),
            "not-installed packages should be excluded"
        );
    }

    #[test]
    fn parse_dpkg_empty_input() {
        let packages = parse_dpkg_status("");
        assert!(packages.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn discover_brew_if_cellar_exists() {
        // Only run if brew is actually installed
        if std::path::Path::new("/opt/homebrew/Cellar").is_dir()
            || std::path::Path::new("/usr/local/Cellar").is_dir()
        {
            let packages = discover_brew().unwrap();
            assert!(
                !packages.is_empty(),
                "brew should find at least one package"
            );
            assert!(packages.iter().all(|p| p.manager == "brew"));
            assert!(packages.iter().all(|p| !p.name.is_empty()));
            assert!(packages.iter().all(|p| !p.version.is_empty()));
        }
    }

    #[tokio::test]
    async fn discover_packages_runs() {
        let result = discover_packages().await;
        // On macOS with brew, should succeed. On CI without either, may error — that's fine.
        if let Ok(packages) = result {
            for pkg in &packages {
                assert!(!pkg.name.is_empty());
                assert!(!pkg.manager.is_empty());
            }
        }
    }
}
