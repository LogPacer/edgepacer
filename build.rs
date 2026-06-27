use std::process::Command;

// Stamps the binary's reported version. Release builds get the clean version the
// pipeline supplies; local/untagged builds get `<version>-dev+<sha>[.dirty]`,
// computed from local git state only (no network). The dev marker makes a build
// unmanaged by the control plane and unpublishable — see scripts/container-image.sh.
fn main() {
    println!("cargo:rerun-if-env-changed=EDGEPACER_RELEASE_VERSION");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");

    println!("cargo:rustc-env=EDGEPACER_VERSION={}", resolve_version());
}

fn resolve_version() -> String {
    // Release builds: the pipeline supplies the clean, resolved version.
    if let Ok(release) = std::env::var("EDGEPACER_RELEASE_VERSION") {
        let release = release.trim();
        if !release.is_empty() {
            return release.to_string();
        }
    }

    // Local / untagged builds: mark as a dev build from local git state only.
    // Cargo sets CARGO_PKG_VERSION from Cargo.toml.
    let base = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = match git(&["status", "--porcelain"]) {
        Some(status) if !status.trim().is_empty() => ".dirty",
        _ => "",
    };

    format!("{base}-dev+{sha}{dirty}")
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
