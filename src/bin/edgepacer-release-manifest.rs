use anyhow::{Context, bail};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use edgepacer::manager::updater::{UPDATE_SIGNATURE_CONTEXT, update_signature_payload};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "edgepacer-release-manifest",
    about = "Generate the signed EdgePacer GitHub Release update manifest"
)]
struct Cli {
    #[arg(long)]
    version: Option<String>,

    #[arg(long, default_value = "LogPacer/edgepacer", env = "GITHUB_REPOSITORY")]
    repository: String,

    #[arg(long)]
    release_tag: Option<String>,

    #[arg(long, default_value = "dist")]
    dist_dir: PathBuf,

    #[arg(long, default_value = "update-manifest.json")]
    output: PathBuf,

    #[arg(long, default_value = "checksums.txt")]
    checksums_output: PathBuf,

    #[arg(long, env = "EDGEPACER_UPDATE_SIGNING_KEY")]
    signing_key_hex: String,

    #[arg(long)]
    print_public_key: bool,
}

#[derive(Debug, Serialize)]
struct Manifest {
    version: String,
    release_tag: String,
    repository: String,
    signature_algorithm: &'static str,
    signature_context: &'static str,
    release_public_key: String,
    assets: Vec<ManifestAsset>,
}

#[derive(Debug, Serialize)]
struct ManifestAsset {
    name: String,
    binary: String,
    platform: String,
    download_url: String,
    sha256: String,
    signature: String,
    sigstore_bundle_url: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let signing_key = signing_key_from_hex(&cli.signing_key_hex)?;
    if cli.print_public_key {
        println!("{}", hex::encode(signing_key.verifying_key().to_bytes()));
        return Ok(());
    }

    let version = cli
        .version
        .context("--version is required unless --print-public-key is used")?;
    let release_tag = cli.release_tag.unwrap_or_else(|| format!("v{version}"));
    let mut assets = release_assets(&cli.dist_dir, &release_tag, &cli.repository)?;

    for asset in &mut assets {
        let payload = update_signature_payload(&version, &asset.platform, &asset.sha256);
        let signature = signing_key.sign(payload.as_bytes());
        asset.signature = hex::encode(signature.to_bytes());
    }

    assets.sort_by(|a, b| {
        a.binary
            .cmp(&b.binary)
            .then(a.platform.cmp(&b.platform))
            .then(a.name.cmp(&b.name))
    });

    let manifest = Manifest {
        version,
        release_tag,
        repository: cli.repository,
        signature_algorithm: "Ed25519",
        signature_context: UPDATE_SIGNATURE_CONTEXT,
        release_public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        assets,
    };

    let output = resolve_output_path(&cli.dist_dir, &cli.output);
    let checksums_output = resolve_output_path(&cli.dist_dir, &cli.checksums_output);
    fs::write(&output, serde_json::to_string_pretty(&manifest)? + "\n")
        .with_context(|| format!("write {}", output.display()))?;
    fs::write(&checksums_output, checksums(&manifest))
        .with_context(|| format!("write {}", checksums_output.display()))?;

    Ok(())
}

fn release_assets(
    dist_dir: &Path,
    release_tag: &str,
    repository: &str,
) -> anyhow::Result<Vec<ManifestAsset>> {
    let mut assets = Vec::new();

    for entry in fs::read_dir(dist_dir).with_context(|| format!("read {}", dist_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let Some((binary, platform)) = parse_release_artifact_name(name) else {
            continue;
        };

        let sha256 = sha256_file(&path).with_context(|| format!("hash {}", path.display()))?;
        let download_url =
            format!("https://github.com/{repository}/releases/download/{release_tag}/{name}");

        assets.push(ManifestAsset {
            name: name.to_string(),
            binary,
            platform,
            download_url: download_url.clone(),
            sha256,
            signature: String::new(),
            sigstore_bundle_url: format!("{download_url}.sigstore.json"),
        });
    }

    if assets.is_empty() {
        bail!(
            "no EdgePacer release binaries found in {}",
            dist_dir.display()
        );
    }

    Ok(assets)
}

fn parse_release_artifact_name(name: &str) -> Option<(String, String)> {
    if name.ends_with(".sha256") || name.ends_with(".sigstore.json") {
        return None;
    }

    let name = name.strip_suffix(".exe").unwrap_or(name);

    if let Some(platform) = name.strip_prefix("edgepacer-manager-") {
        return Some(("edgepacer-manager".to_string(), platform.to_string()));
    }

    name.strip_prefix("edgepacer-")
        .map(|platform| ("edgepacer".to_string(), platform.to_string()))
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn signing_key_from_hex(raw: &str) -> anyhow::Result<SigningKey> {
    let raw = raw.trim();
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("EDGEPACER_UPDATE_SIGNING_KEY must be a 64-character hex Ed25519 seed");
    }

    let bytes = hex::decode(raw).context("decode EDGEPACER_UPDATE_SIGNING_KEY")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("EDGEPACER_UPDATE_SIGNING_KEY decoded to wrong length"))?;

    Ok(SigningKey::from_bytes(&bytes))
}

fn checksums(manifest: &Manifest) -> String {
    let mut lines = manifest
        .assets
        .iter()
        .map(|asset| format!("{}  {}", asset.sha256, asset.name))
        .collect::<Vec<_>>();
    lines.push(String::new());
    lines.join("\n")
}

fn resolve_output_path(dist_dir: &Path, output: &Path) -> PathBuf {
    if output.is_absolute() {
        output.to_path_buf()
    } else {
        dist_dir.join(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_artifact_names() {
        assert_eq!(
            parse_release_artifact_name("edgepacer-linux-amd64"),
            Some(("edgepacer".to_string(), "linux-amd64".to_string()))
        );
        assert_eq!(
            parse_release_artifact_name("edgepacer-manager-windows-amd64.exe"),
            Some(("edgepacer-manager".to_string(), "windows-amd64".to_string()))
        );
        assert_eq!(
            parse_release_artifact_name("edgepacer-linux-amd64.sha256"),
            None
        );
        assert_eq!(
            parse_release_artifact_name("edgepacer-linux-amd64.sigstore.json"),
            None
        );
        assert_eq!(parse_release_artifact_name("checksums.txt"), None);
    }

    #[test]
    fn checksums_use_release_file_names() {
        let manifest = Manifest {
            version: "1.2.3".to_string(),
            release_tag: "v1.2.3".to_string(),
            repository: "LogPacer/edgepacer".to_string(),
            signature_algorithm: "Ed25519",
            signature_context: UPDATE_SIGNATURE_CONTEXT,
            release_public_key: "public-key".to_string(),
            assets: vec![ManifestAsset {
                name: "edgepacer-linux-amd64".to_string(),
                binary: "edgepacer".to_string(),
                platform: "linux-amd64".to_string(),
                download_url: "https://example.test/edgepacer-linux-amd64".to_string(),
                sha256: "abc123".to_string(),
                signature: "def456".to_string(),
                sigstore_bundle_url: "https://example.test/edgepacer-linux-amd64.sigstore.json"
                    .to_string(),
            }],
        };

        assert_eq!(checksums(&manifest), "abc123  edgepacer-linux-amd64\n");
    }
}
