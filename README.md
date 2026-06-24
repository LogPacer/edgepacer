# EdgePacer

EdgePacer is the LogPacer node agent. It tails host and container logs, collects
host metrics, can receive OTLP HTTP traces inside Kubernetes, and ships data to
the LogPacer control plane.

## Kubernetes Install

Create the namespace and account-token Secret:

```bash
kubectl create namespace logpacer-system
kubectl -n logpacer-system create secret generic edgepacer-auth \
  --from-file=account-token=./logpacer-account-token
```

Install the public Helm chart from GHCR:

```bash
helm install edgepacer oci://ghcr.io/logpacer/charts/edgepacer \
  --namespace logpacer-system \
  --set-string controlPlane.railsUrl=https://app.logpacer.com \
  --set auth.createSecret=false \
  --set-string auth.existingSecret=edgepacer-auth \
  --set-string auth.accountTokenKey=account-token \
  --set traces.service.enabled=true \
  --set traces.otlpHttp.enabled=true \
  --set traces.otlpHttp.listenerConfiguredByControlPlane=true
```

The chart deploys a DaemonSet, RBAC, host log mounts, and optional node-local
trace Service exposure. Workloads must opt in to app-level collection with the
`logpacer.com/service-name` pod label.

Set `manager.updatePublicKey` to the hex-encoded Ed25519 release public key to
enable manager self-updates. Without it, the deployed image runs normally but
downloaded binary updates are rejected.

## Local Checks

```bash
cargo fmt --all -- --check
cargo build --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
scripts/kubernetes/validate-kind.sh --render-only
```

On Linux, also compile the eBPF feature path:

```bash
cargo clippy --features ebpf --all-targets -- -D warnings
```

## Images And Charts

- Runtime image: `ghcr.io/logpacer/edgepacer`
- Helm chart: `oci://ghcr.io/logpacer/charts/edgepacer`
- Chart source: `charts/edgepacer`
- GitHub Release binaries:
  `edgepacer-linux-amd64`, `edgepacer-linux-arm64`,
  `edgepacer-windows-amd64.exe`

Release tags publish the container image, Helm chart, standalone binaries,
checksums, Sigstore bundles, and `update-manifest.json` through GitHub Actions.
macOS binaries are skipped by default so releases do not allocate hosted macOS
runners. To build them from a Mac when needed:

```bash
VERSION=0.1.9
scripts/release-package.sh --version "${VERSION}" --skip-manifest darwin-amd64 darwin-arm64
```

## Verify Releases

Release images, charts, and standalone binaries are signed keylessly with
Sigstore from the GitHub Actions release workflow and receive GitHub provenance
attestations. Standalone binaries are also listed in `checksums.txt` and in the
Ed25519-signed `update-manifest.json` used by manager self-updates.

```bash
VERSION=0.1.9

cosign verify ghcr.io/logpacer/edgepacer:${VERSION} \
  --certificate-identity-regexp '^https://github.com/LogPacer/edgepacer/.github/workflows/release.yml@refs/(tags/v|heads/main)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify ghcr.io/logpacer/charts/edgepacer:${VERSION} \
  --certificate-identity-regexp '^https://github.com/LogPacer/edgepacer/.github/workflows/release.yml@refs/(tags/v|heads/main)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/logpacer/edgepacer:${VERSION} \
  -R LogPacer/edgepacer

gh attestation verify oci://ghcr.io/logpacer/charts/edgepacer:${VERSION} \
  -R LogPacer/edgepacer

gh release download v${VERSION} -R LogPacer/edgepacer \
  --pattern edgepacer-linux-amd64 \
  --pattern edgepacer-linux-amd64.sigstore.json \
  --pattern checksums.txt \
  --pattern update-manifest.json

grep '  edgepacer-linux-amd64$' checksums.txt | shasum -a 256 -c -

cosign verify-blob edgepacer-linux-amd64 \
  --bundle edgepacer-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/LogPacer/edgepacer/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Release Key Setup

Manager self-updates use a pinned Ed25519 public key. Generate the GitHub
Actions signing seed and derive the install-time public key with:

```bash
export EDGEPACER_UPDATE_SIGNING_KEY="$(openssl rand -hex 32)"
cargo run --locked --bin edgepacer-release-manifest -- --print-public-key
```

Store `EDGEPACER_UPDATE_SIGNING_KEY` as a GitHub repository secret. Use the
printed public key as the Helm value `manager.updatePublicKey` or the
`EDGEPACER_UPDATE_PUBLIC_KEY` environment variable for standalone installs.

## Security And Data

- Security reporting: `SECURITY.md`
- Data collection, local state, egress, and update integrity: `DATA.md`

## License

EdgePacer is licensed under the Apache License, Version 2.0.
