# Changelog

## Unreleased

- Publish the public EdgePacer repository under Apache-2.0 with NOTICE,
  SECURITY.md, DATA.md, and cargo-deny license/advisory policy.
- Publish the runtime image at `ghcr.io/logpacer/edgepacer` and the Helm chart at
  `oci://ghcr.io/logpacer/charts/edgepacer`.
- Sign GHCR image and chart releases with keyless Sigstore/cosign and publish
  GitHub provenance attestations.
- Publish Linux, macOS, and Windows standalone binaries to GitHub Releases with
  checksums, Sigstore bundles, and an Ed25519-signed update manifest.
- Require signed self-update metadata before the manager installs downloaded
  binaries.
- Include the vendored `logpacer_wire` crate as workspace source for clean
  self-contained public builds.
