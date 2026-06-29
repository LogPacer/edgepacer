# Changelog

## Unreleased

## 0.1.10 - 2026-06-29

- Accept OTLP trace ingestion over gRPC on a sibling `:4317` listener, alongside
  the existing OTLP/HTTP `:4318` receiver, sharing the same forward, disk-buffer,
  and auth path. Control-plane gated; off unless a gRPC listen address is configured.
- Ship Windows Event Logs as structured JSON parsed from `wevtutil` XML, in place
  of the raw `<Event>` XML. The live-query and EventRecordID resume/checkpoint
  engine is unchanged.
- Unify the `prost` dependency on 0.14 (drop the dual 0.13/0.14 pin) and bump
  `anyhow` to 1.0.103 (RUSTSEC-2026-0190).

## 0.1.9 - 2026-06-26

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
