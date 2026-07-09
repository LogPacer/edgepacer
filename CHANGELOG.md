# Changelog

## Unreleased

## 0.2.2 - 2026-07-09

- Build release binaries with fat LTO and a single codegen unit, shrinking the
  agent binary by roughly 25% and improving optimized codegen. Symbols are kept
  so panic backtraces stay readable in self-telemetry. Code-identical to 0.2.1
  otherwise.

## 0.2.1 - 2026-07-08

- Never report a live workload as stopped behind exited replicas. Orchestrators
  like Kamal leave prior-deploy containers exited beside the live one; the
  census could pick a leftover as the workload's representative, showing a
  running service as stopped with a stale SHA. Live containers now always win
  representation, and census state is reported per instance.

## 0.2.0 - 2026-07-08

- Collect by selector-backed service descriptions: the unified config's ordered
  `services` array — each entry a selector over identifier atoms plus a collect
  payload — now drives collection, with array order as match priority. The
  Kubernetes gate on service collection is lifted.
- Census fidelity: report normalized identifier atoms per container, track
  replica groups with per-replica `active_instances`, reconcile on
  discovery-epoch change (not just config checksum), and mark full re-emits
  with `full_report` so the control plane can distinguish them from deltas.
- Dependency bumps: bollard 0.21, sha2 0.11; drop redb from
  LICENSE-3rdparty.csv.

## 0.1.23 - 2026-07-07

- Sample Windows Event Log channels as structured JSON instead of rendered
  text.
- Manager fixes: `--version` reports the release-stamped version, run flags are
  accepted after the subcommand, and uninstall removes the token file.
- Drop redb and the one-shot legacy migration.
- Bump crossbeam-epoch to 0.9.20 (RUSTSEC-2026-0204).

## 0.1.22 - 2026-07-06

- Treat locally readable Docker json-file logs as their own source: strip the
  outer Docker `{log,stream,time}` wrapper before sampling and shipping (while
  preserving checkpoint offsets against the raw wrapper bytes), classify the
  container's payload format after framing removal, and ship JSON object log
  bodies as structured wire entries.

## 0.1.21 - 2026-07-06

- Assemble multiline entries in the streaming readers.

## 0.1.20 - 2026-07-03

- Trust the OS certificate store alongside the bundled webpki roots. The
  webpki-only switch fixed cold-schannel GitHub downloads on Windows but
  silently dropped private-CA trust; both root sets now merge, so private-CA
  endpoints (enterprise TLS-intercepting proxies) verify from the OS store
  while public-CA endpoints keep verifying from the bundled roots.

## 0.1.19 - 2026-07-01

- Honor the control plane's `full_resync_required` census response on every
  inventory lane (containers, services, files, journald, processes, ports,
  Windows event logs, packages), not just packages. The flag now clears the
  committed container/file/service maps so the next scan re-reports the full
  inventory, healing orphaned control-plane rows without an agent restart. Any
  lane's response carrying the one-shot flag resets all lanes.

## 0.1.18 - 2026-07-01

- Derive stable container ids from Kamal labels so redeploys keep container
  identity.
- Split the agent and manager release streams.

## 0.1.17 - 2026-06-30

- Manager: cross-platform install/uninstall lifecycle — the manager acts as the
  supervisor, with Linux-only supervisor items gated so the macOS release
  builds.

## 0.1.16 - 2026-06-30

- Manager: explicit update endpoints and a manual `update` subcommand,
  decoupling manager updates from the agent.

## 0.1.15 - 2026-06-30

- Manager reports its stamped version and gains opt-in self-update.

## 0.1.14 - 2026-06-30

- Windows log-source support: Event Log channel discovery and sampling, UTF-16
  file tailing, and manager self-heal.

_Versions 0.1.12 and 0.1.13 were never released._

## 0.1.11 - 2026-06-30

- Windows support: native process and port discovery, real total-memory
  reporting, self-update, and cross-compiled release stamping.

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
