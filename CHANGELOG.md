# Changelog

## Unreleased

## 0.2.16 - 2026-08-19

- Track per-stream body-variant counts (`entry_json` / `raw_text` /
  `raw_bytes`) at the shipper classification seam, settle-exact: only
  delivered or adjudicated batches count, so deferred retries and 413-shrunk
  encodings never inflate them. The counts reach the control plane as
  `body_variants` on each stream status and re-send on the next interval
  tick when they change, never per increment.
- Carry container stream identity (stdout/stderr) on the wire: it was parsed
  and then discarded in every container lane until now, so each entry's
  envelope `metadata_json` gains `{"stream":"stderr"}` beside the optional
  resource identifier. The disk buffer encodes the stream as one
  backward-compatible trailer byte, so entries written before the upgrade
  still decode untagged. Multiline-assembled entries take their assembler's
  stream; plain-file sources carry none.

## 0.2.15 - 2026-08-13

- Multiline aggregation accepts an ordered `start_patterns` set instead of a
  single anchor, so a source carrying several line formats at once anchors
  each of them rather than gluing the unmatched formats onto the wrong event.
  The singular `start_pattern` is still accepted and hashes identically, so
  existing sources do not reconcile.
- Strip terminal escape sequences (colour, cursor moves, OSC) where a line
  enters the agent, on every source path and in samples. Colour codes sit in
  front of the bytes a start pattern anchors on, so a colourised source used
  to collapse into one unbounded event; they were also stored and shipped for
  nothing. Byte offsets still span the raw source bytes.
- Assemble container multiline events per output stream. stdout and stderr
  share one log but are separate conversations, so a request logged on stdout
  no longer lands inside a stack trace on stderr. Resume points are held back
  accordingly: neither the file checkpoint nor a streaming cursor advances
  past a line another stream is still buffering.
- Rejoin the json-file records Docker splits at 16K, per stream, so a long
  line ships as one entry instead of several fragments.
- Stop reporting the agent's own service units and log files as collectable
  sources, and refuse to sample them — collecting the agent's own output
  feeds it back into the agent, and sampling it teaches format detection the
  agent's format instead of the source's.

## 0.2.14 - 2026-08-12

- Stop double-reporting container runtime log files: file discovery now
  derives the runtime-owned log roots (Docker's data root, inspected
  per-container log paths, the Kubernetes pod log directory) and excludes
  them from file scanning while container discovery owns those logs. If the
  Docker socket is unreachable but its json-file tree is readable, those
  files are still discovered as a fallback — attributed as Docker json logs
  instead of anonymous plain files.
- Leave never-moving files out of the file census: a file whose mtime is
  older than `discovery.max_file_age_days` (default 7, tunable from the
  control plane) is not reported until it moves again, so dead log files
  stop being recommended for collection. Explicitly configured file paths
  are unaffected.
- Report `stopped_files` in the files census and stamp `full_report` on
  fresh-tracker cycles — including an empty full report when no files
  remain — so the control plane can retire file sources that disappeared,
  even while the agent was down.

## 0.2.13 - 2026-08-06

- `edgepacer-manager uninstall` now removes the installed binaries too: the
  agent binary plus its update leftovers (`.backup`, `.new`) and, on Linux and
  macOS, the manager binary itself (Windows cannot delete a running exe, so it
  is left with a note). The uninstall report also works from an interactive
  shell now — the control-plane URL is recovered from the installed
  supervisor config instead of failing on an unset `EDGEPACER_RAILS_URL`.

## 0.2.12 - 2026-08-06

- Ship eBPF-captured L7 requests as OTLP spans through the same Traces-arm
  wire contract as SDK spans, dual-shipped alongside the existing
  `RequestSignal` arm behind `ebpf.spans_otlp` (default on).
- Stop losing eBPF capture events on short buffers near mapped-page
  boundaries: probe reads are bounded and truncation is reported as a fault
  instead of silently dropping the event.
- Capture outbound writes at exit rather than entry, so failed writes no
  longer fabricate phantom protocol data, partial writes report only the
  bytes that reached the stream, and successful writes are captured.
- Resurrect dead L7 trackers when a recycled file descriptor opens a request
  in either direction, keeping long-lived connection reuse visible.

## 0.2.11 - 2026-07-29

- Prevent Docker API streams from re-shipping final container logs after
  reconnect: checkpoints fence the exact timestamp occurrence, and stopped or
  repeatedly missing containers park instead of retrying every 30 seconds.

## 0.2.10 - 2026-07-19

- Gzip every wire upload (`Content-Encoding: gzip`), cutting request-body
  egress by roughly 83% on the release corpus. Each body is compressed once
  and reused across retries, and `bytes_sent` now reports on-wire (compressed)
  bytes for logs, metrics, traces, self-telemetry, and eBPF. Receivers accept
  raw and gzip bodies, so mixed-version fleets keep working during rollout.

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
