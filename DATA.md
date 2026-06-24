# Data Handling

EdgePacer is an observability agent. It reads operational data from the host or
Kubernetes node where it runs and sends selected records to the configured
LogPacer control plane.

## Egress

The Kubernetes chart defaults to:

- control plane: `https://app.logpacer.com` on TCP 443
- image pull: `ghcr.io/logpacer/edgepacer`
- chart pull: `oci://ghcr.io/logpacer/charts/edgepacer`

The agent also talks to the Kubernetes API when Kubernetes discovery is enabled.
Self-updates may download binaries from GitHub Releases, the configured
control-plane host, `releases.logpacer.com`, `github.com`, or
`objects.githubusercontent.com`; non-localhost update downloads must use HTTPS
and must pass signature verification.

The chart's NetworkPolicy is currently ingress-only for the optional OTLP HTTP
trace Service. Clusters with default-deny egress should allow TCP 443 to the
configured control plane, the Kubernetes API, and any release/registry endpoints
used by the deployment process.

## Data Collected

Depending on configuration, EdgePacer may collect:

- host and container log lines from configured log paths and mounted pod logs
- bounded sample log lines when the control plane requests samples for format
  detection
- host metrics such as CPU, memory, disk, network, process, and package census
- container runtime metadata from Docker, containerd, or CRI-O sockets when
  those sockets are mounted
- Kubernetes metadata for pods, namespaces, labels, and owner relationships
- OTLP HTTP trace payloads sent to the optional trace listener
- eBPF-derived process, socket, protocol, and request telemetry when eBPF mode
  is enabled

EdgePacer does not scan arbitrary files by default. The Helm chart mounts
`/var/log` read-only by default and mounts `/var/log/pods` only when
`hostLogs.podLogs.enabled=true`. Runtime sockets are disabled unless explicitly
enabled in chart values.

## Local State

The chart stores local state under `/var/lib/edgepacer` by default. This may
include the installation id, bootstrap token material, SQLite/WAL buffer files,
checkpoints, and pending delivery data. The container root filesystem is
read-only; writable paths are the state volume and `/tmp`.

Buffer sizes are bounded by configuration. Relevant chart values and environment
variables include `agent.bufferCacheMb` / `EDGEPACER_BUFFER_CACHE_MB` and
`agent.shipBatchMaxMb` / `EDGEPACER_SHIP_BATCH_MAX_MB`.

## Authentication And Transport

The manager exchanges the account bootstrap token for a server bootstrap token
and passes only the server token to the child agent. Requests use bearer
authentication. HTTP clients use TLS certificate validation via Rustls and native
root certificates; there is no TLS verification opt-out.

## Update Integrity

Self-updates fail closed unless `EDGEPACER_UPDATE_PUBLIC_KEY` is configured with
the hex-encoded Ed25519 public key used for release signatures. The update API
must return:

- `version`
- `download_url`
- `sha256`
- `signature`

The signature is Ed25519 over this canonical payload:

```text
edgepacer-update-v1
version:<version>
platform:<platform>
sha256:<sha256>
```

The manager verifies the trusted download host, HTTPS, SHA-256 digest, and
signature before replacing the running binary.

GitHub Releases are the intended binary source. Each release includes:

- standalone binaries for Linux and Windows; macOS binaries are built separately
  when needed
- `checksums.txt`
- Sigstore bundle files (`*.sigstore.json`) for customer verification
- `update-manifest.json`, which Rails can read or cache to answer
  `/api/v1/managers/latest`

Rails should select the `binary == "edgepacer"` asset for the manager's
requested platform and return that asset's `download_url`, `sha256`, and
`signature`.
