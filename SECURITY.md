# Security

EdgePacer runs on customer hosts and may read logs, metrics, process metadata,
container metadata, Kubernetes metadata, and optional trace payloads. Treat
security reports as sensitive.

Data collection, egress, local state, and self-update integrity are documented
in `DATA.md`.

## Reporting

Use GitHub private vulnerability reporting for this repository when available.
If private reporting is unavailable, contact the Logpacer maintainers directly
and do not open a public issue with exploit details or customer data.

## Scope

In scope:

- vulnerabilities in the EdgePacer agent, manager, Helm chart, container image,
  or eBPF capture path
- authentication, token handling, update integrity, TLS, and outbound request
  handling
- accidental collection or disclosure of data beyond documented behavior

Out of scope:

- denial-of-service reports that require local administrative control of the
  host and do not cross a privilege boundary
- reports against third-party services not controlled by Logpacer

## Update Integrity

The manager refuses to install downloaded updates unless
`EDGEPACER_UPDATE_PUBLIC_KEY` is configured and the update response includes a
valid Ed25519 signature for the advertised version, platform, and SHA-256 digest.
See `DATA.md` for the update API signature contract.
