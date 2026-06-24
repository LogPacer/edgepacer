# Local Kubernetes Validation

The local validation scripts prove that the Helm chart renders, installs, and
wires Kubernetes resources correctly before publishing a release.

## Requirements

- `helm`
- `kubectl`
- `kind` for local cluster validation
- Docker or another kind-compatible container runtime

## Render-Only Check

```bash
scripts/kubernetes/validate-kind.sh --render-only
```

This runs `helm lint`, renders the chart, and writes manifests under
`${TMPDIR:-/tmp}/edgepacer-k8s-validation`.

## Kind Check

```bash
scripts/kubernetes/validate-kind.sh --delete-cluster-on-exit
```

Default mode uses a dummy local account token and does not require the DaemonSet
to reach a real LogPacer backend. It validates namespace wiring, Secret wiring,
RBAC, scheduling, opt-in sample pods, and rendered trace Service resources.

For a strict run with a real backend token:

```bash
scripts/kubernetes/validate-kind.sh \
  --account-token-file ./tmp/logpacer-account-token \
  --image-repository ghcr.io/logpacer/edgepacer \
  --image-tag latest \
  --require-agent-ready
```

The token value is intentionally not accepted as a command-line flag.

## Authenticated Image Overrides

The default chart image is public:

```text
ghcr.io/logpacer/edgepacer
```

To validate an unreleased image, pass an image repository and tag:

```bash
scripts/kubernetes/validate-kind.sh \
  --image-repository ghcr.io/logpacer/edgepacer \
  --image-tag sha-<commit>
```

If the image requires authentication, create an image pull Secret from
environment variables:

```bash
export GHCR_USERNAME=<github-user-or-bot>
export GHCR_TOKEN=<token-with-read-package-access>

scripts/kubernetes/validate-kind.sh \
  --image-pull-secret ghcr-pull \
  --create-image-pull-secret \
  --require-agent-ready \
  --account-token-file ./tmp/logpacer-account-token
```

## Lima/k3s Check

kind proves the chart mechanics. Lima/k3s adds node realism for containerd,
host paths, and capability checks:

```bash
scripts/kubernetes/validate-lima-k3s.sh \
  --lima-instance edgepacer-k3s \
  --start-lima \
  --install-k3s \
  -- --account-token-file ./tmp/logpacer-account-token --require-agent-ready
```

Add `--enable-ebpf` when validating the eBPF capability profile on a node that
supports it.
