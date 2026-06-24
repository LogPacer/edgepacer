# Kubernetes DaemonSet Install

EdgePacer runs as a DaemonSet so each node can collect node-local logs, metrics,
and optional OTLP HTTP traces.

## Install

Create the namespace and account-token Secret:

```bash
kubectl create namespace logpacer-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n logpacer-system create secret generic edgepacer-auth \
  --from-file=account-token=./logpacer-account-token \
  --dry-run=client -o yaml | kubectl apply -f -
```

Install the chart from GHCR:

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

For upgrades, use the same values with `helm upgrade --install`.

## What The Chart Creates

- DaemonSet running `ghcr.io/logpacer/edgepacer`
- ServiceAccount, ClusterRole, and ClusterRoleBinding for Kubernetes discovery
- hostPath state directory at `/var/lib/edgepacer`
- host log mounts for `/var/log`
- optional OTLP HTTP Service and NetworkPolicy

The chart expects the LogPacer account token to come from an existing Secret.
The token value should be supplied by file or Kubernetes Secret management, not
as a shell flag.

## Workload Opt-In

The DaemonSet may see host logs, but app-level Kubernetes collection only marks
pods as services when the pod opts in:

```yaml
metadata:
  labels:
    logpacer.com/service-name: api
```

Use a stable service name. The collector treats this label as the explicit
customer signal for app-level grouping.

## Trace Proxy Exposure

Enable node-local OTLP HTTP routing with:

```bash
--set traces.service.enabled=true \
--set traces.otlpHttp.enabled=true \
--set traces.otlpHttp.listenerConfiguredByControlPlane=true
```

The chart only publishes the Service and port. The control plane still controls
whether the agent listens for traces and which address it binds.

## eBPF

eBPF capture is disabled by default. Enable it only on clusters where the node
kernel and security policy allow the required capabilities:

```bash
--set ebpf.enabled=true
```

This adds `BPF`, `PERFMON`, and `SYS_RESOURCE` to the container capability set.

## Validation

Render and lint locally from a checkout:

```bash
helm lint charts/edgepacer
scripts/kubernetes/validate-kind.sh --render-only
```

Run a local kind validation:

```bash
scripts/kubernetes/validate-kind.sh --delete-cluster-on-exit
```

Run a strict validation against a pullable image and real backend token:

```bash
scripts/kubernetes/validate-kind.sh \
  --image-repository ghcr.io/logpacer/edgepacer \
  --image-tag latest \
  --account-token-file ./tmp/logpacer-account-token \
  --require-agent-ready
```
