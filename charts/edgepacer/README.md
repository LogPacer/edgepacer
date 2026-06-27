# EdgePacer Helm chart

Deploys EdgePacer as a Kubernetes DaemonSet.

```bash
helm install edgepacer oci://ghcr.io/logpacer/charts/edgepacer \
  --set image.tag=stable \
  --set controlPlane.railsUrl=https://app.logpacer.com
```

## Following a release channel

`image.tag` selects how a deployment tracks releases:

| `image.tag` | Behavior |
|-------------|----------|
| `stable`    | Follows the LogPacer-governed **stable** channel (recommended for production). |
| `edge`      | Follows the **edge** channel (early releases). |
| `1.4.3`     | Pins an exact version, opting out of channel governance. |

A channel is a floating OCI tag that LogPacer moves onto the promoted release
digest whenever an operator repoints the channel. With `pullPolicy: Always`
(the default), pods adopt the channel's current target **on their next
restart** — this is next-restart, not continuous. For active reconciliation,
pair a channel tag with an image automation controller (e.g. Keel or Argo Image
Updater) or trigger a `kubectl rollout restart` after a promotion.

The image and its signature are verified by digest: moving a channel tag never
re-signs, so `cosign verify` against the channel tag resolves to the same signed
digest as the underlying version.

## Self-update vs. image tag

The in-pod `edgepacer-manager` performs signed self-updates for host installs.
In Kubernetes the durable version is the **image tag**, so a pod restart re-pulls
whatever the channel tag points at — pin `image.tag` to a channel (or an exact
version) and let the image, not in-pod self-update, govern the running version.
