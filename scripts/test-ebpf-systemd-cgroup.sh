#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(id -u)" -ne 0 ]]; then
  echo "systemd cgroup proof must run as root" >&2
  exit 1
fi

for command in systemctl systemd-run python3 stat readlink ps; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done
if [[ ! -x /usr/bin/python3 ]]; then
  echo "live proof requires /usr/bin/python3" >&2
  exit 1
fi

if [[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" != "systemd" ]]; then
  echo "PID 1 is not systemd" >&2
  exit 1
fi

system_state="$(systemctl is-system-running 2>/dev/null || true)"
if [[ "$system_state" != "running" && "$system_state" != "degraded" ]]; then
  echo "systemd is not operational: $system_state" >&2
  exit 1
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]] \
  || [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo "/sys/fs/cgroup is not a unified cgroup-v2 hierarchy" >&2
  exit 1
fi

if [[ "$(stat -L -c %i /sys/fs/cgroup)" != "1" ]]; then
  echo "/sys/fs/cgroup is not the host hierarchy root" >&2
  exit 1
fi

if [[ "$(readlink /proc/self/ns/cgroup)" != "cgroup:[4026531835]" ]]; then
  echo "proof requires the initial cgroup namespace" >&2
  exit 1
fi

cargo_bin="${CARGO:-cargo}"
if [[ ! -x "$cargo_bin" ]] && ! command -v "$cargo_bin" >/dev/null 2>&1; then
  echo "cargo executable not found: $cargo_bin" >&2
  exit 1
fi

cleanup_target=false
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  CARGO_TARGET_DIR="$(mktemp -d /tmp/edgepacer-systemd-cgroup.XXXXXX)"
  export CARGO_TARGET_DIR
  cleanup_target=true
fi

cleanup() {
  if [[ "$cleanup_target" == "true" ]]; then
    rm -rf -- "$CARGO_TARGET_DIR"
  fi
}
trap cleanup EXIT

"$cargo_bin" test --lib --features ebpf \
  live_exact_systemd_unit_resolves_and_revalidation_rejects_stop -- \
  --ignored --nocapture --test-threads=1
