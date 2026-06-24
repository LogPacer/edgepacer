#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

lima_instance="edgepacer-k3s"
local_api_port="16443"
output_dir="${TMPDIR:-/tmp}/edgepacer-lima-k3s-validation"
start_lima=0
install_k3s=0
enable_ebpf=0
skip_node_checks=0
cleanup_requested=0
tunnel_pid=""
validate_args=()

usage() {
  cat <<'USAGE'
Validate EdgePacer DaemonSet mode against k3s running inside a Lima VM.

Usage:
  scripts/kubernetes/validate-lima-k3s.sh [lima options] [-- validate-kind options]

Default behavior:
  - require an existing, running Lima VM
  - require k3s to already be installed in that VM
  - open an SSH local port forward to the k3s API server
  - fetch a temporary kubeconfig under --output-dir
  - run scripts/kubernetes/validate-kind.sh --use-existing-cluster with k3s/containerd overrides
  - print node-realism diagnostics from inside the Lima VM

Lima options:
  --lima-instance NAME   Lima instance name. Default: edgepacer-k3s
  --start-lima           Start the existing Lima instance before validation.
  --install-k3s          Install k3s with the official installer when absent.
  --local-api-port PORT  Host port for the k3s API SSH tunnel. Default: 16443
  --output-dir PATH      Directory for generated kubeconfig and rendered YAML.
  --enable-ebpf          Add the chart eBPF capability profile.
  --skip-node-checks     Skip Lima-side node path/capability diagnostics.
  -h, --help             Show this help.

All arguments after -- are passed to validate-kind.sh. Useful examples:
  -- --account-token-file ./tmp/logpacer-token --require-agent-ready
  -- --image-repository ghcr.io/logpacer/edgepacer --image-tag k8s-validation
  -- --cleanup

Examples:
  scripts/kubernetes/validate-lima-k3s.sh --lima-instance ebpf-spike --start-lima --install-k3s
  scripts/kubernetes/validate-lima-k3s.sh --lima-instance ebpf-spike --enable-ebpf -- --require-agent-ready --account-token-file ./tmp/logpacer-token
USAGE
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  if [[ -n "${tunnel_pid}" ]] && kill -0 "${tunnel_pid}" >/dev/null 2>&1; then
    kill "${tunnel_pid}" >/dev/null 2>&1 || true
    wait "${tunnel_pid}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

local_port_open() {
  (echo >"/dev/tcp/127.0.0.1/${local_api_port}") >/dev/null 2>&1
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --)
        shift
        validate_args+=("$@")
        break
        ;;
      --lima-instance)
        lima_instance="${2:?missing value for --lima-instance}"
        shift 2
        ;;
      --local-api-port)
        local_api_port="${2:?missing value for --local-api-port}"
        shift 2
        ;;
      --output-dir)
        output_dir="${2:?missing value for --output-dir}"
        shift 2
        ;;
      --start-lima)
        start_lima=1
        shift
        ;;
      --install-k3s)
        install_k3s=1
        shift
        ;;
      --enable-ebpf)
        enable_ebpf=1
        shift
        ;;
      --skip-node-checks)
        skip_node_checks=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --cleanup)
        cleanup_requested=1
        validate_args+=("$1")
        shift
        ;;
      *)
        validate_args+=("$1")
        shift
        ;;
    esac
  done
}

normalize_args() {
  local arg
  for arg in "${validate_args[@]}"; do
    if [[ "${arg}" == "--cleanup" ]]; then
      cleanup_requested=1
    fi
  done
}

lima_status() {
  limactl list --format '{{.Status}}' "${lima_instance}" 2>/dev/null || true
}

ensure_lima() {
  local status
  status="$(lima_status)"
  [[ -n "${status}" ]] || die "Lima instance not found: ${lima_instance}"

  if [[ "${status}" != "Running" ]]; then
    [[ "${start_lima}" -eq 1 ]] || die "Lima instance ${lima_instance} is ${status}; pass --start-lima to start it"
    log "Starting Lima instance: ${lima_instance}"
    limactl shell --start "${lima_instance}" true
  fi
}

install_k3s_if_requested() {
  if limactl shell "${lima_instance}" test -f /etc/rancher/k3s/k3s.yaml; then
    log "k3s kubeconfig exists in Lima instance: ${lima_instance}"
    return
  fi

  [[ "${install_k3s}" -eq 1 ]] || die "k3s is not installed in ${lima_instance}; pass --install-k3s to install it"

  log "Installing k3s in Lima instance: ${lima_instance}"
  limactl shell "${lima_instance}" bash -lc \
    'set -euo pipefail
installer="$(mktemp)"
cleanup() { rm -f "${installer}"; }
trap cleanup EXIT
chmod 0600 "${installer}"
curl -fsSL https://get.k3s.io -o "${installer}"
sha256sum "${installer}" >&2
sudo env INSTALL_K3S_EXEC="server --write-kubeconfig-mode=644 --disable=traefik" sh "${installer}"'
}

ssh_config_file() {
  limactl list --format '{{.SSHConfigFile}}' "${lima_instance}"
}

ssh_host_alias() {
  local config_file="$1"
  awk '/^Host / { print $2; exit }' "${config_file}"
}

start_k3s_tunnel() {
  local config_file host_alias
  config_file="$(ssh_config_file)"
  [[ -f "${config_file}" ]] || die "Lima SSH config not found: ${config_file}"
  host_alias="$(ssh_host_alias "${config_file}")"
  [[ -n "${host_alias}" ]] || die "could not find host alias in ${config_file}"

  log "Opening k3s API tunnel on 127.0.0.1:${local_api_port}"
  ssh -F "${config_file}" \
    -S none \
    -o ExitOnForwardFailure=yes \
    -o ControlMaster=no \
    -N \
    -L "127.0.0.1:${local_api_port}:127.0.0.1:6443" \
    "${host_alias}" &
  tunnel_pid=$!

  for _ in $(seq 1 30); do
    kill -0 "${tunnel_pid}" >/dev/null 2>&1 || die "failed to start SSH tunnel to ${lima_instance}"
    if local_port_open; then
      return
    fi
    sleep 1
  done

  die "SSH tunnel did not open 127.0.0.1:${local_api_port}"
}

write_kubeconfig() {
  local raw_kubeconfig="${output_dir}/k3s.raw.yaml"
  local kubeconfig="${output_dir}/k3s.yaml"

  mkdir -p "${output_dir}"
  (
    umask 077
    limactl shell "${lima_instance}" sudo cat /etc/rancher/k3s/k3s.yaml > "${raw_kubeconfig}"
    sed -E "s#server: https://[^:]+:6443#server: https://127.0.0.1:${local_api_port}#" \
      "${raw_kubeconfig}" > "${kubeconfig}"
  )
  printf '%s\n' "${kubeconfig}"
}

wait_for_k3s_api() {
  local kubeconfig="$1"

  for _ in $(seq 1 45); do
    if KUBECONFIG="${kubeconfig}" kubectl get nodes >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  KUBECONFIG="${kubeconfig}" kubectl cluster-info || true
  die "k3s API did not become reachable through 127.0.0.1:${local_api_port}"
}

run_chart_validation() {
  local kubeconfig="$1"
  local args=(
    "--use-existing-cluster"
    "--output-dir" "${output_dir}"
    "--helm-set" "runtimeSockets.containerd.enabled=true"
    "--helm-set-string" "runtimeSockets.containerd.path=/run/k3s/containerd/containerd.sock"
  )

  if [[ "${enable_ebpf}" -eq 1 ]]; then
    args+=("--helm-set" "ebpf.enabled=true")
  fi

  args+=("${validate_args[@]}")

  KUBECONFIG="${kubeconfig}" "${repo_root}/scripts/kubernetes/validate-kind.sh" "${args[@]}"
}

print_node_checks() {
  if [[ "${skip_node_checks}" -eq 1 || "${cleanup_requested}" -eq 1 ]]; then
    return
  fi

  log ""
  log "Lima/k3s node diagnostics"
  limactl shell "${lima_instance}" bash -lc '
set -euo pipefail

echo "Kernel:"
uname -a

echo
echo "k3s node:"
sudo k3s kubectl get nodes -o wide || true

echo
echo "containerd socket:"
if sudo test -S /run/k3s/containerd/containerd.sock; then
  echo "PASS /run/k3s/containerd/containerd.sock"
else
  echo "FAIL /run/k3s/containerd/containerd.sock missing"
fi

echo
echo "CRI containers:"
sudo k3s crictl ps | head -n 12 || true

echo
echo "pod log files:"
sudo find /var/log/pods -type f -name "*.log" | head -n 12 || true

echo
echo "sample workload log validation:"
sudo grep -R -m 1 "edgepacer opted-in log line" /var/log/pods || true
sudo grep -R -m 1 "edgepacer not-opted-in log line" /var/log/pods || true

echo
echo "host metrics inputs:"
cat /proc/loadavg
grep -E "^(MemTotal|MemAvailable):" /proc/meminfo

echo
echo "eBPF capability inputs:"
if test -r /sys/kernel/btf/vmlinux; then
  ls -lh /sys/kernel/btf/vmlinux
else
  echo "BTF missing: /sys/kernel/btf/vmlinux"
fi
cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
'
}

main() {
  parse_args "$@"
  normalize_args
  require_cmd limactl
  require_cmd ssh
  require_cmd kubectl
  require_cmd helm

  ensure_lima
  install_k3s_if_requested

  local kubeconfig
  start_k3s_tunnel
  kubeconfig="$(write_kubeconfig)"
  wait_for_k3s_api "${kubeconfig}"
  run_chart_validation "${kubeconfig}"
  print_node_checks
}

main "$@"
