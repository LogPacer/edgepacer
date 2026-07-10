#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
chart_dir="${repo_root}/charts/edgepacer"
output_dir="$(mktemp -d "${TMPDIR:-/tmp}/edgepacer-ebpf-chart.XXXXXX")"
trap 'rm -rf "${output_dir}"' EXIT

enabled_manifest="${output_dir}/enabled.yaml"
disabled_manifest="${output_dir}/disabled.yaml"

helm template edgepacer "${chart_dir}" \
  --set ebpf.enabled=true \
  --set runtimeSockets.containerd.enabled=true > "${enabled_manifest}"
helm template edgepacer "${chart_dir}" --set ebpf.enabled=false > "${disabled_manifest}"

host_root_environment="$(grep -A1 -F -- '- name: EDGEPACER_HOST_CGROUP_ROOT' "${enabled_manifest}")"
printf '%s\n' "${host_root_environment}" | grep -Fq -- 'value: /host/sys/fs/cgroup'

[[ "$(grep -Fc -- 'name: host-cgroup-root' "${enabled_manifest}")" -eq 2 ]]
host_cgroup_blocks="$(grep -A3 -F -- '- name: host-cgroup-root' "${enabled_manifest}")"
printf '%s\n' "${host_cgroup_blocks}" | grep -Fq -- 'mountPath: /host/sys/fs/cgroup'
printf '%s\n' "${host_cgroup_blocks}" | grep -Fq -- 'readOnly: true'
printf '%s\n' "${host_cgroup_blocks}" | grep -Fq -- 'hostPath:'
printf '%s\n' "${host_cgroup_blocks}" | grep -Fq -- 'path: /sys/fs/cgroup'
if grep -Fq -- 'mountPropagation:' "${enabled_manifest}"; then
  echo 'eBPF host cgroup mount must not use mount propagation' >&2
  exit 1
fi

runtime_environment="$(grep -A1 -F -- '- name: CONTAINER_RUNTIME_ENDPOINT' "${enabled_manifest}")"
printf '%s\n' "${runtime_environment}" | grep -Fq -- 'unix:///run/containerd/containerd.sock'
[[ "$(grep -Fc -- 'name: containerd-sock' "${enabled_manifest}")" -eq 2 ]]

if helm template edgepacer "${chart_dir}" --set ebpf.enabled=true >/dev/null 2>&1; then
  echo 'expected ebpf.enabled=true without a selected CRI runtime socket to fail' >&2
  exit 1
fi

crio_manifest="${output_dir}/crio.yaml"
helm template edgepacer "${chart_dir}" \
  --set ebpf.enabled=true \
  --set runtimeSockets.crio.enabled=true > "${crio_manifest}"
grep -A1 -F -- '- name: CONTAINER_RUNTIME_ENDPOINT' "${crio_manifest}" | \
  grep -Fq -- 'unix:///run/crio/crio.sock'
[[ "$(grep -Fc -- 'name: crio-sock' "${crio_manifest}")" -eq 2 ]]

if grep -Fq -- 'EDGEPACER_HOST_CGROUP_ROOT' "${disabled_manifest}"; then
  echo 'disabled eBPF rendering unexpectedly includes the host-root environment' >&2
  exit 1
fi
if grep -Fq -- 'name: host-cgroup-root' "${disabled_manifest}"; then
  echo 'disabled eBPF rendering unexpectedly includes the host cgroup mount' >&2
  exit 1
fi

if helm template edgepacer "${chart_dir}" \
  --set ebpf.enabled=true \
  --set runtimeSockets.containerd.enabled=true \
  --set hostPID=false >/dev/null 2>&1; then
  echo 'expected ebpf.enabled=true with hostPID=false to fail' >&2
  exit 1
fi

if helm template edgepacer "${chart_dir}" \
  --set ebpf.enabled=true \
  --set runtimeSockets.containerd.enabled=true \
  --set 'extraEnv[0].name=EDGEPACER_HOST_CGROUP_ROOT' \
  --set 'extraEnv[0].value=/tmp/untrusted-cgroup-root' >/dev/null 2>&1; then
  echo 'expected an eBPF host-root environment override to fail' >&2
  exit 1
fi
