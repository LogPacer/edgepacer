#!/usr/bin/env bash
# Prove host workload cgroup resolution from a private cgroup namespace.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "requires Linux" >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root (for example: sudo -E $0)" >&2
  exit 1
fi

for command in mount stat unshare; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "${command} is required" >&2
    exit 1
  fi
done
if [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo "/sys/fs/cgroup must be a cgroup-v2 hierarchy" >&2
  exit 1
fi
if [[ "$(stat -c %i /sys/fs/cgroup)" -ne 1 ]]; then
  echo "/sys/fs/cgroup must expose the host hierarchy root (inode 1)" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_cargo="${CARGO:-$(command -v cargo || true)}"
if [[ -z "${test_cargo}" ]] || ! command -v "${test_cargo}" >/dev/null 2>&1; then
  echo "cargo is required; run CARGO=/absolute/path/to/cargo sudo -E $0" >&2
  exit 1
fi
runtime_id="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
target_cgroup="/sys/fs/cgroup/edgepacer-private-target-${runtime_id}"
agent_cgroup="/sys/fs/cgroup/edgepacer-private-agent-$$"
original_path="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
if [[ -z "${original_path}" || "${original_path}" != /* ]]; then
  echo "could not determine the caller's unified cgroup" >&2
  exit 1
fi
if [[ "${original_path}" == "/" ]]; then
  original_cgroup="/sys/fs/cgroup"
else
  original_cgroup="/sys/fs/cgroup${original_path}"
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/edgepacer-private-cgroupns.XXXXXX")"
host_cgroup_root="${temporary}/host-cgroup"
target_pid=""

cleanup() {
  local status=$?
  trap - EXIT
  set +e

  # Leave the test cgroup before removing it.
  if [[ -f "${original_cgroup}/cgroup.procs" ]]; then
    printf '%s\n' "$$" > "${original_cgroup}/cgroup.procs"
  fi
  if [[ -n "${target_pid}" ]]; then
    kill "${target_pid}" >/dev/null 2>&1 || true
    wait "${target_pid}" >/dev/null 2>&1 || true
  fi
  rmdir "${target_cgroup}" >/dev/null 2>&1 || true
  rmdir "${agent_cgroup}" >/dev/null 2>&1 || true
  rmdir "${host_cgroup_root}" >/dev/null 2>&1 || true
  rmdir "${temporary}" >/dev/null 2>&1 || true

  exit "${status}"
}
trap cleanup EXIT

mkdir "${target_cgroup}" "${agent_cgroup}" "${host_cgroup_root}"
sleep 300 &
target_pid=$!
printf '%s\n' "${target_pid}" > "${target_cgroup}/cgroup.procs"
printf '%s\n' "$$" > "${agent_cgroup}/cgroup.procs"

expected_cgroup_id="$(stat -c %i "${target_cgroup}")"
expected_cgroup_level=1
test_target_dir="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/edgepacer-private-cgroup-target}"

export EDGEPACER_HOST_CGROUP_ROOT="${host_cgroup_root}"
export EDGEPACER_TEST_TARGET_PID="${target_pid}"
export EDGEPACER_TEST_RUNTIME_ID="${runtime_id}"
export EDGEPACER_TEST_CGROUP_ID="${expected_cgroup_id}"
export EDGEPACER_TEST_CGROUP_LEVEL="${expected_cgroup_level}"
export EDGEPACER_TEST_CARGO="${test_cargo}"
export EDGEPACER_TEST_CARGO_TARGET_DIR="${test_target_dir}"
export EDGEPACER_TEST_REPO_ROOT="${repo_root}"

run_private_cgroup_namespace() {
  set -euo pipefail
  umount /sys/fs/cgroup
  mount -t cgroup2 cgroup2 /sys/fs/cgroup

  test "$(stat -c %i /sys/fs/cgroup)" -ne 1
  test "$(stat -c %i "${EDGEPACER_HOST_CGROUP_ROOT}")" -eq 1
  cd "${EDGEPACER_TEST_REPO_ROOT}"
  CARGO_TARGET_DIR="${EDGEPACER_TEST_CARGO_TARGET_DIR}" \
    exec "${EDGEPACER_TEST_CARGO}" test --lib --features ebpf \
      private_namespace_resolves_a_host_target_anchor -- \
      --ignored --nocapture --test-threads=1
}

run_private_mount_namespace() {
  set -euo pipefail
  mount --make-rprivate /
  mount --bind /sys/fs/cgroup "${EDGEPACER_HOST_CGROUP_ROOT}"
  mount -o remount,bind,ro "${EDGEPACER_HOST_CGROUP_ROOT}"
  unshare --cgroup -- bash -c run_private_cgroup_namespace
}

export -f run_private_cgroup_namespace run_private_mount_namespace

# The outer mount namespace retains an inode-1 host view. The inner cgroup
# namespace remounts /sys/fs/cgroup so its root is the agent cgroup instead.
unshare --mount -- bash -c run_private_mount_namespace
