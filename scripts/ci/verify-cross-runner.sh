#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"
preflight_image="${EDGEPACER_CROSS_PREFLIGHT_IMAGE:-alpine:3.20}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_path() {
  local label="$1"
  local path="$2"

  [[ -e "${path}" ]] || die "${label} does not exist: ${path}"
}

check_container_in_container_driver() {
  if [[ "${CROSS_CONTAINER_IN_CONTAINER:-}" != "true" ]]; then
    return 0
  fi

  if [[ -z "${HOSTNAME:-}" ]]; then
    die "CROSS_CONTAINER_IN_CONTAINER=true but HOSTNAME is not set"
  fi

  local graph_driver
  graph_driver="$(docker inspect "${HOSTNAME}" --format '{{json .GraphDriver}}' 2>/dev/null || true)"

  if [[ -z "${graph_driver}" || "${graph_driver}" == "null" ]]; then
    die "CROSS_CONTAINER_IN_CONTAINER=true but Docker inspect exposes no GraphDriver for ${HOSTNAME}; cross cannot map runner-container paths on this Docker storage driver"
  fi
}

check_docker_path_visibility() {
  local output

  if output="$(
    docker run --rm \
      --mount "type=bind,source=${repo_root},target=${repo_root},readonly" \
      --mount "type=bind,source=${cargo_home},target=${cargo_home},readonly" \
      --mount "type=bind,source=${rustup_home},target=${rustup_home},readonly" \
      --env "WORKSPACE=${repo_root}" \
      --env "CARGO_HOME=${cargo_home}" \
      --env "RUSTUP_HOME=${rustup_home}" \
      "${preflight_image}" \
      sh -eu -c '
        test -f "${WORKSPACE}/Cargo.toml"
        test -e "${CARGO_HOME}/bin/cargo"
        test -d "${RUSTUP_HOME}/toolchains"
      ' 2>&1
  )"; then
    return 0
  fi

  printf '%s\n' "${output}" >&2
  die "Docker cannot see the release workspace/Rust paths from the same absolute paths as the runner; run release cross builds on a native runner or mount RUNNER_WORKDIR, CARGO_HOME, and RUSTUP_HOME at identical host/container paths"
}

main() {
  require_command docker
  docker version >/dev/null

  require_path "workspace" "${repo_root}"
  require_path "CARGO_HOME" "${cargo_home}"
  require_path "RUSTUP_HOME" "${rustup_home}"

  check_container_in_container_driver
  check_docker_path_visibility

  printf 'cross runner preflight passed\n'
}

main "$@"
