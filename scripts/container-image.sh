#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

image="ghcr.io/logpacer/edgepacer"
platforms="linux/amd64,linux/arm64"
builder="edgepacer-image-builder"
tag=""
version=""
revision=""
created=""
stage_dir="${repo_root}/.docker-stage"
build_binaries=0
dry_run=0
push=0
local_load=0
tag_latest=0
attest=1

usage() {
  cat <<'USAGE'
Build the EdgePacer runtime container image from staged release binaries.

Usage:
  scripts/container-image.sh [options]

Options:
  --attest / --no-attest     Add SBOM and provenance attestations when pushing. Default: --attest.
  --build-binaries           Run build-all.sh for the requested Linux platforms before building the image.
  --builder NAME             Docker buildx builder name. Default: edgepacer-image-builder.
  --dry-run                  Print commands without running them.
  --image IMAGE              Image repository. Default: ghcr.io/logpacer/edgepacer.
  --latest                   Also tag the image as latest.
  --local                    Build and load only the host Docker platform.
  --platforms LIST           Buildx platforms. Default: linux/amd64,linux/arm64.
  --push                     Push a multi-arch image. Required for multi-platform output.
  --tag TAG                  Image tag. Default: sha-<git short sha>.
  --version VERSION          Version label. Default: Cargo.toml package version.
  --revision SHA             Revision label. Default: current git commit.
  --created TIMESTAMP        Created label. Default: current UTC time.
  -h, --help                 Show this help.

Examples:
  scripts/container-image.sh --local
  scripts/container-image.sh --build-binaries --push --tag k8s-validation
USAGE
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

run() {
  log "+ $*"
  if [[ "${dry_run}" -eq 0 ]]; then
    "$@"
  fi
}

run_from_repo_root() {
  log "+ cd ${repo_root}"
  log "+ $*"
  if [[ "${dry_run}" -eq 0 ]]; then
    (cd "${repo_root}" && "$@")
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --attest)
        attest=1
        shift
        ;;
      --no-attest)
        attest=0
        shift
        ;;
      --build-binaries)
        build_binaries=1
        shift
        ;;
      --builder)
        builder="${2:?missing value for --builder}"
        shift 2
        ;;
      --dry-run)
        dry_run=1
        shift
        ;;
      --image)
        image="${2:?missing value for --image}"
        shift 2
        ;;
      --latest)
        tag_latest=1
        shift
        ;;
      --local)
        local_load=1
        shift
        ;;
      --platforms)
        platforms="${2:?missing value for --platforms}"
        shift 2
        ;;
      --push)
        push=1
        shift
        ;;
      --tag)
        tag="${2:?missing value for --tag}"
        shift 2
        ;;
      --version)
        version="${2:?missing value for --version}"
        shift 2
        ;;
      --revision)
        revision="${2:?missing value for --revision}"
        shift 2
        ;;
      --created)
        created="${2:?missing value for --created}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

normalize_args() {
  if [[ "${local_load}" -eq 1 && "${push}" -eq 1 ]]; then
    die "--local and --push cannot be combined"
  fi
}

host_platform() {
  case "$(uname -m)" in
    arm64|aarch64) printf 'linux/arm64\n' ;;
    x86_64|amd64) printf 'linux/amd64\n' ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac
}

docker_arch() {
  case "$1" in
    linux/amd64) printf 'amd64\n' ;;
    linux/arm64) printf 'arm64\n' ;;
    *) die "unsupported image platform: $1" ;;
  esac
}

build_target_for_platform() {
  case "$1" in
    linux/amd64) printf 'linux-amd64\n' ;;
    linux/arm64) printf 'linux-arm64\n' ;;
    *) die "unsupported image platform: $1" ;;
  esac
}

split_platforms() {
  IFS=',' read -r -a selected_platforms <<< "$1"
}

default_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1
}

prepare_defaults() {
  revision="${revision:-$(git -C "${repo_root}" rev-parse HEAD)}"
  local short_revision="${revision:0:12}"
  tag="${tag:-sha-${short_revision}}"
  version="${version:-$(default_version)}"
  created="${created:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
  guard_publishable_version
}

# A dev-marked build must never reach a public registry. The dev marker doubles
# as a publish guard: a -dev version aborts any push (including its :latest and
# channel tags), so a local build cannot clobber published artifacts by accident.
guard_publishable_version() {
  if [[ "${push}" -eq 1 && "${version}" == *-dev* ]]; then
    echo "error: refusing to publish a dev-marked version: ${version}" >&2
    exit 1
  fi
}

ensure_builder() {
  if [[ "${dry_run}" -eq 1 ]]; then
    run docker buildx inspect "${builder}"
    return
  fi

  require_cmd docker

  if ! docker buildx inspect "${builder}" >/dev/null 2>&1; then
    run docker buildx create --name "${builder}" --use --bootstrap
  else
    run docker buildx use "${builder}"
  fi
}

build_binaries_if_requested() {
  if [[ "${build_binaries}" -ne 1 ]]; then
    return 0
  fi

  local selected_platforms=()
  if [[ "${local_load}" -eq 1 ]]; then
    selected_platforms=("$(host_platform)")
  else
    split_platforms "${platforms}"
  fi

  local build_targets=()
  for platform in "${selected_platforms[@]}"; do
    build_targets+=("$(build_target_for_platform "${platform}")")
  done

  run_from_repo_root "${repo_root}/build-all.sh" "${build_targets[@]}"
}

ensure_staged_binaries() {
  local selected_platforms=()
  if [[ "${local_load}" -eq 1 ]]; then
    selected_platforms=("$(host_platform)")
  else
    split_platforms "${platforms}"
  fi

  for platform in "${selected_platforms[@]}"; do
    local arch
    arch="$(docker_arch "${platform}")"
    for binary in edgepacer edgepacer-manager; do
      local path="${stage_dir}/${arch}/${binary}"
      if [[ "${dry_run}" -eq 1 ]]; then
        log "Would require staged binary: ${path}"
        continue
      fi
      [[ -x "${path}" ]] || die "missing staged binary: ${path}. Run build-all.sh or pass --build-binaries."
    done
  done
}

build_image() {
  local build_platforms="${platforms}"
  local output_arg="--push"
  local build_args=()
  local tags=()

  if [[ "${local_load}" -eq 1 ]]; then
    build_platforms="$(host_platform)"
    output_arg="--load"
  elif [[ "${push}" -ne 1 ]]; then
    die "multi-platform image builds require --push. Use --local for a local single-platform image."
  fi

  tags=(-t "${image}:${tag}")
  local short_revision="${revision:0:12}"
  if [[ "${tag}" != "sha-${short_revision}" ]]; then
    tags+=(-t "${image}:sha-${short_revision}")
  fi
  if [[ "${tag_latest}" -eq 1 ]]; then
    tags+=(-t "${image}:latest")
  fi

  build_args=(
    buildx build
    --builder "${builder}"
    --platform "${build_platforms}"
    --build-arg "VERSION=${version}"
    --build-arg "REVISION=${revision}"
    --build-arg "CREATED=${created}"
  )
  build_args+=("${tags[@]}")

  if [[ "${push}" -eq 1 && "${attest}" -eq 1 ]]; then
    build_args+=(--sbom=true --provenance=mode=max)
  else
    build_args+=(--provenance=false)
  fi

  build_args+=("${output_arg}" "${repo_root}")

  run docker "${build_args[@]}"
}

main() {
  parse_args "$@"
  normalize_args
  prepare_defaults
  build_binaries_if_requested
  ensure_staged_binaries
  ensure_builder

  log "Image: ${image}:${tag}"
  log "Version: ${version}"
  log "Revision: ${revision}"
  log "Created: ${created}"
  if [[ "${local_load}" -eq 1 ]]; then
    log "Platforms: $(host_platform)"
  else
    log "Platforms: ${platforms}"
  fi

  build_image
}

main "$@"
