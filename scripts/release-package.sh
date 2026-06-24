#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

version=""
release_tag=""
repository="${GITHUB_REPOSITORY:-LogPacer/edgepacer}"
dist_dir="${repo_root}/dist"
manifest_tool=""
skip_build=0
skip_manifest=0
sign_blobs=0
targets=()

usage() {
  cat <<'USAGE'
Build and package EdgePacer release assets.

Usage:
  scripts/release-package.sh [options] [TARGET...]

Targets:
  linux-amd64
  linux-arm64
  darwin-amd64
  darwin-arm64
  windows-amd64
  all

Options:
  --dist-dir DIR          Release artifact directory. Default: dist.
  --manifest-tool PATH    Prebuilt edgepacer-release-manifest binary.
  --repository OWNER/REPO GitHub repository used in download URLs.
  --sign-blobs           Sign release blobs with cosign sign-blob.
  --skip-build           Package artifacts already present in --dist-dir.
  --skip-manifest        Do not generate update-manifest.json/checksums.txt.
  --tag TAG              Release tag. Default: v<VERSION>.
  --version VERSION      Release version. Default: Cargo.toml package version.
  -h, --help             Show this help.

Environment:
  EDGEPACER_UPDATE_SIGNING_KEY  Required unless --skip-manifest is passed.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

default_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --dist-dir)
        dist_dir="$2"
        shift 2
        ;;
      --manifest-tool)
        manifest_tool="$2"
        shift 2
        ;;
      --repository)
        repository="$2"
        shift 2
        ;;
      --sign-blobs)
        sign_blobs=1
        shift
        ;;
      --skip-build)
        skip_build=1
        shift
        ;;
      --skip-manifest)
        skip_manifest=1
        shift
        ;;
      --tag)
        release_tag="$2"
        shift 2
        ;;
      --version)
        version="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      all|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64|windows-amd64)
        targets+=("$1")
        shift
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

normalize_args() {
  version="${version:-$(default_version)}"
  [[ -n "${version}" ]] || die "could not resolve release version"

  release_tag="${release_tag:-v${version}}"
  dist_dir="$(cd "${repo_root}" && mkdir -p "${dist_dir}" && cd "${dist_dir}" && pwd)"

  if [[ "${#targets[@]}" -eq 0 ]]; then
    targets=(all)
  fi
}

build_assets() {
  if [[ "${skip_build}" -eq 1 ]]; then
    return 0
  fi

  VERSION="${version}" OUTPUT_DIR="${dist_dir}" "${repo_root}/build-all.sh" "${targets[@]}"
}

stage_release_metadata() {
  if [[ "${skip_manifest}" -eq 1 ]]; then
    return 0
  fi

  local third_party_licenses="${repo_root}/LICENSE-3rdparty.csv"
  [[ -f "${third_party_licenses}" ]] || die "missing ${third_party_licenses}"

  cp "${third_party_licenses}" "${dist_dir}/LICENSE-3rdparty.csv"
}

resolve_manifest_tool() {
  if [[ -n "${manifest_tool}" ]]; then
    [[ -x "${manifest_tool}" ]] || die "manifest tool is not executable: ${manifest_tool}"
    printf '%s\n' "${manifest_tool}"
    return 0
  fi

  for candidate in \
    "${dist_dir}/release-manifest" \
    "${dist_dir}/tools/release-manifest"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  printf 'cargo-run\n'
}

generate_manifest() {
  if [[ "${skip_manifest}" -eq 1 ]]; then
    return 0
  fi

  [[ -n "${EDGEPACER_UPDATE_SIGNING_KEY:-}" ]] || die "missing EDGEPACER_UPDATE_SIGNING_KEY"

  local tool
  tool="$(resolve_manifest_tool)"

  if [[ "${tool}" == "cargo-run" ]]; then
    require_cmd cargo
    cargo run --locked --bin edgepacer-release-manifest -- \
      --version "${version}" \
      --release-tag "${release_tag}" \
      --repository "${repository}" \
      --dist-dir "${dist_dir}"
  else
    "${tool}" \
      --version "${version}" \
      --release-tag "${release_tag}" \
      --repository "${repository}" \
      --dist-dir "${dist_dir}"
  fi
}

sign_release_blobs() {
  if [[ "${sign_blobs}" -ne 1 ]]; then
    return 0
  fi

  require_cmd cosign

  find "${dist_dir}" -maxdepth 1 -type f \
    \( -name 'edgepacer-*' -o -name 'edgepacer-manager-*' -o -name 'checksums.txt' -o -name 'update-manifest.json' -o -name 'LICENSE-3rdparty.csv' \) \
    ! -name '*.sha256' \
    ! -name '*.sigstore.json' \
    -print0 |
    while IFS= read -r -d '' artifact; do
      cosign sign-blob --yes "${artifact}" --bundle "${artifact}.sigstore.json"
    done
}

main() {
  parse_args "$@"
  normalize_args
  build_assets
  stage_release_metadata
  generate_manifest
  sign_release_blobs

  printf 'Release artifacts available in %s\n' "${dist_dir}"
}

main "$@"
