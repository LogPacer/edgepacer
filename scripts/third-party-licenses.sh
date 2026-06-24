#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${repo_root}/LICENSE-3rdparty.csv"
command="${1:-check}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

root_dump="${tmpdir}/root.csv"
bpf_dump="${tmpdir}/bpf.csv"
generated="${tmpdir}/LICENSE-3rdparty.csv"

cd "${repo_root}"
dd-rust-license-tool --manifest-path Cargo.toml dump > "${root_dump}"
dd-rust-license-tool --manifest-path bpf/Cargo.toml dump > "${bpf_dump}"

head -n 1 "${root_dump}" > "${generated}"
{
  tail -n +2 "${root_dump}"
  tail -n +2 "${bpf_dump}"
} | LC_ALL=C sort -u >> "${generated}"

case "${command}" in
  write)
    cp "${generated}" "${output}"
    ;;
  check)
    if [[ ! -f "${output}" ]]; then
      printf 'missing %s\n' "${output}" >&2
      exit 1
    fi

    if ! cmp -s "${output}" "${generated}"; then
      printf 'LICENSE-3rdparty.csv is out of date; run scripts/third-party-licenses.sh write\n' >&2
      diff -u "${output}" "${generated}" >&2 || true
      exit 1
    fi
    ;;
  *)
    printf 'usage: scripts/third-party-licenses.sh [check|write]\n' >&2
    exit 2
    ;;
esac
