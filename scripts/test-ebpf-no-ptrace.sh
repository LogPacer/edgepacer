#!/usr/bin/env bash
# Prove authoritative cross-UID listener discovery without CAP_SYS_PTRACE.
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (for example: sudo -E $0)" >&2
  exit 1
fi
if ! command -v capsh >/dev/null 2>&1; then
  echo "capsh is required" >&2
  exit 1
fi

test_cargo="${CARGO:-$(command -v cargo)}"
export EDGEPACER_TEST_CARGO="$test_cargo"

exec capsh --drop=cap_sys_ptrace -- -c \
  'exec "$EDGEPACER_TEST_CARGO" test --lib --features ebpf live_snapshot_reads_a_cross_uid_runtime_namespace_without_ptrace -- --ignored --nocapture'
