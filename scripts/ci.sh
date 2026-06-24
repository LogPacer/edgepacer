#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo build --all-targets
cargo clippy --all-targets -- -D warnings
cargo test

if [[ "$(uname -s)" == "Linux" ]]; then
  cargo clippy --features ebpf --all-targets -- -D warnings
fi

scripts/kubernetes/validate-kind.sh --render-only
