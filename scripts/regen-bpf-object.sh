#!/usr/bin/env bash
# Regenerate or verify the embedded eBPF object (src/ebpf/programs/edgepacer.bpf.o).
#
#   regen-bpf-object.sh            Rebuild the BPF object from source and embed it.
#   regen-bpf-object.sh --check    Rebuild to a temp and compare against the
#                                  committed object (DWARF stripped); exit 1 on drift.
#
# Decision 4: the object is checked in so the agent's musl/cross build needs no
# BPF toolchain. This script is the *only* place that toolchain is used — the BPF
# source lives in the top-level `bpf/` crate, built with the nightly pinned by
# `bpf/rust-toolchain.toml` + bpf-linker. Regeneration is canonical on Linux
# amd64, matching the CI `bpf-object` job (.github/workflows/ci.yml).
set -euo pipefail

unset RUSTUP_TOOLCHAIN

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/bpf"
BUILT="$SRC_DIR/target/bpfel-unknown-none/release/edgepacer-ebpf"
EMBEDDED="$ROOT/src/ebpf/programs/edgepacer.bpf.o"
MODE="${1:-regen}"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  case "$MODE" in
    --check)
      echo "skip --check: canonical BPF object verification requires Linux x86_64" >&2
      exit 0
      ;;
    regen)
      echo "refusing to regenerate BPF object outside Linux x86_64" >&2
      echo "Use the CI bpf-object job environment or an amd64 Linux container." >&2
      exit 1
      ;;
  esac
fi

echo ">> building BPF object (pinned nightly + bpf-linker)"
# `cargo build` (not `+nightly`) so bpf/rust-toolchain.toml's pinned channel wins.
( cd "$SRC_DIR" && cargo build --release )

case "$MODE" in
  regen)
    cp "$BUILT" "$EMBEDDED"
    echo "OK: embedded $EMBEDDED ($(wc -c <"$EMBEDDED") bytes)"
    ;;
  --check)
    # Compare with DWARF stripped — it embeds absolute build paths and is not
    # reproducible; `.BTF` (needed for CO-RE) and the program bytecode stay.
    # GNU objcopy can't parse eBPF objects (EM_BPF), so use LLVM's, which ships
    # with the `llvm-tools-preview` rustup component.
    objcopy_llvm="$(find "$(cd "$SRC_DIR" && rustc --print sysroot 2>/dev/null)" -name llvm-objcopy 2>/dev/null | head -1)"
    if [ -z "$objcopy_llvm" ]; then
      echo "skip --check: llvm-objcopy not found (rustup component add llvm-tools-preview --toolchain nightly)" >&2
      exit 0
    fi
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    # BTF is preserved in the embedded object for runtime consumers, but it also
    # carries absolute source/cache/sysroot paths. Strip it only for the drift
    # compare so local regen and CI rebuilds can run from different directories.
    strip_for_compare() {
      "$objcopy_llvm" \
        --strip-debug \
        --remove-section .BTF \
        --remove-section .rel.BTF \
        --remove-section .BTF.ext \
        --remove-section .rel.BTF.ext \
        "$1" "$2"
    }
    strip_for_compare "$EMBEDDED" "$tmp/committed.o"
    strip_for_compare "$BUILT" "$tmp/rebuilt.o"
    if cmp -s "$tmp/committed.o" "$tmp/rebuilt.o"; then
      echo "OK: embedded object matches source (DWARF/BTF-stripped compare)"
    else
      echo "DRIFT: $EMBEDDED differs from the source rebuild." >&2
      echo "Run '$0' (no args) to regenerate, then commit the updated object." >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
