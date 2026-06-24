#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

unset RUSTUP_TOOLCHAIN

VERSION="${VERSION:-$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)}"
OUTPUT_DIR="${OUTPUT_DIR:-dist}"
STAGE_DIR="${STAGE_DIR:-.docker-stage}"
CARGO_FLAGS="${CARGO_FLAGS:---release}"
BINARIES=(edgepacer edgepacer-manager)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

target_triple_for_platform() {
    local platform_name="$1"

    case "$platform_name" in
        linux-amd64) echo "x86_64-unknown-linux-musl" ;;
        linux-arm64) echo "aarch64-unknown-linux-musl" ;;
        darwin-amd64) echo "x86_64-apple-darwin" ;;
        darwin-arm64) echo "aarch64-apple-darwin" ;;
        windows-amd64) echo "x86_64-pc-windows-gnu" ;;
        *) return 1 ;;
    esac
}

show_help() {
    cat <<EOF
EdgePacer cross-platform build script

Usage: $0 [OPTIONS] [TARGET...]

Targets:
  linux-amd64
  linux-arm64
  darwin-amd64
  darwin-arm64
  windows-amd64
  all

Options:
  --help, -h    Show this help text
  --clean       Remove build artifacts before building
  --parallel    Build cross targets concurrently
  --version VER Override version string (default: Cargo.toml)

Environment:
  VERSION       Override version string
  OUTPUT_DIR    Output directory for renamed binaries
  STAGE_DIR     Docker staging directory (default: .docker-stage)
  CARGO_FLAGS   Additional cargo flags (default: --release)
                Linux targets also add --features ebpf.
EOF
}

require_command() {
    local command_name="$1"
    local install_hint="$2"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        log_error "$command_name not found. $install_hint"
        exit 1
    fi
}

check_dependencies() {
    require_command cargo "Install Rust from https://rustup.rs"
    require_command rustup "Install rustup from https://rustup.rs"

    if needs_cross "$@"; then
        require_command cross "Install it with: cargo install cross"
        require_command docker "Docker must be installed and running for cross builds"
        "${SCRIPT_DIR}/scripts/ci/verify-cross-runner.sh"
    fi
}

setup_target() {
    local target="$1"

    if ! rustup target list --installed | grep -qx "$target"; then
        log_info "Adding rustup target: $target"
        rustup target add "$target"
    fi
}

sha256_file() {
    local file_path="$1"

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" > "${file_path}.sha256"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_path" > "${file_path}.sha256"
    else
        log_error "No SHA256 tool found (expected shasum or sha256sum)"
        exit 1
    fi
}

docker_arch_for_target() {
    local platform_name="$1"

    case "$platform_name" in
        linux-amd64) echo "amd64" ;;
        linux-arm64) echo "arm64" ;;
        *) return 1 ;;
    esac
}

stage_binaries() {
    local platform_name="$1"
    local target_triple
    local docker_arch

    target_triple="$(target_triple_for_platform "$platform_name")" || return 1
    docker_arch="$(docker_arch_for_target "$platform_name")" || return 0

    mkdir -p "${STAGE_DIR}/${docker_arch}"

    for binary_name in "${BINARIES[@]}"; do
        cp "target/${target_triple}/release/${binary_name}" "${STAGE_DIR}/${docker_arch}/${binary_name}"
        chmod +x "${STAGE_DIR}/${docker_arch}/${binary_name}"
    done
}

binary_extension_for_target() {
    local platform_name="$1"

    case "$platform_name" in
        windows-*) echo ".exe" ;;
        *) echo "" ;;
    esac
}

collect_artifacts() {
    local platform_name="$1"
    local target_triple
    local binary_extension
    target_triple="$(target_triple_for_platform "$platform_name")" || return 1
    binary_extension="$(binary_extension_for_target "$platform_name")"

    mkdir -p "${OUTPUT_DIR}"

    for binary_name in "${BINARIES[@]}"; do
        local source_path="target/${target_triple}/release/${binary_name}${binary_extension}"
        local output_path="${OUTPUT_DIR}/${binary_name}-${platform_name}${binary_extension}"

        if [[ ! -f "$source_path" ]]; then
            log_error "Binary not found: $source_path"
            return 1
        fi

        cp "$source_path" "$output_path"
        chmod +x "$output_path"
        sha256_file "$output_path"
    done

    stage_binaries "$platform_name"
}

needs_cross() {
    for platform_name in "$@"; do
        if [[ "$platform_name" == linux-* || "$platform_name" == windows-* ]]; then
            return 0
        fi
    done

    return 1
}

build_target() {
    local platform_name="$1"
    local target_triple
    local target_cargo_flags="${CARGO_FLAGS}"
    local start_time
    target_triple="$(target_triple_for_platform "$platform_name")" || {
        log_error "Unsupported target: ${platform_name}"
        return 1
    }
    start_time="$(date +%s)"

    log_info "Building ${platform_name} (${target_triple})"
    setup_target "$target_triple"

    if [[ "$platform_name" == linux-* ]]; then
        target_cargo_flags+=" --features ebpf"
    fi

    case "$platform_name" in
        linux-*|windows-*)
            local volume_opts="-v edgepacer-cargo-registry-${target_triple}:/usr/local/cargo/registry"
            volume_opts+=" -v edgepacer-cargo-git-${target_triple}:/usr/local/cargo/git"
            local cross_container_opts="${CROSS_CONTAINER_OPTS:-} ${volume_opts}"

            if [[ "$platform_name" == windows-* ]]; then
                # Build-only runs do not need Wine; wineboot can hang under arm64 QEMU.
                cross_container_opts+=" --entrypoint /usr/bin/env"
            fi

            CROSS_CONTAINER_OPTS="${cross_container_opts}" \
                cross build ${target_cargo_flags} --target "$target_triple" --bin edgepacer --bin edgepacer-manager
            ;;
        darwin-*)
            cargo build ${target_cargo_flags} --target "$target_triple" --bin edgepacer --bin edgepacer-manager
            ;;
        *)
            log_error "Unsupported target: ${platform_name}"
            return 1
            ;;
    esac

    collect_artifacts "$platform_name"

    local end_time
    end_time="$(date +%s)"
    log_success "Built ${platform_name} in $((end_time - start_time))s"
}

clean() {
    log_info "Cleaning build artifacts"
    cargo clean
    rm -rf "${OUTPUT_DIR}" "${STAGE_DIR}"
}

build_all() {
    local targets=("$@")

    for platform_name in "${targets[@]}"; do
        build_target "$platform_name"
    done
}

build_all_parallel() {
    local targets=("$@")
    local cross_targets=()
    local native_targets=()
    local pids=()
    local names=()
    local failed=()
    local log_dir="/tmp/edgepacer-build-$$"

    mkdir -p "$log_dir"

    for platform_name in "${targets[@]}"; do
        case "$platform_name" in
            linux-*|windows-*) cross_targets+=("$platform_name") ;;
            *) native_targets+=("$platform_name") ;;
        esac
    done

    for platform_name in "${cross_targets[@]}"; do
        log_info "Starting parallel build: ${platform_name}"
        build_target "$platform_name" > "${log_dir}/${platform_name}.log" 2>&1 &
        pids+=($!)
        names+=("$platform_name")
    done

    for platform_name in "${native_targets[@]}"; do
        build_target "$platform_name"
    done

    for index in "${!pids[@]}"; do
        if wait "${pids[$index]}"; then
            log_success "Parallel build completed: ${names[$index]}"
        else
            log_error "Parallel build failed: ${names[$index]} (see ${log_dir}/${names[$index]}.log)"
            tail -20 "${log_dir}/${names[$index]}.log" 2>/dev/null || true
            failed+=("${names[$index]}")
        fi
    done

    if [[ ${#failed[@]} -gt 0 ]]; then
        return 1
    fi

    rm -rf "$log_dir"
}

main() {
    local do_clean=false
    local do_parallel=false
    local targets=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --clean)
                do_clean=true
                shift
                ;;
            --parallel)
                do_parallel=true
                shift
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            all)
                targets=(linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64)
                shift
                ;;
            linux-amd64|linux-arm64|darwin-amd64|darwin-arm64|windows-amd64)
                targets+=("$1")
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ ${#targets[@]} -eq 0 ]]; then
        targets=(linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64)
    fi

    check_dependencies "${targets[@]}"

    if $do_clean; then
        clean
    fi

    mkdir -p "${OUTPUT_DIR}" "${STAGE_DIR}"

    if $do_parallel && [[ ${#targets[@]} -gt 1 ]]; then
        build_all_parallel "${targets[@]}"
    else
        build_all "${targets[@]}"
    fi

    log_success "Artifacts available in ${OUTPUT_DIR}/"
}

main "$@"
