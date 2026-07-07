# AGENTS.md

## Cursor Cloud specific instructions

EdgePacer is a single Rust workspace (the LogPacer node agent). Standard dev
commands live in `README.md` ("Local Checks") and `scripts/ci.sh`; prefer those
rather than re-deriving them.

### Toolchain / system dependencies (already provisioned in the VM image)
- Rust is pinned to `1.96.0` via `rust-toolchain.toml`; `rustup` auto-selects it.
- `crates/logpacer_wire` compiles a vendored `protoc` from source at build time
  via the `protobuf-src` crate. This needs a working C/C++ toolchain: `cmake`,
  `perl`, and — non-obvious — `libstdc++-14-dev`. `/usr/bin/c++` is clang and it
  selects the GCC 14 lib dir, so without `libstdc++-14-dev` the first build fails
  with `cannot find -lstdc++` from the `protobuf-src`/`cmake` build script. A
  system `protobuf-compiler` is NOT required (the vendored protoc is always used).

### Build / lint / test (self-contained; no external services needed)
- Everything mocks Rails + LogRelay and SQLite is bundled, so no DB/service is
  required for `cargo build`/`cargo test`.
- `cargo fmt --all -- --check`, `cargo build --all-targets`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- eBPF lint path (Linux): `cargo clippy --features ebpf --all-targets -- -D warnings`.
- `helm`/`kubectl` are NOT installed; the Helm/chart validation checks
  (`scripts/kubernetes/validate-kind.sh`, `helm lint`) are skipped unless you
  install them. They are optional and only exercise the Kubernetes packaging.
- Regenerating the committed BPF object (`scripts/regen-bpf-object.sh`) needs the
  nightly toolchain `nightly-2026-05-27` + `bpf-linker`; not needed for normal work.

### Running the agent end-to-end locally (no control plane)
- Use `--local-mode` with a `--directive-file` JSON so no Rails auth is needed.
  Minimal directive shipping a tailed file to a local sink:
  ```json
  { "collect": { "src": {
      "locator": "/tmp/app.log", "matching_strategy": "file_path",
      "subbox_endpoint": "http://127.0.0.1:4317/v1/logpacer-wire",
      "archive_id": "arc_demo", "repo_id": "repo_demo",
      "stamp_resource_identifier": true } } }
  ```
- Start the test sink first: `cargo run --bin mock-logrelay -- 4317` (POST
  `/v1/logpacer-wire`, GET `/stats`, GET `/health`; set `MOCK_RELAY_DUMP=<file>`
  to record received log lines). Then run
  `cargo run --bin edgepacer -- --local-mode --directive-file <config.json>`.
- Non-obvious: the tailer starts "from end" when there is no checkpoint, so append
  NEW lines after the agent reports `delivery pipeline started` — pre-existing
  file content is skipped. Verify shipping via the relay's `/stats` (`total_records`).
