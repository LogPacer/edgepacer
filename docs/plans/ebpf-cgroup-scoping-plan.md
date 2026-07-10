# eBPF cgroup-native capture implementation plan

Branch: `feat/ebpf-cgroup-scoping`.

## Technical rationale

Socket-to-process resolution through `/proc/<pid>/fd` requires `CAP_SYS_PTRACE` for cross-uid
targets and introduces a time-of-check/time-of-use race. Capture identity in-kernel with
`cgroup_id`, then scope through a cgroup allow-set, so the capture path no longer depends on
cross-process `/proc` reads. This design supports a final capability set of `CAP_BPF` and
`CAP_PERFMON`. Phase 1, which stamps captured events with `cgroup_id`, is merged in #83.

## Current snapshot

Phase 2 listener discovery is implemented:

- `ListenerEvent` is shared by the kernel and userspace.
- `capture_listen` stages host-wide TCP listener transitions in `LISTEN_CANDIDATES`, and
  `capture_listen_exit` publishes to `LISTENER_EVENTS` only after `listen(2)` succeeds. Each event
  carries its port, address family, process id, and non-zero `cgroup_id`.
- `CapturedListener`, `spawn_listener_drain`, and the always-on `CAPTURE_LISTEN` attachment drain
  discovery independently of the network-flow toggle.
- The runner records live `port -> cgroup_id` deltas in a bounded observational cache and uses a
  persistent reconciliation interval so event churn cannot starve configuration refreshes. The
  cache is not authoritative; capture scoping still uses `TARGET_PIDS`.
- The canonical x86_64 `src/ebpf/programs/edgepacer.bpf.o` has been regenerated with the listener
  program and map.
- Privileged integration coverage includes IPv4 discovery with network-flow capture disabled,
  IPv6 discovery, and negative bind-without-listen, failed-bind, and failed-listen cases.

Canonical Linux x86_64 object verification, host tests, Linux eBPF linting, and the privileged
capture matrix pass. The remaining Phase 2 gates are the pull-request CI and review checks.

## Canonical object regeneration

Every change to `bpf-common` or `bpf/src/main.rs` requires regenerating the checked-in object on
Linux x86_64. From the repository root, install the pinned toolchain and linker, then run the
repository script:

```bash
rustup toolchain install nightly-2026-05-27 --component rust-src --component llvm-tools-preview
cargo install bpf-linker --version 0.10.3
scripts/regen-bpf-object.sh
scripts/regen-bpf-object.sh --check
```

Commit `src/ebpf/programs/edgepacer.bpf.o` in the same change as its kernel source.

## Steps

### Step 1 — finish Phase 2 listener discovery

Implementation and local verification are complete: the object is regenerated, host tests pass,
Linux eBPF linting passes, and the positive and negative privileged fixtures pass. Open a pull
request against `main`, then require the full CI and review suite to pass.

### Step 2 — Phase 3: cgroup allow-set scoping (additive first)

1. Kernel (`bpf/src/main.rs`): add `ALLOWED_CGROUPS: HashMap<u64, u8>`. At each capture program's
   head, capture when `TARGET_PIDS.get(&tgid)` **or**
   `ALLOWED_CGROUPS.get(&cgroup_id)` matches. Keep the pid path during this additive rollout, then
   regenerate the object.
2. Userspace: add `set_allowed_cgroups(&HashSet<u64>)` to `CaptureProgram`
   (`src/ebpf/manager.rs`) and implement it in `AyaCaptureProgram` (`src/ebpf/capture.rs`). Before
   using listener discovery for scoping, combine the live deltas with an authoritative snapshot
   and garbage collection, reject zero cgroup ids, then resolve each configured open port to the
   live owning cgroups and seed `ALLOWED_CGROUPS` during reconciliation.
3. Attribution: add cgroup-to-`log_source_id` routing alongside `PidRouting` in
   `src/ebpf/pid_resolver.rs`. Route captured events by `cgroup_id` while retaining pid routing in
   parallel during the additive rollout.
4. Capability detection (`src/ebpf/capability.rs`): require cgroup v2 unified mode for cgroup
   scoping. If unavailable, report `cgroup v2 required` with `ebpf_running=false` and fail closed.
5. Regenerate the object, add a privileged integration case that captures a configured workload
   through its cgroup, and pass the pull-request gates.

### Step 3 — Phase 3b: remove the pid path and excess capabilities

1. Remove the `TARGET_PIDS` filter and `/proc` targeting, including the connection-to-port
   resolution and namespace sweep in `src/discovery/ports.rs`.
2. In `src/manager/supervisor.rs`, remove `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, leaving
   `CAP_BPF CAP_PERFMON`. The systemd unit is written at install time, so ensure upgrades rewrite
   the unit when the required capability set changes, or explicitly require reinstalling it.
3. Regenerate the object, run the privileged integration suite, and pass the pull-request gates.

### Later phases

- Phase 1b: join `cgroup_id` to the container census by recording the cgroup directory inode from
  `/sys/fs/cgroup`, yielding `service_name` rather than `log_source_id` attribution.
- Phase 4: key connections by `{cgroup, tgid, first-ktime, fd}` to eliminate `{pid, fd}` reuse in
  `ConnRegistry` (`src/ebpf/l7/conn.rs`).
- Phase 5: produce `SecurityEvent` records from the existing unfiltered `edgepacer_exec`
  tracepoint.

## Conventions

- Regenerate the canonical x86_64 object in the same change as every kernel struct or program
  update.
- Add cgroup scoping before removing pid scoping so every intermediate revision retains a working
  capture path.
- Base pull requests on `main`.
