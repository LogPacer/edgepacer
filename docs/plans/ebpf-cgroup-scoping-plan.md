# eBPF cgroup-native capture implementation plan

Workstream branches are cut from `main` one reviewable slice at a time.

## Technical rationale

Socket-to-process resolution through `/proc/<pid>/fd` requires `CAP_SYS_PTRACE` for cross-uid
targets and introduces a time-of-check/time-of-use race. Capture identity in-kernel with
`cgroup_id`, then scope through a cgroup allow-set, so the capture path no longer depends on
cross-process `/proc` reads. This design supports a final capability set of `CAP_BPF` and
`CAP_PERFMON`. Phase 1, which stamps captured events with `cgroup_id`, is merged in #83.

## Current snapshot

Phase 2 listener discovery is merged in #84:

- `ListenerEvent` is shared by the kernel and userspace.
- `capture_listen` stages host-wide TCP listener transitions in `LISTEN_CANDIDATES`, and
  `capture_listen_exit` publishes to `LISTENER_EVENTS` only after `listen(2)` succeeds. Each event
  carries its port, address family, process id, and non-zero `cgroup_id`.
- `CapturedListener`, `spawn_listener_drain`, and the always-on `CAPTURE_LISTEN` attachment drain
  discovery independently of the network-flow toggle.
- The runner drains live `port -> cgroup_id` deltas and uses a persistent reconciliation interval
  so event churn cannot starve configuration refreshes.
- The canonical x86_64 `src/ebpf/programs/edgepacer.bpf.o` has been regenerated with the listener
  program and map.
- Privileged integration coverage includes IPv4 discovery with network-flow capture disabled,
  IPv6 discovery, and negative bind-without-listen, failed-bind, and failed-listen cases.

Canonical Linux x86_64 object verification, host tests, Linux eBPF linting, the privileged capture
matrix, pull-request CI, and review all passed before merge.

The first Phase 3 slice added the prerequisite authoritative listener state in #85: monotonic timestamps
fence snapshots against live changes, `NETLINK_SOCK_DIAG` provides exact socket evidence in the
current network namespace, isolated runtime namespaces use PID-reuse-guarded local runtime
identities, and periodic replacement snapshots garbage-collect closed listeners. Foreign
namespace listeners retain typed, port-local runtime-cgroup candidates; those candidates are not
authorization until target resolution intersects them with explicit service identity. Likewise,
socket cgroups remain socket facts rather than proof of which cgroup handles traffic (including
systemd socket activation).

The listener drain now has per-CPU publication sequences, a bounded contiguous-watermark fence,
and per-CPU loss epochs. A snapshot becomes ready only after all publications sampled after its
filesystem collection have reached userspace and the loss vector is unchanged. Because live
events do not carry trustworthy network-namespace provenance, a live change invalidates ownership
and is never merged into the host socket inventory; a fresh snapshot classifies it instead. Loss between
snapshots invalidates the previous ready state at the next observation. Private cgroup namespaces,
remote runtime PIDs, incomplete identity, zero/root cgroups, partial socket dumps, bounded-state
overflow, and dead drains all fail closed. Capture scoping still uses `TARGET_PIDS` while the
additive allow-set slice is under review.

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

Complete: merged in #84 after canonical-object verification, host and Linux checks, privileged
positive/negative fixtures, full CI, and review passed.

### Step 2 — Phase 3a: authoritative listener snapshot prerequisite

Complete: merged in #85 after canonical-object verification, the no-ptrace proof, privileged
listener coverage, full CI, and review passed.

1. Preserve host-local, PID-reuse-guarded runtime identity for Docker and CRI/Kubernetes without
   serializing it in census payloads. Reject remote endpoints and partial backend inventory.
2. Build strict cgroup-v2 and `NETLINK_SOCK_DIAG` readers plus bounded, deadline-aware foreign
   namespace inspection that does not require `CAP_SYS_PTRACE`.
3. Reconcile replacement snapshots with timestamped live deltas, per-CPU loss epochs, and a drain
   fence. Keep exact socket cgroups separate from foreign runtime candidates; neither is directly
   an allow-set.
4. Regenerate the x86_64 object, prove cross-UID collection with `CAP_SYS_PTRACE` removed, pass the
   privileged capture matrix and host/Linux/cross-platform gates, then merge this prerequisite.

The no-ptrace proof is self-checking and runs on the privileged Linux test host with:

```bash
sudo -E scripts/test-ebpf-no-ptrace.sh
```

### Step 3 — Phase 3b: cgroup allow-set scoping (additive first)

1. Kernel (`bpf/src/main.rs`): add double-buffered `ALLOWED_CGROUPS` membership maps with
   per-entry policy generations, per-slot packed hierarchy-level metadata, and one atomic selector
   packing the active slot with its generation. A capture program accepts the current cgroup or a
   bounded ancestor and records the matched anchor as `scope_cgroup_id`. The selected monotonic
   policy generation is stamped into every captured event; userspace drops records from stale
   policy or program generations. Keep `TARGET_PIDS` as an additive fallback during this rollout,
   then regenerate the object.
2. Userspace: add `set_allowed_cgroups(&CgroupRouting)` to `CaptureProgram`
   (`src/ebpf/manager.rs`) and implement it in `AyaCaptureProgram` (`src/ebpf/capture.rs`). Resolve
   container workload anchors from verified explicit runtime identity, not from the socket cgroup.
   Require authoritative port evidence; for foreign namespaces, require the target anchor and
   exact namespace token among that port's typed runtime candidates. Shared namespaces retain
   candidates for target-aware intersection instead of authorizing every occupant. Keep host-native
   systemd targets on the additive PID path until their unit cgroup resolver is verified before
   PID-path removal.
3. Attribution: add cgroup-to-`log_source_id` routing alongside `PidRouting`. Route captured events
   by the matched `scope_cgroup_id` while retaining pid routing in parallel during the additive
   rollout. When both identities exist they must agree; conflicts fail closed. Partition L7
   reassembly and protocol hints by capture generation, policy generation, scope cgroup, actual
   cgroup, pid, and fd so bytes cannot cross an authorization boundary.
4. Capability detection (`src/ebpf/capability.rs`): require cgroup v2 unified mode for cgroup
   scoping. Native execution requires the initial cgroup namespace. A private agent cgroup
   namespace is accepted only when an explicit, read-only host hierarchy mount can be mapped
   uniquely to the namespace-local root; every cached filesystem and namespace identity is
   revalidated before use. Otherwise report the concrete capability error with
   `ebpf_running=false` and fail closed.
5. Regenerate the object, add privileged cases for concurrent policy replacement, in-flight
   generation changes, and private-namespace host workload resolution, then pass the pull-request
   gates. The private-namespace proof runs with `sudo -E scripts/test-ebpf-private-cgroupns.sh`.
   The matching Rails heartbeat field, `ebpf_cgroups_targeted`, is merged in LogPacer #427.

### Step 4 — Phase 3c: remove the pid path and excess capabilities

1. Resolve configured host-native systemd targets from their verified unit cgroup, then remove the
   `TARGET_PIDS` filter and `/proc` targeting, including the connection-to-port resolution and
   namespace sweep in `src/discovery/ports.rs`.
2. In `src/manager/supervisor.rs`, remove `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, leaving
   `CAP_BPF CAP_PERFMON`. The systemd unit is written at install time, so ensure upgrades rewrite
   the unit when the required capability set changes, or explicitly require reinstalling it.
3. Regenerate the object, run the privileged integration suite, and pass the pull-request gates.

### Later phases

- Phase 1b: join `cgroup_id` to the container census by recording the cgroup directory inode from
  `/sys/fs/cgroup`, yielding `service_name` rather than `log_source_id` attribution.
- Phase 4: add kernel first-seen ktime to the existing cgroup- and generation-partitioned connection
  key, eliminating same-identity fd reuse in `ConnRegistry` (`src/ebpf/l7/conn.rs`).
- Phase 5: produce `SecurityEvent` records from the existing unfiltered `edgepacer_exec`
  tracepoint.

## Conventions

- Regenerate the canonical x86_64 object in the same change as every kernel struct or program
  update.
- Add cgroup scoping before removing pid scoping so every intermediate revision retains a working
  capture path.
- Base pull requests on `main`.
