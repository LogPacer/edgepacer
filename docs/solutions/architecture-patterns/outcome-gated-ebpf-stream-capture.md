---
title: Gate eBPF stream capture on completed operation outcomes
category: architecture-patterns
source_pr: https://github.com/LogPacer/edgepacer/pull/141
verified_against: 1c3a0c51e78b0b1754c2626347f8ca6bc17b7b30
verified_at: 2026-08-30
---

# Gate eBPF stream capture on completed operation outcomes

## Problem

An entry probe sees what an operation attempted, not what reached the stream. Publishing a requested buffer from `write`, `writev`, or `SSL_write` entry can therefore:

- invent protocol bytes when the operation fails;
- include an unwritten suffix after a partial write; and
- hide the fact that a successful operation exceeded the event capacity or the contiguous prefix available to the probe.

Protocol reassembly cannot repair these mistakes because the event has already asserted false stream history.

## Invariant

Treat entry as intent and exit as outcome:

1. At entry, stage only the arguments needed after return, together with the capture scope.
2. At exit, consume and remove the staged state before handling any result-specific early return.
3. Emit nothing when the operation transferred no bytes.
4. Re-resolve authorization and require it to match the staged scope before emitting.
5. Bound the event by the successful byte count, the contiguous bytes available to the probe, and the event capacity.
6. Mark the event when successful stream bytes are missing from the captured prefix.

In EdgePacer, the in-flight maps are keyed by `bpf_get_current_pid_tgid()`. The exit handlers remove the entry before checking the return value, then compare the current `CaptureScope` with the staged scope. This prevents failed calls and authorization changes from publishing stale data.

## Separate successful bytes from capturable bytes

`l7_capture_outcome` keeps two lengths explicit:

- `stream_len`: bytes the operation actually transferred;
- `contiguous_len`: bytes available as one readable prefix, such as the first `writev` iovec.

The emitted length is:

```text
min(stream_len, contiguous_len, event_capacity)
```

A stream-gap flag is set when `stream_len` is greater than that emitted length. This distinction matters:

- A 32-byte partial return from a 64-byte `write` emits 32 bytes without a gap. The other 32 bytes never entered the stream.
- A successful 2 KiB write captured into a 1 KiB event emits 1 KiB with a gap.
- A successful multi-iovec write whose accepted bytes continue past the first iovec emits the first prefix with a gap.
- A failed or zero-byte operation emits no segment.

Do not infer a gap from the requested length. The only relevant loss is loss from the successful stream history.

## Encode each API's result contract

The exit probe must obtain the successful byte count according to the intercepted API:

- `write`, `sendto`, `writev`, and classic `SSL_write` return the byte count directly when positive.
- `SSL_write_ex` returns `1` on success and stores the byte count through `*written`.
- The corresponding classic and `_ex` read APIs follow the same direct-return versus out-pointer split.

Sharing the staging and emission pattern is safe; pretending these result contracts are identical is not.

## Make capture loss an explicit wire fact

The kernel event carries `L7_FLAG_STREAM_GAP` in the shared `#[repr(C)]` layout. Both plaintext and TLS drains translate it to `CapturedSegment.stream_gap`. The capture layer reports the fact; userspace owns recovery policy.

The current connection registry consumes the trustworthy captured prefix, returns any record completed by that prefix, and then invalidates the tracker. A dead tracker can restart only at a trustworthy request boundary; a response alone cannot resurrect it. This avoids joining bytes from opposite sides of an unknown hole while preserving records that completed before the hole.

## Attach consumers before producers

An entry probe can create in-flight state as soon as it is attached. Attach the matching exit consumer first, then the entry producer. For TLS uprobes, load both programs and count only complete exit/entry symbol pairs as usable. An exit without staged state is harmless; an entry without an exit consumer leaks state and loses outcomes.

The same ordering is used for syscall tracepoint pairs and OpenSSL uprobe/uretprobe pairs.

## Verification pattern

Keep three levels of evidence:

1. Pure tests for the capture-length and gap matrix.
2. Privileged probe tests for failed, partial, oversized, and multi-iovec operations.
3. Userspace tests proving that a gap preserves a completed prefix, discards partial parser state, and recovers only at a request boundary.

The current implementations and tests live in:

- `bpf-common/src/lib.rs` (`l7_capture_outcome` and the shared event flag);
- `bpf/src/main.rs` (entry/exit staging and API-specific result handling);
- `src/ebpf/capture.rs` (consumer-first attachment and event drains);
- `src/ebpf/capture/tests/d2.rs` (privileged syscall outcomes); and
- `src/ebpf/l7/conn.rs` (gap invalidation and bounded recovery).
