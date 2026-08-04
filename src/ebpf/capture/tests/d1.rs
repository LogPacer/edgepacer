use super::*;

#[test]
fn per_cpu_counter_delta_counts_only_new_faults() {
    let mut delta = PerCpuCounterDelta::default();

    assert_eq!(delta.observe(&[2, 3]), 5);
    assert_eq!(delta.observe(&[2, 3]), 0);
    assert_eq!(delta.observe(&[5, 7]), 7);
}

/// A short userspace buffer ending exactly at a mapped page boundary is valid
/// for the syscall, so capture must read only the syscall's reported length.
/// Reading the full destination array crosses into the protected page and
/// silently loses both raw-log and L7 events.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn bounded_reads_capture_page_edge_write_and_writev() {
    let (mut program, mut rx, _flow_rx, mut l7_rx, _listener_rx, counters) =
        program_with_counters();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");

    let write_marker = b"EDGEPACER_PAGE_EDGE_WRITE";
    let writev_marker = b"EDGEPACER_PAGE_EDGE_WRITEV";
    let script = r#"
import ctypes, mmap, os, time

time.sleep(1)
page = mmap.PAGESIZE
region = mmap.mmap(-1, page * 2, prot=mmap.PROT_READ | mmap.PROT_WRITE)
address = ctypes.addressof(ctypes.c_char.from_buffer(region))
libc = ctypes.CDLL(None, use_errno=True)
if libc.mprotect(ctypes.c_void_p(address + page), ctypes.c_size_t(page), 0) != 0:
    raise OSError(ctypes.get_errno(), 'mprotect')

for marker, vectored in (
    (b'EDGEPACER_PAGE_EDGE_WRITE', False),
    (b'EDGEPACER_PAGE_EDGE_WRITEV', True),
):
    start = page - len(marker)
    region[start:page] = marker
    view = memoryview(region)[start:page]
    written = os.writev(1, [view]) if vectored else os.write(1, view)
    assert written == len(marker)
    view.release()
"#;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn page-edge write child");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let mut raw_write = false;
    let mut raw_writev = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(raw_write && raw_writev) {
        let line = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for page-edge raw-log capture")
            .expect("raw-log capture channel closed");
        if line.pid == pid {
            raw_write |= line.bytes == write_marker;
            raw_writev |= line.bytes == writev_marker;
        }
    }

    let mut l7_write = false;
    let mut l7_writev = false;
    while !(l7_write && l7_writev) {
        let segment = tokio::time::timeout_at(deadline, l7_rx.recv())
            .await
            .expect("timed out waiting for page-edge L7 capture")
            .expect("L7 capture channel closed");
        if segment.pid == pid {
            l7_write |= segment.bytes == write_marker;
            l7_writev |= segment.bytes == writev_marker;
        }
    }

    let status = child.wait().expect("wait for page-edge write child");
    assert!(status.success(), "page-edge write child failed: {status}");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        counters.snapshot().ebpf_capture_read_faults,
        0,
        "valid page-edge buffers must not be reported as capture faults"
    );
    program.stop();
}

/// A genuinely invalid userspace pointer may still reach a syscall entry
/// probe. Stopping before the next poll must still fold that loss into agent
/// self-telemetry while the kernel map is alive.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn invalid_user_buffer_is_counted_during_capture_teardown() {
    let (mut program, _rx, _flow_rx, _l7_rx, _listener_rx, counters) = program_with_counters();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let script = r#"
import ctypes, time

time.sleep(0.1)
libc = ctypes.CDLL(None, use_errno=True)
written = libc.write(1, ctypes.c_void_p(1), ctypes.c_size_t(32))
assert written == 32
"#;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn invalid-buffer write child");
    let pid = child.id();
    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let status = child.wait().expect("wait for invalid-buffer write child");
    assert!(
        status.success(),
        "invalid-buffer write child failed: {status}"
    );
    program.stop();

    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let faults = counters.snapshot().ebpf_capture_read_faults;
            if faults >= 2 {
                return faults;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for capture-fault teardown telemetry");
    assert_eq!(observed, 2, "raw-log and L7 probes each report the fault");
}
