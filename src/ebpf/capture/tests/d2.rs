use super::*;

/// Exercises the exit-side L7 programs with real syscall outcomes. The fixture
/// covers a failed write, a deterministic 32-byte partial regular-file write,
/// capacity truncation, and an omitted writev tail in one target process.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn outbound_segments_follow_successful_write_results_and_flag_missing_bytes() {
    let (mut program, _rx, _flow_rx, mut l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");

    let partial_marker = b"EDGEPACER_PARTIAL_RETURN_1234567";
    assert_eq!(partial_marker.len(), 32);
    let oversized_marker = b"EDGEPACER_OVERSIZED_WRITE";
    let iovec_marker = b"EDGEPACER_IOVEC_HEAD";
    let failed_marker = b"EDGEPACER_FAILED_WRITE";
    let script = r#"
import ctypes, os, resource, tempfile, time

time.sleep(1)
failed = ctypes.create_string_buffer(b'EDGEPACER_FAILED_WRITE')
libc = ctypes.CDLL(None, use_errno=True)
assert libc.write(-1, failed, len(failed.value)) == -1

null_fd = os.open('/dev/null', os.O_WRONLY)
oversized = b'EDGEPACER_OVERSIZED_WRITE' + b'X' * 2048
assert os.write(null_fd, oversized) == len(oversized)
first = b'EDGEPACER_IOVEC_HEAD'
second = b'EDGEPACER_IOVEC_TAIL'
assert os.writev(null_fd, [first, second]) == len(first) + len(second)

partial_fd, partial_path = tempfile.mkstemp()
os.unlink(partial_path)
resource.setrlimit(resource.RLIMIT_FSIZE, (32, 32))
partial = b'EDGEPACER_PARTIAL_RETURN_1234567' + b'Y' * 32
assert os.write(partial_fd, partial) == 32
"#;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn outbound-result child");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut partial = None;
    let mut oversized = None;
    let mut iovec = None;
    while partial.is_none() || oversized.is_none() || iovec.is_none() {
        let segment = tokio::time::timeout_at(deadline, l7_rx.recv())
            .await
            .expect("timed out waiting for outbound-result segments")
            .expect("L7 capture channel closed");
        if segment.pid != pid {
            continue;
        }
        assert!(
            !segment
                .bytes
                .windows(failed_marker.len())
                .any(|bytes| bytes == failed_marker),
            "failed write emitted phantom L7 bytes"
        );
        if segment.bytes.starts_with(partial_marker) {
            partial = Some(segment);
        } else if segment.bytes.starts_with(oversized_marker) {
            oversized = Some(segment);
        } else if segment.bytes.starts_with(iovec_marker) {
            iovec = Some(segment);
        }
    }

    let partial = partial.expect("partial write segment");
    assert_eq!(partial.bytes, partial_marker);
    assert!(
        !partial.stream_gap,
        "unwritten request bytes are not part of the stream"
    );

    let oversized = oversized.expect("oversized write segment");
    assert_eq!(oversized.bytes.len(), L7_CHUNK_LEN);
    assert!(oversized.stream_gap);

    let iovec = iovec.expect("writev segment");
    assert_eq!(iovec.bytes, iovec_marker);
    assert!(iovec.stream_gap);

    let status = child.wait().expect("wait for outbound-result child");
    assert!(status.success(), "outbound-result child failed: {status}");
    program.stop();
}
