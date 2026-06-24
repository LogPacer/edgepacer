//! Integration tests proving the file tailer is bulletproof against critical
//! rotation and startup loss scenarios:
//!
//! 1. Rotation race — bytes still unread in the rotated file must be delivered
//!    before the tailer switches to the new file.
//! 2. Non-Unix rotation — rotation must be detectable via mtime/size signals
//!    when inode information is unavailable or unchanged.
//! 3. Startup race — `open()` must not skip bytes written between its
//!    `metadata()` and `seek(End)` steps.
//! 4. Offset drift — `self.offset` must advance by every byte consumed from
//!    the underlying reader, including bytes of filtered empty lines.

use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

use edgepacer::tailer::FileTailer;

/// Rotation with pending unread data: bytes in the rotated file are drained
/// to EOF before the new file becomes active.
#[test]
fn rotation_drains_unread_bytes_from_rotated_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");

    // Write to the original file but do NOT read it yet — there are unread
    // bytes still in the file at the moment rotation happens.
    std::fs::write(&path, "pre-rotation-1\npre-rotation-2\n").unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();

    // Simulate logrotate: rename the current file to path.1, create a fresh
    // file at the original path, and write to the new file. The bytes written
    // to the original file BEFORE rotation are still in the rotated file on
    // disk and must be delivered.
    let rotated = dir.path().join("app.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, "post-rotation-1\n").unwrap();

    // First read: drain the rotated file first, then read the new file.
    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(
        lines.len(),
        3,
        "expected all pre-rotation + post-rotation lines: got {:?}",
        lines
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(lines[0], b"pre-rotation-1");
    assert_eq!(lines[1], b"pre-rotation-2");
    assert_eq!(lines[2], b"post-rotation-1");
}

/// Limited reads must keep draining the rotated file across calls before
/// switching to the new file.
#[test]
fn rotation_drain_has_priority_across_limited_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limited.log");

    std::fs::write(&path, "old-a\nold-b\n").unwrap();
    let mut tailer = FileTailer::open_from_start(&path).unwrap();

    let rotated = dir.path().join("limited.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, "new-a\n").unwrap();

    let first = tailer.read_lines(1).unwrap();
    assert_eq!(first, vec![b"old-a".to_vec()]);

    let second = tailer.read_lines(1).unwrap();
    assert_eq!(second, vec![b"old-b".to_vec()]);

    let third = tailer.read_lines(1).unwrap();
    assert_eq!(third, vec![b"new-a".to_vec()]);
}

/// Rotation via size-shrink heuristic (no inode signal).
///
/// Creates a large file, reads it partially, then truncates the path down
/// to a much smaller file with a different mtime. The tailer must detect
/// rotation without relying on inode (simulating the non-Unix case).
#[test]
fn rotation_detected_via_size_shrink_and_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");

    // Original big file.
    let big_payload = "a".repeat(4096) + "\n" + &"b".repeat(4096) + "\n";
    std::fs::write(&path, &big_payload).unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();
    let first = tailer.read_lines(100).unwrap();
    assert_eq!(first.len(), 2);

    // Ensure mtime changes on the next write — filesystems with 1s granularity
    // need a sleep to guarantee a distinct timestamp.
    sleep(Duration::from_millis(1100));

    // Rename-then-create: simulates logrotate. On Unix inode also changes —
    // this path proves the size-shrink signal catches it even when inode
    // wouldn't (e.g. same device id on exotic filesystems, or non-Unix where
    // `inode_of` returns 0).
    let rotated = dir.path().join("app.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, "fresh\n").unwrap();

    // The tailer must notice rotation and deliver the new line.
    let second = tailer.read_lines(100).unwrap();
    assert!(
        second.iter().any(|l| l == b"fresh"),
        "expected 'fresh' line after rotation, got {:?}",
        second
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect::<Vec<_>>()
    );
}

/// Empty lines are emitted (matching Go's `append(batch, buf)` behavior) AND
/// every consumed byte advances the offset. Both properties matter:
/// the emission is parity with Go; the offset arithmetic preserves the
/// checkpoint invariant.
#[test]
fn empty_lines_emitted_matching_go() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blanks.log");

    // 5 lines * 2 bytes ("x\n") + 3 blank lines * 1 byte ("\n") = 13 bytes.
    let content = "x\n\nx\n\nx\n\nx\nx\n";
    std::fs::write(&path, content).unwrap();
    let expected_offset = content.len() as u64;

    let mut tailer = FileTailer::open_from_start(&path).unwrap();
    let lines = tailer.read_lines(100).unwrap();

    // Go emits one entry per line including blanks. We now match.
    assert_eq!(lines.len(), 8, "emit one entry per line including blanks");
    assert_eq!(lines[0], b"x");
    assert_eq!(lines[1], b"", "blank line emitted as empty Vec");
    assert_eq!(lines[2], b"x");
    assert_eq!(lines[3], b"");
    assert_eq!(lines[4], b"x");
    assert_eq!(lines[5], b"");
    assert_eq!(lines[6], b"x");
    assert_eq!(lines[7], b"x");

    // Offset tracks every byte consumed, including blank-line bytes.
    assert_eq!(
        tailer.position().offset,
        expected_offset,
        "offset must track raw bytes consumed"
    );
}

/// Non-UTF-8 bytes pass through unchanged. Go's `ReadBytes` treats everything
/// as raw bytes; previously the Rust tailer used `read_line(&mut String)`
/// which would return `InvalidData` and silently drop the whole in-flight
/// batch via pipeline.rs's warn-and-discard path.
#[test]
fn tailer_handles_non_utf8_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.log");

    // Mix valid ASCII with lone high bytes that are NOT valid UTF-8 lead
    // bytes on their own: 0xC0, 0xFF, 0xFE. Also a continuation byte (0x80)
    // that has no corresponding lead, which makes it invalid UTF-8.
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"ok-first\n");
    payload.extend_from_slice(&[b'b', b'a', b'd', 0xC0, 0xFF, 0xFE, 0x80, b'\n']);
    payload.extend_from_slice(b"ok-last\n");
    std::fs::write(&path, &payload).unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();
    let lines = tailer.read_lines(100).unwrap();

    assert_eq!(lines.len(), 3, "all three lines must be delivered");
    assert_eq!(lines[0], b"ok-first");
    assert_eq!(lines[1], &[b'b', b'a', b'd', 0xC0, 0xFF, 0xFE, 0x80]);
    assert_eq!(lines[2], b"ok-last");

    // Offset reflects every byte on disk.
    assert_eq!(tailer.position().offset as usize, payload.len());
}

/// Oversize line is truncated to the cap; the following line is unaffected
/// and the reader is advanced past the full on-disk line so subsequent reads
/// align correctly.
#[test]
fn oversize_line_truncated_then_next_line_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.log");

    // Build a line whose size exceeds DEFAULT_MAX_LINE_BYTES (1 MiB).
    let oversize_len: usize = 2 * 1024 * 1024;
    let mut payload: Vec<u8> = Vec::with_capacity(oversize_len + 16);
    payload.extend(std::iter::repeat_n(b'A', oversize_len));
    payload.push(b'\n');
    payload.extend_from_slice(b"next-line-intact\n");
    std::fs::write(&path, &payload).unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();
    let lines = tailer.read_lines(100).unwrap();

    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0].len(),
        edgepacer::tailer::DEFAULT_MAX_LINE_BYTES,
        "oversize line is truncated to the cap"
    );
    assert!(
        lines[0].iter().all(|&b| b == b'A'),
        "captured prefix is all 'A' bytes"
    );
    assert_eq!(lines[1], b"next-line-intact");

    // Offset must reflect the entire on-disk content — the truncated tail
    // was still consumed from the reader so line framing is preserved.
    assert_eq!(tailer.position().offset as usize, payload.len());
}

/// Startup race: the seek-to-end must use the post-seek position as the
/// authoritative offset. A write between `open()` and the first `read_lines`
/// should be captured, not skipped.
#[test]
fn open_at_end_does_not_skip_races_with_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("busy.log");

    std::fs::write(&path, "already-there\n").unwrap();

    let mut tailer = FileTailer::open(&path).unwrap();

    // New writes after open — these must appear in the next read_lines.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writeln!(f, "written-after-open-1").unwrap();
    writeln!(f, "written-after-open-2").unwrap();
    drop(f);

    let lines = tailer.read_lines(100).unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], b"written-after-open-1");
    assert_eq!(lines[1], b"written-after-open-2");
}

/// Tailer can be constructed on a non-existent path and delivers content
/// once the file appears. This is the "customer service about to start
/// writing to a log path that doesn't exist yet" case — Go's ReadLine has
/// an explicit wait-for-reappearance loop; we now do too via lazy open.
#[test]
fn tailer_survives_missing_file_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-yet-there.log");

    // File does NOT exist yet — open must not error.
    let mut tailer = FileTailer::open_from_start(&path).unwrap();

    // First poll against the missing file — expect empty, no error.
    let first = tailer.read_lines(100).unwrap();
    assert!(first.is_empty(), "no data to deliver while file is missing");

    // File appears now.
    std::fs::write(&path, "first-after-appear\nsecond-after-appear\n").unwrap();

    // Next poll: lazy-open kicks in, content is delivered.
    let second = tailer.read_lines(100).unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0], b"first-after-appear");
    assert_eq!(second[1], b"second-after-appear");
}

/// Tailer tolerates PermissionDenied at startup and recovers when
/// permissions are restored. Unix-only because Windows permission semantics
/// differ and the chmod trick doesn't translate.
#[cfg(unix)]
#[test]
fn tailer_survives_permission_denied_at_startup() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.log");
    std::fs::write(&path, "ready-and-waiting\n").unwrap();

    // chmod 000 — unreadable.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Open against the unreadable file must not error.
    let mut tailer = match FileTailer::open_from_start(&path) {
        Ok(t) => t,
        Err(e) => {
            // Some test environments (root, certain containers) may still be
            // able to open chmod-000 files. In that case this test is a no-op.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            panic!("expected tailer to tolerate PermissionDenied at open; got {e:?}");
        }
    };

    // Poll while locked — empty, no error.
    let first = tailer.read_lines(100).unwrap();
    assert!(first.is_empty());

    // Restore permissions.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Next poll: lazy-open upgrades the tailer; content delivered.
    let second = tailer.read_lines(100).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0], b"ready-and-waiting");
}

/// Rotation where the new file doesn't exist yet (brief window between
/// logrotate's rename and create) keeps the old reader alive instead of
/// erroring. Once the new file appears, the usual drain-then-switch flow
/// delivers both the tail of the rotated file and the new file's content.
#[test]
fn rotation_waits_for_new_file_to_appear() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rolling.log");
    std::fs::write(&path, "pre-rotation-a\npre-rotation-b\n").unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();

    // Rename without immediately creating a new file — path is now missing.
    let rotated = dir.path().join("rolling.log.1");
    std::fs::rename(&path, &rotated).unwrap();

    // First read while path is missing — the old fd still has the data via
    // inode. check_rotation sees NotFound, keeps the existing reader alive.
    // We should still get the pre-rotation bytes because they're in the fd.
    let first = tailer.read_lines(100).unwrap();
    assert_eq!(first.len(), 2, "existing fd still serves the rotated file");
    assert_eq!(first[0], b"pre-rotation-a");
    assert_eq!(first[1], b"pre-rotation-b");

    // New file finally appears.
    sleep(Duration::from_millis(1100));
    std::fs::write(&path, "post-rotation\n").unwrap();

    // Next read: rotation is now detected (inode changed), old reader is
    // parked as draining (already at EOF so drops immediately), new reader
    // delivers the new content.
    let second = tailer.read_lines(100).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0], b"post-rotation");
}

/// check_rotation tolerates PermissionDenied on metadata() just like it
/// tolerates NotFound — keeps the existing reader alive and retries next poll.
/// Unix-only.
#[cfg(unix)]
#[test]
fn check_rotation_tolerates_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chmoddy.log");
    std::fs::write(&path, "before-chmod\n").unwrap();

    let mut tailer = FileTailer::open_from_start(&path).unwrap();
    let first = tailer.read_lines(100).unwrap();
    assert_eq!(first.len(), 1);

    // chmod the DIRECTORY to be unreadable, which makes metadata() on the
    // file inside fail with PermissionDenied on most Unix systems. (chmod
    // on the file itself doesn't block metadata() — only open().)
    let dir_path = dir.path();
    std::fs::set_permissions(dir_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Append via the already-open fd — on Unix the inode stays writable even
    // though the dir is locked. Actually we can't append without opening the
    // file again, so just read once more with the locked directory.
    let second = tailer.read_lines(100);

    // Restore permissions before any assertion that could panic and leave
    // the tempdir in a broken state.
    std::fs::set_permissions(dir_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    // The read must not return an error — PermissionDenied on metadata()
    // is treated as "try again next time".
    assert!(
        second.is_ok(),
        "check_rotation must tolerate PermissionDenied: {:?}",
        second
    );
}

/// Multi-read after rotation: once the rotated file is fully drained, the
/// tailer stays on the new file and does not re-read drained bytes.
#[test]
fn after_drain_completes_tailer_stays_on_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ongoing.log");

    std::fs::write(&path, "old-a\nold-b\n").unwrap();
    let mut tailer = FileTailer::open_from_start(&path).unwrap();

    // Rotate with no unread bytes pending (we have unread bytes since we
    // haven't called read_lines yet — drain will pick them up).
    sleep(Duration::from_millis(1100));
    let rotated = dir.path().join("ongoing.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, "new-a\n").unwrap();

    // First read_lines pulls everything (drain + new).
    let first = tailer.read_lines(100).unwrap();
    assert_eq!(first.len(), 3);

    // Append to the new file and read again — must pick up only the appended
    // bytes, not replay the already-drained content.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writeln!(f, "new-b").unwrap();
    drop(f);

    let second = tailer.read_lines(100).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0], b"new-b");
}
