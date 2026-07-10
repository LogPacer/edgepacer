//! Cgroup-v2 process identity.
//!
//! On cgroup v2, the inode of a process's directory under `/sys/fs/cgroup`
//! matches the ID returned by `bpf_get_current_cgroup_id()`. Keep parsing and
//! path construction separate from the Linux filesystem lookup so the
//! fail-closed input contract is host-tested on every platform.

use std::path::{Path, PathBuf};

use thiserror::Error;

const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";
// Linux assigns this fixed inode to the initial cgroup namespace. See
// include/linux/proc_ns.h (PROC_CGROUP_INIT_INO).
const INITIAL_CGROUP_NAMESPACE_INO: u64 = 0xEFFF_FFFB;
// cgroup_setup_root() requires the real hierarchy root to have cgroup ID 1.
// A namespace-private cgroup2 mount rooted at a delegated subtree retains the
// subtree cgroup's inode instead. See kernel/cgroup/cgroup.c.
const CGROUP_HIERARCHY_ROOT_INO: u64 = 1;
// Docker/containerd/CRI-O production IDs are longer (normally 64 hex chars).
// Refuse short names and familiar 12-character display prefixes so only the
// runtime's durable identity can authorize PID attribution.
const MIN_RUNTIME_ID_BYTES: usize = 32;

#[derive(Debug, Error)]
pub(crate) enum CgroupV2Error {
    #[error("invalid /proc/<pid>/cgroup content: {0}")]
    InvalidProcCgroup(String),
    #[error("unsafe cgroup-v2 path {path:?}: {reason}")]
    UnsafePath { path: String, reason: &'static str },
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} is not on a cgroup-v2 filesystem")]
    NotCgroup2(PathBuf),
    #[error("caller is not in the initial cgroup namespace (inode {0})")]
    PrivateCgroupNamespace(u64),
    #[error("{path} is not the host cgroup hierarchy root (inode {inode})")]
    NotHierarchyRoot { path: PathBuf, inode: u64 },
    #[error("resolved cgroup path escapes the cgroup-v2 mount: {0}")]
    EscapesMount(PathBuf),
    #[error("resolved cgroup path is not a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("the root cgroup is not a workload identity")]
    RootCgroup,
    #[error("cgroup-v2 directory returned invalid inode 0")]
    ZeroCgroupId,
    #[error("invalid runtime container ID {0:?}")]
    InvalidRuntimeId(String),
    #[error(
        "/proc/{pid}/cgroup does not identify expected runtime container {expected_runtime_id:?}"
    )]
    RuntimeIdentityMismatch {
        pid: u32,
        expected_runtime_id: String,
    },
    #[error("/proc/{pid}/cgroup changed while resolving runtime container identity")]
    RuntimeIdentityChanged { pid: u32 },
}

/// Parse the one canonical cgroup-v2 entry emitted by `/proc/<pid>/cgroup`.
///
/// A unified host emits exactly `0::<absolute-path>`. Any additional line is a
/// hybrid hierarchy and is rejected rather than silently selecting one side.
pub(crate) fn parse_unified_cgroup_path(contents: &str) -> Result<String, CgroupV2Error> {
    let mut lines = contents.lines();
    let line = lines.next().ok_or_else(|| {
        CgroupV2Error::InvalidProcCgroup("expected one unified entry".to_string())
    })?;

    if line.is_empty() || lines.next().is_some() {
        return Err(CgroupV2Error::InvalidProcCgroup(
            "expected exactly one unified entry".to_string(),
        ));
    }

    let mut fields = line.splitn(3, ':');
    let hierarchy = fields.next();
    let controllers = fields.next();
    let path = fields.next();

    if hierarchy != Some("0") || controllers != Some("") {
        return Err(CgroupV2Error::InvalidProcCgroup(
            "expected a cgroup-v2 0::<path> entry".to_string(),
        ));
    }

    let path = path.ok_or_else(|| {
        CgroupV2Error::InvalidProcCgroup("unified entry is missing its path".to_string())
    })?;
    validate_cgroup_path(path)?;
    Ok(path.to_string())
}

/// Join a parsed Linux cgroup path beneath a mount without letting absolute or
/// traversal components replace or escape the supplied root.
pub(crate) fn join_cgroup_mount(
    mount_root: &Path,
    cgroup_path: &str,
) -> Result<PathBuf, CgroupV2Error> {
    validate_cgroup_path(cgroup_path)?;

    if !mount_root.is_absolute() {
        return Err(CgroupV2Error::UnsafePath {
            path: mount_root.display().to_string(),
            reason: "mount root must be absolute",
        });
    }

    let mut joined = mount_root.to_path_buf();
    for component in cgroup_path.trim_start_matches('/').split('/') {
        if !component.is_empty() {
            joined.push(component);
        }
    }
    Ok(joined)
}

fn validate_cgroup_path(path: &str) -> Result<(), CgroupV2Error> {
    if path.is_empty() {
        return Err(CgroupV2Error::UnsafePath {
            path: path.to_string(),
            reason: "path is empty",
        });
    }
    if !path.starts_with('/') {
        return Err(CgroupV2Error::UnsafePath {
            path: path.to_string(),
            reason: "path must be absolute",
        });
    }
    if path.contains('\0') {
        return Err(CgroupV2Error::UnsafePath {
            path: path.to_string(),
            reason: "path contains a NUL byte",
        });
    }
    if path.contains('\\') {
        return Err(CgroupV2Error::UnsafePath {
            path: path.to_string(),
            reason: "path contains a non-canonical separator",
        });
    }
    if path != "/" && path.ends_with('/') {
        return Err(CgroupV2Error::UnsafePath {
            path: path.to_string(),
            reason: "path has a trailing separator",
        });
    }

    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            if path == "/" {
                continue;
            }
            return Err(CgroupV2Error::UnsafePath {
                path: path.to_string(),
                reason: "path contains an empty component",
            });
        }
        if component == "." || component == ".." {
            return Err(CgroupV2Error::UnsafePath {
                path: path.to_string(),
                reason: "path contains a traversal component",
            });
        }
        if component == "(deleted)" || component.ends_with(" (deleted)") {
            return Err(CgroupV2Error::UnsafePath {
                path: path.to_string(),
                reason: "path refers to a deleted cgroup",
            });
        }
    }

    Ok(())
}

/// Resolve a runtime's init process to the inode used by
/// `bpf_get_current_cgroup_id()`.
///
/// The expected full runtime ID is mandatory. Checking it before and after the
/// filesystem lookup prevents a stale or recycled runtime PID from being
/// attributed to a different workload.
#[cfg(target_os = "linux")]
pub(crate) fn cgroup_id_for_pid(pid: u32, expected_runtime_id: &str) -> Result<u64, CgroupV2Error> {
    let expected_runtime_id = normalize_runtime_id(expected_runtime_id)?;
    // Verify the caller's namespace and mount before interpreting proc paths:
    // /proc/<pid>/cgroup is relative to the reader's cgroup namespace root.
    verified_cgroup2_root(Path::new(CGROUP2_MOUNT))?;

    let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let cgroup_path = read_unified_cgroup_path(&proc_path)?;
    ensure_runtime_identity(pid, &cgroup_path, expected_runtime_id)?;

    let cgroup_id = cgroup_id_for_path(Path::new(CGROUP2_MOUNT), &cgroup_path)?;

    let confirmed_path = read_unified_cgroup_path(&proc_path)?;
    ensure_runtime_identity_unchanged(pid, &cgroup_path, &confirmed_path, expected_runtime_id)?;

    Ok(cgroup_id)
}

#[cfg(target_os = "linux")]
fn read_unified_cgroup_path(path: &Path) -> Result<String, CgroupV2Error> {
    let contents = std::fs::read_to_string(path).map_err(|source| CgroupV2Error::Io {
        operation: "read",
        path: path.to_path_buf(),
        source,
    })?;
    parse_unified_cgroup_path(&contents)
}

fn normalize_runtime_id(runtime_id: &str) -> Result<&str, CgroupV2Error> {
    let id = match runtime_id.split_once("://") {
        Some((runtime, id)) if !runtime.is_empty() => id,
        Some(_) => "",
        None => runtime_id,
    };

    if id.len() < MIN_RUNTIME_ID_BYTES
        || id == "."
        || id == ".."
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CgroupV2Error::InvalidRuntimeId(runtime_id.to_string()));
    }
    Ok(id)
}

fn ensure_runtime_identity(
    pid: u32,
    cgroup_path: &str,
    expected_runtime_id: &str,
) -> Result<(), CgroupV2Error> {
    if cgroup_path_identifies_runtime_id(cgroup_path, expected_runtime_id) {
        Ok(())
    } else {
        Err(CgroupV2Error::RuntimeIdentityMismatch {
            pid,
            expected_runtime_id: expected_runtime_id.to_string(),
        })
    }
}

fn ensure_runtime_identity_unchanged(
    pid: u32,
    initial_path: &str,
    confirmed_path: &str,
    expected_runtime_id: &str,
) -> Result<(), CgroupV2Error> {
    if confirmed_path != initial_path {
        return Err(CgroupV2Error::RuntimeIdentityChanged { pid });
    }
    ensure_runtime_identity(pid, confirmed_path, expected_runtime_id)
}

fn cgroup_path_identifies_runtime_id(cgroup_path: &str, runtime_id: &str) -> bool {
    cgroup_path
        .split('/')
        .filter(|component| !component.is_empty())
        .any(|component| {
            if component == runtime_id {
                return true;
            }

            let stem = component.strip_suffix(".scope").unwrap_or(component);
            stem == runtime_id
                || stem
                    .strip_suffix(runtime_id)
                    .is_some_and(|prefix| prefix.ends_with('-'))
        })
}

/// Return the cgroup-v2 root inode so callers can reject root associations
/// obtained from sources other than [`cgroup_id_for_pid`].
#[cfg(target_os = "linux")]
pub(crate) fn root_cgroup_id() -> Result<u64, CgroupV2Error> {
    verified_cgroup2_root(Path::new(CGROUP2_MOUNT)).map(|(_, inode)| inode)
}

#[cfg(target_os = "linux")]
fn cgroup_id_for_path(mount_root: &Path, cgroup_path: &str) -> Result<u64, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let (canonical_root, root_inode) = verified_cgroup2_root(mount_root)?;

    let joined = join_cgroup_mount(&canonical_root, cgroup_path)?;
    let canonical_path = std::fs::canonicalize(&joined).map_err(|source| CgroupV2Error::Io {
        operation: "resolve",
        path: joined,
        source,
    })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(CgroupV2Error::EscapesMount(canonical_path));
    }

    let metadata = std::fs::metadata(&canonical_path).map_err(|source| CgroupV2Error::Io {
        operation: "stat",
        path: canonical_path.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CgroupV2Error::NotDirectory(canonical_path));
    }

    let cgroup_id = metadata.ino();
    if canonical_path == canonical_root || cgroup_id == root_inode {
        return Err(CgroupV2Error::RootCgroup);
    }
    if cgroup_id == 0 {
        return Err(CgroupV2Error::ZeroCgroupId);
    }

    Ok(cgroup_id)
}

#[cfg(target_os = "linux")]
fn verified_cgroup2_root(mount_root: &Path) -> Result<(PathBuf, u64), CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let namespace_inode = std::fs::metadata("/proc/self/ns/cgroup")
        .map_err(|source| CgroupV2Error::Io {
            operation: "stat",
            path: PathBuf::from("/proc/self/ns/cgroup"),
            source,
        })?
        .ino();
    verify_initial_cgroup_namespace(namespace_inode)?;

    let canonical_root = std::fs::canonicalize(mount_root).map_err(|source| CgroupV2Error::Io {
        operation: "resolve",
        path: mount_root.to_path_buf(),
        source,
    })?;
    verify_cgroup2_filesystem(&canonical_root)?;

    let metadata = std::fs::metadata(&canonical_root).map_err(|source| CgroupV2Error::Io {
        operation: "stat",
        path: canonical_root.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CgroupV2Error::NotDirectory(canonical_root));
    }
    let inode = metadata.ino();
    if inode == 0 {
        return Err(CgroupV2Error::ZeroCgroupId);
    }
    verify_hierarchy_root_inode(inode, &canonical_root)?;

    Ok((canonical_root, inode))
}

fn verify_initial_cgroup_namespace(namespace_inode: u64) -> Result<(), CgroupV2Error> {
    if namespace_inode != INITIAL_CGROUP_NAMESPACE_INO {
        return Err(CgroupV2Error::PrivateCgroupNamespace(namespace_inode));
    }
    Ok(())
}

fn verify_hierarchy_root_inode(mount_inode: u64, mount_root: &Path) -> Result<(), CgroupV2Error> {
    if mount_inode != CGROUP_HIERARCHY_ROOT_INO {
        return Err(CgroupV2Error::NotHierarchyRoot {
            path: mount_root.to_path_buf(),
            inode: mount_inode,
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_cgroup2_filesystem(path: &Path) -> Result<(), CgroupV2Error> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| CgroupV2Error::UnsafePath {
            path: path.display().to_string(),
            reason: "filesystem path contains a NUL byte",
        })?;
    let mut stat = MaybeUninit::<libc::statfs>::zeroed();

    // SAFETY: `c_path` is NUL-terminated and `stat` points to writable storage
    // for the complete `statfs` result. The kernel does not retain either.
    if unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(CgroupV2Error::Io {
            operation: "statfs",
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: a successful `statfs` call initialized the result.
    let stat = unsafe { stat.assume_init() };
    if stat.f_type != CGROUP2_SUPER_MAGIC {
        return Err(CgroupV2Error::NotCgroup2(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_unified_entry() {
        assert_eq!(
            parse_unified_cgroup_path("0::/system.slice/edgepacer.service\n").unwrap(),
            "/system.slice/edgepacer.service"
        );
        assert_eq!(parse_unified_cgroup_path("0::/\n").unwrap(), "/");
    }

    #[test]
    fn rejects_v1_hybrid_and_multiple_entries() {
        for contents in [
            "2:cpu:/workload\n",
            "0::/unified\n2:cpu:/legacy\n",
            "0::/first\n0::/second\n",
            "0:name=systemd:/workload\n",
        ] {
            assert!(
                parse_unified_cgroup_path(contents).is_err(),
                "accepted {contents:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_malformed_deleted_and_traversal_paths() {
        for contents in [
            "",
            "\n",
            "0::\n",
            "0:/missing-field\n",
            "not-a-hierarchy::/workload\n",
            "0::relative\n",
            "0::/workload/../other\n",
            "0::/workload/./child\n",
            "0::/workload//child\n",
            "0::/workload/\n",
            "0::/workload (deleted)\n",
            "0::/workload/(deleted)/child\n",
            "0::/workload\\child\n",
        ] {
            assert!(
                parse_unified_cgroup_path(contents).is_err(),
                "accepted {contents:?}"
            );
        }
    }

    #[test]
    fn joins_only_beneath_an_absolute_mount() {
        let mount = std::env::current_dir().unwrap().join("cgroup-test-root");
        assert_eq!(
            join_cgroup_mount(&mount, "/system.slice/edgepacer.service").unwrap(),
            mount.join("system.slice/edgepacer.service")
        );
        assert_eq!(join_cgroup_mount(&mount, "/").unwrap(), mount);
        assert!(join_cgroup_mount(Path::new("relative"), "/workload").is_err());
        assert!(join_cgroup_mount(&std::env::current_dir().unwrap(), "/../escape").is_err());
    }

    #[test]
    fn recognizes_full_runtime_ids_in_cgroupfs_and_systemd_paths() {
        const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        for path in [
            format!("/docker/{ID}"),
            format!("/system.slice/docker-{ID}.scope"),
            format!("/kubepods.slice/cri-containerd-{ID}.scope"),
            format!("/machine.slice/libpod-{ID}.scope"),
        ] {
            assert!(
                cgroup_path_identifies_runtime_id(&path, ID),
                "did not recognize {path:?}"
            );
        }
        assert_eq!(
            normalize_runtime_id(&format!("containerd://{ID}")).unwrap(),
            ID
        );
    }

    #[test]
    fn rejects_stale_truncated_or_substring_runtime_ids() {
        const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let path = format!("/system.slice/docker-{ID}.scope");

        assert!(!cgroup_path_identifies_runtime_id(&path, &ID[..12]));
        assert!(!cgroup_path_identifies_runtime_id(
            &format!("/docker/{ID}stale"),
            ID
        ));
        assert!(!cgroup_path_identifies_runtime_id(
            &format!("/docker/attacker{ID}.scope"),
            ID
        ));
        assert!(matches!(
            ensure_runtime_identity(42, "/docker/someone-else", ID),
            Err(CgroupV2Error::RuntimeIdentityMismatch { pid: 42, .. })
        ));
        assert!(matches!(
            ensure_runtime_identity_unchanged(
                42,
                &format!("/docker/{ID}"),
                &format!("/docker/{ID}-replacement"),
                ID
            ),
            Err(CgroupV2Error::RuntimeIdentityChanged { pid: 42 })
        ));
    }

    #[test]
    fn rejects_invalid_runtime_ids() {
        for id in [
            "",
            "abc",
            "0123456789ab",
            "://abc",
            "docker://",
            "../abc",
            "abc/def",
            "abc def",
        ] {
            assert!(
                matches!(
                    normalize_runtime_id(id),
                    Err(CgroupV2Error::InvalidRuntimeId(_))
                ),
                "accepted {id:?}"
            );
        }
    }

    #[test]
    fn accepts_only_initial_namespace_and_real_hierarchy_root() {
        let mount = Path::new(CGROUP2_MOUNT);
        assert!(verify_initial_cgroup_namespace(INITIAL_CGROUP_NAMESPACE_INO).is_ok());
        assert!(verify_hierarchy_root_inode(CGROUP_HIERARCHY_ROOT_INO, mount).is_ok());
        assert!(matches!(
            verify_initial_cgroup_namespace(1234),
            Err(CgroupV2Error::PrivateCgroupNamespace(1234))
        ));
        assert!(matches!(
            verify_hierarchy_root_inode(99, mount),
            Err(CgroupV2Error::NotHierarchyRoot { inode: 99, .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_pid_matches_its_cgroup_directory_inode_when_v2_is_available() {
        use std::os::unix::fs::MetadataExt;

        let mount = Path::new(CGROUP2_MOUNT);
        let Ok(canonical_mount) = std::fs::canonicalize(mount) else {
            return;
        };
        if verify_cgroup2_filesystem(&canonical_mount).is_err() {
            return;
        }
        let namespace_inode = std::fs::metadata("/proc/self/ns/cgroup").unwrap().ino();
        if namespace_inode != INITIAL_CGROUP_NAMESPACE_INO {
            assert!(matches!(
                root_cgroup_id(),
                Err(CgroupV2Error::PrivateCgroupNamespace(_))
            ));
            return;
        }
        assert_eq!(root_cgroup_id().unwrap(), CGROUP_HIERARCHY_ROOT_INO);

        let contents = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let path = parse_unified_cgroup_path(&contents).unwrap();
        if path == "/" {
            assert!(matches!(
                cgroup_id_for_path(mount, &path),
                Err(CgroupV2Error::RootCgroup)
            ));
            return;
        }

        let expected_path = join_cgroup_mount(&canonical_mount, &path).unwrap();
        let expected = std::fs::metadata(expected_path).unwrap().ino();
        assert_ne!(expected, 0);
        assert_eq!(cgroup_id_for_path(mount, &path).unwrap(), expected);
    }
}
