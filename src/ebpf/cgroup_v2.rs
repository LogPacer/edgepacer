//! Cgroup-v2 process identity.
//!
//! On cgroup v2, the inode of a process's directory under `/sys/fs/cgroup`
//! matches the ID returned by `bpf_get_current_cgroup_id()`. Keep parsing and
//! path construction separate from the Linux filesystem lookup so the
//! fail-closed input contract is host-tested on every platform.

use std::path::{Path, PathBuf};

use thiserror::Error;

const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const HOST_CGROUP_ROOT_ENV: &str = "EDGEPACER_HOST_CGROUP_ROOT";
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
const MAX_CGROUP_LEVEL: u32 = 32;
#[cfg(target_os = "linux")]
const MAX_CGROUP_SCAN_DIRECTORIES: usize = 262_144;

/// Stable workload scope used by the kernel cgroup allow-set.
///
/// `level` is the absolute depth in the host's unified hierarchy. The kernel
/// needs it to inspect only configured ancestor levels when matching a task in
/// a descendant cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CgroupAnchor {
    pub id: u64,
    pub level: u32,
}

impl CgroupAnchor {
    pub(crate) fn new(id: u64, level: u32) -> Result<Self, CgroupV2Error> {
        if id == 0 {
            return Err(CgroupV2Error::ZeroCgroupId);
        }
        if id == CGROUP_HIERARCHY_ROOT_INO {
            return Err(CgroupV2Error::RootCgroup);
        }
        if !(1..=MAX_CGROUP_LEVEL).contains(&level) {
            return Err(CgroupV2Error::InvalidCgroupLevel(level));
        }
        Ok(Self { id, level })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CgroupMount {
    path: PathBuf,
    inode: u64,
    device: u64,
    read_only: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CgroupEnvironment {
    host_root: PathBuf,
    local_root: PathBuf,
    namespace_root: PathBuf,
    namespace_inode: u64,
    namespace_root_inode: u64,
    root_inode: u64,
    device: u64,
    private_namespace: bool,
}

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
    #[error("explicit host cgroup root is not mounted read-only: {0}")]
    HostRootNotReadOnly(PathBuf),
    #[error(
        "namespace-local cgroup root {local} and host cgroup root {host} are on different filesystems"
    )]
    DifferentCgroupFilesystem { local: PathBuf, host: PathBuf },
    #[error("private cgroup namespace exposes ambiguous hierarchy-root inode 1 at {0}")]
    AmbiguousPrivateRoot(PathBuf),
    #[error("could not find namespace cgroup root inode {inode} beneath {host_root}")]
    NamespaceRootNotFound { host_root: PathBuf, inode: u64 },
    #[error("found namespace cgroup root inode {inode} more than once beneath {host_root}")]
    NamespaceRootAmbiguous { host_root: PathBuf, inode: u64 },
    #[error(
        "cgroup namespace changed while capture was active (expected inode {expected}, found {actual})"
    )]
    CgroupNamespaceChanged { expected: u64, actual: u64 },
    #[error(
        "cached namespace cgroup root {path} changed identity (expected inode {expected_inode}, found {actual_inode})"
    )]
    NamespaceRootChanged {
        path: PathBuf,
        expected_inode: u64,
        actual_inode: u64,
    },
    #[error(
        "host cgroup hierarchy exceeds the bounded namespace-root scan limit of {limit} directories"
    )]
    NamespaceRootScanLimit { limit: usize },
    #[error("the root cgroup is not a workload identity")]
    RootCgroup,
    #[error("cgroup-v2 directory returned invalid inode 0")]
    ZeroCgroupId,
    #[error("cgroup-v2 workload level {0} is outside the supported range 1..=32")]
    InvalidCgroupLevel(u32),
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
    let path = parse_unified_cgroup_entry(contents)?;
    validate_cgroup_path(&path)?;
    Ok(path)
}

fn parse_namespaced_unified_cgroup_path(contents: &str) -> Result<String, CgroupV2Error> {
    let path = parse_unified_cgroup_entry(contents)?;
    validate_namespaced_cgroup_path(&path)?;
    Ok(path)
}

fn parse_unified_cgroup_entry(contents: &str) -> Result<String, CgroupV2Error> {
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
    validate_cgroup_path_with_namespace_parents(path, false)
}

fn validate_namespaced_cgroup_path(path: &str) -> Result<(), CgroupV2Error> {
    validate_cgroup_path_with_namespace_parents(path, true)
}

fn validate_cgroup_path_with_namespace_parents(
    path: &str,
    allow_leading_parents: bool,
) -> Result<(), CgroupV2Error> {
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

    let mut saw_named_component = false;
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
        if component == "."
            || (component == ".." && (!allow_leading_parents || saw_named_component))
        {
            return Err(CgroupV2Error::UnsafePath {
                path: path.to_string(),
                reason: "path contains a traversal component",
            });
        }
        if component == ".." {
            continue;
        }
        if component == "(deleted)" || component.ends_with(" (deleted)") {
            return Err(CgroupV2Error::UnsafePath {
                path: path.to_string(),
                reason: "path refers to a deleted cgroup",
            });
        }
        saw_named_component = true;
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
    cgroup_anchor_for_pid(pid, expected_runtime_id).map(|anchor| anchor.id)
}

/// Resolve a runtime init process to its stable cgroup ID and absolute level.
#[cfg(target_os = "linux")]
pub(crate) fn cgroup_anchor_for_pid(
    pid: u32,
    expected_runtime_id: &str,
) -> Result<CgroupAnchor, CgroupV2Error> {
    let expected_runtime_id = normalize_runtime_id(expected_runtime_id)?;
    let environment = cgroup_environment()?;

    let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let cgroup_path = read_namespaced_unified_cgroup_path(&proc_path)?;
    ensure_runtime_identity(pid, &cgroup_path, expected_runtime_id)?;

    let anchor = cgroup_anchor_for_namespaced_path(environment, &cgroup_path)?;

    let confirmed_path = read_namespaced_unified_cgroup_path(&proc_path)?;
    ensure_runtime_identity_unchanged(pid, &cgroup_path, &confirmed_path, expected_runtime_id)?;

    Ok(anchor)
}

#[cfg(target_os = "linux")]
fn read_namespaced_unified_cgroup_path(path: &Path) -> Result<String, CgroupV2Error> {
    let contents = std::fs::read_to_string(path).map_err(|source| CgroupV2Error::Io {
        operation: "read",
        path: path.to_path_buf(),
        source,
    })?;
    parse_namespaced_unified_cgroup_path(&contents)
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

fn cgroup_level_for_path(cgroup_path: &str) -> Result<u32, CgroupV2Error> {
    validate_cgroup_path(cgroup_path)?;
    let level = cgroup_path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .count();
    cgroup_level_for_component_count(level)
}

fn cgroup_level_for_component_count(level: usize) -> Result<u32, CgroupV2Error> {
    if level == 0 {
        return Err(CgroupV2Error::RootCgroup);
    }
    if level > MAX_CGROUP_LEVEL as usize {
        return Err(CgroupV2Error::InvalidCgroupLevel(
            u32::try_from(level).unwrap_or(u32::MAX),
        ));
    }
    Ok(level as u32)
}

/// Return the cgroup-v2 root inode so callers can reject root associations
/// obtained from sources other than [`cgroup_id_for_pid`].
#[cfg(target_os = "linux")]
pub(crate) fn root_cgroup_id() -> Result<u64, CgroupV2Error> {
    cgroup_environment().map(|environment| environment.root_inode)
}

/// Enforce the complete environment contract shared by capability reporting
/// and capture loading. Native execution requires the initial cgroup namespace.
/// Private namespaces require an explicit read-only host hierarchy mount whose
/// inode identity can be mapped back to the namespace-local root.
#[cfg(target_os = "linux")]
pub(crate) fn validate_environment() -> Result<(), CgroupV2Error> {
    cgroup_environment().map(|_| ())
}

/// Whether the caller sees the host's initial cgroup namespace directly.
/// Host-native systemd identity is only meaningful in this namespace; the
/// private-namespace path intentionally remains available for container
/// runtime identities through the explicit host hierarchy mount.
#[cfg(target_os = "linux")]
pub(crate) fn uses_initial_cgroup_namespace() -> Result<bool, CgroupV2Error> {
    cgroup_environment().map(|environment| !environment.private_namespace)
}

#[cfg(target_os = "linux")]
fn cgroup_environment() -> Result<&'static CgroupEnvironment, CgroupV2Error> {
    static ENVIRONMENT: std::sync::OnceLock<CgroupEnvironment> = std::sync::OnceLock::new();

    if let Some(environment) = ENVIRONMENT.get() {
        revalidate_cgroup_environment(environment)?;
        return Ok(environment);
    }

    let environment = discover_cgroup_environment()?;
    let _ = ENVIRONMENT.set(environment);
    let environment = ENVIRONMENT
        .get()
        .expect("cgroup environment was initialized by this or another thread");
    revalidate_cgroup_environment(environment)?;
    Ok(environment)
}

#[cfg(target_os = "linux")]
fn discover_cgroup_environment() -> Result<CgroupEnvironment, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let namespace_inode = std::fs::metadata("/proc/self/ns/cgroup")
        .map_err(|source| CgroupV2Error::Io {
            operation: "stat",
            path: PathBuf::from("/proc/self/ns/cgroup"),
            source,
        })?
        .ino();

    if namespace_inode == INITIAL_CGROUP_NAMESPACE_INO {
        let mount = inspect_cgroup2_mount(Path::new(CGROUP2_MOUNT))?;
        verify_hierarchy_root_inode(mount.inode, &mount.path)?;
        read_namespaced_unified_cgroup_path(Path::new("/proc/self/cgroup"))?;
        return Ok(CgroupEnvironment {
            namespace_root: mount.path.clone(),
            local_root: mount.path.clone(),
            host_root: mount.path,
            namespace_inode,
            namespace_root_inode: mount.inode,
            root_inode: mount.inode,
            device: mount.device,
            private_namespace: false,
        });
    }

    let Some(host_root) = std::env::var_os(HOST_CGROUP_ROOT_ENV) else {
        return Err(CgroupV2Error::PrivateCgroupNamespace(namespace_inode));
    };
    let host_root = PathBuf::from(host_root);
    if !host_root.is_absolute() {
        return Err(CgroupV2Error::UnsafePath {
            path: host_root.display().to_string(),
            reason: "explicit host cgroup root must be absolute",
        });
    }

    let host_mount = inspect_cgroup2_mount(&host_root)?;
    verify_hierarchy_root_inode(host_mount.inode, &host_mount.path)?;
    if !host_mount.read_only {
        return Err(CgroupV2Error::HostRootNotReadOnly(host_mount.path));
    }

    let local_mount = inspect_cgroup2_mount(Path::new(CGROUP2_MOUNT))?;
    if local_mount.inode == CGROUP_HIERARCHY_ROOT_INO {
        return Err(CgroupV2Error::AmbiguousPrivateRoot(local_mount.path));
    }
    if local_mount.device != host_mount.device {
        return Err(CgroupV2Error::DifferentCgroupFilesystem {
            local: local_mount.path,
            host: host_mount.path,
        });
    }

    let namespace_root = find_unique_directory_by_inode(
        &host_mount.path,
        host_mount.device,
        local_mount.inode,
        MAX_CGROUP_SCAN_DIRECTORIES,
    )?;
    read_namespaced_unified_cgroup_path(Path::new("/proc/self/cgroup"))?;

    Ok(CgroupEnvironment {
        host_root: host_mount.path,
        local_root: local_mount.path,
        namespace_root,
        namespace_inode,
        namespace_root_inode: local_mount.inode,
        root_inode: host_mount.inode,
        device: host_mount.device,
        private_namespace: true,
    })
}

#[cfg(target_os = "linux")]
fn revalidate_cgroup_environment(environment: &CgroupEnvironment) -> Result<(), CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let namespace_inode = std::fs::metadata("/proc/self/ns/cgroup")
        .map_err(|source| CgroupV2Error::Io {
            operation: "stat",
            path: PathBuf::from("/proc/self/ns/cgroup"),
            source,
        })?
        .ino();
    if namespace_inode != environment.namespace_inode {
        return Err(CgroupV2Error::CgroupNamespaceChanged {
            expected: environment.namespace_inode,
            actual: namespace_inode,
        });
    }

    let host_mount = inspect_cgroup2_mount(&environment.host_root)?;
    verify_hierarchy_root_inode(host_mount.inode, &host_mount.path)?;
    if host_mount.path != environment.host_root || host_mount.device != environment.device {
        return Err(CgroupV2Error::DifferentCgroupFilesystem {
            local: host_mount.path,
            host: environment.host_root.clone(),
        });
    }
    if environment.private_namespace && !host_mount.read_only {
        return Err(CgroupV2Error::HostRootNotReadOnly(host_mount.path));
    }

    let local_mount = if environment.local_root == environment.host_root {
        host_mount
    } else {
        inspect_cgroup2_mount(&environment.local_root)?
    };
    if local_mount.path != environment.local_root || local_mount.device != environment.device {
        return Err(CgroupV2Error::DifferentCgroupFilesystem {
            local: local_mount.path,
            host: environment.host_root.clone(),
        });
    }
    if local_mount.inode != environment.namespace_root_inode {
        return Err(CgroupV2Error::NamespaceRootChanged {
            path: local_mount.path,
            expected_inode: environment.namespace_root_inode,
            actual_inode: local_mount.inode,
        });
    }
    if environment.private_namespace && local_mount.inode == CGROUP_HIERARCHY_ROOT_INO {
        return Err(CgroupV2Error::AmbiguousPrivateRoot(local_mount.path));
    }

    let namespace_root =
        std::fs::metadata(&environment.namespace_root).map_err(|source| CgroupV2Error::Io {
            operation: "stat",
            path: environment.namespace_root.clone(),
            source,
        })?;
    if !namespace_root.is_dir() {
        return Err(CgroupV2Error::NotDirectory(
            environment.namespace_root.clone(),
        ));
    }
    if namespace_root.dev() != environment.device {
        return Err(CgroupV2Error::DifferentCgroupFilesystem {
            local: environment.namespace_root.clone(),
            host: environment.host_root.clone(),
        });
    }
    if namespace_root.ino() != environment.namespace_root_inode {
        return Err(CgroupV2Error::NamespaceRootChanged {
            path: environment.namespace_root.clone(),
            expected_inode: environment.namespace_root_inode,
            actual_inode: namespace_root.ino(),
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn cgroup_id_for_path(mount_root: &Path, cgroup_path: &str) -> Result<u64, CgroupV2Error> {
    cgroup_anchor_for_path(mount_root, cgroup_path).map(|anchor| anchor.id)
}

#[cfg(target_os = "linux")]
fn cgroup_anchor_for_path(
    mount_root: &Path,
    cgroup_path: &str,
) -> Result<CgroupAnchor, CgroupV2Error> {
    validate_cgroup_path(cgroup_path)?;
    let mount = verified_cgroup2_root(mount_root)?;
    let environment = CgroupEnvironment {
        host_root: mount.path.clone(),
        local_root: mount.path.clone(),
        namespace_root: mount.path,
        namespace_inode: INITIAL_CGROUP_NAMESPACE_INO,
        namespace_root_inode: mount.inode,
        root_inode: mount.inode,
        device: mount.device,
        private_namespace: false,
    };
    cgroup_anchor_for_namespaced_path(&environment, cgroup_path)
}

fn join_namespaced_cgroup_path(
    host_root: &Path,
    namespace_root: &Path,
    cgroup_path: &str,
) -> Result<PathBuf, CgroupV2Error> {
    validate_namespaced_cgroup_path(cgroup_path)?;
    if !host_root.is_absolute() || !namespace_root.is_absolute() {
        return Err(CgroupV2Error::UnsafePath {
            path: namespace_root.display().to_string(),
            reason: "cgroup roots must be absolute",
        });
    }

    let mut relative = namespace_root
        .strip_prefix(host_root)
        .map_err(|_| CgroupV2Error::EscapesMount(namespace_root.to_path_buf()))?
        .to_path_buf();

    for component in cgroup_path.trim_start_matches('/').split('/') {
        match component {
            "" => {}
            ".." => {
                if !relative.pop() {
                    return Err(CgroupV2Error::EscapesMount(PathBuf::from(cgroup_path)));
                }
            }
            component => relative.push(component),
        }
    }

    Ok(host_root.join(relative))
}

#[cfg(target_os = "linux")]
fn cgroup_anchor_for_namespaced_path(
    environment: &CgroupEnvironment,
    cgroup_path: &str,
) -> Result<CgroupAnchor, CgroupV2Error> {
    let joined = join_namespaced_cgroup_path(
        &environment.host_root,
        &environment.namespace_root,
        cgroup_path,
    )?;
    cgroup_anchor_for_joined_path(environment, joined)
}

/// Resolve an absolute host-hierarchy ControlGroup path, such as the exact
/// value reported by `systemctl show`, to the kernel cgroup identity.
#[cfg(target_os = "linux")]
pub(crate) fn cgroup_anchor_for_host_path(
    cgroup_path: &str,
) -> Result<CgroupAnchor, CgroupV2Error> {
    let environment = cgroup_environment()?;
    let joined = join_cgroup_mount(&environment.host_root, cgroup_path)?;
    cgroup_anchor_for_joined_path(environment, joined)
}

#[cfg(target_os = "linux")]
fn cgroup_anchor_for_joined_path(
    environment: &CgroupEnvironment,
    joined: PathBuf,
) -> Result<CgroupAnchor, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let canonical_path = std::fs::canonicalize(&joined).map_err(|source| CgroupV2Error::Io {
        operation: "resolve",
        path: joined,
        source,
    })?;
    if !canonical_path.starts_with(&environment.host_root) {
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
    if metadata.dev() != environment.device {
        return Err(CgroupV2Error::DifferentCgroupFilesystem {
            local: canonical_path,
            host: environment.host_root.clone(),
        });
    }

    let cgroup_id = metadata.ino();
    if canonical_path == environment.host_root || cgroup_id == environment.root_inode {
        return Err(CgroupV2Error::RootCgroup);
    }
    if cgroup_id == 0 {
        return Err(CgroupV2Error::ZeroCgroupId);
    }

    let relative = canonical_path
        .strip_prefix(&environment.host_root)
        .map_err(|_| CgroupV2Error::EscapesMount(canonical_path.clone()))?;
    let level = cgroup_level_for_component_count(relative.components().count())?;
    CgroupAnchor::new(cgroup_id, level)
}

#[cfg(target_os = "linux")]
fn verified_cgroup2_root(mount_root: &Path) -> Result<CgroupMount, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let namespace_inode = std::fs::metadata("/proc/self/ns/cgroup")
        .map_err(|source| CgroupV2Error::Io {
            operation: "stat",
            path: PathBuf::from("/proc/self/ns/cgroup"),
            source,
        })?
        .ino();
    verify_initial_cgroup_namespace(namespace_inode)?;

    let mount = inspect_cgroup2_mount(mount_root)?;
    verify_hierarchy_root_inode(mount.inode, &mount.path)?;
    Ok(mount)
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
fn inspect_cgroup2_mount(path: &Path) -> Result<CgroupMount, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let canonical_path = std::fs::canonicalize(path).map_err(|source| CgroupV2Error::Io {
        operation: "resolve",
        path: path.to_path_buf(),
        source,
    })?;
    verify_cgroup2_filesystem(&canonical_path)?;
    let read_only = filesystem_is_read_only(&canonical_path)?;
    let metadata = std::fs::metadata(&canonical_path).map_err(|source| CgroupV2Error::Io {
        operation: "stat",
        path: canonical_path.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CgroupV2Error::NotDirectory(canonical_path));
    }
    if metadata.ino() == 0 {
        return Err(CgroupV2Error::ZeroCgroupId);
    }

    Ok(CgroupMount {
        path: canonical_path,
        inode: metadata.ino(),
        device: metadata.dev(),
        read_only,
    })
}

#[cfg(target_os = "linux")]
fn find_unique_directory_by_inode(
    host_root: &Path,
    device: u64,
    inode: u64,
    limit: usize,
) -> Result<PathBuf, CgroupV2Error> {
    use std::os::unix::fs::MetadataExt;

    let mut pending = vec![host_root.to_path_buf()];
    let mut visited = 0usize;
    let mut found = None;

    while let Some(directory) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(CgroupV2Error::Io {
                    operation: "stat",
                    path: directory,
                    source,
                });
            }
        };
        if !metadata.is_dir() || metadata.dev() != device {
            continue;
        }

        visited = visited.saturating_add(1);
        if visited > limit {
            return Err(CgroupV2Error::NamespaceRootScanLimit { limit });
        }
        if metadata.ino() == inode {
            if found.is_some() {
                return Err(CgroupV2Error::NamespaceRootAmbiguous {
                    host_root: host_root.to_path_buf(),
                    inode,
                });
            }
            found = Some(directory.clone());
        }

        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(CgroupV2Error::Io {
                    operation: "list",
                    path: directory,
                    source,
                });
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(CgroupV2Error::Io {
                        operation: "list",
                        path: directory.clone(),
                        source,
                    });
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(CgroupV2Error::Io {
                        operation: "stat",
                        path: entry.path(),
                        source,
                    });
                }
            };
            if file_type.is_dir() {
                pending.push(entry.path());
            }
        }
    }

    found.ok_or_else(|| CgroupV2Error::NamespaceRootNotFound {
        host_root: host_root.to_path_buf(),
        inode,
    })
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

#[cfg(target_os = "linux")]
fn filesystem_is_read_only(path: &Path) -> Result<bool, CgroupV2Error> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| CgroupV2Error::UnsafePath {
            path: path.display().to_string(),
            reason: "filesystem path contains a NUL byte",
        })?;
    let mut stat = MaybeUninit::<libc::statvfs>::zeroed();

    // SAFETY: `c_path` is NUL-terminated and `stat` points to writable storage
    // for the complete `statvfs` result. The kernel does not retain either.
    if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(CgroupV2Error::Io {
            operation: "statvfs",
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: a successful `statvfs` call initialized the result.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.f_flag & libc::ST_RDONLY as libc::c_ulong) != 0)
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
    fn accepts_only_leading_namespace_parent_components() {
        assert_eq!(
            parse_namespaced_unified_cgroup_path("0::/../../../init.scope\n").unwrap(),
            "/../../../init.scope"
        );

        for contents in [
            "0::/child/../sibling\n",
            "0::/./child\n",
            "0::/../child/..\n",
            "0::/..//child\n",
            "0::/../child/\n",
            "0::/../child (deleted)\n",
            "0::/../child\\name\n",
        ] {
            assert!(
                parse_namespaced_unified_cgroup_path(contents).is_err(),
                "accepted {contents:?}"
            );
        }
    }

    #[test]
    fn resolves_namespace_relative_paths_with_bounded_parent_ascent() {
        let host_root = Path::new("/host/sys/fs/cgroup");
        let namespace_root =
            host_root.join("kubepods.slice/burstable.slice/pod-a.slice/container-a.scope");

        assert_eq!(
            join_namespaced_cgroup_path(host_root, &namespace_root, "/").unwrap(),
            namespace_root
        );
        assert_eq!(
            join_namespaced_cgroup_path(host_root, &namespace_root, "/child.scope").unwrap(),
            namespace_root.join("child.scope")
        );
        assert_eq!(
            join_namespaced_cgroup_path(
                host_root,
                &namespace_root,
                "/../../pod-b.slice/container-b.scope"
            )
            .unwrap(),
            host_root.join("kubepods.slice/burstable.slice/pod-b.slice/container-b.scope")
        );
        assert_eq!(
            join_namespaced_cgroup_path(host_root, &namespace_root, "/../../../../init.scope")
                .unwrap(),
            host_root.join("init.scope")
        );
        assert!(matches!(
            join_namespaced_cgroup_path(host_root, &namespace_root, "/../../../../../escape.scope"),
            Err(CgroupV2Error::EscapesMount(_))
        ));
    }

    #[test]
    fn rejects_namespace_roots_outside_the_host_hierarchy() {
        assert!(matches!(
            join_namespaced_cgroup_path(
                Path::new("/host/sys/fs/cgroup"),
                Path::new("/sys/fs/cgroup/private"),
                "/workload.scope"
            ),
            Err(CgroupV2Error::EscapesMount(_))
        ));
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
    fn derives_supported_absolute_workload_levels() {
        assert_eq!(cgroup_level_for_path("/system.slice").unwrap(), 1);
        assert_eq!(
            cgroup_level_for_path("/kubepods.slice/pod.scope/container.scope").unwrap(),
            3
        );
        assert!(matches!(
            cgroup_level_for_path("/"),
            Err(CgroupV2Error::RootCgroup)
        ));

        let too_deep = format!("/{}", vec!["scope"; 33].join("/"));
        assert!(matches!(
            cgroup_level_for_path(&too_deep),
            Err(CgroupV2Error::InvalidCgroupLevel(33))
        ));
    }

    #[test]
    fn cgroup_anchor_rejects_zero_root_and_too_deep_values() {
        assert_eq!(
            CgroupAnchor::new(42, 3).unwrap(),
            CgroupAnchor { id: 42, level: 3 }
        );
        assert!(matches!(
            CgroupAnchor::new(0, 3),
            Err(CgroupV2Error::ZeroCgroupId)
        ));
        assert!(matches!(
            CgroupAnchor::new(CGROUP_HIERARCHY_ROOT_INO, 1),
            Err(CgroupV2Error::RootCgroup)
        ));
        assert!(matches!(
            CgroupAnchor::new(42, 0),
            Err(CgroupV2Error::InvalidCgroupLevel(0))
        ));
        assert!(matches!(
            CgroupAnchor::new(42, 33),
            Err(CgroupV2Error::InvalidCgroupLevel(33))
        ));
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
    fn finds_one_namespace_root_inode_with_a_bounded_walk() {
        use std::os::unix::fs::MetadataExt;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("a/b/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(temporary.path().join("other/branch")).unwrap();

        let metadata = std::fs::metadata(&target).unwrap();
        assert_eq!(
            find_unique_directory_by_inode(temporary.path(), metadata.dev(), metadata.ino(), 32)
                .unwrap(),
            target
        );
        assert!(matches!(
            find_unique_directory_by_inode(temporary.path(), metadata.dev(), u64::MAX, 32),
            Err(CgroupV2Error::NamespaceRootNotFound { .. })
        ));
        assert!(matches!(
            find_unique_directory_by_inode(temporary.path(), metadata.dev(), metadata.ino(), 1),
            Err(CgroupV2Error::NamespaceRootScanLimit { limit: 1 })
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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root, a private cgroup namespace, and a verified read-only host cgroup mount"]
    fn private_namespace_resolves_a_host_target_anchor() {
        let pid = std::env::var("EDGEPACER_TEST_TARGET_PID")
            .expect("EDGEPACER_TEST_TARGET_PID")
            .parse::<u32>()
            .expect("numeric target PID");
        let runtime_id =
            std::env::var("EDGEPACER_TEST_RUNTIME_ID").expect("EDGEPACER_TEST_RUNTIME_ID");
        let expected_id = std::env::var("EDGEPACER_TEST_CGROUP_ID")
            .expect("EDGEPACER_TEST_CGROUP_ID")
            .parse::<u64>()
            .expect("numeric target cgroup ID");
        let expected_level = std::env::var("EDGEPACER_TEST_CGROUP_LEVEL")
            .expect("EDGEPACER_TEST_CGROUP_LEVEL")
            .parse::<u32>()
            .expect("numeric target cgroup level");

        validate_environment().expect("private cgroup namespace environment is verified");
        assert_eq!(root_cgroup_id().unwrap(), CGROUP_HIERARCHY_ROOT_INO);
        assert_eq!(
            cgroup_anchor_for_pid(pid, &runtime_id).unwrap(),
            CgroupAnchor {
                id: expected_id,
                level: expected_level,
            }
        );
    }
}
