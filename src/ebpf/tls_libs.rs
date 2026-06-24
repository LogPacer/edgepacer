//! Discover the TLS libraries a target process actually loaded, so the
//! `SSL_read`/`SSL_write` uprobes attach to the RIGHT one. The system-wide libssl
//! attach catches dynamically-linked OpenSSL (Python, most C/C++/Node-dynamic),
//! but misses runtimes that BUNDLE an OpenSSL-API TLS stack: Node statically links
//! OpenSSL into its binary, and native-backed Java TLS (Conscrypt, netty-tcnative)
//! ships its own BoringSSL `.so`. Scanning `/proc/<pid>/maps` per target finds
//! those, so we cover Node + native-Java TLS zero-config — exactly where the
//! "JVM needs a Java agent" assumption (Groundcover) breaks down. (Pure-JSSE,
//! JIT-compiled, stays an eBPF blind spot for everyone.)
//!
//! Pure parsing is host-tested; the `/proc` read is Linux + `ebpf` only.

/// True if a mapped file path hosts an OpenSSL-API TLS implementation worth a
/// uprobe (all keep the `SSL_read`/`SSL_write`[`_ex`] C ABI).
fn is_tls_lib(path: &str) -> bool {
    const NEEDLES: [&str; 6] = [
        "libssl.so",    // OpenSSL — system or app-bundled
        "libcrypto.so", // OpenSSL / BoringSSL crypto
        "boringssl",    // BoringSSL (direct)
        "tcnative",     // netty-tcnative — bundles BoringSSL (gRPC-Java, Netty)
        "conscrypt",    // Conscrypt — bundles BoringSSL (Android, some servers)
        "/node",        // Node statically links OpenSSL into the `node` binary
    ];
    NEEDLES.iter().any(|needle| path.contains(needle))
}

/// Parse the distinct executable-mapped TLS-library paths from `/proc/<pid>/maps`
/// content. A maps line is `addr perms offset dev inode  pathname`; we want
/// executable (`x`) mappings whose path looks like a TLS lib.
fn tls_libs_in_maps(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        let mut cols = line.split_whitespace();
        let _addr = cols.next();
        let perms = cols.next().unwrap_or("");
        if !perms.contains('x') {
            continue;
        }
        // pathname is the 6th column (index 5); absent for anonymous mappings.
        if let Some(path) = line.split_whitespace().nth(5)
            && is_tls_lib(path)
            && !out.iter().any(|p| p == path)
        {
            out.push(path.to_string());
        }
    }
    out
}

/// The TLS libraries `pid` has mapped executable — uprobe targets for that target.
/// Best-effort; empty if `/proc/<pid>/maps` can't be read or holds no TLS lib.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub fn discover(pid: u32) -> Vec<String> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|maps| tls_libs_in_maps(&maps))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_bundled_tls_libs() {
        assert!(is_tls_lib("/lib/aarch64-linux-gnu/libssl.so.3"));
        assert!(is_tls_lib(
            "/usr/lib/jvm/.../libnetty_tcnative_linux_x86_64.so"
        ));
        assert!(is_tls_lib(
            "/tmp/conscrypt12345/libconscrypt_openjdk_jni.so"
        ));
        assert!(is_tls_lib("/usr/bin/node"));
        assert!(!is_tls_lib("/lib/aarch64-linux-gnu/libc.so.6"));
        assert!(!is_tls_lib("[heap]"));
    }

    #[test]
    fn extracts_executable_tls_mappings_deduped() {
        let maps = "\
aaaa0000-aaaa1000 r-xp 00000000 00:01 11 /usr/bin/node
bbbb0000-bbbb1000 r-xp 00000000 00:01 22 /usr/lib/x86_64-linux-gnu/libssl.so.3
bbbb0000-bbbb2000 rw-p 00001000 00:01 22 /usr/lib/x86_64-linux-gnu/libssl.so.3
cccc0000-cccc1000 r--p 00000000 00:01 33 /usr/lib/x86_64-linux-gnu/libc.so.6
dddd0000-dddd1000 r-xp 00000000 00:00 0 ";
        let libs = tls_libs_in_maps(maps);
        assert_eq!(libs.len(), 2);
        assert!(libs.iter().any(|p| p.ends_with("/node")));
        assert!(libs.iter().any(|p| p.contains("libssl.so.3")));
        // libc (no TLS), the rw non-exec dup of libssl, and the anon mapping are skipped.
    }

    #[test]
    fn no_tls_libs_yields_empty() {
        let maps = "aaaa0000-aaaa1000 r-xp 0 00:01 1 /usr/lib/libc.so.6\n";
        assert!(tls_libs_in_maps(maps).is_empty());
    }
}
