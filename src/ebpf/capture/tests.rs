use super::*;
use crate::config::EbpfTargetConfig;
use crate::discovery::ports::ListeningPort;
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

fn enabled_section(network_flows_enabled: bool) -> EbpfSectionConfig {
    EbpfSectionConfig {
        enabled: true,
        receiver_port: 4318,
        network_flows_enabled,
        network_cidrs: Vec::new(),
        targets: Vec::new(),
        config_hash: "capture-test".to_string(),
    }
}

fn routing_for(pid: u32) -> PidRouting {
    let target = EbpfTargetConfig {
        log_source_id: "capture-test".to_string(),
        service_name: "capture-test".to_string(),
        systemd_unit: None,
        open_ports: vec![65000],
        archive_id: String::new(),
        repo_id: String::new(),
        protocols: Vec::new(),
        subbox_endpoint: String::new(),
    };
    let census = vec![ListeningPort {
        port: 65000,
        protocol: "tcp".to_string(),
        process: "capture-test".to_string(),
        pid,
    }];
    super::super::pid_resolver::resolve_from_ports(&census, &[target])
}

/// A program wired with all channels; tests that ignore one drop its receiver.
fn program() -> (
    AyaCaptureProgram,
    mpsc::Receiver<CapturedLine>,
    mpsc::Receiver<CapturedFlow>,
    mpsc::Receiver<CapturedSegment>,
    mpsc::Receiver<CapturedListener>,
) {
    let (tx, rx) = mpsc::channel(256);
    let (flow_tx, flow_rx) = mpsc::channel(256);
    let (l7_tx, l7_rx) = mpsc::channel(256);
    let (listener_tx, listener_rx) = mpsc::channel(256);
    let (listener_health_tx, _listener_health_rx) = watch::channel(ListenerDrainHealth::stopped());
    (
        AyaCaptureProgram::new(tx, flow_tx, l7_tx, listener_tx, listener_health_tx),
        rx,
        flow_rx,
        l7_rx,
        listener_rx,
    )
}

#[test]
fn cgroup_policy_deduplicates_ids_and_tracks_extreme_levels() {
    let policy = cgroup_policy_from_anchors(
        [
            CgroupAnchor { id: 11, level: 1 },
            CgroupAnchor { id: 22, level: 32 },
            CgroupAnchor { id: 11, level: 1 },
        ],
        7,
    )
    .unwrap();

    assert_eq!(policy.ids, HashSet::from([11, 22]));
    assert_eq!(
        policy.level_policy,
        1 | (1u64 << 31) | (1u64 << CGROUP_MIN_LEVEL_SHIFT) | (32u64 << CGROUP_MAX_LEVEL_SHIFT)
    );
    assert_eq!(policy.generation, 7);
}

#[test]
fn empty_cgroup_policy_has_no_ids_or_levels() {
    let policy = cgroup_policy_from_anchors([], 0).unwrap();

    assert!(policy.ids.is_empty());
    assert_eq!(policy.level_policy, 0);
    assert_eq!(policy.generation, 0);
}

#[test]
fn cgroup_policy_rejects_zero_root_and_unsupported_levels() {
    assert_eq!(
        cgroup_policy_from_anchors([CgroupAnchor { id: 0, level: 1 }], 1).unwrap_err(),
        "allowed cgroup id must be non-zero"
    );
    assert_eq!(
        cgroup_policy_from_anchors([CgroupAnchor { id: 1, level: 1 }], 1).unwrap_err(),
        "the root cgroup is not an allowed workload scope"
    );
    assert_eq!(
        cgroup_policy_from_anchors([CgroupAnchor { id: 11, level: 0 }], 1).unwrap_err(),
        "allowed cgroup 11 is the cgroup-v2 root"
    );
    assert!(
        cgroup_policy_from_anchors([CgroupAnchor { id: 11, level: 33 }], 1)
            .unwrap_err()
            .contains("unsupported level 33")
    );
    assert_eq!(
        cgroup_policy_from_anchors([CgroupAnchor { id: 11, level: 1 }], 0).unwrap_err(),
        "nonempty cgroup policy must use a nonzero generation"
    );
    assert_eq!(
        cgroup_policy_from_anchors([], 1).unwrap_err(),
        "empty cgroup policy must use generation zero"
    );
    assert!(
        cgroup_policy_from_anchors(
            [CgroupAnchor { id: 11, level: 1 }],
            CGROUP_SELECTOR_GENERATION_MASK + 1,
        )
        .unwrap_err()
        .contains("exceeds packed selector maximum")
    );
}

#[test]
fn packed_cgroup_selector_publishes_slot_and_generation_together() {
    let selector = pack_cgroup_selector(1, 19).unwrap();

    assert_eq!(selector, (1u64 << CGROUP_SELECTOR_SLOT_SHIFT) | 19);
    assert_eq!(unpack_cgroup_selector(selector), (1, 19));
    assert_eq!(unpack_cgroup_selector(0), (0, 0));
    assert!(pack_cgroup_selector(2, 1).is_err());
    assert!(pack_cgroup_selector(0, CGROUP_SELECTOR_GENERATION_MASK + 1).is_err());
}

#[test]
fn cgroup_policy_uses_the_routing_discovery_epoch() {
    let routing =
        CgroupRouting::from_entries(19, [(CgroupAnchor { id: 11, level: 4 }, "source")]).unwrap();

    let policy = cgroup_policy_from_routing(&routing).unwrap();

    assert_eq!(policy.generation, 19);
    assert_eq!(
        policy.level_policy,
        (1u64 << 3) | (4u64 << 32) | (4u64 << 40)
    );
}

#[derive(Clone, Copy, Debug)]
enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
    fn python(self) -> (&'static str, &'static str) {
        match self {
            Self::Ipv4 => ("AF_INET", "127.0.0.1"),
            Self::Ipv6 => ("AF_INET6", "::1"),
        }
    }

    fn libc(self) -> u16 {
        match self {
            Self::Ipv4 => libc::AF_INET as u16,
            Self::Ipv6 => libc::AF_INET6 as u16,
        }
    }
}

fn spawn_socket_script(script: &str, description: &str) -> (Child, u32, u16) {
    let mut child = std::process::Command::new("python3")
        .arg("-u")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {description} child (python3): {error}"));
    let pid = child.id();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("child stdout"))
        .read_line(&mut ready)
        .expect("read child readiness");
    let mut fields = ready.split_whitespace();
    assert_eq!(fields.next(), Some("ready"), "{description} became ready");
    let port = fields
        .next()
        .unwrap_or_else(|| panic!("{description} reported its bound port"))
        .parse()
        .unwrap_or_else(|error| panic!("{description} reported a valid port: {error}"));
    assert_eq!(fields.next(), None, "{description} readiness format");
    (child, pid, port)
}

fn spawn_bound_socket(family: SocketFamily, listen: bool) -> (Child, u32, u16) {
    let (python_family, host) = family.python();
    let listen_call = if listen { "s.listen()" } else { "" };
    let script = format!(
        "import socket,time\n\
         s=socket.socket(socket.{python_family},socket.SOCK_STREAM)\n\
         s.bind(('{host}',0))\n\
         {listen_call}\n\
         print('ready',s.getsockname()[1],flush=True)\n\
         time.sleep(3)"
    );
    spawn_socket_script(&script, "bound socket")
}

fn spawn_failed_listen() -> (Child, u32, u16) {
    let script = r#"
import socket,time
first=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
second=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
first.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
second.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
first.bind(('127.0.0.1',0))
port=first.getsockname()[1]
second.bind(('127.0.0.1',port))
first.listen()
try:
    second.listen()
except OSError:
    print('ready',port,flush=True)
    time.sleep(3)
else:
    raise RuntimeError('second listen unexpectedly succeeded')
"#;
    spawn_socket_script(script, "failed listen")
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

async fn receive_listener(
    listener_rx: &mut mpsc::Receiver<CapturedListener>,
    pid: u32,
    port: u16,
    timeout: Duration,
) -> Option<CapturedListener> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, listener_rx.recv()).await {
            Ok(Some(listener)) if listener.tgid == pid && listener.port == port => {
                return Some(listener);
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("listener channel closed"),
            Err(_) => return None,
        }
    }
}

async fn assert_discovers_listener(family: SocketFamily, network_flows_enabled: bool) {
    let (mut program, _rx, _flow_rx, _l7_rx, mut listener_rx) = program();
    program
        .start(&enabled_section(network_flows_enabled))
        .expect("load + attach capture programs (incl. listener discovery)");

    let (mut child, pid, port) = spawn_bound_socket(family, true);
    let listener = receive_listener(&mut listener_rx, pid, port, Duration::from_secs(5))
        .await
        .expect("timed out waiting for listener discovery");

    assert_eq!(listener.family, family.libc());
    assert_ne!(
        listener.cgroup_id, 0,
        "listener discovery must stamp the task's cgroup id in-kernel"
    );
    assert_ne!(
        listener.observed_at_ns, 0,
        "listener discovery must stamp successful listen completion with monotonic time"
    );

    stop_child(&mut child);
    program.stop();
}

#[test]
fn listener_drain_exit_becomes_capture_error() {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (health_tx, health_rx) = watch::channel(ListenerDrainHealth {
        generation: 7,
        running: true,
    });
    assert!(ensure_listener_drain_running(&running).is_ok());

    drop(ListenerDrainGuard {
        running: std::sync::Arc::clone(&running),
        health_tx,
        generation: 7,
    });

    assert_eq!(
        ensure_listener_drain_running(&running).unwrap_err(),
        "LISTENER_EVENTS drain stopped after capture start"
    );
    assert_eq!(
        *health_rx.borrow(),
        ListenerDrainHealth {
            generation: 7,
            running: false,
        }
    );
}

#[test]
fn stale_drain_exit_cannot_overwrite_replacement_health() {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (health_tx, health_rx) = watch::channel(ListenerDrainHealth {
        generation: 8,
        running: true,
    });

    drop(ListenerDrainGuard {
        running,
        health_tx,
        generation: 7,
    });

    assert_eq!(
        *health_rx.borrow(),
        ListenerDrainHealth {
            generation: 8,
            running: true,
        }
    );
}

#[test]
fn stale_drain_exit_cannot_mask_replacement_failure() {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (health_tx, health_rx) = watch::channel(ListenerDrainHealth {
        generation: 8,
        running: false,
    });

    drop(ListenerDrainGuard {
        running,
        health_tx,
        generation: 7,
    });

    assert_eq!(
        *health_rx.borrow(),
        ListenerDrainHealth {
            generation: 8,
            running: false,
        }
    );
}

#[test]
fn listener_fence_acknowledges_only_after_the_sampled_publication_count() {
    let (ack, mut receiver) = oneshot::channel();
    let mut pending = vec![ListenerFence {
        published_counts: vec![2],
        ack,
    }];
    let mut sequences = ListenerSequences::default();

    advance_listener_sequence(&mut sequences, 0, 1).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    advance_listener_sequence(&mut sequences, 0, 2).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert_eq!(receiver.try_recv().unwrap(), Ok(()));
    assert!(pending.is_empty());
}

#[test]
fn listener_fence_waits_for_a_contiguous_per_cpu_sequence() {
    let mut sequences = ListenerSequences::default();
    let (ack, mut receiver) = oneshot::channel();
    let mut pending = vec![ListenerFence {
        published_counts: vec![1],
        ack,
    }];

    advance_listener_sequence(&mut sequences, 0, 2).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert_eq!(sequences.by_cpu[&0].contiguous, 0);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    advance_listener_sequence(&mut sequences, 0, 1).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert_eq!(sequences.by_cpu[&0].contiguous, 2);
    assert_eq!(receiver.try_recv().unwrap(), Ok(()));
}

#[test]
fn listener_fence_does_not_substitute_another_cpus_sequence() {
    let mut sequences = ListenerSequences::default();
    let (ack, mut receiver) = oneshot::channel();
    let mut pending = vec![ListenerFence {
        published_counts: vec![1, 0],
        ack,
    }];

    advance_listener_sequence(&mut sequences, 1, 1).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    advance_listener_sequence(&mut sequences, 0, 1).unwrap();
    acknowledge_listener_fences(&mut pending, &sequences);
    assert_eq!(receiver.try_recv().unwrap(), Ok(()));
}

#[test]
fn listener_sequence_gap_budget_is_global_across_cpus() {
    let mut sequences = ListenerSequences::default();
    for index in 0..MAX_OUT_OF_ORDER_LISTENER_SEQUENCES {
        let cpu_id = (index % MAX_LISTENER_SEQUENCE_CPUS) as u32;
        let sequence = (index / MAX_LISTENER_SEQUENCE_CPUS + 2) as u64;
        advance_listener_sequence(&mut sequences, cpu_id, sequence).unwrap();
    }

    let error = advance_listener_sequence(
        &mut sequences,
        0,
        (MAX_OUT_OF_ORDER_LISTENER_SEQUENCES / MAX_LISTENER_SEQUENCE_CPUS + 2) as u64,
    )
    .unwrap_err();

    assert!(error.contains("sequence gaps exceeded"));
}

/// A successful TCP listener transition is the authoritative live
/// port→cgroup discovery signal. Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn discovers_a_listening_port() {
    assert_discovers_listener(SocketFamily::Ipv4, false).await;
}

/// IPv6 listeners carry the same port→cgroup signal and retain AF_INET6 in the
/// shared event layout. Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn discovers_an_ipv6_listening_port() {
    assert_discovers_listener(SocketFamily::Ipv6, true).await;
}

/// Binding a client/source socket does not make it a listener and must not
/// authorize its cgroup for capture. Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn ignores_a_bound_socket_that_never_listens() {
    let (mut program, _rx, _flow_rx, _l7_rx, mut listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. listener discovery)");

    let (mut child, pid, port) = spawn_bound_socket(SocketFamily::Ipv4, false);
    let observed = receive_listener(&mut listener_rx, pid, port, Duration::from_secs(1)).await;

    assert!(
        observed.is_none(),
        "a bound socket that never listens must not be discovered"
    );

    stop_child(&mut child);
    program.stop();
}

/// A failed bind never owns the port and must not authorize the caller's
/// cgroup for capture. Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn ignores_a_failed_bind() {
    let (mut program, _rx, _flow_rx, _l7_rx, mut listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. listener discovery)");

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("hold a TCP port so the child bind fails");
    let port = listener.local_addr().expect("held socket address").port();
    let script = format!(
        "import socket\n\
         s=socket.socket()\n\
         s.bind(('127.0.0.1',{port}))"
    );
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn failed-bind child (python3)");
    let pid = child.id();
    let status = child.wait().expect("wait for failed-bind child");
    assert!(!status.success(), "the child bind must fail");

    let observed = receive_listener(&mut listener_rx, pid, port, Duration::from_secs(1)).await;

    assert!(
        observed.is_none(),
        "a failed bind must not be discovered as a listener"
    );

    drop(listener);
    program.stop();
}

/// Two SO_REUSEADDR sockets can bind one port, but only one can become the TCP
/// listener. The failed listen(2) must not duplicate the successful discovery.
/// Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn ignores_a_failed_listen() {
    let (mut program, _rx, _flow_rx, _l7_rx, mut listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. listener discovery)");

    let (mut child, pid, port) = spawn_failed_listen();
    let listener = receive_listener(&mut listener_rx, pid, port, Duration::from_secs(5))
        .await
        .expect("successful listen must be discovered");
    assert_eq!(listener.family, libc::AF_INET as u16);
    assert_ne!(listener.cgroup_id, 0);
    assert_ne!(listener.observed_at_ns, 0);

    let duplicate = receive_listener(&mut listener_rx, pid, port, Duration::from_secs(1)).await;
    assert!(
        duplicate.is_none(),
        "the failed listen must not emit a second discovery event"
    );

    stop_child(&mut child);
    program.stop();
}

/// End-to-end L7 capture: a targeted PID does a real HTTP request/response
/// over a socket; the captured bytes reassemble + parse into a span. Exercises
/// the read+write tracepoints, the verifier accepting the L7 programs, the
/// `L7_EVENTS` ring, and the userspace parser end to end. Requires CAP_BPF +
/// python3.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn captures_a_targeted_l7_request() {
    use super::super::l7::ConnRegistry;

    let (mut program, _rx, _flow_rx, mut l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. L7) from the embedded object");

    // A process acting as an HTTP server over a socketpair: it recv()s a
    // request and send()s a response. The other end injects the request and
    // reads the response — those land on a different fd whose stream the parser
    // drops (a request parsed as a response is invalid), so only the server
    // fd yields a record.
    let script = "\
import socket, time
time.sleep(1)
a, b = socket.socketpair()
a.sendall(b'GET /l7test HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')
b.recv(4096)
b.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n')
a.recv(4096)
";
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .spawn()
        .expect("spawn python3 http exchange");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    // Feed captured segments into the reassembler until the request/response
    // round-trip parses into the expected record (or we time out). Other fds
    // (the client side, and fds reused from earlier file reads) yield no
    // matching record, so we filter by operation rather than taking the first.
    let mut conns = ConnRegistry::new();
    let (record, cgroup_id) = tokio::time::timeout(Duration::from_secs(8), async {
        let mut last_cgroup = 0u64;
        loop {
            let seg = l7_rx.recv().await.expect("L7 channel closed");
            if seg.pid == pid {
                last_cgroup = seg.cgroup_id;
            }
            if let Some(rec) = conns
                .on_segment(&seg)
                .into_iter()
                .find(|r| r.operation == "GET /l7test")
            {
                return (rec, last_cgroup);
            }
        }
    })
    .await
    .expect("timed out waiting for the parsed L7 record");

    assert_eq!(record.status_code, 200);
    assert!(!record.error);
    assert_ne!(
        cgroup_id, 0,
        "L7 capture must stamp the target task's cgroup id in-kernel"
    );

    let _ = child.wait();
}

/// End-to-end TLS capture: a targeted PID does an HTTPS exchange over OpenSSL;
/// the SSL_read/SSL_write uprobes recover the plaintext, which reassembles +
/// parses into a span — proving we see inside encryption. Requires CAP_BPF +
/// python3 + openssl.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3 + openssl; run under sudo on the ebpf-spike VM"]
async fn captures_a_targeted_tls_request() {
    use super::super::l7::ConnRegistry;

    let (mut program, _rx, _flow_rx, mut l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. TLS uprobes)");

    // One process acting as both TLS server + client over a socketpair (both
    // OpenSSL-wrapped). The server side SSL_read's the request and SSL_write's
    // the response — the uprobes tap that plaintext before/after encryption.
    let script = r#"
import socket, ssl, threading, subprocess, tempfile, os, time
d = tempfile.mkdtemp()
cert = os.path.join(d, 'c.pem'); key = os.path.join(d, 'k.pem')
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-keyout',key,'-out',cert,
            '-days','1','-nodes','-subj','/CN=localhost'], check=True, capture_output=True)
time.sleep(1)
c, s = socket.socketpair()
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(cert, key)
cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.load_verify_locations(cert)
def server():
    ss = sctx.wrap_socket(s, server_side=True)
    ss.recv(4096)
    ss.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    time.sleep(0.5)
t = threading.Thread(target=server); t.start()
cs = cctx.wrap_socket(c, server_side=False, server_hostname='localhost')
cs.sendall(b'GET /tls HTTP/1.1\r\nHost: x\r\n\r\n')
cs.recv(4096)
t.join()
"#;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .spawn()
        .expect("spawn python3 TLS exchange");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    // The server side's SSL* stream reassembles the decrypted request +
    // response into a record; the client SSL* stream and the raw ciphertext
    // fds yield no "GET /tls" match.
    let mut conns = ConnRegistry::new();
    let record = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let seg = l7_rx.recv().await.expect("L7 channel closed");
            if let Some(rec) = conns
                .on_segment(&seg)
                .into_iter()
                .find(|r| r.operation == "GET /tls")
            {
                return rec;
            }
        }
    })
    .await
    .expect("timed out waiting for the decrypted TLS L7 record");

    assert_eq!(record.status_code, 200);
    assert!(!record.error);

    let _ = child.wait();
}

/// End-to-end validation on real hardware: the embedded `.o` loads, the verifier
/// accepts the programs, attach succeeds, the target PID seeds, and a real
/// `write(2)` from that PID is drained as a `CapturedLine`. Requires CAP_BPF.
#[tokio::test]
#[ignore = "requires CAP_BPF/root; run under sudo on the ebpf-spike VM"]
async fn captures_a_targeted_write() {
    let (mut program, mut rx, _flow_rx, _l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");

    let marker = "EDGEPACER_INAGENT_CAPTURE_OK";
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("sleep 1; printf '%s\\n' '{marker}'"))
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn marker child");
    let pid = child.id();

    let routing = routing_for(pid);
    program
        .set_target_pids(&routing)
        .expect("seed TARGET_PIDS with the child PID");

    let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a captured write")
        .expect("capture channel closed");

    assert_eq!(line.pid, pid, "captured the targeted PID's write");
    assert_eq!(
        line.policy_generation,
        routing
            .policy_generation()
            .expect("nonempty PID routing generation"),
        "the kernel stamps the generation that authorized the PID"
    );
    assert!(
        String::from_utf8_lossy(&line.bytes).contains(marker),
        "captured bytes contain the marker: {:?}",
        String::from_utf8_lossy(&line.bytes)
    );

    let _ = child.wait();
    program.stop();
}

struct TestCgroupTree {
    root: PathBuf,
    allowed: PathBuf,
    allowed_leaf: PathBuf,
    denied: PathBuf,
    allowed_anchor: CgroupAnchor,
    denied_anchor: CgroupAnchor,
    allowed_leaf_id: u64,
}

impl TestCgroupTree {
    fn create() -> Self {
        let current = std::fs::read_to_string("/proc/self/cgroup").expect("read current cgroup");
        let current = super::super::cgroup_v2::parse_unified_cgroup_path(&current)
            .expect("one unified cgroup entry");
        let current_dir =
            super::super::cgroup_v2::join_cgroup_mount(Path::new("/sys/fs/cgroup"), &current)
                .expect("join current cgroup path");
        let unique = format!(
            "edgepacer-capture-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("wall clock after epoch")
                .as_nanos()
        );
        let root = current_dir.join(unique);
        let allowed = root.join("allowed");
        let allowed_leaf = allowed.join("leaf");
        let denied = root.join("denied");
        std::fs::create_dir(&root).expect("create test cgroup root");
        std::fs::create_dir(&allowed).expect("create allowed cgroup");
        std::fs::create_dir(&allowed_leaf).expect("create allowed descendant cgroup");
        std::fs::create_dir(&denied).expect("create denied cgroup");

        let current_level = current
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .count() as u32;
        let allowed_anchor = CgroupAnchor {
            id: std::fs::metadata(&allowed)
                .expect("stat allowed cgroup")
                .ino(),
            level: current_level + 2,
        };
        let denied_anchor = CgroupAnchor {
            id: std::fs::metadata(&denied)
                .expect("stat denied cgroup")
                .ino(),
            level: current_level + 2,
        };
        let allowed_leaf_id = std::fs::metadata(&allowed_leaf)
            .expect("stat allowed leaf cgroup")
            .ino();

        Self {
            root,
            allowed,
            allowed_leaf,
            denied,
            allowed_anchor,
            denied_anchor,
            allowed_leaf_id,
        }
    }

    fn move_pid(path: &Path, pid: u32) {
        std::fs::write(path.join("cgroup.procs"), pid.to_string())
            .expect("move marker process into test cgroup");
    }
}

impl Drop for TestCgroupTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.allowed_leaf);
        let _ = std::fs::remove_dir(&self.allowed);
        let _ = std::fs::remove_dir(&self.denied);
        let _ = std::fs::remove_dir(&self.root);
    }
}

fn spawn_cgroup_marker(marker: &str) -> Child {
    std::process::Command::new("sh")
        .arg("-c")
        .arg("IFS= read -r _; printf '%s\\n' \"$1\"")
        .arg("edgepacer-cgroup-marker")
        .arg(marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn cgroup marker child")
}

fn release_cgroup_marker(child: &mut Child) {
    child
        .stdin
        .take()
        .expect("marker child stdin pipe")
        .write_all(b"\n")
        .expect("release cgroup marker child");
}

fn wait_for_cgroup_marker(child: &mut Child) {
    let status = child.wait().expect("wait for cgroup marker child");
    assert!(status.success(), "cgroup marker child failed: {status}");
}

fn spawn_cgroup_stream(marker: &str) -> Child {
    std::process::Command::new("python3")
        .arg("-u")
        .arg("-c")
        .arg("import os, sys\nmarker = (sys.argv[1] + '\\n').encode()\nwhile os.read(0, 1):\n    os.write(1, marker)\n")
        .arg(marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn cgroup stream child")
}

fn pump_cgroup_stream(
    child: &mut Child,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    let mut stdin = child.stdin.take().expect("cgroup stream stdin pipe");
    std::thread::spawn(move || {
        while running.load(std::sync::atomic::Ordering::Acquire) {
            stdin.write_all(b"\n").expect("trigger cgroup stream write");
            std::thread::sleep(Duration::from_micros(250));
        }
    })
}

async fn receive_cgroup_marker(
    rx: &mut mpsc::Receiver<CapturedLine>,
    marker: &str,
    timeout: Duration,
) -> Option<CapturedLine> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let line = tokio::time::timeout_at(deadline, rx.recv()).await.ok()??;
        if String::from_utf8_lossy(&line.bytes).contains(marker) {
            return Some(line);
        }
    }
}

async fn receive_l7_marker(
    rx: &mut mpsc::Receiver<CapturedSegment>,
    marker: &[u8],
    timeout: Duration,
) -> Option<CapturedSegment> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let segment = tokio::time::timeout_at(deadline, rx.recv()).await.ok()??;
        if segment
            .bytes
            .windows(marker.len())
            .any(|bytes| bytes == marker)
        {
            return Some(segment);
        }
    }
}

struct CgroupPolicySubject<'a> {
    path: &'a Path,
    anchor: CgroupAnchor,
    cgroup_id: u64,
}

async fn assert_cgroup_policy_round(
    program: &mut AyaCaptureProgram,
    rx: &mut mpsc::Receiver<CapturedLine>,
    authorized: &CgroupPolicySubject<'_>,
    unauthorized: &CgroupPolicySubject<'_>,
    previous_generation: Option<u64>,
    generation: u64,
) {
    let routing = CgroupRouting::from_entries(
        generation,
        [(authorized.anchor, format!("round-{generation}"))],
    )
    .unwrap();

    let authorized_stream_marker = format!("EDGEPACER_CGROUP_STREAM_NEXT_{generation}");
    let previous_stream_marker = format!("EDGEPACER_CGROUP_STREAM_PREVIOUS_{generation}");
    let mut authorized_stream = spawn_cgroup_stream(&authorized_stream_marker);
    let mut previous_stream = spawn_cgroup_stream(&previous_stream_marker);
    TestCgroupTree::move_pid(authorized.path, authorized_stream.id());
    TestCgroupTree::move_pid(unauthorized.path, previous_stream.id());
    let streams_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let authorized_pump = pump_cgroup_stream(
        &mut authorized_stream,
        std::sync::Arc::clone(&streams_running),
    );
    let previous_pump = pump_cgroup_stream(
        &mut previous_stream,
        std::sync::Arc::clone(&streams_running),
    );

    // Keep both the old- and new-policy cgroups writing before, throughout,
    // and after the inactive-map rewrite plus selector publication.
    std::thread::sleep(Duration::from_millis(20));
    let publication = program.set_allowed_cgroups(&routing);
    std::thread::sleep(Duration::from_millis(20));
    streams_running.store(false, std::sync::atomic::Ordering::Release);
    authorized_pump.join().expect("join authorized stream pump");
    previous_pump.join().expect("join previous stream pump");
    wait_for_cgroup_marker(&mut authorized_stream);
    wait_for_cgroup_marker(&mut previous_stream);
    publication.expect("atomically replace active cgroup policy");

    let authorized_marker = format!("EDGEPACER_CGROUP_ALLOWED_{generation}");
    let unauthorized_marker = format!("EDGEPACER_CGROUP_DENIED_{generation}");
    let mut authorized_child = spawn_cgroup_marker(&authorized_marker);
    let mut unauthorized_child = spawn_cgroup_marker(&unauthorized_marker);
    TestCgroupTree::move_pid(authorized.path, authorized_child.id());
    TestCgroupTree::move_pid(unauthorized.path, unauthorized_child.id());

    // Both children are parked on the same stdin barrier. Releasing them back
    // to back makes the allowed and denied writes race under one published
    // selector, exposing any stale identity left in a reused slot.
    release_cgroup_marker(&mut authorized_child);
    release_cgroup_marker(&mut unauthorized_child);
    wait_for_cgroup_marker(&mut authorized_child);
    wait_for_cgroup_marker(&mut unauthorized_child);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut authorized_event = None;
    let mut authorized_stream_event = false;
    let mut previous_stream_event = false;
    loop {
        let Ok(Some(line)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
            break;
        };
        let bytes = String::from_utf8_lossy(&line.bytes);
        if bytes.contains(&authorized_stream_marker) {
            assert_eq!(line.scope_cgroup_id, authorized.anchor.id);
            assert_eq!(line.cgroup_id, authorized.cgroup_id);
            assert_eq!(line.policy_generation, generation);
            authorized_stream_event = true;
        }
        if bytes.contains(&previous_stream_marker) {
            let previous_generation = previous_generation.unwrap_or_else(|| {
                panic!(
                    "empty policy captured the previous stream with scope={} policy_generation={}",
                    line.scope_cgroup_id, line.policy_generation
                )
            });
            assert_eq!(line.scope_cgroup_id, unauthorized.anchor.id);
            assert_eq!(line.cgroup_id, unauthorized.cgroup_id);
            assert_eq!(line.policy_generation, previous_generation);
            previous_stream_event = true;
        }
        assert!(
            !bytes.contains(&unauthorized_marker),
            "generation {generation} captured the denied sibling with scope={} policy_generation={}",
            line.scope_cgroup_id,
            line.policy_generation
        );
        if bytes.contains(&authorized_marker) {
            assert_eq!(line.scope_cgroup_id, authorized.anchor.id);
            assert_eq!(line.cgroup_id, authorized.cgroup_id);
            assert_eq!(line.policy_generation, generation);
            assert_ne!(line.capture_generation, 0);
            authorized_event = Some(line);
        }
    }
    assert!(
        authorized_event.is_some(),
        "generation {generation} did not capture the authorized cgroup write"
    );
    assert!(
        authorized_stream_event,
        "generation {generation} did not capture the new-policy stream after publication"
    );
    if previous_generation.is_some() {
        assert!(
            previous_stream_event,
            "generation {generation} did not capture the old-policy stream before publication"
        );
    }
}

fn spawn_blocking_read_child() -> Child {
    std::process::Command::new("python3")
        .arg("-u")
        .arg("-c")
        .arg(
            "import os\n\
             os.read(0, 1)\n\
             os.write(1, b'CONTROL_READY\\n')\n\
             os.read(0, 4096)\n\
             os.write(1, b'NEGATIVE_READY\\n')\n\
             os.read(0, 4096)\n",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn blocking read child")
}

fn write_child_stdin(child: &mut Child, bytes: &[u8]) {
    let stdin = child.stdin.as_mut().expect("blocking child stdin pipe");
    stdin.write_all(bytes).expect("write blocking child stdin");
    stdin.flush().expect("flush blocking child stdin");
}

fn wait_for_l7_read_entry(
    program: &mut AyaCaptureProgram,
    pid: u32,
    expected_cgroup_id: u64,
    expected_scope_cgroup_id: u64,
    expected_policy_generation: u64,
    timeout: Duration,
) {
    let key = ((pid as u64) << 32) | pid as u64;
    let loaded = program.loaded.as_mut().expect("capture program loaded");
    let map = loaded
        .ebpf
        .map_mut("L7_READ_ARGS")
        .expect("L7_READ_ARGS map present");
    // Kernel ReadArgs is five contiguous u64s: buf, fd, and CaptureScope's
    // actual cgroup, matched scope, and policy generation.
    let args: AyaHashMap<_, u64, [u64; 5]> =
        AyaHashMap::try_from(map).expect("open L7_READ_ARGS map");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match args.get(&key, 0) {
            Ok([_buf, _fd, cgroup_id, scope_cgroup_id, policy_generation]) => {
                assert_eq!(cgroup_id, expected_cgroup_id);
                assert_eq!(scope_cgroup_id, expected_scope_cgroup_id);
                assert_eq!(policy_generation, expected_policy_generation);
                return;
            }
            Err(MapError::KeyNotFound) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(MapError::KeyNotFound) => {
                panic!("timed out waiting for child {pid} to enter read(2)")
            }
            Err(error) => panic!("read L7_READ_ARGS for child {pid}: {error}"),
        }
    }
}

/// Proves cgroup-only authorization for logs and network flows, ancestor
/// matching, sibling exclusion, repeated atomic policy replacement with both
/// map slots reused, and policy clearing against the real kernel.
#[tokio::test]
#[ignore = "requires root, writable cgroup v2, and python3; run on the ebpf-spike VM"]
async fn cgroup_policy_captures_descendants_and_replaces_atomically() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "test must run as root");
    let tree = TestCgroupTree::create();
    let (mut program, mut rx, mut flow_rx, _l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");
    program
        .set_target_pids(&PidRouting::default())
        .expect("keep PID fallback empty");

    let allowed = CgroupPolicySubject {
        path: &tree.allowed_leaf,
        anchor: tree.allowed_anchor,
        cgroup_id: tree.allowed_leaf_id,
    };
    let denied = CgroupPolicySubject {
        path: &tree.denied,
        anchor: tree.denied_anchor,
        cgroup_id: tree.denied_anchor.id,
    };

    // Initial publication plus three replacements alternates A/B/A/B. The
    // third and fourth publications necessarily reuse the two inactive maps,
    // so stale IDs or generations left in either slot become observable.
    assert_cgroup_policy_round(&mut program, &mut rx, &allowed, &denied, None, 1).await;

    let mut connect_child = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import socket,sys; sys.stdin.buffer.read(1); \
             socket.socket().connect_ex(('127.0.0.1', 9999))",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cgroup-authorized connect child");
    let connect_pid = connect_child.id();
    TestCgroupTree::move_pid(&tree.allowed_leaf, connect_pid);
    connect_child
        .stdin
        .take()
        .expect("connect child stdin pipe")
        .write_all(b"\n")
        .expect("release cgroup-authorized connect child");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let flow = loop {
        let flow = tokio::time::timeout_at(deadline, flow_rx.recv())
            .await
            .expect("timed out waiting for a cgroup-authorized connect")
            .expect("flow channel closed");
        if flow.pid == connect_pid {
            break flow;
        }
    };
    assert_eq!(flow.cgroup_id, tree.allowed_leaf_id);
    assert_eq!(flow.scope_cgroup_id, tree.allowed_anchor.id);
    assert_eq!(flow.policy_generation, 1);
    assert_ne!(flow.capture_generation, 0);
    assert_eq!(flow.daddr, [127, 0, 0, 1]);
    assert_eq!(flow.dport, 9999);
    let status = connect_child.wait().expect("wait for connect child");
    assert!(status.success(), "connect child failed: {status}");

    assert_cgroup_policy_round(&mut program, &mut rx, &denied, &allowed, Some(1), 2).await;
    assert_cgroup_policy_round(&mut program, &mut rx, &allowed, &denied, Some(2), 3).await;
    assert_cgroup_policy_round(&mut program, &mut rx, &denied, &allowed, Some(3), 4).await;

    program
        .set_allowed_cgroups(&CgroupRouting::default())
        .expect("clear active cgroup policy");
    let cleared_marker = "EDGEPACER_CGROUP_CLEARED";
    let mut cleared_child = spawn_cgroup_marker(cleared_marker);
    TestCgroupTree::move_pid(&tree.denied, cleared_child.id());
    release_cgroup_marker(&mut cleared_child);
    wait_for_cgroup_marker(&mut cleared_child);
    assert!(
        receive_cgroup_marker(&mut rx, cleared_marker, Duration::from_secs(2))
            .await
            .is_none(),
        "cleared cgroup policy must capture nothing"
    );
    program.stop();
}

/// A read authorized at syscall entry must not be emitted under a replacement
/// policy at syscall exit. Polling the in-kernel args map makes the policy flip
/// deterministic instead of relying on a scheduling sleep.
#[tokio::test]
#[ignore = "requires root, writable cgroup v2, and python3; run on the ebpf-spike VM"]
async fn cgroup_policy_change_drops_an_in_flight_read() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "test must run as root");
    let tree = TestCgroupTree::create();
    let (mut program, _rx, _flow_rx, mut l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");
    program
        .set_target_pids(&PidRouting::default())
        .expect("keep PID fallback empty");
    program
        .set_allowed_cgroups(
            &CgroupRouting::from_entries(1, [(tree.allowed_anchor, "allowed")]).unwrap(),
        )
        .expect("activate allowed workload cgroup");

    let mut child = spawn_blocking_read_child();
    let pid = child.id();
    TestCgroupTree::move_pid(&tree.allowed_leaf, pid);

    // The first byte releases a setup read that began before the child moved.
    // A positive read under the unchanged policy proves this fixture can emit
    // the expected descendant-cgroup identity before the replacement case.
    write_child_stdin(&mut child, b"S");
    let mut child_stdout = BufReader::new(child.stdout.take().expect("blocking child stdout pipe"));
    let mut control_ready = String::new();
    child_stdout
        .read_line(&mut control_ready)
        .expect("read blocking child readiness");
    assert_eq!(control_ready, "CONTROL_READY\n");
    let control_marker = b"EDGEPACER_IN_FLIGHT_READ_CONTROL";
    write_child_stdin(&mut child, control_marker);
    let control = receive_l7_marker(&mut l7_rx, control_marker, Duration::from_secs(5))
        .await
        .expect("unchanged cgroup policy captures the control read");
    assert_eq!(control.pid, pid);
    assert_eq!(control.cgroup_id, tree.allowed_leaf_id);
    assert_eq!(control.scope_cgroup_id, tree.allowed_anchor.id);
    assert_eq!(control.policy_generation, 1);
    assert_ne!(control.capture_generation, 0);

    let mut negative_ready = String::new();
    child_stdout
        .read_line(&mut negative_ready)
        .expect("read negative-case readiness");
    assert_eq!(negative_ready, "NEGATIVE_READY\n");

    // The child has now entered a second authorized read. The map poll proves
    // its enter probe persisted generation 1 before the policy is replaced.
    wait_for_l7_read_entry(
        &mut program,
        pid,
        tree.allowed_leaf_id,
        tree.allowed_anchor.id,
        1,
        Duration::from_secs(5),
    );

    program
        .set_allowed_cgroups(
            &CgroupRouting::from_entries(2, [(tree.allowed_anchor, "allowed-v2")]).unwrap(),
        )
        .expect("replace the same scope generation while child is blocked in read(2)");
    let marker = b"EDGEPACER_IN_FLIGHT_READ_MUST_DROP";
    write_child_stdin(&mut child, marker);
    wait_for_cgroup_marker(&mut child);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let Ok(Some(segment)) = tokio::time::timeout_at(deadline, l7_rx.recv()).await else {
            break;
        };
        assert!(
            segment.pid != pid
                || !segment
                    .bytes
                    .windows(marker.len())
                    .any(|bytes| bytes == marker),
            "read spanning the policy change was emitted with scope={} policy_generation={}",
            segment.scope_cgroup_id,
            segment.policy_generation
        );
    }
    program.stop();
}

/// Same validation via `writev(2)` (python3's `os.writev`), exercising the
/// `capture_writev` tracepoint that closes the writev gap (decision 5).
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn captures_a_targeted_writev() {
    let (mut program, mut rx, _flow_rx, _l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs from the embedded object");

    let marker = "EDGEPACER_WRITEV_OK";
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import os,time; time.sleep(1); os.writev(1, [b'{marker}\\n'])"
        ))
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn writev child (python3)");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let line = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for a captured writev")
            .expect("capture channel closed");
        if line.pid == pid && String::from_utf8_lossy(&line.bytes).contains(marker) {
            break;
        }
    }

    let _ = child.wait();
    program.stop();
}

/// Proves the `CONNECT_EVENTS` drain: a targeted child's outbound `connect(2)`
/// is captured as a `CapturedFlow`. The connect to a refused local port still
/// fires `sys_enter_connect`. Requires CAP_BPF + python3 on the VM.
#[tokio::test]
#[ignore = "requires CAP_BPF/root + python3; run under sudo on the ebpf-spike VM"]
async fn captures_a_targeted_connect() {
    let (mut program, _rx, mut flow_rx, _l7_rx, _listener_rx) = program();
    program
        .start(&enabled_section(true))
        .expect("load + attach capture programs (incl. connect)");

    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg("import socket,time; time.sleep(1); socket.socket().connect(('127.0.0.1', 9999))")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn connect child (python3)");
    let pid = child.id();

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let flow = loop {
        let flow = tokio::time::timeout_at(deadline, flow_rx.recv())
            .await
            .expect("timed out waiting for a captured connect")
            .expect("flow channel closed");
        if flow.pid == pid {
            break flow;
        }
    };

    assert_eq!(flow.daddr, [127, 0, 0, 1], "captured destination IPv4");
    assert_eq!(flow.dport, 9999, "captured destination port");

    let _ = child.wait();
    program.stop();
}
