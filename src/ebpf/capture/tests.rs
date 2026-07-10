use super::*;
use crate::config::EbpfTargetConfig;
use crate::discovery::ports::ListeningPort;
use std::io::{BufRead, BufReader};
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

    program
        .set_target_pids(&routing_for(pid))
        .expect("seed TARGET_PIDS with the child PID");

    let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a captured write")
        .expect("capture channel closed");

    assert_eq!(line.pid, pid, "captured the targeted PID's write");
    assert!(
        String::from_utf8_lossy(&line.bytes).contains(marker),
        "captured bytes contain the marker: {:?}",
        String::from_utf8_lossy(&line.bytes)
    );

    let _ = child.wait();
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
