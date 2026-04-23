//! Spawns `quic_pong_quinn` and `quic_ping` to verify one round-trip echo (Quinn ↔ Quinn).

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn quic_ping_round_trip_against_quic_pong_quinn() {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let mut server = Command::new(env!("CARGO_BIN_EXE_quic_pong_quinn"))
        .args([
            "--port",
            &port.to_string(),
            "--exit-delay-secs",
            "5",
            "--threads",
            "2",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn quic_pong_quinn");

    thread::sleep(Duration::from_millis(600));

    let out = Command::new(env!("CARGO_BIN_EXE_quic_ping"))
        .args([
            "--addr",
            &format!("127.0.0.1:{port}"),
            "--threads",
            "2",
        ])
        .output()
        .expect("run quic_ping");

    let _ = server.kill();
    let _ = server.wait();

    assert!(
        out.status.success(),
        "quic_ping exit {}\nstderr:\n{}\nstdout:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("quic_ping: ok"),
        "expected success marker in stdout, got:\n{stdout}"
    );
}
