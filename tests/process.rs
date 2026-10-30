//! The released binary over real pipes: `hello`, exit codes, and every
//! failure that happens before the endpoint binds (so nothing here touches the
//! network). What happens after `ready` is covered in-process by `session.rs`,
//! which runs the same session code on loopback.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use fermix_iroh::protocol::{ErrorCode, Event};
use fermix_iroh::{IROH_VERSION, VERSION};
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_fermix-iroh");

/// The contract's bound on `hello`.
const HELLO_BOUND: Duration = Duration::from_secs(10);
/// The contract's bound between `error` and exit 1.
const ERROR_EXIT_BOUND: Duration = Duration::from_secs(2);
/// How often the exit is polled for.
const POLL: Duration = Duration::from_millis(10);

struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Proc {
    fn spawn() -> Self {
        let mut child = Command::new(BIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the helper binary starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout is piped");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let proc = Proc {
            child,
            stdin,
            lines,
        };
        let hello = proc.raw_line(HELLO_BOUND).expect("hello within 10 s");
        assert_eq!(
            format!("{hello}\n"),
            support::hello_fixture_for_this_build(),
            "hello is the first line"
        );
        proc
    }

    fn raw_line(&self, within: Duration) -> Option<String> {
        // A timeout or a closed stdout both mean "no line".
        self.lines.recv_timeout(within).ok()
    }

    fn event(&self) -> Event {
        let line = self.raw_line(Duration::from_secs(10)).expect("an event");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not an event {line:?}: {e}"))
    }

    /// Write bytes to stdin. The helper may already have exited on an earlier
    /// line, so a broken pipe is expected and not a failure.
    fn write(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        match stdin.write_all(bytes).and_then(|()| stdin.flush()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("writing stdin failed: {e}"),
        }
    }

    fn send(&mut self, op: &serde_json::Value) {
        let mut line = serde_json::to_vec(op).unwrap();
        line.push(b'\n');
        self.write(&line);
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Wait for the exit, at most `bound`; a helper still running is killed.
    fn wait(&mut self, bound: Duration) -> ExitStatus {
        let began = Instant::now();
        while began.elapsed() < bound {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            std::thread::sleep(POLL);
        }
        self.child.kill().expect("kill the overdue helper");
        panic!("the helper did not exit within {bound:?}");
    }

    /// Expect one `error` with `code`, then exit 1 within the contract's 2 s.
    fn expect_fatal(&mut self, code: ErrorCode) -> String {
        let event = self.event();
        let Event::Error { code: got, message } = event else {
            panic!("expected an error, got {event:?}");
        };
        assert_eq!(got, code, "{message}");
        assert!(message.len() <= 512);
        let status = self.wait(ERROR_EXIT_BOUND);
        assert_eq!(status.code(), Some(1));
        assert!(self.raw_line(Duration::from_millis(100)).is_none());
        message
    }
}

fn start_op(key: &Path, dir: &Path) -> serde_json::Value {
    json!({
        "op": "start",
        "secret_key_path": key,
        "bridge_socket": dir.join("bridge.sock"),
        "alpn": "fermix/mobile/1",
        "relays": [{ "url": "https://127.0.0.1:1/", "quic_port": 1 }],
        "limits": {
            "max_connections": 64,
            "max_streams_per_connection": 4,
            "stream_receive_window": 262144,
            "connection_receive_window": 1048576,
            "send_window": 1048576,
        }
    })
}

fn key_file(dir: &Path, len: usize, mode: u32) -> std::path::PathBuf {
    let path = dir.join("iroh_key");
    std::fs::write(&path, vec![9u8; len]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn end_of_stdin_before_start_exits_0_after_hello_only() {
    let mut p = Proc::spawn();
    p.close_stdin();
    assert_eq!(p.wait(Duration::from_secs(5)).code(), Some(0));
    assert!(p.raw_line(Duration::from_millis(100)).is_none());
}

#[test]
fn shutdown_before_start_exits_0() {
    let mut p = Proc::spawn();
    p.write(b"{\"op\":\"shutdown\"}\n");
    assert_eq!(p.wait(Duration::from_secs(5)).code(), Some(0));
}

#[test]
fn a_line_that_is_not_an_op_is_a_bad_request() {
    for line in [
        &b"not json\n"[..],
        b"[1,2]\n",
        b"{\"op\":\"reboot\"}\n",
        b"{\"op\":\"shutdown\",\"force\":true}\n",
        b"\n",
        b"{\"op\":\"shutdown\"}",
    ] {
        let mut p = Proc::spawn();
        p.write(line);
        if !line.ends_with(b"\n") {
            p.close_stdin();
        }
        p.expect_fatal(ErrorCode::BadRequest);
    }
}

#[test]
fn a_line_over_64_kib_is_a_bad_request() {
    let mut p = Proc::spawn();
    let mut line = vec![b' '; 64 * 1024 + 1];
    line.push(b'\n');
    p.write(&line);
    p.expect_fatal(ErrorCode::BadRequest);
}

#[test]
fn set_relays_before_start_is_a_bad_request() {
    let mut p = Proc::spawn();
    p.send(&json!({
        "op": "set_relays",
        "relays": [{ "url": "https://us1.relay.fermix.ai/", "quic_port": 7842 }]
    }));
    let message = p.expect_fatal(ErrorCode::BadRequest);
    assert!(message.contains("before ready"), "{message}");
}

#[test]
fn a_start_outside_the_contract_is_a_bad_request() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path(), 32, 0o600);
    let mutations: [fn(&mut serde_json::Value); 8] = [
        |op| op["alpn"] = json!("fermix/mobile/2"),
        |op| op["secret_key_path"] = json!("relative/iroh_key"),
        |op| op["relays"] = json!([]),
        |op| op["limits"]["max_streams_per_connection"] = json!(17),
        |op| op["limits"]["send_window"] = json!("1048576"),
        // The key and the bridge socket come together or not at all, and an
        // optional field is absent, never null.
        |op| drop(op.as_object_mut().unwrap().remove("bridge_socket")),
        |op| drop(op.as_object_mut().unwrap().remove("secret_key_path")),
        |op| op["secret_key_path"] = json!(null),
    ];
    for mutate in mutations {
        let mut op = start_op(&key, dir.path());
        mutate(&mut op);
        let mut p = Proc::spawn();
        p.send(&op);
        p.expect_fatal(ErrorCode::BadRequest);
    }
}

#[test]
fn a_dial_before_ready_is_a_bad_request() {
    let mut p = Proc::spawn();
    p.send(&json!({
        "op": "dial",
        "dial_id": "5f1c9a2e",
        "endpoint_id": "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        "relays": [{ "url": "https://us1.relay.fermix.ai/", "quic_port": 7842 }],
        "socket": "/tmp/dial-5f1c9a2e.sock"
    }));
    let message = p.expect_fatal(ErrorCode::BadRequest);
    assert!(message.contains("before ready"), "{message}");
}

#[test]
fn a_missing_key_is_key_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Proc::spawn();
    p.send(&start_op(&dir.path().join("absent"), dir.path()));
    p.expect_fatal(ErrorCode::KeyUnreadable);
}

#[test]
fn a_key_with_the_wrong_mode_or_size_is_key_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Proc::spawn();
    p.send(&start_op(&key_file(dir.path(), 32, 0o644), dir.path()));
    let message = p.expect_fatal(ErrorCode::KeyInvalid);
    assert_eq!(message, "key file mode is 0644, not 0600");

    let mut p = Proc::spawn();
    p.send(&start_op(&key_file(dir.path(), 31, 0o600), dir.path()));
    p.expect_fatal(ErrorCode::KeyInvalid);
}

#[test]
fn version_flag_answers_and_other_arguments_are_refused() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("fermix-iroh {VERSION} (iroh {IROH_VERSION})\n")
    );
    let out = Command::new(BIN).arg("--serve").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}
