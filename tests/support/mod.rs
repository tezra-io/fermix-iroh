//! Hermetic harness for driving a helper session in-process.
//!
//! Everything stays on loopback: a relay from iroh's own test utilities bound
//! to 127.0.0.1, a helper and phone-side client endpoints bound to 127.0.0.1
//! with no port mapping and no address lookup, and a fake bridge
//! `UnixListener` in a temporary directory. The helper session is the same
//! `session::run` the binary runs, given only a test `Network`.
//!
//! Also the one place the vendored `hello.json` is adapted to this build, for
//! `fixtures.rs` and `process.rs`.

#![allow(dead_code)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fermix_iroh::VERSION;
use fermix_iroh::endpoint::{BindScope, Network, Timings};
use fermix_iroh::protocol::Event;
use fermix_iroh::session::{self, Exit};
use iroh::endpoint::{Builder, Connection, PortmapperConfig, QuicTransportConfig, VarInt, presets};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// The ALPN the helper accepts.
pub const ALPN: &[u8] = b"fermix/mobile/1";

/// The bound on any single wait in these tests.
pub const STEP: Duration = Duration::from_secs(20);

/// The bound on a whole test.
pub const WHOLE_TEST: Duration = Duration::from_secs(90);

/// Run a test body under [`WHOLE_TEST`].
pub async fn bounded<F: Future<Output = ()>>(body: F) {
    tokio::time::timeout(WHOLE_TEST, body)
        .await
        .expect("the test finished within its bound");
}

/// Await `fut` for at most [`STEP`], naming what was awaited on failure.
pub async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(STEP, fut).await {
        Ok(value) => value,
        Err(_) => panic!("timed out after {STEP:?} waiting for {what}"),
    }
}

/// The helper's network for tests: trust the test relay's self-signed
/// certificate, bind loopback only, and ask no router for a port mapping.
pub fn test_network() -> Network {
    Network {
        ca_tls: CaTlsConfig::insecure_skip_verify(),
        scope: BindScope::Loopback,
        portmapper: PortmapperConfig::Disabled,
        timings: Timings::production(),
    }
}

/// A local relay server. Dropping it stops the server.
pub struct TestRelay {
    pub map: RelayMap,
    pub url: RelayUrl,
    pub quic_port: u16,
    _server: iroh_relay::server::Server,
}

impl TestRelay {
    pub async fn start() -> Self {
        let (map, url, server) = iroh::test_utils::run_relay_server()
            .await
            .expect("the test relay starts");
        let quic_port = map
            .get(&url)
            .and_then(|config| config.quic.as_ref().map(|quic| quic.port))
            .expect("the test relay serves QUIC address discovery");
        TestRelay {
            map,
            url,
            quic_port,
            _server: server,
        }
    }

    /// This relay as a `start`/`set_relays` entry.
    pub fn spec(&self) -> serde_json::Value {
        json!({ "url": self.url.to_string(), "quic_port": self.quic_port })
    }
}

/// A key file, a bridge socket path and the helper's stdio, in one temp dir.
pub struct Helper {
    pub dir: TempDir,
    pub key: SecretKey,
    pub key_path: PathBuf,
    pub socket_path: PathBuf,
    stdin: Option<DuplexStream>,
    stdout: BufReader<DuplexStream>,
    session: Option<JoinHandle<Exit>>,
}

impl Helper {
    /// Spawn a session and read its `hello`.
    pub async fn spawn() -> Self {
        Self::spawn_on(test_network()).await
    }

    /// Spawn a session on `net` and read its `hello`.
    pub async fn spawn_on(net: Network) -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let key = SecretKey::from_bytes(&rand_bytes());
        let key_path = dir.path().join("iroh_key");
        std::fs::write(&key_path, key.to_bytes()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let socket_path = dir.path().join("bridge.sock");
        assert!(
            socket_path.as_os_str().len() < 100,
            "the temp dir is too deep for a Unix socket path: {}",
            socket_path.display()
        );
        let (stdin_tx, stdin_rx) = tokio::io::duplex(128 * 1024);
        let (stdout_tx, stdout_rx) = tokio::io::duplex(128 * 1024);
        let session = tokio::spawn(session::run(stdin_rx, stdout_tx, net));
        let mut helper = Helper {
            dir,
            key,
            key_path,
            socket_path,
            stdin: Some(stdin_tx),
            stdout: BufReader::new(stdout_rx),
            session: Some(session),
        };
        let hello = helper.next_event().await;
        assert_eq!(hello, Event::hello());
        helper
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.key.public()
    }

    /// Listen on the bridge socket, as the daemon does.
    pub fn listen_bridge(&self) -> UnixListener {
        UnixListener::bind(&self.socket_path).expect("the fake bridge binds")
    }

    /// The contract's `start` with these relays and connection bound.
    pub fn start_op(&self, relays: &[&TestRelay], max_connections: u32) -> serde_json::Value {
        self.start_op_with_streams(relays, max_connections, 4)
    }

    /// The contract's `start` with these relays and both bounds.
    pub fn start_op_with_streams(
        &self,
        relays: &[&TestRelay],
        max_connections: u32,
        max_streams: u32,
    ) -> serde_json::Value {
        json!({
            "op": "start",
            "secret_key_path": self.key_path,
            "bridge_socket": self.socket_path,
            "alpn": "fermix/mobile/1",
            "relays": relays.iter().map(|r| r.spec()).collect::<Vec<_>>(),
            "limits": {
                "max_connections": max_connections,
                "max_streams_per_connection": max_streams,
                "stream_receive_window": 262144,
                "connection_receive_window": 1048576,
                "send_window": 1048576,
            }
        })
    }

    /// Send one op line.
    pub async fn send(&mut self, op: &serde_json::Value) {
        let mut line = serde_json::to_vec(op).unwrap();
        line.push(b'\n');
        self.send_raw(&line).await;
    }

    /// Send raw bytes on stdin.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        within("stdin to accept the op", stdin.write_all(bytes))
            .await
            .unwrap();
    }

    /// End stdin.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Start with `relays` and wait for `ready`, the bound-sockets log and the
    /// relay reporting connected to `home`.
    pub async fn start(&mut self, relays: &[&TestRelay], max_connections: u32, home: &TestRelay) {
        self.start_with(&self.start_op(relays, max_connections), home)
            .await;
    }

    /// Send `start_op` and wait as [`Self::start`] does.
    pub async fn start_with(&mut self, start_op: &serde_json::Value, home: &TestRelay) {
        self.send(start_op).await;
        let ready = self.next_event().await;
        assert_eq!(
            ready,
            Event::Ready {
                endpoint_id: self.endpoint_id().to_string()
            }
        );
        self.wait_relay_connected(home).await;
    }

    /// `start` naming these relay entries, with this helper's key and bridge
    /// socket (`listen`) or without either (an endpoint that only dials).
    pub fn start_op_for(&self, relays: &[serde_json::Value], listen: bool) -> serde_json::Value {
        let mut op = json!({
            "op": "start",
            "alpn": "fermix/mobile/1",
            "relays": relays,
            "limits": {
                "max_connections": 8,
                "max_streams_per_connection": 4,
                "stream_receive_window": 262144,
                "connection_receive_window": 1048576,
                "send_window": 1048576,
            }
        });
        if listen {
            op["secret_key_path"] = json!(self.key_path);
            op["bridge_socket"] = json!(self.socket_path);
        }
        op
    }

    /// Send `start_op_for` and read `ready` and the bound-sockets log; returns
    /// the endpoint id `ready` names and the endpoint's UDP address. A listening
    /// endpoint's id must be its key's.
    pub async fn start_on(
        &mut self,
        relays: &[serde_json::Value],
        listen: bool,
    ) -> (EndpointId, SocketAddr) {
        self.send(&self.start_op_for(relays, listen)).await;
        let Event::Ready { endpoint_id } = self.next_event().await else {
            panic!("start is answered with ready");
        };
        let id: EndpointId = endpoint_id.parse().expect("ready names an endpoint id");
        if listen {
            assert_eq!(id, self.endpoint_id());
        }
        let Event::Log { message, .. } = self.next_event().await else {
            panic!("ready is followed by the bound-sockets log");
        };
        let addr = message
            .strip_prefix("bound UDP sockets: ")
            .and_then(|list| list.split(", ").next())
            .and_then(|first| first.parse().ok())
            .unwrap_or_else(|| panic!("no UDP address in {message:?}"));
        (id, addr)
    }

    /// Wait for a `relay` event naming `home` as connected.
    pub async fn wait_relay_connected(&mut self, home: &TestRelay) {
        let url = home.url.to_string();
        self.expect(
            "relay connected",
            |e| matches!(e, Event::Relay { home_relay: Some(h), connected: true, .. } if *h == url),
        )
        .await;
    }

    /// The next event; every line must be one contract-valid event.
    pub async fn next_event(&mut self) -> Event {
        let mut line = String::new();
        let read = within("the next event", self.stdout.read_line(&mut line))
            .await
            .expect("stdout is readable");
        assert!(read > 0, "stdout ended while an event was expected");
        assert!(
            line.ends_with('\n'),
            "an event line ends with \\n: {line:?}"
        );
        assert!(line.len() <= 64 * 1024 + 1, "an event line fits 64 KiB");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not a contract event {line:?}: {e}"))
    }

    /// Skip events until one matches; return it.
    pub async fn expect(&mut self, what: &str, matches: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + STEP;
        loop {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            let event = self.next_event().await;
            if matches(&event) {
                return event;
            }
        }
    }

    /// Every event until stdout ends.
    pub async fn drain_events(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let mut line = String::new();
            let read = within("stdout to end", self.stdout.read_line(&mut line))
                .await
                .expect("stdout is readable");
            if read == 0 {
                return events;
            }
            events.push(serde_json::from_str(&line).expect("a contract event"));
        }
    }

    /// Wait for the session to end; returns how it ended and how long it took.
    pub async fn exit(&mut self) -> (Exit, Duration) {
        let began = Instant::now();
        let session = self.session.take().expect("the session is running");
        let exit = within("the session to exit", session)
            .await
            .expect("the session task did not panic");
        (exit, began.elapsed())
    }
}

fn rand_bytes() -> [u8; 32] {
    // Distinct per helper without a RNG dependency: hash the time and a counter.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seed = COUNTER.fetch_add(1, Ordering::SeqCst)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
    let mut out = [0u8; 32];
    let mut x = seed | 1;
    for byte in &mut out {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = x as u8;
    }
    out
}

/// A phone-side endpoint using only `relay`, bound to loopback.
pub async fn phone(relay: &TestRelay) -> Endpoint {
    bind_phone(phone_builder(relay)).await
}

/// A phone-side endpoint like [`phone`] that gives every stream no
/// flow-control credit: its stream receive window is 0, so the helper can
/// send nothing on a stream it opens, and reading grants none.
pub async fn phone_giving_no_credit(relay: &TestRelay) -> Endpoint {
    let transport = QuicTransportConfig::builder()
        .stream_receive_window(VarInt::from_u32(0))
        .build();
    bind_phone(phone_builder(relay).transport_config(transport)).await
}

fn phone_builder(relay: &TestRelay) -> Builder {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay.map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("a loopback bind address")
}

async fn bind_phone(builder: Builder) -> Endpoint {
    builder.bind().await.expect("the phone endpoint binds")
}

/// Dial the helper at `relay` only, offering `alpn`.
pub async fn dial(
    phone: &Endpoint,
    helper: EndpointId,
    relay: &TestRelay,
    alpn: &[u8],
) -> Result<Connection, String> {
    let addr = EndpointAddr::new(helper).with_relay_url(relay.url.clone());
    within("the dial", phone.connect(addr, alpn))
        .await
        .map_err(|e| e.to_string())
}

/// A relay entry nothing serves: a loopback port that refuses connections, so
/// the endpoint resolves no name and reaches nothing through it.
pub fn dead_relay() -> serde_json::Value {
    json!({ "url": "https://127.0.0.1:1/", "quic_port": 1 })
}

/// The contract's `dial`.
pub fn dial_op(
    dial_id: &str,
    peer: EndpointId,
    relays: &[serde_json::Value],
    socket: &Path,
    addrs: &[SocketAddr],
) -> serde_json::Value {
    let mut op = json!({
        "op": "dial",
        "dial_id": dial_id,
        "endpoint_id": peer.to_string(),
        "relays": relays,
        "socket": socket,
    });
    if !addrs.is_empty() {
        op["addrs"] = json!(addrs.iter().map(ToString::to_string).collect::<Vec<_>>());
    }
    op
}

/// Accept one bridge connection and read its 37-byte preamble.
pub async fn accept_bridge(listener: &UnixListener) -> (UnixStream, [u8; 37]) {
    let (mut unix, _) = within("a bridge connection", listener.accept())
        .await
        .expect("the bridge accepts");
    let mut preamble = [0u8; 37];
    within(
        "the preamble",
        tokio::io::AsyncReadExt::read_exact(&mut unix, &mut preamble),
    )
    .await
    .expect("37 preamble bytes");
    (unix, preamble)
}

/// The preamble the helper must write for `peer`.
pub fn expected_preamble(peer: EndpointId) -> [u8; 37] {
    let mut out = [0u8; 37];
    out[..4].copy_from_slice(b"FXB1");
    out[4] = 0x01;
    out[5..].copy_from_slice(peer.as_bytes());
    out
}

/// The `hello` line this build must send: the daemon's `hello.json`, byte for
/// byte, except the value of `helper_version`, which is this crate's own. The
/// fixture's value is the daemon's example; the contract pins the field, not
/// the helper's version.
pub fn hello_fixture_for_this_build() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/fixtures/hello.json");
    let fixture =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let field = r#""helper_version":""#;
    assert_eq!(
        fixture.matches(field).count(),
        1,
        "hello.json names {field} exactly once"
    );
    let start = fixture.find(field).unwrap() + field.len();
    let end = start
        + fixture[start..]
            .find('"')
            .expect("helper_version's value is a string");
    format!("{}{VERSION}{}", &fixture[..start], &fixture[end..])
}
