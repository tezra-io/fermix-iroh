//! The helper's one iroh endpoint.
//!
//! Built from iroh's `Minimal` preset (a crypto provider and nothing else):
//! the relay map is exactly the daemon's list, there is no address lookup
//! service, no proxy is read from the environment, and DNS goes only to the
//! system's configured nameservers (iroh's public fallback resolvers are turned
//! off). The daemon's limits become QUIC transport parameters. When every one
//! of `max_connections` places is taken, the accept loop gives a new connection
//! the place of the one that has gone longest with no stream open, and refuses
//! it before its handshake only when every place has a stream open. The
//! daemon's `close` reaches a peer's connections through [`Acceptor::close_peer`].
//! An endpoint started without a key and a bridge socket only dials: it
//! refuses every incoming connection before its handshake ([`refuse_all`]).

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use iroh::dns::{DnsResolver, FallbackMode};
use iroh::endpoint::{
    ConnectingError, Connection, ConnectionError, Incoming, PortmapperConfig, QuicTransportConfig,
    RecvStream, SendStream, TransportErrorCode, VarInt, presets,
};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::RelayQuicConfig;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::bridge::{self, StreamContext};
use crate::ndjson::EventSink;
use crate::protocol::{
    Event, LogLevel, RefusedReason, Relay, StartConfig, ValidLimits, kind_for_alpn,
};
use crate::status::PathTracker;

/// The environment variables that would route iroh's HTTPS relay probes
/// through a proxy. iroh 1.3.0's latency and captive-portal probes use reqwest,
/// whose default reads these (through hyper-util) whenever iroh itself has no
/// proxy configured; `proxy_from_env` is not the only way in. The binary
/// removes them from its own environment before anything starts, so a proxy
/// variable inherited from the daemon has no effect, as the contract says.
pub const PROXY_VARIABLES: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The TLS alert a server sends when no offered ALPN matches.
const TLS_ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

/// Where the endpoint binds its UDP sockets, on the port `start` names or on
/// ports the system picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    /// iroh's default: every interface, IPv4 and IPv6. The released helper.
    AllInterfaces,
    /// 127.0.0.1 only, `bind_port` included. Hermetic tests.
    Loopback,
}

/// The network-facing choices that differ between the released helper and the
/// hermetic test suite. The binary always uses [`Network::production`].
#[derive(Debug, Clone)]
pub struct Network {
    /// Trust anchors for the relays' TLS certificates.
    pub ca_tls: CaTlsConfig,
    /// Where to bind.
    pub scope: BindScope,
    /// Whether to ask the local router for a port mapping.
    pub portmapper: PortmapperConfig,
    /// How long a connection may hold a slot without finishing its handshake
    /// or without a stream.
    pub timings: Timings,
}

/// The bounds on how long a connection holds one of `max_connections`.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    /// A handshake not finished by then is dropped, freeing its slot, so a
    /// peer that only starts handshakes cannot hold the connection bound.
    pub handshake_deadline: Duration,
    /// A connection with no stream open for this long is closed with code 0,
    /// reason `idle`: iroh's keep-alive would otherwise keep it, and its slot,
    /// for as long as the peer answers. A phone renewing a session opens its
    /// next stream at once.
    pub streamless_idle: Duration,
    /// A dial whose stream is not open and connected to its socket by then
    /// fails `timeout`.
    pub dial_deadline: Duration,
}

impl Timings {
    /// The released helper's bounds.
    pub fn production() -> Self {
        Timings {
            handshake_deadline: Duration::from_secs(10),
            streamless_idle: Duration::from_secs(30),
            dial_deadline: Duration::from_secs(20),
        }
    }
}

impl Network {
    /// The released helper: Mozilla's roots compiled in, every interface, and a
    /// port mapping requested from the local router.
    pub fn production() -> Self {
        Network {
            ca_tls: CaTlsConfig::embedded(),
            scope: BindScope::AllInterfaces,
            portmapper: PortmapperConfig::default(),
            timings: Timings::production(),
        }
    }
}

/// The QUIC transport parameters for the daemon's limits.
///
/// Peers may open `max_streams_per_connection` bidirectional streams and no
/// unidirectional ones, and may send no unreliable datagrams: the helper only
/// bridges bidirectional streams, so nothing else may hold its memory.
pub fn transport_config(limits: &ValidLimits) -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(limits.max_streams_per_connection))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(limits.stream_receive_window))
        .receive_window(VarInt::from_u32(limits.connection_receive_window))
        .send_window(limits.send_window)
        .datagram_receive_buffer_size(None)
        .build()
}

/// The iroh relay config for one validated relay.
fn relay_config(relay: &Relay) -> RelayConfig {
    RelayConfig::new(
        relay.url.clone(),
        Some(RelayQuicConfig::new(relay.quic_port)),
    )
}

/// `EAFNOSUPPORT`, "address family not supported", in macOS's `<sys/errno.h>`.
#[cfg(target_os = "macos")]
const EAFNOSUPPORT: i32 = 47;
/// `EAFNOSUPPORT`, "address family not supported", in Linux's
/// `asm-generic/errno.h` (both release architectures).
#[cfg(target_os = "linux")]
const EAFNOSUPPORT: i32 = 97;

/// How the endpoint binds its UDP sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindPlan {
    /// iroh's own: every interface, IPv4 and, where the host has it, IPv6, on
    /// ports the system picks.
    Iroh,
    /// Exactly these addresses, each required: one the system refuses is
    /// `bind_failed`, never another address or port.
    Exactly(Vec<SocketAddr>),
    /// A `bind_port` on a kernel with no IPv6 at all: that port for IPv4
    /// alone, required, and a `log` that says so.
    Ipv4Only(SocketAddr),
}

impl BindPlan {
    /// The plan for a `start` in `scope`. A `bind_port` is that port for IPv4
    /// and IPv6 both, unless `kernel_has_ipv6`, asked only for a `bind_port`
    /// on every interface, says the kernel has no IPv6; on loopback it is
    /// 127.0.0.1's port alone.
    pub fn new(
        scope: BindScope,
        port: Option<u16>,
        kernel_has_ipv6: impl FnOnce() -> bool,
    ) -> Self {
        match (scope, port) {
            (BindScope::AllInterfaces, None) => BindPlan::Iroh,
            (BindScope::AllInterfaces, Some(port)) => Self::fixed(port, kernel_has_ipv6()),
            (BindScope::Loopback, port) => BindPlan::Exactly(vec![SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                port.unwrap_or(0),
            ))]),
        }
    }

    fn fixed(port: u16, ipv6: bool) -> Self {
        let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        if !ipv6 {
            return BindPlan::Ipv4Only(v4);
        }
        BindPlan::Exactly(vec![v4, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))])
    }

    /// The addresses to bind, or `None` for iroh's own.
    fn addrs(&self) -> Option<Vec<SocketAddr>> {
        match self {
            BindPlan::Iroh => None,
            BindPlan::Exactly(addrs) => Some(addrs.clone()),
            BindPlan::Ipv4Only(addr) => Some(vec![*addr]),
        }
    }

    /// The `log` the daemon gets about this plan after `ready`, if any.
    pub fn notice(&self) -> Option<String> {
        match self {
            BindPlan::Ipv4Only(addr) => Some(format!(
                "no IPv6 on this host: UDP port {} is bound for IPv4 only",
                addr.port()
            )),
            BindPlan::Iroh | BindPlan::Exactly(_) => None,
        }
    }
}

/// Whether the kernel has IPv6 at all: whether it can make an IPv6 UDP socket.
/// The socket is bound to `[::1]:0` and dropped at once, so nothing reaches
/// the network.
pub fn kernel_has_ipv6() -> bool {
    ipv6_supported(UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).map(drop))
}

/// Only "address family not supported" means the kernel has no IPv6. Any
/// other failure (no `::1`, a refused bind) keeps IPv6 in the plan, so the
/// real bind reports it as `bind_failed`.
fn ipv6_supported(probe: std::io::Result<()>) -> bool {
    !matches!(probe, Err(e) if e.raw_os_error() == Some(EAFNOSUPPORT))
}

/// Bind the endpoint for a validated `start` by `plan`. The error is the text
/// of the `bind_failed` event; with `bind_port` it names the port and the
/// system's reason.
pub async fn bind(
    key: SecretKey,
    cfg: &StartConfig,
    net: &Network,
    plan: &BindPlan,
) -> Result<Endpoint, String> {
    let relays: RelayMap = cfg.relays.iter().map(relay_config).collect();
    let dns = DnsResolver::builder()
        .with_system_defaults()
        .with_fallback_mode(FallbackMode::Never)
        .build();
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![cfg.alpn.clone()])
        .relay_mode(RelayMode::Custom(relays))
        .transport_config(transport_config(&cfg.limits))
        .ca_tls_config(net.ca_tls.clone())
        .dns_resolver(dns)
        .portmapper_config(net.portmapper.clone());
    let builder = match plan.addrs() {
        None => builder,
        Some(addrs) => addrs
            .into_iter()
            .try_fold(builder.clear_ip_transports(), |b, addr| b.bind_addr(addr))
            .map_err(|e| e.to_string())?,
    };
    builder.bind().await.map_err(|e| match cfg.bind_port {
        Some(port) => format!("UDP port {port} could not be bound: {}", error_chain(&e)),
        None => e.to_string(),
    })
}

/// An error and each of its sources, joined by `: `.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The relay map the endpoint currently has, as the daemon last named it.
pub struct RelayTable {
    current: BTreeMap<RelayUrl, u16>,
}

impl RelayTable {
    /// The table for the relays the endpoint was bound with.
    pub fn new(relays: &[Relay]) -> Self {
        RelayTable {
            current: relays
                .iter()
                .map(|r| (r.url.clone(), r.quic_port))
                .collect(),
        }
    }

    /// Make the endpoint's relay map exactly `relays`: add or update what is
    /// named, then remove what is not, so the map is never empty in between.
    pub async fn replace(&mut self, endpoint: &Endpoint, relays: &[Relay]) -> Result<(), String> {
        if endpoint.is_closed() {
            return Err("the endpoint is closed".into());
        }
        for relay in relays {
            if self.current.get(&relay.url) != Some(&relay.quic_port) {
                let config = Arc::new(relay_config(relay));
                endpoint.insert_relay(relay.url.clone(), config).await;
            }
        }
        let gone: Vec<RelayUrl> = self
            .current
            .keys()
            .filter(|url| !relays.iter().any(|r| &r.url == *url))
            .cloned()
            .collect();
        for url in &gone {
            endpoint.remove_relay(url).await;
        }
        self.current = relays
            .iter()
            .map(|r| (r.url.clone(), r.quic_port))
            .collect();
        Ok(())
    }
}

/// A connection's place; dropping it frees the place, unless the place was
/// already given to a newer connection.
struct Slot {
    slots: Arc<Slots>,
    key: u64,
    /// Fires when the place is given to a newer connection.
    room: CancellationToken,
}

impl Slot {
    /// Keep this place while its task waits for the daemon to read an event. A
    /// place is given away only while its task waits on its peer, so a daemon
    /// that stops reading fills the table and the accept loop waits on its
    /// `busy` event, instead of every new connection leaving another task
    /// stalled on the event queue.
    fn reporting(&self) -> Reporting<'_> {
        self.slots.set_reporting(self.key, true);
        Reporting(self)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.slots.table().remove(&self.key);
    }
}

/// A place kept while its task reports; dropping it lets the place go again.
struct Reporting<'a>(&'a Slot);

impl Drop for Reporting<'_> {
    fn drop(&mut self) {
        self.0.slots.set_reporting(self.0.key, false);
    }
}

/// One taken place.
struct Place {
    /// The connection's open streams.
    streams: usize,
    /// Since when it has had no stream open (its accept, or its last stream's
    /// end); `None` while one is.
    silent_since: Option<Instant>,
    /// Its task waits for the daemon to read an event (see [`Slot::reporting`]).
    reporting: bool,
    room: CancellationToken,
}

/// The `max_connections` bound: connections from accept to close, or until
/// their place is given away, handshaking ones included. When every place is
/// taken, a new connection gets the place of the connection that has gone
/// longest with no stream open, so connections that open no stream cannot keep
/// a reconnecting phone out; it is refused only when every place has a stream
/// open or its task is reporting.
struct Slots {
    max: usize,
    next: AtomicU64,
    places: Mutex<HashMap<u64, Place>>,
}

impl Slots {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Slots {
            max,
            next: AtomicU64::new(0),
            places: Mutex::new(HashMap::new()),
        })
    }

    /// A place for a connection accepted at `now`: a free one, else the place
    /// of the connection silent longest, whose `room` then fires (the `bool`
    /// says so). `None` when every place has a stream open or its task is
    /// reporting.
    fn take(self: &Arc<Self>, now: Instant) -> Option<(Slot, bool)> {
        let mut places = self.table();
        let made_room = places.len() >= self.max;
        if made_room {
            let (_, longest) = places
                .iter()
                .filter(|(_, place)| !place.reporting)
                .filter_map(|(key, place)| place.silent_since.map(|since| (since, *key)))
                .min()?;
            if let Some(place) = places.remove(&longest) {
                place.room.cancel();
            }
        }
        let key = self.next.fetch_add(1, Ordering::Relaxed);
        let room = CancellationToken::new();
        places.insert(
            key,
            Place {
                streams: 0,
                silent_since: Some(now),
                reporting: false,
                room: room.clone(),
            },
        );
        let slot = Slot {
            slots: self.clone(),
            key,
            room,
        };
        Some((slot, made_room))
    }

    fn set_reporting(&self, key: u64, reporting: bool) {
        if let Some(place) = self.table().get_mut(&key) {
            place.reporting = reporting;
        }
    }

    /// Count a stream opened on `key`'s connection, under the same lock that
    /// gives places away; `false` once its place went to a newer connection.
    fn stream_opened(&self, key: u64) -> bool {
        let mut places = self.table();
        let Some(place) = places.get_mut(&key) else {
            return false;
        };
        place.streams += 1;
        place.silent_since = None;
        true
    }

    fn stream_closed(&self, key: u64, now: Instant) {
        let mut places = self.table();
        if let Some(place) = places.get_mut(&key) {
            place.streams -= 1;
            if place.streams == 0 {
                place.silent_since = Some(now);
            }
        }
    }

    /// Half the places or more are taken: new peers must prove their address.
    fn under_pressure(&self) -> bool {
        self.table().len() * 2 >= self.max
    }

    fn table(&self) -> MutexGuard<'_, HashMap<u64, Place>> {
        // A panic ends the process with 101 (see `main`), so no thread ever
        // sees the lock poisoned.
        self.places
            .lock()
            .expect("the place table's lock is never poisoned")
    }
}

/// One open stream of a connection; dropping it counts the stream closed.
struct OpenStream {
    streams: Arc<watch::Sender<usize>>,
    slots: Arc<Slots>,
    key: u64,
}

impl OpenStream {
    /// Count a stream open on `slot`'s connection, or `None` once its place
    /// went to a newer connection.
    fn new(streams: &Arc<watch::Sender<usize>>, slot: &Slot) -> Option<Self> {
        if !slot.slots.stream_opened(slot.key) {
            return None;
        }
        streams.send_modify(|n| *n += 1);
        Some(OpenStream {
            streams: streams.clone(),
            slots: slot.slots.clone(),
            key: slot.key,
        })
    }
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.slots.stream_closed(self.key, Instant::now());
        self.streams.send_modify(|n| *n -= 1);
    }
}

/// Resolves once none of a connection's streams is open.
async fn no_stream_open(open: &mut watch::Receiver<usize>) {
    // The loop that waits holds the sender, so the channel cannot close.
    let _ = open.wait_for(|n| *n == 0).await;
}

/// The peer of every established connection, so the daemon's `close` can find
/// a peer's connections.
#[derive(Default)]
struct Peers {
    next: AtomicU64,
    open: Mutex<HashMap<u64, (EndpointId, CancellationToken)>>,
}

impl Peers {
    /// Register one connection of `peer` until the entry is dropped.
    fn enter(&self, peer: EndpointId) -> PeerEntry<'_> {
        let key = self.next.fetch_add(1, Ordering::Relaxed);
        let refused = CancellationToken::new();
        self.table().insert(key, (peer, refused.clone()));
        PeerEntry {
            peers: self,
            key,
            refused,
        }
    }

    /// Fire the `refused` token of every connection of `peer`.
    fn refuse(&self, peer: EndpointId) {
        for (id, refused) in self.table().values() {
            if *id == peer {
                refused.cancel();
            }
        }
    }

    fn table(&self) -> MutexGuard<'_, HashMap<u64, (EndpointId, CancellationToken)>> {
        // A panic ends the process with 101 (see `main`), so no thread ever
        // sees the lock poisoned.
        self.open
            .lock()
            .expect("the peer table's lock is never poisoned")
    }
}

/// One connection's entry in [`Peers`]; dropping it removes the entry.
struct PeerEntry<'a> {
    peers: &'a Peers,
    key: u64,
    /// Fires when the daemon closes this connection's peer.
    refused: CancellationToken,
}

impl Drop for PeerEntry<'_> {
    fn drop(&mut self) {
        self.peers.table().remove(&self.key);
    }
}

/// Everything the accept loop and its connection tasks share.
pub struct Acceptor {
    endpoint: Endpoint,
    slots: Arc<Slots>,
    peers: Peers,
    timings: Timings,
    socket: Arc<Path>,
    sink: EventSink,
    stop: CancellationToken,
    tasks: TaskTracker,
}

/// Why the accept loop returned.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptEnd {
    /// Shutdown asked it to stop.
    Stopped,
    /// The endpoint closed underneath it.
    EndpointClosed,
}

impl Acceptor {
    /// An acceptor for `endpoint` under `cfg`'s limits, bridging to
    /// `bridge_socket`. Connection and stream tasks are spawned on `tasks` and
    /// end when `stop` fires.
    pub fn new(
        endpoint: Endpoint,
        cfg: &StartConfig,
        bridge_socket: &Path,
        timings: Timings,
        sink: EventSink,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> Self {
        Acceptor {
            endpoint,
            slots: Slots::new(cfg.limits.max_connections),
            peers: Peers::default(),
            timings,
            socket: Arc::from(bridge_socket),
            sink,
            stop,
            tasks,
        }
    }

    /// Accept connections until shutdown or until the endpoint closes.
    pub async fn run(self: Arc<Self>) -> AcceptEnd {
        let mut made_room: u64 = 0;
        loop {
            let incoming = tokio::select! {
                _ = self.stop.cancelled() => return AcceptEnd::Stopped,
                incoming = self.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                return AcceptEnd::EndpointClosed;
            };
            // Under load a source must prove its address first (a Retry costs
            // it one round trip), so forged Initials never take a slot.
            let incoming = if self.slots.under_pressure() && !incoming.remote_addr_validated() {
                match incoming.retry() {
                    Ok(()) => continue,
                    // Refused only for an address already validated.
                    Err(err) => err.into_incoming(),
                }
            } else {
                incoming
            };
            match self.slots.take(Instant::now()) {
                Some((slot, displaced)) => {
                    let this = self.clone();
                    self.tasks
                        .spawn(async move { this.serve(incoming, slot).await });
                    if displaced {
                        made_room += 1;
                        self.report_made_room(made_room).await;
                    }
                }
                None => {
                    incoming.refuse();
                    self.refused(RefusedReason::Busy, None).await;
                }
            }
        }
    }

    /// The daemon's `close`: bridge no further stream from `peer`'s
    /// connections, and close each with code 0, reason `refused`, once its
    /// open streams have ended. A peer with no connection has nothing to close.
    pub fn close_peer(&self, peer: EndpointId) {
        self.peers.refuse(peer);
    }

    async fn refused(&self, reason: RefusedReason, endpoint_id: Option<String>) {
        self.sink
            .emit(Event::Refused {
                reason,
                endpoint_id,
            })
            .await;
    }

    /// A full helper makes room silently (a dropped handshake has no event, and
    /// a closed connection only `closed`), so the daemon's log hears of it at
    /// the 1st, 10th, 100th… time: a flood of connections that open no stream
    /// is otherwise invisible.
    async fn report_made_room(&self, count: u64) {
        if !worth_reporting(count) {
            return;
        }
        let message = format!(
            "{count} connection(s) closed `room` so far: the helper was full and each gave its place to a newer one"
        );
        self.sink.emit(Event::log(LogLevel::Warn, &message)).await;
    }

    /// Handshake one connection, then bridge its streams until it ends.
    async fn serve(&self, incoming: Incoming, slot: Slot) {
        let Some(conn) = self.handshake(incoming, &slot).await else {
            return;
        };
        let Some(kind) = kind_for_alpn(conn.alpn()) else {
            // The server config offers one ALPN, so this cannot happen; refuse
            // rather than guess a kind.
            conn.close(VarInt::from_u32(0), b"alpn");
            let _kept = slot.reporting();
            self.refused(RefusedReason::Alpn, Some(conn.remote_id().to_string()))
                .await;
            return;
        };
        self.serve_streams(&conn, kind, &slot).await;
    }

    /// Complete the handshake, or report why it was refused. Only a refused
    /// ALPN is an event; other failed handshakes (timeouts, garbage) are not
    /// the daemon's business.
    ///
    /// A handshake in flight when shutdown starts is not abandoned: QUIC can
    /// carry an application close reason only once the handshake is complete,
    /// so it is allowed to finish (shutdown bounds the wait) and the connection
    /// is then closed with reason `shutdown` like every other. A handshake
    /// whose place goes to a newer connection (`room`) is dropped at once.
    async fn handshake(&self, incoming: Incoming, slot: &Slot) -> Option<Connection> {
        // noq reads the ClientHello here, so an ALPN refusal can surface
        // already from `accept`, before there is anything to await.
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(e) => return self.handshake_failed(&e, slot).await,
        };
        let finished = tokio::select! {
            _ = slot.room.cancelled() => return None,
            finished = tokio::time::timeout(self.timings.handshake_deadline, accepting) => finished,
        };
        match finished {
            Ok(Ok(conn)) => Some(conn),
            Ok(Err(ConnectingError::ConnectionError { source, .. })) => {
                self.handshake_failed(&source, slot).await
            }
            // Dropping the unfinished handshake ends it and frees the slot.
            Ok(Err(_)) | Err(_) => None,
        }
    }

    async fn handshake_failed(&self, err: &ConnectionError, slot: &Slot) -> Option<Connection> {
        if refused_for_alpn(err) {
            let _kept = slot.reporting();
            self.refused(RefusedReason::Alpn, None).await;
        }
        None
    }

    /// Accept streams and report path changes until the connection ends or the
    /// helper shuts down; then report `closed` if a `path` was reported.
    async fn serve_streams(&self, conn: &Connection, kind: u8, slot: &Slot) {
        let mut tracker = PathTracker::new(conn.remote_id());
        self.stream_loop(conn, kind, slot, &mut tracker).await;
        if let Some(event) = tracker.closed() {
            let _kept = slot.reporting();
            self.sink.emit(event).await;
        }
    }

    /// The connection's life: bridge each accepted stream, report each path
    /// change, close it with code 0, reason `idle` once it has had no stream
    /// for `streamless_idle`, with reason `refused` once the daemon closed its
    /// peer and its open streams have ended (resetting every new one
    /// meanwhile), with reason `room` once its place went to a newer
    /// connection, and on shutdown with reason `shutdown`.
    async fn stream_loop(
        &self,
        conn: &Connection,
        kind: u8,
        slot: &Slot,
        tracker: &mut PathTracker,
    ) {
        let peer = conn.remote_id();
        let entry = self.peers.enter(peer);
        let mut paths = conn.paths_stream();
        let mut paths_open = true;
        let (streams, mut open) = watch::channel(0usize);
        let streams = Arc::new(streams);
        let mut refused = false;
        let mut idle_since = Some(Instant::now());
        let mut check = tokio::time::interval(self.timings.streamless_idle / 6);
        loop {
            tokio::select! {
                // In order, so the daemon's `close` (`refused`) wins over
                // `room` when a refused connection's last stream ends as its
                // place is given away.
                biased;
                _ = self.stop.cancelled() => {
                    conn.close(VarInt::from_u32(0), b"shutdown");
                    return;
                }
                _ = entry.refused.cancelled(), if !refused => refused = true,
                _ = no_stream_open(&mut open), if refused => {
                    conn.close(VarInt::from_u32(0), b"refused");
                    return;
                }
                // Only a connection with no stream open loses its place.
                _ = slot.room.cancelled() => {
                    conn.close(VarInt::from_u32(0), b"room");
                    return;
                }
                accepted = conn.accept_bi() => match accepted {
                    // A peer the daemon closed gets no further bridge, even
                    // for a stream that arrives as the close does.
                    Ok((send, recv)) if entry.refused.is_cancelled() => {
                        bridge::abandon(send, recv);
                        refused = true;
                    }
                    Ok((send, recv)) => match OpenStream::new(&streams, slot) {
                        Some(stream) => {
                            idle_since = None;
                            self.spawn_bridge(send, recv, peer, kind, stream);
                        }
                        // The place went to a newer connection as the stream
                        // arrived.
                        None => {
                            bridge::abandon(send, recv);
                            conn.close(VarInt::from_u32(0), b"room");
                            return;
                        }
                    },
                    Err(_) => return,
                },
                _ = check.tick() => {
                    if *open.borrow() > 0 {
                        idle_since = None;
                    } else if idle_since.get_or_insert_with(Instant::now).elapsed()
                        >= self.timings.streamless_idle
                    {
                        conn.close(VarInt::from_u32(0), b"idle");
                        return;
                    }
                }
                snapshot = paths.next(), if paths_open => match snapshot {
                    Some(list) => {
                        if let Some(event) = tracker.observe(&list) {
                            let _kept = slot.reporting();
                            self.sink.emit(event).await;
                        }
                    }
                    None => paths_open = false,
                },
            }
        }
    }

    fn spawn_bridge(
        &self,
        send: SendStream,
        recv: RecvStream,
        peer: EndpointId,
        kind: u8,
        open: OpenStream,
    ) {
        let ctx = StreamContext {
            peer,
            kind,
            socket: self.socket.clone(),
            sink: self.sink.clone(),
            stop: self.stop.child_token(),
        };
        self.tasks.spawn(async move {
            bridge::run(send, recv, ctx).await;
            drop(open);
        });
    }
}

/// The accept loop of an endpoint that only dials: every incoming connection is
/// refused before its handshake, so it costs no key exchange and holds no
/// place. Nothing is reported; the daemon has no listener to account for.
pub async fn refuse_all(endpoint: Endpoint, stop: CancellationToken) -> AcceptEnd {
    loop {
        let incoming = tokio::select! {
            _ = stop.cancelled() => return AcceptEnd::Stopped,
            incoming = endpoint.accept() => incoming,
        };
        match incoming {
            Some(incoming) => incoming.refuse(),
            None => return AcceptEnd::EndpointClosed,
        }
    }
}

/// The 1st, 10th, 100th… of a count: a log that a sustained flood cannot fill.
fn worth_reporting(count: u64) -> bool {
    count > 0 && 10u64.pow(count.ilog10()) == count
}

/// Whether a failed handshake is the TLS handshake refusing every offered ALPN.
fn refused_for_alpn(err: &ConnectionError) -> bool {
    matches!(
        err,
        ConnectionError::TransportError(t)
            if t.code == TransportErrorCode::crypto(TLS_ALERT_NO_APPLICATION_PROTOCOL)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(slots: &Arc<Slots>, now: Instant) -> Slot {
        slots.take(now).expect("a place").0
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    fn never_asked() -> bool {
        panic!("the kernel is asked about IPv6 only for a bind_port on every interface")
    }

    #[test]
    fn a_bind_port_binds_that_port_for_both_families_or_for_loopback_alone() {
        let v4 = |ip: Ipv4Addr, port: u16| SocketAddr::from((ip, port));
        let v6 = |ip: Ipv6Addr, port: u16| SocketAddr::from((ip, port));
        let iroh = BindPlan::new(BindScope::AllInterfaces, None, never_asked);
        assert_eq!(iroh, BindPlan::Iroh);
        assert_eq!(iroh.addrs(), None);
        let both = BindPlan::new(BindScope::AllInterfaces, Some(4100), || true);
        assert_eq!(
            both.addrs(),
            Some(vec![
                v4(Ipv4Addr::UNSPECIFIED, 4100),
                v6(Ipv6Addr::UNSPECIFIED, 4100)
            ])
        );
        let loopback = BindPlan::new(BindScope::Loopback, None, never_asked);
        assert_eq!(loopback.addrs(), Some(vec![v4(Ipv4Addr::LOCALHOST, 0)]));
        let fixed = BindPlan::new(BindScope::Loopback, Some(4100), never_asked);
        assert_eq!(fixed.addrs(), Some(vec![v4(Ipv4Addr::LOCALHOST, 4100)]));
        for plan in [iroh, both, loopback, fixed] {
            assert_eq!(plan.notice(), None, "{plan:?}");
        }
    }

    #[test]
    fn a_bind_port_on_a_kernel_with_no_ipv6_binds_ipv4_alone_and_says_so() {
        let plan = BindPlan::new(BindScope::AllInterfaces, Some(4100), || false);
        let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4100));
        assert_eq!(plan, BindPlan::Ipv4Only(v4));
        assert_eq!(plan.addrs(), Some(vec![v4]));
        assert_eq!(
            plan.notice().as_deref(),
            Some("no IPv6 on this host: UDP port 4100 is bound for IPv4 only")
        );
    }

    #[test]
    fn only_address_family_not_supported_means_the_kernel_has_no_ipv6() {
        use std::io::Error;
        let unsupported = Error::from_raw_os_error(EAFNOSUPPORT);
        // The constant is this target's own "address family not supported".
        assert!(
            unsupported
                .to_string()
                .starts_with("Address family not supported"),
            "{unsupported}"
        );
        assert!(!ipv6_supported(Err(unsupported)));
        assert!(ipv6_supported(Ok(())));
        // Real failures of other kinds keep IPv6 in the plan, for the real
        // bind to report: a port in use, an address the host does not have,
        // and the two permission errors (EPERM 1, EACCES 13 on both targets).
        let held = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let in_use = UdpSocket::bind(held.local_addr().unwrap()).unwrap_err();
        let not_here = UdpSocket::bind((Ipv4Addr::new(192, 0, 2, 1), 0)).unwrap_err();
        for other in [
            in_use,
            not_here,
            Error::from_raw_os_error(1),
            Error::from_raw_os_error(13),
        ] {
            assert!(other.raw_os_error().is_some(), "{other}");
            assert!(ipv6_supported(Err(other)));
        }
    }

    #[test]
    fn slots_refuse_past_the_bound_only_when_every_place_has_a_stream() {
        let (slots, t) = (Slots::new(2), Instant::now());
        let a = taken(&slots, t);
        let b = taken(&slots, at(t, 1));
        assert!(slots.stream_opened(a.key) && slots.stream_opened(b.key));
        assert!(slots.take(at(t, 2)).is_none());
        assert!(!a.room.is_cancelled() && !b.room.is_cancelled());
        drop(a);
        let c = taken(&slots, at(t, 3));
        assert!(slots.stream_opened(c.key));
        assert!(slots.take(at(t, 4)).is_none());
        drop((b, c));
        assert!(slots.table().is_empty());
    }

    #[test]
    fn a_full_table_gives_away_the_place_silent_longest() {
        let (slots, t) = (Slots::new(3), Instant::now());
        // a had a stream until 5 s; b never had one, accepted at 1 s; c has
        // one open. b has been silent longest, though a was accepted first.
        let a = taken(&slots, t);
        let b = taken(&slots, at(t, 1));
        let c = taken(&slots, at(t, 2));
        assert!(slots.stream_opened(a.key) && slots.stream_opened(c.key));
        slots.stream_closed(a.key, at(t, 5));
        let d = taken(&slots, at(t, 6));
        assert!(b.room.is_cancelled());
        assert!(!a.room.is_cancelled() && !c.room.is_cancelled());
        // b's place is d's: b opens no stream, and dropping b frees nothing.
        assert!(!slots.stream_opened(b.key));
        drop(b);
        assert_eq!(slots.table().len(), 3);
        // Next silent longest is a, then d; c keeps its stream and its place.
        let e = taken(&slots, at(t, 7));
        assert!(a.room.is_cancelled() && !d.room.is_cancelled());
        let f = taken(&slots, at(t, 8));
        assert!(d.room.is_cancelled() && !c.room.is_cancelled());
        drop((a, c, d, e, f));
        assert!(slots.table().is_empty());
    }

    #[test]
    fn a_place_is_kept_while_its_task_reports_and_a_taker_says_it_made_room() {
        let (slots, t) = (Slots::new(1), Instant::now());
        let (a, made_room) = slots.take(t).unwrap();
        assert!(!made_room);
        let kept = a.reporting();
        assert!(slots.take(at(t, 1)).is_none());
        assert!(!a.room.is_cancelled());
        drop(kept);
        let (b, made_room) = slots.take(at(t, 2)).unwrap();
        assert!(made_room && a.room.is_cancelled());
        // A displaced place's guard changes nothing of the newcomer's.
        drop(a.reporting());
        assert!(!slots.table()[&b.key].reporting);
    }

    #[test]
    fn displacement_is_reported_at_each_power_of_ten() {
        let reported: Vec<u64> = (0..=1_000).filter(|n| worth_reporting(*n)).collect();
        assert_eq!(reported, [1, 10, 100, 1_000]);
        assert!(worth_reporting(10_000_000_000_000_000_000));
        assert!(!worth_reporting(u64::MAX));
    }

    #[test]
    fn addresses_are_validated_once_half_the_slots_are_taken() {
        let (slots, t) = (Slots::new(4), Instant::now());
        let a = taken(&slots, t);
        assert!(!slots.under_pressure());
        let b = taken(&slots, t);
        assert!(slots.under_pressure());
        drop((a, b));
        assert!(!slots.under_pressure());
    }

    #[test]
    fn an_open_stream_is_counted_until_dropped() {
        let slots = Slots::new(1);
        let slot = taken(&slots, Instant::now());
        let (streams, open) = watch::channel(0usize);
        let streams = Arc::new(streams);
        let one = OpenStream::new(&streams, &slot).unwrap();
        let two = OpenStream::new(&streams, &slot).unwrap();
        assert_eq!(*open.borrow(), 2);
        assert_eq!(slots.table()[&slot.key].silent_since, None);
        drop(one);
        assert_eq!(slots.table()[&slot.key].silent_since, None);
        drop(two);
        assert_eq!(*open.borrow(), 0);
        assert!(slots.table()[&slot.key].silent_since.is_some());
    }

    #[test]
    fn a_refusal_reaches_every_connection_of_that_peer_and_no_other() {
        let peers = Peers::default();
        let a = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let b = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let (a1, a2, b1) = (peers.enter(a), peers.enter(a), peers.enter(b));
        peers.refuse(a);
        assert!(a1.refused.is_cancelled() && a2.refused.is_cancelled());
        assert!(!b1.refused.is_cancelled());
        drop((a1, a2, b1));
        assert!(peers.table().is_empty());
    }
}
