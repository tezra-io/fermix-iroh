//! The helper's one iroh endpoint.
//!
//! Built from iroh's `Minimal` preset (a crypto provider and nothing else):
//! the relay map is exactly the daemon's list, there is no address lookup
//! service, no proxy is read from the environment, and DNS goes only to the
//! system's configured nameservers (iroh's public fallback resolvers are turned
//! off). The daemon's limits become QUIC transport parameters, and the accept
//! loop refuses a connection over `max_connections` before its handshake.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::StreamExt;
use iroh::dns::{DnsResolver, FallbackMode};
use iroh::endpoint::{
    ConnectingError, Connection, ConnectionError, Incoming, PortmapperConfig, QuicTransportConfig,
    RecvStream, SendStream, TransportErrorCode, VarInt, presets,
};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::RelayQuicConfig;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::bridge::{self, StreamContext};
use crate::ndjson::EventSink;
use crate::protocol::{Event, RefusedReason, Relay, StartConfig, ValidLimits, kind_for_alpn};
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

/// Where the endpoint binds its UDP sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    /// iroh's default: every interface, IPv4 and IPv6. The released helper.
    AllInterfaces,
    /// 127.0.0.1 only. Hermetic tests.
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
}

impl Network {
    /// The released helper: Mozilla's roots compiled in, every interface, and a
    /// port mapping requested from the local router.
    pub fn production() -> Self {
        Network {
            ca_tls: CaTlsConfig::embedded(),
            scope: BindScope::AllInterfaces,
            portmapper: PortmapperConfig::default(),
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

/// Bind the endpoint for a validated `start`. The error is the text of the
/// `bind_failed` event.
pub async fn bind(key: SecretKey, cfg: &StartConfig, net: &Network) -> Result<Endpoint, String> {
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
    let builder = match net.scope {
        BindScope::AllInterfaces => builder,
        BindScope::Loopback => builder
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| e.to_string())?,
    };
    builder.bind().await.map_err(|e| e.to_string())
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

/// A taken connection slot; dropping it frees the slot.
struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The `max_connections` bound: connections from accept to close, handshaking
/// ones included.
struct Slots {
    active: AtomicUsize,
    max: usize,
}

impl Slots {
    fn try_take(self: &Arc<Self>) -> Option<Slot> {
        let taken = self
            .active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max).then_some(n + 1)
            });
        taken.ok().map(|_| Slot(self.clone()))
    }
}

/// Everything the accept loop and its connection tasks share.
pub struct Acceptor {
    endpoint: Endpoint,
    slots: Arc<Slots>,
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
    /// An acceptor for `endpoint` under `cfg`'s limits. Connection and stream
    /// tasks are spawned on `tasks` and end when `stop` fires.
    pub fn new(
        endpoint: Endpoint,
        cfg: &StartConfig,
        sink: EventSink,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> Self {
        Acceptor {
            endpoint,
            slots: Arc::new(Slots {
                active: AtomicUsize::new(0),
                max: cfg.limits.max_connections,
            }),
            socket: Arc::from(cfg.bridge_socket.as_path()),
            sink,
            stop,
            tasks,
        }
    }

    /// Accept connections until shutdown or until the endpoint closes.
    pub async fn run(self: Arc<Self>) -> AcceptEnd {
        loop {
            let incoming = tokio::select! {
                _ = self.stop.cancelled() => return AcceptEnd::Stopped,
                incoming = self.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                return AcceptEnd::EndpointClosed;
            };
            match self.slots.try_take() {
                Some(slot) => {
                    let this = self.clone();
                    self.tasks
                        .spawn(async move { this.serve(incoming, slot).await });
                }
                None => {
                    incoming.refuse();
                    self.refused(RefusedReason::Busy, None).await;
                }
            }
        }
    }

    async fn refused(&self, reason: RefusedReason, endpoint_id: Option<String>) {
        self.sink
            .emit(Event::Refused {
                reason,
                endpoint_id,
            })
            .await;
    }

    /// Handshake one connection, then bridge its streams until it ends.
    async fn serve(&self, incoming: Incoming, _slot: Slot) {
        let Some(conn) = self.handshake(incoming).await else {
            return;
        };
        let Some(kind) = kind_for_alpn(conn.alpn()) else {
            // The server config offers one ALPN, so this cannot happen; refuse
            // rather than guess a kind.
            conn.close(VarInt::from_u32(0), b"alpn");
            self.refused(RefusedReason::Alpn, Some(conn.remote_id().to_string()))
                .await;
            return;
        };
        self.serve_streams(&conn, kind).await;
    }

    /// Complete the handshake, or report why it was refused. Only a refused
    /// ALPN is an event; other failed handshakes (timeouts, garbage) are not
    /// the daemon's business.
    ///
    /// A handshake in flight when shutdown starts is not abandoned: QUIC can
    /// carry an application close reason only once the handshake is complete,
    /// so it is allowed to finish (shutdown bounds the wait) and the connection
    /// is then closed with reason `shutdown` like every other.
    async fn handshake(&self, incoming: Incoming) -> Option<Connection> {
        // noq reads the ClientHello here, so an ALPN refusal can surface
        // already from `accept`, before there is anything to await.
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(e) => return self.handshake_failed(&e).await,
        };
        match accepting.await {
            Ok(conn) => Some(conn),
            Err(ConnectingError::ConnectionError { source, .. }) => {
                self.handshake_failed(&source).await
            }
            Err(_) => None,
        }
    }

    async fn handshake_failed(&self, err: &ConnectionError) -> Option<Connection> {
        if refused_for_alpn(err) {
            self.refused(RefusedReason::Alpn, None).await;
        }
        None
    }

    /// Accept streams and report path changes until the connection ends or the
    /// helper shuts down; then report `closed` if a `path` was reported.
    async fn serve_streams(&self, conn: &Connection, kind: u8) {
        let mut tracker = PathTracker::new(conn.remote_id());
        self.stream_loop(conn, kind, &mut tracker).await;
        if let Some(event) = tracker.closed() {
            self.sink.emit(event).await;
        }
    }

    /// The connection's life: bridge each accepted stream, report each path
    /// change, and on shutdown close it with code 0, reason `shutdown`.
    async fn stream_loop(&self, conn: &Connection, kind: u8, tracker: &mut PathTracker) {
        let peer = conn.remote_id();
        let mut paths = conn.paths_stream();
        let mut paths_open = true;
        loop {
            tokio::select! {
                _ = self.stop.cancelled() => {
                    conn.close(VarInt::from_u32(0), b"shutdown");
                    return;
                }
                accepted = conn.accept_bi() => match accepted {
                    Ok((send, recv)) => self.spawn_bridge(send, recv, peer, kind),
                    Err(_) => return,
                },
                snapshot = paths.next(), if paths_open => match snapshot {
                    Some(list) => {
                        if let Some(event) = tracker.observe(&list) {
                            self.sink.emit(event).await;
                        }
                    }
                    None => paths_open = false,
                },
            }
        }
    }

    fn spawn_bridge(&self, send: SendStream, recv: RecvStream, peer: EndpointId, kind: u8) {
        let ctx = StreamContext {
            peer,
            kind,
            socket: self.socket.clone(),
            sink: self.sink.clone(),
            stop: self.stop.child_token(),
        };
        self.tasks.spawn(bridge::run(send, recv, ctx));
    }
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

    #[test]
    fn slots_refuse_past_the_bound_and_free_on_drop() {
        let slots = Arc::new(Slots {
            active: AtomicUsize::new(0),
            max: 2,
        });
        let a = slots.try_take().unwrap();
        let b = slots.try_take().unwrap();
        assert!(slots.try_take().is_none());
        drop(a);
        let c = slots.try_take().unwrap();
        assert!(slots.try_take().is_none());
        drop((b, c));
        assert_eq!(slots.active.load(Ordering::SeqCst), 0);
    }
}
