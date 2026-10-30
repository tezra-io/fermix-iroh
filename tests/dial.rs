//! Dials end to end, in-process and on loopback only: a helper that only dials
//! (or one that also listens) reaching a listening helper, or a stand-in peer,
//! with the daemon's dial socket a `UnixListener` in a temporary directory.
//! Where no relay should carry anything, every relay is `dead_relay()` and the
//! dial names the peer's UDP address directly, as the engine's end-to-end test
//! does.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use fermix_iroh::dial::MAX_DIALS;
use fermix_iroh::protocol::{DialFailure, ErrorCode, Event, PathKind};
use fermix_iroh::session::Exit;
use iroh::endpoint::{
    Connection, ConnectionError, PortmapperConfig, QuicTransportConfig, VarInt, presets,
};
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey};
use support::{
    ALPN, Helper, TestRelay, accept_bridge, bounded, dead_relay, dial_op, expected_preamble,
    test_network, within,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// The daemon's socket for one dial, in the dialing helper's temp dir.
fn dial_socket(helper: &Helper, name: &str) -> PathBuf {
    helper.dir.path().join(format!("{name}.sock"))
}

async fn accept_dial(listener: &UnixListener) -> UnixStream {
    let (unix, _) = within("the dial's connection", listener.accept())
        .await
        .expect("the dial socket accepts");
    unix
}

async fn read_exactly(unix: &mut UnixStream, want: usize) -> Vec<u8> {
    let mut out = vec![0u8; want];
    within("socket bytes", unix.read_exact(&mut out))
        .await
        .expect("the socket delivers the bytes");
    out
}

/// The answer to `dial_id`, skipping every other event.
async fn dial_answer(helper: &mut Helper, dial_id: &str) -> Event {
    helper
        .expect("the dial's answer", |e| match e {
            Event::Dialed { dial_id: id, .. } | Event::DialFailed { dial_id: id, .. } => {
                id == dial_id
            }
            _ => false,
        })
        .await
}

async fn dial_closed(helper: &mut Helper, dial_id: &str) {
    helper
        .expect(
            "dial_closed",
            |e| matches!(e, Event::DialClosed { dial_id: id } if id == dial_id),
        )
        .await;
}

/// A peer that accepts every connection on the mobile ALPN and hands it over
/// (the receiver keeps it open), but gives it no stream credit: a stream to it
/// never opens.
async fn creditless_peer() -> (Endpoint, SocketAddr, mpsc::UnboundedReceiver<Connection>) {
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .build();
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .transport_config(transport)
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("a loopback bind address")
        .bind()
        .await
        .expect("the peer binds");
    let addr = endpoint.bound_sockets()[0];
    let accepting = endpoint.clone();
    let (held, connections) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            let Ok(connecting) = incoming.accept() else {
                continue;
            };
            if let Ok(conn) = connecting.await {
                // The test may have stopped listening; the connection then
                // closes, which is all it needs.
                let _ = held.send(conn);
            }
        }
    });
    (endpoint, addr, connections)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_through_a_relay_is_copied_both_ways_and_ends_with_dial_closed() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut listener = Helper::spawn().await;
        let bridge = listener.listen_bridge();
        listener.start(&[&relay], 8, &relay).await;

        let mut dialer = Helper::spawn().await;
        let (dialer_id, _) = dialer.start_on(&[relay.spec()], false).await;
        dialer.wait_relay_connected(&relay).await;
        let socket = dial_socket(&dialer, "d1");
        let dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("d1", listener.endpoint_id(), &[relay.spec()], &socket, &[]);
        dialer.send(&op).await;

        let Event::Dialed {
            kind, relay: via, ..
        } = dial_answer(&mut dialer, "d1").await
        else {
            panic!("the dial is answered dialed");
        };
        match kind {
            PathKind::Relay => assert_eq!(via, Some(relay.url.to_string())),
            PathKind::Direct => assert_eq!(via, None),
        }
        // No preamble on the dial's socket: the stream's bytes and nothing else.
        let mut unix = accept_dial(&dial_listener).await;
        unix.write_all(b"FXM1 prelude").await.unwrap();

        // On the listener's side a dialed stream is an accepted one.
        let (mut far, preamble) = accept_bridge(&bridge).await;
        assert_eq!(preamble, expected_preamble(dialer_id));
        assert_eq!(read_exactly(&mut far, 12).await, b"FXM1 prelude");
        far.write_all(b"responder reply").await.unwrap();
        assert_eq!(read_exactly(&mut unix, 15).await, b"responder reply");

        // The dialing daemon ends its side; the far daemon reads its last
        // bytes, then end of file, and ends its own.
        unix.write_all(b"bye").await.unwrap();
        drop(unix);
        let mut last = Vec::new();
        within("the far bridge's EOF", far.read_to_end(&mut last))
            .await
            .unwrap();
        assert_eq!(last, b"bye");
        drop(far);
        dial_closed(&mut dialer, "d1").await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_reaches_a_peer_directly_with_no_relay_and_the_far_side_can_end_it() {
    bounded(async {
        let mut listener = Helper::spawn().await;
        let bridge = listener.listen_bridge();
        let (listener_id, listener_addr) = listener.start_on(&[dead_relay()], true).await;

        // A helper that listens can dial too.
        let mut dialer = Helper::spawn().await;
        let _dialer_bridge = dialer.listen_bridge();
        let (dialer_id, _) = dialer.start_on(&[dead_relay()], true).await;
        let socket = dial_socket(&dialer, "direct");
        let dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op(
            "direct",
            listener_id,
            &[dead_relay()],
            &socket,
            &[listener_addr],
        );
        dialer.send(&op).await;

        let answer = dial_answer(&mut dialer, "direct").await;
        assert_eq!(
            answer,
            Event::Dialed {
                dial_id: "direct".into(),
                kind: PathKind::Direct,
                relay: None
            }
        );
        let mut unix = accept_dial(&dial_listener).await;
        unix.write_all(b"hello").await.unwrap();
        let (mut far, preamble) = accept_bridge(&bridge).await;
        assert_eq!(preamble, expected_preamble(dialer_id));
        assert_eq!(read_exactly(&mut far, 5).await, b"hello");

        // The far daemon closes first: its last bytes, then end of file here.
        far.write_all(b"closing").await.unwrap();
        drop(far);
        let mut last = Vec::new();
        within("the dial socket's EOF", unix.read_to_end(&mut last))
            .await
            .unwrap();
        assert_eq!(last, b"closing");
        drop(unix);
        dial_closed(&mut dialer, "direct").await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_only_dials_refuses_every_connection() {
    bounded(async {
        let mut target = Helper::spawn().await;
        let (target_id, target_addr) = target.start_on(&[dead_relay()], false).await;

        let mut dialer = Helper::spawn().await;
        dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "r");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("r", target_id, &[dead_relay()], &socket, &[target_addr]);
        dialer.send(&op).await;

        let answer = dial_answer(&mut dialer, "r").await;
        assert_eq!(
            answer,
            Event::DialFailed {
                dial_id: "r".into(),
                reason: DialFailure::Refused
            }
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_dial_socket_fails_and_frees_the_dial_id() {
    bounded(async {
        let mut listener = Helper::spawn().await;
        let bridge = listener.listen_bridge();
        let (listener_id, listener_addr) = listener.start_on(&[dead_relay()], true).await;

        let mut dialer = Helper::spawn().await;
        dialer.start_on(&[dead_relay()], false).await;
        let nowhere = dial_socket(&dialer, "nobody-listens");
        let op = dial_op("again", listener_id, &[dead_relay()], &nowhere, &[listener_addr]);
        dialer.send(&op).await;
        let log = dialer
            .expect("the unreachable socket's log", |e| matches!(e, Event::Log { .. }))
            .await;
        assert!(
            matches!(&log, Event::Log { message, .. } if message.starts_with("dial again failed: dial socket unreachable")),
            "{log:?}"
        );
        assert_eq!(
            dial_answer(&mut dialer, "again").await,
            Event::DialFailed {
                dial_id: "again".into(),
                reason: DialFailure::BridgeUnreachable
            }
        );

        // The failed dial's id is free again at once, and nothing reached the
        // listener's bridge for it.
        let socket = dial_socket(&dialer, "there");
        let dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("again", listener_id, &[dead_relay()], &socket, &[listener_addr]);
        dialer.send(&op).await;
        assert!(matches!(
            dial_answer(&mut dialer, "again").await,
            Event::Dialed { .. }
        ));
        let mut unix = accept_dial(&dial_listener).await;
        unix.write_all(b"first").await.unwrap();
        let (mut far, _) = accept_bridge(&bridge).await;
        assert_eq!(read_exactly(&mut far, 5).await, b"first");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_whose_stream_never_opens_fails_timeout_at_its_deadline() {
    bounded(async {
        let (peer, peer_addr, _held) = creditless_peer().await;
        let peer_id = peer.id();
        let mut net = test_network();
        net.timings.dial_deadline = Duration::from_secs(2);
        let mut dialer = Helper::spawn_on(net).await;
        dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "slow");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("slow", peer_id, &[dead_relay()], &socket, &[peer_addr]);
        dialer.send(&op).await;

        assert_eq!(
            dial_answer(&mut dialer, "slow").await,
            Event::DialFailed {
                dial_id: "slow".into(),
                reason: DialFailure::Timeout
            }
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_nobody_answers_for_fails_timeout() {
    bounded(async {
        let mut net = test_network();
        net.timings.dial_deadline = Duration::from_secs(2);
        let mut dialer = Helper::spawn_on(net).await;
        dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "gone");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        let nobody: EndpointId = SecretKey::from_bytes(&[9; 32]).public();
        // A UDP port nothing answers on: bind one, learn it, close it.
        let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let op = dial_op("gone", nobody, &[dead_relay()], &socket, &[closed]);
        dialer.send(&op).await;

        assert_eq!(
            dial_answer(&mut dialer, "gone").await,
            Event::DialFailed {
                dial_id: "gone".into(),
                reason: DialFailure::Timeout
            }
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_iroh_cannot_start_is_unreachable() {
    bounded(async {
        let mut dialer = Helper::spawn().await;
        // An endpoint cannot connect to itself: iroh refuses before any packet.
        let (own_id, own_addr) = dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "self");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("self", own_id, &[dead_relay()], &socket, &[own_addr]);
        dialer.send(&op).await;

        assert_eq!(
            dial_answer(&mut dialer, "self").await,
            Event::DialFailed {
                dial_id: "self".into(),
                reason: DialFailure::Unreachable
            }
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_past_the_bound_is_busy_and_a_dial_id_in_flight_is_a_bad_request() {
    bounded(async {
        let (peer, peer_addr, _held) = creditless_peer().await;
        let mut dialer = Helper::spawn().await;
        dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "many");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        // Every one of these waits for stream credit the peer never gives.
        for n in 0..MAX_DIALS {
            let op = dial_op(&format!("d{n}"), peer.id(), &[dead_relay()], &socket, &[peer_addr]);
            dialer.send(&op).await;
        }
        let op = dial_op("one-more", peer.id(), &[dead_relay()], &socket, &[peer_addr]);
        dialer.send(&op).await;
        assert_eq!(
            dial_answer(&mut dialer, "one-more").await,
            Event::DialFailed {
                dial_id: "one-more".into(),
                reason: DialFailure::Busy
            }
        );

        let op = dial_op("d0", peer.id(), &[dead_relay()], &socket, &[peer_addr]);
        dialer.send(&op).await;
        let error = dialer
            .expect("the error", |e| matches!(e, Event::Error { .. }))
            .await;
        assert!(
            matches!(&error, Event::Error { code: ErrorCode::BadRequest, message } if message.contains("d0 is already in flight")),
            "{error:?}"
        );
        assert_eq!(dialer.exit().await.0, Exit::Fatal);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_ends_dials_in_flight_without_an_event_within_5s() {
    bounded(async {
        let (peer, peer_addr, mut connections) = creditless_peer().await;
        let mut dialer = Helper::spawn().await;
        dialer.start_on(&[dead_relay()], false).await;
        let socket = dial_socket(&dialer, "cut");
        let _dial_listener = UnixListener::bind(&socket).unwrap();
        let op = dial_op("cut", peer.id(), &[dead_relay()], &socket, &[peer_addr]);
        dialer.send(&op).await;
        // The dial is connected and waits for stream credit.
        let conn = within("the dial's connection", connections.recv())
            .await
            .expect("the peer accepts the dial's connection");
        dialer.close_stdin();
        let events = dialer.drain_events().await;
        assert!(
            !events.iter().any(|e| matches!(
                e,
                Event::Dialed { .. } | Event::DialFailed { .. } | Event::DialClosed { .. }
            )),
            "{events:?}"
        );
        let (exit, took) = dialer.exit().await;
        assert_eq!(exit, Exit::Shutdown);
        assert!(took < Duration::from_secs(5), "{took:?}");
        let closed = within("the connection's close", conn.closed()).await;
        assert!(
            matches!(&closed, ConnectionError::ApplicationClosed(close) if close.reason.as_ref() == b"shutdown"),
            "{closed:?}"
        );
    })
    .await;
}
