//! The helper end to end, in-process and on loopback only: a local relay, the
//! helper session the binary runs, a fake bridge socket, and phone endpoints
//! that dial the helper through the relay.

mod support;

use std::time::{Duration, Instant};

use fermix_iroh::bridge::ACK_DEADLINE;
use fermix_iroh::protocol::{ErrorCode, Event, PathKind, RefusedReason};
use fermix_iroh::session::Exit;
use iroh::endpoint::{Connection, ConnectionError, ReadError, ReadToEndError, VarInt};
use iroh::{Endpoint, SecretKey};
use serde_json::json;
use support::{
    ALPN, Helper, TestRelay, accept_bridge, bounded, dial, expected_preamble, phone,
    phone_giving_no_credit, within,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a stream may take to show its peer's reset or stop.
const SETTLE: Duration = Duration::from_secs(10);

async fn read_some(unix: &mut tokio::net::UnixStream, want: usize) -> Vec<u8> {
    let mut out = vec![0u8; want];
    within("bridge bytes", unix.read_exact(&mut out))
        .await
        .expect("the bridge delivers the bytes");
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_answers_ready_with_the_keys_endpoint_id_then_logs_and_reports_the_relay() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        helper.send(&helper.start_op(&[&relay], 8)).await;
        assert_eq!(
            helper.next_event().await,
            Event::Ready {
                endpoint_id: helper.endpoint_id().to_string()
            }
        );
        let log = helper.next_event().await;
        assert!(
            matches!(&log, Event::Log { message, .. } if message.starts_with("bound UDP sockets: 127.0.0.1:")),
            "{log:?}"
        );
        helper.wait_relay_connected(&relay).await;
        helper.close_stdin();
        assert_eq!(helper.exit().await.0, Exit::Shutdown);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_is_bridged_with_the_preamble_and_copied_both_ways() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"noise hello").await.unwrap();

        let (mut unix, preamble) = accept_bridge(&bridge).await;
        assert_eq!(preamble, expected_preamble(phone.id()));
        assert_eq!(read_some(&mut unix, 11).await, b"noise hello");

        unix.write_all(b"noise reply").await.unwrap();
        let mut reply = [0u8; 11];
        within("the reply", recv.read_exact(&mut reply))
            .await
            .unwrap();
        assert_eq!(&reply, b"noise reply");

        let path = helper
            .expect("a path for the phone", |e| matches!(e, Event::Path { .. }))
            .await;
        let Event::Path {
            endpoint_id,
            kind,
            relay: via,
        } = path
        else {
            unreachable!()
        };
        assert_eq!(endpoint_id, phone.id().to_string());
        match kind {
            PathKind::Relay => assert_eq!(via, Some(relay.url.to_string())),
            PathKind::Direct => assert_eq!(via, None),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_finish_is_bridge_eof_and_bridge_close_is_stream_finish() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"last words").await.unwrap();
        send.finish().unwrap();

        let (mut unix, _) = accept_bridge(&bridge).await;
        let mut upstream = Vec::new();
        within("bridge EOF", unix.read_to_end(&mut upstream))
            .await
            .unwrap();
        assert_eq!(upstream, b"last words");

        // The daemon still answers after the phone's EOF, then closes.
        unix.write_all(b"goodbye").await.unwrap();
        drop(unix);
        let downstream = within("the stream's finish", recv.read_to_end(1024))
            .await
            .expect("the stream is finished, not reset");
        assert_eq!(downstream, b"goodbye");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_closing_first_finishes_the_stream_and_stops_reading_it() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hi").await.unwrap();

        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 2).await;
        unix.write_all(b"session over").await.unwrap();
        drop(unix);

        let downstream = within("the stream's finish", recv.read_to_end(1024))
            .await
            .expect("finished, not reset");
        assert_eq!(downstream, b"session over");
        let stopped = within("the helper to stop reading", send.stopped())
            .await
            .expect("the stream outlives the stop");
        assert_eq!(stopped, Some(VarInt::from_u32(0)));
        // Ending a stream never closes the connection.
        assert!(conn.close_reason().is_none());
    })
    .await;
}

// A peer can give a stream no flow-control credit. While the daemon's session
// lives that is backpressure, and the session is the daemon's to end. Once the
// daemon closes the bridge, the peer has ACK_DEADLINE to take its last bytes
// and acknowledge them; then the helper resets the stream with code 0, so the
// peer cannot hold it open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_given_no_credit_is_reset_once_the_daemon_has_closed_it() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone_giving_no_credit(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hi").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 2).await;

        // The daemon answers and the peer takes none of it. Past the deadline
        // the helper has still neither reset the stream nor stopped reading it.
        unix.write_all(b"handshake reply").await.unwrap();
        let held = tokio::time::timeout(ACK_DEADLINE + Duration::from_secs(2), async {
            tokio::select! {
                reset = recv.received_reset() => format!("reset: {reset:?}"),
                stopped = send.stopped() => format!("stopped: {stopped:?}"),
            }
        })
        .await;
        assert!(held.is_err(), "a live session's stream ended: {held:?}");

        // The daemon gives up: its close frame, then the bridge closes.
        unix.write_all(b"close frame").await.unwrap();
        let closed_at = Instant::now();
        drop(unix);
        let stopped = within("the helper to stop reading", send.stopped())
            .await
            .expect("the stream outlives the stop");
        assert_eq!(stopped, Some(VarInt::from_u32(0)));
        let reset = within("the stream's reset", recv.received_reset())
            .await
            .expect("the stream is reset, not lost");
        assert_eq!(reset, Some(VarInt::from_u32(0)));
        let took = closed_at.elapsed();
        assert!(took >= ACK_DEADLINE, "reset {took:?} after the close");
        // Ending a stream never closes the connection.
        assert!(conn.close_reason().is_none());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_stream_on_the_same_connection_gets_its_own_bridge_connection() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send1, mut recv1) = conn.open_bi().await.unwrap();
        send1.write_all(b"session-1").await.unwrap();
        let (mut unix1, pre1) = accept_bridge(&bridge).await;
        assert_eq!(read_some(&mut unix1, 9).await, b"session-1");

        // A renewal opens the next stream before the last one has closed.
        let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
        send2.write_all(b"session-2").await.unwrap();
        let (mut unix2, pre2) = accept_bridge(&bridge).await;
        assert_eq!(read_some(&mut unix2, 9).await, b"session-2");
        assert_eq!(pre1, expected_preamble(phone.id()));
        assert_eq!(pre2, pre1);

        unix2.write_all(b"to-2").await.unwrap();
        unix1.write_all(b"to-1").await.unwrap();
        let mut got = [0u8; 4];
        within("stream 2", recv2.read_exact(&mut got))
            .await
            .unwrap();
        assert_eq!(&got, b"to-2");
        within("stream 1", recv1.read_exact(&mut got))
            .await
            .unwrap();
        assert_eq!(&got, b"to-1");

        // The old session ends; the new one carries on over the same connection.
        drop(unix1);
        within("stream 1's finish", recv1.read_to_end(64))
            .await
            .unwrap();
        send2.write_all(b"still here").await.unwrap();
        assert_eq!(read_some(&mut unix2, 10).await, b"still here");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_reset_closes_the_bridge_connection() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 1).await;

        send.reset(VarInt::from_u32(7)).unwrap();
        let mut rest = Vec::new();
        // EOF or a reset: either way the bridge connection is closed.
        let closed = tokio::time::timeout(SETTLE, unix.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "the bridge connection was not closed");
        assert!(rest.is_empty());
        let err = within("the send side's reset", recv.read_to_end(64))
            .await
            .unwrap_err();
        assert!(
            matches!(err, iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from_u32(0)),
            "{err:?}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_bridge_resets_the_stream_with_code_2_and_is_reported() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        // No listener on the bridge socket.
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"anyone there?").await.unwrap();
        let err = within("the reset", recv.read_to_end(64)).await.unwrap_err();
        assert!(
            matches!(err, iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from_u32(2)),
            "{err:?}"
        );
        let refused = helper
            .expect("refused bridge_unreachable", |e| {
                matches!(e, Event::Refused { reason: RefusedReason::BridgeUnreachable, .. })
            })
            .await;
        assert_eq!(
            refused,
            Event::Refused {
                reason: RefusedReason::BridgeUnreachable,
                endpoint_id: Some(phone.id().to_string()),
            }
        );
        // The connection survives: a later stream is tried afresh.
        assert!(conn.close_reason().is_none());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_foreign_alpn_is_refused_in_the_handshake_and_reported() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let _bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let dialed = dial(&phone, helper.endpoint_id(), &relay, b"fermix/other/1").await;
        assert!(dialed.is_err(), "a foreign ALPN must not connect");
        let refused = helper
            .expect("refused alpn", |e| matches!(e, Event::Refused { .. }))
            .await;
        assert_eq!(
            refused,
            Event::Refused {
                reason: RefusedReason::Alpn,
                endpoint_id: None,
            }
        );
    })
    .await;
}

// iroh's keep-alive would hold a connection that opens no stream, and its
// slot, for as long as the peer answers: the helper closes it, `idle`, once it
// has had no stream for `streamless_idle`, and the slot is free again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_with_no_stream_is_closed_idle_and_frees_its_slot() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut net = support::test_network();
        net.timings.streamless_idle = Duration::from_secs(2);
        let mut helper = Helper::spawn_on(net).await;
        let _bridge = helper.listen_bridge();
        helper.start(&[&relay], 1, &relay).await;

        let first = phone(&relay).await;
        let idle = dial(&first, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let reason = within("the idle close", idle.closed()).await;
        match reason {
            ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, VarInt::from_u32(0));
                assert_eq!(&close.reason[..], b"idle");
            }
            other => panic!("expected an application close, got {other:?}"),
        }

        let second = phone(&relay).await;
        dial(&second, helper.endpoint_id(), &relay, ALPN)
            .await
            .expect("the slot the idle connection held is free");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_over_the_limit_is_refused_before_its_handshake() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 1, &relay).await;

        let first = phone(&relay).await;
        let held = dial(&first, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = held.open_bi().await.unwrap();
        send.write_all(b"1").await.unwrap();
        accept_bridge(&bridge).await;

        let second = phone(&relay).await;
        let refused = dial(&second, helper.endpoint_id(), &relay, ALPN).await;
        assert!(refused.is_err(), "the second connection must be refused");
        let event = helper
            .expect("refused busy", |e| matches!(e, Event::Refused { .. }))
            .await;
        assert_eq!(
            event,
            Event::Refused {
                reason: RefusedReason::Busy,
                endpoint_id: None,
            }
        );

        // Closing the first frees its slot.
        held.close(VarInt::from_u32(0), b"done");
        helper
            .expect("closed for the first phone", |e| {
                matches!(e, Event::Closed { endpoint_id } if *endpoint_id == first.id().to_string())
            })
            .await;
        let third = phone(&relay).await;
        dial(&third, helper.endpoint_id(), &relay, ALPN)
            .await
            .expect("a slot is free again");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_follows_the_last_path_once_when_the_peer_closes() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let _bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN).await.unwrap();
        let id = phone.id().to_string();
        helper
            .expect("a path", |e| matches!(e, Event::Path { endpoint_id, .. } if *endpoint_id == id))
            .await;
        conn.close(VarInt::from_u32(0), b"bye");
        helper
            .expect("closed", |e| matches!(e, Event::Closed { endpoint_id } if *endpoint_id == id))
            .await;
        helper.close_stdin();
        let after = helper.drain_events().await;
        assert!(
            !after.iter().any(|e| matches!(e, Event::Path { endpoint_id, .. } | Event::Closed { endpoint_id } if *endpoint_id == id)),
            "nothing about the peer after its closed: {after:?}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_relays_swaps_the_relay_map() {
    bounded(async {
        let old = TestRelay::start().await;
        let new = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&old], 8, &old).await;

        helper
            .send(&json!({ "op": "set_relays", "relays": [new.spec()] }))
            .await;
        helper.wait_relay_connected(&new).await;

        // A phone that knows only the new relay reaches the helper through it.
        let phone = phone(&new).await;
        let conn = dial(&phone, helper.endpoint_id(), &new, ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(b"via new").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        assert_eq!(read_some(&mut unix, 7).await, b"via new");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_closes_with_reason_shutdown_reports_closed_and_exits_within_5s() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(b"busy").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 4).await;
        let id = phone.id().to_string();
        helper
            .expect(
                "a path",
                |e| matches!(e, Event::Path { endpoint_id, .. } if *endpoint_id == id),
            )
            .await;

        helper.send(&json!({ "op": "shutdown" })).await;
        let (exit, took) = helper.exit().await;
        assert_eq!(exit, Exit::Shutdown);
        assert!(took < Duration::from_secs(5), "shutdown took {took:?}");

        let reason = within("the phone to see the close", conn.closed()).await;
        match reason {
            ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, VarInt::from_u32(0));
                assert_eq!(&close.reason[..], b"shutdown");
            }
            other => panic!("expected an application close, got {other:?}"),
        }
        let mut rest = Vec::new();
        within(
            "the bridge connection to close",
            unix.read_to_end(&mut rest),
        )
        .await
        .expect("the bridge connection closed");

        let events = helper.drain_events().await;
        assert!(
            events.contains(&Event::Closed { endpoint_id: id }),
            "closed is reported before exit: {events:?}"
        );
        // No task outlived the drain: every connection and bridge task ended
        // when shutdown cancelled it, and iroh's drain finished in time.
        let leaks: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, Event::Log { message, .. } if message.starts_with("shutdown:")))
            .collect();
        assert!(leaks.is_empty(), "{leaks:?}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_of_stdin_after_ready_is_a_shutdown() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        helper.start(&[&relay], 8, &relay).await;
        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN).await.unwrap();

        helper.close_stdin();
        let (exit, took) = helper.exit().await;
        assert_eq!(exit, Exit::Shutdown);
        assert!(took < Duration::from_secs(5), "shutdown took {took:?}");
        let reason = within("the phone to see the close", conn.closed()).await;
        assert!(
            matches!(&reason, ConnectionError::ApplicationClosed(c) if &c.reason[..] == b"shutdown"),
            "{reason:?}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_start_and_a_bad_set_relays_are_bad_requests() {
    bounded(async {
        let relay = TestRelay::start().await;

        let mut helper = Helper::spawn().await;
        helper.start(&[&relay], 8, &relay).await;
        helper.send(&helper.start_op(&[&relay], 8)).await;
        let error = helper
            .expect("an error", |e| matches!(e, Event::Error { .. }))
            .await;
        assert!(matches!(
            error,
            Event::Error {
                code: ErrorCode::BadRequest,
                ..
            }
        ));
        assert_eq!(helper.exit().await.0, Exit::Fatal);

        let mut helper = Helper::spawn().await;
        helper.start(&[&relay], 8, &relay).await;
        helper
            .send(&json!({ "op": "set_relays", "relays": [] }))
            .await;
        let error = helper
            .expect("an error", |e| matches!(e, Event::Error { .. }))
            .await;
        assert!(matches!(
            error,
            Event::Error {
                code: ErrorCode::BadRequest,
                ..
            }
        ));
        let (exit, took) = helper.exit().await;
        assert_eq!(exit, Exit::Fatal);
        assert!(took < Duration::from_secs(2), "exit 1 took {took:?}");
    })
    .await;
}

/// The close the daemon's `close` op gives a connection.
fn assert_refused(reason: ConnectionError) {
    match reason {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, VarInt::from_u32(0));
            assert_eq!(&close.reason[..], b"refused");
        }
        other => panic!("expected the refused close, got {other:?}"),
    }
}

/// The helper reset a stream it would not bridge, with code 0.
fn assert_reset(read: Result<Vec<u8>, ReadToEndError>) {
    match read {
        Err(ReadToEndError::Read(ReadError::Reset(code))) => {
            assert_eq!(code, VarInt::from_u32(0));
        }
        other => panic!("expected a reset with code 0, got {other:?}"),
    }
}

/// A streamless connection from a peer of its own, for [`await_closes`].
struct Barrier {
    _phone: Endpoint,
    conn: Connection,
    id: String,
}

/// Dial a [`Barrier`] and wait for its first `path`, which shows the helper
/// knows its connection.
async fn dial_barrier(helper: &mut Helper, relay: &TestRelay) -> Barrier {
    let phone = phone(relay).await;
    let conn = dial(&phone, helper.endpoint_id(), relay, ALPN)
        .await
        .unwrap();
    let id = phone.id().to_string();
    helper
        .expect(
            "a path for the barrier",
            |e| matches!(e, Event::Path { endpoint_id, .. } if *endpoint_id == id),
        )
        .await;
    Barrier {
        _phone: phone,
        conn,
        id,
    }
}

/// Wait until every `close` sent so far has taken effect. The helper reads one
/// op at a time, and a `close` has refused every connection of its peer before
/// the next op is read; so once a `close` for the barrier's peer, sent last,
/// has closed the barrier's streamless connection `refused`, each earlier
/// `close` has reached every connection it names.
async fn await_closes(helper: &mut Helper, barrier: &Barrier) {
    helper
        .send(&json!({ "op": "close", "endpoint_id": barrier.id }))
        .await;
    assert_refused(within("the barrier's refused close", barrier.conn.closed()).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_ends_a_streamless_connection_of_that_peer_only() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let refused = phone(&relay).await;
        let refused_conn = dial(&refused, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        // The helper knows a connection's peer once it reports the
        // connection's first path; the daemon only ever closes a peer whose
        // stream it has seen, so later still.
        let id = refused.id().to_string();
        helper
            .expect(
                "a path for the refused peer",
                |e| matches!(e, Event::Path { endpoint_id, .. } if *endpoint_id == id),
            )
            .await;
        let other = phone(&relay).await;
        let other_conn = dial(&other, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = other_conn.open_bi().await.unwrap();
        send.write_all(b"hi").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 2).await;

        helper
            .send(&json!({ "op": "close", "endpoint_id": id }))
            .await;
        // Well before the 30 s streamless bound.
        assert_refused(within("the refused close", refused_conn.closed()).await);

        // The other peer's connection carries on.
        unix.write_all(b"still here").await.unwrap();
        let mut got = [0u8; 10];
        within("the other peer's bytes", recv.read_exact(&mut got))
            .await
            .unwrap();
        assert_eq!(&got, b"still here");
        assert!(other_conn.close_reason().is_none());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_lets_the_daemons_last_bytes_through_before_the_connection_ends() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"handshake").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 9).await;

        // The daemon refuses the session: `close`, then its close frame, then
        // the bridge closes. Far more than one packet, so a connection closed
        // as soon as the stream ends would cut it off.
        let id = phone.id().to_string();
        helper
            .send(&json!({ "op": "close", "endpoint_id": id }))
            .await;
        let last: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        unix.write_all(&last).await.unwrap();
        drop(unix);

        let got = within("the daemon's last bytes", recv.read_to_end(256 * 1024))
            .await
            .expect("every byte arrives before the connection ends");
        assert_eq!(got.len(), last.len());
        assert!(got == last, "the last bytes arrived changed");
        assert_refused(within("the refused close", conn.closed()).await);
    })
    .await;
}

// The hold the 2026-10-25 review found: a peer opens one stream, gives it no
// flow-control credit and stays silent. At its handshake deadline the daemon
// writes its close frame, closes the bridge and sends `close`. The helper's
// write of that frame used to wait forever, so the stream never ended and the
// connection kept its place for as long as the peer answered keep-alives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_ends_the_connection_of_a_peer_that_gives_its_stream_no_credit() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 1, &relay).await;

        let stranger = phone_giving_no_credit(&relay).await;
        let conn = dial(&stranger, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(b"prelude").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 7).await;

        unix.write_all(b"close frame").await.unwrap();
        drop(unix);
        let id = stranger.id().to_string();
        helper
            .send(&json!({ "op": "close", "endpoint_id": id }))
            .await;
        assert_refused(within("the refused close", conn.closed()).await);
        helper
            .expect(
                "closed for the stranger",
                |e| matches!(e, Event::Closed { endpoint_id } if *endpoint_id == id),
            )
            .await;

        let next = phone(&relay).await;
        dial(&next, helper.endpoint_id(), &relay, ALPN)
            .await
            .expect("the place the stranger held is free");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_bridges_no_further_stream_and_waits_for_every_open_one() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let barrier = dial_barrier(&mut helper, &relay).await;
        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send1, mut recv1) = conn.open_bi().await.unwrap();
        send1.write_all(b"one").await.unwrap();
        let (mut unix1, _) = accept_bridge(&bridge).await;
        read_some(&mut unix1, 3).await;
        let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
        send2.write_all(b"two").await.unwrap();
        let (mut unix2, _) = accept_bridge(&bridge).await;
        read_some(&mut unix2, 3).await;

        let id = phone.id().to_string();
        helper
            .send(&json!({ "op": "close", "endpoint_id": id }))
            .await;
        await_closes(&mut helper, &barrier).await;
        unix1.write_all(b"bye-1").await.unwrap();
        drop(unix1);
        let got = within("stream 1's end", recv1.read_to_end(64))
            .await
            .unwrap();
        assert_eq!(got, b"bye-1");

        // Stream 2 still holds the connection open; a stream opened now is
        // reset, never bridged.
        let (mut send3, mut recv3) = conn.open_bi().await.unwrap();
        send3.write_all(b"three").await.unwrap();
        assert_reset(within("stream 3's reset", recv3.read_to_end(64)).await);
        unix2.write_all(b"bye-2").await.unwrap();
        drop(unix2);
        let got = within("stream 2's end", recv2.read_to_end(64))
            .await
            .unwrap();
        assert_eq!(got, b"bye-2");

        assert_refused(within("the refused close", conn.closed()).await);
        let late = tokio::time::timeout(Duration::from_millis(500), bridge.accept()).await;
        assert!(late.is_err(), "a stream opened after close was bridged");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_peers_connection_still_ends_when_it_is_lost() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let barrier = dial_barrier(&mut helper, &relay).await;
        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        // `closed` follows only a connection that reported a `path`.
        let id = phone.id().to_string();
        helper
            .expect(
                "a path for the phone",
                |e| matches!(e, Event::Path { endpoint_id, .. } if *endpoint_id == id),
            )
            .await;
        let (mut send1, _recv1) = conn.open_bi().await.unwrap();
        send1.write_all(b"x").await.unwrap();
        send1.finish().unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        let mut upstream = Vec::new();
        within("the bridge's end of file", unix.read_to_end(&mut upstream))
            .await
            .unwrap();

        // Only the daemon's half of stream 1 is left, and the daemon holds it
        // open; once the close has taken effect, a new stream is reset.
        helper
            .send(&json!({ "op": "close", "endpoint_id": id }))
            .await;
        await_closes(&mut helper, &barrier).await;
        let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
        send2.write_all(b"y").await.unwrap();
        assert_reset(within("stream 2's reset", recv2.read_to_end(64)).await);

        phone.close().await;
        helper
            .expect(
                "closed for the lost peer",
                |e| matches!(e, Event::Closed { endpoint_id } if *endpoint_id == id),
            )
            .await;
        drop(unix);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_before_ready_or_naming_no_endpoint_id_is_a_bad_request() {
    bounded(async {
        let relay = TestRelay::start().await;
        let id = SecretKey::generate().public().to_string();
        let ops = [
            (false, json!({ "op": "close", "endpoint_id": id })),
            (
                true,
                json!({ "op": "close", "endpoint_id": id.to_uppercase() }),
            ),
            (true, json!({ "op": "close", "endpoint_id": &id[..62] })),
            (true, json!({ "op": "close" })),
        ];
        for (after_ready, op) in ops {
            let mut helper = Helper::spawn().await;
            if after_ready {
                helper.start(&[&relay], 8, &relay).await;
            }
            helper.send(&op).await;
            let error = helper
                .expect("an error", |e| matches!(e, Event::Error { .. }))
                .await;
            assert!(
                matches!(
                    error,
                    Event::Error {
                        code: ErrorCode::BadRequest,
                        ..
                    }
                ),
                "{op}: {error:?}"
            );
            assert_eq!(helper.exit().await.0, Exit::Fatal);
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_past_the_per_connection_credit_waits_for_one_to_close() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        let op = helper.start_op_with_streams(&[&relay], 8, 1);
        helper.start_with(&op, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send1, mut recv1) = conn.open_bi().await.unwrap();
        send1.write_all(b"one").await.unwrap();
        let (mut unix1, _) = accept_bridge(&bridge).await;
        read_some(&mut unix1, 3).await;

        // The second stream has no credit while the first is open.
        let mut second = Box::pin(conn.open_bi());
        let early = tokio::time::timeout(Duration::from_millis(500), &mut second).await;
        assert!(
            early.is_err(),
            "a second stream opened past the credit of 1"
        );

        // The daemon ends the first session: the helper finishes the stream
        // and stops reading it. The stream (and its credit) is released once
        // the phone ends its side too; after a stop, only dropping or
        // resetting the send half does that (noq's `finish` is then a no-op).
        drop(unix1);
        within("stream 1's finish", recv1.read_to_end(64))
            .await
            .unwrap();
        drop(send1);
        let (mut send2, _recv2) = within("credit for the second stream", second)
            .await
            .unwrap();
        send2.write_all(b"two").await.unwrap();
        let (mut unix2, _) = accept_bridge(&bridge).await;
        assert_eq!(read_some(&mut unix2, 3).await, b"two");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_connection_closes_its_bridge_connections() {
    bounded(async {
        let relay = TestRelay::start().await;
        let mut helper = Helper::spawn().await;
        let bridge = helper.listen_bridge();
        helper.start(&[&relay], 8, &relay).await;

        let phone = phone(&relay).await;
        let conn = dial(&phone, helper.endpoint_id(), &relay, ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let (mut unix, _) = accept_bridge(&bridge).await;
        read_some(&mut unix, 1).await;

        // The phone process goes away: its whole endpoint closes.
        phone.close().await;
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(SETTLE, unix.read_to_end(&mut rest)).await;
        assert!(
            closed.is_ok(),
            "the bridge connection outlived its iroh connection"
        );
        let id = phone.id().to_string();
        helper
            .expect(
                "closed",
                |e| matches!(e, Event::Closed { endpoint_id } if *endpoint_id == id),
            )
            .await;
    })
    .await;
}
