//! One accepted iroh stream, bridged to one connection on the daemon's socket.
//!
//! The helper writes the 37-byte preamble (`FXB1`, the peer's kind, the peer's
//! raw endpoint id), then copies bytes unchanged both ways through a 64 KiB
//! buffer per direction, never parsing them. How each side ending ends the
//! other is the contract's *Ending* list, implemented in [`splice`]:
//!
//! | The first thing that happens | What the helper does |
//! |---|---|
//! | the peer finishes the stream | shuts down the bridge's write half; keeps copying the daemon's bytes until it closes |
//! | the daemon closes the bridge | stops reading the stream; closes the bridge; sends the peer the daemon's last bytes and finishes the stream; resets it, code 0, unless the peer has taken and acknowledged them within 5 s |
//! | the peer resets the stream, or the connection is lost | closes the bridge (and resets the stream's send side, code 0) |
//! | the peer stops reading the stream | closes the bridge (contract silent; see `DEVIATIONS.md`) |
//! | the bridge socket cannot be reached | resets the stream with code 2, reports `refused` `bridge_unreachable`; no retry |

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{ReadError, RecvStream, SendStream, VarInt, WriteError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::sync::CancellationToken;

use crate::ndjson::EventSink;
use crate::protocol::{Event, LogLevel, RefusedReason};
use crate::status::sanitize_error_text;

/// The preamble's magic, ASCII `FXB1`.
pub const MAGIC: [u8; 4] = *b"FXB1";

/// The preamble's length: magic, kind, endpoint id.
pub const PREAMBLE_LEN: usize = 37;

/// The copy buffer in each direction.
pub const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// The application code a stream is reset with when the bridge is unreachable.
pub const UNREACHABLE_CODE: u32 = 2;

/// The application code for every other stream end the helper initiates.
pub const ABANDON_CODE: u32 = 0;

/// How long connecting to the bridge and writing the preamble may take.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// How long the peer of a stream the daemon ended has to take the daemon's
/// last bytes and acknowledge them, before the stream is reset with code 0.
/// Until then it counts as open, so the connection a `close` ends is not
/// closed under the daemon's close frame.
pub const ACK_DEADLINE: Duration = Duration::from_secs(5);

/// The bridge preamble for a peer of `kind` whose endpoint id is `peer`.
pub fn preamble(kind: u8, peer: &[u8; 32]) -> [u8; PREAMBLE_LEN] {
    let mut out = [0u8; PREAMBLE_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4] = kind;
    out[5..].copy_from_slice(peer);
    out
}

/// What a stream's bridge needs to know.
#[derive(Clone)]
pub struct StreamContext {
    /// The peer's endpoint id.
    pub peer: EndpointId,
    /// The peer's kind, written in the preamble.
    pub kind: u8,
    /// The daemon's bridge socket.
    pub socket: Arc<Path>,
    /// Where `refused` and `log` events go.
    pub sink: EventSink,
    /// Fires when the helper shuts down.
    pub stop: CancellationToken,
}

/// Bridge one accepted bidirectional stream until both directions have ended.
pub async fn run(send: SendStream, recv: RecvStream, ctx: StreamContext) {
    match connect(&ctx).await {
        Ok(unix) => {
            let (rd, wr) = unix.into_split();
            splice(send, recv, rd, wr, &ctx.stop).await;
        }
        Err(reason) => refuse_unreachable(send, recv, &ctx, &reason).await,
    }
}

/// Connect to the bridge socket and write the preamble, within the deadline.
async fn connect(ctx: &StreamContext) -> Result<UnixStream, String> {
    let preamble = preamble(ctx.kind, ctx.peer.as_bytes());
    let attempt = async {
        let mut unix = UnixStream::connect(&*ctx.socket).await?;
        unix.write_all(&preamble).await?;
        Ok::<_, std::io::Error>(unix)
    };
    match tokio::time::timeout(CONNECT_DEADLINE, attempt).await {
        Ok(Ok(unix)) => Ok(unix),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {}s", CONNECT_DEADLINE.as_secs())),
    }
}

async fn refuse_unreachable(
    mut send: SendStream,
    mut recv: RecvStream,
    ctx: &StreamContext,
    reason: &str,
) {
    reset(&mut send, UNREACHABLE_CODE);
    stop(&mut recv, UNREACHABLE_CODE);
    let message = sanitize_error_text(&format!("bridge socket unreachable: {reason}"));
    ctx.sink.emit(Event::log(LogLevel::Warn, &message)).await;
    ctx.sink
        .emit(Event::Refused {
            reason: RefusedReason::BridgeUnreachable,
            endpoint_id: Some(ctx.peer.to_string()),
        })
        .await;
}

/// How the peer-to-daemon direction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpEnd {
    /// The peer finished its side: the bridge's write half is shut down.
    PeerFinished,
    /// The peer reset its side.
    PeerReset,
    /// The stream or its connection is gone.
    StreamLost,
    /// Writing to the bridge failed: the daemon closed it. Reading stopped.
    BridgeClosed,
    /// The other direction or a shutdown ended this one. Reading stopped.
    Cancelled,
}

impl UpEnd {
    /// Whether this ending abandons the stream, so the bridge must close.
    fn abandons_stream(self) -> bool {
        matches!(self, UpEnd::PeerReset | UpEnd::StreamLost)
    }
}

/// How the daemon-to-peer direction ended. Every ending stops the other
/// direction: either the daemon closed the bridge, or the stream cannot carry
/// the daemon's bytes any more.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DownEnd {
    /// The daemon closed the bridge; the peer has yet to take these of its
    /// bytes.
    BridgeClosed(Vec<u8>),
    /// The peer stopped reading the stream.
    PeerStopped,
    /// The stream or its connection is gone.
    StreamLost,
    /// The other direction or a shutdown ended this one: the stream is reset.
    Cancelled,
}

/// Run both directions to their ends, letting each end the other as the
/// contract's *Ending* list says. Both halves of the bridge connection are
/// dropped, and so closed, when this returns.
async fn splice(
    mut send: SendStream,
    recv: RecvStream,
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    stop: &CancellationToken,
) {
    let up_stop = stop.child_token();
    let down_stop = stop.child_token();
    let up = async {
        let end = copy_up(recv, wr, &up_stop).await;
        if end.abandons_stream() {
            down_stop.cancel();
        }
    };
    let down = async {
        let end = copy_down(rd, &mut send, &down_stop).await;
        up_stop.cancel();
        if let DownEnd::BridgeClosed(unsent) = end {
            send_last(&mut send, &unsent, &down_stop).await;
        }
    };
    tokio::join!(up, down);
}

/// Copy peer bytes to the bridge until the peer ends its side or this is stopped.
async fn copy_up(mut recv: RecvStream, mut wr: OwnedWriteHalf, halt: &CancellationToken) -> UpEnd {
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = tokio::select! {
            _ = halt.cancelled() => return stopped_up(&mut recv, UpEnd::Cancelled),
            read = recv.read(&mut buf) => read,
        };
        let n = match read {
            Ok(Some(n)) => n,
            Ok(None) => return finish_up(&mut wr, halt).await,
            Err(ReadError::Reset(_)) => return UpEnd::PeerReset,
            Err(_) => return UpEnd::StreamLost,
        };
        let wrote = tokio::select! {
            _ = halt.cancelled() => return stopped_up(&mut recv, UpEnd::Cancelled),
            wrote = wr.write_all(&buf[..n]) => wrote,
        };
        if wrote.is_err() {
            return stopped_up(&mut recv, UpEnd::BridgeClosed);
        }
    }
}

/// The peer finished: shut down the bridge's write half so the daemon reads EOF.
async fn finish_up(wr: &mut OwnedWriteHalf, halt: &CancellationToken) -> UpEnd {
    let shut = tokio::select! {
        _ = halt.cancelled() => return UpEnd::Cancelled,
        shut = wr.shutdown() => shut,
    };
    match shut {
        Ok(()) => UpEnd::PeerFinished,
        // The daemon already closed the bridge; the other direction sees that.
        Err(_) => UpEnd::BridgeClosed,
    }
}

fn stopped_up(recv: &mut RecvStream, end: UpEnd) -> UpEnd {
    stop(recv, ABANDON_CODE);
    end
}

/// Copy daemon bytes to the peer until the daemon closes or this is stopped.
///
/// The bridge is read whenever the buffer has room, also while a write waits
/// for the peer's flow-control credit, so the daemon's close is seen even
/// when the peer takes nothing. What the peer has not taken by then comes back
/// with [`DownEnd::BridgeClosed`]. Both `read` and noq's `write` are cancel
/// safe, so whichever finishes second loses nothing.
async fn copy_down(
    mut rd: OwnedReadHalf,
    send: &mut SendStream,
    halt: &CancellationToken,
) -> DownEnd {
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    // `buf[sent..filled]` is read from the daemon and not yet taken by the peer.
    let (mut sent, mut filled) = (0, 0);
    loop {
        if sent == filled {
            (sent, filled) = (0, 0);
        } else if filled == buf.len() {
            buf.copy_within(sent..filled, 0);
            (sent, filled) = (0, filled - sent);
        }
        let (held, room) = buf.split_at_mut(filled);
        let unsent = &held[sent..];
        tokio::select! {
            _ = halt.cancelled() => return reset_down(send),
            read = rd.read(room), if !room.is_empty() => match read {
                Ok(n) if n > 0 => filled += n,
                // EOF or a read error: either way the daemon closed the bridge.
                Ok(_) | Err(_) => return DownEnd::BridgeClosed(unsent.to_vec()),
            },
            wrote = send.write(unsent), if !unsent.is_empty() => match wrote {
                Ok(n) => sent += n,
                Err(WriteError::Stopped(_)) => return DownEnd::PeerStopped,
                Err(_) => return DownEnd::StreamLost,
            },
        }
    }
}

/// The daemon closed the bridge: send the peer the bytes it has not taken,
/// finish the stream and wait for the peer to acknowledge every byte of it,
/// all within [`ACK_DEADLINE`]. A peer that has not by then gets the stream
/// reset with code 0, as does a stream this is stopped on meanwhile (a peer
/// reset, a lost stream, shutdown). The stream counts as open until then,
/// because a connection closed while stream data is unacknowledged discards
/// it; the deadline keeps a peer that gives the stream no flow-control credit
/// from holding it open.
async fn send_last(send: &mut SendStream, unsent: &[u8], halt: &CancellationToken) {
    let last = async {
        // A failed write means the peer stopped the stream or the connection
        // is gone: either way the stream has ended.
        if send.write_all(unsent).await.is_ok() {
            // noq's only error here is ClosedStream: the send half already ended.
            let _ = send.finish();
            // Acknowledged, stopped by the peer, or the connection gone: each
            // ends the wait, and none is the daemon's business.
            let _ = send.stopped().await;
        }
    };
    let ended = tokio::select! {
        _ = halt.cancelled() => false,
        ended = tokio::time::timeout(ACK_DEADLINE, last) => ended.is_ok(),
    };
    if !ended {
        reset(send, ABANDON_CODE);
    }
}

fn reset_down(send: &mut SendStream) -> DownEnd {
    reset(send, ABANDON_CODE);
    DownEnd::Cancelled
}

/// End a stream the helper does not bridge: reset its send half and stop
/// reading it, both with code 0.
pub fn abandon(mut send: SendStream, mut recv: RecvStream) {
    reset(&mut send, ABANDON_CODE);
    stop(&mut recv, ABANDON_CODE);
}

fn reset(send: &mut SendStream, code: u32) {
    // noq's only error here is ClosedStream: the send half already ended.
    let _ = send.reset(VarInt::from_u32(code));
}

fn stop(recv: &mut RecvStream, code: u32) {
    // noq's only error here is ClosedStream: the receive half already ended.
    let _ = recv.stop(VarInt::from_u32(code));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preamble_is_magic_kind_and_raw_id() {
        let id: [u8; 32] = std::array::from_fn(|i| i as u8);
        let p = preamble(0x01, &id);
        assert_eq!(p.len(), 37);
        assert_eq!(&p[..4], b"FXB1");
        assert_eq!(p[4], 0x01);
        assert_eq!(&p[5..], &id);
    }
}
