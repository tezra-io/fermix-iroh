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
//! | the daemon closes the bridge | finishes the stream and stops reading it; closes the bridge |
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownEnd {
    /// The daemon closed the bridge: the stream is finished.
    BridgeClosed,
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
    send: SendStream,
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
        copy_down(rd, send, &down_stop).await;
        up_stop.cancel();
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
async fn copy_down(
    mut rd: OwnedReadHalf,
    mut send: SendStream,
    halt: &CancellationToken,
) -> DownEnd {
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = tokio::select! {
            _ = halt.cancelled() => return reset_down(&mut send),
            read = rd.read(&mut buf) => read,
        };
        let n = match read {
            Ok(n) if n > 0 => n,
            // EOF or a read error: either way the daemon closed the bridge.
            Ok(_) | Err(_) => return finish_down(&mut send),
        };
        let wrote = tokio::select! {
            _ = halt.cancelled() => return reset_down(&mut send),
            wrote = send.write_all(&buf[..n]) => wrote,
        };
        match wrote {
            Ok(()) => {}
            Err(WriteError::Stopped(_)) => return DownEnd::PeerStopped,
            Err(_) => return DownEnd::StreamLost,
        }
    }
}

fn finish_down(send: &mut SendStream) -> DownEnd {
    // noq's only error here is ClosedStream: the send half already ended.
    let _ = send.finish();
    DownEnd::BridgeClosed
}

fn reset_down(send: &mut SendStream) -> DownEnd {
    reset(send, ABANDON_CODE);
    DownEnd::Cancelled
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
