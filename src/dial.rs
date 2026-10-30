//! The daemon's dials: one iroh connection and one stream per `dial`, copied
//! to the Unix socket the daemon named for it.
//!
//! | Step | What can end it |
//! |---|---|
//! | connect to the peer through its relays and any direct address | `unreachable`, `refused` |
//! | open one bidirectional stream | `refused` (the connection ended) |
//! | wait for the connection's selected path | `refused` (the connection ended) |
//! | connect to the daemon's socket | `bridge_unreachable`: the stream is reset with code 2 |
//! | all of the above, together | `timeout` once [`crate::endpoint::Timings::dial_deadline`] passes |
//!
//! Then `dialed`, and the stream is copied by the same [`bridge::splice`] as an
//! accepted one, with no preamble; when both directions have ended the
//! connection is closed with code 0, reason `done`, and `dial_closed` is sent.
//! A dial that fails once its connection is made closes it with code 0 and the
//! failure's name as the reason. At most [`MAX_DIALS`] dials are in flight,
//! from the op until their last event; a dial past that is `dial_failed`
//! `busy` at once. A dial is removed from the table before its last event is
//! sent, so the daemon may reuse its id as soon as it reads that event. A dial
//! cut short by shutdown sends nothing (the daemon asked for the shutdown): a
//! connection still in its handshake is dropped, as it cannot carry a reason,
//! and one past it is closed with reason `shutdown` like every other.

use std::collections::HashSet;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::StreamExt;
use iroh::endpoint::{ConnectError, Connection, ConnectionError, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, EndpointAddr, TransportAddr};
use tokio::net::UnixStream;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::bridge;
use crate::ndjson::EventSink;
use crate::protocol::{DialConfig, DialFailure, Event, LogLevel, PathKind};
use crate::status::{sanitize_error_text, selected_path};

/// The most dials in flight at once.
pub const MAX_DIALS: usize = 8;

/// How long connecting to the daemon's socket may take, within the deadline.
const SOCKET_DEADLINE: Duration = bridge::CONNECT_DEADLINE;

/// Starts dials and holds the table of those in flight.
pub struct Dialer {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    deadline: Duration,
    sink: EventSink,
    stop: CancellationToken,
    tasks: TaskTracker,
    active: Arc<Mutex<HashSet<String>>>,
}

/// A dial's place in the table; dropping it frees the place.
struct Active {
    table: Arc<Mutex<HashSet<String>>>,
    dial_id: String,
}

impl Drop for Active {
    fn drop(&mut self) {
        lock(&self.table).remove(&self.dial_id);
    }
}

fn lock(table: &Mutex<HashSet<String>>) -> MutexGuard<'_, HashSet<String>> {
    // A panic ends the process with 101 (see `main`), so no thread ever sees
    // the lock poisoned.
    table
        .lock()
        .expect("the dial table's lock is never poisoned")
}

/// Why a dial made nothing, and the diagnostic for the daemon's log.
struct Failed {
    reason: DialFailure,
    detail: Option<String>,
}

impl Failed {
    fn new(reason: DialFailure, detail: impl Into<String>) -> Self {
        Failed {
            reason,
            detail: Some(detail.into()),
        }
    }
}

impl Dialer {
    /// A dialer on `endpoint`, offering `alpn`. Dial tasks run on `tasks` and
    /// end when `stop` fires.
    pub fn new(
        endpoint: Endpoint,
        alpn: Vec<u8>,
        deadline: Duration,
        sink: EventSink,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> Self {
        Dialer {
            endpoint,
            alpn,
            deadline,
            sink,
            stop,
            tasks,
            active: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Start one dial. A `dial_id` already in flight is the daemon's error
    /// (`bad_request`); a dial past [`MAX_DIALS`] is `dial_failed` `busy`.
    pub async fn dial(&self, cfg: DialConfig) -> Result<(), String> {
        let place = {
            let mut table = lock(&self.active);
            if table.contains(&cfg.dial_id) {
                return Err(format!("dial_id {} is already in flight", cfg.dial_id));
            }
            if table.len() >= MAX_DIALS {
                None
            } else {
                table.insert(cfg.dial_id.clone());
                Some(Active {
                    table: self.active.clone(),
                    dial_id: cfg.dial_id.clone(),
                })
            }
        };
        let Some(place) = place else {
            self.sink
                .emit(failed_event(&cfg.dial_id, DialFailure::Busy))
                .await;
            return Ok(());
        };
        let run = Run {
            endpoint: self.endpoint.clone(),
            alpn: self.alpn.clone(),
            deadline: self.deadline,
            sink: self.sink.clone(),
            stop: self.stop.child_token(),
        };
        self.tasks.spawn(async move { run.dial(cfg, place).await });
        Ok(())
    }
}

/// One dial's task.
struct Run {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    deadline: Duration,
    sink: EventSink,
    stop: CancellationToken,
}

/// How one step of a dial ended.
enum Step<T> {
    Done(T),
    Failed(Failed),
    Stopped,
}

/// The stream, its path and the daemon's socket, ready to copy.
struct Opened {
    send: SendStream,
    recv: RecvStream,
    unix: UnixStream,
    kind: PathKind,
    relay: Option<String>,
}

impl Run {
    /// Connect, then open the stream and its socket, both within one deadline.
    /// A connection still in its handshake when the helper stops is dropped (it
    /// cannot carry a reason); one past it is closed with reason `shutdown`.
    async fn dial(self, cfg: DialConfig, place: Active) {
        let deadline = Instant::now() + self.deadline;
        let conn = match self.step(deadline, self.connect(&cfg)).await {
            Step::Done(conn) => conn,
            Step::Failed(failed) => return self.fail(&cfg.dial_id, failed, place).await,
            Step::Stopped => return,
        };
        match self.step(deadline, open(&conn, &cfg.socket)).await {
            Step::Done(opened) => self.copy(&cfg.dial_id, conn, opened, place).await,
            Step::Failed(failed) => {
                conn.close(VarInt::from_u32(0), close_reason(failed.reason));
                self.fail(&cfg.dial_id, failed, place).await;
            }
            Step::Stopped => conn.close(VarInt::from_u32(0), b"shutdown"),
        }
    }

    async fn step<T>(
        &self,
        deadline: Instant,
        work: impl Future<Output = Result<T, Failed>>,
    ) -> Step<T> {
        tokio::select! {
            _ = self.stop.cancelled() => Step::Stopped,
            done = tokio::time::timeout_at(deadline, work) => match done {
                Ok(Ok(value)) => Step::Done(value),
                Ok(Err(failed)) => Step::Failed(failed),
                Err(_) => {
                    let detail = format!("not connected within {}s", self.deadline.as_secs());
                    Step::Failed(Failed::new(DialFailure::Timeout, detail))
                }
            },
        }
    }

    async fn connect(&self, cfg: &DialConfig) -> Result<Connection, Failed> {
        self.endpoint
            .connect(address(cfg), &self.alpn)
            .await
            .map_err(|e| connect_failed(&e))
    }

    async fn copy(&self, dial_id: &str, conn: Connection, opened: Opened, place: Active) {
        let Opened {
            send,
            recv,
            unix,
            kind,
            relay,
        } = opened;
        let dialed = Event::Dialed {
            dial_id: dial_id.to_string(),
            kind,
            relay,
        };
        self.sink.emit(dialed).await;
        let (rd, wr) = unix.into_split();
        bridge::splice(send, recv, rd, wr, &self.stop).await;
        if self.stop.is_cancelled() {
            conn.close(VarInt::from_u32(0), b"shutdown");
            return;
        }
        conn.close(VarInt::from_u32(0), b"done");
        drop(place);
        let closed = Event::DialClosed {
            dial_id: dial_id.to_string(),
        };
        self.sink.emit(closed).await;
    }

    async fn fail(&self, dial_id: &str, failed: Failed, place: Active) {
        drop(place);
        if let Some(detail) = failed.detail {
            let message = sanitize_error_text(&format!("dial {dial_id} failed: {detail}"));
            self.sink.emit(Event::log(LogLevel::Warn, &message)).await;
        }
        self.sink.emit(failed_event(dial_id, failed.reason)).await;
    }
}

/// Open the stream, wait for the connection's selected path, and connect the
/// daemon's socket. A socket that cannot be reached resets the stream with
/// code 2.
async fn open(conn: &Connection, socket: &Path) -> Result<Opened, Failed> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Failed::new(connection_failure(&e), e.to_string()))?;
    let (kind, relay) = path_of(conn).await?;
    match connect_socket(socket).await {
        Ok(unix) => Ok(Opened {
            send,
            recv,
            unix,
            kind,
            relay,
        }),
        Err(detail) => {
            bridge::abandon_unreachable(send, recv);
            let detail = format!("dial socket unreachable: {detail}");
            Err(Failed::new(DialFailure::BridgeUnreachable, detail))
        }
    }
}

/// The reason a dial's connection is closed with when the dial fails after the
/// connection was made.
fn close_reason(reason: DialFailure) -> &'static [u8] {
    match reason {
        DialFailure::Unreachable => b"unreachable",
        DialFailure::Timeout => b"timeout",
        DialFailure::Refused => b"refused",
        DialFailure::BridgeUnreachable => b"bridge_unreachable",
        DialFailure::Busy => b"busy",
    }
}

fn failed_event(dial_id: &str, reason: DialFailure) -> Event {
    Event::DialFailed {
        dial_id: dial_id.to_string(),
        reason,
    }
}

/// The peer's id, its relays and its direct addresses.
fn address(cfg: &DialConfig) -> EndpointAddr {
    let relays = cfg
        .relays
        .iter()
        .map(|relay| TransportAddr::Relay(relay.url.clone()));
    let direct = cfg.addrs.iter().map(|addr| TransportAddr::Ip(*addr));
    EndpointAddr::from_parts(cfg.peer, relays.chain(direct))
}

/// The selected path once the connection has one. iroh selects one as the
/// handshake completes; a connection that ends first is `refused`.
async fn path_of(conn: &Connection) -> Result<(PathKind, Option<String>), Failed> {
    let mut snapshots = conn.paths_stream();
    while let Some(paths) = snapshots.next().await {
        if let Some(path) = selected_path(&paths) {
            return Ok(path);
        }
    }
    let detail = match conn.close_reason() {
        Some(reason) => reason.to_string(),
        None => "the connection ended before it had a path".to_string(),
    };
    Err(Failed::new(DialFailure::Refused, detail))
}

async fn connect_socket(socket: &Path) -> Result<UnixStream, String> {
    match tokio::time::timeout(SOCKET_DEADLINE, UnixStream::connect(socket)).await {
        Ok(Ok(unix)) => Ok(unix),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {}s", SOCKET_DEADLINE.as_secs())),
    }
}

/// A failed connect: the peer ending or refusing the connection is `refused`;
/// no path, an endpoint that cannot start the connection, or a handshake that
/// times out is `unreachable`.
fn connect_failed(err: &ConnectError) -> Failed {
    let reason = match err {
        ConnectError::Connection { source, .. } => connection_failure(source),
        ConnectError::Connecting { source, .. } => match source {
            iroh::endpoint::ConnectingError::ConnectionError { source, .. } => {
                connection_failure(source)
            }
            iroh::endpoint::ConnectingError::HandshakeFailure { .. } => DialFailure::Refused,
            _ => DialFailure::Unreachable,
        },
        _ => DialFailure::Unreachable,
    };
    Failed::new(reason, err.to_string())
}

/// What an ended connection means for a dial.
fn connection_failure(err: &ConnectionError) -> DialFailure {
    match err {
        ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_)
        | ConnectionError::Reset
        | ConnectionError::TransportError(_)
        | ConnectionError::VersionMismatch => DialFailure::Refused,
        _ => DialFailure::Unreachable,
    }
}
