//! The control loop: `hello`, then one op at a time from stdin.
//!
//! | Op or input | Before `ready` | After `ready` |
//! |---|---|---|
//! | `start` | validate, read the key, bind, answer `ready` | `bad_request` |
//! | `set_relays` | `bad_request` | replace the relay map |
//! | `close` | `bad_request` | close the peer's connections once their streams end |
//! | `shutdown`, or end of stdin | exit 0 | graceful shutdown, exit 0 within 5 s |
//! | a framing or decode error | `bad_request` | `bad_request` |
//!
//! Every failure is one `error` event and exit 1, within 2 s of the event.

use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::endpoint::{self, AcceptEnd, Acceptor, Network, RelayTable};
use crate::key;
use crate::ndjson::{EventSink, EventWriter, LineError, LineReader};
use crate::protocol::{
    ErrorCode, Event, LogLevel, Op, RelaySpec, StartConfig, decode_op, validate_endpoint_id,
    validate_relays,
};
use crate::shutdown;
use crate::status;

/// How long binding the endpoint may take before it is a `bind_failed`.
pub const BIND_DEADLINE: Duration = Duration::from_secs(10);

/// How long the `error` event may take to reach stdout before the helper
/// exits anyway; well inside the contract's 2 s.
pub const ERROR_DEADLINE: Duration = Duration::from_secs(1);

/// How the helper ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// After `shutdown` or end of stdin: exit 0.
    Shutdown,
    /// After an `error` event (or with stdout gone): exit 1.
    Fatal,
}

impl Exit {
    /// The process exit status.
    pub fn code(self) -> u8 {
        match self {
            Exit::Shutdown => 0,
            Exit::Fatal => 1,
        }
    }
}

/// Speak the protocol on `input`/`output` until shutdown or a fatal error.
pub async fn run<R, W>(input: R, output: W, net: Network) -> Exit
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (mut writer, sink) = EventWriter::spawn(output);
    sink.emit(Event::hello()).await;
    let mut lines = LineReader::new(BufReader::new(input));
    let mut session = Session {
        sink,
        net,
        running: None,
    };
    loop {
        let input = tokio::select! {
            line = lines.next_line() => Input::Line(line),
            message = session.background_failure() => Input::Failure(message),
            _ = writer.failed() => return Exit::Fatal,
        };
        if let Some(exit) = session.step(input).await {
            return exit;
        }
    }
}

enum Input {
    Line(Result<Option<String>, LineError>),
    Failure(String),
}

/// The bound endpoint and everything running on it.
struct Running {
    endpoint: Endpoint,
    relays: RelayTable,
    acceptor: Arc<Acceptor>,
    stop: CancellationToken,
    tasks: TaskTracker,
    failures: mpsc::Receiver<String>,
}

struct Session {
    sink: EventSink,
    net: Network,
    running: Option<Running>,
}

impl Session {
    /// Resolves when a background task reports a fatal failure; never before
    /// `ready`.
    async fn background_failure(&mut self) -> String {
        match self.running.as_mut() {
            Some(running) => match running.failures.recv().await {
                Some(message) => message,
                None => std::future::pending().await,
            },
            None => std::future::pending().await,
        }
    }

    /// Handle one input; `Some` ends the helper.
    async fn step(&mut self, input: Input) -> Option<Exit> {
        match input {
            Input::Line(Ok(Some(line))) => self.on_line(&line).await,
            Input::Line(Ok(None)) => Some(self.shutdown().await),
            Input::Line(Err(LineError::Io(e))) => {
                let message = format!("reading stdin failed: {e}");
                Some(self.fail(ErrorCode::Internal, &message).await)
            }
            Input::Line(Err(e)) => Some(self.fail(ErrorCode::BadRequest, &e.to_string()).await),
            Input::Failure(message) => Some(self.fail(ErrorCode::Internal, &message).await),
        }
    }

    async fn on_line(&mut self, line: &str) -> Option<Exit> {
        let op = match decode_op(line) {
            Ok(op) => op,
            Err(e) => return Some(self.fail(ErrorCode::BadRequest, &e.to_string()).await),
        };
        match op {
            Op::Shutdown {} => Some(self.shutdown().await),
            Op::SetRelays { relays } => self.set_relays(&relays).await,
            Op::Close { endpoint_id } => self.close_peer(&endpoint_id).await,
            Op::Start {
                secret_key_path,
                bridge_socket,
                alpn,
                relays,
                limits,
            } => {
                let cfg = StartConfig::validate(
                    &secret_key_path,
                    &bridge_socket,
                    &alpn,
                    &relays,
                    &limits,
                );
                match cfg {
                    Ok(cfg) => self.start(cfg).await,
                    Err(e) => Some(self.fail(ErrorCode::BadRequest, &e.to_string()).await),
                }
            }
        }
    }

    async fn start(&mut self, cfg: StartConfig) -> Option<Exit> {
        if self.running.is_some() {
            return Some(self.fail(ErrorCode::BadRequest, "start sent twice").await);
        }
        let key = match key::load(&cfg.secret_key_path) {
            Ok(key) => key,
            Err(e) => return Some(self.fail(e.code(), &e.to_string()).await),
        };
        let bound = tokio::time::timeout(BIND_DEADLINE, endpoint::bind(key, &cfg, &self.net)).await;
        let endpoint = match bound {
            Ok(Ok(endpoint)) => endpoint,
            Ok(Err(e)) => return Some(self.fail(ErrorCode::BindFailed, &e).await),
            Err(_) => {
                let message = format!("bind did not finish within {}s", BIND_DEADLINE.as_secs());
                return Some(self.fail(ErrorCode::BindFailed, &message).await);
            }
        };
        self.sink
            .emit(Event::Ready {
                endpoint_id: endpoint.id().to_string(),
            })
            .await;
        self.sink.emit(bound_sockets_log(&endpoint)).await;
        self.running = Some(self.launch(endpoint, &cfg));
        None
    }

    /// Start the relay watcher and the accept loop on a bound endpoint.
    fn launch(&self, endpoint: Endpoint, cfg: &StartConfig) -> Running {
        let stop = CancellationToken::new();
        let tasks = TaskTracker::new();
        let (failure_tx, failures) = mpsc::channel(1);
        tasks.spawn(status::watch_relays(
            endpoint.clone(),
            self.sink.clone(),
            stop.clone(),
        ));
        let acceptor = Arc::new(Acceptor::new(
            endpoint.clone(),
            cfg,
            self.net.timings,
            self.sink.clone(),
            stop.clone(),
            tasks.clone(),
        ));
        let accepting = acceptor.clone();
        tasks.spawn(async move {
            if accepting.run().await == AcceptEnd::EndpointClosed {
                let message = "the endpoint closed while accepting".to_string();
                // A full or closed channel means a failure is already pending
                // or the session has ended; either way this one is redundant.
                let _ = failure_tx.try_send(message);
            }
        });
        Running {
            endpoint,
            relays: RelayTable::new(&cfg.relays),
            acceptor,
            stop,
            tasks,
            failures,
        }
    }

    async fn set_relays(&mut self, relays: &[RelaySpec]) -> Option<Exit> {
        match self.replace_relays(relays).await {
            Ok(()) => None,
            Err((code, message)) => Some(self.fail(code, &message).await),
        }
    }

    /// Validate `relays` and make them the endpoint's relay map.
    async fn replace_relays(&mut self, relays: &[RelaySpec]) -> Result<(), (ErrorCode, String)> {
        let Some(running) = self.running.as_mut() else {
            return Err((ErrorCode::BadRequest, "set_relays before ready".into()));
        };
        let relays = validate_relays(relays).map_err(|e| (ErrorCode::BadRequest, e.to_string()))?;
        running
            .relays
            .replace(&running.endpoint, &relays)
            .await
            .map_err(|e| (ErrorCode::Internal, e))
    }

    async fn close_peer(&mut self, endpoint_id: &str) -> Option<Exit> {
        match self.refuse_peer(endpoint_id) {
            Ok(()) => None,
            Err(message) => Some(self.fail(ErrorCode::BadRequest, &message).await),
        }
    }

    /// Validate `endpoint_id` and have that peer's connections closed.
    fn refuse_peer(&self, endpoint_id: &str) -> Result<(), String> {
        let Some(running) = self.running.as_ref() else {
            return Err("close before ready".into());
        };
        let peer = validate_endpoint_id(endpoint_id).map_err(|e| e.to_string())?;
        running.acceptor.close_peer(peer);
        Ok(())
    }

    async fn shutdown(&mut self) -> Exit {
        if let Some(running) = self.running.take() {
            shutdown::graceful(running.endpoint, running.stop, running.tasks, &self.sink).await;
        }
        self.sink.flush(shutdown::FLUSH_DEADLINE).await;
        Exit::Shutdown
    }

    /// Send one `error` event and end the helper with exit 1.
    async fn fail(&mut self, code: ErrorCode, message: &str) -> Exit {
        let report = async {
            self.sink.emit(Event::error(code, message)).await;
            self.sink.flush(ERROR_DEADLINE).await
        };
        if tokio::time::timeout(ERROR_DEADLINE, report).await.is_err() {
            // stdout is not draining; exit regardless so the contract's 2 s holds.
            eprintln!("fermix-iroh: the error event did not reach stdout: {message}");
        }
        Exit::Fatal
    }
}

/// An info `log` naming the UDP sockets the endpoint bound, for firewall
/// diagnostics.
fn bound_sockets_log(endpoint: &Endpoint) -> Event {
    let sockets: Vec<String> = endpoint
        .bound_sockets()
        .iter()
        .map(ToString::to_string)
        .collect();
    Event::log(
        LogLevel::Info,
        &format!("bound UDP sockets: {}", sockets.join(", ")),
    )
}
