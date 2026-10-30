//! Wire types for the Fermix iroh helper protocol.
//!
//! The contract is defined by the daemon and vendored into this repo at
//! `protocol/PROTOCOL.md`, with byte-exact samples in `protocol/fixtures/`.
//! Nothing in this module may drift from those files: `tests/fixtures.rs`
//! round-trips every fixture through these types and compares bytes.
//!
//! Decoding is strict. A line that is not a JSON object, an unknown `op`, a
//! missing field, an unknown field, a field of the wrong type or an optional
//! field sent as `null` is a decode error; a well-typed `start`, `set_relays`,
//! `close` or `dial` whose values are out of range is a validation error. Both
//! end the helper with `bad_request`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use iroh::{EndpointId, RelayUrl};
use serde::{Deserialize, Deserializer, Serialize};

/// The single integer version carried in `hello`. Pinned to `protocol/PROTOCOL.md`.
pub const PROTOCOL_VERSION: u32 = 3;

/// The longest control line, in bytes, not counting its terminating `\n`.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The longest `message` (and relay `error`) text an event carries, in bytes.
pub const MAX_TEXT_BYTES: usize = 512;

/// The one application protocol the endpoint accepts.
pub const ALPN_MOBILE: &str = "fermix/mobile/1";

/// The bridge preamble's peer kind for connections on [`ALPN_MOBILE`]: a phone.
pub const KIND_PHONE: u8 = 0x01;

/// Fewest and most relays a `start` or `set_relays` may name.
pub const RELAYS_MIN: usize = 1;
/// See [`RELAYS_MIN`].
pub const RELAYS_MAX: usize = 8;

/// Bounds of `limits.max_connections`.
pub const MAX_CONNECTIONS_RANGE: (u32, u32) = (1, 1024);
/// Bounds of `limits.max_streams_per_connection`.
pub const MAX_STREAMS_RANGE: (u32, u32) = (1, 16);
/// Bounds of each flow-control window, in bytes.
pub const WINDOW_RANGE: (u64, u64) = (65_536, 16_777_216);

/// The longest `dial_id`, in bytes.
pub const DIAL_ID_MAX_BYTES: usize = 64;

/// The most direct addresses a `dial` may name.
pub const DIAL_ADDRS_MAX: usize = 8;

/// The bridge preamble's peer kind for an accepted ALPN, or `None` for an ALPN
/// this helper has no kind for.
pub fn kind_for_alpn(alpn: &[u8]) -> Option<u8> {
    (alpn == ALPN_MOBILE.as_bytes()).then_some(KIND_PHONE)
}

/// The closed set of fatal error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A malformed or out-of-order `op`.
    BadRequest,
    /// The key file could not be opened or read.
    KeyUnreadable,
    /// The key file is not exactly 32 bytes, mode `0600`, in a regular file.
    KeyInvalid,
    /// The endpoint could not be bound.
    BindFailed,
    /// An unexpected failure inside the helper.
    Internal,
}

/// Why a connection or stream was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedReason {
    /// Over `limits.max_connections` with no connection that can make way;
    /// refused before its handshake.
    Busy,
    /// No matching application protocol; refused in the TLS handshake.
    Alpn,
    /// The bridge socket could not be reached for a stream.
    BridgeUnreachable,
}

/// The level of a `log` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Routine diagnostics.
    Info,
    /// Something the operator may want to look at.
    Warn,
}

/// A connection's selected path kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// Through a relay server.
    Relay,
    /// A direct UDP path.
    Direct,
}

/// Why a `dial` did not give the daemon a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialFailure {
    /// No path to the peer: no address worked, or the endpoint could not start
    /// the connection.
    Unreachable,
    /// The connection, the stream or the socket was not ready within the
    /// dial's deadline.
    Timeout,
    /// The peer ended the connection or failed its handshake.
    Refused,
    /// The daemon's dial socket could not be reached.
    BridgeUnreachable,
    /// The helper already has its most dials in flight.
    Busy,
}

/// Frames the helper sends. Serialized as one compact JSON object per line;
/// field order is declaration order, which the fixtures pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// The first line, within 10 s of spawn.
    Hello {
        /// The wire version this build speaks.
        protocol_version: u32,
        /// This helper's semver.
        helper_version: String,
        /// The iroh version this helper is built against.
        iroh_version: String,
    },
    /// The endpoint is bound with the key from `start`.
    Ready {
        /// Lowercase hex of the key's Ed25519 public key.
        endpoint_id: String,
    },
    /// The endpoint's home relay and whether it is connected.
    Relay {
        /// The home relay URL, or `None` before one is chosen.
        home_relay: Option<String>,
        /// Whether the endpoint is connected to it.
        connected: bool,
        /// Sanitized first line of iroh's error text; omitted when there is none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// A connection's selected path.
    Path {
        /// The peer's endpoint id, lowercase hex.
        endpoint_id: String,
        /// Relay or direct.
        kind: PathKind,
        /// The relay URL, or `None` for a direct path.
        relay: Option<String>,
    },
    /// A connection that had a `path` ended, however it ended. Sent once per
    /// such connection, after its last `path`.
    Closed {
        /// The peer's endpoint id, lowercase hex.
        endpoint_id: String,
    },
    /// A connection or stream the helper refused.
    Refused {
        /// Why.
        reason: RefusedReason,
        /// The peer's endpoint id, or `None` where it is not known.
        endpoint_id: Option<String>,
    },
    /// A diagnostic for the daemon's log.
    Log {
        /// Info or warn.
        level: LogLevel,
        /// At most [`MAX_TEXT_BYTES`]; never key material, never stream contents.
        message: String,
    },
    /// Fatal: the helper exits 1 after sending it.
    Error {
        /// The closed-set code.
        code: ErrorCode,
        /// At most [`MAX_TEXT_BYTES`].
        message: String,
    },
    /// A dial's stream is open and connected to its socket.
    Dialed {
        /// The daemon's id for the dial.
        dial_id: String,
        /// The connection's selected path when the stream opened.
        kind: PathKind,
        /// The relay URL, or `None` for a direct path.
        relay: Option<String>,
    },
    /// A dial ended without a stream.
    DialFailed {
        /// The daemon's id for the dial.
        dial_id: String,
        /// Why.
        reason: DialFailure,
    },
    /// A dialed stream ended, however it ended.
    DialClosed {
        /// The daemon's id for the dial.
        dial_id: String,
    },
}

impl Event {
    /// The `hello` line for this build.
    pub fn hello() -> Self {
        Event::Hello {
            protocol_version: PROTOCOL_VERSION,
            helper_version: crate::VERSION.to_string(),
            iroh_version: crate::IROH_VERSION.to_string(),
        }
    }

    /// A `log` event, its message capped at [`MAX_TEXT_BYTES`].
    pub fn log(level: LogLevel, message: &str) -> Self {
        Event::Log {
            level,
            message: cap_text(message),
        }
    }

    /// An `error` event, its message capped at [`MAX_TEXT_BYTES`].
    pub fn error(code: ErrorCode, message: &str) -> Self {
        Event::Error {
            code,
            message: cap_text(message),
        }
    }

    /// The compact NDJSON line for this event, trailing `\n` included.
    pub fn to_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut line = serde_json::to_vec(self)?;
        line.push(b'\n');
        Ok(line)
    }
}

/// One relay as the daemon names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySpec {
    /// An `https` relay URL.
    pub url: String,
    /// The relay's QUIC address-discovery port.
    pub quic_port: u16,
}

/// The bounds the daemon sets on the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Concurrent iroh connections.
    pub max_connections: u32,
    /// Concurrent bidirectional streams on one connection.
    pub max_streams_per_connection: u32,
    /// QUIC per-stream receive window, bytes.
    pub stream_receive_window: u64,
    /// QUIC per-connection receive window, bytes.
    pub connection_receive_window: u64,
    /// QUIC send window, bytes.
    pub send_window: u64,
}

/// Frames the daemon sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Read the key (or make one in memory), bind the endpoint, answer `ready`.
    Start {
        /// Absolute path to the 32-byte, mode-0600 key file; absent, with
        /// `bridge_socket`, for an endpoint that only dials.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present"
        )]
        secret_key_path: Option<String>,
        /// Absolute path to the daemon's bridge socket; absent, with
        /// `secret_key_path`, for an endpoint that only dials.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present"
        )]
        bridge_socket: Option<String>,
        /// The one application protocol to accept.
        alpn: String,
        /// The relays the endpoint uses, and only these.
        relays: Vec<RelaySpec>,
        /// Connection, stream and window bounds.
        limits: Limits,
    },
    /// Replace the endpoint's relay map.
    SetRelays {
        /// The new relay map.
        relays: Vec<RelaySpec>,
    },
    /// Close a peer's connections once their streams have ended: its session
    /// failed before `hello` or a pair request.
    Close {
        /// The peer's endpoint id, lowercase hex.
        endpoint_id: String,
    },
    /// Dial a peer, open one stream, connect it to `socket` and copy both ways.
    Dial {
        /// The daemon's id for this dial, named in its events.
        dial_id: String,
        /// The peer's endpoint id, lowercase hex.
        endpoint_id: String,
        /// The peer's relays.
        relays: Vec<RelaySpec>,
        /// Absolute path to the Unix socket the daemon listens on for this dial.
        socket: String,
        /// Direct UDP addresses (`ip:port`) to try besides the relays.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present"
        )]
        addrs: Option<Vec<String>>,
    },
    /// Close everything and exit 0. A struct variant, so an unknown field on it
    /// is refused like on every other op.
    Shutdown {},
}

/// A line the daemon sent that this helper cannot honour.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    /// Not a well-typed op.
    #[error("malformed op: {0}")]
    Malformed(String),
    /// Well-typed, but a value is outside the contract.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

impl RequestError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        RequestError::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

/// Decode one control line (newline already stripped) into an [`Op`].
pub fn decode_op(line: &str) -> Result<Op, RequestError> {
    serde_json::from_str(line).map_err(|e| RequestError::Malformed(e.to_string()))
}

/// An optional field that is present: `null` is refused, as the contract's
/// optional fields are absent, never `null`. With `#[serde(default)]`, an absent
/// field is `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Validate a peer's endpoint id: 64 lowercase hex digits, as iroh displays it
/// and the daemon reads it from a preamble, naming an Ed25519 public key.
pub fn validate_endpoint_id(raw: &str) -> Result<EndpointId, RequestError> {
    let hex = raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !hex {
        return Err(RequestError::invalid(
            "endpoint_id",
            "not 64 lowercase hex digits",
        ));
    }
    raw.parse()
        .map_err(|_| RequestError::invalid("endpoint_id", "not an Ed25519 public key"))
}

/// One validated relay: a parsed `https` URL and its QUIC port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// The relay's URL.
    pub url: RelayUrl,
    /// Its QUIC address-discovery port, never 0.
    pub quic_port: u16,
}

/// What a listening endpoint needs: its key and where to bridge its streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    /// Absolute key file path.
    pub secret_key_path: PathBuf,
    /// Absolute bridge socket path.
    pub bridge_socket: PathBuf,
}

/// A validated `start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartConfig {
    /// The key and the bridge socket, or `None` for an endpoint that only
    /// dials, with a key held in memory.
    pub listen: Option<Listen>,
    /// The accepted ALPN, as bytes.
    pub alpn: Vec<u8>,
    /// The peer kind written in every bridge preamble.
    pub kind: u8,
    /// The relay map.
    pub relays: Vec<Relay>,
    /// The bounds, each within its contract range.
    pub limits: ValidLimits,
}

/// [`Limits`] after range checks, in the widths the endpoint uses them at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidLimits {
    /// Concurrent iroh connections, 1 to 1,024.
    pub max_connections: usize,
    /// Concurrent bidirectional streams per connection, 1 to 16.
    pub max_streams_per_connection: u32,
    /// Per-stream receive window, 64 KiB to 16 MiB.
    pub stream_receive_window: u32,
    /// Per-connection receive window, 64 KiB to 16 MiB.
    pub connection_receive_window: u32,
    /// Send window, 64 KiB to 16 MiB.
    pub send_window: u64,
}

impl StartConfig {
    /// Validate the fields of a `start` op. `secret_key_path` and
    /// `bridge_socket` come together or not at all.
    pub fn validate(
        secret_key_path: Option<&str>,
        bridge_socket: Option<&str>,
        alpn: &str,
        relays: &[RelaySpec],
        limits: &Limits,
    ) -> Result<Self, RequestError> {
        let kind = kind_for_alpn(alpn.as_bytes()).ok_or_else(|| {
            RequestError::invalid("alpn", format!("only {ALPN_MOBILE} is accepted"))
        })?;
        Ok(StartConfig {
            listen: validate_listen(secret_key_path, bridge_socket)?,
            alpn: alpn.as_bytes().to_vec(),
            kind,
            relays: validate_relays(relays)?,
            limits: validate_limits(limits)?,
        })
    }
}

fn validate_listen(
    secret_key_path: Option<&str>,
    bridge_socket: Option<&str>,
) -> Result<Option<Listen>, RequestError> {
    match (secret_key_path, bridge_socket) {
        (Some(key), Some(socket)) => Ok(Some(Listen {
            secret_key_path: absolute_path("secret_key_path", key)?,
            bridge_socket: socket_path("bridge_socket", socket)?,
        })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(RequestError::invalid(
            "bridge_socket",
            "secret_key_path and bridge_socket come together",
        )),
        (None, Some(_)) => Err(RequestError::invalid(
            "secret_key_path",
            "secret_key_path and bridge_socket come together",
        )),
    }
}

/// A validated `dial`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialConfig {
    /// The daemon's id for the dial.
    pub dial_id: String,
    /// The peer to dial.
    pub peer: EndpointId,
    /// The peer's relays.
    pub relays: Vec<Relay>,
    /// The daemon's socket for this dial.
    pub socket: PathBuf,
    /// Direct UDP addresses to try besides the relays.
    pub addrs: Vec<SocketAddr>,
}

impl DialConfig {
    /// Validate the fields of a `dial` op.
    pub fn validate(
        dial_id: &str,
        endpoint_id: &str,
        relays: &[RelaySpec],
        socket: &str,
        addrs: Option<&[String]>,
    ) -> Result<Self, RequestError> {
        Ok(DialConfig {
            dial_id: validate_dial_id(dial_id)?,
            peer: validate_endpoint_id(endpoint_id)?,
            relays: validate_relays(relays)?,
            socket: socket_path("socket", socket)?,
            addrs: validate_addrs(addrs.unwrap_or_default())?,
        })
    }
}

/// A dial id: 1 to 64 of `a`–`z`, `0`–`9`, `-` and `_`.
pub fn validate_dial_id(raw: &str) -> Result<String, RequestError> {
    let shaped = (1..=DIAL_ID_MAX_BYTES).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'));
    if !shaped {
        return Err(RequestError::invalid(
            "dial_id",
            format!("not 1 to {DIAL_ID_MAX_BYTES} of a-z, 0-9, - and _"),
        ));
    }
    Ok(raw.to_string())
}

fn validate_addrs(addrs: &[String]) -> Result<Vec<SocketAddr>, RequestError> {
    if addrs.len() > DIAL_ADDRS_MAX {
        return Err(RequestError::invalid(
            "addrs",
            format!("{} entries, at most {DIAL_ADDRS_MAX}", addrs.len()),
        ));
    }
    addrs
        .iter()
        .map(|raw| {
            raw.parse::<SocketAddr>()
                .ok()
                .filter(|addr| addr.port() != 0)
                .ok_or_else(|| RequestError::invalid("addrs", format!("{raw} is not ip:port")))
        })
        .collect()
}

/// Validate a relay list: one to eight distinct `https` URLs with non-zero ports.
pub fn validate_relays(relays: &[RelaySpec]) -> Result<Vec<Relay>, RequestError> {
    if !(RELAYS_MIN..=RELAYS_MAX).contains(&relays.len()) {
        return Err(RequestError::invalid(
            "relays",
            format!(
                "{} entries, expected {RELAYS_MIN} to {RELAYS_MAX}",
                relays.len()
            ),
        ));
    }
    let mut out: Vec<Relay> = Vec::with_capacity(relays.len());
    for spec in relays {
        let relay = validate_relay(spec)?;
        if out.iter().any(|seen| seen.url == relay.url) {
            return Err(RequestError::invalid(
                "relays",
                format!("{} is named twice", relay.url),
            ));
        }
        out.push(relay);
    }
    Ok(out)
}

fn validate_relay(spec: &RelaySpec) -> Result<Relay, RequestError> {
    let url: RelayUrl = spec
        .url
        .parse()
        .map_err(|_| RequestError::invalid("relays.url", "not a URL"))?;
    if url.scheme() != "https" {
        return Err(RequestError::invalid("relays.url", "scheme must be https"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(RequestError::invalid("relays.url", "no host"));
    }
    if spec.quic_port == 0 {
        return Err(RequestError::invalid("relays.quic_port", "must not be 0"));
    }
    Ok(Relay {
        url,
        quic_port: spec.quic_port,
    })
}

fn validate_limits(limits: &Limits) -> Result<ValidLimits, RequestError> {
    Ok(ValidLimits {
        max_connections: narrow(
            "limits.max_connections",
            u64::from(limits.max_connections),
            widen(MAX_CONNECTIONS_RANGE),
        )?,
        max_streams_per_connection: narrow(
            "limits.max_streams_per_connection",
            u64::from(limits.max_streams_per_connection),
            widen(MAX_STREAMS_RANGE),
        )?,
        stream_receive_window: narrow(
            "limits.stream_receive_window",
            limits.stream_receive_window,
            WINDOW_RANGE,
        )?,
        connection_receive_window: narrow(
            "limits.connection_receive_window",
            limits.connection_receive_window,
            WINDOW_RANGE,
        )?,
        send_window: narrow("limits.send_window", limits.send_window, WINDOW_RANGE)?,
    })
}

fn widen((lo, hi): (u32, u32)) -> (u64, u64) {
    (u64::from(lo), u64::from(hi))
}

/// Check `value` against its contract range and convert it to the width the
/// endpoint uses. Every range fits every target width, so a conversion failure
/// is reported as the same out-of-range error.
fn narrow<T: TryFrom<u64>>(
    field: &'static str,
    value: u64,
    (lo, hi): (u64, u64),
) -> Result<T, RequestError> {
    let out_of_range = || RequestError::invalid(field, format!("{value} is outside {lo} to {hi}"));
    if !(lo..=hi).contains(&value) {
        return Err(out_of_range());
    }
    T::try_from(value).map_err(|_| out_of_range())
}

fn absolute_path(field: &'static str, raw: &str) -> Result<PathBuf, RequestError> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(RequestError::invalid(field, "must be an absolute path"));
    }
    Ok(path.to_path_buf())
}

fn socket_path(field: &'static str, raw: &str) -> Result<PathBuf, RequestError> {
    let path = absolute_path(field, raw)?;
    // A path the OS cannot hold in a sockaddr_un would fail every stream as
    // bridge_unreachable; refuse it once, here, instead.
    std::os::unix::net::SocketAddr::from_pathname(&path)
        .map_err(|e| RequestError::invalid(field, e.to_string()))?;
    Ok(path)
}

/// Cap `text` at [`MAX_TEXT_BYTES`], cutting on a character boundary.
pub fn cap_text(text: &str) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text.to_string();
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_connections: 64,
            max_streams_per_connection: 4,
            stream_receive_window: 262_144,
            connection_receive_window: 1_048_576,
            send_window: 1_048_576,
        }
    }

    fn relay(url: &str) -> RelaySpec {
        RelaySpec {
            url: url.into(),
            quic_port: 7842,
        }
    }

    fn start(relays: &[RelaySpec], limits: &Limits) -> Result<StartConfig, RequestError> {
        StartConfig::validate(
            Some("/k/iroh_key"),
            Some("/k/bridge.sock"),
            ALPN_MOBILE,
            relays,
            limits,
        )
    }

    fn validate(key: &str, socket: &str, alpn: &str) -> Result<StartConfig, RequestError> {
        let relays = [relay("https://r.example/")];
        StartConfig::validate(Some(key), Some(socket), alpn, &relays, &limits())
    }

    const PEER: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

    fn dial(id: &str, socket: &str, addrs: Option<&[String]>) -> Result<DialConfig, RequestError> {
        DialConfig::validate(id, PEER, &[relay("https://r.example/")], socket, addrs)
    }

    #[test]
    fn a_contract_start_validates() {
        let cfg = start(&[relay("https://us1.relay.fermix.ai/")], &limits()).unwrap();
        assert_eq!(cfg.kind, KIND_PHONE);
        assert_eq!(
            cfg.listen,
            Some(Listen {
                secret_key_path: PathBuf::from("/k/iroh_key"),
                bridge_socket: PathBuf::from("/k/bridge.sock"),
            })
        );
        assert_eq!(cfg.alpn, b"fermix/mobile/1");
        assert_eq!(
            cfg.relays[0].url.to_string(),
            "https://us1.relay.fermix.ai/"
        );
    }

    #[test]
    fn relay_counts_outside_one_to_eight_are_refused() {
        assert!(start(&[], &limits()).is_err());
        let nine: Vec<_> = (0..9)
            .map(|i| relay(&format!("https://r{i}.example/")))
            .collect();
        assert!(start(&nine, &limits()).is_err());
        assert!(start(&nine[..8], &limits()).is_ok());
    }

    #[test]
    fn a_relay_must_be_https_with_a_port_and_named_once() {
        assert!(start(&[relay("http://r.example/")], &limits()).is_err());
        assert!(start(&[relay("not a url")], &limits()).is_err());
        let zero = RelaySpec {
            url: "https://r.example/".into(),
            quic_port: 0,
        };
        assert!(start(&[zero], &limits()).is_err());
        let twice = [relay("https://r.example/"), relay("https://r.example")];
        assert!(start(&twice, &limits()).is_err());
    }

    #[test]
    fn every_limit_is_held_to_its_range() {
        type Case = (fn(&mut Limits, u64), u64, u64);
        let cases: [Case; 5] = [
            (|l, v| l.max_connections = v as u32, 1, 1024),
            (|l, v| l.max_streams_per_connection = v as u32, 1, 16),
            (|l, v| l.stream_receive_window = v, 65_536, 16_777_216),
            (|l, v| l.connection_receive_window = v, 65_536, 16_777_216),
            (|l, v| l.send_window = v, 65_536, 16_777_216),
        ];
        let relays = [relay("https://r.example/")];
        for (set, lo, hi) in cases {
            for (value, ok) in [(lo - 1, false), (lo, true), (hi, true), (hi + 1, false)] {
                let mut l = limits();
                set(&mut l, value);
                assert_eq!(start(&relays, &l).is_ok(), ok, "{l:?}");
            }
        }
    }

    #[test]
    fn paths_must_be_absolute_and_the_socket_must_fit_a_sockaddr() {
        assert!(validate("k", "/s", ALPN_MOBILE).is_err());
        assert!(validate("/k", "s", ALPN_MOBILE).is_err());
        let long = format!("/{}", "s".repeat(200));
        assert!(validate("/k", &long, ALPN_MOBILE).is_err());
    }

    #[test]
    fn a_start_without_key_and_socket_only_dials_and_one_without_the_other_is_refused() {
        let relays = [relay("https://r.example/")];
        let dial_only = StartConfig::validate(None, None, ALPN_MOBILE, &relays, &limits());
        assert_eq!(dial_only.unwrap().listen, None);
        for (key, socket, field) in [
            (Some("/k"), None, "bridge_socket"),
            (None, Some("/s"), "secret_key_path"),
        ] {
            let half = StartConfig::validate(key, socket, ALPN_MOBILE, &relays, &limits());
            assert!(
                matches!(&half, Err(RequestError::Invalid { field: f, .. }) if *f == field),
                "{half:?}"
            );
        }
    }

    #[test]
    fn optional_fields_are_absent_never_null() {
        let dial_only = r#"{"op":"start","alpn":"fermix/mobile/1","relays":[{"url":"https://r/","quic_port":1}],"limits":{"max_connections":1,"max_streams_per_connection":1,"stream_receive_window":65536,"connection_receive_window":65536,"send_window":65536}}"#;
        assert!(matches!(
            decode_op(dial_only),
            Ok(Op::Start {
                secret_key_path: None,
                bridge_socket: None,
                ..
            })
        ));
        let null_key = dial_only.replace(
            r#""alpn""#,
            r#""secret_key_path":null,"bridge_socket":"/s","alpn""#,
        );
        assert!(matches!(
            decode_op(&null_key),
            Err(RequestError::Malformed(_))
        ));
        let null_addrs = format!(
            r#"{{"op":"dial","dial_id":"a","endpoint_id":"{PEER}","relays":[],"socket":"/s","addrs":null}}"#
        );
        assert!(matches!(
            decode_op(&null_addrs),
            Err(RequestError::Malformed(_))
        ));
    }

    #[test]
    fn a_contract_dial_validates() {
        let addrs = ["127.0.0.1:4100".to_string(), "[::1]:4100".to_string()];
        let cfg = dial("5f1c9a2e", "/k/dial-5f1c9a2e.sock", Some(&addrs)).unwrap();
        assert_eq!(cfg.dial_id, "5f1c9a2e");
        assert_eq!(cfg.peer.to_string(), PEER);
        assert_eq!(cfg.socket, PathBuf::from("/k/dial-5f1c9a2e.sock"));
        assert_eq!(cfg.addrs.len(), 2);
        assert!(dial("a", "/s", None).unwrap().addrs.is_empty());
    }

    #[test]
    fn a_dial_outside_the_contract_is_refused() {
        let long = "d".repeat(DIAL_ID_MAX_BYTES + 1);
        for id in ["", "Upper", "with space", "dot.ted", long.as_str()] {
            assert!(dial(id, "/s", None).is_err(), "{id:?}");
        }
        assert!(dial(&"d".repeat(DIAL_ID_MAX_BYTES), "/s", None).is_ok());
        assert!(dial("a", "relative.sock", None).is_err());
        assert!(dial("a", &format!("/{}", "s".repeat(200)), None).is_err());
        for bad in ["localhost:1", "127.0.0.1", "127.0.0.1:0", "nope"] {
            assert!(dial("a", "/s", Some(&[bad.to_string()])).is_err(), "{bad}");
        }
        let nine: Vec<String> = (1..=9).map(|p| format!("127.0.0.1:{p}")).collect();
        assert!(dial("a", "/s", Some(&nine)).is_err());
        assert!(dial("a", "/s", Some(&nine[..8])).is_ok());
        let none = DialConfig::validate("a", PEER, &[], "/s", None);
        assert!(none.is_err(), "a dial names one to eight relays");
        let bad_peer = DialConfig::validate("a", "79B5", &[relay("https://r/")], "/s", None);
        assert!(bad_peer.is_err());
    }

    #[test]
    fn only_the_mobile_alpn_is_accepted() {
        let other = validate("/k", "/s", "other/1");
        assert!(other.is_err());
        assert_eq!(kind_for_alpn(b"fermix/mobile/1"), Some(0x01));
        assert_eq!(kind_for_alpn(b"fermix/mobile/2"), None);
    }

    #[test]
    fn unknown_ops_fields_and_wrong_types_are_malformed() {
        for line in [
            "",
            "[]",
            "\"shutdown\"",
            "{}",
            "{\"op\":\"reboot\"}",
            "{\"op\":\"shutdown\",\"now\":true}",
            "{\"op\":\"set_relays\",\"relays\":[{\"url\":\"https://r/\",\"quic_port\":\"7842\"}]}",
            "{\"op\":\"set_relays\",\"relays\":[{\"url\":\"https://r/\",\"quic_port\":70000}]}",
            "{\"op\":\"set_relays\"}",
            "{\"op\":\"close\"}",
            "{\"op\":\"close\",\"endpoint_id\":7}",
            "{\"op\":\"dial\",\"dial_id\":\"a\"}",
            "{\"op\":\"dial\",\"dial_id\":\"a\",\"endpoint_id\":\"x\",\"relays\":[],\"socket\":\"/s\",\"via\":\"x\"}",
            "{\"event\":\"hello\"}",
        ] {
            assert!(
                matches!(decode_op(line), Err(RequestError::Malformed(_))),
                "{line:?}"
            );
        }
    }

    #[test]
    fn an_endpoint_id_is_64_lowercase_hex_digits_of_a_public_key() {
        let id = iroh::SecretKey::from_bytes(&[7; 32]).public();
        assert_eq!(validate_endpoint_id(&id.to_string()), Ok(id));
        for raw in [
            id.to_string().to_uppercase(),
            id.to_string()[..62].to_string(),
            format!("{id}00"),
            format!("{}g", &id.to_string()[..63]),
        ] {
            assert!(validate_endpoint_id(&raw).is_err(), "{raw}");
        }
        // y = 2 has no x on the curve: hex-shaped, but no public key.
        let off_curve = format!("02{}", "00".repeat(31));
        assert_eq!(
            validate_endpoint_id(&off_curve),
            Err(RequestError::invalid(
                "endpoint_id",
                "not an Ed25519 public key"
            ))
        );
    }

    #[test]
    fn text_is_capped_on_a_character_boundary() {
        let short = "x".repeat(MAX_TEXT_BYTES);
        assert_eq!(cap_text(&short), short);
        let multibyte = "é".repeat(MAX_TEXT_BYTES);
        let capped = cap_text(&multibyte);
        assert!(capped.len() <= MAX_TEXT_BYTES);
        assert_eq!(capped.len(), MAX_TEXT_BYTES);
        let odd = format!("x{}", "é".repeat(MAX_TEXT_BYTES));
        assert_eq!(cap_text(&odd).len(), MAX_TEXT_BYTES - 1);
    }
}
