//! Wire types for the Fermix iroh helper protocol.
//!
//! The contract is defined by the daemon and vendored into this repo at
//! `protocol/PROTOCOL.md`, with byte-exact samples in `protocol/fixtures/`.
//! Nothing in this module may drift from those files: `tests/fixtures.rs`
//! round-trips every fixture through these types and compares bytes.
//!
//! Decoding is strict. A line that is not a JSON object, an unknown `op`, a
//! missing field, an unknown field or a field of the wrong type is a decode
//! error; a well-typed `start` or `set_relays` whose values are out of range is
//! a validation error. Both end the helper with `bad_request`.

use std::path::{Path, PathBuf};

use iroh::RelayUrl;
use serde::{Deserialize, Serialize};

/// The single integer version carried in `hello`. Pinned to `protocol/PROTOCOL.md`.
pub const PROTOCOL_VERSION: u32 = 1;

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
    /// Over `limits.max_connections`; refused before its handshake.
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
    /// Read the key, bind the endpoint, answer `ready`.
    Start {
        /// Absolute path to the 32-byte, mode-0600 key file.
        secret_key_path: String,
        /// Absolute path to the daemon's bridge socket.
        bridge_socket: String,
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

/// One validated relay: a parsed `https` URL and its QUIC port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// The relay's URL.
    pub url: RelayUrl,
    /// Its QUIC address-discovery port, never 0.
    pub quic_port: u16,
}

/// A validated `start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartConfig {
    /// Absolute key file path.
    pub secret_key_path: PathBuf,
    /// Absolute bridge socket path.
    pub bridge_socket: PathBuf,
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
    /// Validate the fields of a `start` op.
    pub fn validate(
        secret_key_path: &str,
        bridge_socket: &str,
        alpn: &str,
        relays: &[RelaySpec],
        limits: &Limits,
    ) -> Result<Self, RequestError> {
        let kind = kind_for_alpn(alpn.as_bytes()).ok_or_else(|| {
            RequestError::invalid("alpn", format!("only {ALPN_MOBILE} is accepted"))
        })?;
        Ok(StartConfig {
            secret_key_path: absolute_path("secret_key_path", secret_key_path)?,
            bridge_socket: socket_path(bridge_socket)?,
            alpn: alpn.as_bytes().to_vec(),
            kind,
            relays: validate_relays(relays)?,
            limits: validate_limits(limits)?,
        })
    }
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

fn socket_path(raw: &str) -> Result<PathBuf, RequestError> {
    let path = absolute_path("bridge_socket", raw)?;
    // A path the OS cannot hold in a sockaddr_un would fail every stream as
    // bridge_unreachable; refuse it once, here, instead.
    std::os::unix::net::SocketAddr::from_pathname(&path)
        .map_err(|e| RequestError::invalid("bridge_socket", e.to_string()))?;
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
        StartConfig::validate("/k/iroh_key", "/k/bridge.sock", ALPN_MOBILE, relays, limits)
    }

    #[test]
    fn a_contract_start_validates() {
        let cfg = start(&[relay("https://us1.relay.fermix.ai/")], &limits()).unwrap();
        assert_eq!(cfg.kind, KIND_PHONE);
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
        let relays = [relay("https://r.example/")];
        let rel = StartConfig::validate("k", "/s", ALPN_MOBILE, &relays, &limits());
        assert!(rel.is_err());
        let rel = StartConfig::validate("/k", "s", ALPN_MOBILE, &relays, &limits());
        assert!(rel.is_err());
        let long = format!("/{}", "s".repeat(200));
        let long = StartConfig::validate("/k", &long, ALPN_MOBILE, &relays, &limits());
        assert!(long.is_err());
    }

    #[test]
    fn only_the_mobile_alpn_is_accepted() {
        let relays = [relay("https://r.example/")];
        let other = StartConfig::validate("/k", "/s", "other/1", &relays, &limits());
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
            "{\"event\":\"hello\"}",
        ] {
            assert!(
                matches!(decode_op(line), Err(RequestError::Malformed(_))),
                "{line:?}"
            );
        }
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
