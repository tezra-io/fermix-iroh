//! The Fermix daemon's iroh endpoint.
//!
//! `fermix-iroh` binds one iroh endpoint with the daemon's key and relays,
//! accepts connections on one ALPN, and copies each accepted bidirectional
//! stream to one connection on the daemon's Unix bridge socket. It holds no
//! trust of its own and decides nothing: the daemon authenticates every peer
//! through the mobile protocol's Noise session.
//!
//! The wire contract is `protocol/PROTOCOL.md`, vendored from the daemon.

pub mod bridge;
pub mod endpoint;
pub mod key;
pub mod ndjson;
pub mod protocol;
pub mod session;
pub mod shutdown;
pub mod status;

/// This helper's version, sent in `hello`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The iroh version this helper is built against, sent in `hello`. A test pins
/// it to the version `Cargo.lock` resolves.
pub const IROH_VERSION: &str = "1.3.0";
