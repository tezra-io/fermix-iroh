# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

The wire `protocol_version` is versioned separately from this crate; see
`protocol/PROTOCOL.md`.

## [Unreleased]

## [0.1.0] - 2026-10-23

First version. Implements `protocol_version` 1 against iroh 1.3.0.

### Added

- NDJSON helper over stdin/stdout: `hello`, `ready`, `relay`, `path`, `closed`,
  `refused`, `log`, `error` out; `start`, `set_relays`, `shutdown` in. Lines are
  at most 64 KiB; a longer line, a line that is not an op, an unknown op or
  field, or a field of the wrong type ends the helper with `bad_request`.
- One iroh endpoint from the `Minimal` preset with exactly the daemon's relays,
  no address lookup service, no proxy, and DNS through the system's nameservers
  only (iroh's public fallback resolvers off).
- The daemon's limits as QUIC transport parameters: bidirectional stream credit,
  stream and connection receive windows, send window; no unidirectional streams
  and no datagrams. Connections over `max_connections` are refused before their
  handshake and reported as `refused` `busy`; a foreign ALPN is refused in the
  TLS handshake and reported as `refused` `alpn`.
- The bridge: one Unix-socket connection per accepted stream, the 37-byte `FXB1`
  preamble with the peer's kind and endpoint id, then a 64 KiB-per-direction
  copy that ends each side as the contract's *Ending* list says; an unreachable
  bridge resets the stream with code 2 and is reported as `refused`
  `bridge_unreachable`.
- `relay` events for the home relay and its connection state, `path` events for
  each connection's selected path, and `closed` once per connection that had a
  `path`. Relay error text is reduced to its first line, stripped of URL
  credentials and capped at 512 bytes.
- `set_relays` replaces the relay map at run time.
- Shutdown (the op or end of stdin) closes every connection with code 0, reason
  `shutdown`, closes every bridge connection, waits for iroh's drain, and exits
  0 within 5 s. Fatal errors exit 1 within 2 s of their `error` event; a panic
  in any thread exits 101.
- The key file must be exactly 32 bytes, mode `0600`, a regular file:
  otherwise `key_invalid`; a file that cannot be opened is `key_unreadable`.
- Hermetic tests: the fixture round trip, framing property tests, the binary
  over real pipes, and end-to-end sessions over an in-process local relay.
- CI (fmt, clippy, build, test on macOS arm64 and Linux; the macOS x86_64 and
  Linux musl cross builds) and a tagged release workflow building four targets,
  Developer ID signing and notarization for both macOS binaries, sha256
  sidecars, cosign signatures, and publishing behind the `release`
  environment's approval.
