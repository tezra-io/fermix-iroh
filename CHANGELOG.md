# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

The wire `protocol_version` is versioned separately from this crate; see
`protocol/PROTOCOL.md`.

## [Unreleased]

## [0.2.2] - 2026-10-25

A full helper makes room for a new connection instead of refusing it. Still
`protocol_version` 2, with no new op, event or field, so the engine takes it
with a pin bump alone.

### Fixed

- When every `max_connections` place is taken, a new connection takes the
  place of the connection that has gone longest with no stream open (since it
  was accepted, or since its last stream ended; one still in its handshake
  included), which is closed with code `0`, reason `room`, or its handshake
  dropped. A new connection is refused `busy` only when no connection can make
  way. A stranger who opened about 26 connections a second with no stream
  used to hold all 1,024 places, so every phone that reconnected was refused
  before its handshake, where the daemon's bridge could not make room for it.
  Keeping a phone out now takes about 200 new connections a second, each with
  a finished handshake and a stream: the daemon serves 64 streams at once, and
  a stream it has closed stays open only for the 5 s its peer has to
  acknowledge. A connection loses its place only while it has no stream open,
  decided under the lock that counts a stream it accepts, and keeps it while
  the helper waits for the daemon to read an event about it, so a daemon that
  stops reading gets `busy` refusals rather than a task left behind per new
  connection. Making room is reported to the daemon's log as a `log` warning
  at the 1st, 10th, 100th… time; when the daemon's `close` and a newer
  connection land together, the close still reads `refused`.

### Changed

- `protocol/` is re-vendored from fermix 40f7910c, whose contract states the
  rule above.
- The end-to-end busy test keeps its bridge connection open, so its first
  connection holds its place by having a stream open, as the rule now
  requires. The two new end-to-end tests wait for the helper's `path` of the
  connection that makes way before the next dial: until the helper has
  finished that handshake, it drops the handshake instead of closing the
  connection `room`. No test reaches a handshake dropped this way: that needs
  a peer that stalls mid-handshake, which the harness cannot make yet.

## [0.2.1] - 2026-10-25

Fixes a stream a peer could hold open by giving it no flow-control credit,
found by a review of 0.2.0 on 2026-10-25. Still `protocol_version` 2, with no
new op or field, so the engine takes it with a pin bump alone.

### Fixed

- Once the daemon closes the bridge, the peer has at most 5 s to take what the
  daemon wrote and acknowledge it, whatever flow-control credit it gives; the
  helper then resets the stream with code `0`. The 5 s used to cover only the
  acknowledgement: sending the daemon's last bytes waited on the peer's credit
  with no bound, so a peer that gave a stream none and stayed silent held the
  stream open, and neither `close` nor the 30 s idle bound closed its
  connection. 1,024 such connections, opened once, held every
  `max_connections` place for as long as their peers answered keep-alives.
  Every earlier version had the same hole. The helper now reads the bridge
  while a write waits on the peer, into the same 64 KiB buffer, so it sees the
  daemon's close at once unless 64 KiB or more of the daemon's bytes are still
  unsent.

### Changed

- `protocol/` is re-vendored from fermix b6281f72: the contract states the
  bound above, the `start` example's `max_connections` is 1,024, and the bridge
  section describes the daemon's own bound on bridge connections.
- Two end-to-end tests of `close` wait until the refusal has reached the
  connection before they open the next stream, and the relay TLS test accepts
  only the eMudhra intermediates' distrust, not an unknown issuer.
- The release dry run's refusal of a tag without notices names v0.2.0, not
  v0.1.1, which was never tagged.

## [0.2.0] - 2026-10-25

Implements `protocol_version` 2, which adds the daemon's `close`. An engine
that speaks version 1 refuses this helper, so the engine pins it in the same
change that moves the engine to version 2. Fixes three findings of the
2026-10-25 security review.

### Added

- `close`: when a session ends before `hello` or a pair request, the daemon
  names the peer, and the helper resets every further stream on its
  connections with code `0` and closes each connection with code `0`, reason
  `refused`, once its open streams have ended. A peer could otherwise keep one
  of `max_connections` by opening stream after stream that fails its
  handshake.

### Changed

- A stream the daemon ended counts as open until the peer has acknowledged its
  last bytes, for at most 5 s, so when `close` ends a connection, the daemon's
  close frame is never cut off.
- CI no longer refuses every pull request that changes `protocol/`, which
  included each legitimate re-vendor. `PROTOCOL_SOURCE` names the fermix commit
  `protocol/` comes from, and a pull request that changes either fails unless
  that commit is on a fermix branch and `protocol/` is its export byte for
  byte, in regular files only.

### Security

- Relay TLS no longer trusts the eMudhra intermediates whose private keys can
  be recovered from their certificates (RUSTSEC-2026-0381, RUSTSEC-2026-0382):
  rustls-webpki 0.103.16 and webpki-roots 1.0.11. webpki-root-certs 1.0.11
  (RUSTSEC-2026-0383, compiled for no release target) and ctutils 0.4.5
  (RUSTSEC-2026-0385, whose affected functions iroh never calls) move too.
  An attacker on the path to a relay could have impersonated it; iroh's own
  end-to-end authentication kept the phone's traffic private regardless.
- The release's sign job takes exactly the expected files from each build job,
  each from its own artifact, and writes every `.sha256` itself. It used to
  merge every artifact into one directory, where one build job could replace
  another's binary or add an unsigned file to the release.

## [0.1.1] - 2026-10-25

No change in behaviour: the release now also carries the licences of
everything the binaries are built from.

### Added

- `THIRD-PARTY-NOTICES.txt`, one file for all four targets: fermix-iroh's
  licence, the Rust project's notice for the standard library, the
  `LICENSE.TXT` of LLVM 22.1.6's compiler-rt (every binary, through the
  standard library's compiler_builtins) and libunwind (Linux binaries), musl
  1.2.5's `COPYRIGHT` (Linux binaries), and every crate a target compiles in
  with its version, licence expression and licence texts.
  `notices/generate.sh` writes it with cargo-about 0.9.2 and names the eight
  crates allowed on a licence's standard text, which the file lists with
  their authors and repository; `notices/about.toml` accepts exactly the
  licences in the graph, MPL-2.0 for attohttpc alone, and pins every
  clarification by checksum. attohttpc's notice names its source on
  crates.io, with the sha256 `Cargo.lock` pins, and its repository.
- Every release tarball holds `THIRD-PARTY-NOTICES.txt`, and each release
  publishes it once as `fermix-iroh-THIRD-PARTY-NOTICES.txt` with a `.sha256`,
  `.sig` and `.pem`, listed in `SHA256SUMS`.
- CI regenerates the file and fails when the committed one differs; the
  release refuses a missing or stale one before it builds.

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
