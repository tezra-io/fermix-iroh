# fermix-iroh

The [Fermix](https://github.com/tezra-io/fermix) daemon's iroh endpoint. It lets a
paired phone reach the daemon from any network: the daemon spawns `fermix-iroh`
as a child process, speaks NDJSON with it over stdin/stdout, and the helper
binds one [iroh](https://github.com/n0-computer/iroh) endpoint with the daemon's
key and relays, accepts connections on one application protocol, and copies
each accepted stream to one connection on a Unix socket the daemon listens on.

| | |
|---|---|
| Wire | NDJSON on stdio, `protocol_version` 1 |
| iroh | `=1.3.0`, the `Minimal` preset, the daemon's relays only, no address lookup |
| Application protocol | `fermix/mobile/1`, a phone; anything else is refused in the TLS handshake |
| Bridge | one Unix-socket connection per stream: a 37-byte `FXB1` preamble, then the stream's bytes, unparsed |

## What it is not

- **Not a trust anchor.** The helper authorizes nothing. Every peer is
  authenticated by the daemon through the mobile protocol's Noise session; the
  iroh endpoint id the helper passes in the preamble is accounting metadata.
- **Not a router.** A peer names no socket, host, URL or method. Every stream
  goes to the one bridge socket the daemon named in `start`, and nowhere else.
- **Not a parser.** It never reads the bytes it copies; they are the daemon's
  length-prefixed Noise frames, bounded by the daemon.
- **Not a network client of anyone but the daemon's relays.** It binds UDP
  sockets for QUIC, asks the local router for a port mapping, probes only the
  relays the daemon names, and resolves their names through the system's
  configured nameservers only. It opens no listener, publishes nothing to an
  address lookup service, never uses n0's relays, and ignores proxy variables.
- **Not a writer of anything.** It reads one file, the key, and writes none.

## The protocol is not ours

`protocol/` is the daemon's export (`apps/fermix_core/priv/iroh_helper/` in the
fermix repository), vendored verbatim: `PROTOCOL.md` plus byte-exact
`fixtures/*`. **Do not edit anything under `protocol/`.** Fermix defines the
wire; this repo implements it, and the daemon refuses a mismatched `hello` and
ends the process.

`tests/fixtures.rs` holds this crate to those files: every fixture decodes into
this crate's types and re-encodes to the same bytes, trailing newline included;
no fixture is left untested; `PROTOCOL_VERSION` is parsed back out of
`PROTOCOL.md`; the crate's `hello` is `hello.json` byte for byte; the preamble
for the fixture peer is `bridge_preamble.bin`; and the fixture key (bytes
`01 02 … 20`) yields the fixture endpoint id. A rename or a type change on
either side fails CI before it ships, and CI refuses a pull request that edits
`protocol/` by hand.

Where the contract is silent, or iroh 1.3.0 needs more than the contract says to
meet it, the behaviour chosen is recorded in [`DEVIATIONS.md`](DEVIATIONS.md)
with evidence and proposed contract wording.

## Build and test

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

The suite is hermetic and offline once dependencies are fetched. The
integration tests run iroh's own relay server in-process on 127.0.0.1, bind the
helper and the phone-side test endpoints to loopback with port mapping off, and
listen on a fake bridge socket in a temporary directory; the binary-level tests
stop before the endpoint binds.

| Suite | What it pins |
|---|---|
| unit tests (`src/`) | validation ranges, key file checks, framing, text sanitizing, the connection bound |
| `tests/fixtures.rs` | the vendored contract, byte for byte |
| `tests/framing_props.rs` | property tests: arbitrary bytes never panic the reader or the decoder, no line exceeds 64 KiB, an over-long line is refused |
| `tests/process.rs` | the binary over real pipes: `hello` first, exit codes, every failure before bind |
| `tests/session.rs` | end to end over a local relay: preamble, copying both ways, every *Ending* rule, renewal on a second stream, stream credit, ALPN and busy refusals, unreachable bridge, `set_relays`, `closed`, shutdown within 5 s, end of stdin |

### Targets

Releases are built for four targets, all from `release.yml`:

| Target | Built on | Asset |
|---|---|---|
| `aarch64-apple-darwin` | macOS arm64 | `fermix-iroh-macos-aarch64` |
| `x86_64-apple-darwin` | macOS arm64, cross-compiled | `fermix-iroh-macos-x86_64` |
| `aarch64-unknown-linux-musl` | Linux arm64 | `fermix-iroh-linux-aarch64` |
| `x86_64-unknown-linux-musl` | Linux x86_64 | `fermix-iroh-linux-x86_64` |

The helper is Rust apart from the C and assembly that ring and blake3 compile
with the platform's own C compiler, so the Intel Mac binary needs no Intel
runner: `rustup target add x86_64-apple-darwin` and
`cargo build --release --target x86_64-apple-darwin` on an arm64 Mac. The Linux
binaries are static (musl), so one binary runs on every distribution the Linux
package supports; building them locally needs `musl-tools` (`musl-gcc`) and
`CC_<target>=musl-gcc`.

## How the engine uses it

- **Bundled, never downloaded at run time (M62 D3).** The engine's release
  build fetches the bare `fermix-iroh-<target>` binaries of one pinned tag,
  checks each against the `.sha256` sidecar and the cosign signature, and puts
  the helper in every release tree: the app-engine tarballs (and so the Mac
  app's notarized bundle), the formula, and the Linux packages.
- **Pinned, not ranged.** The engine pins a tag, each target's sha256, and the
  signing identity
  `https://github.com/tezra-io/fermix-iroh/.github/workflows/release.yml@refs/tags/<tag>`.
  The daemon also checks `hello`: `protocol_version` must be its own, and
  `iroh_version` must match the iroh version its relays run.
- **Spawned bare.** The daemon starts the helper with no arguments, in its own
  process group (through the `disclaim` exec shim on macOS), reads `hello`
  within 10 s, sends `start`, and treats any exit other than the contract's as
  a crash.

## Releasing

`fermix-iroh` and `fermix` are a paired change, as compux and fermix-stt are.

1. Bump the version in `Cargo.toml`, update `CHANGELOG.md`, and, if the wire
   moved, re-vendor `protocol/` from the engine in the same change. The fixture
   test fails until `hello.json` names this version.
2. Tag `vX.Y.Z` on `main`. `release.yml` builds the four targets, signs and
   notarizes both macOS binaries with the Developer ID certificate (the seven
   `MACOS_*`/`APPLE_*` secrets are mandatory; the run fails without them),
   writes a `.sha256` beside every artifact, signs every artifact with cosign
   (keyless), and waits in the `release` environment for the owner's approval
   before it publishes anything.
3. Pin the tag, the per-target sha256 values from `SHA256SUMS` and the signing
   identity in the engine by a normal PR. Never hand-write a checksum.
4. **Never re-run a published tag's release.** A rebuilt binary does not hash
   the same, so every engine pinning that tag would refuse it. Cut a new version.

## Architecture

```
src/
  main.rs       stdio wiring, proxy variables dropped, exit codes, panic = 101
  session.rs    the control loop: hello, start, set_relays, shutdown, errors
  ndjson.rs     64 KiB line reader, the stdout writer task and its event sink
  protocol.rs   wire types (+ the fixture round trip) and op validation
  key.rs        the 32-byte, mode-0600 key file
  endpoint.rs   Minimal preset, relay map, QUIC limits, accept loop, connections
  bridge.rs     preamble and the bounded two-way copy, with the Ending rules
  status.rs     relay and path watchers, sanitized error text
  shutdown.rs   the bounded graceful shutdown
```

One code path per behaviour: there is no runtime switch, no environment
override and no degraded mode. The test suite differs from the binary only in
the `Network` it passes (trust the test relay's certificate, bind loopback, no
port mapping), and the one constructor that trusts any certificate exists only
in test builds.

## License

MIT — see [LICENSE](LICENSE).
