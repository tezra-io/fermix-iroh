# Deviations and clarifications

`protocol/PROTOCOL.md` is the daemon's contract and this repository does not
edit it. This file records where implementing it against iroh 1.3.0 needed more
than the contract says, or where the contract is silent and a choice had to be
made. Each entry gives what the helper does, why, the evidence, and wording the
engine could adopt so the contract says it. Source references are to the pinned
crates in Cargo's registry (`iroh-1.3.0`, `iroh-dns-1.3.0`, `noq-1.3.0`,
`reqwest-0.13.5`, `hyper-util-0.1.21`, `n0-dns-resolver-0.1.0`).

## A. Where iroh 1.3.0 needs more than the contract says

The daemon's contract adopted A1 to A4 on 2026-10-14 (re-vendored in
`protocol/PROTOCOL.md`); they stay here as the evidence for that wording.

### A1. Proxy variables: not calling `proxy_from_env` is not enough

- **Contract:** "It never calls iroh's `proxy_from_env`, so proxy variables in
  its environment have no effect."
- **iroh 1.3.0:** the net_report HTTPS latency probe and the captive-portal
  check build reqwest clients (`iroh/src/net_report/reportgen.rs:602`, `:827`,
  through `iroh/src/util.rs` `reqwest_client_builder`) and add a proxy only when
  iroh has one configured. reqwest's builder otherwise keeps
  `auto_sys_proxy: true` (`reqwest/src/async_impl/client.rs:310`, `:417`), which
  reads `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, each in upper
  and lower case (`hyper-util/src/client/proxy/matcher.rs:228`). So an inherited
  `HTTPS_PROXY` would route the relay probes through a proxy. (hyper-util's
  macOS/Windows system-settings reader, feature `client-proxy-system`, is not
  compiled in; only the environment matters.)
- **What the helper does:** `main` removes those eight variables from its own
  environment before it starts any thread (`endpoint::PROXY_VARIABLES`). The
  helper starts no child process, so nothing else is affected.
- **Proposed wording:** "It never calls iroh's `proxy_from_env`, and it removes
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` (either case) from its
  own environment at start, because iroh's HTTPS relay probes would otherwise
  honour them; proxy variables in its environment have no effect."

### A2. DNS: iroh's default resolver falls back to public resolvers

- **Contract:** "it opens no listener and contacts no other host", "uses no
  address lookup service".
- **iroh 1.3.0:** without an explicit resolver, `Builder::bind` builds one with
  the system configuration (`iroh/src/endpoint.rs:266`) and the default
  `FallbackMode::Deferred` (`iroh-dns/src/dns.rs:250`), whose fallback tier is a
  list of public resolvers (`iroh-dns/src/dns.rs:539`). When the system's
  nameservers fail, it would query those.
- **What the helper does:** passes its own resolver, the system configuration
  with `FallbackMode::Never`. Relay names resolve through the system's
  nameservers or not at all (the `relay` event then carries the error).
- **Proposed wording:** "It resolves the relays' names through the system's
  configured nameservers only, never a public fallback resolver."

### A3. Files read besides the key

- **Contract:** "It reads no file but the key."
- **iroh 1.3.0:** resolving the relays' hostnames reads the system resolver
  configuration: `/etc/resolv.conf` on Linux
  (`n0-dns-resolver/src/system_config/unix.rs:11`), the System Configuration
  dynamic store on macOS (`.../apple.rs:36`), and `/etc/hosts` on both
  (`.../hosts.rs:81`). The TLS roots are compiled in (`CaTlsConfig::embedded`),
  so no certificate store is read.
- **What the helper does:** this, unavoidably, to reach relays by name.
- **Proposed wording:** "It reads no file but the key and the system's resolver
  configuration (to resolve the relays' names)."

### A4. Closing a connection whose handshake is still in flight

- **Contract:** `shutdown` closes "every connection with application code `0`,
  reason `shutdown`".
- **QUIC:** an application close sent before the handshake completes is
  replaced on the wire by a transport `APPLICATION_ERROR` close with an empty
  reason (RFC 9000 §10.2.3); a peer then sees no `shutdown` reason. The first
  version of this helper abandoned in-flight handshakes at shutdown and the
  end-to-end test caught exactly that.
- **What the helper does:** a handshake already in flight when shutdown starts
  is allowed to finish, within the shutdown's 1 s task drain, and the
  connection is then closed with code 0, reason `shutdown`. A handshake that
  does not finish in that time is closed by iroh's endpoint close (code 0, no
  reason, or the transport form above). New connection attempts are not
  accepted once shutdown starts.
- **Proposed wording:** "close every connection with application code `0`,
  reason `shutdown` (a connection still in its handshake cannot carry a reason
  and is closed without one)".

## B. Where the contract is silent

### B1. Strict decoding: unknown fields are protocol errors

The contract lists "a line that is not a JSON object, an unknown `op` or
`event`, or a field of the wrong type". The helper also refuses, with
`bad_request`: an unknown field (on every op, `shutdown` included, and inside
`relays[]` and `limits`), a missing field, a duplicate key, invalid UTF-8, and
a final line not terminated by `\n` before end of input. A line is at most
65,536 bytes not counting its `\n`.

*Proposed wording:* add "an unknown or missing field" to the list, and "a line
is at most 64 KiB, not counting its `\n`".

### B2. Value validation behind `bad_request`

Beyond the stated ranges (1–8 relays, `max_connections` 1–1,024,
`max_streams_per_connection` 1–16, windows 65,536–16,777,216), a `start` or
`set_relays` is a `bad_request` when: a relay URL does not parse, is not
`https`, or has no host; `quic_port` is 0; two relays name the same URL (after
URL normalization, so `https://r.example` and `https://r.example/` are the
same); `alpn` is anything but `fermix/mobile/1` (the helper has no preamble
kind for another); `secret_key_path` or `bridge_socket` is not absolute; or
`bridge_socket` is too long for a Unix socket address (refused once at `start`
rather than as `bridge_unreachable` on every stream). Validation happens before
the key is read.

*Proposed wording:* "Out-of-range values, a relay that is not a distinct `https`
URL with a non-zero port, an `alpn` other than `fermix/mobile/1`, and a path that
is not absolute (or a `bridge_socket` too long for a socket address) are
`bad_request`."

### B3. The peer stopping its reading (STOP_SENDING)

The *Ending* list covers finish, reset, connection loss and the daemon closing,
but not the peer stopping its read side. The helper treats it like a reset:
it closes the bridge connection (and stops reading the stream). The daemon sees
the bridge connection close.

*Proposed wording:* "When the peer resets the stream, stops reading it, or the
iroh connection is lost, the helper closes the bridge connection."

### B4. Application codes for the endings the helper starts

The contract defines code 2 (bridge unreachable). Every other stream ending the
helper starts uses code 0: stopping its read side after the daemon closed the
bridge (`STOP_SENDING` 0), resetting its send side when the stream is
abandoned after a peer reset or at shutdown (`RESET_STREAM` 0), and both for a
stream that arrives after the daemon's `close` named its peer, which is never
bridged. After a peer stop, noq answers with a reset carrying the peer's own
code.

*Proposed wording:* "Every other stream end the helper initiates carries
application code `0`."

### B5. A preamble that cannot be written

If the bridge socket accepts the connection but the 37-byte preamble cannot be
written (the daemon closed it at once), or connecting and writing take longer
than 5 s, the helper treats the socket as unreachable: reset with code 2,
`refused` `bridge_unreachable`, no retry.

*Proposed wording:* "When the bridge socket cannot be reached, or the preamble
cannot be written to it within 5 s, …"

### B6. Unidirectional streams and datagrams

The contract bounds bidirectional streams and the flow-control windows. The
helper also gives peers no unidirectional stream credit and accepts no QUIC
datagrams (`max_concurrent_uni_streams` 0, no datagram receive buffer): it
bridges only bidirectional streams, so nothing else may hold memory outside the
windows the daemon set. A phone never uses either.

*Proposed wording:* in *limits*, "Peers get no unidirectional stream credit and
cannot send QUIC datagrams."

### B7. When stream credit comes back

QUIC returns a bidirectional stream's credit only when both halves are closed.
After the daemon closes a bridge, the helper finishes its send half and stops
reading, but the stream stays open, and holds one of
`max_streams_per_connection`, until the peer finishes or resets its own send
half. With noq (and so iroh-ffi), a peer's `finish` after a `STOP_SENDING` is a
no-op (`noq/src/send_stream.rs:197`); only resetting or dropping its send half
releases the stream. The end-to-end test
`a_stream_past_the_per_connection_credit_waits_for_one_to_close` pins this.
This is for the phone, not the helper: on a session's end, the Android client
must drop or reset its send half, or a renewal will wait for credit.

### B8. What `path` and `relay` events report a change of

- `path` is sent when the connection's *selected path* changes identity (iroh's
  `PathId`), so two consecutive `path` events for a peer can carry the same
  fields (one direct path replaced by another). It is not sent for a path that
  is neither relay nor IP (none is configured).
- `relay` is sent after `ready` and when the home relay or its `connected`
  state changes; a new `error` text alone is not a change. The first `relay`
  often names no home relay (`null`, not connected) until iroh picks one.

### B9. `max_connections` counts handshaking connections

A connection holds a slot from the moment it is accepted for its handshake
until its task ends, so `max_connections` bounds handshakes in flight as well as
established connections. Refused attempts hold no slot.

A slot is never held for nothing (adopted in the contract, 2026-10-14, after a
review): a handshake not finished within 10 s is dropped; a connection that has
had no stream for 30 s is closed with code 0, reason `idle` (iroh's 5 s
keep-alive would otherwise keep it for as long as the peer answers); and once
half the slots are taken, a peer whose address QUIC has not validated gets a
Retry first, so forged Initials never take one. Before a slot is taken, the
memory a flood of Initials can cost is noq's own bound (65,536 pending
incomings, 100 MiB of buffered data), not anything in `start.limits`. The
timings live in `endpoint::Timings`; the hermetic suite shortens the idle one.

### B10. `closed`

Sent once per connection that had a `path`, after its last `path`, when the
connection ends for any reason, including shutdown (it is sent before the
shutdown's event flush, within the 5 s). A connection that never reported a
`path` (a failed or very short handshake) gets no `closed`.

### B11. Diagnostics the helper sends as `log`

- `info` right after `ready`: `bound UDP sockets: …`, the endpoint's local UDP
  addresses (for firewall diagnostics).
- `warn` with each `bridge_unreachable`: `bridge socket unreachable: <OS
  error>`, sanitized like relay errors.
- `warn` if shutdown has to give up on a task or on iroh's drain (`shutdown: …`).

The daemon logs these and never matches on them.

### B12. Exit statuses besides 0 and 1

`--version` prints `fermix-iroh <version> (iroh <version>)` and exits 0, for
release verification; any other argument exits 2; a runtime that cannot start
exits 3 (before `hello`); a panic in any thread exits 101 through a panic hook,
so a panicking task is never swallowed by the async runtime. A failure to read
stdin is `error` `internal`. If stdout itself fails, the helper exits 1 without
an `error` (there is nowhere to send one). All of these are crashes to the
daemon, as the contract says.
