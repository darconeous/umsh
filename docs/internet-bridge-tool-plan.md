# umsh-bridge: internet bridge command-line tool

This is the plan the tool was built from, kept for the reasoning behind the
decisions rather than as a description of the result. Where the two differ, see
[As landed](#as-landed) at the end.

## Context

`docs/protocol/src/internet-bridging.md` (landed in c87400f7, the most recent commit) fully
specifies a client–server internet bridge — one virtual repeater whose radios sit in
different places, joined by a TLS 1.3 tunnel carrying HDLC-Lite-framed `STR_PHY_RAW`
structures — but no implementation exists anywhere in the repo. The workspace has every
ingredient (HDLC codec, host-side ULCP driver, packet parse/rewrite, duplicate-cache
machinery, UDP fake radio), assembled only into `umshctl` and the single-interface repeater
inside the MAC coordinator. This plan builds the missing tool: a standalone daemon-friendly
binary that acts as bridge server or bridge client, with static TOML configuration, leveled
logging, IPv4+IPv6, and optional support for the UDP-multicast fake radio used by the
examples.

## Decisions taken (user-confirmed)

- **Standalone package `tools/umsh-bridge`**, own binary `umsh-bridge`, own dependencies.
  Not part of umshctl or the umbrella crate. `crates/` stays reserved for library crates;
  binaries live in `tools/`.
- **The `umsh` umbrella crate must not depend on rustyline** (Cargo has no per-target
  dependencies) → **`umshctl` is spun out into its own package** (`tools/umshctl`),
  taking clap/rustyline/shlex/anyhow/libc with it.
- **TLS 1.3 via tokio-rustls**, mutual self-signed certs with SHA-256 fingerprint pinning,
  ALPN `umsh-bridge/1`, built-in rcgen `keygen`. External PSK deferred (rustls lacks it).
- **Forwarding-only scope**: static Ed25519 identity supplies the node/router hints for
  source-route matching and trace prepending. No beacons, no MAC-ack generation, no
  decryption; packets addressed to the bridge are dropped, not forwarded.
- **TOML + serde config; tracing + tracing-subscriber logging** — new precedents confined
  to the new crate.
- **Both roles in one binary**, role chosen by the config file. Foreground process;
  systemd/launchd own daemonization (no self-forking).
- **Default port 21837** (0x554D = ASCII "UM", big-endian) — IANA-unassigned and
  deliberately not a commonly-picked vanity port. Configurable, of course.

## Decisions added by this plan (flag disagreement before Phase 1)

- Role from config (`[server]` xor `[client]`) under a single `run` command — one systemd
  unit shape; `check` validates the exact artifact that runs.
- **Cache-key computation extracted from umsh-mac and shared** (it is the interop surface:
  forwarding confirmation matches on it bit-for-bit); the **frame rewrite is reimplemented
  in the bridge** (clamp, no region insertion, confirmation variant — parameterizing the
  `no_std` coordinator would push bridge policy into the MAC for no gain).
- Bridge-local cache struct reusing `DupCacheKey` + 1 h TTL semantics, because entries must
  also record arrival interface, acceptance time, and the stored confirmation frame.
- Confirmation copy = fan-out frame with the `FHOPS_REM` nibble patched to 0, stored in the
  cache entry so re-confirmation is a queue push, not a re-rewrite.
- Overhear-vs-previous-hop-retry discrimination by the raw FHOPS byte of an arriving
  duplicate (byte-equal → retry, re-send confirmation; different → overheard forwarding,
  defer; abandon after 3 deferrals). Source-routed copies never deferred/abandoned.
- Missing/sentinel RSSI/SNR skips only the threshold it cannot evaluate (logged at debug).
- Fingerprint = SHA-256 of full cert DER (`sha256:<hex>`); SPKI pinning deferred.
- `current_thread` tokio runtime (LoRa-rate traffic; lock-free engine state; house pattern).
- Simplified uniform contention window `[0, 2 × t_frame]` for flood confirmation copies
  (tunnel metadata may be sentinel-filled, so no SNR scaling).
- Server composes the tunnel `TxMeta` (power default 0x7F, flags 0 — NODUTY clear at
  composition); clients relay byte-faithfully, parse-free, per spec.
- `suppress_flood_confirmations` per client interface (spec § Co-located Repeater Role).
- Identity key file = 64-hex Ed25519 seed, 0600-enforced.
- Deferred: locally-handled-unicast step (N/A without node logic; kept as an explicit
  numbered no-op in code), bridge-originated traffic/beacons, callsign rewriting,
  region-code insertion (prohibited for bridges anyway), IPv6 fake radio, PSK, SPKI pins.

## Workspace changes outside the new crate

1. **Spin out `tools/umshctl`** (mechanical: bin sources already use `umsh::` paths).
   Move `umsh/src/bin/umshctl/` → `tools/umshctl/src/`, new Cargo.toml depending on
   `umsh` (features `tokio-support`, `serial-radio`, `ble-radio`) plus clap, rustyline,
   shlex, anyhow, libc. The umbrella's `tokio-support` feature slims to
   `["std", "software-crypto", "dep:rand", "dep:socket2", "dep:tokio"]` (it verifiedly
   only gates `src/ulcp.rs` + `src/tokio_support.rs`, which use none of the REPL deps);
   rustyline/shlex/libc leave `umsh/Cargo.toml` entirely; clap/anyhow drop to
   dev-dependencies iff examples still need them. `serial-radio`/`ble-radio` unchanged.
   Makefile `install-umshctl` → `cargo install --path tools/umshctl` (extcap symlink
   target `~/.cargo/bin/umshctl` unchanged). CLI grammar tests move with the binary.
2. **`umsh/src/ulcp.rs` raw accessors** (~70 lines): `RawRxFrame { data, raw_meta }`,
   `UlcpDevice::poll_receive_raw` (same loop as the `Radio::poll_receive` impl at :2288
   but preserving `RxPacket.raw_meta`, today only reachable via `queue_drain_with`), and
   `transmit_raw_with_meta(data, metadata)` factored out of `Radio::transmit` (:2217) so
   both share the confirmed-TID/CCA-retry body. The spec needs the CMD_STR_RECV body
   relayed unmodified, which `RxInfo` cannot express (it collapses sentinels to 0).
3. **`crates/umsh-mac`**: extract `forward_dup_key`/`routable_packet_identity`/
   `normalized_routable_hash32` (coordinator.rs:4834/4838/5083 — already pure, no `self`)
   into a new public `forward_id` module: `forwarding_dup_key(frame)` /
   `forwarding_dup_key_parsed(&PacketHeader, frame)`; coordinator delegates. Guarded by a
   parity regression test in the bridge.
4. **Root `Cargo.toml`**: add `tools/umshctl` and `tools/umsh-bridge` to both `members`
   and `default-members` (alongside the existing `tools/` members; unlike
   `tools/uniffi-bindgen` these two belong in default builds).
5. **`Makefile`**: `install-umsh-bridge` target (`cargo install --path tools/umsh-bridge`)
   + `.PHONY` entries (pattern at :141).
6. **`README.md`** (tool section + layout table row), **`CLAUDE.md`** (layout lines for
   both new packages), plan committed as `docs/internet-bridge-tool-plan.md` per house
   convention, `contrib/systemd/umsh-bridge.service` sample unit.

## New package: tools/umsh-bridge

```
src/
  main.rs      clap dispatch; #[tokio::main(flavor = "current_thread")]
  cli.rs       run / check / keygen {identity, cert, fingerprint}; -v.. -q --log-filter
  config.rs    serde types, deny_unknown_fields, load + validate
  identity.rs  BridgeIdentity { SoftwareIdentity, node_hint, router_hint }; umsh-uri output
  tls.rs       TLS13-only configs, ALPN, PinnedClientVerifier / PinnedServerVerifier
  keygen.rs    rcgen issuance (10 y validity, CN = name), 0600 keys, fingerprint print
  tunnel.rs    HDLC framing over AsyncRead+Write; literal 0x7E keepalive writes;
               octet-level liveness below the hdlc::Decoder; TunnelQueue (bounded,
               drop-oldest, staleness incl. RX_AGE, clear-on-reconnect)
  iface.rs     InterfaceId/name; Ingress { iface, frame, RxSignal, age_s }; egress handles
  device.rs    DeviceRelay: serial open → attach_existing → CAP_WRITABLE_RAW_STREAM check →
               PROP_MAC_PROMISCUOUS (graceful-refusal warn; re-asserted on every reattach) →
               relay loop; reconnect with backoff
  udp_radio.rs UdpMulticastRadio adapter (synthesizes RxSignal from configured rssi/snr)
  server.rs    multi-addr listeners, TLS accept, fingerprint → client match, per-conn
               reader/writer tasks, reconnect bumps stale session
  client.rs    resolve-all-addrs (v4+v6) connect loop, jittered backoff, device wiring
  engine.rs    13-step evaluate(); BridgeDupCache (128 entries, 1 h TTL, first-insert-wins;
               entries: DupCacheKey + iface + accepted_at + confirmation bytes);
               PendingConfirmation heap + sleep_until timer
  rewrite.rs   rewrite_for_fanout (modeled on coordinator.rs:4399/4466: FCF byte, FHOPS,
               verbatim core, OptionEncoder re-emit w/ trace prepend + source-route pop,
               0xFF marker rules, verbatim body+MIC) ; confirmation_copy (REM nibble → 0)
  policy.rs    per-client + per-pair token buckets, egress allowlists, region matching
tests/         tunnel.rs engine.rs relay.rs (integration, see Verification)
```

Deps (plain versions, per convention): `umsh` (default-features off; `tokio-support`,
`serial-radio`), `umsh-ulcp`, `umsh-core` (`region-codec`), `umsh-mac`, `umsh-crypto`,
`umsh-uri`; tokio (no rt-multi-thread), tokio-rustls, rustls-pki-types, rcgen, serde,
toml, clap, tracing, tracing-subscriber (env-filter), anyhow, rand, sha2.

### Config sketch

```toml
# --- server ---
[identity]
key_file = "/etc/umsh-bridge/identity.key"        # 64-hex Ed25519 seed, 0600

[server]
listen = ["0.0.0.0:21837", "[::]:21837"]

[server.tls]
cert_file = "/etc/umsh-bridge/server.crt"
key_file  = "/etc/umsh-bridge/server.key"

[server.radio]                                     # "serial" | "udp-multicast" | "none"
type = "serial"
port = "/dev/ttyACM0"
baud = 115200

[server.forwarding]
exit_clamp = 1                                     # spec default; SHOULD NOT raise
regions = []                                       # empty = no regional restriction
min_rssi = -120                                    # optional
min_snr  = -3                                      # optional
cache_entries = 128
confirmation_window_secs = 30

[server.tunnel]
keepalive_secs = 10
idle_timeout_secs = 30
max_frame_age_secs = 10
queue_depth = 32

[[server.clients]]
name = "cabin"
fingerprint = "sha256:9f2a…"                       # client cert DER SHA-256
max_frames_per_minute = 60
allow_to = ["radio", "site-b"]                     # egress allowlist; absent = all
suppress_flood_confirmations = false

# --- client ---
[client]
server = "bridge.example.net:21837"                # all A/AAAA tried in order

[client.tls]
cert_file = "/etc/umsh-bridge/cabin.crt"
key_file  = "/etc/umsh-bridge/cabin.key"
server_fingerprint = "sha256:41bb…"

[client.radio]
type = "serial"
port = "/dev/ttyACM0"
baud = 115200

[client.tunnel]
reconnect_min_secs = 1
reconnect_max_secs = 60
```

### Architecture notes

- Channel topology: interface tasks → `mpsc<Ingress>` → engine task (single consumer) →
  bounded egress `TunnelQueue` per interface (hand-rolled VecDeque+Notify — tokio mpsc
  cannot drop-oldest).
- Reader tasks reset the idle deadline on every received-octet count > 0 (bare-0x7E
  keepalives are silently absorbed by `hdlc::Decoder`, so liveness must be measured below
  it). Writers drop stale entries (`now − enqueued_at + RX_AGE` > limit) before encoding;
  keepalive timer writes a single literal `0x7E` (`encode_frame(&[])` is a 4-byte frame,
  not a keepalive). Malformed/over-MTU frames discarded with debug log.
- Tunnel body: `PACKET_LEN(u16 LE) || data || metadata` — client→server relays the raw
  `(data, raw_meta)` pair byte-identically; server→client appends `TxMeta{0x7F, 0}`.
- Clients run no forwarding logic; the client role is a byte-faithful device↔tunnel relay.
- The 13 steps live in `engine::evaluate` in spec order (step 3 as an explicit no-op with a
  spec citation); cache insert happens before any transmission (normative for bridges);
  fan-out skips only over-MTU interfaces individually; flood confirmation copies are
  scheduled with the uniform window and cancelled/deferred on overhear; source-routed
  copies enqueue immediately.

## Phases

1. **umshctl spin-out + umbrella slimming.** No behavior change; `umshctl` builds and runs
   identically from `tools/umshctl`; `umsh` no longer declares rustyline/shlex/libc.
2. **Exposures + skeleton.** `poll_receive_raw`/`transmit_raw_with_meta`, umsh-mac
   `forward_id` extraction (+ parity test), workspace membership, `cli.rs`/`config.rs`,
   working `check`.
3. **Credentials + tunnel.** `keygen`, `tls.rs`, `tunnel.rs`, server accept with pinning,
   client connect/reconnect. Tunnel integration tests green.
4. **Client relay.** `device.rs` + `client.rs` end-to-end; scripted fake-device tests;
   bench smoke against a real board.
5. **Forwarding engine.** `engine.rs`/`rewrite.rs`/`policy.rs` + server wiring; full
   integration suite green.
6. **Fake radio, docs, e2e.** `udp_radio.rs`, Makefile/README/CLAUDE.md/systemd sample,
   plan doc committed, manual two-group `desktop_chat` e2e.

## Verification

- **Unit**: config fixtures (both roles, each radio type, rejects: both/neither role,
  unknown keys, dangling `allow_to`, duplicate fingerprints); clap `debug_assert`;
  rewrite tests on frames built with `umsh_core::builder` (source-route pop preserves
  emptied option, trace prepend, oversize-drop, clamp incl. clamp-without-decrement on
  routed hops, confirmation copy differs in exactly the REM nibble, 0xFF/MacAck cases,
  every output reparses); engine tests (key parity vs `umsh_mac::forwarding_dup_key`,
  cache first-insert-wins/TTL/capacity, per-step drop reasons, overhear-vs-retry,
  re-confirmation window under `tokio::time::pause`); tunnel queue + framing over
  `tokio::io::duplex`; token buckets.
- **Integration** (in-process, `127.0.0.1:0`, ephemeral rcgen certs): fan-out excludes
  arrival; duplicate from second client suppressed; confirmation copy on arrival interface
  with REM=0 and matching key; re-confirmation inside/outside 30 s; source-route match/pop;
  exit clamp visible; rate limits; wrong fingerprint refused at handshake; queues not
  flushed across reconnect. Client relay against a scripted ULCP device over duplex
  (tethered attach, promiscuous re-assert after link drop, byte-faithful relay).
- **Manual e2e**: server on UDP-multicast group A + client process on group B, a
  `desktop_chat` instance on each; chat crosses the bridge, trace route shows the bridge
  hint, 3-hop flood arrives with REM=1.
- Throughout: root `cargo test` / `cargo build` green (both new crates are
  default-members); rustfmt pre-commit clean.

## As landed

The implementation follows the plan; these are the differences worth knowing.

- **BLE is a first-class radio transport**, alongside serial and the UDP fake radio.
  Both ULCP transports attach with `attach_existing` rather than `open_ble`, which
  resets the device — a bridge attaches to a radio that is already operating.
- **`tools/umsh-bridge` is a lib+bin split.** The binary is the library's only
  consumer; the split exists so `tests/bridge.rs` can stand a whole bridge —
  server, client, tunnel, and two fake-radio segments — up in one process.
- **`umsh-mac`'s cache-key extraction needed no parity test.** The bridge calls
  `umsh_mac::forward_id::forwarding_dup_key` directly rather than reimplementing
  it, so the two agree by construction; the coordinator now delegates to the same
  module and the existing MAC suite guards the move.
- **`[server.forwarding] flood_contention_ms`** was added (default 1600). The plan
  called for a uniform contention window but left its width implicit, and it has to
  be settable — a segment with no other repeaters wants zero, and the integration
  tests need determinism.
- **`umsh-bridge check` is its own module**, reading the credentials and identity
  key for real. A configuration that parses but names a key the daemon cannot read
  is not a configuration that works.
- **Radio configuration is read as a flat table, not a tagged enum.** Serde buffers
  an internally tagged enum's content and `deny_unknown_fields` never reaches the
  variant, so a misspelled key in a daemon's configuration would have been silently
  ignored.
- **The TLS 1.3 client-auth refusal is deferred**, inherently: the client half of
  the handshake completes before the server has looked at its certificate, so an
  unpinned client sees the refusal as an alert on its first exchange. The server
  still refuses it at the handshake, and the session never carries a frame.
