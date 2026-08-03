# umsh-bridge

`umsh-bridge` joins the radios of one virtual UMSH repeater over an authenticated
internet tunnel, implementing the protocol's
[Internet Bridging appendix](https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html).
One process runs as the **server**: it owns the bridge's node identity, holds the
shared duplicate cache, and makes every forwarding decision. Every other
participant is a **client**, which relays frames byte for byte between its own
radio and the server and applies no forwarding logic at all. To the mesh, the
whole arrangement is a single repeater that happens to hear traffic in several
places at once.

> [!CAUTION]
> An internet bridge cannot be relied upon in an emergency, and it spends local
> airtime on traffic that is not local. The specification's cautions apply in
> full; this tool exists so that a bridge deployed anyway behaves predictably
> and conservatively — rate-limited, hop-clamped, and duplicate-suppressed by
> default.

## How it works

- Participants connect over **TLS 1.3 only** (older versions are not compiled
  in), with ALPN `umsh-bridge/1`. Both ends present self-signed certificates
  and each pins the SHA-256 fingerprint of the other's. There is no CA:
  admitting a client is adding its fingerprint to the server's configuration,
  and revoking one is deleting that entry.
- The tunnel carries raw PHY frames with their receive metadata in HDLC-Lite
  framing — the same `STR_PHY_RAW` structures the ULCP device protocol uses, so
  clients relay them without parsing. Idle tunnels exchange keepalives; a
  tunnel silent past its idle timeout is torn down and reconnected with jittered
  backoff.
- The server runs the appendix's forwarding procedure over every interface:
  duplicate suppression against a shared cache, per-client rate limits and
  egress allowlists, optional region and signal-quality gates, an outbound hop
  clamp (default: 1 remaining hop), and forwarding-confirmation copies back to
  the interface a packet arrived on.
- Frames are opaque to the bridge. Mesh traffic stays end-to-end encrypted; the
  TLS layer authenticates the participants and keeps the tunnel's contents and
  timing away from the path between them. The bridge never decrypts, never
  originates traffic, and drops packets addressed to itself.

Each participant fronts at most one radio: a ULCP device on a serial port or
over BLE, the UDP-multicast fake radio the workspace examples use, or — for a
server that only joins clients together — no radio at all.

## Installation

`umsh-bridge` is built from this repository; it is not published on crates.io.
Any Rust toolchain recent enough for the 2024 edition (1.85+) works — install
one with [rustup](https://rustup.rs) if in doubt.

### Debian / Ubuntu

```sh
sudo apt install build-essential pkg-config libdbus-1-dev
```

`libdbus-1-dev` and `pkg-config` are needed by the BLE radio support, which
talks to BlueZ over D-Bus; building with BLE disabled (below) removes that
requirement. Then, from a checkout of this repository:

```sh
cargo install --path tools/umsh-bridge
```

(or `make install-umsh-bridge` from the repository root, which runs the same
command). The binary lands in `~/.cargo/bin/umsh-bridge`; for a system service,
copy it somewhere system-wide:

```sh
sudo install -m 0755 ~/.cargo/bin/umsh-bridge /usr/local/bin/
```

At runtime, a serial radio needs the service user in the `dialout` group, and a
BLE radio needs a running `bluetoothd` (package `bluez`) and access to the
system D-Bus.

### macOS

Xcode's command-line tools provide the C toolchain:

```sh
xcode-select --install
```

Then install as above (`cargo install --path tools/umsh-bridge` from a
checkout). Serial ULCP devices appear as `/dev/cu.usbmodem*`; no group
membership is needed. A BLE radio uses CoreBluetooth, so the terminal (or
whatever launches the bridge) must be granted Bluetooth access under
System Settings → Privacy & Security → Bluetooth the first time it runs.

### Feature flags

Both radio transports are on by default. A deployment that will only ever use
one can build without the other:

```sh
cargo install --path tools/umsh-bridge --no-default-features --features serial-radio
```

`serial-radio` and `ble-radio` are independently selectable; the UDP-multicast
fake radio and the radio-less server are always available.

## Quick start

The binary issues every credential a deployment needs. On the server, generate
the bridge's node identity — once, for the life of the bridge; it is the
address the mesh knows the bridge by:

```sh
umsh-bridge keygen identity /etc/umsh-bridge/identity.key
```

Then a TLS certificate for each participant, wherever that participant runs:

```sh
umsh-bridge keygen cert server --cert /etc/umsh-bridge/server.crt --key /etc/umsh-bridge/server.key
```

```sh
umsh-bridge keygen cert myclient --cert /etc/umsh-bridge/myclient.crt --key /etc/umsh-bridge/myclient.key
```

Each `keygen cert` prints the fingerprint the *other* end must pin
(`keygen fingerprint <cert>` re-prints it later). Server configuration:

```toml
# /etc/umsh-bridge/config.toml on the server
[identity]
key_file = "/etc/umsh-bridge/identity.key"

[server]
listen = ["0.0.0.0:21837", "[::]:21837"]   # the default

[server.tls]
cert_file = "/etc/umsh-bridge/server.crt"
key_file = "/etc/umsh-bridge/server.key"

[server.radio]
type = "serial"                    # or "ble", "udp-multicast", "none"
port = "/dev/ttyACM0"

[[server.clients]]
name = "myclient"
fingerprint = "sha256:…"           # printed by `keygen cert myclient`
max_frames_per_minute = 60
```

And the client's:

```toml
# /etc/umsh-bridge/config.toml on the client
[client]
server = "bridge.example.net:21837"

[client.tls]
cert_file = "/etc/umsh-bridge/myclient.crt"
key_file = "/etc/umsh-bridge/myclient.key"
server_fingerprint = "sha256:…"    # printed by `keygen cert server`

[client.radio]
type = "ble"
selector = "UMSH T-Echo"
```

Validate before running — `check` reads the credentials for real but opens no
socket and touches no radio, so it is safe against a live deployment's config:

```sh
umsh-bridge check
```

```sh
umsh-bridge run
```

The role comes from the configuration file, not the command line, so one unit
file and one invocation fit either end. The default port, 21837, is `0x554D` —
big-endian ASCII "UM" — chosen to be unassigned and unlikely to collide with
another service on a shared host.

## Configuration reference

The file is TOML. Unknown keys are rejected rather than ignored — a misspelled
option fails `check` instead of silently doing nothing. Exactly one of
`[server]` or `[client]` must be present.

### `[identity]` — server only

| Key | Description |
| --- | --- |
| `key_file` | File holding the 64-hex Ed25519 seed, readable only by its owner (`keygen identity` writes it with mode 0600, and `check` rejects anything looser). |

### `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `["0.0.0.0:21837", "[::]:21837"]` | Socket addresses to accept tunnels on. |

### `[server.tls]` / `[client.tls]`

| Key | Description |
| --- | --- |
| `cert_file`, `key_file` | This participant's certificate and private key, as issued by `keygen cert`. |
| `server_fingerprint` | *(client only)* SHA-256 of the server's certificate DER, `sha256:<64 hex>`. |
| `server_name` | *(client only, optional)* SNI name to present. The pin is what authenticates the server; this only matters when the server multiplexes on it. |

### `[server.radio]` / `[client.radio]`

Selected by `type`; each type accepts only its own keys.

| `type` | Keys | Description |
| --- | --- | --- |
| `serial` | `port`, `baud` (default 115200) | A ULCP device on a serial port. |
| `ble` | `selector` (optional) | A ULCP device over BLE. Without a selector the first radio discovered is used, which is only unambiguous where exactly one is in range — name the radio for an unattended deployment. |
| `udp-multicast` | `group` (default 239.255.42.42), `port` (default 7373), `rssi` (default −40), `snr` (default 10) | The fake radio the workspace examples use. UDP measures no signal quality, so `rssi`/`snr` are synthesized for received frames. |
| `none` | — | No radio: a server that only joins clients together. Not valid for a client, which would then relay nothing. This is the default when the table is absent. |

### `[server.forwarding]`

| Key | Default | Description |
| --- | --- | --- |
| `exit_clamp` | 1 | Ceiling applied to `FHOPS_REM` on the way out (0–15). The spec advises against raising it on internet-tunneled deployments. |
| `regions` | `[]` | Region codes this bridge will carry: an IATA code (`"SJC"`), a raw code (`"0x7853"`), or a region name that is hashed. Empty means no restriction. |
| `min_rssi` | *(none)* | Drop frames received weaker than this, in dBm. A frame whose metadata carries no reading skips only the gate it cannot evaluate. |
| `min_snr` | *(none)* | Likewise for SNR, in dB; fractional values are kept to a tenth. |
| `cache_entries` | 128 | Duplicate-cache capacity. |
| `confirmation_window_secs` | 30 | How long a forwarded packet's confirmation copy stays available for re-confirmation to a retrying previous hop. |
| `flood_contention_ms` | 1600 | Window a flood confirmation copy is spread over, roughly two frame durations at the segment's data rate. Zero sends it immediately, which a segment with no other repeaters can afford. |

### `[server.tunnel]` / `[client.tunnel]`

| Key | Default | Description |
| --- | --- | --- |
| `keepalive_secs` | 10 | Idle interval after which a keepalive is written. |
| `idle_timeout_secs` | 30 | A tunnel silent this long is torn down. Must exceed `keepalive_secs`. |
| `max_frame_age_secs` | 10 | Frames older than this (including time spent buffered in the device) are dropped rather than tunneled; they have outlived every retry that could have wanted them. |
| `queue_depth` | 32 | Frames held per tunnel before the oldest is dropped. |
| `reconnect_min_secs` / `reconnect_max_secs` | 1 / 60 | Jittered backoff bounds for reconnection. |

### `[[server.clients]]` — one per admitted client

| Key | Default | Description |
| --- | --- | --- |
| `name` | *(required)* | Interface name, used in log lines and in other clients' `allow_to`. `"radio"` is reserved for the server's own radio. |
| `fingerprint` | *(required)* | SHA-256 of this client's certificate DER. Each credential identifies exactly one client. |
| `max_frames_per_minute` | *(unlimited)* | Forwarding budget for frames arriving from this client. `check` warns when absent: an authenticated but misbehaving client is the realistic failure mode. |
| `allow_to` | *(all)* | Interfaces this client's traffic may be fanned out to (client names and/or `"radio"`). |
| `suppress_flood_confirmations` | `false` | Set when the device behind this client also runs its own repeater role: its re-forward already confirms the previous hop, so the bridge's flood confirmation copy would be redundant airtime. Source-routed confirmations are still emitted, and a direct retry from the previous hop is still answered. |

## Command reference

| Command | Description |
| --- | --- |
| `umsh-bridge run` | Run the bridge in the foreground until interrupted (SIGINT/SIGTERM). |
| `umsh-bridge check` | Load and validate a configuration, reading the keys and certificates it names, without opening a socket or touching a radio. Prints the role, fingerprints, and per-client fan-out; exits nonzero on any problem. |
| `umsh-bridge keygen identity <path>` | Generate the bridge's node identity (server only, once) and print its mesh address and hints. |
| `umsh-bridge keygen cert <name> --cert <path> --key <path>` | Issue a self-signed certificate and print the fingerprint to pin at the other end. |
| `umsh-bridge keygen fingerprint <cert>` | Re-print an existing certificate's fingerprint. |

`run` and `check` take `-c`/`--config` (default `/etc/umsh-bridge/config.toml`,
or the `UMSH_BRIDGE_CONFIG` environment variable). `keygen` refuses to replace
an existing file without `--force`, since every peer pinning the old
certificate would need updating — and a replaced *identity* changes the
bridge's mesh address permanently.

Logging goes to stderr: `-v` for debug, `-vv` for trace (per-frame forwarding
verdicts), `-q` for warnings only, `-qq` for errors only. Verbosity is spent on
this crate first — third-party noise stays at warn — and `--log-filter` (or
`UMSH_BRIDGE_LOG`) takes a full `tracing-subscriber` filter for per-module
control, e.g. `umsh_bridge::engine=trace,info`.

## Running as a service

### systemd (Debian / Ubuntu)

A hardened sample unit is provided in
[`contrib/systemd/umsh-bridge.service`](../../contrib/systemd/umsh-bridge.service);
its comments include the full install sequence. In short:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin umsh-bridge
```

```sh
sudo install -d -o umsh-bridge -g umsh-bridge -m 0750 /etc/umsh-bridge
```

Write `config.toml` and generate the credentials into `/etc/umsh-bridge`, then:

```sh
sudo cp contrib/systemd/umsh-bridge.service /etc/systemd/system/
```

```sh
sudo systemctl enable --now umsh-bridge
```

The configuration is read once at start-up, so applying a change is
`systemctl restart` — after `umsh-bridge check`. The process itself retries a
lost radio or tunnel on its own; the unit's `Restart=on-failure` is only for a
process that actually died.

### macOS (launchd)

For a client with a serial radio, a minimal LaunchDaemon works — save as
`/Library/LaunchDaemons/net.example.umsh-bridge.plist` and load with
`sudo launchctl load -w` on that path:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>net.example.umsh-bridge</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/umsh-bridge</string>
        <string>run</string>
        <string>-c</string>
        <string>/etc/umsh-bridge/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
</dict>
</plist>
```

A BLE radio is the complication: macOS grants Bluetooth access per application
via a prompt, which a root daemon has no way to answer. Run a BLE-radio bridge
as a LaunchAgent in a logged-in user session (same plist under
`~/Library/LaunchAgents`) — or simply in a terminal — so the one-time
permission prompt can be approved.

## Trying it without hardware

The `udp-multicast` radio type stands in for a real radio, so a whole bridge —
server, client, and two mesh segments — fits on one machine. Point each end at
a *different* multicast group, run a
[desktop chat](../../README.md#build-and-run-the-desktop-chat-example) instance
on each group, and traffic crosses the bridge: the trace route shows the
bridge's router hint, and a flood that left with three hops arrives clamped to
one remaining.

The repository's integration tests do exactly this in-process; see
[`tests/bridge.rs`](tests/bridge.rs) for a complete two-segment deployment in
miniature.

## Operational notes

- **Rotation and revocation.** Nothing consults a certificate's validity
  window — the pin is the trust decision, so certificates are issued long
  (10 years) and rotation is an operator action: issue a new certificate, add
  its fingerprint at the other end, remove the old one. Revoking a client is
  deleting its `[[server.clients]]` entry and restarting.
- **A rejected client looks connected, briefly.** TLS 1.3 completes the
  client's half of the handshake before the server evaluates the certificate,
  so a client with an unknown fingerprint sees its connection accepted and then
  immediately closed with an alert. If a client connects and instantly drops in
  a loop, compare `keygen fingerprint` output against the server's
  configuration.
- **Reconnects discard the queue.** Frames buffered for a dead tunnel are
  dropped on reconnect rather than delivered late; the mesh's own retry
  machinery is the recovery path, and `max_frame_age_secs` bounds staleness the
  same way for a live one.
- **A busy serial port usually isn't a dead radio.** Check for another process
  holding the port (an orphaned monitor session, a forgotten `umshctl` REPL)
  before suspecting hardware.
- **The device keeps its own role.** The bridge attaches to the ULCP device
  without displacing its configuration and asks for promiscuous reception; a
  device that refuses is logged and relayed as-is. A device that also runs its
  own repeater role on the same segment is what `suppress_flood_confirmations`
  is for.

## Status

The bridge is exercised end-to-end against the UDP-multicast fake radio and an
in-process integration suite covering fan-out, duplicate suppression,
confirmation copies, rate limits, allowlists, and reconnection. The serial and
BLE device paths use the same host-side ULCP driver as `umshctl` but have not
yet been validated against radio hardware — treat a first hardware deployment
as a shakedown, and run it at `-vv` for per-frame verdicts.
