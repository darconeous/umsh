# umsh-bridge

`umsh-bridge` carries UMSH frames between radios that cannot hear each other,
over an authenticated internet tunnel, implementing the protocol's
[Internet Bridging appendix](https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html).
One process runs as the **server**, which copies each frame it receives to every
other participant. Every other participant is a **client**, which relays frames
byte for byte between its own radio and the server. To the participants, the
whole arrangement is a hidden radio layer joining segments that are nowhere near
each other.

Every participant's radio runs in **backhaul mode**, which puts the host on a
point-to-point link to the device's own node instead of on the shared medium.
That node's repeater is the bridging policy: a frame crossing the bridge is
repeated twice, once by the device that heard it — whose transmission is what
the tunnel carries — and once by each device on the far side. Hop accounting,
duplicate suppression, and forwarding policy all belong to those repeaters. The
bridge implements none of it and has no presence on the mesh.

> [!CAUTION]
> An internet bridge cannot be relied upon in an emergency, and it spends local
> airtime on traffic that is not local. The specification's cautions apply in
> full; this tool exists so that a bridge deployed anyway behaves predictably
> and conservatively — rate-limited at the tunnel, and hop-accounted and
> duplicate-suppressed by the repeaters at either end.

## How it works

- Every participant holds its own **Ed25519 identity**, and each side is
  configured with the other's public key, written as the canonical UMSH address.
  The address is public: it can be exchanged over chat, email, or a QR code
  without weakening anything. There is no CA and nothing else to distribute —
  admitting a client is adding its address to the server's configuration, and
  revoking one is deleting that entry.
- Participants connect over **TLS 1.3 only** (older versions are not compiled
  in), with ALPN `umsh-bridge/1`. The certificates TLS requires are minted in
  memory from the identity at startup and never stored; the trust decision is
  the handshake signature checked against the pinned identity — proof the peer
  *holds* the key, independent of anything a certificate claims.
- The tunnel carries raw PHY frames with their receive metadata in HDLC-Lite
  framing — the same `STR_PHY_RAW` structures the ULCP device protocol uses, so
  clients relay them without parsing. Idle tunnels exchange keepalives; a
  tunnel silent past its idle timeout is torn down and reconnected with jittered
  backoff.
- The server copies each frame to every other interface, subject to per-client
  rate limits and egress allowlists — decisions about a connection, not about a
  packet. Its one optional exception is the exit clamp, which lowers a frame's
  remaining flood budget on the way through; it is off unless configured.
- Frames are opaque to the bridge. Mesh traffic stays end-to-end encrypted; the
  TLS layer authenticates the participants and keeps the tunnel's contents and
  timing away from the path between them. The bridge never decrypts and never
  originates traffic.

Each participant fronts at most one radio: a ULCP device on a serial port or
over BLE, the UDP-multicast fake radio the workspace examples use, or — for a
server that only joins clients together — no radio at all.

A device needs `CAP_MAC_BACKHAUL` to join a bridge; one that does not advertise
it is refused, and the interface retries until the firmware is updated. Whether
that device *repeats* is its own persisted setting, which the bridge reads and
never writes. A device with its repeater turned off is a **leaf**: reachable
from everywhere the bridge reaches, and its own traffic crosses, but nothing is
carried onward from its segment. That is a deployment, not a fault, and it is
logged as such.

## Host interfaces

A server can also offer **host interfaces**: a plain socket presenting a ULCP
device whose radio is the bridge itself. Whoever connects joins the bridged
medium as an ordinary node — its own MAC, its own identity — without a radio
anywhere in the path. See the specification's
[Host Interfaces](https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html#host-interfaces).

```toml
[[server.hosts]]
name = "phone"
listen = "127.0.0.1:21838"
max_frames_per_minute = 600
```

The rate limit is required here, unlike a client's. A host spends no airtime of
its own, so nothing bounds it naturally, while every frame it injects is
transmitted by every participant's node.

> [!CAUTION]
> The socket is **unauthenticated**, and it grants what a serial cable grants —
> key provisioning and administrative access to the device it presents.
> Whoever reaches it also has an RF presence on every segment the bridge
> touches. It listens on the loopback by default, and a `listen` anywhere else
> is refused unless the entry also sets `allow_remote = true`.

Two hosts and no radio at all is a two-node mesh on one machine, which is what
these are mainly for — testing an iOS simulator build, or `umshctl`, against a
real mesh stack without hardware:

```sh
umshctl --tcp 127.0.0.1:21838 info
```

The device starts with its PHY disabled, exactly as a real one does after a
reset, so a host must enable the radio before anything crosses (`umshctl --tcp
… phy on`). That is deliberate: a simulated device that switched itself on
would hide the bug where a host forgets to.

Frames delivered to a host carry no signal measurements. The measurement that
crossed the tunnel describes a reception on some other segment by some other
radio, and reporting it here would attribute it to a reception that never
happened.

One host holds an interface at a time, and a second connection displaces the
first rather than queueing behind it — the same rule a tunnel client follows,
and the reason a simulator that dies without closing its socket does not wedge
the interface. The device itself outlives them all: it is built once at
startup, so what one host provisions is still there for the next, exactly as a
radio keeps its configuration when a phone walks away.

The device presents no node of its own — it advertises neither `CAP_REPEATER`
nor `CAP_MAC_BACKHAUL` — so a bridge *client* pointed at a host interface
refuses to attach rather than silently running un-backhauled.

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

Each endpoint generates one identity, once, wherever it runs:

```sh
umsh-bridge keygen identity /etc/umsh-bridge/identity.key
```

It prints the identity's **address** — the public name the other end pins,
re-printable any time with `umsh-bridge address`. Swap addresses between the
two ends (they are public; any channel works) and write the configurations:

```toml
# /etc/umsh-bridge/config.toml on the server
[identity]
key_file = "/etc/umsh-bridge/identity.key"

[server]
listen = ["0.0.0.0:21837", "[::]:21837"]   # the default

[server.radio]
type = "serial"                    # or "ble", "udp-multicast", "none"
port = "/dev/ttyACM0"

[[server.clients]]
name = "myclient"
address = "…"                      # printed by the client's `keygen identity`
max_frames_per_minute = 60
```

And the client's:

```toml
# /etc/umsh-bridge/config.toml on the client
[identity]
key_file = "/etc/umsh-bridge/identity.key"

[client]
server = "bridge.example.net:21837"
server_address = "…"               # printed by the server's `keygen identity`

[client.radio]
type = "ble"
selector = "UMSH T-Echo"
```

There are no certificate files: the TLS credential is minted in memory from
the identity at startup. Validate before running — `check` reads the identity
key for real but opens no socket and touches no radio, so it is safe against a
live deployment's config:

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

### `[identity]` — both roles

| Key | Description |
| --- | --- |
| `key_file` | File holding this endpoint's 64-hex Ed25519 seed, readable only by its owner (`keygen identity` writes it with mode 0600, and `check` rejects anything looser). The server's identity is also the bridge's node identity on the mesh; a client's is its tunnel credential, and is ready to become a mesh-addressable management identity later. |

### `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `["0.0.0.0:21837", "[::]:21837"]` | Socket addresses to accept tunnels on. |

### `[client]`

| Key | Default | Description |
| --- | --- | --- |
| `server` | *(required)* | `host:port` of the bridge server. Every address the name resolves to is tried, IPv6 and IPv4 alike. |
| `server_address` | *(required)* | The server's identity, as the UMSH address its `keygen identity` printed (fixed-44 base58, or 64 hex). |
| `server_name` | *(optional)* | SNI name to present. The pinned identity is what authenticates the server; this only matters when the server multiplexes on it. |

### `[server.radio]` / `[client.radio]`

Selected by `type`; each type accepts only its own keys.

| `type` | Keys | Description |
| --- | --- | --- |
| `serial` | `port`, `baud` (default 115200) | A ULCP device on a serial port. |
| `ble` | `selector` (optional) | A ULCP device over BLE. Without a selector the first radio discovered is used, which is only unambiguous where exactly one is in range — name the radio for an unattended deployment. |
| `udp-multicast` | `group` (default 239.255.42.42), `port` (default 7373), `rssi` (default −40), `snr` (default 10) | The fake radio the workspace examples use. UDP measures no signal quality, so `rssi`/`snr` are synthesized for received frames. |
| `none` | — | No radio: a server that only joins clients together. Not valid for a client, which would then relay nothing. This is the default when the table is absent. |

### `[server.limits]`

| Key | Default | Description |
| --- | --- | --- |
| `exit_clamp` | *(off)* | Ceiling applied to `FHOPS_REM` as a frame crosses (0–15). Absent leaves every frame's budget exactly as it arrived, which is the default: a crossing already spends two hops, one at each end's repeater. Set it to hold traffic closer to home — `0` stops a bridged flood at the far side's own segment, while unicast to those segments' own nodes still arrives. A frame carrying no flood budget is never given one. |

Region matching and signal-quality thresholds are not bridge settings. They
belong to the repeater that actually puts bridged traffic on the air, and are
configured on each device with `umshctl repeater`.

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
| `address` | *(required)* | This client's identity, as the UMSH address its `keygen identity` printed. An identity names exactly one client. |
| `max_frames_per_minute` | *(unlimited)* | Budget for frames arriving from this client. `check` warns when absent: an authenticated but misbehaving client is the realistic failure mode. The budget counts everything the client's node transmits — its repeats, its own traffic, its beacons and acks — including the repeats it makes of frames the bridge handed it. |
| `allow_to` | *(all)* | Interfaces this client's traffic may be fanned out to (client names and/or `"radio"`). The place to stop two clients whose radios share a segment from doubling every frame's airtime. |

## Command reference

| Command | Description |
| --- | --- |
| `umsh-bridge run` | Run the bridge in the foreground until interrupted (SIGINT/SIGTERM). |
| `umsh-bridge check` | Load and validate a configuration, reading the identity key it names, without opening a socket or touching a radio. Prints the role, addresses, and per-client fan-out; exits nonzero on any problem. |
| `umsh-bridge keygen identity <path>` | Generate this endpoint's identity, once for its life, and print its address. |
| `umsh-bridge address <path>` | Print an existing identity's address — the one line the other end needs. Safe to share anywhere. |

`run`, `check`, and `address` default to `/etc/umsh-bridge/config.toml` and
`/etc/umsh-bridge/identity.key`; `run` and `check` take `-c`/`--config` (or the
`UMSH_BRIDGE_CONFIG` environment variable). `keygen identity` refuses to
replace an existing key without `--force`, since the identity's address — what
every peer pins — changes permanently.

Logging goes to stderr: `-v` for debug, `-vv` for trace (per-frame verdicts),
`-q` for warnings only, `-qq` for errors only. Verbosity is spent on this crate
first — third-party noise stays at warn — and `--log-filter` (or
`UMSH_BRIDGE_LOG`) takes a full `tracing-subscriber` filter for per-module
control, e.g. `umsh_bridge::hub=trace,info`.

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

Generate the identity and write `config.toml` into `/etc/umsh-bridge`, then:

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
on each group, and traffic crosses the bridge.

The fake radio has no node behind it, so this shows the tunnel and the fan-out
but not the two repeater hops a real crossing takes: frames arrive with their
hop counts and traces exactly as they left, and nothing suppresses a duplicate.
Two bridges sharing a pair of fake segments would loop for the same reason —
there is no dup cache anywhere to stop it. It is a demonstration of the
plumbing, not of the mesh behavior.

The repository's integration tests do exactly this in-process; see
[`tests/bridge.rs`](tests/bridge.rs) for a complete two-segment deployment in
miniature.

## Operational notes

- **The bridge never waits for a channel.** A backhauled hand-off crosses a
  wire: it spends no airtime, contends with nobody, and books nothing against
  the device's duty budget. What it can meet is a node whose receive queue is
  full, which ULCP reports the only way it can — as a channel-access failure —
  and which the relay answers by waiting a few tens of milliseconds and
  offering the frame again, while still draining reception. Whether the frame
  then goes on the air is the node's decision: a duplicate it has already seen,
  or one whose flood budget is spent, ends there. That is the bridging policy
  working, not a failure.

- **Two hops per crossing.** A frame that leaves its sender with three hops of
  budget arrives on the far segment with one, because the repeaters at both ends
  each spend one. Traffic that has to cross a bridge should be sent with that in
  mind, and `exit_clamp` is the lever for pulling it back in a hurry.

- **Rotation and revocation.** There is nothing to expire: the pinned identity
  is the whole trust decision. Rotating a participant is generating a new
  identity and updating its address at the other end; revoking a client is
  deleting its `[[server.clients]]` entry and restarting. The identity is a
  tunnel credential only — the bridge has no mesh address — so rotating it
  costs nothing beyond reconfiguring the peers that pin it.
- **A rejected client looks connected, briefly.** TLS 1.3 completes the
  client's half of the handshake before the server evaluates its identity, so
  a client the server does not pin sees its connection accepted and then
  immediately closed with an alert. If a client connects and instantly drops
  in a loop, compare its `umsh-bridge address` output against the server's
  configuration.
- **One key, two protocols, safely.** The identity that authenticates the
  tunnel is the same Ed25519 key that will sign UMSH structures if the
  endpoint later acts on the mesh. The two uses cannot be confused: TLS 1.3
  domain-separates its handshake signatures behind a fixed 64-octet padding
  prefix and context string that no UMSH signed structure begins with.
- **Reconnects discard the queue.** Frames buffered for a dead tunnel are
  dropped on reconnect rather than delivered late; the mesh's own retry
  machinery is the recovery path, and `max_frame_age_secs` bounds staleness the
  same way for a live one.
- **A busy serial port usually isn't a dead radio.** Check for another process
  holding the port (an orphaned monitor session, a forgotten `umshctl` REPL)
  before suspecting hardware.
- **The device keeps its own configuration.** The bridge attaches without
  resetting the device and writes exactly two session-scoped properties,
  backhaul and promiscuous delivery, both of which lapse when the session ends.
  Nothing persisted is touched — in particular the repeater setting, which the
  bridge reads and reports but never changes.

## Status

The bridge is exercised end-to-end against the UDP-multicast fake radio and an
in-process integration suite covering fan-out, byte fidelity, the exit clamp,
rate limits, allowlists, pinning, and reconnection. The fake radio has no node
behind it, so the two-hop crossing that a real deployment depends on — and the
duplicate suppression that terminates tunnel echoes — is covered by the device
and MAC test suites rather than here, and has not yet been validated against
radio hardware. The serial and BLE device paths use the same host-side ULCP
driver as `umshctl`. Treat a first hardware deployment as a shakedown, and run
it at `-vv` for per-frame detail.
