![UMSH Logo](docs/logo/umsh-logo-orange-sm.png)

\[ [Protocol Book](https://darconeous.github.io/umsh/docs/protocol/) | [Rustdocs](https://darconeous.github.io/umsh/docs/rust/) \]

**UMSH** is an experimental, LoRa-oriented mesh protocol designed from the ground up with strong cryptography, clean layer separation, and strict bandwidth discipline. The primary use case it enables is decentralized, wide-area text chat and location/sensor reporting.

Originally intended as a proposal for a "[MeshCore](https://github.com/meshcore-dev/MeshCore) 2.0", UMSH grew out of a simple question: what would a cryptographically addressed LoRa mesh protocol look like with proper security and clean architecture as primary design goals? Inspired by [MeshCore](https://github.com/meshcore-dev/MeshCore), it started as a thought experiment addressing the [critical shortcomings](https://darconeous.github.io/umsh/docs/protocol/meshcore-comparison.html#cryptography) in that protocol that would practically require backward-incompatible changes to fix. What began as a toy protocol has since been developed into a [comprehensive specification](https://darconeous.github.io/umsh/docs/protocol/), reference implementation, and iOS app.

> [!NOTE]
> Practically all of the content in this repository was written with the assistance of an LLM.
> For more details, see [`docs/AI.md`](docs/AI.md). This project would not exist without
> LLM coding assistance, as the amount of work required to write this by hand would be too much
> for me to dedicate to unpaid work.
>
> It has taken considerable effort to get it to this point. If you'd like tag along
> for the ride and see where this ends up going, follow the project on github to see
> updates. I'd also love to hear your feedback!

---

## What makes UMSH interesting

### Public-key node identity

Nodes are identified by Ed25519 public keys — the key is simultaneously the network address
and the cryptographic credential, with no numeric IDs, no registration, and no central
authority. On the wire, compact 3-byte hints keep per-packet overhead small; the full key
appears only when needed (first contact, ephemeral identities).

### Cryptography suited to mesh constraints

UMSH uses an AES-SIV-inspired construction where the authentication tag serves as the
encryption nonce. If a frame counter is accidentally reused (e.g., after a reboot with no
persistent storage), the only consequence is detectable plaintext repetition — confidentiality
and authenticity are otherwise preserved. Replay protection uses a monotonic counter rather
than timestamps. Keys are derived via HKDF with domain separation, producing independent
encryption and authentication keys from each ECDH shared secret.

### Channel keys serve two roles

A shared channel key enables symmetric-key multicast. It also enables *blind unicast*: a
unicast packet that resembles multicast traffic on the wire, concealing sender and recipient
identities from anyone without the key. The payload is protected by a key derived from both
the channel key and the pairwise shared secret, so only the intended recipient can read it.

### Composable routing

Source routes, flood hop counts, and trace-route accumulation are independent packet options
that can be freely combined. A packet can source-route to a specific region and then flood
locally from there. Path discovery is not a separate operation — it falls out of normal packet
exchange when the trace-route option is present.

### Minimal mandatory state

Basic operation requires only a node's own keypair and configured channel keys — no path
tables, no clock synchronization. The Rust implementation is `no_std` (although `alloc` is still required at this point), and every packet fits in a single LoRa frame. Perfect forward secrecy is available via ephemeral node identities.


---

## What's in this repository

| Path | Description |
|---|---|
| [`docs/protocol/`](docs/protocol/) | Full mdBook specification for the protocol, including comparisons and test vectors |
| [`docs/hardware/`](docs/hardware/) | Per-board hardware references — pin maps, power, radio and display wiring |
| [`crates/`](crates/) | Layered `no_std` Rust library crates implementing the protocol stack |
| [`umsh/`](umsh/) | Integration crate with runtime adapters and runnable examples; builds the `umshctl` host tool |
| [`firmware/`](firmware/) | nRF52840 device firmware — one shipping image per board, plus per-board bringup consoles |
| [`firmware-esp32/`](firmware-esp32/) | Separate workspace for Espressif boards, which need the Xtensa toolchain |
| [`apps/ios/`](apps/ios/) | SwiftUI iOS application |
| [`packages/UMSHMobileCore`](packages/) | UniFFI Swift package wrapping the Rust core for the app |
| [`tools/`](tools/) | Browser-based ULCP protocol debugger and the UniFFI binding generator |
| [`dissectors/`](dissectors/) | Wireshark Lua dissector, fixtures, and dissector-specific tests |

### Protocol specification

The [`docs/protocol/`](docs/protocol/) directory contains the full UMSH specification as an
[mdBook](https://rust-lang.github.io/mdBook/). It covers the MAC layer, all packet types,
cryptographic constructions, routing, application protocols, and appendices including
protocol comparisons and test vectors. A rendered version is available at
<https://darconeous.github.io/umsh/docs/protocol/>.

### Reference implementation

The [`crates/`](crates/) directory contains a `no_std` Rust implementation organized as a
set of layered library crates, from primitive types (`umsh-core`) up through cryptography,
the MAC layer, node state, and application protocols. The [`umsh/`](umsh/) integration crate
bundles these together and adds Tokio and Embassy runtime adapters, along with examples
including a two-node desktop chat and a simulated multi-hop mesh. Published Rust API docs
are available at <https://darconeous.github.io/umsh/docs/rust/>.

### `umshctl`, the host tool

`umshctl` is the command-line tool for working with a UMSH radio over BLE or USB serial:
inspection, provisioning, device identity, persistence, pairing, radio configuration, and
packet capture. It attaches administratively, so pointing it at an autonomously operating
board never disturbs that board. It runs one-shot commands or opens an interactive shell,
and it is built from the [`umsh/`](umsh/) crate — see
[Manage a radio with `umshctl`](#manage-a-radio-with-umshctl) below.

### Device firmware

The [`firmware/`](firmware/) directory holds the nRF52840 device firmware. There is **one
shipping image per board** — a repeater and a companion radio are the same image holding
different configuration, applied over the local control protocol — alongside a per-board
console harness used during bringup. Espressif boards live in
[`firmware-esp32/`](firmware-esp32/), a separate workspace because the Xtensa targets need
their own Rust toolchain.

| Board | MCU | Flash with |
|---|---|---|
| Seeed SenseCAP T1000-E | nRF52840 | `make flash-t1000e` |
| LilyGO T-Echo | nRF52840 | `make flash-techo` |
| SenseCAP Solar Node P1 / P1-Pro | nRF52840 | `make flash-sensecap-solar` |
| Seeed Wio Tracker L1 / L1 Pro | nRF52840 | `make flash-wio-tracker-l1` |
| Heltec WiFi LoRa 32 V3 | ESP32-S3 | `make flash-heltec-v3` |

Board pin maps and electrical details are in [`docs/hardware/`](docs/hardware/); the
architecture and the recipe for adding a board are in
[docs/firmware-architecture.md](docs/firmware-architecture.md). Build and flash through the
Makefile rather than invoking cargo and the image converters by hand — nRF52840 firmware
links only in release mode, and each image needs its board's UF2 base address.

### iOS application

[`apps/ios/`](apps/ios/) is a SwiftUI application that pairs with a companion radio over
BLE for direct messaging and network inspection. It talks to the same Rust implementation
through [`packages/UMSHMobileCore`](packages/), a UniFFI-generated Swift package.

### Wireshark dissector

The [`dissectors/`](dissectors/) directory contains a Lua plugin for Wireshark 4.x that
dissects and annotates UMSH packets captured from a live network or loaded from a pcap file.
When keys are provided, it can also verify MICs and decrypt payloads for unicast, multicast,
and blind unicast packets. See [dissectors/README.md](dissectors/README.md) for details.

---

## Getting started

### Build and run the desktop chat example

First, generate identities and print the public keys:

```sh
cargo run --example desktop_chat --features tokio-support -- \
    --identity .umsh/alice.identity --print-public-key

cargo run --example desktop_chat --features tokio-support -- \
    --identity .umsh/bob.identity --print-public-key
```

Then, in two separate terminals, start each node with the other's public key:

```sh
# Terminal 1 (Alice)
cargo run --example desktop_chat --features tokio-support -- \
    --identity .umsh/alice.identity --peer <BOB_PUBLIC_KEY>

# Terminal 2 (Bob)
cargo run --example desktop_chat --features tokio-support -- \
    --identity .umsh/bob.identity --peer <ALICE_PUBLIC_KEY>
```

Type a message and press enter to send. The chat also supports `/pfs <minutes>`
to start a perfect forward secrecy session, `/pfs status` to check PFS state,
and `/pfs end` to tear it down.

### Use the interactive CLI

The `cli_udp` example provides a full-featured REPL over a UDP multicast fake-radio. It
supports every operation a developer would want to exercise: unicast messaging, pings, PFS
sessions, channel join/send/leave, statistics, and live log-level changes.

Start two nodes, each with its own identity file. The identity is created automatically on
first run; the local public key is printed in the banner:

```sh
# Terminal 1 (Alice)
cargo run --example cli_udp --features cli -- \
    --identity .umsh/alice.identity

# Terminal 2 (Bob)
cargo run --example cli_udp --features cli -- \
    --identity .umsh/bob.identity
```

Both nodes join the same multicast group (`239.255.42.42:7373` by default) and will hear each
other's traffic automatically. Copy Alice's hex public key from her banner and register it
on Bob's side:

```
/peer add <ALICE_HEX_KEY> alice
```

Then send a message:

```
/msg alice hello from Bob
```

Or set Alice as the current peer and send bare text:

```
/query alice
hello from Bob
```

**Commonly used commands:**

| Command | Description |
|---|---|
| `/help [cmd]` | List all commands, or show help for one |
| `/whoami` | Print the local public key |
| `/peer add <key> [alias]` | Register a peer; key can be hex, base58, or base64 |
| `/peer rm <peer>` | Remove a peer |
| `/peers` | List known peers and their status |
| `/query <peer>` | Set the default peer for bare-text sends |
| `/msg <peer> <text>` | Send a unicast text message |
| `/ping <peer> [bytes]` | Send an echo request and print round-trip time |
| `/pfs start <peer> [minutes]` | Initiate a perfect forward secrecy session |
| `/pfs end <peer>` | Tear down a PFS session |
| `/pfs status [peer]` | Show PFS state |
| `/beacon` | Broadcast a beacon |
| `/channel join <name> <key>` | Join a multicast channel |
| `/channel send <name> <text>` | Send to a channel |
| `/channel leave <name>` | Leave a channel |
| `/stats` | Show TX/RX counters, RSSI, pending pings, and event queue depth |
| `/log <level>` | Change log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `/set [var [val]]` | Show or mutate per-session settings (`flood_hops`, `ack_requested`, `show_hex`) |
| `/raw <peer> <hex>` | Send raw payload bytes |
| `/quit` | Exit |

Peers can also be pre-registered on the command line with `--peer <key>[:alias]`, which
accepts the same key formats as `/peer add`. The `--group` and `--port` flags override the
default multicast address and port if you need to run isolated sessions on the same machine.

### Manage a radio with `umshctl`

`umshctl` is the host tool for a ULCP radio device: inspection, provisioning, device
identity, persistence, pairing, radio configuration, and packet capture. It attaches
administratively, using the non-resetting handshake, so pointing it at an autonomously
operating board never disturbs the board — only the command given changes anything.

```sh
cargo build -p umsh --bin umshctl --features serial-radio,ble-radio
```

Given a command it runs that command and exits:

```sh
umshctl --ble="UMSH T-Echo" info
umshctl --port /dev/cu.usbmodem101 phy on
```

Given none, it opens a shell against a single attachment — worth a great deal over BLE,
where every fresh attach costs a discovery pass plus a handshake:

```
$ umshctl
discovered: UMSH T-Echo
attached: UMSH T-Echo (ble) device=techo/0.1 boot_status=RESET_POWER_ON mode=administrative
umshctl — `help` lists commands, `exit` leaves.
UMSH T-Echo (ble)> repeater on
repeater on (on-board node forwards overheard frames)
saved: changes persist across reboots
UMSH T-Echo (ble)> scan
UMSH T-Echo (ble)> connect 2
UMSH T-1000E (ble)> exit
```

With no connection flag the tool finds a radio itself over BLE: the saved default first
(`default set`), then a two-second scan, offering a numbered choice when several answer.
A serial port is used only when you name one with `--port` or `UMSHCTL_PORT` — identifying
a ULCP device over serial means opening the port and speaking to it, and opening a port can
reset or DFU-trigger hardware that is not a ULCP radio at all.

Mutations persist automatically (`CMD_SAVE`) unless you pass `--no-save`. Tab completion,
`help <command>`, and persistent history come from the same command tree the one-shot
grammar uses.

### Capture live LoRa and ULCP traffic

`umshctl capture` prints every frame a radio receives, with elapsed time, RSSI, SNR, raw
bytes, and an attempted UMSH header decode. Traffic from another protocol is retained and
labeled as not a valid UMSH packet rather than discarded. With no RF flags it listens on
whatever the radio is already configured for, so pointing it at a working node does not
disturb that node.

Before connecting a computer to a board for the first time, put that board into pairing
mode — on boards with a display, from its BLE menu. Stop any serial ULCP tool and
disconnect other BLE-central apps such as nRF Connect; only one host session can own the
radio at a time. Then run, from the repository root:

```sh
cargo run -p umsh --bin umshctl --features ble-radio -- capture
```

With no connection flag the tool discovers a radio itself: one match is used, and several
offer a numbered choice. If more than one ULCP device is nearby, select the board by its
advertised name — each advertises as `UMSH <board>`, such as `UMSH T-Echo`:

```sh
cargo run -p umsh --bin umshctl --features ble-radio -- \
    --ble="UMSH T-1000E" capture
```

Pairing is mediated by the operating system; enter the device's six-digit BLE PIN if
prompted. On Linux, enable a `bluetoothctl` agent and pair/trust the device beforehand if
the automatic subscription is rejected. To verify advertising without connecting or
provoking pairing, use the bounded passive scanner:

```sh
cargo run -p umsh --example ulcp_probe --features ble-radio -- --scan-ble
```

Naming any RF parameter overrides the radio's configuration for the session — written live,
never saved, and reported as a change:

```sh
cargo run -p umsh --bin umshctl --features ble-radio -- \
    --ble="UMSH T-1000E" capture \
    --freq-khz=910525 --bw-hz=62500 --sf=7 --cr=5 --sync-word=0x1424
```

During RF silence the tool probes channel RSSI every 10 seconds and prints an
`idle ... link=ok` line, confirming the BLE connection, command session, and radio runner
are all still responding rather than leaving a packet count apparently frozen. On failure it
reconnects and preserves cumulative counters. Use `--umsh-only` to suppress per-frame output
for traffic that does not parse as a UMSH packet.

Write a Wireshark-readable pcap with `--pcap=PATH`. The default captures over-the-air radio
frames; `--layers=ulcp` instead records the complete Spinel-inspired host/device frame
exchange, and `--layers=both` records both:

```sh
cargo run -p umsh --bin umshctl --features ble-radio -- \
    capture --pcap=techo.pcap --layers=both --umsh-only
```

Portable captures use synthetic Ethernet/IPv4/UDP encapsulation. Radio packets use UDP port
4242 and work with the existing UMSH dissector. ULCP frames use directional ports
4243/4244 and the ULCP dissector included in the same plugin, which exposes transaction
IDs, commands, properties, stream envelopes, radio metadata, and nested UMSH packets.
ULCP captures are diagnostic artifacts and may contain sensitive property values or
application traffic; handle them accordingly before sharing.

For a byte-for-byte LoRa payload capture under a private pcap link type, add `--pcap-raw`
with `--layers=radio` and a numeric `--pcap-linktype`. Raw mode adds no per-packet header
and does not mix capture layers, so Wireshark must have a dissector configured for that
link type.

Use `capture --help` for the complete option list, including the idle-probe interval and
reconnect behavior. Press Ctrl-C to stop the dump — inside the shell that returns to the
prompt, having flushed the pcap and left promiscuous mode. A timeout while subscribing to
Frame Out usually means the computer is not bonded and the board's pairing window has
closed; reopen pairing and retry. If discovery finds no device, ensure the board is awake
and that neither a serial host session nor another BLE central is attached.

### Inspecting packets with Wireshark

Since the desktop chat uses UDP multicast, you can capture traffic in real time
with Wireshark. Start a capture on the loopback interface with the display filter
`udp.port == 7373`, and the UMSH dissector will automatically detect and decode
packets. To decrypt payloads, extract both identity files as hex keys:

```sh
xxd -p -c 32 .umsh/alice.identity
xxd -p -c 32 .umsh/bob.identity
```

Add both as `privkey` entries in the UMSH decryption key table
(Edit > Preferences > Protocols > UMSH). See
[dissectors/README.md](dissectors/README.md) for full setup instructions.

### Build the protocol specification

```sh
mdbook build docs/protocol/
```

The rendered book is also available online at
<https://darconeous.github.io/umsh/docs/protocol/>.

### Run tests

```sh
cargo test
lua dissectors/tests/run_tests.lua   # Wireshark dissector unit tests (Lua 5.3+)
```

---

## Protocol comparisons

The specification includes detailed point-by-point comparisons with
[MeshCore](https://darconeous.github.io/umsh/docs/protocol/meshcore-comparison.html),
[Meshtastic](https://darconeous.github.io/umsh/docs/protocol/meshtastic-comparison.html),
and [Reticulum](https://darconeous.github.io/umsh/docs/protocol/reticulum-comparison.html).

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
