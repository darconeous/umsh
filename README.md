![UMSH Logo](docs/logo/umsh-logo-orange-sm.png)

\[ [`umsh.dev`](https://umsh.dev)
| [Protocol Book](https://darconeous.github.io/umsh/docs/protocol/)
| [Rustdocs](https://darconeous.github.io/umsh/docs/rust/)
\]

**UMSH** is an experimental, LoRa-oriented mesh protocol designed from the ground up with strong cryptography, clean layer separation, and strict bandwidth discipline. The primary use case it enables is decentralized, wide-area text chat and location/sensor reporting.

Originally intended as a proposal for a "[MeshCore](https://github.com/meshcore-dev/MeshCore) 2.0", UMSH grew out of a simple question: what would a cryptographically addressed LoRa mesh protocol look like with proper security and clean architecture as primary design goals? Inspired by [MeshCore](https://github.com/meshcore-dev/MeshCore), it started as a thought experiment addressing the [critical shortcomings](https://darconeous.github.io/umsh/docs/protocol/meshcore-comparison.html#cryptography) in that protocol that would practically require backward-incompatible changes to fix. What began as a toy protocol has since been developed into a [comprehensive specification](https://darconeous.github.io/umsh/docs/protocol/), reference implementation, firmware for seven boards, and an iOS app.

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

UMSH uses AES-SIV (RFC 5297) with AES-256, in which the authentication tag serves as the
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
tables, no clock synchronization. The Rust implementation is `no_std` (although `alloc` is
still required at this point), and every packet fits in a single LoRa frame. Perfect forward
secrecy is available via ephemeral node identities.

### Built to be inspected

The wire format was designed alongside its tooling. A Wireshark dissector decodes and
decrypts UMSH frames, `umshctl` installs as a Wireshark capture interface so a radio in the
mesh is a double-click away, and the host/device control protocol is captured and dissected
on the same footing as the radio traffic.

---

## What's in this repository

| Path | Description |
|---|---|
| [`docs/protocol/`](docs/protocol/) | Full mdBook specification for the protocol, including comparisons and test vectors |
| [`docs/hardware/`](docs/hardware/) | Per-board hardware references — pin maps, power, radio and display wiring |
| [`crates/`](crates/) | Layered `no_std` Rust library crates implementing the protocol stack |
| [`umsh/`](umsh/) | Integration crate with runtime adapters and runnable examples |
| [`firmware/`](firmware/) | nRF52840 device firmware — one shipping image per board |
| [`firmware-esp32/`](firmware-esp32/) | Separate workspace for Espressif boards, which need the Xtensa toolchain |
| [`apps/ios/`](apps/ios/) | SwiftUI iOS application |
| [`packages/UMSHMobileCore`](packages/) | UniFFI Swift package wrapping the Rust core for the app |
| [`tools/`](tools/) | Host binaries — the `umshctl` radio tool and the `umsh-bridge` internet bridge — plus the browser-based ULCP debugger and the UniFFI binding generator |
| [`dissectors/`](dissectors/) | Wireshark Lua dissector, fixtures, and dissector-specific tests |
| [`site/`](site/) | Sources for [umsh.dev](https://umsh.dev) |

The [`docs/protocol/`](docs/protocol/) directory holds the specification as an
[mdBook](https://rust-lang.github.io/mdBook/): the MAC layer, all packet types, cryptographic
constructions, routing, application protocols, and appendices including protocol comparisons
and test vectors. [`crates/`](crates/) implements it as a set of layered `no_std` libraries,
from primitive types (`umsh-core`) up through cryptography, the MAC layer, node state, and
application protocols; [`umsh/`](umsh/) bundles those together and adds Tokio and Embassy
runtime adapters. Rendered copies of both are published at
<https://darconeous.github.io/umsh/docs/protocol/> and
<https://darconeous.github.io/umsh/docs/rust/>.

---

## Getting started

### What you need

A Rust toolchain, plus `arm-none-eabi-objcopy` from the GNU Arm Embedded toolchain if you
intend to flash an nRF52840 board. Espressif boards need their own compiler:
`cargo install espup espflash && espup install`.

Host builds and tests come from the workspace root and deliberately skip `firmware/*`:

```sh
cargo test
```

### Install the host tools

```sh
make install-umshctl
```

That is `cargo install --path tools/umshctl`, so `umshctl` lands in `~/.cargo/bin`.
The Wireshark integration has its own targets, covered below.

### Flash a board

| Board | MCU | Flash with |
|---|---|---|
| Seeed SenseCAP T1000-E | nRF52840 | `make flash-t1000e` |
| LilyGO T-Echo | nRF52840 | `make flash-techo` |
| SenseCAP Solar Node P1 / P1-Pro | nRF52840 | `make flash-sensecap-solar` |
| Seeed Wio Tracker L1 / L1 Pro | nRF52840 | `make flash-wio-tracker-l1` |
| Seeed XIAO nRF52840 + Wio-SX1262 | nRF52840 | `make flash-xiao-nrf52` |
| Heltec WiFi LoRa 32 V3 | ESP32-S3 | `make flash-heltec-v3` |
| LilyGO T-Beam Supreme (SX1262) | ESP32-S3 | `make flash-tbeam-supreme` |

The two Espressif boards are the odd ones out: Xtensa chips need a Rust fork rustup does
not carry, installed once per machine with `cargo install espup espflash && espup install`
([firmware-esp32/README.md](firmware-esp32/README.md)). Their `make` targets check for that
first and say what to run, so a machine without it fails before the build rather than
inside it.

There is **one shipping image per board**: a repeater and a phone companion are the same
firmware holding different configuration, applied afterwards over BLE or USB. Flash through
the Makefile rather than invoking cargo and the image converters by hand — nRF52840 firmware
links only in release mode, and each image needs its board's UF2 base address and family ID,
both of which fail silently when wrong.

The board must be in DFU mode first, and how you get there differs per board; the
[flashing page on umsh.dev](https://umsh.dev/flasher/) and
[`docs/hardware/`](docs/hardware/) cover each one. Board architecture and the recipe for
adding a new board are in [docs/firmware-architecture.md](docs/firmware-architecture.md).

### Talk to a radio with `umshctl`

`umshctl` is the host tool for a UMSH radio over BLE or USB serial: inspection, device
identity, persistence, pairing, radio configuration, and packet capture. It attaches
administratively, using the non-resetting handshake, so pointing it at an autonomously
operating board never disturbs that board — only the command you give changes anything.

Given a command it runs that command and exits:

```sh
umshctl --ble="UMSH T-Echo" info
umshctl --port /dev/cu.usbmodem101 phy on
```

Given none, it opens a shell against a single attachment — worth a great deal over BLE, where
every fresh attach costs a discovery pass plus a handshake:

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
(`default set`), then a two-second scan, offering a numbered choice when several answer. Each
board advertises as `UMSH <board>`, such as `UMSH T-Echo`, which is what `--ble=` matches. A
serial port is used only when you name one with `--port` or `UMSHCTL_PORT` — identifying a
device over serial means opening the port and speaking to it, and opening a port can reset or
DFU-trigger hardware that is not a UMSH radio at all.

Mutations persist automatically (`CMD_SAVE`) unless you pass `--no-save`. Tab completion,
`help <command>`, and persistent history come from the same command tree the one-shot grammar
uses.

Before connecting a computer to a board for the first time, put that board into pairing mode —
on boards with a display, from its BLE menu. Pairing is mediated by the operating system;
enter the device's six-digit BLE PIN if prompted. On Linux, enable a `bluetoothctl` agent and
pair/trust the device beforehand if the automatic subscription is rejected. Only one host
session can own a radio at a time, so stop any serial tool and disconnect other BLE centrals
such as nRF Connect first.

### Watch the mesh in Wireshark

```sh
make install-extcap
make install-colorfilters
```

`install-extcap` installs `umshctl` as a Wireshark
[extcap](https://www.wireshark.org/docs/man-pages/extcap.html) interface, and pulls in the
tool and the Lua dissector along with it, since a capture is useless without both. A radio
then shows up in Wireshark's interface list as **UMSH radio** and a capture is a double-click;
from a terminal it is `tshark -i umsh`. The interface's gear icon chooses which radio to
attach to, a serial port to use instead, and live-only RF overrides — filling in an override
changes the PHY for the duration of the capture and is never saved to the device. Frames
arrive as [LoRaTap](https://github.com/eriknl/LoRaTap) (`LINKTYPE` 270), carrying the
frequency, bandwidth, spreading factor, sync word, RSSI, and SNR the radio reported.

`install-colorfilters` adds the rule that inverts protocol violations in the packet list; it
seeds from Wireshark's stock rules rather than replacing them. The dissector decodes and
annotates UMSH packets from a live capture or a pcap file, and when keys are provided it
verifies MICs and decrypts unicast, multicast, and blind unicast payloads. Full setup,
including the key tables, is in [dissectors/README.md](dissectors/README.md).

> On macOS, Wireshark.app declares no Bluetooth usage description, so a BLE capture started
> from the Wireshark GUI may be denied by the OS with no prompt. Name a serial port in the
> capture options to sidestep it, or run `tshark -i umsh` from a terminal.

`umshctl capture` is the same capture as a terminal dump: every frame the radio receives with
elapsed time, RSSI, SNR, raw bytes, and an attempted UMSH header decode. Traffic from another
protocol is retained and labeled rather than discarded, and `--umsh-only` suppresses it.
During RF silence the tool probes channel RSSI every 10 seconds and prints an
`idle ... link=ok` line, so a quiet mesh is distinguishable from a dead link.

Write a file with `--pcap=PATH`. The default records over-the-air radio frames; `--layers=ulcp`
instead records the complete Spinel-inspired host/device frame exchange, and `--layers=both`
records both:

```sh
umshctl capture --pcap=techo.pcap --layers=both
```

These captures use synthetic Ethernet/IPv4/UDP encapsulation: radio packets on UDP port 4242,
and ULCP frames on directional ports 4243/4244 for the ULCP dissector in the same plugin,
which exposes transaction IDs, commands, properties, stream envelopes, radio metadata, and
nested UMSH packets. ULCP captures are diagnostic artifacts and may contain sensitive property
values or application traffic; handle them accordingly before sharing. For a byte-for-byte
payload capture under a private pcap link type, add `--pcap-raw` with `--layers=radio` and a
numeric `--pcap-linktype`.

### Run the iOS app

[`apps/ios/`](apps/ios/) is a SwiftUI application that pairs with a companion radio over BLE
for direct messaging, chat rooms, mapping, and network inspection. It talks to the same Rust
implementation through [`packages/UMSHMobileCore`](packages/), a UniFFI-generated Swift
package that `make ios-mobile-core` builds. See [apps/ios/README.md](apps/ios/README.md).

### Build the documentation

```sh
make docs        # protocol book -> docs/protocol/book/
make docs-serve  # live-reloading preview
make rust-docs   # cargo doc for the whole workspace
```

---

## Developing without hardware

The [`umsh/`](umsh/) crate ships examples that run the real stack over a UDP multicast
pseudo-radio, so a mesh can be exercised on one machine with no boards involved.

`cli_udp` is a REPL covering the operations a developer wants to poke at — unicast messaging,
pings, PFS sessions, channel join/send/leave, statistics, and live log-level changes. Start
two nodes with their own identity files, which are created on first run; each prints its
public key in the banner:

```sh
cargo run --example cli_udp --features cli -- --identity .umsh/alice.identity
cargo run --example cli_udp --features cli -- --identity .umsh/bob.identity
```

Both join the same multicast group (`239.255.42.42:7373` by default) and hear each other
automatically. Register the other side's key and send a message:

```
/peer add <ALICE_HEX_KEY> alice
/msg alice hello from Bob
```

`/help` lists the rest. Peers can be pre-registered with `--peer <key>[:alias]`, and
`--group`/`--port` isolate concurrent sessions on one machine. `desktop_chat` is the smaller,
two-node version of the same idea, and `simulated_repeater_delivery` runs a multi-hop mesh
under the Embassy adapter.

Because the transport is plain UDP, Wireshark can watch it directly: capture on loopback with
the display filter `udp.port == 7373` and the dissector's UDP heuristic will find the frames.
To decrypt, add both identity files as `privkey` entries in the UMSH key table
(**Edit > Preferences > Protocols > UMSH**):

```sh
xxd -p -c 32 .umsh/alice.identity
```

The dissector has its own test suite, which needs no Wireshark:

```sh
lua dissectors/tests/run_tests.lua
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
