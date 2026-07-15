# UMSH

**UMSH** is an experimental, LoRa-oriented mesh protocol designed from the ground up with strong cryptography, clean layer separation, and strict bandwidth discipline.

Originally intended as a proposal for a "MeshCore 2.0", UMSH grew out of a simple question: what would a cryptographically addressed LoRa mesh look like with security and clean architecture as primary design goals? Inspired by MeshCore, it started as a thought experiment addressing the [critical shortcomings](https://darconeous.github.io/umsh/docs/protocol/meshcore-comparison.html#cryptography) in that protocol that would practically require backward-incompatible changes to fix. What began as a toy protocol has since been developed into a [comprehensive specification](https://darconeous.github.io/umsh/docs/protocol/).

> [!NOTE]
> All of the content in this repository was written with the assistance of an LLM.
> In the case of the [specification](https://darconeous.github.io/umsh/docs/protocol/),
> LLM usage was largely limited to improving readability and acting as a research
> assistant when writing the comparison documents.
>
> The reference implementation and the Wireshark dissector were more or less written
> by the LLM, with heavy feedback from [me](https://github.com/darconeous), mostly
> around API ergonomics and the occasional WTF moments that come with working with a
> coding LLM(if you know, you know). The reference code seems to be at reasonable starting
> point and there are plenty of test cases already implemented. However, there are still
> code-smells and anti-patterns that need to be addressed.
>
> That said, I don't consider this AI slop. I've put dozens of hours into this project,
> and it has taken considerable effort to get it to this point. If you'd like tag along
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
| [`crates/`](crates/) | Layered `no_std` Rust library crates implementing the protocol stack |
| [`umsh/`](umsh/) | Integration crate with runtime adapters and runnable examples |
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

### Capture live LoRa and companion-protocol traffic

The `umsh-capture` tool connects to a T-Echo or T-1000E NCP over BLE, configures and enables its
LoRa radio, and prints every received frame with elapsed time, RSSI, SNR, raw bytes, and an
attempted UMSH header decode. Traffic from another protocol is retained and labeled as not a
valid UMSH packet rather than discarded.

On the T-Echo, choose **Start Pairing** from the BLE menu before connecting a computer for the
first time. Stop any serial companion-radio tool and disconnect other BLE-central apps such as
nRF Connect; only one companion session can own the NCP at a time. Then run, from the repository
root:

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- --ble
```

If more than one Companion Link device is nearby, select the board by its advertised name:

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- \
    --ble "UMSH T-1000E NCP"
```

The T-Echo advertises as `UMSH T-Echo NCP`.

To verify advertising without connecting or provoking pairing, use the bounded passive scanner:

```sh
cargo run -p umsh --example companion_probe --features ble-radio -- --scan-ble
```

Pairing is mediated by the operating system. Enter the NCP's configured six-digit BLE PIN
if prompted. The protected subscription allows up to 90 seconds for the pairing UI and PIN
entry, independently of the shorter timeout used by ordinary GATT operations. On Linux, enable
a `bluetoothctl` agent and pair/trust the device before running the dumper if the automatic
subscription is rejected.

The default RF profile is 910.525 MHz, LoRa SF7, 62.5 kHz bandwidth, coding rate 4/5, and sync
word `0x1424`. Each parameter can be overridden explicitly:

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- \
    --ble "UMSH T-1000E NCP" \
    --freq-khz=910525 --bw-hz=62500 --sf=7 --cr=5 --sync-word=0x1424
```

While no frames arrive, the dumper performs a live channel-RSSI probe every 10 seconds and
prints an `idle ... link=ok` line. This is expected during RF silence and confirms that the BLE
connection, NCP command session, and radio runner are still responding. If one of those layers
stalls or disconnects, the probe reports a specific error instead of leaving a packet count
apparently frozen. On a BLE write failure, the diagnostic includes the platform backend's
`is_connected` result and bounded disconnect-cleanup result. The dumper then rediscovers and
reconnects after two seconds by default, preserves cumulative time/packet counters, and prints a
new session number plus the NCP's retained boot status. This recovery is deliberately local to
the diagnostic tool; normal stateful users of `CompanionRadio` still receive the failure.

Change the probe interval with `--idle-probe-secs=N`, change recovery delay with
`--reconnect-delay-secs=N`, or use `--no-reconnect` to exit on the first failed session.
Use `--umsh-only` to suppress per-frame output for traffic that does not parse as a UMSH
packet; idle/recovery diagnostics and periodic received/displayed/filtered progress counters
remain visible even when the channel is busy with foreign traffic.

Write a Wireshark-readable pcap with `--pcap=PATH`. The default captures
over-the-air radio frames; `--capture=companion` instead records the complete
Spinel-inspired host/NCP frame exchange, while `--capture=both` records both layers:

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- \
    --ble --pcap=techo.pcap --capture=both --umsh-only
```

Portable captures use synthetic Ethernet/IPv4/UDP encapsulation. Radio packets use UDP port
4242 and work with the existing UMSH dissector. Companion frames use directional ports
4243/4244 and the companion dissector included in the same plugin, which exposes transaction
IDs, commands, properties, stream envelopes, radio metadata, and nested UMSH packets.
Companion captures are diagnostic artifacts and may contain sensitive property values or
application traffic; handle them accordingly before sharing.

For an exact byte-for-byte LoRa payload capture under a private or experimental pcap link type,
select radio-only raw mode and supply the numeric `LINKTYPE` value (decimal or `0x` hex):

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- \
    --ble --pcap=raw-lora.pcap --capture=radio \
    --pcap-raw --pcap-linktype=147
```

Raw mode adds no per-packet header and deliberately does not mix capture layers. Wireshark must
have a dissector configured for the chosen private `LINKTYPE` value.

Use `--help` for the complete option list. Press Ctrl-C to stop the dump. A timeout while
subscribing to Frame Out usually means the computer is not bonded and the T-Echo's pairing
window is closed; select **Start Pairing** and retry. If discovery finds no device, ensure the
T-Echo is awake and that neither a serial companion session nor another BLE central is attached.

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
