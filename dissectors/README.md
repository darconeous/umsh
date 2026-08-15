# UMSH Wireshark Dissector

A Lua plugin for [Wireshark](https://www.wireshark.org/) that dissects, annotates,
and (when keys are provided) decrypts UMSH mesh network packets.

Requires **Wireshark 4.x** or later (Lua 5.3+).

## Installation

Copy or symlink the `umsh/` directory into your Wireshark personal plugins folder:

| OS | Path |
|---|---|
| macOS | `~/.config/wireshark/plugins/` |
| Linux | `~/.local/lib/wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |

For example, on macOS:

```sh
mkdir -p ~/.config/wireshark/plugins
ln -s "$(pwd)/dissectors/umsh" ~/.config/wireshark/plugins/umsh
```

Restart Wireshark (or **Analyze > Reload Lua Plugins**) to load the dissector.

From a checkout, `make install-dissector` does the same thing with the right
path for the platform.

## Live Capture from a Radio

`make install-extcap` installs `umshctl` as a Wireshark
[extcap](https://www.wireshark.org/docs/man-pages/extcap.html) interface, so a
radio appears in Wireshark's interface list and a capture is a double-click.
It also installs `umshctl` and the dissector, since a capture is useless
without both.

The interface's gear icon opens the capture options: which radio to attach to
(**Reload** scans for BLE radios), a serial port to use instead, and live-only
RF overrides. The RF override fields are empty by default and left empty mean
"capture on whatever the radio is already tuned to" — filling one in changes
the live PHY for the duration of the capture, and is never saved to the device.

Frames arrive as [LoRaTap](https://github.com/eriknl/LoRaTap) (`LINKTYPE` 270),
which carries the frequency, bandwidth, spreading factor, sync word, RSSI, and
SNR the radio reported, so the reception metadata survives into the capture.

> On macOS, Wireshark.app declares no Bluetooth usage description, so a BLE
> capture started from the Wireshark GUI may be denied by the OS with no
> prompt. Name a serial port in the capture options to sidestep it, or run
> `tshark -i umsh` from a terminal.

## Capturing from the UDP Multicast Pseudo-Radio

The `UdpMulticastRadio` transport sends raw UMSH frames over IPv4 multicast
with no additional framing. Wireshark can capture these directly from the
loopback or LAN interface.

### 1. Start a capture on the right interface

The `desktop_chat` example binds to `0.0.0.0` and joins a multicast group
on the loopback interface by default. To capture this traffic:

- Open Wireshark and start a capture on **Loopback** (macOS/Linux: `lo0` / `lo`).
- Alternatively, if your application is configured for a LAN interface, capture
  on that interface instead.

### 2. Apply a capture or display filter (optional)

If you know the UDP port your application uses, filter to just that traffic:

```
udp.port == 4242
```

Replace `4242` with whatever port you passed to `--udp`.

### 3. Let heuristic detection find UMSH packets

The dissector registers a **UDP heuristic** that automatically identifies UMSH
packets by inspecting the first byte (FCF version field = `0b11`, valid packet
type, and minimum length check). No manual configuration is needed for basic
dissection — UMSH packets in any UDP stream will be detected and decoded
automatically.

If the heuristic isn't triggering (e.g. another dissector claims the port first),
you can force it by setting the UDP port in the UMSH preferences:

1. Go to **Edit > Preferences > Protocols > UMSH**
2. Set **UDP Port** to the port your application uses (e.g. `4242`)

### 4. Example: two-node desktop_chat session

In two terminals, start a chat pair over UDP multicast:

```sh
# Terminal 1 — print public key, then run
cargo run --example desktop_chat --features tokio-support -- --print-public-key
cargo run --example desktop_chat --features tokio-support -- \
    --udp 239.255.42.42:4242 --peer <TERMINAL_2_PUBLIC_KEY>

# Terminal 2
cargo run --example desktop_chat --features tokio-support -- --print-public-key
cargo run --example desktop_chat --features tokio-support -- \
    --udp 239.255.42.42:4242 --peer <TERMINAL_1_PUBLIC_KEY>
```

In Wireshark, capture on loopback with filter `udp.port == 4242`. You should
see UMSH packets appear in real time with decoded FCF, packet type, addresses,
SECINFO, and MIC fields.

## Enabling Decryption

The `public` and `emergency` channels need no configuration. Both derive their
keys from names the spec fixes, so the keys are public knowledge by
construction and the dissector carries them: emergency traffic has its MIC
verified and public traffic is decrypted out of the box. Adding either channel
by hand still works and keeps whatever label you give it.

Everything else needs keys. Without them the dissector shows the raw wire
structure but cannot verify MICs or decrypt payloads. To enable full
decryption:

1. Go to **Edit > Preferences > Protocols > UMSH**
2. Click the **Decryption Keys** button to open the key table editor

### Decryption Keys table (Wireshark 4.6+)

The key table has three columns:

| Column | Description |
|---|---|
| **type** | One of: `pubkey`, `privkey`, or `channel` |
| **key** | The key, in any form below |
| **label** | Human-readable display name |

Key types:
- **pubkey** — maps a 32-byte Ed25519 public key to a display name (annotates
  source/destination hints, no decryption)
- **privkey** — a 32-byte Ed25519 seed used for unicast and blind unicast
  decryption
- **channel** — a 32-byte symmetric channel key used for multicast and blind
  unicast decryption

#### Key formats

A key may be written any of these ways, in the key table and in the
preference strings and key files alike. Hex and base58 are told apart by
length, the same rule `PublicKey::FromStr` uses in the reference
implementation, so an address copied from `umshctl`, the phone app, or this
dissector's own display pastes straight in.

| Form | Example | Valid for |
|---|---|---|
| 64 hex characters | `ED54A59FB1AC3A51…` | all three types |
| 44 base58 characters | `GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU` | all three types |
| `umsh:n:<44-base58>` | `umsh:n:GySVDr1omr3GTodg…` | `pubkey` |
| `umsh:ck:<44-base58>` | `umsh:ck:75hbt6uvDqjPZ9Wg…` | `channel` |
| `umsh:cs:<name>` | `umsh:cs:public` | `channel` (derives the key from the name) |

URI `?k=v` parameters are ignored, so a scanned QR code works unedited. A URI
of the wrong kind is refused rather than read as the wrong sort of key.

Example rows:

| type | key | label |
|---|---|---|
| `pubkey` | `GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU` | Alice |
| `privkey` | `1112131415161718...` | MyNode |
| `channel` | `5A5A5A5A5A5A5A5A...` | TestChannel |
| `channel` | `umsh:cs:public` | Public |

### Fallback for Wireshark < 4.6

On older Wireshark versions, the key table is not available. Instead, three
separate string preferences are shown:

| Preference | Format |
|---|---|
| **Node names** | `<key>:<name>` (one per line) |
| **Private keys** | `<key>:<name>` (one per line) |
| **Channel keys** | `<key>:<name>` or `umsh:cs:<name>:<label>` (one per line) |

`<key>` takes any of the forms in [Key formats](#key-formats) above. The label
is optional.

### Extracting keys from desktop_chat

To decrypt traffic from the `desktop_chat` example, add the 32-byte Ed25519
seed (the raw contents of the `.umsh/desktop-chat.identity` file) as a
`privkey` entry. Convert the identity file to hex with:

```sh
xxd -p -c 32 .umsh/desktop-chat.identity
```

When keys are configured correctly, the dissector will:

- Show a **MIC: Valid** annotation (green) on authenticated packets
- Decrypt encrypted payloads and show the plaintext in the packet tree
- Resolve encrypted source addresses in E=1 multicast and blind unicast
- Parse application-layer content (text messages, MAC commands, node identity)

## Key File

For convenience, keys can also be stored in a text file and loaded via the
**Key File** preference. The file uses an INI-like format:

```ini
[nodes]
ED54A59FB1AC3A512393513629...:<display-name>

[privkeys]
1112131415161718191A1B1C1D...:<display-name>

[channels]
5A5A5A5A5A5A5A5A5A5A5A5A...:<display-name>
```

## Protocol Violations

Frames that break a prohibition the spec states as a sender MUST NOT, and that
a single frame is enough to prove, are reported three ways: as a
`umsh.violation` field carrying the text, as error-severity expert info, and as
a `[VIOLATION]` marker on the summary line. What is checked includes reserved
bits that must be zero, payload types carried by a packet type that may not
carry them (a broadcast echo request, say), the requirements the `public` and
`emergency` channels attach to their names, and the flood-management rules for
a broadcast Identity Request.

A channel ID is a 2-byte hint of a key and the spec permits collisions, so a
finding that rests on one says "channel identified by ID only" until the MIC
verifies under that channel's key and settles which channel it really is.

To colour those frames — red background, white text — install the coloring
rule:

```sh
make install-colorfilters
```

A Lua dissector cannot colour a packet-list row on its own, which is why this
is a separate step; the `umsh.violation` field exists for the rule to match on.
The target seeds a personal rule set from Wireshark's stock rules if you have
none, puts the UMSH rule at the top (rules are first-match-wins), and does
nothing if it is already installed. To do it by hand instead, import
`dissectors/umsh/umsh-colorfilters` from **View > Coloring Rules > Import** and
drag it above the transport rules. `umsh.violation` also works as an ordinary
display filter for pulling every offending frame out of a capture.

## Test Vectors

The `test_vectors.pcap` file contains all 8 protocol test-vector packets
wrapped as UDP payloads on port 4242. Open it in Wireshark with the dissector
installed to verify the plugin is working. Every frame in it is valid, and the
bytes are the ones in `docs/protocol/src/test-vectors.md`. To regenerate it:

```sh
python3 dissectors/make_test_pcap.py dissectors/test_vectors.pcap
```

`violations.pcap` is the counterpart: deliberately non-conformant frames that
exercise the violation reporting and the application-layer summary lines.
Nothing in it is a reference for how to build a packet. Most of its frames are
broadcasts, which carry no MIC and so let the application dissectors run with
no key configured.

```sh
python3 dissectors/make_violation_pcap.py dissectors/violations.pcap
```

## ULCP Capture Files

The `umshctl capture` command can write classic pcap files directly from a serial or BLE ULCP
device. Its portable encoding uses synthetic Ethernet/IPv4/UDP records so one file can contain
both over-the-air LoRa packets and the underlying Spinel-inspired ULCP conversation:

```sh
cargo run -p umsh --bin umsh-capture --features ble-radio -- \
    --ble --pcap=techo.pcap --capture=both
```

Radio frames use UDP port 4242 and are handled by the main UMSH dissector. ULCP frames use
ports 4243 (host) and 4244 (device) and are handled by the included `UMSH ULCP`
dissector. Display filters include `umsh`, `umsh.ulcp`,
`umsh.ulcp.command`, and `umsh.ulcp.property`.
ULCP pcaps may expose sensitive property values and application traffic and should be
treated as diagnostic secrets when stored or shared.

`--pcap-raw --pcap-linktype=N` writes exact LoRa frame bytes under a caller-selected pcap
`LINKTYPE`; it requires `--capture=radio`. This is intended for private/experimental link types
whose Wireshark encapsulation is configured outside this plugin. For a raw capture that needs
no such configuration, prefer the extcap interface above: LoRaTap is a registered link type
this dissector already recognizes, and it carries the reception metadata a bare frame cannot.

## Running Unit Tests

Standalone Lua tests (no Wireshark required, Lua 5.3+):

```sh
lua dissectors/tests/run_tests.lua
```

If `luagcrypt` is installed, the tests also cover HKDF, AES-CMAC, AES-CTR,
key derivation, and full encrypt/decrypt round-trips against the protocol
test vectors. Without `luagcrypt`, crypto tests are skipped locally; CI
builds `luagcrypt` and fails if any assertion reports SKIP, so the crypto
vectors are always exercised there.

## Supported Packet Types

| Type | Name | Decryption |
|---|---|---|
| 0 | BCST (Broadcast/Beacon) | N/A (no crypto) |
| 1 | UACK (MAC Ack) | N/A (no crypto) |
| 2 | UNIC (Unicast) | Private key required |
| 3 | UNAR (Unicast Ack-Req) | Private key required |
| 4 | MCST (Multicast) | Channel key required |
| 6 | BUNI (Blind Unicast) | Channel key + private key required |
| 7 | BUAR (Blind Unicast Ack-Req) | Channel key + private key required |

## Supported Payload Types

Once a payload is readable, the protocol column names the application protocol
carried and the summary line gets a one-line précis of it.

| Type | Name | Protocol column |
|---:|---|---|
| 1 | Node Identity | `UMSH-ID` |
| 2 | MAC Command | `UMSH-MC` |
| 3 | Text Message | `UMSH-TC` |
| 5 | Chat-Room Message | `UMSH-CR` |
| 7 | CoAP-over-UMSH | `CoAP` (from the built-in CoAP dissector) |
| 8 | Node Management Request | `UMSH-NM` |
| 9 | Node Management Response | `UMSH-NM` |

Node Management payloads carry one ULCP frame each, which is handed to the same
frame dissector the local-link ULCP capture uses. The payload type is the
direction, so the summary line reads the exchange as a request or a response
and pairs it with the token.

## MAC Options

All twelve options in the spec's Defined Options table are decoded. Trace
Route and Source Route break out their router hints per hop; Trace Signal
breaks out the RSSI and SNR each repeater recorded; Region Code and the two
callsign options are ARNCE-decoded.

An Ack MIC option (8) is a MAC ack piggy-backed onto a reply instead of sent
as its own packet, so it is resolved to the frame it acknowledges the same
way a standalone ack is — by the public four-byte MIC prefix, which needs no
keys. The acknowledged frame is linked in the tree and named on the summary
line.

## Address Presentation

Addresses render in the canonical forms from the addressing chapter: a full
32-byte key as its 44 base58 digits, and a hint in the star-truncated form,
with the bytes it was read from alongside — `GySV (ED:54:A5)` for a node hint,
`Gy* (ED:54)` for a router hint. Characters before the star are ones every key
matching that hint would produce; the star marks where the hint stops proving
anything. `umsh.src_addr` and `umsh.dst_addr` carry the canonical text for
filtering, and the address columns use it whenever no keystore name is known.
