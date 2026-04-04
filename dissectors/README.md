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

Without keys, the dissector shows the raw wire structure but cannot verify MICs
or decrypt payloads. To enable full decryption:

1. Go to **Edit > Preferences > Protocols > UMSH**
2. Click the **Decryption Keys** button to open the key table editor

### Decryption Keys table (Wireshark 4.6+)

The key table has three columns:

| Column | Description |
|---|---|
| **type** | One of: `pubkey`, `privkey`, or `channel` |
| **key** | Hex key (64 hex chars), or `umsh:cs:<name>` for named channels |
| **label** | Human-readable display name |

Example rows:

| type | key | label |
|---|---|---|
| `pubkey` | `ED54A59FB1AC3A51...` | Alice |
| `privkey` | `1112131415161718...` | MyNode |
| `channel` | `5A5A5A5A5A5A5A5A...` | TestChannel |
| `channel` | `umsh:cs:public` | Public |

Key types:
- **pubkey** — maps a 32-byte Ed25519 public key to a display name (annotates
  source/destination hints, no decryption)
- **privkey** — a 32-byte Ed25519 seed used for unicast and blind unicast
  decryption
- **channel** — a 32-byte symmetric channel key used for multicast and blind
  unicast decryption; alternatively `umsh:cs:<name>` for well-known named
  channels

### Fallback for Wireshark < 4.6

On older Wireshark versions, the key table is not available. Instead, three
separate string preferences are shown:

| Preference | Format |
|---|---|
| **Node names** | `<64-hex-pubkey>:<name>` (one per line) |
| **Private keys** | `<64-hex-ed25519-seed>:<name>` (one per line) |
| **Channel keys** | `<64-hex-key>:<name>` or `umsh:cs:<name>:<label>` (one per line) |

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

## Test Vectors

The `test_vectors.pcap` file contains all 8 protocol test-vector packets
wrapped as UDP payloads on port 4242. Open it in Wireshark with the dissector
installed to verify the plugin is working. To regenerate it:

```sh
python3 dissectors/make_test_pcap.py dissectors/test_vectors.pcap
```

## Running Unit Tests

Standalone Lua tests (no Wireshark required, Lua 5.3+):

```sh
lua dissectors/tests/run_tests.lua
```

If `luagcrypt` is installed, the tests also cover HKDF, AES-CMAC, AES-CTR,
key derivation, and full encrypt/decrypt round-trips against the protocol
test vectors. Without `luagcrypt`, crypto tests are skipped.

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
