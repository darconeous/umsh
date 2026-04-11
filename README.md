# UMSH

**UMSH** is an experimental, LoRa-oriented mesh protocol designed from the ground up with strong cryptography, clean layer separation, and strict bandwidth discipline.

Originally intended as a proposal for a "MeshCore 2.0", UMSH grew out of a simple question: what would a cryptographically addressed LoRa mesh look like with security and clean architecture as primary design goals? Inspired by MeshCore, it started as a thought experiment addressing the [critical shortcomings](https://darconeous.github.io/umsh/docs/protocol/meshcore-comparison.html#cryptography) in that protocol that would practically require backward-incompatible changes to fix. What began as a toy protocol has since been developed into a [comprehensive specification](https://darconeous.github.io/umsh/docs/protocol/).

> *Note*
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
    --identity .umsh/alice.identity \
    --udp 239.255.42.42:4242 --peer <BOB_PUBLIC_KEY>

# Terminal 2 (Bob)
cargo run --example desktop_chat --features tokio-support -- \
    --identity .umsh/bob.identity \
    --udp 239.255.42.42:4242 --peer <ALICE_PUBLIC_KEY>
```

Type a message and press enter to send. The chat also supports `/pfs <minutes>`
to start a perfect forward secrecy session, `/pfs status` to check PFS state,
and `/pfs end` to tear it down.

### Inspecting packets with Wireshark

Since the desktop chat uses UDP multicast, you can capture traffic in real time
with Wireshark. Start a capture on the loopback interface with the display filter
`udp.port == 4242`, and the UMSH dissector will automatically detect and decode
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
