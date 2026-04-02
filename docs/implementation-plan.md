# UMSH Rust Implementation Plan

## Crate Structure

```
umsh/                              # Cargo workspace
  crates/
    umsh-core/                     # Wire format, types, encoding, zero-copy parsing/building
    umsh-crypto/                   # Crypto traits, UMSH operations, software backend
    umsh-hal/                      # Platform abstraction traits (radio, storage, timer, RNG)
    umsh-mac/                      # MAC layer: processing, repeater, routing, acks
    umsh-app/                      # Application protocols: text, chat rooms, identity, MAC cmds
    umsh-node/                     # High-level node: peer DB, sessions, beacons, route mgmt
  umsh/                            # Umbrella crate (re-exports)
  examples/
    repeater/                      # Embassy-based repeater firmware
    desktop-chat/                  # Tokio-based desktop chat client
```

### Dependency Graph

```
umsh-hal                           (no workspace deps — pure hardware abstraction)
umsh-core                          (no workspace deps)
umsh-crypto     -> umsh-core
umsh-mac        -> umsh-core, umsh-crypto, umsh-hal
umsh-app        -> umsh-core, umsh-crypto (optional, for signatures)
umsh-node       -> umsh-core, umsh-crypto, umsh-hal, umsh-mac, umsh-app
umsh            -> all of the above + defines Platform trait
```

### External Dependencies

| Crate         | Role                         | Notes                                     |
|---------------|------------------------------|-------------------------------------------|
| `lwuri`       | URI parsing (`umsh:`, `coap-umsh:` schemes) | `no_std`, zero-copy, your crate  |
| `hamaddr`     | ARNCE/HAM-64 callsign encoding | Behind `amateur-radio` feature; fixed-size encode/decode path must work without `alloc` (see note below) |
| `bs58`        | Base58 encoding for keys in URIs | `no_std`-capable                      |
| `heapless`    | Fixed-capacity collections for `no_std` | Used throughout for buffers, caches  |
| `aes`, `cmac`, `ctr` | RustCrypto AES primitives | Behind `software-crypto` feature     |
| `ed25519-dalek`, `x25519-dalek` | RustCrypto curve ops | Behind `software-crypto` feature |
| `hkdf`, `sha2` | RustCrypto HKDF-SHA256      | Behind `software-crypto` feature          |
| `zeroize`     | Secure memory erasure        | Required for PFS, shared secrets          |

### Feature Flags (Workspace-Wide Conventions)

```toml
[features]
default = ["std", "software-crypto"]
std = ["alloc"]
alloc = []
software-crypto = []       # RustCrypto-based software backend
amateur-radio = []         # ARNCE callsigns, ham mode support
chat-rooms = []            # Chat room protocol
```

---

## Crate Details

### `umsh-core` --- Wire Format, Types, Encoding

The foundational crate. Pure data types and byte-level encoding. No crypto, no I/O,
no async. Everything here is `no_std` without `alloc`.

#### Key Types

```rust
/// Frame Control Field (1 byte).
#[derive(Clone, Copy)]
pub struct Fcf(u8);

impl Fcf {
    pub fn version(self) -> u8;
    pub fn packet_type(self) -> PacketType;
    pub fn full_source(self) -> bool;       // S flag
    pub fn options_present(self) -> bool;   // O flag
    pub fn flood_hops_present(self) -> bool; // H flag
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Broadcast       = 0,
    MacAck          = 1,
    Unicast         = 2,
    UnicastAckReq   = 3,
    Multicast       = 4,
    Reserved5       = 5,
    BlindUnicast    = 6,
    BlindUnicastAckReq = 7,
}

/// Security Control Field (1 byte).
#[derive(Clone, Copy)]
pub struct Scf(u8);

impl Scf {
    pub fn encrypted(self) -> bool;     // E flag
    pub fn mic_size(self) -> MicSize;
    pub fn salt_present(self) -> bool;  // S flag
    pub fn reserved_valid(self) -> bool; // must be zero
}

#[derive(Clone, Copy)]
pub enum MicSize { Mic4 = 0, Mic8 = 1, Mic12 = 2, Mic16 = 3 }

impl MicSize {
    pub const fn byte_len(self) -> usize; // 4, 8, 12, or 16
}

/// Flood hop count (1 byte, split nibbles).
#[derive(Clone, Copy)]
pub struct FloodHops(u8);

impl FloodHops {
    pub fn remaining(self) -> u8;
    pub fn accumulated(self) -> u8;
    pub fn decremented(self) -> Self;
    pub fn new(remaining: u8, accumulated: u8) -> Option<Self>;
}

/// 3-byte node address hint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeHint(pub [u8; 3]);

impl NodeHint {
    pub fn from_public_key(key: &PublicKey) -> Self;
}

/// 2-byte router hint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouterHint(pub [u8; 2]);

impl RouterHint {
    pub fn from_public_key(key: &PublicKey) -> Self;
}

/// 2-byte channel identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; 2]);

/// 32-byte Ed25519 public key (== node address).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn hint(&self) -> NodeHint;
    pub fn router_hint(&self) -> RouterHint;
}

/// 32-byte symmetric channel key.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ChannelKey(pub [u8; 32]);

/// Source address: either a 3-byte hint or a full 32-byte key.
#[derive(Clone, Copy)]
pub enum SourceAddr<'a> {
    Hint(NodeHint),
    Full(&'a PublicKey),
}

impl SourceAddr<'_> {
    pub fn hint(&self) -> NodeHint;
}

/// Decoded SECINFO.
#[derive(Clone, Copy)]
pub struct SecInfo {
    pub scf: Scf,
    pub frame_counter: u32,
    pub salt: Option<u16>,
}

impl SecInfo {
    /// Wire size: 5 or 7 bytes.
    pub fn wire_len(&self) -> usize;
    pub fn encode(&self, buf: &mut [u8]) -> usize;
    pub fn decode(buf: &[u8]) -> Result<Self, ParseError>;
}
```

#### Packet Options

```rust
/// Known packet option types. Unknown options are represented by `Unknown(u16)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OptionNumber {
    RegionCode = 1,
    TraceRoute = 2,
    SourceRoute = 3,
    OperatorCallsign = 4,
    MinRssi = 5,
    StationCallsign = 7,
    MinSnr = 9,
    Unknown(u16),
}

impl OptionNumber {
    pub fn as_u16(self) -> u16;

    /// Bit 0 of the option number: if set, unknown options cause the packet to be dropped.
    pub fn is_critical(self) -> bool { self.as_u16() & 1 != 0 }

    /// Bit 1 of the option number: if set, the option is not covered by the MIC.
    pub fn is_dynamic(self) -> bool { self.as_u16() & 2 != 0 }
}

impl From<u16> for OptionNumber { ... }
```

#### CoAP-Style Option Codec

Reused at both the MAC layer (packet options) and the application layer (text message
options, node identity options, chat room payloads). Lives in `umsh_core::options`.

```rust
pub mod options {
    /// Encodes a sequence of options into a buffer using CoAP delta-length encoding.
    pub struct OptionEncoder<'a> {
        buf: &'a mut [u8],
        pos: usize,
        last_number: u16,
    }

    impl<'a> OptionEncoder<'a> {
        pub fn new(buf: &'a mut [u8]) -> Self;
        pub fn put(&mut self, number: u16, value: &[u8]) -> Result<(), EncodeError>;
        pub fn end_marker(&mut self) -> Result<(), EncodeError>;
        pub fn finish(self) -> usize; // bytes written
    }

    /// Decodes a CoAP-encoded option sequence from a byte slice.
    pub struct OptionDecoder<'a> {
        data: &'a [u8],
        pos: usize,
        last_number: u16,
    }

    impl<'a> Iterator for OptionDecoder<'a> {
        type Item = Result<(u16, &'a [u8]), ParseError>;
    }

    impl<'a> OptionDecoder<'a> {
        pub fn new(data: &'a [u8]) -> Self;
        /// Returns the remainder after the 0xFF end marker (the trailing data).
        pub fn remainder(&self) -> &'a [u8];
    }
}
```

#### Zero-Copy Packet Parsing

The parser reads a raw `&[u8]` from the radio buffer and computes offsets. Small
fixed-size fields (FCF, hints, SECINFO) are copied out into stack values. Variable
fields (options, payload, MIC) are accessed as slices of the original buffer.

The key design constraint is that encrypted packets require mutable access for
in-place decryption. So the parser produces a `PacketHeader` containing copied
header fields, plus offset information that lets the caller index back into
the mutable buffer for crypto operations.

```rust
/// Parsed header fields --- all small, copied to stack. Does not borrow the buffer.
pub struct PacketHeader {
    pub fcf: Fcf,
    pub options_range: Range<usize>,   // byte range of the options field
    pub flood_hops: Option<FloodHops>,

    // Packet-type-specific addressing:
    pub dst: Option<NodeHint>,         // unicast/blind-unicast destination
    pub channel: Option<ChannelId>,    // multicast/blind-unicast channel
    pub ack_dst: Option<[u8; 2]>,      // MAC ack 2-byte destination

    pub source: SourceAddrRef,         // hint or offset+len of full key
    pub sec_info: Option<SecInfo>,

    pub body_range: Range<usize>,      // payload (or ciphertext) byte range
    pub mic_range: Range<usize>,       // MIC byte range (or ack tag for MACK)
    pub total_len: usize,
}

/// Source address as parsed from the header. Full key is referenced by offset,
/// not borrowed, so the header does not hold a reference to the buffer.
pub enum SourceAddrRef {
    Hint(NodeHint),
    FullKeyAt { offset: usize }, // caller reads buf[offset..offset+32]
    Encrypted { offset: usize, len: usize }, // multicast/blind: inside ciphertext
    None,  // MAC ack has no source
}

impl PacketHeader {
    /// Parse a raw packet buffer. Returns the header with computed offsets.
    /// Does not perform any cryptographic verification.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError>;

    pub fn packet_type(&self) -> PacketType;
    pub fn ack_requested(&self) -> bool;
    pub fn is_beacon(&self) -> bool;
}

/// Iterator over the options section. Requires the original buffer.
pub fn iter_options<'a>(buf: &'a [u8], range: Range<usize>) -> OptionDecoder<'a>;

/// Extract specific well-known options for MAC processing.
pub struct ParsedOptions {
    pub region_code: Option<[u8; 2]>,
    pub source_route: Option<Range<usize>>,  // range within buf
    pub trace_route: Option<Range<usize>>,
    pub min_rssi: Option<i16>,
    pub min_snr: Option<i8>,
    pub has_unknown_critical: bool,
}

impl ParsedOptions {
    pub fn extract(buf: &[u8], range: Range<usize>) -> Result<Self, ParseError>;
}
```

#### Packet Building

The builder writes fields into a caller-provided `&mut [u8]` buffer. It lays out
everything *except* the cryptographic finalization (MIC computation, encryption).
This separation allows `umsh-core` to remain crypto-free.

Builders use the **typestate pattern** to enforce correctness at compile time.
The lifecycle is a one-way pipeline of type transitions:

```text
PacketBuilder::new(buf)
    .unicast(dst)              → UnicastBuilder<NeedsSource>    [select packet type]
    .source_hint(hint)         → UnicastBuilder<NeedsCounter>   [set source — exactly once]
    .frame_counter(42)         → UnicastBuilder<Configuring>    [set counter — exactly once]
    .encrypted()               → Self                           [header settings, any order]
    .trace_route()             → Self                           [options, must be in order]
    .flood_hops(4)             → Self                           [header settings, any order]
    .payload(&data)            → UnicastBuilder<Complete>       [terminal — no more options]
    .build()                   → Result<UnsealedPacket<'a>>     [finalize]
```

Each phase offers only the methods valid at that point. The type system prevents:
- Setting source twice (method only exists on `NeedsSource`)
- Calling `encrypted()` on a broadcast (method doesn't exist on `BroadcastBuilder`)
- Adding options after payload (method doesn't exist on `Complete`)
- Calling `build()` before required fields are set (method doesn't exist on `NeedsSource`)

**Option ordering** is enforced at **runtime**: the builder tracks the last option
number written and returns `BuildError::OptionOutOfOrder` if the next option number
is not strictly greater (or equal, for repeatable options). The typed option methods
(`region_code`, `trace_route`, `source_route`, etc.) are documented in their
natural increasing order (1, 2, 3, 4, 5, 7, 9) so correct usage is the obvious
pattern.

```rust
// Typestate markers — zero-sized, exist only at the type level.
pub mod state {
    pub struct NeedsSource;
    pub struct NeedsCounter;
    pub struct Configuring;
    pub struct Complete;
}

/// Entry point. Selects the packet type and transitions to the appropriate builder.
pub struct PacketBuilder<'a> { buf: &'a mut [u8] }

impl<'a> PacketBuilder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self;

    pub fn broadcast(self) -> BroadcastBuilder<'a, NeedsSource>;
    pub fn mac_ack(self, dst: RouterHint, ack_tag: [u8; 8]) -> MacAckBuilder<'a, Configuring>;
    pub fn unicast(self, dst: NodeHint) -> UnicastBuilder<'a, NeedsSource>;
    pub fn multicast(self, channel: ChannelId) -> MulticastBuilder<'a, NeedsSource>;
    pub fn blind_unicast(self, channel: ChannelId, dst: NodeHint)
        -> BlindUnicastBuilder<'a, NeedsSource>;
}
```

**Broadcast** — source only, no crypto:

```rust
pub struct BroadcastBuilder<'a, S> { /* ... */ }

impl<'a> BroadcastBuilder<'a, NeedsSource> {
    pub fn source_hint(self, hint: NodeHint) -> BroadcastBuilder<'a, Configuring>;
    pub fn source_full(self, key: &PublicKey) -> BroadcastBuilder<'a, Configuring>;
}

impl<'a> BroadcastBuilder<'a, Configuring> {
    // Header settings (any order, last-write-wins)
    pub fn flood_hops(self, remaining: u8) -> Self;

    // Options (must be added in increasing option number order)
    pub fn region_code(self, code: RegionCode) -> Self;       // option 1
    pub fn trace_route(self) -> Self;                          // option 2
    pub fn source_route(self, hops: &[RouterHint]) -> Self;    // option 3
    pub fn operator_callsign(self, call: &HamAddr) -> Self;    // option 4
    pub fn station_callsign(self, call: &HamAddr) -> Self;     // option 7
    pub fn option(self, number: OptionNumber, value: &[u8]) -> Self;

    // Terminal — no payload (beacon) or set payload then build.
    pub fn payload(self, data: &[u8]) -> BroadcastBuilder<'a, Complete>;
    pub fn build(self) -> Result<&'a [u8], BuildError>;  // empty payload
}

impl<'a> BroadcastBuilder<'a, Complete> {
    pub fn build(self) -> Result<&'a [u8], BuildError>;
}
```

**Unicast** — requires source + frame counter, has crypto settings:

```rust
pub struct UnicastBuilder<'a, S> { /* ... */ }

impl<'a> UnicastBuilder<'a, NeedsSource> {
    pub fn source_hint(self, hint: NodeHint) -> UnicastBuilder<'a, NeedsCounter>;
    pub fn source_full(self, key: &PublicKey) -> UnicastBuilder<'a, NeedsCounter>;
}

impl<'a> UnicastBuilder<'a, NeedsCounter> {
    pub fn frame_counter(self, counter: u32) -> UnicastBuilder<'a, Configuring>;
}

impl<'a> UnicastBuilder<'a, Configuring> {
    // Header settings (any order)
    pub fn ack_requested(self) -> Self;
    pub fn encrypted(self) -> Self;
    pub fn mic_size(self, size: MicSize) -> Self;
    pub fn salt(self, salt: u16) -> Self;
    pub fn flood_hops(self, remaining: u8) -> Self;

    // Options (increasing order enforced at runtime)
    pub fn region_code(self, code: RegionCode) -> Self;
    pub fn trace_route(self) -> Self;
    pub fn source_route(self, hops: &[RouterHint]) -> Self;
    pub fn operator_callsign(self, call: &HamAddr) -> Self;
    pub fn min_rssi(self) -> Self;  // option 5, default threshold
    pub fn station_callsign(self, call: &HamAddr) -> Self;
    pub fn min_snr(self) -> Self;   // option 9, default threshold
    pub fn option(self, number: OptionNumber, value: &[u8]) -> Self;

    // Terminal
    pub fn payload(self, data: &[u8]) -> UnicastBuilder<'a, Complete>;
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError>;
}

impl<'a> UnicastBuilder<'a, Complete> {
    pub fn build(self) -> Result<UnsealedPacket<'a>, BuildError>;
}
```

**Multicast** and **BlindUnicast** follow the same `NeedsSource → NeedsCounter →
Configuring → Complete` pipeline with type-appropriate methods. BlindUnicast omits
`encrypted()` (always encrypted) and adds nothing else beyond the common set.

**MAC Ack** has all required fields in its constructor and is born in `Configuring`.
It has no crypto settings, no source, and no payload.

**Usage examples:**

```rust
// Beacon (broadcast, no payload)
let packet = PacketBuilder::new(&mut buf)
    .broadcast()
    .source_hint(my_hint)
    .build()?;

// First-contact encrypted unicast with trace route
let unsealed = PacketBuilder::new(&mut buf)
    .unicast(peer_hint)
    .source_full(&my_pubkey)
    .frame_counter(next_counter)
    .encrypted()
    .mic_size(MicSize::Mic16)
    .trace_route()
    .flood_hops(4)
    .payload(&app_data)
    .build()?;
let sealed = crypto.seal(unsealed, &pairwise_keys)?;

// Compile errors for misuse:
//   .broadcast().source_full(&k).source_hint(h)   // source_hint doesn't exist on Configuring
//   .unicast(dst).source_hint(h).build()           // build doesn't exist on NeedsCounter
//   .unicast(dst).source_hint(h).frame_counter(1).payload(d).trace_route()
//                                                             ^^^^^^^^^^^ doesn't exist on Complete
//   .broadcast().source_hint(h).encrypted()        // encrypted doesn't exist on BroadcastBuilder
```

**Internal implementation note:** The builder accumulates header settings (flags,
flood hops, MIC size, etc.) in struct fields and writes options into the buffer
incrementally via the CoAP option encoder. During `build()`, the FCF byte is
finalized, and all fields are laid out in wire order. This avoids intermediate
allocations while preserving the incremental-write property for options.

#### UnsealedPacket

Produced by the secured builders (unicast, multicast, blind unicast). Handed off
to `umsh-crypto` for MIC computation and optional encryption.

```rust
/// A fully laid-out packet whose MIC is not yet computed and payload not yet encrypted.
pub struct UnsealedPacket<'a> {
    buf: &'a mut [u8],
    total_len: usize,
    body_range: Range<usize>,    // plaintext payload (to be encrypted if E=1)
    mic_range: Range<usize>,     // reserved space for MIC
    sec_info_range: Range<usize>,
    aad_static_options: Range<usize>, // for AAD construction
}

impl<'a> UnsealedPacket<'a> {
    pub fn header(&self) -> PacketHeader;
    pub fn body(&self) -> &[u8];
    pub fn body_mut(&mut self) -> &mut [u8];
    pub fn mic_slot(&mut self) -> &mut [u8];
    pub fn as_bytes(&self) -> &[u8];
    pub fn total_len(&self) -> usize;
}
```

#### AAD Construction

The spec defines specific AAD rules (FCF, re-encoded static options, DST/CHANNEL,
SRC when outside ciphertext, SECINFO). Rather than assembling the AAD into a
contiguous buffer (which wastes stack or heap), the AAD components are fed
incrementally into whatever hash/MAC state the caller provides. Each component is
at most a few bytes; re-encoded static options are fed as individual TLV triples.

The feeder accepts any `FnMut(&[u8])` sink, keeping `umsh-core` crypto-agnostic:

```rust
/// Feed AAD components incrementally into `sink`, in the order specified
/// by the UMSH security spec. The sink will be called once per component:
/// FCF, each static option (as absolute TLV), DST/CHANNEL, SRC (if outside
/// ciphertext), and SECINFO.
///
/// The caller wraps their CMAC state (or any hash/MAC) behind the closure.
pub fn feed_aad(
    header: &PacketHeader,
    packet_buf: &[u8],
    sink: impl FnMut(&[u8]),
);
```

Typical usage inside `CryptoEngine::seal_packet` / `open_packet`:

```rust
let mut cmac = CmacState::new(&self.aes, k_mic);
feed_aad(&header, packet_buf, |chunk| cmac.update(chunk));
cmac.update(plaintext);
let full_mac = cmac.finalize();
```

No intermediate buffer. Each `sink` call receives a small borrowed slice
(1 byte for FCF, 4 bytes for an option TLV header — 2-byte big-endian number
followed by 2-byte big-endian length — then the option value slice,
2–3 bytes for DST, etc.).

#### Packet Forwarding

Forwarding is a **third packet-construction path** alongside parsing and building.
It takes a received packet and produces a modified copy for retransmission, without
touching the payload or MIC. Because crypto in UMSH is end-to-end, a repeater never
re-seals the packet — the MAC layer cryptographically blinds only per-hop metadata.

**Static vs. dynamic options.** The AAD covers only *static* options (those not
modified by repeaters). The four per-hop mutations all touch *dynamic* fields:

| Field / Option | Mutation |
|---|---|
| Flood hops (header field) | Decrement `FHOPS_REM`, increment `FHOPS_ACC` |
| Source route (option 3) | Pop the leading `RouterHint`; omit option if emptied |
| Trace route (option 2) | Prepend own `RouterHint` before existing entries |
| Station callsign (option 7) | Replace (or insert, if absent) with repeater's callsign |

Because dynamic options are not authenticated, none of these mutations require
re-computing the MIC. The payload and MIC bytes are copied verbatim.

**Why re-encode rather than patch in place.** Options use CoAP-style delta encoding:
each option header encodes the *delta* from the previous option number. Prepending
two bytes to the trace-route value shifts the length field for that option and may
also shift the delta for the *next* option. Popping two bytes from source route has
the same effect in reverse. Re-encoding the options section from a parsed
representation is simpler and less error-prone than in-place byte manipulation.
Header fields outside the options block (flood hops, addresses, SECINFO) are
small and fixed-size, so they can be patched in place on the copied header.

**API:**

```rust
/// Parameters for a single forwarding rewrite.
pub struct ForwardParams {
    /// This repeater's 2-byte router hint, prepended to the trace-route option
    /// (if present in the source packet).
    pub router_hint: RouterHint,
    /// If `Some`, replace or insert option 7 (station callsign) with this value.
    /// Required when `amateur_mode` is true.
    pub station_callsign: Option<HamAddr>,
}

/// Rewrites a parsed packet into a TX buffer for forwarding.
///
/// Constructed from references to the RX buffer and its parsed metadata.
/// `write()` copies the packet into `dst`, applying per-hop mutations.
///
/// The payload and MIC are copied verbatim — no crypto operations are performed.
pub struct PacketForwarder<'src, 'dst> {
    src: &'src [u8],
    dst: &'dst mut [u8],
    header: &'src PacketHeader,
    options: &'src ParsedOptions,
}

impl<'src, 'dst> PacketForwarder<'src, 'dst> {
    pub fn new(
        src: &'src [u8],
        dst: &'dst mut [u8],
        header: &'src PacketHeader,
        options: &'src ParsedOptions,
    ) -> Self;

    /// Perform the forwarding rewrite. Returns the number of bytes written to `dst`.
    ///
    /// Steps:
    /// 1. Copy the fixed header fields; patch flood-hop counts in place.
    /// 2. Re-encode the options section, applying mutations:
    ///    - Option 2 (trace route): prepend `router_hint` before existing entries.
    ///    - Option 3 (source route): skip the first 2-byte `RouterHint`; omit
    ///      the option entirely if that was the only entry.
    ///    - Option 7 (station callsign): replace with `params.station_callsign`
    ///      if `Some`; copy verbatim if `None`.
    ///    - All other options: copy verbatim, re-encoding deltas for any length
    ///      changes caused by the mutations above.
    /// 3. Copy payload and MIC verbatim from `src`.
    pub fn write(self, params: &ForwardParams) -> Result<usize, ForwardError>;
}

pub enum ForwardError {
    /// The destination buffer is too small to hold the forwarded packet.
    /// (Trace-route prepend grows the packet by 2 bytes per hop.)
    BufferTooSmall,
    /// The packet has exhausted all forwarding budget: no remaining flood hops
    /// and no source-route hints remaining. The MAC coordinator checks this
    /// before constructing the `PacketForwarder`.
    NotForwardable,
}
```

**Forwarding eligibility** is checked by the MAC coordinator *before* constructing a
`PacketForwarder`, not inside `write`. Eligibility criteria (remaining hops, region
match, min-RSSI/SNR, duplicate cache, amateur-mode callsign availability) belong in
the MAC policy layer. `PacketForwarder` is a mechanical rewriter and assumes the
caller has already decided that forwarding should occur.

**Buffer sizing.** The TX buffer must accommodate the original packet plus at most
+2 bytes (one prepended trace-route `RouterHint`). If `station_callsign` is inserted
where none existed before, the packet grows by the encoded option TLV size (~4 bytes).
The MAC coordinator allocates TX buffers large enough for the worst case.

---

### `umsh-crypto` --- Cryptographic Abstractions and UMSH Operations

Defines crypto traits that abstract over software and hardware implementations.
Provides UMSH-specific key derivation, authentication, and encryption operations
built on those traits. Includes a software backend behind the `software-crypto` feature.

#### Crypto Traits

```rust
/// AES-128 block cipher.
/// Implementations may be software (RustCrypto) or hardware (AES peripheral).
pub trait AesCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]);
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

/// Factory for AES-128 cipher instances keyed with a given 16-byte key.
pub trait AesProvider {
    type Cipher: AesCipher;
    fn new_cipher(&self, key: &[u8; 16]) -> Self::Cipher;
}

/// SHA-256 hashing and HMAC-SHA-256.
pub trait Sha256Provider {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32];
    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32];
}

/// A node's cryptographic identity.
///
/// Abstracts over software keys and hardware security modules.
/// The private key may never be directly accessible.
///
/// `sign` and `agree` are async because hardware-backed implementations
/// (e.g., I2C-attached secure element) may need to yield. Software
/// implementations return immediately.
pub trait NodeIdentity {
    type Error;

    /// The node's Ed25519 public key (its network address).
    fn public_key(&self) -> &PublicKey;

    /// 3-byte address hint, derived from the public key.
    fn hint(&self) -> NodeHint {
        NodeHint::from_public_key(self.public_key())
    }

    /// Ed25519 signature.
    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error>;

    /// X25519 ECDH key agreement. Returns the raw 32-byte shared secret.
    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error>;
}
```

#### UMSH Crypto Engine

Implements all UMSH-specific cryptographic operations using the above traits.
Does not hold a radio or any I/O --- pure crypto.

```rust
/// The core UMSH cryptographic engine.
pub struct CryptoEngine<A: AesProvider, S: Sha256Provider> {
    aes: A,
    sha: S,
}

impl<A: AesProvider, S: Sha256Provider> CryptoEngine<A, S> {
    pub fn new(aes: A, sha: S) -> Self;

    // --- Key derivation ---

    /// Derive stable pairwise K_enc and K_mic from an ECDH shared secret.
    pub fn derive_pairwise_keys(&self, shared_secret: &SharedSecret) -> PairwiseKeys;

    /// Derive channel K_enc, K_mic, and channel_id from a channel key.
    pub fn derive_channel_keys(&self, channel_key: &ChannelKey) -> DerivedChannelKeys;

    /// Derive channel_id alone (for quick lookup).
    pub fn derive_channel_id(&self, channel_key: &ChannelKey) -> ChannelId;

    /// Derive blind unicast payload keys (pairwise XOR channel).
    pub fn derive_blind_keys(
        &self,
        pairwise: &PairwiseKeys,
        channel: &DerivedChannelKeys,
    ) -> PairwiseKeys;

    /// Derive a channel key from a named channel string.
    /// HKDF-Extract-SHA256(salt = "UMSH-CHANNEL-V1", ikm = name_bytes).
    pub fn derive_named_channel_key(&self, name: &str) -> ChannelKey;

    // --- Packet-level operations ---

    /// Seal a packet: compute MIC, encrypt payload if E flag set, write MIC.
    /// Operates in-place on the UnsealedPacket buffer.
    /// Returns the total packet length.
    pub fn seal_packet(
        &self,
        packet: &mut UnsealedPacket<'_>,
        keys: &PairwiseKeys,
    ) -> Result<usize, CryptoError>;

    /// Open a received packet: verify MIC, decrypt if encrypted.
    /// `buf` is the full packet bytes (mutable for in-place decryption).
    /// `header` is the pre-parsed header from `PacketHeader::parse`.
    /// Returns the plaintext payload range on success.
    pub fn open_packet(
        &self,
        buf: &mut [u8],
        header: &PacketHeader,
        keys: &PairwiseKeys,
    ) -> Result<Range<usize>, CryptoError>;

    /// Decrypt the ENC_DST_SRC field of a blind unicast packet.
    /// Uses the channel's K_enc and the packet MIC as IV.
    pub fn decrypt_blind_addr(
        &self,
        buf: &mut [u8],
        header: &PacketHeader,
        channel_keys: &DerivedChannelKeys,
    ) -> Result<(NodeHint, SourceAddr), CryptoError>;

    /// Compute the 8-byte ack tag from the full 16-byte CMAC and K_enc.
    pub fn compute_ack_tag(
        &self,
        full_cmac: &[u8; 16],
        k_enc: &[u8; 16],
    ) -> [u8; 8];

    // --- Low-level building blocks (exposed for testing / advanced use) ---

    /// Create an incremental AES-CMAC state for the given key.
    pub fn cmac_state(&self, key: &[u8; 16]) -> CmacState<A::Cipher>;

    /// AES-CMAC over concatenated slices (convenience wrapper).
    pub fn aes_cmac(&self, key: &[u8; 16], data: &[&[u8]]) -> [u8; 16];

    /// AES-128-CTR encrypt/decrypt in place.
    pub fn aes_ctr(&self, key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]);

    /// Build the CTR IV from MIC and SECINFO per spec.
    pub fn build_ctr_iv(&self, mic: &[u8], sec_info_bytes: &[u8]) -> [u8; 16];

    /// HKDF-SHA256 (extract + expand).
    pub fn hkdf(&self, ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]);
}

/// Stable pairwise keys for a given node pair (or channel).
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PairwiseKeys {
    pub k_enc: [u8; 16],
    pub k_mic: [u8; 16],
}

/// Derived channel keys including the channel identifier.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DerivedChannelKeys {
    pub k_enc: [u8; 16],
    pub k_mic: [u8; 16],
    pub channel_id: ChannelId,
}

/// Incremental AES-CMAC computation. Fed chunk-by-chunk via `update()`,
/// finalized into the full 16-byte tag. No intermediate buffer needed
/// beyond the AES block size (16 bytes) held internally.
pub struct CmacState<C: AesCipher> {
    cipher: C,
    // internal: partial block buffer, subkeys, running state
}

impl<C: AesCipher> CmacState<C> {
    pub fn new(cipher: C) -> Self;

    /// Feed arbitrary-length data. May be called any number of times.
    pub fn update(&mut self, data: &[u8]);

    /// Consume the state and return the full 16-byte CMAC tag.
    pub fn finalize(self) -> [u8; 16];
}
```

#### Software Backend

Behind `#[cfg(feature = "software-crypto")]`, using RustCrypto crates.

```rust
#[cfg(feature = "software-crypto")]
pub mod software {
    pub struct SoftwareAes;
    impl AesProvider for SoftwareAes { ... }

    pub struct SoftwareSha256;
    impl Sha256Provider for SoftwareSha256 { ... }

    /// A software node identity holding an Ed25519 keypair in memory.
    pub struct SoftwareIdentity {
        secret: ed25519_dalek::SigningKey,  // zeroize on drop
        public: PublicKey,
    }

    impl SoftwareIdentity {
        pub fn generate(rng: &mut impl Rng) -> Self;
        pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self;
    }

    impl NodeIdentity for SoftwareIdentity { ... }

    /// Convenience alias.
    pub type SoftwareCryptoEngine = CryptoEngine<SoftwareAes, SoftwareSha256>;
}
```

---

### `umsh-hal` --- Platform Abstraction Traits

Minimal crate defining async traits for hardware interaction. No workspace
dependencies. Radio driver crates and storage backends depend on this alone.

```rust
#![no_std]

/// Metadata from a received radio frame.
pub struct RxInfo {
    pub len: usize,
    pub rssi: i16,   // dBm (negative, e.g. -120)
    pub snr: i8,     // dB
}

/// Radio hardware abstraction.
pub trait Radio {
    type Error;

    /// Transmit raw bytes over the air.
    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Receive a frame into `buf`. Returns metadata including actual length.
    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error>;

    /// Channel Activity Detection. Returns `true` if the channel is busy.
    async fn cad(&mut self) -> Result<bool, Self::Error>;

    /// Maximum transmittable frame size (typically ~255 for LoRa).
    fn max_frame_size(&self) -> usize;

    /// Estimated on-air time for a maximum-length frame (T_frame), in milliseconds.
    fn t_frame_ms(&self) -> u32;
}

/// Async delay: use `embedded_hal_async::delay::DelayNs` as the trait bound.
/// Embassy implements it natively. A tokio shim is ~10 lines:
///
/// ```rust
/// pub struct TokioDelay;
/// impl embedded_hal_async::delay::DelayNs for TokioDelay {
///     async fn delay_ns(&mut self, ns: u32) {
///         tokio::time::sleep(Duration::from_nanos(ns as u64)).await;
///     }
/// }
/// ```
///
/// Functions in `umsh-mac` that need to sleep (backoff, contention window,
/// forwarding confirmation) accept `impl DelayNs`.

/// Monotonic clock — no ecosystem standard exists for this, so we define one.
/// Needed for frame counter staleness checks (5-minute rule) and PFS session expiry.
/// On embassy: wraps `embassy_time::Instant`. On std: wraps `std::time::Instant`.
pub trait Clock {
    /// Milliseconds since an arbitrary fixed epoch. Must be monotonically non-decreasing.
    fn now_ms(&self) -> u64;
}

/// Cryptographically suitable random number generator.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);

    fn random_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Random u32 in [0, bound).
    fn random_range(&mut self, bound: u32) -> u32 {
        // Unbiased rejection sampling
        ...
    }
}

/// Persistent frame counter storage.
///
/// Frame counters must survive reboots. Implementations may batch writes
/// or advance by a margin on startup to reduce NVM wear.
pub trait CounterStore {
    type Error;

    /// Load the last persisted counter for a given context key.
    /// Returns 0 if no counter has been stored.
    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error>;

    /// Persist a counter value. May be deferred/batched by the implementation.
    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error>;

    /// Flush any pending writes to durable storage.
    /// Called before deep sleep or shutdown.
    async fn flush(&self) -> Result<(), Self::Error>;
}

/// General-purpose persistent key-value storage.
///
/// Used for peer key cache, routing state, node configuration.
/// Caller provides the output buffer; no allocations required.
pub trait KeyValueStore {
    type Error;

    /// Load a value. Returns `Ok(Some(len))` if found (written into buf),
    /// `Ok(None)` if not found.
    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Store a value.
    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Delete a key.
    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error>;
}
```

Note: the `Platform` trait (which bundles HAL types with crypto types) lives in
the **`umsh` umbrella crate**, not here. `umsh-hal` contains only hardware
abstraction traits with no workspace dependencies, so third-party radio drivers
and storage backends can depend on it alone without pulling in crypto.

---

### `umsh-mac` --- MAC Layer Processing

The MAC layer is the heart of the protocol. It implements the packet processing
pipeline, repeater forwarding, duplicate suppression, channel access, ack handling,
and PFS identity management. All packet-level send/receive flows go through this
crate.

**Terminology used in this section:**

- **Local identity**: an address/keypair active in the MAC, including long-term
  and ephemeral PFS identities. Identified by `LocalIdentityId`.
- **Remote peer**: a learned remote identity with routing and per-local-identity
  crypto state. Identified by `PeerId`.
- **Local endpoint** (in `umsh-node`): application-facing state machine built on
  top of one or more local identities.

#### Duplicate Suppression Cache

The cache key type explicitly mirrors the spec: authenticated packets use the
actual MIC bytes (preserving collision properties of the chosen MIC size);
unauthenticated packets use a local hash.

```rust
/// Cache key for duplicate suppression, reflecting the two cases in the spec.
pub enum DupCacheKey {
    /// Authenticated packets: the on-wire MIC bytes, preserving full entropy.
    Mic { bytes: [u8; 16], len: u8 },
    /// Broadcasts and MAC acks: a locally-computed hash (e.g., CRC-32).
    Hash32(u32),
}

/// Fixed-size ring buffer of recently seen cache keys.
pub struct DuplicateCache<const N: usize = 64> {
    entries: [(DupCacheKey, u64); N],  // (key, timestamp_ms)
    head: usize,
}

impl<const N: usize> DuplicateCache<N> {
    pub fn new() -> Self;
    pub fn contains(&self, key: &DupCacheKey) -> bool;
    pub fn insert(&mut self, key: DupCacheKey, now_ms: u64);
}
```

#### Replay Detection

The spec's backward-window behavior depends on a recent-MIC cache plus a
5-minute staleness bound. The bitmap tracks which counter slots in the backward
range have been used; the MIC cache provides the actual replay-vs-collision
check for late-arriving packets within those slots.

Note: the per-peer MIC cache is distinct from the per-radio `DuplicateCache`.
Duplicate suppression is a repeater-level mechanism (prevents re-forwarding);
replay detection is per-(local identity, remote peer) and prevents accepting
the same packet twice at the application level.

```rust
/// Per-traffic-direction replay detection state.
pub struct ReplayWindow {
    last_accepted: u32,
    last_accepted_time_ms: u64,
    /// Bitmap tracking which counter slots in the backward window are occupied.
    backward_bitmap: u8,
    /// Recent MICs for packets accepted within the backward window.
    /// Used to distinguish replays from legitimate late arrivals when
    /// counter values fall within the backward range. Entries are evicted
    /// after 5 minutes (the spec's staleness bound).
    recent_mics: heapless::Deque<RecentMic, 8>,
}

struct RecentMic {
    counter: u32,
    mic: [u8; 16],
    mic_len: u8,
    accepted_ms: u64,
}

impl ReplayWindow {
    pub fn new() -> Self;

    /// Check whether a (counter, mic) pair is acceptable.
    /// For counters ahead of the window: always Accept.
    /// For counters within the backward window: check the MIC cache.
    /// For counters behind the window or stale: reject.
    pub fn check(&self, counter: u32, mic: &[u8], now_ms: u64) -> ReplayVerdict;

    /// Record an accepted packet.
    pub fn accept(&mut self, counter: u32, mic: &[u8], now_ms: u64);

    /// Reset the window (e.g., after counter resynchronization).
    pub fn reset(&mut self, baseline: u32, now_ms: u64);
}

pub enum ReplayVerdict { Accept, Replay, OutOfWindow, Stale }
```

#### Remote Peer State

Peer knowledge is split into two layers to avoid duplicating the 32-byte public
key and routing state across local identities:

- **Shared (per-radio)**: `PeerRegistry` stores the public key and routing state.
  Physical-topology information — routes and flood distances work for any local
  identity. Indexed by `PeerId`.
- **Per-local-identity**: `PeerCryptoMap` stores pairwise keys and replay windows.
  Keyed by `PeerId` — no public key duplication.

Multicast replay is keyed by **(channel, claimed sender `PeerId`)**, not by
channel alone. This prevents two honest senders on the same channel from
interfering with each other's counter state. The `PeerId` is resolved from the
claimed source public key when available; hint-only lookups fall back to
hint-keyed temporary state that is promoted to `PeerId`-keyed state once the
key is learned.

```rust
/// Index into the shared PeerRegistry. Small, Copy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(u8);

/// Shared knowledge about a remote peer. Stored once per radio.
pub struct PeerInfo {
    pub public_key: PublicKey,
    pub route: Option<CachedRoute>,
    pub last_seen_ms: u64,
}

pub enum CachedRoute {
    Source(heapless::Vec<RouterHint, 15>),
    Flood { hops: u8 },
}

/// Shared peer registry. Lives in the MAC coordinator.
pub struct PeerRegistry<const N: usize> {
    peers: heapless::Vec<PeerInfo, N>,
}

impl<const N: usize> PeerRegistry<N> {
    pub fn lookup_by_hint(&self, hint: &NodeHint) -> impl Iterator<Item = (PeerId, &PeerInfo)>;
    pub fn lookup_by_key(&self, key: &PublicKey) -> Option<(PeerId, &PeerInfo)>;
    pub fn get(&self, id: PeerId) -> Option<&PeerInfo>;
    pub fn insert_or_update(&mut self, key: PublicKey) -> PeerId;
    pub fn update_route(&mut self, id: PeerId, route: CachedRoute);
}

/// Per-(local identity, remote peer) cryptographic state.
pub struct PeerCryptoState {
    pub pairwise_keys: PairwiseKeys,
    pub replay_window: ReplayWindow,
}

/// Per-local-identity map from PeerId to crypto state.
pub struct PeerCryptoMap<const N: usize> {
    entries: heapless::LinearMap<PeerId, PeerCryptoState, N>,
}
```

#### Channel State

Multicast replay is tracked per claimed sender within a channel.

```rust
pub struct ChannelState {
    pub channel_key: ChannelKey,
    pub derived: DerivedChannelKeys,
    /// Per-sender replay windows for senders with resolved PeerId.
    pub replay: heapless::LinearMap<PeerId, ReplayWindow, /* N */>,
    /// Temporary replay windows for senders known only by hint (S=0,
    /// no prior key exchange). These are best-effort: hint collisions
    /// can cause two senders to share a temporary window. Entries are
    /// promoted to the `replay` map (keyed by PeerId) when the sender's
    /// full public key is learned (e.g., via an S=1 packet or identity
    /// beacon). Temporary entries expire after 5 minutes of inactivity.
    pub hint_replay: heapless::LinearMap<NodeHint, ReplayWindow, /* N */>,
}

pub struct ChannelTable<const N: usize> {
    channels: heapless::Vec<ChannelState, N>,
}

impl<const N: usize> ChannelTable<N> {
    pub fn lookup_by_id(&self, id: &ChannelId) -> impl Iterator<Item = &ChannelState>;
    pub fn add(&mut self, key: ChannelKey, derived: DerivedChannelKeys);
}
```

#### Repeater Configuration

```rust
pub struct RepeaterConfig {
    pub enabled: bool,
    pub regions: heapless::Vec<[u8; 2], 8>,
    pub min_rssi: Option<i16>,
    pub min_snr: Option<i8>,
     pub amateur_radio_mode: AmateurRadioMode,
     /// Station callsign for this repeater. In `LicensedOnly` and `Hybrid`
     /// operation, the forwarding path replaces or inserts option 7 (Station
     /// Callsign) with this value before retransmission whenever the repeater is
     /// operating under amateur authority. In `Unlicensed` mode, the repeater
     /// removes station callsigns and does not add its own.
    pub station_callsign: Option<HamAddr>,
}
```

When amateur-radio handling is enabled, the forwarding procedure in `poll_cycle`
performs option 7 rewriting as a first-class step:

1. `LicensedOnly`: only packets carrying an operator callsign (option 4) may be
    forwarded under amateur authority.
2. `Hybrid`: packets with an operator callsign may be forwarded under amateur
    authority; packets without one may still be forwarded under unlicensed
    authority if local rules permit.
3. `LicensedOnly` and `Hybrid`: the repeater replaces or inserts option 7 with
    its own `station_callsign` before retransmission.
4. `Unlicensed`: the repeater removes option 7 if present and does not add its own.

#### Route Learning

Route learning is a **MAC-level responsibility**, not a node-layer concern. The
protocol requires learned routing state to be available before MAC ACK routing
decisions — the receive path generates an ACK and needs a return route immediately,
not after application handling. The MAC coordinator updates the shared
`PeerRegistry` route cache during packet processing:

- If the packet carries a trace-route option, cache the reversed trace as a
  source route for the sender.
- If the packet carries a flood hop count, cache `FHOPS_ACC` as a distance
  estimate for flood-scoped responses.
- Route state is updated in the shared `PeerRegistry` and is immediately
  available for ACK routing within the same `poll_cycle`.

#### MAC Coordinator

The MAC coordinator is **one per physical radio**. It owns the radio and runs as
a single async task. Each `poll_cycle` follows a **state-driven sequence**, not
just a priority queue drain:

```text
poll_cycle:
  1. Drain TX queue (application sends, scheduled retries)
  2. Receive one packet
  3. If packet received:
     a. Parse, authenticate, route-learn, deliver event(s)
     b. If ACK needed: transmit immediately (skip CAD per spec)
     c. If forwarding eligible: enter post-transmit-listen state
  4. Service pending ACK timers (confirmation timeouts, ACK deadlines)
```

**Post-transmit listen** is a first-class state: after transmitting a forwarded
packet or a source-routed send, the coordinator listens for up to 1–3×T_frame
for a duplicate-cache-matched retransmission by the next hop. This is not an
implicit side effect of queue ordering — it is an explicit state transition
between transmit and the next receive cycle. If confirmation arrives, the
`PendingAck` transitions to `AwaitingAck`. If the listen window expires, the
coordinator schedules a retry (up to the max retry count).

**TX priority order** (highest first):

1. **Immediate ACK** — spec allows skipping CAD after a just-received packet
2. **Receive-triggered forwarding** — contention-delayed repeater retransmits
3. **Forwarding retries** — confirmation timeout retransmits
4. **Application-originated sends** — enqueued via `MacHandle`

The coordinator never exposes `&mut self` to application code. Instead,
application code interacts through a **cloneable `MacHandle`** — a lightweight
reference to the coordinator's shared state and command queue. Multiple
`MacHandle` instances (one per `Node`, one per task) coexist naturally without
borrow conflicts.

State ownership:

- **Coordinator-owned**: radio, delay, TX queue, run loop.
- **Shared** (behind interior mutability): crypto engine, clock, RNG, counter store,
  identity registry, peer registry, channel table, dup cache, repeater config.
- **Per-local-identity** (in `IdentitySlot`): identity impl, peer crypto map,
  frame counter, pending acks.

```rust
/// Opaque handle to a registered local identity. Small, Copy.
/// Covers both long-term identities and ephemeral PFS identities.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalIdentityId(u8);

/// A local identity is either the platform's long-term identity type or a
/// software-only ephemeral identity for PFS. This makes the "ephemeral keys
/// are always software" rule structural, not documentary.
pub enum LocalIdentity<I: NodeIdentity> {
    LongTerm(I),
    Ephemeral(SoftwareIdentity),
}

impl<I: NodeIdentity> LocalIdentity<I> {
    pub fn public_key(&self) -> &PublicKey;
    pub fn hint(&self) -> NodeHint;
    pub async fn sign(&self, msg: &[u8]) -> Result<[u8; 64], /* ... */>;
    pub async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, /* ... */>;
}

/// Per-identity state, stored inside the coordinator's registry.
pub struct IdentitySlot<I: NodeIdentity> {
    identity: LocalIdentity<I>,
    peer_crypto: PeerCryptoMap</* N */>,
    frame_counter: u32,
    /// Outstanding ack-requested transmissions, keyed by locally-assigned receipt.
    /// The ack tag (transport-level matching key) is stored inside `PendingAck`,
    /// not exposed through the public `SendReceipt`.
    pending_acks: heapless::LinearMap<SendReceipt, PendingAck, /* N */>,
    next_receipt: u32,
    /// If this is an ephemeral PFS identity, link to the long-term identity.
    pfs_parent: Option<LocalIdentityId>,
}

pub struct PendingAck {
    pub ack_tag: [u8; 8],      // transport-level matching key (internal)
    pub peer: PublicKey,
    pub resend: ResendRecord,  // enough state to reconstruct the retransmission
    pub sent_ms: u64,
    pub ack_deadline_ms: u64,  // absolute deadline for end-to-end ACK
    pub retries: u8,
    pub state: AckState,
}

pub enum AckState {
    /// Waiting for next-hop forwarding confirmation (short timer).
    AwaitingForward { confirm_deadline_ms: u64 },
    /// Forwarding confirmed; waiting for end-to-end MAC ACK (long timer).
    AwaitingAck,
}

/// Enough retained state to reconstruct an exact retransmission.
/// Stores the sealed frame bytes (post-crypto), so retries don't require
/// re-sealing. Bounded to max frame size (~255 bytes).
pub struct ResendRecord {
    pub frame: heapless::Vec<u8, 256>,
    /// Routing state for source-routed retries: the remaining source route
    /// at the time of original send, so retries use the same path.
    pub source_route: Option<heapless::Vec<RouterHint, 15>>,
}
```

**ACK state machine:** The MAC coordinator manages ack-requested delivery
internally. The application never retransmits — it only observes receipts
and timeouts via `SendReceipt`.

1. **Initial send** — creates `SendReceipt` and `PendingAck` with `ResendRecord`
   containing the sealed frame. Initial state depends on the routing context:
   - **Forwarded send** (source-routed or flood with `FHOPS_REM > 0`): state
     starts as `AwaitingForward`. The sender expects a next-hop retransmission
     it can overhear as confirmation.
   - **Direct send** (no source route, no flood hops, or `FHOPS_REM == 0`):
     state starts as `AwaitingAck`. There is no forwarding hop to overhear —
     the next signal is the MAC ACK from the final destination.
2. **Forwarding confirmation** (short timer, ~1–3×T_frame, only in
   `AwaitingForward` state) — if the next-hop retransmission is overheard,
   transition to `AwaitingAck`. If the timer expires without confirmation,
   retransmit (up to 3 retries with CAD+backoff). Each retry resets the
   forwarding confirmation timer.
3. **End-to-end MAC ACK** (long timer) — if the ACK arrives (matched by ack tag
   internally), emit `MacEventRef::AckReceived { receipt }` and remove the entry.
4. **ACK deadline** — if `ack_deadline_ms` expires without an ACK, emit
   `MacEventRef::AckTimeout { receipt }` and remove the entry. This is the
   final deadline; it runs independently of forwarding retries.

The two timers are independent: the forwarding confirmation timer governs
hop-by-hop retry behavior, while the ACK deadline governs end-to-end delivery.
On a multi-hop path, the ACK may arrive well after forwarding is confirmed.

```rust

/// The MAC coordinator. Created once, configured, then started.
pub struct Mac<P: Platform> {
    radio: P::Radio,
    delay: P::Delay,
    shared: MacShared<P>,
    tx_queue: TxQueue,
}

/// Shared mutable state. The coordinator and all MacHandles reference this.
/// Interior mutability: RefCell (single-threaded) or Mutex (behind `std`).
pub struct MacShared<P: Platform> {
    crypto: CryptoEngine<P::Aes, P::Sha>,
    clock: P::Clock,
    rng: P::Rng,
    counter_store: P::CounterStore,

    identities: heapless::Vec<IdentitySlot<P::Identity>, /* MAX_IDENTITIES */>,
    peer_registry: PeerRegistry</* N */>,
    channels: ChannelTable</* N */>,
    dup_cache: DuplicateCache,
    repeater: RepeaterConfig,
    operating_policy: OperatingPolicy,
}

impl<P: Platform> Mac<P> {
    pub fn new(/* platform components + RepeaterConfig */) -> Self;

    /// Register a long-term local identity.
    pub fn add_identity(&mut self, identity: P::Identity) -> LocalIdentityId;

    /// Add a channel (shared across all identities).
    pub fn add_channel(&mut self, key: ChannelKey);

    /// Register a known remote peer's public key.
    pub fn add_peer(&mut self, key: PublicKey) -> PeerId;

    /// Obtain a cloneable handle for sending and configuration.
    pub fn handle(&self) -> MacHandle<P>;

    /// Service one coordinator cycle using the MAC's state-driven sequence.
    /// A cycle may transmit queued work, receive and process one packet,
    /// perform immediate-ACK handling, enter the post-transmit listen state
    /// for forwarding confirmation, and service pending ACK timers.
    ///
    /// The callback may be invoked zero or more times per cycle (zero if no
    /// packet was accepted for local delivery; potentially more than once if a
    /// broadcast matches multiple identities).
    ///
    /// Returns after the cycle's active state transitions are complete. The
    /// caller is then free to drain deferred actions before calling
    /// `poll_cycle` again.
    pub async fn poll_cycle(
        &mut self,
        on_event: impl FnMut(LocalIdentityId, MacEventRef<'_>),
    ) -> Result<(), MacError>;

    /// Run the coordinator until the TX queue is empty, then return.
    /// Performs channel access (CAD + backoff) for each queued packet but
    /// does not enter receive mode. Used for fire-and-forget sends
    /// (deep sleep sensors) and graceful shutdown.
    pub async fn drain_tx_queue(&mut self) -> Result<(), MacError>;
}
```

#### MacHandle — Cloneable Send Interface

```rust
/// Lightweight, cloneable handle to the MAC coordinator.
/// Enqueues send requests and performs shared-state queries.
/// Does not own the radio or the run loop.
///
/// Implementation: holds a reference (or Rc/Arc) to MacShared + a sender
/// to the coordinator's TX command queue. The exact mechanism is
/// platform-dependent (e.g., embassy::channel::Sender on embassy,
/// mpsc::Sender on tokio).
#[derive(Clone)]
pub struct MacHandle<P: Platform> { /* ... */ }

/// Opaque, locally-assigned receipt for an ack-requested transmission.
/// Does not expose transport-level ack tag details. The MAC coordinator
/// maps between receipts and ack tags internally in `PendingAck`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendReceipt(u32);

impl<P: Platform> MacHandle<P> {
    /// Send a unicast packet. Returns `Ok(None)` for fire-and-forget sends,
    /// `Ok(Some(receipt))` when `opts.ack_requested` is true. The receipt can be
    /// matched against `MacEventRef::AckReceived` / `AckTimeout`.
    pub async fn send_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        payload: &[u8],
        opts: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError>;

    pub async fn send_multicast(
        &self,
        from: LocalIdentityId,
        channel: &ChannelId,
        payload: &[u8],
        opts: &SendOptions,
    ) -> Result<(), SendError>;

    /// Send a blind unicast packet. Returns a SendReceipt when ack-requested.
    pub async fn send_blind_unicast(
        &self,
        from: LocalIdentityId,
        dst: &PublicKey,
        channel: &ChannelId,
        payload: &[u8],
        opts: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError>;

    pub async fn send_broadcast(
        &self,
        from: LocalIdentityId,
        payload: &[u8],
        opts: &SendOptions,
    ) -> Result<(), SendError>;

    /// Register a remote peer in the shared registry.
    pub fn add_peer(&self, key: PublicKey) -> PeerId;

    /// Add a channel.
    pub fn add_channel(&self, key: ChannelKey);

    /// Register an ephemeral PFS identity as a MAC-level identity.
    /// Called by the node layer after PFS handshake completes.
    /// The ephemeral identity gets its own IdentitySlot with an independent
    /// frame counter and peer crypto state.
    ///
    /// Takes `SoftwareIdentity` directly — ephemeral keys are always software,
    /// even on hardware-backed platforms, because they must be reliably erasable.
    pub fn register_ephemeral(
        &self,
        parent: LocalIdentityId,
        ephemeral: SoftwareIdentity,
    ) -> LocalIdentityId;

    /// Remove and zeroize an ephemeral identity. Called on PFS session end.
    pub fn remove_ephemeral(&self, id: LocalIdentityId);
}
```

#### MAC Events (Zero-Copy)

```rust
/// Zero-copy event reference. Payload borrows directly from the radio buffer.
pub enum MacEventRef<'a> {
    Unicast {
        from: PublicKey,
        payload: &'a [u8],
        ack_requested: bool,
    },
    Multicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
    },
    BlindUnicast {
        from: PublicKey,
        channel_id: ChannelId,
        payload: &'a [u8],
        ack_requested: bool,
    },
    Broadcast {
        from_hint: NodeHint,
        from_key: Option<PublicKey>,
        payload: &'a [u8],
    },
    /// A MAC ack was received matching a pending ack-requested send.
    /// The receipt identifies which specific transmission was acknowledged.
    AckReceived { peer: PublicKey, receipt: SendReceipt },
    /// An ack-requested send timed out without receiving an ack.
    AckTimeout { peer: PublicKey, receipt: SendReceipt },
}

impl MacEventRef<'_> {
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> MacEvent;
}

/// Owned variant for callers that need to store/queue events.
#[cfg(feature = "alloc")]
pub enum MacEvent {
    Unicast { from: PublicKey, payload: alloc::vec::Vec<u8>, ack_requested: bool },
    Multicast { from: PublicKey, channel_id: ChannelId, payload: alloc::vec::Vec<u8> },
    BlindUnicast { from: PublicKey, channel_id: ChannelId, payload: alloc::vec::Vec<u8>, ack_requested: bool },
    Broadcast { from_hint: NodeHint, from_key: Option<PublicKey>, payload: alloc::vec::Vec<u8> },
    AckReceived { peer: PublicKey, receipt: SendReceipt },
    AckTimeout { peer: PublicKey, receipt: SendReceipt },
}
```

#### Send Options and Policy

`SendOptions` describes what the application requests. Policy layers validate
and may reject or augment the request before it reaches the TX queue.

```rust
pub struct SendOptions {
    pub mic_size: MicSize,
    pub encrypted: bool,
    pub ack_requested: bool,
    pub full_source: bool,
    pub flood_hops: Option<u8>,
    pub trace_route: bool,
    pub source_route: Option<&[RouterHint]>,
    pub region_code: Option<[u8; 2]>,
    pub salt: bool,
}

impl Default for SendOptions {
    /* mic_size: Mic16, encrypted: true, ack_requested: false, flood_hops: Some(5) */
}

impl SendOptions {
    pub fn with_mic_size(mut self, mic_size: MicSize) -> Self { self.mic_size = mic_size; self }
    pub fn with_ack_requested(mut self, v: bool) -> Self { self.ack_requested = v; self }
    pub fn with_flood_hops(mut self, hops: u8) -> Self { self.flood_hops = Some(hops); self }
    pub fn no_flood(mut self) -> Self { self.flood_hops = None; self }
    pub fn with_trace_route(mut self) -> Self { self.trace_route = true; self }
    pub fn with_source_route(mut self, route: &[RouterHint]) -> Self { self.source_route = Some(route); self }
    pub fn with_salt(mut self) -> Self { self.salt = true; self }
    pub fn with_full_source(mut self) -> Self { self.full_source = true; self }
    pub fn unencrypted(mut self) -> Self { self.encrypted = false; self }
}
```

**Three-tier policy separation:**

| Tier | Where | What it enforces |
|------|-------|------------------|
| **Wire-validity** | MAC coordinator, on TX | Packet structure invariants: field sizes, option ordering, frame counter monotonicity |
| **Local-operating** | `OperatingPolicy` in `MacShared` | Mode-level rules: amateur-radio mode selection, operator callsign requirements, and emergency-channel TX constraints |
| **UI acceptance** | `Endpoint::handle_event` | Display rules: public-channel chat without S=1 must not be shown; emergency messages without valid EdDSA signature must not be displayed; invalid identity signatures flagged |

```rust
/// Local operating policy. Configured at startup, consulted on every send.
pub struct OperatingPolicy {
    pub amateur_radio_mode: AmateurRadioMode,
    pub operator_callsign: Option<HamAddr>,
    /// Per-channel overrides (e.g., EMERGENCY requires unencrypted + S=1 + sig).
    pub channel_policies: heapless::Vec<ChannelPolicy, 4>,
}

pub struct ChannelPolicy {
    pub channel_id: ChannelId,
    pub require_unencrypted: bool,
    pub require_full_source: bool,
    pub max_flood_hops: Option<u8>,
    // NOTE: require_signature is NOT here. MAC sees raw payload bytes and
    // cannot verify EdDSA signatures without parsing the application format.
    // Signature validation is enforced in Endpoint::handle_event (UI acceptance).
}
```

#### PFS as MAC-Level Identity

PFS ephemeral identities are first-class MAC identities, not node-layer overlays.
When a PFS handshake completes, `MacHandle::register_ephemeral` creates a new
`IdentitySlot` with:

- Its own `LocalIdentityId`
- Its own frame counter (independent, for wire-level unlinkability)
- Its own `PeerCryptoMap` (derived from the ephemeral ECDH)
- A `pfs_parent` link back to the originating long-term identity

The MAC coordinator routes to and from ephemeral hints exactly like any other
identity. The node layer manages handshake policy and session lifetime only —
it calls `register_ephemeral` / `remove_ephemeral` and maps between the
long-term identity the application sees and the active ephemeral identity
the MAC uses.

On session end, `remove_ephemeral` zeroizes the `IdentitySlot` and removes it
from the registry.

#### Explicitly Out of Scope (v1)

The following protocol surfaces are not yet defined in the spec and are
**not implemented** in v1. No stubs, no placeholder types — the extension
points exist (reserved payload types, the managed channel concept) but no
code pretends to implement them.

- **Managed channel control messages** — join requests, key distribution,
  rotation signalling. The wire formats are undefined.
- **Node management protocol** — TBD in the spec.
- **CoAP-over-UMSH** — payload type reserved but framing/interaction model
  undefined.

---

### `umsh-app` --- Application Layer Protocols

Encode/decode UMSH application payloads. Purely structural --- no I/O, no crypto
(except optional EdDSA signature support gated behind `umsh-crypto`). All parsers
are zero-copy, borrowing from the input payload slice.

#### Payload Type Dispatch

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    Unspecified      = 0,
    NodeIdentity     = 1,
    MacCommand       = 2,
    TextMessage      = 3,
    ChatRoomMessage  = 5,
    CoapOverUmsh     = 7,
    NodeManagement   = 8,
}

impl PayloadType {
    pub fn from_byte(b: u8) -> Option<Self>;
    pub fn allowed_for(self, pkt_type: PacketType) -> bool;
}
```

#### Text Messages

```rust
pub mod text {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum MessageType { Basic = 0, Status = 1, ResendRequest = 2 }

    pub struct MessageSequence {
        pub message_id: u8,
        pub fragment: Option<Fragment>,
    }

    pub struct Fragment {
        pub index: u8,
        pub count: u8,
    }

    pub enum Regarding {
        Unicast { message_id: u8 },
        Multicast { message_id: u8, source_prefix: NodeHint },
    }

    /// Parsed text message, borrowing from the payload buffer.
    pub struct TextMessage<'a> {
        pub message_type: MessageType,
        pub sender_handle: Option<&'a str>,
        pub sequence: Option<MessageSequence>,
        pub sequence_reset: bool,
        pub regarding: Option<Regarding>,
        pub editing: Option<u8>,
        pub bg_color: Option<[u8; 3]>,
        pub text_color: Option<[u8; 3]>,
        pub body: &'a str,
    }

    /// Parse a text message payload (after the payload type byte).
    pub fn parse(payload: &[u8]) -> Result<TextMessage<'_>, ParseError>;

    /// Encode a text message into a buffer. Returns bytes written.
    pub fn encode(msg: &TextMessage<'_>, buf: &mut [u8]) -> Result<usize, EncodeError>;
}
```

#### Node Identity

```rust
pub mod identity {
    #[derive(Clone, Copy)]
    #[repr(u8)]
    pub enum NodeRole {
        Unspecified = 0, Repeater = 1, Chat = 2, Tracker = 3,
        Sensor = 4, Bridge = 5, ChatRoom = 6, TemporarySession = 7,
    }

    bitflags::bitflags! {
        pub struct Capabilities: u8 {
            const REPEATER      = 0x01;
            const MOBILE        = 0x02;
            const TEXT_MESSAGES  = 0x04;
            const TELEMETRY     = 0x08;
            const CHAT_ROOM     = 0x10;
            const COAP          = 0x20;
            const NAME_INCLUDED = 0x40;
            const OPTS_INCLUDED = 0x80;
        }
    }

    /// Parsed node identity payload.
    pub struct NodeIdentityPayload<'a> {
        pub timestamp: u32,
        pub role: NodeRole,
        pub capabilities: Capabilities,
        pub name: Option<&'a str>,
        pub options: OptionDecoder<'a>,
        pub signature: Option<&'a [u8; 64]>,
    }

    pub fn parse(payload: &[u8]) -> Result<NodeIdentityPayload<'_>, ParseError>;
    pub fn encode(id: &NodeIdentityPayload<'_>, buf: &mut [u8]) -> Result<usize, EncodeError>;
}
```

#### MAC Commands

```rust
pub mod mac_cmd {
    #[derive(Clone, Copy)]
    #[repr(u8)]
    pub enum CommandId {
        BeaconRequest       = 0,
        IdentityRequest     = 1,
        SignalReportRequest = 2,
        SignalReportResponse= 3,
        EchoRequest         = 4,
        EchoResponse        = 5,
        PfsSessionRequest   = 6,
        PfsSessionResponse  = 7,
        EndPfsSession       = 8,
    }

    pub enum MacCommand<'a> {
        BeaconRequest { nonce: Option<u32> },
        IdentityRequest,
        SignalReportRequest,
        SignalReportResponse { rssi: u8, snr: i8 },
        EchoRequest { data: &'a [u8] },
        EchoResponse { data: &'a [u8] },
        PfsSessionRequest { ephemeral_key: &'a PublicKey, duration_minutes: u16 },
        PfsSessionResponse { ephemeral_key: &'a PublicKey, duration_minutes: u16 },
        EndPfsSession,
    }

    pub fn parse(payload: &[u8]) -> Result<MacCommand<'_>, ParseError>;
    pub fn encode(cmd: &MacCommand<'_>, buf: &mut [u8]) -> Result<usize, EncodeError>;
}
```

#### Chat Rooms

```rust
#[cfg(feature = "chat-rooms")]
pub mod chat_room {
    pub enum ChatAction<'a> {
        GetRoomInfo,
        RoomInfo(RoomInfo<'a>),
        Login(LoginParams<'a>),
        Logout,
        FetchMessages { timestamp: u32, max_count: u8 },
        FetchUsers,
        AdminCommand(&'a [u8]),
        RoomUpdate(&'a [u8]),
    }

    pub struct RoomInfo<'a> { ... }
    pub struct LoginParams<'a> { ... }

    pub fn parse(payload: &[u8]) -> Result<ChatAction<'_>, ParseError>;
    pub fn encode(action: &ChatAction<'_>, buf: &mut [u8]) -> Result<usize, EncodeError>;
}
```

#### URI Support

```rust
pub mod uri {
    use lwuri::prelude::*;

    pub enum UmshUri<'a> {
        Node(NodeUri<'a>),
        ChannelByName(ChannelNameUri<'a>),
        ChannelByKey(ChannelKeyUri<'a>),
    }

    pub struct NodeUri<'a> {
        pub public_key: PublicKey,
        pub identity_data: Option<&'a [u8]>,
    }

    /// Channel metadata parameters from URI query string (e.g., `?n=MyChannel;mh=6;r=SJC`).
    /// Preserved at parse time so QR-code provisioning doesn't lose advisory fields.
    pub struct ChannelParams<'a> {
        pub display_name: Option<&'a str>,
        pub max_flood_hops: Option<u8>,
        pub region: Option<&'a str>,
        // Additional parameters are accessible via raw query iteration.
    }

    pub struct ChannelNameUri<'a> {
        pub name: &'a str,
        pub params: ChannelParams<'a>,
    }

    pub struct ChannelKeyUri<'a> {
        pub key: ChannelKey,
        pub params: ChannelParams<'a>,
    }

    /// Parse a `umsh:` URI.
    pub fn parse_umsh_uri(uri: &UriRef) -> Result<UmshUri<'_>, ParseError>;

    /// Format a node URI into a buffer.
    pub fn format_node_uri(key: &PublicKey, buf: &mut [u8]) -> Result<usize, EncodeError>;

    /// Format a named channel URI.
    pub fn format_channel_name_uri(name: &str, buf: &mut [u8]) -> Result<usize, EncodeError>;
}
```

---

### `umsh-node` --- High-Level Node Orchestration

A **local endpoint** is the application-facing abstraction. It holds a
`LocalIdentityId`, a cloneable `MacHandle`, and manages PFS handshake policy,
KV storage, and UI-level acceptance rules. It does **not** own the radio or the
MAC run loop. Multiple endpoints coexist naturally — each holds its own `MacHandle`
clone.

Event handling uses a **two-phase design** to reconcile zero-copy receive with
async work. The MAC coordinator's callback is synchronous and borrows the radio
buffer. Most events resolve immediately in the sync phase. Events that require
async work (PFS handshake, first-contact ECDH, KV writes) copy the payload and
return a deferred action that the caller processes after the callback returns and
the radio buffer is released.

This crate requires `alloc` for dynamic peer tracking and message queuing in `std`
environments. For `no_std` without alloc, users configure fixed-capacity bounds
via const generics.

#### Endpoint

```rust
pub struct EndpointConfig {
    pub default_mic_size: MicSize,
    pub default_encrypted: bool,
    pub default_flood_hops: u8,
    pub beacon_interval_ms: Option<u64>,
}

/// A local endpoint — the application-facing state machine.
/// Holds a cloneable MacHandle, not an exclusive borrow.
/// The KV store is optional. A minimal endpoint (repeater, sensor) can operate
/// with in-memory-only state by passing `None`. Persistent peer/session storage
/// is layered on top for devices that need it.
pub struct Endpoint<P: Platform> {
    id: LocalIdentityId,
    mac: MacHandle<P>,
    config: EndpointConfig,
    kv_store: Option<P::KeyValueStore>,
    pfs: PfsSessionManager,
}

impl<P: Platform> Endpoint<P> {
    pub fn new(
        id: LocalIdentityId,
        mac: MacHandle<P>,
        config: EndpointConfig,
    ) -> Self;

    /// Attach persistent storage. Without this, peer and session state is
    /// in-memory only and lost on reboot.
    pub fn with_kv_store(self, kv_store: P::KeyValueStore) -> Self;

    pub fn id(&self) -> LocalIdentityId;

    // --- Sending ---

    /// Returns `Ok(Some(receipt))` when ack-requested, `Ok(None)` for fire-and-forget.
    pub async fn send_text(&mut self, to: &PublicKey, text: &str) -> Result<Option<SendReceipt>, EndpointError>;
    pub async fn send_channel_text(&mut self, channel: &ChannelId, text: &str) -> Result<(), EndpointError>;
    pub async fn send_blind_text(&mut self, to: &PublicKey, channel: &ChannelId, text: &str) -> Result<Option<SendReceipt>, EndpointError>;
    pub async fn send_beacon(&mut self) -> Result<(), EndpointError>;
    pub async fn send_identity_beacon(&mut self) -> Result<(), EndpointError>;

    // --- PFS ---

    pub async fn request_pfs_session(&mut self, peer: &PublicKey, duration_minutes: u16) -> Result<(), EndpointError>;
    pub async fn end_pfs_session(&mut self, peer: &PublicKey) -> Result<(), EndpointError>;

    // --- Configuration (delegates to MacHandle) ---

    pub fn add_named_channel(&self, name: &str);
    pub fn add_private_channel(&self, key: ChannelKey);
    pub fn add_peer(&self, key: PublicKey) -> PeerId;

    // --- Inbound event handling (two-phase) ---

    /// Phase 1: Synchronous, zero-copy. Called inside the Mac::poll_cycle callback
    /// while the radio buffer is live. Performs cheap work: UI acceptance
    /// checks, payload parsing, and known-peer lookups.
    ///
    /// Returns:
    /// - `Handled(Some(event))` — fully processed, here's the app event.
    /// - `Handled(None)` — consumed (e.g., filtered by UI acceptance policy).
    /// - `NeedsAsync(deferred)` — requires async follow-up (PFS handshake,
    ///   first-contact ECDH, KV write). The payload has been copied into
    ///   the `DeferredAction`. Caller must call `handle_deferred` after
    ///   the callback returns.
    pub fn handle_event(&mut self, event: MacEventRef<'_>) -> EventAction;

    /// Phase 2: Async follow-up for events that could not be resolved
    /// synchronously. Called after the Mac::poll_cycle callback returns (radio
    /// buffer released). Performs ECDH, PFS handshake steps, KV writes.
    pub async fn handle_deferred(
        &mut self,
        deferred: DeferredAction,
    ) -> Option<EndpointEvent>;
}

/// Result of the synchronous event handling phase.
pub enum EventAction {
    /// Fully handled inline. Contains the app-level event (or None if filtered).
    Handled(Option<EndpointEvent>),
    /// Requires async work. Payload has been copied into owned form.
    NeedsAsync(DeferredAction),
}

/// Opaque record carrying the copied event data needed for async follow-up.
/// Created by `handle_event` when it encounters first-contact ECDH, PFS
/// handshake messages, or other work that cannot complete synchronously.
pub struct DeferredAction { /* owned MacEvent + context */ }
```

#### UI Acceptance Policy

Display-level rules that belong above the MAC layer. These require parsing
the application payload (which MAC does not do) or verifying EdDSA signatures
(which requires `umsh-crypto` + `umsh-app`, not available at the MAC level):

- Public-channel chat messages without `S=1` must not be displayed.
- Emergency-channel chat messages must include an EdDSA signature in the payload;
  messages without a valid signature must not be accepted or displayed.
- Node identity payloads with invalid signatures should be flagged.

These are enforced inside `Endpoint::handle_event` — it parses the payload via
`umsh-app`, inspects the channel context, verifies signatures when required, and
returns `Handled(None)` for events that fail UI acceptance. The MAC layer does
not enforce these; it delivers wire-valid packets regardless.

#### Events

```rust
pub enum EndpointEvent {
    TextReceived {
        from: PublicKey,
        message: TextMessage<'static>,
    },
    ChannelTextReceived {
        from: PublicKey,
        channel_id: ChannelId,
        message: TextMessage<'static>,
    },
    NodeDiscovered {
        key: PublicKey,
        identity: NodeIdentityPayload<'static>,
    },
    BeaconReceived {
        from_hint: NodeHint,
        from_key: Option<PublicKey>,
    },
    AckReceived { peer: PublicKey, receipt: SendReceipt },
    AckTimeout { peer: PublicKey, receipt: SendReceipt },
    PfsSessionEstablished { peer: PublicKey },
    PfsSessionEnded { peer: PublicKey },
    MacCommand {
        from: PublicKey,
        command: MacCommand<'static>,
    },
}
```

#### PFS Session Manager

Manages PFS handshake policy and session lifetime. When a handshake completes,
calls `MacHandle::register_ephemeral` to make the ephemeral identity a
first-class MAC identity. On session end, calls `MacHandle::remove_ephemeral`.

```rust
pub struct PfsSessionManager {
    sessions: heapless::LinearMap<PublicKey, PfsSession, 4>,
}

pub struct PfsSession {
    pub peer_long_term: PublicKey,
    pub local_ephemeral_id: LocalIdentityId,  // registered in MAC
    pub peer_ephemeral: PublicKey,
    pub expires_ms: u64,
    pub state: PfsState,
}

pub enum PfsState {
    Requested,   // sent request, awaiting response
    Active,      // both sides confirmed, ephemeral identity registered in MAC
}

impl PfsSessionManager {
    /// On session end: calls MacHandle::remove_ephemeral, which zeroizes
    /// the IdentitySlot in the MAC coordinator.
    pub async fn end_session(&mut self, mac: &MacHandle<impl Platform>, peer: &PublicKey);
}
```

---

### `umsh` --- Umbrella Crate

Re-exports all sub-crates and defines the `Platform` trait, which bundles HAL
types with crypto types into a single type parameter. This is the integration
point — it depends on all workspace crates and is where cross-cutting concerns
like `Platform` belong.

```rust
/// Bundle of all platform-specific associated types.
///
/// A single type parameter `P: Platform` replaces what would otherwise be
/// 9+ generic parameters on `Mac`, `Endpoint`, etc. Adding a new platform
/// trait only requires updating this one definition.
///
/// Implementors define a zero-sized struct per target and fill in the types:
///
/// ```rust
/// struct EmbassyPlatform;
/// impl Platform for EmbassyPlatform {
///     type Identity = SoftwareIdentity;
///     type Aes = SoftwareAes;
///     type Sha = SoftwareSha256;
///     type Radio = Sx1262<Spi>;
///     type Delay = embassy_time::Delay;
///     type Clock = EmbassyClock;
///     type Rng = EmbassyHwRng;
///     type CounterStore = FlashCounterStore;
///     type KeyValueStore = FlashKvStore;
/// }
/// ```
pub trait Platform {
    type Identity: NodeIdentity;       // from umsh-crypto
    type Aes: AesProvider;             // from umsh-crypto
    type Sha: Sha256Provider;          // from umsh-crypto
    type Radio: Radio;                 // from umsh-hal
    type Delay: DelayNs;               // from embedded-hal-async
    type Clock: Clock;                 // from umsh-hal
    type Rng: Rng;                     // from umsh-hal
    type CounterStore: CounterStore;   // from umsh-hal
    type KeyValueStore: KeyValueStore; // from umsh-hal
}
```

The umbrella crate also provides a `prelude` module re-exporting commonly used
types from all sub-crates.

---

## Usage Flows

### 1. Bare-Metal Repeater (Embassy, no alloc)

```rust
#![no_std]
#![no_main]

use embassy_executor::Spawner;
use umsh::prelude::*;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let radio = Sx1262Radio::new(spi, pins);
    let identity = SoftwareIdentity::from_secret_bytes(&KEY);

    let mut mac = Mac::new(
        SoftwareCryptoEngine::new(), radio, embassy_time::Delay,
        HardwareRng::new(rng_peripheral), FlashCounterStore::new(flash),
        RepeaterConfig { enabled: true, ..Default::default() },
    );

    mac.add_identity(identity);
    mac.add_channel(ChannelKey::from_name("public"));

    // Pure repeater: the coordinator handles forwarding internally.
    // No application-level event processing needed.
    loop {
        let _ = mac.poll_cycle(|_id, _event| { /* drop */ }).await;
    }
}
```

### 2. Embedded Chat Device (Embassy, alloc)

```rust
let mut mac = Mac::new(crypto, radio, delay, rng, counter_store,
                        RepeaterConfig::default());

let chat_id = mac.add_identity(identity);
mac.add_channel(ChannelKey::from_name("public"));

let handle = mac.handle();
let mut endpoint = Endpoint::new(chat_id, handle.clone(), EndpointConfig::default())
    .with_kv_store(kv_store);
endpoint.add_peer(friend_pubkey);

let mut deferred: heapless::Vec<DeferredAction, 4> = heapless::Vec::new();

loop {
    // Phase 1: Receive cycle — sync callback, zero-copy, radio buffer live.
    mac.poll_cycle(|id, event| {
        if id == chat_id {
            match endpoint.handle_event(event) {
                EventAction::Handled(Some(EndpointEvent::TextReceived { from, message })) => {
                    display.show(&from.hint(), message.body);
                }
                EventAction::Handled(_) => {}
                EventAction::NeedsAsync(action) => {
                    let _ = deferred.push(action);
                }
            }
        }
    }).await?;

    // Phase 2: Deferred work — async, radio buffer released.
    for action in deferred.drain(..) {
        if let Some(ep_event) = endpoint.handle_deferred(action).await {
            handle_app_event(ep_event);
        }
    }
}
```

### 3. Desktop Client (Tokio)

```rust
use umsh::prelude::*;

#[tokio::main]
async fn main() {
    let identity = SoftwareIdentity::from_file("~/.umsh/identity.key")?;
    let radio = SerialLoraRadio::open("/dev/ttyUSB0").await?;

    let mut mac = Mac::new(SoftwareCryptoEngine::new(), radio, TokioDelay,
                            OsRng, FileCounterStore::new("~/.umsh/counters")?,
                            RepeaterConfig::default());

    let chat_id = mac.add_identity(identity);
    mac.add_channel(ChannelKey::from_name("public"));

    let handle = mac.handle();
    let mut endpoint = Endpoint::new(chat_id, handle, EndpointConfig::default())
        .with_kv_store(SqliteStore::open("~/.umsh/peers.db")?);

    // The two-phase pattern works identically on tokio.
    // For cross-task delivery, EndpointEvents (already owned) are sent via channel.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(32);

    // MAC + endpoint task: poll_cycle, handle_event, handle_deferred
    tokio::spawn(async move {
        let mut deferred: heapless::Vec<DeferredAction, 4> = heapless::Vec::new();
        loop {
            mac.poll_cycle(|id, event| {
                if id == chat_id {
                    match endpoint.handle_event(event) {
                        EventAction::Handled(Some(ep_event)) => {
                            let _ = event_tx.try_send(ep_event);
                        }
                        EventAction::Handled(None) => {}
                        EventAction::NeedsAsync(action) => {
                            let _ = deferred.push(action);
                        }
                    }
                }
            }).await.ok();

            for action in deferred.drain(..) {
                if let Some(ep_event) = endpoint.handle_deferred(action).await {
                    let _ = event_tx.try_send(ep_event);
                }
            }
        }
    });

    // Application loop — receives fully-processed EndpointEvents
    while let Some(event) = event_rx.recv().await {
        match event {
            EndpointEvent::TextReceived { from, message } => {
                println!("[{}] {}", hex::encode(from.hint().0), message.body);
            }
            _ => {}
        }
    }
}
```

### 4. Companion Radio (MAC-only, Tokio)

```rust
let mut mac = Mac::new(/* ... */);
let id = mac.add_identity(identity);
let handle = mac.handle();

// MAC coordinator runs, forwarding events to serial
let (serial_tx, serial_rx) = tokio::sync::mpsc::channel(32);

tokio::spawn(async move {
    loop {
        mac.poll_cycle(|node_id, event| {
            let frame = serialize_mac_event_ref(node_id, &event);
            let _ = serial_tx.try_send(frame);
        }).await.ok();
    }
});

// Host command loop
loop {
    tokio::select! {
        Some(frame) = serial_rx.recv() => {
            serial.write_all(&frame).await?;
        }
        frame = read_host_frame(&mut serial) => {
            let cmd: HostCommand = deserialize(&frame?)?;
            match cmd {
                HostCommand::SendUnicast { dst, payload, opts } => {
                    handle.send_unicast(id, &dst, &payload, &opts).await?;
                }
                HostCommand::SendMulticast { channel, payload, opts } => {
                    handle.send_multicast(id, &channel, &payload, &opts).await?;
                }
                // ...
            }
        }
    }
}
```

### 5. Hardware-Backed Identity (Secure Element)

```rust
struct Atecc608Identity<I2C> {
    i2c: I2C,
    slot: u8,
    public_key: PublicKey,
}

impl<I2C: embedded_hal_async::i2c::I2c> NodeIdentity for Atecc608Identity<I2C> {
    type Error = I2cError;
    fn public_key(&self) -> &PublicKey { &self.public_key }
    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Self::Error> { /* SE over I2C */ }
    async fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Self::Error> { /* SE over I2C */ }
}

// Register with the MAC like any other identity:
let identity = Atecc608Identity::init(&mut i2c, 0).await?;
let mut mac = Mac::new(HardwareAes::new(aes_peripheral), /* ... */);
let id = mac.add_identity(identity);
```

### 6. PFS Session

```rust
// Initiate a PFS session.
endpoint.request_pfs_session(&peer_key, 60).await?;

// handle_event processes the PFS handshake response internally:
// 1. Generates ephemeral keypair (SoftwareIdentity)
// 2. Calls mac.register_ephemeral(long_term_id, ephemeral_identity)
// 3. Returns EndpointEvent::PfsSessionEstablished { peer }

// All subsequent sends to this peer transparently use the ephemeral identity.
endpoint.send_text(&peer_key, "Forward-secret message").await?;

// End the session. remove_ephemeral zeroizes the IdentitySlot.
endpoint.end_pfs_session(&peer_key).await?;
```

### 7. Deep Sleep Cycle (Low-Power Sensor)

```rust
loop {
    let radio = Sx1262Radio::new(spi, pins);
    let counter_store = FlashCounterStore::new(flash);

    let mut mac = Mac::new(/* ... */);
    let sensor_id = mac.add_identity(identity);
    let handle = mac.handle();

    // Send a sensor reading via the handle (enqueues to TX queue)
    handle.send_unicast(sensor_id, &gateway_key, &payload,
        &SendOptions::default().with_mic_size(MicSize::Mic4).with_flood_hops(3),
    ).await?;

    // Run the coordinator just long enough to transmit
    // (in practice: run until TX queue is drained)
    mac.drain_tx_queue().await?;

    counter_store.flush().await?;
    enter_deep_sleep(Duration::from_secs(300));
}
```

### 8. Multi-Identity Device (Chat + Repeater on One Radio)

```rust
let mut mac = Mac::new(crypto, radio, delay, rng, counter_store,
                        RepeaterConfig { enabled: true, ..Default::default() });

let chat_id = mac.add_identity(chat_identity);
let _repeater_id = mac.add_identity(repeater_identity);
mac.add_channel(ChannelKey::from_name("public"));

let handle = mac.handle();
let mut endpoint = Endpoint::new(chat_id, handle, EndpointConfig::default())
    .with_kv_store(kv_store);

let mut deferred: heapless::Vec<DeferredAction, 4> = heapless::Vec::new();

loop {
    mac.poll_cycle(|id, event| {
        if id == chat_id {
            match endpoint.handle_event(event) {
                EventAction::Handled(Some(ep_event)) => handle_chat_event(ep_event),
                EventAction::Handled(None) => {}
                EventAction::NeedsAsync(action) => {
                    let _ = deferred.push(action);
                }
            }
        }
        // Repeater identity: forwarding handled internally by the coordinator.
    }).await?;

    for action in deferred.drain(..) {
        if let Some(ep_event) = endpoint.handle_deferred(action).await {
            handle_chat_event(ep_event);
        }
    }
}
```

---

## Implementation Phases

### Phase 1: Foundation

**Goal:** Parse, build, and cryptographically process UMSH packets.
Validate against the spec's test vectors.

- [ ] `umsh-core`: All wire types, FCF/SCF, packet type enum, address types
- [ ] `umsh-core`: CoAP-style option encoder/decoder
- [ ] `umsh-core`: `PacketHeader::parse` — zero-copy packet parser
- [ ] `umsh-core`: `PacketBuilder` — typestate packet construction
- [ ] `umsh-core`: `feed_aad` — incremental AAD feeder
- [ ] `umsh-crypto`: `AesCipher`, `AesProvider`, `Sha256Provider`, `NodeIdentity` traits
- [ ] `umsh-crypto`: `CmacState` — incremental CMAC
- [ ] `umsh-crypto`: Software backend (RustCrypto)
- [ ] `umsh-crypto`: HKDF key derivation (pairwise, channel, blind, named channel)
- [ ] `umsh-crypto`: `seal_packet` / `open_packet` (AES-SIV-style)
- [ ] `umsh-crypto`: Ack tag computation
- [ ] `umsh-crypto`: CTR IV construction
- [ ] Tests against spec test vectors (packet layout, byte counts)
- [ ] Round-trip tests: build -> seal -> parse -> open

### Phase 2: MAC Layer

**Goal:** A working MAC coordinator that can send, receive, authenticate,
forward, and acknowledge packets.

- [x] `umsh-hal`: Radio, Clock, Rng, CounterStore, KeyValueStore traits
- [x] `umsh`: `Platform` trait (umbrella crate, bundles HAL + crypto types)
- [x] `umsh-mac`: `DuplicateCache` with explicit `DupCacheKey` enum
- [x] `umsh-mac`: `ReplayWindow` with per-sender multicast keying
- [x] `umsh-mac`: `PeerRegistry` (shared) and `PeerCryptoMap` (per-identity)
- [x] `umsh-mac`: `ChannelTable` with per-sender replay maps
- [x] `umsh-mac`: `Mac` coordinator — run loop with priority TX queue
- [x] `umsh-mac`: `MacHandle` — cloneable send interface
- [x] `umsh-mac`: Receive pipeline (full packet processing procedure from spec)
- [x] `umsh-mac`: Channel access (CAD + backoff) with immediate-ACK fast path
- [x] `umsh-mac`: Repeater forwarding procedure with contention delay
- [x] `umsh-mac`: MAC ack generation and matching
- [x] `umsh-mac`: Route learning (trace route + flood hop caching in `PeerRegistry`)
- [x] `umsh-mac`: Post-transmit listen state (forwarding confirmation window)
- [x] `umsh-mac`: Forwarding confirmation + retry logic
- [x] `umsh-mac`: `OperatingPolicy` — wire-validity and local-operating enforcement
- [x] `umsh-mac`: `register_ephemeral` / `remove_ephemeral` for PFS identities
- [x] Integration tests with a mock radio
- [ ] ACK state machine edge cases:
  - [x] Direct ack-requested unicast starts in `AwaitingAck`, not `AwaitingForward`
  - [x] Source-routed send starts in `AwaitingForward`, retries on missed confirmation
  - [x] Multi-hop: forwarding confirmed early, MAC ACK arrives later
  - [x] Blind-unicast ACK matching through internal ack-tag → `SendReceipt` mapping
  - [x] Pending-ACK table full: deterministic rejection, not silent drop
  - [x] Receipt counter wraparound behavior
  - [x] ACK and timeout racing in the same `poll_cycle`

### Phase 3: Application Layer

**Goal:** Encode/decode all defined application payloads. Parse and
format UMSH URIs.

- [ ] `umsh-app`: Payload type dispatch and validation
- [ ] `umsh-app`: Text message encode/decode (all options)
- [ ] `umsh-app`: Node identity encode/decode
- [ ] `umsh-app`: MAC command encode/decode (all 9 commands)
- [ ] `umsh-app`: Chat room actions (encode/decode, behind `chat-rooms` feature)
- [ ] `umsh-app`: URI parsing and formatting (`umsh:n:`, `umsh:cs:`, `umsh:ck:`)
- [ ] Round-trip tests for all payload types

### Phase 4: Endpoint Orchestration

**Goal:** High-level API that applications actually use.

- [ ] `umsh-node`: `Endpoint` construction and configuration
- [ ] `umsh-node`: Peer management (delegates to MacHandle)
- [ ] `umsh-node`: Beacon sending and scheduling
- [ ] `umsh-node`: Path discovery orchestration
- [ ] `umsh-node`: PFS session manager (handshake policy, register/remove ephemeral)
- [ ] `umsh-node`: Two-phase event handling: sync `handle_event()` + async `handle_deferred()`
- [ ] `umsh-node`: UI acceptance policy (enforced in sync phase)
- [ ] `umsh-node`: Application-level send helpers (send_text, etc.)
- [ ] `umsh`: Umbrella crate with re-exports and prelude

### Phase 5: Integration and Examples

**Goal:** Prove the stack works end-to-end on real hardware and in
desktop environments.

- [ ] Mock radio for testing (loopback + multi-node simulation)
- [ ] Tokio delay/clock/RNG/storage implementations
- [ ] Embassy delay/clock/RNG/storage implementations
- [ ] Serial LoRa radio adapter (for desktop use with a companion radio module)
- [ ] `examples/repeater`: Bare-metal Embassy repeater
- [ ] `examples/desktop-chat`: Tokio CLI chat client
- [ ] End-to-end test: two simulated endpoints exchanging text messages
- [ ] End-to-end test: multi-hop forwarding through a simulated repeater
- [ ] End-to-end test: PFS session establishment, traffic, and teardown

---

## Design Decisions and Rationale

### Single MAC Coordinator, Not TX/RX Split

LoRa is half-duplex: one radio, one thing at a time. The protocol also requires
the receive path to transmit (immediate ACKs, forwarding, confirmation retries).
A TX/RX split fights both the hardware and the protocol.

The MAC coordinator owns the radio. Each `poll_cycle` is part of a broader
state-driven cycle: it services queued work, receives and processes one packet,
performs immediate ACK transmission when required, enters post-transmit listen
when forwarding confirmation is needed, and then services pending ACK timers.
TX priority ordering still matters, but the coordinator's behavior is defined
by these explicit state transitions rather than by a simple drain-then-receive
loop. Application code sends through a cloneable `MacHandle` that enqueues to
the coordinator.

### Cloneable MacHandle, Not Exclusive Borrows

`MacHandle` is `Clone` — each `Endpoint` holds its own clone. This eliminates the
borrow-checker conflict that arises when multiple endpoints (or an endpoint and
a receive callback) need to send through the same MAC. The handle's internal
mechanism is platform-dependent: `Rc<RefCell<...>>` on single-threaded targets,
`Arc<Mutex<...>>` behind the `std` feature.

### Three Concepts: Local Identity, Local Endpoint, Remote Peer

The word "node" was doing too much work. The plan now distinguishes:

- **Local identity** (`LocalIdentityId`): a specific address/keypair active in the
  MAC, including ephemeral PFS identities. The MAC coordinator operates on these.
- **Local endpoint** (`Endpoint`): application-facing state machine. Built on top of
  one or more local identities. Manages PFS handshake policy, KV storage, UI
  acceptance rules.
- **Remote peer** (`PeerId`): learned remote identity plus routing and
  per-local-identity crypto state.

This separation makes PFS, replay detection, and event routing straightforward
to describe and implement.

### PFS as MAC-Level Identity

When a PFS handshake completes, the endpoint calls
`MacHandle::register_ephemeral(parent, ephemeral)`, which creates a real
`IdentitySlot` in the MAC coordinator with its own frame counter, peer crypto
state, and hint. The MAC routes to and from ephemeral hints exactly like any
other identity. Independent frame counters preserve wire-level unlinkability.
The endpoint manages only handshake policy and session lifetime.

The `IdentitySlot` stores a `LocalIdentity<P::Identity>` enum — either
`LongTerm(P::Identity)` or `Ephemeral(SoftwareIdentity)`. This makes the
"ephemeral keys are always software" rule structural: `register_ephemeral`
takes `SoftwareIdentity` directly, not `P::Identity`, so a hardware-backed
platform cannot accidentally create a hardware-stored ephemeral key.

On session end, `remove_ephemeral` zeroizes the `IdentitySlot` and removes it.

### Per-Sender Multicast Replay

Multicast replay is keyed by **(channel, claimed sender identity)**, not by
channel alone. Two honest senders on the same channel get independent replay
windows. The sender identity is resolved to a `PeerId` when the full public key
is available; hint-only lookups use temporary state that is promoted on key
discovery.

### Duplicate Cache Preserves MIC Entropy

Authenticated packets store the actual MIC bytes (up to 16) in the dup cache,
not a hash. This preserves the collision properties the spec intends for longer
MICs. Unauthenticated packets use a 32-bit hash. The two cases are explicit in
the `DupCacheKey` enum.

### Three-Tier Policy

- **Wire-validity** (MAC coordinator, on TX): structural invariants.
- **Local-operating** (`OperatingPolicy` in MAC): mode rules (amateur, emergency).
- **UI acceptance** (`Endpoint::handle_event`): display rules (public-channel S=1, emergency signature).

Collapsing all three into MAC validation would overconstrain lower-level APIs
and prevent testing MAC behavior independently of application rules.

### Zero-Copy Parsing with Mutable Decryption

The packet parser (`PacketHeader::parse`) does not borrow the input buffer. Instead
it copies out the small header fields and records byte ranges. This allows the
caller to subsequently pass the buffer mutably to the crypto engine for in-place
decryption without lifetime conflicts.

### Async Traits

All HAL traits and `NodeIdentity` use `async fn` in traits (stable since Rust 1.75).
The crypto engine methods remain synchronous.

`Endpoint` uses a two-phase event API: `handle_event` is synchronous (called inside
the zero-copy `Mac::poll_cycle` callback while the radio buffer is live), and
`handle_deferred` is async (called after the callback returns, on owned data).
This avoids holding the radio buffer across an await point while still supporting
ECDH, PFS handshake steps, and KV writes when needed.

### `heapless` for `no_std` Collections

Fixed-capacity collections throughout `umsh-mac`. Capacity is configurable via
const generics. For `std` environments, `umsh-node` can use `alloc` collections
behind a feature flag.

### Separate `umsh-hal` Crate

HAL traits (`Radio`, `Clock`, `Rng`, `CounterStore`, `KeyValueStore`) live in
their own crate with **no workspace dependencies**, allowing radio driver and
storage backend crates to depend on `umsh-hal` alone. The `Platform` trait, which
bundles HAL types with crypto types, lives in the `umsh` umbrella crate — not in
`umsh-hal` — because it references `NodeIdentity`, `AesProvider`, and
`Sha256Provider` from `umsh-crypto`.

### Crypto Trait Granularity

`AesProvider` and `Sha256Provider` are separate from `NodeIdentity`. A system might
use a hardware AES peripheral for bulk encryption but software Ed25519 for signing.
The `CryptoEngine` composes them.

### `hamaddr` for ARNCE

The existing `hamaddr` crate is used for ARNCE encoding/decoding, gated behind
the `amateur-radio` feature. The protocol treats amateur operation and constrained
bare-metal deployment as co-equal use cases. ARNCE encoding for the fixed-size
packet option fields (2/4/6/8-byte callsigns, 2-byte IATA region codes) does not
inherently require heap allocation — only fixed-size byte-array I/O. The `hamaddr`
crate's encode/decode path for these wire-format fields must work in `no_std`
without `alloc`. If the current crate's `Display`/`FromStr` implementations pull
in `alloc`, those can remain behind a feature flag, but the packet-level codec
path must not. This may require a patch or a thin `no_alloc` wrapper.

### Explicitly Out of Scope (v1)

Managed channel control messages, node management protocol, and CoAP-over-UMSH
framing are not defined in the spec and are not implemented. No stubs — stubs
have a way of turning "not designed yet" into "accidentally standardized by
implementation."
