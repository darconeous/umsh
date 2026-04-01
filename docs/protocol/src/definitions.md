# Definitions

The following terms are used throughout this specification. Definitions are given in the context of UMSH; terms with broader meanings in other fields are defined here as they apply to this protocol.

**Address**
: A node's 32-byte Ed25519 public key, used as its stable network identifier. UMSH addresses are not numeric values used for routing. Short *address hints* derived from the address are used on the wire to save space.

**Address Hint**
: A short prefix of a node's public key used as a cheap prefilter before full cryptographic processing. These can be 1, 2, or 3 bytes long, depending on where and how they are used. See [Addressing](addressing.md).

**AES (Advanced Encryption Standard)**
: A symmetric block cipher standardized by NIST. UMSH uses AES-128 in CTR mode for payload encryption and AES-CMAC for message authentication.

**AES-SIV (Synthetic Initialization Vector)**
: A misuse-resistant authenticated encryption scheme (RFC 5297) in which the initialization vector is derived from an authentication tag computed over the plaintext. If the same plaintext is accidentally encrypted twice with the same key, the output reveals only that duplication — keys and other traffic remain uncompromised. UMSH uses a construction inspired by AES-SIV: AES-CMAC is used to compute the MIC, which then seeds AES-128-CTR for encryption.

**ARNCE/HAM-64**
: A compact character encoding scheme for amateur radio callsigns, encoding up to 12 characters into 2, 4, 6, or 8 bytes. Used in UMSH's Operator Callsign and Station Callsign packet options.

**Beacon**
: A broadcast or multicast packet with an empty payload. Beacons advertise a node's presence and are used for path discovery and route learning. See [Beacons & Path Discovery](beacons.md).

**Blind Unicast**
: A packet type that carries a unicast payload addressed to a specific destination while concealing both the sender and destination identities from observers who do not possess the channel key. The destination hint and source address are encrypted using the channel key; the payload is protected end-to-end using keys derived from both the channel key and the pairwise shared secret. See [Frame Types](packet-types.md#blind-unicast-packet).

**Bridge**
: A node that relays UMSH packets between two different media or channels — for example, from a local LoRa radio to an internet backhaul and back to a distant LoRa radio. Bridges are protocol-transparent: they consume source-route hints and forward packets as repeaters do, but their onward transmission cannot be observed on the inbound medium.

**Broadcast**
: A packet intended for all nodes in range. Broadcast packets carry no destination hint and are not encrypted or authenticated at the MAC layer. See [Frame Types](packet-types.md).

**CAD (Channel Activity Detection)**
: A LoRa physical-layer feature that listens briefly for preamble energy on the channel with minimal power draw. UMSH uses CAD to implement listen-before-talk channel access, reducing collisions without requiring continuous reception. See [Channel Access](channel-access.md).

**Channel**
: A logical communication group secured by a shared symmetric key. Channels serve two purposes: group communication (multicast) and metadata concealment (blind unicast). See [Channels](multicast-channels.md).

**CoAP (Constrained Application Protocol)**
: A lightweight request/response protocol designed for constrained networks (RFC 7252). UMSH borrows CoAP's delta-length option encoding for packet options and application-layer payloads.

**Confidentiality**
: The property that payload content is accessible only to intended recipients. UMSH provides confidentiality via AES-128 encryption keyed with material derived from ECDH (unicast) or the channel key (multicast).

**Duplicate Suppression**
: A mechanism by which repeaters track recently forwarded packets and decline to forward the same packet a second time. Each packet is identified by its MIC (for authenticated packets) or a locally computed hash (for unauthenticated packets). This prevents flood-routed packets from circulating indefinitely. See [Repeater Operation](repeater-operation.md#duplicate-suppression).

**ECDH (Elliptic Curve Diffie-Hellman)**
: A key agreement protocol that allows two parties to derive a shared secret using only their public keys and their own private keys. UMSH uses X25519 ECDH to derive pairwise shared secrets for unicast encryption and authentication.

**Ed25519**
: An elliptic curve digital signature algorithm using the Edwards25519 curve. UMSH uses Ed25519 keypairs as node identities. The same keypair is converted to X25519 form for key agreement.

**EdDSA (Edwards-curve Digital Signature Algorithm)**
: The family of signature algorithms that includes Ed25519. Used in UMSH for payload signatures, most notably for node identity broadcasts.

**Ephemeral Key**
: A temporary Ed25519 keypair generated for a single PFS session. Unlike a long-term identity keypair, ephemeral keys are never written to persistent storage and are explicitly erased when the session ends, ensuring that compromise of long-term keys cannot retroactively decrypt traffic protected by them. See [Security & Cryptography](security.md#perfect-forward-secrecy-sessions).

**Flood Routing**
: A routing strategy where a packet is forwarded by every eligible repeater within the flood radius, subject to duplicate suppression. Requires no topology state at repeaters. Bounded by the flood hop count field (`FHOPS`). See [Repeater Operation](repeater-operation.md).

**Frame**
: The unit of transmission at the LoRa PHY layer. A UMSH packet must fit within a single frame. The terms *frame* and *packet* are used interchangeably in this specification; *frame* emphasizes the physical transmission unit, *packet* emphasizes the logical protocol unit.

**Frame Counter**
: A monotonically increasing 4-byte value included in every authenticated packet. The receiver tracks recently seen counter values and rejects packets with counters it has already processed, providing replay protection without requiring synchronized clocks. The counter must be persisted across reboots to prevent reuse. See [Security & Cryptography](security.md#frame-counters).

**Hop**
: One leg of a packet's path through the network — the transmission from one node to an adjacent node within radio range. A packet that travels through two repeaters before reaching its destination has traversed three hops.
The protocol differentiates between source-routed hops and flood-routed hops.

**HKDF (HMAC-based Key Derivation Function)**
: A key derivation function standardized in RFC 5869, composed of two steps: Extract (combining a secret and optional salt into a pseudorandom key) and Expand (stretching that key to the required output length). UMSH uses HKDF-SHA256 with domain-separated labels to derive encryption keys, authentication keys, and channel identifiers from shared secrets and channel keys.

**IoT (Internet of Things)**
: A broad term for networked embedded devices. UMSH is designed to be applicable to IoT use cases in addition to human communication, though it is optimized for the latter.

**Latency**
: The time elapsed between a packet being transmitted and its receipt or acknowledgement. LoRa's low data rate and mesh forwarding introduce significant latency compared to IP networks.

**LoRa (Long Range)**
: A proprietary wireless modulation technology using chirp spread spectrum, designed for long range and low power consumption at the cost of low data rate. LoRa payloads are typically limited to 200–250 bytes, and transmitting a single packet may take hundreds of milliseconds depending on spreading factor and bandwidth. UMSH is designed around these constraints.

**Long-Term Identity**
: A node's stable Ed25519 keypair, used as its persistent network identity. Contrast with ephemeral keypairs used in PFS sessions, which are discarded after use.

**MAC Layer (Medium Access Control)**
: The sublayer of the data link layer responsible for addressing, packet framing, and channel access. In UMSH, the MAC layer handles packet types, addressing, routing options, and cryptography. Application-layer protocols are carried in the payload and are defined separately.

**MAC Ack**
: A packet type generated by the final destination of a unicast packet (UACK or BUAK) to confirm receipt. The MAC Ack carries an *ack tag* — an 8-byte value derived from the original packet's MIC and the pairwise encryption key — which allows the original sender to verify the acknowledgement. Repeaters do not generate MAC Acks; they forward them like any other packet. See [Frame Types](packet-types.md#mac-ack-packet).

**Mesh**
: A network topology where nodes can relay packets on behalf of other nodes, enabling communication beyond direct radio range. UMSH is designed for LoRa mesh networks where repeaters and bridges are used to extend coverage.

**MIC (Message Integrity Code)**
: UMSH's authentication tag, computed using AES-CMAC over the packet's static fields and payload. Size is configurable from 4 to 16 bytes. The term MIC is used instead of the more common "MAC" (Message Authentication Code) to avoid confusion with Medium Access Control. See [Security & Cryptography](security.md).

**Multicast**
: A packet intended for all members of a channel, identified by a 2-byte channel identifier derived from the channel key. See [Frame Types](packet-types.md).

**Node**
: A logical participant in a UMSH network, defined by a unique Ed25519 keypair. A single physical device may host multiple nodes. A node may act as an endpoint (sending and receiving application data), a repeater (forwarding packets), or both.

**Packet**
: The logical unit of the UMSH protocol. Every packet must fit within a single LoRa frame. See *Frame* above.

**Pairwise Key**
: A symmetric key derived from X25519 ECDH between a specific sender and recipient. Each pair of nodes shares a unique set of pairwise keys (one for encryption, one for authentication) derived deterministically from their long-term key material. Pairwise keys are stable across sessions unless a PFS session is used. See [Security & Cryptography](security.md).

**PFS (Perfect Forward Secrecy)**
: A property ensuring that compromise of long-term keys does not allow retroactive decryption of past traffic. UMSH provides optional PFS via ephemeral keypair sessions. See [Security & Cryptography](security.md#perfect-forward-secrecy-sessions).

**PHY (Physical Layer)**
: The lowest layer of a network stack, responsible for modulation and transmission over the physical medium. In UMSH deployments, this is typically LoRa. The PHY layer is below the MAC layer and is not defined by this specification.

**Private Key**
: The secret half of an asymmetric keypair. In UMSH, a node's Ed25519 private key is used to derive its X25519 private key for ECDH and to sign payloads when required. Must never be transmitted or disclosed.

**Privacy**
: Broader than confidentiality: the protection of metadata and communication patterns in addition to payload content. UMSH provides confidentiality but does not fully protect against traffic analysis. See [Security Considerations](security-considerations.md#metadata-exposure).

**Public Key**
: The public half of an asymmetric keypair, which can be freely shared. In UMSH, a node's Ed25519 public key *is* its address. Address hints are derived from it.

**RSSI (Received Signal Strength Indicator)**
: A measurement of received radio signal power, expressed in dBm (negative values; higher is stronger). Used in UMSH's Minimum RSSI packet option and in repeater forwarding decisions to filter out packets received with insufficient signal strength. See [Packet Options](packet-options.md#minimum-rssi-option-5).

**Repeater**
: A node that forwards packets to extend the effective range of the mesh. Repeaters participate in flood routing and source routing but do not generate or consume application payloads for the packets they forward. See [Repeater Operation](repeater-operation.md).

**SNR (Signal-to-Noise Ratio)**
: A measurement of the ratio between received signal power and background noise, expressed in dB. Unlike RSSI, SNR remains meaningful at very low signal levels and is used by LoRa for demodulation decisions. Used in UMSH's Minimum SNR packet option and in repeater contention delay calculations. See [Packet Options](packet-options.md#minimum-snr-option-9).

**Source Routing**
: A routing strategy where the sender specifies the explicit sequence of repeaters a packet must traverse. Requires the sender to have prior knowledge of a valid path. See [Packet Options](packet-options.md#source-route-option-3).

**Trace Route**
: A packet option that instructs each forwarding repeater to prepend its router hint to the option value, building an ordered record of the path a packet has taken (most-recent repeater first). Used for route learning: a destination that receives a packet with a trace route has enough information to construct a source route for the reply. See [Packet Options](packet-options.md#trace-route-option-2).

**Unicast**
: A packet addressed to a single destination node, identified by a 3-byte destination hint. Unicast packets are always authenticated end-to-end; encryption is optional and controlled by the `E` flag. See [Frame Types](packet-types.md).

**URI (Uniform Resource Identifier)**
: A compact string that identifies a resource or address. UMSH defines URI schemes for addressing nodes and channels. See [URI Formats](uri-formats.md).

**X25519**
: An elliptic curve Diffie-Hellman function over Curve25519. UMSH converts Ed25519 keypairs to X25519 form for key agreement. The conversion is deterministic and well-defined.
