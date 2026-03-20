# FAQ

### Can an attacker spoof a MAC Ack to make the sender believe a packet was delivered?

No. A MAC Ack contains an [ack tag](security.md#ack-tag-construction) — an 8-byte value derived by encrypting the full 16-byte CMAC with the pairwise `K_enc`. Computing a valid ack tag requires knowledge of the pairwise encryption key, which in turn requires the ECDH shared secret between the sender and recipient. A passive observer who intercepts the original packet can read the on-wire MIC, but cannot derive the ack tag from it without `K_enc`. Ack forgery is therefore as hard as breaking the pairwise key agreement.

### Doesn't blind unicast have a circular dependency between the MIC and source decryption?

No. The `MIC` field is located at the end of the packet and can be read directly from the wire. It is the pairwise MIC computed over the payload using the sender/recipient shared secret. The receiver reads the MIC, uses it (together with the channel key) as the IV to decrypt `ENC_SRC`, and then derives the pairwise keys from the recovered source public key to authenticate and decrypt `ENC_PAYLOAD`. If the source address has been tampered with, the derived pairwise keys will be wrong and payload authentication will fail. There is no circular dependency — only a specific processing order (see [Blind Unicast](packet-types.md#blind-unicast-packet)).

### Can source-routed packets loop if router hints collide?

No, for two reasons. First, the forwarding path is bounded by the number of router hints in the source route plus the hop count — a packet cannot be forwarded more times than the sum of these values. Second, duplicate suppression (see [Duplicate Suppression](repeater-operation.md#duplicate-suppression)) ensures that each repeater forwards a given packet at most once (identified by MIC). Even if a router hint collision causes an unintended repeater to forward the packet, the probability of subsequent hints also colliding with nearby repeaters drops dramatically at each hop, making extended misrouting extremely unlikely.

### Why doesn't UMSH define a dedicated path-discovery packet type?

The existing primitives are sufficient. A node can discover a path by sending a flooded packet (broadcast, unicast, or beacon) with the trace-route option present. Repeaters prepend their router hints as they forward. The recipient can use the accumulated trace directly as a candidate source route. This avoids adding protocol complexity for a function that composes naturally from existing features. See [Path Discovery](beacons.md#path-discovery) for the full procedure.

### How does UMSH handle frame counter overflow?

The 4-byte frame counter wraps naturally at `2^32`. Replay detection uses modular arithmetic: `delta = (received - last_accepted) mod 2^32`. A positive delta within a reasonable forward window is accepted; zero or excessively large deltas are rejected. This means overflow is not a special case — it is handled identically to any other counter increment. See [Replay Detection](security.md#replay-detection).

### Can a multicast channel member impersonate another member?

Yes. Multicast authentication is based on the shared channel key, not on individual sender identity. Any node with the channel key can construct a valid packet with any claimed source address. This is an inherent property of symmetric-key multicast and is shared by other protocols with similar designs. See [Multicast Sender Authentication](limitations.md#multicast-sender-authentication).

This does not apply to blind unicast. Blind unicast payloads are authenticated using pairwise keys derived from the sender and recipient's key agreement, so only the true sender can produce a valid payload and only the intended recipient can read it.

### When should the S flag (full source address) be set?

The `S` flag controls whether the full 32-byte source public key or a compact 2-byte source hint is included in the packet. Set `S` when:

- This is a first-contact transmission and the receiver has never seen the sender's public key before.
- The sender wants to allow any receiver to perform ECDH and authenticate the packet without prior state.
- The sender is using an ephemeral keypair (anonymous request pattern).

Leave `S` clear when the receiver is known to have the sender's full public key cached — for example, after a prior advertisement, identity exchange, or any earlier `S=1` packet. Using the 2-byte hint saves 30 bytes per packet, which is significant on LoRa.

Receivers that see an unknown source hint on an authenticated packet should treat it as an authentication failure (the cached key lookup fails, so decryption or CMAC verification will fail). The sender can retransmit with `S=1` to provide the full key.

### How does a MAC Ack get routed back to the original sender?

MAC acks are end-to-end: the **final destination** generates the ack, not any intermediate repeater. The ack carries a destination hint and a PKTMIC reference, and like any other packet type it supports the standard optional header fields — including source-route options, hop count, and region code option. If the responding node has a known source route to the original sender (e.g., learned via trace-route on the inbound packet), it can source-route the ack back along that path. Otherwise, the ack floods through the mesh bounded by the hop count, following the same forwarding procedure as any other packet (see [Forwarding Procedure](repeater-operation.md#forwarding-procedure)).

Repeaters do not generate acks themselves. Instead, a repeater can confirm successful forwarding by overhearing the next hop's retransmission of the same packet (see [Forwarding Confirmation](repeater-operation.md#forwarding-confirmation)).

### Why does UMSH use stable pairwise keys instead of a ratcheting scheme like the Signal Protocol?

LoRa mesh networks have high latency, low bandwidth, and unreliable delivery — properties that are hostile to ratcheting protocols. Ratcheting requires reliable in-order message delivery to keep both sides synchronized; a single lost message can desynchronize the ratchet and require an expensive recovery handshake. In a mesh where packets may be lost, duplicated, or arrive out of order, this would lead to frequent resynchronization storms. Stable pairwise keys derived from a single ECDH are simple, stateless, and robust to packet loss. The frame counter and optional salt still provide per-packet uniqueness, and the AES-SIV-inspired construction provides nonce-misuse resistance as an additional safety margin.

When forward secrecy is needed, UMSH provides [PFS sessions](security.md#perfect-forward-secrecy-sessions) — a two-message handshake where both nodes exchange ephemeral node addresses and communicate using session-specific keys for an agreed duration. PFS sessions add no per-packet overhead once established, and the private keys for the ephemeral addresses are erased when the session ends. This provides perfect forward secrecy without the fragility of continuous ratcheting.

### What happens if a 2-byte channel identifier collides across different channel keys?

The 2-byte channel identifier is a hint, not a unique identifier. If two different channel keys happen to produce the same 2-byte channel ID, a receiver configured with both keys will attempt to process the packet with each candidate key. Only the correct key will produce a valid MIC, so the wrong candidate will be rejected during authentication. The cost is wasted computation, not incorrect behavior. With 2 bytes the collision probability is 1 in 65536, which is higher than a 4-byte hint but still negligible for deployments with a small number of configured channels.

### Why use an AES-SIV-inspired construction instead of AES-GCM?

AES-GCM is catastrophically vulnerable to nonce reuse — repeating a nonce with the same key completely breaks both confidentiality and authenticity. In a mesh network, nonce management is difficult: nodes may reboot and lose counter state, clocks may not be synchronized, and packets may be retransmitted. The SIV-style construction used by UMSH is nonce-misuse-resistant: even if a nonce is accidentally reused, the only consequence is that an observer can detect that two plaintexts are identical. Confidentiality and authenticity are otherwise preserved. This robustness is worth the minor overhead of computing the MIC before encryption.

### How does "deliver to a region, then flood" work?

A sender can include both a source-route option and a hop count in the same packet. The source-route directs the packet through specific repeaters, and as each repeater forwards, it removes its own hint. Once all source-route hints are consumed, the packet transitions to flood-based forwarding bounded by the remaining hop count. This allows targeted delivery to a specific area of the mesh followed by a local flood — useful when searching for a node in a known geographic region without flooding the entire network. See [Routing Implications](repeater-operation.md#routing-implications).

### Can UMSH support anonymous requests, similar to MeshCore's ANON_REQ mechanism?

Yes. A node can generate an ephemeral Ed25519 keypair, set the `S` flag, and use the ephemeral public key as the source address for a single request, then discard the private key immediately afterward. The recipient performs ECDH with the ephemeral public key as normal, encrypts a response to it, and sends it back. The requester's long-term identity is never revealed. This pattern also provides forward secrecy for the exchange: once the ephemeral private key is discarded, the session cannot be decrypted even if the requester's long-term key is later compromised. No dedicated packet type is required.

### Does UMSH support automatic route learning?

Yes. A node that wants to learn a source route to a peer sends any flooded packet (unicast, broadcast, or beacon) with the trace-route option present. Repeaters prepend their router hint as they forward. When the peer receives the packet, the trace-route option contains the accumulated path, ordered nearest-repeater-first, and can be used directly as a source-route option on reply packets. Both sides can learn routes simultaneously by including the trace-route option on their outbound packets and caching the results. See [Path Discovery](beacons.md#path-discovery) for the full path-discovery procedure.
