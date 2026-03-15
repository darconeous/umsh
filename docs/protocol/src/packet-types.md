# Frame Types

## Broadcast Packet

Broadcast packets carry a source and payload, but no security info.

```text
+-----+-----------+------+-----+---------+
| FCF | [OPTIONS] |[HOPS]| SRC | PAYLOAD |
+-----+-----------+------+-----+---------+
  1 B    variable   0/1 B 2/32B   var.
```

A broadcast with an empty payload is a **Beacon**.

## MAC Ack Packet

A MAC acknowledgement identifies the recipient by destination hint and carries a packet MIC reference.

```text
+-----+-----------+------+-----+--------+
| FCF | [OPTIONS] |[HOPS]| DST | PKTMIC |
+-----+-----------+------+-----+--------+
  1 B    variable   0/1 B  2 B    var.
```

Where:

- `DST` is the 2-byte destination hint
- `PKTMIC` is the truncated MIC from the original packet,
   up to 8 bytes (or less if the original MIC was smaller)

## Unicast Packet

Unicast packets are addressed by destination hint and carry the source address.

```text
+-----+-----------+------+-----+------+---------+---------+------+
| FCF | [OPTIONS] |[HOPS]| DST | SRC  | SECINFO | PAYLOAD | MIC  |
+-----+-----------+------+-----+------+---------+---------+------+
  1 B    variable   0/1 B  2 B  2/32B   5/7 B     var.   4-16 B
```

`DST` is the first two bytes of the recipient's public key.

Receivers first use `DST` as a cheap filter, then use the source public key (or its cached equivalent when only a hint is present) and their own key to derive the shared secret and authenticate/decrypt the packet.

## Unicast Packet with Ack Requested

This is identical to unicast, but the packet-type value signals that a MAC acknowledgement is requested.

```text
+-----+-----------+------+-----+------+---------+---------+------+
| FCF | [OPTIONS] |[HOPS]| DST | SRC  | SECINFO | PAYLOAD | MIC  |
+-----+-----------+------+-----+------+---------+---------+------+
```

Semantics differ, wire layout does not.

## Multicast Packet

Multicast packets carry a 2-byte channel identifier and source address.

```text
+-----+-----------+------+---------+------+---------+---------+------+
| FCF | [OPTIONS] |[HOPS]| CHANNEL | SRC  | SECINFO | PAYLOAD | MIC  |
+-----+-----------+------+---------+------+---------+---------+------+
  1 B    variable   0/1 B    2 B    2/32B   5/7 B     var.   4-16 B
```

The 2-byte channel identifier is a hint derived from the channel key.

### Channel Identifier Derivation

```text
channel_id = first_2_bytes( HKDF-SHA256(channel_key, salt="UMSH-CHAN-ID", info="", L=2) )
```

## Blind Multicast Packet

Blind multicast hides the source address from observers who do not know the channel key by encrypting the source together with the payload.

```text
+-----+-----------+------+---------+---------+---------------------+------+
| FCF | [OPTIONS] |[HOPS]| CHANNEL | SECINFO | ENCRYPTED(SRC||PLD) | MIC  |
+-----+-----------+------+---------+---------+---------------------+------+
  1 B    variable   0/1 B    2 B     5/7 B          var.           4-16 B
```

The `SRC` inside the ciphertext follows the `S` flag convention: a 2-byte hint when `S` is clear, or the full 32-byte public key when `S` is set.

Only a node with the correct channel key can recover the source address and payload.

## Blind Unicast Packet

Blind unicast uses a multicast channel to conceal sender and destination metadata from observers without the channel key while still protecting the payload end-to-end for the actual destination.

```text
+-----+-----------+------+---------+---------+-------------+------------------+------+
| FCF | [OPTIONS] |[HOPS]| CHANNEL | SECINFO | ENC_SRC(32) | ENC_PAYLOAD(var) | MIC  |
+-----+-----------+------+---------+---------+-------------+------------------+------+
  1 B    variable   0/1 B    2 B     5/7 B      32 B            var.           4-16 B
```

The `MIC` is the pairwise MIC computed over the payload using the sender/recipient shared secret. `ENC_SRC` is encrypted using the channel key and the `MIC` as IV (see [Security & Cryptography](security.md#blind-unicast-source-encryption)). Because `ENC_SRC` decryption depends on the `MIC`, any tampering with the source address will produce an incorrect public key, causing pairwise key derivation to fail and payload authentication to reject.

### Blind Unicast Processing

1. Receiver uses `CHANNEL` to identify candidate channel keys.
2. Receiver reads the `MIC` from the end of the packet.
3. Receiver uses the channel key and `MIC` to decrypt `ENC_SRC`, recovering the sender's public key.
4. Receiver converts the sender Ed25519 public key into an X25519 public key.
5. Receiver converts its own Ed25519 private key into an X25519 private key.
6. Receiver performs ECDH.
7. Receiver derives the stable pairwise encryption and authentication keys.
8. Receiver authenticates and decrypts `ENC_PAYLOAD` using the pairwise keys.
9. If authentication fails, the packet is rejected.

## Blind Unicast with Ack Requested

Same wire layout as blind unicast, but with ack-requested semantics.

```text
+-----+-----------+------+---------+---------+-------------+------------------+------+
| FCF | [OPTIONS] |[HOPS]| CHANNEL | SECINFO | ENC_SRC(32) | ENC_PAYLOAD(var) | MIC  |
+-----+-----------+------+---------+---------+-------------+------------------+------+
```
