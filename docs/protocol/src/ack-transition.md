# Ack Authentication Transition

A MAC Ack's [ack tag](security.md#ack-tag-construction) is a MIC over the ack's own static options, bound to the packet it acknowledges. Some nodes instead seal acks with a legacy tag, which covers the acknowledged packet but none of the ack's options. This appendix defines the legacy tag, the option that marks it, and how senders and receivers choose between the two constructions while both are in use. The legacy construction and option 254 will be removed.

## Legacy Construction

```text
ack_tag = truncate_to_4( AES-256-ECB( key=K_enc, block=V ) )
```

Where:

- `K_enc` is the encryption key that sealed the original packet—the pairwise key for unicast, or the [combined blind unicast key](security.md#blind-unicast-payload-keys) for blind unicast
- `V` is the original packet's full 16-byte S2V output, before truncation to its on-wire MIC length

AES-ECB on a single 16-byte block is the raw AES block cipher—a pseudorandom permutation—and does not have the pattern-leakage weakness associated with multi-block ECB encryption. The legacy tag covers none of the ack's options, so a static option on a legacy-tagged ack is unauthenticated.

## Legacy Ack Tag (option 254)

- Type: flag. Non-Critical, Dynamic, 0 bytes. A receiver treats the option as present whatever its value.
- Semantics: present on a [MAC Ack](packet-types.md#mac-ack-packet) whose `ACK TAG` uses the legacy construction. A receiver ignores it on any other packet type.
- A sender MUST NOT include more than one.
- Being dynamic, the option never enters the [associated data](security.md#associated-data), and a repeater forwards it unchanged.

## Sending

A node sealing an acknowledgement:

- uses the [MIC construction](security.md#ack-tag-construction) when the ack carries a static option, and does not include option 254;
- otherwise uses the legacy construction and includes option 254.

## Verifying

The original sender matches an incoming ack to an outstanding request by its `ACK MIC`, then verifies its `ACK TAG` with the construction its options admit:

| Option 254 | Static option | Verified as |
|---|---|---|
| present | any | legacy construction only |
| absent | present | MIC construction only |
| absent | absent | MIC construction, then legacy construction |

The last row accepts a legacy-tagged ack from a node that does not implement option 254, and a MIC-tagged ack from a node that no longer sends the legacy construction. A forged ack of that shape matches either of two tags, so it succeeds with probability `2^-31` per attempt rather than `2^-32`. An ack whose tag verifies under no admitted construction is discarded.

## Test Vector

Node B's acknowledgement of [Example 4](test-vectors.md#example-4-encrypted-unicast-with-ack-requested-s1), sealed with the legacy construction. `V` is Example 4's 16-byte MIC, and the keys are those of the [test-vector conventions](test-vectors.md#conventions).

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=1 (MAC ack), S=0, R=0, H=0 | `C8` |
| Options | Legacy Ack Tag (option 254) | `D0 F1` |
| ACK MIC | First 4 bytes of V | `AA 17 13 06` |
| ACK TAG | `truncate_to_4(AES-256-ECB(K_enc, V))` | `99 FC 2D 9F` |

```text
C8 D0 F1 AA 17 13 06 99 FC 2D 9F
```

Total: 11 bytes.
