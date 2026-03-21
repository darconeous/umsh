# Test Vectors

This appendix contains byte-level packet examples for implementors. All values are in hexadecimal. Multi-byte numeric fields are big-endian.

Cryptographic outputs (ciphertext, MIC values) are illustrative — they do not correspond to real key material. Implementations should verify field layout and byte counts, not the specific cryptographic values shown here.

## Conventions

The following fictional values are used consistently across examples:

- **Node A** public key: `A1B2 0304 0506 0708 090A 0B0C 0D0E 0F10 1112 1314 1516 1718 191A 1B1C 1D1E 1F20` (hint: `A1B2`)
- **Node B** public key: `C3D4 2526 2728 292A 2B2C 2D2E 2F30 3132 3334 3536 3738 393A 3B3C 3D3E 3F40` (hint: `C3D4`)
- **Channel key**: `5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A` (channel hint: `7E5F`)

### FCF Bit Layout Reference

```text
  7   6   5   4   3   2   1   0
+-------+-----------+---+---+---+
| VER   | PKT TYPE  | S | O | H |
+-------+-----------+---+---+---+
```

### SCF Bit Layout Reference

```text
  7   6   5   4   3   2   1   0
+---+-------+---+---------------+
| E |  MIC  | S |   RESERVED    |
+---+-------+---+---------------+
```

## Example 1: Broadcast Beacon (S=0)

A minimal beacon — a broadcast with no payload and no security.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=0, O=0, H=0 | `C0` |
| SRC | Node A hint | `A1 B2` |

```text
C0 A1 B2
```

Total: 3 bytes.

## Example 2: Broadcast Beacon (S=1)

A first-contact beacon including the sender's full 32-byte public key.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=1, O=0, H=0 | `C4` |
| SRC | Node A full key | `A1 B2 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20` |

```text
C4 A1 B2 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
20
```

Total: 33 bytes.

## Example 3: Unicast Packet (S=0)

An encrypted unicast packet from Node A to Node B using source hints.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=2 (unicast), S=0, O=0, H=0 | `D0` |
| DST | Node B hint | `C3 D4` |
| SRC | Node A hint | `A1 B2` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 42 | `00 00 00 2A` |
| Payload | Encrypted (5 bytes) | `8B 3F C7 A2 15` |
| MIC | 16 bytes | `F0 E1 D2 C3 B4 A5 96 87 78 69 5A 4B 3C 2D 1E 0F` |

```text
D0 C3 D4 A1 B2 E0 00 00 00 2A 8B 3F C7 A2 15 F0
E1 D2 C3 B4 A5 96 87 78 69 5A 4B 3C 2D 1E 0F
```

Total: 31 bytes (1 + 2 + 2 + 5 + 5 + 16).

## Example 4: Unicast with Ack Requested (S=1)

A first-contact encrypted unicast from Node A to Node B requesting a MAC acknowledgement. The full 32-byte source key is included so the receiver can perform ECDH without prior state.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=3 (unicast ack-req), S=1, O=0, H=0 | `DC` |
| DST | Node B hint | `C3 D4` |
| SRC | Node A full key | `A1 B2 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 1 | `00 00 00 01` |
| Payload | Encrypted (3 bytes) | `55 AA 33` |
| MIC | 16 bytes | `B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF` |

```text
DC C3 D4 A1 B2 03 04 05 06 07 08 09 0A 0B 0C 0D
0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D
1E 1F 20 E0 00 00 00 01 55 AA 33 B0 B1 B2 B3 B4
B5 B6 B7 B8 B9 BA BB BC BD BE BF
```

Total: 59 bytes (1 + 2 + 32 + 5 + 3 + 16).

## Example 5: Encrypted Multicast (E=1)

An encrypted multicast from Node A. The source hint and payload are encrypted together, concealing the sender from observers without the channel key.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, O=0, H=0 | `E0` |
| CHANNEL | Channel hint | `7E 5F` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 5 | `00 00 00 05` |
| Encrypted data | ENCRYPT(SRC hint \|\| payload) — 7 bytes | `D4 9C 71 E8 3A 5B 02` |
| MIC | 16 bytes | `AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99` |

```text
E0 7E 5F E0 00 00 00 05 D4 9C 71 E8 3A 5B 02 AA
BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99
```

Total: 30 bytes (1 + 2 + 5 + 7 + 16). The 7 encrypted bytes contain the 2-byte source hint and 5 bytes of plaintext payload.

## Example 6: Unencrypted Multicast (E=0)

An authenticated but unencrypted multicast from Node A. The source hint appears in cleartext.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, O=0, H=0 | `E0` |
| CHANNEL | Channel hint | `7E 5F` |
| SCF | E=0, MIC=3 (16-byte), S=0 | `60` |
| Frame Counter | 3 | `00 00 00 03` |
| SRC | Node A hint | `A1 B2` |
| Payload | Payload type 3 (text message) + "Hello" | `03 48 65 6C 6C 6F` |
| MIC | 16 bytes | `11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00` |

```text
E0 7E 5F 60 00 00 00 03 A1 B2 03 48 65 6C 6C 6F
11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00
```

Total: 32 bytes (1 + 2 + 5 + 2 + 6 + 16).

## Example 7: Unicast with Options

An encrypted unicast from Node A to Node B with a flood hop limit of 4 (FHOPS_REM=4, FHOPS_ACC=0), a region code option, and an empty trace-route option (to be populated by repeaters during flooding).

**Options encoding:**

| Option | Number | Delta | Length | Encoding |
|---|---:|---:|---:|---|
| Region Code | 1 | 1 | 2 | `12` then value `78 53` |
| Trace Route | 2 | 1 | 0 | `10` |
| End marker | — | — | — | `FF` |

The region code value `7853` encodes "SJC" in ARNCE/HAM-64.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=2 (unicast), S=0, O=1, H=1 | `D3` |
| Options | Region code (1) + trace route (2) + end marker | `12 78 53 10 FF` |
| FHOPS | FHOPS_REM=4, FHOPS_ACC=0 | `40` |
| DST | Node B hint | `C3 D4` |
| SRC | Node A hint | `A1 B2` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 10 | `00 00 00 0A` |
| Payload | Encrypted (3 bytes) | `8B 3F C7` |
| MIC | 16 bytes | `D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF` |

```text
D3 12 78 53 10 FF 40 C3 D4 A1 B2 E0 00 00 00 0A
8B 3F C7 D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC
DD DE DF
```

Total: 35 bytes (1 + 5 + 1 + 2 + 2 + 5 + 3 + 16).
