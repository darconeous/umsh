# Test Vectors

This appendix contains byte-level packet examples. All values are hexadecimal, and multi-byte numeric fields are big-endian.

## Conventions

The generated examples use fixed Ed25519 private keys so the appendix covers the full path from private key to public key to X25519 ECDH to packet bytes.

- Node A private key: `1112 1314 1516 1718 191A 1B1C 1D1E 1F20 2122 2324 2526 2728 292A 2B2C 2D2E 2F30`
- Node A public key: `ED54 A59F B1AC 3A51 2393 5136 2941 B868 E85A 60E3 D7B2 485D 8288 21DC 7A69 C279`
  - Source hint: `ED 54 A5`
- Node B private key: `3132 3334 3536 3738 393A 3B3C 3D3E 3F40 4142 4344 4546 4748 494A 4B4C 4D4E 4F50`
- Node B public key: `6C28 FD05 8C18 C88C 6CCE 2AF9 81D2 D11C 851B 123E D5B6 9B78 7677 3ED0 99EA 3F83`
  - Destination hint: `6C 28 FD`
- Pairwise shared secret: `5ADD 834F C109 FAD5 2F04 1C5A F84A 7966 526D 364D 1895 AFFC D794 E044 F3A9 DB14`
  - Derived from the two private keys via the implementation's Ed25519-to-X25519 conversion and X25519 ECDH.
- Channel key: `5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A`
- Derived channel identifier: `B0 8D`

### FCF Bit Layout Reference

```text
  7   6   5   4   3   2   1   0
+-------+-----------+---+---+---+
| VER   | PKT TYPE  | S | R | H |
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

A minimal beacon with a 3-byte source hint and no payload.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=0, R=0, H=0 | `C0` |
| SRC | Node A hint | `ED 54 A5` |

```text
C0 ED 54 A5
```

Total: 4 bytes.

## Example 2: Broadcast Beacon (S=1)

A first-contact beacon carrying the sender's full 32-byte public key.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=1, R=0, H=0 | `C4` |
| SRC | Node A full key | `ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79` |

```text
C4 ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8
68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2
79
```

Total: 33 bytes.

## Example 3: Encrypted Unicast (S=0)

An encrypted unicast from Node A to Node B using source hints and frame counter 42.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=2 (unicast), S=0, R=0, H=0 | `D0` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A hint | `ED 54 A5` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 42 | `00 00 00 2A` |
| Payload | Encrypted `48 65 6C 6C 6F` (`"Hello"`) | `71 35 36 4B C1` |
| MIC | 16 bytes | `97 6D DC 92 2E BA 11 B7 2E 6B B1 7B 36 49 C5 4A` |

```text
D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF 71 35 36
4B C1 97 6D DC 92 2E BA 11 B7 2E 6B B1 7B 36 49
C5 4A
```

Total: 34 bytes.

## Example 4: Encrypted Unicast with Ack Requested (S=1)

A first-contact encrypted unicast from Node A to Node B requesting a MAC acknowledgement. The full 32-byte source key is included.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=3 (unicast ack-req), S=1, R=0, H=0 | `DC` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A full key | `ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 1 | `00 00 00 01` |
| Payload | Encrypted `68 65 79` (`"hey"`) | `9C 77 59` |
| MIC | 16 bytes | `E9 9F 4C 5F 9D 3E 4F 4E D3 CC B2 1E F5 C0 01 97` |

```text
DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36
29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC
7A 69 C2 79 E0 00 00 00 01 FF 9C 77 59 E9 9F 4C
5F 9D 3E 4F 4E D3 CC B2 1E F5 C0 01 97
```

Total: 61 bytes.

## Example 5: Encrypted Multicast (E=1)

An encrypted multicast from Node A on channel `B08D`. The encrypted body contains the source hint followed by the plaintext payload.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, R=0, H=0 | `E0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 5 | `00 00 00 05` |
| Encrypted data | ENCRYPT(`SRC || "Hello"`) | `39 E5 95 FE 97 AF A8 90` |
| MIC | 16 bytes | `30 E3 26 92 83 DB 9A 69 AB 12 64 1E B3 22 42 D6` |

```text
E0 B0 8D E0 00 00 00 05 FF 39 E5 95 FE 97 AF A8
90 30 E3 26 92 83 DB 9A 69 AB 12 64 1E B3 22 42
D6
```

Total: 33 bytes.

## Example 6: Authenticated Multicast (E=0)

An authenticated but unencrypted multicast from Node A carrying payload type `03` followed by `"Hello"`.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, R=0, H=0 | `E0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=0, MIC=3 (16-byte), S=0 | `60` |
| Frame Counter | 3 | `00 00 00 03` |
| SRC | Node A hint | `ED 54 A5` |
| Payload | `03 || "Hello"` | `03 48 65 6C 6C 6F` |
| MIC | 16 bytes | `53 A5 E2 91 F5 40 0A B9 87 FE C7 14 9D F8 97 24` |

```text
E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C
6C 6F 53 A5 E2 91 F5 40 0A B9 87 FE C7 14 9D F8
97 24
```

Total: 34 bytes.

## Example 7: Encrypted Unicast with Options and Flood Hops

An encrypted unicast with a region code option, an empty trace-route option, and flood hop limit 4.

**Options encoding:**

| Option | Number | Delta | Length | Encoding |
|---|---:|---:|---:|---|
| Trace Route | 2 | 2 | 0 | `20` |
| Region Code | 11 | 9 | 2 | `92` then value `78 53` |
| End marker | — | — | — | `FF` |

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=2 (unicast), S=0, R=0, H=1 | `D1` |
| FHOPS | FHOPS_REM=4, FHOPS_ACC=0 | `40` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A hint | `ED 54 A5` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 10 | `00 00 00 0A` |
| Options | Trace route + region code + end marker | `20 92 78 53 FF` |
| Payload | Encrypted `68 65 79` (`"hey"`) | `79 F8 9D` |
| MIC | 16 bytes | `96 91 3C 78 8E 38 5F 64 04 DA 6B 4F 90 4A 7B 38` |

```text
D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 20 92 78
53 FF 79 F8 9D 96 91 3C 78 8E 38 5F 64 04 DA 6B
4F 90 4A 7B 38
```

Total: 37 bytes.

## Example 8: Blind Unicast (S=0)

A blind unicast on channel `B08D`. The destination hint and source hint are encrypted together in `ENC_DST_SRC`, while the payload is encrypted with the blind-unicast payload keys.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=6 (blind unicast), S=0, R=0, H=0 | `F0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 7 | `00 00 00 07` |
| ENC_DST_SRC | ENCRYPT(`DST || SRC`) | `A4 FB D3 6A A0 87` |
| ENC_PAYLOAD | ENCRYPT(`"Hello"`) | `4E 55 F2 08 51` |
| MIC | 16 bytes | `F6 21 C9 8C 78 F7 90 92 34 0D E7 12 AA 07 AE 77` |

```text
F0 B0 8D E0 00 00 00 07 FF A4 FB D3 6A A0 87 4E
55 F2 08 51 F6 21 C9 8C 78 F7 90 92 34 0D E7 12
AA 07 AE 77
```

Total: 36 bytes.
