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

A minimal beacon with a 3-byte source hint and no payload.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=0, O=0, H=0 | `C0` |
| SRC | Node A hint | `ED 54 A5` |

```text
C0 ED 54 A5
```

Total: 4 bytes.

## Example 2: Broadcast Beacon (S=1)

A first-contact beacon carrying the sender's full 32-byte public key.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=1, O=0, H=0 | `C4` |
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
| FCF | VER=3, TYPE=2 (unicast), S=0, O=0, H=0 | `D0` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A hint | `ED 54 A5` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 42 | `00 00 00 2A` |
| Payload | Encrypted `48 65 6C 6C 6F` (`"Hello"`) | `4F A0 84 B2 92` |
| MIC | 16 bytes | `EA 32 F4 91 09 E8 D4 E6 01 16 73 C1 5B 31 84 F0` |

```text
D0 6C 28 FD ED 54 A5 E0 00 00 00 2A 4F A0 84 B2
92 EA 32 F4 91 09 E8 D4 E6 01 16 73 C1 5B 31 84
F0
```

Total: 33 bytes.

## Example 4: Encrypted Unicast with Ack Requested (S=1)

A first-contact encrypted unicast from Node A to Node B requesting a MAC acknowledgement. The full 32-byte source key is included.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=3 (unicast ack-req), S=1, O=0, H=0 | `DC` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A full key | `ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 1 | `00 00 00 01` |
| Payload | Encrypted `68 65 79` (`"hey"`) | `68 CF 7B` |
| MIC | 16 bytes | `96 3F CE BA 86 8C 92 96 DD E2 E5 0F 5B 54 42 3F` |

```text
DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36
29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC
7A 69 C2 79 E0 00 00 00 01 68 CF 7B 96 3F CE BA
86 8C 92 96 DD E2 E5 0F 5B 54 42 3F
```

Total: 60 bytes.

## Example 5: Encrypted Multicast (E=1)

An encrypted multicast from Node A on channel `B08D`. The encrypted body contains the source hint followed by the plaintext payload.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, O=0, H=0 | `E0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 5 | `00 00 00 05` |
| Encrypted data | ENCRYPT(`SRC || "Hello"`) | `9B B6 F2 5E C7 DA 95 D2` |
| MIC | 16 bytes | `30 35 87 B0 01 F2 17 98 7A 08 1C F5 6E DC 85 36` |

```text
E0 B0 8D E0 00 00 00 05 9B B6 F2 5E C7 DA 95 D2
30 35 87 B0 01 F2 17 98 7A 08 1C F5 6E DC 85 36
```

Total: 32 bytes.

## Example 6: Authenticated Multicast (E=0)

An authenticated but unencrypted multicast from Node A carrying payload type `03` followed by `"Hello"`.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, O=0, H=0 | `E0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=0, MIC=3 (16-byte), S=0 | `60` |
| Frame Counter | 3 | `00 00 00 03` |
| SRC | Node A hint | `ED 54 A5` |
| Payload | `03 || "Hello"` | `03 48 65 6C 6C 6F` |
| MIC | 16 bytes | `7C 9A 9C 4B C0 DD B4 96 65 6A 9D F1 5F 5B 9C C4` |

```text
E0 B0 8D 60 00 00 00 03 ED 54 A5 03 48 65 6C 6C
6F 7C 9A 9C 4B C0 DD B4 96 65 6A 9D F1 5F 5B 9C
C4
```

Total: 33 bytes.

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
| FCF | VER=3, TYPE=2 (unicast), S=0, O=1, H=1 | `D3` |
| Options | Trace route + region code + end marker | `20 92 78 53 FF` |
| FHOPS | FHOPS_REM=4, FHOPS_ACC=0 | `40` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A hint | `ED 54 A5` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 10 | `00 00 00 0A` |
| Payload | Encrypted `68 65 79` (`"hey"`) | `AB 87 DC` |
| MIC | 16 bytes | `83 07 00 18 AA 22 DB FC 93 86 B8 D1 F0 74 85 39` |

```text
D3 20 92 78 53 FF 40 6C 28 FD ED 54 A5 E0 00 00
00 0A AB 87 DC 83 07 00 18 AA 22 DB FC 93 86 B8
D1 F0 74 85 39
```

Total: 37 bytes.

## Example 8: Blind Unicast (S=0)

A blind unicast on channel `B08D`. The destination hint and source hint are encrypted together in `ENC_DST_SRC`, while the payload is encrypted with the blind-unicast payload keys.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=6 (blind unicast), S=0, O=0, H=0 | `F0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 7 | `00 00 00 07` |
| ENC_DST_SRC | ENCRYPT(`DST || SRC`) | `9C A3 DF 8D F8 A6` |
| ENC_PAYLOAD | ENCRYPT(`"Hello"`) | `1A 3B 73 CD 1B` |
| MIC | 16 bytes | `42 9D E6 DD 47 AD 3A 6B E5 FF 89 BB 16 15 E8 7A` |

```text
F0 B0 8D E0 00 00 00 07 9C A3 DF 8D F8 A6 1A 3B
73 CD 1B 42 9D E6 DD 47 AD 3A 6B E5 FF 89 BB 16
15 E8 7A
```

Total: 35 bytes.
