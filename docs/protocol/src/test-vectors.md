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
| Payload | Encrypted `48 65 6C 6C 6F` (`"Hello"`) | `AE 71 DC 38 72` |
| MIC | 16 bytes | `61 8E 96 38 FE 4D 9A E8 34 33 1D E8 E0 DD 06 3E` |

```text
D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF AE 71 DC
38 72 61 8E 96 38 FE 4D 9A E8 34 33 1D E8 E0 DD
06 3E
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
| Payload | Encrypted `68 65 79` (`"hey"`) | `F8 82 EE` |
| MIC | 16 bytes | `AA 17 13 06 26 1C E7 FF F2 FF 01 7F 90 10 A7 D9` |

```text
DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36
29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC
7A 69 C2 79 E0 00 00 00 01 FF F8 82 EE AA 17 13
06 26 1C E7 FF F2 FF 01 7F 90 10 A7 D9
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
| Encrypted data | ENCRYPT(`SRC || "Hello"`) | `7C 16 CC CF 27 32 48 78` |
| MIC | 16 bytes | `AC BF 20 01 42 05 B1 04 17 5E A6 8F 66 47 78 83` |

```text
E0 B0 8D E0 00 00 00 05 FF 7C 16 CC CF 27 32 48
78 AC BF 20 01 42 05 B1 04 17 5E A6 8F 66 47 78
83
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
| MIC | 16 bytes | `9A 4B FC DE 39 42 FE B2 25 B8 D3 D4 BC E7 9F DB` |

```text
E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C
6C 6F 9A 4B FC DE 39 42 FE B2 25 B8 D3 D4 BC E7
9F DB
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
| Payload | Encrypted `68 65 79` (`"hey"`) | `81 2D 2F` |
| MIC | 16 bytes | `BA 19 2E EA B5 7D 71 E3 52 BD 7D DF 33 1B 07 27` |

```text
D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 20 92 78
53 FF 81 2D 2F BA 19 2E EA B5 7D 71 E3 52 BD 7D
DF 33 1B 07 27
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
| ENC_DST_SRC | ENCRYPT(`DST || SRC`) | `D5 EC 8B 3D 69 96` |
| ENC_PAYLOAD | ENCRYPT(`"Hello"`) | `88 94 03 C3 07` |
| MIC | 16 bytes | `C7 46 F3 5E 82 28 3E 3C 14 B0 5D 97 56 7B 4E 86` |

```text
F0 B0 8D E0 00 00 00 07 FF D5 EC 8B 3D 69 96 88
94 03 C3 07 C7 46 F3 5E 82 28 3E 3C 14 B0 5D 97
56 7B 4E 86
```

Total: 36 bytes.

## Example 9: Contact Exchange Derivations

[Contact exchange](app-meet.md) values, taking Node A's public key as the asking device's session key `S_A` and Node B's as the asked device's `S_B`.

- `N_A`: `0001 0203 0405 0607 0809 0A0B 0C0D 0E0F`
- `N_B`: `1011 1213 1415 1617 1819 1A1B 1C1D 1E1F`

| Value | Result |
|---|---|
| `COMMITMENT` | `B0B0 5CA5 750B 0DC9 02D5 E7B8 66DC 81D6 3DDE 8BDD 70E0 1A0F 8B50 BF5F FA66 9E7D` |
| Code digest, first four bytes | `D0 43 62 18` |
| `CODE` | `076952` |
| `HUE` of `S_A` | 61, color `D0A84B` |
| `HUE` of `S_B` | 119, color `53C69E` |

Colors at hue steps 0, 64, 128, and 192 are `EC8DAB`, `CBAA4B`, `3DC6B1`, and `90AAFA`.

A Hello from a T-LoRa Pager (model identifier 9), and A's Request:

```text
0A 01 00 00 09
```

```text
0A 01 01 B0 B0 5C A5 75 0B 0D C9 02 D5 E7 B8 66
DC 81 D6 3D DE 8B DD 70 E0 1A 0F 8B 50 BF 5F FA
66 9E 7D
```

## Example 10: MAC Ack

Node B's acknowledgement of Example 4. `ACK MIC` is the first four bytes of Example 4's MIC. `ACK TAG` is `truncate_to_4(S2V(K_mic, S1 = C8, S2 = V, S3 = ACK MIC))`, where `C8` is the ack's AAD (its FCF, with no static options) and `V` is Example 4's full S2V output, which its 16-byte MIC carries whole.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=1 (MAC ack), S=0, R=0, H=0 | `C8` |
| ACK MIC | First 4 bytes of V | `AA 17 13 06` |
| ACK TAG | 4-byte MIC | `D2 FB 63 BD` |

```text
C8 AA 17 13 06 D2 FB 63 BD
```

Total: 9 bytes.

## Example 11: MAC Ack with Operator Callsign

The acknowledgement of Example 10 as a Licensed-Only node sends it, carrying the operator callsign `N0CALL`. The callsign is a static option, so the ack's AAD is `C8` followed by the option's type-length-value encoding, and the tag differs from Example 10's.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=1 (MAC ack), S=0, R=0, H=0 | `C8` |
| Options | Operator Callsign (option 4), `N0CALL` | `44 5B BB 08 2C` |
| ACK MIC | First 4 bytes of V | `AA 17 13 06` |
| ACK TAG | 4-byte MIC | `A8 78 BE 6E` |

```text
C8 44 5B BB 08 2C AA 17 13 06 A8 78 BE 6E
```

Total: 14 bytes.
