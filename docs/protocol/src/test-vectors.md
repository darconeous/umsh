# Test Vectors

This appendix contains byte-level packet examples. All values are hexadecimal, and multi-byte numeric fields are big-endian. The examples omit the [Fence option](packet-options.md#fence-option-257), which every packet a sender originates carries.

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
+---+-------+---+---+-----------+
| E |  MIC  | S | D | RESERVED  |
+---+-------+---+---+-----------+
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
| Payload | Encrypted `48 65 6C 6C 6F` (`"Hello"`) | `8B 60 67 EB 6C` |
| MIC | 16 bytes | `F6 D2 39 C9 05 12 41 ED 8C A4 C2 D8 89 1A 34 58` |

```text
D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF 8B 60 67
EB 6C F6 D2 39 C9 05 12 41 ED 8C A4 C2 D8 89 1A
34 58
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
| Payload | Encrypted `68 65 79` (`"hey"`) | `4C A9 EB` |
| MIC | 16 bytes | `FE A5 FD 44 7A 2F E0 FF D5 57 B5 4E E6 E8 91 81` |

```text
DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36
29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC
7A 69 C2 79 E0 00 00 00 01 FF 4C A9 EB FE A5 FD
44 7A 2F E0 FF D5 57 B5 4E E6 E8 91 81
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
| Encrypted data | ENCRYPT(`SRC || "Hello"`) | `D4 4B B6 0E 34 6D E5 F4` |
| MIC | 16 bytes | `F3 C4 8B 8F 96 EA A1 EF F6 19 47 E8 49 77 16 70` |

```text
E0 B0 8D E0 00 00 00 05 FF D4 4B B6 0E 34 6D E5
F4 F3 C4 8B 8F 96 EA A1 EF F6 19 47 E8 49 77 16
70
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
| MIC | 16 bytes | `14 0E 9E 52 53 A7 3F A6 58 3C 0C 94 C1 5E EA 9F` |

```text
E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C
6C 6F 14 0E 9E 52 53 A7 3F A6 58 3C 0C 94 C1 5E
EA 9F
```

Total: 34 bytes.

## Example 7: Encrypted Unicast with Options and Flood Hops

An encrypted unicast with a region code option, an empty trace option, and flood hop limit 4.

**Options encoding:**

| Option | Number | Delta | Length | Encoding |
|---|---:|---:|---:|---|
| Trace | 7 | 7 | 0 | `70` |
| Region Code | 11 | 4 | 2 | `42` then value `78 53` |
| End marker | — | — | — | `FF` |

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=2 (unicast), S=0, R=0, H=1 | `D1` |
| FHOPS | FHOPS_REM=4, FHOPS_ACC=0 | `40` |
| DST | Node B hint | `6C 28 FD` |
| SRC | Node A hint | `ED 54 A5` |
| SCF | E=1, MIC=3 (16-byte), S=0 | `E0` |
| Frame Counter | 10 | `00 00 00 0A` |
| Options | Trace + region code + end marker | `70 42 78 53 FF` |
| Payload | Encrypted `68 65 79` (`"hey"`) | `B7 C4 59` |
| MIC | 16 bytes | `EC 72 BD EA E9 59 DB 86 BA AD 14 9C 92 5F B4 0B` |

```text
D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 70 42 78
53 FF B7 C4 59 EC 72 BD EA E9 59 DB 86 BA AD 14
9C 92 5F B4 0B
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
| ENC_DST_SRC | ENCRYPT(`DST || SRC`) | `1D 7D 4C CE 9C 9E` |
| ENC_PAYLOAD | ENCRYPT(`"Hello"`) | `B7 B1 EE 01 4B` |
| MIC | 16 bytes | `AF 4C 3E 68 BD 61 82 47 53 98 47 CF F9 0C 28 70` |

```text
F0 B0 8D E0 00 00 00 07 FF 1D 7D 4C CE 9C 9E B7
B1 EE 01 4B AF 4C 3E 68 BD 61 82 47 53 98 47 CF
F9 0C 28 70
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

Node B's acknowledgement of Example 4. `ACK MIC` is the first four bytes of Example 4's MIC. `ACK TAG` is `truncate_to_4(S2V(K_mic, S1 = C8 FF FF, S2 = V, S3 = ACK MIC))`, where `C8 FF FF` is the ack's AAD (its FCF and the terminator, with no static options) and `V` is Example 4's full S2V output, which its 16-byte MIC carries whole.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=1 (MAC ack), S=0, R=0, H=0 | `C8` |
| ACK MIC | First 4 bytes of V | `FE A5 FD 44` |
| ACK TAG | 4-byte MIC | `16 61 6C D1` |

```text
C8 FE A5 FD 44 16 61 6C D1
```

Total: 9 bytes.

## Example 11: MAC Ack with Operator Callsign

The acknowledgement of Example 10 as a Licensed-Only node sends it, carrying the operator callsign `N0CALL`. The callsign is a static option, so the ack's AAD is `C8`, the option's type-length-value encoding, then `FF FF`, and the tag differs from Example 10's.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=1 (MAC ack), S=0, R=0, H=0 | `C8` |
| Options | Operator Callsign (option 4), `N0CALL` | `44 5B BB 08 2C` |
| ACK MIC | First 4 bytes of V | `FE A5 FD 44` |
| ACK TAG | 4-byte MIC | `15 B2 56 E4` |

```text
C8 44 5B BB 08 2C FE A5 FD 44 15 B2 56 E4
```

Total: 14 bytes.

## Signed Frames

Examples 12 to 14 are signed with Node A's Ed25519 key. Each shows its signature input: `"UMSH-SIG"`, the frame's AAD with a broadcast's Frame Signature zeroed, the channel commitment for a multicast, and the plaintext the MIC's S2 covers without the signature.

- Channel commitment of the channel key above: `B08D B3C1 400A 1C11 F1D1 464D D6BA 945F D037 2DDD 38CA 63A1 84D3 6FD1 11FE BA40`

## Example 12: Signed Authenticated Multicast (E=0, D=1)

An unencrypted multicast from Node A carrying its full key, signed. `SRC || PAYLOAD || SIG` is the MIC's S2.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=1, R=0, H=0 | `E4` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=0, MIC=3 (16-byte), S=0, D=1 | `68` |
| Frame Counter | 12 | `00 00 00 0C` |
| End of options | No options | `FF` |
| SRC | Node A public key | `ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79` |
| Payload | `03 || "Help"` | `03 48 65 6C 70` |
| SIG | Ed25519 signature | `64 60 E7 36 CF 31 6B B3 2F 43 8C A2 81 DE 0D E0 2C 3B BE B7 A6 CB 19 5A 5C 60 55 BD 46 A9 F5 E7 53 2C 96 AE F7 CC E8 06 C7 F4 FC 46 2C D9 B8 61 CC 60 D4 47 65 F6 6E 4E 3A 5D DB 10 91 3D 6D 05` |
| MIC | 16 bytes | `59 96 7A 9D 75 D9 FC DC AA 9F AD 4C 50 3B 2E 47` |

```text
E4 B0 8D 68 00 00 00 0C FF ED 54 A5 9F B1 AC 3A
51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48
5D 82 88 21 DC 7A 69 C2 79 03 48 65 6C 70 64 60
E7 36 CF 31 6B B3 2F 43 8C A2 81 DE 0D E0 2C 3B
BE B7 A6 CB 19 5A 5C 60 55 BD 46 A9 F5 E7 53 2C
96 AE F7 CC E8 06 C7 F4 FC 46 2C D9 B8 61 CC 60
D4 47 65 F6 6E 4E 3A 5D DB 10 91 3D 6D 05 59 96
7A 9D 75 D9 FC DC AA 9F AD 4C 50 3B 2E 47
```

Total: 126 bytes.

Signature input (87 bytes):

```text
55 4D 53 48 2D 53 49 47 E4 B0 8D 68 00 00 00 0C
FF FF B0 8D B3 C1 40 0A 1C 11 F1 D1 46 4D D6 BA
94 5F D0 37 2D DD 38 CA 63 A1 84 D3 6F D1 11 FE
BA 40 ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41
B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69
C2 79 03 48 65 6C 70
```

## Example 13: Signed Encrypted Multicast (E=1, D=1)

An encrypted multicast from Node A, signed. The signature is encrypted with the source hint and the payload.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=4 (multicast), S=0, R=0, H=0 | `E0` |
| CHANNEL | Derived channel identifier | `B0 8D` |
| SCF | E=1, MIC=3 (16-byte), S=0, D=1 | `E8` |
| Frame Counter | 13 | `00 00 00 0D` |
| End of options | No options | `FF` |
| Encrypted data | ENCRYPT(`SRC || "Hello" || SIG`) | `69 2E 61 79 21 A2 08 42 BF 2E 1C D8 6F 88 A1 4A E7 EF 44 BC DF 11 34 EC 85 6F 93 06 39 96 0C 99 D6 70 79 87 08 EA A8 0E 61 BA DA 28 E2 B2 A8 58 97 D5 9C C2 8A 12 33 DB 1B 21 18 53 85 5E CE 11 00 79 F3 6C 99 1C 24 10` |
| MIC | 16 bytes | `02 BB 9A 22 FE F4 1A 6E 91 9D 34 72 41 AA 42 B9` |

```text
E0 B0 8D E8 00 00 00 0D FF 69 2E 61 79 21 A2 08
42 BF 2E 1C D8 6F 88 A1 4A E7 EF 44 BC DF 11 34
EC 85 6F 93 06 39 96 0C 99 D6 70 79 87 08 EA A8
0E 61 BA DA 28 E2 B2 A8 58 97 D5 9C C2 8A 12 33
DB 1B 21 18 53 85 5E CE 11 00 79 F3 6C 99 1C 24
10 02 BB 9A 22 FE F4 1A 6E 91 9D 34 72 41 AA 42
B9
```

Total: 97 bytes.

Signature input (58 bytes):

```text
55 4D 53 48 2D 53 49 47 E0 B0 8D E8 00 00 00 0D
FF FF B0 8D B3 C1 40 0A 1C 11 F1 D1 46 4D D6 BA
94 5F D0 37 2D DD 38 CA 63 A1 84 D3 6F D1 11 FE
BA 40 ED 54 A5 48 65 6C 6C 6F
```

## Example 14: Signed Broadcast

A broadcast from Node A carrying its full key and a Frame Signature option (0) with counter 14. In the signature input the option's 64 signature bytes are zeros.

| Field | Value | Hex |
|---|---|---|
| FCF | VER=3, TYPE=0 (broadcast), S=1, R=0, H=0 | `C4` |
| SRC | Node A public key | `ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79` |
| Option header | Delta 0, length 68 (13 + `37`) | `0D 37` |
| Counter | 14 | `00 00 00 0E` |
| SIG | Ed25519 signature | `03 79 A8 FA 3A B8 6E 4F 59 C7 6F 0E E6 5C 76 6B D2 F1 03 38 0E 62 D9 AD 4E E8 66 E5 89 B3 56 C0 54 AC F8 50 AF D6 9A DD B7 A3 8B 7C 18 E8 77 A6 AA 55 84 68 F7 01 2F E0 91 24 4E 6B 89 52 BE 0C` |
| End of options | Payload follows | `FF` |
| Payload | `"Hi"` | `48 69` |

```text
C4 ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8
68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2
79 0D 37 00 00 00 0E 03 79 A8 FA 3A B8 6E 4F 59
C7 6F 0E E6 5C 76 6B D2 F1 03 38 0E 62 D9 AD 4E
E8 66 E5 89 B3 56 C0 54 AC F8 50 AF D6 9A DD B7
A3 8B 7C 18 E8 77 A6 AA 55 84 68 F7 01 2F E0 91
24 4E 6B 89 52 BE 0C FF 48 69
```

Total: 106 bytes.

Signature input (117 bytes):

```text
55 4D 53 48 2D 53 49 47 C4 ED 54 A5 9F B1 AC 3A
51 23 93 51 36 29 41 B8 68 E8 5A 60 E3 D7 B2 48
5D 82 88 21 DC 7A 69 C2 79 00 00 00 44 00 00 00
0E 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 FF FF 48 69
```
