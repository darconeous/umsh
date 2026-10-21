# Contact Exchange

> ![NOTE]
> This section is an early work in progress and this protocol may change significantly.

**Meet** payloads (payload type 10) let two people standing together exchange
contacts without typing an address. Each device announces itself under a
**session key** drawn for the purpose, showing only its model and a color
derived from that key. One holder asks, the other agrees, and both screens show
a six-digit code. Each holder compares the codes and presses Same or
Different. A device sends its own long-term key and
[node identity](node-identity.md) only when its holder presses Same.

Nothing a device sends before its holder's Same identifies it beyond its model.
The person standing there is the identification, and the code confirms that the
two devices talking are the two in their hands.

## Session Keys {#session-keys}

A session key is a fresh Ed25519 key pair, used as an ordinary
[node identity](addressing.md) for the length of one session and never again.
Every Meet frame is sent from the session key with the full source key in the
header, and every unicast is addressed to the other device's session key.

A device MUST draw a new session key, and new nonces, for every exchange
attempt. That includes trying again after an attempt ends in Not now, Busy,
Different, a timeout, or a failure. When an attempt ends for any reason, the
session key's private half is erased.

A session key answers for nothing but Meet. A device MUST NOT accept or answer
any other payload addressed to a session key: no node identity, no MAC command,
no text. Meet unicasts addressed to a long-term identity are dropped.

## Payload Format {#payload-format}

```text
+------+---------+------+------+
| 0x0A | VERSION | KIND | BODY |
+------+---------+------+------+
  1 B     1 B      1 B    var
```

`VERSION` is 1. Any change to a body layout, or a new kind, takes a new
version. Every kind except Identity has a body of exactly the length given
below. Identity's body runs to the end of the payload. No kind is followed by
anything: bytes past the end of a body make the payload malformed.

| Kind | Name | Carriage | Body |
|---:|---|---|---|
| 0 | [Hello](#hello) | broadcast | `MODEL` (2 B) |
| 1 | [Request](#request) | unicast | `COMMITMENT` (32 B) |
| 2 | [Accept](#accept) | unicast | `NONCE` (16 B) |
| 3 | [Reveal](#reveal) | unicast | `NONCE` (16 B) |
| 4 | [Identity](#identity) | unicast | `KEY` (32 B), node identity payload |
| 5 | [End](#end) | unicast | `REASON` (1 B) |

A Hello is carried in a broadcast with no flood hops. Every other kind is
carried in an encrypted unicast between the two session keys, with an
acknowledgment requested and no flood hops. A kind on the wrong carriage is
malformed.

### Hello {#hello}

`MODEL` is the sender's hardware model, a
[model identifier](ulcp-ble.md#ble-model-identifier) (big-endian, 0 when
unspecified). A Hello carries nothing else. It lists the sender on the receiver's Nearby screen,
keyed by its session key.

### Request {#request}

Sent by the device whose holder asked (A) to the device asked (B):

```text
COMMITMENT = SHA-256("UMSH meet commit" ‖ S_A ‖ S_B ‖ N_A)
```

`S_A` and `S_B` are the two session public keys, and `N_A` is 16 random bytes
A keeps until [Reveal](#reveal).

### Accept {#accept}

Sent by B when its holder agrees. `NONCE` is `N_B`, 16 random bytes.

### Reveal {#reveal}

Sent by A on receiving Accept. `NONCE` is `N_A`. B checks that the commitment
it holds equals `SHA-256("UMSH meet commit" ‖ S_A ‖ S_B ‖ N_A)`. On a mismatch
B sends End with reason failed.

### Identity {#identity}

```text
+-----+---------------------------------------------+
| KEY | ROLE | CAPS | OPTIONS | [0xFF | SIGNATURE] |
+-----+---------------------------------------------+
 32 B   node identity payload, to the end of the frame
```

`KEY` is the sender's long-term public key. The rest of the body is its
[node identity payload](node-identity.md), read as follows:

- ROLE, CAPS, then options until the end of the frame or a 0xFF marker.
- If the end of the frame is reached, the payload is unsigned.
- If a 0xFF marker is found, exactly 64 bytes MUST follow it, and they are the
  signature. Any other count, including none, makes the Identity malformed.

The signature is the ordinary node identity signature: Ed25519 by `KEY` over
ROLE through the 0xFF marker, as in a [node URI](uri-formats.md) bundle. It is
optional. A signature that does not verify under `KEY` makes the Identity
malformed.

An Identity carries no session binding. A sender that passed along someone
else's key and payload could neither read what is sent to that key nor send as
it.

A device sends its Identity when its holder presses Same, and the Identity
stands for that Same.

### End {#end}

Ends the attempt for both devices.

| Reason | Meaning |
|---:|---|
| 0 | Not now: the asked holder declined |
| 1 | Busy: the receiver is in another exchange |
| 2 | Different: a holder pressed Different |
| 3 | Left: a holder backed out or closed Add peer |
| 4 | Timed out |
| 5 | Failed: a frame inside the exchange was malformed or did not check out |

An unknown reason still ends the attempt.

## Code and Color {#derivations}

Both devices show:

```text
CODE = BE32(SHA-256("UMSH meet code" ‖ S_A ‖ S_B ‖ N_A ‖ N_B)[0..4]) mod 1000000
```

as six decimal digits, zero-padded.

Each session key has a color. Its hue step is:

```text
HUE = SHA-256("UMSH meet color" ‖ S)[0]
```

The color is the OKLCH color with lightness 0.75, chroma 0.12, and hue angle
`HUE × 360° / 256`, converted to 8-bit sRGB:

1. `a = 0.12·cos(h)`, `b = 0.12·sin(h)`.
2. `l' = 0.75 + 0.3963377774·a + 0.2158037573·b`
   `m' = 0.75 − 0.1055613458·a − 0.0638541728·b`
   `s' = 0.75 − 0.0894841775·a − 1.2914855480·b`
3. `l = l'³`, `m = m'³`, `s = s'³`.
4. Linear sRGB:
   `R = 4.0767416621·l − 3.3077115913·m + 0.2309699292·s`
   `G = −1.2684380046·l + 2.6097574011·m − 0.3413193965·s`
   `B = −0.0041960863·l − 0.7034186147·m + 1.7076147010·s`
5. Each channel `x`, clamped to [0, 1], is encoded as `12.92·x` when
   `x ≤ 0.0031308` and `1.055·x^(1/2.4) − 0.055` otherwise, then scaled by
   255 and rounded.

All 256 colors fall inside the sRGB gamut. Implementations may precompute them
as a table.

## Exchange {#exchange}

1. Both devices broadcast Hellos and list each other.
2. A's holder picks B's row. A sends Request.
3. B's holder is asked. Agreeing sends Accept. Declining sends End (not now).
4. A sends Reveal, and shows the code.
5. B checks the commitment and shows the code.
6. Each holder compares. Same sends that device's Identity. Different sends
   End (different).
7. A device that has both sent and received an Identity has exchanged.

The commitment is sent before either nonce, and each nonce only after the
other side is bound: B sends `N_B` only while holding `C_A`, and A reveals
`N_A` only after receiving `N_B`.

What a device does with a received Identity is up to it, except that it MUST
discard it if its own holder presses Different or leaves.

**Rules**

- An Identity received before the device shows the code is dropped.
- An Identity whose `KEY` is the receiver's own long-term key is dropped.
- When both devices send Request to each other, the device with the lower
  session key (compared as big-endian unsigned integers) ignores the incoming
  one. The other drops its own Request and sends Accept without asking its
  holder, who already asked.
- A Request arriving while the receiver is in an exchange, or after its
  session's attempt has ended, is answered with End (busy).
- A device sends no Hellos while an attempt is in progress.

**Timeouts**

| Waiting for | Limit |
|---|---|
| Accept, after Request | 60 s |
| The asked holder's answer | 60 s |
| Reveal, after Accept | 10 s |
| A holder's Same or Different, after the code is shown | 2 min |
| The other Identity, after sending one's own | 2 min |

A device whose limit passes sends End (timed out).

## Malformed Frames {#malformed}

A frame from the session key a device is in an exchange with, by unicast, is
**inside** the exchange. Inside the exchange, any malformed frame—an unknown
version or kind, a wrong length, a wrong carriage, or an Identity that does not
parse or verify—ends the attempt: the receiver sends End (failed) and keeps
nothing.

Any other frame is **outside**. A malformed frame outside an exchange is
dropped and never answered. A device speaking a newer version is simply not
listed.

A well-formed frame that does not fit the current state is dropped.

## Nearby {#nearby}

A device sends a Hello when it opens a session, one more between 0.5 and 2
seconds after it first hears a session key it has not listed, and then
periodically. The periodic interval is at least 5 seconds, scaled to the
airtime of the current channel settings, and each one is jittered by up to a
quarter either way. A row ages out after three intervals without a Hello.

Two devices of the same model whose hue steps are within 24 of each other
(about 34°, wrapping around) are hard to tell apart. While idle, the device
with the lower session key of such a pair opens a new session, with a new key
and a new color.

## Transmit Power {#transmit-power}

A device SHOULD send every Meet frame, and every acknowledgment of one, at
−9 dBm, or at the least power its radio can transmit if that is higher. The two
holders stand together; nothing farther away needs to hear them.

## Linking a Name to a Key {#linking}

A Meet Identity travels between session keys, not from `KEY`, so nothing but
its signature links its payload to `KEY`. An unsigned Identity's name and other
claims are the sender's word only.
