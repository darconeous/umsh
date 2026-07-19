# Peer Identity, Avatars, and Secure Sessions

This chapter defines the shared peer presentation used by UMSH applications.
It applies to conversation lists, transcripts, discovery results, maps,
notifications, peer details, sharing previews, and accessibility descriptions.
Platform-specific applications adapt the controls but preserve the identity
and security meanings.

## Stable peer identity

A peer is keyed locally by its complete 32-byte public key, not by an
advertised name, alias, NodeHint, color, or PFS ephemeral address. Human labels
and deterministic avatars help recognition but are not cryptographic identity
proof.

When choosing the primary visible label, use this order:

1. the user's **local mnemonic alias**, when set;
2. the most recently accepted advertised name;
3. **Unnamed node**, accompanied by the canonical rendered NodeHint.

The alias is local metadata. Setting it does not transmit a rename, modify the
peer's advertisement, or alter cryptographic identity. Peer Detail preserves
the advertised name as a secondary field so the user can recognize changes or
mistakes. Search matches the alias, advertised name, complete public key, and
canonical NodeHint. Removing an alias immediately restores the advertised-name
fallback.

## Deterministic NodeHint avatar

Every peer has a deterministic fallback avatar derived from its
`umsh_core::NodeHint`. Use it wherever a peer icon appears unless the user has
explicitly chosen a local replacement icon in a future implementation. The
avatar must be reproducible across conforming applications.

### Construction

Given `NodeHint([r, g, b])`:

1. Obtain the avatar text from the standard Rust string representation,
   `NodeHint::to_string()`. Do not independently truncate Base58 text. This
   produces an exact four-character form such as `BtC5`, or a rare
   three-character star-terminated form such as `9v*`, according to the
   canonical addressing algorithm.
2. Draw a circle whose background is the raw three-byte RGB value `#rrggbb`.
   The bytes are used directly; they are not derived from the rendered
   characters or passed through a palette.
3. For a four-character representation, place the first two characters on the
   top line and the final two on the bottom line. For a three-character
   representation, place the first two on top and the final character on the
   bottom. The `*`, when present, is displayed literally.
4. Use the platform's system monospaced font. Scale the glyph size with the
   circle diameter so compact list/chat avatars do not reuse the larger detail
   avatar's type size.
5. Choose black or white text according to whichever produces the greater WCAG
   contrast ratio against the raw RGB background. Use standard sRGB relative
   luminance; do not choose by a fixed brightness threshold or aesthetic
   preference.
6. Expose an accessible label such as **Node hint BtC5**. The color is never an
   identity label by itself.

Examples from the `umsh_core` reference vectors:

| Hint bytes | Standard text | Background | Text layout | Contrast text |
|---|---|---|---|---|
| `a1 b2 03` | `BtC5` | `#A1B203` | `Bt` / `C5` | black |
| `84 81 1b` | `9v*` | `#84811B` | `9v` / `*` | black |
| `5e a1 b2` | `7NQL` | `#5EA1B2` | `7N` / `QL` | black |

The avatar does not resolve NodeHint collisions and must not be presented as a
verification mark. Peer Detail and trust-sensitive confirmation screens expose
the complete fixed-width 44-character Base58 public key.

### Custom replacement icons

A later release may let the user choose a local photo, symbol, or other icon for
a peer. Such a replacement is local-only by default and does not overwrite the
deterministic avatar for other users. The NodeHint avatar remains available in
Peer Detail and as the fallback if the replacement is removed or unavailable.

## PFS status on peer avatars

PFS belongs only to a direct relationship with a peer. It does not apply to a
channel avatar or room icon. While a PFS session is active or changing state,
add a thin outer state ring around the peer avatar without changing its
deterministic RGB background or placing a badge over its contents:

| State | Avatar cue | Required adjacent text |
|---|---|---|
| No active session | No outer ring | **Standard encryption** in Peer Detail; chat may omit it |
| Establishing | Broken/dashed outer ring | **Establishing PFS…** |
| Active | Solid outer ring | **PFS active · expires in 24 min** or **PFS active · until restart** |
| Ending | Broken/dashed outer ring | **Ending PFS…** |
| Failed or lost | No security ring | A specific failure or **Session ended after restart** |

The ring is a compact recognition cue, not the sole status. A shield icon may
appear beside the visible status text, but it does not overlap the avatar.
Screen-reader text and visible text in the direct-conversation header and Peer
Detail state the session condition. Ring form, not only color, distinguishes
active and transitional states, and the visible text remains authoritative.

While PFS is active, the application continues to show the peer's stable alias,
advertised name, long-term NodeHint avatar, and Peer Detail. The ephemeral
addresses are session machinery mapped back to that peer; they must not appear
as a new contact or replace the stable avatar. Advanced session details may
show ephemeral addresses with explicit **Ephemeral session address** labels.

## Peer Detail

Peer Detail is the authoritative user-facing view of one known peer. It is
reachable from a direct-conversation title/avatar, a discovery or Network row,
a channel sender, and other peer references. It contains:

- deterministic NodeHint avatar and any local replacement;
- local alias with **Set alias** or **Edit alias**;
- advertised name, role, capabilities, and observation age;
- complete 44-character Base58 public key, with Copy;
- **Show QR code** and system **Share** for the peer's public identity URI;
- **Message**, when the peer supports text;
- **Ping**, when an authenticated unicast Echo Request can be sent;
- PFS status and **Establish PFS session** or **End PFS session**;
- activity, reported location, routing evidence, services, and advanced data as
  applicable.

QR and sharing expose public identity information only. They never export a
private key, local alias unless explicitly selected as share metadata, or PFS
ephemeral private material.

## Ping behavior

**Ping** sends one MAC Echo Request and measures round-trip time only when the
matching Echo Response returns. Show **Sending ping…**, then a result such as
**Reply in 2.4 s · just now**. A timeout says **No response before timeout**;
it does not say the peer is offline, because packets or responses may be lost
and MAC-command support is optional.

Ping is a deliberate action, not continuous presence polling. Repeated or
automatic pings consume shared airtime and must not run merely because Peer
Detail is visible. When the radio is unavailable or the peer cannot be securely
addressed, retain the control only if an explanation can be shown; otherwise
omit it according to platform conventions.

## Establishing and ending PFS

**Establish PFS session** opens a duration confirmation before transmitting.
The application sends a PFS Session Request over the existing authenticated
long-term unicast relationship and shows **Establishing PFS…** while awaiting
the response. On success, both Peer Detail and the direct-chat header show the
accepted lifetime, not merely the requested lifetime.

While active, direct traffic uses the ephemeral session identities. The UI
still presents the stable peer and must not imply that PFS verifies the human
behind an advertised name. **End PFS session** sends the protocol command and
returns to standard long-term pairwise encryption after completion. Expiration,
either device rebooting, or either party ending the session also terminates it.

PFS state is session state, not durable contact state. Never imply that an
active session will survive a phone or peer reboot. Message details may record
that a message was sent during a PFS session, but the current header indicator must
not retroactively claim protection for messages sent before the session began.
