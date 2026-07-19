# Mobile Application Guidelines

This chapter defines the shared product model for UMSH phone and tablet
applications. Platform chapters adapt the mechanics and visual treatment to the
host operating system. They must preserve the concepts, safety boundaries, and
information architecture defined here.

The application and a tethered companion radio together act as a self-contained
UMSH endpoint. The application owns the user's long-term identity, contacts,
messages, and application behavior. The radio owns the physical LoRa interface
and may perform narrowly delegated work while the application is unavailable.

## Product principles

### Organize around user goals

The ordinary interface should speak about **conversations**, **people**,
**channels**, **rooms**, **devices**, and **radio connection**. Terms such as
address hints, MICs, flood-hop counters, pairwise keys, and companion-link
properties belong in detail or diagnostic views.

Protocol transparency is still important. A user must be able to inspect the
identity, route, delivery evidence, channel membership, and radio state behind
a friendly label when troubleshooting or making a trust decision.

### Keep identity and radio separate

The user's UMSH identity lives in secure storage on the phone. Pairing a radio
does not create the identity, and forgetting a radio must not erase the
identity. Conversely, resetting the user's identity must not silently reset the
radio's own device identity or durable radio settings.

Use these names consistently:

| Concept | User-facing name | Meaning |
|---|---|---|
| Host long-term identity | Your identity | The public/private keypair representing the user in UMSH |
| Companion radio | Radio | The nearby device carrying frames over LoRa |
| Radio-owned node | Radio identity | The radio's separate management/diagnostic node, when present |
| BLE trust | Pairing | Permission for this phone to use the radio's privileged companion link |
| Mesh acquaintance | Known node | A public key and any observed or imported metadata |
| User-curated acquaintance | Contact | A known node the user has deliberately saved |

### Make offline operation explicit

The application must remain useful without internet access. Local messages,
contacts, QR codes, imported URIs, radio settings, maps already cached by the
application, and diagnostics should remain available. Internet-dependent
features must be additive and must identify themselves as unavailable rather
than blocking the mesh interface.

The application should not imply that its own background execution is
continuous. If the radio supports filtering, inbound buffering, or delegated
acknowledgements, describe the specific assistance that is active. Never call
the radio a backup copy of the user's identity: it does not possess the user's
private key.

### Reveal trust at the decision point

Names and avatars are labels, not addresses. Any flow that adds a contact,
joins a private channel, takes over a radio's host domain, or sends sensitive
information must provide a path to inspect the relevant key or address.

An authenticated packet proves control of the corresponding key. It does not
prove that a human-readable name belongs to a particular person. The interface
must not use a generic checkmark to blur these two claims.

Peer labels, deterministic avatars, local mnemonic aliases, ping results, and
PFS state follow [Peer Identity, Avatars, and Secure
Sessions](peer-identity-and-sessions.md). The same peer must remain visually
recognizable across Conversations, Network, maps, details, and notifications.

### Render addresses and hints canonically

Node addresses and partial hints must follow the presentation algorithm in
`docs/protocol/src/addressing.md`. Applications must not invent fingerprint,
ellipsis, suffix, or hexadecimal abbreviations.

- A complete 32-byte node public key is shown as its exact fixed-width
  44-character Base58 address, including any leading `1` padding.
- A three-byte node hint is rendered with the protocol's four-character budget:
  encode the hint padded once with `0x00` and once with `0xFF`; use four
  characters when both encodings agree, otherwise use their two- or
  three-character common prefix followed by `*`.
- A two-byte router hint uses the same process with a three-character budget and
  30 padding bytes. The common result is two verified characters plus `*`.
- `*` means the following Base58 digit is not determined by the available hint;
  it is not a wildcard entered by the user.

If a compact screen knows the complete key but cannot fit 44 characters, use a
name such as **Unnamed node** and move the complete address to the subtitle,
detail, or disclosure view. Do not manufacture a shorter key display. When only
a hint is actually available, the canonical rendered hint may be used as the
identifier and must be labeled **Node hint** or **Router hint**.

Channel keys are also encoded as complete Base58 values when revealed. A
channel screen may keep the shared key concealed behind **Show channel key**,
but it must not replace it with an arbitrary `Key ID`. The protocol's on-wire
channel identifier is a different value and, if shown in diagnostics, must be
labeled **Channel identifier** rather than presented as a shortened key.

### Treat airtime as a shared resource

The application should choose safe routing defaults and explain unusual costs
before transmission. Routine messaging should not require users to understand
LoRa parameters. Expert controls may expose hop counts, regions, routes, duty
cycle, RSSI, and SNR, but must not turn maximum values into recommended values.

Large messages may require multiple frames. The composer should estimate this
before Send, indicate when a message will be fragmented, and discourage bulk
traffic without presenting a byte counter as the primary writing experience.

### Preserve platform conventions

The information architecture is shared across platforms; the widgets and
gestures are not. iOS uses its native navigation, sheets, menus, sharing,
camera, typography, accessibility, and settings conventions. Android should do
the equivalent with native Android patterns. Do not reproduce one platform's
visual chrome on the other.

## Stable information architecture

The compact mobile interface has three top-level destinations:

| Destination | Contains | Does not contain |
|---|---|---|
| **Conversations** | Direct messages, multicast channels, chat rooms, drafts, unread state | Node administration and raw packet logs |
| **Network** | Known nodes, contacts, repeaters, sensors, rooms, discovery, list/map views | A second copy of active conversations |
| **Settings** | User identity, radios, regions and radio presets, notifications, storage, diagnostics | Frequently used send or discovery actions |

These destinations should keep their navigation state when the user switches
between them. Larger screens may present the same hierarchy with persistent
sidebars and adjacent detail panes.

Network is broader than Contacts. It includes people, infrastructure, sensors,
rooms, bridges, and unknown-role nodes. A direct conversation can be started
from a node that supports text without requiring the user to save it as a
contact first.

Map is a presentation of Network, not a separate product area. It should be
available only when there are nodes with usable location metadata. A map must
show the precision and age of reported positions and must not turn a coarse
location cell into a misleading exact pin.

## Global actions

Every platform must provide discoverable routes to:

- scan a UMSH QR code;
- import a pasted or opened UMSH URI;
- share the user's public identity;
- create or join a channel;
- find observed nodes and start an eligible interaction;
- inspect and change the active radio;
- understand why sending is unavailable; and
- reach diagnostics without making diagnostics part of the daily interface.

The camera scanner may be reachable from both Conversations and Network, but it
is one shared action with one preview-and-confirm flow.

## Connection and readiness

The application has several independent readiness dimensions:

1. **Identity ready** — a user identity exists and is unlocked for use.
2. **Radio connected** — a trusted companion link is active.
3. **Radio configured** — an RF preset or explicit parameters are valid.
4. **Mesh reachable** — recent traffic or delivery evidence suggests useful
   connectivity.

Do not collapse these into one green or red dot. A disconnected radio is a
clear, actionable app-wide condition. Lack of recent mesh traffic is weaker
evidence and should be worded as such.

When an action cannot proceed, keep the user's work. Sending requires a
connected radio: a message composed while the radio is disconnected remains a
draft. Send takes on a visibly blocked appearance, and activating it explains
the reason without transmitting. There is no application outbox that starts a
logical send later: an eligible user send starts immediately. Once started,
the MAC may schedule, back off, fragment, or retransmit as required to complete
that active send. If it ends without required confirmation, label it
**delivery unconfirmed** as an effectively terminal result rather than leaving
it looking pending or promising automatic resolution.

### Radio status always includes power state

Every compact or expanded component that reports radio connection state must
also report the radio's battery or power state. This includes navigation-bar
status, connection banners, radio pickers, onboarding progress, readiness
summaries, and Radio Detail.

Use the most specific truthful presentation available:

- **Connected · 78%** when a current battery reading is available;
- **Connected · Charging 78%** when charging is known;
- **Connected · External power** for a device without a meaningful battery
  level;
- **Connected · Battery unavailable** when the radio cannot report it; and
- **Disconnected · Last battery 78%, 12 min ago** for a cached reading.

Never omit the power position merely because its value is unknown, and never
present a cached value as live. The battery glyph is accompanied by an
accessible text value; neither fill color nor icon shape alone conveys the
state. This value always describes the companion radio, not the phone.

The compact app-wide radio status occupies stable app-level chrome at the top
of every top-level and pushed screen. Platform-native toolbars may integrate
normal connected state with navigation controls instead of adding a separate
full-width row. It belongs to the application endpoint, not to the currently
visible chat, peer, map, or settings page. Changing screens must not move it
into that screen's content hierarchy. Selecting it opens Radio Detail.

Normal connected state should be extremely compact: a connection symbol and a
battery/power symbol are enough when the control's accessible label supplies
the exact radio name, connection state, and battery value. Disconnected,
incompatible, or attention-required state expands into an actionable banner in
the app-level slot immediately below the top toolbar and above the screen title
or content. It must not relocate into a chat or page-specific section.
Temporary full-screen system sheets may cover the underlying status; they do
not need to duplicate it unless radio state is directly relevant to the
sheet's decision.

## Safety boundaries

The following are distinct destructive actions and require distinct wording:

- disconnect from the current radio;
- forget this radio's BLE trust;
- replace the radio's configured host identity and wipe its old host-domain
  queue, filters, and provisioned keys;
- clear radio provisioning while preserving BLE trust;
- reset the radio's own identity or durable settings;
- remove a contact or conversation from the phone;
- leave a channel and delete its shared key from the phone;
- delete or replace the user's UMSH identity.

Confirmations must name the affected domain and state what remains. Destructive
actions default to Cancel and should not be combined into a generic **Reset**.

## Accessibility and privacy

- Support the platform's text scaling, screen reader, high-contrast, reduce
  motion, and alternative input features.
- Never encode delivery, urgency, role, or trust using color alone.
- Notification previews should default to the platform convention, with an
  in-app option to hide sender and message content on the lock screen.
- QR codes containing private channel keys must be visibly labeled as secrets.
- Copying a private channel URI should warn that the clipboard may be readable
  by other software.
- Location sharing must expose precision and audience together; a user chooses
  not only whether to share, but how precisely and with whom.

## Product maturity labels

The protocol includes features whose wire behavior is incomplete, such as
managed-channel administration. Mobile designs may reserve conceptual space
for them, but must not present them as implemented. Use **Unavailable in this
version** for known protocol features and **Not supported by this radio** for
capability differences.
