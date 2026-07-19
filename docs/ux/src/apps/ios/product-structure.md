# iOS Product Structure

This chapter applies the [mobile application guidelines](../mobile-guidelines.md)
to iPhone and iPad. It specifies product behavior and native interaction
patterns, not an implementation framework.

## Native iOS character

The app should use standard iOS navigation bars, tab bars, lists, search,
menus, sheets, alerts, share sheets, camera permission, context menus, swipe
actions, Dynamic Type, VoiceOver, and SF Symbols. Platform-default behavior is
preferred unless it conflicts with a UMSH safety or trust requirement.

Treat Apple's current [Human Interface
Guidelines](https://developer.apple.com/design/human-interface-guidelines) as a
living design dependency and recheck it when detailed visual design or
implementation begins. Use the current SDK's system navigation, toolbar, tab,
material, safe-area, and scroll-edge behaviors—including Liquid Glass where the
system supplies it—instead of freezing a custom imitation of one iOS release.
Keep top toolbars sparse, use familiar SF Symbols, preserve native Back and
Close behavior, and provide full accessible labels and system-sized hit regions
for compact symbol-only controls.

On iPhone, each top-level tab owns a navigation stack. On iPad and wide iPhone
layouts, the same hierarchy can adapt to a split view with a sidebar/list and a
detail pane. Resizing must not change the conceptual location of an item or
discard a draft.

The app supports light and dark appearances and must not rely on custom chat
bubble colors supplied by remote senders when they reduce contrast. Remote
color suggestions may be ignored or adapted.

## App-wide shell

The compact tab bar contains:

1. **Conversations** — `message` symbol; badge is unread conversations, not
   raw packets.
2. **Network** — `point.3.connected.trianglepath.dotted` or the closest current
   system symbol; no badge for routine discovery.
3. **Settings** — `gearshape`; a badge appears only for an actionable radio,
   identity, or migration problem.

Every app screen places a compact companion-status toolbar item in the center
group of the top navigation toolbar. In normal connected state it shows only an
appropriate SF Symbol for the companion link and a battery/power SF Symbol; it
does not repeat the radio name or the word **Connected**. Its VoiceOver label
states the complete value, for example **Companion radio T1000-E, connected,
battery 78 percent**. The visible glyphs remain compact, but the toolbar item
keeps a native 44-by-44-point hit region and opens Radio Detail.

The leading toolbar group retains Back or other navigation, and the trailing
group retains the screen's most important action. The page or conversation
title uses the native navigation/large-title region rather than competing with
the centered radio control. Keep toolbar groupings sparse and let system
components, safe areas, scroll-edge effects, and Liquid Glass appearance come
from iOS rather than drawing a custom status bar.

This is the stable position across Conversations, Network, Map, Settings,
conversation transcripts, and pushed details. The radio remains app-level
chrome and never appears to belong to the active conversation.

A disconnected or incompatible state changes the compact toolbar symbols and
adds a concise actionable banner immediately below the toolbar but above the
page title/content. The banner says what happened and offers **Connect** or
**Details**. It includes the last-known battery/power state with its age.
Recovery removes the banner and restores the icon-only toolbar control. The
companion status is not a fourth tab and does not replace message-specific
delivery state.

This treatment follows Apple's current [Human Interface
Guidelines](https://developer.apple.com/design/human-interface-guidelines),
including the guidance for [toolbars](https://developer.apple.com/design/human-interface-guidelines/toolbars),
[layout and safe areas](https://developer.apple.com/design/human-interface-guidelines/layout),
and [accessible control sizing](https://developer.apple.com/design/human-interface-guidelines/accessibility).

Global UMSH URI handling uses the same import sheet whether invoked by camera,
paste, document import, or an external link.

## First launch and onboarding

Onboarding is resumable and contains four conceptual steps. A user may explore
read-only explanatory material without granting Bluetooth or camera access,
but cannot send until Identity and Radio are ready.

### 1. Welcome

Explain in one screen:

- messages travel through a nearby UMSH radio, not through cellular service;
- the user's cryptographic identity belongs to this app/device; and
- the app is useful without internet access.

Primary action: **Set Up UMSH**. Secondary action: **Learn How It Works**.

### 2. Identity

Offer only recovery choices the product can safely support:

- **Create new identity**; and
- **Restore an exported identity**, shown only when the protected identity
  export format is implemented (hidden, not disabled, before then).

Creation asks for a display name first — explained as advertised, changeable,
and not unique — then generates the key pair locally, previews the exact
44-character Base58 public address, and explains that losing the private key
changes how the mesh recognizes the user. The name may be left blank; the
address, not the name, is the identity.

Restore accepts the export artifact (file or QR set; format specified in
`docs/protocol/src/identity-export.md`) and its passphrase, shows
a non-committing preview of the name and complete address, and commits only on
an explicit confirmation. Restore marks a fresh counter epoch and requires the
app to warn that the exporting device must stop using the identity. The app
does not ask the user to confirm an erasure it cannot verify. Restore never
merges with an identity already on the phone.

Do not promise iCloud synchronization until frame-counter, simultaneous-use,
conflict, and recovery behavior are specified. Onboarding creates the app's
first identity; screens should name the identity rather than calling it "your
account," because the product may later hold more than one (see Open
Decisions).

### 3. Radio

Request Bluetooth permission only when the user chooses **Find a radio**. The
scan lists devices advertising the UMSH companion service and displays their
advertised device names without claiming ownership.

Selecting a radio starts the platform pairing flow. The app explains any
required physical-presence gesture or PIN before the system prompt appears.
After attachment, it reads capabilities and compares the radio's configured
host identity with the app identity.

If the radio belongs to another host identity, stop and show a takeover sheet:

> Use this radio with your identity?
>
> This removes the previous phone identity's queued incoming frames, filters,
> and delegated keys from the radio. It keeps the radio's own identity, BLE
> pairing, and radio settings.

Actions: **Cancel** and **Replace host identity**. The destructive action is
not the default.

### 4. Radio preset and readiness

Choose a region/regulatory profile and a compatible radio preset. Prefer named
presets over raw frequency, bandwidth, spreading factor, coding rate, sync
word, and power. Show expert values in a disclosure view.

The completion screen separately confirms:

- identity created;
- radio connected, with current battery/power state;
- radio preset active; and
- optional offline assistance configured.

Primary action: **Open Conversations**. Secondary action: **Share my identity**.

## Conversations tab

### Conversation list

Navigation title: **Conversations**. Toolbar actions:

- compose menu: **New message**, **Join channel**, **Join room**; and
- more menu: **Scan UMSH code**, **Message requests**.

Search filters by local mnemonic alias, advertised name, channel/room name, complete
Base58 node address, and canonical rendered hint. It does not require network
access.

Each row includes:

- deterministic NodeHint avatar for a peer, or an explicit type icon for a
  Channel or Room;
- resolved display label;
- last-message preview or explicit empty-state text;
- time of locally recorded activity;
- unread count; and
- one compact exceptional status such as **Delivery unconfirmed**, **Failed**,
  or **Logged out**.

The type marker also has a visible text equivalent. For example, a channel row
shows **Private channel · Maya: Camp is set** rather than relying on a hash icon
to distinguish it from a direct or room conversation.

Pin, mute, and delete/archive actions use conventional context menus or swipe
actions. Destructive swipe behavior requires confirmation when it would delete
history or a channel key.

Empty state: explain that conversations begin by scanning a person's identity,
choosing a text-capable node from Network, or joining a channel/room. Offer
**Scan code** and **Browse network**.

### Direct conversation

The navigation title uses the local mnemonic alias, falling back to advertised
name or **Unnamed node**. The peer's deterministic NodeHint avatar appears in
the header. The complete address or canonical rendered hint is available in
Peer Detail. A subtitle/status can say **Direct** or **Last seen 12 min ago**;
it must not claim presence from stale traffic, and radio connection state stays
in the app-level toolbar control rather than the conversation subtitle.

When PFS is establishing, active, ending, or failed, the avatar carries the
corresponding outer-ring treatment and visible text beside the title states the exact
condition, for example **PFS active · 24 min remaining**. The deterministic
avatar color never changes for security state. Tapping the avatar/title opens
Peer Detail, where the same status and controls are available.

Tapping the title opens Peer Detail. The transcript uses standard readable
bubbles, date separators, reply previews, inline status/emote messages, and
missing-fragment placeholders. Long-press/context-menu actions include Reply,
React, Copy, Edit/Delete when permitted, Details, and Quote when a wire reply is
no longer representable.

The composer remains usable for drafting when the radio disconnects. Send takes
on a visibly blocked treatment; activating it sends nothing and explains that
a connected radio is required. There is no deferred application outbox. An
eligible logical send starts immediately, although the MAC may schedule and
retransmit while that active send is in progress. A terminal failure stays in
the transcript with an explicit Retry action. Retry sends the same logical chat
message and Message Sequence ID in fresh packets with fresh counters. If a send
ends without its expected acknowledgement, **delivery unconfirmed** is an
effectively terminal state rather than a promise to finish after reconnection.
Valid late evidence may still upgrade it without showing ongoing progress in
the meantime.

When current radio duty information proves the message cannot be transmitted,
the composer preserves the draft and gives Send a visibly blocked treatment.
Activating it explains the airtime limit and shows the earliest
reliable retry time or estimate. No new application-level attempt is queued to
start automatically. An unexpected `STATUS_DUTY_LIMIT` response becomes a
failed attempt with an explicit manual retry after the stated time.

### Channel conversation

Selecting a channel row in Conversations opens its chat transcript, not Channel
Detail. The transcript uses the same composer and message actions as other text
conversations. The user types once and presses **Send**; the app creates one
multicast text message addressed to the channel. There is no recipient picker:
every listening node that possesses the channel key is eligible to receive and
display the message.

The navigation title names the channel and a persistent subtitle identifies
**Private channel · Multicast**, **Public named channel · Multicast**, `public`,
or `EMERGENCY`. Directly above the transcript, a compact audience line says
**Everyone with the channel key** for a symmetric private channel. The composer
placeholder names the destination, for example **Message Trail Crew channel**.
An Info button or tapping the title opens Channel Detail. Sender labels in the
transcript link to Peer Detail without automatically saving contacts.

Incoming messages show the sender's resolved name above the bubble because a
channel contains multiple speakers. The user's own messages align and style
consistently with direct messages. The composer remains available for drafting
while the radio is disconnected; Send requires a connected radio, exactly as in
direct conversations.

Use a neutral iOS-adaptive bubble for all incoming participants rather than a
different color per person. Pair the first bubble in each consecutive sender
group with a deterministic NodeHint avatar and sender label, use tighter spacing within that
group, and add a larger break when the sender changes. Outgoing bubbles align to
the trailing edge and use the app's standard outgoing treatment. Timestamps and
**Sent over radio** remain below/outside the bubble so delivery evidence is not
mistaken for message content.

The message-detail screen explains that **Sent over radio** is not a group
delivery receipt. Invalid public/emergency traffic never appears in the normal
transcript.

Channel Detail is a first-class destination, not a generic group-chat info
screen. It shows channel type, concealed/revealable full channel key, local display name, member
model, region/hop defaults, notification policy, share invitation, and Leave
Channel. For a symmetric channel it must not invent a reliable member list;
recent senders may be shown as **Recently seen participants**, which is
observation rather than authoritative membership.

### Room conversation

Before login, show Room Preview with **Join room**. A password field appears
only when requested by the room. After login, show the current handle and a
members action. **Load earlier messages** requests bounded history; it is not an
infinite-scroll illusion when the room cannot provide more.

The room's echo reconciles an optimistic outgoing bubble. Until the active send
ends, label it **Waiting for room**. If it ends without the echo, including
because the radio disconnects, **delivery unconfirmed** is effectively
terminal. Valid late evidence may still reconcile it. Logout and Delete Local
History are separate actions.

## Network tab

### Network list

Navigation title: **Network**. A native search field and filter menu support:

- All;
- People/Text;
- Sensors;
- Repeaters and bridges;
- Rooms; and
- Saved contacts.

The default list groups **Contacts**, **Recent**, and **Nearby/Observed** when
those groups contain items. Duplicate addresses appear once even if learned by
several paths. Rows show role/capabilities, last observation, and a concise
source label. RSSI/SNR may appear in detail, not as a fake distance.

Toolbar actions: **Scan code**, **Paste URI**, and an overflow action for
**Enter public key**. **Discover peers** is the prominent empty-state action and
remains available from the toolbar menu. A persistent **List | Map** segmented
control sits below search. Tapping **Map** replaces the network list while
keeping the Network tab selected; returning to **List** restores the prior
filters and scroll position.

### Discover peers sheet

The sheet starts a bounded listening session and streams identity-bearing
results into a list. Its header shows elapsed/remaining time and the selected
scope, not an indefinite spinner. Primary actions are:

- **Announce my identity**, which previews included metadata and flood scope;
- **Stop**; and
- a result action to View, Message, or Save Contact.

The first release must not label this **Scan the mesh** or imply that silent
nodes will be returned. A short explanation says that results appear when
nodes announce themselves or otherwise send identity-bearing traffic.

### Network map

The map renders location regions according to advertised precision. A coarse
location is a cell or area, not a centered precision pin. Selecting a mark or
area opens a compact node summary and then Node Detail. The map shows when data
was generated or last observed and distinguishes reported location from phone
location.

The Map choice remains visible even when no mapped nodes exist. Its empty state
says **No reported node locations** and offers **Discover peers** and **Show
list**. On iPad, the List/Map choice stays in the Network toolbar while the
selected node can occupy the detail column.

### Peer detail

Peer Detail is the dedicated view for a known person or other directly
addressable peer. Its header contains the deterministic NodeHint avatar, local
mnemonic alias or fallback name, advertised name when different, canonical
NodeHint, and observation age. The compact companion-radio control remains in
the centered top-toolbar group above the Peer Detail content.

Primary actions are **Message**, **Ping**, and **Show QR**. The system Share
action exports the peer's public identity URI. **Ping** sends one Echo Request,
shows progress, and reports response latency only after the matching Echo
Response. A timeout says **No response before timeout** rather than **Offline**.

The Identity group contains **Set alias** or **Edit alias**, advertised name,
the exact 44-character Base58 public key with Copy, and QR/share actions. A
local alias takes display precedence everywhere but never overwrites the
advertised name or changes the public key.

The Security group shows **Standard encryption**, **Establishing PFS**, or
**PFS active** with the accepted expiration. **Establish PFS session** first
opens a native duration confirmation; **End PFS session** is visible only while
active or establishing. Session expiration and either device reboot return the
relationship to standard long-term pairwise encryption. Ephemeral addresses
are available only in advanced session details and never replace the stable
peer avatar.

Peer Detail is reached by tapping a direct-chat title/avatar, a peer row in
Network or discovery, or a sender identity in a channel transcript. Returning
to chat preserves the draft and transcript position.

### General node detail

The header shows local mnemonic alias, advertised name, role, and capabilities. The
Identity section shows the complete fixed-width Base58 address. If only a hint
is available, it instead shows **Node hint** using the verified-prefix/`*`
algorithm. Primary actions are capability-driven:

- **Message** for text-capable nodes;
- **Open room** for chat-room nodes;
- **View data** for supported sensor/CoAP resources;
- **Manage** only when authorization and implemented management operations are
  known; and
- **Save contact** or **Edit contact**.

When the node is a known directly addressable peer, this content is presented
through Peer Detail rather than as a second competing detail screen. Sensor,
repeater, bridge, and room-specific sections extend the same underlying node
record.

Sections include Identity, Activity, Location, Routing, Services, and Advanced.
Unknown values are omitted rather than shown as zeros. The complete address, URI, raw
identity metadata, signature status, and route diagnostics live under
Identity/Advanced.

### Sensor/resource detail

The first version should support a generic resource list and value/history
presentation rather than inventing a dashboard for every sensor. Each value
shows source node, observation time, units, and staleness. Control/write actions
name the target and require confirmation when consequential.

### Repeater/bridge detail

Show role, supported regions, last observed time, and route evidence. Avoid a
consumer-style signal-strength score. Administrative controls appear only after
the node and authorization scheme support them; ordinary observation does not
imply permission to manage infrastructure.

## Settings tab

Use a native grouped settings list with these sections:

### Identity

- Your identity
- Display name and advertised metadata
- Share identity
- Location-sharing defaults
- Export and restore, only when the protected export format is implemented

Identity Detail shows the complete 44-character Base58 public address, creation/local
record information, and storage/recovery state. Private key bytes are never
shown or copied.

### Radio

- current radio and connection state;
- choose/add radio;
- active preset and region;
- offline assistance summary;
- radio device identity;
- battery or explicit **Battery unavailable**, plus firmware/diagnostics when
  supported; and
- Forget Radio, Clear Provisioning, or Reset Radio as separate actions.

Radio Detail separates **Connection**, **Mesh radio**, **Offline assistance**,
**Radio identity**, and **Maintenance**. Expert RF controls live behind an
explicit disclosure and show regulatory constraints.

Battery belongs beside Connection at the top of Radio Detail, not only in a
diagnostic section. Show percentage, charging/external-power state, and reading
age where applicable.

### Notifications and privacy

- message preview privacy;
- per-kind notification defaults;
- background/offline-assistance explanation;
- location and camera permission links; and
- blocked nodes.

### Data and diagnostics

- local storage summary;
- export diagnostics with a redaction preview;
- packet/radio log for expert troubleshooting;
- protocol and app versions; and
- feature/capability matrix.

Diagnostics should use exact protocol language and preserve evidence. Sharing a
diagnostic package must preview whether keys, message bodies, public addresses,
locations, or device identifiers are included and redact secrets by default.

### Settings overview layout

The Settings tab is a native grouped list, not a dashboard. The first two rows
are the current identity and current radio because they determine whether the
app can participate:

1. **Your identity** — display name and storage/recovery status; selecting it
   opens the complete Base58 address, sharing, advertised metadata, and
   location-sharing defaults.
2. **T1000-E Radio** — **Connected · 78%** (or the truthful alternative power
   state) and active preset; selecting it opens Radio Detail.
3. **Mesh and radio defaults** — regions, routing defaults, named presets, and
   expert controls.
4. **Notifications** and **Privacy**.
5. **Data and diagnostics** — storage, logs, export, and versions.
6. **About UMSH**.

Destructive identity and radio actions appear only inside their respective
detail screens, never on the Settings overview.

## Import preview sheet

The sheet title reflects the decoded type: **Node identity**, **Private channel
invitation**, **Public named channel**, or **UMSH resource**. It includes:

- human-readable target;
- complete Base58 address, canonical rendered hint, or concealed full channel
  key where relevant;
- security meaning in plain language;
- signature and freshness state;
- metadata/routing recommendations; and
- conflict or duplicate information.

The confirmation button names the result: **Message**, **Save contact**, **Join
channel**, or **Open resource**. **Cancel** is always available. Scanning never
adds state before this sheet.

## Sharing on iOS

Use the system share sheet for public identity and URI sharing. A QR sheet adds
brightness-friendly presentation, a readable type label, complete Base58 address, and
Copy/Share actions. Private channel invitations require a disclosure before the
share sheet. Identity sharing defaults to signed public metadata without
location.

Import previews do not place a decorative key glyph above the content. A key
icon can be mistaken for unlabeled key material or an action. The navigation
title states **Private channel invitation**, while the actual shared key appears
only in the labeled invitation-details section using the protocol's canonical
key presentation.

## iPad behavior

Conversations and Network use a two-column split when space permits: list or
sidebar on the leading side, selected detail on the trailing side. Settings may
use a grouped sidebar and detail. Preserve visible selection and support
keyboard navigation, context menus, drag-and-drop of UMSH URIs, and multiple
window widths.

Do not create iPad-only product concepts. An operation available on iPad must
remain reachable on iPhone through the corresponding navigation stack or
sheet.

## Platform references

The native structure should be reviewed against Apple's current Human Interface
Guidelines, especially [Designing for iOS](https://developer.apple.com/design/human-interface-guidelines/designing-for-ios/),
[Tab bars](https://developer.apple.com/design/human-interface-guidelines/tab-bars),
and [Split views](https://developer.apple.com/design/human-interface-guidelines/split-views).
