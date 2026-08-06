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
2. **Peers** — `point.3.connected.trianglepath.dotted` or the closest current
   system symbol; no badge for routine discovery.
3. **Settings** — `gearshape`; a badge appears only for an actionable radio,
   identity, or migration problem.

Channels are not a tab. Membership is a handful of keys that change only when
the user says so, which does not earn a permanent place in the tab bar the way
conversations and peers do. They live under Identity in Settings, which is also
where they belong: the keys are held by the identity, and a different identity
would have a different set.

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

This is the stable position across Conversations, Peers, Map, Settings,
conversation transcripts, and pushed details. The radio remains
app-level chrome and never appears to belong to the active conversation.

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
scan lists devices advertising the ULCP GATT service and displays their
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

Navigation title: **Conversations**. The toolbar carries a compose menu:
**New Message…** and **New Channel Chat…**.

Direct chats and channel group chats share one list with no section headers.
Ordering is by most recent activity across both kinds, so a channel with newer
traffic sits above a quiet direct chat; a conversation with no messages yet is
as recent as its creation, so a chat just opened sits at the top where the
user who opened it will look for it.

Not every joined channel appears. Joining from Settings is membership alone —
the conversation is created when the user asks for one, either from **New
Channel Chat…** or from **Enter Conversation** in Channel Detail. Joining a
channel *through* the compose menu is a request to talk in it, so that path
creates and opens the conversation. `public` is the exception: while joined,
its conversation always exists, because it is where an off-grid conversation
starts when the user holds nobody's key yet.

The search field is hidden until the list is dragged down, which is where a
reader looking for someone reaches for it. Results are grouped in the order
they are most likely wanted:

1. **Conversations** — matching conversations of either kind, rendered exactly
   as they are in the list proper and in the same most-recent-activity order.
   Somewhere the user already talks is almost always what they were reaching
   for.
2. **Peers** — saved nodes with no conversation yet.
3. **Channels** — joined channels with no conversation yet.
4. **Discovered nodes** — the transient tier the Peers list hides, included on
   the reasoning that a node heard over the air is reachable, so it is
   findable.

Tapping anything below the first group opens the conversation with it, creating
it first. Searching a channel out is a request to talk in it, so it creates a
group chat the way joining through the compose menu does. The phone's own
companion radio is never a result; it is hardware, not a correspondent.

Search matches a node's local mnemonic alias, advertised name, Base58 address,
and canonical rendered hint; and a channel's alias, its own name, and its
identifier. Address and identifier matching is by prefix — both are exact
encodings, so a hit in the middle of one carries no meaning. Message search is
not implemented. Searching does not require network access.

Each row includes:

- a deterministic NodeHint avatar for a peer, or the channel's rounded-square
  badge, which is enough to tell the two kinds apart at a glance;
- resolved display label, emphasized while unread;
- last-message preview, or explicit empty-state text. A group preview is
  prefixed with the sender, since the body alone does not say who is talking;
- relative time of the last locally recorded activity;
- an unread dot; and
- a muted-bell marker for a channel with notifications off.

Muting is about banners only. A muted channel still receives, still records,
and still counts as unread.

Deleting a channel conversation removes the local transcript and leaves channel
membership intact; a later message opens it again. Leaving the channel removes
its conversation, since without the key there is nothing to send and nothing
further will arrive.

Pin, mute, and delete/archive actions use conventional context menus or swipe
actions. Destructive swipe behavior requires confirmation when it would delete
history or a channel key.

Empty state: explain that a conversation begins with a peer or in a joined
channel, and offer **New Message…** and **New Channel Chat…**.

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
avatar color never changes for security state.

Tapping the avatar/title opens the **conversation info sheet**, which both kinds
of conversation share. It answers what the conversation *is*: a row leading to
whoever — or whatever — is on the other end (Peer Detail for a direct chat,
Channel Detail for a group one), what the transcript holds, and the
conversation-level actions. It is deliberately not the peer or channel sheet
itself; those describe a node and a key, which outlive any one conversation
with them. From a group conversation, Channel Detail does not offer **Enter
Conversation** — entering it is what got the user there.

**Clear All Messages** erases the transcript while keeping the conversation:
the row, its draft, and its place in the wire stream all survive, so it is the
action for a conversation the user intends to keep using — as distinct from
deleting the conversation. It is local only; nothing is sent and everyone else
keeps their copy. Outbound stream checkpoints are retained for the same reason
deleting a conversation retains them: sequence continuity with the far end has
to outlive the transcript, or the next message would announce a Sequence Reset.
Archived outbound payloads go with the history, so a later resend request for a
cleared message is answered Unavailable.

The transcript uses standard readable
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

The navigation title names the channel and the header carries its badge, the
way a direct conversation carries the peer's avatar; tapping it opens the same
conversation info sheet, whose identity row leads on to Channel Detail. The
composer placeholder names the destination, for example **Message Trail Crew**.

A group message is authenticated as coming from *a member*, not from a
particular person: the channel MIC proves possession of the key, and the only
sender identity the wire must carry is a 3-byte hint. Each inbound bubble is
paired with its sender's deterministic hint avatar and a label, chosen in
descending order of authority:

1. the name this phone has for that peer — an alias it was given, or a name it
   advertised and signed;
2. the name the sender attached to the message itself;
3. their address; then
4. **Member a1b2c3**, the bare hint.

The message-borne name is the sender's own unverified claim — anyone holding
the channel key can write anything there — so it is useful exactly when
nothing better is known, and never displaces a name this phone established. The
member sheet shows it separately as **Calls themselves** when the two differ.
Outgoing group messages carry this phone's advertised name for the same
reason; direct messages do not, because the recipient authenticated us by key.

A hint resolves to a full address on its own, since group sends carry the full
source address. When it does, earlier messages from that member are relabelled
retroactively rather than left inconsistent. Tapping a sender opens what is
known about them, and offers **Request Identity** for a member still
unidentified; that request goes out over the channel itself, since a hint is
not an address anything can be unicast to.

Our own group message, relayed back by a repeater, is never shown a second
time. It names us as its sender because every group send carries our full
address, but it is the message already in the transcript. It is still recorded
under the hood: it is the only proof a multicast ever produces that something
out there received and forwarded it.

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

Multicast has no acknowledgement, so a group message's terminal success state
is **Sent** and never **Delivered**. The message-detail screen explains that
this is not a group delivery receipt. Invalid public/emergency traffic never
appears in the normal transcript.

**Details** on any received message — direct or group — reports what the radio
observed of the frame it arrived on: hop count (**Direct** when nothing
relayed it), signal strength, signal-to-noise, link quality, whether the source
was authenticated, and the route it took. Reachability in a mesh is not
obvious from the outside, so a message that arrived says how it got here.

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

## Peers tab

### Peers list

Navigation title: **Peers**. A native search field and filter menu support:

- All;
- People/Text;
- Sensors;
- Repeaters and bridges; and
- Rooms.

The default list groups **Favorites** and **Saved nodes** when those groups
contain items; a node the user starred is one they want at the top, and there is
no second tier of saved node below that. Nodes heard on the air but not saved
stay out of the list and surface through search and the discovery session.
Duplicate addresses appear once even if learned by several paths. Rows show role/capabilities, last observation, and a concise
source label. RSSI/SNR may appear in detail, not as a fake distance.

Toolbar actions: **Scan code**, **Paste URI**, and an overflow action for
**Enter public key**. **Discover peers** is the prominent empty-state action and
remains available from the toolbar menu. A persistent **List | Map** segmented
control sits below search. Tapping **Map** replaces the network list while
keeping the Peers tab selected; returning to **List** restores the prior
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

### Peers map

The map renders location regions according to advertised precision. A coarse
location is a cell or area, not a centered precision pin. Selecting a mark or
area opens a compact node summary and then Node Detail. The map shows when data
was generated or last observed and distinguishes reported location from phone
location.

The Map choice remains visible even when no mapped nodes exist. Its empty state
says **No reported node locations** and offers **Discover peers** and **Show
list**. On iPad, the List/Map choice stays in the Peers toolbar while the
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

Peer Detail is reached from a direct chat's conversation info sheet, a peer row
in Peers or discovery, or a sender identity in a channel transcript. Returning
to chat preserves the draft and transcript position.

When a saved companion radio exposes its own UMSH public identity, that
identity is also represented by exactly one `NodeRecord` and appears in the
Peers list as a peer. Peer Detail labels it **Companion radio identity** and
links to Radio Detail. The record is system-managed: ordinary peer removal is
unavailable while the associated radio remains saved. This does not
make the radio identity the phone's identity or grant infrastructure-management
authority.

Forgetting the radio removes the association and its system-managed protection,
not message history. If the node is still referenced by a conversation or other
durable evidence, it remains as an ordinary peer record. A transparent radio
that does not expose a device identity does not create a synthetic peer.

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
- **Save Peer**, or rename and favorite one already saved.

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

Configuring a repeater the user physically has is a different path with a
different basis for authority: device setup in Settings connects to it locally
over Bluetooth, gated by that device's own pairing. Nothing there extends to a
node observed only through the mesh, and this screen does not link to it.

## Channels

Reached from **Identity → Channels** in Settings, whose row carries the joined
count. This screen is membership, not a directory: everything in it is a key
this phone holds, and nothing heard on the air can add to it.

### Channel badge

A channel is drawn as a rounded square, distinguishing it at a glance from a
peer's circular avatar. It carries the first letter of each word of the
channel's name, up to four, two to a line — so three and four initials stay as
large as two rather than shrinking. A private channel that was never named has
nothing to initial and shows its identifier instead.

The colour is derived from the key: the channel-identifier derivation run one
byte longer, `HKDF-SHA256(channel_key, salt="UMSH-CHAN-ID", info="", L=3)`, so
its first two bytes are the identifier itself. Everyone holding the key sees
the same badge with nothing agreed or transmitted.

Two exceptions are recognized on sight rather than read: `public` is a white
**P** on blue, `EMERGENCY` a white **E** on red.

A derived colour can land anywhere, including the middle of the brightness
range where neither black nor white text reads well. The badge keeps the
derived hue and moves only brightness and saturation, into whichever of a light
or dark band it is already nearer; each band clears 4.5:1 against a fixed text
colour.

### Channel list

Sections appear only when they contain something:

- The channels this identity is in, with no section header — everything listed
  is joined, which the screen title already says. Each row shows the channel's
  badge, its name as written, a type label (**Built-in**, **Public**,
  **Private**), the two-octet derived identifier in monospace, and which
  identities have joined it (**Phone**, **Radio**, or **Phone and radio**). A
  muted channel carries a bell-slash glyph with a text equivalent for
  VoiceOver. Swiping a row offers to leave, confirmed.
- **On the radio only** — identifiers the companion radio's device identity
  reports that this phone holds no key for. They are shown, not named: the
  device reports derived identifiers and never key material. Selecting one
  explains that, rather than implying the phone could open it.

`public` and `EMERGENCY` are joined on first run with notifications off. They
are the channels a new user is expected to be reachable on, but neither should
announce itself before the user has a reason to care.

Either may be left, and the key survives so re-joining needs no invitation —
but a channel the user has left never appears in this list again. Leaving is a
decision, and re-offering it here would make the tab an argument rather than a
statement of what the user is in. The standing offer belongs in the join sheet,
where the user has already come looking.

The toolbar's add menu offers **Join Channel…** and **New Private Channel…**,
and its trailing position on a channel's own screen is the standard system
share control.

### Join channel

One entry point covers both ways in. The field accepts a public channel name or
a pasted `umsh:cs:` / `umsh:ck:` invitation, and the same staged behavior
applies as every other URI import: parse locally, preview, confirm.

A **Suggested Channels** section lists any standard channel the user has left,
as a one-tap re-join. This is the only place the app raises them again.

The preview names the kind — **Public Channel** or **Private Channel
Invitation** — and states the security meaning plainly: a public name is not a
password, and a private key makes its holder a full member who can also send as
any other member. Joining `EMERGENCY` additionally describes how its traffic
behaves.

The canonicalized name is never shown. It decides which channel a name reaches,
but it is key-derivation machinery, and surfacing a lowercased form beside the
name the user wrote reads as a bug rather than a fact. Channels are named the
way they are written; capitalization simply does not matter, invisibly.

A key the phone already holds turns the action into **Update Local Details**
rather than creating a second channel. A different channel already using the
same name is called out before the button becomes available; the two are
distinct channels and messages never cross between them.

### Channel detail

Leads with the channel itself — name as written, type, derived identifier, and
join date — then local details, then membership. The key is not shown: it is
not something to read, and the invitation is the way it leaves the phone. **Alias** is the local override; it takes display precedence
everywhere but never changes the channel's own name, exactly as a peer alias
behaves, and it is what travels nowhere when the channel is shared. The phone and the companion radio are separate members with separate
key tables, so each has its own control. When no radio with an identity of its
own is attached, the radio control is unavailable and says why — never simply
"not joined".

Where the protocol fixes a channel's behavior, the screen states it instead of
offering a control the user could contradict. `public` and `EMERGENCY` show
their hop ceiling as a value — five without a region code, seven with one —
rather than as a picker, and a **How This Channel Works** section describes
what the channel does.

That section is written as fact, not instruction. The app applies every one of
these rules itself, so the user has nothing to comply with and must never be
addressed as though a message could be sent the wrong way: "All traffic here is
unencrypted", not "Messages must be unencrypted". A hop recommendation arriving
in an invitation for one of these channels is ignored for the same reason, and
is not passed on when the channel is shared again.

Sharing is the standard system share control in the trailing toolbar position,
not a row in the form. It opens a sheet with a QR code and URI. A public channel shares only its name. A
private channel's invitation is key material, and the sheet says so where the
invitation is, not only on the way in. The name travels written as it is read —
`umsh:cs:Trail%20Crew` — and canonicalization happens after percent-decoding on
the way in, so casing survives sharing without changing which channel is meant.

Leaving is confirmed. A built-in or public channel can be re-joined from its
name at any time; a private channel's key is deleted with it, and re-joining
needs a fresh invitation from someone still inside.

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

### Devices

A single **Set up a device…** row opens the device-setup sheet. It is the entry
point for configuring any nearby UMSH device over its local control interface —
a repeater or a tracker.

Device setup is a foreground session and is deliberately unlike the companion
binding:

- it runs on its own Bluetooth session, concurrent with the companion
  connection, and neither interrupts the other;
- it never claims the device for this phone, so the device's existing host
  identity, filters, and queued traffic are left alone;
- nothing is remembered between visits — no saved device list, no automatic
  reconnection, and a dropped link ends the session with **Connection lost**
  and a retry rather than a background wait; and
- the device's own Bluetooth pairing still gates every connection.

The sheet asks what the device is for before it looks for one: **Set up a
tracker**, **Set up a repeater**, or **Change a device's settings**. The goal
comes first because it decides the rest — which devices can serve it, which
settings a person should be asked about, and which the role itself answers.

The two setup goals present a short sheet rather than the full editor. The full
editor is reached from the sheet, but only after the write.

#### What each goal decides

A goal decides what it can from context and asks about the rest. Assumed values
are not recited back — a goal named "set up a tracker" already says the device
will not forward — with one exception, the radio profile below, whose failure
mode is silent.

| | Decided | Asked |
|---|---|---|
| **Tracker** | forwarding off · radio on · role Tracker · mobile · the phone's time zone · the clock, on apply | radio profile · name · discoverability · positioning policy · announcements |
| **Repeater** | forwarding on · radio on · role left derived · stationary · the phone's time zone · the clock, on apply | radio profile · name · forwarding policy · discoverability · positioning policy · announcements |
| **Change settings** | nothing | everything the device supports |

Setup is not monitoring: a setup sheet carries no live readouts, no
find-this-device, and no battery. Those belong to the editor reached afterwards.
The positioning **policy** — receiver, disclosure, precision, clock trust — is a
decision and appears; the fix, satellite count, and coordinates are readings and
do not.

#### Radio profile

Putting a node on a mesh means putting it on the mesh's profile, and the one
profile the phone can be sure of is the one its own radio is using. A setup
sheet copies it, reduced to what the target device accepts, and shows the result
as a single row naming the profile and its numbers — including transmit power,
so copying a handheld's power onto a mast-mounted repeater is visible and
correctable. The row pushes the preset picker and the manual PHY fields.

With no companion radio attached, or one that reported no modem settings, the
row asks instead of guessing, and answering it is what releases Apply. When
there is also nothing safe to offer — the device would not report the modem
settings a profile has to set — the device is left on the profile it already
had, and the row says so.

#### Goals a device cannot serve

A goal is refused only when the device cannot do the thing being asked of it,
and the refusal happens as the device attaches, with the reason and a way back
to the list. A tracker needs its own node identity and a way to announce it. A
repeater needs to be able to forward, and to have reported what its forwarding
policy currently is — a policy that cannot be read is one a sheet must not
overwrite.

Everything else degrades and says so in a line at the top of the sheet: a device
with no receiver, one that cannot be told a role, or one that keeps no clock is
still set up in every other respect.

The scan list marks the phone's own companion radio and does not offer it for
setup, because the companion connection already holds it. Devices are listed in
the order they were first heard, and appear and disappear with an animation: a
list of things in the room should not rearrange itself, and a name arriving on a
later advertisement should not move the row it names.

The editor states whose device it is — **Not configured**, **This phone**, or
**Another host** — as information, not as a gate. A setup sheet reduces that to
the one case worth interrupting for: a device that is another phone's companion
radio. It groups device name, radio profile and PHY parameters, advertised
identity, and repeater policy. The whole editor is applied as one operation: the
radio is disabled first and re-enabled last, the device saves, and the app reads
the saved settings back before reporting success, so what is confirmed is what
the device will boot with. A field the device reports back differently is named
rather than quietly accepted.

A device accepts its configuration whole. Settings a device advertises a
capability for but will not report are still written, from this sheet's values,
because the write is all-or-nothing — the interface says so rather than
promising they are left alone.

#### Finishing a setup

Applying a setup sheet is two exchanges — the configuration, then the clock,
which is written live because a saved epoch comes back arbitrarily wrong — and
they are reported as one result. Apply raises a modal that says what it is doing
and cannot be dismissed while the write is in flight, then resolves in place:

- **success** — a congratulation naming what was set up, a **Save to Peers**
  row, **Review all settings**, and **Set up another device**;
- **success without the clock** — the same, plus a line saying the clock did not
  take, because the device is set up and the retry is one tap away in the
  editor;
- **reported differently** — not a congratulation. It names the field and says
  to read the device again before relying on it; and
- **the write did not land** — the modal goes away and the sheet behind it
  carries the reason, so the operator can correct and retry without dismissing
  anything first.

Save to Peers is offered here rather than before the write, because the device's
advertised role is only certain once it has been set. **Review all settings**
opens the full editor over the same draft. **Set up another device** returns to
the goal chooser, not the scan list, since the next device may be a different
kind of thing.

#### Device identity

A device that exposes its own UMSH identity offers it through the same node
identity screen every other node uses — complete Base58 address, canonical
hint, and shareable QR — not an abbreviated hint on the editor. A device that
exposes no identity says so rather than showing an empty row.

That screen offers **Save Peer**, which records the node locally so it can be
found in Peers afterwards. Saving is local only: nothing is transmitted to the
node, and it is not registered for messaging. This
is the one durable trace a setup session may leave, and only when the user asks
for it.

#### Advertised identity

Role and mobility are separate questions from forwarding. A role left as
**Derive from what it does** lets the device present itself honestly — a
forwarding node advertises as a repeater and anything else as a tracker — and
the editor states the resulting role in place rather than making the user infer
it. An explicit role is advertised verbatim, so a mobile repeater and a
stationary tracker both remain expressible.

The repeater goal chooses to leave the role derived, so what the device says it
is cannot drift from what it does. The tracker goal names the role, because a
tracker that stops moving is still a tracker.

#### Repeater policy

Repeater settings appear only for a device that can forward:

- whether the device forwards other nodes' traffic at all;
- the **routing regions** it relays for;
- which region, if any, is applied to traffic that arrives untagged; and
- minimum signal and quality thresholds below which nothing is relayed.

A routing region is a routing domain, not an RF band plan, and the interface
must never present the two as one choice: a region scopes how far a flood
travels, while frequency and modulation live in the radio profile. Regions are
entered as a three-letter airport code, a region name the local mesh has agreed
on, or a raw code, and are always displayed with that code — `SJC (0x7853)` —
because the code is what appears in a capture or on another node. An empty
region list forwards traffic from every region, which is a different statement
from forwarding nothing; the interface says which one is in effect.

The default-region choice includes an explicit **None — don't tag**, so tagging
untagged traffic is opt-in. Only a region already in the forwarding list can be
chosen, which keeps a device from advertising a region it does not relay.

Adopting a device as this phone's radio is not part of device setup. It belongs
to the companion radio screen, which is the one place that decision is made.

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
3. **Set up a device…** — configuring any other nearby UMSH device, which is a
   separate activity from choosing the radio this phone uses.
4. **Mesh and radio defaults** — regions, routing defaults, named presets, and
   expert controls.
5. **Notifications** and **Privacy**.
6. **Data and diagnostics** — storage, logs, export, and versions.
7. **About UMSH**.

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

The confirmation button names the result: **Message**, **Save Peer**, **Join
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

Conversations, Peers, and Channels use a two-column split when space permits: list or
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
