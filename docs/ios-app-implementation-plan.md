# iOS Application Implementation Plan

This plan turns the UMSH mobile product structure, user stories, and screen
mockups into an implementation sequence. It is an engineering plan, not a
replacement for those product specifications. When this plan and a screen
specification differ about visible behavior, the screen specification and
cross-platform mobile guidelines are authoritative unless the difference has
been explicitly resolved.

The implementation should produce a native Swift application backed by the
existing Rust UMSH implementation. The first release is an off-grid messaging
and network-inspection application, not a general packet laboratory. It must be
useful for direct conversations and channels before advanced management and
diagnostic features are added.

## Product outcome

A release candidate is complete when a user can:

1. create and protect a phone-owned UMSH identity;
2. securely pair and attach a supported companion radio;
3. see the radio connection and battery state in the same compact toolbar
   position throughout the application;
4. import, inspect, save, and share public peer identities using canonical
   UMSH addresses and URIs;
5. discover peers through a bounded, honestly described observation session;
6. exchange direct text messages with accurate send and acknowledgement state;
7. create, join, share, and converse in multicast channels;
8. inspect a peer, set a local mnemonic alias, ping it, and manage a PFS
   session;
9. distinguish people, rooms, sensors, repeaters, and bridges in Network;
10. inspect reported locations in both List and Map presentations; and
11. diagnose connection and protocol failures without exposing secrets by
    default.

Room participation, generic resources, advanced routing, and radio offline
assistance follow the same architecture but may ship after the messaging core
if their protocol and background-behavior dependencies are not ready.

## Non-goals for the first release

The first release should not promise:

- authoritative membership rosters or per-member delivery receipts for
  symmetric multicast channels;
- removal of one channel participant without creating and distributing a new
  key;
- discovery of every nearby or reachable node;
- continuous online presence or reliable distance estimates from RSSI;
- a durable application outbox that defers a user's send until some future
  radio connection or duty-limit window: an eligible send starts immediately,
  while an ineligible send is blocked with an explanation and remains a draft;
- room administration while its commands and authorization model remain
  unspecified;
- arbitrary sensor dashboards inferred from unknown payloads;
- simultaneous multi-device use of one identity until counters and conflict
  behavior are defined;
- managing multiple local identities in the UI, although schema and services
  must be identity-scoped from the start so adding them later is not a
  rewrite;
- identity export or restore, which may be added after the protected export
  format and recovery UX are implemented and tested;
- companion-radio firmware update from the phone, although Radio Detail must
  not preclude adding it later; or
- a custom visual system that imitates one iOS version instead of using current
  platform components.

## Technology decisions

### Application language and UI

Use Swift and SwiftUI for the application. UIKit, MapKit, CoreBluetooth,
UserNotifications, Security/Keychain, and other Apple frameworks remain
available through normal Swift adapters where SwiftUI does not provide the
required system behavior.

Swift owns:

- application and scene lifecycle;
- SwiftUI views, navigation, sheets, menus, alerts, focus, and accessibility;
- CoreBluetooth discovery, connection, pairing, restoration, and GATT I/O;
- system sharing, QR scanning, notifications, MapKit, and permission prompts;
- local application persistence and migrations;
- Keychain access and protected-data availability;
- orchestration, cancellation, background policy, and observable UI state; and
- localization and platform-specific formatting.

The app should use the current SDK's native tab, navigation, toolbar, list,
sheet, map, search, and adaptive-layout behavior. Recheck Apple's Human
Interface Guidelines and the minimum supported SDK before each visual-design
freeze.

### Rust protocol core

Create a purpose-built Rust library crate, provisionally named
`umsh-mobile-core`. It should expose a narrow, versioned mobile API and compose
the existing protocol crates rather than exposing all of their internal types.

Rust owns:

- fixed-width Base58 address encoding and parsing;
- canonical `NodeHint` and router-hint rendering;
- URI parsing, canonicalization, generation, and validation;
- packet construction, parsing, encryption, authentication, and signatures;
- pairwise key derivation and channel-key handling;
- replay windows, frame-counter allocation, and message wire sequences;
- text-message options, fragmentation, and reassembly;
- PFS negotiation and ephemeral-session state;
- companion-link frame encoding, validation, segmentation state, and protocol
  synchronization where it can be shared safely; and
- conversion of valid wire input into typed application events.

The top-level desktop `umsh` crate and its Tokio or desktop Bluetooth features
should not be linked wholesale into iOS. The mobile crate should depend only on
the reusable protocol crates and mobile-appropriate features it needs.

### Swift-to-Rust boundary

Use a short integration spike to choose between UniFFI and a narrow handwritten
C ABI. UniFFI is the preferred starting point because it can generate Swift
bindings now and Kotlin bindings for a later Android application. The spike
must test the selected Swift language mode, errors, callbacks, cancellation,
thread-safety, and binary packaging before the choice becomes architectural
policy.

Keep the boundary coarse-grained and value-oriented:

- pass complete requests, byte buffers, and immutable data-transfer records;
- return explicit results and domain errors, never Rust panics;
- publish a bounded stream or drainable queue of typed core events;
- use opaque session handles rather than exposing Rust object graphs;
- do not call across the boundary for every rendered field or packet byte; and
- do not expose raw pointers, borrowed data, or Rust collection semantics to
  feature code.

Swift should own asynchronous orchestration even when a Rust operation performs
substantial synchronous protocol work. Long-running Rust work must be
cancellable or split into bounded steps. The initial API should avoid relying
on generated cross-language async behavior until its Swift concurrency model is
proven.

```text
SwiftUI views
    ↓ user intent              ↑ observable screen state
Swift feature models and application services
    ↓ typed command            ↑ typed event/result
Swift mobile-core adapter
    ↓ generated binding or C ABI
Rust umsh-mobile-core
    ↓
umsh-core / umsh-crypto / umsh-mac / umsh-node / umsh-text /
umsh-uri / umsh-chat-room / umsh-companion
```

### Binary packaging

Compile the Rust static library for supported iOS device and simulator targets.
Package the slices and generated headers/module metadata as an XCFramework,
then expose that XCFramework through a local Swift package consumed by the app.

The build must be reproducible from the repository and CI. Pin the Rust
toolchain and binding generator, produce deterministic generated bindings, and
fail when generated interface files are stale. Do not require each feature
developer to run an undocumented local script or manually copy a library into
Xcode.

## Architectural boundaries

### Proposed repository structure

The exact names may change during project creation, but responsibilities should
remain visible:

```text
apps/ios/
  UMSH.xcodeproj or UMSH.xcworkspace
  App/                         application entry and dependency assembly
  Features/
    Onboarding/
    Conversations/
    Network/
    Settings/
    ImportShare/
  DesignSystem/                UMSH semantics expressed with native components
  Services/
    Radio/
    MobileCore/
    Persistence/
    Identity/
    Notifications/
    Diagnostics/
  Models/                      Swift application-facing value types
  Tests/
  UITests/

crates/umsh-mobile-core/
  src/                         stable mobile facade and adapters
  tests/                       vectors, lifecycle, and persistence contracts

packages/UMSHMobileCore/
  Package.swift
  generated Swift bindings
  UMSHMobileCore.xcframework

scripts/ios/                   build, package, verify, and update bindings
```

Generated files and binary-artifact policy should be decided with repository
maintainers before landing the project. CI artifacts may be preferable to
committing all compiled slices, while generated source may be committed when it
makes Xcode builds more predictable.

### Dependency direction

Feature views depend on feature models and application protocols. They do not
import generated Rust bindings or CoreBluetooth directly. The radio and
mobile-core adapters implement Swift protocols, allowing previews and tests to
use deterministic fakes.

The mobile core must not call Keychain, SwiftData, CoreBluetooth, MapKit, or
notifications directly. When it needs durable state, time, randomness, or
outbound transport, its facade requests those services through explicit inputs
or adapter callbacks whose ordering and failure behavior are documented.

### Concurrency model

Use Swift actors to define ownership:

- `RadioConnection` owns `CBCentralManager`, the selected peripheral, GATT
  state, negotiated MTU, and transport writes;
- `MeshEngine` serializes calls into the Rust session and drains core events;
- `IdentityVault` serializes protected key access and identity transitions;
- `SendCoordinator` owns active send operations, their ordering, and the
  identity/radio/channel guards checked at send time — there is no durable
  application queue to resume, although the MAC may schedule, back off, and
  retransmit while completing an active send; and
- the persistence layer serializes transactional changes that couple messages,
  counters, and protocol state.

UI-facing feature models run on the main actor and receive immutable snapshots
or events. No view should retain a Rust handle, Bluetooth object, or secret key.

## Identity and secret custody

### Long-term identity

The phone owns the user's long-term UMSH identity. The companion radio does not
receive that private key. In the first implementation:

1. generate the private key using cryptographically secure randomness;
2. store the private key directly as Keychain secret data with
   `kSecAttrSynchronizable` disabled and a `ThisDeviceOnly` accessibility class
   appropriate to the measured foreground and background requirements;
3. load it only after the selected Keychain protection policy permits access;
4. transfer it through one controlled adapter call into the Rust engine;
5. keep cryptographic operations inside Rust while the engine is unlocked; and
6. zeroize replaceable key buffers and tear down the engine when the identity
   locks, changes, or the process ends.

The first release does not add a custom Secure Enclave wrapping construction.
Secure Enclave keys cannot perform UMSH's required Ed25519/X25519 operations,
and direct Keychain storage already provides platform encryption and access
control for secret data. The selected Keychain item must be non-synchronizing
and device-only. No unencrypted private-key bytes may be written to the
application database, files, preferences, logs, backups, or diagnostics. The
key necessarily exists in application memory while Rust performs UMSH
operations; minimize that lifetime and keep it out of ordinary Swift models.

Private keys must never appear in logs, diagnostics, QR codes, pasteboard
items, crash metadata, or SwiftUI state. Public identity sharing uses a
`umsh:n:` URI and clearly labels the result as public information.

### Multiple identities

The first release creates and manages exactly one local identity, but the
architecture must not assume a singleton, so that account-style multiple
identities — as in a mail client — can arrive later without a schema or
service rewrite. Concretely:

- every identity-scoped record — conversations, messages, send attempts,
  channel keys, PFS relationships, counter and replay stores, and radio
  provisioning state — references its owning `LocalIdentity` from the first
  schema version, even while only one row exists;
- counter and replay storage is keyed per identity, never global;
- Keychain items are stored per identity;
- the Rust engine session is constructed for one identity and is torn down
  and rebuilt on identity change rather than mutated in place;
- feature code receives the active identity through its context instead of
  reading a global; and
- radio host provisioning belongs to one identity, so a future identity
  switch is a host-replacement operation on the radio that reuses the
  existing takeover flow rather than inventing a new one.

Only the UI may assume a single identity, and only until the multi-identity
experience is designed.

### Frame counters and replay state

Persistent frame counters are security state, not ordinary preferences. Reuse
the existing MAC counter-persistence contract — an injected storage backend
with reservation blocks whose unused values are skipped rather than
reclaimed — instead of defining a mobile-specific allocation protocol. Other
platforms already depend on that contract, and it must not be reshaped around
iOS. The iOS contribution is a storage implementation with an appropriate
protection class and defined failure behavior.

The existing MAC may construct or queue a frame and schedule a future counter
reservation before that reservation has been flushed. That is safe only while
the frame remains inside the engine: the security requirement is that its
counter is covered by a successfully persisted reservation before the frame is
used on air. The mobile facade must therefore service pending counter
persistence before releasing a not-yet-covered frame to `RadioConnection`.
When protected storage is unavailable or the flush fails, transmission fails
closed; the prepared frame remains internal or is discarded, and the user sees
a storage/preparation failure rather than a radio send. A failed flush does not
roll the counter backward or reclaim its value.

Do **not** eagerly create or advance a counter reservation while loading an
identity or starting the app. This is an intentional flash-longevity invariant,
not an optimization to remove: a device caught in a reboot loop must perform no
counter-store writes if it has not attempted an authenticated transmission.
The first authenticated send after boot is what schedules the reservation; the
mobile facade then flushes it before releasing that prepared frame to the
radio.

Replay windows, identity metadata versions, message sequence-reset state, and
outbound logical-message identity also need explicit persistence contracts.
Tests must simulate termination between every allocation, encryption,
transmission, and commit boundary, and must exercise protected-storage
unavailability at each of them.

### iCloud and multiple devices

Do not enable implicit iCloud Keychain synchronization for the identity in the
first release. A future design must first specify cross-device counter
allocation, simultaneous radio use, message-sequence ownership, conflict
resolution, revocation, and PFS locality. A deliberate device-to-device
transfer flow can be designed separately without making simultaneous use safe.

Direct device-only Keychain storage does not provide a portable identity
backup. A future recovery design can use the separately encrypted
[identity export artifact](protocol/src/identity-export.md), protected by
user-held material and optionally stored in Files or iCloud Drive. Restore is
not a version-one requirement. When implemented, it discards local transmit and
receive counter state, advances the restored outbound counter according to the
export format, and relies on the protocol's authenticated counter
resynchronization when a peer sees the new value outside its window. The user
is warned that the exporting/original installation must stop using the
identity and that the app cannot verify remote erasure; simultaneous use
remains unsupported.

### Channel keys and delegated material

Channel keys are secret membership credentials. Store them with protection
equivalent to the identity key and redact them by default. Reveal and share
only after an explicit user action and disclosure.

Provisioning limited peer/channel material to a full companion radio is a
separate consented operation. The UI must list what is delegated, why, its
limits, and what clearing provisioning removes. The host long-term private key
must never be delegated.

## Radio subsystem

### Layering

CoreBluetooth owns the BLE lifecycle and ATT/GATT operations. The reusable
companion implementation should own companion command encoding, frame
validation, session synchronization, and BLE segment reassembly where doing so
keeps the wire rules in one tested implementation.

The BLE bearer specification already fixes GATT SAR framing owned by the
shared companion implementation, so reassembly belongs to Rust and Swift
shuttles opaque attribute values. The Phase 0 spike verifies that CoreBluetooth
MTU negotiation and write semantics do not force a deviation; it does not
reopen the boundary. One implementation enforces the size, order, timeout, and
reset rules; Swift and Rust must not maintain competing reassembly state.

### Protocol tiers

The companion specification divides capabilities into radio control, the frame
data plane, receive filtering and wake policy, and offline assistance. The
minimal protocol provides the first two, and that is sufficient: the phone
runs the complete MAC over a transparent frame plane. The application must
work against a minimal-protocol radio, with the consequences stated honestly —
reception is promiscuous, nothing is filtered or buffered on the radio,
receiving requires a live BLE link, and battery cost is higher on both sides.

Full-protocol radios add filtering and offline assistance as negotiated
capabilities. When they are present, prefer provisioning the host key and
channel keys/filters over promiscuous reception, and describe radio buffering
or delegated acknowledgement only as measured. No feature may silently require
these capability groups; anything that depends on them must be gated and
labeled by the advertised capabilities.

### Radio state model

Expose one application-level snapshot containing:

- discovered, connecting, pairing, attaching, synchronizing, ready,
  disconnecting, or failed link state;
- radio name and stable local identifier;
- protocol mode and negotiated capabilities;
- authoritative provisioned-host identity;
- battery percentage or unavailable state;
- charging/external-power state when supported;
- age of the battery reading;
- active preset/region and radio enabled state;
- queue/filter/offline-assistance summary; and
- actionable incompatibility or recovery information.

Every screen derives its compact centered toolbar control from this same
snapshot. Connected state shows only link and battery/power symbols visually;
the accessible label contains the complete state. A problem adds the specified
banner below the toolbar and above page content. Feature screens must not build
their own radio-status rows.

### Attachment and host replacement

Treat BLE bonding and UMSH host provisioning as separate state. After a secure
BLE connection, attach, read capabilities and host state, and compare the
radio's authoritative host key with the current phone identity. Never infer a
match from a remembered peripheral alone. A radio without host provisioning is
used as a transparent frame plane under the phone identity and has no host
state to compare. Where host or configuration state does exist, an unexpected
generation change — for example, another client attached in the interim — is a
trust event requiring full resynchronization, not a silent re-sync.

Host replacement requires the takeover confirmation specified in the mockups.
After replacement, synchronize properties from authoritative snapshots, clear
stale inbound/outbound assumptions. There is no durable application queue to
resume; any send in flight during the replacement fails with a reason, and
unconfirmed messages keep the evidence recorded under the identity that sent
them.

### Background behavior

Prototype CoreBluetooth restoration and radio buffering on real devices early.
Document measured behavior for foreground, suspended, terminated, rebooted,
and radio-out-of-range states. The product should describe capabilities such as
radio buffering or delegated acknowledgement individually; it must not expose
an unsupported **Always connected** promise. On a minimal-protocol radio there
is no radio-side buffering at all; disconnected time is honestly offline.

## Application data model

Use durable local identifiers independently of short wire identifiers. A
suggested conceptual model includes:

- `LocalIdentity`: public key, protected-key reference, display metadata,
  creation/version state, and counter-store reference;
- `RadioRecord`: peripheral identity, trust/bond metadata, last capabilities,
  last battery reading, provisioning state, and an optional link to the
  radio-owned `NodeRecord` exposed by the companion protocol;
- `NodeRecord`: complete public key when known, canonical hint, advertised
  metadata and signature state, capabilities, observations, local alias, and
  optional system-managed radio provenance;
- `Observation`: time, source, link/radio metrics, region, reported location,
  and precision;
- `Conversation`: direct, channel, or room kind plus local presentation state;
- `Message`: durable logical ID, wire references, sender/destination, content,
  fragment state, protocol evidence, edits, and timestamps with provenance;
- `SendAttempt`: immutable send context and identity/radio/channel guards for
  one attempt of a logical message; a manual retry creates a new attempt tied
  to the same durable message identity and text-protocol Message Sequence ID,
  while using fresh packet counters for the new transmission;
- `ChannelRecord`: channel-key reference, direct-key/named/special type, local
  name, routing defaults, and notification policy;
- `RoomState`: room node, login state, handle, canonical history cursor, and
  room-provided timestamps;
- `PfsRelationship`: stable peer key, transient lifecycle, accepted expiry,
  and failure reason without persistent ephemeral private material; and
- `ResourceRecord`: node, URI/path, representation, units, observation time,
  and raw value.

Nodes deduplicate by full public key, not display name or `NodeHint`. A hint-only
observation remains provisional and cannot be upgraded to a full peer by name
matching. A local mnemonic alias overrides the advertised name for display but
never overwrites it. Identity-scoped records carry their owning
`LocalIdentity` reference from the first schema version (see Multiple
identities).

When a saved `RadioRecord` exposes a radio-owned public key, upsert exactly one
`NodeRecord` for that key and mark its association as system-managed. It must be
visible through the ordinary Network and Peer Detail surfaces, but ordinary
peer/contact deletion cannot remove it while the radio remains saved. Forgetting
the radio clears the association and protection rather than cascading into
conversation or protocol-evidence deletion. If no durable references remain,
normal storage cleanup may later remove the now-unassociated node. Radios that
do not expose a device identity do not receive a synthetic node.

### Persistence choice

Choose the Apple persistence framework during the foundation spike after
testing migrations, unique constraints, background writes, indexed search, and
transaction boundaries. SwiftData is acceptable only if it can express the
required counter/message transactions and migration tests reliably for the
minimum deployment target. A direct SQLite layer is acceptable if it provides
materially clearer transactional control.

Do not store raw secret bytes in the general application database. Store
Keychain references or stable secret identifiers and resolve them through
`IdentityVault`.

## Mobile-core API shape

The binding design should begin from application operations rather than Rust
module boundaries. Candidate operations include:

- create, unlock, lock, and inspect a local identity;
- render/parse a complete address, node hint, or router hint;
- parse and generate supported UMSH URIs;
- preview an import without mutating application state;
- create/join a channel and derive its identifiers;
- prepare direct, multicast, room, and MAC-command sends;
- ingest one companion frame and return zero or more typed events;
- query or change PFS state for a stable peer;
- construct an echo request and correlate an echo response;
- fragment/reassemble text messages and produce missing-fragment state;
- expose pending counter-persistence work and release only frames covered by a
  durable reservation; and
- acknowledge that a prepared operation was committed, transmitted, failed, or
  cancelled.

Every prepared send should return a stable logical operation ID and the
evidence expected for completion. A frame set may exist internally before its
next reservation flush completes, but the mobile facade must not expose it as
transmit-ready until the persisted boundary covers every frame. This allows
Swift to display one logical message while the protocol may transmit several
frames without turning every preparation into a separate storage write.

Errors should carry a stable machine category, safe user-facing summary key,
and redacted diagnostic detail. Feature code maps categories to localized UI;
Rust error strings are not displayed directly.

## End-to-end event flows

### Receive

1. CoreBluetooth receives a GATT notification or read response.
2. `RadioConnection` validates transport/session generation and forwards the
   segment.
3. The companion layer reassembles and validates one companion frame.
4. `MeshEngine` supplies the contained UMSH frame to the Rust core.
5. Rust performs packet validation, replay checks, authentication, decryption,
   payload parsing, and PFS/control handling.
6. Rust commits replay/security state through its storage contract and returns
   typed events.
7. Persistence commits the resulting application records; duplicate delivery
   after a crash is prevented by durable logical-message identity, not by
   coupling the security store and the application database in one transaction.
8. Feature models receive a database or event update and render it.
9. Notifications are considered only after validation and local policy.

Invalid or unauthenticated input may update redacted diagnostics but must not
create a contact, transcript bubble, urgent notification, or trusted metadata.

### Send

1. A feature model records the user's intent and validates local UI input. If
   a connected, configured radio can accept the message now, activating Send
   starts the send pipeline immediately. Otherwise Send has a visibly blocked
   state; activating it sends nothing, explains the reason, and preserves the
   draft.
2. Persistence creates one optimistic logical message or operation.
3. `SendCoordinator` snapshots identity, destination, channel, and routing
   guards.
4. Rust allocates required wire identifiers/counters through the existing MAC
   persistence contract, encodes, signs or encrypts, fragments if necessary,
   and schedules a future reservation when required.
5. Before a frame not already covered by the persisted boundary can leave the
   engine, the mobile facade flushes the scheduled reservation. If the store is
   unavailable or the flush fails, transmission fails closed; no such frame is
   handed to the radio and used counter values are not reclaimed.
6. `RadioConnection` sends only transmit-ready companion commands/frames and
   reports local transport and radio results.
7. Once submitted, the active send may remain in the MAC's bounded scheduling,
   contention, fragmentation, acknowledgement, and retransmission machinery.
   These operations are part of the send that started immediately; they are
   not an application outbox or a promise to begin transmitting minutes later.
8. The logical item advances through Preparing, Sending, Sent over radio,
   Delivered to node, Accepted by room, Partially sent, or Failed using only
   evidence appropriate to its conversation kind. There is no queued Waiting
   state: a send that cannot complete — the link drops mid-send, the radio
   rejects it, or an error occurs — becomes Failed with a reason, and retry is
   only ever an explicit user action on the failed message. The composer
   prevents a send when current radio duty limits are known to reject it and
   explains when the radio is expected to become eligible; if the radio
   nevertheless returns `STATUS_DUTY_LIMIT`, the attempt becomes Failed with
   that reason and an earliest known retry time.
9. A direct acknowledgement or room echo correlates to the existing optimistic
   item rather than creating a duplicate. Awaiting that evidence after Sent
   over radio is not queueing. If the active send ends without the expected
   evidence, including because the radio disconnects, **Delivery unconfirmed**
   is an effectively terminal result: the UI stops showing progress and does
   not promise that reconnection will resolve it. If valid late evidence does
   arrive, it may upgrade the recorded result without treating the message as
   pending in the meantime.
10. Every outbound chat message includes the text protocol's Message Sequence
   option. Manual Retry re-encodes the same logical message with the same
   Message Sequence ID but allocates fresh packet counters. A receiver that
   already accepted that sender/message-ID pair reconciles the resend instead
   of displaying a second chat message.

### URI import

All camera, paste, file, drag/drop, and universal-link entry points use one
pipeline:

1. acquire raw input;
2. parse and canonicalize locally in Rust;
3. construct a non-mutating typed preview;
4. check signatures, freshness, duplicates, conflicts, and secret meaning;
5. show the type-specific native preview sheet;
6. obtain an explicit named confirmation; and
7. commit exactly one destination record and navigate to the result.

The import screen must contain no unexplained key or decorative key glyph. A
full public key or channel key appears only in a labeled field appropriate to
the decoded type.

## UI composition

### App shell

Implement the three stable destinations—Conversations, Network, and
Settings—with an independent navigation path per tab. Network owns a persistent
List/Map presentation choice; Map is not a fourth tab. Preserve selection,
drafts, filters, and scroll anchors when switching tabs or adapting to iPad
split views.

Build the compact companion control once as app-wide toolbar composition. Every
root and pushed screen uses it in the top centered group. Full-screen system
sheets may cover it when radio state is irrelevant to the decision.

### Shared components

Create semantic components only where UMSH meaning is repeated:

- `PeerAvatar`: deterministic NodeHint circle, monospaced scaled text,
  contrast-selected foreground, accessibility label, optional custom icon, and
  optional PFS outer ring;
- `CompanionToolbarItem`: link and battery/power symbols plus full accessible
  state and Radio Detail action;
- `RadioProblemBanner`: concise failure, last known battery and age, Connect,
  and Details;
- `CanonicalAddressView`: exact 44-character Base58 display, Copy, wrapping,
  and optional comparison mode;
- `HintView`: canonical verified prefix and literal `*` when the full value is
  unknown;
- `ConversationKindLabel`: Direct, Private/Public Channel with Multicast, or
  Room in visible and accessible text;
- `MessageBubble`: incoming/outgoing grouping, sender identity, reply preview,
  edits, fragments, and evidence outside content;
- `DeliveryEvidenceView`: maps protocol facts to the approved honest labels;
- `ImportPreview`: type-specific security meaning, conflicts, and named commit
  action; and
- `ReportedLocationView`: location geometry, precision, provenance, and age.

These are not a custom design system. They compose native typography, controls,
materials, spacing, Dynamic Type, VoiceOver, and SF Symbols.

### NodeHint avatar contract

The Swift UI must never independently derive the displayed avatar characters.
Rust returns the canonical `NodeHint::to_string()` result. Swift receives those
characters and raw three hint bytes, uses the bytes as `#rrggbb`, lays four
characters as two-over-two or the rare three-character form as two-over-one,
and chooses black or white by maximum WCAG contrast. Use the system monospaced
font and scale glyph metrics from the actual avatar diameter. Snapshot-test
small transcript, list, header, detail, notification, and accessibility sizes.

PFS state is a thin solid or broken outer ring plus adjacent visible text. It
must not change the avatar fill or place a badge over the hint characters.

## Feature workstreams

### Foundation and onboarding

- project, targets, signing placeholders, dependency assembly, and CI;
- binding/build spike and mobile-core facade skeleton;
- persistence and migration harness;
- identity creation, direct Keychain custody, protected-data lock
  behavior, and canonical public identity display;
- resumable Welcome, Identity creation, Radio, Preset, and Ready flow per the
  onboarding mockups; future restore UI remains hidden until implemented; and
- native application shell, app-wide radio toolbar placement, Dynamic Type,
  VoiceOver, light/dark mode, and iPhone/iPad navigation tests.

### Companion radio

- BLE permission timing and companion-service scan;
- secure pairing, attach, capability discovery, session generation, and
  synchronization;
- minimal-protocol operation as the working baseline, with filtering,
  provisioning, and offline assistance gated on advertised capabilities;
- battery/power reporting with reading age;
- reconnect without unnecessary pairing;
- host mismatch/takeover; and
- Radio Detail, preset configuration, diagnostics, and distinct destructive
  actions.

### Direct messaging and peers

- node URI scan/paste/open/share, plus canonical Base58 and 32-byte hexadecimal
  public-key paste; all forms canonicalize in Rust before local metadata is
  saved;
- contact and observed-node storage;
- deterministic avatars, mnemonic aliases, and explicitly local node-kind
  classification;
- Message Requests for unknown authenticated senders;
- direct transcript, drafts, immediate send with manual retry, fragmentation,
  reply/reaction/edit, and honest acknowledgement state;
- Peer Detail, QR/share, ping, and PFS lifecycle; and
- system-managed companion-radio peers, protected from ordinary removal while
  their radio remains saved; and
- message and peer search.

### Channels

- create random direct-key channel, import invitation, reveal/share disclosure,
  named-channel canonicalization, and special-channel validation;
- channel rows that visibly state conversation kind;
- channel transcript with multi-sender grouped bubbles and one multicast
  composer;
- **Sent over radio** evidence without group-delivery claims; and
- Channel Detail with key-based membership explanation and recently observed
  participants rather than a roster.

### Network, discovery, and map

- deduplicated node list and capability filters;
- bounded discovery session, streamed results, Stop, and optional identity
  announcement preview;
- general node, sensor/resource, repeater, bridge, and room detail routing;
- List/Map state preservation; and
- reported-location areas, precision, provenance, age, and map empty state.

### Rooms and resources

- room preview, login/logout, handle/password policy, and membership state;
- optimistic send correlated with room echo and canonical message ID;
- bounded history/catch-up and exhaustion behavior;
- generic CoAP resource list/current value/units/age/raw view; and
- write/control confirmation only for explicitly supported representations.

### Notifications, privacy, and diagnostics

- notification classification after authentication and policy;
- preview privacy, channel/room mute, blocked nodes, and permission links;
- storage/retention controls;
- redacted diagnostics preview and export; and
- app, protocol, radio firmware, capability, and migration versions.

## Delivery phases and gates

The phases are dependency order, not calendar estimates. A later workstream may
prototype in parallel, but it does not pass its gate until its prerequisites
are stable.

### Phase 0: decisions and executable spikes

Deliver first, because every workstream depends on them:

- minimum iOS/iPadOS deployment targets and supported device classes;
- UniFFI versus C-ABI decision record;
- device and simulator Rust build packaged as an XCFramework;
- one Swift call that renders reference NodeHints and one Rust error round trip;
- persistence transaction and migration prototype; and
- Keychain protection-class and frame-counter crash-safety design.

Deliver before Phase 2, because they depend on hardware availability rather
than blocking every workstream:

- CoreBluetooth mock transport plus one real-radio attach and battery read; and
- background-behavior measurements on a physical iPhone.

Gate: no feature implementation begins on assumptions that the binding,
counter, radio, or persistence spikes have disproved.

### Phase 1: native shell and secure readiness

Deliver:

- app shell, navigation, iPad adaptation, and centered companion control;
- onboarding through identity and paired-radio readiness;
- Identity and Radio Settings details;
- canonical address/hint and NodeHint avatar components; and
- capability-driven feature flags from the attached radio.

Gate: a fresh install can create an identity, attach a radio, survive relaunch,
and always show truthful connection plus battery state without leaking key
material.

### Phase 2: direct messaging vertical slice

Deliver one complete path before broadening the UI:

```text
scan peer → preview identity → save/message → transcript → compose →
prepare in Rust → send through radio → receive acknowledgement →
Delivered to node → inspect Peer Detail
```

Include disconnection (Send visibly blocked, terminal delivery unconfirmed),
manual retry and receiver deduplication, fragmentation, unknown senders, alias,
ping, and PFS states.

Gate: two physical nodes can exchange test-vector-compatible messages across a
radio link; every displayed state can be traced to stored protocol evidence;
process termination cannot reuse a committed frame counter.

### Phase 3: channels and discovery

Deliver channel creation/import/sharing, channel conversations, named/special
channels, Network list, Peer Discovery, and channel sender-to-peer navigation.

Gate: a channel selection unmistakably opens a multi-sender chat and composer;
one Send produces one multicast logical message; no UI claims a roster or group
delivery; discovery does not promise silent nodes.

### Phase 4: rooms, resources, and map

Deliver room participation, generic resources, role-specific node detail, and
Network Map as dependencies mature.

Gate: room messages reconcile without duplication, history is bounded
honestly, resource values retain provenance/staleness, and coarse locations
render as areas rather than false-precision pins.

### Phase 5: hardening and release

Deliver migrations, restoration, localization readiness, accessibility audit,
privacy manifest/permission copy, diagnostics redaction, performance and energy
measurement, protocol compatibility matrix, security review, and App Store
assets/policy review.

Gate: all release-blocking user stories pass on supported phone/tablet sizes,
real radios and failure conditions; no unresolved security-state migration can
reuse counters or silently change identity.

## Verification strategy

### Rust tests

- existing and new protocol test vectors;
- canonical fixed-width Base58 and ambiguous-hint rendering;
- URI valid/invalid/canonical/conflict cases;
- packet authentication, replay, fragmentation, editing, and Regarding rules;
- PFS request, response, timeout, capacity, expiration, teardown, and reboot;
- companion segmentation, session reset, stale generation, flow control, and
  malformed input; and
- prepared-send crash points and storage-unavailable fail-closed behavior.

Fuzz parsers and reassembly boundaries with arbitrary byte input. A panic or
unbounded allocation from radio or URI input is a release blocker.

### Swift unit and integration tests

- feature models against fake radio, fake mobile core, fake clock, and
  in-memory persistence;
- send-time guards and manual-retry behavior after identity, radio, and
  channel changes;
- active-send MAC scheduling/retransmission without an application outbox, and
  manual resend with the same Message Sequence ID and fresh packet counters;
- persistence uniqueness, migration, transaction rollback, and protected-data
  unavailability;
- delivery-label mapping from evidence, including negative cases;
- radio restoration, host mismatch, stale battery, and capability changes;
- import preview before commit and duplicate/conflict handling; and
- notification policy after authentication and mute/block rules.

### UI, snapshot, and accessibility tests

Exercise every screen in the mockup chapter at:

- smallest supported iPhone, representative standard iPhone, and iPad split
  widths;
- light, dark, increased contrast, and reduced-motion settings;
- large accessibility Dynamic Type sizes;
- VoiceOver traversal and action labels;
- long localized strings and right-to-left layout readiness; and
- connected, disconnected, stale battery, unavailable battery,
  send-unavailable, delivery-unconfirmed, partial, failed, and empty states.

Snapshots are review aids, not substitutes for semantic accessibility tests.
The NodeHint avatar needs pixel-level checks at every supported size because its
monospaced layout and security ring must scale independently.

### Physical and interoperability testing

Maintain a small device matrix covering supported iOS releases, at least one
iPad layout, each supported companion-radio capability level, low battery,
external power, poor BLE conditions, and LoRa loss/duplication/reordering.

For each release, test against Rust/firmware versions at the supported minimum,
current, and capability-mismatch boundaries. Capture evidence for direct
acknowledgements, channel transmission without receipts, room echoes, replay
rejection, PFS reboot termination, radio takeover, and inbound queue recovery.

## Design and review cadence

Implementation does not replace design review. For each workstream:

1. update the textual wireframe and user-story acceptance criteria;
2. build or update an inspectable interactive prototype for the primary path
   and important failures;
3. review iPhone, iPad, large-text, dark-mode, and disconnected states;
4. resolve terminology and safety questions before visual polish;
5. implement the vertical slice with fakes and protocol vectors;
6. test it with a real companion radio; and
7. feed any newly discovered protocol limitation back into the UX docs and
   open-decision list.

The primary path must always be visible in review material. For messaging that
means selecting a conversation, seeing a transcript, composing, sending, and
understanding the result—not only inspecting a setup or detail screen.

## Traceability and definition of done

Every implementation epic should link:

- one or more IDs from
  [iOS User Stories and Flows](ux/src/apps/ios/user-stories.md);
- the relevant screen in
  [iOS Screen Mockups](ux/src/apps/ios/mockups.md);
- protocol sections that define its evidence and limits;
- privacy/security assets it reads or changes;
- supported radio capabilities; and
- automated and physical validation cases.

A feature is done only when:

- its happy path and documented failure paths work;
- visible status is derived from authoritative state;
- secrets are absent from logs and default diagnostics;
- accessibility does not depend on color, glyph, or gesture alone;
- offline/relaunch behavior is defined and tested;
- iPhone and iPad navigation preserve the same product hierarchy;
- protocol incompatibility degrades explicitly; and
- user-story acceptance criteria and mockups match the shipped behavior.

## Decisions required before their dependent phase

The full rationale remains in
[Open iOS Product Decisions](ux/src/apps/ios/open-decisions.md).
The implementation sequence needs these resolution points:

| Decision | Required by | Safe interim behavior |
|---|---|---|
| Keychain accessibility/unlock and device policy | Phase 0 | Device-only, non-synchronizing Keychain item; no cloud escrow or synchronization |
| Crash-safe frame-counter allocation | Phase 0 | Do not send authenticated production traffic |
| UniFFI or C ABI and concurrency contract | Phase 0 | Prototype only |
| Identity export format adoption ([drafted](protocol/src/identity-export.md)) | Future | Create-only onboarding; restore and export entries hidden |
| Minimum OS, database, and migration strategy | Phase 0 | No durable feature schema |
| Direct routing/flood defaults | Phase 2 | Named conservative preset with visible diagnostics |
| Discovery observation/retention policy | Phase 3 | Bounded explicit session; no background address harvest |
| `public` and `EMERGENCY` default presence | Phase 3 | Available to join, not silently joined |
| Supported background/offline-assistance matrix | Phase 3 | Claim foreground behavior only |
| Room administration | After Phase 4 | Read-only owner/admin metadata |
| Generic resource representations | Phase 4 | Current value, units, age, and raw detail only |
| Managed channels | Future | Direct-key and named symmetric channels only |

## Principal risks

### Security-state persistence

Counter reuse, replay-state loss, or an identity/database restore mismatch can
break protocol security. Treat security-state schema and migrations as part of
the cryptographic design and require destructive migration choices to be
explicit.

### Background expectations

iOS scheduling, BLE restoration, and radio buffering can produce behavior that
looks inconsistent if presented as generic connectivity. Base UI labels on
measured capability-specific state and make reading age visible.

### Cross-language complexity

An oversized FFI surface will make Swift concurrency, lifetime, and error
handling fragile. Keep the facade small, test it under Swift concurrency, and
make generated bindings replaceable behind one adapter.

### Protocol evolution

The specification and companion protocol are still evolving. Record protocol
and capability versions with persisted state, negotiate features, preserve
unknown data for diagnostics where safe, and avoid UI controls for operations
whose wire behavior is still undefined.

### Airtime and misleading familiarity

A familiar chat interface can hide LoRa cost and evidence limits. Preserve
familiar composition while showing fragmentation cost, blocked-send and
unconfirmed-delivery state,
conversation kind, multicast audience, and the precise meaning of success.

### Scope pressure

Messaging, rooms, maps, sensors, diagnostics, and radio management can each
become a product. Protect the vertical-slice order: readiness, direct
messaging, channels/discovery, then rooms/resources/map. A broad collection of
incomplete screens is not a usable first release.

## First implementation backlog

The first actionable backlog, after product approval of this plan, is:

1. write architecture decision records for binding technology, key custody,
   counters, persistence, minimum OS, and background support;
2. create the iOS project and reproducible Rust XCFramework build;
3. implement a tiny `umsh-mobile-core` facade for address/NodeHint vectors and
   structured errors;
4. build fake `RadioConnection` and `MeshEngine` protocols for SwiftUI previews;
5. implement the three-tab adaptive shell and centered radio/battery control;
6. build the deterministic avatar and canonical address components from Rust
   reference vectors;
7. prototype direct Keychain identity creation/unlock and crash-safe counter
   reservation;
8. attach to a real companion radio, negotiate capabilities, and read battery;
9. implement the onboarding-to-ready vertical slice; and
10. begin Phase 2 only after the secure-readiness gate passes.

No production UI code should be started until the design artifacts are
approved enough to establish their nouns and primary navigation. Conversely,
the integration and hardware spikes should begin early because their results
may constrain honest UI behavior.
