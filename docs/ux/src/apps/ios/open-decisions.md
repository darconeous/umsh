# Open iOS Product Decisions

These decisions affect security or the durable product model and should be
resolved before implementation. They are intentionally not hidden inside
screen-level design notes.

## Identity continuity and multiple Apple devices

The product direction suggests secure storage that might be shared through
iCloud. Before promising that experience, define:

- whether one UMSH identity may be active on multiple phones/tablets at once;
- how the persistent MAC frame counter remains monotonic across offline devices;
- how per-sender message sequences and local histories merge;
- what happens when two devices attach different radios with the same identity;
- whether ephemeral PFS sessions are device-local; and
- how loss, revocation, transfer, and recovery work without exporting raw
  private key material casually.

Until these are answered, the UX should say the identity is stored securely on
this device. A deliberately authenticated device-to-device transfer is safer to
design than implicit synchronization with undefined concurrency.

## Identity export and restore format

The onboarding restore path and the recovery export depend on the protected
identity export artifact drafted in the protocol specification's Identity
Export Format appendix (`docs/protocol/src/identity-export.md`). The draft
defines the envelope, passphrase key derivation, payload sections, the
counter advance rule, and QR part framing. Remaining product decisions:

- adopt the draft (or amend it) and validate it with cross-platform test
  vectors before any entry becomes visible;
- passphrase UX policy: strength guidance, whether to refuse weak
  passphrases outright, and how the "passphrase is the floor" warning is
  worded;
- which storage destinations the export flow presents (Files, iCloud Drive,
  printed QR) and what the UX says about each location's safety; and
- when and how the app encourages a fresh export after restore, given that
  old artifacts remain valid but stale.

Until the format is adopted and implemented, onboarding and Identity
settings hide the export and restore entries entirely and the UX claims
device-only storage.

## Multiple local identities

The product should eventually support more than one local identity on a
phone, similar to accounts in a mail client, without a disruptive rewrite.
The first release manages exactly one, but its durable schema must scope
identity-owned state (conversations, messages, channel keys, counters, PFS
state, radio provisioning) to an owning identity from the first version.
Before the multi-identity experience ships, decide:

- whether contacts and observed nodes are shared across identities or held
  per identity;
- how switching interacts with the radio, whose provisioned host identity is
  singular — switching likely reuses the host-replacement takeover flow;
- how notifications attribute a message to an identity without leaking
  content;
- whether identities lock and unlock independently; and
- what identity creation looks like when it is no longer part of first-run
  onboarding.

## Contact and identity verification

Decide whether the first release needs a user-facing verification ceremony
beyond comparing complete canonical Base58 addresses or scanning a signed
identity QR in person.
Possible later concepts include **Verified in person**, safety-number changes,
and key-change warnings. None should be represented by the same checkmark used
for a valid signature.

## Default discovery policy

Choose:

- which identity-bearing packets create entries in Recent/Observed;
- retention limits for unknown nodes;
- whether ordinary beacons are requested or sent automatically;
- how often identity metadata refreshes; and
- whether discovery defaults differ in amateur-radio or privacy-sensitive
  profiles.

The default should avoid both an empty, mysterious Network tab and an unbounded
address harvest.

## Active peer-discovery exchange

The current protocol can carry a Node Identity by broadcast/multicast/unicast
and can request identity from an already-known destination. It does not define a
safe broadcast request to which unknown nodes respond. Decide whether the
product needs one beyond bounded listening and explicit identity announcement.

Any new convention must address response implosion, random response delay,
flood scope, rate limiting, privacy/opt-out, amateur-radio behavior, and whether
replies are broadcast, multicast, or learned unicast. The UI should not promise
**Find all nearby peers** until this is specified.

## Routing defaults

Define safe defaults for direct-message discovery floods, regional scoping,
route-cache expiry, and channel hop counts. The UI can hide mechanics only after
the application has a reliable policy. Expert overrides need costs and bounds,
not unexplained numeric fields.

## Public and emergency channel presence

Decide whether `public` and `EMERGENCY` are present but not joined, joined by
default, or offered during onboarding. Emergency traffic has strict validation
rules but the word **emergency** alone must not cause Critical Alerts or other
urgent notification treatment.

## Local outbox policy

Decide whether Send while disconnected:

1. always creates a local waiting item;
2. asks the first time and remembers the choice; or
3. keeps the text as a draft until the radio reconnects.

Also define expiry, ordering across conversations, resume-after-long-gap
behavior, and how pending messages react to identity/radio/channel changes.

## Conversation retention and deletion

Define default local retention, attachment to identity, export, and deletion
behavior. Protocol edits and deletes are messages sent to peers; they cannot
guarantee remote erasure. The confirmation text must not imply otherwise.

## Background operation on iOS

Prototype and measure what the app can reliably do while backgrounded for the
supported companion transports. The UX must distinguish:

- app actively attached;
- radio operating from persisted provisioning;
- radio buffering inbound frames;
- radio acknowledging selected peers; and
- behavior unavailable because the radio lacks full-protocol capabilities.

Avoid a generic **Always connected** switch.

## Notification privacy and urgency

Choose default preview privacy, grouping, muted-channel behavior, sensor alert
policy, and whether any feature justifies requesting Critical Alerts. Ordinary
mesh or emergency-channel traffic should not obtain privileged interruption
without a separate, explicit product policy.

## Generic sensor and CoAP scope

Define the minimum resource discovery and representation supported in version
one. A useful floor is list, current value, units, age, refresh, and raw detail.
Time-series charts and control surfaces require schemas or type knowledge; do
not infer them from arbitrary bytes.

## Room administration

Room admin commands are still unspecified. The app may show room owner/admin
metadata received from a room, but must not design actionable administration
screens until the wire operations and authorization model exist.

## Managed channels

Managed-channel join, key rotation, and administration formats are not yet
defined. The first release should support named and direct-key private channels
without suggesting that individual member removal is available.

## Radio ownership model

The companion protocol allows exactly one provisioned tethered host identity,
while BLE may retain multiple bonds. Decide how the app explains:

- a trusted phone whose identity is not currently provisioned;
- switching between a user's own iPhone and iPad;
- a household-shared radio;
- replacing a lost phone; and
- whether a radio can be marked personal versus shared.

The takeover sheet in the current design is required regardless of the eventual
sharing policy.

## Names and terminology to validate

Test these labels with users:

- **Network** versus **Nodes**;
- **Known node** versus **Recent node**;
- **Radio** versus **Companion radio**;
- **Delivered to node** versus **Received by device**;
- **Private channel** versus **Shared-key channel**; and
- **Waiting for radio** versus **Outbox**.

Prefer the shortest term that remains honest after the user reads its detail
explanation.
