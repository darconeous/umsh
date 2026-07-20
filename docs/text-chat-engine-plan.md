# Rust Text Chat Engine Plan

## Status

Increments 0–3 are implemented in `crates/umsh-text`.

- Increment 0: the open wire questions are settled in
  `docs/protocol/src/app-text-messages.md` — serial-number ordering with the
  1–127 forward half, an automatic repair bound of 8 messages per gap with
  re-baselining beyond it, conversation-determined `Regarding` width (1-byte
  for all one-to-one conversations including blind-unicast), and 160-byte /
  10-fragment wire maxima with defined receiver behavior for larger counts.
  The spec also records the duplicate-option treatments, lazy reset scoping,
  jittered group repair with multicast cancellation, and ID-reuse retirement.
- Increment 1: the codec is rewritten (`codec.rs`, `model.rs`) with
  `MessageUnavailable`, `Channel Group Resend`, occurrence tracking,
  zero-copy extension-option retention, and a true no-alloc
  no-default-features build; semantic validation and the profile contract
  live in `validate.rs` with `DirectChannelProfile`. Canonical byte vectors
  are in `tests/codec_vectors.rs`.
- Increments 2–3: the sans-I/O reducer is in `engine/` (sequence state,
  page-pool reassembly, partial rendering with sentinels, gap inference,
  jittered bounded repair, and the coalescing resend service), exercised by
  the simulations in `tests/engine_tests.rs`.

Review fixes (2026-07-17), from an independent review of increments 0–3:

- **Oversized fragment bodies** no longer panic the engine — previously a
  >160-byte body truncated its stored `u8` length in release builds and
  could panic the fixed-size read paths (remotely triggerable DoS). The
  spec now states both limits are sender obligations whose excess remains
  syntactically valid, with receiver behavior conditional ("a receiver
  that will not reassemble such a message drops the assembly…"). The
  engine *salvages* instead of dropping: the oversized fragment alone is
  marked unavailable in its slot (`Diagnostic::OversizedFragment`; a
  resend would return the same bytes, so no repair is attempted for it —
  an already-queued repair is cancelled by the normal arrival path), an
  oversized fragment zero still contributes its valid options, every
  storable fragment reassembles normally, and a slot settled by the mark
  finalizes immediately. Over-*count* frames are simply ignored at the
  guard (diagnostic, ID accounted): no slot ever opens for a count above
  10, and the count-mismatch guard protects a coherent valid assembly
  from stray frames with a different count — a later valid-count frame
  for the same ID may legitimately open a fresh assembly. A defensive
  `InsertOutcome::TooLarge` guard remains in the page pool.
- **Sequence Reset on a continuation fragment is ignored** (and reported
  via the ignored-continuation-metadata diagnostic) instead of destroying
  the sender's stream and reassembly state; the spec's "options from the
  first fragment apply to the entire message" rule covers it.
- **Fragment-zero presentation metadata survives reassembly at full
  fidelity**: the announcing Insert mutation always runs during the
  receive call that delivered fragment zero, so the sender handle and
  colors are borrowed from that fragment's validated content — nothing is
  retained (or truncated) in the slot, and `FirstMeta` keeps only what
  later calls consult (type, Regarding, Editing). Extension options are
  *not* yet carried through reassembly — nor by `MutationKind::Insert`
  for unfragmented messages — that plumbing is increment 4/6 scope (room
  Timestamp/Sender Sequence).
- **Absent runs split by repair state**: an unavailable portion renders
  `[UNAVAILABLE]` immediately even when adjacent to still-repairable
  fragments (which stay `[PENDING]`, or `[MISSING]` at final render).
  Alternating states can produce up to one sentinel per absent fragment;
  that chatter is bounded by the fragment count and accepted for honesty.
- **Outbound sequence continuity survives displacement**: restored
  checkpoints and streams evicted from the 8-entry active map are held in
  a 24-entry cold stash and resumed on reactivation, instead of silently
  dropping deep restores and re-announcing Sequence Reset at zero. The
  in-memory continuity bound is therefore 8 active + 24 cold
  conversations, and `restore()` takes checkpoints oldest-first (the
  earliest entries are displaced when over the bound). Beyond the bound
  the stream resets — safe by design; exact continuity for unbounded
  conversation counts is the increment-4 compose-hint below.
- **Persist-before-transmit failure contract documented** on
  `Output::StoreCheckpoint`: on a failed checkpoint write the platform
  must drop the covered transmissions and resynchronize via `restore()`.
  A synchronous acknowledgment API was deliberately not added; the
  increment-4 facade wraps the drain loop and is the right place to
  enforce it.
- **Invalid UTF-8 in a completely reassembled body** is now reported
  (`Diagnostic::ReassembledInvalidUtf8`) alongside the lossy U+FFFD
  render, making the spec's reassembly-time validation observable.

Each fix has a regression test (`tests/engine_tests.rs` review section,
plus pool-level tests in `fragment.rs`).

The direct-message portion of Increment 4 is implemented in the iOS mobile
facade: the Rust worker owns the reducer and MAC path, SQLite gates outbound
transmission on a durable checkpoint/archive commit, typed transcript effects
are replayed until acknowledged, and the SwiftUI transcript sends and receives
real messages. Its current boundary and follow-ups are explicit:

- The facade accepts only `ConversationKey::Direct`. Channel and room
  destinations are not silently reimplemented in Swift; exporting those
  profiles belongs with their later mobile integration.
- Wire references survive restarts (2026-07-20). Outbound: `ComposeRef::Wire
  { message_id, epoch }` lets a restored stream edit/delete a persisted
  original; the engine rejects it (`UnknownOriginal`) when the epoch moved or
  continuity was lost, so a dangling edit is never transmitted. Inbound and
  outbound edit/delete mutations now carry their conversation, and the mobile
  facade exports unresolved references as `(peer_address, original_wire_id,
  original_direction)`; the iOS store resolves them against persisted rows,
  newest `(epoch, created_at)` first, matching serial-ID recycling. Room
  (`RoomCanonical`/claimed-member) references remain out of the direct-message
  facade's scope.
- The optional persisted-checkpoint compose hint is still pending coordination
  with the engine API. Without it, conversations beyond the 8 active + 24 cold
  continuity bound safely announce a Sequence Reset instead of continuing the
  exact persisted stream.
- A failed fragment is sticky in the current SQLite delivery projection.
  Manual retry must define a new attempt/generation before it is added; it must
  not overwrite failure with a late `Sent` event from the old attempt.

Remaining: the Increment 4 follow-ups above, Increment 5 (pager adapter and
capacity measurement), and Increment 6 (chat rooms in `umsh-chat-room`,
including extension-option retention through mutations and reassembly). The
spec is authoritative for wire behavior.

## Decision

Implement the stateful text-message protocol once in Rust and use it from both
mobile applications and embedded pagers. Platform code owns presentation,
platform databases, notifications, and physical transport lifecycle. It does
not encode text-message options, allocate message sequence IDs, fragment text,
infer gaps, construct resend requests, resolve edits, or suppress duplicates.

The implementation should evolve the existing `umsh-text` crate rather than
create a second codec or put text rules directly into `umsh-mobile-core`.

## Goals

- One implementation of the wire codec and stateful protocol rules.
- `no_std` operation with bounded memory for embedded pagers.
- A convenient allocated facade for iOS, desktop, and tests.
- Deterministic behavior that can be tested without a radio, clock, database,
  executor, or Swift runtime.
- Explicit crash and restart behavior for per-conversation, per-sender sequence
  IDs,
  reassembly, resend service, and duplicate suppression.
- Honest delivery state: radio acknowledgement is not presented as proof that
  a human received or read a message.
- Preserve the MAC boundary. Text fragmentation and repair remain application
  protocol behavior; the MAC still carries opaque, single-frame payloads.

## Non-goals

- UI layout, localization, drafts, contact aliases, notification policy, or
  read receipts.
- A universal transcript database schema shared by iOS and every pager.
- Chat-room server behavior from `app-chat-rooms.md` in the first increment.
- Hiding companion GATT lifecycle or radio queue ownership inside `umsh-text`.
- Treating resend repair as reliable delivery. Repair is bounded and
  best-effort.

## Current State

`umsh-text` already provides:

- borrowed `TextMessage` parsing and encoding;
- owned convenience types;
- unicast and multicast node wrappers; and
- basic parse diagnostics.

It does not yet provide:

- semantic validation based on packet class and conversation context;
- outbound sequence allocation or reset epochs;
- fragmentation planning or reassembly;
- message-level duplicate suppression;
- gap detection and bounded resend requests;
- resend archive lookup and `Message Unavailable` responses;
- edit/delete resolution; or
- a platform-neutral stream of transcript mutations and transmit effects.

The crate also uses `alloc::Vec` and `alloc::String` unconditionally despite
advertising a `no_std` shape. That must be corrected before calling the engine
pager-ready.

## Layering

Keep four boundaries inside `umsh-text`:

```text
codec -> semantic validation -> deterministic engine -> platform adapter
```

### 1. Codec

The codec owns exact bytes only:

- option decoding and encoding;
- borrowed wire views;
- fixed-width field validation;
- UTF-8 validation; and
- encoding into caller-provided buffers.

It must work without `alloc`. Allocated owned types are an optional convenience
feature, not the canonical representation.

The codec must not model message type as a closed enum or discard every option
outside the base text range. `app-chat-rooms.md` extends text messages with
message types 32–34 and options 12–13. Decode the base fields into typed views
while retaining a zero-copy iterator over extension options. Encoding likewise
accepts ordered extension options supplied by a validated profile. This keeps
the common text codec reusable without teaching it room membership policy.

Suggested modules:

```text
umsh-text/src/
  codec.rs
  model.rs
  validate.rs
  engine/
    mod.rs
    sequence.rs
    fragment.rs
    repair.rs
    edit.rs
  node_adapter.rs
  alloc.rs
```

### 2. Semantic validation

Syntactically valid options are not necessarily valid in context. Validation
receives a MAC-validated envelope containing:

- local identity;
- source scope — an individually authenticated peer key for unicast and
  blind-unicast, or the claimed full key/source hint authenticated only by
  channel membership for multicast (group members may never learn the claimed
  sender's full key, and repair addressability depends on which form is held);
- packet type;
- direct peer or multicast channel identity;
- receive time and optional link metadata; and
- the borrowed decoded text payload.

It enforces rules such as:

- resend requests are accepted only via unicast or blind-unicast;
- the zero-length `Channel Group Resend` option distinguishes multicast-channel
  repair from direct blind-unicast repair;
- `Regarding` has the correct width for the conversation type;
- resend requests carry the required Message Type and Message Sequence
  fields; duplicate required fields are fatal, while all other extra options
  and any body are ignored rather than fatal;
- generated `Message Unavailable` responses contain only Message Type and the
  requested Message Sequence, while receivers ignore any additional options
  and body after recognizing a valid response;
- fragment index is less than fragment count; and
- non-initial fragments cannot override first-fragment metadata.

Unknown non-critical options remain ignorable. The decoder should retain enough
information to detect duplicate known options and forbidden combinations rather
than silently reducing them into a superficially valid struct.

Every recognized text option is a singleton unless a future specification
explicitly declares otherwise, but duplication is fatal only where it creates
unresolvable ambiguity in how the message is processed. A frame that repeats
an option carrying identity, sequencing, or reference semantics —
`Message Type`, `Message Sequence`, `Regarding`, `Editing`, and profile
extensions in the same role such as `Sender Sequence` — is invalid and is
rejected, even if the repeated values are identical. Repeating a presentation
option such as `Sender Handle` or the colors keeps the first occurrence,
ignores the rest, and emits a diagnostic rather than discarding an
authenticated message. Duplicates of zero-length flags such as
`Sequence Reset` are idempotent. Each profile classifies its recognized
extension options into one of these treatments. Repeated unknown non-critical
options remain ignorable.

Validation is selected by a text profile:

- `DirectChannelProfile` recognizes base text message types and options.
- `RoomClientProfile` additionally recognizes room system message types,
  timestamps, sender-sequence correlation, and room-canonical references.
- A later `RoomServerProfile` validates submissions and constructs distributed
  messages while reusing the same codec, fragment, render, edit, and resend
  machinery.

Profiles are static Rust implementations or explicit reducer modes, not Swift
callbacks and not an unbounded runtime plug-in system.

Keep the crate dependency one-way: `umsh-text` defines the profile contract and
base profile; `umsh-chat-room` depends on `umsh-text` and implements the room
profiles and management actions. `umsh-text` must not depend on
`umsh-chat-room`.

### 3. Deterministic engine

The engine is a sans-I/O reducer. It receives commands and emits effects and
events. It does not call a database, sleep, or transmit directly.

Representative input commands:

```text
Compose { conversation, client_token, intent, payload_budget, now }
Receive { envelope, frame, now }
TransmitUpdate { transmission_id, state, now }
ArchiveLookupResult { request_id, result }
RestoreCheckpoint { checkpoint }
Tick { now }
```

Representative effects:

```text
Transmit { transmission_id, destination, payload, send_policy }
StoreMessage { mutation }
LookupOutbound { request_id, conversation, wire_key, fragment }
StoreCheckpoint { checkpoint }
Diagnostic { code, context }
```

Representative application events:

```text
MessageChanged
MessageEdited
MessageDeleted
MessagePartiallyReassembled
MessageUnavailable
DeliveryStateChanged
RepairStarted
RepairFinished
```

Effects carry stable IDs and may be delivered more than once. Platform storage
must apply message mutations idempotently. This protects application state from
duplicate delivery, but does not add stronger custody semantics to a companion
radio's destructive queue drain.

### 4. Platform adapters

Adapters translate effects; they do not reinterpret protocol rules.

- The node adapter maps `Transmit` effects to `PeerConnection` or
  `BoundChannel` sends and maps MAC-validated `ReceivedPacketRef` values into
  engine envelopes without upgrading channel membership authentication into
  proof of an individual multicast sender.
- The mobile facade exports typed commands, snapshots, and events through
  UniFFI. Swift never sees raw text options.
- A pager adapter feeds effects into its event loop and fixed-size flash/ring
  stores.

## Core Identity Model

Keep three identifiers separate:

1. **Application message ID**: a stable local identifier used by a database or
   UI. It never appears on the wire.
2. **Client token**: supplied by a caller when composing, used to correlate an
   optimistic UI row with the Rust result.
3. **Wire key**: conversation, sender scope, local sequence epoch, 8-bit
   message ID, and optional fragment index. Sequence identity is scoped by both
   conversation and sender. In a multicast channel, the sender scope is the
   claimed on-wire source hint; the channel MIC authenticates channel
   membership, not that hint as a particular person's identity.

Room messages may have two simultaneous wire identities:

- the member's sender-scoped sequence ID used for submission correlation and
  later edits/updates by that member; and
- the room-assigned canonical sequence ID used for distributed ordering and
  room-wide `Regarding` references.

A transcript record therefore stores a set of typed wire aliases rather than a
single `message_id` column. Reconciling a room echo attaches a canonical alias
to the existing optimistic record; it does not replace or discard the sender
alias. Retirement is applied within each alias domain.

The local epoch disambiguates ID wrap and `Sequence Reset`; it is not sent on
the wire. Replies and edits resolve to the most recent unambiguous original
message in the applicable conversation-and-sender epoch.

Conversation keys should be explicit:

```text
Direct { peer_public_key }
ChannelGroup { channel_id }
ChannelDirect { channel_id, peer_public_key }
Room { room_public_key }   // reserved for a later chat-room adapter
```

`ChannelGroup` is ordinary multicast conversation traffic. Replies to a group
message remain group messages and use the multicast `Regarding` form that
includes the original sender prefix. `ChannelDirect` is a one-to-one
blind-unicast conversation authenticated with the channel key; replies remain
blind-unicast to that peer and use the single-destination reference form. The
two cases have separate resend archives and UI conversations even though they
share channel cryptographic material. They also have separate sequence state:
the same sender maintains one stream for the group conversation and another
for its direct conversation with a particular peer.

Do not key protocol state by a Swift SQLite row ID, display alias, node hint, or
companion-radio identifier.

Reference identity is also explicit rather than inferred from an integer:

```text
SenderScoped { sender, sequence_id }
RoomCanonical { room, sequence_id }
```

The selected profile determines which form a one-byte `Regarding` or `Editing`
value denotes and whether translation is required while a room redistributes a
member submission.

## Sequence State

Sequence IDs are scoped to `(conversation, sender)`. Each sender has an
independent outbound sequence in each conversation, and receivers track the
corresponding epoch and active-ID mapping independently for every sender scope
in that conversation. They are not a single conversation-wide counter,
because different senders may use the same numeric ID, and they are not a
sender-global counter shared across conversations.

Rules for the engine:

- Allocate the wire ID before fragmentation; all fragments share it.
- A manual retry of the same logical message reuses its wire ID and content but
  uses fresh MAC frame counters.
- Persist a next-ID checkpoint for each `(local sender, conversation)` stream.
  Commit its advancement before releasing the first fragment of that logical
  message. Do not write merely because the engine booted.
- If a stream checkpoint is unavailable or corrupt, create a new epoch for
  that sender in that conversation and never pretend continuity.
- Reset announcement is lazy and scoped to the affected sender/conversation
  stream. Include `Sequence Reset` on the next message sent in that
  conversation; do not transmit standalone reset messages preemptively to
  previous conversations.
- When an ID is reused after normal wrap, retire the older wire mapping for that
  conversation/sender/ID. The old transcript row may remain visible, but it is
  no longer eligible as the target of a wire reference or resend lookup in
  that stream.
- Use modular serial-number arithmetic. Forward deltas `1...127` are ordered;
  deltas `128...255` are old or ambiguous. Do not generate a large repair storm
  for an ambiguous jump.
- A received reset starts a new epoch and discards cached reassembly and active
  wire mappings for that sender in that conversation, but does not delete
  already displayed transcript history.

The persistent stream-checkpoint adapter may use a wear-leveled journal, but it
must not reserve and silently skip IDs unless the resulting gap semantics are
also specified. A failed send may leave a single unused persisted ID; answering
a repair request for it with `Message Unavailable` is safe.

## Fragmentation and Reassembly

Fragmentation is a two-pass operation because fragment count is encoded in
every fragment and first-fragment option overhead differs from continuation
fragments. For now, a fragment carries at most 160 message-body bytes and a
message has at most 10 fragments, limiting reassembled body data to 1,600
bytes. Messages with bodies of 160 bytes or less are not fragmented unless
their encoded options still make the frame too large.

Rules:

- Split at byte boundaries. Individual fragment bodies are raw bytes and are
  not required to be valid UTF-8.
- Fragment zero carries message-level metadata.
- Continuation fragments carry only sequence/fragment metadata.
- Reassembly is keyed by the full conversation-and-sender-scoped wire key,
  never by the 8-bit ID alone.
- Duplicate fragments are idempotent; conflicting bytes for an already-filled
  slot produce a diagnostic and do not replace authenticated data silently.
- Reassembly has configurable time and memory bounds.
- With every fragment present, concatenate the bytes and validate/decode UTF-8
  only after reassembly.
- On expiry, render a final partial display string and retain a missing-fragment
  bitmap in the message status. Rendering skips any UTF-8 code point split by a missing boundary:
  discard the incomplete suffix before the gap and continuation bytes after the
  gap until the next valid scalar start, inserting the selected missing
  sentinel. The sentinel is part of the rendered projection, not the sender's
  canonical message body.
- Repair requests are rate-limited and bounded. Receiving a fragment must not
  cause unbounded allocations or one transmit per missing fragment.

Reassembly storage is a backend of the common engine. Mobile may use an
allocated backend, while a pager uses one global fixed-capacity pool shared by
all conversations. It is never a 1,600-byte reservation per conversation or
sender. A conversation with no incomplete fragmented message consumes no
variable-byte storage.

For the pager, a small page allocator is likely more efficient than one
160-byte block per fragment because the final fragment and first-fragment
extension data have variable lengths. One candidate is twenty-four 80-byte
pages: 1,920 bytes total. A full 160-byte fragment consumes two pages, while a
short fragment or sender-handle/extension data may consume one. Page linkage
and used-length tables are fixed arrays. A reassembly slot holds only its key,
ten-bit presence bitmap, fragment lengths/page heads, first-fragment metadata,
and deadline.

The page and slot counts are build-time capacity choices. When either is
exhausted, policy evicts or expires the oldest incomplete assembly and emits a
partial rendered message/diagnostic; it never allocates more memory
implicitly. A pager that cannot reserve enough RAM to hold even one
maximum-sized message needs a flash/storage-backed fragment backend or must
document a lower local receive capacity. The 1,600 body bytes plus retained
first-fragment metadata must exist somewhere if the implementation guarantees
reconstruction of a maximum-sized message.

The renderer reads the retained pages and writes one display string into an
allocated mobile `String` or caller-provided pager string buffer; callers do not
need to understand fragment spans. The result is consumed before its fragment
pages are released. Outbound fragmentation borrows the caller's body and
encodes one fragment at a time into a caller-provided frame buffer.

### Incomplete-message lifecycle

All fragments of one message carry the same message ID; the three-byte sequence
form distinguishes them by fragment index. For example, a three-fragment
message followed by one complete message is encoded conceptually as:

```text
message M:   [M, index 0, count 3]
             [M, index 1, count 3]   // lost
             [M, index 2, count 3]
message M+1: [M+1]                   // complete, unfragmented
```

Receiving `M+1` does not finalize, discard, or block message `M`. Reassembly is
keyed by conversation, sender scope, epoch, and message ID. The engine
may emit both a partial rendered-message change for `M` and a complete
rendered-message change for `M+1`.

Keep the UI contract simple: the Rust renderer writes a display string and a
completeness state. While repair remains possible, it inserts a stable sentinel
such as `[PENDING]` at each missing run, skipping UTF-8 code points damaged by
the missing byte boundary. If repair expires or the sender answers
`Message Unavailable`, a later rendering replaces that sentinel with the final
missing/unavailable sentinel. These are rendered projections, not bytes added
to the sender's canonical message body.

The engine does not retain another rendered copy per conversation. It renders
from the shared raw-fragment pool into an allocated `String` in the mobile
facade or a caller-provided/fixed scratch string on the pager. The platform may
store that rendered projection in its transcript row.

The engine owns repair scheduling. Seeing a later message is evidence that the
sender has advanced, but packets may be reordered, so it starts or shortens a
small reorder-grace deadline rather than necessarily transmitting immediately.
In `ChannelGroup` conversations the deadline additionally includes a randomized
jitter interval: every member observes the same loss at nearly
the same moment, and without desynchronization the sender receives a burst of
identical requests before its coalescing window can help. Because repair
responses return via multicast, a member whose jittered deadline has not yet
fired cancels its pending request when the repaired message (or its
`Message Unavailable`) arrives first. The jitter is drawn from randomness
supplied to the engine at construction, keeping the reducer deterministic
under test. On `Tick` after grace and jitter, and subject to repair rate
limits, the engine emits a transmit effect containing the exact resend
request for `[M, index 1, count 3]`. The node adapter selects the path from
the conversation key:

- `Direct`: unicast to the individually authenticated sender.
- `ChannelGroup`: when the claimed source hint resolves unambiguously to an
  addressable peer, blind-unicast the request to that peer and include the
  zero-length `Channel Group Resend` option so it selects its group archive
  rather than its channel-direct archive.
- `ChannelDirect`: blind-unicast to the peer without the `Channel Group Resend`
  option.
- `Room`: unicast to the room node. Room conversations never use multicast;
  repair requests and responses follow the same unicast relationship as other
  room traffic.

A group repair request is never multicast to the channel; in a large public
group that would turn every lost fragment into a packet storm. Blind-unicast
requests are also naturally self-limiting there: addressing a blind unicast
requires the original sender's full public key, and a member that has only
seen the sender's source hint cannot construct the request at all. The engine
therefore checks sender addressability before scheduling repair; when the
sender cannot be addressed, it emits no request and finalizes the partial
render at expiry as it would after exhausted repair.

Platform UI code does not construct or schedule this request.

If the missing fragment later arrives, including as a resend, the engine inserts
it into the existing slot, reconstructs the complete byte stream, and emits a
new rendered string and idempotent mutation for the same stable application
message key with a higher content revision and `Complete` status. If a valid
`Message Unavailable` instead names that fragment, the engine marks only that
portion unavailable and emits an updated partial rendering; the other
fragments remain independently repairable. The database updates the existing
row rather than inserting another message. Mobile publishes the committed row
change to its observable conversation model; a pager replaces the text for the
same row/message handle. Newer displayed messages remain in place throughout
the repair.

## Duplicate and Gap Handling

MAC replay protection and text-message duplicate suppression solve different
problems. A user retry legitimately uses new MAC counters while retaining the
same logical message ID, so the text engine still needs bounded deduplication.

Per `(conversation, sender)` stream, retain enough recent state to distinguish:

- a duplicate complete message;
- a duplicate fragment;
- a forward gap small enough to repair;
- an old message still in the recent window;
- an ambiguous wrap/reset; and
- an edit or reply referencing a recent original.

A forward numeric gap within one `(conversation, sender)` stream means that a
message is missing. After a short reordering grace period, the engine requests
the missing message with the 1-byte form, subject to bounded gap size and
repair rate limits. Repair is per-frame: that request elicits a single frame —
the unfragmented message, or fragment zero of a fragmented one — and any
remaining fragments are then requested individually under the same budgets.
A gap observed in one sender's stream says nothing about another sender in the
same conversation. Missing-fragment repair remains more specific because the
fragment count and index identify the absent portion of a known message.

Do not request whole-message gaps when establishing the first observed
baseline, after a reset, or after an ambiguous jump. Apply per-peer and global
repair budgets to avoid authenticated peers turning a pager into a resend
amplifier.

### Hint collisions

In group conversations the sender scope of a wire key is the source identity
as carried on the wire — often only the 3-byte hint. Two members colliding on
a hint therefore merge into one apparent stream, and inbound group packets
cannot be re-attributed even when the receiver holds both full keys. The
probability is low and no protocol-level fix is attempted. The engine's
obligations are containment:

- When two known peer keys in one conversation share a hint, emit a
  diagnostic so the platform can warn the user — for example, when the second
  colliding peer is added to a room or channel.
- While the collision persists, suppress automatic repair in the merged
  stream. Requesting an ID from either candidate key may legitimately return
  that sender's own message with the same numeric ID and splice the wrong
  sender's bytes into the gap; treat the stream like an ambiguous jump
  instead.
- Reference resolution in a merged stream follows the existing rule: resolve
  only when unambiguous, otherwise retain the unresolved wire reference.
- The Sender Handle may inform display-level disambiguation, but it is
  authenticated by the channel key rather than the sender's key and carries
  no identity weight in protocol state.

## Resend Service

The engine constructs and validates all resend traffic.

When a gap is repairable it emits an archive lookup effect. The platform may
return:

- the exact stored logical message/fragment;
- deleted;
- evicted; or
- unknown.

Archive lookup is scoped to the stream implied by the request's arrival path
and the requester's authenticated identity: a unicast request selects the
`Direct` stream with that peer, a blind-unicast request with the zero-length
`Channel Group Resend` option selects the `ChannelGroup` stream, and one
without it selects the `ChannelDirect` stream with that peer. A requested ID
is never resolved against any other stream; if it does not exist in the
selected stream, the answer is `Message Unavailable`, even when the same
numeric ID exists in another conversation.

A repair response returns on the original conversation's delivery mode, not
the request's arrival path: a `Direct` resend is unicast to the peer, a
`ChannelDirect` resend is blind-unicast to the peer, and a `ChannelGroup`
resend — and its `Message Unavailable` response — is re-multicast to the
channel rather than blind-unicast to the requester. This keeps arrival-path
attribution unambiguous at every receiver, repairs other members missing the
same message as a side effect, and lets ordinary duplicate suppression absorb
the copy at members that already hold it. Because several members may request
the same missing message, the sender coalesces: after resending or answering
unavailable for a wire key, further requests for that key within a rate-limit
window are ignored.

The engine then emits either a correctly addressed resend or a
`Message Unavailable` response. It must preserve the original wire message ID,
fragment metadata, and message-level options. A resend is a new MAC send and
therefore uses fresh security counters.

Archive policy is platform-specific:

- iOS can retain a durable transcript and encoded resend material in SQLite;
- a pager can retain a small recent ring; and
- either may legitimately answer unavailable after eviction.

The protocol engine owns the response decision; the storage adapter only
reports what material exists.

## Edits, Deletes, Replies, and Emotes

The engine emits transcript mutations rather than pre-rendered strings.

- An original message creates a stable application record.
- An edit adds revision data and updates the visible revision.
- An empty edit marks the original deleted without destroying the identity
  needed for later `Message Unavailable` responses.
- Platforms SHOULD retain a stable original-message identity or tombstone for
  as long as they retain sequence history for an edit or deletion. Retaining
  prior revision content, including deleted content, is an optional local
  storage/privacy policy. It can be particularly useful for recovering from a
  forged multicast mutation, since multicast edits and deletes are
  authenticated only by channel membership. A deleted message still answers a
  resend request with `Message Unavailable`.
- An edit cannot target another edit.
- Replies and emotes resolve to an original message identity when unambiguous;
  otherwise the event retains an unresolved wire reference.
- Presentation choices such as edit-history UI, reaction grouping, colors, and
  localized fallback text remain outside the engine.

## Persistence Boundary

Persist only state that changes externally observable protocol behavior:

- outbound sequence checkpoint and reset epoch for each local
  sender/conversation stream;
- resendable outbound message material;
- stable transcript mutations needed by the product; and
- optionally recent inbound cursors/deduplication state.

Reassembly timers, rate-limit buckets, and in-flight transport handles may be
volatile. After restart, losing them results in bounded missed repair rather
than unsafe wire behavior.

The current companion `CMD_QUEUE_DRAIN` is destructive as frames are streamed;
it has no per-entry host commit. `RX_FLAG_ACKED` reports a MAC acknowledgement
already sent by the radio and is unrelated to database persistence. Therefore
the chat engine promises idempotent ingestion, not lossless crash recovery in
the middle of a queue drain. Stronger peek/commit custody would require a
separate companion-protocol design.

## Mobile Integration

Extend the long-lived Rust mobile mesh worker rather than add a Swift text
state machine.

Proposed UniFFI surface:

```text
send_text(conversation, client_token, intent) -> operation_id
apply_archive_result(request_id, result)
acknowledge_event(event_id)
poll_update() -> outbound_frames + chat_effects/events
```

Swift responsibilities:

- provide user intent and drafts;
- commit idempotent transcript mutations to SQLite;
- return archive lookup results;
- map delivery states into honest UI language; and
- acknowledge consumed in-process engine events.

Swift must not choose sequence IDs, split UTF-8, build resend requests, or
resolve edits.

## Chat-room Reuse

`app-chat-rooms.md` is an extension of text messaging, not a parallel message
format. The room implementation should reuse:

- base text option parsing and encoding;
- byte fragmentation and reassembly;
- partial UTF-8 rendering;
- duplicate and gap tracking;
- edits, deletes, replies, emotes, and resend material;
- transcript mutations and stable application IDs; and
- sender-scoped sequence allocation for client submissions.

The room-specific layer owns only what is genuinely different:

- login, logout, fetch, membership, and admin actions;
- the room-wide canonical sequence allocator;
- sender-sequence to canonical-sequence aliasing;
- timestamp and sender-sequence extension options;
- room system message types; and
- packing/unpacking length-prefixed messages in `Room Update`.

`Room Update` decoding should yield bounded slices and feed each embedded text
message through the same room text profile. It must not introduce a second text
decoder. On the server, distribution transforms a validated member submission
into a room-authored message by adding the canonical alias and room extensions;
the original sender alias remains available so later member edits can be
correlated as required by the room protocol.

## Pager Integration

The pager uses the same engine with smaller configured capacities:

- fixed reassembly slots and fragment count;
- a bounded recent-message/resend ring;
- flash checkpoints written only after real message activity;
- UI events copied into fixed-size display models; and
- explicit diagnostics/counters for evictions and suppressed repair.

The no-allocation build should be continuously tested on the pager target or at
least with `cargo check -p umsh-text --no-default-features` plus representative
const capacities.

## Implementation Increments

### Increment 0: settle remaining wire semantics

Before expanding code, update the protocol document to resolve:

- wrap ordering and the ambiguous half-range;
- maximum automatic repair gap;
- which `Regarding` width applies over blind-unicast, where the MAC packet is
  channel-addressed but the conversation has a single logical destination; and
- whether the fragment-count limit of 10 is a wire maximum or a local receive
  capacity, and what a receiver does with a larger advertised count.

Record the settled rules that sequence state is maintained independently per
sender within each conversation, a forward gap in one such stream means a
missing message, old wire mappings retire only in that stream when an ID is
reused, fragments split at byte boundaries, reassembly skips code points
damaged by missing fragment boundaries, the temporary fragment-count limit is
10, the body target is 160 bytes per fragment, reset announcement is lazy
rather than preemptive, repair responses use the original conversation's
delivery mode (a channel-group resend and its `Message Unavailable` are
re-multicast to the channel, never blind-unicast to the requester), group
repair requests are always blind-unicast, carry the zero-length
`Channel Group Resend` selector, and have an empty body, group repair requests
are jittered and canceled when the multicast repair arrives first, room repair
is ordinary unicast without group jitter or cross-member cancellation, each
resend request names exactly one frame and a 1-byte request for a fragmented
message is answered with fragment zero, requests SHOULD NOT carry extra options
but receivers ignore all extras after validating the required fields and group
selector,
`Message Unavailable` accounts for the requested whole-message or fragment
position while only an unavailable fragment changes that portion of a partial
render, and duplicate recognized options are rejected only when they carry identity,
sequencing, or reference semantics while duplicated presentation options are
first-wins with a diagnostic.

Add canonical byte vectors for every message type and invalid combination.

### Increment 1: codec hardening

- Add `MessageUnavailable` to the codec.
- Separate borrowed no-allocation types from allocated conveniences.
- Retain option occurrence information needed for semantic validation.
- Preserve extension message types/options and add direct/channel and room
  validation profiles.
- Add context-aware validation and exhaustive vector tests.
- Make the no-default-features build real.

### Increment 2: sequence and single-frame engine

- Implement conversation keys, epochs, outbound allocation, reset handling,
  logical deduplication, and transcript events.
- Support basic/status messages, replies, emotes, edits, and deletes without
  fragmentation or automatic repair.
- Represent multiple typed wire aliases on one stable transcript message so a
  room echo can reconcile sender and canonical IDs without replacing either.
- Add deterministic reducer tests and randomized state-machine tests.

### Increment 3: fragmentation and bounded repair

- Add the two-pass UTF-8 fragment planner and fixed-capacity reassembly.
- Add gap inference, repair budgets, archive lookup effects, resends, and
  unavailable responses.
- Test loss, duplication, reordering, wrap, reset, expiry, and hostile inputs.

### Increment 4: mobile facade and idempotent ingestion

- Embed the engine in the Rust mobile mesh worker.
- Export typed chat commands/events through UniFFI.
- Add SQLite transcript/archive tables and idempotent event application.
- Enforce the `Output::StoreCheckpoint` failure contract in the facade's
  drain loop: the checkpoint write must complete before any covered
  `Transmit` reaches the radio; on failure, drop those transmissions and
  resynchronize the engine via `restore()`.
- Add an optional persisted-checkpoint hint to compose (platform-supplied
  input, keeping the reducer synchronous and sans-I/O) so conversations
  beyond the 8+24 in-memory continuity bound resume exactly instead of
  resetting; have the facade pass the SQLite checkpoint for the
  conversation being composed to.
- Preserve the current companion queue semantics: queue drain is destructive
  and has no durable host-commit handshake. Treat a stronger peek/commit flow
  as a separate companion-protocol feature if it is designed later.
- Replace the iOS placeholder send button and empty transcript.

### Increment 5: pager adapter

- Select and measure bounded capacities on target hardware.
- Implement flash checkpoint and recent-message ring adapters.
- Integrate compose, receive, repair, and transcript events with the pager UI.
- Measure RAM, flash writes, wake time, and worst-case event-loop latency.

### Increment 6: chat rooms

Build room client/server behavior as profiles and adapters over the stable text
engine. Reuse common fragmentation, repair, edits, rendering, and transcript
mutations. Treat the room service as the sender for room-assigned canonical
IDs in the room conversation, with its own alias domain; do not mix those IDs
into a member sender's stream in that conversation.

## Test Strategy

- Canonical codec vectors shared by all features and bindings.
- Cross-profile vectors proving base messages decode identically inside direct,
  channel, room-live, and room-history delivery.
- Room echo tests proving a sender sequence and canonical sequence attach to one
  application record and retire independently.
- Repair vectors covering all four request paths — direct unicast,
  channel-group with the `Channel Group Resend` option, channel-direct without
  it, and room — plus wrong-stream requests that must answer
  `Message Unavailable`, and response vectors proving channel-group repair
  returns via multicast and is coalesced across multiple requesters.
- Round-trip and malformed-input tests for every option form.
- Property tests for arbitrary bytes: parsing never panics or reads out of
  bounds.
- Deterministic simulations covering duplication, reordering, loss, wrap,
  reset, restart, edit chains, and unavailable archives.
- Multi-member group-loss simulations proving jittered requests desynchronize
  across members, pending requests cancel when the multicast repair arrives
  first, and members without the sender's full public key emit no request and
  finalize a partial render.
- Hint-collision simulations proving a merged stream suppresses automatic
  repair, emits its diagnostic, and leaves references unresolved rather than
  misattributed.
- Pool-pressure simulations with two senders interleaving maximum-size
  fragmented messages, proving eviction stays bounded and every eviction
  emits its partial render and diagnostic.
- Differential tests proving allocated and fixed-capacity facades produce the
  same effects when both have sufficient capacity.
- End-to-end modeled-radio tests with two peers and a multicast channel.
- UniFFI tests proving Swift receives typed mutations rather than raw wire
  fields.
- Embedded size/RAM assertions and no-default-features builds in CI.

## Acceptance Criteria

The architecture is ready for product integration when:

- iOS and a no-allocation test harness use the same reducer and codec;
- no platform code constructs or interprets text-message wire fields;
- all externally visible mutations are idempotent and have stable IDs;
- restart never silently reuses sequence continuity;
- repair is bounded in memory, airtime, and request rate;
- manual retry retains logical identity while every MAC transmission uses fresh
  security counters.
