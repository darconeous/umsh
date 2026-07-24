# Text Chat: Ordered Repair, Delivery Reconciliation, Gap Spinners & Fragment Notifications

**Status:** Ready to implement. Written 2026-07-24 for hand-off.
**Scope:** `crates/umsh-text`, `crates/umsh-mobile-core`, `apps/ios/UMSH`, minor `docs/protocol`.
**Applies to:** direct 1:1 conversations (the only text path wired end-to-end to iOS today — see [Scope caveat](#scope-caveat)).

## Problem statement (user-reported)

1. **Out-of-order display.** When the receiver requests resends of sequence IDs it hasn't seen, the backfilled messages arrive and render **at the bottom** of the transcript. Messages must never appear out of sequence order.
2. **Stuck "Not Delivered."** When a previously-missed message is requested, resent, and confirmed, it still shows as "Not Delivered" even though it was delivered.
3. **No gap indication.** When a sequence gap is known, there is no visual cue. We want a **placeholder bubble with a spinner** occupying the gap's position; adjacent spinner bubbles must **collapse into one**. When the missing message (or an edit that fills the slot) arrives, the spinner is replaced/removed. Late-arriving messages should show a **"received late"** status below the bubble.
4. **Fragmented messages never notify.** We want a notification delivered once the **last fragment** is received, **or 30 s after the first fragment**, whichever is sooner.

## Root causes (verified in code)

1. **Late messages land at the bottom.**
   - iOS sorts the transcript by `created_at_ms` (local insert time), *not* wire sequence: `SQLiteApplicationStore.swift:731` (`ORDER BY created_at_ms ASC, rowid ASC`). `created_at_ms` is stamped locally at insert (`SQLiteApplicationStore.swift:980`). There is no sequence field on the UI/stored model.
   - The engine, when a backfilled message finally arrives, allocates a **fresh** `MessageHandle` and emits a brand-new `Insert` "now," carrying `wire_id`/`epoch` but **no positional/ordering hint** (`crates/umsh-text/src/engine/mod.rs:170-187`, single-frame `insert_content` at `mod.rs:1375-1422`, fragmented `publish_slot` at `mod.rs:1236-1373`). So a repaired message is genuinely a new row stamped at arrival time.

2. **Resent messages stay "Not Delivered."** Delivery state exists only for **outbound** messages, reconciled from per-fragment acks (`SQLiteApplicationStore.swift:~590-655`; `acknowledged` when acked-fragment count ≥ `fragment_count`, else `failed`/`sent`/`pending`). When the peer requests a resend, `Engine::archive_result` (`mod.rs:772-808`) re-transmits the stored payload, but the re-transmission's ack is **not** tied back to the original message handle, so the original outbound row stays `failed` = "Not Delivered."

3. **No gap/spinner UI.** There is no placeholder, spinner, or "missing message" bubble in the transcript. `ProgressView` appears only in Settings/RadioPicker, never in `ConversationsView`. Fragment sentinels (`[PENDING]`/`[MISSING]`/`[UNAVAILABLE]`, `crates/umsh-text/src/engine/fragment.rs:446-539`) exist only *inside a single fragmented message's body*, not as transcript rows.

4. **Fragmented messages never notify.** `AppRootView.postNotifications` fires only for mutations where `kind == .insert && complete != false` (`AppRootView.swift:781-793`). A fragmented message arrives as `Insert(complete=false)` then `UpdateBody`; the completing `UpdateBody` is not an insert, so it is silently skipped forever.

## Architecture recap (so the fixes land in the right layer)

Every inbound text message reaches iOS through the Rust engine:

```
Radio → umsh-text Engine → umsh-mobile-core worker → UniFFI → iOS SQLite → SwiftUI
```

- Decoded text-unicast packets are queued at `mobile_mesh.rs:1206-1221` (`node.on_receive`).
- Fed to the engine at `mobile_mesh.rs:1617` (`chat.engine.receive(&envelope, Some(peer), &payload, received_at_ms)`).
- The engine emits an `Output` queue (`mod.rs:322-349`), drained in `mobile_chat.rs:316-377` into UniFFI records (`MobileChatMutationRecord` `mobile_chat.rs:51-83`, `MobileChatDeliveryRecord`, etc.).
- Surfaced to the host via `poll_update()` (`mobile_mesh.rs:924-982`) as `chat_mutations`/`chat_deliveries`.
- iOS consumes it: `AppRootView.applyChatUpdate` (`AppRootView.swift:691`) → `applicationStore.applyChatMutations` → `reloadApplicationState()` rebuilds the `@State` conversations array → SwiftUI re-renders.

**Conclusion:** the engine is the correct place for the ordering/repair/delivery/notify logic; iOS is the presentation layer. No new transport plumbing is needed — only new fields on the existing mutation record.

The engine is a **sans-I/O reducer**: it does not own a transcript. It tracks per-`(conversation, sender)` sequence/dedup/reassembly/repair state and emits idempotent `MessageMutation`s keyed by a stable `MessageHandle(u32)` with an apply-if-newer `revision`. The ordered transcript lives in iOS SQLite, keyed by handle. **Message positioning is the host's responsibility**, driven by what the engine emits.

<a name="scope-caveat"></a>
### Scope caveat

The inbound subscription only accepts `PacketFamily::Unicast` (`mobile_mesh.rs:1208`). Multicast/channel-group text is **not** fed to the engine on iOS yet. The engine's channel-group repair paths (group jitter, 4-byte `Regarding`, blind-unicast repair) are correct but **dormant on iOS** until multicast RX is wired. Keep iOS-facing work focused on direct 1:1 conversations; do not claim channel repair is live on iOS.

---

## The unifying idea: reserve the ordered slot at gap-detection time

Rather than sort the transcript by sequence on iOS (fragile — sequence only orders *within one sender's* stream, and wire IDs wrap at 255), **reserve an ordered slot the moment a gap is detected**, while we are still at the live edge, and **fill that same slot in place** when the real message arrives.

This one mechanism solves problems 1 and 3 together:

- The placeholder row is inserted **now** (correct position — above later messages, below earlier ones) and is what renders the spinner.
- When the missing message arrives, it **reuses the same `MessageHandle`**, so SQLite updates that row in place: it keeps its position and never appears at the bottom.

**Enabler that already exists:** `InboundStream` keeps a `RefRing` mapping `wire_id → MessageHandle` (ring of 16, `sequence.rs:47-85`). Today a handle is registered only when a message actually arrives. The change: **pre-allocate handles for the missing wire IDs at gap-detection time**, register them in the `RefRing`, and emit placeholder mutations. When the real frame arrives, the normal `resolve(wire_id)` finds the pre-allocated handle → emit a fill (reuse handle, newer revision) instead of a fresh insert. Gaps are bounded to 8 (`EngineConfig.max_auto_repair_gap`, `mod.rs:57,79`), well within the 16-entry ring.

**Ordering guarantee:** when the message with `wire_id = baseline + delta` arrives, the missing IDs are `baseline+1 .. baseline+delta-1`. Emit the placeholders **before** the triggering message's Insert in the output queue so their SQLite rowids are smaller and they sort above it (`ORDER BY created_at_ms ASC, rowid ASC`). The filled-in-place message later keeps the placeholder's `created_at_ms`/rowid, so it stays correctly positioned relative to both the earlier peer message and the newer one.

---

## Phase 1 — Engine: reserved gap slots + in-place fill (`crates/umsh-text`)

**Files:** `src/engine/mod.rs`, `src/engine/sequence.rs`, `src/engine/fragment.rs`.

1. **Extend the mutation contract with a presence dimension.** Add a `presence` field to `MutationKind::Insert` (and carry it through updates): `Present | GapPending | Unavailable`. Partial-fragment info already exists via `CompletionStatus::{Complete, Partial{present,count,finalized}}` (`mod.rs:147-157`) and is orthogonal (a `Present` message can still be `Partial`). Reference: `MessageMutation`/`MutationKind` at `mod.rs:159-204`.

2. **Emit placeholders on gap detection.** In `receive_content`'s gap branch (`mod.rs:899-921`, `SerialClass::Newer(delta)` ⇒ `gap = delta-1`): for each missing wire ID within `max_auto_repair_gap`, when sequenced and `!collided`:
   - Allocate a `MessageHandle`, register it in the `RefRing` for that wire ID.
   - Emit `StoreMessage(Insert{ presence: GapPending, direction: Inbound, message_type: Basic, body: empty, wire_id, epoch, sender, conversation, .. })`.
   - Keep the existing `PendingRepair` push, but store the pre-allocated handle on the `PendingRepair` (extend the struct, `sequence.rs`) so the repair machine and the placeholder refer to the same handle.
   - **Emit all placeholders before the triggering message's Insert** (ordering guarantee above).

3. **Fill in place on arrival.** In the receive paths — single-frame `insert_content` (`mod.rs:1375-1422`) and fragmented `publish_slot`/`insert_content` (`mod.rs:1236-1373`) — before allocating a fresh handle, check the `RefRing` for a pre-registered placeholder handle for this wire ID. If found:
   - Reuse it; emit the fill as `Insert` (or `UpdateBody`) with the **same handle**, a **newer `revision`**, `presence: Present`, and a new **`late: true`** flag.
   - Cancel the corresponding `PendingRepair` (existing `cancel_pending`, `sequence.rs:184-194`, already called at `mod.rs:961`) and emit the existing `Event::RepairFinished{ outcome: Repaired }`.

4. **Edit-fills-a-gap.** If the repaired frame at the missing ID is an `Edit` (references an earlier message rather than being a standalone bubble): emit `Delete` for the placeholder handle (spinner disappears) **and** the normal `Edit` mutation for the referenced target. This matches "sometimes the missing message is an edit, which will cause the spinner-bubble to disappear, and that's OK."

5. **Terminal repair states resolve the spinner.** Wire the existing outcomes so a placeholder never spins forever:
   - `Event::RepairFinished{ outcome: Unavailable | Exhausted | Expired }` (`RepairOutcome`, `mod.rs:214-220`) and `Event::MessageUnavailable` (`mod.rs:243-248`, from `receive_unavailable` `mod.rs:1578-1583`) → emit a mutation flipping the placeholder handle to `presence: Unavailable` (spinner → "unavailable"), or `Delete` it. **Decision D3 below** — default: flip to `Unavailable` so the user sees the loss rather than a silently vanishing row.

6. **Tests.** Extend `crates/umsh-text/tests/sim.rs` and `tests/engine_tests.rs`:
   - Drop message N+2 → assert placeholder emitted for N+1 with a stable handle, ordered above N+2.
   - Backfill of N+1 reuses the placeholder handle, `presence: Present`, `late: true`.
   - Edit-fills-gap → `Delete` placeholder + `Edit` target.
   - Exhausted/Unavailable → placeholder flips to `Unavailable`.

## Phase 2 — Engine: reconcile resend delivery to the original message

**File:** `src/engine/mod.rs`.

- In `archive_result` (`mod.rs:772-808`): when re-transmitting a stored outbound payload for a resend request, **track the re-transmission against the original message's handle** (resolve `sequence → original handle` via the outbound stream's refs; see `OutboundStream`, `mod.rs:430-434`). The existing in-flight tracking (`InFlightFrame`, `mod.rs:454-464`; `queue_transmit` `mod.rs:1896-1923`) then produces `Event::DeliveryStateChanged{ handle: original, state: Acked }` when the resend is acked → the sender's row flips from "Not Delivered" to "Delivered."
- Do **not** create a throwaway handle for the resend; the whole point is that the ack updates the original.
- **Tests:** sender's outbound message fails (`Failed`), peer requests resend, resend is acked → assert `DeliveryStateChanged` targets the **original** handle and reaches `Acked`.

> **Decision D1 (confirm):** This fix assumes the reported "Not Delivered" is on the **sender's** side (their outbound message that the peer missed, resent and now acked, but the row stayed failed). This is the only place delivery labels exist (outbound, most-recent — `ConversationsView.swift:832-840`). If instead the *receiver* sees "Not Delivered" on a message it successfully received, that is a different bug — re-scope before implementing Phase 2.

## Phase 3 — Engine: engine-owned notification eligibility

**Files:** `src/engine/mod.rs`, `src/engine/fragment.rs`.

Move the "should the user be notified" decision into the engine — the only layer that knows fragment-completion and timers — and remove iOS's fragile `complete != false` heuristic.

1. Add a **`notify: bool`** flag to inbound mutations (on `Insert`/`UpdateBody`).
2. **Single-frame inbound** → `notify: true` on the Insert.
3. **Fragmented:** track `first_fragment_ms` on the reassembly `Slot` (`fragment.rs:36-63` already has `created_ms`/`last_fragment_ms`; reuse or add). Define `notify_deadline = first_fragment_ms + 30_000`. Emit the `notify: true` mutation on **whichever comes first**:
   - **Completion** — in `publish_slot` when `is_complete()` (`mod.rs:1236-1373`): emit the completing mutation with `notify: true`.
   - **Deadline** — in `tick` (`mod.rs:811`, via `expire_slots` `mod.rs:1590-1599`): if the slot is still incomplete, past `notify_deadline`, and not yet notified, emit an `UpdateBody` of the current partial body with `notify: true` and `CompletionStatus::Partial{..}`.
   - Set a `notified` bit on the slot so it fires exactly once.
4. **Late backfills** (Phase 1 fills): also `notify: true`, so a repaired message still alerts.
5. **Control messages** (ResendRequest, MessageUnavailable — `MessageType::is_control`, `model.rs:41-77`) → never `notify`.
6. **Tests:** fragmented message completing early → one notify at completion; stalled fragmented message → one notify at the 30 s deadline; no double-notify; single-frame → immediate notify; control frames → no notify.

> **Decision D2 (confirm):** This moves notify-eligibility from iOS into the engine (a slightly larger change than patching the Swift heuristic) but fixes single-frame, fragmented, and late-backfill notifications in one place and eliminates the silent-drop at the source. Confirm this ownership move before implementing.

## Phase 4 — Mobile-core FFI records (`crates/umsh-mobile-core`)

**File:** `src/mobile_chat.rs`.

- Extend `MobileChatMutationRecord` (`mobile_chat.rs:51-83`, `#[uniffi::Record]`) with:
  - `presence` (map the engine enum → a new `MobileChatPresence { Present, GapPending, Unavailable }`),
  - `late: bool`,
  - `notify: bool`.
- Map these from the engine `Output` in `drain()` (`mobile_chat.rs:316-377`).
- Regenerate UniFFI bindings (the generated Swift lives at `target/ios-mobile-core/generated/UMSHMobileCore.swift`; follow the existing mobile-core build step — check `Makefile`/scripts, do not hand-edit generated output).
- Keep handle namespacing by `session_id` intact (`mobile_chat.rs:53-58`).

## Phase 5 — iOS persistence & model

**Files:** `apps/ios/UMSH/Services/Persistence/SQLiteApplicationStore.swift`, `apps/ios/UMSH/Models/ConversationModels.swift`, `apps/ios/UMSH/App/AppRootView.swift`.

- **Schema:** add columns to `chat_message` — `presence` (or `is_gap_placeholder` + `is_unavailable`) and `received_late`. Add a migration alongside the existing ones. Insert/update path is at `SQLiteApplicationStore.swift:944-999` (already an upsert-by-handle, so in-place fill works without new logic — the fill mutation reuses the handle → same row id `sessionID:handle`).
- **`StoredChatMessage`** (`SQLiteApplicationStore.swift:41`): add `presence`/`receivedLate`.
- **`ChatMessageSummary`** (`ConversationModels.swift:60`): surface `isGapPlaceholder`, `isUnavailable`, `isReceivedLate`. These are currently dropped when mapping `StoredChatMessage → ChatMessageSummary` at `AppRootView.swift:891-904` — add them there.
- **`failStalePendingMessages`** (`SQLiteApplicationStore.swift:691`, called from `prepareApplicationState` `:814`): must **not** touch gap placeholders. They are inbound and not "stale outbound `pending`," so ensure the query only matches outbound rows (it likely already filters by direction — verify and, if needed, exclude `presence = GapPending`).

## Phase 6 — iOS transcript UI (`apps/ios/UMSH/Features/Conversations/ConversationsView.swift`)

- **Collapse adjacent gaps.** Build a `[TranscriptItem]` (`enum TranscriptItem { case message(ChatMessageSummary); case gap(count: Int) }`) from `conversation.messages`, **merging runs of consecutive `GapPending` placeholders into one `.gap` item**. This guarantees no two adjacent spinner bubbles. Drive the `ForEach` (currently `ForEach(conversation.messages)` at `ConversationsView.swift:356`) off this derived array. Preserve stable `.id`s so SwiftUI diffing stays cheap (e.g. the first placeholder handle in the run for a `.gap`).
- **Gap row.** A bubble containing a `ProgressView` spinner (indeterminate), no body text, no delivery caption. Left-aligned (inbound). Keep it visually distinct from a real bubble but consistent with the design.
- **Unavailable row.** A `presence == Unavailable` placeholder renders as a subtle "message unavailable" bubble (not a spinner). (Depends on D3.)
- **"Received late" caption.** In `ChatMessageBubble` (`ConversationsView.swift:758`), extend the `caption` builder (`:825-840`) to add a **"Received late"** line when `isReceivedLate`, alongside the existing "Edited"/delivery captions (joined with `·`).
- **Scroll behavior.** Keep the existing follow/auto-scroll logic (`ConversationsView.swift:288-428, 578-599`). In-place fill won't yank scroll because the row already exists; only genuinely new rows at the live edge trigger the `.onChange` auto-scroll (`:416`). Verify collapsing/expanding a `.gap` run doesn't fight the follow thresholds.

## Phase 7 — iOS notifications (`apps/ios/UMSH/App/AppRootView.swift`)

- Replace the `complete != false` guard in `postNotifications` (`AppRootView.swift:781-793`) with: **notify on any inbound mutation where `notify == true`** (and non-empty body, non-outbound — keep those existing guards). This covers single-frame, fragmented (complete or 30 s), and late backfills via the single engine signal.
- Keep the foreground-suppression via `VisibleConversationReporter` (`ChatNotificationService.swift:95`, wired at `AppRootView.swift:187-197`) and peer-address threading unchanged.
- Note: since notify can now arrive on an `UpdateBody` (fragment completion/deadline), don't gate on `kind == .insert` anymore.

## Phase 8 — Spec (informative only, no wire change)

**File:** `docs/protocol/src/app-text-messages.md`.

- Add an informative note that repaired messages occupy their sequence slot in **display order** (not arrival order), and that receivers may render a pending-gap placeholder while a repair is outstanding.
- Note the 30 s "first fragment" notification-latency guidance for fragmented messages.
- No bytes change; this is UX/informative text consistent with the existing "Ordering, Gaps, and Automatic Repair" and fragmentation sections.

---

## Open decisions (resolve before/at implementation)

| ID | Decision | Default / recommendation |
|----|----------|--------------------------|
| **D1** | Is the stuck "Not Delivered" the **sender's** outbound row (Phase 2) or something the receiver sees? | Sender-side. Only outbound rows carry delivery labels. Confirm; re-scope Phase 2 if receiver-side. |
| **D2** | Move notify-eligibility into the engine (`notify` flag, Phase 3) vs. patch the iOS heuristic? | Move into engine — fixes all cases at the source. |
| **D3** | When a repair is exhausted/unavailable, does the spinner become an **"unavailable"** bubble or **disappear**? | Become "unavailable" (visible loss). Alternative: delete the row. |

## Build / test commands

- Rust engine: `cargo test -p umsh-text` (unit + `tests/sim.rs`, `tests/engine_tests.rs`, `tests/codec_vectors.rs`).
- Mobile core: `cargo test -p umsh-mobile-core` (facade round-trip `mobile_chat.rs:577-637`; chat sim `mobile_mesh.rs:2203+`).
- Regenerate UniFFI bindings via the existing mobile-core build step before building iOS (check `Makefile`/`scripts/`).
- iOS: build in Xcode against the regenerated `UMSHMobileCore` package.

## Suggested implementation order

1. Phase 1 (engine gap slots + fill) — the keystone; unblocks ordering and spinners.
2. Phase 3 (notify flag) — independent of Phase 1, small.
3. Phase 2 (resend delivery reconciliation) — independent.
4. Phase 4 (FFI records) — after the engine fields exist.
5. Phases 5–7 (iOS) — after FFI regen.
6. Phase 8 (spec) — any time.

Land engine phases with tests green before touching iOS, so the FFI surface is stable when the Swift work starts.
