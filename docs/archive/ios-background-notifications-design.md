# iOS background running and notifications — design

Status: ACCEPTED 2026-07-20 (Keychain migration to
AfterFirstUnlockThisDeviceOnly approved by the user); increments 1–3
implemented the same day, increment 4 (hardware measurement) pending.
Implementation notes at the end. Companion to
`docs/ios-app-implementation-plan.md` (see "Background behavior" and the
Platform entry in the requested-feature backlog).

## Goal and non-goals

Goal: messages received by the connected companion radio reach durable
storage and produce a local notification while the app is backgrounded,
suspended, or has been terminated by the system — for as long as iOS keeps
or restores the BLE link. The product never promises **Always connected**;
every claim in UI copy must map to a measured, capability-specific behavior.

Non-goals for this pass:

- Companion offline-queue drain on reconnect (radio-side buffering while the
  phone is unreachable). That is a companion-protocol feature with its own
  capability gate; this design only keeps the door open for it.
- Remote push. There is no server; everything here is local notifications.
- Background *scanning* UX. We rely on iOS's persistent pending-connect for
  the saved radio; discovery of new radios remains a foreground activity.
- Badge/unread counts. Requires an unread model the store does not have yet;
  follow-up after the first increment ships.

## Facts the design is built on

**The Rust worker is already push-capable.** `MobileMeshSession` runs a
dedicated thread with a current-thread tokio runtime
(`mobile_mesh.rs`, `build()`); MAC ACK timeouts, repair timers, and ping
timeouts fire on that runtime without any help from Swift. The Swift
`pollUpdate` cadence (25 ms bursts during pings, 250 ms steady while chat
consumers exist — `CoreBluetoothRadioConnection.scheduleMeshPump`) exists
only to drain std-mpsc queues: outbound frames, ping/advertisement events,
and the replayed chat batch. Nothing in Rust needs Swift to poll on a clock;
Swift needs to know *when there is something to drain*.

**iOS suspension freezes the worker.** When the app suspends, all threads —
including the Rust worker — stop. tokio timers do not fire late-by-a-little;
they fire whenever the process next runs. With `bluetooth-central`
background mode, the process runs exactly when CoreBluetooth delivers an
event (GATT notification, connect/disconnect), for a short grace window
(~10 s). Additionally, `std::time::Instant` on Darwin counts only awake
time, so deep device sleep stretches every Rust-side deadline further.
Consequence: while suspended, the phone's MAC behaves like a node with a
very slow scheduler — inbound frames are processed promptly (the BLE event
wakes us), but purely timer-driven actions (resend, repair, ping timeout)
run late. That is honest behavior for a phone and is acceptable; it must be
stated in diagnostics copy rather than papered over.

**Locked-phone data protection is currently too strict.** The identity
private key is stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
(`IdentityVault.swift`). A background relaunch via state restoration while
the phone is locked cannot read it, so the mesh session cannot be rebuilt
and restored BLE events would be dropped.

## Design

### 1. Retire the poll cadence: worker wake callback

Add a uniffi callback interface to `umsh-mobile-core`:

```
#[uniffi::export(with_foreign)]
pub trait MobileMeshWakeListener: Send + Sync {
    /// Called at most once per pending-update transition. The listener
    /// must call poll_update() (on its own executor) to drain.
    fn on_update_pending(&self);
}
```

- `MobileMeshSession::set_wake_listener(listener)` stores it; the worker
  signals through a coalescing flag: set on every enqueue to the outbound /
  ping / advertisement / chat channels, cleared by `poll_update()`. At most
  one `on_update_pending` fires per pending→drained cycle, so a burst of
  enqueues costs one FFI crossing.
- The callback runs on the worker thread. The Swift implementation does
  nothing but `bluetoothQueue.async { self.pumpMeshSession() }` (reusing the
  existing `meshPumpScheduled` coalescing).
- `pollUpdate` keeps its exact shape — it stays the single drain point and
  the chat-batch replay contract is untouched.
- MOBILE_API_VERSION bumps.

Swift-side cadence changes in `CoreBluetoothRadioConnection`:

- Delete the 250 ms steady pump and the 25 ms ping burst. All pumps are now
  triggered by (a) the wake callback, (b) inbound BLE data after it is fed
  to the session, and (c) the two bookkeeping timers below.
- Chat-batch retry: the facade replays an unacknowledged batch on every
  `poll_update`, but with no cadence there is no "every". After yielding a
  batch, schedule one coalesced pump at +2 s; if the batch was acked in the
  meantime the pump is a cheap no-op. This replaces the current
  `lastChatBatchYield` age check.
- Keep the existing 8 s sync watchdogs; they are `asyncAfter` one-shots and
  unrelated to the cadence.

Alternative considered and rejected: `pollUpdate` returning a next-wake
deadline (the backlog's original sketch). The worker already owns real
timers; a deadline return would duplicate the scheduler in Swift, and it
cannot cover event-driven wakes (a frame arriving mid-interval must trigger
an immediate drain to transmit the ACK). The callback covers both cases
with less machinery. A returned deadline also keeps GCD timers involved,
which do not fire while suspended anyway.

Foreground win independent of background work: an idle attached app does
zero polls instead of four per second, and ping/chat latency improves
(drain happens immediately instead of at the next tick).

### 2. Background mode and state restoration

- `UIBackgroundModes = [bluetooth-central]` in the merged `Info.plist`.
- Create the `CBCentralManager` with
  `CBCentralManagerOptionRestoreIdentifierKey` (one stable key; single
  central). Implement `centralManager(_:willRestoreState:)`: reclaim the
  restored peripherals, then run the normal saved-radio attach path
  (`attach_existing`, measured 242 ms over BLE — comfortably inside the
  background grace window).
- Ordering hazard: restored delegate events can arrive before the mesh
  session finishes rebuilding. The connection must buffer inbound GATT
  notifications (bounded, newest-wins like the existing streams) until the
  session is attached, then replay in order. Frames lost here are just RF
  loss to the protocol — the MAC/text-engine repair path already covers it —
  so the buffer is an optimization, not a correctness requirement.
- Wrap the wake-triggered work (pump → SQLite apply → notification post →
  batch ack) in a `beginBackgroundTask` assertion so a suspension race
  cannot cut the pipeline between persistence and acknowledgement. The
  facade's replay-until-acked contract makes the worst case a duplicate
  apply, which the store already tolerates, but the assertion keeps the
  common case clean.
- Known platform limits to document (and verify in the measurement pass):
  no relaunch after device reboot until the user first unlocks and iOS
  restores Bluetooth state; restoration does not happen if the user
  force-quits the app from the app switcher (Apple treats that as intent);
  pending connects survive indefinitely but connection latency in
  background is at iOS's discretion.

### 3. Keychain accessibility migration

Move the identity secret to
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. This stays inside the
user-endorsed custody constraints (plain Keychain item, device-only,
non-synchronizing, SEP-rooted via Data Protection) and is the standard
class for apps that must run in background after a lock. The deliberate
trade: the key is readable by the app between first unlock and reboot even
while the screen is locked. Without this change, background relaunch while
locked is impossible and the feature silently degrades to
"foreground-recent only".

Migration: on next successful foreground unlock-time read, re-add the item
with the new accessibility attribute (SecItemUpdate cannot change
accessibility in place for all item classes; delete+add inside one vault
operation, keeping the same account/service identifiers).

SQLite: the store files stay under the default
`NSFileProtectionCompleteUntilFirstUserAuthentication`, which matches the
Keychain class — verify, don't assume, during the measurement pass.

### 4. Local notifications

Trigger point: `AppRootView.applyChatUpdate`, strictly *after*
`applyChatMutations` succeeds and *before* `acknowledgeChatBatch` — i.e.
notifications are only ever posted for messages that reached durable
storage (plan rule: "Notifications are considered only after validation and
local policy"). Classification: notify for mutations that insert a new
inbound message; never for local echoes, delivery-state changes, edits of
already-seen messages, or archive lookups. The store apply already knows
which rows were inserts — surface that (e.g. `applyChatMutations` returns
the inserted inbound message summaries) instead of re-deriving it from the
mutation records.

Policy and content:

- Suppression: no notification for a conversation currently open in a
  foregrounded scene. Implement via `UNUserNotificationCenterDelegate
  .willPresent` (return `[]` for the visible conversation, banner+sound
  otherwise) so the check happens at presentation time, not post time.
- Content: title = display name by the existing precedence (local alias →
  advertised name → star-truncated canonical address); body = message text.
  `threadIdentifier` = conversation ID so iOS groups per conversation.
  Lock-screen content hiding is the OS's job (system preview settings); we
  do not add a redundant app-level "hide previews" toggle in this pass.
- Deep link: `userInfo` carries the conversation ID;
  `didReceive response` routes through the existing `openedConversation`
  binding (same surface the `umsh:` URL routing uses).
- Authorization: request `.alert .sound` on the first successful radio
  attach for an identity — the first moment notifications have a concrete
  meaning — not during onboarding. Denied state is reflected in Settings
  with a link to system settings; we never re-prompt.
- No disconnect/reconnect notifications in this pass. If measurement shows
  iOS drops the link often enough to matter, a default-off "radio link"
  notification toggle is the follow-up, driven by the same honest-labeling
  rule.

### 5. Honest UI

- The radio status control keeps showing measured link state; background
  behavior adds one new user-visible concept: "receiving in background"
  is claimed only while a BLE connection or pending reconnect exists.
- Diagnostics (not headline UI) get a line for the suspension caveat:
  timer-driven protocol actions (repair, resends) run when the phone next
  wakes; peers may see slower acknowledgements from a sleeping phone.
- No change to the send model: sending still requires the app foreground
  with a connected radio; there is still no outbox.

## Measurement checklist (device pass, gates the UI copy)

Per the plan's Background behavior section, measure and record on hardware:

1. Suspended app, phone unlocked: GATT notify → notification latency.
2. Suspended app, phone locked (after first unlock): same path.
3. App terminated by the system (not force-quit): relaunch via
   `willRestoreState`, attach time, end-to-end latency, and whether the
   grace window covers pump→persist→notify→ack.
4. Force-quit: confirm no relaunch (expected), and that the UI never
   claimed otherwise.
5. Reboot: confirm no relaunch before first unlock; behavior after first
   unlock without opening the app.
6. Radio out of range 30+ min then back: pending-connect reconnect latency,
   burst handling of the T-Echo's queued traffic.
7. Battery: overnight attached-idle drain with the callback design vs. the
   old 250 ms cadence (regression guard for the foreground change too).
8. Multi-hour lock: verify Keychain reads and SQLite writes succeed
   throughout (accessibility-class validation).

## Increments

1. **Push pump** (Rust + Swift, testable in simulator): wake-listener
   callback, retire 25/250 ms cadences, 2 s batch-retry one-shot,
   API version bump. Existing e2e Rust tests unaffected; add a facade test
   that the pending flag coalesces and re-arms after drain.
2. **Background mode + restoration + Keychain class**: Info.plist,
   restore-identifier + `willRestoreState` attach path, inbound buffering
   until attached, background task assertion, Keychain migration.
3. **Local notifications**: store returns inserted-inbound summaries,
   authorization flow, post + suppression + deep link.
4. **Measurement pass** on iPhone + T-Echo per the checklist; then write
   the honest-UI copy and update the plan doc's Background behavior section
   with measured numbers.

Increment 1 is worth landing even if 2–4 wait: it removes the standing
foreground poll load and is a prerequisite for everything else.

## Implementation notes (2026-07-20, increments 1–3)

- Wake listener: `MobileMeshWakeListener` + internal `WakeSignal`
  (coalescing `AtomicBool`) + `NotifyingSender` wrappers around all four
  producer channels; `poll_update` re-arms *before* draining so a mid-drain
  enqueue re-notifies. `set_wake_listener` fires immediately when data is
  already pending. One extra seam discovered during implementation:
  `acknowledge_chat_batch` also notifies, because events that queued while
  a batch was outstanding cannot form the next batch until the slot frees —
  with no cadence, nothing else would trigger that drain. API version 25.
  Rust tests cover fire-without-poll, re-arm-after-drain, and
  late-registration.
- Swift retains the yield-once-per-batch gate; redelivery is a one-shot
  pump at +2.1 s scheduled per yield, deliberately bypassing the
  immediate-pump coalescing flag so a parked redelivery can never absorb a
  wake-triggered pump.
- Restoration: the central is created eagerly in `init` when a radio is
  remembered (gated so a first launch cannot prompt for Bluetooth
  permission early); `willRestoreState` adopts the peripheral and defers
  all CoreBluetooth calls to the poweredOn callback; the bootstrap
  `autoConnect` skips when a restored link is pending/connected. Inbound
  frames that arrive before the mesh session installs are buffered
  (bounded 32, oldest dropped) and replayed in `useMeshSession`.
- Notifications: no store change was needed — `MobileChatMutationRecord`
  already carries kind/direction/complete/peerAddress/body, so the app
  classifies inbound inserts directly (kind == insert, direction ==
  inbound, complete != false). Known gap, deliberate: a long fragmented
  message that inserts incomplete and completes via a later `updateBody`
  never notifies; revisit if it matters in practice. Tap routing flows
  through an `AsyncStream` on `ChatNotificationService` consumed by
  `AppRootView` (the delegate cannot capture SwiftUI state directly).
- The background-task assertion wraps `applyChatUpdate`
  (persist → notify → ack) on the app side.
- Standing pending connect (same day, follow-up): the saved-radio
  reconnect's 8 s window is now UI honesty only — on expiry the app
  settles into a new `waitingForRadio` link state and leaves the system
  connection request armed indefinitely, so powering the radio on
  connects (and background-wakes/relaunches the app) with no user action.
  `didFailToConnect` re-arms the request; intentional Disconnect ("Stop
  Waiting") and starting a fresh scan are the two paths that cancel it.
  Cancelling a merely-pending connect produces no delegate callback, so
  `disconnectOnQueue` settles state locally in that case.
