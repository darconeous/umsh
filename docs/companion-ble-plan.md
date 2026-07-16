# Companion Radio BLE Transport — Implementation Plan

*Drafted 2026-07-13. Phase measurements and the license check are
recorded inline as phases complete.*

## Implementation status — 2026-07-15

Phases A, B, C, and the implementation portion of D are now present.
The workspace is on `embassy-nrf` 0.11 / `embassy-sync` 0.8. Trouble
is pinned to `darconeous/trouble@fef9a7a95283be3103e638463a08d355077e2500`,
a single upstream-oriented commit based on audited upstream `78aaf7d`.
That commit contains the pairing-request gate, fixed responder
passkeys, correct negative-LTK replies, and feature-gated redacted
security/connection tracing. Its complete relevant host suite passes
(61 tests). Nordic's
controller/MPSL remain pinned to
`alexmoon/nrf-sdc@abe49d22ebfc85fae134eb082fbfddf752016a55`.

The Phase-0 spike has run on the real T-Echo with the strict 8 s WDT:
SX1262 initialization, MPSL/SDC initialization, advertising, and USB
CDC all complete before the watchdog deadline; USB echo remained live
after a rejected BLE access. Nordic's SDC buffer configuration accepts
at most 251 octets (not Trouble's 255-byte host-pool size), which the
spike established by stage diagnostics. The spike release measured
320,638 bytes text, 4,288 bytes data, and 20,868 bytes BSS before the
final fixed-passkey pin move; its final flash payload was 324,930 bytes.

The production firmware now includes the Companion Link service,
GATT SAR edges, session-generation arbitration, advertising suppression
during a USB session, the pairing gate/static PIN/three-failure lockout,
four-bond + PIN persistence through MPSL-coordinated flash, and the
pairing-mode and bond-wipe policy. The initially implemented 3 s pairing /
10 s BLE-wipe boot gesture was based on a screenless-device interaction
model and has been removed from the T-Echo firmware; the T-Echo must expose
those actions through its display UI. With that UI now linked, its non-debug
release image measures 391,642 bytes text, 6,104 bytes data, and 44,092 bytes
BSS (397,746-byte flash payload) in the 760 KiB application window. On hardware
it completes the USB reset/property
handshake (`umsh-ncp-techo/0.1`, MTU 255), advertises as `UMSH NCP`, and
is visible/connectable in nRF Connect. PIN `123456` was transactionally
committed on hardware; nRF Connect then bonded, enabled the protected
Frame-Out CCCD, wrote complete-SAR `CMD_RST` (`00 81 01`) to Frame In,
and received the exact `RESET_SOFTWARE` notification
(`00 80 06 00 72`). A subsequent clean iOS pairing completed LESC
passkey authentication, received the central's identity address and
IRK, committed the bond to flash, enabled the protected CCCD, and
resumed authenticated encryption without a PIN both after disconnect
and after reflashing/rebooting the identical image. The production
1200-baud CDC recovery path was also verified to enter `TECHOBOOT`.

The hardware trace also found and fixed a Trouble host bug in stale-bond
recovery: on `LE Long Term Key Request` with no matching bond, Trouble
requested an `AuthenticationFailure` disconnect. It now sends the
Bluetooth-defined `LE Long Term Key Request Negative Reply`; the trace
proved the command completed and the disconnect then came from iOS.
iOS retained its asymmetric development bond under an older advertised
name until that entry was manually forgotten, after which clean pairing
and durable reconnect succeeded.

Outside-window rejection is now also verified directly on iOS hardware.
With the store transactionally wiped (`ble-bonds=0`, pairing PIN absent)
and the 30 s window expired, an encrypted-only CCCD subscription caused
iOS to send SMP `Pairing Request` (`0x01`). The fork immediately answered
SMP `Pairing Failed` (`0x05`) with reason `Pairing Not Supported` (`0x05`),
without presenting a PIN UI or enabling notifications. A disconnect and
reconnect then arrived unencrypted with no IRK/table match and no LTK
request, proving the rejected attempt left no stale phone-side bond.

The fixed-PIN failure path and lockout are now hardware-validated. Three
wrong passkeys produced three `ConfirmValueFailed` authentication failures;
the third set `locked=true` and disabled the pairing gate. A subsequent SMP
Pairing Request was rejected immediately with Pairing Failed / Pairing Not
Supported (`0x05`), without another PIN prompt. The continuous serial trace
showed no intervening reset. The 30-minute serial control-plane soak is also
complete; the BLE/live-LoRa long soak remains open. macOS CoreBluetooth now
completes discovery, connection, protected Frame-Out subscription, the
companion reset/property handshake, SX1262 configuration, and live packet
reception. Because CoreBluetooth operations can otherwise block indefinitely,
the host link bounds every `btleplug` stage with an explicit timeout and allows
90 seconds specifically for the OS-mediated protected CCCD subscription and
PIN entry. Still open before declaring the hardware phases complete: the Linux
BlueZ pairing/recovery test and the remaining extended BLE/live-LoRa,
forced-displacement, and storage-fault exercises.

The next validation increment made the two load-bearing pure
policies host-testable. The lockout helper proves that only SMP Confirm Value
Failed and DHKey Check Failed advance the saturating counter, with the third
authentication failure locking pairing. The storage journal tests simulate a
power cut after every byte boundary of both the snapshot-body write and the
four-byte commit write: mount always selects the complete old record until the
new commit word is complete, including across generation wraparound. These
tests cover policy and recovery selection. The real-phone lockout exercise is
now complete; the injected NVMC/MPSL failure test on hardware remains open.
Transport arbitration is now a host-tested pure state machine as well: tests
cover BLE-to-USB displacement, rejection of frames from the displaced
transport, stale-detach immunity, no-session output suppression, advertising
policy, and session-generation wraparound. The USB chunk and BLE segment loops
now share a generation-checked iterator whose test changes the generation
between two writes and proves the remaining writes are suppressed; the forced
mid-frame hardware displacement check remains open. The optional `ble-radio`
host path also has adapter-free tests for configuration bounds, multi-segment
notification reassembly, malformed-segment recovery, and notification-channel
disconnect propagation.

The actual journal body/commit writer is now driven through mockable flash
traits. Fault-injection tests separately fail page erase, record-body write,
and final commit-word write, verify exact page/write bounds and ordering, and
retain the exhaustive byte-boundary recovery coverage above. This proves the
software's failure propagation and old-record selection, while an injected
MPSL/NVMC failure followed by a physical power cycle remains a hardware gate.
The `ble-store-fault-inject` diagnostic feature now supplies that hardware
path: boot-critical local-IRK initialization completes first, then every
runtime record write and page erase fails before touching NVMC while the USB
debug trace reports the fail-closed handling. The feature builds separately
and is never enabled in the production image.

The T-Echo's on-screen BLE menu is implemented and its core interaction has
been validated on hardware. The proven SSD1681 driver has moved into
`umsh-bsp-techo`, with BSP features keeping display-only consumers independent
of the MAC/heap stack. The side button uses the tested T-1000E edge/deadline
recognizer with a T-Echo-specific second hold threshold: single press advances,
double press selects, release after a 1-second hold goes backward, and a
continuing 4-second hold displays `Sleeping` and powers off without first
issuing Back. The touch button retains its board-conventional function as an
active-low, pull-up, **momentary** backlight control: the lamp follows the
physical press state and is not toggled on edges. Clear Bonds defaults to
Cancel and requires a visible choice change plus a second explicit Select.
Differential SSD1681 updates, explicit partial-update power-off, navigation,
sleep, and touch polarity were exercised on the real panel and accepted as a
usable checkpoint. The menu policy and two-stage hold behavior are also covered
by host tests. A final destructive-action pass should still reconfirm Start
Pairing and Clear Bonds end-to-end while the remaining persistence tests run.

Reset diagnostics ruled out slow firmware initialization: instrumented
hardware measured the complete LoRa + MPSL + bond store + SDC + USB path at
62 ms. Auditing Adafruit nRF52 Bootloader 0.6.1 confirmed that its DFU event
loop explicitly detects a watchdog inherited across a software reset and
reloads all eight WDT channels. The supported handoff remains the normal
atomic `GPREGRET=0x57` plus `SYSRESETREQ`; it preserves the strict 8 s
application watchdog without requiring a special hard-reset path. Hardware
validation confirmed that a 1200-baud DTR drop exposes `TECHOBOOT`, the volume
remains mounted beyond the 8 s watchdog deadline, a complete UF2 copy
succeeds, and the application returns with its bond journal intact. The
earlier apparent reboot was not reproduced and does not justify weakening the
watchdog or treating firmware initialization as pathologically slow.

The serial `companion_link_soak` hardware run completed 180/180 property
round trips over 30 minutes without a reset, disconnect, malformed response,
or re-attach. Initial attach took 47,256 us. Property RTT min/average/max was
657/818/1,686 us at a 10 s sample interval. This closes the non-mutating serial
control-plane soak; it does not replace the BLE bearer or live-LoRa traffic
soaks in Phase E.

The new `umsh-capture` tool establishes the requested computer-side live
packet-inspection path without serial/HDLC. It carries the existing
Spinel-inspired companion commands, properties, resets, and asynchronous RX
events over the BLE Companion Link GATT/SAR transport, configures the SX1262,
and prints every received LoRa frame with RF metadata, raw bytes, and attempted
UMSH decoding. A macOS run received 53 real over-the-air frames. That count is
not a queue or protocol limit; the dumper now issues a `PROP_PHY_RSSI` request
after each configurable idle interval. An `idle ... link=ok` line proves the
BLE link, NCP session, and SX1262 runner remain responsive during RF silence,
while a failed probe identifies a real stalled/disconnected path. The README
documents the BLE-only invocation, pairing behavior, RF overrides, and idle
diagnostics.

A subsequent soak received 510 frames before a real transport failure at
approximately 72.5 minutes. The final idle `PROP_PHY_RSSI` transaction
succeeded, but the next probe timed out while writing Frame In, demonstrating
that periodic GATT/RSSI traffic does not keep a broken link alive and that the
failure is below the LoRa receive queue. The diagnostic now captures the
backend's `is_connected` view, performs bounded disconnect cleanup, rediscovers
and reconnects, preserves cumulative counters, and prints the retained NCP boot
status for each new session. A later long-running BLE capture has not reproduced
the failure; it is therefore treated as transient rather than a release gate for
now. The recovery instrumentation remains available to capture evidence if it
recurs.

The Companion Link firmware is now ported to the Seeed SenseCAP T-1000E. The
new `firmware-companion-ncp-t1000e` target shares the proven session,
GATT/SAR, security, persistence, and transport-arbitration implementation with
the T-Echo target while selecting the T-1000E's S140-v7 application origin
(`0x27000`), LR1110 wiring and internal RF-switch table, 16-symbol receive
preamble, active-high LED, battery monitor, buzzer, shutdown sequence, and
button polarity. Its release image measures 376,758 bytes text, 6,104 bytes
data, and 46,860 bytes BSS. The existing runtime button recognizer is retained:
double press toggles buzzer silence, triple press enters UF2 DFU, and a
three-second hold powers off. A short startup press is consumed as the board's
normal wake gesture; remaining held for one second requests the spec's forced
pairing window instead of entering the bootloader.

Hardware validation on macOS confirms that the target advertises the Companion
Link service as `UMSH T-1000E NCP`, accepts a configured passkey, completes the
protected Frame-Out subscription and companion reset/property handshake over
BLE, reports a successful durable commit for the resulting bond, reconnects
without another pairing exchange, and continues reconnecting in the same boot
after the temporary passkey is cleared. Persistence reported success, but
restoration across a T-1000E reboot
remains unverified because further startup testing was deferred. A live
`umsh-capture` session configured the LR1110 at 910.525 MHz / SF7 / BW62.5 kHz /
CR4/5 and completed an idle RSSI health probe over BLE (`link=ok`, -119 dBm).
The USB attach/detach arbitration also behaved as specified; on macOS the
serial client may leave DTR asserted after process exit, in which case an
explicit 115200-baud DTR drop is required before BLE advertising resumes.

The post-DFU first-boot freeze (the "8-second startup beep") is **root-caused
and fixed (2026-07-15)**. The bootloader's DFU USB stack enables the `POWER`
`USBDETECTED`/`USBREMOVED`/`USBPWRRDY` interrupt sources (`INTEN` bits
7–9 = 0x380), and `POWER` lives in the always-on domain, so the enable
survives the activation soft reset into the application. With VBUS present the
corresponding events latch after boot; once MPSL initializes it owns the
shared `CLOCK_POWER` vector but services only CLOCK events, so the pending
POWER USB event re-enters `MPSL_IRQ_CLOCK_Handler` forever at that interrupt
priority. Thread mode and embassy-time starve — the power-on chirp's first
PWM note latches on, heartbeat pets stop — and the 8 s watchdog is the only
thing that survives to reset the device. This is why the freeze required the
BLE image (the `no-ble` diagnostic build never enables that vector and booted
clean over the identical DFU chain), only followed DFU (a normal bootloader
fast-path boot never initializes its USB stack), and was immune to the earlier
pin-silencing/early-heartbeat fix. The fix in the shared firmware main
disarms the inherited `POWER` USB interrupt enables and pending events
immediately after the `RESETREAS` capture, before MPSL takes the vector; it
was verified over repeated 1200-touch → serial-DFU cycles on the T-1000E
(first boot now chirps and attaches immediately). **The T-Echo runs the same
bootloader and MPSL stack and gets the same fix automatically via the shared
main; on it the symptom would have been a silent post-DFU watchdog reboot
(no buzzer), easy to miss.**

Diagnosis evidence and remaining caveats: the freeze was localized with
retained-RAM instrumentation still present in the tree — boot-stage
breadcrumbs and a heartbeat counter, a WDT TIMEOUT-interrupt exception-frame
capture (the nRF52840 fires the WDT interrupt ~61 µs before the reset), and a
1 kHz TIMER2 PC-sampling ring whose contents are dumped as ASCII over the
first DTR-gated USB connect and were symbolized to `MPSL_IRQ_CLOCK_Handler`.
The compact diagnostic `PROP_NCP_VERSION` string currently carries
crumb/beats/RESETREAS/ring fields in place of the SHA and bond count. This
instrumentation is temporary and should be stripped (or feature-gated) before
the next release-quality image. Note also that `RESETREAS.DOG` observed after
a DFU cycle is expected noise: the *previous* image's still-running watchdog
legitimately expires inside the bootloader window between DFU entry and the
transfer, so a post-DFU `RESET_WATCHDOG` boot status alone does not indicate
an application freeze. Forced pairing on the startup-held gesture remains
implemented but hardware-unverified.

## Full-protocol handoff — current position and next work

The BLE transport is no longer the primary implementation blocker. Both the
T-Echo and T-1000E now run the same host-tested NCP session engine over USB and
encrypted BLE GATT/SAR, and a desktop host can configure the PHY, transmit,
receive, capture, reconnect, and inspect the companion frame exchange. What is
working today is the **minimal** companion-radio protocol plus the independently
persisted BLE pairing PIN and `PROP_DEV_NAME`. It remains a raw radio pipe: the
host owns the UMSH MAC and must be attached to receive traffic or generate MAC
acknowledgements.

The normative target for the next development is
[Full Companion Radio Protocol](protocol/src/companion-radio-full.md). The full
protocol keeps the host as MAC owner but adds filtering, detached inbound
queueing, delegated acknowledgements, key provisioning, a device identity, and
explicit saved-state snapshots. These features are not implemented merely by
having a reliable BLE bearer.

### Exact implementation state

* `crates/umsh-companion` currently defines the minimal command grammar,
  minimal properties/capabilities, GATT UUIDs/SAR, HDLC framing, and
  `PROP_DEV_NAME`. It does **not** yet define the full commands, properties,
  capabilities, table item encodings, or full-protocol status codes.
* `crates/umsh-companion-ncp::Session` is the framing-free, host-tested NCP
  engine used by both firmware targets. It currently owns PHY configuration,
  duty tracking, one pending transmit, the device name, and minimal property /
  stream dispatch. It has no host-domain tables, receive filters, detached
  queue, replay state, snapshot, or delegated-ACK scheduler.
* `umsh::companion_radio::CompanionRadio` supplies the desktop host's minimal
  property/radio API over a generic frame link. It can already use serial or
  BLE, but it has no full-protocol provisioning, synchronization, table, queue,
  save, clear, or restore API.
* `firmware/companion-ncp-techo/src/main.rs` is shared by the T-Echo and
  T-1000E packages. It executes `Session` effects and owns the radio, BLE,
  USB, watchdog, board UI, and the BLE bond/PIN journal. That journal is
  transport-security storage, **not** the full protocol's saved snapshot.
* The reusable UMSH implementation already contains packet parsing,
  authentication/key derivation, MAC-ACK construction, and the standard
  `umsh_mac::ReplayWindow`, including the eight-counter duplicate-ACK window.
  Reuse or factor those primitives; do not invent a second replay policy.

One current behavior is incompatible with the full protocol and must be fixed
before advertising any full capability: `Session::attach()` calls the same
reset path used for protocol reset and therefore restores default PHY settings
and disables the radio. Full-protocol attach resets only session state. It
**MUST NOT** change the PHY, device domain, host domain, or queued frames.

### Implementation order

Implement the following increments in order. Keep protocol policy and data
structures in host-testable, `no_std` crates; firmware should remain an I/O and
effect-execution layer. Do not advertise a capability until all behavior it
grants and all prerequisite capabilities are implemented.

#### 1. Full wire vocabulary and host API foundation

Extend `crates/umsh-companion` with:

* `CMD_PROP_INSERT`, `CMD_PROP_REMOVE`, `CMD_PROP_INSERTED`, and
  `CMD_PROP_REMOVED` (4, 5, 7, and 8);
* `CMD_QUEUE_DRAIN`, `CMD_SAVE`, `CMD_CLEAR`, and `CMD_RESTORE` (11–14) —
  all four carry no payload (spec amended 2026-07-15: `CMD_QUEUE_DRAIN` no
  longer takes a stream key; it drains the sole `STR_PHY_RAW` inbound
  queue). Note `CMD_CLEAR` is base-protocol, not gated on `CAP_SAVE`: until
  increment 6 lands it must succeed trivially (nothing persisted), never
  fail `STATUS_UNIMPLEMENTED`;
* `STATUS_ALREADY`, `STATUS_ITEM_NOT_FOUND`, and
  `STATUS_RESET_RESTORED`;
* every full property and capability identifier; and
* parsers/encoders for fixed and length-prefixed multi-value items, preserving
  the distinction between secret-bearing item forms and non-secret digest
  forms.

Extend `CompanionRadio` with correlated command helpers and response handling
for insert/remove, queue drain, save/clear/restore, and unsolicited
`PROP_IS`/`PROP_INSERTED`/`PROP_REMOVED` updates. Tests must cover malformed
PUIs, truncated items, invalid TIDs, unknown commands, and secret-free digest
responses. This increment must not change advertised capabilities yet.

#### 2. Split session, device, and host state

Refactor `Session` around the state classes in the full specification:

* session state: attachment and `PROP_MAC_PROMISCUOUS`;
* device domain: PHY configuration, duty limit, device name, device identity
  tables, and transport configuration references; and
* host domain: host key, host channel/peer keys, filters, auto-ACK policy, and
  inbound queue.

Add explicit attach and detach transitions. Attach clears only session state;
detach preserves device/host state and begins autonomous operation. A protocol
`CMD_RST` restores the applicable post-reset values, which will later come from
the saved snapshot when one exists. Host replacement must be represented as a
single validate-before-mutate operation and must expose a deferred durable-wipe
effect before the new host becomes active.

Acceptance gate: host tests prove that attach leaves an enabled/configured PHY,
the device name, host provisioning, and queued data unchanged, while resetting
promiscuous mode. No firmware/hardware interaction is required for this gate.

#### 3. `CAP_HOST_FILTER` vertical slice

Implement `PROP_MAC_PROMISCUOUS`, `PROP_HOST_KEY`, and
`PROP_HOST_RX_FILTERS`, including whole-table set and individual
insert/remove. Evaluate received frames against explicit filters plus the
implicit host destination hint and provisioned host channel identifiers.
Preserve the compatibility rule: with no host key, channel keys, or explicit
filters, every valid received frame is accepted just as it is today.

The host-domain replacement path must atomically clear filters, keys, auto-ACK
policy, and the queue. Until full persistence exists, use a mock durable-wipe
effect in tests. Note the durable-wipe requirement only applies to saved
host-domain state: before `CAP_SAVE` exists there is none, the wipe is
trivially satisfied, and advertising `CAP_HOST_FILTER` is spec-clean.

Acceptance gate: table-atomicity tests, filter tests for every filter type,
implicit-filter tests, promiscuous-live-delivery tests, factory-compatibility
tests, and host-replacement rollback tests all pass.

#### 4. `CAP_HOST_RX_QUEUE`

Add a fixed-capacity circular RAM queue containing the radio frame, receive
metadata, receive timestamp, and whether delegated acknowledgement succeeded.
While attached, accepted traffic is delivered live. While detached, accepted
traffic is queued. Implement the queue count/capacity/dropped properties,
buffered `RX_FLAGS`/`RX_AGE`, and `CMD_QUEUE_DRAIN`.

A drain covers exactly the frames queued when the command is received.
Because accepted traffic is always delivered live while a host is attached,
the queue cannot grow mid-drain: emit the covered frames oldest-first, then
the correlated completion response immediately after the last one. Live
arrivals during the drain interleave with the buffered deliveries
(`RX_FLAG_BUFFERED` distinguishes them); UMSH does not promise total
ordering. The spec's `CMD_QUEUE_DRAIN` section was amended 2026-07-15 to
this live-interleave model — it previously required mid-drain arrivals to
be appended and delivered buffered after the response.

Use the standard authenticated replay/MIC identity to coalesce duplicates and
Route Retry forms where keys are available. Unauthenticated frames have no
protocol-defined deduplication and occupy separate entries.

Acceptance gate: detached receive -> attach -> count -> drain works entirely in
host tests; overflow evicts the oldest entry and increments the dropped count;
drain-tail liveness, metadata age/flags, live-arrival interleaving, duplicate
coalescing, and reset/host-replacement behavior are covered.

#### 5. `CAP_HOST_KEYS` and `CAP_HOST_AUTO_ACK`

Implement host channel-key and peer-key tables with strict validate-before-
mutate semantics. `CMD_PROP_INSERT` into `PROP_HOST_PEER_KEYS` with a
`PEER_PUBLIC_KEY` matching an existing entry replaces that entry's key
material only — the peer's replay baseline and queued frames are untouched
(both are keyed by the peer's identity, per the spec's 2026-07-15
clarification). Symmetric keys are accepted only over an authorized secure
transport and are never returned: gets and mutation notifications use digest
forms. The session dispatch API therefore needs explicit transport-security
context rather than inferring safety from BLE-specific globals.

For detached acknowledgement delegation, reuse the core UMSH packet crypto,
MAC-ACK construction, and standard replay window. Advance a peer baseline only
after the frame is stored. A duplicate may be re-ACKed only when it authenticates
and falls within the core eight-counter window, without changing the baseline
or adding another queue entry. ACK transmission uses the ordinary serialized
radio path and duty limiter; a frame not stored or an ACK prohibited by duty
limits remains unacknowledged.

Acceptance gate: normative packet vectors cover UNAR and BUAR success, missing
keys, ambiguous source hints, bad MICs, first-contact/reboot baseline behavior,
duplicates inside and outside the re-ACK window, queue-store failure, duty-limit
failure, attached suppression, and buffered `RX_FLAG_ACKED` reporting.

#### 6. `CAP_SAVE` and durable state boundaries

Design a full-protocol snapshot journal separately from the BLE bond/PIN
journal and allocate its flash region explicitly for both boards. Implement
`CMD_SAVE`, `CMD_RESTORE`, `CMD_CLEAR`, `PROP_SAVED`, and boot restoration before
the first host command. The snapshot contains device and host domains, including
the saved PHY-enabled state, but excludes queue contents, replay baselines, and
the independently persisted device identity. The BLE PIN and BLE bonds remain
governed by their existing independent storage rules.

All durable operations must commit before reporting success. A failed save,
clear, restore, identity write, or host replacement leaves both live and durable
old state intact and emits no partial property notifications. Reuse the existing
mock-flash and byte-boundary power-cut testing approach.

Acceptance gate: exhaustive cut-point tests always mount either the complete old
snapshot or complete new snapshot; boot restores and applies the PHY before host
commands; restore has identical rollback semantics in both permitted reporting
forms and preserves queue contents and replay baselines except when the
snapshot's host key differs (host replacement then applies as part of the
revert); clear plus reset produces factory protocol state without altering BLE
bonds or the pairing PIN.

#### 7. `CAP_DEV_IDENTITY`

Implement on-device identity generation and private-key installation,
`PROP_DEV_KEY`, device channel keys, and device peers. Persist the device
identity immediately and independently of snapshots; it changes only through
explicit provisioning or `CMD_CLEAR`, and `CMD_RESTORE` can never resurrect an
older identity. Private and symmetric keys are write-only and subject to the
same secure-transport gate as host key tables.

The current full protocol defines provisioning and identity ownership but does
not yet require repeater or autonomous application behavior for the device
identity. Do not expand this increment into those deferred behaviors.

#### 8. Provisioning/synchronization workflow and integration tests

Add a host-facing provisioning/diagnostic workflow that:

1. reads `PROP_CAPS` and last status;
2. verifies `PROP_HOST_KEY` before treating queued data as its own;
3. reconciles device/host properties and key-table digests;
4. provisions changes transactionally and explicitly saves them; and
5. reads queue count and drains only when the host is ready.

Exercise this against an adapter-free simulated NCP before hardware. Include
capture/log output for every full-protocol command and unsolicited update so a
hardware failure can be placed at the host API, framing, session, storage, or
radio boundary.

#### 9. Full-protocol hardware completion

Validate first on one board, then repeat storage-layout and board-specific
checks on the other. Provision a host identity, filters, channels, peer keys,
auto-ACK, PHY configuration, and saved state; detach the host; receive relevant
traffic and reject unrelated traffic; transmit delegated ACKs; power-cycle with
no host; reconnect; synchronize; and drain the queue. Exercise duplicate
coalescing/re-ACK, overflow, storage failure, host replacement, and BLE/USB
displacement. Record capability lists, flash/RAM sizes, attach/RTT measurements,
queue capacity, and soak results here.

The full-protocol milestone is complete only when a saved configuration boots
into detached autonomous filtering/queueing/ACK operation, and a returning host
can safely identify ownership, reconcile state, and drain buffered traffic on
both firmware targets.

### Increments 1 and 2 — complete (2026-07-15)

The full wire vocabulary is in `crates/umsh-companion`: commands 4/5/7/8 and
11–14, the full property and capability identifiers, the `items` module
(peer-key entries with secret-free digest/Debug forms, filter entries for all
three types, fixed-size and PUI-length-prefixed table iterators), and the
`BufferedRxMeta` `RX_FLAGS`/`RX_AGE` extension with field-boundary truncation
tests. Two spec amendments landed the decided simplifications:
`CMD_QUEUE_DRAIN` carries no stream key (payload ignored; it drains the sole
`STR_PHY_RAW` queue, and mid-drain arrivals are delivered live and may
interleave), and peer-key insert-replacement is documented to leave the peer's
replay baseline and queued frames untouched.

`CompanionRadio` gained `insert_prop_item`/`remove_prop_item` (digest-returning,
`STATUS_ALREADY`/`STATUS_ITEM_NOT_FOUND` surfaced), `queue_drain`/
`queue_drain_with`, `save`/`clear`, `restore` handling both completion forms
(`RESET_RESTORED` is consumed as success, not an unexpected reset), and a
bounded `pop_prop_event` queue for unsolicited `PROP_IS`/`PROP_INSERTED`/
`PROP_REMOVED`. Responses are now kind-tagged so a table notification can never
satisfy a property transaction.

`Session` is refactored into explicit `DeviceDomain`/`HostDomain`/
`SessionState` structs. `attach()` now resets session state only — the PHY
configuration and enable state, device name, and duty accounting survive, and
nothing is emitted; `detach()` exists and firmware calls it only when the
active transport detaches (stale-detach immune). The boot reset cause is seeded
at `Session::new` and attach no longer touches `PROP_LAST_STATUS`.
`PROP_MAC_PROMISCUOUS` is implemented as the sole session-scoped property
(reverts on attach) without advertising `CAP_HOST_FILTER`; with filtering
unconfigured its delivery behavior is definitionally unchanged. `CMD_CLEAR`
succeeds trivially (base protocol); drain/save/restore fail `UNIMPLEMENTED`
until their capabilities exist; insert/remove distinguish known-but-not-a-table
(`INVALID_ARGUMENT`) from unknown (`PROP_NOT_FOUND`). Advertised capabilities
are unchanged.

The increment-2 acceptance gate passes in host tests (attach preserves an
enabled/configured PHY, name, duty limit and usage; resets promiscuous and
pending-TX correlation; reset still restores post-reset values and announces).
All workspace suites pass and both firmware images build. The reflashed
T-1000E completes the USB probe handshake twice: the first attach reported the
retained hardware boot cause and the second reported `RESET_SOFTWARE` from the
prior session's `CMD_RST`, confirming the new attach semantics on hardware.

### Increment 3 — complete (2026-07-15)

`CAP_HOST_FILTER` is implemented and advertised. `umsh-companion-ncp` now
depends on `umsh-core` (no default features) for `PacketHeader` parsing;
protocol policy stays in the host-testable session crate and the firmware
remains an effect executor.

* `HostDomain` holds `PROP_HOST_KEY` and a fixed-capacity (16-entry)
  `PROP_HOST_RX_FILTERS` table. Whole-table `CMD_PROP_SET` validates the
  complete value into a candidate table before committing (invalid entry →
  `INVALID_ARGUMENT`, unsplittable value → `PARSE_ERROR`, either leaves the
  old table fully intact); duplicates in a set value collapse per set
  semantics. Insert/remove enforce `STATUS_ALREADY`/`STATUS_ITEM_NOT_FOUND`/
  `STATUS_NOMEM` and emit `CMD_PROP_INSERTED`/`CMD_PROP_REMOVED` digests.
  Filter validation also rejects packet types above 7.
* Receive filtering follows the spec union: explicit filters (dest hint —
  which also matches a MAC ack's DST — channel id, packet type) plus the
  implicit destination-hint filter derived from the host key. The factory
  compatibility rule is preserved: with no host key and an empty table,
  every frame is delivered without being parsed at all (raw/junk frames
  included), exactly like the minimal protocol. Once any filter exists,
  a frame that does not parse as UMSH matches nothing. Promiscuous mode
  bypasses filtering for live delivery only.
* Host replacement is a deferred validate-before-mutate transaction:
  setting `PROP_HOST_KEY` to a different value (including empty) parks the
  new key and returns `Effect::WipeHostDomain { tid }`; only
  `respond_host_wipe(tid, Ok)` installs it and resets the host domain as
  one unit. `Err` rolls back with `STATUS_FAILURE` and the old domain fully
  in effect; a second set while pending is `BUSY`; attach abandons the
  pending transaction. Setting the current value is idempotent (no wipe,
  filters survive). Firmware completes the wipe trivially until `CAP_SAVE`
  exists (nothing persisted).

The whole increment-3 gate passes in host tests (50 in the session crate):
table atomicity, all three filter types, implicit-filter matching,
promiscuous live delivery, factory compatibility, replacement
rollback/busy/abandonment, `CMD_RST` clearing the host domain, and filters
surviving attach. Both firmware images build; firmware host tests pass.

### Increment 4 — complete (2026-07-15)

`CAP_HOST_RX_QUEUE` is implemented and advertised. The session now tracks
attached-vs-detached (`attach()`/`detach()` set it; `Session::new` starts
detached): while attached, accepted frames are delivered live exactly as
before; while detached, accepted frames go into a fixed 16-entry circular
`RxQueue` inside `HostDomain` (frame, RSSI/LQI/SNR, receive time, acked
flag — always false until `CAP_HOST_AUTO_ACK`). Overflow evicts the
oldest entry and counts it in `PROP_HOST_RX_QUEUE_DROPPED` (wrapping
u32). Count and capacity are exposed as properties; the capacity is fixed
(set fails `UNIMPLEMENTED`, the spec-sanctioned choice). Host-domain
resets (`CMD_RST`, host replacement) discard the queue and its counters
in place — `HostDomain::reset` deliberately avoids staging the multi-KB
entry array on an embedded stack.

`CMD_QUEUE_DRAIN` is effect-driven for transport backpressure: the
firmware `Emitter` has only two staging slots, so the session returns
`Effect::DrainQueue` and the firmware calls `drain_step` repeatedly,
flushing between calls; each step emits exactly one `CMD_STR_RECV`
(oldest first, `RX_FLAG_BUFFERED` plus one-second-granularity `RX_AGE`
in `BufferedRxMeta`) and the final step emits the correlated `STATUS_OK`.
The covered set is fixed at command time; live arrivals mid-drain are
delivered immediately and interleave, per the amended spec. An empty
queue succeeds immediately without an effect; a drain-while-draining is
`BUSY` (unreachable through the serialized firmware loop, guarded
anyway). No keys exist before `CAP_HOST_KEYS`, so no protocol-defined
duplicate detection applies yet: identical unauthenticated frames occupy
separate entries (spec-correct for this capability set), and the queue
insert path is where increment 5's replay/MIC coalescing will hook in.

Gate covered in host tests (58 in the session crate): detached receive →
attach → count → drain with age/flag/metadata assertions, overflow
eviction + dropped accounting, filtering applied to queueing, duplicate
entries, live interleave with a fixed covered set, drain-tail
completion, empty-drain success, reset/host-replacement discard, and
read-only/fixed-capacity property behavior. Host-side
`queue_drain_with`, firmware host tests, and both release images remain
green.

### Increment 5, first half: CAP_HOST_KEYS — complete (2026-07-15)

Increment 5 was split at its natural capability boundary: `CAP_HOST_KEYS`
requires only `CAP_HOST_FILTER`, so advertising it without
`CAP_HOST_AUTO_ACK` is spec-clean. The dependency-boundary decision:
`Session` is now generic over `umsh-crypto`'s `AesProvider`/
`Sha256Provider` and owns a `CryptoEngine` (constructed by the firmware
with the software providers — no hardware providers exist in the BSPs,
and the linker strips the unused dalek identity code). This is the same
engine the MAC uses, so channel-identifier derivation matches the core
spec by construction, and the AUTO_ACK half gets `open_packet`/
`compute_ack_tag`/`decrypt_blind_addr` for free.

* `PROP_HOST_CHANNEL_KEYS` (8 entries; digest = derived channel id,
  remove selector = the 32-byte key) and `PROP_HOST_PEER_KEYS` (8
  entries; digest and selector = the peer public key; inserting a
  matching public key replaces the stored key material — never
  `STATUS_ALREADY`). Whole-table sets validate into a candidate table
  before committing; channel duplicates collapse, repeated peer public
  keys replace in order. Secrets are never read back — GETs and
  INSERTED/REMOVED notices carry digest forms only, and a test asserts
  the pairwise key material appears in no emitted frame.
* Transport-security gate per spec §Provisioning Security:
  `attach(link_secure: bool)` makes the context explicit (no
  BLE-specific globals). Key-bearing `CMD_PROP_SET`/`CMD_PROP_INSERT`
  fail `STATUS_INVALID_STATE` while `link_secure` is false. The shared
  firmware passes `true` for both transports: USB-CDC by physical
  possession, BLE because the companion GATT service already refuses
  access outside an encrypted LESC-bonded link. A bare-UART port would
  pass `false`.
* Each provisioned channel key's derived identifier is an implicit
  receive filter (live and detached queueing), and provisioned channel
  keys alone make filtering "configured" for the compatibility rule.
* Host replacement and `CMD_RST` clear both tables as part of the host
  domain. Property GET buffers grew to `PROP_BUF` (peer digest table is
  256 bytes).

65 session tests pass; firmware host tests and both release images
remain green.

### Increment 5, second half: CAP_HOST_AUTO_ACK — complete (2026-07-15)

Two structural changes landed alongside the feature:

* **Replay detection moved to `umsh-crypto`** (`umsh_crypto::replay`):
  `ReplayWindow`/`RecentMic`/`ReplayVerdict` are Security-chapter
  concepts, and hosting them in the crypto crate lets the NCP share the
  MAC's exact implementation without depending on `umsh-mac` (which
  re-exports them unchanged). The NCP keeps its no-MAC layering.
* **Latent `umsh-crypto` interop bug fixed**: `open_packet` and
  `decrypt_blind_addr` reconstructed the received packet's SECINFO
  bytes as "immediately before the body", but every secure layout puts
  SECINFO before the *options block* — the options end marker and the
  blind address block sit between it and the body. The CTR IV only
  consumes SECINFO bytes when the MIC is shorter than 16 bytes
  (`build_ctr_iv` takes 16), so all existing Mic16 traffic was
  unaffected and the bug never surfaced; any Mic4/8/12 encrypted frame
  with a payload would have failed to interop. Fixed by anchoring on
  `options_range.start`; short-MIC unicast and blind round-trip
  regression tests added.

The auto-ACK implementation follows spec §Acknowledgement Delegation
exactly: while detached, an accepted frame is evaluated on a scratch
copy (the queue always holds original wire bytes) — UNAR authenticates
with the provisioned pairwise keys; BUAR requires the channel key to
decrypt the address block and forms the combined blind payload keys.
The source must resolve by full public key (S flag) or **unique**
3-byte prefix; ambiguous hints never ack. Each provisioned peer carries
a `ReplayWindow` (never saved; key-material replacement leaves it
untouched — proven by a test that reuses a counter across a key
replacement). New frames are queued (acked flag set), the baseline
advances, and a MAC ack (`PacketBuilder::mac_ack` + `compute_ack_tag`
over the plaintext-body CMAC) is staged through the ordinary
single-transmit radio path and duty limiter — a refused ack (auto-ack
off, radio busy, duty exhausted) leaves the frame queued unacked and
the sender's retransmission hits the re-ack window later. Identified
duplicates (same counter + retained MIC, Route Retry forms included)
coalesce without consuming a queue slot and MAY be re-acked only within
the eight-counter window, without baseline movement; farther behind is
never acknowledged. Suspected replays outside the window are queued
unacked as ordinary traffic (the host MAC stays authoritative).
Autonomous ack completions do not touch `PROP_LAST_STATUS`, so a boot
reset code still reaches the next host. `PROP_HOST_AUTO_ACK` is
host-domain (cleared by replacement/reset, survives attach).

Gate: 75 session tests including sealed-packet vectors for UNAR/BUAR
success (with exact ack-tag verification), wrong keys, corrupted MIC,
first-contact baselines, ambiguous vs full-key source resolution,
duplicates inside and outside the re-ack window, attached suppression,
auto-ack-off and duty-refusal paths, `RX_FLAG_ACKED` in drained
metadata, and unstorable-frame non-acknowledgement. The full workspace
suite passes and both boards build. `CAP_HOST_AUTO_ACK` is advertised —
the full-protocol capability set is now
FILTER/RX_QUEUE/KEYS/AUTO_ACK.

### Increment 6 — complete (2026-07-16)

`CAP_SAVE` is implemented and advertised. Session side:

* `SavedState` is the RAM mirror of the durable snapshot — the saveable
  subset of both domains (RF config including the PHY enable state,
  duty limit, device name, host key, filters, channel keys, peer key
  material, auto-ACK) and deliberately never the queue, the replay
  baselines, or the device identity. A versioned fixed-order wire codec
  (`SNAPSHOT_MAX` = 1024) round-trips it; channel identifiers are
  re-derived on decode rather than trusted from storage, and any
  structural defect (bad version, truncation, out-of-range counts,
  trailing bytes) rejects the whole snapshot so the NCP boots as if
  nothing were saved.
* `CMD_SAVE` → `Effect::SaveSnapshot` (bytes from `encode_snapshot`);
  `CMD_CLEAR` → `Effect::ClearSaved`; both complete through
  `respond_save`/`respond_clear` and report success only after the
  durable operation commits — a failure leaves the previous snapshot
  and `PROP_SAVED` untouched. `CMD_RST` post-reset values now come from
  the snapshot when one exists (the PHY comes back configured and
  enabled); factory defaults require `CMD_CLEAR` + `CMD_RST`.
* `CMD_RESTORE` implements the spec's reset reporting form: the revert
  applies in place, session state resets, and an unsolicited
  `STATUS_RESET_RESTORED` announces completion. Queue contents and
  per-peer replay baselines survive a same-host restore (windows are
  transplanted by peer identity); a snapshot naming a different host
  key applies the host-replacement rule as part of the revert. No
  snapshot → `STATUS_INVALID_STATE`, nothing modified.
* Host replacement's durable wipe is now real: the firmware persists
  `encode_wiped_snapshot` (saved device domain + defaulted host domain)
  before `respond_host_wipe(Ok)` installs the new key, and the RAM
  mirror wipes with it — a power cycle cannot resurrect the previous
  host's provisioning, verified by booting a fresh session from the
  wiped bytes.

Firmware side: the snapshot journal (`proto_store`) lives in the two
4 KB pages after the BLE store's (0x000E_6000..0x000E_8000, inside the
NV region both boards share), with 2048-byte slots — MAGIC `UPRS`,
generation, length-prefixed opaque payload, CRC, and a trailing commit
word written last, reusing `ble_store`'s record machinery (its
committed-write helper is now generic over slot size). The single
MPSL-coordinated flash driver moved into a shared async mutex so the
BLE store and the NCP task can both reach it; the two-page rotation
logic was factored out and shared. The journal is mounted at boot
before the NCP session starts, and `restore_at_boot` applies the saved
configuration — re-enabling the PHY and beginning detached
filtering/queueing/delegation — before the first host command. The
`no-ble` diagnostic image has no MPSL flash driver: saves and clears
fail honestly there.

Gate: 81 session tests (codec round trip through a fresh boot, save
rollback, `PROP_SAVED`, reset-from-snapshot including the PHY enable
state, factory reset via clear+reset, restore preserving queue and
baselines, restore-as-host-replacement, wiped-snapshot semantics) and
27 firmware host tests including a byte-boundary power-cut sweep over
the whole record write — every cut point mounts the complete old
record. Both boards and the no-ble variant build.

### Review fixes for increments 4–6 (2026-07-16)

An external review of increments 4–6 surfaced five verified defects,
all fixed:

1. **`CMD_CLEAR` is now a committed tombstone**, not two page erases.
   The journal gained a record kind (`Snapshot`/`Cleared`); the newest
   valid record is authoritative, so a committed tombstone voids older
   snapshot records without any erase, and an interrupted clear leaves
   the previous snapshot fully in effect. Stale records are reclaimed
   by ordinary rotation. Increment 7 note: the tombstone's generation
   can serve as the clear epoch when the independently persisted device
   identity must also honor `CMD_CLEAR`.
2. **`RX_FLAG_ACKED` is earned, not assumed**: queue entries carry a
   wrapping sequence handle; the pending autonomous transmission names
   the entry it acknowledges and only a confirmed `on_tx_result(true)`
   marks it. A failed TX leaves the entry unacked, the retransmission
   hits the re-ack window, and a confirmed re-ack marks the original
   entry (located by authenticated identity). Handles are immune to
   rotation/eviction/reset — a stale handle marks nothing.
3. **Delegated acks carry flood return routing**: a frame that arrived
   by flood gets an ack whose remaining hops seed from the frame's
   accumulated count (clamped 1–15), mirroring the MAC's cached
   flood-route acks; FHOPS is dynamic (outside the AAD) so a duplicate
   re-ack routes from the retransmission it answers. Region-code
   scoping is deliberately omitted for now — an unscoped return flood
   is correct, just broader.
4. **Authenticated multicast coalesces queue-locally**: with the
   channel key held, a multicast frame authenticates and its logical
   identity (frame counter + verified MIC) is matched against the
   entries currently queued — exact retransmissions and Route Retry
   forms coalesce with no per-channel/per-sender replay registry, no
   ack, and no retained state once the entry drains or evicts.
   Unauthenticated multicast still occupies separate entries per spec.
5. **TID-zero commands are properly fire-and-forget**: one `complete()`
   helper now gates every command completion (status responses, value
   echoes, INSERTED/REMOVED) — TID 0 mutates state and records
   `PROP_LAST_STATUS` silently; a TID-0 drain delivers the buffered
   frames but no completion. The deliberate unsolicited notifications
   (`CMD_RST` reset notice, `STATUS_RESET_RESTORED`, live/buffered
   `CMD_STR_RECV`) are unchanged.

88 session tests and 29 firmware tests cover the regressions
(tombstone interruption at every distinct byte boundary, failed-ack
flag clearing, eviction-safe handles, flood-return acks including the
re-ack path, multicast coalescing, and the TID-zero matrix).

### Increment 7 — complete (2026-07-16)

`CAP_DEV_IDENTITY` is implemented and advertised. Session side:

* `PROP_DEV_KEY` (read-only; empty when unconfigured) and write-only
  `PROP_DEV_PRIVATE_KEY`: a 32-octet set installs a private key, an
  empty set commands on-device generation; both forms are key
  provisioning behind the secure-link gate, and a `CMD_PROP_GET` of
  the private key is `STATUS_UNIMPLEMENTED` without disclosing whether
  one exists. The write stages `Effect::ProvisionIdentity`; the
  firmware reads the request via `identity_request()`
  (`IdentitySource::Install`/`Generate`), performs the key math and
  the durable write, and completes with `respond_identity`, which
  announces success as `CMD_PROP_IS` for **`PROP_DEV_KEY`** carrying
  the public key — never the private key — only after the identity is
  durably stored. Concurrent writes are `STATUS_BUSY`; a reported
  failure leaves the previous identity in effect.
* The identity lives outside the snapshot: the session tracks the live
  key and a persisted mirror. `CMD_RST` reverts to the mirror (so the
  identity survives resets), `CMD_RESTORE` never touches it,
  `CMD_CLEAR` erases only the mirror (live state is unaffected, per
  spec) and the `CMD_RST` completing a factory reset then loses it.
  Replacing the identity keeps the device peer list and channel keys.
* `PROP_DEV_CHANNEL_KEYS` (device domain, secure-link gated, digest =
  derived channel identifier) and `PROP_DEV_PEERS` (public keys only,
  ungated like `PROP_HOST_KEY`, digest = item) with insert/remove/
  whole-table-set semantics matching the host tables. Both are in the
  snapshot (post-reset: empty or restored) and survive host
  replacement. Device channel keys deliberately create no implicit
  host receive filters — verified by a detached-queueing test.
  `SNAPSHOT_VERSION` bumped to 2, `SNAPSHOT_MAX` to 1536 (any
  version-1 snapshot on flashed hardware is ignored at boot; re-save
  after flashing).

Firmware side: the identity journal reuses the `proto_store` record
machinery in its own two pages (0x000E_8000..0x000E_A000) — a separate
journal rather than a shared clear-epoch because snapshot saves must
never rotate the identity record away; each journal clears atomically
with its own committed tombstone. The payload is the private key plus
the derived public key; boot mounts it and calls `set_boot_identity`
before the first host command. `CMD_CLEAR` now tombstones both
journals (snapshot first; an interruption between them reports failure
and the host's retry completes the erase). Generation entropy: the RNG
peripheral belongs to the SoftDevice Controller for the stack's
lifetime, so boot seeds a ChaCha20 CSPRNG (`rand_chacha`, already in
the tree via trouble-host) from the hardware TRNG before `build_sdc`,
honoring the no-non-crypto-RNG rule; `SoftwareIdentity` does the
Ed25519 math. The `no-ble` image fails identity persistence closed and
now builds warning-free (a scoped `cfg_attr` allow covers the
deliberately uncalled BLE support source in that diagnostic image
only).

Gate: 97 session tests (provisioning lifecycle incl. replacement,
generation staging, busy/failure/insecure-link paths, RST/RESTORE/
CLEAR interactions, dev-table lifecycles and snapshot round-trip,
no-implicit-filter proof, TID-0 silence) and 30 firmware host tests
(identity payload codec, journal page layout inside the NV region).
Both boards and the no-ble variant build with zero warnings.

### Increment 8 — complete (2026-07-16)

The host-facing provisioning/synchronization workflow and the
adapter-free integration harness. Host side (`umsh::companion_radio`):

* `CompanionRadio::attach_existing` — the full-protocol attach: only
  the identity handshake runs (retained `PROP_LAST_STATUS`, protocol
  version check, NCP version, MTU); no `CMD_RST`, no reconfiguration,
  no PHY enable. The existing resetting constructor remains the
  minimal-protocol path and is documented as unsuitable for an
  autonomously operating NCP.
* `sync(expected_host_key)` — the spec's post-attach procedure:
  retained status with reset-since-last-contact detection, decoded
  `PROP_CAPS`, an ownership verdict (`Ours`/`Unclaimed`/
  `OtherHost(key)`/`Unsupported`), and capability-gated state — PHY
  enable/frequency, device name, `PROP_SAVED`, queue count/dropped,
  and the digest forms of filters, channel identifiers, peer public
  keys, auto-ack, and the device key — into one `NcpSync`.
* `provision(&HostProvisioning)` — digest-based reconciliation of the
  host domain. A differing host key replaces the domain first (spec
  §Host Replacement); filters replace whole-table when the sets
  differ; channel keys insert individually unless the NCP holds an
  identifier the host has no key for (unremovable individually — the
  selector is the key — so the table is replaced atomically); peers
  reconcile by public-key membership so pairwise secrets the NCP
  already holds never cross the link again; auto-ack lands last. The
  `ProvisionReport` says exactly what changed; a reattach reconcile of
  matching state is a verified no-op. Saving stays explicit.
* `ensure_device_identity()` — returns the device key, commanding
  spec-recommended on-device generation when none is configured (the
  success response is `PROP_IS` for `PROP_DEV_KEY`).
* `set_frame_trace` + `describe_frame` — a per-frame trace hook in
  both directions producing one-line summaries (command, TID, property
  mnemonic, decoded status; values summarized by length so traces can
  never leak key material), for placing a hardware failure at the host
  API, framing, session, storage, or radio boundary.

Integration harness (`umsh/tests/companion_full_protocol.rs`): a
`FrameLink` implementation driving the **real**
`umsh_companion_ncp::Session` — no fake NCP — with RAM stand-ins for
the snapshot/identity journals, the radio, entropy, and the clock, and
a per-command log of both directions. The flagship test runs the
increment-9 hardware script in-process: provision + identity
generation + PHY config → save → detach → power cycle (fresh session
boots from the simulated journals via `restore_at_boot` +
`set_boot_identity`) → autonomous detached RX with a transmitted
delegated MAC ack → reattach → sync (reset detected, ownership Ours,
queue count 1) → no-op reconcile → drain with `RX_FLAG_ACKED`
verified. Companion tests cover other-host detection and takeover
whose durable wipe survives a power cycle, channel insert-vs-replace
reconciliation, and the insecure-link refusal surfacing
`STATUS_INVALID_STATE`.

Gate: 4 integration tests + the existing 12 companion_radio unit
tests, full workspace sweep green, firmware unaffected (host-only
increment; T-Echo release build re-verified).

### Increment 9, first pass — T-1000E over USB complete (2026-07-16)

The single-board, USB-tethered portion of the hardware validation ran
green end to end on the T-1000E, driven by the new
`umsh/examples/companion_hw_validate.rs` (one phase per invocation so
the board can be power-cycled between phases; every frame printed
through the host trace hook). Reboots were induced by DFU reflash of
the same image — which additionally proves both journals survive a DFU
cycle. Results:

* **Phase A** — `attach_existing` + `sync` on a fresh image: all ten
  capabilities advertised (8, 16, 38, 515, 32–37); on-device identity
  generated (spec-recommended empty `PROP_DEV_PRIVATE_KEY` write, real
  TRNG-seeded ChaCha20 path) and stable across repeated ensure calls;
  host domain provisioned (host key, one filter, channel key `9b68`,
  one peer, auto-ack); PHY configured/enabled; `CMD_SAVE` committed.
* **Phase B** (after reboot) — reset detected from the retained
  status; ownership `Ours`; boot restore re-enabled the PHY at the
  saved 906 875 kHz with auto-ack armed; the device identity survived;
  the reattach reconcile was a verified no-op (no key material crossed
  the link again); empty-queue drain completed.
* **Phases C+D** — `CMD_CLEAR` erased the snapshot and durable
  identity while every live value stayed in effect; after the next
  reboot the board was factory-fresh (unclaimed, nothing saved,
  `PROP_DEV_KEY` empty — the identity tombstone held across the power
  cycle — PHY disabled, default frequency). Re-provisioning generated
  a **different** identity, confirming fresh entropy per generation.
  The board is left provisioned and saved for autonomous use.
* **Measurements** — attach handshake ≈ 2–310 ms (the high end is
  first-open after enumeration); command RTT over USB-CDC: min 434 µs
  / median 459 µs / max 534 µs (50 × `PROP_LAST_STATUS` get); queue
  capacity 16; flash 481.3 KiB (T-1000E) / 499.4 KiB (T-Echo) of the
  760 KiB app window; static RAM 84.8 / 87.3 KiB.
* Post-DFU `RESET_WATCHDOG` as the boot cause is the documented
  RESETREAS noise, and usefully exercised the reset-detection path.
  The temporary freeze diagnostics ("d6" version string) were still in
  the validated image.

### Increment 9, second pass — RF, T-Echo, and BLE attach (2026-07-16)

With the T-Echo connected as the second radio, the RF portion ran
green (`companion_hw_validate rf-peer` drives the T-Echo as the
transmitting peer while the T-1000E operates detached; `phase-e`
verifies the drain):

* **Delegated acknowledgement on the air** — a sealed,
  ack-requesting unicast from the provisioned peer was queued by the
  detached T-1000E and answered with a MAC ack observed on the T-Echo
  (12 bytes, −20 dBm across the desk).
* **Duplicate coalescing** — the exact retransmission was re-acked on
  the air and occupied no second queue entry.
* **Unrelated traffic** — a sealed ack-requesting unicast to a foreign
  destination drew no ack and (by the final queue arithmetic) was
  never queued.
* **Overflow** — 19 accepted frames into the 16-slot queue: eviction
  counted exactly (the dropped counter is cumulative across drains —
  the first expectation mistake was mine, not the board's), and the
  drain delivered all 16 oldest-first with correct ages; exactly the
  one late ack-requesting frame carried `RX_FLAG_ACKED`.
* **A real host-side bug found and fixed**: `queue_drain_with`'s
  callback used to lose every frame the driver's 8-deep receive
  buffer evicted mid-drain (an NCP queue of 16 delivered only 8).
  The callback is now fed at ingest time — lossless regardless of the
  bounded buffer — with an in-process regression test that fails on
  the old code (`full_queue_drains_losslessly_through_the_callback`).

The T-Echo then passed storage phases a–d itself (identity generation,
provision/save, boot restore, clear-to-factory across reboots), and
the **BLE full-protocol attach** worked end to end:
`attach_existing` over `BleFrameLink` on the bonded LESC link attached
in 242 ms without resetting, `sync` saw the exact provisioned state,
and command RTT over BLE was 59/60/90 ms min/median/max (connection-
interval bound; USB was ~443 µs median on the same board).

One diagnosis worth remembering: the T-Echo's boot restore initially
appeared to lose the saved frequency after every reboot. The journal
and decode were fine — a leftover `umsh-capture --ble` soak process
from earlier in the day was auto-reconnecting over BLE after each
reboot, and its minimal-protocol attach (`CMD_RST` + configure +
enable, at the default profile) legally reconfigured the radio. Two
hosts, both obeyed. This is exactly the hazard `attach_existing`
exists to avoid, demonstrated in the wild; kill stray minimal-protocol
clients before hardware validation.

Increment-9 items still open: host replacement and BLE/USB
displacement exercised deliberately on hardware, the
`ble-store-fault-inject` storage-failure image, and a fresh soak run
(the previous soak was invalidated by today's reflashing).

Follow-up (2026-07-16): MAC-owner hosts (desktop_chat, cli_companion)
currently enable `PROP_MAC_PROMISCUOUS` per session so a provisioned
NCP's host-domain filters cannot eat their live traffic. That is the
accepted short-term shim; the battery-correct long-term form is a
provisioned live-filter plan — `PROP_HOST_KEY` = own identity
(implicit destination-hint filter: unicast + MAC acks) plus channel
coverage per subscribed channel (provisioned channel keys or explicit
non-secret `ChannelId` filters) and `PktType(Broadcast)` if discovery
is wanted. Blind unicast needs nothing extra: BUNI/BUAR are
channel-addressed, so the channel filter matches them on the wire
(peer keys are for authentication/ack delegation, not filter
matching). Design it once in the `umsh::companion_radio` workflow API
rather than per tool. (`umsh-capture` legitimately stays
promiscuous.)

Gap (2026-07-16): there is no proper **companion-radio management
tool**. The workflow API exists (`sync`/`provision`/
`ensure_device_identity`/`save`/`clear`/`restore`/
`set_ble_pairing_pin`), but the only command-line front-ends are the
hardware-validation phases (fixed test-vector keys) and scattered
example flags. A user-facing tool should cover: neutral inspection
(the `info` modes graduate out of the validation example),
provisioning with the operator's real keys (host identity, channel
keys, peer entries from args or a file), device-identity management,
save/restore/clear, pairing-PIN management, and factory reset — over
both serial and BLE. Fill this before the companion radio can be
operated by anyone who is not developing it. Flashing
notes: `diag/reflash_t1000e.py` automates the T-1000E serial-DFU
touch+retry; the T-Echo path is 1200-baud touch → wait for TECHOBOOT →
copy the UF2 **under a fresh filename with `cp`** (overwriting the
existing name, and python `shutil` under the sandbox, both fail with
EPERM; the "Device not configured" error mid-copy is the bootloader
detaching after the last block and means success). The temporary
freeze diagnostics must still be stripped or gated before any
release-quality image (keep the POWER-INTEN disarm fix).

## BLE transport closure work — parallel, not a full-protocol prerequisite

1. **Complete the BLE/live-LoRa soak.** Continue running the recovery-enabled
   `umsh-capture --ble` with representative RF traffic and retain any failure
   diagnostic plus the next session's boot status if the transient failure
   recurs. Then run bidirectional `desktop_chat --ble` traffic and record duration,
   packet/TX-confirmation counts, reconnect behavior, and any WDT/reset event.
2. **Exercise persistence failures on hardware.** Flash the dedicated
   `ble-store-fault-inject` image, provoke PIN and bond writes, verify that each
   fails closed before NVMC is touched, power-cycle immediately, and confirm
   that the prior committed journal and pairing state remain usable. Reflash
   production firmware afterward.
3. **Force transport displacement at frame boundaries.** Displace BLE with USB
   and USB with BLE during multi-segment/multi-chunk output, proving generation
   checks suppress the stale tail and both transports attach cleanly afterward.
4. **Run the Linux/BlueZ host matrix.** Pair through a `bluetoothctl` agent,
   subscribe through `btleplug`, receive live frames, disconnect/reconnect, and
   recover from a deliberately removed/asymmetric bond.
5. **Finish Phase-E measurements and release notes.** Record BLE attach latency,
   RTT/throughput at representative ATT MTUs, advertising/connected idle
   current, and supervision-timeout recovery; reconcile the task-layout header,
   this plan, and the protocol chapter only where observed behavior actually
   diverges.
6. **Close the T-1000E startup/force-pairing gate.** Instrument the first boot
   after clearing BLE security state, verify that early watchdog servicing
   prevents the observed reset and sustained buzzer tone, and then validate
   that an ordinary short wake press is ignored while a continued one-second
   startup hold opens pairing mode with existing bonds. Do not conflate this
   gesture with bootloader entry.
7. **Maintain the Trouble fork deliberately.** Prepare the consolidated
   upstreamable security fix for review and either converge on an accepted
   upstream shape or retain the audited revision pin with its test evidence.

The repository's T-Echo bootloader configuration identifies the board's
resident layout as S140 **v6.1.1** (application base `0x26000`), not the
v7.3.0 fallback assumed below; the physical image's info block still
needs to be dumped before relying on it.

**Decision (2026-07-13): proceed with a pinned trouble fork** that adds
the pairing-request rejection gate (and, only if the spike shows it is
needed, bond-gated attribute access) — see
[The trouble fork](#the-trouble-fork). The `nrf-softdevice` fallback is
demoted to last resort: `nrf-softdevice`'s bindings target S140 v7.x,
which the T-Echo's resident v6.1.1 image is not, so the fallback would
itself require reprovisioning the SoftDevice and moving the app base —
the "already resident, zero provisioning risk" advantage that
originally justified it does not exist on this board.

Implements the [Companion Radio over BLE](protocol/src/companion-radio-ble.md)
spec chapter: the companion-radio protocol carried over the GATT frame
transport, secured with LESC bonding and the pairing-mode/PIN model,
on the T-Echo NCP firmware and the host-side `CompanionRadio` driver.

Scope is the **tethered** case only. The BLE local bearer / BLE-LoRa
bridge is deferred; the only work it imposes here is captured in the
[architecture guardrails](#architecture-guardrails-for-the-future-bridge).

## Decision record

| Decision | Choice | Where settled |
|---|---|---|
| BLE stack (firmware) | `trouble-host` + `nrf-sdc`/`nrf-mpsl`, with trouble consumed via a pinned fork; `nrf-softdevice` demoted to last resort | decided 2026-07-13 |
| Pairing-mode gate | Fork patch: runtime pairing-request rejection (SMP `Pairing Failed`, reason `Pairing Not Supported`); upstream PR pursued in parallel | decided 2026-07-13, §[The trouble fork](#the-trouble-fork) |
| Framing | GATT frame transport, 1-byte SAR header; no HDLC over BLE | Spec §GATT Frame Transport |
| UUIDs | Base `21EB6B15-XXXX-4CCF-92E4-A079171BEC97` (uuidgen), slot in group 2; `0x0100`+ reserved for the local bearer | Spec §UUID Allocation |
| Security | LESC only, bonding required, encrypted+bonded characteristic permissions | Spec §Security |
| Pairing | Pairing mode: auto 15–30 s at power-on only while unbonded; bonded → explicit action in the T-Echo display UI; exits on new bond / bonded connect / timeout | Spec §Pairing Mode |
| Static PIN | `PROP_BLE_PAIRING_PIN` (4864), write-only, persisted; Passkey Entry accepted anytime with ≤3-failures-per-power-cycle lockout | Spec §Pairing PIN Configuration |
| Advertising | Suspended while a USB-CDC companion session is open | Spec §Advertising |
| Host BLE library | `btleplug` (GATT central; macOS + Linux first) | this plan, Phase B2 |
| Session/wire layering | Unchanged: `Session` stays framing-free and transport-free | — |

### Architecture guardrails for the future bridge

- The SAR transport lives in `umsh-companion::gatt` as a
  service-agnostic module (like `hdlc`), not welded to the companion
  service.
- UUID slots `0x0100+` stay unallocated.
- The radio runner (`RADIO_CH` + `NCP_CTL`) remains the single mux
  point for radio clients; nothing added here may assume `Session` is
  the radio's only client.

## Architecture overview

Layer map — asterisks mark what this plan adds or changes:

~~~
Host                                    NCP firmware (companion-ncp-techo)
────                                    ──────────────────────────────────
umsh::companion_radio                   ncp_task: Session + Emitter
  CompanionRadio<L: FrameLink>*           (framing removed from this task)*
    SerialFrameLink<IO>  (HDLC)*        usb_in_task: HDLC decode*   ble_task*
    BleFrameLink (btleplug + SAR)*      output_task: HDLC encode*   (SAR both
                                                                     directions,
umsh-companion (wire crate, no_std)     pairing mode, adv control)
  frame / pui / ids / meta / status
  hdlc  (serial framing)
  gatt* (SAR framing + UUIDs)           trouble-host + nrf-sdc + nrf-mpsl*

umsh-companion-ncp
  Session (+ PROP_BLE_PAIRING_PIN handling, Effect::SetPairingPin)*
~~~

Firmware task/channel graph after Phase C (today's graph is in the
header comment of `firmware/companion-ncp-techo/src/main.rs`):

~~~
usb_in_task ──┐                          ┌──► OUT_USB_CH ─► output_task
  (HDLC decode│                          │      (HDLC encode + 64B chunks)
   + edges)   ├─► INPUT_CH ─► ncp_task ──┤
ble_task ─────┘   (frames +   (Session,  └──► OUT_BLE_CH ─► ble_task notify
  (SAR decode      attach/     routing,         (SAR segments @ ATT MTU)
   + edges)        detach)     arbitration)
radio_task ◄──── RADIO_CH / NCP_CTL ────► ncp_task   (unchanged)
~~~

## The trouble fork {#the-trouble-fork}

Upstream trouble (audited at `78aaf7d`) auto-accepts every incoming
`PairingRequest`: `handle_peripheral` in
`host/src/security_manager/mod.rs` constructs the pairing state
machine unconditionally when idle, the only refusals being the
SC-only/key-size checks, and `ConnectionEvent` exposes pairing only
post-facto (`PairingComplete`/`PairingFailed`). The spec's pairing-mode
and lockout rules both say pairing **MUST be rejected**, so we carry a
fork rather than weaken the spec to "allow, then neutralize."

Why reject-at-request instead of capability-matching (recorded so the
tradeoff isn't relitigated later):

- The spec invariant stays one testable predicate; the alternative
  smears policy across the bondable flag, dynamic IO-capability
  downgrades, `PairingComplete` cleanup, and per-access checks — all
  of which must be simultaneously correct in every mode.
- Unbonded strangers never exercise the SMP stack (no free P-256 work
  for anyone in radio range; future SMP bugs are not reachable
  pre-authorization).
- Allow-then-neutralize leaves the *central* with a stored bond the
  peripheral never kept — the classic asymmetric-bond failure where
  the phone can't reconnect until the user manually forgets the
  device.

**Mechanics.**

- Fork `embassy-rs/trouble` at the audited revision; consume it via
  the workspace `[patch]` table, same discipline as the `lora-phy`
  fork. Its pinned controller
  (`alexmoon/nrf-sdc@abe49d2`) is used as-is.
- **Patch 1 (required) — pairing-acceptance gate.** A runtime
  `set_pairing_enabled(bool)` on the security manager, surfaced
  through the public stack API. While disabled, an idle incoming
  `PairingRequest` is answered with SMP `Pairing Failed`, reason
  **`Pairing Not Supported` (0x05)** — an explicit rejection, not a
  silent drop, so the central fails immediately instead of hanging
  into the 30 s SMP timeout — and no pairing state machine is
  constructed. An exchange already in progress is unaffected; C4's
  mode-exit rules govern those.
- **Fixed responder passkey (required after the spike audit).** Upstream
  generated a random displayed passkey and had no way to install the
  configured `PROP_BLE_PAIRING_PIN`. The fork therefore also exposes
  `set_fixed_passkey(Option<u32>)`; the value is range-checked and used
  in the LESC display-role paths. A paired central/peripheral test proves
  both sides derive matching keys from the configured six-digit value.
- **Patch 2 (only if the spike proves it necessary) — bond-gated
  access.** The spec requires refusing non-bonded access with an ATT
  security error. If trouble's `GattEvent` accept/reject surface lets
  the application reject Frame In writes and the Frame Out CCCD write
  with the appropriate ATT error after an `is_bonded_peer()` check,
  no patch is needed. If the reject path cannot carry the error code,
  or CCCD writes are not surfaced to the application, add a
  bond-required security level to the same fork.
- **Patch-2 decision (2026-07-13): not needed.** CCCD writes are surfaced
  as `GattEvent::Write`, Frame In uses the same event path, and
  `GattEvent::reject(AttErrorCode)` carries
  `INSUFFICIENT_AUTHENTICATION`. The production server performs the
  `is_bonded_peer()` check at those two protected handles; service
  discovery remains available to an unbonded central.
- **Patch 3 (required after hardware stale-bond testing) — negative LTK
  reply.** When the controller raises `LE Long Term Key Request` and no
  matching bond exists, the host sends
  `LE Long Term Key Request Negative Reply`, as defined by the Bluetooth
  HCI contract. The audited upstream path instead requested an
  `AuthenticationFailure` disconnect, trapping iOS/nRF Connect in a
  rapid reconnect loop and obscuring the asymmetric bond. The negative
  reply is also used for an unknown connection identity; its controller
  result is propagated rather than ignored. A redacted hardware trace
  proved the negative reply completed successfully and that the ensuing
  stale-bond disconnect was initiated by iOS.
- **Upstream hedge.** Open the upstream issue/PR for Patch 1
  immediately and track it — "application-controlled pairing policy"
  is generically useful, so the fork is expected to be temporary. If
  upstream lands a different shape, converge on theirs at the next
  deliberate pin move; until then the pin only moves deliberately.
- The C4 lockout and D's bond capacity reuse the same gate: overall,
  `pairing_enabled = bond_count < 4 && (pairing_mode ||
  (pin_configured && !locked_out))`.
  With a PIN configured, this gate is what actually stops passkey
  bit-leak probing once the failure counter trips.

## Phase 0 — BLE stack spike (gate)

Prove `trouble-host` + `nrf-sdc` on our T-Echo alongside everything
the NCP firmware already uses, before touching real firmware. Exit
decides trouble vs. the `nrf-softdevice` fallback.

**Deliverable.** Throwaway binary `firmware/ble-spike-techo` (not in
workspace `default-members`; release-only like the rest).

**Steps.**

1. Dependencies: `nrf-mpsl`, `nrf-sdc` (peripheral role, nRF52840
   feature), and `trouble-host` **via our fork** (peripheral + GATT +
   security features). Pin all three as git revisions in the
   workspace, same discipline as the `lora-phy` patch. The audit
   already established the version coupling: trouble at the pinned
   revision expects `embassy-nrf` 0.11 while the workspace is on
   0.10, so the workspace-wide embassy upgrade happens *here*, in the
   spike, not mid-Phase-C.
2. LFCLK: BLE requires an accurate 32.768 kHz source.
   `umsh_bsp_nrf52840::clocks::default_config()` deliberately does not
   select the external crystal; the spike configures
   `LfclkSource::ExternalXtal` (the T-Echo has the crystal) and we add
   a `clocks::ble_config()` beside the default rather than changing
   existing firmwares.
3. MPSL/SDC bring-up: MPSL claims RTC0, TIMER0, TEMP, RADIO, ECB/AAR
   and specific PPI channels, plus high/low IRQ levels. Verify no
   collision with what the NCP firmware uses (RTC1 for embassy-time,
   TWISPI1, USBD, WDT, GPIOTE) and record the required
   `embassy-nrf::config::Config` interrupt priorities.
4. RNG: `nrf-sdc` takes the RNG peripheral. The NCP firmware doesn't
   use it (no MAC on the NCP), so hand it over wholesale. Record the
   sharing question for future MAC-bearing BLE firmware in the plan,
   not in code.
5. GATT echo service: one write characteristic, one notify
   characteristic, both requiring encryption. Advertise, connect from
   nRF Connect (phone), from macOS, **and from Linux**: pair via
   `bluetoothctl`, then run a `btleplug` smoke test proving a
   security-gated subscription works after out-of-process pairing —
   this BlueZ recovery path is exactly what Phase B2 depends on and
   is not established by the phone test.
6. Security spike — validated on the fork:
   - LESC-only enforcement (reject legacy pairing)?
   - Just Works bonding?
   - Pairing rejection via the fork's `set_pairing_enabled(false)`:
     from a central, rejection outside pairing mode is immediate (a
     clean pairing failure on the phone, reason Pairing Not
     Supported, and **no stale central-side bond**), and an exchange
     already in progress is unaffected?
   - Static passkey as responder (peripheral IO capability
     `DisplayOnly` with a fixed passkey)?
   - Encrypted+bonded enforcement on characteristic access and CCCD
     writes — this answer decides whether the fork needs Patch 2 or
     application-side `is_bonded_peer()` rejection suffices?
   - Bond data export/import (needed for Phase D persistence)?
7. Coexistence: initialize the SX1262 over SPIM and keep USB-CDC echo
   alive during an active BLE connection; run for 30+ minutes with the
   WDT armed.
8. Measure and record: flash delta, RAM delta (SDC memory pool +
   trouble `HostResources`), still links at `0x26000`, S140 blob
   untouched.
9. Fallback insurance: dump the *resident* S140's info block from a
   real T-Echo and record its exact version, required RAM claim, and
   app-base expectations. The `nrf-softdevice` fallback must rest on
   the actual image on the board, not the nominal "S140 v7.3.0".

**Measured implementation notes (2026-07-13).** The pinned `nrf-sdc`
wrapper must currently be built with both its `peripheral` and `central`
features because its controller trait implementation references central
HCI symbols even though this firmware never takes a central role. MPSL
owns CLOCK/POWER, so USB uses `SoftwareVbusDetect` in the permanently
powered/ready state; CDC DTR still supplies protocol attach edges. The
external 32.768 kHz crystal is configured at 20 ppm. MPSL owns RADIO,
RTC0, TIMER0, TEMP and PPI 19/30/31; SDC owns PPI 17/18/20–29 and RNG;
embassy-time remains on RTC1. SDC's controller buffer limit is 251,
while Trouble's 255-byte packet pool includes higher-layer headroom.
(A historical macOS gotcha: a globally exported ESP-specific
`LIBCLANG_PATH` broke `nrf-sdc-sys` bindgen; the export was removed from
the developer's shell profile 2026-07-15 and stock builds work with no
environment overrides.)
MPSL must be constructed with `with_timeslots` and one `SessionMem`
slot—using plain `new` correctly caused the first hardware PIN commit to
fail closed with `STATUS_INTERNAL_ERROR`; the corrected initialization
then committed and activated the PIN successfully.

**Exit criteria.** Bonded LESC connection from a phone; encrypted echo
round-trip; USB-CDC concurrently functional; WDT never fires; the six
security questions answered yes (or fallback invoked); numbers
recorded at the top of this file when done.

**Fallback (last resort).** Corrected 2026-07-13: the T-Echo's
resident SoftDevice is S140 **v6.1.1** at app base `0x26000` (see
[firmware-plan-techo.md](firmware-plan-techo.md); the v7.3.0 figure
belongs to the Wio Tracker L1 / T1000E, whose app base is `0x27000`).
`nrf-softdevice`'s bindings target S140 v7.x, so taking this path
means reprovisioning the SoftDevice (a combined bootloader+SD DFU
package over serial DFU, or SWD), moving the app base to `0x27000`,
raising the RAM origin by the SD's claim, routing flash writes through
`sd_flash_write`, and reshaping the Phase C task code. Phases A/B and
the spec are unaffected — but with no resident-image advantage, this
is strictly a last resort if the fork approach fails on hardware.

## Phase A — wire crate: `umsh_companion::gatt`

New module beside `hdlc`, same rules: `no_std`, allocation-free, zero
dependencies, host-tested.

**API sketch** (mirrors `hdlc`'s conventions):

~~~rust
/// SAR values (segment header bits 7-6).
pub const SAR_COMPLETE: u8 = 0;
pub const SAR_FIRST: u8 = 1;
pub const SAR_CONT: u8 = 2;
pub const SAR_LAST: u8 = 3;

/// Maximum reassembled frame size for the Companion Link Service.
pub const MAX_FRAME: usize = 512;

/// UMSH base UUID with `slot` spliced into the second group.
pub const fn uuid(slot: u16) -> u128;
pub const SERVICE_UUID: u128 = uuid(0x0001);
pub const FRAME_IN_UUID: u128 = uuid(0x0002);
pub const FRAME_OUT_UUID: u128 = uuid(0x0003);

/// Iterator over header-prefixed segments of one frame.
/// `seg_payload` is the usable ATT payload minus the header octet;
/// callers derive it from the negotiated ATT_MTU (mtu - 3 - 1).
pub fn segments(frame: &[u8], seg_payload: usize)
    -> impl Iterator<Item = Segment<'_>>;
/// One segment: `header()` byte + `payload()` slice; `write_to(buf)`.
pub struct Segment<'a> { /* sar, payload */ }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError { ReservedBits, Orphan, TooLong, Runt }

/// Per-characteristic reassembler; `N` bounds the reassembled frame.
pub struct Reassembler<const N: usize> { /* buf, len, in_progress */ }
impl<const N: usize> Reassembler<N> {
    pub const fn new() -> Self;
    pub fn reset(&mut self);
    /// Push one segment (a whole ATT value). Returns a completed
    /// frame, an error (state already reset), or None.
    pub fn push(&mut self, segment: &[u8])
        -> Option<Result<&[u8], DecodeError>>;
}
~~~

Semantics exactly per spec §Segmentation/§Reassembly: `COMPLETE`/
`FIRST` discard any partial frame and start fresh; `CONT`/`LAST`
without a frame in progress → `Orphan`; nonzero reserved bits →
`ReservedBits`; overflow → `TooLong` reported once, subsequent
`CONT`/`LAST` silently ignored until the next `COMPLETE`/`FIRST`.
Empty segment *payloads* are legal, but a zero-length ATT value has
no header octet and is a `Runt`: error, reassembly reset (per spec).
`segments()` requires `seg_payload >= 1` with an **unconditional**
assert (callers derive it from ATT_MTU, whose 23-octet floor yields
19); the host configuration override is validated before constructing
the link. A zero value must fail at that boundary in debug and release
builds, never produce an infinite iterator or reach `chunks(0)`.

**Tests** (mirror the `hdlc` suite):

- round-trip at seg_payload 19 (ATT_MTU 23), 243 (247), 511 (517);
- single-`COMPLETE` frame; frame exactly filling *n* segments; empty
  frame; empty middle segment;
- reserved-bit rejection; `Orphan` cont/last; `Runt` (zero-length
  segment) mid-reassembly and at idle; `FIRST` mid-reassembly
  discards and restarts; overflow then recovery;
- `segments()` with `seg_payload` of 1, and the `seg_payload == 0`
  assertion in both debug and release-style builds;
- `uuid()` spot-check against the spec table's three literal UUIDs.

**Exit criteria.** `cargo test -p umsh-companion` green; module doc
cross-references the spec chapter.

## Phase B — host: framing refactor + BLE central

### B1 — make `CompanionRadio` framing-pluggable

Today `CompanionRadio<IO: AsyncRead + AsyncWrite + Unpin>` owns an
`hdlc::Decoder<WIRE_BUF>` and does byte I/O in `send_frame_buf` /
`read_more`. Extract the byte/framing layer behind a frame-oriented
link trait; everything above (`ingest`, transactions, queues, `Radio`
impl) already thinks in frames.

~~~rust
pub trait FrameLink {
    /// Send one companion frame.
    async fn send_frame(&mut self, frame: &[u8])
        -> Result<(), CompanionRadioError>;
    /// Receive the next complete companion frame. Must be
    /// cancel-safe: dropping the future mid-frame must not lose
    /// buffered partial state.
    async fn recv_frame(&mut self)
        -> Result<Vec<u8>, CompanionRadioError>;
}
~~~

- `SerialFrameLink<IO>`: owns the `hdlc::Decoder<WIRE_BUF>` +
  `READ_CHUNK` buffer **and persistent `read_pos`/`read_len` cursors**.
  `recv_frame` loops buffered-bytes→decode→read until a frame
  completes. If one read contains the end of one frame plus bytes of
  the next, the unread tail remains in the struct for the next call;
  returning a frame never discards it. Partial decoder and read-buffer
  state both live in the struct, making cancellation safe.
  `send_frame` = today's `send_frame_buf` body.
- `CompanionRadio<L: FrameLink>`: `ingest(&[u8])` becomes
  `ingest_frame(&[u8])` (drop the per-byte loop); `read_more` becomes
  `recv_frame` + `tokio::time::timeout` at the call sites that hold
  the deadline.
- `open_serial` keeps its exact signature and the `serial-radio`
  feature; it returns
  `CompanionRadio<SerialFrameLink<tokio_serial::SerialStream>>`.

Regression gate before B2: `cargo test -p umsh`, plus
`companion_probe` against real T-Echo hardware over USB.

### B2 — `BleFrameLink` (btleplug)

New `ble-radio` feature: `ble-radio = ["tokio-support",
"dep:btleplug"]`; macOS and Linux are the supported targets, Windows
best-effort.

- **Discovery/connect**: scan for `gatt::SERVICE_UUID`; selector is
  "only one found" / name substring / platform id string.
  `CompanionRadio::open_ble(selector, config)` mirrors `open_serial`.
- **Attach**: connect → discover services → subscribe to Frame Out.
  The subscription (CCCD write) is the attach edge; the NCP resets its
  session silently, so `CompanionRadio::new` proceeds directly to its
  normal `CMD_RST` handshake. Pairing is OS-mediated: the first
  security-gated operation triggers the platform pairing flow (macOS
  prompts; Linux needs a BlueZ agent — document the `bluetoothctl`
  pair/PIN flow in the example's help text).
- **recv path**: btleplug's notification stream feeds a
  `tokio::sync::mpsc`; `recv_frame` drains it through
  `gatt::Reassembler<{ gatt::MAX_FRAME }>`.
- **send path**: `gatt::segments(frame, seg_payload)` written with
  `WriteType::WithResponse` (the response is our flow control, per
  spec). btleplug does not portably expose the negotiated ATT_MTU, so
  `seg_payload` defaults to **19** (the ATT 23-octet floor — always
  correct, merely chatty) with a config override; B2 investigates
  per-platform MTU discovery and raises the default where reliable.
  Host→NCP frames are small (commands; STR_SEND ≤ ~270 octets ≈ 14
  writes worst-case), and the NCP→host direction — the bulk of
  traffic — segments at the *NCP's* true ATT MTU, so the conservative
  default costs little.
- **Disconnect** surfaces as `CompanionRadioError::Disconnected`.

### B3 — examples and operational tools

`companion_probe` and `desktop_chat` accept `--ble [selector]` as an
alternative to the serial path, gated on the `ble-radio` feature
(new `[[example]] required-features` entries).

`umsh-capture` provides a BLE-first live RF inspection tool: it prints raw
LoRa frames and receive metadata, attempts a UMSH decode without discarding
foreign traffic (or suppresses it with `--umsh-only`), and periodically reads
`PROP_PHY_RSSI` so an idle RF channel is distinguishable from a stalled
BLE/NCP/radio path. It is a package binary rather than an example because live
frame inspection and soak diagnostics are maintained operational tooling. It
can also write portable Ethernet/UDP pcaps containing radio frames, raw
companion-protocol frames, or both; the Wireshark plugin dissects both layers.
A radio-only raw mode writes exact LoRa bytes with a caller-selected private
pcap `LINKTYPE` value.

**Exit criteria.** Loopback unit tests for `SerialFrameLink` parity,
including two frames returned by one underlying read, a frame boundary
with a partial successor, and cancellation with buffered tail bytes;
`companion_probe --ble` connects, bonds, and completes the property
handshake against the Phase C firmware (this criterion lands with C).

## Phase C — NCP firmware integration

All in `firmware/companion-ncp-techo`. C1 is a pure refactor verified
on USB alone; BLE code first appears in C2.

### C1 — framing out of `ncp_task` (USB-only refactor)

Today `ncp_task` owns the HDLC decoder and the `Emitter` HDLC-encodes
at emit time (`OUTPUT_CH` carries 64-byte wire chunks). Move framing
to the transport edges so `ncp_task` deals only in companion frames:

- `INPUT_CH` item becomes:

  ~~~rust
  const FRAME_IN_MAX: usize = 300;
  enum Transport { Usb, Ble }
  enum InEvent {
      Attached(Transport),
      Detached(Transport),
      Frame(Transport, heapless::Vec<u8, FRAME_IN_MAX>),
  }
  ~~~

- `usb_in_task` owns the `hdlc::Decoder<FRAME_IN_MAX>`; emits
  `Attached`/`Detached` on connection edges and whole frames
  otherwise. Decode errors are dropped there (as today).
- `Emitter` stages **raw** frames; `flush` sends them to
  `OUT_USB_CH: Channel<_, heapless::Vec<u8, FRAME_IN_MAX>, 4>`.
- `output_task` HDLC-encodes (keeps `WIRE_MAX`) and chunks to 64-byte
  USB packets.
- `ncp_task` keeps the session-reset-on-attach and decoder-free logic.

Verify on hardware: `companion_probe` + `desktop_chat` over USB behave
identically. Commit before any BLE code.

### C2 — BLE stack + companion service

From the Phase 0 spike, into the real firmware:

- `main`: switch to `clocks::ble_config()`; init MPSL + SDC with the
  spike's priorities and memory pool; spawn `mpsl_task`/`ble_task`.
- `ble_task` owns: the trouble GATT server (Companion Link Service,
  Frame In write + write-without-response, Frame Out notify + CCCD;
  all access encrypted+bonded), advertising, and per-connection state.
- Inbound: Frame In writes → `gatt::Reassembler<512>` (the spec's
  service maximum) → `InEvent::Frame(Transport::Ble, ..)`. A
  reassembled frame larger than `FRAME_IN_MAX` is **dropped whole**,
  never truncated — the transport carries frames unchanged or not at
  all, and truncation could turn oversize input into a different
  valid command. CCCD
  subscribe on a link that meets security → `Attached(Ble)`;
  disconnect or unsubscribe → `Detached(Ble)`.
- Outbound: `OUT_BLE_CH` (same shape as `OUT_USB_CH`); `ble_task`
  segments at the connection's real ATT MTU via `gatt::segments` and
  notifies. If the host is gone mid-frame the remainder is dropped
  with the connection (reassembly resets on detach per spec).

### C3 — transport arbitration + advertising policy

In `ncp_task`, one place, with a **session generation counter** so a
displaced session's state can never leak into its successor:

- `active: Option<Transport>` plus `gen: u32`, published as
  `SESSION_GEN: AtomicU32`.
- `Attached(t)`: `gen += 1`, session reset (existing path),
  `active = Some(t)`. The displaced transport gets an explicit
  logical detach, not an assumption that it will notice on its own:
  BLE is told to disconnect; USB gets no physical edge when displaced,
  so `usb_in_task` compares `SESSION_GEN` against its local copy at
  the top of each read iteration and resets its HDLC decoder on
  change (a partial frame can therefore never straddle sessions).
- Output purge: every frame queued to `OUT_USB_CH`/`OUT_BLE_CH` is
  tagged `(gen, frame)`; the consuming output task drops frames whose
  generation is stale. Responses and radio frames queued for a
  displaced session are thereby discarded rather than delivered to
  the displaced host or, worse, to the next session on that
  transport. The generation is checked again **between every USB HDLC
  chunk and every BLE SAR segment**; if it changes while a frame is in
  flight, the transport aborts the remainder immediately. A dequeue-
  time check alone is insufficient because displacement can occur
  during a multi-chunk/multi-segment send.
- `Frame(t, ..)` where `Some(t) != active` → dropped. Frames emitted
  while `active == None` → dropped (nothing is attached to receive
  them).
- `Detached(t)` where `t == active` → `active = None`.
- Advertising is gated **only** by attach state, never by pairing
  mode or bond state (spec §Advertising: bonded hosts must be able to
  reconnect at any time). An `embassy_sync::watch` carries
  `adv_allowed = (active != Some(Usb))` to `ble_task`; a live BLE
  connection stops advertising as a side effect of being connected.

Policy truth table:

| USB session | BLE state    | Advertising | New pairing accepted |
|---|---|---|---|
| open  | —            | no  | n/a (adv off; existing bonds could still connect if implementation allows, then displace USB on subscribe) |
| —     | attached     | no (connected) | n/a |
| none  | disconnected | yes | only per pairing-mode/PIN/OOB rules |
| none  | connected, not yet attached | no (connected) | per pairing-mode/PIN/OOB rules |

### C4 — pairing mode, display UI, lockout, PIN property

- **Pairing-mode state machine** in `ble_task`:
  - Entry at boot: no bonds → auto pairing mode, 30 s timer. Bonds
    present → only after the user explicitly requests pairing from the
    T-Echo's on-screen BLE UI.
  - The e-paper display presents bond count, pairing state, Start Pairing, and
    Clear Bonds. The side button mapping is single press = forward, double
    press = select, release after a 1-second hold = backward, and a continuing
    4-second hold = power off. The second threshold extends the proven T-1000E
    recognizer without changing its default behavior. The capacitive touch
    button retains its board-conventional backlight-toggle role and is not a
    hidden pairing gesture.
  - Exit: new bond completes | bonded host establishes an encrypted
    connection | timer expiry.
  - Pairing acceptance is the fork's gate, driven from one place (with D's
    capacity term included once persistence lands): `pairing_enabled =
    bond_count < 4 && (pairing_mode || (pin_configured && !locked_out))`.
  - LED: add a pairing-mode pattern to `LedEngine` timings.
- **Lockout**: failed-pairing counter in `ble_task` (RAM; resets on a
  successful pairing or reboot). At 3, `locked_out = true` — the gate
  formula above then rejects *all* pairing until power cycle; once
  locked, a pairing cannot succeed and therefore cannot clear the
  lockout.
- **`PROP_BLE_PAIRING_PIN` (4864)** — deferred completion, mirroring
  the existing `PROP_PHY_RSSI` pattern (`Effect::SampleRssi { tid }` →
  `Session::respond_rssi`):
  - `umsh-companion/src/ids.rs`: `pub const BLE_PAIRING_PIN: u32 =
    4864;` under `prop`.
  - `Session::prop_set`: validate (empty = clear, or `UINT32_LE` ≤
    999 999, else `STATUS_INVALID_ARGUMENT`), then return
    `Effect::SetPairingPin { tid, pin: Option<u32> }` **without
    emitting any response yet**. In Phase C the firmware applies the
    RAM-only SMP configuration; from Phase D it first commits the new
    value and then publishes it to the live SMP state. It then calls
    `Session::respond_pin_set(tid, result, emit)`, which emits
    `CMD_PROP_IS PROP_LAST_STATUS` with `STATUS_OK` on success or
    `STATUS_INTERNAL_ERROR` on apply/commit failure (per spec: this
    property is never echoed, and success is not reported before the
    value is applied and durably stored). **No PIN state is stored in
    `Session`** — the PIN survives `CMD_RST` by design, so its
    authority lives in the firmware/persistence layer.
  - `Session::prop_get` for 4864: `STATUS_UNIMPLEMENTED`, without
    revealing whether a PIN is set (i.e., the same answer always).
  - Host side: `CompanionRadio::finish_prop_transaction` currently
    treats any `PROP_LAST_STATUS` response as an error. Give the
    transaction helper an explicit expected-response policy (or a
    dedicated write-only setter) so **only** operations specified to
    use status-only completion—here, `PROP_BLE_PAIRING_PIN`—accept
    `STATUS_OK` as success carrying no value. Ordinary property gets
    and sets must still require `CMD_PROP_IS` for their requested key;
    a status-only `OK` there is a protocol violation, not success.
  - Firmware: `Effect::SetPairingPin` routes to `ble_task`; when a
    PIN is set, the SMP responder uses IO capability `DisplayOnly`
    with the static passkey; when unset, `NoInputNoOutput` (Just
    Works). RAM-only until Phase D (the apply step completes
    immediately; the effect/respond round-trip shape is the same, so
    Phase D only inserts the flash commit).
  - Lockout accounting per spec: the counter increments **only** on
    passkey authentication failures (LESC confirm-value / DHKey check
    failures); legacy-pairing rejections, pairing refused outside
    pairing mode, and malformed SMP traffic do not count (remote
    DoS resistance); reset on successful pairing or power cycle.
  - Session tests: set/clear/range validation, no premature response,
    `respond_pin_set` success and failure paths, get-refusal, and
    `CMD_RST` *not* emitting any PIN-related effect.

**Exit criteria.** `companion_probe --ble` and `desktop_chat --ble`
pass against the T-Echo; USB regression unchanged; displacement test:
attach over USB mid-BLE-session and vice versa, verifying the
displaced side receives nothing further (no stale generation frames)
and both transports re-attach cleanly afterward; force displacement
in the middle of a multi-chunk USB frame and a multi-segment BLE frame
to exercise the send-loop generation checks; nRF Connect
verification: unencrypted characteristic access refused, pairing
refused outside pairing mode, lockout trips at 3 authentication
failures (and only authentication failures) and clears on power
cycle; a successful pairing also resets a nonzero failure count;
bonded reconnect kills pairing mode.

## Phase D — persistence

- Storage region per [firmware-storage-plan.md](firmware-storage-plan.md):
  sequential-storage on internal NVMC, 64 KB at the top of the app
  window; shrink `FLASH LENGTH` in this firmware's `memory.x`
  accordingly.
- NVMC writes stall the CPU and violate BLE timing: all flash ops go
  through the MPSL-coordinated flash interface (`nrf-mpsl` flash
  feature). This firmware persists nothing else, so this is the only
  flash/BLE interaction.
- Persist: bond store (identity keys + LTKs; cap 4 bonds — at
  capacity, new pairing fails per spec §Bond Management) and the
  pairing PIN (write-only at the protocol; never logged or echoed in
  diagnostics). PIN updates are transactional: validate, commit the
  new value with the MPSL-coordinated flash interface, then publish it
  to the live SMP state through an infallible assignment. Until the
  commit succeeds, the previous live PIN remains in effect;
  `respond_pin_set` reports `STATUS_INTERNAL_ERROR` on failure. The
  storage record format/commit protocol must also make power loss at
  any point select either the complete old value or the complete new
  value on reboot, never a partial record.
- The runtime pairing gate tracks the number of durably stored bonds. At four
  bonds it rejects pairing before constructing an SMP state machine, even when
  pairing mode or a static PIN would otherwise enable pairing; a successful
  local wipe immediately reopens capacity. Host policy tests cover every term
  in this combined gate.
- Bond persistence failure is fail-closed. A newly completed SMP bond
  is not eligible to attach until its keys have been committed. If
  that commit fails, disconnect the peer and delete the volatile bond
  from the controller/host store so it cannot use an apparently valid
  but non-durable bond for characteristic access. Capacity is checked
  before accepting a new pairing.
- Local bond deletion (spec requirement) is an explicit destructive action
  in the T-Echo's on-screen BLE UI. It must display what will be cleared and
  require confirmation before clearing bonds and the PIN. A boot-time
  hold-duration gesture is reserved for screenless devices and is not used
  on the T-Echo.

**Exit criteria.** Bonds and PIN survive power cycles; reconnection
after power cycle needs no re-pairing; on-screen wipe flow verified; BLE
connection stays up across a persistence write burst; injected PIN-
and bond-write failures preserve the previous PIN, reject the new
bond, and leave storage recoverable after an immediate power cycle.

## Phase E — hardware validation and polish

- `companion_link_soak` is the repeatable, non-mutating control-plane harness
  for this phase. It supports serial and BLE selectors, configurable duration,
  interval, and BLE segment payload, and emits attach latency plus CSV
  property-round-trip samples and min/average/max summaries. It does not send
  LoRa traffic; `desktop_chat` remains the end-to-end live-traffic soak.
- Soak: `desktop_chat --ble` for hours alongside live LoRa traffic;
  watch for WDT resets, missed TX confirmations, MAC-timer slippage
  from connection-interval latency.
- Measure and record: attach latency; frame round-trip at ATT MTU
  23 / 185 / 247; idle current added by advertising and by a
  maintained connection; throughput vs. USB.
- Supervision-timeout behavior: walk out of range mid-session; clean
  detach + re-attach; verify `ncp_task` arbitration state recovers.
- Update: spec chapter if reality diverged (connection parameters
  especially), firmware header-comment task layout, project memory.

## Dependency pinning

Git revisions for `trouble-host`, `nrf-sdc`, `nrf-mpsl` are pinned in
the workspace at Phase 0 and only moved deliberately (same policy as
the `lora-phy` patch).

**License check (2026-07-13).** The Rust `nrf-sdc`/`nrf-mpsl` wrappers
are MIT OR Apache-2.0. Nordic's linked SDC and MPSL archives are instead
under `LicenseRef-Nordic-5-Clause`: redistribution is permitted, use is
restricted to Nordic ICs, the binaries may not be reverse engineered,
and the notice/disclaimer conditions apply (binary redistribution
embedded in a Nordic product/software update has the license's explicit
notice exception). This T-Echo target is an nRF52840, so the intended
firmware use is permitted, but the Nordic binary components are not
relicensed MIT/Apache-2.0; release/SBOM materials must preserve their
Nordic license identity and required notices.

## Risks

| Risk | Mitigation |
|---|---|
| trouble SMP gaps beyond the audited one (static passkey or bond export misbehave on hardware) | Phase 0 validates on the fork; last-resort fallback documented above. |
| Fork maintenance: upstream rejects or reshapes the pairing-policy patch | Patch is small and isolated (one gate + one SMP response); upstream PR opened in parallel at Phase 0; converge on upstream's shape at the next deliberate pin move; `lora-phy` fork precedent. |
| nrf-sdc forces an embassy version bump across the workspace | Absorbed in Phase 0, in the spike, before any real firmware changes. |
| SDC + trouble flash/RAM footprint | Measured at Phase 0; NCP firmware is small today; 760 K window. |
| MPSL interrupt priorities vs. SPIM/USBD latency (SX1262 BUSY timing, CDC) | Phase 0 coexistence checks with the radio initialized; Phase E soak. |
| btleplug: no portable ATT MTU query | 19-octet conservative default host→NCP; NCP→host uses true MTU; config override; investigate per-platform in B2. |
| btleplug platform quirks (macOS UUID-not-MAC ids, BlueZ agent, Windows pairing) | B2 scopes macOS + Linux; document per-OS pairing flow; Windows best-effort. |
| T-Echo destructive bond-management action could be invoked accidentally | Clear Bonds defaults to Cancel and needs a visible choice change plus a second Select; core panel/navigation/momentary-touch/sleep behavior is hardware-validated, with a final end-to-end destructive-action pass retained in D. |
| SDC binary license | Checked before Phase C merges (see Dependency pinning). |

## Deferred (tracked, not planned here)

- L2CAP CoC binding (one SDU = one frame) once host platforms allow.
- Numeric-comparison ceremony beyond the initial T-Echo display UI.
- LESC OOB pairing (QR conveyance) — spec leaves room; format
  undefined until a device needs it.
- BLE on T1000E and Wio Tracker L1 — mechanical once companion-ncp-
  techo is proven; T1000E is factory-sealed, so it goes last.
- iOS/Android host library.
- RNG sharing story for future firmware that runs both BLE and the
  UMSH MAC on-device (SDC owns the RNG peripheral in this plan).

## Sequencing summary

| Phase | Depends on | Hardware needed | Gate |
|---|---|---|---|
| 0 spike | fork Patch 1 | T-Echo + phone | fork + stack validated on hardware |
| A wire crate | spec | none | tests green |
| B1 host refactor | A | T-Echo (USB regression) | probe over USB unchanged |
| B2/B3 host BLE | B1, A | none until C lands | compiles; loopback tests |
| C1 firmware refactor | — (parallel with A/B) | T-Echo | USB behavior identical |
| C2–C4 firmware BLE | 0, A, C1 | T-Echo + phone + host | probe/chat over BLE; security checklist |
| D persistence | C | T-Echo | bonds/PIN survive power cycle |
| E validation | C, D | full setup | soak + measurements recorded |

Phases A, B1, and C1 are independent of the Phase 0 outcome and can
proceed while the spike is underway; C2 is the first step that
consumes the spike's results.
