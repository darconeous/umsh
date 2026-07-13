# Companion Radio BLE Transport — Implementation Plan

*Drafted 2026-07-13. Phase measurements and the license check are
recorded inline as phases complete.*

## Implementation status — 2026-07-13

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
those actions through its display UI. After the hardware fixes,
its non-debug release image measures 371,998 bytes text, 6,104 bytes
data, and 37,940 bytes BSS (378,114-byte flash payload). On hardware it
completes the USB reset/property
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

Still open before declaring the hardware phases complete: exercise
fixed-PIN failures and lockout; run the Linux BlueZ pairing/recovery test;
and perform the 30-minute/long soak. macOS
CoreBluetooth discovery did find the service, but both discovery and
post-discovery operations can block indefinitely, so the host link now
bounds each `btleplug` await with explicit timeouts; macOS attach remains
to be completed after the phone security checks.

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
- The C4 lockout reuses the same gate: overall,
  `pairing_enabled = pairing_mode || (pin_configured && !locked_out)`.
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
On macOS the local build must ignore the developer's ESP-specific
`LIBCLANG_PATH` and give bindgen the active macOS SDK sysroot; this is a
host build-environment workaround, not a firmware dependency.
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

### B3 — examples

`companion_probe` and `desktop_chat` accept `--ble [selector]` as an
alternative to the serial path, gated on the `ble-radio` feature
(new `[[example]] required-features` entries).

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
  - The e-paper display presents pairing state and the pairing action;
    the user/touch controls operate that UI. This is an explicit visible
    interaction, not a hidden boot-time hold-duration gesture. The exact
    menu and control mapping must be defined with the rest of the T-Echo
    UI rather than borrowed from the screenless-device gesture FSM.
  - Exit: new bond completes | bonded host establishes an encrypted
    connection | timer expiry.
  - Pairing acceptance is the fork's gate, driven from one place:
    `pairing_enabled = pairing_mode || (pin_configured && !locked_out)`.
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
| T-Echo pairing/bond-management UI is not yet integrated into the NCP firmware | Reuse the proven e-paper driver, define the visible menu/control mapping explicitly, and validate pairing entry and destructive confirmation on hardware in C4/D. |
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
