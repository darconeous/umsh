# SX1262 RX duty cycle: bench findings

**Status: not shipped.** Every board — nRF52 and ESP32 alike — runs
`RxStrategy::Continuous`. Preamble duty cycle (`SetRxDutyCycle` sniffing) was
enabled on all SX1262 boards on 2026-08-30, bench-debugged through eight
instrumented builds the same night, and withdrawn. This document records what
was measured so the work does not have to be rediscovered if the feature is
ever revisited.

The one-line verdict: the SX1262's raw preamble detector false-fires roughly
every other second in duty-cycle mode, and each false detection parks the
demodulator hunting a sync word — deaf to real frames — until the host
intervenes. Everything the host can do radio-side was tried and measured; the
best achievable configuration still loses ~1–2% of single-shot (unretried)
frames, versus effectively zero for continuous RX. That residual is structural,
not a bug in our driver.

## Why we wanted it

Continuous SX1262 RX with TCXO and `rx_boost` draws roughly 5–10 mA and is the
dominant battery load on every board without a hard power switch. The
duty-cycle sequencer sleeps the radio between short listen windows sized to
catch a 32-symbol transmit preamble, cutting radio RX draw roughly in half at
the final window sizing (50% nap) with no protocol change — the transmitter
does not need to know the receiver is sniffing. The T-Beam Supreme power work
(`SetRxDutyCycle` as "fix 3") introduced the mechanism on the ESP32 boards;
this session extended it to the nRF52 SX1262 boards (T-Echo, Wio Tracker L1,
Solar P1, XIAO nRF52840) and immediately hit a loss rate the ESP32 bringup —
which checked function, not loss percentage — had never counted.

The T-1000E was excluded throughout: its LR1110 needs a 16-symbol acquisition,
which leaves no sleep budget against a 32-symbol preamble.

## How the mode works

`SetRxDutyCycle(rxPeriod, sleepPeriod)` puts the chip in a hardware loop:
listen for `rxPeriod`, sleep for `sleepPeriod`, repeat, with both periods in
15.625 µs units. The listen window must be long enough for the preamble
detector to acquire (`det` = 8 symbols in our configuration, plus wake-up and
settle), and the sleep short enough that a window always lands inside a
transmit preamble with `det` symbols still to come:

```
rx    = det + 1 symbols        (base coverage rule)
sleep = tx − 2·det − 1 symbols (tx = transmit preamble length, 32)
```

All vetted UMSH profiles transmit 32 preamble symbols. The default profile
(umsh-us-ca) runs SF10/500 kHz, where a symbol is 2.048 ms, so the base sizing
is a 9-symbol (~18.4 ms) window and a 15-symbol (~30.7 ms) sleep.

On preamble detection the chip is supposed to stay in RX and receive the
frame. Two knobs interact with that:

- **`SetStopRxTimerOnPreamble`** — with it set (the lora-phy upstream
  default), preamble detection stops the RX timeout entirely and the chip
  waits indefinitely for a sync word/header. With it cleared, the timer keeps
  running as an escape hatch.
- **Datasheet §13.1.7** — says that on preamble detection in duty-cycle mode
  the timer restarts at `2·rxPeriod + sleepPeriod`, and warns that the whole
  frame must fit inside that deadline.

Both of those behaviors turned out to differ from the datasheet's implication
in ways that matter; see findings 2 and 3.

## Bench setup and instrumentation

- Path: iOS app → BLE → T-1000E (continuous RX, known clean) → RF → Wio
  Tracker L1 (device under test, running the duty-cycle build). Ping
  exchanges from the app; a missed response is a ~7–8 s app-side timeout.
- Profile umsh-us-ca, SF10/500 kHz, 32-symbol TX preamble, 8-symbol
  acquisition.
- Instrumentation: an `RxIrqStats` block of atomic counters in
  `umsh-radio-loraphy`, incremented per IRQ class in the runner and dumped as
  100 ms deltas over the `ble-debug` USB console
  (`radio-rx d_pre/d_hok/d_done/d_crc/d_hdr/d_tmo/d_none/d_err/d_arm/d_stall`).
  Captured with a detached `screen -L` session so nothing else touched the
  port.

The counters are what made the night productive: every theory below was
confirmed or killed by a specific counter signature, not by vibes.

## Chronology and findings

### 1. Zero-margin windows lose 5–15% (first flash)

The base `det + 1` sizing budgets less than one symbol of slack and nothing
for post-wake PLL/AGC/detector settling beyond the 5 ms TCXO allowance. First
flash on T-Echo and Wio dropped 5–15% of ping exchanges on both boards;
reverting to continuous fixed both. Adding `WINDOW_MARGIN_SYMS = 3` to the
window (taken out of sleep, cycle period unchanged — 12 symbols awake, 12
asleep) cut the loss to roughly one ping in 30. Real, but not the main story.

### 2. The §13.1.7 deadline theory — plausible, wrong

The datasheet deadline (`Tpreamble + Theader ≤ 2·rx + sleep`) was violated by
our sizing at SF10/500 (needed ~90.6 ms, had ~83.7 ms after the margin fix),
and the arithmetic even explained the dose-response of the margin change. A
fix that grew the window until the deadline held was built and flashed. It
made loss *worse*. Two reasons, both confirmed later:

- With `SetStopRxTimerOnPreamble` set, the restarted timer never runs at all,
  so the deadline is unreachable — the fix was inert against the mechanism it
  targeted.
- A longer listen window means more time in the false-detect-prone sniffing
  state (finding 4), so the change was actively harmful.

The window growth was reverted. Lesson: the deadline in §13.1.7 governs only
configurations that clear stop-on-preamble, and those are broken for a
different reason (finding 3).

### 3. Clearing stop-on-preamble silently kills real frames

With `SetStopRxTimerOnPreamble(false)` in duty-cycle mode, the escape timer
does run — but measurement showed two departures from what §13.1.7 implies:

- A valid header does **not** stop the timer. The timer keeps running through
  payload reception.
- In duty-cycle mode, timer expiry raises **no IRQ**. The chip abandons the
  frame mid-payload and goes back to sleep without telling the host anything.

The counter signature was unmistakable: `d_hok` (HeaderValid) with no
subsequent `d_done`, `d_tmo`, or anything else — a frame detected early in
the listen window dies silently partway through the payload. Stop-on-preamble
ON is therefore load-bearing for real frames and was restored (a warning
comment now sits in the fork's `do_rx`). The cost is that it protects false
detections just as faithfully — which is the root problem.

### 4. Root cause: false preamble detections camp the demodulator

With windows correctly sized and stop-on-preamble set, the counters showed
the true mechanism. In duty-cycle sniffing, the raw preamble detector fires
roughly once every couple of seconds with no transmitter on the air
(continuous RX shows no such behavior in months of use — the false fires are
presumably window-edge/AGC artifacts of repeatedly re-entering RX). Each
false fire, protected by stop-on-preamble, parks the demodulator hunting for
a sync word that never comes. While camped:

- real preambles arriving on the air re-fire the detector (`d_pre` counts
  them) but the demodulator never re-syncs — the frame is lost;
- nothing bounds the camp except the host's next re-arm, which in the
  original code happened only after unrelated traffic — hence the observed
  8–30 s deaf episodes and the original 5–15% loss.

Aggregate counters from the two long final captures make the rate concrete:
`pre=314 hok=119` and `pre=401 hok=157` — roughly **two of every three
preamble-detect IRQs were false**, and every one of them started a camp.

The fix that worked was host-side: a stall supervisor in the
`umsh-radio-loraphy` device runner. A lone PreambleDetected with no header
inside a ~110 ms budget (tx + 21 symbols), or a header with no completion
inside a worst-case-frame budget (~1.5 s), forces a re-arm and increments a
`stall` counter. To give the second budget a trigger, the lora-rs fork's
`IrqState` gained a `HeaderReceived` variant so the runner can distinguish
"detector fired" from "header landed." With the supervisor, camps are bounded
at ~110 ms and the final captures show `hok == done` exactly (119/119,
157/157): **once a header was received, no frame was ever lost.** The
supervisor fired about 5–6 times per capture — each one a rescued deaf
period.

### 5. Symbol-timeout validation is a dead end

The last radio-side idea: set `SetLoRaSymbNumTimeout` to the acquisition
length so the chip itself invalidates detections that don't produce a header,
starving false detects cheaply. Result: near-total RX loss (`d_done=2`
against `d_pre=9` in minutes of pinging — "most pings fail"). The validation
countdown evidently runs on top of detector spin-up rather than replacing it,
so legitimate detections get invalidated too. Reverted within minutes; the
fork carries a warning comment.

### Falsified along the way

- **Phantom DIO1 / `Ok(None)` re-arm hole**: the theory that a spurious IRQ
  read while the sequencer napped was killing duty cycle. `d_none=0` in every
  capture, all night. Never happened.
- **"Wio worse than T-Echo" asymmetry**: an artifact of unbounded camps
  interacting with link geometry and traffic patterns, not a board
  difference.

## What the rest of the ecosystem does

- **Meshtastic** calls RadioLib's `startReceiveDutyCycleAuto`, but its
  16-symbol transmit preamble makes RadioLib's sizing compute **zero sleep**
  — the call degenerates to continuous RX. Meshtastic is not actually
  duty-cycling on SX126x.
- **RadioLib**'s `calculateRxDutyCycle` sizes to the end of the preamble plus
  one symbol plus 1 ms — it does not attempt to cover the header, and its
  issue #1597 is this same failure class.
- **MeshCore** mainline is continuous-only; only forks attempt duty cycle.

Nobody in the neighborhood ships a working SX1262 preamble duty cycle against
a 32-symbol preamble. That is consistent with what we measured: the mode as
documented does not compose with stop-on-preamble semantics and a false-firing
detector, and the documented escape hatch destroys real frames.

## Best-achievable configuration

For the record, the configuration that produced the best numbers:

1. Coverage-sized windows with settle margin: `rx = det + 1 + 3` symbols,
   `sleep = tx − 2·det − 1 − 3` (12/12 symbols at the default profile, 50%
   nap).
2. `SetStopRxTimerOnPreamble(true)` — load-bearing, see finding 3.
3. Runner stall supervisor: ~110 ms detect budget, worst-case-frame header
   budget, forced re-arm on expiry.

Measured on the bench: zero loss once a header landed, camps bounded at
~110 ms, and a residual ~1–2% loss of single-shot pings that arrive during a
camp the supervisor has not yet cleared. Retried traffic (anything with MAC
acks and retries) rode through cleanly.

## Why it was not landed

The residual is invisible to retried traffic but permanent for unretried
probes, and it buys roughly half the radio's RX draw on boards where the radio
is only one consumer among several. The complexity bill was also real: a fork
divergence in lora-phy (`IrqState::HeaderReceived`), a timing dependency in
the radio crate, a supervisor with two tuned budgets, and a failure mode
(silent demodulator camping) that only counters can see. The decision was to
withdraw the change: all working-tree changes were stashed rather than
committed, and the ESP32 boards — which had been shipping the unbounded-camp
version of duty cycle since the T-Beam power work, uncounted — were switched
to `RxStrategy::Continuous` as well.

## If this is ever revisited

- Do not start from the datasheet. Findings 2 and 3 (timer not stopped by a
  valid header; expiry raises no IRQ in duty-cycle mode) contradict the
  natural reading of §13.1.7 and were measured directly.
- Do not retry the measured dead ends: window growth for the §13.1.7
  deadline, clearing stop-on-preamble, or `SetLoRaSymbNumTimeout` as a
  detection validator.
- The supervisor + header-gating design above is the radio-side ceiling.
  The remaining 1–2% has exactly one credible fix, and it is MAC-side: one
  retry for ping-class traffic turns a 2% loss into ~0.04%. If duty cycle
  ever ships, it should ship with that.
- Count everything. The functional bringup pass on ESP32 "validated" a
  configuration that was losing a few percent of frames the whole time. A
  loss-rate soak with IRQ counters should be the acceptance gate for any RX
  path change.
