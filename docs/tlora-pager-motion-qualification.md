# T-LoRa Pager motion qualification

**Native capability gate: sufficient to proceed; release acceptance pending.**
The stock image supplies low-power activity and tilt interrupts, separate
movement episodes, and a fresh face-up verification opportunity during continued
movement. The implementation uses these demonstrated native events. Its
two-second stillness timer starts at the sensor's report, never at a guessed
physical stop time. An operator-timed two-second pause supplied only 1,014 ms of
reported stationary state; that pause is intentionally too short to rearm.
Physical rest may therefore need to last longer than two seconds. The 750 ms
ordinary-pickup latency target remains to be measured with actual display wake.

The motion-wake implementation has a hardware feasibility gate. The opt-in
`motion-qualification` build exercises the sensor while the normal tracker
services run. It does not advertise display motion wake, change display policy,
or add a saved setting. Normal builds use the same image with activity 63 and
tilt 48, and expose the saved Motion wake setting. With no registered consumer,
the adapter resets the hub to ROM. This also stops a diagnostic image left
running across an ESP32-only reflash.

## Reproducible configuration

- Board: LILYGO T-LoRa Pager, ESP32-S3, SX1262.
- BHI260AP: I²C address `0x28`, shared SDA GPIO3 / SCL GPIO2 bus at 400 kHz,
  interrupt GPIO8. See [LILYGO's wiring documentation](https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/docs/hardware/lilygo-t-lora-pager.md).
- Image: unchanged Bosch non-turbo RAM image at revision
  `177681d120ac42760c9f19505697ccd5c7103e87`; [asset provenance and checksum](../firmware-esp32/assets/bhi260/README.md).
- Host driver: [`umsh-bhi260`](../crates/umsh-bhi260), `no_std`, asynchronous
  `embedded-hal-async` I²C. Upload and FIFO transfers are at most 32 payload bytes;
  each transaction releases the shared bus.
- Host interrupt configuration: active-high level; status and debug responses
  do not assert the interrupt. Status commands use synchronous responses.
  Host Interface Control is `0x40`: bit 6 routes explicit timestamp requests to
  registers `0x26..0x2a`, without injecting packets into the status channel.
- The probe waits ten seconds after boot, runs for at most eight hours, then
  resets the sensor to ROM. Cleanup has a separate six-second deadline.

Build and flash with the repository targets:

```sh
make build-tlora-pager ESP32_CARGO_FLAGS='--offline --features motion-qualification'
make flash-tlora-pager ESP32_CARGO_FLAGS='--offline --features motion-qualification' ESPFLASH_PORT=/dev/cu.usbmodem101
```

Use Kermit to capture the timestamped `bhi260:` diagnostic lines. Start capture
before the ten-second delay expires. The serial port name is host-specific.

## Initial measurements, September 13, 2026

RAM upload and boot succeeded on the connected Pager: product `0x89`, revision 3,
ROM 5166, kernel 5991, user 5991. The physical-sensor bitmap is `0a 00 00 00 00 00
00 00`: internal accelerometer and gyroscope only.

The running image enumerates virtual sensors:
`1, 3, 4, 5, 6, 7, 10, 12, 13, 14, 15, 16, 28, 29, 31, 32, 37, 38, 48, 50,
52, 53, 55, 57, 59, 61, 63, 67, 69, 70, 75, 77, 94`.
Auxiliary low-power any-motion IDs 142 and 143 are absent. Presence of IDs 75 and
77 alone is not proof that they meet the required behavior.

Each candidate was independently enabled at rate 1, allowed 500 ms to settle,
queried through Physical Sensor Information, then disabled:

| Virtual sensor | Accelerometer mode / rate | Gyroscope mode / rate |
| --- | --- | --- |
| Stationary 75, motion 77 | Low Power Active / 50 Hz | Power Down / 0 Hz |
| Tilt 48, significant motion 55 | Low Power Active / 12.5 Hz | Power Down / 0 Hz |
| Wake gesture 57 | Active / 200 Hz | Power Down / 0 Hz |
| Glance 59, pickup 61, activity 63, wrist tilt 67, orientation 69/70 | Low Power Active / 50 Hz | Power Down / 0 Hz |

These are sensor-reported operating modes, not measured electrical current.
The field definitions come from the [Bosch datasheet](https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bhi260ap-ds000.pdf).

With the operator confirming that the Pager was lying face-up on the counter,
a one-second diagnostic window at 25 Hz returned 23 acceleration samples and
23 GPIO interrupt completions. Representative passthrough readings were
`[-31, 133, -3884]`, `[-26, 135, -3878]`, and `[-32, 134, -3882]`.
This establishes negative sensor Z for face-up on this unit. A screen-normal
positive-Z board convention must invert sensor Z. This initial capture did not
establish the X/Y mapping or remaining five faces; the later reading-angle test
below checks the Y direction. These raw counts are not calibrated g values.
This single operator-requested baseline is diagnostic, not periodic sensing.

During this capture the baseline window ended at host uptime 24,185 ms. No
further sensor events were logged before the probe deadline at 370,706 ms;
cleanup completed at 370,808 ms. Tracker messages continued during this interval.
The operator has not yet confirmed performing the requested movement sequence,
so the absence of motion events is not a failed pickup test or a completed
stationary acceptance test.

The qualification build passes `make build-tlora-pager` and its stack check:
54,844 bytes of main stack, largest individual frame 22,048 bytes, required
reserve 32,768 bytes. This is a narrow static margin; observed startup did not
produce a stack-guard fault, but sustained activity remains to be exercised.
The diagnostic build uses a two-entry queue of 176-byte log lines to retain the
stack reserve. Normal builds retain the existing diagnostic buffer sizes.
Discovery bursts can drop diagnostic lines and report `debug-dropped`; sensor
FIFO consumption itself is independent of the log queue. The initial pickup
retest produced FIFO activity at 355,991 ms but dropped four diagnostic lines.
That capture cannot establish whether a motion event was delivered. The revised
probe omits routine FIFO meta messages, keeps independent event totals, reads
back the armed configuration, and allows eight hours for operator testing.
It enables both stationary and motion detection before the test begins.
The confirmed pickup after the twenty-minute run occurred after its deadline;
it does not establish a detection failure. The longer diagnostic window only
changes the overall session deadline, not the one-second sampling limit or the
sensor's interrupt-driven idle behavior.
The next startup exposed a delayed orientation-69 event left over from the
candidate survey. The strict decoder rejected it and cleanup succeeded. The
probe now reloads the sensor firmware between the survey and the actual test,
then drains every startup FIFO transfer until empty under a bounded budget.

In the clean eight-hour run, configuration readback confirmed rate 1 and zero
batching latency for stationary 75, motion 77, and orientation 70. The initial
sample window ended at 28,141 ms with 23 samples and 23 GPIO wait completions.
Stationary detection arrived at 33,236 ms. The operator subsequently confirmed
a face-up pickup, ten-second hold, and set-down. Orientation 70 reported a change
from 0 to 2 at 287,323 ms, demonstrating that the FIFO/interrupt path was live,
but no motion-77 event or motion-triggered sample window was logged through
301,790 ms. No diagnostic drops or decoder failures were reported during this
test interval. Ordinary pickup is therefore not qualified with this configuration.

The operator's sustained-movement control test did produce motion 77 at
371,609 ms. The first orientation change in that movement sequence was at
368,501 ms: the motion interrupt arrived at least 3,108 ms after movement was
already observable, exceeding the 750 ms pickup target before orientation
verification could even begin. It started a one-second window with 23 samples,
which ended at 372,610 ms with totals `[1, 1, 8, 46]` for motion, stationary,
orientation, and acceleration. Native orientation events continued through
380,482 ms without further acceleration windows. Stationary 75 arrived at
387,223 ms, 6,741 ms after the last orientation change; this is not a precise
measurement from the instant physical movement stopped.

This confirms functioning sensor-generated motion and stationary events and a
bounded event-triggered sampling window, but the tested motion detector is too
slow for the agreed pickup behavior. The documented host configuration exposes
rate and batching latency, and the inspected BSX parameter interface exposes
calibration state and version; no documented motion dwell-time control was
found. This does not prove that every gesture in the image is unsuitable.
The next probe therefore adds native tilt 48, pickup 61, and activity 63, checks
the combined accelerometer/gyroscope modes, and records their individual events.
Only native movement/gesture events can start a sampling window. Activity's
initial "still started" report does not start one.

The combined gesture probe read back all six virtual sensors enabled at rate 1
with zero latency. Physical Sensor Information still reported the accelerometer
in Low Power Active mode at 50 Hz and the gyroscope in Power Down at 0 Hz.
Its baseline window stopped with 23 samples; activity reported `[0, 1]` (still
started) without opening another window, followed by a stationary event.
During the operator-confirmed pickup test, activity 63 emitted "still ended"
and started bounded acceleration windows while motion 77, pickup 61, and tilt
48 remained silent. The latest two activity transitions started at 1,446,662 ms
and 1,456,875 ms, 10,213 ms apart, consistent with the requested pickup and
ten-second hold before set-down. Both windows produced 23 samples and stopped
after one second. Samples retained negative screen-normal Z and showed physical
movement. Activity reported "still started" at 1,451,802 and 1,461,000 ms,
respectively 5,140 and 4,125 ms after "still ended". These intervals include
physical movement time and do not establish exact detection latency.

Activity is therefore a viable source of native movement interrupts for further
qualification; the stock image cannot yet be ruled out solely because motion
77 is slow. Its ability to rearm after only two seconds still remains unverified.
A controlled pair of pickups separated by an operator-timed two-second rest
produced two distinct activity "still ended" events at 3,064,153 and 3,070,306 ms.
Each opened and completed a 23-sample, one-second window. Activity "still
started" arrived at 3,069,292 ms between the two movements, and again at
3,075,446 ms afterward. Thus the hub distinguished the two episodes, but the
reported still interval between the first still event and second movement was
only 1,014 ms. The physical two-second pause is operator-timed, and these events
alone do not prove two seconds of timestamped stationary state for a policy
timer. That timing distinction remains a qualification issue, not a reason to
silently shorten the agreed two-second requirement.

The operator-confirmed sideways-to-screen-up test during continued movement
produced activity at 3,217,556 ms, a tilt event with sideways/disturbed samples at
3,221,336 ms, motion at 3,227,472 ms, then a second tilt at 3,229,646 ms. That
second tilt opened a new 23-sample window with negative, dominant Z readings
consistent with screen-up. Activity did not repeat during the tilt sequence;
it reported stillness at 3,241,177 ms, followed by stationary 75 at 3,242,579 ms.
This demonstrates a native interrupt path for the broad pocket-removal gesture.
It does not establish exact 30°/40° boundaries, two seconds continuously outside
the range, or a fresh interrupt for every small boundary crossing.

Implementation proceeds with conservative sensor-reported stillness timing.
Continuous host sampling is not a fallback. No GPS power automation is enabled.

The driver tests cover bounded startup and command waits,
firmware chunking, response validation, configuration encoding, fragmented FIFO
transfers, independent timestamps, rollover, backwards time, overflow/reset
invalidation, and unknown-frame rejection. Formatting and `git diff --check`
pass. GPIO behavior and application recovery still require hardware acceptance.
After the probe, USB control remained responsive; identity, saved-snapshot
presence, radio settings, BLE/GNSS enables, and advert/beacon intervals matched
the pre-flash baseline. GNSS and battery telemetry remained responsive.

## Remaining hardware acceptance

Actual interrupt timing, stationary rearming, continued movement, orientation
transitions, and mounting axes require physical tests. Whole-board current and
light sleep have not been qualified. The existing Pager application holds a
permanent wake lock for rotary encoder capture; this must be resolved while
preserving encoder behavior before claiming successful application light sleep.

The outside-cone rearming timer remembers the last confidently observed outside
orientation until contradicted by a new measurement; the hub's tilt event starts
fresh verification on rotation. This does not prove every intermediate physical
orientation. A wake always requires 200 ms of fresh measurements within the
orientation range: 45° with the keyboard below the screen, 30° sideways or in
the opposite direction. Combined tilts share an elliptical allowance, with
55°/40° exit thresholds for rearming.
Fine-angle transitions, flat screen-up pocket movement, and rapid repeated
pickups require acceptance testing. Periodic host sampling is not a fallback.

## Screen-wake integration

Small bed vibrations reported by the operator exposed that a native activity
event followed by a steady screen-up hold could previously wake with no minimum
movement amplitude. The display policy now establishes a reference from the
first three valid filtered samples and requires a 120 mg vector excursion for
at least 80 ms in the same one-second verification window. It resets a partial
excursion when readings fall below that threshold. Stale, clipped, disturbed,
or discontinuous data clear the movement evidence along with orientation dwell.
Native activity publication, interrupt configuration, and sensing power demand
are unchanged; this suppresses display wakes rather than sensor interrupts.
The stock datasheet lists command 0x000F, Set Change Sensitivity, but does not
document an activity-63 threshold or units. No unqualified command is issued.
See the [Bosch datasheet](https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bhi260ap-ds000.pdf).

The initial 120 mg/80 ms choice requires physical bed-vibration and pickup
acceptance. Very slow or already-completed lifts may lack sufficient change
within the short window. No periodic sampling or GPS behavior is added.
The filter build is installed. A native activity window in its initial capture
ended after 23 samples with `used=false move=false`, suppressing screen wake.
The operator subsequently reported that the updated behavior "seems to work
better" in response to the bed-vibration/pickup comparison. This supports keeping
the current sensitivity for further use. The report is qualitative; no repeat
count, false-wake rate, or pickup-success rate has been measured.

The operator requested the wider reading angle after the initial 30° tests.
A keyboard-down hold produced negative Y in the original `[X, -Y, -Z]` adapter
coordinates (including `[325, -535, 695]` mg). The adapter now maps native
`[-X, Y, -Z]`: positive Y runs from keyboard to screen top, and positive Z points
out of the screen. The longitudinal sign is physically checked; the full six-face
audit, including the inferred X direction, remains pending. The shared policy
uses `3*x² + y² <= z²` for positive Y, and `3*(x² + y²) <= z²` otherwise,
with positive Z required. Both raw and filtered acceleration must qualify.
The widened policy is installed and both normal and diagnostic builds pass the
stack check with the results below. Startup capture shows successful wakes and
active/dim episode consumption. Operator confirmation specifically in the new
30–45° reading range remains pending.

The production adapter uses activity 63 and tilt 48, with both FIFOs drained
after a level-triggered GPIO8 wake. It samples sensor 1 at 25 Hz only in response
to native movement, stopping after qualification, stationary detection, or the
one-second deadline. Sensor timestamps are correlated through an explicit
hardware timestamp latch. Startup checks the internal-sensor bitmap and actual
accelerometer/gyroscope modes; faults clear candidates and permit at most two
timed retries, then wait for a consumer configuration change or reboot.

`umsh-motion` supplies the board-independent contract, shared observation watch,
independent consumer demand, and display policy. Location demand is reserved for
a future consumer; no GPS behavior changes. The display owner alone applies a
motion wake, and only to a fully lapsed display. ULCP capability 59 and property
4875 use the existing saved device-domain setting path.

The first integrated pickup test did not wake the screen. The service exhausted
its bounded recovery attempts. Inspection found that explicit timestamp
requests were issued while Host Interface Control bit 6 was clear: registers
still held the last IRQ time, and requests instead generated status packets.
The driver now selects request-latch mode and verifies the latch during startup.
See datasheet sections 12.1.7, 12.1.11, and 12.1.22.

The corrected image produced actual display wakes, confirmed by the operator.
The capture recorded movement-to-display intervals of 742, 382, 302, and 341 ms.
These intervals start at the sensor event timestamp, not physical pickup onset.
The operator reported that the wake point did not feel clearly predictable.
Some earlier verification windows began with sideways or strongly disturbed
acceleration; those initial samples alone do not establish why the full window
did not wake. Follow-up diagnostics distinguish expired windows from episodes
consumed while the display was already active or dim. End-to-end pickup latency
and predictable rearming remain open hardware acceptance items.

The follow-up diagnostic capture recorded activity 63 at 45,640 ms, a first
screen-up sample at 45,743 ms, and display wake at 45,983 ms (343 ms after the
sensor event). Another activity event at 50,778 ms opened a 23-sample window
that expired with the episode already consumed. That second movement did not
refresh display attention. A second screen-up event woke after 341 ms. The
operator reported wake during the level hold, approximately half a second after
lifting. Subsequent sideways windows expired without consuming the episode;
rotation back screen-up produced a tilt 48 event and wake 301 ms later. This is
promising functional evidence, not a measured end-to-end latency distribution.

After flashing, ULCP confirmed the original identity and name, an existing saved
snapshot, and unchanged BLE/GNSS enables. Live-only motion-wake Set/Get succeeded
for both false and true; the setting was left enabled without rewriting the
saved snapshot. The diagnostic serial capture was closed after the test.

Host validation: 19 driver tests and 10 policy/service tests pass. The policy tests
include directional 45° entry, opposite/sideways rejection, combined tilt, and
the 55° reading-direction exit hysteresis, small vibrations, isolated taps,
sensor offset, and a level pickup without rotation. The setting
test covers capability gating, BOOL rejection, local notifications, save,
restore, missing-property defaults, and reset. The display suite passes 116 of
117 tests, including motion attention behavior; the existing crowded-status-page
battery-row test remains failing. Host/mobile/runtime compilation and the T-Echo
firmware check pass. The normal Pager build passes its stack check; diagnostic
builds use a smaller best-effort log queue to preserve the same reserve.
Final normal-build stack results are 56,340 bytes available, a 21,872-byte
largest individual frame, and the required 32,768-byte reserve. The installed
diagnostic build reports 54,828 bytes, a 22,048-byte largest frame, and the same
reserve. Both builds pass; the diagnostic build has very little additional
headroom beyond that reserve.
