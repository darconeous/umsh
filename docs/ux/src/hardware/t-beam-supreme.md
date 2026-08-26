# LILYGO T-Beam Supreme

The T-Beam Supreme is a display tracker with a 128×64 emissive OLED, one BOOT
button, a GNSS receiver, a hardware wall clock, and an AXP2101 power management
IC that owns every rail on the board. It is the first board in the class where
the panel, the radio, the receiver, and the sensors are all switched supplies
rather than a fixed 3.3 V plane, and the first ESP32 board with a receiver and a
clock at all.

It carries the same interaction model as every other display tracker. What is
board-special is what power means here: the POWER key is an input to the PMIC
rather than a GPIO, "off" is a PMIC power-off rather than deep sleep, and the
board comes back on with no firmware involved.

## Implemented behavior

The menu is the three-level tree in
[Display Tracker Screens](../classes/display-tracker-screens.md), and this is
the first ESP32 board to show all of it: Status, Identity, and Settings at the
top, with Bluetooth, Radio, and — because a receiver is fitted — GNSS behind
Settings. Row 0 always names the device and carries the battery indicator, and
the entry under the cursor is drawn inverted across the whole row. The Status
page shows only state that departs from nominal, the Statistics page reports
radio activity since boot, and the indicator follows the shared
[battery rules](../interaction-model/status-and-feedback.md).

Four switches are settable from the panel: Bluetooth reachability
(`PROP_BLE_ENABLED`), frame forwarding, the receiver, and whether a fix updates
the identity cell. Each flips through the ULCP session rather than at the
subsystem, stays on its entry, and shows the new state there.

The battery indicator is fuller here than on the Heltec boards. The AXP2101
measures its own battery terminal, runs a fuel gauge, and knows which way
current is flowing, so the panel draws a real charging state rather than
withholding one. The level prefers the gauge and falls back to the
open-circuit-voltage table while the gauge is still unlearned. With no cell
installed, or before the first sample, the indicator says nothing rather than
guessing.

Row 0 also carries a clock, which no other ESP32 board can show. The time comes
from the PCF8563 at boot, from a trusted GNSS fix, or from a host writing
`PROP_TIME`; whenever the device does not know what time it is, the row is
simply absent. There is deliberately no placeholder, because a placeholder
would itself be an indication of the current time.

| Input | Meaning |
|---|---|
| Single BOOT click | Move forward to the next visible item |
| Double click | Select the visible item |
| Release after a 1–4 second hold | Move backward |
| Continue holding for 4 seconds | Power off (PMIC) |

The POWER key is not in that table. It reaches firmware only as an AXP2101
interrupt, and a press wakes the panel — it is not a menu control. Its own
four-second hold is the PMIC's hard power-off, which works with firmware
wedged and is deliberately left alone.

Clear bonds, in the Bluetooth submenu, opens a confirmation page defaulting to
Cancel, exactly as on the T-Echo. Pairing is a menu item rather than a bare
button press: a board this easy to lean on should not open a pairing window by
accident, and the menu makes the action visible before it happens.

### Display attention

The panel is emissive, so a lapse actually powers it down: dimmed at seven
seconds as a warning, dark at ten. A pairing window holds it awake for its
whole duration, because the OLED is the only place the pairing PIN is ever
shown.

Battery samples, bond-count changes, and the clock advancing a minute redraw
the panel while it is lit but never light it — the battery is sampled on a
timer and the clock moves on its own, so treating either as attention would
keep the display on forever. Button presses, BLE connection-state changes, and
POWER-key presses do wake it.

A gesture that begins against a dark panel only relights it and is otherwise
consumed. Waking happens on the press, and the panel is redrawn before it is
switched on, so a stale frame is never visible. Waking always lands on the
status page.

### Power off

The four-second hold passes through regardless of display state — a dark board
still has to be switchable off. The sequence is ordered:

1. The radio enters chip sleep, so it stops transmitting before its rail is
   cut.
2. The display renders “Powering off / hold to wake” and blanks. The panel's
   rail belongs to the PMIC and drops with the others in step 4, not here.
3. The board waits for the BOOT button to be released, feeding the watchdog
   throughout. This is not about wake sources — the PMIC handles waking — but
   about the strap: GPIO0 held low across the *next* power-on would drop the
   board into the ROM bootloader.
4. The switched rails go down, then the PMIC's soft power-off. If the PMIC
   refuses, the abandoned watchdog resets the board to a running state, which
   is worse than off but better than wedged.

Power-on needs no firmware at all: the POWER key tells the PMIC to restore its
rails.

Counter persistence needs no shutdown step: it is flushed as the MAC runs, so
nothing is buffered at power-off.

Implemented in [`firmware-esp32/firmware/esp32-tracker/src/main.rs`][src] — the
sources every ESP32 board shares, with this board selected by its
`board-tbeam-supreme` feature — over the shared
[`umsh-ux-display-tracker`][ux-crate] menu, attention, and gate modules.

## Notes and limitations

- **Not yet hardware-validated.** The image builds and the UX described here is
  implemented, but no part of it has run on a physical board. The hardware
  reference's validation checklist is the gate.
- The panel's I²C address is a population variable: 0x3C normally, 0x3D where a
  QMC6310N magnetometer occupies 0x3C. The firmware probes 0x3D first for
  exactly that reason — an ACK at 0x3C is not proof the display is there. A
  board whose panel never answers boots headless rather than failing.
- There is no firmware-owned status LED. The charge LED belongs to the PMIC's
  charger and the PPS LED to the receiver, so pairing mode is visible on the
  panel's pairing page and nowhere else.
- The 128×64 panel is too small for a scannable QR code, so Identity on this
  board is address text alone.
- Messages is not implemented on any board in the class: there is no
  device-side text store for the page to read.
- No locate alert. The board's only conspicuous output is the OLED, and the two
  LEDs it does have are not the firmware's to drive.
- Whether the PMIC's fuel gauge or the OCV estimate should be the primary level
  source long-term is an open question that only hardware can settle.
- The display timeout is a compile-time constant carried in a runtime-mutable
  config, so exposing it as a device property later is plumbing rather than
  redesign.

[src]: https://github.com/darconeous/umsh/blob/main/firmware-esp32/firmware/esp32-tracker/src/main.rs
[ux-crate]: https://github.com/darconeous/umsh/tree/main/crates/umsh-ux-display-tracker
