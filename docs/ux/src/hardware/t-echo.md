# LilyGO T-Echo

The T-Echo is a display tracker: it has a 200×200 e-paper screen, one side
button, a capacitive touch control used for the display light, and an RGB LED.
The standard model has no buzzer. The phone remains the primary UMSH interface,
but the display makes status and sensitive device actions visible.

## Implemented behavior

The e-paper menu is the three-level tree in
[Display Tracker Screens](../classes/display-tracker-screens.md): Status,
Identity, and Settings at the top, and Bluetooth, GNSS, and Radio behind
Settings. Every frame—menu, confirmation, and the transient message screens
alike—carries a header with the device name and a battery indicator.
The indicator follows the shared
[battery rules](../interaction-model/status-and-feedback.md): a four-segment
body, no body at all when there is no level, and a bolt whenever the pack is on
external power.

The Status page shows only what departs from nominal. A pairing PIN appears
while a window is open, and a line naming the link appears when a host is
connected or when advertising is suppressed; a closed pairing window and
ordinary advertising say nothing at all, because they are what the board does
whenever nothing is happening. What remains on a resting device is one
diagnostic line giving pack voltage and, when it is known, charge level.

The Identity page shows the device's 44-character Base58 address, wrapped
across three rows with the four-character node hint above it. The QR code the
spec wants here is not implemented; see below.

The Statistics page, at the bottom of the Radio submenu, reports what the radio
has actually done since boot: frames
transmitted and received, frames repeated onward, receptions that went
nowhere, the configured transmit power, and duty-cycle usage. It is sampled
when a frame is drawn rather than pushed, so watching it costs no extra panel
refreshes.

Clear bonds, in the Bluetooth submenu, names the count it would destroy—"Clear
3 bonds?"—which is where that number changes a decision.

Four switches are settable from the panel: Bluetooth reachability
(`PROP_BLE_ENABLED`), the GNSS receiver, whether position is shared, and frame
forwarding. Each flips through the ULCP session rather than at the subsystem, so
the property, an attached host, and the saved snapshot all see the same flip;
each stays on its entry and shows the new state there. Entries the board cannot
perform are absent, and a submenu with nothing in it does not appear.

The highlighted entry is drawn inverted across the whole row. The settings
levels are drawn as lists—every entry of the level at once—while the entries
with something to read (Status, Identity, Statistics) take the panel to
themselves.

| Input | Meaning |
|---|---|
| Single side-button click | Move forward to the next visible item |
| Double click | Select the visible item |
| Release after a 1–4 second hold | Move backward |
| Continue holding for 4 seconds | Controlled shutdown |
| Hold capacitive touch control | Turn on the e-paper light until release |

Clear bonds opens a visible confirmation page that defaults to Cancel. Either
forward or backward toggles the choice, and double-click selects it. The display
task serializes input with e-paper refresh, preventing Select from activating an
item that has not yet appeared. Before shutdown it renders “Sleeping / Good
night” and puts the panel to sleep.

The panel is persistent, so display attention lapsing never blanks it: thirty
seconds after the last input the menu returns to Status, dropping any open
confirmation. The panel itself stays readable.

A running locate alert both flashes the indicator LED and strobes the e-paper
backlight twice a second, and the screen says so. The backlight is by far the
most conspicuous output on this board, which is the whole point of an alert; it
is arbitrated, so the touch control behaves normally whenever no alert is
running. Any press during an alert cancels it instead of navigating—except the
four-second power-off hold, which always powers off.

### Charging

The board sees only VBUS presence—the charger's status line reaches no
GPIO—so it can tell that charging has started but never that it has finished.
Charging terminal voltage does not map through the discharge curve, and
without a completion signal there is no later moment to recalibrate against,
so for as long as the board is plugged in it has no state of charge at all.
The indicator therefore shows a bolt with no body beside it and never a plug,
the diagnostic row reads `chg` instead of a percentage, and `PROP_BATTERY`
omits the level while continuing to report voltage and charge state. A real
level returns on the first quiet sample after the charger goes away.

The capacitive touch control sits outside the attention and gate models
entirely. It is a momentary light for reading a bistable panel in the dark, not
a navigation control, so holding it neither counts as activity nor consumes a
gesture.

These are strong precedents for the general guidelines: use the display instead
of hidden pairing gestures, default destructive choices to Cancel, preserve an
always-available long power hold, and account for display latency.

Implemented in [`firmware/nrf52-tracker/src/main.rs`][techo-src] over the shared
[`umsh-ux-display-tracker`][ux-crate] menu, attention, and gate modules.

[techo-src]: https://github.com/darconeous/umsh/blob/main/firmware/nrf52-tracker/src/main.rs
[ux-crate]: https://github.com/darconeous/umsh/tree/main/crates/umsh-ux-display-tracker

## Recommended evolution

- Identity falls back to address text. At 200×200 this board is the one panel
  in the class that can carry a scannable `umsh:n:` symbol—about 110 px square
  below the header—and it should. No QR encoder exists in either workspace yet.
- Messages is not implemented. The device node's receive hook logs the payload
  and returns; there is no device-side text store for the page to read.
- Keep extending the default page toward glanceability: it carries battery,
  BLE connection, and pairing today; silence/attention state, where
  applicable, is still missing.
- Give the charging indicator a time-to-full estimate. It needs per-device
  calibration against the charge level at which the charge began, which is
  why the board currently says nothing beyond the bolt.
- Keep the capacitive control dedicated to illumination unless hardware testing
  shows it is reliable enough and clearly labeled for navigation.
- Treat persistent e-paper content as state: every shutdown, pairing timeout,
  and fatal error must leave a truthful final image.
