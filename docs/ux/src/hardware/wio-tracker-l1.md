# Seeed Wio Tracker L1

The Wio Tracker L1 is a display tracker with a 128×64 emissive OLED, a four-way
pad with a center press, a Back button, a piezo buzzer, one indicator LED, and a
mechanical power switch. It is the first board in the family to combine an
emissive panel with a sounder, so it is also the first where a locate alert has
something loud to say and something bright to say it on.

This page covers the OLED variants—L1, L1 Pro, and L1 Lite share a pin map and
one firmware image. The L1 e-ink variant drives a different panel on a second SPI
bus and is not supported.

It is the only board in the family with enough controls to offer the optional
[Up, Down, and Back intents](../interaction-model/actions-and-navigation.md#display-tracker-navigation)
alongside the three every display tracker requires, and it does: no control on
this board carries more than one meaning.

Its GNSS receiver is driven, and is also the board's only clock: the module
sits on the battery rail with no enable, so its backup domain keeps time
through System OFF and the boot path reads it back. That does not extend to
the mechanical power switch, which is a hard battery disconnect.

## Implemented behavior

The menu is the three-level tree in
[Display Tracker Screens](../classes/display-tracker-screens.md): Status,
Identity, and Settings at the top, and Bluetooth, GNSS, and Radio behind
Settings. Row 0 always names the device and carries the battery indicator, and
the entry under the cursor is drawn inverted across the whole row, so the
current position is visible without remembering it. The indicator follows the
shared [battery rules](../interaction-model/status-and-feedback.md).

Five rows is not many, so the settings levels are drawn as lists—every entry of
the level at once, dropping the gesture hints when the list needs their rows—
while the entries with something to read, Status and Identity and Statistics,
take the panel to themselves. A list longer than the panel clips its last row
half-way rather than spending a column on a scroll bar: 21 characters to a row
is already the tightest budget in the class.

Four switches are settable from the panel: Bluetooth reachability
(`PROP_BLE_ENABLED`), the GNSS receiver, whether position is shared, and frame
forwarding. Each flips through the ULCP session rather than at the subsystem,
so the property, an attached host, and the saved snapshot all see the same
flip; each stays on its entry and shows the new state there.

The Status page spends its remaining rows only on state that departs from
nominal: a pairing PIN while a window is open, a link line when a host is
connected or advertising is suppressed, and a diagnostic line with pack
voltage and charge level. A closed pairing window and ordinary advertising
draw nothing, which is what leaves this five-row panel enough space to show
both gesture hints on the page users sit on.

The Identity page shows the device's 44-character Base58 address with the
four-character node hint above it. There is no room here for a scannable
symbol; see below.

The Statistics page, at the bottom of the Radio submenu, reports frames
transmitted and received, frames repeated onward, receptions that went nowhere,
transmit power, and duty-cycle usage—enough to tell a working node from a deaf
one without a capture.

| Input | Meaning |
|---|---|
| Pad down, pad right | Move forward to the next entry |
| Pad up, pad left | Move backward to the previous entry |
| Pad center press | Select the entry under the cursor |
| Back button | Leave the current level; at the top, return to Status |
| Back button held for 4 seconds | Power off |

Every control does one thing. All four pad directions walk the list—the pad is
how you move, whichever way the board happens to be held—and leaving a screen
is the Back button's job alone. The gesture hints at the bottom of a page name
these controls rather than the click counts a single-button board would show,
because a hint that names a gesture the hardware does not have is worse than no
hint at all.

Clear bonds opens a confirmation page defaulting to Cancel, exactly as on the
T-Echo and the Heltec V3. The question names the count it would destroy, the
pad picks between the two choices, and Back answers it with no.

### Charging

Like the T-Echo, this board sees only VBUS presence and never charge
completion, so while it is plugged in it has no trustworthy state of charge.
The indicator shows a bolt with no body beside it and never a plug, and
`PROP_BATTERY` omits the level while still reporting voltage and charge state.
A level returns on the first quiet sample after unplugging.

### Display attention

The panel is emissive, so a lapse actually powers it down: dimmed at seven
seconds as a warning, dark at ten. A pairing window holds it awake for its whole
duration, because the OLED is the only place the pairing PIN is ever shown, and a
running locate alert holds it awake for the same reason it holds the buzzer.

A press that begins against a dark panel only relights it and is otherwise
consumed—on the pad as much as on the button, since the rule is about what the
user could see, not about which control they reached for. Waking happens on the
press, not on the resolved gesture, so the panel is already lit while the user
is still deciding what a button press will become; the frame is redrawn before
the panel is switched on, so a stale frame is never visible. Waking always lands
on the status page.

Battery readings never light the panel—the battery is sampled on a timer, and
treating a timed sample as attention would keep the display on forever. When the
charge class or level moves the monitor asks for a redraw, which an already-lit
panel takes and a dark one ignores; either way the frame is built from the
monitor's latest published sample, so a fresh value arrives with the next redraw
whatever prompted it.

### Locate alert

The alert takes the whole panel and the buzzer together. The buzzer plays the
shared locate melody on a three-second repeat, the panel shows “Locate alert /
Press to stop”, and the indicator LED keeps its own alert blink. The first
press—any control, pad or button—cancels the alert rather than navigating:
whoever found the radio meant to silence it, not to open a menu.

### Power off

The four-second hold passes through regardless of display state—a dark board
still has to be switchable off. The board blanks the OLED, waits for the Back
button to be released (it is also the wake pin, and arming wake under a held
button would power straight back on), holds the radio in reset, drives the
battery divider gate off, tri-states the remaining peripheral signal pins
(including RXEN, so the external LNA is left unbiased), and enters System OFF
with the Back button armed as the wake source. A later press of that button
powers it back on; the pad does not wake it, which is the same one control the
board offers when the panel is dark.

Unlike the T-Echo, the T-1000E, and the SenseCAP Solar Node, this board has a
mechanical power switch, so software power-off is a convenience rather than the
only way to stop the drain. It still matters: it is what keeps the protective
low-battery cutoff from letting an unattended pack deep-discharge with the switch
left on. There is no board-wide peripheral rail to drop, which is why the radio
is parked by holding its reset line rather than by cutting its power—the same
approach the SenseCAP Solar Node takes.

Implemented in [`firmware/nrf52-tracker/src/main.rs`][src] over the shared
[`umsh-ux-display-tracker`][ux-crate] menu, attention, and gate modules, with the
panel, battery monitor, and buzzer in
[`umsh-bsp-wio-tracker-l1`][bsp].

## Notes and limitations

- The 128×64 panel is too small for a scannable QR code, so Identity here is
  address text alone.
- Messages is not implemented on any board in the class: there is no device-side
  text store for the page to read.
- Pad keys do not auto-repeat while held. No level in the tree is longer than
  four entries, so there is nothing yet to scroll through.
- There is no persisted silence preference, so the buzzer cannot be muted ahead
  of an alert the way the T-1000E's can.
- Whether the board populates a 32.768 kHz crystal is unconfirmed. The image
  assumes it does; if the BLE stack's clock configuration fails on hardware, the
  fix is the existing `lfclk-rc` feature.
- The battery divider constant is nominal, not a fitted calibration.

[src]: https://github.com/darconeous/umsh/blob/main/firmware/nrf52-tracker/src/main.rs
[ux-crate]: https://github.com/darconeous/umsh/tree/main/crates/umsh-ux-display-tracker
[bsp]: https://github.com/darconeous/umsh/tree/main/crates/umsh-bsp-wio-tracker-l1
