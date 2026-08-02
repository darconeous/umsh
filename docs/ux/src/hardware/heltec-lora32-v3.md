# Heltec WiFi LoRa 32 V3

The Heltec V3 is a display tracker with a 128×64 emissive OLED, one PRG button,
and a single indicator LED. It has no buzzer and no second control. The panel is
powered from the switchable `Vext` rail, so turning the rail off removes OLED
power and the controller must be reset and re-initialized before it can be used
again.

It is a bench board rather than a field product, but it runs the same
interaction model as every other display tracker; nothing here is board-special
except the panel technology and what powering off means.

## Implemented behavior

The menu contains Status, Stats, Check in, Start pairing, and Clear bonds. Row
0 always names the device and carries the battery indicator, and row 1 always
shows the menu cursor, so the current position is visible without remembering
it. As on the other display trackers, the Status page shows only state that
departs from nominal, and the Stats page reports radio activity since boot.

No external-power signal reaches the S3 on this board, which is a different
thing from knowing the pack is discharging: the indicator therefore never
draws a charging bolt, and the level it shows is a plain open-circuit-voltage
lookup that reads high while the board is plugged in. The boards that can at
least see VBUS withdraw their level while charging; this one has no signal to
withdraw it on.

| Input | Meaning |
|---|---|
| Single PRG click | Move forward to the next visible item |
| Double click | Select the visible item |
| Release after a 1–4 second hold | Move backward |
| Continue holding for 4 seconds | Power off (deep sleep) |

Clear bonds opens a confirmation page defaulting to Cancel, exactly as on the
T-Echo. Pairing is a menu item rather than a bare button press: a board this
easy to lean on should not open a pairing window by accident, and the menu makes
the action visible before it happens.

### Display attention

The panel is emissive, so a lapse actually powers it down: dimmed at seven
seconds as a warning, dark at ten. A pairing window holds it awake for its whole
duration, because the OLED is the only place the pairing PIN is ever shown.

Battery samples and bond-count changes redraw the panel while it is lit but
never light it — the battery is sampled on a timer, so treating a sample as
attention would keep the display on forever. Button presses and BLE
connection-state changes do wake it.

A gesture that begins against a dark panel only relights it and is otherwise
consumed. Waking happens on the press, and the panel is redrawn before it is
switched on, so a stale frame is never visible. Waking always lands on the
status page.

### Power off

The four-second hold passes through regardless of display state — a dark board
still has to be switchable off. The sequence is ordered:

1. The radio enters chip sleep. It is powered from the board's main rail rather
   than from `Vext`, so it survives deep sleep and would otherwise sit in
   receive and dominate the sleeping current.
2. The display renders “Powering off / hold to wake”, blanks, and drops `Vext`.
3. The board waits for the button to be released before arming the wake source,
   feeding the watchdog throughout. Arming under a still-held button would wake
   the board from the very press that put it to sleep.
4. Deep sleep, waking on PRG.

Counter persistence needs no shutdown step: it is flushed as the MAC runs, so
nothing is buffered at power-off.

Implemented in [`firmware-esp32/firmware/heltec-v3/src/main.rs`][v3-src] over the
shared [`umsh-ux-display-tracker`][ux-crate] menu, attention, and gate modules.

## Notes and limitations

- No locate alert. The board's only conspicuous output is the OLED, and its
  permanent wired attach means a second host can be present while an alert runs.
- `Vext` stays powered while the display is merely lapsed. Only power-off drops
  the rail, because bringing it back requires a full reset and controller
  re-init rather than a resumed draw.
- The display timeout is a compile-time constant carried in a runtime-mutable
  config, so exposing it as a device property later is plumbing rather than
  redesign.

[v3-src]: https://github.com/darconeous/umsh/blob/main/firmware-esp32/firmware/heltec-v3/src/main.rs
[ux-crate]: https://github.com/darconeous/umsh/tree/main/crates/umsh-ux-display-tracker
