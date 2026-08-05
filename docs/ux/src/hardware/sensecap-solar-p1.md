# SenseCAP Solar Node P1

The Solar P1 is a headless outdoor node: two buttons, two LEDs, a GNSS
receiver, a solar panel, and no display or sounder of any kind. It is the only
board in the family that is meant to be installed rather than carried, and
almost every difference in its interaction model follows from that.

Two of those differences are worth stating up front, because they are the
opposite of what the other boards do.

The receiver **defaults to on**. Everywhere else `PROP_GNSS_ENABLED` starts
false, because a tracker in a pocket should not spend a cell finding out where
it is before anyone asks. This board has a panel and does not move, so the
arithmetic inverts: the load is the one it can see coming, and a node that has
to be told to find itself after every reset is the worse failure.

And the two buttons do not share work. On a single-button board every gesture
is a compromise; here PWR does power and USR does everything else, so neither
has to be.

## Buttons

| Button | Enclosure label | Pin | While running | From System OFF |
|---|---|---|---|---|
| Power | **PWR** | P1.01 | Hold ~1.5 s → power off. A short press does nothing. | Any press reaches the bootloader — see below |
| User | **USR** | P1.07 | Press → beacon, or cancel a running locate alert | Press → powers the node on. Held through boot → force pairing |

**PWR is not a wake button.** Any press of it while the node is in System OFF
— a bare tap, duration irrelevant — enters the stock bootloader's DFU mode
rather than starting the firmware. That is a property of the shipped
bootloader and nothing the application can intercept. USR is therefore the
only button that actually powers the node back on, and the operational
asymmetry is worth saying plainly: **hold PWR to turn it off, press USR to
turn it on.**

Because USR is also the wake press, the press that started the node is still
down when the firmware reaches its button task. It is consumed rather than
read as a beacon request, the same way the force-pairing ceremony has to
distinguish a deliberate hold from an ordinary power-on.

### The user button's primary action

A press asks the device node to beacon: a signed identity payload on the air,
carrying the node's position when the identity auto-update is enabled. This is
the shared primary-action slot the
[status and feedback](../interaction-model/status-and-feedback.md) rules
describe, and it confirms the same way — only when the MAC *accepts* the send.
A board with no identity has a dormant node and an inert slot, and stays dark
rather than acknowledging something that did not happen.

While a locate alert is running the first press silences it and does nothing
else. Whoever found the blinking node meant to stop it, not to transmit.

## LEDs

The board has two, and they are given separate jobs rather than multiplexed.

| LED | Colour | Pin | Carries |
|---|---|---|---|
| LED_B | blue | P0.19 | Status: the heartbeat, and the BLE pairing blink |
| LED_A | white | P0.15 | Attention: the locate alert, action confirmations, the power-off acknowledgement |

LED_B answers "is this thing alive, and what is its link state" — worth
glancing at, not worth walking over for. LED_A is the one meant to be seen
across a field, and it **idles dark**: a second heartbeat would only compete
with the first.

Because the two are separate pins, the pairing blink and the locate alert can
run at the same time. On the one-LED boards the alert has to preempt the
pairing blink; here neither has to yield.

LED_A's sequences:

| Sequence | Meaning |
|---|---|
| One short flash | An action was accepted — today, a beacon the MAC took |
| Repeating blink, 1.5 s period | Locate alert (`PROP_ALERT`). This board has no buzzer, so the blink is the entire alert |
| Two flashes | Force-pairing gesture accepted at boot |
| Three flashes | Power-off hold accepted; System OFF follows once they finish |

Two flashes versus three is deliberate: before the acknowledgement existed, a
force-pairing gesture that silently missed looked exactly like one that
worked.

## Power off

The hold is acknowledged on LED_A, and the teardown waits for those blinks to
finish — bounded, so a wedged indicator cannot stop the node powering off.
Then: hold the SX1262 in reset (there is no switchable rail to drop),
disconnect the battery divider, park the GNSS enable and standby lines low,
tri-state the remaining peripheral signal pins so no leftover SENSE bit fires
DETECT, and enter System OFF with **both** buttons armed as wake sources.
Powering off is PWR-only; waking is either button electrically, but only USR
usefully — see above.

## Notes and limitations

- No display and no sounder, so the interaction model is genuinely two buttons
  and two LEDs. Anything richer happens over BLE or USB.
- There is no persisted silence preference, because there is nothing to
  silence.
- The battery divider constant is nominal rather than a fitted calibration.
- Solar-input presence is not observable independently of battery voltage.

Implemented in [`firmware/nrf52-tracker/src/main.rs`][src] under the
`power-button` feature, with the board's pins, shutdown teardown, and GNSS
sequencing in [`umsh-bsp-sensecap-solar`][bsp]. Electrical detail lives in
`docs/hardware/sensecap-solar-node-p1-pro-hardware.md`.

[src]: https://github.com/darconeous/umsh/blob/main/firmware/nrf52-tracker/src/main.rs
[bsp]: https://github.com/darconeous/umsh/tree/main/crates/umsh-bsp-sensecap-solar
