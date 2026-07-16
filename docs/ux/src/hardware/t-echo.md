# LilyGO T-Echo

The T-Echo is a display tracker: it has a 200×200 e-paper screen, one side
button, a capacitive touch control used for the display light, and an RGB LED.
The standard model has no buzzer. The phone remains the primary UMSH interface,
but the display makes status and sensitive device actions visible.

## Current companion NCP interface

The current e-paper BLE menu contains Status, Start pairing, and Clear bonds.
It shows bond count and whether pairing is open, closed, or locked.

| Input | Current meaning |
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

These are strong precedents for the general guidelines: use the display instead
of hidden pairing gestures, default destructive choices to Cancel, preserve an
always-available long power hold, and account for display latency.

## Recommended evolution

- Keep the default page glanceable: battery, BLE connection/pairing, radio or
  last activity, and silence/attention state if applicable.
- Print the one-button legend on every menu or confirmation page.
- Keep the capacitive control dedicated to illumination unless hardware testing
  shows it is reliable enough and clearly labeled for navigation.
- Treat persistent e-paper content as state: every shutdown, pairing timeout,
  and fatal error must leave a truthful final image.
