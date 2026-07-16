# Pairing, Privacy, and Recovery

Pairing creates trust and bond clearing destroys it. Both require more care than
ordinary connection status.

## Pairing

- Pairing must be time-limited or end when a bond succeeds.
- A device with a display must expose pairing as a visible action and show
  whether pairing is open, closed, full, or locked out.
- A screenless device should start pairing from the phone when an existing
  trusted connection exists. First pairing and lost-phone recovery require an
  intentional physical-presence gesture on the tracker.
- Pairing feedback must be distinguishable from ordinary advertising or
  connection feedback.
- Reconnecting an already trusted phone must not require reopening pairing.

## Clearing bonds and identity

Disconnecting, forgetting a phone, clearing all bonds, clearing application
data, and resetting device identity are different actions. Never label them all
“Reset.”

On a display, destructive confirmation must name what will be erased and
default to Cancel. On a headless device, initiate the request from the phone,
explain the consequence there, and require a separate physical confirmation if
the threat model requires it.

Clearing BLE bonds must not implicitly clear the UMSH identity or message data
unless the confirmation explicitly says so.

## Firmware update and bootloader entry

Treat firmware update as a guided maintenance flow. Prefer a phone/USB command
or boot-time recovery ceremony over a runtime multi-click shortcut. If a
runtime shortcut exists for development or compatibility, document it as such,
give distinctive feedback, and keep it out of the routine interaction ladder.

Recovery must remain possible without a functioning companion connection.
