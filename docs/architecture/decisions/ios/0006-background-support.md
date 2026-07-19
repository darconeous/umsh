# ADR 0006: Claim foreground radio behavior only until measured

- Status: Provisional, foreground-only claims
- Phase: 0, evidence required before Phase 3

## Decision

Implement foreground BLE attachment first. Do not describe the app or radio as
always connected. CoreBluetooth restoration, notification delivery, radio-side
buffering, delegated acknowledgement, and offline assistance are separately
capability-gated and may be presented only after physical-device measurement.

Measure foreground, suspended, terminated, rebooted, Bluetooth-disabled, and
radio-out-of-range cases on each supported radio capability tier. A minimal-
protocol radio is offline when the live BLE link is absent.

## Consequences

Background experiments cannot silently widen the Keychain protection policy or
turn active-send scheduling into a durable application outbox. Any supported
background behavior updates this record, the capability matrix, and visible UX
copy together.
