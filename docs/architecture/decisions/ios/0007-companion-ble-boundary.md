# ADR 0007: Keep CoreBluetooth lifecycle in Swift and companion wire state in Rust

- Status: Implemented; physical-radio validation pending
- Phase: 0

## Decision

Swift owns permission timing, service-filtered discovery, peripheral retention,
connection, characteristic discovery, notification subscription, negotiated
write length, and with-response ATT write backpressure. The application asks
for Bluetooth access only after the operator selects **Find companion radio**.

The Rust mobile facade owns the long-lived companion host session: transaction
IDs, response matching, synchronization and inspection stages,
capability-gated reads, host ownership, claim/save choreography, companion
frame encoding and validation, GATT SAR segmentation and bounded reassembly,
raw device-key canonicalization, and battery-value decoding. Swift passes
complete ATT values into one opaque session object and receives outbound frames
plus immutable typed snapshots; feature views never retain CoreBluetooth or
generated types.

CoreBluetooth runs on a dedicated serial queue. Only immutable
`RadioSnapshot` values cross back to the main actor, so GATT notification
reassembly and Rust calls do not consume UI-thread time when the frame data
plane is enabled.

The production app uses the CoreBluetooth adapter. The fake radio exists only
for previews and tests. A radio device identity is published only after a valid
32-octet `PROP_DEV_KEY` response, so the Network peer is never synthesized from
advertising data or a preview fixture.

## Implemented foreground sequence

1. Scan only for Companion Link Service
   `21EB6B15-0001-4CCF-92E4-A079171BEC97`.
2. Connect and discover Frame In and Frame Out.
3. Enable Frame Out notifications. Access to its protected CCCD lets iOS invoke
   the system pairing flow required by the radio.
4. Issue ordered, with-response reads for last status, protocol version,
   capabilities, device key, device name, battery, and host key.
5. Require companion protocol major version 6 and expose validated public radio
   identity, name, and power information as an immutable `RadioSnapshot`.
6. Compare `PROP_HOST_KEY` with the selected phone identity and distinguish an
   unclaimed radio, this phone, another host, and an unavailable phone identity.
7. Allow an unclaimed radio to be configured for this phone. Replacing another
   host requires an explicit destructive confirmation that names the host-domain
   state the protocol atomically erases. The echoed `PROP_HOST_KEY` must exactly
   match the requested key before replacement is accepted as successful.
8. Derive the post-attach read set from the validated capability list. Always
   inspect interface type, PHY enabled state, and frequency; inspect saved state,
   host filters, host key digests, offline-queue counters, and delegated ACK state
   only when their capability dependencies are present.
9. Reduce the complete response set in Rust before publishing **attached**. The
   Swift snapshot contains only operational values and digest counts; it never
   exposes radio-held channel or peer key material.

The attached state means transport, ownership, and read-only state inspection
are complete. It does not yet mean mesh message ingestion is active. In
particular, the app reports queue depth but deliberately does not drain queued
traffic until persistent inbound-message ingestion is implemented.

## Remaining evidence gate

An iOS-on-Mac build on Apple silicon has successfully discovered and paired with
a companion radio. This establishes that the production CoreBluetooth adapter,
service-filtered discovery, and protected notification subscription reach the
system pairing ceremony. The simulator still verifies only unavailable and
disconnected UI. Before accepting real-radio attachment, complete the remaining
tests on supported companion firmware and a physical iOS device where noted:

- the 10-second not-found path and selection when multiple radios advertise;
- reconnect with an existing bond and rejection outside pairing mode;
- exact attach/reset behavior after encrypted CCCD subscription;
- MTU segmentation, notification reassembly, and write-response backpressure;
- protocol/version mismatch, malformed frames, disconnect at every state, and
  battery/device-key reads;
- host-key match, empty-host claim, foreign-host replacement, exact echoed-key
  verification, refusal, timeout, and disconnect during the mutation; and
- minimal and full capability sets, invalid capability dependencies, each
  capability-gated inspection response, and read-only attach without queue drain.

CoreBluetooth restoration and background behavior remain outside this decision
and are governed by ADR 0006.
