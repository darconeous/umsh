# ADR 0003: Reuse reservation-block counter persistence

- Status: Accepted architecture; durable adapter implemented
- Phase: 0

## Decision

The mobile core reuses `umsh_hal::CounterStore` and the reservation-block
contract already implemented by `umsh-mac`. The iOS store is identity-scoped
and atomically replaces a boundary in durable storage. A prepared authenticated
frame is not exposed as transmit-ready until every counter it uses is below a
successfully committed reservation boundary.

On a failed write, protected-data loss, or crash, transmission fails closed.
Allocated values are never reclaimed and startup resumes at the persisted
boundary, skipping unused values.

Identity load and application startup are deliberately read-only with respect
to the counter store. The implementation must not reserve a new block merely
because the device booted: repeated boot failures without a transmission could
otherwise consume embedded-flash endurance. The first authenticated send
schedules the next reservation, which is committed before that prepared frame
is exposed to the radio transport.

## Required evidence

Tests must terminate between allocation, encryption, reservation commit,
frame release, radio submission, and application commit. They must also inject
write failure and protected-data unavailability at every boundary.

## Implemented foundation

`umsh-mobile-core::MobileCounterStore` implements `umsh_hal::CounterStore` with
identity-scoped, checksummed boundary records. A commit writes and synchronizes
a temporary record, atomically renames it over the previous record, and then
synchronizes the containing directory. Swift selects an application-support
directory and supplies only the stable identity context and future boundary.

Rust tests inject failure after write, after file synchronization, and after
rename. Failures before rename recover the previous boundary; an ambiguous
failure after rename recovers the new boundary so unused counters are skipped.
Missing state starts at zero, while invalid contexts and corrupt records fail
closed. Process-termination tests around encryption, frame release, and radio
submission remain part of the Phase 2 prepared-send integration gate.
