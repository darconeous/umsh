# ADR 0002: Device-only Keychain identity custody

- Status: Accepted
- Phase: 0

## Decision

Store each identity's private key as Keychain secret data with an identity-
scoped account, `kSecAttrSynchronizable = false`, and
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The general application
database stores only a stable secret identifier. The key enters one controlled
mobile-core unlock call and never enters SwiftUI state, preferences, files,
diagnostics, pasteboard, or backups.

The engine is torn down on identity change or protected-data loss. Logs and
errors use stable categories and must not contain input or key material.

### Anchoring

A Keychain item outlives the app container: deleting the app removes the
database keyed to the identity and leaves the identity itself behind. The
key alone therefore cannot say whether it belongs to *this* install, so an
**anchor** — a file at `Application Support/UMSH/identity-anchor` naming the
identity — is written whenever an identity is minted or adopted. The anchor
lives where iOS destroys it on delete and keeps it across an upgrade,
restore, or device migration, which is exactly the distinction wanted.

A key found with no anchor is *orphaned*. Nothing is unlocked into service
and nothing is minted over it; the app asks whether to keep the identity or
start fresh. An orphan the store still holds records for is adopted without
asking — that is a container that lost its anchor, not a container that lost
its data.

### Erasure

Two destructive actions, both reachable from Settings. **Erase Identity**
deletes the Keychain secret, every channel key, and the frame-counter
reservations, then mints a fresh identity; the database is left alone, and
its rows become unreachable under a dead owner. **Start Over** does that and
also empties the database, clears the stored preferences, and forgets the
paired radio. Neither is recoverable; nothing holds a second copy of a
private key.

## Consequences

`AfterFirstUnlock` (rather than `WhenUnlocked`) is what lets a background
BLE relaunch rebuild the mesh session while the phone is locked; the key
stays device-only and non-synchronizing. Widening it further would need
physical-device measurements and a threat-model review.

Reinstalling gives back the same node key only if the user asks for it. That
is a deliberate reversal of iOS's default, on the grounds that an identity
whose records are gone is a worse default than a new one: it presents to
peers as a node they know while being unable to hold up its side of any
history they remember.
