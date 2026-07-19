# ADR 0002: Device-only Keychain identity custody

- Status: Accepted for foreground prototype
- Phase: 0

## Decision

Store each identity's private key as Keychain secret data with an identity-
scoped account, `kSecAttrSynchronizable = false`, and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The general application
database stores only a stable secret identifier. The key enters one controlled
mobile-core unlock call and never enters SwiftUI state, preferences, files,
diagnostics, pasteboard, or backups.

The engine is torn down on identity change or protected-data loss. Logs and
errors use stable categories and must not contain input or key material.

## Consequences

The foreground prototype fails closed while protected data is unavailable.
Background access is not promised. This accessibility class may change only
after physical-device measurements establish a required background operation
and its threat-model review accepts the wider access window.
