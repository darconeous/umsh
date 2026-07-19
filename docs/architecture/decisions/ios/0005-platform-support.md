# ADR 0005: Support iOS and iPadOS 18 or later

- Status: Accepted for project creation
- Phase: 0

## Decision

Set the initial deployment target to iOS 18.0 and iPadOS 18.0 on 64-bit iPhone
and iPad devices. Build Rust slices for arm64 iOS devices and arm64 iOS
Simulator. Add an x86_64 simulator slice only if CI or a supported developer
machine requires it.

Use the current Xcode SDK's native SwiftUI navigation, tab, toolbar, list,
sheet, search, and adaptive layout behavior without imitating a specific iOS
visual version.

## Consequences

The minimum may move before release after device-market and framework testing,
but project and persistence choices must support iOS 18 until this ADR changes.
