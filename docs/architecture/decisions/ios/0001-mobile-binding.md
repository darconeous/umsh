# ADR 0001: Spike UniFFI behind a Swift adapter

- Status: Accepted for the value-oriented foreground facade
- Phase: 0

## Decision

Begin with UniFFI because the planned value-oriented API also needs a future
Kotlin binding. Keep all generated types inside `Services/MobileCore`; feature
code depends on Swift protocols and application records. Do not use generated
async APIs in the first spike. Swift owns orchestration and calls bounded,
synchronous Rust operations from an actor.

The first spike must round-trip the `umsh-mobile-core` NodeHint records and a
structured error on device and simulator. A narrow handwritten C ABI replaces
UniFFI if generated Swift cannot demonstrate deterministic packaging, safe
`Sendable` isolation, controlled callbacks, and stable error conversion.

## Consequences

No binding dependency or generated source is production policy until the
XCFramework/Swift call spike passes. Rust facade types remain independent of
UniFFI annotations so the fallback does not change feature code.

## Spike implementation

The binding is pinned to UniFFI 0.32.0 and uses proc-macro metadata in library
mode. `scripts/ios/build-mobile-core.sh` generates Swift, the C header, and the
module map from a host library, builds arm64 device and simulator static
libraries, and packages them as a local XCFramework consumed by
`packages/UMSHMobileCore`.

The script assembles the static-library XCFramework directory and metadata
directly. This avoids loading unrelated Xcode IDE plug-ins during a packaging
step and keeps the artifact construction inspectable; SwiftPM still validates
and consumes the standard XCFramework layout.

The compiled XCFramework is reproducible output and is not committed. The
generated Swift source is retained for deterministic application builds and
must be regenerated whenever the binding-visible Rust facade changes.

`scripts/ios/verify-mobile-core-swift.sh` compiles and runs a host Swift smoke
test against the same generated binding. The Swift package and its XCTest
target are also compiled for the arm64 iOS Simulator SDK as part of spike
verification.

The facade now also validates companion property frames, performs bounded GATT
segmentation and reassembly, canonicalizes raw radio public keys, and decodes
battery status. The packaging script preserves Cargo build caches while
replacing generated bindings and artifact slices, keeping regeneration
incremental without allowing stale generated interfaces.
