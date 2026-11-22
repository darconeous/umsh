# ADR 0001: UniFFI Kotlin bindings, generated at build time

- Status: Accepted
- Phase: 1

## Decision

The app reaches `umsh-mobile-core` through UniFFI's Kotlin bindings, in the
package `com.voria.umsh.core`, from the same proc-macro metadata the Swift
bindings come from. Nothing about the core's API is Android-specific.

- The `:core` Gradle module builds the core with cargo-ndk for `arm64-v8a`
  and `x86_64` at API 31, then generates the Kotlin bindings from the built
  library with `tools/uniffi-bindgen` in library mode. Both outputs go under
  `build/generated` and are never committed, so they cannot go stale.
  `armeabi-v7a` is left out.
- `android` and `android_cleaner` stay unset in `uniffi.toml`. The generated
  code then uses JNA's cleaner, which runs on API 31 and on a host JVM alike;
  `android.system.SystemCleaner` needs API 33 and does not exist off device.
- JNA is the AAR at 5.17 or later (16 KB page alignment), with
  `kotlinx-coroutines-core` for the `suspend` bindings. `:core`'s consumer
  rules keep JNA and `com.voria.umsh.core.**` through R8.
- The NDK is pinned (r28 or later) for 16 KB page alignment.
- A host build of the core (`:core:cargoHost`) serves the JVM unit tests of
  both `:core` and `:app` through `jna.library.path`, so Kotlin tests run
  against the real core without an emulator. `:core`'s smoke suite runs both
  on the host and on a device.

### How the app uses the bindings

- Generated records stay inside `services/mobilecore` and the runtime;
  generated enums and value-compared sealed types (the radio's phase,
  ownership, charge state and problem, a start failure's reason) may reach
  the models.
  `RecordMapping` maps the core's records onto app models compared by value
  (byte fields become `Octets`), so `StateFlow` deduplication works.
- The app core's listener only offers to a conflated channel; one coroutine
  drains `pollChanges()` and applies each batch in order. Synchronous queries
  run on a dispatcher limited to two threads, since they share the store's one
  connection with the core's worker.
- A canceled coroutine does not cancel the Rust future's effect. Commands run
  in the runtime's scope, not a screen's, and anything that must finish (a
  staged seed, a draft save) runs without cancellation. The host cancels a
  runtime's coroutines and waits for them before it stops and closes the
  core, since a call into a closed core throws.
- The core sends no display text. Every exception subclass maps to a string
  resource by an exhaustive `when` in `CoreErrors.kt`, so a variant added to
  the bindings fails the build until it has words; `message` is never shown.

## Consequences

Every Gradle build needs the Rust toolchain, cargo-ndk, and the Android Rust
targets. The cargo tasks are never up to date in Gradle's eyes, because cargo
tracks the crate graph itself; a no-op cargo run costs a second or two.

The bindings' API is whatever the core exports, so a core change that breaks
Kotlin breaks the Android build in the same change, as it does the Swift one.
