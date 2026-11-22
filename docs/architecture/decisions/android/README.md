# Android architecture decisions

These records capture the decisions behind the native Android application.
They follow the iOS records in `../ios/` where the two apps share a concern,
and say where Android differs.

| ADR | Status |
|---|---|
| [0001—Mobile binding](0001-binding.md) | Accepted; host-JVM and emulator tests run against it |
| [0002—Identity key custody](0002-custody.md) | Accepted; StrongBox and TEE unverified on hardware |
| [0003—Application persistence](0003-persistence.md) | Accepted |

The BLE boundary, CompanionDeviceManager, and background records are written
with Phase 2, once the BLE spike and its measurements exist.
