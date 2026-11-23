# Android architecture decisions

These records capture the decisions behind the native Android application.
They follow the iOS records in `../ios/` where the two apps share a concern,
and say where Android differs.

| ADR | Status |
|---|---|
| [0001—Mobile binding](0001-binding.md) | Accepted; host-JVM and emulator tests run against it |
| [0002—Identity key custody](0002-custody.md) | Accepted; StrongBox and TEE unverified on hardware |
| [0003—Application persistence](0003-persistence.md) | Accepted |
| [0004—Bluetooth boundary](0004-ble-boundary.md) | Accepted; emulator-verified against a Bumble peripheral, Pixel and radios unverified |
| [0005—CompanionDeviceManager](0005-companion-device-manager.md) | Accepted; emulator-verified on API 31 and 36, Pixel unverified |
| [0006—Background link](0006-background.md) | Accepted; emulator-verified, power management unverified; carries the Pixel checklist |
