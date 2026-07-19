# UMSH for iOS

Build the local Rust/Swift package before opening the project:

```sh
scripts/ios/build-mobile-core.sh
open apps/ios/UMSH.xcodeproj
```

The initial target supports iOS and iPadOS 18 or later. Signing intentionally
has no team configured; select a development team locally when installing on a
physical device.
