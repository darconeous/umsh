# UMSH for iOS

Build the local Rust/Swift package before opening the project:

```sh
scripts/ios/build-mobile-core.sh
open apps/ios/UMSH.xcodeproj
```

The initial target is iPhone-only (`TARGETED_DEVICE_FAMILY = 1`) on iOS 18 or
later. iPad is deliberately excluded: iPadOS requires all four interface
orientations for multitasking, and the UI is portrait-only. Signing is automatic
against team `2ZEL2X74K7`; override `DEVELOPMENT_TEAM` locally if you build
under a different account.

## TestFlight

`Artifacts/*.xcframework/` is gitignored, so run `scripts/ios/build-mobile-core.sh`
before archiving on any clean checkout. Bump `CURRENT_PROJECT_VERSION` for every
upload — App Store Connect rejects a duplicate build number under the same
`MARKETING_VERSION`.

```sh
scripts/ios/build-mobile-core.sh
xcodebuild -project apps/ios/UMSH.xcodeproj -scheme UMSH \
    -destination 'generic/platform=iOS' -archivePath build/UMSH.xcarchive archive
xcodebuild -exportArchive -archivePath build/UMSH.xcarchive \
    -exportOptionsPlist apps/ios/ExportOptions.plist -exportPath build/export
```

`ExportOptions.plist` sets `destination = upload`, so the second command uploads
straight to App Store Connect. It also sets `testFlightInternalTestingOnly`;
drop that key when you're ready to submit a build for external Beta App Review.

`ITSAppUsesNonExemptEncryption` is declared `false` in `Info.plist`, which stops
App Store Connect asking the encryption questions on every upload. UMSH
implements its own AES-128/AES-CMAC/HKDF/Ed25519 rather than calling CryptoKit,
but these are all published standard algorithms (FIPS 197, RFC 4493, RFC 5869,
RFC 8032) — not proprietary ones. Apple requires no US documentation for that
case, so the key stays `false` regardless of which territories are enabled.

Two separate obligations sit outside this key and are not implied by it:

- **France.** Distributing on the App Store in France requires a French
  encryption declaration. That stems from French rules on cryptographic means —
  an import-side requirement, not a US export exemption — so it does not change
  the value above. Note that a `false` declaration skips App Store Connect's
  encryption questionnaire, which is where that form would otherwise be
  requested; handle it directly if France is added to availability.
- **BIS.** Standard-algorithm mass-market software is generally self-classified
  under License Exception ENC 740.17(b)(1), which carries an annual
  self-classification report due February 1. App Store Connect never asks about
  it.
