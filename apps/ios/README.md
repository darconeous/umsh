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

## Running against a real radio in the simulator

The simulator has no Bluetooth, so a simulator build cannot reach a
companion radio the way a device does. Debug builds can reach one over a
socket instead: the bytes are the same HDLC-Lite frames the USB-CDC link
carries, so the radio cannot tell it is not talking to a wire.

Plug the radio in and bridge its port:

```sh
socat TCP-LISTEN:9000,reuseaddr /dev/cu.usbmodemXXXX,raw,echo=0,b115200
```

Run it one-shot, without `fork`. Each run opens the tty fresh — which
asserts DTR, the attach signal — and exits when the socket closes,
deasserting it again. A forking listener holds the port, and with it DTR,
across sessions, so the device never sees an attach or a detach.

Then in the app: Settings → Bridged radio → *Radio over TCP*, pointed at
`127.0.0.1:9000`. Editing the endpoint rebuilds the connection. The
address can be another machine's as easily as the loopback, though a
build on a physical device would need `NSLocalNetworkUsageDescription`
in `Info.plist`, which is deliberately not there — this is a simulator
facility.

Sanity-check the bridge before involving the app:

```sh
cargo run -p umshctl -- --tcp 127.0.0.1:9000 info
```

Both cannot hold the bridge at once: socat serves one connection.

### Without any radio at all

`socat` puts one *particular* radio in front of the simulator. When what you
want is a mesh rather than a specific device, `umsh-bridge` can serve the same
socket from a simulated device of its own — a
[host interface](../../tools/umsh-bridge/README.md#host-interfaces) — whose
radio is the bridge. Two of them is a two-node mesh on the laptop, so two
simulators can message each other with nothing plugged in:

```toml
[[server.hosts]]
name = "phone"
listen = "127.0.0.1:21838"
max_frames_per_minute = 600
```

Point Settings → Bridged radio at `127.0.0.1:21838`. The socket is
unauthenticated and stays on the loopback; the bridge's README has the
cautions. One host holds an interface at a time, but unlike the socat recipe a
new connection displaces the old one, so relaunching the app just works.

The device starts with its PHY disabled, as a real radio does after a reset.
The app turns it on itself once it has claimed the host, so there is nothing to
do here; only a bare `umshctl` session needs `phy on` first, since it attaches
administratively and claims nothing.

## TestFlight

```sh
make ios-archive
make ios-upload
```

`ios-archive` rebuilds the xcframework first (`Artifacts/*.xcframework/` is
gitignored, so a clean checkout has none), then archives into
`~/Library/Developer/Xcode/Archives/<date>/UMSH-<build>.xcarchive`. That path is
deliberate: Xcode's Organizer lists only archives under that directory, so an
archive written anywhere else — a local `build/`, say — uploads fine but never
appears in Window → Organizer → Archives. `ios-upload` uploads the most recent
`UMSH*.xcarchive` found there, including ones made by Xcode's own Product →
Archive; pass `IOS_UPLOAD_ARCHIVE=<path>` to send an older one.

The build number is not stored in the project. `CURRENT_PROJECT_VERSION` — which
`GENERATE_INFOPLIST_FILE` turns into `CFBundleVersion` — is passed on the
xcodebuild command line as the repository's commit count, so every upload gets a
distinct number that points back at a commit, and App Store Connect never sees
the duplicate it would reject under the same `MARKETING_VERSION`. That count only
increases while you keep landing on `main`; archiving from a shorter side branch
reuses a number. Override it there, or for any one-off:

```sh
make ios-archive IOS_BUILD_NUMBER=$(date -u +%s)
```

`MARKETING_VERSION` is still a deliberate edit in the project — bump it in Xcode
when you want a new user-visible version.

Archiving from Xcode's UI instead (Product → Archive) bypasses all of that and
uses the project's own `CURRENT_PROJECT_VERSION`, which stays at `1`. Use
`make ios-archive` for anything headed to App Store Connect.

`ExportOptions.plist` sets `destination = upload`, so `ios-upload` sends the
archive straight to App Store Connect; that is why it is a separate target from
`ios-archive` rather than a step inside it. It also sets
`testFlightInternalTestingOnly`; drop that key when you're ready to submit a
build for external Beta App Review.

`ITSAppUsesNonExemptEncryption` is declared `false` in `Info.plist`, which stops
App Store Connect asking the encryption questions on every upload. UMSH
implements its own AES-SIV/HKDF/Ed25519 rather than calling CryptoKit,
but these are all published standard algorithms (FIPS 197, RFC 5297, RFC 5869,
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
