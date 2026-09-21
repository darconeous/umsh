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

## Shared interface components

Debug builds include **Settings → Component Gallery**, with static peer, channel,
radio, header, and settings-field examples. It offers light/dark appearance and
accessibility text controls; the same fixtures have SwiftUI previews and require
no runtime or radio services.

Use `PeerRow`, `ChannelIdentityRow`, and `RadioDiscoveryRow` for identity labels.
Keep navigation links, buttons, context menus, and feature-specific metadata with
the screen. `IdentityHeader` provides information, editable-profile, and hero
layouts; shared remote fields and reading footers live beside the management
features. See [the refactoring plan](../../docs/ios-refactoring-plan.md) for scope,
validation, and the pending service work.

## Radio setup and saved radios

On iPhone, **Choose a Radio** and **Choose a Device** show authorized radios
with recent connectable advertisements. Radios disappear after roughly six
to eight seconds without an advertisement. Saved radios that are offline or
already connected are hidden; their pairings are retained. **Add Another Radio…**
opens Apple's picker. Open the radio's pairing window so the picker can match
the ULCP service UUID and display its name.

AccessorySetupKit manages authorization and the saved list. CoreBluetooth
still owns connections, GATT traffic, the selected companion's pending
connection request, background Bluetooth mode and state restoration. Opening
either list starts a foreground scan without a service filter, so flags-only
advertisements can qualify. The list admits only authorized identifiers.
Scanning stops when the list closes or the app becomes inactive; it resumes
with an empty sightings list if the open picker returns to the foreground.
Administrative visits do not select a
new companion or create background reconnect requests for every saved radio.

An upgrade from an older app offers **Finish Radio Setup** directly in the
radio problem banner, radio details and radio picker. This applies even
when that radio already runs privacy firmware. Complete the system migration
before connecting. Cancelling keeps the migration available for another
attempt; it does not erase radio bonds. **Forget Previous Radio…** lets you
abandon an unavailable legacy companion and add another radio. If
the radio cannot be found, bring it nearby and open its pairing window. A
firmware update that erased the bond still requires re-pairing; app migration
cannot recreate erased security keys.

Older apps remembered only the selected companion's Bluetooth identifier.
Previously visited administrative radios and companions no longer saved by
the app must be added through the system picker with pairing open. There is
no supported inventory of all legacy CoreBluetooth bonds to import. This
also applies if the app's saved preferences were erased.

Removing an authorized accessory in Settings or through **Remove Radio** in
the list removes its app entry and stops this app's connection to it. Removal
while the app is closed is reconciled on next launch. Removing an unmigrated
legacy entry merely abandons the saved identifier; it does not erase its
phone-side bond. Neither action resets the radio or clears its other hosts.
Offline radios remain saved and can be removed in Settings. The app remembers
configured names learned through either authenticated connection type and
updates them after subsequent reads and renames. These names take priority
over cached Bluetooth or system accessory names. Until a name has been learned,
the picker uses the advertised/cached name or the system label. This app-side
cache does not rename the accessory in iOS Settings.

The simulator retains its development transport, and iOS-on-Mac retains the
CoreBluetooth discovery fallback. These environments do not exercise the
iPhone system picker. The implementation uses iOS 18 APIs.

Run `scripts/ios/verify-radio-accessories.sh` for host checks of migration,
authorization, foreground availability, name selection, removal and stale-update
handling. Physical iPhone qualification
is pending, including migration of a flags-only advertiser, pairing ceremony,
Settings removal, and locked-phone background reconnection. See
[ADR 0008](../../docs/architecture/decisions/ios/0008-accessory-setup.md) for
the lifecycle and qualification cases.

Companion recovery uses attachment generations to reject late GATT callbacks.
Disconnect retires protocol work immediately and replaces the Bluetooth manager
if cancellation has not completed within five seconds. Service and characteristic
discovery each have a ten-second deadline; notification subscription allows
sixty seconds for system pairing. Individual ATT writes and ULCP control replies
have eight-second deadlines. Unrelated notifications and slow LoRa transmissions
do not extend a control reply deadline. A radio that is simply out of range keeps
its pending connection request without periodic scans or reconnect attempts.

Run `scripts/ios/verify-radio-recovery.sh` for lifecycle and deadline checks.
After rebuilding mobile-core, run `scripts/ios/verify-radio-session-recovery.sh`
to exercise the actual ULCP session with a fake transport, including missing
answers and teardown with delayed work. The Rust mobile session tests cover the
outstanding control-transaction reports used by those deadlines. Physical iPhone
checks remain necessary for Bluetooth resets, dropped callbacks, Service Changed,
AccessorySetupKit invalidation, and background reconnection.

## Running against a real radio in the simulator

The simulator has no Bluetooth, so a simulator build cannot reach a
companion radio the way a device does. Debug builds can reach one over a
socket instead: the bytes are the same HDLC-Lite frames the USB-CDC link
carries, so the radio cannot tell it is not talking to a wire.

Plug the radio in and bridge its port:

```sh
socat TCP-LISTEN:9000,reuseaddr /dev/cu.usbmodemXXXX,raw,echo=0,b115200
```

Run it one-shot, without `fork`. Each run opens the tty fresh—which
asserts DTR, the attach signal—and exits when the socket closes,
deasserting it again. A forking listener holds the port, and with it DTR,
across sessions, so the device never sees an attach or a detach.

Then in the app: Settings → Bridged radio → *Radio over TCP*, pointed at
`127.0.0.1:9000`. Editing the endpoint rebuilds the connection. The
address can be another machine's as easily as the loopback, though a
build on a physical device would need `NSLocalNetworkUsageDescription`
in `Info.plist`, which is deliberately not there—this is a simulator
facility.

Sanity-check the bridge before involving the app:

```sh
cargo run -p umshctl -- --tcp 127.0.0.1:9000 info
```

Both cannot hold the bridge at once: socat serves one connection.

### Without any radio at all

`socat` puts one *particular* radio in front of the simulator. When what you
want is a mesh rather than a specific device, `umsh-bridge` can serve the same
socket from a simulated device of its own—a
[host interface](../../tools/umsh-bridge/README.md#host-interfaces)—whose
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

## Battery diagnostics

Manage Device → Power shows the optional ULCP battery diagnostics alongside
charge, voltage, and charger state. This screen works for the companion radio,
a nearby device in an administrative BLE session, and a device managed over the
mesh. It shows current, remaining/full/design capacities, external power and
battery presence, the gauge's charging-voltage request, readiness and smoothing,
and raw gauge flags with their format identifier.

Battery reads use one multi-get when supported. Devices without multi-get use
individual reads. Unsupported diagnostic properties are hidden; a successful
empty value displays **Unavailable**, while acquisition errors and malformed
values remain visible. Current is positive while charging and negative while
discharging. Diagnostics have their own read time, which ordinary battery
notifications do not advance.

Local management refreshes an unread or cached Power screen on opening. Tap
Refresh for another reading; mesh reads remain manual, with no background
diagnostic polling. The decoder and local/mesh request handling live in
`umsh-mobile-core`, using the shared ULCP wire codecs.

## TestFlight

AccessorySetupKit authorizes access per radio; the app does not depend on a
Bluetooth permission toggle in its Settings page. Before the first radio is
authorized, the app offers **Add Radio** and does not create a CoreBluetooth
manager or scan. CoreBluetooth's unavailable state in this case does not mean
the phone's Bluetooth is off. Open the radio's pairing window and complete the
system setup dialog; existing legacy pairings use **Finish Radio Setup**.
Accessory access is managed in **Settings → Privacy & Security → Accessories**.

For release qualification, test a fresh installation with no authorized radios,
canceled setup followed by successful setup, legacy migration, and removal of
the last accessory. Verify that setup stays accessible, the empty authorization
list never displays a Bluetooth-off warning, and successful setup connects to
the selected radio. Separately test genuine Bluetooth-off behavior with an
authorized radio. These cases require a physical iPhone.

```sh
make ios-archive
make ios-upload
```

`ios-archive` rebuilds the xcframework first (`Artifacts/*.xcframework/` is
gitignored, so a clean checkout has none), then archives into
`~/Library/Developer/Xcode/Archives/<date>/UMSH-<build>.xcarchive`. That path is
deliberate: Xcode's Organizer lists only archives under that directory, so an
archive written anywhere else—a local `build/`, say—uploads fine but never
appears in Window → Organizer → Archives. `ios-upload` uploads the most recent
`UMSH*.xcarchive` found there, including ones made by Xcode's own Product →
Archive; pass `IOS_UPLOAD_ARCHIVE=<path>` to send an older one.

The build number is not stored in the project. `CURRENT_PROJECT_VERSION`—which
`GENERATE_INFOPLIST_FILE` turns into `CFBundleVersion`—is passed on the
xcodebuild command line as the repository's commit count, so every upload gets a
distinct number that points back at a commit, and App Store Connect never sees
the duplicate it would reject under the same `MARKETING_VERSION`. That count only
increases while you keep landing on `main`; archiving from a shorter side branch
reuses a number. Override it there, or for any one-off:

```sh
make ios-archive IOS_BUILD_NUMBER=$(date -u +%s)
```

`MARKETING_VERSION` is still a deliberate edit in the project—bump it in Xcode
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
RFC 8032)—not proprietary ones. Apple requires no US documentation for that
case, so the key stays `false` regardless of which territories are enabled.

Two separate obligations sit outside this key and are not implied by it:

- **France.** Distributing on the App Store in France requires a French
  encryption declaration. That stems from French rules on cryptographic means—
  an import-side requirement, not a US export exemption—so it does not change
  the value above. Note that a `false` declaration skips App Store Connect's
  encryption questionnaire, which is where that form would otherwise be
  requested; handle it directly if France is added to availability.
- **BIS.** Standard-algorithm mass-market software is generally self-classified
  under License Exception ENC 740.17(b)(1), which carries an annual
  self-classification report due February 1. App Store Connect never asks about
  it.
