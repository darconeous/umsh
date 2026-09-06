# Wi-Fi and IP: the spec chapters and the iOS app

How the surface specified in [ULCP: Wi-Fi](protocol/src/ulcp-wifi.md)
and [ULCP: IP Connectivity](protocol/src/ulcp-ip.md) gets into the
phone, with nothing on the device side beyond what the phone needs to
be tested against.
Firmware support for the ESP32 boards and the T1000-E's sniffer is a
separate plan; this one ends at the point where a device that implements
the chapters as written works with the app as built, without the app
changing.

The guarantee that makes that possible is not the UI. It is that every
octet the app reads or writes passes through one codec, in the shared
`umsh-ulcp` crate, that the device session will also use, and that the
codec is pinned to the chapter by tests. A device and a host that share
a codec cannot disagree about a wire format; what is left to disagree
about is behavior, and the sketch's frame orders and refusals are the
contract the fake device and, later, the simulated device implement.

## What exists to build on

The BLE management surface, landed 2026-09-01, is the pattern in every
layer, and this plan follows it file for file.

* **Constants** live once, in `crates/umsh-ulcp/src/ids.rs` (`prop` and
  `cap` modules), with the spec's type, default, and gate restated in
  the doc comment. `describe.rs` carries three parallel tables
  (`property_name`, `PROPERTIES`, `property_type`) and
  `capability_name`; umshctl and the web debugger render from them.
* **Typed enumerations** are sibling modules with `code()` /
  `from_code()` and tests: `alert.rs`, `ble.rs`.
* **The mobile host** is `crates/umsh-mobile-core/src/ulcp.rs`. Property
  octets reach Swift two ways at once: raw, keyed by number
  (`UlcpPropertyFrameRecord`, `UlcpPropertyPushRecord`), and decoded, as
  the all-optional `UlcpDevicePropertiesRecord` that
  `inspect_ulcp_properties` builds from whatever octets it was handed.
  Writes go the other way through `ulcp_dirty_writes`, one arm per
  writable property. `ulcp_category_properties` decides which property
  numbers a management screen asks for, from the device's capability
  octets. Unsolicited updates are not a callback: they are drained from
  `UlcpSessionUpdateRecord.pushed_properties` on every poll.
* **The app** drives all three management links (mesh, companion, bench)
  through one `DeviceManagementBackend` of closures and one
  `ManageDeviceModel`. A category screen is a `ManageDeviceCategory`
  entry, a `RemoteCategoryReading` of octets plus their decoded record,
  an `Edits` struct that folds reported values under edited ones, and
  `remoteCategoryChrome` for Refresh, Apply, and the leave-with-edits
  guard. Refusals render on the row that offered the value. Pushes
  arrive as an `AsyncStream` on local links and not at all on the mesh.
  `RemoteBluetoothScreen.swift` is the exemplar for a toggle-and-status
  screen; `RemotePeerNodesScreen.swift` for a table.
* **The fixture** is `FakeManagedDevice` inside
  `FakeRadioConnection.swift`: a dictionary of octets keyed by property
  number, hand-encoded capability bytes, and fetch/write closures that
  refuse what they do not hold. Staging mode and previews run on it.
* **The simulated device** `crates/umsh-ulcp-simdev` wraps the real
  `umsh_ulcp_device::Session` behind an in-memory link, and
  `umsh-bridge`'s `[[server.hosts]]` presents one on a TCP socket. The
  app's `TcpRadioConnection` attaches to such a socket from the
  simulator. That chain is the only way to put the real session in front
  of the app without hardware, and it is what the last stage uses.

## Stage 1: the spec

Two chapters, because the sketch already argues they are two
subsystems: the station is a link, and the IP layer is the stack on
whichever link the device has. The conformance chapter's subsystem
table wants one row per chapter, and a wired device one day advertises
the second without the first.

### Files

* `docs/protocol/src/ulcp-wifi.md`, `# ULCP: Wi-Fi Station`. The
  sketch's Model, Why No Commands, Capabilities, Properties, Mechanics,
  and Security sections, rewritten in the book's register: no "sketch",
  no "when this lands", no reviewer-facing argument that has already
  been won. The Not In This Sketch list becomes a short "Not Specified"
  section of one line per item, keeping only the reasons that tell an
  implementer what to do (the exact-mode rule, the enterprise
  placeholders) and dropping the ones that were for the reviewer.
* `docs/protocol/src/ulcp-ip.md`, `# ULCP: IP Connectivity`. The IP
  Connectivity section, with Alongside the Station as its closing
  section since it is the part an implementer of either chapter reads
  last.
* `docs/protocol/src/SUMMARY.md`: both after Tethered Host Services and
  before Minimum Requirements. They are subsystem chapters, not
  bindings, so they do not follow ULCP over BLE's placement after the
  index.
* `docs/protocol/src/ulcp.md`: the chapter list at lines 15–33 and the
  "five subsystems" paragraph at line 240 become seven, with one blurb
  each in the style of the existing five.

### House style the sketch does not yet follow

The survey of the existing chapters turned up these, each a mechanical
pass:

* Every `### PROP` heading carries an explicit `{#prop-wifi-enabled}`
  anchor derived from the mnemonic. The index links need them, and
  nothing checks a broken anchor.
* Property summary tables are `Id | Mnemonic | Commands | Description`.
  The sketch's `Class` column is not a convention; the class is stated
  in the chapter prose above the table, as the radio and device chapters
  do, and the What Survives What table stays as the chapter's own
  closing table since nothing in the book contradicts it.
* Value-format diagrams get a `Figure:` caption line after the fence.
* Field names inside a structure are the bold inline `**STATE**:` form
  the sketch uses; the BLE chapter's H4 form is for a header with
  sub-fields and does not fit a one-octet field.
* `Single-Value, Constant` is fine: `PROP_CAPS` uses `Multiple-Value,
  Constant`.
* No spaced em dashes, in the chapters or anywhere else. Much of the
  existing book has them and is wrong; nothing new introduces one, and
  any that fall inside an edit are corrected on the way past.
* Hard wrap at about 72 columns, en dashes in ranges.

### Protocol changes

There are no wire changes relative to the sketch. The sketch's Index
Additions list is complete for the index itself; the survey found four
more places the book keeps the same facts, and one existing gap to fix
on the way through.

* `ulcp-index.md`: properties 4880–4903 appended after 4874 in the one
  continuous table, mnemonics linked to their anchors; capabilities
  53–56 between `CAP_STATS` and `CAP_PHY_LORA`; the six enumerations
  appended to Enumerated Values in the `N NAME, N NAME` form. `Get, Is,
  Inserted` is a new Commands value and is used as written. The two
  shared DNS properties are the first with a disjunctive gate and are
  written `` `CAP_IPV4` or `CAP_IPV6` ``.
* `ulcp-core.md`: the capability registry at lines 1222–1246 has its
  own `Requires` column and currently stops at 51, missing `CAP_STATS`;
  it gains 52 through 56. The `[!NOTE]` at lines 595–598 says a property
  marked `Is` may be emitted asynchronously; it gains a sentence saying
  the same of `Inserted` and `Removed`, since `CMD_PROP_INSERTED`'s own
  definition already allows the unsolicited form. `STATUS_ITEM_NOT_FOUND`
  at lines 1110–1112 broadens as the sketch says.
* `ulcp-conformance.md`: two rows in the Subsystem table.
* `ulcp-saved-state.md`: the saved-state bullet classifies by rule plus
  named exclusions. The nine live properties (four station, five IP)
  get one exclusion paragraph beside `PROP_STAT_*` and `PROP_TIME`,
  and each chapter's live entries carry the reciprocal sentence the BLE
  chapter uses.
* `dissectors/umsh/ulcp.lua`: the `PROPERTIES` table gains the sixteen
  names. It is already missing 4866–4870 and a run of two-digit ids;
  fill those while there, since a dissector that names half the
  properties in a capture is worse than one that names none.

### Verification

`make docs` is the whole CI check for the book, and mdBook does not
fail on a bad anchor, so the index's new links are checked by hand in
`make docs-serve` once. The sketch document stays in place until the
chapters land and is then deleted in the same commit; its decisions are
in the chapters or in memory, and a plan that survives its spec is a
second source of truth.

## Stage 2: shared constants and codecs

`crates/umsh-ulcp`, `no_std`, no dependencies. Everything a host or a
device needs to read or write these properties, and nothing about what
to do with them.

* `ids.rs`: `prop::WIFI_ENABLED` through `prop::IP_RESOLVERS`,
  `cap::WIFI_SCAN` through `cap::IPV6`, doc comments in the existing
  register.
* `describe.rs`: the four tables. Scalars get their `PropertyType`;
  structured values (`WIFI_NETWORKS`, `WIFI_SCAN_RESULTS`, `WIFI_LINK`,
  the configs, the address sets) stay `None` from `property_type`, as
  every structured property does, and umshctl renders their octets.
* `wifi.rs`: `SecurityMode`, `LinkState`, `LinkReason` with `code()` /
  `from_code()`; `NetworkFlags`; a `NetworkEntry` writer that takes
  flags, mode, SSID, and an optional credential and validates the
  sketch's well-formedness rules (empty SSID, credential length by mode,
  reserved mode, raw-key flag on a mode that derives none) so a host
  cannot send what a device would refuse with `STATUS_INVALID_ARGUMENT`;
  a `NetworkEntry` reader for the reported form; a `ScanResult` reader
  and writer; a `Link` reader and writer. Readers are tolerant of
  trailing octets a newer device might append, per the receiver rule,
  and strict about anything shorter than the fixed fields.
* `ip.rs`: `FamilyState`, `Method`; `V4Config` / `V6Config` with the
  usability and gateway validation the chapters specify, so an invalid
  static address is refused on the phone before it is refused on the
  device; `V4Address`; `V6Item` (`Address` / `Router`); resolver items.
* Tests pin every encoding to the chapter with literal octet vectors,
  including the empty forms (`PROP_WIFI_NETWORK` empty, `PROP_WIFI_RSSI`
  empty, `PROP_IPV4_ADDRESS` empty) and the `WIFI_LINK_UP` form with
  its trailing association.

Writers are here and not only readers because the device session will
emit the reported forms and the notifications, and a session that
builds `PROP_WIFI_LINK` by hand next to a host that parses it by hand
is two chances to get it wrong.

## Stage 3: the mobile core

`crates/umsh-mobile-core/src/ulcp.rs` and `mobile_mesh.rs`, then
`make ios-mobile-core` to regenerate the committed bindings, and a
`MOBILE_API_VERSION` bump.

### Records

`UlcpDevicePropertiesRecord` gains one optional field per property,
decoded in `inspect_ulcp_properties` through the Stage 2 readers:

* `wifi_enabled: Option<bool>`, `wifi_scanning: Option<bool>`,
  `wifi_network: Option<Vec<u8>>` (empty is a value: deselected),
  `wifi_rssi: Option<i8>` (absent when empty), `wifi_mac: Option<Vec<u8>>`.
* `wifi_networks: Option<Vec<UlcpWifiNetworkRecord>>` (hidden, mode,
  ssid; never a credential, because the wire never carries one back).
* `wifi_scan_results: Option<Vec<UlcpWifiScanResultRecord>>` (modes as
  a `u16` bit set, frequency, rssi, bssid, ssid).
* `wifi_link: Option<UlcpWifiLinkRecord>` (state, reason, and the
  optional bssid and frequency).
* `ipv4_state`, `ipv6_state: Option<UlcpIpFamilyState>`;
  `ipv4_config: Option<UlcpIpv4ConfigRecord>`, `ipv6_config`;
  `ipv4_address: Option<UlcpIpv4AddressRecord>` (absent when empty);
  `ipv6_addresses: Option<Vec<UlcpIpv6ItemRecord>>`;
  `ip_dns`, `ip_resolvers: Option<Vec<Vec<u8>>>`.

`UlcpManagedPropertyIds` gains the sixteen numbers, which is what lets
`FakeManagedDevice` and the model name them without a second table.
`UlcpDeviceCardRecord` gains `supports_wifi_scan`, `supports_wifi`,
`supports_ipv4`, `supports_ipv6`. `validate_capability_dependencies`
gains `WIFI ⇒ WIFI_SCAN`.

### Categories

`UlcpManageCategory` gains `Wifi` and `Network`. `ulcp_category_properties`:

* `Wifi` with `CAP_WIFI`: all eight station properties. With
  `CAP_WIFI_SCAN` alone: `WIFI_SCANNING` and `WIFI_SCAN_RESULTS`. The
  screen tells the two apart by which properties the card offered, not
  by a flag, so a device that grows a station grows the screen.
  `WIFI_RSSI` and `WIFI_MAC` are asked for and allowed to refuse, as the
  bond count is.
* `Network` with either IP capability: that family's three properties
  plus the two shared ones; with both, all eight. A family the device
  lacks is not asked for, so its absence is never mistaken for a refusal.

The categories are offered by the existing rule, a category with no
properties has no row, so a device with none of the four capabilities
shows nothing new.

### Writes

`ulcp_dirty_writes` gains arms for `WIFI_ENABLED`, `WIFI_NETWORK`,
`IPV4_CONFIG`, `IPV6_CONFIG`, and `IP_DNS` as a whole-set `SET`, which
is how a small set of resolvers is edited in practice and is the one
`SET` on a multi-value property the chapters bless. `WIFI_NETWORKS` is
not a dirty write: it is an insert or a remove, and the sketch's
mechanics depend on the insert's replace-by-SSID semantics. The mesh
session already has `begin_management_insert` / `begin_management_remove`;
the local session has only fetch, writes, and save. `MobileUlcpSession`
gains `begin_property_insert(property_id, item)` and
`begin_property_remove(property_id, selector)`, answered through the
same `management_event` as writes, so the app's backend gets one
`insertNetwork` / `removeNetwork` pair shaped like `setPeer` and does
not care which link is under it.

The credential crosses the FFI boundary once, in the insert's item
octets, and is not held in any record afterward. The insert helper
takes the passphrase as `Vec<u8>` and the Swift side builds it from the
text field and drops it.

### Pushes

`UlcpPropertyPushRecord` today carries the octets of an unsolicited
`CMD_PROP_IS` and nothing else; `apply_property` ignores every other
command because no mirrored field was multi-valued. The scan stream is
`CMD_PROP_INSERTED`, so the record gains a `kind: UlcpPropertyPushKind`
(`Is`, `Inserted`, `Removed`), `consume` forwards all three with
`TID_UNSOLICITED`, and the app merges by kind. `Removed` is forwarded
for completeness though nothing here emits it. The snapshot mirror
(`UlcpSessionSnapshotRecord`) does not grow: none of these properties is
attach-time state the session keeps for its own decisions, and the
category reading is where they live.

### Tests

Mirroring the BLE ones in `ulcp.rs`'s test module:

* the Wi-Fi screen asks for eight properties with `CAP_WIFI`, two with
  `CAP_WIFI_SCAN`, none without either; the Network screen asks per
  family;
* a full reading round-trips every field, and a partial one leaves the
  rest `None`;
* dirty writes emit the five writable properties and refuse the read-only
  ones;
* a well-formed insert item is built for each mode and the malformed
  ones are refused before they leave the phone;
* an unsolicited `INSERTED` reaches `pushed_properties` with its kind,
  and the order clear-then-scanning-then-inserts-then-done survives a
  poll boundary.

## Stage 4: the app

Two new files, four pbxproj lines each with random 24-hex ids, and edits
to the model, the backend, and the fake device. `git status` on the
project file first, since it is often being edited concurrently.

### Backend and model

`DeviceManagementBackend` gains `insertNetwork` and `removeNetwork`
closures, wired at all three construction sites (`AppRuntime`'s mesh
and companion backends, `DeviceSetupFlowView`'s bench backend) to the
new core operations. `RadioConnection` gains the corresponding local
and remote members, implemented in `UlcpRadioSession`,
`AdministrativeDeviceSession`, and `FakeRadioConnection`.

`ManageDeviceModel`:

* `absorb(_ push:)` switches on the push kind. `Is` replaces octets as
  today. `Inserted` for a multi-value property decodes the item and
  replaces-or-appends by key in the reading's decoded list; the reading
  keeps its octets as the truth for single-value properties and its
  decoded list as the truth for the two streamed ones, since the device
  never sends the whole table mid-scan. `Is` with an empty value on
  `WIFI_SCAN_RESULTS` clears the list.
* `ManageDeviceCategory.all` gains Wi-Fi and Network entries, after
  Bluetooth. The Wi-Fi entry's title is "Wi-Fi" whether or not the
  device can join; a scan-only screen says so in its own header.
* `saveValues` excludes `WIFI_SCAN_RESULTS` and `WIFI_RSSI` from the
  property cache. A cached scan is a stale location fingerprint in
  SQLite, and a cached RSSI is a number about a moment. `WIFI_NETWORKS`
  caches as it arrives, since the reported form has no credential.
* A `supportsWifiStation` predicate: `readings[.wifi]?.answered(ulcpProperties.wifiEnabled)`,
  by the pattern `supportsBluetoothPairing` set.

### RemoteWifiScreen.swift

Sections, top to bottom, each present only when its properties were
offered:

1. **Station.** The enabled toggle, with the row-level refusal title.
   `applyWarning` on the mesh link when disabling: the same stranding
   text the Bluetooth screen uses for the mesh arm, since an
   administrator may be turning off the link a bridge rides on.
   Enabling answers `STATUS_INVALID_STATE` on a platform with a radio
   conflict; the refusal text for status 4 already reads as "the device
   is not in a state to accept this" and is left alone.
2. **Connection.** Link state and reason in words, the BSSID, and the
   frequency shown as "Channel 6 (2437 MHz)"; the channel number is
   derived in one Swift function from the frequency, per band. RSSI on
   the same card when the device answered it, refreshed with the
   category. Nothing here is editable.
3. **Networks.** The known-network table, redacted, with the selected
   entry checked. Tapping an entry selects it (a `WIFI_NETWORK` write,
   through `Edits` so it applies with the rest); tapping the selected
   entry deselects it. Swipe to forget runs `removeNetwork` at once
   with a confirmation, since a remove is not a dirty write and the
   sketch says removing the selected entry drops the link. A hidden
   entry shows a badge. An "Add hidden network" row opens the join
   sheet with an SSID field, for the network no scan will show.
4. **Scan.** A button that writes `WIFI_SCANNING = 1` through
   `ulcpDirtyWrites` as its own operation, not the Apply batch, because
   a scan is not an edit. While the reading's `wifiScanning` is true
   the section shows a progress row and the list fills from pushes,
   grouped by SSID, strongest per name, sorted by signal, with a
   security badge from the strongest offered mode and an "In your
   networks" mark for SSIDs in the table. Nameless results group under
   "Hidden network" by BSSID. On the mesh link there are no pushes, so
   the model polls `WIFI_SCANNING` every two seconds after the write
   and reads `WIFI_SCAN_RESULTS` once it reads `0`, which is the flow
   the sketch prescribes for that binding. Tapping a result opens the
   join sheet.

   On a device with `CAP_WIFI_SCAN` and no station, this is the whole
   screen, under a header that says the device can see networks and
   cannot join them, and the join sheet does not exist.
5. **Problems.** `RemoteProblemSection`, as every category has.

**The join sheet** takes an SSID (fixed from a result, editable for a
hidden network), a hidden flag (preset from the path in), a mode picker
limited to the modes the result offered and the app can build a
credential for (open, OWE, WPA2, WPA3, WPA; the enterprise modes and
WEP are listed grayed with "not supported"), and a `SecureField` for
the credential with the mode's length rule enforced by the Stage 2
writer before the sheet will submit. Submit runs `insertNetwork`; on
`STATUS_UNIMPLEMENTED` it offers the next weaker offered mode in the
same sheet rather than failing, which is the sketch's step-down flow
with the operator in the loop instead of an automatic downgrade. On
success it writes `WIFI_NETWORK` to the SSID as a second operation, and
the connection card follows the link from there. A passphrase entered
for an existing SSID replaces the entry, which is how a wrong one is
fixed; the sheet says so when the SSID is already known.

**Edits** carries `enabled` and `network` as `RemoteField`s. Scanning is
not in it.

### RemoteNetworkScreen.swift

One card per family the device offered, IPv4 first:

* **Status**: the family state in words, then what it holds. IPv4: the
  address with its prefix and the gateway, or "No gateway". IPv6: every
  address item and every router item, formatted with the system's
  `IPv6Address` description. `IP_CONFLICT` is rendered as a warning with
  the configured address, since the fix is the row below.
* **Configuration**: a method picker (Automatic, Static, Off) and, for
  Static, address, prefix, and gateway fields validated by the Stage 2
  writer as typed. Applies through `Edits` with the row-level refusal
  title. The stranding warning applies on the mesh link to any static
  change, by the sketch's argument that a wrong static address strands
  a bridge as surely as a disabled station.
* **DNS**, once for both families: the configured list, editable as a
  small table with an add row and swipe to delete, applied as one
  whole-set write; and beneath it the resolvers in use, read-only,
  which is the diagnostic the sketch keeps the second property for.

### Display rules

* An SSID is untrusted octets. It is shown as UTF-8 when it decodes,
  and as a hex string with a monospace font when it does not, and it is
  never used to build a string that reaches anything but a label.
* Credentials are never logged, never cached, never placed in a record
  that outlives the sheet.
* Frequencies are shown with the channel first because that is what a
  router's admin page shows; the megahertz stay in parentheses because
  the channel number is ambiguous across bands and the frequency is
  the fact.

### Fake device

`FakeManagedDevice` grows a Wi-Fi model rather than eight more fixture
octets, because the screen's interesting behavior is sequencing:

* capability bytes for 53–56, and a second constructor for a scan-only
  device (53 alone) behind a debug toggle beside "Staging mode" in
  Settings, since the staged radio is built once at launch from
  `UserDefaults`;
* a known-network table of two entries, one selected, and a link that
  is `UP` on it; the enabled toggle drops it to `DOWN` and back to
  `CONNECTING` then `UP` on a timer;
* a scan that emits the sketch's frame order through the push stream:
  the empty `Is`, `scanning = 1`, six `Inserted` items over about two
  seconds with one BSSID repeated at a different RSSI to exercise
  replace-by-key, and `scanning = 0`. A scan while disabled refuses
  `STATUS_INVALID_STATE`;
* inserts that refuse `STATUS_UNIMPLEMENTED` for WPA3 so the step-down
  path is reachable, `STATUS_INVALID_ARGUMENT` for a bad credential
  length, and `STATUS_NOMEM` past four entries; a select of an unknown
  SSID refuses `STATUS_ITEM_NOT_FOUND`;
* an IP model that follows the link: `IP_NO_LINK` while down,
  `IP_WAITING` for a second, then `IP_READY` with a fixed lease; a
  static write that lands on the "taken" address goes to `IP_CONFLICT`.

On the mesh path the same model answers fetches and writes without
pushes, so the polling flow is exercised against staged peers too.

## Stage 5: the real session in front of the app

This is the stage that turns "the app follows the spec" into "the app
works with the device", and it is optional in the sense that the
previous four stand without it. It is recommended, because it is the
only test of the app against the protocol machinery that firmware
actually runs, and it can run before any board has a Wi-Fi driver.

* `crates/umsh-ulcp-device`: `SessionConfig` gains `wifi: Option<WifiConfig>`
  and `ip: Option<IpConfig>` in the shape of `gnss` and `ble`, the
  session serves the sixteen properties by the chapters, enforces the
  refusals and the frame orders, and the saved schema gains the six
  configuration properties. Station and stack *behavior*, joining,
  scanning, leasing, is behind new `Effect` variants and `DeviceEnv`
  hooks with default implementations that refuse, so both firmwares
  compile unchanged and advertise neither capability.
* `crates/umsh-ulcp-simdev`: an in-memory station and stack that
  answer the hooks: a fixed set of access points to hear, a join that
  succeeds against a known passphrase and fails `WIFI_REASON_AUTH`
  against any other, a lease that arrives a tick after the link.
* `umsh-bridge` `[[server.hosts]]` presents it on a socket; the app's
  TCP radio mode attaches to it from the simulator. `umsh/tests/ulcp_full_protocol.rs`
  gains the scan and join flows end to end, which pins the frame order
  in a test a firmware change cannot break silently.

Nothing in this stage touches `firmware/` or `firmware-esp32/`. What it
leaves for the platform plan is exactly the `DeviceEnv` hooks, with the
simulated device as the reference for what each must do.

## Sequence and commits

1. Stage 1 and the constants half of Stage 2 (`ids.rs`, `describe.rs`,
   the dissector table) as one commit: the spec and every table that
   names its numbers, with the sketch document deleted.
2. The codecs (`wifi.rs`, `ip.rs`) with their tests.
3. The mobile core, bindings regenerated, API version bumped.
4. The app: model and backend, then the two screens, then the fake
   device, verified on the simulator in staging mode against both the
   full and the scan-only fixture and through the mesh path.
5. Stage 5 if taken, verified by attaching the simulator build to a
   bridge host and running every flow in the sketch's Mechanics section
   by hand.

Each of 2 through 4 builds and tests on its own; nothing in the app is
reachable until the category returns properties, and the fixture is the
last thing switched on.

## Out of scope, and where it goes

* **The access point.** The sketch defines `CAP_WIFI_AP` and properties
  4912–4915, and Stage 1 carries them into the Wi-Fi chapter and the
  index so the numbers are taken, with their constants in `ids.rs` and
  `describe.rs` beside the rest. Nothing else in this plan implements
  them: no codec, no record, no screen, no fixture. They are the one
  part of the chapter the app will not exercise, and they wait for a
  use that needs a device to offer a network.
* **Firmware** for the ESP32 station and the T1000-E sniffer: the
  platform plan, against the Stage 5 hooks.
* **umshctl** verbs (`wifi scan`, `wifi join`, `manage wifi …`): a small
  follow-up once the codecs exist; the describe tables already give it
  raw access.
* **The web debugger**: renders from `describe.rs` and gets the names
  for free; a structured view of the scan is its own task.
* **What the connection is for.** No bridge-client, time-source, or
  local-binding capability is designed here; the sketch places each
  behind its own capability.
