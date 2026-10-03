# BLE privacy migration and qualification

The nRF52 and ESP32 firmware use rotating private addresses, advertising
with generic BLE flags and the ULCP service UUID outside pairing. The interval
is 20 ms during pairing and for the first 30 seconds after boot; otherwise it
is 546.25 ms. See
[ULCP over BLE](protocol/src/ulcp-ble.md#ble-advertising) for the policy.
The iPhone app uses AccessorySetupKit to authorize radios. No new UUID, property or firmware configuration
switch is required.

## One-time migration

On the first boot after this update, the firmware automatically removes all
existing radio-side pairings, clears the pairing PIN and replaces the local
IRK. This includes pairings made with the earlier privacy-enabled firmware.
The cleanup and its completion marker are saved as one durable operation,
before BLE starts. Every previously paired phone needs to pair again:

1. Update the radio firmware.
2. Forget the old radio pairing in the phone's Bluetooth settings. Firmware
   cannot remove the phone's saved pairing for it.
3. Enable Bluetooth on the radio if needed, open its pairing window,
   choose **Add Another Radio…** in the app, and pair again. Reopen the window if it
   expires while completing these steps.

Pairing windows last five minutes when no bonds are retained, or two minutes
when at least one bond is retained. The duration is selected when the window
opens. Successful pairing or an encrypted reconnection by a bonded host closes
the window early; internal BLE restarts do not extend it.

The cleanup preserves non-BLE configuration, configured name, device identity
and BLE enablement. It also runs while BLE is disabled without enabling it.
New pairings and the replacement IRK survive normal restarts and subsequent
compatible firmware updates. Renaming alone needs no re-pair.

If saving the migration fails, the previous journal remains intact and BLE
stays blocked; the next boot retries the cleanup. Other transports remain
available. An authorized “forget all hosts” action can also complete the
cleanup; toggle Bluetooth off and on afterward to retry BLE initialization.
For an ordinary clear requested over BLE, a lost response can occur after a
successful durable clear, so check through the local menu or another
authorized interface when the outcome is uncertain.

## Reconnection and names

Keep the app's existing pending CoreBluetooth connection request,
Bluetooth background mode and state restoration. AccessorySetupKit manages
authorization and the saved list; CoreBluetooth retains the transport. Radio
pickers scan for authorized, connectable advertisers while open in the
foreground. Background reconnection does not use polling or scanning loops. The
acceptance target is reconnection within 30 seconds after returning to
stable range with the phone locked and app backgrounded. A build does
not establish this timing guarantee.

The app reconnects to its remembered companion through a pending connection
request, without requiring the ULCP UUID in each advertisement. Verify this
path across RPA rotation with the UUID advertised outside pairing. Paired radios advertising nearby
appear in the app pickers without entering pairing. Devices stop appearing
after roughly six to eight seconds without advertisements, while their saved
authorization is retained. Adding a new radio uses Apple's picker with pairing
open. The app caches configured names from encrypted connections; it does not
expose names in non-pairing advertisements to populate these lists.

An older app's saved companion requires a one-time AccessorySetupKit migration,
including when it was paired with new privacy firmware. Select **Finish Radio
Setup** in the radio banner, radio details or saved-radio list and complete
the system flow before connecting. If it cannot
find the radio, bring it nearby and open its pairing window. Cancelling leaves
the migration pending. The older app did not retain identifiers for all
administrative visits or previous companions; those radios need to be added
through the picker. App migration cannot restore a bond erased by the
firmware cleanup above. See the [iOS setup guide](../apps/ios/README.md#radio-setup-and-saved-radios)
and [qualification cases](architecture/decisions/ios/0008-accessory-setup.md#evidence-and-pending-qualification).

The configured GAP name is available during deliberate pairing and to
encrypted, durably bonded phones. A rename records a pending Service Changed
indication for each retained bond. Each phone's ATT confirmation clears only
its own pending indication; missed renames survive reboot. Ordinary encrypted
reconnects with no pending rename do not send this compatibility indication.
A name-value change is not a service-structure change. iOS controls its Settings
cache and may keep an old name temporarily. The firmware does not force
a disconnect, expose the name publicly, or require re-pairing to try to
refresh it. Check the app name and Settings name separately.

## Implementation policy

BLE advertising waits for the protocol task to finish restoring NVRAM settings
and publish the authoritative device name, BLE enablement and device-domain
settings. A dedicated retained watch releases the advertiser only after
that publication. It remains closed during snapshot fallback and asynchronous
name publication. A factory-fresh device releases it after publishing defaults;
unreadable snapshots follow the existing bounded fallback/default policy and
diagnostics. Readiness remains available across internal BLE restarts. Stack
and controller initialization are not deferred by this gate; only the advertiser
waits. Initialization alone does not permit advertising with a temporary default name.

Both firmware families set equal minimum and maximum advertising intervals:
20,000 microseconds (32 units of 625 microseconds) throughout the pairing window
and for the first 30 seconds of boot uptime, and 546,250 microseconds
(874 units) otherwise. Opening the window selects the faster interval;
expiry, explicit closure, successful pairing and bonded reconnection restore
the normal policy for subsequent advertising once the startup period has ended.
The startup deadline uses boot uptime, so internal BLE restarts and BLE
disable/re-enable do not reset it. When the deadline expires outside pairing,
an active advertiser is reconfigured without waiting for another user event.
The deadline never interrupts controller configuration or an active connection.
Fast startup advertising does not open a pairing window or disclose a name.
The controller adds normal advertising jitter. This follows Apple's
[advertising interval guidance](https://developer.apple.com/library/archive/qa/qa1931/_index.html),
which recommends 20 ms for at least 30 seconds and permits slower intervals
afterward. The faster rate lasts for the existing five-minute unbonded or
two-minute bonded pairing window, unless that window closes earlier. It trades
higher radio activity during startup and setup for more discovery opportunities.
Pairing advertisements carry the ULCP service UUID and the board's model
identifier, as manufacturer data under company identifier `0xFFFF`. Scan
responses carry up to 29 UTF-8-safe name bytes. iOS hands the app only the
advertising data during setup, so the app titles a new radio by its board and
the system picker shows the scan-response name beneath it. Outside pairing, the
advertising payload contains `02 01 04` (Flags, BR/EDR Not Supported) followed
by the complete 128-bit ULCP service UUID list, and scan-response data is empty.
No name, appearance, manufacturer data or service data is sent. Each transition replaces the
advertising payload and explicitly clears previously installed scan-response
data. The common service UUID identifies ULCP capability, while names and
per-device identifiers remain absent outside pairing. RPAs do not make
transmissions invisible or prevent active service probing through a connection.

Trouble uses the persisted local IRK with a 900-second RPA timeout. The static
address remains an internal bonding identity. Pairing boundaries rebuild the
BLE stack to refresh its advertising address, deferring until disconnection
when connected. These restarts preserve pairing deadlines, authentication
failures, lockout and BLE enablement. Ordinary runner exits also rebuild the
stack, with a one-to-five-second backoff that resets after stable operation.
Privacy initialization failures stop advertising and report through firmware
diagnostics; toggling Bluetooth off and on retries initialization.

A BLE request to forget all hosts waits for controller completion of the
final response before replacing the stack. A failed transmission,
disconnection or ten-second response deadline still completes revocation;
diagnostics report when transmission could not be confirmed. A local-menu
clear does not need a transport reply.

The BLE journal retains a name fingerprint and a pending flag per bond.
Journal versions 3 and 4 require the one-time cleanup. Version 5 records its
completion in the same committed snapshot as the empty bonds, cleared PIN
and replacement IRK. Legacy security material is retained only until that
replacement commits and is never restored into a live BLE stack. Unrelated
journal writes cannot mark the cleanup complete. A failed persistence
operation leaves the previous snapshot intact.

## Hardware qualification—pending

These qualification checks have not been performed for this implementation.
Record firmware revision, board, controller/phone OS versions, capture files and raw
measurements with every result. Do not label these checks passed from
source inspection or successful compilation.

**Controller privacy qualification is a flashing prerequisite for deployment
on each board, including every ESP32 variant.** On qualification hardware,
verify that the controller reports at least five resolving-list entries:
four retained peers plus Trouble's local-IRK entry. Verify the local entry
works before the first bond and all four peer entries can coexist with it.
An insufficient capacity or failed privacy setup leaves BLE unavailable;
there is no permanent-address fallback. These controller checks remain
unverified on ESP32 and must not be inferred from a successful build.

| Check | Required evidence | Status |
| --- | --- | --- |
| Advertising on both families | Capture equal min/max configuration and roughly 20-ms events during pairing and the first 30 seconds after boot; verify an automatic return to 1.0225-second events outside both periods, plus BLE jitter. Internal BLE restart and disable/re-enable must not extend the startup deadline | Pending |
| Payload privacy | Active and passive scans show only generic flags, the ULCP UUID and an empty scan response outside pairing; the model identifier and configured names appear only during pairing; no permanent address, stale model identifier or stale name after expiry/closure/success/reconnect | Pending |
| Address changes | Capture at least two complete 15-minute rotation periods; resolve with the retained IRK; check fresh addresses at both pairing boundaries, including deferred refresh after a connected boundary | Pending |
| Privacy failure | Inject unsupported commands, insufficient resolving-list capacity and local/peer IRK-entry failures; verify advertising stops and diagnostics identify failure | Pending on controllers |
| Runner recovery | Inject an ordinary runner/transport exit; verify bounded automatic recovery, unchanged pairing deadline and lockout, and successful bonded reconnect without a BLE toggle | Pending |
| Bonds | Fresh pairing; automatic migration from pre-privacy and earlier privacy firmware, including disabled BLE and interrupted migration; new pairings survive later boots; four retained hosts; fifth-host eviction; BLE off/on; clearing while connected and while disabled | Pending |
| Revocation | Retain the old IRK for the test and verify it cannot resolve advertisements after clear; old bonds cannot reconnect; non-BLE state remains unchanged | Pending |
| Final clear response | Capture all notification segments completing before disconnect/rebuild; repeat with congestion, radio loss and reply timeout, verifying revocation still completes | Pending |
| Background reconnect | At least 20 leave/return trials per tested family, phone locked and app backgrounded; include prolonged absence and RPA rotation; every stable-range trial <=30 seconds | Pending |
| T-1000E pairing indicator | Hold the button through startup with Bluetooth previously disabled; verify double-blink on battery, expiry and reconnect; charging and low-battery indications retain their existing priority | Pending |
| T-1000E LoRa regression | Verify button beacon/chirp and bidirectional LoRa after boot and LoRa disable/re-enable; the corrected LR1110 driver must resume from cold sleep | Pending on hardware; reproduced and covered by driver host tests |
| Two-phone names | Rename connected, rename while away, reboot, reconnect A then B and B then A; compare Settings and app separately; one phone's refresh cannot consume the other's opportunity; an ordinary reconnect with no rename sends no Service Changed indication or extra app attach cycle | Pending |
| Disconnected power | Measure current against 160-ms firmware on the same hardware and settings, with comparable RF conditions; report raw measurements | Pending |
| Connected power | Compare connected-idle current and phone background activity; check for repeated app wakeups/scanning loops | Pending |

Report each reconnect trial's latency and failures; do not silently relax
the 30-second target. Do not estimate battery-life improvement from the
advertising-interval ratio. Address rotation reduces tracking by observers
without the IRK; deliberate pairing and continuous radio observation still
allow correlations.

## Software validation

Host tests cover advertising payloads and UTF-8 boundaries, name-read
permissions and supported ATT read/probe forms, pairing policy/deadlines,
controller privacy command failures, runner-recovery backoff and transmission
fences, per-bond rename confirmation across reboot and interrupted writes,
atomic bond/IRK replacement through journal power cuts, and one-time migration
with subsequent pairings retained. Build all five nRF board
variants and all four ESP32 tracker variants. Run the ESP32 release stack
budget checks before any later flashing; record results separately from
the pending hardware tests above.

A successful release build does not replace the stack-budget checks. Any
failing check is a flashing blocker; do not lower the required reserve to
make it pass. Stack checks cover individual frames and a reserved margin,
not complete call chains or hardware stack qualification.
