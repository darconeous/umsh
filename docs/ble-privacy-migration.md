# BLE privacy migration and qualification

The nRF52 and ESP32 firmware use rotating private addresses, nameless
advertising outside pairing, and a 1,022.5 ms advertising interval. See
[ULCP over BLE](protocol/src/ulcp-ble.md#ble-advertising) for the policy.
No phone application update, new UUID, property or configuration switch
is part of this change.

## One-time migration

Firmware upgrades preserve the existing bond journal. Those old bonds
cannot be relied on for automatic recognition after the radio starts
using its IRK for private addresses. Perform this manual migration once:

1. Update the radio firmware.
2. Explicitly clear the radio's bonds with the local “forget all hosts”
   action or an available authorized interface, such as an attached wired
   session writing zero to `PROP_BLE_BOND_COUNT`. Do not depend on the old
   BLE connection remaining usable after the upgrade.
3. Forget the old radio pairing in the phone's Bluetooth settings.
4. Enable Bluetooth on the radio if needed, open its pairing window,
   select the radio in the app, and pair again. Reopen the window if it
   expires while completing these steps.

Clearing all hosts replaces the local IRK and clears the pairing PIN as
one durable operation. Every previously bonded phone needs re-pairing.
It preserves non-BLE configuration, configured name and device identity.
Normal restarts retain the new bonds and IRK. Renaming alone needs no
re-pair. A failed clear reports failure and retains the previous security
state; a lost response can occur after a successful durable clear, so
check the radio through the local menu or another authorized interface.

## Reconnection and names

Keep the app's existing pending CoreBluetooth connection request,
Bluetooth background mode and state restoration. This implementation
makes no app changes and adds no polling or repeated scanning. The
acceptance target is reconnection within 30 seconds after returning to
stable range with the phone locked and app backgrounded. A build does
not establish this timing guarantee.

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

Both firmware families set the minimum and maximum advertising intervals to
1,022,500 microseconds (1,636 units of 625 microseconds), including during
pairing, with no fast bursts. The controller adds normal advertising jitter.
Pairing advertisements carry up to eight UTF-8-safe name bytes and scan
responses carry up to 29. Outside pairing, both omit the name and any old
scan-response data is explicitly cleared.

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
An older journal is read without changing its security material; its first
configured-name publication seeds the fingerprint without synthesizing a
rename. A failed persistence operation leaves the previous snapshot intact.

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
| Advertising on both families | Capture min/max configuration and roughly 1.0225-second events plus BLE jitter, both in and outside pairing; no fast burst | Pending |
| Payload privacy | Active and passive captures show the ULCP UUID, no local name or permanent address outside pairing, and no stale scan-response name after expiry/closure/success/reconnect | Pending |
| Address changes | Capture at least two complete 15-minute rotation periods; resolve with the retained IRK; check fresh addresses at both pairing boundaries, including deferred refresh after a connected boundary | Pending |
| Privacy failure | Inject unsupported commands, insufficient resolving-list capacity and local/peer IRK-entry failures; verify advertising stops and diagnostics identify failure | Pending on controllers |
| Runner recovery | Inject an ordinary runner/transport exit; verify bounded automatic recovery, unchanged pairing deadline and lockout, and successful bonded reconnect without a BLE toggle | Pending |
| Bonds | Fresh pairing; migration from old firmware; four retained hosts; fifth-host eviction; reboot; BLE off/on; clearing while connected and while disabled | Pending |
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
and atomic bond/IRK replacement through journal power cuts. Build all five nRF board
variants and all four ESP32 tracker variants. Run the ESP32 release stack
budget checks before any later flashing; record results separately from
the pending hardware tests above.

A successful release build does not replace the stack-budget checks. Any
failing check is a flashing blocker; do not lower the required reserve to
make it pass. Stack checks cover individual frames and a reserved margin,
not complete call chains or hardware stack qualification.
