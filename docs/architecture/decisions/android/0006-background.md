# ADR 0006: Background radio link with a connectedDevice foreground service and CDM presence

- Status: Accepted; emulator-verified (API 31 and 36, Bumble and the bridge),
  everything that depends on a real phone's power management unverified
- Phase: 2

The Android counterpart of iOS [ADR 0006](../ios/0006-background-support.md).
The link itself is [ADR 0004](0004-ble-boundary.md); the association that
grants the exemptions below is [ADR 0005](0005-companion-device-manager.md).

## Decision

### The host owns the link; the service holds the process

`AppCoreHost` owns the one live radio connection. `RadioForegroundService`
(type `connectedDevice`, `START_NOT_STICKY`) owns nothing: it keeps the process
at foreground priority and carries the radio notification. A decision function
of the radio's state starts and stops it. It runs while a radio is bound with
`autoConnect` and its link is connecting, attached, or reconnecting within the
window, and, under the Waiting strategy, while waiting. The staging core never
starts it. The debug TCP link uses the same service, satisfying the type's
API 34+ prerequisite with `CHANGE_NETWORK_STATE`; a BLE radio needs the Nearby
devices grant, checked before every start. A refused or lost start is retried
on the next foreground.

The notification is silent, in the Radio connection channel, and shows
Connecting, Connected (with battery), Reconnecting, or Waiting (with the last
battery reading and its age). Disconnect, or Stop while waiting, is a real
Disconnect; swiping it away is not. Task Manager Stop is not a Disconnect
either, but holds the radio off until the app is opened (a deliberate stop,
below). Its tap opens Radio Detail.

### After a link loss

1. Reconnecting, with an `autoConnect` GATT armed, for a 2-minute window on
   the sleep-counting clock, re-checked every 10 s awake so a window that ends
   in deep sleep closes at the first wake.
2. Past the window, by strategy (Developer switch in debug builds):
   - **Presence** (default, when the device has
     `FEATURE_COMPANION_DEVICE_SETUP` and the radio is associated): close the
     GATT, report Waiting for the radio, stop the service. CDM presence wakes
     `RadioPresenceService` (exported behind `BIND_COMPANION_DEVICE_SERVICE`;
     the address form on API 31–32, `AssociationInfo` on 33–35,
     `ObservingDevicePresenceRequest` and `onDevicePresenceEvent` on 36+), which
     starts the service from the background under the association's
     exemption. The service starts the live core headless (never minting an
     identity) and asks the held connection to reconnect. A CDM rebind of the
     service (after an app update or force-stop while the radio is present)
     counts as an appearance.
   - **Waiting**: keep the service and an `autoConnect` GATT armed, for as long
     as a radio is remembered.
3. Bluetooth off: Unavailable. Presence stays registered (the system's presence
   scan resumes with Bluetooth), and an appearance reported while Bluetooth is
   off is held until it comes on; under Waiting the service stays and its
   adapter-state receiver re-arms the link. No manifest receiver can do this.
4. A driver give-up (`invalidate(retry = false)`, bond loss included), DFU,
   Disconnect, Forget and a radio factory reset all clear `autoConnect` in the
   registry, so no later process, presence wake or notification action
   re-arms the radio; only the user's Connect or Reconnect does.

Presence observation is level-triggered from the registry: the bound, wanted,
associated BLE radio under Presence is observed, and every other association
is not.

### After an update

An update ends the process. API 36 and later rebind the presence service
when the radio is present, which counts as an appearance. API 31–35 report
no new appearance for a radio they still count as present, so an
`ACTION_MY_PACKAGE_REPLACED` receiver starts the service instead, from that
broadcast's exemption, under a presence wake's rules: only the bound, wanted
radio that is not still being added, with Bluetooth on. It does nothing on
API 36 and later.

### A deliberate stop

App info's Force stop, and Task Manager's Stop on API 34 and later, mean
"nothing until I open it". Android still binds the presence service after
either, so each process reads `getHistoricalProcessExitReasons` once as it
starts. An exit it has not read before with `REASON_USER_REQUESTED` sets a
kept "stopped until opened" flag; opening the app clears it. While it is set,
neither presence, the rebind nor the update receiver starts the service or
seeks the radio. The flag is kept, so it holds through any number of process
starts until the app is opened. A background kill (another app's
`killBackgroundProcesses`, a memory cleaner, `am kill`) is also recorded as
`REASON_USER_REQUESTED`, described "kill background", and is not a stop. On
API 31–33 an update's own kill is recorded the same way, described as the
installer's stop ("installPackageLI"); with no description, one within 10 s
before the update's recorded time (5 s after) is taken for the update's. API
34 and later record it as `REASON_PACKAGE_UPDATED`.

### Doze and timers

The core and the driver keep their own monotonic timers; a foreground service
does not hold a wake lock, so under Doze they may run late. Phase 2 measures
and does not fix: the app logs, per sent message, the time to each caption
change (`send timing:`). If ack timers slip on a phone, the remedy is a partial
wake lock for the length of one active send, not exact alarms (denied by
default on API 34+).

### Location

No background location. The phone's position is read only while the app is
started and sharing is on; the core keeps the last position until the process
ends. A headless start after that advertises no location until the app is
opened. A `connectedDevice` service cannot read location in the background
without `ACCESS_BACKGROUND_LOCATION` and type `location`, which this avoids.

### Notifications from the background

Message notifications come from the core's change records through one
in-process channel, drained by `MessageNotifier` in the host scope, so they post
while the service holds the process without UI. Every post (a batch's lines,
a Reply's end, an unlock's reveal) goes through one queue, spaced 300 ms apart
and built from lines the notifier keeps, since Android shows a post a moment
after it is made and sheds a package's updates above five a second. Inline Reply holds its
`goAsync` result until the work ends, starts the service first when none runs,
starts the runtime headless, waits up to 15 s for the radio, then sends; a
failure keeps the words as the draft and says so.

## Verification on the emulators

- The reconnect window, both strategies, the Developer switch past the window,
  Bluetooth off and on under each, Stop from the Waiting notification (API 31
  and 36, Bumble).
- Presence wakes with the process dead: real advertising on/off on API 31;
  on API 36 only through `cmd companiondevice simulate-device-appeared`,
  because the emulator's CDM scan filter never matched a rotated private
  address.
- Doze labeled "FGS survives force-idle": `deviceidle force-idle deep` with the
  battery unplugged; a peer's message posted a notification and an inline
  reply went out, on both levels. Emulators do not suspend the CPU, so timer
  lateness is unmeasured.
- Process: `am kill` kept the process (the service held it); associations
  survive. Before the stop flag, `am force-stop` and `am stop-app` came back
  through presence or the rebind. The exit reasons the flag reads were checked
  on both levels: `am force-stop` and `am stop-app` record
  `REASON_USER_REQUESTED` (on API 36 with subreasons FORCE STOP and STOP APP),
  an update `REASON_USER_REQUESTED` on API 31 and `REASON_PACKAGE_UPDATED` on
  API 36, and `am kill` of the cached process `REASON_USER_REQUESTED`
  described "kill background" on both; the flag was set after each stop and cleared on opening, and an
  update alone never set it. After a stop, neither level delivered the update
  broadcast at all. With no radio set up, the update receiver ran but had
  nothing to start, and the presence wake under the flag was not run.
- The device-idle allowlist listed the app after association on both levels
  in the Doze run (API 36 failed to list it once, in an earlier run, cause
  unknown).

## Play and OEMs

- Play requires the `connectedDevice` foreground-service type declaration, with
  a video of the feature, in the Play Console. That is Phase 5 release work.
- OEM battery managers (the main real-world killer of foreground services) are
  untested by design: the plan assumes a Pixel and no other hardware.

## Unverified

The Pixel checklist below is the full list of hardware guesses from Phases 2
and 3, copied from their verification reports. Phase 3's items for links,
sharing and the scanner are in [ADR 0007](0007-links-and-scanner.md). None
has been run on hardware.


Every hardware guess from the plan (§12, G-1 to G-30) and from the build reports (P2a–P2h, G-31 to G-111, plus
P2c's unnumbered items and P2i's), deduplicated. An item that absorbed others lists them in brackets; the lowest
number is kept. P2c's unnumbered items are numbered G-112 to G-121, P2i's G-122 and G-123, and the final review's G-124 to G-135. Radios: a T1000-E (nRF,
trouble) and a Heltec V3 (ESP32, NimBLE). "Pixel" means a current Pixel on API 36; items that need API 31–35 say
so and are n/a without such a phone. Nothing here has been run on hardware.

Retired: **G-1** (netsim carrying a GATT server from a second emulator). The Bumble spike passed, so the fallback
it guarded was never built.

#### A. Bluetooth link

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-7 [G-57] | MTU 517 requested settles at 255 on the nRF radios; the ESP32's value is unknown; no radio grants ≥ 516; the 8 s write deadline is ample | Attach a T1000-E and a Heltec V3; log `onMtuChanged`, connection parameters and write latencies | 255 on the T1000-E; a logged value on the V3; writes well under 8 s | Adjust the deadline; segmentation adapts and the 512 cap makes a large MTU harmless |
| G-10 | GATT status codes on link loss (8 supervision timeout, 19 remote, 22 local, 133) map as the plan's invalidating set | Walk out of range, power the radio off, toggle Bluetooth; log the status | Each ends in Reconnecting, then the window | Adjust the invalidating set in `BleRadioLink` |
| G-11 | `onServiceChanged` arrives after a DFU to a build with a different GATT table, and rediscovery recovers (a rename never raises it); with a frame write in flight, discovery waits for that write's answer and the CCCD write is never refused as busy | DFU a radio to such a build, then reconnect; once more while sending a long message | Attaches after rediscovery; no `DescriptorWritten(257)` fault | Close and reconnect instead of rediscovering |
| G-48 | A 20 ms requeue after `ERROR_GATT_WRITE_REQUEST_BUSY` is enough under notification load (the emulator never returned busy); busy never lasts the 8 s write deadline, which counts from the first issue and ends a stuck write with `WriteUnacknowledged` | Send a burst of long messages while the radio notifies (busy channel) | No write failures; any busy is logged and requeued | Lengthen the requeue delay or back off |
| G-52 | A direct (`autoConnect=false`) connect to a radio that is not advertising times out (~30 s) and falls back to the background reconnect without a visible failure | Radio off, Reconnect from Radio Detail, radio on after 1 min | Connecting, then attached once it advertises; no Failed | Map the timeout to the background path explicitly |
| G-62 | A background `autoConnect` reconnect after link loss arrives within seconds while the radio advertises | Restart the radio; time from advertising to attached | Seconds | Pixel duty cycles may stretch this to minutes: tune or add a direct attempt |
| G-124 | On API 34+ the stack exchanges MTU 517 by itself on connect; the app's later `requestMtu(517)` still gets one `onMtuChanged`, and an unsolicited one arriving while the bond step is current is harmless | Attach a T1000-E and a V3; log every `onMtuChanged` with its timing relative to `requestMtu` | One callback per request; 255 on the nRF radio | A missing callback costs the 10 s MTU deadline and then `AttachmentIncomplete` on every attach: complete the MTU step from any `onMtuChanged`, or skip the request when the MTU is already above 23 |
| G-133 | The app never calls `requestConnectionPriority`; the Pixel's default LE interval (balanced, possibly longer with the screen off) carries long-message bursts and ULCP traffic without visible lag | Send a burst of long messages screen on and off; log write latencies (with G-7) | No visible lag | Ask for HIGH priority while sending, then BALANCED again |

#### B. Scanning and Connect a radio

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-2 [G-49] | The service-UUID scan filter returns pairing-mode radios (flags 0x02 / `0xFFFF` model element in the primary packet, name in the scan response), screen on, within 5 s; the name fills in without reordering | Connect a radio with a T1000-E and a V3 in their pairing windows; log `ScanResult.scanRecord` | Both listed within 5 s with name, model and photo | Unfiltered scan plus an app-side match while the page is open |
| G-50 | Board photos from the `nodpi` 3x PNGs render crisply at Pixel density on the scan rows and the Radio Detail header | Look | Sharp | Ship density buckets |
| G-58 | Pausing the scan while connecting and bonding helps, or does not hurt, connection setup | Pair several times | No 133 on the first connect | Keep scanning during the connect |
| G-59 | A real radio may take a new address when it re-advertises after a failed pairing (Bumble does); the old row then goes within ~3 s and a retap reaches the radio | Decline the pairing dialog, then tap the row again | The new row works; no row hangs on a dead address | Lengthen or shorten the resume grace |
| G-60 | Scan registration failures (2, 6) are rare; the 5 s / 30 s restart recovers; a silently throttled scan (5 starts in 30 s) is not detected | Open and close Connect a radio quickly many times | The list still fills | Add a throttle-aware restart |
| G-31 | Allow on the Nearby devices banner asks while Android still shows the dialog, then opens app settings; dismissing the dialog with Back or a tap outside leaves it askable; a second refusal makes Allow open settings; Turn on asks for Nearby devices first, then goes straight to the Bluetooth request; the permission dialog pauses the activity | Revoke Nearby devices; walk each path | As described | Adjust `PermissionAsking.decide` / `blockedAfterRefusal` |
| G-51 [G-13] | Bluetooth off then on (Quick Settings) gives Unavailable, then a reconnect within seconds; with the app backgrounded the radio comes back by presence (Presence strategy) or by the Waiting service's receiver. With "Bluetooth scanning" on (the Pixel default) Bluetooth off leaves the stack in BLE_ON: CDM may report no disappearance, so no appearance when Bluetooth returns, and the adapter broadcast to a cached app waits until it leaves the cached state (the API 36 emulator tore the whole stack down instead, so it does not predict this) | Toggle in Quick Settings, foreground and backgrounded, under each strategy; under Presence once with Location › Location services › Bluetooth scanning on and once off | Back within seconds without opening the app, in every case | Default to Waiting for users who toggle often; no manifest receiver is possible. Under Presence with scanning on: keep the service through Bluetooth off as Waiting does (a design decision for the user) |

#### C. Pairing and inventory (CompanionDeviceManager, bonds)

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-65 [G-76] | CDM's single-device filter on the scanned resolvable private address (set through the 1-argument `ScanFilter.setDeviceAddress`, a PUBLIC type) still matches under the Pixel's offloaded filtering; the dialog appears within a few seconds | Tap a radio in Connect a radio | Dialog in seconds | Filter by service UUID plus name or MSD; otherwise every first pairing ends NoDevice after CDM's timeout |
| G-28 [G-69, G-75] | The CDM dialog left open past the pairing window ends in `pairing_removed` (emulator: 30 s, one 147 timeout); `onFailure` arrives when discovery finds nothing; a retry with the window reopened works | Open the window, wait in the dialog until it closes; also tap a radio that just left | `pairing_removed` within ~30 s; retry works | Adjust the CDM result handling or the 30 s deadline |
| G-6 [G-54, G-66] | Connect-then-bond is reliable; Just Works shows a plain confirmation or none (API 36 emulator: none for an associated radio); a PIN radio shows the passkey dialog in front of the app; if a radio sends an SMP Security Request, `createBond()` finds BONDING and waits | Pair a T1000-E and a V3 without and with a PIN | Bonded and attached each time | Let the CCCD write trigger pairing (iOS order) |
| G-46 [G-55] | The exported receivers get `ACTION_BOND_STATE_CHANGED`, `ACTION_ENCRYPTION_CHANGE` and `ACTION_KEY_MISSING`; "bond state 11 → 12" lands within a second of pairing | Pair; read logcat | Within a second | The bond step waits for its 60 s deadline: add a state poll |
| G-3 [G-53, G-70] | The address Android reports after bonding is stable across RPA rotation (900 s), a phone reboot and re-choosing a released radio; `getRemoteDevice(linkId)` + `autoConnect` reconnects | Log `linkId`; leave the radio unconnected > 15 min, return; reboot; re-choose a released radio | Same address; reconnects; no dialog on re-choose | Target the matching `bondedDevices` entry; record what Android reports |
| G-77 | Status 133 on the first direct connect right after the scan stops is rare; two in a row end as `connect_failed` and drop the new association | Pair ten times | No `connect_failed` | Third try or a settle delay after `stopScan` |
| G-78 | On API 34+, leaving the app between the tap and `onAssociationPending` may block the IntentSender launch | Tap a radio, go Home at once | Nothing breaks; the row stops spinning when the page is left | Re-launch on return |
| G-81 | After leaving the page with the CDM dialog answered Allow, `onAssociationCreated` still arrives and is removed at once, leaving no stray bond | Tap, Allow, Back immediately | No association, no bond | Remove on next start |
| G-19 | Two radios associated: choosing the other releases the current one first, keeps its association, needs no second dialog | Picker with two radios, both directions | As described | Re-associate on choose |
| G-80 | A released radio (host key cleared, bonded, out of its pairing window) still advertises the ULCP service with a name or model ID, so Choose a radio lists it (P2f M1) at the address CDM recorded | Release radio A by choosing B; open Choose a radio | A listed with its model | M1's promise cannot be kept from the app alone; a firmware question |
| G-21 | On API 36, Forget's `removeBond` removes the system bond and re-adding works | Forget; check Settings › Connected devices; Connect a radio again | Bond gone; re-add works | Leave the bond as on 31–35 |
| G-20 [G-74] | API 31–35 only: Forget leaves the system bond; re-adding the same radio from its pairing window re-bonds over it; stale bonds (one per factory reset or re-add) do not make Settings or address resolution misbehave | On a 31–35 phone: Forget, re-add, repeat | Works; Settings usable | Guide the user to remove the bond (copy change) |
| G-26 | Factory reset radio… from Radio Detail on a radio with CAP_REBOOT: the page closes once the radio accepts, "No radio set up" follows the link drop, re-adding works; firmware without CAP_REBOOT shows no Maintenance rows | Factory reset a T1000-E; re-add; check a radio without the cap | As described | Adjust the abandon path |
| G-56 [G-27, G-47] | A radio that lost this phone's keys (factory reset with the phone bonded, `PROP_BLE_BOND_COUNT = 0`) ends FAILED / "Open the radio's pairing window and add it again." within seconds: API 36 via `ACTION_KEY_MISSING` or HCI 0x05/0x06, older via the unasked re-pair | `umshctl` set the property, reconnect; separately factory reset from the radio | Refused within seconds; no loop | Adjust the bond-loss inference |
| G-71 [G-63, G-64] | API 31–35 only: a radio that lost its keys while Android kept its bond: the CCCD write fails with 5 or 15, or Android stalls and re-pairs (API 31 emulator: stalled; the 60 s subscribe deadline gave `AttachmentIncomplete`); Android's own pairing notification stays up 30 s; Android may drop its bond after an unanswered re-pair | On a 31–35 phone, wipe the radio's bonds | `pairing_removed`, not a reconnect loop | Design question: treat a subscribe timeout on a bonded radio as bond loss |
| G-61 | A system bond removed by the user (Settings › Connected devices › Forget) with the app still bound: the next reconnect is refused at once with no pairing request | Forget the device in Settings | `pairing_removed` | Adjust the no-bond refusal |
| G-72 | The firmware refuses pairing outside its pairing window (Bumble accepts, and API 31 then re-paired a Just Works radio silently) | Factory reset the phone side only, reconnect to a radio out of its window | Pairing refused | Security question for the firmware |
| G-29 | Two phones contending for one radio: the second gets a clear failure line, not a loop | Pair a second phone to an attached radio | One failure | Design follow-up for the user |
| G-68 [G-79, G-73] | API 31–32 only: the app-started passkey prompt is a notification the user must open within 30 s; the whole pairing fits the 90 s attach budget; rotating while the CDM dialog is up still completes | On a 31–32 phone, pair a PIN radio; rotate during the dialog | Completes | Copy hint while pairing with a passkey radio |
| G-135 | A process that ends during Connect a radio (after Allow, before the radio attaches) leaves nothing: the next start undoes the pending binding, releasing an association made for it | Force stop or `am kill` during the pairing dialog (API 31: during the passkey notification), then reopen | No "Failed" radio; no leftover association (`dumpsys companiondevice`); no presence observation for it | Adjust the pending-binding undo |

#### D. Background: reconnect window, presence, foreground service, Doze

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-12 | The 2-minute window catches ordinary drops; Restart radio… returns to Connected within it; "Restart not sent" only when the radio is unreachable | Restart from Radio Detail on both radios; walk away 1 min | Reconnecting, then Connected | Tune D5 |
| G-82 [G-95, G-96] | The window runs on the sleep-counting clock and is re-checked every 10 s awake: it closes at about 120 s on an active phone, at the first wake past it in deep Doze; a "Reconnecting" notification may linger on the lock screen until then | Screen off in a pocket, radio gone; time to service stop (Presence) or Waiting | Near 2 min active; next maintenance window in deep Doze | AlarmManager wake (rejected so far) |
| G-4 [G-83, G-97] | CDM presence wakes the app for a bonded RPA radio after rotation with the process dead (the API 36 emulator's CDM scan never matched a rotated RPA; API 31's did) | `am kill`; power-cycle the radio after 20 min; watch for the service start | The service starts and the radio attaches | Default to Waiting; Radio Detail's "Connects on its own" is false under Presence otherwise |
| G-5 [G-37] | A presence wake and a notification Reply each start the `connectedDevice` FGS from the background with no `ForegroundServiceStartNotAllowedException` | Same as G-4; reply from the shade with the app cold | Logcat "Background started FGS: Allowed" | Keep Waiting; investigate the exemption |
| G-84 [G-88] | API 36 sends `onDevicePresenceEvent(EVENT_BLE_APPEARED)` for a real appearance, plus the legacy callback (ignored on 36+) and BT-connected events on every link change; redundant starts cost nothing visible | Count service starts over a day | No visible churn | Debounce starts |
| G-91 | The 10 s headless-start settle is enough: no presence start stops early on a stale decision, none that should not run lingers | Presence wakes with a resting radio and a wanted one | Wanted attaches; resting stops in ~10 s | Tune the settle |
| G-23 | Phone reboot with a bound radio: presence wakes the app without a `BOOT_COMPLETED` receiver | Reboot, radio on, wait | Attaches without opening the app | Add a receiver that only re-registers presence |
| G-24 [G-85] | App update with the radio in range: on 36 CDM rebinds the service and the app reattaches (`onCreate` counts as an appearance); on 31–35 `AppUpdatedReceiver` starts the service and the radio is sought | Install a new build with the radio attached; again after a Force stop | Reattached within ~10 s; after a Force stop, nothing until opened | The receiver (DP-94); `UserStop` |
| G-86 | App-info Force stop with the radio in range: presence or the rebind still wakes the process within ~10 s, but nothing starts the service or seeks the radio until the app is opened | Force stop with the radio in range, wait a minute, then open the app | No radio notification and no reconnect until opened; reattaches on opening | The exit reason the phone records (`dumpsys activity exit-info`); `UserStop` (DP-84) |
| G-22 [G-87] | The radio notification is silent, under "Silent"; Disconnect works from it; swiping it away is not Disconnect and the radio returns by presence; Task Manager Stop (API 34+) is not Disconnect either, but holds the radio off until the app is opened, as Force stop does; a cold start then Home within seconds still runs the service; a refused start is retried on the next foreground | Each action | As described | Channel settings; the controller's retry; `UserStop` (DP-84) |
| G-25 | Nearby devices revoked while the FGS runs: the process restarts, the service is not restarted, the banner shows; granting brings the radio back with no crash from a stop after a failed `startForeground` | Revoke, then grant (in Settings and in-app) | As described | Adjust the prerequisite guard |
| G-89 | The Waiting notification's per-minute repost for its age costs little battery or wakeups | Hours in Waiting; Battery usage | Negligible | Coarser age updates |
| G-90 [G-94] | After `ACTION_KEY_MISSING` on 36: the system's own "Can't connect …" notification reads acceptably beside ours; with the give-up persisted, later appearances start nothing, no repeated system notices, no presence observation; Radio Detail in a new process shows Disconnected with Connect, which recovers | Bond loss, then process death, radio leaving and returning over a day | No reconnect attempts or service starts | Adjust the persisted give-up |
| G-16 [G-67, G-92] | With the association's device-idle allowlist and the FGS, no battery-optimization exemption is needed; `dumpsys deviceidle whitelist` lists the app on 36 (failed once in P2f, listed in P2g's Doze run); the standby bucket of an associated app (EXEMPTED on the API 36 emulator) | `dumpsys deviceidle whitelist`; `am get-standby-bucket`; overnight screen-off test | Listed; exempted; radio stays attached | Ask for the exemption (a design change for the user) |
| G-8 [G-93] | Doze delays the core's ack and retry timers while the FGS holds a connection with the screen off; the D8 send-timing logs show the Pending → Sent → Acknowledged gaps | Screen off 30 min; peer sends; reply inline; compare `send timing` lines | Small gaps | A partial wake lock for one active send (the plan's remedy) |
| G-125 | With Bluetooth off and "Bluetooth scanning" on, CDM may report the radio appearing; the appearance is held until Bluetooth comes on, then the service starts and the radio attaches without a new appearance; a disappearance drops the hold | Process dead, Bluetooth off, carry the radio out of range and back; then turn Bluetooth on; also leave range before turning it on; watch the shade and logcat `umsh.presence`, `umsh.service` | "Bluetooth is off; held until it is on", no radio notification; attaches within seconds of Bluetooth on; nothing starts after a disappearance | Start the service at once, as before |
| G-126 | The radio notification swiped away (Android 14+ allows it) comes back at its next post: a state change, a battery change (2 s throttle), or the per-minute age tick while Reconnecting or Waiting | Swipe it away in each state | Reappears at the next change; acceptable | Stop reposting after a dismissal (a delete intent; none exists now) |
| G-127 | With App battery usage set to Restricted, background service starts (presence, Reply) are refused despite the association; each refusal is logged, nothing crashes, and the next open recovers | Set Restricted; `am kill`; trigger a presence wake and a shade Reply | `radio service not started: ForegroundServiceStartNotAllowedException`; the radio back on open | Add a Radio Detail line (copy and design change) |
| G-128 | An app used for months only through its service and notifications is not hibernated, and its Nearby devices and notification permissions are not auto-reset (a companion-associated app is exempt) | Settings › Apps › Unused apps; `dumpsys package` hibernation state | Not listed; permissions kept | Guidance to turn off "Pause app activity if unused" |
| G-130 | StrongBox (Titan M2) unwraps the identity fast enough for headless starts: a cold presence wake, or a lock-screen Reply inside the 10 s runtime wait (the emulator has no StrongBox) | `am kill`, then reply from the shade; time the runtime start in logcat | Well under 1 s | Lengthen `RUNTIME_WAIT_MS` |

#### E. Notifications

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-14 [G-33, G-39] | Conversation notifications sit in the shade's Conversations section with the avatar; Android 16's per-app bundle expands; avatar bitmaps are sharp in the shade, lock screen, shortcut icon and long-press launcher menu; Reply and Mark as read work locked (Hide off) | Receive DMs and channel messages locked and unlocked | As described | Adjust shortcut and `Person` setup |
| G-9 [G-38] | Inline reply completes from the shade and lock screen with the app backgrounded, attached and after the window; the broadcast runs on the background queue (60 s) and the 10 s + 15 s waits plus the send fit | Reply after 10 min screen-off, both cases | Sent | Lengthen budgets, or open the app for the reply |
| G-36 | The reply spinner ends whether the reply succeeds or fails; a lock-screen reply asks for unlock first | Reply with the radio off and on | Spinner ends; notice on failure | Repost logic |
| G-15 [G-34, G-35, G-44] | "Hide contents on the lock screen" with the system setting both ways: hidden while locked, revealed on unlock with no second alert, survives process death while locked (`umsh.real` extra); a message posted unlocked and still in the shade when the phone locks shows in full | Toggle both settings; lock; receive; unlock; kill while locked | As described | Revisit D10, or reword settings.svg 5's note |
| G-40 | The radio notification appears right after a POST_NOTIFICATIONS grant while the FGS already runs | Grant from Settings › Notifications › Turn on | Appears | Repost on grant |
| G-41 | A first attach while the phone is locked waits for the activity to resume before asking for notifications | Pair, lock before it attaches | Ask on unlock | Adjust the ask trigger |
| G-43 | API 31–32 only: notifications appear with no ask; the off card follows the app-level toggle | On a 31–32 phone | As described | — |
| G-42 | A staged message (debug only) posts with the app backgrounded and no radio service, if the process is not frozen; low priority | Staging, Home, wait | Posted | None needed |
| G-45 | No "Not showing more notifications" in long use; notices are bounded to three per conversation plus its message notification | Days of use; logcat | None | Bound further |
| G-129 | Android 15+ notification cooldown (a Pixel setting) softens alerts for a burst of channel messages, and the Emergency channel still alerts at full level | Turn cooldown on; receive a burst on Public, then an Emergency message | Emergency alerts at full level | Revisit the Emergency channel's settings |
| G-131 | With a paired Wear OS watch and Hide contents on: while the phone is locked the watch gets the placeholder without Reply; after unlock the revealed notification reaches the watch with Reply | Lock the phone, receive a DM, check the watch; unlock | As described | Accept, or reword the Hide contents note |
| G-134 | A burst of 6 or more messages in one conversation within about a second (a reconnect after the phone was away), and a shade Reply landing while another message arrives there: every line shows, the reply's spinner ends, and logcat shows no "Shedding events" for `com.voria.umsh` (posts go one at a time, 300 ms apart, from lines the notifier keeps) | Reconnect after an absence with several messages held; reply from the shade while a peer sends | Every line; spinner ends; no shedding | Widen the spacing |

#### F. Location

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-17 [G-98] | The Pixel's `fused` provider serves a no-Play-services `LocationManager` client a first fix within seconds, indoors and out, for both grants | Turn sharing on indoors and out | Fix in seconds | GPS + network directly, or a longer wait |
| G-99 | An approximate fix is snapped to Android's ~2 km grid, so the clamp to precision 3 (~9.8 km) is honest | Log approximate fixes moving a few km | ~2 km steps | Raise `APPROXIMATE_GRID_METERS` |
| G-106 | Approximate updates are throttled to ~10 min (`@+10m LOW_POWER` on the emulator) | Move > 10 km under Approximate | Cell trails by up to 10 min | Accept or note |
| G-107 | The legacy `requestLocationUpdates` overload runs fused at BALANCED and may not use GPS; a 38 m cell may land in a neighbor outdoors | Compare logged accuracy to the cell size outdoors | Accuracy within the cell | `QUALITY_HIGH_ACCURACY` at precision 5 or finer |
| G-100 [G-110] | "Only this time" expires ~1 min after leaving the foreground, read as no grant on the next start, withdrawing the position; whether the FGS keeps the grant alive or the process is killed | Grant once, background with the radio attached | Row shows "Location is off for UMSH" next start | Withdraw on stop for one-time grants (design change) |
| G-101 | Precise → Approximate in system Settings kills the process; the first approximate fix goes out at precision ≤ 3; no 38 m cell is ever heard | Change it, `umshctl discover` from a second radio | ≤ 3 bytes | Fix the ordering |
| G-102 | The "upgrade to precise" dialog refused twice stops Android showing it, and Allow then opens settings | Keep approximate twice | Settings opens | Adjust the precise asker's flag |
| G-103 | System location off while sharing: no fixes, the row still shows the area with no line saying why | Quick Settings off | As described | Add a line (design change for the user) |
| G-104 | Precise with a 38 m cell at 60 s / 25 m costs little in an hour of use | Battery usage | Small | Longer interval for cells ≥ 611 m |
| G-105 | Location property writes on each fix are negligible ULCP traffic over BLE | Walk with the app open, send chats | No delay | Push only on cell change (core change) |
| G-108 | Turning Location on from Quick Settings while on Your identity yields a shared fix within a minute without leaving the app | Toggle while on the page | Fix within a minute | Re-request on mode change |
| G-109 | After a reboot with the radio back by presence, adverts carry no location until the app is opened | `umshctl discover` from a second radio | No location until opened | Accepted (DP-104); a check only |
| G-111 | A single provider (GPS) off with Location on: the request is made anyway and delivers once that provider is on | Phone without fused | Delivers later | Request per enabled provider |

#### G. Threads, sending and the shell

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-112 | Swipe to reply: the 64 dp threshold feels right, the SegmentTick haptic fires once on arming, a swipe from the screen edge stays system back | Swipe several bubbles with gesture navigation | As described | Tune threshold, edge exclusion |
| G-113 | Long press: haptic on open; TalkBack's long-click and custom actions (React plus each menu item) are announced | With TalkBack | As described | Semantics |
| G-114 | Predictive back and TalkBack's back close the message menu, the EMERGENCY sheet and the dialogs (the API 36 emulator's accessibility back sometimes missed the menu) | Each with gesture and TalkBack | Closes | Back handling in the sheet |
| G-115 | Send's colors (blue, green, violet) and the dimmed transient Send read well with dynamic color off and on | Look | Distinct | Adjust tokens |
| G-116 | EMERGENCY: Cancel before a send leaves the thread and keeps the draft; the sheet returns after 24 h with no send (the clock counts sleep) and after an app restart; the core's lapse timer (60 s slices) announces it within about a minute on an awake phone, at the first wake past it in Doze, and a send in between is refused by the lazy check | Wait 24 h with the thread open, screen on and then off, or restart | Sheet returns within about a minute, or at the first wake | Core lapse logic; if a late sheet is unacceptable, re-check when the thread resumes |
| G-117 | Message details: the Hint and Address rows copy on tap (Android 13+ shows the system confirmation); TalkBack says "Copy hint"/"Copy address"; Address wraps; a wire ID ≥ 10000 shows ungrouped; the spinner shows briefly and "Message unavailable" shows if the conversation is deleted while open | Each | As described | Row layout |
| G-118 | The retry button beside a short failed bubble has a usable hit target | Tap it | Resend dialog | Larger target |
| G-119 | A long press survives a caption or radio update landing mid-press | Long press during sends | Menu opens | Stabilize handlers |
| G-120 | Editing during a reconnect: the dimmed check gives the "still connecting" alert, not "Edit not sent" | Edit while the radio reconnects | The alert | Gate order |
| G-32 | Predictive back from Radio Detail above the shell previews the shell as left; rotating while a Restart is in flight keeps the failure dialog; leaving drops it | Gesture back; rotate | As described | Navigation |
| G-121 | At 840 dp or wider, opening Details keeps the conversation's row highlighted | Pixel Tablet or unfolded Fold | Highlighted | Selection logic |
| G-122 | On a Pixel Tablet or unfolded Fold, switching destinations never raises the keyboard (P2i fix: each page is a focus target, so the list-detail scaffold's pane focus stops at the page); with a hardware keyboard, Tab enters the pane from there | Open Settings with Developer present; use a keyboard | No IME; Tab moves into the list | Revisit the focus decorator |
| G-123 | The Material "Drag handle" tooltip seen over the message menu and the EMERGENCY sheet in the emulator's shot runs (in every locale) is a test-input artifact and does not appear when a sheet opens by touch | Open both sheets by touch, with and without TalkBack | No tooltip | Give the drag handle no tooltip, or drop it |
| G-132 | The release build (R8, resource-shrunk) runs: it has only been built and inspected, never launched | Install a release build signed for testing; first launch, pair, presence wake, shade Reply and Mark as read, board photos, Forget | All work | Add keep rules |
| G-18 | StrongBox or TEE key protection (carried from Phase 1) | Your identity › Key protection | Security chip or Secure area | — |
| G-30 | An iPhone and the Pixel exchange DMs, reactions, edits and deletes through radios | The plan's cross-platform check | All arrive | — |

### Phase 3: peers, routes, contact exchange, channels

Every hardware guess from the Phase 3 plan (G-136 to G-152) and its build reports (G-153 to G-263), deduplicated
as above. Two build reports reused numbers already taken; their items are renumbered G-249 to G-255. The links,
sharing and scanner items are in [ADR 0007](0007-links-and-scanner.md). Radios as above, plus an iPhone running
UMSH for the cross-platform items.

#### H. Peers, ping and route

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-139 [G-153, G-164] | Ping round trips and the 8 s Ping again fit real RF; a silent node ends in "No reply" after the MAC's wait (about 68 s staged, longer on air), and the waiting state and its elapsed count do not look stuck | Ping a T1000-E one hop and three hops away; ping one that is off | Replies in seconds; "No reply" after the wait | Tune the re-offer; reconsider the waiting copy |
| G-140 [G-163] | Trace-signal legs from real repeaters line up with the rail (leg 1 is the phone's radio), with sensible dBm, SNR and bars on 2+ hop replies | Ping through two repeaters | Legs in order | Fix `PingPath` alignment or the thresholds |
| G-144 [G-157] | Next time heard fires on a saved node's advertisement or forward with the screen off, and the tap opens the peer page or conversation per role; unicast from a node the radio holds no key for never reaches the phone | Arm, wait for a repeater's advert | One notice; the tap opens the right page | — |
| G-146 [G-159] | Distance and bearing come from the phone's fix when location is granted, else the radio's or the advertised position, and the page never asks | Compare to a known node, with and without the grant | Sensible both ways | Fix `PeerDistance` |
| G-158 | A heard notice tapped with the app killed opens the page or conversation within 5 s | Kill, then tap | Opens | Lengthen the wait for the row |
| G-161 | Message details' Repeated-by over RF: named repeaters open their pages, unnamed hints spin a lookup | Receive a repeated message | As described | — |
| G-162 | The first ping to a node never contacted may time out for want of keys | Ping a node just heard | Recorded | — (core) |
| G-165 | Rotation and app switching keep the same ping; a reply that lands while the sheet is closed shows under Earlier | Rotate and switch during a ping | One ping | Fix the re-attach |
| G-167 | A held path's hand-typed hop shows "Entered by hand"; a hop matching a saved repeater shows its name | Hold a path with both kinds | As described | — |
| G-168 | Route's Last ack with no ack reads "Last ack, Unknown" | A route never acked | As described | — |
| G-206a | With location granted, a peer page for a node with no position shows no location indicator | Open such a page | Nothing shown | — |
| G-207 | A received DM routed through a saved repeater: Message details' Route names it, opens its page and shows the hint-ambiguity footer; an unknown hop offers a lookup | Receive a routed DM | As described | — |
| G-208 | On API 31–32, copying the address on a peer page above Radio Detail, Route or Neighbors shows "Address copied" on that page at once | On a 31–32 phone | On the page | Fix the notice host |

#### I. Neighbors and Discover

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-141 [G-169] | A real repeater answers Neighbors with paging, and Load more appends | Refresh a busy repeater | Pages append | — (core) |
| G-142 [G-171] | Discover answers from real nodes arrive over the 0.5–30 s hold while the page is open; Ask is back at 40 s; a hint lookup during the cooldown still goes | Ask nearby; look up a hint during the cooldown | As described | — |
| G-170 | A Peer Repeaters request nobody answers ends in "did not answer" after about 72 s (staged) | Ask a repeater that is off | The inline line | Tune the wait |
| G-172 | Ask near this node reaches nodes near the target | Ask near a node three hops away | Answers from its area | — |
| G-173 | Announce my identity is recorded by a node that never heard the phone | Announce; check the node | Recorded | — |
| G-175 [G-178] | On API 31–32, Copy coordinates shows "Coordinates copied"; on 13+ only the system confirms | Long press a neighbor with a position | As described | — |
| G-176 | Real neighbor tables: fading after 6 h, "heard long ago", quarter-dB SNR | Read a long-running repeater | As described | — |
| G-177 | Clear discovered nodes removes only unsaved nodes and closes their pages | Clear with an unsaved page open | As described | — |
| G-179 | After process death, Neighbors shows its stored listing, not "Not read" | Read, kill, return | Stored listing | Fix the stored read |
| G-180 | Ask near: Ask is disabled while the route is read, and "Nearby—direct" shows first on a restore | Restore a Discover page | As described | — |

#### J. Manual path and learned paths

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-145 [G-187] | The learned-path prompt appears after moving ≥ 200 m with a fix of ≤ 100 m accuracy; Use learned path takes effect on the next send, and Keep is not asked again | Walk with a held path | As described | — (core rule) |
| G-149 [G-189] | Process death on a deep page (Route, the editor) restores the stack and the editor's draft | "Don't keep activities", or let the system reclaim | Restored | Adjust the savers |
| G-154 | The position source gets a fix within 20 s indoors and out; with none, the learned-path check offers nothing | Indoors and out | As described | Lengthen the wait |
| G-156 | With the Location switch off, saving a manual path and the learned-path check answer at once; with it on, a fix comes well inside 20 s | Both ways | As described | — |
| G-182 | Drag reorder works on a real touchscreen | Reorder hops | Smooth | Tune the drag |
| G-184 | Ping along path works on RF, and a path change mid-ping drops the stale result | Test a path, edit during the ping | As described | — |
| G-185 | Neighbors for hop 1 comes from a real companion radio | Add hop 1 | The radio's neighbors | — |
| G-186 | Neighbors through a multi-hop path reach the previous hop, and "Asked through" matches | Add hop 3 | As described | — |
| G-188 | The editor's bar at Pixel 7 width and at 320 dp ("Manual pa…") | Look | Acceptable | Shorter title or two-line bar |
| G-190 | The Base58 prefix keyboard is ASCII with no autocorrect | Enter a hint | As described | Fix the keyboard options |
| G-191 | Edit path with the radio disconnected shows the reason, and seeds once the radio is back | Disconnect, edit | As described | — |
| G-192 | With a held-path thread backgrounded, no location reads are made until the thread shows again | Watch the location indicator | None | Fix the trigger |
| G-213 | A 1-day hold saved at 3:40 PM reads "Held until" with the next day's date on Route, as in the editor | Save one | Matches | — |

#### K. Add peer and contact exchange

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-143 [G-198] | Contact exchange works phone to phone through two radios, Android with an iPhone, with nearness glyphs and the same code digits | Exchange with the iPhone | Both save each other | Report to the core (UEP-0022) |
| G-155 [G-200] | Nearness comes from real Hello signal strength (the bridge always reports 3) | Walk away from the other phone | Arcs drop | — |
| G-193 | Pasting a long `umsh:` link: the clipboard chip, no autocorrect, wrapping | Paste one | As described | — |
| G-194 | A stranger's first direct message reaches the receiver on radios | Message a node that does not have this phone | Arrives, or recorded | — (core) |
| G-195 | Adding and messaging across an Android phone and an iPhone with two radios | Swap links and message | Both ways | — |
| G-196 | The import sheet with the keyboard up at Pixel and 320 dp widths; it cannot be swiped away while saving | Look; swipe while saving | As described | — |
| G-199 | Being asked by a device not yet on Nearby | Have the other phone ask first | The ask sheet | — |
| G-201 | The meet closes only when the process stops, and reopens with a new color | Background and return | As described | — |
| G-203 | Swiping the ask sheet down declines; predictive back on the exchange page backs out for both phones | Do both | As described | — |
| G-204 | The exchange survives a real rotation and a fold or unfold | Rotate and fold mid-exchange | Continues | — |
| G-205 | On a foldable, "You" keeps the advertised outline across an unfold | Unfold on Add peer | Same outline | — |
| G-206 | Radio Detail over Add peer drops the phone off the other device's Nearby, and Back shows it again under a new color | Open Radio Detail from Add peer | As described | — |

#### L. Channels and Conversation info

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-147 [G-237] | Copying a private invitation on Android 13+ shows the system's copy overlay with its contents hidden | Copy an invitation | Hidden | — |
| G-148 [G-238] | A channel joined on the phone carries traffic through a real companion radio both ways (host channel keys provisioned), and leaving stops it | Join, receive, send, leave | As described | Core policy |
| G-242 | The table-full dialog appears on the 33rd channel with a real radio attached, and nothing reaches the radio for the refused one | Join 33 | As described | — |
| G-243 | Request identity to a real member brings their identity back; the sheet fills in the address while open; on EMERGENCY the warning comes first | Ask a member | As described | — |
| G-244 | A real member who sends without a name shows as "Member" and their hint, and fills in after Request identity | Receive from such a node | As described | — |
| G-245 | Test messages on EMERGENCY notifies for a real "TEST:" message only when on; such messages never count as unread | Both settings | As described | — (core policy) |
| G-247 | Clear all messages on a busy channel erases only this phone's copy; later messages land in the same conversation | Clear, then receive | As described | — |
| G-248 | A thumb tap just beside a member's avatar opens their sheet, and a tap on the bubble beside it still reaches the bubble | Tap around the avatar | As described | Widen the gutter |
| G-255 | Swiping down or pressing Back during the channel sheet's join does nothing until the join ends; then the conversation opens | Try it | As described | — |
| G-261 | A channel joined or created on the phone notifies, including for messages the radio queued while the phone was away, and the radio gives its receipt cue for them; Public and EMERGENCY stay muted on both | Join a channel, put the phone out of range, send to it and to Public from another node, come back | The radio cues for the joined channel only; the phone notifies for it only | — (core policy) |

#### M. TalkBack, layout and the release build

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-150 [G-160, G-166, G-174, G-181, G-183, G-197, G-202, G-206c, G-211, G-212, G-240, G-246] | Live TalkBack reads Phase 3's screens as plan §3.10 says, which the AVDs could only check through the semantics tree: glance cells once; Ping's result announced once and legs as one sentence each; the Discover countdown silent and "You can ask again." once; the editor's hop stops, Then flood stepper and move actions (reorder by actions works); Save peer busy as "Saving, disabled"; Nearby glyphs by model and nearness, "Same code on the other screen?" announced, the code digit by digit; the sort chip as a button without a checkbox state; a Neighbors Refresh result announced; Channels, Join channel and the eye; the channel thread title as "Conversation info", the header as one button, and "Show member" offered on a member's messages | A TalkBack pass on the Pixel | As described | Fix semantics |
| G-256 | Live TalkBack reads each extended FAB (New chat, Add peer, Add channel) once, by its label, as a button, and "Join a channel…" without its "+" (Material3 1.4.0 clears the label's own semantics, so the icon carries the label) | TalkBack on each FAB and on New channel chat | As described | Move the label back to the text |
| G-206b | On a tablet or unfolded Pixel with predictive back: back from a page above details returns to details, from details to the thread, from the thread closes it beside the list, and the preview animates the pane | Pixel Tablet or Fold | As described | Navigation |
| G-209 | With the keyboard up, the last Peers search result, the last Add hop row and both "two fit" candidates scroll into view, with no large gap above the keyboard | Each | As described | Fix the insets |
| G-210 | A release-APK smoke run: a peer page restored after process death, Nearby, a manual path editor (R8 keep rules for navigation keys and `platforms.json`) | Install a release build signed for testing | All work | Add keep rules |
