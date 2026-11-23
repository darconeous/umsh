# ADR 0004: Bluetooth lifecycle in Kotlin, companion wire state in Rust

- Status: Accepted; emulator-verified against a Bumble peripheral, Pixel and
  physical radios unverified
- Phase: 2

The Android counterpart of iOS [ADR 0007](../ios/0007-companion-ble-boundary.md).
Pairing and inventory are [ADR 0005](0005-companion-device-manager.md); what
keeps the link up in the background is [ADR 0006](0006-background.md).

## Decision

Kotlin owns the Bluetooth link: scanning, `connectGatt`, bonding, MTU, service
discovery, the Frame Out subscription, the order of every GATT operation and
its deadline, and when to reconnect. The Rust core owns everything above the
ATT value: the ULCP session in `MobileRadioDriver` (attach, synchronization,
claim, transactions), GATT SAR segmentation (`ulcpGattSegments`) and bounded
reassembly (`MobileGattReassembler`). Kotlin never parses a ULCP frame.

### One seam for every link

`RadioConnection` is the host's handle on a radio; `RadioDriverAdapter` is the
base every link extends. It creates one `MobileRadioDriver` per connection and
implements the driver's `RadioLink` callbacks. There are three links:

| Link | Builds | Purpose |
|---|---|---|
| `BleRadioConnection` + `BleRadioLink` | release and debug | the product |
| `TcpRadioConnection` (HDLC over a socket) | debug only | a live mesh on the emulator through a `umsh-bridge` host interface |
| `StagingRadioConnection` | debug only | the staged mesh in the core |

All of them end at the same driver and the same `core.useRadio`, so the
composer, Radio Detail, notifications and the foreground service behave the
same whatever carries the frames. The host owns one connection at a time;
screens read the radio's state only through the core's change records.

### Threads

Each connection has one serial executor (`umsh-radio-<kind>`). Every driver
callback and every Android callback (`BluetoothGattCallback`, bond broadcasts,
socket reads) hops onto it and returns at once; nothing holds a lock across a
foreign call. Each attachment has its own port, and a callback from a port
no longer current is dropped. `close()` stops the link from inside the executor
before the executor shuts down, so a released radio's `BluetoothGatt` is always
closed.

### The GATT sequence

`BleRadioLink` talks to a `GattPort`, not to `BluetoothGatt`;
`AndroidGattPort` adapts the platform (value-carrying callbacks on API 33+,
the deprecated forms on 31–32). `GattQueue` issues one operation at a time
across bond, MTU, discovery, CCCD and writes, each with a deadline counted
from its first issue, so a write the stack keeps refusing as busy still runs
out. A Service Changed indication starts the attach over at discovery, issued
once the operation the stack still holds has been answered.

1. `connectGatt(TRANSPORT_LE)`; every old `BluetoothGatt` for the radio is
   closed first.
2. First pairing only: `createBond()` on the connected device (ADR 0005). Past
   the first pairing, a radio Android holds no bond for is refused without
   connecting, and nothing ever asks to bond again.
3. `requestMtu(517)`; a failure is tolerated (ATT_MTU 23 works).
4. Discovery: the ULCP service with Frame In (write) and Frame Out (notify).
5. Frame Out notifications enabled → `linkReady`.
6. Frames out are segmented to `min(ATT_MTU − 3, 512)` and written with
   response, 8 s per write; `ERROR_GATT_WRITE_REQUEST_BUSY` requeues. Frames in
   are reassembled; a reassembly error ends the link.
7. `onServiceChanged` drops the handles and rediscovers. The hidden
   `BluetoothGatt.refresh()` is never called.

### Bond loss

A radio that no longer holds this phone's keys ends as `AttachmentRefused`,
worded "Open the radio's pairing window and add it again.", never as a
reconnect loop. The signals, from the emulators:

- API 36: `ACTION_KEY_MISSING` for a loss reported while the link is up, and a
  link that ends with HCI 0x05 or 0x06 while being encrypted.
- API 31–35: an unasked `BONDED → BONDING` (Android re-pairing by itself).
- Any level: a bound radio with no Android bond, refused before connecting.

The plan's API 31–35 inference from an insufficient-authentication CCCD error
did not occur on the API 31 emulator: Android retried security itself and the
subscribe deadline fired instead. Bluetooth broadcast receivers for bond,
encryption and key-missing events are registered exported, because the
Bluetooth process sends them; each filters on the radio's address.

### Transport problems

Problems use the iOS `RadioTransportProblem` codes with the same raw values,
so logs and the core agree; Android system errors travel as
`("android.bluetooth.gatt", status)`. Every problem is worded natively; no
system message string is shown.

## Verification

- JVM: `BleRadioLinkTest` drives the link over a scripted `FakeGattPort`
  (queue order, deadlines, busy requeue, stale ports, write failure, fault
  once, reassembly error, service change with a write in flight, MTU 23,
  512-octet cap, bond loss); `GattQueueTest` the queue alone.
  `BleAttachTest` runs `BleRadioConnection` + the real driver and core to a
  real device session (`MobileVirtualRadio` with its PHY off) behind
  `FakeRadioPeripheral`.
- Emulator: `tools/ble-test-peripheral` (Bumble, `make android-ble-peripheral`)
  on the emulators' shared netsim. On API 31 and 36: scan with the scan
  response and manufacturer data, Just Works and passkey LESC bonds, ATT_MTU
  255, encrypted CCCD, segmented frames both ways, attach and claim, a DM to
  `umshctl` and back, Bluetooth off and on, and bond loss.
- Not verified: Pixel controller behavior, the MTU and connection parameters
  the real radios grant, the radios' own pairing stacks, RF loss. These are
  in the Pixel checklist (Bluetooth link and Pairing groups).

## Consequences

Bumble is a second packaged Python project (`tools/ble-test-peripheral`);
its SAR and HDLC codecs are checked against vectors generated from the Rust
codecs (`make ble-test-vectors`). Nothing in the app or the firmware build
needs it.
