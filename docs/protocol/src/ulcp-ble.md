# ULCP over BLE

This chapter defines the normative binding of ULCP
(see [Framing and Common
Semantics](ulcp-core.md)) onto Bluetooth Low Energy. It
covers the **tethered** case only: one host device driving its own
companion radio over a BLE connection, exactly as it would over UART or
USB-CDC.

Using BLE as a shared local bearer — nearby devices exchanging UMSH
frames over BLE as peers, or reaching the UMSH network through a
BLE-LoRa bridge — is a separate bearer design and is out of scope here.
See [BLE As A Local Bearer](ulcp.md#ble-as-a-local-bearer)
for the design space. This chapter reserves identifier space for that
future work (see [UUID Allocation](ulcp-ble.md#uuid-allocation)) but does not specify it.

ULCP is transport-agnostic: frames are carried
opaquely and unchanged. This binding replaces only the framing layer.
HDLC-Lite framing (flags, escaping, and the FCS) is **not** used over
BLE; ATT already provides reliable, ordered, integrity-protected
delivery, and frame boundaries are recovered by the segmentation scheme
below.

## GATT Frame Transport {#gatt-frame-transport}

This section defines a generic, service-agnostic pattern for carrying
delimited frames over GATT. The ULCP GATT Service
(see [ULCP GATT Service](ulcp-ble.md#ulcp-gatt-service)) instantiates it; a future local-bearer
service may instantiate it independently.

A service using this pattern exposes a pair of characteristics:

Characteristic | Direction     | GATT Properties
---------------|---------------|--------------------------------
Frame In       | Client→Server | Write; Write Without Response (optional)
Frame Out      | Server→Client | Notify

Each characteristic carries a sequence of **segments**. A segment is
one ATT value: a single write to Frame In, or a single notification
from Frame Out. One or more consecutive segments reassemble into
exactly one frame. Segments of different frames are never interleaved
on the same characteristic.

### Segment Format {#segment-format}

Every segment begins with a single header octet, followed by zero or
more octets of frame data:

~~~
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|  SAR  |       RESERVED        |
+---+---+---+---+---+---+---+---+
~~~
Figure: Segment Header Format

#### `SAR`: Segmentation and Reassembly

The two most significant bits indicate the segment's position within
its frame:

Value | Name           | Meaning
------|----------------|--------------------------------------------
0     | `SAR_COMPLETE` | The segment contains a complete frame
1     | `SAR_FIRST`    | First segment of a segmented frame
2     | `SAR_CONT`     | Continuation segment of a segmented frame
3     | `SAR_LAST`     | Last segment of a segmented frame

#### `RESERVED`: Reserved

The six least significant bits **MUST** be transmitted as zero. A
receiver encountering a nonzero value **MUST** discard the segment and
reset reassembly on that characteristic (see [Reassembly](ulcp-ble.md#reassembly)).

### Segmentation {#segmentation}

A sender **MUST NOT** produce a segment larger than the current usable
ATT payload (ATT_MTU minus 3 octets for the ATT opcode and handle).
When a frame plus its one-octet segment header fits in a single ATT
value, the sender **SHOULD** emit it as one `SAR_COMPLETE` segment.
Otherwise the frame is split, in order, into one `SAR_FIRST` segment,
zero or more `SAR_CONT` segments, and one `SAR_LAST` segment.

All segments of a frame **MUST** be sent before any segment of the
next frame on the same characteristic.

### Reassembly {#reassembly}

The receiver maintains one reassembly buffer per characteristic:

* `SAR_COMPLETE`: any partially reassembled frame is discarded; the
  segment payload is delivered as a complete frame.
* `SAR_FIRST`: any partially reassembled frame is discarded; the
  segment payload starts a new reassembly.
* `SAR_CONT`, `SAR_LAST`: the segment payload is appended to the
  reassembly in progress. If no reassembly is in progress, the segment
  **MUST** be discarded. On `SAR_LAST`, the reassembled octets are
  delivered as one complete frame.

The service instantiating this pattern defines the maximum reassembled
frame size. If a reassembly exceeds it, the receiver **MUST** discard
the partial frame and ignore subsequent `SAR_CONT`/`SAR_LAST` segments
until the next `SAR_COMPLETE` or `SAR_FIRST` segment.

An ATT value of zero length contains no segment header and is not a
valid segment; the receiver **MUST** discard it and reset reassembly
on that characteristic.

Reassembly state is reset whenever the connection drops or the link
detaches (see [Attach Semantics](ulcp-ble.md#attach-semantics)).

Discarded segments and frames are transport-level events; they do not
generate protocol-level error responses.

### Flow Control {#gatt-flow-control}

Client-to-server flow control uses the ATT write mechanism: a client
using Write (with response) **SHOULD NOT** issue the next write until
the previous response arrives. The server's write response is its
assertion that it has accepted the segment. A client **MAY** use Write
Without Response where supported, in which case it relies on
link-layer backpressure; servers **MUST** process such segments in
order but **MAY** stall the bearer while doing so.

Server-to-client flow control is provided by the notification
mechanism: the server's stack paces notifications to the connection,
and the server **MUST NOT** drop segments of a frame it has begun to
send.

### MTU Considerations

The scheme is correct at any ATT_MTU, including the 23-octet minimum.
Clients **SHOULD** negotiate the largest ATT_MTU they support before
attaching; servers **SHOULD** support an ATT_MTU of at least 247.
Larger MTUs only reduce segment count — they never change frame
semantics.

## ULCP GATT Service {#ulcp-gatt-service}

The ULCP GATT Service carries ULCP frames
using the GATT frame transport defined above. One reassembled frame is
exactly one ULCP frame as defined in
[Frame Format](ulcp-core.md#frame-format); the transport
never inspects or modifies frame contents.

The maximum reassembled frame size for this service is 512 octets.

### UUID Allocation {#uuid-allocation}

UMSH GATT identifiers are allocated from the randomly generated UMSH
base UUID `21EB6B15-XXXX-4CCF-92E4-A079171BEC97`, where `XXXX` is the
assignment slot.

Slot     | UUID                                     | Assignment
---------|------------------------------------------|------------------------------
`0x0001` | `21EB6B15-0001-4CCF-92E4-A079171BEC97`   | ULCP GATT Service
`0x0002` | `21EB6B15-0002-4CCF-92E4-A079171BEC97`   | Frame In characteristic
`0x0003` | `21EB6B15-0003-4CCF-92E4-A079171BEC97`   | Frame Out characteristic
`0x0100`+| —                                        | Reserved: BLE local bearer

Slots `0x0100` and above are reserved for the future BLE local-bearer
service family and **MUST NOT** be used for tethered ULCP
purposes.

### Attach Semantics {#attach-semantics}

A host is **attached** once it has enabled notifications on Frame Out
(by writing the Client Characteristic Configuration Descriptor) over a
connection meeting the security requirements in [Security](ulcp-ble.md#ble-security).
Connection alone does not attach.

On attach, the device **MUST** silently reset its protocol **session
state** — transaction correlation, reassembly, and session-scoped
properties — and **MUST NOT** modify any other state: device and host
provisioning, the RF configuration, and the PHY enable state are
unaffected, and the radio keeps operating through the attach (see
[Attach, Detach, and
Synchronization](ulcp-core.md#attach-sync)). No unsolicited
notification is emitted on attach; the host learns the device's current
state by fetching it. The device **MUST NOT** emit any frame before attach.

A host **detaches** by disabling notifications or by disconnecting.
Partially reassembled frames are discarded on detach.

The device supports one attached host at a time, across all transports it
exposes. If a new host attaches — over BLE or over another transport
such as USB — the device **MUST** detach any previously attached host and
reset the session for the new one. A device **MAY** instead reject new
connections while a host is attached.

### Connection Parameters

The transport is latency-tolerant; any standard connection parameters
work. Devices **SHOULD** accept connection intervals in the 15–50 ms
range so that transmit confirmations and received-frame delivery do
not dominate MAC-layer timing budgets.

## Advertising and Discovery {#ble-advertising}

While powered and not attached, the device **SHOULD** advertise as
connectable and include the ULCP GATT Service UUID in its
advertising data or scan response, so hosts can discover devices
by service rather than by name. The advertised local name is
implementation-specific unless the device advertises `CAP_DEV_NAME`. Such a device
**SHOULD** use its current `PROP_DEV_NAME` as the advertised local name,
shortening it without splitting a UTF-8 code point when the advertising or scan
response payload cannot hold the complete value. A name changed while a BLE
connection is active takes effect on the next advertising cycle; changing it
does not require disconnecting the attached host.

While a host is attached over another transport (for example, an open
ULCP session over USB-CDC), the device **SHOULD** suspend
advertising, and **SHOULD** resume it when that host detaches.

Advertising content **MUST NOT** reveal whether the device holds bonds or
identify previously bonded hosts. Devices **SHOULD** use resolvable
private addresses.

Pairing mode (see [Pairing Mode](ulcp-ble.md#pairing-mode)) governs only the acceptance of
pairing requests; it does not affect advertising. In particular, a
bonded device continues to advertise outside pairing mode so that its
bonded hosts can reconnect.

## Capabilities {#capabilities}

Code | Name              | Requires  | Grants
-----|-------------------|-----------|--------
50   | `CAP_BLE`         | —         | A Bluetooth transport whose reachability the device can turn on and off: `PROP_BLE_ENABLED`
52   | `CAP_BLE_PAIRING` | `CAP_BLE` | Bond management on command: `CMD_BLE_CLEAR_BONDS`, `CMD_BLE_START_PAIRING`, `PROP_BLE_BOND_COUNT`

A device implementing this binding **MAY** advertise `CAP_BLE`. Not
advertising it means the transport is always reachable while the device
is powered, which is what every device did before the capability
existed; it does not mean the device has no BLE.

`CAP_BLE_PAIRING` is separate because the two claims are separate: a
device can be made unreachable without being able to rearrange who it
trusts. A device whose bonds are reachable only by a gesture at the
device itself leaves it out and answers both commands
`STATUS_UNIMPLEMENTED`.

## Reachability {#ble-reachability}

### PROP 4871: `PROP_BLE_ENABLED` {#prop-ble-enabled}

* Type: Single-Value, Read-Write
* Asynchronous Updates: Yes
* Required: `CAP_BLE`
* Value Type: BOOL
* Post-Reset Value: 1 (true), or restored from saved state

Whether the device is reachable over this transport. Cleared, the
device **MUST** stop advertising and **MUST** drop any host attached
over BLE; set again, it advertises as it did before. Bonds are
untouched in both directions, so a bonded host reconnects without
pairing again.

It says nothing about the radio itself. A device **MAY** power the
controller down behind this and **MAY** leave the whole stack running;
what the property promises is reachability, which is what an operator
turning it off is asking about. Claiming the radio is off would be a
claim most platforms cannot honor — a vendor stack that cannot be torn
down at runtime is common — and a property that lies in the direction
of "more private than it is" is the wrong one to guess at.

Asynchronous for the same reason `PROP_GNSS_ENABLED` is: a device
**MAY** offer this as a control the operator can reach, and a switch
someone can flip is a value that moves without the host asking. A
device that flips it locally **MUST** publish the new value like any
other transition the host did not command — which, when it is being
cleared, is the last thing the attached host hears.

The post-reset value is true. A device unreachable by default is a
device that cannot be configured by the host that would make it
reachable again, and on most hardware the only other way in is the menu
on the front of it.

## Bond Management Commands {#bond-management-commands}

### PROP 4872: `PROP_BLE_BOND_COUNT` {#prop-ble-bond-count}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: `CAP_BLE_PAIRING`
* Value Type: UINT8
* Post-Reset Value: the number of bonds the device holds

How many hosts are currently bonded. A device **MUST** report the count
its durable bond store holds, and **MUST** publish the new value when it
changes — enrollment and eviction both happen without the host asking,
so a host that was not told would have to poll.

The count is live transport state, not configuration: it is **NOT** part
of the saved snapshot, and `CMD_RST` **MUST NOT** change it. A protocol
reset returns protocol state to its post-reset values, and a bond is
neither protocol state nor something a reset deletes.

It says how many hosts are enrolled, never which. A device that named
its bonded hosts to whoever asked would leak the association the pairing
ceremony exists to protect, and the count is what an operator deciding
whether to clear bonds actually needs.

### CMD 17: (Host -> Device) `CMD_BLE_CLEAR_BONDS` {#cmd-ble-clear-bonds}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_BLE_CLEAR_B|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Figure: Structure of `CMD_BLE_CLEAR_BONDS`

Delete every stored bond, the pairing PIN, and the pairing failure
lockout, then enter pairing mode.

The device **MUST NOT** report success before the deletion is durable,
and **MUST** drop the deleted bonds from any live in-memory bond table
as well as from durable storage — a bond forgotten on flash but still
held in RAM would keep working until the next boot. It **MUST** then
enter pairing mode: a device that has forgotten every host it trusts and
is not accepting new ones is reachable by nothing.

The device answers `PROP_LAST_STATUS`: `STATUS_OK` once the deletion is
durable, `STATUS_UNIMPLEMENTED` without `CAP_BLE_PAIRING`. Sent over
BLE, that answer is the last thing the sender hears, because the bond
that carried it is among the bonds deleted; the reply **MUST** be
emitted before the connection is dropped.

Clearing the PIN alongside the bonds is deliberate. A PIN outliving the
hosts it was set for would leave a device that has forgotten everyone
still demanding a secret the operator may no longer have, recoverable
only by a local wipe.

### CMD 18: (Host -> Device) `CMD_BLE_START_PAIRING` {#cmd-ble-start-pairing}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_BLE_START_P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Figure: Structure of `CMD_BLE_START_PAIRING`

Enter [pairing mode](#pairing-mode), so an unbonded host may pair
without a physical gesture at the device. The window ends on the same
three conditions as any other, and the device **SHOULD** give the same
perceptible indication.

The device answers `PROP_LAST_STATUS`: `STATUS_OK` once the window is
open, `STATUS_INVALID_STATE` when it cannot open one — the device is
locked out after repeated pairing failures — and
`STATUS_UNIMPLEMENTED` without `CAP_BLE_PAIRING`. A full bond store is
**NOT** a refusal: enrollment at capacity evicts rather than refuses
(see [Bond Management](#bond-management)), so a device with a full store
opens the window like any other.

Both commands are ordinary commands rather than reset-class: what they
did is the whole of what they report, and a caller that heard nothing
could not tell a device that had cleared its bonds from one that never
received the request.

## Security {#ble-security}

ULCP is a privileged interface: an attached
host commands transmission with arbitrary content, timing, and power
under the operator's regulatory responsibility, observes all traffic
metadata the radio receives, and can deny service to the legitimate
host. On serial transports this interface is implicitly protected by
physical possession of the device. The BLE binding **MUST** provide at
least an equivalent barrier, and its cryptographic strength **MUST
NOT** fall below that of UMSH's identity layer (approximately 128-bit,
bounded by Curve25519; see [Security & Cryptography](security.md)).

### Pairing Requirements

* Pairing **MUST** use LE Secure Connections (LESC). Legacy pairing
  **MUST** be rejected; Devices **SHOULD** operate in Secure Connections
  Only mode.
* Bonding is **REQUIRED**. The device **MUST NOT** attach a host over an
  unbonded link.
* The Frame In and Frame Out characteristics, including the Frame Out
  CCCD, **MUST** be readable and writable only over an encrypted link
  keyed by a stored LESC bond. Access over any other link **MUST** be
  refused with the appropriate ATT security error.

LESC pairing (P-256 ECDH) meets the 128-bit strength requirement. The
remaining risk is man-in-the-middle interception during the pairing
ceremony itself, which the following requirements bound.

### Pairing Mode {#pairing-mode}

Except as provided for OOB pairing below, the device accepts pairing
requests from unbonded devices only while in **pairing mode**; at all
other times such requests **MUST** be rejected. A configured pairing PIN
selects the association model but does not bypass the pairing-mode
requirement.

Entering pairing mode:

* While the device holds no bonds, it **SHOULD** enter pairing mode
  automatically at power-on for a short window (15–30 seconds
  **RECOMMENDED**).
* Once the device holds one or more bonds, it **MUST NOT** enter pairing
  mode automatically. Entering pairing mode then requires either a
  deliberate physical gesture distinct from normal power-on — for
  example, holding the user button through power-on until the device
  signals that pairing mode is active — or
  [`CMD_BLE_START_PAIRING`](#cmd-ble-start-pairing) from an authorized
  session.

Pairing mode **MUST** end when any of the following occurs:

* a new bond completes;
* an already-bonded host establishes an encrypted connection;
* an implementation-defined timeout expires.

The device **SHOULD** give a perceptible indication (LED pattern, tone,
or display) while pairing mode is active.

A physical-presence-gated ceremony reduces the pairing trust decision
to possession of the device — the same property that protects the
serial transports. A command from an already-authorized session is the
same decision made by someone who has already passed that ceremony: an
attached host holds a bond, and a mesh administrator is listed in
`PROP_DEV_ADMINS`, which is itself set through an attached session. What
the gesture proves about a person standing at the device, authorization
proves about a party that was admitted earlier; a party that can already
administer the device gains nothing by opening a window it could open by
walking over.

### Association Models

* Devices with a display and a confirmation input **SHOULD** use an
  authenticated association model (numeric comparison, or passkey
  display) for new bonds.
* Devices without a display, and with no pairing PIN configured, use
  Just Works, accepted only in pairing mode. This model is
  unauthenticated; the pairing-mode gesture is the entire trust
  decision.
* Devices with a pairing PIN configured (see [Pairing PIN Configuration](ulcp-ble.md#pairing-pin)) use LESC
  Passkey Entry with the configured PIN as a static passkey. New bonds
  still **MUST** be accepted only while in pairing mode. The device
  **MUST** count consecutive passkey authentication failures — pairing
  attempts that fail the LESC confirm-value or DHKey check — since
  power-on; the counter resets on a successful pairing or a power
  cycle. Rejections that never reach passkey authentication
  (legacy-pairing attempts, pairing refused outside pairing mode,
  malformed pairing requests) **MUST NOT** increment the counter, so
  they cannot be used to lock out pairing remotely. After a small
  limit (**MUST NOT** exceed 5; 3 **RECOMMENDED**), the device **MUST**
  reject all further pairing attempts until it is power cycled.
* Devices **MAY** additionally support LESC Out-of-Band pairing (for
  example, OOB data conveyed by a QR code affixed to or displayed by
  the device). OOB pairing is authenticated and **MAY** be accepted at
  any time. The conveyance and provisioning of OOB data is out of
  scope for this document.

The failed-attempt lockout is load-bearing, not defensive polish: LESC
Passkey Entry discloses the passkey one bit per protocol round, so an
active attacker learns roughly one PIN bit per failed pairing attempt,
and a passive eavesdropper on one *successful* pairing learns the
entire PIN. A static passkey therefore provides bounded, not absolute,
authentication: the lockout caps active extraction at a few bits per
power cycle performed by the operator, and operators **SHOULD** change
the PIN if a pairing exchange may have been observed.

### Pairing PIN Configuration {#pairing-pin}

#### PROP 4864: `PROP_BLE_PAIRING_PIN` {#prop-ble-pairing-pin}

* Type: Single-Value, Write-Only
* Asynchronous Updates: No
* Required: **OPTIONAL** (meaningful only on devices exposing this
  transport)
* Value Type: UINT32_LE, or empty
* Units: LESC passkey, decimal 0–999999
* Post-Reset Value: Persisted

Sets the static passkey used by the configured-PIN association model
above. Writing an empty value clears the PIN, returning the device to
the Just Works model. Values outside 0–999999 fail with
`STATUS_INVALID_ARGUMENT`.

As an exception to the usual `CMD_PROP_SET` behavior, a successful
set of this property is acknowledged with `CMD_PROP_IS` for
`PROP_LAST_STATUS` carrying `STATUS_OK` and the command's TID; the
device **MUST NOT** emit `CMD_PROP_IS` for this property itself. Success
**MUST NOT** be reported before the new value is in effect for
subsequent pairing attempts and, where the device supports
persistence, durably stored; a value that cannot be applied or stored
is reported with an appropriate error status and leaves the previous
PIN state unchanged.

The PIN persists across resets and power cycles. It is write-only:
`CMD_PROP_GET` for this property **MUST** fail with
`STATUS_UNIMPLEMENTED` and **MUST NOT** disclose the value or whether
a PIN is configured.

Because this property is only reachable through an attached session,
it is always protected by the transport that carried it: physical
possession on serial transports, or an existing bonded LESC link on
BLE.

### Bond Management

* Devices **MUST** provide a local mechanism to delete stored bonds. The
  mechanism is implementation-specific. Deletion **MUST NOT** be
  invocable over an unauthenticated path; a device advertising
  `CAP_BLE_PAIRING` additionally accepts
  [`CMD_BLE_CLEAR_BONDS`](#cmd-ble-clear-bonds), whose authorization is
  the session's own (see [Administrative
  Authorization](#administrative-authorization)).
* Devices **MAY** limit the number of stored bonds. A full bond store
  **MUST NOT** cause pairing to be refused: when a new bond is enrolled
  while the store is full, the device **MUST** evict the
  least-recently-used bond to make room. Bond-store capacity **MUST
  NOT** appear as a term in the pairing admission decision.
* A device that evicts by recency **MUST** record use: the recency order
  **MUST** be updated when a bonded host establishes an encrypted
  connection, not only when a bond is created or refreshed. A store
  ordered only by enrollment evicts the wrong bond.
* A device that evicts a bond from durable storage **MUST** also drop it
  from any live in-memory bond table, so the evicted peer cannot
  continue to reconnect as bonded for the remainder of the power cycle.

Refusing enrollment at capacity would be the more restrictive-looking
choice and is the wrong one: it turns a full store into a state from
which the device can only be recovered by a local wipe, while enrollment
already requires physical presence and the eviction victim is by
construction the bond that has gone longest without connecting.

Removing one specific bond while retaining the others is not expressible
through this protocol. `CMD_BLE_CLEAR_BONDS` forgets every host at once,
which is the operation an operator reaching for it wants: the case that
motivates it is a device whose paired hosts are no longer trusted or no
longer known, and enumerating bonds so one could be named would mean
reporting which hosts a device has met.

### Administrative Authorization {#administrative-authorization}

Any retained secure bond may administer the device. There is no
per-host privilege distinction: a host that has completed the pairing
ceremony and holds a stored bond has the same authority as any other,
for as long as its bond is retained.

Equivalently, **possession of a serial transport confers the same
authority**. The serial transports have no cryptographic admission step
at all, so a host that can open the port is attached; this is the
`MUST` in [Pairing Requirements](ulcp-ble.md#pairing-requirements) read the other
way — BLE is required to reach the barrier that physical possession
already provides, not to exceed it.

The consequences worth stating plainly:

* Enrollment, not authorization, is the gate. Reaching the pairing
  ceremony requires pairing mode, and pairing mode requires physical
  presence (see [Pairing Mode](ulcp-ble.md#pairing-mode)).
* Administering a device does not make the administering host that
  device's tethered host, and **MUST NOT** cause the device to adopt it
  as one. See [Local Control Protocol](ulcp.md) for the distinction
  between administrative and tethered attach.
* All transports implementing this protocol **MUST** apply the same
  rules. A device **MUST NOT** grant a capability over one transport that
  it withholds over another.

### Layering Note

BLE link security protects the *transport*. It does not alter the UMSH
security model: MAC-layer keys remain on the host, frames crossing
this link remain UMSH ciphertext where UMSH encrypts them, and a
compromised device still cannot impersonate host identities. Conversely,
future ULCP extensions that provision keying material to
the device (see [Security Boundary](ulcp.md#security-boundary))
**MUST NOT** be carried over a link that does not meet the
requirements of this section.
