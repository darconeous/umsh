# Companion Radio over BLE

This chapter defines the normative binding of the companion-radio
protocol (see [Minimal Companion Radio
Protocol](companion-radio-minimal.md)) onto Bluetooth Low Energy. It
covers the **tethered** case only: one host device driving its own
companion radio over a BLE connection, exactly as it would over UART or
USB-CDC.

Using BLE as a shared local bearer — nearby devices exchanging UMSH
frames over BLE as peers, or reaching the UMSH network through a
BLE-LoRa bridge — is a separate bearer design and is out of scope here.
See [BLE As A Local Bearer](companion-radio.md#ble-as-a-local-bearer)
for the design space. This chapter reserves identifier space for that
future work (see (#uuid-allocation)) but does not specify it.

The companion-radio protocol is transport-agnostic: frames are carried
opaquely and unchanged. This binding replaces only the framing layer.
HDLC-Lite framing (flags, escaping, and the FCS) is **not** used over
BLE; ATT already provides reliable, ordered, integrity-protected
delivery, and frame boundaries are recovered by the segmentation scheme
below.

## GATT Frame Transport {#gatt-frame-transport}

This section defines a generic, service-agnostic pattern for carrying
delimited frames over GATT. The Companion Link Service
(see (#companion-link-service)) instantiates it; a future local-bearer
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
reset reassembly on that characteristic (see (#reassembly)).

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
detaches (see (#attach-semantics)).

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

## Companion Link Service {#companion-link-service}

The Companion Link Service carries companion-radio protocol frames
using the GATT frame transport defined above. One reassembled frame is
exactly one companion-radio frame as defined in
[Frame Format](companion-radio-minimal.md#frame-format); the transport
never inspects or modifies frame contents.

The maximum reassembled frame size for this service is 512 octets.

### UUID Allocation {#uuid-allocation}

UMSH GATT identifiers are allocated from the randomly generated UMSH
base UUID `21EB6B15-XXXX-4CCF-92E4-A079171BEC97`, where `XXXX` is the
assignment slot.

Slot     | UUID                                     | Assignment
---------|------------------------------------------|------------------------------
`0x0001` | `21EB6B15-0001-4CCF-92E4-A079171BEC97`   | Companion Link Service
`0x0002` | `21EB6B15-0002-4CCF-92E4-A079171BEC97`   | Frame In characteristic
`0x0003` | `21EB6B15-0003-4CCF-92E4-A079171BEC97`   | Frame Out characteristic
`0x0100`+| —                                        | Reserved: BLE local bearer

Slots `0x0100` and above are reserved for the future BLE local-bearer
service family and **MUST NOT** be used for tethered companion-link
purposes.

### Attach Semantics {#attach-semantics}

A host is **attached** once it has enabled notifications on Frame Out
(by writing the Client Characteristic Configuration Descriptor) over a
connection meeting the security requirements in (#ble-security).
Connection alone does not attach.

On attach, the NCP **MUST** silently reset its protocol **session
state** — transaction correlation, reassembly, and session-scoped
properties — and **MUST NOT** modify any other state: device and host
provisioning, the RF configuration, and the PHY enable state are
unaffected, and the radio keeps operating through the attach (see
[Attach, Detach, and
Synchronization](companion-radio-full.md#attach-sync)). No unsolicited
notification is emitted on attach; the host learns the NCP's current
state by fetching it. The NCP **MUST NOT** emit any frame before attach.

A host **detaches** by disabling notifications or by disconnecting.
Partially reassembled frames are discarded on detach.

The NCP supports one attached host at a time, across all transports it
exposes. If a new host attaches — over BLE or over another transport
such as USB — the NCP **MUST** detach any previously attached host and
reset the session for the new one. An NCP **MAY** instead reject new
connections while a host is attached.

### Connection Parameters

The transport is latency-tolerant; any standard connection parameters
work. NCPs **SHOULD** accept connection intervals in the 15–50 ms
range so that transmit confirmations and received-frame delivery do
not dominate MAC-layer timing budgets.

## Advertising and Discovery {#ble-advertising}

While powered and not attached, the NCP **SHOULD** advertise as
connectable and include the Companion Link Service UUID in its
advertising data or scan response, so hosts can discover companion
radios by service rather than by name. The advertised local name is
implementation-specific.

While a host is attached over another transport (for example, an open
companion session over USB-CDC), the NCP **SHOULD** suspend
advertising, and **SHOULD** resume it when that host detaches.

Advertising content **MUST NOT** reveal whether the NCP holds bonds or
identify previously bonded hosts. NCPs **SHOULD** use resolvable
private addresses.

Pairing mode (see (#pairing-mode)) governs only the acceptance of
pairing requests; it does not affect advertising. In particular, a
bonded NCP continues to advertise outside pairing mode so that its
bonded hosts can reconnect.

## Security {#ble-security}

The companion-radio protocol is a privileged interface: an attached
host commands transmission with arbitrary content, timing, and power
under the operator's regulatory responsibility, observes all traffic
metadata the radio receives, and can deny service to the legitimate
host. On serial transports this interface is implicitly protected by
physical possession of the device. The BLE binding **MUST** provide at
least an equivalent barrier, and its cryptographic strength **MUST
NOT** fall below that of UMSH itself (approximately 128-bit; see
[Security & Cryptography](security.md)).

### Pairing Requirements

* Pairing **MUST** use LE Secure Connections (LESC). Legacy pairing
  **MUST** be rejected; NCPs **SHOULD** operate in Secure Connections
  Only mode.
* Bonding is **REQUIRED**. The NCP **MUST NOT** attach a host over an
  unbonded link.
* The Frame In and Frame Out characteristics, including the Frame Out
  CCCD, **MUST** be readable and writable only over an encrypted link
  keyed by a stored LESC bond. Access over any other link **MUST** be
  refused with the appropriate ATT security error.

LESC pairing (P-256 ECDH) meets the 128-bit strength requirement. The
remaining risk is man-in-the-middle interception during the pairing
ceremony itself, which the following requirements bound.

### Pairing Mode {#pairing-mode}

Except as provided for configured-PIN and OOB pairing below, the NCP
accepts pairing requests from unbonded devices only while in **pairing
mode**; at all other times such requests **MUST** be rejected.

Entering pairing mode:

* While the NCP holds no bonds, it **SHOULD** enter pairing mode
  automatically at power-on for a short window (15–30 seconds
  **RECOMMENDED**).
* Once the NCP holds one or more bonds, it **MUST NOT** enter pairing
  mode automatically. Entering pairing mode then requires a deliberate
  physical gesture distinct from normal power-on — for example,
  holding the user button through power-on until the device signals
  that pairing mode is active.

Pairing mode **MUST** end when any of the following occurs:

* a new bond completes;
* an already-bonded host establishes an encrypted connection;
* an implementation-defined timeout expires.

The NCP **SHOULD** give a perceptible indication (LED pattern, tone,
or display) while pairing mode is active.

A physical-presence-gated ceremony reduces the pairing trust decision
to possession of the device — the same property that protects the
serial transports.

### Association Models

* Devices with a display and a confirmation input **SHOULD** use an
  authenticated association model (numeric comparison, or passkey
  display) for new bonds.
* Devices without a display, and with no pairing PIN configured, use
  Just Works, accepted only in pairing mode. This model is
  unauthenticated; the pairing-mode gesture is the entire trust
  decision.
* Devices with a pairing PIN configured (see (#pairing-pin)) use LESC
  Passkey Entry with the configured PIN as a static passkey. Such
  pairing **MAY** be accepted outside pairing mode. The NCP **MUST**
  count consecutive passkey authentication failures — pairing
  attempts that fail the LESC confirm-value or DHKey check — since
  power-on; the counter resets on a successful pairing or a power
  cycle. Rejections that never reach passkey authentication
  (legacy-pairing attempts, pairing refused outside pairing mode,
  malformed pairing requests) **MUST NOT** increment the counter, so
  they cannot be used to lock out pairing remotely. After a small
  limit (**MUST NOT** exceed 5; 3 **RECOMMENDED**), the NCP **MUST**
  reject all further pairing attempts until it is power cycled.
* NCPs **MAY** additionally support LESC Out-of-Band pairing (for
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
* Required: **OPTIONAL** (meaningful only on NCPs exposing this
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
NCP **MUST NOT** emit `CMD_PROP_IS` for this property itself. Success
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

* NCPs **MUST** provide a local mechanism to delete stored bonds. The
  mechanism is implementation-specific but **MUST NOT** be invocable
  through the companion-radio protocol itself over an unauthenticated
  path.
* NCPs **MAY** limit the number of stored bonds; when full, new
  pairing attempts fail until a bond is deleted locally.

### Layering Note

BLE link security protects the *transport*. It does not alter the UMSH
security model: MAC-layer keys remain on the host, frames crossing
this link remain UMSH ciphertext where UMSH encrypts them, and a
compromised NCP still cannot impersonate host identities. Conversely,
future companion-protocol extensions that provision keying material to
the NCP (see [Companion Radio](companion-radio.md#security-boundary))
**MUST NOT** be carried over a link that does not meet the
requirements of this section.
