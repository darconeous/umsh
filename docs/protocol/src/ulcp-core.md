# ULCP: Framing and Common Semantics

This chapter defines the ULCP wire format and the semantics every device
implements whatever else it supports: the frame layout, the command
grammar, the property model, the classes of state a device holds, how a
host attaches and synchronizes, and the numeric registries for status
codes, reset codes, and capabilities. The subsystem chapters that follow
build on it.

ULCP is inspired by the Spinel protocol from OpenThread, but it is not
Spinel and does not aim for wire compatibility with it. The protocol
assumes reliable, in-order delivery of frames, as well as a way to assert
flow control. The framing mechanism depends on the underlying transport:

* Asynchronous serial links (UART, USB-CDC) use
  [HDLC-Lite](https://github.com/openthread/openthread/blob/thread-reference-20180926/doc/spinel-protocol-src/spinel-framing.md#hdlc-lite-hdlc-lite),
  exactly as used by Spinel.
* BLE uses the GATT frame transport defined in
  [ULCP over BLE](ulcp-ble.md).

In this chapter, the **device** is the side that owns the transceiver and
the **host** is the side that attaches to it over the local link (see
[Local Control Protocol](ulcp.md)).

The protocol version is **6.0**. Which subsystems a device implements is
discovered through `PROP_CAPS`, never through the version number; see
[Minimum Requirements](ulcp-conformance.md) for what a device is required
to implement in order to be a ULCP device at all.

## Data Representation {#data-representation}

Spinel, being a low-level protocol between two devices which are likely to have
a little-endian architecture, uses little-endian representations exclusively
for all integers smaller than four bytes. For implementation convenience,
values larger than four bytes (EUI64, IPv6 addresses, etc.) are stored as they
are traditionally represented (typically, but not always, big-endian).

### Packed Unsigned Integers {#packed-unsigned-integer}

Certain types of integers, such as command or property identifiers, usually
have a value on the wire that is less than 127. However, in order to not
preclude the use of values larger than 255, we would need to add an extra byte.
Doing this would add an extra byte to all packets, which can add up in terms of
bandwidth. To address this, Spinel uses Packed Unsigned Integers, or PUIs.

The PUI format used in Spinel is based on the [unsigned integer format in
EXI][EXI], except that we limit the maximum value to the largest value that can
be encoded in three bytes. The maximum value that can be encoded is 2,097,151.

[EXI]: https://www.w3.org/TR/exi/#encodingUnsignedInteger

For all values less than 127, the packed form of the number is simply a single
byte which directly represents the number. For values larger than 127, the
following process is used to encode the value:

1. The unsigned integer is broken up into *n* 7-bit chunks and placed into *n*
   bytes, leaving the most significant bit of each byte unused.
2. Order the bytes from least-significant to most-significant. (Little-endian)
3. Clear the most significant bit of the most significant byte. Set the most
   significant bit on all other bytes.

Where *n* is the smallest number of 7-bit chunks you can use to represent the
given value.

Take the value 1337, for example:

    1337 => 0x0539
         => [39 0A]
         => [B9 0A]

To decode the value, you collect the 7-bit chunks until you find a byte with
the most significant bit clear.

## Frame Format {#frame-format}

A ULCP frame is the concatenation of the following elements:

* A header comprising a single byte.
* A command identifier.
* A command-defined payload, which may be empty.

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     HEADER    |  COMMAND ID   | PAYLOAD ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of a typical ULCP frame

Since the size of the frame is part of the framing mechanism, it is omitted
from the frame.

### Frame Header

Each frame has the following format:

~~~
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|  FLG  | RESERVED  |    TID    |
+---+---+---+---+---+---+---+---+
~~~
Figure: Header Format

#### `FLG`: Flag

The Flag (FLG) field in the two most significant bits of the header byte is
always set to the value two (or `10` in binary). Any frame received with these
bits set to any other value SHALL NOT be considered a ULCP frame.

#### `RESERVED`: Reserved

These three bits must always be set to zero and the entire frame ignored if
set to any other value. They may be assigned a meaning (such as an interface
identifier) in a future version of this protocol.

#### `TID`: Transaction Identifier

The Transaction Identifier (TID) field in the three least significant bits of
the header is used for correlating responses to the commands which generated
them. This allows for up to seven host-issued commands to be in flight at
once.

When a command is sent from the host, any reply to that command sent by the device
will use the same value for the TID. When the host receives a frame that
matches the TID of the command it sent, it can easily recognize that frame as
the actual response to that command.

The zero value of TID is used for commands to which a correlated response is
not expected or needed, such as for unsolicited update commands sent to the
host from the device.

Note that while the frame format is symmetric between the frames being sent to
the device versus frames being sent from the device, the behaviors are not. The device
**MUST NOT** send a frame with a non-zero TID that is not a response to a frame
it had recently received with that same TID. All unsolicited or asynchronous
commands originating from the device **MUST** use TID zero (0).

### Command ID

The command identifier is a 7-bit unsigned integer encoded from 0 to 127. The
most significant bit is not set and the frame must be ignored if it is set.

### Payload

The command payload follows the command identifier in a ULCP frame,
containing the serialization of any arguments that the indicated command may
require. The exact composition of a command payload is determined by the
specific command identifier being used and **MUST** be empty if the command has
no arguments.

## Commands

This chapter defines the commands that operate on the protocol itself —
resets, liveness, and the property grammar. The remaining commands are
defined with the subsystem they act on: `CMD_STR_SEND` and `CMD_STR_RECV`
in [Frame Transport](ulcp-transport.md), `CMD_QUEUE_DRAIN` in
[Tethered Host Services](ulcp-host.md), and the four state-management
commands in [Saved State](ulcp-saved-state.md). The complete numeric
allocation is in the [Command and Property Index](ulcp-index.md).

Id | Mnemonic            | Dir          | Description
---|---------------------|--------------|-------------
0  | `CMD_NOP`           | Host->Device | No-Operation
1  | `CMD_RST`           | Host->Device | Reset the device
2  | `CMD_PROP_GET`      | Host->Device | Get property value
3  | `CMD_PROP_SET`      | Host->Device | Set property value
4  | `CMD_PROP_INSERT`   | Host->Device | Insert an item into a multi-value property
5  | `CMD_PROP_REMOVE`   | Host->Device | Remove an item from a multi-value property
6  | `CMD_PROP_IS`       | Device->Host | Property value notification
7  | `CMD_PROP_INSERTED` | Device->Host | Item-inserted notification
8  | `CMD_PROP_REMOVED`  | Device->Host | Item-removed notification

### CMD 0: (Host -> Device) `CMD_NOP` {#cmd-noop}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_NOP    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
^     HEADER    ^    COMMAND    ^
~~~
Figure: Structure of `CMD_NOP`

No-Operation. Commands the device to reply with a `STATUS_OK` code. This is
primarily used for liveness checks.

The command payload for this command SHOULD be empty. The receiver MUST ignore
any non-empty command payload.

There is no error condition for this command.

### CMD 1: (Host -> Device) `CMD_RST` {#cmd-reset}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_RST    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_RST`

Reset device. Commands the device to perform a software reset. Due to the nature of
this command, the TID is ignored. The host should instead wait for a
`CMD_PROP_IS` command from the device indicating `PROP_LAST_STATUS` has been set
to `STATUS_RESET_SOFTWARE` (see [Status Codes](ulcp-core.md#status-codes)).

The command payload SHOULD be empty, and it SHOULD NOT be processed.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 2: (Host -> Device) `CMD_PROP_GET` {#cmd-prop-get}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_GET`

Get property value. Commands the device to emit a `CMD_PROP_IS` command for the
given property identifier.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in [Packed Unsigned Integers](ulcp-core.md#packed-unsigned-integer).

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 3: (Host -> Device) `CMD_PROP_SET` {#cmd-prop-set}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  NEW PROPERTY VALUE ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_SET`

Set property value. Commands the device to set the given property to the specific
given value, replacing any previous value, and to emit a `CMD_PROP_IS` command
for that property indicating the new authoritative value if successful.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in [Packed Unsigned Integers](ulcp-core.md#packed-unsigned-integer), followed by
the property value. The exact format of the property value is defined by the
property.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 4: (Host -> Device) `CMD_PROP_INSERT` {#cmd-prop-insert}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM VALUE ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_INSERT`

Insert item into property. Commands the device to add the given item to the
given multi-value property, and to emit a `CMD_PROP_INSERTED` command for
that property if successful.

The payload for this command is the property identifier encoded in the
packed unsigned integer format, followed by exactly one item encoded in the
property's **item form** (see [Multi-Value Properties](ulcp-core.md#multi-value-properties)). The item is
**not** preceded by a length prefix, regardless of whether the property
uses item length prefixes in its multi-item value form; the framing layer
bounds the item.

If the item is already present the command fails with `STATUS_ALREADY`,
except where a property defines replacement semantics for matching items
(see, e.g., [`PROP_HOST_PEER_KEYS`](ulcp-host.md#prop-host-peer-keys)). If the property exists but is not a
multi-value property, the command fails with `STATUS_INVALID_ARGUMENT`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 5: (Host -> Device) `CMD_PROP_REMOVE` {#cmd-prop-remove}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM SELECTOR ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_REMOVE`

Remove item from property. Commands the device to remove the item matching the
given selector from the given multi-value property, and to emit a
`CMD_PROP_REMOVED` command for that property if successful.

The payload for this command is the property identifier encoded in the
packed unsigned integer format, followed by an item selector. Each
multi-value property documents its selector form; unless stated otherwise
it is the full item value.

If no matching item is present, the command fails with
`STATUS_ITEM_NOT_FOUND`. If the property exists but is not a multi-value
property, the command fails with `STATUS_INVALID_ARGUMENT`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 6: (Device -> Host) `CMD_PROP_IS` {#cmd-prop-is}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  CURRENT PROPERTY VALUE ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_IS`

Property value notification. This command can be sent by the device in response to
a previous command from the host, or it can be sent by the device in an
unsolicited fashion to notify the host of various state changes asynchronously.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in [Packed Unsigned Integers](ulcp-core.md#packed-unsigned-integer), followed by
the current value of the given property.

### CMD 7: (Device -> Host) `CMD_PROP_INSERTED` {#cmd-prop-inserted}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM DIGEST ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_INSERTED`

Item-inserted notification. Sent by the device in response to a successful
`CMD_PROP_INSERT` (with the TID of that command), or unsolicited with a TID
of zero when the device adds an item to a multi-value property for its own
reasons.

The payload is the property identifier followed by the inserted item in the
property's **digest form** (see [Multi-Value Properties](ulcp-core.md#multi-value-properties)) — never in a
form containing key material.

### CMD 8: (Device -> Host) `CMD_PROP_REMOVED` {#cmd-prop-removed}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ITEM DIGEST ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_REMOVED`

Item-removed notification. Sent by the device in response to a successful
`CMD_PROP_REMOVE` (with the TID of that command), or unsolicited with a TID
of zero when the device removes an item from a multi-value property for its
own reasons.

The payload is the property identifier followed by the removed item in the
property's digest form.

## Properties and Streams

A **property** is a piece of device state with a value the host can read
and, where the property allows it, write. A **stream** is a packet-like
flow that is not modeled as state; streams share the property identifier
space and are carried by their own commands (see
[Frame Transport](ulcp-transport.md)).

> [!NOTE]
> The properties marked as supporting `Is` means that the property may be
> emitted asynchronously. All properties that support `Get` or `Set` will emit
> an `Is` to respond with the current/new value of that property.

### Multi-Value Properties {#multi-value-properties}

A **multi-value property** holds an unordered set of items rather than a
single value. `PROP_CAPS` is one, and is constant; the key, peer, and
filter tables of the device and host domains are mutable ones.

Each multi-value property defines two encodings for its items:

* the **item form**, used when the host writes items (`CMD_PROP_SET`,
  `CMD_PROP_INSERT`); and
* the **digest form**, used whenever the device reports items
  (`CMD_PROP_IS`, `CMD_PROP_INSERTED`, `CMD_PROP_REMOVED`).

For most properties the two forms are identical. They differ exactly where
the item form contains symmetric key material: the digest form of such a
property omits or replaces the key material so that secrets can never be
read back (see [Provisioning Security](ulcp-core.md#provisioning-security)).

The commands valid on a mutable multi-value property are:

* `CMD_PROP_GET` — the device replies with `CMD_PROP_IS` whose value is the
  concatenation of all items in digest form. If the property is documented
  as having an item length prefix, each item is preceded by its length in
  octets encoded as a packed unsigned integer; properties whose reported
  items are fixed-size omit the prefix.
* `CMD_PROP_SET` — replaces the entire contents with the items encoded in
  the value, each in item form (with the same length-prefix rule). Setting
  an empty value clears the property. Success is reported with a
  `CMD_PROP_IS` carrying the new complete value in digest form.
* `CMD_PROP_INSERT` / `CMD_PROP_REMOVE` — add or remove one item, as
  defined above.

Hosts manipulating large tables **SHOULD** prefer `Insert`/`Remove` over
whole-table `Set`, since a full table may not fit comfortably in one frame
on all transports.

## Mutation Atomicity {#mutation-atomicity}

State-changing operations in this protocol are transactional and fail
closed:

* The device **MUST** validate a complete request before changing any state.
  A whole-table `CMD_PROP_SET` whose value contains any invalid item fails
  without applying any of it.
* Whole-table replacement is atomic: no observer of device behavior (frame
  filtering, acknowledgement decisions) sees a mixture of the old and new
  contents.
* Operations that include durable writes — `CMD_SAVE`, `CMD_CLEAR`,
  installing or generating the device identity, and setting
  `PROP_BLE_PAIRING_PIN` — **MUST NOT** report success before the durable
  write has completed.
* On any failure, the prior live and durable state remains unchanged, and
  the device **MUST NOT** emit `CMD_PROP_IS`, `CMD_PROP_INSERTED`, or
  `CMD_PROP_REMOVED` notifications describing a partially applied change.
* Host replacement is atomic in the same sense: at no point may the device
  operate with a mixture of the old and new hosts' keys, filters, or
  policy. It involves no durable write, so it cannot fail partway.

Atomicity is per operation, not per sequence. Establishing a host domain
is several property writes, and an interruption between them leaves a
mixture of old and new — bounded by the fact that a host-key change resets
the domain first and a reboot empties it. A host repairs this the same way
it provisions in the first place: by writing everything again.

## Core Properties

These properties exist on every device and are not gated by any
capability.

Id | Mnemonic                | Commands | Description
---|-------------------------|----------|-------------
0  | `PROP_LAST_STATUS`      | Get, Is  | Last status
1  | `PROP_PROTOCOL_VERSION` | Get      | Protocol version
2  | `PROP_DEV_VERSION`      | Get      | Device version string
3  | `PROP_INTERFACE_TYPE`   | Get      | Interface type
5  | `PROP_CAPS`             | Get      | Capabilities

### PROP 0: `PROP_LAST_STATUS` {#prop-last-status}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: **REQUIRED**
* Value Type: PUI + STRING(opt.)
* Units: Enumeration
* Post-Reset Value: Reset Reason Code

This property describes the status code of the last device operation. For many
commands, failure is indicated by emitting `CMD_PROP_IS` for this property with
a TID matching the failing command. It is generally not necessary to ever fetch
the value of this property explicitly, as it is often emitted directly as an
error response. It is also occasionally emitted as a success response with a
value of `STATUS_OK`.

Upon device reset, this property **MUST** be emitted with a status code indicating
the reset reason.

Upon receiving an asynchronous update to `PROP_LAST_STATUS` with a status code
that indicates a reset, the host SHALL assume that the device has been reset and
that all properties have reverted to their defined after-reset values.

See [Status Codes](ulcp-core.md#status-codes) for the complete list of status codes.

### PROP 1: `PROP_PROTOCOL_VERSION` {#prop-protocol-version}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: Device
* Value Type: UINT8, UINT8
* Post-Reset Value: 6, 0

Describes the ULCP version information. This property
contains two fields:

~~~
  0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| MAJOR_VERSION | MINOR_VERSION |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: `PROP_PROTOCOL_VERSION` Value Format

`MAJOR_VERSION`
: The major version number is used to identify backward incompatible
  differences between protocol versions.

`MINOR_VERSION`
: The minor version number is used to identify backward-compatible differences
  between protocol versions. A mismatch between the advertised minor version
  number and the minor version that is supported by the host **SHOULD NOT** be
  fatal to the operation of the host.

This document describes major version 6, minor version 0 of this protocol.

### PROP 2: `PROP_DEV_VERSION` {#prop-dev-version}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: Device
* Value Type: STRING
* Post-Reset Value: Implementation-Specific

Contains a zero-terminated ASCII string which describes the firmware currently
running on the device.

The value of this string **MUST** be different for every firmware release.

The format of the string is not strictly defined, but it is intended to present
similarly to the "User-Agent" string from HTTP. The following format is
**RECOMMENDED**:

`STACK-NAME/STACK-VERSION[BUILD-INFO][; OTHER-INFO][; BUILD-DATE]`

### PROP 3: `PROP_INTERFACE_TYPE` {#prop-interface-type}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Value Type: PUI
* Units: Enumeration
* Post-Reset Value: Implementation-Specific

This unsigned packed integer identifies the network protocol implemented by
this device. It must return the value 8.

### PROP 5: `PROP_CAPS` {#prop-caps}

* Type: Multiple-Value, Constant
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Item Type: PUI
* Units: Enumeration
* Post-Reset Value: Implementation-Specific

Describes the supported capabilities of this device. Encoded as a list of packed
unsigned integers. See [Capabilities](ulcp-core.md#capabilities) for a list of values.

## State Classes {#state-classes}

Every piece of device state belongs to exactly one of three classes. The
classes determine what survives a host attach, a change of host, and a
power cycle.

### Session State {#session-state}

State that exists only while a host is attached: transaction (TID)
correlation, transport reassembly buffers, and session-scoped properties —
currently only `PROP_MAC_PROMISCUOUS`. Session state is reset to defaults
on every attach. Resetting it never affects radio operation.

### Device Domain {#device-domain}

State that belongs to the device itself, independent of which
host is attached:

* the device identity keypair (independently persisted; never part of
  the saved snapshot — see [Saved State](ulcp-saved-state.md#saved-state))
* the device identity's channel keys ([`PROP_DEV_CHANNEL_KEYS`](ulcp-device.md#prop-dev-channel-keys)) and peer
  list ([`PROP_DEV_PEERS`](ulcp-device.md#prop-dev-peers))
* the RF configuration (`PROP_PHY_*`), including `PROP_PHY_ENABLED`, and
  the duty-cycle limit
* the human-readable device name (`PROP_DEV_NAME`)
* live battery telemetry (`PROP_BATTERY`), when `CAP_BATTERY` is present
* device behavior settings (property identifiers 70–95): the repeater
  forwarding switch (`PROP_MAC_REPEATER_ENABLED`), with the rest of the
  range reserved for future definition (further repeater policy,
  positioning, periodic advertisement of the device identity, and similar)
* transport configuration such as `PROP_BLE_PAIRING_PIN`

The RF configuration is deliberately device-domain: a site repeater keeps
its frequency and regulatory limits no matter which phone pairs with it.
An attached host may still reconfigure it at any time.

### Host Domain {#host-domain}

State that belongs to the currently configured tethered host identity:

* `PROP_HOST_KEY` itself
* the host's channel keys and peer keys
* the receive filter table and acknowledgement-delegation policy
* the inbound queue: its configuration and its contents

**The host domain is volatile across a power cycle, and only across a
power cycle.** It **MUST NOT** be persisted: it is not part of the saved
snapshot, and at power-on every host-domain property takes its documented
default.

It emphatically does survive a *disconnect*. A detached radio keeps
filtering, queueing and acknowledging on behalf of its host for as long as
it stays powered — that is the entire value of the host domain, and
nothing about the host going out of range changes what the host wants
done.

The two together give the host a simple rule with no detection in it: a
host **MUST** establish its complete host domain on every tethered
attach, writing every part of it rather than reasoning about what the
device already holds. Key material cannot be compared anyway — the key
tables read back in digest form only (see [Provisioning Security](ulcp-core.md#provisioning-security)), so a
peer's pairwise keys can be replaced without changing anything the host
can observe. Where the device is already provisioned as asked, the rewrite
is redundant; that is preferable to depending on a signal that would also
have to cover partial provisioning, another administrator's intervention,
and future device behavior. A boot generation or reset indication **MAY**
be used to *skip* the rewrite as an optimization, never to decide whether
it is needed.

## Property Allocation {#property-allocation}

Property and stream identifiers are allocated by state class and
subsystem:

Range      | Class
-----------|--------------------------------------------
0–31       | Core protocol state
32–47      | Radio control (`PROP_PHY_*`)
48–63      | Session-scoped and global protocol state
64–95      | Device domain
96–111     | Host domain (`PROP_HOST_*`)
112–127    | Streams (`STR_*`)
4608–4863  | Extended radio control
4864–5119  | Extended device and transport configuration

Unassigned identifiers in these ranges are reserved. The identifiers in
use are listed in the
[Command and Property Index](ulcp-index.md).

## Attach, Detach, and Synchronization {#attach-sync}

How attach and detach are detected is defined by the transport binding:

* **BLE** — enabling/disabling notifications on Frame Out, as specified in
  [ULCP over BLE](ulcp-ble.md#attach-semantics).
* **USB-CDC** — assertion and deassertion of DTR on the ULCP
  interface.
* **Bare UART** — implementation-defined. A device with no way to detect
  host presence MAY treat the host as permanently attached, in which case
  it never enters detached operation and offline assistance
  ([Inbound Queueing](ulcp-host.md#inbound-queueing), [Acknowledgement Delegation](ulcp-host.md#ack-delegation)) is unavailable on that
  transport.

On attach, the device **MUST** reset session state (see [State Classes](ulcp-core.md#state-classes)) and
**MUST NOT** modify the device or host domains in any way. In particular,
the PHY is not disabled and no property outside session state changes
value. The device **MUST NOT** emit any frame before attach, and emits no
unsolicited notification as a result of the attach itself.

Because attach no longer implies any known default state, the host
synchronizes by *fetching*, not by assuming. The following post-attach
procedure is **RECOMMENDED**:

1. `CMD_PROP_GET` for `PROP_LAST_STATUS`. If it returns a reset code (see
   [Reset Codes](ulcp-core.md#reset-codes)), the device has
   reset since the last host command, so any state that is not restored
   from saved state (notably queue contents) has been lost.
2. `CMD_PROP_GET` for `PROP_HOST_KEY`. An empty value is the ordinary
   case after a power cycle — the host domain does not survive one — and
   the host simply provisions. A value matching the host's own identity
   means its provisioning is still live from before the disconnect. Any
   *other* value means another host has taken the radio over since this
   host last attached; the queue and provisioning belong to that
   identity, and this host must decide whether to take the radio over
   (see [Host Replacement](ulcp-host.md#host-replacement)) before doing anything else.
3. `CMD_PROP_GET` for the device-domain properties the host depends on
   (`PROP_SAVED`, the `PROP_PHY_*` configuration), and for
   `PROP_HOST_RX_QUEUE_COUNT`.
4. Establish the complete host domain (see [Host Domain](ulcp-core.md#host-domain)): write
   `PROP_HOST_KEY`, the key tables, the filter table and the delegation
   policy in full. The digest forms of the key tables are read only to
   find entries the host no longer wants, which it removes; entries it
   *does* want are written whether or not the device reports them, since
   key material is not readable and so cannot be compared.
5. Issue `CMD_QUEUE_DRAIN` when actually ready to process backlogged
   traffic.

More generally, a host **MUST** tolerate unsolicited `CMD_PROP_IS`,
`CMD_PROP_INSERTED`, and `CMD_PROP_REMOVED` notifications at any time
while attached, updating its view of the affected property accordingly:
device state can change for reasons the host did not initiate, and
publication of the new authoritative value is how the protocol reports
that.

On detach, the device discards session state, keeps operating with the
current device- and host-domain state, and begins detached operation:
accepted frames are queued rather than delivered, and acknowledgement
delegation (if enabled) becomes active.

## Provisioning Security {#provisioning-security}

Provisioning moves real key material onto the device, within the limits of the
[security boundary](ulcp.md#security-boundary): channel keys and
per-peer symmetric keys — and the device identity's own private key —
but never the host's private key. The rules:

* **All symmetric key material, and the device identity private key, is
  write-only.** `CMD_PROP_GET` and all device-emitted notifications report
  key-bearing properties in their digest forms
  (see [Multi-Value Properties](ulcp-core.md#multi-value-properties)): peer public keys without `K_ENC`/`K_MIC`,
  derived channel identifiers instead of channel keys, and never the
  device private key. This holds for **both** identities' key tables.
  Digest forms let the host verify *what* is provisioned after a
  reconnect without any secret ever crossing the link a second time —
  which matters because more than one host may be able to attach over the
  radio's lifetime (transport bonds are possession credentials, not
  identity credentials), and a later host must not be able to extract an
  earlier host's keys.
* Commands that carry key material — `CMD_PROP_SET` and `CMD_PROP_INSERT`
  for the key tables, and any set of `PROP_DEV_PRIVATE_KEY` — **MUST NOT**
  be carried over a transport that does not meet the requirements of the
  transport's security binding: physical possession for serial transports,
  or an encrypted bonded LESC link as specified in
  [ULCP over BLE](ulcp-ble.md#ble-security).
* A compromised or stolen device exposes the provisioned channels, the
  provisioned pairwise conversations, and its own device identity, but
  cannot impersonate the host to any new peer, cannot sign as the host,
  and cannot decrypt traffic for peers or channels that were never
  provisioned.
* Hosts **SHOULD** provision the minimum useful set of peers and channels,
  **SHOULD** remove entries that are no longer needed, and **SHOULD**
  prefer on-device generation of the device identity over installing one.
* A device advertising `CAP_SAVE` **MUST** store persisted key material in
  the most protected storage available to it.

## Status Codes {#status-codes}

Status codes are used for `PROP_LAST_STATUS`. When a command generates a status
code, it is returned via a `CMD_PROP_IS` with a property of `PROP_LAST_STATUS`
and the `TID` of command it is referring to.

Id | Name
---|----------------------------------
0  | `STATUS_OK`
1  | `STATUS_FAILURE`
2  | `STATUS_UNIMPLEMENTED`
3  | `STATUS_INVALID_ARGUMENT`
4  | `STATUS_INVALID_STATE`
5  | `STATUS_INVALID_COMMAND`
7  | `STATUS_INTERNAL_ERROR`
9  | `STATUS_PARSE_ERROR`
10 | `STATUS_IN_PROGRESS`
11 | `STATUS_NOMEM`
12 | `STATUS_BUSY`
13 | `STATUS_PROP_NOT_FOUND`
18 | `STATUS_CCA_FAILURE`
19 | `STATUS_ALREADY`
20 | `STATUS_ITEM_NOT_FOUND`
32 | `STATUS_DUTY_LIMIT`

`STATUS_OK`
: Indicates that the operation has completed successfully.

`STATUS_FAILURE`
: Indicates that the operation has failed for an unspecified reason. The use of
  this status code **SHOULD** be avoided. If a more specific status code exists
  that better explains the failure, then that status code **MUST** be used
  instead.

`STATUS_UNIMPLEMENTED`
: Indicates that the given operation has not been implemented.

`STATUS_INVALID_ARGUMENT`
: Indicates that an argument to the given operation is invalid. The value may
  be out of range or improperly formatted. This status code is also returned
  when setting an invalid value to a property.

`STATUS_INVALID_STATE`
: Indicates that the given operation is invalid for the current state of the
  device.

`STATUS_INVALID_COMMAND`
: The given command id is not recognized.

`STATUS_INTERNAL_ERROR`
: An internal runtime error has occurred.

`STATUS_PARSE_ERROR`
: An error has occurred while parsing the command.

`STATUS_IN_PROGRESS`
: Indicates that the operation was started but has not completed, and
  completion will be reported asynchronously.

`STATUS_NOMEM`
: The operation has been prevented due to memory pressure.

`STATUS_BUSY`
: The device is currently performing a mutually exclusive operation. This status
  differs from `STATUS_INVALID_STATE` in that it will resolve spontaneously.

`STATUS_PROP_NOT_FOUND`
: The given property key is not recognized.

`STATUS_ALREADY`
: The requested state is already in effect; in particular, the item passed
  to `CMD_PROP_INSERT` is already present in the property.

`STATUS_ITEM_NOT_FOUND`
: The item or selector passed to `CMD_PROP_REMOVE` does not match any item
  in the property.

`STATUS_CCA_FAILURE`
: The packet was not sent due to a CCA failure. This status code is only
  emitted when sending data to a packet stream with a TID other than zero.

`STATUS_DUTY_LIMIT`
: The packet cannot be sent because it would exceed the currently set
  duty-cycle limit.

## Reset Codes {#reset-codes}

All status codes which fall into the inclusive range of 112-127 are considered
*reset codes*. These codes are emitted asynchronously after a device reset and
provide a way to differentiate different causes of resets. If the first command
the host sends to the device after a reset is to fetch `PROP_LAST_STATUS`, then
the reset code **MUST** be returned.

> [!NOTE]
> On a device holding a [saved snapshot](ulcp-saved-state.md#saved-state),
> the post-reset value of every saved property is its saved value rather
> than the documented default. A host **MUST NOT** assume that a reset
> implies documented factory defaults; it should fetch or explicitly set
> the properties it depends on. Without a snapshot the documented
> post-reset values apply unconditionally.

Id  | Name
----|------------------------
112 | `STATUS_RESET_POWER_ON`
113 | `STATUS_RESET_EXTERNAL`
114 | `STATUS_RESET_SOFTWARE`
115 | `STATUS_RESET_RESTORED`
116 | `STATUS_RESET_CRASH`
117 | `STATUS_RESET_ASSERT`
118 | `STATUS_RESET_OTHER`
119 | `STATUS_RESET_UNKNOWN`
120 | `STATUS_RESET_WATCHDOG`

Of these defined reset codes, only `STATUS_RESET_POWER_ON`,
`STATUS_RESET_EXTERNAL`, `STATUS_RESET_SOFTWARE`, and
`STATUS_RESET_RESTORED` are emitted during normal operation. All other
reset codes generally indicate some sort of software bug or hardware
failure.

Unexpected or unrequested resets are always an indication of a problem, no
matter what the code value is.

`STATUS_RESET_POWER_ON`
: Cold power-on start.

`STATUS_RESET_EXTERNAL`
: External device reset. This is generally caused by RESET pin on the device being
  asserted.

`STATUS_RESET_SOFTWARE`
: Software-requested orderly reset. This is generally caused by the host
  sending the device `CMD_RST`.

`STATUS_RESET_RESTORED`
: Protocol reset into the saved snapshot, emitted when a device completes
  `CMD_RESTORE` in its reset form (see
  [`CMD_RESTORE`](ulcp-saved-state.md#cmd-restore)). Unlike the other
  reset codes, this one does not indicate a hardware or firmware restart:
  the transport link and attach state survive it.

`STATUS_RESET_CRASH`
: Unrecoverable software execution failure, like a segmentation fault or a
  stack overflow.

`STATUS_RESET_ASSERT`
: Software invariant property not respected.

`STATUS_RESET_OTHER`
: Unspecified cause.

`STATUS_RESET_UNKNOWN`
: Failure while recovering cause of reset.

`STATUS_RESET_WATCHDOG`
: Watchdog timer expired, forcing a reset.

## Capabilities {#capabilities}

Capabilities are how a device can advertise support for specific behaviors and
functionalities. They can be fetched via the `PROP_CAPS` property.

Each capability is defined by the chapter that specifies the behavior it
grants:

Code | Name                      | Requires                             | Defined in
-----|---------------------------|--------------------------------------|------------
8    | `CAP_WRITABLE_RAW_STREAM` | —                                    | [Frame Transport](ulcp-transport.md#capabilities)
16   | `CAP_PHY_DUTY_LIMIT`      | —                                    | [Radio Control](ulcp-radio.md#capabilities)
32   | `CAP_HOST_FILTER`         | —                                    | [Tethered Host Services](ulcp-host.md#capabilities)
33   | `CAP_HOST_RX_QUEUE`       | `CAP_HOST_FILTER`                    | [Tethered Host Services](ulcp-host.md#capabilities)
34   | `CAP_HOST_KEYS`           | `CAP_HOST_FILTER`                    | [Tethered Host Services](ulcp-host.md#capabilities)
35   | `CAP_HOST_AUTO_ACK`       | `CAP_HOST_KEYS`, `CAP_HOST_RX_QUEUE` | [Tethered Host Services](ulcp-host.md#capabilities)
36   | `CAP_SAVE`                | —                                    | [Saved State](ulcp-saved-state.md#capabilities)
37   | `CAP_DEV_IDENTITY`        | —                                    | [Device Domain](ulcp-device.md#capabilities)
38   | `CAP_DEV_NAME`            | —                                    | [Device Domain](ulcp-device.md#capabilities)
39   | `CAP_BATTERY`             | —                                    | [Device Domain](ulcp-device.md#capabilities)
40   | `CAP_REPEATER`            | `CAP_DEV_IDENTITY`                   | [Device Domain](ulcp-device.md#capabilities)
41   | `CAP_IDENT`               | `CAP_DEV_IDENTITY`                   | [Device Domain](ulcp-device.md#capabilities)
515  | `CAP_PHY_LORA`            | —                                    | [Radio Control](ulcp-radio.md#capabilities)

A device **MUST NOT** advertise a capability without also advertising the
capabilities it requires. The commands and status codes defined in this
chapter are unconditional and need no capability; a device that defines no
mutable multi-value properties simply has nothing to apply
`CMD_PROP_INSERT`/`CMD_PROP_REMOVE` to.
