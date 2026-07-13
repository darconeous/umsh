# Minimal Companion Radio Protocol

The companion radio protocol is inspired by the Spinel protocol from
OpenThread, but it is not Spinel and does not aim for wire compatibility with
it. The protocol assumes reliable, in-order delivery of frames, as well as a
way to assert flow control. The framing mechanism depends on the underlying
transport:

* Asynchronous serial links (UART, USB-CDC) use
  [HDLC-Lite](https://github.com/openthread/openthread/blob/thread-reference-20180926/doc/spinel-protocol-src/spinel-framing.md#hdlc-lite-hdlc-lite),
  exactly as used by Spinel.
* BLE will use a framing scheme to be defined separately.

The specific subset of the protocol documented here is the minimal set needed
to configure and use a LoRa radio. All other concerns are left out to make it
easier to implement this initial step.

In this document, we refer to the companion radio as the "NCP" or "network
control processor". This is a carry-over from Thread, but it seems appropriate
to use here.

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

## Frame Format

A companion-radio frame is the concatenation of the following elements:

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
Figure: Structure of a typical companion-radio frame

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
bits set to any other value SHALL NOT be considered a companion-radio frame.

#### `RESERVED`: Reserved

These three bits must always be set to zero and the entire frame ignored if
set to any other value. They may be assigned a meaning (such as an interface
identifier) in a future version of this protocol.

#### `TID`: Transaction Identifier

The Transaction Identifier (TID) field in the three least significant bits of
the header is used for correlating responses to the commands which generated
them. This allows for up to seven host-issued commands to be in flight at
once.

When a command is sent from the host, any reply to that command sent by the NCP
will use the same value for the TID. When the host receives a frame that
matches the TID of the command it sent, it can easily recognize that frame as
the actual response to that command.

The zero value of TID is used for commands to which a correlated response is
not expected or needed, such as for unsolicited update commands sent to the
host from the NCP.

Note that while the frame format is symmetric between the frames being sent to
the NCP versus frames being sent from the NCP, the behaviors are not. The NCP
**MUST NOT** send a frame with a non-zero TID that is not a response to a frame
it had recently received with that same TID. All unsolicited or asynchronous
commands originating from the NCP **MUST** use TID zero (0).

### Command ID

The command identifier is a 7-bit unsigned integer encoded from 0 to 127. The
most significant bit is not set and the frame must be ignored if it is set.

### Payload

The command payload follows the command identifier in a companion-radio frame,
containing the serialization of any arguments that the indicated command may
require. The exact composition of a command payload is determined by the
specific command identifier being used and **MUST** be empty if the command has
no arguments.

## Commands

The following commands are initially supported:

Id | Mnemonic         | Dir       | Description
---|------------------|-----------|-------------
0  | `CMD_NOP`        | Host->NCP | No-Operation
1  | `CMD_RST`        | Host->NCP | Reset the NCP
2  | `CMD_PROP_GET`   | Host->NCP | Get property value
3  | `CMD_PROP_SET`   | Host->NCP | Set property value
6  | `CMD_PROP_IS`    | NCP->Host | Property value notification
9  | `CMD_STR_SEND`   | Host->NCP | Send data to a stream
10 | `CMD_STR_RECV`   | NCP->Host | Receive data from a stream

Command identifiers 4, 5, 7, and 8 are reserved for property insert/remove
operations and their corresponding notifications, which may be added in a
future version of this protocol.

### CMD 0: (Host -> NCP) `CMD_NOP` {#cmd-noop}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_NOP    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
^     HEADER    ^    COMMAND    ^
~~~
Figure: Structure of `CMD_NOP`

No-Operation. Commands the NCP to reply with a `STATUS_OK` code. This is
primarily used for liveness checks.

The command payload for this command SHOULD be empty. The receiver MUST ignore
any non-empty command payload.

There is no error condition for this command.

### CMD 1: (Host -> NCP) `CMD_RST` {#cmd-reset}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |    CMD_RST    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_RST`

Reset NCP. Commands the NCP to perform a software reset. Due to the nature of
this command, the TID is ignored. The host should instead wait for a
`CMD_PROP_IS` command from the NCP indicating `PROP_LAST_STATUS` has been set
to `STATUS_RESET_SOFTWARE` (see (#status-codes)).

The command payload SHOULD be empty, and it SHOULD NOT be processed.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 2: (Host -> NCP) `CMD_PROP_GET` {#cmd-prop-get}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | PROP_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_PROP_GET`

Get property value. Commands the NCP to emit a `CMD_PROP_IS` command for the
given property identifier.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in (#packed-unsigned-integer).

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 3: (Host -> NCP) `CMD_PROP_SET` {#cmd-prop-set}

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

Set property value. Commands the NCP to set the given property to the specific
given value, replacing any previous value, and to emit a `CMD_PROP_IS` command
for that property indicating the new authoritative value if successful.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in (#packed-unsigned-integer), followed by
the property value. The exact format of the property value is defined by the
property.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 6: (NCP -> Host) `CMD_PROP_IS` {#cmd-prop-is}

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

Property value notification. This command can be sent by the NCP in response to
a previous command from the host, or it can be sent by the NCP in an
unsolicited fashion to notify the host of various state changes asynchronously.

The payload for this command is the property identifier encoded in the packed
unsigned integer format described in (#packed-unsigned-integer), followed by
the current value of the given property.

### CMD 9: (Host -> NCP) `CMD_STR_SEND` {#cmd-str-send}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |      CMD      | STREAM_KEY (PUI, 1-3 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   DATA_LEN (Little endian)    | DATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   METADATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_STR_SEND`

Command for sending data (such as a packet) to a stream.

The format of the metadata is defined by the stream, and may be absent. Since
the framing layer provides the total frame length, `DATA_LEN` is sufficient to
determine the length of both the data and any trailing metadata.

If a non-zero TID is used, the command completes only once the frame has either
been transmitted on air or definitively failed. Success is reported by emitting
`CMD_PROP_IS` for `PROP_LAST_STATUS` with `STATUS_OK` and a matching TID.

The NCP only attempts one confirmed transmit at a time. If a `CMD_STR_SEND`
with a non-zero TID arrives while another confirmed transmit is in progress,
the new command fails with `STATUS_BUSY`.

The radio will never wait for duty-cycle allowance. If transmission would
exceed the currently configured duty-cycle limit and the `NODUTY` flag is not
set, the command fails immediately with `STATUS_DUTY_LIMIT`.

Commands sent with TID zero are fire-and-forget and do not receive a correlated
completion response.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 10: (NCP -> Host) `CMD_STR_RECV` {#cmd-str-recv}

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES |0 0 0|      CMD      | STREAM_KEY (PUI, 1-3 bytes)...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   DATA_LEN (Little endian)    | DATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   METADATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_STR_RECV`

Notification of incoming data received on the given stream. Because this
command is only ever sent asynchronously, the TID is always zero.

The format of the metadata is defined by the stream, and may be absent. Since
the framing layer provides the total frame length, `DATA_LEN` is sufficient to
determine the length of both the data and any trailing metadata.

## Properties and Streams

> [!NOTE]
> The properties marked as supporting `Is` means that the property may be
> emitted asynchronously. All properties that support `Get` or `Set` will emit
> an `Is` to respond with the current/new value of that property.

Id   | Mnemonic              | Commands   | Description
-----|-----------------------|------------|-------------
0    | `PROP_LAST_STATUS`    | Get, Is    | Last status
1    | `PROP_PROTOCOL_VERSION` | Get      | Protocol version
2    | `PROP_NCP_VERSION`    | Get        | NCP version string
3    | `PROP_IFACE_TYPE`     | Get        | Interface type
5    | `PROP_CAPS`           | Get        | Capabilities
32   | `PROP_PHY_ENABLED`    | Get, Set   | PHY enabled
35   | `PROP_PHY_FREQ`       | Get, Set   | Frequency in kHz
37   | `PROP_PHY_TX_POWER`   | Get, Set   | TX power in dBm
38   | `PROP_PHY_RSSI`       | Get        | Current RSSI
39   | `PROP_PHY_LORA_BW`    | Get, Set   | LoRa bandwidth
40   | `PROP_PHY_LORA_SF`    | Get, Set   | LoRa spreading factor
41   | `PROP_PHY_LORA_CR`    | Get, Set   | LoRa coding rate
42   | `PROP_PHY_MTU`        | Get        | Max size of a frame
43   | `PROP_PHY_LORA_SW`    | Get, Set   | LoRa sync word (16-bit style)
113  | `STR_PHY_RAW`         | Send, Recv | Raw radio frame stream
4820 | `PROP_PHY_DUTY_NOW`   | Get        | Current duty usage
4822 | `PROP_PHY_DUTY_LIMIT` | Get, Set   | Duty-cycle limit

### PROP 0: `PROP_LAST_STATUS` {#prop-last-status}

* Type: Single-Value, Read-Only
* Asynchronous Updates: Yes
* Required: **REQUIRED**
* Value Type: PUI + STRING(opt.)
* Units: Enumeration
* Post-Reset Value: Reset Reason Code

This property describes the status code of the last NCP operation. For many
commands, failure is indicated by emitting `CMD_PROP_IS` for this property with
a TID matching the failing command. It is generally not necessary to ever fetch
the value of this property explicitly, as it is often emitted directly as an
error response. It is also occasionally emitted as a success response with a
value of `STATUS_OK`.

Upon NCP reset, this property **MUST** be emitted with a status code indicating
the reset reason.

Upon receiving an asynchronous update to `PROP_LAST_STATUS` with a status code
that indicates a reset, the host SHALL assume that the NCP has been reset and
that all properties have reverted to their defined after-reset values.

See (#status-codes) for the complete list of status codes.

### PROP 1: `PROP_PROTOCOL_VERSION` {#prop-protocol-version}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NCP
* Value Type: UINT8, UINT8
* Post-Reset Value: 6, 0

Describes the companion-radio protocol version information. This property
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

### PROP 2: `PROP_NCP_VERSION` {#prop-ncp-version}

* Type: Single-Value, Constant
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NCP
* Value Type: STRING
* Post-Reset Value: Implementation-Specific

Contains a zero-terminated ASCII string which describes the firmware currently
running on the NCP.

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
this NCP. It must return the value 8.

### PROP 5: `PROP_CAPS` {#prop-caps}

* Type: Multiple-Value, Constant
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Item Type: PUI
* Units: Enumeration
* Post-Reset Value: Implementation-Specific

Describes the supported capabilities of this NCP. Encoded as a list of packed
unsigned integers. See (#capabilities) for a list of values.

### PROP 32: `PROP_PHY_ENABLED` {#prop-phy-enabled}

* Type: Single-Value, Read/Write
* Asynchronous Updates: No
* Required:
  * `CMD_PROP_GET`: **REQUIRED**
  * `CMD_PROP_SET`: **REQUIRED**
* Scope: NLI
* Value Type: BOOL
* Post-Reset Value: 0 (false)

Set to 1 if the PHY is enabled, set to 0 otherwise. May be directly enabled to
bypass higher-level packet processing in order to implement things like packet
sniffers.

### PROP 35: `PROP_PHY_FREQ` {#prop-phy-freq}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Value Type: UINT32_LE
* Units: kHz
* Post-Reset Value: Unspecified

Value is the radio frequency (in kilohertz) of the current channel.

### PROP 37: `PROP_PHY_TX_POWER` {#prop-phy-tx-power}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Value Type: INT8
* Units: dBm
* Post-Reset Value: Implementation-Specific

Value is the radio transmit power in dBm.

### PROP 38: `PROP_PHY_RSSI` {#prop-phy-rssi}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: **REQUIRED**
* Value Type: INT8
* Unit: dBm (RF Power)
* Post-Reset Value: Unspecified

Value is the current RSSI (Received Signal Strength Indication) from the radio.
This value can be used in energy scans and for determining the ambient noise
floor for the operating environment.

Zero dBm represents one milliwatt of power.

Sampling ambient RSSI requires the radio to be actively receiving. If
`PROP_PHY_ENABLED` is false, getting this property fails with
`STATUS_INVALID_STATE`. A get may also fail with `STATUS_FAILURE` if the
radio cannot service the read (for example, mid-reconfiguration).

### PROP 39: `PROP_PHY_LORA_BW` {#prop-phy-lora-bw}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_PHY_LORA`
* Scope: NLI
* Value Type: UINT32_LE
* Units: Hz
* Post-Reset Value: Implementation-Specific

Value is the configured LoRa bandwidth.

### PROP 40: `PROP_PHY_LORA_SF` {#prop-phy-lora-sf}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_PHY_LORA`
* Scope: NLI
* Value Type: UINT8
* Post-Reset Value: Implementation-Specific

Value is the configured LoRa spreading factor.

### PROP 41: `PROP_PHY_LORA_CR` {#prop-phy-lora-cr}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_PHY_LORA`
* Scope: NLI
* Value Type: UINT8
* Post-Reset Value: Implementation-Specific

Value is the configured LoRa coding rate.

### PROP 42: `PROP_PHY_MTU` {#prop-phy-mtu}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: **REQUIRED**
* Scope: NLI
* Value Type: UINT16_LE
* Units: octets
* Post-Reset Value: Implementation-Specific

Maximum size of the `DATA` field that may be supplied to `STR_PHY_RAW`.

### PROP 43: `PROP_PHY_LORA_SW` {#prop-phy-lora-sw}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_PHY_LORA`
* Scope: NLI
* Value Type: UINT16
* Post-Reset Value: Implementation-Specific, but 0x1424 is a good suggestion.

Value is the 16-bit (SX126x-style) LoRa sync-word.

### STREAM 113: `STR_PHY_RAW` {#str-radio-raw}

* Type: Packet-Stream, Input/Output
* Required: **REQUIRED**
* Supported Commands: Send, Recv
* Scope: NLI
* Value Type: Structure

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   PACKET_LEN (Little endian)  | PACKET_DATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   PACKET_METADATA ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

This stream provides the capability of sending and receiving raw packets to and
from the radio.

The packet metadata is optional, but if present will be after the packet data
and will have the following format:

#### Metadata for Send

The `Send` metadata is the following fields in order:

* `TX_POWER` (`i8`): Transmit power override (`0x7F` indicates to use the radio
  default, `0x7E` indicates to transmit at maximum power)
* `TX_FLAGS` (`u8`): Transmit flags
  * `TX_FLAG_NOCCA` Bit 0: If set, do not use CCA (or the equivalent LoRa
    mechanism)
  * `TX_FLAG_NODUTY` Bit 1: If set, send the packet even if it would push us
    over the duty-cycle limit
  * All other bits: *RESERVED*

#### Metadata for Recv

The `Recv` metadata is the following fields in order:

* `RX_RSSI` (`u8`): This is the negative RSSI that this packet was received
  with. So if the RSSI was -91, the value of this field would be 91.
  * If `0xFF`, no RSSI is supported.
* `RX_LQI` (`u8`): This is the link-quality indicator, which is a metric of
  link quality between 1 and 255 with 1 being the worst possible quality that
  still decodes and 255 is perfect reception.
  * If `0x00`, LQI is not supported.
* `RX_SNR` (`i16`): Signal-to-noise ratio in centibels, or 1/10 of a decibel.
  * If `0x8000` (`i16::MIN`), SNR is not supported. This sentinel is chosen
    because it is `-3276.8 dB`, a value no real link can report, so it never
    collides with a genuine measurement (unlike `0xFFFF`, which is `-0.1 dB`).

### PROP 4820: `PROP_PHY_DUTY_NOW` {#prop-phy-duty-now}

* Type: Single-Value, Read-Only
* Value Type: `u16`
* Units: Percent, `0-65535 -> 0-100%`
* Post-Reset Value: 0%
* Required Capability: `CAP_PHY_DUTY_LIMIT`

The radio transmit duty cycle over the past hour, updated in 4-minute
intervals.

Under the hood, this is represented as 15 16-bit bins, one for each 4-minute
interval. An increment of 1 represents 5ms. For each 5ms of transmission time,
the current bin is incremented by 1. So a 20ms transmission would increment
the current bin by 4, but a 22ms transmission would increment the bin by 5. At
the transition between intervals, the new current bin is reset to zero.

To calculate the current duty cycle, all of the bins are added together,
multiplied by 65535, and then divided by 720000.

### PROP 4822: `PROP_PHY_DUTY_LIMIT` {#prop-phy-duty-limit}

* Type: Single-Value, Read-Write
* Value Type: `u16`
* Units: Percent, `0-65535 -> 0-100%`
* Post-Reset Value: Settings-dependent
* Required Capability: `CAP_PHY_DUTY_LIMIT`

The value for `PROP_PHY_DUTY_NOW` above which sending additional packets will
be prevented. Packets that are prevented from being sent will be dropped with
`STATUS_DUTY_LIMIT`.

Set to 0xFFFF to disable duty-cycle limiting. Note that `PROP_PHY_DUTY_NOW` will continue to be updated even if duty-cycle limiting is disabled.

Values for common duty cycles:

Value | Percentage
------|------------
13107 | 20%
6553  | 10%
655   | 1%
65    | 0.1%

## Status Codes

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
19 | `STATUS_DUTY_LIMIT`

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

`STATUS_NOMEM`
: The operation has been prevented due to memory pressure.

`STATUS_BUSY`
: The device is currently performing a mutually exclusive operation. This status
  differs from `STATUS_INVALID_STATE` in that it will resolve spontaneously.

`STATUS_PROP_NOT_FOUND`
: The given property key is not recognized.

`STATUS_CCA_FAILURE`
: The packet was not sent due to a CCA failure. This status code is only
  emitted when sending data to a packet stream with a TID other than zero.

`STATUS_DUTY_LIMIT`
: The packet cannot be sent because it would exceed the currently set
  duty-cycle limit.

## Reset Codes

All status codes which fall into the inclusive range of 112-127 are considered
*reset codes*. These codes are emitted asynchronously after an NCP reset and
provide a way to differentiate different causes of resets. If the first command
the host sends to the NCP after a reset is to fetch `PROP_LAST_STATUS`, then
the reset code **MUST** be returned.

Id  | Name
----|------------------------
112 | `STATUS_RESET_POWER_ON`
113 | `STATUS_RESET_EXTERNAL`
114 | `STATUS_RESET_SOFTWARE`
116 | `STATUS_RESET_CRASH`
117 | `STATUS_RESET_ASSERT`
118 | `STATUS_RESET_OTHER`
119 | `STATUS_RESET_UNKNOWN`
120 | `STATUS_RESET_WATCHDOG`

Of these defined reset codes, only `STATUS_RESET_POWER_ON`,
`STATUS_RESET_EXTERNAL`, and `STATUS_RESET_SOFTWARE` are emitted during normal
operation. All other reset codes generally indicate some sort of software bug
or hardware failure.

Unexpected or unrequested resets are always an indication of a problem, no
matter what the code value is.

`STATUS_RESET_POWER_ON`
: Cold power-on start.

`STATUS_RESET_EXTERNAL`
: External device reset. This is generally caused by RESET pin on the NCP being
  asserted.

`STATUS_RESET_SOFTWARE`
: Software-requested orderly reset. This is generally caused by the host
  sending the NCP `CMD_RST`.

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

Capabilities are how an NCP can advertise support for specific behaviors and
functionalities. They can be fetched via the `PROP_CAPS` property.

See (#prop-caps) for more information on `PROP_CAPS`.

Code | Name
-----|--------------------------
8    | `CAP_WRITABLE_RAW_STREAM`
16   | `CAP_PHY_DUTY_LIMIT`
515  | `CAP_PHY_LORA`
