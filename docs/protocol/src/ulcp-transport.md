# ULCP: Frame Transport

Frame transport is the data plane: the host transmits and receives raw,
complete UMSH frames through the device. Frames cross the link
untouched — the ULCP link carries UMSH frames, not re-encoded UMSH
semantics — so the host runs the entire UMSH MAC and the device moves
frames on its behalf.

One practical consequence is that a host can address the device's own
[device identity](ulcp-device.md#device-identity) with ordinary UMSH
frames over this stream, rather than needing a separate bespoke message
path for such traffic.

There is no outbound queueing. A transmit either happens or fails while
the host is attached to observe the result. Inbound frames may be queued
while no host is attached, which is a
[tethered host service](ulcp-host.md#inbound-queueing) rather than a
property of the stream.

## Capabilities

Code | Name                      | Grants
-----|---------------------------|--------
8    | `CAP_WRITABLE_RAW_STREAM` | `STR_PHY_RAW` accepts host-originated transmission through `CMD_STR_SEND`

Reception needs no capability, and `CMD_STR_SEND` support is required of
every device (see [Minimum Requirements](ulcp-conformance.md)). The
capability is an affirmative advertisement that transmission is
available, not a gate on the command.

## Commands

Id | Mnemonic       | Dir          | Description
---|----------------|--------------|-------------
9  | `CMD_STR_SEND` | Host->Device | Send data to a stream
10 | `CMD_STR_RECV` | Device->Host | Receive data from a stream

### CMD 9: (Host -> Device) `CMD_STR_SEND` {#cmd-str-send}

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

The device only attempts one confirmed transmit at a time. If a `CMD_STR_SEND`
with a non-zero TID arrives while another confirmed transmit is in progress,
the new command fails with `STATUS_BUSY`.

The device will never wait for duty-cycle allowance. If transmission would
exceed the currently configured duty-cycle limit and the `NODUTY` flag is not
set, the command fails immediately with `STATUS_DUTY_LIMIT`.

Commands sent with TID zero are fire-and-forget and do not receive a correlated
completion response.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

### CMD 10: (Device -> Host) `CMD_STR_RECV` {#cmd-str-recv}

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

## Streams

Id  | Mnemonic      | Commands   | Description
----|---------------|------------|-------------
113 | `STR_PHY_RAW` | Send, Recv | Raw radio frame stream

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
  default, `0x7E` indicates to transmit at maximum power). A power the radio
  cannot reach is clamped to its range, as for
  [`PROP_PHY_TX_POWER`](ulcp-radio.md#prop-phy-tx-power).
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

#### Extended Recv Metadata {#buffered-metadata}

The `Recv` metadata may carry two further trailing fields:

* `RX_FLAGS` (`u8`): Delivery flags
  * `RX_FLAG_BUFFERED` Bit 0: The frame was held in the inbound queue and
    is being delivered by `CMD_QUEUE_DRAIN`.
  * `RX_FLAG_ACKED` Bit 1: The device already transmitted a MAC ack for this
    frame on the host's behalf. The host **MUST NOT** send another ack for
    it.
  * `RX_FLAG_SELF_TX` Bit 2: The device transmitted this frame itself and
    is delivering a copy of it. `RX_RSSI` and `RX_SNR` **MUST** carry their
    unsupported sentinels: a transmitter measures nothing.
  * All other bits: *RESERVED*, transmitted as zero
* `RX_AGE` (`u32`, little-endian): Seconds elapsed between reception of the
  frame and its delivery to the host. Zero for live delivery.

As with the existing metadata fields, the metadata may be truncated at any
field boundary; absent fields are treated as zero. A live delivery with
nothing to flag MAY therefore omit these fields entirely, which keeps the
encoding byte-compatible with a device that does not queue at all.
