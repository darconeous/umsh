# ULCP: Minimum Requirements

This chapter is the conformance statement for ULCP. A device that meets
the requirements below is a ULCP device; everything past them is optional
and is discovered through `PROP_CAPS`.

There are no protocol levels, tiers, or profiles. A host that wants a
plain frame pipe and a host that wants a fully provisioned companion
radio speak the same protocol to the same devices and differ only in
which capabilities they look for. A device implements the subsystems its
hardware and purpose call for and advertises exactly those.

## Framing

A device **MUST** implement the [frame format](ulcp-core.md#frame-format)
in full: the header with its `FLG`, `RESERVED`, and `TID` fields, the
[packed unsigned integer](ulcp-core.md#packed-unsigned-integer) encoding
for command, property, and stream identifiers, and the transport's
framing (HDLC-Lite on serial links, the
[GATT frame transport](ulcp-ble.md#gatt-frame-transport) over BLE).

The TID discipline is normative in both directions: a device **MUST NOT**
send a frame with a non-zero TID that is not a response to a frame it
recently received with that TID, and all unsolicited commands **MUST**
use TID zero.

## Commands

Id | Mnemonic       | Required
---|----------------|----------
0  | `CMD_NOP`      | Always
1  | `CMD_RST`      | Always
2  | `CMD_PROP_GET` | Always
3  | `CMD_PROP_SET` | Always
6  | `CMD_PROP_IS`  | Always
9  | `CMD_STR_SEND` | Always
10 | `CMD_STR_RECV` | Always

`CMD_PROP_INSERT`, `CMD_PROP_REMOVE`, and their notifications belong to
the base grammar rather than to any capability. A device that defines no
mutable [multi-value property](ulcp-core.md#multi-value-properties) has
nothing to apply them to and rejects them under the ordinary property
rules. `CMD_QUEUE_DRAIN`, `CMD_SAVE`, and `CMD_RESTORE` belong to their
subsystems' capabilities and **MUST** fail with `STATUS_UNIMPLEMENTED`
when the capability is not advertised, as **MUST**
[`CMD_REBOOT`](ulcp-core.md#cmd-reboot) without `CAP_REBOOT` and
[`CMD_BLE_CLEAR_BONDS`](ulcp-ble.md#cmd-ble-clear-bonds) and
[`CMD_BLE_START_PAIRING`](ulcp-ble.md#cmd-ble-start-pairing) on a device
that does not manage its own bonds; `CMD_CLEAR` and `CMD_FACTORY_RESET`
are available
regardless of capabilities (see [Saved State](ulcp-saved-state.md)).

## Properties

Id  | Mnemonic                | Required
----|-------------------------|----------
0   | `PROP_LAST_STATUS`      | Always
1   | `PROP_PROTOCOL_VERSION` | Always
2   | `PROP_DEV_VERSION`      | Always
3   | `PROP_INTERFACE_TYPE`   | Always
5   | `PROP_CAPS`             | Always
32  | `PROP_PHY_ENABLED`      | Always, `Get` and `Set`
35  | `PROP_PHY_FREQ`         | Always
37  | `PROP_PHY_TX_POWER`     | Always
38  | `PROP_PHY_RSSI`         | Always
42  | `PROP_PHY_MTU`          | Always
113 | `STR_PHY_RAW`           | Always

`PROP_DEV_MODEL` (4) and `PROP_UPTIME` (6) are the two properties that are
neither always required nor capability-gated. Firmware built for a specific
board **SHOULD** implement the first, and a device with a monotonic clock
**SHOULD** implement the second; anything else omits them. A host discovers
both by asking.

Every other property is gated by a capability. A device that does not
advertise the capability does not implement the property, and rejects it
with `STATUS_PROP_NOT_FOUND` or `STATUS_UNIMPLEMENTED`.

## Status and Reset Reporting

A device **MUST** implement `PROP_LAST_STATUS` as the failure channel for
every command, using the most specific applicable
[status code](ulcp-core.md#status-codes), and **MUST** emit a
[reset code](ulcp-core.md#reset-codes) asynchronously after every reset.
A device that cannot determine the cause reports
`STATUS_RESET_UNKNOWN` rather than omitting the notification.

## Optional Subsystems

Everything else in this specification is a capability. Each grants the
commands and properties defined in its chapter, and a device **MUST NOT**
advertise a capability without also advertising the capabilities it
requires.

Subsystem | Capabilities
---|---
[Radio Control](ulcp-radio.md) beyond the required properties | `CAP_PHY_LORA`, `CAP_PHY_DUTY_LIMIT`
[Device Domain](ulcp-device.md) | `CAP_DEV_IDENTITY`, `CAP_DEV_NAME`, `CAP_BATTERY`, `CAP_REPEATER`, `CAP_IDENT`, `CAP_ALERT`, `CAP_TIME`, `CAP_GNSS`, `CAP_ADVERT`, `CAP_ILLUMINANCE`
[Saved State](ulcp-saved-state.md) | `CAP_SAVE`
[Tethered Host Services](ulcp-host.md) | `CAP_HOST_FILTER`, `CAP_HOST_KEYS`, `CAP_HOST_RX_QUEUE`, `CAP_HOST_AUTO_ACK`, `CAP_MAC_BACKHAUL`

A device advertising none of them is a transparent radio: it configures
its PHY, transmits what it is given, and delivers everything it hears.

## Requirements on Hosts

A conforming host:

* **MUST** tolerate unsolicited `CMD_PROP_IS`, `CMD_PROP_INSERTED`, and
  `CMD_PROP_REMOVED` notifications at any time while attached, and update
  its view of the affected property accordingly. Device state changes for
  reasons the host did not initiate, and publication of the new
  authoritative value is how the protocol reports it.
* **MUST** take the value in a `CMD_PROP_IS` as the property's value, and
  **MUST NOT** treat one that differs from what it wrote as an error. A
  write is refused by a `PROP_LAST_STATUS` carrying the failure and by
  nothing else; anything a device reports as a property value is what that
  property is, whether or not it is what was asked for — see
  [`PROP_PHY_TX_POWER`](ulcp-radio.md#prop-phy-tx-power), which a device
  clamps to what its radio can reach. A host that shows the value to a user
  shows the reported one.
* **MUST NOT** treat a failed capability-gated property read as a failed
  attach. A device advertising a capability implements its properties, so
  a refusal is a device fault — but what is unknown is the setting, not the
  device. A host finishes the rest of the read, presents the affected
  setting as unavailable rather than as a default, and omits it from what
  it writes.
* **MUST NOT** assume that a reset implies documented factory defaults. On
  a device holding a [saved snapshot](ulcp-saved-state.md#saved-state) the
  post-reset value of every saved property is its saved value; a host
  fetches or explicitly sets what it depends on.
* **MUST** establish its complete [host domain](ulcp-core.md#host-domain)
  on every tethered attach, if it uses host services at all, rather than
  reasoning about what the device already holds.
* **MUST NOT** write host-domain properties when it is merely
  administering a device rather than being that device's host — see
  [Two Kinds of Attach](ulcp.md#attach-relationships).
* **SHOULD** follow the post-attach procedure in
  [Attach, Detach, and Synchronization](ulcp-core.md#attach-sync).

## Deployment Shapes

The capability sets that correspond to the familiar deployments, as a
reader's aid rather than a normative classification:

Deployment | Typical capabilities
---|---
Transparent radio | `CAP_WRITABLE_RAW_STREAM`, `CAP_PHY_LORA`, `CAP_PHY_DUTY_LIMIT`
Companion radio | The above, plus `CAP_HOST_FILTER`, `CAP_HOST_KEYS`, `CAP_HOST_RX_QUEUE`, `CAP_HOST_AUTO_ACK`
Commissioned repeater | The above, plus `CAP_DEV_IDENTITY`, `CAP_SAVE`, `CAP_REPEATER`, `CAP_IDENT`

The same firmware ordinarily advertises all of them: which deployment a
device is doing is a matter of what its operator provisioned, not of what
it can do.
