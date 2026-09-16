# ULCP: I2C Bus Access

A host drives the device's I2C peripherals directly: one transaction at
a time, addressed to a bus the device names and a peripheral the host
chooses, with the read data coming back in the reply. The device's own
drivers keep running; the host's transactions are interleaved with
theirs on the same bus.

This is a diagnostic and bring-up interface. What is on the bus, what a
register means, and what writing it does are the peripheral's business,
and the device passes none of that judgment along. A host that writes to
the charger has written to the charger.

Nothing here is state. The two properties are constant descriptions of
the hardware, neither command changes anything the device remembers,
and none of it is part of a [saved snapshot](ulcp-saved-state.md).

## Capabilities {#capabilities}

Code | Name      | Requires | Grants
-----|-----------|----------|--------
60   | `CAP_I2C` | —        | `PROP_I2C_BUSES`, `PROP_I2C_DEVICES`, `CMD_I2C_TRANSFER`, `CMD_I2C_SCAN`, `CMD_I2C_RESULT`

A device advertises `CAP_I2C` when it offers at least one bus. Without
it the two commands are `STATUS_UNIMPLEMENTED` and the two properties
`STATUS_PROP_NOT_FOUND`, as for any capability the device lacks.

## Properties {#properties}

Identifiers 4960 through 4975 are allocated to this subsystem.

### PROP 4960: `PROP_I2C_BUSES` {#prop-i2c-buses}

* Type: Multiple-Value, Constant
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_I2C`
* Item Form: structure below
* Post-Reset Value: Unchanged

The buses a host may drive. Each item:

~~~
+-----+-----------+----------+---------+------------+
| BUS | SPEED_KHZ | MAX_DATA | MAX_OPS |  NAME ...  |
+-----+-----------+----------+---------+------------+
  1 B     2 B         2 B       1 B      remainder
~~~
Figure: Bus item format

**BUS** is the number `CMD_I2C_TRANSFER` and `CMD_I2C_SCAN` name the bus
by. **SPEED_KHZ** (UINT16, little-endian) is the clock the device drives
it at. **MAX_DATA** (UINT16, little-endian) is the largest sum of octets
written and octets read the device accepts in one transfer; **MAX_OPS**
is the largest operation count. **NAME** is UTF-8 display text naming the
controller and its pins, such as `I2C0 SDA GPIO3 SCL GPIO2`, and is at
most 64 octets.

### PROP 4961: `PROP_I2C_DEVICES` {#prop-i2c-devices}

* Type: Multiple-Value, Constant
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_I2C`
* Item Form: structure below
* Post-Reset Value: Unchanged

The peripherals the device's own firmware knows to be on its buses. Each
item:

~~~
+-----+------+------------+
| BUS | ADDR |  NAME ...  |
+-----+------+------------+
  1 B   1 B    remainder
~~~
Figure: Peripheral item format

**BUS** is a bus from `PROP_I2C_BUSES`, **ADDR** the peripheral's 7-bit
address, and **NAME** UTF-8 display text naming the part, at most 64
octets. This is what the firmware was built knowing, not what a scan
found: a host uses it to annotate a scan and to recognize an address
whose peripheral the device depends on before writing to it. A device
with `CAP_I2C` and no such knowledge reports an empty table.

A `CMD_PROP_SET`, `CMD_PROP_INSERT`, or `CMD_PROP_REMOVE` of either
property is `STATUS_INVALID_ARGUMENT`.

## Commands {#commands}

### CMD 25: (Host -> Device) `CMD_I2C_TRANSFER` {#cmd-i2c-transfer}

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_I2C_TRANSFER|      BUS      |      ADDR     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      OP ...
+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_I2C_TRANSFER`

One I2C transaction with the peripheral at 7-bit address `ADDR` on bus
`BUS`. The payload after the address is a sequence of one or more
operations:

~~~
+------+-------+----------------------+
| KIND |  LEN  |  DATA (write only)   |
+------+-------+----------------------+
  1 B    PUI       LEN octets
~~~
Figure: Transfer operation format

**KIND** is 0 for a write and 1 for a read. **LEN** is the number of
octets the operation moves: a write carries them in **DATA**; a read
carries nothing and the octets come back in the reply.

The transaction is performed as one bus sequence: START, the address,
the operations in order, and one STOP. A change of direction between
consecutive operations is a repeated START with the address resent;
consecutive operations of the same direction continue without one, so
a write followed by a write is one longer write on the wire, and a read
followed by a read is one longer read. This is the transaction model of
common HAL interfaces, and a register read is a write of the register
address followed by a read.

Only 7-bit addressing is defined. The reserved address ranges
(0x00–0x07 and 0x78–0x7F) are not policed: what a general call or a
device-ID probe does is the host's affair.

On success the device answers with [`CMD_I2C_RESULT`](#cmd-i2c-result)
carrying the command's TID, whose payload is the read data of every
read operation, concatenated in operation order. A transfer with no
read operation is answered with an empty `CMD_I2C_RESULT`.

Failures are reported through `PROP_LAST_STATUS` with the command's TID:

Condition | Status
----------|--------
The payload is truncated or does not parse as the structure above | `STATUS_PARSE_ERROR`
`ADDR` exceeds 0x7F; an unknown `KIND`; an operation with `LEN` zero; no operations; more octets than `MAX_DATA`; more operations than `MAX_OPS` | `STATUS_INVALID_ARGUMENT`
`BUS` is not an item of `PROP_I2C_BUSES` | `STATUS_ITEM_NOT_FOUND`
The `CMD_I2C_RESULT` would not fit the binding's reply | `STATUS_NOMEM`
The bus is not operable now (its rail is off) | `STATUS_INVALID_STATE`
The bus could not be acquired within the device's bound, or the peripheral is held by one of the device's own procedures ([Sharing the Bus](#sharing-the-bus)) | `STATUS_BUSY`
No peripheral acknowledged `ADDR` | `STATUS_NO_DEVICE`
The peripheral did not acknowledge a data octet | `STATUS_NACK`
The bus itself failed: arbitration lost, a bus error, a stuck line, or the transaction outlasting the device's deadline | `STATUS_BUS_ERROR`
The device lacks `CAP_I2C` | `STATUS_UNIMPLEMENTED`

Everything above the bus—parsing, the limits, the bus number, and
whether the reply could be carried—is checked before the bus is
touched, so a refused request has done nothing. A failure on the bus
carries no partial read data, but operations before the failing one
have already acted on the wire: a `STATUS_NACK` on the third operation
means the first two completed.

A device performs the whole transaction under a deadline of its own
choosing, and a transaction that does not complete within it is
`STATUS_BUS_ERROR`, after which the device **MAY** attempt bus recovery.
A zero-length operation is refused rather than performed because a
bare address frame is a probe, which is what
[`CMD_I2C_SCAN`](#cmd-i2c-scan) is for.

### CMD 27: (Host -> Device) `CMD_I2C_SCAN` {#cmd-i2c-scan}

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |  CMD_I2C_SCAN |      BUS      |     FIRST     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     LAST      |
+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_I2C_SCAN`

Probe every 7-bit address from `FIRST` through `LAST` inclusive on bus
`BUS` and report which acknowledged. `FIRST` and `LAST` are optional
together; absent, the range is 0x08 through 0x77, the addresses outside
the reserved ranges. `FIRST` greater than `LAST`, or `LAST` greater
than 0x7F, is `STATUS_INVALID_ARGUMENT`; a payload of any other length
is `STATUS_PARSE_ERROR`.

Each probe is a one-octet read, or a bare address frame on a controller
that can send one. A probe is never a write. The reply is a
[`CMD_I2C_RESULT`](#cmd-i2c-result) carrying the command's TID, whose
payload is the acknowledged addresses in ascending order, one octet
each; nothing acknowledged is an empty payload.

A scan is a hint, not an inventory. A peripheral that does not
acknowledge reads goes unreported, and on some peripherals a one-octet
read is a real read: it can pop a FIFO or clear a latched flag. The
bus, bus-number, and reply-size refusals are as for `CMD_I2C_TRANSFER`,
with `STATUS_NOMEM` judged against the whole range; a bus failure
during the scan is `STATUS_BUS_ERROR` with no partial list.

### CMD 26: (Device -> Host) `CMD_I2C_RESULT` {#cmd-i2c-result}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+
|1 0| RES | TID | CMD_I2C_RESULT|   DATA ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+
~~~
Figure: Structure of `CMD_I2C_RESULT`

The successful answer to `CMD_I2C_TRANSFER` or `CMD_I2C_SCAN`, carrying
the request's TID. `DATA` is what the request defines: concatenated
read data for a transfer, acknowledged addresses for a scan. It is
never sent unsolicited, and a `CMD_I2C_RESULT` received by a device is
`STATUS_INVALID_COMMAND` like any other Device→Host command.

A `CMD_I2C_RESULT` is one frame and is never continued: a device
refuses, with `STATUS_NOMEM` before touching the bus, any request whose
result would not fit the reply its binding can carry. On a local
binding that bound is the frame size; on the Node Management binding
it is the payload budget described [below](#over-node-management).

## Sharing the Bus {#sharing-the-bus}

The device serializes transactions, not procedures. Its own drivers
keep using the bus between a host's commands, and separate commands
form no exclusive session, so a host procedure of several steps—an
unseal, a read, a reseal—can be interleaved with the device's own
traffic to the same peripheral. A host that needs a sequence performed
without interleaving puts it in one `CMD_I2C_TRANSFER`, which is what
the operation list is for.

The same holds in the other direction, and a device **MAY** protect its
own multi-transaction procedures: while one runs, a transfer addressed
to the peripheral it holds, or a scan whose range covers that address,
is `STATUS_BUSY`. The refusal covers the whole scan rather than
silently omitting the address, so the host is told to try again instead
of being handed a wrong inventory. A device **MUST NOT** hold the bus
against its own drivers for the duration of a host's procedure; the
host retries `STATUS_BUSY` after a moment.

A device bounds how long a transfer waits for the bus, and a wait that
exceeds the bound is `STATUS_BUSY`. The bound is the device's; a host
allows for a transaction to take longer to answer than a property read.

## Over the Node Management Binding {#over-node-management}

Both commands are available to a listed administrator over the
[Node Management](app-node-management.md) binding, reads and writes
alike, and `CMD_I2C_RESULT` is one of the frames a Response carries.

The Response is one payload with no continuation, so the reply budget
is what remains of a [payload](app-node-management.md#exchanges) after
the envelope: a transfer whose reads, or a scan whose range, would
exceed it is `STATUS_NOMEM`. An administrator reads in pieces; the
budget is well over a hundred octets, and a peripheral's register file
rarely needs more at once.

The binding answers a retransmitted request from its retained response
rather than executing it again, for as long as that entry exists.
Entries can be evicted and do not survive a reset of the device. Two
consequences follow for writes. A write whose effect resets the node—a
power-management register, say—is never confirmed, because the node
that would confirm it is gone. And a write whose Response was lost
leaves the administrator unable to tell whether it acted: a
retransmission is answered from the retained entry if it still exists,
and executed afresh if it does not. An administrator that must know
reads the register back rather than retransmitting the write, and
treats a write to a register that can reset the node as one-shot.

## Security Considerations {#i2c-security}

This is raw register access to whatever is on the bus: on a typical
board the charger, the power-management IC, the gauge, the real-time
clock, and the sensors. A host can misconfigure the charger, cut a
rail, or corrupt a gauge's learned state, and the device does not
stand in the way.

On a local binding the host already has the device in hand. Over Node
Management the same access is granted to every listed administrator,
who can already factory-reset the node and rewrite its identity; the
bus adds the ability to damage the hardware's configuration rather than
just the node's. An operator lists administrators accordingly.
`PROP_I2C_DEVICES` tells a host which addresses the device itself
depends on; a host tool warns before writing to one of them.
