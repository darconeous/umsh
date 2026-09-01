# ULCP: Radio Control

Radio control is the subsystem the host uses to configure and observe the
physical transceiver: frequency, modulation, transmit power, and the
transmit duty-cycle budget. Every ULCP device implements it.

The interface is deliberately not LoRa-specific in shape where that can be
avoided. The properties that any radio has — enable, frequency, transmit
power, RSSI, MTU — are unconditional; the LoRa modulation parameters are
gated behind `CAP_PHY_LORA`, and duty-cycle accounting behind
`CAP_PHY_DUTY_LIMIT`. Traffic counters are exposed by `CAP_STATS`.

The RF configuration is [device-domain](ulcp-core.md#device-domain) state:
it belongs to the radio rather than to whichever host is attached, it is
part of a [saved snapshot](ulcp-saved-state.md#saved-state), and it
survives a change of host.

## Capabilities

Code | Name                 | Grants
-----|----------------------|--------
16   | `CAP_PHY_DUTY_LIMIT` | Duty-cycle accounting and enforcement: `PROP_PHY_DUTY_NOW`, `PROP_PHY_DUTY_LIMIT`, and `STATUS_DUTY_LIMIT`
52   | `CAP_STATS`          | Radio and forwarding traffic counters: `PROP_STAT_*`
515  | `CAP_PHY_LORA`       | The LoRa modulation parameters: `PROP_PHY_LORA_BW`, `PROP_PHY_LORA_SF`, `PROP_PHY_LORA_CR`, `PROP_PHY_LORA_SW`

## Properties

Id   | Mnemonic              | Commands | Description
-----|-----------------------|----------|-------------
32   | `PROP_PHY_ENABLED`    | Get, Set | PHY enabled
35   | `PROP_PHY_FREQ`       | Get, Set | Frequency in kHz
37   | `PROP_PHY_TX_POWER`   | Get, Set | TX power in dBm
38   | `PROP_PHY_RSSI`       | Get      | Current RSSI
39   | `PROP_PHY_LORA_BW`    | Get, Set | LoRa bandwidth
40   | `PROP_PHY_LORA_SF`    | Get, Set | LoRa spreading factor
41   | `PROP_PHY_LORA_CR`    | Get, Set | LoRa coding rate
42   | `PROP_PHY_MTU`        | Get      | Max size of a frame
43   | `PROP_PHY_LORA_SW`    | Get, Set | LoRa sync word (16-bit style)
4820 | `PROP_PHY_DUTY_NOW`   | Get      | Current duty usage
4822 | `PROP_PHY_DUTY_LIMIT` | Get, Set | Duty-cycle limit
4832 | `PROP_STAT_TX_PACKETS` | Get, Set | Packets transmitted over the air
4833 | `PROP_STAT_TX_CHANNEL_BUSY` | Get, Set | Transmissions deferred because the channel was busy
4834 | `PROP_STAT_RX_PACKETS` | Get, Set | Received packets with a UMSH first-octet pattern
4835 | `PROP_STAT_RX_BAD_CRC` | Get, Set | Receptions rejected because of a bad CRC
4836 | `PROP_STAT_RX_NON_UMSH` | Get, Set | Received packets without a UMSH first-octet pattern
4837 | `PROP_STAT_RX_ACCEPTED` | Get, Set | Received packets accepted by this device's node
4838 | `PROP_STAT_FORWARDED` | Get, Set | Packets this device chose to forward
4839 | `PROP_STAT_FORWARD_DROPPED` | Get, Set | Forwarding candidates rejected by policy
4840 | `PROP_STAT_FORWARD_CANCELLED` | Get, Set | Queued forwards cancelled after an acknowledgement

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

A device **MUST** clamp a written value to the range its radio can reach
rather than rejecting it, and the emitted `CMD_PROP_IS` carries the
clamped value. Nothing else publishes that range, so this is how a host
discovers it: a host that needs to know what a device will actually
transmit at reads the value it gets back rather than the one it wrote.

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

## Statistics

A device advertising `CAP_STATS` exposes cumulative `UINT32_LE` traffic
counters. Values count since boot or the most recent reset of that counter and
wrap modulo 2^32. Writing four zero octets resets a counter. A device **MUST**
reject every other value or length with `STATUS_INVALID_ARGUMENT`.

Statistics are live hardware history rather than configuration. They are not
part of a saved snapshot, and `CMD_RST` **MUST NOT** clear them. A host can reset
several counters with `CMD_PROP_MULTI_SET`, but the individual resets do not
occur simultaneously: traffic arriving during the write sweep can fall on
different sides of different counter resets.

`PROP_PHY_DUTY_NOW` is commonly displayed alongside these counters, but it is a
rolling regulatory measurement and is not resettable.

### PROP 4832: `PROP_STAT_TX_PACKETS` {#prop-stat-tx-packets}

Packets whose transmission completed successfully over the physical radio.
Requires `CAP_STATS`.

### PROP 4833: `PROP_STAT_TX_CHANNEL_BUSY` {#prop-stat-tx-channel-busy}

Transmission attempts deferred because channel assessment reported the channel
busy. Such an attempt does not also increment `PROP_STAT_TX_PACKETS`. Requires
`CAP_STATS`.

### PROP 4834: `PROP_STAT_RX_PACKETS` {#prop-stat-rx-packets}

Off-air receptions whose first octet carries the UMSH version and valid reserved
bits. This classification does not require the rest of the packet to parse.
Requires `CAP_STATS`.

### PROP 4835: `PROP_STAT_RX_BAD_CRC` {#prop-stat-rx-bad-crc}

Receptions the physical radio rejected because their payload CRC was invalid.
Requires `CAP_STATS`.

### PROP 4836: `PROP_STAT_RX_NON_UMSH` {#prop-stat-rx-non-umsh}

Off-air receptions whose first octet does not carry the UMSH version and valid
reserved bits. Requires `CAP_STATS`.

### PROP 4837: `PROP_STAT_RX_ACCEPTED` {#prop-stat-rx-accepted}

Receptions on which this device's own node acted. Frames addressed to an
attached host's identity are not included. Requires `CAP_STATS` and
`CAP_REPEATER`.

### PROP 4838: `PROP_STAT_FORWARDED` {#prop-stat-forwarded}

Receptions this device's own node chose to repeat. The counter records the
forwarding decision; successful physical transmissions are counted separately
by `PROP_STAT_TX_PACKETS`. Requires `CAP_STATS` and `CAP_REPEATER`.

### PROP 4839: `PROP_STAT_FORWARD_DROPPED` {#prop-stat-forward-dropped}

Packets that were eligible for forwarding but were rejected by the configured
flood budget, minimum RSSI, minimum SNR, or region policy. Duplicates,
self-addressed packets, and packets received while forwarding is disabled are
not included. Requires `CAP_STATS` and `CAP_REPEATER`.

### PROP 4840: `PROP_STAT_FORWARD_CANCELLED` {#prop-stat-forward-cancelled}

Queued forwards cancelled because the destination's acknowledgement was
overheard before transmission. Requires `CAP_STATS` and `CAP_REPEATER`.
