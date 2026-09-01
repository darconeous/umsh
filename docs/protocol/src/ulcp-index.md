# ULCP: Command and Property Index

Every numeric identifier the protocol defines, and where it is specified.

## Commands

Id | Mnemonic                                                     | Dir          | Gated by
---|--------------------------------------------------------------|--------------|----------
0  | [`CMD_NOP`](ulcp-core.md#cmd-noop)                           | Host->Device | —
1  | [`CMD_RST`](ulcp-core.md#cmd-reset)                          | Host->Device | —
2  | [`CMD_PROP_GET`](ulcp-core.md#cmd-prop-get)                  | Host->Device | —
3  | [`CMD_PROP_SET`](ulcp-core.md#cmd-prop-set)                  | Host->Device | —
4  | [`CMD_PROP_INSERT`](ulcp-core.md#cmd-prop-insert)            | Host->Device | —
5  | [`CMD_PROP_REMOVE`](ulcp-core.md#cmd-prop-remove)            | Host->Device | —
6  | [`CMD_PROP_IS`](ulcp-core.md#cmd-prop-is)                    | Device->Host | —
7  | [`CMD_PROP_INSERTED`](ulcp-core.md#cmd-prop-inserted)        | Device->Host | —
8  | [`CMD_PROP_REMOVED`](ulcp-core.md#cmd-prop-removed)          | Device->Host | —
9  | [`CMD_STR_SEND`](ulcp-transport.md#cmd-str-send)             | Host->Device | —
10 | [`CMD_STR_RECV`](ulcp-transport.md#cmd-str-recv)             | Device->Host | —
11 | [`CMD_QUEUE_DRAIN`](ulcp-host.md#cmd-queue-drain)            | Host->Device | `CAP_HOST_RX_QUEUE`
12 | [`CMD_SAVE`](ulcp-saved-state.md#cmd-save)                   | Host->Device | `CAP_SAVE`
13 | [`CMD_CLEAR`](ulcp-saved-state.md#cmd-clear)                 | Host->Device | —
14 | [`CMD_RESTORE`](ulcp-saved-state.md#cmd-restore)             | Host->Device | `CAP_SAVE`
15 | [`CMD_FACTORY_RESET`](ulcp-saved-state.md#cmd-factory-reset) | Host->Device | —
16 | [`CMD_REBOOT`](ulcp-core.md#cmd-reboot)                      | Host->Device | `CAP_REBOOT`
21 | [`CMD_PROP_MULTI_GET`](ulcp-core.md#cmd-prop-multi-get)      | Host->Device | `CAP_CMD_MULTI`
22 | [`CMD_PROP_MULTI_SET`](ulcp-core.md#cmd-prop-multi-set)      | Host->Device | `CAP_CMD_MULTI`
23 | [`CMD_PROP_ARE`](ulcp-core.md#cmd-prop-are)                  | Device->Host | `CAP_CMD_MULTI`
24 | [`CMD_SESSION_RESET`](ulcp-core.md#cmd-session-reset)        | Device->Host | —

Command identifiers are 7-bit; 17–20 and 25–127 are unassigned.

## Properties and Streams

Identifiers are allocated by state class; see
[Property Allocation](ulcp-core.md#property-allocation).

Id   | Mnemonic                                                                   | Commands                 | Gated by
-----|----------------------------------------------------------------------------|--------------------------|----------
0    | [`PROP_LAST_STATUS`](ulcp-core.md#prop-last-status)                        | Get, Is                  | —
1    | [`PROP_PROTOCOL_VERSION`](ulcp-core.md#prop-protocol-version)              | Get                      | —
2    | [`PROP_DEV_VERSION`](ulcp-core.md#prop-dev-version)                        | Get                      | —
3    | [`PROP_INTERFACE_TYPE`](ulcp-core.md#prop-interface-type)                  | Get                      | —
4    | [`PROP_DEV_MODEL`](ulcp-core.md#prop-dev-model)                            | Get                      | —
5    | [`PROP_CAPS`](ulcp-core.md#prop-caps)                                      | Get                      | —
6    | [`PROP_UPTIME`](ulcp-core.md#prop-uptime)                                  | Get                      | —
32   | [`PROP_PHY_ENABLED`](ulcp-radio.md#prop-phy-enabled)                       | Get, Set                 | —
35   | [`PROP_PHY_FREQ`](ulcp-radio.md#prop-phy-freq)                             | Get, Set                 | —
37   | [`PROP_PHY_TX_POWER`](ulcp-radio.md#prop-phy-tx-power)                     | Get, Set                 | —
38   | [`PROP_PHY_RSSI`](ulcp-radio.md#prop-phy-rssi)                             | Get                      | —
39   | [`PROP_PHY_LORA_BW`](ulcp-radio.md#prop-phy-lora-bw)                       | Get, Set                 | `CAP_PHY_LORA`
40   | [`PROP_PHY_LORA_SF`](ulcp-radio.md#prop-phy-lora-sf)                       | Get, Set                 | `CAP_PHY_LORA`
41   | [`PROP_PHY_LORA_CR`](ulcp-radio.md#prop-phy-lora-cr)                       | Get, Set                 | `CAP_PHY_LORA`
42   | [`PROP_PHY_MTU`](ulcp-radio.md#prop-phy-mtu)                               | Get                      | —
43   | [`PROP_PHY_LORA_SW`](ulcp-radio.md#prop-phy-lora-sw)                       | Get, Set                 | `CAP_PHY_LORA`
48   | [`PROP_MAC_PROMISCUOUS`](ulcp-host.md#prop-mac-promiscuous)                | Get, Set                 | `CAP_HOST_FILTER`
49   | [`PROP_SAVED`](ulcp-saved-state.md#prop-saved)                             | Get                      | `CAP_SAVE`
50   | [`PROP_MAC_BACKHAUL`](ulcp-host.md#prop-mac-backhaul)                      | Get, Set                 | `CAP_MAC_BACKHAUL`
64   | [`PROP_DEV_KEY`](ulcp-device.md#prop-dev-key)                              | Get                      | `CAP_DEV_IDENTITY`
65   | [`PROP_DEV_PRIVATE_KEY`](ulcp-device.md#prop-dev-private-key)              | Set                      | `CAP_DEV_IDENTITY`
66   | [`PROP_DEV_CHANNEL_KEYS`](ulcp-device.md#prop-dev-channel-keys)            | Get, Set, Insert, Remove | `CAP_DEV_IDENTITY`
67   | [`PROP_DEV_PEERS`](ulcp-device.md#prop-dev-peers)                          | Get, Set, Insert, Remove | `CAP_DEV_IDENTITY`
68   | [`PROP_DEV_NAME`](ulcp-device.md#prop-dev-name)                            | Get, Set                 | `CAP_DEV_NAME`
69   | [`PROP_BATTERY`](ulcp-device.md#prop-battery)                              | Get, Is                  | `CAP_BATTERY`
70   | [`PROP_MAC_REPEATER_ENABLED`](ulcp-device.md#prop-mac-repeater-enabled)    | Get, Set                 | `CAP_REPEATER`
71   | [`PROP_IDENT`](ulcp-device.md#prop-ident)                                  | Get                      | `CAP_IDENT`
72   | [`PROP_IDENT_ROLE`](ulcp-device.md#prop-ident-role)                        | Get, Set                 | `CAP_IDENT`
73   | [`PROP_IDENT_MOBILE`](ulcp-device.md#prop-ident-mobile)                    | Get, Set                 | `CAP_IDENT`
74   | [`PROP_MAC_REPEATER_REGIONS`](ulcp-device.md#prop-mac-repeater-regions)    | Get, Set                 | `CAP_REPEATER`
75   | [`PROP_MAC_REPEATER_DEFAULT_REGION`](ulcp-device.md#prop-mac-repeater-default-region) | Get, Set      | `CAP_REPEATER`
76   | [`PROP_MAC_REPEATER_MIN_RSSI`](ulcp-device.md#prop-mac-repeater-min-rssi)  | Get, Set                 | `CAP_REPEATER`
77   | [`PROP_MAC_REPEATER_MIN_SNR`](ulcp-device.md#prop-mac-repeater-min-snr)    | Get, Set                 | `CAP_REPEATER`
78   | [`PROP_DEV_DISCOVERABLE`](ulcp-device.md#prop-dev-discoverable)            | Get, Set                 | `CAP_DEV_IDENTITY`
79   | [`PROP_ALERT`](ulcp-device.md#prop-alert)                                  | Get, Set, Is             | `CAP_ALERT`
80   | [`PROP_ADVERT_INTERVAL`](ulcp-device.md#prop-advert-interval)              | Get, Set                 | `CAP_ADVERT`
81   | [`PROP_BEACON_INTERVAL`](ulcp-device.md#prop-beacon-interval)              | Get, Set                 | `CAP_ADVERT`
82   | [`PROP_STARTUP_BEACON`](ulcp-device.md#prop-startup-beacon)                | Get, Set                 | `CAP_ADVERT`
83   | [`PROP_IDENT_LOCATION`](ulcp-device.md#prop-ident-location)                | Get, Set                 | `CAP_IDENT`
84   | [`PROP_IDENT_ALTITUDE`](ulcp-device.md#prop-ident-altitude)                | Get, Set                 | `CAP_IDENT`
88   | [`PROP_GNSS_ENABLED`](ulcp-device.md#prop-gnss-enabled)                    | Get, Set                 | `CAP_GNSS`
89   | [`PROP_GNSS_LOCATION`](ulcp-device.md#prop-gnss-location)                  | Get, Is                  | `CAP_GNSS`
90   | [`PROP_GNSS_ALTITUDE`](ulcp-device.md#prop-gnss-altitude)                  | Get                      | `CAP_GNSS`
91   | [`PROP_GNSS_FIX`](ulcp-device.md#prop-gnss-fix)                            | Get, Is                  | `CAP_GNSS`
92   | [`PROP_GNSS_PRECISION`](ulcp-device.md#prop-gnss-precision)                | Get                      | `CAP_GNSS`
93   | [`PROP_GNSS_SATELLITES`](ulcp-device.md#prop-gnss-satellites)              | Get                      | `CAP_GNSS`
94   | [`PROP_ILLUMINANCE`](ulcp-device.md#prop-illuminance)                      | Get                      | `CAP_ILLUMINANCE`
96   | [`PROP_HOST_KEY`](ulcp-host.md#prop-host-key)                              | Get, Set                 | `CAP_HOST_FILTER`
97   | [`PROP_HOST_CHANNEL_KEYS`](ulcp-host.md#prop-host-channel-keys)            | Get, Set, Insert, Remove | `CAP_HOST_KEYS`
98   | [`PROP_HOST_PEER_KEYS`](ulcp-host.md#prop-host-peer-keys)                  | Get, Set, Insert, Remove | `CAP_HOST_KEYS`
99   | [`PROP_HOST_RX_FILTERS`](ulcp-host.md#prop-host-rx-filters)                | Get, Set, Insert, Remove | `CAP_HOST_FILTER`
100  | [`PROP_HOST_AUTO_ACK`](ulcp-host.md#prop-host-auto-ack)                    | Get, Set                 | `CAP_HOST_AUTO_ACK`
101  | [`PROP_HOST_RX_QUEUE_COUNT`](ulcp-host.md#prop-host-rx-queue-count)        | Get                      | `CAP_HOST_RX_QUEUE`
102  | [`PROP_HOST_RX_QUEUE_CAPACITY`](ulcp-host.md#prop-host-rx-queue-capacity)  | Get, Set                 | `CAP_HOST_RX_QUEUE`
103  | [`PROP_HOST_RX_QUEUE_DROPPED`](ulcp-host.md#prop-host-rx-queue-dropped)    | Get                      | `CAP_HOST_RX_QUEUE`
104  | [`PROP_HOST_MUTED_CHANNELS`](ulcp-host.md#prop-host-muted-channels)        | Get, Set, Insert, Remove | `CAP_HOST_RX_QUEUE`
105  | [`PROP_HOST_MUTED_PEERS`](ulcp-host.md#prop-host-muted-peers)              | Get, Set, Insert, Remove | `CAP_HOST_RX_QUEUE`
113  | [`STR_PHY_RAW`](ulcp-transport.md#str-radio-raw)                           | Send, Recv               | —
4820 | [`PROP_PHY_DUTY_NOW`](ulcp-radio.md#prop-phy-duty-now)                     | Get                      | `CAP_PHY_DUTY_LIMIT`
4822 | [`PROP_PHY_DUTY_LIMIT`](ulcp-radio.md#prop-phy-duty-limit)                 | Get, Set                 | `CAP_PHY_DUTY_LIMIT`
4832 | [`PROP_STAT_TX_PACKETS`](ulcp-radio.md#prop-stat-tx-packets)               | Get, Set                 | `CAP_STATS`
4833 | [`PROP_STAT_TX_CHANNEL_BUSY`](ulcp-radio.md#prop-stat-tx-channel-busy)     | Get, Set                 | `CAP_STATS`
4834 | [`PROP_STAT_RX_PACKETS`](ulcp-radio.md#prop-stat-rx-packets)               | Get, Set                 | `CAP_STATS`
4835 | [`PROP_STAT_RX_BAD_CRC`](ulcp-radio.md#prop-stat-rx-bad-crc)               | Get, Set                 | `CAP_STATS`
4836 | [`PROP_STAT_RX_NON_UMSH`](ulcp-radio.md#prop-stat-rx-non-umsh)             | Get, Set                 | `CAP_STATS`
4837 | [`PROP_STAT_RX_ACCEPTED`](ulcp-radio.md#prop-stat-rx-accepted)             | Get, Set                 | `CAP_STATS`, `CAP_REPEATER`
4838 | [`PROP_STAT_FORWARDED`](ulcp-radio.md#prop-stat-forwarded)                 | Get, Set                 | `CAP_STATS`, `CAP_REPEATER`
4839 | [`PROP_STAT_FORWARD_DROPPED`](ulcp-radio.md#prop-stat-forward-dropped)     | Get, Set                 | `CAP_STATS`, `CAP_REPEATER`
4840 | [`PROP_STAT_FORWARD_CANCELLED`](ulcp-radio.md#prop-stat-forward-cancelled) | Get, Set                 | `CAP_STATS`, `CAP_REPEATER`
4864 | [`PROP_BLE_PAIRING_PIN`](ulcp-ble.md#prop-ble-pairing-pin)                 | Set                      | BLE transport
4865 | [`PROP_DEV_ADMINS`](app-node-management.md#prop-dev-admins)                | Get, Set, Insert, Remove | `CAP_ADMIN`
4866 | [`PROP_TIME`](ulcp-device.md#prop-time)                                    | Get, Set, Is             | `CAP_TIME`
4867 | [`PROP_TZ_OFFSET`](ulcp-device.md#prop-tz-offset)                          | Get, Set                 | `CAP_TIME`
4868 | [`PROP_GNSS_IDENT_UPDATE`](ulcp-device.md#prop-gnss-ident-update)          | Get, Set                 | `CAP_GNSS`
4869 | [`PROP_GNSS_IDENT_PRECISION`](ulcp-device.md#prop-gnss-ident-precision)    | Get, Set                 | `CAP_GNSS`
4870 | [`PROP_GNSS_TIME_TRUST`](ulcp-device.md#prop-gnss-time-trust)              | Get, Set                 | `CAP_GNSS`
4871 | [`PROP_BLE_ENABLED`](ulcp-ble.md#prop-ble-enabled)                         | Get, Set, Is             | `CAP_BLE`
4872 | [`PROP_BLE_BOND_COUNT`](ulcp-ble.md#prop-ble-bond-count)                   | Get, Set, Is             | `CAP_BLE`
4873 | [`PROP_BLE_LINK`](ulcp-ble.md#prop-ble-link)                               | Get, Is                  | `CAP_BLE`
4874 | [`PROP_BLE_PAIRING`](ulcp-ble.md#prop-ble-pairing)                         | Get, Set, Is             | `CAP_BLE`

## Capabilities

Advertised through [`PROP_CAPS`](ulcp-core.md#prop-caps); the allocation
is in [Capabilities](ulcp-core.md#capabilities).

Code | Name                      | Defined in
-----|---------------------------|------------
8    | `CAP_WRITABLE_RAW_STREAM` | [Frame Transport](ulcp-transport.md#capabilities)
16   | `CAP_PHY_DUTY_LIMIT`      | [Radio Control](ulcp-radio.md#capabilities)
32   | `CAP_HOST_FILTER`         | [Tethered Host Services](ulcp-host.md#capabilities)
33   | `CAP_HOST_RX_QUEUE`       | [Tethered Host Services](ulcp-host.md#capabilities)
34   | `CAP_HOST_KEYS`           | [Tethered Host Services](ulcp-host.md#capabilities)
35   | `CAP_HOST_AUTO_ACK`       | [Tethered Host Services](ulcp-host.md#capabilities)
36   | `CAP_SAVE`                | [Saved State](ulcp-saved-state.md#capabilities)
37   | `CAP_DEV_IDENTITY`        | [Device Domain](ulcp-device.md#capabilities)
38   | `CAP_DEV_NAME`            | [Device Domain](ulcp-device.md#capabilities)
39   | `CAP_BATTERY`             | [Device Domain](ulcp-device.md#capabilities)
40   | `CAP_REPEATER`            | [Device Domain](ulcp-device.md#capabilities)
41   | `CAP_IDENT`               | [Device Domain](ulcp-device.md#capabilities)
42   | `CAP_ALERT`               | [Device Domain](ulcp-device.md#capabilities)
43   | `CAP_ADMIN`               | [Node Management](app-node-management.md#capabilities)
44   | `CAP_TIME`                | [Device Domain](ulcp-device.md#capabilities)
45   | `CAP_GNSS`                | [Device Domain](ulcp-device.md#capabilities)
46   | `CAP_ADVERT`              | [Device Domain](ulcp-device.md#capabilities)
47   | `CAP_ILLUMINANCE`         | [Device Domain](ulcp-device.md#capabilities)
48   | `CAP_MAC_BACKHAUL`        | [Tethered Host Services](ulcp-host.md#capabilities)
49   | `CAP_CMD_MULTI`           | [Framing and Common Semantics](ulcp-core.md#cmd-prop-multi-get)
50   | `CAP_BLE`                 | [BLE Binding](ulcp-ble.md#capabilities)
51   | `CAP_REBOOT`              | [Framing and Common Semantics](ulcp-core.md#cmd-reboot)
52   | `CAP_STATS`               | [Radio Control](ulcp-radio.md#capabilities)
515  | `CAP_PHY_LORA`            | [Radio Control](ulcp-radio.md#capabilities)

## Status Codes

Defined in [Status Codes](ulcp-core.md#status-codes).

Id | Name                      | Id | Name
---|---------------------------|----|------
0  | `STATUS_OK`               | 12 | `STATUS_BUSY`
1  | `STATUS_FAILURE`          | 13 | `STATUS_PROP_NOT_FOUND`
2  | `STATUS_UNIMPLEMENTED`    | 18 | `STATUS_CCA_FAILURE`
3  | `STATUS_INVALID_ARGUMENT` | 19 | `STATUS_ALREADY`
4  | `STATUS_INVALID_STATE`    | 20 | `STATUS_ITEM_NOT_FOUND`
5  | `STATUS_INVALID_COMMAND`  | 21 | `STATUS_CURSOR_INVALID`
7  | `STATUS_INTERNAL_ERROR`   | 22 | `STATUS_NOT_PERMITTED`
9  | `STATUS_PARSE_ERROR`      | 32 | `STATUS_DUTY_LIMIT`
10 | `STATUS_IN_PROGRESS`      |    |
11 | `STATUS_NOMEM`            |    |

## Reset Codes

Defined in [Reset Codes](ulcp-core.md#reset-codes); the range 112–127 is
reserved for them.

Id  | Name                    | Id  | Name
----|-------------------------|-----|------
112 | `STATUS_RESET_POWER_ON` | 117 | `STATUS_RESET_ASSERT`
113 | `STATUS_RESET_EXTERNAL` | 118 | `STATUS_RESET_OTHER`
114 | `STATUS_RESET_SOFTWARE` | 119 | `STATUS_RESET_UNKNOWN`
115 | `STATUS_RESET_RESTORED` | 120 | `STATUS_RESET_WATCHDOG`
116 | `STATUS_RESET_CRASH`    |     |

## Enumerated Values

The value enumerations carried inside properties and stream metadata.

Enumeration | Values | Defined in
---|---|---
`PROP_SAVED` | 0 none, 1 current, 2 fallback, 3 unreadable | [`PROP_SAVED`](ulcp-saved-state.md#prop-saved)
Filter types | 0 `FILTER_DEST_HINT`, 1 `FILTER_CHANNEL_ID`, 2 `FILTER_PKT_TYPE` | [`PROP_HOST_RX_FILTERS`](ulcp-host.md#prop-host-rx-filters)
Charge states | 0 discharging, 1 charging, 2 charged | [`PROP_BATTERY`](ulcp-device.md#prop-battery)
Alert states | 0 `ALERT_NONE`, 1 `ALERT_LOCATE` | [`PROP_ALERT`](ulcp-device.md#prop-alert)
Fix quality | 0 none, 1 two-dimensional, 2 three-dimensional | [`PROP_GNSS_FIX`](ulcp-device.md#prop-gnss-fix)
Transmit flags | bit 0 `TX_FLAG_NOCCA`, bit 1 `TX_FLAG_NODUTY` | [`STR_PHY_RAW`](ulcp-transport.md#str-radio-raw)
Receive flags | bit 0 `RX_FLAG_BUFFERED`, bit 1 `RX_FLAG_ACKED`, bit 2 `RX_FLAG_SELF_TX` | [Extended Recv Metadata](ulcp-transport.md#buffered-metadata)
Session reset reasons | 0 attached, 1 `CMD_RST`, 2 `CMD_RESTORE` | [`CMD_SESSION_RESET`](ulcp-core.md#cmd-session-reset)
