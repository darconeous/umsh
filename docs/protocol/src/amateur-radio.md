# Amateur Radio Operation

UMSH supports three distinct operating modes for devices or repeaters deployed on
spectrum where amateur operation and unlicensed operation may coexist.

## Operating Modes

### Unlicensed

In `Unlicensed` mode, the node operates only under non-amateur rules.

- Locally originated packets are treated as unlicensed traffic.
- Encryption is enabled by default.
- A repeater MAY forward any packet it may lawfully retransmit under unlicensed rules.
- Maximum transmit power and duty cycle are determined by local rules for unlicensed operation.
- If a forwarded packet carries a [station callsign](packet-options.md#station-callsign-option-7), the repeater MUST remove it rather than replacing it.
- The repeater SHOULD NOT add its own station callsign.

The specific requirements for unlicensed transmission vary by jurisdiction and frequency, but may include restrictions on transmit power, antenna gain, and/or duty cycle.

### Licensed-Only

In `Licensed-Only` mode, all locally originated and forwarded traffic is treated
as amateur-radio traffic.

- Encryption SHALL NOT be enabled for any packet. All encrypted packets encountered SHOULD be immediately dropped.
- Locally originated packets MUST include an [operator callsign](packet-options.md#operator-callsign-option-4).
- Restrictions on transmit power and duty cycle are generally more relaxed.
- A repeater SHALL NOT forward packets that are missing an operator callsign.
- A repeater SHALL replace or insert the station callsign option with its own callsign on every forwarded packet.

> [!TIP]
> While blind unicast is not categorically forbidden by this mode, the expected utility of using it without encryption is limited.

### Hybrid

In `Hybrid` mode, the node may operate under either authority depending on the packet.

- A repeater SHOULD add or replace the station callsign option on forwarded packets.
- Packets carrying an operator callsign MAY be forwarded under amateur-radio authority.
- Packets lacking an operator callsign MAY still be forwarded, but only when the retransmission can lawfully occur under unlicensed rules.
- If the packet has encryption enabled, the transmission MUST be treated as unlicensed traffic, including using power and any other regulatory limits appropriate for unlicensed operation.

Hybrid mode is useful where amateur stations may use higher power for qualifying amateur traffic, while still allowing encrypted or otherwise unlicensed-only traffic to transit the same repeater at unlicensed settings.

## Locally Originated Packets

The MAC layer should apply the following transmit rules:

- `Unlicensed`: no amateur-specific restriction is implied, but restrictions on tx power and duty cycle may apply.
- `Licensed-Only`: encrypted packets must be rejected, and an operator callsign is required. Max transmit power may increase.
- `Hybrid`: encrypted packets are allowed, but they must be transmitted under unlicensed constraints rather than amateur-only ones.

