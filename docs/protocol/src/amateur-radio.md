# Amateur Radio Operation

UMSH supports three distinct operating modes for devices or repeaters deployed on
spectrum where amateur operation and unlicensed operation may coexist.

## Operating Modes

### Unlicensed

In `Unlicensed` mode, the node operates only under non-amateur rules.

- Locally originated packets are treated as unlicensed traffic.
- Encryption and blind unicast are allowed.
- A repeater may forward any packet it lawfully may retransmit under unlicensed rules.
- Maximum transmit power and duty cycle are determined by local rules for unlicensed operation.
- If a forwarded packet carries a [station callsign](packet-options.md#station-callsign-option-7), the repeater removes it rather than replacing it.
- The repeater must not add its own station callsign.

The specific requirements for unlicensed transmission vary by jurisdiction and frequency, but may include restrictions on transmit power, antenna gain, and/or duty cycle.

### Licensed-Only

In `Licensed-Only` mode, all locally originated and forwarded traffic is treated
as amateur-radio traffic.

- Encryption is forbidden. All encrypted packets encountered must be immediately dropped.
- Locally originated packets must include an [operator callsign](packet-options.md#operator-callsign-option-4).
- Restrictions on transmit power and duty cycle are generally more relaxed.
- A repeater forwards only packets that already carry an operator callsign.
- A repeater replaces or inserts the station callsign option with its own callsign on every forwarded packet.

> [!NOTE]
> Blind unicast is not categorically forbidden by this mode, but the expected utility of using it without encryption is limited.

### Hybrid

In `Hybrid` mode, the node may operate under either authority depending on the packet.

- A repeater always adds or replaces the station callsign option on forwarded packets.
- Packets carrying an operator callsign may be forwarded under amateur-radio authority.
- Packets lacking an operator callsign may still be forwarded, but only when the retransmission can lawfully occur under unlicensed rules.
- If encryption is enabled, the transmission must be treated as unlicensed traffic, including using power and any other regulatory limits appropriate for unlicensed operation.

Hybrid mode is useful where amateur stations may use higher power for qualifying amateur traffic, while still allowing encrypted or otherwise unlicensed-only traffic to transit the same repeater at unlicensed settings.

## Locally Originated Packets

The MAC layer should apply the following transmit rules:

- `Unlicensed`: no amateur-specific restriction is implied, but restrictions on tx power and duty cycle may apply.
- `Licensed-Only`: encrypted packets must be rejected, and an operator callsign is required. Max transmit power may increase.
- `Hybrid`: encrypted packets are allowed, but they must be transmitted under unlicensed constraints rather than amateur-only ones.

