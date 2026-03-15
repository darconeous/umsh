# Amateur Radio Operation

When operating under amateur radio rules, UMSH should generally be used in a non-encrypted form.

## Required Amateur-Radio Behavior

- Disable encryption
- Do not use blind unicast packet types
- Add an operator callsign option to locally originated packets

## Repeater Rules Under Amateur Operation

A repeater operating under amateur-radio rules should:

- not forward packets lacking an operator callsign unless the retransmission can lawfully occur under non-amateur rules
- not forward encrypted packets
- update the station callsign option before retransmitting any packet forwarded under amateur-radio authority

Because blind unicast is primarily useful in conjunction with encryption, it is generally not useful in amateur-radio-compliant operation.
