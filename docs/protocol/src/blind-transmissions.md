# Blind Transmissions

## Blind Multicast

Blind multicast uses a multicast channel in a way that conceals the source address from observers who do not possess the channel key.

## Blind Unicast

Blind unicast supports directed unicast delivery while hiding the sender and the destination from observers who do not possess the channel key, while still ensuring that only the actual recipient can decrypt the payload.

The recipient must also possess the channel key for this to work.

## Forwarding Considerations

Some repeaters may decline to forward blind packets for unknown channels. For that reason, blind multicast may not always be desirable even when source concealment is preferred.
