# Payload Format

The UMSH payload carries higher-layer content — either a network-layer protocol (e.g., 6LoWPAN), a third-party application protocol (e.g., CoAP), or one of the UMSH-defined application protocols (e.g., text messages, chat rooms). The MAC layer treats the payload opaquely; it does not interpret, fragment, or reassemble payload content (see [Layer Separation](introduction.md#layer-separation)).

Payloads are typically prefixed by a 1-byte payload type identifier. Values from 128-255
(all values with the most significant bit set) are currently *RESERVED*.

## Payload Type Registry

| Value | Meaning                                |
|------:|----------------------------------------|
| 0     | Unspecified                            |
| 1     | Node Identity                          |
| 2     | MAC Command                            |
| 3     | Text Message                           |
| 4     | *RESERVED*                             |
| 5     | Chat-Room Message                      |
| 6     | *RESERVED*                             |
| 7     | CoAP-over-UMSH                         |
| 8     | Node Management Command                |

## In-Band Node Management

Nodes may optionally support remote management via **Node Management Command** payloads.

Support for in-band management is protocol-defined but implementation-optional.
