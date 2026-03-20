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

## Payload and Packet Type Compatibility

Not all payload types are valid with all packet types. A receiver should drop a packet whose payload type is not compatible with its packet type. For the purposes of this table, blind unicast follows the same rules as unicast.

| Payload Type        | Unicast | Multicast | Broadcast |
|---------------------|:-------:|:---------:|:---------:|
| Empty payload       | Yes     | Yes       | Yes       |
| Node Identity       | Yes     | Yes       | Yes       |
| MAC Command         | Yes     | Note 1    | No        |
| Text Message        | Yes     | Yes       | No        |
| Chat-Room Message   | Yes     | No        | No        |
| CoAP-over-UMSH      | Yes     | Yes       | No        |
| Node Management Cmd | Yes     | Yes       | No        |

Unless explicitly configured otherwise, the only payload types allowed for broadcast are empty payloads and node identities.

**Note 1:** Some MAC commands may be permitted on specific channels. For example, a private channel might allow echo requests to all members and receive echo responses from everyone. Whether a given MAC command is accepted over multicast is deployment-defined and not yet specified by the protocol.

## In-Band Node Management

Nodes may optionally support remote management via **Node Management Command** payloads.

Support for in-band management is protocol-defined but implementation-optional.
