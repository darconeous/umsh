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
| 8     | [Node Management Request](app-node-management.md) |
| 9     | [Node Management Response](app-node-management.md) |

## Payload and Packet Type Compatibility

Not all payload types are valid with all packet types. A receiver should drop a packet whose payload type is not compatible with its packet type. For the purposes of this table, blind unicast follows the same rules as unicast.

| Payload Type        | Unicast | Multicast | Broadcast |
|---------------------|:-------:|:---------:|:---------:|
| Empty payload       | Yes     | Yes       | Yes       |
| Node Identity       | Yes     | Yes       | Yes       |
| MAC Command         | Yes     | Note 1    | Note 2    |
| Text Message        | Yes     | Yes       | No        |
| Chat-Room Message   | Yes     | No        | No        |
| CoAP-over-UMSH      | Yes     | Yes       | No        |
| Node Management Req | Yes     | No        | No        |
| Node Management Resp| Yes     | No        | No        |

Unless explicitly configured otherwise, the only payload types allowed for broadcast are empty payloads, node identities, and the broadcast-permitted MAC commands (Note 2).

**Note 1:** Some MAC commands may be permitted on specific channels. For example, a private channel might allow echo requests to all members and receive echo responses from everyone. Whether a given MAC command is accepted over multicast is deployment-defined and not yet specified by the protocol.

**Note 2:** MAC commands are admitted to broadcast individually: a command may be carried in a broadcast only when its definition says so, and any such definition must weigh the solicitation load a broadcast can create. Currently only the [Identity Request](mac-commands.md#identity-request-1) permits broadcast carriage, under the flood-management restrictions defined there. Receivers drop any other MAC command arriving by broadcast.

## Response Carriage

A response to a unicast request is carried the same way the request was: a request that arrived as [blind unicast](packet-types.md#blind-unicast-packet) on a channel is answered as blind unicast on that same channel, and a request that arrived as plain [unicast](packet-types.md#unicast-packet) is answered as plain unicast. This holds for every request and response the protocol defines—MAC commands, node identity, node management—and applies whether the response comes from the MAC layer or from an application above it.

Blind unicast conceals both endpoints from observers who lack the channel key. A response sent off the channel names the parties the request took care to hide, so it would undo that concealment for the exchange as a whole. A [MAC acknowledgement](packet-types.md#mac-ack-packet) is not a response and remains channel-less; it carries no destination hint and so names neither party.

A node answering a multicast or broadcast request is not bound by this rule, since such a request has no pairwise carriage to mirror. What a node may answer with is left to each command's own definition.

## In-Band Node Management

Nodes may optionally support remote management via **Node Management Request** and **Node Management Response** payloads, which carry ULCP exchanges over the mesh itself. The payload format, authorization model, and reachable state are specified in [Node Management](app-node-management.md); support is advertised through the `CAP_ADMIN` ULCP capability.
