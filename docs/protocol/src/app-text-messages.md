# Text Messages

The text message protocol carries human-readable text between nodes (unicast) or from a node to a channel (multicast).

The payload consists of a CoAP-style option list terminated by a `0xFF` byte, followed by the message body. All options are non-critical — unrecognized options are ignored and the remainder of the message is displayed normally.

## Message Options

| Number | Name | Value |
|---:|---|---|
| 0 | Message Type | 0 or 1 bytes |
| 1 | Sender Handle | UTF-8 string |
| 2 | Message Sequence | 1 or 3 bytes (see below) |
| 3 | Sequence Reset | 0 bytes (flag) |
| 4 | Regarding | 1 or 4 bytes (see below) |
| 5 | Editing | 1 byte |
| 6 | Background Color | 3 bytes, RGB |
| 7 | Text Color | 3 bytes, RGB |

### Message Type

| Value | Name | Rendering |
|---:|---|---|
| 0 | Basic text | Displayed in a text bubble |
| 1 | Status text | Displayed inline as "[HANDLE] [MESSAGE]" (similar to IRC `/me`) |
| 2 | Message Resend Request | Not displayed, has no text, see below | 

If absent or empty, the message type defaults to 0 (basic text).

The presence of the `Regarding` option changes the semantics a bit: A **reply** is a type 0 message with a `Regarding` option specifying which message is being replied to. An **emote** is a type 1 message with a `Regarding` option specifying which message is being reacted to; the body is a single Unicode emoji or a short text token such as `+1`, `-1`, `!`, or `?`. Implementations may differentiate emotes from plain status text by the presence of the Regarding option.

A message resend request it itself not a message but a request to re-send a message that was inferred to exist but was not received. Such a request SHALL only contain one "Message Sequence" option which contains the specific message or fragment that was missed. This
MUST be received via unicast (for one-on-one messages) or blind-unicast (for channel messages), and SHALL be dropped if received via broadcast or multicast.

For requesting a message that was sent to a channel, there is a need to disambiguate between requesting a message missed from the channel chat vs requesting a message missed from a blind unicast 1:1 chat. To disambiguate, when requesting the message from a channel chat, the text body will contain a single ASCII "#" character.

### Sender Handle

A UTF-8 string containing the name or pseudonym of the sender. If not supplied, a handle may be inferred from previously received node metadata for the sender's address.

### Message Sequence

Associates a packet with a per-sender monotonically increasing message identifier, and optionally carries fragmentation state. The option is encouraged on all messages but is not required. Messages without this option cannot be directly referenced in replies or emotes.

The option value is either 1 byte or 3 bytes:

**1-byte form** (message ID only):

| Byte | Field | Description |
|---:|---|---|
| 0 | Message ID | Per-sender message identifier (wraps at 255) |

**3-byte form** (fragment):

| Byte | Field | Description |
|---:|---|---|
| 0 | Message ID | Shared by all fragments of the same message |
| 1 | Fragment Index | Zero-based position of this fragment |
| 2 | Fragment Count | Total number of fragments (must be 2 or greater) |

Rules:

- Message IDs are per-sender and monotonically increasing, wrapping at 255.
- Messages smaller than `MTU`-32 bytes SHOULD NOT be fragmented.
- Options from the first fragment (Fragment Index 0) apply to the entire reassembled message. Subsequent fragments MUST NOT include options that would override those of the first fragment, and any such options MUST be ignored by the receiver.
- During reassembly, missing fragments SHOULD be rendered as `[FRAGMENT MISSING]`, or an appropriately-localized equivalent.
- Out-of-order reassembly SHOULD be supported for fragments received within a reasonable amount of time (thirty seconds to two minutes).
- Edits (see [Editing](#editing)) carry their own message IDs and MUST NOT be referenced by subsequent Editing or Regarding options. The original message ID is the stable reference.

### Sequence Reset

A 0-byte flag option that signals the sender has reset its message ID counter — for example, after a restart. Receivers SHOULD discard any cached message context for this sender, including pending fragment reassembly state.

The Sequence Reset option SHOULD accompany a Message Sequence option bearing the sender's new starting ID. In the absence of a Message Sequence option, receivers SHOULD treat the next message from that sender as starting a fresh sequence.

### Regarding

References a previously sent message for the purposes of replies and emotes.

The option length depends on context:

- **Unicast** (MAC packet addressed to a single destination): 1 byte — the Message ID of the referenced message.
- **Multicast channel**: 4 bytes — the 1-byte Message ID followed by the first 3 bytes of the source public key of the original sender.

The source prefix is necessary in multicast channels to disambiguate messages from different senders that may share the same Message ID. This means a message cannot be referenced if it is more than 255 messages old in that sender's sequence, or if the user has since reset their sequence ID.

In chat rooms, the room assigns canonical Message IDs across all senders (see [Chat Rooms](app-chat-rooms.md#room-update)), so the 1-byte form is used and no source prefix is needed.

### Editing

Indicates that this message replaces a previously sent message from the same sender. The option value is 1 byte: the Message ID of the message being edited. Because only the original sender can issue an edit (enforced by MAC-layer authentication), no source prefix is needed.

An edit with a zero-length body signals deletion of the original message.

Edit messages carry their own Message IDs. References in subsequent Editing or Regarding options MUST use the original message's ID, not the edit's ID.

How edits are presented to users is implementation-defined. Implementations typically display only the most recent edit, with some indication that edits exist, and an optional mechanism to view edit history.

### Background Color

Three bytes (red, green, blue) specifying a suggested background color for the text bubble. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the text color.

### Text Color

Three bytes (red, green, blue) specifying a suggested text color. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the background color.

## Message Body

The message body is a UTF-8 string.
