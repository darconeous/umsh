# Text Messages

The text message protocol carries human-readable text between nodes (unicast) or from a node to a channel (multicast).

The payload consists of a CoAP-style option list terminated by a `0xFF` byte, followed by the message body. All options are non-critical — unrecognized options are ignored and the remainder of the message is displayed normally.

## Message Options

Every recognized option is a singleton unless a specification explicitly declares otherwise. How a receiver treats a duplicated recognized option depends on the option's role:

- An option that carries identity, sequencing, or reference semantics — Message Type, Message Sequence, Regarding, Editing, and extension options in the same role such as Sender Sequence — makes the message invalid when repeated, even if the repeated values are identical. The message MUST be dropped.
- A presentation option — Sender Handle, Background Color, Text Color — keeps the first occurrence when repeated; later occurrences are ignored and MAY be reported diagnostically.
- Duplicates of a zero-length flag option — Sequence Reset, Channel Group Resend — are idempotent.

Repeated unrecognized options remain ignorable.

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
| 8 | Channel Group Resend | 0 bytes (flag) |

### Message Type

| Value | Name | Rendering |
|---:|---|---|
| 0 | Basic text | Displayed in a text bubble |
| 1 | Status text | Displayed inline as "[HANDLE] [MESSAGE]" (similar to IRC `/me`) |
| 2 | Message Resend Request | Not displayed; see the body rules below |
| 3 | Message Unavailable | Not normally displayed; see below |

If absent or empty, the message type defaults to 0 (basic text).

The presence of the `Regarding` option changes the semantics a bit: A **reply** is a type 0 message with a `Regarding` option specifying which message is being replied to. An **emote** is a type 1 message with a `Regarding` option specifying which message is being reacted to; the body is a single Unicode emoji or a short text token such as `+1`, `-1`, `!`, or `?`. Implementations may differentiate emotes from plain status text by the presence of the Regarding option.

A message resend request is itself not a message but a request to re-send a message that was inferred to exist but was not received. Such a request SHALL contain exactly one Message Type option with value 2 and exactly one Message Sequence option identifying the missing frame. A request with duplicate Message Type or Message Sequence options is invalid. It MAY also contain the Channel Group Resend flag described below and SHOULD NOT contain any other options. After validating the required options and the Channel Group Resend flag, receivers MUST ignore every other option and the entire body. Senders SHOULD use an empty body. The request MUST be received via unicast (for one-on-one messages) or blind-unicast (for channel messages), and SHALL be dropped if received via broadcast or multicast.

A resend request identifies exactly one missing frame, and a successful response retransmits exactly one frame. The 1-byte Message Sequence form requests a message by ID without specifying a fragment; the sender responds with the unfragmented message or, if it was fragmented, with fragment zero. The fragment count carried in fragment zero lets the requester ask for any remaining fragments individually. The 3-byte form requests one specific fragment.

Not all messages are available to be resent; for example, a requested message may have been deleted or evicted. In that case, the original sender SHOULD respond with Message Unavailable. A sender producing Message Unavailable SHOULD include only a Message Type option with value 3 and one Message Sequence option exactly matching the requested message or fragment. Its body SHOULD be empty.

Message Unavailable follows the delivery path appropriate to the requested conversation, just like a successful resend of the original message: direct-conversation responses use unicast, blind-unicast one-to-one channel responses use blind-unicast, and channel-group responses use multicast to the channel.

Once a receiver has unambiguously recognized Message Unavailable and its single Message Sequence option, it MUST ignore all other options and the entire body. The indicated sequence position is treated as accounted for, so it no longer remains a gap in that sender's sequence history. The receiver is not required to render a whole-message unavailable response in the UI.

When the three-byte Message Sequence form identifies a fragment, only that requested fragment is reported unavailable, even if the sender no longer has any part of the message. Other fragments remain independently repairable. The receiver SHOULD render the unavailable portion of the partial message as unavailable rather than continuing to show it as pending.

Message Unavailable is also the standard response to a request for an unknown Message Sequence ID, including an ID that has not been sent.

### Channel Group Resend

A zero-length flag used only on a Message Resend Request received by blind-unicast. Both a request for a message missed from a multicast channel conversation and a request for a message missed from a blind-unicast one-to-one conversation arrive by blind-unicast. The presence of this flag selects the sender's archive for the multicast channel conversation. Its absence selects the sender's archive for the blind-unicast one-to-one conversation with the requester.

A receiver MUST drop a request containing this flag if the request was not received by blind-unicast or if the option has a non-zero length. The flag has no meaning on other message types and MUST be ignored there.

### Sender Handle

A UTF-8 string containing the name or pseudonym of the sender. If not supplied, a handle may be inferred from previously received node metadata for the sender's address.

### Message Sequence

Associates a packet with a monotonically increasing message identifier maintained independently for each sender within each conversation, and optionally carries fragmentation state. The option is encouraged on all messages but is not required. Messages without this option cannot be directly referenced in replies or emotes.

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

- Message IDs are monotonically increasing per sender within each conversation, wrapping at 255. A one-to-one blind-unicast conversation and the group conversation on the same channel are distinct conversations with independent sequence streams, even though they share channel key material.
- When an ID wraps and is reused, the older message with that ID in the same conversation-and-sender stream is retired: it is no longer a valid target for Regarding, Editing, or a resend request in that stream. Retirement does not affect any other stream or already-displayed history.
- Messages smaller than `MTU`-32 bytes SHOULD NOT be fragmented.
- A fragment body carries at most 160 bytes, and a message has at most 10 fragments; senders MUST NOT exceed either limit. Larger fragment bodies and larger fragment counts are nevertheless syntactically valid; a receiver that will not reassemble such a message drops the assembly and MAY account for the ID as unavailable rather than leaving a gap.
- Fragmentation splits the body at byte boundaries. An individual fragment body is not required to be valid UTF-8; the reassembled body is validated as UTF-8 only after every fragment is present.
- Options from the first fragment (Fragment Index 0) apply to the entire reassembled message. Subsequent fragments MUST NOT include options that would override those of the first fragment, and any such options MUST be ignored by the receiver.
- During reassembly, missing fragments SHOULD be rendered as `[FRAGMENT MISSING]`, or an appropriately-localized equivalent. When a fragment boundary splits a UTF-8 code point, rendering discards the incomplete code point on each side of the gap; the substituted marker is part of the rendered display, not the message body.
- Out-of-order reassembly SHOULD be supported for fragments received within a reasonable amount of time (thirty seconds to two minutes).
- Edits (see [Editing](#editing)) carry their own message IDs and MUST NOT be referenced by subsequent Editing or Regarding options. The original message ID is the stable reference.

### Ordering, Gaps, and Automatic Repair

Message IDs compare using serial-number arithmetic modulo 256. Relative to the most recent ID accepted from a sender in a conversation, a forward delta of 1 through 127 is newer; a delta of 128 through 255 is old or ambiguous.

A forward delta greater than 1 within one conversation-and-sender stream means messages are missing from that stream. A gap in one sender's stream says nothing about any other sender in the conversation. After a short reordering grace period, a receiver MAY request each missing message with a resend request using the 1-byte Message Sequence form, subject to the limits below:

- Automatic repair is bounded: a receiver SHOULD NOT automatically request more than 8 missing messages from a single observed gap, and SHOULD apply per-peer and overall rate limits to all generated resend requests.
- A forward delta greater than the receiver's automatic-repair bound, an ambiguous delta, the first message observed from a sender, and the first message after a Sequence Reset all establish a new baseline. Receivers MUST NOT generate automatic resend requests to backfill across a baseline.
- Repair of a channel-group conversation requires addressing a blind unicast to the original sender, which requires that sender's full public key. A member holding only the source hint cannot construct the request and simply renders the loss.
- In a channel-group conversation every member observes the same loss at nearly the same moment. Receivers MUST delay each automatic group repair request by an independently randomized interval, and MUST cancel a pending request when the missing message — or a Message Unavailable naming it — arrives on the channel before the request is sent.
- Room conversations are unicast; room repair requests are sent directly to the room without group jitter, and responses repair only the requester.

### Sequence Reset

A 0-byte flag option that signals the sender has reset its message ID counter for the current conversation — for example, after losing that conversation's persistent sequence state. Receivers SHOULD discard cached message context for this sender in this conversation, including pending fragment reassembly state. State for the same sender in other conversations is unaffected.

The Sequence Reset option SHOULD accompany a Message Sequence option bearing the sender's new starting ID. In the absence of a Message Sequence option, receivers SHOULD treat the next message from that sender as starting a fresh sequence.

Reset announcement is lazy and scoped to the affected conversation: the sender includes the flag on the next message it actually sends in that conversation. Senders do not transmit standalone reset messages preemptively to conversations they are not otherwise sending to.

### Regarding

References a previously sent message for the purposes of replies and emotes.

The option length depends on the conversation, not on how the MAC packet is addressed:

- **One-to-one conversation** (unicast, or a blind-unicast conversation with a single logical destination): 1 byte — the Message ID of the referenced message.
- **Channel-group conversation** (delivered by multicast to the channel): 4 bytes — the 1-byte Message ID followed by the first 3 bytes of the source public key of the original sender.

The source prefix is necessary in multicast channels to disambiguate messages from different senders that may share the same Message ID. This means a message cannot be referenced if it is more than 255 messages old in that sender's sequence, or if the user has since reset their sequence ID.

In chat rooms, the room assigns canonical Message IDs across all senders (see [Chat Rooms](app-chat-rooms.md#room-update)), so the 1-byte form is used and no source prefix is needed.

### Editing

Indicates that this message replaces a previously sent message in the same conversation and sender scope. The option value is 1 byte: the Message ID of the message being edited. No source prefix is needed because the source scope comes from the enclosing packet. For unicast and blind-unicast, pairwise authentication binds that source to a peer key. For multicast, authentication proves only possession of the channel key; the source hint is a claimed identity, and the protocol cannot prevent one channel member from impersonating another member.

An edit with a zero-length body signals deletion of the original message.

For as long as a client retains sequence history for an edited or deleted message, it SHOULD retain the stable original-message identity or a tombstone so that references can still be resolved. A client MAY retain prior revision content, including deleted content, for edit-history display; this is a local storage and privacy policy rather than a protocol requirement.

Edit messages carry their own Message IDs. References in subsequent Editing or Regarding options MUST use the original message's ID, not the edit's ID.

How edits are presented to users is implementation-defined. Implementations typically display only the most recent edit, with some indication that edits exist, and an optional mechanism to view edit history.

### Background Color

Three bytes (red, green, blue) specifying a suggested background color for the text bubble. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the text color.

### Text Color

Three bytes (red, green, blue) specifying a suggested text color. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the background color.

## Message Body

The message body is a UTF-8 string.
