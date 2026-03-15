# Text Messages

The text message protocol carries human-readable text between nodes (unicast) or from a node to a channel (multicast).

The payload consists of a CoAP-style option list terminated by a `0xFF` byte, followed by the message body. All options are non-critical — unrecognized options are ignored and the remainder of the message is displayed normally.

## Message Options

| Number | Name | Value |
|---:|---|---|
| 0 | Message Type | 0 or 1 bytes |
| 1 | Sender Handle | UTF-8 string |
| 2 | Multi-Message | 3 bytes (see below) |
| 3 | Background Color | 3 bytes, RGB |
| 4 | Text Color | 3 bytes, RGB |

### Message Type

| Value | Name | Rendering |
|---:|---|---|
| 0 | Basic text | Displayed in a text bubble |
| 1 | Status text | Displayed inline as "[HANDLE] [MESSAGE]" (similar to IRC `/me`) |

If absent or empty, the message type defaults to 0 (basic text).

### Sender Handle

A UTF-8 string containing the name or pseudonym of the sender. If not supplied, a handle may be inferred from previously received node metadata for the sender's address.

### Multi-Message

Fragments a large message across multiple packets. The option value is 3 bytes:

| Byte | Field | Description |
|---:|---|---|
| 0 | Fragment Index | Position of this fragment in the reassembled message |
| 1 | Fragment Count | Total number of fragments (must not be zero or one) |
| 2 | Message Identifier | Shared by all fragments of the same message |

Rules:

- Messages smaller than 140 bytes MUST NOT be fragmented.
- The message identifier may be randomly chosen or simply incremented, but MUST NOT be reused within 5 minutes.
- Options from the first fragment apply to the entire reassembled message. Subsequent fragments cannot override options such as text color.
- During reassembly, missing fragments are rendered as `[FRAGMENT MISSING]`.
- Out-of-order reassembly SHOULD be supported for fragments received within 15–30 seconds.

### Background Color

Three bytes (red, green, blue) specifying a suggested background color for the text bubble. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the text color.

### Text Color

Three bytes (red, green, blue) specifying a suggested text color. Receivers may ignore this option. If supported, implementations should ensure adequate contrast with the background color.

## Message Body

The message body is a UTF-8 string.
