# Chat Rooms

A chat room is a special node that provides limited store-and-forward capability for text messages and potentially other types of data. Chat rooms may be polled or can push updates to joined members.

## Action Types

The first byte of the payload identifies the action type.

| Value | Action | Direction |
|---:|---|---|
| 0 | Get Room Info | User → Room |
| 1 | Room Info | Room → User |
| 2 | Login | User → Room |
| 3 | Logout | User → Room |
| 5 | Fetch Messages | User → Room |
| 6 | Fetch Users | User → Room |
| 7 | Admin Commands | User → Room |
| 8 | Room Update | Room → User |

Regular message exchange — including system events — does not use a dedicated action type. Users send messages to the room as plain text message payloads (unicast to the room node), and the room distributes them to members the same way. Action types are reserved for room management operations. Room Update (action 8) is used only for batch history delivery.

## Get Room Info / Room Info

A user may send a Get Room Info action to a room node without being logged in. The room responds with a Room Info action containing CoAP-option-encoded metadata:

| Number | Name | Notes |
|---:|---|---|
| 0 | Room Name | UTF-8 string |
| 1 | Owner Information | |
| 2 | Administrator | User ID; may appear more than once. May only be included for logged-in users |
| 3 | Active User Count | |
| 4 | Max User Count | |
| 5 | Message Queue Depth | |
| 6 | Most Recent Message Timestamp | |
| 7 | Oldest Retrievable Message Timestamp | |

If the options are terminated with a `0xFF` byte, the remainder of the response is a UTF-8 description of the room.

## Login

The login payload is CoAP-option-encoded:

| Number | Name | Notes |
|---:|---|---|
| 0 | Handle | If omitted, the room uses the previous handle or assigns one |
| 1 | Last Message Timestamp | If present, the room sends up to 10 missed messages since this time |
| 2 | Session Timeout | Requested inactivity timeout in minutes (1 byte) |
| 3 | Password | Required only if the room is password-protected and the user's public key is not already known |

All options are optional. Behavior details:

- If a last-message timestamp is provided and more than 10 messages have been received since then, only the 10 most recent are sent automatically. Older messages can be retrieved with Fetch Messages.
- If the room is password-protected but already recognizes the user's public key, the password is ignored. A room may forget a public key after prolonged inactivity, requiring a password on the next login.
- First-time logins must include the full 32-byte public key (S flag set).

## Logout

Logging out unsubscribes the user from push updates and removes them from the active user list. Previously sent messages remain stored and retrievable by other users up to the history limit.

If the user is currently logged in, the room sends a final text message to all members using the User Left message type (see [System Events](#system-events)).

## Send Message

To send a message to a chat room, a user sends a standard [text message](app-text-messages.md) unicast to the room node. The Sender Handle option is ignored — the room fills it in from the sender's registered handle when distributing the message to members.

The Message Sequence option SHOULD be included, using the sender's own per-sender message ID counter. The room uses this to detect duplicate submissions and to order rapid messages from the same user. The sender's per-sender ID is separate from the canonical room-assigned ID that the room assigns when distributing the message.

## Fetch Messages

Retrieves previous messages posted to the room, which may include system messages.

| Field | Size | Description |
|---|---:|---|
| Timestamp | 4 bytes | Fetch messages up to and including this time |
| Max Count | 1 byte | Maximum number of messages to return |

## Fetch Users

Retrieves the currently active user list, possibly including their public keys.

## Admin Commands

TBD.

## Message Distribution

When the room receives a message from a user, it assigns a monotonically increasing canonical Message Sequence ID from a single room-wide counter and distributes the message to each logged-in member as a text message. System events (user join/leave, admin messages) are distributed the same way, using room-specific message types. This gives the room a single unified message ordering across all activity — a Regarding option referencing a room message ID is unambiguous without a source prefix (see [Regarding](app-text-messages.md#regarding)).

All timestamps are managed by the room and are relative to its own clock — typically a UTC UNIX timestamp, though accuracy depends on whether the room's clock is synchronized.

### Sender Sequence

When the room echoes a message back to the original sender, it faces a correlation problem: the sender showed the message optimistically in their UI the moment they sent it, but the echoed copy arrives with a room-assigned ID the client has never seen. Without some way to link them, the client cannot reliably identify which pending outbound message the echo corresponds to — matching by content alone fails if the user sends identical messages in quick succession.

To solve this, the room includes a Sender Sequence option on the echo it sends back to the original sender. This option is not included in copies sent to other members.

| Number | Name | Value |
|---:|---|---|
| 12 | Timestamp Received | 4 bytes, UTC UNIX timestamp |
| 13 | Sender Sequence | 1 byte — the sender's original Message Sequence ID |

The Sender Sequence value is the per-sender Message Sequence ID the user included in their outbound message. The client matches this against its pending outbound messages to identify the echo, then updates its local record to use the canonical room-assigned ID for future Regarding references.

### System Events

The room delivers system notifications as text messages to all logged-in members, using message types reserved for room use:

| Value | Name |
|---:|---|
| 32 | User Joined |
| 33 | User Left |
| 34 | Admin Message |

The Sender Handle option is automatically populated by the room for all distributed messages, including system events.

## Room Update

Room Update is used exclusively for batch delivery: the history sent on login (via the Last Message Timestamp login option) and the response to Fetch Messages. It contains a list of length-prefixed text messages in chronological order, each carrying the room-injected options defined above (Timestamp Received, and Sender Sequence where applicable). This batching avoids the per-packet overhead of sending history as individual unicast messages on LoRa.

| Value | Action | Direction |
|---:|---|---|
| 8 | Room Update | Room → User |
