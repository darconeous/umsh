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
| 4 | Send Message | User → Room |
| 5 | Fetch Messages | User → Room |
| 6 | Fetch Users | User → Room |
| 7 | Admin Commands | User → Room |
| 8 | Room Update | Room → User |

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

If the user is currently logged in, the room sends one final Room Update containing a system message indicating the user has left.

## Send Message

The payload uses the same format as the [Text Message](app-text-messages.md) protocol, except that the Sender Handle option is ignored (the room fills it in). Once received, the message is echoed back to the sender via a Room Update.

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

## Room Update

A Room Update contains a list of timestamped events from the room. All timestamps are managed by the room and are relative to its own clock — typically a UTC UNIX timestamp, though accuracy depends on whether the room's clock is synchronized. Regardless of absolute accuracy, the chronological ordering by timestamp is the canonical event ordering.

Each event is formatted as a length-prefixed [text message](app-text-messages.md) with the following extensions:

### Additional Message Types

| Value | Name |
|---:|---|
| 32 | User Joined |
| 33 | User Left |
| 34 | Admin Message |

### Additional Options

| Number | Name |
|---:|---|
| 12 | Timestamp Received |

The Sender Handle option is automatically populated by the room.
