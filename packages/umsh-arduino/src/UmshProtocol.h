// Numbers from the ULCP specification that the library and sketches use.
// The names follow the specification's, with a UMSH_ prefix.

#ifndef UMSH_PROTOCOL_H
#define UMSH_PROTOCOL_H

#include <stdint.h>

// A status: a code the radio answered with (zero or more), or one of the
// library's own outcomes below (negative).
typedef int32_t UmshStatus;

// Statuses the radio answers with.
static const UmshStatus UMSH_STATUS_OK = 0;
static const UmshStatus UMSH_STATUS_FAILURE = 1;
static const UmshStatus UMSH_STATUS_UNIMPLEMENTED = 2;
static const UmshStatus UMSH_STATUS_INVALID_ARGUMENT = 3;
static const UmshStatus UMSH_STATUS_INVALID_STATE = 4;
static const UmshStatus UMSH_STATUS_INVALID_COMMAND = 5;
static const UmshStatus UMSH_STATUS_PARSE_ERROR = 9;
static const UmshStatus UMSH_STATUS_NOMEM = 11;
static const UmshStatus UMSH_STATUS_BUSY = 12;
static const UmshStatus UMSH_STATUS_PROP_NOT_FOUND = 13;
static const UmshStatus UMSH_STATUS_CCA_FAILURE = 18;
static const UmshStatus UMSH_STATUS_ALREADY = 19;
static const UmshStatus UMSH_STATUS_ITEM_NOT_FOUND = 20;
static const UmshStatus UMSH_STATUS_NOT_PERMITTED = 22;
static const UmshStatus UMSH_STATUS_CHANNEL_NOT_FOUND = 23;
static const UmshStatus UMSH_STATUS_NO_ACK = 27;
static const UmshStatus UMSH_STATUS_DUTY_LIMIT = 32;
// Reset codes: the radio restarted.
static const UmshStatus UMSH_STATUS_RESET_FIRST = 112;
static const UmshStatus UMSH_STATUS_RESET_LAST = 127;

// The library's own outcomes.
// The link's session started over before the answer came: the request may
// or may not have been carried out.
static const UmshStatus UMSH_LINK_RESET = -1;
// No answer within the time given.
static const UmshStatus UMSH_TIMEOUT = -2;
// The radio has not answered yet, or begin() was not called.
static const UmshStatus UMSH_NOT_READY = -3;
// Seven requests are already waiting for answers.
static const UmshStatus UMSH_NO_TICKET = -4;
// Too long for one frame, or an answer longer than the buffer given.
static const UmshStatus UMSH_TOO_LONG = -5;
// A blocking call from inside a callback.
static const UmshStatus UMSH_IN_CALLBACK = -6;
// An argument the library cannot send, such as a destination with no key.
static const UmshStatus UMSH_INVALID = -7;
// The radio does not offer node messaging.
static const UmshStatus UMSH_UNSUPPORTED = -8;
// An answer of a kind the request does not have.
static const UmshStatus UMSH_UNEXPECTED = -9;

// Commands.
static const uint8_t UMSH_CMD_PROP_GET = 2;
static const uint8_t UMSH_CMD_PROP_SET = 3;
static const uint8_t UMSH_CMD_PROP_INSERT = 4;
static const uint8_t UMSH_CMD_PROP_REMOVE = 5;
static const uint8_t UMSH_CMD_PROP_IS = 6;
static const uint8_t UMSH_CMD_PROP_INSERTED = 7;
static const uint8_t UMSH_CMD_PROP_REMOVED = 8;
static const uint8_t UMSH_CMD_STR_SEND = 9;
static const uint8_t UMSH_CMD_STR_RECV = 10;
static const uint8_t UMSH_CMD_SESSION_DID_END = 24;
static const uint8_t UMSH_CMD_SESSION_START = 28;
static const uint8_t UMSH_CMD_SESSION_DID_START = 29;

// Properties and streams.
static const uint32_t UMSH_PROP_LAST_STATUS = 0;
static const uint32_t UMSH_PROP_CAPS = 5;
static const uint32_t UMSH_PROP_NODE_MSG_LISTEN = 51;
static const uint32_t UMSH_PROP_NODE_MSG_TYPES = 5008;
static const uint32_t UMSH_PROP_NODE_MSG_MTU = 5009;
static const uint32_t UMSH_PROP_UART_WINDOW = 5010;
static const uint32_t UMSH_STR_NODE_MSG = 114;

// Payload types.
static const uint8_t UMSH_PAYLOAD_TEXT = 3;

// How a message is addressed.
enum UmshKind : uint8_t {
  UMSH_UNICAST = 0,
  UMSH_BROADCAST = 1,
  UMSH_BLIND_UNICAST = 2,
  UMSH_MULTICAST = 3,
};

// The longest ULCP frame either end takes, header included.
static const uint16_t UMSH_FRAME_MAX = 300;

static const uint8_t UMSH_KEY_LEN = 32;
static const uint8_t UMSH_HINT_LEN = 3;
static const uint8_t UMSH_CHANNEL_ID_LEN = 16;
static const uint8_t UMSH_MAX_ROUTE_HINTS = 15;

#endif
