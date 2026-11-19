// UmshText: the text message payload (payload type 3), as pure functions
// over octet buffers. It knows nothing of the radio.
//
// What needs history is left to the sketch: fragments are delivered one by
// one and marked as fragments, a body too long for one frame is not split,
// resend requests are not answered, and sequence numbers are the sketch's
// to assign.

#ifndef UMSH_TEXT_H
#define UMSH_TEXT_H

#include <stdint.h>

// Message types.
static const uint8_t UMSH_TEXT_BASIC = 0;
static const uint8_t UMSH_TEXT_STATUS = 1;
static const uint8_t UMSH_TEXT_RESEND_REQUEST = 2;
static const uint8_t UMSH_TEXT_UNAVAILABLE = 3;

class UmshMessage;

// What a text message carries besides its body. Everything starts out
// absent, which sends the smallest message there is.
struct UmshTextOptions {
  UmshTextOptions();

  // The message type; basic text is sent as no option at all.
  uint8_t type;
  // The sender's handle, a NUL-terminated string, or null.
  const char* handle;
  // A message ID, so that the message can be replied to. Set
  // sequenceReset on the first message after a restart.
  bool hasSequence;
  uint8_t messageId;
  bool sequenceReset;
  // Regarding: 1 octet for a message the recipient sent in a one-to-one
  // conversation, 2 (the ID, then 0) for one this sender sent, 4 (the ID,
  // then the original sender's first three key octets) on a channel.
  uint8_t regardingLength;
  uint8_t regarding[4];
  // The ID of a message of this sender's that this one replaces.
  bool hasEditing;
  uint8_t editing;
};

// A decoded text message: views into the payload it was decoded from,
// valid as long as that is.
class UmshText {
public:
  UmshText();

  // Decode `body`: the payload after its type octet. Options that cannot
  // be decoded are treated as absent, as the specification has a receiver
  // do; false only when the options cannot be walked to the body at all.
  static bool decode(const uint8_t* body, uint16_t length, UmshText& out);

  // Encode the options and the body into `out`; returns the length, or -1
  // when it does not fit. The payload type octet is not included.
  static int16_t encode(uint8_t* out, uint16_t capacity, const uint8_t* body, uint16_t length,
                        const UmshTextOptions& options);
  // The same, without the body: the octets that go before it, the marker
  // included when `hasBody`.
  static int16_t encodeOptions(uint8_t* out, uint16_t capacity, const UmshTextOptions& options,
                               bool hasBody);

  // Set `options.regarding` to refer to `text`, received in `message`, for
  // a reply or a reaction. False when the message carries no ID to refer to.
  static bool regarding(const UmshMessage& message, const UmshText& text,
                        UmshTextOptions& options);

  // The body: octets, not checked as UTF-8, and not terminated.
  const uint8_t* body() const { return body_; }
  uint16_t bodyLength() const { return bodyLength_; }

  // The message type; basic when absent, repeated, or misshaped.
  uint8_t type() const { return type_; }
  // The sender's handle, or null.
  const uint8_t* handle() const { return handle_; }
  uint8_t handleLength() const { return handleLength_; }

  bool hasSequence() const { return hasSequence_; }
  uint8_t messageId() const { return messageId_; }
  bool isFragment() const { return fragmentCount_ != 0; }
  uint8_t fragmentIndex() const { return fragmentIndex_; }
  uint8_t fragmentCount() const { return fragmentCount_; }
  bool sequenceReset() const { return sequenceReset_; }

  // Regarding, in one of the three forms above; length 0 when absent.
  uint8_t regardingLength() const { return regardingLength_; }
  const uint8_t* regarding() const { return regarding_; }
  bool hasEditing() const { return hasEditing_; }
  uint8_t editing() const { return editing_; }

  bool isReply() const { return type_ == UMSH_TEXT_BASIC && regardingLength_ != 0; }
  bool isReaction() const { return type_ == UMSH_TEXT_STATUS && regardingLength_ != 0; }
  bool isEdit() const { return hasEditing_; }

private:
  const uint8_t* body_;
  uint16_t bodyLength_;
  const uint8_t* handle_;
  uint8_t handleLength_;
  uint8_t type_;
  bool hasSequence_;
  uint8_t messageId_;
  uint8_t fragmentIndex_;
  uint8_t fragmentCount_;
  bool sequenceReset_;
  uint8_t regardingLength_;
  uint8_t regarding_[4];
  bool hasEditing_;
  uint8_t editing_;
};

#endif
