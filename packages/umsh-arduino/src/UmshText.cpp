#include "UmshText.h"

#include <string.h>

// Octets from `at` to `end`, which is never before it.
static inline uint16_t left(const uint8_t* at, const uint8_t* end) { return (uint16_t)(end - at); }

#include "UmshRadio.h"

// Option numbers.
static const uint16_t OPT_TYPE = 0;
static const uint16_t OPT_HANDLE = 1;
static const uint16_t OPT_SEQUENCE = 2;
static const uint16_t OPT_SEQUENCE_RESET = 3;
static const uint16_t OPT_REGARDING = 4;
static const uint16_t OPT_EDITING = 5;
static const uint16_t OPT_CHANNEL_GROUP_RESEND = 8;
// Numbers from here up are extensions this library ignores.
static const uint16_t OPT_EXTENSION_BASE = 9;

static const uint8_t END_MARKER = 0xFF;

UmshTextOptions::UmshTextOptions()
    : type(UMSH_TEXT_BASIC), handle(0), hasSequence(false), messageId(0), sequenceReset(false),
      regardingLength(0), hasEditing(false), editing(0) {
  memset(regarding, 0, sizeof regarding);
}

UmshText::UmshText()
    : body_(0), bodyLength_(0), handle_(0), handleLength_(0), type_(UMSH_TEXT_BASIC),
      hasSequence_(false), messageId_(0), fragmentIndex_(0), fragmentCount_(0),
      sequenceReset_(false), regardingLength_(0), hasEditing_(false), editing_(0) {
  memset(regarding_, 0, sizeof regarding_);
}

// One CoAP-style delta or length nibble and its extension.
static bool readExtended(const uint8_t*& at, const uint8_t* end, uint8_t nibble,
                         uint16_t* value) {
  if (nibble <= 12) {
    *value = nibble;
  } else if (nibble == 13) {
    if (at >= end) return false;
    *value = (uint16_t)(*at++ + 13);
  } else if (nibble == 14) {
    if (left(at, end) < 2) return false;
    uint32_t extended = ((uint32_t)at[0] << 8 | at[1]) + 269;
    if (extended > 0xFFFF) return false;
    *value = (uint16_t)extended;
    at += 2;
  } else {
    return false;
  }
  return true;
}

bool UmshText::decode(const uint8_t* body, uint16_t length, UmshText& out) {
  out = UmshText();
  const uint8_t* at = body;
  const uint8_t* end = body + length;
  uint16_t number = 0;
  uint16_t seen = 0;
  while (at < end) {
    uint8_t first = *at++;
    if (first == END_MARKER) break;
    uint16_t delta, valueLength;
    if (!readExtended(at, end, first >> 4, &delta)) return false;
    if (!readExtended(at, end, first & 0x0F, &valueLength)) return false;
    if (left(at, end) < valueLength) return false;
    if ((uint32_t)number + delta > 0xFFFF) return false;
    number = (uint16_t)(number + delta);
    const uint8_t* value = at;
    at += valueLength;
    if (number >= OPT_EXTENSION_BASE) continue;

    uint16_t bit = (uint16_t)(1u << number);
    if (seen & bit) {
      // An identity, sequencing, or reference option that repeats cannot
      // be trusted, even with the same value. A flag with a value is not
      // the flag. A presentation option keeps its first occurrence.
      switch (number) {
        case OPT_TYPE:
          out.type_ = UMSH_TEXT_BASIC;
          break;
        case OPT_SEQUENCE:
          out.hasSequence_ = false;
          out.fragmentIndex_ = out.fragmentCount_ = 0;
          break;
        case OPT_REGARDING:
          out.regardingLength_ = 0;
          break;
        case OPT_EDITING:
          out.hasEditing_ = false;
          break;
        case OPT_SEQUENCE_RESET:
          if (valueLength != 0) out.sequenceReset_ = false;
          break;
        default:
          break;
      }
      continue;
    }
    seen |= bit;

    // A value that cannot be decoded leaves the option absent.
    switch (number) {
      case OPT_TYPE:
        if (valueLength == 1) out.type_ = value[0];
        break;
      case OPT_HANDLE:
        if (valueLength <= 0xFF) {
          out.handle_ = value;
          out.handleLength_ = (uint8_t)valueLength;
        }
        break;
      case OPT_SEQUENCE:
        if (valueLength == 1) {
          out.hasSequence_ = true;
          out.messageId_ = value[0];
        } else if (valueLength == 3 && value[2] >= 2 && value[1] < value[2]) {
          out.hasSequence_ = true;
          out.messageId_ = value[0];
          out.fragmentIndex_ = value[1];
          out.fragmentCount_ = value[2];
        }
        break;
      case OPT_SEQUENCE_RESET:
        out.sequenceReset_ = valueLength == 0;
        break;
      case OPT_REGARDING:
        if (valueLength == 1 || valueLength == 4 || (valueLength == 2 && value[1] == 0)) {
          out.regardingLength_ = (uint8_t)valueLength;
          memcpy(out.regarding_, value, valueLength);
        }
        break;
      case OPT_EDITING:
        if (valueLength == 1) {
          out.hasEditing_ = true;
          out.editing_ = value[0];
        }
        break;
      case OPT_CHANNEL_GROUP_RESEND:
      default:
        // Background and text color, and the resend flag: nothing a
        // sketch is offered.
        break;
    }
  }
  out.body_ = at;
  out.bodyLength_ = (uint16_t)(end - at);
  return true;
}

// Writes options in increasing order of number into a buffer.
class OptionWriter {
public:
  OptionWriter(uint8_t* out, uint16_t capacity)
      : out_(out), capacity_(capacity), length_(0), number_(0), ok_(true) {}

  void put(uint16_t number, const uint8_t* value, uint16_t length) {
    uint16_t delta = number - number_;
    number_ = number;
    // The header goes first; its nibbles are known once the extensions
    // after it are written.
    uint16_t header = length_;
    raw(0);
    uint8_t deltaNibble = extended(delta);
    uint8_t lengthNibble = extended(length);
    if (ok_) out_[header] = (uint8_t)(deltaNibble << 4 | lengthNibble);
    for (uint16_t i = 0; i < length; i++) raw(value[i]);
  }

  void raw(uint8_t octet) {
    if (length_ >= capacity_) {
      ok_ = false;
      return;
    }
    out_[length_++] = octet;
  }

  int16_t finish() const { return ok_ ? (int16_t)length_ : -1; }

private:
  uint8_t extended(uint16_t value) {
    if (value <= 12) return (uint8_t)value;
    if (value <= 268) {
      raw((uint8_t)(value - 13));
      return 13;
    }
    raw((uint8_t)((value - 269) >> 8));
    raw((uint8_t)(value - 269));
    return 14;
  }

  uint8_t* out_;
  uint16_t capacity_;
  uint16_t length_;
  uint16_t number_;
  bool ok_;
};

int16_t UmshText::encodeOptions(uint8_t* out, uint16_t capacity, const UmshTextOptions& options,
                                bool hasBody) {
  OptionWriter writer(out, capacity);
  if (options.type != UMSH_TEXT_BASIC) writer.put(OPT_TYPE, &options.type, 1);
  if (options.handle) {
    size_t length = strlen(options.handle);
    if (length > UMSH_FRAME_MAX) return -1;
    writer.put(OPT_HANDLE, (const uint8_t*)options.handle, (uint16_t)length);
  }
  if (options.hasSequence) writer.put(OPT_SEQUENCE, &options.messageId, 1);
  if (options.sequenceReset) writer.put(OPT_SEQUENCE_RESET, 0, 0);
  if (options.regardingLength != 0) {
    if (options.regardingLength > 4 || options.regardingLength == 3) return -1;
    writer.put(OPT_REGARDING, options.regarding, options.regardingLength);
  }
  if (options.hasEditing) writer.put(OPT_EDITING, &options.editing, 1);
  // The marker only when a body follows the options.
  if (hasBody) writer.raw(END_MARKER);
  return writer.finish();
}

int16_t UmshText::encode(uint8_t* out, uint16_t capacity, const uint8_t* body, uint16_t length,
                         const UmshTextOptions& options) {
  int16_t prefix = encodeOptions(out, capacity, options, length != 0);
  if (prefix < 0 || capacity - (uint16_t)prefix < length) return -1;
  memcpy(out + prefix, body, length);
  return (int16_t)(prefix + length);
}

bool UmshText::regarding(const UmshMessage& message, const UmshText& text,
                         UmshTextOptions& options) {
  if (!text.hasSequence()) return false;
  options.regarding[0] = text.messageId();
  if (message.kind() == UMSH_MULTICAST) {
    // On a channel, IDs are told apart by their sender: a key or a hint
    // begins with the same three octets.
    memcpy(options.regarding + 1, message.source(), 3);
    options.regardingLength = 4;
  } else {
    // In a one-to-one conversation, the one octet names a message the
    // recipient of the reply sent.
    options.regardingLength = 1;
  }
  return true;
}
