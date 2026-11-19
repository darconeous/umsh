#include "UmshHdlc.h"

// What the FCS register holds after a whole frame and its own FCS have
// gone through it (RFC 1662).
static const uint16_t FCS_GOOD = 0xF0B8;

uint16_t umshFcsUpdate(uint16_t fcs, uint8_t octet) {
  fcs ^= octet;
  for (uint8_t bit = 0; bit < 8; bit++) {
    fcs = (fcs & 1) ? (fcs >> 1) ^ 0x8408 : fcs >> 1;
  }
  return fcs;
}

uint8_t umshPuiLength(uint32_t value) {
  if (value < 0x80) return 1;
  if (value < 0x4000) return 2;
  return 3;
}

bool umshReadPui(const uint8_t*& at, const uint8_t* end, uint32_t* value) {
  uint32_t result = 0;
  for (uint8_t shift = 0; shift < 21; shift += 7) {
    if (at >= end) return false;
    uint8_t octet = *at++;
    result |= (uint32_t)(octet & 0x7F) << shift;
    if (!(octet & 0x80)) {
      *value = result;
      return true;
    }
  }
  return false;
}

UmshEncoder::UmshEncoder(Print& out) : out_(out), fcs_(0xFFFF) {}

void UmshEncoder::begin(uint8_t tid, uint8_t command) {
  fcs_ = 0xFFFF;
  out_.write(UMSH_HDLC_FLAG);
  put((uint8_t)(0x80 | (tid & 0x07)));
  put(command);
}

void UmshEncoder::escaped(uint8_t octet) {
  if (octet == UMSH_HDLC_FLAG || octet == UMSH_HDLC_ESCAPE || octet == UMSH_HDLC_XON ||
      octet == UMSH_HDLC_XOFF) {
    out_.write(UMSH_HDLC_ESCAPE);
    out_.write((uint8_t)(octet ^ 0x20));
  } else {
    out_.write(octet);
  }
}

void UmshEncoder::put(uint8_t octet) {
  fcs_ = umshFcsUpdate(fcs_, octet);
  escaped(octet);
}

void UmshEncoder::put(const uint8_t* data, uint16_t length) {
  for (uint16_t i = 0; i < length; i++) put(data[i]);
}

void UmshEncoder::putPui(uint32_t value) {
  while (value >= 0x80) {
    put((uint8_t)(0x80 | (value & 0x7F)));
    value >>= 7;
  }
  put((uint8_t)value);
}

void UmshEncoder::putU16(uint16_t value) {
  put((uint8_t)value);
  put((uint8_t)(value >> 8));
}

void UmshEncoder::end() {
  uint16_t fcs = (uint16_t)~fcs_;
  escaped((uint8_t)fcs);
  escaped((uint8_t)(fcs >> 8));
  out_.write(UMSH_HDLC_FLAG);
}

UmshDecoder::UmshDecoder(uint8_t* buffer, uint16_t capacity)
    : buffer_(buffer), capacity_(capacity), count_(0), length_(0), fcs_(0xFFFF), escaped_(false),
      skipping_(false) {}

void UmshDecoder::reset() {
  count_ = 0;
  fcs_ = 0xFFFF;
  escaped_ = false;
  skipping_ = false;
}

UmshDecoder::Event UmshDecoder::push(uint8_t octet) {
  if (octet == UMSH_HDLC_XON || octet == UMSH_HDLC_XOFF) {
    // Flow control, never frame content.
    return NONE;
  }
  if (skipping_) {
    if (octet == UMSH_HDLC_FLAG) skipping_ = false;
    return NONE;
  }
  if (octet == UMSH_HDLC_FLAG) {
    uint16_t count = count_;
    bool escaped = escaped_;
    bool good = fcs_ == FCS_GOOD;
    reset();
    if (escaped) return LOST;
    // Flags back to back, or idle between frames.
    if (count == 0) return NONE;
    if (count < 2 || count > capacity_ || !good) return LOST;
    length_ = count - 2;
    return FRAME;
  }
  if (count_ == 0 && !escaped_ &&
      (octet == UMSH_HDLC_TEXT_MARKER || octet == UMSH_HDLC_FILL)) {
    // Marked text or fill: neither is a frame, nor a lost one.
    skipping_ = true;
    return NONE;
  }
  if (octet == UMSH_HDLC_ESCAPE) {
    escaped_ = true;
    return NONE;
  }
  if (escaped_) {
    octet ^= 0x20;
    escaped_ = false;
  }
  fcs_ = umshFcsUpdate(fcs_, octet);
  if (count_ < capacity_) buffer_[count_] = octet;
  if (count_ != 0xFFFF) count_++;
  return NONE;
}
