// HDLC-Lite framing, as ULCP uses it on a serial link: frames between
// 0x7E flags, 0x7D 0x11 0x13 0x7E escaped inside them, and a 16-bit FCS
// (CRC-16/X-25) after each, low octet first.

#ifndef UMSH_HDLC_H
#define UMSH_HDLC_H

#include <Arduino.h>
#include <stdint.h>

static const uint8_t UMSH_HDLC_FLAG = 0x7E;
static const uint8_t UMSH_HDLC_ESCAPE = 0x7D;
static const uint8_t UMSH_HDLC_XON = 0x11;
static const uint8_t UMSH_HDLC_XOFF = 0x13;
static const uint8_t UMSH_HDLC_TEXT_MARKER = 0x23;
static const uint8_t UMSH_HDLC_FILL = 0xFF;

uint16_t umshFcsUpdate(uint16_t fcs, uint8_t octet);

// Writes one frame straight to a Print, escaping as it goes and keeping a
// running FCS, so no frame is ever held in memory.
class UmshEncoder {
public:
  explicit UmshEncoder(Print& out);

  // The opening flag, the header with `tid`, and the command.
  void begin(uint8_t tid, uint8_t command);
  void put(uint8_t octet);
  void put(const uint8_t* data, uint16_t length);
  // A packed unsigned integer.
  void putPui(uint32_t value);
  // A 16-bit integer, low octet first.
  void putU16(uint16_t value);
  // The FCS and the closing flag.
  void end();

private:
  void escaped(uint8_t octet);

  Print& out_;
  uint16_t fcs_;
};

// The octets a packed unsigned integer takes.
uint8_t umshPuiLength(uint32_t value);
// Read a packed unsigned integer at `at`, advancing it; false if it runs
// past `end` or is longer than three octets.
bool umshReadPui(const uint8_t*& at, const uint8_t* end, uint32_t* value);

// Takes received octets one at a time and reports each frame as it ends.
// Bare XON and XOFF octets, marked text, and fill are skipped.
class UmshDecoder {
public:
  enum Event : uint8_t {
    // Nothing yet.
    NONE,
    // A whole frame, its FCS checked and removed: frame() and length().
    FRAME,
    // A damaged frame: a bad FCS, a frame too short for one, an escape
    // cut off by a flag, or a frame longer than the buffer.
    LOST,
  };

  UmshDecoder(uint8_t* buffer, uint16_t capacity);

  Event push(uint8_t octet);
  const uint8_t* frame() const { return buffer_; }
  uint16_t length() const { return length_; }
  // Partway through a frame, marked text, or fill.
  bool inFrame() const { return count_ != 0 || escaped_ || skipping_; }
  void reset();

private:
  uint8_t* buffer_;
  uint16_t capacity_;
  // Octets of the current frame so far, its FCS included; may pass the
  // capacity, and the frame is then lost.
  uint16_t count_;
  uint16_t length_;
  uint16_t fcs_;
  bool escaped_;
  bool skipping_;
};

#endif
