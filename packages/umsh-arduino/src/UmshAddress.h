// UmshAddress: a node's address as people see it, and a channel
// identifier as a radio lists it.

#ifndef UMSH_ADDRESS_H
#define UMSH_ADDRESS_H

#include <stdint.h>

class UmshAddress {
public:
  // A 32-octet key from the 44 base58 digits the app shows, or from 64
  // hex digits. False, with `key` untouched, for anything else.
  static bool parse(const char* text, uint8_t key[32]);
  // The 44 base58 digits of `key`, NUL-terminated.
  static void format(const uint8_t key[32], char out[45]);
  // A 16-octet channel identifier from its 32 hex digits.
  static bool parseChannel(const char* text, uint8_t id[16]);
  // Hex digits for `length` octets, NUL-terminated: `out` holds
  // 2 * length + 1.
  static void formatHex(const uint8_t* bytes, uint8_t length, char* out);
};

#endif
