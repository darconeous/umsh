#include "UmshAddress.h"

#include <string.h>

static const char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const uint8_t ENCODED_LEN = 44;

static int8_t digitValue(char digit) {
  const char* at = strchr(ALPHABET, digit);
  return digit != 0 && at ? (int8_t)(at - ALPHABET) : -1;
}

static int8_t hexValue(char digit) {
  if (digit >= '0' && digit <= '9') return digit - '0';
  if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
  if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
  return -1;
}

static bool parseHex(const char* text, uint8_t* out, uint8_t length) {
  if (strlen(text) != 2u * length) return false;
  for (uint8_t i = 0; i < 2 * length; i++) {
    if (hexValue(text[i]) < 0) return false;
  }
  for (uint8_t i = 0; i < length; i++) {
    out[i] = (uint8_t)(hexValue(text[2 * i]) << 4 | hexValue(text[2 * i + 1]));
  }
  return true;
}

bool UmshAddress::parse(const char* text, uint8_t key[32]) {
  size_t length = strlen(text);
  if (length == 64) return parseHex(text, key, 32);
  if (length != ENCODED_LEN) return false;
  uint8_t value[32];
  memset(value, 0, sizeof value);
  for (uint8_t i = 0; i < ENCODED_LEN; i++) {
    int8_t digit = digitValue(text[i]);
    if (digit < 0) return false;
    uint16_t carry = (uint16_t)digit;
    for (int8_t at = 31; at >= 0; at--) {
      uint16_t acc = (uint16_t)(value[at] * 58 + carry);
      value[at] = (uint8_t)acc;
      carry = acc >> 8;
    }
    // More than 32 octets' worth.
    if (carry != 0) return false;
  }
  memcpy(key, value, 32);
  return true;
}

void UmshAddress::format(const uint8_t key[32], char out[45]) {
  uint8_t value[32];
  memcpy(value, key, sizeof value);
  for (int8_t slot = ENCODED_LEN - 1; slot >= 0; slot--) {
    uint16_t remainder = 0;
    for (uint8_t at = 0; at < 32; at++) {
      uint16_t acc = (uint16_t)(remainder << 8 | value[at]);
      value[at] = (uint8_t)(acc / 58);
      remainder = acc % 58;
    }
    out[slot] = ALPHABET[remainder];
  }
  out[ENCODED_LEN] = 0;
}

bool UmshAddress::parseChannel(const char* text, uint8_t id[16]) { return parseHex(text, id, 16); }

void UmshAddress::formatHex(const uint8_t* bytes, uint8_t length, char* out) {
  static const char digits[] = "0123456789abcdef";
  for (uint8_t i = 0; i < length; i++) {
    out[2 * i] = digits[bytes[i] >> 4];
    out[2 * i + 1] = digits[bytes[i] & 0x0F];
  }
  out[2 * length] = 0;
}
