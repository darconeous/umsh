// Just enough of the Arduino core to build the library on a desktop, with
// a clock the tests drive.

#ifndef ARDUINO_STUB_H
#define ARDUINO_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

class Print {
public:
  virtual ~Print() {}
  virtual size_t write(uint8_t octet) = 0;
  virtual void flush() {}
};

class Stream : public Print {
public:
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int peek() = 0;
};

// The serial buffer the library's default window is taken from.
#define SERIAL_RX_BUFFER_SIZE 64

uint32_t millis();
uint32_t micros();

#endif
