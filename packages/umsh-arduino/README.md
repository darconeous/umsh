# UMSH for Arduino

A sketch wired to a UMSH radio's serial port sends and receives mesh
messages through the radio's own node. The radio encrypts, routes,
retries, and collects acknowledgements under its device identity; the
sketch hands it payloads and destinations, and receives the payloads of
the types it claims ([ULCP Node Messaging](../../docs/protocol/src/ulcp-node-messaging.md)).

Plain C++11 with no heap, no STL, and no `String`. The one Arduino
dependency is `Stream`, so it runs on a small AVR and builds on a desktop
for its tests.

```cpp
#include <Umsh.h>

UmshRadio radio(Serial1);

void text(const UmshMessage& message, const UmshText& t) {
  radio.replyText(message, t, "pong");
}

void setup() {
  Serial1.begin(115200);
  radio.onText(text);
  radio.setClaims(UMSH_PAYLOAD_TEXT);
  radio.begin();
}

void loop() { radio.poll(); }
```

Install it by copying or linking this directory into the sketchbook's
`libraries` folder.

## Wiring

The two XIAO kits serve an application on D6 (the radio's TX) and D7 (its
RX): wire them crossed to the sketch's serial port, with ground between.

- **The XIAO ESP32S3 kit** serves it by default.
- **The XIAO nRF52840 kit** needs firmware built with `ulcp-uart`, which
  takes D6 and D7 from the header I2C bus. See
  [its README](../../firmware/xiao-nrf52/README.md).

The pads are 3.3 V. A 3.3 V board wires straight across; a 5 V board goes
through a level shifter.

The radio's baud rate is set when its firmware is built: 115200 unless
`UMSH_ULCP_UART_BAUD` names another. Open the port at the same rate. A part
clocked at 8 MHz needs 57600 or lower.

Any `Stream` that receives while it sends will do: a hardware UART, or
AltSoftSerial on a part with only one. SoftwareSerial cannot receive while
it sends and does not work.

## What the library takes care of

- **Flow control.** The radio sends only what the serial buffer holds, a
  window at a time, so a sketch may block in a callback or in `delay()` for
  as long as it likes and lose nothing. The window is a little under half
  the buffer (30 octets on a 64-octet AVR buffer); `begin(window)` sets
  another, and `begin(0)` selects plain XON/XOFF, with `hold()` and
  `release()`, for a port that holds a whole frame.
- **Waking the radio.** The ESP32S3 kit sleeps while it listens. The
  library sends a wake preamble whenever the line has been quiet.
- **The session.** `begin()` opens a session with the radio and returns at
  once; `poll()` does the rest, and `ready()` says when it is done. A frame
  damaged in either direction, or a radio that restarts or stops
  answering, starts a new session: every send still waiting is completed
  with `UMSH_LINK_RESET`, meaning it may or may not have gone, claims and
  listening are set again, and `onLinkReset` is called. A message the
  radio delivers again after that arrives with `redelivered()` set.
- **Claims.** `setClaims()` says which payload types the sketch receives,
  exactly: claims are saved on the radio, so a sketch that sets none gets
  whatever the last one claimed.

## Sending

`send()` and `sendText()` return a ticket from 1 to 7 at once, and the
outcome arrives at `onSendResult()`; 0 means not sent, with the reason in
`lastError()`. `sendAndWait()` blocks until the outcome is known, still
delivering what arrives meanwhile, and is refused inside a callback.

Destinations are `UmshDest::peer(key)`, `channel(id)`, `blind(id, key)`,
`broadcast()`, and `replyTo(message)`. A unicast asks for an
acknowledgement unless `UmshSendOptions` says otherwise; the options carry
everything else the protocol offers (full source key, signature, flood
hops, source route, transmit power).

`UmshAddress::parse()` reads the 44-character address the app shows, and
`parseChannel()` the 32-digit channel identifier the radio lists.

## Text

`UmshText` decodes and encodes the [text payload](../../docs/protocol/src/app-text-messages.md)
as pure functions. `replyText()` and `react()` build the reference to a
received message. What needs history is the sketch's: each fragment of a
long message is delivered as it comes, marked as one; a body too long for
one frame is not split; resend requests are not answered; and message IDs
are the sketch's to assign.

## Memory

About 460 octets of RAM on an AVR, most of it the receive buffer, which
holds the longest frame a radio sends.

## Tests

`make arduino-test` builds the library on the desktop and runs it against
a stub radio over a modeled 64-octet serial buffer, and checks it against
`test/vectors.txt`, which the Rust codecs are checked against too
(`cargo test -p umsh-ulcp -p umsh-text --test arduino_vectors`).
