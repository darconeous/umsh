// TextEcho: answers every text message with its own body.
//
// Wire this board's Serial1 to the radio's application UART (D6 and D7 on
// a XIAO kit: TX to RX, RX to TX, and ground). The pads are 3.3 V: a 5 V
// board goes through a level shifter. Send a text to the radio, or on one
// of its channels, and it comes back as a reply.

#include <Umsh.h>

UmshRadio radio(Serial1);

void text(const UmshMessage& message, const UmshText& t) {
  // Status text, reactions, and resend requests are not echoed.
  if (t.type() != UMSH_TEXT_BASIC) return;
  radio.replyText(message, t, t.body(), t.bodyLength());
}

void setup() {
  // The radio's rate is set when its firmware is built; 115200 unless
  // changed.
  Serial1.begin(115200);
  radio.onText(text);
  radio.setClaims(UMSH_PAYLOAD_TEXT);
  radio.begin();
}

void loop() { radio.poll(); }
