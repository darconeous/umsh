// ChannelChat: the Serial Monitor on one of the radio's channels. Lines
// typed are sent to the channel, and text on the channel is printed.
//
// The channel must already be one of the radio's own: add it with
// `umshctl dev-channel add`, and `umshctl dev-channel list` prints its
// 32-digit identifier.

#include <Umsh.h>

const char CHANNEL[] = "PASTE THE CHANNEL'S 32-DIGIT IDENTIFIER HERE";
// The name others see.
const char HANDLE[] = "arduino";

UmshRadio radio(Serial1);
uint8_t channel[16];
char line[160];
uint8_t lineLength = 0;

void text(const UmshMessage& message, const UmshText& t) {
  if (!message.channel() || memcmp(message.channel(), channel, 16) != 0) return;
  if (t.isReaction()) return;
  if (t.handle()) {
    Serial.write(t.handle(), t.handleLength());
  } else {
    // No handle: the first octets of the sender's key, as hex.
    char hint[7];
    UmshAddress::formatHex(message.source(), 3, hint);
    Serial.print(hint);
  }
  Serial.print(F(": "));
  Serial.write(t.body(), t.bodyLength());
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  if (!UmshAddress::parseChannel(CHANNEL, channel)) {
    Serial.println(F("CHANNEL is not a channel identifier"));
    for (;;) {
    }
  }
  radio.onText(text);
  radio.setClaims(UMSH_PAYLOAD_TEXT);
  radio.begin();
}

void loop() {
  radio.poll();
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c != '\n' && lineLength < sizeof line - 1) {
      line[lineLength++] = c;
      continue;
    }
    if (c != '\n') continue;
    line[lineLength] = 0;
    lineLength = 0;
    if (line[0] == 0) continue;
    UmshTextOptions options;
    options.handle = HANDLE;
    if (!radio.sendText(UmshDest::channel(channel), line, options)) {
      Serial.print(F("not sent: "));
      Serial.println(radio.lastError());
    }
  }
}
