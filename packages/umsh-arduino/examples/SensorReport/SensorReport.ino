// SensorReport: sends a reading to one node every minute, and tries again
// when it is not acknowledged.
//
// The reading goes as the smallest text message there is: payload type 3,
// the octet 0xFF, and the text. Any payload type is sent the same way.
//
// Between reports the sketch blocks in delay(). Text sent to it meanwhile
// is not lost: the radio sends only what the serial buffer can hold, and
// keeps the rest until the sketch reads again. It is printed when it
// arrives.

#include <Umsh.h>

// The node that collects the readings: its address as the app shows it.
const char COLLECTOR[] = "PASTE THE COLLECTOR'S 44-CHARACTER ADDRESS HERE";

UmshRadio radio(Serial1);
uint8_t collector[32];

int readSensor() { return analogRead(A0); }

void text(const UmshMessage& message, const UmshText& t) {
  Serial.print(message.redelivered() ? F("again: ") : F("text: "));
  Serial.write(t.body(), t.bodyLength());
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  if (!UmshAddress::parse(COLLECTOR, collector)) {
    Serial.println(F("COLLECTOR is not an address"));
    for (;;) {
    }
  }
  radio.onText(text);
  radio.setClaims(UMSH_PAYLOAD_TEXT);
  radio.begin();
}

void loop() {
  uint8_t report[24];
  report[0] = 0xFF;
  int length = snprintf((char*)report + 1, sizeof report - 1, "A0=%d", readSensor());

  for (uint8_t attempt = 1; attempt <= 3; attempt++) {
    UmshStatus status = radio.sendAndWait(UmshDest::peer(collector), UMSH_PAYLOAD_TEXT, report,
                                          1 + length);
    Serial.print(F("report: "));
    Serial.println(status);
    if (status != UMSH_STATUS_NO_ACK) break;
  }

  delay(60000);
  // What arrived during the delay.
  radio.poll();
}
