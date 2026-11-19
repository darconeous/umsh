// Desktop tests for the UMSH Arduino library: the shared vector file, and
// the link's behavior against a stub radio over a modeled serial line.
//
// The line runs at a real baud rate on a virtual clock. The sketch's
// receive buffer holds 64 octets and drops what arrives when it is full,
// as an AVR's does. The stub radio paces itself by XON, XOFF, and its
// window, sleeps after 250 ms without receiving, loses what arrives while
// it wakes, and checks every wake preamble the library sends.

#include <stdio.h>

#include <deque>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "Arduino.h"
#include "Umsh.h"

typedef std::vector<uint8_t> Bytes;

static int failures = 0;
#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) {                                                        \
      failures++;                                                         \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                     \
  } while (0)
#define CHECK_EQ(a, b)                                                    \
  do {                                                                    \
    long long va = (long long)(a), vb = (long long)(b);                   \
    if (va != vb) {                                                       \
      failures++;                                                         \
      fprintf(stderr, "%s:%d: %s == %lld, expected %s == %lld\n", __FILE__, __LINE__, #a, va, \
              #b, vb);                                                    \
    }                                                                     \
  } while (0)

static std::string hexOf(const uint8_t* bytes, size_t length) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < length; i++) {
    out += digits[bytes[i] >> 4];
    out += digits[bytes[i] & 15];
  }
  return out.empty() ? "-" : out;
}
static std::string hexOf(const Bytes& bytes) { return hexOf(bytes.data(), bytes.size()); }

static Bytes hex(const std::string& text) {
  Bytes out;
  if (text == "-") return out;
  for (size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back((uint8_t)strtoul(text.substr(i, 2).c_str(), 0, 16));
  }
  return out;
}

// ---- The clock ----

static uint64_t nowNs = 0;
static void advance(uint64_t ns);

// Every look at the clock costs a little time, as it does on a real part,
// so that a loop waiting on the clock moves the world along.
uint32_t micros() {
  advance(2000);
  return (uint32_t)(nowNs / 1000);
}
uint32_t millis() {
  advance(2000);
  return (uint32_t)(nowNs / 1000000);
}

static const uint64_t MS = 1000000;

// ---- Frames, for the stub radio ----

static uint16_t fcs(const Bytes& data) {
  uint16_t value = 0xFFFF;
  for (uint8_t octet : data) value = umshFcsUpdate(value, octet);
  return (uint16_t)~value;
}

static Bytes wire(const Bytes& frame) {
  Bytes out(1, 0x7E);
  Bytes body = frame;
  uint16_t check = fcs(frame);
  body.push_back((uint8_t)check);
  body.push_back((uint8_t)(check >> 8));
  for (uint8_t octet : body) {
    if (octet == 0x7E || octet == 0x7D || octet == 0x11 || octet == 0x13) {
      out.push_back(0x7D);
      out.push_back(octet ^ 0x20);
    } else {
      out.push_back(octet);
    }
  }
  out.push_back(0x7E);
  return out;
}

static void putPui(Bytes& out, uint32_t value) {
  while (value >= 0x80) {
    out.push_back((uint8_t)(0x80 | (value & 0x7F)));
    value >>= 7;
  }
  out.push_back((uint8_t)value);
}

static Bytes propIs(uint8_t tid, uint32_t key, const Bytes& value) {
  Bytes frame = {(uint8_t)(0x80 | tid), UMSH_CMD_PROP_IS};
  putPui(frame, key);
  frame.insert(frame.end(), value.begin(), value.end());
  return frame;
}

static Bytes lastStatus(uint8_t tid, uint32_t status) {
  Bytes value;
  putPui(value, status);
  return propIs(tid, UMSH_PROP_LAST_STATUS, value);
}

struct Delivery {
  Bytes data;
  uint8_t kind;
  uint8_t flags;
  Bytes channel;
  Bytes source;
};

static Bytes recvFrame(const Delivery& message) {
  Bytes frame = {0x80, UMSH_CMD_STR_RECV};
  putPui(frame, UMSH_STR_NODE_MSG);
  frame.push_back((uint8_t)message.data.size());
  frame.push_back((uint8_t)(message.data.size() >> 8));
  frame.insert(frame.end(), message.data.begin(), message.data.end());
  frame.push_back(message.kind);
  frame.push_back(message.flags);
  frame.insert(frame.end(), message.channel.begin(), message.channel.end());
  frame.insert(frame.end(), message.source.begin(), message.source.end());
  return frame;
}

// ---- The line and the stub radio ----

struct Radio;
static Radio* radio = 0;

// The sketch's serial port: a 64-octet receive buffer, and a transmitter
// that takes each octet's time on the wire.
struct Port : public Stream {
  std::deque<uint8_t> rx;
  int overruns = 0;
  uint64_t octetNs = 10000000000ULL / 115200;

  // The wake rule, checked on every octet the library sends.
  uint64_t lastEnd = 0;
  bool everWrote = false;
  bool inPreamble = false;
  int fill = 0;
  uint64_t fillStart = 0;
  int violations = 0;
  int preambles = 0;

  size_t write(uint8_t octet);
  int available() { return (int)rx.size(); }
  int read() {
    if (rx.empty()) return -1;
    uint8_t octet = rx.front();
    rx.pop_front();
    return octet;
  }
  int peek() { return rx.empty() ? -1 : rx.front(); }
  void arrive(uint8_t octet) {
    if (rx.size() >= SERIAL_RX_BUFFER_SIZE) {
      overruns++;
    } else {
      rx.push_back(octet);
    }
  }
};

struct Radio {
  Port& port;
  explicit Radio(Port& p) : port(p) {}

  // Configuration.
  bool sleeps = true;
  int silentStarts = 0;
  bool nodeMessaging = true;
  int xonsToLose = 0;
  bool answerSends = true;
  uint32_t sendStatus = 0;
  uint64_t sendDelay = 0;
  bool damageNextOut = false;

  // Flow control. The window set takes effect at the next XON.
  uint16_t windowSet = 0;
  long permitted = -1;  // -1: no limit

  // Waking.
  uint64_t lastActive = 0;
  bool waking = false;
  uint64_t wokeAt = 0;

  // Receiving.
  Bytes current;
  bool escaped = false;
  bool skipping = false;

  bool live = true;
  std::deque<uint8_t> out;
  uint64_t nextOctet = 0;
  struct Due {
    uint64_t at;
    Bytes frame;
  };
  std::vector<Due> due;
  std::vector<Delivery> delivered;

  // What happened.
  std::vector<Bytes> sends;
  std::vector<Bytes> claims;
  int starts = 0;
  int lost = 0;
  int xons = 0;
  int wakes = 0;

  void boot(uint16_t window) {
    windowSet = window;
    permitted = window == 0 ? -1 : 0;
    live = true;
  }

  void queue(const Bytes& frame) {
    Bytes encoded = wire(frame);
    if (damageNextOut) {
      encoded[3] ^= 0x01;
      damageNextOut = false;
    }
    out.insert(out.end(), encoded.begin(), encoded.end());
  }

  void deliver(const Delivery& message) {
    delivered.push_back(message);
    queue(recvFrame(message));
  }

  bool asleep() const { return sleeps && nowNs - lastActive >= 250 * MS; }

  void receive(uint8_t octet) {
    if (asleep()) {
      wakes++;
      waking = true;
      wokeAt = nowNs;
    }
    lastActive = nowNs;
    if (waking) {
      // What arrives while the UART starts is lost; what comes after it,
      // up to a flag, is what is left of a preamble.
      if (nowNs - wokeAt >= 3 * MS && octet == 0x7E) waking = false;
      return;
    }
    if (octet == 0x11) {
      if (xonsToLose > 0) {
        xonsToLose--;
        return;
      }
      xons++;
      permitted = windowSet == 0 ? -1 : windowSet;
      return;
    }
    if (octet == 0x13) {
      permitted = 0;
      return;
    }
    if (skipping) {
      skipping = octet != 0x7E;
      return;
    }
    if (octet == 0x7E) {
      Bytes frame;
      frame.swap(current);
      bool aborted = escaped;
      escaped = false;
      if (frame.empty()) return;
      if (aborted || frame.size() < 2) {
        frameLost();
        return;
      }
      Bytes body(frame.begin(), frame.end() - 2);
      uint16_t check = fcs(body);
      if (frame[frame.size() - 2] != (uint8_t)check || frame[frame.size() - 1] != check >> 8) {
        frameLost();
        return;
      }
      handle(body);
      return;
    }
    if (current.empty() && !escaped && (octet == 0x23 || octet == 0xFF)) {
      skipping = true;
      return;
    }
    if (octet == 0x7D) {
      escaped = true;
      return;
    }
    if (escaped) {
      octet ^= 0x20;
      escaped = false;
    }
    current.push_back(octet);
  }

  void frameLost() {
    lost++;
    if (!live) return;
    live = false;
    due.clear();
    queue(Bytes{0x80, UMSH_CMD_SESSION_DID_END, 0});
  }

  void handle(const Bytes& frame) {
    uint8_t tid = frame[0] & 7;
    uint8_t command = frame[1];
    const uint8_t* at = frame.data() + 2;
    const uint8_t* end = frame.data() + frame.size();
    uint32_t key = 0;
    if (command >= UMSH_CMD_PROP_GET && command <= UMSH_CMD_PROP_REMOVE) {
      umshReadPui(at, end, &key);
    }
    Bytes value(at, end);
    if (command == UMSH_CMD_PROP_SET && key == UMSH_PROP_UART_WINDOW) {
      windowSet = (uint16_t)(value[0] | value[1] << 8);
      if (live && tid) queue(propIs(tid, key, value));
      return;
    }
    if (command == UMSH_CMD_SESSION_START) {
      if (silentStarts > 0) {
        silentStarts--;
        return;
      }
      starts++;
      live = true;
      due.clear();
      queue(Bytes{(uint8_t)(0x80 | tid), UMSH_CMD_SESSION_DID_START});
      // Every message delivered to the link before goes again.
      for (Delivery message : delivered) {
        message.flags |= 0x10;
        queue(recvFrame(message));
      }
      return;
    }
    if (!live) return;
    switch (command) {
      case UMSH_CMD_PROP_GET:
        if (key == UMSH_PROP_NODE_MSG_MTU && nodeMessaging) {
          queue(propIs(tid, key, Bytes{200, 0}));
        } else if (key == 6000) {
          queue(propIs(tid, key, Bytes{'a', 'b', 'c'}));
        } else {
          queue(lastStatus(tid, UMSH_STATUS_PROP_NOT_FOUND));
        }
        break;
      case UMSH_CMD_PROP_SET:
        if (key == UMSH_PROP_NODE_MSG_TYPES) {
          claims.push_back(value);
          queue(propIs(tid, key, value));
        } else if (key == UMSH_PROP_NODE_MSG_LISTEN) {
          queue(lastStatus(tid, UMSH_STATUS_NOT_PERMITTED));
        } else {
          queue(propIs(tid, key, value));
        }
        break;
      case UMSH_CMD_STR_SEND:
        sends.push_back(frame);
        if (answerSends && tid) due.push_back(Due{nowNs + sendDelay, lastStatus(tid, sendStatus)});
        break;
      default:
        queue(lastStatus(tid, UMSH_STATUS_INVALID_COMMAND));
        break;
    }
  }

  // The next moment something happens on the radio's side, or ~0.
  uint64_t next() const {
    uint64_t when = ~0ULL;
    for (const Due& d : due) when = d.at < when ? d.at : when;
    if (!out.empty() && permitted != 0) when = nextOctet < when ? nextOctet : when;
    return when;
  }

  void step() {
    for (size_t i = 0; i < due.size(); i++) {
      if (due[i].at <= nowNs) {
        queue(due[i].frame);
        due.erase(due.begin() + i);
        i--;
      }
    }
    if (!out.empty() && permitted != 0 && nextOctet <= nowNs) {
      port.arrive(out.front());
      out.pop_front();
      if (permitted > 0) permitted--;
      lastActive = nowNs;
      nextOctet = nowNs + port.octetNs;
    }
    if (nextOctet < nowNs) nextOctet = nowNs;
  }
};

static void advance(uint64_t ns) {
  uint64_t target = nowNs + ns;
  if (radio) {
    for (;;) {
      uint64_t when = radio->next();
      if (when > target) break;
      if (when > nowNs) nowNs = when;
      radio->step();
    }
  }
  nowNs = target;
}

size_t Port::write(uint8_t octet) {
  uint64_t start = nowNs;
  if (!everWrote || start - lastEnd >= 100 * MS) {
    // After a quiet, the first octet must begin a preamble.
    if (octet != 0xFF) {
      violations++;
      fprintf(stderr, "octet %02x after %llu ms quiet, no preamble\n", octet,
              (unsigned long long)((start - lastEnd) / MS));
    }
    inPreamble = octet == 0xFF;
    fill = 0;
    fillStart = start;
  }
  everWrote = true;
  if (inPreamble) {
    if (octet == 0xFF) {
      fill++;
    } else {
      if (octet != 0x7E || fill < 8 || start - fillStart < 5 * MS) {
        violations++;
        fprintf(stderr, "preamble of %d octets, %llu us\n", fill,
                (unsigned long long)((start - fillStart) / 1000));
      }
      preambles++;
      inPreamble = false;
    }
  }
  advance(octetNs);
  lastEnd = nowNs;
  if (radio) radio->receive(octet);
  return 1;
}

// ---- What the sketch hears ----

struct Heard {
  std::vector<Bytes> bodies;
  std::vector<bool> redelivered;
  std::vector<std::pair<uint8_t, UmshStatus> > results;
  int resets = 0;
  int texts = 0;
  std::vector<Bytes> textBodies;
};
static Heard heard;
static UmshRadio* sketchRadio = 0;
static UmshStatus nestedStatus = 0;

static void onMessage(const UmshMessage& m) {
  heard.bodies.push_back(Bytes(m.body(), m.body() + m.bodyLength()));
  heard.redelivered.push_back(m.redelivered());
  // A blocking call here would overwrite the message: it is refused.
  if (sketchRadio) {
    uint8_t one = 1;
    nestedStatus = sketchRadio->sendAndWait(UmshDest::broadcast(), 0x80, &one, 1, 1000);
  }
}
static void onResult(uint8_t ticket, UmshStatus status) {
  heard.results.push_back(std::make_pair(ticket, status));
}
static void onReset() { heard.resets++; }
static void onText(const UmshMessage& m, const UmshText& t) {
  heard.texts++;
  heard.textBodies.push_back(Bytes(t.body(), t.body() + t.bodyLength()));
  if (sketchRadio) sketchRadio->replyText(m, t, "pong");
}

// A sketch and a radio, wired together.
struct Bench {
  Port port;
  Radio stub;
  UmshRadio umsh;

  explicit Bench(uint16_t radioWindow = 0) : stub(port), umsh(port) {
    nowNs += 10 * 1000 * MS;
    radio = &stub;
    stub.boot(radioWindow);
    stub.lastActive = nowNs;
    heard = Heard();
    sketchRadio = 0;
    umsh.onMessage(onMessage);
    umsh.onSendResult(onResult);
    umsh.onLinkReset(onReset);
  }
  ~Bench() { radio = 0; }

  // Poll every `everyMs` for `ms`.
  void run(uint32_t ms, uint32_t everyMs = 1) {
    uint64_t end = nowNs + ms * MS;
    while (nowNs < end) {
      umsh.poll();
      advance(everyMs * MS);
    }
  }

  void start(uint8_t claim = 0x80) {
    umsh.setClaims(claim);
    umsh.begin();
    run(200);
  }
};

static Delivery message(const Bytes& data, uint8_t flags = 0x01) {
  Delivery m;
  m.data = data;
  m.kind = UMSH_UNICAST;
  m.flags = flags;
  m.source = Bytes(32, 0xA5);
  return m;
}

// ---- The vector file ----

typedef std::map<std::string, std::string> Fields;

static std::vector<Fields> cases(const std::vector<std::string>& lines, const std::string& kind) {
  std::vector<Fields> found;
  for (const std::string& line : lines) {
    std::istringstream words(line);
    std::string first;
    words >> first;
    if (first != kind) continue;
    Fields fields;
    std::string word;
    while (words >> word) {
      size_t eq = word.find('=');
      fields[word.substr(0, eq)] = word.substr(eq + 1);
    }
    found.push_back(fields);
  }
  CHECK(!found.empty());
  return found;
}

struct Capture : public Print {
  Bytes octets;
  size_t write(uint8_t octet) {
    octets.push_back(octet);
    return 1;
  }
};

static Bytes decodeOne(const Bytes& octets) {
  uint8_t buffer[UMSH_FRAME_MAX + 2];
  UmshDecoder decoder(buffer, sizeof buffer);
  Bytes frame;
  int frames = 0;
  for (uint8_t octet : octets) {
    if (decoder.push(octet) == UmshDecoder::FRAME) {
      frames++;
      frame.assign(decoder.frame(), decoder.frame() + decoder.length());
    }
  }
  CHECK_EQ(frames, 1);
  return frame;
}

static std::string textField(const UmshText& t, const std::string& name) {
  if (name == "type") return std::to_string(t.type());
  if (name == "handle") return hexOf(t.handle(), t.handleLength());
  if (name == "seq") {
    if (!t.hasSequence()) return "-";
    Bytes seq(1, t.messageId());
    if (t.isFragment()) {
      seq.push_back(t.fragmentIndex());
      seq.push_back(t.fragmentCount());
    }
    return hexOf(seq);
  }
  if (name == "reset") return t.sequenceReset() ? "1" : "0";
  if (name == "regarding") return hexOf(t.regarding(), t.regardingLength());
  if (name == "editing") return t.hasEditing() ? std::to_string(t.editing()) : "-";
  if (name == "body") return hexOf(t.body(), t.bodyLength());
  return "?";
}

static void checkText(const Bytes& data, const Fields& f) {
  UmshText t;
  bool ok = UmshText::decode(data.data(), (uint16_t)data.size(), t);
  if (f.count("ok") && f.at("ok") == "0") {
    CHECK(!ok);
    return;
  }
  CHECK(ok);
  const char* names[] = {"type", "handle", "seq", "reset", "regarding", "editing", "body"};
  for (const char* name : names) {
    if (textField(t, name) != f.at(name)) {
      failures++;
      fprintf(stderr, "text %s: %s is %s, expected %s\n", f.at("data").c_str(), name,
              textField(t, name).c_str(), f.at(name).c_str());
    }
  }
}

static void testVectors(const char* path) {
  std::ifstream file(path);
  CHECK(file.good());
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(file, line)) lines.push_back(line);

  for (const Fields& f : cases(lines, "pui")) {
    Capture capture;
    UmshEncoder encoder(capture);
    uint32_t value = (uint32_t)strtoul(f.at("value").c_str(), 0, 10);
    encoder.putPui(value);
    CHECK(hexOf(capture.octets) == f.at("hex"));
    CHECK_EQ(umshPuiLength(value), capture.octets.size());
    const uint8_t* at = capture.octets.data();
    uint32_t decoded = 0;
    CHECK(umshReadPui(at, at + capture.octets.size(), &decoded));
    CHECK_EQ(decoded, value);
  }

  for (const Fields& f : cases(lines, "hdlc")) {
    Bytes frame = hex(f.at("frame"));
    Capture capture;
    UmshEncoder encoder(capture);
    encoder.begin(frame[0] & 7, frame[1]);
    encoder.put(frame.data() + 2, (uint16_t)(frame.size() - 2));
    encoder.end();
    CHECK(hexOf(capture.octets) == f.at("wire"));
    CHECK(decodeOne(capture.octets) == frame);
  }

  for (const Fields& f : cases(lines, "send")) {
    uint8_t kind = (uint8_t)atoi(f.at("kind").c_str());
    uint8_t flags = (uint8_t)atoi(f.at("flags").c_str());
    Bytes channel = hex(f.at("channel")), peer = hex(f.at("peer")), route = hex(f.at("route"));
    Bytes data = hex(f.at("data"));
    UmshDest dest;
    switch (kind) {
      case UMSH_UNICAST: dest = UmshDest::peer(peer.data()); break;
      case UMSH_BROADCAST: dest = UmshDest::broadcast(); break;
      case UMSH_BLIND_UNICAST: dest = UmshDest::blind(channel.data(), peer.data()); break;
      default: dest = UmshDest::channel(channel.data()); break;
    }
    UmshSendOptions options;
    options.ack = flags & 1;
    options.fullSource = flags & 2;
    options.sign = flags & 4;
    if (f.at("hops") != "-") options.floodHops = (int8_t)atoi(f.at("hops").c_str());
    if (!route.empty()) {
      options.route = route.data();
      options.routeHints = (uint8_t)(route.size() / 2);
    }
    if (f.at("power") != "-") {
      options.setTxPower = true;
      options.txPower = (int8_t)atoi(f.at("power").c_str());
    }
    CHECK_EQ(UmshRadio::checkSend(dest, (uint16_t)data.size(), options), UMSH_STATUS_OK);
    Capture capture;
    UmshEncoder encoder(capture);
    encoder.begin((uint8_t)atoi(f.at("tid").c_str()), UMSH_CMD_STR_SEND);
    UmshRadio::writeSend(encoder, dest, data[0], 0, 0, data.data() + 1,
                         (uint16_t)(data.size() - 1), options);
    encoder.end();
    if (hexOf(decodeOne(capture.octets)) != f.at("frame")) {
      failures++;
      fprintf(stderr, "send %s\n  is %s\n", f.at("frame").c_str(),
              hexOf(decodeOne(capture.octets)).c_str());
    }
  }

  for (const Fields& f : cases(lines, "recv")) {
    Bytes frame = hex(f.at("frame"));
    UmshMessage m;
    CHECK(UmshMessage::parse(frame.data() + 2, (uint16_t)(frame.size() - 2), m));
    Bytes data(1, m.payloadType());
    data.insert(data.end(), m.body(), m.body() + m.bodyLength());
    CHECK(hexOf(data) == f.at("data"));
    CHECK_EQ(m.kind(), atoi(f.at("kind").c_str()));
    uint8_t flags = (uint8_t)atoi(f.at("flags").c_str());
    CHECK_EQ(m.hasSourceKey(), (flags & 1) != 0);
    CHECK_EQ(m.senderAuthenticated(), (flags & 2) != 0);
    CHECK_EQ(m.acked(), (flags & 4) != 0);
    CHECK_EQ(m.gap(), (flags & 8) != 0);
    CHECK_EQ(m.redelivered(), (flags & 16) != 0);
    CHECK(hexOf(m.channel(), m.channel() ? 16 : 0) == f.at("channel"));
    CHECK(hexOf(m.source(), m.sourceLength()) == f.at("src"));
    CHECK((m.hasRssi() ? std::to_string(m.rssi()) : "-") == f.at("rssi"));
    CHECK((m.hasSnr() ? std::to_string(m.snr()) : "-") == f.at("snr"));
    CHECK(hexOf(m.trace(), 2 * m.traceHints()) == f.at("trace"));
  }

  for (const Fields& f : cases(lines, "text")) {
    Bytes data = hex(f.at("data"));
    Bytes handle = hex(f.at("handle")), seq = hex(f.at("seq")), regarding = hex(f.at("regarding"));
    Bytes body = hex(f.at("body"));
    std::string handleText(handle.begin(), handle.end());
    UmshTextOptions options;
    options.type = (uint8_t)atoi(f.at("type").c_str());
    if (!handle.empty()) options.handle = handleText.c_str();
    if (!seq.empty()) {
      options.hasSequence = true;
      options.messageId = seq[0];
    }
    options.sequenceReset = f.at("reset") == "1";
    options.regardingLength = (uint8_t)regarding.size();
    memcpy(options.regarding, regarding.data(), regarding.size());
    if (f.at("editing") != "-") {
      options.hasEditing = true;
      options.editing = (uint8_t)atoi(f.at("editing").c_str());
    }
    uint8_t out[256];
    int16_t length = UmshText::encode(out, sizeof out, body.data(), (uint16_t)body.size(), options);
    CHECK(length >= 0);
    CHECK(hexOf(out, length < 0 ? 0 : length) == f.at("data"));
    checkText(data, f);
  }

  for (const Fields& f : cases(lines, "textin")) checkText(hex(f.at("data")), f);
}

// ---- Behavior ----

static void testStartAndClaims() {
  Bench bench(30);
  bench.start(0x80);
  CHECK(bench.umsh.ready());
  CHECK_EQ(bench.umsh.mtu(), 200);
  CHECK_EQ(bench.stub.starts, 1);
  CHECK_EQ(bench.stub.windowSet, 30);
  CHECK_EQ(bench.stub.claims.size(), 1u);
  CHECK(bench.stub.claims.size() == 1 && bench.stub.claims[0] == Bytes{0x80});
  CHECK_EQ(bench.umsh.claimStatus(), UMSH_STATUS_OK);
  CHECK_EQ(heard.resets, 0);
  CHECK_EQ(bench.port.violations, 0);
}

static void testLongFrameWhileBlocking() {
  Bench bench(30);
  bench.start();
  // The longest payload a unicast carries, arriving while the sketch
  // polls only every half second: one window waits in the buffer, and the
  // poll that finds it reads the rest of the frame.
  Bytes data(226, 0);
  data[0] = 0x80;
  for (size_t i = 1; i < data.size(); i++) data[i] = (uint8_t)(i * 7);
  data[5] = 0x7E;
  data[6] = 0x11;
  data[7] = 0x13;
  bench.stub.deliver(message(data));
  bench.run(20000, 500);
  CHECK_EQ(heard.bodies.size(), 1u);
  CHECK(heard.bodies.size() == 1 && heard.bodies[0] == Bytes(data.begin() + 1, data.end()));
  CHECK_EQ(bench.port.overruns, 0);
  CHECK_EQ(bench.stub.lost, 0);
  CHECK_EQ(heard.resets, 0);
  CHECK_EQ(bench.port.violations, 0);
  // The radio slept before the message, and the first XON woke it.
  CHECK(bench.stub.wakes >= 1);
}

static void testLostXon() {
  Bench bench(30);
  bench.start();
  bench.stub.xonsToLose = 1;
  Bytes data(120, 0x55);
  data[0] = 0x80;
  bench.stub.deliver(message(data));
  bench.run(5000, 10);
  CHECK_EQ(heard.bodies.size(), 1u);
  CHECK_EQ(bench.port.overruns, 0);
  CHECK_EQ(heard.resets, 0);
  CHECK_EQ(bench.port.violations, 0);
}

static void testDamagedFrameFromRadio() {
  Bench bench(30);
  bench.start();
  bench.stub.sendDelay = 2000 * MS;
  uint8_t body[] = {1, 2, 3};
  uint8_t key[32] = {7};
  uint8_t ticket = bench.umsh.send(UmshDest::peer(key), 0x80, body, sizeof body);
  CHECK(ticket != 0);
  bench.run(50);
  // A message damaged on the way: the library starts a new session.
  bench.stub.damageNextOut = true;
  bench.stub.deliver(message(Bytes{0x80, 9}));
  bench.run(3000, 5);
  CHECK_EQ(bench.stub.starts, 2);
  CHECK(bench.umsh.ready());
  CHECK_EQ(heard.resets, 1);
  // The ticket ends once, unknown; the answer the old session owed never
  // comes, and nothing from it is taken for an answer in the new one.
  CHECK_EQ(heard.results.size(), 1u);
  CHECK(heard.results.size() == 1 && heard.results[0] == std::make_pair(ticket, UMSH_LINK_RESET));
  // The damaged message is delivered again, flagged.
  CHECK_EQ(heard.bodies.size(), 1u);
  CHECK(heard.redelivered.size() == 1 && heard.redelivered[0]);
  CHECK_EQ(bench.port.violations, 0);
}

static void testDamagedFrameToRadio() {
  Bench bench(30);
  bench.start();
  uint8_t key[32] = {7};
  uint8_t body[] = {1};
  bench.stub.answerSends = false;
  uint8_t ticket = bench.umsh.send(UmshDest::peer(key), 0x80, body, 1);
  bench.run(10);
  // A frame the radio cannot read: it ends the session, and the library
  // starts another.
  bench.port.write(0x7E);
  bench.port.write(0x81);
  bench.port.write(0x02);
  bench.port.write(0x7E);
  bench.run(3000, 5);
  CHECK_EQ(bench.stub.lost, 1);
  CHECK_EQ(bench.stub.starts, 2);
  CHECK(bench.umsh.ready());
  CHECK_EQ(heard.resets, 1);
  CHECK(heard.results.size() == 1 && heard.results[0] == std::make_pair(ticket, UMSH_LINK_RESET));
}

static void testRadioStillBooting() {
  Bench bench(30);
  bench.stub.silentStarts = 2;
  bench.umsh.begin();
  bench.run(500);
  CHECK(!bench.umsh.ready());
  bench.run(3000);
  CHECK(bench.umsh.ready());
  CHECK_EQ(bench.stub.starts, 1);
  CHECK_EQ(heard.resets, 0);
  CHECK_EQ(bench.port.violations, 0);
}

static void testUnpacedRadioAlreadySending() {
  // A radio with a window of 0 starts permitted, and is already sending
  // when the sketch begins: nothing it sends is lost, and what came before
  // the session is delivered again in it.
  Bench bench(0);
  for (int i = 0; i < 4; i++) bench.stub.deliver(message(Bytes{0x80, (uint8_t)i}));
  bench.umsh.setClaims(0x80);
  bench.umsh.begin();
  bench.run(3000);
  CHECK(bench.umsh.ready());
  CHECK_EQ(bench.port.overruns, 0);
  CHECK_EQ(heard.bodies.size(), 4u);
  for (size_t i = 0; i < heard.bodies.size(); i++) {
    CHECK(heard.bodies[i] == Bytes{(uint8_t)i});
  }
}

static void testMarkedTextIsSkipped() {
  Bench bench(30);
  bench.start();
  const char* line = "#boot: hello";
  bench.stub.out.push_back(0x7E);
  for (const char* c = line; *c; c++) bench.stub.out.push_back((uint8_t)*c);
  bench.stub.out.push_back(0x7E);
  bench.stub.deliver(message(Bytes{0x80, 1}));
  bench.run(1000);
  CHECK_EQ(heard.bodies.size(), 1u);
  CHECK_EQ(heard.resets, 0);
}

static void testSendAndWait() {
  Bench bench(30);
  bench.start();
  bench.stub.sendDelay = 3000 * MS;
  bench.stub.sendStatus = UMSH_STATUS_NO_ACK;
  uint8_t key[32] = {1};
  uint8_t body[] = {9};
  // Polling inside the wait still delivers what arrives.
  bench.stub.deliver(message(Bytes{0x80, 4}));
  UmshStatus status = bench.umsh.sendAndWait(UmshDest::peer(key), 0x80, body, 1);
  CHECK_EQ(status, UMSH_STATUS_NO_ACK);
  CHECK_EQ(heard.bodies.size(), 1u);
  CHECK(heard.results.empty());
  // Refused inside a callback.
  sketchRadio = &bench.umsh;
  nestedStatus = 0;
  bench.stub.deliver(message(Bytes{0x80, 5}));
  bench.run(500);
  CHECK_EQ(nestedStatus, UMSH_IN_CALLBACK);
  // The sends went out acknowledged, to the key given.
  CHECK(!bench.stub.sends.empty());
  CHECK_EQ(bench.port.violations, 0);
}

static void testTextEcho() {
  Bench bench(30);
  bench.umsh.onText(onText);
  bench.start(UMSH_PAYLOAD_TEXT);
  sketchRadio = &bench.umsh;
  // "ping" with message ID 12, from a peer.
  Bytes data = {UMSH_PAYLOAD_TEXT, 0x21, 12, 0xFF, 'p', 'i', 'n', 'g'};
  bench.stub.deliver(message(data, 0x03));
  bench.run(1000);
  CHECK_EQ(heard.texts, 1);
  CHECK(heard.textBodies.size() == 1 && heard.textBodies[0] == (Bytes{'p', 'i', 'n', 'g'}));
  CHECK_EQ(bench.stub.sends.size(), 1u);
  if (bench.stub.sends.size() == 1) {
    UmshFrame frame = {0, 0, bench.stub.sends[0].data() + 2,
                       (uint16_t)(bench.stub.sends[0].size() - 2)};
    // A reply to message 12, to the sender's key, acknowledged.
    Bytes expected = {UMSH_PAYLOAD_TEXT, 0x41, 12, 0xFF, 'p', 'o', 'n', 'g', UMSH_UNICAST, 1};
    expected.insert(expected.end(), 32, 0xA5);
    Bytes sent(frame.payload + 3, frame.payload + frame.length);
    CHECK(hexOf(sent) == hexOf(expected));
  }
}

static void testRadioThatStopsAnswering() {
  Bench bench(30);
  bench.start();
  bench.stub.answerSends = false;
  uint8_t key[32] = {1};
  uint8_t body[] = {9};
  uint8_t ticket = bench.umsh.send(UmshDest::peer(key), 0x80, body, 1);
  bench.run(59000, 100);
  CHECK(heard.results.empty());
  bench.run(3000, 100);
  CHECK(heard.results.size() == 1 && heard.results[0] == std::make_pair(ticket, UMSH_LINK_RESET));
  CHECK_EQ(bench.stub.starts, 2);
  CHECK(bench.umsh.ready());
}

static void testRadioWithoutNodeMessaging() {
  Bench bench(30);
  bench.stub.nodeMessaging = false;
  bench.start();
  CHECK(!bench.umsh.ready());
  CHECK_EQ(bench.umsh.status(), UMSH_UNSUPPORTED);
  uint8_t body[] = {1};
  CHECK_EQ(bench.umsh.send(UmshDest::broadcast(), 0x80, body, 1), 0);
  CHECK_EQ(bench.umsh.lastError(), UMSH_UNSUPPORTED);
  // The link itself still answers.
  uint8_t value[8];
  uint16_t length = 0;
  CHECK_EQ(bench.umsh.getProperty(6000, value, sizeof value, &length), UMSH_STATUS_OK);
  CHECK(length == 3 && memcmp(value, "abc", 3) == 0);
}

static void testRadioRestart() {
  Bench bench(30);
  bench.start();
  // The radio restarts: it has no permission, and says why it restarted
  // once it is given some.
  bench.stub.boot(30);
  bench.stub.queue(lastStatus(0, 112));
  bench.run(40000, 100);
  CHECK_EQ(bench.stub.starts, 2);
  CHECK(bench.umsh.ready());
  CHECK_EQ(heard.resets, 1);
  CHECK_EQ(bench.port.violations, 0);
}

// A frame of the longest length arrives whole; one longer, from a radio
// that breaks the limit, is lost like a damaged one.
static void testFrameLimit() {
  Bench bench(30);
  bench.start();
  bench.stub.queue(propIs(0, 6002, Bytes(UMSH_FRAME_MAX - 4, 0x55)));
  bench.run(3000, 10);
  CHECK_EQ(bench.stub.starts, 1);
  bench.stub.queue(propIs(0, 6002, Bytes(UMSH_FRAME_MAX - 3, 0x55)));
  bench.run(3000, 10);
  CHECK_EQ(bench.stub.starts, 2);
  CHECK_EQ(heard.resets, 1);
  CHECK(bench.umsh.ready());
  CHECK_EQ(bench.port.overruns, 0);
  CHECK_EQ(bench.port.violations, 0);
}

static void testAddresses() {
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 37 + 1);
  char text[45];
  UmshAddress::format(key, text);
  CHECK_EQ(strlen(text), 44u);
  uint8_t back[32];
  CHECK(UmshAddress::parse(text, back));
  CHECK(memcmp(key, back, 32) == 0);
  uint8_t zero[32] = {0};
  UmshAddress::format(zero, text);
  CHECK(std::string(text) == std::string(44, '1'));
  // One past the largest 32-octet value does not parse.
  CHECK(!UmshAddress::parse("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", back));
  CHECK(!UmshAddress::parse("0OIl", back));
  char hexText[65];
  UmshAddress::formatHex(key, 32, hexText);
  CHECK(UmshAddress::parse(hexText, back) && memcmp(key, back, 32) == 0);
  uint8_t id[16];
  CHECK(UmshAddress::parseChannel("00112233445566778899aabbccddeeff", id) && id[15] == 0xFF);
}

int main(int argc, char** argv) {
  testVectors(argc > 1 ? argv[1] : "vectors.txt");
  testAddresses();
  testStartAndClaims();
  testLongFrameWhileBlocking();
  testLostXon();
  testDamagedFrameFromRadio();
  testDamagedFrameToRadio();
  testRadioStillBooting();
  testUnpacedRadioAlreadySending();
  testMarkedTextIsSkipped();
  testSendAndWait();
  testTextEcho();
  testRadioThatStopsAnswering();
  testRadioWithoutNodeMessaging();
  testRadioRestart();
  testFrameLimit();
  if (failures) {
    fprintf(stderr, "%d failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}
