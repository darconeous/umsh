#include "UmshLink.h"

#include <string.h>

// A little under half the receive buffer: an XON sent again after a loss
// can leave two windows on their way.
#if defined(SERIAL_RX_BUFFER_SIZE)
static const uint16_t DEFAULT_WINDOW = SERIAL_RX_BUFFER_SIZE / 2 - 2;
#else
static const uint16_t DEFAULT_WINDOW = 30;
#endif

// A reader that has sent nothing for 100 ms sends a wake preamble before
// its next octet. The time measured runs from when the last octet was
// handed to the port, never later than it left, so it errs toward a
// preamble; the margin covers millis() stepping by two.
static const uint32_t WAKE_QUIET_MS = 100 - 10;
// The preamble's fill: at least 8 octets, lasting at least 5 ms.
static const uint32_t WAKE_FILL_US = 5000;
static const uint16_t WAKE_FILL_MIN = 8;
// Bounds the fill when the port's flush() does not wait for the wire.
static const uint16_t WAKE_FILL_MAX = 512;
// A session start with no answer is sent again after this long.
static const uint32_t START_RESEND_MS = 1000;
// Partway through a window with nothing arriving: an octet was lost, or
// an XON was, so permission is granted again.
static const uint32_t STALL_MS = 1000;
// poll() waits this long for the rest of a frame that has stopped coming.
static const uint32_t FRAME_WAIT_MS = 50;

UmshLink::UmshLink(Stream& io)
    : io_(io), encoder_(io), decoder_(rx_, sizeof rx_), state_(IDLE), held_(false),
      everSent_(false), resetPending_(false), inCallback_(0), window_(DEFAULT_WINDOW),
      sinceXon_(0), lastReceived_(0), lastXon_(0), lastSent_(0), startSent_(0),
      replyLimit_(60000), xonRefresh_(30000), outstanding_(0), nextTid_(1), frameHook_(0),
      resetHook_(0) {
  waiter_.tid = 0;
  waiter_.done = false;
}

void UmshLink::begin() { begin(DEFAULT_WINDOW); }

void UmshLink::begin(uint16_t window) {
  window_ = window;
  held_ = false;
  decoder_.reset();
  restart();
  // A first session is not a reset.
  resetPending_ = false;
}

bool UmshLink::ready() const { return state_ == OPEN; }

bool UmshLink::waitReady(uint32_t timeoutMs) {
  // Inside a callback poll() reads nothing, so there is nothing to wait for.
  if (inCallback_) return ready();
  uint32_t start = millis();
  while (!ready() && millis() - start < timeoutMs) poll();
  return ready();
}

// ---- Sending ----

void UmshLink::wake() {
  if (everSent_ && millis() - lastSent_ < WAKE_QUIET_MS) return;
  everSent_ = true;
  // Fill for 8 octets and 5 ms, then a flag. Flushing after each octet
  // past the eighth times the fill by the wire, whatever the baud rate.
  uint32_t start = micros();
  for (uint16_t sent = 1;; sent++) {
    io_.write(UMSH_HDLC_FILL);
    if (sent < WAKE_FILL_MIN) continue;
    io_.flush();
    if (micros() - start >= WAKE_FILL_US || sent >= WAKE_FILL_MAX) break;
  }
  io_.write(UMSH_HDLC_FLAG);
}

void UmshLink::sent() { lastSent_ = millis(); }

void UmshLink::flow(uint8_t octet) {
  wake();
  io_.write(octet);
  sent();
}

void UmshLink::grant() {
  flow(UMSH_HDLC_XON);
  sinceXon_ = 0;
  lastXon_ = millis();
}

void UmshLink::hold() {
  held_ = true;
  if (state_ != IDLE) flow(UMSH_HDLC_XOFF);
}

void UmshLink::release() {
  held_ = false;
  if (state_ != IDLE) grant();
}

UmshEncoder& UmshLink::frameBegin(uint8_t tid, uint8_t command) {
  wake();
  encoder_.begin(tid, command);
  return encoder_;
}

void UmshLink::frameEnd() {
  encoder_.end();
  sent();
}

uint8_t UmshLink::allocTid() {
  for (uint8_t tries = 0; tries < 7; tries++) {
    uint8_t tid = nextTid_;
    nextTid_ = tid == 7 ? 1 : tid + 1;
    if (!(outstanding_ & (1 << tid))) {
      outstanding_ |= (uint8_t)(1 << tid);
      sentAt_[tid] = millis();
      return tid;
    }
  }
  return 0;
}

// ---- Sessions ----

// A reader that does not know the radio's state withdraws permission,
// sets the window, starts the session, and only then permits again, so
// the window is in force before the first octet. All of it goes again with
// every resend, since any of it can vanish with the request. The window
// is set with TID 0: an answer would come before the boundary and be
// discarded.
void UmshLink::startSession() {
  state_ = STARTING;
  flow(UMSH_HDLC_XOFF);
  uint8_t value[2] = {(uint8_t)window_, (uint8_t)(window_ >> 8)};
  UmshEncoder& out = frameBegin(0, UMSH_CMD_PROP_SET);
  out.putPui(UMSH_PROP_UART_WINDOW);
  out.put(value, 2);
  frameEnd();
  frameBegin(1, UMSH_CMD_SESSION_START);
  frameEnd();
  if (!held_) grant();
  startSent_ = millis();
}

// The session is lost: start a new one, and complete every request of the
// old one, which will never be answered.
void UmshLink::restart() {
  if (state_ == OPEN) resetPending_ = true;
  uint8_t lost = outstanding_;
  outstanding_ = 0;
  nextTid_ = 2;
  startSession();
  for (uint8_t tid = 1; tid <= 7; tid++) {
    if (lost & (1 << tid)) failed(tid, UMSH_LINK_RESET);
  }
}

void UmshLink::sessionOpened() { linkReady(); }

void UmshLink::linkReady() {
  if (!resetPending_) return;
  resetPending_ = false;
  if (resetHook_) {
    Callback callback(*this);
    resetHook_();
  }
}

// ---- Receiving ----

void UmshLink::poll() {
  // Inside a callback the frame being handled is still in the buffer.
  if (state_ == IDLE || inCallback_) return;
  uint32_t progress = millis();
  for (;;) {
    while (io_.available() > 0) {
      int next = io_.read();
      if (next < 0) break;
      lastReceived_ = progress = millis();
      octet((uint8_t)next);
    }
    // A frame in progress is read to its end, so a long one does not take
    // a pass of loop() per window.
    if (!decoder_.inFrame() || millis() - progress >= FRAME_WAIT_MS) break;
  }

  uint32_t now = millis();
  if (state_ == STARTING && now - startSent_ >= START_RESEND_MS) startSession();
  if (state_ == OPEN) {
    for (uint8_t tid = 1; tid <= 7; tid++) {
      if ((outstanding_ & (1 << tid)) && now - sentAt_[tid] >= replyLimit_) {
        // A reply that never comes is a session-level error.
        restart();
        break;
      }
    }
  }
  if (window_ != 0 && !held_ && state_ != IDLE) {
    uint32_t quiet = now - lastReceived_;
    uint32_t sinceXon = now - lastXon_;
    // Partway through a frame, or a window, the radio has more to send.
    bool partway = decoder_.inFrame() || sinceXon_ != 0;
    bool stalled = partway && quiet >= STALL_MS && sinceXon >= STALL_MS;
    bool idle = quiet >= xonRefresh_ && sinceXon >= xonRefresh_;
    if (stalled || idle) grant();
  }
  service();
}

void UmshLink::octet(uint8_t octet) {
  if (sinceXon_ != 0xFFFF) sinceXon_++;
  UmshDecoder::Event event = decoder_.push(octet);
  if (window_ != 0 && !held_) {
    // A spent window is granted again at once, and a frame's end tops up
    // a window it left partly spent: the radio may have more to say and
    // waits for nothing else.
    if (sinceXon_ >= window_ || (event != UmshDecoder::NONE && sinceXon_ != 0)) grant();
  }
  switch (event) {
    case UmshDecoder::NONE:
      break;
    case UmshDecoder::FRAME:
      dispatch(decoder_.frame(), decoder_.length());
      break;
    case UmshDecoder::LOST:
      // A frame that belongs to the session being left is no loss of the
      // one to come.
      if (state_ == OPEN) restart();
      break;
  }
}

// The status a PROP_IS of PROP_LAST_STATUS carries, or -1 for none.
static int32_t lastStatus(const UmshFrame& frame) {
  if (frame.command != UMSH_CMD_PROP_IS) return -1;
  const uint8_t* at = frame.payload;
  const uint8_t* end = at + frame.length;
  uint32_t key, status;
  if (!umshReadPui(at, end, &key) || key != UMSH_PROP_LAST_STATUS) return -1;
  if (!umshReadPui(at, end, &status)) return -1;
  return (int32_t)status;
}

void UmshLink::dispatch(const uint8_t* bytes, uint16_t length) {
  if (length < 2) return;
  uint8_t header = bytes[0];
  // Not a ULCP frame, or one this version must ignore.
  if ((header & 0xF8) != 0x80 || (bytes[1] & 0x80)) return;
  UmshFrame frame;
  frame.tid = header & 0x07;
  frame.command = bytes[1];
  frame.payload = bytes + 2;
  frame.length = length - 2;

  if (state_ == STARTING) {
    // Every frame before the answer belongs to the session that ended. A
    // radio that predates sessions says so, and goes on without them.
    if (frame.command == UMSH_CMD_SESSION_DID_START ||
        (frame.tid == 1 && lastStatus(frame) == UMSH_STATUS_INVALID_COMMAND)) {
      state_ = OPEN;
      sessionOpened();
    }
    return;
  }
  if (frame.command == UMSH_CMD_SESSION_DID_END) {
    restart();
    return;
  }
  int32_t status = lastStatus(frame);
  if (frame.tid == 0 && status >= UMSH_STATUS_RESET_FIRST && status <= UMSH_STATUS_RESET_LAST) {
    // The radio restarted, and nothing asked before it will be answered.
    restart();
    return;
  }
  // An answer to a start sent again: the radio handled it before anything
  // sent since.
  if (frame.command == UMSH_CMD_SESSION_DID_START) return;
  if (frame.tid != 0) {
    uint8_t bit = (uint8_t)(1 << frame.tid);
    if (outstanding_ & bit) {
      outstanding_ &= (uint8_t)~bit;
      answered(frame.tid, frame);
    }
    return;
  }
  unsolicited(frame);
}

void UmshLink::unsolicited(const UmshFrame& frame) {
  if (frameHook_) {
    Callback callback(*this);
    frameHook_(frame);
  }
}

// ---- Blocking property requests ----

void UmshLink::answered(uint8_t tid, const UmshFrame& frame) {
  if (tid != waiter_.tid || waiter_.done) return;
  waiter_.done = true;
  const uint8_t* at = frame.payload;
  const uint8_t* end = at + frame.length;
  uint32_t key;
  bool item = frame.command == UMSH_CMD_PROP_INSERTED || frame.command == UMSH_CMD_PROP_REMOVED;
  if ((frame.command != UMSH_CMD_PROP_IS && !item) || !umshReadPui(at, end, &key)) {
    waiter_.status = UMSH_UNEXPECTED;
    return;
  }
  if (key == UMSH_PROP_LAST_STATUS && waiter_.key != UMSH_PROP_LAST_STATUS) {
    uint32_t status;
    waiter_.status = umshReadPui(at, end, &status) ? (UmshStatus)status : UMSH_UNEXPECTED;
    return;
  }
  if (key != waiter_.key) {
    waiter_.status = UMSH_UNEXPECTED;
    return;
  }
  uint16_t length = (uint16_t)(end - at);
  waiter_.length = length;
  if (!waiter_.out) {
    waiter_.status = UMSH_STATUS_OK;
  } else if (length > waiter_.capacity) {
    waiter_.status = UMSH_TOO_LONG;
  } else {
    memcpy(waiter_.out, at, length);
    waiter_.status = UMSH_STATUS_OK;
  }
}

void UmshLink::failed(uint8_t tid, UmshStatus why) {
  if (tid != waiter_.tid || waiter_.done) return;
  waiter_.done = true;
  waiter_.status = why;
}

UmshStatus UmshLink::request(uint8_t command, uint32_t key, const uint8_t* value,
                             uint16_t length, uint8_t* out, uint16_t capacity,
                             uint16_t* outLength, uint32_t timeoutMs) {
  if (outLength) *outLength = 0;
  if (inCallback_) return UMSH_IN_CALLBACK;
  if (2u + umshPuiLength(key) + length > UMSH_FRAME_MAX) return UMSH_TOO_LONG;
  uint32_t start = millis();
  uint8_t tid = 0;
  while (!(state_ == OPEN && (tid = allocTid()) != 0)) {
    if (millis() - start >= timeoutMs) return state_ == OPEN ? UMSH_NO_TICKET : UMSH_NOT_READY;
    poll();
  }
  waiter_.tid = tid;
  waiter_.done = false;
  waiter_.command = command;
  waiter_.key = key;
  waiter_.out = out;
  waiter_.capacity = capacity;
  waiter_.length = 0;
  waiter_.status = UMSH_TIMEOUT;
  UmshEncoder& frame = frameBegin(tid, command);
  frame.putPui(key);
  frame.put(value, length);
  frameEnd();
  while (!waiter_.done && millis() - start < timeoutMs) poll();
  // An answer after this is discarded; its TID stays taken until then.
  waiter_.tid = 0;
  if (!waiter_.done) return UMSH_TIMEOUT;
  if (outLength) *outLength = waiter_.length;
  return waiter_.status;
}

UmshStatus UmshLink::getProperty(uint32_t key, uint8_t* value, uint16_t capacity,
                                 uint16_t* length, uint32_t timeoutMs) {
  return request(UMSH_CMD_PROP_GET, key, 0, 0, value, capacity, length, timeoutMs);
}

UmshStatus UmshLink::setProperty(uint32_t key, const uint8_t* value, uint16_t length,
                                 uint32_t timeoutMs) {
  return request(UMSH_CMD_PROP_SET, key, value, length, 0, 0, 0, timeoutMs);
}

UmshStatus UmshLink::insertProperty(uint32_t key, const uint8_t* item, uint16_t length,
                                    uint32_t timeoutMs) {
  return request(UMSH_CMD_PROP_INSERT, key, item, length, 0, 0, 0, timeoutMs);
}

UmshStatus UmshLink::removeProperty(uint32_t key, const uint8_t* item, uint16_t length,
                                    uint32_t timeoutMs) {
  return request(UMSH_CMD_PROP_REMOVE, key, item, length, 0, 0, 0, timeoutMs);
}
