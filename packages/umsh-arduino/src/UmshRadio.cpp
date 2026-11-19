#include "UmshRadio.h"

#include <string.h>

// Octets from `at` to `end`, which is never before it.
static inline uint16_t left(const uint8_t* at, const uint8_t* end) { return (uint16_t)(end - at); }

// Send options.
static const uint32_t TX_OPT_FLOOD_HOPS = 1;
static const uint32_t TX_OPT_SOURCE_ROUTE = 2;
static const uint32_t TX_OPT_TX_POWER = 3;
static const uint8_t MAX_FLOOD_HOPS = 15;
// Receive options.
static const uint32_t RX_OPT_RSSI = 1;
static const uint32_t RX_OPT_SNR = 2;
static const uint32_t RX_OPT_TRACE = 3;
static const uint8_t RX_FLAG_SRC_KEY = 0x01;

// ---- Received messages ----

UmshMessage::UmshMessage()
    : data_(0), dataLength_(0), kind_(UMSH_UNICAST), flags_(0), sourceKey_(false), source_(0),
      channel_(0), hasRssi_(false), hasSnr_(false), rssi_(0), snr_(0), trace_(0),
      traceHints_(0) {}

bool UmshMessage::parse(const uint8_t* payload, uint16_t length, UmshMessage& out) {
  out = UmshMessage();
  const uint8_t* at = payload;
  const uint8_t* end = payload + length;
  uint32_t stream;
  if (!umshReadPui(at, end, &stream) || stream != UMSH_STR_NODE_MSG) return false;
  if (left(at, end) < 2) return false;
  uint16_t dataLength = (uint16_t)(at[0] | at[1] << 8);
  at += 2;
  // A payload has at least its type octet.
  if (dataLength == 0 || left(at, end) < dataLength) return false;
  out.data_ = at;
  out.dataLength_ = dataLength;
  at += dataLength;

  if (left(at, end) < 2 || at[0] > UMSH_MULTICAST) return false;
  out.kind_ = (UmshKind)at[0];
  out.flags_ = at[1];
  at += 2;
  if (out.kind_ & 0x02) {
    if (left(at, end) < UMSH_CHANNEL_ID_LEN) return false;
    out.channel_ = at;
    at += UMSH_CHANNEL_ID_LEN;
  }
  out.sourceKey_ = out.flags_ & RX_FLAG_SRC_KEY;
  uint8_t sourceLength = out.sourceLength();
  if (left(at, end) < sourceLength) return false;
  out.source_ = at;
  at += sourceLength;

  // Options a receiver does not know, or whose value is misshaped, are
  // ignored.
  while (at < end) {
    uint32_t entryLength, key;
    if (!umshReadPui(at, end, &entryLength) || left(at, end) < entryLength) return false;
    const uint8_t* entryEnd = at + entryLength;
    if (!umshReadPui(at, entryEnd, &key)) return false;
    const uint8_t* value = at;
    uint16_t valueLength = (uint16_t)(entryEnd - at);
    at = entryEnd;
    if (key == RX_OPT_RSSI && valueLength == 1) {
      // 0xFF: the radio does not report it.
      if (value[0] != 0xFF) {
        out.hasRssi_ = true;
        out.rssi_ = -(int16_t)value[0];
      }
    } else if (key == RX_OPT_SNR && valueLength == 2) {
      int16_t snr = (int16_t)(uint16_t)(value[0] | value[1] << 8);
      if (snr != (int16_t)0x8000) {
        out.hasSnr_ = true;
        out.snr_ = snr;
      }
    } else if (key == RX_OPT_TRACE && valueLength != 0 && valueLength % 2 == 0 &&
               valueLength <= 2 * UMSH_MAX_ROUTE_HINTS) {
      out.trace_ = value;
      out.traceHints_ = (uint8_t)(valueLength / 2);
    }
  }
  return true;
}

// ---- Destinations and options ----

UmshDest::UmshDest() : kind_(UMSH_BROADCAST) {
  memset(key_, 0, sizeof key_);
  memset(channel_, 0, sizeof channel_);
}

UmshDest UmshDest::peer(const uint8_t key[32]) {
  UmshDest dest;
  dest.kind_ = UMSH_UNICAST;
  memcpy(dest.key_, key, UMSH_KEY_LEN);
  return dest;
}

UmshDest UmshDest::channel(const uint8_t id[16]) {
  UmshDest dest;
  dest.kind_ = UMSH_MULTICAST;
  memcpy(dest.channel_, id, UMSH_CHANNEL_ID_LEN);
  return dest;
}

UmshDest UmshDest::blind(const uint8_t id[16], const uint8_t key[32]) {
  UmshDest dest;
  dest.kind_ = UMSH_BLIND_UNICAST;
  memcpy(dest.channel_, id, UMSH_CHANNEL_ID_LEN);
  memcpy(dest.key_, key, UMSH_KEY_LEN);
  return dest;
}

UmshDest UmshDest::broadcast() { return UmshDest(); }

UmshDest UmshDest::replyTo(const UmshMessage& message) {
  // A unicast or blind unicast always names its sender by key; a key left
  // as zeros is one no radio holds, and the send fails.
  static const uint8_t none[32] = {0};
  const uint8_t* key = message.hasSourceKey() ? message.source() : none;
  switch (message.kind()) {
    case UMSH_UNICAST:
      return peer(key);
    case UMSH_BLIND_UNICAST:
      return blind(message.channel(), key);
    case UMSH_MULTICAST:
      return channel(message.channel());
    case UMSH_BROADCAST:
    default:
      return message.hasSourceKey() ? peer(key) : broadcast();
  }
}

UmshSendOptions::UmshSendOptions()
    : ack(false), fullSource(false), sign(false), floodHops(-1), route(0), routeHints(0),
      setTxPower(false), txPower(0) {}

UmshSendOptions UmshSendOptions::defaultsFor(const UmshDest& dest) {
  UmshSendOptions options;
  options.ack = dest.hasPeer();
  return options;
}

// ---- Sending ----

static uint8_t sendFlags(const UmshSendOptions& options) {
  return (uint8_t)((options.ack ? 0x01 : 0) | (options.fullSource ? 0x02 : 0) |
                   (options.sign ? 0x04 : 0));
}

UmshStatus UmshRadio::checkSend(const UmshDest& dest, uint16_t dataLength,
                                const UmshSendOptions& options) {
  if (options.floodHops > (int8_t)MAX_FLOOD_HOPS) return UMSH_INVALID;
  if (options.route && (options.routeHints == 0 || options.routeHints > UMSH_MAX_ROUTE_HINTS))
    return UMSH_INVALID;
  // Header, command, stream, DATA_LEN, DATA, kind, flags, addresses, and
  // each option as its entry: a length, a key, and a value.
  uint32_t length = 2 + 1 + 2 + (uint32_t)dataLength + 2;
  if (dest.hasChannel()) length += UMSH_CHANNEL_ID_LEN;
  if (dest.hasPeer()) length += UMSH_KEY_LEN;
  if (options.floodHops >= 0) length += 3;
  if (options.route) length += 2 + 2 * (uint32_t)options.routeHints;
  if (options.setTxPower) length += 3;
  return length <= UMSH_FRAME_MAX ? UMSH_STATUS_OK : UMSH_TOO_LONG;
}

static void putEntry(UmshEncoder& out, uint32_t key, const uint8_t* value, uint16_t length) {
  out.putPui(umshPuiLength(key) + length);
  out.putPui(key);
  out.put(value, length);
}

void UmshRadio::writeSend(UmshEncoder& out, const UmshDest& dest, uint8_t type,
                          const uint8_t* prefix, uint16_t prefixLength, const uint8_t* body,
                          uint16_t bodyLength, const UmshSendOptions& options) {
  out.putPui(UMSH_STR_NODE_MSG);
  out.putU16((uint16_t)(1 + prefixLength + bodyLength));
  out.put(type);
  out.put(prefix, prefixLength);
  out.put(body, bodyLength);
  out.put((uint8_t)dest.kind());
  out.put(sendFlags(options));
  if (dest.hasChannel()) out.put(dest.channelId(), UMSH_CHANNEL_ID_LEN);
  if (dest.hasPeer()) out.put(dest.key(), UMSH_KEY_LEN);
  if (options.floodHops >= 0) {
    uint8_t hops = (uint8_t)options.floodHops;
    putEntry(out, TX_OPT_FLOOD_HOPS, &hops, 1);
  }
  if (options.route) putEntry(out, TX_OPT_SOURCE_ROUTE, options.route, 2 * options.routeHints);
  if (options.setTxPower) {
    uint8_t power = (uint8_t)options.txPower;
    putEntry(out, TX_OPT_TX_POWER, &power, 1);
  }
}

UmshRadio::UmshRadio(Stream& io)
    : UmshLink(io), mtu_(0), supported_(true), needMtu_(true), needClaims_(false),
      needListen_(false), listen_(false), claimsSet_(false), claimCount_(0), syncTid_(0),
      syncKey_(0), claimStatus_(UMSH_NOT_READY), listenStatus_(UMSH_NOT_READY), tickets_(0),
      waitTicket_(0), waitDone_(false), waitStatus_(UMSH_TIMEOUT),
      lastError_(UMSH_STATUS_OK), messageHook_(0), textHook_(0), resultHook_(0) {}

bool UmshRadio::sending() const { return open() && supported_ && !needMtu_ && mtu_ != 0; }

bool UmshRadio::ready() const {
  return sending() && !needClaims_ && !needListen_ && syncTid_ == 0;
}

UmshStatus UmshRadio::status() const {
  if (ready()) return UMSH_STATUS_OK;
  return open() && !supported_ ? UMSH_UNSUPPORTED : UMSH_NOT_READY;
}

uint8_t UmshRadio::sendParts(const UmshDest& dest, uint8_t type, const uint8_t* prefix,
                             uint16_t prefixLength, const uint8_t* body, uint16_t bodyLength,
                             const UmshSendOptions& options) {
  if (!sending()) {
    lastError_ = open() && !supported_ ? UMSH_UNSUPPORTED : UMSH_NOT_READY;
    return 0;
  }
  lastError_ = checkSend(dest, (uint16_t)(1 + prefixLength + bodyLength), options);
  if (lastError_ != UMSH_STATUS_OK) return 0;
  uint8_t tid = allocTid();
  if (!tid) {
    lastError_ = UMSH_NO_TICKET;
    return 0;
  }
  UmshEncoder& out = frameBegin(tid, UMSH_CMD_STR_SEND);
  writeSend(out, dest, type, prefix, prefixLength, body, bodyLength, options);
  frameEnd();
  tickets_ |= (uint8_t)(1 << tid);
  return tid;
}

uint8_t UmshRadio::send(const UmshDest& dest, uint8_t type, const uint8_t* body,
                        uint16_t length) {
  return sendParts(dest, type, 0, 0, body, length, UmshSendOptions::defaultsFor(dest));
}

uint8_t UmshRadio::send(const UmshDest& dest, uint8_t type, const uint8_t* body, uint16_t length,
                        const UmshSendOptions& options) {
  return sendParts(dest, type, 0, 0, body, length, options);
}

UmshStatus UmshRadio::waitFor(uint8_t ticket, uint32_t start, uint32_t timeoutMs) {
  waitTicket_ = ticket;
  waitDone_ = false;
  while (!waitDone_ && millis() - start < timeoutMs) poll();
  waitTicket_ = 0;
  // A result after this goes to onSendResult().
  return waitDone_ ? waitStatus_ : UMSH_TIMEOUT;
}

UmshStatus UmshRadio::sendAndWait(const UmshDest& dest, uint8_t type, const uint8_t* body,
                                  uint16_t length, uint32_t timeoutMs) {
  return sendAndWait(dest, type, body, length, UmshSendOptions::defaultsFor(dest), timeoutMs);
}

UmshStatus UmshRadio::sendAndWait(const UmshDest& dest, uint8_t type, const uint8_t* body,
                                  uint16_t length, const UmshSendOptions& options,
                                  uint32_t timeoutMs) {
  // Polling here would overwrite the message a callback is handling.
  if (inCallback()) return UMSH_IN_CALLBACK;
  uint32_t start = millis();
  uint8_t ticket;
  while ((ticket = send(dest, type, body, length, options)) == 0) {
    // Waiting helps only a radio that is not ready yet, or one with every
    // ticket in use.
    if (lastError_ != UMSH_NOT_READY && lastError_ != UMSH_NO_TICKET) return lastError_;
    if (millis() - start >= timeoutMs) return lastError_;
    poll();
  }
  return waitFor(ticket, start, timeoutMs);
}

uint8_t UmshRadio::sendTextParts(const UmshDest& dest, const uint8_t* body, size_t length,
                                 const UmshTextOptions& textOptions,
                                 const UmshSendOptions& options) {
  if (length > UMSH_FRAME_MAX) {
    lastError_ = UMSH_TOO_LONG;
    return 0;
  }
  uint8_t prefix[64];
  int16_t prefixLength = UmshText::encodeOptions(prefix, sizeof prefix, textOptions, length != 0);
  if (prefixLength < 0) {
    lastError_ = UMSH_TOO_LONG;
    return 0;
  }
  return sendParts(dest, UMSH_PAYLOAD_TEXT, prefix, (uint16_t)prefixLength, body,
                   (uint16_t)length, options);
}

static const uint8_t* octets(const char* text) { return (const uint8_t*)text; }

uint8_t UmshRadio::sendText(const UmshDest& dest, const char* text) {
  return sendTextParts(dest, octets(text), strlen(text), UmshTextOptions(),
                       UmshSendOptions::defaultsFor(dest));
}

uint8_t UmshRadio::sendText(const UmshDest& dest, const char* text,
                            const UmshTextOptions& textOptions) {
  return sendTextParts(dest, octets(text), strlen(text), textOptions,
                       UmshSendOptions::defaultsFor(dest));
}

uint8_t UmshRadio::sendText(const UmshDest& dest, const char* text,
                            const UmshTextOptions& textOptions, const UmshSendOptions& options) {
  return sendTextParts(dest, octets(text), strlen(text), textOptions, options);
}

uint8_t UmshRadio::sendText(const UmshDest& dest, const uint8_t* body, uint16_t length,
                            const UmshTextOptions& textOptions, const UmshSendOptions& options) {
  return sendTextParts(dest, body, length, textOptions, options);
}

uint8_t UmshRadio::replyText(const UmshMessage& message, const UmshText& text,
                             const char* reply) {
  return replyText(message, text, octets(reply), (uint16_t)strlen(reply));
}

uint8_t UmshRadio::replyText(const UmshMessage& message, const UmshText& text,
                             const uint8_t* reply, uint16_t length) {
  UmshTextOptions options;
  UmshText::regarding(message, text, options);
  UmshDest dest = UmshDest::replyTo(message);
  return sendTextParts(dest, reply, length, options, UmshSendOptions::defaultsFor(dest));
}

uint8_t UmshRadio::react(const UmshMessage& message, const UmshText& text, const char* token) {
  UmshTextOptions options;
  options.type = UMSH_TEXT_STATUS;
  if (!UmshText::regarding(message, text, options)) {
    // Without a reference it would be status text, not a reaction.
    lastError_ = UMSH_INVALID;
    return 0;
  }
  UmshDest dest = UmshDest::replyTo(message);
  return sendTextParts(dest, octets(token), strlen(token), options,
                       UmshSendOptions::defaultsFor(dest));
}

void UmshRadio::result(uint8_t ticket, UmshStatus status) {
  tickets_ &= (uint8_t)~(1 << ticket);
  if (ticket == waitTicket_) {
    waitDone_ = true;
    waitStatus_ = status;
  } else if (resultHook_) {
    Callback callback(*this);
    resultHook_(ticket, status);
  }
}

// ---- Claims and listening ----

bool UmshRadio::setClaims(const uint8_t* types, uint8_t count) {
  if (count > UMSH_MAX_CLAIMS) return false;
  if (count) memcpy(claims_, types, count);
  claimCount_ = count;
  claimsSet_ = true;
  needClaims_ = true;
  return true;
}

bool UmshRadio::setClaims(uint8_t type) { return setClaims(&type, 1); }

bool UmshRadio::claim(uint8_t type) {
  for (uint8_t i = 0; i < claimCount_; i++) {
    if (claims_[i] == type) return true;
  }
  if (claimCount_ == UMSH_MAX_CLAIMS) return false;
  claims_[claimCount_++] = type;
  claimsSet_ = true;
  needClaims_ = true;
  return true;
}

bool UmshRadio::unclaim(uint8_t type) {
  for (uint8_t i = 0; i < claimCount_; i++) {
    if (claims_[i] == type) {
      claims_[i] = claims_[--claimCount_];
      break;
    }
  }
  claimsSet_ = true;
  needClaims_ = true;
  return true;
}

void UmshRadio::listen(bool on) {
  // Clear at the start of every session, so off needs saying only after
  // on.
  if (on || listen_) needListen_ = true;
  listen_ = on;
}

// ---- The session ----

// Whatever this session must learn or say first: the MTU, which also says
// whether the radio offers node messaging, then the claims, then
// listening, which is session state and starts clear.
void UmshRadio::sessionOpened() {
  syncTid_ = 0;
  supported_ = true;
  needMtu_ = true;
  needClaims_ = claimsSet_;
  needListen_ = listen_;
}

void UmshRadio::service() {
  if (!open() || syncTid_ != 0) return;
  uint32_t key;
  uint8_t command;
  if (needMtu_) {
    key = UMSH_PROP_NODE_MSG_MTU;
    command = UMSH_CMD_PROP_GET;
  } else if (!supported_) {
    return;
  } else if (needClaims_) {
    key = UMSH_PROP_NODE_MSG_TYPES;
    command = UMSH_CMD_PROP_SET;
  } else if (needListen_) {
    key = UMSH_PROP_NODE_MSG_LISTEN;
    command = UMSH_CMD_PROP_SET;
  } else {
    return;
  }
  uint8_t tid = allocTid();
  if (!tid) return;
  UmshEncoder& out = frameBegin(tid, command);
  out.putPui(key);
  // A change made while this is on its way is sent again after it.
  if (key == UMSH_PROP_NODE_MSG_MTU) {
    needMtu_ = false;
  } else if (key == UMSH_PROP_NODE_MSG_TYPES) {
    out.put(claims_, claimCount_);
    needClaims_ = false;
  } else {
    out.put(listen_ ? 1 : 0);
    needListen_ = false;
  }
  frameEnd();
  syncTid_ = tid;
  syncKey_ = key;
}

// The status an answer to a request for `key` carries, and the value of a
// PROP_IS of `key`.
static UmshStatus answerStatus(const UmshFrame& frame, uint32_t key, const uint8_t** value,
                               uint16_t* length) {
  const uint8_t* at = frame.payload;
  const uint8_t* end = at + frame.length;
  uint32_t answered;
  if (frame.command != UMSH_CMD_PROP_IS || !umshReadPui(at, end, &answered))
    return UMSH_UNEXPECTED;
  if (answered == UMSH_PROP_LAST_STATUS) {
    uint32_t status;
    return umshReadPui(at, end, &status) ? (UmshStatus)status : UMSH_UNEXPECTED;
  }
  if (answered != key) return UMSH_UNEXPECTED;
  *value = at;
  *length = (uint16_t)(end - at);
  return UMSH_STATUS_OK;
}

void UmshRadio::syncDone(uint8_t tid, UmshStatus status, const UmshFrame* frame) {
  (void)tid;
  syncTid_ = 0;
  const uint8_t* value = 0;
  uint16_t length = 0;
  if (frame) status = answerStatus(*frame, syncKey_, &value, &length);
  if (syncKey_ == UMSH_PROP_NODE_MSG_MTU) {
    if (status == UMSH_STATUS_OK && length == 2) {
      mtu_ = (uint16_t)(value[0] | value[1] << 8);
    } else if (status == UMSH_LINK_RESET) {
      return;
    } else {
      // The property comes with node messaging.
      supported_ = false;
    }
  } else if (syncKey_ == UMSH_PROP_NODE_MSG_TYPES) {
    claimStatus_ = status;
  } else {
    listenStatus_ = status;
  }
  if (ready()) linkReady();
}

void UmshRadio::answered(uint8_t tid, const UmshFrame& frame) {
  if (tid == syncTid_) {
    syncDone(tid, UMSH_STATUS_OK, &frame);
  } else if (tickets_ & (1 << tid)) {
    const uint8_t* value;
    uint16_t length;
    UmshStatus status = answerStatus(frame, UMSH_PROP_LAST_STATUS, &value, &length);
    result(tid, status);
  } else {
    UmshLink::answered(tid, frame);
  }
}

void UmshRadio::failed(uint8_t tid, UmshStatus why) {
  if (tid == syncTid_) {
    syncDone(tid, why, 0);
  } else if (tickets_ & (1 << tid)) {
    result(tid, why);
  } else {
    UmshLink::failed(tid, why);
  }
}

void UmshRadio::unsolicited(const UmshFrame& frame) {
  UmshMessage message;
  if (frame.command != UMSH_CMD_STR_RECV ||
      !UmshMessage::parse(frame.payload, frame.length, message)) {
    UmshLink::unsolicited(frame);
    return;
  }
  Callback callback(*this);
  if (message.payloadType() == UMSH_PAYLOAD_TEXT && textHook_) {
    UmshText text;
    if (UmshText::decode(message.body(), message.bodyLength(), text)) {
      textHook_(message, text);
      return;
    }
  }
  if (messageHook_) messageHook_(message);
}
