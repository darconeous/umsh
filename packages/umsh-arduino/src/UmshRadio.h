// UmshRadio: node messaging through a UMSH radio. The radio encrypts,
// routes, retries, and collects acknowledgments under its own identity;
// the sketch hands it payloads and destinations, and receives the payloads
// of the types it claims.

#ifndef UMSH_RADIO_H
#define UMSH_RADIO_H

#include <Arduino.h>
#include <stdint.h>

#include "UmshLink.h"
#include "UmshText.h"

// The most payload types a sketch claims.
#ifndef UMSH_MAX_CLAIMS
#define UMSH_MAX_CLAIMS 8
#endif

// A received message, valid only during the callback it is handed to.
class UmshMessage {
public:
  UmshMessage();

  // Decode the payload of a CMD_STR_RECV on STR_NODE_MSG. False for
  // another stream, or for one that does not parse.
  static bool parse(const uint8_t* payload, uint16_t length, UmshMessage& out);

  uint8_t payloadType() const { return data_[0]; }
  // The payload after its type octet.
  const uint8_t* body() const { return data_ + 1; }
  uint16_t bodyLength() const { return dataLength_ - 1; }

  UmshKind kind() const { return kind_; }
  // The sender: its 32-octet key when hasSourceKey(), otherwise its
  // 3-octet hint (a multicast or broadcast from a sender the radio does
  // not know).
  const uint8_t* source() const { return source_; }
  uint8_t sourceLength() const { return sourceKey_ ? UMSH_KEY_LEN : UMSH_HINT_LEN; }
  bool hasSourceKey() const { return sourceKey_; }
  // The channel identifier, or null for a kind with none.
  const uint8_t* channel() const { return channel_; }

  bool senderAuthenticated() const { return flags_ & 0x02; }
  bool acked() const { return flags_ & 0x04; }
  // Unacknowledged messages were discarded since the last one.
  bool gap() const { return flags_ & 0x08; }
  // Delivered before, over a session that then ended: possibly a repeat.
  bool redelivered() const { return flags_ & 0x10; }

  bool hasRssi() const { return hasRssi_; }
  int16_t rssi() const { return rssi_; }
  bool hasSnr() const { return hasSnr_; }
  // Centibels.
  int16_t snr() const { return snr_; }
  // The router hints of the path it came by, nearest repeater first, two
  // octets each, or null. A reply can send them back as its source route.
  const uint8_t* trace() const { return trace_; }
  uint8_t traceHints() const { return traceHints_; }

private:
  const uint8_t* data_;
  uint16_t dataLength_;
  UmshKind kind_;
  uint8_t flags_;
  bool sourceKey_;
  const uint8_t* source_;
  const uint8_t* channel_;
  bool hasRssi_;
  bool hasSnr_;
  int16_t rssi_;
  int16_t snr_;
  const uint8_t* trace_;
  uint8_t traceHints_;
};

// Where a message goes. Holds copies of the key and channel it names.
class UmshDest {
public:
  UmshDest();
  // One node, by its 32-octet key.
  static UmshDest peer(const uint8_t key[32]);
  // Everyone on one of the radio's channels, by its 16-octet identifier.
  static UmshDest channel(const uint8_t id[16]);
  // One node, through one of the radio's channels.
  static UmshDest blind(const uint8_t id[16], const uint8_t key[32]);
  // Everyone in range.
  static UmshDest broadcast();
  // Back the way `message` came: to its sender for a unicast or blind
  // unicast, to its channel for a multicast, and for a broadcast to its
  // sender when the radio knows its key, otherwise as a broadcast.
  static UmshDest replyTo(const UmshMessage& message);

  UmshKind kind() const { return kind_; }
  const uint8_t* key() const { return key_; }
  const uint8_t* channelId() const { return channel_; }
  bool hasPeer() const { return !(kind_ & 0x01); }
  bool hasChannel() const { return kind_ & 0x02; }

private:
  UmshKind kind_;
  uint8_t key_[32];
  uint8_t channel_[16];
};

// How a message is sent. Everything the protocol offers; nothing is
// checked here that the radio checks itself.
struct UmshSendOptions {
  UmshSendOptions();
  // What send() uses when given no options: an acknowledgment for a
  // destination that can give one, and nothing else.
  static UmshSendOptions defaultsFor(const UmshDest& dest);

  // Ask for an acknowledgment: unicast and blind unicast only.
  bool ack;
  // Carry the radio's whole key as the source, not its hint.
  bool fullSource;
  // Carry a frame signature.
  bool sign;
  // The flood budget, 0 to 15; -1 for the radio's default.
  int8_t floodHops;
  // A source route: `routeHints` router hints of two octets each, next
  // repeater first. Null for the route the radio has learned.
  const uint8_t* route;
  uint8_t routeHints;
  // Transmit power in dBm, when setTxPower is set.
  bool setTxPower;
  int8_t txPower;
};

class UmshRadio : public UmshLink {
public:
  explicit UmshRadio(Stream& io);

  // The link is open, the radio offers node messaging, and the claims and
  // listening the sketch asked for are in place.
  bool ready() const;
  // Why the radio is not ready: UMSH_UNSUPPORTED for a radio without node
  // messaging, otherwise UMSH_NOT_READY. UMSH_STATUS_OK once it is.
  UmshStatus status() const;

  // The longest payload, type octet included, that every plain send takes;
  // 0 until the radio has said.
  uint16_t mtu() const { return mtu_; }

  // Claim exactly these payload types: messages of a claimed type are
  // delivered here. Claims are saved on the radio, so a sketch that sets
  // none inherits whatever the last one claimed. Applied now and after
  // every new session; claimStatus() says how the radio took them.
  bool setClaims(const uint8_t* types, uint8_t count);
  bool setClaims(uint8_t type);
  bool claim(uint8_t type);
  bool unclaim(uint8_t type);
  UmshStatus claimStatus() const { return claimStatus_; }

  // For a sketch on a host link: receive node messages there. The radio
  // refuses it on its own interface, where claims are what count.
  void listen(bool on);
  UmshStatus listenStatus() const { return listenStatus_; }

  // Send a payload of type `type`. Does not block: returns a ticket from 1
  // to 7, and the outcome arrives at onSendResult(); or returns 0, with the
  // reason in lastError().
  uint8_t send(const UmshDest& dest, uint8_t type, const uint8_t* body, uint16_t length);
  uint8_t send(const UmshDest& dest, uint8_t type, const uint8_t* body, uint16_t length,
               const UmshSendOptions& options);
  // Send, and poll until the outcome is known, still delivering what
  // arrives. Refused inside a callback.
  UmshStatus sendAndWait(const UmshDest& dest, uint8_t type, const uint8_t* body,
                         uint16_t length, uint32_t timeoutMs = 60000);
  UmshStatus sendAndWait(const UmshDest& dest, uint8_t type, const uint8_t* body,
                         uint16_t length, const UmshSendOptions& options,
                         uint32_t timeoutMs = 60000);

  // Text. `text` is NUL-terminated; the smallest message is sent unless
  // `textOptions` asks for more.
  uint8_t sendText(const UmshDest& dest, const char* text);
  uint8_t sendText(const UmshDest& dest, const char* text, const UmshTextOptions& textOptions);
  uint8_t sendText(const UmshDest& dest, const char* text, const UmshTextOptions& textOptions,
                   const UmshSendOptions& options);
  // A body of `length` octets, such as one received.
  uint8_t sendText(const UmshDest& dest, const uint8_t* body, uint16_t length,
                   const UmshTextOptions& textOptions, const UmshSendOptions& options);
  // A reply to, or a reaction to, a text message received in `message`.
  // A reply to a message that carries no ID goes without a reference; a
  // reaction to one cannot be sent, and returns 0 with UMSH_INVALID.
  uint8_t replyText(const UmshMessage& message, const UmshText& text, const char* reply);
  uint8_t replyText(const UmshMessage& message, const UmshText& text, const uint8_t* reply,
                    uint16_t length);
  uint8_t react(const UmshMessage& message, const UmshText& text, const char* token);

  UmshStatus lastError() const { return lastError_; }

  // Every message of a claimed type; text too, unless onText() is set.
  void onMessage(void (*hook)(const UmshMessage& message)) { messageHook_ = hook; }
  // Text messages, decoded.
  void onText(void (*hook)(const UmshMessage& message, const UmshText& text)) {
    textHook_ = hook;
  }
  // The outcome of a send: UMSH_STATUS_OK, UMSH_STATUS_NO_ACK, another
  // status from the radio, or UMSH_LINK_RESET when the session started
  // over first and whether it went is unknown.
  void onSendResult(void (*hook)(uint8_t ticket, UmshStatus status)) { resultHook_ = hook; }

  // Whether a send of `dataLength` octets, type octet included, can be
  // framed: UMSH_STATUS_OK, UMSH_TOO_LONG, or UMSH_INVALID for options
  // out of range.
  static UmshStatus checkSend(const UmshDest& dest, uint16_t dataLength,
                              const UmshSendOptions& options);
  // Write the payload of a CMD_STR_SEND on STR_NODE_MSG: the payload is
  // `type`, then `prefix`, then `body`.
  static void writeSend(UmshEncoder& out, const UmshDest& dest, uint8_t type,
                        const uint8_t* prefix, uint16_t prefixLength, const uint8_t* body,
                        uint16_t bodyLength, const UmshSendOptions& options);

protected:
  void answered(uint8_t tid, const UmshFrame& frame);
  void failed(uint8_t tid, UmshStatus why);
  void unsolicited(const UmshFrame& frame);
  void sessionOpened();
  void service();

private:
  uint8_t sendParts(const UmshDest& dest, uint8_t type, const uint8_t* prefix,
                    uint16_t prefixLength, const uint8_t* body, uint16_t bodyLength,
                    const UmshSendOptions& options);
  uint8_t sendTextParts(const UmshDest& dest, const uint8_t* body, size_t length,
                        const UmshTextOptions& textOptions, const UmshSendOptions& options);
  UmshStatus waitFor(uint8_t ticket, uint32_t start, uint32_t timeoutMs);
  bool sending() const;
  void result(uint8_t ticket, UmshStatus status);
  void syncDone(uint8_t tid, UmshStatus status, const UmshFrame* frame);

  uint16_t mtu_;
  bool supported_;
  // What still has to be told to the radio in this session.
  bool needMtu_;
  bool needClaims_;
  bool needListen_;
  bool listen_;
  bool claimsSet_;
  uint8_t claims_[UMSH_MAX_CLAIMS];
  uint8_t claimCount_;
  // The request of the step in progress, and which step it is.
  uint8_t syncTid_;
  uint32_t syncKey_;
  UmshStatus claimStatus_;
  UmshStatus listenStatus_;

  uint8_t tickets_;
  uint8_t waitTicket_;
  bool waitDone_;
  UmshStatus waitStatus_;
  UmshStatus lastError_;

  void (*messageHook_)(const UmshMessage&);
  void (*textHook_)(const UmshMessage&, const UmshText&);
  void (*resultHook_)(uint8_t, UmshStatus);
};

#endif
