// UmshLink: a ULCP link to a UMSH radio over a serial port.
//
// It frames with HDLC-Lite, opens and restarts the link's session, hands
// out transaction identifiers, paces the radio with XON and a window, and
// sends the wake preamble a radio that sleeps needs. Property requests are
// raw octets; UmshRadio builds node messaging on top.
//
// Nothing here blocks except the property calls, which say so. Call poll()
// from loop().

#ifndef UMSH_LINK_H
#define UMSH_LINK_H

#include <Arduino.h>
#include <stdint.h>

#include "UmshHdlc.h"
#include "UmshProtocol.h"

// A received frame, valid only during the call it is handed to.
struct UmshFrame {
  uint8_t tid;
  uint8_t command;
  const uint8_t* payload;
  uint16_t length;
};

class UmshLink {
public:
  explicit UmshLink(Stream& io);
  virtual ~UmshLink() {}

  // Start the link with the default window: a little under half the
  // serial port's receive buffer. Returns at once; poll() does the rest.
  void begin();
  // Start the link with a window of `window` octets per XON. 0 selects
  // plain XON/XOFF, for a port whose buffer holds a whole frame.
  void begin(uint16_t window);

  // Read what has arrived, hand it to the callbacks, and keep the link
  // going. A frame in progress is read to its end before this returns.
  void poll();

  // The link's session is open: the radio answers requests.
  virtual bool ready() const;
  // Poll until ready() or `timeoutMs` passes; returns ready().
  bool waitReady(uint32_t timeoutMs);

  // Withdraw and restore permission for the radio to send. A windowed link
  // needs neither; plain XON/XOFF does.
  void hold();
  void release();

  uint16_t window() const { return window_; }

  // Blocking property requests, with the value as raw octets. Each polls
  // until the radio answers or `timeoutMs` passes, delivering whatever
  // else arrives meanwhile, and is refused inside a callback.
  UmshStatus getProperty(uint32_t key, uint8_t* value, uint16_t capacity, uint16_t* length,
                         uint32_t timeoutMs = 2000);
  UmshStatus setProperty(uint32_t key, const uint8_t* value, uint16_t length,
                         uint32_t timeoutMs = 2000);
  UmshStatus insertProperty(uint32_t key, const uint8_t* item, uint16_t length,
                            uint32_t timeoutMs = 2000);
  UmshStatus removeProperty(uint32_t key, const uint8_t* item, uint16_t length,
                            uint32_t timeoutMs = 2000);

  // Every frame the library does not handle itself, such as a property the
  // radio publishes because someone else changed it.
  void onFrame(void (*hook)(const UmshFrame& frame)) { frameHook_ = hook; }
  // The session started over and is ready again. Requests outstanding
  // when it ended were completed with UMSH_LINK_RESET.
  void onLinkReset(void (*hook)()) { resetHook_ = hook; }

  // A request older than this starts a new session: the radio has stopped
  // answering. Default 60 s.
  void setReplyLimit(uint32_t ms) { replyLimit_ = ms; }
  // With nothing received for this long, permission to send is granted
  // again, for a radio that restarted. Default 30 s.
  void setXonRefresh(uint32_t ms) { xonRefresh_ = ms; }

protected:
  enum State : uint8_t { IDLE, STARTING, OPEN };

  // A transaction identifier for a new request, or 0 when all seven wait.
  uint8_t allocTid();
  // Start a frame; the caller writes its payload to the encoder.
  UmshEncoder& frameBegin(uint8_t tid, uint8_t command);
  void frameEnd();
  bool open() const { return state_ == OPEN; }
  // Tell onLinkReset() that the session that replaced a lost one is
  // ready, if one was lost.
  void linkReady();

  // A frame with an outstanding request's TID: its answer.
  virtual void answered(uint8_t tid, const UmshFrame& frame);
  // An outstanding request that will get no answer.
  virtual void failed(uint8_t tid, UmshStatus why);
  // Any other frame of the session.
  virtual void unsolicited(const UmshFrame& frame);
  // The session has opened. The default calls linkReady().
  virtual void sessionOpened();
  // Called at the end of every poll().
  virtual void service() {}

  // Call a sketch's callback: blocking calls inside it are refused.
  struct Callback {
    explicit Callback(UmshLink& link) : link_(link) { link_.inCallback_++; }
    ~Callback() { link_.inCallback_--; }
    UmshLink& link_;
  };
  bool inCallback() const { return inCallback_ != 0; }

private:
  void startSession();
  void restart();
  void octet(uint8_t octet);
  void dispatch(const uint8_t* frame, uint16_t length);
  void wake();
  void flow(uint8_t octet);
  void grant();
  void sent();
  UmshStatus request(uint8_t command, uint32_t key, const uint8_t* value, uint16_t length,
                     uint8_t* out, uint16_t capacity, uint16_t* outLength, uint32_t timeoutMs);

  Stream& io_;
  UmshEncoder encoder_;
  // The longest frame, and its FCS.
  uint8_t rx_[UMSH_FRAME_MAX + 2];
  UmshDecoder decoder_;

  State state_;
  bool held_;
  bool everSent_;
  // A session was lost since the last onLinkReset().
  bool resetPending_;
  uint8_t inCallback_;
  uint16_t window_;
  // Octets received since the last XON.
  uint16_t sinceXon_;
  uint32_t lastReceived_;
  uint32_t lastXon_;
  uint32_t lastSent_;
  uint32_t startSent_;
  uint32_t replyLimit_;
  uint32_t xonRefresh_;

  uint8_t outstanding_;
  uint8_t nextTid_;
  uint32_t sentAt_[8];

  // The one blocking request in progress.
  struct Waiter {
    uint8_t tid;
    bool done;
    uint8_t command;
    uint32_t key;
    uint8_t* out;
    uint16_t capacity;
    uint16_t length;
    UmshStatus status;
  } waiter_;

  void (*frameHook_)(const UmshFrame&);
  void (*resetHook_)();
};

#endif
