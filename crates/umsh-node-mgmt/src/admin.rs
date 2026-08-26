//! The administrator side of an exchange: token choice, retransmission
//! pacing, and the cursor continuation loop.
//!
//! The engine performs no I/O. It hands the caller payloads to send and
//! reads the payloads that come back; the caller owns the transport, the
//! clock, and the buffer the read reassembles into.
//!
//! One [`Exchange`] serves a whole operation, which may span several
//! request/response round trips when a read does not fit one payload.
//! An administrator MUST NOT have more than one exchange outstanding
//! with a given device, so one of these per device is the whole
//! bookkeeping.

use umsh_ulcp::frame::{Cmd, Frame};
use umsh_ulcp::status::Status;

use crate::envelope::{Envelope, EnvelopeError, Token};

/// How long to wait for a response before retransmitting, matching the
/// request pacing `umsh-text` settled on for the same mesh.
pub const RETRY_MS: u64 = 8_000;

/// Retransmissions before an exchange is abandoned. Four attempts across
/// half a minute is long enough for a multi-hop path to recover and
/// short enough that a person waiting on it gets an answer.
pub const MAX_ATTEMPTS: u32 = 4;

/// How an exchange ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Every attempt went unanswered.
    TimedOut,
    /// A response carried a critical option this implementation does not
    /// recognize, so what it says cannot be trusted.
    UnknownCriticalOption(u16),
    /// A response could not be read as an envelope, or its frame could
    /// not be parsed.
    Malformed,
    /// A continued read produced more than the reassembly buffer holds.
    TooLarge,
    /// The device refused the cursor. The caller restarts the read from
    /// a cursor-less request.
    CursorInvalid,
}

/// What the caller should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Send `out[..len]` as a Node Management Request payload.
    Send { len: usize },
    /// Nothing to do until `deadline_ms`, when [`Exchange::poll`] will
    /// have another attempt to hand out.
    Wait { deadline_ms: u64 },
    /// The exchange is over.
    Done(Outcome),
}

/// A finished exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The device answered. The reply frame is the reassembly buffer's
    /// first `len` octets — one whole ULCP frame, its trailing content
    /// the concatenation of every fragment.
    Replied { len: usize },
    /// A reset-class command, which is answered by no response payload.
    /// Delivery is confirmed by the MAC acknowledgment, not here.
    NoResponse,
    /// The exchange failed.
    Failed(Failure),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for a response to the attempt now outstanding.
    Awaiting {
        deadline_ms: u64,
        attempts: u32,
    },
    Finished(Outcome),
}

/// A buffer a continued read reassembles into.
///
/// The caller owns the storage, so a device firmware can put it in a
/// static and a host can put it on the heap.
pub struct Reassembly<'a> {
    buf: &'a mut [u8],
    /// Octets of the reply frame written so far: the frame's header and
    /// its first fragment, then each further fragment's trailing content
    /// appended.
    len: usize,
}

impl<'a> Reassembly<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Take up a reassembly whose position the caller kept.
    ///
    /// A caller that cannot hold the borrow between exchanges — anything
    /// awaiting a radio round trip — keeps the storage and the length it
    /// reached, and hands both back for the next fragment.
    pub fn resume(buf: &'a mut [u8], len: usize) -> Self {
        let len = len.min(buf.len());
        Self { buf, len }
    }

    /// The reply frame assembled so far.
    pub fn frame(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Octets assembled so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no fragment has been taken up yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discard what has been assembled, so the storage can serve
    /// another exchange.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    fn append(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.buf.len() {
            return false;
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        true
    }
}

/// One operation against one device.
pub struct Exchange<const REQUEST: usize> {
    /// The request being sent, envelope excluded: one ULCP frame.
    frame: [u8; REQUEST],
    frame_len: usize,
    /// The cursor to present with the next request, once a fragment has
    /// asked for one.
    cursor: [u8; crate::envelope::CURSOR_MAX],
    cursor_len: usize,
    token: Token,
    /// Advances with each new exchange in the continuation loop, which
    /// is how the next token differs from the previous one.
    counter: u16,
    /// A reset-class command is complete when it has been sent; there is
    /// no response to wait for.
    resets: bool,
    /// The most recent REMAINING the device offered, for progress
    /// reporting.
    remaining: Option<u32>,
    state: State,
}

impl<const REQUEST: usize> Exchange<REQUEST> {
    /// Begin an operation carrying `frame`.
    ///
    /// `seed` picks the first token. A device retains its answer to every
    /// recent token against retransmission, and answers a reused token
    /// with the retained response instead of executing — so the seed must
    /// come from above [`Exchange::counter`] of every exchange the device
    /// may still remember: a counter carried across exchanges, itself
    /// seeded unpredictably.
    pub fn new(frame: &[u8], seed: u16, now_ms: u64) -> Result<Self, Failure> {
        if frame.len() > REQUEST {
            return Err(Failure::TooLarge);
        }
        let resets = Frame::parse(frame)
            .ok()
            .and_then(|parsed| parsed.command())
            .is_some_and(|cmd| {
                matches!(
                    cmd,
                    Cmd::Reset | Cmd::Restore | Cmd::FactoryReset | Cmd::Reboot
                )
            });

        let mut stored = [0u8; REQUEST];
        stored[..frame.len()].copy_from_slice(frame);
        Ok(Self {
            frame: stored,
            frame_len: frame.len(),
            cursor: [0; crate::envelope::CURSOR_MAX],
            cursor_len: 0,
            token: seed.to_be_bytes(),
            counter: seed,
            resets,
            remaining: None,
            state: State::Awaiting {
                deadline_ms: now_ms,
                attempts: 0,
            },
        })
    }

    /// The token now outstanding. A response carrying any other token
    /// belongs to someone else's exchange.
    pub fn token(&self) -> Token {
        self.token
    }

    /// The counter behind the last token this exchange issued.
    ///
    /// A continued read issues a fresh token per fragment, so an exchange
    /// consumes a caller-invisible stretch of the counter space. The next
    /// exchange's seed must come from above this value: the device holds
    /// every answered token against retransmission, and a new request
    /// under any of them is answered with the old response instead of
    /// running.
    pub fn counter(&self) -> u16 {
        self.counter
    }

    /// The device's most recent estimate of octets not yet returned,
    /// advisory and present only during a continued read.
    pub fn remaining(&self) -> Option<u32> {
        self.remaining
    }

    /// When the outstanding attempt stops waiting, or `None` once the
    /// exchange has finished.
    pub fn deadline_ms(&self) -> Option<u64> {
        match self.state {
            State::Awaiting { deadline_ms, .. } => Some(deadline_ms),
            State::Finished(_) => None,
        }
    }

    /// What to do now: send an attempt, wait for the deadline, or stop.
    ///
    /// The first call hands out the first attempt; later calls hand out
    /// retransmissions of the identical request under the identical
    /// token, which the device answers from its retained response rather
    /// than executing again.
    pub fn poll(&mut self, now_ms: u64, out: &mut [u8]) -> Step {
        let (deadline_ms, attempts) = match self.state {
            State::Finished(outcome) => return Step::Done(outcome),
            State::Awaiting {
                deadline_ms,
                attempts,
            } => (deadline_ms, attempts),
        };

        if now_ms < deadline_ms {
            return Step::Wait { deadline_ms };
        }
        if attempts >= MAX_ATTEMPTS {
            return self.finish(Outcome::Failed(Failure::TimedOut));
        }

        let mut request = Envelope::new(self.token, &self.frame[..self.frame_len]);
        if self.cursor_len > 0 {
            request = request.with_cursor(&self.cursor[..self.cursor_len]);
        }
        let Ok(len) = request.encode(out) else {
            return self.finish(Outcome::Failed(Failure::TooLarge));
        };

        self.state = State::Awaiting {
            deadline_ms: now_ms + RETRY_MS,
            attempts: attempts + 1,
        };
        Step::Send { len }
    }

    /// A reset-class command has been delivered — the MAC acknowledged
    /// it — and no response is coming.
    ///
    /// Calling this for anything else discards a reply that may still
    /// arrive; the caller checks [`Exchange::expects_response`] first.
    pub fn delivered(&mut self) -> Step {
        self.finish(Outcome::NoResponse)
    }

    /// Whether a response is guaranteed. False for the reset-class
    /// commands, whose completion is observed by reading state in a
    /// later exchange rather than by a reply.
    ///
    /// One that arrives anyway is still accepted — `CMD_RESTORE` on a
    /// device with no saved snapshot resets nothing and answers like any
    /// other command — so this says when to wait on the acknowledgment
    /// instead, not when to stop listening.
    pub fn expects_response(&self) -> bool {
        !self.resets
    }

    /// Feed an arriving Node Management Response payload, the payload
    /// type byte already stripped.
    ///
    /// A payload whose token does not match the outstanding one is not
    /// this exchange's; the caller discards it with accounting. Returns
    /// `None` in that case, and otherwise what to do next — which for a
    /// fragmented read is the next continuation to send.
    pub fn receive(
        &mut self,
        payload: &[u8],
        reassembly: &mut Reassembly<'_>,
        now_ms: u64,
        out: &mut [u8],
    ) -> Option<Step> {
        if matches!(self.state, State::Finished(_)) {
            return None;
        }

        // The token leads the payload, so even a response whose options
        // are unreadable can be attributed — and one that cannot be
        // attributed is not this exchange's problem.
        let &[token0, token1, ..] = payload else {
            return None;
        };
        if [token0, token1] != self.token {
            return None;
        }

        let response = match Envelope::parse(payload) {
            Ok(response) => response,
            Err(EnvelopeError::UnknownCritical(number)) => {
                return Some(self.finish(Outcome::Failed(Failure::UnknownCriticalOption(number))));
            }
            Err(_) => return Some(self.finish(Outcome::Failed(Failure::Malformed))),
        };

        let Ok(parsed) = Frame::parse(response.frame) else {
            return Some(self.finish(Outcome::Failed(Failure::Malformed)));
        };

        // A refused cursor ends the read: the position is gone, and only
        // the caller knows whether starting over is worth it.
        if self.cursor_len > 0 && reported_status(&parsed) == Some(Status::CURSOR_INVALID) {
            return Some(self.finish(Outcome::Failed(Failure::CursorInvalid)));
        }

        self.remaining = response.remaining;

        // The first fragment contributes the whole frame; later ones
        // contribute only their trailing content, which appends to what
        // the first frame already carries.
        let contribution = if reassembly.len == 0 {
            response.frame
        } else {
            crate::fragment::trailing(response.frame)
        };
        if !reassembly.append(contribution) {
            return Some(self.finish(Outcome::Failed(Failure::TooLarge)));
        }

        let Some(cursor) = response.cursor else {
            let len = reassembly.len;
            return Some(self.finish(Outcome::Replied { len }));
        };

        // Continue: same request, fresh token, the cursor returned
        // byte for byte.
        let stalled = contribution.is_empty();
        self.cursor[..cursor.len()].copy_from_slice(cursor);
        self.cursor_len = cursor.len();
        self.counter = self.counter.wrapping_add(1);
        self.token = self.counter.to_be_bytes();

        if stalled {
            // An empty fragment means nothing further is available yet,
            // which suits data that accumulates over time. Asking again
            // at once would spin; the deadline paces it instead, and
            // the attempt budget still bounds the wait.
            let deadline_ms = now_ms + RETRY_MS;
            self.state = State::Awaiting {
                deadline_ms,
                attempts: 0,
            };
            return Some(Step::Wait { deadline_ms });
        }

        self.state = State::Awaiting {
            deadline_ms: now_ms,
            attempts: 0,
        };
        Some(self.poll(now_ms, out))
    }

    fn finish(&mut self, outcome: Outcome) -> Step {
        self.state = State::Finished(outcome);
        Step::Done(outcome)
    }
}

/// The status a `CMD_PROP_IS` of `PROP_LAST_STATUS` reports.
fn reported_status(parsed: &Frame<'_>) -> Option<Status> {
    if parsed.command() != Some(Cmd::PropIs) {
        return None;
    }
    let (key, consumed) = umsh_ulcp::pui::decode(parsed.payload).ok()?;
    if key != umsh_ulcp::ids::prop::LAST_STATUS {
        return None;
    }
    let (status, _) = umsh_ulcp::pui::decode(&parsed.payload[consumed..]).ok()?;
    Some(Status(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceEngine, Dispatch, Ingress, Produced, PublicKey};
    use umsh_ulcp::frame;
    use umsh_ulcp::ids::prop;

    const PAYLOAD: usize = 180;
    const ADMIN: PublicKey = [0xAA; 32];
    type Device = DeviceEngine<PAYLOAD, 2>;
    type Admin = Exchange<64>;

    fn get(key: u32, buf: &mut [u8]) -> usize {
        frame::prop_get(buf, 0, key).expect("encode")
    }

    #[test]
    fn the_first_poll_hands_out_a_request_and_the_next_one_waits() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut exchange = Admin::new(frame, 0x2A, 1_000).expect("begin");

        let mut out = [0u8; PAYLOAD];
        let Step::Send { len } = exchange.poll(1_000, &mut out) else {
            panic!("expected a request");
        };
        let request = Envelope::parse(&out[..len]).expect("envelope");
        assert_eq!(request.token, exchange.token());
        assert_eq!(request.cursor, None);
        assert_eq!(request.frame, frame);

        assert_eq!(
            exchange.poll(1_001, &mut out),
            Step::Wait {
                deadline_ms: 1_000 + RETRY_MS
            }
        );
    }

    #[test]
    fn a_retransmission_repeats_the_request_under_the_same_token() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut exchange = Admin::new(frame, 1, 0).expect("begin");

        let mut first = [0u8; PAYLOAD];
        let Step::Send { len } = exchange.poll(0, &mut first) else {
            panic!("expected a request");
        };
        let first = first[..len].to_vec();

        let mut again = [0u8; PAYLOAD];
        let Step::Send { len } = exchange.poll(RETRY_MS, &mut again) else {
            panic!("expected a retransmission");
        };
        assert_eq!(&again[..len], &first[..]);
    }

    #[test]
    fn an_unanswered_exchange_times_out_after_its_attempts() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut exchange = Admin::new(frame, 1, 0).expect("begin");
        let mut out = [0u8; PAYLOAD];

        for attempt in 0..MAX_ATTEMPTS {
            let now = u64::from(attempt) * RETRY_MS;
            assert!(matches!(exchange.poll(now, &mut out), Step::Send { .. }));
        }
        assert_eq!(
            exchange.poll(u64::from(MAX_ATTEMPTS) * RETRY_MS, &mut out),
            Step::Done(Outcome::Failed(Failure::TimedOut))
        );
    }

    #[test]
    fn a_response_for_another_exchange_is_not_this_ones() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut exchange = Admin::new(frame, 1, 0).expect("begin");
        let mut out = [0u8; PAYLOAD];
        exchange.poll(0, &mut out);

        let mut storage = [0u8; 256];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut stranger = [0u8; PAYLOAD];
        let len = Envelope::new([0xFF, 0xFF], &[0x80, 0x06])
            .encode(&mut stranger)
            .unwrap();
        assert_eq!(
            exchange.receive(&stranger[..len], &mut reassembly, 0, &mut out),
            None
        );
    }

    #[test]
    fn a_reset_expects_no_response() {
        let mut buf = [0u8; 8];
        for len in [
            frame::reset(&mut buf, 0).unwrap(),
            frame::factory_reset(&mut buf, 0).unwrap(),
            frame::reboot(&mut buf, 0).unwrap(),
        ] {
            let mut exchange = Admin::new(&buf[..len], 1, 0).expect("begin");
            assert!(!exchange.expects_response());
            assert_eq!(exchange.delivered(), Step::Done(Outcome::NoResponse));
        }

        let len = get(prop::CAPS, &mut buf);
        assert!(Admin::new(&buf[..len], 1, 0).unwrap().expects_response());
    }

    /// Run a whole exchange against a real [`DeviceEngine`], with the
    /// caller's dispatch serving `value` in fragments of at most
    /// `chunk` octets.
    fn converse(request: &[u8], value: &[u8], chunk: usize) -> (Outcome, Vec<u8>) {
        let mut device = Device::new(0x5AA5);
        let mut admin = Admin::new(request, 7, 0).expect("begin");
        let mut storage = [0u8; 1024];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut now = 0u64;

        let mut step = admin.poll(now, &mut wire);
        while let Step::Send { len } = step {
            let mut response = [0u8; PAYLOAD];
            let Ingress::Dispatch(Dispatch { resume, budget, .. }) =
                device.begin(&ADMIN, &wire[..len], 1, now, &mut response)
            else {
                panic!("expected a dispatch");
            };

            // Serve the value from `resume`, in `chunk`-sized bites.
            let resume = resume as usize;
            let mut frame_buf = [0u8; PAYLOAD];
            let head = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[]).unwrap();
            let room = budget.saturating_sub(head).min(chunk);
            let end = (resume + room).min(value.len());
            let fragment = &value[resume..end];
            let len = frame::prop_is(&mut frame_buf, 0, prop::CAPS, fragment).unwrap();
            let remaining = (value.len() - end) as u32;
            let len = device
                .complete(
                    Produced::fragment(&frame_buf[..len], fragment.len() as u32, remaining),
                    &mut response,
                )
                .expect("complete")
                .expect("a response");

            now += 100;
            step = admin
                .receive(&response[..len], &mut reassembly, now, &mut wire)
                .expect("this exchange's response");
        }

        let Step::Done(outcome) = step else {
            panic!("expected a finished exchange, got {step:?}");
        };
        (outcome, reassembly.frame().to_vec())
    }

    #[test]
    fn a_read_that_fits_one_payload_finishes_in_one_exchange() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let value: Vec<u8> = (0..16u8).collect();

        let (outcome, assembled) = converse(frame, &value, 256);
        let Outcome::Replied { len } = outcome else {
            panic!("expected a reply, got {outcome:?}");
        };
        assert_eq!(len, assembled.len());
        assert_eq!(crate::fragment::trailing(&assembled), &value[..]);
    }

    #[test]
    fn a_read_spanning_several_exchanges_reassembles_to_the_whole_value() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let value: Vec<u8> = (0..500u32).map(|index| index as u8).collect();

        for chunk in [1, 7, 64, 128] {
            let (outcome, assembled) = converse(frame, &value, chunk);
            assert!(
                matches!(outcome, Outcome::Replied { .. }),
                "chunk {chunk}: {outcome:?}"
            );
            assert_eq!(
                crate::fragment::trailing(&assembled),
                &value[..],
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn each_continuation_carries_a_fresh_token_and_the_cursor_verbatim() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut device = Device::new(1);
        let mut admin = Admin::new(frame, 100, 0).expect("begin");
        let mut storage = [0u8; 1024];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];

        let Step::Send { len } = admin.poll(0, &mut wire) else {
            panic!("expected a request");
        };
        let first_token = Envelope::parse(&wire[..len]).unwrap().token;

        let mut response = [0u8; PAYLOAD];
        assert!(matches!(
            device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
            Ingress::Dispatch(_)
        ));
        let mut frame_buf = [0u8; 32];
        let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[1, 2, 3, 4]).unwrap();
        let len = device
            .complete(
                Produced::fragment(&frame_buf[..reply], 4, 12),
                &mut response,
            )
            .unwrap()
            .unwrap();
        let issued = Envelope::parse(&response[..len]).unwrap();
        let cursor = issued.cursor.expect("a cursor").to_vec();
        assert_eq!(admin.remaining(), None);

        let Some(Step::Send { len }) =
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire)
        else {
            panic!("expected a continuation");
        };
        let continuation = Envelope::parse(&wire[..len]).unwrap();
        assert_ne!(continuation.token, first_token);
        assert_eq!(continuation.cursor, Some(&cursor[..]));
        assert_eq!(continuation.frame, frame, "the read is repeated verbatim");
        assert_eq!(admin.remaining(), Some(12));
        assert_eq!(
            admin.counter(),
            101,
            "the counter reports the continuation's token, so a successor \
             seeded from it cannot reissue one the device has answered"
        );
    }

    #[test]
    fn a_refused_cursor_ends_the_exchange_so_the_caller_can_start_over() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut device = Device::new(1);
        let mut admin = Admin::new(frame, 5, 0).expect("begin");
        let mut storage = [0u8; 1024];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut response = [0u8; PAYLOAD];

        // One fragment at generation 1, issuing a cursor.
        let Step::Send { len } = admin.poll(0, &mut wire) else {
            panic!("expected a request");
        };
        assert!(matches!(
            device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
            Ingress::Dispatch(_)
        ));
        let mut frame_buf = [0u8; 32];
        let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[1, 2]).unwrap();
        let len = device
            .complete(Produced::fragment(&frame_buf[..reply], 2, 8), &mut response)
            .unwrap()
            .unwrap();
        let Some(Step::Send { len }) =
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire)
        else {
            panic!("expected a continuation");
        };

        // The device domain moves before the continuation lands.
        let Ingress::Respond { len } = device.begin(&ADMIN, &wire[..len], 2, 0, &mut response)
        else {
            panic!("expected a refusal");
        };
        assert_eq!(
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire),
            Some(Step::Done(Outcome::Failed(Failure::CursorInvalid)))
        );
    }

    #[test]
    fn an_empty_fragment_paces_the_next_request_rather_than_spinning() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut device = Device::new(1);
        let mut admin = Admin::new(frame, 11, 0).expect("begin");
        let mut storage = [0u8; 256];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut response = [0u8; PAYLOAD];
        let mut frame_buf = [0u8; 32];

        let Step::Send { len } = admin.poll(0, &mut wire) else {
            panic!("expected a request");
        };
        assert!(matches!(
            device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
            Ingress::Dispatch(_)
        ));
        let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[1, 2]).unwrap();
        let len = device
            .complete(Produced::fragment(&frame_buf[..reply], 2, 4), &mut response)
            .unwrap()
            .unwrap();
        let Some(Step::Send { len }) =
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire)
        else {
            panic!("expected a continuation");
        };

        // Nothing further is available yet: the same cursor comes back
        // with an empty fragment.
        assert!(matches!(
            device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
            Ingress::Dispatch(_)
        ));
        let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[]).unwrap();
        let len = device
            .complete(Produced::fragment(&frame_buf[..reply], 0, 4), &mut response)
            .unwrap()
            .unwrap();
        assert_eq!(
            admin.receive(&response[..len], &mut reassembly, 100, &mut wire),
            Some(Step::Wait {
                deadline_ms: 100 + RETRY_MS
            })
        );
        // Nothing was contributed, and the read is still going.
        assert_eq!(crate::fragment::trailing(reassembly.frame()), &[1u8, 2][..]);
        assert!(matches!(
            admin.poll(100 + RETRY_MS, &mut wire),
            Step::Send { .. }
        ));
    }

    #[test]
    fn a_read_larger_than_the_reassembly_buffer_fails_rather_than_truncating() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut device = Device::new(1);
        let mut admin = Admin::new(frame, 5, 0).expect("begin");
        let mut storage = [0u8; 24];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut response = [0u8; PAYLOAD];
        let mut frame_buf = [0u8; 64];

        let mut step = admin.poll(0, &mut wire);
        for _ in 0..8 {
            let Step::Send { len } = step else { break };
            assert!(matches!(
                device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
                Ingress::Dispatch(_)
            ));
            let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[0; 16]).unwrap();
            let len = device
                .complete(
                    Produced::fragment(&frame_buf[..reply], 16, 999),
                    &mut response,
                )
                .unwrap()
                .unwrap();
            step = admin
                .receive(&response[..len], &mut reassembly, 0, &mut wire)
                .expect("this exchange's response");
        }
        assert_eq!(step, Step::Done(Outcome::Failed(Failure::TooLarge)));
    }

    #[test]
    fn an_unknown_critical_option_in_a_response_fails_the_exchange() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut admin = Admin::new(frame, 0x0102, 0).expect("begin");
        let mut wire = [0u8; PAYLOAD];
        admin.poll(0, &mut wire);
        let token = admin.token();

        let mut response = [0u8; PAYLOAD];
        response[0] = token[0];
        response[1] = token[1];
        let len = {
            let mut enc = umsh_core::options::OptionEncoder::new(&mut response[2..]);
            enc.put(5, &[0]).unwrap();
            enc.end_marker().unwrap();
            2 + enc.finish()
        };

        let mut storage = [0u8; 64];
        let mut reassembly = Reassembly::new(&mut storage);
        assert_eq!(
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire),
            Some(Step::Done(Outcome::Failed(Failure::UnknownCriticalOption(
                5
            ))))
        );
    }

    #[test]
    fn a_response_whose_frame_does_not_parse_fails_the_exchange() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut admin = Admin::new(frame, 3, 0).expect("begin");
        let mut wire = [0u8; PAYLOAD];
        admin.poll(0, &mut wire);

        let mut response = [0u8; PAYLOAD];
        let len = Envelope::new(admin.token(), &[0x00])
            .encode(&mut response)
            .unwrap();
        let mut storage = [0u8; 64];
        let mut reassembly = Reassembly::new(&mut storage);
        assert_eq!(
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire),
            Some(Step::Done(Outcome::Failed(Failure::Malformed)))
        );
    }

    #[test]
    fn a_finished_exchange_ignores_everything_that_arrives_after() {
        let mut buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut buf);
        let frame = &buf[..frame_len];
        let mut admin = Admin::new(frame, 3, 0).expect("begin");
        let mut wire = [0u8; PAYLOAD];
        admin.poll(0, &mut wire);

        let mut response = [0u8; PAYLOAD];
        let mut frame_buf = [0u8; 16];
        let reply = frame::prop_is(&mut frame_buf, 0, prop::CAPS, &[9]).unwrap();
        let len = Envelope::new(admin.token(), &frame_buf[..reply])
            .encode(&mut response)
            .unwrap();

        let mut storage = [0u8; 64];
        let mut reassembly = Reassembly::new(&mut storage);
        assert!(matches!(
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire),
            Some(Step::Done(Outcome::Replied { .. }))
        ));
        assert_eq!(
            admin.receive(&response[..len], &mut reassembly, 0, &mut wire),
            None
        );
        assert!(matches!(
            admin.poll(1_000_000, &mut wire),
            Step::Done(Outcome::Replied { .. })
        ));
    }

    #[test]
    fn a_multi_get_reassembles_into_one_are_frame() {
        let mut buf = [0u8; 16];
        let len = frame::prop_multi_get(&mut buf, 0, &[prop::CAPS, prop::DEV_ADMINS]).unwrap();
        let request = &buf[..len];

        let mut device = Device::new(1);
        let mut admin = Admin::new(request, 9, 0).expect("begin");
        let mut storage = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut storage);
        let mut wire = [0u8; PAYLOAD];
        let mut response = [0u8; PAYLOAD];

        // The whole entry list, served two entries at a time.
        let mut whole = [0u8; 128];
        let whole_len = {
            let mut writer = frame::prop_are(&mut whole, 0).unwrap();
            for index in 0..4u32 {
                writer
                    .write_entry(prop::CAPS + index, &[index as u8; 8])
                    .unwrap();
            }
            writer.finish()
        };
        // Skip the two-octet frame header to get the entry list alone.
        let entries = &whole[2..whole_len];

        let mut served = 0usize;
        let mut step = admin.poll(0, &mut wire);
        while let Step::Send { len } = step {
            assert!(matches!(
                device.begin(&ADMIN, &wire[..len], 1, 0, &mut response),
                Ingress::Dispatch(_)
            ));
            let end = (served + 22).min(entries.len());
            let mut frame_buf = [0u8; 64];
            let reply = {
                let mut writer = frame::prop_are(&mut frame_buf, 0).unwrap();
                writer.write_bytes(&entries[served..end]).unwrap();
                writer.finish()
            };
            let produced = (end - served) as u32;
            let remaining = (entries.len() - end) as u32;
            served = end;
            let len = device
                .complete(
                    Produced::fragment(&frame_buf[..reply], produced, remaining),
                    &mut response,
                )
                .unwrap()
                .unwrap();
            step = admin
                .receive(&response[..len], &mut reassembly, 0, &mut wire)
                .expect("this exchange's response");
        }

        assert!(matches!(step, Step::Done(Outcome::Replied { .. })));
        assert_eq!(reassembly.frame(), &whole[..whole_len]);
    }
}
