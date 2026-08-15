//! The device side of an exchange: tokens, retained responses, and
//! cursors.
//!
//! The engine performs no I/O and runs no ULCP command. It reads an
//! arriving request, decides whether the request needs to be executed at
//! all, and hands the caller the embedded frame together with where in a
//! continued read to resume. The caller dispatches that frame through
//! whatever machinery serves its local link and reports what came back;
//! the engine wraps it, hands it out, and retains it against a
//! retransmission.
//!
//! Authorization is not the engine's concern: a request reaches it only
//! after its source has been checked against the administrator list.

use umsh_ulcp::frame::{self, Cmd, Frame};
use umsh_ulcp::status::Status;

use crate::envelope::{Envelope, EnvelopeError, Token};

/// An Ed25519 public key naming a node.
pub type PublicKey = [u8; 32];

/// Retained entries the reference engine keeps, one per administrator.
///
/// The spec requires only the most recently active administrator's, and
/// bounds nothing above that. Four covers a device managed by a handful
/// of people at once and costs about a kilobyte.
pub const CACHE_ENTRIES: usize = 4;

/// Why an arriving payload produced nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The payload was too short to hold a token, so there is nothing to
    /// correlate a response with and no way to report the problem.
    NoToken,
    /// The output buffer could not hold the response. The caller sized
    /// it below the transport's own payload limit.
    NoRoom,
}

/// What the caller must do with an arriving payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress<'p> {
    /// Send nothing and account for it.
    Drop(DropReason),
    /// `out[..len]` is a complete response payload: a retained response
    /// being retransmitted, or an error the engine answered on its own.
    Respond { len: usize },
    /// Dispatch the frame, then call [`DeviceEngine::complete`].
    Dispatch(Dispatch<'p>),
}

/// A request the engine wants executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch<'p> {
    /// Exactly one ULCP frame, in the grammar of the local bindings. Its
    /// TID is zero and receivers ignore it.
    pub frame: &'p [u8],
    /// Where in the logical trailing content — the value of a
    /// `CMD_PROP_IS`, or the entry list of a `CMD_PROP_ARE` — this
    /// response resumes. Zero for a request carrying no cursor.
    pub resume: u32,
    /// Octets available for the reply frame, the envelope's worst case
    /// already deducted.
    pub budget: usize,
    /// A reset-class command, which is answered by no response payload
    /// at all. The caller executes it and completes with
    /// [`Produced::no_response`].
    pub resets: bool,
}

impl Dispatch<'_> {
    /// The parsed command, absent when this build does not define it.
    /// Such a frame is the caller's to answer `STATUS_INVALID_COMMAND`;
    /// the engine only needed enough of it to apply the cursor rules.
    pub fn command(&self) -> Option<Cmd> {
        Frame::parse(self.frame).ok().and_then(|f| f.command())
    }
}

/// What dispatching a frame produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Produced<'a> {
    /// The reply frame, or empty for a reset-class command.
    pub frame: &'a [u8],
    /// Octets of trailing content this frame carries, which is where the
    /// next fragment resumes. Meaningless unless `remaining` is nonzero.
    pub produced: u32,
    /// Octets of trailing content this frame does not carry. Zero ends
    /// the read; anything else issues a cursor.
    pub remaining: u32,
}

impl<'a> Produced<'a> {
    /// A reply that says everything it has to say.
    pub const fn complete(frame: &'a [u8]) -> Self {
        Self {
            frame,
            produced: 0,
            remaining: 0,
        }
    }

    /// A leading fragment of a read that does not fit one payload.
    pub const fn fragment(frame: &'a [u8], produced: u32, remaining: u32) -> Self {
        Self {
            frame,
            produced,
            remaining,
        }
    }

    /// A reset-class command: executed, and answered by nothing.
    pub const fn no_response() -> Self {
        Self {
            frame: &[],
            produced: 0,
            remaining: 0,
        }
    }
}

/// Why a response could not be assembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteError {
    /// [`DeviceEngine::complete`] was called without a dispatch in
    /// flight.
    NotDispatched,
    /// The reply frame exceeds the budget the dispatch handed out, or
    /// the read ran past what a cursor can address.
    TooLarge,
}

/// A cursor as this engine issues them.
///
/// ```text
/// +-------+------------+-----+--------+
/// | NONCE | GENERATION | TAG | OFFSET |
/// +-------+------------+-----+--------+
///    2 B       2 B       2 B    2 B
/// ```
///
/// Opaque to the administrator, which returns it byte for byte. Each
/// field answers one of the ways a cursor can go stale: NONCE a reboot,
/// GENERATION a device-domain change out from under the position, and
/// TAG a cursor presented with a read other than the one it was issued
/// for. OFFSET caps a continued read at 64 KiB, which is orders of
/// magnitude past anything a device holds.
const CURSOR_LEN: usize = 8;

fn encode_cursor(nonce: u16, generation: u16, tag: u16, offset: u16) -> [u8; CURSOR_LEN] {
    let mut out = [0u8; CURSOR_LEN];
    out[0..2].copy_from_slice(&nonce.to_be_bytes());
    out[2..4].copy_from_slice(&generation.to_be_bytes());
    out[4..6].copy_from_slice(&tag.to_be_bytes());
    out[6..8].copy_from_slice(&offset.to_be_bytes());
    out
}

/// A 16-bit FNV-1a of the request frame, binding a cursor to the read it
/// was issued for. A continuation repeats the frame verbatim — the
/// cursor rides in the envelope, not the frame — so an honest
/// continuation always matches.
fn request_tag(frame: &[u8]) -> u16 {
    let mut hash: u32 = 0x811C_9DC5;
    for &byte in frame {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Fold to 16 bits rather than truncate, so every input byte reaches
    // the result.
    ((hash >> 16) ^ hash) as u16
}

/// Whether a cursor may continue this command.
const fn continuable(cmd: Cmd) -> bool {
    matches!(cmd, Cmd::PropGet | Cmd::PropMultiGet)
}

/// Whether this command initiates a reset, and so is answered by no
/// response payload.
///
/// `CMD_RESTORE` qualifies because a device that has a saved snapshot
/// resets into it; one that has none answers normally, but the
/// administrator cannot know which in advance, so the binding treats the
/// command as reset-class either way and the administrator confirms
/// delivery with a MAC acknowledgment.
const fn reset_class(cmd: Cmd) -> bool {
    matches!(cmd, Cmd::Reset | Cmd::Restore | Cmd::FactoryReset)
}

/// One administrator's most recent exchange.
#[derive(Clone, Copy)]
struct Entry<const PAYLOAD: usize> {
    key: PublicKey,
    token: Token,
    payload: [u8; PAYLOAD],
    len: usize,
    /// When this administrator was last heard from, for eviction.
    last_ms: u64,
    occupied: bool,
}

// `[u8; PAYLOAD]` does not derive `Default` for an arbitrary const.
impl<const PAYLOAD: usize> Default for Entry<PAYLOAD> {
    fn default() -> Self {
        Self {
            key: [0; 32],
            token: [0; 2],
            payload: [0; PAYLOAD],
            len: 0,
            last_ms: 0,
            occupied: false,
        }
    }
}

/// The exchange between [`DeviceEngine::begin`] and
/// [`DeviceEngine::complete`].
#[derive(Clone, Copy)]
struct InFlight {
    key: PublicKey,
    token: Token,
    generation: u16,
    tag: u16,
    resume: u32,
    budget: usize,
    now_ms: u64,
}

/// The device half of the Node Management binding.
///
/// `PAYLOAD` is the largest response payload the transport can carry,
/// which is also the size of each retained entry. `ENTRIES` is how many
/// administrators keep a retained response.
pub struct DeviceEngine<const PAYLOAD: usize, const ENTRIES: usize = CACHE_ENTRIES> {
    nonce: u16,
    entries: [Entry<PAYLOAD>; ENTRIES],
    in_flight: Option<InFlight>,
}

impl<const PAYLOAD: usize, const ENTRIES: usize> DeviceEngine<PAYLOAD, ENTRIES> {
    /// Build an engine. `nonce` is drawn once per boot from the
    /// cryptographic RNG: it is what stops a cursor issued before a
    /// reboot from being honored after one, when the generation counter
    /// has started over.
    pub fn new(nonce: u16) -> Self {
        Self {
            nonce,
            entries: [Entry::default(); ENTRIES],
            in_flight: None,
        }
    }

    /// Read an arriving Node Management Request payload, the payload type
    /// byte already stripped.
    ///
    /// `generation` is the device-domain version: every change to it
    /// invalidates the cursors issued before it. `now_ms` orders the
    /// retained entries for eviction.
    pub fn begin<'p>(
        &mut self,
        from: &PublicKey,
        payload: &'p [u8],
        generation: u16,
        now_ms: u64,
        out: &mut [u8],
    ) -> Ingress<'p> {
        self.in_flight = None;

        // The token leads the payload, so it survives anything the
        // option block does. Every envelope that has one is answered;
        // only a payload too short to hold one is dropped, since a
        // response nothing can be correlated with is no answer at all.
        let &[token0, token1, ..] = payload else {
            return Ingress::Drop(DropReason::NoToken);
        };
        let token = [token0, token1];

        let request = match Envelope::parse(payload) {
            Ok(request) => request,
            Err(EnvelopeError::UnknownCritical(_)) => {
                return self.answer(from, token, Status::UNIMPLEMENTED, now_ms, out);
            }
            Err(EnvelopeError::InvalidOptionValue(crate::envelope::OPT_CURSOR)) => {
                return self.answer(from, token, Status::CURSOR_INVALID, now_ms, out);
            }
            Err(_) => return self.answer(from, token, Status::PARSE_ERROR, now_ms, out),
        };

        // A retransmission is answered from the retained response
        // without executing anything — before the request is even looked
        // at, since the point is not to look at it again.
        if let Some(entry) = self.retained(from, token) {
            entry.last_ms = now_ms;
            let len = entry.len;
            if out.len() < len {
                return Ingress::Drop(DropReason::NoRoom);
            }
            out[..len].copy_from_slice(&entry.payload[..len]);
            return Ingress::Respond { len };
        }

        // A frame that does not parse is answered rather than dropped:
        // the administrator learns its request was heard and malformed.
        let Ok(parsed) = Frame::parse(request.frame) else {
            return self.answer(from, token, Status::PARSE_ERROR, now_ms, out);
        };
        let cmd = parsed.command();

        let mut resume = 0;
        if let Some(cursor) = request.cursor {
            // A cursor on something that is not a read at all, including
            // a command this build does not define.
            if !cmd.is_some_and(continuable) {
                return self.answer(from, token, Status::INVALID_ARGUMENT, now_ms, out);
            }
            match self.parse_cursor(cursor, generation, request.frame) {
                Some(offset) => resume = offset,
                None => return self.answer(from, token, Status::CURSOR_INVALID, now_ms, out),
            }
        }

        let budget = PAYLOAD
            .min(out.len())
            .saturating_sub(crate::envelope::OVERHEAD_MAX);
        self.in_flight = Some(InFlight {
            key: *from,
            token,
            generation,
            // Binds any cursor this exchange issues to the read that
            // issued it.
            tag: request_tag(request.frame),
            resume,
            budget,
            now_ms,
        });
        Ingress::Dispatch(Dispatch {
            frame: request.frame,
            resume,
            // Measured against the worst envelope rather than this
            // request's, so a reply that turns out to need a cursor
            // still fits the payload it was sized for.
            budget,
            resets: cmd.is_some_and(reset_class),
        })
    }

    /// Wrap what the dispatch produced, retain it, and write the
    /// response payload into `out`.
    ///
    /// Returns the payload's length, or `None` for a reset-class command,
    /// which is answered by no payload at all.
    pub fn complete(
        &mut self,
        produced: Produced<'_>,
        out: &mut [u8],
    ) -> Result<Option<usize>, CompleteError> {
        let in_flight = self.in_flight.take().ok_or(CompleteError::NotDispatched)?;

        if produced.frame.is_empty() {
            // A reset takes the retained entries with it: after one, a
            // retransmitted request is executed again, with the same
            // result.
            self.entries = [Entry::default(); ENTRIES];
            return Ok(None);
        }

        if produced.frame.len() > in_flight.budget {
            return Err(CompleteError::TooLarge);
        }

        let mut response = Envelope::new(in_flight.token, produced.frame);
        let cursor;
        if produced.remaining > 0 {
            let offset = in_flight
                .resume
                .checked_add(produced.produced)
                .and_then(|offset| u16::try_from(offset).ok())
                .ok_or(CompleteError::TooLarge)?;
            cursor = encode_cursor(self.nonce, in_flight.generation, in_flight.tag, offset);
            response = response
                .with_cursor(&cursor)
                .with_remaining(produced.remaining);
        }

        let len = response.encode(out).map_err(|_| CompleteError::TooLarge)?;
        self.retain(
            &in_flight.key,
            in_flight.token,
            &out[..len],
            in_flight.now_ms,
        );
        Ok(Some(len))
    }

    /// Forget every retained response, as a reset does.
    pub fn forget_retained(&mut self) {
        self.entries = [Entry::default(); ENTRIES];
    }

    /// Answer a request the engine can decide on its own, and retain the
    /// answer like any other.
    fn answer(
        &mut self,
        from: &PublicKey,
        token: Token,
        status: Status,
        now_ms: u64,
        out: &mut [u8],
    ) -> Ingress<'static> {
        let mut buf = [0u8; 8];
        let Ok(len) = frame::last_status(&mut buf, frame::TID_UNSOLICITED, status) else {
            return Ingress::Drop(DropReason::NoRoom);
        };
        let Ok(len) = Envelope::new(token, &buf[..len]).encode(out) else {
            return Ingress::Drop(DropReason::NoRoom);
        };
        self.retain(from, token, &out[..len], now_ms);
        Ingress::Respond { len }
    }

    /// The offset a cursor names, or `None` if it cannot be honored.
    fn parse_cursor(&self, cursor: &[u8], generation: u16, frame: &[u8]) -> Option<u32> {
        let cursor: [u8; CURSOR_LEN] = cursor.try_into().ok()?;
        let nonce = u16::from_be_bytes([cursor[0], cursor[1]]);
        let issued_at = u16::from_be_bytes([cursor[2], cursor[3]]);
        let tag = u16::from_be_bytes([cursor[4], cursor[5]]);
        let offset = u16::from_be_bytes([cursor[6], cursor[7]]);
        if nonce != self.nonce || issued_at != generation || tag != request_tag(frame) {
            return None;
        }
        Some(u32::from(offset))
    }

    fn retained(&mut self, key: &PublicKey, token: Token) -> Option<&mut Entry<PAYLOAD>> {
        self.entries
            .iter_mut()
            .find(|entry| entry.occupied && &entry.key == key && entry.token == token)
    }

    fn retain(&mut self, key: &PublicKey, token: Token, payload: &[u8], now_ms: u64) {
        if payload.len() > PAYLOAD {
            // Unretainable, so a retransmission would be executed again.
            // Nothing this crate builds gets here; a caller that
            // overruns its own budget does.
            return;
        }
        let slot = self
            .entries
            .iter_mut()
            .position(|entry| entry.occupied && &entry.key == key)
            .or_else(|| self.entries.iter().position(|entry| !entry.occupied))
            .or_else(|| {
                // Evict the least recently active administrator, which
                // by construction is never the one we are answering.
                self.entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.last_ms)
                    .map(|(index, _)| index)
            });
        let Some(slot) = slot else { return };
        let entry = &mut self.entries[slot];
        entry.key = *key;
        entry.token = token;
        entry.payload[..payload.len()].copy_from_slice(payload);
        entry.len = payload.len();
        entry.last_ms = now_ms;
        entry.occupied = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::ids::prop;

    const PAYLOAD: usize = 180;
    type Engine = DeviceEngine<PAYLOAD, 2>;

    const ALICE: PublicKey = [0xAA; 32];
    const BOB: PublicKey = [0xBB; 32];

    fn request(token: Token, frame: &[u8], out: &mut [u8]) -> usize {
        Envelope::new(token, frame).encode(out).expect("encode")
    }

    fn get(key: u32, buf: &mut [u8]) -> usize {
        frame::prop_get(buf, 0, key).expect("encode")
    }

    /// The status a `PROP_LAST_STATUS` response reports.
    fn reported_status(payload: &[u8]) -> Status {
        let envelope = Envelope::parse(payload).expect("envelope");
        let parsed = Frame::parse(envelope.frame).expect("frame");
        assert_eq!(parsed.command(), Some(Cmd::PropIs));
        let (key, consumed) = umsh_ulcp::pui::decode(parsed.payload).expect("key");
        assert_eq!(key, prop::LAST_STATUS);
        let (status, _) = umsh_ulcp::pui::decode(&parsed.payload[consumed..]).expect("status");
        Status(status)
    }

    #[test]
    fn a_plain_request_is_dispatched_and_its_reply_comes_back_whole() {
        let mut engine = Engine::new(0x1234);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 2], frame, &mut payload);

        let mut out = [0u8; PAYLOAD];
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 7, 0, &mut out)
        else {
            panic!("expected a dispatch");
        };
        assert_eq!(dispatch.frame, frame);
        assert_eq!(dispatch.resume, 0);
        assert!(!dispatch.resets);
        assert_eq!(dispatch.budget, PAYLOAD - crate::envelope::OVERHEAD_MAX);

        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[1, 2, 3]).unwrap();
        let len = engine
            .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
            .expect("complete")
            .expect("a response");

        let response = Envelope::parse(&out[..len]).expect("envelope");
        assert_eq!(response.token, [1, 2]);
        assert_eq!(response.cursor, None);
        assert_eq!(response.frame, &reply_buf[..reply_len]);
    }

    #[test]
    fn completing_without_a_dispatch_is_an_error() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        assert_eq!(
            engine.complete(Produced::complete(&[0x80, 0x06]), &mut out),
            Err(CompleteError::NotDispatched)
        );
    }

    #[test]
    fn a_repeated_token_is_answered_from_the_retained_response() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut payload = [0u8; PAYLOAD];
        let len = request([9, 9], frame, &mut payload);

        let mut out = [0u8; PAYLOAD];
        assert!(matches!(
            engine.begin(&ALICE, &payload[..len], 0, 0, &mut out),
            Ingress::Dispatch(_)
        ));
        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[7]).unwrap();
        let first = engine
            .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
            .unwrap()
            .unwrap();
        let first = out[..first].to_vec();

        // The identical request again: answered, not executed.
        let mut again = [0u8; PAYLOAD];
        match engine.begin(&ALICE, &payload[..len], 0, 1_000, &mut again) {
            Ingress::Respond { len } => assert_eq!(&again[..len], &first[..]),
            other => panic!("expected the retained response, got {other:?}"),
        }

        // A different administrator sending the same token has its own
        // exchange, and gets dispatched.
        assert!(matches!(
            engine.begin(&BOB, &payload[..len], 0, 2_000, &mut again),
            Ingress::Dispatch(_)
        ));
    }

    #[test]
    fn a_new_token_from_the_same_administrator_replaces_the_retained_entry() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];
        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[7]).unwrap();

        for token in [[1, 1], [2, 2]] {
            let mut payload = [0u8; PAYLOAD];
            let len = request(token, frame, &mut payload);
            assert!(matches!(
                engine.begin(&ALICE, &payload[..len], 0, 0, &mut out),
                Ingress::Dispatch(_)
            ));
            engine
                .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
                .unwrap();
        }

        // Only the most recent exchange is retained, and one
        // administrator never occupies two slots.
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 1], frame, &mut payload);
        assert!(matches!(
            engine.begin(&ALICE, &payload[..len], 0, 0, &mut out),
            Ingress::Dispatch(_)
        ));
        assert_eq!(engine.entries.iter().filter(|e| e.occupied).count(), 1);
    }

    #[test]
    fn the_least_recently_active_administrator_is_evicted() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];
        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[7]).unwrap();
        let carol: PublicKey = [0xCC; 32];

        // Two slots, three administrators; Alice is the stalest.
        for (key, now) in [(&ALICE, 0u64), (&BOB, 10), (&carol, 20)] {
            let mut payload = [0u8; PAYLOAD];
            let len = request([1, 1], frame, &mut payload);
            assert!(matches!(
                engine.begin(key, &payload[..len], 0, now, &mut out),
                Ingress::Dispatch(_)
            ));
            engine
                .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
                .unwrap();
        }

        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 1], frame, &mut payload);
        // Bob and Carol are still answered from their retained entries.
        assert!(matches!(
            engine.begin(&BOB, &payload[..len], 0, 30, &mut out),
            Ingress::Respond { .. }
        ));
        // Alice's is gone, so her retransmission is executed again.
        assert!(matches!(
            engine.begin(&ALICE, &payload[..len], 0, 40, &mut out),
            Ingress::Dispatch(_)
        ));
    }

    #[test]
    fn a_frame_that_does_not_parse_is_answered_parse_error() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];

        for frame in [&[][..], &[0x00, 0x02][..], &[0x80][..]] {
            let mut payload = [0u8; PAYLOAD];
            let len = request([3, 3], frame, &mut payload);
            let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
            else {
                panic!("expected an answer for {frame:?}");
            };
            assert_eq!(reported_status(&out[..len]), Status::PARSE_ERROR);
            // Even the error is retained: a retransmission must not be
            // re-derived, only re-sent.
            engine.forget_retained();
        }
    }

    #[test]
    fn a_payload_too_short_for_a_token_is_dropped() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        for payload in [&[][..], &[0x01][..]] {
            assert_eq!(
                engine.begin(&ALICE, payload, 0, 0, &mut out),
                Ingress::Drop(DropReason::NoToken)
            );
        }
    }

    #[test]
    fn a_malformed_option_block_is_answered_because_the_token_precedes_it() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        // A length nibble promising more than the payload holds.
        let Ingress::Respond { len } = engine.begin(&ALICE, &[4, 5, 0x1F, 0x00], 0, 0, &mut out)
        else {
            panic!("expected an answer");
        };
        assert_eq!(reported_status(&out[..len]), Status::PARSE_ERROR);
        assert_eq!(Envelope::parse(&out[..len]).unwrap().token, [4, 5]);
    }

    #[test]
    fn a_cursor_of_an_impossible_width_is_answered_cursor_invalid() {
        let mut payload = [0u8; PAYLOAD];
        payload[0] = 1;
        payload[1] = 2;
        let len = {
            let mut enc = umsh_core::options::OptionEncoder::new(&mut payload[2..]);
            enc.put(crate::envelope::OPT_CURSOR, &[0u8; 9]).unwrap();
            enc.end_marker().unwrap();
            2 + enc.finish()
        };

        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out) else {
            panic!("expected an answer");
        };
        assert_eq!(reported_status(&out[..len]), Status::CURSOR_INVALID);
    }

    #[test]
    fn an_unknown_critical_option_is_answered_unimplemented() {
        let mut payload = [0u8; PAYLOAD];
        payload[0] = 5;
        payload[1] = 6;
        let len = {
            let mut enc = umsh_core::options::OptionEncoder::new(&mut payload[2..]);
            enc.put(7, &[0]).unwrap();
            enc.end_marker().unwrap();
            2 + enc.finish()
        };

        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out) else {
            panic!("expected an answer");
        };
        assert_eq!(reported_status(&out[..len]), Status::UNIMPLEMENTED);
        assert_eq!(Envelope::parse(&out[..len]).unwrap().token, [5, 6]);
    }

    /// Drive one fragment of a continued read, returning where it
    /// resumed and the length of the response written into `out`.
    fn fragment(
        engine: &mut Engine,
        token: Token,
        frame: &[u8],
        cursor: Option<&[u8]>,
        generation: u16,
        // Octets this fragment carries, and octets left after it.
        (produced, remaining): (u32, u32),
        out: &mut [u8],
    ) -> (u32, usize) {
        let mut payload = [0u8; PAYLOAD];
        let mut envelope = Envelope::new(token, frame);
        if let Some(cursor) = cursor {
            envelope = envelope.with_cursor(cursor);
        }
        let len = envelope.encode(&mut payload).expect("encode");
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], generation, 0, out)
        else {
            panic!("expected a dispatch");
        };
        let mut reply_buf = [0u8; 32];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[0; 4]).unwrap();
        let len = engine
            .complete(
                Produced::fragment(&reply_buf[..reply_len], produced, remaining),
                out,
            )
            .expect("complete")
            .expect("a response");
        (dispatch.resume, len)
    }

    #[test]
    fn a_cursor_carries_the_position_from_one_exchange_to_the_next() {
        let mut engine = Engine::new(0xBEEF);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];

        let (resume, len) = fragment(&mut engine, [1, 0], frame, None, 3, (40, 90), &mut out);
        assert_eq!(resume, 0);
        let first = Envelope::parse(&out[..len]).unwrap();
        assert_eq!(first.remaining, Some(90));
        let cursor = first.cursor.expect("a cursor").to_vec();

        let (resume, len) = fragment(
            &mut engine,
            [2, 0],
            frame,
            Some(&cursor),
            3,
            (40, 50),
            &mut out,
        );
        assert_eq!(resume, 40);
        let second = Envelope::parse(&out[..len]).unwrap();
        let cursor = second.cursor.expect("a cursor").to_vec();

        // The last fragment ends the read by carrying no cursor.
        let mut payload = [0u8; PAYLOAD];
        let len = Envelope::new([3, 0], frame)
            .with_cursor(&cursor)
            .encode(&mut payload)
            .unwrap();
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 3, 0, &mut out)
        else {
            panic!("expected a dispatch");
        };
        assert_eq!(dispatch.resume, 80);
        let mut reply_buf = [0u8; 32];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[0; 4]).unwrap();
        let len = engine
            .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(Envelope::parse(&out[..len]).unwrap().cursor, None);
    }

    #[test]
    fn a_cursor_is_refused_once_the_device_domain_moves() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];

        let (_, len) = fragment(&mut engine, [1, 0], frame, None, 5, (10, 10), &mut out);
        let cursor = Envelope::parse(&out[..len])
            .unwrap()
            .cursor
            .unwrap()
            .to_vec();

        let mut payload = [0u8; PAYLOAD];
        let len = Envelope::new([2, 0], frame)
            .with_cursor(&cursor)
            .encode(&mut payload)
            .unwrap();
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 6, 0, &mut out) else {
            panic!("a cursor issued at generation 5 must not be honored at 6");
        };
        assert_eq!(reported_status(&out[..len]), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_is_refused_for_a_read_other_than_the_one_it_began() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];
        let (_, len) = fragment(&mut engine, [1, 0], frame, None, 0, (10, 10), &mut out);
        let cursor = Envelope::parse(&out[..len])
            .unwrap()
            .cursor
            .unwrap()
            .to_vec();

        // Same command, different property.
        let mut other_buf = [0u8; 8];
        let other_len = get(prop::PROTOCOL_VERSION, &mut other_buf);
        let other = &other_buf[..other_len];
        let mut payload = [0u8; PAYLOAD];
        let len = Envelope::new([2, 0], other)
            .with_cursor(&cursor)
            .encode(&mut payload)
            .unwrap();
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out) else {
            panic!("expected a refusal");
        };
        assert_eq!(reported_status(&out[..len]), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_from_before_a_reboot_is_refused() {
        let mut engine = Engine::new(0x1111);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];
        let (_, len) = fragment(&mut engine, [1, 0], frame, None, 0, (10, 10), &mut out);
        let cursor = Envelope::parse(&out[..len])
            .unwrap()
            .cursor
            .unwrap()
            .to_vec();

        // Same generation — a counter that started over — but a new
        // per-boot nonce.
        let mut rebooted = Engine::new(0x2222);
        let mut payload = [0u8; PAYLOAD];
        let len = Envelope::new([2, 0], frame)
            .with_cursor(&cursor)
            .encode(&mut payload)
            .unwrap();
        let Ingress::Respond { len } = rebooted.begin(&ALICE, &payload[..len], 0, 0, &mut out)
        else {
            panic!("expected a refusal");
        };
        assert_eq!(reported_status(&out[..len]), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_malformed_cursor_is_refused_rather_than_read_from_the_beginning() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut out = [0u8; PAYLOAD];

        for cursor in [&[0u8][..], &[0u8; 7][..], &[0xFF; 8][..]] {
            let mut payload = [0u8; PAYLOAD];
            let len = Envelope::new([1, 0], frame)
                .with_cursor(cursor)
                .encode(&mut payload)
                .unwrap();
            let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
            else {
                panic!("expected a refusal for {cursor:?}");
            };
            assert_eq!(reported_status(&out[..len]), Status::CURSOR_INVALID);
            engine.forget_retained();
        }
    }

    #[test]
    fn a_cursor_on_a_request_that_is_not_a_read_is_an_invalid_argument() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        let mut frame_buf = [0u8; 8];

        for len in [
            frame::prop_set(&mut frame_buf, 0, prop::CAPS, &[1]).unwrap(),
            frame::save(&mut frame_buf, 0).unwrap(),
        ] {
            let mut payload = [0u8; PAYLOAD];
            let len = Envelope::new([1, 0], &frame_buf[..len])
                .with_cursor(&[0; 8])
                .encode(&mut payload)
                .unwrap();
            let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
            else {
                panic!("expected a refusal");
            };
            assert_eq!(reported_status(&out[..len]), Status::INVALID_ARGUMENT);
            engine.forget_retained();
        }
    }

    #[test]
    fn a_multi_get_continues_the_same_way_a_get_does() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 16];
        let len =
            frame::prop_multi_get(&mut frame_buf, 0, &[prop::CAPS, prop::DEV_ADMINS]).unwrap();
        let frame = &frame_buf[..len];
        let mut out = [0u8; PAYLOAD];

        let (_, len) = fragment(&mut engine, [1, 0], frame, None, 0, (60, 20), &mut out);
        let cursor = Envelope::parse(&out[..len])
            .unwrap()
            .cursor
            .unwrap()
            .to_vec();
        let (resume, _) = fragment(
            &mut engine,
            [2, 0],
            frame,
            Some(&cursor),
            0,
            (20, 0),
            &mut out,
        );
        assert_eq!(resume, 60);
    }

    #[test]
    fn a_reset_is_answered_by_nothing_and_forgets_what_was_retained() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        let mut frame_buf = [0u8; 8];

        // Something to retain first.
        let get_len = get(prop::CAPS, &mut frame_buf);
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 1], &frame_buf[..get_len], &mut payload);
        assert!(matches!(
            engine.begin(&ALICE, &payload[..len], 0, 0, &mut out),
            Ingress::Dispatch(_)
        ));
        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[7]).unwrap();
        engine
            .complete(Produced::complete(&reply_buf[..reply_len]), &mut out)
            .unwrap();

        let mut frame_buf = [0u8; 8];
        for len in [
            frame::reset(&mut frame_buf, 0).unwrap(),
            frame::restore(&mut frame_buf, 0).unwrap(),
            frame::factory_reset(&mut frame_buf, 0).unwrap(),
        ] {
            let mut payload = [0u8; PAYLOAD];
            let len = request([2, 2], &frame_buf[..len], &mut payload);
            let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
            else {
                panic!("expected a dispatch");
            };
            assert!(dispatch.resets);
            assert_eq!(engine.complete(Produced::no_response(), &mut out), Ok(None));
        }

        // The earlier exchange is no longer retained, so its
        // retransmission is executed again.
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 1], &frame_buf[..get_len], &mut payload);
        assert!(matches!(
            engine.begin(&ALICE, &payload[..len], 0, 0, &mut out),
            Ingress::Dispatch(_)
        ));
    }

    #[test]
    fn a_reply_that_overruns_the_budget_is_refused_rather_than_truncated() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 2], frame, &mut payload);

        let mut out = [0u8; PAYLOAD];
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
        else {
            panic!("expected a dispatch");
        };

        let oversized = [0u8; PAYLOAD];
        assert_eq!(
            engine.complete(
                Produced::complete(&oversized[..dispatch.budget + 1]),
                &mut out[..PAYLOAD]
            ),
            Err(CompleteError::TooLarge)
        );
    }

    #[test]
    fn a_reply_exactly_at_the_budget_fits_even_when_it_acquires_a_cursor() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0u8; 8];
        let frame_len = get(prop::CAPS, &mut frame_buf);
        let frame = &frame_buf[..frame_len];
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 2], frame, &mut payload);

        let mut out = [0u8; PAYLOAD];
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, 0, &mut out)
        else {
            panic!("expected a dispatch");
        };
        let full = [0u8; PAYLOAD];
        let len = engine
            .complete(
                Produced::fragment(&full[..dispatch.budget], 100, 200),
                &mut out,
            )
            .expect("the budget already allows for the worst envelope")
            .expect("a response");
        assert!(len <= PAYLOAD);
    }
}
