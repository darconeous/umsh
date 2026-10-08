//! The device side of an exchange: tokens, retained replies, and
//! cursors.
//!
//! The engine performs no I/O and runs no ULCP command. It reads an
//! arriving request and decides whether the request needs to be executed
//! at all. When it does, the caller dispatches the embedded frame through
//! whatever machinery serves its local link and hands back the whole
//! reply, and the engine wraps the share one payload carries.
//!
//! A reply is retained only where executing the request again would be
//! wrong. A command that changes something is retained so that its
//! retransmission is answered rather than executed twice. A read too
//! large for one payload is retained whole, so that every continuation is
//! cut from it and the read comes back as one execution produced it. A
//! read that fits one payload is not retained at all: running it again
//! changes nothing, so its retransmission is simply answered afresh.
//!
//! Authorization is not the engine's concern: a request reaches it only
//! after its source has been checked against the administrator list.

use umsh_ulcp::frame::{self, Cmd, Frame};
use umsh_ulcp::status::Status;

use crate::envelope::{Envelope, EnvelopeError, OVERHEAD_MAX, Token};
use crate::fragment::{Cut, continuable, cut};

/// An Ed25519 public key naming a node.
pub type PublicKey = [u8; 32];

/// How many administrators the reference engine retains a reply for at
/// once.
///
/// The spec requires only the most recently active administrator's, and
/// bounds nothing above that. An entry is occupied only by a write or a
/// read in progress, and costs a small header—the replies themselves
/// share the engine's pool—so four covers a device managed by a handful
/// of people at once.
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
    /// `out[..len]` is a complete response payload, and nothing was
    /// executed: a retransmission, the next fragment of a continued read,
    /// or an error the engine answered on its own.
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
    /// The largest reply frame [`DeviceEngine::complete`] takes back. A
    /// read may answer with as much as the engine retains, because its
    /// continuations are cut from the retained reply. Anything else must
    /// fit one response payload, the envelope's worst case already
    /// deducted, because there is no continuing it.
    pub budget: usize,
    /// A reset-class command, which is answered by no response payload
    /// at all. The caller executes it and completes with an empty reply.
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

/// Why a response could not be assembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteError {
    /// [`DeviceEngine::complete`] was called without a dispatch in
    /// flight.
    NotDispatched,
    /// The reply exceeds the budget the dispatch handed out, or its
    /// leading bytes leave a payload no room to carry any of it.
    TooLarge,
}

/// A cursor as this engine issues them.
///
/// ```text
/// +-------+--------+--------+
/// | NONCE | SERIAL | OFFSET |
/// +-------+--------+--------+
///    2 B     2 B      2 B
/// ```
///
/// Opaque to the administrator, which returns it byte for byte. A cursor
/// is a position in a reply the engine retains, so each field answers one
/// way that reply can be gone: NONCE a reboot, and SERIAL the
/// administrator's retained entry having moved on to another exchange,
/// or to nobody after an eviction or a reset. OFFSET is where in the
/// reply's trailing content the next fragment begins.
const CURSOR_LEN: usize = 6;

fn encode_cursor(nonce: u16, serial: u16, offset: u16) -> [u8; CURSOR_LEN] {
    let mut out = [0u8; CURSOR_LEN];
    out[0..2].copy_from_slice(&nonce.to_be_bytes());
    out[2..4].copy_from_slice(&serial.to_be_bytes());
    out[4..6].copy_from_slice(&offset.to_be_bytes());
    out
}

/// A 16-bit FNV-1a of the request frame, binding a continuation to the
/// read whose reply it is cut from. A continuation repeats the frame
/// verbatim—the cursor rides in the envelope, not the frame—so an
/// honest continuation always matches.
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

/// Whether this command initiates a reset, and so is answered by no
/// response payload.
///
/// `CMD_RESTORE` qualifies because a device that has a saved snapshot
/// resets into it; one that has none answers normally, but the
/// administrator cannot know which in advance, so the binding treats the
/// command as reset-class either way and the administrator confirms
/// delivery with a MAC acknowledgment. `CMD_REBOOT` qualifies for the
/// same reason: a board restarts and says nothing, while one that cannot
/// answers `STATUS_UNIMPLEMENTED`.
const fn reset_class(cmd: Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Reset | Cmd::Restore | Cmd::FactoryReset | Cmd::Reboot
    )
}

/// One administrator's most recent exchange, where it is one that has to
/// be retained.
///
/// What is kept is the whole reply, not the payload that carried it, and
/// it lives in the engine's shared pool at its own length. A write's
/// reply fits one payload and goes out whole; a read that does not fit
/// goes out a fragment per exchange, every fragment cut from this one
/// reply. The fragment fields record which share the exchange under
/// `token` carried, so a retransmission repeats exactly that.
#[derive(Clone, Copy, Default)]
struct Entry {
    key: PublicKey,
    token: Token,
    /// Where the reply lies in the pool.
    start: u16,
    len: u16,
    /// Leading octets every fragment repeats: all of them, for a reply
    /// with no trailing content.
    prefix: u16,
    /// The share of the trailing content `token`'s exchange carried.
    resume: u16,
    take: u16,
    /// [`request_tag`] of the frame the reply answers.
    tag: u16,
    /// What this reply's cursors name it by.
    serial: u16,
    /// When this administrator was last heard from, for eviction.
    last_ms: u64,
    occupied: bool,
}

impl Entry {
    fn reply<'p>(&self, pool: &'p [u8]) -> &'p [u8] {
        let start = usize::from(self.start);
        &pool[start..start + usize::from(self.len)]
    }

    fn trailing_len(&self) -> usize {
        usize::from(self.len - self.prefix)
    }

    /// Make `cut` the share this entry's exchange carries.
    fn carry(&mut self, cut: Cut) {
        // Every position lies within the reply, which `DeviceEngine::new`
        // holds to what a cursor's offset addresses.
        self.prefix = cut.prefix as u16;
        self.resume = cut.resume as u16;
        self.take = cut.take as u16;
    }

    /// Write the response payload carrying this entry's share of the
    /// reply it keeps in `pool`.
    fn encode(&self, pool: &[u8], nonce: u16, out: &mut [u8]) -> Option<usize> {
        let (prefix, trailing) = self.reply(pool).split_at(usize::from(self.prefix));
        let start = usize::from(self.resume);
        let end = start + usize::from(self.take);
        let fragment = &trailing[start..end];
        let remaining = trailing.len() - end;

        let cursor = encode_cursor(nonce, self.serial, end as u16);
        let mut envelope = Envelope::new(self.token, &[]);
        if remaining > 0 {
            envelope = envelope
                .with_cursor(&cursor)
                .with_remaining(remaining as u32);
        }
        // The frame is the prefix followed by the fragment, which are not
        // contiguous in the reply, so the envelope goes first and the two
        // parts after it.
        let head = envelope.encode(out).ok()?;
        let len = head + prefix.len() + fragment.len();
        let (lead, rest) = out.get_mut(head..len)?.split_at_mut(prefix.len());
        lead.copy_from_slice(prefix);
        rest.copy_from_slice(fragment);
        Some(len)
    }
}

/// The exchange between [`DeviceEngine::begin`] and
/// [`DeviceEngine::complete`].
#[derive(Clone, Copy)]
struct InFlight {
    key: PublicKey,
    token: Token,
    tag: u16,
    /// A read, whose reply is retained only when it does not fit one
    /// payload.
    read: bool,
    budget: usize,
    /// Frame octets one response payload carries.
    room: usize,
    now_ms: u64,
}

/// The device half of the Node Management binding.
///
/// `PAYLOAD` is the largest response payload the transport can carry.
/// `POOL` is the octets every retained reply shares, each held at its own
/// length and the least recently active administrator's evicted when a
/// new one needs the room. It is also the largest read the engine can
/// serve, since a read too large for one payload is retained whole so
/// that its continuations can be cut from it. `ENTRIES` is how many
/// administrators can hold a retained reply at once.
pub struct DeviceEngine<
    const PAYLOAD: usize,
    const POOL: usize,
    const ENTRIES: usize = CACHE_ENTRIES,
> {
    nonce: u16,
    /// The serial the next retained reply takes.
    serial: u16,
    entries: [Entry; ENTRIES],
    /// Every retained reply, packed from the start by [`Self::compact`].
    pool: [u8; POOL],
    in_flight: Option<InFlight>,
}

impl<const PAYLOAD: usize, const POOL: usize, const ENTRIES: usize>
    DeviceEngine<PAYLOAD, POOL, ENTRIES>
{
    const ADDRESSABLE: () = assert!(
        POOL <= u16::MAX as usize,
        "a cursor addresses at most 64 KiB of reply"
    );

    /// Build an engine. `nonce` is drawn once per boot from the
    /// cryptographic RNG: it is what stops a cursor issued before a
    /// reboot from being honored after one, when the serials have
    /// started over.
    pub fn new(nonce: u16) -> Self {
        let () = Self::ADDRESSABLE;
        Self {
            nonce,
            serial: 0,
            entries: [Entry::default(); ENTRIES],
            pool: [0; POOL],
            in_flight: None,
        }
    }

    /// Read an arriving Node Management Request payload, the payload type
    /// byte already stripped.
    ///
    /// `now_ms` orders the retained entries for eviction.
    pub fn begin<'p>(
        &mut self,
        from: &PublicKey,
        payload: &'p [u8],
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

        // A retransmission of a retained exchange is answered from the
        // retained reply without executing anything—before the request
        // is even looked at, since the point is not to look at it again.
        if let Some(index) = self.retained(from, token) {
            self.entries[index].last_ms = now_ms;
            return self.respond(index, out);
        }

        let request = match Envelope::parse(payload) {
            Ok(request) => request,
            Err(EnvelopeError::UnknownCritical(_)) => {
                return self.answer(from, token, Status::UNIMPLEMENTED, out);
            }
            Err(EnvelopeError::InvalidOptionValue(crate::envelope::OPT_CURSOR)) => {
                return self.answer(from, token, Status::CURSOR_INVALID, out);
            }
            Err(_) => return self.answer(from, token, Status::PARSE_ERROR, out),
        };

        // A frame that does not parse is answered rather than dropped:
        // the administrator learns its request was heard and malformed.
        let Ok(parsed) = Frame::parse(request.frame) else {
            return self.answer(from, token, Status::PARSE_ERROR, out);
        };
        let cmd = parsed.command();
        let read = cmd.is_some_and(continuable);
        let room = Self::room(out);

        if let Some(cursor) = request.cursor {
            // A cursor on something that is not a read at all, including
            // a command this build does not define.
            if !read {
                return self.answer(from, token, Status::INVALID_ARGUMENT, out);
            }
            let Some((index, offset)) = self.continued(from, cursor, request.frame) else {
                return self.answer(from, token, Status::CURSOR_INVALID, out);
            };
            // A continuation executes nothing. It is the next fragment of
            // the reply its read began with, so the read comes back as
            // one execution produced it, however the device has changed
            // since.
            let Some(next) = cut(self.entries[index].reply(&self.pool), offset, room) else {
                return Ingress::Drop(DropReason::NoRoom);
            };
            let entry = &mut self.entries[index];
            entry.token = token;
            entry.last_ms = now_ms;
            entry.carry(next);
            return self.respond(index, out);
        }

        // A new exchange ends the one retained before it, whether or not
        // this one is retained in turn. Tokens need only differ from the
        // previous exchange's, so an older retained token is one the
        // administrator may legitimately use again.
        self.release(from);
        let budget = if read { POOL } else { room.min(POOL) };
        self.in_flight = Some(InFlight {
            key: *from,
            token,
            // Binds any cursor this exchange issues to the read that
            // issued it.
            tag: request_tag(request.frame),
            read,
            budget,
            room,
            now_ms,
        });
        Ingress::Dispatch(Dispatch {
            frame: request.frame,
            budget,
            resets: cmd.is_some_and(reset_class),
        })
    }

    /// Write the response payload carrying the first share of the reply
    /// the dispatch produced into `out`, retaining the reply unless it is
    /// a read that fits whole.
    ///
    /// `reply` is empty for a reset-class command, which is answered by
    /// no payload at all, and the result is then `None`; otherwise it is
    /// the payload's length.
    pub fn complete(
        &mut self,
        reply: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CompleteError> {
        let in_flight = self.in_flight.take().ok_or(CompleteError::NotDispatched)?;

        if reply.is_empty() {
            // A reset takes the retained entries with it: after one, a
            // retransmitted request is executed again, with the same
            // result, and a cursor has nothing left to continue.
            self.forget_retained();
            return Ok(None);
        }

        if reply.len() > in_flight.budget {
            return Err(CompleteError::TooLarge);
        }
        let first = cut(reply, 0, in_flight.room).ok_or(CompleteError::TooLarge)?;
        if in_flight.read && first.remaining == 0 {
            // Running a read again changes nothing, so its retransmission
            // is simply answered afresh, with current values.
            return Envelope::new(in_flight.token, reply)
                .encode(out)
                .map(Some)
                .map_err(|_| CompleteError::TooLarge);
        }
        let index = self
            .retain(
                &in_flight.key,
                in_flight.token,
                reply,
                first,
                in_flight.tag,
                in_flight.now_ms,
            )
            .ok_or(CompleteError::TooLarge)?;
        self.entries[index]
            .encode(&self.pool, self.nonce, out)
            .map(Some)
            .ok_or(CompleteError::TooLarge)
    }

    /// Forget every retained reply, as a reset does.
    pub fn forget_retained(&mut self) {
        self.entries = [Entry::default(); ENTRIES];
    }

    /// Replace an unsent lifecycle success with a failure for the same token.
    /// A retry must not replay OK after its pending handoff was canceled.
    pub fn fail_retained(&mut self, from: &PublicKey, token: Token) {
        let Some(index) = self.retained(from, token) else {
            return;
        };
        let last_ms = self.entries[index].last_ms;
        let mut buf = [0; 8];
        let len = frame::last_status(&mut buf, 0, Status::FAILURE).expect("status fits");
        let failure = &buf[..len];
        // Retaining afresh releases the success first, so even a failure
        // that could not be retained leaves no success to replay.
        let _ = cut(failure, 0, failure.len())
            .and_then(|whole| self.retain(from, token, failure, whole, 0, last_ms));
    }

    /// Frame octets one response payload carries, measured against the
    /// worst envelope rather than any particular one, so a fragment that
    /// acquires a cursor still fits the payload it was cut for.
    fn room(out: &[u8]) -> usize {
        PAYLOAD.min(out.len()).saturating_sub(OVERHEAD_MAX)
    }

    /// Answer a request the engine can decide on its own. Like any new
    /// exchange it ends the retained one; nothing of its own is retained,
    /// since the same request always draws the same answer.
    fn answer(
        &mut self,
        from: &PublicKey,
        token: Token,
        status: Status,
        out: &mut [u8],
    ) -> Ingress<'static> {
        self.release(from);
        let mut buf = [0u8; 8];
        let Ok(len) = frame::last_status(&mut buf, frame::TID_UNSOLICITED, status) else {
            return Ingress::Drop(DropReason::NoRoom);
        };
        match Envelope::new(token, &buf[..len]).encode(out) {
            Ok(len) => Ingress::Respond { len },
            Err(_) => Ingress::Drop(DropReason::NoRoom),
        }
    }

    /// Forget whatever `key` has retained.
    fn release(&mut self, key: &PublicKey) {
        for entry in self.entries.iter_mut() {
            if entry.occupied && &entry.key == key {
                entry.occupied = false;
            }
        }
    }

    /// Write the response payload for the share entry `index` carries.
    fn respond(&self, index: usize, out: &mut [u8]) -> Ingress<'static> {
        match self.entries[index].encode(&self.pool, self.nonce, out) {
            Some(len) => Ingress::Respond { len },
            None => Ingress::Drop(DropReason::NoRoom),
        }
    }

    /// The retained entry a cursor continues, and where in its reply's
    /// trailing content, or `None` if the cursor cannot be honored.
    fn continued(&self, from: &PublicKey, cursor: &[u8], frame: &[u8]) -> Option<(usize, usize)> {
        let cursor: [u8; CURSOR_LEN] = cursor.try_into().ok()?;
        let nonce = u16::from_be_bytes([cursor[0], cursor[1]]);
        let serial = u16::from_be_bytes([cursor[2], cursor[3]]);
        let offset = usize::from(u16::from_be_bytes([cursor[4], cursor[5]]));
        if nonce != self.nonce {
            return None;
        }
        // Retained under the administrator that began the read, so no
        // other administrator's cursor reaches it.
        let tag = request_tag(frame);
        let index = self.entries.iter().position(|entry| {
            entry.occupied && &entry.key == from && entry.serial == serial && entry.tag == tag
        })?;
        // Strictly inside the trailing content: a cursor is issued only
        // while something remains.
        (offset < self.entries[index].trailing_len()).then_some((index, offset))
    }

    fn retained(&self, key: &PublicKey, token: Token) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.occupied && &entry.key == key && entry.token == token)
    }

    /// Hold `reply` as `key`'s most recent exchange, carrying `cut`, and
    /// say where.
    ///
    /// The administrator's earlier entry gives way first. Then the least
    /// recently active administrators are evicted, one at a time, until
    /// both an entry and the reply's octets are free—which by
    /// construction never evicts the administrator being answered.
    fn retain(
        &mut self,
        key: &PublicKey,
        token: Token,
        reply: &[u8],
        cut: Cut,
        tag: u16,
        now_ms: u64,
    ) -> Option<usize> {
        if reply.len() > POOL {
            // Unretainable. Nothing this crate builds gets here; a caller
            // that overruns its own budget does.
            return None;
        }
        self.release(key);
        loop {
            let used: usize = self
                .entries
                .iter()
                .filter(|entry| entry.occupied)
                .map(|entry| usize::from(entry.len))
                .sum();
            let unoccupied = self.entries.iter().any(|entry| !entry.occupied);
            if unoccupied && used + reply.len() <= POOL {
                break;
            }
            let stalest = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.occupied)
                .min_by_key(|(_, entry)| entry.last_ms)
                .map(|(index, _)| index)?;
            self.entries[stalest].occupied = false;
        }
        let start = self.compact();
        let slot = self.entries.iter().position(|entry| !entry.occupied)?;
        self.pool[start..start + reply.len()].copy_from_slice(reply);

        let serial = self.serial;
        self.serial = serial.wrapping_add(1);
        let entry = &mut self.entries[slot];
        entry.key = *key;
        entry.token = token;
        // Within the pool, which `new` holds to what a `u16` addresses.
        entry.start = start as u16;
        entry.len = reply.len() as u16;
        entry.carry(cut);
        entry.tag = tag;
        // A new serial for every reply, so a cursor issued against the
        // one this replaces names nothing.
        entry.serial = serial;
        entry.last_ms = now_ms;
        entry.occupied = true;
        Some(slot)
    }

    /// Pack every retained reply against the start of the pool, and say
    /// where the free space begins.
    fn compact(&mut self) -> usize {
        let mut packed = [false; ENTRIES];
        let mut next = 0;
        // Lowest start first, so each reply moves down over space already
        // vacated and never over one still waiting to move.
        while let Some(index) = (0..ENTRIES)
            .filter(|&index| self.entries[index].occupied && !packed[index])
            .min_by_key(|&index| self.entries[index].start)
        {
            let entry = &mut self.entries[index];
            let start = usize::from(entry.start);
            let len = usize::from(entry.len);
            self.pool.copy_within(start..start + len, next);
            entry.start = next as u16;
            next += len;
            packed[index] = true;
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::trailing;
    use umsh_ulcp::ids::prop;

    const PAYLOAD: usize = 180;
    /// Room for one large read and some writes, but not two large reads.
    const POOL: usize = 400;
    type Engine = DeviceEngine<PAYLOAD, POOL, 2>;

    const ALICE: PublicKey = [0xAA; 32];
    const BOB: PublicKey = [0xBB; 32];
    const CAROL: PublicKey = [0xCC; 32];

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

    /// What came of one exchange.
    #[derive(Debug, PartialEq, Eq)]
    enum Answer {
        /// The engine had the request executed; this is the response.
        Executed(Vec<u8>),
        /// Answered without executing anything.
        Answered(Vec<u8>),
    }

    impl Answer {
        fn payload(&self) -> &[u8] {
            match self {
                Self::Executed(payload) | Self::Answered(payload) => payload,
            }
        }
    }

    /// Run one exchange, executing it—if the engine asks—as a device
    /// whose whole reply is `reply`.
    fn exchange(
        engine: &mut Engine,
        from: &PublicKey,
        token: Token,
        frame: &[u8],
        cursor: Option<&[u8]>,
        reply: &[u8],
        now_ms: u64,
    ) -> Answer {
        let mut payload = [0u8; PAYLOAD];
        let mut envelope = Envelope::new(token, frame);
        if let Some(cursor) = cursor {
            envelope = envelope.with_cursor(cursor);
        }
        let len = envelope.encode(&mut payload).expect("encode");
        let mut out = [0u8; PAYLOAD];
        match engine.begin(from, &payload[..len], now_ms, &mut out) {
            Ingress::Respond { len } => Answer::Answered(out[..len].to_vec()),
            Ingress::Dispatch(_) => {
                let len = engine
                    .complete(reply, &mut out)
                    .expect("complete")
                    .expect("a response");
                Answer::Executed(out[..len].to_vec())
            }
            Ingress::Drop(reason) => panic!("dropped: {reason:?}"),
        }
    }

    /// The peer table read whole: a request, and a reply too large for
    /// one payload whose value counts up from `seed`, so that two
    /// executions can be told apart.
    fn peers_read(len: usize, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut request = [0u8; 8];
        let request_len = get(prop::DEV_PEERS, &mut request);
        let value: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
        let mut reply = vec![0u8; len + 8];
        let reply_len = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &value).unwrap();
        reply.truncate(reply_len);
        (request[..request_len].to_vec(), reply)
    }

    /// A write of the device name and the reply that echoes it: an
    /// exchange that changes something, and so is retained.
    fn rename(name: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut request = [0u8; 64];
        let request_len = frame::prop_set(&mut request, 0, prop::DEV_NAME, name).unwrap();
        let mut reply = [0u8; 64];
        let reply_len = frame::prop_is(&mut reply, 0, prop::DEV_NAME, name).unwrap();
        (request[..request_len].to_vec(), reply[..reply_len].to_vec())
    }

    fn occupied(engine: &Engine) -> usize {
        engine.entries.iter().filter(|entry| entry.occupied).count()
    }

    fn cursor_of(payload: &[u8]) -> Option<Vec<u8>> {
        Envelope::parse(payload).unwrap().cursor.map(<[u8]>::to_vec)
    }

    fn frame_of(payload: &[u8]) -> Vec<u8> {
        Envelope::parse(payload).unwrap().frame.to_vec()
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
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("expected a dispatch");
        };
        assert_eq!(dispatch.frame, frame);
        assert!(!dispatch.resets);
        assert_eq!(dispatch.budget, POOL, "a read may answer at full size");

        let mut reply_buf = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply_buf, 0, prop::CAPS, &[1, 2, 3]).unwrap();
        let len = engine
            .complete(&reply_buf[..reply_len], &mut out)
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
            engine.complete(&[0x80, 0x06], &mut out),
            Err(CompleteError::NotDispatched)
        );
    }

    #[test]
    fn dfu_is_response_tracked_and_failed_transmission_invalidates_cached_success() {
        let mut engine = Engine::new(1);
        let mut frame_buf = [0; 8];
        let n = frame::dfu(&mut frame_buf, 0, Some(umsh_ulcp::DfuMode::Ble)).unwrap();
        let mut payload = [0; PAYLOAD];
        let len = request([1, 2], &frame_buf[..n], &mut payload);
        let mut out = [0; PAYLOAD];
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("DFU must be dispatched");
        };
        assert!(
            !dispatch.resets,
            "a delivery acknowledgment cannot confirm DFU"
        );
        let n = frame::last_status(&mut frame_buf, 0, Status::OK).unwrap();
        let n = engine.complete(&frame_buf[..n], &mut out).unwrap().unwrap();
        assert_eq!(reported_status(&out[..n]), Status::OK);
        engine.fail_retained(&BOB, [1, 2]);
        engine.fail_retained(&ALICE, [2, 3]);
        let Ingress::Respond { len: n } = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("retry must replay, never dispatch again");
        };
        assert_eq!(reported_status(&out[..n]), Status::OK);
        engine.fail_retained(&ALICE, [1, 2]);
        let Ingress::Respond { len: n } = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("canceled DFU must retain a refusal");
        };
        assert_eq!(reported_status(&out[..n]), Status::FAILURE);
    }

    #[test]
    fn a_repeated_token_is_answered_from_the_retained_response() {
        let mut engine = Engine::new(1);
        let (write, echo) = rename(b"Ridgeline");

        let first = exchange(&mut engine, &ALICE, [9, 9], &write, None, &echo, 0);
        assert!(matches!(first, Answer::Executed(_)));

        // The identical request again: answered, not executed.
        let again = exchange(&mut engine, &ALICE, [9, 9], &write, None, &echo, 1_000);
        assert_eq!(again, Answer::Answered(first.payload().to_vec()));

        // A different administrator sending the same token has its own
        // exchange, and gets dispatched.
        let theirs = exchange(&mut engine, &BOB, [9, 9], &write, None, &echo, 2_000);
        assert!(matches!(theirs, Answer::Executed(_)));
    }

    /// Running a read again changes nothing, so nothing is kept for it: a
    /// retransmission is answered afresh, with whatever the device says
    /// now.
    #[test]
    fn a_retransmitted_read_that_fits_is_executed_afresh() {
        let mut engine = Engine::new(1);
        let mut request = [0u8; 8];
        let request_len = get(prop::CAPS, &mut request);
        let read = &request[..request_len];
        let mut before = [0u8; 16];
        let before_len = frame::prop_is(&mut before, 0, prop::CAPS, &[7]).unwrap();
        let mut after = [0u8; 16];
        let after_len = frame::prop_is(&mut after, 0, prop::CAPS, &[8]).unwrap();

        let first = exchange(
            &mut engine,
            &ALICE,
            [9, 9],
            read,
            None,
            &before[..before_len],
            0,
        );
        assert!(matches!(first, Answer::Executed(_)));
        assert_eq!(occupied(&engine), 0, "nothing retained");

        let again = exchange(
            &mut engine,
            &ALICE,
            [9, 9],
            read,
            None,
            &after[..after_len],
            0,
        );
        let Answer::Executed(again) = again else {
            panic!("a read's retransmission runs again");
        };
        assert_eq!(frame_of(&again), &after[..after_len]);
    }

    #[test]
    fn a_new_token_from_the_same_administrator_replaces_the_retained_entry() {
        let mut engine = Engine::new(1);
        let (write, echo) = rename(b"Ridgeline");

        for token in [[1, 1], [2, 2]] {
            exchange(&mut engine, &ALICE, token, &write, None, &echo, 0);
        }

        // Only the most recent exchange is retained, and one
        // administrator never occupies two slots.
        let replayed = exchange(&mut engine, &ALICE, [1, 1], &write, None, &echo, 0);
        assert!(matches!(replayed, Answer::Executed(_)));
        assert_eq!(occupied(&engine), 1);
    }

    /// A token need only differ from the previous exchange's. An exchange
    /// that retains nothing still ends the one before it, or a later
    /// request reusing the older token would be answered with a reply to
    /// something else.
    #[test]
    fn an_exchange_that_retains_nothing_still_ends_the_retained_one() {
        let mut engine = Engine::new(1);
        let (write, echo) = rename(b"Ridgeline");
        let (rewrite, reecho) = rename(b"Saddle Peak");
        let mut request = [0u8; 8];
        let request_len = get(prop::CAPS, &mut request);
        let mut reply = [0u8; 16];
        let reply_len = frame::prop_is(&mut reply, 0, prop::CAPS, &[7]).unwrap();

        exchange(&mut engine, &ALICE, [1, 1], &write, None, &echo, 0);
        let read = &request[..request_len];
        exchange(
            &mut engine,
            &ALICE,
            [2, 2],
            read,
            None,
            &reply[..reply_len],
            0,
        );
        assert_eq!(occupied(&engine), 0);

        let renamed = exchange(&mut engine, &ALICE, [1, 1], &rewrite, None, &reecho, 0);
        assert!(matches!(renamed, Answer::Executed(_)));
    }

    #[test]
    fn the_least_recently_active_administrator_is_evicted() {
        let mut engine = Engine::new(1);
        let (write, echo) = rename(b"Ridgeline");

        // Two slots, three administrators; Alice is the stalest.
        for (key, now) in [(&ALICE, 0u64), (&BOB, 10), (&CAROL, 20)] {
            exchange(&mut engine, key, [1, 1], &write, None, &echo, now);
        }

        // Bob and Carol are still answered from their retained entries.
        let bob = exchange(&mut engine, &BOB, [1, 1], &write, None, &echo, 30);
        assert!(matches!(bob, Answer::Answered(_)));
        // Alice's is gone, so her retransmission is executed again.
        let alice = exchange(&mut engine, &ALICE, [1, 1], &write, None, &echo, 40);
        assert!(matches!(alice, Answer::Executed(_)));
    }

    /// Replies are held at their own length, so a small one costs the
    /// pool only what it is and sits beside a read in progress.
    #[test]
    fn a_read_in_progress_and_a_write_share_the_pool() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let (write, echo) = rename(b"Ridgeline");

        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");
        let written = exchange(&mut engine, &BOB, [1, 0], &write, None, &echo, 10);
        assert_eq!(occupied(&engine), 2);

        let again = exchange(&mut engine, &BOB, [1, 0], &write, None, &echo, 20);
        assert_eq!(again, Answer::Answered(written.payload().to_vec()));
        let rest = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&cursor), &[], 30);
        let mut assembled = frame_of(first.payload());
        assembled.extend_from_slice(trailing(&frame_of(rest.payload())));
        assert_eq!(assembled, reply);
    }

    /// When the octets run out before the entries do, room is made the
    /// same way: the least recently active administrator gives way.
    #[test]
    fn room_in_the_pool_is_made_by_evicting_the_least_recently_active() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let (_, other) = peers_read(250, 0x80);

        let alice = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let alice_cursor = cursor_of(alice.payload()).expect("a cursor");
        let bob = exchange(&mut engine, &BOB, [1, 0], &read, None, &other, 10);
        let bob_cursor = cursor_of(bob.payload()).expect("a cursor");
        assert_eq!(occupied(&engine), 1, "two of these do not fit");

        let refused = exchange(
            &mut engine,
            &ALICE,
            [2, 0],
            &read,
            Some(&alice_cursor),
            &[],
            20,
        );
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
        let rest = exchange(&mut engine, &BOB, [2, 0], &read, Some(&bob_cursor), &[], 30);
        let mut assembled = frame_of(bob.payload());
        assembled.extend_from_slice(trailing(&frame_of(rest.payload())));
        assert_eq!(assembled, other);
    }

    /// Releasing a reply that lies before another leaves a hole, which
    /// the next retention closes by moving the other down. The read that
    /// moved still continues from exactly the octets it began with.
    #[test]
    fn a_read_in_progress_survives_the_pool_compacting_beneath_it() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let (long, long_echo) = rename(b"A name long enough to leave a hole");
        let (short, short_echo) = rename(b"Gap");

        exchange(&mut engine, &ALICE, [1, 0], &long, None, &long_echo, 0);
        let first = exchange(&mut engine, &BOB, [1, 0], &read, None, &reply, 10);
        let cursor = cursor_of(first.payload()).expect("a cursor");
        let renamed = exchange(&mut engine, &ALICE, [2, 0], &short, None, &short_echo, 20);
        assert!(matches!(renamed, Answer::Executed(_)));

        let rest = exchange(&mut engine, &BOB, [2, 0], &read, Some(&cursor), &[], 30);
        let mut assembled = frame_of(first.payload());
        assembled.extend_from_slice(trailing(&frame_of(rest.payload())));
        assert_eq!(assembled, reply);
        let again = exchange(&mut engine, &ALICE, [2, 0], &short, None, &short_echo, 40);
        assert_eq!(again, Answer::Answered(renamed.payload().to_vec()));
    }

    #[test]
    fn a_frame_that_does_not_parse_is_answered_parse_error() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];

        for frame in [&[][..], &[0x00, 0x02][..], &[0x80][..]] {
            let mut payload = [0u8; PAYLOAD];
            let len = request([3, 3], frame, &mut payload);
            let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, &mut out)
            else {
                panic!("expected an answer for {frame:?}");
            };
            assert_eq!(reported_status(&out[..len]), Status::PARSE_ERROR);
            // The same request always draws the same answer, so there is
            // nothing to retain.
            assert_eq!(occupied(&engine), 0);
        }
    }

    #[test]
    fn a_payload_too_short_for_a_token_is_dropped() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        for payload in [&[][..], &[0x01][..]] {
            assert_eq!(
                engine.begin(&ALICE, payload, 0, &mut out),
                Ingress::Drop(DropReason::NoToken)
            );
        }
    }

    #[test]
    fn a_malformed_option_block_is_answered_because_the_token_precedes_it() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];
        // A length nibble promising more than the payload holds.
        let Ingress::Respond { len } = engine.begin(&ALICE, &[4, 5, 0x1F, 0x00], 0, &mut out)
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
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
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
        let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("expected an answer");
        };
        assert_eq!(reported_status(&out[..len]), Status::UNIMPLEMENTED);
        assert_eq!(Envelope::parse(&out[..len]).unwrap().token, [5, 6]);
    }

    /// The whole point of retaining the reply: the continuation is cut
    /// from what the first exchange produced, and the device it would
    /// otherwise have run against—here, one whose answer has since
    /// changed—is never asked.
    #[test]
    fn a_read_that_does_not_fit_is_continued_without_executing_again() {
        let mut engine = Engine::new(0xBEEF);
        let (read, reply) = peers_read(250, 0);
        let (_, changed) = peers_read(250, 0x80);

        let Answer::Executed(first) = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0)
        else {
            panic!("the first exchange executes the read");
        };
        assert!(first.len() <= PAYLOAD);
        let envelope = Envelope::parse(&first).unwrap();
        let cursor = envelope.cursor.expect("a cursor").to_vec();
        let mut assembled = envelope.frame.to_vec();
        assert_eq!(
            envelope.remaining,
            Some((reply.len() - assembled.len()) as u32)
        );

        let Answer::Answered(rest) = exchange(
            &mut engine,
            &ALICE,
            [2, 0],
            &read,
            Some(&cursor),
            &changed,
            10,
        ) else {
            panic!("a continuation executes nothing");
        };
        assert_eq!(cursor_of(&rest), None, "the last fragment ends the read");
        assembled.extend_from_slice(trailing(&frame_of(&rest)));
        assert_eq!(assembled, reply, "one execution, reassembled whole");
    }

    #[test]
    fn a_cursor_presented_again_yields_the_same_fragment() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        let once = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&cursor), &[], 0);
        let again = exchange(&mut engine, &ALICE, [3, 0], &read, Some(&cursor), &[], 0);
        let (Answer::Answered(once), Answer::Answered(again)) = (once, again) else {
            panic!("neither continuation executes anything");
        };
        assert_eq!(frame_of(&once), frame_of(&again));
        assert_eq!(Envelope::parse(&again).unwrap().token, [3, 0]);
    }

    /// Mid-read, a retransmission is still only a retransmission: the
    /// fragment it repeats, cursor and all, is the one its token carried.
    #[test]
    fn a_retransmission_mid_read_repeats_its_fragment_verbatim() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);

        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let first_again = exchange(&mut engine, &ALICE, [1, 0], &read, None, &[], 0);
        assert_eq!(first_again, Answer::Answered(first.payload().to_vec()));

        let cursor = cursor_of(first.payload()).expect("a cursor");
        let rest = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&cursor), &[], 0);
        let rest_again = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&cursor), &[], 0);
        assert_eq!(rest, rest_again);
    }

    /// The largest read the engine retains goes out in fragments that
    /// each fit a payload, cursor and all.
    #[test]
    fn the_largest_retainable_read_goes_out_within_the_payload() {
        let mut engine = Engine::new(1);
        let mut request = [0u8; 8];
        let request_len = get(prop::DEV_PEERS, &mut request);
        let read = &request[..request_len];
        let mut reply = [0u8; POOL];
        let head = frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &[]).unwrap();
        let reply_len =
            frame::prop_is(&mut reply, 0, prop::DEV_PEERS, &vec![0x5A; POOL - head]).unwrap();
        assert_eq!(reply_len, POOL);

        let mut payload = exchange(&mut engine, &ALICE, [1, 0], read, None, &reply, 0)
            .payload()
            .to_vec();
        let mut assembled = frame_of(&payload);
        let mut token = 1u8;
        while let Some(cursor) = cursor_of(&payload) {
            assert!(payload.len() <= PAYLOAD);
            token += 1;
            payload = exchange(&mut engine, &ALICE, [token, 0], read, Some(&cursor), &[], 0)
                .payload()
                .to_vec();
            assembled.extend_from_slice(trailing(&frame_of(&payload)));
        }
        assert!(payload.len() <= PAYLOAD);
        assert_eq!(assembled, reply);
    }

    #[test]
    fn a_multi_get_continues_the_same_way_a_get_does() {
        let mut request = [0u8; 16];
        let request_len =
            frame::prop_multi_get(&mut request, 0, &[prop::DEV_PEERS, prop::DEV_ADMINS]).unwrap();
        let read = &request[..request_len];
        let mut reply = [0u8; POOL];
        let reply_len = {
            let mut writer = frame::prop_are(&mut reply, 0).unwrap();
            writer.write_entry(prop::DEV_PEERS, &[0x11; 160]).unwrap();
            writer.write_entry(prop::DEV_ADMINS, &[0x22; 64]).unwrap();
            writer.finish()
        };
        let reply = &reply[..reply_len];

        let mut engine = Engine::new(1);
        let first = exchange(&mut engine, &ALICE, [1, 0], read, None, reply, 0);
        assert!(matches!(first, Answer::Executed(_)));
        let cursor = cursor_of(first.payload()).expect("a cursor");
        let rest = exchange(&mut engine, &ALICE, [2, 0], read, Some(&cursor), &[], 0);
        assert!(matches!(rest, Answer::Answered(_)));

        let mut assembled = frame_of(first.payload());
        assembled.extend_from_slice(trailing(&frame_of(rest.payload())));
        assert_eq!(assembled, reply);
    }

    /// The reply is retained as its administrator's most recent exchange,
    /// so beginning any other exchange takes the reply—and with it what
    /// the cursor pointed into—away.
    #[test]
    fn a_cursor_is_refused_once_its_administrator_moves_on() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        let mut other = [0u8; 8];
        let other_len = get(prop::CAPS, &mut other);
        let mut small = [0u8; 16];
        let small_len = frame::prop_is(&mut small, 0, prop::CAPS, &[7]).unwrap();
        exchange(
            &mut engine,
            &ALICE,
            [2, 0],
            &other[..other_len],
            None,
            &small[..small_len],
            0,
        );

        let refused = exchange(&mut engine, &ALICE, [3, 0], &read, Some(&cursor), &reply, 0);
        assert!(matches!(refused, Answer::Answered(_)));
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    /// Beginning the same read afresh executes it afresh, and a cursor
    /// from the earlier execution must not splice its position into the
    /// new reply.
    #[test]
    fn a_cursor_from_an_earlier_execution_of_the_same_read_is_refused() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let (_, changed) = peers_read(250, 0x80);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let stale = cursor_of(first.payload()).expect("a cursor");

        let fresh = exchange(&mut engine, &ALICE, [2, 0], &read, None, &changed, 0);
        assert!(matches!(fresh, Answer::Executed(_)));
        let refused = exchange(&mut engine, &ALICE, [3, 0], &read, Some(&stale), &[], 0);
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_is_refused_from_any_administrator_but_its_own() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        // Bob has read the same thing, and still cannot use Alice's place
        // in it.
        exchange(&mut engine, &BOB, [1, 0], &read, None, &reply, 0);
        let refused = exchange(&mut engine, &BOB, [2, 0], &read, Some(&cursor), &[], 0);
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_does_not_outlive_its_administrators_eviction() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        // Two slots, and two administrators more recent than Alice whose
        // writes have to be retained.
        let (write, echo) = rename(b"Ridgeline");
        for (key, now) in [(&BOB, 10), (&CAROL, 20)] {
            exchange(&mut engine, key, [1, 0], &write, None, &echo, now);
        }

        let refused = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&cursor), &[], 30);
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_is_refused_for_a_read_other_than_the_one_it_began() {
        let mut engine = Engine::new(1);
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        // Same command, different property.
        let mut other = [0u8; 8];
        let other_len = get(prop::PROTOCOL_VERSION, &mut other);
        let refused = exchange(
            &mut engine,
            &ALICE,
            [2, 0],
            &other[..other_len],
            Some(&cursor),
            &[],
            0,
        );
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_cursor_from_before_a_reboot_is_refused_even_where_the_serials_line_up() {
        let (read, reply) = peers_read(250, 0);
        let mut engine = Engine::new(0x1111);
        let first = exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        // The rebooted engine's first reply takes the serial the first
        // engine's did, for the same read by the same administrator; only
        // the per-boot nonce tells them apart.
        let mut rebooted = Engine::new(0x2222);
        exchange(&mut rebooted, &ALICE, [1, 0], &read, None, &reply, 0);
        let refused = exchange(&mut rebooted, &ALICE, [2, 0], &read, Some(&cursor), &[], 0);
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_malformed_cursor_is_refused_rather_than_read_from_the_beginning() {
        let (read, reply) = peers_read(250, 0);
        let mut issued = Engine::new(1);
        let first = exchange(&mut issued, &ALICE, [1, 0], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");
        // The right width, naming positions the reply's 250 trailing
        // octets do not have.
        let at = |offset: u16| {
            let mut forged = cursor.clone();
            forged[4..6].copy_from_slice(&offset.to_be_bytes());
            forged
        };

        for forged in [
            vec![0u8],
            vec![0u8; 5],
            vec![0u8; 7],
            vec![0xFF; 6],
            at(250),
            at(u16::MAX),
        ] {
            let mut engine = Engine::new(1);
            exchange(&mut engine, &ALICE, [1, 0], &read, None, &reply, 0);
            let refused = exchange(&mut engine, &ALICE, [2, 0], &read, Some(&forged), &[], 0);
            assert_eq!(
                reported_status(refused.payload()),
                Status::CURSOR_INVALID,
                "{forged:?}"
            );
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
                .with_cursor(&[0; CURSOR_LEN])
                .encode(&mut payload)
                .unwrap();
            let Ingress::Respond { len } = engine.begin(&ALICE, &payload[..len], 0, &mut out)
            else {
                panic!("expected a refusal");
            };
            assert_eq!(reported_status(&out[..len]), Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn a_reset_is_answered_by_nothing_and_forgets_what_was_retained() {
        let mut engine = Engine::new(1);
        let mut out = [0u8; PAYLOAD];

        // Something to retain first: a read still in progress.
        let (read, reply) = peers_read(250, 0);
        let first = exchange(&mut engine, &ALICE, [1, 1], &read, None, &reply, 0);
        let cursor = cursor_of(first.payload()).expect("a cursor");

        let mut frame_buf = [0u8; 8];
        for len in [
            frame::reset(&mut frame_buf, 0).unwrap(),
            frame::restore(&mut frame_buf, 0).unwrap(),
            frame::factory_reset(&mut frame_buf, 0).unwrap(),
            frame::reboot(&mut frame_buf, 0).unwrap(),
        ] {
            let mut payload = [0u8; PAYLOAD];
            let len = request([2, 2], &frame_buf[..len], &mut payload);
            let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, &mut out)
            else {
                panic!("expected a dispatch");
            };
            assert!(dispatch.resets);
            assert_eq!(engine.complete(&[], &mut out), Ok(None));
        }

        // The read is no longer retained: its retransmission is executed
        // again, and its cursor has nothing left to continue.
        let again = exchange(&mut engine, &BOB, [1, 1], &read, None, &reply, 0);
        assert!(matches!(again, Answer::Executed(_)));
        let refused = exchange(&mut engine, &ALICE, [3, 3], &read, Some(&cursor), &[], 0);
        assert_eq!(reported_status(refused.payload()), Status::CURSOR_INVALID);
    }

    #[test]
    fn a_reply_that_overruns_the_budget_is_refused_rather_than_truncated() {
        let mut engine = Engine::new(1);
        let oversized = [0u8; POOL + 1];
        let mut out = [0u8; PAYLOAD];

        // A write is never continued, so its reply gets one payload.
        let mut frame_buf = [0u8; 8];
        let frame_len = frame::prop_set(&mut frame_buf, 0, prop::DEV_NAME, b"x").unwrap();
        let mut payload = [0u8; PAYLOAD];
        let len = request([1, 2], &frame_buf[..frame_len], &mut payload);
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("expected a dispatch");
        };
        assert_eq!(dispatch.budget, PAYLOAD - OVERHEAD_MAX);
        assert_eq!(
            engine.complete(&oversized[..dispatch.budget + 1], &mut out),
            Err(CompleteError::TooLarge)
        );

        // A read gets all the engine retains, and not an octet more.
        let frame_len = get(prop::DEV_PEERS, &mut frame_buf);
        let len = request([1, 3], &frame_buf[..frame_len], &mut payload);
        let Ingress::Dispatch(dispatch) = engine.begin(&ALICE, &payload[..len], 0, &mut out) else {
            panic!("expected a dispatch");
        };
        assert_eq!(dispatch.budget, POOL);
        assert_eq!(
            engine.complete(&oversized, &mut out),
            Err(CompleteError::TooLarge)
        );
    }
}
