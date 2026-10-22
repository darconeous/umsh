//! Contact exchange: payload type 10, "Meet" (app-meet.md).
//!
//! Two people standing together each open Add peer. Their devices announce
//! themselves under a throwaway session key, showing only a model and a color
//! derived from that key. One asks, the other answers, both read a six-digit
//! code off their screens, and each device sends its own key and identity
//! when its holder presses Same.
//!
//! [`Meet`] is the sans-IO state machine. The caller owns the session key's
//! MAC identity, feeds received frames and the clock in, and carries out the
//! [`MeetAction`]s it queues. It never touches a radio, a clock, or a random
//! source of its own: every draw comes from the seed passed to
//! [`Meet::start`], expanded by HMAC.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use umsh_core::PayloadType;
use umsh_core::PublicKey;
use umsh_core::options::OptionDecoder;
use umsh_crypto::Sha256Provider;
use umsh_crypto::software::SoftwareSha256;
use zeroize::Zeroize;

use crate::{IdentitySignature, NodeIdentityPayload};

mod meeting;
pub use meeting::{Exchange, MeetCommand, Meeting, Nearby, NearbyId};

/// The only version this implementation speaks.
pub const VERSION: u8 = 1;

/// Length of the commitment a Request carries.
pub const COMMITMENT_LEN: usize = 32;
/// Length of the nonces Accept and Reveal carry.
pub const NONCE_LEN: usize = 16;
/// Length of an Identity's signature, when it carries one.
pub const SIGNATURE_LEN: usize = 64;

/// Codes run 000000–999999.
pub const CODE_MODULUS: u32 = 1_000_000;
/// Two same-model devices whose hues are this close look alike on Nearby.
pub const CLOSE_HUE_STEPS: u8 = 24;

/// Request→Accept.
pub const REQUEST_TIMEOUT_MS: u64 = 60_000;
/// Accept→Reveal.
pub const REVEAL_TIMEOUT_MS: u64 = 10_000;
/// Code shown, nobody has pressed anything.
pub const COMPARE_TIMEOUT_MS: u64 = 120_000;
/// Own Identity sent→theirs.
pub const IDENTITY_TIMEOUT_MS: u64 = 120_000;
/// The shortest periodic Hello interval.
pub const MIN_HELLO_INTERVAL_MS: u64 = 5_000;
/// A row ages out after this many Hello intervals of silence.
pub const ROW_LIFETIME_INTERVALS: u64 = 3;
/// The answering Hello goes out this long after first hearing a new key.
pub const REPLY_HELLO_DELAY_MS: core::ops::RangeInclusive<u64> = 500..=2_000;
/// Most devices listed at once.
pub const MAX_ROWS: usize = 16;
/// Every Meet frame, and every ack for one, goes out at this power in dBm,
/// or the least the radio can transmit if that is more.
pub const TX_POWER_DBM: i8 = -9;

const COMMIT_LABEL: &[u8] = b"UMSH meet commit";
const CODE_LABEL: &[u8] = b"UMSH meet code";
const COLOR_LABEL: &[u8] = b"UMSH meet color";
const DRAW_LABEL: &[u8] = b"UMSH meet draw";

/// Message kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MeetKind {
    Hello = 0,
    Request = 1,
    Accept = 2,
    Reveal = 3,
    Identity = 4,
    End = 5,
}

impl MeetKind {
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Hello,
            1 => Self::Request,
            2 => Self::Accept,
            3 => Self::Reveal,
            4 => Self::Identity,
            5 => Self::End,
            _ => return None,
        })
    }
}

/// Why an exchange ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The asked side declined.
    NotNow,
    /// The asked side is in another exchange.
    Busy,
    /// A holder pressed Different.
    Different,
    /// A holder backed out or closed Add peer.
    Left,
    /// A step took too long.
    TimedOut,
    /// A frame inside the exchange was malformed or did not check out.
    Failed,
    /// A reason this implementation does not know; it still ends the exchange.
    Unknown(u8),
}

impl EndReason {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::NotNow,
            1 => Self::Busy,
            2 => Self::Different,
            3 => Self::Left,
            4 => Self::TimedOut,
            5 => Self::Failed,
            n => Self::Unknown(n),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            Self::NotNow => 0,
            Self::Busy => 1,
            Self::Different => 2,
            Self::Left => 3,
            Self::TimedOut => 4,
            Self::Failed => 5,
            Self::Unknown(n) => n,
        }
    }
}

/// One decoded Meet message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeetMessage<'a> {
    Hello { model: u16 },
    Request { commitment: [u8; COMMITMENT_LEN] },
    Accept { nonce: [u8; NONCE_LEN] },
    Reveal { nonce: [u8; NONCE_LEN] },
    Identity(IdentityBody<'a>),
    End { reason: EndReason },
}

/// An Identity's body: the sender's long-term key and its node identity
/// payload, exactly as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBody<'a> {
    pub key: PublicKey,
    pub payload: &'a [u8],
    pub identity: NodeIdentityPayload,
    /// Whether a signature by `key` covers `payload`. An unsigned payload
    /// is accepted but is not linked to `key`.
    pub signed: bool,
}

/// Why a Meet body did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeetParseError {
    /// Empty body.
    Truncated,
    /// A version this implementation does not speak.
    Version(u8),
    /// A kind this version does not define.
    Kind(u8),
    /// A body of the wrong length for its kind.
    Length,
    /// An Identity whose node identity payload does not parse, whose
    /// terminator is followed by anything but a signature, or whose
    /// signature does not verify.
    Identity,
}

impl<'a> MeetMessage<'a> {
    /// Decode `body`: the payload after its payload-type byte.
    pub fn parse(body: &'a [u8]) -> Result<Self, MeetParseError> {
        let [version, rest @ ..] = body else {
            return Err(MeetParseError::Truncated);
        };
        if *version != VERSION {
            return Err(MeetParseError::Version(*version));
        }
        let [kind, rest @ ..] = rest else {
            return Err(MeetParseError::Truncated);
        };
        let kind = MeetKind::from_byte(*kind).ok_or(MeetParseError::Kind(*kind))?;
        Ok(match kind {
            MeetKind::Hello => {
                let model: [u8; 2] = rest.try_into().map_err(|_| MeetParseError::Length)?;
                Self::Hello {
                    model: u16::from_be_bytes(model),
                }
            }
            MeetKind::Request => Self::Request {
                commitment: rest.try_into().map_err(|_| MeetParseError::Length)?,
            },
            MeetKind::Accept => Self::Accept {
                nonce: rest.try_into().map_err(|_| MeetParseError::Length)?,
            },
            MeetKind::Reveal => Self::Reveal {
                nonce: rest.try_into().map_err(|_| MeetParseError::Length)?,
            },
            MeetKind::Identity => Self::Identity(parse_identity(rest)?),
            MeetKind::End => {
                let [reason] = rest else {
                    return Err(MeetParseError::Length);
                };
                Self::End {
                    reason: EndReason::from_byte(*reason),
                }
            }
        })
    }

    /// Encode as a whole payload, payload-type byte first.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 32);
        out.push(PayloadType::Meet as u8);
        out.push(VERSION);
        match self {
            Self::Hello { model } => {
                out.push(MeetKind::Hello as u8);
                out.extend_from_slice(&model.to_be_bytes());
            }
            Self::Request { commitment } => {
                out.push(MeetKind::Request as u8);
                out.extend_from_slice(commitment);
            }
            Self::Accept { nonce } => {
                out.push(MeetKind::Accept as u8);
                out.extend_from_slice(nonce);
            }
            Self::Reveal { nonce } => {
                out.push(MeetKind::Reveal as u8);
                out.extend_from_slice(nonce);
            }
            Self::Identity(body) => return encode_identity(&body.key, body.payload),
            Self::End { reason } => {
                out.push(MeetKind::End as u8);
                out.push(reason.as_byte());
            }
        }
        out
    }
}

/// Encode an Identity from a long-term key and its node identity payload
/// (signed or not).
pub fn encode_identity(key: &PublicKey, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 32 + payload.len());
    out.extend_from_slice(&[PayloadType::Meet as u8, VERSION, MeetKind::Identity as u8]);
    out.extend_from_slice(&key.0);
    out.extend_from_slice(payload);
    out
}

/// The Identity body runs to the end of the frame: the key, then a node
/// identity payload whose options end either at the end of the frame
/// (unsigned) or at a 0xFF followed by exactly a signature.
fn parse_identity(rest: &[u8]) -> Result<IdentityBody<'_>, MeetParseError> {
    let (key, payload) = rest
        .split_first_chunk::<32>()
        .ok_or(MeetParseError::Length)?;
    let key = PublicKey(*key);
    if payload.len() < 2 || !umsh_crypto::is_valid_ed25519_public_key(&key) {
        return Err(MeetParseError::Identity);
    }
    // `from_bytes` reads a 0xFF with nothing after it as unsigned, and the
    // two encodings must not mean the same thing here, so find where the
    // options end first.
    let options = &payload[2..];
    let mut decoder = OptionDecoder::new(options);
    let marker = loop {
        let at = decoder.position();
        match decoder.next() {
            Some(Ok(_)) => {}
            Some(Err(_)) => return Err(MeetParseError::Identity),
            None => break at < options.len(),
        }
    };
    if marker && decoder.remainder().len() != SIGNATURE_LEN {
        return Err(MeetParseError::Identity);
    }
    let identity =
        NodeIdentityPayload::from_bytes(payload).map_err(|_| MeetParseError::Identity)?;
    let signed = match identity.signature_state(&key, payload) {
        IdentitySignature::Valid => true,
        IdentitySignature::Unsigned => false,
        IdentitySignature::Invalid => return Err(MeetParseError::Identity),
    };
    Ok(IdentityBody {
        key,
        payload,
        identity,
        signed,
    })
}

/// `C_A = H("UMSH meet commit" ‖ S_A ‖ S_B ‖ N_A)`, where A asked.
pub fn commitment(
    asker: &PublicKey,
    asked: &PublicKey,
    asker_nonce: &[u8; NONCE_LEN],
) -> [u8; COMMITMENT_LEN] {
    SoftwareSha256.hash(&[COMMIT_LABEL, &asker.0, &asked.0, asker_nonce])
}

/// The six-digit code both holders compare.
pub fn code(
    asker: &PublicKey,
    asked: &PublicKey,
    asker_nonce: &[u8; NONCE_LEN],
    asked_nonce: &[u8; NONCE_LEN],
) -> u32 {
    let digest = SoftwareSha256.hash(&[CODE_LABEL, &asker.0, &asked.0, asker_nonce, asked_nonce]);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % CODE_MODULUS
}

/// The session color's hue step, one of 256 around the OKLCH circle.
pub fn session_hue(session: &PublicKey) -> u8 {
    SoftwareSha256.hash(&[COLOR_LABEL, &session.0])[0]
}

include!(concat!(env!("OUT_DIR"), "/session_colors.rs"));

/// The session color, as `0xRRGGBB`, that a device shows for `session`.
pub fn session_color(session: &PublicKey) -> u32 {
    SESSION_COLORS[usize::from(session_hue(session))]
}

/// Whether two hue steps are near enough to be mistaken for each other.
pub fn hues_close(a: u8, b: u8) -> bool {
    let d = a.wrapping_sub(b);
    d.min(d.wrapping_neg()) <= CLOSE_HUE_STEPS
}

/// A device announcing itself on Nearby.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearbyRow {
    /// Its session key: the address for every unicast in an exchange.
    pub key: PublicKey,
    pub model: u16,
    pub hue: u8,
    /// Signal of the last Hello heard, when the bearer reports it.
    pub rssi: Option<i16>,
    pub last_heard_ms: u64,
}

/// Where the current attempt stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeetStage {
    /// No session key: before [`Meet::start`] or after [`Meet::close`].
    Closed,
    /// Listed on Nearby, nothing in progress.
    Idle,
    /// We asked `peer`; waiting for an answer.
    Requesting { peer: PublicKey },
    /// `peer` asked us; waiting for our holder.
    Asked { peer: PublicKey },
    /// We agreed; waiting for `peer` to reveal.
    Accepted { peer: PublicKey },
    /// Both hold the code. `sent` once our holder pressed Same.
    Comparing {
        peer: PublicKey,
        code: u32,
        sent: bool,
    },
    /// The attempt ended without an exchange. The session key is spent.
    Ended(EndReason),
    /// Both identities crossed. The session key is spent.
    Exchanged,
}

/// The other device's identity once both holders pressed Same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchanged {
    pub key: PublicKey,
    /// The node identity payload as received, signature and all.
    pub payload: Vec<u8>,
    pub identity: NodeIdentityPayload,
    /// A valid signature by `key` covers `payload`. Without one the name
    /// and the rest are not linked to `key`.
    pub signed: bool,
}

/// Work for the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeetAction {
    /// Send `frame` from the session identity: to `to`, ack-requested and
    /// not flooded, or as a broadcast with the full source when `to` is
    /// `None`.
    Send {
        to: Option<PublicKey>,
        frame: Vec<u8>,
    },
    /// This session's color is too close to another device of the same
    /// model: draw a new session key and [`start`](Meet::start) again.
    Renew,
    /// The rows or the stage changed.
    Changed,
    /// The exchange completed.
    Exchanged(Exchanged),
}

/// Frames dropped with accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeetStats {
    /// Outside an exchange, a frame that did not decode or rode the wrong
    /// packet family.
    pub malformed: u32,
    /// From the exchange's peer, well-formed but not expected now.
    pub out_of_order: u32,
    /// From a session key this one is not exchanging with.
    pub foreign: u32,
    /// An Identity carrying this device's own key.
    pub own_key: u32,
    /// A Hello from a new device while every row was taken.
    pub rows_full: u32,
}

struct Session {
    key: PublicKey,
    seed: [u8; 32],
    draws: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

enum Attempt {
    Idle,
    Requesting {
        peer: PublicKey,
        nonce: [u8; NONCE_LEN],
        since: u64,
    },
    Asked {
        peer: PublicKey,
        commitment: [u8; COMMITMENT_LEN],
        since: u64,
    },
    Accepted {
        peer: PublicKey,
        commitment: [u8; COMMITMENT_LEN],
        nonce: [u8; NONCE_LEN],
        since: u64,
    },
    Comparing {
        peer: PublicKey,
        code: u32,
        sent: bool,
        theirs: Option<Exchanged>,
        since: u64,
    },
    Ended(EndReason),
    Exchanged,
}

impl Attempt {
    fn peer(&self) -> Option<PublicKey> {
        match self {
            Self::Requesting { peer, .. }
            | Self::Asked { peer, .. }
            | Self::Accepted { peer, .. }
            | Self::Comparing { peer, .. } => Some(*peer),
            _ => None,
        }
    }

    fn deadline(&self) -> Option<u64> {
        match self {
            Self::Requesting { since, .. } | Self::Asked { since, .. } => {
                Some(since + REQUEST_TIMEOUT_MS)
            }
            Self::Accepted { since, .. } => Some(since + REVEAL_TIMEOUT_MS),
            Self::Comparing { sent, since, .. } => Some(
                since
                    + if *sent {
                        IDENTITY_TIMEOUT_MS
                    } else {
                        COMPARE_TIMEOUT_MS
                    },
            ),
            _ => None,
        }
    }
}

/// The contact-exchange state machine for one Add peer visit.
///
/// It spans session renewals so Nearby keeps its rows, but each session key
/// carries at most one attempt: once an attempt ends, for any reason, the
/// caller must retire the key and start again with a fresh one.
pub struct Meet {
    own: PublicKey,
    model: u16,
    hello_interval_ms: u64,
    session: Option<Session>,
    attempt: Attempt,
    rows: Vec<NearbyRow>,
    next_hello: u64,
    reply_pending: bool,
    renew_pending: bool,
    actions: VecDeque<MeetAction>,
    stats: MeetStats,
}

impl Meet {
    /// `own` is this device's long-term key and `hello_interval_ms` the
    /// periodic Hello interval for the current preset (raised to at least
    /// [`MIN_HELLO_INTERVAL_MS`]).
    pub fn new(own: PublicKey, model: u16, hello_interval_ms: u64) -> Self {
        Self {
            own,
            model,
            hello_interval_ms: hello_interval_ms.max(MIN_HELLO_INTERVAL_MS),
            session: None,
            attempt: Attempt::Idle,
            rows: Vec::new(),
            next_hello: 0,
            reply_pending: false,
            renew_pending: false,
            actions: VecDeque::new(),
            stats: MeetStats::default(),
        }
    }

    /// Begin a session under a freshly drawn key. `seed` is fresh randomness
    /// that every nonce and jitter of this session is drawn from.
    ///
    /// Its End must leave from the old key, so an attempt still in progress
    /// is [`cancel`](Self::cancel)led, and its actions carried out, first;
    /// one that is not is dropped without a word to its peer.
    pub fn start(&mut self, now_ms: u64, key: PublicKey, seed: [u8; 32]) {
        self.session = Some(Session {
            key,
            seed,
            draws: 0,
        });
        self.attempt = Attempt::Idle;
        self.next_hello = now_ms;
        self.reply_pending = false;
        self.renew_pending = false;
        self.changed();
        self.tick(now_ms);
    }

    /// Leave Add peer: cancel any attempt and give up the session key.
    pub fn close(&mut self, now_ms: u64) {
        self.cancel(now_ms);
        self.session = None;
        self.changed();
    }

    /// The holder backed out of the attempt in progress, if any.
    pub fn cancel(&mut self, _now_ms: u64) {
        if let Some(peer) = self.attempt.peer() {
            self.end_with(peer, EndReason::Left);
        }
    }

    /// Ask the device behind a listed row to exchange.
    pub fn ask(&mut self, now_ms: u64, peer: PublicKey) -> bool {
        if !matches!(self.attempt, Attempt::Idle) || !self.rows.iter().any(|row| row.key == peer) {
            return false;
        }
        let Some(own) = self.session_key() else {
            return false;
        };
        let nonce = self.draw();
        let commitment = commitment(&own, &peer, &nonce);
        self.send(Some(peer), MeetMessage::Request { commitment });
        self.attempt = Attempt::Requesting {
            peer,
            nonce,
            since: now_ms,
        };
        self.changed();
        true
    }

    /// Answer the request shown to our holder.
    pub fn answer(&mut self, now_ms: u64, accept: bool) -> bool {
        let Attempt::Asked {
            peer, commitment, ..
        } = self.attempt
        else {
            return false;
        };
        if accept {
            self.accept(now_ms, peer, commitment);
        } else {
            self.end_with(peer, EndReason::NotNow);
        }
        true
    }

    /// Our holder found the codes the same: send `identity`, our node
    /// identity payload, signed by our long-term key when it can be.
    pub fn same(&mut self, now_ms: u64, identity: &[u8]) -> bool {
        let Attempt::Comparing {
            peer, sent: false, ..
        } = self.attempt
        else {
            return false;
        };
        let frame = encode_identity(&self.own, identity);
        self.actions.push_back(MeetAction::Send {
            to: Some(peer),
            frame,
        });
        if let Attempt::Comparing {
            sent,
            theirs,
            since,
            ..
        } = &mut self.attempt
        {
            *sent = true;
            *since = now_ms;
            if let Some(theirs) = theirs.take() {
                self.complete(theirs);
                return true;
            }
        }
        self.changed();
        true
    }

    /// Our holder found the codes different: end the exchange and drop
    /// whatever arrived.
    pub fn different(&mut self, _now_ms: u64) -> bool {
        let Attempt::Comparing { peer, .. } = self.attempt else {
            return false;
        };
        self.end_with(peer, EndReason::Different);
        true
    }

    /// Feed one received Meet frame. `body` is the payload after its
    /// payload-type byte, `from` the full source key, and `broadcast`
    /// whether it rode a broadcast rather than a unicast.
    pub fn hear(
        &mut self,
        now_ms: u64,
        from: PublicKey,
        broadcast: bool,
        rssi: Option<i16>,
        body: &[u8],
    ) {
        let own_session = self.session_key();
        if own_session == Some(from) {
            return;
        }
        // A unicast from the peer of the attempt in progress is inside the
        // exchange: anything wrong with it ends the exchange. Anything else
        // is dropped with accounting and never answered.
        let inside = !broadcast && self.attempt.peer() == Some(from);
        let message = match MeetMessage::parse(body) {
            Ok(message) if broadcast == matches!(message, MeetMessage::Hello { .. }) => message,
            _ if inside => {
                self.end_with(from, EndReason::Failed);
                return;
            }
            _ => {
                self.stats.malformed += 1;
                return;
            }
        };
        match message {
            MeetMessage::Hello { model } => self.hello(now_ms, from, model, rssi),
            _ if own_session.is_none() => self.stats.foreign += 1,
            MeetMessage::Request { commitment } => self.request(now_ms, from, commitment),
            MeetMessage::Accept { nonce: asked_nonce } => {
                let Attempt::Requesting { peer, nonce, .. } = self.attempt else {
                    return self.unexpected(from);
                };
                if peer != from {
                    return self.unexpected(from);
                }
                let Some(own) = own_session else { return };
                self.send(Some(peer), MeetMessage::Reveal { nonce });
                self.compare(now_ms, peer, code(&own, &peer, &nonce, &asked_nonce));
            }
            MeetMessage::Reveal { nonce: asker_nonce } => {
                let Attempt::Accepted {
                    peer,
                    commitment: expected,
                    nonce,
                    ..
                } = self.attempt
                else {
                    return self.unexpected(from);
                };
                if peer != from {
                    return self.unexpected(from);
                }
                let Some(own) = own_session else { return };
                if commitment(&peer, &own, &asker_nonce) != expected {
                    self.end_with(peer, EndReason::Failed);
                    return;
                }
                self.compare(now_ms, peer, code(&peer, &own, &asker_nonce, &nonce));
            }
            MeetMessage::Identity(body) => {
                let Attempt::Comparing {
                    peer, sent, theirs, ..
                } = &mut self.attempt
                else {
                    return self.unexpected(from);
                };
                if *peer != from || theirs.is_some() {
                    return self.unexpected(from);
                }
                if body.key == self.own {
                    self.stats.own_key += 1;
                    return;
                }
                let received = Exchanged {
                    key: body.key,
                    payload: body.payload.to_vec(),
                    identity: body.identity,
                    signed: body.signed,
                };
                if *sent {
                    self.complete(received);
                } else {
                    // Held until our holder decides; Different discards it.
                    *theirs = Some(received);
                }
            }
            MeetMessage::End { reason } => {
                if self.attempt.peer() != Some(from) {
                    return self.unexpected(from);
                }
                self.attempt = Attempt::Ended(reason);
                self.forget(from);
                self.changed();
            }
        }
    }

    /// Service deadlines: Hellos, timeouts, and aging rows.
    pub fn tick(&mut self, now_ms: u64) {
        let lifetime = self.hello_interval_ms * ROW_LIFETIME_INTERVALS;
        let before = self.rows.len();
        self.rows
            .retain(|row| row.last_heard_ms + lifetime > now_ms);
        if self.rows.len() != before {
            self.changed();
        }

        if let (Some(peer), Some(deadline)) = (self.attempt.peer(), self.attempt.deadline())
            && now_ms >= deadline
        {
            self.end_with(peer, EndReason::TimedOut);
        }

        if self.hello_due(now_ms) {
            self.send(None, MeetMessage::Hello { model: self.model });
            let interval = self.hello_interval_ms;
            let jitter = self.draw_below(interval / 2);
            self.next_hello = now_ms + interval * 3 / 4 + jitter;
            self.reply_pending = false;
        }
    }

    /// When [`tick`](Self::tick) next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        let lifetime = self.hello_interval_ms * ROW_LIFETIME_INTERVALS;
        let hello = self.hello_live().then_some(self.next_hello);
        let rows = self
            .rows
            .iter()
            .map(|row| row.last_heard_ms + lifetime)
            .min();
        [hello, rows, self.attempt.deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    /// The next action to carry out.
    pub fn poll_action(&mut self) -> Option<MeetAction> {
        self.actions.pop_front()
    }

    pub fn stage(&self) -> MeetStage {
        if self.session.is_none() {
            return MeetStage::Closed;
        }
        match &self.attempt {
            Attempt::Idle => MeetStage::Idle,
            Attempt::Requesting { peer, .. } => MeetStage::Requesting { peer: *peer },
            Attempt::Asked { peer, .. } => MeetStage::Asked { peer: *peer },
            Attempt::Accepted { peer, .. } => MeetStage::Accepted { peer: *peer },
            Attempt::Comparing {
                peer, code, sent, ..
            } => MeetStage::Comparing {
                peer: *peer,
                code: *code,
                sent: *sent,
            },
            Attempt::Ended(reason) => MeetStage::Ended(*reason),
            Attempt::Exchanged => MeetStage::Exchanged,
        }
    }

    /// Devices heard on Nearby, oldest first.
    pub fn rows(&self) -> &[NearbyRow] {
        &self.rows
    }

    /// The current session key, whose hue is this device's own color.
    pub fn session_key(&self) -> Option<PublicKey> {
        self.session.as_ref().map(|session| session.key)
    }

    pub fn stats(&self) -> MeetStats {
        self.stats
    }

    fn hello(&mut self, now_ms: u64, from: PublicKey, model: u16, rssi: Option<i16>) {
        let hue = session_hue(&from);
        if let Some(row) = self.rows.iter_mut().find(|row| row.key == from) {
            row.model = model;
            row.rssi = rssi;
            row.last_heard_ms = now_ms;
        } else if self.rows.len() >= MAX_ROWS {
            self.stats.rows_full += 1;
            return;
        } else {
            self.rows.push(NearbyRow {
                key: from,
                model,
                hue,
                rssi,
                last_heard_ms: now_ms,
            });
            // Answer a newcomer soon, so both lists fill without waiting
            // out a whole interval.
            if self.hello_live() && !self.reply_pending {
                let span = REPLY_HELLO_DELAY_MS.end() - REPLY_HELLO_DELAY_MS.start() + 1;
                let at = now_ms + REPLY_HELLO_DELAY_MS.start() + self.draw_below(span);
                self.next_hello = self.next_hello.min(at);
                self.reply_pending = true;
            }
        }
        self.changed();

        // Of two same-model devices with colors alike, the lower session key
        // draws a new one.
        if let Some(own) = self.session_key()
            && matches!(self.attempt, Attempt::Idle)
            && !self.renew_pending
            && model == self.model
            && hues_close(hue, session_hue(&own))
            && own.0 < from.0
        {
            self.renew_pending = true;
            self.actions.push_back(MeetAction::Renew);
        }
    }

    fn request(&mut self, now_ms: u64, from: PublicKey, commitment: [u8; COMMITMENT_LEN]) {
        match self.attempt {
            Attempt::Idle => {
                self.attempt = Attempt::Asked {
                    peer: from,
                    commitment,
                    since: now_ms,
                };
                self.changed();
            }
            // Both asked each other at once. The lower session key's request
            // stands; the higher one drops its own and agrees without
            // asking its holder, who already asked for this.
            Attempt::Requesting { peer, .. } if peer == from => {
                let Some(own) = self.session_key() else {
                    return;
                };
                if own.0 > from.0 {
                    self.accept(now_ms, from, commitment);
                }
            }
            _ if self.attempt.peer() == Some(from) => self.stats.out_of_order += 1,
            _ => self.send(
                Some(from),
                MeetMessage::End {
                    reason: EndReason::Busy,
                },
            ),
        }
    }

    fn accept(&mut self, now_ms: u64, peer: PublicKey, commitment: [u8; COMMITMENT_LEN]) {
        let nonce = self.draw();
        self.send(Some(peer), MeetMessage::Accept { nonce });
        self.attempt = Attempt::Accepted {
            peer,
            commitment,
            nonce,
            since: now_ms,
        };
        self.changed();
    }

    fn compare(&mut self, now_ms: u64, peer: PublicKey, code: u32) {
        self.attempt = Attempt::Comparing {
            peer,
            code,
            sent: false,
            theirs: None,
            since: now_ms,
        };
        self.changed();
    }

    fn complete(&mut self, theirs: Exchanged) {
        if let Some(peer) = self.attempt.peer() {
            self.forget(peer);
        }
        self.attempt = Attempt::Exchanged;
        self.actions.push_back(MeetAction::Exchanged(theirs));
        self.changed();
    }

    /// End the attempt with `peer`, telling it why.
    fn end_with(&mut self, peer: PublicKey, reason: EndReason) {
        self.send(Some(peer), MeetMessage::End { reason });
        self.attempt = Attempt::Ended(reason);
        self.forget(peer);
        self.changed();
    }

    /// Drop the row of a peer whose attempt is over. Its key is spent like
    /// ours, so the row could only lead to a request nobody answers.
    fn forget(&mut self, peer: PublicKey) {
        self.rows.retain(|row| row.key != peer);
    }

    fn unexpected(&mut self, from: PublicKey) {
        if self.attempt.peer() == Some(from) {
            self.stats.out_of_order += 1;
        } else {
            self.stats.foreign += 1;
        }
    }

    fn send(&mut self, to: Option<PublicKey>, message: MeetMessage<'_>) {
        self.actions.push_back(MeetAction::Send {
            to,
            frame: message.encode(),
        });
    }

    fn changed(&mut self) {
        if self.actions.back() != Some(&MeetAction::Changed) {
            self.actions.push_back(MeetAction::Changed);
        }
    }

    /// Hellos go out only while listed and idle: an exchange in progress
    /// stops them.
    fn hello_live(&self) -> bool {
        self.session.is_some() && matches!(self.attempt, Attempt::Idle)
    }

    fn hello_due(&self, now_ms: u64) -> bool {
        self.hello_live() && now_ms >= self.next_hello
    }

    fn draw<const N: usize>(&mut self) -> [u8; N] {
        let session = self
            .session
            .as_mut()
            .expect("draws happen only under a session");
        let counter = session.draws.to_be_bytes();
        session.draws += 1;
        let block = SoftwareSha256.hmac(&session.seed, &[DRAW_LABEL, &counter]);
        let mut out = [0u8; N];
        out.copy_from_slice(&block[..N]);
        out
    }

    /// A draw in `0..bound`, or 0 when `bound` is 0.
    fn draw_below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        u64::from_be_bytes(self.draw()) % bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeCapabilities, NodeRole};

    /// The colors `test-vectors.md` gives for the exchange's session keys.
    #[test]
    fn session_colors_match_the_spec() {
        assert_eq!(SESSION_COLORS[0], 0xEC8DAB);
        assert_eq!(SESSION_COLORS[61], 0xD0A84B);
        assert_eq!(SESSION_COLORS[64], 0xCBAA4B);
        assert_eq!(SESSION_COLORS[119], 0x53C69E);
        assert_eq!(SESSION_COLORS[128], 0x3DC6B1);
        assert_eq!(SESSION_COLORS[192], 0x90AAFA);
    }
    use alloc::string::String;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use umsh_crypto::NodeIdentity;
    use umsh_crypto::software::SoftwareIdentity;

    const PAGER: u16 = 0x0101;
    const INTERVAL: u64 = 10_000;

    fn ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        match pin!(future).poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("software signing never waits"),
        }
    }

    fn identity_payload(signer: &SoftwareIdentity, name: &str, sign: bool) -> Vec<u8> {
        let payload = NodeIdentityPayload {
            role: NodeRole::Chat,
            capabilities: NodeCapabilities::TEXT_MESSAGES,
            name: Some(String::from(name)),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 128];
        if !sign {
            let len = payload.encode(&mut buf).unwrap();
            return buf[..len].to_vec();
        }
        let len = payload.encode_for_signing(&mut buf).unwrap();
        let signature = ready(signer.sign(&buf[..len])).unwrap();
        let mut out = buf[..len].to_vec();
        out.extend_from_slice(&signature);
        out
    }

    struct Device {
        long_term: SoftwareIdentity,
        identity: Vec<u8>,
        meet: Meet,
        sessions: u8,
        tag: u8,
    }

    impl Device {
        fn new(tag: u8, model: u16) -> Self {
            let long_term = SoftwareIdentity::from_secret_bytes(&[tag; 32]);
            let name = if tag == 1 { "Ana" } else { "Ben" };
            let identity = identity_payload(&long_term, name, true);
            let mut device = Self {
                meet: Meet::new(*long_term.public_key(), model, INTERVAL),
                long_term,
                identity,
                sessions: 0,
                tag,
            };
            device.renew(0);
            device
        }

        /// A key never used before, the way the node draws one per attempt.
        fn renew(&mut self, now: u64) -> PublicKey {
            self.sessions += 1;
            let secret = SoftwareSha256.hash(&[b"session", &[self.tag, self.sessions]]);
            let key = *SoftwareIdentity::from_secret_bytes(&secret).public_key();
            self.meet
                .start(now, key, SoftwareSha256.hash(&[b"seed", &secret]));
            key
        }

        fn key(&self) -> PublicKey {
            self.meet.session_key().unwrap()
        }

        fn same(&mut self, now: u64) -> bool {
            self.meet.same(now, &self.identity)
        }

        fn drain(&mut self) -> Vec<MeetAction> {
            core::iter::from_fn(|| self.meet.poll_action()).collect()
        }

        fn sends(&mut self) -> Vec<(Option<PublicKey>, Vec<u8>)> {
            self.drain()
                .into_iter()
                .filter_map(|action| match action {
                    MeetAction::Send { to, frame } => Some((to, frame)),
                    _ => None,
                })
                .collect()
        }
    }

    /// Carry every frame queued on `from` to `to` (broadcasts too).
    fn deliver(now: u64, from: &mut Device, to: &mut Device) -> Vec<MeetAction> {
        let source = from.key();
        let mut other = Vec::new();
        for action in from.drain() {
            match action {
                MeetAction::Send { to: dst, frame } => {
                    if dst.is_none() || dst == to.meet.session_key() {
                        to.meet
                            .hear(now, source, dst.is_none(), Some(-40), &frame[1..]);
                    }
                }
                action => other.push(action),
            }
        }
        other
    }

    fn listed_pair() -> (Device, Device) {
        let mut ana = Device::new(1, PAGER);
        let mut ben = Device::new(2, 0x0102);
        deliver(0, &mut ana, &mut ben);
        deliver(0, &mut ben, &mut ana);
        (ana, ben)
    }

    fn exchange_to_code(ana: &mut Device, ben: &mut Device) -> u32 {
        assert!(ana.meet.ask(1_000, ben.key()));
        deliver(1_000, ana, ben);
        assert!(matches!(ben.meet.stage(), MeetStage::Asked { .. }));
        assert!(ben.meet.answer(2_000, true));
        deliver(2_000, ben, ana);
        deliver(2_000, ana, ben);
        let MeetStage::Comparing { code: a, .. } = ana.meet.stage() else {
            panic!("asker shows no code: {:?}", ana.meet.stage());
        };
        let MeetStage::Comparing { code: b, .. } = ben.meet.stage() else {
            panic!("asked side shows no code: {:?}", ben.meet.stage());
        };
        assert_eq!(a, b);
        a
    }

    fn exchanged(actions: &[MeetAction]) -> Option<&Exchanged> {
        actions.iter().find_map(|action| match action {
            MeetAction::Exchanged(done) => Some(done),
            _ => None,
        })
    }

    fn sent_end(device: &mut Device) -> Option<EndReason> {
        device
            .sends()
            .into_iter()
            .find_map(|(_, frame)| match MeetMessage::parse(&frame[1..]) {
                Ok(MeetMessage::End { reason }) => Some(reason),
                _ => None,
            })
    }

    #[test]
    fn every_kind_round_trips() {
        let signer = SoftwareIdentity::from_secret_bytes(&[9; 32]);
        let payload = identity_payload(&signer, "Ana", true);
        let messages = [
            MeetMessage::Hello { model: 0x1234 },
            MeetMessage::Request {
                commitment: [7; 32],
            },
            MeetMessage::Accept { nonce: [1; 16] },
            MeetMessage::Reveal { nonce: [2; 16] },
            MeetMessage::End {
                reason: EndReason::Busy,
            },
        ];
        for message in messages {
            let frame = message.encode();
            assert_eq!(frame[0], PayloadType::Meet as u8);
            assert_eq!(MeetMessage::parse(&frame[1..]), Ok(message));
        }
        let frame = encode_identity(signer.public_key(), &payload);
        let Ok(MeetMessage::Identity(body)) = MeetMessage::parse(&frame[1..]) else {
            panic!("identity did not parse");
        };
        assert!(body.signed);
        assert_eq!(body.key, *signer.public_key());
        assert_eq!(body.payload, &payload[..]);
        assert_eq!(body.identity.name.as_deref(), Some("Ana"));
    }

    #[test]
    fn lengths_are_exact() {
        for message in [
            MeetMessage::Hello { model: 1 },
            MeetMessage::Request {
                commitment: [0; 32],
            },
            MeetMessage::Accept { nonce: [0; 16] },
            MeetMessage::Reveal { nonce: [0; 16] },
            MeetMessage::End {
                reason: EndReason::Left,
            },
        ] {
            let frame = message.encode();
            let mut long = frame.clone();
            long.push(0);
            assert_eq!(MeetMessage::parse(&long[1..]), Err(MeetParseError::Length));
            assert_eq!(
                MeetMessage::parse(&frame[1..frame.len() - 1]),
                Err(MeetParseError::Length)
            );
        }
        assert_eq!(MeetMessage::parse(&[]), Err(MeetParseError::Truncated));
        assert_eq!(
            MeetMessage::parse(&[2, 0, 0, 1]),
            Err(MeetParseError::Version(2))
        );
        assert_eq!(MeetMessage::parse(&[1, 6]), Err(MeetParseError::Kind(6)));
    }

    #[test]
    fn an_unknown_end_reason_still_decodes() {
        assert_eq!(
            MeetMessage::parse(&[1, 5, 200]),
            Ok(MeetMessage::End {
                reason: EndReason::Unknown(200)
            })
        );
    }

    #[test]
    fn identity_signature_is_optional_but_never_partial() {
        let signer = SoftwareIdentity::from_secret_bytes(&[9; 32]);
        let key = signer.public_key();

        let unsigned = identity_payload(&signer, "Ana", false);
        let frame = encode_identity(key, &unsigned);
        let Ok(MeetMessage::Identity(body)) = MeetMessage::parse(&frame[1..]) else {
            panic!("unsigned identity did not parse");
        };
        assert!(!body.signed);

        // A terminator with nothing after it is not the same as no
        // terminator.
        let mut marker_only = unsigned.clone();
        marker_only.push(0xFF);
        let frame = encode_identity(key, &marker_only);
        assert_eq!(
            MeetMessage::parse(&frame[1..]),
            Err(MeetParseError::Identity)
        );

        let signed = identity_payload(&signer, "Ana", true);
        for cut in [1, 63] {
            let frame = encode_identity(key, &signed[..signed.len() - cut]);
            assert_eq!(
                MeetMessage::parse(&frame[1..]),
                Err(MeetParseError::Identity)
            );
        }
        let mut long = signed.clone();
        long.push(0);
        let frame = encode_identity(key, &long);
        assert_eq!(
            MeetMessage::parse(&frame[1..]),
            Err(MeetParseError::Identity)
        );

        // Signed by someone else.
        let other = SoftwareIdentity::from_secret_bytes(&[8; 32]);
        let frame = encode_identity(other.public_key(), &signed);
        assert_eq!(
            MeetMessage::parse(&frame[1..]),
            Err(MeetParseError::Identity)
        );
    }

    #[test]
    fn derivations_follow_the_spec_inputs() {
        let a = PublicKey([0xA1; 32]);
        let b = PublicKey([0xB2; 32]);
        let n_a = [0x11; 16];
        let n_b = [0x22; 16];
        let mut input = Vec::new();
        input.extend_from_slice(b"UMSH meet commit");
        input.extend_from_slice(&a.0);
        input.extend_from_slice(&b.0);
        input.extend_from_slice(&n_a);
        assert_eq!(commitment(&a, &b, &n_a), SoftwareSha256.hash(&[&input]));
        assert_ne!(commitment(&a, &b, &n_a), commitment(&b, &a, &n_a));
        assert!(code(&a, &b, &n_a, &n_b) < CODE_MODULUS);
        assert_ne!(code(&a, &b, &n_a, &n_b), code(&a, &b, &n_b, &n_a));
        assert!(hues_close(250, 10));
        assert!(hues_close(10, 34));
        assert!(!hues_close(10, 35));
    }

    /// test-vectors.md, Example 9.
    #[test]
    fn spec_vectors() {
        fn hex(text: &str) -> Vec<u8> {
            let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
            digits
                .chunks(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }
        let key = |text| PublicKey(hex(text).try_into().unwrap());
        let s_a =
            key("ED54 A59F B1AC 3A51 2393 5136 2941 B868 E85A 60E3 D7B2 485D 8288 21DC 7A69 C279");
        let s_b =
            key("6C28 FD05 8C18 C88C 6CCE 2AF9 81D2 D11C 851B 123E D5B6 9B78 7677 3ED0 99EA 3F83");
        let n_a: [u8; 16] = core::array::from_fn(|i| i as u8);
        let n_b: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
        let c_a = commitment(&s_a, &s_b, &n_a);
        assert_eq!(
            c_a.to_vec(),
            hex("B0B0 5CA5 750B 0DC9 02D5 E7B8 66DC 81D6 3DDE 8BDD 70E0 1A0F 8B50 BF5F FA66 9E7D")
        );
        assert_eq!(code(&s_a, &s_b, &n_a, &n_b), 76_952);
        assert_eq!(session_hue(&s_a), 61);
        assert_eq!(session_hue(&s_b), 119);
        assert_eq!(
            MeetMessage::Hello { model: 9 }.encode(),
            hex("0A 01 00 00 09")
        );
        let mut request = hex("0A 01 01");
        request.extend_from_slice(&c_a);
        assert_eq!(MeetMessage::Request { commitment: c_a }.encode(), request);
    }

    #[test]
    fn hellos_list_each_other_and_carry_nothing_but_the_model() {
        let mut ana = Device::new(1, PAGER);
        let hello = ana.sends();
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0].0, None);
        assert_eq!(
            MeetMessage::parse(&hello[0].1[1..]),
            Ok(MeetMessage::Hello { model: PAGER })
        );
        let (ana, ben) = listed_pair();
        assert_eq!(ana.meet.rows().len(), 1);
        assert_eq!(ana.meet.rows()[0].key, ben.key());
        assert_eq!(ana.meet.rows()[0].model, 0x0102);
        assert_eq!(ben.meet.rows()[0].hue, session_hue(&ana.key()));
    }

    #[test]
    fn a_new_key_is_answered_within_two_seconds() {
        let mut ana = Device::new(1, PAGER);
        ana.drain();
        let mut ben = Device::new(2, 0x0102);
        deliver(0, &mut ben, &mut ana);
        ana.drain();
        let at = ana.meet.deadline().unwrap();
        assert!((500..=2_000).contains(&at), "{at}");
        ana.meet.tick(at);
        assert_eq!(ana.sends().len(), 1);
        // Then back to the periodic cadence.
        let next = ana.meet.deadline().unwrap();
        assert!((at + INTERVAL * 3 / 4..at + INTERVAL * 5 / 4).contains(&next));
    }

    #[test]
    fn rows_age_out_after_three_intervals() {
        let (mut ana, _) = listed_pair();
        ana.meet.tick(INTERVAL * 3 - 1);
        assert_eq!(ana.meet.rows().len(), 1);
        ana.meet.tick(INTERVAL * 3);
        assert!(ana.meet.rows().is_empty());
    }

    #[test]
    fn contacts_cross_only_after_each_holders_same() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);

        assert!(ben.same(3_000));
        let identity = ben.sends();
        assert_eq!(identity.len(), 1);
        ana.meet
            .hear(3_000, ben.key(), false, None, &identity[0].1[1..]);
        // Ana's holder hasn't decided: nothing is handed over yet.
        assert!(exchanged(&ana.drain()).is_none());

        assert!(ana.same(4_000));
        let done = ana.drain();
        let theirs = exchanged(&done).expect("ana completes on her own Same");
        assert_eq!(theirs.key, *ben.long_term.public_key());
        assert_eq!(theirs.identity.name.as_deref(), Some("Ben"));
        assert!(theirs.signed);
        assert_eq!(ana.meet.stage(), MeetStage::Exchanged);

        let identity: Vec<_> = done
            .into_iter()
            .filter_map(|action| match action {
                MeetAction::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .collect();
        ben.meet
            .hear(4_000, ana.key(), false, None, &identity[0][1..]);
        let done = ben.drain();
        assert_eq!(exchanged(&done).unwrap().key, *ana.long_term.public_key());
    }

    #[test]
    fn nothing_long_term_is_sent_before_same() {
        let (mut ana, mut ben) = listed_pair();
        let ana_key = ana.long_term.public_key().0;
        let mut frames = Vec::new();
        assert!(ana.meet.ask(1_000, ben.key()));
        frames.extend(ana.sends());
        ben.meet
            .hear(1_000, ana.key(), false, None, &frames[0].1[1..]);
        ben.drain();
        ben.meet.answer(2_000, true);
        let accept = ben.sends();
        ana.meet
            .hear(2_000, ben.key(), false, None, &accept[0].1[1..]);
        frames.extend(ana.sends());
        for (_, frame) in &frames {
            assert!(!frame.windows(32).any(|window| window == ana_key));
        }
    }

    #[test]
    fn different_discards_what_arrived() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ben.same(3_000);
        deliver(3_000, &mut ben, &mut ana);
        assert!(ana.meet.different(4_000));
        let actions = ana.drain();
        assert!(exchanged(&actions).is_none());
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::Different));
        let end = actions.iter().find_map(|action| match action {
            MeetAction::Send { frame, .. } => Some(frame.clone()),
            _ => None,
        });
        ben.meet
            .hear(4_000, ana.key(), false, None, &end.unwrap()[1..]);
        assert_eq!(ben.meet.stage(), MeetStage::Ended(EndReason::Different));
    }

    #[test]
    fn declining_ends_it_for_both() {
        let (mut ana, mut ben) = listed_pair();
        ana.meet.ask(1_000, ben.key());
        deliver(1_000, &mut ana, &mut ben);
        ben.meet.answer(2_000, false);
        assert_eq!(ben.meet.stage(), MeetStage::Ended(EndReason::NotNow));
        deliver(2_000, &mut ben, &mut ana);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::NotNow));
    }

    #[test]
    fn a_request_during_an_exchange_is_busy() {
        let (mut ana, mut ben) = listed_pair();
        let mut cam = Device::new(3, PAGER);
        deliver(0, &mut cam, &mut ana);
        ana.drain();
        exchange_to_code(&mut ana, &mut ben);
        // Cam saw Ana's Hello before the exchange started.
        cam.meet.hear(
            0,
            ana.key(),
            true,
            None,
            &MeetMessage::Hello { model: PAGER }.encode()[1..],
        );
        cam.drain();
        assert!(cam.meet.ask(5_000, ana.key()));
        deliver(5_000, &mut cam, &mut ana);
        assert!(matches!(ana.meet.stage(), MeetStage::Comparing { .. }));
        assert_eq!(sent_end(&mut ana), Some(EndReason::Busy));
    }

    #[test]
    fn hellos_stop_during_an_exchange() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.drain();
        ana.meet.tick(INTERVAL * 2);
        assert!(ana.sends().iter().all(|(to, _)| to.is_some()));
    }

    #[test]
    fn leaving_cancels_the_exchange() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.meet.close(3_000);
        assert_eq!(ana.meet.stage(), MeetStage::Closed);
        deliver_raw(3_000, &mut ana, &mut ben);
        assert_eq!(ben.meet.stage(), MeetStage::Ended(EndReason::Left));
    }

    /// Like [`deliver`], for a sender that has already given up its key.
    fn deliver_raw(now: u64, from: &mut Device, to: &mut Device) {
        let source = to.meet.stage().peer().expect("receiver is in an exchange");
        for (dst, frame) in from.sends() {
            assert_eq!(dst, to.meet.session_key());
            to.meet.hear(now, source, false, None, &frame[1..]);
        }
    }

    impl MeetStage {
        fn peer(&self) -> Option<PublicKey> {
            match self {
                Self::Requesting { peer }
                | Self::Asked { peer }
                | Self::Accepted { peer }
                | Self::Comparing { peer, .. } => Some(*peer),
                _ => None,
            }
        }
    }

    #[test]
    fn simultaneous_requests_resolve_either_way() {
        for swap in [false, true] {
            let (mut ana, mut ben) = listed_pair();
            let (first, second) = if swap {
                (&mut ben, &mut ana)
            } else {
                (&mut ana, &mut ben)
            };
            let first_key = first.key();
            let second_key = second.key();
            assert!(first.meet.ask(1_000, second_key));
            assert!(second.meet.ask(1_000, first_key));
            let a = first.sends();
            let b = second.sends();
            first
                .meet
                .hear(1_100, second_key, false, None, &b[0].1[1..]);
            second
                .meet
                .hear(1_100, first_key, false, None, &a[0].1[1..]);
            // Exactly one side agrees, without asking its holder.
            let (higher, lower) = if first_key.0 > second_key.0 {
                (first, second)
            } else {
                (second, first)
            };
            assert!(matches!(higher.meet.stage(), MeetStage::Accepted { .. }));
            assert!(matches!(lower.meet.stage(), MeetStage::Requesting { .. }));
            deliver(1_200, higher, lower);
            deliver(1_200, lower, higher);
            assert!(matches!(lower.meet.stage(), MeetStage::Comparing { .. }));
            assert!(matches!(higher.meet.stage(), MeetStage::Comparing { .. }));
        }
    }

    #[test]
    fn a_bad_reveal_fails_the_exchange() {
        let (mut ana, mut ben) = listed_pair();
        ana.meet.ask(1_000, ben.key());
        deliver(1_000, &mut ana, &mut ben);
        ben.meet.answer(2_000, true);
        ben.drain();
        let reveal = MeetMessage::Reveal { nonce: [0; 16] }.encode();
        ben.meet.hear(2_100, ana.key(), false, None, &reveal[1..]);
        assert_eq!(ben.meet.stage(), MeetStage::Ended(EndReason::Failed));
        assert_eq!(sent_end(&mut ben), Some(EndReason::Failed));
    }

    #[test]
    fn a_bad_signature_inside_the_exchange_fails_it() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.drain();
        let mut payload = identity_payload(&ben.long_term, "Ben", true);
        *payload.last_mut().unwrap() ^= 1;
        let frame = encode_identity(ben.long_term.public_key(), &payload);
        ana.meet.hear(3_000, ben.key(), false, None, &frame[1..]);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::Failed));
        assert_eq!(sent_end(&mut ana), Some(EndReason::Failed));
    }

    #[test]
    fn malformed_frames_are_fatal_inside_and_dropped_outside() {
        let (mut ana, mut ben) = listed_pair();
        let mut hello = MeetMessage::Hello { model: PAGER }.encode();
        hello.push(0);
        ana.meet.hear(500, ben.key(), true, None, &hello[1..]);
        assert_eq!(ana.meet.stats().malformed, 1);
        assert_eq!(ana.meet.stage(), MeetStage::Idle);
        // A newer version outside a session: not listed, never answered.
        ana.meet
            .hear(500, PublicKey([5; 32]), true, None, &[2, 0, 0, 1]);
        assert_eq!(ana.meet.rows().len(), 1);
        assert!(ana.sends().is_empty());

        exchange_to_code(&mut ana, &mut ben);
        ana.drain();
        ana.meet.hear(3_000, ben.key(), false, None, &[2, 5, 0]);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::Failed));
    }

    #[test]
    fn an_early_identity_is_dropped() {
        let (mut ana, mut ben) = listed_pair();
        ana.meet.ask(1_000, ben.key());
        deliver(1_000, &mut ana, &mut ben);
        ben.meet.answer(2_000, true);
        ben.drain();
        let frame = encode_identity(
            ben.long_term.public_key(),
            &identity_payload(&ben.long_term, "Ben", true),
        );
        ana.meet.hear(2_000, ben.key(), false, None, &frame[1..]);
        assert_eq!(ana.meet.stats().out_of_order, 1);
        assert!(matches!(ana.meet.stage(), MeetStage::Requesting { .. }));
    }

    #[test]
    fn an_identity_with_the_receivers_own_key_is_dropped() {
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.same(3_000);
        ana.drain();
        let frame = encode_identity(
            ana.long_term.public_key(),
            &identity_payload(&ana.long_term, "Ana", true),
        );
        ana.meet.hear(3_000, ben.key(), false, None, &frame[1..]);
        assert_eq!(ana.meet.stats().own_key, 1);
        assert!(exchanged(&ana.drain()).is_none());
    }

    #[test]
    fn each_step_times_out() {
        // Request→Accept.
        let (mut ana, ben) = listed_pair();
        ana.meet.ask(1_000, ben.key());
        ana.drain();
        ana.meet.tick(1_000 + REQUEST_TIMEOUT_MS);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::TimedOut));
        assert_eq!(sent_end(&mut ana), Some(EndReason::TimedOut));

        // Accept→Reveal.
        let (mut ana, mut ben2) = listed_pair();
        ana.meet.ask(1_000, ben2.key());
        deliver(1_000, &mut ana, &mut ben2);
        ben2.meet.answer(2_000, true);
        ben2.drain();
        ben2.meet.tick(2_000 + REVEAL_TIMEOUT_MS - 1);
        assert!(matches!(ben2.meet.stage(), MeetStage::Accepted { .. }));
        ben2.meet.tick(2_000 + REVEAL_TIMEOUT_MS);
        assert_eq!(ben2.meet.stage(), MeetStage::Ended(EndReason::TimedOut));

        // Compare idle.
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.meet.tick(2_000 + COMPARE_TIMEOUT_MS - 1);
        assert!(matches!(ana.meet.stage(), MeetStage::Comparing { .. }));
        ana.meet.tick(2_000 + COMPARE_TIMEOUT_MS);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::TimedOut));

        // Own Identity→theirs, counted from the Same.
        let (mut ana, mut ben) = listed_pair();
        exchange_to_code(&mut ana, &mut ben);
        ana.same(10_000);
        ana.meet.tick(10_000 + IDENTITY_TIMEOUT_MS - 1);
        assert!(matches!(
            ana.meet.stage(),
            MeetStage::Comparing { sent: true, .. }
        ));
        ana.meet.tick(10_000 + IDENTITY_TIMEOUT_MS);
        assert_eq!(ana.meet.stage(), MeetStage::Ended(EndReason::TimedOut));
    }

    #[test]
    fn an_ended_session_takes_no_new_request_until_renewed() {
        let (mut ana, mut ben) = listed_pair();
        ana.meet.ask(1_000, ben.key());
        deliver(1_000, &mut ana, &mut ben);
        ben.meet.answer(2_000, false);
        deliver(2_000, &mut ben, &mut ana);
        assert!(!ana.meet.ask(3_000, ben.key()));

        let old = ana.key();
        let fresh = ana.renew(3_000);
        assert_ne!(old, fresh);
        assert_eq!(ana.meet.stage(), MeetStage::Idle);
        // A fresh session announces itself at once.
        assert_eq!(ana.sends().iter().filter(|(to, _)| to.is_none()).count(), 1);
    }

    #[test]
    fn the_lower_of_two_alike_colors_renews() {
        // Search for two same-model sessions whose hues collide.
        let mut keys = Vec::new();
        for n in 0..=255u8 {
            let key = *SoftwareIdentity::from_secret_bytes(&[n; 32]).public_key();
            keys.push(key);
        }
        let (low, high) = keys
            .iter()
            .flat_map(|a| keys.iter().map(move |b| (*a, *b)))
            .find(|(a, b)| a.0 < b.0 && hues_close(session_hue(a), session_hue(b)))
            .expect("some pair collides");
        let mut meet_low = Meet::new(PublicKey([1; 32]), PAGER, INTERVAL);
        meet_low.start(0, low, [1; 32]);
        let mut meet_high = Meet::new(PublicKey([2; 32]), PAGER, INTERVAL);
        meet_high.start(0, high, [2; 32]);
        let hello = MeetMessage::Hello { model: PAGER }.encode();
        meet_low.hear(0, high, true, None, &hello[1..]);
        meet_high.hear(0, low, true, None, &hello[1..]);
        let renews = |meet: &mut Meet| {
            core::iter::from_fn(|| meet.poll_action())
                .filter(|action| *action == MeetAction::Renew)
                .count()
        };
        assert_eq!(renews(&mut meet_low), 1);
        assert_eq!(renews(&mut meet_high), 0);
        // A different model never collides.
        let mut meet_other = Meet::new(PublicKey([3; 32]), 0x0102, INTERVAL);
        meet_other.start(0, low, [3; 32]);
        meet_other.hear(0, high, true, None, &hello[1..]);
        assert_eq!(renews(&mut meet_other), 0);
    }

    #[test]
    fn a_hello_must_ride_a_broadcast() {
        let (mut ana, ben) = listed_pair();
        let hello = MeetMessage::Hello { model: PAGER }.encode();
        ana.meet
            .hear(1_000, PublicKey([7; 32]), false, None, &hello[1..]);
        assert_eq!(ana.meet.stats().malformed, 1);
        let request = MeetMessage::Request {
            commitment: [0; 32],
        }
        .encode();
        ana.meet.hear(1_000, ben.key(), true, None, &request[1..]);
        assert_eq!(ana.meet.stats().malformed, 2);
        assert_eq!(ana.meet.stage(), MeetStage::Idle);
    }
}
