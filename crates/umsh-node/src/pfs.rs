#[cfg(feature = "software-crypto")]
use alloc::vec::Vec;
#[cfg(feature = "software-crypto")]
use core::cell::RefCell;

use umsh_core::ChannelKey;
#[cfg(feature = "software-crypto")]
use umsh_core::PayloadType;
#[cfg(feature = "software-crypto")]
use umsh_core::PublicKey;
#[cfg(feature = "software-crypto")]
use umsh_crypto::{NodeIdentity, software::SoftwareIdentity};
#[cfg(feature = "software-crypto")]
use umsh_mac::{LocalIdentityId, PeerHolder, SendOptions, SendReceipt};
#[cfg(feature = "software-crypto")]
use zeroize::Zeroize;

#[cfg(feature = "software-crypto")]
use crate::{
    MacCommand,
    mac::MacBackend,
    mac_command,
    node::{LocalNodeState, NodeError},
};

#[cfg(feature = "software-crypto")]
const DEFAULT_MAX_PFS_SESSIONS: usize = 4;

/// How long a sent PFS request waits for a response before it is abandoned and
/// reported as a [`PfsFailure::Timeout`](crate::PfsFailure::Timeout). A
/// `Requested` session holds no MAC resources (the ephemeral identity is only
/// registered once a response arrives), so timing one out just drops the entry.
#[cfg(feature = "software-crypto")]
const PFS_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// How often one peer may open a session here: a further request inside
/// this window is refused, unless it repeats the one already answered.
#[cfg(feature = "software-crypto")]
const PFS_REQUEST_INTERVAL_MS: u64 = 60_000;

/// How many peers' latest requests are remembered for
/// [`PFS_REQUEST_INTERVAL_MS`].
#[cfg(feature = "software-crypto")]
const MAX_RECENT_REQUESTERS: usize = 16;

/// How many acknowledged sends in a row under a session may go undelivered
/// before the session is ended.
///
/// Each undelivered send has already spent the MAC's whole retry budget, so
/// one is several transmissions unanswered. One or two in a row are what a
/// fade or a busy channel produces; a third, with nothing heard under the
/// session in between, is far likelier a peer that no longer holds it. Ending
/// it costs little: traffic goes on under the long-term keys, and a new
/// request opens a fresh session.
#[cfg(feature = "software-crypto")]
pub(crate) const PFS_MAX_UNDELIVERED_SENDS: u8 = 3;

/// The longest PFS session this node agrees to, in minutes.
///
/// A responder answers a longer request with this, and either side reads a
/// duration of 0—which no node may send—as this rather than as a session
/// that never ends. Forward secrecy holds only once the ephemeral keys are
/// erased, so every session has an end.
#[cfg(feature = "software-crypto")]
pub(crate) const MAX_PFS_SESSION_MINUTES: u16 = 24 * 60;

/// The lifetime this node holds a session to, given the duration a request
/// or response named.
#[cfg(feature = "software-crypto")]
pub(crate) fn session_minutes(duration_minutes: u16) -> u16 {
    match duration_minutes {
        0 => MAX_PFS_SESSION_MINUTES,
        minutes => minutes.min(MAX_PFS_SESSION_MINUTES),
    }
}

#[cfg(feature = "software-crypto")]
/// Lifecycle state for a PFS session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PfsState {
    /// Session requested but not fully activated.
    Requested,
    /// This node answered the peer's request. The session's identity is
    /// registered, so it hears the peer under the session, but nothing is
    /// sent under it until the peer's first frame there shows the response
    /// arrived.
    Answered,
    /// Session active and mapped to an ephemeral MAC identity.
    Active,
}

#[cfg(feature = "software-crypto")]
impl PfsState {
    /// Whether the session's identity is registered with the MAC: it has
    /// both halves, and frames under it can be heard.
    pub(crate) fn has_keys(self) -> bool {
        self != Self::Requested
    }
}

/// Whether frame counter `counter` comes after `earlier`, as counters
/// compare (modulo 2^32). An unknown counter comes after nothing.
#[cfg(feature = "software-crypto")]
fn counter_after(counter: Option<u32>, earlier: Option<u32>) -> bool {
    match (counter, earlier) {
        (Some(counter), Some(earlier)) => {
            (1..=i32::MAX as u32).contains(&counter.wrapping_sub(earlier))
        }
        _ => false,
    }
}

#[cfg(feature = "software-crypto")]
/// One tracked PFS session.
pub(crate) struct PfsSession {
    /// Peer long-term identity.
    pub peer_long_term: PublicKey,
    /// Local ephemeral MAC identity.
    pub local_ephemeral_id: LocalIdentityId,
    /// Local ephemeral public key: the address the peer sends to while the
    /// session is active.
    pub local_ephemeral: PublicKey,
    /// Peer ephemeral public key.
    pub peer_ephemeral: PublicKey,
    /// Absolute expiry time in milliseconds.
    ///
    /// While the session is still [`Requested`](PfsState::Requested), this is a
    /// provisional value computed at request time and replaced when the session
    /// becomes active.
    pub expires_ms: u64,
    /// Session lifecycle state.
    pub state: PfsState,
    /// Deadline by which a [`Requested`](PfsState::Requested) session must
    /// receive its response, after which it is abandoned. Unused once `Active`.
    pub request_deadline_ms: u64,
    /// The lifetime this node accepted, when it answered the peer's request:
    /// what a repeat of that request is answered with again.
    answered_minutes: Option<u16>,
    /// The frame counter of the peer's half of the handshake: the request
    /// this node answered, or the response it accepted. An End under the
    /// long-term keys ends the session only if it comes after this.
    handshake_counter: Option<u32>,
    /// Acknowledged sends under the session that went undelivered since
    /// the last one delivered or the last frame heard under it.
    undelivered: u8,
    pending_local: Option<SoftwareIdentity>,
}

#[cfg(feature = "software-crypto")]
impl core::fmt::Debug for PfsSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PfsSession")
            .field("peer_long_term", &self.peer_long_term)
            .field("local_ephemeral_id", &self.local_ephemeral_id)
            .field("local_ephemeral", &self.local_ephemeral)
            .field("peer_ephemeral", &self.peer_ephemeral)
            .field("expires_ms", &self.expires_ms)
            .field("state", &self.state)
            .field("request_deadline_ms", &self.request_deadline_ms)
            .field("answered_minutes", &self.answered_minutes)
            .field("handshake_counter", &self.handshake_counter)
            .field("undelivered", &self.undelivered)
            .finish()
    }
}

#[cfg(feature = "software-crypto")]
/// Fixed-capacity manager for endpoint-level PFS sessions.
///
/// The table itself is synchronous. The operations that need the MAC are the
/// free functions below, over the cell that holds it: a MAC await can last a
/// whole transmission, and the pump needs [`LocalNodeState`] to dispatch what
/// that transmission produced, so they borrow the cell only between awaits.
/// A session is in the table from before its first send to the end of its
/// life, so whatever runs during those awaits sees it, and an operation
/// finds at its next step whether it was ended or replaced in the meantime.
pub(crate) struct PfsSessionManager {
    sessions: Vec<PfsSession>,
    max_sessions: usize,
    /// Requests and responses refused because the ephemeral key they named
    /// is already an address this node knows.
    refused_ephemeral_keys: u32,
    /// Requests refused because the requester is not a contact.
    refused_requesters: u32,
    /// Requests refused for coming too soon after the same peer's last.
    rate_limited_requests: u32,
    /// Requests refused because they crossed this node's own request to
    /// the same peer, and its own won.
    crossed_requests: u32,
    /// Responses this node no longer wanted, answered with an End.
    unwanted_responses: u32,
    /// Ends ignored because the session held with their sender began after
    /// them, or still waits for its response.
    stale_ends: u32,
    /// Sessions ended because sends under them went undelivered.
    undelivered_sessions: u32,
    /// The peers whose requests this node answered within
    /// [`PFS_REQUEST_INTERVAL_MS`], and when, oldest first.
    recent_requests: Vec<(PublicKey, u64)>,
}

#[cfg(feature = "software-crypto")]
impl Default for PfsSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "software-crypto")]
impl PfsSessionManager {
    /// Create an empty session manager.
    pub(crate) fn new() -> Self {
        Self {
            sessions: Vec::new(),
            max_sessions: DEFAULT_MAX_PFS_SESSIONS,
            refused_ephemeral_keys: 0,
            refused_requesters: 0,
            rate_limited_requests: 0,
            crossed_requests: 0,
            unwanted_responses: 0,
            stale_ends: 0,
            undelivered_sessions: 0,
            recent_requests: Vec::new(),
        }
    }

    /// Borrow the tracked sessions.
    pub(crate) fn sessions(&self) -> &[PfsSession] {
        &self.sessions
    }

    /// How many requests and responses were refused for naming an ephemeral
    /// key this node already knows.
    pub(crate) fn refused_ephemeral_keys(&self) -> u32 {
        self.refused_ephemeral_keys
    }

    fn note_refused_ephemeral_key(&mut self) {
        self.refused_ephemeral_keys = self.refused_ephemeral_keys.saturating_add(1);
    }

    /// How many requests were refused for coming from a peer that is not a
    /// contact.
    pub(crate) fn refused_requesters(&self) -> u32 {
        self.refused_requesters
    }

    fn note_unwanted_response(&mut self) {
        self.unwanted_responses = self.unwanted_responses.saturating_add(1);
    }

    fn note_refused_requester(&mut self) {
        self.refused_requesters = self.refused_requesters.saturating_add(1);
    }

    /// How many requests were refused for coming too soon after the same
    /// peer's last.
    pub(crate) fn rate_limited_requests(&self) -> u32 {
        self.rate_limited_requests
    }

    /// How many requests were refused because they crossed this node's own
    /// request to the same peer, and its own won.
    pub(crate) fn crossed_requests(&self) -> u32 {
        self.crossed_requests
    }

    /// How many responses this node no longer wanted and answered with an
    /// End.
    pub(crate) fn unwanted_responses(&self) -> u32 {
        self.unwanted_responses
    }

    /// How many Ends were ignored because the session held with their
    /// sender began after them, or still waits for its response.
    pub(crate) fn stale_ends(&self) -> u32 {
        self.stale_ends
    }

    /// How many sessions were ended because sends under them went
    /// undelivered.
    pub(crate) fn undelivered_sessions(&self) -> u32 {
        self.undelivered_sessions
    }

    /// Whether a request from `peer` naming `peer_ephemeral` crosses this
    /// node's own request to them and loses, counting it when it does.
    ///
    /// When two peers ask each other at once, the request under the lower
    /// ephemeral key, compared as a big-endian unsigned integer, stands:
    /// its sender ignores the other, and the other's sender answers it.
    fn crossed_and_lost(&mut self, peer: &PublicKey, peer_ephemeral: &PublicKey) -> bool {
        let lost = self.sessions.iter().any(|session| {
            session.peer_long_term == *peer
                && session.state == PfsState::Requested
                && session.answered_minutes.is_none()
                && session.local_ephemeral.0 < peer_ephemeral.0
        });
        if lost {
            self.crossed_requests = self.crossed_requests.saturating_add(1);
        }
        lost
    }

    /// Note a frame heard from `from` under the local identity `identity`.
    /// A frame from the peer's half of a session there shows the peer holds
    /// it. Returns the peer when that confirms a session this node
    /// answered, which is then established.
    pub(crate) fn note_session_frame(
        &mut self,
        identity: LocalIdentityId,
        from: &PublicKey,
    ) -> Option<PublicKey> {
        let session = self.sessions.iter_mut().find(|session| {
            session.state.has_keys()
                && session.local_ephemeral_id == identity
                && session.peer_ephemeral == *from
        })?;
        session.undelivered = 0;
        if session.state != PfsState::Answered {
            return None;
        }
        session.state = PfsState::Active;
        Some(session.peer_long_term)
    }

    /// Note that a send under the local identity `identity` was delivered.
    pub(crate) fn note_session_delivered(&mut self, identity: LocalIdentityId) {
        if let Some(session) = self.active_under(identity) {
            session.undelivered = 0;
        }
    }

    /// Note that a send under the local identity `identity` went
    /// undelivered. Returns the session's local key once
    /// [`PFS_MAX_UNDELIVERED_SENDS`] have gone so in a row.
    pub(crate) fn note_session_undelivered(
        &mut self,
        identity: LocalIdentityId,
    ) -> Option<PublicKey> {
        let session = self.active_under(identity)?;
        session.undelivered = session.undelivered.saturating_add(1);
        (session.undelivered == PFS_MAX_UNDELIVERED_SENDS).then_some(session.local_ephemeral)
    }

    fn active_under(&mut self, identity: LocalIdentityId) -> Option<&mut PfsSession> {
        self.sessions.iter_mut().find(|session| {
            session.state == PfsState::Active && session.local_ephemeral_id == identity
        })
    }

    /// Remove the session under `local_ephemeral` if its sends are still
    /// going undelivered.
    fn take_undelivered(&mut self, local_ephemeral: &PublicKey) -> Option<PfsSession> {
        let index = self.sessions.iter().position(|session| {
            session.local_ephemeral == *local_ephemeral
                && session.undelivered >= PFS_MAX_UNDELIVERED_SENDS
        })?;
        self.undelivered_sessions = self.undelivered_sessions.saturating_add(1);
        Some(self.sessions.swap_remove(index))
    }

    /// The local key of the session an End from `from` with frame counter
    /// `counter` ends, counting it when it is ignored as stale.
    ///
    /// An End under a session's own keys ends that session. One under the
    /// long-term keys ends the session held with its sender, but only if
    /// it comes after the sender's half of that session's handshake: an
    /// older End, delayed or replayed, was about a session before this one.
    /// A request still waiting for its response is never ended by one.
    fn end_target(&mut self, from: &PublicKey, counter: Option<u32>) -> Option<PublicKey> {
        if let Some(session) = self
            .sessions
            .iter()
            .find(|session| session.state.has_keys() && session.peer_ephemeral == *from)
        {
            return Some(session.local_ephemeral);
        }
        let session = self
            .sessions
            .iter()
            .find(|session| session.peer_long_term == *from)?;
        if counter_after(counter, session.handshake_counter) {
            return Some(session.local_ephemeral);
        }
        self.stale_ends = self.stale_ends.saturating_add(1);
        None
    }

    /// Whether `peer` may open a session at `now_ms`, counting it when it
    /// may not: one opened in the last [`PFS_REQUEST_INTERVAL_MS`] stops it.
    fn admit_request(&mut self, peer: &PublicKey, now_ms: u64) -> bool {
        self.recent_requests
            .retain(|(_, at)| now_ms.saturating_sub(*at) < PFS_REQUEST_INTERVAL_MS);
        if self
            .recent_requests
            .iter()
            .any(|(requester, _)| requester == peer)
        {
            self.rate_limited_requests = self.rate_limited_requests.saturating_add(1);
            return false;
        }
        true
    }

    /// Start `peer`'s window: this node answered its request at `now_ms`.
    fn note_answered(&mut self, peer: &PublicKey, now_ms: u64) {
        if self.recent_requests.len() >= MAX_RECENT_REQUESTERS {
            self.recent_requests.remove(0);
        }
        self.recent_requests.push((*peer, now_ms));
    }

    /// The response this node sent to `peer`'s request naming
    /// `peer_ephemeral`, if that request opened a session that still stands:
    /// its local key and accepted lifetime.
    fn answer_to(
        &self,
        peer: &PublicKey,
        peer_ephemeral: &PublicKey,
        now_ms: u64,
    ) -> Option<(PublicKey, u16)> {
        let session = self.sessions.iter().find(|session| {
            session.peer_long_term == *peer
                && session.state.has_keys()
                && session.peer_ephemeral == *peer_ephemeral
                && session.expires_ms > now_ms
        })?;
        Some((session.local_ephemeral, session.answered_minutes?))
    }

    /// Whether this node's own request to `peer` is waiting for its
    /// response.
    fn is_pending(&self, peer: &PublicKey) -> bool {
        self.sessions.iter().any(|session| {
            session.peer_long_term == *peer
                && session.pending_local.is_some()
                && session.answered_minutes.is_none()
        })
    }

    /// Whether any session is held with `peer`, in whatever state.
    fn holds(&self, peer: &PublicKey) -> bool {
        self.sessions
            .iter()
            .any(|session| session.peer_long_term == *peer)
    }

    /// Return the active ephemeral route for `peer`, if any.
    pub(crate) fn active_route(
        &self,
        peer: &PublicKey,
        now_ms: u64,
    ) -> Option<(LocalIdentityId, PublicKey)> {
        self.sessions
            .iter()
            .find(|session| {
                session.peer_long_term == *peer
                    && session.state == PfsState::Active
                    && session.expires_ms > now_ms
            })
            .map(|session| (session.local_ephemeral_id, session.peer_ephemeral))
    }

    /// Put `session` in the table in place of any held with the same peer,
    /// which comes back to be released.
    fn install<M: MacBackend>(
        &mut self,
        session: PfsSession,
    ) -> Result<Option<PfsSession>, NodeError<M>> {
        if let Some(existing) = self
            .sessions
            .iter_mut()
            .find(|existing| existing.peer_long_term == session.peer_long_term)
        {
            return Ok(Some(core::mem::replace(existing, session)));
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(NodeError::PfsSessionTableFull);
        }
        self.sessions.push(session);
        Ok(None)
    }

    /// Remove the session held with `peer`.
    fn take_peer(&mut self, peer: &PublicKey) -> Option<PfsSession> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.peer_long_term == *peer)?;
        Some(self.sessions.swap_remove(index))
    }

    /// Remove the session under the local key `local_ephemeral`.
    fn take_local(&mut self, local_ephemeral: &PublicKey) -> Option<PfsSession> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.local_ephemeral == *local_ephemeral)?;
        Some(self.sessions.swap_remove(index))
    }

    /// Remove one session past its end.
    fn take_expired(&mut self, now_ms: u64) -> Option<PfsSession> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.expires_ms <= now_ms)?;
        Some(self.sessions.swap_remove(index))
    }

    /// Take the local identity of the session held with `peer`, if it is
    /// waiting to be activated.
    fn take_pending(&mut self, peer: &PublicKey) -> Option<SoftwareIdentity> {
        self.sessions
            .iter_mut()
            .find(|session| session.peer_long_term == *peer)?
            .pending_local
            .take()
    }

    /// Give the session under `active`'s local key both its halves: active
    /// if this node asked for it, or waiting for the peer to confirm it if
    /// this node answered. Fails if it is no longer in the table.
    fn activate(
        &mut self,
        peer_ephemeral: PublicKey,
        active: &ActivatedPfsIdentity,
        handshake_counter: Option<u32>,
    ) -> bool {
        let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.local_ephemeral == active.local_public)
        else {
            return false;
        };
        session.local_ephemeral_id = active.local_ephemeral_id;
        session.peer_ephemeral = peer_ephemeral;
        session.expires_ms = active.expires_ms;
        session.handshake_counter = handshake_counter;
        session.state = match session.answered_minutes {
            Some(_) => PfsState::Answered,
            None => PfsState::Active,
        };
        true
    }

    /// Drop any `Requested` sessions whose response deadline has passed and
    /// return their peers. These hold no MAC resources (no ephemeral identity
    /// is registered until a response arrives), so no `mac` cleanup is needed.
    pub(crate) fn expire_requests(&mut self, now_ms: u64) -> Vec<PublicKey> {
        let mut timed_out = Vec::new();
        let mut index = 0usize;
        while index < self.sessions.len() {
            let session = &self.sessions[index];
            if session.state == PfsState::Requested && session.request_deadline_ms <= now_ms {
                timed_out.push(self.sessions.swap_remove(index).peer_long_term);
            } else {
                index += 1;
            }
        }
        timed_out
    }
}

/// How an inbound PFS command arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Carriage {
    /// The channel a blind unicast arrived on: an answer follows it back.
    pub(crate) channel: Option<ChannelKey>,
    /// The frame counter it was sent under.
    pub(crate) counter: Option<u32>,
}

/// Initiate a new PFS session request.
#[cfg(feature = "software-crypto")]
pub(crate) async fn request_session<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer: &PublicKey,
    duration_minutes: u16,
    options: &SendOptions,
) -> Result<Option<SendReceipt>, NodeError<M>> {
    let duration_minutes = session_minutes(duration_minutes);
    let local_public = begin_session(state, mac, peer, duration_minutes, false, None).await?;
    let sent = send_pfs_command(
        mac,
        parent,
        peer,
        None,
        &MacCommand::PfsSessionRequest {
            ephemeral_key: local_public,
            duration_minutes,
        },
        options,
    )
    .await;
    if sent.is_err() {
        abandon(state, mac, &local_public).await;
    }
    sent
}

/// Accept an inbound PFS request, and report whether it was answered with a
/// session that stood when that was done. The session waits for the peer's
/// first frame under it before anything is sent there.
///
/// Only a contact may open a session, and once a minute at most. A request
/// that repeats the one that opened the standing session, under the same
/// ephemeral key, gets the same response again and opens nothing. No
/// response goes out for a request refused as coming from a stranger or too
/// soon, for one that crossed this node's own request and lost, for one
/// naming an ephemeral key this node already knows, or when the session was
/// ended while it was being set up.
#[cfg(feature = "software-crypto")]
#[allow(
    clippy::too_many_arguments,
    reason = "the parts of one inbound request"
)]
pub(crate) async fn accept_request<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer_long_term: PublicKey,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
    carriage: Carriage,
    options: &SendOptions,
) -> Result<bool, NodeError<M>> {
    // Refused before anything is set up, so a session already held with
    // this peer survives a request that could not replace it.
    if !mac.is_application_peer(&peer_long_term).await {
        state.borrow_mut().pfs.note_refused_requester();
        return Ok(false);
    }
    // This node's own request stands, and the peer answers it.
    if state
        .borrow_mut()
        .pfs
        .crossed_and_lost(&peer_long_term, &peer_ephemeral)
    {
        return Ok(false);
    }
    let now_ms = mac.now_ms().await;
    let answer = state
        .borrow()
        .pfs
        .answer_to(&peer_long_term, &peer_ephemeral, now_ms);
    if let Some((local_public, duration_minutes)) = answer {
        // The response was lost, or the peer asked again before it arrived.
        send_pfs_command(
            mac,
            parent,
            &peer_long_term,
            carriage.channel,
            &MacCommand::PfsSessionResponse {
                ephemeral_key: local_public,
                duration_minutes,
            },
            options,
        )
        .await?;
        return Ok(false);
    }
    if !state
        .borrow_mut()
        .pfs
        .admit_request(&peer_long_term, now_ms)
    {
        return Ok(false);
    }
    if !admit_peer_ephemeral(state, mac, parent, &peer_long_term, &peer_ephemeral).await {
        return Ok(false);
    }
    // The accepted lifetime is what the response carries, so both sides hold
    // the session to the same one.
    let duration_minutes = session_minutes(duration_minutes);
    begin_session(
        state,
        mac,
        &peer_long_term,
        duration_minutes,
        true,
        carriage.counter,
    )
    .await?;
    let Some(local_public) = establish(
        state,
        mac,
        parent,
        &peer_long_term,
        peer_ephemeral,
        duration_minutes,
        carriage.counter,
    )
    .await?
    else {
        return Ok(false);
    };
    let sent = send_pfs_command(
        mac,
        parent,
        &peer_long_term,
        carriage.channel,
        &MacCommand::PfsSessionResponse {
            ephemeral_key: local_public,
            duration_minutes,
        },
        options,
    )
    .await;
    if let Err(error) = sent {
        abandon(state, mac, &local_public).await;
        return Err(error);
    }
    state
        .borrow_mut()
        .pfs
        .note_answered(&peer_long_term, now_ms);
    Ok(true)
}

/// Accept an inbound PFS response for an existing request, and report whether
/// the session stood when that was done.
///
/// A response no request is waiting for—one that arrived after the request
/// was ended or timed out, or after the node rebooted—is answered with an
/// End when no session is held with the peer, so that the peer drops the
/// half it holds. With a session held, it is a repeat of the response that
/// opened it, or older than that, and is dropped. So is one naming an
/// ephemeral key this node already knows, and the request then waits out
/// its deadline.
#[cfg(feature = "software-crypto")]
#[allow(
    clippy::too_many_arguments,
    reason = "the parts of one inbound response"
)]
pub(crate) async fn accept_response<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer_long_term: PublicKey,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
    carriage: Carriage,
    options: &SendOptions,
) -> Result<bool, NodeError<M>> {
    if !state.borrow().pfs.is_pending(&peer_long_term) {
        let unwanted = !state.borrow().pfs.holds(&peer_long_term);
        if unwanted {
            state.borrow_mut().pfs.note_unwanted_response();
            // Best effort: the peer's half also ends with its lifetime.
            let _ = send_pfs_command(
                mac,
                parent,
                &peer_long_term,
                carriage.channel,
                &MacCommand::EndPfsSession,
                options,
            )
            .await;
        }
        return Ok(false);
    }
    if !admit_peer_ephemeral(state, mac, parent, &peer_long_term, &peer_ephemeral).await {
        return Ok(false);
    }
    let established = establish(
        state,
        mac,
        parent,
        &peer_long_term,
        peer_ephemeral,
        session_minutes(duration_minutes),
        carriage.counter,
    )
    .await?;
    Ok(established.is_some())
}

/// Take an inbound End from `from`, and return the peer whose session it
/// ended, if any. Which session that is, if any, is
/// [`PfsSessionManager::end_target`]'s to judge.
#[cfg(feature = "software-crypto")]
pub(crate) async fn accept_end<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    from: &PublicKey,
    carriage: Carriage,
) -> Option<PublicKey> {
    let session = {
        let mut state = state.borrow_mut();
        let target = state.pfs.end_target(from, carriage.counter)?;
        state.pfs.take_local(&target)?
    };
    let peer = session.peer_long_term;
    release(mac, session).await;
    Some(peer)
}

/// End one session and optionally notify the peer.
#[cfg(feature = "software-crypto")]
pub(crate) async fn end_session<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer: &PublicKey,
    notify_peer: bool,
    options: &SendOptions,
) -> Result<bool, NodeError<M>> {
    let Some(session) = state.borrow_mut().pfs.take_peer(peer) else {
        return Err(NodeError::PfsSessionMissing);
    };
    release(mac, session).await;
    if notify_peer {
        send_pfs_command(mac, parent, peer, None, &MacCommand::EndPfsSession, options).await?;
    }
    Ok(true)
}

/// End the session under `local_ephemeral`, if sends under it are still
/// going undelivered, and tell the peer. Returns the peer.
#[cfg(feature = "software-crypto")]
pub(crate) async fn end_undelivered<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    local_ephemeral: &PublicKey,
    options: &SendOptions,
) -> Option<PublicKey> {
    let session = state.borrow_mut().pfs.take_undelivered(local_ephemeral)?;
    let peer = session.peer_long_term;
    release(mac, session).await;
    // Best effort: a peer that still holds its half hears it under the
    // long-term keys, if the trouble was the session's alone.
    let _ = send_pfs_command(
        mac,
        parent,
        &peer,
        None,
        &MacCommand::EndPfsSession,
        options,
    )
    .await;
    Some(peer)
}

/// Expire any sessions whose deadlines have passed.
#[cfg(feature = "software-crypto")]
pub(crate) async fn expire_sessions<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    now_ms: u64,
) -> Result<Vec<PublicKey>, NodeError<M>> {
    let mut expired = Vec::new();
    loop {
        let Some(session) = state.borrow_mut().pfs.take_expired(now_ms) else {
            return Ok(expired);
        };
        expired.push(session.peer_long_term);
        release(mac, session).await;
    }
}

/// Put a [`Requested`](PfsState::Requested) session with `peer` in the table
/// under a fresh key, and return that key. A session already held with them
/// is released first, so that its slot in the MAC is free for this one's.
/// `answering` says this node is answering the peer's request with
/// `duration_minutes`, sent under frame counter `handshake_counter`.
#[cfg(feature = "software-crypto")]
async fn begin_session<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    peer: &PublicKey,
    duration_minutes: u16,
    answering: bool,
    handshake_counter: Option<u32>,
) -> Result<PublicKey, NodeError<M>> {
    let mut secret = [0u8; 32];
    mac.fill_random(&mut secret).await;
    let local_ephemeral = SoftwareIdentity::from_secret_bytes(&secret);
    secret.zeroize();
    let local_public = *local_ephemeral.public_key();
    let now_ms = mac.now_ms().await;
    let displaced = state.borrow_mut().pfs.install(PfsSession {
        peer_long_term: *peer,
        local_ephemeral_id: LocalIdentityId(u8::MAX),
        local_ephemeral: local_public,
        peer_ephemeral: PublicKey([0u8; 32]),
        expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
        state: PfsState::Requested,
        request_deadline_ms: now_ms.saturating_add(PFS_REQUEST_TIMEOUT_MS),
        answered_minutes: answering.then_some(duration_minutes),
        handshake_counter,
        undelivered: 0,
        pending_local: Some(local_ephemeral),
    })?;
    if let Some(displaced) = displaced {
        release(mac, displaced).await;
    }
    Ok(local_public)
}

/// Activate the session waiting with `peer`, and return its local key, or
/// `None` if none is waiting or it left the table while its identity was
/// being registered. `handshake_counter` is the frame counter of the peer's
/// half of the handshake.
#[cfg(feature = "software-crypto")]
async fn establish<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer: &PublicKey,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
    handshake_counter: Option<u32>,
) -> Result<Option<PublicKey>, NodeError<M>> {
    let Some(local_ephemeral) = state.borrow_mut().pfs.take_pending(peer) else {
        return Ok(None);
    };
    let local_public = *local_ephemeral.public_key();
    let activated = activate_identity(
        mac,
        parent,
        local_ephemeral,
        peer_ephemeral,
        duration_minutes,
    )
    .await;
    let active = match activated {
        Ok(active) => active,
        Err(error) => {
            abandon(state, mac, &local_public).await;
            return Err(error);
        }
    };
    if state
        .borrow_mut()
        .pfs
        .activate(peer_ephemeral, &active, handshake_counter)
    {
        return Ok(Some(local_public));
    }
    let _ = mac.remove_ephemeral(active.local_ephemeral_id).await;
    let _ = mac.release_peer(&peer_ephemeral, PeerHolder::Session).await;
    Ok(None)
}

/// Whether `key` may stand as `peer`'s half of a new session, counting it
/// when it may not.
///
/// The session holds the key's peer slot for its life, the address its
/// traffic is credited to `peer` under, and gives it back when it ends. So
/// it must be no address this node already answers to or sends to: not one
/// of its own keys, not a registered peer's, and not another session's.
#[cfg(feature = "software-crypto")]
async fn admit_peer_ephemeral<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer: &PublicKey,
    key: &PublicKey,
) -> bool {
    let in_table = state.borrow().pfs.sessions().iter().any(|session| {
        session.local_ephemeral == *key
            || (session.state.has_keys() && session.peer_ephemeral == *key)
    });
    let mut known = *key == *peer || in_table;
    if !known {
        known = mac.identity_public_key(parent).await == Some(*key)
            || mac.is_local_identity_key(key).await;
    }
    if !known {
        mac.for_each_peer(&mut |registered| known |= registered == *key)
            .await;
    }
    if known {
        state.borrow_mut().pfs.note_refused_ephemeral_key();
    }
    !known
}

/// Drop the session under `local_ephemeral`, if it is still in the table,
/// when setting it up has failed.
#[cfg(feature = "software-crypto")]
async fn abandon<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    local_ephemeral: &PublicKey,
) {
    let session = state.borrow_mut().pfs.take_local(local_ephemeral);
    if let Some(session) = session {
        release(mac, session).await;
    }
}

/// Give back what a session removed from the table holds in the MAC: its
/// local identity and its hold on the peer slot under the peer's ephemeral
/// key. A contact the application added under that key since keeps the slot.
#[cfg(feature = "software-crypto")]
async fn release<M: MacBackend>(mac: &M, session: PfsSession) {
    if session.state.has_keys() {
        let _ = mac.remove_ephemeral(session.local_ephemeral_id).await;
        let _ = mac
            .release_peer(&session.peer_ephemeral, PeerHolder::Session)
            .await;
    }
}

#[cfg(feature = "software-crypto")]
struct ActivatedPfsIdentity {
    local_ephemeral_id: LocalIdentityId,
    local_public: PublicKey,
    expires_ms: u64,
}

#[cfg(feature = "software-crypto")]
async fn activate_identity<M: MacBackend>(
    mac: &M,
    parent: LocalIdentityId,
    local_ephemeral: SoftwareIdentity,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
) -> Result<ActivatedPfsIdentity, NodeError<M>> {
    let _peer_id = mac.hold_peer(peer_ephemeral, PeerHolder::Session).await?;
    let local_public = *local_ephemeral.public_key();
    let local_ephemeral_id = match mac.register_ephemeral(parent, local_ephemeral).await {
        Ok(id) => id,
        Err(error) => {
            let _ = mac.release_peer(&peer_ephemeral, PeerHolder::Session).await;
            return Err(error.into());
        }
    };
    let now_ms = mac.now_ms().await;
    Ok(ActivatedPfsIdentity {
        local_ephemeral_id,
        local_public,
        expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
    })
}

#[cfg(feature = "software-crypto")]
/// Send one PFS control command.
///
/// `channel` carries the response-carriage rule: it is `Some` when this
/// command answers a request that arrived as a blind unicast, and the answer
/// stays on that channel rather than naming both parties in the clear.
async fn send_pfs_command<M: MacBackend>(
    mac: &M,
    from: LocalIdentityId,
    peer: &PublicKey,
    channel: Option<ChannelKey>,
    command: &MacCommand<'_>,
    options: &SendOptions,
) -> Result<Option<SendReceipt>, NodeError<M>> {
    let mut body = [0u8; 80];
    let len = mac_command::encode(command, &mut body)?;
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(PayloadType::MacCommand as u8);
    payload.extend_from_slice(&body[..len]);
    match channel {
        Some(channel) => mac
            .send_blind_unicast(from, peer, &channel, &payload, options)
            .await
            .map_err(Into::into),
        None => mac
            .send_unicast(from, peer, &payload, options)
            .await
            .map_err(Into::into),
    }
}
