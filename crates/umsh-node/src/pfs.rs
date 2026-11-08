#[cfg(feature = "software-crypto")]
use alloc::vec::Vec;
#[cfg(feature = "software-crypto")]
use core::cell::RefCell;

#[cfg(feature = "software-crypto")]
use umsh_core::ChannelKey;
#[cfg(feature = "software-crypto")]
use umsh_core::PayloadType;
#[cfg(feature = "software-crypto")]
use umsh_core::PublicKey;
#[cfg(feature = "software-crypto")]
use umsh_crypto::{NodeIdentity, software::SoftwareIdentity};
#[cfg(feature = "software-crypto")]
use umsh_mac::{LocalIdentityId, SendOptions, SendReceipt};
#[cfg(feature = "software-crypto")]
use zeroize::Zeroize;

#[cfg(feature = "software-crypto")]
use crate::{
    MacCommand, SendToken,
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
    /// Session active and mapped to an ephemeral MAC identity.
    Active,
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
            .finish()
    }
}

/// The public half of a session with forward secrecy: what a node keeps of
/// it in durable storage so that, after a reboot loses the session's private
/// key, it still recognizes traffic the peer goes on sending under it and can
/// end the session (security.md, Retired Sessions).
///
/// Every field is public. Nothing here can open the session's traffic.
#[cfg(feature = "software-crypto")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PfsSessionRecord {
    /// The peer's long-term address.
    pub peer: PublicKey,
    /// The address this node answered to during the session.
    pub local_ephemeral: PublicKey,
    /// The address the peer sent from during the session.
    pub peer_ephemeral: PublicKey,
    /// When the session ends, in seconds since the Unix epoch, if the
    /// node knew the time when the record was taken.
    pub expires_at: Option<u32>,
    /// What was left of the session, in seconds, when the record was taken.
    /// Counted from any later moment, this is never short of what is left.
    pub lifetime_s: u32,
}

#[cfg(feature = "software-crypto")]
impl PfsSessionRecord {
    /// Length of one record's encoding.
    pub const ENCODED_LEN: usize = 1 + 3 * 32 + 4 + 4;
    const VERSION: u8 = 1;

    /// Encode as a version byte, the three keys, then `expires_at` (0 when
    /// unknown) and `lifetime_s`, big-endian.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = Self::VERSION;
        out[1..33].copy_from_slice(&self.peer.0);
        out[33..65].copy_from_slice(&self.local_ephemeral.0);
        out[65..97].copy_from_slice(&self.peer_ephemeral.0);
        out[97..101].copy_from_slice(&self.expires_at.unwrap_or(0).to_be_bytes());
        out[101..105].copy_from_slice(&self.lifetime_s.to_be_bytes());
        out
    }

    /// Decode one record, or `None` for anything that is not one.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::ENCODED_LEN] = bytes.try_into().ok()?;
        if bytes[0] != Self::VERSION {
            return None;
        }
        let key = |at: usize| {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[at..at + 32]);
            PublicKey(key)
        };
        let word = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Some(Self {
            peer: key(1),
            local_ephemeral: key(33),
            peer_ephemeral: key(65),
            expires_at: Some(word(97)).filter(|at| *at != 0),
            lifetime_s: word(101),
        })
    }

    /// Encode `records` one after another.
    pub fn encode_all(records: &[Self]) -> Vec<u8> {
        let mut out = Vec::with_capacity(records.len() * Self::ENCODED_LEN);
        for record in records {
            out.extend_from_slice(&record.encode());
        }
        out
    }

    /// Decode what [`Self::encode_all`] wrote, skipping any record that
    /// does not decode.
    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        bytes
            .chunks_exact(Self::ENCODED_LEN)
            .filter_map(Self::decode)
            .collect()
    }

    /// What is left of the session at `now_unix`, in milliseconds. Without
    /// both times, the session is held to the whole of `lifetime_s`; and it
    /// is never held past that, whatever the clock says.
    pub fn remaining_ms(&self, now_unix: Option<u32>) -> u64 {
        let lifetime_s = match (self.expires_at, now_unix) {
            (Some(expires_at), Some(now)) => expires_at.saturating_sub(now).min(self.lifetime_s),
            _ => self.lifetime_s,
        };
        u64::from(lifetime_s) * 1000
    }

    /// The record of a session ending at `expires_ms`, or `None` once it
    /// has ended.
    fn of(
        peer: PublicKey,
        local_ephemeral: PublicKey,
        peer_ephemeral: PublicKey,
        expires_ms: u64,
        now_ms: u64,
        now_unix: Option<u32>,
    ) -> Option<Self> {
        let remaining_ms = expires_ms.checked_sub(now_ms).filter(|ms| *ms > 0)?;
        let lifetime_s = u32::try_from(remaining_ms.div_ceil(1000)).unwrap_or(u32::MAX);
        Some(Self {
            peer,
            local_ephemeral,
            peer_ephemeral,
            expires_at: now_unix.map(|now| now.saturating_add(lifetime_s)),
            lifetime_s,
        })
    }
}

/// How far ending a retired session with its peer has got.
#[cfg(feature = "software-crypto")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Closing {
    /// Nothing sent, or what was sent went unanswered.
    Idle,
    /// The End PFS Session is being queued.
    Sending,
    /// Sent, waiting for the peer's acknowledgment.
    AwaitingAck(SendToken),
    /// Acknowledged: the session has ended at both ends.
    Closed,
}

/// A session this node can no longer use, kept until it would have ended so
/// that the peer's traffic under it is recognized; see [`PfsSessionRecord`].
#[cfg(feature = "software-crypto")]
#[derive(Debug)]
pub(crate) struct RetiredPfsSession {
    peer_long_term: PublicKey,
    local_ephemeral: PublicKey,
    peer_ephemeral: PublicKey,
    expires_ms: u64,
    closing: Closing,
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
    /// Sessions lost to a reboot, held to the same capacity as live ones.
    retired: Vec<RetiredPfsSession>,
    max_sessions: usize,
    /// Set whenever what [`Self::records`] would return changes, until
    /// [`Self::take_records_changed`] reports it.
    records_changed: bool,
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
            retired: Vec::new(),
            max_sessions: DEFAULT_MAX_PFS_SESSIONS,
            records_changed: false,
        }
    }

    /// The record of every active session and every retired one, as of
    /// `now_ms` on the MAC clock and `now_unix` on the wall clock.
    pub(crate) fn records(&self, now_ms: u64, now_unix: Option<u32>) -> Vec<PfsSessionRecord> {
        let active = self
            .sessions
            .iter()
            .filter(|session| session.state == PfsState::Active)
            .map(|session| {
                (
                    session.peer_long_term,
                    session.local_ephemeral,
                    session.peer_ephemeral,
                    session.expires_ms,
                )
            });
        let retired = self.retired.iter().map(|retired| {
            (
                retired.peer_long_term,
                retired.local_ephemeral,
                retired.peer_ephemeral,
                retired.expires_ms,
            )
        });
        active
            .chain(retired)
            .filter_map(|(peer, local, peer_ephemeral, expires_ms)| {
                PfsSessionRecord::of(peer, local, peer_ephemeral, expires_ms, now_ms, now_unix)
            })
            .collect()
    }

    /// Whether the records changed since this was last asked.
    pub(crate) fn take_records_changed(&mut self) -> bool {
        core::mem::take(&mut self.records_changed)
    }

    /// Note that `session` left the table.
    fn note_removed(&mut self, session: &PfsSession) {
        if session.state == PfsState::Active {
            self.records_changed = true;
        }
    }

    /// Retire `record`, ending at `expires_ms`, unless a session with its
    /// peer is already known or the table is full.
    fn retire(&mut self, record: &PfsSessionRecord, expires_ms: u64) -> bool {
        let known = self
            .sessions
            .iter()
            .any(|session| session.peer_long_term == record.peer)
            || self
                .retired
                .iter()
                .any(|retired| retired.peer_long_term == record.peer);
        if known || self.retired.len() >= self.max_sessions {
            return false;
        }
        self.retired.push(RetiredPfsSession {
            peer_long_term: record.peer,
            local_ephemeral: record.local_ephemeral,
            peer_ephemeral: record.peer_ephemeral,
            expires_ms,
            closing: Closing::Idle,
        });
        self.records_changed = true;
        true
    }

    /// Remove the retired session with `peer`, returning its local address.
    fn take_retired_peer(&mut self, peer: &PublicKey) -> Option<PublicKey> {
        let index = self
            .retired
            .iter()
            .position(|retired| retired.peer_long_term == *peer)?;
        self.records_changed = true;
        Some(self.retired.swap_remove(index).local_ephemeral)
    }

    /// Remove one retired session that has ended, returning its local
    /// address and peer, and whether it ended by the peer acknowledging
    /// its close.
    fn take_finished_retired(&mut self, now_ms: u64) -> Option<(PublicKey, PublicKey, bool)> {
        let index = self.retired.iter().position(|retired| {
            retired.closing == Closing::Closed || retired.expires_ms <= now_ms
        })?;
        self.records_changed = true;
        let retired = self.retired.swap_remove(index);
        Some((
            retired.local_ephemeral,
            retired.peer_long_term,
            retired.closing == Closing::Closed,
        ))
    }

    /// Begin closing the retired session under `address`, returning its
    /// peer, unless a close is already under way or done.
    fn begin_close(&mut self, address: &PublicKey) -> Option<PublicKey> {
        let retired = self
            .retired
            .iter_mut()
            .find(|retired| retired.local_ephemeral == *address)?;
        if retired.closing != Closing::Idle {
            return None;
        }
        retired.closing = Closing::Sending;
        Some(retired.peer_long_term)
    }

    /// Record what became of queueing the close for `address`: `Some`
    /// waits for that send's acknowledgment, `None` counts it closed, and
    /// a failure (`sent == false`) leaves it to be tried again.
    fn close_queued(&mut self, address: &PublicKey, sent: bool, token: Option<SendToken>) {
        let Some(retired) = self
            .retired
            .iter_mut()
            .find(|retired| retired.local_ephemeral == *address)
        else {
            return;
        };
        if retired.closing != Closing::Sending {
            return;
        }
        retired.closing = match (sent, token) {
            (false, _) => Closing::Idle,
            (true, Some(token)) => Closing::AwaitingAck(token),
            (true, None) => Closing::Closed,
        };
    }

    /// Settle the close sent as `token`: acknowledged, or not, in which
    /// case the next stale frame tries again. Reports whether `token` was
    /// one.
    pub(crate) fn close_settled(&mut self, token: SendToken, acked: bool) -> bool {
        let Some(retired) = self
            .retired
            .iter_mut()
            .find(|retired| retired.closing == Closing::AwaitingAck(token))
        else {
            return false;
        };
        retired.closing = if acked {
            Closing::Closed
        } else {
            Closing::Idle
        };
        true
    }

    /// Borrow the tracked sessions.
    pub(crate) fn sessions(&self) -> &[PfsSession] {
        &self.sessions
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
            let displaced = core::mem::replace(existing, session);
            self.note_removed(&displaced);
            return Ok(Some(displaced));
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
        let session = self.sessions.swap_remove(index);
        self.note_removed(&session);
        Some(session)
    }

    /// Remove the session under the local key `local_ephemeral`.
    fn take_local(&mut self, local_ephemeral: &PublicKey) -> Option<PfsSession> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.local_ephemeral == *local_ephemeral)?;
        let session = self.sessions.swap_remove(index);
        self.note_removed(&session);
        Some(session)
    }

    /// Remove one session past its end.
    fn take_expired(&mut self, now_ms: u64) -> Option<PfsSession> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.expires_ms <= now_ms)?;
        let session = self.sessions.swap_remove(index);
        self.note_removed(&session);
        Some(session)
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

    /// Mark the session under `active`'s local key active. Fails if it is no
    /// longer in the table.
    fn activate(&mut self, peer_ephemeral: PublicKey, active: &ActivatedPfsIdentity) -> bool {
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
        session.state = PfsState::Active;
        self.records_changed = true;
        true
    }

    /// The earliest moment a session ends or a request is abandoned.
    pub(crate) fn next_deadline_ms(&self) -> Option<u64> {
        self.sessions
            .iter()
            .map(|session| match session.state {
                PfsState::Requested => session.expires_ms.min(session.request_deadline_ms),
                PfsState::Active => session.expires_ms,
            })
            .min()
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
    let local_public = begin_session(state, mac, peer, duration_minutes).await?;
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

/// Accept an inbound PFS request, and report whether the session stood when
/// that was done: it does not if it was ended in the meantime, and then no
/// response goes out.
///
/// `channel` is the carriage the request arrived on; the response follows it
/// back.
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
    channel: Option<ChannelKey>,
    options: &SendOptions,
) -> Result<bool, NodeError<M>> {
    // The accepted lifetime is what the response carries, so both sides hold
    // the session to the same one.
    let duration_minutes = session_minutes(duration_minutes);
    begin_session(state, mac, &peer_long_term, duration_minutes).await?;
    let Some(local_public) = establish(
        state,
        mac,
        parent,
        &peer_long_term,
        peer_ephemeral,
        duration_minutes,
    )
    .await?
    else {
        return Ok(false);
    };
    let sent = send_pfs_command(
        mac,
        parent,
        &peer_long_term,
        channel,
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
    Ok(true)
}

/// Accept an inbound PFS response for an existing request, and report whether
/// the session stood when that was done.
#[cfg(feature = "software-crypto")]
pub(crate) async fn accept_response<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer_long_term: PublicKey,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
) -> Result<bool, NodeError<M>> {
    let established = establish(
        state,
        mac,
        parent,
        &peer_long_term,
        peer_ephemeral,
        session_minutes(duration_minutes),
    )
    .await?;
    Ok(established.is_some())
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
    let session = state.borrow_mut().pfs.take_peer(peer);
    if let Some(session) = session {
        release(mac, session).await;
    } else {
        // A session lost to a reboot ends the same way, and the peer's
        // End is what tells a node its retired session is over.
        let retired = state.borrow_mut().pfs.take_retired_peer(peer);
        let Some(address) = retired else {
            return Err(NodeError::PfsSessionMissing);
        };
        let _ = mac.forget_retired_address(&address).await;
    }
    if notify_peer {
        send_pfs_command(mac, parent, peer, None, &MacCommand::EndPfsSession, options).await?;
    }
    Ok(true)
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

/// Retire the sessions `records` describe: this node lost their keys, but
/// recognizes the traffic their peers go on sending under them. A record
/// with nothing left of its session, or with a peer a session is already
/// known with, is dropped, as is any past the table's capacity.
#[cfg(feature = "software-crypto")]
pub(crate) async fn restore_records<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    records: &[PfsSessionRecord],
    now_unix: Option<u32>,
) {
    let now_ms = mac.now_ms().await;
    for record in records {
        let remaining_ms = record.remaining_ms(now_unix);
        if remaining_ms == 0 {
            continue;
        }
        let retired = state
            .borrow_mut()
            .pfs
            .retire(record, now_ms.saturating_add(remaining_ms));
        if retired
            && !mac
                .watch_retired_address(parent, record.local_ephemeral, record.peer_ephemeral)
                .await
        {
            let _ = state.borrow_mut().pfs.take_retired_peer(&record.peer);
        }
    }
    // Whatever was dropped is gone from the records too.
    state.borrow_mut().pfs.records_changed = true;
}

/// Ask the peer of the retired session under `address` to end it, unless
/// that is already under way.
#[cfg(feature = "software-crypto")]
pub(crate) async fn close_retired<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    address: &PublicKey,
    options: &SendOptions,
) {
    let Some(peer) = state.borrow_mut().pfs.begin_close(address) else {
        return;
    };
    // The peer may be nobody this run has spoken to yet.
    if mac.add_peer(peer).await.is_err() {
        state.borrow_mut().pfs.close_queued(address, false, None);
        return;
    }
    let (sent, token) = match send_pfs_command(
        mac,
        parent,
        &peer,
        None,
        &MacCommand::EndPfsSession,
        options,
    )
    .await
    {
        Ok(receipt) => (true, receipt.map(|receipt| SendToken::new(parent, receipt))),
        Err(_) => (false, None),
    };
    state.borrow_mut().pfs.close_queued(address, sent, token);
}

/// Drop the retired sessions that are over, and return the peers of those
/// that ended by the peer acknowledging their close.
#[cfg(feature = "software-crypto")]
pub(crate) async fn settle_retired<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    now_ms: u64,
) -> Vec<PublicKey> {
    let mut closed = Vec::new();
    loop {
        let finished = state.borrow_mut().pfs.take_finished_retired(now_ms);
        let Some((address, peer, acknowledged)) = finished else {
            return closed;
        };
        let _ = mac.forget_retired_address(&address).await;
        if acknowledged {
            closed.push(peer);
        }
    }
}

/// Put a [`Requested`](PfsState::Requested) session with `peer` in the table
/// under a fresh key, and return that key. A session already held with them
/// is released first, so that its slot in the MAC is free for this one's.
#[cfg(feature = "software-crypto")]
async fn begin_session<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    peer: &PublicKey,
    duration_minutes: u16,
) -> Result<PublicKey, NodeError<M>> {
    let mut secret = [0u8; 32];
    mac.fill_random(&mut secret).await;
    let local_ephemeral = SoftwareIdentity::from_secret_bytes(&secret);
    secret.zeroize();
    let local_public = *local_ephemeral.public_key();
    let now_ms = mac.now_ms().await;
    let request_deadline_ms = now_ms.saturating_add(PFS_REQUEST_TIMEOUT_MS);
    let displaced = state.borrow_mut().pfs.install(PfsSession {
        peer_long_term: *peer,
        local_ephemeral_id: LocalIdentityId(u8::MAX),
        local_ephemeral: local_public,
        peer_ephemeral: PublicKey([0u8; 32]),
        expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
        state: PfsState::Requested,
        request_deadline_ms,
        pending_local: Some(local_ephemeral),
    })?;
    // A request nobody answers has to be noticed on a quiet radio.
    mac.wake_by(request_deadline_ms).await;
    if let Some(displaced) = displaced {
        release(mac, displaced).await;
    }
    // A new session with the peer replaces a retired one too.
    let retired = state.borrow_mut().pfs.take_retired_peer(peer);
    if let Some(address) = retired {
        let _ = mac.forget_retired_address(&address).await;
    }
    Ok(local_public)
}

/// Activate the session waiting with `peer`, and return its local key, or
/// `None` if it left the table while its identity was being registered.
#[cfg(feature = "software-crypto")]
async fn establish<M: MacBackend>(
    state: &RefCell<LocalNodeState>,
    mac: &M,
    parent: LocalIdentityId,
    peer: &PublicKey,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
) -> Result<Option<PublicKey>, NodeError<M>> {
    let Some(local_ephemeral) = state.borrow_mut().pfs.take_pending(peer) else {
        return Err(NodeError::PfsSessionMissing);
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
    if state.borrow_mut().pfs.activate(peer_ephemeral, &active) {
        return Ok(Some(local_public));
    }
    let _ = mac.remove_ephemeral(active.local_ephemeral_id).await;
    Ok(None)
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

/// Give back what a session removed from the table holds in the MAC.
#[cfg(feature = "software-crypto")]
async fn release<M: MacBackend>(mac: &M, session: PfsSession) {
    if session.state == PfsState::Active {
        let _ = mac.remove_ephemeral(session.local_ephemeral_id).await;
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
    let _peer_id = mac.add_peer(peer_ephemeral).await?;
    let local_public = *local_ephemeral.public_key();
    let local_ephemeral_id = mac.register_ephemeral(parent, local_ephemeral).await?;
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
