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
        }
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
    let Some(session) = state.borrow_mut().pfs.take_peer(peer) else {
        return Err(NodeError::PfsSessionMissing);
    };
    release(mac, session).await;
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
    let displaced = state.borrow_mut().pfs.install(PfsSession {
        peer_long_term: *peer,
        local_ephemeral_id: LocalIdentityId(u8::MAX),
        local_ephemeral: local_public,
        peer_ephemeral: PublicKey([0u8; 32]),
        expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
        state: PfsState::Requested,
        request_deadline_ms: now_ms.saturating_add(PFS_REQUEST_TIMEOUT_MS),
        pending_local: Some(local_ephemeral),
    })?;
    if let Some(displaced) = displaced {
        release(mac, displaced).await;
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
