#[cfg(feature = "software-crypto")]
use alloc::vec::Vec;

#[cfg(feature = "software-crypto")]
use umsh_app::{mac_command, MacCommand, PayloadType};
#[cfg(feature = "software-crypto")]
use umsh_core::PublicKey;
#[cfg(feature = "software-crypto")]
use umsh_crypto::{software::SoftwareIdentity, NodeIdentity};
#[cfg(feature = "software-crypto")]
use umsh_mac::{LocalIdentityId, SendOptions, SendReceipt};

#[cfg(feature = "software-crypto")]
use crate::{mac::MacBackend, node::NodeError};

#[cfg(feature = "software-crypto")]
const DEFAULT_MAX_PFS_SESSIONS: usize = 4;

#[cfg(feature = "software-crypto")]
/// Lifecycle state for a PFS session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PfsState {
    /// Session requested but not fully activated.
    Requested,
    /// Session active and mapped to an ephemeral MAC identity.
    Active,
}

#[cfg(feature = "software-crypto")]
/// One tracked PFS session.
pub struct PfsSession {
    /// Peer long-term identity.
    pub peer_long_term: PublicKey,
    /// Local ephemeral MAC identity.
    pub local_ephemeral_id: LocalIdentityId,
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
    pending_local: Option<SoftwareIdentity>,
}

#[cfg(feature = "software-crypto")]
impl core::fmt::Debug for PfsSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PfsSession")
            .field("peer_long_term", &self.peer_long_term)
            .field("local_ephemeral_id", &self.local_ephemeral_id)
            .field("peer_ephemeral", &self.peer_ephemeral)
            .field("expires_ms", &self.expires_ms)
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(feature = "software-crypto")]
/// Fixed-capacity manager for endpoint-level PFS sessions.
pub struct PfsSessionManager {
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
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            max_sessions: DEFAULT_MAX_PFS_SESSIONS,
        }
    }

    /// Borrow the tracked sessions.
    pub fn sessions(&self) -> &[PfsSession] {
        &self.sessions
    }

    /// Return the active ephemeral route for `peer`, if any.
    pub fn active_route(&self, peer: &PublicKey, now_ms: u64) -> Option<(LocalIdentityId, PublicKey)> {
        self.sessions
            .iter()
            .find(|session| session.peer_long_term == *peer && session.state == PfsState::Active && session.expires_ms > now_ms)
            .map(|session| (session.local_ephemeral_id, session.peer_ephemeral))
    }

    /// Initiate a new PFS session request.
    pub async fn request_session<M: MacBackend>(
        &mut self,
        mac: &M,
        parent: LocalIdentityId,
        peer: &PublicKey,
        duration_minutes: u16,
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, NodeError<M>> {
        self.remove_existing(mac, peer)?;
        self.ensure_capacity()?;
        let mut secret = [0u8; 32];
        mac.fill_random(&mut secret)?;
        let local_ephemeral = SoftwareIdentity::from_secret_bytes(&secret);
        let now_ms = mac.now_ms()?;
        let receipt = send_pfs_command(
            mac,
            parent,
            peer,
            &MacCommand::PfsSessionRequest {
                ephemeral_key: *local_ephemeral.public_key(),
                duration_minutes,
            },
            options,
        )
        .await?;
        self.sessions.push(PfsSession {
            peer_long_term: *peer,
            local_ephemeral_id: LocalIdentityId(u8::MAX),
            peer_ephemeral: PublicKey([0u8; 32]),
            expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
            state: PfsState::Requested,
            pending_local: Some(local_ephemeral),
        });
        Ok(receipt)
    }

    /// Accept an inbound PFS request.
    pub async fn accept_request<M: MacBackend>(
        &mut self,
        mac: &M,
        parent: LocalIdentityId,
        peer_long_term: PublicKey,
        peer_ephemeral: PublicKey,
        duration_minutes: u16,
        options: &SendOptions,
    ) -> Result<(), NodeError<M>> {
        self.remove_existing(mac, &peer_long_term)?;
        self.ensure_capacity()?;
        let mut secret = [0u8; 32];
        mac.fill_random(&mut secret)?;
        let local_ephemeral = SoftwareIdentity::from_secret_bytes(&secret);
        let active = activate_identity(mac, parent, local_ephemeral, peer_ephemeral, duration_minutes)?;
        send_pfs_command(
            mac,
            parent,
            &peer_long_term,
            &MacCommand::PfsSessionResponse {
                ephemeral_key: active.peer_local_public,
                duration_minutes,
            },
            options,
        )
        .await?;
        self.sessions.push(PfsSession {
            peer_long_term,
            local_ephemeral_id: active.local_ephemeral_id,
            peer_ephemeral,
            expires_ms: active.expires_ms,
            state: PfsState::Active,
            pending_local: None,
        });
        Ok(())
    }

    /// Accept an inbound PFS response for an existing request.
    pub fn accept_response<M: MacBackend>(
        &mut self,
        mac: &M,
        parent: LocalIdentityId,
        peer_long_term: PublicKey,
        peer_ephemeral: PublicKey,
        duration_minutes: u16,
    ) -> Result<bool, NodeError<M>> {
        let Some(index) = self.sessions.iter().position(|session| session.peer_long_term == peer_long_term) else {
            return Err(NodeError::PfsSessionMissing);
        };
        let mut session = self.sessions.swap_remove(index);
        let Some(local_ephemeral) = session.pending_local.take() else {
            self.sessions.push(session);
            return Err(NodeError::PfsSessionMissing);
        };
        let active = activate_identity(mac, parent, local_ephemeral, peer_ephemeral, duration_minutes)?;
        session.local_ephemeral_id = active.local_ephemeral_id;
        session.peer_ephemeral = peer_ephemeral;
        session.expires_ms = active.expires_ms;
        session.state = PfsState::Active;
        self.sessions.push(session);
        Ok(true)
    }

    /// End one session and optionally notify the peer.
    pub async fn end_session<M: MacBackend>(
        &mut self,
        mac: &M,
        parent: LocalIdentityId,
        peer: &PublicKey,
        notify_peer: bool,
        options: &SendOptions,
    ) -> Result<bool, NodeError<M>> {
        let Some(index) = self.sessions.iter().position(|session| session.peer_long_term == *peer) else {
            return Err(NodeError::PfsSessionMissing);
        };
        let session = self.sessions.swap_remove(index);
        if session.state == PfsState::Active {
            let _ = mac.remove_ephemeral(session.local_ephemeral_id)?;
        }
        if notify_peer {
            send_pfs_command(mac, parent, peer, &MacCommand::EndPfsSession, options)
                .await?;
        }
        Ok(true)
    }

    /// Expire any sessions whose deadlines have passed.
    pub fn expire_sessions<M: MacBackend>(
        &mut self,
        mac: &M,
        now_ms: u64,
    ) -> Result<Vec<PublicKey>, NodeError<M>> {
        let mut expired = Vec::new();
        let mut index = 0usize;
        while index < self.sessions.len() {
            if self.sessions[index].expires_ms > now_ms {
                index += 1;
                continue;
            }
            let session = self.sessions.swap_remove(index);
            if session.state == PfsState::Active {
                let _ = mac.remove_ephemeral(session.local_ephemeral_id)?;
            }
            expired.push(session.peer_long_term);
        }
        Ok(expired)
    }

    fn remove_existing<M: MacBackend>(&mut self, mac: &M, peer: &PublicKey) -> Result<(), NodeError<M>> {
        if let Some(index) = self.sessions.iter().position(|session| session.peer_long_term == *peer) {
            let session = self.sessions.swap_remove(index);
            if session.state == PfsState::Active {
                let _ = mac.remove_ephemeral(session.local_ephemeral_id)?;
            }
        }
        Ok(())
    }

    fn ensure_capacity<M: MacBackend>(&self) -> Result<(), NodeError<M>> {
        if self.sessions.len() >= self.max_sessions {
            Err(NodeError::PfsSessionTableFull)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "software-crypto")]
struct ActivatedPfsIdentity {
    local_ephemeral_id: LocalIdentityId,
    peer_local_public: PublicKey,
    expires_ms: u64,
}

#[cfg(feature = "software-crypto")]
fn activate_identity<M: MacBackend>(
    mac: &M,
    parent: LocalIdentityId,
    local_ephemeral: SoftwareIdentity,
    peer_ephemeral: PublicKey,
    duration_minutes: u16,
) -> Result<ActivatedPfsIdentity, NodeError<M>> {
    let _peer_id = mac.add_peer(peer_ephemeral)?;
    let peer_local_public = *local_ephemeral.public_key();
    let local_ephemeral_id = mac.register_ephemeral(parent, local_ephemeral)?;
    let now_ms = mac.now_ms()?;
    Ok(ActivatedPfsIdentity {
        local_ephemeral_id,
        peer_local_public,
        expires_ms: now_ms.saturating_add(u64::from(duration_minutes) * 60_000),
    })
}

#[cfg(feature = "software-crypto")]
async fn send_pfs_command<M: MacBackend>(
    mac: &M,
    from: LocalIdentityId,
    peer: &PublicKey,
    command: &MacCommand<'_>,
    options: &SendOptions,
) -> Result<Option<SendReceipt>, NodeError<M>> {
    let mut body = [0u8; 80];
    let len = mac_command::encode(command, &mut body)?;
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(PayloadType::MacCommand as u8);
    payload.extend_from_slice(&body[..len]);
    mac.send_unicast(from, peer, &payload, options)
        .await
        .map_err(Into::into)
}
