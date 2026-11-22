//! The core's commands over peers, conversations and discovery.
//!
//! Each writes the store first, raises the flags for what it wrote, and
//! runs the pass. A session call after the store's commit is logged, never
//! returned. Input is parsed before the worker, so a bad link or address
//! reads as bad input.

use super::bootstrap::{CHANNEL_ADDRESS_PREFIX, advertises_mobile};
use super::limits::DISCOVERY_COOLDOWN_MS;
use super::pipeline::{link_identity_replaces, node_kind};
use super::records::{MobileAppChangesRecord, MobileAppLifecycle};
use super::routes::{checked_address, checked_conversation_address};
use super::worker::Worker;
use super::{MobileAppCore, MobileAppError, mesh_error};
use crate::mobile_mesh::MobilePeerRegistrationRecord;
use crate::store::{MobilePeerUpsertRecord, MobileStoreError, MobileStoredNodeRecord};
use crate::{MobileMeshError, NodeUriPreviewRecord, SecretVaultError};

/// The text the user typed or a link carried, trimmed; `None` when empty.
pub(super) fn trimmed(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// The identity a link carries, as one upsert: the advertised name, the
/// node kind and the payload together, unauthenticated and undated. None
/// of them when the link carries no bundle that may be stored.
fn link_identity(link: &NodeUriPreviewRecord) -> MobilePeerUpsertRecord {
    match (&link.identity, &link.identity_payload) {
        (Some(identity), Some(payload)) => MobilePeerUpsertRecord {
            advertised_name: identity.name.clone(),
            node_kind: Some(node_kind(identity.role_code)),
            advertisement: Some(payload.clone()),
            advertisement_authenticated: false,
            advertisement_received_at_ms: None,
            ..MobilePeerUpsertRecord::default()
        },
        _ => MobilePeerUpsertRecord::default(),
    }
}

fn peers_changed() -> MobileAppChangesRecord {
    MobileAppChangesRecord {
        peers_changed: true,
        ..MobileAppChangesRecord::default()
    }
}

fn conversations_changed(transcript: Option<String>) -> MobileAppChangesRecord {
    MobileAppChangesRecord {
        conversations_changed: true,
        transcripts: transcript.into_iter().collect(),
        ..MobileAppChangesRecord::default()
    }
}

impl Worker {
    /// Raise what a command wrote, then run the pass, which reads it.
    pub(super) fn committed(&self, changes: MobileAppChangesRecord) {
        self.raise(changes);
        self.policy_triggered();
    }

    fn owner_or_refuse(&self) -> Result<String, MobileAppError> {
        self.owner().ok_or(MobileAppError::NoOwner)
    }

    /// The owner's row for a peer, or `NotFound`.
    fn stored_peer(
        &self,
        owner: &str,
        address: &str,
    ) -> Result<MobileStoredNodeRecord, MobileAppError> {
        self.store
            .node(owner, address)?
            .ok_or(MobileAppError::NotFound)
    }

    /// Register a peer a conversation now names with the session, mobile
    /// by its stored advertisement, as bootstrap does.
    async fn register_peer(&self, owner: &str, address: &str) {
        let Some(session) = self.session() else {
            return;
        };
        let mobile = self
            .store
            .node(owner, address)
            .ok()
            .flatten()
            .is_some_and(|node| advertises_mobile(&node));
        let registered = session
            .register_peers(vec![MobilePeerRegistrationRecord {
                address: address.to_owned(),
                mobile,
            }])
            .await;
        if let Err(error) = registered {
            log::warn!(error:? = error; "a conversation's peer could not be registered");
        }
    }

    async fn save_peer(
        &self,
        link: NodeUriPreviewRecord,
        alias: Option<String>,
        start_conversation: bool,
    ) -> Result<String, MobileAppError> {
        let owner = self.owner_or_refuse()?;
        let address = link.canonical_address.clone();
        if address == owner {
            return Err(MobileAppError::InvalidRequest);
        }
        // The read and the upsert with no await between: nothing writes the
        // row in the meantime.
        let stored = self.store.node(&owner, &address)?;
        let identity = if link_identity_replaces(stored.as_ref(), &link) {
            link_identity(&link)
        } else {
            MobilePeerUpsertRecord::default()
        };
        self.store.upsert_peer(
            owner.clone(),
            address.clone(),
            MobilePeerUpsertRecord {
                alias: trimmed(alias),
                is_saved: true,
                ..identity
            },
        )?;
        if !start_conversation {
            self.committed(peers_changed());
            return Ok(address);
        }
        let started = self
            .store
            .ensure_direct_conversation(owner.clone(), address.clone(), self.clock.now_ms())
            .map(|_| ());
        self.committed(MobileAppChangesRecord {
            peers_changed: true,
            conversations_changed: started.is_ok(),
            ..MobileAppChangesRecord::default()
        });
        started?;
        self.register_peer(&owner, &address).await;
        Ok(address)
    }

    fn record_link_peer(
        &self,
        link: NodeUriPreviewRecord,
    ) -> Result<Option<String>, MobileAppError> {
        let owner = self.owner_or_refuse()?;
        let address = link.canonical_address.clone();
        if address == owner {
            return Ok(None);
        }
        if self.store.node(&owner, &address)?.is_some() {
            return Ok(Some(address));
        }
        // No retention pass: a row never heard is the oldest-heard there
        // is, so a full tier would evict it before its page opened.
        self.store
            .upsert_peer(owner, address.clone(), link_identity(&link))?;
        self.committed(peers_changed());
        Ok(Some(address))
    }

    fn save_administered_device(
        &self,
        address: String,
        name: Option<String>,
        role: Option<u8>,
    ) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        self.store.upsert_peer(
            owner,
            address,
            MobilePeerUpsertRecord {
                advertised_name: trimmed(name),
                is_saved: true,
                node_kind: role.map(node_kind),
                ..MobilePeerUpsertRecord::default()
            },
        )?;
        self.committed(peers_changed());
        Ok(())
    }

    /// A write on a stored peer: `NotFound` with no row.
    fn edit_peer(
        &self,
        address: String,
        write: impl FnOnce(&Worker, String, String) -> Result<(), MobileStoreError>,
    ) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        self.stored_peer(&owner, &address)?;
        write(self, owner, address)?;
        self.committed(peers_changed());
        Ok(())
    }

    async fn delete_peer(
        &self,
        address: String,
        with_conversation: bool,
    ) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        self.stored_peer(&owner, &address)?;
        let deleted = if with_conversation {
            self.store
                .delete_peer_and_conversation(owner, address.clone())?
        } else {
            self.store.delete_peer(owner, address.clone())?
        };
        // A conversation holds it, or it is the companion radio.
        if !deleted {
            return Err(MobileAppError::InvalidRequest);
        }
        self.forget_conversation(&address);
        self.committed(MobileAppChangesRecord {
            peers_changed: true,
            conversations_changed: with_conversation,
            transcripts: if with_conversation {
                vec![address.clone()]
            } else {
                Vec::new()
            },
            ..MobileAppChangesRecord::default()
        });
        if let Some(session) = self.session()
            && let Err(error) = session.remove_peers(vec![address]).await
        {
            log::warn!(error:? = error; "a deleted peer could not leave the session");
        }
        Ok(())
    }

    fn clear_discovered(&self) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        self.store.clear_transient_peers(owner)?;
        self.committed(peers_changed());
        Ok(())
    }

    async fn start_conversation(&self, address: String) -> Result<String, MobileAppError> {
        let owner = self.owner_or_refuse()?;
        self.store
            .ensure_direct_conversation(owner.clone(), address.clone(), self.clock.now_ms())
            .map_err(|error| match error {
                MobileStoreError::RecordNotFound => MobileAppError::NotFound,
                error => error.into(),
            })?;
        self.committed(conversations_changed(None));
        self.register_peer(&owner, &address).await;
        Ok(address)
    }

    fn delete_conversation(&self, address: String) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        if address.starts_with(CHANNEL_ADDRESS_PREFIX) {
            let Some((id, _)) = self
                .store
                .channel_conversation_by_address(&owner, &address)?
            else {
                return Ok(());
            };
            self.store.delete_channel_conversation(owner, id)?;
        } else {
            let Some(id) = self.store.direct_conversation_id(&owner, &address)? else {
                return Ok(());
            };
            self.store.delete_direct_conversation(owner, id)?;
        }
        self.forget_conversation(&address);
        self.committed(conversations_changed(Some(address)));
        Ok(())
    }

    fn set_conversation_notifications(
        &self,
        address: String,
        enabled: bool,
    ) -> Result<(), MobileAppError> {
        if address.starts_with(CHANNEL_ADDRESS_PREFIX) {
            return Err(MobileAppError::InvalidRequest);
        }
        let owner = self.owner_or_refuse()?;
        let id = self
            .store
            .direct_conversation_id(&owner, &address)?
            .ok_or(MobileAppError::NotFound)?;
        self.store
            .set_direct_conversation_notifications(owner, id, enabled)?;
        self.committed(conversations_changed(None));
        Ok(())
    }

    async fn request_member_identity(
        &self,
        address: String,
        hint: Vec<u8>,
    ) -> Result<(), MobileAppError> {
        let owner = self.owner_or_refuse()?;
        // The cache names the channel when its key was read; a locked one
        // is found through its conversation instead.
        let cached = self.channels.borrow().channel_at(&address);
        let channel_id = match cached {
            Some(id) => Some(id),
            None => self
                .store
                .channel_conversation_by_address(&owner, &address)?
                .map(|(_, id)| id),
        };
        let joined = match channel_id {
            Some(id) => self
                .store
                .channel_by_id(&owner, &id)?
                .is_some_and(|channel| channel.joined_phone),
            None => false,
        };
        if !joined {
            return Err(MobileAppError::NotFound);
        }
        // It goes out over the channel, so `EMERGENCY`'s warning comes
        // first, whatever the radio's state.
        self.emergency_refusal(&owner, &address)?;
        let session = self.radio_session()?;
        match session.request_identity_by_hint(address, hint).await {
            Ok(()) => Ok(()),
            // Joined, but the session does not hold it.
            Err(MobileMeshError::UnknownConversation) => Err(if self.channels.borrow().locked {
                MobileAppError::Vault {
                    error: SecretVaultError::Unavailable,
                }
            } else {
                MobileAppError::SendFailed
            }),
            Err(error) => Err(mesh_error(error)),
        }
    }
}

/// How long until `ready_at_ms`, from `now_ms`.
fn discovery_wait(ready_at_ms: Option<i64>, now_ms: i64) -> u64 {
    ready_at_ms.map_or(0, |ready| {
        u64::try_from(ready.saturating_sub(now_ms)).unwrap_or(0)
    })
}

/// An unnarrowed ask's hold on the discovery cooldown: what it set, and
/// what it replaced.
pub(super) struct DiscoveryCooldown {
    previous: Option<i64>,
    set: i64,
}

impl Worker {
    /// Start the discovery cooldown, or `InvalidRequest` inside it. Read
    /// and written under one lock, so two asks cannot both pass.
    fn begin_discovery(&self) -> Result<DiscoveryCooldown, MobileAppError> {
        let now = self.clock.monotonic_ms();
        let mut snapshot = self.shared.snapshot();
        if discovery_wait(snapshot.discovery_ready_at_ms, now) > 0 {
            return Err(MobileAppError::InvalidRequest);
        }
        let set = now.saturating_add(DISCOVERY_COOLDOWN_MS as i64);
        let previous = snapshot.discovery_ready_at_ms.replace(set);
        Ok(DiscoveryCooldown { previous, set })
    }

    /// An ask that never went gives its cooldown back, unless a later one
    /// has started its own since.
    fn abandon_discovery(&self, cooldown: DiscoveryCooldown) {
        let mut snapshot = self.shared.snapshot();
        if snapshot.discovery_ready_at_ms == Some(cooldown.set) {
            snapshot.discovery_ready_at_ms = cooldown.previous;
        }
    }
}

/// A route of 2-byte router hints, and a node hint of 2 or 3 bytes.
fn checked_discovery(node_hint: Option<&[u8]>, route: &[Vec<u8>]) -> Result<(), MobileAppError> {
    let hint_fits = node_hint.is_none_or(|hint| matches!(hint.len(), 2 | 3));
    if !hint_fits || route.iter().any(|hop| hop.len() != 2) {
        return Err(MobileAppError::InvalidRequest);
    }
    Ok(())
}

#[uniffi::export]
impl MobileAppCore {
    /// Save a peer from a link, a Base58 address or hex: saved, with
    /// `alias` (empty or `None` keeps the stored one). The link's identity
    /// replaces the stored one only when it is validly signed and newer,
    /// or nothing is stored. With `start_conversation`, its conversation is
    /// opened too. Answers with the peer's address, which is also its
    /// conversation's. This phone's own address is `InvalidRequest`.
    pub async fn save_peer(
        &self,
        input: String,
        alias: Option<String>,
        start_conversation: bool,
    ) -> Result<String, MobileAppError> {
        let link = crate::inspect_peer_identity(input)?;
        self.command(move |worker| async move {
            worker.save_peer(link, alias, start_conversation).await
        })
        .await
    }

    /// The peer an opened node link names, recorded unsaved with the
    /// link's identity when the phone has no row for it; a row in any tier
    /// is left as it is. `None` for this phone's own address.
    pub async fn record_link_peer(&self, input: String) -> Result<Option<String>, MobileAppError> {
        let link = crate::inspect_peer_identity(input)?;
        self.command(move |worker| async move { worker.record_link_peer(link) })
            .await
    }

    /// Save a device this phone configured: `name` is its advertised name,
    /// until its own identity is heard; `role` its role code, or `None` to
    /// keep the stored kind.
    pub async fn save_administered_device(
        &self,
        address: String,
        name: Option<String>,
        role: Option<u8>,
    ) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(
            move |worker| async move { worker.save_administered_device(address, name, role) },
        )
        .await
    }

    /// What this user calls a peer, trimmed; empty or `None` clears it.
    pub async fn set_alias(
        &self,
        address: String,
        alias: Option<String>,
    ) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.edit_peer(address, |worker, owner, address| {
                worker
                    .store
                    .update_node_alias(owner, address, trimmed(alias))
            })
        })
        .await
    }

    /// Favoriting a peer also saves it.
    pub async fn set_favorite(
        &self,
        address: String,
        favorite: bool,
    ) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.edit_peer(address, |worker, owner, address| {
                worker.store.set_peer_favorite(owner, address, favorite)
            })
        })
        .await
    }

    /// Arm or disarm the one-shot watch: a `peer_heard` notification the
    /// next time the peer is heard.
    pub async fn set_notify_when_heard(
        &self,
        address: String,
        armed: bool,
    ) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.edit_peer(address, |worker, owner, address| {
                worker.store.set_notify_when_heard(owner, address, armed)
            })
        })
        .await
    }

    pub async fn promote_peer(&self, address: String) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.edit_peer(address, |worker, owner, address| {
                worker.store.promote_peer_to_saved(owner, address)
            })
        })
        .await
    }

    /// Back to the transient tier, without its favorite and alias. The
    /// companion radio's row is left as it is. A conversation keeps
    /// working.
    pub async fn demote_peer(&self, address: String) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.edit_peer(address, |worker, owner, address| {
                worker.store.demote_peer_to_transient(owner, address)
            })
        })
        .await
    }

    /// Delete a peer, and with `with_conversation` its conversation and
    /// history too. Without, a peer a conversation holds is
    /// `InvalidRequest`, as the companion radio always is.
    pub async fn delete_peer(
        &self,
        address: String,
        with_conversation: bool,
    ) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(
            move |worker| async move { worker.delete_peer(address, with_conversation).await },
        )
        .await
    }

    /// Forget the transient peers nothing else holds.
    pub async fn clear_discovered(&self) -> Result<(), MobileAppError> {
        self.command(|worker| async move { worker.clear_discovered() })
            .await
    }

    /// Open the conversation with a stored peer, or find it open. Answers
    /// with its address.
    pub async fn start_conversation(&self, address: String) -> Result<String, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move { worker.start_conversation(address).await })
            .await
    }

    /// Delete a conversation, direct or a channel's, and its history. The
    /// peer stays, and a channel stays joined. Nothing there is not an
    /// error.
    pub async fn delete_conversation(&self, address: String) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.command(move |worker| async move { worker.delete_conversation(address) })
            .await
    }

    /// Whether a direct conversation may notify. A channel's is
    /// `set_channel_notifications`.
    pub async fn set_conversation_notifications(
        &self,
        address: String,
        enabled: bool,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        self.command(move |worker| async move {
            worker.set_conversation_notifications(address, enabled)
        })
        .await
    }

    /// Ask a peer for its identity. The answer arrives as a peers change.
    pub async fn fetch_identity(&self, address: String) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            let session = worker.radio_session()?;
            session.request_identity(address).await.map_err(mesh_error)
        })
        .await
    }

    /// Ask the nodes in range, or those where `route` ends, for their
    /// identities: those with `role`, or with a node hint starting with
    /// `node_hint` (2 or 3 bytes). Each hop of `route` is a 2-byte router
    /// hint. Answers arrive as peers changes.
    ///
    /// An ask without `node_hint` draws every node in range, so one goes
    /// at most once per `mobile_limits().discovery_cooldown_ms`, whatever
    /// its role or route; one sooner is `InvalidRequest`, and
    /// `discovery_wait_ms` says how long is left.
    pub async fn discover(
        &self,
        role: Option<u8>,
        node_hint: Option<Vec<u8>>,
        route: Vec<Vec<u8>>,
    ) -> Result<(), MobileAppError> {
        checked_discovery(node_hint.as_deref(), &route)?;
        self.command(move |worker| async move {
            let session = worker.radio_session()?;
            let cooldown = match node_hint {
                Some(_) => None,
                None => Some(worker.begin_discovery()?),
            };
            let asked = session
                .discover_identities(role, None, node_hint, route)
                .await;
            // Unsaved counters fail an ask that still went on the air.
            let went = matches!(
                asked,
                Ok(()) | Err(MobileMeshError::CounterPersistenceFailed)
            );
            if !went && let Some(cooldown) = cooldown {
                worker.abandon_discovery(cooldown);
            }
            asked.map_err(mesh_error)
        })
        .await
    }

    /// Milliseconds until an unnarrowed `discover` may go; 0 when it may
    /// now.
    pub fn discovery_wait_ms(&self) -> Result<u64, MobileAppError> {
        let snapshot = self.shared.snapshot();
        if snapshot.lifecycle == MobileAppLifecycle::Stopped {
            return Err(MobileAppError::Stopped);
        }
        Ok(discovery_wait(
            snapshot.discovery_ready_at_ms,
            self.clock.monotonic_ms(),
        ))
    }

    /// Ask the member of a channel conversation known by its 3-byte hint
    /// for its identity.
    pub async fn request_member_identity(
        &self,
        address: String,
        hint: Vec<u8>,
    ) -> Result<(), MobileAppError> {
        checked_conversation_address(&address)?;
        if !address.starts_with(CHANNEL_ADDRESS_PREFIX) || hint.len() != 3 {
            return Err(MobileAppError::InvalidRequest);
        }
        self.command(
            move |worker| async move { worker.request_member_identity(address, hint).await },
        )
        .await
    }
}
