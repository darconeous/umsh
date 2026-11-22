//! The core's commands over the phone's channels: join, create, leave,
//! rejoin, the user's settings, the conversation and the invitation.
//!
//! The store is written first, then the reconciler brings the session in
//! step (`refresh_channels`); no command registers or removes a channel
//! itself. A join, a create or a rejoin that the session refuses is rolled
//! back, and says why. Only membership and ceiling changes reconcile: the
//! alias and the notifications flag derive nothing. A key is read only
//! where the command needs it, and never leaves the core but in a private
//! channel's invitation, which is the key.

use super::bootstrap::{is_public, random_uuid};
use super::channels::{ChannelReport, ChannelState};
use super::peers::trimmed;
use super::records::{MobileAppChangesRecord, MobileAppJoinedChannelRecord};
use super::worker::Worker;
use super::{MobileAppCore, MobileAppError};
use crate::store::{MobileStoredChannelKind, MobileStoredChannelRecord};
use crate::{
    ChannelKindRecord, ChannelPreviewRecord, MobileError, SecretVaultError, well_known_channel,
};

/// The most hops a channel's messages may flood (`umsh_mac::MAX_FLOOD_HOPS`).
const MAX_FLOOD_HOPS: u8 = umsh_mac::MAX_FLOOD_HOPS;

/// A channel invitation (a `umsh:` URI) or a channel's name, parsed.
pub(super) fn parse_channel_input(input: &str) -> Result<ChannelPreviewRecord, MobileAppError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(MobileError::InvalidUri.into());
    }
    let is_uri = input
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("umsh:"));
    Ok(if is_uri {
        crate::inspect_channel_uri(input.to_owned())?
    } else {
        crate::inspect_channel_name(input.to_owned())?
    })
}

/// What a channel command answers for where the channel stands after its
/// reconcile, when it needed it phone-joined and held by the session.
fn joined(report: &ChannelReport, id: &str) -> Result<(), MobileAppError> {
    if report.stale {
        return Err(MobileAppError::NotRunning);
    }
    match report.state(id) {
        ChannelState::Registered => Ok(()),
        ChannelState::Full => Err(MobileAppError::ChannelTableFull),
        ChannelState::Locked => Err(MobileAppError::Vault {
            error: SecretVaultError::Unavailable,
        }),
        ChannelState::KeyFailed => Err(MobileAppError::Vault {
            error: SecretVaultError::Failed,
        }),
        // The session's own reason. Registering sends nothing, so a reason
        // with no code of its own is a refused request, not `SendFailed`.
        ChannelState::Failed(error) => Err(match super::mesh_error(error) {
            MobileAppError::SendFailed => MobileAppError::InvalidRequest,
            other => other,
        }),
        ChannelState::NotJoined | ChannelState::Gone => Err(MobileAppError::NotFound),
    }
}

fn channels_changed(conversations: bool) -> MobileAppChangesRecord {
    MobileAppChangesRecord {
        channels_changed: true,
        conversations_changed: conversations,
        ..MobileAppChangesRecord::default()
    }
}

/// Whether the protocol fixes the channel's ceiling.
fn is_well_known(channel: &MobileStoredChannelRecord) -> bool {
    well_known_channel(channel.canonical_name.clone()).is_some()
}

impl Worker {
    /// The owner's channel, or `NotFound`.
    fn stored_channel(
        &self,
        id: &str,
    ) -> Result<(String, MobileStoredChannelRecord), MobileAppError> {
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let channel = self
            .store
            .channel_by_id(&owner, id)?
            .ok_or(MobileAppError::NotFound)?;
        Ok((owner, channel))
    }

    async fn join_channel(
        &self,
        preview: ChannelPreviewRecord,
        alias: Option<String>,
        open_conversation: bool,
    ) -> Result<MobileAppJoinedChannelRecord, MobileAppError> {
        if preview
            .max_flood_hops
            .is_some_and(|hops| hops > MAX_FLOOD_HOPS)
        {
            return Err(MobileAppError::InvalidRequest);
        }
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let digest = crate::channel_key_digest(preview.key.clone());
        // The lookup and a new channel's insert have no await between, so
        // a second join of the same key finds the first's row.
        let channel_id = match self.store.channel(owner.clone(), digest.clone())? {
            Some(held) => {
                self.join_held(held.clone(), &preview, trimmed(alias))
                    .await?;
                held.id
            }
            None => {
                self.join_new(&owner, &preview, &digest, trimmed(alias))
                    .await?
            }
        };
        let conversation_address = if open_conversation {
            Some(self.open_conversation(&owner, &channel_id).await?)
        } else {
            None
        };
        Ok(MobileAppJoinedChannelRecord {
            channel_id,
            conversation_address,
        })
    }

    /// A key the phone already holds: rejoined if it was left, then given
    /// the alias, and the region and ceiling the invitation names where
    /// the channel has none.
    async fn join_held(
        &self,
        held: MobileStoredChannelRecord,
        preview: &ChannelPreviewRecord,
        alias: Option<String>,
    ) -> Result<(), MobileAppError> {
        if !held.joined_phone {
            self.rejoin(&held).await?;
        }
        if alias.is_some() {
            self.store.set_channel_alias(&held.id, alias)?;
        }
        let region = held.region_code.clone().or_else(|| preview.region.clone());
        let hops = if is_well_known(&held) {
            held.max_flood_hops
        } else {
            held.max_flood_hops.or(preview.max_flood_hops)
        };
        let routed = region != held.region_code || hops != held.max_flood_hops;
        if routed {
            self.store.set_channel_routing(&held.id, region, hops)?;
        }
        self.committed(channels_changed(false));
        // A rejoin reconciled already; a ceiling it lacked, or a channel
        // joined all along, reconciles here. Never `Ok` for a row a
        // concurrent rollback deleted.
        if held.joined_phone || hops != held.max_flood_hops {
            let report = self.refresh_channels().await;
            joined(&report, &held.id)?;
        }
        Ok(())
    }

    /// A key the phone does not hold: to the vault first, then the row,
    /// then the session. A refusal takes the row and the key back.
    async fn join_new(
        &self,
        owner: &str,
        preview: &ChannelPreviewRecord,
        digest: &str,
        alias: Option<String>,
    ) -> Result<String, MobileAppError> {
        let id = random_uuid();
        let now_ms = self.clock.now_ms();
        self.vault.store(id.clone(), preview.key.clone())?;
        let inserted = self.store.insert_channel(
            MobileStoredChannelRecord {
                id: id.clone(),
                owner_identity_id: owner.to_owned(),
                kind: match preview.kind {
                    ChannelKindRecord::NamedPublic => MobileStoredChannelKind::Named,
                    ChannelKindRecord::PrivateKey => MobileStoredChannelKind::PrivateKey,
                },
                canonical_name: preview.canonical_name.clone(),
                name: preview.display_name.clone(),
                alias,
                channel_id_hex: crate::mobile_chat::hex(&preview.channel_id),
                tint: preview.tint.clone(),
                region_code: preview.region.clone(),
                max_flood_hops: preview.max_flood_hops,
                joined_phone: true,
                joined_device: false,
                notifications_enabled: false,
                joined_at_ms: Some(now_ms),
            },
            digest.to_owned(),
            now_ms,
        );
        if let Err(error) = inserted {
            if let Err(error) = self.vault.delete(id.clone()) {
                log::warn!(error:? = error; "a channel's key outlived its failed join");
            }
            return Err(error.into());
        }
        let report = self
            .refresh_channels_holding(Some((&id, &preview.key)))
            .await;
        if let Err(error) = joined(&report, &id) {
            if let Err(error) = self.store.delete_channel(id.clone()) {
                log::warn!(error:? = error; "a refused channel's row was not taken back");
            }
            if let Err(error) = self.vault.delete(id) {
                log::warn!(error:? = error; "a refused channel's key was not taken back");
            }
            // The pass may have sent the key to the radio meanwhile.
            self.rolled_back_channel();
            self.committed(channels_changed(false));
            return Err(error);
        }
        self.committed(channels_changed(false));
        Ok(id)
    }

    /// Join a left channel again. A refusal clears the flag again and says
    /// why. Public's conversation returns with Public.
    async fn rejoin(&self, channel: &MobileStoredChannelRecord) -> Result<(), MobileAppError> {
        self.store
            .set_channel_joined_phone(&channel.id, true, self.clock.now_ms())?;
        let report = self.refresh_channels().await;
        if let Err(error) = joined(&report, &channel.id) {
            if let Err(error) =
                self.store
                    .set_channel_joined_phone(&channel.id, false, self.clock.now_ms())
            {
                log::warn!(error:? = error; "a refused rejoin was not taken back");
            }
            self.rolled_back_channel();
            self.committed(channels_changed(false));
            return Err(error);
        }
        let opened =
            is_public(channel) && self.ensure_public_conversation(&channel.owner_identity_id);
        self.committed(channels_changed(opened));
        Ok(())
    }

    async fn rejoin_channel(&self, id: String) -> Result<(), MobileAppError> {
        let (_, channel) = self.stored_channel(&id)?;
        if channel.joined_phone {
            return Ok(());
        }
        self.rejoin(&channel).await
    }

    async fn create_private_channel(&self, name: String) -> Result<String, MobileAppError> {
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let key = crate::generate_channel_key();
        let preview = ChannelPreviewRecord {
            kind: ChannelKindRecord::PrivateKey,
            canonical_name: None,
            channel_id: crate::derive_channel_id(key.clone())?,
            tint: crate::derive_channel_tint(key.clone())?,
            key,
            display_name: Some(name),
            max_flood_hops: None,
            region: None,
        };
        let digest = crate::channel_key_digest(preview.key.clone());
        self.join_new(&owner, &preview, &digest, None).await
    }

    async fn leave_channel(&self, id: String) -> Result<(), MobileAppError> {
        let (owner, channel) = self.stored_channel(&id)?;
        let left = self
            .store
            .leave_channel(&owner, &channel.id)?
            .ok_or(MobileAppError::NotFound)?;
        if left.deleted
            && let Err(error) = self.vault.delete(channel.id.clone())
        {
            // Erase takes it.
            log::warn!(error:? = error; "a left channel's key stays until erase");
        }
        self.committed(MobileAppChangesRecord {
            channels_changed: true,
            conversations_changed: true,
            transcripts: left.conversation_address.into_iter().collect(),
            ..MobileAppChangesRecord::default()
        });
        // Out of the session by address: no key is read.
        let report = self.refresh_channels().await;
        if report.state(&channel.id) == ChannelState::Registered {
            log::warn!("a left channel is still held by the session");
        }
        Ok(())
    }

    fn set_channel_alias(&self, id: String, alias: Option<String>) -> Result<(), MobileAppError> {
        let (_, channel) = self.stored_channel(&id)?;
        self.store.set_channel_alias(&channel.id, trimmed(alias))?;
        self.committed(channels_changed(false));
        Ok(())
    }

    fn set_channel_notifications(&self, id: String, enabled: bool) -> Result<(), MobileAppError> {
        let (_, channel) = self.stored_channel(&id)?;
        self.store.set_channel_notifications(&channel.id, enabled)?;
        self.committed(channels_changed(false));
        Ok(())
    }

    async fn set_channel_routing(
        &self,
        id: String,
        region: Option<u16>,
        max_flood_hops: Option<u8>,
    ) -> Result<(), MobileAppError> {
        let (_, channel) = self.stored_channel(&id)?;
        if max_flood_hops.is_some() && is_well_known(&channel) {
            return Err(MobileAppError::InvalidRequest);
        }
        let region = region.map(|code| code.to_be_bytes().to_vec());
        self.store
            .set_channel_routing(&channel.id, region, max_flood_hops)?;
        self.committed(channels_changed(false));
        // The session restates a changed ceiling. A locked key waits for
        // the pass, which retries.
        if channel.joined_phone && max_flood_hops != channel.max_flood_hops {
            let report = self.refresh_channels().await;
            if let Err(error) = joined(&report, &channel.id) {
                log::info!(error:? = error; "a channel's new ceiling waits");
            }
        }
        Ok(())
    }

    /// A phone-joined channel's conversation address: from the cache, or
    /// from one reconcile when its key was never read this session.
    async fn conversation_address(&self, id: &str) -> Result<String, MobileAppError> {
        if let Some(address) = self.channels.borrow().conversation_address(id) {
            return Ok(address);
        }
        let report = self.refresh_channels().await;
        if let Some(address) = self.channels.borrow().conversation_address(id) {
            return Ok(address);
        }
        Err(joined(&report, id).err().unwrap_or(MobileAppError::Vault {
            error: SecretVaultError::Failed,
        }))
    }

    /// Open a phone-joined channel's conversation, or find it open. A
    /// channel left while its address was derived opens none.
    async fn open_conversation(&self, owner: &str, id: &str) -> Result<String, MobileAppError> {
        let address = self.conversation_address(id).await?;
        let opened = self.store.open_joined_channel_conversation(
            owner,
            id,
            &address,
            self.clock.now_ms(),
        )?;
        match opened {
            Some(true) => self.committed(MobileAppChangesRecord {
                conversations_changed: true,
                ..MobileAppChangesRecord::default()
            }),
            Some(false) => {}
            None => {
                self.stored_channel(id)?;
                return Err(MobileAppError::InvalidRequest);
            }
        }
        Ok(address)
    }

    async fn open_channel_conversation(&self, id: String) -> Result<String, MobileAppError> {
        let (owner, channel) = self.stored_channel(&id)?;
        if !channel.joined_phone {
            return Err(MobileAppError::InvalidRequest);
        }
        self.open_conversation(&owner, &channel.id).await
    }

    fn channel_invitation(&self, id: String) -> Result<String, MobileAppError> {
        let (_, channel) = self.stored_channel(&id)?;
        let secret = channel.kind == MobileStoredChannelKind::PrivateKey;
        // A named channel's key is its name's; only a private one's is
        // read.
        let named_key = channel
            .canonical_name
            .clone()
            .filter(|_| !secret)
            .and_then(|name| crate::inspect_channel_name(name).ok())
            .map(|preview| preview.key);
        let key = match named_key {
            Some(key) => key,
            None => self
                .vault
                .load(channel.id.clone())?
                .ok_or(MobileAppError::Vault {
                    error: SecretVaultError::Failed,
                })?,
        };
        let fixed = is_well_known(&channel);
        // A named channel's URI names the channel, so it carries the name
        // the key is derived from. Its own name travels in that place only
        // when it differs by casing; any other name travels as the display
        // name, as a private channel's does.
        let (uri_name, display_name) = match (&channel.canonical_name, &channel.name) {
            (Some(canonical), Some(name)) if !secret => {
                if name.eq_ignore_ascii_case(canonical) {
                    (Some(name.clone()), None)
                } else {
                    (Some(canonical.clone()), Some(name.clone()))
                }
            }
            (Some(canonical), None) if !secret => (Some(canonical.clone()), None),
            _ => (None, channel.name.clone()),
        };
        Ok(crate::format_channel_invitation(
            key,
            uri_name,
            display_name,
            if fixed { None } else { channel.max_flood_hops },
            channel.region_code,
        )?)
    }
}

#[uniffi::export]
impl MobileAppCore {
    /// Join a channel by invitation (a `umsh:` URI) or by name, as
    /// `preview_channel` reads it. A key the phone holds already is
    /// rejoined if it was left, and given the invitation's region and
    /// ceiling only where it has none. `alias` empty or `None` keeps the
    /// stored one. With `open_conversation`, its conversation opens too.
    /// A session that holds as many channels as it can is
    /// `ChannelTableFull`, and nothing is kept.
    pub async fn join_channel(
        &self,
        input: String,
        alias: Option<String>,
        open_conversation: bool,
    ) -> Result<MobileAppJoinedChannelRecord, MobileAppError> {
        let preview = parse_channel_input(&input)?;
        self.command(move |worker| async move {
            worker.join_channel(preview, alias, open_conversation).await
        })
        .await
    }

    /// Create a private channel called `name`, under a new key that never
    /// leaves the core but in its invitation. Answers with its ID.
    pub async fn create_private_channel(&self, name: String) -> Result<String, MobileAppError> {
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(MobileAppError::InvalidRequest);
        }
        self.command(move |worker| async move { worker.create_private_channel(name).await })
            .await
    }

    /// Leave a channel: its conversation and history go, and so do the row
    /// and the key of any but Public and EMERGENCY, which stay to be
    /// joined again.
    pub async fn leave_channel(&self, id: String) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.leave_channel(id).await })
            .await
    }

    /// Join a left channel again. Public's conversation opens with it.
    pub async fn rejoin_channel(&self, id: String) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.rejoin_channel(id).await })
            .await
    }

    /// What this user calls a channel, trimmed; empty or `None` clears it.
    pub async fn set_channel_alias(
        &self,
        id: String,
        alias: Option<String>,
    ) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.set_channel_alias(id, alias) })
            .await
    }

    /// Whether a channel's conversation may notify.
    pub async fn set_channel_notifications(
        &self,
        id: String,
        enabled: bool,
    ) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.set_channel_notifications(id, enabled) })
            .await
    }

    /// A channel's region, at most one for now, and its flood-hop ceiling,
    /// at most 15; `None` is the default. Public and EMERGENCY take no
    /// ceiling: the protocol fixes theirs.
    pub async fn set_channel_routing(
        &self,
        id: String,
        regions: Vec<u16>,
        max_flood_hops: Option<u8>,
    ) -> Result<(), MobileAppError> {
        if regions.len() > 1 || max_flood_hops.is_some_and(|hops| hops > MAX_FLOOD_HOPS) {
            return Err(MobileAppError::InvalidRequest);
        }
        let region = regions.first().copied();
        self.command(move |worker| async move {
            worker.set_channel_routing(id, region, max_flood_hops).await
        })
        .await
    }

    /// Open a phone-joined channel's conversation, or find it open.
    /// Answers with its address.
    pub async fn open_channel_conversation(&self, id: String) -> Result<String, MobileAppError> {
        self.command(move |worker| async move { worker.open_channel_conversation(id).await })
            .await
    }

    /// The invitation to a channel: its name for a named channel, its key
    /// for a private one, with its region, and its ceiling where the
    /// protocol fixes none. The alias never travels.
    pub async fn channel_invitation(&self, id: String) -> Result<String, MobileAppError> {
        self.command(move |worker| async move { worker.channel_invitation(id) })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MobileMeshError;

    #[test]
    fn a_refused_registration_says_why_and_never_that_it_sent() {
        let answer = |error| joined(&ChannelReport::of("c", ChannelState::Failed(error)), "c");
        assert_eq!(
            answer(MobileMeshError::SessionUnavailable),
            Err(MobileAppError::NotRunning)
        );
        assert_eq!(
            answer(MobileMeshError::InvalidRequest),
            Err(MobileAppError::InvalidRequest)
        );
        assert_eq!(
            answer(MobileMeshError::OperationInProgress),
            Err(MobileAppError::InvalidRequest)
        );
    }
}
