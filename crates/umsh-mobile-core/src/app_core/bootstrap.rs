//! What `start` does between building the session and handing it to the
//! radio: the store's repairs, the built-in channels, channel registration,
//! chat, held paths, and the settings the session starts without.
//!
//! Only the repairs can fail `start`. Everything after them is logged and
//! retried where a retry can help: a channel whose key will not load is
//! registered on a later pass.

use std::collections::BTreeSet;
use std::rc::Rc;

use super::worker::Worker;
use crate::MobileStoredNodeRecord;
use crate::mobile_mesh::{MobileMeshExplicitPath, MobilePeerRegistrationRecord};
use crate::store::{MobileStoreError, MobileStoredChannelKind, MobileStoredChannelRecord};

/// The channels every identity starts on, written the way the protocol
/// names them. Only the canonical form reaches the key, so the casing is
/// how the channels are labeled.
const BUILTIN_CHANNELS: [&str; 2] = ["Public", "EMERGENCY"];

/// The prefix of a channel conversation's address.
pub(super) const CHANNEL_ADDRESS_PREFIX: &str = "ch:";

impl Worker {
    /// The repairs a session needs before anything runs: the identity row
    /// `knows_identity` looks for, sends a previous run left unfinished,
    /// and gaps nobody can fill now that their session is gone.
    pub(super) fn repair_store(&self, owner: &str) -> Result<(), MobileStoreError> {
        self.store
            .upsert_identity(owner.to_owned(), owner.to_owned(), self.clock.now_ms())?;
        self.store.settle_interrupted_deliveries(owner.to_owned())?;
        self.store.resolve_gaps_unavailable(owner.to_owned(), None)
    }

    /// Steps 4 to 7 of `start`.
    pub(super) async fn bootstrap(self: &Rc<Self>, owner: &str) {
        self.ensure_builtin_channels(owner);
        // A channel checkpoint means something only once its key is held,
        // so channels are registered before chat is restored.
        self.refresh_channels().await;
        self.ensure_public_conversation(owner);
        self.prepare_chat(owner).await;
        self.reinstall_manual_paths(owner).await;
        self.push_settings().await;
    }

    /// Make sure `Public` and `EMERGENCY` exist. Both start joined with
    /// notifications off; leaving one clears its flags but keeps its row.
    fn ensure_builtin_channels(&self, owner: &str) {
        for name in BUILTIN_CHANNELS {
            let Ok(preview) = crate::inspect_channel_name(name.to_owned()) else {
                continue;
            };
            let digest = crate::channel_key_digest(preview.key.clone());
            match self.store.channel(owner.to_owned(), digest.clone()) {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(error) => {
                    log::warn!(error:? = error; "a built-in channel could not be looked up");
                    continue;
                }
            }
            let id = random_uuid();
            let now_ms = self.clock.now_ms();
            if let Err(error) = self.vault.store(id.clone(), preview.key.clone()) {
                log::warn!(error:? = error; "a built-in channel's key could not be stored");
                continue;
            }
            let inserted = self.store.insert_channel(
                MobileStoredChannelRecord {
                    id: id.clone(),
                    owner_identity_id: owner.to_owned(),
                    kind: MobileStoredChannelKind::Builtin,
                    canonical_name: preview.canonical_name,
                    name: preview.display_name,
                    alias: None,
                    channel_id_hex: crate::mobile_chat::hex(&preview.channel_id),
                    tint: preview.tint,
                    region_code: None,
                    max_flood_hops: None,
                    joined_phone: true,
                    joined_device: false,
                    notifications_enabled: false,
                    joined_at_ms: Some(now_ms),
                },
                digest,
                now_ms,
            );
            if let Err(error) = inserted {
                log::warn!(error:? = error; "a built-in channel could not be stored");
                let _ = self.vault.delete(id);
            }
        }
    }

    /// The public channel is where an off-grid conversation starts, so its
    /// chat is always there to open. Other channels wait to be asked.
    /// Whether it opened one that was not open.
    pub(super) fn ensure_public_conversation(&self, owner: &str) -> bool {
        let Ok(channels) = self.store.channels(owner.to_owned()) else {
            return false;
        };
        let Some(public) = channels
            .into_iter()
            .find(|channel| channel.joined_phone && is_public(channel))
        else {
            return false;
        };
        let address = self.channels.borrow().conversation_address(&public.id);
        let Some(address) = address else {
            return false;
        };
        match self.store.open_joined_channel_conversation(
            owner,
            &public.id,
            &address,
            self.clock.now_ms(),
        ) {
            Ok(opened) => opened == Some(true),
            Err(error) => {
                log::warn!(error:? = error; "the public conversation could not be opened");
                false
            }
        }
    }

    /// Hand the session the chat store, the peers its conversations name,
    /// and where each conversation's numbering stood.
    async fn prepare_chat(&self, owner: &str) {
        let Some(session) = self.session() else {
            return;
        };
        // The store first, so arrivals are kept whatever follows.
        if let Err(error) = session.clone().attach_chat_store(
            self.store.clone(),
            owner.to_owned(),
            self.silent_tests_address(),
        ) {
            log::error!(error:? = error; "the chat store could not be attached");
            return;
        }
        self.silent_tests_pushed();

        let checkpoints = match self.store.chat_checkpoints(owner.to_owned()) {
            Ok(checkpoints) => checkpoints,
            Err(error) => {
                log::error!(error:? = error; "chat checkpoints could not be read");
                return;
            }
        };
        let nodes = self.store.list_nodes(owner.to_owned()).unwrap_or_default();
        // Not every stored peer: the transient tier could overflow the
        // session's table. Those with a conversation, or a checkpoint.
        let mut addresses: BTreeSet<String> = self
            .store
            .list_direct_conversations(owner.to_owned())
            .unwrap_or_default()
            .into_iter()
            .map(|conversation| conversation.node.public_address)
            .collect();
        addresses.extend(
            checkpoints
                .iter()
                .map(|checkpoint| checkpoint.conversation_address.clone())
                .filter(|address| !address.starts_with(CHANNEL_ADDRESS_PREFIX)),
        );
        let peers = addresses
            .into_iter()
            .filter(|address| {
                // One address that does not decode would fail them all.
                let decodes = crate::public_identity_bytes(address.clone()).is_ok();
                if !decodes {
                    log::warn!(
                        "a conversation's address does not decode; its peer is not registered"
                    );
                }
                decodes
            })
            .map(|address| {
                let mobile = nodes
                    .iter()
                    .find(|node| node.public_address == address)
                    .is_some_and(advertises_mobile);
                MobilePeerRegistrationRecord { address, mobile }
            })
            .collect();
        if let Err(error) = session.register_peers(peers).await {
            log::error!(error:? = error; "chat peers could not be registered");
            return;
        }
        if let Err(error) = session.restore_chat(checkpoints).await {
            log::error!(error:? = error; "chat could not be restored");
        }
    }

    /// Hold again every manual path whose hold has not ended.
    async fn reinstall_manual_paths(&self, owner: &str) {
        let Some(session) = self.session() else {
            return;
        };
        let now_ms = self.clock.now_ms();
        let routes = match self.store.manual_routes(owner.to_owned(), now_ms) {
            Ok(routes) => routes,
            Err(error) => {
                log::warn!(error:? = error; "manual paths could not be read");
                return;
            }
        };
        for route in routes {
            let Ok(remaining) = u64::try_from(route.hold_until_ms - now_ms) else {
                continue;
            };
            if remaining == 0 {
                continue;
            }
            let held = session
                .hold_peer_route(
                    route.public_address,
                    MobileMeshExplicitPath {
                        hints: route.hints,
                        flood_hops: route.flood_hops,
                    },
                    remaining,
                )
                .await;
            if let Err(error) = held {
                log::warn!(error:? = error; "a manual path could not be held again");
            }
        }
    }
}

/// Whether `channel` is the public channel.
pub(super) fn is_public(channel: &MobileStoredChannelRecord) -> bool {
    crate::well_known_channel(channel.canonical_name.clone())
        .is_some_and(|known| known.channel == crate::MobileWellKnownChannel::Public)
}

/// Whether a peer's stored advertisement says it is mobile. Only an
/// advertisement that can be attributed to the peer counts: a valid
/// signature, or an unsigned one that arrived authenticated.
pub(super) fn advertises_mobile(node: &MobileStoredNodeRecord) -> bool {
    let Some(advertisement) = &node.advertisement else {
        return false;
    };
    let Ok(identity) =
        crate::decode_node_identity(node.public_address.clone(), advertisement.clone())
    else {
        return false;
    };
    super::mapping::attributable(identity.signature, node.advertisement_authenticated)
        && identity.capability_bits & umsh_node::NodeCapabilities::MOBILE.bits() != 0
}

/// A random version 4 UUID, uppercase, as the vault's accounts are named.
pub(super) fn random_uuid() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = crate::mobile_chat::hex(&bytes).to_uppercase();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
