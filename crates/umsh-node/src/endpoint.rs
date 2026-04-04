use alloc::{string::String, vec::Vec};

use umsh_app::{identity_payload, mac_command, parse_payload, text_message, PayloadRef, PayloadType};
use umsh_core::{ChannelId, MicSize, PacketType, PublicKey};
use umsh_mac::{LocalIdentityId, MacEventRef, SendOptions, SendReceipt};

use crate::{
    error::EndpointError,
    mac::NodeMac,
    owned::{DeferredAction, EndpointEvent, EventAction, OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage},
};

#[cfg(feature = "software-crypto")]
use crate::pfs::PfsSessionManager;

/// Synchronous application-level filtering applied during `handle_event`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiAcceptancePolicy {
    /// Whether direct text messages should be surfaced.
    pub allow_direct_text: bool,
    /// Whether channel text messages should be surfaced.
    pub allow_channel_text: bool,
    /// Whether node-identity payloads should be surfaced.
    pub allow_node_identity: bool,
    /// Whether MAC commands should be surfaced or deferred.
    pub allow_mac_commands: bool,
}

impl Default for UiAcceptancePolicy {
    fn default() -> Self {
        Self {
            allow_direct_text: true,
            allow_channel_text: true,
            allow_node_identity: true,
            allow_mac_commands: true,
        }
    }
}

/// Endpoint configuration used by high-level send helpers and scheduled beacons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointConfig {
    /// Default MIC size for high-level send helpers.
    pub default_mic_size: MicSize,
    /// Whether high-level send helpers should request encryption by default.
    pub default_encrypted: bool,
    /// Default flood-hop budget for high-level send helpers.
    pub default_flood_hops: u8,
    /// Optional periodic beacon interval.
    pub beacon_interval_ms: Option<u64>,
    /// Synchronous UI-acceptance policy.
    pub ui_acceptance: UiAcceptancePolicy,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            default_mic_size: MicSize::Mic16,
            default_encrypted: true,
            default_flood_hops: 5,
            beacon_interval_ms: None,
            ui_acceptance: UiAcceptancePolicy::default(),
        }
    }
}

/// Application-facing endpoint built on top of a cloneable MAC handle.
pub struct Endpoint<M: NodeMac, KV = ()> {
    id: LocalIdentityId,
    mac: M,
    config: EndpointConfig,
    kv_store: Option<KV>,
    advertised_identity: Option<OwnedNodeIdentityPayload>,
    next_beacon_ms: Option<u64>,
    #[cfg(feature = "software-crypto")]
    pfs: PfsSessionManager,
}

impl<M: NodeMac> Endpoint<M, ()> {
    /// Create a new endpoint without attached persistent storage.
    pub fn new(id: LocalIdentityId, mac: M, config: EndpointConfig) -> Self {
        let next_beacon_ms = config.beacon_interval_ms;
        Self {
            id,
            mac,
            config,
            kv_store: None,
            advertised_identity: None,
            next_beacon_ms,
            #[cfg(feature = "software-crypto")]
            pfs: PfsSessionManager::default(),
        }
    }
}

impl<M: NodeMac, KV> Endpoint<M, KV> {
    /// Attach an application-owned key-value store handle.
    ///
    /// The endpoint currently retains this handle for caller-managed state and
    /// future persistence hooks; the built-in event/send logic does not read or
    /// write it yet.
    pub fn with_kv_store<KV2>(self, kv_store: KV2) -> Endpoint<M, KV2> {
        Endpoint {
            id: self.id,
            mac: self.mac,
            config: self.config,
            kv_store: Some(kv_store),
            advertised_identity: self.advertised_identity,
            next_beacon_ms: self.next_beacon_ms,
            #[cfg(feature = "software-crypto")]
            pfs: self.pfs,
        }
    }

    /// Borrow the attached key-value store handle, if one is present.
    pub fn kv_store(&self) -> Option<&KV> {
        self.kv_store.as_ref()
    }

    /// Mutably borrow the attached key-value store handle, if one is present.
    pub fn kv_store_mut(&mut self) -> Option<&mut KV> {
        self.kv_store.as_mut()
    }

    /// Configure the node-identity payload that identity beacons will advertise.
    pub fn with_advertised_identity(mut self, identity: OwnedNodeIdentityPayload) -> Self {
        self.advertised_identity = Some(identity);
        self
    }

    /// Return the local identity identifier used by this endpoint.
    pub fn id(&self) -> LocalIdentityId {
        self.id
    }

    /// Add or refresh a named channel.
    pub fn add_named_channel(&self, name: &str) -> Result<(), EndpointError<M>> {
        self.mac.add_named_channel(name).map_err(Into::into)
    }

    /// Add or refresh a private channel by raw key.
    pub fn add_private_channel(&self, key: umsh_core::ChannelKey) -> Result<(), EndpointError<M>> {
        self.mac.add_private_channel(key).map_err(Into::into)
    }

    /// Add or refresh a peer.
    pub fn add_peer(&self, key: PublicKey) -> Result<umsh_mac::PeerId, EndpointError<M>> {
        self.mac.add_peer(key).map_err(Into::into)
    }

    /// Install pairwise transport keys for a peer.
    pub fn install_pairwise_keys(
        &self,
        peer_id: umsh_mac::PeerId,
        pairwise_keys: umsh_crypto::PairwiseKeys,
    ) -> Result<Option<umsh_mac::PeerCryptoState>, EndpointError<M>> {
        self.mac.install_pairwise_keys(self.id, peer_id, pairwise_keys).map_err(Into::into)
    }

    /// Encode and queue a direct text message.
    pub fn send_text(&self, to: &PublicKey, text: &str) -> Result<Option<SendReceipt>, EndpointError<M>> {
        #[cfg(feature = "software-crypto")]
        let (from_id, routed_to) = self.active_unicast_route(to)?;
        #[cfg(not(feature = "software-crypto"))]
        let (from_id, routed_to) = (self.id, *to);
        let payload = Self::encode_basic_text_payload(text)?;
        self.mac.send_unicast(from_id, &routed_to, &payload, &self.default_send_options().with_ack_requested(true)).map_err(Into::into)
    }

    /// Encode and queue a channel text message.
    pub fn send_channel_text(&self, channel: &ChannelId, text: &str) -> Result<(), EndpointError<M>> {
        let payload = Self::encode_basic_text_payload(text)?;
        self.mac.send_multicast(self.id, channel, &payload, &self.default_send_options()).map_err(Into::into)
    }

    /// Encode and queue a blind-unicast text message.
    pub fn send_blind_text(
        &self,
        to: &PublicKey,
        channel: &ChannelId,
        text: &str,
    ) -> Result<Option<SendReceipt>, EndpointError<M>> {
        #[cfg(feature = "software-crypto")]
        let (from_id, routed_to) = self.active_unicast_route(to)?;
        #[cfg(not(feature = "software-crypto"))]
        let (from_id, routed_to) = (self.id, *to);
        let payload = Self::encode_basic_text_payload(text)?;
        self.mac.send_blind_unicast(from_id, &routed_to, channel, &payload, &self.default_send_options().with_ack_requested(true)).map_err(Into::into)
    }

    /// Queue an empty broadcast beacon.
    pub fn send_beacon(&self) -> Result<(), EndpointError<M>> {
        let options = SendOptions::default()
            .with_mic_size(self.config.default_mic_size)
            .with_flood_hops(self.config.default_flood_hops)
            .unencrypted();
        self.mac.send_broadcast(self.id, &[], &options).map_err(Into::into)
    }

    /// Queue the configured node-identity beacon.
    pub fn send_identity_beacon(&self) -> Result<(), EndpointError<M>> {
        let identity = self.advertised_identity.as_ref().ok_or(EndpointError::MissingAdvertisedIdentity)?;
        let mut body = [0u8; 512];
        let len = identity_payload::encode(&identity.as_borrowed(), &mut body)?;
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(PayloadType::NodeIdentity as u8);
        payload.extend_from_slice(&body[..len]);
        let options = SendOptions::default()
            .with_mic_size(self.config.default_mic_size)
            .with_flood_hops(self.config.default_flood_hops)
            .unencrypted();
        self.mac.send_broadcast(self.id, &payload, &options).map_err(Into::into)
    }

    /// Send a beacon-request MAC command with trace routing enabled.
    pub fn request_path_discovery(&self, to: &PublicKey) -> Result<Option<SendReceipt>, EndpointError<M>> {
        let command = umsh_app::MacCommand::BeaconRequest { nonce: None };
        let mut body = [0u8; 64];
        let len = mac_command::encode(&command, &mut body)?;
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(PayloadType::MacCommand as u8);
        payload.extend_from_slice(&body[..len]);
        let options = self.default_send_options().with_trace_route().with_ack_requested(true).no_flood();
        self.mac.send_unicast(self.id, to, &payload, &options).map_err(Into::into)
    }

    #[cfg(feature = "software-crypto")]
    /// Begin a PFS session with `peer`.
    pub fn request_pfs_session(&mut self, peer: &PublicKey, duration_minutes: u16) -> Result<Option<SendReceipt>, EndpointError<M>> {
        let options = self.default_send_options().with_ack_requested(true);
        self.pfs.request_session(&self.mac, self.id, peer, duration_minutes, &options)
    }

    #[cfg(feature = "software-crypto")]
    /// End the active PFS session with `peer`.
    pub fn end_pfs_session(&mut self, peer: &PublicKey) -> Result<bool, EndpointError<M>> {
        let options = self.default_send_options();
        self.pfs.end_session(&self.mac, self.id, peer, true, &options)
    }

    #[cfg(feature = "software-crypto")]
    /// Expire any stale PFS sessions.
    pub fn expire_pfs_sessions(&mut self) -> Result<Vec<PublicKey>, EndpointError<M>> {
        let now_ms = self.mac.now_ms()?;
        self.pfs.expire_sessions(&self.mac, now_ms)
    }

    /// Return whether the periodic beacon is due at `now_ms`.
    pub fn beacon_due(&self, now_ms: u64) -> bool {
        self.next_beacon_ms.map(|deadline| now_ms >= deadline).unwrap_or(false)
    }

    /// Send the scheduled beacon if due, returning whether one was sent.
    pub fn send_scheduled_beacon(&mut self, now_ms: u64) -> Result<bool, EndpointError<M>> {
        if !self.beacon_due(now_ms) {
            return Ok(false);
        }
        self.send_beacon()?;
        self.next_beacon_ms = self.config.beacon_interval_ms.map(|interval| now_ms.saturating_add(interval));
        Ok(true)
    }

    /// Perform the synchronous phase of event handling.
    pub fn handle_event(&mut self, event: MacEventRef<'_>) -> EventAction {
        match self.try_handle_event(event) {
            Ok(action) => action,
            Err(_) => EventAction::Handled(None),
        }
    }

    /// Perform deferred follow-up work returned by [`handle_event`](Self::handle_event).
    ///
    /// This convenience wrapper preserves the existing behavior of suppressing
    /// deferred-processing errors. Use [`try_handle_deferred`](Self::try_handle_deferred)
    /// when the caller needs visibility into PFS or MAC-handle failures.
    pub async fn handle_deferred(&mut self, deferred: DeferredAction) -> Option<EndpointEvent> {
        self.try_handle_deferred(deferred).await.ok().flatten()
    }

    /// Perform deferred follow-up work and return any processing error.
    pub async fn try_handle_deferred(
        &mut self,
        deferred: DeferredAction,
    ) -> Result<Option<EndpointEvent>, EndpointError<M>> {
        match deferred {
            DeferredAction::MacCommand { from, command } => self.try_handle_deferred_mac_command(from, command),
        }
    }

    fn try_handle_event(&mut self, event: MacEventRef<'_>) -> Result<EventAction, EndpointError<M>> {
        match event {
            MacEventRef::Unicast { from, payload, .. } => self.handle_payload(from, None, PacketType::Unicast, payload),
            MacEventRef::Multicast { from, channel_id, payload } => self.handle_payload(from, Some(channel_id), PacketType::Multicast, payload),
            MacEventRef::BlindUnicast { from, channel_id, payload, .. } => {
                self.handle_payload(from, Some(channel_id), PacketType::BlindUnicast, payload)
            }
            MacEventRef::Broadcast { from_hint, from_key, payload } => {
                if payload.is_empty() {
                    return Ok(EventAction::Handled(Some(EndpointEvent::BeaconReceived { from_hint, from_key })));
                }
                match from_key {
                    Some(from) => self.handle_payload(from, None, PacketType::Broadcast, payload),
                    None => Ok(EventAction::Handled(Some(EndpointEvent::BeaconReceived { from_hint, from_key }))),
                }
            }
            MacEventRef::AckReceived { peer, receipt } => Ok(EventAction::Handled(Some(EndpointEvent::AckReceived { peer, receipt }))),
            MacEventRef::AckTimeout { peer, receipt } => Ok(EventAction::Handled(Some(EndpointEvent::AckTimeout { peer, receipt }))),
        }
    }

    fn handle_payload(
        &mut self,
        from: PublicKey,
        channel_id: Option<ChannelId>,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<EventAction, EndpointError<M>> {
        match parse_payload(packet_type, payload)? {
            PayloadRef::TextMessage(message) => {
                if !self.config.ui_acceptance.allow_direct_text && channel_id.is_none() {
                    return Ok(EventAction::Handled(None));
                }
                if !self.config.ui_acceptance.allow_channel_text && channel_id.is_some() {
                    return Ok(EventAction::Handled(None));
                }
                let owned = OwnedTextMessage::try_from(message).map_err(|_| EndpointError::UnsupportedPayload)?;
                Ok(EventAction::Handled(Some(match channel_id {
                    Some(channel_id) => EndpointEvent::ChannelTextReceived { from, channel_id, message: owned },
                    None => EndpointEvent::TextReceived { from, message: owned },
                })))
            }
            PayloadRef::NodeIdentity(identity) => {
                if !self.config.ui_acceptance.allow_node_identity {
                    return Ok(EventAction::Handled(None));
                }
                let owned = OwnedNodeIdentityPayload::try_from(identity).map_err(|_| EndpointError::UnsupportedPayload)?;
                Ok(EventAction::Handled(Some(EndpointEvent::NodeDiscovered { key: from, identity: owned })))
            }
            PayloadRef::MacCommand(command) => {
                if !self.config.ui_acceptance.allow_mac_commands {
                    return Ok(EventAction::Handled(None));
                }
                let owned = OwnedMacCommand::from(command);
                if matches!(owned, OwnedMacCommand::PfsSessionRequest { .. } | OwnedMacCommand::PfsSessionResponse { .. } | OwnedMacCommand::EndPfsSession) {
                    Ok(EventAction::NeedsAsync(DeferredAction::MacCommand { from, command: owned }))
                } else {
                    Ok(EventAction::Handled(Some(EndpointEvent::MacCommand { from, command: owned })))
                }
            }
            _ => Ok(EventAction::Handled(None)),
        }
    }

    fn default_send_options(&self) -> SendOptions {
        let mut options = SendOptions::default().with_mic_size(self.config.default_mic_size);
        options = options.with_flood_hops(self.config.default_flood_hops);
        if !self.config.default_encrypted {
            options = options.unencrypted();
        }
        options
    }

    fn encode_basic_text_payload(text: &str) -> Result<Vec<u8>, EndpointError<M>> {
        let message = OwnedTextMessage {
            message_type: umsh_app::MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            body: String::from(text),
        };
        let mut body = [0u8; 512];
        let len = text_message::encode(&message.as_borrowed(), &mut body)?;
        let mut payload = Vec::with_capacity(len + 1);
        payload.push(PayloadType::TextMessage as u8);
        payload.extend_from_slice(&body[..len]);
        Ok(payload)
    }

    #[cfg(feature = "software-crypto")]
    fn active_unicast_route(&self, peer: &PublicKey) -> Result<(LocalIdentityId, PublicKey), EndpointError<M>> {
        let now_ms = self.mac.now_ms()?;
        Ok(self.pfs.active_route(peer, now_ms).unwrap_or((self.id, *peer)))
    }

    #[cfg(feature = "software-crypto")]
    fn try_handle_deferred_mac_command(
        &mut self,
        from: PublicKey,
        command: OwnedMacCommand,
    ) -> Result<Option<EndpointEvent>, EndpointError<M>> {
        match command {
            OwnedMacCommand::PfsSessionRequest { ephemeral_key, duration_minutes } => {
                let options = self.default_send_options().with_ack_requested(true);
                self.pfs.accept_request(&self.mac, self.id, from, ephemeral_key, duration_minutes, &options)?;
                Ok(Some(EndpointEvent::PfsSessionEstablished { peer: from }))
            }
            OwnedMacCommand::PfsSessionResponse { ephemeral_key, duration_minutes } => {
                let activated = self
                    .pfs
                    .accept_response(&self.mac, self.id, from, ephemeral_key, duration_minutes)?;
                Ok(activated.then_some(EndpointEvent::PfsSessionEstablished { peer: from }))
            }
            OwnedMacCommand::EndPfsSession => {
                let options = self.default_send_options();
                let ended = self.pfs.end_session(&self.mac, self.id, &from, false, &options)?;
                Ok(ended.then_some(EndpointEvent::PfsSessionEnded { peer: from }))
            }
            other => Ok(Some(EndpointEvent::MacCommand { from, command: other })),
        }
    }

    #[cfg(not(feature = "software-crypto"))]
    fn try_handle_deferred_mac_command(
        &mut self,
        from: PublicKey,
        command: OwnedMacCommand,
    ) -> Result<Option<EndpointEvent>, EndpointError<M>> {
        Ok(Some(EndpointEvent::MacCommand { from, command }))
    }
}