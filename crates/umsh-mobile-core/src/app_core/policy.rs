//! The radio policy: what the core keeps in step with the attached radio.
//!
//! Radio state is handled the moment it arrives (claim bookkeeping, the
//! per-session flags); everything that talks to the radio runs in the
//! pass, one task with a dirty flag. A trigger that arrives while the pass
//! runs makes it run again once it ends, so the pass is the one writer of
//! every gate it keeps, and nothing waits for it.
//!
//! "A session with the radio" is the radio attached, or being configured,
//! with this phone as its host. Configuring does not end it: the once per
//! session work (revocation, the drain) is not repeated by a configuration
//! change. A cache advances only on success; a failure is logged and the
//! step runs again on the next trigger.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::records::{MobileAppChangesRecord, MobileAppLifecycle};
use super::worker::Worker;
use crate::mobile_mesh::MobileMeshPropertyWriteRecord;
use crate::radio_driver::{MobileRadioError, MobileRadioPhase, MobileRadioStateRecord};
use crate::secret_vault::SecretVaultError;
use crate::store::MobileStoredChannelKind;
use crate::ulcp::{UlcpHostOwnership, UlcpSyncRecord};

/// How often an attached radio's claim is written again.
const CLAIM_REWRITE_MS: i64 = 10 * 60 * 1000;
/// The longest the core waits for a remote operation's report before
/// giving up on it, should the session have dropped it.
pub(super) const MANAGEMENT_BACKSTOP_MS: i64 = 5 * 60 * 1000;

/// The radio's muted channels and muted peers, as last written.
type MuteLists = (Vec<Vec<u8>>, Vec<Vec<u8>>);

#[derive(Debug, Default)]
pub(super) struct PolicyState {
    /// Something the pass reads changed since it last ran.
    dirty: bool,
    /// Counts sessions with the radio, begun and ended. A pass that finds
    /// it moved across an await abandons what it was doing.
    generation: u64,
    /// The destinations the session's forward-secret addresses need.
    destination_hints: Vec<Vec<u8>>,
    // Once per session with the radio.
    revoked: bool,
    drained: bool,
    // What the radio, or the store, was last brought to.
    radio_peer: Option<RadioPeer>,
    device_peers: Option<Vec<String>>,
    host_channels: Option<Vec<String>>,
    /// The table waits for the vault to unlock.
    host_channels_locked: bool,
    host_peers: Option<Vec<String>>,
    auto_ack: bool,
    mutes: Option<MuteLists>,
    test_alerts: Option<bool>,
    /// The test-alert value written live whose save did not land.
    test_alerts_unsaved: Option<bool>,
    destinations: Option<Vec<Vec<u8>>>,
    // Claims.
    claim_recorded_at: HashMap<String, i64>,
    /// Radios that confirmed releasing this phone, until attached again.
    released: HashSet<String>,
    revoking: bool,
    revoke_again: bool,
    /// The dropped-frame count each radio last reported, kept across
    /// detaches so a rise while away is seen.
    dropped_frames: HashMap<String, u32>,
}

/// The four facts the radio's peer row keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RadioPeer {
    owner: String,
    address: String,
    name: Option<String>,
    link_id: String,
}

/// Whether `state` is in a session with the radio as this phone's.
fn in_session(state: Option<&MobileRadioStateRecord>) -> bool {
    state.is_some_and(|state| {
        matches!(
            state.phase,
            MobileRadioPhase::Attached | MobileRadioPhase::Configuring
        ) && state.host == UlcpHostOwnership::Ours
            && state.device_key.is_some()
    })
}

/// Whether `state` is attached at all, to anyone.
fn attached(state: Option<&MobileRadioStateRecord>) -> bool {
    state.is_some_and(|state| {
        matches!(
            state.phase,
            MobileRadioPhase::Attached | MobileRadioPhase::Configuring
        )
    })
}

/// The radio's address, when it has a device identity.
pub(super) fn device_address(state: &MobileRadioStateRecord) -> Option<String> {
    let key = state.device_key.clone()?;
    crate::inspect_public_identity_bytes(key)
        .ok()
        .map(|identity| identity.canonical_address)
}

/// What a pass works from: the radio as it is now, when it carries this
/// phone and can be talked to.
struct Radio {
    driver: std::sync::Arc<crate::radio_driver::MobileRadioDriver>,
    sync: UlcpSyncRecord,
    /// The session with the radio the pass began in. A gate is written
    /// only while it lasts, so a step that finishes after a detach does
    /// not mark the next session's radio done.
    generation: u64,
}

impl Worker {
    /// Something the pass reads may have changed: run it, or run it again.
    pub(super) fn policy_triggered(&self) {
        self.policy.borrow_mut().dirty = true;
        self.policy_wake.notify_one();
    }

    /// The radio's state changed.
    pub(super) fn radio_policy_changed(&self) {
        self.policy_triggered();
    }

    /// Forget every gate and per-session flag: the identity's session or
    /// the radio changed.
    pub(super) fn reset_policy(&self) {
        let mut policy = self.policy.borrow_mut();
        let generation = policy.generation + 1;
        let revoking = policy.revoking;
        *policy = PolicyState {
            dirty: true,
            generation,
            revoking,
            ..PolicyState::default()
        };
        drop(policy);
        self.policy_wake.notify_one();
    }

    /// The radio moved from `previous` to `state`: the bookkeeping that
    /// cannot wait for the pass.
    pub(super) fn radio_transition(
        &self,
        previous: Option<&MobileRadioStateRecord>,
        state: Option<&MobileRadioStateRecord>,
    ) {
        if let Some(state) = state {
            self.note_dropped_frames(state);
        }
        let address = state.and_then(device_address);
        // A fresh attach to a radio forgets that it released this phone.
        if !attached(previous)
            && attached(state)
            && let Some(address) = &address
        {
            let mut policy = self.policy.borrow_mut();
            policy.released.remove(address);
            policy.claim_recorded_at.remove(address);
        }
        let was = in_session(previous);
        let is = in_session(state);
        if was == is {
            return;
        }
        {
            let mut policy = self.policy.borrow_mut();
            let PolicyState {
                generation,
                destination_hints,
                claim_recorded_at,
                released,
                revoking,
                revoke_again,
                dropped_frames,
                ..
            } = std::mem::take(&mut *policy);
            *policy = PolicyState {
                dirty: true,
                generation: generation + 1,
                destination_hints,
                claim_recorded_at,
                released,
                revoking,
                revoke_again,
                dropped_frames,
                ..PolicyState::default()
            };
        }
        // The radio's own lease starts at the detach, so the record's age
        // does too.
        if was
            && !is
            && let Some(previous) = previous
        {
            self.record_claim(previous, true);
        }
    }

    /// The radio confirmed it let this phone go.
    pub(super) fn host_released(&self, device_key: &[u8]) {
        let Ok(identity) = crate::inspect_public_identity_bytes(device_key.to_vec()) else {
            return;
        };
        let address = identity.canonical_address;
        self.policy.borrow_mut().released.insert(address.clone());
        self.forget_claim(&address);
    }

    /// The destinations the radio's filter should pass.
    pub(super) fn set_destination_hints(&self, hints: Vec<Vec<u8>>) {
        self.policy.borrow_mut().destination_hints = hints;
        self.policy_triggered();
    }

    /// The pass task, for the worker's whole life.
    pub(super) async fn run_policy(self: Rc<Self>) {
        loop {
            self.policy_wake.notified().await;
            while std::mem::take(&mut self.policy.borrow_mut().dirty) {
                self.policy_pass().await;
            }
        }
    }

    async fn policy_pass(self: &Rc<Self>) {
        if self.lifecycle() != MobileAppLifecycle::Running {
            return;
        }
        // Every channel write the cache derives from is the core's own,
        // made by a command that refreshes before it resolves or by a
        // rollback that marks the cache incomplete, so only an incomplete
        // cache is refreshed here.
        let incomplete = self.channels.borrow().incomplete;
        if incomplete {
            self.refresh_channels().await;
        }
        let state = self.shared.snapshot().radio.clone();
        let generation = self.policy.borrow().generation;
        self.radio_peer(state.as_ref());
        let Some(radio) = self.radio(state.as_ref(), generation) else {
            return;
        };
        // In order: the tables first, so the drain replays into them.
        if !self.stepped(self.host_channels(&radio).await, &radio, generation)
            || !self.stepped(self.host_peers(&radio).await, &radio, generation)
            || !self.stepped(self.auto_ack(&radio).await, &radio, generation)
            || !self.stepped(self.host_mutes(&radio).await, &radio, generation)
            || !self.stepped(self.test_alerts(&radio).await, &radio, generation)
            || !self.stepped(self.destinations(&radio).await, &radio, generation)
        {
            return;
        }
        self.stepped(self.drain(&radio).await, &radio, generation);
    }

    /// Log a failed step; answer whether the pass goes on. A detach, a
    /// new session, or a driver gone abandons the rest.
    fn stepped(
        self: &Rc<Self>,
        result: Result<(), MobileRadioError>,
        radio: &Radio,
        generation: u64,
    ) -> bool {
        if let Err(error) = result {
            if error == MobileRadioError::Stopped {
                self.lose_driver(&radio.driver);
                return false;
            }
            log::warn!(error:? = error; "a radio policy step failed");
        }
        self.policy.borrow().generation == generation
            && self.lifecycle() == MobileAppLifecycle::Running
    }

    /// The radio, when it is attached as this phone's and has been read.
    fn radio(&self, state: Option<&MobileRadioStateRecord>, generation: u64) -> Option<Radio> {
        let state = state?;
        if state.phase != MobileRadioPhase::Attached || state.host != UlcpHostOwnership::Ours {
            return None;
        }
        Some(Radio {
            driver: self.driver()?,
            sync: state.provisioning.clone()?,
            generation,
        })
    }

    /// Write what a step brought the radio to, while the session with it
    /// that the step ran in lasts.
    fn settle(&self, radio: &Radio, update: impl FnOnce(&mut PolicyState)) {
        let mut policy = self.policy.borrow_mut();
        if policy.generation == radio.generation {
            update(&mut policy);
        }
    }

    /// The radio's own peer row, its claim, and the peers its device
    /// identity holds.
    fn radio_peer(self: &Rc<Self>, state: Option<&MobileRadioStateRecord>) {
        let owner = self.owner();
        let gated = state
            .filter(|state| in_session(Some(state)))
            .and_then(|state| {
                Some((
                    state,
                    device_address(state)?,
                    state.link_id.clone()?,
                    owner.clone()?,
                ))
            });
        let Some((state, address, link_id, owner)) = gated else {
            {
                let mut policy = self.policy.borrow_mut();
                policy.radio_peer = None;
                policy.device_peers = None;
            }
            if let Some(state) = state {
                self.forget_claim_if_held_elsewhere(state);
            }
            return;
        };
        self.record_claim(state, false);
        self.revoke_once();

        if let Some(keys) = state
            .provisioning
            .as_ref()
            .and_then(|sync| sync.dev_peer_keys.clone())
        {
            let addresses: Vec<String> = keys
                .into_iter()
                .filter_map(|key| crate::inspect_public_identity_bytes(key).ok())
                .map(|identity| identity.canonical_address)
                .collect();
            if self.policy.borrow().device_peers.as_ref() != Some(&addresses) {
                match self
                    .store
                    .reconcile_device_identity_peers(owner.clone(), addresses.clone())
                {
                    Ok(()) => {
                        self.policy.borrow_mut().device_peers = Some(addresses);
                        self.raise(MobileAppChangesRecord {
                            peers_changed: true,
                            ..MobileAppChangesRecord::default()
                        });
                    }
                    Err(error) => {
                        log::warn!(error:? = error; "the device identity's peers were not kept");
                    }
                }
            }
        }

        let record = RadioPeer {
            owner: owner.clone(),
            address: address.clone(),
            name: state.name.clone(),
            link_id: link_id.clone(),
        };
        if self.policy.borrow().radio_peer.as_ref() == Some(&record) {
            return;
        }
        match self
            .store
            .upsert_ulcp_device_peer(owner, address, state.name.clone(), link_id)
        {
            Ok(()) => {
                self.policy.borrow_mut().radio_peer = Some(record);
                self.raise(MobileAppChangesRecord {
                    peers_changed: true,
                    ..MobileAppChangesRecord::default()
                });
            }
            Err(error) => log::warn!(error:? = error; "the radio's peer row was not kept"),
        }
    }

    /// The radio's host channel table: every phone-joined channel, built-in
    /// ones first, then the most recently joined. A key that will not load
    /// fails the step rather than shedding the channel from the radio.
    async fn host_channels(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if radio.sync.host_channel_count.is_none() && radio.sync.filter_count.is_none() {
            return Ok(());
        }
        let Some(owner) = self.owner() else {
            return Ok(());
        };
        let Ok(mut rows) = self.store.channels(owner) else {
            return Ok(());
        };
        rows.retain(|row| row.joined_phone);
        rows.sort_by_key(|row| {
            (
                row.kind != MobileStoredChannelKind::Builtin,
                std::cmp::Reverse(row.joined_at_ms.unwrap_or(i64::MIN)),
            )
        });
        let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
        if self.policy.borrow().host_channels.as_ref() == Some(&ids) {
            return Ok(());
        }
        self.policy.borrow_mut().host_channels_locked = false;
        let mut keys = Vec::with_capacity(ids.len());
        for id in &ids {
            match self.vault.load(id.clone()) {
                Ok(Some(key)) => keys.push(key),
                // Gone for good; nothing to send.
                Ok(None) => {}
                // The drain waits for the channels too (see `drain`).
                Err(SecretVaultError::Unavailable) => {
                    log::info!("the vault is locked; the radio's channels wait");
                    self.settle(radio, |policy| policy.host_channels_locked = true);
                    return Ok(());
                }
                Err(error) => {
                    log::warn!(error:? = error; "a channel's key would not load");
                    return Ok(());
                }
            }
        }
        radio.driver.reconcile_host_channel_keys(keys).await?;
        self.settle(radio, |policy| policy.host_channels = Some(ids));
        Ok(())
    }

    /// The direct conversations' addresses, most recent first.
    fn recent_conversations(&self, muted_only: bool) -> Vec<(String, bool)> {
        let Some(owner) = self.owner() else {
            return Vec::new();
        };
        let mut conversations = self
            .store
            .list_direct_conversations(owner)
            .unwrap_or_default();
        conversations.sort_by_key(|conversation| {
            std::cmp::Reverse(
                conversation
                    .last_message
                    .as_ref()
                    .map_or(conversation.created_at_ms, |message| message.created_at_ms),
            )
        });
        let known = conversations
            .iter()
            .map(|conversation| conversation.node.public_address.clone())
            .collect::<Vec<_>>();
        self.pipeline.borrow_mut().known_conversations.extend(known);
        conversations
            .into_iter()
            .filter(|conversation| !muted_only || !conversation.notifications_enabled)
            .map(|conversation| {
                (
                    conversation.node.public_address,
                    conversation.notifications_enabled,
                )
            })
            .collect()
    }

    /// The radio's host peer keys: the most recent open conversations.
    async fn host_peers(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if radio.sync.host_channel_count.is_none() {
            return Ok(());
        }
        let Some(session) = self.session() else {
            return Ok(());
        };
        let addresses: Vec<String> = self
            .recent_conversations(false)
            .into_iter()
            .map(|(address, _)| address)
            .filter(|address| crate::public_identity_bytes(address.clone()).is_ok())
            .take(usize::from(crate::ulcp::ulcp_max_host_peers()))
            .collect();
        if self.policy.borrow().host_peers.as_ref() == Some(&addresses) {
            return Ok(());
        }
        let entries = match session.host_peer_key_entries(addresses.clone()).await {
            Ok(entries) => entries,
            Err(error) => {
                log::warn!(error:? = error; "host peer keys could not be derived");
                return Ok(());
            }
        };
        radio.driver.reconcile_host_peer_keys(entries).await?;
        self.settle(radio, |policy| policy.host_peers = Some(addresses));
        Ok(())
    }

    /// Delegated acknowledgment, where the radio offers it with host keys.
    async fn auto_ack(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if radio.sync.host_channel_count.is_none()
            || !radio.sync.supports_delegated_ack
            || self.policy.borrow().auto_ack
        {
            return Ok(());
        }
        radio.driver.set_host_auto_ack(true).await?;
        self.settle(radio, |policy| policy.auto_ack = true);
        Ok(())
    }

    /// The radio's mute lists: muted channels and muted conversations, so
    /// it does not wake the phone for them.
    async fn host_mutes(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if !radio.sync.supports_offline_queue {
            return Ok(());
        }
        let Some(owner) = self.owner() else {
            return Ok(());
        };
        let Ok(mut rows) = self.store.channels(owner) else {
            return Ok(());
        };
        rows.retain(|row| row.joined_phone && !row.notifications_enabled);
        rows.sort_by_key(|row| {
            (
                row.kind != MobileStoredChannelKind::Builtin,
                std::cmp::Reverse(row.joined_at_ms.unwrap_or(i64::MIN)),
            )
        });
        let mut channels = Vec::new();
        for row in rows
            .iter()
            .take(usize::from(crate::ulcp::ulcp_max_host_muted_channels()))
        {
            let Some(identifier) = self.channels.borrow().identifier(&row.id) else {
                // Not derived yet: the next pass, once it is.
                return Ok(());
            };
            channels.push(identifier);
        }
        let peers: Vec<Vec<u8>> = self
            .recent_conversations(true)
            .into_iter()
            .filter_map(|(address, _)| crate::public_identity_bytes(address).ok())
            .take(usize::from(crate::ulcp::ulcp_max_host_muted_peers()))
            .collect();
        let lists = (channels, peers);
        if self.policy.borrow().mutes.as_ref() == Some(&lists) {
            return Ok(());
        }
        radio
            .driver
            .reconcile_host_mutes(lists.0.clone(), lists.1.clone())
            .await?;
        self.settle(radio, |policy| policy.mutes = Some(lists));
        Ok(())
    }

    /// Whether the radio alerts for test messages, as the policy says. A
    /// radio without the property is settled as it is. A write whose save
    /// failed is saved on a later pass, unless the policy moved on.
    async fn test_alerts(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if !radio.sync.supports_offline_queue {
            return Ok(());
        }
        let Some(desired) = self
            .settings
            .borrow()
            .policy
            .as_ref()
            .map(|policy| policy.test_message_alerts)
        else {
            return Ok(());
        };
        let (settled, unsaved) = {
            let policy = self.policy.borrow();
            (policy.test_alerts, policy.test_alerts_unsaved)
        };
        if settled == Some(desired) && unsaved.is_none() {
            return Ok(());
        }
        if unsaved != Some(desired) {
            let property = crate::ulcp::ulcp_managed_property_ids().test_message_alerts;
            let value = vec![u8::from(desired)];
            let held = radio.driver.fetch_properties(vec![property]).await?;
            let held = held.answers.into_iter().next();
            if held.as_ref().is_some_and(|held| held.status_code.is_some()) {
                // Older firmware without the property.
                self.settle(radio, |policy| {
                    policy.test_alerts = Some(desired);
                    policy.test_alerts_unsaved = None;
                });
                return Ok(());
            }
            if held.and_then(|held| held.value).as_ref() == Some(&value) {
                if unsaved.is_none() {
                    self.settle(radio, |policy| policy.test_alerts = Some(desired));
                    return Ok(());
                }
                // Live already, after an earlier unsaved write: only the
                // save is owed.
                self.settle(radio, |policy| policy.test_alerts_unsaved = Some(desired));
            } else {
                let written = radio
                    .driver
                    .write_properties(vec![MobileMeshPropertyWriteRecord {
                        property_id: property,
                        value,
                    }])
                    .await?;
                if written
                    .answers
                    .first()
                    .is_some_and(|answer| answer.status_code.is_some())
                {
                    log::warn!("the radio refused the test-alert setting");
                    return Ok(());
                }
                self.settle(radio, |policy| policy.test_alerts_unsaved = Some(desired));
            }
        }
        let saved = radio.driver.save().await?;
        if let Some(refusal) = saved.refusal {
            log::warn!(refusal; "the radio did not save the test-alert setting");
            return Ok(());
        }
        self.settle(radio, |policy| {
            policy.test_alerts_unsaved = None;
            policy.test_alerts = Some(desired);
        });
        Ok(())
    }

    /// The radio's destination filter: this phone's forward-secret
    /// addresses.
    async fn destinations(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        if radio.sync.filter_count.is_none() {
            return Ok(());
        }
        let hints = self.policy.borrow().destination_hints.clone();
        if self.policy.borrow().destinations.as_ref() == Some(&hints) {
            return Ok(());
        }
        radio
            .driver
            .reconcile_host_destination_hints(hints.clone())
            .await?;
        self.settle(radio, |policy| policy.destinations = Some(hints));
        Ok(())
    }

    /// Replay what the radio queued while the phone was away, once per
    /// session with it, after its tables are set.
    /// Not while the locked vault holds a channel back from the session or
    /// from the radio's table: what the queue holds for it would arrive
    /// with nothing to read it, and is replayed only once. A failure that
    /// will not pass does not hold the drain back.
    async fn drain(&self, radio: &Radio) -> Result<(), MobileRadioError> {
        let channels_waiting =
            self.channels.borrow().locked || self.policy.borrow().host_channels_locked;
        if !radio.sync.supports_offline_queue
            || self.policy.borrow().drained
            || self.session().is_none()
            || channels_waiting
        {
            return Ok(());
        }
        self.policy.borrow_mut().drained = true;
        let drained = radio.driver.drain_queue().await;
        if drained.is_err() {
            self.settle(radio, |policy| policy.drained = false);
        }
        drained
    }

    /// Log a rise in a radio's dropped-frame count, across detaches too.
    fn note_dropped_frames(&self, state: &MobileRadioStateRecord) {
        let Some(dropped) = state
            .provisioning
            .as_ref()
            .and_then(|sync| sync.dropped_frames)
        else {
            return;
        };
        let Some(address) = device_address(state) else {
            return;
        };
        let previous = self
            .policy
            .borrow_mut()
            .dropped_frames
            .insert(address, dropped);
        if let Some(previous) = previous
            && dropped > previous
        {
            let lost = dropped - previous;
            log::info!(lost; "the radio dropped queued frames; that interval's transcript is incomplete");
        }
    }

    // --- Claimed radios. ---

    /// Write that this phone holds `state`'s radio, at most every ten
    /// minutes unless `refresh`.
    fn record_claim(&self, state: &MobileRadioStateRecord, refresh: bool) {
        let Some(owner) = self.owner() else {
            return;
        };
        let Some(address) = device_address(state) else {
            return;
        };
        let now_ms = self.clock.now_ms();
        {
            let policy = self.policy.borrow();
            if policy.released.contains(&address) {
                return;
            }
            if !refresh
                && policy
                    .claim_recorded_at
                    .get(&address)
                    .is_some_and(|at| now_ms - at < CLAIM_REWRITE_MS)
            {
                return;
            }
        }
        match self
            .store
            .record_claimed_radio(owner, address.clone(), state.name.clone(), now_ms)
        {
            Ok(()) => {
                self.policy
                    .borrow_mut()
                    .claim_recorded_at
                    .insert(address, now_ms);
                self.raise_claims();
            }
            Err(error) => log::warn!(error:? = error; "the radio's claim was not kept"),
        }
    }

    /// A radio found unclaimed, unsupported or held by another host is
    /// not this phone's to remember.
    fn forget_claim_if_held_elsewhere(&self, state: &MobileRadioStateRecord) {
        if state.phase != MobileRadioPhase::Attached
            || !matches!(
                state.host,
                UlcpHostOwnership::Unclaimed
                    | UlcpHostOwnership::OtherHost
                    | UlcpHostOwnership::Unsupported
            )
        {
            return;
        }
        let Some(address) = device_address(state) else {
            return;
        };
        let Some(owner) = self.owner() else {
            return;
        };
        let claimed = self
            .store
            .claimed_radios(owner, self.clock.now_ms())
            .is_ok_and(|claims| claims.iter().any(|claim| claim.device_address == address));
        if claimed {
            self.forget_claim(&address);
        }
    }

    fn forget_claim(&self, address: &str) {
        let Some(owner) = self.owner() else {
            return;
        };
        self.policy.borrow_mut().claim_recorded_at.remove(address);
        match self.store.clear_claimed_radio(owner, address.to_owned()) {
            Ok(()) => self.raise_claims(),
            Err(error) => log::warn!(error:? = error; "a radio's claim was not forgotten"),
        }
    }

    fn raise_claims(&self) {
        self.shared.publish(|_| MobileAppChangesRecord {
            claimed_radios_changed: true,
            ..MobileAppChangesRecord::default()
        });
    }

    /// Revoke the other radios this phone holds, once per session with
    /// the radio.
    fn revoke_once(self: &Rc<Self>) {
        if self.policy.borrow().revoked || self.session().is_none() {
            return;
        }
        self.policy.borrow_mut().revoked = true;
        let worker = self.clone();
        tokio::task::spawn_local(async move { worker.revoke_claimed_radios().await });
    }

    /// Ask every radio this phone holds but the one attached, across the
    /// mesh, to forget its key. One asked while another runs runs after it.
    /// Resolves once no round is left to run.
    pub(super) async fn revoke_claimed_radios(&self) {
        if self.policy.borrow().revoking {
            self.policy.borrow_mut().revoke_again = true;
            loop {
                let done = self.revocation_done.notified();
                tokio::pin!(done);
                done.as_mut().enable();
                if !self.policy.borrow().revoking {
                    return;
                }
                done.await;
            }
        }
        self.set_revoking(true);
        loop {
            self.revoke_round().await;
            if !std::mem::take(&mut self.policy.borrow_mut().revoke_again) {
                break;
            }
        }
        self.set_revoking(false);
        self.revocation_done.notify_waiters();
    }

    /// One round. The radio attached is read before each ask, not when the
    /// round began, so a radio attached meanwhile is never asked.
    async fn revoke_round(&self) {
        let Some(owner) = self.owner() else {
            return;
        };
        let Ok(claims) = self.store.claimed_radios(owner, self.clock.now_ms()) else {
            return;
        };
        self.raise_claims();
        let host_key = crate::ulcp::ulcp_managed_property_ids().host_key;
        for claim in claims {
            let radio = self.shared.snapshot().radio.clone();
            if !super::pipeline::carries_this_phone(radio.as_ref()) {
                return;
            }
            if radio.as_ref().and_then(device_address).as_ref() == Some(&claim.device_address) {
                continue;
            }
            let Some(session) = self.session() else {
                return;
            };
            let Ok(id) = session.begin_management_set_many(
                claim.device_address.clone(),
                vec![MobileMeshPropertyWriteRecord {
                    property_id: host_key,
                    value: Vec::new(),
                }],
            ) else {
                continue;
            };
            let deadline = self.clock.monotonic_ms() + MANAGEMENT_BACKSTOP_MS;
            let Ok(event) = self.await_management(id, deadline).await else {
                continue;
            };
            // Revoked when the device echoes the empty key.
            let revoked = event.answers.iter().any(|answer| {
                answer.property_id == host_key
                    && answer.status_code.is_none()
                    && answer.value.as_ref().is_some_and(Vec::is_empty)
            });
            if revoked {
                self.forget_claim(&claim.device_address);
            }
        }
    }

    fn set_revoking(&self, revoking: bool) {
        self.policy.borrow_mut().revoking = revoking;
        self.shared.publish(|snapshot| {
            snapshot.revoking_claimed_radios = revoking;
            MobileAppChangesRecord {
                revoking_claimed_radios: Some(revoking),
                ..MobileAppChangesRecord::default()
            }
        });
    }
}
