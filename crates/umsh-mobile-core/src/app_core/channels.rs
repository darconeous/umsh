//! The derived-value cache: for each stored channel, its 16-byte identifier
//! and its conversation address. Neither is secret, so the policy pass
//! works from these instead of reading keys. A key is read only to derive
//! them, and to register a phone-joined channel with the session.
//!
//! `refresh_channels` is the one path from the channel rows to the
//! session: bootstrap, the pass and every channel command go through it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::worker::Worker;
use crate::mobile_mesh::{MobileChannelRegistrationRecord, MobileMeshSession};
use crate::secret_vault::SecretVaultError;
use crate::{MobileMeshError, MobileWellKnownChannel, well_known_channel};

/// What a channel's key derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DerivedChannel {
    /// The 16-byte identifier the radio's tables name the channel by.
    pub(super) identifier: Vec<u8>,
    pub(super) conversation_address: String,
    pub(super) emergency: bool,
    pub(super) joined_phone: bool,
    /// Registered with the session, under the ceiling it holds. Only a
    /// phone-joined channel is.
    registered: Option<Option<u8>>,
}

#[derive(Debug, Default)]
pub(super) struct ChannelCache {
    /// By channel ID.
    entries: BTreeMap<String, DerivedChannel>,
    /// A phone-joined channel is missing (its key would not load, or its
    /// registration failed), or a refused command's rollback wrote behind
    /// the cache. Retried on the next trigger.
    pub(super) incomplete: bool,
    /// Some key could not be read because the vault is locked, which
    /// passes: what waits on the channels waits for it. A failure that
    /// will not pass (a full table, a vault error) is only retried.
    pub(super) locked: bool,
    /// What the session was last told about silent tests: `None` until it
    /// is told anything.
    pub(super) silent_tests_in: Option<Option<String>>,
}

impl ChannelCache {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn conversation_address(&self, channel_id: &str) -> Option<String> {
        self.entries
            .get(channel_id)
            .map(|channel| channel.conversation_address.clone())
    }

    /// The channel whose conversation `address` is, when its key was read.
    pub(super) fn channel_at(&self, address: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|(_, channel)| channel.conversation_address == address)
            .map(|(id, _)| id.clone())
    }

    pub(super) fn identifier(&self, channel_id: &str) -> Option<Vec<u8>> {
        self.entries
            .get(channel_id)
            .map(|channel| channel.identifier.clone())
    }

    /// The ceiling a channel is registered with the session under, when it
    /// is.
    #[cfg(test)]
    pub(super) fn registered_ceiling(&self, channel_id: &str) -> Option<Option<u8>> {
        self.entries
            .get(channel_id)
            .and_then(|channel| channel.registered)
    }

    fn emergency_address(&self) -> Option<String> {
        self.entries
            .values()
            .find(|channel| channel.emergency && channel.joined_phone)
            .map(|channel| channel.conversation_address.clone())
    }
}

/// Where one stored channel stands after a refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChannelState {
    /// Phone-joined and held by the session, under its stored ceiling.
    Registered,
    /// The session's table is full.
    Full,
    /// The vault is locked.
    Locked,
    /// The key is gone, malformed, or the vault failed.
    KeyFailed,
    /// The session would not take it for another reason, which it gave.
    Failed(MobileMeshError),
    /// Stored, but the phone has not joined it.
    NotJoined,
    /// Not stored.
    Gone,
}

/// What one refresh found.
#[derive(Debug, Default)]
pub(super) struct ChannelReport {
    /// The session changed under the refresh, which stopped: nothing it
    /// found is kept.
    pub(super) stale: bool,
    states: HashMap<String, ChannelState>,
}

impl ChannelReport {
    pub(super) fn state(&self, channel_id: &str) -> ChannelState {
        self.states
            .get(channel_id)
            .copied()
            .unwrap_or(ChannelState::Gone)
    }

    /// A report that found `state` for one channel.
    #[cfg(test)]
    pub(super) fn of(channel_id: &str, state: ChannelState) -> Self {
        Self {
            stale: false,
            states: HashMap::from([(channel_id.to_owned(), state)]),
        }
    }
}

/// Whether `session` is still `captured`: a refresh that resumes after the
/// session went (a stop, an erase) must not refill the cache they cleared.
fn same_session(
    captured: &Arc<MobileMeshSession>,
    session: Option<&Arc<MobileMeshSession>>,
) -> bool {
    session.is_some_and(|session| Arc::ptr_eq(captured, session))
}

impl Worker {
    /// A refused join or rejoin took its write back after the refresh it
    /// ran, so the cache and the session may still hold what it wrote: the
    /// next pass refreshes again.
    pub(super) fn rolled_back_channel(&self) {
        self.channels.borrow_mut().incomplete = true;
    }

    /// Bring the cache and the session up to date with the store: derive
    /// each channel the cache lacks, register each phone-joined one the
    /// session lacks or holds under another ceiling, take those left or
    /// gone out of the session, and forget the gone. One refresh at a
    /// time.
    pub(super) async fn refresh_channels(&self) -> ChannelReport {
        self.refresh_channels_holding(None).await
    }

    /// As `refresh_channels`, with `held`'s key already in hand, so a
    /// channel just stored is not read back from the vault.
    pub(super) async fn refresh_channels_holding(
        &self,
        held: Option<(&str, &[u8])>,
    ) -> ChannelReport {
        let _refresh = self.channel_refresh.lock().await;
        let mut report = ChannelReport::default();
        let Some(owner) = self.owner() else {
            return report;
        };
        // Gone already (a stop, an erase under way): as stale as one that
        // goes during the refresh.
        let Some(session) = self.session() else {
            report.stale = true;
            return report;
        };
        let rows = match self.store.channels(owner) {
            Ok(rows) => rows,
            Err(error) => {
                log::warn!(error:? = error; "channels could not be read");
                self.channels.borrow_mut().incomplete = true;
                return report;
            }
        };
        let mut complete = true;
        let mut locked = false;

        // Those left or gone leave the session first, by address: the
        // session holds their keys, so none is read.
        let leaving: Vec<(String, String)> = self
            .channels
            .borrow()
            .entries
            .iter()
            .filter(|(id, channel)| {
                channel.registered.is_some()
                    && !rows.iter().any(|row| &row.id == *id && row.joined_phone)
            })
            .map(|(id, channel)| (id.clone(), channel.conversation_address.clone()))
            .collect();
        if !leaving.is_empty() {
            let addresses = leaving.iter().map(|(_, address)| address.clone()).collect();
            let removed = session.remove_channels_by_address(addresses).await;
            if !same_session(&session, self.session().as_ref()) {
                report.stale = true;
                return report;
            }
            match removed {
                Ok(()) => {
                    let mut cache = self.channels.borrow_mut();
                    for (id, _) in &leaving {
                        if let Some(entry) = cache.entries.get_mut(id) {
                            entry.registered = None;
                        }
                    }
                }
                Err(error) => {
                    log::warn!(error:? = error; "a channel could not leave the session");
                    complete = false;
                }
            }
        }
        // A channel still held keeps its entry until it has left.
        self.channels.borrow_mut().entries.retain(|id, channel| {
            channel.registered.is_some() || rows.iter().any(|row| &row.id == id)
        });

        for row in rows {
            let wanted = {
                let mut cache = self.channels.borrow_mut();
                match cache.entries.get_mut(&row.id) {
                    Some(entry) => {
                        entry.joined_phone = row.joined_phone;
                        row.joined_phone && entry.registered != Some(row.max_flood_hops)
                    }
                    // A channel the phone has left needs no key.
                    None => row.joined_phone,
                }
            };
            if !wanted {
                // Left, or held under its ceiling already.
                let state = if row.joined_phone {
                    ChannelState::Registered
                } else {
                    ChannelState::NotJoined
                };
                report.states.insert(row.id.clone(), state);
                continue;
            }
            let key = match held {
                Some((id, key)) if id == row.id => Ok(Some(key.to_vec())),
                _ => self.vault.load(row.id.clone()),
            };
            let key = match key {
                Ok(Some(key)) => key,
                // Nothing to retry: the key is gone for good.
                Ok(None) => {
                    log::warn!("a stored channel has no key in the vault");
                    report
                        .states
                        .insert(row.id.clone(), ChannelState::KeyFailed);
                    continue;
                }
                Err(SecretVaultError::Unavailable) => {
                    complete = false;
                    locked = true;
                    report.states.insert(row.id.clone(), ChannelState::Locked);
                    continue;
                }
                Err(error) => {
                    log::warn!(error:? = error; "a channel's key would not load");
                    complete = false;
                    report
                        .states
                        .insert(row.id.clone(), ChannelState::KeyFailed);
                    continue;
                }
            };
            let known = self.channels.borrow().entries.contains_key(&row.id);
            if !known {
                let (Ok(identifier), Ok(conversation_address)) = (
                    crate::channel_identifier(key.clone()),
                    crate::channel_conversation_address(key.clone()),
                ) else {
                    log::warn!("a stored channel key is malformed");
                    report
                        .states
                        .insert(row.id.clone(), ChannelState::KeyFailed);
                    continue;
                };
                let emergency = well_known_channel(row.canonical_name.clone())
                    .is_some_and(|known| known.channel == MobileWellKnownChannel::Emergency);
                self.channels.borrow_mut().entries.insert(
                    row.id.clone(),
                    DerivedChannel {
                        identifier,
                        conversation_address,
                        emergency,
                        joined_phone: row.joined_phone,
                        registered: None,
                    },
                );
                // Where tests arrive silently goes before EMERGENCY can carry
                // one, or the first would be stored as audible.
                if emergency {
                    self.push_silent_tests();
                }
            }
            // One at a time, so a full table keeps what fit. A channel
            // held already is registered again under its new ceiling.
            let registered = session
                .register_channels(vec![MobileChannelRegistrationRecord {
                    key,
                    max_flood_hops: row.max_flood_hops,
                }])
                .await;
            if !same_session(&session, self.session().as_ref()) {
                report.stale = true;
                return report;
            }
            let state = match registered {
                Ok(()) => {
                    if let Some(entry) = self.channels.borrow_mut().entries.get_mut(&row.id) {
                        entry.registered = Some(row.max_flood_hops);
                    }
                    ChannelState::Registered
                }
                Err(error) => {
                    log::warn!(error:? = error; "a channel could not be registered");
                    complete = false;
                    match error {
                        MobileMeshError::ChannelCapacity => ChannelState::Full,
                        MobileMeshError::InvalidChannelKey => ChannelState::KeyFailed,
                        error => ChannelState::Failed(error),
                    }
                }
            };
            report.states.insert(row.id.clone(), state);
        }
        let mut cache = self.channels.borrow_mut();
        cache.incomplete = !complete;
        cache.locked = locked;
        drop(cache);
        self.push_silent_tests();
        report
    }

    /// Where tests should arrive silently: EMERGENCY's conversation, unless
    /// the user asked to be told of them.
    pub(super) fn silent_tests_address(&self) -> Option<String> {
        if self.test_message_alerts() {
            return None;
        }
        self.channels.borrow().emergency_address()
    }

    /// Record that the session was given the current silent-tests address.
    pub(super) fn silent_tests_pushed(&self) {
        let address = self.silent_tests_address();
        self.channels.borrow_mut().silent_tests_in = Some(address);
    }

    /// Tell the session where tests arrive silently, when that changed.
    pub(super) fn push_silent_tests(&self) {
        let Some(session) = self.session() else {
            return;
        };
        let address = self.silent_tests_address();
        if self.channels.borrow().silent_tests_in.as_ref() == Some(&address) {
            return;
        }
        match session.set_chat_silent_tests_in(address.clone()) {
            Ok(()) => self.channels.borrow_mut().silent_tests_in = Some(address),
            // No chat store yet: the next push tries again.
            Err(error) => log::debug!(error:? = error; "silent tests not pushed"),
        }
    }
}
