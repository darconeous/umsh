//! The derived-value cache: for each stored channel, its 16-byte identifier
//! and its conversation address. Neither is secret, so the policy pass
//! works from these instead of reading keys. A key is read only to derive
//! them, and to register a phone-joined channel with the session.

use std::collections::BTreeMap;

use super::worker::Worker;
use crate::mobile_mesh::MobileChannelRegistrationRecord;
use crate::secret_vault::SecretVaultError;

/// What a channel's key derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DerivedChannel {
    /// The 16-byte identifier the radio's tables name the channel by.
    pub(super) identifier: Vec<u8>,
    pub(super) conversation_address: String,
    pub(super) emergency: bool,
    pub(super) joined_phone: bool,
    /// Registered with the session. Only a phone-joined channel is.
    registered: bool,
}

#[derive(Debug, Default)]
pub(super) struct ChannelCache {
    /// By channel ID.
    entries: BTreeMap<String, DerivedChannel>,
    /// A phone-joined channel is missing: its key would not load, or its
    /// registration failed. Retried on the next trigger.
    pub(super) incomplete: bool,
    /// Some key could not be read because the vault is locked, which
    /// passes: what waits on the channels waits for it. A failure that
    /// will not pass (a full table, a vault error) is only retried.
    pub(super) locked: bool,
    /// Moves whenever an entry is added or removed, so what was matched
    /// against the entries knows to match again.
    pub(super) version: u64,
    /// The store's write count when the cache was last brought up to date.
    pub(super) seen_writes: Option<u64>,
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

    pub(super) fn identifier(&self, channel_id: &str) -> Option<Vec<u8>> {
        self.entries
            .get(channel_id)
            .map(|channel| channel.identifier.clone())
    }

    fn emergency_address(&self) -> Option<String> {
        self.entries
            .values()
            .find(|channel| channel.emergency && channel.joined_phone)
            .map(|channel| channel.conversation_address.clone())
    }
}

impl Worker {
    /// Bring the cache up to date with the store: derive each channel the
    /// cache lacks, register each phone-joined one the session lacks, and
    /// forget those gone. Returns whether nothing is left to retry.
    pub(super) async fn refresh_channels(&self) -> bool {
        let Some(owner) = self.owner() else {
            return false;
        };
        let writes = self.store.content_writes();
        let rows = match self.store.channels(owner) {
            Ok(rows) => rows,
            Err(error) => {
                log::warn!(error:? = error; "channels could not be read");
                self.channels.borrow_mut().incomplete = true;
                return false;
            }
        };
        {
            let mut cache = self.channels.borrow_mut();
            let before = cache.entries.len();
            cache
                .entries
                .retain(|id, _| rows.iter().any(|row| &row.id == id));
            if cache.entries.len() != before {
                cache.version += 1;
            }
        }
        let session = self.session();
        let mut complete = true;
        let mut locked = false;
        for row in rows {
            let wanted = {
                let mut cache = self.channels.borrow_mut();
                match cache.entries.get_mut(&row.id) {
                    Some(entry) => {
                        entry.joined_phone = row.joined_phone;
                        // Left: native code took it from the session.
                        if !row.joined_phone {
                            entry.registered = false;
                        }
                        entry.joined_phone && !entry.registered && session.is_some()
                    }
                    None => true,
                }
            };
            if !wanted {
                continue;
            }
            let key = match self.vault.load(row.id.clone()) {
                Ok(Some(key)) => key,
                // Nothing to retry: the key is gone for good.
                Ok(None) => {
                    log::warn!("a stored channel has no key in the vault");
                    continue;
                }
                Err(SecretVaultError::Unavailable) => {
                    complete = false;
                    locked = true;
                    continue;
                }
                Err(error) => {
                    log::warn!(error:? = error; "a channel's key would not load");
                    complete = false;
                    continue;
                }
            };
            let (Ok(identifier), Ok(conversation_address)) = (
                crate::channel_identifier(key.clone()),
                crate::channel_conversation_address(key.clone()),
            ) else {
                log::warn!("a stored channel key is malformed");
                continue;
            };
            let emergency = row.canonical_name.as_deref() == Some("emergency");
            self.channels.borrow_mut().version += 1;
            self.channels.borrow_mut().entries.insert(
                row.id.clone(),
                DerivedChannel {
                    identifier,
                    conversation_address,
                    emergency,
                    joined_phone: row.joined_phone,
                    registered: false,
                },
            );
            // Where tests arrive silently goes before EMERGENCY can carry
            // one, or the first would be stored as audible.
            if emergency {
                self.push_silent_tests();
            }
            if row.joined_phone
                && let Some(session) = &session
            {
                // One at a time, so a full table keeps what fit.
                match session
                    .register_channels(vec![MobileChannelRegistrationRecord {
                        key,
                        max_flood_hops: row.max_flood_hops,
                    }])
                    .await
                {
                    Ok(()) => {
                        if let Some(entry) = self.channels.borrow_mut().entries.get_mut(&row.id) {
                            entry.registered = true;
                        }
                    }
                    Err(error) => {
                        log::warn!(error:? = error; "a channel could not be registered");
                        complete = false;
                    }
                }
            }
        }
        let mut cache = self.channels.borrow_mut();
        cache.incomplete = !complete;
        cache.locked = locked;
        cache.seen_writes = Some(writes);
        drop(cache);
        self.push_silent_tests();
        complete
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
