use alloc::string::String;

use umsh_core::{ChannelId, ChannelKey};
use umsh_crypto::{CryptoEngine, software::{SoftwareAes, SoftwareSha256}};

/// A channel descriptor — holds the key, derived ID, and display name.
///
/// Not bound to any node. Create via [`Channel::named`] (key derived from name)
/// or [`Channel::private`] (key independent of name).
#[derive(Clone)]
pub struct Channel {
    key: ChannelKey,
    channel_id: ChannelId,
    name: String,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("channel_id", &self.channel_id)
            .field("name", &self.name)
            .finish()
    }
}

impl Channel {
    /// Create a named channel whose key is derived from the name.
    ///
    /// Uses the same derivation as the MAC layer's `add_named_channel`.
    pub fn named(name: &str) -> Self {
        let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let key = crypto.derive_named_channel_key(name);
        let channel_id = crypto.derive_channel_id(&key);

        Self {
            key,
            channel_id,
            name: String::from(name),
        }
    }

    /// Create a private channel with an explicit key.
    ///
    /// The name is for display only — it does not affect the key.
    pub fn private(key: ChannelKey, name: &str) -> Self {
        let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let channel_id = crypto.derive_channel_id(&key);

        Self {
            key,
            channel_id,
            name: String::from(name),
        }
    }

    /// The channel's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The derived 2-byte channel ID (used for routing/filtering).
    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    /// The full symmetric channel key.
    pub fn key(&self) -> &ChannelKey {
        &self.key
    }
}

impl PartialEq for Channel {
    fn eq(&self, other: &Self) -> bool {
        self.key.0 == other.key.0
    }
}

impl Eq for Channel {}
