//! The core's queries, and the store writes with no policy in them. Each
//! reads for the current owner, synchronously; native code calls them off
//! its main thread.

use super::channel_commands::parse_channel_input;
use super::mapping::{self, PeerIndex};
use super::records::{
    MobileAppChannelPreviewRecord, MobileAppRepeaterListingRecord, MobileAppStateRecord,
    MobileAppTranscriptPageRecord,
};
use super::{MobileAppCore, MobileAppError};
use crate::channel_key_digest;
use crate::store::{
    MobileStoredChannelRecord, MobileStoredChatCursorRecord, MobileStoredChatMessagePageRecord,
    MobileStoredChatMessageRefRecord, MobileStoredClaimedRadioRecord,
};

#[uniffi::export]
impl MobileAppCore {
    /// Everything the lists show. With `conversations_only`, peers and
    /// neighbor reports are neither read nor answered.
    #[uniffi::method(default(conversations_only = false))]
    pub fn state(&self, conversations_only: bool) -> Result<MobileAppStateRecord, MobileAppError> {
        let owner = self.reader()?;
        let records = self
            .store
            .application_records(owner.clone(), conversations_only)?;
        let advertised_name = self.store.local_advertised_name(owner)?;
        let certified = self.shared.snapshot().emergency_certified;
        let lists = mapping::lists(records, conversations_only, certified);
        Ok(MobileAppStateRecord {
            peers: lists.peers,
            channels: lists.channels,
            direct_conversations: lists.direct_conversations,
            channel_conversations: lists.channel_conversations,
            neighbor_reports: lists.neighbor_reports,
            advertised_name,
        })
    }

    /// The newest `limit` messages of a conversation. `limit` is held to
    /// between 1 and 500.
    pub fn transcript_newest(
        &self,
        conversation_address: String,
        limit: u32,
    ) -> Result<MobileAppTranscriptPageRecord, MobileAppError> {
        let owner = self.reader()?;
        let page =
            self.store
                .chat_message_page_newest(owner.clone(), conversation_address, limit)?;
        self.transcript_page(owner, page)
    }

    /// Up to `limit` messages older than `cursor`.
    pub fn transcript_before(
        &self,
        conversation_address: String,
        cursor: MobileStoredChatCursorRecord,
        limit: u32,
    ) -> Result<MobileAppTranscriptPageRecord, MobileAppError> {
        let owner = self.reader()?;
        let page = self.store.chat_message_page_before(
            owner.clone(),
            conversation_address,
            cursor,
            limit,
        )?;
        self.transcript_page(owner, page)
    }

    /// Up to `limit` messages newer than `cursor`, and the one at it when
    /// `including`.
    pub fn transcript_after(
        &self,
        conversation_address: String,
        cursor: MobileStoredChatCursorRecord,
        including: bool,
        limit: u32,
    ) -> Result<MobileAppTranscriptPageRecord, MobileAppError> {
        let owner = self.reader()?;
        let page = self.store.chat_message_page_after(
            owner.clone(),
            conversation_address,
            cursor,
            limit,
            including,
        )?;
        self.transcript_page(owner, page)
    }

    /// `message` with up to `radius` messages on each side, or `None` when
    /// the conversation does not hold it.
    pub fn transcript_around(
        &self,
        conversation_address: String,
        message: MobileStoredChatMessageRefRecord,
        radius: u32,
    ) -> Result<Option<MobileAppTranscriptPageRecord>, MobileAppError> {
        let owner = self.reader()?;
        self.store
            .chat_message_window(owner.clone(), conversation_address, message, radius)?
            .map(|page| self.transcript_page(owner, page))
            .transpose()
    }

    /// How many messages a conversation holds, reactions not counted.
    pub fn message_count(&self, conversation_address: String) -> Result<i64, MobileAppError> {
        let owner = self.reader()?;
        Ok(self.store.chat_message_count(owner, conversation_address)?)
    }

    /// What a router last said about its neighbors, or `None` when it was
    /// never asked.
    pub fn peer_repeaters(
        &self,
        public_address: String,
    ) -> Result<Option<MobileAppRepeaterListingRecord>, MobileAppError> {
        let owner = self.reader()?;
        let Some(listing) = self
            .store
            .peer_repeater_listing(owner.clone(), public_address)?
        else {
            return Ok(None);
        };
        let peers = PeerIndex::of_nodes(self.store.list_nodes(owner)?);
        Ok(Some(mapping::listing(listing, &peers)))
    }

    /// The radios this phone was host of recently, most recent first.
    /// Reading forgets those whose claim has lapsed.
    pub fn claimed_radios(&self) -> Result<Vec<MobileStoredClaimedRadioRecord>, MobileAppError> {
        let owner = self.reader()?;
        Ok(self.store.claimed_radios(owner, self.clock.now_ms())?)
    }

    /// The claimed radios other than the one attached with this phone as
    /// its host: those that may still hold this phone's key.
    pub fn stranded_radios(&self) -> Result<Vec<MobileStoredClaimedRadioRecord>, MobileAppError> {
        let attached = self.shared.snapshot().attached_host.clone();
        let mut radios = self.claimed_radios()?;
        radios.retain(|radio| Some(&radio.device_address) != attached.as_ref());
        Ok(radios)
    }

    /// A channel invitation (a `umsh:` URI) or name, with the stored
    /// channel that has its key and any other channel called the same.
    pub fn preview_channel(
        &self,
        input: String,
    ) -> Result<MobileAppChannelPreviewRecord, MobileAppError> {
        let owner = self.reader()?;
        let preview = parse_channel_input(&input)?;
        let existing = self
            .store
            .channel(owner.clone(), channel_key_digest(preview.key.clone()))?;
        let name_conflict = preview
            .display_name
            .as_deref()
            .or(preview.canonical_name.as_deref())
            .map(str::to_lowercase)
            .map(|name| -> Result<_, MobileAppError> {
                Ok(self.store.channels(owner)?.into_iter().find(|channel| {
                    Some(&channel.id) != existing.as_ref().map(|existing| &existing.id)
                        && title(channel).is_some_and(|title| title.to_lowercase() == name)
                }))
            })
            .transpose()?
            .flatten();
        Ok(MobileAppChannelPreviewRecord {
            preview,
            existing,
            name_conflict,
        })
    }

    /// This phone's node key, as `PROP_HOST_KEY` carries it.
    pub fn phone_node_key(&self) -> Result<Vec<u8>, MobileAppError> {
        Ok(crate::public_identity_bytes(self.reader()?)?)
    }
}

impl MobileAppCore {
    /// A stored page, mapped. The peers are read only when the page names
    /// a repeater.
    fn transcript_page(
        &self,
        owner: String,
        page: MobileStoredChatMessagePageRecord,
    ) -> Result<MobileAppTranscriptPageRecord, MobileAppError> {
        let peers = if mapping::names_repeaters(&page) {
            Some(PeerIndex::of_nodes(self.store.list_nodes(owner)?))
        } else {
            None
        };
        Ok(mapping::page(page, peers.as_ref(), self.clock.now_ms()))
    }
}

/// What the user calls a channel: its alias, else its name. A channel with
/// neither has no title to conflict with.
fn title(channel: &MobileStoredChannelRecord) -> Option<&str> {
    [channel.alias.as_deref(), channel.name.as_deref()]
        .into_iter()
        .flatten()
        .find(|title| !title.is_empty())
}
