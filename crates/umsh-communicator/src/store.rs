//! The interface every back end implements.

use umsh_core::{ChannelTag, NodeHint, PublicKey};
use umsh_text::ConversationKey;
use umsh_text::engine::{ArchiveKey, StreamCheckpoint};

use crate::batch::{Batch, Committed};
use crate::ids::{ChatId, MessageId, PeerId};
use crate::record::{
    ChannelChange, ChannelRecord, ChatChange, ChatRecord, MessageRecord, PeerChange, PeerFilter,
    PeerRecord, ReactorRecord, StoreError, Usage, WireAlias,
};

/// A communicator's durable chat state.
///
/// Iterators are lazy and their items owned: taking a page, filtering, and
/// stopping early cost only what they read, and a flash back end decodes
/// each record as it is asked for. Items are results, because a read can
/// fail partway through. The store is always a type parameter, never a
/// trait object.
pub trait ChatStore {
    /// Writes `batch` in order—checkpoint, archive deletes, archives,
    /// transcript—and returns the IDs given to inserted messages.
    fn commit(&mut self, batch: &Batch<'_>) -> Result<Committed, StoreError>;

    /// The chat's messages, newest first, from just before `before`.
    fn messages(
        &self,
        chat: ChatId,
        before: Option<MessageId>,
    ) -> impl Iterator<Item = Result<MessageRecord, StoreError>> + '_;
    fn message(&self, id: MessageId) -> Result<Option<MessageRecord>, StoreError>;
    fn body<'b>(&self, id: MessageId, out: &'b mut [u8]) -> Result<Option<&'b str>, StoreError>;
    /// Who reacted to the message, and how: the latest from each sender,
    /// in the order they came. Their counts are the record's `reactions`.
    fn reactors(&self, id: MessageId) -> impl Iterator<Item = ReactorRecord> + '_;
    fn resolve_wire(&self, alias: &WireAlias) -> Option<MessageId>;

    fn archive<'b>(
        &self,
        key: &ArchiveKey,
        out: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, StoreError>;
    fn checkpoint(&self, conversation: &ConversationKey) -> Option<StreamCheckpoint>;
    /// The most recently used checkpoints, oldest first, for `Engine::restore`.
    fn recent_checkpoints(&self, limit: usize) -> impl Iterator<Item = StreamCheckpoint> + '_;

    /// Chats, most recently active first.
    fn chats(&self) -> impl Iterator<Item = Result<ChatRecord, StoreError>> + '_;
    fn chat_for(&self, conversation: &ConversationKey) -> Option<ChatId>;
    fn draft<'b>(&self, chat: ChatId, out: &'b mut [u8]) -> Result<Option<&'b str>, StoreError>;
    fn update_chat(&mut self, chat: ChatId, change: ChatChange<'_>) -> Result<ChatId, StoreError>;

    fn peer(&self, key: &PublicKey) -> Result<Option<PeerRecord>, StoreError>;
    fn peers_with_hint(&self, hint: NodeHint) -> impl Iterator<Item = PublicKey> + '_;
    fn peers(
        &self,
        filter: PeerFilter,
    ) -> impl Iterator<Item = Result<PeerRecord, StoreError>> + '_;
    fn update_peer(
        &mut self,
        key: &PublicKey,
        change: PeerChange<'_>,
    ) -> Result<PeerId, StoreError>;

    fn channels(&self) -> impl Iterator<Item = Result<ChannelRecord, StoreError>> + '_;
    fn update_channel(
        &mut self,
        tag: &ChannelTag,
        change: ChannelChange<'_>,
    ) -> Result<(), StoreError>;

    /// The record the device keeps here of its own lists, beside the
    /// chats: what it persists outside its saved snapshot (spec §Lists
    /// Held by the Device's Store). Gone with everything else on
    /// [`ChatStore::erase`].
    fn device_lists<'b>(&self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, StoreError>;
    /// Keeps `record` as the device's lists, or forgets them with `None`.
    fn keep_device_lists(&mut self, record: Option<&[u8]>) -> Result<(), StoreError>;

    /// The record the interface keeps here of the characters it last
    /// picked to type. Gone with everything else on [`ChatStore::erase`].
    fn recent_picks<'b>(&self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, StoreError>;
    /// Keeps `record` as the recent picks, or forgets them with `None`.
    fn keep_recent_picks(&mut self, record: Option<&[u8]>) -> Result<(), StoreError>;

    /// Fails what each outbound message still awaited (see
    /// [`Delivery::interrupt`]), as a new session starts: no word on the
    /// last one's frames will be taken.
    ///
    /// [`Delivery::interrupt`]: crate::Delivery::interrupt
    fn interrupt(&mut self) -> Result<(), StoreError>;

    fn usage(&self) -> Usage;
    /// Forget everything: a factory reset. Identifiers are still never
    /// reused.
    fn erase(&mut self) -> Result<(), StoreError>;
}
