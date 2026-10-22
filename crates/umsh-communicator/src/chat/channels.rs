//! Channels: joining one by its name or by an invitation, sharing one,
//! and the invitations messages carry.
//!
//! A channel joined here is held at once, with its key, and the device is
//! asked to hold it too (`PROP_DEV_CHANNEL_KEYS`). A channel the device
//! will not hold is let go again, and its chat with it when nothing was
//! said there.
//!
//! An invitation is a `umsh:ck:` or `umsh:cs:` URI (`app-text-messages.md`,
//! Channel Invitations in Messages). A named channel goes by the name its
//! key derives from, which is what sharing it gives; a private channel by
//! the name its invitation gave it, or by its key's first characters.

use core::fmt::Write as _;

use umsh_core::{ChannelKey, ChannelTag, base58};
use umsh_text::ConversationKey;
use umsh_uri::{ChannelParams, UmshUri};
use umsh_ux_communicator::avatar;
use umsh_ux_communicator::model::{self, ChannelEntry, ChatSummary, Invite, NodeEvent, ShareUri};
use umsh_ux_communicator::text::SharedText;

use super::{Chats, address};
use crate::ids::ChatId;
use crate::record::{
    BuiltinChannel, ChannelAccess, ChannelChange, ChatChange, NAME_MAX, Name, name,
};
use crate::store::ChatStore;

/// What an invitation to a private channel starts with.
const BY_KEY: &str = "umsh:ck:";

/// What an invitation to a named channel starts with.
const BY_NAME: &str = "umsh:cs:";

/// A channel named or invited to.
pub(crate) struct Found {
    key: ChannelKey,
    /// The name it goes by: for a named channel, the one its key derives
    /// from.
    name: Name,
    access: ChannelAccess,
}

/// A channel joined: its chat, and the key and tag the device is to hold
/// when it does not yet.
pub(crate) type Joined = (ChatSummary, Option<(ChannelKey, ChannelTag)>);

impl<S: ChatStore> Chats<S> {
    /// The channel `text` names: a name, or a whole invitation.
    fn find_channel(&self, text: &str) -> Option<Found> {
        let text = text.trim();
        if !text.starts_with("umsh:") {
            return self.named_channel(text);
        }
        match umsh_uri::parse_umsh_str(text).ok()? {
            UmshUri::ChannelByName(uri) => {
                self.named_channel(&umsh_uri::decode_percent(uri.name).ok()?)
            }
            UmshUri::ChannelByKey(uri) => Some(Found {
                key: uri.key,
                name: invited_name(&uri.params).unwrap_or_else(|| default_name(&uri.key)),
                access: ChannelAccess::Private,
            }),
            UmshUri::Node(_) => None,
        }
    }

    /// The channel called `text`, when that is a channel's name the store
    /// can keep whole.
    fn named_channel(&self, text: &str) -> Option<Found> {
        if text.is_empty() || text.len() > NAME_MAX || text.contains(':') {
            return None;
        }
        Some(Found {
            key: (self.crypto.named)(text)?,
            name: name(text),
            access: ChannelAccess::Named,
        })
    }

    /// What `text`, typed as a channel's name or invitation, names so far.
    pub fn inspect_channel(&self, text: &str) -> ChannelEntry {
        let text = text.trim();
        if text.is_empty() {
            return ChannelEntry::Empty;
        }
        if let Some(rest) = text.strip_prefix(BY_KEY) {
            let digits = rest.split_once('?').map_or(rest, |(digits, _)| digits);
            let missing = base58::ENCODED_LEN.saturating_sub(digits.len()) as u8;
            if digits.len() > base58::ENCODED_LEN
                || (!digits.is_empty() && base58::prefix_bounds(digits.as_bytes()).is_err())
            {
                return ChannelEntry::Invalid;
            }
            return match missing {
                0 if self.find_channel(text).is_some() => ChannelEntry::Private,
                0 => ChannelEntry::Invalid,
                missing => ChannelEntry::Partial { missing },
            };
        }
        // An invitation still being typed.
        if BY_KEY.starts_with(text) && !BY_NAME.starts_with(text) {
            return ChannelEntry::Partial {
                missing: base58::ENCODED_LEN as u8,
            };
        }
        if BY_NAME.starts_with(text) {
            return ChannelEntry::Empty;
        }
        match self.find_channel(text) {
            Some(_) => ChannelEntry::Named,
            None => ChannelEntry::Invalid,
        }
    }

    /// Joins the channel `text` names or invites to.
    pub fn add_channel(&mut self, text: &str, events: &mut dyn FnMut(NodeEvent)) -> Option<Joined> {
        let found = self.find_channel(text)?;
        self.join_found(found, None, events)
    }

    /// Joins the channel `invite` invites to, called `shown` here.
    pub fn join(
        &mut self,
        invite: &Invite,
        shown: &str,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Joined> {
        let key = ChannelKey(invite.key);
        let invited = name(invite.name.as_str());
        // A named channel goes by the name its key derives from, or is
        // private after all.
        let named = invite.access == model::ChannelAccess::Named
            && (self.crypto.named)(&invited).is_some_and(|named| named.0 == key.0);
        let found = Found {
            key,
            name: invited,
            access: if named {
                ChannelAccess::Named
            } else {
                ChannelAccess::Private
            },
        };
        let shown = shown.trim();
        let shown = (!shown.is_empty() && shown != found.name.as_str()).then_some(shown);
        self.join_found(found, shown, events)
    }

    /// Holds the channel `found`, called `shown` here when not by its own
    /// name, and keeps its chat. A channel the device already holds is
    /// not joined again.
    fn join_found(
        &mut self,
        found: Found,
        shown: Option<&str>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Joined> {
        self.facade.as_ref()?;
        let tag = (self.crypto.tag)(&found.key);
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let held = self.held.contains(&tag);
        if held && let Some(chat) = self.store.chat_for(&conversation) {
            self.register(tag, found.key, events);
            return Some((self.chat(chat.0)?, None));
        }
        let builtin = self.crypto.builtin(&found.key);
        let access = match builtin {
            Some(BuiltinChannel::Emergency) => ChannelAccess::Clear,
            _ => found.access,
        };
        let change = ChannelChange::Add {
            name: found.name.as_str(),
            access,
            builtin,
        };
        self.store.update_channel(&tag, change).ok()?;
        let kept = self.store.chat_for(&conversation);
        let open = ChatChange::Open {
            conversation,
            name: shown,
        };
        let chat = self.store.update_chat(ChatId(0), open).ok()?;
        if kept.is_some() && shown.is_some() {
            _ = self.store.update_chat(chat, ChatChange::Rename(shown));
        }
        if !held {
            self.held.push(tag);
        }
        self.register(tag, found.key, events);
        events(NodeEvent::ChatChanged(chat.0));
        let summary = self.chat(chat.0)?;
        Some((summary, (!held).then_some((found.key, tag))))
    }

    /// The device will not hold the channel `tag`: it goes, and its chat
    /// with it when nothing was said there.
    pub fn let_go(&mut self, tag: ChannelTag, events: &mut dyn FnMut(NodeEvent)) {
        self.held.retain(|held| *held != tag);
        if let Some(facade) = &mut self.facade {
            facade.channels_mut().remove(&tag);
        }
        let conversation = ConversationKey::ChannelGroup { channel: tag };
        let Some(chat) = self.store.chat_for(&conversation) else {
            return;
        };
        if self.store.messages(chat, None).next().is_some() {
            return;
        }
        if self.store.update_chat(chat, ChatChange::Delete).is_ok() {
            _ = self.store.update_channel(&tag, ChannelChange::Remove);
            events(NodeEvent::ChatRemoved(chat.0));
        }
    }

    /// Leaves the channel `chat` is in: lets go of it, and of its chat and
    /// the chat's messages. Returns the key and tag the device is to let go
    /// of.
    pub fn leave(
        &mut self,
        chat: model::ChatId,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<(ChannelKey, ChannelTag)> {
        let ConversationKey::ChannelGroup { channel: tag } = self.conversation(chat)? else {
            return None;
        };
        let facade = self.facade.as_mut()?;
        let key = facade.channels().key(&tag)?;
        facade.channels_mut().remove(&tag);
        self.held.retain(|held| *held != tag);
        self.store
            .update_chat(ChatId(chat), ChatChange::Delete)
            .ok()?;
        _ = self.store.update_channel(&tag, ChannelChange::Remove);
        events(NodeEvent::ChatRemoved(chat));
        Some((key, tag))
    }

    /// The link that shares the channel `chat` is in: its name, for a
    /// named channel; else its key, and the name it is shown by when that
    /// fits.
    pub fn share_channel(&self, chat: model::ChatId) -> Option<ShareUri> {
        let record = self
            .store
            .chats()
            .flatten()
            .find(|record| record.id.0 == chat)?;
        let ConversationKey::ChannelGroup { channel } = record.conversation else {
            return None;
        };
        let kept = self
            .store
            .channels()
            .flatten()
            .find(|kept| kept.tag == channel)?;
        let key = self.facade.as_ref()?.channels().key(&channel)?;
        // As long as a share link can be.
        let mut out = [0u8; 96];
        let named = kept.access != ChannelAccess::Private
            && (self.crypto.named)(&kept.name).is_some_and(|named| named.0 == key.0);
        let len = if named {
            let canonical = kept.name.to_ascii_lowercase();
            umsh_uri::format_channel_name_uri(&canonical, &mut out).ok()?
        } else {
            let shown = record.name.as_deref().unwrap_or(kept.name.as_str());
            let params = ChannelParams {
                display_name: Some(shown),
                max_flood_hops: None,
                region: None,
                raw_query: None,
            };
            umsh_uri::format_channel_key_uri_with_params(&key, &params, &mut out)
                .or_else(|_| umsh_uri::format_channel_key_uri(&key, &mut out))
                .ok()?
        };
        ShareUri::try_from(core::str::from_utf8(&out[..len]).ok()?).ok()
    }

    /// The invitation `text` is, when the whole of it is one.
    pub(super) fn invite_in(&self, text: &str) -> Option<Invite> {
        let text = text.trim();
        if !text.starts_with(BY_KEY) && !text.starts_with(BY_NAME) {
            return None;
        }
        let found = self.find_channel(text)?;
        let tag = (self.crypto.tag)(&found.key);
        let builtin = self
            .crypto
            .builtin(&found.key)
            .map(|builtin| match builtin {
                BuiltinChannel::Public => avatar::BuiltinChannel::Public,
                BuiltinChannel::Emergency => avatar::BuiltinChannel::Emergency,
            });
        let shown = match self.crypto.builtin(&found.key) {
            Some(builtin) => builtin.name(),
            None => found.name.as_str(),
        };
        Some(Invite {
            name: SharedText::new(self.heap, shown)?,
            builtin,
            tint: [tag.0[0], tag.0[1], tag.0[2]],
            access: match found.access {
                ChannelAccess::Named => model::ChannelAccess::Named,
                ChannelAccess::Private => model::ChannelAccess::Private,
                ChannelAccess::Clear => model::ChannelAccess::Clear,
            },
            key: found.key.0,
        })
    }
}

/// The name an invitation gives its channel, when it gives one that is
/// not blank.
fn invited_name(params: &ChannelParams<'_>) -> Option<Name> {
    let given = umsh_uri::decode_percent(params.display_name?).ok()?;
    let given = given.trim();
    (!given.is_empty()).then(|| name(given))
}

/// What a private channel goes by without a name of its own.
pub(super) fn default_name(key: &ChannelKey) -> Name {
    let mut name = Name::new();
    let encoded = address(&key.0);
    _ = write!(name, "Channel {}", encoded.get(..4).unwrap_or_default());
    name
}
