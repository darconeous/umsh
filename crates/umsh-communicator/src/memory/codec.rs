//! Records as octets, for a durable layer.
//!
//! A record's key is its kind and what names it; the record is the rest.
//! Numbers are big-endian, an absent value is a zero octet and a present
//! one a one octet before it, and text is its length then its UTF-8. A
//! record that does not decode is left out when the store is mounted, and
//! the rest are kept; octets past the end of one are ignored.

use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{ChannelTag, NodeHint, PublicKey, RouterHint};
use umsh_text::engine::{CompletionStatus, Direction, Presence, StreamCheckpoint};
use umsh_text::{ConversationKey, MessageType, SenderScope};

use super::{CHAT, ChatEntry, Disk, MESSAGE, MessageEntry, PEER, PeerEntry, Reactor, RecordKey};
use crate::ids::{ChatId, MessageId, PeerId};
use crate::reaction::{Cluster, Reaction, Reactions};
use crate::record::{
    self, BODY_MAX, BuiltinChannel, ChannelAccess, ChannelRecord, ChatRecord, Delivery,
    IDENTITY_MAX, LinkInfo, MessageFlags, MessageRecord, NAME_MAX, Name, PeerRecord, ROUTE_MAX,
};
use crate::wire::{ConversationCode, SenderCode};

/// The longest key: an archive's.
pub(super) const KEY_MAX: usize = 1 + 49 + 2;

const COUNTERS: u8 = 0;
const CHECKPOINT: u8 = 1;
const ARCHIVE: u8 = 2;
const CHAT_RECORD: u8 = 3;
pub(super) const MESSAGE_RECORD: u8 = 4;
const PEER_RECORD: u8 = 5;
const CHANNEL: u8 = 6;
const DEVICE_LISTS: u8 = 7;
const RECENT_PICKS: u8 = 8;

/// A reactor's reaction that is not one of the emotes, its cluster after.
/// The emotes are their place in [`Reaction::ALL`].
const OTHER_REACTION: u8 = 0xFF;

/// The key of the record `key` names.
pub(super) fn key(key: &RecordKey, out: &mut heapless::Vec<u8, KEY_MAX>) {
    out.clear();
    let mut put = |bytes: &[u8]| {
        let _ = out.extend_from_slice(bytes);
    };
    match key {
        RecordKey::Counters => put(&[COUNTERS]),
        RecordKey::Checkpoint(code) => {
            put(&[CHECKPOINT]);
            put(code.as_bytes());
        }
        RecordKey::Archive((code, wire_id, fragment)) => {
            put(&[ARCHIVE]);
            put(code.as_bytes());
            put(&[*wire_id, *fragment]);
        }
        RecordKey::Chat(id) => {
            put(&[CHAT_RECORD]);
            put(&id.to_be_bytes());
        }
        RecordKey::Message(id) => {
            put(&[MESSAGE_RECORD]);
            put(&id.to_be_bytes());
        }
        RecordKey::Peer(peer) => {
            put(&[PEER_RECORD]);
            put(peer);
        }
        RecordKey::Channel(tag) => {
            put(&[CHANNEL]);
            put(tag);
        }
        RecordKey::DeviceLists => put(&[DEVICE_LISTS]),
        RecordKey::RecentPicks => put(&[RECENT_PICKS]),
    }
}

/// The record `key` names in `disk`, into `out`. Returns whether there is
/// one.
pub(super) fn record(disk: &Disk, key: &RecordKey, out: &mut Vec<u8>) -> bool {
    let mut out = Out(out);
    match key {
        RecordKey::Counters => {
            for reserved in disk.reserved {
                out.u32(reserved);
            }
        }
        RecordKey::Checkpoint(code) => {
            let Some((checkpoint, used)) = disk.checkpoints.get(code) else {
                return false;
            };
            out.conversation(&checkpoint.conversation);
            out.u8(checkpoint.next_id);
            out.u16(checkpoint.epoch);
            out.u64(*used);
        }
        RecordKey::Archive(code) => {
            let Some(payload) = disk.archives.get(code) else {
                return false;
            };
            out.bytes(payload);
        }
        RecordKey::Chat(id) => {
            let Some(chat) = disk.chats.get(id) else {
                return false;
            };
            let record = &chat.record;
            out.conversation(&record.conversation);
            out.name(record.name.as_deref());
            out.flag(record.muted);
            out.u32(record.unread);
            out.option(record.last_activity, Out::u32);
            out.u64(chat.activity);
            out.option(chat.draft.as_deref(), Out::long);
        }
        RecordKey::Message(id) => {
            let Some(message) = disk.messages.get(id) else {
                return false;
            };
            let record = &message.record;
            out.u32(record.chat.0);
            out.conversation(&message.conversation);
            out.flag(record.direction == Direction::Outbound);
            out.sender(&record.sender);
            out.name(record.sender_handle.as_deref());
            out.option(record.wire_id, Out::u8);
            out.u16(record.epoch);
            out.u8(record.message_type.to_byte());
            out.option(record.regarding.map(|id| id.0), Out::u32);
            out.option(record.bg_color, |out, color| out.bytes(&color));
            out.option(record.text_color, |out, color| out.bytes(&color));
            match record.status {
                CompletionStatus::Complete => out.u8(0),
                CompletionStatus::Partial {
                    present,
                    count,
                    finalized,
                } => {
                    out.u8(1);
                    out.u16(present);
                    out.u8(count);
                    out.flag(finalized);
                }
            }
            out.u8(match record.presence {
                Presence::Present => 0,
                Presence::GapPending => 1,
                Presence::Unavailable => 2,
            });
            let flags = &record.flags;
            out.u8(u8::from(flags.late)
                | u8::from(flags.notify) << 1
                | u8::from(flags.edited) << 2
                | u8::from(flags.deleted) << 3
                | u8::from(flags.forward_secret) << 4);
            out.u16(record.delivery.sent);
            out.u16(record.delivery.acked);
            out.u16(record.delivery.failed);
            out.option(record.link, |out, link| {
                out.option(link.rssi_dbm, Out::i16);
                out.option(link.snr_centibels, Out::i16);
                out.option(link.hop_count, Out::u8);
                out.u8(u8::from(link.authenticated) | u8::from(link.forward_secret) << 1);
            });
            out.option(record.time, Out::u32);
            out.u32(message.revision);
            out.u8(message.reactors.len() as u8);
            for reactor in &message.reactors {
                out.sender(&reactor.who.scope());
                out.flag(reactor.mine);
                match reactor.reaction {
                    Reaction::Other(cluster) => {
                        out.u8(OTHER_REACTION);
                        out.short(cluster.as_str().as_bytes());
                    }
                    reaction => out.u8(Reaction::ALL
                        .iter()
                        .position(|&r| r == reaction)
                        .unwrap_or_default() as u8),
                }
            }
            out.long(&message.body);
        }
        RecordKey::Peer(peer) => {
            let Some(peer) = disk.peers.get(peer) else {
                return false;
            };
            let record = &peer.record;
            out.u32(record.id.0);
            out.name(record.name.as_deref());
            out.short(&record.identity);
            out.option(record.last_heard, Out::u32);
            out.option(record.route.as_ref(), |out, route| {
                out.u8(route.len() as u8);
                for hint in route {
                    out.bytes(&hint.0);
                }
            });
            out.flag(record.forward_secrecy);
            out.flag(record.saved);
            out.u64(peer.heard);
            out.flag(record.linked);
            out.name(record.alias.as_deref());
        }
        RecordKey::Channel(tag) => {
            let Some(channel) = disk.channels.get(tag) else {
                return false;
            };
            out.short(channel.name.as_bytes());
            out.u8(match channel.access {
                ChannelAccess::Named => 0,
                ChannelAccess::Private => 1,
                ChannelAccess::Clear => 2,
            });
            out.option(channel.builtin, |out, builtin| {
                out.u8(match builtin {
                    BuiltinChannel::Public => 0,
                    BuiltinChannel::Emergency => 1,
                });
            });
        }
        RecordKey::DeviceLists => {
            let Some(lists) = &disk.device_lists else {
                return false;
            };
            out.bytes(lists);
        }
        RecordKey::RecentPicks => {
            let Some(picks) = &disk.recent_picks else {
                return false;
            };
            out.bytes(picks);
        }
    }
    true
}

/// Take one kept record into `disk`. One that does not decode is left
/// out.
pub(super) fn restore(disk: &mut Disk, key: &[u8], record: &[u8]) {
    let _ = restore_one(disk, key, record);
}

fn restore_one(disk: &mut Disk, key: &[u8], record: &[u8]) -> Option<()> {
    let (&kind, name) = key.split_first()?;
    let mut input = In(record);
    match kind {
        COUNTERS => {
            for reserved in &mut disk.reserved {
                *reserved = input.u32()?;
            }
        }
        DEVICE_LISTS => disk.device_lists = Some(record.to_vec()),
        RECENT_PICKS => disk.recent_picks = Some(record.to_vec()),
        CHECKPOINT => {
            let conversation = input.conversation()?;
            let checkpoint = StreamCheckpoint {
                conversation,
                next_id: input.u8()?,
                epoch: input.u16()?,
            };
            let used = input.u64()?;
            disk.checkpoints
                .insert((&conversation).into(), (checkpoint, used));
        }
        ARCHIVE => {
            let (code, rest) = name.split_first_chunk::<49>()?;
            let code = ConversationCode::from_bytes(*code)?;
            let &[wire_id, fragment] = rest else {
                return None;
            };
            disk.archives
                .insert((code, wire_id, fragment), record.to_vec());
        }
        CHAT_RECORD => {
            let id = u32::from_be_bytes(name.try_into().ok()?);
            let conversation = input.conversation()?;
            let name = input.name()?;
            let muted = input.flag()?;
            let unread = input.u32()?;
            let last_activity = input.option(In::u32)?;
            let activity = input.u64()?;
            let draft = input
                .option(|input| core::str::from_utf8(input.long()?).ok())?
                .map(String::from);
            disk.chats.insert(
                id,
                ChatEntry {
                    record: ChatRecord {
                        id: ChatId(id),
                        conversation,
                        name,
                        muted,
                        unread,
                        last_activity,
                        has_draft: draft.is_some(),
                    },
                    activity,
                    draft,
                },
            );
        }
        MESSAGE_RECORD => {
            let id = u32::from_be_bytes(name.try_into().ok()?);
            let message = message(id, &mut input)?;
            disk.messages.insert(id, message);
        }
        PEER_RECORD => {
            let key = PublicKey(name.try_into().ok()?);
            let id = PeerId(input.u32()?);
            let name = input.name()?;
            let identity = heapless::Vec::<u8, IDENTITY_MAX>::from_slice(input.short()?).ok()?;
            let last_heard = input.option(In::u32)?;
            let route = input.option(|input| {
                let count = input.u8()? as usize;
                let mut route = heapless::Vec::<RouterHint, ROUTE_MAX>::new();
                for _ in 0..count {
                    route.push(RouterHint(input.array()?)).ok()?;
                }
                Some(route)
            })?;
            let forward_secrecy = input.flag()?;
            let saved = input.flag()?;
            let heard = input.u64()?;
            // Kept from before provenance was: nothing says whose word it is.
            let linked = input.flag().unwrap_or(false);
            // Kept from before aliases were.
            let alias = input.name().unwrap_or(None);
            disk.peers.insert(
                key.0,
                PeerEntry {
                    record: PeerRecord {
                        id,
                        key,
                        name,
                        identity,
                        linked,
                        last_heard,
                        route,
                        forward_secrecy,
                        saved,
                        alias,
                    },
                    heard,
                },
            );
        }
        CHANNEL => {
            let tag = ChannelTag(name.try_into().ok()?);
            let name = text::<NAME_MAX>(input.short()?)?;
            let access = match input.u8()? {
                0 => ChannelAccess::Named,
                1 => ChannelAccess::Private,
                2 => ChannelAccess::Clear,
                _ => return None,
            };
            let builtin = input.option(|input| match input.u8()? {
                0 => Some(BuiltinChannel::Public),
                1 => Some(BuiltinChannel::Emergency),
                _ => None,
            })?;
            disk.channels.insert(
                tag.0,
                ChannelRecord {
                    tag,
                    name,
                    access,
                    builtin,
                },
            );
        }
        _ => return None,
    }
    Some(())
}

fn message(id: u32, input: &mut In<'_>) -> Option<MessageEntry> {
    let chat = ChatId(input.u32()?);
    let conversation = input.conversation()?;
    let direction = if input.flag()? {
        Direction::Outbound
    } else {
        Direction::Inbound
    };
    let sender = input.sender()?;
    let sender_handle = input.name()?;
    let wire_id = input.option(In::u8)?;
    let epoch = input.u16()?;
    let message_type = MessageType::from_byte(input.u8()?);
    let regarding = input.option(In::u32)?.map(MessageId);
    let bg_color = input.option(In::array)?;
    let text_color = input.option(In::array)?;
    let status = match input.u8()? {
        0 => CompletionStatus::Complete,
        1 => CompletionStatus::Partial {
            present: input.u16()?,
            count: input.u8()?,
            finalized: input.flag()?,
        },
        _ => return None,
    };
    let presence = match input.u8()? {
        0 => Presence::Present,
        1 => Presence::GapPending,
        2 => Presence::Unavailable,
        _ => return None,
    };
    let flags = input.u8()?;
    let flags = MessageFlags {
        late: flags & 1 != 0,
        notify: flags & 2 != 0,
        edited: flags & 4 != 0,
        deleted: flags & 8 != 0,
        forward_secret: flags & 16 != 0,
    };
    let delivery = Delivery {
        sent: input.u16()?,
        acked: input.u16()?,
        failed: input.u16()?,
    };
    let link = input.option(|input| {
        let rssi_dbm = input.option(In::i16)?;
        let snr_centibels = input.option(In::i16)?;
        let hop_count = input.option(In::u8)?;
        let flags = input.u8()?;
        Some(LinkInfo {
            rssi_dbm,
            snr_centibels,
            hop_count,
            authenticated: flags & 1 != 0,
            forward_secret: flags & 2 != 0,
        })
    })?;
    let time = input.option(In::u32)?;
    let revision = input.u32()?;
    let count = input.u8()?;
    let mut reactors = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let who = SenderCode::from(&input.sender()?);
        let mine = input.flag()?;
        let reaction = match input.u8()? {
            OTHER_REACTION => {
                Reaction::Other(Cluster::new(core::str::from_utf8(input.short()?).ok()?)?)
            }
            emote => *Reaction::ALL.get(usize::from(emote))?,
        };
        reactors.push(Reactor {
            who,
            mine,
            reaction,
        });
    }
    let body = core::str::from_utf8(input.long()?).ok()?;
    let body = String::from(record::clip(body, BODY_MAX));
    Some(MessageEntry {
        record: MessageRecord {
            id: MessageId(id),
            chat,
            direction,
            sender,
            sender_handle,
            wire_id,
            epoch,
            message_type,
            regarding,
            body_len: body.len() as u16,
            bg_color,
            text_color,
            status,
            presence,
            flags,
            delivery,
            link,
            time,
            reactions: Reactions::new(),
        },
        conversation,
        body,
        revision,
        reactors,
    })
}

/// Once every record is restored: the clock is set past every stamp, and
/// each identifier counter past every identifier given out and every
/// block kept. Returns the messages no chat holds, to be forgotten.
pub(super) fn settle(disk: &mut Disk) -> Vec<RecordKey> {
    let stamps = disk
        .chats
        .values()
        .map(|chat| chat.activity)
        .chain(disk.peers.values().map(|peer| peer.heard))
        .chain(disk.checkpoints.values().map(|(_, used)| *used));
    disk.clock = stamps.max().unwrap_or(0);

    let orphans: Vec<u32> = disk
        .messages
        .iter()
        .filter(|(_, message)| !disk.chats.contains_key(&message.record.chat.0))
        .map(|(&id, _)| id)
        .collect();
    for id in &orphans {
        disk.messages.remove(id);
    }

    let past = |highest: Option<u32>| highest.map_or(0, |id| id + 1);
    let used = [
        past(disk.chats.keys().max().copied()),
        past(disk.messages.keys().max().copied()),
        past(disk.peers.values().map(|peer| peer.record.id.0).max()),
    ];
    for kind in [CHAT, MESSAGE, PEER] {
        disk.ids[kind] = disk.reserved[kind].max(used[kind]);
        disk.reserved[kind] = disk.ids[kind];
    }
    orphans.into_iter().map(RecordKey::Message).collect()
}

/// `bytes` as text of at most `N` octets.
fn text<const N: usize>(bytes: &[u8]) -> Option<heapless::String<N>> {
    heapless::String::try_from(core::str::from_utf8(bytes).ok()?).ok()
}

struct Out<'a>(&'a mut Vec<u8>);

impl Out<'_> {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn i16(&mut self, value: i16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn flag(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// At most 255 octets, after their length.
    fn short(&mut self, bytes: &[u8]) {
        let bytes = &bytes[..bytes.len().min(usize::from(u8::MAX))];
        self.u8(bytes.len() as u8);
        self.bytes(bytes);
    }

    /// At most 65,535 octets, after their length.
    fn long(&mut self, text: &str) {
        let bytes = &text.as_bytes()[..text.len().min(usize::from(u16::MAX))];
        self.u16(bytes.len() as u16);
        self.bytes(bytes);
    }

    fn name(&mut self, name: Option<&str>) {
        self.option(name, |out, name| out.short(name.as_bytes()));
    }

    fn option<T>(&mut self, value: Option<T>, put: impl FnOnce(&mut Self, T)) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                put(self, value);
            }
        }
    }

    fn conversation(&mut self, conversation: &ConversationKey) {
        match conversation {
            ConversationKey::Direct { peer } => {
                self.u8(1);
                self.bytes(&peer.0);
            }
            ConversationKey::ChannelGroup { channel } => {
                self.u8(2);
                self.bytes(&channel.0);
            }
            ConversationKey::ChannelDirect { channel, peer } => {
                self.u8(3);
                self.bytes(&channel.0);
                self.bytes(&peer.0);
            }
            ConversationKey::Room { room } => {
                self.u8(4);
                self.bytes(&room.0);
            }
        }
    }

    fn sender(&mut self, sender: &SenderScope) {
        match sender {
            SenderScope::Local => self.u8(0),
            SenderScope::Peer(key) => {
                self.u8(1);
                self.bytes(&key.0);
            }
            SenderScope::ClaimedMember(hint) => {
                self.u8(2);
                self.bytes(&hint.0);
            }
        }
    }
}

struct In<'a>(&'a [u8]);

impl<'a> In<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (taken, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(taken)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    fn i16(&mut self) -> Option<i16> {
        self.array().map(i16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    fn flag(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn short(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    fn long(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// A name: absent, or present and valid.
    fn name(&mut self) -> Option<Option<Name>> {
        self.option(|input| text::<NAME_MAX>(input.short()?))
    }

    /// An optional value: `None` when it does not decode, `Some(None)` when
    /// it is absent.
    fn option<T>(&mut self, take: impl FnOnce(&mut Self) -> Option<T>) -> Option<Option<T>> {
        match self.u8()? {
            0 => Some(None),
            1 => take(self).map(Some),
            _ => None,
        }
    }

    fn conversation(&mut self) -> Option<ConversationKey> {
        Some(match self.u8()? {
            1 => ConversationKey::Direct {
                peer: PublicKey(self.array()?),
            },
            2 => ConversationKey::ChannelGroup {
                channel: ChannelTag(self.array()?),
            },
            3 => ConversationKey::ChannelDirect {
                channel: ChannelTag(self.array()?),
                peer: PublicKey(self.array()?),
            },
            4 => ConversationKey::Room {
                room: PublicKey(self.array()?),
            },
            _ => return None,
        })
    }

    fn sender(&mut self) -> Option<SenderScope> {
        Some(match self.u8()? {
            0 => SenderScope::Local,
            1 => SenderScope::Peer(PublicKey(self.array()?)),
            2 => SenderScope::ClaimedMember(NodeHint(self.array()?)),
            _ => return None,
        })
    }
}
