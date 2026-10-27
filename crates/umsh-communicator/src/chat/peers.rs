//! Peers: the nodes the chats hear from, the ones the device keeps
//! (`PROP_DEV_PEERS`), and what the interface asks of them.
//!
//! The store keeps who a node says it is and whether it is saved. How it
//! was last heard—how far, how strongly, how long ago on the board's
//! clock—is kept here, in memory, for the nodes heard most recently.

use core::fmt::Write as _;

use umsh_core::{NodeHint, PublicKey, RouterHint, base58};
use umsh_mac::SendOptions;
use umsh_node::{NodeCapabilities, NodeIdentityPayload, NodeRole, PING_MIC_SIZE};
use umsh_text::node_adapter::{RxSummary, channel_reach, with_flood_reach};
use umsh_text::{ConversationKey, SenderScope};
use umsh_uri::UmshUri;
use umsh_ux_communicator::avatar::{AvatarStyle, PeerShape};
use umsh_ux_communicator::heapless::{String, Vec};
use umsh_ux_communicator::model::{
    self, Age, Card, ChatSummary, Contact, ContactUri, Heard, MAX_HEARD, MAX_PEERS, Member,
    NodeEvent, PeerDetail, PeerEntry, PeerSummary, Sender, word_match,
};
use umsh_ux_communicator::text::SharedText;

use super::{Chats, FLOOD_HOPS, address, cut, unnamed_member};
use crate::ids::{ChatId, MessageId, PeerId};
use crate::record::{ChatChange, IDENTITY_MAX, PeerChange, PeerFilter, PeerRecord};
use crate::store::ChatStore;
use crate::task::{Command, Secrecy};

/// How many nodes' links are kept. Past it, the one heard longest ago
/// goes.
const LINKS_KEPT: usize = 64;

/// How long a link says where a node is. Past it, how far away the node
/// is and how strongly it came in are no longer shown, until it is heard
/// again.
const LINK_FRESH_MS: u64 = 30 * 60 * 1_000;

/// What a peer invitation starts with.
const INVITATION: &str = "umsh:n:";

/// A node's link, and what its identity bundle says of it when the bundle
/// holds up.
pub(crate) struct NodeLink {
    pub key: PublicKey,
    pub bundle: Option<Bundle>,
}

/// An identity bundle that parses, and whose signature, if it has one, is
/// its key's.
pub(crate) struct Bundle {
    pub identity: NodeIdentityPayload,
    /// The bytes it came as, which a signed one is kept as.
    pub payload: alloc::vec::Vec<u8>,
    pub signed: bool,
}

/// Where a session with forward secrecy with a peer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Session {
    Asked,
    Held,
}

/// How a node was last heard.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Link {
    /// Radio links the frame crossed, the last one into this device
    /// included.
    hop_count: Option<u8>,
    rssi_dbm: Option<i16>,
    snr_centibels: Option<i16>,
    /// When, on the board's clock.
    at_ms: u64,
}

impl Link {
    /// How many hops away the node is: one when heard directly.
    pub fn hops(&self) -> Option<u8> {
        self.hop_count
    }

    fn direct(&self) -> bool {
        self.hop_count == Some(1)
    }

    /// How strongly it came in, when it came directly.
    pub(super) fn direct_signal(&self) -> Option<model::Signal> {
        let signal = model::Signal {
            rssi: self.rssi_dbm?,
            snr: self.snr_centibels?,
        };
        self.direct().then_some(signal)
    }

    /// Whether it still says where the node is.
    fn placed(&self) -> bool {
        self.hop_count.is_some() || self.rssi_dbm.is_some() || self.snr_centibels.is_some()
    }
}

impl<S: ChatStore> Chats<S> {
    // ─── Hearing ─────────────────────────────────────────────────────

    /// Notes how `key` was just heard.
    pub(super) fn hear(
        &mut self,
        key: &PublicKey,
        rx: &RxSummary,
        now_ms: u64,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        if !self.links.contains_key(&key.0)
            && self.links.len() >= LINKS_KEPT
            && let Some(oldest) = self
                .links
                .iter()
                .min_by_key(|(_, link)| link.at_ms)
                .map(|(key, _)| *key)
        {
            self.links.remove(&oldest);
        }
        self.links.insert(
            key.0,
            Link {
                hop_count: rx.hop_count,
                rssi_dbm: rx.rssi_dbm,
                snr_centibels: rx.snr_centibels,
                at_ms: now_ms,
            },
        );
        self.shown_changed(key, events);
        // What was heard can have taught the device node a route.
        if self.routed(key) {
            self.read_route(*key);
        }
    }

    /// Forgets where nodes not heard for [`LINK_FRESH_MS`] were heard
    /// from, keeping when.
    pub(super) fn lapse_links(&mut self, now_ms: u64, events: &mut dyn FnMut(NodeEvent)) {
        let lapsed: alloc::vec::Vec<[u8; 32]> = self
            .links
            .iter_mut()
            .filter(|(_, link)| link.placed() && now_ms.saturating_sub(link.at_ms) >= LINK_FRESH_MS)
            .map(|(key, link)| {
                link.hop_count = None;
                link.rssi_dbm = None;
                link.snr_centibels = None;
                *key
            })
            .collect();
        for key in lapsed {
            self.shown_changed(&PublicKey(key), events);
        }
    }

    /// What is shown of `key` changed: their row, when they are a saved
    /// peer, and their chat.
    fn shown_changed(&self, key: &PublicKey, events: &mut dyn FnMut(NodeEvent)) {
        if let Ok(Some(kept)) = self.store.peer(key)
            && kept.saved
        {
            events(NodeEvent::PeerChanged(kept.id.0));
        }
        if let Some(chat) = self.store.chat_for(&ConversationKey::Direct { peer: *key }) {
            events(NodeEvent::ChatChanged(chat.0));
        }
    }

    /// Takes a node's identity, as it claims it, from `payload`, a frame
    /// only its key could have sent or that its key signed.
    #[allow(clippy::too_many_arguments)]
    pub fn identify(
        &mut self,
        key: PublicKey,
        identity: &NodeIdentityPayload,
        payload: &[u8],
        rx: &RxSummary,
        now_ms: u64,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        self.hear(&key, rx, now_ms, events);
        self.learn(key, identity, payload, true, time, events);
    }

    /// Keeps what `identity`, parsed from `payload`, says of the node
    /// `key`: its own word when `linked`, else someone else's, which never
    /// replaces its own. A signed payload is kept whole, to pass on.
    pub fn learn(
        &mut self,
        key: PublicKey,
        identity: &NodeIdentityPayload,
        payload: &[u8],
        linked: bool,
        time: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let before = self.store.peer(&key).ok().flatten();
        let kind = [identity.role.as_byte(), identity.capabilities.bits()];
        let kept = if identity.signature.is_some() && payload.len() <= IDENTITY_MAX {
            payload
        } else {
            &kind[..]
        };
        let heard = PeerChange::Heard {
            at: time,
            name: identity.name.as_deref(),
            identity: Some(kept),
            linked,
        };
        let Ok(id) = self.store.update_peer(&key, heard) else {
            return;
        };
        let after = self.store.peer(&key).ok().flatten();
        if after.as_ref().is_some_and(|after| after.saved) {
            events(NodeEvent::PeerChanged(id.0));
        }
        let renamed =
            before.as_ref().map(|before| &before.name) != after.as_ref().map(|after| &after.name);
        if before.is_none() || renamed {
            // Members known by their hints may be this node.
            events(NodeEvent::IdentitiesLearned);
            if let Some(chat) = self.store.chat_for(&ConversationKey::Direct { peer: key }) {
                events(NodeEvent::ChatChanged(chat.0));
            }
        }
    }

    /// How long ago `key` was heard, in seconds: on the board's clock when
    /// it was heard since the board started, else by the wall clock.
    pub(super) fn heard_ago(
        &self,
        key: &PublicKey,
        kept: Option<&PeerRecord>,
        now_ms: u64,
        wall: Option<u32>,
    ) -> Option<u32> {
        if let Some(link) = self.links.get(&key.0) {
            return Some(
                u32::try_from(now_ms.saturating_sub(link.at_ms) / 1_000).unwrap_or(u32::MAX),
            );
        }
        Some(wall?.saturating_sub(kept?.last_heard?))
    }

    /// The one known peer whose hint is `hint`, when only one is.
    pub(super) fn only_peer_with(&self, hint: NodeHint) -> Option<PublicKey> {
        let mut keys = self.store.peers_with_hint(hint);
        let key = keys.next()?;
        keys.next().is_none().then_some(key)
    }

    /// The known node a repeater's `hint` most plausibly names: the one it
    /// could be that forwards, else the one it could be at all. Two octets
    /// never prove which node it was.
    pub(super) fn name_router_hint(&self, hint: RouterHint) -> Option<PeerRecord> {
        let candidates: alloc::vec::Vec<PeerRecord> = self
            .store
            .peers_with_router_hint(hint)
            .filter_map(|key| self.store.peer(&key).ok().flatten())
            .collect();
        let mut forwarding = candidates.iter().filter(|kept| forwards(kept));
        if let (Some(only), None) = (forwarding.next(), forwarding.next()) {
            return Some(only.clone());
        }
        match candidates.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        }
    }

    /// How a repeater that forwarded under `hint` is shown: as the node it
    /// most plausibly is, else by the hint alone.
    pub(super) fn repeater(&self, hint: RouterHint) -> Option<model::Repeater> {
        let (name, avatar, known) = match self.name_router_hint(hint) {
            Some(kept) => (
                name(&kept.key, Some(&kept)),
                avatar(&kept.key, Some(&kept)),
                Some(SharedText::new(self.heap, &address(&kept.key.0))?),
            ),
            None => {
                let mut text = String::<32>::new();
                _ = write!(text, "{hint}");
                let avatar = AvatarStyle::router_hint(&text);
                (text, avatar, None)
            }
        };
        Some(model::Repeater {
            name: SharedText::new(self.heap, &name)?,
            avatar,
            address: known,
            hint: hint.0,
        })
    }

    // ─── Saved peers ─────────────────────────────────────────────────

    /// The device keeps exactly `keys` as its peers, which the store's
    /// saved peers follow.
    pub fn hold_peers(&mut self, keys: &[[u8; 32]], events: &mut dyn FnMut(NodeEvent)) {
        if self.saved == keys {
            return;
        }
        self.saved.clear();
        self.saved.extend_from_slice(keys);
        for key in keys {
            let key = PublicKey(*key);
            if self
                .store
                .peer(&key)
                .ok()
                .flatten()
                .is_some_and(|kept| kept.saved)
            {
                continue;
            }
            if let Ok(id) = self
                .store
                .update_peer(&key, PeerChange::Save { name: None })
            {
                events(NodeEvent::PeerChanged(id.0));
            }
        }
        let gone: alloc::vec::Vec<PeerRecord> = self
            .store
            .peers(PeerFilter::Saved)
            .flatten()
            .filter(|kept| !keys.contains(&kept.key.0))
            .collect();
        for kept in gone {
            if self
                .store
                .update_peer(&kept.key, PeerChange::Unsave)
                .is_ok()
            {
                events(NodeEvent::PeerRemoved(kept.id.0));
            }
        }
    }

    /// Fills `peers` with the saved peers, most recently heard first.
    pub fn peers(&self, peers: &mut model::Peers, now_ms: u64, wall: Option<u32>) {
        let mut saved: alloc::vec::Vec<(Option<u32>, PeerRecord)> = self
            .store
            .peers(PeerFilter::Saved)
            .flatten()
            .map(|kept| (self.heard_ago(&kept.key, Some(&kept), now_ms, wall), kept))
            .collect();
        saved.sort_by_key(|(ago, _)| ago.unwrap_or(u32::MAX));
        for (ago, kept) in saved.iter().take(MAX_PEERS) {
            _ = peers.push(self.peer_summary(kept, *ago));
        }
    }

    fn peer_summary(&self, kept: &PeerRecord, ago: Option<u32>) -> PeerSummary {
        let link = self.links.get(&kept.key.0);
        PeerSummary {
            id: kept.id.0,
            avatar: avatar(&kept.key, Some(kept)),
            name: name(&kept.key, Some(kept)),
            hops: link.and_then(Link::hops),
            signal: link
                .filter(|link| link.direct())
                .and_then(|link| link.snr_centibels)
                .map(bars),
            heard: ago.map(short_age).unwrap_or_default(),
        }
    }

    /// The saved peer `peer`.
    pub(super) fn saved_peer(&self, peer: model::PeerId) -> Option<PeerRecord> {
        self.store
            .peers(PeerFilter::Saved)
            .flatten()
            .find(|kept| kept.id == PeerId(peer))
    }

    pub fn peer_detail(
        &self,
        peer: model::PeerId,
        now_ms: u64,
        wall: Option<u32>,
    ) -> Option<PeerDetail> {
        let kept = self.saved_peer(peer)?;
        Some(PeerDetail {
            address: address(&kept.key.0),
            route: self
                .peer_route(peer, now_ms)
                .map(|route| model::route_text(&route)),
            heard: self
                .heard_ago(&kept.key, Some(&kept), now_ms, wall)
                .map(long_age)
                .unwrap_or_default(),
            forward_secrecy: kept.forward_secrecy,
            alias: kept.alias.as_deref().map(cut),
            advertised: kept.name.as_deref().map(cut),
        })
    }

    /// Keeps `member` among the saved peers, called by the name they gave
    /// when nothing else names them. Returns their key, for the device to
    /// keep too, and how the Peers list shows them.
    pub fn save_peer(
        &mut self,
        member: &Member,
        now_ms: u64,
        wall: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<(PublicKey, PeerSummary)> {
        let key = PublicKey(base58::decode(member.address.as_ref()?.as_bytes()).ok()?);
        let kept = self.store.peer(&key).ok().flatten();
        let lettering = address(&key.0);
        let given = member.sender.name.as_str();
        let name = (kept.as_ref().is_none_or(|kept| kept.name.is_none())
            && given != unnamed_member(lettering.get(..4).unwrap_or_default()).as_str())
        .then_some(given);
        let id = self
            .store
            .update_peer(&key, PeerChange::Save { name })
            .ok()?;
        if !self.saved.contains(&key.0) {
            self.saved.push(key.0);
        }
        events(NodeEvent::PeerChanged(id.0));
        let kept = self.store.peer(&key).ok().flatten()?;
        let ago = self.heard_ago(&key, Some(&kept), now_ms, wall);
        Some((key, self.peer_summary(&kept, ago)))
    }

    /// No longer keeps the saved peer `peer`. Returns their key, for the
    /// device to let go of too.
    pub fn forget_peer(
        &mut self,
        peer: model::PeerId,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<PublicKey> {
        let kept = self.saved_peer(peer)?;
        self.store.update_peer(&kept.key, PeerChange::Unsave).ok()?;
        self.saved.retain(|key| *key != kept.key.0);
        self.forget_way(&kept.key);
        events(NodeEvent::PeerRemoved(peer));
        Some(kept.key)
    }

    /// The saved peer at the other end of the direct chat `chat`.
    pub fn chat_peer(&self, chat: model::ChatId) -> Option<model::PeerId> {
        let ConversationKey::Direct { peer } = self.conversation(chat)? else {
            return None;
        };
        let kept = self.store.peer(&peer).ok().flatten()?;
        kept.saved.then_some(kept.id.0)
    }

    /// Keeps whether `peer` prefers forward secrecy.
    pub fn set_forward_secrecy(
        &mut self,
        peer: model::PeerId,
        on: bool,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        if self
            .store
            .update_peer(&kept.key, PeerChange::ForwardSecrecy(on))
            .is_ok()
        {
            events(NodeEvent::PeerChanged(peer));
        }
        if on {
            self.keep_secrecy(kept.key);
        } else if let Some(was) = self.secrecy.remove(&kept.key.0) {
            self.commands.push_back(Command::EndSecrecy {
                peer: kept.key,
                options: secrecy_options(),
            });
            if was == Session::Held {
                self.shown_changed(&kept.key, events);
            }
        }
    }

    /// Calls the saved peer `peer` `alias` here, or by its own name again
    /// when `None`.
    pub fn set_peer_alias(
        &mut self,
        peer: model::PeerId,
        alias: Option<&str>,
        events: &mut dyn FnMut(NodeEvent),
    ) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        if self
            .store
            .update_peer(&kept.key, PeerChange::Alias(alias))
            .is_err()
        {
            return;
        }
        events(NodeEvent::PeerChanged(peer));
        // Its chat and the members it may be are shown by it.
        events(NodeEvent::IdentitiesLearned);
        if let Some(chat) = self
            .store
            .chat_for(&ConversationKey::Direct { peer: kept.key })
        {
            events(NodeEvent::ChatChanged(chat.0));
        }
    }

    /// Whether what is sent in `conversation` now goes under a session
    /// with forward secrecy.
    pub fn holds_secrecy(&self, conversation: &ConversationKey) -> bool {
        match conversation {
            ConversationKey::Direct { peer } => self.secrecy.get(&peer.0) == Some(&Session::Held),
            _ => false,
        }
    }

    /// Asks `peer` for a session with forward secrecy when they prefer one
    /// and none is asked for or held.
    pub(super) fn keep_secrecy(&mut self, peer: PublicKey) {
        let prefers = self
            .store
            .peer(&peer)
            .ok()
            .flatten()
            .is_some_and(|kept| kept.saved && kept.forward_secrecy);
        if prefers && !self.secrecy.contains_key(&peer.0) {
            self.secrecy.insert(peer.0, Session::Asked);
            self.commands.push_back(Command::StartSecrecy {
                peer,
                options: secrecy_options(),
            });
        }
    }

    /// Takes word of a session with forward secrecy with `peer`. One that
    /// was held and ended is asked for again while they prefer it; one
    /// that could not be had is asked for again when next needed.
    pub fn secrecy(&mut self, peer: PublicKey, change: Secrecy, events: &mut dyn FnMut(NodeEvent)) {
        let was = match change {
            Secrecy::Established => self.secrecy.insert(peer.0, Session::Held),
            Secrecy::Ended | Secrecy::Failed => self.secrecy.remove(&peer.0),
        };
        let held = change == Secrecy::Established;
        if held != (was == Some(Session::Held)) {
            self.shown_changed(&peer, events);
        }
        if change == Secrecy::Ended && was == Some(Session::Held) {
            self.keep_secrecy(peer);
        }
    }

    /// Asks the device node to ping `peer`.
    pub fn ping(&mut self, peer: model::PeerId, now_ms: u64) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        self.pinged(kept.key, now_ms);
        // By full key, in case the peer has not registered us.
        let options = with_flood_reach(SendOptions::default(), FLOOD_HOPS)
            .with_full_source()
            .with_trace_route()
            .with_trace_signal()
            .with_mic_size(PING_MIC_SIZE);
        self.commands.push_back(Command::Ping {
            peer: kept.key,
            options,
        });
    }

    /// Asks the saved peer `peer` for their identity, which arrives as
    /// any identity does.
    pub fn request_peer_identity(&mut self, peer: model::PeerId) {
        let Some(kept) = self.saved_peer(peer) else {
            return;
        };
        // By full key, in case the peer has not registered us.
        let options = with_flood_reach(SendOptions::default(), FLOOD_HOPS).with_full_source();
        self.commands.push_back(Command::AskPeer {
            peer: kept.key,
            options,
        });
    }

    /// What the chats ask of the device node next.
    pub fn command(&mut self) -> Option<Command> {
        self.commands.pop_front()
    }

    // ─── Finding peers ───────────────────────────────────────────────

    /// The direct chat with the node at `address`, made if there is none.
    /// A new chat is called `name` when nothing else names the node.
    pub fn direct_chat(
        &mut self,
        address_text: &str,
        name_given: &str,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<ChatSummary> {
        let key = PublicKey(base58::decode(address_text.as_bytes()).ok()?);
        let conversation = ConversationKey::Direct { peer: key };
        let chat = match self.store.chat_for(&conversation) {
            Some(chat) => chat,
            None => {
                let unnamed = self
                    .store
                    .peer(&key)
                    .ok()
                    .flatten()
                    .is_none_or(|kept| kept.shown_name().is_none());
                let lettering = address(&key.0);
                let name = (unnamed
                    && !name_given.trim().is_empty()
                    && name_given != lettering.get(..4).unwrap_or_default())
                .then_some(name_given);
                let open = ChatChange::Open { conversation, name };
                let chat = self.store.update_chat(ChatId(0), open).ok()?;
                events(NodeEvent::ChatChanged(chat.0));
                chat
            }
        };
        self.chat(chat.0)
    }

    /// What `text`, typed as an address or a peer invitation, names so far.
    pub fn inspect_peer(&self, text: &str) -> PeerEntry {
        let text = text.trim();
        if text.is_empty() {
            return PeerEntry::Empty;
        }
        let (digits, identity) = match text.strip_prefix(INVITATION) {
            Some(rest) => match rest.split_once(':') {
                Some((digits, identity)) => (digits, Some(identity)),
                None => (rest, None),
            },
            // An invitation still being typed.
            None if INVITATION.starts_with(text) => ("", None),
            None => (text, None),
        };
        if digits.is_empty() {
            return PeerEntry::Partial {
                avatar: None,
                hint: String::new(),
                missing: base58::ENCODED_LEN as u8,
            };
        }
        if digits.len() == base58::ENCODED_LEN {
            let Ok(key) = base58::decode(digits.as_bytes()) else {
                return PeerEntry::Invalid;
            };
            let key = PublicKey(key);
            let kept = self.store.peer(&key).ok().flatten();
            // A known node's name here; else the one its invitation gives.
            let named = kept.as_ref().and_then(PeerRecord::shown_name).map(cut);
            let invited = identity
                .and_then(|identity| self.bundle(&key, identity))
                .and_then(|bundle| bundle.identity.name)
                .map(|name| cut(&name));
            return PeerEntry::Complete {
                avatar: avatar(&key, kept.as_ref()),
                hint: cut(&digits[..4]),
                address: cut(digits),
                name: named.or(invited),
            };
        }
        let Ok((low, high)) = base58::prefix_bounds(digits.as_bytes()) else {
            return PeerEntry::Invalid;
        };
        // The avatar shows once the characters settle the hint.
        let settled = low[..3] == high[..3];
        let mut hint: String<8> = String::new();
        if settled {
            _ = write!(hint, "{}", NodeHint([low[0], low[1], low[2]]));
        }
        PeerEntry::Partial {
            avatar: settled
                .then(|| AvatarStyle::peer([low[0], low[1], low[2]], &hint, PeerShape::Hexagon)),
            hint,
            missing: (base58::ENCODED_LEN - digits.len()) as u8,
        }
    }

    /// The node `text` links to, when the whole of it is a node's link.
    pub(super) fn node_link(&self, text: &str) -> Option<NodeLink> {
        let Ok(UmshUri::Node(node)) = umsh_uri::parse_umsh_str(text.trim()) else {
            return None;
        };
        let key = node.public_key;
        Some(NodeLink {
            key,
            bundle: node.identity_data.and_then(|data| self.bundle(&key, data)),
        })
    }

    /// What a message whose whole text is `body` offers as a card: the
    /// channel it invites to, or the node it introduces.
    pub(super) fn card_in(&self, body: &str) -> Option<Card> {
        if let Some(invite) = self.invite_in(body) {
            return Some(Card::Channel(invite));
        }
        let link = self.node_link(body)?;
        let kept = self.store.peer(&link.key).ok().flatten();
        // Called as it is kept here; else as its link calls it.
        let named = kept.as_ref().and_then(PeerRecord::shown_name);
        let given = link.bundle.and_then(|bundle| bundle.identity.name);
        let name = match named.or(given.as_deref()) {
            Some(name) => SharedText::new(self.heap, name)?,
            None => SharedText::new(self.heap, &name(&link.key, None))?,
        };
        Some(Card::Contact(Contact {
            key: link.key.0,
            name,
            avatar: avatar(&link.key, kept.as_ref()),
        }))
    }

    /// The identity bundle `data` carries for `key`, when it parses and
    /// any signature it has is `key`'s.
    fn bundle(&self, key: &PublicKey, data: &str) -> Option<Bundle> {
        let payload = umsh_uri::decode_base58_bytes(data).ok()?;
        let identity = NodeIdentityPayload::from_bytes(&payload).ok()?;
        let signed = match &identity.signature {
            None => false,
            Some(signature) => {
                let covered = &payload[..payload.len() - signature.len()];
                if !(self.crypto.verify)(key, covered, signature) {
                    return None;
                }
                true
            }
        };
        Some(Bundle {
            identity,
            payload,
            signed,
        })
    }

    /// What is known of the node `text` names, a node's link or its bare
    /// address. A link's identity is kept as heard, as its key's own word
    /// only when its key signed it.
    pub fn known_member(
        &mut self,
        text: &str,
        now_ms: u64,
        wall: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Option<Member> {
        let text = text.trim();
        let key = match self.node_link(text) {
            Some(link) => {
                let me = self.facade.as_ref().map(|facade| facade.local_key());
                if let Some(bundle) = &link.bundle
                    && me != Some(link.key)
                {
                    self.learn(
                        link.key,
                        &bundle.identity,
                        &bundle.payload,
                        bundle.signed,
                        None,
                        events,
                    );
                }
                link.key
            }
            None => PublicKey(base58::decode(text.as_bytes()).ok()?),
        };
        Some(self.member_of(&key, now_ms, wall))
    }

    /// Takes the contact a contact exchange brought, `signed` when its
    /// node identity is signed by `key`. It is kept as heard, never saved.
    #[cfg(feature = "software-crypto")]
    #[allow(clippy::too_many_arguments)]
    pub fn exchanged(
        &mut self,
        key: PublicKey,
        identity: &NodeIdentityPayload,
        payload: &[u8],
        signed: bool,
        now_ms: u64,
        wall: Option<u32>,
        events: &mut dyn FnMut(NodeEvent),
    ) -> Member {
        self.learn(key, identity, payload, signed, wall, events);
        self.member_of(&key, now_ms, wall)
    }

    /// What is known of the node `key`, under the name it is kept by.
    pub(super) fn member_of(&self, key: &PublicKey, now_ms: u64, wall: Option<u32>) -> Member {
        let kept = self.store.peer(key).ok().flatten();
        let mut hint = String::new();
        _ = write!(hint, "{}", key.hint());
        Member {
            sender: Sender {
                name: cut(&name(key, kept.as_ref())),
                avatar: avatar(key, kept.as_ref()),
            },
            hint,
            address: Some(address(&key.0)),
            heard: self
                .heard_ago(key, kept.as_ref(), now_ms, wall)
                .map(short_age)
                .unwrap_or_default(),
            saved: kept.is_some_and(|kept| kept.saved),
        }
    }

    /// The saved peer at `address`.
    pub fn saved_at(&self, address: &str) -> Option<model::PeerId> {
        let key = PublicKey(base58::decode(address.as_bytes()).ok()?);
        let kept = self.store.peer(&key).ok().flatten()?;
        kept.saved.then_some(kept.id.0)
    }

    /// The link that shares the saved peer `peer`, carrying their own
    /// signed identity when one is kept: what a receiver can check.
    pub fn contact_uri(&self, peer: model::PeerId) -> Option<ContactUri> {
        let kept = self.saved_peer(peer)?;
        let mut uri = ContactUri::new();
        uri.push_str(INVITATION).ok()?;
        uri.push_str(&address(&kept.key.0)).ok()?;
        let signed = NodeIdentityPayload::from_bytes(&kept.identity)
            .is_ok_and(|identity| identity.signature.is_some());
        if signed {
            uri.push(':').ok()?;
            uri.push_str(&umsh_uri::encode_base58_bytes(&kept.identity))
                .ok()?;
        }
        Some(uri)
    }

    /// Nodes heard but not saved whose names have a word starting with
    /// `query`, most recently heard first.
    pub fn find_heard(&self, query: &str, now_ms: u64, wall: Option<u32>) -> Vec<Heard, MAX_HEARD> {
        let mut found = Vec::new();
        for kept in self.store.peers(PeerFilter::Heard).flatten() {
            let Some(name) = kept.shown_name() else {
                continue;
            };
            if word_match(name, query).is_none() {
                continue;
            }
            let link = self.links.get(&kept.key.0);
            let heard = Heard {
                address: address(&kept.key.0),
                avatar: avatar(&kept.key, Some(&kept)),
                name: cut(name),
                distance: distance(link.and_then(Link::hops)),
                age: self
                    .heard_ago(&kept.key, Some(&kept), now_ms, wall)
                    .map(short_age)
                    .unwrap_or_default(),
            };
            if found.push(heard).is_err() {
                break;
            }
        }
        found
    }

    /// Asks the repeater that forwards under `hint` who it is, by way of
    /// the repeaters `before` it: with none, only the nodes in earshot, as
    /// one heard carrying our own frame is.
    pub fn identify_repeater(&mut self, hint: RouterHint, before: &[RouterHint]) {
        self.commands.push_back(Command::AskRepeater {
            hint,
            route: before.to_vec(),
        });
    }

    /// Asks the channel `message` came on for the identity of the member
    /// who sent it.
    pub fn request_identity(&mut self, chat: model::ChatId, message: model::MessageId) {
        let Some(ConversationKey::ChannelGroup { channel }) = self.conversation(chat) else {
            return;
        };
        let Ok(Some(record)) = self.store.message(MessageId(message)) else {
            return;
        };
        let SenderScope::ClaimedMember(hint) = record.sender else {
            return;
        };
        let Some(facade) = &self.facade else {
            return;
        };
        let channels = facade.channels();
        let Some(key) = channels.key(&channel) else {
            return;
        };
        let reach = channel_reach(channels, &self.policy.well_known, &channel, FLOOD_HOPS);
        // The full source, so the member can answer with a unicast.
        let options = with_flood_reach(SendOptions::default(), reach).with_full_source();
        self.commands.push_back(Command::AskChannel {
            channel: key,
            hint,
            options,
        });
    }
}

/// How a node is drawn: its hint's color, its address's first characters,
/// and the shape of what it says it is.
fn avatar(key: &PublicKey, kept: Option<&PeerRecord>) -> AvatarStyle {
    let lettering = address(&key.0);
    AvatarStyle::peer(
        key.hint().0,
        lettering.get(..4).unwrap_or_default(),
        shape(kept),
    )
}

/// What a node is called: its alias or its name, else its address's
/// first characters.
fn name(key: &PublicKey, kept: Option<&PeerRecord>) -> String<32> {
    match kept.and_then(PeerRecord::shown_name) {
        Some(name) => cut(name),
        None => cut(address(&key.0).get(..4).unwrap_or_default()),
    }
}

/// Whether a node forwards others' traffic, by the identity it is kept
/// with.
fn forwards(kept: &PeerRecord) -> bool {
    let Some(&[role, capabilities]) = kept.identity.get(..2) else {
        return false;
    };
    umsh_node::forwards(
        NodeRole::from_byte(role),
        NodeCapabilities::from_bits_truncate(capabilities),
    )
}

/// The outline of what a node says it is: a node that chats, a repeater
/// or bridge, or anything else, which a node known by nothing but its
/// address is too.
pub(super) fn shape(kept: Option<&PeerRecord>) -> PeerShape {
    let Some(&[role, capabilities]) = kept.and_then(|kept| kept.identity.get(..2)) else {
        return PeerShape::Hexagon;
    };
    match NodeRole::from_byte(role) {
        NodeRole::Repeater | NodeRole::Bridge => PeerShape::Triangle,
        NodeRole::Chat => PeerShape::Circle,
        _ if NodeCapabilities::from_bits_truncate(capabilities)
            .contains(NodeCapabilities::TEXT_MESSAGES) =>
        {
            PeerShape::Circle
        }
        _ => PeerShape::Hexagon,
    }
}

/// Of four bars, how strongly a node is heard, by the signal-to-noise
/// ratio in centibels.
fn bars(snr_centibels: i16) -> u8 {
    match snr_centibels {
        50.. => 4,
        0.. => 3,
        -50.. => 2,
        _ => 1,
    }
}

/// How far away a heard node is, as Find says it.
fn distance(hops: Option<u8>) -> String<12> {
    match hops {
        Some(1) => String::try_from("Nearby").unwrap_or_default(),
        Some(hops) => model::hops_text(hops),
        None => String::new(),
    }
}

/// `seconds` ago, as a list says it, such as `5m`.
pub(super) fn short_age(seconds: u32) -> Age {
    model::age(Some(0), Some(seconds))
}

/// `seconds` ago, as a peer's screen says it, such as `5 min ago`.
pub(super) fn long_age(seconds: u32) -> String<12> {
    const MINUTE: u32 = 60;
    const HOUR: u32 = 60 * MINUTE;
    const DAY: u32 = 24 * HOUR;
    const WEEK: u32 = 7 * DAY;
    let mut age = String::new();
    match seconds {
        0..MINUTE => _ = age.push_str("Just now"),
        MINUTE..HOUR => _ = write!(age, "{} min ago", seconds / MINUTE),
        HOUR..DAY => _ = write!(age, "{} hr ago", seconds / HOUR),
        DAY..WEEK if seconds < 2 * DAY => _ = age.push_str("1 day ago"),
        DAY..WEEK => _ = write!(age, "{} days ago", seconds / DAY),
        _ => _ = write!(age, "{} wk ago", seconds / WEEK),
    }
    age
}

/// How a session with forward secrecy is asked for and ended: by full key,
/// in case the peer has not registered us.
fn secrecy_options() -> SendOptions {
    with_flood_reach(SendOptions::default(), FLOOD_HOPS).with_full_source()
}
