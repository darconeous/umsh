//! The node behind a communicator's interface.
//!
//! Two halves: the device's settings through its own ULCP session
//! ([`Settings`]), and the chats, which the device node's received frames
//! feed and whose frames it sends (see [`crate::task`]).

use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::task::Poll;

use embassy_sync::waitqueue::WakerRegistration;

use umsh_core::{ChannelKey, PublicKey};
use umsh_text::chat::Seeds;
use umsh_text::node_adapter::{Departure, Sent};
use umsh_ulcp::profiles::VETTED;
use umsh_ulcp_admin::LocalPort;
use umsh_ux_communicator::avatar::AvatarStyle;
use umsh_ux_communicator::heapless::{String, Vec};
use umsh_ux_communicator::model::{
    ChannelEntry, ChatId, ChatSummary, Chats, ClockSettings, ClockSource, ContactUri, Details,
    EventQueue, Heard, Invite, KeyboardSettings, MAX_HEARD, MeetState, Member, Message, MessageId,
    Messages, NearbyId, Node, NodeEvent, PeerDetail, PeerEntry, PeerId, PeerSummary, Peers,
    RadioSettings, Reaction, Setting, ShareUri, Shareable,
};
use umsh_ux_communicator::picker::RecentText;
use umsh_ux_communicator::text::TextHeap;

use crate::chat::{ChannelCrypto, Chats as ChatHalf, Joined};
#[cfg(feature = "software-crypto")]
use crate::meet::Meeting;
use crate::memory::MemoryStore;
use crate::record::StoreError;
use crate::settings::Settings;
use crate::store::ChatStore;
use crate::task::{Arrival, Command};

/// How many events wait for the interface before they collapse into a
/// resync.
const EVENTS: usize = 16;

/// The board's clocks, as the node reads them.
pub trait Clock {
    /// Milliseconds on the board's monotonic clock.
    fn now_ms(&self) -> u64;
    /// The time in Unix seconds, once it is known.
    fn wall(&self) -> Option<u32>;
    /// Where the time came from, and when on [`Clock::now_ms`], while it
    /// is known.
    fn source(&self) -> Option<(ClockSource, u64)> {
        None
    }
}

/// A communicator's node, over the device's own ULCP session reached
/// through `P`, keeping its chats in `S`.
///
/// Every method borrows the node for the length of the call and no
/// longer, so the interface and the board's tasks can share it on one
/// executor.
pub struct CommunicatorNode<P, S = MemoryStore> {
    settings: RefCell<Settings<P>>,
    chats: RefCell<ChatHalf<S>>,
    /// Add peer's contact exchange.
    #[cfg(feature = "software-crypto")]
    meeting: RefCell<Meeting>,
    events: RefCell<EventQueue<EVENTS>>,
    clock: &'static dyn Clock,
    /// What the chats start with, once the device identity is known.
    seeds: Seeds,
    /// The chats have frames for the device node.
    work: Cell<bool>,
    worker: RefCell<WakerRegistration>,
}

impl<P: LocalPort, S: ChatStore> CommunicatorNode<P, S> {
    /// A node whose messages' text is kept on `heap`. Its chats start as
    /// the device identity once the device reports it, from `seeds`, which
    /// are random.
    pub fn new(
        port: P,
        store: S,
        crypto: ChannelCrypto,
        heap: TextHeap,
        clock: &'static dyn Clock,
        seeds: Seeds,
    ) -> Self {
        Self {
            settings: RefCell::new(Settings::new(port)),
            chats: RefCell::new(ChatHalf::new(store, crypto, heap)),
            #[cfg(feature = "software-crypto")]
            meeting: RefCell::new(Meeting::new()),
            events: RefCell::new(EventQueue::new()),
            clock,
            seeds,
            work: Cell::new(false),
            worker: RefCell::new(WakerRegistration::new()),
        }
    }

    pub fn clock(&self) -> &'static dyn Clock {
        self.clock
    }

    /// Sets this board's model id (`boards.json`), which a contact exchange
    /// shows the devices nearby.
    pub fn set_model(&self, model: u16) {
        #[cfg(feature = "software-crypto")]
        self.meeting.borrow_mut().set_model(model);
        #[cfg(not(feature = "software-crypto"))]
        let _ = model;
    }

    /// Whether the chats have started.
    pub fn started(&self) -> bool {
        self.chats.borrow().started()
    }

    /// Hands the device what is waiting and takes in what it sent. The
    /// board calls this after the interface has taken an input, whenever
    /// the port has something, and at [`CommunicatorNode::next_deadline`].
    ///
    /// The chats start here, as the device identity, as soon as the
    /// device has reported it, and hold the device's channels from then
    /// on.
    pub fn pump(&self) {
        let now_ms = self.clock.now_ms();
        let mut events = self.events.borrow_mut();
        let mut push = |event| events.push(event);
        let mut settings = self.settings.borrow_mut();
        settings.pump(now_ms, &mut push);
        if !settings.primed() {
            return;
        }
        let mut chats = self.chats.borrow_mut();
        if !chats.started()
            && let Some(key) = settings.key()
        {
            chats.start(PublicKey(*key), self.seeds, now_ms, &mut push);
        }
        chats.hold(settings.channels(), &mut push);
        for tag in settings.take_refused_joins() {
            chats.let_go(tag, &mut push);
        }
        chats.hold_peers(&settings.peers(), &mut push);
        chats.set_handle(&settings.device_name());
    }

    /// Takes what the device node received for the chats.
    pub fn arrive(&self, arrival: Arrival) {
        #[cfg(feature = "software-crypto")]
        let arrival = match arrival {
            Arrival::Meet {
                from,
                broadcast,
                rssi,
                body,
            } => {
                let now_ms = self.clock.now_ms();
                return self.with_meeting(|meeting, events| {
                    meeting.hear(now_ms, from, broadcast, rssi, &body, events)
                });
            }
            Arrival::MeetOpened(session) => {
                let now_ms = self.clock.now_ms();
                return self
                    .with_meeting(|meeting, events| meeting.opened(now_ms, session, events));
            }
            arrival => arrival,
        };
        self.with_chats(|chats, now_ms, time, events| match arrival {
            Arrival::Text(inbound) => chats.receive(inbound, now_ms, time, events),
            Arrival::Identity {
                key,
                identity,
                payload,
                rx,
            } => {
                chats.identify(key, &identity, &payload, &rx, now_ms, time, events);
            }
            Arrival::Pong {
                peer,
                round_trip_ms,
                rx,
            } => chats.pong(peer, round_trip_ms, &rx, now_ms, events),
            Arrival::Secrecy { peer, change } => chats.secrecy(peer, change, events),
            #[cfg(feature = "software-crypto")]
            Arrival::Meet { .. } | Arrival::MeetOpened(_) => {}
        });
    }

    /// Whether the chats wait on the device node for a channel's key: the
    /// device lists a channel by its tag alone.
    pub fn misses_channel_keys(&self) -> bool {
        self.chats.borrow().misses_keys()
    }

    /// Takes `keys`, those of the device node's channels.
    pub fn learn_channel_keys(&self, keys: &[ChannelKey]) {
        self.with_chats(|chats, _, _, events| {
            for key in keys {
                chats.learn_key(*key, events);
            }
        });
    }

    /// What the chats ask of the device node next, besides sending frames.
    pub fn command(&self) -> Option<Command> {
        #[cfg(feature = "software-crypto")]
        if let Some(command) = self.meeting.borrow_mut().command() {
            return Some(command);
        }
        self.chats.borrow_mut().command()
    }

    /// Advances the chats' timers.
    pub fn tick(&self) {
        self.with_chats(|chats, now_ms, time, events| chats.tick(now_ms, time, events));
    }

    /// Takes the word on the chats' frames in flight, and keeps the
    /// contact exchange's deadlines.
    pub fn service(&self) {
        self.with_chats(|chats, now_ms, time, events| chats.service(now_ms, time, events));
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            self.with_meeting(|meeting, events| meeting.tick(now_ms, events));
        }
    }

    /// When [`CommunicatorNode::service`] next has a contact-exchange
    /// deadline to keep.
    pub fn meet_deadline(&self) -> Option<u64> {
        #[cfg(feature = "software-crypto")]
        return self.meeting.borrow().deadline();
        #[cfg(not(feature = "software-crypto"))]
        None
    }

    /// The chats' next frame for the device node, or `None` while nothing
    /// may go. Send it with [`umsh_text::node_adapter::transmit`], then
    /// hand back how that went to [`CommunicatorNode::departed`].
    pub fn depart(&self) -> Option<Departure> {
        self.with_chats(|chats, now_ms, time, events| chats.depart(now_ms, time, events))
    }

    /// Takes how the device node took a frame. Returns whether it has room
    /// for more.
    pub fn departed(&self, departure: Departure, sent: Sent) -> bool {
        self.with_chats(|chats, now_ms, time, events| {
            chats.departed(departure, sent, now_ms, time, events)
        })
    }

    /// Waits until the interface has given the chats something to send.
    pub async fn work(&self) {
        poll_fn(|cx| {
            if self.work.take() {
                return Poll::Ready(());
            }
            self.worker.borrow_mut().register(cx.waker());
            Poll::Pending
        })
        .await;
    }

    fn wake(&self) {
        self.work.set(true);
        self.worker.borrow_mut().wake();
    }

    /// Runs `f` with the chats, the time, and the event queue.
    fn with_chats<R>(
        &self,
        f: impl FnOnce(&mut ChatHalf<S>, u64, Option<u32>, &mut dyn FnMut(NodeEvent)) -> R,
    ) -> R {
        let mut events = self.events.borrow_mut();
        f(
            &mut self.chats.borrow_mut(),
            self.clock.now_ms(),
            self.clock.wall(),
            &mut |event| events.push(event),
        )
    }

    /// Runs `f` with the contact exchange and the event queue, then takes
    /// in the contact an exchange it completed brought.
    #[cfg(feature = "software-crypto")]
    fn with_meeting(
        &self,
        f: impl FnOnce(&mut Meeting, &mut dyn FnMut(NodeEvent)) -> Option<umsh_node::meet::Exchanged>,
    ) {
        let theirs = {
            let mut events = self.events.borrow_mut();
            f(&mut self.meeting.borrow_mut(), &mut |event| {
                events.push(event)
            })
        };
        if let Some(theirs) = theirs {
            let member = self.with_chats(|chats, now_ms, time, events| {
                chats.exchanged(
                    theirs.key,
                    &theirs.identity,
                    &theirs.payload,
                    theirs.signed,
                    now_ms,
                    time,
                    events,
                )
            });
            let mut events = self.events.borrow_mut();
            self.meeting
                .borrow_mut()
                .exchanged_with(member, &mut |event| events.push(event));
        }
        if self.meeting.borrow().has_commands() {
            self.wake();
        }
    }

    /// The node identity payload a contact exchange sends: the device's
    /// own, signed, or failing that the name alone, unsigned.
    #[cfg(feature = "software-crypto")]
    fn own_identity(&self) -> alloc::vec::Vec<u8> {
        use umsh_node::{NodeCapabilities, NodeIdentityPayload, NodeRole};

        let settings = self.settings.borrow();
        if let Some(signed) = settings.identity() {
            return signed.to_vec();
        }
        let name = settings.device_name();
        let payload = NodeIdentityPayload {
            role: NodeRole::Chat,
            capabilities: NodeCapabilities::TEXT_MESSAGES,
            name: (!name.is_empty()).then(|| name.as_str().into()),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; crate::record::IDENTITY_MAX];
        payload
            .encode(&mut buf)
            .map_or_else(|_| alloc::vec::Vec::new(), |len| buf[..len].to_vec())
    }

    /// Whether events wait for the interface.
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    /// When [`CommunicatorNode::pump`] next has work of its own.
    pub fn next_deadline(&self) -> Option<u64> {
        self.settings.borrow().next_deadline()
    }

    /// Whether every setting has been read from the device once.
    pub fn primed(&self) -> bool {
        self.settings.borrow().primed()
    }

    /// Runs `f` with the port, such as to wait on it.
    pub fn with_port<R>(&self, f: impl FnOnce(&P) -> R) -> R {
        f(self.settings.borrow().port())
    }

    /// The device's lists as the store keeps them, laid out in `out`
    /// (see [`ChatStore::device_lists`]): what the board's device session
    /// starts from.
    pub fn device_lists<'b>(&self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, StoreError> {
        self.chats.borrow().store().device_lists(out)
    }

    /// The store keeps `record` as the device's lists, or forgets them
    /// with `None`, as the board's device session asks.
    pub fn keep_device_lists(&self, record: Option<&[u8]>) -> Result<(), StoreError> {
        self.chats
            .borrow_mut()
            .store_mut()
            .keep_device_lists(record)
    }

    /// Asks the device to hold the channel a join here holds already, and
    /// lets it go if it cannot be asked.
    fn joined(&self, joined: Option<Joined>) -> Option<ChatSummary> {
        let (summary, join) = joined?;
        if let Some((key, tag)) = join
            && !self.settings.borrow_mut().join_channel(&key.0, tag)
        {
            self.with_chats(|chats, _, _, events| chats.let_go(tag, events));
            return None;
        }
        Some(summary)
    }

    fn change(&self, setting: Setting, change: impl FnOnce(&mut Settings<P>) -> bool) {
        if !change(&mut self.settings.borrow_mut()) {
            self.events
                .borrow_mut()
                .push(NodeEvent::SettingRefused(setting));
        }
    }
}

impl<P: LocalPort, S: ChatStore> Node for CommunicatorNode<P, S> {
    fn next_event(&self) -> Option<NodeEvent> {
        self.events.borrow_mut().pop()
    }

    // ─── Chats ───────────────────────────────────────────────────────

    fn chats(&self, chats: &mut Chats) {
        self.chats.borrow().chats(chats);
    }

    fn chat(&self, chat: ChatId) -> Option<ChatSummary> {
        self.chats.borrow().chat(chat)
    }

    fn peers(&self, peers: &mut Peers) {
        self.chats
            .borrow()
            .peers(peers, self.clock.now_ms(), self.clock.wall());
    }

    fn load(&self, chat: ChatId, messages: &mut Messages) {
        self.chats.borrow().load(chat, messages);
    }

    fn message(&self, chat: ChatId, message: MessageId) -> Option<Message> {
        self.chats.borrow().message(chat, message)
    }

    fn opened(&self, chat: ChatId) {
        self.chats.borrow_mut().opened(chat);
    }

    fn save_draft(&self, chat: ChatId, text: &str) {
        self.chats.borrow_mut().save_draft(chat, text);
    }

    fn recent_picks(&self) -> RecentText {
        self.chats.borrow().recent_picks()
    }

    fn keep_recent_picks(&self, picks: &str) {
        self.chats.borrow_mut().keep_recent_picks(picks);
    }

    fn details(&self, chat: ChatId, message: MessageId) -> Option<Details> {
        let mine = self.settings.borrow().avatar();
        self.chats.borrow().details(chat, message, &mine)
    }

    fn member(&self, chat: ChatId, message: MessageId) -> Option<Member> {
        self.chats
            .borrow()
            .member(chat, message, self.clock.now_ms(), self.clock.wall())
    }

    // ─── Sending ─────────────────────────────────────────────────────

    fn send(
        &self,
        chat: ChatId,
        text: &str,
        reply_to: Option<MessageId>,
        forward_secret: bool,
    ) -> Option<Message> {
        let message = self.with_chats(|chats, now_ms, time, events| {
            chats.send(chat, text, reply_to, forward_secret, now_ms, time, events)
        });
        self.wake();
        message
    }

    fn react(&self, chat: ChatId, message: MessageId, reaction: Option<Reaction>) {
        self.with_chats(|chats, now_ms, time, events| {
            chats.react(chat, message, reaction, now_ms, time, events);
        });
        self.wake();
    }

    fn delete_message(&self, chat: ChatId, message: MessageId) {
        self.with_chats(|chats, now_ms, time, events| {
            chats.delete_message(chat, message, now_ms, time, events);
        });
        self.wake();
    }

    fn retry(&self, chat: ChatId, message: MessageId) -> bool {
        let queued = self.with_chats(|chats, now_ms, time, events| {
            chats.retry(chat, message, now_ms, time, events)
        });
        self.wake();
        queued
    }

    fn retry_without_secrecy(&self, chat: ChatId, message: MessageId) -> bool {
        let queued = self.with_chats(|chats, now_ms, time, events| {
            chats.retry_without_secrecy(chat, message, now_ms, time, events)
        });
        self.wake();
        queued
    }

    // ─── Peers ───────────────────────────────────────────────────────

    fn request_identity(&self, chat: ChatId, message: MessageId) {
        self.chats.borrow_mut().request_identity(chat, message);
        self.wake();
    }

    /// A new chat is drawn as the node it is with, whatever `avatar` says.
    fn direct_chat(&self, address: &str, name: &str, _avatar: &AvatarStyle) -> Option<ChatSummary> {
        self.with_chats(|chats, _, _, events| chats.direct_chat(address, name, events))
    }

    fn inspect_peer(&self, text: &str) -> PeerEntry {
        self.chats.borrow().inspect_peer(text)
    }

    fn known_member(&self, text: &str) -> Option<Member> {
        self.with_chats(|chats, now_ms, _, events| {
            chats.known_member(text, now_ms, self.clock.wall(), events)
        })
    }

    fn saved_peer(&self, address: &str) -> Option<PeerId> {
        self.chats.borrow().saved_at(address)
    }

    fn contact_uri(&self, peer: PeerId) -> Option<ContactUri> {
        self.chats.borrow().contact_uri(peer)
    }

    fn peer_detail(&self, peer: PeerId) -> Option<PeerDetail> {
        self.chats
            .borrow()
            .peer_detail(peer, self.clock.now_ms(), self.clock.wall())
    }

    fn set_forward_secrecy(&self, peer: PeerId, on: bool) {
        self.with_chats(|chats, _, _, events| chats.set_forward_secrecy(peer, on, events));
        self.wake();
    }

    fn ping(&self, peer: PeerId) {
        self.chats.borrow_mut().ping(peer);
        self.wake();
    }

    fn clock(&self) -> ClockSettings {
        self.settings.borrow().clock()
    }

    fn set_clock_automatic(&self, on: bool) {
        self.change(Setting::Clock, |settings| settings.set_clock_automatic(on));
    }

    fn set_time(&self, time: u32) {
        self.change(Setting::Time, |settings| settings.set_time(time));
    }

    fn set_zone(&self, rule: &str) {
        self.change(Setting::Clock, |settings| settings.set_zone(rule));
    }

    fn set_hour24(&self, on: bool) {
        self.change(Setting::Clock, |settings| settings.set_hour24(on));
    }

    fn clock_source(&self) -> Option<(ClockSource, u64)> {
        self.clock.source()
    }

    fn request_peer_identity(&self, peer: PeerId) {
        self.chats.borrow_mut().request_peer_identity(peer);
        self.wake();
    }

    fn forget_peer(&self, peer: PeerId) {
        let key = self.with_chats(|chats, _, _, events| chats.forget_peer(peer, events));
        if let Some(key) = key {
            self.settings.borrow_mut().forget_peer(&key.0);
        }
    }

    fn chat_peer(&self, chat: ChatId) -> Option<PeerId> {
        self.chats.borrow().chat_peer(chat)
    }

    fn chat_member(&self, chat: ChatId) -> Option<Member> {
        self.chats
            .borrow()
            .chat_member(chat, self.clock.now_ms(), self.clock.wall())
    }

    fn delete_chat(&self, chat: ChatId) {
        self.with_chats(|chats, _, _, events| chats.delete_chat(chat, events));
    }

    fn save_peer(&self, member: &Member) -> Option<PeerSummary> {
        let (key, summary) = self.with_chats(|chats, now_ms, _, events| {
            chats.save_peer(member, now_ms, self.clock.wall(), events)
        })?;
        self.settings.borrow_mut().save_peer(&key.0);
        Some(summary)
    }

    // ─── Channels ────────────────────────────────────────────────────

    fn join(&self, invite: &Invite, name: &str) -> Option<ChatSummary> {
        let joined = self.with_chats(|chats, _, _, events| chats.join(invite, name, events));
        self.joined(joined)
    }

    fn inspect_channel(&self, text: &str) -> ChannelEntry {
        self.chats.borrow().inspect_channel(text)
    }

    fn add_channel(&self, text: &str) -> Option<ChatSummary> {
        let joined = self.with_chats(|chats, _, _, events| chats.add_channel(text, events));
        self.joined(joined)
    }

    fn find_heard(&self, query: &str) -> Vec<Heard, MAX_HEARD> {
        self.chats
            .borrow()
            .find_heard(query, self.clock.now_ms(), self.clock.wall())
    }

    // ─── The device ──────────────────────────────────────────────────

    fn address(&self) -> String<44> {
        self.settings.borrow().address()
    }

    fn avatar(&self) -> AvatarStyle {
        self.settings.borrow().avatar()
    }

    fn device_name(&self) -> String<24> {
        self.settings.borrow().device_name()
    }

    fn set_name(&self, name: &str) {
        self.change(Setting::Name, |settings| settings.set_name(name));
    }

    fn share_uri(&self, what: Shareable) -> Option<ShareUri> {
        match what {
            Shareable::Identity => self.settings.borrow().share_uri(),
            Shareable::Channel(chat) => self.chats.borrow().share_channel(chat),
        }
    }

    fn profile_count(&self) -> usize {
        VETTED.len()
    }

    fn profile(&self, index: usize) -> Option<&'static str> {
        VETTED.get(index).map(|profile| profile.name)
    }

    fn set_profile(&self, index: usize) {
        self.change(Setting::Profile, |settings| settings.set_profile(index));
    }

    fn radio(&self) -> RadioSettings {
        self.settings.borrow().radio()
    }

    fn set_radio_enabled(&self, on: bool) {
        self.change(Setting::Radio, |settings| settings.set_radio_enabled(on));
    }

    fn set_forwarding(&self, on: bool) {
        self.change(Setting::Forwarding, |settings| settings.set_forwarding(on));
    }

    fn set_share_location(&self, on: bool) {
        self.change(Setting::ShareLocation, |settings| {
            settings.set_share_location(on)
        });
    }

    fn set_transmit_power(&self, dbm: i8) {
        self.change(Setting::TransmitPower, |settings| {
            settings.set_transmit_power(dbm)
        });
    }

    fn keyboard(&self) -> KeyboardSettings {
        self.settings.borrow().keyboard()
    }

    fn set_keyboard(&self, keyboard: KeyboardSettings) {
        self.change(Setting::Keyboard, |settings| {
            settings.set_keyboard(keyboard)
        });
    }

    fn brightness(&self) -> u8 {
        self.settings.borrow().brightness()
    }

    fn set_brightness(&self, brightness: u8) {
        self.change(Setting::Brightness, |settings| {
            settings.set_brightness(brightness)
        });
    }

    fn bluetooth_enabled(&self) -> Option<bool> {
        self.settings.borrow().bluetooth_enabled()
    }

    fn set_bluetooth_enabled(&self, on: bool) {
        self.change(Setting::Bluetooth, |settings| {
            settings.set_bluetooth_enabled(on)
        });
    }

    fn set_pairing(&self, open: bool) {
        self.change(Setting::Pairing, |settings| settings.set_pairing(open));
    }

    fn clear_pairings(&self) {
        self.change(Setting::Pairing, Settings::clear_pairings);
    }

    fn gnss_enabled(&self) -> Option<bool> {
        self.settings.borrow().gnss_enabled()
    }

    fn set_gnss_enabled(&self, on: bool) {
        self.change(Setting::Gnss, |settings| settings.set_gnss_enabled(on));
    }

    // ─── Contact exchange ────────────────────────────────────────────

    fn open_meet(&self) {
        #[cfg(feature = "software-crypto")]
        {
            let (own, frame_ms) = {
                let mut settings = self.settings.borrow_mut();
                settings.read_for_meet();
                (settings.key().copied(), settings.frame_ms())
            };
            let Some(own) = own else { return };
            let now_ms = self.clock.now_ms();
            self.with_meeting(|meeting, events| {
                meeting.open(now_ms, PublicKey(own), frame_ms, events);
                None
            });
        }
    }

    fn close_meet(&self) {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            self.with_meeting(|meeting, events| {
                meeting.close(now_ms, events);
                None
            });
        }
    }

    fn meet(&self, state: &mut MeetState) {
        #[cfg(feature = "software-crypto")]
        self.meeting.borrow().state(state);
        #[cfg(not(feature = "software-crypto"))]
        {
            *state = MeetState::new();
        }
    }

    fn ask_to_exchange(&self, device: NearbyId) -> bool {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            let mut asked = false;
            self.with_meeting(|meeting, events| {
                asked = meeting.ask(now_ms, device, events);
                None
            });
            asked
        }
        #[cfg(not(feature = "software-crypto"))]
        {
            let _ = device;
            false
        }
    }

    fn answer_exchange(&self, accept: bool) {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            self.with_meeting(|meeting, events| {
                meeting.answer(now_ms, accept, events);
                None
            });
        }
        #[cfg(not(feature = "software-crypto"))]
        let _ = accept;
    }

    fn confirm_code(&self, same: bool) {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            if !same {
                self.with_meeting(|meeting, events| {
                    meeting.different(now_ms, events);
                    None
                });
                return;
            }
            if !self.meeting.borrow().comparing() {
                return;
            }
            let identity = self.own_identity();
            self.with_meeting(|meeting, events| meeting.same(now_ms, &identity, events));
        }
        #[cfg(not(feature = "software-crypto"))]
        let _ = same;
    }

    fn cancel_exchange(&self) {
        #[cfg(feature = "software-crypto")]
        {
            let now_ms = self.clock.now_ms();
            self.with_meeting(|meeting, events| {
                meeting.cancel(now_ms, events);
                None
            });
        }
    }
}
