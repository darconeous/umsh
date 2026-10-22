//! What the screens show: plain data the device fills in from its node,
//! chat store, and peripherals, kept separate from how it is drawn.

use buoyant::primitives::Point;
use buoyant::view::EditBuffer;
use heapless::{String, Vec};
pub use umsh_hal::tz::Rule;

use crate::avatar::{AvatarStyle, BuiltinChannel, Title, channel_title};
use crate::board::{Board, Metrics};
use crate::clock::Local;
use crate::keyboard::{Aids, Keyboard};
use crate::lock::Lock;
use crate::nav::{DevicePage, Screen, Unsent, keys};
use crate::picker::{Picker, RecentText, Recents};
use crate::text::{DraftText, SharedText, TextHeap};

/// The most chats the list holds at once.
pub const MAX_CHATS: usize = 12;
/// How many saved peers the Peers list holds.
pub const MAX_PEERS: usize = 12;
/// The most messages a conversation keeps; older ones are dropped.
pub const MAX_MESSAGES: usize = 16;
/// The longest message, in bytes: a UMSH text message is at most ten
/// fragments of 160 bytes.
pub const MESSAGE_LEN: usize = 1600;

/// Identifies a chat for as long as it exists, wherever it sits in the list.
pub type ChatId = u32;
/// Identifies a message for as long as the node keeps it: given by the
/// node, and never given to another.
pub type MessageId = u32;
/// An unsent message and the cursor in it, up to a message long.
pub type Draft = EditBuffer<DraftText>;
/// The chats the list holds, newest first.
pub type Chats = Vec<ChatSummary, MAX_CHATS>;
/// The saved peers the Peers list holds, most recently heard first.
pub type Peers = Vec<PeerSummary, MAX_PEERS>;
/// How long ago something happened, already formatted, such as `2m`.
pub type Age = String<6>;

/// How long ago `since` was at `now`, both in Unix seconds, as a list says
/// it: `now`, then minutes, hours, days, weeks, and years, such as `5m`.
/// Empty when either is not known.
#[must_use]
pub fn age(since: Option<u32>, now: Option<u32>) -> Age {
    const MINUTE: u32 = 60;
    const HOUR: u32 = 60 * MINUTE;
    const DAY: u32 = 24 * HOUR;
    const WEEK: u32 = 7 * DAY;
    const YEAR: u32 = 365 * DAY;
    let mut age = Age::new();
    let (Some(since), Some(now)) = (since, now) else {
        return age;
    };
    let seconds = now.saturating_sub(since);
    let (count, unit) = match seconds {
        0..MINUTE => {
            _ = age.push_str("now");
            return age;
        }
        MINUTE..HOUR => (seconds / MINUTE, 'm'),
        HOUR..DAY => (seconds / HOUR, 'h'),
        DAY..WEEK => (seconds / DAY, 'd'),
        WEEK..YEAR => (seconds / WEEK, 'w'),
        _ => (seconds / YEAR, 'y'),
    };
    _ = core::fmt::write(&mut age, format_args!("{count}{unit}"));
    age
}

/// The always-visible strip along the top of the screen.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StatusStrip {
    pub device_name: String<24>,
    /// Remaining charge in thirds, 0 to 3.
    pub battery_segments: u8,
    /// Remaining charge in percent, when it is known.
    pub battery_percent: Option<u8>,
    /// External power is charging the battery, or has charged it.
    pub charging: bool,
    /// Bluetooth, while it is on.
    pub bluetooth: Option<Bluetooth>,
    /// Wi-Fi, while it is on.
    pub wifi: Option<Wifi>,
    /// GNSS, while it is on.
    pub gnss: Option<Gnss>,
    /// Optional sounds are silenced.
    pub silent: bool,
    /// The charge is low enough to say so.
    pub battery_low: bool,
}

/// Bluetooth, while it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bluetooth {
    /// Nothing is connected.
    Waiting,
    /// A phone is connected.
    Connected,
    /// A pairing window is open.
    Pairing,
}

/// Wi-Fi, while it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wifi {
    /// No network is joined.
    Disconnected,
    /// A network is being joined.
    Joining,
    Connected,
}

/// GNSS, while it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gnss {
    /// No position yet.
    Searching,
    /// A position is held.
    Fixed,
}

/// What the board reads of its links, for the screens that show them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Links {
    pub bluetooth: BluetoothReading,
    pub gnss: GnssReading,
}

/// Bluetooth as it stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BluetoothReading {
    /// A phone is connected.
    pub connected: bool,
    /// How many phones are paired, where the board keeps its own pairings.
    pub paired: Option<u8>,
    /// A pairing window is open.
    pub pairing: bool,
    /// The PIN a phone pairing now must give.
    pub pin: Option<u32>,
}

/// The GNSS receiver's solution as it stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GnssReading {
    pub fix: Fix,
    /// Latitude and longitude, in millionths of a degree.
    pub position: Option<(i32, i32)>,
    /// Meters above the ellipsoid, with a three-dimensional fix.
    pub altitude: Option<i32>,
    /// Satellites in the solution.
    pub used: u8,
    /// Satellites in view, where the receiver says.
    pub in_view: Option<u8>,
}

/// The battery as the board last read it, for the Battery screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatteryReading {
    /// Remaining charge in percent, when it is known.
    pub percent: Option<u8>,
    /// What external power is doing, where the board can tell.
    pub charge: Option<Charge>,
    /// The cell's voltage in millivolts, when it is known.
    pub millivolts: Option<u16>,
}

impl BatteryReading {
    /// External power is charging the battery, or has charged it.
    #[must_use]
    pub const fn charging(&self) -> bool {
        matches!(self.charge, Some(Charge::Charging | Charge::Charged))
    }
}

/// What external power is doing for the battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    /// No external power: the battery runs the board.
    Discharging,
    Charging,
    /// External power, and the battery is full.
    Charged,
    /// External power, and the battery is not taking it.
    NotCharging,
}

/// The device's counters, as last read, each where the device keeps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    /// Seconds since the device started.
    pub uptime: Option<u32>,
    /// Frames that reached the air.
    pub sent: Option<u32>,
    /// Transmits held back for a busy channel.
    pub channel_busy: Option<u32>,
    /// UMSH packets heard, whoever they were for.
    pub heard: Option<u32>,
    pub bad_crc: Option<u32>,
    /// Packets heard that are not UMSH.
    pub other: Option<u32>,
    /// Packets this node acted on.
    pub accepted: Option<u32>,
    pub forwarded: Option<u32>,
    /// Forwards the forwarding policy declined.
    pub forward_dropped: Option<u32>,
    /// Forwards dropped once their acknowledgement was heard.
    pub forward_cancelled: Option<u32>,
    pub meshcore_seen: Option<u32>,
    pub meshcore_routed: Option<u32>,
    pub meshcore_flooded: Option<u32>,
    pub meshcore_declined: Option<u32>,
}

/// What Device › About reads of the node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct About {
    /// Octets the chats keep, of the most they may.
    pub stored: u32,
    pub quota: u32,
}

/// How much of a position the receiver has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fix {
    #[default]
    None,
    TwoD,
    ThreeD,
}

/// A chat as the list knows it, whether or not it is open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatSummary {
    pub id: ChatId,
    pub avatar: AvatarStyle,
    pub name: String<32>,
    /// The last message.
    pub preview: String<64>,
    /// When it was last active, in Unix seconds, when the clock was known.
    pub last_activity: Option<u32>,
    pub unread: bool,
    pub muted: bool,
    pub kind: ChatKind,
    /// What is sent now goes under a session with forward secrecy.
    pub forward_secret: bool,
    /// The unsent message, kept until it is sent or erased.
    pub draft: Draft,
}

impl ChatSummary {
    /// A chat with no messages, whose draft is kept on `heap`.
    #[must_use]
    pub fn new(id: ChatId, avatar: AvatarStyle, name: &str, heap: TextHeap) -> Self {
        let mut summary = Self {
            id,
            avatar,
            name: String::new(),
            preview: String::new(),
            last_activity: None,
            unread: false,
            muted: false,
            kind: ChatKind::Peer { hops: None },
            forward_secret: false,
            draft: EditBuffer::with_text(DraftText::new(heap)),
        };
        push_cut(&mut summary.name, name);
        summary
    }

    /// What a row that identifies the chat calls it: a channel as
    /// [`channel_title`] says, and a peer by its name.
    #[must_use]
    pub fn title(&self) -> Title {
        match self.kind {
            ChatKind::Channel { .. } => channel_title(&self.name),
            ChatKind::Peer { .. } => Title::copy(&self.name),
        }
    }

    /// Shows `message` as the last one.
    pub fn preview(&mut self, message: &Message) {
        self.preview.clear();
        match (message.direction, &message.sender) {
            (Direction::Outbound, _) => push_cut(&mut self.preview, "You: "),
            (Direction::Inbound, Some(sender)) => {
                push_cut(&mut self.preview, &sender.name);
                push_cut(&mut self.preview, ": ");
            }
            (Direction::Inbound, None) => {}
        }
        match &message.card {
            Some(Card::Channel(invite)) => {
                push_cut(&mut self.preview, "Channel invite: ");
                push_cut(&mut self.preview, &invite.name);
            }
            Some(Card::Contact(contact)) => {
                push_cut(&mut self.preview, "Contact: ");
                push_cut(&mut self.preview, &contact.name);
            }
            None => push_cut(&mut self.preview, &message.text),
        }
    }
}

/// What a saved peer's screen shows beyond the Peers list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerDetail {
    pub address: String<44>,
    /// How they are reached, such as `Direct · −97 dBm`, when known.
    pub route: Option<String<24>>,
    /// When they were last heard, such as `5 min ago`.
    pub heard: String<12>,
    pub forward_secrecy: bool,
    /// The round trip of the last ping they answered, such as `1.4 s`.
    pub ping: Option<String<8>>,
}

/// A node heard nearby but not saved, as Find shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub address: String<44>,
    pub avatar: AvatarStyle,
    pub name: String<32>,
    /// How far away it is, such as `Nearby` or `2 hops`.
    pub distance: String<12>,
    /// How long ago it was heard, such as `12m`.
    pub age: String<6>,
}

/// One of Find's results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub kind: FoundKind,
    pub avatar: AvatarStyle,
    /// What the row calls it: [`ChatSummary::title`] for a chat, and a
    /// peer's or a heard node's name.
    pub title: Title,
    /// How far away a peer or a heard node is.
    pub distance: String<12>,
    pub age: String<6>,
}

/// What a result of Find is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoundKind {
    Chat(ChatId),
    Peer(PeerId),
    /// A node heard but not saved, at its address.
    Heard(String<44>),
}

/// The most results Find lists.
pub const MAX_FOUND: usize = 8;

/// The most heard nodes Find lists.
pub const MAX_HEARD: usize = 4;

/// Where `query` starts a word of `name`, ignoring ASCII case: the byte
/// offset of the match. An empty query matches nothing.
#[must_use]
pub fn word_match(name: &str, query: &str) -> Option<usize> {
    if query.is_empty() {
        return None;
    }
    let mut at_word = true;
    for (i, c) in name.char_indices() {
        if at_word
            && name
                .get(i..i + query.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(query))
        {
            return Some(i);
        }
        at_word = !c.is_alphanumeric();
    }
    None
}

/// What the text typed into Add channel names, as far as it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelEntry {
    /// Nothing yet.
    Empty,
    /// Neither a channel's name nor an invitation.
    Invalid,
    /// A named channel, whose key anyone can derive from its name.
    Named,
    /// The start of a private channel's invitation, and how many characters
    /// its key lacks.
    Partial { missing: u8 },
    /// A private channel's whole invitation.
    Private,
}

/// What Share shows as a code: this node, or a channel it has joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shareable {
    Identity,
    Channel(ChatId),
}

/// A link that shares a node or a channel, such as `umsh:n:…`.
pub type ShareUri = String<96>;
/// A link that shares a node: its address and its own signed identity.
pub type ContactUri = String<320>;

/// Which of the node's radio profiles the radio is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The profile at this index, below [`Node::profile_count`].
    Vetted(usize),
    /// Settings no profile has, made by other means.
    Custom,
}

/// The radio's settings, and how much of its airtime it has spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioSettings {
    /// The radio is on.
    pub enabled: bool,
    /// What it sends and listens on, which nodes must share to hear one
    /// another.
    pub profile: Profile,
    /// Repeats what it hears for others.
    pub forwarding: bool,
    pub share_location: bool,
    /// The radio's transmit power, in dBm.
    pub transmit_power: i8,
    /// How much of this hour's airtime is spent, in percent.
    pub airtime: u8,
}

/// The transmit powers the radio can be set to, in dBm.
pub const TRANSMIT_POWER: core::ops::RangeInclusive<i8> = -9..=22;

/// The keyboard's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyboardSettings {
    /// Shift arms itself at the start of a sentence.
    pub capitalize: bool,
    /// Two quick spaces after a word type a period.
    pub period: bool,
    /// The keyboard is lit while the screen is.
    pub light: bool,
}

impl KeyboardSettings {
    #[must_use]
    pub const fn aids(self) -> Aids {
        Aids {
            capitalize: self.capitalize,
            period: self.period,
        }
    }
}

/// The clock's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSettings {
    /// The receiver sets the clock, on a board with one.
    pub automatic: Option<bool>,
    /// Hours are written from 0 to 23.
    pub hour24: bool,
    /// The time zone.
    pub zone: Rule,
}

/// Where the clock's time came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSource {
    /// Set by hand, here or from a linked phone.
    Manual,
    /// The GNSS receiver.
    Gnss,
    /// A clock on the board that keeps time while it is off.
    Rtc,
}

impl Default for ClockSettings {
    fn default() -> Self {
        Self {
            automatic: None,
            hour24: true,
            zone: Rule::UTC,
        }
    }
}

/// The screen's brightness levels, from 1 to this.
pub const BRIGHTNESS_LEVELS: u8 = 10;

/// The level a brightness of `brightness`, from 0 to 255, is nearest.
#[must_use]
pub const fn brightness_level(brightness: u8) -> u8 {
    let steps = BRIGHTNESS_LEVELS as u16 - 1;
    ((brightness as u16 * steps + 127) / 255) as u8 + 1
}

/// The brightness, from 0 to 255, of `level`, from 1 to
/// [`BRIGHTNESS_LEVELS`].
#[must_use]
pub const fn brightness_at(level: u8) -> u8 {
    let steps = BRIGHTNESS_LEVELS as u16 - 1;
    let level = if level < 1 {
        1
    } else if level > BRIGHTNESS_LEVELS {
        BRIGHTNESS_LEVELS
    } else {
        level
    };
    (((level as u16 - 1) * 255 + steps / 2) / steps) as u8
}

/// How long the screen stays lit without input, in seconds, until a
/// device says otherwise.
pub const DEFAULT_AUTO_LOCK_S: u16 = 30;

/// The times Auto-Lock offers, in seconds, in the order listed: 0 is
/// never.
pub const AUTO_LOCK_CHOICES: [u16; 5] = [0, 30, 60, 120, 300];

/// What the text typed into Add peer names, as far as it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEntry {
    /// Nothing yet.
    Empty,
    /// Not the start of an address or an invitation.
    Invalid,
    /// The start of an address, and how many characters it lacks. The avatar
    /// and hint show once the characters settle them.
    Partial {
        avatar: Option<AvatarStyle>,
        hint: String<8>,
        missing: u8,
    },
    /// A whole address, typed or in an invitation, with the name the
    /// invitation gives.
    Complete {
        avatar: AvatarStyle,
        hint: String<8>,
        address: String<44>,
        name: Option<String<32>>,
    },
}

/// Names a saved peer.
pub type PeerId = u32;

/// How far away a node `hops` hops away is, such as `3 hops`; a node
/// heard directly, one hop away, is `Direct`.
#[must_use]
pub fn hops_text(hops: u8) -> String<12> {
    let mut text = String::new();
    match hops {
        1 => _ = text.push_str("Direct"),
        n => _ = core::fmt::write(&mut text, format_args!("{n} hops")),
    }
    text
}

/// A saved peer, as the Peers list shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSummary {
    pub id: PeerId,
    pub avatar: AvatarStyle,
    pub name: String<32>,
    /// How many hops away they are, when known: one when heard directly.
    pub hops: Option<u8>,
    /// Of four bars, how strongly they are heard, when direct.
    pub signal: Option<u8>,
    /// How long ago they were last heard, already formatted, such as `5m`.
    pub heard: String<6>,
}

/// Whom a chat is with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatKind {
    /// One peer, and how many hops away it is when that is known.
    Peer { hops: Option<u8> },
    /// Everyone holding the channel's key.
    Channel { access: ChannelAccess },
}

/// Who can read a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelAccess {
    /// Those its key was given to.
    Private,
    /// Anyone who knows its name, which its key is derived from.
    Named,
    /// Anyone within earshot: EMERGENCY is sent unencrypted.
    Clear,
}

impl ChannelAccess {
    /// Whether anyone, not only those given its key, can read it.
    #[must_use]
    pub const fn is_open(self) -> bool {
        !matches!(self, Self::Private)
    }
}

impl ChatKind {
    /// Whether anyone within earshot can read what is written in the chat.
    #[must_use]
    pub const fn is_open(self) -> bool {
        match self {
            Self::Channel { access } => access.is_open(),
            Self::Peer { .. } => false,
        }
    }
}

/// Who sent a channel message, as the channel shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sender {
    /// The best name known for them, or their hint.
    pub name: String<24>,
    pub avatar: AvatarStyle,
}

/// A channel member as the member screen shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub sender: Sender,
    /// The leading digits of their address, which their messages carry.
    pub hint: String<8>,
    /// Their whole address, once their identity is known.
    pub address: Option<String<44>>,
    /// How long ago they were last heard, already formatted, such as `2m`.
    pub heard: String<6>,
    /// They are among my peers.
    pub saved: bool,
}

/// How many devices Nearby lists.
pub const MAX_NEARBY: usize = 16;

/// Names a device listed on Nearby for as long as Add peer is open.
pub type NearbyId = u32;

/// A device listed on Nearby. It says what kind of device it is and the
/// color it shows for this visit, and nothing of whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NearbyDevice {
    pub id: NearbyId,
    /// Its model id (`boards.json`, `platforms.json`).
    pub model: u16,
    /// Its session color, as `0xRRGGBB`.
    pub color: u32,
    /// How near it seems, 0 (far) to 3 (close), when the bearer reports
    /// signal strength.
    pub nearness: Option<u8>,
}

/// Why an exchange ended without contacts crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeEnd {
    /// The other holder declined.
    NotNow,
    /// The other device is in another exchange.
    Busy,
    /// A holder found the codes different.
    Different,
    /// The other holder backed out.
    Left,
    /// No answer in time.
    TimedOut,
    /// Something did not check out.
    Failed,
}

/// Where a contact exchange stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exchange {
    /// Add peer is not open.
    Closed,
    /// Add peer is open and its session is being set up.
    Opening,
    /// Listed on Nearby, nothing in progress.
    Idle,
    /// We asked `with`; waiting for an answer.
    Asking(NearbyDevice),
    /// `with` asked us; waiting for our holder.
    Asked(NearbyDevice),
    /// We agreed; waiting for `with` to go on.
    Accepted(NearbyDevice),
    /// Both hold `code`. `sent` once our holder pressed Same.
    Comparing {
        with: NearbyDevice,
        code: u32,
        sent: bool,
    },
    Ended(ExchangeEnd),
    /// Contacts crossed: who the other device says it is. Nothing is saved.
    Exchanged(Member),
}

/// What Add peer shows: our own color, the devices nearby, and the
/// exchange in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeetState {
    /// Our session color for this visit, as `0xRRGGBB`, once the session
    /// is up.
    pub own_color: Option<u32>,
    /// The devices heard, oldest first.
    pub devices: Vec<NearbyDevice, MAX_NEARBY>,
    /// The device the exchange is with, or was until it ended.
    pub with: Option<NearbyDevice>,
    pub exchange: Exchange,
}

impl MeetState {
    /// Add peer closed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            own_color: None,
            devices: Vec::new(),
            with: None,
            exchange: Exchange::Closed,
        }
    }
}

impl Default for MeetState {
    fn default() -> Self {
        Self::new()
    }
}

/// Which way a message went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// How far an outgoing message has got, from what became of each of its
/// fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Not every fragment has been sent yet.
    Sending,
    /// Every fragment has been sent: as far as a channel's message goes.
    Sent,
    /// The peer's radio acknowledged every fragment. That says it arrived,
    /// never that it was read.
    Delivered,
    /// A fragment was not acknowledged: it may not have arrived.
    Unconfirmed,
}

/// Whether a message's place in its conversation holds the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Present,
    /// A message is missing here, and has been asked for again.
    PendingRepair,
    /// A message is missing here, and will not come.
    Unavailable,
}

/// A reaction to a message: one of UMSH's emote tokens, or another emoji.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reaction {
    Heart,
    ThumbsUp,
    ThumbsDown,
    Laugh,
    Exclaim,
    Question,
    /// An emoji the board draws.
    Emoji(umsh_emoji::Id),
    /// Anything else, drawn as the placeholder.
    Other,
}

impl Reaction {
    /// The palette, in the order the actions menu shows it.
    pub const ALL: [Self; 6] = [
        Self::Heart,
        Self::ThumbsUp,
        Self::ThumbsDown,
        Self::Laugh,
        Self::Exclaim,
        Self::Question,
    ];

    /// What it is drawn as: an emoji's sequence, as iOS draws the emotes.
    #[must_use]
    pub fn face(self) -> &'static str {
        match self {
            Self::Heart => "\u{1FA77}",
            Self::ThumbsUp => "\u{1F44D}",
            Self::ThumbsDown => "\u{1F44E}",
            Self::Laugh => "\u{1F923}",
            Self::Exclaim => "\u{203C}\u{FE0F}",
            Self::Question => "\u{2753}",
            Self::Emoji(id) => umsh_emoji::sequence(id),
            Self::Other => umsh_emoji::PLACEHOLDER,
        }
    }

    /// The reaction `cluster` is: an emote for the emoji that stand for
    /// one, as the chat store reads them, the emoji it draws as, or
    /// [`Reaction::Other`].
    #[must_use]
    pub fn of(cluster: &str) -> Self {
        let umsh_emoji::Shown::Glyph(id) = umsh_emoji::shown(cluster) else {
            return Self::Other;
        };
        let bare: heapless::String<16> = umsh_emoji::sequence(id)
            .chars()
            .filter(|&c| c != '\u{FE0F}')
            .collect();
        match bare.as_str() {
            "\u{2665}" | "\u{2764}" | "\u{1FA77}" => Self::Heart,
            "\u{1F44D}" => Self::ThumbsUp,
            "\u{1F44E}" => Self::ThumbsDown,
            "\u{1F923}" => Self::Laugh,
            "\u{2757}" | "\u{2755}" | "\u{203C}" => Self::Exclaim,
            "\u{2753}" | "\u{2754}" => Self::Question,
            _ => Self::Emoji(id),
        }
    }
}

/// Everyone who reacted to a message one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reacted {
    pub reaction: Reaction,
    pub count: u8,
    /// One of them is me.
    pub mine: bool,
}

/// The most kinds of reaction a message shows.
pub const REACTIONS: usize = 8;

/// A message's reactions, in the order they first arrived. Each sender has
/// at most one.
pub type Reactions = Vec<Reacted, REACTIONS>;

/// One message in a conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: MessageId,
    pub direction: Direction,
    /// Who sent an incoming channel message.
    pub sender: Option<Sender>,
    pub text: SharedText,
    pub delivery: Delivery,
    pub reactions: Reactions,
    /// The channel it invites to or the node it introduces, when its whole
    /// text is that one's link: a card says nothing besides.
    pub card: Option<Card>,
    /// What it replies to, as it quotes it.
    pub reply: Option<Quote>,
    /// When it was sent or received, in Unix seconds, when the clock was
    /// known.
    pub time: Option<u32>,
    pub presence: Presence,
    /// Its sender changed it after sending it.
    pub edited: bool,
    /// Its sender took it back: what it said is gone.
    pub deleted: bool,
    /// It came after messages sent later than it.
    pub late: bool,
    /// Mine, and sent under a session with forward secrecy.
    pub forward_secret: bool,
    /// How far it has come, while it is still arriving in parts.
    pub parts: Option<Parts>,
}

/// A reply's quote of the message it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    /// Who sent it, or `None` for this node.
    pub name: Option<SharedText>,
    /// What it says, or as much of it as one line shows.
    pub text: SharedText,
}

/// A message arriving in parts: how many, which have come, and which will
/// not, each a bit by its index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Parts {
    pub count: u8,
    pub received: u16,
    pub lost: u16,
}

/// An invitation to a channel. Every message carries room for one, so it
/// keeps its name on the text heap and its avatar as what draws it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub name: SharedText,
    pub builtin: Option<BuiltinChannel>,
    pub tint: [u8; 3],
    /// Who can read it: those given the invitation, or anyone who knows
    /// the name.
    pub access: ChannelAccess,
    /// The channel's key, which joining it under another name still needs.
    pub key: [u8; 32],
}

impl Invite {
    #[must_use]
    pub fn avatar(&self) -> AvatarStyle {
        AvatarStyle::channel(self.builtin, &self.name, self.tint)
    }
}

/// What a message whose whole text is a link offers, shown as a card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Card {
    Channel(Invite),
    Contact(Contact),
}

/// A node a message introduces by its link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub key: [u8; 32],
    /// What it is called here, else what its link calls it, else its
    /// address's first characters.
    pub name: SharedText,
    pub avatar: AvatarStyle,
}

impl Message {
    /// The channel it invites to.
    #[must_use]
    pub fn invite(&self) -> Option<&Invite> {
        match &self.card {
            Some(Card::Channel(invite)) => Some(invite),
            _ => None,
        }
    }

    /// The node it introduces.
    #[must_use]
    pub fn contact(&self) -> Option<&Contact> {
        match &self.card {
            Some(Card::Contact(contact)) => Some(contact),
            _ => None,
        }
    }

    /// My reaction, if I have reacted.
    #[must_use]
    pub fn my_reaction(&self) -> Option<Reaction> {
        self.reactions.iter().find(|r| r.mine).map(|r| r.reaction)
    }

    /// Makes `reaction` mine, in place of any I had.
    pub fn set_my_reaction(&mut self, reaction: Option<Reaction>) {
        if let Some(index) = self.reactions.iter().position(|r| r.mine) {
            let old = &mut self.reactions[index];
            old.mine = false;
            old.count -= 1;
            if old.count == 0 {
                self.reactions.remove(index);
            }
        }
        let Some(reaction) = reaction else {
            return;
        };
        match self.reactions.iter_mut().find(|r| r.reaction == reaction) {
            Some(same) => {
                same.count = same.count.saturating_add(1);
                same.mine = true;
            }
            None => {
                _ = self.reactions.push(Reacted {
                    reaction,
                    count: 1,
                    mine: true,
                });
            }
        }
    }
}

/// How a message reached this device, for its details.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Details {
    /// When it was received or sent, in Unix seconds, when the clock was
    /// known.
    pub time: Option<u32>,
    /// How many hops it took: one when heard directly.
    pub hops: Option<u8>,
    /// The routers it came through, already formatted.
    pub route: String<24>,
    /// The signal's strength, in dBm.
    pub rssi: Option<i16>,
    /// Signal-to-noise, in tenths of a dB.
    pub snr: Option<i16>,
    /// It came, or for mine was to go, under a session with forward
    /// secrecy.
    pub forward_secret: bool,
    /// Who reacted to it, and how, in the order they did.
    pub reactors: Vec<Reactor, MAX_REACTORS>,
}

/// The most reactions a message's details list: the latest.
pub const MAX_REACTORS: usize = 8;

/// Someone's reaction to a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reactor {
    /// Who reacted, or `None` for this node.
    pub name: Option<SharedText>,
    pub avatar: AvatarStyle,
    pub reaction: Reaction,
}

/// The newest messages of the open chat, oldest first.
pub type Messages = Vec<Message, MAX_MESSAGES>;

/// The open chat's messages, as many as the screen keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub chat: ChatId,
    pub messages: Messages,
    /// How many messages have been sent here, which brings the newest into
    /// view each time it changes.
    pub sent: u32,
}

impl Conversation {
    /// Adds `message` as the newest, dropping the oldest when full.
    pub fn push(&mut self, message: Message) {
        push_newest(&mut self.messages, message);
    }

    /// Takes in `message` where it belongs among those listed: in place of
    /// what is listed for it, or in the order of its ID, which is the order
    /// the node keeps a chat's messages in. One older than everything
    /// listed while the list is full is not among the newest, and stays out.
    pub fn place(&mut self, message: Message) {
        if let Some(listed) = self.messages.iter_mut().find(|m| m.id == message.id) {
            *listed = message;
            return;
        }
        let mut index = self
            .messages
            .iter()
            .position(|m| m.id > message.id)
            .unwrap_or(self.messages.len());
        if self.messages.is_full() {
            if index == 0 {
                return;
            }
            self.messages.remove(0);
            index -= 1;
        }
        _ = self.messages.insert(index, message);
    }
}

/// Adds `message` to `messages` as the newest, dropping the oldest when full.
pub fn push_newest(messages: &mut Messages, message: Message) {
    if messages.is_full() {
        messages.remove(0);
    }
    _ = messages.push(message);
}

/// A setting the node can refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    Name,
    Profile,
    TransmitPower,
    Forwarding,
    ShareLocation,
    Keyboard,
    Brightness,
    Clock,
    Time,
    Bluetooth,
    Pairing,
    Gnss,
    Radio,
    AutoLock,
}

/// What changed in the node without the interface asking. An event names
/// what changed, and the interface reads it from the node again: an event
/// carries no text, and one taken in twice does no harm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeEvent {
    /// `message` arrived in `chat`, which is now its most recently active.
    Arrived {
        chat: ChatId,
        message: MessageId,
    },
    /// `message` in `chat` changed: its delivery, its reactions, its text,
    /// or its sender. When that changes how its chat is listed,
    /// [`NodeEvent::ChatChanged`] says so too.
    MessageChanged {
        chat: ChatId,
        message: MessageId,
    },
    /// How `chat` is listed changed, or it is new.
    ChatChanged(ChatId),
    ChatRemoved(ChatId),
    /// Identities arrived: members known by their hints may now be known by
    /// name and address.
    IdentitiesLearned,
    /// A saved peer changed, or is newly saved.
    PeerChanged(PeerId),
    PeerRemoved(PeerId),
    /// The peer answered a ping.
    PingAnswered(PeerId),
    /// Settings were applied, as set or adjusted.
    SettingsChanged,
    /// A setting was refused, and stays as it was.
    SettingRefused(Setting),
    /// How long until sending is allowed again, while the airtime it may
    /// use is spent; `None` once it is allowed.
    Airtime {
        wait: Option<u16>,
    },
    /// What Add peer shows changed: read it with [`Node::meet`].
    MeetChanged,
    /// Events were lost: everything shown is to be read again.
    Resync,
}

impl NodeEvent {
    /// What the event is about: two events with the same subject say the
    /// same thing, and the later one is the one to keep.
    fn subject(&self) -> (u8, u32) {
        match *self {
            Self::Arrived { message, .. } => (0, message),
            Self::MessageChanged { message, .. } => (1, message),
            Self::ChatChanged(chat) => (2, chat),
            Self::ChatRemoved(chat) => (3, chat),
            Self::IdentitiesLearned => (4, 0),
            Self::PeerChanged(peer) => (5, peer),
            Self::PeerRemoved(peer) => (6, peer),
            Self::PingAnswered(peer) => (7, peer),
            Self::SettingsChanged => (8, 0),
            Self::SettingRefused(setting) => (9, setting as u32),
            Self::Airtime { .. } => (10, 0),
            Self::Resync => (11, 0),
            Self::MeetChanged => (12, 0),
        }
    }
}

/// The events a node holds until the interface takes them, oldest first:
/// one for each kind and subject, and when they overflow, a
/// [`NodeEvent::Resync`] in place of them all.
#[derive(Clone, Debug, Default)]
pub struct EventQueue<const N: usize> {
    events: Vec<NodeEvent, N>,
}

impl<const N: usize> EventQueue<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Queues `event`, in place of an earlier one about the same thing:
    /// what it names is read when the interface takes it, so it moves to
    /// the back as though it were the only one.
    pub fn push(&mut self, event: NodeEvent) {
        let subject = event.subject();
        if let Some(index) = self.events.iter().position(|e| e.subject() == subject) {
            self.events.remove(index);
        }
        if self.events.push(event).is_err() {
            self.events.clear();
            _ = self.events.push(NodeEvent::Resync);
        }
    }

    /// The oldest event, taken off the queue.
    pub fn pop(&mut self) -> Option<NodeEvent> {
        (!self.events.is_empty()).then(|| self.events.remove(0))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// The node behind the interface: where every chat's messages are kept,
/// what it knows of peers and channels, and the device's settings. The
/// interface holds only the chats and peers it lists and the open chat's
/// newest messages, and reads them from here.
///
/// Reads are answered at once. What changes in the node by itself is
/// announced by the [`NodeEvent`]s [`Node::next_event`] hands out, which the
/// interface takes in through [`State::apply`]. How the node lets the board
/// know events are waiting is the node's own, and stays out of this trait.
///
/// A setting's setter changes what its read reports at once. Its outcome
/// follows as an event: [`NodeEvent::SettingsChanged`] once it is applied,
/// perhaps adjusted, or [`NodeEvent::SettingRefused`], after which the read
/// reports the value in force.
pub trait Node {
    /// The oldest event waiting, taken off the node's queue.
    fn next_event(&self) -> Option<NodeEvent>;

    /// Fills `chats`, which is empty, with the most recently active chats,
    /// newest first, as many as it holds.
    fn chats(&self, chats: &mut Chats);

    /// The chat `chat`, as the list shows it. `None` once it is gone.
    fn chat(&self, chat: ChatId) -> Option<ChatSummary>;

    /// Fills `peers`, which is empty, with the saved peers, most recently
    /// heard first, as many as it holds.
    fn peers(&self, peers: &mut Peers);

    /// Fills `messages`, which is empty, with the newest messages of `chat`.
    /// A chat's messages are in the order of their IDs.
    fn load(&self, chat: ChatId, messages: &mut Messages);

    /// The message `message` of `chat`. `None` once it is gone.
    fn message(&self, chat: ChatId, message: MessageId) -> Option<Message>;

    /// `chat` has been read: none of its messages are unread.
    fn opened(&self, chat: ChatId);

    /// Keeps `text` as the draft of `chat`, which was left unsent. A draft
    /// of nothing but whitespace is no draft, and clears the one kept.
    fn save_draft(&self, chat: ChatId, text: &str);

    /// The characters last picked in the character picker, as
    /// [`Node::keep_recent_picks`] last kept them.
    fn recent_picks(&self) -> RecentText;
    /// Keeps `picks`: each pick's text, newest first, a line each.
    fn keep_recent_picks(&self, picks: &str);

    /// Keeps `text`, sent now in reply to `reply_to` if it is a reply, as the
    /// newest message of `chat`, and returns the message as kept, or `None`
    /// when there is no room for it. With `forward_secret` it goes under a
    /// session with forward secrecy or not at all; without, never under one.
    fn send(
        &self,
        chat: ChatId,
        text: &str,
        reply_to: Option<MessageId>,
        forward_secret: bool,
    ) -> Option<Message>;

    /// Keeps `reaction` as my reaction to `message` in `chat`; `None`
    /// withdraws it.
    fn react(&self, chat: ChatId, message: MessageId, reaction: Option<Reaction>);

    /// How `message` in `chat` reached this device, when that is known.
    fn details(&self, chat: ChatId, message: MessageId) -> Option<Details>;

    /// The member who sent `message` in the channel `chat`.
    fn member(&self, chat: ChatId, message: MessageId) -> Option<Member>;

    /// Asks the channel `chat` for the identity of the member who sent
    /// `message`.
    fn request_identity(&self, chat: ChatId, message: MessageId);

    /// The direct chat with the peer at `address`, made if there is none yet,
    /// named `name` and drawn as `avatar`. `None` when there is no room for it.
    fn direct_chat(&self, address: &str, name: &str, avatar: &AvatarStyle) -> Option<ChatSummary>;

    /// What `text`, typed as an address or a peer invitation, names so far.
    fn inspect_peer(&self, text: &str) -> PeerEntry;

    /// What is known of the node `text` names, a node's link or its bare
    /// address. A link's identity is kept as heard, never saved, and as
    /// only its key's own word when its key signed it. `None` for anything
    /// else.
    fn known_member(&self, text: &str) -> Option<Member>;

    /// The saved peer at `address`, when they are saved.
    fn saved_peer(&self, address: &str) -> Option<PeerId>;

    /// The link that shares the saved peer `peer`: their address, with
    /// their own signed identity when one is kept.
    fn contact_uri(&self, peer: PeerId) -> Option<ContactUri>;

    /// What is known of the saved peer `peer`.
    fn peer_detail(&self, peer: PeerId) -> Option<PeerDetail>;

    /// Turns forward secrecy with `peer` on or off.
    fn set_forward_secrecy(&self, peer: PeerId, on: bool);

    /// Pings `peer`. Its answer shows in their detail.
    fn ping(&self, peer: PeerId);

    /// The clock's settings as they stand.
    fn clock(&self) -> ClockSettings;

    /// Whether the receiver sets the clock.
    fn set_clock_automatic(&self, on: bool);

    /// Sets the clock to `time`, in Unix seconds.
    fn set_time(&self, time: u32);

    /// Sets the time zone to `rule`, a POSIX TZ rule.
    fn set_zone(&self, rule: &str);

    /// Whether hours are written from 0 to 23.
    fn set_hour24(&self, on: bool);

    /// Where the clock's time came from, and when on the board's clock in
    /// milliseconds, while it is known.
    fn clock_source(&self) -> Option<(ClockSource, u64)>;

    /// Asks `peer` for their identity. What they answer comes as
    /// [`NodeEvent::PeerChanged`].
    fn request_peer_identity(&self, peer: PeerId);

    /// Forgets the saved peer `peer`.
    fn forget_peer(&self, peer: PeerId);

    /// The saved peer at the other end of the direct chat `chat`.
    fn chat_peer(&self, chat: ChatId) -> Option<PeerId>;

    /// The peer at the other end of the direct chat `chat`, saved or not.
    fn chat_member(&self, chat: ChatId) -> Option<Member>;

    /// Deletes the direct chat `chat` and its messages. Its peer stays
    /// saved, and their next message starts a new chat. The chat goes as
    /// [`NodeEvent::ChatRemoved`].
    fn delete_chat(&self, chat: ChatId);

    /// Keeps `member`, whose identity is known, among my peers, and returns
    /// them as the Peers list shows them. `None` when there is no room.
    fn save_peer(&self, member: &Member) -> Option<PeerSummary>;

    // ─── Contact exchange ────────────────────────────────────────────

    /// Opens Add peer under a session key never used before, keeping the
    /// devices already listed. Each attempt opens its own: after an
    /// exchange ends, for any reason, Add peer is opened again.
    fn open_meet(&self);

    /// Closes Add peer, backing out of any exchange in progress.
    fn close_meet(&self);

    /// What Add peer shows, read into `state`. Changes come as
    /// [`NodeEvent::MeetChanged`].
    fn meet(&self, state: &mut MeetState);

    /// Asks `device` to exchange contacts. Returns whether it was asked.
    fn ask_to_exchange(&self, device: NearbyId) -> bool;

    /// Answers the device that asked.
    fn answer_exchange(&self, accept: bool);

    /// Our holder compared the codes. Same sends our contact; Different
    /// ends the exchange and drops whatever arrived.
    fn confirm_code(&self, same: bool);

    /// Backs out of the exchange in progress, staying on Nearby.
    fn cancel_exchange(&self);

    /// Joins the channel `invite` invites to, called `name` here, and returns
    /// its chat: the one already joined, if it is. `None` when there is no
    /// room for it.
    fn join(&self, invite: &Invite, name: &str) -> Option<ChatSummary>;

    /// Sends `message` in `chat`, which is unconfirmed, again. Returns whether
    /// it is on its way.
    fn retry(&self, chat: ChatId, message: MessageId) -> bool;

    /// Deletes my `message` in `chat` for everyone. What becomes of it
    /// comes as [`NodeEvent::MessageChanged`].
    fn delete_message(&self, chat: ChatId, message: MessageId);

    /// Sends `message` in `chat`, which was to go under a session with
    /// forward secrecy and is unconfirmed, again without one. Returns
    /// whether it is on its way.
    fn retry_without_secrecy(&self, chat: ChatId, message: MessageId) -> bool;

    /// What `text`, typed as a channel's name or invitation, names so far.
    fn inspect_channel(&self, text: &str) -> ChannelEntry;

    /// Joins the channel `text` names or invites to, and returns its chat:
    /// the one already joined, if it is. `None` when `text` names no channel
    /// or there is no room for it.
    fn add_channel(&self, text: &str) -> Option<ChatSummary>;

    /// Nodes heard but not saved whose names have a word starting with
    /// `query`, most recently heard first.
    fn find_heard(&self, query: &str) -> Vec<Heard, MAX_HEARD>;

    /// This node's address.
    fn address(&self) -> String<44>;

    /// How this node is drawn.
    fn avatar(&self) -> AvatarStyle;

    /// What this node is called, which may be nothing.
    fn device_name(&self) -> String<24>;

    /// Calls this node `name`, which may be empty.
    fn set_name(&self, name: &str);

    /// The link that shares `what`. `None` when it cannot be shared.
    fn share_uri(&self, what: Shareable) -> Option<ShareUri>;

    /// How many radio profiles the radio can be set to.
    fn profile_count(&self) -> usize;

    /// The name of the radio profile at `index`, below
    /// [`Node::profile_count`].
    fn profile(&self, index: usize) -> Option<&'static str>;

    /// Sets the radio to the profile at `index`.
    fn set_profile(&self, index: usize);

    /// The radio's settings as they stand.
    fn radio(&self) -> RadioSettings;

    /// Turns the radio on or off.
    fn set_radio_enabled(&self, on: bool);

    fn set_forwarding(&self, on: bool);

    fn set_share_location(&self, on: bool);

    /// Sets the radio's transmit power, within [`TRANSMIT_POWER`].
    fn set_transmit_power(&self, dbm: i8);

    fn keyboard(&self) -> KeyboardSettings;

    fn set_keyboard(&self, settings: KeyboardSettings);

    /// The screen's brightness: 0 is the dimmest that is not dark, and 255
    /// the brightest.
    fn brightness(&self) -> u8;

    fn set_brightness(&self, brightness: u8);

    /// How long the screen stays lit without input while the interface is
    /// unlocked, in seconds; 0 is never. `None` where the device does not
    /// say.
    fn auto_lock(&self) -> Option<u16>;

    fn set_auto_lock(&self, seconds: u16);

    /// The device's counters, as last read.
    fn statistics(&self) -> Statistics;

    fn about(&self) -> About;

    /// Keeps the counters being read while `on`: at once, and again every
    /// few seconds, each read followed by [`NodeEvent::SettingsChanged`].
    fn watch_statistics(&self, on: bool);

    /// Whether Bluetooth is on. `None` where the board has none.
    fn bluetooth_enabled(&self) -> Option<bool>;

    fn set_bluetooth_enabled(&self, on: bool);

    /// Opens a window for a phone to pair, or closes it.
    fn set_pairing(&self, open: bool);

    /// Forgets every paired phone.
    fn clear_pairings(&self);

    /// Whether the GNSS receiver is on. `None` where the board has none.
    fn gnss_enabled(&self) -> Option<bool>;

    fn set_gnss_enabled(&self, on: bool);
}

/// At or below this charge, in percent, the battery is low.
pub const BATTERY_LOW_PERCENT: u8 = 10;
/// The charge, in percent, at which a low battery stops being low.
const BATTERY_RECOVERED_PERCENT: u8 = 15;

/// The strip's lit thirds for a charge of `percent`. Each count is centered
/// on the level it depicts, and the ends are narrower: a body should look
/// neither full at 80 % nor empty at 20 %.
#[must_use]
pub const fn battery_segments(percent: u8) -> u8 {
    match percent {
        0..=16 => 0,
        17..=49 => 1,
        50..=82 => 2,
        _ => 3,
    }
}

/// How long a banner stays, in milliseconds.
pub const BANNER_MS: u64 = 4000;

/// Something shown over the screen for a moment, taking no input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Banner {
    pub notice: Notice,
    /// When it goes, on the board's clock, in milliseconds.
    pub until: u64,
}

/// What a banner says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A message arrived in another chat; the banner shows the chat as the
    /// list does.
    Message(ChatId),
    /// The charge has fallen low, to `percent`.
    BatteryLow { percent: u8 },
}

/// A chat that got a message while the interface was locked, as the lock
/// screen lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrived {
    pub chat: ChatId,
    /// The newest message, with its sender ahead of it in a channel.
    pub text: SharedText,
    /// When it arrived, on the board's clock, in milliseconds: its age is
    /// known even while the time of day is not.
    pub at: u64,
}

/// The top-level lists the rail switches between.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Section {
    #[default]
    Chats,
    Peers,
    Device,
}

/// Everything the interface draws from.
pub struct State {
    pub status: StatusStrip,
    /// The battery as the board last read it.
    pub battery: BatteryReading,
    /// What the board last read of its links.
    pub links: Links,
    pub section: Section,
    /// Newest first.
    pub chats: Chats,
    /// Saved peers, most recently heard first.
    pub peers: Peers,
    /// The time, in Unix seconds, as the board last read its clock, when
    /// it is known. Ages are counted to it.
    pub wall_time: Option<u32>,
    /// The clock's settings, as the node last said.
    pub clock: ClockSettings,
    /// The open chat's messages, while one is open.
    pub conversation: Option<Conversation>,
    /// The screens, the one shown last. The Chats screen is always first.
    pub screens: Vec<Screen, 4>,
    pub node: &'static dyn Node,
    /// Seconds until sending is allowed again, while the airtime it may use
    /// is spent.
    pub airtime_wait: Option<u16>,
    /// A message that arrived in a chat not on screen, shown for a moment.
    pub banner: Option<Banner>,
    /// The panel is dark: nothing on it is being read.
    pub dark: bool,
    /// Whether the interface is locked, and how far toward unlocking.
    pub lock: Lock,
    /// The board's clock, in milliseconds, as of the last input, event, or
    /// change of the panel: what the lock screen counts ages to.
    pub uptime: u64,
    /// The chats that got messages while the interface was locked, in the
    /// order they first did, for the lock screen.
    pub arrived: Vec<Arrived, MAX_CHATS>,
    /// The board is turning off: shown over everything, and the end of
    /// input.
    pub ending: Option<Ending>,
    /// What keys type: the focused field's modifiers and aids.
    pub keyboard: Keyboard,
    /// The character picker, while it is open.
    pub picker: Option<Picker>,
    /// The characters last picked.
    pub recents: Recents,
    /// A brief card for a setting a key changed.
    pub glance: Option<Glance>,
    /// The wheel is down, since this press began.
    pub press: Option<Press>,
    /// A finger is on the screen, since this touch began.
    pub touch: Option<TouchHold>,
    /// What is being taken in is a touch: a tap on a message selects it,
    /// and holding it opens what a press would.
    pub touching: bool,
    /// What Add peer shows, while it is open.
    pub meet: MeetState,
    /// The board this runs on.
    pub board: &'static Board,
    /// The firmware's release tag, or its commit for a development build.
    pub firmware: &'static str,
}

/// The wheel held down. What it presses is pressed when it comes back up,
/// unless holding it opened a menu first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Press {
    /// When holding it opens the focused chat's menu, on the board's clock;
    /// `None` once it has, or where nothing would open.
    pub hold_until: Option<u64>,
    /// Holding it opened a menu, so letting go presses nothing.
    pub held: bool,
}

/// A finger on the screen, which a long press holds where it touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchHold {
    /// Where it touched.
    pub at: Point,
    /// When holding it there is a long press, on the board's clock; `None`
    /// once it is, or once it has moved away.
    pub hold_until: Option<u64>,
}

/// How long the wheel is held to open a menu, in milliseconds.
pub const HOLD_MS: u64 = 500;

/// A brief card, with no words, for a setting changed from the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glance {
    /// The screen's brightness, now at this level.
    Brightness { level: u8, until: u64 },
    /// The keyboard light, now on or off.
    KeyboardLight { on: bool, until: u64 },
}

impl Glance {
    const fn until(self) -> u64 {
        match self {
            Self::Brightness { until, .. } | Self::KeyboardLight { until, .. } => until,
        }
    }
}

/// How long a glance stays, in milliseconds.
const GLANCE_MS: u64 = 1500;

/// What lies over the screen: the topmost of what could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overlay {
    Ending(Ending),
    Picker,
    Glance(Glance),
    Banner(Notice),
}

/// What the screen says as the board turns off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Turning off as asked.
    ShuttingDown,
    /// The battery is empty: the screen shows only that, its icon lit or
    /// not as the board blinks it.
    BatteryEmpty { lit: bool },
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("State")
            .field("status", &self.status)
            .field("section", &self.section)
            .field("chats", &self.chats)
            .field("peers", &self.peers)
            .field("wall_time", &self.wall_time)
            .field("clock", &self.clock)
            .field("conversation", &self.conversation)
            .field("screens", &self.screens)
            .field("airtime_wait", &self.airtime_wait)
            .field("banner", &self.banner)
            .field("dark", &self.dark)
            .field("lock", &self.lock)
            .field("arrived", &self.arrived)
            .field("ending", &self.ending)
            .field("keyboard", &self.keyboard)
            .field("picker", &self.picker)
            .field("glance", &self.glance)
            .field("press", &self.press)
            .field("touch", &self.touch)
            .field("touching", &self.touching)
            .field("meet", &self.meet)
            .finish_non_exhaustive()
    }
}

impl State {
    /// No chats, on the Chats screen of `board`, with chats' messages kept
    /// in `node`. [`State::reload`] reads them.
    #[must_use]
    pub fn new(node: &'static dyn Node, board: &'static Board) -> Self {
        let mut screens = Vec::new();
        _ = screens.push(Screen::chats());
        Self {
            status: StatusStrip::default(),
            battery: BatteryReading::default(),
            links: Links::default(),
            section: Section::default(),
            chats: Vec::new(),
            peers: Vec::new(),
            wall_time: None,
            clock: ClockSettings::default(),
            conversation: None,
            screens,
            node,
            airtime_wait: None,
            banner: None,
            dark: false,
            lock: Lock::default(),
            uptime: 0,
            arrived: Vec::new(),
            ending: None,
            keyboard: Keyboard::new(board.controls.keyboard),
            picker: None,
            recents: Recents::default(),
            glance: None,
            press: None,
            touch: None,
            touching: false,
            meet: MeetState::default(),
            board,
            firmware: "",
        }
    }

    /// The screen, and the sizes laid out on it.
    #[must_use]
    pub const fn metrics(&self) -> &'static Metrics {
        &self.board.metrics
    }

    /// How many chats have unread messages, for the rail's badge.
    #[must_use]
    pub fn unread_chats(&self) -> usize {
        self.chats.iter().filter(|c| c.unread).count()
    }

    #[must_use]
    pub fn chat(&self, chat: ChatId) -> Option<&ChatSummary> {
        self.chats.iter().find(|c| c.id == chat)
    }

    #[must_use]
    pub fn peer(&self, peer: PeerId) -> Option<&PeerSummary> {
        self.peers.iter().find(|p| p.id == peer)
    }

    fn chat_mut(&mut self, chat: ChatId) -> Option<&mut ChatSummary> {
        self.chats.iter_mut().find(|c| c.id == chat)
    }

    /// The messages of `chat`, when it is the open chat.
    #[must_use]
    pub fn conversation(&self, chat: ChatId) -> Option<&Conversation> {
        self.conversation.as_ref().filter(|c| c.chat == chat)
    }

    /// The draft of `chat`, which its composer edits.
    pub fn draft_mut(&mut self, chat: ChatId) -> Option<&mut Draft> {
        self.chat_mut(chat).map(|c| &mut c.draft)
    }

    /// Reads the newest messages of `chat` from the node, as the open
    /// chat's.
    pub(crate) fn load_conversation(&mut self, chat: ChatId) {
        // Filled where it lies: a conversation is too large to build aside.
        let conversation = self.conversation.get_or_insert_with(|| Conversation {
            chat,
            messages: Vec::new(),
            sent: 0,
        });
        conversation.chat = chat;
        conversation.messages.clear();
        self.node.load(chat, &mut conversation.messages);
    }

    /// Sends the draft of `chat`: it becomes the newest message, and the
    /// chat moves to the top of the list. A draft stays a draft while airtime
    /// is spent, or when the node has no room for it.
    pub fn send(&mut self, chat: ChatId) {
        if self.airtime_wait.is_some() {
            return;
        }
        let Some(index) = self
            .chats
            .iter()
            .position(|c| c.id == chat && !c.draft.text().trim().is_empty())
        else {
            return;
        };
        let reply_to = match self.screens.last() {
            Some(Screen::Conversation {
                chat: shown, reply, ..
            }) if *shown == chat => *reply,
            _ => None,
        };
        let summary = &self.chats[index];
        let Some(message) =
            self.node
                .send(chat, summary.draft.text(), reply_to, summary.forward_secret)
        else {
            return;
        };
        if let Some(Screen::Conversation { reply, .. }) = self.screens.last_mut() {
            *reply = None;
        }
        let mut summary = self.chats.remove(index);
        summary.draft.clear();
        summary.preview(&message);
        summary.last_activity = message.time;
        _ = self.chats.insert(0, summary);
        if let Some(conversation) = self.conversation.as_mut().filter(|c| c.chat == chat) {
            conversation.push(message);
            conversation.sent = conversation.sent.wrapping_add(1);
        }
    }

    /// How long ago `chat` was last active, as its row says it.
    #[must_use]
    pub fn age(&self, chat: &ChatSummary) -> Age {
        age(chat.last_activity, self.wall_time)
    }

    /// `time`, in Unix seconds, in local time: in the offset the zone
    /// keeps at that moment, which need not be the one it keeps now.
    #[must_use]
    pub fn local(&self, time: u32) -> Local {
        Local::at(time, self.clock.zone.offset_at(i64::from(time)))
    }

    /// Whether times are written on a 24-hour clock.
    #[must_use]
    pub fn hour24(&self) -> bool {
        self.clock.hour24
    }

    /// The board read its clock: `time`, in Unix seconds, or not known.
    /// Ages are counted to it, so a board sets it each minute.
    pub fn set_wall_time(&mut self, time: Option<u32>) {
        self.wall_time = time;
    }

    /// Reads the chats and saved peers from the node, and the open chat's
    /// messages, as when the interface starts. The open chat keeps the
    /// draft being written in it.
    pub fn reload(&mut self) {
        let open = self.conversation.as_ref().map(|c| c.chat);
        let writing = open
            .and_then(|chat| self.chat(chat))
            .map(|c| c.draft.clone());
        self.chats.clear();
        self.node.chats(&mut self.chats);
        if let Some((chat, draft)) = open.zip(writing)
            && let Some(summary) = self.chat_mut(chat)
        {
            summary.draft = draft;
        }
        self.peers.clear();
        self.node.peers(&mut self.peers);
        match open {
            Some(chat) if self.chat(chat).is_some() => self.load_conversation(chat),
            Some(_) => self.leave_chats(),
            None => {}
        }
        self.refresh_settings();
        self.refresh_peer();
        self.refresh_members();
        self.node.meet(&mut self.meet);
    }

    /// Takes in `event`, from the node, at `now` on the board's clock.
    /// Returns whether it calls for attention, as only a message arriving
    /// can: see [`NodeEvent::Arrived`].
    // Kept out of line, so that what it reads from the node is in a frame of
    // its own, gone once it returns, rather than widening the frame of the
    // board's task on every poll.
    #[inline(never)]
    pub fn apply(&mut self, event: NodeEvent, now: u64) -> bool {
        match event {
            NodeEvent::Arrived { chat, message } => return self.receive(chat, message, now),
            NodeEvent::MessageChanged { chat, message } => self.refresh_message(chat, message),
            NodeEvent::ChatChanged(chat) => self.refresh_chat(chat),
            NodeEvent::ChatRemoved(chat) => self.remove_chat(chat),
            NodeEvent::IdentitiesLearned => self.identities_learned(),
            NodeEvent::PeerChanged(_) => {
                self.peers.clear();
                self.node.peers(&mut self.peers);
                self.refresh_peer();
            }
            NodeEvent::PeerRemoved(peer) => self.remove_peer(peer),
            NodeEvent::PingAnswered(_) => self.refresh_peer(),
            NodeEvent::SettingsChanged | NodeEvent::SettingRefused(_) => self.refresh_settings(),
            NodeEvent::Airtime { wait } => self.airtime_wait = wait,
            NodeEvent::MeetChanged => self.refresh_meet(),
            NodeEvent::Resync => self.reload(),
        }
        false
    }

    /// Whether `chat` is being read: open, on a lit panel.
    fn reading(&self, chat: ChatId) -> bool {
        !self.dark
            && matches!(
                self.screen(),
                Screen::Conversation { chat: shown, .. } if *shown == chat
            )
    }

    /// Lists `fresh` in place of the chat it is, keeping the draft the
    /// interface holds, or first when it is not listed. Returns where it is
    /// listed.
    fn place(&mut self, mut fresh: ChatSummary) -> usize {
        if self.reading(fresh.id) {
            fresh.unread = false;
        }
        match self.chats.iter_mut().position(|c| c.id == fresh.id) {
            Some(index) => {
                let old = &mut self.chats[index];
                core::mem::swap(&mut fresh.draft, &mut old.draft);
                *old = fresh;
                index
            }
            None => {
                if self.chats.is_full() {
                    self.chats.pop();
                }
                _ = self.chats.insert(0, fresh);
                0
            }
        }
    }

    /// Reads how `chat` is listed from the node again.
    fn refresh_chat(&mut self, chat: ChatId) {
        match self.node.chat(chat) {
            Some(fresh) => _ = self.place(fresh),
            None => self.remove_chat(chat),
        }
    }

    /// Reads `message` of the open chat from the node again, taking it in
    /// when it is new among the newest: a placeholder for a missing message,
    /// or one still arriving in parts.
    fn refresh_message(&mut self, chat: ChatId, message: MessageId) {
        let node = self.node;
        let Some(conversation) = self.conversation.as_mut().filter(|c| c.chat == chat) else {
            return;
        };
        match node.message(chat, message) {
            Some(fresh) => conversation.place(fresh),
            None => {
                if let Some(index) = conversation.messages.iter().position(|m| m.id == message) {
                    conversation.messages.remove(index);
                }
            }
        }
    }

    /// Lets go of `chat`, which the node no longer has: its row, what was
    /// shown of it, and its conversation, which returns to the list.
    fn remove_chat(&mut self, chat: ChatId) {
        let Some(index) = self.chats.iter().position(|c| c.id == chat) else {
            return;
        };
        self.chats.remove(index);
        self.arrived.retain(|a| a.chat != chat);
        if self
            .banner
            .is_some_and(|b| b.notice == Notice::Message(chat))
        {
            self.banner = None;
        }
        if self.conversation.as_ref().is_some_and(|c| c.chat == chat) {
            self.leave_chats();
        }
        if let Some(Screen::Chats { menu, .. }) = self.screens.first_mut()
            && menu.is_some_and(|m| m.chat() == chat)
        {
            *menu = None;
        }
        // The row that took its place is focused instead.
        let next = self
            .chats
            .get(index)
            .or_else(|| self.chats.last())
            .map(|c| keys::chat(c.id));
        if let Some(Screen::Chats { focus, row, .. }) = self.screens.first_mut() {
            if *row == Some(keys::chat(chat)) {
                *row = next;
            }
            if focus.current() == Some(keys::chat(chat)) {
                match next {
                    Some(next) => focus.request(next),
                    None => focus.request(keys::rail(Section::Chats)),
                }
            }
        }
    }

    /// Closes everything over the list, the open chat with it, as when what
    /// they showed is gone.
    fn leave_chats(&mut self) {
        self.screens.truncate(1);
        self.conversation = None;
    }
}

impl State {
    /// Whether `message` in the open chat was received rather than sent.
    #[must_use]
    pub fn inbound(&self, message: MessageId) -> bool {
        self.conversation
            .as_ref()
            .and_then(|c| c.messages.iter().find(|m| m.id == message))
            .is_some_and(|m| m.direction == Direction::Inbound)
    }

    /// Reacts to `message` in the open chat with `reaction`, in place of any
    /// reaction I had; choosing the one I had withdraws it.
    pub fn react(&mut self, message: MessageId, reaction: Reaction) {
        let Some(conversation) = self.conversation.as_mut() else {
            return;
        };
        let Some(target) = conversation.messages.iter_mut().find(|m| m.id == message) else {
            return;
        };
        let mine = (target.my_reaction() != Some(reaction)).then_some(reaction);
        target.set_my_reaction(mine);
        self.node.react(conversation.chat, message, mine);
    }

    /// Sends `message` in the open chat again, if it is unconfirmed and
    /// airtime allows. One that was to go under forward secrecy asks
    /// first whether to go without it.
    pub fn retry(&mut self, message: MessageId) {
        if self.airtime_wait.is_some() {
            return;
        }
        let Some(target) = self.unconfirmed(message) else {
            return;
        };
        if target.forward_secret {
            if let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() {
                *unsent = Some(Unsent::Resend(message));
                focus.request(keys::RESEND);
            }
            return;
        }
        self.resend_now(message, false);
    }

    /// The unconfirmed `message` of the open chat. One deleted is gone,
    /// confirmed or not.
    pub(crate) fn unconfirmed(&mut self, message: MessageId) -> Option<&mut Message> {
        self.conversation
            .as_mut()?
            .messages
            .iter_mut()
            .find(|m| m.id == message && m.delivery == Delivery::Unconfirmed && !m.deleted)
    }

    /// Closes what is open over an unconfirmed message: the choices of how
    /// to send it again, or its Delete's confirmation. Focuses the message
    /// and returns it.
    pub fn cancel_resend(&mut self) -> Option<MessageId> {
        let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() else {
            return None;
        };
        let message = unsent.take()?.message();
        focus.request(keys::message(message));
        Some(message)
    }

    /// Sends the message whose choices are open again, as it was to go.
    pub fn resend(&mut self) {
        if let Some(message) = self.cancel_resend() {
            self.resend_now(message, false);
        }
    }

    /// Sends the message whose choices are open again, without forward
    /// secrecy.
    pub fn resend_without_secrecy(&mut self) {
        if let Some(message) = self.cancel_resend() {
            self.resend_now(message, true);
        }
    }

    fn resend_now(&mut self, message: MessageId, without_secrecy: bool) {
        if self.airtime_wait.is_some() {
            return;
        }
        let node = self.node;
        let Some(chat) = self.conversation.as_ref().map(|c| c.chat) else {
            return;
        };
        let Some(target) = self.unconfirmed(message) else {
            return;
        };
        let queued = if without_secrecy {
            node.retry_without_secrecy(chat, message)
        } else {
            node.retry(chat, message)
        };
        if queued {
            target.delivery = Delivery::Sending;
            target.forward_secret &= !without_secrecy;
        }
    }

    /// Takes in `message`, which arrived in `chat` and is already kept by
    /// the node, at `now` on the board's clock. The chat moves to the top of
    /// the list. Returns whether the message calls for attention: it does
    /// not while its chat is being read, or when the chat is muted.
    ///
    /// One that arrives while the panel is dark, or the interface locked,
    /// is listed on the lock screen, and locks the interface if the panel
    /// has only just gone dark: a dark panel lights only to the lock screen.
    fn receive(&mut self, chat: ChatId, message: MessageId, now: u64) -> bool {
        let Some(fresh) = self.node.chat(chat) else {
            return false;
        };
        let Some(message) = self.node.message(chat, message) else {
            self.refresh_chat(chat);
            return false;
        };
        let reading = self.reading(chat);
        if reading {
            self.node.opened(chat);
        }
        let index = self.place(fresh);
        let mut summary = self.chats.remove(index);
        summary.unread = !reading;
        let muted = summary.muted;
        _ = self.chats.insert(0, summary);
        if let Some(conversation) = self.conversation.as_mut().filter(|c| c.chat == chat) {
            conversation.place(message.clone());
        }
        let away = self.dark || self.lock.locked;
        if away {
            self.list_arrival(chat, &message, now);
            self.lock();
        }
        if reading || muted {
            return false;
        }
        if !away && !matches!(self.screen(), Screen::Chats { .. }) {
            // The list shows it arrive; anywhere else, a banner does.
            self.banner = Some(Banner {
                notice: Notice::Message(chat),
                until: now + BANNER_MS,
            });
        }
        true
    }

    /// Lists `message`, the newest of `chat`, on the lock screen, as having
    /// arrived at `now`. A chat already listed moves to the top.
    fn list_arrival(&mut self, chat: ChatId, message: &Message, now: u64) {
        let text = message
            .sender
            .as_ref()
            .and_then(|sender| {
                SharedText::joined(message.text.heap(), &[&sender.name, ": ", &message.text])
            })
            .unwrap_or_else(|| message.text.clone());
        if let Some(index) = self.arrived.iter().position(|a| a.chat == chat) {
            self.arrived.remove(index);
        } else if self.arrived.is_full() {
            self.arrived.pop();
        }
        self.uptime = now;
        _ = self.arrived.insert(
            0,
            Arrived {
                chat,
                text,
                at: now,
            },
        );
    }

    /// The battery as the board last read it. The strip shows its charge,
    /// and whether external power is charging it; falling to
    /// [`BATTERY_LOW_PERCENT`] with nothing charging turns the strip's
    /// battery amber, and a banner says so once while the panel is lit.
    pub fn battery(&mut self, reading: BatteryReading, now: u64) {
        self.battery = reading;
        let (percent, charging) = (reading.percent, reading.charging());
        self.status.battery_segments = percent.map_or(0, battery_segments);
        self.status.battery_percent = percent;
        self.status.charging = charging;
        let was = self.status.battery_low;
        // Low until it charges or climbs clear, so a reading wavering at
        // the threshold says so once.
        let low = !charging
            && match percent {
                Some(percent) if was => percent < BATTERY_RECOVERED_PERCENT,
                Some(percent) => percent <= BATTERY_LOW_PERCENT,
                None => was,
            };
        self.status.battery_low = low;
        if let Some(percent) = percent.filter(|_| low && !was && !self.dark) {
            self.banner = Some(Banner {
                notice: Notice::BatteryLow { percent },
                until: now + BANNER_MS,
            });
        }
    }

    /// Whether `reading` changes what is shown: its charge or what external
    /// power is doing, always, and the voltage while the Battery screen
    /// shows it. A board reading often takes in only these, so that a
    /// wavering voltage nobody is looking at draws nothing.
    #[must_use]
    pub fn battery_changes(&self, reading: &BatteryReading) -> bool {
        let shown = &self.battery;
        let voltage_shown = matches!(
            self.screen(),
            Screen::Device {
                page: DevicePage::Battery,
                ..
            }
        );
        shown.percent != reading.percent
            || shown.charge != reading.charge
            || (voltage_shown && shown.millivolts != reading.millivolts)
    }

    /// The battery is empty: the screen shows only its icon, `lit` or not.
    pub fn battery_empty(&mut self, lit: bool) {
        self.save_recents();
        self.ending = Some(Ending::BatteryEmpty { lit });
    }

    /// The board is turning off as asked, and says so.
    pub fn shutting_down(&mut self) {
        self.save_recents();
        self.ending = Some(Ending::ShuttingDown);
    }

    /// Hands the node the recent picks, if they changed since it last had
    /// them.
    fn save_recents(&mut self) {
        if self.recents.save_at.take().is_some() {
            self.node.keep_recent_picks(&self.recents.text());
        }
    }

    /// Opens the character picker, on the recent picks.
    pub fn open_picker(&mut self) {
        let node = self.node;
        self.recents.load(|| node.recent_picks());
        self.picker = Some(Picker::default());
    }

    /// Opens the character picker to react to `message` with an emoji.
    pub fn open_picker_to_react(&mut self, message: MessageId) {
        self.open_picker();
        self.picker = Some(Picker::to_react(message));
    }

    /// The picker's cells to a row, on this board.
    #[must_use]
    pub fn picker_columns(&self) -> u16 {
        crate::ui::picker_columns(self.metrics()) as u16
    }

    /// When the screen next changes by itself, on the board's clock.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        [
            self.banner.map(|b| b.until),
            self.glance.map(Glance::until),
            self.lock.deadline(),
            self.press.and_then(|p| p.hold_until),
            self.touch.and_then(|t| t.hold_until),
            self.recents.save_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Lets go of whatever has had its time by `now`.
    pub fn expire(&mut self, now: u64) {
        self.uptime = now;
        self.expire_lock(now);
        if self.banner.is_some_and(|b| b.until <= now) {
            self.banner = None;
        }
        if self.glance.is_some_and(|g| g.until() <= now) {
            self.glance = None;
        }
        if let Some(mut press) = self.press
            && press.hold_until.is_some_and(|until| until <= now)
        {
            press.hold_until = None;
            press.held = self.hold();
            self.press = Some(press);
        }
        if self.recents.save_at.is_some_and(|at| at <= now) {
            self.save_recents();
        }
    }

    /// What lies over the screen.
    #[must_use]
    pub fn overlay(&self) -> Option<Overlay> {
        self.ending
            .map(Overlay::Ending)
            .or(self.picker.as_ref().map(|_| Overlay::Picker))
            .or(self.glance.map(Overlay::Glance))
            .or(self.banner.map(|b| Overlay::Banner(b.notice)))
    }

    /// Moves the screen's brightness `steps` levels, more brightening, and
    /// returns the level it is at.
    pub fn step_brightness(&mut self, steps: i8) -> u8 {
        let level = (i16::from(brightness_level(self.node.brightness())) + i16::from(steps))
            .clamp(1, i16::from(BRIGHTNESS_LEVELS)) as u8;
        self.node.set_brightness(brightness_at(level));
        level
    }

    /// Turns the screen's brightness by `detents` levels, and shows it:
    /// turned up, it brightens, and turned down, it dims.
    pub fn adjust_brightness(&mut self, detents: i8, now: u64) {
        let level = self.step_brightness(detents.saturating_neg());
        self.glance = Some(Glance::Brightness {
            level,
            until: now + GLANCE_MS,
        });
    }

    /// Switches the keyboard light, and shows it.
    pub fn switch_keyboard_light(&mut self, now: u64) {
        self.toggle_keyboard_light();
        self.glance = Some(Glance::KeyboardLight {
            on: self.node.keyboard().light,
            until: now + GLANCE_MS,
        });
    }
}

/// Appends as much of `s` as fits, ending between grapheme clusters.
fn push_cut<const N: usize>(into: &mut String<N>, s: &str) {
    let room = N - into.len();
    let _ = into.push_str(umsh_grapheme::cut(s, room));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static HEAP: std::alloc::System = std::alloc::System;

    fn message(id: MessageId, text: &str) -> Message {
        Message {
            id,
            direction: Direction::Inbound,
            sender: None,
            text: SharedText::new(&HEAP, text).unwrap(),
            delivery: Delivery::Sent,
            reactions: Reactions::new(),
            card: None,
            reply: None,
            time: None,
            presence: Presence::Present,
            edited: false,
            deleted: false,
            late: false,
            forward_secret: false,
            parts: None,
        }
    }

    fn ids(conversation: &Conversation) -> std::vec::Vec<MessageId> {
        conversation.messages.iter().map(|m| m.id).collect()
    }

    #[test]
    fn a_message_takes_its_place_among_the_newest() {
        let mut conversation = Conversation {
            chat: 1,
            messages: Messages::new(),
            sent: 0,
        };
        for id in [10, 12, 13] {
            conversation.place(message(id, "listed"));
        }
        // A missing message's placeholder, then its late arrival.
        conversation.place(Message {
            presence: Presence::PendingRepair,
            ..message(11, "")
        });
        assert_eq!(ids(&conversation), [10, 11, 12, 13]);
        conversation.place(message(11, "late"));
        assert_eq!(ids(&conversation), [10, 11, 12, 13]);
        assert_eq!(conversation.messages[1].text.as_str(), "late");
        assert_eq!(conversation.messages[1].presence, Presence::Present);

        // Full, a newer message drops the oldest; an older one stays out.
        for id in 20..20 + MAX_MESSAGES as MessageId - 4 {
            conversation.place(message(id, "newer"));
        }
        assert!(conversation.messages.is_full());
        conversation.place(message(14, "between"));
        assert_eq!(conversation.messages[0].id, 11);
        assert_eq!(conversation.messages[3].id, 14);
        conversation.place(message(5, "old"));
        assert!(conversation.messages.iter().all(|m| m.id != 5));
    }
}
