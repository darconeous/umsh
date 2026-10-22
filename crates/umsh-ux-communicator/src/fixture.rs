//! Stand-in content until a real node backs the interface: the chats from
//! the T-LoRa Pager mockup, so a render compares directly with it. It
//! behaves as a node does: what changes is announced as events, and its
//! messages arrive and its identities are answered on timers of its own.

use core::cell::{Cell, RefCell, RefMut};

use crate::avatar::{AvatarStyle, BuiltinChannel, PeerShape};
use crate::board::Board;
use crate::model::{
    Bluetooth, BluetoothReading, Card, ChannelAccess, ChannelEntry, ChatId, ChatKind, ChatSummary,
    Chats, ClockSettings, ClockSource, Contact, ContactUri, Delivery, Details, Direction,
    EventQueue, Exchange, ExchangeEnd, Fix, Gnss, GnssReading, Heard, Invite, KeyboardSettings,
    Links, MAX_CHATS, MAX_HEARD, MAX_PEERS, MESSAGE_LEN, MeetState, Member, Message, MessageId,
    Messages, NearbyDevice, NearbyId, Node, NodeEvent, Parts, PeerDetail, PeerEntry, PeerId,
    PeerSummary, Peers, Presence, Profile, Quote, RadioSettings, Reacted, Reaction, Reactions,
    Reactor, Rule, Sender, Setting, ShareUri, Shareable, State, StatusStrip, TRANSMIT_POWER,
    brightness_at, push_newest, word_match,
};
use crate::models;
use crate::picker::RecentText;
use crate::text::{DraftText, SharedText, TextHeap};
use buoyant::view::{EditBuffer, EditText as _};
use heapless::{String, Vec};
use umsh_ulcp::profiles::VETTED;

fn s<const N: usize>(text: &str) -> String<N> {
    String::try_from(text).expect("fixture text fits")
}

/// The mockup's time, 14:32, in Unix seconds: the fixture's clock starts
/// here, on a minute.
const STARTED: u32 = 1_792_247_520;

/// How long an identity asked for takes to arrive, in milliseconds.
const IDENTITY_DELAY: u64 = 2000;
/// How long after an arrival, when arrivals are paced, the next comes.
const ARRIVAL_SPACING: u64 = 40_000;

/// A channel member as the channel shows them: a name the mockup gives
/// them, or their hint when nothing better is known.
fn member(name: &str) -> Sender {
    let (color, hint, shape, _) = member_traits(name);
    Sender {
        name: s(name),
        avatar: AvatarStyle::peer(color, hint, shape),
    }
}

/// The channel member `name`'s color, hint, shape, and address. Those with
/// names have made their identity known; the one shown by their hint has
/// not.
fn member_traits(name: &str) -> ([u8; 3], &'static str, PeerShape, Option<&'static str>) {
    match name {
        "Sam" => (
            [218, 50, 133],
            "j3DC",
            PeerShape::Circle,
            Some("j3DCtP9oDcDsv6D8njFcSGvuiLjrAbbY2fru5HBh9gBk"),
        ),
        "Kit" | "Kit Moreno" => (
            [187, 150, 80],
            "iMyA",
            PeerShape::Circle,
            Some("iMyAmdi5uCtG278cpgWezD7WJ2nkTBYa8B92BXfWwRYR"),
        ),
        "Lee Park" => (
            [120, 140, 92],
            "R9f2",
            PeerShape::Circle,
            Some("R9f2wQe8LxV3nTGk5ZbYcJhAs7mPdU1oKrN4tFiHvXyE"),
        ),
        "Ranger Station" => (
            [104, 44, 156],
            "aExj",
            PeerShape::Circle,
            Some("aExjT6pRw2KsL9mQvBzN3cYhG8dUoF5iAeZ1tXkPnWr7"),
        ),
        _ => ([245, 212, 31], "4Fz*", PeerShape::Hexagon, None),
    }
}

/// The member known by their hint until asked, and who they turn out to be.
const UNIDENTIFIED: &str = "Member 4Fz*";
const IDENTIFIED: (&str, &str) = ("Robin Hale", "4FzRC8jVNGDYhYCXKWyHDHzm8MakqsCxtGBGDpQdZDtk");

/// What is known of the channel member `name`, who is `identified` when
/// their identity has arrived.
fn member_card(name: &str, identified: bool) -> Member {
    let (color, hint, shape, address) = member_traits(name);
    if name == UNIDENTIFIED && identified {
        let (name, address) = IDENTIFIED;
        let hint = &address[..4];
        return Member {
            sender: Sender {
                name: s(name),
                avatar: AvatarStyle::peer(color, hint, shape),
            },
            hint: s(hint),
            address: Some(s(address)),
            heard: s("2m"),
            saved: false,
        };
    }
    Member {
        sender: member(name),
        hint: s(hint),
        address: address.map(s),
        heard: s("2m"),
        saved: false,
    }
}

/// A chat as the fixture keeps it.
struct ChatRow {
    id: ChatId,
    avatar: AvatarStyle,
    name: String<32>,
    kind: ChatKind,
    unread: bool,
    muted: bool,
    /// When it was last active, in Unix seconds.
    activity: u32,
    draft: Option<SharedText>,
}

/// How long before the fixture starts the mockup's chats were last
/// active, in seconds.
fn quiet_for(chat: ChatId) -> u32 {
    match chat {
        1 => 2 * 60,
        2 => 9 * 60,
        3 => 41 * 60,
        4 => 60 * 60,
        5 => 3 * 60 * 60,
        6 => 5 * 60 * 60,
        _ => 6 * 60 * 60,
    }
}

/// The mockup's chats, most recently active first, with their drafts kept
/// on `heap`.
fn mockup_chats(heap: TextHeap) -> [ChatRow; 7] {
    let row = |id, avatar, name, kind, unread, muted, draft: &str| ChatRow {
        id,
        avatar,
        name: s(name),
        kind,
        unread,
        muted,
        activity: STARTED - quiet_for(id),
        draft: (!draft.is_empty())
            .then(|| SharedText::new(heap, draft))
            .flatten(),
    };
    let peer = |hops| ChatKind::Peer { hops: Some(hops) };
    let channel = |access| ChatKind::Channel { access };
    [
        row(
            1,
            AvatarStyle::peer([235, 187, 21], "kBkQ", PeerShape::Circle),
            "Ridge Medic",
            peer(2),
            false,
            false,
            "On my way, save me some hot coffee",
        ),
        row(
            2,
            AvatarStyle::channel(None, "Trail Crew", [203, 24, 112]),
            "Trail Crew",
            channel(ChannelAccess::Private),
            true,
            false,
            "",
        ),
        row(
            3,
            AvatarStyle::peer([179, 246, 158], "YmRG", PeerShape::Circle),
            "Pat Okafor",
            peer(1),
            false,
            false,
            "",
        ),
        row(
            4,
            AvatarStyle::channel(Some(BuiltinChannel::Public), "Public", [0, 0, 0]),
            "Public",
            channel(ChannelAccess::Named),
            false,
            true,
            "",
        ),
        row(
            5,
            AvatarStyle::peer([94, 10, 224], "H1x*", PeerShape::Circle),
            "Jo Reyes",
            peer(3),
            false,
            false,
            "",
        ),
        row(
            6,
            AvatarStyle::channel(Some(BuiltinChannel::Emergency), "EMERGENCY", [0, 0, 0]),
            "EMERGENCY",
            channel(ChannelAccess::Clear),
            false,
            false,
            "",
        ),
        row(
            STATES,
            AvatarStyle::peer([218, 50, 133], "j3DC", PeerShape::Circle),
            "Sam",
            peer(2),
            false,
            false,
            "",
        ),
    ]
}

/// Ridge Medic's address. They are not among my peers.
const RIDGE: &str = "kBkQ7vZr2mXcN4pLwT9sYhGdA3eFuJ6bK1oRiVnE8qWz";

/// The chat that shows what can become of a message on its way: since
/// yesterday, with Sam.
const STATES: ChatId = 7;

/// Who sent a message.
#[derive(Clone, Copy)]
enum From {
    Me,
    /// The peer of a peer chat.
    Peer,
    /// A member of a channel.
    Member(&'static str),
}

/// The messages of `chat`, oldest first.
fn messages(chat: ChatId) -> &'static [(From, &'static str)] {
    match chat {
        1 => &[
            (
                From::Peer,
                "At the north junction yet? Sam says the creek is high",
            ),
            (From::Me, "Just passed it. ETA 20 min."),
            (From::Peer, "See you at the hut"),
        ],
        2 => &[
            (From::Member("Sam"), "At the saddle"),
            (From::Member("Member 4Fz*"), "Two of us behind you"),
            (From::Member("Sam"), "Will wait 10 min"),
        ],
        3 => &[
            (From::Peer, "Is Bald Knob back up?"),
            (From::Me, "Not yet, Saturday."),
            (From::Me, "Bring the spare antenna?"),
        ],
        4 => &[(From::Member("Kit"), "Anyone near Mill Creek?")],
        6 => &[
            (From::Member("Kit Moreno"), "Heard a slide near mile 3?"),
            (From::Member("Lee Park"), "Rockslide on FS 42 at mile 3"),
            (From::Member("Ranger Station"), "Copy. Crew on the way."),
        ],
        5 => &[
            (From::Me, "Which channel is base camp on?"),
            (From::Peer, "This one:"),
            // An invitation, and nothing besides.
            (From::Peer, ""),
            (
                From::Peer,
                "Hut is open and the stove works. Water from the spring is fine if you \
                 filter it. Snow starts about 200 m above the hut, so leave the trail \
                 runners and bring boots. The bunk room sleeps six; we have four, so there \
                 is room for you and Sam. Radio check at 19:00 on the usual channel.",
            ),
            (From::Peer, "Thanks!"),
        ],
        STATES => &[
            (From::Me, "Leaving at 7"),
            (From::Peer, "Stove is lit"),
            (From::Peer, "Coffee in ten"),
            // Taken back.
            (From::Peer, ""),
            // Asked for again.
            (From::Peer, ""),
            (From::Peer, "It covers the north side now"),
            // Not to come.
            (From::Peer, ""),
            (From::Me, "How is the trail past the creek?"),
            (From::Peer, "Washed out past the second crossing"),
            (From::Peer, "Snow starts above the hut, so bring boots"),
        ],
        _ => &[],
    }
}

/// The channel a message of the fixture's invites to, and its link, which
/// is the whole of what the message says.
fn invite(heap: TextHeap, chat: ChatId, index: usize) -> Option<(Invite, ShareUri)> {
    if chat != 5 || index != 2 {
        return None;
    }
    let invite = Invite {
        name: SharedText::new(heap, "Base Camp")?,
        builtin: None,
        tint: [46, 125, 196],
        access: ChannelAccess::Private,
        key: umsh_core::base58::decode(JOINED_KEY.as_bytes()).ok()?,
    };
    Some((invite, private_uri(JOINED_KEY, "Base Camp")?))
}

/// Others' reactions to a message of the fixture's, one each.
fn their_reactions(chat: ChatId, index: usize) -> &'static [(From, Reaction)] {
    match (chat, index) {
        (1, 1) => &[(From::Peer, Reaction::Heart)],
        (2, 1) => &[
            (From::Member("Sam"), Reaction::ThumbsUp),
            (From::Member("Member 4Fz*"), Reaction::Exclaim),
        ],
        _ => &[],
    }
}

/// Messages that arrive after the fixture starts, in order.
const ARRIVALS: [(ChatId, From, &str); 3] = [
    (
        2,
        From::Member("Sam"),
        "Will wait 10 min at the saddle, then we head down",
    ),
    (3, From::Peer, "Got the antenna. Bringing two."),
    (5, From::Peer, "Are you on the ridge yet?"),
];

/// How far a message of the fixture's got.
fn delivery(chat: ChatId, index: usize) -> Delivery {
    if (chat, index) == (3, 2) || (chat, index) == (STATES, 7) {
        Delivery::Unconfirmed
    } else {
        Delivery::Delivered
    }
}

/// What became of one of the fixture's messages, besides arriving whole.
#[derive(Clone, Copy)]
struct Condition {
    presence: Presence,
    edited: bool,
    deleted: bool,
    late: bool,
    forward_secret: bool,
    /// The message it replies to, by its place.
    reply: Option<usize>,
    parts: Option<Parts>,
}

fn condition(chat: ChatId, index: usize) -> Condition {
    let mut condition = Condition {
        presence: Presence::Present,
        edited: false,
        deleted: false,
        late: false,
        forward_secret: false,
        reply: None,
        parts: None,
    };
    if chat == STATES {
        match index {
            2 => condition.edited = true,
            3 => condition.deleted = true,
            4 => condition.presence = Presence::PendingRepair,
            5 => condition.late = true,
            6 => condition.presence = Presence::Unavailable,
            7 => condition.forward_secret = true,
            8 => condition.reply = Some(7),
            9 => {
                condition.parts = Some(Parts {
                    count: 3,
                    received: 0b011,
                    lost: 0,
                });
            }
            _ => {}
        }
    }
    condition
}

/// What a reply quotes of `message`, in the chat called `chat_name`.
fn quote_of(heap: TextHeap, message: &Message, chat_name: &str) -> Option<Quote> {
    let name = match (message.direction, &message.sender) {
        (Direction::Outbound, _) => None,
        (Direction::Inbound, Some(sender)) => Some(SharedText::new(heap, &sender.name)?),
        (Direction::Inbound, None) => Some(SharedText::new(heap, chat_name)?),
    };
    Some(Quote {
        name,
        text: message.text.clone(),
    })
}

/// Where the fixture's own messages are numbered: by chat, then by place.
fn mockup_id(chat: ChatId, index: usize) -> MessageId {
    (chat << 8) | index as MessageId
}

/// Where messages sent or received since the fixture started are numbered
/// from, above its own.
const FIRST_KEPT: MessageId = 0x1_0000;

/// When the fixture's message `index` in `chat` was sent: a minute apart,
/// the last when its chat was last active, but for the first of the
/// states, the evening before.
fn mockup_time(chat: ChatId, index: usize) -> u32 {
    let count = messages(chat).len();
    let time = STARTED - quiet_for(chat) - 60 * (count - 1 - index) as u32;
    if chat == STATES && index == 0 {
        time - 13 * 60 * 60
    } else {
        time
    }
}

/// The fixture's message, with its text kept on `heap`, when there is room.
fn mockup_message(
    heap: TextHeap,
    chat: ChatId,
    index: usize,
    (from, text): (From, &str),
) -> Option<Message> {
    assert!(text.len() <= MESSAGE_LEN, "fixture message fits");
    let time = mockup_time(chat, index);
    let condition = condition(chat, index);
    let reply = match condition.reply {
        Some(quoted) => {
            let message = mockup_message(heap, chat, quoted, *messages(chat).get(quoted)?)?;
            let chat_name = mockup_chats(heap)
                .into_iter()
                .find(|row| row.id == chat)
                .map(|row| row.name)
                .unwrap_or_default();
            quote_of(heap, &message, &chat_name)
        }
        None => None,
    };
    let (invite, text) = match invite(heap, chat, index) {
        Some((invite, uri)) => (Some(invite), SharedText::new(heap, &uri)?),
        None => (None, SharedText::new(heap, text)?),
    };
    Some(Message {
        id: mockup_id(chat, index),
        direction: match from {
            From::Me => Direction::Outbound,
            From::Peer | From::Member(_) => Direction::Inbound,
        },
        sender: match from {
            From::Member(name) => Some(member(name)),
            From::Me | From::Peer => None,
        },
        text,
        delivery: delivery(chat, index),
        reactions: their_reactions(chat, index)
            .iter()
            .map(|&(_, reaction)| Reacted {
                reaction,
                count: 1,
                mine: false,
            })
            .collect::<Reactions>(),
        card: invite.map(Card::Channel),
        reply,
        time: Some(time),
        presence: condition.presence,
        edited: condition.edited,
        deleted: condition.deleted,
        late: condition.late,
        forward_secret: condition.forward_secret,
        parts: condition.parts,
    })
}

/// How many messages sent or received since it started the fixture keeps,
/// across all chats, and how many of each thing made since.
const KEPT: usize = 8;
/// How many chats the fixture keeps: its own, and those made since.
const CHATS: usize = 7 + 2 * KEPT;
/// How many events wait for the interface before they overflow.
const EVENTS: usize = 16;

/// The fixture's messages, and the ones sent or received since it started,
/// with their text kept on a heap of the device's choosing.
pub struct Store {
    heap: TextHeap,
    /// The chats, most recently active first: the mockup's, until it is
    /// first read, and those made since.
    chats: RefCell<Vec<ChatRow, CHATS>>,
    chats_made: Cell<bool>,
    kept: RefCell<Vec<(ChatId, Message), KEPT>>,
    /// How many of the fixture's arrivals have arrived.
    arrived: Cell<usize>,
    /// My reactions, by message.
    mine: RefCell<Vec<(MessageId, Reaction), KEPT>>,
    /// Unconfirmed messages sent again, and those of them sent again
    /// without forward secrecy.
    retried: RefCell<Vec<MessageId, KEPT>>,
    without_secrecy: RefCell<Vec<MessageId, KEPT>>,
    /// Mine, deleted for everyone.
    deleted: RefCell<Vec<MessageId, KEPT>>,
    next: Cell<MessageId>,
    /// The unidentified member's identity has been asked for, and has
    /// arrived.
    asked: Cell<bool>,
    identified: Cell<bool>,
    /// Members saved as peers, by address, in the order they were saved.
    saved: RefCell<Vec<(String<44>, PeerSummary), KEPT>>,
    /// Direct chats made with members, by address.
    direct: RefCell<Vec<String<44>, KEPT>>,
    /// Channels joined since, by name, and who can read them.
    joined: RefCell<Vec<(String<32>, ChannelAccess), KEPT>>,
    /// Peers with forward secrecy turned on, peers pinged, and peers forgotten.
    secrecy: RefCell<Vec<PeerId, KEPT>>,
    pinged: RefCell<Vec<PeerId, KEPT>>,
    forgotten: RefCell<Vec<PeerId, KEPT>>,
    /// This node's name, once it is given one.
    name: RefCell<Option<String<24>>>,
    /// The radio's settings.
    radio_enabled: Cell<bool>,
    profile: Cell<Profile>,
    forwarding: Cell<bool>,
    share_location: Cell<bool>,
    transmit_power: Cell<i8>,
    keyboard: Cell<KeyboardSettings>,
    /// The character picker's recent picks, as kept.
    picks: RefCell<RecentText>,
    clock: Cell<ClockSettings>,
    brightness: Cell<u8>,
    /// Bluetooth and the GNSS receiver, on or off.
    bluetooth: Cell<bool>,
    gnss: Cell<bool>,
    /// What Add peer shows, and whether the other holder of the exchange
    /// pressed Same.
    meet: RefCell<MeetState>,
    meet_theirs: Cell<bool>,
    /// How many times Add peer opened, for a new color each time.
    meet_opened: Cell<u8>,
    events: RefCell<EventQueue<EVENTS>>,
    /// The board's clock, in milliseconds, as it last told the fixture. The
    /// fixture's own clock runs from [`STARTED`] with it.
    now: Cell<u64>,
    /// How far the clock has been set from where it started, in seconds.
    set_by: Cell<i64>,
    /// Where the clock's time came from, and when.
    clock_source: Cell<(ClockSource, u64)>,
    /// When, on the board's clock, the next arrival and the identity asked
    /// for come.
    arrival_at: Cell<Option<u64>>,
    identity_at: Cell<Option<u64>>,
}

impl Store {
    #[must_use]
    pub const fn new(heap: TextHeap) -> Self {
        Self {
            heap,
            chats: RefCell::new(Vec::new()),
            chats_made: Cell::new(false),
            kept: RefCell::new(Vec::new()),
            arrived: Cell::new(0),
            mine: RefCell::new(Vec::new()),
            retried: RefCell::new(Vec::new()),
            without_secrecy: RefCell::new(Vec::new()),
            deleted: RefCell::new(Vec::new()),
            next: Cell::new(FIRST_KEPT),
            asked: Cell::new(false),
            identified: Cell::new(false),
            saved: RefCell::new(Vec::new()),
            direct: RefCell::new(Vec::new()),
            joined: RefCell::new(Vec::new()),
            secrecy: RefCell::new(Vec::new()),
            pinged: RefCell::new(Vec::new()),
            forgotten: RefCell::new(Vec::new()),
            name: RefCell::new(None),
            radio_enabled: Cell::new(true),
            profile: Cell::new(Profile::Vetted(0)),
            forwarding: Cell::new(true),
            share_location: Cell::new(false),
            transmit_power: Cell::new(22),
            clock: Cell::new(ClockSettings {
                automatic: Some(true),
                hour24: true,
                zone: Rule::UTC,
            }),
            keyboard: Cell::new(KeyboardSettings {
                capitalize: true,
                period: true,
                light: true,
            }),
            picks: RefCell::new(RecentText::new()),
            brightness: Cell::new(brightness_at(5)),
            bluetooth: Cell::new(true),
            gnss: Cell::new(true),
            meet: RefCell::new(MeetState::new()),
            meet_theirs: Cell::new(false),
            meet_opened: Cell::new(0),
            events: RefCell::new(EventQueue::new()),
            now: Cell::new(0),
            set_by: Cell::new(0),
            clock_source: Cell::new((ClockSource::Gnss, 0)),
            arrival_at: Cell::new(None),
            identity_at: Cell::new(None),
        }
    }
}

/// A node heard nearby but not saved.
struct HeardNode {
    address: &'static str,
    color: [u8; 3],
    shape: PeerShape,
    name: &'static str,
    distance: &'static str,
    age: &'static str,
}

/// Nodes heard nearby but not saved, most recently heard first. Find's
/// mockup board has these two.
const HEARD: [HeardNode; 2] = [
    HeardNode {
        address: "8UQWMASi45ub7Qe4ZE36UT5G6cU4ud8Fhhe4deS4F3cw",
        color: [61, 214, 140],
        shape: PeerShape::Triangle,
        name: "Riverbend Camp",
        distance: "Nearby",
        age: "12m",
    },
    HeardNode {
        address: "6aNt9KTAb8dLcukC7edhDQ7cn5d4gEYkbUrMWeWQLGsC",
        color: [26, 92, 64],
        shape: PeerShape::Circle,
        name: "Ridge Runner",
        distance: "2 hops",
        age: "1d",
    },
];

/// One of the fixture's saved peers.
struct SavedPeer {
    address: &'static str,
    color: [u8; 3],
    hint: &'static str,
    name: &'static str,
    hops: Option<u8>,
    signal: Option<u8>,
    /// How long ago they were last heard, as the Peers list says it and as
    /// their screen does.
    heard: &'static str,
    heard_long: &'static str,
    /// How they are reached.
    route: Option<&'static str>,
    /// The chat with them, when there is one.
    chat: Option<ChatId>,
}

/// The fixture's saved peers, most recently heard first, numbered from 1.
const PEERS: [SavedPeer; 4] = [
    SavedPeer {
        address: "YmRGmitsDJy13p2eiuxziZph6qDZFS1pcN1uaofYjM45",
        color: [179, 246, 158],
        hint: "YmRG",
        name: "Pat Okafor",
        hops: Some(1),
        signal: Some(3),
        heard: "5m",
        heard_long: "5 min ago",
        route: Some("Direct \u{B7} \u{2212}97 dBm"),
        chat: Some(3),
    },
    SavedPeer {
        address: "H1xBRrvv1ExLhX3wqH3LdU7ew8dkovDZsgMuCcPZXa7y",
        color: [94, 10, 224],
        hint: "H1x*",
        name: "Jo Reyes",
        hops: Some(3),
        signal: None,
        heard: "1h",
        heard_long: "1 hr ago",
        route: Some("3 hops"),
        chat: Some(5),
    },
    SavedPeer {
        address: "hhaevhk7fePTPDkBgW55Sd5Zh9oy3bC5ueFrUxcVUtYg",
        color: [178, 186, 92],
        hint: "hhae",
        name: "Rick Alvarez",
        hops: Some(3),
        signal: None,
        heard: "3h",
        heard_long: "3 hr ago",
        route: Some("3 hops"),
        chat: None,
    },
    SavedPeer {
        address: "Dc7qZiXV4uuYKB4TvuRhW2XFUgdP5v986FkCyhq9FAyq",
        color: [64, 160, 200],
        hint: "Dc7q",
        name: "Dana Cho",
        hops: Some(2),
        signal: None,
        heard: "4h",
        heard_long: "4 hr ago",
        route: Some("2 hops"),
        chat: None,
    },
];

/// How a node URI begins.
const PEER_INVITATION: &str = "umsh:n:";

/// The mockup's exchange code.
const MEET_CODE: u32 = 482_931;

/// What the other holder of an exchange does: see [`Store::meet_peer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeetStep {
    /// Asks to exchange, from the first device listed.
    Asks,
    /// Answers our request.
    Answers(bool),
    Same,
    Different,
    /// Backs out.
    Leaves,
}

/// Where direct chats made with members are numbered from, above the
/// fixture's own chats.
const FIRST_DIRECT: ChatId = 0x100;
/// Where members saved as peers are numbered from, above the fixture's own
/// peers.
const FIRST_SAVED: PeerId = 0x100;
/// Where channels joined since are numbered from.
const FIRST_JOINED: ChatId = 0x200;
const CHANNEL_INVITATION: &str = "umsh:ck:";

/// This node's address, as the mockup's Share screen shows it.
const ADDRESS: &str = "Geb9QfXhe5f1vXHcFDnXbvcXShxAFhAxaRp1jr5Bqe3L";
/// Private channels' keys: Trail Crew's, and any joined from an invitation.
const TRAIL_CREW_KEY: &str = "5BFn8YGKJ6pZR4qV3tW7mNhDrXsCxEaL9kUv2wAjT8bP";
const JOINED_KEY: &str = "8xQvW3mZr7KpN2sTfYhB6cLdJ4gE9aUoRiV5tHnXkM1w";

/// As much of `text` as a name holds.
fn cut<const N: usize>(text: &str) -> String<N> {
    let mut name = String::new();
    for c in text.chars() {
        if name.push(c).is_err() {
            break;
        }
    }
    name
}

/// A channel's name as its key is derived from: ASCII folded to lowercase.
fn folded(name: &str) -> String<32> {
    let mut folded = cut(name);
    folded.make_ascii_lowercase();
    folded
}

/// A URI parameter's value with its percent-encoding undone; what does not
/// decode to text stays as it was typed.
fn decoded(value: &str) -> String<32> {
    let mut bytes: Vec<u8, 32> = Vec::new();
    let mut rest = value.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        let escaped = match (byte, tail) {
            (b'%', [high, low, after @ ..]) => core::str::from_utf8(&[*high, *low])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .map(|byte| (byte, after)),
            _ => None,
        };
        let (byte, tail) = escaped.unwrap_or((byte, tail));
        if bytes.push(byte).is_err() {
            break;
        }
        rest = tail;
    }
    core::str::from_utf8(&bytes).map_or_else(|_| cut(value), cut)
}

/// A channel avatar's color, from its name.
fn tint(name: &str) -> [u8; 3] {
    let hash = name.bytes().fold(0x811C_9DC5_u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    let [r, g, b, _] = hash.to_be_bytes();
    [r, g, b]
}

/// `name` as a URI parameter: what is not a letter, a digit, or `-._~` is
/// percent-encoded.
fn push_encoded(uri: &mut ShareUri, name: &str) -> Option<()> {
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            uri.push(char::from(byte)).ok()?;
        } else {
            core::fmt::write(uri, format_args!("%{byte:02X}")).ok()?;
        }
    }
    Some(())
}

fn private_uri(key: &str, name: &str) -> Option<ShareUri> {
    let mut uri = ShareUri::new();
    core::fmt::write(&mut uri, format_args!("umsh:ck:{key}?n=")).ok()?;
    push_encoded(&mut uri, name)?;
    Some(uri)
}

impl Store {
    /// The chats, the mockup's made the first time they are read.
    fn rows(&self) -> RefMut<'_, Vec<ChatRow, CHATS>> {
        let mut rows = self.chats.borrow_mut();
        if !self.chats_made.replace(true) {
            for row in mockup_chats(self.heap) {
                _ = rows.push(row);
            }
        }
        rows
    }

    fn queue(&self, event: NodeEvent) {
        self.events.borrow_mut().push(event);
    }

    /// The exchange ends for `end`, or else goes on to `next`.
    fn meet_ends_or(&self, end: Option<ExchangeEnd>, next: Exchange) {
        let mut meet = self.meet.borrow_mut();
        if meet.exchange == Exchange::Closed {
            return;
        }
        meet.exchange = match end {
            Some(end) => {
                // The other device's key is spent with ours.
                if let Some(with) = meet.with {
                    meet.devices.retain(|d| d.id != with.id);
                }
                Exchange::Ended(end)
            }
            None => next,
        };
        drop(meet);
        self.queue(NodeEvent::MeetChanged);
    }

    /// Contacts crossed: the other device is Kit Moreno's, not saved.
    fn meet_exchanged(&self) {
        let address = member_traits("Kit Moreno").3.unwrap_or_default();
        let member = self.known_at(address);
        let mut meet = self.meet.borrow_mut();
        if let Some(with) = meet.with {
            meet.devices.retain(|d| d.id != with.id);
        }
        meet.exchange = Exchange::Exchanged(member);
        drop(meet);
        self.queue(NodeEvent::MeetChanged);
    }

    /// What the other holder of an exchange does, as the fixture plays it.
    pub fn meet_peer(&self, step: MeetStep) {
        let exchange = self.meet.borrow().exchange.clone();
        match (step, exchange) {
            (MeetStep::Asks, Exchange::Idle) => {
                let device = self.meet.borrow().devices.first().copied();
                if let Some(device) = device {
                    let mut meet = self.meet.borrow_mut();
                    meet.with = Some(device);
                    meet.exchange = Exchange::Asked(device);
                    drop(meet);
                    self.queue(NodeEvent::MeetChanged);
                }
            }
            (MeetStep::Answers(accept), Exchange::Asking(with)) => self.meet_ends_or(
                (!accept).then_some(ExchangeEnd::NotNow),
                Exchange::Comparing {
                    with,
                    code: MEET_CODE,
                    sent: false,
                },
            ),
            (MeetStep::Same, Exchange::Comparing { sent: true, .. }) => self.meet_exchanged(),
            (MeetStep::Same, Exchange::Comparing { sent: false, .. }) => {
                self.meet_theirs.set(true);
            }
            (MeetStep::Different, Exchange::Comparing { .. }) => {
                self.meet_ends_or(Some(ExchangeEnd::Different), Exchange::Idle);
            }
            (MeetStep::Leaves, _) => self.cancel_exchange(),
            _ => {}
        }
    }

    /// The fixture's clock: the mockup's time, moved on with the board's.
    #[must_use]
    pub fn time(&self) -> u32 {
        (i64::from(STARTED + (self.now.get() / 1000) as u32) + self.set_by.get()) as u32
    }

    /// Milliseconds until the fixture's clock reaches the next minute.
    #[must_use]
    pub fn millis_to_next_minute(&self) -> u64 {
        60_000 - self.now.get() % 60_000
    }

    /// Moves the fixture on to `now` on the board's clock, in milliseconds:
    /// its clock, and what it has to do by then. An identity asked for
    /// arrives a moment after the first time it is moved on.
    pub fn advance(&self, now: u64) {
        self.now.set(now);
        if self.identity_asked() {
            match self.identity_at.get() {
                None => self.identity_at.set(Some(now + IDENTITY_DELAY)),
                Some(at) if at <= now => _ = self.answer_identity(),
                Some(_) => {}
            }
        }
        if self.arrival_at.get().is_some_and(|at| at <= now) {
            self.arrival_at.set(None);
            if self.arrive() {
                self.pace_arrivals(now + ARRIVAL_SPACING);
            }
        }
    }

    /// When, on the board's clock, the fixture next has something to do.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        match (self.arrival_at.get(), self.identity_at.get()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The next message arrives at `at` on the board's clock, and each one
    /// after it a while later, while any are left.
    pub fn pace_arrivals(&self, at: u64) {
        if self.arrived.get() < ARRIVALS.len() {
            self.arrival_at.set(Some(at));
        }
    }

    /// The next message to arrive, one of those on the T-LoRa Pager
    /// mockup's wake screen, arrives now, and is kept as the newest message
    /// of its chat. Returns whether one was left to.
    pub fn arrive(&self) -> bool {
        let index = self.arrived.get();
        let Some(&(chat, from, text)) = ARRIVALS.get(index) else {
            return false;
        };
        self.arrived.set(index + 1);
        self.receive(chat, from, text);
        true
    }

    /// A message saying `text` arrives in `chat`, from the peer at its
    /// other end or, in a channel, from the last of its members to speak.
    pub fn arrive_in(&self, chat: ChatId, text: &str) {
        let from = if self.is_channel(chat) {
            messages(chat)
                .iter()
                .rev()
                .find(|(from, _)| matches!(from, From::Member(_)))
                .map_or(From::Member("Sam"), |&(from, _)| from)
        } else {
            From::Peer
        };
        self.receive(chat, from, text);
    }

    /// Keeps `text`, from `from`, as the newest message of `chat`, which is
    /// unread now, and announces it.
    fn receive(&self, chat: ChatId, from: From, text: &str) {
        let Some(message) = self.keep(chat, from, text, None, false) else {
            return;
        };
        if let Some(mut row) = self.touch(chat) {
            row.unread = true;
        }
        self.queue(NodeEvent::Arrived {
            chat,
            message: message.id,
        });
    }

    /// An identity has been asked for and has not yet arrived.
    #[must_use]
    pub fn identity_asked(&self) -> bool {
        self.asked.get() && !self.identified.get()
    }

    /// The identity asked for arrives now, if one was asked for, and
    /// returns whether one was.
    pub fn answer_identity(&self) -> bool {
        let answered = self.identity_asked();
        if answered {
            self.identified.set(true);
            self.identity_at.set(None);
            self.queue(NodeEvent::IdentitiesLearned);
        }
        answered
    }

    /// The radio is set, by other means than this interface, to settings
    /// no profile has: as an attached host could set it.
    pub fn set_custom_radio(&self) {
        self.profile.set(Profile::Custom);
        self.queue(NodeEvent::SettingsChanged);
    }

    /// What is known of the channel member `name`.
    fn card(&self, name: &str) -> Member {
        let mut member = member_card(name, self.identified.get());
        member.saved = member
            .address
            .as_ref()
            .is_some_and(|address| self.saved_peer(address).is_some());
        member
    }

    /// The member saved at `address`, while they are saved.
    fn saved_since(&self, address: &str) -> Option<PeerId> {
        let index = self.saved.borrow().iter().position(|(a, _)| a == address)?;
        let peer = FIRST_SAVED + index as PeerId;
        (!self.forgotten.borrow().contains(&peer)).then_some(peer)
    }

    /// The address `text` names: a node's link, or the bare address.
    fn address_in(text: &str) -> Option<&str> {
        let text = text.trim();
        let rest = text.strip_prefix("umsh:n:").unwrap_or(text);
        // The fixture's addresses are made up, so only their shape is
        // checked.
        let address = rest.split(':').next()?;
        (address.len() == umsh_core::base58::ENCODED_LEN).then_some(address)
    }

    /// What is known of the node at `address`: a saved peer, a member the
    /// fixture names, or someone known by nothing but their address.
    fn known_at(&self, address: &str) -> Member {
        if let Some((peer, saved)) = (1..)
            .zip(PEERS.iter())
            .find(|(_, saved)| saved.address == address)
        {
            return Member {
                sender: Sender {
                    name: s(saved.name),
                    avatar: AvatarStyle::peer(saved.color, saved.hint, PeerShape::Circle),
                },
                hint: s(saved.hint),
                address: Some(s(address)),
                heard: s(saved.heard),
                saved: !self.forgotten.borrow().contains(&peer),
            };
        }
        let named = ["Sam", "Kit Moreno", "Lee Park", "Ranger Station"]
            .into_iter()
            .find(|name| member_traits(name).3 == Some(address));
        let mut member = match named {
            Some(name) => member_card(name, false),
            None => {
                let mut name = s::<24>("Member ");
                _ = name.push_str(&address[..4]);
                Member {
                    sender: Sender {
                        name: s(&name),
                        avatar: AvatarStyle::peer([90, 90, 90], &address[..4], PeerShape::Hexagon),
                    },
                    hint: s(&address[..4]),
                    address: Some(s(address)),
                    heard: String::new(),
                    saved: false,
                }
            }
        };
        member.saved = self.saved_since(address).is_some();
        member
    }

    /// The node a message whose whole text is `text` introduces.
    fn contact_in(&self, text: &str) -> Option<Contact> {
        if !text.trim().starts_with("umsh:n:") {
            return None;
        }
        let address = Self::address_in(text)?;
        let member = self.known_at(address);
        Some(Contact {
            key: umsh_core::base58::decode(address.as_bytes()).unwrap_or_default(),
            name: SharedText::new(self.heap, &member.sender.name)?,
            avatar: member.sender.avatar,
        })
    }

    /// Whether `chat` is a channel.
    fn is_channel(&self, chat: ChatId) -> bool {
        self.rows()
            .iter()
            .find(|row| row.id == chat)
            .is_some_and(|row| matches!(row.kind, ChatKind::Channel { .. }))
    }

    /// Moves `chat` to the top, active now, and returns it.
    fn touch(&self, chat: ChatId) -> Option<RefMut<'_, ChatRow>> {
        let time = self.time();
        let mut rows = self.rows();
        let index = rows.iter().position(|row| row.id == chat)?;
        let mut row = rows.remove(index);
        row.activity = time;
        _ = rows.insert(0, row);
        Some(RefMut::map(rows, |rows| &mut rows[0]))
    }

    /// Lists a chat made now, first.
    fn make_chat(&self, id: ChatId, avatar: AvatarStyle, name: &str, kind: ChatKind) {
        let row = ChatRow {
            id,
            avatar,
            name: cut(name),
            kind,
            unread: false,
            muted: false,
            activity: self.time(),
            draft: None,
        };
        let mut rows = self.rows();
        if rows.is_full() {
            rows.pop();
        }
        _ = rows.insert(0, row);
        drop(rows);
        self.queue(NodeEvent::ChatChanged(id));
    }

    /// The chat of the channel joined since as `name`, numbered the first
    /// time it is joined, and whether it is new.
    fn joined_id(&self, name: &str, access: ChannelAccess) -> Option<(ChatId, bool)> {
        let mut joined = self.joined.borrow_mut();
        let (index, new) = match joined.iter().position(|(n, _)| n.as_str() == name) {
            Some(index) => (index, false),
            None => {
                joined.push((cut(name), access)).ok()?;
                (joined.len() - 1, true)
            }
        };
        Some((FIRST_JOINED + index as ChatId, new))
    }

    /// `row` as the list shows it.
    fn summary(&self, row: &ChatRow) -> ChatSummary {
        let mut summary = ChatSummary::new(row.id, row.avatar.clone(), &row.name, self.heap);
        summary.kind = row.kind;
        summary.unread = row.unread;
        summary.muted = row.muted;
        summary.last_activity = Some(row.activity);
        // The chat of message states holds a session with forward secrecy.
        summary.forward_secret = row.id == STATES;
        if let Some(last) = self.last_message(row.id) {
            summary.preview(&last);
        }
        if let Some(draft) = &row.draft {
            let mut text = DraftText::new(self.heap);
            _ = text.splice(0..0, draft);
            summary.draft = EditBuffer::with_text(text);
        }
        summary
    }

    /// The newest message of `chat`.
    fn last_message(&self, chat: ChatId) -> Option<Message> {
        let kept = self
            .kept
            .borrow()
            .iter()
            .rev()
            .find(|(c, _)| *c == chat)
            .map(|(_, message)| message.clone());
        let mut message = kept.or_else(|| {
            let all = messages(chat);
            let last = all.len().checked_sub(1)?;
            mockup_message(self.heap, chat, last, all[last])
        })?;
        self.overlay(&mut message);
        Some(message)
    }

    /// Applies to `message` what has happened to it since the fixture
    /// started: my reaction, a retry, and its sender identified.
    fn overlay(&self, message: &mut Message) {
        if let Some(&(_, reaction)) = self.mine.borrow().iter().find(|(id, _)| *id == message.id) {
            message.set_my_reaction(Some(reaction));
        }
        if self.retried.borrow().contains(&message.id) {
            message.delivery = Delivery::Sending;
        }
        if self.without_secrecy.borrow().contains(&message.id) {
            message.forward_secret = false;
        }
        if self.deleted.borrow().contains(&message.id) {
            message.deleted = true;
        }
        if self.identified.get()
            && let Some(sender) = message.sender.as_mut().filter(|s| s.name == UNIDENTIFIED)
        {
            *sender = self.card(UNIDENTIFIED).sender;
        }
    }

    /// Keeps `text`, from `from`, in reply to `reply_to`, as the newest
    /// message of `chat`.
    fn keep(
        &self,
        chat: ChatId,
        from: From,
        text: &str,
        reply_to: Option<MessageId>,
        forward_secret: bool,
    ) -> Option<Message> {
        let reply = match reply_to {
            Some(id) => {
                let quoted = self.message(chat, id)?;
                let chat_name = self.chat(chat).map(|chat| chat.name).unwrap_or_default();
                quote_of(self.heap, &quoted, &chat_name)
            }
            None => None,
        };
        let message = Message {
            id: self.next.get(),
            direction: match from {
                From::Me => Direction::Outbound,
                From::Peer | From::Member(_) => Direction::Inbound,
            },
            sender: match from {
                From::Member(name) => Some(member(name)),
                From::Me | From::Peer => None,
            },
            text: SharedText::new(self.heap, text)?,
            delivery: match from {
                // A channel's sends have no acknowledgment to wait for.
                From::Me if self.is_channel(chat) => Delivery::Sent,
                From::Me => Delivery::Sending,
                From::Peer | From::Member(_) => Delivery::Delivered,
            },
            reactions: Reactions::new(),
            card: self.contact_in(text).map(Card::Contact),
            reply,
            time: Some(self.time()),
            presence: Presence::Present,
            edited: false,
            deleted: false,
            late: false,
            forward_secret,
            parts: None,
        };
        self.next.set(message.id + 1);
        let mut kept = self.kept.borrow_mut();
        if kept.is_full() {
            kept.remove(0);
        }
        _ = kept.push((chat, message.clone()));
        Some(message)
    }

    /// Sets a setting with `set`, which says whether it was taken, and
    /// announces the outcome.
    fn setting(&self, setting: Setting, set: impl FnOnce() -> bool) {
        self.queue(if set() {
            NodeEvent::SettingsChanged
        } else {
            NodeEvent::SettingRefused(setting)
        });
    }
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("kept", &self.kept)
            .field("arrived", &self.arrived)
            .field("mine", &self.mine)
            .field("retried", &self.retried)
            .field("next", &self.next)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl Node for Store {
    fn next_event(&self) -> Option<NodeEvent> {
        self.events.borrow_mut().pop()
    }

    fn chats(&self, into: &mut Chats) {
        for row in self.rows().iter().take(MAX_CHATS) {
            _ = into.push(self.summary(row));
        }
    }

    fn chat(&self, chat: ChatId) -> Option<ChatSummary> {
        let rows = self.rows();
        let row = rows.iter().find(|row| row.id == chat)?;
        Some(self.summary(row))
    }

    fn peers(&self, into: &mut Peers) {
        let forgotten = self.forgotten.borrow();
        let saved = self.saved.borrow();
        // Members saved since were heard just now, and come first.
        let members = saved
            .iter()
            .rev()
            .map(|(_, summary)| summary.clone())
            .filter(|summary| !forgotten.contains(&summary.id));
        let mockup = (1..).zip(PEERS.iter()).map(|(id, peer)| PeerSummary {
            id,
            avatar: AvatarStyle::peer(peer.color, peer.hint, PeerShape::Circle),
            name: s(peer.name),
            hops: peer.hops,
            signal: peer.signal,
            heard: s(peer.heard),
        });
        for summary in members
            .chain(mockup.filter(|summary| !forgotten.contains(&summary.id)))
            .take(MAX_PEERS)
        {
            _ = into.push(summary);
        }
    }

    fn load(&self, chat: ChatId, into: &mut Messages) {
        for (index, &entry) in messages(chat).iter().enumerate() {
            if let Some(message) = mockup_message(self.heap, chat, index, entry) {
                push_newest(into, message);
            }
        }
        for (_, kept) in self.kept.borrow().iter().filter(|(c, _)| *c == chat) {
            push_newest(into, kept.clone());
        }
        for message in into.iter_mut() {
            self.overlay(message);
        }
    }

    fn message(&self, chat: ChatId, message: MessageId) -> Option<Message> {
        let mut found = if message >= FIRST_KEPT {
            let kept = self.kept.borrow();
            kept.iter()
                .find(|(c, m)| *c == chat && m.id == message)
                .map(|(_, m)| m.clone())?
        } else {
            let index = (message & 0xFF) as usize;
            if mockup_id(chat, index) != message {
                return None;
            }
            mockup_message(self.heap, chat, index, *messages(chat).get(index)?)?
        };
        self.overlay(&mut found);
        Some(found)
    }

    fn opened(&self, chat: ChatId) {
        if let Some(row) = self.rows().iter_mut().find(|row| row.id == chat) {
            row.unread = false;
        }
    }

    fn recent_picks(&self) -> RecentText {
        self.picks.borrow().clone()
    }

    fn keep_recent_picks(&self, picks: &str) {
        *self.picks.borrow_mut() = RecentText::try_from(picks).unwrap_or_default();
    }

    fn save_draft(&self, chat: ChatId, text: &str) {
        let draft = (!text.trim().is_empty())
            .then(|| SharedText::new(self.heap, text))
            .flatten();
        if let Some(row) = self.rows().iter_mut().find(|row| row.id == chat) {
            row.draft = draft;
        }
    }

    fn send(
        &self,
        chat: ChatId,
        text: &str,
        reply_to: Option<MessageId>,
        forward_secret: bool,
    ) -> Option<Message> {
        let message = self.keep(chat, From::Me, text, reply_to, forward_secret)?;
        if let Some(mut row) = self.touch(chat) {
            row.draft = None;
        }
        self.queue(NodeEvent::ChatChanged(chat));
        Some(message)
    }

    fn react(&self, chat: ChatId, message: MessageId, reaction: Option<Reaction>) {
        let mut mine = self.mine.borrow_mut();
        mine.retain(|(id, _)| *id != message);
        if let Some(reaction) = reaction {
            if mine.is_full() {
                mine.remove(0);
            }
            _ = mine.push((message, reaction));
        }
        drop(mine);
        self.queue(NodeEvent::MessageChanged { chat, message });
    }

    fn retry(&self, chat: ChatId, message: MessageId) -> bool {
        let mut retried = self.retried.borrow_mut();
        if !retried.contains(&message) {
            if retried.is_full() {
                retried.remove(0);
            }
            _ = retried.push(message);
        }
        drop(retried);
        self.queue(NodeEvent::MessageChanged { chat, message });
        true
    }

    fn delete_message(&self, chat: ChatId, message: MessageId) {
        let mut deleted = self.deleted.borrow_mut();
        if !deleted.contains(&message) {
            if deleted.is_full() {
                deleted.remove(0);
            }
            _ = deleted.push(message);
        }
        drop(deleted);
        self.queue(NodeEvent::MessageChanged { chat, message });
    }

    fn retry_without_secrecy(&self, chat: ChatId, message: MessageId) -> bool {
        let mut without = self.without_secrecy.borrow_mut();
        if !without.contains(&message) {
            if without.is_full() {
                without.remove(0);
            }
            _ = without.push(message);
        }
        drop(without);
        self.retry(chat, message)
    }

    fn member(&self, chat: ChatId, message: MessageId) -> Option<Member> {
        let name = if message >= FIRST_KEPT {
            let kept = self.kept.borrow();
            let (_, kept) = kept.iter().find(|(_, m)| m.id == message)?;
            kept.sender.as_ref()?.name.clone()
        } else {
            match messages(chat).get((message & 0xFF) as usize)? {
                (From::Member(name), _) => s(name),
                _ => return None,
            }
        };
        Some(self.card(&name))
    }

    fn request_identity(&self, _chat: ChatId, _message: MessageId) {
        // Only the unidentified member has an identity to come.
        self.asked.set(true);
    }

    fn direct_chat(&self, address: &str, name: &str, avatar: &AvatarStyle) -> Option<ChatSummary> {
        // A saved peer the fixture already has a chat with.
        if let Some(chat) = PEERS
            .iter()
            .find(|peer| peer.address == address)
            .and_then(|peer| peer.chat)
        {
            return self.chat(chat);
        }
        if address == RIDGE {
            return self.chat(1);
        }
        let mut direct = self.direct.borrow_mut();
        let chat = match direct.iter().position(|a| a == address) {
            Some(index) => FIRST_DIRECT + index as ChatId,
            None => {
                direct.push(String::try_from(address).ok()?).ok()?;
                let chat = FIRST_DIRECT + (direct.len() - 1) as ChatId;
                drop(direct);
                self.make_chat(chat, avatar.clone(), name, ChatKind::Peer { hops: None });
                chat
            }
        };
        self.chat(chat)
    }

    fn peer_detail(&self, peer: PeerId) -> Option<PeerDetail> {
        if self.forgotten.borrow().contains(&peer) {
            return None;
        }
        let (address, route, heard) = match peer.checked_sub(1).and_then(|i| PEERS.get(i as usize))
        {
            Some(saved) => (s(saved.address), saved.route.map(s), saved.heard_long),
            // A member saved since the fixture started.
            None => {
                let saved = self.saved.borrow();
                let index = peer.checked_sub(FIRST_SAVED)? as usize;
                (saved.get(index)?.0.clone(), None, "2 min ago")
            }
        };
        Some(PeerDetail {
            address,
            route,
            heard: s(heard),
            forward_secrecy: self.secrecy.borrow().contains(&peer),
            // A ping is answered at once.
            ping: self.pinged.borrow().contains(&peer).then(|| s("1.4 s")),
        })
    }

    fn set_forward_secrecy(&self, peer: PeerId, on: bool) {
        let mut secrecy = self.secrecy.borrow_mut();
        secrecy.retain(|p| *p != peer);
        if on {
            _ = secrecy.push(peer);
        }
        drop(secrecy);
        self.queue(NodeEvent::PeerChanged(peer));
    }

    fn ping(&self, peer: PeerId) {
        let mut pinged = self.pinged.borrow_mut();
        if !pinged.contains(&peer) {
            _ = pinged.push(peer);
        }
        drop(pinged);
        self.queue(NodeEvent::PingAnswered(peer));
    }

    fn clock(&self) -> ClockSettings {
        self.clock.get()
    }

    fn set_clock_automatic(&self, on: bool) {
        self.setting(Setting::Clock, || {
            let mut clock = self.clock.get();
            clock.automatic = Some(on);
            self.clock.set(clock);
            true
        });
    }

    fn set_time(&self, time: u32) {
        let set_by = i64::from(time) - i64::from(self.time()) + self.set_by.get();
        self.set_by.set(set_by);
        self.clock_source.set((ClockSource::Manual, self.now.get()));
        self.setting(Setting::Time, || true);
    }

    fn set_zone(&self, rule: &str) {
        self.setting(Setting::Clock, || {
            let Ok(zone) = Rule::parse(rule) else {
                return false;
            };
            let mut clock = self.clock.get();
            clock.zone = zone;
            self.clock.set(clock);
            true
        });
    }

    fn set_hour24(&self, on: bool) {
        self.setting(Setting::Clock, || {
            let mut clock = self.clock.get();
            clock.hour24 = on;
            self.clock.set(clock);
            true
        });
    }

    fn clock_source(&self) -> Option<(ClockSource, u64)> {
        Some(self.clock_source.get())
    }

    /// Saved peers' identities are what the fixture has: asking changes
    /// nothing.
    fn request_peer_identity(&self, peer: PeerId) {
        self.queue(NodeEvent::PeerChanged(peer));
    }

    fn forget_peer(&self, peer: PeerId) {
        let mut forgotten = self.forgotten.borrow_mut();
        if !forgotten.contains(&peer) {
            _ = forgotten.push(peer);
        }
        drop(forgotten);
        self.queue(NodeEvent::PeerRemoved(peer));
    }

    fn chat_peer(&self, chat: ChatId) -> Option<PeerId> {
        let peer = (1..)
            .zip(PEERS.iter())
            .find(|(_, saved)| saved.chat == Some(chat))?
            .0;
        (!self.forgotten.borrow().contains(&peer)).then_some(peer)
    }

    fn known_member(&self, text: &str) -> Option<Member> {
        Some(self.known_at(Self::address_in(text)?))
    }

    fn saved_peer(&self, address: &str) -> Option<PeerId> {
        let mockup = (1..)
            .zip(PEERS.iter())
            .find(|(_, saved)| saved.address == address)
            .map(|(peer, _)| peer)
            .filter(|peer| !self.forgotten.borrow().contains(peer));
        mockup.or_else(|| self.saved_since(address))
    }

    fn contact_uri(&self, peer: PeerId) -> Option<ContactUri> {
        let address = match peer.checked_sub(1).and_then(|i| PEERS.get(i as usize)) {
            Some(saved) => s::<44>(saved.address),
            None => self
                .saved
                .borrow()
                .get(peer.checked_sub(FIRST_SAVED)? as usize)?
                .0
                .clone(),
        };
        let mut uri = ContactUri::new();
        uri.push_str("umsh:n:").ok()?;
        uri.push_str(&address).ok()?;
        Some(uri)
    }

    fn chat_member(&self, chat: ChatId) -> Option<Member> {
        let summary = self
            .chat(chat)
            .filter(|c| matches!(c.kind, ChatKind::Peer { .. }))?;
        let listed = PEERS.iter().find(|peer| peer.chat == Some(chat));
        let address: String<44> = match (listed, chat) {
            (Some(peer), _) => s(peer.address),
            (None, STATES) => s(member_traits("Sam").3?),
            (None, 1) => s(RIDGE),
            (None, _) => self
                .direct
                .borrow()
                .get(chat.checked_sub(FIRST_DIRECT)? as usize)?
                .clone(),
        };
        Some(Member {
            sender: Sender {
                name: s(&summary.name),
                avatar: summary.avatar.clone(),
            },
            hint: s(&address[..4]),
            saved: self.chat_peer(chat).is_some() || self.saved_since(&address).is_some(),
            address: Some(address),
            heard: s(listed.map_or("2m", |peer| peer.heard)),
        })
    }

    fn delete_chat(&self, chat: ChatId) {
        let mut rows = self.rows();
        let Some(index) = rows.iter().position(|row| row.id == chat) else {
            return;
        };
        rows.remove(index);
        drop(rows);
        self.kept.borrow_mut().retain(|(kept, _)| *kept != chat);
        self.queue(NodeEvent::ChatRemoved(chat));
    }

    fn find_heard(&self, query: &str) -> Vec<Heard, MAX_HEARD> {
        HEARD
            .iter()
            .filter(|node| word_match(node.name, query).is_some())
            .map(|node| Heard {
                address: s(node.address),
                avatar: AvatarStyle::peer(node.color, &node.address[..4], node.shape),
                name: s(node.name),
                distance: s(node.distance),
                age: s(node.age),
            })
            .take(MAX_HEARD)
            .collect()
    }

    fn address(&self) -> String<44> {
        s(ADDRESS)
    }

    fn share_uri(&self, what: Shareable) -> Option<ShareUri> {
        match what {
            Shareable::Identity => {
                let mut uri = ShareUri::new();
                core::fmt::write(&mut uri, format_args!("umsh:n:{ADDRESS}")).ok()?;
                Some(uri)
            }
            Shareable::Channel(2) => private_uri(TRAIL_CREW_KEY, "Trail Crew"),
            Shareable::Channel(4) => ShareUri::try_from("umsh:cs:public").ok(),
            Shareable::Channel(6) => ShareUri::try_from("umsh:cs:emergency").ok(),
            Shareable::Channel(chat) => {
                let index = chat.checked_sub(FIRST_JOINED)? as usize;
                let joined = self.joined.borrow();
                let (name, access) = joined.get(index)?;
                match access {
                    ChannelAccess::Private => private_uri(JOINED_KEY, name),
                    _ => {
                        let mut uri = ShareUri::new();
                        core::fmt::write(&mut uri, format_args!("umsh:cs:")).ok()?;
                        push_encoded(&mut uri, &folded(name))?;
                        Some(uri)
                    }
                }
            }
        }
    }

    fn avatar(&self) -> AvatarStyle {
        AvatarStyle::peer([150, 156, 166], &ADDRESS[..4], PeerShape::Circle)
    }

    fn device_name(&self) -> String<24> {
        self.name.borrow().clone().unwrap_or_else(|| s("Juniper"))
    }

    fn set_name(&self, name: &str) {
        self.setting(Setting::Name, || {
            *self.name.borrow_mut() = Some(cut(name));
            true
        });
    }

    fn profile_count(&self) -> usize {
        VETTED.len()
    }

    fn profile(&self, index: usize) -> Option<&'static str> {
        VETTED.get(index).map(|profile| profile.name)
    }

    fn set_profile(&self, index: usize) {
        self.setting(Setting::Profile, || {
            let vetted = index < VETTED.len();
            if vetted {
                self.profile.set(Profile::Vetted(index));
            }
            vetted
        });
    }

    fn radio(&self) -> RadioSettings {
        RadioSettings {
            enabled: self.radio_enabled.get(),
            profile: self.profile.get(),
            forwarding: self.forwarding.get(),
            share_location: self.share_location.get(),
            transmit_power: self.transmit_power.get(),
            airtime: 3,
        }
    }

    fn set_radio_enabled(&self, on: bool) {
        self.setting(Setting::Radio, || {
            self.radio_enabled.set(on);
            true
        });
    }

    fn set_forwarding(&self, on: bool) {
        self.setting(Setting::Forwarding, || {
            self.forwarding.set(on);
            true
        });
    }

    fn set_share_location(&self, on: bool) {
        self.setting(Setting::ShareLocation, || {
            self.share_location.set(on);
            true
        });
    }

    fn set_transmit_power(&self, dbm: i8) {
        self.setting(Setting::TransmitPower, || {
            let usable = TRANSMIT_POWER.contains(&dbm);
            if usable {
                self.transmit_power.set(dbm);
            }
            usable
        });
    }

    fn keyboard(&self) -> KeyboardSettings {
        self.keyboard.get()
    }

    fn set_keyboard(&self, settings: KeyboardSettings) {
        self.setting(Setting::Keyboard, || {
            self.keyboard.set(settings);
            true
        });
    }

    fn brightness(&self) -> u8 {
        self.brightness.get()
    }

    fn set_brightness(&self, brightness: u8) {
        self.setting(Setting::Brightness, || {
            self.brightness.set(brightness);
            true
        });
    }

    fn bluetooth_enabled(&self) -> Option<bool> {
        Some(self.bluetooth.get())
    }

    fn set_bluetooth_enabled(&self, on: bool) {
        self.setting(Setting::Bluetooth, || {
            self.bluetooth.set(on);
            true
        });
    }

    fn set_pairing(&self, _open: bool) {
        self.setting(Setting::Pairing, || true);
    }

    fn clear_pairings(&self) {
        self.setting(Setting::Pairing, || true);
    }

    fn gnss_enabled(&self) -> Option<bool> {
        Some(self.gnss.get())
    }

    fn set_gnss_enabled(&self, on: bool) {
        self.setting(Setting::Gnss, || {
            self.gnss.set(on);
            true
        });
    }

    /// Two devices are nearby: the mockup's T-Deck, near, and a XIAO kit
    /// farther off.
    fn open_meet(&self) {
        let opened = self.meet_opened.get().wrapping_add(1);
        self.meet_opened.set(opened);
        let mut meet = self.meet.borrow_mut();
        // The mockup's violet first, then far around the circle each time:
        // the session colors of hue steps 220, 61, 158, 255, 96, 193, 34
        // and 131.
        const OWN: [u32; 8] = [
            0xC598E7, 0xD0A84B, 0x41BEE4, 0xEB8DAD, 0x8CBF70, 0x92A9FA, 0xEC9669, 0x37C6B7,
        ];
        meet.own_color = Some(OWN[usize::from(opened.wrapping_sub(1)) % OWN.len()]);
        if meet.devices.is_empty() {
            // The session colors of hue steps 130 and 40.
            for (id, model, color, nearness) in [
                (1, models::LILYGO_T_DECK, 0x39C6B5, 3),
                (2, models::SEEED_XIAO_ESP32S3_KIT, 0xE8995F, 1),
            ] {
                _ = meet.devices.push(NearbyDevice {
                    id,
                    model,
                    color,
                    nearness: Some(nearness),
                });
            }
        }
        meet.with = None;
        meet.exchange = Exchange::Idle;
        self.meet_theirs.set(false);
        drop(meet);
        self.queue(NodeEvent::MeetChanged);
    }

    fn close_meet(&self) {
        *self.meet.borrow_mut() = MeetState::new();
        self.queue(NodeEvent::MeetChanged);
    }

    fn meet(&self, state: &mut MeetState) {
        state.clone_from(&self.meet.borrow());
    }

    fn ask_to_exchange(&self, device: NearbyId) -> bool {
        let mut meet = self.meet.borrow_mut();
        let Some(&device) = meet.devices.iter().find(|d| d.id == device) else {
            return false;
        };
        if meet.exchange != Exchange::Idle {
            return false;
        }
        meet.with = Some(device);
        meet.exchange = Exchange::Asking(device);
        drop(meet);
        self.queue(NodeEvent::MeetChanged);
        true
    }

    fn answer_exchange(&self, accept: bool) {
        let Exchange::Asked(device) = self.meet.borrow().exchange else {
            return;
        };
        self.meet_ends_or(
            (!accept).then_some(ExchangeEnd::NotNow),
            Exchange::Comparing {
                with: device,
                code: MEET_CODE,
                sent: false,
            },
        );
    }

    fn confirm_code(&self, same: bool) {
        let Exchange::Comparing {
            with,
            code,
            sent: false,
        } = self.meet.borrow().exchange
        else {
            return;
        };
        if !same {
            self.meet_ends_or(Some(ExchangeEnd::Different), Exchange::Idle);
        } else if self.meet_theirs.get() {
            self.meet_exchanged();
        } else {
            self.meet_ends_or(
                None,
                Exchange::Comparing {
                    with,
                    code,
                    sent: true,
                },
            );
        }
    }

    fn cancel_exchange(&self) {
        let in_progress = !matches!(
            self.meet.borrow().exchange,
            Exchange::Closed | Exchange::Idle | Exchange::Ended(_) | Exchange::Exchanged(_)
        );
        if in_progress {
            self.meet_ends_or(Some(ExchangeEnd::Left), Exchange::Idle);
        }
    }

    fn inspect_peer(&self, text: &str) -> PeerEntry {
        use umsh_core::NodeHint;
        use umsh_core::base58::{ENCODED_LEN, prefix_bounds};

        let text = text.trim();
        if text.is_empty() {
            return PeerEntry::Empty;
        }
        // An invitation carries the address, and may carry an identity after
        // it, whose name a node would read; the fixture does not.
        let (digits, name) = match text.strip_prefix(PEER_INVITATION) {
            Some(rest) => (
                rest.split_once(':').map_or(rest, |(digits, _)| digits),
                None,
            ),
            // An invitation still being typed.
            None if PEER_INVITATION.starts_with(text) => {
                return PeerEntry::Partial {
                    avatar: None,
                    hint: String::new(),
                    missing: ENCODED_LEN as u8,
                };
            }
            None => (text, None),
        };
        if digits.is_empty() {
            return PeerEntry::Partial {
                avatar: None,
                hint: String::new(),
                missing: ENCODED_LEN as u8,
            };
        }
        let Ok((low, high)) = prefix_bounds(digits.as_bytes()) else {
            return PeerEntry::Invalid;
        };
        let bytes = [low[0], low[1], low[2]];
        let mut hint: String<8> = String::new();
        _ = core::fmt::write(&mut hint, format_args!("{}", NodeHint(bytes)));
        if digits.len() == ENCODED_LEN {
            // The whole address settles every character of the hint.
            let hint: String<8> = s(&digits[..4]);
            let avatar = AvatarStyle::peer(bytes, &hint, PeerShape::Hexagon);
            return PeerEntry::Complete {
                avatar,
                hint,
                address: s(digits),
                name,
            };
        }
        // A peer known by nothing but their address is drawn as a hexagon.
        let avatar = AvatarStyle::peer(bytes, &hint, PeerShape::Hexagon);
        // The avatar shows once the characters settle the hint.
        let settled = low[..3] == high[..3];
        PeerEntry::Partial {
            avatar: settled.then_some(avatar),
            hint: if settled { hint } else { String::new() },
            missing: (ENCODED_LEN - digits.len()) as u8,
        }
    }

    fn join(&self, invite: &Invite, name: &str) -> Option<ChatSummary> {
        let (chat, new) = self.joined_id(&invite.name, invite.access)?;
        if new {
            let kind = ChatKind::Channel {
                access: invite.access,
            };
            self.make_chat(chat, invite.avatar(), name, kind);
        }
        self.chat(chat)
    }

    fn inspect_channel(&self, text: &str) -> ChannelEntry {
        use umsh_core::base58::{ENCODED_LEN, prefix_bounds};

        let text = text.trim();
        if text.is_empty() {
            return ChannelEntry::Empty;
        }
        let missing = |key: &str| ChannelEntry::Partial {
            missing: (ENCODED_LEN - key.len()) as u8,
        };
        match text.strip_prefix(CHANNEL_INVITATION) {
            Some(rest) => {
                let key = rest.split_once('?').map_or(rest, |(key, _)| key);
                if key.is_empty() {
                    missing(key)
                } else if key.len() > ENCODED_LEN || prefix_bounds(key.as_bytes()).is_err() {
                    ChannelEntry::Invalid
                } else if key.len() == ENCODED_LEN {
                    ChannelEntry::Private
                } else {
                    missing(key)
                }
            }
            // An invitation still being typed.
            None if CHANNEL_INVITATION.starts_with(text) && text.contains(':') => missing(""),
            // A name is any ASCII without the invitation's colon.
            None if text.is_ascii() && !text.contains(':') => ChannelEntry::Named,
            None => ChannelEntry::Invalid,
        }
    }

    fn add_channel(&self, text: &str) -> Option<ChatSummary> {
        let text = text.trim();
        let (name, access): (String<32>, _) = match self.inspect_channel(text) {
            ChannelEntry::Named => match folded(text).as_str() {
                // Joined from the start.
                "public" => return self.chat(4),
                "emergency" => return self.chat(6),
                _ => (cut(text), ChannelAccess::Named),
            },
            ChannelEntry::Private => {
                let rest = &text[CHANNEL_INVITATION.len()..];
                let (key, query) = rest.split_once('?').unwrap_or((rest, ""));
                let name = query
                    .split(';')
                    .find_map(|p| p.strip_prefix("n="))
                    .map(decoded)
                    .filter(|n| !n.is_empty());
                let name = name.unwrap_or_else(|| {
                    let mut name: String<32> = String::new();
                    _ = core::fmt::write(&mut name, format_args!("Channel {}", &key[..4]));
                    name
                });
                (name, ChannelAccess::Private)
            }
            _ => return None,
        };
        let (chat, new) = self.joined_id(&name, access)?;
        if new {
            let avatar = AvatarStyle::channel(None, &name, tint(&name));
            self.make_chat(chat, avatar, &name, ChatKind::Channel { access });
        }
        self.chat(chat)
    }

    fn save_peer(&self, member: &Member) -> Option<PeerSummary> {
        let address = member.address.as_ref()?;
        let mut saved = self.saved.borrow_mut();
        let summary = match saved.iter().position(|(a, _)| a == address) {
            Some(index) => saved[index].1.clone(),
            None => {
                let summary = PeerSummary {
                    id: FIRST_SAVED + saved.len() as PeerId,
                    avatar: member.sender.avatar.clone(),
                    name: s(&member.sender.name),
                    hops: None,
                    signal: None,
                    heard: member.heard.clone(),
                };
                saved.push((address.clone(), summary.clone())).ok()?;
                summary
            }
        };
        drop(saved);
        self.forgotten.borrow_mut().retain(|p| *p != summary.id);
        self.queue(NodeEvent::PeerChanged(summary.id));
        Some(summary)
    }

    fn details(&self, chat: ChatId, message: MessageId) -> Option<Details> {
        // Sent or received since the fixture started, or the fixture's own.
        let (outbound, time) = if message >= FIRST_KEPT {
            let kept = self.kept.borrow();
            let (_, kept) = kept.iter().find(|(_, m)| m.id == message)?;
            (kept.direction == Direction::Outbound, kept.time)
        } else {
            let index = (message & 0xFF) as usize;
            let (from, _) = *messages(chat).get(index)?;
            let time = Some(mockup_time(chat, index));
            (matches!(from, From::Me), time)
        };
        let mut details = if outbound {
            Details {
                time,
                ..Details::default()
            }
        } else {
            Details {
                time,
                hops: Some(3),
                route: s("Gh* \u{203A} 4Tn"),
                rssi: Some(-97),
                snr: Some(65),
                ..Details::default()
            }
        };
        // Sam's chat is the one under forward secrecy.
        details.forward_secret = chat == STATES;
        let index = (message & 0xFF) as usize;
        let theirs = if message < FIRST_KEPT {
            their_reactions(chat, index)
        } else {
            &[]
        };
        for &(from, reaction) in theirs {
            let (name, avatar) = match from {
                From::Member(name) => (name, member(name).avatar),
                From::Me | From::Peer => {
                    let summary = self.chat(chat)?;
                    let name = SharedText::new(self.heap, &summary.name)?;
                    _ = details.reactors.push(Reactor {
                        name: Some(name),
                        avatar: summary.avatar,
                        reaction,
                    });
                    continue;
                }
            };
            _ = details.reactors.push(Reactor {
                name: Some(SharedText::new(self.heap, name)?),
                avatar,
                reaction,
            });
        }
        if let Some(&(_, reaction)) = self.mine.borrow().iter().find(|(id, _)| *id == message) {
            _ = details.reactors.push(Reactor {
                name: None,
                avatar: self.avatar(),
                reaction,
            });
        }
        Some(details)
    }
}

/// The mockup's chats and peers, read from `store`, as the interface
/// starts on them on `board`.
pub fn state(store: &'static Store, board: &'static Board) -> State {
    let mut state = State::new(store, board);
    state.status = StatusStrip {
        device_name: store.device_name(),
        battery_segments: 3,
        battery_percent: Some(64),
        charging: false,
        bluetooth: Some(Bluetooth::Connected),
        wifi: None,
        gnss: Some(Gnss::Fixed),
        silent: false,
        battery_low: false,
    };
    state.links = Links {
        bluetooth: BluetoothReading {
            connected: true,
            paired: Some(1),
            pairing: false,
            pin: None,
        },
        gnss: GnssReading {
            fix: Fix::ThreeD,
            position: Some((46_852_450, -121_760_550)),
            altitude: Some(1_646),
            used: 9,
            in_view: Some(14),
        },
    };
    state.set_wall_time(Some(store.time()));
    state.reload();
    state.focus_list();
    state
}
