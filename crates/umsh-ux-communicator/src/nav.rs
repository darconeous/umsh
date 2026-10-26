//! Moving between screens, and where focus goes when you do.
//!
//! Each screen remembers its own focus, so Back returns to what you left.
//! Opening and leaving screens happen here and nowhere else, whether a
//! press or a key asked for it.

use buoyant::focus::{FocusKey, FocusState};

use buoyant::view::EditBuffer;
use heapless::String;

use crate::avatar::Title;
pub use crate::clock_settings::{ClockPage, DateParts, Part, ZoneFind};
use crate::keyboard::Field;
use crate::model::{
    AUTO_LOCK_CHOICES, ChannelEntry, ChatId, ChatKind, ChatSummary, Details, Exchange, Found,
    FoundKind, Invite, KeyboardSettings, MAX_FOUND, MAX_REPEATERS, Member, MessageId, NearbyId,
    PeerDetail, PeerEntry, PeerId, Profile, RadioSettings, Reaction, Section, Shareable, State,
    TRANSMIT_POWER, word_match,
};

use crate::text::SharedText;
use umsh_sound::Cue;

/// What a joined channel is to be called here, as it is edited.
pub type JoinName = EditBuffer<String<32>>;
/// An address or a peer invitation, as it is typed into Add peer.
pub type PeerText = EditBuffer<String<64>>;
/// A channel's name or invitation, as it is typed into Add channel.
pub type ChannelText = EditBuffer<String<96>>;
/// This node's name, as it is typed on first run.
pub type NameText = EditBuffer<String<24>>;
/// What Find looks for, as it is typed.
pub type FindText = EditBuffer<String<24>>;
/// A transmit power in dBm, as it is typed.
pub type PowerText = EditBuffer<String<4>>;

/// How long a repeater asked who it is is waited on, in milliseconds.
const IDENTIFY_WAIT_MS: u64 = 15_000;

/// The steps of the spinner of a repeater asked who it is, and how long
/// each is shown.
pub const SPIN_PHASES: u8 = 8;
const SPIN_STEP_MS: u64 = 125;

/// The names of focusable elements. The high byte says what kind of element
/// a key names, so keys of different kinds never collide.
pub mod keys {
    use super::{ChatId, FocusKey, MessageId, NearbyId, PeerId, Reaction, Section};

    const KIND: u32 = 0xFF00_0000;
    const RAIL: u32 = 0x0100_0000;
    const CHAT: u32 = 0x0200_0000;
    const MESSAGE: u32 = 0x0300_0000;
    const ACTION: u32 = 0x0500_0000;
    const PEER: u32 = 0x0900_0000;
    const DEVICE: u32 = 0x0D00_0000;
    const SHARE: u32 = 0x0F00_0000;
    const PROFILE_ROW: u32 = 0x1300_0000;
    const FOUND: u32 = 0x1500_0000;
    const TIME_PART: u32 = 0x1B00_0000;
    const ZONE_ROW: u32 = 0x1C00_0000;
    const NEARBY: u32 = 0x2000_0000;
    const AUTO_LOCK_ROW: u32 = 0x2400_0000;

    /// A conversation's composer. Only one conversation is shown at a time.
    pub const COMPOSER: FocusKey = FocusKey(0x0400_0000);
    /// The actions menu's Reply and Details.
    pub const REPLY: FocusKey = FocusKey(ACTION | 0x100);
    pub const DETAILS: FocusKey = FocusKey(ACTION | 0x101);
    /// The actions menu's View member, on a member's message.
    pub const VIEW_MEMBER: FocusKey = FocusKey(ACTION | 0x102);
    /// The actions menu's Join, on a message carrying an invitation.
    pub const JOIN: FocusKey = FocusKey(ACTION | 0x103);
    /// The actions menu's Retry and Delete, on an unconfirmed message.
    pub const RETRY: FocusKey = FocusKey(ACTION | 0x104);
    pub const DELETE_MESSAGE: FocusKey = FocusKey(ACTION | 0x105);
    /// The actions menu's Show, on a message carrying a contact.
    pub const VIEW_CONTACT: FocusKey = FocusKey(ACTION | 0x106);
    /// What the details screen shows, which the wheel scrolls through,
    /// and what it says under its repeaters.
    pub const DETAIL_LIST: FocusKey = FocusKey(0x0600_0000);
    pub const DETAIL_NOTE: FocusKey = FocusKey(0x0600_0100);
    /// The member screen's Request identity, Message, and Save peer.
    pub const REQUEST_IDENTITY: FocusKey = FocusKey(0x0700_0000);
    pub const MESSAGE_MEMBER: FocusKey = FocusKey(0x0700_0001);
    pub const SAVE_PEER: FocusKey = FocusKey(0x0700_0002);
    /// The Peers list's Add peer, which heads it.
    pub const ADD_PEER: FocusKey = FocusKey(0x0A00_0000);
    /// A saved peer's screen: its actions, in order, and Forget's
    /// confirmation.
    pub const PEER_MESSAGE: FocusKey = FocusKey(0x0C00_0000);
    pub const PEER_SECRECY: FocusKey = FocusKey(0x0C00_0003);
    pub const PEER_PING: FocusKey = FocusKey(0x0C00_0004);
    pub const PEER_FORGET: FocusKey = FocusKey(0x0C00_0005);
    pub const PEER_IDENTITY: FocusKey = FocusKey(0x0C00_0006);
    pub const FORGET_CONFIRM: FocusKey = FocusKey(0x0C00_0007);
    pub const FORGET_CANCEL: FocusKey = FocusKey(0x0C00_0008);
    pub const PEER_SHARE: FocusKey = FocusKey(0x0C00_0009);
    pub const PEER_ALIAS: FocusKey = FocusKey(0x0C00_000A);
    /// A chat's menu, which holding the wheel on its row opens: its peer
    /// or channel, and Delete or Leave; and their confirmation.
    pub const CHAT_SHOW: FocusKey = FocusKey(0x1D00_0000);
    pub const CHAT_DELETE: FocusKey = FocusKey(0x1D00_0001);
    pub const DELETE_CONFIRM: FocusKey = FocusKey(0x1D00_0002);
    pub const DELETE_CANCEL: FocusKey = FocusKey(0x1D00_0003);
    /// The Channels screen's Add channel, which heads it; the channels
    /// under it are named as the Chats list names them.
    pub const ADD_CHANNEL: FocusKey = FocusKey(0x1000_0000);
    /// Add channel's field, and its Join.
    pub const CHANNEL_FIELD: FocusKey = FocusKey(0x1100_0000);
    pub const JOIN_ENTRY: FocusKey = FocusKey(0x1100_0001);
    /// Find's field.
    pub const FIND_FIELD: FocusKey = FocusKey(0x1400_0000);
    /// First run's name field and Continue.
    pub const NAME_FIELD: FocusKey = FocusKey(0x1200_0000);
    pub const CONTINUE: FocusKey = FocusKey(0x1200_0001);
    /// Enter an address's field, and its Message.
    pub const PEER_FIELD: FocusKey = FocusKey(0x0B00_0000);
    pub const MESSAGE_PEER: FocusKey = FocusKey(0x0B00_0001);
    /// Nearby's Enter an address and Show my code, and the card asking to
    /// exchange.
    pub const ENTER_ADDRESS: FocusKey = FocusKey(0x2100_0000);
    pub const SHOW_MY_CODE: FocusKey = FocusKey(0x2100_0001);
    pub const EXCHANGE_ACCEPT: FocusKey = FocusKey(0x2100_0002);
    pub const EXCHANGE_DECLINE: FocusKey = FocusKey(0x2100_0003);
    /// The exchange's choices: on the code, and once it ended.
    pub const SAME: FocusKey = FocusKey(0x2100_0004);
    pub const DIFFERENT: FocusKey = FocusKey(0x2100_0005);
    pub const TRY_AGAIN: FocusKey = FocusKey(0x2100_0006);
    pub const DONE: FocusKey = FocusKey(0x2100_0007);
    /// The join screen's Name and Join channel.
    pub const JOIN_NAME: FocusKey = FocusKey(0x0800_0000);
    pub const JOIN_CHANNEL: FocusKey = FocusKey(0x0800_0001);
    /// A code that shares this node or a channel, which the wheel rests on.
    pub const SHARE_CODE: FocusKey = FocusKey(SHARE);
    /// The Identity screen's Name and View QR code.
    pub const IDENTITY_NAME: FocusKey = FocusKey(0x2800_0000);
    pub const IDENTITY_CODE: FocusKey = FocusKey(0x2800_0001);
    /// A channel's screen: its actions and settings, in order, and Leave's
    /// confirmation.
    pub const CHANNEL_MESSAGE: FocusKey = FocusKey(0x2900_0000);
    pub const CHANNEL_CODE: FocusKey = FocusKey(0x2900_0001);
    pub const CHANNEL_NAME: FocusKey = FocusKey(0x2900_0002);
    pub const CHANNEL_NOTIFICATIONS: FocusKey = FocusKey(0x2900_0003);
    pub const CHANNEL_LEAVE: FocusKey = FocusKey(0x2900_0004);
    pub const LEAVE_CONFIRM: FocusKey = FocusKey(0x2900_0005);
    pub const LEAVE_CANCEL: FocusKey = FocusKey(0x2900_0006);
    /// The Device list's categories.
    pub const IDENTITY: FocusKey = FocusKey(DEVICE);
    pub const CHANNELS: FocusKey = FocusKey(DEVICE | 1);
    pub const RADIO: FocusKey = FocusKey(DEVICE | 2);
    pub const DISPLAY: FocusKey = FocusKey(DEVICE | 4);
    pub const BLUETOOTH: FocusKey = FocusKey(DEVICE | 5);
    pub const SHUT_DOWN: FocusKey = FocusKey(DEVICE | 7);
    pub const KEYBOARD: FocusKey = FocusKey(DEVICE | 8);
    pub const CLOCK: FocusKey = FocusKey(DEVICE | 9);
    pub const GNSS: FocusKey = FocusKey(DEVICE | 10);
    pub const BATTERY: FocusKey = FocusKey(DEVICE | 11);
    pub const STATISTICS: FocusKey = FocusKey(DEVICE | 12);
    pub const ABOUT: FocusKey = FocusKey(DEVICE | 13);
    pub const SOUNDS: FocusKey = FocusKey(DEVICE | 14);
    /// A Device screen with nothing in it to focus, as a whole: turning
    /// scrolls it.
    pub const READING: FocusKey = FocusKey(0x2800_0000);
    /// About's Credits.
    pub const CREDITS: FocusKey = FocusKey(0x2600_0000);
    /// The Display screen's rows, in order.
    pub const BRIGHTNESS: FocusKey = FocusKey(0x2300_0000);
    pub const AUTO_LOCK: FocusKey = FocusKey(0x2300_0001);
    /// The Bluetooth screen's actions, in order, and Clear pairings'
    /// confirmation.
    pub const BLUETOOTH_ENABLED: FocusKey = FocusKey(0x1E00_0000);
    pub const PAIRING: FocusKey = FocusKey(0x1E00_0003);
    pub const CLEAR_PAIRINGS: FocusKey = FocusKey(0x1E00_0005);
    pub const CLEAR_PAIRINGS_CONFIRM: FocusKey = FocusKey(0x1E00_0006);
    pub const CLEAR_PAIRINGS_CANCEL: FocusKey = FocusKey(0x1E00_0007);
    /// The GNSS screen's switch.
    pub const GNSS_ENABLED: FocusKey = FocusKey(0x1F00_0000);
    /// The Sounds screen's rows, in order.
    pub const SOUNDS_ENABLED: FocusKey = FocusKey(0x2A00_0000);
    pub const VOLUME: FocusKey = FocusKey(0x2A00_0001);
    /// The Clock screen's rows, in order.
    pub const CLOCK_AUTOMATIC: FocusKey = FocusKey(0x1A00_0000);
    pub const CLOCK_TIME: FocusKey = FocusKey(0x1A00_0001);
    pub const CLOCK_ZONE: FocusKey = FocusKey(0x1A00_0002);
    pub const CLOCK_24H: FocusKey = FocusKey(0x1A00_0003);
    /// Date and time's Set.
    pub const SET_TIME: FocusKey = FocusKey(0x1A00_0005);
    /// The Keyboard screen's switches, in order.
    pub const CAPITALIZE: FocusKey = FocusKey(0x1700_0000);
    pub const PERIOD: FocusKey = FocusKey(0x1700_0001);
    pub const KEYBOARD_LIGHT: FocusKey = FocusKey(0x1700_0002);
    /// Radio's Transmit power row, and the field it opens.
    pub const TRANSMIT_POWER: FocusKey = FocusKey(0x0E00_0001);
    pub const POWER_FIELD: FocusKey = FocusKey(0x1800_0000);

    /// The text field `key` names, as the keyboard treats it.
    #[must_use]
    pub const fn field(key: FocusKey) -> Option<super::Field> {
        use super::Field;
        match key {
            COMPOSER => Some(Field::Prose),
            NAME_FIELD | JOIN_NAME | IDENTITY_NAME | CHANNEL_NAME | PEER_ALIAS => Some(Field::Name),
            FIND_FIELD | PEER_FIELD | CHANNEL_FIELD => Some(Field::Literal),
            POWER_FIELD => Some(Field::Number),
            _ => None,
        }
    }
    /// The choices of how to send again a message that was to go under
    /// forward secrecy.
    pub const RESEND: FocusKey = FocusKey(0x1900_0000);
    pub const RESEND_WITHOUT_SECRECY: FocusKey = FocusKey(0x1900_0001);
    pub const RESEND_CANCEL: FocusKey = FocusKey(0x1900_0002);
    /// Deleting a message, asking to be confirmed.
    pub const DELETE_MESSAGE_CONFIRM: FocusKey = FocusKey(0x1900_0003);
    pub const DELETE_MESSAGE_CANCEL: FocusKey = FocusKey(0x1900_0004);
    /// Shut down's confirmation.
    pub const SHUT_DOWN_CONFIRM: FocusKey = FocusKey(0x1600_0000);
    pub const SHUT_DOWN_CANCEL: FocusKey = FocusKey(0x1600_0001);
    /// The Radio screen's switch, its Profile, and its other switches.
    pub const RADIO_ENABLED: FocusKey = FocusKey(0x0E00_0005);
    pub const PROFILE: FocusKey = FocusKey(0x0E00_0000);
    pub const FORWARDING: FocusKey = FocusKey(0x0E00_0002);
    pub const SHARE_LOCATION: FocusKey = FocusKey(0x0E00_0003);

    /// A reaction in the actions menu's palette: any but the emotes is
    /// on More.
    #[must_use]
    pub const fn reaction(reaction: Reaction) -> FocusKey {
        FocusKey(
            ACTION
                | match reaction {
                    Reaction::Heart => 0,
                    Reaction::ThumbsUp => 1,
                    Reaction::ThumbsDown => 2,
                    Reaction::Laugh => 3,
                    Reaction::Exclaim => 4,
                    Reaction::Question => 5,
                    Reaction::Emoji(_) | Reaction::Other => 6,
                },
        )
    }
    /// The palette's More, which opens the character picker.
    pub const MORE_REACTIONS: FocusKey = reaction(Reaction::Other);

    /// A device listed on Nearby.
    #[must_use]
    pub const fn nearby(device: NearbyId) -> FocusKey {
        FocusKey(NEARBY | (device & !KIND))
    }

    #[must_use]
    pub const fn rail(section: Section) -> FocusKey {
        FocusKey(RAIL | section as u32)
    }

    /// One of Find's results, by its place among them.
    #[must_use]
    pub const fn found(index: usize) -> FocusKey {
        FocusKey(FOUND | (index as u32 & !KIND))
    }

    /// One of Auto-Lock's choices, by its place among them.
    #[must_use]
    pub const fn auto_lock_choice(index: usize) -> FocusKey {
        FocusKey(AUTO_LOCK_ROW | (index as u32 & !KIND))
    }

    /// A radio profile in the list of them, by its place there.
    #[must_use]
    pub const fn profile(index: usize) -> FocusKey {
        FocusKey(PROFILE_ROW | (index as u32 & !KIND))
    }

    /// A part of the date and time being set.
    #[must_use]
    pub const fn time_part(part: super::Part) -> FocusKey {
        FocusKey(TIME_PART | part as u32)
    }

    /// The part of the date and time `key` names.
    #[must_use]
    pub const fn part_of(key: FocusKey) -> Option<super::Part> {
        if key.0 & KIND == TIME_PART {
            super::Part::from_index((key.0 & !KIND) as usize)
        } else {
            None
        }
    }

    /// The row of the time zone at `index` in [`crate::zones::ZONES`].
    #[must_use]
    pub const fn zone(index: usize) -> FocusKey {
        FocusKey(ZONE_ROW | (index as u32 & !KIND))
    }

    /// The time zone whose row `key` names.
    #[must_use]
    pub const fn zone_of(key: FocusKey) -> Option<usize> {
        if key.0 & KIND == ZONE_ROW {
            Some((key.0 & !KIND) as usize)
        } else {
            None
        }
    }

    /// The place of the radio profile whose row `key` names.
    #[must_use]
    pub const fn profile_of(key: FocusKey) -> Option<usize> {
        if key.0 & KIND == PROFILE_ROW {
            Some((key.0 & !KIND) as usize)
        } else {
            None
        }
    }

    /// Whether `key` names one of the Device list's categories.
    #[must_use]
    pub const fn is_category(key: FocusKey) -> bool {
        key.0 & KIND == DEVICE
    }

    /// A chat's row in the Chats list.
    #[must_use]
    pub const fn chat(chat: ChatId) -> FocusKey {
        FocusKey(CHAT | (chat & !KIND))
    }

    /// A peer's row in the Peers list.
    #[must_use]
    pub const fn peer(peer: PeerId) -> FocusKey {
        FocusKey(PEER | (peer & !KIND))
    }

    /// The peer whose row `key` names.
    #[must_use]
    pub const fn peer_of(key: FocusKey) -> Option<PeerId> {
        if key.0 & KIND == PEER {
            Some(key.0 & !KIND)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn message(message: MessageId) -> FocusKey {
        FocusKey(MESSAGE | (message & !KIND))
    }

    /// A repeater's row on the details screen, by its place.
    #[must_use]
    pub const fn repeater(index: usize) -> FocusKey {
        FocusKey(DETAIL_LIST.0 | (index as u32 + 1))
    }

    /// The section whose rail item `key` names.
    #[must_use]
    pub const fn section(key: FocusKey) -> Option<Section> {
        if key.0 & KIND != RAIL {
            return None;
        }
        match key.0 & !KIND {
            0 => Some(Section::Chats),
            1 => Some(Section::Peers),
            2 => Some(Section::Device),
            _ => None,
        }
    }

    /// The chat whose row `key` names.
    #[must_use]
    pub const fn chat_of(key: FocusKey) -> Option<ChatId> {
        if key.0 & KIND == CHAT {
            Some(key.0 & !KIND)
        } else {
            None
        }
    }

    /// Whether `key` names a message.
    #[must_use]
    pub const fn is_message(key: FocusKey) -> bool {
        key.0 & KIND == MESSAGE
    }
}

/// How far away a peer is, as Find says it.
fn distance(hops: Option<u8>) -> String<12> {
    hops.map(crate::model::hops_text).unwrap_or_default()
}

/// What lies over the Chats list for one chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatMenu {
    /// Its menu, which holding the wheel on its row opened.
    Open(ChatId),
    /// Its Delete, or its channel's Leave, asking to be confirmed.
    ConfirmDelete(ChatId),
}

impl ChatMenu {
    #[must_use]
    pub const fn chat(self) -> ChatId {
        match self {
            Self::Open(chat) | Self::ConfirmDelete(chat) => chat,
        }
    }
}

/// What is open over an unconfirmed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsent {
    /// How to send again one that was to go under forward secrecy.
    Resend(MessageId),
    /// Its Delete, or its channel's Leave, asking to be confirmed.
    ConfirmDelete(MessageId),
}

impl Unsent {
    #[must_use]
    pub const fn message(self) -> MessageId {
        match self {
            Self::Resend(message) | Self::ConfirmDelete(message) => message,
        }
    }
}

/// Where the member screen was opened from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberFrom {
    /// A message they sent in the conversation's channel.
    Message(MessageId),
    /// The direct chat with them.
    Chat(ChatId),
    /// A contact's link, or anything else that names them by address.
    Known,
}

/// A screen under Device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DevicePage {
    /// The radio's settings.
    Radio { settings: RadioSettings },
    /// This node: its name, which is edited in place, and its address.
    Identity { name: NameText },
    /// A code that shares `what`.
    Share { what: Shareable },
    /// The joined channels.
    Channels,
    /// A channel's name or invitation, being typed.
    AddChannel { text: ChannelText },
    /// The radio profiles the radio can be set to.
    Profiles,
    /// The keyboard's settings.
    Keyboard { settings: KeyboardSettings },
    /// The radio's transmit power, being typed.
    TransmitPower { text: PowerText },
    /// The clock's settings, and the screens they open.
    Clock { page: ClockPage },
    /// Bluetooth's settings and what it is doing; while `confirm`,
    /// clearing the pairings asks to be confirmed.
    Bluetooth { confirm: bool },
    /// The GNSS receiver's switch and its solution.
    Gnss,
    /// The battery's readings.
    Battery,
    /// Whether the device plays sounds, and how loud; while `adjusting`,
    /// turning changes the volume.
    Sounds { adjusting: bool },
    /// The screen's settings; while `adjusting`, turning changes the
    /// brightness.
    Display { adjusting: bool },
    /// How long the screen stays lit without input.
    AutoLock,
    /// The device's counters.
    Statistics,
    /// What the device is and runs.
    About,
    /// What the firmware is built from, and its licenses.
    Credits,
}

/// A screen a new device starts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupPage {
    /// What to call this node, which may be left empty.
    Name { text: NameText },
    /// The radio profile, which must be set before the radio sends.
    Profile,
    /// The time zone.
    Zone { find: ZoneFind },
}

/// A screen on the navigation stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    Chats {
        focus: FocusState,
        /// The row to return to from the rail.
        row: Option<FocusKey>,
        /// What the Chats list is filtered by, while Find is open.
        find: Option<FindText>,
        /// The Device list is asking to confirm Shut down.
        confirm_shut_down: bool,
        /// A chat's menu is open, or Delete is asking to be confirmed.
        menu: Option<ChatMenu>,
    },
    Conversation {
        chat: ChatId,
        focus: FocusState,
        /// The message whose actions menu is open.
        actions: Option<MessageId>,
        /// The message the draft replies to.
        reply: Option<MessageId>,
        /// What is open over an unconfirmed message.
        unsent: Option<Unsent>,
    },
    /// How a message reached this device, or how mine went.
    Details {
        message: MessageId,
        details: Details,
        /// The unknown repeaters asked who they are, and until when the
        /// answer is waited for, on the board's clock.
        asked: heapless::Vec<([u8; 2], u64), MAX_REPEATERS>,
        focus: FocusState,
    },
    /// The member who sent a channel message, or the unsaved peer of a
    /// direct chat.
    Member {
        from: MemberFrom,
        member: Member,
        /// Their identity has been asked for.
        requested: bool,
        focus: FocusState,
    },
    /// A saved peer.
    Peer {
        peer: PeerId,
        detail: PeerDetail,
        /// What they are called here, edited in place.
        alias: JoinName,
        /// Forget is asking to be confirmed.
        confirm: bool,
        /// Their identity has been asked for.
        requested: bool,
        focus: FocusState,
    },
    /// The chats a saved peer's contact can be sent to.
    ShareContact { peer: PeerId, focus: FocusState },
    /// A joined channel.
    Channel {
        chat: ChatId,
        /// What it is called here, edited in place.
        name: JoinName,
        /// Leave is asking to be confirmed.
        confirm: bool,
        focus: FocusState,
    },
    /// One of the screens under Device.
    Device { page: DevicePage, focus: FocusState },
    /// One of the screens a new device starts on, over the Chats screen
    /// it leads to.
    Setup { page: SetupPage, focus: FocusState },
    /// Add peer: the devices nearby with it open too, then Enter an address
    /// and Show my code.
    Nearby { focus: FocusState },
    /// A contact exchange with a device from Nearby, in its place.
    Exchange { focus: FocusState },
    /// A peer's address or invitation, being typed.
    EnterAddress { text: PeerText, focus: FocusState },
    /// A channel an invitation offers, before it is joined.
    Join {
        invite: Invite,
        /// What the channel is to be called here.
        name: JoinName,
        focus: FocusState,
    },
}

impl Screen {
    /// The Chats screen, its list focused.
    #[must_use]
    pub fn chats() -> Self {
        Self::Chats {
            focus: FocusState::new(),
            row: None,
            find: None,
            confirm_shut_down: false,
            menu: None,
        }
    }

    #[must_use]
    pub fn focus(&self) -> &FocusState {
        match self {
            Self::Chats { focus, .. }
            | Self::Conversation { focus, .. }
            | Self::Details { focus, .. }
            | Self::Member { focus, .. }
            | Self::Join { focus, .. }
            | Self::Nearby { focus }
            | Self::Exchange { focus }
            | Self::EnterAddress { focus, .. }
            | Self::Peer { focus, .. }
            | Self::ShareContact { focus, .. }
            | Self::Channel { focus, .. }
            | Self::Device { focus, .. }
            | Self::Setup { focus, .. } => focus,
        }
    }

    /// Whether this is one of the joined channel `chat`'s own screens.
    #[must_use]
    pub fn about(&self, chat: ChatId) -> bool {
        match self {
            Self::Channel { chat: shown, .. }
            | Self::Device {
                page:
                    DevicePage::Share {
                        what: Shareable::Channel(shown),
                    },
                ..
            } => *shown == chat,
            _ => false,
        }
    }

    pub fn focus_mut(&mut self) -> &mut FocusState {
        match self {
            Self::Chats { focus, .. }
            | Self::Conversation { focus, .. }
            | Self::Details { focus, .. }
            | Self::Member { focus, .. }
            | Self::Join { focus, .. }
            | Self::Nearby { focus }
            | Self::Exchange { focus }
            | Self::EnterAddress { focus, .. }
            | Self::Peer { focus, .. }
            | Self::ShareContact { focus, .. }
            | Self::Channel { focus, .. }
            | Self::Device { focus, .. }
            | Self::Setup { focus, .. } => focus,
        }
    }
}

impl State {
    /// The screen shown.
    ///
    /// # Panics
    ///
    /// When there is no screen, which the navigation here never allows.
    #[must_use]
    pub fn screen(&self) -> &Screen {
        self.screens.last().expect("the Chats screen is never left")
    }

    /// The focus of the screen shown, where the app keeps it.
    ///
    /// # Panics
    ///
    /// When there is no screen, which the navigation here never allows.
    pub fn focus(&mut self) -> &mut FocusState {
        self.screens
            .last_mut()
            .expect("the Chats screen is never left")
            .focus_mut()
    }

    /// Focuses the first chat in the list, as when the Chats screen first
    /// shows.
    pub fn focus_list(&mut self) {
        let row = self.list_row();
        if let Some(row) = row {
            self.focus().request(row);
        }
    }

    /// The row to focus on returning to the list: the one left, or the first.
    fn list_row(&self) -> Option<FocusKey> {
        let remembered = match self.screens.first() {
            Some(Screen::Chats { row, .. }) => *row,
            _ => None,
        };
        remembered
            .filter(|row| self.lists(*row))
            .or_else(|| match self.section {
                Section::Chats => self.chats.first().map(|c| keys::chat(c.id)),
                Section::Peers => Some(keys::ADD_PEER),
                Section::Device => Some(keys::IDENTITY),
            })
    }

    /// Whether `row` is a row of the list shown.
    fn lists(&self, row: FocusKey) -> bool {
        match self.section {
            Section::Chats => keys::chat_of(row).is_some_and(|chat| self.chat(chat).is_some()),
            Section::Peers => {
                row == keys::ADD_PEER
                    || keys::peer_of(row).is_some_and(|peer| self.peer(peer).is_some())
            }
            Section::Device => keys::is_category(row),
        }
    }

    /// Moves from the list to the rail, remembering the row left.
    pub fn focus_rail(&mut self) {
        let section = self.section;
        let left = self
            .screen()
            .focus()
            .current()
            .filter(|key| self.lists(*key));
        if let Some(Screen::Chats { focus, row, .. }) = self.screens.last_mut() {
            *row = left;
            focus.request(keys::rail(section));
        }
    }

    /// Opens Find over the Chats list, its field focused to take what is
    /// typed.
    pub fn start_find(&mut self) {
        if let Some(Screen::Chats { focus, find, .. }) = self.screens.last_mut() {
            *find = Some(FindText::new());
            focus.request(keys::FIND_FIELD);
        }
    }

    /// What Find looks for, while it is open.
    #[must_use]
    pub fn find_query(&self) -> Option<&str> {
        match self.screens.first() {
            Some(Screen::Chats {
                find: Some(find), ..
            }) => Some(find.text().trim()),
            _ => None,
        }
    }

    /// What is being typed into Find.
    pub fn find_text_mut(&mut self) -> Option<&mut FindText> {
        match self.screens.last_mut() {
            Some(Screen::Chats { find, .. }) => find.as_mut(),
            _ => None,
        }
    }

    /// Closes Find, returning to the whole list.
    pub fn end_find(&mut self) {
        if let Some(Screen::Chats { find, row, .. }) = self.screens.first_mut() {
            *find = None;
            *row = None;
        }
        if matches!(self.screens.last(), Some(Screen::Chats { .. })) {
            self.focus_list();
        }
    }

    /// What Find finds, up to as many as it lists, and how many there are
    /// in all: chats, then saved peers, then nodes heard nearby.
    #[must_use]
    pub fn found(&self) -> (heapless::Vec<Found, MAX_FOUND>, usize) {
        let mut found = heapless::Vec::new();
        let Some(query) = self.find_query().filter(|q| !q.is_empty()) else {
            return (found, 0);
        };
        let mut count = 0;
        let mut add = |item: Found| {
            count += 1;
            _ = found.push(item);
        };
        for chat in self.chats.iter() {
            // By its name, or by what its row calls it: "fire" finds 🔥.
            let title = chat.title();
            if word_match(&chat.name, query).is_some()
                || word_match(title.as_ref(), query).is_some()
            {
                add(Found {
                    kind: FoundKind::Chat(chat.id),
                    avatar: chat.avatar.clone(),
                    title,
                    distance: String::new(),
                    age: self.age(chat),
                });
            }
        }
        for peer in self.peers.iter() {
            if word_match(&peer.name, query).is_some() {
                add(Found {
                    kind: FoundKind::Peer(peer.id),
                    avatar: peer.avatar.clone(),
                    title: Title::copy(&peer.name),
                    distance: distance(peer.hops),
                    age: peer.heard.clone(),
                });
            }
        }
        for heard in self.node.find_heard(query) {
            add(Found {
                kind: FoundKind::Heard(heard.address),
                avatar: heard.avatar,
                title: Title::copy(&heard.name),
                distance: heard.distance,
                age: heard.age,
            });
        }
        (found, count)
    }

    /// Opens Find's result at `index`, and closes Find.
    pub fn open_found(&mut self, index: usize) {
        let Some(found) = self.found().0.get(index).cloned() else {
            return;
        };
        self.end_find();
        match found.kind {
            FoundKind::Chat(chat) => self.open_chat(chat),
            FoundKind::Peer(peer) => self.open_peer(peer),
            FoundKind::Heard(address) => {
                // A heard node's title is its name.
                let name = found.title.as_ref();
                if let Some(chat) = self.node.direct_chat(&address, name, &found.avatar) {
                    let chat = self.add_chat(chat);
                    self.go_to_chat(chat);
                }
            }
        }
    }

    /// Opens Find's top result, as Enter in its field does.
    pub fn open_top_found(&mut self) {
        self.open_found(0);
    }

    /// Shows `section` and moves from the rail into its list.
    pub fn enter_section(&mut self, section: Section) {
        self.section = section;
        self.focus_list();
    }

    /// Opens the conversation of `chat`, with its composer focused.
    pub fn open_chat(&mut self, chat: ChatId) {
        if self.chat(chat).is_none() || self.screens.is_full() {
            return;
        }
        self.load_conversation(chat);
        if let Some(summary) = self.chats.iter_mut().find(|c| c.id == chat) {
            summary.unread = false;
        }
        self.node.opened(chat);
        _ = self.screens.push(Screen::Conversation {
            chat,
            focus: FocusState::requesting(keys::COMPOSER),
            actions: None,
            reply: None,
            unsent: None,
        });
    }

    /// Opens the actions menu of `message` in the conversation shown, with
    /// Reply focused; Retry, on an unconfirmed one.
    pub fn open_actions(&mut self, message: MessageId) {
        // A card offers what it is for first.
        let first = if self.unconfirmed(message).is_some() {
            keys::RETRY
        } else if self.invite(message).is_some() {
            keys::JOIN
        } else if self.contact_link(message).is_some() {
            keys::VIEW_CONTACT
        } else {
            keys::REPLY
        };
        if let Some(Screen::Conversation { actions, focus, .. }) = self.screens.last_mut() {
            *actions = Some(message);
            focus.request(first);
        }
    }

    /// The invitation `message` in the open chat carries.
    fn invite(&self, message: MessageId) -> Option<Invite> {
        self.open_message(message)?.invite().cloned()
    }

    /// The link of the contact `message` in the open chat carries.
    fn contact_link(&self, message: MessageId) -> Option<SharedText> {
        self.open_message(message)
            .filter(|m| m.contact().is_some())
            .map(|m| m.text)
    }

    /// Shows the node the contact of the message whose actions menu is open
    /// introduces: their page when they are saved, else what is known of
    /// them, on Message. Nothing is saved until Save peer is pressed.
    pub fn view_contact_from_actions(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        let Some(link) = self.contact_link(message) else {
            return;
        };
        let Some(member) = self.node.known_member(link.as_str()) else {
            return;
        };
        self.show_known(member);
    }

    /// Shows `member`, known by address: their page when they are saved,
    /// else their sheet on Message.
    pub(crate) fn show_known(&mut self, member: Member) {
        if member.saved
            && let Some(peer) = member
                .address
                .as_deref()
                .and_then(|address| self.node.saved_peer(address))
            && self.peer(peer).is_some()
        {
            self.open_peer(peer);
            return;
        }
        _ = self.screens.push(Screen::Member {
            from: MemberFrom::Known,
            member,
            requested: false,
            focus: FocusState::requesting(keys::MESSAGE_MEMBER),
        });
    }

    /// Shows the chats the saved peer shown can be sent to, the first
    /// focused.
    pub fn share_contact(&mut self) {
        let Some(&Screen::Peer { peer, .. }) = self.screens.last() else {
            return;
        };
        let Some(first) = self.chats.first().map(|c| c.id) else {
            return;
        };
        _ = self.screens.push(Screen::ShareContact {
            peer,
            focus: FocusState::requesting(keys::chat(first)),
        });
    }

    /// Sends the contact on the Share contact screen to `chat`, and opens
    /// it.
    pub fn send_contact(&mut self, chat: ChatId) {
        let Some(&Screen::ShareContact { peer, .. }) = self.screens.last() else {
            return;
        };
        if self.airtime_wait.is_some() {
            return;
        }
        let Some(index) = self.chats.iter().position(|c| c.id == chat) else {
            return;
        };
        let Some(link) = self.node.contact_uri(peer) else {
            return;
        };
        let forward_secret = self.chats[index].forward_secret;
        let Some(message) = self.node.send(chat, &link, None, forward_secret) else {
            return;
        };
        let mut summary = self.chats.remove(index);
        summary.preview(&message);
        summary.last_activity = message.time;
        _ = self.chats.insert(0, summary);
        self.chime(Cue::Sent);
        self.go_to_chat(chat);
    }

    /// Shows the channel the message whose actions menu is open invites to,
    /// before it is joined.
    pub fn join_from_actions(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        let Some(invite) = self.invite(message) else {
            return;
        };
        let name = JoinName::with_text(String::try_from(invite.name.as_str()).unwrap_or_default());
        _ = self.screens.push(Screen::Join {
            invite,
            name,
            focus: FocusState::requesting(keys::JOIN_CHANNEL),
        });
    }

    /// The name being given to the channel on the join screen.
    pub fn join_name_mut(&mut self) -> Option<&mut JoinName> {
        match self.screens.last_mut() {
            Some(Screen::Join { name, .. }) => Some(name),
            _ => None,
        }
    }

    /// Joins the channel on the join screen, by the name given it, or its
    /// own when none is, and opens it.
    pub fn join(&mut self) {
        let Some(Screen::Join { invite, name, .. }) = self.screens.last() else {
            return;
        };
        let given = name.text().trim();
        let given = if given.is_empty() {
            invite.name.as_str()
        } else {
            given
        };
        if let Some(summary) = self.node.join(invite, given) {
            let chat = self.add_chat(summary);
            self.go_to_chat(chat);
        }
    }

    /// Shows the saved peer `peer`, Message focused.
    pub fn open_peer(&mut self, peer: PeerId) {
        if self.peer(peer).is_none() {
            return;
        }
        let Some(detail) = self.node.peer_detail(peer) else {
            return;
        };
        let alias = JoinName::with_text(detail.alias.clone().unwrap_or_default());
        _ = self.screens.push(Screen::Peer {
            peer,
            detail,
            alias,
            confirm: false,
            requested: false,
            focus: FocusState::requesting(keys::PEER_MESSAGE),
        });
    }

    /// The saved peer shown.
    fn shown_peer(&self) -> Option<PeerId> {
        match self.screens.last() {
            Some(Screen::Peer { peer, .. }) => Some(*peer),
            _ => None,
        }
    }

    /// Reads the saved peer shown from the node again.
    pub(crate) fn refresh_peer(&mut self) {
        let node = self.node;
        if let Some(Screen::Peer { peer, detail, .. }) = self.screens.last_mut()
            && let Some(fresh) = node.peer_detail(*peer)
        {
            *detail = fresh;
        }
    }

    /// The alias being edited on the saved peer's screen.
    pub fn peer_alias_mut(&mut self) -> Option<&mut JoinName> {
        match self.screens.last_mut() {
            Some(Screen::Peer { alias, .. }) => Some(alias),
            _ => None,
        }
    }

    /// The alias begins or ends an edit. An edit ended keeps the alias as
    /// typed.
    pub fn peer_alias_active(&mut self, active: bool) {
        self.field_active(active);
        if !active {
            self.alias_peer();
        }
    }

    /// Calls the saved peer shown what its screen's alias says, or by
    /// their own name when that is empty, and shows the alias as it then
    /// stands.
    pub fn alias_peer(&mut self) {
        let Some(Screen::Peer {
            peer,
            detail,
            alias,
            ..
        }) = self.screens.last()
        else {
            return;
        };
        let peer = *peer;
        let typed: String<32> = String::try_from(alias.text().trim()).unwrap_or_default();
        if detail.alias.as_deref().unwrap_or_default() != typed {
            self.node
                .set_peer_alias(peer, (!typed.is_empty()).then_some(typed.as_str()));
            self.peers.clear();
            self.node.peers(&mut self.peers);
            self.refresh_peer();
        }
        if let Some(Screen::Peer { detail, alias, .. }) = self.screens.last_mut() {
            *alias = JoinName::with_text(detail.alias.clone().unwrap_or_default());
        }
    }

    /// Opens the direct chat with the saved peer shown.
    pub fn message_peer(&mut self) {
        let Some(Screen::Peer { peer, detail, .. }) = self.screens.last() else {
            return;
        };
        let Some(summary) = self.peer(*peer) else {
            return;
        };
        if let Some(chat) = self
            .node
            .direct_chat(&detail.address, &summary.name, &summary.avatar)
        {
            let chat = self.add_chat(chat);
            self.go_to_chat(chat);
        }
    }

    /// Turns forward secrecy with the saved peer shown on or off.
    pub fn toggle_forward_secrecy(&mut self) {
        let Some(Screen::Peer { peer, detail, .. }) = self.screens.last() else {
            return;
        };
        self.node
            .set_forward_secrecy(*peer, !detail.forward_secrecy);
        self.refresh_peer();
    }

    /// Pings the saved peer shown.
    pub fn ping_peer(&mut self) {
        if let Some(peer) = self.shown_peer() {
            self.node.ping(peer);
            self.refresh_peer();
        }
    }

    /// Asks the saved peer shown for their identity.
    pub fn request_peer_identity(&mut self) {
        if let Some(Screen::Peer {
            peer, requested, ..
        }) = self.screens.last_mut()
        {
            self.node.request_peer_identity(*peer);
            *requested = true;
        }
    }

    /// Asks to confirm forgetting the saved peer shown, Cancel focused.
    pub fn ask_forget(&mut self) {
        if let Some(Screen::Peer { confirm, focus, .. }) = self.screens.last_mut() {
            *confirm = true;
            focus.request(keys::FORGET_CANCEL);
        }
    }

    /// Keeps the saved peer shown after all.
    pub fn cancel_forget(&mut self) {
        if let Some(Screen::Peer { confirm, focus, .. }) = self.screens.last_mut() {
            *confirm = false;
            focus.request(keys::PEER_FORGET);
        }
    }

    /// Forgets the saved peer shown and returns to the Peers list, at the
    /// row that took its place.
    pub fn forget_peer(&mut self) {
        if let Some(peer) = self.shown_peer() {
            self.node.forget_peer(peer);
            self.remove_peer(peer);
        }
    }

    /// Lets go of `peer`, no longer saved: its row, and its screen, which
    /// returns to the Peers list at the row that took its place.
    pub(crate) fn remove_peer(&mut self, peer: PeerId) {
        let Some(index) = self.peers.iter().position(|p| p.id == peer) else {
            return;
        };
        self.peers.remove(index);
        let next = self
            .peers
            .get(index)
            .or_else(|| self.peers.last())
            .map_or(keys::ADD_PEER, |p| keys::peer(p.id));
        if self.shown_peer() == Some(peer) {
            self.back();
            self.focus().request(next);
        }
        if let Some(Screen::Chats { focus, row, .. }) = self.screens.first_mut() {
            if *row == Some(keys::peer(peer)) {
                *row = Some(next);
            }
            if focus.current() == Some(keys::peer(peer)) {
                focus.request(next);
            }
        }
    }

    /// Shows this node, its name focused.
    pub fn open_identity(&mut self) {
        let name = NameText::with_text(self.status.device_name.clone());
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Identity { name },
            focus: FocusState::requesting(keys::IDENTITY_NAME),
        });
    }

    /// The name being edited on the Identity screen.
    pub fn identity_name_mut(&mut self) -> Option<&mut NameText> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::Identity { name },
                ..
            }) => Some(name),
            _ => None,
        }
    }

    /// The Identity screen's name begins or ends an edit. An edit ended
    /// keeps the name as typed.
    pub fn identity_name_active(&mut self, active: bool) {
        self.field_active(active);
        if !active {
            self.rename_identity();
        }
    }

    /// Calls this node what the Identity screen's name says, empty or not,
    /// and shows the name as it then stands.
    pub fn rename_identity(&mut self) {
        let Some(Screen::Device {
            page: DevicePage::Identity { name },
            ..
        }) = self.screens.last()
        else {
            return;
        };
        let typed = name.text().trim();
        if typed != self.status.device_name.as_str() {
            self.node.set_name(typed);
            self.refresh_settings();
        }
        let shown = self.status.device_name.clone();
        if let Some(name) = self.identity_name_mut() {
            *name = NameText::with_text(shown);
        }
    }

    /// Shows this node's code.
    pub fn open_identity_code(&mut self) {
        self.open_share(Shareable::Identity);
    }

    /// Shows the code that shares `what`: this node's dated afresh.
    fn open_share(&mut self, what: Shareable) {
        if what == Shareable::Identity {
            self.node.read_contact();
        }
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Share { what },
            focus: FocusState::requesting(keys::SHARE_CODE),
        });
    }

    /// Shows the radio's settings, its switch focused.
    pub fn open_radio(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Radio {
                settings: self.node.radio(),
            },
            focus: FocusState::requesting(keys::RADIO_ENABLED),
        });
    }

    pub fn toggle_radio(&mut self) {
        if let Some(settings) = self.shown_radio() {
            self.node.set_radio_enabled(!settings.enabled);
            self.refresh_settings();
        }
    }

    /// Shows Bluetooth's settings, its switch focused.
    pub fn open_bluetooth(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Bluetooth { confirm: false },
            focus: FocusState::requesting(keys::BLUETOOTH_ENABLED),
        });
    }

    pub fn toggle_bluetooth(&mut self) {
        if let Some(on) = self.node.bluetooth_enabled() {
            self.node.set_bluetooth_enabled(!on);
        }
    }

    /// Opens a window for a phone to pair, or closes it. What is shown
    /// changes at once; the board's next reading says how it went.
    pub fn toggle_pairing(&mut self) {
        let open = !self.links.bluetooth.pairing;
        self.node.set_pairing(open);
        self.links.bluetooth.pairing = open;
    }

    /// Asks to confirm forgetting every paired phone, Cancel focused.
    pub fn ask_clear_pairings(&mut self) {
        if let Some(Screen::Device {
            page: DevicePage::Bluetooth { confirm },
            focus,
        }) = self.screens.last_mut()
        {
            *confirm = true;
            *focus = FocusState::requesting(keys::CLEAR_PAIRINGS_CANCEL);
        }
    }

    pub fn clear_pairings(&mut self) {
        self.node.clear_pairings();
        self.links.bluetooth.paired = self.links.bluetooth.paired.map(|_| 0);
        self.cancel_clear_pairings();
    }

    pub fn cancel_clear_pairings(&mut self) {
        if let Some(Screen::Device {
            page: DevicePage::Bluetooth { confirm },
            focus,
        }) = self.screens.last_mut()
        {
            *confirm = false;
            *focus = FocusState::requesting(keys::CLEAR_PAIRINGS);
        }
    }

    /// Shows the GNSS receiver's switch and solution, its switch focused.
    pub fn open_gnss(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Gnss,
            focus: FocusState::requesting(keys::GNSS_ENABLED),
        });
    }

    pub fn toggle_gnss(&mut self) {
        if let Some(on) = self.node.gnss_enabled() {
            self.node.set_gnss_enabled(!on);
        }
    }

    /// Shows whether the device plays sounds, its switch focused.
    pub fn open_sounds(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Sounds { adjusting: false },
            focus: FocusState::requesting(keys::SOUNDS_ENABLED),
        });
    }

    /// Volume was pressed: turning starts or stops changing it.
    pub fn press_volume(&mut self) {
        if let Some(Screen::Device {
            page: DevicePage::Sounds { adjusting },
            ..
        }) = self.screens.last_mut()
        {
            *adjusting = !*adjusting;
        }
    }

    /// Whether turning changes the volume: it was pressed, and is still
    /// focused.
    #[must_use]
    pub fn adjusting_volume(&self) -> bool {
        matches!(
            self.screen(),
            Screen::Device {
                page: DevicePage::Sounds { adjusting: true },
                focus,
            } if focus.current() == Some(keys::VOLUME)
        )
    }

    /// The wheel turned `detents` while the volume is being changed:
    /// changes it, turned up louder, and returns whether it did.
    pub fn turn_volume(&mut self, detents: i8) -> bool {
        if !self.adjusting_volume() {
            return false;
        }
        self.step_volume(detents.saturating_neg());
        true
    }

    pub fn toggle_sound(&mut self) {
        if let Some(on) = self.node.sound_enabled() {
            self.node.set_sound_enabled(!on);
            self.status.silent = on;
        }
    }

    /// Shows the battery's readings.
    pub fn open_battery(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Battery,
            focus: FocusState::requesting(keys::READING),
        });
    }

    /// Shows the screen's settings, Brightness focused.
    pub fn open_display(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Display { adjusting: false },
            focus: FocusState::requesting(keys::BRIGHTNESS),
        });
    }

    fn adjusting_mut(&mut self) -> Option<&mut bool> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::Display { adjusting },
                ..
            }) => Some(adjusting),
            _ => None,
        }
    }

    /// Brightness was pressed: turning starts or stops changing it.
    pub fn press_brightness(&mut self) {
        if let Some(adjusting) = self.adjusting_mut() {
            *adjusting = !*adjusting;
        }
    }

    /// Whether turning changes the brightness: it was pressed, and is
    /// still focused.
    #[must_use]
    pub fn adjusting_brightness(&self) -> bool {
        matches!(
            self.screen(),
            Screen::Device {
                page: DevicePage::Display { adjusting: true },
                focus,
            } if focus.current() == Some(keys::BRIGHTNESS)
        )
    }

    /// The wheel turned `detents` while the brightness is being changed:
    /// changes it, turned up brightening, and returns whether it did.
    pub fn turn_brightness(&mut self, detents: i8) -> bool {
        if !self.adjusting_brightness() {
            return false;
        }
        self.step_brightness(detents.saturating_neg());
        true
    }

    /// Shows Auto-Lock's choices, the one in force focused. Any change of
    /// brightness under way ends.
    pub fn open_auto_lock(&mut self) {
        if let Some(adjusting) = self.adjusting_mut() {
            *adjusting = false;
        }
        let current = self
            .node
            .auto_lock()
            .and_then(|seconds| AUTO_LOCK_CHOICES.iter().position(|&c| c == seconds))
            .unwrap_or(0);
        _ = self.screens.push(Screen::Device {
            page: DevicePage::AutoLock,
            focus: FocusState::requesting(keys::auto_lock_choice(current)),
        });
    }

    /// Sets Auto-Lock to `seconds`, and returns to Display.
    pub fn choose_auto_lock(&mut self, seconds: u16) {
        self.node.set_auto_lock(seconds);
        self.back();
    }

    /// Shows the device's counters, read for as long as they are shown.
    pub fn open_statistics(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Statistics,
            focus: FocusState::requesting(keys::READING),
        });
        self.settle();
    }

    /// Shows what the device is and runs.
    pub fn open_about(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::About,
            focus: FocusState::requesting(keys::CREDITS),
        });
    }

    /// Shows what the firmware is built from.
    pub fn open_credits(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Credits,
            focus: FocusState::requesting(keys::READING),
        });
    }

    /// Reads the settings shown from the node again: this node's name, and
    /// the radio's and the keyboard's settings.
    pub(crate) fn refresh_settings(&mut self) {
        let node = self.node;
        self.status.device_name = node.device_name();
        self.status.silent = node.sound_enabled() == Some(false);
        self.clock = node.clock();
        for screen in &mut self.screens {
            match screen {
                Screen::Device {
                    page: DevicePage::Radio { settings },
                    ..
                } => *settings = node.radio(),
                Screen::Device {
                    page: DevicePage::Keyboard { settings },
                    ..
                } => *settings = node.keyboard(),
                // The Clock screens read the clock's settings from the state.
                _ => {}
            }
        }
    }

    /// The name of the radio's profile, or Custom when it has settings no
    /// profile has.
    #[must_use]
    pub fn profile_name(&self, settings: &RadioSettings) -> &'static str {
        match settings.profile {
            Profile::Vetted(index) => self.node.profile(index).unwrap_or_default(),
            Profile::Custom => "Custom",
        }
    }

    /// The radio's settings shown.
    fn shown_radio(&self) -> Option<&RadioSettings> {
        match self.screens.last() {
            Some(Screen::Device {
                page: DevicePage::Radio { settings },
                ..
            }) => Some(settings),
            _ => None,
        }
    }

    pub fn toggle_forwarding(&mut self) {
        if let Some(settings) = self.shown_radio() {
            self.node.set_forwarding(!settings.forwarding);
            self.refresh_settings();
        }
    }

    /// Opens Transmit power, its field focused.
    pub fn open_transmit_power(&mut self) {
        let mut text = PowerText::default();
        let mut dbm: String<4> = String::new();
        _ = core::fmt::write(
            &mut dbm,
            format_args!("{}", self.node.radio().transmit_power),
        );
        for c in dbm.chars() {
            text.insert(c);
        }
        _ = self.screens.push(Screen::Device {
            page: DevicePage::TransmitPower { text },
            focus: FocusState::requesting(keys::POWER_FIELD),
        });
    }

    pub fn power_text_mut(&mut self) -> Option<&mut PowerText> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::TransmitPower { text },
                ..
            }) => Some(text),
            _ => None,
        }
    }

    /// Sets the transmit power typed, and returns to Radio. A power the
    /// radio cannot use leaves the field as it is, to be corrected.
    pub fn submit_transmit_power(&mut self) {
        let Some(dbm) = self
            .power_text_mut()
            .and_then(|text| text.text().trim().parse::<i8>().ok())
            .filter(|dbm| TRANSMIT_POWER.contains(dbm))
        else {
            return;
        };
        self.node.set_transmit_power(dbm);
        self.back();
        self.refresh_settings();
    }

    /// Opens the keyboard's settings.
    pub fn open_keyboard(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Keyboard {
                settings: self.node.keyboard(),
            },
            focus: FocusState::requesting(keys::CAPITALIZE),
        });
    }

    /// Changes the keyboard's settings by `change`, and shows them.
    fn change_keyboard(&mut self, change: impl FnOnce(&mut KeyboardSettings)) {
        let mut settings = self.node.keyboard();
        change(&mut settings);
        self.node.set_keyboard(settings);
        self.refresh_settings();
    }

    pub fn toggle_capitalize(&mut self) {
        self.change_keyboard(|s| s.capitalize = !s.capitalize);
    }

    pub fn toggle_period(&mut self) {
        self.change_keyboard(|s| s.period = !s.period);
    }

    pub fn toggle_keyboard_light(&mut self) {
        self.change_keyboard(|s| s.light = !s.light);
    }

    pub fn toggle_share_location(&mut self) {
        if let Some(settings) = self.shown_radio() {
            self.node.set_share_location(!settings.share_location);
            self.refresh_settings();
        }
    }

    /// Shows the radio profiles, the radio's own focused.
    pub fn open_profiles(&mut self) {
        let current = self.current_profile();
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Profiles,
            focus: FocusState::requesting(keys::profile(current)),
        });
    }

    /// Where the radio's profile sits in the list of them; the first when
    /// it has settings no profile has.
    fn current_profile(&self) -> usize {
        match self.node.radio().profile {
            Profile::Vetted(index) => index,
            Profile::Custom => 0,
        }
    }

    /// Sets the radio to the profile at `index`, and goes on: to the time
    /// zone on first run, back to Radio otherwise.
    pub fn choose_profile(&mut self, index: usize) {
        self.node.set_profile(index);
        match self.screens.last() {
            Some(Screen::Setup { .. }) => self.ask_setup_zone(),
            _ => {
                self.back();
                self.refresh_settings();
            }
        }
    }

    /// Starts first run: what to call this node, its radio profile, and its
    /// time zone.
    pub fn start_setup(&mut self) {
        self.close_conversation();
        self.screens.truncate(1);
        _ = self.screens.push(Screen::Setup {
            page: SetupPage::Name {
                text: NameText::new(),
            },
            focus: FocusState::requesting(keys::NAME_FIELD),
        });
    }

    /// Whether first run is still on screen.
    #[must_use]
    pub fn in_setup(&self) -> bool {
        matches!(self.screens.last(), Some(Screen::Setup { .. }))
    }

    /// The name being typed on first run.
    pub fn name_text_mut(&mut self) -> Option<&mut NameText> {
        match self.screens.last_mut() {
            Some(Screen::Setup {
                page: SetupPage::Name { text },
                ..
            }) => Some(text),
            _ => None,
        }
    }

    /// Keeps the name typed, empty or not, and goes on to the radio
    /// profile.
    pub fn continue_setup(&mut self) {
        let Some(Screen::Setup {
            page: SetupPage::Name { text },
            ..
        }) = self.screens.last()
        else {
            return;
        };
        self.node.set_name(text.text().trim());
        self.refresh_settings();
        let current = self.current_profile();
        _ = self.screens.push(Screen::Setup {
            page: SetupPage::Profile,
            focus: FocusState::requesting(keys::profile(current)),
        });
    }

    /// Ends first run on the Chats screen.
    pub(crate) fn finish_setup(&mut self) {
        self.screens.truncate(1);
        self.focus_list();
    }

    /// Shows the joined channels, Add channel focused.
    /// Asks to confirm turning the board off.
    pub fn ask_shut_down(&mut self) {
        if let Some(Screen::Chats {
            confirm_shut_down,
            focus,
            ..
        }) = self.screens.last_mut()
        {
            *confirm_shut_down = true;
            focus.request(keys::SHUT_DOWN_CANCEL);
        }
    }

    /// Keeps the board on after all.
    pub fn cancel_shut_down(&mut self) {
        if let Some(Screen::Chats {
            confirm_shut_down,
            focus,
            ..
        }) = self.screens.last_mut()
        {
            *confirm_shut_down = false;
            focus.request(keys::SHUT_DOWN);
        }
    }

    /// Turns the board off, confirmed: the screen says so, and the board,
    /// finding [`State::ending`] set by an input, does it.
    pub fn shut_down(&mut self) {
        if let Some(Screen::Chats {
            confirm_shut_down, ..
        }) = self.screens.last_mut()
        {
            *confirm_shut_down = false;
        }
        self.shutting_down();
    }

    /// The wheel, or a finger, was held down long enough on what is
    /// focused: opens its menu. Returns whether one opened.
    pub(crate) fn hold(&mut self) -> bool {
        match self.screens.last() {
            Some(Screen::Chats { .. }) => self.hold_chat(),
            Some(Screen::Conversation { .. }) => self.hold_message(),
            _ => false,
        }
    }

    /// Opens the menu of the chat focused in the Chats list, with its
    /// first choice focused.
    fn hold_chat(&mut self) -> bool {
        let Some(Screen::Chats { focus, menu, .. }) = self.screens.last() else {
            return false;
        };
        if menu.is_some() {
            return false;
        }
        let Some(chat) = focus.current().and_then(keys::chat_of) else {
            return false;
        };
        if self.chat(chat).is_none() {
            return false;
        }
        if let Some(Screen::Chats { focus, menu, .. }) = self.screens.last_mut() {
            *menu = Some(ChatMenu::Open(chat));
            focus.request(keys::CHAT_SHOW);
        }
        true
    }

    /// Opens what pressing the focused message does: its actions.
    fn hold_message(&mut self) -> bool {
        let Some(Screen::Conversation {
            focus,
            actions: None,
            unsent: None,
            ..
        }) = self.screens.last()
        else {
            return false;
        };
        let Some(key) = focus.current() else {
            return false;
        };
        // Read from the newest, where focus mostly is.
        let node = self.node;
        let Some(id) = self.conversation.as_ref().and_then(|c| {
            (0..node.rows(c.chat))
                .rev()
                .filter_map(|row| node.row_id(c.chat, row))
                .find(|&id| keys::message(id) == key)
        }) else {
            return false;
        };
        self.open_actions(id);
        true
    }

    /// The chat whose menu or confirmation is open.
    fn menu_chat(&self) -> Option<ChatId> {
        match self.screens.last() {
            Some(Screen::Chats { menu, .. }) => menu.map(ChatMenu::chat),
            _ => None,
        }
    }

    /// Closes the chat's menu, or its confirmation, back to its row.
    pub fn close_chat_menu(&mut self) {
        if let Some(Screen::Chats { focus, menu, .. }) = self.screens.last_mut()
            && let Some(open) = menu.take()
        {
            focus.request(keys::chat(open.chat()));
        }
    }

    /// Shows whom or what the chat whose menu is open is with: its
    /// channel; or its peer's page when they are saved, else what is known
    /// of them, with Save peer.
    pub fn show_chat(&mut self) {
        let Some(chat) = self.menu_chat() else {
            return;
        };
        self.close_chat_menu();
        if self.is_channel(chat) {
            self.open_channel(chat);
        } else if let Some(peer) = self.node.chat_peer(chat) {
            self.open_peer(peer);
        } else if let Some(member) = self.node.chat_member(chat) {
            let focus = if member.saved {
                keys::MESSAGE_MEMBER
            } else {
                keys::SAVE_PEER
            };
            _ = self.screens.push(Screen::Member {
                from: MemberFrom::Chat(chat),
                member,
                requested: false,
                focus: FocusState::requesting(focus),
            });
        }
    }

    /// Asks to confirm deleting the chat whose menu is open, Cancel
    /// focused.
    pub fn ask_delete_chat(&mut self) {
        if let Some(Screen::Chats { focus, menu, .. }) = self.screens.last_mut()
            && let Some(ChatMenu::Open(chat)) = *menu
        {
            *menu = Some(ChatMenu::ConfirmDelete(chat));
            focus.request(keys::DELETE_CANCEL);
        }
    }

    /// Deletes the direct chat, or leaves the channel, confirmed. Its row
    /// goes when the node says it has.
    pub fn delete_chat(&mut self) {
        let Some(chat) = self.menu_chat() else {
            return;
        };
        self.close_chat_menu();
        if self.is_channel(chat) {
            self.node.leave_channel(chat);
        } else {
            self.node.delete_chat(chat);
        }
    }

    /// Whether `chat` is a channel's.
    #[must_use]
    pub fn is_channel(&self, chat: ChatId) -> bool {
        self.chat(chat)
            .is_some_and(|c| matches!(c.kind, ChatKind::Channel { .. }))
    }

    pub fn open_channels(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Channels,
            focus: FocusState::requesting(keys::ADD_CHANNEL),
        });
    }

    /// Shows the joined channel `chat`, Message focused.
    pub fn open_channel(&mut self, chat: ChatId) {
        let Some(summary) = self
            .chat(chat)
            .filter(|c| matches!(c.kind, ChatKind::Channel { .. }))
        else {
            return;
        };
        let name = JoinName::with_text(summary.name.clone());
        _ = self.screens.push(Screen::Channel {
            chat,
            name,
            confirm: false,
            focus: FocusState::requesting(keys::CHANNEL_MESSAGE),
        });
    }

    /// The channel shown.
    fn shown_channel(&self) -> Option<ChatId> {
        match self.screens.last() {
            Some(Screen::Channel { chat, .. }) => Some(*chat),
            _ => None,
        }
    }

    /// Opens the conversation of the channel shown.
    pub fn message_channel(&mut self) {
        if let Some(chat) = self.shown_channel() {
            self.go_to_chat(chat);
        }
    }

    /// Shows the code that shares the channel shown.
    pub fn open_channel_code(&mut self) {
        if let Some(chat) = self.shown_channel() {
            self.open_share(Shareable::Channel(chat));
        }
    }

    /// The name being edited on the channel's screen.
    pub fn channel_name_mut(&mut self) -> Option<&mut JoinName> {
        match self.screens.last_mut() {
            Some(Screen::Channel { name, .. }) => Some(name),
            _ => None,
        }
    }

    /// The channel's name begins or ends an edit. An edit ended keeps the
    /// name as typed.
    pub fn channel_name_active(&mut self, active: bool) {
        self.field_active(active);
        if !active {
            self.rename_channel();
        }
    }

    /// Calls the channel shown what its screen's name says, or by its own
    /// name when that is empty, and shows the name as it then stands.
    pub fn rename_channel(&mut self) {
        let Some(Screen::Channel { chat, name, .. }) = self.screens.last() else {
            return;
        };
        let chat = *chat;
        let typed: String<32> = String::try_from(name.text().trim()).unwrap_or_default();
        if self.chat(chat).is_some_and(|c| c.name != typed) {
            self.node
                .rename_chat(chat, (!typed.is_empty()).then_some(typed.as_str()));
            self.refresh_chat(chat);
        }
        let shown = self.chat(chat).map(|c| c.name.clone()).unwrap_or_default();
        if let Some(name) = self.channel_name_mut() {
            *name = JoinName::with_text(shown);
        }
    }

    /// Turns the shown channel's notifications on or off.
    pub fn toggle_channel_notifications(&mut self) {
        let Some(chat) = self.shown_channel() else {
            return;
        };
        if let Some(muted) = self.chat(chat).map(|c| c.muted) {
            self.node.set_muted(chat, !muted);
            self.refresh_chat(chat);
        }
    }

    /// Asks to confirm leaving the channel shown, Cancel focused.
    pub fn ask_leave(&mut self) {
        if let Some(Screen::Channel { confirm, focus, .. }) = self.screens.last_mut() {
            *confirm = true;
            focus.request(keys::LEAVE_CANCEL);
        }
    }

    /// Stays in the channel shown after all.
    pub fn cancel_leave(&mut self) {
        if let Some(Screen::Channel { confirm, focus, .. }) = self.screens.last_mut() {
            *confirm = false;
            focus.request(keys::CHANNEL_LEAVE);
        }
    }

    /// Leaves the channel shown, confirmed. Its screens go with its chat.
    pub fn leave_channel(&mut self) {
        if let Some(chat) = self.shown_channel() {
            self.node.leave_channel(chat);
            self.refresh_chat(chat);
        }
    }

    /// Shows Add channel, its field focused, so typing starts the name.
    pub fn open_add_channel(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::AddChannel {
                text: ChannelText::new(),
            },
            focus: FocusState::requesting(keys::CHANNEL_FIELD),
        });
    }

    /// The name or invitation being typed into Add channel.
    pub fn channel_text_mut(&mut self) -> Option<&mut ChannelText> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::AddChannel { text },
                ..
            }) => Some(text),
            _ => None,
        }
    }

    /// What has been typed into Add channel names so far.
    #[must_use]
    pub fn channel_entry(&self) -> ChannelEntry {
        match self.screens.last() {
            Some(Screen::Device {
                page: DevicePage::AddChannel { text },
                ..
            }) => self.node.inspect_channel(text.text()),
            _ => ChannelEntry::Empty,
        }
    }

    /// Joins the channel typed into Add channel and opens it.
    pub fn add_channel(&mut self) {
        let Some(Screen::Device {
            page: DevicePage::AddChannel { text },
            ..
        }) = self.screens.last()
        else {
            return;
        };
        if let Some(chat) = self.node.add_channel(text.text()) {
            let chat = self.add_chat(chat);
            self.go_to_chat(chat);
        }
    }

    /// Shows Add peer, on Nearby. Its session is open while it is shown.
    pub fn open_add_peer(&mut self) {
        _ = self.screens.push(Screen::Nearby {
            focus: FocusState::requesting(keys::ENTER_ADDRESS),
        });
        self.settle_meet();
    }

    /// Shows Enter an address, its field focused, so typing starts the
    /// address.
    pub fn open_enter_address(&mut self) {
        _ = self.screens.push(Screen::EnterAddress {
            text: PeerText::new(),
            focus: FocusState::requesting(keys::PEER_FIELD),
        });
        self.settle_meet();
    }

    /// Shows this node's code, from Add peer.
    pub fn show_my_code(&mut self) {
        self.open_identity_code();
        self.settle_meet();
    }

    /// Asks the device on Nearby's row `device` to exchange contacts.
    pub fn ask_to_exchange(&mut self, device: NearbyId) {
        if self.node.ask_to_exchange(device) {
            self.refresh_meet();
        }
    }

    /// Answers the device that asked to exchange. Not now stays on Nearby,
    /// under a new session key.
    pub fn answer_exchange(&mut self, accept: bool) {
        self.node.answer_exchange(accept);
        if !accept {
            self.node.open_meet();
        }
        self.refresh_meet();
    }

    /// Our holder compared the codes.
    pub fn confirm_code(&mut self, same: bool) {
        self.node.confirm_code(same);
        self.refresh_meet();
    }

    /// Back to Nearby after an exchange ended, under a new session key.
    pub fn try_again(&mut self) {
        if let Some(screen @ Screen::Exchange { .. }) = self.screens.last_mut() {
            *screen = Screen::Nearby {
                focus: FocusState::requesting(keys::ENTER_ADDRESS),
            };
            self.node.open_meet();
            self.refresh_meet();
        }
    }

    /// Reads Add peer again from the node, and follows where it went.
    pub(crate) fn refresh_meet(&mut self) {
        self.node.meet(&mut self.meet);
        self.follow_meet();
    }

    /// Keeps what the node does for a screen in step with what is shown:
    /// Add peer's session, and the counters' reads.
    pub(crate) fn settle(&mut self) {
        self.settle_meet();
        let counting = !self.lock.locked
            && matches!(
                self.screen(),
                Screen::Device {
                    page: DevicePage::Statistics,
                    ..
                }
            );
        self.node.watch_statistics(counting);
    }

    /// Keeps Add peer's session open while Nearby or the exchange is shown
    /// and the interface is unlocked, and closed otherwise. Whatever opens
    /// it again opens a new one.
    pub(crate) fn settle_meet(&mut self) {
        let shown = !self.lock.locked
            && matches!(
                self.screen(),
                Screen::Nearby { .. } | Screen::Exchange { .. }
            );
        let open = self.meet.exchange != Exchange::Closed;
        if shown && !open {
            self.node.open_meet();
        } else if !shown && open {
            self.node.close_meet();
        } else {
            return;
        }
        self.refresh_meet();
    }

    /// Moves between Nearby and the exchange as the exchange goes, and
    /// focuses what it asks of the holder.
    fn follow_meet(&mut self) {
        let nearby = matches!(self.screen(), Screen::Nearby { .. });
        let exchange = matches!(self.screen(), Screen::Exchange { .. });
        if !nearby && !exchange {
            return;
        }
        let focus = self
            .screen()
            .focus()
            .current()
            .or(self.screen().focus().pending());
        let held = |keys: &[FocusKey]| focus.is_some_and(|focus| keys.contains(&focus));
        match &self.meet.exchange {
            Exchange::Exchanged(member) => {
                let member = member.clone();
                self.screens.truncate(1);
                self.settle();
                self.show_known(member);
            }
            Exchange::Asked(_) if nearby => {
                if !held(&[keys::EXCHANGE_ACCEPT, keys::EXCHANGE_DECLINE]) {
                    self.focus().request(keys::EXCHANGE_ACCEPT);
                }
            }
            Exchange::Asking(_)
            | Exchange::Accepted(_)
            | Exchange::Comparing { .. }
            | Exchange::Ended(_)
                if nearby =>
            {
                if let Some(screen) = self.screens.last_mut() {
                    *screen = Screen::Exchange {
                        focus: FocusState::new(),
                    };
                }
                self.follow_meet();
            }
            Exchange::Comparing { sent: false, .. } => {
                if !held(&[keys::SAME, keys::DIFFERENT]) {
                    self.focus().request(keys::SAME);
                }
            }
            Exchange::Ended(_) => {
                if !held(&[keys::TRY_AGAIN, keys::DONE]) {
                    self.focus().request(keys::TRY_AGAIN);
                }
            }
            // Under a new session key, back on Nearby.
            Exchange::Opening | Exchange::Idle if exchange => {
                if let Some(screen) = self.screens.last_mut() {
                    *screen = Screen::Nearby {
                        focus: FocusState::requesting(keys::ENTER_ADDRESS),
                    };
                }
            }
            // The card went: back to the rows.
            Exchange::Idle | Exchange::Opening
                if held(&[keys::EXCHANGE_ACCEPT, keys::EXCHANGE_DECLINE]) =>
            {
                self.focus().request(keys::ENTER_ADDRESS);
            }
            _ => {}
        }
    }

    /// The address or invitation being typed into Enter an address.
    pub fn peer_text_mut(&mut self) -> Option<&mut PeerText> {
        match self.screens.last_mut() {
            Some(Screen::EnterAddress { text, .. }) => Some(text),
            _ => None,
        }
    }

    /// What has been typed into Add peer names so far.
    #[must_use]
    pub fn peer_entry(&self) -> PeerEntry {
        match self.screens.last() {
            Some(Screen::EnterAddress { text, .. }) => self.node.inspect_peer(text.text()),
            _ => PeerEntry::Empty,
        }
    }

    /// Opens the direct chat with the peer Add peer names, once it names one
    /// whole, called by the name its invitation gives, or by their hint.
    pub fn message_entry(&mut self) {
        let PeerEntry::Complete {
            avatar,
            hint,
            address,
            name,
        } = self.peer_entry()
        else {
            return;
        };
        let name = name.as_ref().map_or(hint.as_str(), String::as_str);
        if let Some(summary) = self.node.direct_chat(&address, name, &avatar) {
            let chat = self.add_chat(summary);
            self.go_to_chat(chat);
        }
    }

    /// Lists `summary` first, unless its chat is listed already, and returns
    /// its chat. The oldest gives way when the list is full.
    fn add_chat(&mut self, summary: ChatSummary) -> ChatId {
        let chat = summary.id;
        if self.chat(chat).is_none() {
            if self.chats.is_full() {
                self.chats.pop();
            }
            _ = self.chats.insert(0, summary);
        }
        chat
    }

    /// Closes the actions menu, focusing the message it was opened on, and
    /// returns that message.
    pub fn close_actions(&mut self) -> Option<MessageId> {
        let Some(Screen::Conversation { actions, focus, .. }) = self.screens.last_mut() else {
            return None;
        };
        let message = actions.take()?;
        focus.request(keys::message(message));
        Some(message)
    }

    /// Sends again the unconfirmed message whose actions menu is open.
    pub fn retry_from_actions(&mut self) {
        if let Some(message) = self.close_actions() {
            self.retry(message);
        }
    }

    /// Asks to confirm deleting the unconfirmed message whose actions menu
    /// is open, Cancel focused.
    pub fn ask_delete_message(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        if let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() {
            *unsent = Some(Unsent::ConfirmDelete(message));
            focus.request(keys::DELETE_MESSAGE_CANCEL);
        }
    }

    /// Deletes for everyone the message whose deletion was confirmed.
    pub fn delete_message(&mut self) {
        let chat = self.conversation.as_ref().map(|c| c.chat);
        let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() else {
            return;
        };
        let Some(Unsent::ConfirmDelete(message)) = *unsent else {
            return;
        };
        *unsent = None;
        focus.request(keys::message(message));
        if let Some(chat) = chat {
            self.node.delete_message(chat, message);
        }
    }

    /// Reacts to the message whose actions menu is open, and closes it.
    pub fn react_from_actions(&mut self, reaction: Reaction) {
        if let Some(message) = self.close_actions() {
            self.react(message, reaction);
        }
    }

    /// Closes the actions menu, and opens the character picker to react to
    /// its message with any emoji.
    pub fn more_reactions_from_actions(&mut self) {
        if let Some(message) = self.close_actions() {
            self.open_picker_to_react(message);
        }
    }

    /// Starts a reply to the message whose actions menu is open, in the
    /// composer.
    pub fn reply_from_actions(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        if let Some(Screen::Conversation { reply, focus, .. }) = self.screens.last_mut() {
            *reply = Some(message);
            focus.request(keys::COMPOSER);
        }
    }

    /// Drops the reply being written, keeping its text. Returns `false` when
    /// the draft is not a reply.
    pub fn drop_reply(&mut self) -> bool {
        match self.screens.last_mut() {
            Some(Screen::Conversation { reply, .. }) => reply.take().is_some(),
            _ => false,
        }
    }

    /// Shows how the message whose actions menu is open reached this device.
    pub fn details_from_actions(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        let Some(chat) = self.conversation.as_ref().map(|c| c.chat) else {
            return;
        };
        let details = self.node.details(chat, message).unwrap_or_default();
        _ = self.screens.push(Screen::Details {
            message,
            details,
            asked: heapless::Vec::new(),
            focus: FocusState::requesting(keys::DETAIL_LIST),
        });
    }

    /// Reads the details shown of `message` from the node again, or of
    /// whichever message they are when `message` is `None`.
    pub(crate) fn refresh_details(&mut self, message: Option<MessageId>) {
        let node = self.node;
        let chat = self.conversation.as_ref().map(|c| c.chat);
        if let Some(Screen::Details {
            message: shown,
            details,
            ..
        }) = self.screens.last_mut()
            && message.is_none_or(|message| message == *shown)
            && let Some(fresh) = chat.and_then(|chat| node.details(chat, *shown))
        {
            *details = fresh;
        }
    }

    /// Opens the node the repeater at `index` on the details screen most
    /// plausibly is, or asks who it is when no known node could be.
    pub fn open_repeater(&mut self, index: usize) {
        let uptime = self.uptime;
        let Some(Screen::Details { details, asked, .. }) = self.screens.last_mut() else {
            return;
        };
        let Some(repeater) = details.repeaters.get(index) else {
            return;
        };
        match repeater.address.clone() {
            Some(address) => {
                if let Some(member) = self.node.known_member(&address) {
                    self.show_known(member);
                }
            }
            None => {
                let hint = repeater.hint;
                if asked
                    .iter()
                    .any(|&(asked, until)| asked == hint && until > uptime)
                {
                    return;
                }
                asked.retain(|(asked, _)| *asked != hint);
                if asked.push((hint, uptime + IDENTIFY_WAIT_MS)).is_ok() {
                    self.node.identify_repeater(hint);
                }
            }
        }
    }

    /// The unknown repeaters on the details screen whose identity is still
    /// waited for.
    #[must_use]
    pub fn identifying(&self) -> heapless::Vec<[u8; 2], MAX_REPEATERS> {
        match self.screens.last() {
            Some(Screen::Details { asked, .. }) => asked
                .iter()
                .filter(|&&(_, until)| until > self.uptime)
                .map(|&(hint, _)| hint)
                .collect(),
            _ => heapless::Vec::new(),
        }
    }

    /// Where the spinner of a repeater asked who it is stands, by the
    /// board's clock.
    #[must_use]
    pub fn spinner_phase(&self) -> u8 {
        ((self.uptime / SPIN_STEP_MS) % u64::from(SPIN_PHASES)) as u8
    }

    /// When the details screen next changes by itself: its spinner's next
    /// step while it waits on a repeater, and when it gives up.
    pub(crate) fn details_deadline(&self) -> Option<u64> {
        let Some(Screen::Details { asked, .. }) = self.screens.last() else {
            return None;
        };
        let waiting = asked
            .iter()
            .map(|&(_, until)| until)
            .filter(|&until| until > self.uptime);
        let until = waiting.min()?;
        let step = (self.uptime / SPIN_STEP_MS + 1) * SPIN_STEP_MS;
        Some(step.min(until))
    }

    /// Shows the member who sent the message whose actions menu is open.
    pub fn view_member_from_actions(&mut self) {
        let Some(message) = self.close_actions() else {
            return;
        };
        let Some(chat) = self.conversation.as_ref().map(|c| c.chat) else {
            return;
        };
        let Some(member) = self.node.member(chat, message) else {
            return;
        };
        let focus = if member.address.is_none() {
            keys::REQUEST_IDENTITY
        } else {
            keys::MESSAGE_MEMBER
        };
        _ = self.screens.push(Screen::Member {
            from: MemberFrom::Message(message),
            member,
            requested: false,
            focus: FocusState::requesting(focus),
        });
    }

    /// Asks the channel for the identity of the member shown.
    pub fn request_identity(&mut self) {
        let chat = self.conversation.as_ref().map(|c| c.chat);
        let Some(Screen::Member {
            from: MemberFrom::Message(message),
            requested,
            ..
        }) = self.screens.last_mut()
        else {
            return;
        };
        if let Some(chat) = chat {
            self.node.request_identity(chat, *message);
            *requested = true;
        }
    }

    /// Shows the identities the node has learned since they were drawn:
    /// members' names and addresses in the conversation and on the member
    /// screen.
    pub(crate) fn identities_learned(&mut self) {
        if let Some(chat) = self.conversation.as_ref().map(|c| c.chat) {
            self.load_conversation(chat);
        }
        self.refresh_members();
        self.refresh_details(None);
    }

    /// Reads the members shown from the node again. Focus on a Request
    /// identity that is no longer offered moves to Message.
    pub(crate) fn refresh_members(&mut self) {
        let conversation = self.conversation.as_ref().map(|c| c.chat);
        let node = self.node;
        for screen in &mut self.screens {
            let Screen::Member {
                from,
                member,
                focus,
                ..
            } = screen
            else {
                continue;
            };
            let known = match *from {
                MemberFrom::Message(message) => {
                    conversation.and_then(|chat| node.member(chat, message))
                }
                MemberFrom::Chat(chat) => node.chat_member(chat),
                MemberFrom::Known => member
                    .address
                    .as_deref()
                    .and_then(|address| node.known_member(address)),
            };
            if let Some(known) = known {
                *member = known;
            }
            let asking = focus.current().or(focus.pending()) == Some(keys::REQUEST_IDENTITY);
            if asking && member.address.is_some() {
                focus.request(keys::MESSAGE_MEMBER);
            }
        }
    }

    /// Opens the direct chat with the member shown, made if there is none.
    /// Back from it goes to the list, as the interface holds one
    /// conversation.
    pub fn message_member(&mut self) {
        let Some(Screen::Member { member, .. }) = self.screens.last() else {
            return;
        };
        let Some(address) = member.address.as_ref() else {
            return;
        };
        let Some(summary) =
            self.node
                .direct_chat(address, &member.sender.name, &member.sender.avatar)
        else {
            return;
        };
        let chat = self.add_chat(summary);
        self.go_to_chat(chat);
    }

    /// Keeps the member shown among my peers. Focus on Save peer, which is
    /// no longer offered, moves to Message.
    pub fn save_member(&mut self) {
        let node = self.node;
        let Some(Screen::Member { member, focus, .. }) = self.screens.last_mut() else {
            return;
        };
        if member.address.is_none() || member.saved {
            return;
        }
        let saved = node.save_peer(member);
        member.saved = true;
        focus.request(keys::MESSAGE_MEMBER);
        if let Some(peer) = saved
            && self.peer(peer.id).is_none()
        {
            if self.peers.is_full() {
                self.peers.pop();
            }
            _ = self.peers.insert(0, peer);
        }
    }

    /// Opens `chat` in place of whatever is shown. The interface holds one
    /// conversation, so whatever was open closes; Back from the chat goes to
    /// the list, at its row.
    fn go_to_chat(&mut self, chat: ChatId) {
        self.close_conversation();
        self.screens.truncate(1);
        self.settle();
        self.section = Section::Chats;
        self.focus().request(keys::chat(chat));
        self.open_chat(chat);
    }

    /// Lets go of the open chat's messages, and keeps its draft in the node
    /// as it was left.
    fn close_conversation(&mut self) {
        let Some(chat) = self.conversation.as_ref().map(|c| c.chat) else {
            return;
        };
        // Dropped where it lies: a conversation is too large to move aside.
        self.conversation = None;
        if let Some(summary) = self.chat(chat) {
            self.node.save_draft(chat, summary.draft.text());
        }
    }

    /// Returns to the screen before this one, focused where it was left.
    /// Returns `false` on the Chats screen, which nothing comes before.
    pub fn back(&mut self) -> bool {
        if self.screens.len() < 2 {
            return false;
        }
        if let Some(Screen::Conversation { .. }) = self.screens.pop() {
            self.close_conversation();
        }
        self.settle();
        // Focus returns where it was, unless the screen was left asking for
        // somewhere else.
        let focus = self.focus();
        if focus.pending().is_none()
            && let Some(key) = focus.current()
        {
            focus.request(key);
        }
        true
    }
}
