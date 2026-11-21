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
#[cfg(feature = "directional")]
use crate::model::Directions;
use crate::model::{
    AUTO_LOCK_CHOICES, BANDWIDTHS, CODING_RATES, ChannelAccess, ChannelEntry, ChatId, ChatKind,
    ChatSummary, Details, Exchange, Found, FoundKind, HintRead, Invite, KeyboardSettings, Listing,
    LoraChoice, MAX_FOUND, MAX_HINT_READS, MAX_LISTED, MAX_PATH, MAX_REPEATERS, MAX_SCREENS,
    Member, MessageId, NearbyId, PeerDetail, PeerEntry, PeerId, PingView, Profile, RadioSettings,
    Reaction, Repeater, RouteKind, SPREADING_FACTORS, Section, Shareable, State, TRANSMIT_LIMITS,
    TRANSMIT_POWER, word_match,
};
use crate::ui::GammaTest;
pub use crate::wifi_settings::{NetworkText, PasswordText, WifiPage};

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
/// A frequency in kHz, as it is typed.
pub type FrequencyText = EditBuffer<String<8>>;

/// How long a repeater asked who it is is waited on, in milliseconds.
const IDENTIFY_WAIT_MS: u64 = 15_000;

/// The steps of the spinner of a repeater asked who it is, and how long
/// each is shown.
pub const SPIN_PHASES: u8 = 8;
const SPIN_STEP_MS: u64 = 125;

/// The unknown repeaters a screen has asked who they are, and until when
/// each answer is waited for, on the board's clock.
pub type Asked = heapless::Vec<([u8; 2], u64), MAX_REPEATERS>;

/// The most earlier pings the Ping screen lists.
pub const MAX_EARLIER: usize = 3;

/// A ping the Ping screen sent before the latest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingSummary {
    /// Its round trip in milliseconds; `None` when it went unanswered.
    pub round_trip_ms: Option<u32>,
    /// How many hops its reply took.
    pub hops: Option<u8>,
    /// When it settled, on the board's clock.
    pub at: u64,
}

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
    const NEIGHBOR: u32 = 0x2200_0000;
    const SHEET: u32 = 0x2700_0000;
    const PATH: u32 = 0x2B00_0000;
    const WIFI_ROW: u32 = 0x2E00_0000;
    const LORA_CHOICE_ROW: u32 = 0x2F00_0000;
    /// Add hop's known repeaters, then the router hints typed text fixes.
    const PICK: u32 = 0x3000_0000;
    const PICK_HINT: u32 = 0x100;
    const PICK_KNOWN: u32 = 0x1_0000;
    /// Nearby networks' rows, after the saved ones'.
    const WIFI_NEARBY: u32 = 0x100;

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
    pub const PEER_ROUTE: FocusKey = FocusKey(0x0C00_0001);
    pub const PEER_SECRECY: FocusKey = FocusKey(0x0C00_0003);
    pub const PEER_PING: FocusKey = FocusKey(0x0C00_0004);
    pub const PEER_FORGET: FocusKey = FocusKey(0x0C00_0005);
    pub const PEER_IDENTITY: FocusKey = FocusKey(0x0C00_0006);
    pub const FORGET_CONFIRM: FocusKey = FocusKey(0x0C00_0007);
    pub const FORGET_CANCEL: FocusKey = FocusKey(0x0C00_0008);
    pub const PEER_SHARE: FocusKey = FocusKey(0x0C00_0009);
    pub const PEER_ALIAS: FocusKey = FocusKey(0x0C00_000A);
    /// The Route screen's Reset route, and its Ping when no route is held.
    pub const ROUTE_RESET: FocusKey = FocusKey(0x2C00_0000);
    pub const ROUTE_PING: FocusKey = FocusKey(0x2C00_0001);
    /// The Ping screen's Ping again.
    pub const PING_AGAIN: FocusKey = FocusKey(0x2C00_0002);
    /// The Route screen's Edit route, and the editor's rows after its
    /// hops, which are [`path`]'s.
    pub const ROUTE_EDIT: FocusKey = FocusKey(0x2C00_0003);
    pub const ROUTE_FLOOD: FocusKey = FocusKey(0x2C00_0004);
    pub const ROUTE_PING_ALONG: FocusKey = FocusKey(0x2C00_0005);
    pub const ROUTE_HOLD: FocusKey = FocusKey(0x2C00_0006);
    pub const ROUTE_SAVE: FocusKey = FocusKey(0x2C00_0007);
    /// A hop's menu in the editor.
    pub const HOP_MOVE: FocusKey = FocusKey(0x2C00_0008);
    pub const HOP_REMOVE: FocusKey = FocusKey(0x2C00_0009);
    /// What leaving the editor with changes asks.
    pub const LEAVE_SAVE: FocusKey = FocusKey(0x2C00_000A);
    pub const LEAVE_DISCARD: FocusKey = FocusKey(0x2C00_000B);
    pub const LEAVE_KEEP: FocusKey = FocusKey(0x2C00_000C);
    /// The editor's Add hop, and Add hop's field while text is typed.
    pub const ROUTE_ADD: FocusKey = FocusKey(0x2C00_000D);
    pub const PICK_FIELD: FocusKey = FocusKey(0x2C00_000E);
    /// Neighbors on a repeater's page, and Load more and Refresh under
    /// the list.
    pub const MEMBER_NEIGHBORS: FocusKey = FocusKey(0x0700_0003);
    pub const PEER_NEIGHBORS: FocusKey = FocusKey(0x0C00_0002);
    pub const NEIGHBORS_MORE: FocusKey = FocusKey(0x2500_0000);
    pub const NEIGHBORS_REFRESH: FocusKey = FocusKey(0x2500_0001);
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
    /// The Identity screen's Name, View QR code, and Share location.
    pub const IDENTITY_NAME: FocusKey = FocusKey(0x2800_0000);
    pub const IDENTITY_CODE: FocusKey = FocusKey(0x2800_0001);
    pub const SHARE_LOCATION: FocusKey = FocusKey(0x2800_0002);
    /// A channel's screen: its actions and settings, in order, and Leave's
    /// confirmation.
    pub const CHANNEL_MESSAGE: FocusKey = FocusKey(0x2900_0000);
    pub const CHANNEL_CODE: FocusKey = FocusKey(0x2900_0001);
    pub const CHANNEL_NAME: FocusKey = FocusKey(0x2900_0002);
    pub const CHANNEL_NOTIFICATIONS: FocusKey = FocusKey(0x2900_0003);
    pub const CHANNEL_TEST_MESSAGES: FocusKey = FocusKey(0x2900_0007);
    pub const CHANNEL_LEAVE: FocusKey = FocusKey(0x2900_0004);
    pub const LEAVE_CONFIRM: FocusKey = FocusKey(0x2900_0005);
    pub const LEAVE_CANCEL: FocusKey = FocusKey(0x2900_0006);
    /// The Device list's categories.
    pub const IDENTITY: FocusKey = FocusKey(DEVICE);
    pub const CHANNELS: FocusKey = FocusKey(DEVICE | 1);
    pub const WIFI: FocusKey = FocusKey(DEVICE | 3);
    pub const RADIO: FocusKey = FocusKey(DEVICE | 2);
    pub const DISPLAY: FocusKey = FocusKey(DEVICE | 4);
    pub const BLUETOOTH: FocusKey = FocusKey(DEVICE | 5);
    pub const SHUT_DOWN: FocusKey = FocusKey(DEVICE | 7);
    pub const FACTORY_RESET: FocusKey = FocusKey(DEVICE | 15);
    pub const RESTART: FocusKey = FocusKey(DEVICE | 16);
    pub const KEYBOARD: FocusKey = FocusKey(DEVICE | 8);
    pub const CLOCK: FocusKey = FocusKey(DEVICE | 9);
    pub const GNSS: FocusKey = FocusKey(DEVICE | 10);
    pub const BATTERY: FocusKey = FocusKey(DEVICE | 11);
    pub const STATISTICS: FocusKey = FocusKey(DEVICE | 12);
    pub const ABOUT: FocusKey = FocusKey(DEVICE | 13);
    pub const SOUNDS: FocusKey = FocusKey(DEVICE | 14);
    pub const TRACKBALL: FocusKey = FocusKey(DEVICE | 17);
    /// A Device screen with nothing in it to focus, as a whole: turning
    /// scrolls it.
    pub const READING: FocusKey = FocusKey(0x2800_0000);
    /// About's Credits.
    pub const CREDITS: FocusKey = FocusKey(0x2600_0000);
    /// The Display screen's rows, in order.
    pub const BRIGHTNESS: FocusKey = FocusKey(0x2300_0000);
    pub const AUTO_LOCK: FocusKey = FocusKey(0x2300_0001);
    pub const GAMMA: FocusKey = FocusKey(0x2300_0002);
    /// The gamma chart, as a whole.
    pub const GAMMA_CHART: FocusKey = FocusKey(0x2300_0003);
    /// The Bluetooth screen's actions, in order, and Clear pairings'
    /// confirmation.
    pub const BLUETOOTH_ENABLED: FocusKey = FocusKey(0x1E00_0000);
    pub const PAIRING: FocusKey = FocusKey(0x1E00_0003);
    pub const CLEAR_PAIRINGS: FocusKey = FocusKey(0x1E00_0005);
    pub const CLEAR_PAIRINGS_CONFIRM: FocusKey = FocusKey(0x1E00_0006);
    pub const CLEAR_PAIRINGS_CANCEL: FocusKey = FocusKey(0x1E00_0007);
    /// The Wi-Fi screens' rows: the switch, the network in use, Other
    /// network, Scan again, and IP multicast; a sheet's Join or Disconnect, Join
    /// automatically, Change password, Forget and its confirmation; a
    /// password's field and the row that submits it; and Other network's
    /// name and security.
    pub const WIFI_ENABLED: FocusKey = FocusKey(0x2D00_0000);
    pub const WIFI_CURRENT: FocusKey = FocusKey(0x2D00_0001);
    pub const WIFI_OTHER: FocusKey = FocusKey(0x2D00_0002);
    pub const WIFI_SCAN: FocusKey = FocusKey(0x2D00_0003);
    pub const WIFI_ACT: FocusKey = FocusKey(0x2D00_0004);
    pub const WIFI_AUTO_JOIN: FocusKey = FocusKey(0x2D00_0005);
    pub const WIFI_CHANGE_PASSWORD: FocusKey = FocusKey(0x2D00_0006);
    pub const WIFI_FORGET: FocusKey = FocusKey(0x2D00_0007);
    pub const WIFI_FORGET_CONFIRM: FocusKey = FocusKey(0x2D00_0008);
    pub const WIFI_FORGET_CANCEL: FocusKey = FocusKey(0x2D00_0009);
    pub const WIFI_PASSWORD_FIELD: FocusKey = FocusKey(0x2D00_000A);
    pub const WIFI_SUBMIT: FocusKey = FocusKey(0x2D00_000B);
    pub const WIFI_NAME_FIELD: FocusKey = FocusKey(0x2D00_000C);
    pub const WIFI_SECURITY: FocusKey = FocusKey(0x2D00_000D);
    pub const WIFI_IP_MULTICAST: FocusKey = FocusKey(0x2D00_000E);
    /// Rows of Wi-Fi's list that never take focus, named so the list can
    /// tell its rows apart.
    pub const WIFI_IDLE: FocusKey = FocusKey(0x2D00_0020);
    pub const WIFI_SAVED_LABEL: FocusKey = FocusKey(0x2D00_0021);
    pub const WIFI_NEARBY_LABEL: FocusKey = FocusKey(0x2D00_0022);
    pub const WIFI_ADDRESS: FocusKey = FocusKey(0x2D00_0023);

    /// The readout at `index` on a Wi-Fi network's sheet: Signal, Address,
    /// Channel, Security. Never focused.
    #[must_use]
    pub const fn wifi_readout(index: usize) -> FocusKey {
        FocusKey(0x2D00_0030 + index as u32)
    }

    /// The choice of [`crate::wifi_settings::OTHER_SECURITY`] at `index`.
    #[must_use]
    pub const fn wifi_security(index: usize) -> FocusKey {
        FocusKey(0x2D00_0010 + index as u32)
    }

    /// The row of the saved network at `index`.
    #[must_use]
    pub const fn wifi_saved(index: usize) -> FocusKey {
        FocusKey(WIFI_ROW | index as u32)
    }

    /// The row of the nearby network at `index`.
    #[must_use]
    pub const fn wifi_nearby(index: usize) -> FocusKey {
        FocusKey(WIFI_ROW | WIFI_NEARBY | index as u32)
    }

    /// The GNSS screen's switch.
    pub const GNSS_ENABLED: FocusKey = FocusKey(0x1F00_0000);
    /// The Sounds screen's rows, in order.
    pub const SOUNDS_ENABLED: FocusKey = FocusKey(0x2A00_0000);
    pub const VOLUME: FocusKey = FocusKey(0x2A00_0001);
    /// The Trackball screen's switches, in order.
    pub const TRACKBALL_VERTICAL: FocusKey = FocusKey(0x2F00_0000);
    pub const TRACKBALL_HORIZONTAL: FocusKey = FocusKey(0x2F00_0001);
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
    /// LoRa's Transmit power row, and the field it opens.
    pub const TRANSMIT_POWER: FocusKey = FocusKey(0x0E00_0001);
    pub const POWER_FIELD: FocusKey = FocusKey(0x1800_0000);
    /// Radio's LoRa row, and the LoRa screen's rows after its Profile.
    pub const LORA: FocusKey = FocusKey(0x0E00_0006);
    pub const FREQUENCY: FocusKey = FocusKey(0x0E00_0007);
    pub const BANDWIDTH: FocusKey = FocusKey(0x0E00_0008);
    pub const SPREADING_FACTOR: FocusKey = FocusKey(0x0E00_0009);
    pub const CODING_RATE: FocusKey = FocusKey(0x0E00_000A);
    pub const TRANSMIT_LIMIT: FocusKey = FocusKey(0x0E00_000B);
    /// The field Frequency opens.
    pub const FREQUENCY_FIELD: FocusKey = FocusKey(0x1800_0001);

    /// The text field `key` names, as the keyboard treats it.
    #[must_use]
    pub const fn field(key: FocusKey) -> Option<super::Field> {
        use super::Field;
        match key {
            COMPOSER => Some(Field::Prose),
            NAME_FIELD | JOIN_NAME | IDENTITY_NAME | CHANNEL_NAME | PEER_ALIAS => Some(Field::Name),
            FIND_FIELD | PEER_FIELD | CHANNEL_FIELD | WIFI_PASSWORD_FIELD | WIFI_NAME_FIELD
            | PICK_FIELD => Some(Field::Literal),
            POWER_FIELD | FREQUENCY_FIELD => Some(Field::Number),
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
    /// The warning before the first message sent on `EMERGENCY`.
    pub const EMERGENCY_CERTIFY: FocusKey = FocusKey(0x1900_0005);
    pub const EMERGENCY_CANCEL: FocusKey = FocusKey(0x1900_0006);
    /// The learned route, offered in place of one held by hand.
    pub const LEARNED_USE: FocusKey = FocusKey(0x1900_0007);
    pub const LEARNED_KEEP: FocusKey = FocusKey(0x1900_0008);
    /// Shut down's confirmation.
    pub const SHUT_DOWN_CONFIRM: FocusKey = FocusKey(0x1600_0000);
    pub const SHUT_DOWN_CANCEL: FocusKey = FocusKey(0x1600_0001);
    /// Factory reset's two confirmations.
    pub const FACTORY_RESET_CONFIRM: FocusKey = FocusKey(0x1600_0002);
    pub const FACTORY_RESET_CANCEL: FocusKey = FocusKey(0x1600_0003);
    pub const ERASE_CONFIRM: FocusKey = FocusKey(0x1600_0004);
    pub const ERASE_CANCEL: FocusKey = FocusKey(0x1600_0005);
    /// Restart's confirmation.
    pub const RESTART_CONFIRM: FocusKey = FocusKey(0x1600_0006);
    pub const RESTART_CANCEL: FocusKey = FocusKey(0x1600_0007);
    /// The Radio screen's switch and Forwarding, and the LoRa screen's
    /// Profile.
    pub const RADIO_ENABLED: FocusKey = FocusKey(0x0E00_0005);
    pub const PROFILE: FocusKey = FocusKey(0x0E00_0000);
    pub const FORWARDING: FocusKey = FocusKey(0x0E00_0002);

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

    /// A repeater a router reports hearing, by its place in the listing.
    #[must_use]
    pub const fn neighbor(index: usize) -> FocusKey {
        FocusKey(NEIGHBOR | (index as u32 & !KIND))
    }

    /// A row of the route editor or of Neighbors that focus passes over,
    /// by its place.
    #[must_use]
    pub const fn sheet(index: usize) -> FocusKey {
        FocusKey(SHEET | (index as u32 & !KIND))
    }

    /// One of the known repeaters Add hop offers, by its router hint:
    /// their order changes as they are heard, and focus stays with each.
    #[must_use]
    pub const fn known(hint: [u8; 2]) -> FocusKey {
        FocusKey(PICK | PICK_KNOWN | u16::from_be_bytes(hint) as u32)
    }

    /// One of the router hints typed into Add hop fixes, by its place.
    #[must_use]
    pub const fn hint_read(index: usize) -> FocusKey {
        FocusKey(PICK | PICK_HINT | (index as u32 & 0xFF))
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

    /// One of a LoRa setting's values in the list of them, by its place
    /// there.
    #[must_use]
    pub const fn lora_choice(index: usize) -> FocusKey {
        FocusKey(LORA_CHOICE_ROW | (index as u32 & !KIND))
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

    /// A repeater's row on a path, the Route screen's or the Ping screen's,
    /// by its place from this device.
    #[must_use]
    pub const fn path(index: usize) -> FocusKey {
        FocusKey(PATH | (index as u32 & !KIND))
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

/// What is open over the conversation: about a message not yet sent, or
/// not confirmed, or about the route its messages go by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsent {
    /// How to send again one that was to go under forward secrecy.
    Resend(MessageId),
    /// Its Delete, or its channel's Leave, asking to be confirmed.
    ConfirmDelete(MessageId),
    /// The warning before the first thing sent on `EMERGENCY` since the
    /// device started, asking to be certified, with what waits on it.
    CertifyEmergency { then: Certified },
    /// The route learned while the peer's was held by hand, offered in
    /// its place.
    Learned,
}

/// What waits on `EMERGENCY`'s warning: anything that would go on the air
/// there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certified {
    /// The draft.
    Draft,
    /// The contact of a peer.
    Contact(PeerId),
    /// A reaction to a message.
    React(MessageId, Reaction),
    /// An unconfirmed message of mine, sent again.
    Retry(MessageId),
    /// A message of mine, deleted for everyone.
    Delete(MessageId),
    /// A message missing here, asked for again.
    Repair(MessageId),
}

impl Unsent {
    /// The message it is open over, if it is open over one.
    #[must_use]
    pub const fn message(self) -> Option<MessageId> {
        match self {
            Self::Resend(message) | Self::ConfirmDelete(message) => Some(message),
            Self::CertifyEmergency { .. } | Self::Learned => None,
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
    /// The LoRa settings: the profile, and each parameter it sets.
    Lora { settings: RadioSettings },
    /// The radio profiles the radio can be set to.
    Profiles,
    /// The radio's center frequency, being typed.
    Frequency { text: FrequencyText },
    /// The values a LoRa setting can be set to, the radio's own checked.
    LoraChoice { choice: LoraChoice },
    /// The keyboard's settings.
    Keyboard { settings: KeyboardSettings },
    /// The directions the trackball acts in.
    Trackball,
    /// The radio's transmit power, being typed.
    TransmitPower { text: PowerText },
    /// The clock's settings, and the screens they open.
    Clock { page: ClockPage },
    /// Wi-Fi's settings, and the screens they open.
    Wifi { page: WifiPage },
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
    /// A chart to read the panel's gamma from.
    Gamma { test: GammaTest },
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
    /// Set up, and Add peer next.
    Done,
}

/// What the Device list is asking to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceConfirm {
    ShutDown,
    /// Factory reset, asked once.
    FactoryReset,
    /// Factory reset, asked again, its choices the other way around, so
    /// that pressing twice in one place does not erase the device.
    Erase,
    Restart,
}

/// A screen on the navigation stack.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "no allocator here; the navigation stack is fixed-size"
)]
pub enum Screen {
    Chats {
        focus: FocusState,
        /// The row to return to from the rail.
        row: Option<FocusKey>,
        /// What the Chats list is filtered by, while Find is open.
        find: Option<FindText>,
        /// What the Device list is asking to confirm.
        confirm: Option<DeviceConfirm>,
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
        asked: Asked,
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
    /// The route the next message to a saved peer takes, as the node holds
    /// it; or, while `edit` is one, a route being chosen in its place.
    Route {
        peer: PeerId,
        edit: Option<RouteDraft>,
        asked: Asked,
        focus: FocusState,
    },
    /// The repeaters the router at `router` reports hearing, as last read;
    /// or, while `pick` is one, Add hop: what the last hop of the route
    /// being edited beneath reports hearing, to choose the next from. An
    /// empty `router` is a last hop known only by its hint, which cannot
    /// be asked.
    Neighbors {
        router: String<44>,
        pick: Option<AddHop>,
        asked: Asked,
        focus: FocusState,
    },
    /// Pings to a saved peer, and the path the latest answer took. How the
    /// latest went is the node's.
    Ping {
        peer: PeerId,
        /// When the latest ping was sent, on the board's clock.
        sent_at: u64,
        /// When it settled, answered or not; `None` while it waits.
        settled_at: Option<u64>,
        /// The pings before it, the latest first.
        earlier: heapless::Vec<PingSummary, MAX_EARLIER>,
        asked: Asked,
        focus: FocusState,
    },
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

// The navigation stack holds `MAX_SCREENS` of these, so a variant that
// outgrows the rest costs every slot. Raise a bound only on purpose.
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<Screen>() <= 1016);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Screen>() <= 1192);

/// How long a route chosen by hand can be held, in milliseconds, and
/// which of them a new one starts at.
pub const HOLD_CHOICES: [u32; 5] = [
    30 * 60_000,
    60 * 60_000,
    4 * 60 * 60_000,
    12 * 60 * 60_000,
    24 * 60 * 60_000,
];
const HOLD_DEFAULT: u8 = 1;
/// The farthest a route chosen by hand floods past its last hop.
pub const MAX_FLOOD: u8 = 15;

/// A route being chosen by hand: its hops, the repeater nearest this
/// device first, how far it floods past them, and how long it is to be
/// held. Nothing reaches the node until it is saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteDraft {
    hints: [[u8; 2]; MAX_PATH],
    len: u8,
    pub flood: u8,
    /// Which of [`HOLD_CHOICES`].
    pub hold: u8,
    /// The hop being moved: where it is now, and where it was.
    pub lifted: Option<(u8, u8)>,
    /// The value turning changes.
    pub adjusting: Option<Adjust>,
    /// What is open over the editor.
    pub over: Option<EditOver>,
    /// It differs from what it started as.
    pub dirty: bool,
    /// A ping went along it as it stands, and its row says how it went.
    pub pinged: bool,
}

/// A value of a route being chosen that turning changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adjust {
    Flood,
    Hold,
}

/// A row of the route editor, from the top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditRow {
    You,
    /// The hop at this place, the one nearest this device first.
    Hop(usize),
    /// Add hop, while the route has room for one.
    Add,
    Flood,
    Peer,
    Ping,
    Hold,
    Save,
}

/// A row of a router's Neighbors, from the top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListRow {
    /// When the listing was read, or that it never was.
    Read,
    /// The repeater at this place in the listing.
    Neighbor(usize),
    /// That the router listed nobody, or did not answer.
    Said,
    More,
    Refresh,
}

/// The row at `index` of a router's Neighbors, `listing` as last read.
#[must_use]
pub fn listing_row(listing: Option<&Listing>, index: usize) -> Option<ListRow> {
    let count = listing.map_or(0, |listing| usize::from(listing.count));
    let read = listing.is_some_and(|listing| listing.read_ms_ago.is_some());
    let no_answer = listing.is_some_and(|listing| listing.no_answer);
    let asking = listing.is_some_and(|listing| listing.asking.is_some());
    let said = no_answer || (read && count == 0 && !asking);
    let more = listing.is_some_and(|listing| listing.more);
    let rows = [
        (true, ListRow::Read),
        (said, ListRow::Said),
        (more, ListRow::More),
        (true, ListRow::Refresh),
    ];
    match index {
        0 => Some(ListRow::Read),
        i if i <= count => Some(ListRow::Neighbor(i - 1)),
        i => rows[1..]
            .iter()
            .filter(|(shown, _)| *shown)
            .nth(i - count - 1)
            .map(|&(_, row)| row),
    }
}

/// How many rows a router's Neighbors has, `listing` as last read.
#[must_use]
pub fn listing_rows(listing: Option<&Listing>) -> usize {
    (0..)
        .take_while(|&i| listing_row(listing, i).is_some())
        .count()
}

/// The most rows the route editor, Neighbors, or Add hop lays out: the
/// editor's with every hop.
pub const SHEET_ROWS: usize = MAX_PATH + 6;
const _: () = assert!(MAX_LISTED + 4 <= SHEET_ROWS);

/// Add hop: the hop after the last of the route being edited beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddHop {
    /// The peer the route goes to, beside whom it can end, and their
    /// address.
    pub peer: PeerId,
    pub address: String<44>,
    /// What the rows are narrowed by, as it is typed.
    pub find: String<16>,
    /// The top of the listing was asked for, and focus goes to its first
    /// row when it comes.
    pub landing: bool,
}

/// A row of Add hop, from the top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickRow {
    /// The field, while text is typed: Enter adds the row under it.
    Field,
    /// Who reported the repeaters under it, and when.
    Heard,
    /// The repeater at this place in the listing.
    Neighbor(u8),
    /// That the router listed nobody, or did not answer.
    Said,
    More,
    Refresh,
    /// The label over the known repeaters.
    Known,
    /// The known repeater at this place of the node's last gathering,
    /// and its router hint.
    KnownAt(u8, [u8; 2]),
    /// The label over the router hints typed text fixes.
    Hints,
    Hint(u8),
}

/// Add hop's rows, as they stand: the field while text is typed, then what
/// the last hop reports hearing, the peer first, known repeaters, and the
/// router hints typed text fixes, each narrowed by what is typed. Past [`SHEET_ROWS`], the last
/// are left out.
#[derive(Clone)]
pub struct PickRows {
    pub listing: Option<Listing>,
    pub hints: heapless::Vec<HintRead, MAX_HINT_READS>,
    /// The peer's place in the listing, whose row is pinned to the top.
    pub peer_at: Option<u8>,
    /// How many rows match what is typed; `None` while nothing is.
    pub found: Option<usize>,
    rows: heapless::Vec<PickRow, SHEET_ROWS>,
    /// The rows already on the route, by place: focus passes over them.
    in_path: u32,
}

impl PickRows {
    #[must_use]
    pub fn row(&self, index: usize) -> Option<PickRow> {
        self.rows.get(index).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Whether the row at `index` is already on the route.
    #[must_use]
    pub fn in_path(&self, index: usize) -> bool {
        index < 32 && self.in_path & (1 << index) != 0
    }

    /// The row at `index`'s key, and whether focus lands on it: never on
    /// a row already on the route, which a press would not add.
    #[must_use]
    pub fn key(&self, index: usize) -> (FocusKey, bool) {
        if self.in_path(index) {
            return (keys::sheet(index), false);
        }
        match self.row(index) {
            Some(PickRow::Field) => (keys::PICK_FIELD, true),
            Some(PickRow::Neighbor(at)) => (keys::neighbor(usize::from(at)), true),
            Some(PickRow::More) => (keys::NEIGHBORS_MORE, true),
            Some(PickRow::Refresh) => (keys::NEIGHBORS_REFRESH, true),
            Some(PickRow::KnownAt(_, hint)) => (keys::known(hint), true),
            Some(PickRow::Hint(at)) => (keys::hint_read(usize::from(at)), true),
            _ => (keys::sheet(index), false),
        }
    }

    /// The first row focus lands on.
    #[must_use]
    pub fn first_key(&self) -> Option<FocusKey> {
        (0..self.len())
            .map(|index| self.key(index))
            .find(|&(_, focusable)| focusable)
            .map(|(key, _)| key)
    }

    /// Where the row with `key` is now, given that it was at `index`.
    #[must_use]
    pub fn place(&self, index: usize, key: FocusKey) -> Option<usize> {
        if self.key(index).0 == key {
            return Some(index);
        }
        (0..self.len()).find(|&at| self.key(at).0 == key)
    }

    /// The top row past the field, which Enter in it adds.
    #[must_use]
    pub fn top(&self) -> Option<usize> {
        (0..self.len()).find(|&index| self.row(index) != Some(PickRow::Field) && self.key(index).1)
    }
}

/// What is open over the route editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditOver {
    /// A hop's menu: Move and Remove.
    Hop(u8),
    /// Leaving with changes: Save, Discard changes, or Keep editing.
    Leave,
}

impl RouteDraft {
    /// A draft of `hints`, flooding `flood` past them.
    #[must_use]
    pub fn new(hints: &[[u8; 2]], flood: u8) -> Self {
        let mut draft = Self {
            hints: [[0; 2]; MAX_PATH],
            len: 0,
            flood: flood.min(MAX_FLOOD),
            hold: HOLD_DEFAULT,
            lifted: None,
            adjusting: None,
            over: None,
            dirty: false,
            pinged: false,
        };
        for &hint in hints.iter().take(MAX_PATH) {
            draft.hints[usize::from(draft.len)] = hint;
            draft.len += 1;
        }
        draft
    }

    /// Its hops, the one nearest this device first.
    #[must_use]
    pub fn hints(&self) -> &[[u8; 2]] {
        &self.hints[..usize::from(self.len)]
    }

    /// The editor's row at `index`.
    #[must_use]
    pub fn row(&self, index: usize) -> Option<EditRow> {
        let hops = usize::from(self.len);
        let add = usize::from(self.has_room());
        Some(match index {
            0 => EditRow::You,
            i if i <= hops => EditRow::Hop(i - 1),
            i if i <= hops + add => EditRow::Add,
            i => match i - hops - add {
                1 => EditRow::Flood,
                2 => EditRow::Peer,
                3 => EditRow::Ping,
                4 => EditRow::Hold,
                5 => EditRow::Save,
                _ => return None,
            },
        })
    }

    /// How many rows the editor has.
    #[must_use]
    pub fn rows(&self) -> usize {
        usize::from(self.len) + usize::from(self.has_room()) + 6
    }

    /// It can take another hop.
    #[must_use]
    pub fn has_room(&self) -> bool {
        usize::from(self.len) < MAX_PATH
    }

    /// Adds `hint` after the last hop.
    fn push(&mut self, hint: [u8; 2]) {
        if self.has_room() {
            self.hints[usize::from(self.len)] = hint;
            self.len += 1;
            self.changed();
        }
    }

    /// How long it is to be held, in milliseconds.
    #[must_use]
    pub fn hold_ms(&self) -> u32 {
        HOLD_CHOICES[usize::from(self.hold).min(HOLD_CHOICES.len() - 1)]
    }

    /// Puts a lifted hop down where it is, returning where that is.
    fn put_down(&mut self) -> Option<u8> {
        let (now, from) = self.lifted.take()?;
        if now != from {
            self.changed();
        }
        Some(now)
    }

    /// It changed: what was pinged along it no longer is it.
    fn changed(&mut self) {
        self.dirty = true;
        self.pinged = false;
    }

    /// Takes the hop at `index` out.
    fn remove(&mut self, index: usize) {
        let len = usize::from(self.len);
        if index >= len {
            return;
        }
        self.hints.copy_within(index + 1..len, index);
        self.len -= 1;
        self.changed();
    }

    /// Moves the hop at `from` to `to`, the others closing up around it.
    fn shift(&mut self, from: usize, to: usize) {
        let len = usize::from(self.len);
        if from >= len || to >= len || from == to {
            return;
        }
        if from < to {
            self.hints[from..=to].rotate_left(1);
        } else {
            self.hints[to..=from].rotate_right(1);
        }
    }
}

impl Screen {
    /// The Chats screen, its list focused.
    #[must_use]
    pub fn chats() -> Self {
        Self::Chats {
            focus: FocusState::new(),
            row: None,
            find: None,
            confirm: None,
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
            | Self::Route { focus, .. }
            | Self::Neighbors { focus, .. }
            | Self::Ping { focus, .. }
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

    /// The saved peer this is one of the screens of.
    #[must_use]
    pub fn peer(&self) -> Option<PeerId> {
        match self {
            Self::Peer { peer, .. }
            | Self::ShareContact { peer, .. }
            | Self::Route { peer, .. }
            | Self::Ping { peer, .. }
            | Self::Neighbors {
                pick: Some(AddHop { peer, .. }),
                ..
            } => Some(*peer),
            _ => None,
        }
    }

    /// The unknown repeaters this screen has asked who they are.
    fn asked(&self) -> Option<&Asked> {
        match self {
            Self::Details { asked, .. }
            | Self::Route { asked, .. }
            | Self::Neighbors { asked, .. }
            | Self::Ping { asked, .. } => Some(asked),
            _ => None,
        }
    }

    fn asked_mut(&mut self) -> Option<&mut Asked> {
        match self {
            Self::Details { asked, .. }
            | Self::Route { asked, .. }
            | Self::Neighbors { asked, .. }
            | Self::Ping { asked, .. } => Some(asked),
            _ => None,
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
            | Self::Route { focus, .. }
            | Self::Neighbors { focus, .. }
            | Self::Ping { focus, .. }
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
                Section::Chats => self.node.chat_at(0).map(keys::chat),
                Section::Peers => Some(keys::ADD_PEER),
                Section::Device => Some(keys::IDENTITY),
            })
    }

    /// Whether `row` is a row of the list shown.
    fn lists(&self, row: FocusKey) -> bool {
        match self.section {
            Section::Chats => keys::chat_of(row).is_some_and(|chat| self.node.chat(chat).is_some()),
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
        let chats = (0..self.node.chat_count())
            .filter_map(|index| self.node.chat(self.node.chat_at(index)?));
        for chat in chats {
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
                    age: self.age(&chat),
                });
            }
        }
        for peer in (0..self.peer_count()).filter_map(|index| self.peer_at(index)) {
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
        if !self.keep_chat(chat) || self.screens.is_full() {
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
        self.refresh_learned_route(false);
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
        self.room_for_screen();
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
        let Some(first) = self.node.chat_at(0) else {
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
        if self.must_certify(chat) {
            // Asked where it would go, as a message typed there would be.
            self.go_to_chat(chat);
            self.ask_certify(Certified::Contact(peer));
            return;
        }
        if self.send_contact_to(chat, peer) {
            self.go_to_chat(chat);
        }
    }

    /// Sends the contact of `peer` to `chat`. Returns whether it went.
    fn send_contact_to(&mut self, chat: ChatId, peer: PeerId) -> bool {
        self.keep_chat(chat);
        let Some(index) = self.chats.iter().position(|c| c.id == chat) else {
            return false;
        };
        let Some(link) = self.node.contact_uri(peer) else {
            return false;
        };
        let forward_secret = self.chats[index].forward_secret;
        let Some(message) = self.node.send(chat, &link, None, forward_secret) else {
            return false;
        };
        let mut summary = self.chats.remove(index);
        summary.preview(&message);
        summary.last_activity = message.time;
        _ = self.chats.insert(0, summary);
        self.chime(Cue::Sent);
        true
    }

    /// Whether anything going on the air in `chat` waits on the warning
    /// first: it is `EMERGENCY`, and the warning has not been certified
    /// since the device started.
    pub(crate) fn must_certify(&self, chat: ChatId) -> bool {
        !self.emergency_certified
            && self.chat(chat).is_some_and(|summary| {
                matches!(
                    summary.kind,
                    ChatKind::Channel {
                        access: ChannelAccess::Clear
                    }
                )
            })
    }

    /// Opens the warning over the conversation shown, Cancel focused, with
    /// `then` waiting on it.
    pub(crate) fn ask_certify(&mut self, then: Certified) {
        if let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() {
            *unsent = Some(Unsent::CertifyEmergency { then });
            focus.request(keys::EMERGENCY_CANCEL);
        }
    }

    /// Certifies the warning, and does what waited on it. Nothing asks
    /// again until the device restarts.
    pub fn certify_emergency(&mut self) {
        let Some(Screen::Conversation {
            chat,
            unsent,
            focus,
            ..
        }) = self.screens.last_mut()
        else {
            return;
        };
        let Some(Unsent::CertifyEmergency { then }) = *unsent else {
            return;
        };
        let chat = *chat;
        *unsent = None;
        focus.request(match then {
            Certified::Draft | Certified::Contact(_) => keys::COMPOSER,
            Certified::React(message, _)
            | Certified::Retry(message)
            | Certified::Delete(message)
            | Certified::Repair(message) => keys::message(message),
        });
        self.emergency_certified = true;
        match then {
            Certified::Draft => self.send(chat),
            Certified::Contact(peer) => _ = self.send_contact_to(chat, peer),
            Certified::React(message, reaction) => self.react(message, reaction),
            Certified::Retry(message) => self.retry(message),
            Certified::Delete(message) => self.node.delete_message(chat, message),
            Certified::Repair(message) => self.ask_for_missing(message),
        }
    }

    /// Turns the warning down: closes it. One over a draft or a contact
    /// leaves the conversation, the draft kept; one over a message goes
    /// back to the message. Returns `false`, doing nothing, when the
    /// warning is not open.
    pub fn decline_emergency(&mut self) -> bool {
        let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() else {
            return false;
        };
        let Some(Unsent::CertifyEmergency { then }) = *unsent else {
            return false;
        };
        *unsent = None;
        match then {
            Certified::Draft | Certified::Contact(_) => self.back(),
            Certified::React(message, _)
            | Certified::Retry(message)
            | Certified::Delete(message)
            | Certified::Repair(message) => {
                focus.request(keys::message(message));
                true
            }
        }
    }

    /// Whether something is under way over the conversation shown that an
    /// offer opening now would cut into: a menu, a card other than the
    /// learned route's offer, the picker, the wheel or a finger down, or
    /// the lock screen.
    pub(crate) fn conversation_busy(&self) -> bool {
        matches!(
            self.screens.last(),
            Some(Screen::Conversation { actions, unsent, .. })
                if actions.is_some()
                    || unsent.is_some_and(|over| over != Unsent::Learned)
                    || self.picker.is_some()
                    || self.press.is_some()
                    || self.touch.is_some()
                    || self.lock.locked
        )
    }

    /// Offers the route learned while the peer's was held by hand, over the
    /// conversation with them, once it is time to and nothing is under way
    /// there; and takes the offer back once it is no longer made. One that
    /// comes `unasked`, while the conversation is in use, waits while a
    /// draft or a reply is being written, or the composer is taken up to
    /// write one: the next key meant for it would answer the offer.
    pub(crate) fn refresh_learned_route(&mut self, unasked: bool) {
        let node = self.node;
        let Some(&Screen::Conversation { chat, reply, .. }) = self.screens.last() else {
            return;
        };
        let writing = unasked
            && (reply.is_some()
                || self.keyboard.editing()
                || self
                    .chats
                    .iter()
                    .find(|summary| summary.id == chat)
                    .is_some_and(|summary| !summary.draft.text().is_empty()));
        let busy = self.conversation_busy();
        let Some(Screen::Conversation { unsent, focus, .. }) = self.screens.last_mut() else {
            return;
        };
        let offered = node
            .chat_peer(chat)
            .is_some_and(|peer| node.learned_route(peer).is_some());
        match *unsent {
            None if offered && !busy && !writing => {
                *unsent = Some(Unsent::Learned);
                focus.request(keys::LEARNED_USE);
            }
            Some(Unsent::Learned) if !offered => {
                *unsent = None;
                focus.request(keys::COMPOSER);
            }
            _ => {}
        }
    }

    /// `key`, or the composer in its place when `key` is one of the learned
    /// route's choices and the offer is no longer open.
    pub(crate) fn still_offered(&self, key: FocusKey) -> FocusKey {
        let offer = key == keys::LEARNED_USE || key == keys::LEARNED_KEEP;
        let open = matches!(
            self.screens.last(),
            Some(Screen::Conversation {
                unsent: Some(Unsent::Learned),
                ..
            })
        );
        if offer && !open { keys::COMPOSER } else { key }
    }

    /// Switches to the learned route offered over the conversation.
    pub fn use_learned_route(&mut self) {
        if let Some(peer) = self.close_learned_route() {
            self.node.adopt_learned_route(peer);
        }
    }

    /// Keeps the route held by hand that the offer over the conversation
    /// would replace, and asks no more until it is held again. Returns
    /// whether the offer was open.
    pub fn keep_manual_route(&mut self) -> bool {
        let Some(peer) = self.close_learned_route() else {
            return false;
        };
        self.node.keep_manual_route(peer);
        true
    }

    /// Closes the learned route's offer, returning to the composer. Returns
    /// the peer it was made for, if it was open.
    fn close_learned_route(&mut self) -> Option<PeerId> {
        let node = self.node;
        let Some(Screen::Conversation {
            chat,
            unsent,
            focus,
            ..
        }) = self.screens.last_mut()
        else {
            return None;
        };
        if *unsent != Some(Unsent::Learned) {
            return None;
        }
        *unsent = None;
        focus.request(keys::COMPOSER);
        node.chat_peer(*chat)
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

    /// Shows the saved peer `peer`, Message focused, reading their route
    /// again.
    pub fn open_peer(&mut self, peer: PeerId) {
        if self.peer(peer).is_none() {
            return;
        }
        self.node.load_route(peer);
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

    /// Reads the saved peers open from the node again.
    pub(crate) fn refresh_peer(&mut self) {
        let node = self.node;
        for screen in &mut self.screens {
            if let Screen::Peer { peer, detail, .. } = screen
                && let Some(fresh) = node.peer_detail(*peer)
            {
                *detail = fresh;
            }
        }
    }

    /// Notes the pings open that the node says have settled: those to
    /// `peer`, or all of them when `peer` is `None`. One that has just
    /// settled is marked as settled now, and Ping again is focused.
    pub(crate) fn refresh_ping(&mut self, peer: Option<PeerId>) {
        let node = self.node;
        let uptime = self.uptime;
        for screen in &mut self.screens {
            if let Screen::Ping {
                peer: shown,
                settled_at,
                focus,
                ..
            } = screen
                && peer.is_none_or(|peer| peer == *shown)
                && settled_at.is_none()
                && !matches!(node.ping_view(*shown), None | Some(PingView::Waiting))
            {
                *settled_at = Some(uptime);
                focus.request(keys::PING_AGAIN);
            }
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
            self.node.sort_peers();
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

    /// Shows the route to the saved peer shown, reading it again.
    pub fn open_route(&mut self) {
        let Some(peer) = self.shown_peer() else {
            return;
        };
        self.node.load_route(peer);
        _ = self.screens.push(Screen::Route {
            peer,
            edit: None,
            asked: Asked::new(),
            focus: FocusState::new(),
        });
    }

    /// Forgets the route shown, so that the next message floods.
    pub fn reset_route(&mut self) {
        if let Some(&Screen::Route { peer, .. }) = self.screens.last() {
            self.node.reset_route(peer);
        }
    }

    /// The route being chosen on the Route screen shown.
    #[must_use]
    pub fn route_draft(&self) -> Option<&RouteDraft> {
        match self.screens.last() {
            Some(Screen::Route {
                edit: Some(draft), ..
            }) => Some(draft),
            _ => None,
        }
    }

    fn route_draft_mut(&mut self) -> Option<(&mut RouteDraft, &mut FocusState)> {
        match self.screens.last_mut() {
            Some(Screen::Route {
                edit: Some(draft),
                focus,
                ..
            }) => Some((draft, focus)),
            _ => None,
        }
    }

    /// Turns the Route screen shown into its editor, starting from the
    /// route shown: its repeaters when it names them, else none, and how
    /// far it floods past them when it was chosen by hand.
    pub fn edit_route(&mut self) {
        let Some(&Screen::Route {
            peer, edit: None, ..
        }) = self.screens.last()
        else {
            return;
        };
        let route = self.node.peer_route(peer);
        let hints: heapless::Vec<[u8; 2], MAX_PATH> = match &route {
            Some(route) if route.kind == RouteKind::Source => {
                route.repeaters.iter().map(|r| r.hint).collect()
            }
            _ => heapless::Vec::new(),
        };
        let flood = route
            .as_ref()
            .and_then(|route| route.manual.as_ref())
            .map_or(u8::from(!hints.is_empty()), |manual| manual.flood_hops);
        if let Some(Screen::Route { edit, focus, .. }) = self.screens.last_mut() {
            *edit = Some(RouteDraft::new(&hints, flood));
            focus.request(if hints.is_empty() {
                keys::ROUTE_FLOOD
            } else {
                keys::path(0)
            });
        }
    }

    /// A hop of the route being chosen was pressed: a lifted one is put
    /// down where it is, and any other opens its menu.
    pub fn press_hop(&mut self, index: usize) {
        let Some((draft, focus)) = self.route_draft_mut() else {
            return;
        };
        if let Some(now) = draft.put_down() {
            focus.request(keys::path(usize::from(now)));
            return;
        }
        if index < draft.hints().len() {
            draft.adjusting = None;
            draft.over = Some(EditOver::Hop(index as u8));
            focus.request(keys::HOP_MOVE);
        }
    }

    /// The hop whose menu is open is lifted: turning carries it.
    pub fn move_hop(&mut self) {
        let Some((draft, focus)) = self.route_draft_mut() else {
            return;
        };
        if let Some(EditOver::Hop(index)) = draft.over.take() {
            draft.lifted = Some((index, index));
            focus.request(keys::path(usize::from(index)));
        }
    }

    /// The hop whose menu is open is taken out of the route.
    pub fn remove_hop(&mut self) {
        let Some((draft, focus)) = self.route_draft_mut() else {
            return;
        };
        if let Some(EditOver::Hop(index)) = draft.over.take() {
            let index = usize::from(index);
            draft.remove(index);
            let left = draft.hints().len();
            focus.request(if left == 0 {
                keys::ROUTE_FLOOD
            } else {
                keys::path(index.min(left - 1))
            });
        }
    }

    /// Closes what is open over the editor, back to what opened it.
    pub fn close_route_over(&mut self) {
        let Some((draft, focus)) = self.route_draft_mut() else {
            return;
        };
        match draft.over.take() {
            Some(EditOver::Hop(index)) => focus.request(keys::path(usize::from(index))),
            Some(EditOver::Leave) => focus.request(keys::ROUTE_SAVE),
            None => {}
        }
    }

    /// Then flood was pressed: turning starts or stops changing it.
    pub fn press_flood(&mut self) {
        self.press_adjust(Adjust::Flood);
    }

    /// Hold for was pressed: turning starts or stops changing it.
    pub fn press_hold(&mut self) {
        self.press_adjust(Adjust::Hold);
    }

    fn press_adjust(&mut self, what: Adjust) {
        if let Some((draft, _)) = self.route_draft_mut() {
            // A tap can reach the row with a hop still lifted.
            draft.put_down();
            draft.adjusting = if draft.adjusting == Some(what) {
                None
            } else {
                Some(what)
            };
        }
    }

    /// Which value of the route being chosen turning changes: it was
    /// pressed, and is still focused.
    #[must_use]
    pub fn adjusting_route(&self) -> Option<Adjust> {
        let Some(Screen::Route {
            edit: Some(draft),
            focus,
            ..
        }) = self.screens.last()
        else {
            return None;
        };
        let key = match draft.adjusting? {
            Adjust::Flood => keys::ROUTE_FLOOD,
            Adjust::Hold => keys::ROUTE_HOLD,
        };
        draft.adjusting.filter(|_| focus.current() == Some(key))
    }

    /// The wheel turned `detents` in the route editor: carries a lifted
    /// hop, turned down toward the peer, or changes the value being
    /// changed, turned up for more. Returns whether it did either.
    pub fn turn_route_edit(&mut self, detents: i8) -> bool {
        let adjusting = self.adjusting_route();
        let Some((draft, focus)) = self.route_draft_mut() else {
            return false;
        };
        if let Some((now, from)) = draft.lifted {
            let last = draft.hints().len().saturating_sub(1);
            let to = (usize::from(now) as isize + isize::from(detents)).clamp(0, last as isize);
            let to = to as usize;
            draft.shift(usize::from(now), to);
            draft.lifted = Some((to as u8, from));
            focus.request(keys::path(to));
            return true;
        }
        let up = i16::from(detents.saturating_neg());
        match adjusting {
            Some(Adjust::Flood) => {
                let flood = (i16::from(draft.flood) + up).clamp(0, i16::from(MAX_FLOOD)) as u8;
                if flood != draft.flood {
                    draft.flood = flood;
                    draft.changed();
                }
                true
            }
            Some(Adjust::Hold) => {
                let last = HOLD_CHOICES.len() as i16 - 1;
                let hold = (i16::from(draft.hold) + up).clamp(0, last) as u8;
                if hold != draft.hold {
                    draft.hold = hold;
                    draft.dirty = true;
                }
                true
            }
            None => false,
        }
    }

    /// Backspace in the route editor: closes what is open over it, puts a
    /// lifted hop back where it was, stops a value changing, asks what to
    /// do with changes, or else leaves the editor for the route.
    pub fn route_edit_back(&mut self) {
        let Some((draft, focus)) = self.route_draft_mut() else {
            return;
        };
        if draft.over.is_some() {
            self.close_route_over();
        } else if let Some((now, from)) = draft.lifted.take() {
            draft.shift(usize::from(now), usize::from(from));
            focus.request(keys::path(usize::from(from)));
        } else if draft.adjusting.is_some() {
            draft.adjusting = None;
        } else if draft.dirty {
            draft.over = Some(EditOver::Leave);
            focus.request(keys::LEAVE_SAVE);
        } else {
            self.discard_route();
        }
    }

    /// Leaves the route editor without saving.
    pub fn discard_route(&mut self) {
        if let Some(Screen::Route { edit, focus, .. }) = self.screens.last_mut()
            && edit.take().is_some()
        {
            focus.request(keys::ROUTE_EDIT);
        }
    }

    /// Holds the route being chosen and leaves the editor.
    pub fn save_route(&mut self) {
        if let Some((draft, _)) = self.route_draft_mut() {
            draft.put_down();
        }
        let Some(&Screen::Route {
            peer,
            edit: Some(draft),
            ..
        }) = self.screens.last()
        else {
            return;
        };
        self.node
            .hold_route(peer, draft.hints(), draft.flood, draft.hold_ms());
        self.discard_route();
    }

    /// Pings the peer along the route being chosen, unsaved, and shows how
    /// it goes.
    pub fn ping_along(&mut self) {
        if let Some((draft, _)) = self.route_draft_mut() {
            draft.put_down();
        }
        let Some(&Screen::Route {
            peer,
            edit: Some(draft),
            ..
        }) = self.screens.last()
        else {
            return;
        };
        if let Some((draft, _)) = self.route_draft_mut() {
            draft.adjusting = None;
            draft.pinged = true;
        }
        self.node.ping_along(peer, draft.hints(), draft.flood);
        self.show_ping(peer);
    }

    /// Pings the saved peer shown, or whose route is shown, and shows how
    /// it goes.
    pub fn open_ping(&mut self) {
        let Some(peer) = self.screens.last().and_then(Screen::peer) else {
            return;
        };
        self.node.ping(peer);
        self.show_ping(peer);
    }

    /// Shows the ping to `peer` just sent.
    fn show_ping(&mut self, peer: PeerId) {
        _ = self.screens.push(Screen::Ping {
            peer,
            sent_at: self.uptime,
            settled_at: None,
            earlier: heapless::Vec::new(),
            asked: Asked::new(),
            focus: FocusState::new(),
        });
    }

    /// Pings the peer of the Ping screen again, listing the ping before
    /// among the earlier ones.
    pub fn ping_again(&mut self) {
        let uptime = self.uptime;
        let node = self.node;
        // Opened from the route editor, it pings along the route there.
        let along = match self.screens.len().checked_sub(2).map(|i| &self.screens[i]) {
            Some(&Screen::Route {
                edit: Some(draft), ..
            }) => Some(draft),
            _ => None,
        };
        let Some(Screen::Ping {
            peer,
            sent_at,
            settled_at,
            earlier,
            asked,
            ..
        }) = self.screens.last_mut()
        else {
            return;
        };
        let Some(at) = settled_at.take() else {
            return;
        };
        let (round_trip_ms, hops) = match node.ping_view(*peer) {
            Some(PingView::Reply(reply)) => (Some(reply.round_trip_ms), reply.hops),
            _ => (None, None),
        };
        if earlier.is_full() {
            earlier.pop();
        }
        _ = earlier.insert(
            0,
            PingSummary {
                round_trip_ms,
                hops,
                at,
            },
        );
        asked.clear();
        *sent_at = uptime;
        match along {
            Some(draft) => node.ping_along(*peer, draft.hints(), draft.flood),
            None => node.ping(*peer),
        }
    }

    /// How long the ping shown has been waiting for an answer.
    #[must_use]
    pub fn ping_elapsed(&self) -> Option<u64> {
        match self.screens.last() {
            Some(&Screen::Ping {
                sent_at,
                settled_at: None,
                ..
            }) => Some(self.uptime.saturating_sub(sent_at)),
            _ => None,
        }
    }

    /// How long ago an earlier ping settled.
    #[must_use]
    pub fn since(&self, at: u64) -> u64 {
        self.uptime.saturating_sub(at)
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
        let Some(index) =
            (0..self.node.peer_count()).find(|&index| self.node.peer_at(index) == Some(peer))
        else {
            return;
        };
        self.node.sort_peers();
        let next = self
            .node
            .peer_at(index)
            .or_else(|| self.node.peer_at(self.node.peer_count().checked_sub(1)?))
            .map_or(keys::ADD_PEER, keys::peer);
        // Its screens close, from its route or a ping on down, any route
        // being chosen with them.
        let mut left = false;
        while self.screen().peer() == Some(peer) && self.leave() {
            left = true;
        }
        if left {
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

    pub fn toggle_share_location(&mut self) {
        if let Some(on) = self.node.share_location() {
            self.node.set_share_location(!on);
        }
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
        let seconds = self.node.auto_lock();
        let current = AUTO_LOCK_CHOICES
            .iter()
            .position(|&c| c == seconds)
            .unwrap_or(0);
        _ = self.screens.push(Screen::Device {
            page: DevicePage::AutoLock,
            focus: FocusState::requesting(keys::auto_lock_choice(current)),
        });
    }

    /// Shows the gamma chart. Any change of brightness under way ends.
    pub fn open_gamma(&mut self) {
        if let Some(adjusting) = self.adjusting_mut() {
            *adjusting = false;
        }
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Gamma {
                test: GammaTest::new(),
            },
            focus: FocusState::requesting(keys::GAMMA_CHART),
        });
    }

    fn gamma_mut(&mut self) -> Option<&mut GammaTest> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::Gamma { test },
                ..
            }) => Some(test),
            _ => None,
        }
    }

    /// The gamma chart was pressed: its next field is shown.
    pub fn next_gamma_field(&mut self) {
        if let Some(test) = self.gamma_mut() {
            *test = test.next_field();
        }
    }

    /// The wheel turned `detents` while the gamma chart is shown: its
    /// square changes, turned up lightening, and returns whether it did.
    pub fn turn_gamma(&mut self, detents: i8) -> bool {
        let Some(test) = self.gamma_mut() else {
            return false;
        };
        *test = test.step(detents.saturating_neg());
        true
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
        node.wifi(&mut self.wifi);
        for screen in &mut self.screens {
            match screen {
                Screen::Device {
                    page: DevicePage::Radio { settings } | DevicePage::Lora { settings },
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

    /// Steps Forwarding to its next setting.
    pub fn step_forwarding(&mut self) {
        if let Some(settings) = self.shown_radio() {
            self.node.set_forwarding(settings.forwarding.next());
            self.refresh_settings();
        }
    }

    /// Opens Transmit power, its field being edited: a number already in
    /// it is there to be changed, so Backspace erases.
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
        self.edit_opened = true;
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

    /// Sets the transmit power typed, and returns to LoRa. A power the
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

    /// Shows the directions the trackball acts in.
    pub fn open_trackball(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Trackball,
            focus: FocusState::requesting(keys::TRACKBALL_VERTICAL),
        });
    }

    /// Turns rolling up and down on, or off.
    #[cfg(feature = "directional")]
    pub fn toggle_trackball_vertical(&mut self) {
        let directions = self.node.directions().toggled(Directions::VERTICAL);
        self.node.set_directions(directions);
    }

    /// Turns rolling left and right on, or off.
    #[cfg(feature = "directional")]
    pub fn toggle_trackball_horizontal(&mut self) {
        let directions = self.node.directions().toggled(Directions::HORIZONTAL);
        self.node.set_directions(directions);
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

    /// Records the keyboard light as the keyboard itself switched it.
    pub fn set_keyboard_light(&mut self, lit: bool) {
        if self.node.keyboard().light != lit {
            self.change_keyboard(|s| s.light = lit);
        }
    }

    /// Opens the LoRa settings, at their Profile.
    pub fn open_lora(&mut self) {
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Lora {
                settings: self.node.radio(),
            },
            focus: FocusState::requesting(keys::PROFILE),
        });
    }

    /// Opens Frequency, its field being edited, in kHz: a number already
    /// in it is there to be changed, so Backspace erases.
    pub fn open_frequency(&mut self) {
        let mut text = FrequencyText::default();
        let mut khz: String<8> = String::new();
        _ = core::fmt::write(
            &mut khz,
            format_args!("{}", self.node.radio().frequency_khz),
        );
        for c in khz.chars() {
            text.insert(c);
        }
        _ = self.screens.push(Screen::Device {
            page: DevicePage::Frequency { text },
            focus: FocusState::requesting(keys::FREQUENCY_FIELD),
        });
        self.edit_opened = true;
    }

    pub fn frequency_text_mut(&mut self) -> Option<&mut FrequencyText> {
        match self.screens.last_mut() {
            Some(Screen::Device {
                page: DevicePage::Frequency { text },
                ..
            }) => Some(text),
            _ => None,
        }
    }

    /// Sets the frequency typed, and returns to LoRa. What is not a
    /// frequency leaves the field as it is, to be corrected; one the radio
    /// cannot tune to the device refuses.
    pub fn submit_frequency(&mut self) {
        let Some(khz) = self
            .frequency_text_mut()
            .and_then(|text| text.text().trim().parse::<u32>().ok())
            .filter(|&khz| khz > 0)
        else {
            return;
        };
        self.node.set_frequency(khz);
        self.back();
        self.refresh_settings();
    }

    /// Shows the values `choice` can be set to, the radio's own focused.
    pub fn open_lora_choice(&mut self, choice: LoraChoice) {
        let current = choice.position(&self.node.radio()).unwrap_or(0);
        _ = self.screens.push(Screen::Device {
            page: DevicePage::LoraChoice { choice },
            focus: FocusState::requesting(keys::lora_choice(current)),
        });
    }

    /// Sets `choice` to its value at `index`, and returns to LoRa.
    pub fn choose_lora(&mut self, choice: LoraChoice, index: usize) {
        let node = self.node;
        let set = match choice {
            LoraChoice::Bandwidth => BANDWIDTHS.get(index).map(|&(hz, _)| node.set_bandwidth(hz)),
            LoraChoice::SpreadingFactor => SPREADING_FACTORS
                .get(index)
                .map(|&(sf, _)| node.set_spreading_factor(sf)),
            LoraChoice::CodingRate => CODING_RATES
                .get(index)
                .map(|&(cr, _)| node.set_coding_rate(cr)),
            LoraChoice::TransmitLimit => TRANSMIT_LIMITS
                .get(index)
                .map(|&(limit, _)| node.set_transmit_limit(limit)),
        };
        if set.is_some() {
            self.back();
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

    /// Ends first run, the device now set up: says so, Add peer next.
    pub(crate) fn finish_setup(&mut self) {
        self.node.set_setup_complete(true);
        self.screens.truncate(1);
        _ = self.screens.push(Screen::Setup {
            page: SetupPage::Done,
            focus: FocusState::requesting(keys::CONTINUE),
        });
    }

    /// Leaves first run's last page for Add peer, over the Peers list.
    pub fn add_peers_after_setup(&mut self) {
        self.screens.truncate(1);
        self.section = Section::Peers;
        self.focus().request(keys::ADD_PEER);
        self.open_add_peer();
    }

    /// Leaves first run's last page for the Chats list.
    pub fn leave_setup(&mut self) {
        self.screens.truncate(1);
        self.focus_list();
    }

    /// Shows the joined channels, Add channel focused.
    /// Asks the Device list to confirm `asked`, with `key` focused, or
    /// stops asking and focuses `key`.
    fn device_confirm(&mut self, asked: Option<DeviceConfirm>, key: FocusKey) {
        if let Some(Screen::Chats { confirm, focus, .. }) = self.screens.last_mut() {
            *confirm = asked;
            focus.request(key);
        }
    }

    /// Asks to confirm turning the board off.
    pub fn ask_shut_down(&mut self) {
        self.device_confirm(Some(DeviceConfirm::ShutDown), keys::SHUT_DOWN_CANCEL);
    }

    /// Keeps the board on after all.
    pub fn cancel_shut_down(&mut self) {
        self.device_confirm(None, keys::SHUT_DOWN);
    }

    /// Turns the board off, confirmed: the screen says so, and the board,
    /// finding [`State::ending`] set by an input, does it.
    pub fn shut_down(&mut self) {
        if let Some(Screen::Chats { confirm, .. }) = self.screens.last_mut() {
            *confirm = None;
        }
        self.shutting_down();
    }

    /// Asks to confirm erasing the device.
    pub fn ask_factory_reset(&mut self) {
        self.device_confirm(
            Some(DeviceConfirm::FactoryReset),
            keys::FACTORY_RESET_CANCEL,
        );
    }

    /// Confirmed once: asks again.
    pub fn confirm_factory_reset(&mut self) {
        self.device_confirm(Some(DeviceConfirm::Erase), keys::ERASE_CANCEL);
    }

    /// Keeps the device as it is after all.
    pub fn cancel_factory_reset(&mut self) {
        self.device_confirm(None, keys::FACTORY_RESET);
    }

    /// Erases the device, confirmed twice. It restarts as new.
    pub fn factory_reset(&mut self) {
        self.device_confirm(None, keys::FACTORY_RESET);
        self.node.factory_reset();
    }

    /// Asks to confirm restarting the device.
    pub fn ask_restart(&mut self) {
        self.device_confirm(Some(DeviceConfirm::Restart), keys::RESTART_CANCEL);
    }

    /// Keeps the device running after all.
    pub fn cancel_restart(&mut self) {
        self.device_confirm(None, keys::RESTART);
    }

    /// Restarts the device, confirmed. It comes back as it was.
    pub fn restart(&mut self) {
        self.device_confirm(None, keys::RESTART);
        self.node.restart();
    }

    /// Stops asking the Device list to confirm anything.
    pub fn cancel_device_confirm(&mut self) {
        match self.screen() {
            Screen::Chats {
                confirm: Some(DeviceConfirm::ShutDown),
                ..
            } => self.cancel_shut_down(),
            Screen::Chats {
                confirm: Some(DeviceConfirm::Restart),
                ..
            } => self.cancel_restart(),
            Screen::Chats {
                confirm: Some(_), ..
            } => self.cancel_factory_reset(),
            _ => {}
        }
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
        if !self.keep_chat(chat) {
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
        self.keep_chat(chat);
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

    /// Whether test messages on `EMERGENCY` call for attention.
    pub fn test_message_alerts(&self) -> bool {
        self.node.test_message_alerts()
    }

    /// Turns attention for test messages on `EMERGENCY` on or off.
    pub fn toggle_test_messages(&mut self) {
        let on = self.node.test_message_alerts();
        self.node.set_test_message_alerts(!on);
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
        self.node.watch_wifi(!self.lock.locked && self.wifi_shown());
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
            self.make_room();
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
        let Some(chat) = chat else {
            return;
        };
        if self.must_certify(chat) {
            self.ask_certify(Certified::Delete(message));
            return;
        }
        self.node.delete_message(chat, message);
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

    /// Makes room on a full stack for one more screen, by letting go of the
    /// one shown: a walk from node to node through their Neighbors would
    /// otherwise stop where the stack does. A conversation is kept.
    // Not `leave`: the screen pushed next is settled in its place, and
    // `leave`'s frame would sit on the deepest path the stack check walks.
    fn room_for_screen(&mut self) {
        if self.screens.is_full()
            && !matches!(self.screens.last(), Some(Screen::Conversation { .. }))
        {
            self.screens.pop();
        }
    }

    /// Shows what the node whose page is shown reports hearing, as last
    /// read: opening asks for nothing.
    pub fn open_neighbors(&mut self) {
        let router = match self.screens.last() {
            Some(Screen::Member { member, .. }) => member.address.clone(),
            Some(Screen::Peer { detail, .. }) => Some(detail.address.clone()),
            _ => None,
        };
        let Some(router) = router else {
            return;
        };
        let first = if self
            .node
            .listing(&router)
            .is_some_and(|listing| listing.count > 0)
        {
            keys::neighbor(0)
        } else {
            keys::NEIGHBORS_REFRESH
        };
        self.room_for_screen();
        _ = self.screens.push(Screen::Neighbors {
            router,
            pick: None,
            asked: Asked::new(),
            focus: FocusState::requesting(first),
        });
    }

    /// Presses the row at `index` of the route editor or of Neighbors,
    /// whichever is shown.
    pub fn press_sheet(&mut self, index: usize, key: FocusKey) {
        match self.screens.last() {
            Some(Screen::Route {
                edit: Some(draft), ..
            }) => match draft.row(index) {
                Some(EditRow::Hop(hop)) => self.press_hop(hop),
                Some(EditRow::Add) => self.add_hop(),
                Some(EditRow::Flood) => self.press_flood(),
                Some(EditRow::Ping) => self.ping_along(),
                Some(EditRow::Hold) => self.press_hold(),
                Some(EditRow::Save) => self.save_route(),
                Some(EditRow::You | EditRow::Peer) | None => {}
            },
            Some(Screen::Neighbors { pick: Some(_), .. }) => self.press_pick(index, key),
            Some(Screen::Neighbors { router, .. }) => {
                match listing_row(self.node.listing(router).as_ref(), index) {
                    Some(ListRow::Neighbor(at)) => self.press_neighbor(at),
                    Some(ListRow::More) => self.more_neighbors(),
                    Some(ListRow::Refresh) => self.refresh_neighbors(),
                    Some(ListRow::Read | ListRow::Said) | None => {}
                }
            }
            _ => {}
        }
    }

    /// Asks the router shown for the top of what it hears again.
    pub fn refresh_neighbors(&mut self) {
        self.ask_listing(false);
    }

    /// Asks the router shown for the page after the last one held.
    pub fn more_neighbors(&mut self) {
        self.ask_listing(true);
    }

    /// Asks the router shown for a page of what it hears, keeping the
    /// listings of every Neighbors screen open. Add hop asks along the
    /// route being edited, up to the router.
    fn ask_listing(&mut self, more: bool) {
        let along: Option<heapless::Vec<[u8; 2], MAX_PATH>> = self.pick_draft().map(|draft| {
            let hints = draft.hints();
            hints[..hints.len().saturating_sub(1)]
                .iter()
                .copied()
                .collect()
        });
        if let Some(Screen::Neighbors {
            pick: Some(pick), ..
        }) = self.screens.last_mut()
        {
            pick.landing |= !more;
        }
        let Some(Screen::Neighbors { router, .. }) = self.screens.last() else {
            return;
        };
        let shown: heapless::Vec<&str, MAX_SCREENS> = self
            .screens
            .iter()
            .filter_map(|screen| match screen {
                Screen::Neighbors { router, .. } => Some(router.as_str()),
                _ => None,
            })
            .collect();
        self.node
            .ask_listing(router, more, &shown, along.as_deref());
    }

    /// The route being edited beneath Add hop, while it is shown.
    #[must_use]
    pub fn pick_draft(&self) -> Option<&RouteDraft> {
        let Some(Screen::Neighbors { pick: Some(_), .. }) = self.screens.last() else {
            return None;
        };
        match self.screens.get(self.screens.len().checked_sub(2)?) {
            Some(Screen::Route {
                edit: Some(draft), ..
            }) => Some(draft),
            _ => None,
        }
    }

    /// Opens Add hop over the route editor shown, on what its last hop
    /// reports hearing, as last read; for the first hop, on what this
    /// device hears, read anew.
    pub fn add_hop(&mut self) {
        // A hop lifted, or a value being changed, is settled first, as a
        // press on any other row settles it.
        let Some((draft, _)) = self.route_draft_mut() else {
            return;
        };
        draft.put_down();
        draft.adjusting = None;
        let Some(&Screen::Route {
            peer,
            edit: Some(draft),
            ..
        }) = self.screens.last()
        else {
            return;
        };
        if !draft.has_room() {
            return;
        }
        let Some(detail) = self.node.peer_detail(peer) else {
            return;
        };
        let router = match draft.hints().last() {
            Some(&hint) => self.hop_address(hint),
            None => Some(self.node.address()),
        };
        self.room_beneath();
        self.show_pick(router.unwrap_or_default(), peer, detail.address, false);
    }

    /// Makes room on a full stack for a screen over the one shown, by
    /// letting go of the oldest screen between it and the Chats screen. A
    /// conversation is kept.
    fn room_beneath(&mut self) {
        if !self.screens.is_full() {
            return;
        }
        let shown = self.screens.len() - 1;
        if let Some(oldest) =
            (1..shown).find(|&at| !matches!(self.screens[at], Screen::Conversation { .. }))
        {
            self.screens.remove(oldest);
        }
    }

    /// The address of the node the hop `hint` most plausibly is.
    fn hop_address(&self, hint: [u8; 2]) -> Option<String<44>> {
        let repeater = self.node.repeater(hint)?;
        String::try_from(repeater.address?.as_str()).ok()
    }

    /// Shows Add hop on what the router at `router` reports hearing, in
    /// place of the one shown when `replace`. This device's own list is
    /// read anew, which sends nothing.
    fn show_pick(&mut self, router: String<44>, peer: PeerId, address: String<44>, replace: bool) {
        if replace {
            self.screens.pop();
        }
        let here = router == self.node.address();
        _ = self.screens.push(Screen::Neighbors {
            router,
            pick: Some(AddHop {
                peer,
                address,
                find: String::new(),
                landing: false,
            }),
            asked: Asked::new(),
            focus: FocusState::new(),
        });
        if here {
            self.ask_listing(false);
        }
        self.focus_top_pick();
    }

    /// Asks focus for Add hop's top row.
    fn focus_top_pick(&mut self) {
        if let Some(key) = self.pick_rows().and_then(|rows| rows.first_key()) {
            self.focus().request(key);
        }
    }

    /// Focus goes to the top of what Add hop's router reports hearing
    /// once the top of it has come.
    pub(crate) fn listing_landed(&mut self) {
        let node = self.node;
        let Some(Screen::Neighbors {
            router,
            pick: Some(pick),
            ..
        }) = self.screens.last_mut()
        else {
            return;
        };
        if !pick.landing
            || node
                .listing(router)
                .is_none_or(|listing| listing.asking.is_some())
        {
            return;
        }
        pick.landing = false;
        self.focus_top_pick();
    }

    /// Add hop's rows, while it is shown.
    #[must_use]
    pub fn pick_rows(&self) -> Option<PickRows> {
        let Some(Screen::Neighbors {
            router,
            pick: Some(pick),
            ..
        }) = self.screens.last()
        else {
            return None;
        };
        let node = self.node;
        let query = pick.find.trim();
        let finding = !query.is_empty();
        let heard = !router.is_empty();
        let listing = heard.then(|| node.listing(router)).flatten();
        let count = listing.map_or(0, |listing| usize::from(listing.count));
        let peer_at = heard
            .then(|| node.listed_place(router, &pick.address))
            .flatten()
            .filter(|&at| at < count);
        let hops = self.pick_draft().map_or(&[][..], RouteDraft::hints);
        let mut rows: heapless::Vec<PickRow, SHEET_ROWS> = heapless::Vec::new();
        let mut in_path = 0u32;
        let mut push =
            |rows: &mut heapless::Vec<PickRow, SHEET_ROWS>, row, hint: Option<[u8; 2]>| {
                if hint.is_some_and(|hint| hops.contains(&hint)) && rows.len() < 32 {
                    in_path |= 1 << rows.len();
                }
                _ = rows.push(row);
            };
        if finding {
            push(&mut rows, PickRow::Field, None);
        }
        let mut found = 0;
        if heard {
            push(&mut rows, PickRow::Heard, None);
            // The peer is pinned to the top, the rest as listed.
            for at in peer_at
                .into_iter()
                .chain((0..count).filter(|&at| Some(at) != peer_at))
            {
                let listed = node.listed(router, at);
                if finding
                    && listed
                        .as_ref()
                        .is_none_or(|listed| word_match(&listed.name, query).is_none())
                {
                    continue;
                }
                found += 1;
                // The peer is never a hop, whatever its hint.
                let hint = listed
                    .filter(|_| Some(at) != peer_at)
                    .map(|listed| listed.hint);
                push(&mut rows, PickRow::Neighbor(at as u8), hint);
            }
            if finding {
                if rows.last() == Some(&PickRow::Heard) {
                    rows.pop();
                }
            } else {
                for index in count + 1.. {
                    let row = match listing_row(listing.as_ref(), index) {
                        Some(ListRow::Said) => PickRow::Said,
                        Some(ListRow::More) => PickRow::More,
                        Some(ListRow::Refresh) => PickRow::Refresh,
                        _ => break,
                    };
                    push(&mut rows, row, None);
                }
            }
        }
        // Read by place as the rows are drawn, so that none of them is
        // held here.
        let mut known = 0;
        // The peer the route goes to is no hop on it.
        for at in 0..node.gather_known(query, router, &pick.address) {
            let Some(repeater) = node.known_repeater(at) else {
                continue;
            };
            if known == 0 {
                push(&mut rows, PickRow::Known, None);
            }
            known += 1;
            let hint = repeater.hint;
            push(&mut rows, PickRow::KnownAt(at as u8, hint), Some(hint));
        }
        let hints = if finding {
            node.hint_reads(query)
        } else {
            heapless::Vec::new()
        };
        if !hints.is_empty() {
            push(&mut rows, PickRow::Hints, None);
            for (at, read) in hints.iter().enumerate() {
                push(&mut rows, PickRow::Hint(at as u8), Some(read.hint));
            }
        }
        found += known + hints.len();
        Some(PickRows {
            listing,
            hints,
            peer_at: peer_at.map(|at| at as u8),
            found: finding.then_some(found),
            rows,
            in_path,
        })
    }

    /// Presses Add hop's row drawn at `index` with `key`: a repeater is
    /// added as the next hop, the peer ends the route there, and Load more
    /// and Refresh ask.
    fn press_pick(&mut self, index: usize, key: FocusKey) {
        let Some(rows) = self.pick_rows() else {
            return;
        };
        let Some(Screen::Neighbors { router, .. }) = self.screens.last() else {
            return;
        };
        // The rows may have moved since they were drawn, as a repeater is
        // heard: the row pressed is the one that still has its key.
        let Some(index) = rows.place(index, key) else {
            return;
        };
        // The field adds the row under it. Resolved here rather than by
        // pressing again, which would hold a second set of rows on the
        // stack.
        let index = match rows.row(index) {
            Some(PickRow::Field) => match rows.top() {
                Some(top) => top,
                None => return,
            },
            _ => index,
        };
        let (hint, address) = match rows.row(index) {
            Some(PickRow::Neighbor(at)) if rows.peer_at == Some(at) => {
                self.finish_route();
                return;
            }
            Some(PickRow::Neighbor(at)) => {
                let Some(listed) = self.node.listed(router, usize::from(at)) else {
                    return;
                };
                (listed.hint, listed.address)
            }
            Some(PickRow::KnownAt(at, _)) => {
                let Some(known) = self.node.known_repeater(usize::from(at)) else {
                    return;
                };
                (known.hint, Some(known.address))
            }
            Some(PickRow::Hint(at)) => {
                let Some(read) = rows.hints.get(usize::from(at)) else {
                    return;
                };
                (read.hint, self.hop_address(read.hint))
            }
            Some(PickRow::More) => return self.ask_listing(true),
            Some(PickRow::Refresh) => return self.ask_listing(false),
            _ => return,
        };
        self.choose_hop(hint, address);
    }

    /// Adds `hint`, the node at `address` when it is known, as the next hop
    /// of the route beneath, and moves Add hop on to the hop after it, or,
    /// with the route full, returns to the editor. A hop already on the
    /// route is not added again.
    fn choose_hop(&mut self, hint: [u8; 2], address: Option<String<44>>) {
        let Some(Screen::Neighbors {
            pick: Some(pick), ..
        }) = self.screens.last()
        else {
            return;
        };
        let (peer, to) = (pick.peer, pick.address.clone());
        let below = self.screens.len() - 2;
        let Some(Screen::Route {
            edit: Some(draft), ..
        }) = self.screens.get_mut(below)
        else {
            return;
        };
        if draft.hints().contains(&hint) {
            return;
        }
        draft.push(hint);
        let (room, last) = (draft.has_room(), draft.hints().len() - 1);
        if room {
            self.show_pick(address.unwrap_or_default(), peer, to, true);
        } else {
            self.leave();
            self.focus().request(keys::path(last));
        }
    }

    /// Ends the route beneath where it is, the peer heard by its last hop,
    /// and returns to the editor at Save.
    fn finish_route(&mut self) {
        self.leave();
        self.focus().request(keys::ROUTE_SAVE);
    }

    /// Narrows Add hop by a character typed, its field focused, whose
    /// Enter adds the top row. Returns whether Add hop took it.
    pub fn find_hop(&mut self, c: char) -> bool {
        let Some(Screen::Neighbors {
            pick: Some(pick), ..
        }) = self.screens.last_mut()
        else {
            return false;
        };
        // Nothing is found by a space before anything else.
        if c == ' ' && pick.find.trim().is_empty() {
            return true;
        }
        _ = pick.find.push(c);
        self.focus().request(keys::PICK_FIELD);
        true
    }

    /// Takes back the last character Add hop was narrowed by, and returns
    /// whether there was one. With none left, the field goes, and focus
    /// goes to the top row.
    pub fn unfind_hop(&mut self) -> bool {
        let Some(Screen::Neighbors {
            pick: Some(pick), ..
        }) = self.screens.last_mut()
        else {
            return false;
        };
        let taken = pick.find.pop().is_some();
        let cleared = pick.find.trim().is_empty();
        if taken && cleared {
            self.focus_top_pick();
        }
        taken
    }

    /// Opens the node the repeater at `index` in the listing shown most
    /// plausibly is, or asks who it is, of the nodes in earshot of the
    /// router, when no known node could be.
    pub fn press_neighbor(&mut self, index: usize) {
        let uptime = self.uptime;
        let node = self.node;
        let Some(Screen::Neighbors { router, asked, .. }) = self.screens.last_mut() else {
            return;
        };
        let Some(listed) = node.listed(router, index) else {
            return;
        };
        if let Some(address) = listed.address {
            if let Some(member) = node.known_member(&address) {
                self.show_known(member);
            }
            return;
        }
        let Some(listing) = node.listing(router) else {
            return;
        };
        let hint = listed.hint;
        if asked
            .iter()
            .any(|&(asked, until)| asked == hint && until > uptime)
        {
            return;
        }
        asked.retain(|&(asked, until)| asked != hint && until > uptime);
        if asked.push((hint, uptime + IDENTIFY_WAIT_MS)).is_ok() {
            node.identify_repeater(hint, &[listing.hint]);
        }
    }

    /// Opens the node the repeater at `index` on the screen shown most
    /// plausibly is, or asks who it is when no known node could be. A
    /// repeater on a path is asked by way of the repeaters before it.
    pub fn open_repeater(&mut self, index: usize) {
        let uptime = self.uptime;
        let node = self.node;
        // A path is the node's, read as it stands; a message's repeaters
        // are its details'.
        let (repeater, before) = match self.screens.last() {
            Some(Screen::Details { details, .. }) => {
                (details.repeaters.get(index).cloned(), heapless::Vec::new())
            }
            Some(&Screen::Route { peer, .. }) => {
                path_stop(node.peer_route(peer).map(|r| r.repeaters), index)
            }
            Some(&Screen::Ping { peer, .. }) => match node.ping_view(peer) {
                Some(PingView::Reply(reply)) => path_stop(Some(reply.repeaters), index),
                _ => (None, heapless::Vec::new()),
            },
            _ => (None, heapless::Vec::new()),
        };
        let Some(repeater) = repeater else {
            return;
        };
        let Some(asked) = self.screens.last_mut().and_then(Screen::asked_mut) else {
            return;
        };
        match repeater.address {
            Some(address) => {
                if let Some(member) = node.known_member(&address) {
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
                // Those that gave up waiting make room.
                asked.retain(|&(asked, until)| asked != hint && until > uptime);
                if asked.push((hint, uptime + IDENTIFY_WAIT_MS)).is_ok() {
                    node.identify_repeater(hint, &before);
                }
            }
        }
    }

    /// The unknown repeaters on the screen shown whose identity is still
    /// waited for.
    #[must_use]
    pub fn identifying(&self) -> heapless::Vec<[u8; 2], MAX_PATH> {
        self.screens
            .last()
            .and_then(Screen::asked)
            .map(|asked| {
                asked
                    .iter()
                    .filter(|&&(_, until)| until > self.uptime)
                    .map(|&(hint, _)| hint)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Where the spinner of a repeater asked who it is stands, by the
    /// board's clock.
    #[must_use]
    pub fn spinner_phase(&self) -> u8 {
        ((self.uptime / SPIN_STEP_MS) % u64::from(SPIN_PHASES)) as u8
    }

    /// When the screen shown next changes by itself: a spinner's next step
    /// while it waits on a repeater or a ping, and when it gives up on a
    /// repeater.
    pub(crate) fn screen_deadline(&self) -> Option<u64> {
        let screen = self.screens.last()?;
        let step = (self.uptime / SPIN_STEP_MS + 1) * SPIN_STEP_MS;
        if let Screen::Ping {
            settled_at: None, ..
        } = screen
        {
            return Some(step);
        }
        // A listing asked for spins in its row until it is answered.
        if let Screen::Neighbors { router, .. } = screen
            && self
                .node
                .listing(router)
                .is_some_and(|listing| listing.asking.is_some())
        {
            return Some(step);
        }
        // Wi-Fi's spinners: a scan, and looking for a saved network.
        if let Screen::Device {
            page: DevicePage::Wifi {
                page: WifiPage::Main,
            },
            ..
        } = screen
            && (self.wifi.scanning || self.wifi.searching)
        {
            return Some(step);
        }
        let waiting = screen
            .asked()?
            .iter()
            .map(|&(_, until)| until)
            .filter(|&until| until > self.uptime);
        let until = waiting.min()?;
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
        _ = node.save_peer(member);
        member.saved = true;
        focus.request(keys::MESSAGE_MEMBER);
        node.sort_peers();
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

    /// Backspace, or the header's way back: returns to the screen before
    /// this one, focused where it was left, or, in the route editor, steps
    /// back within it. Returns `false` on the Chats screen, which nothing
    /// comes before.
    pub fn back(&mut self) -> bool {
        // The route editor goes back to the route before leaving it.
        if self.route_draft().is_some() {
            self.route_edit_back();
            return true;
        }
        self.leave()
    }

    /// Closes the screen shown, whatever is under way on it, for the one
    /// before, focused where it was left. Returns `false` on the Chats
    /// screen, which nothing comes before.
    fn leave(&mut self) -> bool {
        if self.screens.len() < 2 {
            return false;
        }
        if let Some(Screen::Conversation { .. }) = self.screens.pop() {
            self.close_conversation();
        }
        self.settle();
        // Back on a conversation, what came due over it meanwhile is offered.
        self.refresh_learned_route(false);
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

/// The repeater at `index` on a path through `repeaters`, the one nearest
/// this device first, and the hints of those before it, which an ask to it
/// goes by way of.
fn path_stop(
    repeaters: Option<heapless::Vec<Repeater, MAX_PATH>>,
    index: usize,
) -> (Option<Repeater>, heapless::Vec<[u8; 2], MAX_PATH>) {
    let Some(repeaters) = repeaters else {
        return (None, heapless::Vec::new());
    };
    let before = repeaters.iter().take(index).map(|r| r.hint).collect();
    (repeaters.get(index).cloned(), before)
}
