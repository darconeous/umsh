//! What a managed device publishes, and what its commands answer. Every
//! name here is a code that native code puts into words; nothing carries
//! display text.

use crate::ulcp::{
    UlcpAlertState, UlcpDeviceCardRecord, UlcpDevicePropertiesRecord, UlcpManageCategory,
    UlcpWifiScanResultRecord,
};

/// Which link a device is managed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileManagementLink {
    /// Across the mesh, through the attached radio.
    Mesh,
    /// The attached radio, over its own link.
    Companion,
    /// A device native code holds an administrative link to.
    Administrative,
}

/// Everything a screen shows about one managed device, as last published.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileManagedDeviceRecord {
    /// Raised by every published change; equal revisions read equal.
    pub revision: u64,
    pub link: MobileManagementLink,
    pub uses_bluetooth: bool,
    /// What the cache is keyed by; `None` when nothing is cached for the
    /// device: an administrative link, a radio with no identity, or no
    /// owner to keep a cache for.
    pub address: Option<String>,
    pub card: Option<UlcpDeviceCardRecord>,
    pub card_as_of_ms: Option<i64>,
    /// The card came off the air during this device's lifetime.
    pub card_is_fresh: bool,
    /// The categories this device offers, each with the properties it
    /// covers on this card, in a suggested order native code may change.
    /// Empty without a card.
    pub categories: Vec<MobileOfferedCategoryRecord>,
    /// One per category read or loaded this lifetime.
    pub readings: Vec<MobileCategoryReadingRecord>,
    pub alert: UlcpAlertState,
    /// Something asked of the device has not finished.
    pub busy: bool,
    /// The device confirmed entering firmware update; nothing more is
    /// asked of it.
    pub entered_dfu: bool,
    pub problem: Option<MobileManagementProblem>,
    /// This phone's node key, as the device would hold it.
    pub phone_node_key: Option<Vec<u8>>,
    /// What a Wi-Fi scan heard, strongest first, one per network name.
    pub heard_networks: Vec<MobileHeardNetworkRecord>,
    /// A stale or empty reading refreshes itself when loaded.
    pub refreshes_stale_readings: bool,
    pub offers_factory_reset: bool,
    /// This phone's position stands for the device's own.
    pub phone_stands_for_device: bool,
    /// The device answered for its Wi-Fi station.
    pub supports_wifi_station: bool,
    /// The device answered for its Bluetooth bonds.
    pub supports_bluetooth_pairing: bool,
    /// The peer-nodes reading's peer table, once read.
    pub peers: Option<MobileKeyTableRecord>,
    /// The peer-nodes reading's administrators, once read.
    pub administrators: Option<MobileKeyTableRecord>,
}

/// A category this device offers, with the properties it covers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileOfferedCategoryRecord {
    pub category: UlcpManageCategory,
    pub property_ids: Vec<u32>,
}

/// What is known of one category.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileCategoryReadingRecord {
    pub category: UlcpManageCategory,
    /// What this category covers on this device, in ask order.
    pub property_ids: Vec<u32>,
    /// `property_ids` minus the properties the last read refused. A
    /// reading built from the cache refused nothing, so it answers every
    /// id, held or not.
    pub answered: Vec<u32>,
    /// The octets as the device reported them, each with its own sample
    /// instant.
    pub values: Vec<MobilePropertyValueRecord>,
    /// What those octets mean.
    pub properties: UlcpDevicePropertiesRecord,
    /// Every property's read state, in ask order.
    pub states: Vec<MobilePropertyStateRecord>,
    /// Values the device refused on the last write, by property.
    pub refusals: Vec<MobilePropertyRefusalRecord>,
    /// The sensors' temperatures, classified, when the category covers
    /// them.
    pub temperatures: Option<MobileTemperatureSummaryRecord>,
    /// Reset Counters would zero something: the reading answered for at
    /// least one counter. Always false outside Statistics.
    pub can_reset_counters: bool,
    pub battery_diagnostics_as_of_ms: Option<i64>,
    /// When the values were learned; `None` when nothing has been.
    pub as_of_ms: Option<i64>,
    /// Some of it came off the air during this device's lifetime.
    pub is_fresh: bool,
    /// Raised when this reading changes.
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobilePropertyValueRecord {
    pub property_id: u32,
    pub value: Vec<u8>,
    pub received_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobilePropertyStateRecord {
    pub property_id: u32,
    pub state: MobilePropertyState,
}

/// What a read learned of one property.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobilePropertyState {
    NotRead,
    /// Octets decoded into the reading's properties.
    Present,
    /// The device holds nothing (zero octets).
    Empty,
    /// Octets this build cannot decode.
    Invalid,
    Refused {
        refusal: MobileRefusal,
    },
    /// The device answered the request without this property.
    NoResponse,
    /// The request failed.
    Failed {
        problem: MobileManagementProblem,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobilePropertyRefusalRecord {
    pub property_id: u32,
    pub refusal: MobileRefusal,
}

/// A refusal: what the device's status means, and the status, for its
/// name.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRefusal {
    pub reason: MobileRefusalReason,
    pub status: Option<u32>,
}

/// What a refusal's status means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileRefusalReason {
    /// `UNIMPLEMENTED`.
    NotImplemented,
    /// `PROP_NOT_FOUND`.
    NoSuchProperty,
    /// `INVALID_ARGUMENT`.
    OutOfRange,
    /// `INVALID_STATE`.
    NotNow,
    /// `NOMEM`.
    TooLarge,
    /// `IN_PROGRESS` or `BUSY`.
    Busy,
    /// `NOT_PERMITTED`.
    NotPermitted,
    /// A value missing with no status in its place.
    NoStatus,
    /// Any other status; native code names it.
    Other,
}

/// The sensors' temperatures, classified for the screen.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileTemperatureSummaryRecord {
    pub rows: Vec<MobileTemperatureRowRecord>,
    /// Why the readings show no numbers, if they do not.
    pub failure: Option<MobilePropertyState>,
    pub names: MobileTemperatureNames,
    pub sampled_at_ms: Option<i64>,
}

/// Whether the sensors' names can be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileTemperatureNames {
    Known,
    /// The names could not be read: the request failed or was refused.
    Unreadable,
    /// The names are malformed, or fewer than the readings.
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileTemperatureRowRecord {
    pub index: u32,
    pub name: Option<String>,
    pub value: MobileTemperatureValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileTemperatureValue {
    Reading {
        tenths_kelvin: u16,
    },
    /// The sensor reported no value.
    Unavailable,
    /// No reading for this index.
    NotRead,
}

/// One network a scan heard.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileHeardNetworkRecord {
    /// The strongest result for this network name, or the one nameless
    /// result.
    pub result: UlcpWifiScanResultRecord,
    /// The device already knows this network.
    pub is_known: bool,
}

/// One of a device's key tables, with what may be taken out.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileKeyTableRecord {
    pub entries: Vec<MobileKeyEntryRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileKeyEntryRecord {
    pub key: Vec<u8>,
    pub is_this_phone: bool,
    pub removable: bool,
}

/// Which of a device's key tables a command edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileKeyTable {
    /// The nodes the device may hold a secure session with on its own.
    Peers,
    /// The nodes that may manage the device.
    Administrators,
}

/// How far an announcement travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAnnouncementReach {
    /// The device's own neighbors.
    Nearby,
    /// Flooded across the mesh.
    Mesh,
}

/// What went wrong, for the status bar and a screen's alerts. Native code
/// words each case.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileManagementProblem {
    /// The request was acknowledged, then nothing: a lost answer, or this
    /// phone is not one of its administrators.
    NoAnswer,
    /// The request was never acknowledged.
    Unreachable,
    Refused {
        refusal: MobileRefusal,
    },
    /// An answer this build cannot read.
    Unreadable,
    /// No link to send through: the radio left, the link failed, or the
    /// driver stopped.
    NoRadio,
    /// The radio has as many exchanges waiting as it takes.
    RadioBusy,
    /// The device's table is full.
    TableFull,
    /// The device lacks what the request needs.
    Unsupported,
    DfuUnsupported,
    DfuRefused {
        status: u32,
    },
    DfuUnconfirmed,
    /// Some values were refused, so nothing was saved; with `saving`, the
    /// ones taken are running unsaved.
    NotAllApplied {
        saving: bool,
    },
    /// This app could not build the request.
    NotBuilt,
    /// No identity is running.
    NotRunning,
    /// No owner is set.
    NoOwner,
    /// The attached radio is not this phone's.
    NotThisPhone,
    /// What the command names is not stored.
    NotFound,
    /// The request cannot be made as asked.
    InvalidRequest,
    /// The mesh session could not send.
    SendFailed,
    /// The core is starting, erasing or stopping.
    Busy,
    /// The core stopped.
    Stopped,
    /// Any other failure.
    Other,
}

/// How a command ended.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileManagementOutcome {
    Done,
    /// The operator canceled it.
    Cancelled,
    /// It did not run: the device entered firmware update, or every screen
    /// on it closed.
    Skipped,
    Failed {
        problem: MobileManagementProblem,
    },
}

/// How an apply ended.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileApplyOutcome {
    /// Rebuild what was edited from the reading: the device answered the
    /// write, or there was nothing to write.
    pub answered: bool,
    pub result: MobileApplyResult,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileApplyResult {
    Applied,
    NothingToApply,
    /// Something edited is invalid; nothing was sent.
    Invalid,
    /// The device refused some values; the reading's refusals say which.
    Refused,
    Cancelled,
    Skipped,
    Failed {
        problem: MobileManagementProblem,
    },
}

/// How a command that stores a Wi-Fi network ended.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileWifiOutcome {
    Done,
    /// The device would not take the network; nothing was saved.
    Refused {
        refusal: MobileWifiRefusal,
    },
    Cancelled,
    Skipped,
    Failed {
        problem: MobileManagementProblem,
    },
}

/// Why a device would not take a network.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileWifiRefusal {
    /// The device has no room for another network.
    NoRoom,
    /// The credential does not fit the security mode.
    CredentialRejected,
    /// The device cannot use this network with `tried`; `weaker` is the
    /// next mode the network also offers, if any. The device answers this
    /// too for a name, key or password it cannot hold, so `weaker` is a
    /// mode to try, never one known to work.
    SecurityUnsupported { tried: u8, weaker: Option<u8> },
    /// Anything else, at `step`.
    Other {
        step: MobileWifiStep,
        refusal: MobileRefusal,
    },
}

/// The steps of joining a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileWifiStep {
    /// Storing the network.
    Store,
    /// Turning the station on.
    TurnOn,
    /// Joining the network.
    Select,
}

/// The security modes a sheet offers for a network.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileWifiJoinPlanRecord {
    /// `WIFI_SEC_*` codes, in the order offered; a step-down walks it.
    pub choices: Vec<u8>,
    /// Modes the network offers that this app cannot set up.
    pub unsupported: Vec<u8>,
    /// The mode chosen at first.
    pub initial: u8,
}

/// What a sheet's entry would send, judged before it is sent.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileWifiEntryCheckRecord {
    /// The mode takes a credential.
    pub takes_credential: bool,
    /// An empty credential keeps the stored one.
    pub keeps_credential: bool,
    /// Something differs from what is stored; always, with nothing stored.
    pub changed: bool,
    /// Why the entry cannot be sent, if it cannot.
    pub problem: Option<MobileWifiEntryProblem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileWifiEntryProblem {
    SsidEmpty,
    /// Longer than a network name can be.
    SsidTooLong,
    /// The mode needs a credential and none is typed or kept.
    CredentialRequired,
    /// The credential does not fit the mode.
    CredentialInvalid,
}

// MARK: Drafts

/// Which editor a draft belongs to. Repeater and MeshCore both read and
/// apply under `UlcpManageCategory::Repeater`, with disjoint properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileDraftKind {
    Radio,
    Identity,
    Repeater,
    MeshCore,
    Wifi,
    Network,
    Bridge,
    Bluetooth,
    Gnss,
    Time,
}

// Field records. `reported` and `known` are the baseline the draft was
// built on, and native code never writes them; `value` (or `text`) is
// what the form holds. An unknown field takes nothing: the device never
// answered for it, so there is no baseline to compare an edit against.

/// A switch.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileToggleField {
    pub property_id: u32,
    pub known: bool,
    pub reported: bool,
    pub value: bool,
}

/// A picker. `None` is a real choice where the field has one.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChoiceField {
    pub property_id: u32,
    pub known: bool,
    pub reported: Option<i64>,
    pub value: Option<i64>,
}

/// A number the operator types; empty text is not a value. An unknown one
/// holds 0, which is never shown.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileIntegerField {
    pub property_id: u32,
    pub known: bool,
    pub reported: i64,
    pub value: i64,
}

/// A number the operator types where empty text is allowed: a value (no
/// threshold, the device's default, no stated height), or a gap the core
/// judges (a static prefix not yet typed).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileOptionalIntegerField {
    pub property_id: u32,
    pub known: bool,
    pub reported: Option<i64>,
    pub value: Option<i64>,
}

/// A position as one field. The reported pair is both `Some` or both
/// `None` (no position); `reported_location` is the reported location as
/// the device holds it, which an edit is compared against. Both
/// coordinates `None` clears the position, and one alone is not an edit.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobilePositionField {
    pub property_id: u32,
    pub known: bool,
    pub reported_latitude: Option<f64>,
    pub reported_longitude: Option<f64>,
    pub reported_location: Vec<u8>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Text whose value is text or an identifier: a name, a host, an address.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileTextField {
    pub property_id: u32,
    pub known: bool,
    pub reported: String,
    pub text: String,
}

/// A list of text entries: region names, resolvers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileTextListField {
    pub property_id: u32,
    pub known: bool,
    pub reported: Vec<String>,
    pub value: Vec<String>,
}

/// A picker's values: those offered, and the field's own value when it is
/// known and not one of them, which the picker must still show.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileChoiceList {
    pub offered: Vec<i64>,
    pub other: Option<i64>,
}

// The drafts. Each holds the revision of the reading it was built or
// rebased on; native code receives, copies and mutates them, and never
// constructs one.

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRadioDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
    pub frequency_khz: MobileIntegerField,
    pub transmit_power_dbm: MobileIntegerField,
    /// In hertz.
    pub bandwidth: MobileChoiceField,
    pub spreading_factor: MobileChoiceField,
    /// The denominator.
    pub coding_rate: MobileChoiceField,
    pub duty_limit: MobileChoiceField,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileIdentityDraft {
    pub reading_revision: u64,
    pub name: MobileTextField,
    /// `None` is a device deriving its own role.
    pub role: MobileChoiceField,
    pub mobile: MobileToggleField,
    pub discoverable: MobileToggleField,
    pub position: MobilePositionField,
    /// `None` is no stated height.
    pub altitude_m: MobileOptionalIntegerField,
    pub self_positions: MobileToggleField,
    pub precision: MobileChoiceField,
    /// In seconds.
    pub advert_interval: MobileChoiceField,
    /// In seconds.
    pub beacon_interval: MobileChoiceField,
    pub startup_beacon: MobileToggleField,
    /// The precision a hand-placed position is encoded to on a device
    /// with no precision property. Local; never on the air as itself.
    pub manual_precision: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRepeaterDraft {
    pub reading_revision: u64,
    pub mode: MobileChoiceField,
    pub regions: MobileTextListField,
    /// The region floods are tagged with, as a region string; empty
    /// never tags.
    pub default_region: MobileTextField,
    /// `None` is no threshold.
    pub min_rssi: MobileOptionalIntegerField,
    /// `None` is no threshold.
    pub min_snr: MobileOptionalIntegerField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileMeshCoreDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
    pub policy: MobileChoiceField,
    pub regions: MobileTextListField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileWifiDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
}

/// Addressing per family. Each family's address, prefix and gateway are
/// edited as one configuration under its method.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileNetworkDraft {
    pub reading_revision: u64,
    pub v4_method: MobileChoiceField,
    pub v4_address: MobileTextField,
    pub v4_prefix: MobileOptionalIntegerField,
    /// Empty is no default route.
    pub v4_gateway: MobileTextField,
    pub v6_method: MobileChoiceField,
    pub v6_address: MobileTextField,
    pub v6_prefix: MobileOptionalIntegerField,
    /// Empty is no default route.
    pub v6_gateway: MobileTextField,
    /// Resolver addresses; blank rows are dropped.
    pub dns: MobileTextListField,
    /// Empty is the device's default.
    pub group: MobileTextField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileBridgeDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
    pub host: MobileTextField,
    pub port: MobileIntegerField,
    /// A UMSH address; empty clears it.
    pub server_key: MobileTextField,
    pub local_enabled: MobileToggleField,
    /// Empty is the device's default.
    pub group: MobileTextField,
    /// Frames per minute; `None` is the device's default.
    pub ingress_limit: MobileOptionalIntegerField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileBluetoothDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
    pub pairing: MobileToggleField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileGnssDraft {
    pub reading_revision: u64,
    pub enabled: MobileToggleField,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileTimeDraft {
    pub reading_revision: u64,
    /// A POSIX TZ rule.
    pub tz_rule: MobileTextField,
    pub time_24h: MobileToggleField,
    pub time_trust: MobileToggleField,
}

/// One editor's draft.
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum MobileManagementDraft {
    Radio { draft: MobileRadioDraft },
    Identity { draft: MobileIdentityDraft },
    Repeater { draft: MobileRepeaterDraft },
    MeshCore { draft: MobileMeshCoreDraft },
    Wifi { draft: MobileWifiDraft },
    Network { draft: MobileNetworkDraft },
    Bridge { draft: MobileBridgeDraft },
    Bluetooth { draft: MobileBluetoothDraft },
    Gnss { draft: MobileGnssDraft },
    Time { draft: MobileTimeDraft },
}

/// What a draft would do if applied now.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileDraftReviewRecord {
    /// What Apply would write, by property, ascending.
    pub dirty: Vec<u32>,
    /// Edited fields whose value cannot be applied; they are not in
    /// `dirty`. A field equal to its `reported` is never listed.
    pub problems: Vec<MobileFieldProblemRecord>,
    /// `dirty` is not empty: Apply is offered, and leaving asks first.
    pub has_edits: bool,
    /// What to confirm before Apply, on the link the device is on.
    pub warning: Option<MobileApplyWarning>,
    pub details: MobileDraftDetails,
}

/// A field problem, on the row of the property it would write.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileFieldProblemRecord {
    pub property_id: u32,
    pub problem: MobileFieldProblem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileFieldProblem {
    /// Outside what the property can hold, or what the device takes as a
    /// value of this kind.
    OutOfRange,
    HostInvalid,
    /// Not 1 to 65,535.
    PortInvalid,
    ServerKeyInvalid,
    GroupInvalid,
    /// Not 1 to 65,535.
    LimitInvalid,
    AddressInvalid,
    /// Missing, or longer than the family's address.
    PrefixInvalid,
    GatewayInvalid,
    ResolverInvalid,
}

/// A change Apply should confirm first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileApplyWarning {
    /// Across the mesh, a radio change that can leave the device where it
    /// cannot be reached.
    StrandsRadio,
    /// Across the mesh, the station switched off.
    DisablesWifi,
    /// Across the mesh, a family moved onto a static address.
    ChangesStaticAddressing,
    /// Bluetooth switched off on a device reached over Bluetooth.
    DisablesBluetooth,
    /// The pairing window opened.
    OpensPairing,
}

/// What an editor shows beside its fields.
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum MobileDraftDetails {
    None,
    Radio {
        /// The vetted preset the fields spell out; `None` is custom.
        preset_id: Option<String>,
        /// Every parameter a preset sets has been read.
        shows_presets: bool,
    },
    Identity {
        /// The device keeps its own position, so the position and
        /// altitude are not written.
        self_positioning: bool,
        /// What a typed or placed position is encoded to.
        encoding_precision: u8,
        /// Decimals the coordinate fields show at that precision.
        coordinate_decimals: u8,
        /// The position Apply would leave, decoded: the reported one while
        /// self-positioning. Both `None` for no position.
        latitude_deg: Option<f64>,
        longitude_deg: Option<f64>,
    },
    Repeater {
        /// The regions the default-region picker offers: those listed,
        /// and the one the device tags with.
        taggable_regions: Vec<String>,
    },
    MeshCore {
        /// The device's identity key may forward MeshCore.
        identity_allowed: bool,
        /// The switch cannot be turned on.
        toggle_locked: bool,
    },
    Bluetooth {
        /// Turning Bluetooth off ends the link this phone manages over.
        disables_this_link: bool,
    },
}

/// Why a region could not be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileRegionEntryProblem {
    /// Not a region name the device takes.
    Invalid,
    /// Already listed, exactly.
    AlreadyListed,
}

impl std::fmt::Display for MobileRegionEntryProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for MobileRegionEntryProblem {}
