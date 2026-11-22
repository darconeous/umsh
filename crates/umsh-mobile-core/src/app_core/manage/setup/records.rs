//! What setting up a device publishes, edits and answers. Every name here
//! is a code native code puts into words; nothing carries display text,
//! and every number is a number.

use crate::app_core::manage::records::{
    MobileChoiceField, MobileChoiceList, MobileFieldProblemRecord, MobileKeyEntryRecord,
    MobileManagementProblem, MobileRadioDraft, MobileRepeaterDraft, MobileTextField,
    MobileToggleField,
};
use crate::ulcp::UlcpSyncRecord;

/// What the operator is setting a device up as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileSetupGoal {
    /// A mobile node that carries its own identity and does not forward.
    Tracker,
    /// A node that forwards traffic for the mesh.
    Repeater,
}

/// Why a device cannot serve the goal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupRefusal {
    /// The device attached but reported no settings.
    NotReported,
    /// Tracker: no device identity of its own.
    NoDeviceIdentity,
    /// Tracker: cannot announce itself on a schedule.
    NoAdvertSchedule,
    /// Repeater: cannot forward.
    CannotForward,
    /// Repeater: would not report its forwarding policy.
    ForwardingUnreported,
}

/// What the goal will not manage on this device. Not a warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupNote {
    /// No positioning receiver: it will not report where it is.
    NoPositioning,
    /// It cannot be told a role: it advertises the one it derives.
    NoRole,
    /// It keeps no clock: its time zone is not set.
    NoClock,
}

/// The settings the goal asks about, in the order the sheet shows them.
/// Link notices, notes, host state and the apply status are native
/// layout, not goal policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupSection {
    Name,
    Forwarding,
    Discoverability,
    Positioning,
    Announcements,
    RadioProfile,
    Administrators,
}

/// The radio a set-up device is put on, captured when the sheet opens.
/// Typed values from the core's own radio; native code holds it and
/// hands it back.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileSetupCompanionRecord {
    /// That radio's own name, when it has one.
    pub name: Option<String>,
    pub frequency_khz: i64,
    pub transmit_power_dbm: i64,
    /// `None` when the radio did not report it.
    pub bandwidth_hz: Option<i64>,
    pub spreading_factor: Option<i64>,
    pub coding_rate: Option<i64>,
    pub duty_limit: Option<i64>,
}

/// A setting the device would not report, so the sheet neither shows nor
/// writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupUnreadable {
    ModemProfile,
    TransmitLimit,
    AdvertisedIdentity,
    Discoverability,
    ForwardingPolicy,
    MeshCoreForwarding,
    Positioning,
    Announcements,
    TimeZone,
    Administrators,
}

/// Why no profile could be copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupProfileGap {
    /// This phone has no radio, or it has not reported its profile.
    NoCompanion,
    /// This phone's radio reported no modem profile for a device that
    /// needs one.
    CompanionHasNoModemProfile,
    /// The device would not report its modem profile, so none is copied
    /// onto it.
    DeviceModemUnreported,
}

/// Where the radio profile on the draft came from.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupProfile {
    /// From this phone's radio, reduced to what the device accepts.
    /// `companion_name` is that radio's own name, when it has one.
    Copied { companion_name: Option<String> },
    /// Nothing copied; the operator must choose before Apply.
    MustChoose { gap: MobileSetupProfileGap },
    /// Nothing copied and nothing safe to offer; the device keeps its own.
    LeftAsFound { gap: MobileSetupProfileGap },
}

/// A setting as the operator knows it: what a mismatch names, and what a
/// review problem on a setting with no box of its own names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum MobileSetupSetting {
    RadioSwitch,
    Frequency,
    Bandwidth,
    SpreadingFactor,
    CodingRate,
    TransmitLimit,
    AdvertisedRole,
    Mobility,
    Discoverability,
    ForwardingPolicy,
    MeshCoreForwarding,
    TimeZone,
    ClockFormat,
    Positioning,
    Announcements,
}

/// Everything the setup sheet shows that is not the draft.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileDeviceSetupRecord {
    pub goal: MobileSetupGoal,
    pub refusal: Option<MobileSetupRefusal>,
    /// Empty for a refused device.
    pub sections: Vec<MobileSetupSection>,
    /// Empty for a refused device.
    pub notes: Vec<MobileSetupNote>,
    /// Empty for a refused device.
    pub unreadable: Vec<MobileSetupUnreadable>,
    /// `None` for a refused device.
    pub profile: Option<MobileSetupProfile>,
    /// The radio-profile editor's gates.
    pub shows_presets: bool,
    pub shows_modem: bool,
    pub shows_duty_limit: bool,
    /// The forwarding section proposes regions from the phone's position.
    pub suggests_regions_from_phone: bool,
    /// The engine's: the first caller's on a shared engine.
    pub phone_node_key: Option<Vec<u8>>,
    /// What the device reports now: the attach's record, then each
    /// read-back.
    pub reported: Option<UlcpSyncRecord>,
    /// The role code to file the device under in Peers, from `reported`;
    /// `None` keeps the kind it is already filed under.
    pub advertised_role: Option<u8>,
    /// An apply is under way.
    pub applying: bool,
    /// How the last apply that got past review ended; `None` before one
    /// and while one runs. The status section words the failures.
    pub last_result: Option<MobileSetupResult>,
}

/// What the setup sheet edits. Field records are the management drafts':
/// `known` and `reported` are the baseline the draft was built on, and
/// native code never writes them. A field whose setting the device did
/// not report is unknown, holds a placeholder, and is never written.
/// Native code receives, copies and mutates a draft, and never constructs
/// one.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileSetupDraft {
    pub name: MobileTextField,
    /// `reading_revision` is 0: built on no reading. Write the six
    /// parameters through `setup_set_radio_parameter`, which settles a
    /// pending profile choice; `enabled` directly.
    pub radio: MobileRadioDraft,
    pub discoverable: MobileToggleField,
    /// `reading_revision` is 0. Mode 0 off, 1 on, 2 adaptive; regions
    /// edited through `draft_add_repeater_region` and
    /// `draft_adopt_regions`; the default region as region text, empty
    /// never tags; thresholds `None` for none.
    pub repeater: MobileRepeaterDraft,
    pub gnss_enabled: MobileToggleField,
    /// `PROP_GNSS_IDENT_UPDATE`: fixes refresh the advertised position.
    pub share_position: MobileToggleField,
    pub precision: MobileChoiceField,
    pub time_trust: MobileToggleField,
    /// Seconds; 0 is off.
    pub advert_interval: MobileChoiceField,
    /// Seconds; 0 is off.
    pub beacon_interval: MobileChoiceField,
    pub startup_beacon: MobileToggleField,
    pub administrators: MobileKeyListField,
    /// A pending profile choice was made. Set by `setup_adopt_preset` and
    /// `setup_set_radio_parameter`; native code never writes it.
    pub profile_settled: bool,
}

/// A list of keys: the device's administrators.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileKeyListField {
    pub property_id: u32,
    pub known: bool,
    pub reported: Vec<Vec<u8>>,
    pub value: Vec<Vec<u8>>,
}

/// One radio parameter `setup_set_radio_parameter` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupRadioParameter {
    Frequency,
    TransmitPower,
    Bandwidth,
    SpreadingFactor,
    CodingRate,
    DutyLimit,
}

/// What Apply would do with a draft now.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileSetupReviewRecord {
    /// Every value Apply would write that the device cannot take, by
    /// property, ascending. Judged on every known value, not only edits:
    /// setup writes them all.
    pub problems: Vec<MobileFieldProblemRecord>,
    /// The settings of `problems` that have no box of their own on the
    /// sheet (all but the name, frequency and power), once each, in
    /// `MobileSetupSetting` order.
    pub unshown_problems: Vec<MobileSetupSetting>,
    /// No profile choice is pending.
    pub profile_chosen: bool,
    /// No problem, the profile chosen, no apply under way, not released.
    /// Native code adds its link state.
    pub can_apply: bool,
    /// The device confirmed exactly this draft.
    pub applied: bool,
    /// The vetted preset the radio fields spell out; `None` is custom.
    pub preset_id: Option<String>,
    pub choices: MobileSetupChoicesRecord,
    /// The default-region picker's rows.
    pub taggable_regions: Vec<String>,
    /// The device would tag untagged floods with a region it does not
    /// relay.
    pub default_region_unlisted: bool,
    pub administrators: Vec<MobileKeyEntryRecord>,
    pub phone_administers: bool,
    /// The "this phone" switch can be moved.
    pub phone_switch_enabled: bool,
    pub administrators_full: bool,
}

/// Every picker's values.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileSetupChoicesRecord {
    pub bandwidths_hz: MobileChoiceList,
    pub spreading_factors: MobileChoiceList,
    pub coding_rates: MobileChoiceList,
    pub duty_limits: MobileChoiceList,
    pub precisions: MobileChoiceList,
    pub advert_intervals_s: MobileChoiceList,
    pub beacon_intervals_s: MobileChoiceList,
    /// "Off" (`None`) is always offered besides these.
    pub min_rssi_dbm: MobileChoiceList,
    /// "Off" (`None`) is always offered besides these.
    pub min_snr_db: MobileChoiceList,
}

/// How an apply ended, and the draft to keep.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileSetupApplyOutcome {
    pub result: MobileSetupResult,
    /// The one applied, with the transmit power the device reported and
    /// the administrator list it now holds once the device answered; the
    /// one given otherwise.
    pub draft: MobileSetupDraft,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileSetupResult {
    /// Saved and read back as asked. `clock_failed`: the goal sets the
    /// clock and the device would not take it.
    Configured { clock_failed: bool },
    /// Saved, and then reported `setting` back differently.
    ReportedDifferently { setting: MobileSetupSetting },
    /// Configured, but the administrator list did not take.
    AdministratorsNotApplied { problem: MobileManagementProblem },
    /// The configuration did not land, or may not have (by `problem`).
    NotApplied { problem: MobileManagementProblem },
    /// Saved, then the read-back failed: nothing could be verified.
    NotVerified { problem: MobileManagementProblem },
    /// Stopped after the configuration was sent. `configured` false:
    /// during the configuration pass, so the device may or may not have
    /// kept it; true: after the device confirmed it, so nothing was
    /// verified.
    Interrupted { configured: bool },
    /// Review would not allow it; nothing was sent.
    Invalid,
    /// Stopped before anything was sent.
    Cancelled,
    /// The device entered firmware update; nothing was sent.
    Skipped,
}
