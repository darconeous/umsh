use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use umsh_core::RegionCode;
use umsh_node::location::{MAX_PRECISION, NodeLocation};
use umsh_ulcp::{
    AlertState, BatteryChargeState, BatteryStatus, Cmd, Frame, StreamPayload, frame,
    gatt::{self, MAX_FRAME, Reassembler},
    gnss::{FixKind, GnssSnapshot},
    host::{PropertyNotification, PropertyNotificationKind, TidAllocator},
    ids::{INTERFACE_TYPE, PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION, cap, prop, saved},
    items::{self, Filter},
    meta::{BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED},
    pui,
};

use crate::MobileError;

/// One header-prefixed ATT value produced by ULCP GATT segmentation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GattSegmentRecord {
    pub value: Vec<u8>,
}

/// A validated property-bearing ULCP frame.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpPropertyFrameRecord {
    pub transaction_id: u8,
    pub command: u8,
    pub property_id: u32,
    pub value: Vec<u8>,
}

/// UI-relevant fields from a validated `PROP_BATTERY` value.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpBatteryRecord {
    pub percentage: Option<u8>,
    /// Measured terminal voltage in millivolts, when the device reports it.
    pub voltage_mv: Option<u16>,
    /// What the charging system is doing, when the device reports it.
    /// Whether the radio is on external power follows from this rather
    /// than being carried separately.
    pub charge_state: Option<UlcpChargeState>,
}

/// The charge state a device reports in `PROP_BATTERY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpChargeState {
    /// Running off the battery.
    Discharging,
    /// On external power, taking charge.
    Charging,
    /// On external power, charge complete.
    Charged,
}

impl UlcpChargeState {
    fn from_wire(state: BatteryChargeState) -> Self {
        match state {
            BatteryChargeState::Discharging => Self::Discharging,
            BatteryChargeState::Charging => Self::Charging,
            BatteryChargeState::Charged => Self::Charged,
        }
    }
}

/// The device identity's autonomous flood-forwarding policy.
///
/// Region codes travel as the opaque 2-octet wire values they are on the
/// air: the same bytes the device advertises as its Supported Regions
/// identity option. Text forms are a presentation concern —
/// [`region_code_from_string`] and [`region_code_description`] convert.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpRepeaterSettingsRecord {
    /// `PROP_MAC_REPEATER_ENABLED`. The remaining fields are inert while
    /// this is false, but are still read and written.
    pub enabled: bool,
    /// `PROP_MAC_REPEATER_REGIONS`: which region-tagged floods to
    /// forward, each entry exactly two octets. Empty imposes no regional
    /// restriction rather than blocking every flood.
    pub regions: Vec<Vec<u8>>,
    /// `PROP_MAC_REPEATER_DEFAULT_REGION`: the tag inserted into an
    /// untagged flood before forwarding it. `None` forwards untagged.
    pub default_region: Option<Vec<u8>>,
    /// `PROP_MAC_REPEATER_MIN_RSSI` in dBm. `None` accepts any.
    pub min_rssi_dbm: Option<i16>,
    /// `PROP_MAC_REPEATER_MIN_SNR` in whole dB. `None` accepts any.
    pub min_snr_db: Option<i8>,
}

/// The device's positioning policy: whether the receiver runs, and what
/// is done with what it finds.
///
/// Read and written as a whole, like [`UlcpRepeaterSettingsRecord`] and
/// for the same reason — a receiver switched on under half a policy
/// starts advertising a position nobody just agreed to. `enabled` is
/// written last so the rest is already in force when it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpGnssSettingsRecord {
    /// `PROP_GNSS_ENABLED`: whether the receiver is powered. Off is the
    /// lowest power state the board can reach, and on most of them the
    /// receiver is the largest continuous load there is.
    pub enabled: bool,
    /// `PROP_GNSS_IDENT_UPDATE`: whether fixes refresh the location the
    /// node advertises in its identity.
    pub ident_update: bool,
    /// `PROP_GNSS_IDENT_PRECISION`: how many location bytes that
    /// advertised position is clamped to, 1 (coarsest) through 7. This is
    /// a disclosure control — see [`ulcp_location_cell_meters`].
    pub ident_precision: u8,
    /// `PROP_GNSS_TIME_TRUST`: whether receiver-derived time may set the
    /// wall clock. Cleared, a hand-set clock is safe from a jammed or
    /// spoofed sky; position reporting is unaffected.
    pub time_trust: bool,
}

/// `PROP_GNSS_FIX`: what kind of position solution the receiver has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpFixKind {
    /// No solution — the receiver is off, or on and still searching.
    #[default]
    None,
    /// Position without altitude.
    TwoD,
    /// Position and altitude.
    ThreeD,
}

impl UlcpFixKind {
    fn from_wire(fix: FixKind) -> Self {
        match fix {
            FixKind::None => Self::None,
            FixKind::TwoD => Self::TwoD,
            FixKind::ThreeD => Self::ThreeD,
        }
    }
}

/// What the receiver currently reports, folded from the five positioning
/// telemetry properties.
///
/// Unlike a battery reading this is carried on *every* snapshot rather
/// than reported once: it is state the UI mirrors — a map pin does not
/// disappear because an unrelated property arrived — and the receiver
/// announces position and fix changes on its own schedule.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct UlcpGnssRecord {
    pub fix: UlcpFixKind,
    /// `PROP_GNSS_LOCATION` as it travels: the interleaved
    /// variable-precision grid code, empty without a fix. Carried
    /// verbatim so a caller can compare or forward the cell itself
    /// rather than re-encoding degrees.
    pub location: Vec<u8>,
    /// Center of the encoded cell, in degrees. `None` without a fix.
    ///
    /// A location names a cell rather than a point; `location_cell_meters`
    /// says how large that cell is, and rendering a pin without it claims
    /// a precision the device did not report. Widened from the f32 the
    /// decoder works in, because that is the shape every consumer of a
    /// coordinate wants.
    pub latitude_deg: Option<f64>,
    pub longitude_deg: Option<f64>,
    /// Approximate width of the encoded cell at the equator, in meters.
    pub location_cell_meters: Option<f64>,
    /// `PROP_GNSS_ALTITUDE` in meters above the WGS-84 ellipsoid.
    pub altitude_m: Option<i32>,
    /// `PROP_GNSS_PRECISION`: estimated horizontal accuracy in
    /// decimeters. An estimate scaled from dilution of precision, not a
    /// measured error bound.
    pub accuracy_dm: Option<u16>,
    /// Satellites contributing to the solution. Reads 0 while the
    /// receiver is off.
    pub satellites_used: u8,
    /// Satellites in view, when the receiver reports them.
    pub satellites_in_view: Option<u8>,
}

/// `PROP_TIME`: what the device's wall clock read when it last reported.
///
/// Take-once, like a battery reading and for the same reason: a clock
/// value means nothing without the instant it was received, so a consumer
/// stamps what arrives. Republishing it on unrelated updates would
/// restamp a stale reading as a fresh one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpTimeRecord {
    /// Seconds since the Unix epoch, or `None` when the device does not
    /// know what time it is. A device that has never had a fix, a manual
    /// set, or a retained RTC is in that state, and says so rather than
    /// reporting zero.
    pub epoch_seconds: Option<u32>,
}

/// Read-only, capability-gated device state gathered after host ownership
/// has been resolved. Counts describe digest forms and contain no key material.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpSyncRecord {
    pub capability_count: u32,
    pub has_host_filtering: bool,
    pub supports_offline_queue: bool,
    pub supports_delegated_ack: bool,
    pub supports_device_name: bool,
    pub supports_lora: bool,
    pub supports_duty_cycle_limit: bool,
    /// The device measures its own power state (`CAP_BATTERY`). A device
    /// without it never reports a battery, so callers have nothing to show.
    pub supports_battery: bool,
    /// The device can forward for the mesh on its own (`CAP_REPEATER`).
    pub supports_repeater: bool,
    /// The device serves and configures its own advertised node identity
    /// (`CAP_IDENT`).
    pub supports_ident: bool,
    /// The device has an identity domain of its own (`CAP_DEV_IDENTITY`),
    /// including the `PROP_DEV_PEERS` list.
    pub supports_device_identity: bool,
    /// The device keeps a wall clock (`CAP_TIME`). It says nothing about
    /// where the time comes from, or whether the device currently knows
    /// it — an unset clock is a device with `CAP_TIME` and no epoch.
    pub supports_time: bool,
    /// A GNSS receiver is fitted (`CAP_GNSS`), so the positioning
    /// properties exist and the device can locate itself.
    pub supports_gnss: bool,
    pub phy_enabled: bool,
    pub frequency_khz: u32,
    pub transmit_power_dbm: i8,
    pub bandwidth_hz: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate_denom: Option<u8>,
    pub duty_cycle_now: Option<u16>,
    pub duty_cycle_limit: Option<u16>,
    pub saved: Option<SavedSnapshotRecord>,
    pub queued_frames: Option<u16>,
    pub dropped_frames: Option<u32>,
    pub filter_count: Option<u32>,
    pub host_channel_count: Option<u32>,
    pub host_peer_count: Option<u32>,
    pub auto_ack: Option<bool>,
    /// Present when `supports_repeater` and the device reported the whole
    /// policy.
    pub repeater: Option<UlcpRepeaterSettingsRecord>,
    /// `PROP_DEV_PEERS`: the peer public keys stored on the device
    /// identity, read back losslessly. Present when
    /// `supports_device_identity` and the device reported the list.
    pub dev_peer_keys: Option<Vec<Vec<u8>>>,
    /// `PROP_DEV_CHANNEL_KEYS`: the two-octet identifiers of the channels the
    /// device identity has joined. Key material is never read back, so a
    /// caller names these by deriving identifiers from the keys it holds; one
    /// that matches nothing locally is a channel the device knows and this
    /// phone does not.
    pub dev_channel_ids: Option<Vec<Vec<u8>>>,
    /// `PROP_IDENT_ROLE`. `None` covers "the device derives its role from
    /// what it is actually doing", "no `CAP_IDENT`", and "the device would
    /// not report it" — `supports_ident` and `unreadable_properties`
    /// distinguish them.
    pub ident_role: Option<u8>,
    /// `PROP_IDENT_MOBILE`. Present when `supports_ident` and the device
    /// reported it.
    pub ident_mobile: Option<bool>,
    /// `PROP_DEV_DISCOVERABLE`: whether the device identity answers
    /// Identity Requests. Present when `supports_device_identity` and the
    /// device reported it.
    pub dev_discoverable: Option<bool>,
    /// `PROP_TZ_OFFSET` in minutes east of UTC. Present when
    /// `supports_time` and the device reported it.
    ///
    /// The zone is configuration and the epoch is not: where a device is
    /// meant to be is known even when what time it is is not, which is
    /// why this is here and the clock reading is on the session snapshot.
    pub tz_offset_min: Option<i16>,
    /// The positioning policy. Present when `supports_gnss` and the
    /// device reported the whole of it.
    pub gnss: Option<UlcpGnssSettingsRecord>,
    /// Capability-gated properties the device advertised but would not
    /// report, in ascending order.
    ///
    /// A device that refuses a property — old firmware behind a newer
    /// capability, a property it never implemented — is a device with an
    /// unknown setting, not one this phone cannot administer. Their values
    /// are absent above, they are left out of configuration writes, and
    /// nothing about them can be verified after a save.
    pub unreadable_properties: Vec<u32>,
}

/// `PROP_SAVED`: what the radio reports about its stored snapshot.
///
/// `Fallback` and `Unreadable` are the values worth surfacing: the radio
/// is running on configuration older than the one last saved, or on none
/// at all, and looks healthy otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SavedSnapshotRecord {
    /// Nothing is saved.
    None,
    /// The newest saved generation is in effect.
    Current,
    /// A newer generation was rejected at boot; an older one is in
    /// effect. Saving again clears it.
    Fallback,
    /// A snapshot exists but could not be read; the radio booted with
    /// factory defaults.
    Unreadable,
}

/// Long-lived host-session phase. Swift maps this value to UI link state but
/// does not implement ULCP transitions itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpSessionPhase {
    Idle,
    Synchronizing,
    AwaitingHost,
    Claiming,
    Configuring,
    Attached,
}

/// Complete desired live radio configuration. Capability-gated fields must be
/// omitted when the device does not advertise their associated capability.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpRadioSettingsRecord {
    pub device_name: Option<String>,
    pub phy_enabled: bool,
    pub frequency_khz: u32,
    pub transmit_power_dbm: i8,
    pub bandwidth_hz: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate_denom: Option<u8>,
    pub duty_cycle_limit: Option<u16>,
}

/// Complete desired configuration of a device's *own* domain: what it is
/// and what it does when no phone is attached.
///
/// This is the commissioning counterpart to [`UlcpRadioSettingsRecord`],
/// which describes only the radio. Every capability-gated field must be
/// present exactly when the device advertises the matching capability, so
/// the record always states a whole desired configuration rather than a
/// patch — a property that a future template feature can lean on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpDeviceConfigRecord {
    /// The live radio profile, applied with the same disable-first,
    /// enable-last ordering [`MobileUlcpSession::configure`] uses.
    pub radio: UlcpRadioSettingsRecord,
    /// `PROP_IDENT_ROLE`, or `None` to let the device derive its
    /// advertised role from what it is actually doing. Requires
    /// `CAP_IDENT`.
    pub ident_role: Option<u8>,
    /// `PROP_IDENT_MOBILE`. Present exactly when the device advertises
    /// `CAP_IDENT`.
    pub ident_mobile: Option<bool>,
    /// `PROP_DEV_DISCOVERABLE`: whether the device identity answers
    /// Identity Requests. Present exactly when the device advertises
    /// `CAP_DEV_IDENTITY`.
    pub dev_discoverable: Option<bool>,
    /// The flood-forwarding policy. Present exactly when the device
    /// advertises `CAP_REPEATER`.
    pub repeater: Option<UlcpRepeaterSettingsRecord>,
    /// `PROP_TZ_OFFSET` in minutes east of UTC. Present exactly when the
    /// device advertises `CAP_TIME`.
    ///
    /// The clock itself is not here: it is live state rather than
    /// configuration, is never saved, and is set with
    /// [`MobileUlcpSession::set_time`].
    pub tz_offset_min: Option<i16>,
    /// The positioning policy. Present exactly when the device advertises
    /// `CAP_GNSS`.
    pub gnss: Option<UlcpGnssSettingsRecord>,
}

/// Present one folded [`GnssSnapshot`] as the record Swift sees.
fn gnss_record(snapshot: &GnssSnapshot) -> UlcpGnssRecord {
    let bytes = snapshot.location();
    let placed = (!bytes.is_empty()).then(|| NodeLocation::from_bytes(bytes).center());
    UlcpGnssRecord {
        fix: UlcpFixKind::from_wire(snapshot.fix),
        location: bytes.to_vec(),
        latitude_deg: placed.map(|(_, latitude)| latitude.into()),
        longitude_deg: placed.map(|(longitude, _)| longitude.into()),
        location_cell_meters: (!bytes.is_empty())
            .then(|| ulcp_location_cell_meters(bytes.len() as u8))
            .flatten(),
        altitude_m: snapshot.altitude_m,
        accuracy_dm: snapshot.accuracy_dm,
        satellites_used: snapshot.sats_used,
        satellites_in_view: snapshot.sats_in_view,
    }
}

/// Approximate width, at the equator, of the cell one location precision
/// names — 2,500 km at one byte down to 15 cm at seven. `None` outside
/// 1–7.
///
/// This is what makes a precision mean something to a person: the setting
/// is a disclosure control, and how much it discloses is an area, not a
/// byte count. Fractional because the finest two cells are smaller than a
/// meter, which a whole number could only report as zero.
#[uniffi::export]
pub fn ulcp_location_cell_meters(precision_bytes: u8) -> Option<f64> {
    // 360° of longitude divided into 16^N cells, at 111,320 m per degree.
    (1..=MAX_PRECISION)
        .contains(&precision_bytes)
        .then(|| 360.0 * 111_320.0 / 16f64.powi(precision_bytes.into()))
}

/// `PROP_ALERT`: what the radio is doing to make itself findable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpAlertState {
    /// Nothing; the nominal state.
    None,
    /// The radio is making itself as conspicuous as its hardware allows
    /// — beeping, flashing, or both, depending on the board.
    Locate,
}

impl UlcpAlertState {
    fn from_wire(state: AlertState) -> Self {
        match state {
            AlertState::None => Self::None,
            AlertState::Locate => Self::Locate,
        }
    }

    fn to_wire(self) -> AlertState {
        match self {
            Self::None => AlertState::None,
            Self::Locate => AlertState::Locate,
        }
    }
}

/// Authoritative comparison of `PROP_HOST_KEY` with the selected phone identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpHostOwnership {
    Unknown,
    LocalIdentityUnavailable,
    Unsupported,
    Unclaimed,
    Ours,
    OtherHost,
}

/// Typed state published after each bounded ULCP-session transition.
///
/// Not `Eq`: a position is degrees, and floating point has no total
/// equality to offer.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct UlcpSessionSnapshotRecord {
    pub generation: u64,
    pub phase: UlcpSessionPhase,
    pub host_ownership: UlcpHostOwnership,
    pub device_key: Option<Vec<u8>>,
    pub device_name: Option<String>,
    pub battery: Option<UlcpBatteryRecord>,
    /// `PROP_ALERT`, or `None` on a radio without `CAP_ALERT`.
    ///
    /// Unlike `battery`, this is carried on *every* snapshot rather than
    /// reported once: it is state the UI mirrors, and the radio ends an
    /// alert on its own — a button press or its deadline — so the button
    /// must follow the radio rather than what the phone last asked for.
    pub alert: Option<UlcpAlertState>,
    /// A clock reading that arrived with this update, on a `CAP_TIME`
    /// device. Reported once — see [`UlcpTimeRecord`].
    pub time: Option<UlcpTimeRecord>,
    /// What the receiver reports, on a `CAP_GNSS` device, or `None` until
    /// the first positioning property is read. Mirrored like `alert`
    /// rather than taken like `battery`.
    pub gnss: Option<UlcpGnssRecord>,
    pub provisioning: Option<UlcpSyncRecord>,
}

/// What the platform adapter should do after a completed raw PHY request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpRawTransmitDisposition {
    Sent,
    Retry,
    Rejected,
}

/// Typed completion of one host-requested raw PHY transmission.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpRawTransmitResultRecord {
    pub transaction_id: u8,
    pub status_code: u32,
    pub status_name: String,
    pub disposition: UlcpRawTransmitDisposition,
}

/// A correlated CRP operation completed with a non-OK `PROP_LAST_STATUS`.
/// This is an operation failure, never evidence that the transport framing is
/// corrupt or that the BLE connection should be closed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpOperationErrorRecord {
    pub operation: String,
    pub status_code: u32,
    pub status_name: String,
}

/// Work produced by the Rust ULCP session. Frames are complete ULCP
/// frames; the platform adapter remains responsible for GATT segmentation and
/// write backpressure.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct UlcpSessionUpdateRecord {
    pub outbound_frames: Vec<Vec<u8>>,
    pub received_frames: Vec<UlcpReceivedFrameRecord>,
    pub snapshot: UlcpSessionSnapshotRecord,
    pub waiting_for_responses: bool,
    /// True while one host-requested raw PHY transmission is awaiting the
    /// radio's `PROP_LAST_STATUS` completion.
    pub raw_transmit_pending: bool,
    /// Transaction allocated by `transmit_raw` in this update, if any.
    pub raw_transmit_started_transaction_id: Option<u8>,
    /// Completion for the raw PHY transmission consumed by this update.
    /// Rejections are ordinary radio-level send failures, not malformed
    /// ULCP frames.
    pub raw_transmit_result: Option<UlcpRawTransmitResultRecord>,
    /// Non-transmit operation error consumed by this update. The ULCP
    /// session has already recovered to a stable stage and remains usable.
    pub operation_error: Option<UlcpOperationErrorRecord>,
}

/// One validated raw mesh frame delivered by the companion radio.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpReceivedFrameRecord {
    pub data: Vec<u8>,
    pub rssi_dbm: Option<i16>,
    pub lqi: Option<u8>,
    pub snr_cb: Option<i16>,
    pub was_buffered: bool,
    pub was_acknowledged: bool,
    pub age_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionStage {
    Idle,
    Initial,
    Inspection,
    Refreshing,
    Claiming,
    Saving,
    Configuring,
    SavingConfiguration,
    AwaitingHost,
    Attached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedResponse {
    Property(u32),
    Claim,
    Save,
    /// A `CMD_PROP_SET` of this property. The value written is not kept:
    /// the device's `CMD_PROP_IS` is what the property is worth, so there
    /// is nothing to compare it against.
    ConfigurationProperty(u32),
    SaveConfiguration,
    RawTransmit,
    /// A `CMD_PROP_INSERT` of this key into `PROP_DEV_PEERS`.
    DevPeerInsert(Vec<u8>),
    /// A `CMD_PROP_REMOVE` of this key from `PROP_DEV_PEERS`.
    DevPeerRemove(Vec<u8>),
    /// The `CMD_SAVE` chained behind a device-peer mutation.
    SaveDevPeers,
    /// A `CMD_PROP_INSERT` into `PROP_DEV_CHANNEL_KEYS`. Carries the derived
    /// identifier rather than the key, because the device confirms a channel
    /// mutation by echoing the identifier — key material is never read back.
    DevChannelInsert(Vec<u8>),
    /// A `CMD_PROP_REMOVE` from `PROP_DEV_CHANNEL_KEYS`, selected by key and
    /// confirmed by identifier.
    DevChannelRemove(Vec<u8>),
    /// The `CMD_SAVE` chained behind a device-channel mutation.
    SaveDevChannels,
    /// One `CMD_PROP_INSERT` in the host channel-key reconciliation, carrying
    /// the keys still to be sent. `ALREADY` is success here: a channel key is
    /// its own item, so a duplicate insert asserts a state that already holds.
    HostChannelInsert(VecDeque<Vec<u8>>),
    /// The whole-table `CMD_PROP_SET` used when the device holds a channel
    /// this phone cannot name, and so cannot select for removal.
    HostChannelReplace,
}

struct UlcpSessionState {
    generation: u64,
    /// Which relationship this session represents. Held here, not only on
    /// the object, because ownership resolution is what it changes: an
    /// administrative session reports foreign ownership truthfully but
    /// never waits for a host decision it will not make.
    mode: UlcpAttachMode,
    stage: SessionStage,
    tids: TidAllocator,
    expected: HashMap<u8, ExpectedResponse>,
    selected_host_key: Option<[u8; 32]>,
    radio_host_key: Option<Vec<u8>>,
    host_key_unsupported: bool,
    responses: HashMap<u32, UlcpPropertyFrameRecord>,
    inspection_queue: VecDeque<u32>,
    configuration_queue: VecDeque<(u32, Vec<u8>)>,
    device_key: Option<Vec<u8>>,
    device_name: Option<String>,
    /// A battery snapshot this session has received and not yet reported.
    ///
    /// Deliberately *not* a cache: it is taken when an update record is
    /// built, so `UlcpSessionSnapshotRecord::battery` means "a fresh
    /// measurement arrived with this update" rather than "the last
    /// measurement ever seen". Battery is live telemetry — a consumer that
    /// timestamps what it receives would otherwise restamp a minutes-old
    /// reading on every unrelated update and report it as current.
    battery: Option<UlcpBatteryRecord>,
    /// The radio's live `PROP_ALERT`, or `None` until one is read (and
    /// permanently on a radio without `CAP_ALERT`). Held rather than
    /// taken: it is a state to mirror, not an event to report once.
    alert: Option<UlcpAlertState>,
    /// A `PROP_TIME` reading not yet reported. Taken, for the reason
    /// [`UlcpTimeRecord`] gives.
    time: Option<UlcpTimeRecord>,
    /// The receiver's view of the world, folded from whichever
    /// positioning properties have arrived. Held: the properties are
    /// announced separately, so taking it would report a fix without the
    /// satellite count that came a frame earlier.
    gnss: Option<GnssSnapshot>,
    provisioning: Option<UlcpSyncRecord>,
    stage_failure_pending: bool,
}

impl Default for UlcpSessionState {
    fn default() -> Self {
        Self {
            generation: 0,
            mode: UlcpAttachMode::Tethered,
            stage: SessionStage::Idle,
            tids: TidAllocator::new(),
            expected: HashMap::new(),
            selected_host_key: None,
            radio_host_key: None,
            host_key_unsupported: false,
            responses: HashMap::new(),
            inspection_queue: VecDeque::new(),
            configuration_queue: VecDeque::new(),
            device_key: None,
            device_name: None,
            battery: None,
            alert: None,
            time: None,
            gnss: None,
            provisioning: None,
            stage_failure_pending: false,
        }
    }
}

/// The two relationships a phone can have with a radio.
///
/// They are different things with different lifecycles, and Swift should
/// model them as different objects: "my radio" is exactly one, tethered,
/// and re-provisioned on every attach; "radios I administer" is any
/// number, configured but never claimed. One list must not serve both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpAttachMode {
    /// This phone is the radio's tethered host: it claims the radio and
    /// the radio filters, queues and acknowledges on its behalf.
    #[default]
    Tethered,
    /// This phone is administering the radio without claiming it. A
    /// phone commissioning ten repeaters must not write its host key on
    /// any of them.
    Administrative,
}

/// Stateful mobile host session for the ULCP.
///
/// This is the protocol boundary: it consumes complete reassembled ULCP
/// frames and owns TIDs, response matching, capability-driven synchronization,
/// host ownership, and claim/save choreography. Platform code owns only the
/// transport lifecycle, byte shuttling, and timers.
#[derive(uniffi::Object)]
pub struct MobileUlcpSession {
    inner: Mutex<UlcpSessionState>,
    mode: UlcpAttachMode,
}

#[uniffi::export]
impl MobileUlcpSession {
    /// A session for the phone's own radio: the one it tethers to.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::with_mode(UlcpAttachMode::Tethered))
    }

    /// A session for a radio this phone administers but does not claim.
    /// [`Self::claim`] is refused; everything else behaves identically.
    #[uniffi::constructor]
    pub fn administrative() -> Arc<Self> {
        Arc::new(Self::with_mode(UlcpAttachMode::Administrative))
    }

    /// Which relationship this session represents.
    pub fn attach_mode(&self) -> UlcpAttachMode {
        self.mode
    }

    /// Begin post-attach synchronization for a new transport generation.
    pub fn begin(
        &self,
        selected_host_key: Option<Vec<u8>>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let selected_host_key = selected_host_key
            .map(|key| {
                key.try_into()
                    .map_err(|_| MobileError::InvalidPublicKeyLength)
            })
            .transpose()?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let generation = state.generation.wrapping_add(1);
        *state = UlcpSessionState {
            generation,
            mode: self.mode,
            stage: SessionStage::Initial,
            selected_host_key,
            ..UlcpSessionState::default()
        };

        let mut outbound = Vec::new();
        for property in [
            prop::LAST_STATUS,
            prop::PROTOCOL_VERSION,
            prop::CAPS,
            prop::DEV_KEY,
            prop::DEV_NAME,
            prop::BATTERY,
            prop::HOST_KEY,
        ] {
            outbound.push(state.get_property(property)?);
        }
        Ok(state.update(outbound))
    }

    /// Replace an unclaimed or other-host configuration with this phone's key.
    pub fn claim(&self, host_key: Vec<u8>) -> Result<UlcpSessionUpdateRecord, MobileError> {
        // Commissioning is not tethering: an administrative session
        // configures the radio's own domain and never writes a host key.
        if self.mode == UlcpAttachMode::Administrative {
            return Err(MobileError::AdministrativeSession);
        }
        let host_key: [u8; 32] = host_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::AwaitingHost
            || !matches!(
                state.ownership(),
                UlcpHostOwnership::Unclaimed | UlcpHostOwnership::OtherHost
            )
        {
            return Err(MobileError::InvalidUlcpFrame);
        }
        state.selected_host_key = Some(host_key);
        state.stage = SessionStage::Claiming;
        state.expected.clear();
        let tid = state.allocate_tid();
        state.expected.insert(tid, ExpectedResponse::Claim);
        let frame = ulcp_prop_set(tid, prop::HOST_KEY, host_key.to_vec())?;
        Ok(state.update(vec![frame]))
    }

    /// Erase ALL mutable state on the radio (saved provisioning, device
    /// identity, BLE bonds, pairing PIN, every persisted journal) and
    /// reboot it. The radio does not reply — the reset drops the link —
    /// so this is fire-and-forget: send the frame, then treat the ensuing
    /// disconnect as completion. Permitted from any stage so a misbehaving
    /// radio can always be wiped; unlike `claim`/`configure` it makes no
    /// stage or ownership demands.
    pub fn factory_reset(&self) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let tid = state.allocate_tid();
        // Deliberately no ExpectedResponse: the device wipes storage and
        // reboots without answering, so `update` reports
        // waiting_for_responses = false and the caller does not block.
        let frame = ulcp_factory_reset(tid)?;
        Ok(state.update(vec![frame]))
    }

    /// Start or stop the radio's locate alert (`PROP_ALERT`) so a
    /// misplaced radio can be found.
    ///
    /// Not part of `configure_device`, and never saved: this is live
    /// behavior rather than configuration, and it deliberately survives
    /// the phone walking out of BLE range — which is precisely when a
    /// search needs it. What ends it is this call, a button press at the
    /// radio, or the radio's own deadline; the latter two arrive as an
    /// unsolicited `PROP_ALERT` carried on the session snapshot.
    ///
    /// Re-sending `Locate` while an alert is running restarts that
    /// deadline, which is how a longer search keeps the alert alive.
    pub fn set_alert(&self, state: UlcpAlertState) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut session = self.inner.lock().expect("ULCP session mutex poisoned");
        if session.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        if !session.has_capability(cap::ALERT)? {
            return Err(MobileError::UnsupportedCapability);
        }
        let mut value = [0u8; pui::MAX_LEN];
        let len = pui::encode(state.to_wire().code(), &mut value)
            .map_err(|_| MobileError::InvalidUlcpFrame)?;
        let tid = session.allocate_tid();
        session
            .expected
            .insert(tid, ExpectedResponse::Property(prop::ALERT));
        let frame = ulcp_prop_set(tid, prop::ALERT, value[..len].to_vec())?;
        Ok(session.update(vec![frame]))
    }

    /// Set — or clear — the device's wall clock (`PROP_TIME`).
    ///
    /// Live state rather than configuration, and never saved: an epoch
    /// written to flash would come back arbitrarily wrong, since nothing
    /// bounds how long a device spends powered off. So this is not part
    /// of [`Self::configure_device`], which carries the time *zone* —
    /// where the device is meant to be is worth persisting even when what
    /// time it is is not.
    ///
    /// `None` clears the clock back to unknown, which is what a device
    /// reports before its first fix. On a device whose receiver is
    /// trusted for time, a fix will overwrite whatever is set here.
    ///
    /// The device answers with the epoch it now holds; that answer, not
    /// the value written, is what the session snapshot reports.
    pub fn set_time(
        &self,
        epoch_seconds: Option<u32>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut session = self.inner.lock().expect("ULCP session mutex poisoned");
        if session.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        if !session.has_capability(cap::TIME)? {
            return Err(MobileError::UnsupportedCapability);
        }
        let value = epoch_seconds
            .map(|epoch| epoch.to_le_bytes().to_vec())
            .unwrap_or_default();
        let tid = session.allocate_tid();
        session
            .expected
            .insert(tid, ExpectedResponse::Property(prop::TIME));
        let frame = ulcp_prop_set(tid, prop::TIME, value)?;
        Ok(session.update(vec![frame]))
    }

    /// Apply, verify, and persist a complete radio-settings snapshot.
    pub fn configure(
        &self,
        settings: UlcpRadioSettingsRecord,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        validate_radio_settings(&settings, &state)?;

        state.expected.clear();
        state.configuration_queue = state.writable(configuration_values(settings, Vec::new()));
        let mut outbound = Vec::new();
        state.start_configuration(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Apply, verify, and persist a complete configuration of the device's
    /// own domain: its radio, the role it advertises, and whether and how
    /// it forwards for the mesh on its own.
    ///
    /// This is what commissioning writes. It touches nothing in the host
    /// domain — no host key, no filters, no queues — so it is equally
    /// valid from an administrative session on someone else's radio and
    /// from a tethered session on this phone's own.
    pub fn configure_device(
        &self,
        configuration: UlcpDeviceConfigRecord,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        validate_radio_settings(&configuration.radio, &state)?;
        let device_values = validate_device_settings(&configuration, &state)?;

        state.expected.clear();
        state.configuration_queue =
            state.writable(configuration_values(configuration.radio, device_values));
        let mut outbound = Vec::new();
        state.start_configuration(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Re-read every capability-gated property represented by the mobile
    /// snapshot. The existing snapshot remains usable while the bounded
    /// refresh is in flight; authoritative provisioning is published when
    /// the full capability-gated read completes.
    pub fn refresh(&self) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached || !state.expected.is_empty() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let capabilities = state
            .responses
            .get(&prop::CAPS)
            .ok_or(MobileError::InvalidUlcpFrame)?
            .value
            .clone();
        state.inspection_queue = ulcp_refresh_properties(capabilities)?.into();
        let mut outbound = Vec::new();
        state.start_refresh(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Store one channel key on the radio's device identity
    /// (`PROP_DEV_CHANNEL_KEYS`), then persist with a chained `CMD_SAVE` when
    /// the device can.
    ///
    /// This is the device's own channel membership, independent of the phone's:
    /// it is what the device uses for its own advertisements, blind-unicast
    /// addressing, and repeater filtering, and it survives host replacement.
    ///
    /// Requires an attached, otherwise-idle session on a device advertising
    /// `CAP_DEV_IDENTITY`, and the device additionally requires an encrypted
    /// link before it will accept key material. Failures surface as
    /// `operation_error` with the device's status name — `NOMEM` when the list
    /// is full (capacity [`ulcp_max_dev_channels`]), `ALREADY` when the key is
    /// already stored, which callers should treat as success.
    pub fn insert_device_channel_key(
        &self,
        channel_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let id = dev_channel_id(&channel_key)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_dev_peer_operation()?;
        let tid = state.allocate_tid();
        state
            .expected
            .insert(tid, ExpectedResponse::DevChannelInsert(id));
        let frame = ulcp_prop_insert(tid, prop::DEV_CHANNEL_KEYS, &channel_key)?;
        Ok(state.update(vec![frame]))
    }

    /// Remove one channel key from the radio's device identity
    /// (`PROP_DEV_CHANNEL_KEYS`), then persist with a chained `CMD_SAVE` when
    /// the device can.
    ///
    /// The remove selector is the key itself, so only a channel the caller
    /// still holds the key for can be removed this way. Same preconditions as
    /// [`Self::insert_device_channel_key`]; `ITEM_NOT_FOUND` surfaces as
    /// `operation_error` and callers should treat it as success.
    pub fn remove_device_channel_key(
        &self,
        channel_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let id = dev_channel_id(&channel_key)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_dev_peer_operation()?;
        let tid = state.allocate_tid();
        state
            .expected
            .insert(tid, ExpectedResponse::DevChannelRemove(id));
        let frame = ulcp_prop_remove(tid, prop::DEV_CHANNEL_KEYS, &channel_key)?;
        Ok(state.update(vec![frame]))
    }

    /// Make the radio's host channel-key table (`PROP_HOST_CHANNEL_KEYS`)
    /// match the phone identity's joined channels.
    ///
    /// The radio needs these keys to recognize multicast and blind-unicast
    /// traffic addressed to channels this phone has joined, and to queue it
    /// while the phone is away. That is bookkeeping between the app and its
    /// own radio, not a user-facing setting: callers reconcile on attach and
    /// after every join or leave, and never surface it.
    ///
    /// The host domain is volatile — the device does not persist it — so no
    /// `CMD_SAVE` is chained and reconciling on attach is what makes it stick.
    /// Requires an attached, idle session on a device advertising
    /// `CAP_HOST_KEYS`; otherwise the table is not this session's to manage
    /// and the call reports that the capability is missing.
    ///
    /// Returns without any frames when the device already holds exactly the
    /// requested set.
    pub fn reconcile_host_channel_keys(
        &self,
        keys: Vec<Vec<u8>>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut desired = VecDeque::with_capacity(keys.len());
        let mut desired_ids = Vec::with_capacity(keys.len());
        for key in keys {
            desired_ids.push(dev_channel_id(&key)?);
            desired.push_back(key);
        }

        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached || !state.expected.is_empty() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        if !state.has_capability(cap::HOST_KEYS)? {
            return Err(MobileError::UnsupportedCapability);
        }

        let current = state
            .responses
            .get(&prop::HOST_CHANNEL_KEYS)
            .map(|entry| entry.value.clone())
            .unwrap_or_default();
        let current_ids: Vec<Vec<u8>> = current
            .chunks(items::CHANNEL_ID_LEN)
            .map(<[u8]>::to_vec)
            .collect();

        // Shedding a channel needs its key as the remove selector, and an
        // identifier this phone cannot derive is one whose key it does not
        // hold. The table is small, so one whole-table write says everything.
        if current_ids.iter().any(|id| !desired_ids.contains(id)) {
            let table: Vec<u8> = desired.iter().flatten().copied().collect();
            let tid = state.allocate_tid();
            state
                .expected
                .insert(tid, ExpectedResponse::HostChannelReplace);
            state.set_host_channel_ids(&desired_ids);
            let frame = ulcp_prop_set(tid, prop::HOST_CHANNEL_KEYS, table)?;
            return Ok(state.update(vec![frame]));
        }

        desired.retain(|key| {
            !current_ids
                .iter()
                .any(|id| dev_channel_id(key).is_ok_and(|derived| &derived == id))
        });
        match state.next_host_channel_insert(desired) {
            Some(frame) => Ok(state.update(vec![frame])),
            None => Ok(state.update(Vec::new())),
        }
    }

    /// Store one peer public key on the radio's device identity
    /// (`PROP_DEV_PEERS`), then persist with a chained `CMD_SAVE` when the
    /// device can.
    ///
    /// Requires an attached, otherwise-idle session on a device advertising
    /// `CAP_DEV_IDENTITY`. Failures surface as `operation_error` with the
    /// device's status name — `NOMEM` when the list is full (capacity
    /// [`ulcp_max_dev_peers`]), `ALREADY` when the key is already stored,
    /// which callers should treat as success.
    pub fn insert_device_peer(
        &self,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_dev_peer_operation()?;
        let tid = state.allocate_tid();
        state
            .expected
            .insert(tid, ExpectedResponse::DevPeerInsert(public_key.to_vec()));
        let frame = ulcp_prop_insert(tid, prop::DEV_PEERS, &public_key)?;
        Ok(state.update(vec![frame]))
    }

    /// Remove one peer public key from the radio's device identity
    /// (`PROP_DEV_PEERS`), then persist with a chained `CMD_SAVE` when the
    /// device can.
    ///
    /// Same preconditions as [`Self::insert_device_peer`]. `ITEM_NOT_FOUND`
    /// surfaces as `operation_error` and callers should treat it as success —
    /// the key is not on the device either way.
    pub fn remove_device_peer(
        &self,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_dev_peer_operation()?;
        let tid = state.allocate_tid();
        state
            .expected
            .insert(tid, ExpectedResponse::DevPeerRemove(public_key.to_vec()));
        let frame = ulcp_prop_remove(tid, prop::DEV_PEERS, &public_key)?;
        Ok(state.update(vec![frame]))
    }

    /// Queue one complete raw UMSH frame on `STR_PHY_RAW`.
    ///
    /// The platform adapter supplies only opaque bytes from `MobileMeshSession`;
    /// Rust owns the ULCP command, stream identifier, metadata, TID, and
    /// confirmation matching. `nocca` sets `TX_FLAG_NOCCA` so the device
    /// transmits without its pre-transmit channel-activity check — used for
    /// immediate MAC acks (see [`MobileMeshOutboundFrameRecord::nocca`]).
    pub fn transmit_raw(
        &self,
        data: Vec<u8>,
        nocca: bool,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let raw_pipeline_active = state
            .expected
            .values()
            .all(|expected| matches!(expected, ExpectedResponse::RawTransmit));
        if state.stage != SessionStage::Attached || !raw_pipeline_active || data.is_empty() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let mut available_tid = None;
        for _ in 0..usize::from(frame::TID_MAX) {
            let candidate = state.allocate_tid();
            if !state.expected.contains_key(&candidate) {
                available_tid = Some(candidate);
                break;
            }
        }
        let tid = available_tid.ok_or(MobileError::InvalidUlcpFrame)?;
        state.expected.insert(tid, ExpectedResponse::RawTransmit);
        let mut metadata = [0u8; umsh_ulcp::TxMeta::WIRE_LEN];
        let flags = if nocca {
            umsh_ulcp::meta::TX_FLAG_NOCCA
        } else {
            0
        };
        umsh_ulcp::TxMeta {
            flags,
            ..umsh_ulcp::TxMeta::default()
        }
        .encode(&mut metadata)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
        let mut frame = vec![0u8; data.len() + 16];
        let len = umsh_ulcp::frame::str_send(
            &mut frame,
            tid,
            umsh_ulcp::ids::stream::PHY_RAW,
            &data,
            &metadata,
        )
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
        frame.truncate(len);
        let mut update = state.update(vec![frame]);
        update.raw_transmit_started_transaction_id = Some(tid);
        Ok(update)
    }

    /// Consume one complete ULCP frame and advance the session reducer.
    pub fn consume(&self, frame: Vec<u8>) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let parsed = Frame::parse(&frame).map_err(|_| MobileError::InvalidUlcpFrame)?;
        if parsed.command() == Some(Cmd::StrRecv) {
            if parsed.header.tid() != frame::TID_UNSOLICITED {
                return Err(MobileError::InvalidUlcpFrame);
            }
            let payload =
                StreamPayload::parse(parsed.payload).map_err(|_| MobileError::InvalidUlcpFrame)?;
            if payload.stream != umsh_ulcp::ids::stream::PHY_RAW {
                return Err(MobileError::InvalidUlcpFrame);
            }
            let metadata = BufferedRxMeta::decode(payload.metadata)
                .map_err(|_| MobileError::InvalidUlcpFrame)?;
            let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
            if state.stage == SessionStage::Idle {
                return Err(MobileError::InvalidUlcpFrame);
            }
            return Ok(state.update_with_received(vec![UlcpReceivedFrameRecord {
                data: payload.data.to_vec(),
                rssi_dbm: metadata.rx.rssi_dbm,
                lqi: metadata.rx.lqi.map(core::num::NonZeroU8::get),
                snr_cb: metadata.rx.snr_cb,
                was_buffered: metadata.flags & RX_FLAG_BUFFERED != 0,
                was_acknowledged: metadata.flags & RX_FLAG_ACKED != 0,
                age_seconds: metadata.age_s,
            }]));
        }
        let response = inspect_ulcp_property_frame(frame)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let mut outbound = Vec::new();
        let mut raw_transmit_result = None;
        let mut operation_error = None;

        if response.transaction_id == frame::TID_UNSOLICITED {
            if response.command == Cmd::PropIs as u8 {
                state
                    .responses
                    .insert(response.property_id, response.clone());
            }
            state.apply_property(&response)?;
            state.refresh_attached_snapshot(Some(response.property_id))?;
            return Ok(state.update(outbound));
        }

        let expected = state
            .expected
            .remove(&response.transaction_id)
            .ok_or(MobileError::InvalidUlcpFrame)?;
        match expected {
            ExpectedResponse::Property(property) => {
                if response.property_id == prop::LAST_STATUS && property != prop::LAST_STATUS {
                    // A capability-gated property the device declines is one
                    // unknown setting, not an unusable device: drop any value
                    // cached from an earlier read so the reduction reports it
                    // as unreadable, and carry on with the rest of the queue.
                    let expected_property = matches!(
                        state.stage,
                        SessionStage::Inspection | SessionStage::Refreshing
                    );
                    if expected_property {
                        state.responses.remove(&property);
                    } else {
                        operation_error = Some(ulcp_operation_error(
                            format!("read property {property}"),
                            response.value.as_slice(),
                        )?);
                        let optional_initial_property = state.stage == SessionStage::Initial
                            && matches!(
                                property,
                                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY | prop::HOST_KEY
                            );
                        state.stage_failure_pending |= !optional_initial_property;
                        if state.stage == SessionStage::Initial && property == prop::HOST_KEY {
                            state.host_key_unsupported = true;
                        }
                    }
                } else {
                    if response.property_id != property || response.command != Cmd::PropIs as u8 {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    state.responses.insert(property, response.clone());
                    state.apply_property(&response)?;
                }
            }
            ExpectedResponse::Claim => {
                if response.property_id == prop::LAST_STATUS {
                    operation_error = Some(ulcp_operation_error(
                        "claim host identity".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    if response.property_id != prop::HOST_KEY
                        || response.command != Cmd::PropIs as u8
                    {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    // Whatever the device reports is its host key, even if
                    // it is not the one just written — a claim that did not
                    // take means this radio belongs to someone else, which
                    // `ownership()` reads off this value and reports as
                    // `OtherHost`. That is an answer, not a broken session.
                    state.radio_host_key = Some(response.value.clone());
                    state.responses.insert(prop::HOST_KEY, response);
                    if state.has_capability(cap::SAVE)? {
                        state.stage = SessionStage::Saving;
                        let tid = state.allocate_tid();
                        state.expected.insert(tid, ExpectedResponse::Save);
                        outbound.push(ulcp_save(tid)?);
                    } else {
                        state.start_inspection(&mut outbound)?;
                    }
                }
            }
            ExpectedResponse::Save => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    operation_error = Some(ulcp_operation_error(
                        "save claimed host identity".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    state.start_inspection(&mut outbound)?;
                }
            }
            ExpectedResponse::ConfigurationProperty(property) => {
                if response.property_id == prop::LAST_STATUS {
                    operation_error = Some(ulcp_operation_error(
                        format!("set property {property}"),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                    // The status frame describes the write, not the property.
                    // Filing it under the property would leave the snapshot
                    // reducing a status code as that property's value.
                    state.responses.remove(&property);
                } else if response.property_id != property || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                } else {
                    // A `CMD_PROP_IS` is the device's authoritative value,
                    // whatever was written. It reports what the device holds
                    // — clamped to hardware, reduced to what it supports,
                    // changed for a reason this host has no view of — and a
                    // value differing from the write is that report, not a
                    // fault. The snapshot published to the UI is what the
                    // device says, never what was asked for. Failure is a
                    // `PROP_LAST_STATUS`, handled above.
                    state.responses.insert(property, response.clone());
                    state.apply_property(&response)?;
                }
            }
            ExpectedResponse::SaveConfiguration => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    operation_error = Some(ulcp_operation_error(
                        "save radio configuration".to_owned(),
                        response.value.as_slice(),
                    )?);
                    state.stage_failure_pending = true;
                } else {
                    state.finish_configuration()?;
                }
            }
            ExpectedResponse::RawTransmit => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                let status_code = inspect_ulcp_status(response.value)?;
                let status = umsh_ulcp::Status(status_code);
                raw_transmit_result = Some(UlcpRawTransmitResultRecord {
                    transaction_id: response.transaction_id,
                    status_code,
                    status_name: format!("{status:?}"),
                    disposition: if status == umsh_ulcp::Status::OK {
                        UlcpRawTransmitDisposition::Sent
                    } else if status == umsh_ulcp::Status::BUSY
                        || status == umsh_ulcp::Status::CCA_FAILURE
                    {
                        // Both are transient channel-contention refusals: the
                        // frame never left the radio, so retry with backoff.
                        UlcpRawTransmitDisposition::Retry
                    } else {
                        UlcpRawTransmitDisposition::Rejected
                    },
                });
            }
            ExpectedResponse::HostChannelInsert(mut remaining) => {
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        "provision host channel key".to_owned(),
                        response.value.as_slice(),
                    )?;
                    // A channel key is its own item, so ALREADY asserts the
                    // state that was asked for. Anything else — NOMEM above
                    // all — stops the pass; the phone still runs its own MAC
                    // while attached, so this degrades radio-side filtering
                    // rather than the user's ability to use the channel.
                    if error.status_code != umsh_ulcp::Status::ALREADY.0 {
                        operation_error = Some(error);
                        state.refresh_attached_snapshot(None)?;
                        remaining.clear();
                    }
                } else if response.property_id != prop::HOST_CHANNEL_KEYS
                    || response.command != Cmd::PropInserted as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if let Some(frame) = state.next_host_channel_insert(remaining) {
                    outbound.push(frame);
                } else {
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::HostChannelReplace => {
                if response.property_id == prop::LAST_STATUS {
                    operation_error = Some(ulcp_operation_error(
                        "provision host channel keys".to_owned(),
                        response.value.as_slice(),
                    )?);
                } else if response.property_id != prop::HOST_CHANNEL_KEYS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                state.refresh_attached_snapshot(None)?;
            }
            ExpectedResponse::DevChannelInsert(id) => {
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        "insert device channel key".to_owned(),
                        response.value.as_slice(),
                    )?;
                    // ALREADY is the device saying the channel is stored.
                    if error.status_code == umsh_ulcp::Status::ALREADY.0 {
                        state.patch_dev_channels(&id, true);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != prop::DEV_CHANNEL_KEYS
                        || response.command != Cmd::PropInserted as u8
                        || response.value != id
                    {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    state.patch_dev_channels(&id, true);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state
                            .expected
                            .insert(tid, ExpectedResponse::SaveDevChannels);
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::DevChannelRemove(id) => {
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        "remove device channel key".to_owned(),
                        response.value.as_slice(),
                    )?;
                    if error.status_code == umsh_ulcp::Status::ITEM_NOT_FOUND.0 {
                        state.patch_dev_channels(&id, false);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != prop::DEV_CHANNEL_KEYS
                        || response.command != Cmd::PropRemoved as u8
                        || response.value != id
                    {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    state.patch_dev_channels(&id, false);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state
                            .expected
                            .insert(tid, ExpectedResponse::SaveDevChannels);
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::SaveDevChannels => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    operation_error = Some(ulcp_operation_error(
                        "save device channel keys".to_owned(),
                        response.value.as_slice(),
                    )?);
                }
            }
            ExpectedResponse::DevPeerInsert(item) => {
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        "insert device peer".to_owned(),
                        response.value.as_slice(),
                    )?;
                    // ALREADY is the device saying the key is stored; keep
                    // the cache truthful even though the operation "failed".
                    if error.status_code == umsh_ulcp::Status::ALREADY.0 {
                        state.patch_dev_peers(&item, true);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != prop::DEV_PEERS
                        || response.command != Cmd::PropInserted as u8
                        || response.value != item
                    {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    state.patch_dev_peers(&item, true);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state.expected.insert(tid, ExpectedResponse::SaveDevPeers);
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::DevPeerRemove(item) => {
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        "remove device peer".to_owned(),
                        response.value.as_slice(),
                    )?;
                    // ITEM_NOT_FOUND means the key is not on the device,
                    // which is the state the caller asked for.
                    if error.status_code == umsh_ulcp::Status::ITEM_NOT_FOUND.0 {
                        state.patch_dev_peers(&item, false);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != prop::DEV_PEERS
                        || response.command != Cmd::PropRemoved as u8
                        || response.value != item
                    {
                        return Err(MobileError::InvalidUlcpFrame);
                    }
                    state.patch_dev_peers(&item, false);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state.expected.insert(tid, ExpectedResponse::SaveDevPeers);
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::SaveDevPeers => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    // The live mutation stuck; only persistence failed. The
                    // session stays attached and the caller sees the same
                    // `saved` warning path a failed configuration save uses.
                    operation_error = Some(ulcp_operation_error(
                        "save device peers".to_owned(),
                        response.value.as_slice(),
                    )?);
                }
            }
        }

        if state.expected.is_empty() {
            if state.stage_failure_pending {
                state.stage_failure_pending = false;
                state.recover_from_operation_failure(&mut outbound)?;
            } else {
                state.advance_completed_stage(&mut outbound)?;
            }
        }
        Ok(state.update_with(outbound, Vec::new(), raw_transmit_result, operation_error))
    }

    /// Invalidate all outstanding transactions for a disconnected transport.
    pub fn reset(&self) -> UlcpSessionUpdateRecord {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let generation = state.generation.wrapping_add(1);
        *state = UlcpSessionState {
            generation,
            mode: self.mode,
            ..UlcpSessionState::default()
        };
        state.update(Vec::new())
    }

    /// Abandon raw transactions whose GATT writes were rejected locally.
    /// Their late correlated responses are ignored once; the attachment and
    /// all non-raw session state remain intact.
    pub fn abandon_raw_transmits(&self, transaction_ids: Vec<u8>) -> UlcpSessionUpdateRecord {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        for tid in transaction_ids {
            if matches!(
                state.expected.get(&tid),
                Some(ExpectedResponse::RawTransmit)
            ) {
                state.expected.remove(&tid);
            }
        }
        state.update(Vec::new())
    }
}

impl MobileUlcpSession {
    fn with_mode(mode: UlcpAttachMode) -> Self {
        Self {
            inner: Mutex::new(UlcpSessionState {
                mode,
                ..UlcpSessionState::default()
            }),
            mode,
        }
    }
}

impl UlcpSessionState {
    fn allocate_tid(&mut self) -> u8 {
        self.tids.allocate()
    }

    fn get_property(&mut self, property: u32) -> Result<Vec<u8>, MobileError> {
        let tid = self.allocate_tid();
        self.expected
            .insert(tid, ExpectedResponse::Property(property));
        ulcp_prop_get(tid, property)
    }

    fn phase(&self) -> UlcpSessionPhase {
        match self.stage {
            SessionStage::Idle => UlcpSessionPhase::Idle,
            SessionStage::Initial | SessionStage::Inspection | SessionStage::Saving => {
                UlcpSessionPhase::Synchronizing
            }
            // A refresh deliberately preserves the attached phase so live UI
            // does not disappear while fresh authoritative values are read.
            SessionStage::Refreshing => UlcpSessionPhase::Attached,
            SessionStage::AwaitingHost => UlcpSessionPhase::AwaitingHost,
            SessionStage::Claiming => UlcpSessionPhase::Claiming,
            SessionStage::Configuring | SessionStage::SavingConfiguration => {
                UlcpSessionPhase::Configuring
            }
            SessionStage::Attached => UlcpSessionPhase::Attached,
        }
    }

    fn ownership(&self) -> UlcpHostOwnership {
        if self.host_key_unsupported {
            return UlcpHostOwnership::Unsupported;
        }
        let Some(radio_key) = self.radio_host_key.as_deref() else {
            return UlcpHostOwnership::Unknown;
        };
        if radio_key.is_empty() {
            return UlcpHostOwnership::Unclaimed;
        }
        match self.selected_host_key {
            None => UlcpHostOwnership::LocalIdentityUnavailable,
            Some(selected) if radio_key == selected => UlcpHostOwnership::Ours,
            Some(_) => UlcpHostOwnership::OtherHost,
        }
    }

    fn update(&mut self, outbound_frames: Vec<Vec<u8>>) -> UlcpSessionUpdateRecord {
        self.update_with(outbound_frames, Vec::new(), None, None)
    }

    fn update_with_received(
        &mut self,
        received_frames: Vec<UlcpReceivedFrameRecord>,
    ) -> UlcpSessionUpdateRecord {
        self.update_with(Vec::new(), received_frames, None, None)
    }

    fn update_with(
        &mut self,
        outbound_frames: Vec<Vec<u8>>,
        received_frames: Vec<UlcpReceivedFrameRecord>,
        raw_transmit_result: Option<UlcpRawTransmitResultRecord>,
        operation_error: Option<UlcpOperationErrorRecord>,
    ) -> UlcpSessionUpdateRecord {
        let raw_transmit_pending = self
            .expected
            .values()
            .any(|expected| matches!(expected, ExpectedResponse::RawTransmit));
        UlcpSessionUpdateRecord {
            outbound_frames,
            received_frames,
            snapshot: UlcpSessionSnapshotRecord {
                generation: self.generation,
                phase: self.phase(),
                host_ownership: self.ownership(),
                device_key: self.device_key.clone(),
                device_name: self.device_name.clone(),
                // Taken, not cloned: reported once, on the update that
                // actually carries a new measurement.
                battery: self.battery.take(),
                alert: self.alert,
                time: self.time.take(),
                gnss: self.gnss.as_ref().map(gnss_record),
                provisioning: self.provisioning.clone(),
            },
            waiting_for_responses: !self.expected.is_empty(),
            raw_transmit_pending,
            raw_transmit_started_transaction_id: None,
            raw_transmit_result,
            operation_error,
        }
    }

    fn apply_property(&mut self, response: &UlcpPropertyFrameRecord) -> Result<(), MobileError> {
        if response.command != Cmd::PropIs as u8 {
            // Insert/remove notifications are valid protocol frames, but none
            // of the mobile snapshot fields are multi-value payloads.
            return Ok(());
        }
        match response.property_id {
            prop::DEV_KEY => {
                if response.value.is_empty() {
                    self.device_key = None;
                } else if response.value.len() == items::PUBLIC_KEY_LEN {
                    self.device_key = Some(response.value.clone());
                } else {
                    return Err(MobileError::InvalidUlcpFrame);
                }
            }
            prop::DEV_NAME => {
                let name = core::str::from_utf8(&response.value)
                    .map_err(|_| MobileError::InvalidUlcpFrame)?;
                self.device_name = (!name.is_empty()).then(|| name.to_owned());
            }
            prop::BATTERY => {
                self.battery = Some(inspect_ulcp_battery(response.value.clone())?);
            }
            prop::ALERT => {
                // Arrives both as the answer to a write and unsolicited,
                // when the radio ends the alert itself.
                self.alert = Some(inspect_ulcp_alert(response.value.clone())?);
            }
            prop::TIME => {
                // Announced when the clock goes from unknown to known and
                // whenever it steps, which is how a phone learns the
                // device found the time on its own.
                self.time = Some(UlcpTimeRecord {
                    epoch_seconds: decode_optional(&response.value, decode_u32)?,
                });
            }
            key if umsh_ulcp::gnss::is_positioning_property(key) => {
                // Position and fix are announced; the rest arrive when
                // read. Folding rather than replacing is what lets one
                // announced property update the view without erasing the
                // others.
                self.gnss
                    .get_or_insert(GnssSnapshot::SEARCHING)
                    .absorb(key, &response.value)
                    .map_err(|_| MobileError::InvalidUlcpFrame)?;
            }
            prop::HOST_KEY => {
                if !response.value.is_empty() && response.value.len() != items::PUBLIC_KEY_LEN {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                self.radio_host_key = Some(response.value.clone());
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether synchronization may proceed straight to inspection without
    /// pausing for the user to decide about host ownership.
    ///
    /// A tethered session must pause: it is about to become the radio's
    /// host, and taking a radio from another phone is a decision only the
    /// user can make. An administrative session never claims anything, so
    /// there is no decision to pause for — whose radio this is stays worth
    /// reporting, but only as information.
    fn attaches_without_host_decision(&self) -> bool {
        self.mode == UlcpAttachMode::Administrative
            || matches!(
                self.ownership(),
                UlcpHostOwnership::Ours | UlcpHostOwnership::Unsupported
            )
    }

    /// Gate a device-peer mutation: attached, no other operation in
    /// flight, and the device actually has a device identity domain.
    fn begin_dev_peer_operation(&mut self) -> Result<(), MobileError> {
        if self.stage != SessionStage::Attached || !self.expected.is_empty() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        if !self.has_capability(cap::DEV_IDENTITY)? {
            return Err(MobileError::InvalidUlcpFrame);
        }
        Ok(())
    }

    /// Queue the next host channel-key insert, if any remain. The cached
    /// digest is updated as each key is accepted.
    fn next_host_channel_insert(&mut self, mut remaining: VecDeque<Vec<u8>>) -> Option<Vec<u8>> {
        let key = remaining.pop_front()?;
        let tid = self.allocate_tid();
        let frame = ulcp_prop_insert(tid, prop::HOST_CHANNEL_KEYS, &key).ok()?;
        self.expected
            .insert(tid, ExpectedResponse::HostChannelInsert(remaining));
        if let Ok(id) = dev_channel_id(&key) {
            self.push_host_channel_id(&id);
        }
        Some(frame)
    }

    /// Replace the cached `PROP_HOST_CHANNEL_KEYS` digest wholesale.
    fn set_host_channel_ids(&mut self, ids: &[Vec<u8>]) {
        let value = ids.concat();
        self.host_channel_entry().value = value;
    }

    fn push_host_channel_id(&mut self, id: &[u8]) {
        let entry = self.host_channel_entry();
        if !entry.value.chunks(items::CHANNEL_ID_LEN).any(|c| c == id) {
            entry.value.extend_from_slice(id);
        }
    }

    fn host_channel_entry(&mut self) -> &mut UlcpPropertyFrameRecord {
        self.responses
            .entry(prop::HOST_CHANNEL_KEYS)
            .or_insert_with(|| UlcpPropertyFrameRecord {
                transaction_id: frame::TID_UNSOLICITED,
                command: Cmd::PropIs as u8,
                property_id: prop::HOST_CHANNEL_KEYS,
                value: Vec::new(),
            })
    }

    /// Patch the cached `PROP_DEV_CHANNEL_KEYS` digest after a confirmed
    /// mutation. The cached value is a list of derived identifiers, so this
    /// tracks identifiers rather than key material.
    fn patch_dev_channels(&mut self, id: &[u8], present: bool) {
        let entry = self
            .responses
            .entry(prop::DEV_CHANNEL_KEYS)
            .or_insert_with(|| UlcpPropertyFrameRecord {
                transaction_id: frame::TID_UNSOLICITED,
                command: Cmd::PropIs as u8,
                property_id: prop::DEV_CHANNEL_KEYS,
                value: Vec::new(),
            });
        let mut value = Vec::with_capacity(entry.value.len() + id.len());
        let mut found = false;
        for chunk in entry.value.chunks(items::CHANNEL_ID_LEN) {
            if chunk == id {
                found = true;
                if !present {
                    continue;
                }
            }
            value.extend_from_slice(chunk);
        }
        if present && !found {
            value.extend_from_slice(id);
        }
        entry.value = value;
    }

    /// Patch the cached `PROP_DEV_PEERS` table after a confirmed mutation,
    /// keeping it lossless without a round-trip re-read.
    fn patch_dev_peers(&mut self, key: &[u8], present: bool) {
        let entry =
            self.responses
                .entry(prop::DEV_PEERS)
                .or_insert_with(|| UlcpPropertyFrameRecord {
                    transaction_id: frame::TID_UNSOLICITED,
                    command: Cmd::PropIs as u8,
                    property_id: prop::DEV_PEERS,
                    value: Vec::new(),
                });
        let mut value = Vec::with_capacity(entry.value.len() + key.len());
        let mut found = false;
        for chunk in entry.value.chunks(items::PUBLIC_KEY_LEN) {
            if chunk == key {
                found = true;
                if !present {
                    continue;
                }
            }
            value.extend_from_slice(chunk);
        }
        if present && !found {
            value.extend_from_slice(key);
        }
        entry.value = value;
    }

    fn has_capability(&self, capability: u32) -> Result<bool, MobileError> {
        let capabilities = self
            .responses
            .get(&prop::CAPS)
            .ok_or(MobileError::InvalidUlcpFrame)?;
        Ok(decode_capabilities(&capabilities.value)?.contains(&capability))
    }

    /// Drop the writes the device has already refused to answer for.
    ///
    /// A capability-gated property that would not read is one the device
    /// does not implement, so writing it fails — and one rejected write
    /// abandons the whole configuration pass. The caller still states a
    /// complete configuration; what cannot land is left out here, where the
    /// device's own answers are known, rather than in the form.
    fn writable(&self, values: Vec<(u32, Vec<u8>)>) -> VecDeque<(u32, Vec<u8>)> {
        let Some(unreadable) = self
            .provisioning
            .as_ref()
            .map(|sync| sync.unreadable_properties.as_slice())
            .filter(|unreadable| !unreadable.is_empty())
        else {
            return values.into();
        };
        let dropped = |property: u32| {
            unreadable.contains(&property)
                || WHOLE_WRITE_GROUPS.iter().any(|group| {
                    group.contains(&property) && group.iter().any(|part| unreadable.contains(part))
                })
        };
        values
            .into_iter()
            .filter(|(property, _)| !dropped(*property))
            .collect()
    }

    fn advance_completed_stage(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        match self.stage {
            SessionStage::Initial => {
                let version = self
                    .responses
                    .get(&prop::PROTOCOL_VERSION)
                    .ok_or(MobileError::InvalidUlcpFrame)?;
                if version.value != [PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION] {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                let capabilities = self
                    .responses
                    .get(&prop::CAPS)
                    .ok_or(MobileError::InvalidUlcpFrame)?;
                self.inspection_queue =
                    ulcp_inspection_properties(capabilities.value.clone())?.into();
                let advertises_host_filter = self.has_capability(cap::HOST_FILTER)?;
                if advertises_host_filter == self.host_key_unsupported {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                if self.attaches_without_host_decision() {
                    self.start_inspection(outbound)?;
                } else {
                    self.stage = SessionStage::AwaitingHost;
                }
            }
            SessionStage::Inspection => self.start_inspection(outbound)?,
            SessionStage::Refreshing => self.start_refresh(outbound)?,
            SessionStage::Configuring => {
                if !self.configuration_queue.is_empty() {
                    self.start_configuration(outbound)?;
                } else if self.has_capability(cap::SAVE)? {
                    self.stage = SessionStage::SavingConfiguration;
                    let tid = self.allocate_tid();
                    self.expected
                        .insert(tid, ExpectedResponse::SaveConfiguration);
                    outbound.push(ulcp_save(tid)?);
                } else {
                    self.finish_configuration()?;
                }
            }
            SessionStage::Claiming
            | SessionStage::Saving
            | SessionStage::AwaitingHost
            | SessionStage::Attached
            | SessionStage::SavingConfiguration
            | SessionStage::Idle => {}
        }
        Ok(())
    }

    /// Abort only the failed operation stage. A correlated CRP status error
    /// never invalidates GATT framing and therefore never resets the session.
    fn recover_from_operation_failure(
        &mut self,
        outbound: &mut Vec<Vec<u8>>,
    ) -> Result<(), MobileError> {
        self.configuration_queue.clear();
        self.inspection_queue.clear();
        match self.stage {
            SessionStage::Claiming => self.stage = SessionStage::AwaitingHost,
            SessionStage::Saving => {
                // The host-key write succeeded even if persistence did not.
                // Continue attaching while reporting that SAVE failed.
                self.start_inspection(outbound)?;
            }
            SessionStage::Refreshing
            | SessionStage::Configuring
            | SessionStage::SavingConfiguration => {
                // Retain the last authoritative snapshot. Property echoes that
                // completed before the failed operation remain available for
                // the next explicit refresh.
                self.stage = SessionStage::Attached;
            }
            SessionStage::Inspection if self.provisioning.is_some() => {
                self.stage = SessionStage::Attached;
            }
            SessionStage::Initial | SessionStage::Inspection => {
                // The transport is healthy but the initial snapshot is not
                // trustworthy enough to attach. Stay connected and report the
                // operation error; reconnect/refresh may retry synchronization.
                self.stage = SessionStage::Initial;
            }
            SessionStage::Attached | SessionStage::AwaitingHost | SessionStage::Idle => {}
        }
        Ok(())
    }

    fn finish_configuration(&mut self) -> Result<(), MobileError> {
        let responses = self.responses.values().cloned().collect();
        self.provisioning = Some(inspect_ulcp_sync(responses)?);
        self.stage = SessionStage::Attached;
        Ok(())
    }

    fn start_configuration(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Configuring;
        for _ in 0..usize::from(frame::TID_MAX) {
            let Some((property, value)) = self.configuration_queue.pop_front() else {
                break;
            };
            let tid = self.allocate_tid();
            self.expected
                .insert(tid, ExpectedResponse::ConfigurationProperty(property));
            outbound.push(ulcp_prop_set(tid, property, value)?);
        }
        Ok(())
    }

    fn start_inspection(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Inspection;
        if self.inspection_queue.is_empty() {
            let responses = self.responses.values().cloned().collect();
            self.provisioning = Some(inspect_ulcp_sync(responses)?);
            self.stage = SessionStage::Attached;
            return Ok(());
        }
        for _ in 0..usize::from(frame::TID_MAX) {
            let Some(property) = self.inspection_queue.pop_front() else {
                break;
            };
            outbound.push(self.get_property(property)?);
        }
        Ok(())
    }

    fn start_refresh(&mut self, outbound: &mut Vec<Vec<u8>>) -> Result<(), MobileError> {
        self.stage = SessionStage::Refreshing;
        if self.inspection_queue.is_empty() {
            let responses = self.responses.values().cloned().collect();
            self.provisioning = Some(inspect_ulcp_sync(responses)?);
            self.stage = SessionStage::Attached;
            return Ok(());
        }
        for _ in 0..usize::from(frame::TID_MAX) {
            let Some(property) = self.inspection_queue.pop_front() else {
                break;
            };
            outbound.push(self.get_property(property)?);
        }
        Ok(())
    }

    /// Recompute the attached provisioning snapshot after device state
    /// changed under an established session.
    ///
    /// `changed_property` is the property the triggering notification
    /// carried, or `None` for a change this session made itself.
    ///
    /// Re-opening the host decision is deliberately limited to a
    /// `PROP_HOST_KEY` change. Another phone claiming the radio out from
    /// under an attached session is a question only the user can answer,
    /// so that case still returns to the host prompt. Every *other*
    /// published value is news, not a decision: a session attached to a
    /// radio owned by another identity (a tethered claim that did not
    /// take, which attaches deliberately — see the `Claim` arm) would
    /// otherwise be thrown back to the prompt by any unsolicited update at
    /// all. `PROP_BATTERY` makes that concrete, being the one notification
    /// that arrives on its own schedule for the life of the session.
    fn refresh_attached_snapshot(
        &mut self,
        changed_property: Option<u32>,
    ) -> Result<(), MobileError> {
        if self.stage != SessionStage::Attached {
            return Ok(());
        }
        let responses = self.responses.values().cloned().collect();
        self.provisioning = Some(inspect_ulcp_sync(responses)?);
        if changed_property == Some(prop::HOST_KEY) && !self.attaches_without_host_decision() {
            self.stage = SessionStage::AwaitingHost;
        }
        Ok(())
    }
}

/// Return the authoritative properties needed for the read-only post-attach
/// inspection, gated by the supplied `PROP_CAPS` value.
#[uniffi::export]
pub fn ulcp_inspection_properties(capabilities: Vec<u8>) -> Result<Vec<u32>, MobileError> {
    let capabilities = decode_capabilities(&capabilities)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);

    let mut properties = vec![
        prop::INTERFACE_TYPE,
        prop::PHY_ENABLED,
        prop::PHY_FREQ,
        prop::PHY_TX_POWER,
    ];
    if has(cap::PHY_LORA) {
        properties.extend([prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR]);
    }
    if has(cap::PHY_DUTY_LIMIT) {
        properties.extend([prop::PHY_DUTY_NOW, prop::PHY_DUTY_LIMIT]);
    }
    if has(cap::SAVE) {
        properties.push(prop::SAVED);
    }
    if has(cap::HOST_FILTER) {
        properties.push(prop::HOST_RX_FILTERS);
    }
    if has(cap::HOST_KEYS) {
        properties.extend([prop::HOST_CHANNEL_KEYS, prop::HOST_PEER_KEYS]);
    }
    if has(cap::HOST_RX_QUEUE) {
        properties.extend([prop::HOST_RX_QUEUE_COUNT, prop::HOST_RX_QUEUE_DROPPED]);
    }
    if has(cap::HOST_AUTO_ACK) {
        properties.push(prop::HOST_AUTO_ACK);
    }
    if has(cap::REPEATER) {
        properties.extend([
            prop::MAC_REPEATER_ENABLED,
            prop::MAC_REPEATER_REGIONS,
            prop::MAC_REPEATER_DEFAULT_REGION,
            prop::MAC_REPEATER_MIN_RSSI,
            prop::MAC_REPEATER_MIN_SNR,
        ]);
    }
    if has(cap::IDENT) {
        properties.extend([prop::IDENT_ROLE, prop::IDENT_MOBILE]);
    }
    if has(cap::DEV_IDENTITY) {
        properties.extend([
            prop::DEV_PEERS,
            prop::DEV_CHANNEL_KEYS,
            prop::DEV_DISCOVERABLE,
        ]);
    }
    if has(cap::ALERT) {
        // Read at attach so a phone reconnecting mid-search finds the
        // alert it left running rather than a stale "off".
        properties.push(prop::ALERT);
    }
    if has(cap::TIME) {
        // The clock is live rather than configuration, but it is read
        // here for the same reason the alert is: a phone that just
        // attached should know whether the device knows the time, not
        // wait for the next announcement to find out.
        properties.extend([prop::TIME, prop::TZ_OFFSET]);
    }
    if has(cap::GNSS) {
        properties.extend([
            prop::GNSS_ENABLED,
            prop::GNSS_LOCATION,
            prop::GNSS_ALTITUDE,
            prop::GNSS_FIX,
            prop::GNSS_PRECISION,
            prop::GNSS_SATELLITES,
            prop::GNSS_IDENT_UPDATE,
            prop::GNSS_IDENT_PRECISION,
            prop::GNSS_TIME_TRUST,
        ]);
    }
    Ok(properties)
}

fn ulcp_refresh_properties(capabilities: Vec<u8>) -> Result<Vec<u32>, MobileError> {
    let decoded = decode_capabilities(&capabilities)?;
    validate_capability_dependencies(&decoded)?;
    let has = |capability| decoded.contains(&capability);
    let mut properties = Vec::new();
    if has(cap::DEV_IDENTITY) {
        properties.push(prop::DEV_KEY);
    }
    if has(cap::DEV_NAME) {
        properties.push(prop::DEV_NAME);
    }
    if has(cap::BATTERY) {
        properties.push(prop::BATTERY);
    }
    if has(cap::HOST_FILTER) {
        properties.push(prop::HOST_KEY);
    }
    properties.extend(ulcp_inspection_properties(capabilities)?);
    Ok(properties)
}

/// Validate and reduce the property responses from the read-only post-attach
/// inspection.
///
/// The four properties every ULCP device must answer — the interface type
/// and the live PHY triple — are required: without them there is no radio
/// to describe. Everything else is capability-gated and merely *expected*,
/// so a device that refuses one, or answers it with something undecodable,
/// yields a snapshot with that setting absent and named in
/// `unreadable_properties` rather than no snapshot at all.
#[uniffi::export]
pub fn inspect_ulcp_sync(
    responses: Vec<UlcpPropertyFrameRecord>,
) -> Result<UlcpSyncRecord, MobileError> {
    let value = |key| property_value(&responses, key);
    let capabilities = decode_capabilities(value(prop::CAPS)?)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);

    let interface = decode_exact_pui(value(prop::INTERFACE_TYPE)?)?;
    if interface != INTERFACE_TYPE {
        return Err(MobileError::InvalidUlcpFrame);
    }
    let phy_enabled = decode_bool(value(prop::PHY_ENABLED)?)?;
    let frequency_khz = decode_u32(value(prop::PHY_FREQ)?)?;
    let transmit_power_dbm = decode_i8(value(prop::PHY_TX_POWER)?)?;

    let mut expected = ExpectedProperties {
        responses: &responses,
        unreadable: Vec::new(),
    };
    let lora = has(cap::PHY_LORA);
    let bandwidth_hz = expected.read(lora, prop::PHY_LORA_BW, decode_u32);
    let spreading_factor = expected.read(lora, prop::PHY_LORA_SF, decode_u8);
    let coding_rate_denom = expected.read(lora, prop::PHY_LORA_CR, decode_u8);
    let duty = has(cap::PHY_DUTY_LIMIT);
    let duty_cycle_now = expected.read(duty, prop::PHY_DUTY_NOW, decode_u16);
    let duty_cycle_limit = expected.read(duty, prop::PHY_DUTY_LIMIT, decode_u16);
    let saved = expected.read(has(cap::SAVE), prop::SAVED, decode_saved);
    let queue = has(cap::HOST_RX_QUEUE);
    let queued_frames = expected.read(queue, prop::HOST_RX_QUEUE_COUNT, decode_u16);
    let dropped_frames = expected.read(queue, prop::HOST_RX_QUEUE_DROPPED, decode_u32);
    let filter_count = expected.read(
        has(cap::HOST_FILTER),
        prop::HOST_RX_FILTERS,
        decode_filter_count,
    );
    let host_keys = has(cap::HOST_KEYS);
    let host_channel_count = expected.read(
        host_keys,
        prop::HOST_CHANNEL_KEYS,
        decode_fixed_count::<{ items::CHANNEL_ID_LEN }>,
    );
    let host_peer_count = expected.read(
        host_keys,
        prop::HOST_PEER_KEYS,
        decode_fixed_count::<{ items::PUBLIC_KEY_LEN }>,
    );
    let auto_ack = expected.read(has(cap::HOST_AUTO_ACK), prop::HOST_AUTO_ACK, decode_bool);
    let dev_identity = has(cap::DEV_IDENTITY);
    let dev_peer_keys = expected.read(
        dev_identity,
        prop::DEV_PEERS,
        decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>,
    );
    let dev_channel_ids = expected.read(
        dev_identity,
        prop::DEV_CHANNEL_KEYS,
        decode_fixed_list::<{ items::CHANNEL_ID_LEN }>,
    );

    // Every part of the policy is read before any of it is required, so one
    // unreadable property does not hide the others behind it.
    let forwards = has(cap::REPEATER);
    let repeater_enabled = expected.read(forwards, prop::MAC_REPEATER_ENABLED, decode_bool);
    let regions = expected.read(forwards, prop::MAC_REPEATER_REGIONS, decode_region_list);
    let default_region = expected.read(
        forwards,
        prop::MAC_REPEATER_DEFAULT_REGION,
        decode_optional_region,
    );
    let min_rssi_dbm = expected.read(forwards, prop::MAC_REPEATER_MIN_RSSI, |value| {
        decode_optional(value, decode_i16)
    });
    let min_snr_db = expected.read(forwards, prop::MAC_REPEATER_MIN_SNR, |value| {
        decode_optional(value, decode_i8)
    });
    let repeater = (|| {
        Some(UlcpRepeaterSettingsRecord {
            enabled: repeater_enabled?,
            regions: regions?,
            default_region: default_region?,
            min_rssi_dbm: min_rssi_dbm?,
            min_snr_db: min_snr_db?,
        })
    })();

    // An empty PROP_IDENT_ROLE is the device saying it derives its own
    // role, which is the same `None` a device without CAP_IDENT reports.
    let ident = has(cap::IDENT);
    let ident_role = expected
        .read(ident, prop::IDENT_ROLE, |value| {
            decode_optional(value, decode_u8)
        })
        .flatten();
    let ident_mobile = expected.read(ident, prop::IDENT_MOBILE, decode_bool);
    let dev_discoverable = expected.read(dev_identity, prop::DEV_DISCOVERABLE, decode_bool);

    let tz_offset_min = expected.read(has(cap::TIME), prop::TZ_OFFSET, decode_i16);

    // Read whole, like the forwarding policy above and for the same
    // reason: this is written as a set.
    let positioning = has(cap::GNSS);
    let gnss_enabled = expected.read(positioning, prop::GNSS_ENABLED, decode_bool);
    let ident_update = expected.read(positioning, prop::GNSS_IDENT_UPDATE, decode_bool);
    let ident_precision = expected.read(positioning, prop::GNSS_IDENT_PRECISION, decode_precision);
    let time_trust = expected.read(positioning, prop::GNSS_TIME_TRUST, decode_bool);
    let gnss = (|| {
        Some(UlcpGnssSettingsRecord {
            enabled: gnss_enabled?,
            ident_update: ident_update?,
            ident_precision: ident_precision?,
            time_trust: time_trust?,
        })
    })();

    let mut unreadable_properties = expected.unreadable;
    unreadable_properties.sort_unstable();

    Ok(UlcpSyncRecord {
        capability_count: capabilities
            .len()
            .try_into()
            .map_err(|_| MobileError::InvalidUlcpFrame)?,
        has_host_filtering: has(cap::HOST_FILTER),
        supports_offline_queue: has(cap::HOST_RX_QUEUE),
        supports_delegated_ack: has(cap::HOST_AUTO_ACK),
        supports_device_name: has(cap::DEV_NAME),
        supports_lora: has(cap::PHY_LORA),
        supports_duty_cycle_limit: has(cap::PHY_DUTY_LIMIT),
        supports_battery: has(cap::BATTERY),
        supports_repeater: has(cap::REPEATER),
        supports_ident: has(cap::IDENT),
        supports_device_identity: has(cap::DEV_IDENTITY),
        supports_time: has(cap::TIME),
        supports_gnss: positioning,
        phy_enabled,
        frequency_khz,
        transmit_power_dbm,
        bandwidth_hz,
        spreading_factor,
        coding_rate_denom,
        duty_cycle_now,
        duty_cycle_limit,
        saved,
        queued_frames,
        dropped_frames,
        filter_count,
        host_channel_count,
        host_peer_count,
        auto_ack,
        repeater,
        dev_peer_keys,
        dev_channel_ids,
        ident_role,
        ident_mobile,
        dev_discoverable,
        tz_offset_min,
        gnss,
        unreadable_properties,
    })
}

/// Properties only ever written as a set. Writing part of a modem profile
/// or part of a forwarding policy leaves the device running a configuration
/// nobody asked for, so one unreadable member withdraws the whole group.
/// These are the same groupings the reduction reports as a unit.
const WHOLE_WRITE_GROUPS: [&[u32]; 3] = [
    &[prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR],
    &[
        prop::MAC_REPEATER_ENABLED,
        prop::MAC_REPEATER_REGIONS,
        prop::MAC_REPEATER_DEFAULT_REGION,
        prop::MAC_REPEATER_MIN_RSSI,
        prop::MAC_REPEATER_MIN_SNR,
    ],
    &[
        prop::GNSS_ENABLED,
        prop::GNSS_IDENT_UPDATE,
        prop::GNSS_IDENT_PRECISION,
        prop::GNSS_TIME_TRUST,
    ],
];

/// The capability-gated half of an inspection: properties the device is
/// expected to answer, each of which it may nevertheless decline.
struct ExpectedProperties<'a> {
    responses: &'a [UlcpPropertyFrameRecord],
    unreadable: Vec<u32>,
}

impl ExpectedProperties<'_> {
    /// Decode `key` when the device advertises the capability that gates it.
    ///
    /// A missing or undecodable value is recorded and reported as `None`
    /// rather than failing the whole reduction: the setting is unknown, which
    /// is a fact about one property and not about the device as a whole.
    fn read<T>(
        &mut self,
        gated_on: bool,
        key: u32,
        decode: impl FnOnce(&[u8]) -> Result<T, MobileError>,
    ) -> Option<T> {
        if !gated_on {
            return None;
        }
        match property_value(self.responses, key).and_then(decode) {
            Ok(value) => Some(value),
            Err(_) => {
                self.unreadable.push(key);
                None
            }
        }
    }
}

fn property_value(responses: &[UlcpPropertyFrameRecord], key: u32) -> Result<&[u8], MobileError> {
    let mut matching = responses
        .iter()
        .filter(|response| response.property_id == key);
    let response = matching.next().ok_or(MobileError::InvalidUlcpFrame)?;
    if matching.next().is_some() || response.command != Cmd::PropIs as u8 {
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(&response.value)
}

fn decode_capabilities(value: &[u8]) -> Result<Vec<u32>, MobileError> {
    let mut capabilities = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (capability, used) = pui::decode(rest).map_err(|_| MobileError::InvalidUlcpFrame)?;
        if capabilities.contains(&capability) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        capabilities.push(capability);
        rest = &rest[used..];
    }
    Ok(capabilities)
}

fn validate_capability_dependencies(capabilities: &[u32]) -> Result<(), MobileError> {
    let has = |capability| capabilities.contains(&capability);
    if has(cap::HOST_RX_QUEUE) && !has(cap::HOST_FILTER)
        || has(cap::HOST_KEYS) && !has(cap::HOST_FILTER)
        || has(cap::HOST_AUTO_ACK) && (!has(cap::HOST_KEYS) || !has(cap::HOST_RX_QUEUE))
        // A device with no identity of its own has nothing to forward for
        // and nothing to advertise.
        || has(cap::REPEATER) && !has(cap::DEV_IDENTITY)
        || has(cap::IDENT) && !has(cap::DEV_IDENTITY)
        // A receiver that cannot set a clock is still a receiver, but the
        // device also dates its fixes, so CAP_GNSS implies CAP_TIME.
        || has(cap::GNSS) && !has(cap::TIME)
    {
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(())
}

fn decode_exact_pui(value: &[u8]) -> Result<u32, MobileError> {
    let (decoded, used) = pui::decode(value).map_err(|_| MobileError::InvalidUlcpFrame)?;
    (used == value.len())
        .then_some(decoded)
        .ok_or(MobileError::InvalidUlcpFrame)
}

fn decode_bool(value: &[u8]) -> Result<bool, MobileError> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(MobileError::InvalidUlcpFrame),
    }
}

fn decode_saved(value: &[u8]) -> Result<SavedSnapshotRecord, MobileError> {
    match value {
        [saved::NONE] => Ok(SavedSnapshotRecord::None),
        [saved::CURRENT] => Ok(SavedSnapshotRecord::Current),
        [saved::FALLBACK] => Ok(SavedSnapshotRecord::Fallback),
        [saved::UNREADABLE] => Ok(SavedSnapshotRecord::Unreadable),
        _ => Err(MobileError::InvalidUlcpFrame),
    }
}

fn decode_u16(value: &[u8]) -> Result<u16, MobileError> {
    value
        .try_into()
        .map(u16::from_le_bytes)
        .map_err(|_| MobileError::InvalidUlcpFrame)
}

fn decode_u8(value: &[u8]) -> Result<u8, MobileError> {
    value
        .first()
        .copied()
        .filter(|_| value.len() == 1)
        .ok_or(MobileError::InvalidUlcpFrame)
}

fn decode_i8(value: &[u8]) -> Result<i8, MobileError> {
    decode_u8(value).map(|value| value as i8)
}

/// A location precision, which is only ever 1–7 bytes. A device
/// reporting anything else is reporting a setting this phone cannot
/// present, so it is recorded as unreadable rather than shown.
fn decode_precision(value: &[u8]) -> Result<u8, MobileError> {
    decode_u8(value)
        .ok()
        .filter(|bytes| (1..=MAX_PRECISION).contains(bytes))
        .ok_or(MobileError::InvalidUlcpFrame)
}

fn decode_i16(value: &[u8]) -> Result<i16, MobileError> {
    value
        .try_into()
        .map(i16::from_le_bytes)
        .map_err(|_| MobileError::InvalidUlcpFrame)
}

/// Decode a property whose empty value means "unset" rather than zero.
fn decode_optional<T>(
    value: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, MobileError>,
) -> Result<Option<T>, MobileError> {
    if value.is_empty() {
        return Ok(None);
    }
    decode(value).map(Some)
}

/// Split a `PROP_MAC_REPEATER_REGIONS` value into individual codes.
///
/// Deliberately imposes no upper bound: how many regions a device holds
/// is its own business, and a device reporting more than this phone would
/// ever write is not a malformed frame.
fn decode_region_list(value: &[u8]) -> Result<Vec<Vec<u8>>, MobileError> {
    if !value.len().is_multiple_of(items::REGION_CODE_LEN) {
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(value
        .chunks(items::REGION_CODE_LEN)
        .map(<[u8]>::to_vec)
        .collect())
}

fn decode_optional_region(value: &[u8]) -> Result<Option<Vec<u8>>, MobileError> {
    match value.len() {
        0 => Ok(None),
        items::REGION_CODE_LEN => Ok(Some(value.to_vec())),
        _ => Err(MobileError::InvalidUlcpFrame),
    }
}

/// Order one configuration pass: everything that changes live PHY
/// behavior happens with the radio down, and the radio comes back up only
/// once the complete new profile is in place.
///
/// `device_values` are the device-domain writes, which ride between the
/// two PHY_ENABLED writes for the same reason the PHY parameters do — a
/// repeater must not start forwarding under half of its new policy.
fn configuration_values(
    settings: UlcpRadioSettingsRecord,
    device_values: Vec<(u32, Vec<u8>)>,
) -> Vec<(u32, Vec<u8>)> {
    let mut values = Vec::new();
    if !settings.phy_enabled {
        values.push((prop::PHY_ENABLED, vec![0]));
    }
    if let Some(name) = settings.device_name {
        values.push((prop::DEV_NAME, name.into_bytes()));
    }
    values.extend([
        (
            prop::PHY_FREQ,
            settings.frequency_khz.to_le_bytes().to_vec(),
        ),
        (prop::PHY_TX_POWER, vec![settings.transmit_power_dbm as u8]),
    ]);
    if let (Some(bandwidth), Some(sf), Some(cr)) = (
        settings.bandwidth_hz,
        settings.spreading_factor,
        settings.coding_rate_denom,
    ) {
        values.extend([
            (prop::PHY_LORA_BW, bandwidth.to_le_bytes().to_vec()),
            (prop::PHY_LORA_SF, vec![sf]),
            (prop::PHY_LORA_CR, vec![cr]),
        ]);
    }
    if let Some(limit) = settings.duty_cycle_limit {
        values.push((prop::PHY_DUTY_LIMIT, limit.to_le_bytes().to_vec()));
    }
    values.extend(device_values);
    if settings.phy_enabled {
        values.push((prop::PHY_ENABLED, vec![1]));
    }
    values
}

/// Check the device-domain half of a commissioning record against what
/// the device says it can do, and reduce it to property writes.
///
/// Capability-gated fields must be present exactly when the capability
/// is: the record states a whole desired configuration, so a field the
/// device cannot honor is a caller mistake rather than something to
/// silently drop.
fn validate_device_settings(
    configuration: &UlcpDeviceConfigRecord,
    state: &UlcpSessionState,
) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
    let mut values = Vec::new();

    let supports_ident = state.has_capability(cap::IDENT)?;
    if configuration.ident_mobile.is_some() != supports_ident
        || (configuration.ident_role.is_some() && !supports_ident)
    {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if supports_ident {
        // An empty PROP_IDENT_ROLE hands the choice back to the device.
        values.push((
            prop::IDENT_ROLE,
            configuration
                .ident_role
                .map(|role| vec![role])
                .unwrap_or_default(),
        ));
        values.push((
            prop::IDENT_MOBILE,
            vec![configuration.ident_mobile.unwrap_or(false) as u8],
        ));
    }

    let supports_dev_identity = state.has_capability(cap::DEV_IDENTITY)?;
    if configuration.dev_discoverable.is_some() != supports_dev_identity {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(discoverable) = configuration.dev_discoverable {
        values.push((prop::DEV_DISCOVERABLE, vec![discoverable as u8]));
    }

    let supports_repeater = state.has_capability(cap::REPEATER)?;
    if configuration.repeater.is_some() != supports_repeater {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(repeater) = &configuration.repeater {
        let mut regions = Vec::with_capacity(repeater.regions.len() * items::REGION_CODE_LEN);
        for region in &repeater.regions {
            if region.len() != items::REGION_CODE_LEN {
                return Err(MobileError::InvalidUlcpFrame);
            }
            regions.extend_from_slice(region);
        }
        if let Some(default_region) = &repeater.default_region {
            if default_region.len() != items::REGION_CODE_LEN {
                return Err(MobileError::InvalidUlcpFrame);
            }
        }
        // Enabling last means the forwarding policy is already whole by
        // the time the device starts acting on it. The device does not
        // cross-check the default region against the forwarding list —
        // that is a SHOULD the presenting UI is better placed to warn on.
        values.extend([
            (prop::MAC_REPEATER_REGIONS, regions),
            (
                prop::MAC_REPEATER_DEFAULT_REGION,
                repeater.default_region.clone().unwrap_or_default(),
            ),
            (
                prop::MAC_REPEATER_MIN_RSSI,
                repeater
                    .min_rssi_dbm
                    .map(|rssi| rssi.to_le_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (
                prop::MAC_REPEATER_MIN_SNR,
                repeater
                    .min_snr_db
                    .map(|snr| vec![snr as u8])
                    .unwrap_or_default(),
            ),
            (prop::MAC_REPEATER_ENABLED, vec![repeater.enabled as u8]),
        ]);
    }

    let keeps_time = state.has_capability(cap::TIME)?;
    if configuration.tz_offset_min.is_some() != keeps_time {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(minutes) = configuration.tz_offset_min {
        // The extremes of the zone database, not of the encoding: a
        // fourteen-hour offset is Kiritimati, and anything past it is a
        // caller mistake rather than a place.
        if !(-12 * 60..=14 * 60).contains(&minutes) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        values.push((prop::TZ_OFFSET, minutes.to_le_bytes().to_vec()));
    }

    let positioning = state.has_capability(cap::GNSS)?;
    if configuration.gnss.is_some() != positioning {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(gnss) = configuration.gnss {
        if !(1..=MAX_PRECISION).contains(&gnss.ident_precision) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        // Enabled last, so a receiver that starts looking does it under
        // the disclosure and trust policy just written rather than the
        // one it happened to be holding.
        values.extend([
            (prop::GNSS_IDENT_UPDATE, vec![gnss.ident_update as u8]),
            (prop::GNSS_IDENT_PRECISION, vec![gnss.ident_precision]),
            (prop::GNSS_TIME_TRUST, vec![gnss.time_trust as u8]),
            (prop::GNSS_ENABLED, vec![gnss.enabled as u8]),
        ]);
    }
    Ok(values)
}

fn validate_radio_settings(
    settings: &UlcpRadioSettingsRecord,
    state: &UlcpSessionState,
) -> Result<(), MobileError> {
    if settings.frequency_khz == 0 {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(name) = &settings.device_name {
        if !state.has_capability(cap::DEV_NAME)?
            || name.is_empty()
            || name.len() > 64
            || name.as_bytes().contains(&0)
        {
            return Err(MobileError::InvalidUlcpFrame);
        }
    }
    let lora = (
        settings.bandwidth_hz,
        settings.spreading_factor,
        settings.coding_rate_denom,
    );
    match lora {
        (None, None, None) if !state.has_capability(cap::PHY_LORA)? => {}
        (Some(bandwidth), Some(sf), Some(cr))
            if state.has_capability(cap::PHY_LORA)?
                && bandwidth > 0
                && (5..=12).contains(&sf)
                && (5..=8).contains(&cr) => {}
        _ => return Err(MobileError::InvalidUlcpFrame),
    }
    if settings.duty_cycle_limit.is_some() != state.has_capability(cap::PHY_DUTY_LIMIT)? {
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(())
}

fn decode_u32(value: &[u8]) -> Result<u32, MobileError> {
    value
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| MobileError::InvalidUlcpFrame)
}

/// Split a concatenation of fixed-width items into the items themselves.
/// The lossless counterpart of [`decode_fixed_count`], for properties whose
/// GET form reads back full values rather than digests.
fn decode_fixed_list<const N: usize>(value: &[u8]) -> Result<Vec<Vec<u8>>, MobileError> {
    items::fixed_items::<N>(value)
        .map_err(|_| MobileError::InvalidUlcpFrame)?
        .map(|item| Ok(item.to_vec()))
        .collect()
}

fn decode_fixed_count<const N: usize>(value: &[u8]) -> Result<u32, MobileError> {
    let count = items::fixed_items::<N>(value)
        .map_err(|_| MobileError::InvalidUlcpFrame)?
        .count();
    count.try_into().map_err(|_| MobileError::InvalidUlcpFrame)
}

fn decode_filter_count(value: &[u8]) -> Result<u32, MobileError> {
    let mut count = 0u32;
    for item in items::prefixed_items(value) {
        let item = item.map_err(|_| MobileError::InvalidUlcpFrame)?;
        Filter::decode(item).map_err(|_| MobileError::InvalidUlcpFrame)?;
        count = count.checked_add(1).ok_or(MobileError::InvalidUlcpFrame)?;
    }
    Ok(count)
}

/// Split a ULCP frame into ATT values using the negotiated maximum write
/// length. The returned values include the one-octet SAR header.
#[uniffi::export]
pub fn ulcp_gatt_segments(
    frame: Vec<u8>,
    maximum_value_length: u16,
) -> Result<Vec<GattSegmentRecord>, MobileError> {
    let segment_payload = usize::from(maximum_value_length)
        .checked_sub(1)
        .filter(|length| *length > 0)
        .ok_or(MobileError::InvalidGattSegment)?;
    if frame.len() > MAX_FRAME {
        return Err(MobileError::InvalidUlcpFrame);
    }

    Ok(gatt::segments(&frame, segment_payload)
        .map(|segment| {
            let mut value = vec![0; segment.payload().len() + 1];
            let length = segment
                .write_to(&mut value)
                .expect("sized from the segment payload");
            value.truncate(length);
            GattSegmentRecord { value }
        })
        .collect())
}

/// Encode a `CMD_PROP_GET` request with the shared ULCP codec.
#[uniffi::export]
pub fn ulcp_prop_get(transaction_id: u8, property_id: u32) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 8];
    let length = frame::prop_get(&mut output, transaction_id, property_id)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(output[..length].to_vec())
}

/// Encode a `CMD_PROP_SET` request with the shared ULCP codec.
#[uniffi::export]
pub fn ulcp_prop_set(
    transaction_id: u8,
    property_id: u32,
    value: Vec<u8>,
) -> Result<Vec<u8>, MobileError> {
    if value.len() > MAX_FRAME {
        return Err(MobileError::InvalidUlcpFrame);
    }
    let mut output = vec![0; MAX_FRAME];
    let length = frame::prop_set(&mut output, transaction_id, property_id, &value)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    output.truncate(length);
    Ok(output)
}

/// Encode a `CMD_PROP_INSERT` request. Deliberately not exported: typed
/// session operations own multi-value mutations.
fn ulcp_prop_insert(
    transaction_id: u8,
    property_id: u32,
    item: &[u8],
) -> Result<Vec<u8>, MobileError> {
    let mut output = vec![0; MAX_FRAME];
    let length = frame::prop_insert(&mut output, transaction_id, property_id, item)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    output.truncate(length);
    Ok(output)
}

/// Encode a `CMD_PROP_REMOVE` request. Deliberately not exported, like
/// [`ulcp_prop_insert`].
fn ulcp_prop_remove(
    transaction_id: u8,
    property_id: u32,
    selector: &[u8],
) -> Result<Vec<u8>, MobileError> {
    let mut output = vec![0; MAX_FRAME];
    let length = frame::prop_remove(&mut output, transaction_id, property_id, selector)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    output.truncate(length);
    Ok(output)
}

/// Capacity of the device identity's peer list (`PROP_DEV_PEERS`).
///
/// A label constant only — the device's `NOMEM` stays authoritative for
/// when the list is actually full.
#[uniffi::export]
pub fn ulcp_max_dev_peers() -> u8 {
    8
}

/// Capacity of the device identity's channel list (`PROP_DEV_CHANNEL_KEYS`).
///
/// A label constant, like [`ulcp_max_dev_peers`].
#[uniffi::export]
pub fn ulcp_max_dev_channels() -> u8 {
    8
}

/// Derive the identifier a device will echo for a channel key.
fn dev_channel_id(channel_key: &[u8]) -> Result<Vec<u8>, MobileError> {
    let bytes: [u8; items::CHANNEL_KEY_LEN] = channel_key
        .try_into()
        .map_err(|_| MobileError::InvalidChannelKeyLength)?;
    Ok(crate::derive_channel_id(bytes.to_vec())?)
}

/// Encode a `CMD_SAVE` request with the shared ULCP codec.
#[uniffi::export]
pub fn ulcp_save(transaction_id: u8) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 2];
    let length =
        frame::save(&mut output, transaction_id).map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(output[..length].to_vec())
}

/// Encode a `CMD_FACTORY_RESET` request with the shared ULCP codec.
#[uniffi::export]
pub fn ulcp_factory_reset(transaction_id: u8) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 2];
    let length = frame::factory_reset(&mut output, transaction_id)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(output[..length].to_vec())
}

/// Decode an exact packed status value from `PROP_LAST_STATUS`.
#[uniffi::export]
pub fn inspect_ulcp_status(value: Vec<u8>) -> Result<u32, MobileError> {
    decode_exact_pui(&value)
}

fn ulcp_operation_error(
    operation: String,
    value: &[u8],
) -> Result<UlcpOperationErrorRecord, MobileError> {
    let status_code = inspect_ulcp_status(value.to_vec())?;
    let status = umsh_ulcp::Status(status_code);
    if status == umsh_ulcp::Status::OK {
        // A property operation that promised an echoed value cannot silently
        // substitute status-only success. That is a real session violation,
        // not a reported operation error.
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(UlcpOperationErrorRecord {
        operation,
        status_code,
        status_name: format!("{status:?}"),
    })
}

/// Parse and validate a property notification or response.
#[uniffi::export]
pub fn inspect_ulcp_property_frame(bytes: Vec<u8>) -> Result<UlcpPropertyFrameRecord, MobileError> {
    let parsed = PropertyNotification::parse(&bytes).map_err(|_| MobileError::InvalidUlcpFrame)?;
    let command = match parsed.kind {
        PropertyNotificationKind::Is => Cmd::PropIs,
        PropertyNotificationKind::Inserted => Cmd::PropInserted,
        PropertyNotificationKind::Removed => Cmd::PropRemoved,
    };
    Ok(UlcpPropertyFrameRecord {
        transaction_id: parsed.tid,
        command: command as u8,
        property_id: parsed.key,
        value: parsed.value.to_vec(),
    })
}

/// Validate and reduce a `PROP_BATTERY` value to fields used by mobile UI.
#[uniffi::export]
pub fn inspect_ulcp_battery(value: Vec<u8>) -> Result<UlcpBatteryRecord, MobileError> {
    let battery = BatteryStatus::decode(&value).map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(UlcpBatteryRecord {
        percentage: battery.level_percent,
        voltage_mv: battery.voltage_mv,
        charge_state: battery.charge_state.map(UlcpChargeState::from_wire),
    })
}

/// Validate and reduce a `PROP_ALERT` value.
#[uniffi::export]
pub fn inspect_ulcp_alert(value: Vec<u8>) -> Result<UlcpAlertState, MobileError> {
    let (code, consumed) = pui::decode(&value).map_err(|_| MobileError::InvalidUlcpFrame)?;
    if consumed != value.len() {
        return Err(MobileError::InvalidUlcpFrame);
    }
    AlertState::from_code(code)
        .map(UlcpAlertState::from_wire)
        .ok_or(MobileError::InvalidUlcpFrame)
}

/// Read a region code from what someone typed, yielding the two wire
/// octets used everywhere else in the ULCP and mesh surfaces.
///
/// Three ASCII letters are a nearest-airport IATA code, `0xXXXX` is a
/// literal code, and anything else is a region *name* hashed into a
/// disjoint part of the code space — so "SJC" and "San Jose" are
/// deliberately different regions, and no name can ever collide with an
/// airport.
#[uniffi::export]
pub fn region_code_from_string(text: String) -> Result<Vec<u8>, MobileError> {
    text.parse::<RegionCode>()
        .map(|code| code.to_bytes().to_vec())
        .map_err(|_| MobileError::InvalidRegionCode)
}

/// Render a region code for display. Codes derived from an airport come
/// back as their three letters; everything else as `0xXXXX`, which
/// [`region_code_from_string`] reads back.
#[uniffi::export]
pub fn region_code_description(code: Vec<u8>) -> Result<String, MobileError> {
    let bytes: [u8; items::REGION_CODE_LEN] = code
        .try_into()
        .map_err(|_| MobileError::InvalidRegionCode)?;
    Ok(RegionCode::from_bytes(bytes).to_string())
}

/// Stateful, bounded receiver for Frame Out notifications.
#[derive(uniffi::Object)]
pub struct MobileGattReassembler {
    inner: Mutex<Reassembler<MAX_FRAME>>,
}

#[uniffi::export]
impl MobileGattReassembler {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Reassembler::new()),
        })
    }

    /// Consume one ATT value, returning a complete ULCP frame when the
    /// segment ends one. Invalid input resets the shared reassembly state.
    pub fn push(&self, segment: Vec<u8>) -> Result<Option<Vec<u8>>, MobileError> {
        let mut reassembler = self.inner.lock().expect("GATT reassembler mutex poisoned");
        match reassembler.push(&segment) {
            None => Ok(None),
            Some(Ok(frame)) => Ok(Some(frame.to_vec())),
            Some(Err(_)) => Err(MobileError::InvalidGattSegment),
        }
    }

    pub fn reset(&self) {
        self.inner
            .lock()
            .expect("GATT reassembler mutex poisoned")
            .reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::PropPayload;

    fn response(property_id: u32, value: &[u8]) -> UlcpPropertyFrameRecord {
        UlcpPropertyFrameRecord {
            transaction_id: 1,
            command: Cmd::PropIs as u8,
            property_id,
            value: value.to_vec(),
        }
    }

    fn encoded_capabilities(values: &[u32]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for value in values {
            let mut bytes = [0; pui::MAX_LEN];
            let len = pui::encode(*value, &mut bytes).unwrap();
            encoded.extend_from_slice(&bytes[..len]);
        }
        encoded
    }

    fn property_request(bytes: &[u8]) -> (u8, u32) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropGet));
        let (property, used) = pui::decode(parsed.payload).unwrap();
        assert_eq!(used, parsed.payload.len());
        (parsed.header.tid(), property)
    }

    fn property_response(tid: u8, property: u32, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; MAX_FRAME];
        let length = frame::prop_is(&mut bytes, tid, property, value).unwrap();
        bytes.truncate(length);
        bytes
    }

    fn answer_requests(
        session: &MobileUlcpSession,
        requests: Vec<Vec<u8>>,
        value: impl Fn(u32) -> (u32, Vec<u8>),
    ) -> UlcpSessionUpdateRecord {
        let mut last = None;
        for request in requests {
            let (tid, requested) = property_request(&request);
            let (returned, bytes) = value(requested);
            last = Some(
                session
                    .consume(property_response(tid, returned, &bytes))
                    .unwrap(),
            );
        }
        last.unwrap()
    }

    /// Capabilities of a device that is a full mesh citizen in its own
    /// right: it has an identity, advertises one, and can forward.
    fn commissionable_capabilities() -> Vec<u32> {
        vec![
            cap::HOST_FILTER,
            cap::SAVE,
            cap::DEV_NAME,
            cap::DEV_IDENTITY,
            cap::REPEATER,
            cap::IDENT,
        ]
    }

    /// Answer whatever the session asks for, for a device with the
    /// capabilities above and a factory-default device domain.
    fn commissionable_value(property: u32) -> (u32, Vec<u8>) {
        let value = match property {
            prop::LAST_STATUS => vec![0],
            prop::PROTOCOL_VERSION => vec![6, 0],
            prop::CAPS => encoded_capabilities(&commissionable_capabilities()),
            prop::DEV_NAME => b"Ridge repeater".to_vec(),
            prop::DEV_KEY => vec![0x5A; 32],
            prop::BATTERY => Vec::new(),
            prop::INTERFACE_TYPE => vec![INTERFACE_TYPE as u8],
            prop::PHY_ENABLED => vec![1],
            prop::PHY_FREQ => 915_000u32.to_le_bytes().to_vec(),
            prop::PHY_TX_POWER => vec![14],
            prop::SAVED => vec![saved::CURRENT],
            prop::HOST_RX_FILTERS => Vec::new(),
            prop::MAC_REPEATER_ENABLED => vec![0],
            prop::MAC_REPEATER_REGIONS
            | prop::MAC_REPEATER_DEFAULT_REGION
            | prop::MAC_REPEATER_MIN_RSSI
            | prop::MAC_REPEATER_MIN_SNR
            | prop::IDENT_ROLE
            | prop::DEV_PEERS
            | prop::DEV_CHANNEL_KEYS => Vec::new(),
            prop::IDENT_MOBILE => vec![0],
            prop::DEV_DISCOVERABLE => vec![1],
            other => unreachable!("unexpected property {other}"),
        };
        (property, value)
    }

    /// Answer every bounded read batch until the session stops asking.
    fn drive_reads(
        session: &MobileUlcpSession,
        requests: Vec<Vec<u8>>,
        value: impl Fn(u32) -> (u32, Vec<u8>),
    ) -> UlcpSessionUpdateRecord {
        let mut pending = requests;
        let mut last = None;
        while !pending.is_empty() {
            let update = answer_requests(session, pending, &value);
            pending = update.outbound_frames.clone();
            last = Some(update);
        }
        last.expect("at least one batch")
    }

    /// Bring a session to `Attached` against a commissionable device that
    /// reports `host_key` as its tethered host.
    fn attach_commissionable(
        session: &MobileUlcpSession,
        selected_host_key: Option<Vec<u8>>,
        host_key: Vec<u8>,
    ) -> UlcpSessionUpdateRecord {
        let begin = session.begin(selected_host_key).unwrap();
        drive_reads(session, begin.outbound_frames, move |property| {
            if property == prop::HOST_KEY {
                (property, host_key.clone())
            } else {
                commissionable_value(property)
            }
        })
    }

    /// Bring a session to `Attached` against a device that also offers the
    /// host key tables, which the commissionable fixture deliberately does
    /// not.
    fn attach_host_keys_capable(session: &MobileUlcpSession) -> UlcpSessionUpdateRecord {
        let mut capabilities = commissionable_capabilities();
        capabilities.push(cap::HOST_KEYS);
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        drive_reads(
            session,
            begin.outbound_frames,
            move |property| match property {
                prop::CAPS => (property, encoded_capabilities(&capabilities)),
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                prop::HOST_CHANNEL_KEYS | prop::HOST_PEER_KEYS => (property, Vec::new()),
                _ => commissionable_value(property),
            },
        )
    }

    /// Consume a configuration batch, returning the writes it made as a
    /// property map, the order they were issued in, and the `CMD_SAVE`
    /// transaction that closed it.
    fn drive_configuration(
        session: &MobileUlcpSession,
        first_batch: Vec<Vec<u8>>,
    ) -> (HashMap<u32, Vec<u8>>, Vec<u32>, u8) {
        let mut pending = VecDeque::from(first_batch);
        let mut written = HashMap::new();
        let mut order = Vec::new();
        loop {
            let request = pending.pop_front().expect("configuration ends in a save");
            let parsed = Frame::parse(&request).unwrap();
            if parsed.command() == Some(Cmd::Save) {
                return (written, order, parsed.header.tid());
            }
            assert_eq!(parsed.command(), Some(Cmd::PropSet));
            let payload = PropPayload::parse(parsed.payload).unwrap();
            order.push(payload.key);
            written.insert(payload.key, payload.value.to_vec());
            let update = session
                .consume(property_response(
                    parsed.header.tid(),
                    payload.key,
                    payload.value,
                ))
                .unwrap_or_else(|error| {
                    panic!("write of property {} failed: {error:?}", payload.key)
                });
            pending.extend(update.outbound_frames);
        }
    }

    #[test]
    fn exported_gatt_round_trip_uses_shared_codec() {
        let frame = ulcp_prop_get(3, 4_864).unwrap();
        let segments = ulcp_gatt_segments(frame.clone(), 4).unwrap();
        let receiver = MobileGattReassembler::new();
        let mut completed = None;
        for segment in segments {
            if let Some(value) = receiver.push(segment.value).unwrap() {
                completed = Some(value);
            }
        }
        assert_eq!(completed, Some(frame));
    }

    #[test]
    fn property_response_is_validated_and_typed() {
        let mut bytes = [0; 16];
        let length = frame::prop_is(&mut bytes, 5, 64, &[1, 2, 3]).unwrap();
        assert_eq!(
            inspect_ulcp_property_frame(bytes[..length].to_vec()).unwrap(),
            UlcpPropertyFrameRecord {
                transaction_id: 5,
                command: Cmd::PropIs as u8,
                property_id: 64,
                value: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn property_set_uses_shared_frame_codec() {
        let encoded = ulcp_prop_set(6, 96, vec![7; 32]).unwrap();
        let parsed = Frame::parse(&encoded).unwrap();
        assert_eq!(parsed.header.tid(), 6);
        assert_eq!(parsed.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.key, 96);
        assert_eq!(payload.value, &[7; 32]);
    }

    #[test]
    fn save_and_status_use_shared_frame_codec() {
        let encoded = ulcp_save(7).unwrap();
        let parsed = Frame::parse(&encoded).unwrap();
        assert_eq!(parsed.header.tid(), 7);
        assert_eq!(parsed.command(), Some(Cmd::Save));
        assert!(parsed.payload.is_empty());

        assert_eq!(inspect_ulcp_status(vec![0]).unwrap(), 0);
        assert_eq!(
            inspect_ulcp_status(vec![0x80]),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    #[test]
    fn exported_transport_rejects_invalid_bounds_and_segments() {
        assert_eq!(
            ulcp_gatt_segments(vec![0; MAX_FRAME + 1], 20),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            ulcp_gatt_segments(vec![1], 1),
            Err(MobileError::InvalidGattSegment)
        );
        assert_eq!(
            MobileGattReassembler::new().push(vec![]),
            Err(MobileError::InvalidGattSegment)
        );
    }

    #[test]
    fn battery_reduction_preserves_supported_ui_fields() {
        assert_eq!(
            inspect_ulcp_battery(vec![0b110, 82, 1]).unwrap(),
            UlcpBatteryRecord {
                percentage: Some(82),
                voltage_mv: None,
                charge_state: Some(UlcpChargeState::Charging),
            }
        );
        assert_eq!(
            inspect_ulcp_battery(vec![0b111, 0xEC, 0x0E, 82, 0]).unwrap(),
            UlcpBatteryRecord {
                percentage: Some(82),
                voltage_mv: Some(3820),
                charge_state: Some(UlcpChargeState::Discharging),
            }
        );
        assert_eq!(
            inspect_ulcp_battery(vec![]).unwrap(),
            UlcpBatteryRecord {
                percentage: None,
                voltage_mv: None,
                charge_state: None,
            }
        );
    }

    #[test]
    fn minimal_inspection_is_small_and_validated() {
        assert_eq!(
            ulcp_inspection_properties(vec![cap::WRITABLE_RAW_STREAM as u8]).unwrap(),
            [
                prop::INTERFACE_TYPE,
                prop::PHY_ENABLED,
                prop::PHY_FREQ,
                prop::PHY_TX_POWER,
            ]
        );
        let sync = inspect_ulcp_sync(vec![
            response(prop::CAPS, &[cap::WRITABLE_RAW_STREAM as u8]),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[14]),
        ])
        .unwrap();
        assert!(sync.phy_enabled);
        assert_eq!(sync.frequency_khz, 915_000);
        assert_eq!(sync.transmit_power_dbm, 14);
        assert!(!sync.has_host_filtering);
        assert_eq!(sync.queued_frames, None);
    }

    #[test]
    fn full_inspection_reports_only_digest_counts() {
        let capabilities = (cap::HOST_FILTER..=cap::BATTERY)
            .map(|capability| capability as u8)
            .collect::<Vec<_>>();
        let properties = ulcp_inspection_properties(capabilities.clone()).unwrap();
        assert!(properties.contains(&prop::HOST_RX_FILTERS));
        assert!(properties.contains(&prop::HOST_RX_QUEUE_COUNT));
        assert!(properties.contains(&prop::HOST_AUTO_ACK));

        let sync = inspect_ulcp_sync(vec![
            response(prop::CAPS, &capabilities),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &868_100u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[22]),
            response(prop::SAVED, &[1]),
            response(prop::HOST_RX_FILTERS, &[]),
            response(prop::HOST_CHANNEL_KEYS, &[1, 2, 3, 4]),
            response(prop::HOST_PEER_KEYS, &[7; 32]),
            response(prop::HOST_RX_QUEUE_COUNT, &3u16.to_le_bytes()),
            response(prop::HOST_RX_QUEUE_DROPPED, &4u32.to_le_bytes()),
            response(prop::HOST_AUTO_ACK, &[1]),
            response(prop::DEV_PEERS, &[7; 64]),
            response(prop::DEV_DISCOVERABLE, &[1]),
        ])
        .unwrap();
        assert_eq!(sync.saved, Some(SavedSnapshotRecord::Current));
        assert_eq!(sync.queued_frames, Some(3));
        assert_eq!(sync.dropped_frames, Some(4));
        assert_eq!(sync.filter_count, Some(0));
        assert_eq!(sync.host_channel_count, Some(2));
        assert_eq!(sync.host_peer_count, Some(1));
        assert_eq!(sync.auto_ack, Some(true));
        // The device-identity peer list is the one key table read back
        // losslessly rather than as a digest count.
        assert!(sync.supports_device_identity);
        assert_eq!(sync.dev_peer_keys, Some(vec![vec![7; 32], vec![7; 32]]));
    }

    #[test]
    fn invalid_capability_dependencies_and_values_fail_closed() {
        assert_eq!(
            ulcp_inspection_properties(vec![cap::HOST_RX_QUEUE as u8]),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            inspect_ulcp_sync(vec![
                response(prop::CAPS, &[]),
                response(prop::INTERFACE_TYPE, &[7]),
                response(prop::PHY_ENABLED, &[1]),
                response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            ]),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    #[test]
    fn mobile_session_owns_sync_tids_and_attaches_transparent_radio() {
        let session = MobileUlcpSession::new();
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        assert_eq!(begin.snapshot.phase, UlcpSessionPhase::Synchronizing);
        assert_eq!(begin.outbound_frames.len(), 7);
        assert_eq!(
            begin
                .outbound_frames
                .iter()
                .map(|request| property_request(request).0)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7]
        );

        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::WRITABLE_RAW_STREAM as u8]),
                prop::DEV_KEY => (property, Vec::new()),
                prop::DEV_NAME => (property, b"Transparent".to_vec()),
                prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        assert_eq!(inspection.outbound_frames.len(), 4);
        assert_eq!(
            inspection.snapshot.host_ownership,
            UlcpHostOwnership::Unsupported
        );

        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.device_name.as_deref(),
            Some("Transparent")
        );
        assert_eq!(
            attached.snapshot.provisioning.unwrap().frequency_khz,
            915_000
        );
    }

    #[test]
    fn mobile_session_owns_claim_then_save_choreography() {
        let host_key = vec![0xAA; 32];
        let session = MobileUlcpSession::new();
        let begin = session.begin(Some(host_key.clone())).unwrap();
        let awaiting =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::HOST_FILTER as u8, cap::SAVE as u8]),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY | prop::HOST_KEY => {
                    (property, Vec::new())
                }
                _ => unreachable!(),
            });
        assert_eq!(awaiting.snapshot.phase, UlcpSessionPhase::AwaitingHost);
        assert_eq!(
            awaiting.snapshot.host_ownership,
            UlcpHostOwnership::Unclaimed
        );

        let claim = session.claim(host_key.clone()).unwrap();
        assert_eq!(claim.snapshot.phase, UlcpSessionPhase::Claiming);
        assert_eq!(claim.outbound_frames.len(), 1);
        let parsed_claim = Frame::parse(&claim.outbound_frames[0]).unwrap();
        assert_eq!(parsed_claim.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed_claim.payload).unwrap();
        assert_eq!(payload.key, prop::HOST_KEY);
        assert_eq!(payload.value, host_key);

        let save = session
            .consume(property_response(
                parsed_claim.header.tid(),
                prop::HOST_KEY,
                &host_key,
            ))
            .unwrap();
        assert_eq!(save.outbound_frames.len(), 1);
        let parsed_save = Frame::parse(&save.outbound_frames[0]).unwrap();
        assert_eq!(parsed_save.command(), Some(Cmd::Save));

        let inspection = session
            .consume(property_response(
                parsed_save.header.tid(),
                prop::LAST_STATUS,
                &[0],
            ))
            .unwrap();
        assert_eq!(inspection.outbound_frames.len(), 6);
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 868_100u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    prop::SAVED => (property, vec![1]),
                    prop::HOST_RX_FILTERS => (property, Vec::new()),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(attached.snapshot.host_ownership, UlcpHostOwnership::Ours);
        assert_eq!(
            attached.snapshot.provisioning.unwrap().saved,
            Some(SavedSnapshotRecord::Current)
        );

        let changed_host = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::HOST_KEY,
                &[0xBB; 32],
            ))
            .unwrap();
        assert_eq!(changed_host.snapshot.phase, UlcpSessionPhase::AwaitingHost);
        assert_eq!(
            changed_host.snapshot.host_ownership,
            UlcpHostOwnership::OtherHost
        );
    }

    #[test]
    fn administrative_session_attaches_without_claiming_anyones_radio() {
        let phone = vec![0xAA; 32];
        let other_phone = vec![0xBB; 32];

        // A radio someone else tethered. An administrative session has no
        // decision to put to the user, so it attaches — and still reports
        // whose radio it is, because that is worth showing.
        let session = MobileUlcpSession::administrative();
        let attached = attach_commissionable(&session, Some(phone.clone()), other_phone.clone());
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.host_ownership,
            UlcpHostOwnership::OtherHost
        );
        assert_eq!(
            session.claim(phone.clone()),
            Err(MobileError::AdministrativeSession)
        );

        // An unclaimed radio likewise: commissioning ten repeaters must
        // not leave this phone's host key on any of them.
        let unclaimed = MobileUlcpSession::administrative();
        let attached = attach_commissionable(&unclaimed, Some(phone.clone()), Vec::new());
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.host_ownership,
            UlcpHostOwnership::Unclaimed
        );

        // The tethered session is the one that must pause: it is about to
        // take the radio from the other phone.
        let tethered = MobileUlcpSession::new();
        let begin = tethered.begin(Some(phone.clone())).unwrap();
        let awaiting = answer_requests(&tethered, begin.outbound_frames, move |property| {
            if property == prop::HOST_KEY {
                (property, other_phone.clone())
            } else {
                commissionable_value(property)
            }
        });
        assert_eq!(awaiting.snapshot.phase, UlcpSessionPhase::AwaitingHost);

        // A host-key change pushed mid-session does not evict an
        // administrative session either.
        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::HOST_KEY,
                &[0xCC; 32],
            ))
            .unwrap();
        assert_eq!(pushed.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(pushed.snapshot.host_ownership, UlcpHostOwnership::OtherHost);
    }

    #[test]
    fn attached_snapshot_reports_the_devices_own_domain() {
        let session = MobileUlcpSession::administrative();
        let attached = attach_commissionable(&session, None, Vec::new());
        let provisioning = attached.snapshot.provisioning.unwrap();
        assert!(provisioning.supports_repeater);
        assert!(provisioning.supports_ident);
        assert_eq!(provisioning.ident_role, None);
        assert_eq!(provisioning.ident_mobile, Some(false));
        assert_eq!(
            provisioning.repeater,
            Some(UlcpRepeaterSettingsRecord {
                enabled: false,
                regions: Vec::new(),
                default_region: None,
                min_rssi_dbm: None,
                min_snr_db: None,
            })
        );

        // A device with no repeater or identity capability reports the
        // absence rather than a default-shaped policy.
        let plain = inspect_ulcp_sync(vec![
            response(prop::CAPS, &[cap::WRITABLE_RAW_STREAM as u8]),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[14]),
        ])
        .unwrap();
        assert!(!plain.supports_repeater);
        assert!(!plain.supports_ident);
        assert_eq!(plain.repeater, None);
        assert_eq!(plain.ident_mobile, None);
    }

    #[test]
    fn repeater_policy_round_trips_through_the_sync_reducer() {
        let capabilities = encoded_capabilities(&commissionable_capabilities());
        let sync = inspect_ulcp_sync(vec![
            response(prop::CAPS, &capabilities),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[14]),
            response(prop::SAVED, &[saved::CURRENT]),
            response(prop::HOST_RX_FILTERS, &[]),
            response(prop::MAC_REPEATER_ENABLED, &[1]),
            // SJC and SFO, the two-octet codes exactly as advertised.
            response(prop::MAC_REPEATER_REGIONS, &[0x78, 0x53, 0x7C, 0x0F]),
            response(prop::MAC_REPEATER_DEFAULT_REGION, &[0x78, 0x53]),
            response(prop::MAC_REPEATER_MIN_RSSI, &(-115i16).to_le_bytes()),
            response(prop::MAC_REPEATER_MIN_SNR, &[(-7i8) as u8]),
            response(prop::IDENT_ROLE, &[3]),
            response(prop::IDENT_MOBILE, &[1]),
            response(prop::DEV_PEERS, &[]),
            response(prop::DEV_DISCOVERABLE, &[1]),
        ])
        .unwrap();
        assert_eq!(
            sync.repeater,
            Some(UlcpRepeaterSettingsRecord {
                enabled: true,
                regions: vec![vec![0x78, 0x53], vec![0x7C, 0x0F]],
                default_region: Some(vec![0x78, 0x53]),
                min_rssi_dbm: Some(-115),
                min_snr_db: Some(-7),
            })
        );
        assert_eq!(sync.ident_role, Some(3));
        assert_eq!(sync.ident_mobile, Some(true));

        // An odd-length region list is not a set of region codes, so the
        // policy is not reported — but the device still is. A repeater
        // without an identity of its own, on the other hand, is not a
        // repeater, and that is a malformed capability set.
        let malformed = |property, value: &[u8]| {
            let mut responses = vec![
                response(prop::CAPS, &capabilities),
                response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
                response(prop::PHY_ENABLED, &[1]),
                response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
                response(prop::PHY_TX_POWER, &[14]),
                response(prop::SAVED, &[saved::CURRENT]),
                response(prop::MAC_REPEATER_ENABLED, &[0]),
                response(prop::MAC_REPEATER_REGIONS, &[]),
                response(prop::MAC_REPEATER_DEFAULT_REGION, &[]),
                response(prop::MAC_REPEATER_MIN_RSSI, &[]),
                response(prop::MAC_REPEATER_MIN_SNR, &[]),
                response(prop::IDENT_ROLE, &[]),
                response(prop::IDENT_MOBILE, &[0]),
                response(prop::DEV_PEERS, &[]),
                response(prop::DEV_DISCOVERABLE, &[1]),
            ];
            responses.retain(|entry| entry.property_id != property);
            responses.push(response(property, value));
            inspect_ulcp_sync(responses)
        };
        for property in [
            prop::MAC_REPEATER_REGIONS,
            prop::MAC_REPEATER_DEFAULT_REGION,
            prop::MAC_REPEATER_MIN_RSSI,
        ] {
            let sync = malformed(property, &[0x8D, 0x53, 0x7C]).expect("device still described");
            assert_eq!(sync.repeater, None, "property {property}");
            assert!(sync.supports_repeater, "property {property}");
            assert!(
                sync.unreadable_properties.contains(&property),
                "property {property}"
            );
        }
        assert_eq!(
            ulcp_inspection_properties(encoded_capabilities(&[cap::REPEATER])),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    /// A device that refuses one capability-gated property — firmware
    /// older than the capability it advertises — is a device with one
    /// unknown setting, not one this phone cannot administer. It attaches,
    /// it describes itself, and it stays configurable; the refused setting
    /// is absent, named, and left out of the write that follows.
    #[test]
    fn a_refused_property_still_yields_an_administrable_device() {
        let session = MobileUlcpSession::administrative();
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        let attached = drive_reads(&session, begin.outbound_frames, |property| match property {
            // One property of its own, and one part of a policy that is
            // only meaningful whole.
            prop::DEV_DISCOVERABLE | prop::MAC_REPEATER_MIN_RSSI => (
                prop::LAST_STATUS,
                vec![umsh_ulcp::Status::PROP_NOT_FOUND.0 as u8],
            ),
            prop::HOST_KEY => (property, vec![0xBB; 32]),
            other => commissionable_value(other),
        });

        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        // Nobody asked to read that property in particular; they asked to
        // attach, and the attach succeeded. Reporting it as a failed
        // operation is what used to strand the caller with no snapshot.
        assert_eq!(attached.operation_error, None);
        let sync = attached.snapshot.provisioning.expect("device described");
        assert!(sync.supports_device_identity);
        assert_eq!(sync.dev_discoverable, None);
        assert_eq!(
            sync.unreadable_properties,
            vec![prop::MAC_REPEATER_MIN_RSSI, prop::DEV_DISCOVERABLE]
        );
        // The rest of the same capability is unaffected.
        assert_eq!(sync.dev_peer_keys, Some(Vec::new()));
        // A policy missing one part is not a policy, so none of it is
        // reported — the device still says it can forward.
        assert!(sync.supports_repeater);
        assert_eq!(sync.repeater, None);

        let configured = session
            .configure_device(UlcpDeviceConfigRecord {
                radio: UlcpRadioSettingsRecord {
                    device_name: None,
                    phy_enabled: true,
                    frequency_khz: 906_875,
                    transmit_power_dbm: 20,
                    bandwidth_hz: None,
                    spreading_factor: None,
                    coding_rate_denom: None,
                    duty_cycle_limit: None,
                },
                ident_role: None,
                ident_mobile: Some(true),
                dev_discoverable: Some(true),
                repeater: Some(UlcpRepeaterSettingsRecord {
                    enabled: false,
                    regions: Vec::new(),
                    default_region: None,
                    min_rssi_dbm: None,
                    min_snr_db: None,
                }),
                tz_offset_min: None,
                gnss: None,
            })
            .unwrap();
        let (written, _, _) = drive_configuration(&session, configured.outbound_frames);
        // The write the device would have rejected — failing the whole
        // pass over a setting nobody can even see — is never sent, and
        // neither is the rest of the policy it belongs to: a device left
        // forwarding under half a policy is worse than one left alone.
        assert!(!written.contains_key(&prop::DEV_DISCOVERABLE));
        for property in [
            prop::MAC_REPEATER_ENABLED,
            prop::MAC_REPEATER_REGIONS,
            prop::MAC_REPEATER_DEFAULT_REGION,
            prop::MAC_REPEATER_MIN_RSSI,
            prop::MAC_REPEATER_MIN_SNR,
        ] {
            assert!(!written.contains_key(&property), "property {property}");
        }
        assert_eq!(written.get(&prop::IDENT_MOBILE), Some(&vec![1]));
        assert_eq!(
            written.get(&prop::PHY_FREQ),
            Some(&906_875u32.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn configuring_a_device_writes_its_whole_domain_as_a_property_map() {
        let session = MobileUlcpSession::administrative();
        let attached = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xBB; 32]);
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);

        let configured = session
            .configure_device(UlcpDeviceConfigRecord {
                radio: UlcpRadioSettingsRecord {
                    device_name: Some("Ridge repeater".into()),
                    phy_enabled: true,
                    frequency_khz: 906_875,
                    transmit_power_dbm: 22,
                    bandwidth_hz: None,
                    spreading_factor: None,
                    coding_rate_denom: None,
                    duty_cycle_limit: None,
                },
                ident_role: Some(3),
                ident_mobile: Some(false),
                dev_discoverable: Some(false),
                repeater: Some(UlcpRepeaterSettingsRecord {
                    enabled: true,
                    regions: vec![vec![0x78, 0x53]],
                    default_region: Some(vec![0x78, 0x53]),
                    min_rssi_dbm: Some(-115),
                    min_snr_db: Some(-7),
                }),
                tz_offset_min: None,
                gnss: None,
            })
            .unwrap();
        assert_eq!(configured.snapshot.phase, UlcpSessionPhase::Configuring);

        let (written, order, save_tid) = drive_configuration(&session, configured.outbound_frames);

        // The whole configuration is a property -> value map with nothing
        // else in it. A template feature that produces such a map has
        // everything it needs; nothing here is shaped around this record.
        assert_eq!(
            written,
            HashMap::from([
                (prop::DEV_NAME, b"Ridge repeater".to_vec()),
                (prop::PHY_FREQ, 906_875u32.to_le_bytes().to_vec()),
                (prop::PHY_TX_POWER, vec![22]),
                (prop::IDENT_ROLE, vec![3]),
                (prop::IDENT_MOBILE, vec![0]),
                (prop::DEV_DISCOVERABLE, vec![0]),
                (prop::MAC_REPEATER_REGIONS, vec![0x78, 0x53]),
                (prop::MAC_REPEATER_DEFAULT_REGION, vec![0x78, 0x53]),
                (
                    prop::MAC_REPEATER_MIN_RSSI,
                    (-115i16).to_le_bytes().to_vec()
                ),
                (prop::MAC_REPEATER_MIN_SNR, vec![(-7i8) as u8]),
                (prop::MAC_REPEATER_ENABLED, vec![1]),
                (prop::PHY_ENABLED, vec![1]),
            ])
        );
        // Forwarding starts only once the whole policy — and the radio it
        // forwards over — is in place.
        assert_eq!(
            &order[order.len() - 2..],
            &[prop::MAC_REPEATER_ENABLED, prop::PHY_ENABLED]
        );

        let attached = session
            .consume(property_response(save_tid, prop::LAST_STATUS, &[0]))
            .unwrap();
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.host_ownership,
            UlcpHostOwnership::OtherHost
        );
        let provisioning = attached.snapshot.provisioning.unwrap();
        assert_eq!(provisioning.frequency_khz, 906_875);
        assert_eq!(provisioning.ident_role, Some(3));
        assert_eq!(
            provisioning.repeater,
            Some(UlcpRepeaterSettingsRecord {
                enabled: true,
                regions: vec![vec![0x78, 0x53]],
                default_region: Some(vec![0x78, 0x53]),
                min_rssi_dbm: Some(-115),
                min_snr_db: Some(-7),
            })
        );
    }

    #[test]
    fn device_configuration_must_match_what_the_device_can_do() {
        let session = MobileUlcpSession::administrative();
        attach_commissionable(&session, None, Vec::new());

        let radio = UlcpRadioSettingsRecord {
            device_name: None,
            phy_enabled: true,
            frequency_khz: 915_000,
            transmit_power_dbm: 14,
            bandwidth_hz: None,
            spreading_factor: None,
            coding_rate_denom: None,
            duty_cycle_limit: None,
        };
        let repeater = UlcpRepeaterSettingsRecord {
            enabled: true,
            regions: Vec::new(),
            default_region: None,
            min_rssi_dbm: None,
            min_snr_db: None,
        };
        let configure = |ident_role, ident_mobile, dev_discoverable, repeater| {
            session.configure_device(UlcpDeviceConfigRecord {
                radio: radio.clone(),
                ident_role,
                ident_mobile,
                dev_discoverable,
                repeater,
                tz_offset_min: None,
                gnss: None,
            })
        };

        // Every capability-gated field is required, because the record
        // states a whole desired configuration rather than a patch.
        assert_eq!(
            configure(Some(3), None, Some(true), Some(repeater.clone())),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            configure(None, Some(false), Some(true), None),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            configure(None, Some(false), None, Some(repeater.clone())),
            Err(MobileError::InvalidUlcpFrame)
        );
        // A region code is two octets or it is not a region code.
        assert_eq!(
            configure(
                None,
                Some(false),
                Some(true),
                Some(UlcpRepeaterSettingsRecord {
                    regions: vec![vec![0x78]],
                    ..repeater.clone()
                })
            ),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            configure(
                None,
                Some(false),
                Some(true),
                Some(UlcpRepeaterSettingsRecord {
                    default_region: Some(vec![0x78, 0x53, 0x00]),
                    ..repeater.clone()
                })
            ),
            Err(MobileError::InvalidUlcpFrame)
        );

        // An omitted role is the device deriving its own, written as an
        // empty value rather than skipped.
        let configured = configure(None, Some(true), Some(true), Some(repeater)).unwrap();
        let (written, ..) = drive_configuration(&session, configured.outbound_frames);
        assert_eq!(written.get(&prop::IDENT_ROLE), Some(&Vec::new()));
        assert_eq!(written.get(&prop::IDENT_MOBILE), Some(&vec![1]));
        assert_eq!(written.get(&prop::DEV_DISCOVERABLE), Some(&vec![1]));
        assert_eq!(written.get(&prop::MAC_REPEATER_REGIONS), Some(&Vec::new()));
        assert_eq!(written.get(&prop::MAC_REPEATER_MIN_RSSI), Some(&Vec::new()));
    }

    #[test]
    fn region_codes_convert_between_text_and_wire_octets() {
        assert_eq!(region_code_from_string("SJC".into()).unwrap(), [0x78, 0x53]);
        assert_eq!(region_code_description(vec![0x78, 0x53]).unwrap(), "SJC");
        // A name lands outside the airport letter space, so it never
        // renders as three letters and round-trips through hex.
        let named = region_code_from_string("Rogue Valley".into()).unwrap();
        assert_eq!(named, [0xDF, 0x6F]);
        let described = region_code_description(named.clone()).unwrap();
        assert_eq!(described, "0xDF6F");
        assert_eq!(region_code_from_string(described).unwrap(), named);

        assert_eq!(
            region_code_from_string("  ".into()),
            Err(MobileError::InvalidRegionCode)
        );
        assert_eq!(
            region_code_description(vec![0x78]),
            Err(MobileError::InvalidRegionCode)
        );
    }

    #[test]
    fn mobile_session_rejects_mismatched_transaction_response() {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let (tid, _) = property_request(&begin.outbound_frames[0]);
        assert_eq!(
            session.consume(property_response(tid, prop::PHY_FREQ, &[0; 4])),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    #[test]
    fn mobile_session_emits_typed_raw_receive_during_sync() {
        let session = MobileUlcpSession::new();
        session.begin(None).unwrap();

        let metadata = BufferedRxMeta {
            rx: umsh_ulcp::RxMeta {
                rssi_dbm: Some(-87),
                lqi: core::num::NonZeroU8::new(42),
                snr_cb: Some(125),
            },
            flags: RX_FLAG_BUFFERED | RX_FLAG_ACKED,
            age_s: 9,
        };
        let mut metadata_bytes = [0; BufferedRxMeta::WIRE_LEN];
        metadata.encode(&mut metadata_bytes).unwrap();
        let mut bytes = vec![0; MAX_FRAME];
        let len = frame::str_recv(
            &mut bytes,
            umsh_ulcp::ids::stream::PHY_RAW,
            &[1, 2, 3],
            &metadata_bytes,
        )
        .unwrap();
        bytes.truncate(len);

        let update = session.consume(bytes).unwrap();
        assert_eq!(update.received_frames.len(), 1);
        assert_eq!(
            update.received_frames[0],
            UlcpReceivedFrameRecord {
                data: vec![1, 2, 3],
                rssi_dbm: Some(-87),
                lqi: Some(42),
                snr_cb: Some(125),
                was_buffered: true,
                was_acknowledged: true,
                age_seconds: 9,
            }
        );
        assert!(update.outbound_frames.is_empty());
        assert!(update.waiting_for_responses);
    }

    #[test]
    fn mobile_session_reports_raw_transmit_rejection_without_ending_session() {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::WRITABLE_RAW_STREAM as u8]),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);

        let transmit = session.transmit_raw(vec![1, 2, 3], false).unwrap();
        assert!(transmit.raw_transmit_pending);
        assert_eq!(transmit.raw_transmit_result, None);
        assert_eq!(transmit.outbound_frames.len(), 1);
        let second_transmit = session.transmit_raw(vec![4], false).unwrap();
        assert_ne!(
            transmit.raw_transmit_started_transaction_id,
            second_transmit.raw_transmit_started_transaction_id
        );

        let request = Frame::parse(&transmit.outbound_frames[0]).unwrap();
        let rejected = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::INVALID_STATE.0 as u8],
            ))
            .unwrap();
        assert_eq!(rejected.snapshot.phase, UlcpSessionPhase::Attached);
        assert!(rejected.raw_transmit_pending);
        assert_eq!(
            rejected.raw_transmit_result,
            Some(UlcpRawTransmitResultRecord {
                transaction_id: request.header.tid(),
                status_code: umsh_ulcp::Status::INVALID_STATE.0,
                status_name: "Status::INVALID_STATE".into(),
                disposition: UlcpRawTransmitDisposition::Rejected,
            })
        );
        let second_request = Frame::parse(&second_transmit.outbound_frames[0]).unwrap();
        let completed = session
            .consume(property_response(
                second_request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::OK.0 as u8],
            ))
            .unwrap();
        assert!(!completed.raw_transmit_pending);

        // A radio-level rejection completes only that send; the attached
        // session remains usable for the next raw frame.
        let retryable = session.transmit_raw(vec![5], false).unwrap();
        let request = Frame::parse(&retryable.outbound_frames[0]).unwrap();
        let busy = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::BUSY.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            busy.raw_transmit_result.unwrap().disposition,
            UlcpRawTransmitDisposition::Retry
        );

        let abandoned = session.transmit_raw(vec![6], false).unwrap();
        let abandoned_request = Frame::parse(&abandoned.outbound_frames[0]).unwrap();
        assert!(
            !session
                .abandon_raw_transmits(vec![abandoned_request.header.tid()])
                .raw_transmit_pending
        );

        // A status error for an ordinary property operation is also
        // nonfatal. Finish the rest of the bounded batch, recover to Attached,
        // and prove the same session can issue another raw transmission.
        let configured = session
            .configure(UlcpRadioSettingsRecord {
                device_name: None,
                phy_enabled: true,
                frequency_khz: 915_000,
                transmit_power_dbm: 14,
                bandwidth_hz: None,
                spreading_factor: None,
                coding_rate_denom: None,
                duty_cycle_limit: None,
            })
            .unwrap();
        let mut final_update = None;
        for (index, request) in configured.outbound_frames.into_iter().enumerate() {
            let parsed = Frame::parse(&request).unwrap();
            let payload = PropPayload::parse(parsed.payload).unwrap();
            let response = if index == 0 {
                property_response(
                    parsed.header.tid(),
                    prop::LAST_STATUS,
                    &[umsh_ulcp::Status::INVALID_ARGUMENT.0 as u8],
                )
            } else {
                property_response(parsed.header.tid(), payload.key, payload.value)
            };
            let update = session.consume(response).unwrap();
            if index == 0 {
                assert_eq!(
                    update.operation_error,
                    Some(UlcpOperationErrorRecord {
                        operation: format!("set property {}", payload.key),
                        status_code: umsh_ulcp::Status::INVALID_ARGUMENT.0,
                        status_name: "Status::INVALID_ARGUMENT".into(),
                    })
                );
            }
            final_update = Some(update);
        }
        assert_eq!(
            final_update.unwrap().snapshot.phase,
            UlcpSessionPhase::Attached
        );
        assert!(session.transmit_raw(vec![6], false).is_ok());
    }

    #[test]
    fn mobile_session_verifies_radio_configuration_then_saves() {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (
                    property,
                    encoded_capabilities(&[
                        cap::SAVE,
                        cap::DEV_NAME,
                        cap::PHY_LORA,
                        cap::PHY_DUTY_LIMIT,
                    ]),
                ),
                prop::DEV_NAME => (property, b"Old name".to_vec()),
                prop::DEV_KEY | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let partial =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    prop::PHY_LORA_BW => (property, 125_000u32.to_le_bytes().to_vec()),
                    prop::PHY_LORA_SF => (property, vec![9]),
                    prop::PHY_LORA_CR => (property, vec![5]),
                    _ => unreachable!(),
                },
            );
        let attached = answer_requests(
            &session,
            partial.outbound_frames,
            |property| match property {
                prop::PHY_DUTY_NOW => (property, 65u16.to_le_bytes().to_vec()),
                prop::PHY_DUTY_LIMIT => (property, 655u16.to_le_bytes().to_vec()),
                prop::SAVED => (property, vec![1]),
                _ => unreachable!(),
            },
        );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);

        let configured = session
            .configure(UlcpRadioSettingsRecord {
                device_name: Some("Trail radio".into()),
                phy_enabled: true,
                frequency_khz: 868_100,
                transmit_power_dbm: 20,
                bandwidth_hz: Some(250_000),
                spreading_factor: Some(10),
                coding_rate_denom: Some(6),
                duty_cycle_limit: Some(6_553),
            })
            .unwrap();
        assert_eq!(configured.snapshot.phase, UlcpSessionPhase::Configuring);
        assert_eq!(
            configured.outbound_frames.len(),
            usize::from(frame::TID_MAX)
        );
        let mut pending = VecDeque::from(configured.outbound_frames);
        let mut configured_properties = Vec::new();
        let save_tid = loop {
            let request = pending.pop_front().unwrap();
            let parsed = Frame::parse(&request).unwrap();
            if parsed.command() == Some(Cmd::Save) {
                break parsed.header.tid();
            }
            assert_eq!(parsed.command(), Some(Cmd::PropSet));
            let payload = PropPayload::parse(parsed.payload).unwrap();
            configured_properties.push(payload.key);
            // This radio tops out below the 20 dBm asked for and answers
            // with the power it will actually use. A `CMD_PROP_IS` is the
            // device's word on the property, so the session takes it.
            let answer: &[u8] = match payload.key {
                prop::PHY_TX_POWER => &[17],
                _ => payload.value,
            };
            let update = session
                .consume(property_response(parsed.header.tid(), payload.key, answer))
                .unwrap_or_else(|error| {
                    panic!(
                        "configuration response for property {} failed: {error:?}",
                        payload.key
                    )
                });
            pending.extend(update.outbound_frames);
        };
        assert_eq!(configured_properties.last(), Some(&prop::PHY_ENABLED));
        let attached = session
            .consume(property_response(save_tid, prop::LAST_STATUS, &[0]))
            .unwrap();
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.device_name.as_deref(),
            Some("Trail radio")
        );
        let provisioning = attached.snapshot.provisioning.unwrap();
        assert_eq!(provisioning.frequency_khz, 868_100);
        // 20 dBm was written; the device said 17, so 17 is what the phone
        // shows.
        assert_eq!(provisioning.transmit_power_dbm, 17);
        assert_eq!(provisioning.bandwidth_hz, Some(250_000));
        assert_eq!(provisioning.spreading_factor, Some(10));
        assert_eq!(provisioning.coding_rate_denom, Some(6));
        assert_eq!(provisioning.duty_cycle_now, Some(65));
        assert_eq!(provisioning.duty_cycle_limit, Some(6_553));

        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::PHY_DUTY_NOW,
                &131u16.to_le_bytes(),
            ))
            .unwrap();
        assert_eq!(
            pushed.snapshot.provisioning.unwrap().duty_cycle_now,
            Some(131)
        );

        let refresh = session.refresh().unwrap();
        assert_eq!(refresh.snapshot.phase, UlcpSessionPhase::Attached);
        assert!(refresh.waiting_for_responses);
        let refresh_tail =
            answer_requests(
                &session,
                refresh.outbound_frames,
                |property| match property {
                    prop::DEV_NAME => (property, b"Fresh name".to_vec()),
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 910_525u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![18]),
                    prop::PHY_LORA_BW => (property, 62_500u32.to_le_bytes().to_vec()),
                    prop::PHY_LORA_SF => (property, vec![7]),
                    _ => unreachable!(),
                },
            );
        let refreshed =
            answer_requests(
                &session,
                refresh_tail.outbound_frames,
                |property| match property {
                    prop::PHY_LORA_CR => (property, vec![5]),
                    prop::PHY_DUTY_NOW => (property, 262u16.to_le_bytes().to_vec()),
                    prop::PHY_DUTY_LIMIT => (property, 655u16.to_le_bytes().to_vec()),
                    prop::SAVED => (property, vec![1]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(refreshed.snapshot.phase, UlcpSessionPhase::Attached);
        assert!(!refreshed.waiting_for_responses);
        assert_eq!(
            refreshed.snapshot.device_name.as_deref(),
            Some("Fresh name")
        );
        let refreshed = refreshed.snapshot.provisioning.unwrap();
        assert_eq!(refreshed.frequency_khz, 910_525);
        assert_eq!(refreshed.duty_cycle_now, Some(262));
        assert_eq!(refreshed.duty_cycle_limit, Some(655));
    }

    fn inserted_response(tid: u8, property: u32, item: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; MAX_FRAME];
        let length = frame::prop_inserted(&mut bytes, tid, property, item).unwrap();
        bytes.truncate(length);
        bytes
    }

    fn removed_response(tid: u8, property: u32, item: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; MAX_FRAME];
        let length = frame::prop_removed(&mut bytes, tid, property, item).unwrap();
        bytes.truncate(length);
        bytes
    }

    fn dev_peer_keys(update: &UlcpSessionUpdateRecord) -> Vec<Vec<u8>> {
        update
            .snapshot
            .provisioning
            .as_ref()
            .unwrap()
            .dev_peer_keys
            .clone()
            .unwrap()
    }

    #[test]
    fn device_peer_insert_and_remove_patch_the_table_and_chain_a_save() {
        let session = MobileUlcpSession::new();
        let attached = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(dev_peer_keys(&attached), Vec::<Vec<u8>>::new());

        let insert = session.insert_device_peer(vec![0xC1; 32]).unwrap();
        assert_eq!(insert.outbound_frames.len(), 1);
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropInsert));

        let confirmed = session
            .consume(inserted_response(
                request.header.tid(),
                prop::DEV_PEERS,
                &[0xC1; 32],
            ))
            .unwrap();
        assert_eq!(dev_peer_keys(&confirmed), vec![vec![0xC1; 32]]);
        assert_eq!(confirmed.operation_error, None);
        // The mutation is live but unsaved; CMD_SAVE rides behind it.
        assert!(confirmed.waiting_for_responses);
        assert_eq!(confirmed.outbound_frames.len(), 1);
        let save = Frame::parse(&confirmed.outbound_frames[0]).unwrap();
        assert_eq!(save.command(), Some(Cmd::Save));

        let saved = session
            .consume(property_response(
                save.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::OK.0 as u8],
            ))
            .unwrap();
        assert_eq!(saved.operation_error, None);
        assert!(!saved.waiting_for_responses);
        assert_eq!(saved.snapshot.phase, UlcpSessionPhase::Attached);

        let remove = session.remove_device_peer(vec![0xC1; 32]).unwrap();
        let request = Frame::parse(&remove.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropRemove));
        let confirmed = session
            .consume(removed_response(
                request.header.tid(),
                prop::DEV_PEERS,
                &[0xC1; 32],
            ))
            .unwrap();
        assert_eq!(dev_peer_keys(&confirmed), Vec::<Vec<u8>>::new());
        let save = Frame::parse(&confirmed.outbound_frames[0]).unwrap();
        assert_eq!(save.command(), Some(Cmd::Save));
        let saved = session
            .consume(property_response(
                save.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::OK.0 as u8],
            ))
            .unwrap();
        assert!(!saved.waiting_for_responses);
    }

    #[test]
    fn device_peer_failures_report_status_without_ending_the_session() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        // NOMEM: the list is full. Nothing changed on the device, so the
        // cache stays put and no save is chained.
        let insert = session.insert_device_peer(vec![0xC2; 32]).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        let full = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::NOMEM.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            full.operation_error,
            Some(UlcpOperationErrorRecord {
                operation: "insert device peer".into(),
                status_code: umsh_ulcp::Status::NOMEM.0,
                status_name: "Status::NOMEM".into(),
            })
        );
        assert_eq!(dev_peer_keys(&full), Vec::<Vec<u8>>::new());
        assert!(!full.waiting_for_responses);
        assert_eq!(full.snapshot.phase, UlcpSessionPhase::Attached);

        // ALREADY: the key is on the device; the cache reflects that even
        // though the operation reports a non-OK status.
        let insert = session.insert_device_peer(vec![0xC3; 32]).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        let already = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::ALREADY.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            already.operation_error.as_ref().unwrap().status_name,
            "Status::ALREADY"
        );
        assert_eq!(dev_peer_keys(&already), vec![vec![0xC3; 32]]);

        // ITEM_NOT_FOUND on remove: the key is not on the device, which is
        // what the caller asked for.
        let remove = session.remove_device_peer(vec![0xC3; 32]).unwrap();
        let request = Frame::parse(&remove.outbound_frames[0]).unwrap();
        let missing = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::ITEM_NOT_FOUND.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            missing.operation_error.as_ref().unwrap().status_name,
            "Status::ITEM_NOT_FOUND"
        );
        assert_eq!(dev_peer_keys(&missing), Vec::<Vec<u8>>::new());

        // The session remains attached and usable.
        assert!(session.insert_device_peer(vec![0xC4; 32]).is_ok());
    }

    fn dev_channel_ids(update: &UlcpSessionUpdateRecord) -> Vec<Vec<u8>> {
        update
            .snapshot
            .provisioning
            .as_ref()
            .unwrap()
            .dev_channel_ids
            .clone()
            .unwrap()
    }

    #[test]
    fn device_channel_insert_and_remove_track_identifiers_not_keys() {
        let session = MobileUlcpSession::new();
        let attached = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(dev_channel_ids(&attached), Vec::<Vec<u8>>::new());

        // The wire carries the key; the device answers with the derived
        // identifier, because a channel key is never read back.
        let key = vec![0xB7; 32];
        let id = crate::derive_channel_id(key.clone()).unwrap();
        assert_eq!(id.len(), items::CHANNEL_ID_LEN);

        let insert = session.insert_device_channel_key(key.clone()).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropInsert));

        let confirmed = session
            .consume(inserted_response(
                request.header.tid(),
                prop::DEV_CHANNEL_KEYS,
                &id,
            ))
            .unwrap();
        assert_eq!(dev_channel_ids(&confirmed), vec![id.clone()]);
        assert_eq!(confirmed.operation_error, None);
        let save = Frame::parse(&confirmed.outbound_frames[0]).unwrap();
        assert_eq!(save.command(), Some(Cmd::Save));
        let saved = session
            .consume(property_response(
                save.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::OK.0 as u8],
            ))
            .unwrap();
        assert!(!saved.waiting_for_responses);

        // Removal selects by key and is likewise confirmed by identifier.
        let remove = session.remove_device_channel_key(key).unwrap();
        let request = Frame::parse(&remove.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropRemove));
        let confirmed = session
            .consume(removed_response(
                request.header.tid(),
                prop::DEV_CHANNEL_KEYS,
                &id,
            ))
            .unwrap();
        assert_eq!(dev_channel_ids(&confirmed), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn device_channel_failures_report_status_without_ending_the_session() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let key = vec![0xC7; 32];
        let id = crate::derive_channel_id(key.clone()).unwrap();

        let insert = session.insert_device_channel_key(key.clone()).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        let full = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::NOMEM.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            full.operation_error,
            Some(UlcpOperationErrorRecord {
                operation: "insert device channel key".into(),
                status_code: umsh_ulcp::Status::NOMEM.0,
                status_name: "Status::NOMEM".into(),
            })
        );
        assert_eq!(dev_channel_ids(&full), Vec::<Vec<u8>>::new());
        assert_eq!(full.snapshot.phase, UlcpSessionPhase::Attached);

        // ALREADY means the device holds it, so the cache says so too.
        let insert = session.insert_device_channel_key(key.clone()).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        let already = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::ALREADY.0 as u8],
            ))
            .unwrap();
        assert_eq!(dev_channel_ids(&already), vec![id]);

        let remove = session.remove_device_channel_key(key).unwrap();
        let request = Frame::parse(&remove.outbound_frames[0]).unwrap();
        let missing = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::ITEM_NOT_FOUND.0 as u8],
            ))
            .unwrap();
        assert_eq!(
            missing.operation_error.as_ref().unwrap().status_name,
            "Status::ITEM_NOT_FOUND"
        );
        assert_eq!(dev_channel_ids(&missing), Vec::<Vec<u8>>::new());

        assert!(session.insert_device_channel_key(vec![0xC8; 32]).is_ok());
    }

    fn host_channel_count(update: &UlcpSessionUpdateRecord) -> Option<u32> {
        update
            .snapshot
            .provisioning
            .as_ref()
            .unwrap()
            .host_channel_count
    }

    #[test]
    fn host_channel_reconcile_inserts_what_the_radio_is_missing() {
        let session = MobileUlcpSession::new();
        let attached = attach_host_keys_capable(&session);
        assert_eq!(host_channel_count(&attached), Some(0));

        let first = vec![0xD1; 32];
        let second = vec![0xD2; 32];
        let update = session
            .reconcile_host_channel_keys(vec![first.clone(), second.clone()])
            .unwrap();

        // One insert at a time; the next rides on the previous confirmation.
        assert_eq!(update.outbound_frames.len(), 1);
        let request = Frame::parse(&update.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropInsert));
        let confirmed = session
            .consume(inserted_response(
                request.header.tid(),
                prop::HOST_CHANNEL_KEYS,
                &crate::derive_channel_id(first).unwrap(),
            ))
            .unwrap();
        assert_eq!(confirmed.outbound_frames.len(), 1);
        let request = Frame::parse(&confirmed.outbound_frames[0]).unwrap();
        let done = session
            .consume(inserted_response(
                request.header.tid(),
                prop::HOST_CHANNEL_KEYS,
                &crate::derive_channel_id(second).unwrap(),
            ))
            .unwrap();
        assert!(done.outbound_frames.is_empty());
        assert!(!done.waiting_for_responses);
        assert_eq!(done.operation_error, None);
        assert_eq!(host_channel_count(&done), Some(2));
    }

    #[test]
    fn host_channel_reconcile_is_a_no_op_when_the_radio_already_matches() {
        let session = MobileUlcpSession::new();
        attach_host_keys_capable(&session);
        let key = vec![0xD3; 32];

        let update = session
            .reconcile_host_channel_keys(vec![key.clone()])
            .unwrap();
        let request = Frame::parse(&update.outbound_frames[0]).unwrap();
        session
            .consume(inserted_response(
                request.header.tid(),
                prop::HOST_CHANNEL_KEYS,
                &crate::derive_channel_id(key.clone()).unwrap(),
            ))
            .unwrap();

        // Reconciling the same set again asks the radio for nothing, which is
        // what makes reconnecting cheap.
        let again = session.reconcile_host_channel_keys(vec![key]).unwrap();
        assert!(again.outbound_frames.is_empty());
        assert!(!again.waiting_for_responses);
    }

    #[test]
    fn host_channel_reconcile_replaces_the_table_to_shed_an_unknown_channel() {
        let session = MobileUlcpSession::new();
        attach_host_keys_capable(&session);
        let stranger = vec![0xD4; 32];

        // Something else provisioned a channel this phone has no key for.
        let update = session
            .reconcile_host_channel_keys(vec![stranger.clone()])
            .unwrap();
        let request = Frame::parse(&update.outbound_frames[0]).unwrap();
        session
            .consume(inserted_response(
                request.header.tid(),
                prop::HOST_CHANNEL_KEYS,
                &crate::derive_channel_id(stranger).unwrap(),
            ))
            .unwrap();

        // Removal selects by key, so an unnameable entry forces a whole-table
        // write rather than a remove.
        let mine = vec![0xD5; 32];
        let replace = session
            .reconcile_host_channel_keys(vec![mine.clone()])
            .unwrap();
        let request = Frame::parse(&replace.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropSet));

        let done = session
            .consume(property_response(
                request.header.tid(),
                prop::HOST_CHANNEL_KEYS,
                &crate::derive_channel_id(mine).unwrap(),
            ))
            .unwrap();
        assert_eq!(host_channel_count(&done), Some(1));
        assert!(!done.waiting_for_responses);
    }

    #[test]
    fn a_full_host_channel_table_reports_status_and_stays_attached() {
        let session = MobileUlcpSession::new();
        attach_host_keys_capable(&session);

        let update = session
            .reconcile_host_channel_keys(vec![vec![0xD6; 32], vec![0xD7; 32]])
            .unwrap();
        let request = Frame::parse(&update.outbound_frames[0]).unwrap();
        let full = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::NOMEM.0 as u8],
            ))
            .unwrap();

        assert_eq!(
            full.operation_error.as_ref().unwrap().status_name,
            "Status::NOMEM"
        );
        // The pass stops rather than hammering a table it cannot fit, and the
        // session stays usable.
        assert!(full.outbound_frames.is_empty());
        assert!(!full.waiting_for_responses);
        assert_eq!(full.snapshot.phase, UlcpSessionPhase::Attached);
    }

    #[test]
    fn an_already_stored_host_channel_key_is_success() {
        let session = MobileUlcpSession::new();
        attach_host_keys_capable(&session);

        let update = session
            .reconcile_host_channel_keys(vec![vec![0xD8; 32]])
            .unwrap();
        let request = Frame::parse(&update.outbound_frames[0]).unwrap();
        let already = session
            .consume(property_response(
                request.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::ALREADY.0 as u8],
            ))
            .unwrap();
        assert_eq!(already.operation_error, None);
        assert!(!already.waiting_for_responses);
    }

    #[test]
    fn device_channel_keys_must_be_full_length() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(
            session.insert_device_channel_key(vec![0x01; 31]),
            Err(MobileError::InvalidChannelKeyLength)
        );
        assert_eq!(
            session.remove_device_channel_key(Vec::new()),
            Err(MobileError::InvalidChannelKeyLength)
        );
    }

    #[test]
    fn device_peer_operations_require_the_device_identity_capability() {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, vec![cap::WRITABLE_RAW_STREAM as u8]),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            session.insert_device_peer(vec![0xC1; 32]).unwrap_err(),
            MobileError::InvalidUlcpFrame
        );
        assert_eq!(
            session.remove_device_peer(vec![0xC1; 32]).unwrap_err(),
            MobileError::InvalidUlcpFrame
        );
        // And a malformed key is rejected before any frame is built.
        assert_eq!(
            session.insert_device_peer(vec![0xC1; 31]).unwrap_err(),
            MobileError::InvalidPublicKeyLength
        );
    }

    /// Attach a battery-reporting device and return the session sitting in
    /// the attached phase.
    fn attached_battery_session() -> std::sync::Arc<MobileUlcpSession> {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, encoded_capabilities(&[cap::BATTERY])),
                // Voltage + level + charge state, discharging at 60 %.
                prop::BATTERY => (property, vec![0b111, 0x74, 0x0E, 60, 0]),
                prop::DEV_KEY | prop::DEV_NAME => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        session
    }

    #[test]
    fn battery_is_reported_once_per_measurement_not_on_every_update() {
        let session = attached_battery_session();

        // An unsolicited snapshot is carried by the update that receives
        // it: 45 %, now charging.
        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::BATTERY,
                &[0b111, 0x10, 0x10, 45, 1],
            ))
            .unwrap();
        let battery = pushed.snapshot.battery.expect("push carries the snapshot");
        assert_eq!(battery.percentage, Some(45));
        assert_eq!(battery.voltage_mv, Some(0x1010));
        assert_eq!(battery.charge_state, Some(UlcpChargeState::Charging));

        // A later update that carries no measurement must not repeat it.
        // Consumers timestamp what they receive, so a repeat would report
        // a stale reading as a fresh one.
        let unrelated = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::DEV_NAME,
                b"Ridge repeater",
            ))
            .unwrap();
        assert!(unrelated.snapshot.battery.is_none());
        assert_eq!(
            unrelated.snapshot.device_name.as_deref(),
            Some("Ridge repeater"),
            "unrelated state still propagates"
        );

        // The next measurement is reported again.
        let again = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::BATTERY,
                &[0b111, 0x20, 0x10, 50, 1],
            ))
            .unwrap();
        assert_eq!(
            again.snapshot.battery.expect("second push").percentage,
            Some(50)
        );
    }

    /// Attach an alert-capable device sitting in the attached phase.
    fn attached_alert_session() -> std::sync::Arc<MobileUlcpSession> {
        let session = MobileUlcpSession::new();
        let begin = session.begin(None).unwrap();
        let inspection =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                prop::CAPS => (property, encoded_capabilities(&[cap::ALERT])),
                prop::DEV_KEY | prop::DEV_NAME | prop::BATTERY => (property, Vec::new()),
                prop::HOST_KEY => (prop::LAST_STATUS, vec![2]),
                _ => unreachable!(),
            });
        let attached =
            answer_requests(
                &session,
                inspection.outbound_frames,
                |property| match property {
                    prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                    prop::PHY_ENABLED => (property, vec![1]),
                    prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                    prop::PHY_TX_POWER => (property, vec![14]),
                    prop::ALERT => (property, vec![0]),
                    _ => unreachable!(),
                },
            );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(attached.snapshot.alert, Some(UlcpAlertState::None));
        session
    }

    #[test]
    fn alert_state_follows_the_radio_not_the_request() {
        let session = attached_alert_session();

        let request = session.set_alert(UlcpAlertState::Locate).unwrap();
        let [frame] = &request.outbound_frames[..] else {
            panic!("one CMD_PROP_SET");
        };
        let parsed = Frame::parse(frame).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!((payload.key, payload.value), (prop::ALERT, &[1u8][..]));

        let started = session
            .consume(property_response(parsed.header.tid(), prop::ALERT, &[1]))
            .unwrap();
        assert_eq!(started.snapshot.alert, Some(UlcpAlertState::Locate));

        // Unlike battery, the state persists across unrelated updates —
        // the UI mirrors it rather than reacting to it once.
        let unrelated = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::DEV_NAME,
                b"Ridge repeater",
            ))
            .unwrap();
        assert_eq!(unrelated.snapshot.alert, Some(UlcpAlertState::Locate));

        // Someone presses the button on the radio (or its deadline
        // expires): the unsolicited update is what the phone believes.
        let cancelled = session
            .consume(property_response(frame::TID_UNSOLICITED, prop::ALERT, &[0]))
            .unwrap();
        assert_eq!(cancelled.snapshot.alert, Some(UlcpAlertState::None));
        assert_eq!(cancelled.snapshot.phase, UlcpSessionPhase::Attached);
    }

    #[test]
    fn alert_needs_the_capability() {
        let session = attached_battery_session();
        assert_eq!(
            session.set_alert(UlcpAlertState::Locate).unwrap_err(),
            MobileError::UnsupportedCapability
        );
        // And a radio that never reported one leaves the field empty, so
        // the UI can hide the control rather than show a dead button.
        let update = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::BATTERY,
                &[0b111, 0x10, 0x10, 45, 1],
            ))
            .unwrap();
        assert_eq!(update.snapshot.alert, None);
    }

    #[test]
    fn malformed_alert_values_are_rejected() {
        assert_eq!(inspect_ulcp_alert(vec![0]).unwrap(), UlcpAlertState::None);
        assert_eq!(inspect_ulcp_alert(vec![1]).unwrap(), UlcpAlertState::Locate);
        // Unknown state, trailing bytes, and the empty value.
        assert!(inspect_ulcp_alert(vec![2]).is_err());
        assert!(inspect_ulcp_alert(vec![1, 0]).is_err());
        assert!(inspect_ulcp_alert(Vec::new()).is_err());
    }

    /// A commissionable device that also keeps a clock and has a receiver
    /// holding a three-dimensional fix.
    fn attach_positioning(session: &MobileUlcpSession) -> UlcpSessionUpdateRecord {
        let mut capabilities = commissionable_capabilities();
        capabilities.extend([cap::TIME, cap::GNSS]);
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        drive_reads(
            session,
            begin.outbound_frames,
            move |property| match property {
                prop::CAPS => (property, encoded_capabilities(&capabilities)),
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                prop::TIME => (property, 1_754_000_000u32.to_le_bytes().to_vec()),
                // Pacific daylight time, which is an offset and not a zone
                // — the device has no database to shift itself with.
                prop::TZ_OFFSET => (property, (-420i16).to_le_bytes().to_vec()),
                prop::GNSS_ENABLED | prop::GNSS_IDENT_UPDATE | prop::GNSS_TIME_TRUST => {
                    (property, vec![1])
                }
                prop::GNSS_LOCATION => (property, placed_location().as_bytes().to_vec()),
                prop::GNSS_ALTITUDE => (property, 71i32.to_le_bytes().to_vec()),
                prop::GNSS_FIX => (property, vec![2]),
                prop::GNSS_PRECISION => (property, 62u16.to_le_bytes().to_vec()),
                prop::GNSS_SATELLITES => (property, vec![9, 14]),
                prop::GNSS_IDENT_PRECISION => (property, vec![5]),
                _ => commissionable_value(property),
            },
        )
    }

    /// A five-byte fix — a ~38 m cell, the default identity precision.
    fn placed_location() -> NodeLocation {
        NodeLocation::from_e7(-1_224_194_160, 377_749_290, 5)
    }

    #[test]
    fn a_positioning_device_reports_its_fix_and_its_policy() {
        let session = MobileUlcpSession::new();
        let attached = attach_positioning(&session);
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);

        let sync = attached.snapshot.provisioning.clone().expect("described");
        assert!(sync.supports_time && sync.supports_gnss);
        assert_eq!(sync.tz_offset_min, Some(-420));
        assert_eq!(
            sync.gnss,
            Some(UlcpGnssSettingsRecord {
                enabled: true,
                ident_update: true,
                ident_precision: 5,
                time_trust: true,
            })
        );
        assert!(sync.unreadable_properties.is_empty());

        let gnss = attached.snapshot.gnss.expect("a receiver was read");
        assert_eq!(gnss.fix, UlcpFixKind::ThreeD);
        assert_eq!(gnss.altitude_m, Some(71));
        assert_eq!(gnss.accuracy_dm, Some(62));
        assert_eq!(
            (gnss.satellites_used, gnss.satellites_in_view),
            (9, Some(14))
        );
        assert_eq!(gnss.location, placed_location().as_bytes());
        // The center of the cell the fix named, which is as close to the
        // encoded position as a cell that size can be.
        let (longitude, latitude) = (gnss.longitude_deg.unwrap(), gnss.latitude_deg.unwrap());
        assert!((longitude + 122.419_416).abs() < 5e-4, "{longitude}");
        assert!((latitude - 37.774_929).abs() < 5e-4, "{latitude}");
        assert!((38.0..39.0).contains(&gnss.location_cell_meters.unwrap()));
    }

    #[test]
    fn the_clock_is_reported_once_and_the_fix_is_mirrored() {
        let session = MobileUlcpSession::new();
        attach_positioning(&session);

        // Unrelated news must not restamp the clock read at attach as a
        // fresh one, but it must not lose the position either: the pin
        // stays on the map, the clock does not get a new timestamp.
        let unrelated = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::DEV_NAME,
                b"Ridge repeater",
            ))
            .unwrap();
        assert_eq!(unrelated.snapshot.time, None);
        assert_eq!(
            unrelated.snapshot.gnss.expect("still known").fix,
            UlcpFixKind::ThreeD
        );

        // An announced fix change folds into what is already known rather
        // than replacing it: the satellite count came a frame earlier and
        // is still true.
        let lost = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::GNSS_FIX,
                &[1],
            ))
            .unwrap();
        let gnss = lost.snapshot.gnss.expect("still known");
        assert_eq!(gnss.fix, UlcpFixKind::TwoD);
        assert_eq!(gnss.satellites_used, 9);
        assert_eq!(gnss.altitude_m, Some(71));

        // The device finding the time on its own is announced, and is
        // reported once like any other reading.
        let stepped = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::TIME,
                &1_754_000_600u32.to_le_bytes(),
            ))
            .unwrap();
        assert_eq!(
            stepped.snapshot.time,
            Some(UlcpTimeRecord {
                epoch_seconds: Some(1_754_000_600)
            })
        );
        assert_eq!(stepped.snapshot.phase, UlcpSessionPhase::Attached);
    }

    #[test]
    fn setting_the_clock_writes_the_epoch_and_clearing_it_writes_nothing() {
        let session = MobileUlcpSession::new();
        attach_positioning(&session);

        let request = session.set_time(Some(1_754_000_900)).unwrap();
        let [frame] = &request.outbound_frames[..] else {
            panic!("one CMD_PROP_SET");
        };
        let parsed = Frame::parse(frame).unwrap();
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.key, prop::TIME);
        assert_eq!(payload.value, &1_754_000_900u32.to_le_bytes()[..]);

        // What the device answers is what the snapshot reports, even when
        // it is not what was written — a trusted receiver may have moved
        // the clock between the write and the echo.
        let set = session
            .consume(property_response(
                parsed.header.tid(),
                prop::TIME,
                &1_754_000_901u32.to_le_bytes(),
            ))
            .unwrap();
        assert_eq!(
            set.snapshot.time,
            Some(UlcpTimeRecord {
                epoch_seconds: Some(1_754_000_901)
            })
        );

        // The empty value is how a clock goes back to unknown.
        let clearing = session.set_time(None).unwrap();
        let parsed = Frame::parse(&clearing.outbound_frames[0]).unwrap();
        let payload = PropPayload::parse(parsed.payload).unwrap();
        assert_eq!((payload.key, payload.value), (prop::TIME, &[][..]));
        let cleared = session
            .consume(property_response(parsed.header.tid(), prop::TIME, &[]))
            .unwrap();
        assert_eq!(
            cleared.snapshot.time,
            Some(UlcpTimeRecord {
                epoch_seconds: None
            })
        );
    }

    #[test]
    fn the_clock_needs_the_capability() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(
            session.set_time(Some(1_754_000_900)).unwrap_err(),
            MobileError::UnsupportedCapability
        );
        let sync = session
            .refresh()
            .unwrap()
            .snapshot
            .provisioning
            .expect("described");
        assert!(!sync.supports_time && !sync.supports_gnss);
        assert_eq!((sync.tz_offset_min, sync.gnss), (None, None));
    }

    #[test]
    fn positioning_settings_are_written_whole_with_the_receiver_last() {
        let session = MobileUlcpSession::administrative();
        attach_positioning(&session);

        let configured = session
            .configure_device(UlcpDeviceConfigRecord {
                radio: UlcpRadioSettingsRecord {
                    device_name: None,
                    phy_enabled: true,
                    frequency_khz: 915_000,
                    transmit_power_dbm: 14,
                    bandwidth_hz: None,
                    spreading_factor: None,
                    coding_rate_denom: None,
                    duty_cycle_limit: None,
                },
                ident_role: None,
                ident_mobile: Some(false),
                dev_discoverable: Some(true),
                repeater: Some(UlcpRepeaterSettingsRecord {
                    enabled: false,
                    regions: Vec::new(),
                    default_region: None,
                    min_rssi_dbm: None,
                    min_snr_db: None,
                }),
                tz_offset_min: Some(60),
                gnss: Some(UlcpGnssSettingsRecord {
                    enabled: true,
                    ident_update: false,
                    ident_precision: 3,
                    time_trust: false,
                }),
            })
            .unwrap();
        let (written, order, _) = drive_configuration(&session, configured.outbound_frames);
        assert_eq!(
            written.get(&prop::TZ_OFFSET),
            Some(&60i16.to_le_bytes().to_vec())
        );
        assert_eq!(written.get(&prop::GNSS_IDENT_UPDATE), Some(&vec![0]));
        assert_eq!(written.get(&prop::GNSS_IDENT_PRECISION), Some(&vec![3]));
        assert_eq!(written.get(&prop::GNSS_TIME_TRUST), Some(&vec![0]));
        assert_eq!(written.get(&prop::GNSS_ENABLED), Some(&vec![1]));

        // The receiver starts under the disclosure and trust policy just
        // written, never the one it happened to be holding.
        let switch = order.iter().position(|key| *key == prop::GNSS_ENABLED);
        for policy in [
            prop::GNSS_IDENT_UPDATE,
            prop::GNSS_IDENT_PRECISION,
            prop::GNSS_TIME_TRUST,
        ] {
            assert!(
                order.iter().position(|key| *key == policy) < switch,
                "{policy}"
            );
        }
    }

    #[test]
    fn a_positioning_record_must_match_what_the_device_can_do() {
        let session = MobileUlcpSession::administrative();
        attach_positioning(&session);

        let whole = UlcpDeviceConfigRecord {
            radio: UlcpRadioSettingsRecord {
                device_name: None,
                phy_enabled: true,
                frequency_khz: 915_000,
                transmit_power_dbm: 14,
                bandwidth_hz: None,
                spreading_factor: None,
                coding_rate_denom: None,
                duty_cycle_limit: None,
            },
            ident_role: None,
            ident_mobile: Some(false),
            dev_discoverable: Some(true),
            repeater: Some(UlcpRepeaterSettingsRecord {
                enabled: false,
                regions: Vec::new(),
                default_region: None,
                min_rssi_dbm: None,
                min_snr_db: None,
            }),
            tz_offset_min: Some(0),
            gnss: Some(UlcpGnssSettingsRecord {
                enabled: true,
                ident_update: false,
                ident_precision: 5,
                time_trust: true,
            }),
        };

        // Both gated fields are required on a device that has them.
        assert_eq!(
            session.configure_device(UlcpDeviceConfigRecord {
                tz_offset_min: None,
                ..whole.clone()
            }),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            session.configure_device(UlcpDeviceConfigRecord {
                gnss: None,
                ..whole.clone()
            }),
            Err(MobileError::InvalidUlcpFrame)
        );
        // A precision outside 1–7 names no cell.
        assert_eq!(
            session.configure_device(UlcpDeviceConfigRecord {
                gnss: Some(UlcpGnssSettingsRecord {
                    ident_precision: 8,
                    ..whole.gnss.unwrap()
                }),
                ..whole.clone()
            }),
            Err(MobileError::InvalidUlcpFrame)
        );
        // And an offset no zone on Earth uses.
        assert_eq!(
            session.configure_device(UlcpDeviceConfigRecord {
                tz_offset_min: Some(15 * 60),
                ..whole.clone()
            }),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    #[test]
    fn half_a_positioning_policy_is_withdrawn_whole() {
        let session = MobileUlcpSession::administrative();
        let mut capabilities = commissionable_capabilities();
        capabilities.extend([cap::TIME, cap::GNSS]);
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        let attached = drive_reads(
            &session,
            begin.outbound_frames,
            move |property| match property {
                prop::CAPS => (property, encoded_capabilities(&capabilities)),
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                // Firmware older than the capability it advertises.
                prop::GNSS_TIME_TRUST => (
                    prop::LAST_STATUS,
                    vec![umsh_ulcp::Status::PROP_NOT_FOUND.0 as u8],
                ),
                prop::TIME => (property, Vec::new()),
                prop::TZ_OFFSET => (property, 0i16.to_le_bytes().to_vec()),
                prop::GNSS_ENABLED | prop::GNSS_IDENT_UPDATE => (property, vec![0]),
                prop::GNSS_IDENT_PRECISION => (property, vec![5]),
                prop::GNSS_LOCATION | prop::GNSS_ALTITUDE | prop::GNSS_PRECISION => {
                    (property, Vec::new())
                }
                prop::GNSS_FIX => (property, vec![0]),
                prop::GNSS_SATELLITES => (property, vec![0]),
                _ => commissionable_value(property),
            },
        );

        let sync = attached.snapshot.provisioning.clone().expect("described");
        assert!(sync.supports_gnss);
        assert_eq!(sync.gnss, None);
        assert_eq!(sync.unreadable_properties, vec![prop::GNSS_TIME_TRUST]);
        // A receiver that is off answers the facts it is sure of and
        // leaves the position empty.
        let gnss = attached.snapshot.gnss.expect("the receiver was read");
        assert_eq!(gnss.fix, UlcpFixKind::None);
        assert!(gnss.location.is_empty());
        assert_eq!(gnss.latitude_deg, None);

        // None of the group is written, because a receiver switched on
        // under half a policy is worse than one left alone.
        let configured = session
            .configure_device(UlcpDeviceConfigRecord {
                radio: UlcpRadioSettingsRecord {
                    device_name: None,
                    phy_enabled: true,
                    frequency_khz: 915_000,
                    transmit_power_dbm: 14,
                    bandwidth_hz: None,
                    spreading_factor: None,
                    coding_rate_denom: None,
                    duty_cycle_limit: None,
                },
                ident_role: None,
                ident_mobile: Some(false),
                dev_discoverable: Some(true),
                repeater: Some(UlcpRepeaterSettingsRecord {
                    enabled: false,
                    regions: Vec::new(),
                    default_region: None,
                    min_rssi_dbm: None,
                    min_snr_db: None,
                }),
                tz_offset_min: Some(0),
                gnss: Some(UlcpGnssSettingsRecord {
                    enabled: true,
                    ident_update: true,
                    ident_precision: 5,
                    time_trust: true,
                }),
            })
            .unwrap();
        let (written, _, _) = drive_configuration(&session, configured.outbound_frames);
        for property in [
            prop::GNSS_ENABLED,
            prop::GNSS_IDENT_UPDATE,
            prop::GNSS_IDENT_PRECISION,
            prop::GNSS_TIME_TRUST,
        ] {
            assert!(!written.contains_key(&property), "property {property}");
        }
        // The zone is its own property and is unaffected.
        assert_eq!(
            written.get(&prop::TZ_OFFSET),
            Some(&0i16.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn a_receiver_without_a_clock_is_not_a_device_this_phone_believes() {
        // CAP_GNSS requires CAP_TIME: the device dates its own fixes, so a
        // receiver with no clock to date them against is a malformed
        // capability set rather than a limited device.
        assert_eq!(
            ulcp_inspection_properties(encoded_capabilities(&[cap::GNSS])),
            Err(MobileError::InvalidUlcpFrame)
        );

        // The clock is read at attach along with the policy, so a phone
        // that has just connected knows whether the device knows the time
        // rather than waiting for the next announcement to find out.
        let asked =
            ulcp_inspection_properties(encoded_capabilities(&[cap::TIME, cap::GNSS])).unwrap();
        for property in [
            prop::TIME,
            prop::TZ_OFFSET,
            prop::GNSS_ENABLED,
            prop::GNSS_LOCATION,
            prop::GNSS_FIX,
            prop::GNSS_SATELLITES,
            prop::GNSS_TIME_TRUST,
        ] {
            assert!(asked.contains(&property), "property {property}");
        }
        // And a device with a clock and no receiver is asked for neither.
        let clock_only = ulcp_inspection_properties(encoded_capabilities(&[cap::TIME])).unwrap();
        assert!(clock_only.contains(&prop::TIME));
        assert!(!clock_only.contains(&prop::GNSS_ENABLED));
    }

    #[test]
    fn a_precision_outside_the_encoding_names_no_cell() {
        assert_eq!(ulcp_location_cell_meters(0), None);
        assert_eq!(ulcp_location_cell_meters(8), None);
        // The default identity precision discloses a ~38 m cell.
        let five = ulcp_location_cell_meters(5).unwrap();
        assert!((38.0..39.0).contains(&five), "{five}");
    }

    #[test]
    fn battery_push_does_not_move_an_attached_session_out_of_phase() {
        let session = attached_battery_session();
        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::BATTERY,
                &[0b111, 0x10, 0x10, 45, 1],
            ))
            .unwrap();
        assert_eq!(pushed.snapshot.phase, UlcpSessionPhase::Attached);
        assert!(!pushed.waiting_for_responses);
        assert!(pushed.outbound_frames.is_empty());
    }

    #[test]
    fn battery_push_to_a_tethered_session_on_another_phones_radio_stays_attached() {
        // A tethered claim that did not take is an answer, not a failure:
        // synchronization completes and the session attaches while
        // `ownership()` reports `OtherHost` (see the `Claim` arm). Battery
        // is the first unsolicited notification that arrives *routinely*,
        // so this is the path that turns a latent re-decision into one the
        // user would actually see — a settled session must not bounce back
        // to awaiting-host every time the radio reports its charge.
        let session = MobileUlcpSession::new();
        let ours = vec![0x11; 32];
        let theirs = vec![0x22; 32];
        let begin = session.begin(Some(ours.clone())).unwrap();
        let synchronized =
            answer_requests(&session, begin.outbound_frames, |property| match property {
                prop::LAST_STATUS => (property, vec![0]),
                prop::PROTOCOL_VERSION => (property, vec![6, 0]),
                // A readable `PROP_HOST_KEY` requires `CAP_HOST_FILTER`
                // and vice versa (`advance_completed_stage` enforces it).
                prop::CAPS => (
                    property,
                    encoded_capabilities(&[cap::BATTERY, cap::HOST_FILTER]),
                ),
                prop::BATTERY => (property, vec![0b111, 0x74, 0x0E, 60, 0]),
                prop::DEV_KEY | prop::DEV_NAME => (property, Vec::new()),
                // The radio already belongs to another identity.
                prop::HOST_KEY => (property, theirs.clone()),
                _ => unreachable!(),
            });
        assert_eq!(
            synchronized.snapshot.host_ownership,
            UlcpHostOwnership::OtherHost
        );
        assert_eq!(synchronized.snapshot.phase, UlcpSessionPhase::AwaitingHost);

        // The user takes the radio; the device refuses the write and keeps
        // reporting the other identity's key. No `CAP_SAVE`, so the claim
        // answer runs straight into inspection.
        let claim = session.claim(ours).unwrap();
        let claim_tid = Frame::parse(&claim.outbound_frames[0])
            .unwrap()
            .header
            .tid();
        let claimed = session
            .consume(property_response(claim_tid, prop::HOST_KEY, &theirs))
            .unwrap();
        let attached = answer_requests(
            &session,
            claimed.outbound_frames,
            |property| match property {
                prop::INTERFACE_TYPE => (property, vec![INTERFACE_TYPE as u8]),
                prop::PHY_ENABLED => (property, vec![1]),
                prop::PHY_FREQ => (property, 915_000u32.to_le_bytes().to_vec()),
                prop::PHY_TX_POWER => (property, vec![14]),
                prop::HOST_RX_FILTERS => (property, Vec::new()),
                _ => unreachable!(),
            },
        );
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.host_ownership,
            UlcpHostOwnership::OtherHost,
            "the claim did not take"
        );

        let pushed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::BATTERY,
                &[0b111, 0x10, 0x10, 45, 1],
            ))
            .unwrap();
        assert_eq!(
            pushed.snapshot.battery.expect("push carries it").percentage,
            Some(45)
        );
        assert_eq!(
            pushed.snapshot.phase,
            UlcpSessionPhase::Attached,
            "a battery report is not an attach decision"
        );

        // The decision itself is still re-opened by the one change that
        // warrants it: the radio reporting a different owner.
        let reclaimed = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::HOST_KEY,
                &[0x33; 32],
            ))
            .unwrap();
        assert_eq!(
            reclaimed.snapshot.phase,
            UlcpSessionPhase::AwaitingHost,
            "a third phone taking the radio is the user's call"
        );
    }
}
