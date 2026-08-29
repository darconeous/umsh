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
    hdlc,
    host::{PropertyNotification, PropertyNotificationError, TidAllocator},
    ids::{
        INTERFACE_TYPE, MAX_AUTO_ANNOUNCE_INTERVAL_S, MIN_AUTO_ANNOUNCE_INTERVAL_S,
        PROTOCOL_MAJOR_VERSION, PROTOCOL_MINOR_VERSION, cap, prop, saved,
    },
    items::{self, Filter},
    meta::{BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED},
    pui,
};

use crate::{
    MobileError,
    mobile_mesh::{MobileMeshManagementAnswerRecord, MobileMeshPropertyWriteRecord},
};

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
/// The filter is written as region strings — the same strings the device
/// advertises as its Supported Regions identity option — while the
/// default tag is a 2-octet code, because that is what goes on the air
/// packet by packet. [`region_code_from_string`] and
/// [`region_code_description`] convert between the two.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpRepeaterSettingsRecord {
    /// `PROP_MAC_REPEATER_ENABLED`. The remaining fields are inert while
    /// this is false, but are still read and written.
    pub enabled: bool,
    /// `PROP_MAC_REPEATER_REGIONS`: which region-tagged floods to
    /// forward, as region strings of 1 to 24 octets — a short code, a
    /// name, or a literal `0x1234`. Empty imposes no regional
    /// restriction rather than blocking every flood.
    pub regions: Vec<String>,
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

/// What the device announces without being asked.
///
/// Read and written as a whole, like [`UlcpGnssSettingsRecord`], because
/// the two schedules are how much of the mesh's airtime this device
/// claims and an operator sets that as one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpAdvertSettingsRecord {
    /// `PROP_ADVERT_INTERVAL`: seconds between signed identity
    /// advertisements, 0 for none. An advertisement reaches only the
    /// device's own neighbours.
    pub advert_interval_seconds: u32,
    /// `PROP_BEACON_INTERVAL`: seconds between empty beacons, 0 for none.
    /// A beacon floods, collecting the path back to the device as it
    /// goes, and costs a fraction of an advertisement.
    pub beacon_interval_seconds: u32,
    /// `PROP_STARTUP_BEACON`: whether one beacon goes out at bring-up.
    pub startup_beacon: bool,
}

/// Where the device says it is: the claim it advertises, not a
/// measurement.
///
/// A position names a cell rather than a point, so the encoded cell is
/// carried verbatim alongside what it decodes to — the bytes are what a
/// region proposal needs, because the cell's bounds *are* the
/// uncertainty, and the degrees are what a readout shows.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct UlcpIdentPositionRecord {
    /// `PROP_IDENT_LOCATION` verbatim. Empty is a device advertising no
    /// position, which is a value rather than an absence.
    pub location: Vec<u8>,
    /// The center of the advertised cell, absent when there is none.
    pub latitude_deg: Option<f64>,
    /// See `latitude_deg`.
    pub longitude_deg: Option<f64>,
    /// How wide the advertised cell is at the equator, in meters.
    pub cell_meters: Option<f64>,
    /// `PROP_IDENT_ALTITUDE` in whole meters, absent at no stated height.
    pub altitude_m: Option<i32>,
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
// Not `Eq`: the advertised position carries decoded degrees, and a
// coordinate is a measurement rather than an identity. Nothing compares
// snapshots for anything but equality.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct UlcpSyncRecord {
    pub capability_count: u32,
    pub has_host_filtering: bool,
    pub supports_offline_queue: bool,
    pub supports_delegated_ack: bool,
    pub supports_device_name: bool,
    /// `PROP_DEV_NAME`, when the device has one and reported it. Empty is
    /// a device with no name rather than a device named "".
    pub device_name: Option<String>,
    pub supports_lora: bool,
    pub supports_duty_cycle_limit: bool,
    /// The device measures its own power state (`CAP_BATTERY`). A device
    /// without it never reports a battery, so callers have nothing to show.
    pub supports_battery: bool,
    /// `PROP_BATTERY`, when the device measures one and has reported it.
    ///
    /// A reading rather than a setting, and absent for a reason that is
    /// never a fault: on the local link a device announces this on its own
    /// schedule, so a session that has only just attached has not heard one
    /// yet. Deliberately not counted among `unreadable_properties` — there
    /// is no setting here to be written over.
    pub battery: Option<UlcpBatteryRecord>,
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
    /// The device announces itself on a schedule of its own
    /// (`CAP_ADVERT`).
    pub supports_advert: bool,
    /// The device answers Node Management Requests from the administrators
    /// it lists (`CAP_ADMIN`). A device without it can only ever be
    /// configured by whoever is holding it.
    pub supports_admin: bool,
    /// The device can make itself conspicuous on request (`CAP_ALERT`).
    pub supports_alert: bool,
    /// The device can restart its hardware on request (`CAP_REBOOT`).
    pub supports_reboot: bool,
    /// `PROP_ALERT`: what the device is doing to make itself findable, when
    /// it has said. Live state like `battery`, and absent on the same terms.
    pub alert: Option<UlcpAlertState>,
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
    /// `PROP_DEV_ADMINS`: the node public keys allowed to manage this device
    /// over the mesh, read back losslessly. Present when `supports_admin`
    /// and the device reported the list; an empty list is a device that
    /// nobody may manage remotely.
    pub dev_admin_keys: Option<Vec<Vec<u8>>>,
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
    /// Where the device says it is. Present when `supports_ident` and the
    /// device reported its position; a device that advertises none reports
    /// an empty cell rather than nothing.
    pub ident_position: Option<UlcpIdentPositionRecord>,
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
    /// The advertisement policy. Present when `supports_advert` and the
    /// device reported the whole of it.
    pub advert: Option<UlcpAdvertSettingsRecord>,
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
    /// The advertisement policy. Present exactly when the device
    /// advertises `CAP_ADVERT`.
    pub advert: Option<UlcpAdvertSettingsRecord>,
}

/// Present one folded [`GnssSnapshot`] as the record Swift sees.
fn gnss_record(snapshot: &GnssSnapshot) -> UlcpGnssRecord {
    let bytes = snapshot.location();
    let placed = (!bytes.is_empty()).then(|| NodeLocation::from_bytes(bytes).center());
    UlcpGnssRecord {
        fix: UlcpFixKind::from_wire(snapshot.fix),
        location: bytes.to_vec(),
        latitude_deg: placed.map(|(latitude, _)| latitude.into()),
        longitude_deg: placed.map(|(_, longitude)| longitude.into()),
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

/// One property value the device announced on its own — `CMD_PROP_IS`
/// with the unsolicited transaction — as opposed to the answer to
/// anything this session asked.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpPropertyPushRecord {
    pub property_id: u32,
    pub value: Vec<u8>,
}

/// The completion of one local management operation started with
/// [`MobileUlcpSession::begin_property_fetch`],
/// [`begin_property_writes`](MobileUlcpSession::begin_property_writes), or
/// [`begin_save`](MobileUlcpSession::begin_save).
///
/// Answers wear the same record the mesh management path reports, and mean
/// the same things: a value is what the device holds, a status in its
/// place is a refusal of that one property. What differs is the carrier —
/// here the completion rides the session update instead of a mesh event.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpLocalManagementEventRecord {
    pub answers: Vec<MobileMeshManagementAnswerRecord>,
    /// The `CMD_SAVE` outcome, on a save. `None` on fetches, on writes,
    /// and on a save the device has no `CAP_SAVE` to answer.
    pub status_code: Option<u32>,
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
    /// Completion of the local management operation, when this update
    /// carries one.
    pub management_event: Option<UlcpLocalManagementEventRecord>,
    /// Values the device announced unsolicited with this update, verbatim.
    /// The snapshot has already absorbed what it recognizes; these carry
    /// the raw octets to whoever caches values by property number.
    pub pushed_properties: Vec<UlcpPropertyPushRecord>,
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
    /// A `CMD_PROP_INSERT` of this key into a device-domain public-key
    /// table: `PROP_DEV_PEERS` or `PROP_DEV_ADMINS`. The two are the same
    /// operation on different lists — a table of 32-byte keys the device
    /// echoes back item by item — so they are confirmed the same way.
    DevKeyInsert {
        property: u32,
        item: Vec<u8>,
    },
    /// A `CMD_PROP_REMOVE` of this key from a device-domain public-key table.
    DevKeyRemove {
        property: u32,
        item: Vec<u8>,
    },
    /// The `CMD_SAVE` chained behind a device-domain key-table mutation.
    SaveDevKeys {
        property: u32,
    },
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
    /// A `CMD_PROP_GET` issued by a local management fetch. Unlike
    /// `Property`, a refusal is an answer to record, never a stage
    /// failure: the caller asked an open question about one property.
    ManagementGet(u32),
    /// A `CMD_PROP_SET` issued by a local management write, answered by
    /// the device's echo or a per-property refusal.
    ManagementSet(u32),
    /// The `CMD_SAVE` issued by a local management save.
    ManagementSave,
}

impl ExpectedResponse {
    /// Whether this response belongs to the local management operation,
    /// which is what decides when that operation continues or completes.
    fn is_management(&self) -> bool {
        matches!(
            self,
            Self::ManagementGet(_) | Self::ManagementSet(_) | Self::ManagementSave
        )
    }
}

/// One local management operation in flight: what is still to ask, what
/// is still to write, and what the device has answered so far.
///
/// The local counterpart of a mesh management exchange, kept to the same
/// shape deliberately — one operation at a time, answers accumulated
/// until everything is answered, refusals recorded per property rather
/// than failing the run.
#[derive(Debug, Default)]
struct LocalManagement {
    fetch_queue: VecDeque<u32>,
    write_queue: VecDeque<(u32, Vec<u8>)>,
    answers: Vec<MobileMeshManagementAnswerRecord>,
    save_status: Option<u32>,
}

struct UlcpSessionState {
    generation: u64,
    /// Which relationship this session represents. Held here, not only on
    /// the object, because ownership resolution is what it changes: an
    /// administrative session reports foreign ownership truthfully but
    /// never waits for a host decision it will not make.
    mode: UlcpAttachMode,
    /// Whether post-attach inspection reads only what attaching itself
    /// requires, leaving everything else to be asked for on demand.
    lazy_inspection: bool,
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
    /// The local management operation in flight, if any.
    management: Option<LocalManagement>,
    /// A completed management operation not yet reported. Taken by the
    /// next update, like a battery reading.
    management_event: Option<UlcpLocalManagementEventRecord>,
    /// Values announced unsolicited and not yet reported, verbatim.
    pushed_properties: Vec<UlcpPropertyPushRecord>,
}

impl Default for UlcpSessionState {
    fn default() -> Self {
        Self {
            generation: 0,
            mode: UlcpAttachMode::Tethered,
            lazy_inspection: false,
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
            management: None,
            management_event: None,
            pushed_properties: Vec::new(),
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
    lazy_inspection: bool,
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

    /// An administrative session that attaches without reading the device
    /// whole.
    ///
    /// Post-attach inspection is cut to what attaching itself requires —
    /// the interface check and the always-present radio basics — so the
    /// link is usable in a couple of exchanges instead of tens. Everything
    /// else is read on demand through
    /// [`Self::begin_property_fetch`], which is the point: a settings
    /// screen that reads lazily has no use for an attach that reads
    /// everything first.
    ///
    /// The provisioning snapshot such a session reports lists every
    /// unread capability-gated property as unreadable, so the
    /// whole-record configure calls — which withdraw writes to unreadable
    /// properties — are not meaningful here. A lazy session writes
    /// through [`Self::begin_property_writes`].
    #[uniffi::constructor]
    pub fn administrative_lazy() -> Arc<Self> {
        let mut session = Self::with_mode(UlcpAttachMode::Administrative);
        session.lazy_inspection = true;
        Arc::new(session)
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
            lazy_inspection: self.lazy_inspection,
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

    /// Restart the radio (`CMD_REBOOT`), keeping everything it has
    /// persisted. Fire-and-forget for the same reason
    /// [`Self::factory_reset`] is: a radio that restarts answers nothing
    /// and the reboot drops the link. A radio without `CAP_REBOOT`
    /// answers `STATUS_UNIMPLEMENTED` instead, which arrives as an
    /// ordinary unsolicited status.
    ///
    /// Permitted from any stage, again like the factory reset: a radio
    /// worth restarting is often one that is not answering properly.
    pub fn reboot(&self) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        let tid = state.allocate_tid();
        let frame = ulcp_reboot(tid)?;
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
        let value = encode_alert_state(state)?;
        let tid = session.allocate_tid();
        session
            .expected
            .insert(tid, ExpectedResponse::Property(prop::ALERT));
        let frame = ulcp_prop_set(tid, prop::ALERT, value)?;
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
        validate_radio_settings(&settings, DeviceCapabilities::read(&state)?)?;

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
        let capabilities = DeviceCapabilities::read(&state)?;
        validate_radio_settings(&configuration.radio, capabilities)?;
        let device_values = validate_device_settings(&configuration, capabilities)?;

        state.expected.clear();
        state.configuration_queue =
            state.writable(configuration_values(configuration.radio, device_values));
        let mut outbound = Vec::new();
        state.start_configuration(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Apply and persist the time zone and the positioning policy, and
    /// nothing else.
    ///
    /// [`Self::configure_device`] can write these too, as part of a whole
    /// device domain — that is what commissioning does. This exists for
    /// the case commissioning does not cover: a phone changing the
    /// positioning settings of the radio it is *tethered* to, which has
    /// no reason to restate that radio's role, discoverability, or
    /// forwarding policy in order to switch a receiver on.
    ///
    /// Each argument must be present exactly when the device advertises
    /// the matching capability, and the four positioning properties
    /// travel together for the reason [`UlcpGnssSettingsRecord`] gives.
    /// The write is echo-verified property by property and closed with a
    /// save, like any other configuration pass.
    pub fn configure_positioning(
        &self,
        gnss: Option<UlcpGnssSettingsRecord>,
        tz_offset_min: Option<i16>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let values = positioning_values(gnss, tz_offset_min, DeviceCapabilities::read(&state)?)?;
        // A radio with neither capability has nothing here to configure,
        // which is a caller mistake rather than an empty success.
        if values.is_empty() {
            return Err(MobileError::UnsupportedCapability);
        }

        state.expected.clear();
        state.configuration_queue = state.writable(values);
        let mut outbound = Vec::new();
        state.start_configuration(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Apply and persist the advertisement policy, and nothing else.
    ///
    /// The tethered-radio counterpart of [`Self::configure_positioning`]:
    /// a phone changing how often its own radio announces itself has no
    /// reason to restate that radio's role, forwarding policy, or
    /// receiver settings to do it.
    pub fn configure_advertising(
        &self,
        advert: Option<UlcpAdvertSettingsRecord>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        if state.stage != SessionStage::Attached {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let values = advert_values(advert, DeviceCapabilities::read(&state)?)?;
        // A radio that announces nothing on its own has nothing here to
        // configure, which is a caller mistake rather than a no-op.
        if values.is_empty() {
            return Err(MobileError::UnsupportedCapability);
        }

        state.expected.clear();
        state.configuration_queue = state.writable(values);
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

    /// Sample where the device is, and how well it knows.
    ///
    /// The device announces a fix indicator and nothing else about a
    /// position — a receiver reports about a fix a second and ordinary
    /// noise moves the reading, so announcing any of this would keep the
    /// radio transmitting for a host that may not be looking. A host that
    /// *is* looking asks, at whatever rate it can use the answer.
    ///
    /// Deliberately narrower than [`refresh`](Self::refresh): the five
    /// positioning properties and nothing else, so a screen watching a
    /// position does not re-read the PHY triple every time it looks.
    pub fn refresh_positioning(&self) -> Result<UlcpSessionUpdateRecord, MobileError> {
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
        // A device without the capability has nothing to sample, and
        // asking anyway would earn a refusal per property.
        if !decode_capabilities(&capabilities)?.contains(&cap::GNSS) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        state.inspection_queue = VecDeque::from(vec![
            prop::GNSS_LOCATION,
            prop::GNSS_ALTITUDE,
            prop::GNSS_FIX,
            prop::GNSS_PRECISION,
            prop::GNSS_SATELLITES,
        ]);
        let mut outbound = Vec::new();
        state.start_refresh(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Read the named properties, whatever they are, and answer with what
    /// the device said about each.
    ///
    /// The local counterpart of a mesh management fetch, and it reports
    /// the same way: one answer per property, a refusal recorded as that
    /// property's status rather than failing the run. The completion
    /// arrives as [`UlcpSessionUpdateRecord::management_event`] once every
    /// answer is in. One operation may run at a time.
    ///
    /// Values read fold into the session's own snapshot as well, so a
    /// settings screen reading a property does not leave the attached
    /// provisioning stale.
    pub fn begin_property_fetch(
        &self,
        property_ids: Vec<u32>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_local_management()?;
        state.management = Some(LocalManagement {
            fetch_queue: property_ids.into(),
            ..LocalManagement::default()
        });
        let mut outbound = Vec::new();
        state.continue_local_management(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Write the given properties, in the given order, and answer with
    /// what the device says each is now worth.
    ///
    /// The order is the caller's to state and is preserved — a dirty-write
    /// plan brackets the radio with `PROP_PHY_ENABLED`, and reordering it
    /// would ask the device to retune mid-transmission. Writes go out one
    /// at a time for the same reason. A refusal is recorded as that
    /// property's answer and the run continues, matching the mesh path.
    ///
    /// Nothing is saved: persistence is a separate, explicit
    /// [`Self::begin_save`], again matching the mesh path.
    pub fn begin_property_writes(
        &self,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_local_management()?;
        state.management = Some(LocalManagement {
            write_queue: writes
                .into_iter()
                .map(|write| (write.property_id, write.value))
                .collect(),
            ..LocalManagement::default()
        });
        let mut outbound = Vec::new();
        state.continue_local_management(&mut outbound)?;
        Ok(state.update(outbound))
    }

    /// Persist whatever the device is holding, reporting the `CMD_SAVE`
    /// status on the completion event.
    ///
    /// On a device without `CAP_SAVE` there is nothing to ask, and the
    /// operation completes immediately with no status — running
    /// configuration is all such a device has.
    pub fn begin_save(&self) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_local_management()?;
        if !state.has_capability(cap::SAVE)? {
            state.management_event = Some(UlcpLocalManagementEventRecord {
                answers: Vec::new(),
                status_code: None,
            });
            return Ok(state.update(Vec::new()));
        }
        state.management = Some(LocalManagement::default());
        let tid = state.allocate_tid();
        state.expected.insert(tid, ExpectedResponse::ManagementSave);
        let frame = ulcp_save(tid)?;
        Ok(state.update(vec![frame]))
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
        state.begin_device_domain_operation(cap::DEV_IDENTITY)?;
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
        state.begin_device_domain_operation(cap::DEV_IDENTITY)?;
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
        self.insert_device_key(cap::DEV_IDENTITY, prop::DEV_PEERS, public_key)
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
        self.remove_device_key(cap::DEV_IDENTITY, prop::DEV_PEERS, public_key)
    }

    /// Store one administrator public key on the radio's device identity
    /// (`PROP_DEV_ADMINS`), then persist with a chained `CMD_SAVE` when the
    /// device can.
    ///
    /// This is the bench half of node management: a key listed here may
    /// manage this radio over the mesh, so the phone puts its own node key
    /// on a radio it is attached to and manages it later from across the
    /// valley. The list is what authorizes an administrator — no pairwise
    /// provisioning follows, because the session is derived from the two
    /// identities.
    ///
    /// Requires an attached, otherwise-idle session on a device advertising
    /// `CAP_ADMIN`. Failures surface as `operation_error` with the device's
    /// status name — `NOMEM` when the list is full (capacity
    /// [`ulcp_max_dev_admins`]), `ALREADY` when the key is already listed,
    /// which callers should treat as success.
    pub fn insert_device_admin(
        &self,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        self.insert_device_key(cap::ADMIN, prop::DEV_ADMINS, public_key)
    }

    /// Remove one administrator public key from the radio's device identity
    /// (`PROP_DEV_ADMINS`), then persist with a chained `CMD_SAVE` when the
    /// device can.
    ///
    /// Same preconditions as [`Self::insert_device_admin`]. Emptying the
    /// list is how a device stops being manageable over the mesh at all.
    /// `ITEM_NOT_FOUND` surfaces as `operation_error` and callers should
    /// treat it as success — the key is not listed either way.
    pub fn remove_device_admin(
        &self,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        self.remove_device_key(cap::ADMIN, prop::DEV_ADMINS, public_key)
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
        let parsed = Frame::parse(&frame).map_err(|_| MobileError::UlcpFrameUnparsable)?;
        if parsed.command() == Some(Cmd::StrRecv) {
            if parsed.header.tid() != frame::TID_UNSOLICITED {
                return Err(MobileError::UlcpUnexpectedFrame);
            }
            let payload = StreamPayload::parse(parsed.payload)
                .map_err(|_| MobileError::UlcpMalformedPayload)?;
            if payload.stream != umsh_ulcp::ids::stream::PHY_RAW {
                return Err(MobileError::UlcpUnexpectedFrame);
            }
            let metadata = BufferedRxMeta::decode(payload.metadata)
                .map_err(|_| MobileError::UlcpMalformedPayload)?;
            let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
            if state.stage == SessionStage::Idle {
                return Err(MobileError::UlcpUnexpectedFrame);
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
                // Carried out verbatim as well as folded into the
                // snapshot, so a consumer caching values by property
                // number hears about it without knowing the property.
                state.pushed_properties.push(UlcpPropertyPushRecord {
                    property_id: response.property_id,
                    value: response.value.clone(),
                });
            }
            state.apply_property(&response)?;
            state.refresh_attached_snapshot(Some(response.property_id))?;
            return Ok(state.update(outbound));
        }

        let expected = state
            .expected
            .remove(&response.transaction_id)
            .ok_or(MobileError::UlcpUnexpectedFrame)?;
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
                        return Err(MobileError::UlcpMismatchedResponse);
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
                        return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
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
                        return Err(MobileError::UlcpMismatchedResponse);
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
                        return Err(MobileError::UlcpMismatchedResponse);
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
                    return Err(MobileError::UlcpMismatchedResponse);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    operation_error = Some(ulcp_operation_error(
                        "save device channel keys".to_owned(),
                        response.value.as_slice(),
                    )?);
                }
            }
            ExpectedResponse::DevKeyInsert { property, item } => {
                let table = dev_key_table_name(property);
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        format!("insert device {table}"),
                        response.value.as_slice(),
                    )?;
                    // ALREADY is the device saying the key is stored; keep
                    // the cache truthful even though the operation "failed".
                    if error.status_code == umsh_ulcp::Status::ALREADY.0 {
                        state.patch_dev_keys(property, &item, true);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != property
                        || response.command != Cmd::PropInserted as u8
                        || response.value != item
                    {
                        return Err(MobileError::UlcpMismatchedResponse);
                    }
                    state.patch_dev_keys(property, &item, true);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state
                            .expected
                            .insert(tid, ExpectedResponse::SaveDevKeys { property });
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::DevKeyRemove { property, item } => {
                let table = dev_key_table_name(property);
                if response.property_id == prop::LAST_STATUS {
                    let error = ulcp_operation_error(
                        format!("remove device {table}"),
                        response.value.as_slice(),
                    )?;
                    // ITEM_NOT_FOUND means the key is not on the device,
                    // which is the state the caller asked for.
                    if error.status_code == umsh_ulcp::Status::ITEM_NOT_FOUND.0 {
                        state.patch_dev_keys(property, &item, false);
                        state.refresh_attached_snapshot(None)?;
                    }
                    operation_error = Some(error);
                } else {
                    if response.property_id != property
                        || response.command != Cmd::PropRemoved as u8
                        || response.value != item
                    {
                        return Err(MobileError::UlcpMismatchedResponse);
                    }
                    state.patch_dev_keys(property, &item, false);
                    if state.has_capability(cap::SAVE)? {
                        let tid = state.allocate_tid();
                        state
                            .expected
                            .insert(tid, ExpectedResponse::SaveDevKeys { property });
                        outbound.push(ulcp_save(tid)?);
                    }
                    state.refresh_attached_snapshot(None)?;
                }
            }
            ExpectedResponse::SaveDevKeys { property } => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::UlcpMismatchedResponse);
                }
                if inspect_ulcp_status(response.value.clone())? != 0 {
                    // The live mutation stuck; only persistence failed. The
                    // session stays attached and the caller sees the same
                    // `saved` warning path a failed configuration save uses.
                    let table = dev_key_table_name(property);
                    operation_error = Some(ulcp_operation_error(
                        format!("save device {table}s"),
                        response.value.as_slice(),
                    )?);
                }
            }
            ExpectedResponse::ManagementGet(property) => {
                if response.property_id == prop::LAST_STATUS && property != prop::LAST_STATUS {
                    // A refusal is the device's whole answer about this
                    // property. Drop any stale cached value so the session
                    // snapshot agrees with what was just reported.
                    let status_code = inspect_ulcp_status(response.value.clone())?;
                    state.responses.remove(&property);
                    state.record_management_answer(MobileMeshManagementAnswerRecord {
                        property_id: property,
                        value: None,
                        status_code: Some(status_code),
                    });
                } else if response.property_id != property || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::UlcpMismatchedResponse);
                } else {
                    state.responses.insert(property, response.clone());
                    state.apply_property(&response)?;
                    state.record_management_answer(MobileMeshManagementAnswerRecord {
                        property_id: property,
                        value: Some(response.value.clone()),
                        status_code: None,
                    });
                }
                state.continue_local_management(&mut outbound)?;
            }
            ExpectedResponse::ManagementSet(property) => {
                if response.property_id == prop::LAST_STATUS && property != prop::LAST_STATUS {
                    // A refused write leaves the device holding whatever it
                    // held. The answer records the refusal and the run
                    // continues — the caller decides per property, like the
                    // mesh path.
                    let status_code = inspect_ulcp_status(response.value.clone())?;
                    state.record_management_answer(MobileMeshManagementAnswerRecord {
                        property_id: property,
                        value: None,
                        status_code: Some(status_code),
                    });
                } else if response.property_id != property || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::UlcpMismatchedResponse);
                } else {
                    // The echo is the device's authoritative value, whatever
                    // was written — see the ConfigurationProperty arm.
                    state.responses.insert(property, response.clone());
                    state.apply_property(&response)?;
                    state.record_management_answer(MobileMeshManagementAnswerRecord {
                        property_id: property,
                        value: Some(response.value.clone()),
                        status_code: None,
                    });
                }
                state.continue_local_management(&mut outbound)?;
            }
            ExpectedResponse::ManagementSave => {
                if response.property_id != prop::LAST_STATUS
                    || response.command != Cmd::PropIs as u8
                {
                    return Err(MobileError::UlcpMismatchedResponse);
                }
                let status_code = inspect_ulcp_status(response.value.clone())?;
                if let Some(op) = state.management.as_mut() {
                    op.save_status = Some(status_code);
                }
                state.continue_local_management(&mut outbound)?;
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
            lazy_inspection: self.lazy_inspection,
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
            lazy_inspection: false,
        }
    }

    /// Add one key to a device-domain public-key table.
    fn insert_device_key(
        &self,
        capability: u32,
        property: u32,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_device_domain_operation(capability)?;
        let tid = state.allocate_tid();
        state.expected.insert(
            tid,
            ExpectedResponse::DevKeyInsert {
                property,
                item: public_key.to_vec(),
            },
        );
        let frame = ulcp_prop_insert(tid, property, &public_key)?;
        Ok(state.update(vec![frame]))
    }

    /// Take one key out of a device-domain public-key table.
    fn remove_device_key(
        &self,
        capability: u32,
        property: u32,
        public_key: Vec<u8>,
    ) -> Result<UlcpSessionUpdateRecord, MobileError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| MobileError::InvalidPublicKeyLength)?;
        let mut state = self.inner.lock().expect("ULCP session mutex poisoned");
        state.begin_device_domain_operation(capability)?;
        let tid = state.allocate_tid();
        state.expected.insert(
            tid,
            ExpectedResponse::DevKeyRemove {
                property,
                item: public_key.to_vec(),
            },
        );
        let frame = ulcp_prop_remove(tid, property, &public_key)?;
        Ok(state.update(vec![frame]))
    }
}

/// What a device-domain key table holds, for the operation names an error
/// carries.
fn dev_key_table_name(property: u32) -> &'static str {
    match property {
        prop::DEV_ADMINS => "administrator",
        _ => "peer",
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
            // Taken, like the battery: a completion is reported on the
            // one update that carries it.
            management_event: self.management_event.take(),
            pushed_properties: std::mem::take(&mut self.pushed_properties),
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
                // Read or announced, indifferently: a device is meant to
                // announce only the fix indicator and leave a position to
                // be sampled, but one that volunteers a position anyway is
                // carrying the value a read would have returned, so this
                // takes it. Folding rather than replacing is what lets a
                // single property arrive without erasing the others.
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

    /// Gate a device-domain mutation: attached, no other operation in
    /// flight, and the device advertising whatever capability puts the
    /// table being written within reach.
    fn begin_device_domain_operation(&mut self, capability: u32) -> Result<(), MobileError> {
        if self.stage != SessionStage::Attached || !self.expected.is_empty() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        if !self.has_capability(capability)? {
            return Err(MobileError::InvalidUlcpFrame);
        }
        Ok(())
    }

    /// Gate a local management operation: attached, nothing else in
    /// flight. One operation at a time is the same discipline the mesh
    /// path enforces, and what lets a completion be attributed to the one
    /// operation that could have produced it.
    ///
    /// Raw PHY transmissions are not "something else": a tethered radio
    /// carries mesh traffic continuously, each exchange is matched by its
    /// own transaction, and a settings screen that could only work on a
    /// quiet mesh would rarely work at all.
    fn begin_local_management(&mut self) -> Result<(), MobileError> {
        if self.stage != SessionStage::Attached || self.management.is_some() {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let busy = self
            .expected
            .values()
            .any(|expected| !matches!(expected, ExpectedResponse::RawTransmit));
        if busy {
            return Err(MobileError::InvalidUlcpFrame);
        }
        Ok(())
    }

    /// A transaction identifier no outstanding exchange is using.
    ///
    /// The allocator cycles blindly, which is safe for the staged bulk
    /// reads — they only run with nothing outstanding — but a management
    /// round can coexist with a live one-off like an alert write, and
    /// must not reuse its identifier.
    fn allocate_management_tid(&mut self) -> Result<u8, MobileError> {
        for _ in 0..usize::from(frame::TID_MAX) {
            let tid = self.tids.allocate();
            if !self.expected.contains_key(&tid) {
                return Ok(tid);
            }
        }
        Err(MobileError::InvalidUlcpFrame)
    }

    /// Record one answer for the local management operation in flight.
    fn record_management_answer(&mut self, answer: MobileMeshManagementAnswerRecord) {
        if let Some(op) = self.management.as_mut() {
            op.answers.push(answer);
        }
    }

    /// Issue the next round of the local management operation, or complete
    /// it. Called at the start of the operation and each time one of its
    /// answers arrives; does nothing while any of them remain outstanding.
    fn continue_local_management(
        &mut self,
        outbound: &mut Vec<Vec<u8>>,
    ) -> Result<(), MobileError> {
        if self.expected.values().any(ExpectedResponse::is_management) {
            return Ok(());
        }
        let Some(mut op) = self.management.take() else {
            return Ok(());
        };
        if let Some((property, value)) = op.write_queue.pop_front() {
            // One write at a time: the plan's order is load-bearing (the
            // PHY bracket), and a device applies what it is asked in the
            // order asked only if it is asked in that order.
            let tid = self.allocate_management_tid()?;
            self.expected
                .insert(tid, ExpectedResponse::ManagementSet(property));
            outbound.push(ulcp_prop_set(tid, property, value)?);
            self.management = Some(op);
        } else if !op.fetch_queue.is_empty() {
            let budget = usize::from(frame::TID_MAX).saturating_sub(self.expected.len());
            for _ in 0..budget {
                let Some(property) = op.fetch_queue.pop_front() else {
                    break;
                };
                let tid = self.allocate_management_tid()?;
                self.expected
                    .insert(tid, ExpectedResponse::ManagementGet(property));
                outbound.push(ulcp_prop_get(tid, property)?);
            }
            self.management = Some(op);
        } else {
            self.management_event = Some(UlcpLocalManagementEventRecord {
                answers: op.answers,
                status_code: op.save_status,
            });
            self.refresh_attached_snapshot(None)?;
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

    /// Patch a cached device-domain public-key table after a confirmed
    /// mutation, keeping it lossless without a round-trip re-read.
    fn patch_dev_keys(&mut self, property: u32, key: &[u8], present: bool) {
        let entry = self
            .responses
            .entry(property)
            .or_insert_with(|| UlcpPropertyFrameRecord {
                transaction_id: frame::TID_UNSOLICITED,
                command: Cmd::PropIs as u8,
                property_id: property,
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

    fn writable(&self, values: Vec<(u32, Vec<u8>)>) -> VecDeque<(u32, Vec<u8>)> {
        let unreadable = self
            .provisioning
            .as_ref()
            .map(|sync| sync.unreadable_properties.as_slice())
            .unwrap_or_default();
        writable(values, unreadable).into()
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
                self.inspection_queue = if self.lazy_inspection {
                    // Only what the sync reduction insists on: the
                    // interface check and the radio basics every device
                    // has. The rest is read on demand, which is the whole
                    // point of a lazy session.
                    VecDeque::from(vec![
                        prop::INTERFACE_TYPE,
                        prop::PHY_ENABLED,
                        prop::PHY_FREQ,
                        prop::PHY_TX_POWER,
                    ])
                } else {
                    ulcp_inspection_properties(capabilities.value.clone())?.into()
                };
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
        properties.extend([
            prop::IDENT_ROLE,
            prop::IDENT_MOBILE,
            // Where the device says it is. Read at attach because it is
            // the position a region proposal starts from, and a phone at
            // a bench cannot ask for it separately: the local link's
            // snapshot is the whole of what a setup sheet knows.
            prop::IDENT_LOCATION,
            prop::IDENT_ALTITUDE,
        ]);
    }
    if has(cap::DEV_IDENTITY) {
        properties.extend([
            prop::DEV_PEERS,
            prop::DEV_CHANNEL_KEYS,
            prop::DEV_DISCOVERABLE,
        ]);
    }
    if has(cap::ADMIN) {
        properties.push(prop::DEV_ADMINS);
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
    if has(cap::ADVERT) {
        properties.extend([
            prop::ADVERT_INTERVAL,
            prop::BEACON_INTERVAL,
            prop::STARTUP_BEACON,
        ]);
    }
    Ok(properties)
}

pub(crate) fn ulcp_refresh_properties(capabilities: Vec<u8>) -> Result<Vec<u32>, MobileError> {
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
    let manageable = has(cap::ADMIN);
    let dev_admin_keys = expected.read(
        manageable,
        prop::DEV_ADMINS,
        decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>,
    );
    // Read here as well as onto the session snapshot, because a phone
    // reading a device across the mesh has no session with it and this
    // record is the whole of what it learned.
    let device_name = expected
        .read(has(cap::DEV_NAME), prop::DEV_NAME, decode_device_name)
        .flatten();

    // Readings, not settings, so they go around `expected`: a device that
    // has not reported its battery yet has not withheld a setting, and
    // saying it had would put "its battery" in a notice about configuration
    // this phone is about to write over. On the local link neither is even
    // asked for at attach — the battery arrives unsolicited — while a
    // reading across the mesh asks for both and gets an answer or none.
    let battery = reported_value(&responses, has(cap::BATTERY), prop::BATTERY, |value| {
        inspect_ulcp_battery(value.to_vec())
    });
    let alert = reported_value(&responses, has(cap::ALERT), prop::ALERT, |value| {
        inspect_ulcp_alert(value.to_vec())
    });

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
    // Read as a pair, like the policies above: the cell and the height
    // are one statement of where the device is, and a device keeping its
    // own position refuses both together.
    let ident_location = expected.read(ident, prop::IDENT_LOCATION, |value| {
        Ok::<Vec<u8>, MobileError>(value.to_vec())
    });
    let ident_altitude = expected.read(ident, prop::IDENT_ALTITUDE, decode_optional_altitude);
    let ident_position = (|| {
        let location = ident_location?;
        let placed = (!location.is_empty()).then(|| NodeLocation::from_bytes(&location).center());
        Some(UlcpIdentPositionRecord {
            latitude_deg: placed.map(|(latitude, _)| latitude.into()),
            longitude_deg: placed.map(|(_, longitude)| longitude.into()),
            cell_meters: (!location.is_empty())
                .then(|| ulcp_location_cell_meters(location.len() as u8))
                .flatten(),
            altitude_m: ident_altitude?,
            location,
        })
    })();
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

    // Also read whole: the two schedules together are how much airtime
    // this device claims, which is one decision.
    let announces = has(cap::ADVERT);
    let advert_interval = expected.read(announces, prop::ADVERT_INTERVAL, decode_u32);
    let beacon_interval = expected.read(announces, prop::BEACON_INTERVAL, decode_u32);
    let startup_beacon = expected.read(announces, prop::STARTUP_BEACON, decode_bool);
    let advert = (|| {
        Some(UlcpAdvertSettingsRecord {
            advert_interval_seconds: advert_interval?,
            beacon_interval_seconds: beacon_interval?,
            startup_beacon: startup_beacon?,
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
        device_name,
        supports_lora: has(cap::PHY_LORA),
        supports_duty_cycle_limit: has(cap::PHY_DUTY_LIMIT),
        supports_battery: has(cap::BATTERY),
        battery,
        supports_repeater: has(cap::REPEATER),
        supports_ident: has(cap::IDENT),
        supports_device_identity: has(cap::DEV_IDENTITY),
        supports_time: has(cap::TIME),
        supports_gnss: positioning,
        supports_advert: announces,
        supports_admin: manageable,
        supports_alert: has(cap::ALERT),
        supports_reboot: has(cap::REBOOT),
        alert,
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
        dev_admin_keys,
        dev_channel_ids,
        ident_role,
        ident_mobile,
        ident_position,
        dev_discoverable,
        tz_offset_min,
        gnss,
        advert,
        unreadable_properties,
    })
}

// ─── Managing one device, a screen at a time ─────────────────────────────

/// One screenful of a device's settings.
///
/// Reading a device whole costs tens of properties and several round
/// trips, which over a link a few hops deep is the difference between a
/// screen that opens and one that is waited on. A category is what one
/// screen shows, and asking for exactly that is normally one exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UlcpManageCategory {
    /// What the battery reports. Read-only.
    Power,
    /// The radio: frequency, power, the modem profile, the duty ledger.
    Radio,
    /// What the device advertises about itself, including where it is.
    Identity,
    /// The receiver, and what it currently sees. The fix is read-only.
    Gnss,
    /// The wall clock: what time the device holds, where it is meant to
    /// be, and whether the receiver may set the clock.
    Time,
    /// The forwarding policy.
    Repeater,
    /// Who this device talks to, and who may manage it.
    PeerNodes,
}

/// The property numbers the management screens name.
///
/// A screen has to say which fields the operator edited, and it caches
/// values under the number the device answered for, so the numbers cross
/// the boundary whether or not anyone likes it. Handing them over once,
/// from the same constants everything else here is built on, is what
/// keeps a second copy from being written down somewhere in Swift.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpManagedPropertyIds {
    pub caps: u32,
    pub device_version: u32,
    pub device_model: u32,
    pub device_name: u32,
    pub battery: u32,
    pub phy_enabled: u32,
    pub frequency: u32,
    pub transmit_power: u32,
    pub lora_bandwidth: u32,
    pub lora_spreading_factor: u32,
    pub lora_coding_rate: u32,
    pub duty_cycle_now: u32,
    pub duty_cycle_limit: u32,
    pub ident_role: u32,
    pub ident_mobile: u32,
    pub ident_location: u32,
    pub ident_altitude: u32,
    pub dev_discoverable: u32,
    pub gnss_ident_update: u32,
    pub gnss_ident_precision: u32,
    pub uptime: u32,
    pub advert_interval: u32,
    pub beacon_interval: u32,
    pub startup_beacon: u32,
    pub gnss_enabled: u32,
    pub gnss_time_trust: u32,
    pub time: u32,
    pub tz_offset: u32,
    pub alert: u32,
    pub repeater_enabled: u32,
    pub repeater_regions: u32,
    pub repeater_default_region: u32,
    pub repeater_min_rssi: u32,
    pub repeater_min_snr: u32,
    pub dev_peers: u32,
    pub dev_admins: u32,
}

/// The property numbers, from the constants themselves.
#[uniffi::export]
pub fn ulcp_managed_property_ids() -> UlcpManagedPropertyIds {
    UlcpManagedPropertyIds {
        caps: prop::CAPS,
        device_version: prop::DEV_VERSION,
        device_model: prop::DEV_MODEL,
        device_name: prop::DEV_NAME,
        battery: prop::BATTERY,
        phy_enabled: prop::PHY_ENABLED,
        frequency: prop::PHY_FREQ,
        transmit_power: prop::PHY_TX_POWER,
        lora_bandwidth: prop::PHY_LORA_BW,
        lora_spreading_factor: prop::PHY_LORA_SF,
        lora_coding_rate: prop::PHY_LORA_CR,
        duty_cycle_now: prop::PHY_DUTY_NOW,
        duty_cycle_limit: prop::PHY_DUTY_LIMIT,
        ident_role: prop::IDENT_ROLE,
        ident_mobile: prop::IDENT_MOBILE,
        ident_location: prop::IDENT_LOCATION,
        ident_altitude: prop::IDENT_ALTITUDE,
        dev_discoverable: prop::DEV_DISCOVERABLE,
        gnss_ident_update: prop::GNSS_IDENT_UPDATE,
        gnss_ident_precision: prop::GNSS_IDENT_PRECISION,
        uptime: prop::UPTIME,
        advert_interval: prop::ADVERT_INTERVAL,
        beacon_interval: prop::BEACON_INTERVAL,
        startup_beacon: prop::STARTUP_BEACON,
        gnss_enabled: prop::GNSS_ENABLED,
        gnss_time_trust: prop::GNSS_TIME_TRUST,
        time: prop::TIME,
        tz_offset: prop::TZ_OFFSET,
        alert: prop::ALERT,
        repeater_enabled: prop::MAC_REPEATER_ENABLED,
        repeater_regions: prop::MAC_REPEATER_REGIONS,
        repeater_default_region: prop::MAC_REPEATER_DEFAULT_REGION,
        repeater_min_rssi: prop::MAC_REPEATER_MIN_RSSI,
        repeater_min_snr: prop::MAC_REPEATER_MIN_SNR,
        dev_peers: prop::DEV_PEERS,
        dev_admins: prop::DEV_ADMINS,
    }
}

/// The four properties a device is identified by, asked for together.
///
/// Capabilities first, so a device that declines the batch teaches the
/// crawl to ask one at a time before the rest.
#[uniffi::export]
pub fn ulcp_card_properties() -> Vec<u32> {
    vec![
        prop::CAPS,
        prop::DEV_VERSION,
        prop::DEV_MODEL,
        prop::DEV_NAME,
    ]
}

/// What one category asks for, given what the device says it can do.
///
/// Capability-gated so a screen never spends airtime on a property the
/// device does not have, and filtered to what an administrator may
/// reach.
#[uniffi::export]
pub fn ulcp_category_properties(
    category: UlcpManageCategory,
    capabilities: Vec<u8>,
) -> Result<Vec<u32>, MobileError> {
    let capabilities = decode_capabilities(&capabilities)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);
    let mut properties = Vec::new();
    let mut when = |gate: bool, keys: &[u32]| {
        if gate {
            properties.extend_from_slice(keys);
        }
    };

    match category {
        UlcpManageCategory::Power => when(has(cap::BATTERY), &[prop::BATTERY]),
        UlcpManageCategory::Radio => {
            when(
                true,
                &[prop::PHY_ENABLED, prop::PHY_FREQ, prop::PHY_TX_POWER],
            );
            when(
                has(cap::PHY_LORA),
                &[prop::PHY_LORA_BW, prop::PHY_LORA_SF, prop::PHY_LORA_CR],
            );
            when(
                has(cap::PHY_DUTY_LIMIT),
                &[prop::PHY_DUTY_NOW, prop::PHY_DUTY_LIMIT],
            );
        }
        UlcpManageCategory::Identity => {
            when(has(cap::DEV_NAME), &[prop::DEV_NAME]);
            when(
                has(cap::IDENT),
                &[
                    prop::IDENT_ROLE,
                    prop::IDENT_MOBILE,
                    prop::IDENT_LOCATION,
                    prop::IDENT_ALTITUDE,
                ],
            );
            when(has(cap::DEV_IDENTITY), &[prop::DEV_DISCOVERABLE]);
            // Whether the device maintains its own position decides
            // whether the location rows above are editable at all, so
            // this screen has to know even though the receiver has its
            // own.
            when(
                has(cap::GNSS),
                &[prop::GNSS_IDENT_UPDATE, prop::GNSS_IDENT_PRECISION],
            );
            when(
                has(cap::ADVERT),
                &[
                    prop::ADVERT_INTERVAL,
                    prop::BEACON_INTERVAL,
                    prop::STARTUP_BEACON,
                ],
            );
        }
        UlcpManageCategory::Gnss => when(
            has(cap::GNSS),
            &[
                prop::GNSS_ENABLED,
                prop::GNSS_LOCATION,
                prop::GNSS_ALTITUDE,
                prop::GNSS_FIX,
                prop::GNSS_PRECISION,
                prop::GNSS_SATELLITES,
            ],
        ),
        UlcpManageCategory::Time => {
            // Ungated: a device with no wall clock may still know how
            // long it has been up, and a refusal costs one slot.
            when(true, &[prop::UPTIME]);
            when(has(cap::TIME), &[prop::TIME, prop::TZ_OFFSET]);
            // Whether the receiver may set the clock is the clock's
            // business, so it lives here rather than with the receiver.
            when(has(cap::GNSS), &[prop::GNSS_TIME_TRUST]);
        }
        UlcpManageCategory::Repeater => when(
            has(cap::REPEATER),
            &[
                prop::MAC_REPEATER_ENABLED,
                prop::MAC_REPEATER_REGIONS,
                prop::MAC_REPEATER_DEFAULT_REGION,
                prop::MAC_REPEATER_MIN_RSSI,
                prop::MAC_REPEATER_MIN_SNR,
            ],
        ),
        UlcpManageCategory::PeerNodes => {
            when(has(cap::DEV_IDENTITY), &[prop::DEV_PEERS]);
            when(has(cap::ADMIN), &[prop::DEV_ADMINS]);
        }
    }
    properties.retain(|&key| umsh_ulcp::ids::admin_reachable(key));
    Ok(properties)
}

/// What a device is, as opposed to how it is configured.
///
/// The four properties worth learning once and keeping: capabilities and
/// firmware version change only when the firmware does, the model never,
/// and the name rarely. Cached against the version, this is what lets
/// opening a device's settings cost nothing at all.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UlcpDeviceCardRecord {
    /// `PROP_CAPS` verbatim, to plan later reads against without asking
    /// the device again.
    pub capabilities: Vec<u8>,
    /// `PROP_DEV_VERSION`: what firmware it is running. The natural key
    /// for everything cached about it — capabilities cannot change
    /// without this changing too.
    pub device_version: Option<String>,
    /// `PROP_DEV_MODEL`: the hardware, when the device names it.
    pub device_model: Option<String>,
    pub device_name: Option<String>,
    pub supports_device_name: bool,
    pub supports_battery: bool,
    pub supports_lora: bool,
    pub supports_duty_cycle_limit: bool,
    pub supports_repeater: bool,
    pub supports_ident: bool,
    pub supports_device_identity: bool,
    pub supports_gnss: bool,
    pub supports_advert: bool,
    pub supports_admin: bool,
    pub supports_alert: bool,
    /// Whether a Restart control is worth offering (`CAP_REBOOT`).
    pub supports_reboot: bool,
    pub supports_save: bool,
    /// Whether batched property reads are worth trying. A device that
    /// declines one is asked again a property at a time, so this is a
    /// hint rather than a contract.
    pub supports_multi: bool,
}

/// Reduce the answers to a card read into what a device is.
///
/// Capabilities are required — without them there is nothing to plan the
/// rest against. Everything else is absent rather than fatal: a device
/// that will not name its hardware is a device that does not name its
/// hardware.
#[uniffi::export]
pub fn inspect_ulcp_device_card(
    responses: Vec<UlcpPropertyFrameRecord>,
) -> Result<UlcpDeviceCardRecord, MobileError> {
    let raw = property_value(&responses, prop::CAPS)?.to_vec();
    let capabilities = decode_capabilities(&raw)?;
    validate_capability_dependencies(&capabilities)?;
    let has = |capability| capabilities.contains(&capability);
    let text = |key| {
        property_value(&responses, key)
            .and_then(decode_device_name)
            .ok()
            .flatten()
    };

    Ok(UlcpDeviceCardRecord {
        capabilities: raw,
        device_version: text(prop::DEV_VERSION),
        device_model: text(prop::DEV_MODEL),
        device_name: text(prop::DEV_NAME),
        supports_device_name: has(cap::DEV_NAME),
        supports_battery: has(cap::BATTERY),
        supports_lora: has(cap::PHY_LORA),
        supports_duty_cycle_limit: has(cap::PHY_DUTY_LIMIT),
        supports_repeater: has(cap::REPEATER),
        supports_ident: has(cap::IDENT),
        supports_device_identity: has(cap::DEV_IDENTITY),
        supports_gnss: has(cap::GNSS),
        supports_advert: has(cap::ADVERT),
        supports_admin: has(cap::ADMIN),
        supports_alert: has(cap::ALERT),
        supports_reboot: has(cap::REBOOT),
        supports_save: has(cap::SAVE),
        supports_multi: has(cap::CMD_MULTI),
    })
}

/// Everything the six management screens show, all of it optional.
///
/// A category read answers a handful of properties, so anything outside
/// it is simply absent — this record says what the last read of *some*
/// category found, and a screen fills in from it whatever it recognizes.
/// The counterpart to [`UlcpSyncRecord`], which describes a whole device
/// and can insist on the properties every device must answer.
#[derive(Clone, Debug, Default, PartialEq, uniffi::Record)]
pub struct UlcpDevicePropertiesRecord {
    pub battery: Option<UlcpBatteryRecord>,
    pub phy_enabled: Option<bool>,
    pub frequency_khz: Option<u32>,
    pub transmit_power_dbm: Option<i8>,
    pub bandwidth_hz: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate_denom: Option<u8>,
    pub duty_cycle_now: Option<u16>,
    pub duty_cycle_limit: Option<u16>,
    pub device_name: Option<String>,
    /// `None` is the device deriving its own role, which reads the same
    /// as never having been told.
    pub ident_role: Option<u8>,
    pub ident_mobile: Option<bool>,
    /// `PROP_IDENT_LOCATION` verbatim. Empty is a device advertising no
    /// position, which is different from not having been asked.
    pub ident_location: Option<Vec<u8>>,
    pub ident_latitude_deg: Option<f64>,
    pub ident_longitude_deg: Option<f64>,
    /// Width of the advertised cell at the equator, in meters — what the
    /// length of the location actually discloses.
    pub ident_location_cell_meters: Option<f64>,
    pub ident_altitude_m: Option<i32>,
    pub dev_discoverable: Option<bool>,
    /// Whether the device maintains its own advertised position. Set,
    /// the location and altitude above are the device's to write and a
    /// host's write is refused.
    pub gnss_ident_update: Option<bool>,
    pub gnss_ident_precision: Option<u8>,
    /// `PROP_UPTIME`: seconds since the device booted. Absent on a
    /// device that does not report it.
    pub uptime_seconds: Option<u32>,
    pub advert_interval_seconds: Option<u32>,
    pub beacon_interval_seconds: Option<u32>,
    pub startup_beacon: Option<bool>,
    pub gnss_enabled: Option<bool>,
    /// What the receiver currently sees. Read-only, and absent on a
    /// device with no receiver.
    pub gnss: Option<UlcpGnssRecord>,
    pub gnss_time_trust: Option<bool>,
    /// What the device's clock read when it answered. Present when the
    /// clock was asked about; the inner epoch is absent on a device that
    /// has not found the time.
    pub time: Option<UlcpTimeRecord>,
    pub tz_offset_min: Option<i16>,
    pub repeater_enabled: Option<bool>,
    pub repeater_regions: Option<Vec<String>>,
    pub repeater_default_region: Option<Vec<u8>>,
    pub repeater_min_rssi_dbm: Option<i16>,
    pub repeater_min_snr_db: Option<i8>,
    pub dev_peer_keys: Option<Vec<Vec<u8>>>,
    pub dev_admin_keys: Option<Vec<Vec<u8>>>,
}

/// Encode a place as the cell a device advertises it from.
///
/// The counterpart to the latitude and longitude an inspection reports:
/// what goes on the air is a cell rather than a point, and how large that
/// cell is — the precision, which is also the value's length — is what the
/// device discloses. See [`ulcp_location_cell_meters`] for what each
/// precision is worth in meters.
///
/// Precision must be 1 through 7. A coordinate outside its own range is
/// refused rather than wrapped: a longitude of 200° is a typo, not a
/// place.
#[uniffi::export]
pub fn ulcp_encode_location(
    latitude_deg: f64,
    longitude_deg: f64,
    precision: u8,
) -> Result<Vec<u8>, MobileError> {
    if !(1..=MAX_PRECISION).contains(&precision)
        || !(-90.0..=90.0).contains(&latitude_deg)
        || !(-180.0..=180.0).contains(&longitude_deg)
    {
        return Err(MobileError::InvalidUlcpFrame);
    }
    // Through the exact constructor rather than the float one: at the
    // finest precisions, rounding a typed-in coordinate into a binary
    // float can land it in the neighboring cell.
    let e7 = |degrees: f64| (degrees * 1e7).round() as i32;
    Ok(
        NodeLocation::from_e7(e7(latitude_deg), e7(longitude_deg), precision)
            .as_bytes()
            .to_vec(),
    )
}

/// Present one remembered value as the property frame the inspectors read.
///
/// What [`ulcp_records_from_answers`] does for a fresh answer, for a value
/// that came out of a cache instead. Cached octets and answered octets are
/// the same octets, so they decode through the same path — and a caller
/// never has to know which command byte a reported value wears.
#[uniffi::export]
pub fn ulcp_property_record(property_id: u32, value: Vec<u8>) -> UlcpPropertyFrameRecord {
    UlcpPropertyFrameRecord {
        // A management exchange is correlated by its envelope token, so
        // every request on one carries transaction zero.
        transaction_id: 0,
        command: Cmd::PropIs as u8,
        property_id,
        value,
    }
}

/// Decode whatever a category read answered.
///
/// Nothing is required and nothing fails: a property that did not come
/// back, or came back undecodable, is left absent. Which properties were
/// *refused* is a separate question, and the answers to the read say so
/// directly.
#[uniffi::export]
pub fn inspect_ulcp_properties(
    responses: Vec<UlcpPropertyFrameRecord>,
) -> UlcpDevicePropertiesRecord {
    let at = &responses;
    let location = optional_value(at, prop::IDENT_LOCATION, |value| {
        Ok::<Vec<u8>, MobileError>(value.to_vec())
    });
    let placed = location
        .as_ref()
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| NodeLocation::from_bytes(bytes).center());

    UlcpDevicePropertiesRecord {
        battery: optional_value(at, prop::BATTERY, |value| {
            inspect_ulcp_battery(value.to_vec())
        }),
        phy_enabled: optional_value(at, prop::PHY_ENABLED, decode_bool),
        frequency_khz: optional_value(at, prop::PHY_FREQ, decode_u32),
        transmit_power_dbm: optional_value(at, prop::PHY_TX_POWER, decode_i8),
        bandwidth_hz: optional_value(at, prop::PHY_LORA_BW, decode_u32),
        spreading_factor: optional_value(at, prop::PHY_LORA_SF, decode_u8),
        coding_rate_denom: optional_value(at, prop::PHY_LORA_CR, decode_u8),
        duty_cycle_now: optional_value(at, prop::PHY_DUTY_NOW, decode_u16),
        duty_cycle_limit: optional_value(at, prop::PHY_DUTY_LIMIT, decode_u16),
        device_name: optional_value(at, prop::DEV_NAME, decode_device_name).flatten(),
        ident_role: optional_value(at, prop::IDENT_ROLE, |value| {
            decode_optional(value, decode_u8)
        })
        .flatten(),
        ident_mobile: optional_value(at, prop::IDENT_MOBILE, decode_bool),
        ident_latitude_deg: placed.map(|(latitude, _)| latitude.into()),
        ident_longitude_deg: placed.map(|(_, longitude)| longitude.into()),
        ident_location_cell_meters: location
            .as_ref()
            .filter(|bytes| !bytes.is_empty())
            .and_then(|bytes| ulcp_location_cell_meters(bytes.len() as u8)),
        ident_location: location,
        ident_altitude_m: optional_value(at, prop::IDENT_ALTITUDE, decode_optional_altitude)
            .flatten(),
        dev_discoverable: optional_value(at, prop::DEV_DISCOVERABLE, decode_bool),
        gnss_ident_update: optional_value(at, prop::GNSS_IDENT_UPDATE, decode_bool),
        gnss_ident_precision: optional_value(at, prop::GNSS_IDENT_PRECISION, decode_precision),
        uptime_seconds: optional_value(at, prop::UPTIME, decode_u32),
        advert_interval_seconds: optional_value(at, prop::ADVERT_INTERVAL, decode_u32),
        beacon_interval_seconds: optional_value(at, prop::BEACON_INTERVAL, decode_u32),
        startup_beacon: optional_value(at, prop::STARTUP_BEACON, decode_bool),
        gnss_enabled: optional_value(at, prop::GNSS_ENABLED, decode_bool),
        gnss: gnss_readout(at),
        gnss_time_trust: optional_value(at, prop::GNSS_TIME_TRUST, decode_bool),
        time: optional_value(at, prop::TIME, |value| {
            Ok::<UlcpTimeRecord, MobileError>(UlcpTimeRecord {
                epoch_seconds: decode_optional(value, decode_u32)?,
            })
        }),
        tz_offset_min: optional_value(at, prop::TZ_OFFSET, decode_i16),
        repeater_enabled: optional_value(at, prop::MAC_REPEATER_ENABLED, decode_bool),
        repeater_regions: optional_value(at, prop::MAC_REPEATER_REGIONS, decode_region_list),
        repeater_default_region: optional_value(
            at,
            prop::MAC_REPEATER_DEFAULT_REGION,
            decode_optional_region,
        )
        .flatten(),
        repeater_min_rssi_dbm: optional_value(at, prop::MAC_REPEATER_MIN_RSSI, |value| {
            decode_optional(value, decode_i16)
        })
        .flatten(),
        repeater_min_snr_db: optional_value(at, prop::MAC_REPEATER_MIN_SNR, |value| {
            decode_optional(value, decode_i8)
        })
        .flatten(),
        dev_peer_keys: optional_value(
            at,
            prop::DEV_PEERS,
            decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>,
        ),
        dev_admin_keys: optional_value(
            at,
            prop::DEV_ADMINS,
            decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>,
        ),
    }
}

/// Fold whatever positioning properties came back into one readout.
///
/// `None` unless the fix indicator arrived: without it there is nothing
/// to say whether the rest describes a position or the absence of one.
fn gnss_readout(responses: &[UlcpPropertyFrameRecord]) -> Option<UlcpGnssRecord> {
    let mut snapshot = GnssSnapshot::SEARCHING;
    property_value(responses, prop::GNSS_FIX)
        .ok()
        .and_then(|value| snapshot.absorb(prop::GNSS_FIX, value).ok())?;
    for key in [
        prop::GNSS_LOCATION,
        prop::GNSS_ALTITUDE,
        prop::GNSS_PRECISION,
        prop::GNSS_SATELLITES,
    ] {
        if let Ok(value) = property_value(responses, key) {
            let _ = snapshot.absorb(key, value);
        }
    }
    Some(gnss_record(&snapshot))
}

/// `PROP_IDENT_ALTITUDE`: empty, or a minimal-length signed integer.
fn decode_optional_altitude(value: &[u8]) -> Result<Option<i32>, MobileError> {
    match value {
        [] => Ok(None),
        bytes => umsh_ulcp::sint::decode(bytes)
            .map(Some)
            .map_err(|_| MobileError::InvalidUlcpFrame),
    }
}

/// Encode only the properties the operator actually changed.
///
/// The whole point of the category screens: a device several hops away
/// takes one write for one edit, rather than a restatement of its entire
/// configuration. `dirty_property_ids` names what was edited; anything
/// else in `desired` is ignored, so a record filled in from a stale
/// cache cannot write stale values back.
///
/// The radio is bracketed when any of its parameters move: the PHY goes
/// down first and comes back up last, so a device is never asked to
/// change the frequency it is transmitting on.
#[uniffi::export]
pub fn ulcp_dirty_writes(
    desired: UlcpDevicePropertiesRecord,
    dirty_property_ids: Vec<u32>,
) -> Result<Vec<MobileMeshPropertyWriteRecord>, MobileError> {
    let mut dirty: Vec<u32> = dirty_property_ids;
    dirty.sort_unstable();
    dirty.dedup();

    let mut values: Vec<(u32, Vec<u8>)> = Vec::new();
    for key in &dirty {
        // A property named as edited whose value is absent is a caller
        // mistake: there is nothing to write, and silently skipping it
        // would report success for an edit that never happened.
        let missing = || MobileError::InvalidUlcpFrame;
        let value = match *key {
            prop::PHY_ENABLED => vec![desired.phy_enabled.ok_or_else(missing)? as u8],
            prop::PHY_FREQ => desired
                .frequency_khz
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::PHY_TX_POWER => vec![desired.transmit_power_dbm.ok_or_else(missing)? as u8],
            prop::PHY_LORA_BW => desired
                .bandwidth_hz
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::PHY_LORA_SF => vec![desired.spreading_factor.ok_or_else(missing)?],
            prop::PHY_LORA_CR => vec![desired.coding_rate_denom.ok_or_else(missing)?],
            prop::PHY_DUTY_LIMIT => desired
                .duty_cycle_limit
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::DEV_NAME => desired
                .device_name
                .clone()
                .ok_or_else(missing)?
                .into_bytes(),
            // Empty is a legitimate value for both: the device derives
            // its own role, and advertises no position.
            prop::IDENT_ROLE => desired
                .ident_role
                .map(|role| vec![role])
                .unwrap_or_default(),
            prop::IDENT_MOBILE => vec![desired.ident_mobile.ok_or_else(missing)? as u8],
            prop::IDENT_LOCATION => {
                let location = desired.ident_location.clone().unwrap_or_default();
                if location.len() > MAX_PRECISION as usize {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                location
            }
            prop::IDENT_ALTITUDE => match desired.ident_altitude_m {
                Some(meters) => {
                    let mut buf = [0u8; umsh_ulcp::sint::MAX_LEN];
                    let len = umsh_ulcp::sint::encode(meters, &mut buf)
                        .map_err(|_| MobileError::InvalidUlcpFrame)?;
                    buf[..len].to_vec()
                }
                None => Vec::new(),
            },
            prop::DEV_DISCOVERABLE => vec![desired.dev_discoverable.ok_or_else(missing)? as u8],
            prop::GNSS_ENABLED => vec![desired.gnss_enabled.ok_or_else(missing)? as u8],
            prop::GNSS_IDENT_UPDATE => vec![desired.gnss_ident_update.ok_or_else(missing)? as u8],
            prop::GNSS_IDENT_PRECISION => {
                let precision = desired.gnss_ident_precision.ok_or_else(missing)?;
                if !(1..=MAX_PRECISION).contains(&precision) {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                vec![precision]
            }
            prop::GNSS_TIME_TRUST => vec![desired.gnss_time_trust.ok_or_else(missing)? as u8],
            // Empty clears the clock back to unknown, which is what a
            // device reports before its first fix.
            prop::TIME => desired
                .time
                .ok_or_else(missing)?
                .epoch_seconds
                .map(|epoch| epoch.to_le_bytes().to_vec())
                .unwrap_or_default(),
            prop::TZ_OFFSET => desired
                .tz_offset_min
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::ADVERT_INTERVAL => desired
                .advert_interval_seconds
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::BEACON_INTERVAL => desired
                .beacon_interval_seconds
                .ok_or_else(missing)?
                .to_le_bytes()
                .to_vec(),
            prop::STARTUP_BEACON => vec![desired.startup_beacon.ok_or_else(missing)? as u8],
            prop::MAC_REPEATER_ENABLED => vec![desired.repeater_enabled.ok_or_else(missing)? as u8],
            prop::MAC_REPEATER_REGIONS => encode_region_list(
                desired
                    .repeater_regions
                    .clone()
                    .ok_or_else(missing)?
                    .as_slice(),
            )?,
            // Empty is "never tag" and "no threshold" respectively.
            prop::MAC_REPEATER_DEFAULT_REGION => {
                let region = desired.repeater_default_region.clone().unwrap_or_default();
                if !region.is_empty() && region.len() != items::REGION_CODE_LEN {
                    return Err(MobileError::InvalidUlcpFrame);
                }
                region
            }
            prop::MAC_REPEATER_MIN_RSSI => desired
                .repeater_min_rssi_dbm
                .map(|rssi| rssi.to_le_bytes().to_vec())
                .unwrap_or_default(),
            prop::MAC_REPEATER_MIN_SNR => desired
                .repeater_min_snr_db
                .map(|snr| vec![snr as u8])
                .unwrap_or_default(),
            // Everything else is either read-only or edited as a table,
            // one entry at a time.
            _ => return Err(MobileError::InvalidUlcpFrame),
        };
        values.push((*key, value));
    }

    // Bracket the radio when anything it is transmitting under moves.
    const RADIO: [u32; 6] = [
        prop::PHY_FREQ,
        prop::PHY_TX_POWER,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
        prop::PHY_DUTY_LIMIT,
    ];
    if values.iter().any(|(key, _)| RADIO.contains(key)) {
        let ends_enabled = match values.iter().find(|(key, _)| *key == prop::PHY_ENABLED) {
            Some((_, value)) => value.first() == Some(&1),
            // Not edited, so it ends however it started — which the
            // caller states by filling this in from the last read.
            None => desired.phy_enabled.unwrap_or(true),
        };
        values.retain(|(key, _)| *key != prop::PHY_ENABLED);
        values.insert(0, (prop::PHY_ENABLED, vec![0]));
        values.push((prop::PHY_ENABLED, vec![ends_enabled as u8]));
    }

    Ok(values
        .into_iter()
        .map(|(property_id, value)| MobileMeshPropertyWriteRecord { property_id, value })
        .collect())
}

/// Properties only ever written as a set. Writing part of a modem profile
/// or part of a forwarding policy leaves the device running a configuration
/// nobody asked for, so one unreadable member withdraws the whole group.
/// These are the same groupings the reduction reports as a unit.
const WHOLE_WRITE_GROUPS: [&[u32]; 4] = [
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
    &[
        prop::ADVERT_INTERVAL,
        prop::BEACON_INTERVAL,
        prop::STARTUP_BEACON,
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

/// Decode a live reading the device may or may not have reported.
///
/// The counterpart to [`ExpectedProperties::read`] for values that are not
/// configuration: absence is ordinary rather than a withheld setting, so
/// nothing is recorded and the reduction reports what it has.
fn reported_value<T>(
    responses: &[UlcpPropertyFrameRecord],
    gated_on: bool,
    key: u32,
    decode: impl FnOnce(&[u8]) -> Result<T, MobileError>,
) -> Option<T> {
    if !gated_on {
        return None;
    }
    optional_value(responses, key, decode)
}

/// Decode a property a reply need not contain at all.
///
/// What [`reported_value`] does once a capability says the property
/// should be there, for the reductions that make no such demand: a
/// category read answers a handful of properties and says nothing about
/// the rest.
fn optional_value<T>(
    responses: &[UlcpPropertyFrameRecord],
    key: u32,
    decode: impl FnOnce(&[u8]) -> Result<T, MobileError>,
) -> Option<T> {
    property_value(responses, key).and_then(decode).ok()
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

pub(crate) fn decode_capabilities(value: &[u8]) -> Result<Vec<u32>, MobileError> {
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
        // An administrator is authorized against the device identity and
        // reaches the device domain, so there is nothing to manage without
        // one.
        || has(cap::ADMIN) && !has(cap::DEV_IDENTITY)
        // What a scheduled advertisement carries *is* the device identity.
        || has(cap::ADVERT) && !has(cap::DEV_IDENTITY)
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

/// Split a `PROP_MAC_REPEATER_REGIONS` value into its region strings.
///
/// Deliberately imposes no upper bound: how many regions a device holds
/// is its own business, and a device reporting more than this phone would
/// ever write is not a malformed frame.
fn decode_region_list(value: &[u8]) -> Result<Vec<String>, MobileError> {
    let mut regions = Vec::new();
    for item in items::prefixed_items(value) {
        let item = item.map_err(|_| MobileError::InvalidUlcpFrame)?;
        let text = core::str::from_utf8(item).map_err(|_| MobileError::InvalidUlcpFrame)?;
        regions.push(text.to_owned());
    }
    Ok(regions)
}

/// Pack region strings back into a `PROP_MAC_REPEATER_REGIONS` value.
///
/// Over-long names are refused here rather than on the air: the device
/// rejects them outright, and one rejected write abandons everything
/// after it.
fn encode_region_list(regions: &[String]) -> Result<Vec<u8>, MobileError> {
    let mut value = Vec::new();
    for region in regions {
        if !(1..=items::REGION_STRING_MAX_LEN).contains(&region.len()) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        let mut item = vec![0u8; region.len() + 4];
        let len = items::encode_prefixed_item(region.as_bytes(), &mut item)
            .map_err(|_| MobileError::InvalidUlcpFrame)?;
        value.extend_from_slice(&item[..len]);
    }
    Ok(value)
}

fn decode_optional_region(value: &[u8]) -> Result<Option<Vec<u8>>, MobileError> {
    match value.len() {
        0 => Ok(None),
        items::REGION_CODE_LEN => Ok(Some(value.to_vec())),
        _ => Err(MobileError::InvalidUlcpFrame),
    }
}

/// Drop the writes the device has already refused to answer for.
///
/// A capability-gated property that would not read is one the device does
/// not implement, so writing it fails — and one rejected write abandons
/// the whole configuration pass. The caller still states a complete
/// configuration; what cannot land is left out here, where the device's
/// own answers are known, rather than in the form.
fn writable(values: Vec<(u32, Vec<u8>)>, unreadable: &[u32]) -> Vec<(u32, Vec<u8>)> {
    if unreadable.is_empty() {
        return values;
    }
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

/// Reduce a whole device configuration to the property writes that state
/// it, in the order they must be sent, against a device known only by
/// what a completed read reported.
///
/// This is [`MobileUlcpSession::configure_device`] with the session taken
/// out of it: an administrator on the mesh writes the same properties, in
/// the same order, and drops the same unreadable ones — it just has no
/// attached device to ask, only the record it read.
pub(crate) fn device_config_writes(
    configuration: UlcpDeviceConfigRecord,
    reported: &UlcpSyncRecord,
) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
    let capabilities = DeviceCapabilities::reported(reported);
    validate_radio_settings(&configuration.radio, capabilities)?;
    let device_values = validate_device_settings(&configuration, capabilities)?;
    Ok(writable(
        configuration_values(configuration.radio, device_values),
        &reported.unreadable_properties,
    ))
}

/// What a device can be told, as either half of the app learns it.
///
/// A bench session reads the capability list off the device it is holding
/// open; a mesh administrator reads it out of the record a whole-device
/// read produced. The configuration reduces to the same writes either
/// way, so both build one of these and nothing below has to ask which
/// side it came from.
#[derive(Clone, Copy)]
struct DeviceCapabilities {
    device_name: bool,
    lora: bool,
    duty_cycle_limit: bool,
    ident: bool,
    dev_identity: bool,
    repeater: bool,
    time: bool,
    gnss: bool,
    advert: bool,
}

impl DeviceCapabilities {
    /// What the attached device answered `PROP_CAPS` with.
    fn read(state: &UlcpSessionState) -> Result<Self, MobileError> {
        Ok(Self {
            device_name: state.has_capability(cap::DEV_NAME)?,
            lora: state.has_capability(cap::PHY_LORA)?,
            duty_cycle_limit: state.has_capability(cap::PHY_DUTY_LIMIT)?,
            ident: state.has_capability(cap::IDENT)?,
            dev_identity: state.has_capability(cap::DEV_IDENTITY)?,
            repeater: state.has_capability(cap::REPEATER)?,
            time: state.has_capability(cap::TIME)?,
            gnss: state.has_capability(cap::GNSS)?,
            advert: state.has_capability(cap::ADVERT)?,
        })
    }

    /// The same list as a completed read reports it.
    fn reported(sync: &UlcpSyncRecord) -> Self {
        Self {
            device_name: sync.supports_device_name,
            lora: sync.supports_lora,
            duty_cycle_limit: sync.supports_duty_cycle_limit,
            ident: sync.supports_ident,
            dev_identity: sync.supports_device_identity,
            repeater: sync.supports_repeater,
            time: sync.supports_time,
            gnss: sync.supports_gnss,
            advert: sync.supports_advert,
        }
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
    capabilities: DeviceCapabilities,
) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
    let mut values = Vec::new();

    let supports_ident = capabilities.ident;
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

    let supports_dev_identity = capabilities.dev_identity;
    if configuration.dev_discoverable.is_some() != supports_dev_identity {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(discoverable) = configuration.dev_discoverable {
        values.push((prop::DEV_DISCOVERABLE, vec![discoverable as u8]));
    }

    let supports_repeater = capabilities.repeater;
    if configuration.repeater.is_some() != supports_repeater {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(repeater) = &configuration.repeater {
        let regions = encode_region_list(&repeater.regions)?;
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

    values.extend(positioning_values(
        configuration.gnss,
        configuration.tz_offset_min,
        capabilities,
    )?);
    values.extend(advert_values(configuration.advert, capabilities)?);
    Ok(values)
}

/// Reduce the advertisement policy to property writes.
///
/// Split out for the same reason [`positioning_values`] is: a tethered
/// phone changes these on its companion radio without commissioning it,
/// and both paths have to produce the same writes.
fn advert_values(
    advert: Option<UlcpAdvertSettingsRecord>,
    capabilities: DeviceCapabilities,
) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
    let announces = capabilities.advert;
    if advert.is_some() != announces {
        return Err(MobileError::InvalidUlcpFrame);
    }
    let Some(advert) = advert else {
        return Ok(Vec::new());
    };
    // The device refuses these too. Catching them here means an
    // out-of-range interval fails before any of the group has been
    // written, rather than leaving the schedule half-changed.
    for interval in [
        advert.advert_interval_seconds,
        advert.beacon_interval_seconds,
    ] {
        if interval != 0
            && !(MIN_AUTO_ANNOUNCE_INTERVAL_S..=MAX_AUTO_ANNOUNCE_INTERVAL_S).contains(&interval)
        {
            return Err(MobileError::InvalidUlcpFrame);
        }
    }
    Ok(vec![
        (
            prop::ADVERT_INTERVAL,
            advert.advert_interval_seconds.to_le_bytes().to_vec(),
        ),
        (
            prop::BEACON_INTERVAL,
            advert.beacon_interval_seconds.to_le_bytes().to_vec(),
        ),
        (prop::STARTUP_BEACON, vec![advert.startup_beacon as u8]),
    ])
}

/// Reduce the zone and the positioning policy to property writes.
///
/// Split out because these are the one part of a device's own domain a
/// phone changes on its *companion* radio without commissioning it —
/// [`MobileUlcpSession::configure_positioning`] writes exactly this list
/// and nothing else, where [`validate_device_settings`] folds it into a
/// whole-domain write. Same values either way, so the two paths cannot
/// drift apart.
///
/// Each field must be present exactly when its capability is: these
/// state a whole desired setting rather than a patch.
fn positioning_values(
    gnss: Option<UlcpGnssSettingsRecord>,
    tz_offset_min: Option<i16>,
    capabilities: DeviceCapabilities,
) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
    let mut values = Vec::new();

    let keeps_time = capabilities.time;
    if tz_offset_min.is_some() != keeps_time {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(minutes) = tz_offset_min {
        // The extremes of the zone database, not of the encoding: a
        // fourteen-hour offset is Kiritimati, and anything past it is a
        // caller mistake rather than a place.
        if !(-12 * 60..=14 * 60).contains(&minutes) {
            return Err(MobileError::InvalidUlcpFrame);
        }
        values.push((prop::TZ_OFFSET, minutes.to_le_bytes().to_vec()));
    }

    let positioning = capabilities.gnss;
    if gnss.is_some() != positioning {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(gnss) = gnss {
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
    capabilities: DeviceCapabilities,
) -> Result<(), MobileError> {
    if settings.frequency_khz == 0 {
        return Err(MobileError::InvalidUlcpFrame);
    }
    if let Some(name) = &settings.device_name {
        if !capabilities.device_name
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
        (None, None, None) if !capabilities.lora => {}
        (Some(bandwidth), Some(sf), Some(cr))
            if capabilities.lora
                && bandwidth > 0
                && (5..=12).contains(&sf)
                && (5..=8).contains(&cr) => {}
        _ => return Err(MobileError::InvalidUlcpFrame),
    }
    if settings.duty_cycle_limit.is_some() != capabilities.duty_cycle_limit {
        return Err(MobileError::InvalidUlcpFrame);
    }
    Ok(())
}

/// A device name, which is UTF-8 and may be empty — a device that has not
/// been named, rather than one named nothing.
fn decode_device_name(value: &[u8]) -> Result<Option<String>, MobileError> {
    let name = core::str::from_utf8(value).map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok((!name.is_empty()).then(|| name.to_owned()))
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
        .ok_or(MobileError::GattMtuTooSmall)?;
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

/// Frame a ULCP frame for an HDLC-Lite byte stream — a serial port, or
/// a socket standing in for one — including both delimiting flags.
///
/// The byte-stream counterpart of [`ulcp_gatt_segments`]: a stream has
/// no segmentation, so one frame encodes to one write.
#[uniffi::export]
pub fn ulcp_hdlc_encode(frame: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    if frame.len() > MAX_FRAME {
        return Err(MobileError::InvalidUlcpFrame);
    }
    let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
    let length =
        hdlc::encode_frame(&frame, &mut wire).map_err(|_| MobileError::InvalidUlcpFrame)?;
    wire.truncate(length);
    Ok(wire)
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

/// Capacity of the device identity's administrator list
/// (`PROP_DEV_ADMINS`).
///
/// A label constant, like [`ulcp_max_dev_peers`].
#[uniffi::export]
pub fn ulcp_max_dev_admins() -> u8 {
    8
}

/// One vetted PHY profile, as a preset picker consumes it.
///
/// A crossing of `umsh_ulcp::profiles::PhyProfile`. The bindings carry
/// no constants, so the table travels as a function.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RadioPresetRecord {
    pub id: String,
    pub name: String,
    pub frequency_khz: u32,
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate_denom: u8,
    /// Absent where the profile has no vetted power, in which case
    /// adopting it leaves a device's configured power alone.
    pub transmit_power_dbm: Option<i8>,
    pub duty_cycle_limit: u16,
    pub sync_word: u16,
    pub tx_preamble_symbols: u16,
}

/// Every vetted radio profile, in the order to offer them: the profile
/// a device ships on first.
#[uniffi::export]
pub fn ulcp_radio_presets() -> Vec<RadioPresetRecord> {
    umsh_ulcp::profiles::VETTED
        .iter()
        .map(|profile| RadioPresetRecord {
            id: profile.id.to_string(),
            name: profile.name.to_string(),
            frequency_khz: profile.freq_khz,
            bandwidth_hz: profile.bw_hz,
            spreading_factor: profile.sf,
            coding_rate_denom: profile.cr_denom,
            transmit_power_dbm: profile.tx_power_dbm,
            duty_cycle_limit: profile.duty_limit,
            sync_word: profile.sync_word,
            tx_preamble_symbols: profile.tx_preamble_symbols,
        })
        .collect()
}

/// The LoRa bandwidths a device accepts, in Hz, ascending.
#[uniffi::export]
pub fn ulcp_supported_bandwidths_hz() -> Vec<u32> {
    umsh_ulcp::profiles::SUPPORTED_BANDWIDTHS_HZ.to_vec()
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

/// Encode a `CMD_REBOOT` request with the shared ULCP codec.
#[uniffi::export]
pub fn ulcp_reboot(transaction_id: u8) -> Result<Vec<u8>, MobileError> {
    let mut output = [0; 2];
    let length =
        frame::reboot(&mut output, transaction_id).map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(output[..length].to_vec())
}

/// What a status code is called.
///
/// A device answering across the mesh reports a bare code, where a device
/// on the local link reports one already named in
/// [`UlcpOperationErrorRecord`]. Both are the same statuses, so both are
/// named the same way here rather than by a table on the other side of
/// the bindings that would have to be kept in step with this one.
#[uniffi::export]
pub fn ulcp_status_name(status: u32) -> String {
    format!("{:?}", umsh_ulcp::Status(status))
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

/// Summarize a frame's header for a diagnostic log.
///
/// Deliberately structural: transaction, command, property, and lengths,
/// never payload bytes. A platform logging this alongside a rejected
/// frame's cause learns what arrived without putting message contents
/// in the system log.
#[uniffi::export]
pub fn describe_ulcp_frame(bytes: Vec<u8>) -> String {
    let Ok(parsed) = Frame::parse(&bytes) else {
        return format!("unparsable len={}", bytes.len());
    };
    let command = match parsed.command() {
        Some(cmd) => format!("{cmd:?}({})", parsed.cmd),
        None => format!("unknown({})", parsed.cmd),
    };
    let property = match PropertyNotification::parse(&bytes) {
        Ok(notification) => format!(
            " prop=0x{:04x} value={}B",
            notification.key,
            notification.value.len()
        ),
        Err(_) => String::new(),
    };
    format!(
        "tid={} cmd={command}{property} len={}",
        parsed.header.tid(),
        bytes.len()
    )
}

/// Parse and validate a property notification or response.
#[uniffi::export]
pub fn inspect_ulcp_property_frame(bytes: Vec<u8>) -> Result<UlcpPropertyFrameRecord, MobileError> {
    let parsed = PropertyNotification::parse(&bytes).map_err(|cause| match cause {
        PropertyNotificationError::MalformedFrame => MobileError::UlcpFrameUnparsable,
        PropertyNotificationError::UnexpectedCommand => MobileError::UlcpUnexpectedCommand,
        PropertyNotificationError::MalformedPayload => MobileError::UlcpMalformedPayload,
    })?;
    Ok(UlcpPropertyFrameRecord {
        transaction_id: parsed.tid,
        command: parsed.kind.command() as u8,
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

/// Encode a `PROP_ALERT` value.
///
/// Shared by the local link and by a mesh administrator so an alert is one
/// encoding rather than two that have to agree.
pub(crate) fn encode_alert_state(state: UlcpAlertState) -> Result<Vec<u8>, MobileError> {
    let mut value = [0u8; pui::MAX_LEN];
    let len = pui::encode(state.to_wire().code(), &mut value)
        .map_err(|_| MobileError::InvalidUlcpFrame)?;
    Ok(value[..len].to_vec())
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
/// One to three ASCII letters or digits are a short code — an airport,
/// a country, a state — `0xXXXX` is a literal code, and anything else is a
/// region *name* hashed into a part of the code space disjoint from the
/// all-letter short codes. So "SJC" and "San Jose" are deliberately
/// different regions, and no name can ever collide with a letter code.
#[uniffi::export]
pub fn region_code_from_string(text: String) -> Result<Vec<u8>, MobileError> {
    text.parse::<RegionCode>()
        .map(|code| code.to_bytes().to_vec())
        .map_err(|_| MobileError::InvalidRegionCode)
}

/// Render a region code for display. Codes derived from an all-letter
/// short code come back as those letters; everything else as `0xXXXX`,
/// which [`region_code_from_string`] reads back.
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
            Some(Err(cause)) => Err(cause.into()),
        }
    }

    pub fn reset(&self) {
        self.inner
            .lock()
            .expect("GATT reassembler mutex poisoned")
            .reset();
    }
}

/// Stateful, bounded receiver for an HDLC-Lite byte stream.
///
/// Sized to admit exactly the frames [`MobileGattReassembler`] does:
/// the decoder's bound counts the two FCS octets, which a ULCP frame's
/// own length does not.
#[derive(uniffi::Object)]
pub struct MobileHdlcDecoder {
    inner: Mutex<hdlc::Decoder<{ MAX_FRAME + 2 }>>,
}

#[uniffi::export]
impl MobileHdlcDecoder {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(hdlc::Decoder::new()),
        })
    }

    /// Consume received bytes, returning every frame they completed.
    ///
    /// A stream delivers arbitrary chunks rather than whole frames, so
    /// one call can complete none or several. Corrupt and oversized
    /// frames are discarded rather than reported: the decoder
    /// resynchronizes on the next flag, and a byte stream can carry
    /// line noise that belongs to nobody — a bridge opening a serial
    /// port mid-transmission, most commonly. This is the one place the
    /// two transports differ, GATT being reliable enough that a bad
    /// segment is a protocol violation worth surfacing.
    pub fn push(&self, bytes: Vec<u8>) -> Vec<Vec<u8>> {
        let mut decoder = self.inner.lock().expect("HDLC decoder mutex poisoned");
        let mut frames = Vec::new();
        for byte in bytes {
            if let Some(Ok(frame)) = decoder.push(byte) {
                frames.push(frame.to_vec());
            }
        }
        frames
    }

    /// Discard any partially received frame. Used when the link comes
    /// up, so a half-frame from a previous connection cannot merge into
    /// the first frame of this one.
    pub fn reset(&self) {
        self.inner
            .lock()
            .expect("HDLC decoder mutex poisoned")
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
    /// right: it has an identity, advertises one, can forward, and answers
    /// to the administrators it lists.
    fn commissionable_capabilities() -> Vec<u32> {
        vec![
            cap::HOST_FILTER,
            cap::SAVE,
            cap::DEV_NAME,
            cap::DEV_IDENTITY,
            cap::REPEATER,
            cap::IDENT,
            cap::ADMIN,
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
            // A factory-default device states no position and no height.
            | prop::IDENT_LOCATION
            | prop::IDENT_ALTITUDE
            | prop::DEV_PEERS
            | prop::DEV_ADMINS
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
    fn exported_hdlc_round_trip_uses_shared_codec() {
        let frame = ulcp_prop_get(3, 4_864).unwrap();
        let wire = ulcp_hdlc_encode(frame.clone()).unwrap();

        // The export must produce the bytes the shared encoder does,
        // or a phone and a serial host would disagree on the wire.
        let mut expected = vec![0; hdlc::max_encoded_len(frame.len())];
        let length = hdlc::encode_frame(&frame, &mut expected).unwrap();
        expected.truncate(length);
        assert_eq!(wire, expected);

        let decoder = MobileHdlcDecoder::new();
        assert_eq!(decoder.push(wire), vec![frame]);
    }

    #[test]
    fn hdlc_decoding_spans_chunk_boundaries_and_batches() {
        // A stream hands over arbitrary chunks: a frame can arrive in
        // pieces, and one read can carry several frames.
        let first = ulcp_prop_get(1, 4_864).unwrap();
        let second = ulcp_prop_get(2, 4_865).unwrap();
        let mut wire = ulcp_hdlc_encode(first.clone()).unwrap();
        wire.extend(ulcp_hdlc_encode(second.clone()).unwrap());

        let decoder = MobileHdlcDecoder::new();
        let split = wire.len() / 3;
        assert!(decoder.push(wire[..split].to_vec()).is_empty());
        assert_eq!(decoder.push(wire[split..].to_vec()), vec![first, second]);
    }

    #[test]
    fn hdlc_decoding_escapes_the_framing_bytes() {
        // A frame whose payload spells the delimiters must survive.
        let frame = vec![hdlc::FLAG, hdlc::ESCAPE, 0x11, 0x13, 0x00, 0xFF];
        let decoder = MobileHdlcDecoder::new();
        assert_eq!(
            decoder.push(ulcp_hdlc_encode(frame.clone()).unwrap()),
            vec![frame]
        );
    }

    #[test]
    fn hdlc_decoding_resynchronizes_past_noise() {
        // Opening a bridged port mid-transmission leaves a partial
        // frame in the stream; the next good one must still arrive.
        let frame = ulcp_prop_get(7, 4_864).unwrap();
        let mut wire = vec![0x01, 0x02, hdlc::FLAG, 0xDE, 0xAD];
        wire.extend(ulcp_hdlc_encode(frame.clone()).unwrap());

        let decoder = MobileHdlcDecoder::new();
        assert_eq!(decoder.push(wire), vec![frame]);
    }

    #[test]
    fn hdlc_encoding_admits_exactly_what_gatt_does() {
        // Both transports carry the same frames, so a phone cannot
        // build one it could send over BLE but not over a socket.
        let largest = vec![0xA5; MAX_FRAME];
        let decoder = MobileHdlcDecoder::new();
        assert_eq!(
            decoder.push(ulcp_hdlc_encode(largest.clone()).unwrap()),
            vec![largest]
        );
        assert!(matches!(
            ulcp_hdlc_encode(vec![0xA5; MAX_FRAME + 1]),
            Err(MobileError::InvalidUlcpFrame)
        ));
    }

    #[test]
    fn a_reset_decoder_drops_the_partial_frame() {
        let frame = ulcp_prop_get(5, 4_864).unwrap();
        let wire = ulcp_hdlc_encode(frame.clone()).unwrap();

        let decoder = MobileHdlcDecoder::new();
        assert!(decoder.push(wire[..wire.len() - 2].to_vec()).is_empty());
        // Without the reset the tail would finish the stale frame.
        decoder.reset();
        assert!(decoder.push(wire[wire.len() - 2..].to_vec()).is_empty());
        assert_eq!(decoder.push(wire), vec![frame]);
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
            Err(MobileError::GattMtuTooSmall)
        );
        assert_eq!(
            MobileGattReassembler::new().push(vec![]),
            Err(MobileError::GattSegmentRunt)
        );
        // Each reassembly failure names itself, so a fatal link teardown
        // says which one happened rather than "invalid segment".
        let receiver = MobileGattReassembler::new();
        assert_eq!(
            receiver.push(vec![0xC0]),
            Err(MobileError::GattSegmentOrphan)
        );
        assert_eq!(
            receiver.push(vec![0x08]),
            Err(MobileError::GattSegmentReservedBits)
        );
        let mut oversized = vec![0u8; MAX_FRAME + 2];
        oversized[0] = gatt::SAR_FIRST << 6;
        assert_eq!(
            receiver.push(oversized),
            Err(MobileError::GattSegmentTooLong)
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
    fn a_reading_is_carried_when_reported_and_missed_quietly_when_not() {
        let capabilities = encoded_capabilities(&[cap::BATTERY, cap::ALERT]);
        let base = |extra: Vec<UlcpPropertyFrameRecord>| {
            let mut responses = vec![
                response(prop::CAPS, &capabilities),
                response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
                response(prop::PHY_ENABLED, &[1]),
                response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
                response(prop::PHY_TX_POWER, &[14]),
            ];
            responses.extend(extra);
            inspect_ulcp_sync(responses).unwrap()
        };

        let reported = base(vec![
            response(prop::BATTERY, &[0b110, 82, 1]),
            response(prop::ALERT, &[AlertState::Locate.code() as u8]),
        ]);
        assert_eq!(reported.battery.unwrap().percentage, Some(82));
        assert_eq!(reported.alert, Some(UlcpAlertState::Locate));

        // The case that matters: a device that has said nothing about
        // either is not a device withholding settings. Both are absent, and
        // neither shows up in the notice about configuration this phone
        // would write over.
        let silent = base(Vec::new());
        assert!(silent.supports_battery && silent.supports_alert);
        assert_eq!(silent.battery, None);
        assert_eq!(silent.alert, None);
        assert!(silent.unreadable_properties.is_empty());
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
            // SJC and SFO, the strings exactly as they were written.
            response(
                prop::MAC_REPEATER_REGIONS,
                &[3, b'S', b'J', b'C', 3, b'S', b'F', b'O'],
            ),
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
                regions: vec!["SJC".to_owned(), "SFO".to_owned()],
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
                advert: None,
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
                    regions: vec!["SJC".to_owned()],
                    default_region: Some(vec![0x78, 0x53]),
                    min_rssi_dbm: Some(-115),
                    min_snr_db: Some(-7),
                }),
                tz_offset_min: None,
                gnss: None,
                advert: None,
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
                (prop::MAC_REPEATER_REGIONS, vec![3, b'S', b'J', b'C']),
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
                regions: vec!["SJC".to_owned()],
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
                advert: None,
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
        // A region string is 1 to 24 octets; outside that the device
        // refuses it, so the write never leaves the phone.
        for bad in ["", &"A".repeat(items::REGION_STRING_MAX_LEN + 1)] {
            assert_eq!(
                configure(
                    None,
                    Some(false),
                    Some(true),
                    Some(UlcpRepeaterSettingsRecord {
                        regions: vec![bad.to_owned()],
                        ..repeater.clone()
                    })
                ),
                Err(MobileError::InvalidUlcpFrame)
            );
        }
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
        // A two-letter short code is a region in its own right.
        assert_eq!(region_code_from_string("WA".into()).unwrap(), [0x8F, 0xE8]);
        assert_eq!(region_code_description(vec![0x8F, 0xE8]).unwrap(), "WA");
        // A name lands outside the letter space, so it never renders as
        // letters and round-trips through hex.
        let named = region_code_from_string("Rogue Valley".into()).unwrap();
        assert_eq!(named, [0xC0, 0xF9]);
        let described = region_code_description(named.clone()).unwrap();
        assert_eq!(described, "0xC0F9");
        assert_eq!(region_code_from_string(described).unwrap(), named);

        // Case is not part of a region's identity, on either derivation.
        assert_eq!(region_code_from_string("sjc".into()).unwrap(), [0x78, 0x53]);
        assert_eq!(
            region_code_from_string("rogue valley".into()).unwrap(),
            named
        );

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
            Err(MobileError::UlcpMismatchedResponse)
        );
        // The rejection consumed the expectation, so a second response on
        // that transaction is a different fault — nobody is waiting on it —
        // and says so rather than reusing one catch-all.
        assert_eq!(
            session.consume(property_response(tid, prop::PHY_FREQ, &[0; 4])),
            Err(MobileError::UlcpUnexpectedFrame)
        );
    }

    #[test]
    fn received_frame_causes_are_distinguishable() {
        let session = MobileUlcpSession::new();
        assert_eq!(
            session.consume(vec![0x00, 0x06]),
            Err(MobileError::UlcpFrameUnparsable)
        );
        // A well-formed command this session does not handle — a newer
        // firmware's unsolicited notification, or a `CMD_PROP_ARE` — is
        // named as such, not reported as a corrupt frame.
        let mut save = [0u8; 8];
        let len = frame::save(&mut save, 1).unwrap();
        assert_eq!(
            session.consume(save[..len].to_vec()),
            Err(MobileError::UlcpUnexpectedCommand)
        );
    }

    #[test]
    fn frame_descriptions_name_the_command_without_payload_bytes() {
        let mut bytes = [0u8; 16];
        let len = frame::prop_is(&mut bytes, 3, 0x1234, &[5, 6]).unwrap();
        assert_eq!(
            describe_ulcp_frame(bytes[..len].to_vec()),
            "tid=3 cmd=PropIs(6) prop=0x1234 value=2B len=6"
        );
        assert_eq!(describe_ulcp_frame(vec![0x00]), "unparsable len=1");
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

    fn dev_admin_keys(update: &UlcpSessionUpdateRecord) -> Vec<Vec<u8>> {
        update
            .snapshot
            .provisioning
            .as_ref()
            .unwrap()
            .dev_admin_keys
            .clone()
            .unwrap()
    }

    #[test]
    fn listing_an_administrator_is_the_bench_half_of_node_management() {
        let session = MobileUlcpSession::new();
        let attached = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert!(
            attached
                .snapshot
                .provisioning
                .as_ref()
                .unwrap()
                .supports_admin
        );
        assert_eq!(dev_admin_keys(&attached), Vec::<Vec<u8>>::new());

        // The phone's own node key, put on a radio it is holding so it can
        // manage that radio from somewhere else later.
        let phone = vec![0x11; 32];
        let insert = session.insert_device_admin(phone.clone()).unwrap();
        let request = Frame::parse(&insert.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropInsert));

        let confirmed = session
            .consume(inserted_response(
                request.header.tid(),
                prop::DEV_ADMINS,
                &phone,
            ))
            .unwrap();
        assert_eq!(dev_admin_keys(&confirmed), vec![phone.clone()]);
        // Administrators are the one table that must survive a reboot to be
        // worth anything, so the save rides behind the mutation.
        let save = Frame::parse(&confirmed.outbound_frames[0]).unwrap();
        assert_eq!(save.command(), Some(Cmd::Save));
        session
            .consume(property_response(
                save.header.tid(),
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::OK.0 as u8],
            ))
            .unwrap();

        // The peer table is a different list and is untouched by any of it.
        assert_eq!(dev_peer_keys(&confirmed), Vec::<Vec<u8>>::new());

        let remove = session.remove_device_admin(phone.clone()).unwrap();
        let request = Frame::parse(&remove.outbound_frames[0]).unwrap();
        assert_eq!(request.command(), Some(Cmd::PropRemove));
        let confirmed = session
            .consume(removed_response(
                request.header.tid(),
                prop::DEV_ADMINS,
                &phone,
            ))
            .unwrap();
        assert_eq!(dev_admin_keys(&confirmed), Vec::<Vec<u8>>::new());
    }

    /// An administrator on the mesh has no session to hand a configuration
    /// to, only the record its read produced. It must still write exactly
    /// what a phone holding the device would write, in the same order.
    #[test]
    fn a_configuration_reduces_the_same_way_with_or_without_a_session() {
        let configuration = UlcpDeviceConfigRecord {
            radio: UlcpRadioSettingsRecord {
                device_name: Some("Ridge repeater".into()),
                phy_enabled: true,
                frequency_khz: 906_875,
                transmit_power_dbm: 20,
                bandwidth_hz: None,
                spreading_factor: None,
                coding_rate_denom: None,
                duty_cycle_limit: None,
            },
            ident_role: None,
            ident_mobile: Some(false),
            dev_discoverable: Some(true),
            repeater: Some(UlcpRepeaterSettingsRecord {
                enabled: true,
                regions: Vec::new(),
                default_region: None,
                min_rssi_dbm: None,
                min_snr_db: None,
            }),
            tz_offset_min: None,
            gnss: None,
            advert: None,
        };

        let session = MobileUlcpSession::new();
        let attached = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        let reported = attached.snapshot.provisioning.clone().unwrap();

        let configured = session.configure_device(configuration.clone()).unwrap();
        let (written, order, _) = drive_configuration(&session, configured.outbound_frames);

        let writes = device_config_writes(configuration, &reported).unwrap();
        assert_eq!(
            writes.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            order
        );
        for (key, value) in &writes {
            assert_eq!(written.get(key), Some(value));
        }
        // Not vacuous: the name leads, and the PHY is the last thing turned
        // on — a repeater must not start forwarding under half a policy.
        assert_eq!(writes.first().unwrap().0, prop::DEV_NAME);
        assert_eq!(writes.last().unwrap(), &(prop::PHY_ENABLED, vec![1]));
    }

    /// A device that would not report a property is a device that will
    /// refuse to be told it, whichever side is doing the telling.
    #[test]
    fn an_unreadable_property_is_left_out_of_an_administrator_s_write() {
        let mut reported = attach_commissionable(
            &MobileUlcpSession::new(),
            Some(vec![0xAA; 32]),
            vec![0xAA; 32],
        )
        .snapshot
        .provisioning
        .clone()
        .unwrap();
        reported.unreadable_properties = vec![prop::DEV_DISCOVERABLE];

        let configuration = UlcpDeviceConfigRecord {
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
            ident_mobile: Some(false),
            dev_discoverable: Some(true),
            repeater: Some(UlcpRepeaterSettingsRecord {
                enabled: true,
                regions: Vec::new(),
                default_region: None,
                min_rssi_dbm: None,
                min_snr_db: None,
            }),
            tz_offset_min: None,
            gnss: None,
            advert: None,
        };
        // The record still states discoverability — the form does not know
        // which properties a device refuses — and the write does not.
        let writes = device_config_writes(configuration, &reported).unwrap();
        assert!(!writes.iter().any(|(key, _)| *key == prop::DEV_DISCOVERABLE));
    }

    #[test]
    fn an_administrator_failure_names_the_list_it_came_from() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let insert = session.insert_device_admin(vec![0x22; 32]).unwrap();
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
                operation: "insert device administrator".into(),
                status_code: umsh_ulcp::Status::NOMEM.0,
                status_name: "Status::NOMEM".into(),
            })
        );
        assert_eq!(dev_admin_keys(&full), Vec::<Vec<u8>>::new());
        assert_eq!(full.snapshot.phase, UlcpSessionPhase::Attached);
    }

    #[test]
    fn a_radio_that_cannot_be_managed_refuses_the_administrator_table() {
        let session = MobileUlcpSession::new();
        // CAP_ADMIN withheld: the list does not exist on this device, so
        // writing it is not something to try and fail at.
        let capabilities = vec![
            cap::HOST_FILTER,
            cap::SAVE,
            cap::DEV_NAME,
            cap::DEV_IDENTITY,
        ];
        let sync = inspect_ulcp_sync(vec![
            response(prop::CAPS, &encoded_capabilities(&capabilities)),
            response(prop::INTERFACE_TYPE, &[INTERFACE_TYPE as u8]),
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &915_000u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[14]),
            response(prop::HOST_RX_FILTERS, &[]),
            response(prop::SAVED, &[saved::CURRENT]),
            response(prop::DEV_PEERS, &[]),
            response(prop::DEV_CHANNEL_KEYS, &[]),
            response(prop::DEV_DISCOVERABLE, &[1]),
        ])
        .unwrap();
        assert!(!sync.supports_admin);
        assert_eq!(sync.dev_admin_keys, None);
        assert!(!sync.unreadable_properties.contains(&prop::DEV_ADMINS));
        assert!(
            !ulcp_inspection_properties(encoded_capabilities(&capabilities))
                .unwrap()
                .contains(&prop::DEV_ADMINS)
        );

        assert!(session.insert_device_admin(vec![0x33; 32]).is_err());
    }

    #[test]
    fn an_administrator_list_needs_a_device_identity_to_authorize_against() {
        assert!(
            ulcp_inspection_properties(encoded_capabilities(&[cap::ADMIN])).is_err(),
            "CAP_ADMIN without CAP_DEV_IDENTITY is not a device this phone can describe"
        );
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

    fn attach_advertising(session: &MobileUlcpSession) -> UlcpSessionUpdateRecord {
        let mut capabilities = commissionable_capabilities();
        capabilities.push(cap::ADVERT);
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        drive_reads(
            session,
            begin.outbound_frames,
            move |property| match property {
                prop::CAPS => (property, encoded_capabilities(&capabilities)),
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                prop::ADVERT_INTERVAL => (property, 14_400u32.to_le_bytes().to_vec()),
                prop::BEACON_INTERVAL => (property, 3_600u32.to_le_bytes().to_vec()),
                prop::STARTUP_BEACON => (property, vec![1]),
                _ => commissionable_value(property),
            },
        )
    }

    #[test]
    fn advertisement_policy_folds_into_the_sync_record() {
        let session = MobileUlcpSession::administrative();
        let update = attach_advertising(&session);
        let sync = update.snapshot.provisioning.expect("device described");

        assert!(sync.supports_advert);
        assert_eq!(
            sync.advert,
            Some(UlcpAdvertSettingsRecord {
                advert_interval_seconds: 14_400,
                beacon_interval_seconds: 3_600,
                startup_beacon: true,
            })
        );
    }

    /// A commissioning phone has no way to ask for one property on its
    /// own, so the position the device advertises has to arrive with the
    /// attach snapshot — it is where a region proposal starts from.
    #[test]
    fn the_advertised_position_folds_into_the_sync_record() {
        let cell = NodeLocation::from_lat_lon(37.5119, -122.2495, 4);
        let session = MobileUlcpSession::administrative();
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        let bytes = cell.as_bytes().to_vec();
        let update = drive_reads(
            &session,
            begin.outbound_frames,
            move |property| match property {
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                prop::IDENT_LOCATION => (property, bytes.clone()),
                prop::IDENT_ALTITUDE => (property, vec![0x64]),
                _ => commissionable_value(property),
            },
        );
        let sync = update.snapshot.provisioning.expect("device described");
        let position = sync.ident_position.expect("position reported");

        assert_eq!(position.location, cell.as_bytes());
        assert!((position.latitude_deg.unwrap() - 37.5119).abs() < 0.01);
        assert!((position.longitude_deg.unwrap() + 122.2495).abs() < 0.01);
        assert!((610.0..613.0).contains(&position.cell_meters.unwrap()));
        assert_eq!(position.altitude_m, Some(100));
    }

    /// A device that states no position reports an empty cell, which is a
    /// value: it is placed nowhere, not unread.
    #[test]
    fn an_unplaced_device_reports_an_empty_cell() {
        let session = MobileUlcpSession::administrative();
        let update = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        let sync = update.snapshot.provisioning.expect("device described");
        let position = sync.ident_position.expect("position reported");

        assert!(position.location.is_empty());
        assert_eq!(position.latitude_deg, None);
        assert_eq!(position.cell_meters, None);
        assert_eq!(position.altitude_m, None);
    }

    /// A device that never claimed `CAP_ADVERT` has no schedule to report,
    /// and the read must not go looking for one.
    #[test]
    fn a_device_without_the_capability_reports_no_advertisement_policy() {
        let session = MobileUlcpSession::administrative();
        let update = attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        let sync = update.snapshot.provisioning.expect("device described");

        assert!(!sync.supports_advert);
        assert_eq!(sync.advert, None);
    }

    #[test]
    fn configure_advertising_writes_the_whole_schedule() {
        let session = MobileUlcpSession::administrative();
        attach_advertising(&session);

        let configured = session
            .configure_advertising(Some(UlcpAdvertSettingsRecord {
                advert_interval_seconds: 0,
                beacon_interval_seconds: 1_800,
                startup_beacon: false,
            }))
            .unwrap();
        let (written, _, _) = drive_configuration(&session, configured.outbound_frames);
        assert_eq!(
            written.get(&prop::ADVERT_INTERVAL).map(Vec::as_slice),
            Some(&0u32.to_le_bytes()[..])
        );
        assert_eq!(
            written.get(&prop::BEACON_INTERVAL).map(Vec::as_slice),
            Some(&1_800u32.to_le_bytes()[..])
        );
        assert_eq!(
            written.get(&prop::STARTUP_BEACON).map(Vec::as_slice),
            Some(&[0u8][..])
        );
    }

    /// Catching the bounds here means an out-of-range interval fails
    /// before any of the group is written, rather than half-changing the
    /// schedule.
    #[test]
    fn an_advertisement_record_must_match_what_the_device_can_do() {
        let session = MobileUlcpSession::administrative();
        attach_advertising(&session);
        let whole = UlcpAdvertSettingsRecord {
            advert_interval_seconds: 14_400,
            beacon_interval_seconds: 3_600,
            startup_beacon: true,
        };

        // Absent on a device that advertises the capability.
        assert_eq!(
            session.configure_advertising(None),
            Err(MobileError::InvalidUlcpFrame)
        );
        for out_of_range in [
            MIN_AUTO_ANNOUNCE_INTERVAL_S - 1,
            MAX_AUTO_ANNOUNCE_INTERVAL_S + 1,
        ] {
            assert_eq!(
                session.configure_advertising(Some(UlcpAdvertSettingsRecord {
                    beacon_interval_seconds: out_of_range,
                    ..whole
                })),
                Err(MobileError::InvalidUlcpFrame)
            );
        }
        // Zero is the off switch, not a too-short interval.
        assert!(
            session
                .configure_advertising(Some(UlcpAdvertSettingsRecord {
                    beacon_interval_seconds: 0,
                    ..whole
                }))
                .is_ok()
        );
    }

    /// Present on a device that does not advertise the capability is the
    /// mirror-image mistake, and is refused the same way.
    #[test]
    fn an_advertisement_record_is_refused_without_the_capability() {
        let session = MobileUlcpSession::administrative();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(
            session.configure_advertising(Some(UlcpAdvertSettingsRecord {
                advert_interval_seconds: 14_400,
                beacon_interval_seconds: 3_600,
                startup_beacon: true,
            })),
            Err(MobileError::InvalidUlcpFrame)
        );
    }

    /// A five-byte fix — a ~38 m cell, the default identity precision.
    fn placed_location() -> NodeLocation {
        NodeLocation::from_e7(377_749_290, -1_224_194_160, 5)
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
        let (latitude, longitude) = (gnss.latitude_deg.unwrap(), gnss.longitude_deg.unwrap());
        assert!((latitude - 37.774_929).abs() < 5e-4, "{latitude}");
        assert!((longitude + 122.419_416).abs() < 5e-4, "{longitude}");
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
    fn sampling_a_position_asks_for_the_position_and_nothing_else() {
        let session = MobileUlcpSession::new();
        attach_positioning(&session);

        // The device never announces where it is — a receiver reports
        // about a fix a second and noise moves the reading, so a host that
        // wants a position asks for one.
        let poll = session.refresh_positioning().unwrap();
        let asked: Vec<u32> = poll
            .outbound_frames
            .iter()
            .map(|frame| {
                let parsed = Frame::parse(frame).unwrap();
                PropPayload::parse(parsed.payload).unwrap().key
            })
            .collect();
        assert_eq!(
            asked,
            vec![
                prop::GNSS_LOCATION,
                prop::GNSS_ALTITUDE,
                prop::GNSS_FIX,
                prop::GNSS_PRECISION,
                prop::GNSS_SATELLITES,
            ]
        );

        // Narrower than a full refresh, which is the point: a screen
        // watching a position must not re-read the radio's whole
        // configuration once a minute to do it.
        assert!(!asked.contains(&prop::PHY_FREQ));
        assert!(!asked.contains(&prop::DEV_NAME));

        // The answers land in the same snapshot field the announcements
        // used to fill, so nothing downstream can tell the two apart.
        let sampled = answer_requests(&session, poll.outbound_frames, |property| match property {
            prop::GNSS_LOCATION => (property, placed_location().as_bytes().to_vec()),
            prop::GNSS_ALTITUDE => (property, 88i32.to_le_bytes().to_vec()),
            prop::GNSS_FIX => (property, vec![2]),
            prop::GNSS_PRECISION => (property, 40u16.to_le_bytes().to_vec()),
            prop::GNSS_SATELLITES => (property, vec![11, 15]),
            _ => unreachable!("{property}"),
        });
        let gnss = sampled.snapshot.gnss.expect("a receiver was sampled");
        assert_eq!(gnss.altitude_m, Some(88));
        assert_eq!(gnss.satellites_used, 11);
        assert_eq!(sampled.snapshot.phase, UlcpSessionPhase::Attached);
    }

    #[test]
    fn a_radio_without_a_receiver_is_never_asked_where_it_is() {
        // Every positioning property would be refused one at a time; the
        // question is not worth asking at all.
        let session = attached_battery_session();
        assert_eq!(
            session.refresh_positioning(),
            Err(MobileError::InvalidUlcpFrame)
        );
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
                advert: None,
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
    fn a_tethered_phone_changes_positioning_without_restating_the_domain() {
        // The companion case: switching a receiver on must not require
        // saying anything about the radio's role or what it forwards.
        let session = MobileUlcpSession::new();
        attach_positioning(&session);

        let configured = session
            .configure_positioning(
                Some(UlcpGnssSettingsRecord {
                    enabled: false,
                    ident_update: false,
                    ident_precision: 3,
                    time_trust: false,
                }),
                Some(0),
            )
            .unwrap();
        let (written, order, save_tid) = drive_configuration(&session, configured.outbound_frames);

        assert_eq!(
            written,
            HashMap::from([
                (prop::TZ_OFFSET, 0i16.to_le_bytes().to_vec()),
                (prop::GNSS_IDENT_UPDATE, vec![0]),
                (prop::GNSS_IDENT_PRECISION, vec![3]),
                (prop::GNSS_TIME_TRUST, vec![0]),
                (prop::GNSS_ENABLED, vec![0]),
            ]),
            "only the zone and the positioning policy are written"
        );
        assert_eq!(order.last(), Some(&prop::GNSS_ENABLED));

        // It closes like any configuration pass: a save, then the
        // device's own answers reduced into a fresh snapshot.
        let attached = session
            .consume(property_response(save_tid, prop::LAST_STATUS, &[0]))
            .unwrap();
        assert_eq!(attached.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            attached.snapshot.provisioning.unwrap().gnss,
            Some(UlcpGnssSettingsRecord {
                enabled: false,
                ident_update: false,
                ident_precision: 3,
                time_trust: false,
            })
        );
    }

    #[test]
    fn positioning_on_its_own_still_matches_the_capabilities() {
        let session = MobileUlcpSession::new();
        attach_positioning(&session);
        let whole = UlcpGnssSettingsRecord {
            enabled: true,
            ident_update: false,
            ident_precision: 5,
            time_trust: true,
        };
        // The same presence rule as the whole-domain write.
        assert_eq!(
            session.configure_positioning(Some(whole), None),
            Err(MobileError::InvalidUlcpFrame)
        );
        assert_eq!(
            session.configure_positioning(None, Some(0)),
            Err(MobileError::InvalidUlcpFrame)
        );

        // And a radio with neither capability has nothing to configure,
        // which is a caller mistake rather than an empty success.
        let plain = MobileUlcpSession::new();
        attach_commissionable(&plain, Some(vec![0xAA; 32]), vec![0xAA; 32]);
        assert_eq!(
            plain.configure_positioning(None, None),
            Err(MobileError::UnsupportedCapability)
        );
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
            advert: None,
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
                advert: None,
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

    // ─── Cached, category-at-a-time remote management ────────────────────

    /// The capabilities of a full-featured tracker, for planning against.
    fn managed_capabilities() -> Vec<u8> {
        encoded_capabilities(&[
            cap::DEV_NAME,
            cap::BATTERY,
            cap::PHY_LORA,
            cap::PHY_DUTY_LIMIT,
            cap::REPEATER,
            cap::IDENT,
            cap::DEV_IDENTITY,
            cap::GNSS,
            cap::TIME,
            cap::ADVERT,
            cap::ADMIN,
            cap::ALERT,
            cap::SAVE,
            cap::CMD_MULTI,
        ])
    }

    #[test]
    fn a_category_asks_only_for_its_own_screen() {
        let caps = managed_capabilities();
        let radio = ulcp_category_properties(UlcpManageCategory::Radio, caps.clone()).unwrap();
        assert_eq!(
            radio,
            vec![
                prop::PHY_ENABLED,
                prop::PHY_FREQ,
                prop::PHY_TX_POWER,
                prop::PHY_LORA_BW,
                prop::PHY_LORA_SF,
                prop::PHY_LORA_CR,
                prop::PHY_DUTY_NOW,
                prop::PHY_DUTY_LIMIT,
            ]
        );
        assert_eq!(
            ulcp_category_properties(UlcpManageCategory::Power, caps).unwrap(),
            vec![prop::BATTERY],
            "one property is the whole of a power screen"
        );
    }

    /// The bug this pins: an edit to one property must not drag its
    /// neighbors into the write. A device holding a value nobody touched
    /// keeps it because nothing was sent, not because the same value was
    /// sent back — restating it can be refused, and a refusal abandons
    /// the settings someone actually changed.
    #[test]
    fn only_what_was_edited_is_written() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                gnss_enabled: Some(true),
                gnss_ident_update: Some(false),
                gnss_ident_precision: Some(4),
                gnss_time_trust: Some(true),
                ..Default::default()
            },
            &[prop::GNSS_IDENT_UPDATE],
        )
        .unwrap();
        assert_eq!(
            written,
            vec![(prop::GNSS_IDENT_UPDATE, vec![0])],
            "the other three GNSS settings were not edited, so they do not travel"
        );
    }

    #[test]
    fn a_category_leaves_out_what_the_device_cannot_do() {
        // A repeater with no receiver and no modem knobs.
        let caps = encoded_capabilities(&[cap::REPEATER, cap::IDENT, cap::DEV_IDENTITY]);
        assert_eq!(
            ulcp_category_properties(UlcpManageCategory::Radio, caps.clone()).unwrap(),
            vec![prop::PHY_ENABLED, prop::PHY_FREQ, prop::PHY_TX_POWER],
            "a device without CAP_PHY_LORA is not asked for a modem profile"
        );
        assert!(
            ulcp_category_properties(UlcpManageCategory::Gnss, caps.clone())
                .unwrap()
                .is_empty(),
            "a device with no receiver has no GNSS screen to fill"
        );
        let identity = ulcp_category_properties(UlcpManageCategory::Identity, caps).unwrap();
        assert!(
            identity.contains(&prop::IDENT_LOCATION),
            "a fixed repeater still has a position to state"
        );
        assert!(
            !identity.contains(&prop::GNSS_IDENT_UPDATE),
            "nothing to auto-update from"
        );
    }

    #[test]
    fn the_card_is_what_survives_between_openings() {
        let card = inspect_ulcp_device_card(vec![
            response(prop::CAPS, &managed_capabilities()),
            response(prop::DEV_VERSION, b"fw-2026.08.01"),
            response(prop::DEV_MODEL, b"T1000-E"),
            response(prop::DEV_NAME, b"Ridge"),
        ])
        .unwrap();
        assert_eq!(card.device_version.as_deref(), Some("fw-2026.08.01"));
        assert_eq!(card.device_model.as_deref(), Some("T1000-E"));
        assert_eq!(card.device_name.as_deref(), Some("Ridge"));
        assert!(card.supports_alert, "the find-my-device button is offered");
        assert!(card.supports_multi, "batched reads are worth trying");
        assert_eq!(
            card.capabilities,
            managed_capabilities(),
            "kept verbatim, to plan later reads against without asking again"
        );
    }

    #[test]
    fn a_card_without_capabilities_is_no_card_at_all() {
        assert!(
            inspect_ulcp_device_card(vec![response(prop::DEV_NAME, b"Ridge")]).is_err(),
            "nothing can be planned against a device that would not say what it is"
        );
    }

    #[test]
    fn a_card_tolerates_a_device_that_names_neither_firmware_nor_model() {
        let card =
            inspect_ulcp_device_card(vec![response(prop::CAPS, &managed_capabilities())]).unwrap();
        assert_eq!(card.device_version, None);
        assert_eq!(card.device_model, None);
        assert!(card.supports_gnss, "the capabilities still read");
    }

    #[test]
    fn a_category_read_says_nothing_about_the_categories_it_did_not_ask_for() {
        let read = inspect_ulcp_properties(vec![
            response(prop::PHY_ENABLED, &[1]),
            response(prop::PHY_FREQ, &906_875u32.to_le_bytes()),
            response(prop::PHY_TX_POWER, &[22]),
            response(prop::PHY_LORA_SF, &[11]),
        ]);
        assert_eq!(read.phy_enabled, Some(true));
        assert_eq!(read.frequency_khz, Some(906_875));
        assert_eq!(read.transmit_power_dbm, Some(22));
        assert_eq!(read.spreading_factor, Some(11));
        assert_eq!(read.device_name, None, "nobody asked");
        assert_eq!(read.repeater_enabled, None);
        assert_eq!(read.gnss, None);
    }

    #[test]
    fn an_unreadable_answer_leaves_its_field_absent_rather_than_failing_the_read() {
        let read = inspect_ulcp_properties(vec![
            response(prop::PHY_FREQ, &[0x01, 0x02]),
            response(prop::PHY_TX_POWER, &[17]),
        ]);
        assert_eq!(read.frequency_khz, None, "two octets are not a frequency");
        assert_eq!(
            read.transmit_power_dbm,
            Some(17),
            "one bad answer does not cost the screen the rest"
        );
    }

    #[test]
    fn an_advertised_position_reads_as_a_place() {
        let cell = [0x84, 0x21, 0x9f, 0x40];
        let read = inspect_ulcp_properties(vec![
            response(prop::IDENT_LOCATION, &cell),
            response(prop::IDENT_ALTITUDE, &[0xC8, 0x00]),
        ]);
        assert_eq!(read.ident_location.as_deref(), Some(&cell[..]));
        assert!(read.ident_latitude_deg.is_some());
        assert!(read.ident_longitude_deg.is_some());
        assert_eq!(
            read.ident_location_cell_meters,
            ulcp_location_cell_meters(4),
            "what the four octets actually disclose"
        );
        assert_eq!(
            read.ident_altitude_m,
            Some(200),
            "a padded altitude reads the same as a minimal one"
        );
    }

    #[test]
    fn a_device_advertising_no_position_is_not_a_device_that_was_never_asked() {
        let read = inspect_ulcp_properties(vec![
            response(prop::IDENT_LOCATION, &[]),
            response(prop::IDENT_ALTITUDE, &[]),
        ]);
        assert_eq!(read.ident_location, Some(Vec::new()));
        assert_eq!(read.ident_latitude_deg, None);
        assert_eq!(read.ident_altitude_m, None);
    }

    #[test]
    fn a_place_encodes_to_the_cell_it_reads_back_as() {
        let cell = ulcp_encode_location(37.3382, -121.8863, 5).unwrap();
        assert_eq!(cell.len(), 5, "the precision is the value's length");
        let read = inspect_ulcp_properties(vec![response(prop::IDENT_LOCATION, &cell)]);
        assert!(
            (read.ident_latitude_deg.unwrap() - 37.3382).abs() < 0.01,
            "the cell the point falls in"
        );
        assert!((read.ident_longitude_deg.unwrap() + 121.8863).abs() < 0.01);
    }

    #[test]
    fn a_coordinate_off_the_globe_is_a_typo_rather_than_a_place() {
        assert!(ulcp_encode_location(37.0, 200.0, 5).is_err());
        assert!(ulcp_encode_location(91.0, 0.0, 5).is_err());
        assert!(ulcp_encode_location(37.0, 0.0, 0).is_err());
        assert!(ulcp_encode_location(37.0, 0.0, 8).is_err());
    }

    #[test]
    fn a_negative_altitude_is_an_ordinary_place() {
        let read = inspect_ulcp_properties(vec![response(prop::IDENT_ALTITUDE, &[0x9C])]);
        assert_eq!(read.ident_altitude_m, Some(-100), "Death Valley reads");
    }

    #[test]
    fn a_receiver_readout_needs_the_fix_to_mean_anything() {
        let without = inspect_ulcp_properties(vec![
            response(prop::GNSS_ENABLED, &[1]),
            response(prop::GNSS_SATELLITES, &[7, 9]),
        ]);
        assert_eq!(without.gnss_enabled, Some(true));
        assert_eq!(
            without.gnss, None,
            "satellite counts alone do not say whether there is a position"
        );

        let with = inspect_ulcp_properties(vec![
            response(prop::GNSS_FIX, &[FixKind::ThreeD as u8]),
            response(prop::GNSS_LOCATION, &[0x84, 0x21, 0x9f, 0x40]),
            response(prop::GNSS_ALTITUDE, &1_400i32.to_le_bytes()),
            response(prop::GNSS_SATELLITES, &[7, 9]),
        ]);
        let readout = with.gnss.expect("a fix makes a readout");
        assert_eq!(readout.altitude_m, Some(1_400));
        assert_eq!(readout.satellites_used, 7);
        assert!(readout.latitude_deg.is_some());
    }

    /// The writes a dirty-apply produced, in order.
    fn dirty(
        desired: UlcpDevicePropertiesRecord,
        edited: &[u32],
    ) -> Result<Vec<(u32, Vec<u8>)>, MobileError> {
        Ok(ulcp_dirty_writes(desired, edited.to_vec())?
            .into_iter()
            .map(|write| (write.property_id, write.value))
            .collect())
    }

    #[test]
    fn one_edit_is_one_write() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                device_name: Some("Saddle".into()),
                // Everything a full read would have filled in, none of
                // which was touched.
                ident_mobile: Some(true),
                repeater_enabled: Some(true),
                dev_discoverable: Some(false),
                ..Default::default()
            },
            &[prop::DEV_NAME],
        )
        .unwrap();
        assert_eq!(
            written,
            vec![(prop::DEV_NAME, b"Saddle".to_vec())],
            "the point of the whole design: a rename costs one write"
        );
    }

    #[test]
    fn an_edit_with_nothing_to_write_is_a_caller_mistake() {
        assert!(
            dirty(UlcpDevicePropertiesRecord::default(), &[prop::DEV_NAME]).is_err(),
            "reporting success for an edit that carries no value would be a lie"
        );
    }

    #[test]
    fn a_modem_knob_travels_alone_inside_the_bracket() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                phy_enabled: Some(true),
                bandwidth_hz: Some(250_000),
                spreading_factor: Some(10),
                coding_rate_denom: Some(5),
                ..Default::default()
            },
            &[prop::PHY_LORA_SF],
        )
        .unwrap();
        let keys: Vec<u32> = written.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![prop::PHY_ENABLED, prop::PHY_LORA_SF, prop::PHY_ENABLED],
            "the untouched bandwidth and coding rate stay home"
        );
        assert_eq!(written.first().unwrap().1, vec![0], "the radio goes down");
        assert_eq!(
            written.last().unwrap().1,
            vec![1],
            "and comes back up as it was"
        );
    }

    #[test]
    fn a_radio_left_off_stays_off_after_the_change() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                phy_enabled: Some(false),
                frequency_khz: Some(915_000),
                ..Default::default()
            },
            &[prop::PHY_FREQ],
        )
        .unwrap();
        assert_eq!(written.first().unwrap(), &(prop::PHY_ENABLED, vec![0]));
        assert_eq!(
            written.last().unwrap(),
            &(prop::PHY_ENABLED, vec![0]),
            "bringing the radio up would be a change nobody asked for"
        );
    }

    #[test]
    fn turning_the_radio_off_is_not_bracketed() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                phy_enabled: Some(false),
                ..Default::default()
            },
            &[prop::PHY_ENABLED],
        )
        .unwrap();
        assert_eq!(
            written,
            vec![(prop::PHY_ENABLED, vec![0])],
            "nothing is transmitting under a parameter that moved"
        );
    }

    #[test]
    fn an_altitude_takes_no_more_octets_than_it_needs() {
        for (meters, expected) in [
            (100i32, vec![0x64]),
            (-100, vec![0x9C]),
            (200, vec![0xC8, 0x00]),
            (-200, vec![0x38, 0xFF]),
            (100_000, vec![0xA0, 0x86, 0x01]),
            (-100_000, vec![0x60, 0x79, 0xFE]),
        ] {
            let written = dirty(
                UlcpDevicePropertiesRecord {
                    ident_altitude_m: Some(meters),
                    ..Default::default()
                },
                &[prop::IDENT_ALTITUDE],
            )
            .unwrap();
            assert_eq!(
                written,
                vec![(prop::IDENT_ALTITUDE, expected)],
                "{meters} m"
            );
        }
    }

    #[test]
    fn clearing_a_position_writes_the_clearing() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                ident_location: None,
                ident_altitude_m: None,
                ..Default::default()
            },
            &[prop::IDENT_LOCATION, prop::IDENT_ALTITUDE],
        )
        .unwrap();
        assert_eq!(
            written,
            vec![
                (prop::IDENT_LOCATION, Vec::new()),
                (prop::IDENT_ALTITUDE, Vec::new()),
            ],
            "an empty value is how a device is told it has no position"
        );
    }

    #[test]
    fn a_position_finer_than_the_encoding_allows_is_refused_here() {
        assert!(
            dirty(
                UlcpDevicePropertiesRecord {
                    ident_location: Some(vec![0; 8]),
                    ..Default::default()
                },
                &[prop::IDENT_LOCATION],
            )
            .is_err(),
            "the device would refuse it, costing a round trip that could only fail"
        );
    }

    #[test]
    fn a_read_only_property_is_not_something_to_apply() {
        assert!(
            dirty(
                UlcpDevicePropertiesRecord {
                    duty_cycle_now: Some(12),
                    ..Default::default()
                },
                &[prop::PHY_DUTY_NOW],
            )
            .is_err(),
            "a device's own report of its past hour is not the phone's to state"
        );
    }

    #[test]
    fn a_forwarding_policy_edit_travels_alone() {
        let written = dirty(
            UlcpDevicePropertiesRecord {
                repeater_enabled: Some(true),
                repeater_regions: Some(vec!["SJC".into()]),
                repeater_default_region: None,
                repeater_min_rssi_dbm: Some(-115),
                repeater_min_snr_db: None,
                ..Default::default()
            },
            &[prop::MAC_REPEATER_MIN_RSSI, prop::MAC_REPEATER_REGIONS],
        )
        .unwrap();
        assert_eq!(
            written.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            vec![prop::MAC_REPEATER_REGIONS, prop::MAC_REPEATER_MIN_RSSI],
            "the three untouched policy settings stay home"
        );
        assert_eq!(
            written[0].1,
            vec![3, b'S', b'J', b'C'],
            "regions pack the same way they do over the local link"
        );
    }

    // ─── Local management operations ─────────────────────────────────

    /// A `CMD_PROP_SET` request, decoded.
    fn set_request(bytes: &[u8]) -> (u8, u32, Vec<u8>) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropSet));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        (parsed.header.tid(), payload.key, payload.value.to_vec())
    }

    #[test]
    fn local_fetch_reports_values_and_refusals_alike() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let update = session
            .begin_property_fetch(vec![prop::DEV_NAME, prop::GNSS_ENABLED])
            .unwrap();
        assert_eq!(update.outbound_frames.len(), 2);

        let (name_tid, name_prop) = property_request(&update.outbound_frames[0]);
        assert_eq!(name_prop, prop::DEV_NAME);
        let (gnss_tid, gnss_prop) = property_request(&update.outbound_frames[1]);
        assert_eq!(gnss_prop, prop::GNSS_ENABLED);

        let mid = session
            .consume(property_response(name_tid, prop::DEV_NAME, b"Ridge"))
            .unwrap();
        assert!(
            mid.management_event.is_none(),
            "half-answered is not answered"
        );
        // The device has no receiver, so it refuses the second property.
        let done = session
            .consume(property_response(
                gnss_tid,
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::PROP_NOT_FOUND.0 as u8],
            ))
            .unwrap();
        let event = done.management_event.expect("both answers are in");
        assert_eq!(
            event.answers,
            vec![
                MobileMeshManagementAnswerRecord {
                    property_id: prop::DEV_NAME,
                    value: Some(b"Ridge".to_vec()),
                    status_code: None,
                },
                MobileMeshManagementAnswerRecord {
                    property_id: prop::GNSS_ENABLED,
                    value: None,
                    status_code: Some(umsh_ulcp::Status::PROP_NOT_FOUND.0),
                },
            ],
            "a refusal is that property's answer, not the operation's failure"
        );
        assert_eq!(event.status_code, None);
        assert_eq!(
            done.snapshot.device_name.as_deref(),
            Some("Ridge"),
            "what a fetch learns, the session snapshot learns too"
        );
    }

    #[test]
    fn local_fetch_asks_in_bounded_batches() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        // Nine properties: seven in the first round, two in the second.
        let properties: Vec<u32> = vec![
            prop::DEV_NAME,
            prop::PHY_ENABLED,
            prop::PHY_FREQ,
            prop::PHY_TX_POWER,
            prop::IDENT_MOBILE,
            prop::DEV_DISCOVERABLE,
            prop::MAC_REPEATER_ENABLED,
            prop::DEV_PEERS,
            prop::DEV_ADMINS,
        ];
        let update = session.begin_property_fetch(properties.clone()).unwrap();
        assert_eq!(
            update.outbound_frames.len(),
            usize::from(frame::TID_MAX),
            "a round asks for no more than the transaction space holds"
        );
        let second = answer_requests(&session, update.outbound_frames, commissionable_value);
        assert_eq!(second.outbound_frames.len(), 2);
        assert!(second.management_event.is_none());
        let done = answer_requests(&session, second.outbound_frames, commissionable_value);
        let event = done.management_event.expect("all nine answered");
        assert_eq!(event.answers.len(), properties.len());
    }

    #[test]
    fn local_writes_go_out_one_at_a_time_and_survive_a_refusal() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let update = session
            .begin_property_writes(vec![
                MobileMeshPropertyWriteRecord {
                    property_id: prop::DEV_NAME,
                    value: b"Saddle".to_vec(),
                },
                MobileMeshPropertyWriteRecord {
                    property_id: prop::IDENT_MOBILE,
                    value: vec![1],
                },
            ])
            .unwrap();
        assert_eq!(
            update.outbound_frames.len(),
            1,
            "order is load-bearing, so nothing is pipelined"
        );
        let (tid, property, value) = set_request(&update.outbound_frames[0]);
        assert_eq!(
            (property, value.as_slice()),
            (prop::DEV_NAME, &b"Saddle"[..])
        );

        // The device refuses the name; the run continues to the next write.
        let mid = session
            .consume(property_response(
                tid,
                prop::LAST_STATUS,
                &[umsh_ulcp::Status::INVALID_ARGUMENT.0 as u8],
            ))
            .unwrap();
        assert!(mid.management_event.is_none());
        assert_eq!(mid.outbound_frames.len(), 1);
        let (tid, property, value) = set_request(&mid.outbound_frames[0]);
        assert_eq!((property, value), (prop::IDENT_MOBILE, vec![1]));

        let done = session
            .consume(property_response(tid, prop::IDENT_MOBILE, &[1]))
            .unwrap();
        let event = done.management_event.expect("both writes answered");
        assert_eq!(
            event.answers,
            vec![
                MobileMeshManagementAnswerRecord {
                    property_id: prop::DEV_NAME,
                    value: None,
                    status_code: Some(umsh_ulcp::Status::INVALID_ARGUMENT.0),
                },
                MobileMeshManagementAnswerRecord {
                    property_id: prop::IDENT_MOBILE,
                    value: Some(vec![1]),
                    status_code: None,
                },
            ],
        );
    }

    #[test]
    fn local_save_reports_the_device_status() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let update = session.begin_save().unwrap();
        assert_eq!(update.outbound_frames.len(), 1);
        let parsed = Frame::parse(&update.outbound_frames[0]).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::Save));
        let done = session
            .consume(property_response(
                parsed.header.tid(),
                prop::LAST_STATUS,
                &[0],
            ))
            .unwrap();
        let event = done.management_event.expect("the save answered");
        assert!(event.answers.is_empty());
        assert_eq!(event.status_code, Some(0));
    }

    #[test]
    fn local_save_without_the_capability_is_already_done() {
        let session = MobileUlcpSession::new();
        let capabilities: Vec<u32> = commissionable_capabilities()
            .into_iter()
            .filter(|&capability| capability != cap::SAVE)
            .collect();
        let begin = session.begin(Some(vec![0xAA; 32])).unwrap();
        drive_reads(
            &session,
            begin.outbound_frames,
            move |property| match property {
                prop::CAPS => (property, encoded_capabilities(&capabilities)),
                prop::HOST_KEY => (property, vec![0xAA; 32]),
                _ => commissionable_value(property),
            },
        );

        let update = session.begin_save().unwrap();
        assert!(update.outbound_frames.is_empty());
        let event = update
            .management_event
            .expect("nothing to ask, so the operation is already complete");
        assert_eq!(event.status_code, None);
    }

    #[test]
    fn one_local_operation_at_a_time() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let update = session.begin_property_fetch(vec![prop::DEV_NAME]).unwrap();
        assert!(
            session.begin_property_fetch(vec![prop::DEV_NAME]).is_err(),
            "a second operation must wait for the first"
        );
        assert!(session.refresh().is_err(), "so must a refresh");

        let (tid, _) = property_request(&update.outbound_frames[0]);
        let done = session
            .consume(property_response(tid, prop::DEV_NAME, b"Ridge"))
            .unwrap();
        assert!(done.management_event.is_some());
        assert!(
            session.begin_property_fetch(vec![prop::DEV_NAME]).is_ok(),
            "and once it completes, the next may run"
        );
    }

    #[test]
    fn an_unsolicited_value_is_carried_out_verbatim() {
        let session = MobileUlcpSession::new();
        attach_commissionable(&session, Some(vec![0xAA; 32]), vec![0xAA; 32]);

        let update = session
            .consume(property_response(
                frame::TID_UNSOLICITED,
                prop::IDENT_MOBILE,
                &[1],
            ))
            .unwrap();
        assert_eq!(
            update.pushed_properties,
            vec![UlcpPropertyPushRecord {
                property_id: prop::IDENT_MOBILE,
                value: vec![1],
            }],
            "a push reaches whoever caches values by number, not just the snapshot"
        );
    }

    #[test]
    fn a_lazy_administrative_attach_reads_only_what_attaching_requires() {
        let session = MobileUlcpSession::administrative_lazy();
        let begin = session.begin(None).unwrap();
        let mut asked = Vec::new();
        let mut pending = begin.outbound_frames;
        let mut last = None;
        while !pending.is_empty() {
            let update = answer_requests(&session, pending.clone(), |property| match property {
                // Someone else's radio, which an administrative session
                // attaches to anyway.
                prop::HOST_KEY => (property, vec![0xBB; 32]),
                _ => commissionable_value(property),
            });
            for request in &pending {
                asked.push(property_request(request).1);
            }
            pending = update.outbound_frames.clone();
            last = Some(update);
        }
        let update = last.unwrap();
        assert_eq!(update.snapshot.phase, UlcpSessionPhase::Attached);
        assert_eq!(
            asked.len(),
            11,
            "the seven-property preamble and the four the sync reduction insists on"
        );
        assert!(
            !asked.contains(&prop::MAC_REPEATER_ENABLED),
            "the device domain is left to be read on demand"
        );

        // And reading on demand works.
        let fetch = session
            .begin_property_fetch(vec![prop::MAC_REPEATER_ENABLED])
            .unwrap();
        let (tid, _) = property_request(&fetch.outbound_frames[0]);
        let done = session
            .consume(property_response(tid, prop::MAC_REPEATER_ENABLED, &[0]))
            .unwrap();
        assert!(done.management_event.is_some());
    }

    #[test]
    fn radio_presets_cross_the_bindings_whole() {
        let presets = ulcp_radio_presets();
        assert_eq!(presets.len(), umsh_ulcp::profiles::VETTED.len());
        assert_eq!(presets[0].id, umsh_ulcp::profiles::DEFAULT.id);

        // Every field of every vetted profile, rather than one profile's
        // numbers written out again. A field dropped or crossed onto the
        // wrong one is what this conversion can get wrong; which entry holds
        // the default, and what it is tuned to, belongs to the profile table.
        for (preset, profile) in presets.iter().zip(umsh_ulcp::profiles::VETTED) {
            assert_eq!(preset.id, profile.id);
            assert_eq!(preset.name, profile.name);
            assert_eq!(preset.frequency_khz, profile.freq_khz);
            assert_eq!(preset.bandwidth_hz, profile.bw_hz);
            assert_eq!(preset.spreading_factor, profile.sf);
            assert_eq!(preset.coding_rate_denom, profile.cr_denom);
            assert_eq!(preset.transmit_power_dbm, profile.tx_power_dbm);
            assert_eq!(preset.duty_cycle_limit, profile.duty_limit);
            assert_eq!(preset.sync_word, profile.sync_word);
            assert_eq!(preset.tx_preamble_symbols, profile.tx_preamble_symbols);
        }

        // A profile with no vetted power crosses as an absent one
        // rather than a zero.
        assert!(
            presets
                .iter()
                .any(|preset| preset.transmit_power_dbm.is_none()),
            "the optional power is reachable from the app"
        );
        assert_eq!(
            ulcp_supported_bandwidths_hz(),
            umsh_ulcp::profiles::SUPPORTED_BANDWIDTHS_HZ
        );
    }
}
