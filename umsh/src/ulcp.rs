//! Host-side client for the UMSH Local Control Protocol (ULCP).
//!
//! [`UlcpDevice`] drives a device over a frame-oriented [`FrameLink`], and
//! exposes the link as a [`umsh_hal::Radio`] so the host can run the
//! full MAC/node stack with the device acting purely as the PHY.
//!
//! The wire format lives in [`umsh_ulcp`] (re-exported as
//! [`crate::ulcp_wire`]); this module owns the host-side session
//! behavior: the reset/configure handshake, request/response
//! transactions, and queueing of frames that arrive while a command is
//! in flight.
//!
//! See `docs/protocol/src/ulcp.md` and the chapters under it for the
//! protocol.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use umsh_core::{ChannelKey, RegionCode};
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_hal::{CadPolicy, Radio, RxBuffered, RxInfo, RxOrigin, Snr, TxError, TxOptions};
use umsh_ulcp::Status;
use umsh_ulcp::airtime::lora_airtime_ms;
use umsh_ulcp::alert::AlertState;
use umsh_ulcp::announce::Announcement;
use umsh_ulcp::battery::BatteryStatus;
use umsh_ulcp::frame::{
    self, Cmd, Frame, SessionResetReason, StreamPayload, TID_UNSOLICITED, parse_session_reset,
};
use umsh_ulcp::gnss::GnssSnapshot;
use umsh_ulcp::hdlc;
use umsh_ulcp::host::{PropertyNotification, PropertyNotificationKind, TidAllocator};
use umsh_ulcp::i2c;
use umsh_ulcp::ids::{self, cap, prop, stream};
use umsh_ulcp::items;
use umsh_ulcp::meta::{
    BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED, RX_FLAG_SELF_TX, RxMeta, TX_FLAG_NOCCA, TxMeta,
};
use umsh_ulcp::pui;

/// Capacity of the HDLC reassembly buffer (unescaped frame + FCS).
const WIRE_BUF: usize = 1024;
/// Size of one read from the underlying stream.
const READ_CHUNK: usize = 256;
/// Received frames buffered while a command transaction is in flight.
/// The oldest frame is dropped on overflow, matching radio-FIFO
/// overrun semantics.
const RX_QUEUE_DEPTH: usize = 8;
/// Stale command responses retained before the oldest is dropped.
const RESPONSE_QUEUE_DEPTH: usize = 8;
/// Unsolicited property notifications retained before the oldest is
/// dropped.
const PROP_EVENT_DEPTH: usize = 16;
/// Delay between transmit retries while CCA reports a busy channel.
const CCA_RETRY_DELAY: Duration = Duration::from_millis(10);
/// Loss-of-state notices one attach exchange absorbs before giving up on
/// the device: a boot and an attach are one or two each, and a device
/// announcing resets without end is not one to attach to.
const ATTACH_NOTICE_LIMIT: usize = 4;
/// The frame ceiling assumed when a device does not report a usable
/// `PROP_PHY_MTU`: the largest LoRa payload there is. A frame over the
/// device's real ceiling is refused per transmit, which costs that frame
/// and nothing else.
const FALLBACK_MTU: usize = 255;

/// The frame airtime assumed when the device's cannot be learned and
/// nothing better is cached: the slowest LoRa settings there are (SF12,
/// 125 kHz, CR 4/8) carrying a whole frame behind the 32-symbol preamble
/// UMSH firmware sends. A transmit deadline built on it is long rather
/// than short, and a long deadline only waits; a short one fails a frame
/// that is still on the air.
fn conservative_t_frame_ms(max_frame_size: usize) -> u32 {
    let frame = if max_frame_size == 0 {
        FALLBACK_MTU
    } else {
        max_frame_size
    };
    umsh_ulcp::airtime::lora_airtime_ms_with_preamble(12, 125_000, 8, frame, 32).max(1)
}

/// Run one attach exchange, absorbing the loss-of-state notices a device
/// sends while it is booting or being attached to.
///
/// Spec §`CMD_SESSION_RESET`: the reason is diagnostic and a host's
/// obligation is the same for every value—resynchronize—which is what
/// an attach is about to do anyway. A reset notice says the device
/// booted, which is what the boot status records. Neither means this
/// attach failed; the exchange the notice cut short is simply asked
/// again.
macro_rules! absorbing_attach_notices {
    ($device:expr, $exchange:expr) => {{
        let mut absorbed = 0;
        loop {
            match $exchange.await {
                Err(error)
                    if absorbed < ATTACH_NOTICE_LIMIT && $device.absorb_attach_notice(&error) =>
                {
                    absorbed += 1;
                }
                result => break result,
            }
        }
    }};
}

#[derive(Debug)]
pub enum UlcpError {
    Io(io::Error),
    /// The stream reached end-of-file; the device link is gone.
    Disconnected,
    /// The device violated the ULCP.
    Protocol(&'static str),
    /// The device reported a failure status for a command.
    Status(Status),
    /// The device reset outside of an initialization handshake, losing
    /// its configuration. The radio must be re-initialized.
    UnexpectedReset(Status),
    /// The device discarded session state under us: every session-scoped
    /// property is back at its default, and whatever this host had
    /// established there is gone. The session must be set up again.
    SessionReset(SessionResetReason),
    /// The frame exceeds the device's advertised MTU.
    FrameTooLarge(usize),
    /// The device did not answer a command in time.
    Timeout,
    /// A non-stream transport failed.
    Transport(String),
    /// A host-domain write was attempted on an administrative handle.
    /// Administering a device configures the device; it does not claim
    /// the device (see [`AttachMode`]).
    AdministrativeAttach,
}

impl core::fmt::Display for UlcpError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Disconnected => write!(formatter, "ULCP link disconnected"),
            Self::Protocol(message) => write!(formatter, "protocol error: {message}"),
            Self::Status(status) => write!(formatter, "device reported {status:?}"),
            Self::UnexpectedReset(status) => {
                write!(formatter, "device reset unexpectedly ({status:?})")
            }
            Self::SessionReset(reason) => {
                write!(formatter, "device reset the session ({reason:?})")
            }
            Self::FrameTooLarge(len) => write!(formatter, "frame too large: {len} bytes"),
            Self::Timeout => write!(formatter, "timed out waiting for device response"),
            Self::Transport(message) => write!(formatter, "transport error: {message}"),
            Self::AdministrativeAttach => write!(
                formatter,
                "host-domain writes need a tethered attach, not an administrative one"
            ),
        }
    }
}

impl UlcpError {
    /// Whether the transport underneath the handle is gone, as opposed to
    /// the device having answered badly or slowly.
    ///
    /// [`Timeout`](Self::Timeout) is deliberately not included: it is the
    /// device's deadline, not the link's, and a link that has actually
    /// died reports so through the receive side while the wait is still
    /// in progress. Over the mesh, [`Transport`](Self::Transport) carries
    /// a failed *exchange* rather than a dead wire, which is why a handle
    /// consults its own attach mode before believing this.
    pub fn is_link_lost(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Io(_) | Self::Transport(_))
    }
}

impl std::error::Error for UlcpError {}

impl From<io::Error> for UlcpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// RF and session configuration applied during initialization.
#[derive(Clone, Debug)]
pub struct UlcpDeviceConfig {
    /// Center frequency in kHz (`PROP_PHY_FREQ`).
    pub freq_khz: u32,
    /// LoRa bandwidth in Hz (`PROP_PHY_LORA_BW`).
    pub bandwidth_hz: u32,
    /// LoRa spreading factor, 5-12 (`PROP_PHY_LORA_SF`).
    pub spreading_factor: u8,
    /// LoRa coding-rate denominator: 5 for 4/5 through 8 for 4/8
    /// (`PROP_PHY_LORA_CR`).
    pub coding_rate_denom: u8,
    /// Transmit power in dBm (`PROP_PHY_TX_POWER`).
    pub tx_power_dbm: i8,
    /// SX126x-style 16-bit sync word (`PROP_PHY_LORA_SW`).
    pub sync_word: u16,
    /// How long to wait for the device to answer one command. Transmit
    /// confirmations allow the largest of this, three seconds, and twice
    /// the device's current maximum frame airtime.
    pub response_timeout: Duration,
}

impl UlcpDeviceConfig {
    /// Configuration with the given RF link parameters, 0 dBm transmit
    /// power, the suggested default sync word, and a 2-second response
    /// timeout.
    pub fn new(
        freq_khz: u32,
        bandwidth_hz: u32,
        spreading_factor: u8,
        coding_rate_denom: u8,
    ) -> Self {
        Self {
            freq_khz,
            bandwidth_hz,
            spreading_factor,
            coding_rate_denom,
            tx_power_dbm: 0,
            sync_word: umsh_ulcp::profiles::DEFAULT_SYNC_WORD,
            response_timeout: Duration::from_secs(2),
        }
    }
}

struct RxPacket {
    data: Vec<u8>,
    meta: RxMeta,
    /// Raw trailing metadata bytes, preserving the full protocol's
    /// buffered-frame extension for callers that decode it.
    raw_meta: Vec<u8>,
}

/// Which device-to-host property command carried a payload.
type ResponseKind = PropertyNotificationKind;

/// One position in a `CMD_PROP_ARE`: the property and the value the
/// device reported, or the status that stands in its place.
pub type MultiValue = Result<(u32, Vec<u8>), Status>;

/// A property notification received with a non-zero TID (a command
/// response).
struct Response {
    tid: u8,
    kind: ResponseKind,
    key: u32,
    value: Vec<u8>,
}

#[derive(Clone, Copy)]
enum PropResponsePolicy {
    Value,
    StatusOnly,
}

/// One I2C bus a device lets a host drive, as `PROP_I2C_BUSES` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2cBus {
    pub bus: u8,
    /// The clock the device drives the bus at.
    pub speed_khz: u16,
    /// The largest sum of write-data and read-length octets one transfer
    /// may carry.
    pub max_data: u16,
    /// The largest operation count one transfer may carry.
    pub max_ops: u8,
    /// Display text: the controller and its pins, typically.
    pub name: String,
}

/// One peripheral the firmware knows to be on a bus, as
/// `PROP_I2C_DEVICES` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2cPeripheral {
    pub bus: u8,
    /// The 7-bit address.
    pub addr: u8,
    pub name: String,
}

/// An unsolicited property notification (TID zero) retained for the
/// caller: device state can change for reasons the host did not initiate,
/// and publication of the new authoritative value is how the protocol
/// reports that. Multi-value payloads are in digest form and never
/// contain key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropEvent {
    /// `CMD_PROP_IS`: the property now has this complete value.
    Is { key: u32, value: Vec<u8> },
    /// `CMD_PROP_INSERTED`: an item was added to a multi-value property.
    Inserted { key: u32, digest: Vec<u8> },
    /// `CMD_PROP_REMOVED`: an item was removed from a multi-value
    /// property.
    Removed { key: u32, digest: Vec<u8> },
}

/// Direction of a traced ULCP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceDirection {
    HostToDevice,
    DeviceToHost,
}

impl core::fmt::Display for TraceDirection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::HostToDevice => "host→device",
            Self::DeviceToHost => "device→host",
        })
    }
}

/// Sink for per-frame trace lines (see
/// [`UlcpDevice::set_frame_trace`]).
pub type FrameTrace = Box<dyn FnMut(TraceDirection, &str) + Send>;

/// How the device reported a successful `CMD_RESTORE`. Both forms leave
/// the device in the same configuration; they differ only in reporting and
/// session-state handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreCompletion {
    /// Update form: values reverted in place (each change published as
    /// an unsolicited update; see [`UlcpDevice::pop_prop_event`]).
    Updated,
    /// Reset form (`STATUS_RESET_RESTORED`): the device also reset its
    /// protocol session state. Cached property views are invalid;
    /// saved properties hold their saved values.
    Reset,
}

/// Verdict of comparing `PROP_HOST_KEY` against this host's identity
/// (spec §Attach, Detach, and Synchronization, step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOwnership {
    /// The device is configured for this host: queued traffic and
    /// provisioning are ours to use and drain.
    Ours,
    /// No host identity is configured.
    Unclaimed,
    /// Another host has taken the radio over; the queue and
    /// provisioning belong to that identity and must not be treated as
    /// ours without deliberately replacing it (see
    /// [`UlcpDevice::provision`]).
    OtherHost([u8; 32]),
    /// The device implements host filtering, but its `PROP_HOST_KEY`
    /// could not be read: refused, or not a key this host can compare.
    /// Nothing here is known to be ours, so treat it as another host's.
    Unknown,
    /// The device does not implement host filtering (minimal protocol
    /// only).
    Unsupported,
}

/// `PROP_SAVED`: what the device reports about its stored snapshot.
///
/// The two failure values are the point of the property. An unattended
/// repeater that comes back on stale configuration, or on none at all,
/// looks identical to a healthy one from the outside—this is how a
/// host that does eventually attach finds out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedSnapshot {
    /// Nothing is saved.
    None,
    /// The newest saved generation is in effect.
    Current,
    /// A newer generation was rejected at boot and an older one is in
    /// effect: the device is working, on stale configuration. Re-save to
    /// clear it.
    Fallback,
    /// A snapshot exists but no generation could be read; the device
    /// booted with post-reset defaults.
    Unreadable,
    /// A code this host does not assign, kept as reported.
    Other(u8),
}

impl SavedSnapshot {
    /// Read the value's first octet; anything after it is the sender's
    /// business. `None` only for an empty value.
    fn from_octet(value: &[u8]) -> Option<Self> {
        Some(match *value.first()? {
            ids::saved::NONE => Self::None,
            ids::saved::CURRENT => Self::Current,
            ids::saved::FALLBACK => Self::Fallback,
            ids::saved::UNREADABLE => Self::Unreadable,
            other => Self::Other(other),
        })
    }

    /// Whether a saved snapshot is known to be in effect, in either
    /// generation. An unassigned code does not say so.
    pub fn is_saved(self) -> bool {
        matches!(self, Self::Current | Self::Fallback)
    }
}

/// One `PROP_HOST_RX_FILTERS` entry as a device reported it.
///
/// [`items::Filter`] is the strict form a device validates writes
/// against, and stays strict. A host reading the table back has no such
/// job: an entry it cannot interpret is still an entry the device holds,
/// and dropping it—or refusing the whole table over it—would misreport
/// what the device filters on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportedFilter {
    /// An entry this host understands.
    Known(items::Filter),
    /// An entry with a `FILTER_TYPE` this host does not assign, or a
    /// value whose length does not match its type, kept as reported.
    Unknown { filter_type: u8, value: Vec<u8> },
}

impl ReportedFilter {
    /// Read one filter item (without its length prefix). `None` only for
    /// an empty item, which names no type at all.
    pub fn decode(item: &[u8]) -> Option<Self> {
        let [filter_type, value @ ..] = item else {
            return None;
        };
        Some(match items::Filter::decode(item) {
            Ok(filter) => Self::Known(filter),
            Err(_) => Self::Unknown {
                filter_type: *filter_type,
                value: value.to_vec(),
            },
        })
    }

    /// The strict filter, when this host understands the entry.
    pub fn known(&self) -> Option<&items::Filter> {
        match self {
            Self::Known(filter) => Some(filter),
            Self::Unknown { .. } => None,
        }
    }
}

/// `PROP_ALERT` as a device reported it.
///
/// [`AlertState`] names the codes this host knows. A device newer than it
/// may report one it does not, which is still an answer—the device is
/// doing *something* conspicuous—and is kept rather than refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportedAlert {
    Known(AlertState),
    /// An unassigned alert code, as reported.
    Unknown(u32),
}

impl ReportedAlert {
    fn from_code(code: u32) -> Self {
        match AlertState::from_code(code) {
            Some(state) => Self::Known(state),
            None => Self::Unknown(code),
        }
    }
}

/// Device state gathered by [`UlcpDevice::sync`]: the spec's
/// post-attach synchronization procedure. Fields whose capability the
/// device does not advertise are `None`, and so is any field the device
/// refused or answered with a value this host could not read—one
/// property is never a reason to lose the rest. Multi-value properties
/// are the digest forms and never contain key material.
#[derive(Clone, Debug)]
pub struct DeviceSync {
    /// Retained `PROP_LAST_STATUS`.
    pub last_status: Status,
    /// `last_status` was a reset code: the device has reset since the
    /// last host command, so state not restored from a saved snapshot
    /// (notably queue contents) has been lost.
    pub reset_since_last_contact: bool,
    /// Advertised `PROP_CAPS`.
    pub capabilities: Vec<u32>,
    /// Whether the queued data and provisioning belong to this host.
    pub ownership: HostOwnership,
    /// The configured host identity, when one exists.
    pub host_key: Option<[u8; 32]>,
    /// `PROP_PHY_ENABLED`—with a restored snapshot the PHY may
    /// already be up.
    pub phy_enabled: Option<bool>,
    /// `PROP_PHY_FREQ` in kHz.
    pub freq_khz: Option<u32>,
    /// `PROP_DEV_NAME`.
    pub device_name: Option<String>,
    /// `PROP_SAVED` (`CAP_SAVE`).
    pub saved: Option<SavedSnapshot>,
    /// `PROP_HOST_RX_QUEUE_COUNT` (`CAP_HOST_RX_QUEUE`).
    pub queue_count: Option<u16>,
    /// `PROP_HOST_RX_QUEUE_DROPPED` (`CAP_HOST_RX_QUEUE`).
    pub queue_dropped: Option<u32>,
    /// `PROP_HOST_RX_FILTERS` (`CAP_HOST_FILTER`).
    pub filters: Option<Vec<ReportedFilter>>,
    /// Derived channel identifiers of `PROP_HOST_CHANNEL_KEYS`
    /// (`CAP_HOST_KEYS`).
    pub host_channel_ids: Option<Vec<[u8; items::CHANNEL_IDENTIFIER_LEN]>>,
    /// Provisioned peer public keys of `PROP_HOST_PEER_KEYS`
    /// (`CAP_HOST_KEYS`).
    pub host_peer_keys: Option<Vec<[u8; items::PUBLIC_KEY_LEN]>>,
    /// `PROP_HOST_AUTO_ACK` (`CAP_HOST_AUTO_ACK`).
    pub auto_ack: Option<bool>,
    /// The device identity public key (`CAP_DEV_IDENTITY`), when one
    /// is configured.
    pub dev_key: Option<[u8; 32]>,
}

impl DeviceSync {
    /// Whether the device advertised this capability code.
    pub fn has_capability(&self, capability: u32) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// The repeater forwarding policy of a `CAP_REPEATER` device.
///
/// The four gates are independent and are written separately, so this is
/// a report rather than a transaction: reading it back after a partial
/// write shows exactly what the device holds.
///
/// Like every multi-property report here ([`MeshCoreForwarding`],
/// [`DeviceTime`], [`GnssStatus`], [`AdvertPolicy`]), each field is
/// `None` when the device did not report that member—refused it, or
/// answered with a value this host cannot read—and the rest stand. A
/// member that is optional in its own right is `Option<Option<T>>`: the
/// outer level says whether it was reported, the inner one what it is,
/// the same shape [`decode_opt_i16`] returns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepeaterPolicy {
    /// `PROP_MAC_REPEATER_ENABLED`: whether the on-board node forwards at
    /// all. The remaining fields are inert while this is false.
    pub enabled: Option<bool>,
    /// `PROP_MAC_REPEATER_REGIONS`: which region-tagged floods to forward,
    /// as the strings an operator wrote—a short code, a name, or a
    /// literal `0x1234`. Empty imposes no regional restriction. The
    /// device derives the 2-octet codes the filter actually compares;
    /// pass a name through [`RegionCode::from_str`] to see them.
    pub regions: Option<Vec<String>>,
    /// `PROP_MAC_REPEATER_DEFAULT_REGION`: the tag inserted into an
    /// untagged flood before forwarding it. `Some(None)` forwards
    /// untagged.
    pub default_region: Option<Option<RegionCode>>,
    /// `PROP_MAC_REPEATER_MIN_RSSI` in dBm: floor below which a frame is
    /// not worth relaying. `Some(None)` accepts any.
    pub min_rssi: Option<Option<i16>>,
    /// `PROP_MAC_REPEATER_MIN_SNR` in dB. `Some(None)` accepts any.
    pub min_snr: Option<Option<i8>>,
}

/// How MeshCore transport codes gate flood forwarding
/// (`PROP_MESHCORE_REGION_POLICY`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MeshCoreRegionPolicy {
    /// Unscoped floods, and scoped floods for a configured region.
    #[default]
    Open,
    /// Only scoped floods for a configured region.
    ScopedOnly,
    /// Every flood, whatever its scope.
    Ignore,
    /// A code this host does not assign, kept as reported. Never parsed
    /// from a name: a host writes only the policies it knows.
    Other(u8),
}

impl MeshCoreRegionPolicy {
    /// The policy a wire value names, or `None` for an unassigned one.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            ids::meshcore_region_policy::OPEN => Some(Self::Open),
            ids::meshcore_region_policy::SCOPED_ONLY => Some(Self::ScopedOnly),
            ids::meshcore_region_policy::IGNORE => Some(Self::Ignore),
            _ => None,
        }
    }

    /// Tolerant conversion, for a reader: an unassigned code is
    /// [`Self::Other`] rather than an error.
    pub const fn from_wire(value: u8) -> Self {
        match Self::from_u8(value) {
            Some(policy) => policy,
            None => Self::Other(value),
        }
    }

    /// The wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Open => ids::meshcore_region_policy::OPEN,
            Self::ScopedOnly => ids::meshcore_region_policy::SCOPED_ONLY,
            Self::Ignore => ids::meshcore_region_policy::IGNORE,
            Self::Other(code) => code,
        }
    }

    /// The name the CLI reads and prints; `unknown` for an unassigned
    /// code, whose number [`Display`](core::fmt::Display) adds.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ScopedOnly => "scoped",
            Self::Ignore => "ignore",
            Self::Other(_) => "unknown",
        }
    }
}

impl core::fmt::Display for MeshCoreRegionPolicy {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Other(code) => write!(formatter, "unknown ({code})"),
            policy => formatter.write_str(policy.name()),
        }
    }
}

impl core::str::FromStr for MeshCoreRegionPolicy {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, ()> {
        [Self::Open, Self::ScopedOnly, Self::Ignore]
            .into_iter()
            .find(|policy| policy.name().eq_ignore_ascii_case(name))
            .ok_or(())
    }
}

/// A `CAP_MESHCORE_FORWARDER` device's MeshCore settings. A field is
/// `None` when the device did not report it (see [`RepeaterPolicy`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshCoreForwarding {
    /// `PROP_MESHCORE_FORWARDING_ENABLED`. Independent of
    /// [`RepeaterPolicy::enabled`].
    pub enabled: Option<bool>,
    /// `PROP_MESHCORE_REGION_POLICY`.
    pub region_policy: Option<MeshCoreRegionPolicy>,
    /// `PROP_MESHCORE_REGIONS`: MeshCore region names, without the `#`
    /// their keys derive under.
    pub regions: Option<Vec<String>>,
}

/// Whether a device identity whose public key is `dev_key` can forward
/// MeshCore traffic. MeshCore reserves keys beginning `0x00` and `0xFF`.
pub fn meshcore_identity_allowed(dev_key: &[u8; 32]) -> bool {
    ids::meshcore_identity_allowed(dev_key[0])
}

/// The wall clock of a `CAP_TIME` device. A field is `None` when the
/// device did not report it (see [`RepeaterPolicy`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTime {
    /// `PROP_TIME`: Unix seconds, or `Some(None)` when the device does not
    /// know what time it is. Unsigned, so the encoding is wrap-free into
    /// 2106.
    pub epoch: Option<Option<u32>>,
    /// `PROP_TZ_RULE`: the zone, as a POSIX TZ rule. Always set—where
    /// the device is meant to be is known even when the time is not.
    pub tz_rule: Option<String>,
    /// `PROP_TIME_24H`: whether a clock the device shows writes hours
    /// from 0 to 23.
    pub time_24h: Option<bool>,
}

/// Everything a `CAP_GNSS` device reports about positioning: the switch,
/// the current fix, and the policy that governs what is done with it.
///
/// A report rather than a transaction, like [`RepeaterPolicy`]: the
/// properties are written separately, and reading this back after a
/// partial write shows exactly what the device holds. A field is `None`
/// when the device did not report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GnssStatus {
    /// `PROP_GNSS_ENABLED`: whether the receiver is powered. Everything in
    /// `fix` reads as searching while this is false.
    pub enabled: Option<bool>,
    /// The five positioning telemetry properties, folded into one value.
    /// A member the device did not report keeps its
    /// [`GnssSnapshot::SEARCHING`] reading—nothing is known about it,
    /// which is what searching says.
    pub fix: GnssSnapshot,
    /// `PROP_GNSS_IDENT_UPDATE`: whether fixes refresh the advertised
    /// node identity's location.
    pub ident_update: Option<bool>,
    /// `PROP_GNSS_IDENT_PRECISION`: location bytes the advertised
    /// position is clamped to.
    pub ident_precision: Option<u8>,
    /// `PROP_GNSS_TIME_TRUST`: whether receiver-derived time may set the
    /// wall clock.
    pub time_trust: Option<bool>,
}

/// What a device announces without being asked. A field is `None` when
/// the device did not report it (see [`RepeaterPolicy`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvertPolicy {
    /// `PROP_ADVERT_INTERVAL`: seconds between signed identity
    /// advertisements, 0 for none.
    pub advert_interval_s: Option<u32>,
    /// `PROP_BEACON_INTERVAL`: seconds between empty beacons, 0 for none.
    pub beacon_interval_s: Option<u32>,
    /// `PROP_STARTUP_BEACON`: whether one beacon goes out at bring-up.
    pub startup_beacon: Option<bool>,
}

/// The host-domain state [`UlcpDevice::provision`] establishes on
/// the device.
#[derive(Clone, Debug)]
pub struct HostProvisioning {
    /// The host identity (`PROP_HOST_KEY`). Provisioning a key
    /// different from the configured one replaces the host domain
    /// (spec §Host Replacement).
    pub host_key: [u8; 32],
    /// Desired explicit receive filter set (`PROP_HOST_RX_FILTERS`).
    pub filters: Vec<items::Filter>,
    /// Desired channel keys (`PROP_HOST_CHANNEL_KEYS`).
    pub channel_keys: Vec<[u8; items::CHANNEL_KEY_LEN]>,
    /// Desired peer key entries (`PROP_HOST_PEER_KEYS`). Reconciled by
    /// public-key membership: an entry whose public key the device
    /// already reports is *not* re-sent, so rotated key material for
    /// an existing peer must be re-inserted explicitly (insert
    /// replaces).
    pub peer_keys: Vec<items::PeerKeyEntry>,
    /// Desired `PROP_HOST_AUTO_ACK`.
    pub auto_ack: bool,
}

/// What [`UlcpDevice::provision`] wrote.
///
/// A count of writes issued, not of differences found: provisioning
/// asserts the whole host domain unconditionally, so most of these are
/// non-zero on every call whether or not the device already agreed. Only
/// `host_replaced` and `peers_removed` report an observed difference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProvisionReport {
    /// `PROP_HOST_KEY` differed, so the device discarded the previous
    /// host domain and every table below landed on an empty one.
    pub host_replaced: bool,
    /// The filter table was written whole.
    pub filters_replaced: bool,
    /// The channel-key table was written whole, because the device held
    /// an identifier we have no key for and the remove selector is the
    /// key itself.
    pub channels_replaced: bool,
    /// Channel keys inserted individually.
    pub channels_inserted: usize,
    /// Peer entries inserted.
    pub peers_inserted: usize,
    /// Peer entries removed because the desired set omits them.
    pub peers_removed: usize,
    /// `PROP_HOST_AUTO_ACK` was written.
    pub auto_ack_changed: bool,
}

/// A cancel-safe, frame-oriented ULCP transport.
#[allow(async_fn_in_trait)]
pub trait FrameLink {
    /// Send one complete ULCP frame.
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError>;

    /// Poll for the next complete ULCP frame.
    ///
    /// Implementations keep all partial state in `self`, so cancellation cannot
    /// discard a partial frame or unread bytes following a completed frame.
    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>>;

    /// Receive the next complete ULCP frame.
    async fn recv_frame(&mut self) -> Result<Vec<u8>, UlcpError> {
        core::future::poll_fn(|cx| self.poll_recv_frame(cx)).await
    }
}

/// HDLC-Lite framing over a reliable asynchronous byte stream.
pub struct SerialFrameLink<IO> {
    io: IO,
    decoder: hdlc::Decoder<WIRE_BUF>,
    read_buf: [u8; READ_CHUNK],
    read_pos: usize,
    read_len: usize,
}

impl<IO> SerialFrameLink<IO> {
    /// Wrap a byte stream in ULCP HDLC framing.
    pub fn new(io: IO) -> Self {
        Self {
            io,
            decoder: hdlc::Decoder::new(),
            read_buf: [0; READ_CHUNK],
            read_pos: 0,
            read_len: 0,
        }
    }

    /// Recover the underlying byte stream.
    pub fn into_inner(self) -> IO {
        self.io
    }
}

impl<IO> FrameLink for SerialFrameLink<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        let mut wire = vec![0u8; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut wire).expect("buffer sized with max_encoded_len");
        self.io.write_all(&wire[..len]).await?;
        self.io.flush().await?;
        Ok(())
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        loop {
            while self.read_pos < self.read_len {
                let byte = self.read_buf[self.read_pos];
                self.read_pos += 1;
                if let Some(Ok(frame)) = self.decoder.push(byte) {
                    return core::task::Poll::Ready(Ok(frame.to_vec()));
                }
            }

            self.read_pos = 0;
            self.read_len = 0;
            let mut read_buf = ReadBuf::new(&mut self.read_buf);
            match core::pin::Pin::new(&mut self.io).poll_read(cx, &mut read_buf) {
                core::task::Poll::Ready(Ok(())) => {
                    self.read_len = read_buf.filled().len();
                    if self.read_len == 0 {
                        return core::task::Poll::Ready(Err(UlcpError::Disconnected));
                    }
                }
                core::task::Poll::Ready(Err(error)) => {
                    return core::task::Poll::Ready(Err(UlcpError::Io(error)));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }
}

/// BLE-specific link configuration.
#[cfg(feature = "ble-radio")]
#[derive(Clone, Copy, Debug)]
pub struct BleFrameLinkConfig {
    /// Frame bytes per GATT segment, excluding the SAR header.
    pub segment_payload: usize,
    /// How long discovery may run before reporting no matching peripheral.
    pub discovery_timeout: Duration,
    /// Maximum duration for each CoreBluetooth/BlueZ link operation.
    pub operation_timeout: Duration,
    /// Maximum duration for the protected Frame-Out subscription. Unlike an
    /// ordinary GATT operation, this may include OS-mediated pairing and human
    /// PIN entry.
    pub pairing_timeout: Duration,
    /// How long to wait for the adapter to be powered on before scanning.
    ///
    /// Zero (the default) refuses a powered-off adapter at once, which is
    /// the right answer for a first connection: a scan against a radio
    /// that is switched off can only time out. A link being recovered
    /// after the machine slept, or after Bluetooth was toggled, wants
    /// to wait instead—the adapter is the thing that is about to come
    /// back.
    pub power_on_timeout: Duration,
}

#[cfg(feature = "ble-radio")]
impl Default for BleFrameLinkConfig {
    fn default() -> Self {
        Self {
            // Correct for the mandatory ATT_MTU 23 floor on every platform.
            segment_payload: 19,
            discovery_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(10),
            pairing_timeout: Duration::from_secs(90),
            power_on_timeout: Duration::ZERO,
        }
    }
}

#[cfg(feature = "ble-radio")]
impl BleFrameLinkConfig {
    fn validate(&self) -> Result<(), UlcpError> {
        if !(1..=511).contains(&self.segment_payload) {
            return Err(UlcpError::Protocol(
                "BLE segment payload must be in 1..=511",
            ));
        }
        if self.discovery_timeout.is_zero()
            || self.operation_timeout.is_zero()
            || self.pairing_timeout.is_zero()
        {
            return Err(UlcpError::Protocol(
                "BLE discovery, operation, and pairing timeouts must be nonzero",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "ble-radio")]
struct BleNotificationReceiver {
    notifications: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reassembler: umsh_ulcp::gatt::Reassembler<{ umsh_ulcp::gatt::MAX_FRAME }>,
}

#[cfg(feature = "ble-radio")]
impl BleNotificationReceiver {
    fn new(notifications: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            notifications,
            reassembler: umsh_ulcp::gatt::Reassembler::new(),
        }
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        loop {
            match self.notifications.poll_recv(cx) {
                core::task::Poll::Ready(Some(segment)) => {
                    if let Some(Ok(frame)) = self.reassembler.push(&segment) {
                        return core::task::Poll::Ready(Ok(frame.to_vec()));
                    }
                    // Transport-level malformed/oversize segments are dropped.
                }
                core::task::Poll::Ready(None) => {
                    self.reassembler.reset();
                    return core::task::Poll::Ready(Err(UlcpError::Disconnected));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }
}

/// One ULCP GATT Service peripheral seen during a
/// [`BleFrameLink::scan`].
#[cfg(feature = "ble-radio")]
#[derive(Clone, Debug)]
pub struct BleScanResult {
    /// Platform peripheral identifier, usable as a connect selector.
    pub id: String,
    /// Advertised local name, when present.
    pub name: Option<String>,
    /// Last advertisement RSSI in dBm, when the platform reports it.
    pub rssi: Option<i16>,
}

/// GATT/SAR frame transport backed by `btleplug`.
///
/// The backend only reports an unsolicited disconnect on the adapter's
/// event stream; the notification stream simply goes quiet, and a write
/// to a peripheral the backend has already forgotten never answers. So
/// the link watches the adapter's events for its own peripheral, and
/// turns the disconnect into a closed receive side and a fast-failing
/// send side, rather than letting an idle link stay "connected" until
/// the next write times out.
#[cfg(feature = "ble-radio")]
pub struct BleFrameLink {
    peripheral: btleplug::platform::Peripheral,
    /// Kept only so the event stream the watcher holds stays alive; a
    /// link never scans on it again. After an unsolicited disconnect the
    /// backend forgets the peripheral internally but not in this
    /// adapter's own map, and rediscovering it on the same adapter trips
    /// an assertion in the backend. Every connection builds a fresh one.
    _adapter: btleplug::platform::Adapter,
    frame_in: btleplug::api::Characteristic,
    receiver: BleNotificationReceiver,
    /// Set by the watcher when the adapter reports this peripheral gone.
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
    segment_payload: usize,
    operation_timeout: Duration,
}

#[cfg(feature = "ble-radio")]
impl BleFrameLink {
    /// Scan for ULCP GATT Service peripherals without connecting.
    ///
    /// Runs discovery for the full `timeout` and reports every matching
    /// peripheral seen, so nearby radios all get listed (unlike
    /// [`connect`](Self::connect), which returns as soon as a match
    /// appears).
    pub async fn scan(timeout: Duration) -> Result<Vec<BleScanResult>, UlcpError> {
        use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};

        let manager = btleplug::platform::Manager::new()
            .await
            .map_err(ble_error)?;
        let adapters = manager.adapters().await.map_err(ble_error)?;
        let service = uuid::Uuid::from_u128(umsh_ulcp::gatt::SERVICE_UUID);
        let deadline = Instant::now() + timeout;
        let mut results: Vec<BleScanResult> = Vec::new();

        for adapter in adapters {
            adapter
                .start_scan(ScanFilter {
                    services: vec![service],
                })
                .await
                .map_err(ble_error)?;
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let peripherals =
                    match tokio::time::timeout_at(deadline, adapter.peripherals()).await {
                        Ok(result) => result.map_err(ble_error)?,
                        Err(_) => break,
                    };
                for peripheral in peripherals {
                    let properties =
                        match tokio::time::timeout_at(deadline, peripheral.properties()).await {
                            Ok(result) => result.map_err(ble_error)?,
                            Err(_) => break,
                        };
                    let advertises_service = properties
                        .as_ref()
                        .is_some_and(|properties| properties.services.contains(&service));
                    if !advertises_service {
                        continue;
                    }
                    let id = peripheral.id().to_string();
                    let name = properties
                        .as_ref()
                        .and_then(|properties| properties.local_name.clone());
                    let rssi = properties.as_ref().and_then(|properties| properties.rssi);
                    match results.iter_mut().find(|result| result.id == id) {
                        Some(existing) => {
                            existing.name = name.or(existing.name.take());
                            existing.rssi = rssi.or(existing.rssi);
                        }
                        None => results.push(BleScanResult { id, name, rssi }),
                    }
                }
            }
            // CoreBluetooth operations can block indefinitely; bound the
            // cleanup like connect does.
            let _ = tokio::time::timeout(Duration::from_secs(1), adapter.stop_scan()).await;
        }
        Ok(results)
    }

    /// Discover and attach to a ULCP GATT Service peripheral.
    ///
    /// `selector` matches a local-name substring or the platform peripheral ID.
    /// With no selector, discovery must yield exactly one companion radio.
    pub async fn connect(
        selector: Option<&str>,
        config: BleFrameLinkConfig,
    ) -> Result<Self, UlcpError> {
        use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
        use futures_util::{FutureExt, StreamExt};

        config.validate()?;

        let manager = btleplug::platform::Manager::new()
            .await
            .map_err(ble_error)?;
        let adapters = manager.adapters().await.map_err(ble_error)?;
        let service = uuid::Uuid::from_u128(umsh_ulcp::gatt::SERVICE_UUID);
        let deadline = Instant::now() + config.discovery_timeout;
        let mut matches = Vec::new();
        let mut chosen = None;

        for adapter in adapters {
            // Subscribed before anything else happens on this adapter, so
            // the disconnect that can race the setup below is not missed,
            // and so a power-on can be waited for.
            let events = adapter.events().await.map_err(ble_error)?;
            let mut events = await_power_on(&adapter, events, config.power_on_timeout).await?;
            adapter
                .start_scan(ScanFilter {
                    services: vec![service],
                })
                .await
                .map_err(ble_error)?;
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                matches.clear();
                let peripherals =
                    match tokio::time::timeout_at(deadline, adapter.peripherals()).await {
                        Ok(result) => result.map_err(ble_error)?,
                        Err(_) => break,
                    };
                for peripheral in peripherals {
                    let properties =
                        match tokio::time::timeout_at(deadline, peripheral.properties()).await {
                            Ok(result) => result.map_err(ble_error)?,
                            Err(_) => break,
                        };
                    let id = peripheral.id().to_string();
                    let name = properties
                        .as_ref()
                        .and_then(|properties| properties.local_name.as_deref());
                    let selected = selector.is_none_or(|selector| {
                        id == selector || name.is_some_and(|name| name.contains(selector))
                    });
                    let advertises_service = properties
                        .as_ref()
                        .is_some_and(|properties| properties.services.contains(&service));
                    if selected && advertises_service {
                        matches.push(peripheral);
                    }
                }
                if !matches.is_empty() || Instant::now() >= deadline {
                    break;
                }
            }
            // CoreBluetooth operations can block indefinitely. Discovery's
            // configured deadline applies to every await, including cleanup.
            let _ = tokio::time::timeout(Duration::from_secs(1), adapter.stop_scan()).await;
            if !matches.is_empty() {
                chosen = Some((adapter, events));
                break;
            }
            // Drain what the scan produced so the next adapter's wait
            // does not read this one's history.
            while let Some(Some(_)) = events.next().now_or_never() {}
        }

        let peripheral = match matches.len() {
            0 => {
                return Err(UlcpError::Transport(
                    "no ULCP GATT Service peripheral found".into(),
                ));
            }
            1 => matches.pop().unwrap(),
            _ => {
                return Err(UlcpError::Transport(
                    "multiple companion radios found; provide a selector".into(),
                ));
            }
        };
        let (adapter, mut events) = chosen.expect("a match names the adapter it was found on");
        let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let setup = async {
            let is_connected =
                tokio::time::timeout(config.operation_timeout, peripheral.is_connected())
                    .await
                    .map_err(|_| ble_timeout("querying connection state"))?
                    .map_err(ble_error)?;
            if !is_connected {
                tokio::time::timeout(config.operation_timeout, peripheral.connect())
                    .await
                    .map_err(|_| ble_timeout("connecting"))?
                    .map_err(ble_error)?;
            }
            tokio::time::timeout(config.operation_timeout, peripheral.discover_services())
                .await
                .map_err(|_| ble_timeout("discovering services"))?
                .map_err(ble_error)?;

            let frame_in_uuid = uuid::Uuid::from_u128(umsh_ulcp::gatt::FRAME_IN_UUID);
            let frame_out_uuid = uuid::Uuid::from_u128(umsh_ulcp::gatt::FRAME_OUT_UUID);
            let characteristics = peripheral.characteristics();
            let frame_in = characteristics
                .iter()
                .find(|characteristic| characteristic.uuid == frame_in_uuid)
                .cloned()
                .ok_or(UlcpError::Protocol("missing BLE Frame In"))?;
            let frame_out = characteristics
                .iter()
                .find(|characteristic| characteristic.uuid == frame_out_uuid)
                .cloned()
                .ok_or(UlcpError::Protocol("missing BLE Frame Out"))?;

            let mut stream =
                tokio::time::timeout(config.operation_timeout, peripheral.notifications())
                    .await
                    .map_err(|_| ble_timeout("opening notifications"))?
                    .map_err(ble_error)?;
            let (tx, notifications) = tokio::sync::mpsc::channel(32);
            // One task forwards notifications and watches for the
            // disconnect. Ending the task is what drops `tx`, and a
            // dropped `tx` is how the receive side learns the link is
            // gone; the flag is how the send side learns it.
            let id = peripheral.id();
            let dead = dead.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        notification = stream.next() => match notification {
                            Some(notification) => {
                                if notification.uuid == frame_out_uuid
                                    && tx.send(notification.value).await.is_err()
                                {
                                    break;
                                }
                            }
                            None => break,
                        },
                        event = events.next() => match event {
                            Some(btleplug::api::CentralEvent::DeviceDisconnected(gone))
                                if gone == id =>
                            {
                                dead.store(true, std::sync::atomic::Ordering::Release);
                                break;
                            }
                            Some(_) => {}
                            None => break,
                        },
                    }
                }
            });
            // This security-gated CCCD write is the protocol attach edge.
            // Pairing prompts are mediated by the host OS.
            tokio::time::timeout(config.pairing_timeout, peripheral.subscribe(&frame_out))
                .await
                .map_err(|_| ble_timeout("subscribing to Frame Out"))?
                .map_err(ble_error)?;
            Ok::<_, UlcpError>((frame_in, notifications))
        }
        .await;

        let (frame_in, notifications) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                // Failed setup must not leave the single-connection device
                // occupied and invisible to the next retry.
                let _ = tokio::time::timeout(Duration::from_secs(1), peripheral.disconnect()).await;
                return Err(error);
            }
        };

        Ok(Self {
            peripheral,
            _adapter: adapter,
            frame_in,
            receiver: BleNotificationReceiver::new(notifications),
            dead,
            segment_payload: config.segment_payload,
            operation_timeout: config.operation_timeout,
        })
    }

    /// Whether the adapter has reported this peripheral disconnected.
    fn is_dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Let go of the peripheral, waiting a bounded moment for the backend
    /// to agree.
    ///
    /// Dropping the link does not disconnect the peripheral, and a radio
    /// that admits one connection at a time stays occupied—and stops
    /// advertising—until something does. A link being replaced is closed
    /// first for exactly that reason; a link that is simply finished with
    /// may be dropped.
    pub async fn close(self) {
        use btleplug::api::Peripheral as _;
        if self.is_dead() {
            return;
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.peripheral.disconnect()).await;
    }

    /// Capture the backend's view of a failed link, then make a bounded
    /// best-effort disconnect so a subsequent discovery does not inherit a
    /// stale CoreBluetooth/BlueZ connection object.
    ///
    /// A backend that already knows the peripheral is gone, or says so
    /// when asked, makes this a plain disconnect; the prose form is kept
    /// for a write that failed on a link the backend still believes in.
    async fn diagnose_and_disconnect(&self, failure: String) -> UlcpError {
        use btleplug::api::Peripheral as _;

        if self.is_dead() {
            return UlcpError::Disconnected;
        }
        let connected = match tokio::time::timeout(
            Duration::from_secs(2),
            self.peripheral.is_connected(),
        )
        .await
        {
            Ok(Ok(false)) => return UlcpError::Disconnected,
            Ok(Ok(value)) => value.to_string(),
            Ok(Err(error)) => format!("error({error})"),
            Err(_) => "query-timeout".into(),
        };
        let cleanup = match tokio::time::timeout(
            Duration::from_secs(2),
            self.peripheral.disconnect(),
        )
        .await
        {
            Ok(Ok(())) => "ok".into(),
            Ok(Err(error)) => format!("error({error})"),
            Err(_) => "timeout".into(),
        };
        UlcpError::Transport(format!(
            "{failure}; backend is_connected={connected}; disconnect cleanup={cleanup}"
        ))
    }
}

/// Wait for `adapter` to be powered on, for up to `timeout`.
///
/// A powered-off adapter is refused outright when there is nothing to
/// wait with, which is also a better answer than the empty scan it would
/// otherwise produce. The backend reports an adapter it has not yet
/// heard from as unknown rather than off; that is what a scan has always
/// started against, and it still does.
#[cfg(feature = "ble-radio")]
async fn await_power_on(
    adapter: &btleplug::platform::Adapter,
    mut events: core::pin::Pin<
        Box<dyn futures_util::Stream<Item = btleplug::api::CentralEvent> + Send>,
    >,
    timeout: Duration,
) -> Result<
    core::pin::Pin<Box<dyn futures_util::Stream<Item = btleplug::api::CentralEvent> + Send>>,
    UlcpError,
> {
    use btleplug::api::{Central as _, CentralEvent, CentralState};
    use futures_util::StreamExt;

    let state = tokio::time::timeout(Duration::from_secs(2), adapter.adapter_state())
        .await
        .map_err(|_| ble_timeout("reading the adapter state"))?
        .map_err(ble_error)?;
    if state == CentralState::PoweredOn || (state == CentralState::Unknown && timeout.is_zero()) {
        return Ok(events);
    }
    if timeout.is_zero() {
        return Err(UlcpError::Transport("Bluetooth is powered off".into()));
    }
    let deadline = Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, events.next()).await {
            Ok(Some(CentralEvent::StateUpdate(CentralState::PoweredOn))) => return Ok(events),
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(UlcpError::Transport(
                    "the Bluetooth adapter went away".into(),
                ));
            }
            Err(_) => return Err(ble_timeout("waiting for Bluetooth to be powered on")),
        }
    }
}

#[cfg(feature = "ble-radio")]
impl FrameLink for BleFrameLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        use btleplug::api::{Peripheral as _, WriteType};

        // A write to a peripheral the backend has forgotten never
        // answers; the flag is what keeps a dead link from costing a
        // write timeout per frame.
        if self.is_dead() {
            return Err(UlcpError::Disconnected);
        }
        for segment in umsh_ulcp::gatt::segments(frame, self.segment_payload) {
            let mut value = vec![0; segment.payload().len() + 1];
            segment
                .write_to(&mut value)
                .expect("segment destination is exactly sized");
            let write = tokio::time::timeout(
                self.operation_timeout,
                self.peripheral
                    .write(&self.frame_in, &value, WriteType::WithResponse),
            )
            .await;
            match write {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(self
                        .diagnose_and_disconnect(format!("BLE Frame In write failed: {error}"))
                        .await);
                }
                Err(_) => {
                    return Err(self
                        .diagnose_and_disconnect("BLE timed out while writing Frame In".into())
                        .await);
                }
            }
        }
        Ok(())
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
        self.receiver.poll_recv_frame(cx)
    }
}

#[cfg(feature = "ble-radio")]
fn ble_error(error: btleplug::Error) -> UlcpError {
    UlcpError::Transport(error.to_string())
}

#[cfg(feature = "ble-radio")]
fn ble_timeout(operation: &'static str) -> UlcpError {
    UlcpError::Transport(format!("BLE timed out while {operation}"))
}

/// Companion radio attached over a frame link, usable as a
/// [`umsh_hal::Radio`].
pub struct UlcpDevice<L> {
    link: L,
    config: UlcpDeviceConfig,
    rx_queue: VecDeque<RxPacket>,
    responses: VecDeque<Response>,
    prop_events: VecDeque<PropEvent>,
    /// Unsolicited reset notification not yet surfaced to the caller.
    seen_reset: Option<Status>,
    /// Unsolicited session-reset notice not yet surfaced to the caller.
    ///
    /// Latched exactly like `seen_reset` and surfaced from the same
    /// places, because it means the same thing to whoever is holding
    /// session-scoped state: what you established is gone.
    seen_session_reset: Option<SessionResetReason>,
    /// A session reset this host asked for, to be absorbed rather than
    /// reported when its notice arrives.
    ///
    /// Set before the action that causes one and consumed by the first
    /// matching notice. It is not enough to swallow notices for the
    /// duration of a call: the device emits the notice after the reply
    /// that completes the command, so it commonly arrives during the
    /// *next* exchange. Matching on the reason keeps the expectation
    /// from absorbing a reset somebody else caused in the meantime.
    expected_session_reset: Option<SessionResetReason>,
    /// The transport reported that it is gone. Latched where the error is
    /// born rather than classified by whoever ends up holding it, because
    /// by then it has usually been turned into prose. Cleared by
    /// [`Self::reattach`].
    link_lost: bool,
    max_frame_size: usize,
    t_frame_ms: u32,
    dev_version: String,
    dev_model: Option<String>,
    /// Hardware reset cause retained by the device before our protocol reset.
    boot_status: Status,
    /// `PROP_CAPS`, once something has read it.
    ///
    /// A device's capabilities are fixed by its firmware and the board it
    /// was built for, so one answer stands until the device on the other
    /// end could have changed: a new link, or new firmware. Over the mesh
    /// every read is an exchange on the air, and asking again before each
    /// gated command would cost more than the command.
    caps: Option<Vec<u32>>,
    tids: TidAllocator,
    /// Optional per-frame trace sink for both directions.
    trace: Option<FrameTrace>,
    mode: AttachMode,
}

/// The relationships a host can have with a device.
///
/// They are different things, and conflating them is how one phone
/// administering ten repeaters ends up claiming all of them. Tethering is
/// a transient local relationship—at most one at a time, re-established
/// on every attach, invisible to the mesh. Administration is
/// configuration of the device's own identity and behavior, which
/// outlives any particular host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachMode {
    /// This host is the device's tethered host: it provisions the host
    /// domain and the device filters, queues and acknowledges for it.
    #[default]
    Tethered,
    /// This host is administering the device without tethering to it.
    /// Host-domain writes are refused.
    Administrative,
    /// This host is administering the device over the mesh, through the
    /// Node Management binding rather than a wire.
    ///
    /// Administrative in every respect, and additionally bounded by what
    /// that binding carries. Reads are not bounded at all: the device
    /// answers an administrator's `CMD_PROP_GET` for anything it
    /// implements, so this handle asks for whatever it wants and lets
    /// the answer decide. Writes are the gated half
    /// ([`admin_writable`](umsh_ulcp::ids::admin_writable)).
    Remote,
}

impl<L> UlcpDevice<L>
where
    L: FrameLink,
{
    fn bare(link: L, config: UlcpDeviceConfig) -> Self {
        Self {
            link,
            config,
            rx_queue: VecDeque::new(),
            responses: VecDeque::new(),
            prop_events: VecDeque::new(),
            seen_reset: None,
            seen_session_reset: None,
            expected_session_reset: None,
            link_lost: false,
            max_frame_size: 0,
            t_frame_ms: 0,
            dev_version: String::new(),
            dev_model: None,
            boot_status: Status::RESET_UNKNOWN,
            caps: None,
            tids: TidAllocator::new(),
            trace: None,
            mode: AttachMode::Tethered,
        }
    }

    /// Which relationship this handle has with the device.
    pub fn attach_mode(&self) -> AttachMode {
        self.mode
    }

    /// Whether this handle reaches the device over the mesh rather than a
    /// wire, and is therefore bounded by what the administrative binding
    /// carries.
    pub fn is_remote(&self) -> bool {
        self.mode == AttachMode::Remote
    }

    /// Refuse a host-domain write on an administrative handle.
    fn require_tethered(&self, key: u32) -> Result<(), UlcpError> {
        let host_domain = matches!(
            key,
            prop::HOST_KEY
                | prop::HOST_CHANNEL_KEYS
                | prop::HOST_PEER_KEYS
                | prop::HOST_RX_FILTERS
                | prop::HOST_AUTO_ACK
        );
        match self.mode {
            AttachMode::Administrative | AttachMode::Remote if host_domain => {
                Err(UlcpError::AdministrativeAttach)
            }
            _ => Ok(()),
        }
    }

    /// Attach to a device: reset it, verify the protocol version, apply
    /// the RF configuration, and enable the PHY.
    ///
    /// This is the minimal-protocol attach: `CMD_RST` discards a
    /// full-protocol device's session-independent state visibility (and
    /// with a saved snapshot the post-reset values come from the
    /// snapshot, not the documented defaults). A host cooperating with
    /// an autonomously operating device should use
    /// [`Self::attach_existing`] instead.
    pub async fn new(link: L, config: UlcpDeviceConfig) -> Result<Self, UlcpError> {
        let mut radio = Self::bare(link, config);
        radio.initialize().await?;
        Ok(radio)
    }

    /// Attach to an already-operating device as its **tethered host**:
    /// the one host whose traffic it filters, queues and acknowledges.
    ///
    /// This is the full-protocol attach (spec §Attach, Detach, and
    /// Synchronization): attach implies no known state, so the host
    /// synchronizes by fetching. Only the identity handshake runs here
    ///—retained `PROP_LAST_STATUS` (the reset cause, preserved for
    /// [`Self::boot_status`] and [`Self::sync`]), the protocol version
    /// check, `PROP_DEV_VERSION`, `PROP_PHY_MTU`, and the current frame
    /// airtime. The PHY keeps
    /// whatever configuration and enable state it had; queued frames
    /// and provisioning are untouched. Follow with [`Self::sync`],
    /// [`Self::provision`], and drain the queue when ready.
    ///
    /// Use [`Self::attach_administrative`] to configure a device you do
    /// not intend to tether to—one phone administering ten repeaters
    /// must not write `PROP_HOST_KEY` on any of them.
    pub async fn attach_existing(link: L, config: UlcpDeviceConfig) -> Result<Self, UlcpError> {
        Self::attach_with_mode(link, config, AttachMode::Tethered).await
    }

    /// Attach to an already-operating device to **administer** it:
    /// configure its own identity, radio, and behavior without becoming
    /// its host.
    ///
    /// Commissioning and tethering are different relationships and this
    /// is the difference made mechanical. The handle refuses every
    /// host-domain write—`PROP_HOST_KEY`, the host key tables, the
    /// filter table, the delegation policy, and [`Self::provision`]—
    /// with [`UlcpError::AdministrativeAttach`]. Everything
    /// else, including the device identity and the saved snapshot, works
    /// normally.
    ///
    /// A device may be administered by many hosts over its lifetime and
    /// tethered to at most one at a time; nothing about administering it
    /// disturbs whichever host it is currently serving.
    pub async fn attach_administrative(
        link: L,
        config: UlcpDeviceConfig,
    ) -> Result<Self, UlcpError> {
        Self::attach_with_mode(link, config, AttachMode::Administrative).await
    }

    /// Open a handle on a device reached over the mesh, through the Node
    /// Management binding.
    ///
    /// Nothing goes on the air. An attach down a wire opens with a few
    /// reads because the link has just come up and the host knows
    /// nothing about what is on the other end; none of that is a
    /// handshake in the sense of establishing anything, because the
    /// device is told nothing and holds no state for it. Over the
    /// binding those reads would be exchanges on the air, minutes of
    /// them in bad conditions, spent before the command you actually
    /// asked for. A command that wants the firmware version or the boot
    /// status reads it, and pays for it then.
    ///
    /// So [`Self::dev_version`], [`Self::dev_model`], and
    /// [`Self::boot_status`] are empty on this handle, and the frame
    /// ceiling comes from the binding—[`umsh_node_mgmt::REQUEST_MAX`],
    /// which bounds a request here more tightly than the device's own
    /// PHY MTU does—rather than from asking. Give `config` the
    /// device's PHY and a response timeout that outlasts the binding's
    /// own retry budget, or a slow answer becomes a transport error here
    /// before the exchange engine has finished trying.
    pub fn open_remote(link: L, config: UlcpDeviceConfig) -> Self {
        let mut radio = Self::bare(link, config);
        radio.mode = AttachMode::Remote;
        radio.max_frame_size = umsh_node_mgmt::REQUEST_MAX;
        radio.t_frame_ms = lora_airtime_ms(
            radio.config.spreading_factor,
            radio.config.bandwidth_hz,
            radio.config.coding_rate_denom,
            radio.max_frame_size,
        )
        .max(1);
        radio
    }

    async fn attach_with_mode(
        link: L,
        config: UlcpDeviceConfig,
        mode: AttachMode,
    ) -> Result<Self, UlcpError> {
        let mut radio = Self::bare(link, config);
        radio.mode = mode;
        // Opening the transport is what attached us, and the device
        // announces the session state it discarded doing so. Recording
        // the expectation before the first exchange keeps that notice
        // from failing the very handshake it belongs to; a mesh handle
        // is not a session and gets none.
        if mode != AttachMode::Remote {
            radio.expected_session_reset = Some(SessionResetReason::Attached);
        }
        radio.handshake().await?;
        Ok(radio)
    }

    /// The non-resetting attach handshake: learn what is on the other
    /// end of the link without telling it anything.
    async fn handshake(&mut self) -> Result<(), UlcpError> {
        self.read_boot_status().await?;

        // Everything else the handshake wants, in one exchange.
        const REST: [u32; 4] = [
            prop::PROTOCOL_VERSION,
            prop::DEV_VERSION,
            prop::DEV_MODEL,
            prop::PHY_MTU,
        ];
        let answers = absorbing_attach_notices!(self, self.read_each(&REST))?;
        let [version, dev_version, dev_model, mtu] = answers.as_slice() else {
            return Err(UlcpError::Protocol("short answer to the attach handshake"));
        };

        // The one answer that can end an attach: it is what says the far
        // end speaks this protocol at all.
        let version = version
            .as_ref()
            .map_err(|status| UlcpError::Status(*status))?;
        check_protocol_version(version)?;
        // Everything else is a description of the device, and a device
        // that describes itself badly is still one to attach to.
        // `PROP_DEV_MODEL` is OPTIONAL besides, so its refusal means only
        // "this device does not name its hardware".
        self.dev_version = dev_version
            .as_ref()
            .map(|value| decode_string(value))
            .unwrap_or_default();
        self.dev_model = dev_model.as_ref().ok().map(|value| decode_string(value));
        self.max_frame_size = decode_mtu(mtu.as_ref().ok());

        absorbing_attach_notices!(self, self.refresh_t_frame_or_keep())?;
        self.absorb_latched_attach_notices();
        Ok(())
    }

    /// Absorb a loss-of-state notice an attach exchange failed on (see
    /// [`absorbing_attach_notices`]), returning whether it was one.
    fn absorb_attach_notice(&mut self, error: &UlcpError) -> bool {
        match error {
            UlcpError::UnexpectedReset(status) => {
                self.boot_status = *status;
                true
            }
            UlcpError::SessionReset(_) => true,
            _ => false,
        }
    }

    /// Absorb whatever notice is still latched once the attach exchanges
    /// are done. One that arrived in the same read as the last answer was
    /// never reported, and belongs to the attach as much as the rest.
    fn absorb_latched_attach_notices(&mut self) {
        if let Some(error) = self.take_reset_notice() {
            self.absorb_attach_notice(&error);
        }
    }

    /// Give this handle a new transport to the same device.
    ///
    /// Everything the handle *is* survives—its attach mode, its
    /// configuration, its trace sink—and everything it *held about the
    /// old link* is discarded: queued frames and responses, latched
    /// notices, the transaction-identifier space. What it *learned* at
    /// attach survives too: the device on the other end is the one it
    /// attached to, so its version, model, MTU and frame time are not
    /// asked for again. The one thing that can have changed in between
    /// is whether it rebooted, so the retained status is re-read; that
    /// single exchange is also what proves the new link is live.
    ///
    /// The old transport is dropped here, not closed. A transport the
    /// device admits one of at a time (BLE) must be closed *before*
    /// the new one is opened, or the device is still occupied by the
    /// stale connection and never found; that is the caller's job, since
    /// only the caller knows what a link is.
    ///
    /// The state is swapped before the first await, so a handshake that
    /// is cancelled leaves a live link behind it; whatever the handshake
    /// did not get to learn, the next exchange corrects.
    ///
    /// A mesh handle has no transport of its own to replace: the radio
    /// underneath it is what gets reattached, and asking for this on the
    /// handle is refused.
    pub async fn reattach(&mut self, link: L) -> Result<(), UlcpError> {
        if self.mode == AttachMode::Remote {
            return Err(UlcpError::Protocol("a mesh handle cannot be reattached"));
        }
        self.link = link;
        self.rx_queue.clear();
        self.responses.clear();
        self.prop_events.clear();
        self.seen_reset = None;
        self.seen_session_reset = None;
        self.expected_session_reset = Some(SessionResetReason::Attached);
        self.tids = TidAllocator::new();
        self.link_lost = false;
        // A link that dropped may have dropped for a firmware update, and
        // capabilities are what a new build changes. Asking again costs
        // one read down a wire.
        self.caps = None;
        self.read_boot_status().await?;
        self.absorb_latched_attach_notices();
        Ok(())
    }

    /// Learn whether the device rebooted, without touching anything.
    ///
    /// Reading LAST_STATUS does not overwrite it, so sync() still sees
    /// a retained reset code after this.
    ///
    /// It also cannot travel with other properties. A `CMD_PROP_ARE`
    /// reports a refused position by putting `PROP_LAST_STATUS` in it,
    /// so a status that *is* the answer and a status standing in for
    /// one are the same bytes. Asking for it alone is what tells them
    /// apart.
    ///
    /// A device that booted as the link came up announces it, ahead of
    /// or alongside this answer; that announcement is the boot status
    /// too, not a failure of the read (see [`absorbing_attach_notices`]).
    async fn read_boot_status(&mut self) -> Result<(), UlcpError> {
        let boot_status = absorbing_attach_notices!(self, self.get_prop(prop::LAST_STATUS))?;
        self.boot_status = decode_status(&boot_status);
        Ok(())
    }

    /// Whether the transport has reported itself gone since the handle
    /// was attached or last reattached. Every call on the handle fails
    /// while this holds; [`Self::reattach`] is the way out.
    pub fn link_lost(&self) -> bool {
        self.link_lost
    }

    /// Borrow the transport, for whoever has to close or replace it.
    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    /// Latch a transport failure where it is born. Over the mesh a
    /// transport error is a failed exchange, not a dead wire, and the
    /// radio underneath keeps its own latch.
    fn note_link_error(&mut self, error: &UlcpError) {
        if self.mode != AttachMode::Remote && error.is_link_lost() {
            self.link_lost = true;
        }
    }

    /// Give up this handle and recover the transport underneath it.
    ///
    /// The link stays open, so the device sees no detach and keeps its
    /// session-scoped state: this releases the *host's* bookkeeping, not
    /// the connection. Re-attaching the returned link produces a fresh
    /// handle, which is how a long-lived interactive host changes
    /// [`AttachMode`]—administrative for inspection, tethered for the
    /// one command that establishes a host domain—without making the
    /// user wait through a BLE reconnect.
    pub fn into_link(self) -> L {
        self.link
    }

    /// Install (or clear) a per-frame trace sink. Every frame sent and
    /// every frame received is reported as a one-line summary (see
    /// [`describe_frame`]), so a failure can be placed at the host API,
    /// framing, session, storage, or radio boundary.
    pub fn set_frame_trace(&mut self, trace: Option<FrameTrace>) {
        self.trace = trace;
    }

    /// Send one frame through the trace hook.
    async fn send(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        if let Some(trace) = &mut self.trace {
            trace(TraceDirection::HostToDevice, &describe_frame(frame));
        }
        let result = self.link.send_frame(frame).await;
        if let Err(error) = &result {
            self.note_link_error(error);
        }
        result
    }

    /// The device's firmware version string (`PROP_DEV_VERSION`).
    pub fn dev_version(&self) -> &str {
        &self.dev_version
    }

    /// The device's hardware model (`PROP_DEV_MODEL`), or `None` on a
    /// device that does not implement the optional property—a
    /// simulator, or firmware predating it.
    pub fn dev_model(&self) -> Option<&str> {
        self.dev_model.as_deref()
    }

    /// Fetch the device's human-readable `PROP_DEV_NAME`.
    ///
    /// Read as the device reports it. The length and content rules bind
    /// the writer—[`Self::set_device_name`] keeps to them—and a name
    /// that breaks them is still the device's name, shown as best it can
    /// be.
    pub async fn device_name(&mut self) -> Result<String, UlcpError> {
        Ok(decode_string(&self.get_prop(prop::DEV_NAME).await?))
    }

    /// Set the device's human-readable `PROP_DEV_NAME`.
    pub async fn set_device_name(&mut self, name: &str) -> Result<(), UlcpError> {
        if name.is_empty() || name.len() > 64 || name.as_bytes().contains(&0) {
            return Err(UlcpError::Protocol("invalid PROP_DEV_NAME"));
        }
        let authoritative = self.set_prop(prop::DEV_NAME, name.as_bytes()).await?;
        if authoritative != name.as_bytes() {
            return Err(UlcpError::Protocol("PROP_DEV_NAME response mismatch"));
        }
        Ok(())
    }

    /// Fetch a live battery status snapshot (`PROP_BATTERY`).
    ///
    /// `Ok(None)` means the device is not battery powered.
    /// `Ok(Some(status))` with every field `None` means battery powered
    /// with unsupported reporting. A measurement the device cannot
    /// currently obtain surfaces as a command failure, never as `None`—
    /// battery is live telemetry, so this is deliberately not part of
    /// [`UlcpDevice::sync`].
    ///
    /// One exchange: the property's own absence is the answer
    /// `CAP_BATTERY` would have given, and over the mesh a capability
    /// read to learn the same thing is a round trip on the air.
    pub async fn battery_status(&mut self) -> Result<Option<BatteryStatus>, UlcpError> {
        let value = match self.get_prop(prop::BATTERY).await {
            Ok(value) => value,
            Err(UlcpError::Status(Status::PROP_NOT_FOUND)) => return Ok(None),
            Err(error) => return Err(error),
        };
        match BatteryStatus::decode(&value) {
            Ok(status) => Ok(Some(status)),
            Err(_) => Err(UlcpError::Protocol("malformed PROP_BATTERY")),
        }
    }

    /// Fetch a live ambient illuminance reading in millilux
    /// (`PROP_ILLUMINANCE`).
    ///
    /// `Ok(None)` means either that the device does not advertise
    /// `CAP_ILLUMINANCE`—no light sensor is fitted—or that a device
    /// which does could not read the sensor just now. Both are "there is
    /// no reading", which is what a caller acts on; neither is an error.
    /// Live telemetry, so deliberately not part of [`UlcpDevice::sync`].
    pub async fn illuminance(&mut self) -> Result<Option<u32>, UlcpError> {
        let Some(answers) = self
            .read_gated(cap::ILLUMINANCE, &[prop::ILLUMINANCE])
            .await?
        else {
            return Ok(None);
        };
        // A refusal is the device saying it has no reading either.
        let [answer] = positions(answers)?;
        Ok(answer.ok().and_then(|value| decode_u32_prefix(&value)))
    }

    /// Read the device's locate-alert state (`PROP_ALERT`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_ALERT`—it has
    /// no way to make itself conspicuous.
    pub async fn alert(&mut self) -> Result<Option<ReportedAlert>, UlcpError> {
        let Some(answers) = self.read_gated(cap::ALERT, &[prop::ALERT]).await? else {
            return Ok(None);
        };
        let [value] = required_answers(answers)?;
        Ok(Some(decode_alert(&value)?))
    }

    /// Start or stop the device's locate alert (`PROP_ALERT`).
    ///
    /// Setting [`AlertState::Locate`] while an alert is already running
    /// restarts the device's deadline rather than failing, so a host that
    /// wants an alert to outlast the board's own bound re-sends this.
    /// Returns the authoritative state the device reported.
    ///
    /// The alert also ends when someone cancels it at the device or the
    /// deadline expires; both arrive as an unsolicited `PROP_ALERT`
    /// update rather than as a response to this call.
    ///
    /// A device without `CAP_ALERT` answers `STATUS_PROP_NOT_FOUND`.
    pub async fn set_alert(&mut self, state: AlertState) -> Result<ReportedAlert, UlcpError> {
        let mut value = [0u8; pui::MAX_LEN];
        let len = pui::encode(state.code(), &mut value)
            .map_err(|_| UlcpError::Protocol("PROP_ALERT encode"))?;
        let authoritative = self.set_prop(prop::ALERT, &value[..len]).await?;
        decode_alert(&authoritative)
    }

    /// Reset cause reported by the device immediately after transport attach.
    pub fn boot_status(&self) -> Status {
        self.boot_status
    }

    /// Read the device's full repeater forwarding policy.
    ///
    /// `Ok(None)` means the device does not advertise `CAP_REPEATER`.
    pub async fn repeater_policy(&mut self) -> Result<Option<RepeaterPolicy>, UlcpError> {
        const KEYS: [u32; 5] = [
            prop::MAC_REPEATER_ENABLED,
            prop::MAC_REPEATER_REGIONS,
            prop::MAC_REPEATER_DEFAULT_REGION,
            prop::MAC_REPEATER_MIN_RSSI,
            prop::MAC_REPEATER_MIN_SNR,
        ];
        let Some(answers) = self.read_gated(cap::REPEATER, &KEYS).await? else {
            return Ok(None);
        };
        let [enabled, regions, default_region, min_rssi, min_snr] = positions(answers)?;
        Ok(Some(RepeaterPolicy {
            enabled: reported(&enabled, decode_bool),
            regions: reported(&regions, |value| Some(decode_region_list(value))),
            default_region: reported(&default_region, |value| decode_region_code(value).ok()),
            min_rssi: reported(&min_rssi, decode_opt_i16),
            min_snr: reported(&min_snr, decode_opt_i8),
        }))
    }

    /// Read the forwarding filter's region strings on their own.
    pub async fn repeater_regions(&mut self) -> Result<Vec<String>, UlcpError> {
        Ok(decode_region_list(
            &self.get_prop(prop::MAC_REPEATER_REGIONS).await?,
        ))
    }

    /// Set which region-tagged floods the device forwards
    /// (`PROP_MAC_REPEATER_REGIONS`), as region strings. An empty list
    /// clears the filter, which imposes no regional restriction rather
    /// than blocking every flood.
    ///
    /// Returns the list the device actually stored. A device with less
    /// capacity than the caller offered refuses the write outright, so a
    /// shorter return means it collapsed a repeat.
    pub async fn set_repeater_regions(
        &mut self,
        regions: &[String],
    ) -> Result<Vec<String>, UlcpError> {
        let mut value = Vec::new();
        for region in regions {
            check_region(region)?;
            let mut item = vec![0u8; region.len() + 4];
            let len = items::encode_prefixed_item(region.as_bytes(), &mut item)
                .map_err(|_| UlcpError::Protocol("region item encode"))?;
            value.extend_from_slice(&item[..len]);
        }
        let authoritative = self.set_prop(prop::MAC_REPEATER_REGIONS, &value).await?;
        Ok(decode_region_list(&authoritative))
    }

    /// Add one region to the forwarding filter without resending the rest
    /// of the table. A region already present fails with `STATUS_ALREADY`.
    pub async fn add_repeater_region(&mut self, region: &str) -> Result<(), UlcpError> {
        check_region(region)?;
        self.insert_prop_item(prop::MAC_REPEATER_REGIONS, region.as_bytes())
            .await
            .map(|_| ())
    }

    /// Remove one region from the forwarding filter. The selector is the
    /// string as it was written, not the code it derives to.
    pub async fn remove_repeater_region(&mut self, region: &str) -> Result<(), UlcpError> {
        check_region(region)?;
        self.remove_prop_item(prop::MAC_REPEATER_REGIONS, region.as_bytes())
            .await
            .map(|_| ())
    }

    /// Set the region code inserted into untagged floods before
    /// forwarding (`PROP_MAC_REPEATER_DEFAULT_REGION`). `None` forwards
    /// untagged.
    ///
    /// Deliberately not cross-checked against
    /// [`set_repeater_regions`](Self::set_repeater_regions): the two are
    /// written in either order.
    pub async fn set_repeater_default_region(
        &mut self,
        region: Option<RegionCode>,
    ) -> Result<Option<RegionCode>, UlcpError> {
        let value = region.map(|code| code.to_bytes()).unwrap_or_default();
        let value: &[u8] = match region {
            Some(_) => &value,
            None => &[],
        };
        let authoritative = self
            .set_prop(prop::MAC_REPEATER_DEFAULT_REGION, value)
            .await?;
        decode_region_code(&authoritative)
    }

    /// Set the RSSI floor for forwarding in dBm
    /// (`PROP_MAC_REPEATER_MIN_RSSI`). `None` accepts any.
    pub async fn set_repeater_min_rssi(
        &mut self,
        min_rssi: Option<i16>,
    ) -> Result<Option<i16>, UlcpError> {
        let encoded = min_rssi.map(i16::to_le_bytes).unwrap_or_default();
        let value: &[u8] = match min_rssi {
            Some(_) => &encoded,
            None => &[],
        };
        let authoritative = self.set_prop(prop::MAC_REPEATER_MIN_RSSI, value).await?;
        decode_opt_i16(&authoritative)
            .ok_or(UlcpError::Protocol("malformed PROP_MAC_REPEATER_MIN_RSSI"))
    }

    /// Set the SNR floor for forwarding in dB
    /// (`PROP_MAC_REPEATER_MIN_SNR`). `None` accepts any.
    pub async fn set_repeater_min_snr(
        &mut self,
        min_snr: Option<i8>,
    ) -> Result<Option<i8>, UlcpError> {
        let encoded = [min_snr.unwrap_or_default() as u8];
        let value: &[u8] = match min_snr {
            Some(_) => &encoded,
            None => &[],
        };
        let authoritative = self.set_prop(prop::MAC_REPEATER_MIN_SNR, value).await?;
        decode_opt_i8(&authoritative)
            .ok_or(UlcpError::Protocol("malformed PROP_MAC_REPEATER_MIN_SNR"))
    }

    /// Read the device's MeshCore forwarding settings.
    ///
    /// `Ok(None)` means the device does not advertise
    /// `CAP_MESHCORE_FORWARDER`.
    pub async fn meshcore_forwarding(&mut self) -> Result<Option<MeshCoreForwarding>, UlcpError> {
        const KEYS: [u32; 3] = [
            prop::MESHCORE_FORWARDING_ENABLED,
            prop::MESHCORE_REGION_POLICY,
            prop::MESHCORE_REGIONS,
        ];
        let Some(answers) = self.read_gated(cap::MESHCORE_FORWARDER, &KEYS).await? else {
            return Ok(None);
        };
        let [enabled, region_policy, regions] = positions(answers)?;
        Ok(Some(MeshCoreForwarding {
            enabled: reported(&enabled, decode_bool),
            region_policy: reported(&region_policy, decode_meshcore_region_policy),
            regions: reported(&regions, |value| Some(decode_meshcore_regions(value))),
        }))
    }

    /// Set the MeshCore regions whose scoped floods the device forwards
    /// (`PROP_MESHCORE_REGIONS`). A leading `#` on a name is dropped: the
    /// device supplies it.
    ///
    /// Returns the list the device actually stored.
    pub async fn set_meshcore_regions(
        &mut self,
        regions: &[String],
    ) -> Result<Vec<String>, UlcpError> {
        let mut value = Vec::new();
        for region in regions {
            let name = meshcore_region_name(region)?;
            let mut item = vec![0u8; name.len() + 4];
            let len = items::encode_prefixed_item(name.as_bytes(), &mut item)
                .map_err(|_| UlcpError::Protocol("region item encode"))?;
            value.extend_from_slice(&item[..len]);
        }
        let authoritative = self.set_prop(prop::MESHCORE_REGIONS, &value).await?;
        Ok(decode_meshcore_regions(&authoritative))
    }

    /// Add one MeshCore region. A region already present fails with
    /// `STATUS_ALREADY`.
    pub async fn add_meshcore_region(&mut self, region: &str) -> Result<(), UlcpError> {
        let name = meshcore_region_name(region)?;
        self.insert_prop_item(prop::MESHCORE_REGIONS, name.as_bytes())
            .await
            .map(|_| ())
    }

    /// Remove one MeshCore region, matched exactly, case included.
    pub async fn remove_meshcore_region(&mut self, region: &str) -> Result<(), UlcpError> {
        let name = meshcore_region_name(region)?;
        self.remove_prop_item(prop::MESHCORE_REGIONS, name.as_bytes())
            .await
            .map(|_| ())
    }

    /// Set whether MeshCore traffic is forwarded too
    /// (`PROP_MESHCORE_FORWARDING_ENABLED`). Enabling fails with
    /// `STATUS_INVALID_STATE` under an identity
    /// [`meshcore_identity_allowed`] refuses.
    pub async fn set_meshcore_forwarding_enabled(
        &mut self,
        enabled: bool,
    ) -> Result<bool, UlcpError> {
        let authoritative = self
            .set_prop(prop::MESHCORE_FORWARDING_ENABLED, &[enabled as u8])
            .await?;
        bool_echo(&authoritative, "PROP_MESHCORE_FORWARDING_ENABLED")
    }

    /// Set how MeshCore transport codes gate flood forwarding
    /// (`PROP_MESHCORE_REGION_POLICY`).
    pub async fn set_meshcore_region_policy(
        &mut self,
        policy: MeshCoreRegionPolicy,
    ) -> Result<MeshCoreRegionPolicy, UlcpError> {
        let authoritative = self
            .set_prop(prop::MESHCORE_REGION_POLICY, &[policy.as_u8()])
            .await?;
        decode_meshcore_region_policy(&authoritative)
            .ok_or(UlcpError::Protocol("empty PROP_MESHCORE_REGION_POLICY"))
    }

    /// Read the device's wall clock and time zone (`PROP_TIME`,
    /// `PROP_TZ_RULE`, `PROP_TIME_24H`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_TIME`.
    /// `Ok(Some(time))` with `time.epoch == Some(None)` means it has one
    /// and does not know what time it is—the state in which a device with
    /// a screen must show no clock at all.
    pub async fn time(&mut self) -> Result<Option<DeviceTime>, UlcpError> {
        let Some(answers) = self
            .read_gated(cap::TIME, &[prop::TIME, prop::TZ_RULE, prop::TIME_24H])
            .await?
        else {
            return Ok(None);
        };
        let [epoch, tz_rule, time_24h] = positions(answers)?;
        Ok(Some(DeviceTime {
            epoch: reported(&epoch, |value| decode_epoch(value).ok()),
            tz_rule: reported(&tz_rule, |value| Some(decode_string(value))),
            time_24h: reported(&time_24h, decode_bool),
        }))
    }

    /// Set the device's wall clock (`PROP_TIME`). `None` returns it to not
    /// knowing what time it is.
    ///
    /// A manual set outranks every receiver-derived one, including while
    /// `PROP_GNSS_TIME_TRUST` is clear.
    pub async fn set_time(&mut self, epoch: Option<u32>) -> Result<Option<u32>, UlcpError> {
        let encoded = epoch.map(u32::to_le_bytes).unwrap_or_default();
        let value: &[u8] = match epoch {
            Some(_) => &encoded,
            None => &[],
        };
        let authoritative = self.set_prop(prop::TIME, value).await?;
        decode_epoch(&authoritative)
    }

    /// Set the device's time zone, as a POSIX TZ rule (`PROP_TZ_RULE`).
    pub async fn set_tz_rule(&mut self, rule: &str) -> Result<String, UlcpError> {
        let authoritative = self.set_prop(prop::TZ_RULE, rule.as_bytes()).await?;
        Ok(decode_string(&authoritative))
    }

    /// Set whether a clock the device shows writes hours from 0 to 23
    /// (`PROP_TIME_24H`).
    pub async fn set_time_24h(&mut self, on: bool) -> Result<bool, UlcpError> {
        let authoritative = self.set_prop(prop::TIME_24H, &[u8::from(on)]).await?;
        decode_bool(&authoritative).ok_or(UlcpError::Protocol("malformed PROP_TIME_24H"))
    }

    /// Read everything the device reports about positioning
    /// (`PROP_GNSS_*`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_GNSS`. The fix
    /// is live telemetry, so a disabled or searching receiver reports
    /// [`GnssSnapshot::SEARCHING`] rather than an error.
    pub async fn gnss_status(&mut self) -> Result<Option<GnssStatus>, UlcpError> {
        const FIX_KEYS: [u32; 5] = [
            prop::GNSS_FIX,
            prop::GNSS_LOCATION,
            prop::GNSS_ALTITUDE,
            prop::GNSS_PRECISION,
            prop::GNSS_SATELLITES,
        ];
        const KEYS: [u32; 9] = [
            prop::GNSS_ENABLED,
            FIX_KEYS[0],
            FIX_KEYS[1],
            FIX_KEYS[2],
            FIX_KEYS[3],
            FIX_KEYS[4],
            prop::GNSS_IDENT_UPDATE,
            prop::GNSS_IDENT_PRECISION,
            prop::GNSS_TIME_TRUST,
        ];
        let Some(answers) = self.read_gated(cap::GNSS, &KEYS).await? else {
            return Ok(None);
        };
        let [
            enabled,
            fix_values @ ..,
            ident_update,
            ident_precision,
            time_trust,
        ] = positions::<9>(answers)?;
        // One reading of the receiver, all five fields of it from the
        // same moment, which a property-at-a-time read never promised. A
        // member the device refused or that will not decode leaves its
        // field as searching, and the others still land.
        let mut fix = GnssSnapshot::SEARCHING;
        for (key, value) in FIX_KEYS.into_iter().zip(&fix_values) {
            if let Ok(value) = value {
                let mut absorbed = fix;
                if absorbed.absorb(key, value).is_ok() {
                    fix = absorbed;
                }
            }
        }
        Ok(Some(GnssStatus {
            enabled: reported(&enabled, decode_bool),
            fix,
            ident_update: reported(&ident_update, decode_bool),
            ident_precision: reported(&ident_precision, |value| value.first().copied()),
            time_trust: reported(&time_trust, decode_bool),
        }))
    }

    /// Read the device's advertisement policy, or `None` on a device
    /// without `CAP_ADVERT`.
    pub async fn advert_policy(&mut self) -> Result<Option<AdvertPolicy>, UlcpError> {
        const KEYS: [u32; 3] = [
            prop::ADVERT_INTERVAL,
            prop::BEACON_INTERVAL,
            prop::STARTUP_BEACON,
        ];
        let Some(answers) = self.read_gated(cap::ADVERT, &KEYS).await? else {
            return Ok(None);
        };
        let [advert_interval_s, beacon_interval_s, startup_beacon] = positions(answers)?;
        Ok(Some(AdvertPolicy {
            advert_interval_s: reported(&advert_interval_s, |value| decode_interval(value).ok()),
            beacon_interval_s: reported(&beacon_interval_s, |value| decode_interval(value).ok()),
            startup_beacon: reported(&startup_beacon, decode_bool),
        }))
    }

    /// Set the seconds between signed identity advertisements, 0 for none
    /// (`PROP_ADVERT_INTERVAL`).
    pub async fn set_advert_interval(&mut self, seconds: u32) -> Result<u32, UlcpError> {
        let authoritative = self
            .set_prop(prop::ADVERT_INTERVAL, &seconds.to_le_bytes())
            .await?;
        decode_interval(&authoritative)
    }

    /// Set the seconds between empty beacons, 0 for none
    /// (`PROP_BEACON_INTERVAL`).
    pub async fn set_beacon_interval(&mut self, seconds: u32) -> Result<u32, UlcpError> {
        let authoritative = self
            .set_prop(prop::BEACON_INTERVAL, &seconds.to_le_bytes())
            .await?;
        decode_interval(&authoritative)
    }

    /// Set whether one beacon goes out at bring-up (`PROP_STARTUP_BEACON`).
    pub async fn set_startup_beacon(&mut self, enabled: bool) -> Result<bool, UlcpError> {
        let authoritative = self
            .set_prop(prop::STARTUP_BEACON, &[enabled as u8])
            .await?;
        bool_echo(&authoritative, "PROP_STARTUP_BEACON")
    }

    /// Power the GNSS receiver on or off (`PROP_GNSS_ENABLED`).
    pub async fn set_gnss_enabled(&mut self, enabled: bool) -> Result<bool, UlcpError> {
        let authoritative = self.set_prop(prop::GNSS_ENABLED, &[enabled as u8]).await?;
        bool_echo(&authoritative, "PROP_GNSS_ENABLED")
    }

    /// Set whether fixes refresh the advertised node identity's location
    /// (`PROP_GNSS_IDENT_UPDATE`).
    pub async fn set_gnss_ident_update(&mut self, enabled: bool) -> Result<bool, UlcpError> {
        let authoritative = self
            .set_prop(prop::GNSS_IDENT_UPDATE, &[enabled as u8])
            .await?;
        bool_echo(&authoritative, "PROP_GNSS_IDENT_UPDATE")
    }

    /// Set the precision the advertised location is clamped to, in
    /// location bytes (`PROP_GNSS_IDENT_PRECISION`).
    pub async fn set_gnss_ident_precision(&mut self, precision: u8) -> Result<u8, UlcpError> {
        let authoritative = self
            .set_prop(prop::GNSS_IDENT_PRECISION, &[precision])
            .await?;
        authoritative
            .first()
            .copied()
            .ok_or(UlcpError::Protocol("empty PROP_GNSS_IDENT_PRECISION"))
    }

    /// Set whether receiver-derived time may set the wall clock
    /// (`PROP_GNSS_TIME_TRUST`).
    ///
    /// Clearing it leaves a manually-set clock proof against a jammed or
    /// spoofed sky; position reporting is unaffected.
    pub async fn set_gnss_time_trust(&mut self, trust: bool) -> Result<bool, UlcpError> {
        let authoritative = self.set_prop(prop::GNSS_TIME_TRUST, &[trust as u8]).await?;
        bool_echo(&authoritative, "PROP_GNSS_TIME_TRUST")
    }

    async fn initialize(&mut self) -> Result<(), UlcpError> {
        // Opening the transport is what attached us; the notice for that
        // is ours, and would otherwise fail the handshake it belongs to.
        self.expected_session_reset = Some(SessionResetReason::Attached);
        // The reset-status property is deliberately read before CMD_RST. The
        // protocol requires the device to retain its hardware boot cause for this
        // first query; CMD_RST would replace it with RESET_SOFTWARE.
        self.read_boot_status().await?;
        // A boot announcement still latched would otherwise be taken for
        // the answer to the CMD_RST below.
        self.absorb_latched_attach_notices();

        // Reset and wait for the reset notification. The TID is
        // ignored for CMD_RST; the notification is unsolicited.
        let deadline = Instant::now() + self.config.response_timeout;
        self.send_reset(deadline).await?;

        // Reject devices speaking an incompatible protocol revision.
        let version = absorbing_attach_notices!(self, self.get_prop(prop::PROTOCOL_VERSION))?;
        check_protocol_version(&version)?;

        // The rest describes the device, and a device that describes
        // itself badly is still one to attach to.
        self.dev_version = absorbent(absorbing_attach_notices!(
            self,
            self.get_prop(prop::DEV_VERSION)
        ))?
        .map(|value| decode_string(&value))
        .unwrap_or_default();
        self.dev_model = self.get_prop_string_opt(prop::DEV_MODEL).await;
        let mtu = absorbent(absorbing_attach_notices!(
            self,
            self.get_prop(prop::PHY_MTU)
        ))?;
        self.max_frame_size = decode_mtu(mtu.as_ref());

        let config = self.config.clone();
        self.set_prop(prop::PHY_FREQ, &config.freq_khz.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_LORA_BW, &config.bandwidth_hz.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_LORA_SF, &[config.spreading_factor])
            .await?;
        self.set_prop(prop::PHY_LORA_CR, &[config.coding_rate_denom])
            .await?;
        self.set_prop(prop::PHY_TX_POWER, &[config.tx_power_dbm as u8])
            .await?;
        self.set_prop(prop::PHY_LORA_SW, &config.sync_word.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_ENABLED, &[1]).await?;

        self.refresh_t_frame_or_keep().await?;
        self.absorb_latched_attach_notices();
        Ok(())
    }

    /// Refresh the PHY-independent airtime bound. Older devices lack the
    /// property, so read their live LoRa parameters rather than assuming the
    /// host's constructor configuration still describes the radio.
    ///
    /// Fails when the device would not say, or said something unusable;
    /// the handle's own transmits do not depend on that (see
    /// [`Self::refresh_t_frame_or_keep`]).
    pub async fn refresh_t_frame(&mut self) -> Result<u32, UlcpError> {
        const MALFORMED: UlcpError = UlcpError::Protocol("malformed PHY timing");
        let duration = match self.get_prop(prop::PHY_T_FRAME).await {
            Ok(value) => decode_u32_prefix(&value).ok_or(MALFORMED)?,
            Err(UlcpError::Status(Status::PROP_NOT_FOUND | Status::UNIMPLEMENTED)) => {
                let bw = self.get_prop(prop::PHY_LORA_BW).await?;
                let sf = self.get_prop(prop::PHY_LORA_SF).await?;
                let cr = self.get_prop(prop::PHY_LORA_CR).await?;
                let mtu = self.get_prop(prop::PHY_MTU).await?;
                let bw = decode_u32_prefix(&bw).ok_or(MALFORMED)?;
                let (Some(&sf), Some(&cr), [lo, hi, ..]) = (sf.first(), cr.first(), &mtu[..])
                else {
                    return Err(MALFORMED);
                };
                let mtu = u16::from_le_bytes([*lo, *hi]);
                if bw == 0 || mtu == 0 || !(5..=12).contains(&sf) || !(5..=8).contains(&cr) {
                    return Err(UlcpError::Protocol("invalid legacy PHY parameters"));
                }
                // Existing UMSH firmware uses a fixed 32-symbol TX preamble.
                // This compatibility estimate is only needed before T_FRAME.
                umsh_ulcp::airtime::lora_airtime_ms_with_preamble(sf, bw, cr, usize::from(mtu), 32)
            }
            Err(error) => return Err(error),
        };
        if duration == 0 {
            return Err(UlcpError::Protocol("zero PROP_PHY_T_FRAME"));
        }
        self.t_frame_ms = duration;
        Ok(duration)
    }

    /// Refresh the frame airtime, or keep the one in hand when the device
    /// cannot supply a usable one: the last good reading, or
    /// [`conservative_t_frame_ms`] before there has been one.
    ///
    /// What this feeds is a transmit deadline, and a stale or pessimistic
    /// one costs only waiting. Refusing to transmit because a timing read
    /// failed would cost the frame—and, for a caller that treats a
    /// transmit error as fatal, the whole session. Only what says the
    /// link or the session itself is in trouble still fails, because the
    /// transmit could not succeed past it either and a swallowed reset
    /// notice is a lost one.
    async fn refresh_t_frame_or_keep(&mut self) -> Result<u32, UlcpError> {
        let refreshed = match self.refresh_t_frame().await {
            // Slow to answer is not gone: the transmit itself says which,
            // and the late answer is dropped as stale.
            Err(UlcpError::Timeout) => None,
            result => absorbent(result)?,
        };
        match refreshed {
            Some(duration) => Ok(duration),
            None => {
                if self.t_frame_ms == 0 {
                    self.t_frame_ms = conservative_t_frame_ms(self.max_frame_size);
                }
                Ok(self.t_frame_ms)
            }
        }
    }

    fn transmit_timeout(&self) -> Duration {
        self.config
            .response_timeout
            .max(Duration::from_secs(3))
            .max(Duration::from_millis(u64::from(self.t_frame_ms) * 2))
    }

    /// Fetch a property's raw value via `CMD_PROP_GET`.
    pub async fn get_prop(&mut self, key: u32) -> Result<Vec<u8>, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len =
            frame::prop_get(&mut buf, tid, key).map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, key, PropResponsePolicy::Value)
            .await
    }

    /// Typed optional battery diagnostics. Each property retains not-found,
    /// unavailable, failed, or valid state. Wire codecs are shared with firmware.
    pub async fn battery_diagnostics(
        &mut self,
        keys: &[u32],
    ) -> Result<Vec<Result<Option<umsh_ulcp::battery_diagnostics::Value>, Status>>, UlcpError> {
        use umsh_ulcp::battery_diagnostics::{Value, index};
        if keys.iter().any(|key| index(*key).is_none()) {
            return Err(UlcpError::Protocol("not a battery diagnostic property"));
        }
        let values = self.read_each(keys).await?;
        Ok(keys
            .iter()
            .zip(values)
            .map(|(&key, value)| value.and_then(|bytes| Value::decode(key, &bytes)))
            .collect())
    }

    /// Fetch an OPTIONAL string property, treating a refusal as absence.
    ///
    /// A device that does not implement the property answers with an
    /// error status rather than a value, which is a legitimate answer and
    /// not a transport failure—so this collapses both to `None`. Only
    /// for properties the spec marks OPTIONAL; a REQUIRED one that
    /// refuses is a real fault and should stay an `Err`.
    async fn get_prop_string_opt(&mut self, key: u32) -> Option<String> {
        let value = self.get_prop(key).await.ok()?;
        Some(decode_string(&value))
    }

    /// Fetch one property for a reader that can do without it: `None`
    /// when the device refused it or answered with something else (see
    /// [`absorbent`]). The link failing, or the session, is still an
    /// error.
    async fn get_optional(&mut self, key: u32) -> Result<Option<Vec<u8>>, UlcpError> {
        absorbent(self.get_prop(key).await)
    }

    /// Set a property via `CMD_PROP_SET`, returning the authoritative
    /// value echoed by the device.
    pub async fn set_prop(&mut self, key: u32, value: &[u8]) -> Result<Vec<u8>, UlcpError> {
        self.require_tethered(key)?;
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; value.len() + 8];
        let len = frame::prop_set(&mut buf, tid, key, value)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, key, PropResponsePolicy::Value)
            .await
    }

    /// Read several properties, in as few exchanges as the frame and
    /// reply budgets allow.
    ///
    /// One `CMD_PROP_MULTI_GET`, continued where the reply ran out of
    /// room, and split where the request itself would not fit a frame.
    /// Every position comes back either as a value or as the status
    /// standing in for one, so an OPTIONAL property's refusal reads as the
    /// answer it is rather than ending the whole read.
    ///
    /// `PROP_LAST_STATUS` must not appear in `keys`: a refused position
    /// is reported by putting that very property into it, so its value
    /// and a refusal are indistinguishable. Read it on its own.
    pub async fn read_each(
        &mut self,
        keys: &[u32],
    ) -> Result<Vec<Result<Vec<u8>, Status>>, UlcpError> {
        debug_assert!(
            !keys.contains(&prop::LAST_STATUS),
            "PROP_LAST_STATUS cannot share a multi-property read"
        );
        let mut answers: Vec<Result<Vec<u8>, Status>> = Vec::with_capacity(keys.len());
        while answers.len() < keys.len() {
            let remaining = self.keys_that_fit(&keys[answers.len()..]);
            let entries = self.get_props(remaining).await?;
            if entries.is_empty() {
                // Nothing usable came back—not even a first position—so
                // asking the same question again would get the same
                // answer forever. Break the batch up instead, as the mesh
                // path does: one property on its own still makes progress.
                let key = remaining[0];
                answers.push(match self.get_prop(key).await {
                    Ok(value) => Ok(value),
                    Err(UlcpError::Status(status)) => Err(status),
                    // An answer that does not fit the question is no
                    // value, from a device that could not say why.
                    Err(UlcpError::Protocol(_)) => Err(Status::FAILURE),
                    Err(error) => return Err(error),
                });
                continue;
            }
            // Every entry is the answer to the key at its position (see
            // `finish_multi_transaction`); whatever the reply did not reach
            // is asked for again.
            answers.extend(
                entries
                    .into_iter()
                    .map(|entry| entry.map(|(_, value)| value)),
            );
        }
        Ok(answers)
    }

    /// Read every one of `keys` in one batch, for a caller that needs them
    /// all: a refusal anywhere fails the read with the error a lone
    /// `CMD_PROP_GET` of that property would have raised.
    pub async fn read_all<const N: usize>(
        &mut self,
        keys: &[u32; N],
    ) -> Result<[Vec<u8>; N], UlcpError> {
        required_answers(self.read_each(keys).await?)
    }

    /// The longest leading run of `keys` one `CMD_PROP_MULTI_GET` frame
    /// can carry, and never less than one key.
    ///
    /// Before the attach handshake has learned the ceiling there is none
    /// to keep to; the handshake's own few keys are all that is asked
    /// then.
    fn keys_that_fit<'k>(&self, keys: &'k [u32]) -> &'k [u32] {
        // The frame's header and command octets.
        const FRAME_OVERHEAD: usize = 2;
        if self.max_frame_size == 0 {
            return keys;
        }
        let mut room = self.max_frame_size.saturating_sub(FRAME_OVERHEAD);
        let mut count = 0;
        for &key in keys {
            let len = pui::encoded_len(key);
            if len > room {
                break;
            }
            room -= len;
            count += 1;
        }
        &keys[..count.max(1)]
    }

    /// Read several properties in one exchange via
    /// `CMD_PROP_MULTI_GET`.
    ///
    /// Reading continues past failures: a property that could not be
    /// fetched occupies its own position as an `Err` carrying the status
    /// a lone `CMD_PROP_GET` would have produced. A device that answers
    /// with fewer entries than were requested ran out of room in the
    /// response; the caller reissues the remainder.
    ///
    /// Host-domain keys are not refused here. Reading one is not writing
    /// it: a local device answers an administrative handle's read the
    /// same way it answers a tethered one, and over the mesh the
    /// unreachable half of the property space refuses per position, as
    /// any other absent property does. Only writes are the host's alone,
    /// and [`Self::set_prop`] still says so.
    pub async fn get_props(&mut self, keys: &[u32]) -> Result<Vec<MultiValue>, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; keys.len() * pui::MAX_LEN + 8];
        let len = frame::prop_multi_get(&mut buf, tid, keys)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let timeout = self.property_timeout(keys.contains(&prop::BATTERY_GAUGE_CONFIG));
        self.finish_multi_transaction(tid, keys, timeout).await
    }

    /// Write several properties in order in one exchange via
    /// `CMD_PROP_MULTI_SET`.
    ///
    /// The device applies the writes strictly in order and stops at the
    /// first failure, so the returned entries cover a prefix of the
    /// request: each is either the authoritative value the device echoed
    /// or the status that ended the sequence. A short reply whose last
    /// entry succeeded means the device ran out of response space; the
    /// caller reissues the remainder.
    pub async fn set_props(
        &mut self,
        entries: &[(u32, Vec<u8>)],
    ) -> Result<Vec<MultiValue>, UlcpError> {
        let mut capacity = 8;
        for (key, value) in entries {
            self.require_tethered(*key)?;
            capacity += value.len() + pui::MAX_LEN * 2;
        }
        let borrowed: Vec<(u32, &[u8])> = entries
            .iter()
            .map(|(key, value)| (*key, value.as_slice()))
            .collect();
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; capacity];
        let len = frame::prop_multi_set(&mut buf, tid, &borrowed)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let keys: Vec<u32> = entries.iter().map(|(key, _)| *key).collect();
        self.finish_multi_transaction(tid, &keys, self.config.response_timeout)
            .await
    }

    /// Await the `CMD_PROP_ARE` answering a multi-property command and
    /// split it into per-position outcomes against the keys `requested`.
    ///
    /// The reading is [`umsh_ulcp::reply::entries`], shared with every
    /// other reader of a reply: an entry is attributed only to the key it
    /// names. One that names a different property, or will not parse,
    /// ends the reading there—what came before it stands, and the rest
    /// reads as unanswered, exactly as for a reply that ran out of room.
    /// One bad position costs the positions after it a second asking,
    /// never the whole batch.
    async fn finish_multi_transaction(
        &mut self,
        tid: u8,
        requested: &[u32],
        timeout: Duration,
    ) -> Result<Vec<MultiValue>, UlcpError> {
        let deadline = Instant::now() + timeout;
        let response = self.wait_response(tid, deadline).await?;
        match response.kind {
            ResponseKind::Are => {}
            // A device without `CAP_CMD_MULTI` answers the unrecognized
            // command with a plain status.
            ResponseKind::Is if response.key == prop::LAST_STATUS => {
                return Err(UlcpError::Status(decode_status(&response.value)));
            }
            _ => {
                return Err(UlcpError::Protocol(
                    "single-property response answering a multi-property command",
                ));
            }
        }
        let entries = umsh_ulcp::reply::entries(requested, &response.value)
            .map_err(|_| UlcpError::Protocol("malformed multi-property answer"))?;
        Ok(entries
            .map_while(Result::ok)
            // More answers than questions name nothing this caller asked.
            .take(requested.len())
            .map(|(key, answer)| match answer {
                umsh_ulcp::reply::Answer::Value(value) => Ok((key, value.to_vec())),
                umsh_ulcp::reply::Answer::Refused(status) => Err(status),
            })
            .collect())
    }

    /// Insert one item into a multi-value property via
    /// `CMD_PROP_INSERT`, returning the reported form of the inserted
    /// item from the correlated `CMD_PROP_INSERTED`.
    ///
    /// `item` is in the property's item form with no length prefix.
    /// A duplicate fails with `STATUS_ALREADY` unless the property
    /// defines replacement semantics (`PROP_HOST_PEER_KEYS`).
    pub async fn insert_prop_item(&mut self, key: u32, item: &[u8]) -> Result<Vec<u8>, UlcpError> {
        self.require_tethered(key)?;
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; item.len() + 8];
        let len = frame::prop_insert(&mut buf, tid, key, item)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_table_transaction(tid, key, ResponseKind::Inserted)
            .await
    }

    /// Remove one item from a multi-value property via
    /// `CMD_PROP_REMOVE`, returning the reported form of the removed
    /// item from the correlated `CMD_PROP_REMOVED`.
    ///
    /// `selector` is the property's documented remove selector. A
    /// missing item fails with `STATUS_ITEM_NOT_FOUND`.
    pub async fn remove_prop_item(
        &mut self,
        key: u32,
        selector: &[u8],
    ) -> Result<Vec<u8>, UlcpError> {
        self.require_tethered(key)?;
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; selector.len() + 8];
        let len = frame::prop_remove(&mut buf, tid, key, selector)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_table_transaction(tid, key, ResponseKind::Removed)
            .await
    }

    /// Send a payload-less command completed by a correlated
    /// `PROP_LAST_STATUS`.
    async fn status_only_command(
        &mut self,
        encode: fn(&mut [u8], u8) -> Result<usize, frame::WriteError>,
    ) -> Result<(), UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = encode(&mut buf, tid).map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::LAST_STATUS, PropResponsePolicy::StatusOnly)
            .await
            .map(|_| ())
    }

    /// Drain the device's inbound queue (`CMD_QUEUE_DRAIN`).
    ///
    /// Buffered frames are delivered as ordinary `CMD_STR_RECV` and land
    /// in the receive queue for [`Radio::poll_receive`]; this future
    /// resolves on the correlated completion status.
    pub async fn queue_drain(&mut self) -> Result<(), UlcpError> {
        self.queue_drain_with(|_data, _meta| {}).await
    }

    /// As [`Self::queue_drain`], invoking `on_frame` with each frame
    /// (data, trailing metadata bytes) delivered before completion—
    /// buffered and interleaved live frames alike. The callback sees
    /// **every** such frame: an device queue larger than this driver's
    /// bounded receive buffer drains losslessly through it. Frames are
    /// additionally queued for [`Radio::poll_receive`], where the
    /// bounded buffer's oldest-dropped policy still applies.
    pub async fn queue_drain_with(
        &mut self,
        mut on_frame: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len =
            frame::queue_drain(&mut buf, tid).map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;

        let deadline = Instant::now() + self.config.response_timeout;
        loop {
            while let Some(response) = self.responses.pop_front() {
                if response.tid != tid {
                    continue;
                }
                if response.kind == ResponseKind::Is && response.key == prop::LAST_STATUS {
                    let status = decode_status(&response.value);
                    return if status == Status::OK {
                        Ok(())
                    } else {
                        Err(UlcpError::Status(status))
                    };
                }
                return Err(UlcpError::Protocol("unexpected drain response"));
            }
            if let Some(error) = self.take_reset_notice() {
                return Err(error);
            }
            // Deliver at ingest time: each read that queued a stream
            // frame reports it immediately, so the callback cannot
            // miss frames the bounded receive buffer evicts mid-drain.
            if self.read_more(deadline).await? {
                let packet = self
                    .rx_queue
                    .back()
                    .expect("read_more reported a queued frame");
                on_frame(&packet.data, &packet.raw_meta);
            }
        }
    }

    /// Save the device's device and host domains to non-volatile storage
    /// (`CMD_SAVE`; requires `CAP_SAVE`).
    pub async fn save(&mut self) -> Result<(), UlcpError> {
        self.status_only_command(frame::save).await
    }

    /// Erase the device's saved snapshot and other persisted provisioning
    /// (`CMD_CLEAR`; base protocol, BLE bonds and pairing PIN exempt).
    pub async fn clear(&mut self) -> Result<(), UlcpError> {
        self.status_only_command(frame::clear).await
    }

    /// Reset the device (`CMD_RST`) and wait for the reset notification,
    /// returning the announced reset status. The device comes up as from
    /// a power cycle—restoring its saved snapshot when one exists,
    /// factory configuration otherwise. All session-scoped state and
    /// cached views are gone; follow with [`Self::sync`].
    pub async fn reset(&mut self) -> Result<Status, UlcpError> {
        let deadline = Instant::now() + self.config.response_timeout;
        self.send_reset(deadline).await
    }

    /// Factory-reset the device (`CMD_FACTORY_RESET`): erase ALL mutable
    /// state—saved provisioning, the device identity, BLE bonds, and the
    /// pairing PIN—and reboot to a blank factory state. Unlike
    /// [`Self::reset`] this sends no expectation of a reply and does not
    /// wait: the device wipes storage and reboots without responding, which
    /// drops the transport link. Treat the ensuing disconnect as
    /// completion; a caller that needs the radio again must re-open the
    /// transport and re-pair, since the bond it used is now gone.
    pub async fn factory_reset(&mut self) -> Result<(), UlcpError> {
        let mut buf = [0u8; 2];
        let len = frame::factory_reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        Ok(())
    }

    /// Restart the device (`CMD_REBOOT`; requires `CAP_REBOOT`): a power
    /// cycle that keeps every persisted journal, so the device comes back
    /// as itself with its saved configuration.
    ///
    /// `Ok(false)` means the device does not advertise `CAP_REBOOT` and
    /// nothing was sent—asked rather than sent-and-timed-out, because a
    /// device that *will* reboot answers nothing at all and waiting for
    /// silence cannot tell the two apart. When it does reboot, the link
    /// drops; treat the ensuing disconnect as completion.
    pub async fn reboot(&mut self) -> Result<bool, UlcpError> {
        if !self.capabilities().await?.contains(&cap::REBOOT) {
            return Ok(false);
        }
        let mut buf = [0u8; 2];
        let len = frame::reboot(&mut buf, TID_UNSOLICITED)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        Ok(true)
    }

    /// Enter bootloader DFU after receiving its successful status response.
    /// A dropped link or timeout never counts as confirmation.
    pub async fn enter_dfu(&mut self, mode: umsh_ulcp::DfuMode) -> Result<(), UlcpError> {
        // Whatever comes back from the bootloader may be another build.
        self.caps = None;
        let tid = self.alloc_tid();
        let mut buf = [0u8; 3];
        let len = frame::dfu(&mut buf, tid, Some(mode))
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::LAST_STATUS, PropResponsePolicy::StatusOnly)
            .await?;
        Ok(())
    }

    /// Announce the device now (`CMD_ANNOUNCE`; requires `CAP_ADVERT`):
    /// send an advertisement or a beacon, as a broadcast or on one of the
    /// device's own channels.
    ///
    /// `Ok(false)` means the device does not advertise `CAP_ADVERT` and
    /// nothing was sent. Otherwise the device answers once the
    /// announcement is queued for transmission—channel access and the
    /// duty limit decide later whether it reaches the air, exactly as for
    /// a scheduled announcement.
    pub async fn announce(&mut self, request: &Announcement) -> Result<bool, UlcpError> {
        if !self.capabilities().await?.contains(&cap::ADVERT) {
            return Ok(false);
        }
        let tid = self.alloc_tid();
        let mut buf = [0u8; 48];
        let len = frame::announce(&mut buf, tid, request)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::LAST_STATUS, PropResponsePolicy::StatusOnly)
            .await?;
        Ok(true)
    }

    /// The I2C buses a host may drive directly (`PROP_I2C_BUSES`;
    /// requires `CAP_I2C`), or `None` when the device has none.
    pub async fn i2c_buses(&mut self) -> Result<Option<Vec<I2cBus>>, UlcpError> {
        let value = match self.get_prop(prop::I2C_BUSES).await {
            Err(UlcpError::Status(Status::PROP_NOT_FOUND)) => return Ok(None),
            result => result?,
        };
        // An item this host cannot read is skipped and the rest kept; a
        // broken length prefix ends the list, since nothing after it can
        // be located (see `items::prefixed_items`).
        let buses = i2c::buses(&value)
            .filter_map(Result::ok)
            .map(|bus| I2cBus {
                bus: bus.bus,
                speed_khz: bus.speed_khz,
                max_data: bus.max_data,
                max_ops: bus.max_ops,
                name: bus.name.to_owned(),
            })
            .collect();
        Ok(Some(buses))
    }

    /// The peripherals the firmware knows to be on its buses
    /// (`PROP_I2C_DEVICES`; requires `CAP_I2C`), or `None` when the
    /// device has no bus at all. Returns the firmware's cached inventory;
    /// this query does not initiate identification or a scan.
    pub async fn i2c_devices(&mut self) -> Result<Option<Vec<I2cPeripheral>>, UlcpError> {
        let value = match self.get_prop(prop::I2C_DEVICES).await {
            Err(UlcpError::Status(Status::PROP_NOT_FOUND)) => return Ok(None),
            result => result?,
        };
        // Skipping what will not read, as for the bus table.
        let devices = i2c::devices(&value)
            .filter_map(Result::ok)
            .map(|device| I2cPeripheral {
                bus: device.bus,
                addr: device.addr,
                name: device.name.to_owned(),
            })
            .collect();
        Ok(Some(devices))
    }

    /// Perform one I2C transaction (`CMD_I2C_TRANSFER`; requires
    /// `CAP_I2C`) on `bus` with the 7-bit address `addr`: the operations
    /// in order, a repeated START on each change of direction, and one
    /// STOP at the end.
    ///
    /// Sends the transfer directly, without a capability or device-table
    /// query. `Ok(None)` means the device returned `STATUS_UNIMPLEMENTED`;
    /// `Ok(Some(data))` is the concatenated read data, empty for a
    /// write-only transfer. The device's refusals surface as statuses:
    /// `STATUS_NO_DEVICE` for an unacknowledged address, `STATUS_NACK`
    /// for a refused data octet, `STATUS_BUS_ERROR` for the bus itself,
    /// `STATUS_BUSY` when the bus or the peripheral is held, and
    /// `STATUS_NOMEM` when the read would not fit the binding's reply.
    pub async fn i2c_transfer(
        &mut self,
        bus: u8,
        addr: u8,
        ops: &[i2c::Op<'_>],
    ) -> Result<Option<Vec<u8>>, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; 4 + ops.iter().map(|op| op.wire_len()).sum::<usize>()];
        let len = i2c::encode_transfer(&mut buf, tid, bus, addr, ops)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        match self.finish_i2c_transaction(tid).await {
            Err(UlcpError::Status(Status::UNIMPLEMENTED)) => Ok(None),
            result => result.map(Some),
        }
    }

    /// Probe a range of 7-bit addresses on `bus` (`CMD_I2C_SCAN`;
    /// requires `CAP_I2C`), `None` for the default 0x08 through 0x77.
    ///
    /// Sends the scan directly, without a capability or device-table
    /// query. `Ok(None)` means the device returned `STATUS_UNIMPLEMENTED`;
    /// `Ok(Some(addresses))` lists what acknowledged, ascending. A probe
    /// is a one-octet read, which some peripherals treat as a real
    /// read, and one that does not acknowledge reads goes unreported,
    /// so the list is a hint rather than an inventory.
    pub async fn i2c_scan(
        &mut self,
        bus: u8,
        range: Option<(u8, u8)>,
    ) -> Result<Option<Vec<u8>>, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len = i2c::encode_scan(&mut buf, tid, bus, range)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        match self.finish_i2c_transaction(tid).await {
            Err(UlcpError::Status(Status::UNIMPLEMENTED)) => Ok(None),
            result => result.map(Some),
        }
    }

    /// Await the `CMD_I2C_RESULT` answering a transfer or a scan, or the
    /// status that refused it.
    async fn finish_i2c_transaction(&mut self, tid: u8) -> Result<Vec<u8>, UlcpError> {
        // A bus transaction waits on the device's own lock and deadline
        // before it answers, which can outlast the ordinary property
        // timeout.
        let deadline = Instant::now() + self.config.response_timeout + Duration::from_secs(3);
        let response = self.wait_response(tid, deadline).await?;
        match response.kind {
            ResponseKind::I2cResult => Ok(response.value),
            ResponseKind::Is if response.key == prop::LAST_STATUS => {
                Err(UlcpError::Status(decode_status(&response.value)))
            }
            _ => Err(UlcpError::Protocol(
                "property response answering an I2C command",
            )),
        }
    }

    /// Forget every Bluetooth bond, the pairing PIN, and the pairing
    /// lockout, then leave the device in a pairing window—the bond
    /// count written to zero (`PROP_BLE_BOND_COUNT`; requires `CAP_BLE`).
    ///
    /// `Ok(None)` means the device has no Bluetooth transport at all and
    /// nothing was sent; `Ok(Some(count))` quotes the count the device
    /// now holds. One that has a transport but does not manage its own
    /// bonds answers `STATUS_PROP_NOT_FOUND`, which surfaces as an error—
    /// the caps list stops at "has Bluetooth", so the refusal is where the
    /// rest of the answer lives.
    ///
    /// Over Bluetooth this severs the caller's own link—the bond that
    /// carried it is one of the bonds deleted—but the answer arrives
    /// first; over a cable and over the mesh nothing is disturbed.
    pub async fn clear_ble_bonds(&mut self) -> Result<Option<u8>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::BLE) {
            return Ok(None);
        }
        let value = self.set_prop(prop::BLE_BOND_COUNT, &[0]).await?;
        Ok(Some(value.first().copied().unwrap_or(0)))
    }

    /// Open or close the pairing window (`PROP_BLE_PAIRING`; requires
    /// `CAP_BLE`). Open, an unbonded host can pair without a gesture at
    /// the device; the window also closes by itself, on a new bond or a
    /// timeout, which is why it is a property a caller can read back
    /// rather than a command.
    ///
    /// `Ok(None)` means the device has no Bluetooth transport at all;
    /// `Ok(Some(state))` quotes the state the device settled on. A
    /// device that does not manage its own bonds answers
    /// `STATUS_PROP_NOT_FOUND`, and one that could not open a window
    /// right now—locked out, or with Bluetooth disabled—answers
    /// `STATUS_INVALID_STATE`; both surface as errors rather than a
    /// quiet success.
    pub async fn set_ble_pairing(&mut self, open: bool) -> Result<Option<bool>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::BLE) {
            return Ok(None);
        }
        let value = self.set_prop(prop::BLE_PAIRING, &[open as u8]).await?;
        Ok(Some(decode_bool(&value).unwrap_or(false)))
    }

    /// Revert the device to its saved snapshot (`CMD_RESTORE`; requires
    /// `CAP_SAVE`), accepting both spec-permitted completion forms.
    pub async fn restore(&mut self) -> Result<RestoreCompletion, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = frame::restore(&mut buf, tid).map_err(|_| UlcpError::Protocol("frame encode"))?;
        // The reset form of a restore discards session state; the notice
        // for it is ours, and lands after the announcement below.
        self.expected_session_reset = Some(SessionResetReason::Restored);
        self.send(&buf[..len]).await?;

        let deadline = Instant::now() + self.config.response_timeout;
        loop {
            while let Some(response) = self.responses.pop_front() {
                if response.tid != tid {
                    continue;
                }
                if response.kind == ResponseKind::Is && response.key == prop::LAST_STATUS {
                    let status = decode_status(&response.value);
                    // The updated form leaves session state alone, so
                    // there is no notice coming after all.
                    self.expected_session_reset = None;
                    return if status == Status::OK {
                        Ok(RestoreCompletion::Updated)
                    } else {
                        Err(UlcpError::Status(status))
                    };
                }
                self.expected_session_reset = None;
                return Err(UlcpError::Protocol("unexpected restore response"));
            }
            if self.seen_reset == Some(Status::RESET_RESTORED) {
                self.seen_reset = None;
                return Ok(RestoreCompletion::Reset);
            }
            if let Some(error) = self.take_reset_notice() {
                return Err(error);
            }
            self.read_more(deadline).await?;
        }
    }

    /// Set or clear the device's persisted, write-only BLE pairing PIN.
    ///
    /// This property is the protocol's sole status-only property write: the
    /// value is never echoed. `None` clears the configured passkey.
    pub async fn set_ble_pairing_pin(&mut self, pin: Option<u32>) -> Result<(), UlcpError> {
        if pin.is_some_and(|pin| pin > 999_999) {
            return Err(UlcpError::Protocol("BLE pairing PIN out of range"));
        }
        let tid = self.alloc_tid();
        let value = pin.map(u32::to_le_bytes);
        let mut buf = [0u8; 12];
        let len = frame::prop_set(
            &mut buf,
            tid,
            prop::BLE_PAIRING_PIN,
            value.as_ref().map_or(&[], |value| &value[..]),
        )
        .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::BLE_PAIRING_PIN, PropResponsePolicy::StatusOnly)
            .await
            .map(|_| ())
    }

    /// The device's capability list (`PROP_CAPS`), read at most once per
    /// handle.
    pub async fn capabilities(&mut self) -> Result<Vec<u32>, UlcpError> {
        if let Some(caps) = &self.caps {
            return Ok(caps.clone());
        }
        let caps = decode_capabilities(&self.get_prop(prop::CAPS).await?);
        self.caps = Some(caps.clone());
        Ok(caps)
    }

    /// The capability list, if this handle has already read it.
    ///
    /// For a caller planning a batch: knowing the list already, it asks
    /// for exactly what it needs; not knowing it, it can have the list
    /// ride along with [`Self::read_each_with_capabilities`] rather than
    /// spend an exchange learning it first.
    pub fn cached_capabilities(&self) -> Option<&[u32]> {
        self.caps.as_deref()
    }

    /// Read `keys` together with the capability list that decides what
    /// they mean.
    ///
    /// When the list is not yet known, `PROP_CAPS` rides at the end of
    /// the same batch rather than costing an exchange of its own. Over the
    /// mesh that is the difference between one exchange and two for every
    /// gated read. A key the device lacks the capability for comes back
    /// refused in its position, which costs a few octets and asks the
    /// device nothing it cannot answer.
    ///
    /// The list goes last so that, should the answer ever be cut across
    /// two exchanges, the entry straddling the cut is the one value that
    /// cannot have changed in between.
    pub async fn read_each_with_capabilities(
        &mut self,
        keys: &[u32],
    ) -> Result<(Vec<u32>, Vec<Result<Vec<u8>, Status>>), UlcpError> {
        if let Some(caps) = self.caps.clone() {
            return Ok((caps, self.read_each(keys).await?));
        }
        let mut batch = keys.to_vec();
        batch.push(prop::CAPS);
        let mut answers = self.read_each(&batch).await?;
        let raw = answers
            .pop()
            .ok_or(UlcpError::Protocol("short multi-property answer"))?
            .map_err(UlcpError::Status)?;
        let caps = decode_capabilities(&raw);
        self.caps = Some(caps.clone());
        Ok((caps, answers))
    }

    /// Read `keys` if the device advertises `capability`, or `None` if it
    /// does not—in one exchange either way.
    async fn read_gated(
        &mut self,
        capability: u32,
        keys: &[u32],
    ) -> Result<Option<Vec<Result<Vec<u8>, Status>>>, UlcpError> {
        // Known not to be there: nothing to ask at all.
        if self
            .caps
            .as_ref()
            .is_some_and(|caps| !caps.contains(&capability))
        {
            return Ok(None);
        }
        let (caps, answers) = self.read_each_with_capabilities(keys).await?;
        Ok(caps.contains(&capability).then_some(answers))
    }

    /// Run the spec's post-attach synchronization procedure: fetch the
    /// retained `PROP_LAST_STATUS` (detecting a reset since the last
    /// contact), the capability list, the configured host identity—
    /// yielding an ownership verdict against `expected_host_key`—and
    /// the state each advertised capability grants, all in digest form.
    ///
    /// The host must decide ownership before treating queued data as
    /// its own: [`HostOwnership::OtherHost`] means the queue and
    /// provisioning belong to another identity.
    pub async fn sync(
        &mut self,
        expected_host_key: Option<&[u8; 32]>,
    ) -> Result<DeviceSync, UlcpError> {
        // Step 1: the retained status, before any other command can
        // overwrite a reset code.
        let last_status = decode_status(&self.get_prop(prop::LAST_STATUS).await?);
        let capabilities = self.capabilities().await?;
        let has = |capability: u32| capabilities.contains(&capability);

        // Everything after the capability list is one property apiece,
        // and none of them is worth the rest: a property the device
        // refuses, or answers in a form this host cannot read, is `None`
        // in the report and the procedure carries on. Only the link or
        // the session failing ends it.

        // Step 2: ownership. A key this host cannot compare is not known
        // to be ours, which is all ownership needs to say.
        let (host_key, ownership) = if has(cap::HOST_FILTER) {
            match self.get_optional(prop::HOST_KEY).await? {
                Some(value) if value.is_empty() => (None, HostOwnership::Unclaimed),
                Some(value) => match <[u8; 32]>::try_from(value.as_slice()) {
                    Ok(key) => {
                        let ownership = match expected_host_key {
                            Some(expected) if *expected == key => HostOwnership::Ours,
                            _ => HostOwnership::OtherHost(key),
                        };
                        (Some(key), ownership)
                    }
                    Err(_) => (None, HostOwnership::Unknown),
                },
                None => (None, HostOwnership::Unknown),
            }
        } else {
            (None, HostOwnership::Unsupported)
        };

        // Step 3: the device-domain and host-domain state we depend
        // on, gated by the advertised capabilities.
        let phy_enabled = self
            .get_optional(prop::PHY_ENABLED)
            .await?
            .and_then(|value| decode_bool(&value));
        let freq_khz = self
            .get_optional(prop::PHY_FREQ)
            .await?
            .and_then(|value| decode_u32_prefix(&value));
        let device_name = self
            .get_optional(prop::DEV_NAME)
            .await?
            .map(|value| decode_string(&value));
        let saved = match has(cap::SAVE) {
            true => self
                .get_optional(prop::SAVED)
                .await?
                .and_then(|value| SavedSnapshot::from_octet(&value)),
            false => None,
        };
        let (queue_count, queue_dropped) = if has(cap::HOST_RX_QUEUE) {
            let count = self.get_optional(prop::HOST_RX_QUEUE_COUNT).await?;
            let dropped = self.get_optional(prop::HOST_RX_QUEUE_DROPPED).await?;
            (
                count.and_then(|value| Some(u16::from_le_bytes(*value.first_chunk()?))),
                dropped.and_then(|value| decode_u32_prefix(&value)),
            )
        } else {
            (None, None)
        };
        let filters = match has(cap::HOST_FILTER) {
            true => self
                .get_optional(prop::HOST_RX_FILTERS)
                .await?
                .map(|value| decode_filter_table(&value)),
            false => None,
        };
        let (host_channel_ids, host_peer_keys) = if has(cap::HOST_KEYS) {
            (
                self.get_optional(prop::HOST_CHANNEL_KEYS)
                    .await?
                    .map(|value| decode_fixed_list::<{ items::CHANNEL_IDENTIFIER_LEN }>(&value)),
                self.get_optional(prop::HOST_PEER_KEYS)
                    .await?
                    .map(|value| decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>(&value)),
            )
        } else {
            (None, None)
        };
        let auto_ack = match has(cap::HOST_AUTO_ACK) {
            true => self
                .get_optional(prop::HOST_AUTO_ACK)
                .await?
                .and_then(|value| decode_bool(&value)),
            false => None,
        };
        // An unreadable identity reads as none known, as an empty one does.
        let dev_key = match has(cap::DEV_IDENTITY) {
            true => self
                .get_optional(prop::DEV_KEY)
                .await?
                .and_then(|value| <[u8; 32]>::try_from(value.as_slice()).ok()),
            false => None,
        };

        Ok(DeviceSync {
            reset_since_last_contact: last_status.is_reset(),
            last_status,
            capabilities,
            ownership,
            host_key,
            phy_enabled,
            freq_khz,
            device_name,
            saved,
            queue_count,
            queue_dropped,
            filters,
            host_channel_ids,
            host_peer_keys,
            auto_ack,
            dev_key,
        })
    }

    /// Establish `desired` as the device's complete host domain,
    /// writing every part of it unconditionally.
    ///
    /// **This does not compare and patch, and that is deliberate.** Key
    /// tables read back in lossy form only: the device reports channel
    /// identifiers and peer public keys, never key material. An
    /// administrator can replace a peer's `K_enc`/`K_mic` without
    /// changing anything observable, so no comparison over the readable
    /// surface can detect it—and a digest over the secret state would
    /// mean deriving a readable value from key material, which is worse
    /// than the problem. The host asserts what it wants; it does not
    /// reason about what the device already holds.
    ///
    /// Removals still come from comparison, and that is not a
    /// contradiction: *membership* is readable even though key material
    /// is not. So this reads the digest lists, removes what `desired`
    /// omits, and writes everything `desired` contains regardless of
    /// what came back.
    ///
    /// The host domain is volatile across power cycles, so the usual
    /// case is a device that has just rebooted and holds nothing. When
    /// it has *not* rebooted the rewrite is redundant—that is the
    /// point. Correctness must not depend on detecting which case this
    /// is, because reboot detection would also have to cover partial
    /// provisioning, another administrator having intervened, and future
    /// device behavior changes.
    ///
    /// Each individual write is transactional on the device (spec
    /// §Mutation Atomicity); the *sequence* is not (see the ULCP
    /// transition plan, decision 7). An interrupted call leaves a
    /// mixture, which the next call repairs by rewriting everything.
    ///
    /// Provisioning is per item rather than per table wherever the table
    /// can grow: a whole peer table stops fitting in a frame at the
    /// fifth entry.
    pub async fn provision(
        &mut self,
        desired: &HostProvisioning,
    ) -> Result<ProvisionReport, UlcpError> {
        self.require_tethered(prop::HOST_KEY)?;
        let mut report = ProvisionReport::default();
        let current_key = self.get_prop(prop::HOST_KEY).await?;
        // A host-key write to a different value resets the whole host
        // domain on the device, so everything below lands on an empty
        // one; writing the same key is idempotent and has no effect.
        if current_key.as_slice() != desired.host_key.as_slice() {
            report.host_replaced = true;
        }
        self.set_prop(prop::HOST_KEY, &desired.host_key).await?;

        // Filters: item and digest forms are identical and the whole
        // table is small, so one atomic write says everything.
        let mut table = Vec::new();
        for filter in &desired.filters {
            let mut item = [0u8; items::Filter::MAX_WIRE_LEN];
            let item_len = filter
                .encode(&mut item)
                .map_err(|_| UlcpError::Protocol("filter encode"))?;
            let mut prefixed = [0u8; items::Filter::MAX_WIRE_LEN + 2];
            let prefixed_len = items::encode_prefixed_item(&item[..item_len], &mut prefixed)
                .map_err(|_| UlcpError::Protocol("filter encode"))?;
            table.extend_from_slice(&prefixed[..prefixed_len]);
        }
        self.set_prop(prop::HOST_RX_FILTERS, &table).await?;
        report.filters_replaced = true;

        // Channel keys: the remove selector is the key itself, which we
        // hold for everything we want and not for anything we do not, so
        // shedding an unknown channel needs the whole-table form. That
        // table is bounded and small enough to send.
        let engine = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let desired_ids: Vec<[u8; items::CHANNEL_IDENTIFIER_LEN]> = desired
            .channel_keys
            .iter()
            .map(|key| engine.derive_channel_tag(&ChannelKey(*key)).0)
            .collect();
        // A listing with a ragged tail holds something this host cannot
        // name, which is as good a reason to replace the table as an
        // identifier it does not want.
        let (current_ids, ragged) = if report.host_replaced {
            (Vec::new(), false)
        } else {
            let listing = self.get_prop(prop::HOST_CHANNEL_KEYS).await?;
            (
                decode_fixed_list::<{ items::CHANNEL_IDENTIFIER_LEN }>(&listing),
                listing.len() % items::CHANNEL_IDENTIFIER_LEN != 0,
            )
        };
        if ragged || current_ids.iter().any(|id| !desired_ids.contains(id)) {
            let table: Vec<u8> = desired.channel_keys.concat();
            self.set_prop(prop::HOST_CHANNEL_KEYS, &table).await?;
            report.channels_replaced = true;
        } else {
            // Insert every desired key, including ones already reported.
            // A channel key *is* its own item, so a duplicate insert
            // asserts a state that already holds: `STATUS_ALREADY` says
            // "the entry is present", which is what was asked for, and
            // is treated as success. (Peers differ—a matching public
            // key replaces the entry's key material—so their inserts
            // never report it.)
            for key in &desired.channel_keys {
                match self.insert_prop_item(prop::HOST_CHANNEL_KEYS, key).await {
                    Ok(_) => report.channels_inserted += 1,
                    Err(UlcpError::Status(Status::ALREADY)) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        // Peers: remove by comparison over the readable public keys,
        // then insert every desired entry unconditionally. The device
        // reconciles rather than rebuilding, so re-inserting a peer it
        // already holds preserves that peer's replay baseline.
        let current_peers = if report.host_replaced {
            Vec::new()
        } else {
            // Only whole keys can be removed by name; a ragged tail is
            // nothing a selector could match.
            decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>(
                &self.get_prop(prop::HOST_PEER_KEYS).await?,
            )
        };
        for existing in &current_peers {
            if !desired
                .peer_keys
                .iter()
                .any(|entry| entry.public_key == *existing)
            {
                self.remove_prop_item(prop::HOST_PEER_KEYS, existing)
                    .await?;
                report.peers_removed += 1;
            }
        }
        for entry in &desired.peer_keys {
            let mut item = [0u8; items::PeerKeyEntry::WIRE_LEN];
            entry
                .encode(&mut item)
                .map_err(|_| UlcpError::Protocol("peer entry encode"))?;
            self.insert_prop_item(prop::HOST_PEER_KEYS, &item).await?;
            report.peers_inserted += 1;
        }

        // Delegation policy last, once the keys it depends on exist.
        self.set_prop(prop::HOST_AUTO_ACK, &[desired.auto_ack as u8])
            .await?;
        report.auto_ack_changed = true;
        Ok(report)
    }

    /// The device's device identity public key, generating one on-device
    /// if none is configured (`CAP_DEV_IDENTITY`; generation requires
    /// the transport's provisioning-security binding).
    ///
    /// On-device generation is the spec-recommended form: the private
    /// key never exists anywhere but the radio, and only the resulting
    /// public key crosses the link.
    pub async fn ensure_device_identity(&mut self) -> Result<[u8; 32], UlcpError> {
        let current = self.get_prop(prop::DEV_KEY).await?;
        if let Ok(key) = <[u8; 32]>::try_from(current.as_slice()) {
            return Ok(key);
        }
        if !current.is_empty() {
            return Err(UlcpError::Protocol("malformed PROP_DEV_KEY"));
        }
        // An empty PROP_DEV_PRIVATE_KEY write commands generation;
        // success is announced as PROP_IS for PROP_DEV_KEY carrying
        // the new public key.
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len = frame::prop_set(&mut buf, tid, prop::DEV_PRIVATE_KEY, &[])
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let value = self
            .finish_prop_transaction(tid, prop::DEV_KEY, PropResponsePolicy::Value)
            .await?;
        <[u8; 32]>::try_from(value.as_slice())
            .map_err(|_| UlcpError::Protocol("malformed PROP_DEV_KEY"))
    }

    fn property_timeout(&self, gauge_config: bool) -> Duration {
        // Gauge access cleanup can outlast the ordinary telemetry deadline.
        self.config.response_timeout
            + if gauge_config {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            }
    }

    async fn finish_prop_transaction(
        &mut self,
        tid: u8,
        key: u32,
        policy: PropResponsePolicy,
    ) -> Result<Vec<u8>, UlcpError> {
        let deadline = Instant::now() + self.property_timeout(key == prop::BATTERY_GAUGE_CONFIG);
        let response = self.wait_response(tid, deadline).await?;
        if response.kind != ResponseKind::Is {
            return Err(UlcpError::Protocol(
                "table notification answering a property command",
            ));
        }
        match (policy, response.key) {
            (PropResponsePolicy::Value, response_key) if response_key == key => Ok(response.value),
            (PropResponsePolicy::StatusOnly, prop::LAST_STATUS) => {
                let status = decode_status(&response.value);
                if status == Status::OK {
                    Ok(Vec::new())
                } else {
                    Err(UlcpError::Status(status))
                }
            }
            (PropResponsePolicy::Value, prop::LAST_STATUS) => {
                let status = decode_status(&response.value);
                if status == Status::OK {
                    Err(UlcpError::Protocol(
                        "unexpected status-only property response",
                    ))
                } else {
                    Err(UlcpError::Status(status))
                }
            }
            _ => Err(UlcpError::Protocol("response for unexpected property")),
        }
    }

    /// Complete a `CMD_PROP_INSERT`/`CMD_PROP_REMOVE` transaction:
    /// success is the matching item notification carrying the digest,
    /// failure a correlated `PROP_LAST_STATUS`.
    async fn finish_table_transaction(
        &mut self,
        tid: u8,
        key: u32,
        expected: ResponseKind,
    ) -> Result<Vec<u8>, UlcpError> {
        let deadline = Instant::now() + self.config.response_timeout;
        let response = self.wait_response(tid, deadline).await?;
        match (response.kind, response.key) {
            (kind, response_key) if kind == expected && response_key == key => Ok(response.value),
            (ResponseKind::Is, prop::LAST_STATUS) => {
                let status = decode_status(&response.value);
                if status == Status::OK {
                    Err(UlcpError::Protocol(
                        "status-only success for a table mutation",
                    ))
                } else {
                    Err(UlcpError::Status(status))
                }
            }
            _ => Err(UlcpError::Protocol("response for unexpected property")),
        }
    }

    fn alloc_tid(&mut self) -> u8 {
        self.tids.allocate()
    }

    /// Sort a complete ULCP frame into the receive queue, response queue,
    /// or the reset flag; returns whether a stream frame was queued
    /// (the back of `rx_queue` is then the new packet). Malformed
    /// frames are dropped.
    fn ingest_frame(&mut self, frame_bytes: &[u8]) -> bool {
        if let Some(trace) = &mut self.trace {
            trace(TraceDirection::DeviceToHost, &describe_frame(frame_bytes));
        }
        let Ok(frame) = Frame::parse(frame_bytes) else {
            return false;
        };
        match frame.command() {
            Some(Cmd::StrRecv) => {
                let Ok(payload) = StreamPayload::parse(frame.payload) else {
                    return false;
                };
                if payload.stream != stream::PHY_RAW {
                    return false;
                }
                let meta = RxMeta::decode(payload.metadata).unwrap_or_default();
                if self.rx_queue.len() >= RX_QUEUE_DEPTH {
                    self.rx_queue.pop_front();
                }
                self.rx_queue.push_back(RxPacket {
                    data: payload.data.to_vec(),
                    meta,
                    raw_meta: payload.metadata.to_vec(),
                });
                return true;
            }
            Some(Cmd::PropIs) => self.ingest_prop_notification(ResponseKind::Is, &frame),
            Some(Cmd::PropInserted) => {
                self.ingest_prop_notification(ResponseKind::Inserted, &frame)
            }
            Some(Cmd::PropRemoved) => self.ingest_prop_notification(ResponseKind::Removed, &frame),
            // `CMD_PROP_ARE` carries entries rather than one key and
            // value, so it is queued whole—the frame itself, which is
            // what the shared reply reader takes—and decoded by whichever
            // multi-property transaction is waiting on the TID. It is
            // never unsolicited, so a TID-0 one is dropped.
            Some(Cmd::PropAre) => {
                let tid = frame.header.tid();
                if tid != TID_UNSOLICITED {
                    if self.responses.len() >= RESPONSE_QUEUE_DEPTH {
                        self.responses.pop_front();
                    }
                    self.responses.push_back(Response {
                        tid,
                        kind: ResponseKind::Are,
                        key: prop::LAST_STATUS,
                        value: frame_bytes.to_vec(),
                    });
                }
            }
            // The answer to a transfer or a scan: bytes rather than a
            // property, queued whole for the transaction waiting on the
            // TID. Never unsolicited, so a TID-0 one is dropped.
            Some(Cmd::I2cResult) => {
                let tid = frame.header.tid();
                if tid != TID_UNSOLICITED {
                    if self.responses.len() >= RESPONSE_QUEUE_DEPTH {
                        self.responses.pop_front();
                    }
                    self.responses.push_back(Response {
                        tid,
                        kind: ResponseKind::I2cResult,
                        key: prop::LAST_STATUS,
                        value: frame.payload.to_vec(),
                    });
                }
            }
            // The device discarded session state. One we asked for is
            // absorbed—the caller who asked is already rebuilding the
            // session; anything else is surfaced as an error.
            Some(Cmd::SessionReset) => {
                let Ok(reason) = parse_session_reset(frame.payload) else {
                    return false;
                };
                if self.expected_session_reset == Some(reason) {
                    self.expected_session_reset = None;
                    return false;
                }
                self.seen_session_reset = Some(reason);
            }
            _ => {}
        }
        false
    }

    fn ingest_prop_notification(&mut self, kind: ResponseKind, frame: &Frame<'_>) {
        let Ok(notification) = PropertyNotification::from_frame(frame) else {
            return;
        };
        // The caller dispatches from the parsed command; keep that assertion
        // explicit so future command additions cannot be misclassified.
        if notification.kind != kind {
            return;
        }
        let tid = notification.tid;
        if tid != TID_UNSOLICITED {
            if self.responses.len() >= RESPONSE_QUEUE_DEPTH {
                self.responses.pop_front();
            }
            self.responses.push_back(Response {
                tid,
                kind,
                key: notification.key,
                value: notification.value.to_vec(),
            });
            return;
        }
        // Unsolicited `PROP_LAST_STATUS` is a reset notice or an
        // operation status, not a property update to retain.
        if kind == ResponseKind::Is && notification.key == prop::LAST_STATUS {
            let status = decode_status(notification.value);
            if status.is_reset() {
                self.seen_reset = Some(status);
            }
            return;
        }
        let event = match kind {
            ResponseKind::Is => PropEvent::Is {
                key: notification.key,
                value: notification.value.to_vec(),
            },
            ResponseKind::Inserted => PropEvent::Inserted {
                key: notification.key,
                digest: notification.value.to_vec(),
            },
            ResponseKind::Removed => PropEvent::Removed {
                key: notification.key,
                digest: notification.value.to_vec(),
            },
            // Unreachable: `PropertyNotification` refuses the forms that
            // carry no key, and this path only sees notifications it
            // parsed.
            ResponseKind::Are | ResponseKind::I2cResult => return,
        };
        if self.prop_events.len() >= PROP_EVENT_DEPTH {
            self.prop_events.pop_front();
        }
        self.prop_events.push_back(event);
    }

    /// Take whichever unsolicited loss-of-state notice is latched, as the
    /// error the caller should see.
    ///
    /// A device reset is reported ahead of a session reset when both are
    /// pending: it is the broader loss—the host domain went with it—
    /// and a reboot implies the session reset that follows the reattach.
    fn take_reset_notice(&mut self) -> Option<UlcpError> {
        if let Some(status) = self.seen_reset.take() {
            // The reboot took the session with it; one report is enough.
            self.seen_session_reset = None;
            return Some(UlcpError::UnexpectedReset(status));
        }
        self.seen_session_reset.take().map(UlcpError::SessionReset)
    }

    /// Take the oldest retained unsolicited property notification.
    ///
    /// Events accumulate while other calls read from the link (bounded
    /// at [`PROP_EVENT_DEPTH`], oldest dropped first).
    pub fn pop_prop_event(&mut self) -> Option<PropEvent> {
        self.prop_events.pop_front()
    }

    /// Read from the stream until the response for `tid` arrives.
    ///
    /// Frames received meanwhile are queued for [`Radio::poll_receive`].
    async fn wait_response(&mut self, tid: u8, deadline: Instant) -> Result<Response, UlcpError> {
        loop {
            // Drain responses before honoring a loss-of-state notice: if
            // both arrived in one read, the response was sent first and
            // the command did complete. The notice stays latched for the
            // next receive poll.
            while let Some(response) = self.responses.pop_front() {
                if response.tid == tid {
                    return Ok(response);
                }
                // A stale response from an earlier timed-out
                // transaction; drop it.
            }
            if let Some(error) = self.take_reset_notice() {
                return Err(error);
            }
            self.read_more(deadline).await?;
        }
    }

    /// Read until the device announces a reset via `PROP_LAST_STATUS`.
    async fn wait_reset(&mut self, deadline: Instant) -> Result<Status, UlcpError> {
        loop {
            if let Some(status) = self.seen_reset.take() {
                return Ok(status);
            }
            // Accept a reset notice even if the device attached a TID.
            while let Some(response) = self.responses.pop_front() {
                if response.kind == ResponseKind::Is && response.key == prop::LAST_STATUS {
                    let status = decode_status(&response.value);
                    if status.is_reset() {
                        return Ok(status);
                    }
                }
            }
            self.read_more(deadline).await?;
        }
    }

    /// Send `CMD_RST` and wait for the device to announce it.
    ///
    /// The session reset that follows is ours, and lands after the
    /// announcement—commonly during the next exchange—so the
    /// expectation is recorded here rather than waited on.
    async fn send_reset(&mut self, deadline: Instant) -> Result<Status, UlcpError> {
        let mut buf = [0u8; 2];
        let len = frame::reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.expected_session_reset = Some(SessionResetReason::Reset);
        self.send(&buf[..len]).await?;
        self.wait_reset(deadline).await
    }

    /// Read and ingest one frame before `deadline`; returns whether it
    /// was a stream frame that is now the back of `rx_queue`.
    async fn read_more(&mut self, deadline: Instant) -> Result<bool, UlcpError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(UlcpError::Timeout);
        }
        let frame = match tokio::time::timeout(deadline - now, self.link.recv_frame()).await {
            Err(_elapsed) => return Err(UlcpError::Timeout),
            Ok(Err(error)) => {
                self.note_link_error(&error);
                return Err(error);
            }
            Ok(Ok(frame)) => frame,
        };
        Ok(self.ingest_frame(&frame))
    }

    fn pop_rx(&mut self, buf: &mut [u8]) -> Option<RxInfo> {
        let packet = self.rx_queue.pop_front()?;
        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        // `RX_FLAG_SELF_TX` says the *device* transmitted the frame. To
        // the host that is not a self-transmission at all—the device is
        // a separate node, and its frames are as real as any peer's. What
        // carries across is that nothing measured the frame on its way
        // here, which is exactly what `Backhaul` means on this side of
        // the link. Calling it `LocalTx` would tell the host's own MAC
        // that its antenna had already sent the frame, and it would
        // refuse to forward it.
        let buffered_meta = BufferedRxMeta::decode(&packet.raw_meta).ok();
        let self_tx = buffered_meta.is_some_and(|meta| meta.flags & RX_FLAG_SELF_TX != 0);
        let buffered = buffered_meta
            .filter(|meta| meta.flags & RX_FLAG_BUFFERED != 0)
            .map(|meta| RxBuffered {
                age_s: meta.age_s,
                acked: meta.flags & RX_FLAG_ACKED != 0,
            });
        Some(RxInfo {
            len,
            rssi: packet.meta.rssi_dbm.unwrap_or(0),
            snr: Snr::from_centibels(packet.meta.snr_cb.unwrap_or(0)),
            lqi: packet.meta.lqi,
            // A reception the device could not measure—one from a LAN
            // bearer, say—is as unmeasured here as the device's own.
            origin: if self_tx || packet.meta.snr_cb.is_none() {
                RxOrigin::Backhaul
            } else {
                RxOrigin::Air
            },
            buffered,
        })
    }

    /// Issue one `CMD_STR_SEND` with an already-encoded metadata block
    /// and await its confirmation, retrying while CCA reports the
    /// channel busy and `cca_deadline` has not passed.
    async fn send_confirmed(
        &mut self,
        data: &[u8],
        metadata: &[u8],
        cca_deadline: Option<Instant>,
    ) -> Result<(), TxError<UlcpError>> {
        // The PHY may have changed through local controls or another admin
        // since attachment. Remote management handles already have an explicit
        // timing budget; avoid adding radio exchanges to those operations.
        // A timing read that fails keeps the deadline in hand rather than
        // costing the frame.
        if self.mode != AttachMode::Remote {
            self.refresh_t_frame_or_keep().await.map_err(TxError::Io)?;
        }
        loop {
            let tid = self.alloc_tid();
            let mut frame_buf = vec![0u8; data.len() + metadata.len() + 16];
            let frame_len = frame::str_send(&mut frame_buf, tid, stream::PHY_RAW, data, metadata)
                .map_err(|_| TxError::Io(UlcpError::Protocol("frame encode")))?;
            self.send(&frame_buf[..frame_len])
                .await
                .map_err(TxError::Io)?;

            // Direct RF sends confirm after airtime (or a definitive
            // failure); backhaul sends confirm after the node handoff.
            let deadline = Instant::now() + self.transmit_timeout();
            let response = self
                .wait_response(tid, deadline)
                .await
                .map_err(TxError::Io)?;
            if response.kind != ResponseKind::Is || response.key != prop::LAST_STATUS {
                return Err(TxError::Io(UlcpError::Protocol(
                    "unexpected transmit response",
                )));
            }
            match decode_status(&response.value) {
                Status::OK => return Ok(()),
                Status::CCA_FAILURE => match cca_deadline {
                    Some(deadline) if Instant::now() < deadline => {
                        tokio::time::sleep(CCA_RETRY_DELAY).await;
                    }
                    _ => return Err(TxError::CadTimeout),
                },
                status => return Err(TxError::Io(UlcpError::Status(status))),
            }
        }
    }

    /// Transmit a frame with a caller-supplied `STR_PHY_RAW` metadata
    /// block, byte for byte.
    ///
    /// [`Radio::transmit`] composes the metadata from [`TxOptions`],
    /// which is what a MAC wants. A bridge does not: it relays frames
    /// whose transmit parameters were decided elsewhere, and must be
    /// able to put exactly those bytes on the wire—including fields
    /// [`TxOptions`] has no vocabulary for, such as a power override.
    ///
    /// The channel-access retry budget comes from the metadata itself:
    /// with `TX_FLAG_NOCCA` clear the device performs CCA and a busy
    /// channel fails immediately with [`TxError::CadTimeout`], leaving
    /// the retry policy to the caller.
    pub async fn transmit_raw_with_meta(
        &mut self,
        data: &[u8],
        metadata: &[u8],
    ) -> Result<(), TxError<UlcpError>> {
        if data.len() > self.max_frame_size {
            return Err(TxError::Io(UlcpError::FrameTooLarge(data.len())));
        }
        let skips_cca = metadata
            .get(1)
            .is_some_and(|flags| flags & TX_FLAG_NOCCA != 0);
        let cca_deadline = (!skips_cca).then(Instant::now);
        self.send_confirmed(data, metadata, cca_deadline).await
    }

    /// Poll for one inbound frame, preserving its metadata bytes.
    ///
    /// [`Radio::poll_receive`] decodes the metadata into [`RxInfo`],
    /// which cannot represent it faithfully: the "unsupported" sentinels
    /// collapse to zero and the buffered-frame extension is discarded
    /// entirely. A bridge relays the metadata rather than interpreting
    /// it, so it needs the bytes.
    pub fn poll_receive_raw(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<RawRxFrame, UlcpError>> {
        loop {
            if let Some(error) = self.take_reset_notice() {
                return core::task::Poll::Ready(Err(error));
            }
            if let Some(packet) = self.rx_queue.pop_front() {
                return core::task::Poll::Ready(Ok(RawRxFrame {
                    data: packet.data,
                    metadata: packet.raw_meta,
                }));
            }

            match self.link.poll_recv_frame(cx) {
                core::task::Poll::Ready(Ok(frame)) => {
                    self.ingest_frame(&frame);
                }
                core::task::Poll::Ready(Err(error)) => {
                    self.note_link_error(&error);
                    return core::task::Poll::Ready(Err(error));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }

    /// Await one inbound frame with its metadata bytes intact.
    ///
    /// Cancel-safe: the frame is only removed from the inbound queue
    /// once this future is ready to return it.
    pub async fn receive_raw(&mut self) -> Result<RawRxFrame, UlcpError> {
        core::future::poll_fn(|cx| self.poll_receive_raw(cx)).await
    }
}

/// One inbound `STR_PHY_RAW` frame with its trailing metadata exactly as
/// the device sent it.
#[derive(Clone, Debug)]
pub struct RawRxFrame {
    pub data: Vec<u8>,
    pub metadata: Vec<u8>,
}

#[cfg(feature = "serial-radio")]
impl UlcpDevice<SerialFrameLink<tokio_serial::SerialStream>> {
    /// Attach to a device on a serial port.
    pub async fn open_serial(
        path: impl AsRef<str>,
        baud_rate: u32,
        config: UlcpDeviceConfig,
    ) -> Result<Self, UlcpError> {
        use tokio_serial::SerialPortBuilderExt;

        let stream = tokio_serial::new(path.as_ref(), baud_rate)
            .open_native_async()
            .map_err(|error| UlcpError::Io(error.into()))?;
        Self::new(SerialFrameLink::new(stream), config).await
    }
}

#[cfg(feature = "ble-radio")]
impl UlcpDevice<BleFrameLink> {
    /// Discover, connect, attach, and initialize a BLE companion radio.
    pub async fn open_ble(
        selector: Option<&str>,
        config: UlcpDeviceConfig,
    ) -> Result<Self, UlcpError> {
        Self::open_ble_with_link_config(selector, config, BleFrameLinkConfig::default()).await
    }

    /// As [`Self::open_ble`], with an explicit GATT link configuration.
    pub async fn open_ble_with_link_config(
        selector: Option<&str>,
        config: UlcpDeviceConfig,
        link_config: BleFrameLinkConfig,
    ) -> Result<Self, UlcpError> {
        let link = BleFrameLink::connect(selector, link_config).await?;
        Self::new(link, config).await
    }
}

impl<L> Radio for UlcpDevice<L>
where
    L: FrameLink,
{
    type Error = UlcpError;

    /// Transmit one frame and await the device's confirmation.
    ///
    /// A confirmed transmit blocks the caller for up to
    /// `max(response_timeout, 3 seconds, 2 × t_frame_ms)` after refreshing the
    /// device's frame duration, while the frame goes out on air. This
    /// is inherent to the half-duplex [`Radio::transmit`] contract and a real
    /// radio behaves the same way. Frames the device receives during this window
    /// are not lost—they are queued (see [`wait_response`](Self::wait_response)
    /// → [`ingest`](Self::ingest)) and surface on the next
    /// [`poll_receive`](Radio::poll_receive). MAC-layer timers (ACK timeouts,
    /// retransmit deadlines) cannot advance while this future is pending, but
    /// they are only *delayed*, not missed: the coordinator re-evaluates every
    /// deadline against the current clock as soon as `transmit` returns, so a
    /// deadline that came due mid-transmit fires immediately afterward.
    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if data.len() > self.max_frame_size {
            return Err(TxError::Io(UlcpError::FrameTooLarge(data.len())));
        }

        // The device performs CCA itself; the CAD policy becomes a host-side
        // retry budget around `STATUS_CCA_FAILURE`.
        let mut meta = TxMeta {
            power: TxMeta::power_for(options.power_dbm),
            ..TxMeta::default()
        };
        let cca_deadline = match options.cad {
            CadPolicy::Skip => {
                meta.flags |= TX_FLAG_NOCCA;
                None
            }
            // Gate is a single attempt: a zero-length budget, so a busy channel
            // fails immediately with CadTimeout.
            CadPolicy::Gate => Some(Instant::now()),
            CadPolicy::RetryFor { timeout_ms } => {
                Some(Instant::now() + Duration::from_millis(timeout_ms.into()))
            }
        };
        let mut meta_buf = [0u8; TxMeta::WIRE_LEN];
        let meta_len = meta
            .encode(&mut meta_buf)
            .expect("buffer sized with WIRE_LEN");

        self.send_confirmed(data, &meta_buf[..meta_len], cca_deadline)
            .await
    }

    fn poll_receive(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        loop {
            if let Some(error) = self.take_reset_notice() {
                return core::task::Poll::Ready(Err(error));
            }
            if let Some(info) = self.pop_rx(buf) {
                return core::task::Poll::Ready(Ok(info));
            }

            match self.link.poll_recv_frame(cx) {
                core::task::Poll::Ready(Ok(frame)) => {
                    self.ingest_frame(&frame);
                }
                core::task::Poll::Ready(Err(error)) => {
                    self.note_link_error(&error);
                    return core::task::Poll::Ready(Err(error));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
    }

    fn spreading_factor(&self) -> Option<u8> {
        Some(self.config.spreading_factor)
    }
}

// ─── Value decoders ──────────────────────────────────────────────────
//
// Public because fetching and decoding are separable and a batched read
// separates them. A caller that asks for a dozen properties in one
// `CMD_PROP_MULTI_GET` holds a bag of octets afterwards, and needs the
// same readings the per-property methods here apply—otherwise the only
// way to understand a value is to spend a round trip fetching it alone,
// which is the cost batching exists to avoid.

/// The answers to a batch whose every position the reader needs, in the
/// order asked. A refused position fails the read with the error a lone
/// `CMD_PROP_GET` of that property would have raised.
fn required_answers<const N: usize>(
    answers: Vec<Result<Vec<u8>, Status>>,
) -> Result<[Vec<u8>; N], UlcpError> {
    let values = answers
        .into_iter()
        .map(|answer| answer.map_err(UlcpError::Status))
        .collect::<Result<Vec<_>, _>>()?;
    values
        .try_into()
        .map_err(|_| UlcpError::Protocol("short multi-property answer"))
}

/// The answers to a batch, one per position in the order asked, for a
/// reader that takes each member on its own merits: a refusal stays in
/// its position rather than failing the read.
fn positions<const N: usize>(
    answers: Vec<Result<Vec<u8>, Status>>,
) -> Result<[Result<Vec<u8>, Status>; N], UlcpError> {
    answers
        .try_into()
        .map_err(|_| UlcpError::Protocol("short multi-property answer"))
}

/// One member of a multi-property report: `decode` applied to its value,
/// or `None` when the device refused it or `decode` cannot read it.
fn reported<T>(
    answer: &Result<Vec<u8>, Status>,
    decode: impl FnOnce(&[u8]) -> Option<T>,
) -> Option<T> {
    answer.as_ref().ok().and_then(|value| decode(value))
}

/// The value of an exchange whose failure costs only that value. A
/// refusal, or an answer that does not fit the question, is `None`;
/// anything that says the link or the session is in trouble is still an
/// error, because nothing after it can succeed either and a reset notice
/// swallowed here would be one the caller never hears about.
fn absorbent<T>(result: Result<T, UlcpError>) -> Result<Option<T>, UlcpError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(UlcpError::Status(_) | UlcpError::Protocol(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Refuse a device that does not speak this protocol's major version,
/// which is the one thing about an attach that can make it pointless.
/// The minor version is not compared—a mismatch there SHOULD NOT be
/// fatal (ulcp-minimal.md § `PROP_PROTOCOL_VERSION`)—and octets past the
/// two the property defines are the sender's business.
fn check_protocol_version(value: &[u8]) -> Result<(), UlcpError> {
    match value {
        [major, _minor, ..] if *major == ids::PROTOCOL_MAJOR_VERSION => Ok(()),
        [_, _, ..] => Err(UlcpError::Protocol("protocol major version mismatch")),
        _ => Err(UlcpError::Protocol("malformed PROP_PROTOCOL_VERSION")),
    }
}

/// The frame ceiling a `PROP_PHY_MTU` answer gives: its first two octets,
/// or [`FALLBACK_MTU`] when there is no usable answer—refused, short, or
/// zero, none of which is a reason to give up on the device.
fn decode_mtu(value: Option<&Vec<u8>>) -> usize {
    match value.map(Vec::as_slice) {
        Some([lo, hi, ..]) if u16::from_le_bytes([*lo, *hi]) != 0 => {
            usize::from(u16::from_le_bytes([*lo, *hi]))
        }
        _ => FALLBACK_MTU,
    }
}

/// A string property as text: invalid UTF-8 replaced, and the trailing
/// NUL some firmware sends dropped.
fn decode_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .trim_end_matches('\0')
        .to_owned()
}

/// The leading `UINT32_LE` of a value; longer is the sender's business,
/// shorter is no value.
fn decode_u32_prefix(value: &[u8]) -> Option<u32> {
    value.first_chunk().copied().map(u32::from_le_bytes)
}

/// Decode a `PROP_LAST_STATUS` value. Anything malformed reads as
/// `STATUS_FAILURE`, which is what a device unable to say why would mean.
pub fn decode_status(value: &[u8]) -> Status {
    match pui::decode(value) {
        Ok((code, _)) => Status(code),
        Err(_) => Status::FAILURE,
    }
}

/// Decode a `PROP_CAPS` value: capability codes as consecutive PUIs. A
/// malformed one ends the list; the codes before it stand.
pub fn decode_capabilities(value: &[u8]) -> Vec<u32> {
    let mut caps = Vec::new();
    let mut rest = value;
    while let Ok((code, used)) = pui::decode(rest) {
        caps.push(code);
        rest = &rest[used..];
    }
    caps
}

/// Decode a `PROP_HOST_RX_FILTERS` digest table (PUI-length-prefixed
/// filter items). An entry this host cannot interpret is kept as
/// [`ReportedFilter::Unknown`]; a broken length prefix ends the table,
/// since nothing after it can be located, and the entries before it
/// stand.
pub fn decode_filter_table(value: &[u8]) -> Vec<ReportedFilter> {
    items::prefixed_items(value)
        .map_while(Result::ok)
        .filter_map(ReportedFilter::decode)
        .collect()
}

/// Decode `PROP_MAC_REPEATER_REGIONS`: length-prefixed UTF-8 region
/// strings, in the order they were written. A string that is not UTF-8
/// is skipped and the rest kept; a broken length prefix ends the list.
pub fn decode_region_list(value: &[u8]) -> Vec<String> {
    decode_string_items(value)
}

/// The UTF-8 items of a length-prefixed list, skipping any that are not
/// text and stopping where the framing breaks.
fn decode_string_items(value: &[u8]) -> Vec<String> {
    items::prefixed_items(value)
        .map_while(Result::ok)
        .filter_map(|item| core::str::from_utf8(item).ok())
        .map(str::to_owned)
        .collect()
}

/// Reject a region string the device is bound to refuse, so a malformed
/// write fails here rather than costing a round trip
/// (ulcp-device.md § `PROP_MAC_REPEATER_REGIONS`).
fn check_region(region: &str) -> Result<(), UlcpError> {
    match (1..=umsh_core::REGION_NAME_MAX_LEN).contains(&region.len()) {
        true => Ok(()),
        false => Err(UlcpError::Protocol(
            "a region string is 1 to 24 octets of UTF-8",
        )),
    }
}

/// Decode `PROP_MESHCORE_REGIONS`: length-prefixed UTF-8 MeshCore region
/// names, without their `#`. Read as tolerantly as
/// [`decode_region_list`].
pub fn decode_meshcore_regions(value: &[u8]) -> Vec<String> {
    decode_string_items(value)
}

/// A MeshCore region name as `PROP_MESHCORE_REGIONS` stores it: `input`
/// without a leading `#`, refused where the device is bound to refuse it
/// (ulcp-device.md § `PROP_MESHCORE_REGIONS`).
pub fn meshcore_region_name(input: &str) -> Result<&str, UlcpError> {
    let name = input.strip_prefix('#').unwrap_or(input);
    if name.starts_with('$') {
        return Err(UlcpError::Protocol(
            "private MeshCore regions ($) are not supported",
        ));
    }
    if name.starts_with('#') {
        return Err(UlcpError::Protocol(
            "a MeshCore region name takes at most one leading #",
        ));
    }
    if !(1..=items::MESHCORE_REGION_NAME_MAX_LEN).contains(&name.len()) {
        return Err(UlcpError::Protocol(
            "a MeshCore region name is 1 to 30 octets of UTF-8",
        ));
    }
    Ok(name)
}

/// Decode a single optional region code. Empty means unset; octets past
/// the two a code takes are ignored.
pub fn decode_region_code(value: &[u8]) -> Result<Option<RegionCode>, UlcpError> {
    match value {
        [] => Ok(None),
        [high, low, ..] => Ok(Some(RegionCode::from_bytes([*high, *low]))),
        _ => Err(UlcpError::Protocol(
            "malformed PROP_MAC_REPEATER_DEFAULT_REGION",
        )),
    }
}

/// Decode an optional INT16 gate. Empty means unset; `None` is malformed.
pub fn decode_opt_i16(value: &[u8]) -> Option<Option<i16>> {
    match value {
        [] => Some(None),
        [low, high, ..] => Some(Some(i16::from_le_bytes([*low, *high]))),
        _ => None,
    }
}

/// Decode an optional INT8 gate. Empty means unset.
pub fn decode_opt_i8(value: &[u8]) -> Option<Option<i8>> {
    Some(value.first().map(|byte| *byte as i8))
}

/// Decode a `PROP_ALERT` value: one PUI naming a state, kept as reported
/// when it names one this host does not know. Only a value with no
/// readable PUI at all is malformed.
pub fn decode_alert(value: &[u8]) -> Result<ReportedAlert, UlcpError> {
    let (code, _) = pui::decode(value).map_err(|_| UlcpError::Protocol("malformed PROP_ALERT"))?;
    Ok(ReportedAlert::from_code(code))
}

/// Decode a `PROP_TIME` value. Empty means the device does not know what
/// time it is, which is an answer rather than a malformed one.
fn decode_epoch(value: &[u8]) -> Result<Option<u32>, UlcpError> {
    match value {
        [] => Ok(None),
        value => decode_u32_prefix(value)
            .map(Some)
            .ok_or(UlcpError::Protocol("malformed PROP_TIME")),
    }
}

/// Decode a boolean property: any nonzero first octet is true. `None`
/// only for an empty value.
fn decode_bool(value: &[u8]) -> Option<bool> {
    value.first().map(|byte| *byte != 0)
}

/// The boolean a device echoed for a write, naming the property in the
/// error when there was none to read.
fn bool_echo(value: &[u8], what: &'static str) -> Result<bool, UlcpError> {
    decode_bool(value).ok_or(UlcpError::Protocol(what))
}

/// Decode a `PROP_MESHCORE_REGION_POLICY` value, an unassigned code
/// included. `None` only for an empty value.
fn decode_meshcore_region_policy(value: &[u8]) -> Option<MeshCoreRegionPolicy> {
    value.first().copied().map(MeshCoreRegionPolicy::from_wire)
}

/// Decode a `UINT32_LE` announcement interval in seconds.
fn decode_interval(value: &[u8]) -> Result<u32, UlcpError> {
    decode_u32_prefix(value).ok_or(UlcpError::Protocol("malformed announcement interval"))
}

/// Decode a digest table of fixed-size items. A ragged tail is not an
/// item and is left out; every whole item before it stands.
fn decode_fixed_list<const N: usize>(value: &[u8]) -> Vec<[u8; N]> {
    value
        .chunks_exact(N)
        .map(|chunk| chunk.try_into().expect("chunks_exact yields N-byte chunks"))
        .collect()
}

/// Render one ULCP frame as a one-line human-readable summary:
/// command, TID, property mnemonic, and the decoded status where the
/// payload is a `PROP_LAST_STATUS` value. Values are summarized by
/// length—never dumped—so traces cannot leak key material.
pub fn describe_frame(bytes: &[u8]) -> String {
    umsh_ulcp::FrameDescription(bytes).to_string()
}

/// In-process stand-ins for a device, for the tests here and for the
/// tools built on this crate, which want a device to attach to that is
/// as real as a pipe.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::AsyncReadExt;
    use umsh_ulcp::PropPayload;
    use umsh_ulcp::meta::RX_FLAG_BUFFERED;

    /// Payload that makes the fake device report a CCA failure.
    pub const CCA_FAIL: &[u8] = b"cca-fail";
    /// Payload that makes the fake device report success and then
    /// announce a spurious watchdog reset.
    pub const RESET_AFTER: &[u8] = b"reset-after";
    /// Payload that makes the fake device report success and then
    /// announce a session reset nobody asked for—a second host
    /// displacing this one, as far as this host can tell.
    pub const SESSION_RESET_AFTER: &[u8] = b"session-reset-after";
    /// Property that switches the fake device's `CMD_RESTORE` completion
    /// to the reset form.
    pub const RESTORE_RESET_FORM_KEY: u32 = 59_999;

    /// Minimal in-process device: answers the initialization handshake,
    /// stores property sets and multi-value tables, and echoes
    /// transmitted frames back as received frames.
    ///
    /// Generic over the stream so the same device can be reached down a
    /// pipe or across a socket—which is the whole claim TCP support
    /// rests on.
    pub async fn fake_device<IO: AsyncRead + AsyncWrite + Unpin>(io: IO) {
        fake_device_with(io, false).await
    }

    /// The same device with `CAP_CMD_MULTI`, which the non-resetting
    /// attach handshake needs.
    pub async fn fake_multi_device<IO: AsyncRead + AsyncWrite + Unpin>(io: IO) {
        fake_device_with(io, true).await
    }

    /// What the fake device reports for a property read.
    fn fake_value(key: u32, props: &HashMap<u32, Vec<u8>>) -> Vec<u8> {
        match key {
            prop::LAST_STATUS => vec![Status::RESET_POWER_ON.0 as u8],
            prop::PROTOCOL_VERSION => {
                vec![ids::PROTOCOL_MAJOR_VERSION, ids::PROTOCOL_MINOR_VERSION]
            }
            prop::DEV_VERSION => b"fake-dev/0.1\0".to_vec(),
            prop::DEV_MODEL => b"Fake Board\0".to_vec(),
            prop::PHY_MTU => 255u16.to_le_bytes().to_vec(),
            prop::PHY_T_FRAME => props
                .get(&key)
                .cloned()
                .unwrap_or_else(|| 624u32.to_le_bytes().to_vec()),
            _ => props.get(&key).cloned().unwrap_or_default(),
        }
    }

    pub async fn fake_device_with<IO: AsyncRead + AsyncWrite + Unpin>(mut io: IO, multi_get: bool) {
        let mut decoder = hdlc::Decoder::<WIRE_BUF>::new();
        let mut props: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut tables: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        let mut chunk = [0u8; READ_CHUNK];
        // This device attaches lazily, the way the ESP32 wired transport
        // does: the host's own first frame creates the session, so the
        // notice for it precedes the reply to that frame.
        let mut announced_attach = false;
        loop {
            let read = match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            let mut replies: Vec<Vec<u8>> = Vec::new();
            for &byte in &chunk[..read] {
                let Some(Ok(frame_bytes)) = decoder.push(byte) else {
                    continue;
                };
                let frame = Frame::parse(frame_bytes).expect("host sent malformed frame");
                let tid = frame.header.tid();
                let mut buf = vec![0u8; 512];
                if !announced_attach {
                    announced_attach = true;
                    let len = frame::session_reset(&mut buf, SessionResetReason::Attached).unwrap();
                    replies.push(buf[..len].to_vec());
                }
                match frame.command().expect("host sent unknown command") {
                    Cmd::Reset => {
                        let len =
                            frame::last_status(&mut buf, TID_UNSOLICITED, Status::RESET_SOFTWARE)
                                .unwrap();
                        replies.push(buf[..len].to_vec());
                        // Announced after the status, the way the driver
                        // pays the debt at the tail of its loop.
                        let len =
                            frame::session_reset(&mut buf, SessionResetReason::Reset).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropGet => {
                        let key = PropPayload::parse(frame.payload).unwrap().key;
                        let value = fake_value(key, &props);
                        let len = frame::prop_is(&mut buf, tid, key, &value).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropMultiGet if multi_get => {
                        let mut writer = frame::prop_are(&mut buf, tid).unwrap();
                        for key in umsh_ulcp::frame::MultiGetKeys::new(frame.payload) {
                            let key = key.unwrap();
                            writer.write_entry(key, &fake_value(key, &props)).unwrap();
                        }
                        let len = writer.finish();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropSet => {
                        let payload = PropPayload::parse(frame.payload).unwrap();
                        props.insert(payload.key, payload.value.to_vec());
                        let len = if payload.key == prop::BLE_PAIRING_PIN {
                            frame::last_status(&mut buf, tid, Status::OK).unwrap()
                        } else {
                            frame::prop_is(&mut buf, tid, payload.key, payload.value).unwrap()
                        };
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::StrSend => {
                        let payload = StreamPayload::parse(frame.payload).unwrap();
                        assert_eq!(payload.stream, stream::PHY_RAW);
                        if payload.data == CCA_FAIL {
                            let len =
                                frame::last_status(&mut buf, tid, Status::CCA_FAILURE).unwrap();
                            replies.push(buf[..len].to_vec());
                            continue;
                        }
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                        if payload.data == RESET_AFTER {
                            let len = frame::last_status(
                                &mut buf,
                                TID_UNSOLICITED,
                                Status::RESET_WATCHDOG,
                            )
                            .unwrap();
                            replies.push(buf[..len].to_vec());
                            continue;
                        }
                        if payload.data == SESSION_RESET_AFTER {
                            let len = frame::session_reset(&mut buf, SessionResetReason::Attached)
                                .unwrap();
                            replies.push(buf[..len].to_vec());
                            continue;
                        }
                        // Echo the packet back as a reception.
                        let mut meta = [0u8; RxMeta::WIRE_LEN];
                        RxMeta {
                            rssi_dbm: Some(-91),
                            lqi: None,
                            snr_cb: Some(55),
                        }
                        .encode(&mut meta)
                        .unwrap();
                        let len = frame::str_recv(&mut buf, stream::PHY_RAW, payload.data, &meta)
                            .unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::Nop => {
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropInsert => {
                        let payload = PropPayload::parse(frame.payload).unwrap();
                        // PROP_HOST_PEER_KEYS: secret-bearing 64-byte item,
                        // 32-byte public-key digest, insert-replaces on a
                        // matching public key. Other tables: item == digest,
                        // duplicates fail with STATUS_ALREADY.
                        let replaces = payload.key == prop::HOST_PEER_KEYS;
                        let stored = payload.value.to_vec();
                        let digest_len = if replaces {
                            assert_eq!(stored.len(), 64);
                            32
                        } else {
                            stored.len()
                        };
                        let table = tables.entry(payload.key).or_default();
                        let existing = table.iter_mut().find(|item| {
                            item[..digest_len.min(item.len())] == stored[..digest_len]
                        });
                        let len = match existing {
                            Some(_) if !replaces => {
                                frame::last_status(&mut buf, tid, Status::ALREADY).unwrap()
                            }
                            Some(existing) => {
                                *existing = stored.clone();
                                frame::prop_inserted(
                                    &mut buf,
                                    tid,
                                    payload.key,
                                    &stored[..digest_len],
                                )
                                .unwrap()
                            }
                            None => {
                                table.push(stored.clone());
                                frame::prop_inserted(
                                    &mut buf,
                                    tid,
                                    payload.key,
                                    &stored[..digest_len],
                                )
                                .unwrap()
                            }
                        };
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropRemove => {
                        let payload = PropPayload::parse(frame.payload).unwrap();
                        let table = tables.entry(payload.key).or_default();
                        let position = table.iter().position(|item| {
                            item[..payload.value.len().min(item.len())] == *payload.value
                        });
                        let len = match position {
                            Some(index) => {
                                let removed = table.remove(index);
                                let digest = &removed[..payload.value.len().min(removed.len())];
                                frame::prop_removed(&mut buf, tid, payload.key, digest).unwrap()
                            }
                            None => {
                                frame::last_status(&mut buf, tid, Status::ITEM_NOT_FOUND).unwrap()
                            }
                        };
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::QueueDrain => {
                        // Two buffered frames, oldest first, then completion.
                        for (index, age_s) in [5u32, 3].into_iter().enumerate() {
                            let mut meta = [0u8; BufferedRxMeta::WIRE_LEN];
                            BufferedRxMeta {
                                rx: RxMeta {
                                    rssi_dbm: Some(-80),
                                    lqi: None,
                                    snr_cb: Some(10),
                                },
                                flags: RX_FLAG_BUFFERED,
                                age_s,
                            }
                            .encode(&mut meta)
                            .unwrap();
                            let data = [0xB0u8 + index as u8];
                            let len =
                                frame::str_recv(&mut buf, stream::PHY_RAW, &data, &meta).unwrap();
                            replies.push(buf[..len].to_vec());
                        }
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    // The fake device has no durable state to erase, so a
                    // factory reset is acknowledged like the rest; the
                    // reboot it implies is out of this harness's scope.
                    // An announcement is acknowledged the same way: the
                    // status reports the queuing, never the airing.
                    Cmd::Save | Cmd::Clear | Cmd::FactoryReset | Cmd::Announce => {
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::Restore => {
                        if props
                            .get(&RESTORE_RESET_FORM_KEY)
                            .is_some_and(|value| value == &[1])
                        {
                            let len = frame::last_status(
                                &mut buf,
                                TID_UNSOLICITED,
                                Status::RESET_RESTORED,
                            )
                            .unwrap();
                            replies.push(buf[..len].to_vec());
                        } else {
                            // Update form: publish the reverted value, then
                            // the correlated completion.
                            let len = frame::prop_is(
                                &mut buf,
                                TID_UNSOLICITED,
                                prop::PHY_FREQ,
                                &905_000u32.to_le_bytes(),
                            )
                            .unwrap();
                            replies.push(buf[..len].to_vec());
                            let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                            replies.push(buf[..len].to_vec());
                        }
                    }
                    // This device predates CAP_CMD_MULTI, CAP_REBOOT, and
                    // CAP_I2C: it answers commands it does not implement
                    // the way any such device answers them.
                    Cmd::PropMultiGet
                    | Cmd::PropMultiSet
                    | Cmd::Reboot
                    | Cmd::Dfu
                    | Cmd::I2cTransfer
                    | Cmd::I2cScan => {
                        let len = frame::last_status(&mut buf, tid, Status::UNIMPLEMENTED).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropIs
                    | Cmd::StrRecv
                    | Cmd::PropInserted
                    | Cmd::PropRemoved
                    | Cmd::PropAre
                    | Cmd::SessionReset
                    | Cmd::I2cResult => {
                        panic!("host sent a device-only command")
                    }
                }
            }
            for reply in replies {
                let mut wire = vec![0u8; hdlc::max_encoded_len(reply.len())];
                let len = hdlc::encode_frame(&reply, &mut wire).unwrap();
                if io.write_all(&wire[..len]).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use tokio::io::DuplexStream;
    use umsh_ulcp::PropPayload;
    use umsh_ulcp::meta::RX_FLAG_BUFFERED;

    #[test]
    fn meshcore_region_policies_round_trip() {
        for value in 0..=u8::MAX {
            match MeshCoreRegionPolicy::from_u8(value) {
                Some(policy) => {
                    assert_eq!(policy.as_u8(), value);
                    assert_eq!(policy.name().parse(), Ok(policy));
                }
                None => assert!(value > 2),
            }
        }
        assert_eq!("Scoped".parse(), Ok(MeshCoreRegionPolicy::ScopedOnly));
        // An unassigned code is reported, not refused, and never parsed.
        assert_eq!(
            decode_meshcore_region_policy(&[3, 0xEE]),
            Some(MeshCoreRegionPolicy::Other(3))
        );
        assert_eq!(MeshCoreRegionPolicy::Other(3).to_string(), "unknown (3)");
        assert_eq!(MeshCoreRegionPolicy::Other(3).as_u8(), 3);
        assert!("unknown".parse::<MeshCoreRegionPolicy>().is_err());
        assert_eq!(decode_meshcore_region_policy(&[]), None);
        assert!(!meshcore_identity_allowed(&[0xFF; 32]));
        assert!(meshcore_identity_allowed(&[0x01; 32]));
    }

    #[test]
    fn meshcore_region_names_drop_their_hash() {
        assert_eq!(meshcore_region_name("#us-ca").unwrap(), "us-ca");
        assert_eq!(meshcore_region_name("US-CA").unwrap(), "US-CA");
        for bad in ["", "#", "##us-ca", "$ops", "#$ops", &"x".repeat(31)] {
            assert!(meshcore_region_name(bad).is_err(), "{bad:?}");
        }
        assert!(meshcore_region_name(&format!("#{}", "x".repeat(30))).is_ok());
        assert_eq!(
            decode_meshcore_regions(&[2, b'a', b'b', 1, b'C']),
            ["ab", "C"]
        );
    }

    /// One bad item costs that item. A string that is not text is skipped
    /// and the rest kept; a length prefix running off the end of the
    /// value ends the list, and what came before it stands.
    #[test]
    fn a_bad_list_item_costs_only_itself() {
        assert_eq!(decode_meshcore_regions(&[2, 0xFF, 0xFE, 1, b'C']), ["C"]);
        assert_eq!(decode_region_list(&[3, b'S', b'J', b'C', 9, b'x']), ["SJC"]);
        assert_eq!(decode_capabilities(&[cap::SAVE as u8, 0xFF]), [cap::SAVE]);
        assert_eq!(decode_fixed_list::<2>(&[1, 2, 3, 4, 5]), [[1, 2], [3, 4]]);
    }

    /// An unknown filter type is an entry the device holds, so it is kept
    /// as reported rather than refusing the table.
    #[test]
    fn an_unknown_filter_type_is_preserved() {
        let table = [
            2,
            items::FILTER_PKT_TYPE,
            0,
            3,
            0x7F,
            0xAB,
            0xCD,
            3,
            1,
            0x12,
            0x34,
        ];
        assert_eq!(
            decode_filter_table(&table),
            [
                ReportedFilter::Known(items::Filter::PktType(0)),
                ReportedFilter::Unknown {
                    filter_type: 0x7F,
                    value: vec![0xAB, 0xCD],
                },
                ReportedFilter::Known(items::Filter::ChannelId([0x12, 0x34])),
            ]
        );
    }

    #[test]
    fn unassigned_codes_are_reported_rather_than_refused() {
        assert_eq!(
            SavedSnapshot::from_octet(&[9, 9]),
            Some(SavedSnapshot::Other(9))
        );
        assert!(!SavedSnapshot::Other(9).is_saved());
        assert_eq!(SavedSnapshot::from_octet(&[]), None);
        assert_eq!(
            decode_alert(&[200, 1]).unwrap(),
            ReportedAlert::Unknown(200)
        );
        assert_eq!(
            decode_alert(&[AlertState::Locate.code() as u8]).unwrap(),
            ReportedAlert::Known(AlertState::Locate)
        );
        assert_eq!(decode_bool(&[2]), Some(true));
        assert_eq!(decode_bool(&[]), None);
    }

    #[test]
    fn the_protocol_version_check_reads_only_the_major() {
        let major = ids::PROTOCOL_MAJOR_VERSION;
        assert!(check_protocol_version(&[major, 0]).is_ok());
        assert!(check_protocol_version(&[major, 99, 7]).is_ok());
        assert!(check_protocol_version(&[major.wrapping_add(1), 0]).is_err());
        assert!(check_protocol_version(&[major]).is_err());
    }

    fn test_config() -> UlcpDeviceConfig {
        let mut config = UlcpDeviceConfig::new(906_875, 250_000, 11, 5);
        config.tx_power_dbm = 10;
        config.response_timeout = Duration::from_millis(500);
        config
    }

    async fn attached_radio() -> UlcpDevice<SerialFrameLink<DuplexStream>> {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_device(server));
        UlcpDevice::new(SerialFrameLink::new(client), test_config())
            .await
            .unwrap()
    }

    fn wire(frame: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut encoded).unwrap();
        encoded.truncate(len);
        encoded
    }

    #[tokio::test]
    async fn serial_link_preserves_two_frames_from_one_read() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut bytes = wire(b"first");
        bytes.extend_from_slice(&wire(b"second"));
        server.write_all(&bytes).await.unwrap();

        let mut link = SerialFrameLink::new(client);
        assert_eq!(link.recv_frame().await.unwrap(), b"first");
        assert_eq!(link.recv_frame().await.unwrap(), b"second");
    }

    #[tokio::test]
    async fn serial_link_cancellation_keeps_partial_and_buffered_tail() {
        let (client, mut server) = tokio::io::duplex(1024);
        let first = wire(b"first");
        let second = wire(b"second");
        let split = second.len() / 2;
        let mut initial = first;
        initial.extend_from_slice(&second[..split]);
        server.write_all(&initial).await.unwrap();

        let mut link = SerialFrameLink::new(client);
        assert_eq!(link.recv_frame().await.unwrap(), b"first");
        assert!(
            tokio::time::timeout(Duration::from_millis(1), link.recv_frame())
                .await
                .is_err()
        );
        server.write_all(&second[split..]).await.unwrap();
        assert_eq!(link.recv_frame().await.unwrap(), b"second");
    }

    /// A socket is a serial link with a different name on it, which is
    /// what lets a bridged port serve a radio over TCP. The payload
    /// carries every byte the framing gives meaning to—flag, escape,
    /// and both flow-control bytes—so any encoder that treated the
    /// socket as transparent would fail here.
    #[tokio::test]
    async fn serial_link_frames_the_same_bytes_over_a_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(endpoint).await.unwrap();

        let mut device = SerialFrameLink::new(accepted.await.unwrap());
        let mut host = SerialFrameLink::new(client);

        let hostile = [0x7E, 0x7D, 0x11, 0x13, 0x00, 0xFF];
        host.send_frame(&hostile).await.unwrap();
        assert_eq!(device.recv_frame().await.unwrap(), hostile);

        device.send_frame(b"pong").await.unwrap();
        assert_eq!(host.recv_frame().await.unwrap(), b"pong");
    }

    /// The handshake itself over a socket, not just the framing under
    /// it: a bridged radio has to attach exactly as a wired one does.
    #[tokio::test]
    async fn a_radio_attaches_over_a_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            fake_device(stream).await;
        });

        let stream = tokio::net::TcpStream::connect(endpoint).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut device = UlcpDevice::new(SerialFrameLink::new(stream), test_config())
            .await
            .unwrap();

        // Attach is only half of it; a property exchange proves the
        // session is live in both directions.
        device.set_prop(prop::PHY_TX_POWER, &[14]).await.unwrap();
        assert_eq!(device.get_prop(prop::PHY_TX_POWER).await.unwrap(), [14]);
    }

    /// The far end going away has to surface as a dropped link rather
    /// than an endless wait, or a session whose bridge was killed would
    /// hang instead of reporting a detach.
    #[tokio::test]
    async fn serial_link_reports_a_closed_socket_as_a_lost_link() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = tokio::net::TcpStream::connect(endpoint).await.unwrap();

        drop(accepted.await.unwrap());
        let mut host = SerialFrameLink::new(client);
        assert!(matches!(
            host.recv_frame().await,
            Err(UlcpError::Disconnected)
        ));
    }

    #[cfg(feature = "ble-radio")]
    #[test]
    fn ble_link_config_rejects_invalid_values_without_opening_an_adapter() {
        let mut config = BleFrameLinkConfig::default();
        assert!(config.validate().is_ok());
        config.segment_payload = 0;
        assert!(matches!(config.validate(), Err(UlcpError::Protocol(_))));
        config.segment_payload = 512;
        assert!(matches!(config.validate(), Err(UlcpError::Protocol(_))));
        config.segment_payload = 19;
        config.operation_timeout = Duration::ZERO;
        assert!(matches!(config.validate(), Err(UlcpError::Protocol(_))));
        config.operation_timeout = Duration::from_secs(1);
        config.pairing_timeout = Duration::ZERO;
        assert!(matches!(config.validate(), Err(UlcpError::Protocol(_))));
    }

    #[cfg(feature = "ble-radio")]
    #[tokio::test]
    async fn ble_notification_receiver_reassembles_and_recovers_from_malformed_segment() {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut receiver = BleNotificationReceiver::new(rx);

        // Reserved header bits are malformed and must be dropped without
        // poisoning the next valid frame.
        tx.send(vec![0x01, 0xff]).await.unwrap();
        let frame = b"a frame larger than one tiny GATT segment";
        for segment in umsh_ulcp::gatt::segments(frame, 7) {
            let mut value = vec![0; segment.payload().len() + 1];
            segment.write_to(&mut value).unwrap();
            tx.send(value).await.unwrap();
        }

        let received = core::future::poll_fn(|cx| receiver.poll_recv_frame(cx))
            .await
            .unwrap();
        assert_eq!(received, frame);
    }

    #[cfg(feature = "ble-radio")]
    #[tokio::test]
    async fn ble_notification_channel_close_surfaces_disconnect() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut receiver = BleNotificationReceiver::new(rx);
        drop(tx);
        let result = core::future::poll_fn(|cx| receiver.poll_recv_frame(cx)).await;
        assert!(matches!(result, Err(UlcpError::Disconnected)));
    }

    #[test]
    fn link_loss_is_the_transport_going_away_and_nothing_else() {
        assert!(UlcpError::Disconnected.is_link_lost());
        assert!(UlcpError::Io(io::Error::other("unplugged")).is_link_lost());
        assert!(UlcpError::Transport("BLE write failed".into()).is_link_lost());
        for error in [
            UlcpError::Timeout,
            UlcpError::Protocol("nonsense"),
            UlcpError::Status(Status::FAILURE),
            UlcpError::UnexpectedReset(Status::RESET_WATCHDOG),
            UlcpError::SessionReset(SessionResetReason::Attached),
            UlcpError::FrameTooLarge(300),
            UlcpError::AdministrativeAttach,
        ] {
            assert!(!error.is_link_lost(), "{error}");
        }
    }

    /// The handle outlives its transport: what it learned stays, what it
    /// held about the old link goes, and the fresh attach on the far end
    /// is expected rather than reported.
    #[tokio::test]
    async fn reattach_restores_a_handle_after_the_link_dies() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (client, server) = tokio::io::duplex(4096);
        let device_task = tokio::spawn(fake_multi_device(server));
        let mut radio =
            UlcpDevice::attach_administrative(SerialFrameLink::new(client), test_config())
                .await
                .unwrap();
        let traced = Arc::new(AtomicUsize::new(0));
        let counter = traced.clone();
        radio.set_frame_trace(Some(Box::new(move |_, _| {
            counter.fetch_add(1, Ordering::Relaxed);
        })));
        assert!(!radio.link_lost());

        // The far end goes away; the next exchange fails and says so.
        device_task.abort();
        let _ = device_task.await;
        let error = radio.get_prop(prop::PHY_FREQ).await.unwrap_err();
        assert!(error.is_link_lost(), "{error}");
        assert!(radio.link_lost());
        // A dead link stays dead until it is replaced.
        assert!(radio.get_prop(prop::PHY_FREQ).await.is_err());
        assert!(radio.link_lost());

        // The replacement device cannot answer a multi-get: a reattach
        // is not a second attach handshake.
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_device(server));
        let before = traced.load(Ordering::Relaxed);
        radio.reattach(SerialFrameLink::new(client)).await.unwrap();
        assert!(!radio.link_lost());
        assert_eq!(radio.attach_mode(), AttachMode::Administrative);
        assert_eq!(radio.dev_version(), "fake-dev/0.1");
        assert_eq!(radio.max_frame_size(), 255);
        // The trace sink installed before the loss still sees frames,
        // and it saw exactly one exchange: the status read and its answer,
        // plus the fresh-attach notice the device sends on the first
        // frame it hears. Nothing the handle already knew was asked for.
        assert_eq!(traced.load(Ordering::Relaxed) - before, 3);

        // A whole exchange, on a device that announced a fresh attach the
        // moment it was spoken to: the notice was expected and absorbed.
        radio.set_prop(prop::PHY_TX_POWER, &[14]).await.unwrap();
        assert_eq!(radio.get_prop(prop::PHY_TX_POWER).await.unwrap(), [14]);
        assert!(!radio.link_lost());
    }

    /// Frames queued from the old link are not delivered on the new one.
    #[tokio::test]
    async fn reattach_clears_what_the_old_link_left_behind() {
        let mut radio = attached_radio().await;
        // The fake echoes a transmission back as a reception, which the
        // exchange that follows queues for the next receive poll.
        radio
            .transmit(b"echoed", TxOptions::default())
            .await
            .unwrap();
        radio.get_prop(prop::PHY_FREQ).await.unwrap();

        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_multi_device(server));
        radio.reattach(SerialFrameLink::new(client)).await.unwrap();

        let mut buf = [0u8; 256];
        let receive = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receive)
                .await
                .is_err(),
            "the old link's reception was delivered on the new one"
        );
    }

    #[tokio::test]
    async fn a_mesh_handle_refuses_reattach() {
        let (client, _server) = tokio::io::duplex(64);
        let mut radio = UlcpDevice::open_remote(SerialFrameLink::new(client), test_config());
        let (client, _server) = tokio::io::duplex(64);
        assert!(matches!(
            radio.reattach(SerialFrameLink::new(client)).await,
            Err(UlcpError::Protocol(_))
        ));
        assert!(!radio.link_lost());
    }

    /// A device that does not answer is not a link that has gone away:
    /// the handle stays attached, and only a transport failure latches.
    #[tokio::test]
    async fn a_timeout_is_not_link_loss() {
        let mut radio = attached_radio().await;
        // Swap in a link nobody is listening to, keeping its far end
        // alive so the write succeeds and the read simply waits.
        let (client, _server) = tokio::io::duplex(4096);
        *radio.link_mut() = SerialFrameLink::new(client);
        assert!(matches!(
            radio.get_prop(prop::PHY_FREQ).await,
            Err(UlcpError::Timeout)
        ));
        assert!(!radio.link_lost());
    }

    #[tokio::test]
    async fn initialization_handshake() {
        let radio = attached_radio().await;
        assert_eq!(radio.max_frame_size(), 255);
        assert_eq!(radio.dev_version(), "fake-dev/0.1");
        assert_eq!(radio.dev_model(), Some("Fake Board"));
        assert_eq!(radio.boot_status(), Status::RESET_POWER_ON);
        assert!(radio.t_frame_ms() > 0);
    }

    struct TimingLink {
        duration: Result<Vec<u8>, Status>,
        response: Option<Vec<u8>>,
        sends: usize,
    }

    impl FrameLink for TimingLink {
        async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), UlcpError> {
            let request = Frame::parse(bytes).unwrap();
            let tid = request.header.tid();
            let mut response = [0; 64];
            let len = if request.command() == Some(Cmd::StrSend) {
                self.sends += 1;
                frame::last_status(&mut response, tid, Status::CCA_FAILURE).unwrap()
            } else {
                let key = PropPayload::parse(request.payload).unwrap().key;
                let value = match key {
                    prop::PHY_T_FRAME => self.duration.clone(),
                    prop::PHY_LORA_BW => Ok(125_000u32.to_le_bytes().to_vec()),
                    prop::PHY_LORA_SF => Ok(vec![12]),
                    prop::PHY_LORA_CR => Ok(vec![5]),
                    prop::PHY_MTU => Ok(255u16.to_le_bytes().to_vec()),
                    _ => panic!("unexpected property {key}"),
                };
                match value {
                    Ok(value) => frame::prop_is(&mut response, tid, key, &value).unwrap(),
                    Err(status) => frame::last_status(&mut response, tid, status).unwrap(),
                }
            };
            self.response = Some(response[..len].to_vec());
            Ok(())
        }

        fn poll_recv_frame(
            &mut self,
            _: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
            self.response
                .take()
                .map_or(core::task::Poll::Pending, |reply| {
                    core::task::Poll::Ready(Ok(reply))
                })
        }
    }

    fn timing_radio(duration: Result<Vec<u8>, Status>) -> UlcpDevice<TimingLink> {
        UlcpDevice::bare(
            TimingLink {
                duration,
                response: None,
                sends: 0,
            },
            UlcpDeviceConfig::new(917_500, 500_000, 10, 5),
        )
    }

    #[tokio::test]
    async fn transmit_refreshes_device_timing_and_busy_returns_immediately() {
        let mut radio = timing_radio(Ok(624u32.to_le_bytes().to_vec()));
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            radio.send_confirmed(&[1], &[], None),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(TxError::CadTimeout)));
        assert_eq!(radio.t_frame_ms(), 624);
        assert_eq!(radio.transmit_timeout(), Duration::from_secs(3));

        radio.link.duration = Ok(5_000u32.to_le_bytes().to_vec());
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            radio.send_confirmed(&[1], &[], None),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(TxError::CadTimeout)));
        assert_eq!(radio.t_frame_ms(), 5_000);
        assert_eq!(radio.transmit_timeout(), Duration::from_secs(10));
        assert_eq!(radio.link.sends, 2);
        radio.config.response_timeout = Duration::from_secs(20);
        assert_eq!(radio.transmit_timeout(), Duration::from_secs(20));
        radio.t_frame_ms = u32::MAX;
        assert_eq!(
            radio.transmit_timeout(),
            Duration::from_millis(u64::from(u32::MAX) * 2)
        );
    }

    #[tokio::test]
    async fn legacy_timing_uses_live_phy_instead_of_host_defaults() {
        for status in [Status::PROP_NOT_FOUND, Status::UNIMPLEMENTED] {
            let mut radio = timing_radio(Err(status));
            assert_eq!(radio.refresh_t_frame().await.unwrap(), 9806);
            assert_eq!(radio.transmit_timeout(), Duration::from_millis(19612));
        }
    }

    /// A timing read that fails costs nothing but freshness: the frame
    /// still goes out, under the last good deadline or, before there has
    /// been one, the slowest the radio could possibly be.
    #[tokio::test]
    async fn malformed_or_failed_timing_still_transmits_on_a_conservative_deadline() {
        for value in [
            Ok(vec![]),
            Ok(vec![1]),
            Ok(0u32.to_le_bytes().to_vec()),
            Err(Status::FAILURE),
        ] {
            let mut radio = timing_radio(value.clone());
            assert!(matches!(
                radio.send_confirmed(&[1], &[], None).await,
                Err(TxError::CadTimeout)
            ));
            assert_eq!(radio.link.sends, 1, "{value:?}");
            assert_eq!(radio.t_frame_ms(), conservative_t_frame_ms(0));
            assert!(radio.transmit_timeout() >= Duration::from_secs(10));

            // With a good reading in hand, a bad one keeps it.
            radio.t_frame_ms = 624;
            assert!(matches!(
                radio.send_confirmed(&[1], &[], None).await,
                Err(TxError::CadTimeout)
            ));
            assert_eq!(radio.link.sends, 2);
            assert_eq!(radio.t_frame_ms(), 624);
        }

        // Octets past the four the property defines are the sender's.
        let mut long = 700u32.to_le_bytes().to_vec();
        long.push(0xEE);
        let mut radio = timing_radio(Ok(long));
        assert_eq!(radio.refresh_t_frame().await.unwrap(), 700);
    }

    #[tokio::test]
    async fn explicit_reset_returns_the_announced_status() {
        let mut radio = attached_radio().await;
        let status = radio.reset().await.unwrap();
        assert_eq!(status, Status::RESET_SOFTWARE);
        // The link and session must remain usable after the reset.
        radio.get_prop(prop::LAST_STATUS).await.unwrap();
    }

    #[tokio::test]
    async fn write_only_pairing_pin_accepts_status_completion() {
        let mut radio = attached_radio().await;
        radio.set_ble_pairing_pin(Some(123_456)).await.unwrap();
        radio.set_ble_pairing_pin(None).await.unwrap();
        assert!(radio.set_ble_pairing_pin(Some(1_000_000)).await.is_err());

        let error = radio
            .set_prop(prop::BLE_PAIRING_PIN, &123_456u32.to_le_bytes())
            .await
            .unwrap_err();
        assert!(matches!(error, UlcpError::Protocol(_)));
    }

    #[tokio::test]
    async fn device_name_typed_accessors_round_trip_and_validate() {
        let mut radio = attached_radio().await;
        radio.set_device_name("Field Radio 📻").await.unwrap();
        assert_eq!(radio.device_name().await.unwrap(), "Field Radio 📻");
        assert!(radio.set_device_name("").await.is_err());
        assert!(radio.set_device_name(&"x".repeat(65)).await.is_err());
        assert!(radio.set_device_name("bad\0name").await.is_err());
    }

    #[tokio::test]
    async fn transmit_and_receive_round_trip() {
        let mut radio = attached_radio().await;
        let packet = [0x10u8, 0x20, 0x30, 0x40];
        radio.transmit(&packet, TxOptions::default()).await.unwrap();

        let mut buf = [0u8; 256];
        let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(&buf[..info.len], &packet);
        assert_eq!(info.rssi, -91);
        assert_eq!(info.snr.as_centibels(), 55);
    }

    #[tokio::test]
    async fn cca_failure_maps_to_cad_timeout() {
        let mut radio = attached_radio().await;
        let result = radio
            .transmit(
                CCA_FAIL,
                TxOptions {
                    cad: CadPolicy::Gate,
                    power_dbm: None,
                },
            )
            .await;
        assert!(matches!(result, Err(TxError::CadTimeout)));
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let mut radio = attached_radio().await;
        let oversized = vec![0u8; radio.max_frame_size() + 1];
        let result = radio.transmit(&oversized, TxOptions::default()).await;
        assert!(matches!(
            result,
            Err(TxError::Io(UlcpError::FrameTooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn unexpected_reset_surfaces_on_receive() {
        let mut radio = attached_radio().await;
        radio
            .transmit(RESET_AFTER, TxOptions::default())
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let result = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await;
        assert!(matches!(
            result,
            Err(UlcpError::UnexpectedReset(status))
                if status == Status::RESET_WATCHDOG
        ));
    }

    /// The attach handshake absorbs the notice its own attach produced;
    /// every test in this module would fail on the first exchange
    /// otherwise, since the fake device attaches lazily and announces it
    /// ahead of the first reply.
    #[tokio::test]
    async fn the_attach_handshake_absorbs_its_own_notice() {
        let mut radio = attached_radio().await;
        // The session is usable, so nothing was left latched to fire on
        // the next exchange either.
        assert_eq!(radio.get_prop(prop::PHY_FREQ).await.unwrap().len(), 4);
    }

    /// A link to the fake device that slips extra device frames in ahead
    /// of the real answers: the first batch on the first frame sent, the
    /// second on the first multi-property read.
    struct NoisyLink {
        inner: SerialFrameLink<DuplexStream>,
        on_first: Vec<Vec<u8>>,
        on_multi_get: Vec<Vec<u8>>,
        pending: VecDeque<Vec<u8>>,
    }

    impl FrameLink for NoisyLink {
        async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), UlcpError> {
            self.pending.extend(self.on_first.drain(..));
            if Frame::parse(bytes).unwrap().command() == Some(Cmd::PropMultiGet) {
                self.pending.extend(self.on_multi_get.drain(..));
            }
            self.inner.send_frame(bytes).await
        }

        fn poll_recv_frame(
            &mut self,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
            match self.pending.pop_front() {
                Some(frame) => core::task::Poll::Ready(Ok(frame)),
                None => self.inner.poll_recv_frame(cx),
            }
        }
    }

    fn reset_notice(status: Status) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::last_status(&mut buf, TID_UNSOLICITED, status).unwrap();
        buf[..len].to_vec()
    }

    fn session_notice(reason: SessionResetReason) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::session_reset(&mut buf, reason).unwrap();
        buf[..len].to_vec()
    }

    /// A device that boots as the port opens announces the boot and the
    /// session it discarded, whatever it calls the reason. None of that
    /// is the attach failing: the boot is the boot status, and the
    /// session is the one the attach is about to establish anyway.
    #[tokio::test]
    async fn an_attach_survives_a_device_booting_under_it() {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_multi_device(server));
        let link = NoisyLink {
            inner: SerialFrameLink::new(client),
            on_first: vec![
                reset_notice(Status::RESET_POWER_ON),
                session_notice(SessionResetReason::Reset),
            ],
            on_multi_get: vec![
                session_notice(SessionResetReason::Restored),
                session_notice(SessionResetReason::Other(9)),
                reset_notice(Status::RESET_WATCHDOG),
            ],
            pending: VecDeque::new(),
        };
        let mut radio = UlcpDevice::attach_existing(link, test_config())
            .await
            .expect("the attach absorbs every notice the boot produced");
        // The latest announcement is the boot status.
        assert_eq!(radio.boot_status(), Status::RESET_WATCHDOG);
        assert_eq!(radio.dev_version(), "fake-dev/0.1");
        assert_eq!(radio.max_frame_size(), 255);
        // Nothing was left latched to fail the first exchange after it.
        assert_eq!(radio.get_prop(prop::PHY_FREQ).await.unwrap(), b"");
        radio.set_prop(prop::PHY_TX_POWER, &[3]).await.unwrap();
    }

    /// A stand-in device whose answers a test writes: each request frame
    /// goes to `answer`, which returns the frames to reply with.
    struct ScriptLink {
        answer: Box<dyn FnMut(&Frame<'_>) -> Vec<Vec<u8>> + Send>,
        replies: VecDeque<Vec<u8>>,
    }

    impl FrameLink for ScriptLink {
        async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), UlcpError> {
            let request = Frame::parse(bytes).unwrap();
            let replies = (self.answer)(&request);
            self.replies.extend(replies);
            Ok(())
        }

        fn poll_recv_frame(
            &mut self,
            _: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<Vec<u8>, UlcpError>> {
            self.replies
                .pop_front()
                .map_or(core::task::Poll::Pending, |reply| {
                    core::task::Poll::Ready(Ok(reply))
                })
        }
    }

    /// Answer single and multi-property reads from `value`: a value, or
    /// the status refusing that property.
    fn answering(
        value: fn(u32) -> Result<Vec<u8>, Status>,
    ) -> Box<dyn FnMut(&Frame<'_>) -> Vec<Vec<u8>> + Send> {
        Box::new(move |request| {
            let tid = request.header.tid();
            let mut buf = vec![0u8; 512];
            let len = match request.command() {
                Some(Cmd::PropGet) => {
                    let key = PropPayload::parse(request.payload).unwrap().key;
                    match value(key) {
                        Ok(value) => frame::prop_is(&mut buf, tid, key, &value).unwrap(),
                        Err(status) => frame::last_status(&mut buf, tid, status).unwrap(),
                    }
                }
                Some(Cmd::PropMultiGet) => {
                    let mut writer = frame::prop_are(&mut buf, tid).unwrap();
                    for key in umsh_ulcp::frame::MultiGetKeys::new(request.payload) {
                        let key = key.unwrap();
                        match value(key) {
                            Ok(value) => writer.write_entry(key, &value).unwrap(),
                            Err(status) => writer.write_status_entry(status).unwrap(),
                        }
                    }
                    writer.finish()
                }
                other => panic!("unexpected request {other:?}"),
            };
            vec![buf[..len].to_vec()]
        })
    }

    fn scripted(
        answer: Box<dyn FnMut(&Frame<'_>) -> Vec<Vec<u8>> + Send>,
        caps: &[u32],
    ) -> UlcpDevice<ScriptLink> {
        let mut radio = UlcpDevice::bare(
            ScriptLink {
                answer,
                replies: VecDeque::new(),
            },
            test_config(),
        );
        radio.max_frame_size = 255;
        radio.caps = Some(caps.to_vec());
        radio
    }

    /// One member refused, one malformed, one longer than it should be:
    /// the report keeps everything it can read and marks the rest as not
    /// reported, rather than failing the whole policy.
    #[tokio::test]
    async fn a_policy_with_a_refused_member_reports_the_rest() {
        let mut radio = scripted(
            answering(|key| match key {
                prop::MAC_REPEATER_ENABLED => Ok(vec![2]),
                prop::MAC_REPEATER_REGIONS => Err(Status::PROP_NOT_FOUND),
                prop::MAC_REPEATER_DEFAULT_REGION => Ok(vec![0x12, 0x34, 0xEE]),
                prop::MAC_REPEATER_MIN_RSSI => Ok(vec![0xFF]),
                prop::MAC_REPEATER_MIN_SNR => Ok(vec![]),
                _ => panic!("unexpected property {key}"),
            }),
            &[cap::REPEATER],
        );
        let policy = radio.repeater_policy().await.unwrap().unwrap();
        assert_eq!(
            policy,
            RepeaterPolicy {
                enabled: Some(true),
                regions: None,
                default_region: Some(Some(RegionCode::from_bytes([0x12, 0x34]))),
                min_rssi: None,
                min_snr: Some(None),
            }
        );
    }

    /// The synchronization procedure is a report too: an unknown filter
    /// type, an unassigned snapshot code, a refused host key and a refused
    /// counter each cost only themselves.
    #[tokio::test]
    async fn sync_reports_around_what_it_cannot_read() {
        let mut radio = scripted(
            answering(|key| match key {
                prop::LAST_STATUS => Ok(vec![Status::OK.0 as u8]),
                prop::HOST_KEY => Err(Status::FAILURE),
                prop::PHY_ENABLED => Ok(vec![1]),
                prop::PHY_FREQ => Ok(vec![0x10, 0x27, 0, 0, 0xEE]),
                prop::DEV_NAME => Ok(b"Ridge\0".to_vec()),
                prop::SAVED => Ok(vec![7]),
                prop::HOST_RX_QUEUE_COUNT => Err(Status::PROP_NOT_FOUND),
                prop::HOST_RX_QUEUE_DROPPED => Ok(3u32.to_le_bytes().to_vec()),
                prop::HOST_RX_FILTERS => Ok(vec![2, items::FILTER_PKT_TYPE, 0, 2, 0x55, 9]),
                _ => panic!("unexpected property {key}"),
            }),
            &[cap::HOST_FILTER, cap::SAVE, cap::HOST_RX_QUEUE],
        );
        let sync = radio.sync(None).await.expect("sync completes");
        assert_eq!(sync.ownership, HostOwnership::Unknown);
        assert_eq!(sync.host_key, None);
        assert_eq!(sync.phy_enabled, Some(true));
        assert_eq!(sync.freq_khz, Some(10_000));
        assert_eq!(sync.device_name.as_deref(), Some("Ridge"));
        assert_eq!(sync.saved, Some(SavedSnapshot::Other(7)));
        assert_eq!(sync.queue_count, None);
        assert_eq!(sync.queue_dropped, Some(3));
        assert_eq!(
            sync.filters,
            Some(vec![
                ReportedFilter::Known(items::Filter::PktType(0)),
                ReportedFilter::Unknown {
                    filter_type: 0x55,
                    value: vec![9],
                },
            ])
        );
    }

    /// An answer that skips a position ends the reading there: what came
    /// before it stands, and the rest is asked for again rather than the
    /// whole batch failing.
    #[tokio::test]
    async fn a_multi_get_answer_out_of_order_keeps_what_matched() {
        let mut first = true;
        let mut radio = scripted(
            Box::new(move |request| {
                let tid = request.header.tid();
                let keys: Vec<u32> = umsh_ulcp::frame::MultiGetKeys::new(request.payload)
                    .map(Result::unwrap)
                    .collect();
                let mut buf = vec![0u8; 128];
                let mut writer = frame::prop_are(&mut buf, tid).unwrap();
                if std::mem::take(&mut first) {
                    // Asked for three; skips the second.
                    assert_eq!(keys.len(), 3);
                    writer.write_entry(keys[0], b"a").unwrap();
                    writer.write_entry(keys[2], b"c").unwrap();
                } else {
                    for key in keys {
                        writer.write_entry(key, &key.to_le_bytes()).unwrap();
                    }
                }
                let len = writer.finish();
                vec![buf[..len].to_vec()]
            }),
            &[],
        );
        let keys = [prop::PHY_FREQ, prop::PHY_TX_POWER, prop::DEV_NAME];
        let answers = radio.read_each(&keys).await.unwrap();
        assert_eq!(
            answers,
            vec![
                Ok(b"a".to_vec()),
                Ok(prop::PHY_TX_POWER.to_le_bytes().to_vec()),
                Ok(prop::DEV_NAME.to_le_bytes().to_vec()),
            ]
        );
    }

    /// An answer whose very first position is wrong makes no progress at
    /// all, so the batch is broken up rather than asked again forever.
    #[tokio::test]
    async fn a_multi_get_that_answers_nothing_usable_falls_back_to_single_reads() {
        let mut radio = scripted(
            Box::new(|request| {
                let tid = request.header.tid();
                let mut buf = vec![0u8; 128];
                let len = match request.command() {
                    Some(Cmd::PropMultiGet) => {
                        let mut writer = frame::prop_are(&mut buf, tid).unwrap();
                        writer.write_entry(60_000, b"?").unwrap();
                        writer.finish()
                    }
                    Some(Cmd::PropGet) => {
                        let key = PropPayload::parse(request.payload).unwrap().key;
                        frame::prop_is(&mut buf, tid, key, &[key as u8]).unwrap()
                    }
                    other => panic!("unexpected request {other:?}"),
                };
                vec![buf[..len].to_vec()]
            }),
            &[],
        );
        let keys = [prop::PHY_FREQ, prop::PHY_TX_POWER];
        let answers = radio.read_each(&keys).await.unwrap();
        assert_eq!(
            answers,
            vec![
                Ok(vec![prop::PHY_FREQ as u8]),
                Ok(vec![prop::PHY_TX_POWER as u8]),
            ]
        );
    }

    /// A session reset this host did not cause is an error, from the
    /// command path and the receive path alike: whatever it established
    /// in session state is gone, and it has to be told.
    #[tokio::test]
    async fn an_unrequested_session_reset_surfaces_on_receive() {
        let mut radio = attached_radio().await;
        radio
            .transmit(SESSION_RESET_AFTER, TxOptions::default())
            .await
            .unwrap();

        let result = core::future::poll_fn(|cx| radio.poll_receive_raw(cx)).await;
        assert!(matches!(
            result,
            Err(UlcpError::SessionReset(SessionResetReason::Attached))
        ));
    }

    #[tokio::test]
    async fn an_unrequested_session_reset_surfaces_from_a_command() {
        let mut radio = attached_radio().await;
        radio
            .transmit(SESSION_RESET_AFTER, TxOptions::default())
            .await
            .unwrap();

        assert!(matches!(
            radio.get_prop(prop::PHY_FREQ).await,
            Err(UlcpError::SessionReset(SessionResetReason::Attached))
        ));
        // Reported once: the latch is consumed, not sticky.
        assert!(radio.get_prop(prop::PHY_FREQ).await.is_ok());
    }

    /// A reset the host asked for takes the session with it, and says so
    /// through `PROP_LAST_STATUS`. Reporting the narrower loss as well
    /// would be noise.
    #[tokio::test]
    async fn a_requested_reset_absorbs_the_session_notice_it_causes() {
        let mut radio = attached_radio().await;
        assert_eq!(radio.reset().await.unwrap(), Status::RESET_SOFTWARE);
        assert!(radio.get_prop(prop::PHY_FREQ).await.is_ok());
    }

    #[tokio::test]
    async fn table_insert_replace_remove_with_secret_free_digests() {
        let mut radio = attached_radio().await;
        let mut item = vec![0x11u8; 64];
        item[32..].fill(0x22);
        let digest = radio
            .insert_prop_item(prop::HOST_PEER_KEYS, &item)
            .await
            .unwrap();
        // The digest form is the public key alone—no key material.
        assert_eq!(digest, vec![0x11; 32]);

        // Same public key, new pairwise keys: replacement, not ALREADY.
        let mut replacement = item.clone();
        replacement[32..].fill(0x33);
        let digest = radio
            .insert_prop_item(prop::HOST_PEER_KEYS, &replacement)
            .await
            .unwrap();
        assert_eq!(digest, vec![0x11; 32]);

        let removed = radio
            .remove_prop_item(prop::HOST_PEER_KEYS, &[0x11; 32])
            .await
            .unwrap();
        assert_eq!(removed, vec![0x11; 32]);
        let error = radio
            .remove_prop_item(prop::HOST_PEER_KEYS, &[0x11; 32])
            .await
            .unwrap_err();
        assert!(matches!(error, UlcpError::Status(status) if status == Status::ITEM_NOT_FOUND));
    }

    #[tokio::test]
    async fn duplicate_insert_reports_already() {
        let mut radio = attached_radio().await;
        let filter = [2u8, 0]; // FILTER_PKT_TYPE broadcast
        radio
            .insert_prop_item(prop::HOST_RX_FILTERS, &filter)
            .await
            .unwrap();
        let error = radio
            .insert_prop_item(prop::HOST_RX_FILTERS, &filter)
            .await
            .unwrap_err();
        assert!(matches!(error, UlcpError::Status(status) if status == Status::ALREADY));
    }

    #[tokio::test]
    async fn queue_drain_delivers_buffered_frames_then_completes() {
        let mut radio = attached_radio().await;
        let mut drained = Vec::new();
        radio
            .queue_drain_with(|data, meta| {
                drained.push((data.to_vec(), BufferedRxMeta::decode(meta).unwrap()));
            })
            .await
            .unwrap();
        assert_eq!(drained.len(), 2);
        assert!(
            drained
                .iter()
                .all(|(_, meta)| meta.flags & RX_FLAG_BUFFERED != 0)
        );
        assert_eq!((drained[0].1.age_s, drained[1].1.age_s), (5, 3));

        // The frames also surface through the ordinary receive path,
        // oldest first, wearing their buffered-delivery metadata.
        let mut buf = [0u8; 16];
        for (expected, age_s) in [(0xB0u8, 5), (0xB1, 3)] {
            let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(&buf[..info.len], &[expected]);
            let buffered = info.buffered.expect("drained frames report as buffered");
            assert_eq!(buffered.age_s, age_s);
            assert!(!buffered.acked);
        }
    }

    /// A device that never learned the multi-property commands answers
    /// with a plain status rather than a `CMD_PROP_ARE`. That is the
    /// exchange failing, not a malformed reply, and the client must say
    /// which status ended it.
    #[tokio::test]
    async fn a_device_without_multi_property_support_reports_unimplemented() {
        let mut radio = attached_radio().await;
        let error = radio
            .get_props(&[prop::PHY_FREQ, prop::PHY_TX_POWER])
            .await
            .expect_err("the fake device does not implement CMD_PROP_MULTI_GET");
        assert!(matches!(error, UlcpError::Status(Status::UNIMPLEMENTED)));
    }

    /// An administrative handle attaches to a device it does not own, so
    /// it refuses to *write* the host domain. Reading it is another
    /// matter: a local device answers an administrative read exactly as
    /// it answers a tethered one, and refusing here would only mean the
    /// question was never asked.
    ///
    /// The fake device implements no multi-property command, so a read
    /// that reaches the wire comes back UNIMPLEMENTED. That is the whole
    /// assertion—the refusal is the device's to make, not the handle's.
    #[tokio::test]
    async fn an_administrative_handle_reads_the_host_domain_but_will_not_write_it() {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_device(server));
        let mut radio = UlcpDevice::bare(SerialFrameLink::new(client), test_config());
        radio.mode = AttachMode::Administrative;
        // Standing in for the handshake this test skips: the fake device
        // has no CAP_CMD_MULTI, so `attach_administrative` cannot get
        // past its own multi-property read.
        radio.expected_session_reset = Some(SessionResetReason::Attached);

        let error = radio
            .get_props(&[prop::HOST_KEY, prop::HOST_AUTO_ACK])
            .await
            .expect_err("the fake device does not implement CMD_PROP_MULTI_GET");
        assert!(
            matches!(error, UlcpError::Status(Status::UNIMPLEMENTED)),
            "a host-domain read must reach the device, got {error:?}"
        );

        let error = radio
            .set_prop(prop::HOST_AUTO_ACK, &[1])
            .await
            .expect_err("a host-domain write needs a tethered attach");
        assert!(matches!(error, UlcpError::AdministrativeAttach));
    }

    #[tokio::test]
    async fn save_and_clear_complete_on_status() {
        let mut radio = attached_radio().await;
        radio.save().await.unwrap();
        radio.clear().await.unwrap();
    }

    #[tokio::test]
    async fn restore_update_form_reports_updated_and_retains_events() {
        let mut radio = attached_radio().await;
        assert_eq!(radio.restore().await.unwrap(), RestoreCompletion::Updated);
        assert_eq!(
            radio.pop_prop_event(),
            Some(PropEvent::Is {
                key: prop::PHY_FREQ,
                value: 905_000u32.to_le_bytes().to_vec(),
            })
        );
        assert_eq!(radio.pop_prop_event(), None);
    }

    #[tokio::test]
    async fn restore_reset_form_is_success_not_unexpected_reset() {
        let mut radio = attached_radio().await;
        radio.set_prop(RESTORE_RESET_FORM_KEY, &[1]).await.unwrap();
        assert_eq!(radio.restore().await.unwrap(), RestoreCompletion::Reset);

        // The consumed RESET_RESTORED must not resurface as an
        // unexpected reset on the next operation.
        radio.transmit(&[0x55], TxOptions::default()).await.unwrap();
        let mut buf = [0u8; 16];
        let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(&buf[..info.len], &[0x55]);
    }

    #[tokio::test]
    async fn unsolicited_table_notifications_are_retained_events() {
        let mut radio = attached_radio().await;
        let mut buf = [0u8; 48];
        let len = frame::prop_inserted(&mut buf, TID_UNSOLICITED, prop::HOST_RX_FILTERS, &[2, 0])
            .unwrap();
        radio.ingest_frame(&buf[..len]);
        let len = frame::prop_removed(
            &mut buf,
            TID_UNSOLICITED,
            prop::HOST_CHANNEL_KEYS,
            &[0x12, 0x34],
        )
        .unwrap();
        radio.ingest_frame(&buf[..len]);

        assert_eq!(
            radio.pop_prop_event(),
            Some(PropEvent::Inserted {
                key: prop::HOST_RX_FILTERS,
                digest: vec![2, 0],
            })
        );
        assert_eq!(
            radio.pop_prop_event(),
            Some(PropEvent::Removed {
                key: prop::HOST_CHANNEL_KEYS,
                digest: vec![0x12, 0x34],
            })
        );
        assert_eq!(radio.pop_prop_event(), None);
    }

    #[test]
    fn airtime_is_plausible() {
        // ~255-byte frame at SF11/BW250 is on the order of seconds.
        let airtime = lora_airtime_ms(11, 250_000, 5, 255);
        assert!((500..5_000).contains(&airtime), "airtime {airtime}");
        // Faster settings give shorter airtime.
        assert!(lora_airtime_ms(7, 250_000, 5, 255) < airtime);
    }
}
