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
use umsh_hal::{CadPolicy, Radio, RxInfo, Snr, TxError, TxOptions};
use umsh_ulcp::Status;
use umsh_ulcp::airtime::lora_airtime_ms;
use umsh_ulcp::alert::AlertState;
use umsh_ulcp::battery::BatteryStatus;
use umsh_ulcp::frame::{self, Cmd, Frame, StreamPayload, TID_UNSOLICITED};
use umsh_ulcp::gnss::GnssSnapshot;
use umsh_ulcp::hdlc;
use umsh_ulcp::host::{PropertyNotification, PropertyNotificationKind, TidAllocator};
use umsh_ulcp::ids::{self, cap, prop, stream};
use umsh_ulcp::items;
use umsh_ulcp::meta::{RxMeta, TX_FLAG_NOCCA, TxMeta};
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
    /// How long to wait for the device to answer one command, excluding
    /// airtime (transmit confirmations extend this by the frame
    /// airtime).
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
            sync_word: 0x1424,
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
    /// The device does not implement host filtering (minimal protocol
    /// only).
    Unsupported,
}

/// `PROP_SAVED`: what the device reports about its stored snapshot.
///
/// The two failure values are the point of the property. An unattended
/// repeater that comes back on stale configuration, or on none at all,
/// looks identical to a healthy one from the outside — this is how a
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
}

impl SavedSnapshot {
    fn from_octet(value: &[u8]) -> Result<Self, UlcpError> {
        match value {
            [ids::saved::NONE] => Ok(Self::None),
            [ids::saved::CURRENT] => Ok(Self::Current),
            [ids::saved::FALLBACK] => Ok(Self::Fallback),
            [ids::saved::UNREADABLE] => Ok(Self::Unreadable),
            _ => Err(UlcpError::Protocol("malformed PROP_SAVED")),
        }
    }

    /// Whether a saved snapshot is in effect at all, in either
    /// generation.
    pub fn is_saved(self) -> bool {
        matches!(self, Self::Current | Self::Fallback)
    }
}

/// Device state gathered by [`UlcpDevice::sync`]: the spec's
/// post-attach synchronization procedure. Fields whose capability the
/// device does not advertise are `None`; multi-value properties are the
/// digest forms and never contain key material.
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
    /// `PROP_PHY_ENABLED` — with a restored snapshot the PHY may
    /// already be up.
    pub phy_enabled: bool,
    /// `PROP_PHY_FREQ` in kHz.
    pub freq_khz: u32,
    /// `PROP_DEV_NAME`.
    pub device_name: String,
    /// `PROP_SAVED` (`CAP_SAVE`).
    pub saved: Option<SavedSnapshot>,
    /// `PROP_HOST_RX_QUEUE_COUNT` (`CAP_HOST_RX_QUEUE`).
    pub queue_count: Option<u16>,
    /// `PROP_HOST_RX_QUEUE_DROPPED` (`CAP_HOST_RX_QUEUE`).
    pub queue_dropped: Option<u32>,
    /// `PROP_HOST_RX_FILTERS` (`CAP_HOST_FILTER`).
    pub filters: Option<Vec<items::Filter>>,
    /// Derived channel identifiers of `PROP_HOST_CHANNEL_KEYS`
    /// (`CAP_HOST_KEYS`).
    pub host_channel_ids: Option<Vec<[u8; items::CHANNEL_ID_LEN]>>,
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepeaterPolicy {
    /// `PROP_MAC_REPEATER_ENABLED`: whether the on-board node forwards at
    /// all. The remaining fields are inert while this is false.
    pub enabled: bool,
    /// `PROP_MAC_REPEATER_REGIONS`: which region-tagged floods to forward.
    /// Empty imposes no regional restriction.
    pub regions: Vec<RegionCode>,
    /// `PROP_MAC_REPEATER_DEFAULT_REGION`: the tag inserted into an
    /// untagged flood before forwarding it. `None` forwards untagged.
    pub default_region: Option<RegionCode>,
    /// `PROP_MAC_REPEATER_MIN_RSSI` in dBm: floor below which a frame is
    /// not worth relaying. `None` accepts any.
    pub min_rssi: Option<i16>,
    /// `PROP_MAC_REPEATER_MIN_SNR` in dB. `None` accepts any.
    pub min_snr: Option<i8>,
}

/// The wall clock of a `CAP_TIME` device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceTime {
    /// `PROP_TIME`: Unix seconds, or `None` when the device does not know
    /// what time it is. Unsigned, so the encoding is wrap-free into 2106.
    pub epoch: Option<u32>,
    /// `PROP_TZ_OFFSET`: minutes east of UTC. Always present — where the
    /// device is meant to be is known even when the time is not.
    pub tz_offset_min: i16,
}

/// Everything a `CAP_GNSS` device reports about positioning: the switch,
/// the current fix, and the policy that governs what is done with it.
///
/// A report rather than a transaction, like [`RepeaterPolicy`]: the
/// properties are written separately, and reading this back after a
/// partial write shows exactly what the device holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GnssStatus {
    /// `PROP_GNSS_ENABLED`: whether the receiver is powered. Everything in
    /// `fix` reads as searching while this is false.
    pub enabled: bool,
    /// The five positioning telemetry properties, folded into one value.
    pub fix: GnssSnapshot,
    /// `PROP_GNSS_IDENT_UPDATE`: whether fixes refresh the advertised
    /// node identity's location.
    pub ident_update: bool,
    /// `PROP_GNSS_IDENT_PRECISION`: location bytes the advertised
    /// position is clamped to.
    pub ident_precision: u8,
    /// `PROP_GNSS_TIME_TRUST`: whether receiver-derived time may set the
    /// wall clock.
    pub time_trust: bool,
}

/// What a device announces without being asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvertPolicy {
    /// `PROP_ADVERT_INTERVAL`: seconds between signed identity
    /// advertisements, 0 for none.
    pub advert_interval_s: u32,
    /// `PROP_BEACON_INTERVAL`: seconds between empty beacons, 0 for none.
    pub beacon_interval_s: u32,
    /// `PROP_STARTUP_BEACON`: whether one beacon goes out at bring-up.
    pub startup_beacon: bool,
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
#[cfg(feature = "ble-radio")]
pub struct BleFrameLink {
    peripheral: btleplug::platform::Peripheral,
    frame_in: btleplug::api::Characteristic,
    receiver: BleNotificationReceiver,
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
        use futures_util::StreamExt;

        config.validate()?;

        let manager = btleplug::platform::Manager::new()
            .await
            .map_err(ble_error)?;
        let adapters = manager.adapters().await.map_err(ble_error)?;
        let service = uuid::Uuid::from_u128(umsh_ulcp::gatt::SERVICE_UUID);
        let deadline = Instant::now() + config.discovery_timeout;
        let mut matches = Vec::new();

        for adapter in adapters {
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
                break;
            }
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
            tokio::spawn(async move {
                while let Some(notification) = stream.next().await {
                    if notification.uuid == frame_out_uuid
                        && tx.send(notification.value).await.is_err()
                    {
                        break;
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
            frame_in,
            receiver: BleNotificationReceiver::new(notifications),
            segment_payload: config.segment_payload,
            operation_timeout: config.operation_timeout,
        })
    }

    /// Capture the backend's view of a failed link, then make a bounded
    /// best-effort disconnect so a subsequent discovery does not inherit a
    /// stale CoreBluetooth/BlueZ connection object.
    async fn diagnose_and_disconnect(&self, failure: String) -> UlcpError {
        use btleplug::api::Peripheral as _;

        let connected = match tokio::time::timeout(
            Duration::from_secs(2),
            self.peripheral.is_connected(),
        )
        .await
        {
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

#[cfg(feature = "ble-radio")]
impl FrameLink for BleFrameLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), UlcpError> {
        use btleplug::api::{Peripheral as _, WriteType};

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
    max_frame_size: usize,
    t_frame_ms: u32,
    dev_version: String,
    /// Hardware reset cause retained by the device before our protocol reset.
    boot_status: Status,
    tids: TidAllocator,
    /// Optional per-frame trace sink for both directions.
    trace: Option<FrameTrace>,
    mode: AttachMode,
}

/// The two relationships a host can have with a device.
///
/// They are different things, and conflating them is how one phone
/// administering ten repeaters ends up claiming all of them. Tethering is
/// a transient local relationship — at most one at a time, re-established
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
            max_frame_size: 0,
            t_frame_ms: 0,
            dev_version: String::new(),
            boot_status: Status::RESET_UNKNOWN,
            tids: TidAllocator::new(),
            trace: None,
            mode: AttachMode::Tethered,
        }
    }

    /// Which relationship this handle has with the device.
    pub fn attach_mode(&self) -> AttachMode {
        self.mode
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
            AttachMode::Administrative if host_domain => Err(UlcpError::AdministrativeAttach),
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
    /// — retained `PROP_LAST_STATUS` (the reset cause, preserved for
    /// [`Self::boot_status`] and [`Self::sync`]), the protocol version
    /// check, `PROP_DEV_VERSION`, and `PROP_PHY_MTU`. The PHY keeps
    /// whatever configuration and enable state it had; queued frames
    /// and provisioning are untouched. Follow with [`Self::sync`],
    /// [`Self::provision`], and drain the queue when ready.
    ///
    /// Use [`Self::attach_administrative`] to configure a device you do
    /// not intend to tether to — one phone administering ten repeaters
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
    /// host-domain write — `PROP_HOST_KEY`, the host key tables, the
    /// filter table, the delegation policy, and [`Self::provision`] —
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

    async fn attach_with_mode(
        link: L,
        config: UlcpDeviceConfig,
        mode: AttachMode,
    ) -> Result<Self, UlcpError> {
        let mut radio = Self::bare(link, config);
        radio.mode = mode;
        // Reading LAST_STATUS does not overwrite it, so sync() still
        // sees a retained reset code after this handshake.
        let boot_status = radio.get_prop(prop::LAST_STATUS).await?;
        radio.boot_status = decode_status(&boot_status);

        let version = radio.get_prop(prop::PROTOCOL_VERSION).await?;
        if version.first().copied() != Some(ids::PROTOCOL_MAJOR_VERSION) {
            return Err(UlcpError::Protocol("protocol major version mismatch"));
        }
        let dev_version = radio.get_prop(prop::DEV_VERSION).await?;
        radio.dev_version = String::from_utf8_lossy(&dev_version)
            .trim_end_matches('\0')
            .to_owned();

        let mtu = radio.get_prop(prop::PHY_MTU).await?;
        let [mtu_lo, mtu_hi, ..] = mtu[..] else {
            return Err(UlcpError::Protocol("malformed PROP_PHY_MTU"));
        };
        radio.max_frame_size = usize::from(u16::from_le_bytes([mtu_lo, mtu_hi]));
        if radio.max_frame_size == 0 {
            return Err(UlcpError::Protocol("device advertised zero MTU"));
        }
        radio.t_frame_ms = lora_airtime_ms(
            radio.config.spreading_factor,
            radio.config.bandwidth_hz,
            radio.config.coding_rate_denom,
            radio.max_frame_size,
        )
        .max(1);
        Ok(radio)
    }

    /// Give up this handle and recover the transport underneath it.
    ///
    /// The link stays open, so the device sees no detach and keeps its
    /// session-scoped state: this releases the *host's* bookkeeping, not
    /// the connection. Re-attaching the returned link produces a fresh
    /// handle, which is how a long-lived interactive host changes
    /// [`AttachMode`] — administrative for inspection, tethered for the
    /// one command that establishes a host domain — without making the
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
        self.link.send_frame(frame).await
    }

    /// The device's firmware version string (`PROP_DEV_VERSION`).
    pub fn dev_version(&self) -> &str {
        &self.dev_version
    }

    /// Fetch the device's human-readable `PROP_DEV_NAME`.
    pub async fn device_name(&mut self) -> Result<String, UlcpError> {
        let value = self.get_prop(prop::DEV_NAME).await?;
        let name = core::str::from_utf8(&value)
            .map_err(|_| UlcpError::Protocol("malformed PROP_DEV_NAME"))?;
        if name.is_empty() || value.len() > 64 || value.contains(&0) {
            return Err(UlcpError::Protocol("malformed PROP_DEV_NAME"));
        }
        Ok(name.to_owned())
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
    /// `Ok(None)` means the device does not advertise `CAP_BATTERY` (not
    /// battery powered). `Ok(Some(status))` with every field `None` means
    /// battery powered with unsupported reporting. A measurement the device
    /// cannot currently obtain surfaces as a command failure, never as
    /// `None` — battery is live telemetry, so this is deliberately not
    /// part of [`UlcpDevice::sync`].
    pub async fn battery_status(&mut self) -> Result<Option<BatteryStatus>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::BATTERY) {
            return Ok(None);
        }
        let value = self.get_prop(prop::BATTERY).await?;
        match BatteryStatus::decode(&value) {
            Ok(status) => Ok(Some(status)),
            Err(_) => Err(UlcpError::Protocol("malformed PROP_BATTERY")),
        }
    }

    /// Read the device's locate-alert state (`PROP_ALERT`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_ALERT` — it has
    /// no way to make itself conspicuous.
    pub async fn alert(&mut self) -> Result<Option<AlertState>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::ALERT) {
            return Ok(None);
        }
        let value = self.get_prop(prop::ALERT).await?;
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
    pub async fn set_alert(&mut self, state: AlertState) -> Result<AlertState, UlcpError> {
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
        if !self.capabilities().await?.contains(&cap::REPEATER) {
            return Ok(None);
        }
        let enabled = self.get_prop(prop::MAC_REPEATER_ENABLED).await?;
        let enabled = match enabled.first() {
            Some(&byte) => byte != 0,
            None => return Err(UlcpError::Protocol("malformed PROP_MAC_REPEATER_ENABLED")),
        };
        let regions = decode_region_list(&self.get_prop(prop::MAC_REPEATER_REGIONS).await?)?;
        let default_region =
            decode_region_code(&self.get_prop(prop::MAC_REPEATER_DEFAULT_REGION).await?)?;
        let min_rssi = decode_opt_i16(&self.get_prop(prop::MAC_REPEATER_MIN_RSSI).await?)
            .ok_or(UlcpError::Protocol("malformed PROP_MAC_REPEATER_MIN_RSSI"))?;
        let min_snr = decode_opt_i8(&self.get_prop(prop::MAC_REPEATER_MIN_SNR).await?)
            .ok_or(UlcpError::Protocol("malformed PROP_MAC_REPEATER_MIN_SNR"))?;
        Ok(Some(RepeaterPolicy {
            enabled,
            regions,
            default_region,
            min_rssi,
            min_snr,
        }))
    }

    /// Set which region-tagged floods the device forwards
    /// (`PROP_MAC_REPEATER_REGIONS`). An empty list clears the filter,
    /// which imposes no regional restriction rather than blocking every
    /// flood.
    ///
    /// Returns the list the device actually stored. A device with less
    /// capacity than the caller offered keeps a prefix, so a shorter
    /// return is a truncation, not an error.
    pub async fn set_repeater_regions(
        &mut self,
        regions: &[RegionCode],
    ) -> Result<Vec<RegionCode>, UlcpError> {
        let mut value = Vec::with_capacity(regions.len() * 2);
        for region in regions {
            value.extend_from_slice(&region.to_bytes());
        }
        let authoritative = self.set_prop(prop::MAC_REPEATER_REGIONS, &value).await?;
        decode_region_list(&authoritative)
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

    /// Read the device's wall clock and time zone (`PROP_TIME`,
    /// `PROP_TZ_OFFSET`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_TIME`.
    /// `Ok(Some(time))` with `time.epoch == None` means it has one and
    /// does not know what time it is — the state in which a device with a
    /// screen must show no clock at all.
    pub async fn time(&mut self) -> Result<Option<DeviceTime>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::TIME) {
            return Ok(None);
        }
        let epoch = decode_epoch(&self.get_prop(prop::TIME).await?)?;
        let tz_offset_min = decode_tz_offset(&self.get_prop(prop::TZ_OFFSET).await?)?;
        Ok(Some(DeviceTime {
            epoch,
            tz_offset_min,
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

    /// Set the device's local time-zone offset in minutes east of UTC
    /// (`PROP_TZ_OFFSET`).
    pub async fn set_tz_offset(&mut self, minutes: i16) -> Result<i16, UlcpError> {
        let authoritative = self
            .set_prop(prop::TZ_OFFSET, &minutes.to_le_bytes())
            .await?;
        decode_tz_offset(&authoritative)
    }

    /// Read everything the device reports about positioning
    /// (`PROP_GNSS_*`).
    ///
    /// `Ok(None)` means the device does not advertise `CAP_GNSS`. The fix
    /// is live telemetry, so a disabled or searching receiver reports
    /// [`GnssSnapshot::SEARCHING`] rather than an error.
    pub async fn gnss_status(&mut self) -> Result<Option<GnssStatus>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::GNSS) {
            return Ok(None);
        }
        let enabled = decode_bool(
            &self.get_prop(prop::GNSS_ENABLED).await?,
            "PROP_GNSS_ENABLED",
        )?;
        let mut fix = GnssSnapshot::SEARCHING;
        for key in [
            prop::GNSS_FIX,
            prop::GNSS_LOCATION,
            prop::GNSS_ALTITUDE,
            prop::GNSS_PRECISION,
            prop::GNSS_SATELLITES,
        ] {
            let value = self.get_prop(key).await?;
            fix.absorb(key, &value)
                .map_err(|_| UlcpError::Protocol("malformed PROP_GNSS_* value"))?;
        }
        let ident_update = decode_bool(
            &self.get_prop(prop::GNSS_IDENT_UPDATE).await?,
            "PROP_GNSS_IDENT_UPDATE",
        )?;
        let ident_precision = match self.get_prop(prop::GNSS_IDENT_PRECISION).await?[..] {
            [precision] => precision,
            _ => return Err(UlcpError::Protocol("malformed PROP_GNSS_IDENT_PRECISION")),
        };
        let time_trust = decode_bool(
            &self.get_prop(prop::GNSS_TIME_TRUST).await?,
            "PROP_GNSS_TIME_TRUST",
        )?;
        Ok(Some(GnssStatus {
            enabled,
            fix,
            ident_update,
            ident_precision,
            time_trust,
        }))
    }

    /// Read the device's advertisement policy, or `None` on a device
    /// without `CAP_ADVERT`.
    pub async fn advert_policy(&mut self) -> Result<Option<AdvertPolicy>, UlcpError> {
        if !self.capabilities().await?.contains(&cap::ADVERT) {
            return Ok(None);
        }
        let advert_interval_s = self.get_interval(prop::ADVERT_INTERVAL).await?;
        let beacon_interval_s = self.get_interval(prop::BEACON_INTERVAL).await?;
        let startup_beacon = decode_bool(
            &self.get_prop(prop::STARTUP_BEACON).await?,
            "PROP_STARTUP_BEACON",
        )?;
        Ok(Some(AdvertPolicy {
            advert_interval_s,
            beacon_interval_s,
            startup_beacon,
        }))
    }

    async fn get_interval(&mut self, key: u32) -> Result<u32, UlcpError> {
        decode_interval(&self.get_prop(key).await?)
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
        decode_bool(&authoritative, "PROP_STARTUP_BEACON")
    }

    /// Power the GNSS receiver on or off (`PROP_GNSS_ENABLED`).
    pub async fn set_gnss_enabled(&mut self, enabled: bool) -> Result<bool, UlcpError> {
        let authoritative = self.set_prop(prop::GNSS_ENABLED, &[enabled as u8]).await?;
        decode_bool(&authoritative, "PROP_GNSS_ENABLED")
    }

    /// Set whether fixes refresh the advertised node identity's location
    /// (`PROP_GNSS_IDENT_UPDATE`).
    pub async fn set_gnss_ident_update(&mut self, enabled: bool) -> Result<bool, UlcpError> {
        let authoritative = self
            .set_prop(prop::GNSS_IDENT_UPDATE, &[enabled as u8])
            .await?;
        decode_bool(&authoritative, "PROP_GNSS_IDENT_UPDATE")
    }

    /// Set the precision the advertised location is clamped to, in
    /// location bytes (`PROP_GNSS_IDENT_PRECISION`).
    pub async fn set_gnss_ident_precision(&mut self, precision: u8) -> Result<u8, UlcpError> {
        let authoritative = self
            .set_prop(prop::GNSS_IDENT_PRECISION, &[precision])
            .await?;
        match authoritative[..] {
            [stored] => Ok(stored),
            _ => Err(UlcpError::Protocol("malformed PROP_GNSS_IDENT_PRECISION")),
        }
    }

    /// Set whether receiver-derived time may set the wall clock
    /// (`PROP_GNSS_TIME_TRUST`).
    ///
    /// Clearing it leaves a manually-set clock proof against a jammed or
    /// spoofed sky; position reporting is unaffected.
    pub async fn set_gnss_time_trust(&mut self, trust: bool) -> Result<bool, UlcpError> {
        let authoritative = self.set_prop(prop::GNSS_TIME_TRUST, &[trust as u8]).await?;
        decode_bool(&authoritative, "PROP_GNSS_TIME_TRUST")
    }

    async fn initialize(&mut self) -> Result<(), UlcpError> {
        // The reset-status property is deliberately read before CMD_RST. The
        // protocol requires the device to retain its hardware boot cause for this
        // first query; CMD_RST would replace it with RESET_SOFTWARE.
        let boot_status = self.get_prop(prop::LAST_STATUS).await?;
        self.boot_status = decode_status(&boot_status);

        // Reset and wait for the reset notification. The TID is
        // ignored for CMD_RST; the notification is unsolicited.
        let mut buf = [0u8; 2];
        let len = frame::reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let deadline = Instant::now() + self.config.response_timeout;
        self.wait_reset(deadline).await?;

        // Reject devices speaking an incompatible protocol revision.
        let version = self.get_prop(prop::PROTOCOL_VERSION).await?;
        if version.first().copied() != Some(ids::PROTOCOL_MAJOR_VERSION) {
            return Err(UlcpError::Protocol("protocol major version mismatch"));
        }

        let dev_version = self.get_prop(prop::DEV_VERSION).await?;
        self.dev_version = String::from_utf8_lossy(&dev_version)
            .trim_end_matches('\0')
            .to_owned();

        let mtu = self.get_prop(prop::PHY_MTU).await?;
        let [mtu_lo, mtu_hi, ..] = mtu[..] else {
            return Err(UlcpError::Protocol("malformed PROP_PHY_MTU"));
        };
        self.max_frame_size = usize::from(u16::from_le_bytes([mtu_lo, mtu_hi]));
        if self.max_frame_size == 0 {
            return Err(UlcpError::Protocol("device advertised zero MTU"));
        }

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

        self.t_frame_ms = lora_airtime_ms(
            config.spreading_factor,
            config.bandwidth_hz,
            config.coding_rate_denom,
            self.max_frame_size,
        )
        .max(1);
        Ok(())
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

    /// Insert one item into a multi-value property via
    /// `CMD_PROP_INSERT`, returning the inserted item's digest form
    /// from the correlated `CMD_PROP_INSERTED`.
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
    /// `CMD_PROP_REMOVE`, returning the removed item's digest form from
    /// the correlated `CMD_PROP_REMOVED`.
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
    /// (data, trailing metadata bytes) delivered before completion —
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
            if let Some(status) = self.seen_reset.take() {
                return Err(UlcpError::UnexpectedReset(status));
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
    /// a power cycle — restoring its saved snapshot when one exists,
    /// factory configuration otherwise. All session-scoped state and
    /// cached views are gone; follow with [`Self::sync`].
    pub async fn reset(&mut self) -> Result<Status, UlcpError> {
        let mut buf = [0u8; 2];
        let len = frame::reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| UlcpError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let deadline = Instant::now() + self.config.response_timeout;
        self.wait_reset(deadline).await
    }

    /// Factory-reset the device (`CMD_FACTORY_RESET`): erase ALL mutable
    /// state — saved provisioning, the device identity, BLE bonds, and the
    /// pairing PIN — and reboot to a blank factory state. Unlike
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

    /// Revert the device to its saved snapshot (`CMD_RESTORE`; requires
    /// `CAP_SAVE`), accepting both spec-permitted completion forms.
    pub async fn restore(&mut self) -> Result<RestoreCompletion, UlcpError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = frame::restore(&mut buf, tid).map_err(|_| UlcpError::Protocol("frame encode"))?;
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
                        Ok(RestoreCompletion::Updated)
                    } else {
                        Err(UlcpError::Status(status))
                    };
                }
                return Err(UlcpError::Protocol("unexpected restore response"));
            }
            match self.seen_reset.take() {
                Some(status) if status == Status::RESET_RESTORED => {
                    return Ok(RestoreCompletion::Reset);
                }
                Some(status) => return Err(UlcpError::UnexpectedReset(status)),
                None => {}
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

    /// Fetch and decode `PROP_CAPS`.
    pub async fn capabilities(&mut self) -> Result<Vec<u32>, UlcpError> {
        let raw = self.get_prop(prop::CAPS).await?;
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let (value, used) = pui::decode(&raw[offset..])
                .map_err(|_| UlcpError::Protocol("malformed PROP_CAPS"))?;
            caps.push(value);
            offset += used;
        }
        Ok(caps)
    }

    /// Run the spec's post-attach synchronization procedure: fetch the
    /// retained `PROP_LAST_STATUS` (detecting a reset since the last
    /// contact), the capability list, the configured host identity —
    /// yielding an ownership verdict against `expected_host_key` — and
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

        // Step 2: ownership.
        let (host_key, ownership) = if has(cap::HOST_FILTER) {
            let value = self.get_prop(prop::HOST_KEY).await?;
            match <[u8; 32]>::try_from(value.as_slice()) {
                Ok(key) => {
                    let ownership = match expected_host_key {
                        Some(expected) if *expected == key => HostOwnership::Ours,
                        _ => HostOwnership::OtherHost(key),
                    };
                    (Some(key), ownership)
                }
                Err(_) if value.is_empty() => (None, HostOwnership::Unclaimed),
                Err(_) => return Err(UlcpError::Protocol("malformed PROP_HOST_KEY")),
            }
        } else {
            (None, HostOwnership::Unsupported)
        };

        // Step 3: the device-domain and host-domain state we depend
        // on, gated by the advertised capabilities.
        let phy_enabled = self.get_prop(prop::PHY_ENABLED).await? == [1];
        let freq = self.get_prop(prop::PHY_FREQ).await?;
        let freq_khz = u32::from_le_bytes(
            freq.as_slice()
                .try_into()
                .map_err(|_| UlcpError::Protocol("malformed PROP_PHY_FREQ"))?,
        );
        let device_name = self.device_name().await?;
        let saved = match has(cap::SAVE) {
            true => Some(SavedSnapshot::from_octet(
                &self.get_prop(prop::SAVED).await?,
            )?),
            false => None,
        };
        let (queue_count, queue_dropped) = if has(cap::HOST_RX_QUEUE) {
            let count = self.get_prop(prop::HOST_RX_QUEUE_COUNT).await?;
            let dropped = self.get_prop(prop::HOST_RX_QUEUE_DROPPED).await?;
            (
                Some(u16::from_le_bytes(count.as_slice().try_into().map_err(
                    |_| UlcpError::Protocol("malformed PROP_HOST_RX_QUEUE_COUNT"),
                )?)),
                Some(u32::from_le_bytes(dropped.as_slice().try_into().map_err(
                    |_| UlcpError::Protocol("malformed PROP_HOST_RX_QUEUE_DROPPED"),
                )?)),
            )
        } else {
            (None, None)
        };
        let filters = match has(cap::HOST_FILTER) {
            true => Some(decode_filter_table(
                &self.get_prop(prop::HOST_RX_FILTERS).await?,
            )?),
            false => None,
        };
        let (host_channel_ids, host_peer_keys) = if has(cap::HOST_KEYS) {
            (
                Some(decode_fixed_list::<{ items::CHANNEL_ID_LEN }>(
                    &self.get_prop(prop::HOST_CHANNEL_KEYS).await?,
                    "malformed PROP_HOST_CHANNEL_KEYS digest",
                )?),
                Some(decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>(
                    &self.get_prop(prop::HOST_PEER_KEYS).await?,
                    "malformed PROP_HOST_PEER_KEYS digest",
                )?),
            )
        } else {
            (None, None)
        };
        let auto_ack = match has(cap::HOST_AUTO_ACK) {
            true => Some(self.get_prop(prop::HOST_AUTO_ACK).await? == [1]),
            false => None,
        };
        let dev_key = if has(cap::DEV_IDENTITY) {
            let value = self.get_prop(prop::DEV_KEY).await?;
            match <[u8; 32]>::try_from(value.as_slice()) {
                Ok(key) => Some(key),
                Err(_) if value.is_empty() => None,
                Err(_) => return Err(UlcpError::Protocol("malformed PROP_DEV_KEY")),
            }
        } else {
            None
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
    /// surface can detect it — and a digest over the secret state would
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
    /// it has *not* rebooted the rewrite is redundant — that is the
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
        let desired_ids: Vec<[u8; items::CHANNEL_ID_LEN]> = desired
            .channel_keys
            .iter()
            .map(|key| engine.derive_channel_id(&ChannelKey(*key)).0)
            .collect();
        let current_ids = if report.host_replaced {
            Vec::new()
        } else {
            decode_fixed_list::<{ items::CHANNEL_ID_LEN }>(
                &self.get_prop(prop::HOST_CHANNEL_KEYS).await?,
                "malformed PROP_HOST_CHANNEL_KEYS digest",
            )?
        };
        if current_ids.iter().any(|id| !desired_ids.contains(id)) {
            let table: Vec<u8> = desired.channel_keys.concat();
            self.set_prop(prop::HOST_CHANNEL_KEYS, &table).await?;
            report.channels_replaced = true;
        } else {
            // Insert every desired key, including ones already reported.
            // A channel key *is* its own item, so a duplicate insert
            // asserts a state that already holds: `STATUS_ALREADY` says
            // "the entry is present", which is what was asked for, and
            // is treated as success. (Peers differ — a matching public
            // key replaces the entry's key material — so their inserts
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
            decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>(
                &self.get_prop(prop::HOST_PEER_KEYS).await?,
                "malformed PROP_HOST_PEER_KEYS digest",
            )?
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

    async fn finish_prop_transaction(
        &mut self,
        tid: u8,
        key: u32,
        policy: PropResponsePolicy,
    ) -> Result<Vec<u8>, UlcpError> {
        let deadline = Instant::now() + self.config.response_timeout;
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
        };
        if self.prop_events.len() >= PROP_EVENT_DEPTH {
            self.prop_events.pop_front();
        }
        self.prop_events.push_back(event);
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
            // Drain responses before honoring a reset notice: if both
            // arrived in one read, the response was sent first and the
            // command did complete. The reset stays latched for the
            // next receive poll.
            while let Some(response) = self.responses.pop_front() {
                if response.tid == tid {
                    return Ok(response);
                }
                // A stale response from an earlier timed-out
                // transaction; drop it.
            }
            if let Some(status) = self.seen_reset.take() {
                return Err(UlcpError::UnexpectedReset(status));
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

    /// Read and ingest one frame before `deadline`; returns whether it
    /// was a stream frame that is now the back of `rx_queue`.
    async fn read_more(&mut self, deadline: Instant) -> Result<bool, UlcpError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(UlcpError::Timeout);
        }
        let frame = match tokio::time::timeout(deadline - now, self.link.recv_frame()).await {
            Err(_elapsed) => return Err(UlcpError::Timeout),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(frame)) => frame,
        };
        Ok(self.ingest_frame(&frame))
    }

    fn pop_rx(&mut self, buf: &mut [u8]) -> Option<RxInfo> {
        let packet = self.rx_queue.pop_front()?;
        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        Some(RxInfo {
            len,
            rssi: packet.meta.rssi_dbm.unwrap_or(0),
            snr: Snr::from_centibels(packet.meta.snr_cb.unwrap_or(0)),
            lqi: packet.meta.lqi,
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
        loop {
            let tid = self.alloc_tid();
            let mut frame_buf = vec![0u8; data.len() + metadata.len() + 16];
            let frame_len = frame::str_send(&mut frame_buf, tid, stream::PHY_RAW, data, metadata)
                .map_err(|_| TxError::Io(UlcpError::Protocol("frame encode")))?;
            self.send(&frame_buf[..frame_len])
                .await
                .map_err(TxError::Io)?;

            // The confirmation arrives only after the frame is on the
            // air (or definitively failed), so allow for airtime.
            let deadline = Instant::now()
                + self.config.response_timeout
                + Duration::from_millis(u64::from(self.t_frame_ms) * 2);
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
    /// able to put exactly those bytes on the wire — including fields
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
            if let Some(status) = self.seen_reset.take() {
                return core::task::Poll::Ready(Err(UlcpError::UnexpectedReset(status)));
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
                core::task::Poll::Ready(Err(error)) => return core::task::Poll::Ready(Err(error)),
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
    /// `response_timeout + 2 × t_frame_ms` while the frame goes out on air. This
    /// is inherent to the half-duplex [`Radio::transmit`] contract and a real
    /// radio behaves the same way. Frames the device receives during this window
    /// are not lost — they are queued (see [`wait_response`](Self::wait_response)
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
        let mut meta = TxMeta::default();
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
            if let Some(status) = self.seen_reset.take() {
                return core::task::Poll::Ready(Err(UlcpError::UnexpectedReset(status)));
            }
            if let Some(info) = self.pop_rx(buf) {
                return core::task::Poll::Ready(Ok(info));
            }

            match self.link.poll_recv_frame(cx) {
                core::task::Poll::Ready(Ok(frame)) => {
                    self.ingest_frame(&frame);
                }
                core::task::Poll::Ready(Err(error)) => return core::task::Poll::Ready(Err(error)),
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
}

fn decode_status(value: &[u8]) -> Status {
    match pui::decode(value) {
        Ok((code, _)) => Status(code),
        Err(_) => Status::FAILURE,
    }
}

/// Decode a `PROP_HOST_RX_FILTERS` digest table (PUI-length-prefixed
/// filter items).
fn decode_filter_table(value: &[u8]) -> Result<Vec<items::Filter>, UlcpError> {
    let mut filters = Vec::new();
    for item in items::prefixed_items(value) {
        let item = item.map_err(|_| UlcpError::Protocol("malformed PROP_HOST_RX_FILTERS"))?;
        filters.push(
            items::Filter::decode(item)
                .map_err(|_| UlcpError::Protocol("malformed PROP_HOST_RX_FILTERS"))?,
        );
    }
    Ok(filters)
}

/// Decode `PROP_MAC_REPEATER_REGIONS`: 2-byte region codes back to back,
/// with no separator and no length prefix.
fn decode_region_list(value: &[u8]) -> Result<Vec<RegionCode>, UlcpError> {
    if value.len() % 2 != 0 {
        return Err(UlcpError::Protocol("malformed PROP_MAC_REPEATER_REGIONS"));
    }
    Ok(value
        .chunks_exact(2)
        .map(|code| RegionCode::from_bytes([code[0], code[1]]))
        .collect())
}

/// Decode a single optional region code. Empty means unset.
fn decode_region_code(value: &[u8]) -> Result<Option<RegionCode>, UlcpError> {
    match value {
        [] => Ok(None),
        [high, low] => Ok(Some(RegionCode::from_bytes([*high, *low]))),
        _ => Err(UlcpError::Protocol(
            "malformed PROP_MAC_REPEATER_DEFAULT_REGION",
        )),
    }
}

/// Decode an optional INT16 gate. Empty means unset; `None` is malformed.
fn decode_opt_i16(value: &[u8]) -> Option<Option<i16>> {
    match value {
        [] => Some(None),
        [low, high] => Some(Some(i16::from_le_bytes([*low, *high]))),
        _ => None,
    }
}

/// Decode an optional INT8 gate. Empty means unset; `None` is malformed.
fn decode_opt_i8(value: &[u8]) -> Option<Option<i8>> {
    match value {
        [] => Some(None),
        [byte] => Some(Some(*byte as i8)),
        _ => None,
    }
}

/// Decode a `PROP_ALERT` value: exactly one PUI naming a known state.
fn decode_alert(value: &[u8]) -> Result<AlertState, UlcpError> {
    const MALFORMED: &str = "malformed PROP_ALERT";
    let (code, consumed) = pui::decode(value).map_err(|_| UlcpError::Protocol(MALFORMED))?;
    if consumed != value.len() {
        return Err(UlcpError::Protocol(MALFORMED));
    }
    AlertState::from_code(code).ok_or(UlcpError::Protocol(MALFORMED))
}

/// Decode a `PROP_TIME` value. Empty means the device does not know what
/// time it is, which is an answer rather than a malformed one.
fn decode_epoch(value: &[u8]) -> Result<Option<u32>, UlcpError> {
    match value {
        [] => Ok(None),
        [a, b, c, d] => Ok(Some(u32::from_le_bytes([*a, *b, *c, *d]))),
        _ => Err(UlcpError::Protocol("malformed PROP_TIME")),
    }
}

/// Decode a `PROP_TZ_OFFSET` value: minutes east of UTC, always present.
fn decode_tz_offset(value: &[u8]) -> Result<i16, UlcpError> {
    match value {
        [low, high] => Ok(i16::from_le_bytes([*low, *high])),
        _ => Err(UlcpError::Protocol("malformed PROP_TZ_OFFSET")),
    }
}

/// Decode a single-octet boolean property, naming the property in the
/// error so a malformed one is attributable.
fn decode_bool(value: &[u8], what: &'static str) -> Result<bool, UlcpError> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(UlcpError::Protocol(what)),
    }
}

/// Decode a `UINT32_LE` announcement interval in seconds.
fn decode_interval(value: &[u8]) -> Result<u32, UlcpError> {
    match value {
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(UlcpError::Protocol("malformed announcement interval")),
    }
}

/// Decode a digest table of fixed-size items.
fn decode_fixed_list<const N: usize>(
    value: &[u8],
    what: &'static str,
) -> Result<Vec<[u8; N]>, UlcpError> {
    items::fixed_items::<N>(value)
        .map(|iterator| iterator.copied().collect())
        .map_err(|_| UlcpError::Protocol(what))
}

/// Render one ULCP frame as a one-line human-readable summary:
/// command, TID, property mnemonic, and the decoded status where the
/// payload is a `PROP_LAST_STATUS` value. Values are summarized by
/// length — never dumped — so traces cannot leak key material.
pub fn describe_frame(bytes: &[u8]) -> String {
    umsh_ulcp::FrameDescription(bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use umsh_ulcp::PropPayload;
    use umsh_ulcp::meta::{BufferedRxMeta, RX_FLAG_BUFFERED};

    /// Payload that makes the fake device report a CCA failure.
    const CCA_FAIL: &[u8] = b"cca-fail";
    /// Payload that makes the fake device report success and then
    /// announce a spurious watchdog reset.
    const RESET_AFTER: &[u8] = b"reset-after";
    /// Property that switches the fake device's `CMD_RESTORE` completion
    /// to the reset form.
    const RESTORE_RESET_FORM_KEY: u32 = 59_999;

    /// Minimal in-process device: answers the initialization handshake,
    /// stores property sets and multi-value tables, and echoes
    /// transmitted frames back as received frames.
    async fn fake_device(mut io: DuplexStream) {
        let mut decoder = hdlc::Decoder::<WIRE_BUF>::new();
        let mut props: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut tables: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        let mut chunk = [0u8; READ_CHUNK];
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
                match frame.command().expect("host sent unknown command") {
                    Cmd::Reset => {
                        let len =
                            frame::last_status(&mut buf, TID_UNSOLICITED, Status::RESET_SOFTWARE)
                                .unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropGet => {
                        let key = PropPayload::parse(frame.payload).unwrap().key;
                        let value: Vec<u8> = match key {
                            prop::LAST_STATUS => vec![Status::RESET_POWER_ON.0 as u8],
                            prop::PROTOCOL_VERSION => {
                                vec![ids::PROTOCOL_MAJOR_VERSION, ids::PROTOCOL_MINOR_VERSION]
                            }
                            prop::DEV_VERSION => b"fake-dev/0.1\0".to_vec(),
                            prop::PHY_MTU => 255u16.to_le_bytes().to_vec(),
                            _ => props.get(&key).cloned().unwrap_or_default(),
                        };
                        let len = frame::prop_is(&mut buf, tid, key, &value).unwrap();
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
                    Cmd::Save | Cmd::Clear | Cmd::FactoryReset => {
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
                    Cmd::PropIs | Cmd::StrRecv | Cmd::PropInserted | Cmd::PropRemoved => {
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

    #[tokio::test]
    async fn initialization_handshake() {
        let radio = attached_radio().await;
        assert_eq!(radio.max_frame_size(), 255);
        assert_eq!(radio.dev_version(), "fake-dev/0.1");
        assert_eq!(radio.boot_status(), Status::RESET_POWER_ON);
        assert!(radio.t_frame_ms() > 0);
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

    #[tokio::test]
    async fn table_insert_replace_remove_with_secret_free_digests() {
        let mut radio = attached_radio().await;
        let mut item = vec![0x11u8; 64];
        item[32..].fill(0x22);
        let digest = radio
            .insert_prop_item(prop::HOST_PEER_KEYS, &item)
            .await
            .unwrap();
        // The digest form is the public key alone — no key material.
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
        // oldest first.
        let mut buf = [0u8; 16];
        for expected in [0xB0u8, 0xB1] {
            let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(&buf[..info.len], &[expected]);
        }
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
