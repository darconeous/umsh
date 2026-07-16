//! Host-side client for the minimal companion-radio (NCP) protocol.
//!
//! [`CompanionRadio`] drives an NCP over a frame-oriented [`FrameLink`], and
//! exposes the link as a [`umsh_hal::Radio`] so the host can run the
//! full MAC/node stack with the NCP acting purely as the PHY.
//!
//! The wire format lives in [`umsh_companion`] (re-exported as
//! [`crate::companion`]); this module owns the host-side session
//! behavior: the reset/configure handshake, request/response
//! transactions, and queueing of frames that arrive while a command is
//! in flight.
//!
//! See `docs/protocol/src/companion-radio-minimal.md` for the protocol.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use umsh_companion::Status;
use umsh_companion::airtime::lora_airtime_ms;
use umsh_companion::frame::{self, Cmd, Frame, PropPayload, StreamPayload, TID_UNSOLICITED};
use umsh_companion::hdlc;
use umsh_companion::ids::{self, cap, prop, stream};
use umsh_companion::items;
use umsh_companion::meta::{RxMeta, TX_FLAG_NOCCA, TxMeta};
use umsh_companion::pui;
use umsh_core::ChannelKey;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_hal::{CadPolicy, Radio, RxInfo, Snr, TxError, TxOptions};

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
pub enum CompanionRadioError {
    Io(io::Error),
    /// The stream reached end-of-file; the NCP link is gone.
    Disconnected,
    /// The NCP violated the companion-radio protocol.
    Protocol(&'static str),
    /// The NCP reported a failure status for a command.
    Status(Status),
    /// The NCP reset outside of an initialization handshake, losing
    /// its configuration. The radio must be re-initialized.
    UnexpectedReset(Status),
    /// The frame exceeds the NCP's advertised MTU.
    FrameTooLarge(usize),
    /// The NCP did not answer a command in time.
    Timeout,
    /// A non-stream transport failed.
    Transport(String),
}

impl core::fmt::Display for CompanionRadioError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Disconnected => write!(formatter, "companion link disconnected"),
            Self::Protocol(message) => write!(formatter, "protocol error: {message}"),
            Self::Status(status) => write!(formatter, "NCP reported {status:?}"),
            Self::UnexpectedReset(status) => {
                write!(formatter, "NCP reset unexpectedly ({status:?})")
            }
            Self::FrameTooLarge(len) => write!(formatter, "frame too large: {len} bytes"),
            Self::Timeout => write!(formatter, "timed out waiting for NCP response"),
            Self::Transport(message) => write!(formatter, "transport error: {message}"),
        }
    }
}

impl std::error::Error for CompanionRadioError {}

impl From<io::Error> for CompanionRadioError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// RF and session configuration applied during initialization.
#[derive(Clone, Debug)]
pub struct CompanionRadioConfig {
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
    /// How long to wait for the NCP to answer one command, excluding
    /// airtime (transmit confirmations extend this by the frame
    /// airtime).
    pub response_timeout: Duration,
}

impl CompanionRadioConfig {
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

/// Which NCP-to-host property command carried a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseKind {
    /// `CMD_PROP_IS`
    Is,
    /// `CMD_PROP_INSERTED`
    Inserted,
    /// `CMD_PROP_REMOVED`
    Removed,
}

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
/// caller: NCP state can change for reasons the host did not initiate,
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

/// Direction of a traced companion frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceDirection {
    HostToNcp,
    NcpToHost,
}

impl core::fmt::Display for TraceDirection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::HostToNcp => "host→ncp",
            Self::NcpToHost => "ncp→host",
        })
    }
}

/// Sink for per-frame trace lines (see
/// [`CompanionRadio::set_frame_trace`]).
pub type FrameTrace = Box<dyn FnMut(TraceDirection, &str) + Send>;

/// How the NCP reported a successful `CMD_RESTORE`. Both forms leave
/// the NCP in the same configuration; they differ only in reporting and
/// session-state handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreCompletion {
    /// Update form: values reverted in place (each change published as
    /// an unsolicited update; see [`CompanionRadio::pop_prop_event`]).
    Updated,
    /// Reset form (`STATUS_RESET_RESTORED`): the NCP also reset its
    /// protocol session state. Cached property views are invalid;
    /// saved properties hold their saved values.
    Reset,
}

/// Verdict of comparing `PROP_HOST_KEY` against this host's identity
/// (spec §Attach, Detach, and Synchronization, step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOwnership {
    /// The NCP is configured for this host: queued traffic and
    /// provisioning are ours to use and drain.
    Ours,
    /// No host identity is configured.
    Unclaimed,
    /// Another host has taken the radio over; the queue and
    /// provisioning belong to that identity and must not be treated as
    /// ours without deliberately replacing it (see
    /// [`CompanionRadio::provision`]).
    OtherHost([u8; 32]),
    /// The NCP does not implement host filtering (minimal protocol
    /// only).
    Unsupported,
}

/// NCP state gathered by [`CompanionRadio::sync`]: the spec's
/// post-attach synchronization procedure. Fields whose capability the
/// NCP does not advertise are `None`; multi-value properties are the
/// digest forms and never contain key material.
#[derive(Clone, Debug)]
pub struct NcpSync {
    /// Retained `PROP_LAST_STATUS`.
    pub last_status: Status,
    /// `last_status` was a reset code: the NCP has reset since the
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
    pub saved: Option<bool>,
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

impl NcpSync {
    /// Whether the NCP advertised this capability code.
    pub fn has_capability(&self, capability: u32) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// The host-domain state [`CompanionRadio::provision`] establishes on
/// the NCP.
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
    /// public-key membership: an entry whose public key the NCP
    /// already reports is *not* re-sent, so rotated key material for
    /// an existing peer must be re-inserted explicitly (insert
    /// replaces).
    pub peer_keys: Vec<items::PeerKeyEntry>,
    /// Desired `PROP_HOST_AUTO_ACK`.
    pub auto_ack: bool,
}

/// What [`CompanionRadio::provision`] actually changed. Everything not
/// reported here already matched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProvisionReport {
    /// `PROP_HOST_KEY` differed: the NCP wiped the previous host
    /// domain and every table was provisioned from empty.
    pub host_replaced: bool,
    /// The filter table was replaced whole.
    pub filters_replaced: bool,
    /// The channel-key table was replaced whole (the NCP held an
    /// identifier we have no key for, which cannot be removed
    /// individually — the remove selector is the key itself).
    pub channels_replaced: bool,
    /// Channel keys inserted individually.
    pub channels_inserted: usize,
    /// Peer entries inserted.
    pub peers_inserted: usize,
    /// Peer entries removed.
    pub peers_removed: usize,
    /// `PROP_HOST_AUTO_ACK` was rewritten.
    pub auto_ack_changed: bool,
}

impl ProvisionReport {
    /// Whether provisioning changed anything at all (if not, an
    /// explicit `CMD_SAVE` is only needed when live state had diverged
    /// from the snapshot for other reasons).
    pub fn changed(&self) -> bool {
        *self != Self::default()
    }
}

/// A cancel-safe, frame-oriented companion transport.
#[allow(async_fn_in_trait)]
pub trait FrameLink {
    /// Send one complete companion frame.
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), CompanionRadioError>;

    /// Poll for the next complete companion frame.
    ///
    /// Implementations keep all partial state in `self`, so cancellation cannot
    /// discard a partial frame or unread bytes following a completed frame.
    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, CompanionRadioError>>;

    /// Receive the next complete companion frame.
    async fn recv_frame(&mut self) -> Result<Vec<u8>, CompanionRadioError> {
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
    /// Wrap a byte stream in companion HDLC framing.
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
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), CompanionRadioError> {
        let mut wire = vec![0u8; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut wire).expect("buffer sized with max_encoded_len");
        self.io.write_all(&wire[..len]).await?;
        self.io.flush().await?;
        Ok(())
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, CompanionRadioError>> {
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
                        return core::task::Poll::Ready(Err(CompanionRadioError::Disconnected));
                    }
                }
                core::task::Poll::Ready(Err(error)) => {
                    return core::task::Poll::Ready(Err(CompanionRadioError::Io(error)));
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
    fn validate(&self) -> Result<(), CompanionRadioError> {
        if !(1..=511).contains(&self.segment_payload) {
            return Err(CompanionRadioError::Protocol(
                "BLE segment payload must be in 1..=511",
            ));
        }
        if self.discovery_timeout.is_zero()
            || self.operation_timeout.is_zero()
            || self.pairing_timeout.is_zero()
        {
            return Err(CompanionRadioError::Protocol(
                "BLE discovery, operation, and pairing timeouts must be nonzero",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "ble-radio")]
struct BleNotificationReceiver {
    notifications: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reassembler: umsh_companion::gatt::Reassembler<{ umsh_companion::gatt::MAX_FRAME }>,
}

#[cfg(feature = "ble-radio")]
impl BleNotificationReceiver {
    fn new(notifications: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            notifications,
            reassembler: umsh_companion::gatt::Reassembler::new(),
        }
    }

    fn poll_recv_frame(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Vec<u8>, CompanionRadioError>> {
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
                    return core::task::Poll::Ready(Err(CompanionRadioError::Disconnected));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }
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
    /// Discover and attach to a Companion Link Service peripheral.
    ///
    /// `selector` matches a local-name substring or the platform peripheral ID.
    /// With no selector, discovery must yield exactly one companion radio.
    pub async fn connect(
        selector: Option<&str>,
        config: BleFrameLinkConfig,
    ) -> Result<Self, CompanionRadioError> {
        use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
        use futures_util::StreamExt;

        config.validate()?;

        let manager = btleplug::platform::Manager::new()
            .await
            .map_err(ble_error)?;
        let adapters = manager.adapters().await.map_err(ble_error)?;
        let service = uuid::Uuid::from_u128(umsh_companion::gatt::SERVICE_UUID);
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
                return Err(CompanionRadioError::Transport(
                    "no Companion Link Service peripheral found".into(),
                ));
            }
            1 => matches.pop().unwrap(),
            _ => {
                return Err(CompanionRadioError::Transport(
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

            let frame_in_uuid = uuid::Uuid::from_u128(umsh_companion::gatt::FRAME_IN_UUID);
            let frame_out_uuid = uuid::Uuid::from_u128(umsh_companion::gatt::FRAME_OUT_UUID);
            let characteristics = peripheral.characteristics();
            let frame_in = characteristics
                .iter()
                .find(|characteristic| characteristic.uuid == frame_in_uuid)
                .cloned()
                .ok_or(CompanionRadioError::Protocol("missing BLE Frame In"))?;
            let frame_out = characteristics
                .iter()
                .find(|characteristic| characteristic.uuid == frame_out_uuid)
                .cloned()
                .ok_or(CompanionRadioError::Protocol("missing BLE Frame Out"))?;

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
            Ok::<_, CompanionRadioError>((frame_in, notifications))
        }
        .await;

        let (frame_in, notifications) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                // Failed setup must not leave the single-connection NCP
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
    async fn diagnose_and_disconnect(&self, failure: String) -> CompanionRadioError {
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
        CompanionRadioError::Transport(format!(
            "{failure}; backend is_connected={connected}; disconnect cleanup={cleanup}"
        ))
    }
}

#[cfg(feature = "ble-radio")]
impl FrameLink for BleFrameLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), CompanionRadioError> {
        use btleplug::api::{Peripheral as _, WriteType};

        for segment in umsh_companion::gatt::segments(frame, self.segment_payload) {
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
    ) -> core::task::Poll<Result<Vec<u8>, CompanionRadioError>> {
        self.receiver.poll_recv_frame(cx)
    }
}

#[cfg(feature = "ble-radio")]
fn ble_error(error: btleplug::Error) -> CompanionRadioError {
    CompanionRadioError::Transport(error.to_string())
}

#[cfg(feature = "ble-radio")]
fn ble_timeout(operation: &'static str) -> CompanionRadioError {
    CompanionRadioError::Transport(format!("BLE timed out while {operation}"))
}

/// Companion radio attached over a frame link, usable as a
/// [`umsh_hal::Radio`].
pub struct CompanionRadio<L> {
    link: L,
    config: CompanionRadioConfig,
    rx_queue: VecDeque<RxPacket>,
    responses: VecDeque<Response>,
    prop_events: VecDeque<PropEvent>,
    /// Unsolicited reset notification not yet surfaced to the caller.
    seen_reset: Option<Status>,
    max_frame_size: usize,
    t_frame_ms: u32,
    ncp_version: String,
    /// Hardware reset cause retained by the NCP before our protocol reset.
    boot_status: Status,
    next_tid: u8,
    /// Optional per-frame trace sink for both directions.
    trace: Option<FrameTrace>,
}

impl<L> CompanionRadio<L>
where
    L: FrameLink,
{
    fn bare(link: L, config: CompanionRadioConfig) -> Self {
        Self {
            link,
            config,
            rx_queue: VecDeque::new(),
            responses: VecDeque::new(),
            prop_events: VecDeque::new(),
            seen_reset: None,
            max_frame_size: 0,
            t_frame_ms: 0,
            ncp_version: String::new(),
            boot_status: Status::RESET_UNKNOWN,
            next_tid: 1,
            trace: None,
        }
    }

    /// Attach to an NCP: reset it, verify the protocol version, apply
    /// the RF configuration, and enable the PHY.
    ///
    /// This is the minimal-protocol attach: `CMD_RST` discards a
    /// full-protocol NCP's session-independent state visibility (and
    /// with a saved snapshot the post-reset values come from the
    /// snapshot, not the documented defaults). A host cooperating with
    /// an autonomously operating NCP should use
    /// [`Self::attach_existing`] instead.
    pub async fn new(link: L, config: CompanionRadioConfig) -> Result<Self, CompanionRadioError> {
        let mut radio = Self::bare(link, config);
        radio.initialize().await?;
        Ok(radio)
    }

    /// Attach to an already-operating NCP without resetting or
    /// reconfiguring it.
    ///
    /// This is the full-protocol attach (spec §Attach, Detach, and
    /// Synchronization): attach implies no known state, so the host
    /// synchronizes by fetching. Only the identity handshake runs here
    /// — retained `PROP_LAST_STATUS` (the reset cause, preserved for
    /// [`Self::boot_status`] and [`Self::sync`]), the protocol version
    /// check, `PROP_NCP_VERSION`, and `PROP_PHY_MTU`. The PHY keeps
    /// whatever configuration and enable state it had; queued frames
    /// and provisioning are untouched. Follow with [`Self::sync`] and
    /// drain the queue when actually ready to process it.
    pub async fn attach_existing(
        link: L,
        config: CompanionRadioConfig,
    ) -> Result<Self, CompanionRadioError> {
        let mut radio = Self::bare(link, config);
        // Reading LAST_STATUS does not overwrite it, so sync() still
        // sees a retained reset code after this handshake.
        let boot_status = radio.get_prop(prop::LAST_STATUS).await?;
        radio.boot_status = decode_status(&boot_status);

        let version = radio.get_prop(prop::PROTOCOL_VERSION).await?;
        if version.first().copied() != Some(ids::PROTOCOL_MAJOR_VERSION) {
            return Err(CompanionRadioError::Protocol(
                "protocol major version mismatch",
            ));
        }
        let ncp_version = radio.get_prop(prop::NCP_VERSION).await?;
        radio.ncp_version = String::from_utf8_lossy(&ncp_version)
            .trim_end_matches('\0')
            .to_owned();

        let mtu = radio.get_prop(prop::PHY_MTU).await?;
        let [mtu_lo, mtu_hi, ..] = mtu[..] else {
            return Err(CompanionRadioError::Protocol("malformed PROP_PHY_MTU"));
        };
        radio.max_frame_size = usize::from(u16::from_le_bytes([mtu_lo, mtu_hi]));
        if radio.max_frame_size == 0 {
            return Err(CompanionRadioError::Protocol("NCP advertised zero MTU"));
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

    /// Install (or clear) a per-frame trace sink. Every frame sent and
    /// every frame received is reported as a one-line summary (see
    /// [`describe_frame`]), so a failure can be placed at the host API,
    /// framing, session, storage, or radio boundary.
    pub fn set_frame_trace(&mut self, trace: Option<FrameTrace>) {
        self.trace = trace;
    }

    /// Send one frame through the trace hook.
    async fn send(&mut self, frame: &[u8]) -> Result<(), CompanionRadioError> {
        if let Some(trace) = &mut self.trace {
            trace(TraceDirection::HostToNcp, &describe_frame(frame));
        }
        self.link.send_frame(frame).await
    }

    /// The NCP's firmware version string (`PROP_NCP_VERSION`).
    pub fn ncp_version(&self) -> &str {
        &self.ncp_version
    }

    /// Fetch the NCP's human-readable `PROP_DEV_NAME`.
    pub async fn device_name(&mut self) -> Result<String, CompanionRadioError> {
        let value = self.get_prop(prop::DEV_NAME).await?;
        let name = core::str::from_utf8(&value)
            .map_err(|_| CompanionRadioError::Protocol("malformed PROP_DEV_NAME"))?;
        if name.is_empty() || value.len() > 64 || value.contains(&0) {
            return Err(CompanionRadioError::Protocol("malformed PROP_DEV_NAME"));
        }
        Ok(name.to_owned())
    }

    /// Set the NCP's human-readable `PROP_DEV_NAME`.
    pub async fn set_device_name(&mut self, name: &str) -> Result<(), CompanionRadioError> {
        if name.is_empty() || name.len() > 64 || name.as_bytes().contains(&0) {
            return Err(CompanionRadioError::Protocol("invalid PROP_DEV_NAME"));
        }
        let authoritative = self.set_prop(prop::DEV_NAME, name.as_bytes()).await?;
        if authoritative != name.as_bytes() {
            return Err(CompanionRadioError::Protocol(
                "PROP_DEV_NAME response mismatch",
            ));
        }
        Ok(())
    }

    /// Reset cause reported by the NCP immediately after transport attach.
    pub fn boot_status(&self) -> Status {
        self.boot_status
    }

    async fn initialize(&mut self) -> Result<(), CompanionRadioError> {
        // The reset-status property is deliberately read before CMD_RST. The
        // protocol requires the NCP to retain its hardware boot cause for this
        // first query; CMD_RST would replace it with RESET_SOFTWARE.
        let boot_status = self.get_prop(prop::LAST_STATUS).await?;
        self.boot_status = decode_status(&boot_status);

        // Reset and wait for the reset notification. The TID is
        // ignored for CMD_RST; the notification is unsolicited.
        let mut buf = [0u8; 2];
        let len = frame::reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let deadline = Instant::now() + self.config.response_timeout;
        self.wait_reset(deadline).await?;

        // Reject NCPs speaking an incompatible protocol revision.
        let version = self.get_prop(prop::PROTOCOL_VERSION).await?;
        if version.first().copied() != Some(ids::PROTOCOL_MAJOR_VERSION) {
            return Err(CompanionRadioError::Protocol(
                "protocol major version mismatch",
            ));
        }

        let ncp_version = self.get_prop(prop::NCP_VERSION).await?;
        self.ncp_version = String::from_utf8_lossy(&ncp_version)
            .trim_end_matches('\0')
            .to_owned();

        let mtu = self.get_prop(prop::PHY_MTU).await?;
        let [mtu_lo, mtu_hi, ..] = mtu[..] else {
            return Err(CompanionRadioError::Protocol("malformed PROP_PHY_MTU"));
        };
        self.max_frame_size = usize::from(u16::from_le_bytes([mtu_lo, mtu_hi]));
        if self.max_frame_size == 0 {
            return Err(CompanionRadioError::Protocol("NCP advertised zero MTU"));
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
    pub async fn get_prop(&mut self, key: u32) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len = frame::prop_get(&mut buf, tid, key)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, key, PropResponsePolicy::Value)
            .await
    }

    /// Set a property via `CMD_PROP_SET`, returning the authoritative
    /// value echoed by the NCP.
    pub async fn set_prop(
        &mut self,
        key: u32,
        value: &[u8],
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; value.len() + 8];
        let len = frame::prop_set(&mut buf, tid, key, value)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
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
    pub async fn insert_prop_item(
        &mut self,
        key: u32,
        item: &[u8],
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; item.len() + 8];
        let len = frame::prop_insert(&mut buf, tid, key, item)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
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
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; selector.len() + 8];
        let len = frame::prop_remove(&mut buf, tid, key, selector)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_table_transaction(tid, key, ResponseKind::Removed)
            .await
    }

    /// Send a payload-less command completed by a correlated
    /// `PROP_LAST_STATUS`.
    async fn status_only_command(
        &mut self,
        encode: fn(&mut [u8], u8) -> Result<usize, frame::WriteError>,
    ) -> Result<(), CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = encode(&mut buf, tid).map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::LAST_STATUS, PropResponsePolicy::StatusOnly)
            .await
            .map(|_| ())
    }

    /// Drain the NCP's inbound queue (`CMD_QUEUE_DRAIN`).
    ///
    /// Buffered frames are delivered as ordinary `CMD_STR_RECV` and land
    /// in the receive queue for [`Radio::poll_receive`]; this future
    /// resolves on the correlated completion status.
    pub async fn queue_drain(&mut self) -> Result<(), CompanionRadioError> {
        self.queue_drain_with(|_data, _meta| {}).await
    }

    /// As [`Self::queue_drain`], invoking `on_frame` with each frame
    /// (data, trailing metadata bytes) delivered before completion —
    /// buffered and interleaved live frames alike. Frames are also
    /// queued for [`Radio::poll_receive`] as usual.
    pub async fn queue_drain_with(
        &mut self,
        mut on_frame: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = frame::queue_drain(&mut buf, tid)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;

        let deadline = Instant::now() + self.config.response_timeout;
        let mut delivered = self.rx_queue.len();
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
                        Err(CompanionRadioError::Status(status))
                    };
                }
                return Err(CompanionRadioError::Protocol("unexpected drain response"));
            }
            if let Some(status) = self.seen_reset.take() {
                return Err(CompanionRadioError::UnexpectedReset(status));
            }
            self.read_more(deadline).await?;
            while delivered < self.rx_queue.len() {
                let packet = &self.rx_queue[delivered];
                on_frame(&packet.data, &packet.raw_meta);
                delivered += 1;
            }
            // Overflow of the bounded receive queue shifts indices; the
            // callback view is best-effort in that case.
            delivered = delivered.min(self.rx_queue.len());
        }
    }

    /// Save the NCP's device and host domains to non-volatile storage
    /// (`CMD_SAVE`; requires `CAP_SAVE`).
    pub async fn save(&mut self) -> Result<(), CompanionRadioError> {
        self.status_only_command(frame::save).await
    }

    /// Erase the NCP's saved snapshot and other persisted provisioning
    /// (`CMD_CLEAR`; base protocol, BLE bonds and pairing PIN exempt).
    pub async fn clear(&mut self) -> Result<(), CompanionRadioError> {
        self.status_only_command(frame::clear).await
    }

    /// Revert the NCP to its saved snapshot (`CMD_RESTORE`; requires
    /// `CAP_SAVE`), accepting both spec-permitted completion forms.
    pub async fn restore(&mut self) -> Result<RestoreCompletion, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 4];
        let len = frame::restore(&mut buf, tid)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
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
                        Err(CompanionRadioError::Status(status))
                    };
                }
                return Err(CompanionRadioError::Protocol("unexpected restore response"));
            }
            match self.seen_reset.take() {
                Some(status) if status == Status::RESET_RESTORED => {
                    return Ok(RestoreCompletion::Reset);
                }
                Some(status) => return Err(CompanionRadioError::UnexpectedReset(status)),
                None => {}
            }
            self.read_more(deadline).await?;
        }
    }

    /// Set or clear the NCP's persisted, write-only BLE pairing PIN.
    ///
    /// This property is the protocol's sole status-only property write: the
    /// value is never echoed. `None` clears the configured passkey.
    pub async fn set_ble_pairing_pin(
        &mut self,
        pin: Option<u32>,
    ) -> Result<(), CompanionRadioError> {
        if pin.is_some_and(|pin| pin > 999_999) {
            return Err(CompanionRadioError::Protocol(
                "BLE pairing PIN out of range",
            ));
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
        .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        self.finish_prop_transaction(tid, prop::BLE_PAIRING_PIN, PropResponsePolicy::StatusOnly)
            .await
            .map(|_| ())
    }

    /// Fetch and decode `PROP_CAPS`.
    pub async fn capabilities(&mut self) -> Result<Vec<u32>, CompanionRadioError> {
        let raw = self.get_prop(prop::CAPS).await?;
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let (value, used) = pui::decode(&raw[offset..])
                .map_err(|_| CompanionRadioError::Protocol("malformed PROP_CAPS"))?;
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
    ) -> Result<NcpSync, CompanionRadioError> {
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
                Err(_) => return Err(CompanionRadioError::Protocol("malformed PROP_HOST_KEY")),
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
                .map_err(|_| CompanionRadioError::Protocol("malformed PROP_PHY_FREQ"))?,
        );
        let device_name = self.device_name().await?;
        let saved = match has(cap::SAVE) {
            true => Some(self.get_prop(prop::SAVED).await? == [1]),
            false => None,
        };
        let (queue_count, queue_dropped) = if has(cap::HOST_RX_QUEUE) {
            let count = self.get_prop(prop::HOST_RX_QUEUE_COUNT).await?;
            let dropped = self.get_prop(prop::HOST_RX_QUEUE_DROPPED).await?;
            (
                Some(u16::from_le_bytes(count.as_slice().try_into().map_err(
                    |_| CompanionRadioError::Protocol("malformed PROP_HOST_RX_QUEUE_COUNT"),
                )?)),
                Some(u32::from_le_bytes(dropped.as_slice().try_into().map_err(
                    |_| CompanionRadioError::Protocol("malformed PROP_HOST_RX_QUEUE_DROPPED"),
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
                Err(_) => return Err(CompanionRadioError::Protocol("malformed PROP_DEV_KEY")),
            }
        } else {
            None
        };

        Ok(NcpSync {
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

    /// Establish `desired` as the NCP's host domain, reconciling
    /// against the digest forms so secrets the NCP already holds are
    /// never re-sent. A `host_key` differing from the configured one
    /// replaces the whole host domain first (spec §Host Replacement).
    ///
    /// Each individual write is transactional on the NCP (spec
    /// §Mutation Atomicity). Changes are live only: follow with
    /// [`Self::save`] to persist the provisioned state for autonomous
    /// operation.
    pub async fn provision(
        &mut self,
        desired: &HostProvisioning,
    ) -> Result<ProvisionReport, CompanionRadioError> {
        let mut report = ProvisionReport::default();
        let current_key = self.get_prop(prop::HOST_KEY).await?;
        if current_key.as_slice() != desired.host_key.as_slice() {
            self.set_prop(prop::HOST_KEY, &desired.host_key).await?;
            report.host_replaced = true;
        }

        // Filters: item and digest forms are identical, so replace the
        // whole table (atomically, no secrets involved) when the sets
        // differ.
        let current_filters = if report.host_replaced {
            Vec::new()
        } else {
            decode_filter_table(&self.get_prop(prop::HOST_RX_FILTERS).await?)?
        };
        if !same_set(&current_filters, &desired.filters) {
            let mut table = Vec::new();
            for filter in &desired.filters {
                let mut item = [0u8; items::Filter::MAX_WIRE_LEN];
                let item_len = filter
                    .encode(&mut item)
                    .map_err(|_| CompanionRadioError::Protocol("filter encode"))?;
                let mut prefixed = [0u8; items::Filter::MAX_WIRE_LEN + 2];
                let prefixed_len = items::encode_prefixed_item(&item[..item_len], &mut prefixed)
                    .map_err(|_| CompanionRadioError::Protocol("filter encode"))?;
                table.extend_from_slice(&prefixed[..prefixed_len]);
            }
            self.set_prop(prop::HOST_RX_FILTERS, &table).await?;
            report.filters_replaced = true;
        }

        // Channel keys are compared through their derived identifiers.
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
            // The NCP holds a channel we have no key for; its remove
            // selector is the key itself, so the only way to shed it
            // is an atomic whole-table replacement.
            let table: Vec<u8> = desired.channel_keys.concat();
            self.set_prop(prop::HOST_CHANNEL_KEYS, &table).await?;
            report.channels_replaced = true;
        } else {
            for (key, id) in desired.channel_keys.iter().zip(&desired_ids) {
                if !current_ids.contains(id) {
                    self.insert_prop_item(prop::HOST_CHANNEL_KEYS, key).await?;
                    report.channels_inserted += 1;
                }
            }
        }

        // Peers reconcile by public-key membership; the pairwise key
        // material of peers the NCP already reports never crosses the
        // link again.
        let current_peers = if report.host_replaced {
            Vec::new()
        } else {
            decode_fixed_list::<{ items::PUBLIC_KEY_LEN }>(
                &self.get_prop(prop::HOST_PEER_KEYS).await?,
                "malformed PROP_HOST_PEER_KEYS digest",
            )?
        };
        for entry in &desired.peer_keys {
            if !current_peers.contains(&entry.public_key) {
                let mut item = [0u8; items::PeerKeyEntry::WIRE_LEN];
                entry
                    .encode(&mut item)
                    .map_err(|_| CompanionRadioError::Protocol("peer entry encode"))?;
                self.insert_prop_item(prop::HOST_PEER_KEYS, &item).await?;
                report.peers_inserted += 1;
            }
        }
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

        // Delegation policy last, once the keys it depends on exist.
        let current_auto_ack = if report.host_replaced {
            false
        } else {
            self.get_prop(prop::HOST_AUTO_ACK).await? == [1]
        };
        if current_auto_ack != desired.auto_ack {
            self.set_prop(prop::HOST_AUTO_ACK, &[desired.auto_ack as u8])
                .await?;
            report.auto_ack_changed = true;
        }
        Ok(report)
    }

    /// The NCP's device identity public key, generating one on-device
    /// if none is configured (`CAP_DEV_IDENTITY`; generation requires
    /// the transport's provisioning-security binding).
    ///
    /// On-device generation is the spec-recommended form: the private
    /// key never exists anywhere but the radio, and only the resulting
    /// public key crosses the link.
    pub async fn ensure_device_identity(&mut self) -> Result<[u8; 32], CompanionRadioError> {
        let current = self.get_prop(prop::DEV_KEY).await?;
        if let Ok(key) = <[u8; 32]>::try_from(current.as_slice()) {
            return Ok(key);
        }
        if !current.is_empty() {
            return Err(CompanionRadioError::Protocol("malformed PROP_DEV_KEY"));
        }
        // An empty PROP_DEV_PRIVATE_KEY write commands generation;
        // success is announced as PROP_IS for PROP_DEV_KEY carrying
        // the new public key.
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len = frame::prop_set(&mut buf, tid, prop::DEV_PRIVATE_KEY, &[])
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send(&buf[..len]).await?;
        let value = self
            .finish_prop_transaction(tid, prop::DEV_KEY, PropResponsePolicy::Value)
            .await?;
        <[u8; 32]>::try_from(value.as_slice())
            .map_err(|_| CompanionRadioError::Protocol("malformed PROP_DEV_KEY"))
    }

    async fn finish_prop_transaction(
        &mut self,
        tid: u8,
        key: u32,
        policy: PropResponsePolicy,
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let deadline = Instant::now() + self.config.response_timeout;
        let response = self.wait_response(tid, deadline).await?;
        if response.kind != ResponseKind::Is {
            return Err(CompanionRadioError::Protocol(
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
                    Err(CompanionRadioError::Status(status))
                }
            }
            (PropResponsePolicy::Value, prop::LAST_STATUS) => {
                let status = decode_status(&response.value);
                if status == Status::OK {
                    Err(CompanionRadioError::Protocol(
                        "unexpected status-only property response",
                    ))
                } else {
                    Err(CompanionRadioError::Status(status))
                }
            }
            _ => Err(CompanionRadioError::Protocol(
                "response for unexpected property",
            )),
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
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let deadline = Instant::now() + self.config.response_timeout;
        let response = self.wait_response(tid, deadline).await?;
        match (response.kind, response.key) {
            (kind, response_key) if kind == expected && response_key == key => Ok(response.value),
            (ResponseKind::Is, prop::LAST_STATUS) => {
                let status = decode_status(&response.value);
                if status == Status::OK {
                    Err(CompanionRadioError::Protocol(
                        "status-only success for a table mutation",
                    ))
                } else {
                    Err(CompanionRadioError::Status(status))
                }
            }
            _ => Err(CompanionRadioError::Protocol(
                "response for unexpected property",
            )),
        }
    }

    fn alloc_tid(&mut self) -> u8 {
        let tid = self.next_tid;
        self.next_tid = if tid >= frame::TID_MAX { 1 } else { tid + 1 };
        tid
    }

    /// Sort a complete companion frame into the receive queue, response queue,
    /// or the
    /// reset flag. Malformed frames are dropped.
    fn ingest_frame(&mut self, frame_bytes: &[u8]) {
        if let Some(trace) = &mut self.trace {
            trace(TraceDirection::NcpToHost, &describe_frame(frame_bytes));
        }
        let Ok(frame) = Frame::parse(frame_bytes) else {
            return;
        };
        match frame.command() {
            Some(Cmd::StrRecv) => {
                let Ok(payload) = StreamPayload::parse(frame.payload) else {
                    return;
                };
                if payload.stream != stream::PHY_RAW {
                    return;
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
            }
            Some(Cmd::PropIs) => self.ingest_prop_notification(ResponseKind::Is, &frame),
            Some(Cmd::PropInserted) => {
                self.ingest_prop_notification(ResponseKind::Inserted, &frame)
            }
            Some(Cmd::PropRemoved) => self.ingest_prop_notification(ResponseKind::Removed, &frame),
            _ => {}
        }
    }

    fn ingest_prop_notification(&mut self, kind: ResponseKind, frame: &Frame<'_>) {
        let Ok(payload) = PropPayload::parse(frame.payload) else {
            return;
        };
        let tid = frame.header.tid();
        if tid != TID_UNSOLICITED {
            if self.responses.len() >= RESPONSE_QUEUE_DEPTH {
                self.responses.pop_front();
            }
            self.responses.push_back(Response {
                tid,
                kind,
                key: payload.key,
                value: payload.value.to_vec(),
            });
            return;
        }
        // Unsolicited `PROP_LAST_STATUS` is a reset notice or an
        // operation status, not a property update to retain.
        if kind == ResponseKind::Is && payload.key == prop::LAST_STATUS {
            let status = decode_status(payload.value);
            if status.is_reset() {
                self.seen_reset = Some(status);
            }
            return;
        }
        let event = match kind {
            ResponseKind::Is => PropEvent::Is {
                key: payload.key,
                value: payload.value.to_vec(),
            },
            ResponseKind::Inserted => PropEvent::Inserted {
                key: payload.key,
                digest: payload.value.to_vec(),
            },
            ResponseKind::Removed => PropEvent::Removed {
                key: payload.key,
                digest: payload.value.to_vec(),
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
    async fn wait_response(
        &mut self,
        tid: u8,
        deadline: Instant,
    ) -> Result<Response, CompanionRadioError> {
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
                return Err(CompanionRadioError::UnexpectedReset(status));
            }
            self.read_more(deadline).await?;
        }
    }

    /// Read until the NCP announces a reset via `PROP_LAST_STATUS`.
    async fn wait_reset(&mut self, deadline: Instant) -> Result<Status, CompanionRadioError> {
        loop {
            if let Some(status) = self.seen_reset.take() {
                return Ok(status);
            }
            // Accept a reset notice even if the NCP attached a TID.
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

    async fn read_more(&mut self, deadline: Instant) -> Result<(), CompanionRadioError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(CompanionRadioError::Timeout);
        }
        let frame = match tokio::time::timeout(deadline - now, self.link.recv_frame()).await {
            Err(_elapsed) => return Err(CompanionRadioError::Timeout),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(frame)) => frame,
        };
        self.ingest_frame(&frame);
        Ok(())
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
}

#[cfg(feature = "serial-radio")]
impl CompanionRadio<SerialFrameLink<tokio_serial::SerialStream>> {
    /// Attach to an NCP on a serial port.
    pub async fn open_serial(
        path: impl AsRef<str>,
        baud_rate: u32,
        config: CompanionRadioConfig,
    ) -> Result<Self, CompanionRadioError> {
        use tokio_serial::SerialPortBuilderExt;

        let stream = tokio_serial::new(path.as_ref(), baud_rate)
            .open_native_async()
            .map_err(|error| CompanionRadioError::Io(error.into()))?;
        Self::new(SerialFrameLink::new(stream), config).await
    }
}

#[cfg(feature = "ble-radio")]
impl CompanionRadio<BleFrameLink> {
    /// Discover, connect, attach, and initialize a BLE companion radio.
    pub async fn open_ble(
        selector: Option<&str>,
        config: CompanionRadioConfig,
    ) -> Result<Self, CompanionRadioError> {
        Self::open_ble_with_link_config(selector, config, BleFrameLinkConfig::default()).await
    }

    /// As [`Self::open_ble`], with an explicit GATT link configuration.
    pub async fn open_ble_with_link_config(
        selector: Option<&str>,
        config: CompanionRadioConfig,
        link_config: BleFrameLinkConfig,
    ) -> Result<Self, CompanionRadioError> {
        let link = BleFrameLink::connect(selector, link_config).await?;
        Self::new(link, config).await
    }
}

impl<L> Radio for CompanionRadio<L>
where
    L: FrameLink,
{
    type Error = CompanionRadioError;

    /// Transmit one frame and await the NCP's confirmation.
    ///
    /// A confirmed transmit blocks the caller for up to
    /// `response_timeout + 2 × t_frame_ms` while the frame goes out on air. This
    /// is inherent to the half-duplex [`Radio::transmit`] contract and a real
    /// radio behaves the same way. Frames the NCP receives during this window
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
            return Err(TxError::Io(CompanionRadioError::FrameTooLarge(data.len())));
        }

        // The NCP performs CCA itself; the CAD policy becomes a host-side
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

        loop {
            let tid = self.alloc_tid();
            let mut frame_buf = vec![0u8; data.len() + 16];
            let frame_len = frame::str_send(
                &mut frame_buf,
                tid,
                stream::PHY_RAW,
                data,
                &meta_buf[..meta_len],
            )
            .map_err(|_| TxError::Io(CompanionRadioError::Protocol("frame encode")))?;
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
                return Err(TxError::Io(CompanionRadioError::Protocol(
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
                status => return Err(TxError::Io(CompanionRadioError::Status(status))),
            }
        }
    }

    fn poll_receive(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        loop {
            if let Some(status) = self.seen_reset.take() {
                return core::task::Poll::Ready(Err(CompanionRadioError::UnexpectedReset(status)));
            }
            if let Some(info) = self.pop_rx(buf) {
                return core::task::Poll::Ready(Ok(info));
            }

            match self.link.poll_recv_frame(cx) {
                core::task::Poll::Ready(Ok(frame)) => self.ingest_frame(&frame),
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
fn decode_filter_table(value: &[u8]) -> Result<Vec<items::Filter>, CompanionRadioError> {
    let mut filters = Vec::new();
    for item in items::prefixed_items(value) {
        let item =
            item.map_err(|_| CompanionRadioError::Protocol("malformed PROP_HOST_RX_FILTERS"))?;
        filters.push(
            items::Filter::decode(item)
                .map_err(|_| CompanionRadioError::Protocol("malformed PROP_HOST_RX_FILTERS"))?,
        );
    }
    Ok(filters)
}

/// Decode a digest table of fixed-size items.
fn decode_fixed_list<const N: usize>(
    value: &[u8],
    what: &'static str,
) -> Result<Vec<[u8; N]>, CompanionRadioError> {
    items::fixed_items::<N>(value)
        .map(|iterator| iterator.copied().collect())
        .map_err(|_| CompanionRadioError::Protocol(what))
}

/// Order-insensitive equality of two item sets (both are sets on the
/// wire; tables are small).
fn same_set<T: PartialEq>(left: &[T], right: &[T]) -> bool {
    left.len() == right.len() && left.iter().all(|item| right.contains(item))
}

/// The spec mnemonic for a property identifier this module knows.
fn prop_name(key: u32) -> Option<&'static str> {
    Some(match key {
        prop::LAST_STATUS => "PROP_LAST_STATUS",
        prop::PROTOCOL_VERSION => "PROP_PROTOCOL_VERSION",
        prop::NCP_VERSION => "PROP_NCP_VERSION",
        prop::INTERFACE_TYPE => "PROP_INTERFACE_TYPE",
        prop::CAPS => "PROP_CAPS",
        prop::PHY_ENABLED => "PROP_PHY_ENABLED",
        prop::PHY_FREQ => "PROP_PHY_FREQ",
        prop::PHY_TX_POWER => "PROP_PHY_TX_POWER",
        prop::PHY_RSSI => "PROP_PHY_RSSI",
        prop::PHY_LORA_BW => "PROP_PHY_LORA_BW",
        prop::PHY_LORA_SF => "PROP_PHY_LORA_SF",
        prop::PHY_LORA_CR => "PROP_PHY_LORA_CR",
        prop::PHY_MTU => "PROP_PHY_MTU",
        prop::PHY_LORA_SW => "PROP_PHY_LORA_SW",
        prop::MAC_PROMISCUOUS => "PROP_MAC_PROMISCUOUS",
        prop::SAVED => "PROP_SAVED",
        prop::DEV_KEY => "PROP_DEV_KEY",
        prop::DEV_PRIVATE_KEY => "PROP_DEV_PRIVATE_KEY",
        prop::DEV_CHANNEL_KEYS => "PROP_DEV_CHANNEL_KEYS",
        prop::DEV_PEERS => "PROP_DEV_PEERS",
        prop::DEV_NAME => "PROP_DEV_NAME",
        prop::HOST_KEY => "PROP_HOST_KEY",
        prop::HOST_CHANNEL_KEYS => "PROP_HOST_CHANNEL_KEYS",
        prop::HOST_PEER_KEYS => "PROP_HOST_PEER_KEYS",
        prop::HOST_RX_FILTERS => "PROP_HOST_RX_FILTERS",
        prop::HOST_AUTO_ACK => "PROP_HOST_AUTO_ACK",
        prop::HOST_RX_QUEUE_COUNT => "PROP_HOST_RX_QUEUE_COUNT",
        prop::HOST_RX_QUEUE_CAPACITY => "PROP_HOST_RX_QUEUE_CAPACITY",
        prop::HOST_RX_QUEUE_DROPPED => "PROP_HOST_RX_QUEUE_DROPPED",
        prop::PHY_DUTY_NOW => "PROP_PHY_DUTY_NOW",
        prop::PHY_DUTY_LIMIT => "PROP_PHY_DUTY_LIMIT",
        prop::BLE_PAIRING_PIN => "PROP_BLE_PAIRING_PIN",
        _ => return None,
    })
}

/// Render one companion frame as a one-line human-readable summary:
/// command, TID, property mnemonic, and the decoded status where the
/// payload is a `PROP_LAST_STATUS` value. Values are summarized by
/// length — never dumped — so traces cannot leak key material.
pub fn describe_frame(bytes: &[u8]) -> String {
    let Ok(frame) = Frame::parse(bytes) else {
        return format!("malformed frame ({} bytes)", bytes.len());
    };
    let tid = frame.header.tid();
    let Some(command) = frame.command() else {
        return format!("unknown command tid={tid} ({} bytes)", bytes.len());
    };
    match command {
        Cmd::Nop
        | Cmd::Reset
        | Cmd::QueueDrain
        | Cmd::Save
        | Cmd::Clear
        | Cmd::Restore => format!("{command:?} tid={tid}"),
        Cmd::PropGet
        | Cmd::PropSet
        | Cmd::PropIs
        | Cmd::PropInsert
        | Cmd::PropRemove
        | Cmd::PropInserted
        | Cmd::PropRemoved => {
            let Ok(payload) = PropPayload::parse(frame.payload) else {
                return format!("{command:?} tid={tid} (malformed payload)");
            };
            let key = prop_name(payload.key)
                .map_or_else(|| format!("prop {}", payload.key), str::to_owned);
            if payload.key == prop::LAST_STATUS && command == Cmd::PropIs {
                format!(
                    "{command:?} tid={tid} {key} = {:?}",
                    decode_status(payload.value)
                )
            } else {
                format!(
                    "{command:?} tid={tid} {key} ({} value bytes)",
                    payload.value.len()
                )
            }
        }
        Cmd::StrSend | Cmd::StrRecv => match StreamPayload::parse(frame.payload) {
            Ok(payload) => format!(
                "{command:?} tid={tid} stream={} ({} data bytes, {} meta bytes)",
                payload.stream,
                payload.data.len(),
                payload.metadata.len()
            ),
            Err(_) => format!("{command:?} tid={tid} (malformed payload)"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use umsh_companion::meta::{BufferedRxMeta, RX_FLAG_BUFFERED};

    /// Payload that makes the fake NCP report a CCA failure.
    const CCA_FAIL: &[u8] = b"cca-fail";
    /// Payload that makes the fake NCP report success and then
    /// announce a spurious watchdog reset.
    const RESET_AFTER: &[u8] = b"reset-after";
    /// Property that switches the fake NCP's `CMD_RESTORE` completion
    /// to the reset form.
    const RESTORE_RESET_FORM_KEY: u32 = 59_999;

    /// Minimal in-process NCP: answers the initialization handshake,
    /// stores property sets and multi-value tables, and echoes
    /// transmitted frames back as received frames.
    async fn fake_ncp(mut io: DuplexStream) {
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
                            prop::NCP_VERSION => b"fake-ncp/0.1\0".to_vec(),
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
                        let existing = table
                            .iter_mut()
                            .find(|item| item[..digest_len.min(item.len())] == stored[..digest_len]);
                        let len = match existing {
                            Some(_) if !replaces => {
                                frame::last_status(&mut buf, tid, Status::ALREADY).unwrap()
                            }
                            Some(existing) => {
                                *existing = stored.clone();
                                frame::prop_inserted(&mut buf, tid, payload.key, &stored[..digest_len])
                                    .unwrap()
                            }
                            None => {
                                table.push(stored.clone());
                                frame::prop_inserted(&mut buf, tid, payload.key, &stored[..digest_len])
                                    .unwrap()
                            }
                        };
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropRemove => {
                        let payload = PropPayload::parse(frame.payload).unwrap();
                        let table = tables.entry(payload.key).or_default();
                        let position = table
                            .iter()
                            .position(|item| item[..payload.value.len().min(item.len())] == *payload.value);
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
                    Cmd::Save | Cmd::Clear => {
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::Restore => {
                        if props.get(&RESTORE_RESET_FORM_KEY).is_some_and(|value| value == &[1]) {
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
                        panic!("host sent an NCP-only command")
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

    fn test_config() -> CompanionRadioConfig {
        let mut config = CompanionRadioConfig::new(906_875, 250_000, 11, 5);
        config.tx_power_dbm = 10;
        config.response_timeout = Duration::from_millis(500);
        config
    }

    async fn attached_radio() -> CompanionRadio<SerialFrameLink<DuplexStream>> {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_ncp(server));
        CompanionRadio::new(SerialFrameLink::new(client), test_config())
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
        assert!(matches!(
            config.validate(),
            Err(CompanionRadioError::Protocol(_))
        ));
        config.segment_payload = 512;
        assert!(matches!(
            config.validate(),
            Err(CompanionRadioError::Protocol(_))
        ));
        config.segment_payload = 19;
        config.operation_timeout = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(CompanionRadioError::Protocol(_))
        ));
        config.operation_timeout = Duration::from_secs(1);
        config.pairing_timeout = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(CompanionRadioError::Protocol(_))
        ));
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
        for segment in umsh_companion::gatt::segments(frame, 7) {
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
        assert!(matches!(result, Err(CompanionRadioError::Disconnected)));
    }

    #[tokio::test]
    async fn initialization_handshake() {
        let radio = attached_radio().await;
        assert_eq!(radio.max_frame_size(), 255);
        assert_eq!(radio.ncp_version(), "fake-ncp/0.1");
        assert_eq!(radio.boot_status(), Status::RESET_POWER_ON);
        assert!(radio.t_frame_ms() > 0);
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
        assert!(matches!(error, CompanionRadioError::Protocol(_)));
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
            Err(TxError::Io(CompanionRadioError::FrameTooLarge(_)))
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
            Err(CompanionRadioError::UnexpectedReset(status))
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
        assert!(
            matches!(error, CompanionRadioError::Status(status) if status == Status::ITEM_NOT_FOUND)
        );
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
        assert!(matches!(error, CompanionRadioError::Status(status) if status == Status::ALREADY));
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
        assert!(drained.iter().all(|(_, meta)| meta.flags & RX_FLAG_BUFFERED != 0));
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
        let len =
            frame::prop_inserted(&mut buf, TID_UNSOLICITED, prop::HOST_RX_FILTERS, &[2, 0])
                .unwrap();
        radio.ingest_frame(&buf[..len]);
        let len =
            frame::prop_removed(&mut buf, TID_UNSOLICITED, prop::HOST_CHANNEL_KEYS, &[0x12, 0x34])
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
