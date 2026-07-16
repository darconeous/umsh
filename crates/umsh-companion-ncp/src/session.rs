//! The NCP protocol session state machine.

use umsh_companion::Status;
use umsh_companion::airtime::lora_airtime_ms;
use umsh_companion::frame::{self, Cmd, Frame, PropPayload, StreamPayload, TID_UNSOLICITED};
use umsh_companion::ids::{self, cap, prop, stream};
use umsh_companion::items::{self, Filter, ItemError};
use umsh_companion::meta::{self, BufferedRxMeta, RX_FLAG_ACKED, RX_FLAG_BUFFERED, RxMeta, TxMeta};
use umsh_companion::pui;
use umsh_core::{ChannelKey, PacketHeader};
use umsh_crypto::{AesProvider, CryptoEngine, Sha256Provider};

use crate::duty::DutyTracker;

/// Largest radio payload the session can carry (SX126x-class limit).
pub const MAX_MTU: usize = 255;

/// Maximum UTF-8 byte length of `PROP_DEV_NAME`.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// Room for a `CMD_STR_RECV` frame around a full-MTU payload.
const SCRATCH: usize = MAX_MTU + 24;

/// Largest encoded property value the session produces (bounded by
/// `PROP_HOST_PEER_KEYS`' digest form: one public key per entry).
const PROP_BUF: usize = MAX_PEER_KEYS * items::PUBLIC_KEY_LEN + 16;

/// LoRa bandwidths accepted for `PROP_PHY_LORA_BW`, in Hz.
const SUPPORTED_BW_HZ: [u32; 10] = [
    7_810, 10_420, 15_630, 20_830, 31_250, 41_670, 62_500, 125_000, 250_000, 500_000,
];

/// Radio configuration owned by the session and pushed to the radio
/// via [`Effect::ApplyRadio`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioSettings {
    pub enabled: bool,
    pub freq_khz: u32,
    pub bw_hz: u32,
    pub sf: u8,
    pub cr_denom: u8,
    pub tx_power_dbm: i8,
}

/// Transmit power selection for one pending transmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPower {
    /// Use the configured `PROP_PHY_TX_POWER`.
    Default,
    /// Transmit at the radio's maximum power.
    Max,
    /// Explicit per-frame override in dBm.
    Dbm(i8),
}

/// Fixed properties of the device this session runs on.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    /// `PROP_NCP_VERSION` string (without NUL terminator).
    pub ncp_version: &'static str,
    /// Factory/post-reset value of `PROP_DEV_NAME`.
    pub default_device_name: &'static str,
    /// `PROP_PHY_MTU`; must not exceed [`MAX_MTU`].
    pub mtu: u16,
    /// The only sync word this firmware can use; `PROP_PHY_LORA_SW`
    /// sets must match it (v0 limitation).
    pub sync_word: u16,
    /// Lowest transmit power the radio supports, in dBm.
    pub min_tx_power_dbm: i8,
    /// Highest transmit power the radio supports, in dBm.
    pub max_tx_power_dbm: i8,
    /// Tunable frequency range in kHz, inclusive.
    pub freq_khz_min: u32,
    pub freq_khz_max: u32,
    /// Post-reset radio settings. `enabled` is forced off on reset per
    /// the spec regardless of what this carries.
    pub defaults: RadioSettings,
    /// Post-reset `PROP_PHY_DUTY_LIMIT`.
    pub default_duty_limit: u16,
}

/// A radio side effect for the caller to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The radio configuration changed; (re)apply it.
    ApplyRadio(RadioSettings),
    /// Begin transmitting [`Session::tx_data`] at
    /// [`Session::tx_power`]; report completion with
    /// [`Session::on_tx_result`].
    StartTransmit,
    /// Sample the current instantaneous RSSI from the radio and feed the
    /// result back with [`Session::respond_rssi`], quoting this `tid`. Emitted
    /// for a `PROP_PHY_RSSI` get while the PHY is enabled, because the session
    /// itself has no live view of the radio.
    SampleRssi { tid: u8 },
    /// Apply and persist a new BLE pairing PIN, then complete the deferred
    /// property transaction with [`Session::respond_pin_set`].
    SetPairingPin { tid: u8, pin: Option<u32> },
    /// The live human-readable device name changed. Transports that expose a
    /// name should refresh it without disrupting the active session.
    DeviceNameChanged,
    /// A `PROP_HOST_KEY` write is replacing the host identity. Durably
    /// wipe any saved host-domain state (spec §Host Replacement), then
    /// complete the deferred transaction with
    /// [`Session::respond_host_wipe`]. Until `CAP_SAVE` exists nothing
    /// is persisted and the wipe trivially succeeds; the live host
    /// domain is replaced only on `Ok`.
    WipeHostDomain { tid: u8 },
    /// A `CMD_QUEUE_DRAIN` accepted a non-empty queue. Repeatedly call
    /// [`Session::drain_step`] until it returns `false`, flushing the
    /// emitted frame to the transport between calls (each step emits at
    /// most one frame, so a bounded emitter never overflows and the
    /// transport can apply backpressure).
    DrainQueue,
}

struct PendingTx {
    tid: u8,
    airtime_ms: u32,
    power: TxPower,
}

/// Outcome of dispatching a property key for encoding.
enum PropValue {
    Encoded(usize),
    Unimplemented,
    Unknown,
}

/// State belonging to the companion radio itself, independent of which
/// host is attached (spec §State Classes, device domain). Survives
/// attach and host replacement; `CMD_RST` restores its post-reset
/// values.
struct DeviceDomain {
    settings: RadioSettings,
    duty_limit: u16,
    duty: DutyTracker,
    name: [u8; MAX_DEVICE_NAME_LEN],
    name_len: usize,
}

impl DeviceDomain {
    fn post_reset(config: &SessionConfig) -> Self {
        let mut settings = config.defaults;
        settings.enabled = false;
        let mut name = [0; MAX_DEVICE_NAME_LEN];
        let name_len = config.default_device_name.len();
        name[..name_len].copy_from_slice(config.default_device_name.as_bytes());
        Self {
            settings,
            duty_limit: config.default_duty_limit,
            duty: DutyTracker::new(),
            name,
            name_len,
        }
    }
}

/// Maximum number of explicit `PROP_HOST_RX_FILTERS` entries.
pub const MAX_RX_FILTERS: usize = 16;

/// The explicit receive filter table: an unordered set with fixed
/// capacity. Whole-table replacement builds a candidate table first so
/// a failed set never leaves a partial mixture (spec §Mutation
/// Atomicity).
#[derive(Clone, Copy)]
struct FilterTable {
    entries: [Filter; MAX_RX_FILTERS],
    len: usize,
}

impl Default for FilterTable {
    fn default() -> Self {
        Self {
            entries: [Filter::PktType(0); MAX_RX_FILTERS],
            len: 0,
        }
    }
}

impl FilterTable {
    fn iter(&self) -> impl Iterator<Item = &Filter> {
        self.entries[..self.len].iter()
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add a filter; duplicates fail with `STATUS_ALREADY`, a full
    /// table with `STATUS_NOMEM`.
    fn insert(&mut self, filter: Filter) -> Result<(), Status> {
        if self.iter().any(|existing| *existing == filter) {
            return Err(Status::ALREADY);
        }
        if self.len == MAX_RX_FILTERS {
            return Err(Status::NOMEM);
        }
        self.entries[self.len] = filter;
        self.len += 1;
        Ok(())
    }

    /// Remove the filter matching `filter` (the selector is the full
    /// item); a missing item fails with `STATUS_ITEM_NOT_FOUND`.
    fn remove(&mut self, filter: Filter) -> Result<(), Status> {
        let Some(index) = self.iter().position(|existing| *existing == filter) else {
            return Err(Status::ITEM_NOT_FOUND);
        };
        self.len -= 1;
        self.entries[index] = self.entries[self.len];
        Ok(())
    }

    /// Parse a whole-table `CMD_PROP_SET` value (PUI-length-prefixed
    /// filter entries) into a complete replacement table, validating
    /// everything before the caller commits it. Duplicate items in the
    /// value collapse, matching the property's set semantics.
    fn parse_table(value: &[u8]) -> Result<Self, Status> {
        let mut table = Self::default();
        for item in items::prefixed_items(value) {
            let filter = decode_filter(item.map_err(table_error)?)?;
            match table.insert(filter) {
                Ok(()) | Err(Status::ALREADY) => {}
                Err(status) => return Err(status),
            }
        }
        Ok(table)
    }
}

/// Decode and validate one filter item. Unrecognized types, mismatched
/// value lengths, and out-of-range packet types are invalid arguments
/// per the `PROP_HOST_RX_FILTERS` spec.
fn decode_filter(item: &[u8]) -> Result<Filter, Status> {
    let filter = Filter::decode(item).map_err(|_| Status::INVALID_ARGUMENT)?;
    if matches!(filter, Filter::PktType(pkt_type) if pkt_type > 7) {
        return Err(Status::INVALID_ARGUMENT);
    }
    Ok(filter)
}

/// Map a table-structure decoding failure (bad or truncated item
/// length prefix) to a status. Entry-level problems are invalid
/// arguments; a value that cannot be split into items at all is
/// malformed.
fn table_error(error: ItemError) -> Status {
    match error {
        ItemError::BadPrefix | ItemError::Truncated => Status::PARSE_ERROR,
        _ => Status::INVALID_ARGUMENT,
    }
}

/// `PROP_HOST_RX_QUEUE_CAPACITY`: the fixed size of the inbound queue.
pub const RX_QUEUE_CAPACITY: usize = 16;

/// One inbound-queue entry: the frame, its receive metadata, the time
/// of reception, and whether the NCP acknowledged it on the host's
/// behalf (always false until `CAP_HOST_AUTO_ACK`).
#[derive(Clone, Copy)]
struct QueueEntry {
    data: [u8; MAX_MTU],
    len: u16,
    rssi_dbm: i16,
    snr_cb: i16,
    lqi: Option<core::num::NonZeroU8>,
    rx_time_ms: u64,
    acked: bool,
}

impl QueueEntry {
    const EMPTY: Self = Self {
        data: [0; MAX_MTU],
        len: 0,
        rssi_dbm: 0,
        snr_cb: 0,
        lqi: None,
        rx_time_ms: 0,
        acked: false,
    };

    fn frame(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

/// The circular FIFO inbound queue (spec §Inbound Queueing). When full,
/// accepting a new frame evicts the oldest entry and counts it in
/// `PROP_HOST_RX_QUEUE_DROPPED`, so the queue always holds the most
/// recent accepted traffic.
struct RxQueue {
    entries: [QueueEntry; RX_QUEUE_CAPACITY],
    /// Index of the oldest entry.
    head: usize,
    len: usize,
    dropped: u32,
}

impl Default for RxQueue {
    fn default() -> Self {
        Self {
            entries: [QueueEntry::EMPTY; RX_QUEUE_CAPACITY],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }
}

impl RxQueue {
    /// Reset to empty without constructing a fresh entry array (the
    /// array is several KB; hosts of this crate include embedded
    /// stacks).
    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.dropped = 0;
    }

    fn push(
        &mut self,
        data: &[u8],
        rssi_dbm: i16,
        snr_cb: i16,
        lqi: Option<core::num::NonZeroU8>,
        rx_time_ms: u64,
    ) {
        debug_assert!(data.len() <= MAX_MTU);
        if self.len == RX_QUEUE_CAPACITY {
            self.head = (self.head + 1) % RX_QUEUE_CAPACITY;
            self.len -= 1;
            self.dropped = self.dropped.wrapping_add(1);
        }
        let slot = (self.head + self.len) % RX_QUEUE_CAPACITY;
        let entry = &mut self.entries[slot];
        entry.data[..data.len()].copy_from_slice(data);
        entry.len = data.len() as u16;
        entry.rssi_dbm = rssi_dbm;
        entry.snr_cb = snr_cb;
        entry.lqi = lqi;
        entry.rx_time_ms = rx_time_ms;
        entry.acked = false;
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<QueueEntry> {
        if self.len == 0 {
            return None;
        }
        let entry = self.entries[self.head];
        self.head = (self.head + 1) % RX_QUEUE_CAPACITY;
        self.len -= 1;
        Some(entry)
    }
}

/// Maximum number of `PROP_HOST_CHANNEL_KEYS` entries.
pub const MAX_CHANNEL_KEYS: usize = 8;
/// Maximum number of `PROP_HOST_PEER_KEYS` entries.
pub const MAX_PEER_KEYS: usize = 8;

/// One provisioned host channel key with its derived channel
/// identifier (the digest form, and an implicit receive filter).
#[derive(Clone, Copy)]
struct ChannelKeyEntry {
    key: [u8; items::CHANNEL_KEY_LEN],
    id: [u8; items::CHANNEL_ID_LEN],
}

/// `PROP_HOST_CHANNEL_KEYS`: an unordered set of channel keys. The
/// remove selector is the key; the digest form is the derived channel
/// identifier.
#[derive(Default)]
struct ChannelKeyTable {
    entries: [Option<ChannelKeyEntry>; MAX_CHANNEL_KEYS],
    len: usize,
}

impl ChannelKeyTable {
    fn iter(&self) -> impl Iterator<Item = &ChannelKeyEntry> {
        self.entries[..self.len].iter().map(|entry| {
            entry.as_ref().expect("entries below len are populated")
        })
    }

    fn insert(&mut self, entry: ChannelKeyEntry) -> Result<(), Status> {
        if self.iter().any(|existing| existing.key == entry.key) {
            return Err(Status::ALREADY);
        }
        if self.len == MAX_CHANNEL_KEYS {
            return Err(Status::NOMEM);
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// Remove by channel key, returning the removed entry's derived
    /// identifier (the digest form).
    fn remove(&mut self, key: &[u8; items::CHANNEL_KEY_LEN]) -> Result<[u8; 2], Status> {
        let Some(index) = self.iter().position(|existing| existing.key == *key) else {
            return Err(Status::ITEM_NOT_FOUND);
        };
        let id = self.entries[index].expect("populated").id;
        self.len -= 1;
        self.entries[index] = self.entries[self.len];
        self.entries[self.len] = None;
        Ok(id)
    }
}

/// `PROP_HOST_PEER_KEYS`: pairwise key material for provisioned peers.
/// Keyed by peer public key (the digest form and remove selector);
/// inserting a matching public key replaces the stored key material.
#[derive(Default)]
struct PeerKeyTable {
    entries: [Option<items::PeerKeyEntry>; MAX_PEER_KEYS],
    len: usize,
}

impl PeerKeyTable {
    fn iter(&self) -> impl Iterator<Item = &items::PeerKeyEntry> {
        self.entries[..self.len].iter().map(|entry| {
            entry.as_ref().expect("entries below len are populated")
        })
    }

    /// Insert or replace (by public key). Replacement updates only the
    /// stored key material per the spec: nothing else is keyed by the
    /// key values.
    fn insert(&mut self, entry: items::PeerKeyEntry) -> Result<(), Status> {
        if let Some(existing) = self.entries[..self.len]
            .iter_mut()
            .flatten()
            .find(|existing| existing.public_key == entry.public_key)
        {
            *existing = entry;
            return Ok(());
        }
        if self.len == MAX_PEER_KEYS {
            return Err(Status::NOMEM);
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// Remove by peer public key.
    fn remove(&mut self, public_key: &[u8; items::PUBLIC_KEY_LEN]) -> Result<(), Status> {
        let Some(index) = self
            .iter()
            .position(|existing| existing.public_key == *public_key)
        else {
            return Err(Status::ITEM_NOT_FOUND);
        };
        self.len -= 1;
        self.entries[index] = self.entries[self.len];
        self.entries[self.len] = None;
        Ok(())
    }
}

/// State belonging to the configured tethered host identity (spec
/// §State Classes, host domain): host key, key tables, filters,
/// auto-ACK policy, and the inbound queue. The `CAP_HOST_AUTO_ACK`
/// increment extends it; host replacement resets it as one unit.
#[derive(Default)]
struct HostDomain {
    /// `PROP_HOST_KEY`; `None` means no host identity is configured.
    key: Option<[u8; items::PUBLIC_KEY_LEN]>,
    /// `PROP_HOST_RX_FILTERS`.
    filters: FilterTable,
    /// `PROP_HOST_CHANNEL_KEYS`.
    channel_keys: ChannelKeyTable,
    /// `PROP_HOST_PEER_KEYS`.
    peer_keys: PeerKeyTable,
    /// The inbound queue, populated while the host is detached.
    queue: RxQueue,
}

impl HostDomain {
    /// Reset the whole domain to defaults with `key` installed,
    /// in place: the domain embeds the multi-KB queue array, and a
    /// wholesale struct replacement would stage that array on the
    /// caller's stack.
    fn reset(&mut self, key: Option<[u8; items::PUBLIC_KEY_LEN]>) {
        self.key = key;
        self.filters = FilterTable::default();
        self.channel_keys = ChannelKeyTable::default();
        self.peer_keys = PeerKeyTable::default();
        self.queue.clear();
    }

    /// Spec §Receive Filtering compatibility rule: with no host key, no
    /// host channel keys, and an empty explicit table, filtering is
    /// unconfigured and every received frame is accepted.
    fn filtering_configured(&self) -> bool {
        self.key.is_some() || !self.filters.is_empty() || self.channel_keys.len != 0
    }

    /// Whether receive filtering accepts this frame: any explicit
    /// filter or the implicit destination-hint filter for the host key
    /// matches. Hints are prefilters — over-acceptance is fine, the
    /// host verifies cryptographically. A frame that does not parse as
    /// UMSH can match no filter.
    fn accepts_frame(&self, data: &[u8]) -> bool {
        if !self.filtering_configured() {
            return true;
        }
        let Ok(header) = PacketHeader::parse(data) else {
            return false;
        };
        // A MAC ack's DST field carries the destination's 3-byte
        // public-key prefix just like a unicast destination hint.
        let dst = header.dst.or(header.ack_dst).map(|hint| hint.0);
        if let Some(key) = &self.key
            && dst == Some([key[0], key[1], key[2]])
        {
            return true;
        }
        let channel = header.channel.map(|channel| channel.0);
        // Each provisioned host channel key's derived identifier is an
        // implicit channel filter.
        if channel.is_some()
            && self
                .channel_keys
                .iter()
                .any(|entry| channel == Some(entry.id))
        {
            return true;
        }
        let pkt_type = header.fcf.packet_type() as u8;
        self.filters.iter().any(|filter| match filter {
            Filter::DestHint(hint) => dst == Some(*hint),
            Filter::ChannelId(id) => channel == Some(*id),
            Filter::PktType(filtered) => pkt_type == *filtered,
        })
    }
}

/// State that exists only while a host is attached (spec §State
/// Classes): transaction correlation and session-scoped properties.
/// Reset on every attach without touching the radio.
#[derive(Default)]
struct SessionState {
    /// `PROP_MAC_PROMISCUOUS` — the only session-scoped property.
    promiscuous: bool,
    pending: Option<PendingTx>,
    /// Host replacement awaiting its durable wipe
    /// ([`Effect::WipeHostDomain`]). The new key is installed only when
    /// the wipe completes; a detach mid-flight abandons the
    /// transaction, leaving the old host domain in effect.
    pending_host: Option<PendingHostKey>,
    /// A drain in progress ([`Effect::DrainQueue`]). Covers exactly the
    /// frames queued when `CMD_QUEUE_DRAIN` arrived; an attach or
    /// detach abandons the drain, leaving undelivered frames queued.
    drain: Option<DrainState>,
}

struct PendingHostKey {
    tid: u8,
    key: Option<[u8; items::PUBLIC_KEY_LEN]>,
}

struct DrainState {
    tid: u8,
    remaining: usize,
}

pub struct Session<A: AesProvider, S: Sha256Provider> {
    config: SessionConfig,
    /// Protocol crypto (channel-identifier derivation now; packet
    /// authentication and delegated acknowledgement with
    /// `CAP_HOST_AUTO_ACK`).
    engine: CryptoEngine<A, S>,
    device: DeviceDomain,
    host: HostDomain,
    session: SessionState,
    /// Whether a host is currently attached: accepted frames are
    /// delivered live when true and queued when false. Starts detached;
    /// the transport binding reports attach/detach edges.
    attached: bool,
    /// Whether the attached transport meets its security binding for
    /// key provisioning (spec §Provisioning Security): physical
    /// possession for serial, an encrypted bonded LESC link for BLE.
    link_secure: bool,
    last_status: Status,
    tx_buf: [u8; MAX_MTU],
    tx_len: usize,
    scratch: [u8; SCRATCH],
}

impl<A: AesProvider, S: Sha256Provider> Session<A, S> {
    /// `boot_status` is the retained hardware reset cause, reported by
    /// the first `PROP_LAST_STATUS` get of the first session.
    pub fn new(config: SessionConfig, boot_status: Status, engine: CryptoEngine<A, S>) -> Self {
        debug_assert!(usize::from(config.mtu) <= MAX_MTU);
        debug_assert!(valid_device_name(config.default_device_name.as_bytes()));
        Self {
            config,
            engine,
            device: DeviceDomain::post_reset(&config),
            host: HostDomain::default(),
            session: SessionState::default(),
            attached: false,
            link_secure: false,
            last_status: boot_status,
            tx_buf: [0; MAX_MTU],
            tx_len: 0,
            scratch: [0; SCRATCH],
        }
    }

    /// The active radio settings.
    pub fn settings(&self) -> RadioSettings {
        self.device.settings
    }

    /// Current UTF-8 `PROP_DEV_NAME` value.
    pub fn device_name(&self) -> &str {
        core::str::from_utf8(&self.device.name[..self.device.name_len])
            .expect("validated device name")
    }

    /// Payload of the transmit requested by [`Effect::StartTransmit`].
    pub fn tx_data(&self) -> &[u8] {
        &self.tx_buf[..self.tx_len]
    }

    /// Power selection for the pending transmit.
    pub fn tx_power(&self) -> TxPower {
        self.session.pending
            .as_ref()
            .map(|pending| pending.power)
            .unwrap_or(TxPower::Default)
    }

    /// Whether a transmit is awaiting [`Session::on_tx_result`].
    pub fn has_pending_tx(&self) -> bool {
        self.session.pending.is_some()
    }

    /// Reset all protocol state to post-reset values, announce the
    /// reset with the given reason, and return the radio effect
    /// restoring the post-reset (disabled) radio configuration.
    ///
    /// Used for `CMD_RST` (with [`Status::RESET_SOFTWARE`]). Once a
    /// saved snapshot exists (`CAP_SAVE`), the post-reset values come
    /// from it instead of the documented defaults.
    pub fn reset(&mut self, reason: Status, emit: &mut impl FnMut(&[u8])) -> Effect {
        self.device = DeviceDomain::post_reset(&self.config);
        self.host.reset(None);
        self.session = SessionState::default();
        self.send_status(TID_UNSOLICITED, reason, emit);
        Effect::ApplyRadio(self.device.settings)
    }

    /// A host attached. Resets session state only (spec §Attach): the
    /// device and host domains — PHY configuration and enable state,
    /// device name, duty accounting, provisioning, and the inbound
    /// queue — are untouched, and nothing is emitted; the attach itself
    /// produces no notification. Accepted frames are delivered live
    /// from here on; queued frames wait for `CMD_QUEUE_DRAIN`.
    ///
    /// `link_secure` states whether this transport meets its security
    /// binding for key provisioning (spec §Provisioning Security):
    /// physical possession for serial transports, an encrypted bonded
    /// LESC link for BLE. Key-bearing writes are refused while false.
    pub fn attach(&mut self, link_secure: bool) {
        self.session = SessionState::default();
        self.attached = true;
        self.link_secure = link_secure;
    }

    /// The host detached. Session state is discarded; the device and
    /// host domains keep operating detached: accepted frames are queued
    /// instead of delivered (delegated acknowledgement arrives with
    /// `CAP_HOST_AUTO_ACK`).
    pub fn detach(&mut self) {
        self.session = SessionState::default();
        self.attached = false;
        self.link_secure = false;
    }

    /// Handle one decoded companion-link frame from the host.
    pub fn handle_frame(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        // Malformed frames (bad flag, reserved bits, command MSB) are
        // ignored per the spec.
        let received = Frame::parse(bytes).ok()?;
        let tid = received.header.tid();
        match received.command() {
            Some(Cmd::Nop) => {
                self.send_status(tid, Status::OK, emit);
                None
            }
            Some(Cmd::Reset) => Some(self.reset(Status::RESET_SOFTWARE, emit)),
            Some(Cmd::PropGet) => match PropPayload::parse(received.payload) {
                Ok(payload) => self.prop_get(tid, payload.key, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            Some(Cmd::PropSet) => match PropPayload::parse(received.payload) {
                Ok(payload) => self.prop_set(tid, payload.key, payload.value, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            Some(Cmd::StrSend) => match StreamPayload::parse(received.payload) {
                Ok(payload) => self.str_send(tid, &payload, now_ms, emit),
                Err(_) => {
                    self.fail(tid, Status::PARSE_ERROR, emit);
                    None
                }
            },
            Some(Cmd::PropInsert) => {
                match PropPayload::parse(received.payload) {
                    Ok(payload) => self.prop_insert(tid, payload.key, payload.value, emit),
                    Err(_) => self.fail(tid, Status::PARSE_ERROR, emit),
                }
                None
            }
            Some(Cmd::PropRemove) => {
                match PropPayload::parse(received.payload) {
                    Ok(payload) => self.prop_remove(tid, payload.key, payload.value, emit),
                    Err(_) => self.fail(tid, Status::PARSE_ERROR, emit),
                }
                None
            }
            // Deliver queued inbound frames. The payload MUST be
            // ignored. The drain covers exactly the frames queued now;
            // an empty queue succeeds immediately.
            Some(Cmd::QueueDrain) => {
                if self.session.drain.is_some() {
                    self.fail(tid, Status::BUSY, emit);
                    return None;
                }
                if self.host.queue.len == 0 {
                    self.send_status(tid, Status::OK, emit);
                    return None;
                }
                self.session.drain = Some(DrainState {
                    tid,
                    remaining: self.host.queue.len,
                });
                Some(Effect::DrainQueue)
            }
            // Capability-gated full commands this session does not yet
            // advertise (`CAP_SAVE`).
            Some(Cmd::Save | Cmd::Restore) => {
                self.fail(tid, Status::UNIMPLEMENTED, emit);
                None
            }
            // Base-protocol command, available regardless of
            // capabilities. Nothing this session persists is subject to
            // CMD_CLEAR (BLE bonds and the pairing PIN are exempt by
            // spec), so it succeeds trivially.
            Some(Cmd::Clear) => {
                self.send_status(tid, Status::OK, emit);
                None
            }
            // NCP-to-host commands arriving from the host.
            Some(Cmd::PropIs | Cmd::StrRecv | Cmd::PropInserted | Cmd::PropRemoved) => {
                self.fail(tid, Status::INVALID_COMMAND, emit);
                None
            }
            None => {
                self.fail(tid, Status::INVALID_COMMAND, emit);
                None
            }
        }
    }

    /// Report a frame received on air at `now_ms`. While a host is
    /// attached, accepted frames are emitted live as `CMD_STR_RECV`
    /// (promiscuous mode bypasses filtering for live delivery only);
    /// while detached, accepted frames are placed in the inbound queue
    /// instead. Ignored while the PHY is disabled.
    pub fn on_radio_rx(
        &mut self,
        data: &[u8],
        rssi_dbm: i16,
        snr_cb: i16,
        lqi: Option<core::num::NonZeroU8>,
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) {
        if !self.device.settings.enabled || data.len() > usize::from(self.config.mtu) {
            return;
        }
        if !self.attached {
            // Detached operation: no protocol-defined duplicate
            // detection applies until keys exist (`CAP_HOST_KEYS`), so
            // every accepted frame occupies its own entry.
            if self.host.accepts_frame(data) {
                self.host.queue.push(data, rssi_dbm, snr_cb, lqi, now_ms);
            }
            return;
        }
        if !self.session.promiscuous && !self.host.accepts_frame(data) {
            return;
        }
        let mut rx_meta = [0u8; RxMeta::WIRE_LEN];
        let meta_len = RxMeta {
            rssi_dbm: Some(rssi_dbm),
            lqi,
            snr_cb: Some(snr_cb),
        }
        .encode(&mut rx_meta)
        .expect("buffer sized with WIRE_LEN");
        if let Ok(len) = frame::str_recv(
            &mut self.scratch,
            stream::PHY_RAW,
            data,
            &rx_meta[..meta_len],
        ) {
            emit(&self.scratch[..len]);
        }
    }

    /// Report completion of the transmit started by
    /// [`Effect::StartTransmit`].
    pub fn on_tx_result(&mut self, success: bool, now_ms: u64, emit: &mut impl FnMut(&[u8])) {
        let Some(pending) = self.session.pending.take() else {
            return;
        };
        if success {
            self.device.duty.record(now_ms, pending.airtime_ms);
            if pending.tid != TID_UNSOLICITED {
                self.send_status(pending.tid, Status::OK, emit);
            } else {
                self.last_status = Status::OK;
            }
        } else {
            self.fail(pending.tid, Status::FAILURE, emit);
        }
    }

    // ─── Command implementations ─────────────────────────────────────

    fn prop_get(
        &mut self,
        tid: u8,
        key: u32,
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        // PROP_PHY_RSSI is an instantaneous radio reading the session cannot
        // produce on its own. While the PHY is enabled (in RX), defer to the
        // caller to sample it; while disabled there is no ambient RSSI to read.
        if key == prop::BLE_PAIRING_PIN {
            self.fail(tid, Status::UNIMPLEMENTED, emit);
            return None;
        }
        if key == prop::PHY_RSSI {
            if self.device.settings.enabled {
                return Some(Effect::SampleRssi { tid });
            }
            self.fail(tid, Status::INVALID_STATE, emit);
            return None;
        }
        let mut value = [0u8; PROP_BUF];
        match self.encode_prop(key, now_ms, &mut value) {
            PropValue::Encoded(len) => self.send_prop_is(tid, key, &value[..len], emit),
            PropValue::Unimplemented => self.fail(tid, Status::UNIMPLEMENTED, emit),
            PropValue::Unknown => self.fail(tid, Status::PROP_NOT_FOUND, emit),
        }
        None
    }

    /// Complete a deferred `PROP_PHY_RSSI` read requested via
    /// [`Effect::SampleRssi`]. `rssi` is the sampled value in dBm, or `Err` if
    /// the radio read failed. Quote the same `tid` the effect carried.
    pub fn respond_rssi(&mut self, tid: u8, rssi: Result<i16, ()>, emit: &mut impl FnMut(&[u8])) {
        match rssi {
            Ok(dbm) => {
                let clamped = dbm.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8;
                self.send_prop_is(tid, prop::PHY_RSSI, &[clamped as u8], emit);
            }
            Err(()) => self.fail(tid, Status::FAILURE, emit),
        }
    }

    /// Advance the drain started by [`Effect::DrainQueue`] one step,
    /// emitting either the next covered frame (oldest first, as
    /// `CMD_STR_RECV` with buffered metadata) or, once the covered set
    /// is exhausted, the completion status. Returns `true` while
    /// another call is needed; flush the transport between calls.
    pub fn drain_step(&mut self, now_ms: u64, emit: &mut impl FnMut(&[u8])) -> bool {
        let Some(drain) = &mut self.session.drain else {
            return false;
        };
        if drain.remaining == 0 {
            let tid = drain.tid;
            self.session.drain = None;
            self.send_status(tid, Status::OK, emit);
            return false;
        }
        drain.remaining -= 1;
        let Some(entry) = self.host.queue.pop_front() else {
            // The covered set outliving the queue means state was reset
            // mid-drain; complete rather than stall.
            let tid = drain.tid;
            self.session.drain = None;
            self.send_status(tid, Status::OK, emit);
            return false;
        };
        let mut rx_meta = [0u8; BufferedRxMeta::WIRE_LEN];
        let meta_len = BufferedRxMeta {
            rx: RxMeta {
                rssi_dbm: Some(entry.rssi_dbm),
                lqi: entry.lqi,
                snr_cb: Some(entry.snr_cb),
            },
            flags: RX_FLAG_BUFFERED | if entry.acked { RX_FLAG_ACKED } else { 0 },
            age_s: u32::try_from(now_ms.saturating_sub(entry.rx_time_ms) / 1000)
                .unwrap_or(u32::MAX),
        }
        .encode(&mut rx_meta)
        .expect("buffer sized with WIRE_LEN");
        if let Ok(len) = frame::str_recv(
            &mut self.scratch,
            stream::PHY_RAW,
            entry.frame(),
            &rx_meta[..meta_len],
        ) {
            emit(&self.scratch[..len]);
        }
        true
    }

    /// Complete a deferred host replacement requested via
    /// [`Effect::WipeHostDomain`], quoting the same `tid`. On `Ok` the
    /// live host domain resets as one unit and the new key takes
    /// effect; on `Err` the old host domain remains fully in effect and
    /// the new key is not installed (spec §Mutation Atomicity).
    pub fn respond_host_wipe(
        &mut self,
        tid: u8,
        result: Result<(), ()>,
        emit: &mut impl FnMut(&[u8]),
    ) {
        let Some(pending) = self.session.pending_host.take_if(|pending| pending.tid == tid) else {
            return;
        };
        match result {
            Ok(()) => {
                self.host.reset(pending.key);
                let value = pending.key.as_ref().map_or(&[][..], |key| &key[..]);
                self.send_prop_is(tid, prop::HOST_KEY, value, emit);
            }
            Err(()) => self.fail(tid, Status::FAILURE, emit),
        }
    }

    /// Complete a deferred write of the write-only BLE pairing PIN.
    pub fn respond_pin_set(
        &mut self,
        tid: u8,
        result: Result<(), ()>,
        emit: &mut impl FnMut(&[u8]),
    ) {
        self.send_status(
            tid,
            if result.is_ok() {
                Status::OK
            } else {
                Status::INTERNAL_ERROR
            },
            emit,
        );
    }

    fn prop_set(
        &mut self,
        tid: u8,
        key: u32,
        value: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        if key == prop::BLE_PAIRING_PIN {
            let pin = if value.is_empty() {
                None
            } else {
                match parse_u32(value) {
                    Ok(pin) if pin <= 999_999 => Some(pin),
                    _ => {
                        self.fail(tid, Status::INVALID_ARGUMENT, emit);
                        return None;
                    }
                }
            };
            return Some(Effect::SetPairingPin { tid, pin });
        }
        if key == prop::HOST_KEY {
            let new_key = match value.len() {
                0 => None,
                items::PUBLIC_KEY_LEN => {
                    let mut key = [0; items::PUBLIC_KEY_LEN];
                    key.copy_from_slice(value);
                    Some(key)
                }
                _ => {
                    self.fail(tid, Status::INVALID_ARGUMENT, emit);
                    return None;
                }
            };
            // Setting the current value is idempotent and has no side
            // effects; a different value replaces the whole host domain
            // behind a durable wipe (spec §Host Replacement).
            if new_key == self.host.key {
                self.send_prop_is(tid, key, value, emit);
                return None;
            }
            if self.session.pending_host.is_some() {
                self.fail(tid, Status::BUSY, emit);
                return None;
            }
            self.session.pending_host = Some(PendingHostKey { tid, key: new_key });
            return Some(Effect::WipeHostDomain { tid });
        }
        if key == prop::DEV_NAME {
            if !valid_device_name(value) {
                self.fail(tid, Status::INVALID_ARGUMENT, emit);
                return None;
            }
            self.device.name[..value.len()].copy_from_slice(value);
            self.device.name_len = value.len();
            self.send_prop_is(tid, key, value, emit);
            return Some(Effect::DeviceNameChanged);
        }
        let radio_affecting = match self.apply_prop_set(key, value) {
            Ok(radio_affecting) => radio_affecting,
            Err(status) => {
                self.fail(tid, status, emit);
                return None;
            }
        };
        // Echo the authoritative value back from session state.
        let mut encoded = [0u8; PROP_BUF];
        if let PropValue::Encoded(len) = self.encode_prop(key, now_ms, &mut encoded) {
            self.send_prop_is(tid, key, &encoded[..len], emit);
        }
        radio_affecting.then_some(Effect::ApplyRadio(self.device.settings))
    }

    /// Validate and apply a property write. Returns whether the radio
    /// configuration changed.
    fn apply_prop_set(&mut self, key: u32, value: &[u8]) -> Result<bool, Status> {
        match key {
            prop::PHY_ENABLED => {
                self.device.settings.enabled = parse_bool(value)?;
                Ok(true)
            }
            prop::PHY_FREQ => {
                let freq_khz = parse_u32(value)?;
                if !(self.config.freq_khz_min..=self.config.freq_khz_max).contains(&freq_khz) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.device.settings.freq_khz = freq_khz;
                Ok(true)
            }
            prop::PHY_TX_POWER => {
                let power = parse_i8(value)?;
                if !(self.config.min_tx_power_dbm..=self.config.max_tx_power_dbm).contains(&power) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.device.settings.tx_power_dbm = power;
                Ok(true)
            }
            prop::PHY_LORA_BW => {
                let bw_hz = parse_u32(value)?;
                if !SUPPORTED_BW_HZ.contains(&bw_hz) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.device.settings.bw_hz = bw_hz;
                Ok(true)
            }
            prop::PHY_LORA_SF => {
                let sf = parse_u8(value)?;
                if !(5..=12).contains(&sf) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.device.settings.sf = sf;
                Ok(true)
            }
            prop::PHY_LORA_CR => {
                let cr = parse_u8(value)?;
                if !(5..=8).contains(&cr) {
                    return Err(Status::INVALID_ARGUMENT);
                }
                self.device.settings.cr_denom = cr;
                Ok(true)
            }
            prop::PHY_LORA_SW => {
                // v0: the sync word is fixed at build time; accept only
                // a write of the same value.
                if parse_u16(value)? != self.config.sync_word {
                    return Err(Status::INVALID_ARGUMENT);
                }
                Ok(false)
            }
            prop::PHY_DUTY_LIMIT => {
                self.device.duty_limit = parse_u16(value)?;
                Ok(false)
            }
            prop::MAC_PROMISCUOUS => {
                // Session-scoped: reverts to false on every attach.
                self.session.promiscuous = parse_bool(value)?;
                Ok(false)
            }
            // Whole-table replacement: the complete value is validated
            // into a candidate table before anything changes, so no
            // observer sees a mixture of old and new contents.
            prop::HOST_RX_FILTERS => {
                self.host.filters = FilterTable::parse_table(value)?;
                Ok(false)
            }
            // Key-bearing writes require the transport's security
            // binding (spec §Provisioning Security).
            prop::HOST_CHANNEL_KEYS => {
                self.require_secure_link()?;
                let mut table = ChannelKeyTable::default();
                for key in items::fixed_items::<{ items::CHANNEL_KEY_LEN }>(value)
                    .map_err(|_| Status::INVALID_ARGUMENT)?
                {
                    // Duplicate keys in a set value collapse.
                    match table.insert(self.channel_entry(key)) {
                        Ok(()) | Err(Status::ALREADY) => {}
                        Err(status) => return Err(status),
                    }
                }
                self.host.channel_keys = table;
                Ok(false)
            }
            prop::HOST_PEER_KEYS => {
                self.require_secure_link()?;
                let mut table = PeerKeyTable::default();
                for item in items::fixed_items::<{ items::PeerKeyEntry::WIRE_LEN }>(value)
                    .map_err(|_| Status::INVALID_ARGUMENT)?
                {
                    let entry = items::PeerKeyEntry::decode(item)
                        .map_err(|_| Status::INVALID_ARGUMENT)?;
                    // A repeated public key replaces the earlier entry.
                    table.insert(entry)?;
                }
                self.host.peer_keys = table;
                Ok(false)
            }
            // This NCP's queue size is fixed; adjustment is optional in
            // the spec and unimplemented here.
            prop::HOST_RX_QUEUE_CAPACITY => Err(Status::UNIMPLEMENTED),
            // Known read-only properties.
            prop::LAST_STATUS
            | prop::PROTOCOL_VERSION
            | prop::NCP_VERSION
            | prop::INTERFACE_TYPE
            | prop::CAPS
            | prop::PHY_RSSI
            | prop::PHY_MTU
            | prop::PHY_DUTY_NOW
            | prop::HOST_RX_QUEUE_COUNT
            | prop::HOST_RX_QUEUE_DROPPED => Err(Status::INVALID_ARGUMENT),
            _ => Err(Status::PROP_NOT_FOUND),
        }
    }

    /// `CMD_PROP_INSERT`: add one item (in item form, no length prefix)
    /// to a multi-value property.
    fn prop_insert(&mut self, tid: u8, key: u32, item: &[u8], emit: &mut impl FnMut(&[u8])) {
        match key {
            prop::HOST_RX_FILTERS => {
                let filter = match decode_filter(item) {
                    Ok(filter) => filter,
                    Err(status) => return self.fail(tid, status, emit),
                };
                match self.host.filters.insert(filter) {
                    Ok(()) => self.send_prop_inserted(tid, key, item, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            // Key-bearing inserts require the transport's security
            // binding. The emitted digest never contains key material.
            prop::HOST_CHANNEL_KEYS => {
                let result = self.require_secure_link().and_then(|()| {
                    let key: &[u8; items::CHANNEL_KEY_LEN] =
                        item.try_into().map_err(|_| Status::INVALID_ARGUMENT)?;
                    let entry = self.channel_entry(key);
                    self.host.channel_keys.insert(entry).map(|()| entry.id)
                });
                match result {
                    Ok(id) => self.send_prop_inserted(tid, key, &id, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            prop::HOST_PEER_KEYS => {
                let result = self.require_secure_link().and_then(|()| {
                    let entry = items::PeerKeyEntry::decode(item)
                        .map_err(|_| Status::INVALID_ARGUMENT)?;
                    // A matching public key replaces the stored key
                    // material (never STATUS_ALREADY).
                    self.host.peer_keys.insert(entry).map(|()| entry.public_key)
                });
                match result {
                    Ok(public_key) => self.send_prop_inserted(tid, key, &public_key, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            // A known property that is not a mutable multi-value
            // property cannot be inserted into.
            _ if self.known_prop(key) => self.fail(tid, Status::INVALID_ARGUMENT, emit),
            _ => self.fail(tid, Status::PROP_NOT_FOUND, emit),
        }
    }

    /// `CMD_PROP_REMOVE`: remove the item matching the selector from a
    /// multi-value property.
    fn prop_remove(&mut self, tid: u8, key: u32, selector: &[u8], emit: &mut impl FnMut(&[u8])) {
        match key {
            prop::HOST_RX_FILTERS => {
                // The remove selector is the full item.
                let filter = match decode_filter(selector) {
                    Ok(filter) => filter,
                    Err(status) => return self.fail(tid, status, emit),
                };
                match self.host.filters.remove(filter) {
                    Ok(()) => self.send_prop_removed(tid, key, selector, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            // The channel-key remove selector is the key itself; the
            // digest reported back is the derived channel identifier.
            prop::HOST_CHANNEL_KEYS => {
                let result = selector
                    .try_into()
                    .map_err(|_| Status::INVALID_ARGUMENT)
                    .and_then(|key: &[u8; items::CHANNEL_KEY_LEN]| {
                        self.host.channel_keys.remove(key)
                    });
                match result {
                    Ok(id) => self.send_prop_removed(tid, key, &id, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            // The peer remove selector is the peer public key (already
            // the digest form).
            prop::HOST_PEER_KEYS => {
                let result = selector
                    .try_into()
                    .map_err(|_| Status::INVALID_ARGUMENT)
                    .and_then(|public_key: &[u8; items::PUBLIC_KEY_LEN]| {
                        self.host.peer_keys.remove(public_key)
                    });
                match result {
                    Ok(()) => self.send_prop_removed(tid, key, selector, emit),
                    Err(status) => self.fail(tid, status, emit),
                }
            }
            _ if self.known_prop(key) => self.fail(tid, Status::INVALID_ARGUMENT, emit),
            _ => self.fail(tid, Status::PROP_NOT_FOUND, emit),
        }
    }

    /// Derive a channel key's identifier (its digest form and implicit
    /// receive filter).
    fn channel_entry(&self, key: &[u8; items::CHANNEL_KEY_LEN]) -> ChannelKeyEntry {
        ChannelKeyEntry {
            key: *key,
            id: self.engine.derive_channel_id(&ChannelKey(*key)).0,
        }
    }

    /// Refuse key-bearing writes over a transport that does not meet
    /// its security binding (spec §Provisioning Security).
    fn require_secure_link(&self) -> Result<(), Status> {
        if self.link_secure {
            Ok(())
        } else {
            Err(Status::INVALID_STATE)
        }
    }

    fn str_send(
        &mut self,
        tid: u8,
        payload: &StreamPayload<'_>,
        now_ms: u64,
        emit: &mut impl FnMut(&[u8]),
    ) -> Option<Effect> {
        if payload.stream != stream::PHY_RAW {
            self.fail(tid, Status::PROP_NOT_FOUND, emit);
            return None;
        }
        if !self.device.settings.enabled {
            self.fail(tid, Status::INVALID_STATE, emit);
            return None;
        }
        if payload.data.len() > usize::from(self.config.mtu) {
            self.fail(tid, Status::INVALID_ARGUMENT, emit);
            return None;
        }
        let Ok(tx_meta) = TxMeta::decode(payload.metadata) else {
            self.fail(tid, Status::PARSE_ERROR, emit);
            return None;
        };
        if self.session.pending.is_some() {
            self.fail(tid, Status::BUSY, emit);
            return None;
        }

        let airtime_ms = lora_airtime_ms(
            self.device.settings.sf,
            self.device.settings.bw_hz,
            self.device.settings.cr_denom,
            payload.data.len(),
        );
        if tx_meta.flags & meta::TX_FLAG_NODUTY == 0
            && self.device.duty.would_exceed(now_ms, airtime_ms, self.device.duty_limit)
        {
            self.fail(tid, Status::DUTY_LIMIT, emit);
            return None;
        }
        // v0: the CCA flag is ignored — this firmware's radio path has
        // no CAD gate, so every transmit behaves as NOCCA.

        self.tx_buf[..payload.data.len()].copy_from_slice(payload.data);
        self.tx_len = payload.data.len();
        self.session.pending = Some(PendingTx {
            tid,
            airtime_ms,
            power: match tx_meta.power {
                meta::TX_POWER_DEFAULT => TxPower::Default,
                meta::TX_POWER_MAX => TxPower::Max,
                dbm => TxPower::Dbm(dbm),
            },
        });
        Some(Effect::StartTransmit)
    }

    // ─── Property encoding ───────────────────────────────────────────

    /// Whether `key` names a property this session knows, including
    /// write-only (`PROP_BLE_PAIRING_PIN`) and deferred-read
    /// (`PROP_PHY_RSSI`) properties that `encode_prop` cannot produce.
    fn known_prop(&self, key: u32) -> bool {
        matches!(
            key,
            prop::LAST_STATUS
                | prop::PROTOCOL_VERSION
                | prop::NCP_VERSION
                | prop::INTERFACE_TYPE
                | prop::CAPS
                | prop::PHY_ENABLED
                | prop::PHY_FREQ
                | prop::PHY_TX_POWER
                | prop::PHY_RSSI
                | prop::PHY_LORA_BW
                | prop::PHY_LORA_SF
                | prop::PHY_LORA_CR
                | prop::PHY_MTU
                | prop::PHY_LORA_SW
                | prop::DEV_NAME
                | prop::PHY_DUTY_NOW
                | prop::PHY_DUTY_LIMIT
                | prop::BLE_PAIRING_PIN
                | prop::MAC_PROMISCUOUS
                | prop::HOST_KEY
                | prop::HOST_RX_FILTERS
                | prop::HOST_CHANNEL_KEYS
                | prop::HOST_PEER_KEYS
                | prop::HOST_RX_QUEUE_COUNT
                | prop::HOST_RX_QUEUE_CAPACITY
                | prop::HOST_RX_QUEUE_DROPPED
        )
    }

    fn encode_prop(&mut self, key: u32, now_ms: u64, out: &mut [u8; PROP_BUF]) -> PropValue {
        let len = match key {
            prop::LAST_STATUS => pui::encode(self.last_status.0, out).unwrap_or(0),
            prop::PROTOCOL_VERSION => {
                out[0] = ids::PROTOCOL_MAJOR_VERSION;
                out[1] = ids::PROTOCOL_MINOR_VERSION;
                2
            }
            prop::NCP_VERSION => {
                let bytes = self.config.ncp_version.as_bytes();
                let len = bytes.len().min(out.len() - 1);
                out[..len].copy_from_slice(&bytes[..len]);
                out[len] = 0; // NUL terminator per spec
                len + 1
            }
            prop::INTERFACE_TYPE => pui::encode(ids::INTERFACE_TYPE, out).unwrap_or(0),
            prop::CAPS => {
                let mut len = 0;
                for capability in [
                    cap::WRITABLE_RAW_STREAM,
                    cap::PHY_DUTY_LIMIT,
                    cap::DEV_NAME,
                    cap::PHY_LORA,
                    cap::HOST_FILTER,
                    cap::HOST_RX_QUEUE,
                    cap::HOST_KEYS,
                ] {
                    len += pui::encode(capability, &mut out[len..]).unwrap_or(0);
                }
                len
            }
            prop::PHY_ENABLED => {
                out[0] = self.device.settings.enabled as u8;
                1
            }
            prop::PHY_FREQ => put(out, &self.device.settings.freq_khz.to_le_bytes()),
            prop::PHY_TX_POWER => {
                out[0] = self.device.settings.tx_power_dbm as u8;
                1
            }
            prop::PHY_RSSI => return PropValue::Unimplemented,
            prop::PHY_LORA_BW => put(out, &self.device.settings.bw_hz.to_le_bytes()),
            prop::PHY_LORA_SF => {
                out[0] = self.device.settings.sf;
                1
            }
            prop::PHY_LORA_CR => {
                out[0] = self.device.settings.cr_denom;
                1
            }
            prop::PHY_MTU => put(out, &self.config.mtu.to_le_bytes()),
            prop::PHY_LORA_SW => put(out, &self.config.sync_word.to_le_bytes()),
            prop::DEV_NAME => put(out, &self.device.name[..self.device.name_len]),
            prop::PHY_DUTY_NOW => put(out, &self.device.duty.usage(now_ms).to_le_bytes()),
            prop::PHY_DUTY_LIMIT => put(out, &self.device.duty_limit.to_le_bytes()),
            prop::MAC_PROMISCUOUS => {
                out[0] = self.session.promiscuous as u8;
                1
            }
            prop::HOST_KEY => match &self.host.key {
                Some(key) => put(out, key),
                None => 0,
            },
            // Key tables report digest forms only: derived channel
            // identifiers and peer public keys. Key material is never
            // read back (spec §Provisioning Security).
            prop::HOST_CHANNEL_KEYS => {
                let mut len = 0;
                for entry in self.host.channel_keys.iter() {
                    len += put(&mut out[len..], &entry.id);
                }
                len
            }
            prop::HOST_PEER_KEYS => {
                let mut len = 0;
                for entry in self.host.peer_keys.iter() {
                    len += put(&mut out[len..], &entry.public_key);
                }
                len
            }
            prop::HOST_RX_QUEUE_COUNT => put(out, &(self.host.queue.len as u16).to_le_bytes()),
            prop::HOST_RX_QUEUE_CAPACITY => {
                put(out, &(RX_QUEUE_CAPACITY as u16).to_le_bytes())
            }
            prop::HOST_RX_QUEUE_DROPPED => put(out, &self.host.queue.dropped.to_le_bytes()),
            prop::HOST_RX_FILTERS => {
                // Digest form equals item form; items carry PUI length
                // prefixes in whole-table values.
                let mut len = 0;
                for filter in self.host.filters.iter() {
                    let mut item = [0u8; Filter::MAX_WIRE_LEN];
                    let item_len = filter.encode(&mut item).expect("MAX_WIRE_LEN sized");
                    len += items::encode_prefixed_item(&item[..item_len], &mut out[len..])
                        .expect("out sized for a full filter table");
                }
                len
            }
            _ => return PropValue::Unknown,
        };
        PropValue::Encoded(len)
    }

    // ─── Emission helpers ────────────────────────────────────────────

    /// Emit `CMD_PROP_IS` for `key` with `value`.
    fn send_prop_is(&mut self, tid: u8, key: u32, value: &[u8], emit: &mut impl FnMut(&[u8])) {
        let mut buf = [0u8; PROP_BUF + 16];
        if let Ok(len) = frame::prop_is(&mut buf, tid, key, value) {
            emit(&buf[..len]);
        }
    }

    /// Emit `CMD_PROP_INSERTED` for `key` with the item's digest form.
    fn send_prop_inserted(&mut self, tid: u8, key: u32, digest: &[u8], emit: &mut impl FnMut(&[u8])) {
        let mut buf = [0u8; PROP_BUF + 16];
        if let Ok(len) = frame::prop_inserted(&mut buf, tid, key, digest) {
            emit(&buf[..len]);
        }
    }

    /// Emit `CMD_PROP_REMOVED` for `key` with the item's digest form.
    fn send_prop_removed(&mut self, tid: u8, key: u32, digest: &[u8], emit: &mut impl FnMut(&[u8])) {
        let mut buf = [0u8; PROP_BUF + 16];
        if let Ok(len) = frame::prop_removed(&mut buf, tid, key, digest) {
            emit(&buf[..len]);
        }
    }

    /// Emit `PROP_LAST_STATUS` unconditionally (success paths and
    /// unsolicited notices).
    fn send_status(&mut self, tid: u8, status: Status, emit: &mut impl FnMut(&[u8])) {
        self.last_status = status;
        let mut buf = [0u8; 16];
        if let Ok(len) = frame::last_status(&mut buf, tid, status) {
            emit(&buf[..len]);
        }
    }

    /// Record a failure. Correlated commands get an error response;
    /// fire-and-forget (TID 0) failures only update `PROP_LAST_STATUS`.
    fn fail(&mut self, tid: u8, status: Status, emit: &mut impl FnMut(&[u8])) {
        if tid == TID_UNSOLICITED {
            self.last_status = status;
        } else {
            self.send_status(tid, status, emit);
        }
    }
}

fn put(out: &mut [u8], bytes: &[u8]) -> usize {
    out[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

fn parse_bool(value: &[u8]) -> Result<bool, Status> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_u8(value: &[u8]) -> Result<u8, Status> {
    match value {
        [byte] => Ok(*byte),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_i8(value: &[u8]) -> Result<i8, Status> {
    parse_u8(value).map(|byte| byte as i8)
}

fn parse_u16(value: &[u8]) -> Result<u16, Status> {
    match value {
        [lo, hi] => Ok(u16::from_le_bytes([*lo, *hi])),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn parse_u32(value: &[u8]) -> Result<u32, Status> {
    match value {
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(Status::INVALID_ARGUMENT),
    }
}

fn valid_device_name(value: &[u8]) -> bool {
    (1..=MAX_DEVICE_NAME_LEN).contains(&value.len())
        && !value.contains(&0)
        && core::str::from_utf8(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_crypto::software::{SoftwareAes, SoftwareSha256};

    type TestSession = Session<SoftwareAes, SoftwareSha256>;

    fn test_engine() -> CryptoEngine<SoftwareAes, SoftwareSha256> {
        CryptoEngine::new(SoftwareAes, SoftwareSha256)
    }

    /// A session with a host attached over a secure transport (the
    /// normal state for command dispatch and live-delivery tests).
    /// Queueing tests detach it; gate tests re-attach insecurely.
    fn test_session() -> TestSession {
        let mut session = test_session_with_boot_status(Status::RESET_POWER_ON);
        session.attach(true);
        session
    }

    fn test_session_with_boot_status(boot_status: Status) -> TestSession {
        let mut session = Session::new(test_config(), boot_status, test_engine());
        session.attach(true);
        session
    }

    fn test_config() -> SessionConfig {
        SessionConfig {
            ncp_version: "test-ncp/0.1",
            default_device_name: "Test UMSH NCP",
            mtu: 255,
            sync_word: 0x1424,
            min_tx_power_dbm: -9,
            max_tx_power_dbm: 22,
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: 0xFFFF,
        }
    }

    /// Drive `handle_frame` and collect emitted frames.
    fn dispatch(
        session: &mut TestSession,
        request: &[u8],
        now_ms: u64,
    ) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut emitted = Vec::new();
        let effect = session.handle_frame(request, now_ms, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        (emitted, effect)
    }

    /// Parse an emitted frame as `CMD_PROP_IS` and return (tid, key, value).
    fn parse_prop_is(bytes: &[u8]) -> (u8, u32, Vec<u8>) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::PropIs));
        let payload = PropPayload::parse(parsed.payload).unwrap();
        (parsed.header.tid(), payload.key, payload.value.to_vec())
    }

    fn expect_status(bytes: &[u8], tid: u8, status: Status) {
        let (response_tid, key, value) = parse_prop_is(bytes);
        assert_eq!(response_tid, tid);
        assert_eq!(key, prop::LAST_STATUS);
        assert_eq!(pui::decode(&value).unwrap().0, status.0);
    }

    fn get(session: &mut TestSession, key: u32) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 1, key).unwrap();
        let (emitted, effect) = dispatch(session, &buf[..len], 0);
        assert!(effect.is_none());
        let (_, response_key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(response_key, key);
        value
    }

    fn set(session: &mut TestSession, key: u32, value: &[u8]) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 640];
        let len = frame::prop_set(&mut buf, 2, key, value).unwrap();
        dispatch(session, &buf[..len], 0)
    }

    fn send_packet(
        session: &mut TestSession,
        tid: u8,
        data: &[u8],
        meta: &[u8],
        now_ms: u64,
    ) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 320];
        let len = frame::str_send(&mut buf, tid, stream::PHY_RAW, data, meta).unwrap();
        dispatch(session, &buf[..len], now_ms)
    }

    fn enable(session: &mut TestSession) {
        let (_, effect) = set(session, prop::PHY_ENABLED, &[1]);
        assert!(matches!(effect, Some(Effect::ApplyRadio(settings)) if settings.enabled));
    }

    #[test]
    fn nop_replies_ok() {
        let mut session = test_session();
        let mut buf = [0u8; 4];
        let len = frame::nop(&mut buf, 3).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 3, Status::OK);
    }

    #[test]
    fn reset_returns_to_defaults() {
        let mut session = test_session();
        enable(&mut session);
        set(&mut session, prop::PHY_LORA_SF, &[12]);

        let mut buf = [0u8; 4];
        let len = frame::reset(&mut buf, 0).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        expect_status(&emitted[0], TID_UNSOLICITED, Status::RESET_SOFTWARE);
        let Some(Effect::ApplyRadio(settings)) = effect else {
            panic!("expected ApplyRadio, got {effect:?}");
        };
        assert!(!settings.enabled);
        assert_eq!(settings.sf, 7);
        assert_eq!(get(&mut session, prop::PHY_ENABLED), [0]);
    }

    #[test]
    fn identity_properties() {
        let mut session = test_session();
        assert_eq!(get(&mut session, prop::PROTOCOL_VERSION), [6, 0]);
        assert_eq!(get(&mut session, prop::NCP_VERSION), b"test-ncp/0.1\0");
        assert_eq!(get(&mut session, prop::DEV_NAME), b"Test UMSH NCP");
        assert_eq!(get(&mut session, prop::PHY_MTU), 255u16.to_le_bytes());
        assert_eq!(
            pui::decode(&get(&mut session, prop::INTERFACE_TYPE))
                .unwrap()
                .0,
            ids::INTERFACE_TYPE
        );
        // Post-reset LAST_STATUS is the reset reason.
        assert_eq!(
            pui::decode(&get(&mut session, prop::LAST_STATUS))
                .unwrap()
                .0,
            Status::RESET_POWER_ON.0
        );
    }

    #[test]
    fn caps_list_decodes() {
        let mut session = test_session();
        let raw = get(&mut session, prop::CAPS);
        let mut caps = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let (value, used) = pui::decode(&raw[offset..]).unwrap();
            caps.push(value);
            offset += used;
        }
        assert_eq!(
            caps,
            [
                cap::WRITABLE_RAW_STREAM,
                cap::PHY_DUTY_LIMIT,
                cap::DEV_NAME,
                cap::PHY_LORA,
                cap::HOST_FILTER,
                cap::HOST_RX_QUEUE,
                cap::HOST_KEYS
            ]
        );
    }

    #[test]
    fn device_name_round_trips_survives_attach_and_resets_to_default() {
        let mut session = test_session();
        let configured = "Field Radio 📻";
        let (emitted, effect) = set(&mut session, prop::DEV_NAME, configured.as_bytes());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::DEV_NAME);
        assert_eq!(value, configured.as_bytes());
        assert_eq!(effect, Some(Effect::DeviceNameChanged));
        assert_eq!(session.device_name(), configured);

        session.attach(true);
        assert_eq!(get(&mut session, prop::DEV_NAME), configured.as_bytes());

        let _ = session.reset(Status::RESET_SOFTWARE, &mut |_| {});
        assert_eq!(get(&mut session, prop::DEV_NAME), b"Test UMSH NCP");
    }

    #[test]
    fn attach_preserves_device_domain_and_emits_nothing() {
        let mut session = test_session_with_boot_status(Status::RESET_WATCHDOG);

        // Configure and enable the PHY, adjust the duty limit, and
        // record duty usage.
        set(&mut session, prop::PHY_FREQ, &906_875u32.to_le_bytes());
        set(&mut session, prop::PHY_LORA_SF, &[9]);
        set(&mut session, prop::PHY_DUTY_LIMIT, &100u16.to_le_bytes());
        enable(&mut session);
        let settings_before = session.settings();
        assert!(settings_before.enabled);
        let (_, effect) = send_packet(&mut session, 1, &[0xAB; 8], &[], 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
        let mut emitted = Vec::new();
        session.on_tx_result(true, 0, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        let duty_before = get(&mut session, prop::PHY_DUTY_NOW);
        assert_ne!(duty_before, 0u16.to_le_bytes());

        // Attach must not reconfigure or disable the PHY, must not
        // touch the duty limit or accounting, and must emit nothing.
        session.attach(true);
        assert_eq!(session.settings(), settings_before);
        assert_eq!(get(&mut session, prop::PHY_ENABLED), [1]);
        assert_eq!(get(&mut session, prop::PHY_FREQ), 906_875u32.to_le_bytes());
        assert_eq!(get(&mut session, prop::PHY_DUTY_LIMIT), 100u16.to_le_bytes());
        assert_eq!(get(&mut session, prop::PHY_DUTY_NOW), duty_before);
    }

    #[test]
    fn attach_retains_boot_status_for_first_query() {
        let mut session = test_session_with_boot_status(Status::RESET_WATCHDOG);
        session.attach(true);
        let raw = get(&mut session, prop::LAST_STATUS);
        assert_eq!(pui::decode(&raw).unwrap().0, Status::RESET_WATCHDOG.0);
    }

    #[test]
    fn attach_resets_promiscuous_mode() {
        let mut session = test_session();
        set(&mut session, prop::MAC_PROMISCUOUS, &[1]);
        assert_eq!(get(&mut session, prop::MAC_PROMISCUOUS), [1]);
        session.attach(true);
        assert_eq!(get(&mut session, prop::MAC_PROMISCUOUS), [0]);

        // Detach discards session state the same way.
        set(&mut session, prop::MAC_PROMISCUOUS, &[1]);
        session.detach();
        session.attach(true);
        assert_eq!(get(&mut session, prop::MAC_PROMISCUOUS), [0]);

        // BOOL validation.
        let (emitted, _) = set(&mut session, prop::MAC_PROMISCUOUS, &[2]);
        expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
    }

    #[test]
    fn attach_clears_pending_transmit_correlation() {
        let mut session = test_session();
        enable(&mut session);
        let (_, effect) = send_packet(&mut session, 3, &[0x01; 4], &[], 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
        assert!(session.has_pending_tx());

        // The requesting session is gone; its TID correlation must not
        // leak into the successor.
        session.attach(true);
        assert!(!session.has_pending_tx());
        let mut emitted = Vec::new();
        session.on_tx_result(true, 0, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        assert!(emitted.is_empty());

        // The new session is free to transmit (no stale BUSY).
        let (_, effect) = send_packet(&mut session, 4, &[0x02; 4], &[], 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
    }

    #[test]
    fn reset_restores_post_reset_values_and_announces() {
        let mut session = test_session();
        set(&mut session, prop::PHY_FREQ, &906_875u32.to_le_bytes());
        set(&mut session, prop::MAC_PROMISCUOUS, &[1]);
        enable(&mut session);

        let mut emitted = Vec::new();
        let effect = session.reset(Status::RESET_SOFTWARE, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        expect_status(&emitted[0], TID_UNSOLICITED, Status::RESET_SOFTWARE);
        assert!(matches!(effect, Effect::ApplyRadio(settings) if !settings.enabled));
        assert_eq!(get(&mut session, prop::PHY_FREQ), 910_525u32.to_le_bytes());
        assert_eq!(get(&mut session, prop::MAC_PROMISCUOUS), [0]);
    }

    #[test]
    fn device_name_rejects_empty_invalid_nul_and_oversize_values() {
        let mut session = test_session();
        let oversize = [b'x'; MAX_DEVICE_NAME_LEN + 1];
        for bad in [&[][..], &[0xff][..], b"bad\0name", &oversize[..]] {
            let (emitted, effect) = set(&mut session, prop::DEV_NAME, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
        assert_eq!(session.device_name(), "Test UMSH NCP");
    }

    #[test]
    fn rf_property_round_trip() {
        let mut session = test_session();
        let (emitted, effect) = set(&mut session, prop::PHY_FREQ, &906_875u32.to_le_bytes());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::PHY_FREQ);
        assert_eq!(value, 906_875u32.to_le_bytes());
        assert!(matches!(effect, Some(Effect::ApplyRadio(s)) if s.freq_khz == 906_875));
        assert_eq!(get(&mut session, prop::PHY_FREQ), 906_875u32.to_le_bytes());
    }

    #[test]
    fn invalid_values_rejected() {
        let mut session = test_session();
        for (key, bad) in [
            (prop::PHY_LORA_SF, &[4][..]),
            (prop::PHY_LORA_SF, &[13][..]),
            (prop::PHY_LORA_CR, &[9][..]),
            (prop::PHY_LORA_BW, &123_456u32.to_le_bytes()[..]),
            (prop::PHY_FREQ, &10_000u32.to_le_bytes()[..]),
            (prop::PHY_TX_POWER, &[40][..]),
            (prop::PHY_ENABLED, &[2][..]),
            (prop::PHY_LORA_SW, &0xBEEFu16.to_le_bytes()[..]),
            // Wrong width.
            (prop::PHY_FREQ, &[1, 2][..]),
        ] {
            let (emitted, effect) = set(&mut session, key, bad);
            assert!(effect.is_none(), "key {key} accepted {bad:?}");
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn read_only_and_unknown_props() {
        let mut session = test_session();
        let (emitted, _) = set(&mut session, prop::PHY_MTU, &[0, 1]);
        expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);

        let (emitted, _) = set(&mut session, 9_999, &[0]);
        expect_status(&emitted[0], 2, Status::PROP_NOT_FOUND);

        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 1, 9_999).unwrap();
        let (emitted, _) = dispatch(&mut session, &buf[..len], 0);
        expect_status(&emitted[0], 1, Status::PROP_NOT_FOUND);

        // PHY_RSSI while the PHY is disabled: no ambient RSSI to read.
        let len = frame::prop_get(&mut buf, 1, prop::PHY_RSSI).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 1, Status::INVALID_STATE);
    }

    #[test]
    fn phy_rssi_defers_to_radio_when_enabled() {
        let mut session = test_session();
        enable(&mut session);

        // A GET while enabled defers instead of answering inline.
        let mut buf = [0u8; 16];
        let len = frame::prop_get(&mut buf, 3, prop::PHY_RSSI).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(emitted.is_empty(), "no response until the radio is sampled");
        assert_eq!(effect, Some(Effect::SampleRssi { tid: 3 }));

        // The caller feeds the sample back; the session emits PROP_IS.
        let mut out = Vec::new();
        session.respond_rssi(3, Ok(-91), &mut |bytes: &[u8]| out.push(bytes.to_vec()));
        let (tid, key, value) = parse_prop_is(&out[0]);
        assert_eq!(tid, 3);
        assert_eq!(key, prop::PHY_RSSI);
        assert_eq!(value, [(-91i8) as u8]);

        // A failed radio read surfaces as STATUS_FAILURE.
        let mut out = Vec::new();
        session.respond_rssi(4, Err(()), &mut |bytes: &[u8]| out.push(bytes.to_vec()));
        expect_status(&out[0], 4, Status::FAILURE);
    }

    #[test]
    fn pairing_pin_set_clear_validate_and_defer() {
        let mut session = test_session();

        let (emitted, effect) = set(
            &mut session,
            prop::BLE_PAIRING_PIN,
            &123_456u32.to_le_bytes(),
        );
        assert!(
            emitted.is_empty(),
            "PIN must not be acknowledged before apply"
        );
        assert_eq!(
            effect,
            Some(Effect::SetPairingPin {
                tid: 2,
                pin: Some(123_456)
            })
        );

        let (emitted, effect) = set(&mut session, prop::BLE_PAIRING_PIN, &[]);
        assert!(emitted.is_empty());
        assert_eq!(effect, Some(Effect::SetPairingPin { tid: 2, pin: None }));

        for bad in [&1_000_000u32.to_le_bytes()[..], &[1, 2, 3][..]] {
            let (emitted, effect) = set(&mut session, prop::BLE_PAIRING_PIN, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn pairing_pin_completion_and_get_refusal() {
        let mut session = test_session();
        let mut emitted = Vec::new();
        session.respond_pin_set(7, Ok(()), &mut |frame| emitted.push(frame.to_vec()));
        expect_status(&emitted[0], 7, Status::OK);
        emitted.clear();
        session.respond_pin_set(6, Err(()), &mut |frame| emitted.push(frame.to_vec()));
        expect_status(&emitted[0], 6, Status::INTERNAL_ERROR);

        let mut request = [0; 16];
        let len = frame::prop_get(&mut request, 5, prop::BLE_PAIRING_PIN).unwrap();
        let (emitted, effect) = dispatch(&mut session, &request[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 5, Status::UNIMPLEMENTED);
    }

    #[test]
    fn reset_has_no_pairing_pin_effect() {
        let mut session = test_session();
        let mut request = [0; 4];
        let len = frame::reset(&mut request, 1).unwrap();
        let (_, effect) = dispatch(&mut session, &request[..len], 0);
        assert!(matches!(effect, Some(Effect::ApplyRadio(_))));
    }

    #[test]
    fn transmit_lifecycle() {
        let mut session = test_session();
        enable(&mut session);

        let packet = [0xAAu8; 32];
        let (emitted, effect) = send_packet(&mut session, 4, &packet, &[], 0);
        assert!(emitted.is_empty(), "no response until TX completes");
        assert_eq!(effect, Some(Effect::StartTransmit));
        assert_eq!(session.tx_data(), &packet);
        assert_eq!(session.tx_power(), TxPower::Default);

        // A second confirmed send while busy fails with BUSY.
        let (emitted, effect) = send_packet(&mut session, 5, &packet, &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 5, Status::BUSY);

        // Completion emits OK with the original TID and records duty.
        let mut emitted = Vec::new();
        session.on_tx_result(true, 0, &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        expect_status(&emitted[0], 4, Status::OK);
        assert!(!session.has_pending_tx());
        let duty = get(&mut session, prop::PHY_DUTY_NOW);
        assert!(u16::from_le_bytes([duty[0], duty[1]]) > 0);
    }

    #[test]
    fn transmit_requires_enabled_phy() {
        let mut session = test_session();
        let (emitted, effect) = send_packet(&mut session, 4, &[0u8; 8], &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 4, Status::INVALID_STATE);
    }

    #[test]
    fn transmit_power_override() {
        let mut session = test_session();
        enable(&mut session);
        let meta = [22u8, 0x00];
        let (_, effect) = send_packet(&mut session, 4, &[0u8; 8], &meta, 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
        assert_eq!(session.tx_power(), TxPower::Dbm(22));
    }

    #[test]
    fn duty_limit_blocks_and_noduty_bypasses() {
        let mut session = test_session();
        enable(&mut session);
        // Slowest settings: one full frame is minutes of airtime.
        set(&mut session, prop::PHY_LORA_SF, &[12]);
        set(&mut session, prop::PHY_LORA_BW, &7_810u32.to_le_bytes());
        // 0.1% limit.
        set(&mut session, prop::PHY_DUTY_LIMIT, &65u16.to_le_bytes());

        let packet = [0u8; 255];
        let (emitted, effect) = send_packet(&mut session, 3, &packet, &[], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 3, Status::DUTY_LIMIT);

        // NODUTY flag bypasses the limit.
        let meta = [meta::TX_POWER_DEFAULT as u8, meta::TX_FLAG_NODUTY];
        let (_, effect) = send_packet(&mut session, 3, &packet, &meta, 0);
        assert_eq!(effect, Some(Effect::StartTransmit));
    }

    #[test]
    fn fire_and_forget_failures_are_silent() {
        let mut session = test_session();
        // PHY disabled: a TID-0 send fails without emitting anything.
        let (emitted, effect) = send_packet(&mut session, 0, &[0u8; 4], &[], 0);
        assert!(effect.is_none());
        assert!(emitted.is_empty());
        // ... but LAST_STATUS records it.
        assert_eq!(
            pui::decode(&get(&mut session, prop::LAST_STATUS))
                .unwrap()
                .0,
            Status::INVALID_STATE.0
        );
    }

    #[test]
    fn radio_rx_emits_str_recv() {
        let mut session = test_session();
        enable(&mut session);
        let mut emitted = Vec::new();
        session.on_radio_rx(&[1, 2, 3], -91, -53, None, 0, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        let parsed = Frame::parse(&emitted[0]).unwrap();
        assert_eq!(parsed.command(), Some(Cmd::StrRecv));
        assert_eq!(parsed.header.tid(), TID_UNSOLICITED);
        let payload = StreamPayload::parse(parsed.payload).unwrap();
        assert_eq!(payload.data, &[1, 2, 3]);
        let rx_meta = RxMeta::decode(payload.metadata).unwrap();
        assert_eq!(rx_meta.rssi_dbm, Some(-91));
        assert_eq!(rx_meta.snr_cb, Some(-53));
    }

    #[test]
    fn radio_rx_suppressed_while_disabled() {
        let mut session = test_session();
        let mut emitted = Vec::new();
        session.on_radio_rx(&[1, 2, 3], -91, -53, None, 0, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        assert!(emitted.is_empty());
        // Nothing is queued either: the PHY is disabled.
        session.detach();
        session.on_radio_rx(&[1, 2, 3], -91, -53, None, 0, &mut |_: &[u8]| {});
        session.attach(true);
        assert_eq!(
            get(&mut session, prop::HOST_RX_QUEUE_COUNT),
            0u16.to_le_bytes()
        );
    }

    #[test]
    fn unknown_command_rejected() {
        let mut session = test_session();
        let (emitted, _) = dispatch(&mut session, &[0x81, 42], 0);
        expect_status(&emitted[0], 1, Status::INVALID_COMMAND);
    }

    #[test]
    fn insert_remove_reject_per_property_knowledge() {
        let mut session = test_session();
        let mut buf = [0u8; 80];

        // A known single-value property is not insertable/removable.
        for known in [prop::PHY_FREQ, prop::BLE_PAIRING_PIN, prop::CAPS] {
            let len = frame::prop_insert(&mut buf, 1, known, &[0; 4]).unwrap();
            let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
            assert!(effect.is_none());
            expect_status(&emitted[0], 1, Status::INVALID_ARGUMENT);
        }
        // An unknown property is not found. DEV_CHANNEL_KEYS exists in
        // the full spec but this session does not implement it yet.
        for unknown in [prop::DEV_CHANNEL_KEYS, 1_234] {
            let len = frame::prop_remove(&mut buf, 2, unknown, &[0; 4]).unwrap();
            let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::PROP_NOT_FOUND);
        }
        // A payload without a decodable property key is malformed.
        let (emitted, _) = dispatch(&mut session, &[0x81, Cmd::PropInsert as u8], 0);
        expect_status(&emitted[0], 1, Status::PARSE_ERROR);
    }

    #[test]
    fn ungated_full_commands_unimplemented_and_clear_succeeds() {
        let mut session = test_session();
        let mut buf = [0u8; 8];
        for encode in [
            frame::save as fn(&mut [u8], u8) -> Result<usize, frame::WriteError>,
            frame::restore,
        ] {
            let len = encode(&mut buf, 3).unwrap();
            let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
            assert!(effect.is_none());
            expect_status(&emitted[0], 3, Status::UNIMPLEMENTED);
        }

        // CMD_CLEAR is base-protocol and succeeds trivially; it must
        // not disturb live state (the device name survives).
        set(&mut session, prop::DEV_NAME, b"kept name");
        let len = frame::clear(&mut buf, 4).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 4, Status::OK);
        assert_eq!(session.device_name(), "kept name");
    }

    #[test]
    fn ncp_only_notifications_rejected_from_host() {
        let mut session = test_session();
        for cmd in [Cmd::PropInserted, Cmd::PropRemoved, Cmd::PropIs, Cmd::StrRecv] {
            let (emitted, effect) = dispatch(&mut session, &[0x81, cmd as u8], 0);
            assert!(effect.is_none());
            expect_status(&emitted[0], 1, Status::INVALID_COMMAND);
        }
    }

    #[test]
    fn malformed_frames_ignored() {
        let mut session = test_session();
        for bad in [&[][..], &[0x81][..], &[0x00, 0x00][..], &[0xB8, 0x00][..]] {
            let (emitted, effect) = dispatch(&mut session, bad, 0);
            assert!(emitted.is_empty());
            assert!(effect.is_none());
        }
    }

    // ─── CAP_HOST_FILTER gate ────────────────────────────────────────

    use umsh_core::{ChannelId, NodeHint, PacketBuilder};

    fn unicast_to(dst: [u8; 3]) -> Vec<u8> {
        let mut buf = [0u8; 64];
        PacketBuilder::new(&mut buf)
            .unicast(NodeHint(dst))
            .source_hint(NodeHint([9, 9, 9]))
            .frame_counter(1)
            .payload(&[1, 2, 3])
            .build()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn multicast_on(channel: [u8; 2]) -> Vec<u8> {
        let mut buf = [0u8; 64];
        PacketBuilder::new(&mut buf)
            .multicast(ChannelId(channel))
            .source_hint(NodeHint([9, 9, 9]))
            .frame_counter(1)
            .payload(&[1, 2, 3])
            .build()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn blind_unicast_on(channel: [u8; 2]) -> Vec<u8> {
        let mut buf = [0u8; 96];
        PacketBuilder::new(&mut buf)
            .blind_unicast(ChannelId(channel), NodeHint([7, 7, 7]))
            .source_hint(NodeHint([9, 9, 9]))
            .frame_counter(1)
            .payload(&[1, 2, 3])
            .build()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn broadcast_frame() -> Vec<u8> {
        let mut buf = [0u8; 64];
        PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([9, 9, 9]))
            .payload(&[1, 2, 3])
            .build()
            .unwrap()
            .to_vec()
    }

    fn mac_ack_to(dst: [u8; 3]) -> Vec<u8> {
        let mut buf = [0u8; 32];
        PacketBuilder::new(&mut buf)
            .mac_ack(NodeHint(dst), [0xA5; 8])
            .build()
            .unwrap()
            .to_vec()
    }

    /// Feed a radio frame in and report whether it was delivered.
    fn delivered(session: &mut TestSession, frame: &[u8]) -> bool {
        delivered_at(session, frame, 0)
    }

    fn delivered_at(session: &mut TestSession, frame: &[u8], now_ms: u64) -> bool {
        let mut emitted = Vec::new();
        session.on_radio_rx(frame, -80, 40, None, now_ms, &mut |bytes: &[u8]| {
            emitted.push(bytes.to_vec())
        });
        !emitted.is_empty()
    }

    fn insert_item(session: &mut TestSession, key: u32, item: &[u8]) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 96];
        let len = frame::prop_insert(&mut buf, 5, key, item).unwrap();
        dispatch(session, &buf[..len], 0)
    }

    fn remove_item(session: &mut TestSession, key: u32, item: &[u8]) -> (Vec<Vec<u8>>, Option<Effect>) {
        let mut buf = [0u8; 96];
        let len = frame::prop_remove(&mut buf, 6, key, item).unwrap();
        dispatch(session, &buf[..len], 0)
    }

    /// Install a host key, completing the deferred durable wipe.
    fn install_host_key(session: &mut TestSession, key: &[u8; 32]) {
        let (emitted, effect) = set(session, prop::HOST_KEY, key);
        assert!(emitted.is_empty(), "no response before the wipe completes");
        assert_eq!(effect, Some(Effect::WipeHostDomain { tid: 2 }));
        let mut emitted = Vec::new();
        session.respond_host_wipe(2, Ok(()), &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        let (_, response_key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(response_key, prop::HOST_KEY);
        assert_eq!(value, key);
    }

    /// Parse an emitted frame as INSERTED/REMOVED and return (key, digest).
    fn parse_table_notice(bytes: &[u8], expected: Cmd, tid: u8) -> (u32, Vec<u8>) {
        let parsed = Frame::parse(bytes).unwrap();
        assert_eq!(parsed.command(), Some(expected));
        assert_eq!(parsed.header.tid(), tid);
        let payload = PropPayload::parse(parsed.payload).unwrap();
        (payload.key, payload.value.to_vec())
    }

    #[test]
    fn factory_state_accepts_everything() {
        let mut session = test_session();
        enable(&mut session);
        // No host key, no filters: minimal-protocol behavior, including
        // frames that do not parse as UMSH at all.
        assert!(delivered(&mut session, &unicast_to([1, 2, 3])));
        assert!(delivered(&mut session, &broadcast_frame()));
        assert!(delivered(&mut session, &[0x00, 0x01, 0x02]));
    }

    #[test]
    fn host_key_round_trip_and_implicit_dest_filter() {
        let mut session = test_session();
        enable(&mut session);
        assert_eq!(get(&mut session, prop::HOST_KEY), Vec::<u8>::new());

        let key = [0xC4; 32];
        install_host_key(&mut session, &key);
        assert_eq!(get(&mut session, prop::HOST_KEY), key);

        // The implicit destination-hint filter: traffic to the host's
        // 3-byte prefix (unicast and returning MAC acks) is accepted,
        // everything else — including unparseable frames — is not.
        assert!(delivered(&mut session, &unicast_to([0xC4, 0xC4, 0xC4])));
        assert!(delivered(&mut session, &mac_ack_to([0xC4, 0xC4, 0xC4])));
        assert!(!delivered(&mut session, &unicast_to([1, 2, 3])));
        assert!(!delivered(&mut session, &broadcast_frame()));
        assert!(!delivered(&mut session, &[0x00, 0x01, 0x02]));
    }

    #[test]
    fn host_key_rejects_bad_lengths() {
        let mut session = test_session();
        for bad in [&[0u8; 31][..], &[0u8; 33][..], &[1u8][..]] {
            let (emitted, effect) = set(&mut session, prop::HOST_KEY, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn host_key_set_is_idempotent_for_current_value() {
        let mut session = test_session();
        // Empty -> empty: no replacement, immediate echo.
        let (emitted, effect) = set(&mut session, prop::HOST_KEY, &[]);
        assert!(effect.is_none());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::HOST_KEY);
        assert!(value.is_empty());

        let host_key = [0xC4; 32];
        install_host_key(&mut session, &host_key);
        insert_item(&mut session, prop::HOST_RX_FILTERS, &[items::FILTER_PKT_TYPE, 0]);

        // Same key again: no wipe, and the filter table survives.
        let (emitted, effect) = set(&mut session, prop::HOST_KEY, &host_key);
        assert!(effect.is_none());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::HOST_KEY);
        assert_eq!(value, host_key);
        assert!(!get(&mut session, prop::HOST_RX_FILTERS).is_empty());
    }

    #[test]
    fn host_replacement_clears_host_domain_and_rolls_back_on_failure() {
        let mut session = test_session();
        install_host_key(&mut session, &[0xAA; 32]);
        insert_item(&mut session, prop::HOST_RX_FILTERS, &[items::FILTER_PKT_TYPE, 0]);

        // A failed durable wipe leaves the old host domain fully in
        // effect and the new key not installed.
        let (emitted, effect) = set(&mut session, prop::HOST_KEY, &[0xBB; 32]);
        assert!(emitted.is_empty());
        assert_eq!(effect, Some(Effect::WipeHostDomain { tid: 2 }));
        let mut emitted = Vec::new();
        session.respond_host_wipe(2, Err(()), &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        expect_status(&emitted[0], 2, Status::FAILURE);
        assert_eq!(get(&mut session, prop::HOST_KEY), [0xAA; 32]);
        assert!(!get(&mut session, prop::HOST_RX_FILTERS).is_empty());

        // A successful replacement installs the new key and resets the
        // host domain as one unit.
        install_host_key(&mut session, &[0xBB; 32]);
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());

        // Clearing the key (set to empty) is also a replacement.
        insert_item(&mut session, prop::HOST_RX_FILTERS, &[items::FILTER_PKT_TYPE, 0]);
        let (_, effect) = set(&mut session, prop::HOST_KEY, &[]);
        assert_eq!(effect, Some(Effect::WipeHostDomain { tid: 2 }));
        session.respond_host_wipe(2, Ok(()), &mut |_: &[u8]| {});
        assert_eq!(get(&mut session, prop::HOST_KEY), Vec::<u8>::new());
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());
    }

    #[test]
    fn host_replacement_is_busy_while_pending_and_abandoned_by_attach() {
        let mut session = test_session();
        let (_, effect) = set(&mut session, prop::HOST_KEY, &[0xAA; 32]);
        assert_eq!(effect, Some(Effect::WipeHostDomain { tid: 2 }));

        // A second replacement while one is in flight is BUSY.
        let (emitted, effect) = set(&mut session, prop::HOST_KEY, &[0xBB; 32]);
        assert!(effect.is_none());
        expect_status(&emitted[0], 2, Status::BUSY);

        // Attach discards the pending transaction: a late wipe
        // completion must not install the key into the new session.
        session.attach(true);
        let mut emitted = Vec::new();
        session.respond_host_wipe(2, Ok(()), &mut |bytes: &[u8]| emitted.push(bytes.to_vec()));
        assert!(emitted.is_empty());
        assert_eq!(get(&mut session, prop::HOST_KEY), Vec::<u8>::new());
    }

    #[test]
    fn cmd_rst_clears_host_domain() {
        let mut session = test_session();
        install_host_key(&mut session, &[0xAA; 32]);
        insert_item(&mut session, prop::HOST_RX_FILTERS, &[items::FILTER_PKT_TYPE, 0]);
        let _ = session.reset(Status::RESET_SOFTWARE, &mut |_| {});
        assert_eq!(get(&mut session, prop::HOST_KEY), Vec::<u8>::new());
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());
    }

    #[test]
    fn filter_insert_remove_lifecycle() {
        let mut session = test_session();
        let item = [items::FILTER_DEST_HINT, 0x11, 0x22, 0x33];

        let (emitted, effect) = insert_item(&mut session, prop::HOST_RX_FILTERS, &item);
        assert!(effect.is_none());
        let (key, digest) = parse_table_notice(&emitted[0], Cmd::PropInserted, 5);
        assert_eq!(key, prop::HOST_RX_FILTERS);
        assert_eq!(digest, item);

        // Duplicate insert fails with ALREADY.
        let (emitted, _) = insert_item(&mut session, prop::HOST_RX_FILTERS, &item);
        expect_status(&emitted[0], 5, Status::ALREADY);

        // GET returns the whole table with item length prefixes.
        let table = get(&mut session, prop::HOST_RX_FILTERS);
        assert_eq!(table, [&[4u8][..], &item[..]].concat());

        let (emitted, _) = remove_item(&mut session, prop::HOST_RX_FILTERS, &item);
        let (key, digest) = parse_table_notice(&emitted[0], Cmd::PropRemoved, 6);
        assert_eq!(key, prop::HOST_RX_FILTERS);
        assert_eq!(digest, item);
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());

        // Removing a missing item fails with ITEM_NOT_FOUND.
        let (emitted, _) = remove_item(&mut session, prop::HOST_RX_FILTERS, &item);
        expect_status(&emitted[0], 6, Status::ITEM_NOT_FOUND);
    }

    #[test]
    fn filter_insert_rejects_invalid_entries() {
        let mut session = test_session();
        for bad in [
            &[][..],                                  // empty item
            &[3, 0][..],                              // unknown FILTER_TYPE
            &[items::FILTER_DEST_HINT, 1, 2][..],     // wrong value length
            &[items::FILTER_CHANNEL_ID, 1, 2, 3][..], // wrong value length
            &[items::FILTER_PKT_TYPE, 8][..],         // packet type out of range
        ] {
            let (emitted, effect) = insert_item(&mut session, prop::HOST_RX_FILTERS, bad);
            assert!(effect.is_none());
            expect_status(&emitted[0], 5, Status::INVALID_ARGUMENT);
        }
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());
    }

    #[test]
    fn filter_table_capacity_is_bounded() {
        let mut session = test_session();
        for index in 0..MAX_RX_FILTERS as u8 {
            let (emitted, _) = insert_item(
                &mut session,
                prop::HOST_RX_FILTERS,
                &[items::FILTER_DEST_HINT, index, 0, 0],
            );
            parse_table_notice(&emitted[0], Cmd::PropInserted, 5);
        }
        let (emitted, _) = insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_DEST_HINT, 0xFF, 0, 0],
        );
        expect_status(&emitted[0], 5, Status::NOMEM);
    }

    #[test]
    fn whole_table_set_is_atomic() {
        let mut session = test_session();
        let good_a = [items::FILTER_DEST_HINT, 1, 2, 3];
        let good_b = [items::FILTER_PKT_TYPE, 0];

        let mut table = Vec::new();
        for item in [&good_a[..], &good_b[..]] {
            table.push(item.len() as u8);
            table.extend_from_slice(item);
        }
        let (emitted, effect) = set(&mut session, prop::HOST_RX_FILTERS, &table);
        assert!(effect.is_none());
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::HOST_RX_FILTERS);
        assert_eq!(value, table);

        // A set containing any invalid item fails without applying
        // anything: the previous table is fully retained.
        let mut bad_table = table.clone();
        bad_table.extend_from_slice(&[2, 3, 0]); // unknown FILTER_TYPE 3
        let (emitted, _) = set(&mut session, prop::HOST_RX_FILTERS, &bad_table);
        expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        assert_eq!(get(&mut session, prop::HOST_RX_FILTERS), table);

        // A value that cannot be split into items is malformed.
        let (emitted, _) = set(&mut session, prop::HOST_RX_FILTERS, &[9, 1]);
        expect_status(&emitted[0], 2, Status::PARSE_ERROR);
        assert_eq!(get(&mut session, prop::HOST_RX_FILTERS), table);

        // Duplicates in the value collapse (a set, not a list).
        let mut doubled = table.clone();
        doubled.extend_from_slice(&table);
        let (emitted, _) = set(&mut session, prop::HOST_RX_FILTERS, &doubled);
        let (_, _, value) = parse_prop_is(&emitted[0]);
        assert_eq!(value, table);

        // Setting an empty value clears the table.
        let (emitted, _) = set(&mut session, prop::HOST_RX_FILTERS, &[]);
        let (_, _, value) = parse_prop_is(&emitted[0]);
        assert!(value.is_empty());
        assert!(get(&mut session, prop::HOST_RX_FILTERS).is_empty());
    }

    #[test]
    fn explicit_filters_match_each_type() {
        let mut session = test_session();
        enable(&mut session);

        // Destination-hint filter.
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_DEST_HINT, 0x11, 0x22, 0x33],
        );
        assert!(delivered(&mut session, &unicast_to([0x11, 0x22, 0x33])));
        assert!(delivered(&mut session, &mac_ack_to([0x11, 0x22, 0x33])));
        assert!(!delivered(&mut session, &unicast_to([4, 5, 6])));
        assert!(!delivered(&mut session, &broadcast_frame()));

        // Channel filter: matches multicast and blind unicast on the
        // channel (a blind unicast's destination hint is concealed).
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_CHANNEL_ID, 0xAB, 0xCD],
        );
        assert!(delivered(&mut session, &multicast_on([0xAB, 0xCD])));
        assert!(delivered(&mut session, &blind_unicast_on([0xAB, 0xCD])));
        assert!(!delivered(&mut session, &multicast_on([0x00, 0x01])));

        // Packet-type filter (broadcasts must be requested explicitly).
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_PKT_TYPE, 0],
        );
        assert!(delivered(&mut session, &broadcast_frame()));
        // Still rejects frames matching no filter.
        assert!(!delivered(&mut session, &unicast_to([4, 5, 6])));
        assert!(!delivered(&mut session, &[0x00, 0x01, 0x02]));
    }

    #[test]
    fn promiscuous_bypasses_filtering_for_live_delivery() {
        let mut session = test_session();
        enable(&mut session);
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_DEST_HINT, 0x11, 0x22, 0x33],
        );
        assert!(!delivered(&mut session, &unicast_to([4, 5, 6])));

        set(&mut session, prop::MAC_PROMISCUOUS, &[1]);
        assert!(delivered(&mut session, &unicast_to([4, 5, 6])));
        assert!(delivered(&mut session, &[0x00, 0x01, 0x02]));

        // Attach reverts promiscuous mode; filtering applies again.
        session.attach(true);
        assert!(!delivered(&mut session, &unicast_to([4, 5, 6])));
    }

    #[test]
    fn filters_survive_attach() {
        let mut session = test_session();
        enable(&mut session);
        install_host_key(&mut session, &[0xC4; 32]);
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_PKT_TYPE, 0],
        );
        session.attach(true);
        assert_eq!(get(&mut session, prop::HOST_KEY), [0xC4; 32]);
        assert!(delivered(&mut session, &broadcast_frame()));
        assert!(delivered(&mut session, &unicast_to([0xC4, 0xC4, 0xC4])));
        assert!(!delivered(&mut session, &unicast_to([1, 2, 3])));
    }

    #[test]
    fn host_key_insert_remove_is_invalid_argument() {
        let mut session = test_session();
        let (emitted, _) = insert_item(&mut session, prop::HOST_KEY, &[0; 32]);
        expect_status(&emitted[0], 5, Status::INVALID_ARGUMENT);
        let (emitted, _) = remove_item(&mut session, prop::HOST_KEY, &[0; 32]);
        expect_status(&emitted[0], 6, Status::INVALID_ARGUMENT);
    }

    // ─── CAP_HOST_RX_QUEUE gate ──────────────────────────────────────

    /// Feed a frame while detached at `now_ms` (asserting it is not
    /// delivered live).
    fn receive_detached(session: &mut TestSession, frame: &[u8], now_ms: u64) {
        assert!(!delivered_at(session, frame, now_ms));
    }

    fn queue_count(session: &mut TestSession) -> u16 {
        let raw = get(session, prop::HOST_RX_QUEUE_COUNT);
        u16::from_le_bytes([raw[0], raw[1]])
    }

    /// Issue CMD_QUEUE_DRAIN and run it to completion, returning the
    /// drained (frame, metadata) pairs. Asserts correct completion.
    fn drain(session: &mut TestSession, now_ms: u64) -> Vec<(Vec<u8>, BufferedRxMeta)> {
        let mut buf = [0u8; 4];
        let len = frame::queue_drain(&mut buf, 7).unwrap();
        let (emitted, effect) = dispatch(session, &buf[..len], now_ms);
        if effect.is_none() {
            // Empty queue: immediate success, nothing drained.
            expect_status(&emitted[0], 7, Status::OK);
            return Vec::new();
        }
        assert_eq!(effect, Some(Effect::DrainQueue));
        assert!(emitted.is_empty());
        let mut steps = Vec::new();
        loop {
            let mut emitted = Vec::new();
            let more = session.drain_step(now_ms, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
            assert_eq!(emitted.len(), 1, "each step emits exactly one frame");
            if !more {
                expect_status(&emitted[0], 7, Status::OK);
                return steps;
            }
            let parsed = Frame::parse(&emitted[0]).unwrap();
            assert_eq!(parsed.command(), Some(Cmd::StrRecv));
            let payload = StreamPayload::parse(parsed.payload).unwrap();
            steps.push((
                payload.data.to_vec(),
                BufferedRxMeta::decode(payload.metadata).unwrap(),
            ));
        }
    }

    #[test]
    fn detached_receive_then_attach_count_drain() {
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        receive_detached(&mut session, &unicast_to([1, 2, 3]), 1_000);
        receive_detached(&mut session, &broadcast_frame(), 3_000);

        // Attach does not flush the queue; live delivery resumes while
        // the backlog waits for an explicit drain.
        session.attach(true);
        assert_eq!(queue_count(&mut session), 2);
        assert!(delivered(&mut session, &unicast_to([7, 7, 7])));
        assert_eq!(queue_count(&mut session), 2);

        let drained = drain(&mut session, 8_000);
        assert_eq!(drained.len(), 2);
        // Oldest first, with buffered metadata: flags, one-second age
        // granularity, and the recorded RSSI/SNR.
        assert_eq!(drained[0].0, unicast_to([1, 2, 3]));
        assert_eq!(drained[1].0, broadcast_frame());
        for (_, meta) in &drained {
            assert_eq!(meta.flags, RX_FLAG_BUFFERED);
            assert_eq!(meta.rx.rssi_dbm, Some(-80));
            assert_eq!(meta.rx.snr_cb, Some(40));
        }
        assert_eq!((drained[0].1.age_s, drained[1].1.age_s), (7, 5));

        assert_eq!(queue_count(&mut session), 0);
        // Draining an empty queue succeeds immediately.
        assert!(drain(&mut session, 9_000).is_empty());
    }

    #[test]
    fn queue_overflow_evicts_oldest_and_counts_dropped() {
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        // Overfill by three: the queue keeps the most recent traffic.
        for index in 0..(RX_QUEUE_CAPACITY + 3) as u8 {
            receive_detached(&mut session, &unicast_to([index, 0, 0]), 0);
        }
        session.attach(true);
        assert_eq!(queue_count(&mut session), RX_QUEUE_CAPACITY as u16);
        assert_eq!(
            get(&mut session, prop::HOST_RX_QUEUE_DROPPED),
            3u32.to_le_bytes()
        );
        let drained = drain(&mut session, 0);
        assert_eq!(drained[0].0, unicast_to([3, 0, 0]));
        assert_eq!(
            drained.last().unwrap().0,
            unicast_to([(RX_QUEUE_CAPACITY + 2) as u8, 0, 0])
        );
    }

    #[test]
    fn queue_respects_receive_filtering() {
        let mut session = test_session();
        enable(&mut session);
        insert_item(
            &mut session,
            prop::HOST_RX_FILTERS,
            &[items::FILTER_DEST_HINT, 0x11, 0x22, 0x33],
        );
        session.detach();
        receive_detached(&mut session, &unicast_to([0x11, 0x22, 0x33]), 0);
        receive_detached(&mut session, &unicast_to([4, 5, 6]), 0); // rejected
        receive_detached(&mut session, &[0xFF, 0xFE], 0); // unparseable
        session.attach(true);
        assert_eq!(queue_count(&mut session), 1);
    }

    #[test]
    fn unauthenticated_duplicates_occupy_separate_entries() {
        // No keys are provisioned before CAP_HOST_KEYS, so no
        // protocol-defined duplicate detection applies.
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        let frame = unicast_to([1, 2, 3]);
        receive_detached(&mut session, &frame, 0);
        receive_detached(&mut session, &frame, 0);
        session.attach(true);
        assert_eq!(queue_count(&mut session), 2);
    }

    #[test]
    fn live_arrivals_interleave_with_a_drain() {
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        receive_detached(&mut session, &unicast_to([1, 0, 0]), 0);
        receive_detached(&mut session, &unicast_to([2, 0, 0]), 0);
        session.attach(true);

        let mut buf = [0u8; 4];
        let len = frame::queue_drain(&mut buf, 7).unwrap();
        let (_, effect) = dispatch(&mut session, &buf[..len], 10_000);
        assert_eq!(effect, Some(Effect::DrainQueue));

        // First covered frame.
        let mut emitted = Vec::new();
        assert!(session.drain_step(10_000, &mut |bytes: &[u8]| emitted.push(bytes.to_vec())));

        // A live arrival mid-drain is delivered immediately and is not
        // part of the covered set.
        assert!(delivered_at(&mut session, &unicast_to([3, 0, 0]), 10_000));

        // The drain still covers exactly the original two frames.
        let mut frames = 0;
        loop {
            let mut emitted = Vec::new();
            let more = session.drain_step(10_000, &mut |bytes: &[u8]| {
                emitted.push(bytes.to_vec())
            });
            if !more {
                expect_status(&emitted[0], 7, Status::OK);
                break;
            }
            frames += 1;
        }
        assert_eq!(frames, 1);
        assert_eq!(queue_count(&mut session), 0);
    }

    #[test]
    fn second_drain_while_in_progress_is_busy() {
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        receive_detached(&mut session, &unicast_to([1, 0, 0]), 0);
        session.attach(true);

        let mut buf = [0u8; 4];
        let len = frame::queue_drain(&mut buf, 7).unwrap();
        let (_, effect) = dispatch(&mut session, &buf[..len], 0);
        assert_eq!(effect, Some(Effect::DrainQueue));

        let len = frame::queue_drain(&mut buf, 6).unwrap();
        let (emitted, effect) = dispatch(&mut session, &buf[..len], 0);
        assert!(effect.is_none());
        expect_status(&emitted[0], 6, Status::BUSY);
    }

    #[test]
    fn reset_and_host_replacement_discard_the_queue() {
        let mut session = test_session();
        enable(&mut session);
        session.detach();
        for _ in 0..(RX_QUEUE_CAPACITY + 1) {
            receive_detached(&mut session, &unicast_to([1, 2, 3]), 0);
        }
        session.attach(true);
        assert_ne!(queue_count(&mut session), 0);

        // Host replacement discards the queue and its counters as part
        // of the host domain.
        install_host_key(&mut session, &[0xAA; 32]);
        assert_eq!(queue_count(&mut session), 0);
        assert_eq!(
            get(&mut session, prop::HOST_RX_QUEUE_DROPPED),
            0u32.to_le_bytes()
        );

        // CMD_RST does too. (Refill first; the host key now filters, so
        // address the host.)
        enable(&mut session);
        session.detach();
        receive_detached(&mut session, &unicast_to([0xAA, 0xAA, 0xAA]), 0);
        session.attach(true);
        assert_eq!(queue_count(&mut session), 1);
        let _ = session.reset(Status::RESET_SOFTWARE, &mut |_| {});
        assert_eq!(queue_count(&mut session), 0);
    }

    // ─── CAP_HOST_KEYS gate ──────────────────────────────────────────

    /// Insert a channel key, returning its derived identifier digest.
    fn install_channel_key(session: &mut TestSession, key: &[u8; 32]) -> [u8; 2] {
        let (emitted, effect) = insert_item(session, prop::HOST_CHANNEL_KEYS, key);
        assert!(effect.is_none());
        let (prop_key, digest) = parse_table_notice(&emitted[0], Cmd::PropInserted, 5);
        assert_eq!(prop_key, prop::HOST_CHANNEL_KEYS);
        digest.try_into().expect("channel digest is 2 bytes")
    }

    fn peer_entry(seed: u8) -> [u8; 64] {
        let mut item = [0u8; 64];
        item[..32].fill(seed);
        item[32..48].fill(0xE0 | (seed & 0x0F));
        item[48..].fill(0x50 | (seed & 0x0F));
        item
    }

    #[test]
    fn channel_key_lifecycle_and_digest_is_derived_id() {
        let mut session = test_session();
        let key = [0x42; 32];
        let expected_id = test_engine().derive_channel_id(&ChannelKey(key)).0;

        let digest = install_channel_key(&mut session, &key);
        assert_eq!(digest, expected_id);
        assert_eq!(get(&mut session, prop::HOST_CHANNEL_KEYS), expected_id);

        // Duplicate channel key fails with ALREADY.
        let (emitted, _) = insert_item(&mut session, prop::HOST_CHANNEL_KEYS, &key);
        expect_status(&emitted[0], 5, Status::ALREADY);

        // Remove selector is the key; the digest reported is the id.
        let (emitted, _) = remove_item(&mut session, prop::HOST_CHANNEL_KEYS, &key);
        let (_, digest) = parse_table_notice(&emitted[0], Cmd::PropRemoved, 6);
        assert_eq!(digest, expected_id);
        assert!(get(&mut session, prop::HOST_CHANNEL_KEYS).is_empty());

        let (emitted, _) = remove_item(&mut session, prop::HOST_CHANNEL_KEYS, &key);
        expect_status(&emitted[0], 6, Status::ITEM_NOT_FOUND);

        // Wrong-size items are invalid.
        for bad in [&[0u8; 31][..], &[0u8; 33][..], &[][..]] {
            let (emitted, _) = insert_item(&mut session, prop::HOST_CHANNEL_KEYS, bad);
            expect_status(&emitted[0], 5, Status::INVALID_ARGUMENT);
        }
    }

    #[test]
    fn channel_key_capacity_is_bounded() {
        let mut session = test_session();
        for seed in 0..MAX_CHANNEL_KEYS as u8 {
            install_channel_key(&mut session, &[seed; 32]);
        }
        let (emitted, _) =
            insert_item(&mut session, prop::HOST_CHANNEL_KEYS, &[0xFF; 32]);
        expect_status(&emitted[0], 5, Status::NOMEM);
    }

    #[test]
    fn peer_key_lifecycle_replacement_and_secret_free_digests() {
        let mut session = test_session();
        let entry = peer_entry(0xA1);

        let (emitted, _) = insert_item(&mut session, prop::HOST_PEER_KEYS, &entry);
        let (_, digest) = parse_table_notice(&emitted[0], Cmd::PropInserted, 5);
        assert_eq!(digest, entry[..32]);
        // No emitted frame may carry the pairwise key material.
        for frame in &emitted {
            assert!(!frame.windows(16).any(|window| window == &entry[32..48]));
            assert!(!frame.windows(16).any(|window| window == &entry[48..]));
        }

        // GET reports public keys only.
        assert_eq!(get(&mut session, prop::HOST_PEER_KEYS), entry[..32]);

        // Inserting the same public key with new key material replaces
        // the entry (never ALREADY) and does not grow the table.
        let mut replacement = entry;
        replacement[32..].fill(0x77);
        let (emitted, _) = insert_item(&mut session, prop::HOST_PEER_KEYS, &replacement);
        let (_, digest) = parse_table_notice(&emitted[0], Cmd::PropInserted, 5);
        assert_eq!(digest, entry[..32]);
        assert_eq!(get(&mut session, prop::HOST_PEER_KEYS), entry[..32]);

        // Remove selector is the public key.
        let (emitted, _) = remove_item(&mut session, prop::HOST_PEER_KEYS, &entry[..32]);
        let (_, digest) = parse_table_notice(&emitted[0], Cmd::PropRemoved, 6);
        assert_eq!(digest, entry[..32]);
        assert!(get(&mut session, prop::HOST_PEER_KEYS).is_empty());

        let (emitted, _) = remove_item(&mut session, prop::HOST_PEER_KEYS, &entry[..32]);
        expect_status(&emitted[0], 6, Status::ITEM_NOT_FOUND);

        // Malformed entries are invalid.
        let (emitted, _) = insert_item(&mut session, prop::HOST_PEER_KEYS, &entry[..63]);
        expect_status(&emitted[0], 5, Status::INVALID_ARGUMENT);
    }

    #[test]
    fn key_table_whole_set_is_atomic_and_collapses_duplicates() {
        let mut session = test_session();

        // Channels: duplicates collapse; a short trailing item fails
        // the whole set, leaving the table unchanged.
        let key_a = [0xA0; 32];
        let key_b = [0xB0; 32];
        let mut table = Vec::new();
        table.extend_from_slice(&key_a);
        table.extend_from_slice(&key_b);
        table.extend_from_slice(&key_a);
        let (emitted, _) = set(&mut session, prop::HOST_CHANNEL_KEYS, &table);
        let (_, key, value) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::HOST_CHANNEL_KEYS);
        assert_eq!(value.len(), 4, "two unique channels, 2-byte ids");

        let (emitted, _) = set(&mut session, prop::HOST_CHANNEL_KEYS, &table[..40]);
        expect_status(&emitted[0], 2, Status::INVALID_ARGUMENT);
        assert_eq!(get(&mut session, prop::HOST_CHANNEL_KEYS).len(), 4);

        // Peers: a repeated public key replaces the earlier entry.
        let mut peers = Vec::new();
        peers.extend_from_slice(&peer_entry(0x01));
        let mut updated = peer_entry(0x01);
        updated[32..].fill(0x99);
        peers.extend_from_slice(&updated);
        let (emitted, _) = set(&mut session, prop::HOST_PEER_KEYS, &peers);
        let (_, _, value) = parse_prop_is(&emitted[0]);
        assert_eq!(value, peer_entry(0x01)[..32], "one entry, digest form");

        // Empty set clears; oversized set fails atomically.
        let (emitted, _) = set(&mut session, prop::HOST_PEER_KEYS, &[]);
        let (_, _, value) = parse_prop_is(&emitted[0]);
        assert!(value.is_empty());
        let mut oversized = Vec::new();
        for seed in 0..(MAX_PEER_KEYS + 1) as u8 {
            oversized.extend_from_slice(&peer_entry(seed));
        }
        let (emitted, _) = set(&mut session, prop::HOST_PEER_KEYS, &oversized);
        expect_status(&emitted[0], 2, Status::NOMEM);
        assert!(get(&mut session, prop::HOST_PEER_KEYS).is_empty());
    }

    #[test]
    fn insecure_transport_refuses_key_writes() {
        let mut session = test_session();
        session.attach(false); // e.g. a bare UART with no possession story

        for (key, item) in [
            (prop::HOST_CHANNEL_KEYS, &[0x42u8; 32][..]),
            (prop::HOST_PEER_KEYS, &peer_entry(0x01)[..]),
        ] {
            let (emitted, effect) = set(&mut session, key, item);
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, Status::INVALID_STATE);
            let (emitted, _) = insert_item(&mut session, key, item);
            expect_status(&emitted[0], 5, Status::INVALID_STATE);
            assert!(get(&mut session, key).is_empty(), "table must stay empty");
        }

        // Non-key properties are unaffected by the gate.
        let (emitted, _) = set(&mut session, prop::PHY_DUTY_LIMIT, &100u16.to_le_bytes());
        let (_, key, _) = parse_prop_is(&emitted[0]);
        assert_eq!(key, prop::PHY_DUTY_LIMIT);

        // Re-attaching over a secure transport unlocks provisioning.
        session.attach(true);
        install_channel_key(&mut session, &[0x42; 32]);
    }

    #[test]
    fn provisioned_channel_id_is_an_implicit_filter() {
        let mut session = test_session();
        enable(&mut session);
        // Only a channel key is provisioned: filtering becomes
        // configured (compatibility rule) and the derived id matches
        // multicast and blind unicast on that channel.
        let id = install_channel_key(&mut session, &[0x42; 32]);
        assert!(delivered(&mut session, &multicast_on(id)));
        assert!(delivered(&mut session, &blind_unicast_on(id)));
        let other = [id[0] ^ 0xFF, id[1]];
        assert!(!delivered(&mut session, &multicast_on(other)));
        assert!(!delivered(&mut session, &broadcast_frame()));
        assert!(!delivered(&mut session, &[0x00, 0x01, 0x02]));

        // Detached queueing honors the same implicit filter.
        session.detach();
        receive_detached(&mut session, &multicast_on(id), 0);
        receive_detached(&mut session, &multicast_on(other), 0);
        session.attach(true);
        assert_eq!(queue_count(&mut session), 1);
    }

    #[test]
    fn host_replacement_clears_key_tables() {
        let mut session = test_session();
        install_channel_key(&mut session, &[0x42; 32]);
        insert_item(&mut session, prop::HOST_PEER_KEYS, &peer_entry(0x01));

        install_host_key(&mut session, &[0xAA; 32]);
        assert!(get(&mut session, prop::HOST_CHANNEL_KEYS).is_empty());
        assert!(get(&mut session, prop::HOST_PEER_KEYS).is_empty());

        // CMD_RST clears them too.
        install_channel_key(&mut session, &[0x42; 32]);
        let _ = session.reset(Status::RESET_SOFTWARE, &mut |_| {});
        assert!(get(&mut session, prop::HOST_CHANNEL_KEYS).is_empty());
    }

    #[test]
    fn queue_properties_are_read_only_and_capacity_fixed() {
        let mut session = test_session();
        assert_eq!(
            get(&mut session, prop::HOST_RX_QUEUE_CAPACITY),
            (RX_QUEUE_CAPACITY as u16).to_le_bytes()
        );
        for (key, status) in [
            (prop::HOST_RX_QUEUE_COUNT, Status::INVALID_ARGUMENT),
            (prop::HOST_RX_QUEUE_DROPPED, Status::INVALID_ARGUMENT),
            (prop::HOST_RX_QUEUE_CAPACITY, Status::UNIMPLEMENTED),
        ] {
            let (emitted, effect) = set(&mut session, key, &0u16.to_le_bytes());
            assert!(effect.is_none());
            expect_status(&emitted[0], 2, status);
        }
    }
}
