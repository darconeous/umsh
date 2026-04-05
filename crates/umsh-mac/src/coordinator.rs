use core::{future::poll_fn, task::Poll};

use hamaddr::HamAddr;
use heapless::{LinearMap, Vec};
use rand::{Rng, RngExt as _};
use umsh_core::{
    BuildError, ChannelId, ChannelKey, NodeHint, OptionNumber, PacketBuilder, PacketHeader,
    PacketType, ParseError, ParsedOptions, PublicKey, RouterHint, SourceAddrRef, UnsealedPacket,
    feed_aad, options::OptionEncoder,
};
use umsh_crypto::{
    CmacState, CryptoEngine, CryptoError, DerivedChannelKeys, NodeIdentity, PairwiseKeys,
};
use umsh_hal::{Clock, CounterStore, Radio, RxInfo, TxError, TxOptions};

use crate::{
    CapacityError, DEFAULT_ACKS, DEFAULT_CHANNELS, DEFAULT_DUP, DEFAULT_IDENTITIES, DEFAULT_PEERS,
    DEFAULT_TX, MAX_CAD_ATTEMPTS, MAX_FORWARD_RETRIES, MAX_RESEND_FRAME_LEN, Platform,
    ReplayVerdict, ReplayWindow,
    cache::{DupCacheKey, DuplicateCache},
    peers::{ChannelTable, PeerCryptoMap, PeerCryptoState, PeerId, PeerRegistry},
    send::{
        PendingAck, PendingAckError, ResendRecord, SendOptions, SendReceipt, TxPriority, TxQueue,
    },
};

const COUNTER_PERSIST_BLOCK_SIZE: u32 = 128;
const COUNTER_PERSIST_BLOCK_MASK: u32 = COUNTER_PERSIST_BLOCK_SIZE - 1;
const COUNTER_PERSIST_SCHEDULE_OFFSET: u32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PostTxListen {
    identity_id: LocalIdentityId,
    receipt: SendReceipt,
    confirm_key: DupCacheKey,
    deadline_ms: u64,
}

/// Opaque handle that identifies a locally registered identity within the [`Mac`] coordinator.
///
/// Every UMSH node presents one or more Ed25519 public keys to the network. When a key is
/// registered via [`Mac::add_identity`] (or [`Mac::register_ephemeral`] for PFS sessions),
/// the coordinator allocates a slot and returns a `LocalIdentityId` that permanently names it.
///
/// The inner `u8` is a stable zero-based slot index — slot `0` is the first identity
/// registered, slot `1` the second, and so on. All per-identity coordinator operations
/// (`queue_unicast`, `queue_multicast`, ACK tracking, key installation, frame-counter
/// persistence) accept a `LocalIdentityId` to select which local keypair to use, allowing a
/// single coordinator instance to operate multiple identities simultaneously — for example, a
/// persistent long-term identity alongside an ephemeral PFS session identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalIdentityId(pub u8);

/// A local node identity that the [`Mac`] coordinator owns and acts on behalf of.
///
/// UMSH nodes are identified by Ed25519 public keys. An identity provides the public key and
/// the ability to derive pairwise keys via ECDH with the corresponding private key.
/// Two variants are supported:
///
/// - **`LongTerm(I)`** — wraps the platform-supplied `I: NodeIdentity`, which is typically
///   backed by secure-element storage, an HSM, or a platform keystore. Long-term identities
///   persist across reboots; their frame counters are saved to the [`umsh_hal::CounterStore`]
///   so that replay protection remains valid after a power cycle.
///
/// - **`Ephemeral`** — wraps an in-memory [`SoftwareIdentity`](umsh_crypto::software::SoftwareIdentity)
///   generated fresh at runtime for Perfect Forward Secrecy sessions. Because the key material
///   itself vanishes on power loss, ephemeral identities do not persist their frame counters;
///   replay protection is meaningful only within a single session. Requires the
///   `software-crypto` crate feature.
///
/// Use [`LocalIdentity::public_key`] or [`LocalIdentity::hint`] to inspect the address
/// presented to the network without matching on the variant.
pub enum LocalIdentity<I: NodeIdentity> {
    /// Long-term platform identity.
    LongTerm(I),
    #[cfg(feature = "software-crypto")]
    /// Software ephemeral identity used for PFS sessions.
    Ephemeral(umsh_crypto::software::SoftwareIdentity),
}

impl<I: NodeIdentity> LocalIdentity<I> {
    /// Return the public key for this identity.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::LongTerm(identity) => identity.public_key(),
            #[cfg(feature = "software-crypto")]
            Self::Ephemeral(identity) => identity.public_key(),
        }
    }

    /// Return the derived node hint for this identity.
    pub fn hint(&self) -> umsh_core::NodeHint {
        self.public_key().hint()
    }

    /// Return whether this identity is ephemeral.
    pub fn is_ephemeral(&self) -> bool {
        match self {
            Self::LongTerm(_) => false,
            #[cfg(feature = "software-crypto")]
            Self::Ephemeral(_) => true,
        }
    }
}

impl<I: NodeIdentity> From<I> for LocalIdentity<I> {
    fn from(value: I) -> Self {
        Self::LongTerm(value)
    }
}

/// Per-identity runtime state owned by the [`Mac`] coordinator.
///
/// There is exactly one `IdentitySlot` per registered local identity ([`LocalIdentityId`]).
/// The slot bundles everything the coordinator needs to send, receive, and authenticate
/// on behalf of a single local keypair:
///
/// - The [`LocalIdentity`] (public key + ECDH capability).
/// - A [`PeerCryptoMap`](crate::peers::PeerCryptoMap) mapping each known remote peer to its
///   established [`umsh_crypto::PairwiseKeys`] and replay window. Entries are populated by
///   [`Mac::install_pairwise_keys`].
/// - A monotonically increasing **frame counter** stamped into SECINFO of every sealed
///   packet, plus the bookkeeping needed to persist it safely (see below).
/// - A [`LinearMap`] of in-flight [`PendingAck`](crate::send::PendingAck) records keyed by
///   [`SendReceipt`](crate::send::SendReceipt), one entry per ACK-requested send awaiting
///   either forwarding confirmation or a final transport ACK.
/// - An internal `next_receipt` counter used to issue unique
///   [`SendReceipt`](crate::send::SendReceipt) values without allocation.
///
/// ## Frame-counter persistence
///
/// UMSH uses a monotonic frame counter instead of a timestamp for replay protection.
/// If the counter resets to a previously-seen value after a reboot, replayed old frames
/// might be accepted. To prevent this, the coordinator "reserves" counter ranges by writing
/// boundary values to the [`umsh_hal::CounterStore`] *before* using them. The slot tracks
/// three values:
///
/// - `frame_counter` — the live in-use value, advanced on every secured send.
/// - `persisted_counter` — the last boundary safely committed to the store.
/// - `pending_persist_target` — a scheduled future boundary written on the next call to
///   [`Mac::service_counter_persistence`].
///
/// If the live counter reaches `persisted_counter + COUNTER_PERSIST_BLOCK_SIZE` without a
/// successful flush, secure sends on that identity are blocked
/// ([`SendError::CounterPersistenceLag`]) until the store catches up. Ephemeral identities
/// opt out of this mechanism entirely.
pub struct IdentitySlot<
    I: NodeIdentity,
    const PEERS: usize,
    const ACKS: usize,
    const FRAME: usize = MAX_RESEND_FRAME_LEN,
> {
    identity: LocalIdentity<I>,
    peer_crypto: PeerCryptoMap<PEERS>,
    frame_counter: u32,
    persisted_counter: u32,
    pending_persist_target: Option<u32>,
    save_scheduled_since_boot: bool,
    counter_persistence_enabled: bool,
    pending_acks: LinearMap<SendReceipt, PendingAck<FRAME>, ACKS>,
    next_receipt: u32,
    pfs_parent: Option<LocalIdentityId>,
}

impl<I: NodeIdentity, const PEERS: usize, const ACKS: usize, const FRAME: usize>
    IdentitySlot<I, PEERS, ACKS, FRAME>
{
    /// Create a new identity slot.
    pub fn new(
        identity: LocalIdentity<I>,
        frame_counter: u32,
        pfs_parent: Option<LocalIdentityId>,
    ) -> Self {
        let counter_persistence_enabled = !identity.is_ephemeral();
        Self {
            identity,
            peer_crypto: PeerCryptoMap::new(),
            frame_counter,
            persisted_counter: frame_counter,
            pending_persist_target: None,
            save_scheduled_since_boot: false,
            counter_persistence_enabled,
            pending_acks: LinearMap::new(),
            next_receipt: 0,
            pfs_parent,
        }
    }

    /// Borrow the underlying identity.
    pub fn identity(&self) -> &LocalIdentity<I> {
        &self.identity
    }
    /// Borrow the per-peer secure-state map.
    pub fn peer_crypto(&self) -> &PeerCryptoMap<PEERS> {
        &self.peer_crypto
    }
    /// Mutably borrow the per-peer secure-state map.
    pub fn peer_crypto_mut(&mut self) -> &mut PeerCryptoMap<PEERS> {
        &mut self.peer_crypto
    }
    /// Return the current frame counter.
    pub fn frame_counter(&self) -> u32 {
        self.frame_counter
    }
    /// Return the persisted frame-counter reservation boundary.
    pub fn persisted_counter(&self) -> u32 {
        self.persisted_counter
    }
    /// Overwrite the current frame counter.
    pub fn set_frame_counter(&mut self, value: u32) {
        self.frame_counter = value;
    }
    /// Overwrite the persisted frame-counter reservation boundary.
    pub fn set_persisted_counter(&mut self, value: u32) {
        self.persisted_counter = value;
    }

    /// Return the next scheduled persist target, if any.
    pub fn pending_persist_target(&self) -> Option<u32> {
        self.pending_persist_target
    }

    /// Return whether counter persistence is enabled for this identity.
    pub fn counter_persistence_enabled(&self) -> bool {
        self.counter_persistence_enabled
    }

    /// Return the current frame counter and advance it with wrapping semantics.
    pub fn advance_frame_counter(&mut self) -> u32 {
        let current = self.frame_counter;
        self.frame_counter = self.frame_counter.wrapping_add(1);
        current
    }

    /// Load a persisted counter boundary for this identity.
    pub fn load_persisted_counter(&mut self, value: u32) {
        let aligned = align_counter_boundary(value);
        self.frame_counter = aligned;
        self.persisted_counter = aligned;
        self.pending_persist_target = None;
        self.save_scheduled_since_boot = false;
    }

    fn schedule_counter_persist_if_needed(&mut self) {
        if !self.counter_persistence_enabled {
            return;
        }

        let should_schedule = !self.save_scheduled_since_boot
            || (self.frame_counter & COUNTER_PERSIST_BLOCK_MASK) == COUNTER_PERSIST_SCHEDULE_OFFSET;
        if !should_schedule {
            return;
        }

        let target = next_counter_persist_target(self.frame_counter);
        self.pending_persist_target = Some(
            self.pending_persist_target
                .map(|existing| existing.max(target))
                .unwrap_or(target),
        );
        self.save_scheduled_since_boot = true;
    }

    fn mark_counter_persisted(&mut self, value: u32) {
        let aligned = align_counter_boundary(value);
        self.persisted_counter = aligned;
        if self.pending_persist_target == Some(aligned) {
            self.pending_persist_target = None;
        }
    }

    fn counter_window_exhausted(&self) -> bool {
        self.counter_persistence_enabled
            && self.frame_counter.wrapping_sub(self.persisted_counter) >= COUNTER_PERSIST_BLOCK_SIZE
    }

    /// Allocate the next send receipt.
    pub fn next_receipt(&mut self) -> SendReceipt {
        let receipt = SendReceipt(self.next_receipt);
        self.next_receipt = self.next_receipt.wrapping_add(1);
        receipt
    }

    /// Overrides the next send receipt value in tests that exercise wraparound behavior.
    #[cfg(test)]
    pub(crate) fn set_next_receipt_for_test(&mut self, value: u32) {
        self.next_receipt = value;
    }

    /// Overrides counter-persistence scheduling state in tests.
    #[cfg(test)]
    pub(crate) fn set_counter_persistence_state_for_test(
        &mut self,
        save_scheduled_since_boot: bool,
        pending_persist_target: Option<u32>,
    ) {
        self.save_scheduled_since_boot = save_scheduled_since_boot;
        self.pending_persist_target = pending_persist_target;
    }

    /// Insert or replace pending-ACK state for a send receipt.
    pub fn try_insert_pending_ack(
        &mut self,
        receipt: SendReceipt,
        pending: PendingAck<FRAME>,
    ) -> Result<Option<PendingAck<FRAME>>, PendingAckError> {
        self.pending_acks
            .insert(receipt, pending)
            .map_err(|_| PendingAckError::TableFull)
    }

    /// Borrow pending-ACK state by receipt.
    pub fn pending_ack(&self, receipt: &SendReceipt) -> Option<&PendingAck<FRAME>> {
        self.pending_acks.get(receipt)
    }

    /// Mutably borrow pending-ACK state by receipt.
    pub fn pending_ack_mut(&mut self, receipt: &SendReceipt) -> Option<&mut PendingAck<FRAME>> {
        self.pending_acks.get_mut(receipt)
    }

    /// Remove pending-ACK state by receipt.
    pub fn remove_pending_ack(&mut self, receipt: &SendReceipt) -> Option<PendingAck<FRAME>> {
        self.pending_acks.remove(receipt)
    }

    /// Return the parent long-term identity if this slot is ephemeral.
    pub fn pfs_parent(&self) -> Option<LocalIdentityId> {
        self.pfs_parent
    }
}

/// Per-channel operating-policy overrides enforced on outgoing traffic.
///
/// [`OperatingPolicy`] holds a small list of `ChannelPolicy` entries, one per channel that
/// requires non-default behavior. When the coordinator builds a multicast or blind-unicast
/// frame, it checks whether the target `channel_id` appears in this list and applies any
/// overrides before sealing the packet.
///
/// Typical use cases:
/// - **Unlicensed spectrum compliance** — force `require_unencrypted = true` for channels
///   that must operate under Part 15 / ISM-band rules where encryption is permissible but
///   the channel operator has chosen to run openly.
/// - **Metadata reduction** — force `require_full_source = true` when receiving nodes need
///   to resolve the sender without a prior key-exchange round-trip (e.g., a public beacon
///   channel where all senders are first-contact).
/// - **Propagation budget** — set `max_flood_hops` for high-density channels where
///   uncontrolled flooding would waste airtime.
///
/// Channels absent from the policy list use the permissive defaults inherited from
/// [`SendOptions`](crate::send::SendOptions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPolicy {
    /// Channel to which this policy applies.
    pub channel_id: ChannelId,
    /// Whether the channel must be sent unencrypted.
    pub require_unencrypted: bool,
    /// Whether the channel requires the full source public key.
    pub require_full_source: bool,
    /// Optional maximum flood-hop budget.
    pub max_flood_hops: Option<u8>,
}

/// Controls how the coordinator and optional repeater handle amateur-radio legal requirements.
///
/// Amateur (ham) radio law in most jurisdictions prohibits encrypted transmissions and requires
/// station identification on all transmitted frames. UMSH supports three operating modes to
/// accommodate networks that mix licensed and unlicensed nodes, or that operate exclusively
/// under one regulatory regime.
///
/// | Mode | Encryption | Operator callsign | Repeater station callsign |
/// |------|------------|------------------|--------------------------|
/// | `Unlicensed` | Allowed | Optional | Not added |
/// | `LicensedOnly` | Prohibited | Required | Required |
/// | `Hybrid` | Allowed (local) | Optional | Added to forwarded frames |
///
/// The mode appears on both [`OperatingPolicy`] (for locally-originated traffic) and
/// [`RepeaterConfig`] (for forwarding decisions) and they may differ independently — a node
/// might transmit its own encrypted application traffic (`Unlicensed`) while acting as a
/// licensed-identified repeater (`LicensedOnly`) for third-party frames it forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmateurRadioMode {
    /// Treat traffic as unlicensed operation only.
    ///
    /// Local transmit policy does not require operator callsigns or amateur-only
    /// restrictions. Repeaters operating in this mode must not add a station
    /// callsign when forwarding and should only retransmit packets that can be
    /// handled under unlicensed rules.
    Unlicensed,
    /// Treat forwarded and locally originated traffic as amateur-only.
    ///
    /// Encryption and blind unicast are disallowed, operator callsigns are
    /// required on originated packets, and repeaters must identify themselves
    /// with a station callsign on forwarded traffic.
    LicensedOnly,
    /// Permit both unlicensed and amateur-qualified forwarding behavior.
    ///
    /// Local transmit policy remains permissive, but repeaters identify
    /// forwarded packets with their station callsign and may still forward
    /// packets lacking an operator callsign when they can do so under
    /// unlicensed rules.
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransmitAuthority {
    Unlicensed,
    Amateur,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForwardStationAction {
    Remove,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ForwardPlan {
    router_hint: RouterHint,
    consume_source_route: bool,
    decrement_flood_hops: bool,
    delay_ms: u64,
    station_action: ForwardStationAction,
}

/// Local transmission policy enforced by the [`Mac`] coordinator on all outgoing frames.
///
/// `OperatingPolicy` governs what the coordinator is *allowed to send*, independent of what
/// the application requests. It is consulted at the start of every `queue_*` call via an
/// internal policy check, which returns [`SendError::PolicyViolation`] if the requested send
/// would violate it. This policy applies only to locally-originated frames; forwarding
/// decisions are governed separately by [`RepeaterConfig`].
///
/// - **`amateur_radio_mode`** — determines whether encryption and blind-unicast are permitted
///   and whether an operator callsign must be appended to originated frames.
///   See [`AmateurRadioMode`].
/// - **`operator_callsign`** — the ARNCE/HAM-64 callsign automatically appended to every
///   locally-originated frame when set. Required in `LicensedOnly` mode; optional otherwise.
/// - **`channel_policies`** — a small list of per-channel overrides for multicast and
///   blind-unicast traffic. Channels absent from the list use permissive defaults.
///
/// The default configuration (via [`Default`]) sets `Unlicensed` mode with no callsign and
/// no per-channel overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatingPolicy {
    /// Amateur-radio operating mode.
    pub amateur_radio_mode: AmateurRadioMode,
    /// Optional local operator callsign.
    pub operator_callsign: Option<HamAddr>,
    /// Per-channel overrides.
    pub channel_policies: Vec<ChannelPolicy, 4>,
}

impl Default for OperatingPolicy {
    fn default() -> Self {
        Self {
            amateur_radio_mode: AmateurRadioMode::Unlicensed,
            operator_callsign: None,
            channel_policies: Vec::new(),
        }
    }
}

/// Configuration governing whether and how the node forwards received frames.
///
/// The UMSH MAC layer includes an optional built-in repeater that forwards packets it
/// successfully receives, extending the effective range of the network without requiring
/// dedicated infrastructure. `RepeaterConfig` controls every facet of that behavior:
///
/// - **`enabled`** — master on/off switch. When `false`, all inbound forwarding logic is
///   skipped even if the other fields are populated.
/// - **`regions`** — a filter list of 2-byte ARNCE region codes. When non-empty, only packets
///   carrying a matching region code in their options block are eligible for forwarding. An
///   empty list means "forward regardless of region code".
/// - **`min_rssi` / `min_snr`** — signal-quality thresholds. Packets received below these
///   values are not forwarded; this prevents marginal receptions from being re-injected into
///   the network at full power, which would degrade SNR for nearby nodes rather than help.
/// - **`amateur_radio_mode`** — determines whether the repeater may forward encrypted or
///   blind-unicast frames, and whether it must inject a station callsign. See
///   [`AmateurRadioMode`].
/// - **`station_callsign`** — the ARNCE/HAM-64 callsign injected into the options block of
///   every forwarded frame when operating in `LicensedOnly` or `Hybrid` mode, satisfying the
///   third-party identification requirements of FCC §97.119 and equivalent regulations.
///
/// The default configuration has `enabled: false`; repeating must be explicitly opted in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepeaterConfig {
    /// Whether repeater forwarding is enabled.
    pub enabled: bool,
    /// Allowed repeater region codes.
    pub regions: Vec<[u8; 2], 8>,
    /// Minimum RSSI threshold for forwarding.
    pub min_rssi: Option<i16>,
    /// Minimum SNR threshold for forwarding.
    pub min_snr: Option<i8>,
    /// Amateur-radio operating mode for forwarding.
    pub amateur_radio_mode: AmateurRadioMode,
    /// Optional station callsign injected on forwarded traffic.
    pub station_callsign: Option<HamAddr>,
}

impl Default for RepeaterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            regions: Vec::new(),
            min_rssi: None,
            min_snr: None,
            amateur_radio_mode: AmateurRadioMode::Unlicensed,
            station_callsign: None,
        }
    }
}

/// Errors returned by the [`Mac`] coordinator when queueing an outbound send.
///
/// Returned synchronously by `queue_broadcast`, `queue_unicast`, `queue_multicast`, and
/// related methods. An error here means the send could not be *enqueued* — it says nothing
/// about the fate of frames already in the transmit queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The [`LocalIdentityId`] passed to the queue call does not correspond to an occupied
    /// identity slot. This indicates the identity was never registered or was removed.
    IdentityMissing,
    /// The destination [`umsh_core::PublicKey`] is not present in the peer registry.
    /// Register the peer first via [`Mac::add_peer`].
    PeerMissing,
    /// No pairwise session keys exist for the target peer on this identity.
    /// Keys must be installed via [`Mac::install_pairwise_keys`] after a key exchange.
    PairwiseKeysMissing,
    /// The target [`umsh_core::ChannelId`] is not present in the channel table.
    /// Register the channel first via [`Mac::add_channel`] or [`Mac::add_named_channel`].
    ChannelMissing,
    /// The [`OperatingPolicy`] rejected this send — for example, attempting to send an
    /// encrypted frame while operating in [`AmateurRadioMode::LicensedOnly`] mode.
    PolicyViolation,
    /// The requested packet type does not support transport ACKs (e.g., broadcast).
    AckUnsupported,
    /// The requested encryption mode is not valid for this packet type.
    EncryptionUnsupported,
    /// The requested salt option is not valid for this packet type.
    SaltUnsupported,
    /// The low-level packet builder failed, typically because the frame buffer is too small
    /// for the requested options and payload.
    Build(BuildError),
    /// Packet parsing failed while reprocessing a freshly-built frame, indicating an
    /// internal inconsistency in the packet construction logic.
    Parse(ParseError),
    /// The cryptographic seal operation failed. This typically indicates a mismatched key
    /// length or an internal crypto engine error.
    Crypto(CryptoError),
    /// The transmit queue is at the configured `TX` capacity. Back off and retry after
    /// the event loop has drained some entries.
    QueueFull,
    /// The in-flight ACK table for this identity is at the configured `ACKS` capacity.
    /// Wait for an existing ACK-requested send to complete or time out before sending another.
    PendingAckFull,
    /// Secure sends are blocked because the live frame counter has reached the persisted
    /// reservation boundary. Call [`Mac::service_counter_persistence`] to flush a new
    /// boundary to the counter store before retrying.
    CounterPersistenceLag,
}

impl From<BuildError> for SendError {
    fn from(value: BuildError) -> Self {
        Self::Build(value)
    }
}

impl From<ParseError> for SendError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<CryptoError> for SendError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Runtime errors produced by the [`Mac`] coordinator's async event loop.
///
/// Unlike [`SendError`], which is returned synchronously when *enqueueing* a send,
/// `MacError` surfaces from the async methods (`next_event`,
/// `service_counter_persistence`) that actually drive the coordinator forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacError<RadioError> {
    /// The underlying [`umsh_hal::Radio`] driver returned an error during a receive or
    /// channel-sense operation. The inner type is platform-specific (e.g., SPI fault on
    /// embedded hardware, socket error on a UDP transport).
    Radio(RadioError),
    /// A transmit-phase error from the radio, such as channel-activity-detection (CAD)
    /// exhaustion after [`MAX_CAD_ATTEMPTS`] retries. The frame was not sent.
    Transmit(TxError<RadioError>),
    /// An internal capacity invariant was violated: the coordinator needed to enqueue a
    /// control frame (MAC ACK, forwarded packet) but the transmit queue was full.
    /// Increase the `TX` const generic on [`Mac`] to give the queue more headroom.
    QueueFull,
}

/// Errors returned while loading persisted frame-counter boundaries via [`Mac::load_persisted_counter`].
///
/// On startup, applications should call [`Mac::load_persisted_counter`] for each registered
/// long-term identity to restore the safe starting point for the frame counter from
/// non-volatile storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CounterPersistenceError<StoreError> {
    /// The [`LocalIdentityId`] supplied does not correspond to an occupied identity slot.
    IdentityMissing,
    /// The underlying [`umsh_hal::CounterStore`] read operation failed. The application
    /// should decide whether to halt, retry, or start the counter at a conservatively high
    /// value to avoid replay-window collisions with pre-reset traffic.
    Store(StoreError),
}

impl<RadioError> From<RadioError> for MacError<RadioError> {
    fn from(value: RadioError) -> Self {
        Self::Radio(value)
    }
}

impl<RadioError> From<TxError<RadioError>> for MacError<RadioError> {
    fn from(value: TxError<RadioError>) -> Self {
        Self::Transmit(value)
    }
}

/// Central MAC coordinator that owns and drives the full UMSH radio-facing state machine.
///
/// `Mac` is the top-level entry point for UMSH protocol operation. It combines a radio driver,
/// cryptographic engine, clock, RNG, counter store, and all protocol state into a single
/// fully-typed, allocation-free structure. All const-generic capacity parameters are enforced
/// at compile time via `heapless` collections — there are no heap allocations inside `Mac`.
///
/// ## Generic parameters
///
/// - **`P: Platform`** — a trait bundle supplying the concrete driver types for `Radio`,
///   `Aes`/`Sha` (crypto), `Clock`, `Rng`, and `CounterStore`. Implement [`Platform`] once
///   per deployment target to swap in real hardware drivers, software stubs, or test doubles.
/// - **`IDENTITIES`** — maximum simultaneously active local identities (default
///   [`DEFAULT_IDENTITIES`]).
/// - **`PEERS`** — maximum known remote peers and their per-identity pairwise key entries
///   (default [`DEFAULT_PEERS`]).
/// - **`CHANNELS`** — maximum registered multicast channel keys (default
///   [`DEFAULT_CHANNELS`]).
/// - **`ACKS`** — maximum simultaneously in-flight ACK-requested sends per identity
///   (default [`DEFAULT_ACKS`]).
/// - **`TX`** — depth of the transmit queue (default [`DEFAULT_TX`]). Must be large enough
///   to absorb a burst of control frames (MAC ACKs + forwarded frames) alongside any
///   backlogged application sends.
/// - **`FRAME`** — maximum byte length of a stored frame buffer for retransmission
///   (default [`MAX_RESEND_FRAME_LEN`]).
/// - **`DUP`** — capacity of the duplicate-detection cache (default [`DEFAULT_DUP`]).
///
/// ## Lifecycle
///
/// 1. **Construct** with [`Mac::new`], supplying concrete driver instances and policy.
/// 2. **Register identities** via [`Mac::add_identity`]; call
///    [`Mac::load_persisted_counter`] on each long-term identity to restore the safe
///    frame-counter start point from non-volatile storage.
/// 3. **Register peers** via [`Mac::add_peer`] and install pairwise keys via
///    [`Mac::install_pairwise_keys`] after completing a key-exchange handshake.
/// 4. **Register channels** via [`Mac::add_channel`] or [`Mac::add_named_channel`].
/// 5. **Drive the event loop** by awaiting [`Mac::next_event`] in a loop. The coordinator
///    handles incoming frames, outgoing transmits, forwarding, ACK matching, retransmission
///    scheduling, and timer deadlines — no external polling required.
/// 6. **Send traffic** by calling `queue_broadcast`, `queue_unicast`, `queue_multicast`,
///    etc. from application code between (or concurrent with) event-loop iterations.
/// 7. **Persist counters** by calling [`Mac::service_counter_persistence`] whenever
///    `next_event` signals that pending persistence work is ready to flush.
///
/// ## Example (pseudo-code)
///
/// ```rust,ignore
/// let mut mac = Mac::<MyPlatform>::new(
///     radio, crypto, clock, rng, counter_store,
///     RepeaterConfig::default(), OperatingPolicy::default(),
/// );
/// let id = mac.add_identity(my_identity)?;
/// mac.load_persisted_counter(id).await?;
///
/// loop {
///     let event = mac.next_event(&mut callbacks).await?;
///     if event.needs_counter_persist {
///         mac.service_counter_persistence().await?;
///     }
/// }
/// ```
pub struct Mac<
    P: Platform,
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = MAX_RESEND_FRAME_LEN,
    const DUP: usize = DEFAULT_DUP,
> {
    radio: P::Radio,
    crypto: CryptoEngine<P::Aes, P::Sha>,
    clock: P::Clock,
    rng: P::Rng,
    counter_store: P::CounterStore,
    identities: Vec<Option<IdentitySlot<P::Identity, PEERS, ACKS, FRAME>>, IDENTITIES>,
    peer_registry: PeerRegistry<PEERS>,
    channels: ChannelTable<CHANNELS>,
    dup_cache: DuplicateCache<DUP>,
    tx_queue: TxQueue<TX, FRAME>,
    post_tx_listen: Option<PostTxListen>,
    repeater: RepeaterConfig,
    operating_policy: OperatingPolicy,
}

impl<
    P: Platform,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
> Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    /// Creates a MAC coordinator with the supplied radio, crypto, timing, and policy state.
    pub fn new(
        radio: P::Radio,
        crypto: CryptoEngine<P::Aes, P::Sha>,
        clock: P::Clock,
        rng: P::Rng,
        counter_store: P::CounterStore,
        repeater: RepeaterConfig,
        operating_policy: OperatingPolicy,
    ) -> Self {
        Self {
            radio,
            crypto,
            clock,
            rng,
            counter_store,
            identities: Vec::new(),
            peer_registry: PeerRegistry::new(),
            channels: ChannelTable::new(),
            dup_cache: DuplicateCache::new(),
            tx_queue: TxQueue::new(),
            post_tx_listen: None,
            repeater,
            operating_policy,
        }
    }

    /// Borrow the underlying radio.
    pub fn radio(&self) -> &P::Radio {
        &self.radio
    }

    /// Mutably borrow the underlying radio.
    pub fn radio_mut(&mut self) -> &mut P::Radio {
        &mut self.radio
    }

    /// Borrow the crypto engine.
    pub fn crypto(&self) -> &CryptoEngine<P::Aes, P::Sha> {
        &self.crypto
    }

    /// Borrow the monotonic clock.
    pub fn clock(&self) -> &P::Clock {
        &self.clock
    }

    /// Borrow the RNG.
    pub fn rng(&self) -> &P::Rng {
        &self.rng
    }

    /// Mutably borrow the RNG.
    pub fn rng_mut(&mut self) -> &mut P::Rng {
        &mut self.rng
    }

    /// Borrow the counter store.
    pub fn counter_store(&self) -> &P::CounterStore {
        &self.counter_store
    }
    /// Borrow the transmit queue.
    pub fn tx_queue(&self) -> &TxQueue<TX, FRAME> {
        &self.tx_queue
    }
    /// Mutably borrow the transmit queue.
    pub fn tx_queue_mut(&mut self) -> &mut TxQueue<TX, FRAME> {
        &mut self.tx_queue
    }
    /// Borrow the duplicate cache.
    pub fn dup_cache(&self) -> &DuplicateCache<DUP> {
        &self.dup_cache
    }
    /// Borrow the peer registry.
    pub fn peer_registry(&self) -> &PeerRegistry<PEERS> {
        &self.peer_registry
    }
    /// Mutably borrow the peer registry.
    pub fn peer_registry_mut(&mut self) -> &mut PeerRegistry<PEERS> {
        &mut self.peer_registry
    }
    /// Borrow the channel table.
    pub fn channels(&self) -> &ChannelTable<CHANNELS> {
        &self.channels
    }
    /// Mutably borrow the channel table.
    pub fn channels_mut(&mut self) -> &mut ChannelTable<CHANNELS> {
        &mut self.channels
    }
    /// Borrow repeater configuration.
    pub fn repeater_config(&self) -> &RepeaterConfig {
        &self.repeater
    }
    /// Mutably borrow repeater configuration.
    pub fn repeater_config_mut(&mut self) -> &mut RepeaterConfig {
        &mut self.repeater
    }
    /// Borrow the local operating policy.
    pub fn operating_policy(&self) -> &OperatingPolicy {
        &self.operating_policy
    }
    /// Mutably borrow the local operating policy.
    pub fn operating_policy_mut(&mut self) -> &mut OperatingPolicy {
        &mut self.operating_policy
    }

    /// Register one long-term local identity.
    pub fn add_identity(
        &mut self,
        identity: P::Identity,
    ) -> Result<LocalIdentityId, CapacityError> {
        self.insert_identity(LocalIdentity::LongTerm(identity), None)
    }

    /// Load the persisted frame-counter boundary for `id` from the counter store.
    pub async fn load_persisted_counter(
        &mut self,
        id: LocalIdentityId,
    ) -> Result<u32, CounterPersistenceError<<P::CounterStore as CounterStore>::Error>> {
        let context = {
            let slot = self
                .identity(id)
                .ok_or(CounterPersistenceError::IdentityMissing)?;
            if !slot.counter_persistence_enabled() {
                return Ok(slot.frame_counter());
            }
            *slot.identity().public_key()
        };
        let loaded = self
            .counter_store
            .load(&context.0)
            .await
            .map_err(CounterPersistenceError::Store)?;
        let aligned = align_counter_boundary(loaded);
        let slot = self
            .identity_mut(id)
            .ok_or(CounterPersistenceError::IdentityMissing)?;
        slot.load_persisted_counter(aligned);
        Ok(aligned)
    }

    /// Persist all currently scheduled frame-counter reservations.
    pub async fn service_counter_persistence(
        &mut self,
    ) -> Result<usize, <P::CounterStore as CounterStore>::Error> {
        let mut pending = Vec::<(LocalIdentityId, [u8; 32], u32), IDENTITIES>::new();
        for (index, slot) in self.identities.iter().enumerate() {
            let Some(slot) = slot.as_ref() else {
                continue;
            };
            let Some(target) = slot.pending_persist_target() else {
                continue;
            };
            if !slot.counter_persistence_enabled() {
                continue;
            }
            pending
                .push((
                    LocalIdentityId(index as u8),
                    slot.identity().public_key().0,
                    target,
                ))
                .expect("identity enumeration must fit configured identity capacity");
        }

        let mut wrote = 0usize;
        for (_, context, target) in pending.iter() {
            self.counter_store
                .store(context, align_counter_boundary(*target))
                .await?;
            wrote += 1;
        }
        if wrote > 0 {
            self.counter_store.flush().await?;
            for (id, _, target) in pending {
                if let Some(slot) = self.identity_mut(id) {
                    slot.mark_counter_persisted(target);
                }
            }
        }
        Ok(wrote)
    }

    #[cfg(feature = "software-crypto")]
    /// Register an ephemeral software identity linked to `parent`.
    pub fn register_ephemeral(
        &mut self,
        parent: LocalIdentityId,
        identity: umsh_crypto::software::SoftwareIdentity,
    ) -> Result<LocalIdentityId, CapacityError> {
        self.insert_identity(LocalIdentity::Ephemeral(identity), Some(parent))
    }

    #[cfg(feature = "software-crypto")]
    /// Remove an ephemeral identity slot if one exists at `id`.
    pub fn remove_ephemeral(&mut self, id: LocalIdentityId) -> bool {
        if let Some(slot) = self.identities.get_mut(id.0 as usize) {
            let should_remove = slot
                .as_ref()
                .map(|identity_slot| identity_slot.identity().is_ephemeral())
                .unwrap_or(false);
            if should_remove {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Borrow an identity slot by identifier.
    pub fn identity(
        &self,
        id: LocalIdentityId,
    ) -> Option<&IdentitySlot<P::Identity, PEERS, ACKS, FRAME>> {
        self.identities.get(id.0 as usize)?.as_ref()
    }

    /// Mutably borrow an identity slot by identifier.
    pub fn identity_mut(
        &mut self,
        id: LocalIdentityId,
    ) -> Option<&mut IdentitySlot<P::Identity, PEERS, ACKS, FRAME>> {
        self.identities.get_mut(id.0 as usize)?.as_mut()
    }

    /// Registers or refreshes a known remote peer in the shared registry.
    pub fn add_peer(&mut self, key: PublicKey) -> Result<PeerId, CapacityError> {
        self.peer_registry.try_insert_or_update(key)
    }

    /// Adds or updates a shared channel and derives its multicast keys.
    pub fn add_channel(&mut self, key: ChannelKey) -> Result<(), CapacityError> {
        let derived = self.crypto.derive_channel_keys(&key);
        self.channels.try_add(key, derived)
    }

    /// Adds or updates a named channel using the coordinator's channel-key derivation.
    pub fn add_named_channel(&mut self, name: &str) -> Result<(), CapacityError> {
        let key = self.crypto.derive_named_channel_key(name);
        self.add_channel(key)
    }

    /// Return the number of occupied identity slots.
    pub fn identity_count(&self) -> usize {
        self.identities.iter().filter(|slot| slot.is_some()).count()
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    pub fn install_pairwise_keys(
        &mut self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<PeerCryptoState>, SendError> {
        let slot = self
            .identity_mut(identity_id)
            .ok_or(SendError::IdentityMissing)?;
        slot.peer_crypto_mut()
            .insert(
                peer_id,
                PeerCryptoState {
                    pairwise_keys,
                    replay_window: ReplayWindow::new(),
                },
            )
            .map_err(|_| SendError::QueueFull)
    }

    /// Enqueues a broadcast frame for transmission.
    pub fn queue_broadcast(
        &mut self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), SendError> {
        self.enforce_send_policy(None, options, false)?;
        if options.encrypted {
            return Err(SendError::EncryptionUnsupported);
        }
        if options.ack_requested {
            return Err(SendError::AckUnsupported);
        }
        if options.salt {
            return Err(SendError::SaltUnsupported);
        }

        let source_key = *self
            .identity(from)
            .ok_or(SendError::IdentityMissing)?
            .identity()
            .public_key();
        let mut buf = [0u8; FRAME];
        let builder = PacketBuilder::new(&mut buf).broadcast();
        let mut builder = if options.full_source {
            builder.source_full(&source_key)
        } else {
            builder.source_hint(source_key.hint())
        };
        if let Some(hops) = options.flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = options.source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let frame = builder.payload(payload).build()?;
        if frame.len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue(TxPriority::Application, frame, None)
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    /// Enqueues a multicast frame using the configured channel keys.
    pub fn queue_multicast(
        &mut self,
        from: LocalIdentityId,
        channel_id: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<(), SendError> {
        self.enforce_send_policy(Some(*channel_id), options, false)?;
        if options.ack_requested {
            return Err(SendError::AckUnsupported);
        }

        let derived = self
            .channels
            .lookup_by_id(channel_id)
            .next()
            .ok_or(SendError::ChannelMissing)?
            .derived
            .clone();
        let keys = PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        };
        let (source_key, frame_counter) = self.identity_and_advance(from)?;
        let salt = self.take_salt(options);
        let mut buf = [0u8; FRAME];
        let builder = PacketBuilder::new(&mut buf).multicast(*channel_id);
        let builder = if options.full_source {
            builder.source_full(&source_key)
        } else {
            builder.source_hint(source_key.hint())
        };
        let mut builder = builder.frame_counter(frame_counter);
        if options.encrypted {
            builder = builder.encrypted();
        }
        builder = builder.mic_size(options.mic_size);
        if let Some(salt) = salt {
            builder = builder.salt(salt);
        }
        if let Some(hops) = options.flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = options.source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let mut packet = builder.payload(payload).build()?;
        self.crypto.seal_packet(&mut packet, &keys)?;
        self.enqueue_packet(packet, None)
    }

    /// Enqueues an immediate MAC ACK frame.
    pub fn queue_mac_ack(&mut self, dst: NodeHint, ack_tag: [u8; 8]) -> Result<(), SendError> {
        let mut buf = [0u8; FRAME];
        let frame = PacketBuilder::new(&mut buf).mac_ack(dst, ack_tag).build()?;
        if frame.len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue(TxPriority::ImmediateAck, frame, None)
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    /// Enqueues a unicast frame and optional pending-ACK state.
    pub fn queue_unicast(
        &mut self,
        from: LocalIdentityId,
        peer: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        self.enforce_send_policy(None, options, false)?;
        let (peer_id, _) = self
            .peer_registry
            .lookup_by_key(peer)
            .ok_or(SendError::PeerMissing)?;
        let pairwise_keys = self
            .identity(from)
            .ok_or(SendError::IdentityMissing)?
            .peer_crypto()
            .get(&peer_id)
            .ok_or(SendError::PairwiseKeysMissing)?
            .pairwise_keys
            .clone();

        let (source_key, frame_counter) = self.identity_and_advance(from)?;
        let salt = self.take_salt(options);
        let mut buf = [0u8; FRAME];
        let builder = PacketBuilder::new(&mut buf).unicast(peer.hint());
        let builder = if options.full_source {
            builder.source_full(&source_key)
        } else {
            builder.source_hint(source_key.hint())
        };
        let mut builder = builder.frame_counter(frame_counter);
        if options.ack_requested {
            builder = builder.ack_requested();
        }
        if options.encrypted {
            builder = builder.encrypted();
        }
        builder = builder.mic_size(options.mic_size);
        if let Some(salt) = salt {
            builder = builder.salt(salt);
        }
        if let Some(hops) = options.flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = options.source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let mut packet = builder.payload(payload).build()?;

        let receipt = if options.ack_requested {
            Some(self.prepare_pending_ack(from, *peer, &packet, &pairwise_keys, options)?)
        } else {
            None
        };

        self.crypto.seal_packet(&mut packet, &pairwise_keys)?;
        if let Some(receipt) = receipt {
            self.refresh_pending_resend(
                from,
                receipt,
                packet.as_bytes(),
                options.source_route.as_ref().map(|route| route.as_slice()),
            )?;
        }
        if let Err(err) = self.enqueue_packet(packet, receipt) {
            if let Some(receipt) = receipt {
                let _ = self
                    .identity_mut(from)
                    .and_then(|slot| slot.remove_pending_ack(&receipt));
            }
            return Err(err);
        }
        Ok(receipt)
    }

    /// Enqueues a blind-unicast frame and optional pending-ACK state.
    pub fn queue_blind_unicast(
        &mut self,
        from: LocalIdentityId,
        peer: &PublicKey,
        channel_id: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        self.enforce_send_policy(Some(*channel_id), options, true)?;
        let (peer_id, _) = self
            .peer_registry
            .lookup_by_key(peer)
            .ok_or(SendError::PeerMissing)?;
        let pairwise_keys = self
            .identity(from)
            .ok_or(SendError::IdentityMissing)?
            .peer_crypto()
            .get(&peer_id)
            .ok_or(SendError::PairwiseKeysMissing)?
            .pairwise_keys
            .clone();
        let channel_keys = self
            .channels
            .lookup_by_id(channel_id)
            .next()
            .ok_or(SendError::ChannelMissing)?
            .derived
            .clone();
        let blind_keys = self.crypto.derive_blind_keys(&pairwise_keys, &channel_keys);

        let (source_key, frame_counter) = self.identity_and_advance(from)?;
        let salt = self.take_salt(options);
        let mut buf = [0u8; FRAME];
        let builder = PacketBuilder::new(&mut buf).blind_unicast(*channel_id, peer.hint());
        let builder = if options.full_source {
            builder.source_full(&source_key)
        } else {
            builder.source_hint(source_key.hint())
        };
        let mut builder = builder.frame_counter(frame_counter);
        if options.ack_requested {
            builder = builder.ack_requested();
        }
        if !options.encrypted {
            builder = builder.unencrypted();
        }
        builder = builder.mic_size(options.mic_size);
        if let Some(salt) = salt {
            builder = builder.salt(salt);
        }
        if let Some(hops) = options.flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = options.source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let mut packet = builder.payload(payload).build()?;

        let receipt = if options.ack_requested {
            Some(self.prepare_pending_ack(from, *peer, &packet, &blind_keys, options)?)
        } else {
            None
        };

        self.crypto
            .seal_blind_packet(&mut packet, &blind_keys, &channel_keys)
            .map_err(SendError::Crypto)?;
        if let Some(receipt) = receipt {
            self.refresh_pending_resend(
                from,
                receipt,
                packet.as_bytes(),
                options.source_route.as_ref().map(|route| route.as_slice()),
            )?;
        }
        if let Err(err) = self.enqueue_packet(packet, receipt) {
            if let Some(receipt) = receipt {
                let _ = self
                    .identity_mut(from)
                    .and_then(|slot| slot.remove_pending_ack(&receipt));
            }
            return Err(err);
        }
        Ok(receipt)
    }

    /// Transmit the next eligible queued frame, if any.
    ///
    /// While a post-transmit forwarding listen window is active, only immediate MAC
    /// ACK traffic is permitted to bypass the listen state. Forwarded sends arm a new
    /// listen window after the radio transmit completes. Non-immediate traffic honors
    /// queued CAD backoff state and gives up after the configured maximum number of
    /// CAD attempts.
    pub async fn transmit_next(
        &mut self,
    ) -> Result<Option<SendReceipt>, MacError<<P::Radio as Radio>::Error>> {
        self.expire_post_tx_listen_if_needed();
        let Some(queued) = self.tx_queue.pop_next() else {
            return Ok(None);
        };
        let now_ms = self.clock.now_ms();

        if queued.not_before_ms > now_ms {
            self.requeue_tx(&queued).map_err(|_| MacError::QueueFull)?;
            return Ok(None);
        }

        if self.post_tx_listen.is_some() && queued.priority != TxPriority::ImmediateAck {
            self.requeue_tx(&queued).map_err(|_| MacError::QueueFull)?;
            return Ok(None);
        }

        let receipt = queued.receipt;
        let tx_options = if queued.priority == TxPriority::ImmediateAck {
            TxOptions::default()
        } else {
            TxOptions {
                cad_timeout_ms: Some(0),
            }
        };
        match self
            .radio
            .transmit(queued.frame.as_slice(), tx_options)
            .await
        {
            Ok(()) => {}
            Err(TxError::CadTimeout) => {
                let next_attempt = queued.cad_attempts.saturating_add(1);
                if next_attempt >= MAX_CAD_ATTEMPTS {
                    return Ok(None);
                }
                let backoff_ms = u64::from(
                    self.rng
                        .random_range(..self.radio.t_frame_ms().saturating_add(1)),
                );
                self.tx_queue
                    .enqueue_with_state(
                        queued.priority,
                        queued.frame.as_slice(),
                        queued.receipt,
                        now_ms.saturating_add(backoff_ms),
                        next_attempt,
                    )
                    .map_err(|_| MacError::QueueFull)?;
                return Ok(None);
            }
            Err(error) => return Err(MacError::Transmit(error)),
        }
        if let Some(receipt) = receipt {
            self.arm_post_tx_listen(receipt, queued.frame.as_slice());
        }
        Ok(receipt)
    }

    /// Keep transmitting until the queue is empty.
    ///
    /// Progress stops when CAD keeps reporting busy, when a post-transmit listen window blocks
    /// normal traffic, or when the queue is otherwise unable to shrink further in the current cycle.
    pub async fn drain_tx_queue(&mut self) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        while !self.tx_queue.is_empty() {
            let queue_len = self.tx_queue.len();
            let _ = self.transmit_next().await?;
            if self.tx_queue.len() >= queue_len {
                break;
            }
        }
        Ok(())
    }

    /// Runs one coordinator cycle over the current MAC state.
    ///
    /// The cycle performs four ordered phases:
    ///
    /// 1. Drain any queued transmit work.
    /// 2. Receive and process at most one inbound frame.
    /// 3. Drain any immediate ACK generated during receive handling.
    /// 4. Service pending ACK timers and emit timeout events.
    ///
    /// The callback may be invoked zero or more times depending on what the
    /// receive and timeout phases accept or resolve.
    /// Service one MAC coordinator cycle.
    pub async fn poll_cycle(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        self.drain_tx_queue().await?;
        if self.post_tx_listen.is_some() {
            self.service_post_tx_listen(&mut on_event).await?;
        } else {
            let _ = self.receive_one(&mut on_event).await?;
        }
        self.drain_tx_queue().await?;
        self.service_pending_ack_timeouts(&mut on_event)
            .map_err(|_| MacError::QueueFull)?;
        Ok(())
    }

    /// Compute the earliest deadline across all coordinator timers.
    ///
    /// Returns `None` when there are no pending timers.  The returned value
    /// covers pending ACK deadlines (both `ack_deadline_ms` and forwarding
    /// `confirm_deadline_ms`), the post-transmit listen window, and deferred
    /// transmit-queue entries.
    pub fn earliest_deadline_ms(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;

        if let Some(listen) = &self.post_tx_listen {
            earliest =
                Some(earliest.map_or(listen.deadline_ms, |e: u64| e.min(listen.deadline_ms)));
        }

        for slot in self.identities.iter().filter_map(|s| s.as_ref()) {
            for (_, pending) in slot.pending_acks.iter() {
                earliest = Some(earliest.map_or(pending.ack_deadline_ms, |e: u64| {
                    e.min(pending.ack_deadline_ms)
                }));
                if let crate::AckState::AwaitingForward {
                    confirm_deadline_ms,
                } = pending.state
                {
                    earliest = Some(
                        earliest.map_or(confirm_deadline_ms, |e: u64| e.min(confirm_deadline_ms)),
                    );
                }
            }
        }

        if let Some(nb) = self.tx_queue.earliest_not_before_ms() {
            earliest = Some(earliest.map_or(nb, |e: u64| e.min(nb)));
        }

        earliest
    }

    /// Run the coordinator's event loop until at least one event is delivered
    /// or a timer-driven action (retransmit, timeout) is processed.
    ///
    /// Unlike [`poll_cycle`](Self::poll_cycle), this method properly awaits the
    /// radio and timer deadlines instead of returning immediately when nothing
    /// is ready.  Callers can use `tokio::select!` (or equivalent) to multiplex
    /// user input alongside MAC events:
    ///
    /// ```ignore
    /// loop {
    ///     tokio::select! {
    ///         line = stdin.next_line() => { /* handle input */ }
    ///         result = mac.next_event(|id, event| { /* handle event */ }) => {
    ///             result?;
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn next_event(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        loop {
            // Phase 1: Drain ready transmit work.
            self.drain_tx_queue().await?;

            // Phase 2: Wait for a radio frame or the earliest timer deadline.
            let mut buf = [0u8; FRAME];
            enum WakeReason {
                Received(RxInfo),
                TimerExpired,
            }
            let reason = poll_fn(|cx| {
                // Try to receive a frame (non-blocking poll).
                match self.radio.poll_receive(cx, &mut buf) {
                    Poll::Ready(Ok(rx)) => return Poll::Ready(Ok(WakeReason::Received(rx))),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }

                // Check whether any timer has expired.
                let now_ms = self.clock.now_ms();
                if let Some(deadline) = self.earliest_deadline_ms() {
                    if now_ms >= deadline {
                        return Poll::Ready(Ok(WakeReason::TimerExpired));
                    }
                    // Register for wakeup at the earliest deadline.
                    let _ = self.clock.poll_delay_until(cx, deadline);
                }

                // Check for tx_queue items that became ready.
                if self.tx_queue.has_ready(now_ms) {
                    return Poll::Ready(Ok(WakeReason::TimerExpired));
                }

                Poll::Pending
            })
            .await
            .map_err(MacError::Radio)?;

            // Phase 3: Process what woke us up.
            match reason {
                WakeReason::Received(rx) => {
                    let frame_len = rx.len.min(buf.len());
                    let _ = self.process_received_frame(&mut buf, frame_len, &rx, &mut on_event);
                }
                WakeReason::TimerExpired => {
                    // Timers are handled in phase 4 below.
                }
            }

            // Phase 4: Drain any immediate ACKs generated during receive.
            self.drain_tx_queue().await?;

            // Phase 5: Service pending ACK timers.
            self.service_pending_ack_timeouts(&mut on_event)
                .map_err(|_| MacError::QueueFull)?;

            // If the tx_queue has new work (e.g. retransmits just enqueued),
            // loop back to drain it before waiting again.
            if !self.tx_queue.is_empty() {
                continue;
            }

            return Ok(());
        }
    }

    /// Process a received frame, dispatching events through `on_event`.
    ///
    /// This is the shared implementation used by both [`receive_one`](Self::receive_one)
    /// and [`next_event`](Self::next_event).  Returns `true` when the frame
    /// produced at least one event or side-effect.
    fn process_received_frame(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        _rx: &RxInfo,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let Ok(header) = PacketHeader::parse(&buf[..frame_len]) else {
            return false;
        };
        let forwarding_confirmed = self.observe_forwarding_confirmation(&buf[..frame_len]);

        match header.packet_type() {
            PacketType::Broadcast => self.process_broadcast(buf, frame_len, &header, &mut on_event),
            PacketType::MacAck => {
                self.process_mac_ack(buf, frame_len, &header, forwarding_confirmed, &mut on_event)
            }
            PacketType::Unicast | PacketType::UnicastAckReq => self.process_unicast(
                buf,
                frame_len,
                &header,
                _rx,
                forwarding_confirmed,
                &mut on_event,
            ),
            PacketType::Multicast => self.process_multicast(
                buf,
                frame_len,
                &header,
                _rx,
                forwarding_confirmed,
                &mut on_event,
            ),
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => self
                .process_blind_unicast(
                    buf,
                    frame_len,
                    &header,
                    _rx,
                    forwarding_confirmed,
                    &mut on_event,
                ),
            PacketType::Reserved5 => false,
        }
    }

    fn process_broadcast(
        &mut self,
        buf: &[u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let Some((from_hint, from_key)) = Self::resolve_broadcast_source(&buf[..frame_len], header)
        else {
            return false;
        };
        if !Self::payload_is_allowed(header.packet_type(), &buf[header.body_range.clone()]) {
            return false;
        }
        let mut delivered = false;
        for (index, slot) in self.identities.iter().enumerate() {
            if slot.is_none() {
                continue;
            }
            delivered = true;
            on_event(
                LocalIdentityId(index as u8),
                crate::MacEventRef::Broadcast {
                    from_hint,
                    from_key,
                    payload: &buf[header.body_range.clone()],
                },
            );
        }
        delivered
    }

    fn process_mac_ack(
        &mut self,
        buf: &[u8; FRAME],
        _frame_len: usize,
        header: &PacketHeader,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let Some(ack_dst) = header.ack_dst else {
            return false;
        };
        let Some(target_peer) = self
            .identities
            .iter()
            .filter_map(|slot| slot.as_ref())
            .find(|slot| slot.identity().public_key().hint() == ack_dst)
            .and_then(|slot| self.match_pending_peer_for_ack(slot, &buf[header.mic_range.clone()]))
        else {
            return false;
        };
        let mut ack_tag = [0u8; 8];
        ack_tag.copy_from_slice(&buf[header.mic_range.clone()]);
        if let Some((identity_id, receipt)) = self.complete_ack(&target_peer, &ack_tag) {
            on_event(
                identity_id,
                crate::MacEventRef::AckReceived {
                    peer: target_peer,
                    receipt,
                },
            );
            return true;
        }
        forwarding_confirmed
    }

    fn process_unicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let handled = if let Some(local_id) = self.find_local_identity_for_dst(header.dst) {
            let mut handled = false;
            for (peer_id, peer_key) in
                self.resolve_source_peer_candidates(&buf[..frame_len], header)
            {
                let Some(keys) = self
                    .identity(local_id)
                    .and_then(|slot| slot.peer_crypto().get(&peer_id))
                    .map(|state| state.pairwise_keys.clone())
                else {
                    continue;
                };
                let Ok(body_range) = self
                    .crypto
                    .open_packet(&mut buf[..frame_len], header, &keys)
                else {
                    continue;
                };
                if !Self::payload_is_allowed(header.packet_type(), &buf[body_range.clone()]) {
                    continue;
                }
                if !self.accept_unicast_replay(local_id, peer_id, header, &buf[..frame_len]) {
                    continue;
                }
                self.learn_route_for_peer(peer_id, &buf[..frame_len], header);

                if header.ack_requested()
                    && self.should_emit_destination_ack(&buf[..frame_len], header)
                {
                    let ack_tag = self.compute_received_ack_tag(
                        &buf[..frame_len],
                        header,
                        body_range.clone(),
                        &keys,
                    );
                    self.queue_mac_ack(peer_key.hint(), ack_tag).ok();
                }

                on_event(
                    local_id,
                    crate::MacEventRef::Unicast {
                        from: peer_key,
                        payload: &buf[body_range],
                        ack_requested: header.ack_requested(),
                    },
                );
                handled = true;
                break;
            }
            handled
        } else {
            false
        };
        let forwarded = self.maybe_forward_received(&original[..frame_len], header, rx, handled);
        handled || forwarding_confirmed || forwarded
    }

    fn process_multicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let delivered = if let Some(channel_id) = header.channel {
            let derived = {
                self.channels
                    .lookup_by_id(&channel_id)
                    .next()
                    .map(|channel| channel.derived.clone())
            };
            if let Some(derived) = derived {
                let keys = PairwiseKeys {
                    k_enc: derived.k_enc,
                    k_mic: derived.k_mic,
                };
                if let Ok(body_range) =
                    self.crypto
                        .open_packet(&mut buf[..frame_len], header, &keys)
                {
                    if !Self::payload_is_allowed(header.packet_type(), &buf[body_range.clone()]) {
                        false
                    } else if let Some((peer_id, from)) =
                        self.resolve_multicast_source(&buf[..frame_len], header)
                    {
                        if self.accept_multicast_replay(
                            channel_id,
                            peer_id,
                            header,
                            &buf[..frame_len],
                        ) {
                            self.learn_route_for_peer(peer_id, &buf[..frame_len], header);
                            let mut delivered = false;
                            for (index, slot) in self.identities.iter().enumerate() {
                                if slot.is_none() {
                                    continue;
                                }
                                delivered = true;
                                on_event(
                                    LocalIdentityId(index as u8),
                                    crate::MacEventRef::Multicast {
                                        from,
                                        channel_id,
                                        payload: &buf[body_range.clone()],
                                    },
                                );
                            }
                            delivered
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        let forwarded = self.maybe_forward_received(&original[..frame_len], header, rx, false);
        delivered || forwarding_confirmed || forwarded
    }

    fn process_blind_unicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let handled = if let Some(channel_id) = header.channel {
            let channel_candidates: Vec<DerivedChannelKeys, CHANNELS> = self
                .channels
                .lookup_by_id(&channel_id)
                .map(|channel| channel.derived.clone())
                .collect();
            if channel_candidates.is_empty() {
                false
            } else {
                let mut handled = false;
                for channel_keys in channel_candidates {
                    buf[..frame_len].copy_from_slice(&original[..frame_len]);
                    let Ok((dst, source_addr)) = self.crypto.decrypt_blind_addr(
                        &mut buf[..frame_len],
                        header,
                        &channel_keys,
                    ) else {
                        continue;
                    };
                    let Some(local_id) = self.find_local_identity_for_dst(Some(dst)) else {
                        continue;
                    };
                    for (peer_id, peer_key) in
                        self.resolve_blind_source_peer_candidates(&buf[..frame_len], source_addr)
                    {
                        let Some(pairwise_keys) = self
                            .identity(local_id)
                            .and_then(|slot| slot.peer_crypto().get(&peer_id))
                            .map(|state| state.pairwise_keys.clone())
                        else {
                            continue;
                        };
                        let blind_keys =
                            self.crypto.derive_blind_keys(&pairwise_keys, &channel_keys);
                        let body_range = match self.crypto.open_packet(
                            &mut buf[..frame_len],
                            header,
                            &blind_keys,
                        ) {
                            Ok(range) => range,
                            Err(_) => continue,
                        };
                        if !Self::payload_is_allowed(header.packet_type(), &buf[body_range.clone()])
                        {
                            continue;
                        }
                        if !self.accept_unicast_replay(local_id, peer_id, header, &buf[..frame_len])
                        {
                            continue;
                        }
                        self.learn_route_for_peer(peer_id, &buf[..frame_len], header);

                        if header.ack_requested()
                            && self.should_emit_destination_ack(&buf[..frame_len], header)
                        {
                            let ack_tag = self.compute_received_ack_tag(
                                &buf[..frame_len],
                                header,
                                body_range.clone(),
                                &blind_keys,
                            );
                            self.queue_mac_ack(peer_key.hint(), ack_tag).ok();
                        }

                        on_event(
                            local_id,
                            crate::MacEventRef::BlindUnicast {
                                from: peer_key,
                                channel_id,
                                payload: &buf[body_range],
                                ack_requested: header.ack_requested(),
                            },
                        );
                        handled = true;
                        break;
                    }
                    if handled {
                        break;
                    }
                }
                handled
            }
        } else {
            false
        };
        let forwarded = self.maybe_forward_received(&original[..frame_len], header, rx, handled);
        handled || forwarding_confirmed || forwarded
    }

    /// Non-blocking receive: polls the radio once and processes a frame if available.
    ///
    /// This is the legacy non-blocking API used by [`poll_cycle`](Self::poll_cycle).
    /// For new code, prefer [`next_event`](Self::next_event) which properly awaits
    /// the radio and timer deadlines.
    pub async fn receive_one(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<bool, MacError<<P::Radio as Radio>::Error>> {
        let mut buf = [0u8; FRAME];
        let Some(rx) = poll_fn(|cx| match self.radio.poll_receive(cx, &mut buf) {
            Poll::Ready(Ok(rx)) => Poll::Ready(Ok(Some(rx))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Ready(Ok(None)),
        })
        .await
        .map_err(MacError::Radio)?
        else {
            return Ok(false);
        };

        let frame_len = rx.len.min(buf.len());
        Ok(self.process_received_frame(&mut buf, frame_len, &rx, &mut on_event))
    }

    /// Mark a pending receipt as acknowledged and emit an event through `on_event`.
    pub fn complete_ack(
        &mut self,
        peer: &PublicKey,
        ack_tag: &[u8; 8],
    ) -> Option<(LocalIdentityId, SendReceipt)> {
        for (index, slot) in self.identities.iter_mut().enumerate() {
            let Some(slot) = slot.as_mut() else {
                continue;
            };

            let receipt = slot.pending_acks.iter().find_map(|(receipt, pending)| {
                (pending.peer == *peer && pending.ack_tag == *ack_tag).then_some(*receipt)
            });

            if let Some(receipt) = receipt {
                slot.pending_acks.remove(&receipt);
                if self
                    .post_tx_listen
                    .as_ref()
                    .map(|listen| {
                        listen.identity_id == LocalIdentityId(index as u8)
                            && listen.receipt == receipt
                    })
                    .unwrap_or(false)
                {
                    self.post_tx_listen = None;
                }
                return Some((LocalIdentityId(index as u8), receipt));
            }
        }

        None
    }

    /// Expire or retry pending ACK state based on `now_ms`.
    pub fn service_pending_ack_timeouts(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), CapacityError> {
        self.expire_post_tx_listen_if_needed();

        #[derive(Clone)]
        enum Action<const FRAME: usize> {
            Retry {
                receipt: SendReceipt,
                resend: ResendRecord<FRAME>,
            },
            Timeout {
                receipt: SendReceipt,
                peer: PublicKey,
            },
        }

        let now_ms = self.clock.now_ms();
        let confirm_window_ms = self.radio.t_frame_ms() as u64 * 3;

        for (index, slot) in self.identities.iter_mut().enumerate() {
            let Some(slot) = slot.as_mut() else {
                continue;
            };

            let mut actions: Vec<Action<FRAME>, ACKS> = Vec::new();
            for (receipt, pending) in slot.pending_acks.iter_mut() {
                if now_ms >= pending.ack_deadline_ms {
                    actions
                        .push(Action::Timeout {
                            receipt: *receipt,
                            peer: pending.peer,
                        })
                        .map_err(|_| CapacityError)?;
                    continue;
                }

                if let crate::AckState::AwaitingForward {
                    confirm_deadline_ms,
                } = pending.state
                {
                    if now_ms >= confirm_deadline_ms && pending.retries < MAX_FORWARD_RETRIES {
                        pending.retries = pending.retries.saturating_add(1);
                        pending.sent_ms = now_ms;
                        pending.state = crate::AckState::AwaitingForward {
                            confirm_deadline_ms: now_ms + confirm_window_ms,
                        };
                        actions
                            .push(Action::Retry {
                                receipt: *receipt,
                                resend: pending.resend.clone(),
                            })
                            .map_err(|_| CapacityError)?;
                    }
                }
            }

            for action in actions {
                match action {
                    Action::Retry { receipt, resend } => {
                        self.tx_queue.enqueue(
                            TxPriority::Retry,
                            resend.frame.as_slice(),
                            Some(receipt),
                        )?;
                    }
                    Action::Timeout { receipt, peer } => {
                        slot.pending_acks.remove(&receipt);
                        on_event(
                            LocalIdentityId(index as u8),
                            crate::MacEventRef::AckTimeout { peer, receipt },
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn identity_and_advance(
        &mut self,
        from: LocalIdentityId,
    ) -> Result<(PublicKey, u32), SendError> {
        let slot = self.identity_mut(from).ok_or(SendError::IdentityMissing)?;
        if slot.counter_window_exhausted() {
            return Err(SendError::CounterPersistenceLag);
        }
        let source_key = *slot.identity().public_key();
        let frame_counter = slot.advance_frame_counter();
        slot.schedule_counter_persist_if_needed();
        Ok((source_key, frame_counter))
    }

    fn take_salt(&mut self, options: &SendOptions) -> Option<u16> {
        options.salt.then(|| self.rng.next_u32() as u16)
    }

    fn enforce_send_policy(
        &self,
        channel_id: Option<ChannelId>,
        options: &SendOptions,
        blind_unicast: bool,
    ) -> Result<(), SendError> {
        let _authority = self.classify_send_authority(options, blind_unicast)?;

        let Some(channel_id) = channel_id else {
            return Ok(());
        };
        let Some(policy) = self
            .operating_policy
            .channel_policies
            .iter()
            .find(|policy| policy.channel_id == channel_id)
        else {
            return Ok(());
        };

        if policy.require_unencrypted && options.encrypted {
            return Err(SendError::PolicyViolation);
        }
        if policy.require_full_source && !options.full_source {
            return Err(SendError::PolicyViolation);
        }
        if let Some(max_flood_hops) = policy.max_flood_hops {
            if options
                .flood_hops
                .map(|hops| hops > max_flood_hops)
                .unwrap_or(false)
            {
                return Err(SendError::PolicyViolation);
            }
        }

        Ok(())
    }

    fn classify_send_authority(
        &self,
        options: &SendOptions,
        _blind_unicast: bool,
    ) -> Result<TransmitAuthority, SendError> {
        match self.operating_policy.amateur_radio_mode {
            AmateurRadioMode::Unlicensed => Ok(TransmitAuthority::Unlicensed),
            AmateurRadioMode::LicensedOnly => {
                if options.encrypted || self.operating_policy.operator_callsign.is_none() {
                    return Err(SendError::PolicyViolation);
                }
                Ok(TransmitAuthority::Amateur)
            }
            AmateurRadioMode::Hybrid => {
                if options.encrypted {
                    // Hybrid encrypted traffic must be treated as unlicensed
                    // traffic for downstream transmit-power and duty-cycle policy.
                    Ok(TransmitAuthority::Unlicensed)
                } else if self.operating_policy.operator_callsign.is_some() {
                    Ok(TransmitAuthority::Amateur)
                } else {
                    Ok(TransmitAuthority::Unlicensed)
                }
            }
        }
    }

    fn enqueue_packet(
        &mut self,
        packet: UnsealedPacket<'_>,
        receipt: Option<SendReceipt>,
    ) -> Result<(), SendError> {
        if packet.total_len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue(TxPriority::Application, packet.as_bytes(), receipt)
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    fn refresh_pending_resend(
        &mut self,
        from: LocalIdentityId,
        receipt: SendReceipt,
        frame: &[u8],
        source_route: Option<&[RouterHint]>,
    ) -> Result<(), SendError> {
        let resend =
            ResendRecord::try_new(frame, source_route).map_err(|_| SendError::QueueFull)?;
        let pending = self
            .identity_mut(from)
            .ok_or(SendError::IdentityMissing)?
            .pending_ack_mut(&receipt)
            .ok_or(SendError::IdentityMissing)?;
        pending.resend = resend;
        Ok(())
    }

    fn prepare_pending_ack(
        &mut self,
        from: LocalIdentityId,
        peer: PublicKey,
        packet: &UnsealedPacket<'_>,
        keys: &PairwiseKeys,
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        let header = PacketHeader::parse(packet.as_bytes())?;
        let mut cmac: CmacState<_> = self.crypto.cmac_state(&keys.k_mic);
        feed_aad(&header, packet.as_bytes(), |chunk| cmac.update(chunk));
        cmac.update(packet.body());
        let full_mac = cmac.finalize();
        let ack_tag = self.crypto.compute_ack_tag(&full_mac, &keys.k_enc);
        let sent_ms = self.clock.now_ms();
        let ack_deadline_ms = sent_ms + (self.radio.t_frame_ms() as u64 * 10);
        let confirm_deadline_ms = sent_ms + (self.radio.t_frame_ms() as u64 * 3);
        let is_forwarded = options
            .source_route
            .as_ref()
            .map(|route| !route.is_empty())
            .unwrap_or(false)
            || options.flood_hops.unwrap_or(0) > 0;
        let resend = ResendRecord::try_new(
            packet.as_bytes(),
            options.source_route.as_ref().map(|route| route.as_slice()),
        )
        .map_err(|_| SendError::QueueFull)?;

        let slot = self.identity_mut(from).ok_or(SendError::IdentityMissing)?;
        let receipt = slot.next_receipt();
        let pending = if is_forwarded {
            PendingAck::forwarded(
                ack_tag,
                peer,
                resend,
                sent_ms,
                ack_deadline_ms,
                confirm_deadline_ms,
            )
        } else {
            PendingAck::direct(ack_tag, peer, resend, sent_ms, ack_deadline_ms)
        };
        slot.try_insert_pending_ack(receipt, pending)
            .map_err(|_| SendError::PendingAckFull)?;
        Ok(receipt)
    }

    fn insert_identity(
        &mut self,
        identity: LocalIdentity<P::Identity>,
        pfs_parent: Option<LocalIdentityId>,
    ) -> Result<LocalIdentityId, CapacityError> {
        if let Some((index, slot)) = self
            .identities
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(IdentitySlot::new(identity, 0, pfs_parent));
            return Ok(LocalIdentityId(index as u8));
        }

        let next_id = self.identities.len();
        self.identities
            .push(Some(IdentitySlot::new(identity, 0, pfs_parent)))
            .map_err(|_| CapacityError)?;
        Ok(LocalIdentityId(next_id as u8))
    }

    fn compute_received_ack_tag(
        &self,
        buf: &[u8],
        header: &PacketHeader,
        body_range: core::ops::Range<usize>,
        keys: &PairwiseKeys,
    ) -> [u8; 8] {
        let mut cmac: CmacState<_> = self.crypto.cmac_state(&keys.k_mic);
        feed_aad(header, buf, |chunk| cmac.update(chunk));
        cmac.update(&buf[body_range]);
        let full_mac = cmac.finalize();
        self.crypto.compute_ack_tag(&full_mac, &keys.k_enc)
    }

    fn requeue_tx(&mut self, queued: &crate::QueuedTx<FRAME>) -> Result<u32, CapacityError> {
        self.tx_queue.enqueue_with_state(
            queued.priority,
            queued.frame.as_slice(),
            queued.receipt,
            queued.not_before_ms,
            queued.cad_attempts,
        )
    }

    fn accept_unicast_replay(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        header: &PacketHeader,
        frame: &[u8],
    ) -> bool {
        let Some((counter, mic)) = Self::replay_metadata(header, frame) else {
            return false;
        };
        let now_ms = self.clock.now_ms();
        let Some(window) = self
            .identity_mut(local_id)
            .and_then(|slot| slot.peer_crypto_mut().get_mut(&peer_id))
            .map(|state| &mut state.replay_window)
        else {
            return false;
        };

        if window.check(counter, mic, now_ms) != ReplayVerdict::Accept {
            return false;
        }

        window.accept(counter, mic, now_ms);
        true
    }

    fn accept_multicast_replay(
        &mut self,
        channel_id: ChannelId,
        peer_id: PeerId,
        header: &PacketHeader,
        frame: &[u8],
    ) -> bool {
        let Some((counter, mic)) = Self::replay_metadata(header, frame) else {
            return false;
        };
        let now_ms = self.clock.now_ms();
        let Some(channel) = self.channels.get_mut_by_id(&channel_id) else {
            return false;
        };

        if let Some(window) = channel.replay.get_mut(&peer_id) {
            if window.check(counter, mic, now_ms) != ReplayVerdict::Accept {
                return false;
            }
            window.accept(counter, mic, now_ms);
            return true;
        }

        let mut window = ReplayWindow::new();
        window.accept(counter, mic, now_ms);
        channel.replay.insert(peer_id, window).is_ok()
    }

    fn replay_metadata<'a>(header: &PacketHeader, frame: &'a [u8]) -> Option<(u32, &'a [u8])> {
        let counter = header.sec_info?.frame_counter;
        let mic = frame.get(header.mic_range.clone())?;
        Some((counter, mic))
    }

    fn find_local_identity_for_dst(
        &self,
        dst: Option<umsh_core::NodeHint>,
    ) -> Option<LocalIdentityId> {
        let dst = dst?;
        self.identities
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.as_ref()
                    .map(|slot| slot.identity().public_key().hint() == dst)
                    .unwrap_or(false)
            })
            .map(|(index, _)| LocalIdentityId(index as u8))
    }

    fn resolve_source_peer(
        &self,
        frame: &[u8],
        header: &PacketHeader,
    ) -> Option<(PeerId, PublicKey)> {
        match header.source {
            SourceAddrRef::FullKeyAt { offset } => {
                let mut key = [0u8; 32];
                key.copy_from_slice(frame.get(offset..offset + 32)?);
                let public_key = PublicKey(key);
                let (peer_id, _) = self.peer_registry.lookup_by_key(&public_key)?;
                Some((peer_id, public_key))
            }
            SourceAddrRef::Hint(hint) => {
                let mut matches = self.peer_registry.lookup_by_hint(&hint);
                let (peer_id, info) = matches.next()?;
                if matches.next().is_some() {
                    return None;
                }
                Some((peer_id, info.public_key))
            }
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => None,
        }
    }

    fn resolve_source_peer_candidates(
        &self,
        frame: &[u8],
        header: &PacketHeader,
    ) -> Vec<(PeerId, PublicKey), PEERS> {
        match header.source {
            SourceAddrRef::FullKeyAt { .. } => self
                .resolve_source_peer(frame, header)
                .into_iter()
                .collect(),
            SourceAddrRef::Hint(hint) => self
                .peer_registry
                .lookup_by_hint(&hint)
                .map(|(peer_id, info)| (peer_id, info.public_key))
                .collect(),
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => Vec::new(),
        }
    }

    fn resolve_multicast_source(
        &mut self,
        frame: &[u8],
        header: &PacketHeader,
    ) -> Option<(PeerId, PublicKey)> {
        match header.source {
            SourceAddrRef::FullKeyAt { offset } => {
                let mut key = [0u8; 32];
                key.copy_from_slice(frame.get(offset..offset + 32)?);
                let public_key = PublicKey(key);
                let peer_id = self.peer_registry.try_insert_or_update(public_key).ok()?;
                Some((peer_id, public_key))
            }
            SourceAddrRef::Hint(hint) => self.resolve_unique_hint(hint),
            SourceAddrRef::Encrypted { offset, len } => match len {
                32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(frame.get(offset..offset + 32)?);
                    let public_key = PublicKey(key);
                    let peer_id = self.peer_registry.try_insert_or_update(public_key).ok()?;
                    Some((peer_id, public_key))
                }
                3 => {
                    let hint = umsh_core::NodeHint([
                        *frame.get(offset)?,
                        *frame.get(offset + 1)?,
                        *frame.get(offset + 2)?,
                    ]);
                    self.resolve_unique_hint(hint)
                }
                _ => None,
            },
            SourceAddrRef::None => None,
        }
    }

    fn resolve_blind_source_peer(
        &self,
        frame: &[u8],
        source: SourceAddrRef,
    ) -> Option<(PeerId, PublicKey)> {
        match source {
            SourceAddrRef::FullKeyAt { offset } => {
                let mut key = [0u8; 32];
                key.copy_from_slice(frame.get(offset..offset + 32)?);
                let public_key = PublicKey(key);
                let (peer_id, _) = self.peer_registry.lookup_by_key(&public_key)?;
                Some((peer_id, public_key))
            }
            SourceAddrRef::Hint(hint) => self.resolve_unique_hint(hint),
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => None,
        }
    }

    fn resolve_blind_source_peer_candidates(
        &self,
        frame: &[u8],
        source: SourceAddrRef,
    ) -> Vec<(PeerId, PublicKey), PEERS> {
        match source {
            SourceAddrRef::FullKeyAt { .. } => self
                .resolve_blind_source_peer(frame, source)
                .into_iter()
                .collect(),
            SourceAddrRef::Hint(hint) => self
                .peer_registry
                .lookup_by_hint(&hint)
                .map(|(peer_id, info)| (peer_id, info.public_key))
                .collect(),
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => Vec::new(),
        }
    }

    fn resolve_unique_hint(&self, hint: umsh_core::NodeHint) -> Option<(PeerId, PublicKey)> {
        let mut matches = self.peer_registry.lookup_by_hint(&hint);
        let (peer_id, info) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some((peer_id, info.public_key))
    }

    fn learn_route_for_peer(&mut self, peer_id: PeerId, frame: &[u8], header: &PacketHeader) {
        let now_ms = self.clock.now_ms();
        self.peer_registry.touch(peer_id, now_ms);

        let Ok(options) = ParsedOptions::extract(frame, header.options_range.clone()) else {
            return;
        };

        if let Some(trace_range) = options.trace_route {
            if let Some(route) = self.reverse_trace_route(frame.get(trace_range).unwrap_or(&[])) {
                self.peer_registry
                    .update_route(peer_id, crate::CachedRoute::Source(route));
                return;
            }
        }

        if let Some(flood_hops) = header.flood_hops {
            self.peer_registry.update_route(
                peer_id,
                crate::CachedRoute::Flood {
                    hops: flood_hops.accumulated(),
                },
            );
        }
    }

    fn resolve_broadcast_source(
        frame: &[u8],
        header: &PacketHeader,
    ) -> Option<(umsh_core::NodeHint, Option<PublicKey>)> {
        match header.source {
            SourceAddrRef::Hint(hint) => Some((hint, None)),
            SourceAddrRef::FullKeyAt { offset } => {
                let mut key = [0u8; 32];
                key.copy_from_slice(frame.get(offset..offset + 32)?);
                let public_key = PublicKey(key);
                Some((public_key.hint(), Some(public_key)))
            }
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => None,
        }
    }

    fn payload_is_allowed(packet_type: PacketType, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }

        let payload_type = payload[0];
        if payload_type & 0x80 != 0 {
            return false;
        }
        if matches!(payload_type, 4 | 6) {
            return false;
        }

        match packet_type {
            PacketType::Broadcast => matches!(payload_type, 1),
            PacketType::Multicast => !matches!(payload_type, 2 | 5),
            PacketType::Unicast
            | PacketType::UnicastAckReq
            | PacketType::BlindUnicast
            | PacketType::BlindUnicastAckReq => true,
            PacketType::MacAck | PacketType::Reserved5 => false,
        }
    }

    fn reverse_trace_route(
        &self,
        trace_bytes: &[u8],
    ) -> Option<heapless::Vec<RouterHint, { crate::MAX_SOURCE_ROUTE_HOPS }>> {
        if trace_bytes.len() % 2 != 0 {
            return None;
        }

        let mut route = heapless::Vec::new();
        for chunk in trace_bytes.chunks_exact(2).rev() {
            route.push(RouterHint([chunk[0], chunk[1]])).ok()?;
        }
        Some(route)
    }

    fn should_emit_destination_ack(&self, frame: &[u8], header: &PacketHeader) -> bool {
        let Ok(options) = ParsedOptions::extract(frame, header.options_range.clone()) else {
            return false;
        };

        options
            .source_route
            .map(|range| range.is_empty())
            .unwrap_or(true)
    }

    fn maybe_forward_received(
        &mut self,
        frame: &[u8],
        header: &PacketHeader,
        rx: &RxInfo,
        locally_handled_unicast: bool,
    ) -> bool {
        if !self.repeater.enabled || !header.packet_type().is_secure() {
            return false;
        }
        if locally_handled_unicast
            && matches!(
                header.packet_type(),
                PacketType::Unicast
                    | PacketType::UnicastAckReq
                    | PacketType::BlindUnicast
                    | PacketType::BlindUnicastAckReq
            )
        {
            return false;
        }

        let Ok(options) = ParsedOptions::extract(frame, header.options_range.clone()) else {
            return false;
        };
        let Some(cache_key) = Self::forward_dup_key(header, frame) else {
            return false;
        };
        if self.dup_cache.contains(&cache_key) {
            self.cancel_pending_forward(&cache_key);
            return false;
        }

        let Some(plan) = self.plan_forwarding(frame, header, &options, rx) else {
            return false;
        };

        let mut rewritten = [0u8; FRAME];
        let Ok(total_len) =
            self.rewrite_forwarded_frame(frame, header, &options, plan, &mut rewritten)
        else {
            return false;
        };
        if total_len > self.radio.max_frame_size() {
            return false;
        }

        let now_ms = self.clock.now_ms();
        if self
            .tx_queue
            .enqueue_with_state(
                TxPriority::Forward,
                &rewritten[..total_len],
                None,
                now_ms.saturating_add(plan.delay_ms),
                0,
            )
            .is_err()
        {
            return false;
        }
        self.dup_cache.insert(cache_key, now_ms);
        true
    }

    fn plan_forwarding(
        &mut self,
        frame: &[u8],
        header: &PacketHeader,
        options: &ParsedOptions,
        rx: &RxInfo,
    ) -> Option<ForwardPlan> {
        if options.has_unknown_critical {
            return None;
        }
        if let Some(min_rssi) = Self::effective_min_rssi(options, &self.repeater) {
            if rx.rssi < min_rssi {
                return None;
            }
        }
        if let Some(min_snr) = Self::effective_min_snr(options, &self.repeater) {
            if rx.snr < min_snr {
                return None;
            }
        }

        let router_hint = self.repeater_router_hint()?;
        let station_action = self.classify_forward_station_action(frame, header)?;

        let source_route_bytes = options
            .source_route
            .as_ref()
            .and_then(|range| frame.get(range.clone()))
            .unwrap_or(&[]);
        if source_route_bytes.len() % 2 != 0 {
            return None;
        }

        let mut consume_source_route = false;
        let mut decrement_flood_hops = false;
        let mut delay_ms = 0u64;

        if !source_route_bytes.is_empty() {
            if source_route_bytes[..2] != router_hint.0 {
                return None;
            }
            consume_source_route = true;
            if source_route_bytes.len() == 2 {
                decrement_flood_hops = true;
            }
        } else {
            decrement_flood_hops = true;
        }

        if decrement_flood_hops {
            let flood_hops = header.flood_hops?;
            if flood_hops.remaining() == 0 {
                return None;
            }
            if let Some(region_code) = options.region_code {
                if !self
                    .repeater
                    .regions
                    .iter()
                    .any(|configured| *configured == region_code)
                {
                    return None;
                }
            }
            delay_ms = self.sample_flood_contention_delay_ms(rx, options);
        }

        Some(ForwardPlan {
            router_hint,
            consume_source_route,
            decrement_flood_hops,
            delay_ms,
            station_action,
        })
    }

    fn classify_forward_station_action(
        &self,
        frame: &[u8],
        header: &PacketHeader,
    ) -> Option<ForwardStationAction> {
        let has_operator_callsign = if header.options_range.is_empty() {
            false
        } else {
            umsh_core::iter_options(frame, header.options_range.clone())
                .filter_map(Result::ok)
                .any(|(number, _)| OptionNumber::from(number) == OptionNumber::OperatorCallsign)
        };
        let encrypted = header
            .sec_info
            .map(|sec| sec.scf.encrypted())
            .unwrap_or(false);

        match self.repeater.amateur_radio_mode {
            AmateurRadioMode::Unlicensed => Some(ForwardStationAction::Remove),
            AmateurRadioMode::LicensedOnly => {
                if encrypted || !has_operator_callsign || self.repeater.station_callsign.is_none() {
                    None
                } else {
                    Some(ForwardStationAction::Replace)
                }
            }
            AmateurRadioMode::Hybrid => {
                if !encrypted && has_operator_callsign {
                    self.repeater
                        .station_callsign
                        .as_ref()
                        .map(|_| ForwardStationAction::Replace)
                } else {
                    Some(ForwardStationAction::Remove)
                }
            }
        }
    }

    fn rewrite_forwarded_frame(
        &self,
        src: &[u8],
        header: &PacketHeader,
        options: &ParsedOptions,
        plan: ForwardPlan,
        dst: &mut [u8],
    ) -> Result<usize, CapacityError> {
        if dst.is_empty() {
            return Err(CapacityError);
        }

        let options_len =
            self.encode_forwarded_options(src, header, options, plan, &mut dst[1..])?;
        let mut cursor = 1 + options_len;
        let has_options = options_len > 0;
        dst[0] = umsh_core::Fcf::new(
            header.packet_type(),
            header.fcf.full_source(),
            has_options,
            header.flood_hops.is_some(),
        )
        .0;

        if let Some(flood_hops) = header.flood_hops {
            let next = if plan.decrement_flood_hops {
                flood_hops.decremented().0
            } else {
                flood_hops.0
            };
            *dst.get_mut(cursor).ok_or(CapacityError)? = next;
            cursor += 1;
        }

        let fixed_start = header.options_range.end + usize::from(header.flood_hops.is_some());
        let tail = src.get(fixed_start..).ok_or(CapacityError)?;
        let end = cursor + tail.len();
        dst.get_mut(cursor..end)
            .ok_or(CapacityError)?
            .copy_from_slice(tail);
        Ok(end)
    }

    fn encode_forwarded_options(
        &self,
        src: &[u8],
        header: &PacketHeader,
        _options: &ParsedOptions,
        plan: ForwardPlan,
        dst: &mut [u8],
    ) -> Result<usize, CapacityError> {
        let mut encoder = OptionEncoder::new(dst);
        let mut inserted_station = false;
        let mut saw_station = false;
        let mut wrote_any = false;

        if !header.options_range.is_empty() {
            for entry in umsh_core::iter_options(src, header.options_range.clone()) {
                let (number, value) = entry.map_err(|_| CapacityError)?;
                if !inserted_station
                    && matches!(plan.station_action, ForwardStationAction::Replace)
                    && number > OptionNumber::StationCallsign.as_u16()
                {
                    encoder
                        .put(
                            OptionNumber::StationCallsign.as_u16(),
                            self.repeater
                                .station_callsign
                                .as_ref()
                                .ok_or(CapacityError)?
                                .as_trimmed_slice(),
                        )
                        .map_err(|_| CapacityError)?;
                    inserted_station = true;
                    wrote_any = true;
                }

                match OptionNumber::from(number) {
                    OptionNumber::TraceRoute => {
                        let mut trace = [0u8; crate::MAX_SOURCE_ROUTE_HOPS * 2 + 2];
                        trace[..2].copy_from_slice(&plan.router_hint.0);
                        trace[2..2 + value.len()].copy_from_slice(value);
                        encoder
                            .put(number, &trace[..2 + value.len()])
                            .map_err(|_| CapacityError)?;
                        wrote_any = true;
                    }
                    OptionNumber::SourceRoute if plan.consume_source_route => {
                        if value.len() < 2 || value.len() % 2 != 0 {
                            return Err(CapacityError);
                        }
                        if value.len() > 2 {
                            encoder
                                .put(number, &value[2..])
                                .map_err(|_| CapacityError)?;
                            wrote_any = true;
                        }
                    }
                    OptionNumber::StationCallsign => {
                        saw_station = true;
                        match plan.station_action {
                            ForwardStationAction::Remove => {}
                            ForwardStationAction::Replace => {
                                encoder
                                    .put(
                                        number,
                                        self.repeater
                                            .station_callsign
                                            .as_ref()
                                            .ok_or(CapacityError)?
                                            .as_trimmed_slice(),
                                    )
                                    .map_err(|_| CapacityError)?;
                                inserted_station = true;
                                wrote_any = true;
                            }
                        }
                    }
                    _ => {
                        encoder.put(number, value).map_err(|_| CapacityError)?;
                        wrote_any = true;
                    }
                }
            }
        }

        if matches!(plan.station_action, ForwardStationAction::Replace)
            && !inserted_station
            && !saw_station
        {
            encoder
                .put(
                    OptionNumber::StationCallsign.as_u16(),
                    self.repeater
                        .station_callsign
                        .as_ref()
                        .ok_or(CapacityError)?
                        .as_trimmed_slice(),
                )
                .map_err(|_| CapacityError)?;
            wrote_any = true;
        }
        if wrote_any {
            encoder.end_marker().map_err(|_| CapacityError)?;
            Ok(encoder.finish())
        } else {
            Ok(0)
        }
    }

    fn repeater_router_hint(&self) -> Option<RouterHint> {
        self.identities
            .iter()
            .filter_map(|slot| slot.as_ref())
            .next()
            .map(|slot| slot.identity().public_key().router_hint())
    }

    fn effective_min_rssi(options: &ParsedOptions, repeater: &RepeaterConfig) -> Option<i16> {
        match (options.min_rssi, repeater.min_rssi) {
            (Some(packet), Some(local)) => Some(packet.max(local)),
            (Some(packet), None) => Some(packet),
            (None, Some(local)) => Some(local),
            (None, None) => None,
        }
    }

    fn effective_min_snr(options: &ParsedOptions, repeater: &RepeaterConfig) -> Option<i8> {
        match (options.min_snr, repeater.min_snr) {
            (Some(packet), Some(local)) => Some(packet.max(local)),
            (Some(packet), None) => Some(packet),
            (None, Some(local)) => Some(local),
            (None, None) => None,
        }
    }

    fn sample_flood_contention_delay_ms(&mut self, rx: &RxInfo, options: &ParsedOptions) -> u64 {
        let threshold = i32::from(Self::effective_min_snr(options, &self.repeater).unwrap_or(0));
        let received = i32::from(rx.snr);
        let normalized = (20 - (received - threshold).clamp(0, 20)) as u32;
        let window_ms = self.radio.t_frame_ms().saturating_mul(normalized) / 20;
        if window_ms == 0 {
            0
        } else {
            u64::from(self.rng.random_range(..window_ms.saturating_add(1)))
        }
    }

    fn forward_dup_key(header: &PacketHeader, frame: &[u8]) -> Option<DupCacheKey> {
        if !header.packet_type().is_secure() {
            return None;
        }
        let mic = frame.get(header.mic_range.clone())?;
        if mic.is_empty() || mic.len() > 16 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes[..mic.len()].copy_from_slice(mic);
        Some(DupCacheKey::Mic {
            bytes,
            len: mic.len() as u8,
        })
    }

    fn cancel_pending_forward(&mut self, key: &DupCacheKey) {
        let _ = self.tx_queue.remove_first_matching(|entry| {
            entry.priority == TxPriority::Forward
                && Self::confirmation_key(entry.frame.as_slice())
                    .map(|entry_key| &entry_key == key)
                    .unwrap_or(false)
        });
    }

    async fn service_post_tx_listen(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        loop {
            self.expire_post_tx_listen_if_needed();
            if self.post_tx_listen.is_none() {
                return Ok(());
            }

            let handled = self.receive_one(&mut on_event).await?;
            if !handled {
                return Ok(());
            }
        }
    }

    fn arm_post_tx_listen(&mut self, receipt: SendReceipt, frame: &[u8]) {
        let Some(confirm_key) = Self::confirmation_key(frame) else {
            return;
        };
        let sent_ms = self.clock.now_ms();
        let duration_ms = self.sample_forward_confirm_window_ms();
        let deadline_ms = sent_ms.saturating_add(duration_ms);

        let Some((identity_id, pending)) = self.pending_ack_mut(receipt) else {
            return;
        };
        if !matches!(pending.state, crate::AckState::AwaitingForward { .. }) {
            return;
        }

        pending.sent_ms = sent_ms;
        pending.state = crate::AckState::AwaitingForward {
            confirm_deadline_ms: deadline_ms,
        };
        self.post_tx_listen = Some(PostTxListen {
            identity_id,
            receipt,
            confirm_key,
            deadline_ms,
        });
    }

    fn expire_post_tx_listen_if_needed(&mut self) {
        let should_clear = self
            .post_tx_listen
            .as_ref()
            .map(|listen| self.clock.now_ms() >= listen.deadline_ms)
            .unwrap_or(false);
        if should_clear {
            self.post_tx_listen = None;
        }
    }

    fn sample_forward_confirm_window_ms(&mut self) -> u64 {
        let base = self.radio.t_frame_ms();
        let span = base.saturating_mul(2).saturating_add(1);
        let jitter = self.rng.random_range(..span);
        u64::from(base.saturating_add(jitter))
    }

    fn pending_ack_mut(
        &mut self,
        receipt: SendReceipt,
    ) -> Option<(LocalIdentityId, &mut PendingAck<FRAME>)> {
        for (index, slot) in self.identities.iter_mut().enumerate() {
            let Some(slot) = slot.as_mut() else {
                continue;
            };
            if let Some(pending) = slot.pending_ack_mut(&receipt) {
                return Some((LocalIdentityId(index as u8), pending));
            }
        }
        None
    }

    fn confirmation_key(frame: &[u8]) -> Option<DupCacheKey> {
        let header = PacketHeader::parse(frame).ok()?;
        let mic = frame.get(header.mic_range)?;
        if mic.is_empty() || mic.len() > 16 {
            return None;
        }

        let mut bytes = [0u8; 16];
        bytes[..mic.len()].copy_from_slice(mic);
        Some(DupCacheKey::Mic {
            bytes,
            len: mic.len() as u8,
        })
    }

    fn observe_forwarding_confirmation(&mut self, frame: &[u8]) -> bool {
        self.expire_post_tx_listen_if_needed();
        let Some(listen) = self.post_tx_listen.clone() else {
            return false;
        };

        let Some(received_key) = Self::confirmation_key(frame) else {
            return false;
        };
        if received_key != listen.confirm_key {
            return false;
        }

        let Some(slot) = self.identity_mut(listen.identity_id) else {
            self.post_tx_listen = None;
            return false;
        };
        let Some(pending) = slot.pending_ack_mut(&listen.receipt) else {
            self.post_tx_listen = None;
            return false;
        };
        if !matches!(pending.state, crate::AckState::AwaitingForward { .. }) {
            self.post_tx_listen = None;
            return false;
        }

        pending.state = crate::AckState::AwaitingAck;
        self.post_tx_listen = None;
        true
    }

    fn match_pending_peer_for_ack(
        &self,
        slot: &IdentitySlot<P::Identity, PEERS, ACKS, FRAME>,
        ack_tag_bytes: &[u8],
    ) -> Option<PublicKey> {
        if ack_tag_bytes.len() != 8 {
            return None;
        }

        slot.pending_acks
            .iter()
            .find_map(|(_, pending)| (pending.ack_tag == ack_tag_bytes).then_some(pending.peer))
    }
}

fn align_counter_boundary(value: u32) -> u32 {
    value & !COUNTER_PERSIST_BLOCK_MASK
}

fn next_counter_persist_target(next_counter: u32) -> u32 {
    next_counter.wrapping_add(COUNTER_PERSIST_BLOCK_SIZE) & !COUNTER_PERSIST_BLOCK_MASK
}
