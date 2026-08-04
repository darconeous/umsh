use core::num::NonZeroU8;
use core::{future::poll_fn, task::Poll};

use hamaddr::HamAddr;
use heapless::{LinearMap, Vec};
use rand::{Rng, RngExt as _};
use umsh_core::{
    BuildError, ChannelId, ChannelKey, FloodHops, NodeHint, OptionNumber, PacketBuilder,
    PacketHeader, PacketType, ParseError, ParsedOptions, PayloadType, PublicKey, RouterHint,
    SourceAddrRef, UnsealedPacket, feed_aad, options::OptionEncoder,
};
use umsh_crypto::{
    CmacState, CryptoEngine, CryptoError, DerivedChannelKeys, NodeIdentity, PairwiseKeys,
};
use umsh_hal::{Clock, CounterStore, Radio, RxInfo, Snr, TxError, TxOptions};

use crate::{
    AddPeerError, CapacityError, DEFAULT_ACKS, DEFAULT_CHANNEL_HINT_REPLAY, DEFAULT_CHANNEL_REPLAY,
    DEFAULT_CHANNELS, DEFAULT_DUP, DEFAULT_IDENTITIES, DEFAULT_PEERS, DEFAULT_TX,
    ESTABLISHED_ROUTE_EXTRA_HOPS, MAX_CAD_ATTEMPTS, MAX_FLOOD_HOPS, MAX_FORWARD_RETRIES,
    MAX_RESEND_FRAME_LEN, MAX_SOURCE_ROUTE_HOPS, Platform, ReplayVerdict, ReplayWindow,
    cache::{DupCacheKey, DuplicateCache},
    peers::CachedRoute,
    peers::{ChannelTable, PeerCryptoMap, PeerId, PeerRegistry},
    send::{
        CompletionSignal, PendingAck, PendingAckError, ResendRecord, SendOptions, SendReceipt,
        TxPriority, TxQueue,
    },
};

/// Why [`Mac::poll_wait_for_wake`] returned ready.
///
/// Returned by the sync phase-2 poll so that callers sharing a coordinator
/// across tasks can decide when to re-acquire the exclusive borrow for
/// [`Mac::process_wake_reason`].
pub enum WakeReason {
    /// A frame was received; its metadata is attached and the caller-provided
    /// buffer has been populated with `rx.len` bytes.
    Received(RxInfo),
    /// At least one coordinator timer has elapsed (ACK deadline, post-TX
    /// listen window, or a deferred transmit becoming ready).
    TimerExpired,
}

const COUNTER_PERSIST_BLOCK_SIZE: u32 = 128;
const COUNTER_PERSIST_BLOCK_MASK: u32 = COUNTER_PERSIST_BLOCK_SIZE - 1;
const COUNTER_PERSIST_SCHEDULE_OFFSET: u32 = 100;
const MAC_COMMAND_ECHO_REQUEST_ID: u8 = 4;
const MAC_COMMAND_ECHO_RESPONSE_ID: u8 = 5;
const COUNTER_RESYNC_NONCE_LEN: usize = 4;
const COUNTER_RESYNC_REQUEST_RETRY_MS: u64 = 5_000;
/// Minimum backward gap (peer's `last_accepted` minus received counter) that
/// will trigger a counter-resync exchange. Gaps smaller than this are silently
/// dropped: they're indistinguishable from ordinary mesh reordering and would
/// otherwise cause resync churn whenever a slightly-late packet arrives. A
/// real desync (peer reboot, lost persistence boundary) typically produces a
/// jump much larger than this.
const COUNTER_RESYNC_GAP_THRESHOLD: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingCounterResync {
    nonce: u32,
    requested_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeferredCounterResyncFrame<const FRAME: usize> {
    local_id: LocalIdentityId,
    peer_id: PeerId,
    frame: Vec<u8, FRAME>,
    rssi: i16,
    snr: Snr,
    lqi: Option<NonZeroU8>,
    received_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedMulticastSource {
    peer_id: Option<PeerId>,
    public_key: Option<PublicKey>,
    hint: Option<NodeHint>,
}

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
///   established [`umsh_crypto::PairwiseKeys`] and replay window. Entries are populated on
///   first secure contact, or through the advanced manual-install escape hatch.
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
    pending_counter_resync: LinearMap<PeerId, PendingCounterResync, PEERS>,
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
            pending_counter_resync: LinearMap::new(),
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
    ///
    /// # Safety (logical)
    /// Misuse can break replay protection.
    #[cfg(test)]
    pub(crate) fn set_frame_counter(&mut self, value: u32) {
        self.frame_counter = value;
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
    pub(crate) fn advance_frame_counter(&mut self) -> u32 {
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
        if !self.counter_persistence_enabled {
            return false;
        }

        let ahead = self.persisted_counter.wrapping_sub(self.frame_counter);
        if ahead > 0 && ahead <= COUNTER_PERSIST_BLOCK_SIZE {
            return false;
        }

        if ahead == 0 {
            return self.save_scheduled_since_boot;
        }

        self.frame_counter.wrapping_sub(self.persisted_counter) >= COUNTER_PERSIST_BLOCK_SIZE
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

    /// Iterate every tracked in-flight send in this slot.
    ///
    /// Includes internally tracked repeat-confirmed sends, whose receipts are
    /// never returned to the application.
    pub fn pending_acks(&self) -> impl Iterator<Item = (&SendReceipt, &PendingAck<FRAME>)> {
        self.pending_acks.iter()
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

    /// Borrow the pending counter-resynchronization table.
    fn pending_counter_resync(&self) -> &LinearMap<PeerId, PendingCounterResync, PEERS> {
        &self.pending_counter_resync
    }

    /// Mutably borrow the pending counter-resynchronization table.
    fn pending_counter_resync_mut(
        &mut self,
    ) -> &mut LinearMap<PeerId, PendingCounterResync, PEERS> {
        &mut self.pending_counter_resync
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
    insert_region_code: Option<[u8; 2]>,
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
/// - **`regions`** — a local list of 2-byte ARNCE region codes used as the flood-forwarding
///   eligibility filter. When non-empty, packets carrying region codes are flood-forwarded only
///   if at least one of those codes appears here; when empty, forwarding imposes no region check
///   and a tagged packet is forwarded whatever its region.
/// - **`default_region`** — the region code inserted into a flood-forwarded packet that carries
///   none. `None` — the default — means the repeater never tags: untagged packets are forwarded
///   untagged. Tagging is deliberately opt-in and independent of `regions`, because inserting a
///   code asserts where the packet *is*, not merely which regions the repeater will carry. An
///   already-tagged packet is always forwarded with its codes unchanged.
/// - **`min_rssi` / `min_snr`** — signal-quality thresholds for flood forwarding. Packets
///   received below these values are not flood-forwarded; this prevents marginal receptions
///   from being re-injected into the network at full power, which would degrade SNR for
///   nearby nodes rather than help. These thresholds do not apply to source-routed hops.
/// - **Flood contention tuning** — controls the SNR-to-delay mapping used when several
///   eligible repeaters contend to flood-forward the same frame. These values should usually
///   remain aligned across the mesh.
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
    /// Allowed repeater region codes. Empty imposes no region check.
    pub regions: Vec<[u8; 2], 8>,
    /// Region code inserted into an untagged flood-forwarded packet.
    /// `None` forwards untagged packets untagged.
    pub default_region: Option<[u8; 2]>,
    /// Minimum RSSI threshold for flood forwarding.
    pub min_rssi: Option<i16>,
    /// Minimum SNR threshold for flood forwarding.
    pub min_snr: Option<i8>,
    /// Lower clamp bound for SNR-based flood forwarding contention.
    pub flood_contention_snr_low_db: i8,
    /// Upper clamp bound for SNR-based flood forwarding contention.
    pub flood_contention_snr_high_db: i8,
    /// Minimum forwarding contention window as a percentage of `T_frame`.
    pub flood_contention_min_window_percent: u8,
    /// Maximum forwarding contention window as a multiple of `T_frame`.
    pub flood_contention_max_window_frames: u8,
    /// ACK protection interval as a percentage of `T_frame`, added to the
    /// contention delay when flood-forwarding an ack-requested packet that was
    /// received with no remaining source-route hops (see channel-access.md
    /// § ACK Protection Interval).
    pub flood_contention_ack_guard_percent: u8,
    /// Maximum number of overheard-repeat deferrals before abandoning a pending forward.
    pub flood_contention_max_deferrals: u8,
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
            default_region: None,
            min_rssi: None,
            min_snr: None,
            flood_contention_snr_low_db: -6,
            flood_contention_snr_high_db: 15,
            flood_contention_min_window_percent: 20,
            flood_contention_max_window_frames: 2,
            flood_contention_ack_guard_percent: 25,
            flood_contention_max_deferrals: 3,
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
    /// No cached pairwise session keys exist for the target peer on this identity.
    /// This is only returned by the low-level `queue_*` APIs; the public async send APIs
    /// derive and cache peer state automatically.
    PairwiseKeysMissing,
    /// The local identity failed to derive a shared secret for this peer.
    IdentityAgreementFailed,
    /// The target [`umsh_core::ChannelId`] is not present in the channel table.
    /// Register the channel first via [`Mac::add_channel`] or [`Mac::add_named_channel`].
    ChannelMissing,
    /// The [`OperatingPolicy`] rejected this send — for example, attempting to send an
    /// encrypted frame while operating in [`AmateurRadioMode::LicensedOnly`] mode.
    PolicyViolation,
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
    /// A transmit-phase error from the radio. The frame was not sent.
    ///
    /// Channel-busy (CAD) verdicts are not surfaced here: they are retried
    /// with backoff, and exhausting the retry budget emits
    /// [`MacEventRef::TxAbandoned`](crate::MacEventRef::TxAbandoned) instead.
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
/// 3. **Register peers** via [`Mac::add_peer`]. Secure unicast and blind-unicast state is
///    derived lazily from the local private key and peer public key on first use.
/// 4. **Register channels** via [`Mac::add_channel`] or [`Mac::add_named_channel`].
/// 5. **Drive the event loop** via [`Mac::run`] / [`Mac::run_quiet`] for long-lived tasks,
///    or by awaiting [`Mac::next_event`] when you need to multiplex MAC progress with other
///    async work. The coordinator handles incoming frames, outgoing transmits, forwarding,
///    ACK matching, retransmission scheduling, and timer deadlines — no external polling
///    required.
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
/// mac.run(|id, event| {
///     let _ = (id, event);
///     // handle deliveries / ACKs here and schedule persistence work as needed
/// }).await?;
/// ```
/// Cumulative frame tallies for the coordinator, since construction.
///
/// Diagnostic only: nothing in the protocol depends on them, and they are
/// deliberately not persisted. They exist so an operator can tell a
/// working node from a deaf one without a capture — a radio whose
/// `rx_frames` never moves is not hearing anybody.
///
/// Every field saturates rather than wraps. A counter that rolled over
/// would make a long-running node look freshly booted; pinning at the
/// maximum is at least monotone, which is the property a reader is
/// actually using them for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacCounters {
    /// Frames the radio accepted for transmission, including forwards.
    pub tx_frames: u32,
    /// Frames given up on after [`MAX_CAD_ATTEMPTS`] busy channels.
    pub tx_abandoned: u32,
    /// Frames the radio handed up, whoever they were addressed to.
    pub rx_frames: u32,
    /// Receptions that produced an event or a side effect. The shortfall
    /// against [`Self::rx_frames`] is other people's traffic, duplicates,
    /// and undecodable noise.
    pub rx_accepted: u32,
    /// Receptions this node repeated onward.
    pub forwarded: u32,
    /// Queued forwards dropped because the destination's ack was overheard
    /// before they went out. Airtime this node did not have to spend.
    pub forward_cancelled: u32,
}

impl MacCounters {
    fn bump(slot: &mut u32) {
        *slot = slot.saturating_add(1);
    }
}

pub struct Mac<
    P: Platform,
    const IDENTITIES: usize = DEFAULT_IDENTITIES,
    const PEERS: usize = DEFAULT_PEERS,
    const CHANNELS: usize = DEFAULT_CHANNELS,
    const ACKS: usize = DEFAULT_ACKS,
    const TX: usize = DEFAULT_TX,
    const FRAME: usize = MAX_RESEND_FRAME_LEN,
    const DUP: usize = DEFAULT_DUP,
    const RN: usize = DEFAULT_CHANNEL_REPLAY,
    const HN: usize = DEFAULT_CHANNEL_HINT_REPLAY,
> {
    radio: P::Radio,
    crypto: CryptoEngine<P::Aes, P::Sha>,
    clock: P::Clock,
    rng: P::Rng,
    counter_store: P::CounterStore,
    identities: Vec<Option<IdentitySlot<P::Identity, PEERS, ACKS, FRAME>>, IDENTITIES>,
    peer_registry: PeerRegistry<PEERS>,
    channels: ChannelTable<CHANNELS, RN, HN>,
    dup_cache: DuplicateCache<DUP>,
    multicast_unknown_dup_cache: DuplicateCache<DUP>,
    tx_queue: TxQueue<TX, FRAME>,
    post_tx_listen: Option<PostTxListen>,
    repeater: RepeaterConfig,
    operating_policy: OperatingPolicy,
    auto_register_full_key_peers: bool,
    deferred_counter_resync_frame: Option<DeferredCounterResyncFrame<FRAME>>,
    counters: MacCounters,
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
    const RN: usize,
    const HN: usize,
> Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP, RN, HN>
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
            multicast_unknown_dup_cache: DuplicateCache::new(),
            tx_queue: TxQueue::new(),
            post_tx_listen: None,
            repeater,
            operating_policy,
            auto_register_full_key_peers: false,
            deferred_counter_resync_frame: None,
            counters: MacCounters::default(),
        }
    }

    /// Cumulative frame tallies since construction.
    pub const fn counters(&self) -> MacCounters {
        self.counters
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
    pub fn channels(&self) -> &ChannelTable<CHANNELS, RN, HN> {
        &self.channels
    }
    /// Mutably borrow the channel table.
    pub fn channels_mut(&mut self) -> &mut ChannelTable<CHANNELS, RN, HN> {
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

    /// Return whether inbound secure packets carrying a full source key may auto-register peers.
    pub fn auto_register_full_key_peers(&self) -> bool {
        self.auto_register_full_key_peers
    }

    /// Enable or disable inbound full-key peer auto-registration.
    pub fn set_auto_register_full_key_peers(&mut self, enabled: bool) {
        self.auto_register_full_key_peers = enabled;
    }

    /// Register one long-term local identity.
    pub fn add_identity(
        &mut self,
        identity: P::Identity,
    ) -> Result<LocalIdentityId, CapacityError> {
        self.insert_identity(LocalIdentity::LongTerm(identity), None)
    }

    /// Load the persisted frame-counter boundary for `id` from the counter store.
    ///
    /// # Flash-wear invariant
    ///
    /// This method must remain read-only. In particular, booting or repeatedly
    /// rebooting without transmitting must never write a new reservation and
    /// wear out embedded flash. The first authenticated send schedules the
    /// future reservation; the MAC driver services that pending write because
    /// actual transmission has made persistence necessary.
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
        // Zero is the store's missing-record sentinel. Keep the random non-zero
        // initial value in that case; it covers both a fresh identity and
        // counter-state loss for an identity that survived in a separate secret
        // store. Do not persist here: see the flash-wear invariant above.
        if loaded == 0 {
            let slot = self
                .identity(id)
                .ok_or(CounterPersistenceError::IdentityMissing)?;
            return Ok(slot.frame_counter());
        }
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

    /// Persist RX frame-counter boundaries for all peers that have received
    /// enough frames since the last flush.
    ///
    /// Called automatically from [`Self::next_event`] so applications need not
    /// invoke this directly.
    pub(crate) async fn service_rx_counter_persistence(
        &mut self,
    ) -> Result<usize, <P::CounterStore as CounterStore>::Error> {
        // Collect all (identity_index, peer_id, peer_pk, last_accepted) tuples
        // that need persisting. We collect before awaiting to avoid holding
        // live references across the async CounterStore calls.
        let mut pending: heapless::Vec<(u8, crate::peers::PeerId, [u8; 32], u32), PEERS> =
            heapless::Vec::new();

        for (identity_index, slot) in self.identities.iter().enumerate() {
            let Some(slot) = slot.as_ref() else {
                continue;
            };
            for (peer_id, state) in slot.peer_crypto().iter() {
                if !state.needs_rx_persist {
                    continue;
                }
                let Some(info) = self.peer_registry.get(*peer_id) else {
                    continue;
                };
                let _ = pending.push((
                    identity_index as u8,
                    *peer_id,
                    info.public_key.0,
                    state.replay_window.last_accepted,
                ));
            }
        }

        let mut wrote = 0usize;
        for (_, _, pk, last) in pending.iter() {
            let key = rx_counter_key_bytes(pk);
            self.counter_store.store(&key, *last).await?;
            wrote += 1;
        }
        if wrote > 0 {
            self.counter_store.flush().await?;
            // Clear flags and update persisted_rx_counter only after a
            // successful flush.
            for (identity_index, peer_id, _, last) in pending.iter() {
                if let Some(slot) = self.identities[*identity_index as usize].as_mut() {
                    if let Some(state) = slot.peer_crypto_mut().get_mut(peer_id) {
                        state.persisted_rx_counter = *last;
                        state.needs_rx_persist = false;
                    }
                }
            }
        }
        Ok(wrote)
    }

    /// Load persisted RX frame-counter boundaries for all registered peers and
    /// store them in [`PeerInfo::initial_rx_counter`].
    ///
    /// Call this once at boot after registering all known peers. When pairwise
    /// keys are first derived for each peer, the replay window is initialised
    /// to the loaded boundary so frames replayed from before the reboot are
    /// rejected.
    pub async fn load_all_persisted_rx_counters(
        &mut self,
    ) -> Result<usize, <P::CounterStore as CounterStore>::Error> {
        let mut loaded = 0usize;
        // PeerRegistry is a dense Vec; PeerId(i) == index i. Break on first None.
        for peer_index in 0..PEERS {
            let peer_id = crate::peers::PeerId(peer_index as u8);
            let Some(info) = self.peer_registry.get(peer_id) else {
                break;
            };
            let pk = info.public_key;
            let key = rx_counter_key_bytes(&pk.0);
            let stored = self.counter_store.load(&key).await?;
            if stored > 0 {
                if let Some(info) = self.peer_registry.get_mut(peer_id) {
                    info.initial_rx_counter = stored;
                    loaded += 1;
                }
            }
        }
        Ok(loaded)
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
    ///
    /// When the `software-crypto` feature is enabled, the supplied public key
    /// is validated as a well-formed Ed25519 compressed point on the curve.
    /// Malformed keys are rejected with [`AddPeerError::InvalidPublicKey`]
    /// before they can pollute the peer registry.
    pub fn add_peer(&mut self, key: PublicKey) -> Result<PeerId, AddPeerError> {
        #[cfg(feature = "software-crypto")]
        {
            if !umsh_crypto::is_valid_ed25519_public_key(&key) {
                return Err(AddPeerError::InvalidPublicKey);
            }
        }
        Ok(self.peer_registry.try_insert_or_update(key)?)
    }

    /// Removes a registered peer and every piece of per-peer transport state:
    /// pairwise crypto, replay windows, pending counter resyncs, and any
    /// deferred inbound frame. Returns whether the peer was registered.
    ///
    /// The peer registry is dense, so removal moves the last entry into the
    /// freed slot; state keyed by the moved peer's old identifier is re-keyed
    /// here. Persisted RX counter boundaries are deliberately retained: if
    /// the peer is re-added later, replay protection resumes from the stored
    /// boundary instead of accepting replays from before the removal.
    pub fn remove_peer(&mut self, key: &PublicKey) -> bool {
        let Some((peer_id, _)) = self.peer_registry.lookup_by_key(key) else {
            return false;
        };
        self.clear_peer_slot_state(peer_id);
        if self
            .deferred_counter_resync_frame
            .as_ref()
            .is_some_and(|deferred| deferred.peer_id == peer_id)
        {
            self.deferred_counter_resync_frame = None;
        }
        let Some(removal) = self.peer_registry.remove(peer_id) else {
            return false;
        };
        if let Some((old_id, new_id)) = removal.moved {
            self.rekey_peer_slot_state(old_id, new_id);
        }
        true
    }

    /// Adds or updates a shared channel and derives its multicast keys.
    pub fn add_channel(&mut self, key: ChannelKey) -> Result<(), CapacityError> {
        let derived = self.crypto.derive_channel_keys(&key);
        self.channels.try_add(key, derived)
    }

    /// Removes a previously added channel by its exact key, discarding
    /// the channel's replay state with it (re-adding the key later
    /// starts at first contact). Returns whether a channel was removed.
    pub fn remove_channel(&mut self, key: &ChannelKey) -> bool {
        self.channels.remove_by_key(key)
    }

    /// Adds or updates a named channel using the coordinator's channel-key derivation.
    ///
    /// The name is canonicalized (ASCII lowercase fold) before derivation, so
    /// `Public` and `public` register the same channel.
    pub fn add_named_channel(&mut self, name: &str) -> Result<(), crate::AddChannelError> {
        let key = self
            .crypto
            .derive_named_channel_key(name)
            .map_err(crate::AddChannelError::InvalidName)?;
        self.add_channel(key)?;
        Ok(())
    }

    /// Return the number of occupied identity slots.
    pub fn identity_count(&self) -> usize {
        self.identities.iter().filter(|slot| slot.is_some()).count()
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// # Safety (logical)
    /// Installing wrong keys will silently corrupt the session. This method
    /// is crate-internal; external callers should use the `unsafe-advanced`
    /// feature or go through the node-layer PFS session manager.
    #[cfg(any(feature = "unsafe-advanced", test))]
    pub(crate) fn install_pairwise_keys(
        &mut self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, SendError> {
        // Read initial_rx_counter and clock before the mutable identity borrow.
        let initial = self
            .peer_registry
            .get(peer_id)
            .map(|info| info.initial_rx_counter)
            .unwrap_or(0);
        let now_ms = self.clock.now_ms();
        let mut replay_window = ReplayWindow::new();
        if initial > 0 {
            replay_window.reset(initial, now_ms);
        }
        let slot = self
            .identity_mut(identity_id)
            .ok_or(SendError::IdentityMissing)?;
        slot.peer_crypto_mut()
            .insert(
                peer_id,
                crate::peers::PeerCryptoState {
                    pairwise_keys,
                    replay_window,
                    persisted_rx_counter: initial,
                    needs_rx_persist: false,
                },
            )
            .map_err(|_| SendError::QueueFull)
    }

    /// Installs pairwise transport keys for one local identity and remote peer.
    ///
    /// # Safety (logical)
    /// Installing wrong keys will silently corrupt the session. This method
    /// is deliberately gated behind the `unsafe-advanced` feature. Prefer
    /// going through the node-layer PFS session manager instead.
    #[cfg(feature = "unsafe-advanced")]
    pub fn install_pairwise_keys_advanced(
        &mut self,
        identity_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<Option<crate::peers::PeerCryptoState>, SendError> {
        self.install_pairwise_keys(identity_id, peer_id, pairwise_keys)
    }

    /// Enqueues a broadcast frame for transmission.
    ///
    /// Note: the `encrypted`, `ack_requested`, and `salt` flags on `options`
    /// are silently forced to `false` because broadcasts cannot carry any of
    /// them on the wire.
    ///
    /// TODO: this sanitization is silent — a caller that explicitly set
    /// `ack_requested = true` for a broadcast will get a successful
    /// `SendReceipt` and never learn the flag was dropped. Surface this as a
    /// debug-level event (or split `SendOptions` into kind-specific
    /// builders) so the loss is observable.
    pub fn queue_broadcast(
        &mut self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        // Broadcasts are always unencrypted, never ack-requested, and never
        // salted by the MAC. Sanitize before policy classification so a reused
        // `SendOptions` (whose default `encrypted = true`) doesn't get rejected
        // as a `PolicyViolation` in `LicensedOnly` mode for a send that will
        // in fact go out unencrypted.
        let mut options = options.clone();
        options.encrypted = false;
        options.ack_requested = false;
        options.salt = false;
        let options = &options;
        self.enforce_send_policy(None, options, false)?;

        let slot = self.identity_mut(from).ok_or(SendError::IdentityMissing)?;
        let source_key = *slot.identity().public_key();
        let receipt = slot.next_receipt();
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
        if options.trace_route {
            builder = builder.trace_route();
        }
        // A route that constrains no hop is not attached: only a repeater
        // consuming the final hint may leave an empty SourceRoute option.
        if let Some(route) = options
            .source_route
            .as_ref()
            .filter(|route| !route.is_empty())
        {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let frame = builder.payload(payload).build()?;
        if frame.len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        let not_before_ms = self.tx_not_before_ms(options);
        self.tx_queue
            .enqueue_with_state(
                TxPriority::Application,
                frame,
                Some(receipt),
                Some(from),
                not_before_ms,
                0,
                0,
            )
            .map_err(|_| SendError::QueueFull)?;
        Ok(receipt)
    }

    /// Enqueue a broadcast frame for transmission.
    pub async fn send_broadcast(
        &mut self,
        from: LocalIdentityId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        self.queue_broadcast(from, payload, options)
    }

    /// Enqueues a multicast frame using the configured channel keys.
    pub fn queue_multicast(
        &mut self,
        from: LocalIdentityId,
        channel_id: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        self.enforce_send_policy(Some(*channel_id), options, false)?;
        // Multicast has no unicast receiver to ack, so an `ack_requested`
        // flag carried over from shared `SendOptions` is silently ignored.
        // TODO: surface this drop as a debug-level event (see the matching
        // TODO on `queue_broadcast`) so callers can detect when their
        // requested flags were not applied.

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
        let receipt = self
            .identity_mut(from)
            .ok_or(SendError::IdentityMissing)?
            .next_receipt();
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
        if options.trace_route {
            builder = builder.trace_route();
        }
        // A route that constrains no hop is not attached: only a repeater
        // consuming the final hint may leave an empty SourceRoute option.
        if let Some(route) = options
            .source_route
            .as_ref()
            .filter(|route| !route.is_empty())
        {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
        }
        if let Some(callsign) = self.operating_policy.operator_callsign {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        let mut packet = builder.payload(payload).build()?;
        self.crypto.seal_packet(&mut packet, &keys)?;
        let not_before_ms = self.tx_not_before_ms(options);
        self.enqueue_packet(packet, Some(receipt), Some(from), not_before_ms)?;
        Ok(receipt)
    }

    /// Enqueue a multicast frame for transmission.
    pub async fn send_multicast(
        &mut self,
        from: LocalIdentityId,
        channel_id: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendReceipt, SendError> {
        self.queue_multicast(from, channel_id, payload, options)
    }

    /// Enqueues a MAC ACK frame, using any cached route to `peer_id` when available.
    pub fn queue_mac_ack_for_peer(
        &mut self,
        peer_id: PeerId,
        ack_trailer: [u8; 8],
    ) -> Result<(), SendError> {
        let mut buf = [0u8; FRAME];
        let mut builder = PacketBuilder::new(&mut buf).mac_ack(ack_trailer);
        if let Some(peer) = self.peer_registry.get(peer_id) {
            match peer.route.as_ref() {
                Some(CachedRoute::Source(route)) if !route.is_empty() => {
                    builder = builder.source_route(route.as_slice());
                }
                Some(CachedRoute::Flood { hops, regions }) => {
                    builder = builder.flood_hops((*hops).clamp(1, MAX_FLOOD_HOPS));
                    for region in regions {
                        builder = builder.region_code(*region);
                    }
                }
                // Direct, unknown, or a route that constrains no hop: there
                // is nothing to attach, and an empty option must not be
                // originated.
                _ => {}
            }
        }
        let frame = builder.build()?;
        if frame.len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue(TxPriority::ImmediateAck, frame, None, None)
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    /// Enqueues an immediate direct MAC ACK frame.
    pub fn queue_mac_ack(&mut self, ack_trailer: [u8; 8]) -> Result<(), SendError> {
        let mut buf = [0u8; FRAME];
        let frame = PacketBuilder::new(&mut buf).mac_ack(ack_trailer).build()?;
        if frame.len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue(TxPriority::ImmediateAck, frame, None, None)
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
        let effective_source_route = self.effective_source_route(peer_id, options);
        let effective_flood_hops =
            self.effective_flood_hops(peer_id, options, effective_source_route.as_ref());

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
        if let Some(hops) = effective_flood_hops {
            builder = builder.flood_hops(hops);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = effective_source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
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
                effective_source_route
                    .as_ref()
                    .map(|route| route.as_slice()),
                options.flood_hops,
            )?;
        }
        // A non-ACK send that rides through repeaters is tracked under an
        // internal receipt so it can retry until a repeat is heard. The caller
        // asked for no tracking and sees none.
        let tracked_receipt = match receipt {
            Some(receipt) => Some(receipt),
            None if Self::send_has_hops(effective_source_route.as_ref(), effective_flood_hops) => {
                Some(self.prepare_repeat_confirmed_send(
                    from,
                    *peer,
                    packet.as_bytes(),
                    effective_source_route.as_ref(),
                    options.flood_hops,
                )?)
            }
            None => None,
        };
        let not_before_ms = self.tx_not_before_ms(options);
        if let Err(err) = self.enqueue_packet(packet, tracked_receipt, Some(from), not_before_ms) {
            if let Some(tracked_receipt) = tracked_receipt {
                let _ = self
                    .identity_mut(from)
                    .and_then(|slot| slot.remove_pending_ack(&tracked_receipt));
            }
            return Err(err);
        }
        Ok(receipt)
    }

    /// Enqueue a unicast frame for transmission, deriving secure peer state on first use.
    pub async fn send_unicast(
        &mut self,
        from: LocalIdentityId,
        peer: &PublicKey,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        let (peer_id, _) = self
            .peer_registry
            .lookup_by_key(peer)
            .ok_or(SendError::PeerMissing)?;
        let _ = self.ensure_peer_crypto(from, peer_id).await?;
        self.queue_unicast(from, peer, payload, options)
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
        let effective_source_route = self.effective_source_route(peer_id, options);
        let effective_flood_hops =
            self.effective_flood_hops(peer_id, options, effective_source_route.as_ref());

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
        if let Some(hops) = effective_flood_hops {
            builder = builder.flood_hops(hops);
        }
        if options.trace_route {
            builder = builder.trace_route();
        }
        if let Some(route) = effective_source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(region_code) = options.region_code {
            builder = builder.region_code(region_code);
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
                effective_source_route
                    .as_ref()
                    .map(|route| route.as_slice()),
                options.flood_hops,
            )?;
        }
        // A non-ACK send that rides through repeaters is tracked under an
        // internal receipt so it can retry until a repeat is heard. The caller
        // asked for no tracking and sees none.
        let tracked_receipt = match receipt {
            Some(receipt) => Some(receipt),
            None if Self::send_has_hops(effective_source_route.as_ref(), effective_flood_hops) => {
                Some(self.prepare_repeat_confirmed_send(
                    from,
                    *peer,
                    packet.as_bytes(),
                    effective_source_route.as_ref(),
                    options.flood_hops,
                )?)
            }
            None => None,
        };
        let not_before_ms = self.tx_not_before_ms(options);
        if let Err(err) = self.enqueue_packet(packet, tracked_receipt, Some(from), not_before_ms) {
            if let Some(tracked_receipt) = tracked_receipt {
                let _ = self
                    .identity_mut(from)
                    .and_then(|slot| slot.remove_pending_ack(&tracked_receipt));
            }
            return Err(err);
        }
        Ok(receipt)
    }

    /// Enqueue a blind-unicast frame for transmission, deriving secure peer state on first use.
    pub async fn send_blind_unicast(
        &mut self,
        from: LocalIdentityId,
        peer: &PublicKey,
        channel_id: &ChannelId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        let (peer_id, _) = self
            .peer_registry
            .lookup_by_key(peer)
            .ok_or(SendError::PeerMissing)?;
        let _ = self.ensure_peer_crypto(from, peer_id).await?;
        self.queue_blind_unicast(from, peer, channel_id, payload, options)
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
        on_event: &mut impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
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
        let identity_id = queued.identity_id;

        // A retransmission exists only to serve a send still waiting on an
        // outcome, and that send may have reached one while the frame sat in
        // the queue — acknowledged, confirmed by an overheard repeat, timed
        // out, or cancelled. All of those drop the pending entry, so its
        // absence is what makes the frame unwanted. Only retries are judged
        // this way: a first transmission carries a receipt for reporting
        // (broadcast and multicast do so with no pending entry at all) and is
        // always sent.
        if queued.priority == TxPriority::Retry
            && let (Some(receipt), Some(identity_id)) = (receipt, identity_id)
            && self
                .identity(identity_id)
                .map(|slot| slot.pending_ack(&receipt).is_none())
                .unwrap_or(true)
        {
            return Ok(None);
        }

        let tx_options = if queued.priority == TxPriority::ImmediateAck {
            // Immediate ACK: the channel was clear when the packet ended, so
            // transmit without CAD (see channel-access.md § Immediate ACK).
            TxOptions {
                cad: umsh_hal::CadPolicy::Skip,
            }
        } else {
            TxOptions {
                cad: umsh_hal::CadPolicy::Gate,
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
                    // Counted whether or not anyone is told: a forwarded
                    // frame is dropped without an event, and a node
                    // abandoning every forward is exactly the condition
                    // this tally exists to make visible.
                    MacCounters::bump(&mut self.counters.tx_abandoned);
                    // Drop with accounting: locally-originated frames report
                    // the abandonment to the owning identity (a send that
                    // never aired will see no AckReceived/AckTimeout, so this
                    // is its terminal state). Forwarded frames (no identity)
                    // are best-effort and dropped without an event. A
                    // *retransmission* that lost CAD is neither: its send has
                    // aired before and its deadlines still stand, so the
                    // attempt is dropped quietly and the timers judge the
                    // send.
                    if let Some(identity_id) = identity_id
                        && queued.priority != TxPriority::Retry
                    {
                        // Terminal means the tracking entry goes too; left
                        // behind in `Queued` it would outlive every timer,
                        // holding its slot until the identity is removed.
                        if let Some(receipt) = receipt
                            && let Some(slot) = self.identity_mut(identity_id)
                        {
                            let _ = slot.pending_acks.remove(&receipt);
                        }
                        on_event(
                            identity_id,
                            crate::MacEventRef::TxAbandoned {
                                identity_id,
                                receipt,
                            },
                        );
                    }
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
                        queued.identity_id,
                        now_ms.saturating_add(backoff_ms),
                        next_attempt,
                        queued.forward_deferrals,
                    )
                    .map_err(|_| MacError::QueueFull)?;
                return Ok(None);
            }
            Err(error) => return Err(MacError::Transmit(error)),
        }
        // Counted before the event, which only locally-originated frames
        // get: a repeater's whole output would otherwise be invisible.
        MacCounters::bump(&mut self.counters.tx_frames);
        if let Some(identity_id) = identity_id {
            on_event(
                identity_id,
                crate::MacEventRef::Transmitted {
                    identity_id,
                    receipt,
                    wire_bytes: queued.frame.as_slice(),
                },
            );
        }
        if let Some(receipt) = receipt {
            self.note_transmitted_tracked(receipt, queued.frame.as_slice());
        }
        Ok(receipt)
    }

    /// Keep transmitting until the queue is empty.
    ///
    /// Progress stops when CAD keeps reporting busy, when a post-transmit listen window blocks
    /// normal traffic, or when the queue is otherwise unable to shrink further in the current cycle.
    pub async fn drain_tx_queue(
        &mut self,
        on_event: &mut impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        while !self.tx_queue.is_empty() {
            let queue_len = self.tx_queue.len();
            let _ = self.transmit_next(on_event).await?;
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
        self.drain_tx_queue(&mut on_event).await?;
        if self.post_tx_listen.is_some() {
            self.service_post_tx_listen(&mut on_event).await?;
        } else {
            let _ = self.receive_one(&mut on_event).await?;
        }
        self.drain_tx_queue(&mut on_event).await?;
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
                if !matches!(pending.state, crate::AckState::Queued { .. }) {
                    earliest = Some(earliest.map_or(pending.ack_deadline_ms, |e: u64| {
                        e.min(pending.ack_deadline_ms)
                    }));
                }
                // A confirm deadline is only a wake-up if its expiry can
                // still queue a retry. With the retry budget spent it would
                // report a moment that services nothing, and a deadline in
                // the past that never clears pins the caller's timer loop.
                if let crate::AckState::AwaitingForward {
                    confirm_deadline_ms,
                } = pending.state
                    && pending.retries < MAX_FORWARD_RETRIES
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
            self.drain_tx_queue(&mut on_event).await?;

            // Phase 2: Wait for a radio frame or the earliest timer deadline.
            let mut buf = [0u8; FRAME];
            let reason = poll_fn(|cx| self.poll_wait_for_wake(cx, &mut buf))
                .await
                .map_err(MacError::Radio)?;

            // Phases 3-5: process the wake, drain any follow-up sends, and run timeouts.
            self.process_wake_reason(reason, &mut buf, &mut on_event)
                .await?;

            // Flush any pending TX or RX counter boundaries to durable storage.
            // Errors are intentionally ignored — persistence is best-effort and
            // must not block the radio event loop.
            let _ = self.service_counter_persistence().await;
            let _ = self.service_rx_counter_persistence().await;

            // If the tx_queue has new work (e.g. retransmits just enqueued),
            // loop back to drain it before waiting again.
            if !self.tx_queue.is_empty() {
                continue;
            }

            return Ok(());
        }
    }

    /// Register radio/timer wakers and report what has become ready.
    ///
    /// This is Phase 2 of [`next_event`](Self::next_event) exposed as a sync
    /// poll method so that callers sharing the coordinator through an
    /// `AsyncRefCell` can release the exclusive borrow between polls. The
    /// caller-provided `buf` is populated with the received frame when the
    /// return value is [`WakeReason::Received`].
    pub fn poll_wait_for_wake(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8; FRAME],
    ) -> Poll<Result<WakeReason, <P::Radio as Radio>::Error>> {
        match self.radio.poll_receive(cx, buf) {
            Poll::Ready(Ok(rx)) => return Poll::Ready(Ok(WakeReason::Received(rx))),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }

        let now_ms = self.clock.now_ms();
        if let Some(deadline) = self.earliest_deadline_ms() {
            if now_ms >= deadline {
                return Poll::Ready(Ok(WakeReason::TimerExpired));
            }
            // A `Ready` here means the deadline elapsed between the `now_ms`
            // snapshot above and this poll. Treat it as a timer expiry so the
            // deadline is never silently dropped; a `Pending` result must have
            // arranged a wake (a registered timer, or the default impl's
            // immediate self-wake busy-poll).
            if self.clock.poll_delay_until(cx, deadline).is_ready() {
                return Poll::Ready(Ok(WakeReason::TimerExpired));
            }
        }

        // Ready queue entries are only actionable when they could actually
        // transmit: during a post-transmit listen window only immediate-ACK
        // frames may go out, and the window's own expiry is already covered
        // by `earliest_deadline_ms` above. Reporting a blocked-but-ready
        // frame here would spin this poll hot for the whole window —
        // starving every other task sharing the executor — since the drain
        // it triggers requeues the frame without progress.
        if self.tx_queue.has_ready(now_ms)
            && (self.post_tx_listen.is_none() || self.tx_queue.has_ready_immediate_ack(now_ms))
        {
            return Poll::Ready(Ok(WakeReason::TimerExpired));
        }

        Poll::Pending
    }

    /// Run Phases 3-5 after [`poll_wait_for_wake`](Self::poll_wait_for_wake)
    /// has reported a wake reason: process the received frame (if any),
    /// drain immediate ACKs, and service pending ACK timeouts.
    ///
    /// # Precondition
    ///
    /// When `reason` is [`WakeReason::Received`], `buf` **must** be the same
    /// buffer — containing the same bytes — that was passed to the matching
    /// [`poll_wait_for_wake`](Self::poll_wait_for_wake) call. The received
    /// frame bytes live in `buf[..rx.len]`; `reason` only carries the
    /// accompanying metadata (`RxInfo`). Passing a different or reinitialized
    /// buffer will cause the received frame to be silently discarded and the
    /// contents of `buf` to be misinterpreted as a MAC frame.
    ///
    /// This precondition only matters when using the split-phase API for
    /// [`AsyncRefCell`](umsh_sync::AsyncRefCell) sharing. When driving the
    /// coordinator through [`next_event`](Self::next_event) the buffer is a
    /// local stack variable and the pairing is guaranteed automatically.
    pub async fn process_wake_reason(
        &mut self,
        reason: WakeReason,
        buf: &mut [u8; FRAME],
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        match reason {
            WakeReason::Received(rx) => {
                let frame_len = rx.len.min(buf.len());
                let _ = self
                    .process_received_frame(buf, frame_len, &rx, &mut on_event)
                    .await;
            }
            WakeReason::TimerExpired => {}
        }

        self.drain_tx_queue(&mut on_event).await?;

        self.service_pending_ack_timeouts(&mut on_event)
            .map_err(|_| MacError::QueueFull)?;

        Ok(())
    }

    /// Drive the coordinator forever, invoking `on_event` for each delivered event.
    ///
    /// This is the preferred long-lived run loop for standalone MAC-driven tasks such as
    /// repeaters or dedicated radio services. Unlike manually calling
    /// [`poll_cycle`](Self::poll_cycle) in a loop, `run` keeps the wake/sleep policy inside
    /// the coordinator by delegating to [`next_event`](Self::next_event), which already
    /// waits for radio activity and protocol deadlines.
    pub async fn run(
        &mut self,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        loop {
            self.next_event(&mut on_event).await?;
        }
    }

    /// Drive the coordinator forever while ignoring emitted events.
    ///
    /// Useful for standalone repeaters or bridge tasks that do not need to observe inbound
    /// deliveries directly but still need the coordinator to service forwarding, ACKs, and
    /// retransmissions without an app-owned polling loop.
    pub async fn run_quiet(&mut self) -> Result<(), MacError<<P::Radio as Radio>::Error>> {
        self.run(|_, _| {}).await
    }

    /// Process a received frame, dispatching events through `on_event`.
    ///
    /// This is the shared implementation used by both [`receive_one`](Self::receive_one)
    /// and [`next_event`](Self::next_event).  Returns `true` when the frame
    /// produced at least one event or side-effect.
    ///
    /// Every reception passes through here exactly once, which is what
    /// makes it the place to tally them: the `rx_frames`/`rx_accepted`
    /// pair counts one radio reception and whether anything came of it.
    pub async fn process_received_frame(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        rx: &RxInfo,
        on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        MacCounters::bump(&mut self.counters.rx_frames);
        let handled = self
            .process_received_frame_inner(buf, frame_len, rx, on_event)
            .await;
        if handled {
            MacCounters::bump(&mut self.counters.rx_accepted);
        }
        handled
    }

    async fn process_received_frame_inner(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        rx: &RxInfo,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let received_at_ms = self.clock.now_ms();
        let mut current_len = frame_len;
        let mut current_rx = RxInfo {
            len: frame_len,
            rssi: rx.rssi,
            snr: rx.snr,
            lqi: rx.lqi,
        };
        let mut current_received_at_ms = received_at_ms;
        let mut handled_any = false;

        loop {
            let Ok(header) = PacketHeader::parse(&buf[..current_len]) else {
                return handled_any;
            };
            // A piggy-backed Ack MIC option is read here, before any
            // decryption, because it is aimed at whoever happens to be
            // carrying the acknowledged packet — not at this frame's
            // addressee.
            self.cancel_forwards_for_ack_mic_option(&buf[..current_len], &header);
            let forwarding_confirmed = if let Some((identity_id, receipt)) =
                self.observe_forwarding_confirmation(&buf[..current_len])
            {
                let hint = match header.source {
                    SourceAddrRef::Hint(h) => Some(RouterHint([h.0[0], h.0[1]])),
                    SourceAddrRef::FullKeyAt { offset } => {
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&buf[offset..offset + 32]);
                        let h = PublicKey(key_bytes).hint();
                        Some(RouterHint([h.0[0], h.0[1]]))
                    }
                    _ => None,
                };
                on_event(
                    identity_id,
                    crate::MacEventRef::Forwarded {
                        identity_id,
                        receipt,
                        hint,
                    },
                );
                true
            } else {
                false
            };

            let (handled, replay_target) = match header.packet_type() {
                PacketType::Broadcast => (
                    self.process_broadcast(
                        buf,
                        current_len,
                        &header,
                        &current_rx,
                        current_received_at_ms,
                        &mut on_event,
                    ),
                    None,
                ),
                PacketType::MacAck => (
                    self.process_mac_ack(
                        buf,
                        current_len,
                        &header,
                        &current_rx,
                        forwarding_confirmed,
                        &mut on_event,
                    ),
                    None,
                ),
                PacketType::Unicast | PacketType::UnicastAckReq => {
                    self.process_unicast(
                        buf,
                        current_len,
                        &header,
                        &current_rx,
                        current_received_at_ms,
                        forwarding_confirmed,
                        &mut on_event,
                    )
                    .await
                }
                PacketType::Multicast => (
                    self.process_multicast(
                        buf,
                        current_len,
                        &header,
                        &current_rx,
                        current_received_at_ms,
                        forwarding_confirmed,
                        &mut on_event,
                    ),
                    None,
                ),
                PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
                    self.process_blind_unicast(
                        buf,
                        current_len,
                        &header,
                        &current_rx,
                        current_received_at_ms,
                        forwarding_confirmed,
                        &mut on_event,
                    )
                    .await
                }
                PacketType::Reserved5 => (false, None),
            };
            handled_any |= handled;

            let Some((local_id, peer_id)) = replay_target else {
                return handled_any;
            };
            let Some(deferred) = self.take_deferred_counter_resync_frame(local_id, peer_id) else {
                return handled_any;
            };
            current_len = deferred.frame.len();
            buf[..current_len].copy_from_slice(deferred.frame.as_slice());
            current_rx = RxInfo {
                len: current_len,
                rssi: deferred.rssi,
                snr: deferred.snr,
                lqi: deferred.lqi,
            };
            current_received_at_ms = deferred.received_at_ms;
        }
    }

    fn process_broadcast(
        &mut self,
        buf: &[u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        received_at_ms: u64,
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
                crate::MacEventRef::Received(crate::ReceivedPacketRef::new(
                    &buf[..frame_len],
                    &buf[header.body_range.clone()],
                    header.clone(),
                    ParsedOptions::extract(&buf[..frame_len], header.options_range.clone())
                        .unwrap_or_default(),
                    from_key,
                    Some(from_hint),
                    false,
                    None,
                    crate::send::RxMetadata::new(
                        Some(rx.rssi),
                        Some(rx.snr),
                        rx.lqi,
                        Some(received_at_ms),
                    ),
                )),
            );
        }
        // Broadcast delivery does not consume the packet. Broadcast remains a
        // routable mesh packet and may still be forwarded by a repeater after
        // local delivery.
        let forwarded = self.maybe_forward_received(&buf[..frame_len], header, rx, false);
        delivered || forwarded
    }

    fn process_mac_ack(
        &mut self,
        buf: &[u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        // MAC acks carry no destination hint. Correlation is by the 8-byte
        // ack trailer (`ack_mic || ack_tag`): the public `ack_mic` half links
        // the ack to an outstanding request, and the keyed `ack_tag` half
        // authenticates it. A colliding `ack_mic` from an unrelated exchange
        // fails the full-trailer comparison and falls through to forwarding.
        if header.mic_range.len() != 8 {
            return forwarding_confirmed
                || self.maybe_forward_received(&buf[..frame_len], header, rx, false);
        }
        let mut ack_trailer = [0u8; 8];
        ack_trailer.copy_from_slice(&buf[header.mic_range.clone()]);
        // Independent of whether this node is the ack's addressee: a node can
        // be the origin of one exchange and a repeater for another, and the
        // queued forward it may be holding is not this ack's business to
        // match against.
        self.cancel_forwards_for_ack_mic(&ack_trailer[..4]);
        if let Some(target_peer) = self.peer_for_ack_trailer(&ack_trailer)
            && let Some((identity_id, receipt)) = self.complete_ack(&target_peer, &ack_trailer)
        {
            on_event(
                identity_id,
                crate::MacEventRef::AckReceived {
                    peer: target_peer,
                    receipt,
                },
            );
            return true;
        }
        forwarding_confirmed || self.maybe_forward_received(&buf[..frame_len], header, rx, false)
    }

    async fn process_unicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        received_at_ms: u64,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> (bool, Option<(LocalIdentityId, PeerId)>) {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let mut replay_target = None;
        let handled = if let Some(local_id) = self.find_local_identity_for_dst(header.dst) {
            let mut handled = false;
            for (peer_id, peer_key) in
                self.resolve_source_peer_candidates(&buf[..frame_len], header)
            {
                let Ok(keys) = self.ensure_peer_crypto(local_id, peer_id).await else {
                    continue;
                };
                let Ok(body_range) = self
                    .crypto
                    .open_packet(&mut buf[..frame_len], header, &keys)
                else {
                    continue;
                };
                let payload = &buf[body_range.clone()];
                if !Self::payload_is_allowed(header.packet_type(), payload) {
                    continue;
                }
                if header.ack_requested()
                    && self.should_emit_destination_ack(&buf[..frame_len], header)
                    && self.is_acknowledgeable_unicast_duplicate(
                        local_id,
                        peer_id,
                        header,
                        &buf[..frame_len],
                    )
                {
                    let ack_trailer = self.compute_received_ack_trailer(
                        &buf[..frame_len],
                        header,
                        body_range.clone(),
                        &keys,
                    );
                    self.queue_mac_ack_for_peer(peer_id, ack_trailer).ok();
                    handled = true;
                    break;
                }
                match self.unicast_replay_verdict(local_id, peer_id, header, &buf[..frame_len]) {
                    Some(ReplayVerdict::Accept) => {
                        let _ = self.accept_unicast_replay(
                            local_id,
                            peer_id,
                            header,
                            &buf[..frame_len],
                        );
                    }
                    Some(ReplayVerdict::OutOfWindow | ReplayVerdict::Stale) => {
                        if self.try_accept_counter_resync_response(
                            local_id,
                            peer_id,
                            header,
                            &buf[..frame_len],
                            payload,
                        ) {
                            replay_target = Some((local_id, peer_id));
                        } else {
                            // Only initiate a counter resync if the backward
                            // gap is large enough that out-of-order delivery
                            // can't explain it. Small gaps (handful of packets)
                            // are silently dropped to avoid resync churn from
                            // normal mesh reordering. See
                            // `COUNTER_RESYNC_GAP_THRESHOLD`.
                            let counter = Self::replay_metadata(header, &buf[..frame_len])
                                .map(|(c, _)| c)
                                .unwrap_or(0);
                            let gap = self
                                .identity(local_id)
                                .and_then(|slot| slot.peer_crypto().get(&peer_id))
                                .map(|state| {
                                    state.replay_window.last_accepted.wrapping_sub(counter)
                                })
                                .unwrap_or(0);
                            if gap >= COUNTER_RESYNC_GAP_THRESHOLD {
                                self.store_deferred_counter_resync_frame(
                                    local_id,
                                    peer_id,
                                    &original[..frame_len],
                                    rx,
                                    received_at_ms,
                                );
                                self.maybe_request_counter_resync(local_id, peer_id, peer_key)
                                    .await;
                            }
                            continue;
                        }
                    }
                    Some(ReplayVerdict::Replay) | None => continue,
                }
                self.learn_route_for_peer(peer_id, &buf[..frame_len], header);

                if header.ack_requested()
                    && self.should_emit_destination_ack(&buf[..frame_len], header)
                {
                    let ack_trailer = self.compute_received_ack_trailer(
                        &buf[..frame_len],
                        header,
                        body_range.clone(),
                        &keys,
                    );
                    self.queue_mac_ack_for_peer(peer_id, ack_trailer).ok();
                }

                if let Some(data) = Self::echo_request_data(payload) {
                    let response =
                        Self::build_echo_command_payload(MAC_COMMAND_ECHO_RESPONSE_ID, data);
                    let options = Self::echo_response_options(&original[..frame_len], header);
                    let _ = self
                        .send_unicast(local_id, &peer_key, response.as_slice(), &options)
                        .await;
                }

                on_event(
                    local_id,
                    crate::MacEventRef::Received(crate::ReceivedPacketRef::new(
                        &original[..frame_len],
                        &buf[body_range],
                        header.clone(),
                        ParsedOptions::extract(
                            &original[..frame_len],
                            header.options_range.clone(),
                        )
                        .unwrap_or_default(),
                        Some(peer_key),
                        Some(peer_key.hint()),
                        true,
                        None,
                        crate::send::RxMetadata::new(
                            Some(rx.rssi),
                            Some(rx.snr),
                            rx.lqi,
                            Some(received_at_ms),
                        ),
                    )),
                );
                handled = true;
                break;
            }
            handled
        } else {
            false
        };
        let forwarded = self.maybe_forward_received(&original[..frame_len], header, rx, handled);
        (
            handled || forwarding_confirmed || forwarded,
            handled.then_some(()).and(replay_target),
        )
    }

    fn process_multicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        received_at_ms: u64,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> bool {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let delivered = if let Some(channel_id) = header.channel {
            let channel_info = {
                self.channels
                    .lookup_by_id(&channel_id)
                    .next()
                    .map(|channel| (channel.channel_key.clone(), channel.derived.clone()))
            };
            if let Some((channel_key, derived)) = channel_info {
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
                    } else if let Some(source) =
                        self.resolve_multicast_source(&buf[..frame_len], header)
                    {
                        let accepted = if let Some(peer_id) = source.peer_id {
                            let accepted = self.accept_multicast_replay(
                                channel_id,
                                peer_id,
                                header,
                                &buf[..frame_len],
                            );
                            if accepted {
                                self.learn_route_for_peer(peer_id, &buf[..frame_len], header);
                            }
                            accepted
                        } else {
                            self.accept_unknown_multicast_replay(header, &buf[..frame_len])
                        };
                        if accepted {
                            let mut delivered = false;
                            for (index, slot) in self.identities.iter().enumerate() {
                                if slot.is_none() {
                                    continue;
                                }
                                delivered = true;
                                on_event(
                                    LocalIdentityId(index as u8),
                                    crate::MacEventRef::Received(crate::ReceivedPacketRef::new(
                                        &original[..frame_len],
                                        &buf[body_range.clone()],
                                        header.clone(),
                                        ParsedOptions::extract(
                                            &original[..frame_len],
                                            header.options_range.clone(),
                                        )
                                        .unwrap_or_default(),
                                        source.public_key,
                                        source
                                            .hint
                                            .or_else(|| source.public_key.map(|key| key.hint())),
                                        true,
                                        Some(crate::ChannelInfoRef {
                                            id: channel_id,
                                            key: &channel_key,
                                        }),
                                        crate::send::RxMetadata::new(
                                            Some(rx.rssi),
                                            Some(rx.snr),
                                            rx.lqi,
                                            Some(received_at_ms),
                                        ),
                                    )),
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

    async fn process_blind_unicast(
        &mut self,
        buf: &mut [u8; FRAME],
        frame_len: usize,
        header: &PacketHeader,
        rx: &RxInfo,
        received_at_ms: u64,
        forwarding_confirmed: bool,
        mut on_event: impl FnMut(LocalIdentityId, crate::MacEventRef<'_>),
    ) -> (bool, Option<(LocalIdentityId, PeerId)>) {
        let mut original = [0u8; FRAME];
        original[..frame_len].copy_from_slice(&buf[..frame_len]);
        let mut replay_target = None;
        let handled = if let Some(channel_id) = header.channel {
            let channel_candidates: Vec<(ChannelKey, DerivedChannelKeys), CHANNELS> = self
                .channels
                .lookup_by_id(&channel_id)
                .map(|channel| (channel.channel_key.clone(), channel.derived.clone()))
                .collect();
            if channel_candidates.is_empty() {
                false
            } else {
                let mut handled = false;
                for (resolved_channel_key, channel_keys) in channel_candidates {
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
                        let Ok(pairwise_keys) = self.ensure_peer_crypto(local_id, peer_id).await
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
                        let payload = &buf[body_range.clone()];
                        if !Self::payload_is_allowed(header.packet_type(), payload) {
                            continue;
                        }
                        if header.ack_requested()
                            && self.should_emit_destination_ack(&buf[..frame_len], header)
                            && self.is_acknowledgeable_unicast_duplicate(
                                local_id,
                                peer_id,
                                header,
                                &buf[..frame_len],
                            )
                        {
                            let ack_trailer = self.compute_received_ack_trailer(
                                &buf[..frame_len],
                                header,
                                body_range.clone(),
                                &blind_keys,
                            );
                            self.queue_mac_ack_for_peer(peer_id, ack_trailer).ok();
                            handled = true;
                            break;
                        }
                        match self.unicast_replay_verdict(
                            local_id,
                            peer_id,
                            header,
                            &buf[..frame_len],
                        ) {
                            Some(ReplayVerdict::Accept) => {
                                let _ = self.accept_unicast_replay(
                                    local_id,
                                    peer_id,
                                    header,
                                    &buf[..frame_len],
                                );
                            }
                            Some(ReplayVerdict::OutOfWindow | ReplayVerdict::Stale) => {
                                if self.try_accept_counter_resync_response(
                                    local_id,
                                    peer_id,
                                    header,
                                    &buf[..frame_len],
                                    payload,
                                ) {
                                    replay_target = Some((local_id, peer_id));
                                } else {
                                    self.store_deferred_counter_resync_frame(
                                        local_id,
                                        peer_id,
                                        &original[..frame_len],
                                        rx,
                                        received_at_ms,
                                    );
                                    self.maybe_request_counter_resync(local_id, peer_id, peer_key)
                                        .await;
                                    continue;
                                }
                            }
                            Some(ReplayVerdict::Replay) | None => continue,
                        }
                        self.learn_route_for_peer(peer_id, &buf[..frame_len], header);

                        if header.ack_requested()
                            && self.should_emit_destination_ack(&buf[..frame_len], header)
                        {
                            let ack_trailer = self.compute_received_ack_trailer(
                                &buf[..frame_len],
                                header,
                                body_range.clone(),
                                &blind_keys,
                            );
                            self.queue_mac_ack_for_peer(peer_id, ack_trailer).ok();
                        }

                        if let Some(data) = Self::echo_request_data(payload) {
                            let response = Self::build_echo_command_payload(
                                MAC_COMMAND_ECHO_RESPONSE_ID,
                                data,
                            );
                            let options =
                                Self::echo_response_options(&original[..frame_len], header);
                            let _ = self
                                .send_unicast(local_id, &peer_key, response.as_slice(), &options)
                                .await;
                        }

                        on_event(
                            local_id,
                            crate::MacEventRef::Received(crate::ReceivedPacketRef::new(
                                &original[..frame_len],
                                &buf[body_range],
                                header.clone(),
                                ParsedOptions::extract(
                                    &original[..frame_len],
                                    header.options_range.clone(),
                                )
                                .unwrap_or_default(),
                                Some(peer_key),
                                Some(peer_key.hint()),
                                true,
                                Some(crate::ChannelInfoRef {
                                    id: channel_id,
                                    key: &resolved_channel_key,
                                }),
                                crate::send::RxMetadata::new(
                                    Some(rx.rssi),
                                    Some(rx.snr),
                                    rx.lqi,
                                    Some(received_at_ms),
                                ),
                            )),
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
        (
            handled || forwarding_confirmed || forwarded,
            handled.then_some(()).and(replay_target),
        )
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
        Ok(self
            .process_received_frame(&mut buf, frame_len, &rx, &mut on_event)
            .await)
    }

    /// Mark a pending receipt as acknowledged and emit an event through `on_event`.
    pub fn complete_ack(
        &mut self,
        peer: &PublicKey,
        ack_trailer: &[u8; 8],
    ) -> Option<(LocalIdentityId, SendReceipt)> {
        for (index, slot) in self.identities.iter_mut().enumerate() {
            let Some(slot) = slot.as_mut() else {
                continue;
            };

            let receipt = slot.pending_acks.iter().find_map(|(receipt, pending)| {
                (pending.expects_ack()
                    && pending.peer == *peer
                    && pending.ack_trailer == *ack_trailer)
                    .then_some(*receipt)
            });

            if let Some(receipt) = receipt {
                slot.pending_acks.remove(&receipt);
                let identity_id = LocalIdentityId(index as u8);
                // A retransmission may already be queued behind this ack.
                // Nothing downstream re-checks, so it would otherwise go out
                // after the send it belongs to has been confirmed.
                self.tx_queue.remove_all_matching(|entry| {
                    entry.receipt == Some(receipt) && entry.identity_id == Some(identity_id)
                });
                if self
                    .post_tx_listen
                    .as_ref()
                    .map(|listen| listen.identity_id == identity_id && listen.receipt == receipt)
                    .unwrap_or(false)
                {
                    self.post_tx_listen = None;
                }
                return Some((identity_id, receipt));
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
                not_before_ms: u64,
            },
            RouteRetry {
                receipt: SendReceipt,
                peer: PublicKey,
                resend: ResendRecord<FRAME>,
                not_before_ms: u64,
            },
            Timeout {
                receipt: SendReceipt,
                peer: PublicKey,
            },
            /// A repeat-confirmed send whose ladder ran out. Nobody is
            /// waiting on the outcome, so the entry just goes away.
            Abandon { receipt: SendReceipt },
        }

        let now_ms = self.clock.now_ms();
        let t_frame_ms = self.radio.t_frame_ms();

        for index in 0..self.identities.len() {
            let identity_id = LocalIdentityId(index as u8);
            let actions = {
                let Some(slot) = self.identities[index].as_mut() else {
                    continue;
                };

                let mut actions: Vec<Action<FRAME>, ACKS> = Vec::new();
                for (receipt, pending) in slot.pending_acks.iter_mut() {
                    if !matches!(pending.state, crate::AckState::Queued { .. })
                        && now_ms >= pending.ack_deadline_ms
                    {
                        if !pending.expects_ack() {
                            actions
                                .push(Action::Abandon { receipt: *receipt })
                                .map_err(|_| CapacityError)?;
                        } else if Self::can_attempt_route_retry(pending) {
                            let backoff_cap_ms = t_frame_ms;
                            let backoff_ms = if backoff_cap_ms == 0 {
                                0
                            } else {
                                u64::from(self.rng.random_range(..backoff_cap_ms.saturating_add(1)))
                            };
                            actions
                                .push(Action::RouteRetry {
                                    receipt: *receipt,
                                    peer: pending.peer,
                                    resend: pending.resend.clone(),
                                    not_before_ms: now_ms.saturating_add(backoff_ms),
                                })
                                .map_err(|_| CapacityError)?;
                        } else {
                            actions
                                .push(Action::Timeout {
                                    receipt: *receipt,
                                    peer: pending.peer,
                                })
                                .map_err(|_| CapacityError)?;
                        }
                        continue;
                    }

                    if let crate::AckState::AwaitingForward {
                        confirm_deadline_ms,
                    } = pending.state
                    {
                        if now_ms >= confirm_deadline_ms && pending.retries < MAX_FORWARD_RETRIES {
                            pending.retries = pending.retries.saturating_add(1);
                            let backoff_cap_ms = t_frame_ms;
                            let backoff_ms = if backoff_cap_ms == 0 {
                                0
                            } else {
                                u64::from(self.rng.random_range(..backoff_cap_ms.saturating_add(1)))
                            };
                            let not_before_ms = now_ms.saturating_add(backoff_ms);
                            pending.state = crate::AckState::RetryQueued;
                            actions
                                .push(Action::Retry {
                                    receipt: *receipt,
                                    resend: pending.resend.clone(),
                                    not_before_ms,
                                })
                                .map_err(|_| CapacityError)?;
                        }
                    }
                }
                actions
            };

            for action in actions {
                match action {
                    Action::Retry {
                        receipt,
                        resend,
                        not_before_ms,
                    } => {
                        self.tx_queue.enqueue_with_state(
                            TxPriority::Retry,
                            resend.frame.as_slice(),
                            Some(receipt),
                            Some(identity_id),
                            not_before_ms,
                            0,
                            0,
                        )?;
                    }
                    Action::RouteRetry {
                        receipt,
                        peer,
                        resend,
                        not_before_ms,
                    } => {
                        if let Some(rewritten) = self.synthesize_route_retry_resend(&peer, &resend)
                        {
                            let rewritten_key = Self::confirmation_key(rewritten.frame.as_slice());
                            // The rewritten attempt always floods, so it earns
                            // the forwarded window. It is armed here, from the
                            // moment the frame becomes eligible to air, rather
                            // than left at zero for the transmit path to fill
                            // in: an unarmed deadline reads as *already
                            // expired* to both the timeout sweep and
                            // `earliest_deadline_ms`, which would retire the
                            // send — and drop the frame back out of the queue —
                            // before the retry it just scheduled ever aired.
                            let retry_deadline_ms =
                                not_before_ms.saturating_add(self.forwarded_ack_timeout_ms());
                            if let Some(pending) = self
                                .identity_mut(identity_id)
                                .and_then(|slot| slot.pending_ack_mut(&receipt))
                            {
                                pending.resend = rewritten.clone();
                                pending.retries = 0;
                                pending.sent_ms = 0;
                                pending.ack_deadline_ms = retry_deadline_ms;
                                pending.state = crate::AckState::RetryQueued;
                                // The rebuilt frame is a distinct forwarding
                                // identity; a repeat of the abandoned one no
                                // longer confirms this attempt.
                                pending.confirm_key = rewritten_key;
                            }
                            self.tx_queue.enqueue_with_state(
                                TxPriority::Retry,
                                rewritten.frame.as_slice(),
                                Some(receipt),
                                Some(identity_id),
                                not_before_ms,
                                0,
                                0,
                            )?;
                        } else {
                            if let Some(slot) = self.identity_mut(identity_id) {
                                slot.pending_acks.remove(&receipt);
                            }
                            on_event(
                                identity_id,
                                crate::MacEventRef::AckTimeout { peer, receipt },
                            );
                        }
                    }
                    Action::Timeout { receipt, peer } => {
                        if let Some(slot) = self.identity_mut(identity_id) {
                            slot.pending_acks.remove(&receipt);
                        }
                        self.tx_queue.remove_all_matching(|entry| {
                            entry.receipt == Some(receipt) && entry.identity_id == Some(identity_id)
                        });
                        on_event(
                            identity_id,
                            crate::MacEventRef::AckTimeout { peer, receipt },
                        );
                    }
                    Action::Abandon { receipt } => {
                        if let Some(slot) = self.identity_mut(identity_id) {
                            slot.pending_acks.remove(&receipt);
                        }
                        self.tx_queue.remove_all_matching(|entry| {
                            entry.receipt == Some(receipt) && entry.identity_id == Some(identity_id)
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Cancel a pending ACK-requested send, stopping retransmissions.
    ///
    /// Removes the pending ACK entry for the given identity slot and receipt,
    /// and removes any matching entry from the transmit queue. Returns `true`
    /// if a pending ACK was found and removed.
    pub fn cancel_pending_ack(
        &mut self,
        identity_id: LocalIdentityId,
        receipt: SendReceipt,
    ) -> bool {
        let removed = self
            .identity_mut(identity_id)
            .and_then(|slot| slot.remove_pending_ack(&receipt))
            .is_some();

        // Also remove any queued retransmission for this receipt.
        self.tx_queue.remove_first_matching(|entry| {
            entry.receipt == Some(receipt) && entry.identity_id == Some(identity_id)
        });

        // Clear the post-tx listen if it was tracking this receipt.
        if let Some(listen) = &self.post_tx_listen {
            if listen.identity_id == identity_id && listen.receipt == receipt {
                self.post_tx_listen = None;
            }
        }

        removed
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
        identity_id: Option<LocalIdentityId>,
        not_before_ms: u64,
    ) -> Result<(), SendError> {
        if packet.total_len() > self.radio.max_frame_size() {
            return Err(SendError::Build(BuildError::BufferTooSmall));
        }
        self.tx_queue
            .enqueue_with_state(
                TxPriority::Application,
                packet.as_bytes(),
                receipt,
                identity_id,
                not_before_ms,
                0,
                0,
            )
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    /// The earliest transmit instant a send's options allow: now plus the
    /// requested [`SendOptions::tx_delay_ms`], or zero for immediate.
    fn tx_not_before_ms(&self, options: &SendOptions) -> u64 {
        options
            .tx_delay_ms
            .map(|delay| self.clock.now_ms() + u64::from(delay))
            .unwrap_or(0)
    }

    fn refresh_pending_resend(
        &mut self,
        from: LocalIdentityId,
        receipt: SendReceipt,
        frame: &[u8],
        source_route: Option<&[RouterHint]>,
        requested_flood_hops: Option<u8>,
    ) -> Result<(), SendError> {
        let resend = ResendRecord::try_new(frame, source_route)
            .map_err(|_| SendError::QueueFull)?
            .with_requested_flood_hops(requested_flood_hops);
        let pending = self
            .identity_mut(from)
            .ok_or(SendError::IdentityMissing)?
            .pending_ack_mut(&receipt)
            .ok_or(SendError::IdentityMissing)?;
        pending.resend = resend;
        Ok(())
    }

    /// Whether a send travels through repeaters rather than straight to its
    /// destination.
    fn send_has_hops(
        source_route: Option<&Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
        flood_hops: Option<u8>,
    ) -> bool {
        source_route.map(|route| !route.is_empty()).unwrap_or(false) || flood_hops.unwrap_or(0) > 0
    }

    /// Track a non-ACK send that travels through repeaters.
    ///
    /// Such a send has no acknowledgement coming, but it is not therefore
    /// unverifiable: hearing the next hop carry the frame onward says it was
    /// received, and hearing nothing says the one transmission may have been
    /// the only chance it got. The receipt is the coordinator's own — the
    /// caller asked for no tracking and gets none — and exists so the retry
    /// ladder has something to hang on.
    ///
    /// A send with no hops is left alone: there is no repeater to hear, and
    /// repeating a direct packet nobody asked to acknowledge would be noise.
    fn prepare_repeat_confirmed_send(
        &mut self,
        from: LocalIdentityId,
        peer: PublicKey,
        frame: &[u8],
        source_route: Option<&Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
        requested_flood_hops: Option<u8>,
    ) -> Result<SendReceipt, SendError> {
        let resend = ResendRecord::try_new(frame, source_route.map(|route| route.as_slice()))
            .map_err(|_| SendError::QueueFull)?
            .with_requested_flood_hops(requested_flood_hops);
        let slot = self.identity_mut(from).ok_or(SendError::IdentityMissing)?;
        let receipt = slot.next_receipt();
        slot.try_insert_pending_ack(receipt, PendingAck::repeat_only(peer, resend))
            .map_err(|_| SendError::PendingAckFull)?;
        Ok(receipt)
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
        let ack_trailer = self.crypto.compute_ack_trailer(&full_mac, &keys.k_enc);
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
        .map_err(|_| SendError::QueueFull)?
        .with_requested_flood_hops(options.flood_hops);

        let slot = self.identity_mut(from).ok_or(SendError::IdentityMissing)?;
        let receipt = slot.next_receipt();
        let pending = if is_forwarded {
            PendingAck::forwarded(ack_trailer, peer, resend)
        } else {
            PendingAck::direct(ack_trailer, peer, resend)
        };
        slot.try_insert_pending_ack(receipt, pending)
            .map_err(|_| SendError::PendingAckFull)?;
        Ok(receipt)
    }

    async fn derive_pairwise_keys_for_peer(
        &self,
        local_id: LocalIdentityId,
        peer_key: &PublicKey,
    ) -> Result<PairwiseKeys, SendError> {
        let shared_secret = {
            let slot = self.identity(local_id).ok_or(SendError::IdentityMissing)?;
            match slot.identity() {
                LocalIdentity::LongTerm(identity) => identity
                    .agree(peer_key)
                    .await
                    .map_err(|_| SendError::IdentityAgreementFailed)?,
                #[cfg(feature = "software-crypto")]
                LocalIdentity::Ephemeral(identity) => identity
                    .agree(peer_key)
                    .await
                    .map_err(|_| SendError::IdentityAgreementFailed)?,
            }
        };

        Ok(self.crypto.derive_pairwise_keys(&shared_secret))
    }

    fn effective_source_route(
        &self,
        peer_id: PeerId,
        options: &SendOptions,
    ) -> Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>> {
        // An explicitly supplied route that constrains no hop is the same as
        // no route at all, and must not reach the wire as an empty option.
        if let Some(route) = options.source_route.as_ref() {
            return (!route.is_empty()).then(|| route.clone());
        }

        let Some(peer) = self.peer_registry.get(peer_id) else {
            return None;
        };
        match peer.route.as_ref() {
            Some(CachedRoute::Source(route)) => Some(route.clone()),
            _ => None,
        }
    }

    /// Flood budget for a unicast send, narrowed by whatever is already known
    /// about how to reach the peer.
    ///
    /// `options.flood_hops` is a ceiling, not a target: a learned route only
    /// lowers it, and `no_flood()` still emits no flood-hop field at all. Each
    /// route form keeps [`ESTABLISHED_ROUTE_EXTRA_HOPS`] of slack beyond the
    /// flood distance it already covers, so a slightly stale route still
    /// self-heals. A source route covers that distance without spending flood
    /// budget, so its slack is the entire budget.
    ///
    /// The result is clamped to [`MAX_FLOOD_HOPS`], the largest value the
    /// `FHOPS_REM` nibble can hold.
    fn effective_flood_hops(
        &self,
        peer_id: PeerId,
        options: &SendOptions,
        source_route: Option<&Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
    ) -> Option<u8> {
        let requested = options.flood_hops?;
        let cached = self
            .peer_registry
            .get(peer_id)
            .and_then(|peer| peer.route.as_ref());
        // An empty source route is carried for provenance only; it constrains
        // no hop, so it costs nothing.
        let source_route = source_route.filter(|route| !route.is_empty());

        let ceiling = match (source_route, cached) {
            // A source route costs no flood budget at all — routed hops do not
            // touch `FHOPS` — so the whole budget is slack past the route's
            // end. Heard directly is the same shape: our own transmission is
            // the delivery, and the slack only buys a repeater backstop.
            (Some(_), _) | (None, Some(CachedRoute::Direct)) => ESTABLISHED_ROUTE_EXTRA_HOPS,
            // Flooding has to cover the distance the peer was last heard from.
            (None, Some(CachedRoute::Flood { hops, .. })) => {
                hops.saturating_add(ESTABLISHED_ROUTE_EXTRA_HOPS)
            }
            // A cached source route not attached to this send (the caller
            // suppressed it) has to be flooded end to end instead.
            (None, Some(CachedRoute::Source(route))) => u8::try_from(route.len())
                .unwrap_or(u8::MAX)
                .saturating_add(ESTABLISHED_ROUTE_EXTRA_HOPS),
            // Nothing known about the peer: first contact floods as asked.
            (None, None) => MAX_FLOOD_HOPS,
        };

        Some(requested.min(ceiling))
    }

    fn cache_peer_crypto(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        pairwise_keys: PairwiseKeys,
    ) -> Result<(), SendError> {
        let slot = self
            .identity_mut(local_id)
            .ok_or(SendError::IdentityMissing)?;
        if slot.peer_crypto().get(&peer_id).is_some() {
            return Ok(());
        }
        let initial = self
            .peer_registry
            .get(peer_id)
            .map(|info| info.initial_rx_counter)
            .unwrap_or(0);
        let now_ms = self.clock.now_ms();
        let mut replay_window = ReplayWindow::new();
        if initial > 0 {
            replay_window.reset(initial, now_ms);
        }
        let slot = self
            .identity_mut(local_id)
            .ok_or(SendError::IdentityMissing)?;
        slot.peer_crypto_mut()
            .insert(
                peer_id,
                crate::peers::PeerCryptoState {
                    pairwise_keys,
                    replay_window,
                    persisted_rx_counter: initial,
                    needs_rx_persist: false,
                },
            )
            .map_err(|_| SendError::QueueFull)?;
        Ok(())
    }

    async fn ensure_peer_crypto(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
    ) -> Result<PairwiseKeys, SendError> {
        if let Some(keys) = self
            .identity(local_id)
            .and_then(|slot| slot.peer_crypto().get(&peer_id))
            .map(|state| state.pairwise_keys.clone())
        {
            return Ok(keys);
        }

        let peer_key = self
            .peer_registry
            .get(peer_id)
            .ok_or(SendError::PeerMissing)?
            .public_key;
        let pairwise_keys = self
            .derive_pairwise_keys_for_peer(local_id, &peer_key)
            .await?;
        self.cache_peer_crypto(local_id, peer_id, pairwise_keys.clone())?;
        Ok(pairwise_keys)
    }

    fn insert_identity(
        &mut self,
        identity: LocalIdentity<P::Identity>,
        pfs_parent: Option<LocalIdentityId>,
    ) -> Result<LocalIdentityId, CapacityError> {
        let initial_frame_counter = nonzero_initial_frame_counter(self.rng.next_u32());

        if let Some((index, slot)) = self
            .identities
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(IdentitySlot::new(
                identity,
                initial_frame_counter,
                pfs_parent,
            ));
            return Ok(LocalIdentityId(index as u8));
        }

        let next_id = self.identities.len();
        self.identities
            .push(Some(IdentitySlot::new(
                identity,
                initial_frame_counter,
                pfs_parent,
            )))
            .map_err(|_| CapacityError)?;
        Ok(LocalIdentityId(next_id as u8))
    }

    fn compute_received_ack_trailer(
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
        self.crypto.compute_ack_trailer(&full_mac, &keys.k_enc)
    }

    fn requeue_tx(&mut self, queued: &crate::QueuedTx<FRAME>) -> Result<u32, CapacityError> {
        self.tx_queue.enqueue_with_state(
            queued.priority,
            queued.frame.as_slice(),
            queued.receipt,
            queued.identity_id,
            queued.not_before_ms,
            queued.cad_attempts,
            queued.forward_deferrals,
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
        let Some(state) = self
            .identity_mut(local_id)
            .and_then(|slot| slot.peer_crypto_mut().get_mut(&peer_id))
        else {
            return false;
        };

        if state.replay_window.check(counter, mic, now_ms) != ReplayVerdict::Accept {
            return false;
        }

        state.replay_window.accept(counter, mic, now_ms);
        // Schedule an RX counter flush when we've advanced one full persist block.
        let last = state.replay_window.last_accepted;
        if last.wrapping_sub(state.persisted_rx_counter) >= COUNTER_PERSIST_BLOCK_SIZE {
            state.needs_rx_persist = true;
        }
        true
    }

    fn unicast_replay_verdict(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        header: &PacketHeader,
        frame: &[u8],
    ) -> Option<ReplayVerdict> {
        let Some((counter, mic)) = Self::replay_metadata(header, frame) else {
            return None;
        };
        let now_ms = self.clock.now_ms();
        self.identity_mut(local_id)
            .and_then(|slot| slot.peer_crypto_mut().get_mut(&peer_id))
            .map(|state| state.replay_window.check(counter, mic, now_ms))
    }

    fn is_acknowledgeable_unicast_duplicate(
        &self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        header: &PacketHeader,
        frame: &[u8],
    ) -> bool {
        let Some((counter, mic)) = Self::replay_metadata(header, frame) else {
            return false;
        };
        let now_ms = self.clock.now_ms();
        self.identity(local_id)
            .and_then(|slot| slot.peer_crypto().get(&peer_id))
            .is_some_and(|state| {
                state
                    .replay_window
                    .is_acknowledgeable_duplicate(counter, mic, now_ms)
            })
    }

    fn try_accept_counter_resync_response(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        header: &PacketHeader,
        frame: &[u8],
        payload: &[u8],
    ) -> bool {
        let Some(nonce) = Self::echo_response_nonce(payload) else {
            return false;
        };
        let Some((counter, mic)) = Self::replay_metadata(header, frame) else {
            return false;
        };
        let now_ms = self.clock.now_ms();
        let Some(slot) = self.identity_mut(local_id) else {
            return false;
        };
        let Some(pending) = slot.pending_counter_resync().get(&peer_id).copied() else {
            return false;
        };
        if pending.nonce != nonce {
            return false;
        }
        let Some(state) = slot.peer_crypto_mut().get_mut(&peer_id) else {
            return false;
        };
        state.replay_window.reset(counter, now_ms);
        state.replay_window.accept(counter, mic, now_ms);
        // A resync resets the window; treat the new counter as a fresh baseline
        // and schedule a persist so the new boundary survives a reboot.
        state.persisted_rx_counter = 0;
        state.needs_rx_persist = true;
        let _ = slot.pending_counter_resync_mut().remove(&peer_id);
        true
    }

    async fn maybe_request_counter_resync(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        peer_key: PublicKey,
    ) {
        let now_ms = self.clock.now_ms();
        let should_send = {
            let Some(slot) = self.identity(local_id) else {
                return;
            };
            match slot.pending_counter_resync().get(&peer_id).copied() {
                Some(pending) => {
                    now_ms.saturating_sub(pending.requested_ms) >= COUNTER_RESYNC_REQUEST_RETRY_MS
                }
                None => true,
            }
        };
        if !should_send {
            return;
        }

        let nonce = self.rng.next_u32();
        let payload =
            Self::build_echo_command_payload(MAC_COMMAND_ECHO_REQUEST_ID, &nonce.to_be_bytes());
        let options = SendOptions::default();
        if self
            .send_unicast(local_id, &peer_key, payload.as_slice(), &options)
            .await
            .is_ok()
        {
            if let Some(slot) = self.identity_mut(local_id) {
                let _ = slot.pending_counter_resync_mut().insert(
                    peer_id,
                    PendingCounterResync {
                        nonce,
                        requested_ms: now_ms,
                    },
                );
            }
        }
    }

    fn store_deferred_counter_resync_frame(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
        frame: &[u8],
        rx: &RxInfo,
        received_at_ms: u64,
    ) {
        let mut stored = Vec::new();
        stored
            .extend_from_slice(frame)
            .expect("received frame length must fit configured frame capacity");
        self.deferred_counter_resync_frame = Some(DeferredCounterResyncFrame {
            local_id,
            peer_id,
            frame: stored,
            rssi: rx.rssi,
            snr: rx.snr,
            lqi: rx.lqi,
            received_at_ms,
        });
    }

    fn take_deferred_counter_resync_frame(
        &mut self,
        local_id: LocalIdentityId,
        peer_id: PeerId,
    ) -> Option<DeferredCounterResyncFrame<FRAME>> {
        match self.deferred_counter_resync_frame.as_ref() {
            Some(deferred) if deferred.local_id == local_id && deferred.peer_id == peer_id => {
                self.deferred_counter_resync_frame.take()
            }
            _ => None,
        }
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

    fn clear_peer_slot_state(&mut self, peer_id: PeerId) {
        for slot in self.identities.iter_mut().filter_map(|slot| slot.as_mut()) {
            let _ = slot.peer_crypto_mut().remove(&peer_id);
            let _ = slot.pending_counter_resync_mut().remove(&peer_id);
        }
        for channel in self.channels.iter_mut() {
            let _ = channel.replay.remove(&peer_id);
        }
    }

    /// Move every piece of `PeerId`-keyed state from `old_id` to `new_id`
    /// after a registry swap-remove relocated that peer. Mirrors the
    /// structures [`Self::clear_peer_slot_state`] clears; the destination
    /// slots were freed by the removal, so the inserts cannot overflow.
    fn rekey_peer_slot_state(&mut self, old_id: PeerId, new_id: PeerId) {
        for slot in self.identities.iter_mut().filter_map(|slot| slot.as_mut()) {
            if let Some(state) = slot.peer_crypto_mut().remove(&old_id) {
                let _ = slot.peer_crypto_mut().insert(new_id, state);
            }
            if let Some(pending) = slot.pending_counter_resync_mut().remove(&old_id) {
                let _ = slot.pending_counter_resync_mut().insert(new_id, pending);
            }
        }
        for channel in self.channels.iter_mut() {
            if let Some(window) = channel.replay.remove(&old_id) {
                let _ = channel.replay.insert(new_id, window);
            }
        }
        if let Some(deferred) = self.deferred_counter_resync_frame.as_mut() {
            if deferred.peer_id == old_id {
                deferred.peer_id = new_id;
            }
        }
    }

    /// Ensure `key` is registered at least transiently, returning its slot.
    ///
    /// A known peer is returned as-is; an unknown one is auto-registered
    /// exactly like a full-source sender would be — unpinned and
    /// LRU-evictable, never promoted. This is the node layer's hook for
    /// answering a stranger (an Identity Request reply, say) whose frame
    /// arrived on a path that does not auto-register its source, such as a
    /// broadcast. Deliberately not gated on
    /// [`auto_register_full_key_peers`](Self::auto_register_full_key_peers):
    /// the caller is making an explicit per-peer decision, not opting into
    /// registering every full-source sender.
    pub fn ensure_transient_peer(&mut self, key: &PublicKey) -> Result<PeerId, AddPeerError> {
        if let Some((peer_id, _)) = self.peer_registry.lookup_by_key(key) {
            return Ok(peer_id);
        }
        self.try_auto_register_peer(*key)
    }

    fn try_auto_register_peer(&mut self, key: PublicKey) -> Result<PeerId, AddPeerError> {
        #[cfg(feature = "software-crypto")]
        {
            if !umsh_crypto::is_valid_ed25519_public_key(&key) {
                return Err(AddPeerError::InvalidPublicKey);
            }
        }
        let now_ms = self.clock.now_ms();
        let outcome = self.peer_registry.try_insert_or_update_auto(key, now_ms)?;
        if outcome.evicted_key.is_some() {
            self.clear_peer_slot_state(outcome.peer_id);
        }
        Ok(outcome.peer_id)
    }

    fn replay_metadata<'a>(header: &PacketHeader, frame: &'a [u8]) -> Option<(u32, &'a [u8])> {
        let counter = header.sec_info?.frame_counter;
        let mic = frame.get(header.mic_range.clone())?;
        Some((counter, mic))
    }

    fn build_echo_command_payload(command_id: u8, data: &[u8]) -> Vec<u8, FRAME> {
        let mut payload = Vec::new();
        let _ = payload.push(PayloadType::MacCommand as u8);
        let _ = payload.push(command_id);
        let _ = payload.extend_from_slice(data);
        payload
    }

    fn echo_request_data(payload: &[u8]) -> Option<&[u8]> {
        let (&payload_type, rest) = payload.split_first()?;
        let (&command_id, data) = rest.split_first()?;
        if PayloadType::from_byte(payload_type)? != PayloadType::MacCommand
            || command_id != MAC_COMMAND_ECHO_REQUEST_ID
        {
            return None;
        }
        Some(data)
    }

    fn echo_response_options(frame: &[u8], header: &PacketHeader) -> SendOptions {
        let mut options = SendOptions::default();
        let requests_trace = ParsedOptions::extract(frame, header.options_range.clone())
            .map(|parsed| parsed.trace_route.is_some())
            .unwrap_or(false);
        if requests_trace {
            options = options.with_trace_route();
        }
        options
    }

    fn echo_response_nonce(payload: &[u8]) -> Option<u32> {
        let (&payload_type, rest) = payload.split_first()?;
        let (&command_id, data) = rest.split_first()?;
        if PayloadType::from_byte(payload_type)? != PayloadType::MacCommand
            || command_id != MAC_COMMAND_ECHO_RESPONSE_ID
            || data.len() != COUNTER_RESYNC_NONCE_LEN
        {
            return None;
        }
        Some(u32::from_be_bytes(data.try_into().ok()?))
    }

    fn full_key_at(frame: &[u8], offset: usize) -> Option<PublicKey> {
        let mut key = [0u8; 32];
        key.copy_from_slice(frame.get(offset..offset + 32)?);
        Some(PublicKey(key))
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

    /// True when this frame names one of our own identities as its source.
    ///
    /// A repeater is not a relay for itself. Re-flooding a packet we sent
    /// wastes airtime, and because the forwarding rewrite prepends our router
    /// hint to the trace route it also fabricates a hop that never happened —
    /// the destination then learns a return path that starts by routing back
    /// through the originator.
    fn is_locally_originated(&self, frame: &[u8], header: &PacketHeader) -> bool {
        let mut locals = self.identities.iter().filter_map(|slot| slot.as_ref());
        match header.source {
            SourceAddrRef::Hint(hint) => {
                locals.any(|slot| slot.identity().public_key().hint() == hint)
            }
            SourceAddrRef::FullKeyAt { offset } => match Self::full_key_at(frame, offset) {
                Some(key) => locals.any(|slot| *slot.identity().public_key() == key),
                None => false,
            },
            // An encrypted blind-unicast source is unreadable, and a packet
            // with no source field names nobody.
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => false,
        }
    }

    fn resolve_source_peer_candidates(
        &mut self,
        frame: &[u8],
        header: &PacketHeader,
    ) -> Vec<(PeerId, PublicKey), PEERS> {
        match header.source {
            SourceAddrRef::FullKeyAt { offset } => {
                let Some(peer_key) = Self::full_key_at(frame, offset) else {
                    return Vec::new();
                };

                if let Some((peer_id, _)) = self.peer_registry.lookup_by_key(&peer_key) {
                    let mut out = Vec::new();
                    let _ = out.push((peer_id, peer_key));
                    return out;
                }

                if self.auto_register_full_key_peers {
                    if let Ok(peer_id) = self.try_auto_register_peer(peer_key) {
                        let mut out = Vec::new();
                        let _ = out.push((peer_id, peer_key));
                        return out;
                    }
                }

                Vec::new()
            }
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
    ) -> Option<ResolvedMulticastSource> {
        match header.source {
            SourceAddrRef::FullKeyAt { offset } => {
                let mut key = [0u8; 32];
                key.copy_from_slice(frame.get(offset..offset + 32)?);
                let public_key = PublicKey(key);
                let peer_id = self
                    .peer_registry
                    .lookup_by_key(&public_key)
                    .map(|(peer_id, _)| peer_id);
                Some(ResolvedMulticastSource {
                    peer_id,
                    public_key: Some(public_key),
                    hint: Some(public_key.hint()),
                })
            }
            SourceAddrRef::Hint(hint) => {
                let resolved = self.resolve_unique_hint(hint);
                Some(ResolvedMulticastSource {
                    peer_id: resolved.map(|(peer_id, _)| peer_id),
                    public_key: resolved.map(|(_, key)| key),
                    hint: Some(hint),
                })
            }
            SourceAddrRef::Encrypted { offset, len } => match len {
                32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(frame.get(offset..offset + 32)?);
                    let public_key = PublicKey(key);
                    let peer_id = self
                        .peer_registry
                        .lookup_by_key(&public_key)
                        .map(|(peer_id, _)| peer_id);
                    Some(ResolvedMulticastSource {
                        peer_id,
                        public_key: Some(public_key),
                        hint: Some(public_key.hint()),
                    })
                }
                3 => {
                    let hint = umsh_core::NodeHint([
                        *frame.get(offset)?,
                        *frame.get(offset + 1)?,
                        *frame.get(offset + 2)?,
                    ]);
                    let resolved = self.resolve_unique_hint(hint);
                    Some(ResolvedMulticastSource {
                        peer_id: resolved.map(|(peer_id, _)| peer_id),
                        public_key: resolved.map(|(_, key)| key),
                        hint: Some(hint),
                    })
                }
                _ => None,
            },
            SourceAddrRef::None => None,
        }
    }

    fn accept_unknown_multicast_replay(&mut self, header: &PacketHeader, frame: &[u8]) -> bool {
        let Some(cache_key) = Self::forward_dup_key(header, frame) else {
            return false;
        };
        let now_ms = self.clock.now_ms();
        if self
            .multicast_unknown_dup_cache
            .contains(&cache_key, now_ms)
        {
            return false;
        }
        self.multicast_unknown_dup_cache.insert(cache_key, now_ms);
        true
    }

    fn resolve_blind_source_peer_candidates(
        &mut self,
        frame: &[u8],
        source: SourceAddrRef,
    ) -> Vec<(PeerId, PublicKey), PEERS> {
        match source {
            SourceAddrRef::FullKeyAt { offset } => {
                let Some(peer_key) = Self::full_key_at(frame, offset) else {
                    return Vec::new();
                };

                if let Some((peer_id, _)) = self.peer_registry.lookup_by_key(&peer_key) {
                    let mut out = Vec::new();
                    let _ = out.push((peer_id, peer_key));
                    return out;
                }

                if self.auto_register_full_key_peers {
                    if let Ok(peer_id) = self.try_auto_register_peer(peer_key) {
                        let mut out = Vec::new();
                        let _ = out.push((peer_id, peer_key));
                        return out;
                    }
                }

                Vec::new()
            }
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
            if let Some(route) = self.source_route_from_trace(frame.get(trace_range).unwrap_or(&[]))
            {
                // A trace route that accumulated no hints means the packet
                // reached us without passing through a repeater. That is a
                // direct neighbour, not a zero-hop source route — caching it
                // as a route would attach an empty SourceRoute option to
                // everything we send back. Only a repeater consuming the
                // final hint may leave an empty option behind, for
                // provenance; an originator must never add one.
                let learned = if route.is_empty() {
                    crate::CachedRoute::Direct
                } else {
                    crate::CachedRoute::Source(route)
                };
                self.peer_registry.update_route(peer_id, learned);
                return;
            }
        }

        // A source-routed packet — including one whose hints are all consumed,
        // since the emptied option is preserved for provenance — spends flood
        // budget only after the route runs out. Its `FHOPS_ACC` therefore
        // counts the tail of the path, not its length, and would understate
        // how far away the peer is. Leave whatever route is already cached
        // (that route is what carried this packet here) rather than replacing
        // it with a distance estimate that is known to be short.
        if options.source_route.is_some() {
            return;
        }

        if let Some(flood_hops) = header.flood_hops {
            let regions = Self::region_codes_from_options(frame, header.options_range.clone());
            self.peer_registry.update_route(
                peer_id,
                crate::CachedRoute::Flood {
                    hops: flood_hops.accumulated(),
                    regions,
                },
            );
        }
    }

    fn region_codes_from_options(
        frame: &[u8],
        options_range: core::ops::Range<usize>,
    ) -> Vec<[u8; 2], 8> {
        let mut regions = Vec::new();
        if options_range.is_empty() {
            return regions;
        }
        for entry in umsh_core::iter_options(frame, options_range) {
            let Ok((number, value)) = entry else {
                continue;
            };
            if OptionNumber::from(number) != OptionNumber::RegionCode || value.len() != 2 {
                continue;
            }
            if regions.push([value[0], value[1]]).is_err() {
                break;
            }
        }
        regions
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

        PayloadType::from_byte(payload[0])
            .unwrap_or(PayloadType::Empty)
            .allowed_for(packet_type)
    }

    fn source_route_from_trace(
        &self,
        trace_bytes: &[u8],
    ) -> Option<heapless::Vec<RouterHint, { crate::MAX_SOURCE_ROUTE_HOPS }>> {
        if trace_bytes.len() % 2 != 0 {
            return None;
        }

        let mut route = heapless::Vec::new();
        for chunk in trace_bytes.chunks_exact(2) {
            route.push(RouterHint([chunk[0], chunk[1]])).ok()?;
        }
        Some(route)
    }

    fn should_emit_destination_ack(&self, frame: &[u8], header: &PacketHeader) -> bool {
        let Ok(options) = ParsedOptions::extract(frame, header.options_range.clone()) else {
            return false;
        };

        // Destination ACKs are emitted only once a source route is fully
        // consumed. An empty SourceRoute still matters for provenance, but it
        // no longer constrains forwarding and therefore counts as "at the
        // destination" for ACK purposes.
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
        if !self.repeater.enabled {
            return false;
        }
        if !header.packet_type().is_routable() {
            return false;
        }
        if self.is_locally_originated(frame, header) {
            return false;
        }
        // A packet that names one of our identities as its destination has
        // arrived. Whether we could actually process it — we may lack the key,
        // or it may be a replay — is a separate question from whether it still
        // needs carrying, and it does not.
        if self.find_local_identity_for_dst(header.dst).is_some() {
            return false;
        }
        // Once a point-to-point packet is handled by its actual destination, it
        // should not also be repeated by that same node. This still matters for
        // encrypted blind unicast, whose destination hint is not on the wire.
        // Other packet classes, including broadcast and MAC ACK, remain
        // routable.
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
        if self.dup_cache.contains(&cache_key, self.clock.now_ms()) {
            self.defer_pending_forward(&cache_key, header, rx, &options);
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
                None,
                now_ms.saturating_add(plan.delay_ms),
                0,
                0,
            )
            .is_err()
        {
            return false;
        }
        self.dup_cache.insert(cache_key, now_ms);
        // Counted at the decision to repeat rather than at the eventual
        // transmit, so the tally measures what this node chose to carry.
        // The frame is also counted again in `tx_frames` when it actually
        // goes out, which is the correct relationship: a repeat that CAD
        // abandons shows up here and not there.
        MacCounters::bump(&mut self.counters.forwarded);
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
        let mut insert_region_code = None;
        let mut delay_ms = 0u64;

        if !source_route_bytes.is_empty() {
            // A source-routed hop costs no flood budget, even the one that
            // consumes the last hint: `FHOPS` counts flood hops only
            // (packet-structure.md § Flood Hop Count). Emptying the route
            // makes the packet floodable, but the transition is observed by
            // the *next* repeater, which sees an empty route and pays for the
            // first real flood hop. Everything gated below — hop accounting,
            // signal thresholds, region policy, contention delay — is flood
            // behaviour and does not apply to a hop that was named explicitly.
            if source_route_bytes[..2] != router_hint.0 {
                return None;
            }
            consume_source_route = true;
        } else {
            decrement_flood_hops = true;
        }

        if decrement_flood_hops {
            let flood_hops = header.flood_hops?;
            if flood_hops.remaining() == 0 {
                return None;
            }
            // Signal-quality filtering applies only to flood forwarding,
            // not to source-routed hops.
            if let Some(min_rssi) = Self::effective_min_rssi(options, &self.repeater) {
                if rx.rssi < min_rssi {
                    return None;
                }
            }
            if let Some(min_snr) = Self::effective_min_snr(options, &self.repeater) {
                if rx.snr < Snr::from_decibels(min_snr) {
                    return None;
                }
            }
            let mut saw_region_code = false;
            let mut matched_region_code = false;
            if !header.options_range.is_empty() {
                for entry in umsh_core::iter_options(frame, header.options_range.clone()) {
                    let (number, value) = entry.ok()?;
                    if OptionNumber::from(number) != OptionNumber::RegionCode || value.len() != 2 {
                        continue;
                    }
                    saw_region_code = true;
                    let region_code = [value[0], value[1]];
                    if self
                        .repeater
                        .regions
                        .iter()
                        .any(|configured| *configured == region_code)
                    {
                        matched_region_code = true;
                    }
                }
            }
            if saw_region_code {
                // An empty configured list imposes no regional restriction.
                if !self.repeater.regions.is_empty() && !matched_region_code {
                    return None;
                }
            } else {
                insert_region_code = self.repeater.default_region;
            }
            delay_ms = self.sample_flood_contention_delay_ms(rx, options);
            // An ack-requested packet flood-forwarded with no remaining
            // source-route hops elicits an immediate, CAD-skipping ACK from its
            // destination (channel-access.md § Immediate ACK Transmission);
            // hold the forward back long enough for that ACK to clear.
            if header.ack_requested() {
                delay_ms = delay_ms.saturating_add(self.ack_guard_delay_ms());
            }
        }

        Some(ForwardPlan {
            router_hint,
            consume_source_route,
            decrement_flood_hops,
            insert_region_code,
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

        // FCF (no options bit in new format)
        dst[0] = umsh_core::Fcf::new(
            header.packet_type(),
            header.fcf.full_source(),
            header.flood_hops.is_some(),
        )
        .0;
        let mut cursor = 1;

        // FHOPS
        if let Some(flood_hops) = header.flood_hops {
            let next = if plan.decrement_flood_hops {
                flood_hops.decremented().0
            } else {
                flood_hops.0
            };
            *dst.get_mut(cursor).ok_or(CapacityError)? = next;
            cursor += 1;
        }

        // Fixed core: DST/CHANNEL/SRC/SECINFO from original (between FHOPS and options)
        let fhops_len = usize::from(header.flood_hops.is_some());
        let fixed_core = src
            .get(1 + fhops_len..header.options_range.start)
            .ok_or(CapacityError)?;
        let core_end = cursor + fixed_core.len();
        dst.get_mut(cursor..core_end)
            .ok_or(CapacityError)?
            .copy_from_slice(fixed_core);
        cursor = core_end;

        // Re-encoded options (without 0xFF — caller emits marker)
        let options_len =
            self.encode_forwarded_options(src, header, options, plan, &mut dst[cursor..])?;
        cursor += options_len;

        // 0xFF marker when a body follows (not needed for MAC ack whose trailer is at fixed offset)
        let needs_marker = !matches!(header.packet_type(), PacketType::MacAck)
            && header.options_range.end < header.total_len;
        if needs_marker {
            *dst.get_mut(cursor).ok_or(CapacityError)? = 0xFF;
            cursor += 1;
        }

        // Body + MIC from original (src[options_range.end] is already past the original 0xFF)
        let tail = src
            .get(header.options_range.end..header.total_len)
            .ok_or(CapacityError)?;
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
        let mut inserted_region = false;
        let mut inserted_station = false;
        let mut saw_station = false;

        if !header.options_range.is_empty() {
            for entry in umsh_core::iter_options(src, header.options_range.clone()) {
                let (number, value) = entry.map_err(|_| CapacityError)?;
                if !inserted_region {
                    if let Some(region_code) = plan.insert_region_code {
                        if number > OptionNumber::RegionCode.as_u16() {
                            encoder
                                .put(OptionNumber::RegionCode.as_u16(), &region_code)
                                .map_err(|_| CapacityError)?;
                            inserted_region = true;
                        }
                    }
                }
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
                }

                match OptionNumber::from(number) {
                    OptionNumber::RegionCode => {
                        inserted_region = true;
                        encoder.put(number, value).map_err(|_| CapacityError)?;
                    }
                    OptionNumber::TraceRoute => {
                        let mut trace = [0u8; crate::MAX_SOURCE_ROUTE_HOPS * 2 + 2];
                        trace[..2].copy_from_slice(&plan.router_hint.0);
                        trace[2..2 + value.len()].copy_from_slice(value);
                        encoder
                            .put(number, &trace[..2 + value.len()])
                            .map_err(|_| CapacityError)?;
                    }
                    OptionNumber::SourceRoute if plan.consume_source_route => {
                        if value.len() < 2 || value.len() % 2 != 0 {
                            return Err(CapacityError);
                        }
                        let remaining = if value.len() > 2 { &value[2..] } else { &[] };
                        encoder.put(number, remaining).map_err(|_| CapacityError)?;
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
                            }
                        }
                    }
                    _ => {
                        encoder.put(number, value).map_err(|_| CapacityError)?;
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
        }
        if let Some(region_code) = plan.insert_region_code {
            if !inserted_region {
                encoder
                    .put(OptionNumber::RegionCode.as_u16(), &region_code)
                    .map_err(|_| CapacityError)?;
            }
        }
        Ok(encoder.finish())
    }

    fn synthesize_route_retry_resend(
        &self,
        peer: &PublicKey,
        resend: &ResendRecord<FRAME>,
    ) -> Option<ResendRecord<FRAME>> {
        let header = PacketHeader::parse(resend.frame.as_slice()).ok()?;
        let options =
            ParsedOptions::extract(resend.frame.as_slice(), header.options_range.clone()).ok()?;
        if options.route_retry {
            return None;
        }
        let source_route = resend
            .source_route
            .as_ref()
            .filter(|route| !route.is_empty());
        if source_route.is_none() && resend.requested_flood_hops.is_none() {
            // Neither a route to abandon nor an application budget to restore.
            return None;
        }

        let flood_hops =
            self.route_retry_flood_hops(peer, &header, source_route, resend.requested_flood_hops)?;
        let has_flood_hops = flood_hops > 0;
        let mut rewritten = [0u8; FRAME];

        // FCF
        rewritten[0] = umsh_core::Fcf::new(
            header.packet_type(),
            header.fcf.full_source(),
            has_flood_hops,
        )
        .0;
        let mut cursor = 1;

        // FHOPS
        if has_flood_hops {
            *rewritten.get_mut(cursor)? = FloodHops::new(flood_hops, 0)?.0;
            cursor += 1;
        }

        // Fixed core: DST/CHANNEL/SRC/SECINFO from original
        let fhops_len = usize::from(header.flood_hops.is_some());
        let fixed_core = resend
            .frame
            .get(1 + fhops_len..header.options_range.start)?;
        let core_end = cursor + fixed_core.len();
        rewritten
            .get_mut(cursor..core_end)?
            .copy_from_slice(fixed_core);
        cursor = core_end;

        // Re-encoded options
        let options_len = self
            .encode_route_retry_options(
                resend.frame.as_slice(),
                header.options_range.clone(),
                &options,
                &mut rewritten[cursor..],
            )
            .ok()?;
        cursor += options_len;

        // 0xFF marker when body follows
        let needs_marker = !matches!(header.packet_type(), PacketType::MacAck)
            && header.options_range.end < header.total_len;
        if needs_marker {
            *rewritten.get_mut(cursor)? = 0xFF;
            cursor += 1;
        }

        // Body + MIC from original
        let tail = resend
            .frame
            .get(header.options_range.end..header.total_len)?;
        let end = cursor + tail.len();
        rewritten.get_mut(cursor..end)?.copy_from_slice(tail);

        ResendRecord::try_new(&rewritten[..end], None)
            .ok()
            .map(|record| record.with_requested_flood_hops(resend.requested_flood_hops))
    }

    fn encode_route_retry_options(
        &self,
        src: &[u8],
        options_range: core::ops::Range<usize>,
        _options: &ParsedOptions,
        dst: &mut [u8],
    ) -> Result<usize, CapacityError> {
        let mut encoder = OptionEncoder::new(dst);
        let mut inserted_trace_route = false;
        let mut inserted_route_retry = false;

        if !options_range.is_empty() {
            for entry in umsh_core::iter_options(src, options_range) {
                let (number, value) = entry.map_err(|_| CapacityError)?;
                if !inserted_trace_route && number > OptionNumber::TraceRoute.as_u16() {
                    encoder
                        .put(OptionNumber::TraceRoute.as_u16(), &[])
                        .map_err(|_| CapacityError)?;
                    inserted_trace_route = true;
                }
                if !inserted_route_retry && number > OptionNumber::RouteRetry.as_u16() {
                    encoder
                        .put(OptionNumber::RouteRetry.as_u16(), &[])
                        .map_err(|_| CapacityError)?;
                    inserted_route_retry = true;
                }
                match OptionNumber::from(number) {
                    OptionNumber::SourceRoute => {}
                    OptionNumber::TraceRoute => {
                        encoder.put(number, value).map_err(|_| CapacityError)?;
                        inserted_trace_route = true;
                    }
                    OptionNumber::RouteRetry => {}
                    _ => {
                        encoder.put(number, value).map_err(|_| CapacityError)?;
                    }
                }
            }
        }

        if !inserted_trace_route {
            encoder
                .put(OptionNumber::TraceRoute.as_u16(), &[])
                .map_err(|_| CapacityError)?;
        }
        if !inserted_route_retry {
            encoder
                .put(OptionNumber::RouteRetry.as_u16(), &[])
                .map_err(|_| CapacityError)?;
        }

        Ok(encoder.finish())
    }

    fn route_retry_flood_hops(
        &self,
        peer: &PublicKey,
        header: &PacketHeader,
        source_route: Option<&heapless::Vec<RouterHint, MAX_SOURCE_ROUTE_HOPS>>,
        requested: Option<u8>,
    ) -> Option<u8> {
        // The failed attempt was narrowed against a route assumption — either
        // an attached source route, or a cached route that clamped `FHOPS_REM`
        // below what was asked for. Rediscovery has to reach past the break,
        // so prefer the budget the application was willing to spend; it is
        // also the ceiling, since route recovery may undo the MAC's narrowing
        // but not exceed the caller's own limit.
        let requested = requested
            .filter(|hops| *hops > 0)
            .map(|hops| hops.clamp(1, MAX_FLOOD_HOPS));
        let existing = header
            .flood_hops
            .map(|hops| hops.remaining())
            .filter(|hops| *hops > 0);
        let cached = self
            .peer_registry
            .lookup_by_key(peer)
            .and_then(|(_, info)| match info.route.as_ref() {
                Some(crate::CachedRoute::Flood { hops, .. }) => {
                    Some((*hops).clamp(1, MAX_FLOOD_HOPS))
                }
                _ => None,
            });
        let route_len = source_route
            .and_then(|route| u8::try_from(route.len()).ok())
            .map(|hops| hops.clamp(1, MAX_FLOOD_HOPS));

        requested.or(existing).or(cached).or(route_len).or(Some(5))
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
        let effective_threshold_db =
            Self::effective_min_snr(options, &self.repeater).unwrap_or(i8::MIN);
        let low_db = self
            .repeater
            .flood_contention_snr_low_db
            .max(effective_threshold_db);
        let high_db = self
            .repeater
            .flood_contention_snr_high_db
            .max(low_db.saturating_add(1));
        let low = i32::from(Snr::from_decibels(low_db).as_centibels());
        let high = i32::from(Snr::from_decibels(high_db).as_centibels());
        let received = i32::from(rx.snr.as_centibels());
        let clamped = (received - low).clamp(0, high - low) as u32;
        let range = (high - low) as u32;
        let t_frame_ms = u64::from(self.radio.t_frame_ms());
        let min_window_ms = t_frame_ms
            .saturating_mul(u64::from(self.repeater.flood_contention_min_window_percent))
            / 100;
        let max_window_ms = t_frame_ms
            .saturating_mul(u64::from(self.repeater.flood_contention_max_window_frames))
            .max(min_window_ms);
        let window_span_ms = max_window_ms.saturating_sub(min_window_ms);
        let window_ms = if range == 0 {
            max_window_ms
        } else {
            max_window_ms.saturating_sub(
                window_span_ms.saturating_mul(u64::from(clamped)) / u64::from(range),
            )
        };
        if window_ms == 0 {
            0
        } else {
            self.rng.random_range(..window_ms.saturating_add(1))
        }
    }

    /// ACK protection interval: minimum head start granted to a destination's
    /// immediate ACK before any flood forward of the same packet may transmit.
    fn ack_guard_delay_ms(&self) -> u64 {
        u64::from(self.radio.t_frame_ms())
            .saturating_mul(u64::from(self.repeater.flood_contention_ack_guard_percent))
            / 100
    }

    /// Routing identity used for duplicate suppression at repeaters.
    ///
    /// Defined in [`crate::forward_id`], which every forwarder in the mesh
    /// shares.
    pub(crate) fn forward_dup_key(header: &PacketHeader, frame: &[u8]) -> Option<DupCacheKey> {
        crate::forward_id::forwarding_dup_key_parsed(header, frame)
    }

    fn defer_pending_forward(
        &mut self,
        key: &DupCacheKey,
        header: &PacketHeader,
        rx: &RxInfo,
        options: &ParsedOptions,
    ) {
        let Some(queued) = self.tx_queue.remove_first_matching(|entry| {
            entry.priority == TxPriority::Forward
                && Self::confirmation_key(entry.frame.as_slice())
                    .map(|entry_key| &entry_key == key)
                    .unwrap_or(false)
        }) else {
            return;
        };

        if queued.forward_deferrals >= self.repeater.flood_contention_max_deferrals {
            return;
        }

        let now_ms = self.clock.now_ms();
        let mut delay_ms = self.sample_flood_contention_delay_ms(rx, options);
        // The overheard copy may itself elicit an immediate ACK from the
        // destination; give that ACK the same head start as on first receipt.
        let overheard_has_route_hops = options
            .source_route
            .as_ref()
            .map(|range| !range.is_empty())
            .unwrap_or(false);
        if header.ack_requested() && !overheard_has_route_hops {
            delay_ms = delay_ms.saturating_add(self.ack_guard_delay_ms());
        }
        let _ = self.tx_queue.enqueue_with_state(
            queued.priority,
            queued.frame.as_slice(),
            queued.receipt,
            queued.identity_id,
            now_ms.saturating_add(delay_ms),
            queued.cad_attempts,
            queued.forward_deferrals.saturating_add(1),
        );
    }

    /// Drop any queued forward the destination has already acknowledged.
    ///
    /// A MAC ack echoes `ack_mic` — the first four bytes of the acknowledged
    /// packet's on-wire MIC — which every forwarder can read without keys, and
    /// which survives the rewrites a repeater performs. A forward still sitting
    /// in the transmit queue when that ack is overheard has been overtaken by
    /// events: the destination has the packet, so repeating it buys nothing but
    /// airtime. The [ACK protection interval] exists to put the ack on the air
    /// first, which is precisely what makes this observation available.
    ///
    /// This cancels what is queued at this instant and leaves nothing behind. A
    /// [route-retry] copy that arrives later carries a distinct forwarding
    /// identity, is queued and forwarded normally — the origin resorted to it
    /// because the ack never reached it, and carrying it prompts the
    /// destination to acknowledge again — and is in turn cancelable by another
    /// overheard ack.
    ///
    /// Only unattributed forwards are eligible. A queued frame carrying a
    /// receipt is this node's own send, whose completion is decided by the
    /// authenticated `ack_tag` in [`Mac::complete_ack`], never by a four-byte
    /// public prefix.
    ///
    /// [ACK protection interval]: https://darconeous.github.io/umsh/docs/protocol/channel-access.html#ack-protection-interval
    /// [route-retry]: https://darconeous.github.io/umsh/docs/protocol/packet-options.html#route-retry-option-6
    fn cancel_forwards_for_ack_mic(&mut self, ack_mic: &[u8]) -> usize {
        if ack_mic.len() != 4 {
            return 0;
        }
        let removed = self.tx_queue.remove_all_matching(|entry| {
            if entry.priority != TxPriority::Forward || entry.receipt.is_some() {
                return false;
            }
            let frame = entry.frame.as_slice();
            let Ok(header) = PacketHeader::parse(frame) else {
                return false;
            };
            // Only the packet types whose destination emits a MAC ack can be
            // the subject of one. Without this, a forwarded ack awaiting
            // transmission would be cancelled by a second copy of itself: a
            // MAC ack's own trailer opens with the same four bytes it echoes.
            if !matches!(
                header.packet_type(),
                PacketType::UnicastAckReq | PacketType::BlindUnicastAckReq
            ) {
                return false;
            }
            frame
                .get(header.mic_range.clone())
                .and_then(|mic| mic.get(..4))
                .map(|prefix| prefix == ack_mic)
                .unwrap_or(false)
        });
        if removed > 0 {
            MacCounters::bump(&mut self.counters.forward_cancelled);
        }
        removed
    }

    /// Cancel queued forwards named by a piggy-backed [Ack MIC option].
    ///
    /// The option carries the same correlation handle as a standalone ack, on
    /// an ordinary authenticated packet travelling the other way. It sits in
    /// the options block, which is not encrypted, so a forwarder reads it
    /// under the same terms as the standalone form.
    ///
    /// [Ack MIC option]: https://darconeous.github.io/umsh/docs/protocol/packet-options.html#ack-mic-option-8
    fn cancel_forwards_for_ack_mic_option(&mut self, frame: &[u8], header: &PacketHeader) {
        if header.options_range.is_empty() {
            return;
        }
        let mut ack_mic = None;
        for entry in umsh_core::iter_options(frame, header.options_range.clone()) {
            let Ok((number, value)) = entry else {
                continue;
            };
            if OptionNumber::from(number) == OptionNumber::AckMic && value.len() == 4 {
                ack_mic = Some([value[0], value[1], value[2], value[3]]);
                break;
            }
        }
        if let Some(ack_mic) = ack_mic {
            self.cancel_forwards_for_ack_mic(&ack_mic);
        }
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

    /// Start the completion timers for a tracked send that just went on the air.
    fn note_transmitted_tracked(&mut self, receipt: SendReceipt, frame: &[u8]) {
        let sent_ms = self.clock.now_ms();
        let direct_ack_deadline_ms = sent_ms.saturating_add(self.direct_ack_timeout_ms());
        let forwarded_ack_deadline_ms = sent_ms.saturating_add(self.forwarded_ack_timeout_ms());
        let repeat_only_deadline_ms = sent_ms.saturating_add(self.repeat_confirm_timeout_ms());
        let confirm_timeout_ms = self.forward_confirm_timeout_ms();
        let confirm_key = Self::confirmation_key(frame);

        let post_tx_listen = {
            let Some((identity_id, pending)) = self.pending_ack_mut(receipt) else {
                return;
            };

            let needs_forward_confirmation = match pending.state {
                crate::AckState::Queued {
                    needs_forward_confirmation,
                } => needs_forward_confirmation,
                crate::AckState::RetryQueued => true,
                _ => return,
            };

            pending.sent_ms = sent_ms;
            pending.confirm_key = confirm_key.clone();
            // Zero means the send has never aired and its window is still to
            // be set. A route retry arrives here already armed — it has to be,
            // to survive the wait in the queue — and keeps the deadline it was
            // scheduled with.
            if pending.ack_deadline_ms == 0 {
                pending.ack_deadline_ms = match (pending.completion, needs_forward_confirmation) {
                    (CompletionSignal::RepeatOnly, _) => repeat_only_deadline_ms,
                    (CompletionSignal::Ack, true) => forwarded_ack_deadline_ms,
                    (CompletionSignal::Ack, false) => direct_ack_deadline_ms,
                };
            }

            if needs_forward_confirmation {
                let deadline_ms = sent_ms.saturating_add(confirm_timeout_ms);
                pending.state = crate::AckState::AwaitingForward {
                    confirm_deadline_ms: deadline_ms,
                };
                // The dedicated listen window — which holds all other
                // transmissions back for the whole confirmation wait — is
                // reserved for sends with an ACK on the line. A repeat-only
                // send is best-effort by construction; the pending entry
                // matches an overheard repeat whenever the radio hears one,
                // and stalling unrelated traffic for seconds is a price
                // best-effort delivery does not get to charge.
                if pending.expects_ack() {
                    confirm_key.map(|confirm_key| PostTxListen {
                        identity_id,
                        receipt,
                        confirm_key,
                        deadline_ms,
                    })
                } else {
                    None
                }
            } else {
                pending.state = crate::AckState::AwaitingAck;
                None
            }
        };

        self.post_tx_listen = post_tx_listen;
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

    fn forward_confirm_timeout_ms(&self) -> u64 {
        let t_frame_ms = u64::from(self.radio.t_frame_ms());
        t_frame_ms
            .saturating_add(self.max_forward_contention_delay_ms())
            .saturating_add(self.ack_guard_delay_ms())
            .saturating_add(t_frame_ms)
    }

    fn max_forward_contention_delay_ms(&self) -> u64 {
        u64::from(self.radio.t_frame_ms())
            .saturating_mul(u64::from(self.repeater.flood_contention_max_window_frames))
    }

    /// Jitter cap for a forwarding-confirmation retry: one frame time, flat
    /// across the ladder.
    ///
    /// The jitter exists to decorrelate retries between nodes, and one frame
    /// time is all that takes. Growing the delay would only stretch the
    /// ladder: every window it adds is time the payload spends undelivered,
    /// and a packet the mesh cannot carry after three prompt attempts is
    /// better dropped than delivered tens of seconds late.
    fn forward_retry_backoff_cap_ms(&self) -> u32 {
        self.radio.t_frame_ms()
    }

    /// Whether a timed-out send carries a route assumption worth abandoning.
    ///
    /// An attached source route is the obvious case: the named path did not
    /// deliver. The subtler one is a flood budget the MAC narrowed on the
    /// sender's behalf. A peer cached as [`CachedRoute::Direct`] transmits at
    /// [`ESTABLISHED_ROUTE_EXTRA_HOPS`] however wide a flood the application
    /// asked for, so a peer that has since moved out of direct range cannot be
    /// reached by repeating the same frame — and nothing in the options records
    /// that a route was ever assumed. That is the same staleness as a dead
    /// source-route hint, kept in `FHOPS` instead of in an option.
    ///
    /// A budget the *application* chose is left alone. Route recovery exists to
    /// undo the MAC's own narrowing, not to flood wider than the caller was
    /// willing to.
    fn can_attempt_route_retry(pending: &PendingAck<FRAME>) -> bool {
        // Route recovery re-attempts delivery of a packet whose fate is
        // knowable. A send with no ack to wait for never learns whether the
        // route failed, so it has nothing to recover from.
        if !pending.expects_ack() {
            return false;
        }
        let Ok(header) = PacketHeader::parse(pending.resend.frame.as_slice()) else {
            return false;
        };
        let Ok(options) = ParsedOptions::extract(
            pending.resend.frame.as_slice(),
            header.options_range.clone(),
        ) else {
            return false;
        };
        if options.route_retry {
            return false;
        }
        let has_source_route = pending
            .resend
            .source_route
            .as_ref()
            .map(|route| !route.is_empty())
            .unwrap_or(false);
        if has_source_route {
            return true;
        }
        // An absent `FHOPS` byte is a budget of zero: the send went out direct.
        let sent = header
            .flood_hops
            .map(|hops| hops.remaining())
            .unwrap_or_default();
        pending
            .resend
            .requested_flood_hops
            .is_some_and(|requested| requested > sent)
    }

    fn direct_ack_timeout_ms(&self) -> u64 {
        u64::from(self.radio.t_frame_ms()).saturating_mul(10)
    }

    fn forwarded_ack_timeout_ms(&self) -> u64 {
        self.repeat_confirm_timeout_ms()
            .saturating_add(u64::from(self.radio.t_frame_ms()))
    }

    /// How long a send waits to overhear its own packet carried onward before
    /// the attempt is over.
    ///
    /// This spans the full retry ladder: every confirmation window plus the
    /// backoff that separates them. A send with no ACK to wait for ends here;
    /// an ACK-requested send allows a further frame time for the ack to
    /// return.
    fn repeat_confirm_timeout_ms(&self) -> u64 {
        let per_retry_ms = u64::from(self.forward_retry_backoff_cap_ms())
            .saturating_add(self.forward_confirm_timeout_ms());
        self.forward_confirm_timeout_ms()
            .saturating_add(per_retry_ms.saturating_mul(u64::from(MAX_FORWARD_RETRIES)))
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

    pub(crate) fn confirmation_key(frame: &[u8]) -> Option<DupCacheKey> {
        crate::forward_id::forwarding_dup_key(frame)
    }

    /// Check if a received frame confirms forwarding of a pending send.
    ///
    /// Confirmation is not tied to the post-transmit listen window. That
    /// window governs when this node stays off the air waiting; the sender's
    /// interest in hearing its packet carried onward outlives it. A repeat
    /// that arrives late — or while a retransmission is already sitting in
    /// backoff — is the same evidence it would have been a moment earlier, so
    /// every pending send still waiting for a repeat is matched, and a retry
    /// queued on its behalf is withdrawn.
    ///
    /// Returns `Some((identity_id, receipt))` on successful confirmation,
    /// `None` otherwise. A send expecting an ACK moves on to wait for it; a
    /// [`CompletionSignal::RepeatOnly`] send is finished by the repeat itself.
    fn observe_forwarding_confirmation(
        &mut self,
        frame: &[u8],
    ) -> Option<(LocalIdentityId, SendReceipt)> {
        self.expire_post_tx_listen_if_needed();
        let received_key = Self::confirmation_key(frame)?;

        // Whatever the pending table decides below, the wait itself is over.
        if self
            .post_tx_listen
            .as_ref()
            .map(|listen| listen.confirm_key == received_key)
            .unwrap_or(false)
        {
            self.post_tx_listen = None;
        }

        let mut found = None;
        'search: for (index, slot) in self.identities.iter().enumerate() {
            let Some(slot) = slot.as_ref() else {
                continue;
            };
            for (receipt, pending) in slot.pending_acks.iter() {
                if !matches!(
                    pending.state,
                    crate::AckState::AwaitingForward { .. } | crate::AckState::RetryQueued
                ) {
                    continue;
                }
                if pending.confirm_key.as_ref() != Some(&received_key) {
                    continue;
                }
                found = Some((LocalIdentityId(index as u8), *receipt, pending.completion));
                break 'search;
            }
        }
        let (identity_id, receipt, completion) = found?;

        // A retransmission scheduled while this confirmation was in flight has
        // been overtaken by it.
        self.tx_queue.remove_all_matching(|entry| {
            entry.receipt == Some(receipt) && entry.identity_id == Some(identity_id)
        });

        match completion {
            CompletionSignal::Ack => {
                if let Some(pending) = self
                    .identity_mut(identity_id)
                    .and_then(|slot| slot.pending_ack_mut(&receipt))
                {
                    pending.state = crate::AckState::AwaitingAck;
                }
            }
            // Nothing further is coming: the repeat was the whole point.
            CompletionSignal::RepeatOnly => {
                if let Some(slot) = self.identity_mut(identity_id) {
                    slot.pending_acks.remove(&receipt);
                }
            }
        }
        Some((identity_id, receipt))
    }

    /// Find the destination peer of the outstanding ack-requested send whose
    /// expected ack trailer (`ack_mic || ack_tag`) equals `ack_trailer`,
    /// searching every local identity's pending table.
    fn peer_for_ack_trailer(&self, ack_trailer: &[u8; 8]) -> Option<PublicKey> {
        self.identities
            .iter()
            .filter_map(|slot| slot.as_ref())
            .find_map(|slot| self.match_pending_peer_for_ack(slot, ack_trailer))
    }

    fn match_pending_peer_for_ack(
        &self,
        slot: &IdentitySlot<P::Identity, PEERS, ACKS, FRAME>,
        ack_trailer_bytes: &[u8],
    ) -> Option<PublicKey> {
        if ack_trailer_bytes.len() != 8 {
            return None;
        }

        slot.pending_acks.iter().find_map(|(_, pending)| {
            (pending.expects_ack() && pending.ack_trailer == ack_trailer_bytes)
                .then_some(pending.peer)
        })
    }
}

fn align_counter_boundary(value: u32) -> u32 {
    value & !COUNTER_PERSIST_BLOCK_MASK
}

pub(crate) const fn nonzero_initial_frame_counter(random: u32) -> u32 {
    if random == 0 { 1 } else { random }
}

fn next_counter_persist_target(next_counter: u32) -> u32 {
    next_counter.wrapping_add(COUNTER_PERSIST_BLOCK_SIZE) & !COUNTER_PERSIST_BLOCK_MASK
}

/// Build the CounterStore context key for a peer's RX boundary.
///
/// Format: `mac.rx:` (7 bytes) + raw Ed25519 pubkey (32 bytes) = 39 bytes.
/// This is distinct from the TX key (which is the bare 32-byte local pubkey)
/// and from peer record keys in the flash KV store.
fn rx_counter_key_bytes(pk: &[u8; 32]) -> [u8; 39] {
    let mut key = [0u8; 39];
    key[..7].copy_from_slice(b"mac.rx:");
    key[7..].copy_from_slice(pk);
    key
}
