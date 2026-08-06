import Foundation
import UMSHMobileCore

protocol RadioConnection: AnyObject, Sendable {
    func snapshots() async -> AsyncStream<RadioSnapshot>
    func receivedFrames() async -> AsyncStream<RadioReceivedFrame>
    func chatUpdates() async -> AsyncStream<RadioChatUpdate>
    func advertisementEvents() async -> AsyncStream<RadioAdvertisementEvent>
    /// Every frame the mesh accepted, reported as presence only. This is the
    /// sole signal a beacon produces, so it is what keeps "last heard" honest
    /// for nodes that are reachable but have nothing to say.
    func peerHeardEvents() async -> AsyncStream<RadioPeerHeardEvent>
    func advertiseIdentity(name: String?) async throws
    /// The same advertisement, sent because the phone's own interval came
    /// round rather than because someone asked for it. Reaches only direct
    /// neighbours, since a restatement on a timer does not need to cross
    /// the mesh the way an introduction does.
    func advertiseIdentityScheduled(name: String?) async throws
    /// Broadcast an empty beacon: it publishes the path back to this
    /// phone rather than who this phone is, for a fraction of the airtime.
    func sendBeacon() async throws
    /// Set the position this phone's identity carries, already reduced to
    /// the disclosed cell, or nil to stop sharing one. Reaches live
    /// identity payloads — advertisements and Identity Request replies —
    /// and never the durable QR/URI bundle. Best-effort, like
    /// discoverability: the value is reapplied on every session install.
    func setAdvertisedLocation(_ location: MobileMeshSharedLocationRecord?) async
    /// Set whether this phone answers nearby nodes' Identity Requests with
    /// its own identity, and the display name those replies carry.
    /// Best-effort: the preference is reapplied on every session install.
    func setPhoneDiscoverable(_ enabled: Bool, name: String?) async
    func signIdentityBundle(name: String?) async throws -> Data
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws
    func useMeshSession(_ session: MobileMeshSession?) async
    func autoConnect() async
    func reconnect() async
    func connect() async throws
    /// Begin an explicit discovery scan and stream the live list of nearby
    /// companion radios. The scan runs until `stopDiscovery()` or `selectRadio`
    /// is called; it never auto-connects. Each element is the full current
    /// list, sorted for display.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]>
    /// Attach to a specific radio surfaced by `discoverRadios()`. Ends
    /// discovery and drives the normal connect/attach path.
    func selectRadio(_ id: UUID) async throws
    /// Cancel an in-progress discovery scan without connecting.
    func stopDiscovery() async
    func claimForCurrentIdentity() async throws
    /// Erase ALL mutable state on the radio (saved provisioning, device
    /// identity, BLE bonds, pairing PIN) and reboot it to a blank factory
    /// state. Requires a live connection; the radio drops the link on reset.
    /// The app also abandons its binding to the radio.
    func factoryReset() async throws
    /// Start or stop the radio's locate alert (`PROP_ALERT`) so a
    /// misplaced radio announces itself. What the radio does is up to its
    /// hardware — a buzzer, an indicator LED, or both — and the alert
    /// overrides a silenced buzzer.
    ///
    /// It deliberately keeps running when the phone walks out of range;
    /// the radio ends it on a button press or its own deadline, reported
    /// back through `RadioSnapshot.alert`.
    func setAlert(_ state: RadioAlertState) async throws
    /// Set the radio's wall clock (`PROP_TIME`), or clear it back to
    /// unknown with `nil`.
    ///
    /// Live state, never saved: an epoch written to flash comes back
    /// arbitrarily wrong, since nothing bounds how long a radio spends
    /// powered off. The time *zone* is saved configuration and travels
    /// with a device-configuration write instead.
    func setTime(epochSeconds: UInt32?) async throws
    func refresh() async throws -> RadioSnapshot
    /// Sample where the radio is, and how well it knows.
    ///
    /// The radio announces a fix indicator and nothing else about a
    /// position: a receiver reports about a fix a second, and at the
    /// precision it keeps, ordinary noise from a receiver standing still
    /// moves the reading. Announcing that would keep the radio
    /// transmitting, and the phone waking, for a screen that may not even
    /// be open — so a position is asked for, by whoever is showing one,
    /// no more often than they can use the answer.
    ///
    /// Throws on a radio without `CAP_GNSS`, which has nothing to sample.
    func refreshPositioning() async throws -> RadioSnapshot
    func configure(_ settings: RadioSettings) async throws
    /// Apply and persist the radio's time zone and positioning policy.
    ///
    /// Separate from `configure` because it touches the radio's own
    /// domain rather than its PHY, and separate from the commissioning
    /// path because changing where a tethered radio's receiver stands has
    /// no business restating that radio's role or forwarding policy.
    /// Each argument must be present exactly when the radio advertises
    /// the matching capability.
    func configurePositioning(
        gnss: UlcpGnssSettingsRecord?,
        timeZoneOffsetMinutes: Int16?
    ) async throws
    /// Apply and persist what the radio announces on its own schedule.
    ///
    /// Separate from `configurePositioning` for the same reason that one
    /// is separate from `configure`: it is its own decision, and a phone
    /// changing how often its radio speaks has no business restating
    /// anything else. Must be present exactly when the radio advertises
    /// `CAP_ADVERT`.
    func configureAdvertising(_ advert: UlcpAdvertSettingsRecord?) async throws
    /// Store a peer public key on the radio's device identity
    /// (`PROP_DEV_PEERS`), persisting it with a chained save. Idempotent:
    /// a key the radio already holds resolves as success.
    func addDevicePeer(_ publicKey: Data) async throws
    /// Remove a peer public key from the radio's device identity.
    /// Idempotent: a key the radio does not hold resolves as success.
    func removeDevicePeer(_ publicKey: Data) async throws
    /// Store a channel key on the radio's device identity
    /// (`PROP_DEV_CHANNEL_KEYS`), persisting it with a chained save. This is
    /// the device's own membership, separate from the phone's. Idempotent.
    func addDeviceChannel(_ channelKey: Data) async throws
    /// Remove a channel key from the radio's device identity. Idempotent.
    func removeDeviceChannel(_ channelKey: Data) async throws
    /// Register channel keys with the phone's own MAC so their traffic is
    /// accepted. Called with the full joined set at session start and
    /// incrementally on join.
    func registerChannels(_ channelKeys: [Data]) async throws
    /// Drop channel keys from the phone's MAC.
    func removeChannels(_ channelKeys: [Data]) async throws
    /// Make the radio's host channel-key table match the phone's joined
    /// channels, so it can filter and queue that traffic while the phone is
    /// away. Bookkeeping between the app and its own radio: callers reconcile
    /// on attach and after every membership change, and never surface it.
    func reconcileHostChannels(_ channelKeys: [Data]) async throws
    func ping(peerAddress: String) async throws -> RadioPingResult
    /// Solicit a peer's current node identity by sending a targeted MAC
    /// Identity Request. Resolves once the request is handed to the radio;
    /// the peer's response arrives asynchronously on `advertisementEvents()`.
    func requestIdentity(peerAddress: String) async throws
    /// Ask every matching node in direct radio range to identify itself,
    /// with one zero-hop broadcast Identity Request (repeaters never carry
    /// it). `roleFilter` is a wire role byte to narrow who answers; nil asks
    /// everyone. Replies arrive on `advertisementEvents()`.
    func requestNearbyIdentities(roleFilter: UInt8?) async throws
    /// Ask one channel member — known only by the hint their group messages
    /// claim — to identify themselves. The request goes out over that
    /// channel, since a hint is not an address anything can be unicast to.
    /// The reply arrives on `advertisementEvents()`.
    func requestIdentityByHint(conversationAddress: String, hint: Data) async throws
    /// Set the name carried on this phone's own group messages. Direct
    /// messages never carry it — the recipient authenticated us by key.
    func setChatDisplayName(_ name: String) async throws
    /// The route the phone's MAC will use for the next frame to this peer.
    /// Read-only: inspecting a peer never registers it.
    func peerRoute(peerAddress: String) async throws -> RadioPeerRoute
    /// Discard this peer's learned route, returning whether one was held.
    /// Keys and counters are untouched.
    func clearPeerRoute(peerAddress: String) async throws -> Bool
    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws
    func registerChatPeers(_ peerAddresses: [String]) async throws
    /// Drop these peers from the phone MAC's peer registry (idempotent;
    /// unknown peers are ignored). Best-effort: the store is the authority
    /// and `prepareChat` rebuilds the registry on the next attach.
    func removeChatPeers(_ peerAddresses: [String]) async throws
    func composeText(
        conversationAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord
    func composeEdit(
        conversationAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord
    func composeDelete(
        conversationAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef
    ) async throws -> MobileChatComposeBatchRecord
    /// React to a message, or withdraw a reaction with an empty body. The
    /// target may be either party's message, usually one stored before this
    /// launch, so it is named by wire coordinates rather than a live handle.
    func composeReaction(
        conversationAddress: String,
        clientToken: UInt32,
        target: MobileChatRegardingRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord
    func commitChatBatch(_ batchID: UInt64) async throws
    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws
    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws
    func acknowledgeChatBatch(_ batchID: UInt64) async throws
    func disconnect() async
    /// Unbind from the remembered radio entirely: revoke any standing connect
    /// and clear the persisted `connectedUUID`. The app stops offering
    /// Reconnect and will not auto-connect on launch until a radio is chosen
    /// again via `selectRadio`.
    func forget() async
}

/// A node-identity advertisement received over the mesh. The payload is the
/// raw bundle; consumers verify its signature before trusting any claim.
struct RadioAdvertisementEvent: Equatable, Sendable {
    let peerAddress: String
    let payload: Data
    /// Whether the MAC authenticated the sender of the frame that carried
    /// this bundle.
    ///
    /// An Identity Request reply arrives as a unicast authenticated by its
    /// MIC, so it carries no detached signature; a broadcast advertisement
    /// has no MIC and must carry one. See `isTrustworthy(given:)`.
    let sourceAuthenticated: Bool

    /// Whether these claims may be attributed to the peer.
    ///
    /// A bundle is trustworthy when *something* authenticated it: either its
    /// embedded signature verifies against the claimed key, or the MAC
    /// authenticated the frame that delivered it. A broadcast advertisement
    /// has no MIC, so it must be signed — anything else could be spoofed by
    /// any nearby transmitter. An Identity Request reply is a unicast
    /// authenticated by its MIC and deliberately carries no signature, so it
    /// is trusted without one.
    ///
    /// A signature that is present and fails to verify is never trusted,
    /// however the bundle arrived.
    func isTrustworthy(given signature: MeshIdentitySignatureState) -> Bool {
        switch signature {
        case .valid: true
        case .unsigned: sourceAuthenticated
        case .invalid: false
        }
    }
}

/// Evidence that a node was on the air. Carries no claims — only who sent a
/// frame the mesh accepted, and how confidently that can be said.
struct RadioPeerHeardEvent: Equatable, Sendable {
    /// Canonical Base58 address, when the frame named a full public key.
    let peerAddress: String?
    /// The 3-byte source hint, when the frame carried one.
    let nodeHint: Data?
    /// Whether the MAC authenticated the sender. A beacon is an
    /// unauthenticated broadcast, so this is normally false.
    let sourceAuthenticated: Bool

    /// Which saved peer this was, if it can be said at all.
    ///
    /// A full key is decisive. A hint is three bytes of a 32-byte key and is
    /// ambiguous by design, so it resolves a peer only when exactly one saved
    /// peer could have sent it: a hint two peers share names neither.
    func resolve(among peers: [PeerSummary]) -> PeerSummary? {
        if let peerAddress {
            return peers.first { $0.identity.canonicalAddress == peerAddress }
        }
        guard let nodeHint else { return nil }
        let candidates = peers.filter { $0.identity.hint.bytes == nodeHint }
        return candidates.count == 1 ? candidates[0] : nil
    }
}

struct RadioChatUpdate: Sendable {
    let batchID: UInt64
    let mutations: [MobileChatMutationRecord]
    let deliveries: [MobileChatDeliveryRecord]
    let archiveLookups: [MobileChatArchiveLookupRecord]
    /// Channel members whose claimed hint has resolved to a real address.
    let senderResolutions: [MobileChatSenderResolutionRecord]
    let diagnostics: [String]
}

struct RadioPingReply: Equatable, Sendable {
    let roundTripMilliseconds: UInt64
    let hopCount: UInt8?
    let routeHints: [Data]
    let rssiDBm: Int16?
    let signalToNoiseCentibels: Int16?
    let linkQuality: UInt8?
}

enum RadioPingResult: Equatable, Sendable {
    case reply(RadioPingReply)
    case timedOut
}

/// The route the phone's MAC currently holds for one peer, as raw wire values.
struct RadioPeerRoute: Equatable, Sendable {
    let kind: MobileMeshRouteKind
    /// Routers named by a source route, in send order.
    let hints: [Data]
    let floodHops: UInt8?
    /// Two-octet region codes learned with a flood route.
    let floodRegions: [Data]

    static let unknown = RadioPeerRoute(kind: .unknown, hints: [], floodHops: nil, floodRegions: [])

    init(kind: MobileMeshRouteKind, hints: [Data], floodHops: UInt8?, floodRegions: [Data]) {
        self.kind = kind
        self.hints = hints
        self.floodHops = floodHops
        self.floodRegions = floodRegions
    }

    init(_ record: MobileMeshRouteRecord) {
        self.init(
            kind: record.kind,
            hints: record.hints,
            floodHops: record.floodHops,
            floodRegions: record.floodRegions
        )
    }
}

struct RadioReceivedFrame: Equatable, Sendable {
    let data: Data
    let rssiDBm: Int?
    let linkQuality: UInt8?
    let signalToNoiseCentibels: Int?
    let wasBuffered: Bool
    let wasAcknowledgedByRadio: Bool
    let ageSeconds: UInt32
}

enum RadioConnectionError: Error, Equatable, Sendable {
    case bluetoothUnavailable
    case radioNotFound
    case incompatibleProtocol
    /// The device refused an encrypted characteristic because it and this
    /// phone have no usable pairing. Distinct from `incompatibleProtocol`:
    /// the device is fine, the pairing is missing.
    case pairingRequired
    case identityUnavailable
    case takeoverNotAllowed
    case operationInProgress
    case operationRejected(String)
    /// The device stopped answering partway through an exchange the link never
    /// reported as broken. Distinct from `operationRejected`: a refusal is the
    /// device saying no, and this is the device saying nothing — so whether it
    /// acted on the request is unknown.
    case operationTimedOut
}

/// Failures of device-identity peer mutations, shaped for the UI's
/// disabled-state and inline-error copy.
enum DevicePeerError: Error, Equatable, Sendable {
    /// No attached radio configured for this phone.
    case radioUnavailable
    /// The radio's peer list is full; the device's `NOMEM` is authoritative.
    case deviceFull
    /// The radio does not advertise a device identity domain.
    case unsupported
    /// Any other rejection, carrying the radio's status name.
    case failed(String)
}
