#if DEBUG
import Foundation
import UMSHMobileCore

/// The air around the staged mesh.
///
/// Real Rust sessions stand behind the staged nodes: a message sent in
/// staging is encrypted, framed, transmitted, decrypted, and acknowledged by
/// the same code that does it over RF, using the same fixed-seed keys the
/// seeded transcripts are signed with. Only the medium is fabricated —
/// frames move through memory instead of the ether, and airtime is free.
///
/// The topology is a star: everything the phone transmits reaches every
/// staged peer, and everything a peer transmits reaches only the phone.
/// Peers never hear each other, which is what keeps a fabricated mesh of
/// non-repeating chat nodes from needing a channel-access model.
actor StagingMeshAir: FakeRadioAir {
    private struct Peer {
        let name: String
        let session: MobileMeshSession
        /// How the phone hears this peer, and how this peer hears the phone.
        /// Fixed per node so a staged conversation reads the same every run.
        let rssiDBm: Int16
        let snrCentibels: Int16
        let linkQuality: UInt8
    }

    private var peers: [Peer]?
    private var buildTask: Task<[Peer], Never>?
    private var phoneAddress: String?
    private var onAir: (@Sendable ([MobileMeshRxRecord]) -> Void)?
    /// The sessions hold their wake listeners weakly; these keep them alive.
    private var wakeListeners: [StagedPeerWakeListener] = []

    func attach(onAir: @escaping @Sendable ([MobileMeshRxRecord]) -> Void) {
        self.onAir = onAir
    }

    func registerPhone(address: String) async {
        phoneAddress = address
        guard let peers else { return }
        for peer in peers {
            try? await peer.session.registerPeers(peerAddresses: [address])
        }
    }

    func transmit(_ data: Data) async {
        let peers = await ensurePeers()
        for (index, peer) in peers.enumerated() {
            try? peer.session.receive(
                frame: MobileMeshRxRecord(
                    data: data,
                    rssiDbm: peer.rssiDBm,
                    lqi: peer.linkQuality,
                    snrCb: peer.snrCentibels
                )
            )
            pumpPeer(index)
        }
    }

    /// Drain one staged peer: complete its transmissions, feed them to the
    /// phone, and consume its chat inbox — staged peers have no app above
    /// them, so acknowledging a batch is what reading it means here.
    private func pumpPeer(_ index: Int) {
        guard let peers, peers.indices.contains(index) else { return }
        let peer = peers[index]
        let update = peer.session.pollUpdate()
        for frame in update.outboundFrames {
            try? peer.session.completeOutboundFrame(frameId: frame.id, transmitted: true)
        }
        if let batchID = update.chatBatchId {
            try? peer.session.acknowledgeChatBatch(batchId: batchID)
        }
        guard !update.outboundFrames.isEmpty, let onAir else { return }
        onAir(
            update.outboundFrames.map {
                MobileMeshRxRecord(
                    data: $0.data,
                    rssiDbm: peer.rssiDBm,
                    lqi: peer.linkQuality,
                    snrCb: peer.snrCentibels
                )
            }
        )
    }

    fileprivate func peerAnnouncedUpdate(_ index: Int) {
        pumpPeer(index)
    }

    private func ensurePeers() async -> [Peer] {
        if let peers { return peers }
        if let buildTask { return await buildTask.value }
        let task = Task { await buildPeers() }
        buildTask = task
        let built = await task.value
        peers = built
        return built
    }

    /// Stand up a session for every staged node that would carry chat.
    /// Repeaters stay out: a phone-role session does not forward, and a
    /// repeater that cannot repeat would just be a mute participant.
    private func buildPeers() async -> [Peer] {
        let channelKeys = Self.channelKeys()
        var built: [Peer] = []
        for node in StagingScenario.nodes where node.role != .repeater {
            do {
                let identity = try MobileIdentity.unlock(secretKey: node.secretKey)
                let store = try MobileCounterStore(
                    rootDirectory: Self.counterDirectory(for: node).path
                )
                let session = try await MobileMeshSession(
                    identity: identity,
                    counterStore: store
                )
                try await session.setChatDisplayName(name: node.name)
                if !channelKeys.isEmpty {
                    try await session.registerChannels(keys: channelKeys)
                }
                if let phoneAddress {
                    try await session.registerPeers(peerAddresses: [phoneAddress])
                }
                let listener = StagedPeerWakeListener(air: self, peerIndex: built.count)
                wakeListeners.append(listener)
                session.setWakeListener(listener: listener)
                built.append(
                    Peer(
                        name: node.name,
                        session: session,
                        rssiDBm: -52 - 6 * Int16(built.count),
                        snrCentibels: 74 - 9 * Int16(built.count),
                        linkQuality: 214 - 13 * UInt8(built.count)
                    )
                )
            } catch {
                // A peer that cannot stand up is a node the staged mesh
                // simply never hears from; everything else keeps working.
            }
        }
        return built
    }

    /// Both staged channels' keys, derived exactly as joining them would
    /// derive them, so every peer can read and speak on both group chats.
    private static func channelKeys() -> [Data] {
        var keys = [StagingScenario.privateChannelKey]
        if let named = try? inspectChannelName(name: StagingScenario.channelName) {
            keys.append(named.key)
        }
        return keys
    }

    /// Frame counters must survive relaunches for replay protection to hold
    /// between the staged peers and the phone, so each peer gets a durable
    /// reservation directory of its own, apart from the phone's.
    private static func counterDirectory(for node: StagingNode) -> URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("UMSH", isDirectory: true)
            .appendingPathComponent("StagingAirCounters", isDirectory: true)
            .appendingPathComponent(String(format: "%02x", node.seed), isDirectory: true)
    }
}

/// Bridges a staged peer session's pending-update announcement back into the
/// air. Runs on the Rust worker thread; holds the air weakly so a retired
/// mesh cannot keep it alive.
private final class StagedPeerWakeListener: MobileMeshWakeListener, @unchecked Sendable {
    private weak var air: StagingMeshAir?
    private let peerIndex: Int

    init(air: StagingMeshAir, peerIndex: Int) {
        self.air = air
        self.peerIndex = peerIndex
    }

    func onUpdatePending() {
        guard let air else { return }
        Task { await air.peerAnnouncedUpdate(peerIndex) }
    }
}
#endif
