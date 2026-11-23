import Foundation
import OSLog
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Action bundles

    /// The one set of peer operations every peer sheet gets, wherever it is
    /// opened from. Built here because this is the only place that holds the
    /// store, the radio, and the mesh engine together.
    var peerActions: PeerActions {
        PeerActions(
            knownPeers: peers,
            startConversation: startConversation,
            ping: pingPeer,
            fetchIdentity: fetchIdentity,
            updateAlias: updateAlias,
            loadRoute: peerRoute,
            resetRoute: clearPeerRoute,
            identifyRepeater: identifyRepeater(_:precededBy:),
            cachedPeerRepeaters: cachedPeerRepeaters,
            loadPeerRepeaters: loadPeerRepeaters(_:cursor:),
            loadPeerRepeatersAlong: { peer, cursor, route in
                await self.loadPeerRepeaters(peer, cursor: cursor, route: route)
            },
            radioIdentityPeer: radioSnapshot.deviceIdentity.flatMap { identity in
                peers.first { $0.identity.canonicalAddress == identity.canonicalAddress }
            },
            setManualPath: setManualPath,
            clearManualPath: clearManualPath,
            adoptLearnedPath: adoptLearnedPath,
            keepManualPath: keepManualPath,
            learnedPathOffer: learnedPathOffer,
            pingAlongPath: { peer, path in await self.pingPeer(peer, along: path) },
            parseRepeaterHint: { text, format in
                await self.meshEngine.parseRepeaterHintInput(text, format: format)
            },
            renderRepeaterHint: { bytes in try? await self.meshEngine.renderRepeaterHint(bytes) },
            setFavorite: setPeerFavorite,
            setNotifyWhenHeard: setPeerNotifyWhenHeard,
            setConversationNotifications: setConversationNotifications,
            promoteToSaved: promotePeerToSaved,
            demoteToTransient: demotePeerToTransient,
            deletePeer: deletePeer,
            deletePeerAndConversation: deletePeerAndConversation,
            manageDevice: { peer in try await self.manageDevice(peer) },
            manageCompanion: { name in try await self.manageRadio(name: name) },
            manageAdministered: { driver, phoneNodeKey, peer in
                try await self.manageAdministered(driver: driver, phoneNodeKey: phoneNodeKey, peer: peer)
            }
        )
    }

    func inspectPeerIdentity(_ input: String) async -> Result<MeshNodeURIPreview, MeshEngineError> {
        do {
            return .success(try await meshEngine.inspectPeerIdentity(input))
        } catch let error as MeshEngineError {
            return .failure(error)
        } catch {
            return .failure(.coreFailure)
        }
    }

    /// Save the node `preview` was read from, with this phone's name for it,
    /// and open a conversation with it when `startConversation` asks.
    ///
    /// The core reads the preview's text again rather than taking what was
    /// shown, and decides whether the link's identity replaces one already
    /// held. Returns the conversation when one was asked for.
    func savePeer(
        _ preview: MeshNodeURIPreview,
        details: PeerImportDetails,
        startConversation: Bool
    ) async throws -> DirectConversationSummary? {
        let address = try await run {
            try await $0.savePeer(
                input: preview.input,
                alias: details.alias,
                startConversation: startConversation
            )
        }
        guard startConversation else { return nil }
        return try directConversation(at: address)
    }

    /// The stored row for the node a link names, so its peer page has a row
    /// to act on.
    ///
    /// A node this phone has never come across is recorded unsaved, carrying
    /// whatever identity the link did, the same tier a node heard over the
    /// air lands in. Saving it stays the operator's call, made on that page.
    /// A node already on file is returned as it stands: a link's bundle is no
    /// fresher than what was heard. `nil` for this phone's own address,
    /// which is not a peer.
    func peer(forLink preview: MeshNodeURIPreview) async throws -> PeerSummary? {
        guard let address = try await run({ try await $0.recordLinkPeer(input: preview.input) }) else {
            return nil
        }
        guard let peer = peers.first(where: { $0.identity.canonicalAddress == address }) else {
            throw MobileAppError.NotFound
        }
        return peer
    }

    /// Record a device the phone has been configuring as an ordinary peer.
    ///
    /// Deliberately not a chat peer: a repeater is infrastructure the operator
    /// wants to find again, not someone to talk to. Starting a conversation
    /// with it remains an ordinary Peers action. A `nil` role keeps whatever
    /// kind the node is already filed under.
    func saveAdministeredDevice(
        _ identity: MeshPublicIdentity,
        name: String?,
        role: PeerRole?
    ) async throws {
        try await run {
            try await $0.saveAdministeredDevice(
                address: identity.canonicalAddress,
                name: name,
                role: role?.roleCode
            )
        }
    }

    private func updateAlias(_ peer: PeerSummary, _ alias: String?) async throws {
        try await run { try await $0.setAlias(address: peer.identity.canonicalAddress, alias: alias) }
    }

    private func setPeerFavorite(_ peer: PeerSummary, _ favorite: Bool) async throws {
        try await run { try await $0.setFavorite(address: peer.identity.canonicalAddress, favorite: favorite) }
    }

    /// Arm or disarm the one-shot watch on a node.
    ///
    /// Arming asks for a notification, so it is also the moment to make sure
    /// the app can post one: a watch set on a phone that has never been asked
    /// about notifications would come due and produce nothing.
    private func setPeerNotifyWhenHeard(_ peer: PeerSummary, _ armed: Bool) async throws {
        try await run { try await $0.setNotifyWhenHeard(address: peer.identity.canonicalAddress, armed: armed) }
        if armed { notificationService.requestAuthorizationIfNeeded() }
    }

    private func promotePeerToSaved(_ peer: PeerSummary) async throws {
        try await run { try await $0.promotePeer(address: peer.identity.canonicalAddress) }
    }

    /// Take a peer off the local identity while keeping its row, history, and
    /// searchability. The mesh session keeps the peer registered when a
    /// conversation exists—chat continuity is the point of demoting.
    private func demotePeerToTransient(_ peer: PeerSummary) async throws {
        try await run { try await $0.demotePeer(address: peer.identity.canonicalAddress) }
    }

    /// Delete a node with no conversation. The core refuses one that has
    /// gained a conversation since the page offered this.
    private func deletePeer(_ peer: PeerSummary) async throws {
        try await run {
            try await $0.deletePeer(address: peer.identity.canonicalAddress, withConversation: false)
        }
    }

    private func deletePeerAndConversation(_ peer: PeerSummary) async throws {
        try await run {
            try await $0.deletePeer(address: peer.identity.canonicalAddress, withConversation: true)
        }
    }

    /// One broadcast Identity Request for the Discover sheet: matching nodes
    /// reply with their identities, which the core records. Returns once the
    /// request was handed to the radio.
    ///
    /// Without a vantage it is zero-hop, answered by nodes in this phone's own
    /// range. With one it is steered down that route and answered by whatever
    /// is in range of where it lands.
    func solicitNearbyIdentities(
        _ roleFilter: PeerRole?,
        _ vantage: SolicitVantage?
    ) async throws {
        try await ask {
            try await $0.discover(role: roleFilter?.roleCode, nodeHint: nil, route: vantage?.repeaters ?? [])
        }
    }

    /// How long until the core takes another ask from the Discover sheet;
    /// zero when it would take one now, or when there is no core to ask.
    /// One wait covers every such ask this core sends, wherever it was made.
    func discoveryWait() -> Duration {
        guard let core, let milliseconds = try? core.discoveryWaitMs() else { return .zero }
        return .milliseconds(Int64(clamping: milliseconds))
    }

    /// Ask one repeater named by a route who it is.
    ///
    /// A repeater consumes its own hint while forwarding rather than while
    /// receiving, so a request whose route still names it is one it drops.
    /// The ask is steered to the hop *before* it—`precedingRepeaters`, which
    /// is empty for a first hop, since that one is in direct range by
    /// construction—and narrowed to the repeater's own hint, so it is the
    /// only node in that neighborhood that answers.
    private func identifyRepeater(
        _ hint: Data,
        precededBy precedingRepeaters: [Data]
    ) async throws {
        try await ask { try await $0.discover(role: nil, nodeHint: hint, route: precedingRepeaters) }
    }

    /// Drop every transient row nothing depends on, from the Discover
    /// sheet's overflow. Saved peers, conversations, device-identity rows,
    /// and the companion radio are untouched by the store's guards.
    func clearDiscoveredNodes() async throws {
        try await run { try await $0.clearDiscovered() }
    }

    /// Open the conversation with `peer`, creating it the first time.
    private func startConversation(_ peer: PeerSummary) async throws -> DirectConversationSummary {
        let address = try await run { try await $0.startConversation(address: peer.identity.canonicalAddress) }
        return try directConversation(at: address)
    }

    /// The direct conversation a command just returned the address of.
    private func directConversation(at address: String) throws -> DirectConversationSummary {
        guard let conversation = conversations.first(where: { $0.conversationAddress == address }) else {
            throw MobileAppError.NotFound
        }
        return conversation
    }

    private func pingPeer(_ peer: PeerSummary) async -> PeerPingResult {
        await pingPeer(peer, along: nil)
    }

    /// Ping `peer`, down `path` when one is given: a test of a path that
    /// installs nothing. A reply counts as hearing the peer, which the core
    /// records.
    private func pingPeer(_ peer: PeerSummary, along path: ManualPath?) async -> PeerPingResult {
        let unsent = String(localized: "The radio could not send the ping.", comment: "Why a ping could not be sent.")
        guard let core else { return .unavailable(reason: unsent) }
        do {
            switch try await core.ping(address: peer.identity.canonicalAddress, path: path?.explicitPath) {
            case let .reply(reply):
                return .reply(PeerPingReply(reply))
            case .timedOut:
                return .timedOut
            case .canceled:
                return .canceled
            }
        } catch MobileAppError.NoAnswer {
            // The core's backstop on a ping nothing ever ended.
            return .timedOut
        } catch MobileAppError.SendFailed {
            return .unavailable(reason: unsent)
        } catch let error as MobileAppError {
            return .unavailable(reason: error.message)
        } catch {
            return .unavailable(reason: unsent)
        }
    }

    /// Report the route this phone will use for the next frame to `peer`.
    /// A core that cannot answer reads as nothing learned, which is what an
    /// unreachable MAC effectively means for the next send.
    private func peerRoute(_ peer: PeerSummary) async -> PeerRoute {
        guard let route = try? await core?.peerRoute(address: peer.identity.canonicalAddress) else {
            return .unavailable
        }
        return PeerRoute(route)
    }

    // MARK: - Manual paths

    /// Hold `path` for `peer`, and keep it so the next session holds it
    /// again.
    ///
    /// Notes where the phone is, when it already may know, as the point a
    /// later move is measured from. Saving a path never asks for location.
    private func setManualPath(
        _ peer: PeerSummary,
        path: ManualPath,
        hold: ManualPathHold
    ) async -> Bool {
        guard let core else { return false }
        let position = await locationService.readOnceIfAuthorized().map(MobilePositionRecord.init)
        do {
            let held = try await core.setManualPath(
                address: peer.identity.canonicalAddress,
                path: path.explicitPath,
                holdMs: UInt64(hold.duration * 1000),
                position: position
            )
            await reloadApplicationState()
            return held
        } catch {
            Self.logger.error("A manual path was not kept: \(String(describing: error), privacy: .public)")
            return false
        }
    }

    /// Drop a held path and what the phone kept about it.
    private func clearManualPath(_ peer: PeerSummary) async -> Bool {
        let cleared = (try? await core?.clearManualPath(address: peer.identity.canonicalAddress)) ?? false
        await reloadApplicationState()
        return cleared
    }

    /// Switch a held path for the one learned while it was held.
    private func adoptLearnedPath(_ peer: PeerSummary) async -> Bool {
        let adopted = (try? await core?.adoptLearnedPath(address: peer.identity.canonicalAddress)) ?? false
        await reloadApplicationState()
        return adopted
    }

    private func keepManualPath(_ peer: PeerSummary) async {
        try? await core?.keepManualPath(address: peer.identity.canonicalAddress)
        await reloadApplicationState()
    }

    /// The held route, when the path learned while holding it is due to be
    /// offered. The phone's position is read only when the core asks for
    /// it, and only where location access was already granted.
    private func learnedPathOffer(_ peer: PeerSummary) async -> PeerRoute? {
        guard let core else { return nil }
        let address = peer.identity.canonicalAddress
        do {
            var offer = try await core.learnedPathOffer(address: address, position: nil)
            if case .needsPosition = offer {
                let reading: MobileAppPositionReading
                if let fix = await locationService.readOnceIfAuthorized() {
                    reading = .found(position: MobilePositionRecord(fix))
                } else {
                    reading = .unavailable
                }
                offer = try await core.learnedPathOffer(address: address, position: reading)
            }
            guard case let .offer(route) = offer else { return nil }
            return PeerRoute(route)
        } catch {
            return nil
        }
    }

    /// Discard a peer's learned route. Returns whether one was held, so the
    /// UI can distinguish a reset from a no-op.
    private func clearPeerRoute(_ peer: PeerSummary) async -> Bool {
        (try? await core?.clearRoute(address: peer.identity.canonicalAddress)) ?? false
    }

    // MARK: - Neighboring repeaters

    /// What a repeater last said about its neighbors, from this phone's own
    /// store. Nothing goes on the air.
    private func cachedPeerRepeaters(_ peer: PeerSummary) async -> PeerRepeaterListing? {
        let address = peer.identity.canonicalAddress
        guard let record = try? await read({ try $0.peerRepeaters(publicAddress: address) }) else {
            return nil
        }
        return PeerRepeaterListing(record)
    }

    /// Ask a repeater for one page of its neighbor listing, folded into what
    /// this phone holds about that repeater. The cursor is the caller's:
    /// none asks for the top of the listing and replaces what was held, one
    /// asks for the page after it and adds to it. Never follows a cursor on
    /// its own.
    private func loadPeerRepeaters(
        _ peer: PeerSummary,
        cursor: Data?
    ) async -> PeerRepeatersPageResult {
        await loadPeerRepeaters(peer, cursor: cursor, route: [])
    }

    /// The same, asked down `route` (send order) when it names any repeaters.
    private func loadPeerRepeaters(
        _ peer: PeerSummary,
        cursor: Data?,
        route: [MeshRepeaterHint]
    ) async -> PeerRepeatersPageResult {
        guard let core else { return .failed }
        do {
            return .page(PeerRepeaterListing(try await core.requestPeerRepeaters(
                address: peer.identity.canonicalAddress,
                cursor: cursor,
                route: route.map(\.bytes)
            )))
        } catch let error as MobileAppError {
            switch error {
            case .NoAnswer:
                return .noAnswer
            case .NoRadio:
                return .unavailable(reason: String(
                    localized: "Connect a configured companion radio to ask this repeater.",
                    comment: "Why a repeater's neighbors could not be asked for: no radio is attached."
                ))
            case .NotThisPhone:
                return .unavailable(reason: String(
                    localized: "Set up this radio for the current phone identity before asking repeaters.",
                    comment: "Why a repeater's neighbors could not be asked for: the radio is not this phone's."
                ))
            case .NoOwner, .NotRunning, .Busy, .Stopped:
                return .unavailable(reason: error.message)
            default:
                return .failed
            }
        } catch {
            return .failed
        }
    }

    /// Solicit a peer's current identity over the mesh. The response is not
    /// awaited here—the core records it when it arrives, which refreshes
    /// the sheet. Returns once the request was sent, for a brief UI
    /// confirmation.
    private func fetchIdentity(_ peer: PeerSummary) async throws {
        try await ask { try await $0.fetchIdentity(address: peer.identity.canonicalAddress) }
    }
}

extension ManualPath {
    /// The path as the mesh session takes it.
    var explicitPath: MobileMeshExplicitPath {
        MobileMeshExplicitPath(hints: hops.map(\.bytes), floodHops: floodHops)
    }
}
