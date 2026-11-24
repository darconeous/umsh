import Foundation
import UMSHMobileCore

extension AppRuntime {
    /// The channel operations the Channels tab is built from, assembled here
    /// for the same reason as `peerActions`.
    ///
    /// Opening the conversation a channel leads to is navigation, which is
    /// the view's business rather than the pipeline's, so the caller passes
    /// what to do with the conversation this resolves.
    func channelActions(
        enterConversation: @escaping (ChannelConversationSummary) -> Void
    ) -> ChannelActions {
        ChannelActions(
            preview: previewChannel,
            join: joinChannel,
            rejoin: rejoinChannel,
            leave: leaveChannel,
            createPrivate: createPrivateChannel,
            setAlias: setChannelAlias,
            setRouting: setChannelRouting,
            setNotifications: setChannelNotifications,
            invitation: channelInvitation,
            enterConversation: { channel in
                enterConversation(try await self.startChannelConversation(channel))
            },
            parseRegion: { text in try? await self.meshEngine.regionCode(from: text) },
            describeRegion: { code in try? await self.meshEngine.regionDescription(code) }
        )
    }

    // MARK: - Channels

    /// Resolve typed input—a public channel name or a pasted `umsh:gs:` /
    /// `umsh:gk:` URI—into a preview, with whatever local context the user
    /// needs to see before committing.
    private func previewChannel(_ input: String) async -> Result<ChannelPreview, MeshEngineError> {
        do {
            return .success(ChannelPreview(try await read { try $0.previewChannel(input: input) }, input: input))
        } catch MobileAppError.InvalidInput(let error) {
            return .failure(RustMeshEngine.inputError(error, invalidURI: .invalidChannelURI))
        } catch {
            return .failure(.coreFailure)
        }
    }

    /// Join by the text a preview was read from, which the core reads again:
    /// a key the phone already holds keeps its routing and takes the alias,
    /// one it does not is stored and registered. A `nil` alias keeps a held
    /// channel's alias unless `clearAlias`; a clear that fails is logged and
    /// the join still stands. With `openConversation` the channel's
    /// conversation opens too, and its address is returned.
    private func joinChannel(
        input: String,
        alias: String?,
        clearAlias: Bool,
        openConversation: Bool
    ) async throws -> String? {
        let logger = Self.logger
        return try await run { core in
            let joined = try await core.joinChannel(input: input, alias: alias, openConversation: openConversation)
            if clearAlias, alias == nil {
                do {
                    try await core.setChannelAlias(id: joined.channelId, alias: nil)
                } catch {
                    logger.warning("channel alias not cleared: \(String(describing: error), privacy: .public)")
                }
            }
            return joined
        }.conversationAddress
    }

    /// Create a private channel under a key the core makes and keeps.
    private func createPrivateChannel(name: String) async throws {
        _ = try await run { try await $0.createPrivateChannel(name: name) }
    }

    /// Leave on the phone identity. The conversation and its messages go,
    /// and every channel but a built-in loses its row and key.
    private func leaveChannel(_ channel: ChannelSummary) async throws {
        let id = channel.id.uuidString
        try await run { try await $0.leaveChannel(id: id) }
    }

    /// Join a channel the phone left but still holds.
    private func rejoinChannel(_ channel: ChannelSummary) async throws {
        let id = channel.id.uuidString
        try await run { try await $0.rejoinChannel(id: id) }
    }

    private func setChannelAlias(_ channel: ChannelSummary, _ alias: String?) async throws {
        let id = channel.id.uuidString
        try await run { try await $0.setChannelAlias(id: id, alias: alias) }
    }

    /// A channel's region and flood-hop ceiling; `nil` for either is the
    /// default. A changed ceiling applies at once.
    private func setChannelRouting(
        _ channel: ChannelSummary,
        _ regionCode: Data?,
        _ maxFloodHops: Int?
    ) async throws {
        let id = channel.id.uuidString
        // The stored code is the region's two bytes, big-endian.
        let regions = try regionCode.map { code -> [UInt16] in
            guard code.count == 2 else { throw MobileAppError.InvalidRequest }
            return [code.reduce(UInt16(0)) { $0 << 8 | UInt16($1) }]
        } ?? []
        let hops = try maxFloodHops.map { hops in
            guard let hops = UInt8(exactly: hops) else { throw MobileAppError.InvalidRequest }
            return hops
        }
        try await run { try await $0.setChannelRouting(id: id, regions: regions, maxFloodHops: hops) }
    }

    /// Toggle a channel's banners, from its page or from inside its
    /// conversation, where the question actually comes up. The same switch
    /// decides, through the core, whether a companion radio holding this
    /// channel's traffic makes a sound about it.
    func setChannelNotifications(_ channel: ChannelSummary, _ enabled: Bool) async throws {
        let id = channel.id.uuidString
        try await run { try await $0.setChannelNotifications(id: id, enabled: enabled) }
    }

    /// Toggle a direct conversation's banners, from the same sheet the
    /// channel switch lives in—and, through the mute tables, whether a
    /// companion radio chirps when it takes one of these messages in for a
    /// phone that is away.
    func setConversationNotifications(
        _ conversation: DirectConversationSummary,
        _ enabled: Bool
    ) async throws {
        try await run {
            try await $0.setConversationNotifications(address: conversation.conversationAddress, enabled: enabled)
        }
    }

    /// The URI that invites someone else to this channel: a named channel
    /// shares only its name, a private one its key. The alias stays here.
    private func channelInvitation(_ channel: ChannelSummary) async throws -> String {
        guard let core else { throw MobileAppError.NotRunning }
        return try await core.channelInvitation(id: channel.id.uuidString)
    }
}
