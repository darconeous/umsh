import Foundation

actor FakeMeshEngine: MeshEngine {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint {
        guard bytes.count == 3 else {
            throw MeshEngineError.invalidNodeHint
        }
        return MeshNodeHint(bytes: bytes, text: "BtC5")
    }

    func renderRouterHint(_ bytes: Data) throws -> MeshRouterHint {
        guard bytes.count == 2 else {
            throw MeshEngineError.invalidRouterHint
        }
        return MeshRouterHint(bytes: bytes, text: "BtC")
    }

    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity {
        guard address.count == 44 else {
            throw MeshEngineError.invalidAddress
        }
        return MeshPublicIdentity(
            canonicalAddress: address,
            hint: MeshNodeHint(bytes: Data(address.utf8.prefix(3)), text: "BtC5")
        )
    }

    func inspectNodeURI(_ uri: String) throws -> MeshNodeURIPreview {
        guard uri.hasPrefix("umsh:n:") else {
            throw MeshEngineError.invalidAddress
        }
        return MeshNodeURIPreview(
            publicIdentity: try inspectPublicIdentity(String(uri.dropFirst("umsh:n:".count))),
            hasIdentityData: false,
            identity: nil,
            identityPayload: nil
        )
    }

    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview {
        if input.hasPrefix("umsh:n:") {
            return try inspectNodeURI(input)
        }
        return MeshNodeURIPreview(
            publicIdentity: try inspectPublicIdentity(input),
            hasIdentityData: false,
            identity: nil,
            identityPayload: nil
        )
    }

    func decodeNodeIdentity(address: String, payload: Data) throws -> MeshNodeIdentity {
        throw MeshEngineError.invalidIdentityData
    }

    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity {
        guard secretKey.count == 32 else {
            throw MeshEngineError.invalidAddress
        }
        return MeshPublicIdentity(
            canonicalAddress: "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
            hint: MeshNodeHint(bytes: Data([0x00, 0x01, 0x02]), text: "111t")
        )
    }

    func lockIdentity() {}

    func inspectChannelURI(_ uri: String) throws -> MeshChannelPreview {
        if let name = uri.strippingPrefix("umsh:cs:") {
            return try inspectChannelName(name)
        }
        guard uri.strippingPrefix("umsh:ck:") != nil else {
            throw MeshEngineError.invalidChannelURI
        }
        let key = generateChannelKey()
        return MeshChannelPreview(
            kind: .privateKey,
            canonicalName: nil,
            key: key,
            channelID: try deriveChannelID(key: key),
            tint: try deriveChannelTint(key: key),
            displayName: nil,
            maxFloodHops: nil,
            regionCode: nil
        )
    }

    func inspectChannelName(_ name: String) throws -> MeshChannelPreview {
        guard name.allSatisfy(\.isASCII) else {
            throw MeshEngineError.channelNameNotASCII
        }
        guard name.utf8.count <= 64 else {
            throw MeshEngineError.channelNameTooLong
        }
        let canonical = name.lowercased()
        // Deterministic in the name, like the real derivation, so previews
        // and joins agree across calls.
        var key = Data(repeating: 0, count: 32)
        for (index, byte) in canonical.utf8.enumerated() {
            key[index % 32] ^= byte
        }
        return MeshChannelPreview(
            kind: .namedPublic,
            canonicalName: canonical,
            key: key,
            channelID: try deriveChannelID(key: key),
            tint: try deriveChannelTint(key: key),
            displayName: nil,
            maxFloodHops: nil,
            regionCode: nil
        )
    }

    func generateChannelKey() -> Data {
        var key = Data(count: 32)
        for index in key.indices {
            key[index] = UInt8.random(in: 0...255)
        }
        return key
    }

    func deriveChannelID(key: Data) throws -> Data {
        guard key.count == 32 else {
            throw MeshEngineError.coreFailure
        }
        return Data([key.reduce(0, ^), key.first ?? 0])
    }

    func channelConversationAddress(key: Data) throws -> String {
        guard key.count == 32 else { throw MeshEngineError.coreFailure }
        return "ch:" + key.prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    func deriveChannelTint(key: Data) throws -> Data {
        try deriveChannelID(key: key) + Data([key.last ?? 0])
    }

    func formatChannelInvitation(
        key: Data,
        name: String?,
        displayName: String?,
        maxFloodHops: UInt8?,
        regionCode: Data?
    ) throws -> String {
        if let name {
            return "umsh:cs:\(name)"
        }
        return "umsh:ck:" + key.map { String(format: "%02x", $0) }.joined()
    }

    func regionCode(from text: String) throws -> Data {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw MeshEngineError.invalidRegion }
        return Data(trimmed.utf8.prefix(2))
    }

    func regionDescription(_ code: Data) throws -> String {
        String(decoding: code, as: UTF8.self)
    }
}

private extension String {
    func strippingPrefix(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}
