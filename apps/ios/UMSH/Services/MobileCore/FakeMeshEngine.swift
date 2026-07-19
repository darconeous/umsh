import Foundation

actor FakeMeshEngine: MeshEngine {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint {
        guard bytes.count == 3 else {
            throw MeshEngineError.invalidNodeHint
        }
        return MeshNodeHint(bytes: bytes, text: "BtC5")
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
            hasIdentityData: false
        )
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
}
