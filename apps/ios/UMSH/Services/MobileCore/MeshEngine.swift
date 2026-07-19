import Foundation

struct MeshNodeHint: Hashable, Sendable {
    let bytes: Data
    let text: String
}

struct MeshPublicIdentity: Hashable, Sendable {
    let canonicalAddress: String
    let hint: MeshNodeHint
}

struct MeshNodeURIPreview: Equatable, Sendable {
    let publicIdentity: MeshPublicIdentity
    let hasIdentityData: Bool
}

enum MeshEngineError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidNodeHint
    case coreFailure
}

protocol MeshEngine: Actor {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint
    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity
    func inspectNodeURI(_ uri: String) throws -> MeshNodeURIPreview
    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity
}
