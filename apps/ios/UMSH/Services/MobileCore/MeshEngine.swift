import Foundation

struct MeshNodeHint: Equatable, Sendable {
    let bytes: Data
    let text: String
}

struct MeshPublicIdentity: Equatable, Sendable {
    let canonicalAddress: String
    let hint: MeshNodeHint
}

enum MeshEngineError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidNodeHint
    case coreFailure
}

protocol MeshEngine: Actor {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint
    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity
    func derivePublicIdentity(secretKey: Data) throws -> MeshPublicIdentity
}
