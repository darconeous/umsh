import Foundation

struct MeshNodeHint: Hashable, Sendable {
    let bytes: Data
    let text: String
}

struct MeshPublicIdentity: Hashable, Sendable {
    let canonicalAddress: String
    let hint: MeshNodeHint
}

extension MeshPublicIdentity {
    /// Canonical shareable node URI. The prefix and fixed-width Base58 body
    /// match the Rust `umsh-uri` `format_node_uri` output; the address here
    /// is already the canonical Rust-rendered form.
    var nodeURI: String { "umsh:n:" + canonicalAddress }
}

enum MeshIdentitySignatureState: Hashable, Sendable {
    /// No signature was attached; the claims are unauthenticated.
    case unsigned
    /// The signature verifies against the node's public key.
    case valid
    /// The signature fails verification; the claims must not be shown as
    /// coming from the key's owner.
    case invalid
}

struct MeshNodeIdentity: Hashable, Sendable {
    let roleCode: UInt8
    let roleLabel: String
    let capabilities: [String]
    let name: String?
    let latitude: Double?
    let longitude: Double?
    /// Grid-code precision in bytes (1-7); larger is finer.
    let locationPrecision: UInt8?
    let altitudeMeters: Int32?
    let timestamp: UInt32?
    let signature: MeshIdentitySignatureState
}

struct MeshNodeURIPreview: Equatable, Sendable {
    let publicIdentity: MeshPublicIdentity
    let hasIdentityData: Bool
    let identity: MeshNodeIdentity?
    /// Raw bundle bytes for persistence; absent when unparseable or when the
    /// signature failed verification.
    let identityPayload: Data?
}

enum MeshEngineError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidNodeHint
    case invalidIdentityData
    case coreFailure
}

protocol MeshEngine: Actor {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint
    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity
    func inspectNodeURI(_ uri: String) throws -> MeshNodeURIPreview
    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview
    func decodeNodeIdentity(address: String, payload: Data) throws -> MeshNodeIdentity
    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity
}
