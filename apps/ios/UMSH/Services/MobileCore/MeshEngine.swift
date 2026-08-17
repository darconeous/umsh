import Foundation

struct MeshNodeHint: Hashable, Sendable {
    let bytes: Data
    let text: String
}

/// Two-byte router hint carried in a learned route, rendered by the Rust core
/// with the protocol's canonical ambiguity rules.
struct MeshRouterHint: Hashable, Sendable {
    let bytes: Data
    let text: String

    /// Whether this hint could have come from `identity`. A router hint is the
    /// first two bytes of the node's key, so a match narrows the field but
    /// never proves which node forwarded the frame.
    func matches(_ identity: MeshPublicIdentity) -> Bool {
        identity.hint.bytes.count >= bytes.count
            && identity.hint.bytes.prefix(bytes.count).elementsEqual(bytes)
    }
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

/// The advertised capability bits, in wire order.
///
/// The labels a node advertises alongside these are what the detail view
/// prints; these are what filtering asks questions of, so a filter never has
/// to match on rendered English.
struct MeshNodeCapabilities: OptionSet, Hashable, Sendable {
    let rawValue: UInt8

    static let repeater = MeshNodeCapabilities(rawValue: 0x01)
    static let mobile = MeshNodeCapabilities(rawValue: 0x02)
    static let textMessages = MeshNodeCapabilities(rawValue: 0x04)
    static let telemetry = MeshNodeCapabilities(rawValue: 0x08)
    static let chatRoom = MeshNodeCapabilities(rawValue: 0x10)
    static let coap = MeshNodeCapabilities(rawValue: 0x20)
}

struct MeshNodeIdentity: Hashable, Sendable {
    let roleCode: UInt8
    let roleLabel: String
    let capabilities: [String]
    /// The same capabilities the labels name, as bits. A node may set bits
    /// this build has no label for; they survive here and match nothing.
    let capabilityBits: MeshNodeCapabilities
    let name: String?
    let latitude: Double?
    let longitude: Double?
    /// Grid-code precision in bytes (1-7); larger is finer.
    let locationPrecision: UInt8?
    let altitudeMeters: Int32?
    let timestamp: UInt32?
    let signature: MeshIdentitySignatureState

    /// Canonical label the Rust core renders for the repeater capability bit.
    static let repeaterCapabilityLabel = "Repeater"
}

struct MeshNodeURIPreview: Equatable, Sendable {
    let publicIdentity: MeshPublicIdentity
    let hasIdentityData: Bool
    let identity: MeshNodeIdentity?
    /// Raw bundle bytes for persistence; absent when unparseable or when the
    /// signature failed verification.
    let identityPayload: Data?
}

/// How a channel's key was established.
enum MeshChannelKind: Hashable, Sendable {
    /// Derived from a name anyone may know; the name is not a secret.
    case namedPublic
    /// Distributed out of band. Possession of the key is membership.
    case privateKey
}

/// A channel the user is about to join, previewed without committing anything.
///
/// `key` is membership material for a private channel: it goes straight to the
/// Keychain vault and never into the application store.
struct MeshChannelPreview: Equatable, Sendable {
    let kind: MeshChannelKind
    /// Canonical lowercase name a named channel's key is derived from. Show it
    /// when it differs from what the user typed — it, not the input, decides
    /// which channel is joined.
    let canonicalName: String?
    let key: Data
    /// Two-octet derived identifier. A hint, not an identity: distinct keys
    /// may collide, and receivers resolve that by trial decryption.
    let channelID: Data
    /// Three presentation octets — the identifier extended by one byte.
    let tint: Data
    /// Local name suggested by an invitation.
    let displayName: String?
    let maxFloodHops: UInt8?
    let regionCode: Data?
}

enum MeshEngineError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidNodeHint
    case invalidRouterHint
    case invalidIdentityData
    case invalidChannelURI
    /// A public channel name fell outside the derivation domain: the
    /// canonicalization is an ASCII case fold, so non-ASCII has no key.
    case channelNameNotASCII
    case channelNameTooLong
    /// Text could not be read as a routing region.
    case invalidRegion
    case coreFailure
}

protocol MeshEngine: Actor {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint
    func renderRouterHint(_ bytes: Data) throws -> MeshRouterHint
    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity
    func inspectNodeURI(_ uri: String) throws -> MeshNodeURIPreview
    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview
    func decodeNodeIdentity(address: String, payload: Data) throws -> MeshNodeIdentity
    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity
    func inspectChannelURI(_ uri: String) throws -> MeshChannelPreview
    func inspectChannelName(_ name: String) throws -> MeshChannelPreview
    func generateChannelKey() -> Data
    func deriveChannelID(key: Data) throws -> Data
    /// The address the mesh facade keys this channel's chat records by.
    /// Derived rather than stored, so it can never disagree with the records
    /// it is matched against.
    func channelConversationAddress(key: Data) throws -> String
    /// Three presentation octets for a key — the identifier extended by one
    /// byte, so a channel's color is stable wherever it is shown.
    func deriveChannelTint(key: Data) throws -> Data
    func formatChannelInvitation(
        key: Data,
        name: String?,
        displayName: String?,
        maxFloodHops: UInt8?,
        regionCode: Data?
    ) throws -> String
    /// Read a routing region written as a three-letter airport code, an agreed
    /// name, or a raw `0xXXXX` code.
    func regionCode(from text: String) throws -> Data
    /// Render a region code the way it is entered and the way it appears in a
    /// capture: its letters when it came from an airport code, `0xXXXX`
    /// otherwise.
    func regionDescription(_ code: Data) throws -> String
}
