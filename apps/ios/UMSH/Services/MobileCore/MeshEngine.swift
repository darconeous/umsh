import Foundation

struct MeshNodeHint: Hashable, Sendable {
    let bytes: Data
    let text: String
}

/// Two-byte repeater hint carried in a learned route, rendered by the Rust core
/// with the protocol's canonical ambiguity rules.
struct MeshRepeaterHint: Hashable, Sendable {
    let bytes: Data
    let text: String

    /// Whether this hint could have come from `identity`. A repeater hint is the
    /// first two bytes of the node's key, so a match narrows the field but
    /// never proves which node forwarded the frame.
    func matches(_ identity: MeshPublicIdentity) -> Bool {
        identity.hint.bytes.count >= bytes.count
            && identity.hint.bytes.prefix(bytes.count).elementsEqual(bytes)
    }
}

/// How a person wrote a repeater hint by hand.
enum RepeaterHintFormat: Hashable, Sendable, CaseIterable {
    /// The first four or more characters of the node's address.
    case base58Prefix
    /// The hint itself, as four hexadecimal digits.
    case hex
}

/// What typed text says about a repeater hint.
struct RepeaterHintInput: Equatable, Sendable {
    enum Problem: Equatable, Sendable {
        case tooShort
        case tooLong
        case invalidCharacter
        case outOfRange
    }

    /// One hint, or two when a prefix straddles a hint boundary.
    let candidates: [MeshRepeaterHint]
    let problem: Problem?

    static let empty = RepeaterHintInput(candidates: [], problem: .tooShort)
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
/// The core sends bits, never names: what each is called is this app's to
/// say, in the reader's language (`MeshNodeCapabilities.labels`).
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
    /// A node may set bits this build has no name for; they survive here and
    /// match nothing.
    let capabilityBits: MeshNodeCapabilities
    /// Whether the node says it forwards other nodes' traffic, by the rule
    /// the Rust core applies on every platform.
    let forwards: Bool
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
    /// The text this preview was read from. Saving hands it back to the
    /// core, which reads it again rather than trusting what was shown.
    let input: String
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
    /// when it differs from what the user typed—it, not the input, decides
    /// which channel is joined.
    let canonicalName: String?
    let key: Data
    /// Two-octet derived identifier. A hint, not an identity: distinct keys
    /// may collide, and receivers resolve that by trial decryption.
    let channelID: Data
    /// Three presentation octets—the identifier extended by one byte.
    let tint: Data
    /// Local name suggested by an invitation.
    let displayName: String?
    let maxFloodHops: UInt8?
    let regionCode: Data?
}

enum MeshEngineError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidNodeHint
    case invalidRepeaterHint
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
    func renderRepeaterHint(_ bytes: Data) throws -> MeshRepeaterHint
    /// Read a repeater hint typed by a person.
    func parseRepeaterHintInput(_ text: String, format: RepeaterHintFormat) -> RepeaterHintInput
    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity
    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview
    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity
    /// Forget the unlocked identity and everything built on it.
    ///
    /// The counterpart to `unlockIdentity`, and the only way to end up
    /// holding none: erasing a phone's identity has to leave the engine
    /// with nothing rather than with the key it is about to destroy.
    func lockIdentity()
    /// A fresh secret for a new local identity, redrawn while the hint
    /// filter matches its key.
    func generateIdentitySecret() -> Data
    /// Read a routing region written as a short code, an agreed name, or a
    /// raw `0xXXXX` code.
    func regionCode(from text: String) throws -> Data
    /// Render a region code the way it is entered and the way it appears in a
    /// capture: its letters when it came from an all-letter short code,
    /// `0xXXXX` otherwise.
    func regionDescription(_ code: Data) throws -> String
}
