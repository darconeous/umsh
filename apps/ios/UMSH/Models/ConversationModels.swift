import Foundation

struct PeerSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let identity: MeshPublicIdentity
    let alias: String?
    let advertisedName: String?
    let isContact: Bool
    let systemRole: String?

    var displayName: String {
        alias ?? advertisedName ?? (isCompanionRadio ? "Companion radio" : identity.hint.text)
    }

    var isCompanionRadio: Bool { systemRole == "companion_radio" }
}

struct DirectConversationSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let peer: PeerSummary
    var draftText: String
}
