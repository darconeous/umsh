import Foundation

struct PeerSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let identity: MeshPublicIdentity
    let alias: String?
    let advertisedName: String?
    let isContact: Bool
    let systemRole: String?
    let kind: PeerKind

    var displayName: String {
        alias ?? advertisedName ?? (isCompanionRadio ? "Companion radio" : identity.hint.text)
    }

    var isCompanionRadio: Bool { systemRole == "companion_radio" }
}

enum PeerKind: String, CaseIterable, Hashable, Sendable, Identifiable {
    case person
    case room
    case sensor
    case repeater
    case bridge
    case unknown

    var id: Self { self }

    var label: String {
        switch self {
        case .person: "Person"
        case .room: "Room"
        case .sensor: "Sensor"
        case .repeater: "Repeater"
        case .bridge: "Bridge"
        case .unknown: "Unspecified"
        }
    }
}

struct PeerImportDetails: Sendable {
    let alias: String?
    let kind: PeerKind
    let isContact: Bool
}

struct DirectConversationSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let peer: PeerSummary
    var draftText: String
}

enum PeerPingResult: Equatable, Sendable {
    case reply(roundTripMilliseconds: UInt64)
    case timedOut
    case unavailable(reason: String)
}
