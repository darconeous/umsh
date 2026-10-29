import SwiftUI

/// What a peer page offers to do with its node, as tiles under the name.
enum PeerVerb: Hashable, CaseIterable {
    case identify
    case message
    case ping
    case neighbors
    case manage

    var title: LocalizedStringResource {
        switch self {
        case .identify:
            LocalizedStringResource("Identify", comment: "Tile: ask a node to say who it is.")
        case .message:
            LocalizedStringResource("Message", comment: "Tile: open a conversation with the node. A verb.")
        case .ping:
            LocalizedStringResource("Ping", comment: "Tile: check that the node answers. A verb.")
        case .neighbors:
            LocalizedStringResource("Neighbors", comment: "Tile: list the repeaters this node can hear.")
        case .manage:
            LocalizedStringResource("Manage", comment: "Tile: read and change the node's settings. A verb.")
        }
    }

    var systemImage: String {
        switch self {
        case .identify: "person.crop.circle.badge.questionmark"
        case .message: "message.fill"
        case .ping: "wave.3.right"
        case .neighbors: "antenna.radiowaves.left.and.right"
        case .manage: "slider.horizontal.3"
        }
    }

    var accessibilityIdentifier: String {
        switch self {
        case .identify: "peer.tile.identify"
        case .message: "peer.tile.message"
        case .ping: "peer.tile.ping"
        case .neighbors: "peer.tile.neighbors"
        case .manage: "peer.tile.manage"
        }
    }

    /// What the page can do at all, from the actions wired into it.
    struct Availability: Equatable {
        var identify = false
        var message = false
        var ping = false
        var neighbors = false
        var manage = false

        init(
            identify: Bool = false,
            message: Bool = false,
            ping: Bool = false,
            neighbors: Bool = false,
            manage: Bool = false
        ) {
            self.identify = identify
            self.message = message
            self.ping = ping
            self.neighbors = neighbors
            self.manage = manage
        }

        init(_ actions: PeerActions) {
            identify = actions.fetchIdentity != nil
            message = actions.startConversation != nil
            ping = actions.ping != nil
            neighbors = actions.loadPeerRepeaters != nil
            manage = actions.manageDevice != nil
        }
    }

    /// The tiles for a node, in order.
    ///
    /// Chosen by what the node advertises it can do, never by its role: a
    /// chat device may also repeat. A verb is left out when the node's
    /// advertisement lacks its capability, even one naming none at all; a
    /// node nothing has been heard from keeps every verb. Ping and Manage are
    /// always offered: any node answers a ping, and a device tells only its
    /// administrators that it can be managed. A node with no advertisement
    /// leads with Identify, the one thing that fills the rest in.
    ///
    /// The companion radio's own identity is reached over its link, not the
    /// mesh: it offers Ping and Manage alone.
    static func offered(for peer: PeerSummary, availability: Availability) -> [PeerVerb] {
        let capabilities = peer.advertisedCapabilities
        var verbs: [PeerVerb] = []
        if peer.isUlcpDevice {
            if availability.ping { verbs.append(.ping) }
            if availability.manage { verbs.append(.manage) }
            return verbs
        }
        if peer.advertisedIdentity == nil, availability.identify {
            verbs.append(.identify)
        }
        if availability.message, capabilities?.contains(.textMessages) ?? true {
            verbs.append(.message)
        }
        if availability.ping {
            verbs.append(.ping)
        }
        if availability.neighbors, capabilities?.contains(.repeater) ?? true {
            verbs.append(.neighbors)
        }
        if availability.manage {
            verbs.append(.manage)
        }
        return verbs
    }
}
