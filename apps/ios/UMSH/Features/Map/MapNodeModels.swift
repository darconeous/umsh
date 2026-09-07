import CoreLocation
import Foundation

/// What a pin on the map stands for.
///
/// A node's own claim is keyed by its row; a position a router reported for
/// one of its neighbors is keyed by the hint the router gave, since that may
/// be all anyone knows about it.
enum MapNodeID: Hashable {
    case peer(Int64)
    case neighbor(hint: Data)
}

/// One node's reported location, ready to draw.
///
/// A flat value rather than a reference into the peer list, so the derivation
/// can be compared cheaply: the app root reloads on every advertisement, and
/// an unchanged mesh has to produce an equal array or the map redraws for
/// nothing.
struct MapNode: Identifiable, Hashable {
    let id: MapNodeID
    /// The node this pin is, when this phone knows it: the node whose own
    /// identity placed it, or a known node a router placed. `nil` for a
    /// neighbor known only by a hint, which has no page to open.
    let peer: PeerSummary?
    let displayName: String
    let hint: MeshNodeHint
    let isFavorite: Bool
    /// The router whose neighbor listing placed this pin. `nil` when the
    /// node placed itself.
    let reportedBy: PeerSummary?
    let latitude: Double
    let longitude: Double
    /// How wide the reported grid cell is. A location names a cell, not a
    /// point; without this the marker would claim a precision the node never
    /// reported.
    let cellMeters: Double?
    /// When the claim was made: the identity bundle's own timestamp for a
    /// node's own position, the router's answer for a reported one. Not the
    /// same question as `lastHeard`, which is when the node was last on the
    /// air at all.
    let reportedAt: Date?
    /// When the node was last heard—by this phone for its own pins, by the
    /// reporting router for reported ones.
    let lastHeard: Date?
    /// Whether the claims may be attributed to this node at all. A location
    /// that nothing authenticated is one any nearby transmitter could have
    /// written. A router's report is authenticated to the router, and the
    /// pin says so by its styling rather than by a warning.
    let isAttributable: Bool

    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }

    /// Whether this pin is what a router said rather than what the node said.
    var isReported: Bool { reportedBy != nil }

    /// Cells this coarse cover a city or more. Drawing a marker alone at that
    /// size would read as a street address.
    var isCoarse: Bool { (cellMeters ?? 0) >= 5_000 }

    func distance(from origin: CLLocationCoordinate2D) -> CLLocationDistance {
        CLLocation(latitude: latitude, longitude: longitude)
            .distance(from: CLLocation(latitude: origin.latitude, longitude: origin.longitude))
    }
}

/// Which tier of node the map is drawing.
///
/// The map's whole subject is nodes that reported a location, and most of
/// those were heard over the air and never saved—so `all` is the default
/// and the narrower tiers are the deliberate act.
enum MapTierFilter: String, CaseIterable, Identifiable {
    case all
    case saved
    case favorites

    var id: Self { self }

    var label: String {
        switch self {
        case .all: "All nodes"
        case .saved: "Saved"
        case .favorites: "Favorites"
        }
    }

    /// Whether a pin belongs to the tier. A reported neighbor this phone
    /// does not know is in no tier but `all`: there is no row to have saved
    /// or favorited.
    func includes(_ peer: PeerSummary?) -> Bool {
        switch self {
        case .all: true
        case .saved: peer?.isSaved == true
        case .favorites: peer?.isFavorite == true
        }
    }
}

/// A capability the map can filter on, paired with what to call it.
///
/// The labels match what the core renders for the same bits, so the filter
/// menu and a peer's Capabilities row never disagree.
struct MapCapabilityFilterOption: Identifiable, Hashable {
    let capability: MeshNodeCapabilities
    let label: String

    var id: UInt8 { capability.rawValue }

    static let all: [Self] = [
        Self(capability: .repeater, label: "Repeater"),
        Self(capability: .mobile, label: "Mobile"),
        Self(capability: .textMessages, label: "Text messages"),
        Self(capability: .telemetry, label: "Telemetry"),
        Self(capability: .chatRoom, label: "Chat room"),
        Self(capability: .coap, label: "CoAP"),
    ]
}

/// Where the operator is, from whichever source is wired.
///
/// Today the only answer is the companion radio's own receiver, which is why
/// it is labeled as the radio's rather than drawn as this phone's. A
/// CoreLocation provider can fill the same slot later without the map
/// changing shape.
struct MapSelfPosition: Equatable {
    let latitude: Double
    let longitude: Double
    let cellMeters: Double?
    /// What to call the source, since the map shows whose position it is.
    let sourceLabel: String

    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }

    /// The radio's fix, when it has one. A receiver that is searching reports
    /// no coordinates, and there is nothing to draw until it does.
    init?(radioPosition: RadioPosition?) {
        guard let radioPosition,
              let latitude = radioPosition.latitude,
              let longitude = radioPosition.longitude
        else { return nil }
        self.latitude = latitude
        self.longitude = longitude
        cellMeters = radioPosition.cellMeters
        sourceLabel = "This radio"
    }
}

extension MapNode {
    /// The one statement of what "has somewhere to be drawn" means, shared by
    /// the derivation and the emptiness probe so the two cannot drift.
    ///
    /// The companion radio is left out: it is on the map already as the
    /// operator's own position, and drawing it twice would put two markers on
    /// one antenna.
    private static func location(
        of peer: PeerSummary
    ) -> (identity: MeshNodeIdentity, latitude: Double, longitude: Double)? {
        guard !peer.isUlcpDevice,
              let identity = peer.advertisedIdentity,
              let latitude = identity.latitude,
              let longitude = identity.longitude
        else { return nil }
        return (identity, latitude, longitude)
    }

    /// Whether anything has a location at all, filters aside—what tells an
    /// empty mesh apart from an over-narrow filter, without deriving and
    /// sorting the whole array to ask.
    static func anyLocations(
        peers: [PeerSummary],
        neighborReports: [PeerRepeaterNeighborReport]
    ) -> Bool {
        peers.contains { location(of: $0) != nil }
            || neighborReports.contains { $0.neighbor.hasLocation }
    }

    /// Every node the filters admit that has somewhere to be drawn: nodes
    /// that placed themselves, then neighbors routers placed that no node
    /// has placed already.
    static func nodes(
        peers: [PeerSummary],
        neighborReports: [PeerRepeaterNeighborReport],
        tier: MapTierFilter,
        capabilities: MeshNodeCapabilities
    ) -> [MapNode] {
        var nodes: [MapNode] = peers.compactMap { peer -> MapNode? in
            guard let (identity, latitude, longitude) = location(of: peer),
                  tier.includes(peer),
                  capabilities.isEmpty
                      || !capabilities.isDisjoint(with: identity.capabilityBits)
            else { return nil }
            return MapNode(
                id: .peer(peer.id),
                peer: peer,
                displayName: peer.displayName,
                hint: peer.identity.hint,
                isFavorite: peer.isFavorite,
                reportedBy: nil,
                latitude: latitude,
                longitude: longitude,
                cellMeters: identity.locationPrecision
                    .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) },
                reportedAt: identity.timestamp
                    .map { Date(timeIntervalSince1970: TimeInterval($0)) },
                lastHeard: peer.lastHeard,
                isAttributable: peer.advertisedIdentityIsAttributable
            )
        }
        // Filters aside: a node that could place itself is not also placed
        // by a router, whether or not the current filter shows it.
        let selfPlaced = Set(peers.filter { location(of: $0) != nil }.map(\.id))
        nodes.append(contentsOf: reportedNodes(
            neighborReports,
            peers: peers,
            selfPlaced: selfPlaced,
            tier: tier,
            capabilities: capabilities
        ))
        // A stable order, so annotation identity survives a reload and the
        // markers do not shuffle when an unrelated node is heard.
        return nodes.sorted { sortKey($0.id) < sortKey($1.id) }
    }

    /// Pins for neighbors routers have placed. One pin per hint, from the
    /// freshest report; none for a neighbor that turns out to be a node
    /// with its own position, or the companion radio, which is the self
    /// marker already.
    private static func reportedNodes(
        _ reports: [PeerRepeaterNeighborReport],
        peers: [PeerSummary],
        selfPlaced: Set<Int64>,
        tier: MapTierFilter,
        capabilities: MeshNodeCapabilities
    ) -> [MapNode] {
        // Neighbors are repeaters by definition, so the capability filter
        // admits them when it names that or names nothing.
        guard capabilities.isEmpty || capabilities.contains(.repeater) else { return [] }
        var freshest: [Data: PeerRepeaterNeighborReport] = [:]
        for report in reports where report.neighbor.hasLocation {
            if let held = freshest[report.neighbor.hint],
               held.neighbor.reportedAt >= report.neighbor.reportedAt
            {
                continue
            }
            freshest[report.neighbor.hint] = report
        }
        return freshest.values.compactMap { report -> MapNode? in
            let neighbor = report.neighbor
            guard let latitude = neighbor.latitude, let longitude = neighbor.longitude else {
                return nil
            }
            let resolved = neighbor.resolve(among: peers)
            if let resolved, selfPlaced.contains(resolved.id) || resolved.isUlcpDevice {
                return nil
            }
            guard tier.includes(resolved) else { return nil }
            return MapNode(
                id: .neighbor(hint: neighbor.hint),
                peer: resolved,
                displayName: neighbor.title(among: peers),
                hint: resolved?.identity.hint ?? neighbor.avatarHint,
                isFavorite: resolved?.isFavorite == true,
                reportedBy: report.reporter,
                latitude: latitude,
                longitude: longitude,
                cellMeters: neighbor.locationPrecision
                    .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) },
                reportedAt: neighbor.reportedAt,
                lastHeard: neighbor.lastHeardAt,
                isAttributable: true
            )
        }
    }

    /// Nodes that placed themselves first, by row; reported neighbors after,
    /// by hint. Neither set reorders when the other moves.
    private static func sortKey(_ id: MapNodeID) -> (Int, Int64, [UInt8]) {
        switch id {
        case let .peer(rowID): (0, rowID, [])
        case let .neighbor(hint): (1, 0, Array(hint))
        }
    }
}

private func < (lhs: (Int, Int64, [UInt8]), rhs: (Int, Int64, [UInt8])) -> Bool {
    if lhs.0 != rhs.0 { return lhs.0 < rhs.0 }
    if lhs.1 != rhs.1 { return lhs.1 < rhs.1 }
    return lhs.2.lexicographicallyPrecedes(rhs.2)
}
