import CoreLocation
import Foundation

/// One node's reported location, ready to draw.
///
/// A flat value rather than a reference into the peer list, so the derivation
/// can be compared cheaply: the app root reloads on every advertisement, and
/// an unchanged mesh has to produce an equal array or the map redraws for
/// nothing.
struct MapNode: Identifiable, Hashable {
    let peer: PeerSummary
    let latitude: Double
    let longitude: Double
    /// How wide the reported grid cell is. A location names a cell, not a
    /// point; without this the marker would claim a precision the node never
    /// reported.
    let cellMeters: Double?
    /// When the node built the claim, from the identity bundle's own
    /// timestamp. Not the same question as `peer.lastHeard`, which is when we
    /// last heard anything at all from it.
    let reportedAt: Date?

    var id: Int64 { peer.id }

    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }

    /// Whether the claims may be attributed to this node at all. A location
    /// that nothing authenticated is one any nearby transmitter could have
    /// written.
    var isAttributable: Bool { peer.advertisedIdentityIsAttributable }

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
/// those were heard over the air and never saved — so `all` is the default
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

    func includes(_ peer: PeerSummary) -> Bool {
        switch self {
        case .all: true
        case .saved: peer.isSaved
        case .favorites: peer.isFavorite
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
/// it is labelled as the radio's rather than drawn as this phone's. A
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

    /// Whether anything has a location at all, filters aside — what tells an
    /// empty mesh apart from an over-narrow filter, without deriving and
    /// sorting the whole array to ask.
    static func anyLocations(peers: [PeerSummary]) -> Bool {
        peers.contains { location(of: $0) != nil }
    }

    /// Every node the filters admit that has somewhere to be drawn.
    static func nodes(
        peers: [PeerSummary],
        tier: MapTierFilter,
        capabilities: MeshNodeCapabilities
    ) -> [MapNode] {
        peers.compactMap { peer -> MapNode? in
            guard let (identity, latitude, longitude) = location(of: peer),
                  tier.includes(peer),
                  capabilities.isEmpty
                      || !capabilities.isDisjoint(with: identity.capabilityBits)
            else { return nil }
            return MapNode(
                peer: peer,
                latitude: latitude,
                longitude: longitude,
                cellMeters: identity.locationPrecision
                    .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) },
                reportedAt: identity.timestamp
                    .map { Date(timeIntervalSince1970: TimeInterval($0)) }
            )
        }
        // A stable order, so annotation identity survives a reload and the
        // markers do not shuffle when an unrelated node is heard.
        .sorted { $0.id < $1.id }
    }
}
