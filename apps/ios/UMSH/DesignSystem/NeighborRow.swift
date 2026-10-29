import SwiftUI

/// One repeater a router reported as its neighbor, as every neighbor list
/// draws it: the known node's name and avatar when this phone has one, the
/// signal and age the router gave, and the regions and position when it had
/// any. Screens own navigation and menus around it.
struct NeighborRow<Trailing: View>: View {
    let neighbor: PeerRepeaterNeighbor
    /// The router that reported it, whose position the distance is from.
    let reporter: PeerSummary
    let knownPeers: [PeerSummary]
    private let trailing: Trailing

    init(
        neighbor: PeerRepeaterNeighbor,
        reporter: PeerSummary,
        knownPeers: [PeerSummary],
        @ViewBuilder trailing: () -> Trailing = { EmptyView() }
    ) {
        self.neighbor = neighbor
        self.reporter = reporter
        self.knownPeers = knownPeers
        self.trailing = trailing()
    }

    /// How long since the router last heard a neighbor before the row is
    /// drawn as a memory rather than a presence.
    static var staleAge: TimeInterval { 6 * 60 * 60 }

    var body: some View {
        let resolved = neighbor.resolve(among: knownPeers)
        // A neighbor the repeater has not heard in hours is still in its
        // table, but the table is remembering rather than reporting, and
        // the row should read that way at a glance: text and avatar both.
        PeerRow(
            // The known node's own hint when there is one: the row is that
            // node, and its avatar should be the one it wears everywhere
            // else. A two-byte hint draws gray, which is what a node known
            // only by its trace looks like.
            hint: resolved?.identity.hint ?? neighbor.avatarHint,
            shape: resolved?.avatarShape ?? .hexagon,
            title: neighbor.title(among: knownPeers),
            subtitle: subtitle,
            size: .compact,
            showsFavoriteStar: resolved?.isFavorite == true,
            isStale: neighbor.lastHeard(isOlderThan: Self.staleAge),
            trailing: { trailing }
        )
    }

    /// The signal and age on one line, the regions and position on a second
    /// only when there are any: nothing is shown as a dash.
    private var subtitle: String {
        var lines: [String] = []

        var heard: [String] = [Self.signalText(neighbor)]
        if let age = Self.heardText(neighbor) { heard.append(age) }
        lines.append(heard.joined(separator: " · "))

        var detail: [String] = []
        if !neighbor.regionCodes.isEmpty {
            detail.append(neighbor.regionCodes.map(RegionCodeText.label).joined(separator: ", "))
        }
        if let latitude = neighbor.latitude, let longitude = neighbor.longitude {
            // The cell size only decides how many digits are real; the size
            // itself is not something a person reading a neighbor list weighs.
            let cellMeters = neighbor.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
            detail.append(
                LocationPresentation.coordinateText(
                    latitude: latitude,
                    longitude: longitude,
                    cellMeters: cellMeters
                )
            )
            if let separation = separationText(
                latitude: latitude,
                longitude: longitude,
                cellMeters: cellMeters
            ) {
                detail.append(separation)
            }
        }
        if !detail.isEmpty { lines.append(detail.joined(separator: " · ")) }

        return lines.joined(separator: "\n")
    }

    /// How far the neighbor is from the repeater being asked, which is the
    /// distance a neighbor listing is about: the reach of one hop, not how
    /// far anything is from this phone. `nil` when the repeater has not
    /// placed itself.
    private func separationText(
        latitude: Double,
        longitude: Double,
        cellMeters: Double?
    ) -> String? {
        guard let identity = reporter.advertisedIdentity,
              let routerLatitude = identity.latitude,
              let routerLongitude = identity.longitude
        else { return nil }
        return LocationPresentation.separationText(
            centerMeters: LocationPresentation.distanceMeters(
                fromLatitude: routerLatitude,
                longitude: routerLongitude,
                toLatitude: latitude,
                longitude: longitude
            ),
            cellMeters: identity.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) },
            otherCellMeters: cellMeters
        )
    }

    /// `−72 dBm · SNR 6.5 dB`. Quarter-decibel steps on the wire, unlike the
    /// centibels a ping reply carries, so this is its own conversion.
    ///
    /// A neighbor with no signal at all was never heard over the air: the
    /// repeater knows it through a backhaul, and the row says so rather than
    /// leaving a gap where the figures would be.
    private static func signalText(_ neighbor: PeerRepeaterNeighbor) -> String {
        SignalPresentation.readingText(
            rssiDBm: neighbor.rssiDBm,
            snrDecibels: neighbor.snrQuarterDB.map { Double($0) / 4 }
        ) ?? String(localized: "Bridged", comment: "A neighbor heard over a non-radio link, so it has no signal reading.")
    }

    /// When the router last heard the node, as an age on this phone's clock.
    /// The wire's saturated figure is not a measurement and is not shown as
    /// one.
    private static func heardText(_ neighbor: PeerRepeaterNeighbor) -> String? {
        if let heardAt = neighbor.lastHeardAt {
            return "heard \(heardAt.formatted(.relative(presentation: .named)))"
        }
        if neighbor.lastHeardMinutes != nil {
            return "heard long ago"
        }
        return nil
    }
}
