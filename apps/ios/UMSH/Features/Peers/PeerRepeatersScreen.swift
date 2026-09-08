import SwiftUI

/// What one router says about the repeaters around it, a page at a time.
///
/// Opens on whatever this phone last heard from the router and puts nothing
/// on the air until asked: every page is one exchange across the mesh at
/// everyone's expense, so Refresh asks for the top of the listing, Load more
/// for the page after the last one held, and neither happens on its own.
///
/// A plain MAC command any node may send, so unlike the Manage Device
/// screens this needs no standing as an administrator—only a router that
/// keeps a neighbor table and is in reach.
struct PeerRepeatersScreen: View {
    let peer: PeerSummary
    let actions: PeerActions
    /// How a neighbor this phone knows opens: as the same peer page this
    /// screen was pushed from.
    let browsing: RemotePeerBrowsing

    @State private var listing: PeerRepeaterListing?
    @State private var isBusy = false
    /// Whether `listing` was answered during this visit, as opposed to
    /// prefilled from the cache.
    @State private var isFresh = false
    @State private var problem: String?
    @State private var hasLoadedCache = false

    var body: some View {
        List {
            neighborsSection
            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Neighboring Repeaters")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if isBusy {
                    ProgressView()
                } else {
                    Button {
                        ask(cursor: nil)
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(actions.loadPeerRepeaters == nil)
                }
            }
        }
        .task {
            // The cache and nothing else: opening the screen must not ask.
            guard !hasLoadedCache else { return }
            hasLoadedCache = true
            listing = await actions.cachedPeerRepeaters?(peer)
        }
        .animation(UMSHAnimation.list, value: listing?.entries.map(\.hint))
    }

    // MARK: - Neighbors

    private var entries: [PeerRepeaterNeighbor] { listing?.entries ?? [] }

    private var neighborsSection: some View {
        Section {
            ForEach(entries, id: \.hint) { neighbor in
                row(neighbor)
            }
            if entries.isEmpty {
                // Never asked and asked-and-empty are different answers.
                Text(listing == nil ? "Not read" : "None")
                    .foregroundStyle(.secondary)
            }
            if let listing, let cursor = listing.nextCursor {
                Button {
                    ask(cursor: cursor)
                } label: {
                    HStack {
                        Label("Load more", systemImage: "ellipsis.circle")
                        Spacer()
                        if let total = listing.total {
                            Text("\(listing.entries.count) of \(total)")
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                }
                .disabled(isBusy || actions.loadPeerRepeaters == nil)
            }
        } header: {
            Text("Neighbors")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                RemoteReadingFooter(
                    asOf: listing?.asOf,
                    isFresh: isFresh,
                    isBusy: isBusy,
                    subject: "the repeater"
                )
                if let listing, listing.isComplete, let total = listing.total, total > 0 {
                    Text("\(listing.entries.count) of \(total) neighbors listed.")
                }
            }
        }
    }

    /// One neighbor. A neighbor this phone knows opens that node's page;
    /// one it does not is a row with nowhere further to go, since a hint
    /// alone is not a key to address.
    @ViewBuilder
    private func row(_ neighbor: PeerRepeaterNeighbor) -> some View {
        let resolved = neighbor.resolve(among: actions.knownPeers)
        Group {
            if let resolved {
                NavigationLink {
                    browsing.open(resolved)
                } label: {
                    rowContent(neighbor, resolved: resolved)
                }
            } else {
                rowContent(neighbor, resolved: nil)
            }
        }
        .modifier(
            NeighborCoordinateActions(
                neighbor: neighbor,
                pinName: neighbor.title(among: actions.knownPeers)
            )
        )
    }

    /// How long since the router last heard a neighbor before the row is
    /// drawn as a memory rather than a presence.
    private static let staleAge: TimeInterval = 2 * 24 * 60 * 60

    private func rowContent(_ neighbor: PeerRepeaterNeighbor, resolved: PeerSummary?) -> some View {
        PeerRow(
            // The known node's own hint when there is one: the row is that
            // node, and its avatar should be the one it wears everywhere
            // else. A two-byte hint draws gray, which is what a node known
            // only by its trace looks like.
            hint: resolved?.identity.hint ?? neighbor.avatarHint,
            title: neighbor.title(among: actions.knownPeers),
            subtitle: subtitle(neighbor),
            diameter: 32,
            showsFavoriteStar: resolved?.isFavorite == true
        )
        // A neighbor the router has not heard in days is still in its
        // table, but the table is remembering rather than reporting, and
        // the row should read that way at a glance.
        .foregroundStyle(
            neighbor.lastHeard(isOlderThan: Self.staleAge)
                ? AnyShapeStyle(.secondary)
                : AnyShapeStyle(.primary)
        )
    }

    /// The signal and age on one line, the regions and position on a second
    /// only when there are any: nothing is shown as a dash.
    private func subtitle(_ neighbor: PeerRepeaterNeighbor) -> String {
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
        guard let identity = peer.advertisedIdentity,
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

    /// `−72 dBm, 6.5 dB`. Quarter-decibel steps on the wire, unlike the
    /// centibels a ping reply carries, so this is its own conversion.
    ///
    /// A neighbor with no signal at all was never heard over the air: the
    /// repeater knows it through a backhaul, and the row says so rather than
    /// leaving a gap where the figures would be.
    private static func signalText(_ neighbor: PeerRepeaterNeighbor) -> String {
        var parts: [String] = []
        if let rssi = neighbor.rssiDBm { parts.append("\(rssi) dBm") }
        if let snr = neighbor.snrQuarterDB {
            parts.append(String(format: "%.1f dB", Double(snr) / 4))
        }
        return parts.isEmpty ? "Bridged" : parts.joined(separator: ", ")
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

    // MARK: - Asking

    private func ask(cursor: Data?) {
        guard let load = actions.loadPeerRepeaters, !isBusy else { return }
        isBusy = true
        problem = nil
        Task {
            let result = await load(peer, cursor)
            switch result {
            case let .page(page):
                listing = page
                isFresh = true
            case .noAnswer:
                problem = "The repeater did not answer. It may be out of reach, "
                    + "or it may not keep a neighbor table."
            case .failed:
                problem = "This phone could not send the request."
            case let .unavailable(reason):
                problem = reason
            }
            isBusy = false
        }
    }
}

/// The coordinate menu on a neighbor that reported a position, and nothing
/// on one that did not. A modifier because a conditional modifier chain
/// would change the row's view identity as pages land.
private struct NeighborCoordinateActions: ViewModifier {
    let neighbor: PeerRepeaterNeighbor
    let pinName: String

    func body(content: Content) -> some View {
        if let latitude = neighbor.latitude, let longitude = neighbor.longitude {
            let cellMeters = neighbor.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
            content.coordinateActions(
                latitude: latitude,
                longitude: longitude,
                fractionDigits: LocationPresentation.coordinateDecimals(cellMeters: cellMeters),
                pinName: pinName
            )
        } else {
            content
        }
    }
}
