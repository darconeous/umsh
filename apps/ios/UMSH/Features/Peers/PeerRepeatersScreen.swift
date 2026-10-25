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
    /// The route to this repeater, which an ask after one of its neighbors
    /// goes down.
    @State private var route: PeerRoute?

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
            route = await actions.loadRoute?(peer)
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
    /// one it does not offers to ask it who it is, since a hint alone is not
    /// a key to address.
    @ViewBuilder
    private func row(_ neighbor: PeerRepeaterNeighbor) -> some View {
        let resolved = neighbor.resolve(among: actions.knownPeers)
        Group {
            if let resolved {
                NavigationLink {
                    browsing.open(resolved)
                } label: {
                    NeighborRow(neighbor: neighbor, reporter: peer, knownPeers: actions.knownPeers)
                }
            } else {
                NeighborRow(neighbor: neighbor, reporter: peer, knownPeers: actions.knownPeers) {
                    if let identify = actions.identifyRepeater, let path = pathToRepeater {
                        HintDiscoveryButton { await identify(neighbor.hint, path) }
                    }
                }
            }
        }
        .modifier(
            NeighborCoordinateActions(
                neighbor: neighbor,
                pinName: neighbor.title(among: actions.knownPeers)
            )
        )
    }

    /// The repeaters an ask after a neighbor goes down, ending at this
    /// repeater so the neighbor hears it one hop on. `nil` when the route
    /// cannot honestly land there.
    private var pathToRepeater: [Data]? {
        guard let vantage = SolicitVantage(peer: peer, route: route), vantage.landsAtPeer else {
            return nil
        }
        return vantage.repeaters
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
