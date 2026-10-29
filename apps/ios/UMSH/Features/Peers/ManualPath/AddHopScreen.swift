import SwiftUI

/// Pick the next repeater on a manual path, from what the previous hop says
/// it hears or from the repeaters this phone knows.
///
/// One screen for every hop: choosing a row appends it and the screen moves
/// on to the hop after, asking the node just chosen. Opening a listing shows
/// what was last heard and sends nothing; every page is a tap.
struct AddHopScreen: View {
    let destination: PeerSummary
    let actions: PeerActions
    @Binding var hops: [ManualPathHop]

    private enum Source: Hashable {
        case neighbors
        case knownRepeaters
    }

    @Environment(\.dismiss) private var dismiss
    /// The path as it stood when the sheet opened, for Cancel.
    @State private var original: [ManualPathHop]?
    @State private var source = Source.neighbors
    @State private var query = ""
    @State private var listing: PeerRepeaterListing?
    @State private var isFresh = false
    @State private var isBusy = false
    @State private var problem: String?

    init(destination: PeerSummary, actions: PeerActions, hops: Binding<[ManualPathHop]>) {
        self.destination = destination
        self.actions = actions
        _hops = hops
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(breadcrumb)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Picker("Source", selection: Binding(
                        get: { effectiveSource },
                        set: { source = $0 }
                    )) {
                        Text("Neighbors").tag(Source.neighbors)
                        Text("Known Repeaters").tag(Source.knownRepeaters)
                    }
                    .pickerStyle(.segmented)
                    .disabled(!canAskNeighbors)
                }
                if isFull {
                    Section {
                        Text("The path holds \(ManualPathDraft.maximumHops) repeaters, the most it can carry.")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    if destinationIsNeighbor {
                        Section {
                            PeerRow(peer: destination, size: .compact)
                            Button("Finish Here") { dismiss() }
                        }
                    }
                    switch effectiveSource {
                    case .neighbors: neighborsSection
                    case .knownRepeaters: knownRepeatersSection
                    }
                    if let problem {
                        Section { Text(problem).foregroundStyle(.red) }
                    }
                    Section {
                        NavigationLink("Enter Router Hint…") {
                            RouterHintEntryScreen(
                                actions: actions,
                                isInPath: { hint in hops.contains { $0.hint == hint } },
                                add: { hint in
                                    hops.append(ManualPathHop(hint: hint, enteredByHand: true))
                                }
                            )
                        }
                    }
                }
            }
            .searchable(text: $query, prompt: "Name or router hint")
            .navigationTitle("Add Hop \(hops.count + 1)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        if let original { hops = original }
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                if original == nil { original = hops }
            }
            .task(id: previousHop?.identity.canonicalAddress) {
                await loadCachedListing()
            }
        }
    }

    // MARK: - Where the path stands

    private var isFull: Bool { hops.count >= ManualPathDraft.maximumHops }

    private var breadcrumb: String {
        let names = hops.map { hop in
            hop.named(among: actions.knownPeers)?.displayName ?? hop.hint.text
        }
        return (["This phone"] + names + ["?"]).joined(separator: " › ")
    }

    /// The node asked for this hop's neighbors: the companion radio for the
    /// first hop, else the last hop chosen. `nil` when that hop is known
    /// only by its hint, since a hint is not an address to ask.
    private var previousHop: PeerSummary? {
        guard let last = hops.last else { return actions.radioIdentityPeer }
        return last.named(among: actions.knownPeers)
    }

    /// The repeaters ahead of the previous hop, which the ask is sent down.
    private var pathToPrevious: [MeshRouterHint] {
        hops.dropLast().map(\.hint)
    }

    /// Whether there is a node to ask for this hop's neighbors.
    private var canAskNeighbors: Bool {
        previousHop != nil && actions.loadPeerRepeatersAlong != nil
    }

    private var effectiveSource: Source {
        canAskNeighbors ? source : .knownRepeaters
    }

    private func isInPath(_ peer: PeerSummary) -> Bool {
        hops.contains { $0.named(among: actions.knownPeers)?.id == peer.id }
    }

    private func isInPath(hintBytes: Data) -> Bool {
        hops.contains { $0.hint.bytes == hintBytes.prefix(2) }
    }

    private var destinationIsNeighbor: Bool {
        guard effectiveSource == .neighbors, let listing else { return false }
        return listing.entries.contains { $0.resolve(among: actions.knownPeers)?.id == destination.id }
    }

    // MARK: - Neighbors

    private var neighbors: [PeerRepeaterNeighbor] {
        (listing?.entries ?? []).filter { neighbor in
            let resolved = neighbor.resolve(among: actions.knownPeers)
            guard resolved?.id != destination.id else { return false }
            guard !query.isEmpty else { return true }
            if let resolved { return resolved.matches(searchQuery: query) }
            return neighbor.title(among: actions.knownPeers)
                .range(of: query, options: .caseInsensitive) != nil
                || neighbor.hintText.range(of: query, options: .caseInsensitive) != nil
        }
    }

    @ViewBuilder
    private var neighborsSection: some View {
        if let previousHop {
            Section {
                ForEach(neighbors, id: \.hint) { neighbor in
                    let inPath = isInPath(hintBytes: neighbor.hint)
                    Button {
                        Task { await choose(neighbor) }
                    } label: {
                        NeighborRow(
                            neighbor: neighbor,
                            reporter: previousHop,
                            knownPeers: actions.knownPeers
                        ) {
                            if inPath {
                                Text("In path").foregroundStyle(.secondary)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(inPath)
                }
                if neighbors.isEmpty {
                    Text(listing == nil ? "Not read" : "None")
                        .foregroundStyle(.secondary)
                }
                if let listing, let cursor = listing.nextCursor {
                    Button {
                        ask(cursor: cursor)
                    } label: {
                        HStack {
                            Text("Load More")
                            Spacer()
                            if let total = listing.total {
                                Text("\(listing.entries.count) of \(total)")
                                    .foregroundStyle(.secondary)
                                    .monospacedDigit()
                            }
                        }
                    }
                    .disabled(isBusy)
                }
            } header: {
                HStack {
                    Text("Heard by \(previousHop.displayName)")
                    Spacer()
                    if isBusy {
                        ProgressView()
                    } else {
                        Button("Refresh") { ask(cursor: nil) }
                            .font(.footnote)
                            .textCase(nil)
                    }
                }
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    RemoteReadingFooter(
                        asOf: listing?.asOf,
                        isFresh: isFresh,
                        isBusy: isBusy,
                        subject: "the repeater"
                    )
                    if !pathToPrevious.isEmpty {
                        Text("Asked through \(pathToPrevious.map { RouterHintNaming.label($0, among: actions.knownPeers) }.joined(separator: " › ")).")
                    }
                }
            }
        }
    }

    // MARK: - Known repeaters

    private var knownRepeaters: [PeerSummary] {
        actions.knownPeers
            .filter { $0.id != destination.id && !$0.isUlcpDevice }
            .filter(\.isLikelyRepeater)
            .filter { $0.matches(searchQuery: query) }
            .sorted { ($0.lastHeard ?? .distantPast) > ($1.lastHeard ?? .distantPast) }
    }

    private var knownRepeatersSection: some View {
        Section {
            ForEach(knownRepeaters) { peer in
                let inPath = isInPath(peer)
                Button {
                    Task { await choose(peer) }
                } label: {
                    PeerRow(
                        hint: peer.identity.hint,
                        shape: peer.avatarShape,
                        title: peer.displayName,
                        subtitle: peer.lastHeard.map {
                            "heard \($0.formatted(.relative(presentation: .named)))"
                        },
                        size: .compact,
                        showsFavoriteStar: peer.isFavorite,
                        trailing: {
                            if inPath {
                                Text("In path").foregroundStyle(.secondary)
                            }
                        }
                    )
                }
                .buttonStyle(.plain)
                .disabled(inPath)
            }
            if knownRepeaters.isEmpty {
                Text("None").foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Choosing

    private func choose(_ neighbor: PeerRepeaterNeighbor) async {
        guard let hint = await routerHint(neighbor.hint.prefix(2)) else { return }
        var hop = ManualPathHop(hint: hint, node: neighbor.resolve(among: actions.knownPeers))
        if let rssi = neighbor.rssiDBm { hop.signal = "\(rssi) dBm" }
        append(hop)
    }

    private func choose(_ peer: PeerSummary) async {
        guard let bytes = peer.routerHintBytes, let hint = await routerHint(bytes) else { return }
        append(ManualPathHop(hint: hint, node: peer))
    }

    private func append(_ hop: ManualPathHop) {
        hops.append(hop)
        query = ""
        listing = nil
        isFresh = false
        problem = nil
        source = .neighbors
    }

    private func routerHint(_ bytes: Data) async -> MeshRouterHint? {
        await actions.renderRouterHint?(Data(bytes))
    }

    // MARK: - Asking

    private func loadCachedListing() async {
        isFresh = false
        problem = nil
        guard let previousHop else {
            listing = nil
            return
        }
        listing = await actions.cachedPeerRepeaters?(previousHop)
    }

    private func ask(cursor: Data?) {
        guard let load = actions.loadPeerRepeatersAlong, let previousHop, !isBusy else { return }
        isBusy = true
        problem = nil
        let route = pathToPrevious
        Task {
            switch await load(previousHop, cursor, route) {
            case let .page(page):
                listing = page
                isFresh = true
            case .noAnswer:
                problem = "No answer. Pick from Known Repeaters instead."
            case .failed:
                problem = "This phone could not send the request."
            case let .unavailable(reason):
                problem = reason
            }
            isBusy = false
        }
    }
}
