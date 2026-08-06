import MapKit
import SwiftUI

/// Where the mesh is, as opposed to who is in it.
///
/// Deliberately separate from the peer list rather than a second presentation
/// of it. What belongs here is every node that has reported a location —
/// mostly nodes heard over the air and never saved — so the peer list is not
/// the set being drawn, and a toggle above the peer list would say it was.
/// The tier filter narrows to saved or favorite nodes on request, but the
/// default is the whole set.
struct NodeMapView: View {
    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    let peers: [PeerSummary]
    /// Whether launch bootstrap is still running, so an empty map reads as
    /// "not read yet" rather than "nothing is out there".
    var isLoading = false
    var peerActions: PeerActions = .unavailable
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    var messageActions: ChatMessageActions = .unavailable
    /// Send the reader to the Peers tab, for the empty state's way out.
    var openPeersList: () -> Void = {}
    var openConversation: (DirectConversationSummary) -> Void = { _ in }
    var advertiseIdentity: (() async -> String?)? = nil
    var advertisedName: String = ""
    var clearDiscoveredNodes: (() async -> Void)? = nil
    var solicitNearbyIdentities: ((PeerRole?) async -> Bool)? = nil

    @AppStorage("map.tier") private var tierFilter: MapTierFilter = .all
    /// The capability filter, as raw bits. `AppStorage` stores what it can
    /// store; the typed set is one initializer away and nothing else sees
    /// this number.
    @AppStorage("map.capabilities") private var capabilityFilterBits = 0
    @State private var camera: MapCameraPosition = .automatic
    /// The map frames itself once. After that the camera belongs to the
    /// reader: an advertisement landing mid-pan must not yank the view.
    @State private var hasFramedNodes = false
    @State private var selectedNodeID: Int64?
    @State private var cardDetent: MapCardDetent = .peek
    @State private var showsDiscovery = false

    private var capabilityFilter: MeshNodeCapabilities {
        MeshNodeCapabilities(rawValue: UInt8(truncatingIfNeeded: capabilityFilterBits))
    }

    private var nodes: [MapNode] {
        MapNode.nodes(peers: peers, tier: tierFilter, capabilities: capabilityFilter)
    }

    private var hasAnyLocations: Bool {
        MapNode.anyLocations(peers: peers)
    }

    private var isFiltered: Bool { tierFilter != .all || !capabilityFilter.isEmpty }

    private var selfPosition: MapSelfPosition? {
        MapSelfPosition(radioPosition: radioSnapshot.position)
    }

    var body: some View {
        let nodes = nodes

        // The card is the content and the map is its background, rather than
        // the two being stacked. A `Map` gives up the safe area so it can
        // draw edge to edge, and anything stacked with it inherits that and
        // lands under the tab bar — but a background does not affect what it
        // sits behind. So the map still fills the screen while the card keeps
        // the safe area, resting on the tab bar's top edge with every tab
        // reachable at any detent.
        //
        // The reader supplies the card's ceiling: the card is what would
        // create an inset, so measuring the region from inside it would be
        // circular.
        GeometryReader { proxy in
            // The reader's child region stops at the floating tab bar; the
            // card opts past that boundary so its glass and its list run to
            // the screen's bottom edge, the way Find My's sheet does — rows
            // show frosted through the bar, and a matching scroll margin
            // (applied inside the card) lets every row scroll clear of it.
            let tabBar = proxy.safeAreaInsets.bottom
            card(
                nodes: nodes,
                availableHeight: proxy.size.height,
                bottomInset: tabBar
            )
                .frame(
                    maxWidth: .infinity,
                    maxHeight: .infinity,
                    alignment: .bottom
                )
                .ignoresSafeArea(.container, edges: .bottom)
        }
        .background {
            map(nodes: nodes)
                .ignoresSafeArea()
        }
        .navigationTitle("Map")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) { filterMenu }
        }
        .sheet(isPresented: $showsDiscovery) {
            DiscoverPeersView(
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                peers: peers,
                peerActions: peerActions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions,
                advertiseIdentity: advertiseIdentity,
                advertisedName: advertisedName,
                clearDiscoveredNodes: clearDiscoveredNodes,
                solicitNearbyIdentities: solicitNearbyIdentities,
                openConversation: { conversation in
                    showsDiscovery = false
                    openConversation(conversation)
                }
            )
        }
        .onAppear {
            frameNodesIfNeeded(nodes)
            revealEmptyStateIfNeeded(nodes)
        }
        .onChange(of: nodes.isEmpty) { _, isEmpty in
            if isEmpty {
                revealEmptyStateIfNeeded(nodes)
            } else {
                frameNodesIfNeeded(nodes)
            }
        }
        .onChange(of: selectedNodeID) { _, selected in
            guard let node = nodes.first(where: { $0.id == selected }) else { return }
            focus(on: node)
        }
    }

    private func map(nodes: [MapNode]) -> some View {
        Map(position: $camera, selection: $selectedNodeID) {
            ForEach(nodes) { node in
                if shouldDrawCell(node), let cellMeters = node.cellMeters {
                    MapCircle(center: node.coordinate, radius: cellMeters / 2)
                        .foregroundStyle(Color.accentColor.opacity(0.12))
                        .stroke(Color.accentColor.opacity(0.45), lineWidth: 1)
                }
                Annotation(node.peer.displayName, coordinate: node.coordinate) {
                    MapNodeMarker(node: node, isSelected: node.id == selectedNodeID)
                }
                .tag(node.id)
                .annotationTitles(.hidden)
            }
            if let selfPosition {
                // The nodes' rule — coarse or selected — does not transfer:
                // the self marker cannot be selected, so any cell big enough
                // to see gets drawn. Below ~100 m the circle is smaller than
                // the marker at any zoom the map spends time at.
                if let cellMeters = selfPosition.cellMeters, cellMeters >= 100 {
                    MapCircle(center: selfPosition.coordinate, radius: cellMeters / 2)
                        .foregroundStyle(Color.accentColor.opacity(0.10))
                        .stroke(Color.accentColor.opacity(0.35), lineWidth: 1)
                }
                // Unlike the nodes', this title stays visible: the marker is
                // the one thing on the map that is not a peer, and the label
                // is what says whose position it is — the radio's, not this
                // phone's.
                Annotation(selfPosition.sourceLabel, coordinate: selfPosition.coordinate) {
                    MapSelfPositionMarker()
                }
            }
        }
        .mapControls {
            MapCompass()
            MapScaleView()
        }
    }

    // MARK: - The card

    private func card(
        nodes: [MapNode],
        availableHeight: CGFloat,
        bottomInset: CGFloat
    ) -> some View {
        MapBottomCard(
            detent: $cardDetent,
            availableHeight: availableHeight,
            bottomInset: bottomInset
        ) {
            cardHeader(nodes: nodes)
        } content: {
            MapNodeListCard(
                nodes: nodes,
                selectedNodeID: $selectedNodeID,
                selfPosition: selfPosition,
                hasAnyLocations: hasAnyLocations,
                isFiltered: isFiltered,
                isLoading: isLoading,
                clearFilters: clearFilters,
                discoverPeers: { showsDiscovery = true },
                openPeersList: openPeersList,
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                peerActions: peerActions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions
            )
        }
    }

    /// The count, plus what is being left out — but only when something is.
    /// Unfiltered, naming the whole set again would say nothing, and one
    /// line is one line the list does not get.
    private func cardHeader(nodes: [MapNode]) -> some View {
        Text(cardHeaderText(nodes: nodes))
            .font(.headline)
            .lineLimit(1)
            .frame(maxWidth: .infinity)
            .padding(.horizontal)
    }

    private func cardHeaderText(nodes: [MapNode]) -> String {
        let count = nodes.count == 1 ? "1 node" : "\(nodes.count) nodes"
        var parts = [count]
        if tierFilter != .all { parts.append(tierFilter.label) }
        // "or", because that is what the filter does: any selected
        // capability admits a node. Dots would read as all-of.
        let capabilities = MapCapabilityFilterOption.all
            .filter { capabilityFilter.contains($0.capability) }
            .map(\.label)
        if !capabilities.isEmpty {
            parts.append(capabilities.joined(separator: " or "))
        }
        return parts.joined(separator: " · ")
    }

    // MARK: - Filters

    private var filterMenu: some View {
        Menu {
            Picker("Show", selection: $tierFilter) {
                ForEach(MapTierFilter.allCases) { filter in
                    Text(filter.label).tag(filter)
                }
            }
            .pickerStyle(.inline)
            // A section rather than a submenu, because a submenu cannot be
            // used for this: selecting inside one always collapses it back
            // to its parent, so choosing three capabilities meant opening
            // it three times. Flat, every toggle leaves the menu exactly
            // where it was, which is what a multiple choice needs.
            Section("Capabilities") {
                Toggle(
                    "Any capability",
                    isOn: Binding(
                        get: { capabilityFilter.isEmpty },
                        // Turning it off names no capability to filter on,
                        // so there is nothing to do; selecting one of the
                        // six below is what turns it off.
                        set: { isOn in if isOn { capabilityFilterBits = 0 } }
                    )
                )
                ForEach(MapCapabilityFilterOption.all) { option in
                    Toggle(
                        option.label,
                        isOn: Binding(
                            get: { capabilityFilter.contains(option.capability) },
                            set: { _ in toggle(option.capability) }
                        )
                    )
                }
            }
            if isFiltered {
                Divider()
                Button("Clear filters", action: clearFilters)
            }
        } label: {
            Label(
                "Filter",
                systemImage: isFiltered
                    ? "line.3.horizontal.decrease.circle.fill"
                    : "line.3.horizontal.decrease.circle"
            )
        }
        // Without this every toggle closes the menu, which for a filter
        // that is meant to be built up a piece at a time makes the second
        // piece cost a full reopen. Selecting a tier no longer closes the
        // menu either; that is the price, and it is small.
        .menuActionDismissBehavior(.disabled)
    }

    private func toggle(_ capability: MeshNodeCapabilities) {
        var bits = capabilityFilter
        if bits.contains(capability) {
            bits.remove(capability)
        } else {
            bits.insert(capability)
        }
        capabilityFilterBits = Int(bits.rawValue)
    }

    private func clearFilters() {
        tierFilter = .all
        capabilityFilterBits = 0
    }

    // MARK: - Camera

    /// A cell this coarse covers a city or more; a marker on its own would
    /// read as an address the node never gave. Finer cells draw their circle
    /// only when selected, so a crowded map stays legible.
    private func shouldDrawCell(_ node: MapNode) -> Bool {
        node.isCoarse || node.id == selectedNodeID
    }

    /// A card at its lowest with nothing in it shows a count and no reason
    /// for it. Lift it far enough that the explanation and its way out are
    /// on screen.
    private func revealEmptyStateIfNeeded(_ nodes: [MapNode]) {
        guard nodes.isEmpty, cardDetent == .peek else { return }
        cardDetent = .half
    }

    private func frameNodesIfNeeded(_ nodes: [MapNode]) {
        guard !hasFramedNodes else { return }
        var coordinates = nodes.map(\.coordinate)
        if let selfPosition { coordinates.append(selfPosition.coordinate) }
        guard let region = Self.region(fitting: coordinates) else { return }
        // A frame around the radio alone is provisional: the mesh has not
        // arrived yet, and latching now would strand the camera on one
        // antenna when it does. Only a frame that holds nodes is the one
        // the camera keeps.
        hasFramedNodes = !nodes.isEmpty
        camera = .region(region)
    }

    private func focus(on node: MapNode) {
        // Zoom to the cell, not to the street: a node that named a 10 km
        // square has not told us which building it is in.
        let span = max(node.cellMeters ?? 0, 400) * 4
        withAnimation(.spring(response: 0.4, dampingFraction: 0.9)) {
            camera = .region(
                MKCoordinateRegion(
                    center: node.coordinate,
                    latitudinalMeters: span,
                    longitudinalMeters: span
                )
            )
        }
        if cardDetent == .tall { cardDetent = .half }
    }

    /// A region holding every coordinate, with room around the edges so
    /// markers are not cut off by the frame they sit in.
    ///
    /// Longitude lives on a circle, so min/max is the wrong question: nodes
    /// at 179° and −179° are two degrees apart, not 358. The arc that holds
    /// everyone is the complement of the widest empty gap between them.
    private static func region(fitting coordinates: [CLLocationCoordinate2D])
        -> MKCoordinateRegion?
    {
        guard let first = coordinates.first else { return nil }
        var minLatitude = first.latitude
        var maxLatitude = first.latitude
        for coordinate in coordinates.dropFirst() {
            minLatitude = min(minLatitude, coordinate.latitude)
            maxLatitude = max(maxLatitude, coordinate.latitude)
        }

        let longitudes = coordinates.map(\.longitude).sorted()
        var gapStart = longitudes.last!
        var gapWidth = longitudes.first! + 360 - gapStart
        for (previous, next) in zip(longitudes, longitudes.dropFirst())
        where next - previous > gapWidth {
            gapStart = previous
            gapWidth = next - previous
        }
        let arcStart = gapStart + gapWidth
        let arcWidth = 360 - gapWidth
        var centerLongitude = arcStart + arcWidth / 2
        if centerLongitude > 180 { centerLongitude -= 360 }

        return MKCoordinateRegion(
            center: CLLocationCoordinate2D(
                latitude: (minLatitude + maxLatitude) / 2,
                longitude: centerLongitude
            ),
            span: MKCoordinateSpan(
                latitudeDelta: min(max((maxLatitude - minLatitude) * 1.4, 0.01), 180),
                longitudeDelta: min(max(arcWidth * 1.4, 0.01), 360)
            )
        )
    }
}
