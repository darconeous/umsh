import CoreLocation
import SwiftUI

/// What the card over the map holds: the same nodes the map is drawing, in
/// the order they are nearest.
struct MapNodeListCard: View {
    let nodes: [MapNode]
    @Binding var selectedNodeID: MapNodeID?
    let selfPosition: MapSelfPosition?
    /// Whether any node at all reported a location, regardless of filters—
    /// the difference between an empty mesh and an empty filter.
    let hasAnyLocations: Bool
    let isFiltered: Bool
    var isLoading = false
    let clearFilters: () -> Void
    let discoverPeers: () -> Void
    let openPeersList: () -> Void

    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    var peerActions: PeerActions = .unavailable
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    var messageActions: ChatMessageActions = .unavailable

    /// The row's own tap belongs to the map—it selects and focuses, which
    /// is what a list beside a map is for. Details are a press or a swipe
    /// away rather than a control in the row, so nothing competes with the
    /// distance for the trailing edge.
    @State private var nodePendingDetail: PeerSummary?

    var body: some View {
        Group {
            if nodes.isEmpty {
                emptyState
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                // The minute tick is what keeps "51m ago" true: nothing else
                // re-renders a quiet mesh, and a relative time composed once
                // is frozen at whenever the last advertisement landed. The
                // timeline pauses off screen, so other tabs pay nothing.
                TimelineView(.everyMinute) { context in
                    ScrollViewReader { scroll in
                        List(orderedNodes) { node in
                            row(node, now: context.date)
                                .id(node.id)
                                .listRowBackground(
                                    node.id == selectedNodeID
                                        ? Color.accentColor.opacity(0.12)
                                        : Color.clear
                                )
                        }
                        .listStyle(.plain)
                        .scrollContentBackground(.hidden)
                        .onChange(of: selectedNodeID) { _, selected in
                            guard let selected else { return }
                            withAnimation { scroll.scrollTo(selected, anchor: .top) }
                        }
                    }
                }
            }
        }
        .navigationDestination(item: $nodePendingDetail) { peer in
            PeerDetailView(
                peer: peer,
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                actions: peerActions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions
            )
        }
    }

    /// Nearest first, since the distance is what the row leads with—and by
    /// name when there is nothing to measure from, which at least does not
    /// reorder itself as nodes are heard.
    private var orderedNodes: [MapNode] {
        guard let selfPosition else {
            return nodes.sorted {
                $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
                    == .orderedAscending
            }
        }
        return nodes
            .map { ($0, $0.distance(from: selfPosition.coordinate)) }
            .sorted { $0.1 < $1.1 }
            .map(\.0)
    }

    // MARK: - Rows

    private func row(_ node: MapNode, now: Date) -> some View {
        HStack(spacing: 12) {
            PeerAvatar(
                hint: node.hint,
                diameter: 40,
                showsFavoriteStar: node.isFavorite
            )
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(node.displayName)
                        .lineLimit(1)
                    if !node.isAttributable {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("Location unverified")
                    } else if node.isReported {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Position reported by a router")
                    }
                }
                if let subtitle = subtitle(node, now: now) {
                    Text(subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if let distance = distanceText(node) {
                Text(distance)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .contentShape(.rect)
        .onTapGesture { selectedNodeID = node.id }
        // The tap belongs to the map—select and focus—so the deeper
        // commitment gets the longer gesture, as a menu rather than a bare
        // `onLongPressGesture`. The recognizer navigates on its own but draws
        // nothing: no lift, no blur, no haptic, so a press that has not yet
        // fired is indistinguishable from a row that ignores presses. The
        // menu is the system's own press treatment, and it is the same one
        // the coordinate readouts elsewhere in the app already use.
        .coordinateActions(
            latitude: node.latitude,
            longitude: node.longitude,
            fractionDigits: LocationPresentation.coordinateDecimals(cellMeters: node.cellMeters),
            pinName: node.displayName
        ) {
            // A neighbor known only by a hint has no page: a hint is not a
            // key to address, and there is nothing behind it to show.
            if let peer = node.peer {
                Button("Details", systemImage: "info.circle") {
                    nodePendingDetail = peer
                }
            }
        }
        // The tap gesture confers nothing on VoiceOver: without the trait
        // the row reads as static text, and Details would exist only in a
        // menu and a swipe nobody is told about.
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { selectedNodeID = node.id }
        .modifier(NodeDetailsAffordances(peer: node.peer) { nodePendingDetail = $0 })
    }

    /// How far off the node claims to be, from wherever we are.
    ///
    /// `nil` when there is nothing to measure from—no companion radio, or
    /// one that has yet to get a fix. A dash would imply zero.
    private func distanceText(_ node: MapNode) -> String? {
        guard let selfPosition else { return nil }
        return LocationPresentation.distanceText(
            meters: node.distance(from: selfPosition.coordinate)
        )
    }

    /// One age—when the node was last on the air—and a second only when
    /// it earns its place: a location claim that predates the last contact
    /// by more than four hours means a node that is reachable but may no
    /// longer be where it said. Two agreeing ages would say the same thing
    /// twice, and a row that was only ever imported has no honest age at
    /// all: the bundle's own timestamp is not when it was added, and nothing
    /// records that.
    ///
    /// `now` is the enclosing timeline's tick—and the reason this is a
    /// `RelativeDateTimeFormatter` rather than the `.relative` format style
    /// used elsewhere in the app: only the formatter takes a reference date.
    private func subtitle(_ node: MapNode, now: Date) -> String? {
        if let reporter = node.reportedBy {
            // Second-hand: who said so, and when they last heard the node.
            var parts = ["Reported by \(reporter.displayName)"]
            if let heard = node.lastHeard {
                parts.append("heard \(Self.ageText(heard, now: now))")
            }
            return parts.joined(separator: " · ")
        }
        guard let heard = node.lastHeard else { return nil }
        let heardText = "Heard \(Self.ageText(heard, now: now))"
        if let reported = node.reportedAt,
           heard.timeIntervalSince(reported) > 4 * 3_600
        {
            return "\(heardText) · location from \(Self.ageText(reported, now: now))"
        }
        return heardText
    }

    /// Floored at the refresh tick: the row updates once a minute, and a
    /// reading in seconds would sit frozen on screen claiming a precision
    /// the refresh cannot honor.
    private static func ageText(_ date: Date, now: Date) -> String {
        if now.timeIntervalSince(date) < 60 { return "just now" }
        return relative.localizedString(for: date, relativeTo: now)
    }

    private static let relative: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    // MARK: - Empty states

    @ViewBuilder
    private var emptyState: some View {
        if isLoading, !hasAnyLocations {
            ContentUnavailableView {
                ProgressView()
                    .accessibilityLabel("Loading nodes")
            } description: {
                Text("Loading nodes…")
            }
        } else if hasAnyLocations, isFiltered {
            ContentUnavailableView {
                Label("No nodes match", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text("Nodes have reported locations, but none of them pass the current filters.")
            } actions: {
                Button("Clear filters", action: clearFilters)
                    .buttonStyle(.borderedProminent)
            }
        } else {
            ContentUnavailableView {
                Label("No reported locations", systemImage: "map")
            } description: {
                Text(
                    "Locations reported by observed nodes will appear here with their precision and age."
                )
            } actions: {
                Button("Discover peers", action: discoverPeers)
                    .buttonStyle(.borderedProminent)
                Button("Show list", action: openPeersList)
            }
        }
    }
}

/// The swipe and the VoiceOver action that open a node's page, present only
/// when there is a page: a reported neighbor this phone does not know has
/// none. A modifier rather than two conditionals in the row, so the row's
/// view identity does not change with what it is showing.
private struct NodeDetailsAffordances: ViewModifier {
    let peer: PeerSummary?
    let open: (PeerSummary) -> Void

    func body(content: Content) -> some View {
        if let peer {
            content
                .accessibilityAction(named: "Details") { open(peer) }
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    Button {
                        open(peer)
                    } label: {
                        Label("Details", systemImage: "info.circle")
                    }
                    .tint(.blue)
                }
        } else {
            content
        }
    }
}
