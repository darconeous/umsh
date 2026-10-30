import SwiftUI

/// How this phone reaches a node: the path the next frame takes, when that
/// path last carried an acknowledgment, and the controls that change it.
///
/// Edit turns the same list into the manual path editor, in place.
struct RouteScreen: View {
    let peer: PeerSummary
    let actions: PeerActions
    let radioName: String?
    let browsing: RemotePeerBrowsing
    /// The route moved: reset, cleared, or held by hand.
    let onRouteChanged: () -> Void

    @State private var route: PeerRoute?
    @State private var draft: ManualPathDraft?
    @State private var isResetting = false
    @State private var isClearing = false
    @State private var openedPeer: PeerSummary?
    @Environment(\.askNearbyIdentities) private var askNearbyIdentities
    @Environment(\.showTransientNotice) private var showTransientNotice

    var body: some View {
        List {
            if let draft {
                ManualPathEditSections(draft: draft, peer: peer, actions: actions, radioName: radioName)
            } else if let route {
                pathSection(route)
                detailsSection(route)
                controlsSection(route)
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
            }
        }
        .environment(\.editMode, .constant(draft == nil ? .inactive : .active))
        .navigationTitle(Text("Route", comment: "Title of the screen showing how this phone reaches a node. A noun."))
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(draft != nil)
        .toolbar { toolbar }
        .navigationDestination(item: $openedPeer) { peer in
            browsing.open(peer)
        }
        .task(id: peer.lastHeard) { await loadRoute() }
        .transientNoticePresenter()
    }

    // MARK: Viewing

    private func pathSection(_ route: PeerRoute) -> some View {
        let stops = [PathRailStop(id: 0, kind: .phone(radioName: radioName))]
            + route.hints.enumerated().map { index, hint in
                PathRailStop(
                    id: index + 1,
                    kind: .repeater(
                        hint,
                        named: RouterHintNaming.match(hint, among: actions.knownPeers),
                        preceding: Array(route.hints.prefix(index))
                    )
                )
            }
            + [PathRailStop(id: route.hints.count + 1, kind: .peer(peer))]
        return Section {
            PathRail(
                stops: stops,
                legs: Self.legs(for: route),
                isTentative: route.kind == .unknown || route.kind == .unavailable,
                open: { openedPeer = $0 },
                identifyRepeater: actions.identifyRepeater
            )
            .accessibilityIdentifier("route.path")
        } header: {
            HStack {
                Text("Path", comment: "Section header: the repeaters a route goes through.")
                Spacer()
                if let hops = route.hopCount, !route.isDirect {
                    Text(verbatim: RoutePresentation.hopsText(Int(hops)))
                }
            }
        } footer: {
            if route.hints.contains(where: { RouterHintNaming.match($0, among: actions.knownPeers) != nil }) {
                Text(RouterHintNaming.ambiguityNote)
            }
        }
    }

    /// The legs of a cached route, numbered in send order. A flood names no
    /// repeaters, so its one leg is a dashed stretch for the hops it spent.
    nonisolated static func legs(for route: PeerRoute) -> [PathRailLeg] {
        switch route.kind {
        case .unknown, .unavailable:
            return [.pending]
        case .flood where route.hints.isEmpty:
            if let flood = route.floodHops, flood > 0 {
                return [.unnamed(count: Int(flood))]
            }
            return [.pending]
        default:
            return (0...route.hints.count).map { .numbered($0 + 1) }
        }
    }

    private func detailsSection(_ route: PeerRoute) -> some View {
        Section {
            LabeledContent {
                Text(verbatim: RoutePresentation.kindText(route))
            } label: {
                Text("Next send", comment: "Row label: how the next frame to this node is routed.")
            }
            .accessibilityIdentifier("route.nextSend")
            if route.kind != .unavailable {
                LabeledContent {
                    if let lastAcknowledged = route.lastAcknowledged {
                        AgeText(since: lastAcknowledged)
                    } else {
                        Text(verbatim: "—")
                    }
                } label: {
                    Text("Confirmed", comment: "Row label: when this route last carried an acknowledgment.")
                }
                .accessibilityIdentifier("route.confirmed")
            }
            if !route.floodRegions.isEmpty {
                LabeledContent {
                    Text(verbatim: route.floodRegions.map(RegionCodeText.label).formatted(.list(type: .and, width: .narrow)))
                        .multilineTextAlignment(.trailing)
                } label: {
                    Text("Regions", comment: "Row label: the regions a flood route was learned in.")
                }
            }
            if let holdUntil = route.holdUntil {
                if !route.hints.isEmpty, let floodHops = route.heldFloodHops {
                    LabeledContent {
                        Text(verbatim: RoutePresentation.floodText(floodHops))
                    } label: {
                        Text("Then flood", comment: "Row label: how far a manual path floods past its last repeater.")
                    }
                }
                LabeledContent {
                    Text(holdUntil, format: .dateTime.hour().minute())
                } label: {
                    Text("Held until", comment: "Row label: when a manual path's hold ends.")
                }
            }
        }
    }

    @ViewBuilder
    private func controlsSection(_ route: PeerRoute) -> some View {
        let offersAsk = askNearbyIdentities != nil
        let offersReset = actions.resetRoute != nil && !route.isHeld
        let offersClear = actions.clearManualPath != nil && route.isHeld
        if offersAsk || offersReset || offersClear {
            Section {
                if let askNearbyIdentities {
                    let vantage = SolicitVantage(peer: peer, route: route)
                    Button {
                        askNearbyIdentities(vantage)
                    } label: {
                        Label {
                            Text("Ask Near This Node", comment: "Button: discover the nodes in range of this one.")
                        } icon: {
                            Image(systemName: "wave.3.right")
                        }
                    }
                    .disabled(vantage == nil)
                    .accessibilityIdentifier("route.askNear")
                }
                if offersClear {
                    Button(role: .destructive) {
                        Task { await clearManualPath() }
                    } label: {
                        Label {
                            Text("Clear Manual Path", comment: "Button: drop a hand-chosen path.")
                        } icon: {
                            Image(systemName: "xmark.circle")
                        }
                    }
                    .disabled(isClearing)
                    .accessibilityIdentifier("route.clearManual")
                } else if offersReset {
                    Button(role: .destructive) {
                        Task { await resetRoute() }
                    } label: {
                        Label {
                            Text("Reset Route", comment: "Button: forget the learned route to this node.")
                        } icon: {
                            Image(systemName: "arrow.counterclockwise")
                        }
                    }
                    .disabled(isResetting || route.kind == .unknown || route.kind == .unavailable)
                    .accessibilityIdentifier("route.reset")
                }
            }
        }
    }

    // MARK: Editing

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if let draft {
            ToolbarItem(placement: .cancellationAction) {
                Button {
                    self.draft = nil
                } label: {
                    Text("Cancel", comment: "Leaves editing without saving.")
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                if draft.isSaving {
                    ProgressView()
                } else {
                    Button {
                        Task { await save(draft) }
                    } label: {
                        Text("Save", comment: "Saves an edit.")
                    }
                    .accessibilityIdentifier("route.edit.save")
                }
            }
        } else if actions.setManualPath != nil, let route, route.kind != .unavailable {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    draft = ManualPathDraft(route: route)
                } label: {
                    Text("Edit", comment: "Starts editing the route by hand.")
                }
                .accessibilityIdentifier("route.edit")
            }
        }
    }

    private func save(_ draft: ManualPathDraft) async {
        guard await draft.save(peer, actions: actions) else { return }
        self.draft = nil
        await loadRoute()
        onRouteChanged()
    }

    // MARK: Actions

    private func loadRoute() async {
        guard let loadRoute = actions.loadRoute else {
            route = .unavailable
            return
        }
        route = await loadRoute(peer)
    }

    private func resetRoute() async {
        guard let resetRoute = actions.resetRoute, !isResetting else { return }
        isResetting = true
        defer { isResetting = false }
        let hadRoute = await resetRoute(peer)
        await loadRoute()
        onRouteChanged()
        if !hadRoute {
            showTransientNotice(LocalizedStringResource("No route to reset", comment: "Brief notice when there was no learned route."))
        }
    }

    private func clearManualPath() async {
        guard let clearManualPath = actions.clearManualPath, !isClearing else { return }
        isClearing = true
        defer { isClearing = false }
        _ = await clearManualPath(peer)
        await loadRoute()
        onRouteChanged()
    }
}
