import SwiftUI

/// One ping sent from a peer page, and how it ended.
struct PingRecord: Identifiable, Equatable {
    let id = UUID()
    let sentAt: Date
    let result: PeerPingResult
}

/// The path a ping reply drew, as a rail: the stops it names and what is
/// known about each leg between them.
struct PingPath: Equatable {
    let stops: [Stop]
    let legs: [PathRailLeg]

    enum Stop: Equatable {
        case phone
        case repeater(MeshRouterHint, preceding: [MeshRouterHint])
        case peer
    }

    /// Lay out a reply.
    ///
    /// The reply's repeaters run nearest this phone first. The leg from the
    /// phone to the first of them is the phone's own reading of the reply;
    /// every leg after that is how the repeater at its near end heard the
    /// node at its far end, entry for entry. A reading with neither figure
    /// crossed a link that is not radio and is drawn as bridged.
    ///
    /// A flooded reply counts the repeaters it crossed without naming them;
    /// the uncounted ones are drawn as one dashed stretch before the peer,
    /// rather than letting them read as a direct link.
    init(reply: PeerPingReply) {
        let hints = reply.routeHints
        var stops: [Stop] = [.phone]
        for (index, hint) in hints.enumerated() {
            stops.append(.repeater(hint, preceding: Array(hints.prefix(index))))
        }
        stops.append(.peer)

        let own = MeshLegSignal(rssiDBm: reply.rssiDBm, signalToNoiseCentibels: reply.signalToNoiseCentibels)
        var legs: [PathRailLeg] = [own.rssiDBm == nil && own.signalToNoiseCentibels == nil ? .plain : .reading(own)]
        for index in hints.indices {
            legs.append(index < reply.traceSignal.count ? .reading(reply.traceSignal[index]) : .plain)
        }
        let unnamed = reply.hopCount.map { Int($0) - 1 - hints.count } ?? 0
        if unnamed > 0 {
            legs[legs.count - 1] = .unnamed(count: unnamed)
        }
        self.stops = stops
        self.legs = legs
    }

    /// Before an answer, or without one: the phone and the peer, and a
    /// dashed leg between them.
    init(unanswered broken: Bool) {
        stops = [.phone, .peer]
        legs = [broken ? .broken : .pending]
    }
}

/// Ping a node and show what came back, the way the communicator does: a
/// sheet that sends on open, then the round trip, the path the reply took,
/// and how each leg of it was heard.
struct PingSheet: View {
    let peer: PeerSummary
    let actions: PeerActions
    let radioName: String?
    /// This visit's pings, newest first. Owned by the page, so closing and
    /// reopening the sheet keeps them.
    @Binding var history: [PingRecord]
    let browsing: RemotePeerBrowsing
    /// The route may have moved: a reply teaches one, a reset drops it.
    let onRouteChanged: () -> Void

    /// When the ping being waited on was sent.
    @State private var outstanding: Date?
    /// Names the ping being waited on. A newer ping cancels it, and the
    /// answer the canceled one gets back is then not this sheet's to show.
    @State private var waitID: UUID?
    /// Whether the wait has gone on long enough to offer pinging again.
    @State private var isWaitingLong = false
    @State private var latest: PingRecord?
    @State private var isResetting = false
    @State private var openedPeer: PeerSummary?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.showTransientNotice) private var showTransientNotice

    var body: some View {
        NavigationStack {
            List {
                Section {
                    resultCard
                        .cardListRow()
                    Button {
                        Task { await send() }
                    } label: {
                        Text("Ping Again", comment: "Button: send another ping.")
                            .font(.headline)
                            .frame(maxWidth: .infinity, minHeight: 34)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(actions.ping == nil || (outstanding != nil && !isWaitingLong))
                    .accessibilityIdentifier("ping.again")
                    .cardListRow()
                }
                Section {
                    PathRail(
                        stops: path.stops.enumerated().map { PathRailStop(id: $0.offset, kind: railKind($0.element)) },
                        legs: path.legs,
                        isTentative: latestReply == nil,
                        open: { openedPeer = $0 },
                        identifyRepeater: actions.identifyRepeater
                    )
                    .accessibilityIdentifier("ping.path")
                } header: {
                    if latestReply != nil {
                        Text("Reply Path", comment: "Section header: the route a ping reply took.")
                    }
                } footer: {
                    if let reply = latestReply, hasGuessedNames(reply) {
                        Text(RouterHintNaming.ambiguityNote)
                    }
                }
                if actions.resetRoute != nil {
                    Section {
                        Button(role: .destructive) {
                            Task { await resetRoute() }
                        } label: {
                            Label {
                                Text("Reset Route", comment: "Button: forget the learned route to this node.")
                            } icon: {
                                Image(systemName: "arrow.counterclockwise")
                            }
                        }
                        .disabled(isResetting)
                        .accessibilityIdentifier("ping.resetRoute")
                    }
                }
                if !earlier.isEmpty {
                    Section {
                        ForEach(earlier) { record in
                            LabeledContent {
                                AgeText(since: record.sentAt)
                            } label: {
                                earlierLabel(record.result)
                            }
                        }
                    } header: {
                        Text("Earlier", comment: "Section header: pings sent before the one shown.")
                    }
                }
            }
            .navigationTitle(Text("Ping", comment: "Title of the ping sheet. A noun."))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Text("Done", comment: "Closes a sheet.")
                    }
                }
            }
            .navigationDestination(item: $openedPeer) { peer in
                browsing.open(peer)
            }
        }
        .transientNoticePresenter()
        .task { await send() }
        .task(id: waitID) {
            // A reply over a short path is back well before this; past it,
            // the ping may have been lost, and a new one is worth offering
            // even though a long flood's reply could still be coming.
            isWaitingLong = false
            guard waitID != nil else { return }
            try? await Task.sleep(for: Self.sendAgainAfter)
            if !Task.isCancelled { isWaitingLong = true }
        }
    }

    /// How long a ping waits before a new one, replacing it, is offered.
    static let sendAgainAfter: Duration = .seconds(8)

    // MARK: Result

    @ViewBuilder
    private var resultCard: some View {
        HStack(spacing: 12) {
            if let outstanding {
                ProgressView()
                    .controlSize(.large)
                TimelineView(.periodic(from: outstanding, by: 0.1)) { context in
                    Text(verbatim: Self.secondsText(context.date.timeIntervalSince(outstanding)))
                        .font(.largeTitle.bold().monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer()
            } else if let latest {
                switch latest.result {
                case let .reply(reply):
                    Image(systemName: "checkmark.circle.fill")
                        .font(.title)
                        .foregroundStyle(.green)
                    Text(verbatim: Self.secondsText(Double(reply.roundTripMilliseconds) / 1_000))
                        .font(.largeTitle.bold().monospacedDigit())
                    Spacer()
                    if let hops = RoutePresentation.replyHopsText(reply.hopCount) {
                        Text(verbatim: hops)
                            .font(.title3)
                            .foregroundStyle(.secondary)
                    }
                case .canceled:
                    EmptyView()
                case .timedOut:
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.title)
                        .foregroundStyle(.orange)
                    Text("No reply", comment: "Ping result: nothing came back.")
                        .font(.title.bold())
                        .foregroundStyle(.orange)
                    Spacer()
                case let .unavailable(reason):
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title)
                        .foregroundStyle(.red)
                    Text(verbatim: reason)
                        .font(.headline)
                    Spacer()
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 72, alignment: .leading)
        .background(
            Color(uiColor: .secondarySystemGroupedBackground),
            in: RoundedRectangle(cornerRadius: 12, style: .continuous)
        )
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("ping.result")
    }

    private func earlierLabel(_ result: PeerPingResult) -> some View {
        Group {
            switch result {
            case let .reply(reply):
                let time = Self.secondsText(Double(reply.roundTripMilliseconds) / 1_000)
                if let hops = RoutePresentation.replyHopsText(reply.hopCount) {
                    Text("\(time) · \(hops)", comment: "An earlier ping: its round trip, then how many hops it took.")
                } else {
                    Text(verbatim: time)
                }
            case .timedOut:
                Text("No reply", comment: "Ping result: nothing came back.")
                    .foregroundStyle(.orange)
            case .canceled:
                EmptyView()
            case let .unavailable(reason):
                Text(verbatim: reason)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// A round trip: "1.4 sec".
    static func secondsText(_ seconds: Double, locale: Locale = .current) -> String {
        Measurement(value: max(seconds, 0), unit: UnitDuration.seconds).formatted(
            .measurement(width: .abbreviated, numberFormatStyle: .number.precision(.fractionLength(1)))
            .locale(locale)
        )
    }

    // MARK: Path

    private var latestReply: PeerPingReply? {
        guard outstanding == nil, case let .reply(reply) = latest?.result else { return nil }
        return reply
    }

    private var path: PingPath {
        if outstanding != nil { return PingPath(unanswered: false) }
        switch latest?.result {
        case let .reply(reply): return PingPath(reply: reply)
        case .timedOut: return PingPath(unanswered: true)
        case .canceled, .unavailable, nil: return PingPath(unanswered: false)
        }
    }

    private func railKind(_ stop: PingPath.Stop) -> PathRailStop.Kind {
        switch stop {
        case .phone:
            .phone(radioName: nil)
        case let .repeater(hint, preceding):
            .repeater(hint, named: RouterHintNaming.match(hint, among: actions.knownPeers), preceding: preceding)
        case .peer:
            .peer(peer)
        }
    }

    private func hasGuessedNames(_ reply: PeerPingReply) -> Bool {
        reply.routeHints.contains { RouterHintNaming.match($0, among: actions.knownPeers) != nil }
    }

    /// Everything before the result on show.
    private var earlier: [PingRecord] {
        history.filter { $0.id != latest?.id || outstanding != nil }
    }

    // MARK: Actions

    /// Send a ping and wait for its answer. A ping still waiting is
    /// canceled by the new one, and its timer starts over.
    private func send() async {
        guard let ping = actions.ping else { return }
        let id = UUID()
        let sentAt = Date.now
        waitID = id
        outstanding = sentAt
        let result = await ping(peer)
        // Replaced by a newer ping, whose wait is the one on show.
        guard waitID == id else { return }
        let record = PingRecord(sentAt: sentAt, result: result)
        history.insert(record, at: 0)
        latest = record
        outstanding = nil
        waitID = nil
        // A reply is exactly what teaches the MAC a route.
        if case .reply = result { onRouteChanged() }
    }

    private func resetRoute() async {
        guard let resetRoute = actions.resetRoute, !isResetting else { return }
        isResetting = true
        defer { isResetting = false }
        let hadRoute = await resetRoute(peer)
        onRouteChanged()
        showTransientNotice(
            hadRoute
                ? LocalizedStringResource("Route reset", comment: "Brief notice after the learned route was forgotten.")
                : LocalizedStringResource("No route to reset", comment: "Brief notice when there was no learned route.")
        )
    }
}

