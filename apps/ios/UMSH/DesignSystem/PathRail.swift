import SwiftUI

/// One node on a drawn path.
struct PathRailStop: Identifiable {
    enum Kind {
        /// The phone the path starts from, with the radio it sends through
        /// when that is worth saying.
        case phone(radioName: String?)
        /// A repeater known only by its router hint: the node it most
        /// plausibly names, if any, and the repeaters ahead of it in send
        /// order, which is the path an ask to identify it has to take.
        case repeater(MeshRouterHint, named: PeerSummary?, preceding: [MeshRouterHint])
        /// The node at the far end.
        case peer(PeerSummary)
    }

    let id: Int
    let kind: Kind
}

/// What lies between two stops.
enum PathRailLeg: Equatable {
    /// A plain stretch of rail.
    case plain
    /// The leg's place in the path, drawn on the rail: the Route screen's
    /// numbering.
    case numbered(Int)
    /// How the far node of the leg was heard.
    case reading(MeshLegSignal)
    /// Repeaters counted without being named, as a dashed stretch.
    case unnamed(count: Int)
    /// Nothing known yet: a dashed stretch.
    case pending
    /// Nothing came back: a dashed stretch broken by an X.
    case broken
}

/// A path drawn top to bottom, the phone first: one row per node, joined by
/// a rail, with what is known about each leg between them.
///
/// A repeater named by a guess opens that node's page; one that names no
/// known node offers to ask who it is.
struct PathRail: View {
    let stops: [PathRailStop]
    /// Exactly one fewer than `stops`.
    let legs: [PathRailLeg]
    /// The whole rail dashed: nothing is known about any of it yet.
    var isTentative = false
    /// Opens a named repeater's page. `nil` leaves those rows inert.
    var open: ((PeerSummary) -> Void)? = nil
    /// Asks the node behind a hint to identify itself, given the hint and the
    /// repeaters ahead of it. `nil` hides the control.
    var identifyRepeater: ((Data, [Data]) async -> Bool)? = nil

    static let columnWidth: CGFloat = IdentityRowSize.compact.avatarDiameter

    init(
        stops: [PathRailStop],
        legs: [PathRailLeg],
        isTentative: Bool = false,
        open: ((PeerSummary) -> Void)? = nil,
        identifyRepeater: ((Data, [Data]) async -> Bool)? = nil
    ) {
        precondition(legs.count == max(stops.count - 1, 0), "a leg between each pair of stops")
        self.stops = stops
        self.legs = legs
        self.isTentative = isTentative
        self.open = open
        self.identifyRepeater = identifyRepeater
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(stops.enumerated()), id: \.element.id) { index, stop in
                stopRow(stop, isFirst: index == 0, isLast: index == stops.count - 1)
                if index < legs.count {
                    PathRailLegView(leg: legs[index], isTentative: isTentative)
                }
            }
        }
    }

    @ViewBuilder
    private func stopRow(_ stop: PathRailStop, isFirst: Bool, isLast: Bool) -> some View {
        stopContent(stop)
            .padding(.vertical, 6)
            .background(alignment: .leading) {
                RailSegment(
                    top: !isFirst,
                    bottom: !isLast,
                    dashed: isTentative
                )
                .frame(width: Self.columnWidth)
            }
    }

    @ViewBuilder
    private func stopContent(_ stop: PathRailStop) -> some View {
        switch stop.kind {
        case let .phone(radioName):
            IdentityRowLayout {
                Image(systemName: "iphone.gen3")
                    .foregroundStyle(.secondary)
                    .frame(width: Self.columnWidth, height: Self.columnWidth)
                    .background(Circle().fill(Color(uiColor: .secondarySystemGroupedBackground)))
                    .overlay(Circle().strokeBorder(Color(uiColor: .separator), lineWidth: 1.5))
                    .accessibilityHidden(true)
            } title: {
                Text("This phone", comment: "The first node on a drawn path: the phone the user holds.")
            } subtitle: {
                if let radioName {
                    Text("Sent through \(radioName)", comment: "Under This phone on a path. The placeholder is the companion radio's name.")
                }
            } trailing: {
                EmptyView()
            }
        case let .repeater(hint, named, preceding):
            if let named, let open {
                Button {
                    open(named)
                } label: {
                    HStack {
                        RouterHintRow(hint: hint, named: named)
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            } else {
                RouterHintRow(
                    hint: hint,
                    named: named,
                    discover: identifyRepeater.map { identify in
                        { await identify(hint.bytes, preceding.map(\.bytes)) }
                    }
                )
            }
        case let .peer(peer):
            PeerRow(peer: peer, size: .compact)
        }
    }
}

/// The stretch of rail between two stops, and whatever is known about it.
private struct PathRailLegView: View {
    let leg: PathRailLeg
    let isTentative: Bool

    var body: some View {
        HStack(spacing: IdentityPresentation.rowSpacing) {
            marker
                .frame(width: PathRail.columnWidth)
                .frame(maxHeight: .infinity)
                .background {
                    RailSegment(top: true, bottom: true, dashed: isDashed)
                }
            caption
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minHeight: minHeight)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var isDashed: Bool {
        switch leg {
        case .unnamed, .pending, .broken: true
        case .plain, .numbered, .reading: isTentative
        }
    }

    private var minHeight: CGFloat {
        switch leg {
        case .plain: 10
        case .numbered: 24
        case .reading, .unnamed: 26
        case .pending, .broken: 40
        }
    }

    @ViewBuilder
    private var marker: some View {
        switch leg {
        case let .numbered(number):
            Text(number.formatted())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 20, height: 20)
                .background(Circle().fill(Color(uiColor: .secondarySystemGroupedBackground)))
                .overlay(Circle().strokeBorder(Color(uiColor: .separator), lineWidth: 1.5))
                .accessibilityHidden(true)
        case .broken:
            Image(systemName: "xmark")
                .font(.body.weight(.bold))
                .foregroundStyle(.red)
                .frame(width: 24, height: 24)
                .background(Circle().fill(Color(uiColor: .secondarySystemGroupedBackground)))
                .accessibilityLabel(Text("No path", comment: "VoiceOver label for the X on a ping that got no reply."))
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var caption: some View {
        switch leg {
        case let .reading(signal):
            if let text = SignalPresentation.readingText(
                rssiDBm: signal.rssiDBm,
                snrCentibels: signal.signalToNoiseCentibels
            ) {
                HStack(spacing: 6) {
                    if let bars = SignalPresentation.bars(
                        rssiDBm: signal.rssiDBm,
                        snrDecibels: signal.signalToNoiseCentibels.map(SignalPresentation.decibels(centibels:))
                    ) {
                        Image(systemName: "cellularbars", variableValue: Double(bars) / 4)
                            .foregroundStyle(.green)
                            .accessibilityHidden(true)
                    }
                    Text(verbatim: text)
                }
            } else {
                // A leg with no reading crossed a link that is not radio: a
                // bridge's backhaul.
                Text("Bridged", comment: "A path leg that crossed a non-radio link, so it has no signal reading.")
            }
        case let .unnamed(count):
            Text(verbatim: RoutePresentation.unnamedRepeatersText(count))
        default:
            EmptyView()
        }
    }
}

/// The rail through one row's avatar column: above the avatar, below it, or
/// both. The avatar is drawn over it.
private struct RailSegment: View {
    let top: Bool
    let bottom: Bool
    let dashed: Bool

    var body: some View {
        Canvas { context, size in
            let x = size.width / 2
            var path = Path()
            path.move(to: CGPoint(x: x, y: top ? 0 : size.height / 2))
            path.addLine(to: CGPoint(x: x, y: bottom ? size.height : size.height / 2))
            context.stroke(
                path,
                with: .color(Color(uiColor: .separator)),
                style: StrokeStyle(lineWidth: 2, lineCap: .butt, dash: dashed ? [3, 5] : [])
            )
        }
        .accessibilityHidden(true)
    }
}
