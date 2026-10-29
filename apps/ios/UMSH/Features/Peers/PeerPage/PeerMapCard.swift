import MapKit
import SwiftUI

extension EnvironmentValues {
    /// Switch to the Map tab with this node selected. Nil where nothing
    /// above can show the map, and the card is then just a picture.
    @Entry var showOnMap: (@MainActor (PeerSummary) -> Void)? = nil
}

/// Where a node says it is: a small map of its reported cell, and when and
/// how precisely it said so. Tapping it opens the Map tab on the node.
///
/// The node is drawn by the Map tab's own code, so it looks the same here as
/// it does there.
struct PeerMapCard: View {
    let node: MapNode
    /// When this phone heard the location. `nil` for an imported bundle.
    let reportedAt: Date?
    let open: (() -> Void)?

    private var cellMeters: Double? { node.cellMeters }

    var body: some View {
        Button {
            open?()
        } label: {
            VStack(spacing: 0) {
                Map(initialPosition: .region(region), interactionModes: []) {
                    MapNodeContent(node: node, drawsCell: true)
                }
                .frame(height: 150)
                .allowsHitTesting(false)
                .accessibilityHidden(true)
                HStack {
                    if let caption {
                        Text(verbatim: caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if open != nil {
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(Color(uiColor: .secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(open == nil)
        .accessibilityLabel(Text("Show on Map", comment: "VoiceOver label for the map card on a peer page."))
        .accessibilityValue(Text(verbatim: caption ?? ""))
        .accessibilityIdentifier("peer.map")
    }

    /// Wide enough to show the cell with room around it, and never so tight
    /// that a precise fix shows nothing but one street.
    private var region: MKCoordinateRegion {
        let span = max((cellMeters ?? 0) * 3, 2_000)
        return MKCoordinateRegion(center: node.coordinate, latitudinalMeters: span, longitudinalMeters: span)
    }

    /// "3:42 PM · within 150 m": when the location was heard, and how
    /// large the cell it names is.
    private var caption: String? {
        let time = reportedAt.map { date in
            Calendar.current.isDateInToday(date)
                ? date.formatted(date: .omitted, time: .shortened)
                : date.formatted(.dateTime.month(.abbreviated).day().hour().minute())
        }
        let size = cellMeters.map { LocationPresentation.cellSizeText(meters: $0) }
        switch (time, size) {
        case let (time?, size?):
            return String(
                localized: "\(time) · within \(size)",
                comment: "Under a peer's map: when the location was heard, then the size of the area it names."
            )
        case let (nil, size?):
            return String(
                localized: "Within \(size)",
                comment: "Under a peer's map: the size of the area the location names."
            )
        case let (time?, nil):
            return time
        case (nil, nil):
            return nil
        }
    }
}
