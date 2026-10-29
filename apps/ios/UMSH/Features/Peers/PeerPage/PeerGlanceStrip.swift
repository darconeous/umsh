import CoreLocation
import SwiftUI

extension EnvironmentValues {
    /// Where this phone is, read only when location access was already
    /// granted. Nil, or a nil answer, where it was not: a page that merely
    /// shows a distance never asks for permission.
    @Entry var readPhonePositionIfAuthorized: (@MainActor () async -> CLLocation?)? = nil
}

/// How far a node is and which way, from the best reference at hand.
struct PeerDistance: Equatable {
    let text: String
    let bearingDegrees: Double

    /// The distance between a reference point and a node's reported cell,
    /// honest about both cells' size.
    init(
        from reference: (latitude: Double, longitude: Double, cellMeters: Double?),
        to identity: MeshNodeIdentity
    ) {
        let latitude = identity.latitude ?? 0
        let longitude = identity.longitude ?? 0
        text = LocationPresentation.separationText(
            centerMeters: LocationPresentation.distanceMeters(
                fromLatitude: reference.latitude,
                longitude: reference.longitude,
                toLatitude: latitude,
                longitude: longitude
            ),
            cellMeters: reference.cellMeters,
            otherCellMeters: identity.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
        )
        bearingDegrees = LocationPresentation.bearingDegrees(
            fromLatitude: reference.latitude,
            longitude: reference.longitude,
            toLatitude: latitude,
            longitude: longitude
        )
    }
}

/// The three facts people check about a node, side by side: when it was
/// last heard, how it is reached, and how far away it is.
///
/// Unknown values show a dash, so the strip keeps its shape.
struct PeerGlanceStrip: View {
    let lastHeard: Date?
    let routeText: String
    let distance: PeerDistance?
    let openRoute: (() -> Void)?

    var body: some View {
        HStack(spacing: 0) {
            cell(title: LocalizedStringResource("Heard", comment: "Strip label: when the node was last heard. Keep short.")) {
                if let lastHeard {
                    AgeText(since: lastHeard)
                } else {
                    dash
                }
            }
            .accessibilityIdentifier("peer.strip.heard")
            Divider().padding(.vertical, 12)
            Button {
                openRoute?()
            } label: {
                cell(title: LocalizedStringResource("Route", comment: "Strip label: how this phone reaches the node. A noun. Keep short.")) {
                    HStack(spacing: 4) {
                        Text(verbatim: routeText)
                        Spacer(minLength: 0)
                        if openRoute != nil {
                            Image(systemName: "chevron.forward")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                                .accessibilityHidden(true)
                        }
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(openRoute == nil)
            .accessibilityIdentifier("peer.strip.route")
            Divider().padding(.vertical, 12)
            cell(title: LocalizedStringResource("Distance", comment: "Strip label: how far away the node is. Keep short.")) {
                if let distance {
                    HStack(spacing: 6) {
                        Text(verbatim: distance.text)
                        // North-up: the arrow points along the bearing on a
                        // map, so it rotates from a symbol that never mirrors.
                        Image(systemName: "location.north.fill")
                            .font(.caption)
                            .foregroundStyle(.tint)
                            .rotationEffect(.degrees(distance.bearingDegrees))
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(
                        Text(
                            "\(distance.text), \(LocationPresentation.compassText(degrees: distance.bearingDegrees))",
                            comment: "VoiceOver: a distance, then which way it lies, such as 4.2 km, northeast."
                        )
                    )
                } else {
                    dash
                }
            }
            .accessibilityIdentifier("peer.strip.distance")
        }
        .fixedSize(horizontal: false, vertical: true)
        .background(
            Color(uiColor: .secondarySystemGroupedBackground),
            in: RoundedRectangle(cornerRadius: 12, style: .continuous)
        )
    }

    private var dash: some View {
        Text(verbatim: "—").foregroundStyle(.tertiary)
    }

    private func cell<Value: View>(
        title: LocalizedStringResource,
        @ViewBuilder value: () -> Value
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption2.weight(.semibold))
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            value()
                .font(.headline)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
    }
}
