import SwiftUI

struct AdvertisedIdentitySection: View {
    let identity: MeshNodeIdentity
    let isAttributable: Bool

    var body: some View {
        Section {
            AdvertisedIdentityRows(identity: identity)
        } header: {
            Text("Advertised identity")
        } footer: {
            // Identity replies can be authenticated by their enclosing unicast
            // without carrying a signature of their own.
            Text(isAttributable
                 ? "These details are claims made by the peer. Nothing here is independently verified."
                 : "These details are unsigned, so they may not have come from the peer at all. Nothing here is independently verified.")
        }
    }
}

/// A signature notice for an advertised identity, shown only when the
/// signature does not verify.
///
/// A good signature deliberately renders nothing. It proves only that the
/// keypair which *is* this address asserted these claims about itself, which
/// is no evidence the claims are true—a node can sign a fabricated name or
/// location as easily as a real one. A "verified" badge invites far more
/// trust than that supports, so the affirmative case stays silent and only a
/// failure, which is genuinely decision-relevant at import time, speaks up.
struct AdvertisedIdentityWarning: View {
    let identity: MeshNodeIdentity

    var body: some View {
        switch identity.signature {
        case .valid:
            EmptyView()
        case .unsigned:
            Label(
                "These details carry no signature, so they may not have come from this node at all.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        case .invalid:
            Label(
                "The signature on these details does not verify. Do not rely on them.",
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.caption)
            .foregroundStyle(.red)
        }
    }
}

/// Rows describing a decoded advertised node identity: the peer's own claims
/// about itself, none of them independently verified. Shared by the peer
/// sheet and the import preview.
struct AdvertisedIdentityRows: View {
    let identity: MeshNodeIdentity

    var body: some View {
        if let name = identity.name {
            LabeledContent("Name", value: name)
        }
        LabeledContent("Role", value: identity.roleLabel)
        if !identity.capabilities.isEmpty {
            LabeledContent("Capabilities") {
                Text(identity.capabilities.joined(separator: ", "))
                    .multilineTextAlignment(.trailing)
            }
        }
        if let latitude = identity.latitude, let longitude = identity.longitude {
            let cellMeters = identity.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
            LabeledContent("Location") {
                VStack(alignment: .trailing) {
                    Text(
                        LocationPresentation.coordinateText(
                            latitude: latitude,
                            longitude: longitude,
                            cellMeters: cellMeters
                        )
                    )
                    if let cellMeters {
                        Text("within \(LocationPresentation.cellLabel(meters: cellMeters))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .coordinateActions(
                latitude: latitude,
                longitude: longitude,
                fractionDigits: LocationPresentation.coordinateDecimals(cellMeters: cellMeters),
                pinName: identity.name
            )
        }
        if let altitude = identity.altitudeMeters {
            LabeledContent("Altitude", value: "\(altitude) m")
        }
        if let timestamp = identity.timestamp {
            LabeledContent("Reported") {
                Text(
                    Date(timeIntervalSince1970: TimeInterval(timestamp)),
                    format: .dateTime.year().month().day().hour().minute()
                )
            }
        }
    }

}
