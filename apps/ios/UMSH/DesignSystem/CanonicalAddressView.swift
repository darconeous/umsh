import SwiftUI
import UIKit

struct CanonicalAddressView: View {
    let address: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Public address")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    UIPasteboard.general.string = address
                    copied = true
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderless)
            }

            Text(address)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Public address \(address)")
        }
    }
}

extension View {
    /// Put a value on the pasteboard with a long press, the way Settings does
    /// with a serial number.
    ///
    /// Addresses and hints are shown so they can be checked against something
    /// else — another screen, a terminal, a message to someone. A 44-character
    /// base58 address that can only be read is close to useless, and the rows
    /// these appear in are usually truncated on top of that.
    ///
    /// Deliberately not paired with `.textSelection(.enabled)`: both want the
    /// long press, and the menu is the one that reliably gets it inside a
    /// `Form`.
    func copyable(_ value: String) -> some View {
        contextMenu {
            Button("Copy", systemImage: "doc.on.doc") {
                UIPasteboard.general.string = value
            }
        }
    }

    /// Offer a coordinate for copying and for opening in Maps.
    ///
    /// The sibling of [`copyable`](View/copyable(_:)), and deliberately
    /// built the same way: a modifier over the row rather than a control
    /// wrapped around it. A coordinate row is a readout, and a readout
    /// that is also a `Menu` or a `Button` acquires that control's
    /// chrome — a tinted label, a filled capsule — and stops looking like
    /// the rows above and below it. A modifier contributes no appearance
    /// at all, so there is nothing to style back.
    ///
    /// `fractionDigits` should match what the row displays: a location
    /// names a cell, and digits past what the grid code resolves would be
    /// invented. `pinName` names the pin Maps drops.
    func coordinateActions(
        latitude: Double,
        longitude: Double,
        fractionDigits: Int = 4,
        pinName: String? = nil
    ) -> some View {
        coordinateActions(
            latitude: latitude,
            longitude: longitude,
            fractionDigits: fractionDigits,
            pinName: pinName
        ) {
            EmptyView()
        }
    }

    /// The same, for a row that has business of its own in the menu.
    ///
    /// `ownActions` are listed first, because a row that offers something
    /// beyond its coordinate is a row where the coordinate is the detail. A
    /// second `contextMenu` would not do: the later one replaces the earlier
    /// rather than adding to it, so anything wanting both has to say so here.
    func coordinateActions<Own: View>(
        latitude: Double,
        longitude: Double,
        fractionDigits: Int = 4,
        pinName: String? = nil,
        @ViewBuilder ownActions: () -> Own
    ) -> some View {
        modifier(
            CoordinateActions(
                latitude: latitude,
                longitude: longitude,
                fractionDigits: fractionDigits,
                pinName: pinName,
                ownActions: ownActions()
            )
        )
    }
}

/// The actions behind [`coordinateActions`](View/coordinateActions(latitude:longitude:fractionDigits:pinName:)).
///
/// A modifier rather than a free function because opening Maps needs the
/// environment's URL opener.
private struct CoordinateActions<Own: View>: ViewModifier {
    let latitude: Double
    let longitude: Double
    let fractionDigits: Int
    let pinName: String?
    let ownActions: Own

    @Environment(\.openURL) private var openURL

    private var latitudeText: String { String(format: "%.\(fractionDigits)f", latitude) }
    private var longitudeText: String { String(format: "%.\(fractionDigits)f", longitude) }

    /// What goes on the pasteboard: the pair and nothing else — no label,
    /// no degree signs, no parentheses. It is meant to be pasted into a
    /// search field or a message and work there unedited.
    private var plain: String { "\(latitudeText), \(longitudeText)" }

    private var mapsURL: URL? {
        var components = URLComponents(string: "https://maps.apple.com/")
        components?.queryItems = [
            URLQueryItem(name: "ll", value: "\(latitudeText),\(longitudeText)"),
            URLQueryItem(name: "q", value: pinName ?? "Reported location"),
        ]
        return components?.url
    }

    func body(content: Content) -> some View {
        content.contextMenu {
            ownActions
            Button("Copy coordinates", systemImage: "doc.on.doc") {
                UIPasteboard.general.string = plain
            }
            if let mapsURL {
                Button("Show in Maps…", systemImage: "map") {
                    openURL(mapsURL)
                }
            }
        }
    }
}
