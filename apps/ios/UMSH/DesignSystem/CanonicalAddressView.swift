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
}
