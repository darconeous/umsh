import SwiftUI

/// Selection policy stays with each picker; signal and setup presentation
/// stays identical for companions and administrative devices.
struct RadioDiscoveryRow: View {
    let radio: DiscoveredRadio
    let fallbackName: String
    var badge: String?
    var isBusy = false

    var body: some View {
        IdentityRowLayout {
            SignalStrengthIcon(bars: radio.signalBars, hasSignal: radio.hasSignal)
                .frame(width: 22)
        } title: {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 6) {
                    Text(radio.name ?? fallbackName)
                    if let badge { StatusBadge(title: badge) }
                }
                VStack(alignment: .leading, spacing: IdentityPresentation.textSpacing) {
                    Text(radio.name ?? fallbackName)
                    if let badge { StatusBadge(title: badge) }
                }
            }
        } subtitle: {
            Text(radio.requiresMigration ? "Finish setup to reconnect"
                 : radio.hasSignal ? "\(radio.rssiDBm) dBm" : "Available")
                .monospaced()
        } trailing: {
            if isBusy { ProgressView().accessibilityLabel("Connecting") }
        }
        .foregroundStyle(.primary)
        .contentShape(Rectangle())
    }
}
