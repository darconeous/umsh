import SwiftUI

struct CompanionToolbarItem: View {
    let snapshot: RadioSnapshot
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: snapshot.linkState.symbolName)
                if let batteryPercentage = snapshot.batteryPercentage {
                    Image(systemName: batterySymbol(for: batteryPercentage))
                    if snapshot.isExternallyPowered == true {
                        Image(systemName: "bolt.fill")
                            .font(.caption2)
                    }
                }
            }
            .font(.subheadline)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(snapshot.accessibleSummary)
        .accessibilityHint("Shows radio details")
    }

    private func batterySymbol(for percentage: Int) -> String {
        switch percentage {
        case 76...: "battery.100percent"
        case 51...: "battery.75percent"
        case 26...: "battery.50percent"
        case 1...: "battery.25percent"
        default: "battery.0percent"
        }
    }
}

struct RadioProblemBanner: View {
    let snapshot: RadioSnapshot
    let action: () -> Void

    var body: some View {
        if let problemDescription = snapshot.problemDescription {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(problemDescription)
                        .font(.subheadline.weight(.semibold))
                    Text(snapshot.accessibleSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Details", action: action)
                    .buttonStyle(.bordered)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.bar)
        }
    }
}
