import SwiftUI

/// A live list of nearby companion radios. Discovery runs while the sheet is
/// open and never auto-connects — the user taps the radio they want. This is
/// the deliberate-selection counterpart to the auto-connect "first match"
/// path, and is what makes a multi-radio test bench usable.
struct RadioPickerView: View {
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var radios: [DiscoveredRadio] = []
    @State private var selecting: UUID?
    @State private var problem: String?
    @State private var hasSearchedAwhile = false

    var body: some View {
        List {
            Section {
                if radios.isEmpty {
                    HStack(spacing: 12) {
                        ProgressView()
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Searching for companion radios")
                            Text(hasSearchedAwhile
                                 ? "Make sure the radio is powered on and nearby."
                                 : "Nearby radios will appear here.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                } else {
                    ForEach(radios) { radio in
                        Button {
                            Task { await select(radio) }
                        } label: {
                            RadioPickerRow(radio: radio, isSelecting: selecting == radio.id)
                        }
                        .disabled(selecting != nil)
                    }
                }
            } header: {
                Text("Nearby radios")
            } footer: {
                if let problem {
                    Text(problem).foregroundStyle(.red)
                } else {
                    Text("Discovery keeps running while this list is open. Radios that power off drop out after a few seconds.")
                }
            }
        }
        .navigationTitle("Choose a Radio")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .task {
            for await list in await discoverRadios() {
                radios = list
            }
        }
        .task {
            // A gentle nudge after a few quiet seconds, without failing the
            // scan — the radio may simply be booting.
            try? await Task.sleep(nanoseconds: 4 * 1_000_000_000)
            hasSearchedAwhile = true
        }
    }

    private func select(_ radio: DiscoveredRadio) async {
        guard selecting == nil else { return }
        selecting = radio.id
        problem = nil
        do {
            try await selectRadio(radio.id)
            await stopDiscovery()
            dismiss()
        } catch {
            selecting = nil
            problem = "Could not connect to that radio. It may have moved out of range."
        }
    }
}

private struct RadioPickerRow: View {
    let radio: DiscoveredRadio
    let isSelecting: Bool

    var body: some View {
        HStack(spacing: 12) {
            SignalStrengthIcon(bars: radio.signalBars, hasSignal: radio.hasSignal)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(radio.name ?? "Unnamed radio")
                        .foregroundStyle(.primary)
                    if radio.isRemembered {
                        Text("Saved")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(.tint.opacity(0.15), in: Capsule())
                            .foregroundStyle(.tint)
                    }
                }
                Text(radio.hasSignal ? "\(radio.rssiDBm) dBm" : "Signal unavailable")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if isSelecting {
                ProgressView()
            }
        }
        .contentShape(Rectangle())
    }
}

private struct SignalStrengthIcon: View {
    let bars: Int
    let hasSignal: Bool

    var body: some View {
        if hasSignal {
            HStack(alignment: .bottom, spacing: 2) {
                ForEach(1...3, id: \.self) { level in
                    RoundedRectangle(cornerRadius: 1)
                        .fill(level <= bars ? Color.accentColor : Color.secondary.opacity(0.25))
                        .frame(width: 4, height: CGFloat(4 + level * 4))
                }
            }
        } else {
            Image(systemName: "wifi.slash")
                .foregroundStyle(.secondary)
                .font(.caption)
        }
    }
}

#Preview {
    NavigationStack {
        RadioPickerView(
            discoverRadios: {
                AsyncStream { continuation in
                    continuation.yield([
                        DiscoveredRadio(id: UUID(), name: "T-Echo", rssiDBm: -47, isRemembered: true),
                        DiscoveredRadio(id: UUID(), name: "T-1000-E", rssiDBm: -71, isRemembered: false),
                        DiscoveredRadio(id: UUID(), name: nil, rssiDBm: 127, isRemembered: false),
                    ])
                }
            },
            selectRadio: { _ in },
            stopDiscovery: {}
        )
    }
}
