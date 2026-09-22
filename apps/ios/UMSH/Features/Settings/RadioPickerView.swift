import SwiftUI

/// Select an advertising companion or add one through the system picker.
/// Platforms without AccessorySetupKit retain service-filtered discovery.
struct RadioPickerView: View {
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        RadioScanList(
            discoverRadios: discoverRadios,
            selectRadio: selectRadio,
            stopDiscovery: stopDiscovery,
            onConnected: { dismiss() }
        )
        .navigationTitle("Choose a Radio")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
    }
}

/// The radio list itself, without the chrome that decides what selecting a
/// radio means. Onboarding shows the same list as the picker sheet and follows
/// a selection with its own step, so the search, the rows and the "nothing yet"
/// state are stated once and each screen supplies its own title and way out.
struct RadioScanList: View {
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// Called once a radio has been selected and discovery has been stopped.
    let onConnected: () -> Void

    @State private var radios: [DiscoveredRadio] = []
    @State private var selecting: UUID?
    @State private var problem: String?
    @State private var hasSearchedAwhile = false

    var body: some View {
        List {
            Section {
                if radios.isEmpty && RadioAccessories.usesSystemPicker {
                    Text("No available radios. Turn on a paired radio nearby, or add a radio with its pairing window open.")
                        .foregroundStyle(.secondary)
                } else if radios.isEmpty {
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
                            RadioDiscoveryRow(
                                radio: radio,
                                fallbackName: "Unnamed radio",
                                badge: radio.isRemembered ? "Saved" : nil,
                                isBusy: selecting == radio.id
                            )
                        }
                        .disabled(selecting != nil)
                        .contextMenu {
                            if RadioAccessories.usesSystemPicker {
                                Button("Remove Radio", role: .destructive) {
                                    Task {
                                        do { try await RadioAccessories.shared.remove(radio.id) }
                                        catch { problem = RadioAccessories.message(for: error) }
                                    }
                                }
                            }
                        }
                    }
                }
            } header: {
                Text("Available radios")
            } footer: {
                if let problem {
                    Text(problem).foregroundStyle(.red)
                } else {
                    Text(RadioAccessories.usesSystemPicker
                         ? "Only paired radios advertising nearby appear here. Radios disappear after a few seconds without an advertisement."
                         : "Discovery keeps running while this list is open. Radios that power off drop out after a few seconds.")
                }
            }
            if RadioAccessories.usesSystemPicker { RadioAccessoryActions() }
        }
        // Only membership changes animate; a rename or fallback RSSI update
        // must not look like the row moved.
        .animation(UMSHAnimation.list, value: radios.map(\.id))
        .task {
            for await list in await discoverRadios() {
                radios = list
            }
        }
        .onDisappear { Task { await stopDiscovery() } }
        .task {
            guard !RadioAccessories.usesSystemPicker else { return }
            // A gentle nudge after a few quiet seconds, without failing the
            // scan—the radio may simply be booting.
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
            onConnected()
        } catch {
            selecting = nil
            problem = RadioAccessories.message(for: error)
        }
    }
}

/// Shared by companion selection and administrative device selection. Apple
/// owns discovery and authorization of new radios; these lists own selection
/// among already authorized ones.
struct RadioAccessoryActions: View {
    @State private var accessories = RadioAccessories.shared
    @State private var confirmsForget = false
    @State private var removalProblem: String?

    var body: some View {
        Section {
            RadioAccessoryPickerButton(
                migrationOnly: accessories.inventory.migrationID != nil
            )
            if accessories.inventory.migrationID != nil {
                Button("Forget Previous Radio…", role: .destructive) { confirmsForget = true }
            }
        } footer: {
            Text(removalProblem ?? accessories.inventory.problem
                 ?? "Keep the radio nearby and open its pairing window. iOS will ask you to allow access.")
        }
        .confirmationDialog("Forget the previous radio?", isPresented: $confirmsForget, titleVisibility: .visible) {
            Button("Forget Previous Radio", role: .destructive) {
                guard let id = accessories.inventory.migrationID else { return }
                Task {
                    do { try await accessories.remove(id) }
                    catch { removalProblem = RadioAccessories.message(for: error) }
                }
            }
        } message: {
            Text("This abandons its saved app connection so you can add another radio. It does not reset the radio or remove the pairing from Bluetooth Settings.")
        }
    }
}

/// The same recovery action is available at the problem banner, radio details
/// and saved-radio list. No screen sends the user hunting for another screen.
struct RadioAccessoryPickerButton: View {
    let migrationOnly: Bool
    var onFinished: (UUID) async throws -> Void = { _ in }

    @State private var accessories = RadioAccessories.shared
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        Button {
            let migrating = migrationOnly
            busy = true
            Task {
                defer { busy = false }
                do {
                    let id = try await (migrating ? accessories.finishSetup() : accessories.addRadio())
                    if let id { try await onFinished(id) }
                } catch {
                    problem = RadioAccessories.message(for: error)
                }
            }
        } label: {
            if busy {
                Label("Setting Up…", systemImage: "hourglass")
            } else {
                Label(migrationOnly ? "Finish Radio Setup" : "Add Another Radio…",
                      systemImage: migrationOnly ? "checkmark.circle" : "plus.circle")
            }
        }
        .disabled(busy || accessories.inventory.pickerActive)
        .alert("Radio Setup", isPresented: Binding(
            get: { problem != nil }, set: { if !$0 { problem = nil } }
        )) {
            Button("OK", role: .cancel) { problem = nil }
        } message: { Text(problem ?? "") }
    }
}

/// Three-bar signal strength, shared by every list of nearby devices.
struct SignalStrengthIcon: View {
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
            Image(systemName: "antenna.radiowaves.left.and.right")
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
