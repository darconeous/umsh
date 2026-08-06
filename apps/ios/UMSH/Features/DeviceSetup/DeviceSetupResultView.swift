import SwiftUI
import UMSHMobileCore

/// How a setup sheet's write went, over the sheet that started it.
///
/// One screen for the whole write rather than a spinner in a toolbar and an
/// outcome somewhere else: a commissioning apply is two exchanges with the
/// device, and the operator is owed one answer about both.
struct DeviceSetupResultView: View {
    let phase: DeviceConfigDraft.ApplyPhase
    /// What the device was set up as — "tracker", "repeater".
    let deviceNoun: String
    let deviceName: String?
    /// Nil when this app has nowhere to file a peer.
    let savePeer: (() async -> Bool)?
    let isPeerSaved: Bool
    let reviewAllSettings: () -> Void
    let setUpAnother: () -> Void
    /// Close the result and go back to the sheet behind it.
    let close: () -> Void
    /// Close the whole setup flow.
    let finish: () -> Void

    @State private var savingPeer = false
    @State private var savedPeer = false
    @State private var savePeerFailed = false

    var body: some View {
        NavigationStack {
            Group {
                switch phase {
                case .applying:
                    applying
                case .succeeded, .succeededWithoutClock:
                    succeeded
                case let .reportedDifferently(field):
                    reportedDifferently(field)
                }
            }
            .toolbar {
                if phase != .applying {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { finish() }
                    }
                }
            }
        }
        // A write in flight is not a thing to swipe away: the device is being
        // reconfigured either way, and a dismissed spinner would leave the
        // operator believing otherwise.
        .interactiveDismissDisabled(phase == .applying)
    }

    private var applying: some View {
        VStack(spacing: 16) {
            ProgressView()
                .controlSize(.large)
            Text("Applying settings…")
                .font(.headline)
            Text("Leave the device powered on and nearby.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var succeeded: some View {
        List {
            Section {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 52))
                        .foregroundStyle(.green)
                    Text("Congrats, you've successfully set up your \(deviceNoun)!")
                        .font(.title3.weight(.semibold))
                        .multilineTextAlignment(.center)
                    if let deviceName {
                        Text(deviceName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            .listRowBackground(Color.clear)

            if phase == .succeededWithoutClock {
                Section {
                    Label("The clock could not be set", systemImage: "clock.badge.exclamationmark")
                        .foregroundStyle(.orange)
                } footer: {
                    Text("Everything else was saved. You can set the clock from Review all settings.")
                }
            }

            if let savePeer {
                Section {
                    savePeerRow(savePeer)
                } footer: {
                    Text("Saving it to Peers is how you find this \(deviceNoun) again from the rest of the app.")
                }
            }

            Section {
                Button("Review all settings") { reviewAllSettings() }
                Button("Set up another device") { setUpAnother() }
            }
        }
    }

    @ViewBuilder
    private func savePeerRow(_ savePeer: @escaping () async -> Bool) -> some View {
        // The device's role is only certain now: before the write it would
        // have been filed under whatever it used to be.
        let saved = isPeerSaved || savedPeer
        Button {
            savePeerFailed = false
            savingPeer = true
            Task {
                savedPeer = await savePeer()
                savePeerFailed = !savedPeer
                savingPeer = false
            }
        } label: {
            HStack {
                Label(saved ? "Saved to Peers" : "Save to Peers", systemImage: saved ? "checkmark" : "plus")
                Spacer()
                if savingPeer { ProgressView() }
            }
        }
        .disabled(saved || savingPeer)
        if savePeerFailed {
            Label("Could not save it. Try again from the device's identity.", systemImage: "exclamationmark.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func reportedDifferently(_ field: String) -> some View {
        List {
            Section {
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 44))
                        .foregroundStyle(.orange)
                    Text("The device reported \(field) back differently")
                        .font(.title3.weight(.semibold))
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            .listRowBackground(Color.clear)

            Section {
                Text("It saved its settings, but what it read back afterwards is not what it was asked for. Read the device again before relying on this configuration.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button("Review all settings") { reviewAllSettings() }
                Button("Close") { close() }
            }
        }
    }
}
