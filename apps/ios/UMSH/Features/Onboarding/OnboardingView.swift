import SwiftUI

/// The first-run introduction: what this phone is called on the mesh, and which
/// radio carries its traffic.
///
/// Creating the identity is deliberately not a step. There is no decision in it
/// — no name to choose, no options, nothing to confirm — and a phone without one
/// cannot save a peer, join a channel or send a message, so the only honest
/// thing to do with a missing identity is to mint one. By the time this appears
/// that has already happened, and what is left is the part that is genuinely the
/// user's: the name their messages arrive under, and the radio, if they have one
/// to hand.
struct OnboardingView: View {
    let identity: LocalIdentitySnapshot
    /// The name already on record, for the case where this runs against an
    /// identity that has been named by hand.
    let advertisedName: String
    let saveAdvertisedName: (String) async -> Void
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// Ends the flow. Called however it finishes — radio paired or skipped —
    /// so there is one way out and one place that records it as done.
    let finish: () -> Void

    private enum Step: Hashable {
        case radio
    }

    @State private var path: [Step] = []
    @State private var name = ""
    @FocusState private var nameFocused: Bool

    var body: some View {
        NavigationStack(path: $path) {
            nameStep
                .navigationDestination(for: Step.self) { step in
                    switch step {
                    case .radio: radioStep
                    }
                }
        }
        .interactiveDismissDisabled()
        .onAppear { name = advertisedName }
    }

    private var nameStep: some View {
        Form {
            Section {
                VStack(spacing: 12) {
                    PeerAvatar(hint: identity.publicIdentity.hint, diameter: 72)
                    Text("Welcome to UMSH")
                        .font(.title2.weight(.semibold))
                    Text("This phone now has an identity of its own — \(identity.publicIdentity.hint.text) — and the key behind it never leaves the device.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .listRowBackground(Color.clear)
            }

            Section {
                TextField("Name", text: $name)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .focused($nameFocused)
                    .onSubmit { Task { await continueToRadio() } }
            } header: {
                Text("What to call you")
            } footer: {
                // The one place the user is told what this name does before
                // they choose it: it is broadcast, not a local label.
                Text("Nearby nodes see this name when they ask who this phone is, and it rides along with anything you say in a channel. Leave it empty to stay a bare hint. You can change it later in Settings.")
            }

            Section {
                Button {
                    Task { await continueToRadio() }
                } label: {
                    Text("Continue").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .listRowBackground(Color.clear)
            }
        }
        .navigationTitle("")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { nameFocused = true }
    }

    private var radioStep: some View {
        RadioScanList(
            discoverRadios: discoverRadios,
            selectRadio: selectRadio,
            stopDiscovery: stopDiscovery,
            onConnected: finish
        )
        .navigationTitle("Connect a Radio")
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Text("A companion radio is what puts this phone on the mesh. Without one you can still look around, but nothing is sent or received.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Set Up Later") {
                    Task {
                        await stopDiscovery()
                        finish()
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity)
            .background(.bar)
        }
    }

    private func continueToRadio() async {
        nameFocused = false
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        // Saved before moving on rather than at the end: pairing a radio pushes
        // the display name into the mesh session, and the name should already be
        // the chosen one by the time that happens.
        if trimmed != advertisedName {
            await saveAdvertisedName(trimmed)
        }
        path.append(.radio)
    }
}
