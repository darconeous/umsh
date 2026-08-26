import SwiftUI

/// The question a reinstall asks: this phone's key is still here, and none
/// of what belonged to it is.
///
/// Deleting an app removes its container but not its Keychain items, so the
/// node key outlives every message, contact, and channel that was filed
/// under it. Neither answer is recovery — the records are gone either way.
/// What is actually being chosen is whether the mesh keeps seeing the same
/// node, which is a question about other people's phones, so it is theirs
/// to answer rather than the app's to assume.
struct RecoveredIdentityView: View {
    let identity: LocalIdentitySnapshot
    let keep: () async -> Void
    let startFresh: () async -> Void

    @State private var isWorking = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)

            VStack(spacing: 20) {
                PeerAvatar(hint: identity.publicIdentity.hint, diameter: 72)
                VStack(spacing: 8) {
                    Text("An identity is already here")
                        .font(.title2.bold())
                        .multilineTextAlignment(.center)
                    Text("UMSH found the key for **\(identity.publicIdentity.hint.text)** on this phone, from an install that is gone. Its messages, contacts, and channels went with it and cannot be recovered.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                CanonicalAddressView(address: identity.publicIdentity.canonicalAddress)
            }
            .padding(.horizontal, 28)

            Spacer(minLength: 0)

            VStack(spacing: 12) {
                Button {
                    run(keep)
                } label: {
                    Text("Keep This Identity")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button {
                    run(startFresh)
                } label: {
                    Text("Start Fresh")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                Text("Keeping it means everyone who knew this phone still recognizes it. Starting fresh destroys the key and mints a new one, so it arrives on the mesh as a node nobody has met.")
                    .font(.caption)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 32)
        }
        .disabled(isWorking)
        .overlay {
            if isWorking { ProgressView() }
        }
        .interactiveDismissDisabled()
    }

    /// Both answers are irreversible, and both take a moment. Hold the
    /// screen rather than let a second tap land on the other one.
    private func run(_ answer: @escaping () async -> Void) {
        guard !isWorking else { return }
        isWorking = true
        Task {
            await answer()
            isWorking = false
        }
    }
}
