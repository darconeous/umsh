import SwiftUI

/// Create a private channel: generate a key, name it locally, and share the
/// invitation with whoever should be in it.
struct ChannelCreateView: View {
    let actions: ChannelActions

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var isCreating = false
    @State private var failure: FailureNotice?

    var body: some View {
        Form {
            Section {
                LabeledContent("Name") {
                    TextField("Required", text: $name)
                        .multilineTextAlignment(.trailing)
                }
            } header: {
                Text("Name")
            } footer: {
                Text("Stored on this phone and suggested to anyone you invite. It is not part of the key, so two people can call the same channel different things.")
            }

            Section {
                Text("A new random key is generated on this phone. Everyone you share the invitation with becomes a full member: they can read everything sent here and send messages that appear to come from any member.")
                Text("Removing someone later means creating a new channel and re-inviting everyone else.")
            } header: {
                Text("What this creates")
            }

            Section {
                Button("Create Channel") { Task { await create() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(trimmedName.isEmpty || isCreating || actions.createPrivate == nil)
            }
        }
        .navigationTitle("New Private Channel")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .failureAlert($failure)
    }

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func create() async {
        guard let createPrivate = actions.createPrivate else { return }
        isCreating = true
        defer { isCreating = false }
        if await $failure.attempt(Self.notCreatedTitle, { try await createPrivate(trimmedName) }) {
            dismiss()
        }
    }

    private static var notCreatedTitle: String {
        String(localized: "Channel Not Created", comment: "Alert title: creating a private channel failed.")
    }
}

#Preview {
    NavigationStack {
        ChannelCreateView(actions: .unavailable)
    }
}
