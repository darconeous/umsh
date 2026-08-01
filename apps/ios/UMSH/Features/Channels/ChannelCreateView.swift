import SwiftUI

/// Create a private channel: generate a key, name it locally, and share the
/// invitation with whoever should be in it.
struct ChannelCreateView: View {
    let actions: ChannelActions

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var isCreating = false
    @State private var problem: String?

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

            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("New Private Channel")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
    }

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func create() async {
        isCreating = true
        defer { isCreating = false }
        switch await actions.createPrivate?(trimmedName, ChannelDetails()) {
        case .success:
            dismiss()
        case .phoneFull:
            problem = "This phone is already holding as many channels as it can. Leave one to make room."
        case .none, .failed, .deviceFull, .radioUnavailable, .unsupported:
            problem = "The channel could not be created. Nothing was changed."
        }
    }
}

#Preview {
    NavigationStack {
        ChannelCreateView(actions: .unavailable)
    }
}
