import SwiftUI

/// The single way into a channel: a public name, or an invitation URI.
///
/// Follows the staged import the app uses everywhere — acquire, parse locally,
/// preview, confirm — so nothing is stored and nothing is transmitted until
/// the user commits.
struct ChannelJoinView: View {
    let actions: ChannelActions
    /// Channels this phone still holds keys for but has left — the standard
    /// ones. Offered here, where the user has come looking for a channel to
    /// join, and nowhere else.
    var rejoinable: [ChannelSummary] = []
    /// Prefilled by a `umsh:cs:` or `umsh:ck:` link, which then validates
    /// immediately rather than waiting for the button.
    var initialInput: String? = nil
    /// Called after a successful join, for callers that join in order to do
    /// something with the channel. Joining alone dismisses without it.
    var onJoined: ((MeshChannelPreview) async -> Void)? = nil

    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var resolved: ChannelPreview?
    @State private var problem: String?
    @State private var isInspecting = false
    @State private var isJoining = false
    @State private var alias = ""
    @State private var revealsKey = false

    var body: some View {
        Form {
            Section {
                TextField("Channel name or invitation", text: $input, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button("Look Up Channel") { Task { await inspect() } }
                    .disabled(trimmedInput.isEmpty || isInspecting)
            } header: {
                Text("Channel")
            } footer: {
                Text("A public channel is joined by name — anyone who knows the name can join it. A private channel needs its invitation.")
            }

            if resolved == nil, !rejoinable.isEmpty {
                Section {
                    ForEach(rejoinable) { channel in
                        Button(channel.title) {
                            Task {
                                if await actions.rejoin?(channel) == .success { dismiss() }
                            }
                        }
                        .disabled(actions.rejoin == nil)
                    }
                } header: {
                    Text("Suggested Channels")
                }
            }

            if let resolved {
                previewSection(resolved)
                detailsSection(resolved)
                confirmSection(resolved)
            }

            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Join Channel")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .task {
            if let initialInput, input.isEmpty {
                input = initialInput
                await inspect()
            }
        }
    }

    @ViewBuilder
    private func previewSection(_ resolved: ChannelPreview) -> some View {
        Section(resolved.preview.kind == .namedPublic ? "Public Channel" : "Private Channel Invitation") {
            if let name = resolved.preview.displayName, !name.isEmpty {
                LabeledContent("Name", value: name)
            }
            LabeledContent("Identifier") {
                Text(hex(resolved.preview.channelID))
                    .font(.body.monospaced())
            }

            if resolved.preview.kind == .privateKey {
                DisclosureGroup("Channel key", isExpanded: $revealsKey) {
                    Text(hex(resolved.preview.key))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                Text("Anyone holding this key can read the channel and send messages that appear to come from any member. Treat the invitation as a secret.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("The name is not a password. Anyone who knows it can join and read everything sent here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if resolved.preview.canonicalName == "emergency" {
                Text("Traffic here is unencrypted and signed, so anyone in range can read it and every message identifies its sender.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text("Looking up a channel does not join it or transmit anything.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }

        if let existing = resolved.existing {
            Section {
                Label("Already joined as “\(existing.title)”", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.secondary)
                Text("This is the same key you already hold. Continuing updates its local details instead of adding a second channel.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }

        if let conflict = resolved.nameConflict {
            Section {
                Label("A different channel is already called “\(conflict.title)”", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("Same name, different key — they are separate channels and messages will not cross between them. Give this one a different name to tell them apart.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func detailsSection(_ resolved: ChannelPreview) -> some View {
        Section {
            LabeledContent("Alias") {
                TextField(resolved.preview.displayName ?? "Optional", text: $alias)
                    .multilineTextAlignment(.trailing)
            }
        } header: {
            Text("Local Details")
        } footer: {
            Text("Stored only on this phone. An alias replaces the channel's name here without changing it for anyone else.")
        }
    }

    private func confirmSection(_ resolved: ChannelPreview) -> some View {
        Section {
            Button(resolved.existing == nil ? "Join Channel" : "Update Local Details") {
                Task { await join(resolved) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isJoining || actions.join == nil)
        }
    }

    private var trimmedInput: String {
        input.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func inspect() async {
        isInspecting = true
        defer { isInspecting = false }
        guard let preview = actions.preview else { return }
        switch await preview(trimmedInput) {
        case let .success(value):
            resolved = value
            problem = nil
            if alias.isEmpty {
                // Prefilled with what the channel already calls itself, so
                // the field reads as an override rather than a blank demand.
                alias = value.existing?.alias ?? ""
            }
        case let .failure(error):
            resolved = nil
            problem = message(for: error)
        }
    }

    private func join(_ resolved: ChannelPreview) async {
        isJoining = true
        defer { isJoining = false }
        let trimmedAlias = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        let details = ChannelDetails(
            alias: trimmedAlias.isEmpty ? nil : trimmedAlias,
            regionCode: resolved.preview.regionCode,
            maxFloodHops: resolved.preview.maxFloodHops.map(Int.init),
            notificationsEnabled: resolved.existing?.notificationsEnabled ?? false
        )
        switch await actions.join?(resolved.preview, details) {
        case .success:
            if let onJoined {
                await onJoined(resolved.preview)
            } else {
                dismiss()
            }
        case .phoneFull:
            problem = "This phone is already holding as many channels as it can. Leave one to make room."
        case .none, .failed, .deviceFull, .radioUnavailable, .unsupported:
            problem = "The channel could not be joined. Nothing was changed."
        }
    }

    private func message(for error: MeshEngineError) -> String {
        switch error {
        case .channelNameNotASCII:
            "Channel names use plain ASCII letters, digits, and punctuation. A name with other characters has no channel behind it; share a private invitation instead."
        case .channelNameTooLong:
            "That channel name is too long. Use 64 characters or fewer."
        default:
            "Enter a public channel name, or a umsh:cs: or umsh:ck: invitation. Nothing was joined."
        }
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

#Preview {
    NavigationStack {
        ChannelJoinView(actions: .unavailable)
    }
}
