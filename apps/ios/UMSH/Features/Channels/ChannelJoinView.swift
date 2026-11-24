import SwiftUI
import UMSHMobileCore

/// The single way into a channel: a public name, or an invitation URI.
///
/// Follows the staged import the app uses everywhere—acquire, parse locally,
/// preview, confirm—so nothing is stored and nothing is transmitted until
/// the user commits.
struct ChannelJoinView: View {
    let actions: ChannelActions
    /// Channels this phone still holds keys for but has left—the standard
    /// ones. Offered here, where the user has come looking for a channel to
    /// join, and nowhere else.
    var rejoinable: [ChannelSummary] = []
    /// Prefilled by a `umsh:gs:` or `umsh:gk:` link, which then validates
    /// immediately rather than waiting for the button.
    var initialInput: String? = nil
    /// Called with the conversation's address after a join that opened it,
    /// for callers that join in order to talk in the channel. Joining alone
    /// dismisses without it.
    var onJoined: ((String) async throws -> Void)? = nil

    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var resolved: ChannelPreview?
    @State private var problem: String?
    @State private var isInspecting = false
    @State private var isJoining = false
    @State private var alias = ChannelAliasDraft()
    @State private var revealsKey = false
    @State private var failure: FailureNotice?

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
                Text("A public channel is joined by name—anyone who knows the name can join it. A private channel needs its invitation.")
            }

            if resolved == nil, !rejoinable.isEmpty {
                Section {
                    ForEach(rejoinable) { channel in
                        Button(channel.title) {
                            Task { await rejoin(channel) }
                        }
                        .disabled(actions.rejoin == nil || isJoining)
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
        .failureAlert($failure)
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

            if resolved.wellKnown?.channel == .emergency {
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
                Text("Same name, different key—they are separate channels and messages will not cross between them. Give this one a different name to tell them apart.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func detailsSection(_ resolved: ChannelPreview) -> some View {
        Section {
            LabeledContent("Alias") {
                TextField(
                    resolved.preview.displayName ?? "Optional",
                    text: Binding(get: { alias.text }, set: { alias.type($0) })
                )
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
            alias.previewed(value.existing)
        case let .failure(error):
            resolved = nil
            problem = message(for: error)
        }
    }

    /// Join what was looked up, by the text it was looked up from. An empty
    /// alias leaves a new channel unnamed and clears a held one's alias.
    private func join(_ resolved: ChannelPreview) async {
        guard let join = actions.join else { return }
        isJoining = true
        defer { isJoining = false }
        let draft = alias
        var address: String?
        let didJoin = await $failure.attempt(Self.notJoinedTitle) {
            address = try await draft.join(
                resolved.input,
                existing: resolved.existing,
                openConversation: onJoined != nil,
                through: join
            )
        }
        guard didJoin else { return }
        if let onJoined, let address {
            await $failure.attempt(Self.conversationUnavailableTitle) { try await onJoined(address) }
        } else {
            dismiss()
        }
    }

    private func rejoin(_ channel: ChannelSummary) async {
        guard let rejoin = actions.rejoin else { return }
        isJoining = true
        defer { isJoining = false }
        if await $failure.attempt(Self.notJoinedTitle, { try await rejoin(channel) }) {
            dismiss()
        }
    }

    private static var notJoinedTitle: String {
        String(localized: "Channel Not Joined", comment: "Alert title: joining a channel failed.")
    }

    private static var conversationUnavailableTitle: String {
        String(localized: "Conversation Unavailable", comment: "Alert title.")
    }

    private func message(for error: MeshEngineError) -> String {
        switch error {
        case .channelNameNotASCII:
            String(
                localized: "Channel names use plain ASCII letters, digits, and punctuation. A name with other characters has no channel behind it; share a private invitation instead.",
                comment: "A typed channel name has characters no channel can be named with."
            )
        case .channelNameTooLong:
            String(
                localized: "That channel name is too long. Use 64 characters or fewer.",
                comment: "A typed channel name is too long."
            )
        default:
            String(
                localized: "Enter a public channel name, or a umsh:gs: or umsh:gk: invitation. Nothing was joined.",
                comment: "Typed text is neither a channel name nor a channel invitation."
            )
        }
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

/// The alias field's draft beside a preview. A held channel's own alias is
/// filled in when a lookup first shows that channel; filled in rather than
/// typed, it goes when a different channel is looked up, so it never lands
/// on another channel. Emptying the field clears the alias of the held
/// channel the lookup showed.
struct ChannelAliasDraft: Equatable {
    private(set) var text = ""
    /// Whether the user typed the text, rather than it being filled in.
    private var typed = false
    /// The held channel the last lookup showed, nil for one not held.
    private var shownFor: UUID?

    /// The user typed in the field.
    mutating func type(_ alias: String) {
        text = alias
        typed = true
    }

    /// A lookup succeeded, showing `existing` when the phone holds it.
    mutating func previewed(_ existing: ChannelSummary?) {
        guard existing?.id != shownFor else { return }
        if !typed { text = "" }
        shownFor = existing?.id
        if text.isEmpty, let own = existing?.alias {
            text = own
            typed = false
        }
    }

    /// What Join sends for `existing`, the channel the last lookup showed:
    /// the trimmed alias, or nil; and whether to clear the alias it holds.
    func outcome(for existing: ChannelSummary?) -> (alias: String?, clears: Bool) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let named = trimmed.isEmpty ? nil : trimmed
        return (named, named == nil && existing?.alias != nil)
    }

    /// Join `input` through `join` with what the field holds for
    /// `existing`, the held channel the last lookup showed.
    @MainActor
    func join(
        _ input: String,
        existing: ChannelSummary?,
        openConversation: Bool,
        through join: (_ input: String, _ alias: String?, _ clearAlias: Bool, _ openConversation: Bool) async throws -> String?
    ) async throws -> String? {
        let outcome = outcome(for: existing)
        return try await join(input, outcome.alias, outcome.clears, openConversation)
    }
}

#Preview {
    NavigationStack {
        ChannelJoinView(actions: .unavailable)
    }
}
