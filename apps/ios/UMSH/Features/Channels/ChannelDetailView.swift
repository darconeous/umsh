import SwiftUI

/// Everything about one channel: what it is, how to invite someone, and how
/// to leave.
struct ChannelDetailView: View {
    let channel: ChannelSummary
    let actions: ChannelActions

    @Environment(\.dismiss) private var dismiss
    @State private var alias: String
    @State private var region = ""
    @State private var maxFloodHops: Int
    @State private var regionProblem: String?
    /// What the notification switch shows until the lists come back with
    /// the new value, so it does not spring back mid-write.
    @State private var pendingNotifications: Bool?
    /// Notification writes still under way. The switch holds its pending
    /// value until the last of them is done, not the first.
    @State private var notificationWrites = 0
    /// The latest alias or routing save. Each waits for the one before it,
    /// so the saves reach the core in the order the edits were made.
    @State private var lastSave: Task<Void, Never>?
    /// Carries the URI itself rather than a presentation flag: a sheet driven
    /// by a separate boolean can be built before the value it needs lands.
    @State private var invitation: ChannelInvitation?
    @State private var confirmsLeave = false
    @State private var failure: FailureNotice?
    /// Whether test messages on `EMERGENCY` notify. The runtime reads the
    /// same key.
    @AppStorage("notifications.testMessages") private var testMessageAlerts = false

    private struct ChannelInvitation: Identifiable {
        let id = UUID()
        let uri: String
    }

    init(channel: ChannelSummary, actions: ChannelActions) {
        self.channel = channel
        self.actions = actions
        _alias = State(initialValue: channel.alias ?? "")
        // 0 stands for "unset", which is the protocol's own default rather
        // than a hop count this channel chose.
        _maxFloodHops = State(initialValue: channel.maxFloodHops ?? 0)
    }

    var body: some View {
        Form {
            // What the user can change comes first; reference detail after it,
            // and the parts nobody can change last.
            identitySection
            if channel.joinedPhone, actions.enterConversation != nil {
                conversationSection
            }
            localDetailsSection
            if channel.joinedPhone {
                leaveSection
            }
            behaviorSection
        }
        .navigationTitle(channel.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                // Opens the invitation sheet rather than the system share
                // sheet directly: a private channel's URI is key material and
                // has to be disclosed before it can leave the app.
                Button {
                    guard let make = actions.invitation else { return }
                    Task {
                        await $failure.attempt(Self.notSharedTitle) {
                            invitation = ChannelInvitation(uri: try await make(channel))
                        }
                    }
                } label: {
                    Label("Share Channel", systemImage: "square.and.arrow.up")
                }
                .disabled(actions.invitation == nil)
            }
        }
        .task {
            if let code = channel.regionCode, region.isEmpty {
                region = await actions.describeRegion?(code) ?? ""
            }
        }
        .sheet(item: $invitation) { item in
            NavigationStack {
                ChannelShareView(channel: channel, invitation: item.uri)
            }
        }
        .confirmationDialog(
            channel.leaveTitle,
            isPresented: $confirmsLeave,
            titleVisibility: .visible
        ) {
            Button("Leave Channel", role: .destructive) {
                guard let leave = actions.leave else { return }
                Task {
                    if await $failure.attempt(Self.notLeftTitle, { try await leave(channel) }) {
                        dismiss()
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: channel.leaveMessage)
        }
        .failureAlert($failure)
    }

    private var identitySection: some View {
        Section("Channel") {
            if let name = channel.name, !name.isEmpty {
                LabeledContent("Name", value: name)
            }
            LabeledContent("Type", value: channel.kindLabel)
            LabeledContent("Identifier") {
                Text(channel.channelIDHex)
                    .font(.body.monospaced())
            }
            if let joinedAt = channel.joinedAt {
                LabeledContent("Joined", value: joinedAt.formatted(date: .abbreviated, time: .shortened))
            }
        }
    }

    private var conversationSection: some View {
        Section {
            Button {
                guard let enter = actions.enterConversation else { return }
                Task {
                    await $failure.attempt(Self.conversationUnavailableTitle) { try await enter(channel) }
                }
            } label: {
                Label("Enter Conversation", systemImage: "bubble.left.and.bubble.right")
            }
        }
    }

    private var localDetailsSection: some View {
        Section {
            LabeledContent("Alias") {
                TextField(channel.name ?? "Optional", text: $alias)
                    .multilineTextAlignment(.trailing)
                    .onSubmit { save(saveAlias) }
            }
            LabeledContent("Region") {
                TextField("None", text: $region)
                    .multilineTextAlignment(.trailing)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .onSubmit { save(saveRouting) }
            }
            if let fixed = channel.protocolMaxFloodHops {
                // Fixed by the protocol for this channel, and moving with the
                // region rather than with anything the user picks.
                LabeledContent("Maximum hops", value: "\(fixed)")
                    .foregroundStyle(.secondary)
            } else {
                Picker("Maximum hops", selection: $maxFloodHops) {
                    Text("Default").tag(0)
                    ForEach(1...Int(CoreLimits.current.maxFloodHops), id: \.self) { hops in
                        Text("\(hops)").tag(hops)
                    }
                }
                .onChange(of: maxFloodHops) { save(saveRouting) }
            }
            Toggle("Notifications", isOn: Binding(
                get: { pendingNotifications ?? channel.notificationsEnabled },
                set: { enabled in Task { await setNotifications(enabled) } }
            ))
            if channel.isEmergency {
                Toggle(
                    String(localized: "Test Messages", comment: "Switch on the EMERGENCY channel's page: whether messages starting with TEST: notify."),
                    isOn: $testMessageAlerts
                )
            }
            if let regionProblem {
                Text(regionProblem)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Local Details")
        }
    }

    /// How this channel behaves. Described, not demanded: the app applies all
    /// of it, so there is nothing here for the user to do.
    @ViewBuilder
    private var behaviorSection: some View {
        let behavior = channel.protocolBehavior
        if !behavior.isEmpty {
            Section("How This Channel Works") {
                ForEach(behavior, id: \.self) { statement in
                    Text(statement)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var leaveSection: some View {
        Section {
            Button("Leave Channel", role: .destructive) { confirmsLeave = true }
                .disabled(actions.leave == nil)
        }
    }

    private static var notChangedTitle: String {
        String(localized: "Channel Not Changed", comment: "Alert title: a channel's alias, region, hops or notifications were not saved.")
    }

    private static var notLeftTitle: String {
        String(localized: "Channel Not Left", comment: "Alert title: leaving a channel failed.")
    }

    private static var notSharedTitle: String {
        String(localized: "Invitation Unavailable", comment: "Alert title: a channel's invitation could not be made.")
    }

    private static var conversationUnavailableTitle: String {
        String(localized: "Conversation Unavailable", comment: "Alert title.")
    }

    private func setNotifications(_ enabled: Bool) async {
        guard let set = actions.setNotifications else { return }
        pendingNotifications = enabled
        notificationWrites += 1
        await $failure.attempt(Self.notChangedTitle) { try await set(channel, enabled) }
        notificationWrites -= 1
        // The lists have reloaded by now, so the switch follows them again:
        // the new value, or the old one when the write did not happen.
        if notificationWrites == 0 {
            pendingNotifications = nil
        }
    }

    /// Run `work` after the save before it.
    private func save(_ work: @escaping @MainActor () async -> Void) {
        let previous = lastSave
        lastSave = Task {
            await previous?.value
            await work()
        }
    }

    /// Send the alias as the field now holds it. Always sent, never compared
    /// with `channel`: that copy is only as new as the last reload, so an
    /// edit back to it before then would be skipped and the earlier one kept.
    private func saveAlias() async {
        guard let setAlias = actions.setAlias else { return }
        let trimmed = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        let newAlias = trimmed.isEmpty ? nil : trimmed
        await $failure.attempt(Self.notChangedTitle) { try await setAlias(channel, newAlias) }
    }

    /// Send the region and hop limit as the fields now hold them, for the
    /// same reason as `saveAlias`.
    private func saveRouting() async {
        let trimmedRegion = region.trimmingCharacters(in: .whitespacesAndNewlines)

        var regionCode: Data?
        if !trimmedRegion.isEmpty {
            guard let parsed = await actions.parseRegion?(trimmedRegion) else {
                regionProblem = String(
                    localized: "That is not a region. Use a short code like SJC or WA, a name your mesh has agreed on, or a raw 0xXXXX code.",
                    comment: "A channel's region field holds text that names no region."
                )
                return
            }
            regionCode = parsed
        }
        regionProblem = nil

        // A protocol-fixed ceiling is not stored: it follows from the channel
        // and its region, so persisting a copy would let the two drift apart.
        let hops = channel.protocolMaxFloodHops == nil && maxFloodHops != 0
            ? maxFloodHops
            : nil
        if let setRouting = actions.setRouting {
            await $failure.attempt(Self.notChangedTitle) { try await setRouting(channel, regionCode, hops) }
        }
        // Adopt the canonical rendering so the field shows the code the mesh
        // actually carries, not only what was typed.
        if let regionCode, let described = await actions.describeRegion?(regionCode) {
            region = described
        }
    }
}

/// A channel invitation as a QR code and copyable URI.
///
/// A private invitation is key material, so the disclosure is stated on the
/// sheet itself rather than only on the way in.
struct ChannelShareView: View {
    let channel: ChannelSummary
    let invitation: String

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                IdentityShareView(
                    uri: invitation,
                    copyLabel: channel.invitationIsSecret ? "Copy Invitation" : "Copy Channel URI"
                )
            }
            Section {
                Text(
                    channel.invitationIsSecret
                        ? "Anyone who scans or receives this becomes a full member of “\(channel.title)”. They can read everything sent here, send messages that appear to come from any member, and pass the invitation on."
                        : "This is the channel's public name. Anyone who knows it can join."
                )
                .font(.callout)
            }
            Section {
                ShareLink(item: invitation) {
                    Label("Share…", systemImage: "square.and.arrow.up")
                }
            }
        }
        .navigationTitle(channel.invitationIsSecret ? "Private Channel Invitation" : "Public Channel")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
    }
}

#Preview {
    NavigationStack {
        ChannelDetailView(
            channel: ChannelSummary(
                id: UUID(),
                kind: .privateKey,
                canonicalName: nil,
                name: "Trail Crew",
                alias: nil,
                channelIDHex: "0a3c",
                tint: Data([0x0a, 0x3c, 0x91]),
                regionCode: nil,
                maxFloodHops: 3,
                joinedPhone: true,
                notificationsEnabled: false,
                joinedAt: .now
            ),
            actions: .unavailable
        )
    }
}
