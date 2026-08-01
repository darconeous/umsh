import SwiftUI

/// Everything about one channel: what it is, who has joined it, how to invite
/// someone, and how to leave.
struct ChannelDetailView: View {
    let channel: ChannelSummary
    let radioSnapshot: RadioSnapshot
    let actions: ChannelActions

    @Environment(\.dismiss) private var dismiss
    @State private var alias: String
    @State private var region = ""
    @State private var maxFloodHops: Int
    @State private var regionProblem: String?
    /// Carries the URI itself rather than a presentation flag: a sheet driven
    /// by a separate boolean can be built before the value it needs lands.
    @State private var invitation: ChannelInvitation?
    @State private var confirmsLeave = false
    @State private var deviceProblem: String?
    @State private var isWorking = false

    private struct ChannelInvitation: Identifiable {
        let id = UUID()
        let uri: String
    }

    init(channel: ChannelSummary, radioSnapshot: RadioSnapshot, actions: ChannelActions) {
        self.channel = channel
        self.radioSnapshot = radioSnapshot
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
            membershipSection
            if channel.isJoined {
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
                    Task {
                        guard let uri = await actions.invitation?(channel) else { return }
                        invitation = ChannelInvitation(uri: uri)
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
            leaveTitle,
            isPresented: $confirmsLeave,
            titleVisibility: .visible
        ) {
            Button("Leave Channel", role: .destructive) {
                Task {
                    if await actions.leave?(channel) == .success { dismiss() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(leaveMessage)
        }
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
                Task { await actions.enterConversation?(channel) }
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
                    .onSubmit { Task { await saveDetails() } }
            }
            LabeledContent("Region") {
                TextField("None", text: $region)
                    .multilineTextAlignment(.trailing)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .onSubmit { Task { await saveDetails() } }
            }
            if let fixed = channel.protocolMaxFloodHops {
                // Fixed by the protocol for this channel, and moving with the
                // region rather than with anything the user picks.
                LabeledContent("Maximum hops", value: "\(fixed)")
                    .foregroundStyle(.secondary)
            } else {
                // The remaining-hop budget is a four-bit field, so 15 is the
                // most the wire can carry.
                Picker("Maximum hops", selection: $maxFloodHops) {
                    Text("Default").tag(0)
                    ForEach(1...15, id: \.self) { hops in
                        Text("\(hops)").tag(hops)
                    }
                }
                .onChange(of: maxFloodHops) { Task { await saveDetails() } }
            }
            Toggle("Notifications", isOn: Binding(
                get: { channel.notificationsEnabled },
                set: { enabled in Task { await saveDetails(notificationsEnabled: enabled) } }
            ))
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

    private var membershipSection: some View {
        Section {
            Toggle("This phone", isOn: Binding(
                get: { channel.joinedPhone },
                set: { _ in confirmsLeave = channel.joinedPhone }
            ))
            .disabled(!channel.joinedPhone || isWorking)

            Toggle("Companion radio", isOn: Binding(
                get: { channel.joinedDevice },
                set: { joined in Task { await setDeviceMembership(joined) } }
            ))
            .disabled(!deviceMembershipAvailable || isWorking)

            if let deviceProblem {
                Text(deviceProblem)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Joined By")
        } footer: {
            Text(membershipFooter)
        }
    }

    private var leaveSection: some View {
        Section {
            Button("Leave Channel", role: .destructive) { confirmsLeave = true }
                .disabled(actions.leave == nil)
        }
    }

    /// The radio's device identity is a separate member with its own key
    /// table, so this control needs a radio that actually has one.
    private var deviceMembershipAvailable: Bool {
        (radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready)
            && radioSnapshot.hostState == .matchesCurrentIdentity
            && radioSnapshot.provisioning?.supportsDeviceIdentity == true
            && actions.setDeviceMembership != nil
    }

    private var membershipFooter: String {
        if !deviceMembershipAvailable {
            return "The companion radio keeps its own channel membership, used for its own beacons and for forwarding. Connect a radio with its own identity to manage it."
        }
        return "The radio's own identity joins channels separately from this phone. It uses them for its own beacons and for recognizing traffic addressed to it."
    }

    private var leaveTitle: String {
        "Leave “\(channel.title)”?"
    }

    private var leaveMessage: String {
        if channel.canRejoinAfterLeaving {
            return "You can join again at any time using the channel's name. Messages already received stay on this phone."
        }
        return "The channel key is deleted from this phone. Joining again requires a new invitation from someone still in the channel."
    }

    private func setDeviceMembership(_ joined: Bool) async {
        isWorking = true
        defer { isWorking = false }
        deviceProblem = nil
        switch await actions.setDeviceMembership?(channel, joined) {
        case .success, .none:
            break
        case .deviceFull:
            deviceProblem = "The radio is already holding as many channels as it can (\(deviceChannelCapacity))."
        case .radioUnavailable:
            deviceProblem = "The companion radio is not connected."
        case .unsupported:
            deviceProblem = "This radio does not have an identity of its own."
        case .failed, .phoneFull:
            deviceProblem = "The radio did not accept the change."
        }
    }

    private func saveDetails(notificationsEnabled: Bool? = nil) async {
        let trimmedAlias = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedRegion = region.trimmingCharacters(in: .whitespacesAndNewlines)

        var regionCode: Data?
        if !trimmedRegion.isEmpty {
            guard let parsed = await actions.parseRegion?(trimmedRegion) else {
                regionProblem = "That is not a region. Use an airport code, a name your mesh has agreed on, or a raw 0xXXXX code."
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
        _ = await actions.updateDetails?(
            channel,
            ChannelDetails(
                alias: trimmedAlias.isEmpty ? nil : trimmedAlias,
                regionCode: regionCode,
                maxFloodHops: hops,
                notificationsEnabled: notificationsEnabled ?? channel.notificationsEnabled
            )
        )
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
                joinedDevice: false,
                notificationsEnabled: false,
                joinedAt: .now
            ),
            radioSnapshot: .previewReady,
            actions: .unavailable
        )
    }
}
