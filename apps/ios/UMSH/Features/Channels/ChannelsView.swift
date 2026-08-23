import SwiftUI

/// The Channels tab: which channels this identity has joined, and the ways in.
///
/// A channel is a shared key, so this list is membership, not a directory —
/// nothing here was discovered over the air, and nothing on the air can add to
/// it. `public` and `EMERGENCY` are seeded joined; leaving either keeps the key
/// so the join sheet can offer it back, but this list shows only what the user
/// is actually in.
struct ChannelsView: View {
    let channels: [ChannelSummary]
    let unknownDeviceChannels: [UnknownDeviceChannel]
    let radioSnapshot: RadioSnapshot
    let actions: ChannelActions

    @State private var showsJoin = false
    @State private var showsCreate = false
    @State private var explainedUnknown: UnknownDeviceChannel?
    @State private var pendingLeave: ChannelSummary?

    var body: some View {
        List {
            if joined.isEmpty {
                emptyState
            } else {
                // No section header: everything listed here is joined, which
                // the tab already says.
                Section {
                    ForEach(joined) { channel in
                        NavigationLink {
                            ChannelDetailView(
                                channel: channel,
                                radioSnapshot: radioSnapshot,
                                actions: actions
                            )
                        } label: {
                            ChannelRow(channel: channel)
                        }
                        .swipeActions(edge: .trailing) {
                            // Not role: .destructive — that role animates the
                            // row away on the tap, and this button only asks.
                            // The row must stand still behind the
                            // confirmation.
                            Button {
                                pendingLeave = channel
                            } label: {
                                Label("Leave", systemImage: "trash")
                            }
                            .tint(.red)
                        }
                    }
                }
            }
            if !unknownDeviceChannels.isEmpty {
                Section {
                    ForEach(unknownDeviceChannels) { entry in
                        Button {
                            explainedUnknown = entry
                        } label: {
                            LabeledContent("Channel \(entry.identifierHex)") {
                                Text("On radio")
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("On the radio only")
                } footer: {
                    Text("The radio's own identity has joined these. It reports identifiers, never keys, so they cannot be named or used from this phone.")
                }
            }
        }
        // See the note in PeersView: leaving a channel changes storage, and
        // the published reload needs an animated transaction to slide the
        // row out rather than blink it away.
        .animation(.default, value: channels)
        .navigationTitle("Channels")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Join Channel…") { showsJoin = true }
                    Button("New Private Channel…") { showsCreate = true }
                } label: {
                    Label("Add channel", systemImage: "plus")
                }
                .disabled(actions.join == nil)
            }
        }
        .sheet(isPresented: $showsJoin) {
            NavigationStack {
                ChannelJoinView(actions: actions, rejoinable: suggested)
            }
        }
        .sheet(isPresented: $showsCreate) {
            NavigationStack {
                ChannelCreateView(actions: actions)
            }
        }
        .confirmationDialog(
            pendingLeave.map { "Leave “\($0.title)”?" } ?? "",
            isPresented: Binding(
                get: { pendingLeave != nil },
                set: { if !$0 { pendingLeave = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Leave Channel", role: .destructive) {
                if let channel = pendingLeave {
                    Task { _ = await actions.leave?(channel) }
                }
                pendingLeave = nil
            }
            Button("Cancel", role: .cancel) { pendingLeave = nil }
        } message: {
            if let channel = pendingLeave {
                Text(
                    channel.canRejoinAfterLeaving
                        ? "You can join again at any time using the channel's name."
                        : "The channel key is deleted from this phone. Joining again requires a new invitation."
                )
            }
        }
        .alert(
            "Channel \(explainedUnknown?.identifierHex ?? "")",
            isPresented: Binding(
                get: { explainedUnknown != nil },
                set: { if !$0 { explainedUnknown = nil } }
            )
        ) {
            Button("OK", role: .cancel) { explainedUnknown = nil }
        } message: {
            Text("The companion radio's own identity has joined this channel, but this phone does not hold its key. Join it here with its name or invitation to see it by name.")
        }
    }

    private var joined: [ChannelSummary] {
        channels.filter(\.isJoined)
    }

    /// Built-in channels the user has left, offered again only inside the join
    /// sheet. Leaving one is a decision, and the list this tab shows is what
    /// the user is actually in — not a standing invitation to reconsider.
    private var suggested: [ChannelSummary] {
        channels.filter { $0.kind == .builtin && !$0.isJoined }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Channels", systemImage: "number")
        } description: {
            Text("A channel is a shared key. Join one by name if it is public, or with an invitation if it is private.")
        } actions: {
            Button("Join Channel…") { showsJoin = true }
                .buttonStyle(.borderedProminent)
            Button("New Private Channel…") { showsCreate = true }
        }
    }

}

/// One channel in a list: what it is called, what kind it is, and who has
/// joined it.
struct ChannelRow: View {
    let channel: ChannelSummary
    var showsScope = true

    var body: some View {
        HStack(spacing: 12) {
            ChannelAvatar(channel: channel, size: 40)
            content
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(channel.title)
                if !channel.notificationsEnabled && channel.isJoined {
                    Image(systemName: "bell.slash")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Notifications off")
                }
            }
            HStack(spacing: 6) {
                Text(channel.kindLabel)
                Text(channel.channelIDHex)
                    .font(.caption.monospaced())
                if showsScope, let scope = scopeLabel {
                    Text("· \(scope)")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private var scopeLabel: String? {
        switch (channel.joinedPhone, channel.joinedDevice) {
        case (true, true): "Phone and radio"
        case (true, false): "Phone"
        case (false, true): "Radio"
        case (false, false): nil
        }
    }
}

#Preview {
    NavigationStack {
        ChannelsView(
            channels: [
                ChannelSummary(
                    id: UUID(),
                    kind: .builtin,
                    canonicalName: "public",
                    name: "Public",
                    alias: nil,
                    channelIDHex: "7f21",
                    tint: Data([0x7f, 0x21, 0xC4]),
                    regionCode: nil,
                    maxFloodHops: 5,
                    joinedPhone: true,
                    joinedDevice: false,
                    notificationsEnabled: false,
                    joinedAt: .now
                ),
                ChannelSummary(
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
                    joinedDevice: true,
                    notificationsEnabled: true,
                    joinedAt: .now
                ),
            ],
            unknownDeviceChannels: [UnknownDeviceChannel(identifier: Data([0x3f, 0xa1]))],
            radioSnapshot: .previewReady,
            actions: .unavailable
        )
    }
}
