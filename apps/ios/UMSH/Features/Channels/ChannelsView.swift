import SwiftUI

/// The Channels tab: which channels this identity has joined, and the ways in.
///
/// A channel is a shared key, so this list is membership, not a directory—
/// nothing here was discovered over the air, and nothing on the air can add to
/// it. `public` and `EMERGENCY` are seeded joined; leaving either keeps the key
/// so the join sheet can offer it back, but this list shows only what the user
/// is actually in.
struct ChannelsView: View {
    let channels: [ChannelSummary]
    let actions: ChannelActions

    @State private var showsJoin = false
    @State private var showsCreate = false
    @State private var pendingLeave: ChannelSummary?
    @State private var failure: FailureNotice?

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
                            ChannelDetailView(channel: channel, actions: actions)
                        } label: {
                            ChannelRow(channel: channel)
                        }
                        .swipeActions(edge: .trailing) {
                            // Not role: .destructive—that role animates the
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
        }
        // See the note in PeersView: leaving a channel changes storage, and
        // the published reload needs an animated transaction to slide the
        // row out rather than blink it away.
        .animation(UMSHAnimation.list, value: channels)
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
            pendingLeave?.leaveTitle ?? "",
            isPresented: Binding(
                get: { pendingLeave != nil },
                set: { if !$0 { pendingLeave = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Leave Channel", role: .destructive) {
                if let channel = pendingLeave, let leave = actions.leave {
                    Task {
                        await $failure.attempt(Self.notLeftTitle) { try await leave(channel) }
                    }
                }
                pendingLeave = nil
            }
            Button("Cancel", role: .cancel) { pendingLeave = nil }
        } message: {
            if let channel = pendingLeave {
                Text(verbatim: channel.leaveMessage)
            }
        }
        .failureAlert($failure)
    }

    private static var notLeftTitle: String {
        String(localized: "Channel not left", comment: "Alert title: leaving a channel failed.")
    }

    private var joined: [ChannelSummary] {
        channels.filter(\.joinedPhone)
    }

    /// Built-in channels the user has left, offered again only inside the join
    /// sheet. Leaving one is a decision, and the list this tab shows is what
    /// the user is actually in—not a standing invitation to reconsider.
    private var suggested: [ChannelSummary] {
        channels.filter { $0.kind == .builtin && !$0.joinedPhone }
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
                    notificationsEnabled: true,
                    joinedAt: .now
                ),
            ],
            actions: .unavailable
        )
    }
}
