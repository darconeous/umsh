import SwiftUI

/// What an open conversation *is*, reached from the transcript header.
///
/// Both kinds of conversation answer the question the same way: a row leading
/// to whoever — or whatever — is on the other end, what the transcript holds,
/// and the conversation-level actions underneath. The sheet is deliberately
/// not the peer or channel sheet itself; those describe a node and a key,
/// which outlive any one conversation with them.
struct DirectConversationDetailView: View {
    let conversation: DirectConversationSummary
    let radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    var peerActions: PeerActions = .unavailable
    var messageActions: ChatMessageActions = .unavailable
    var updateDraft: ((Int64, String) async -> Void)? = nil
    var sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil
    /// Erase the transcript. Absent when there is no store to erase it from.
    var clearMessages: (() async -> Void)? = nil

    private var peer: PeerSummary { conversation.peer }

    var body: some View {
        Form {
            Section {
                NavigationLink {
                    PeerDetailView(
                        peer: peer,
                        radioSnapshot: .constant(radioSnapshot),
                        conversations: $conversations,
                        actions: peerActions,
                        updateDraft: updateDraft,
                        sendMessage: sendMessage,
                        messageActions: messageActions
                    )
                } label: {
                    HStack(spacing: 12) {
                        PeerAvatar(hint: peer.identity.hint, diameter: 52)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(peer.displayName)
                                .font(.headline)
                            Text(peer.isUlcpDevice ? "Companion radio identity" : peer.role.label)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } footer: {
                Text("Everything this phone knows about the node on the other end.")
            }
            Section("Conversation") {
                LabeledContent("Node hint") {
                    Text(peer.identity.hint.text)
                        .font(.body.monospaced())
                }
                LabeledContent("Messages", value: "\(conversation.messages.count)")
            }
            if let clearMessages {
                ClearMessagesSection(
                    messageCount: conversation.messages.count,
                    warning: "The message history on this phone is erased. Nothing is sent, and \(peer.displayName) keeps their copy.",
                    clear: clearMessages
                )
            }
        }
        .navigationTitle(peer.displayName)
    }
}

/// The channel behind an open group conversation, reached from the transcript
/// header the way a peer's profile is.
struct ChannelConversationDetailView: View {
    let conversation: ChannelConversationSummary
    let radioSnapshot: RadioSnapshot
    /// The channel-management operations, for the row leading to the channel
    /// itself. `enterConversation` is deliberately not offered here: it is
    /// this conversation.
    var channelActions: ChannelActions = .unavailable
    var setNotifications: (ChannelSummary, Bool) async -> Void = { _, _ in }
    var clearMessages: (() async -> Void)? = nil

    /// What the toggle shows until the store comes back with the new value.
    /// Without it the switch springs back mid-write, which reads as a failure
    /// even though the write is on its way.
    @State private var pendingNotifications: Bool?

    var body: some View {
        Form {
            Section {
                NavigationLink {
                    ChannelDetailView(
                        channel: conversation.channel,
                        radioSnapshot: radioSnapshot,
                        actions: channelWithoutConversationEntry
                    )
                } label: {
                    HStack(spacing: 12) {
                        ChannelAvatar(channel: conversation.channel, size: 52)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(conversation.channel.title)
                                .font(.headline)
                            Text(conversation.channel.kindLabel)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } footer: {
                Text("The channel itself: who has joined it, how to invite someone, and how to leave.")
            }
            Section {
                Toggle("Notifications", isOn: Binding(
                    get: { pendingNotifications ?? conversation.channel.notificationsEnabled },
                    set: { enabled in
                        pendingNotifications = enabled
                        Task {
                            await setNotifications(conversation.channel, enabled)
                            // The store has reloaded by now, so hand the toggle
                            // back to it — including when the write failed and
                            // the honest answer is the old value.
                            pendingNotifications = nil
                        }
                    }
                ))
            } footer: {
                Text("Messages in this channel still arrive and still count as unread. This decides only whether they interrupt you.")
            }
            Section("Conversation") {
                LabeledContent("Identifier") {
                    Text(conversation.channel.channelIDHex)
                        .font(.body.monospaced())
                }
                LabeledContent("Messages", value: "\(conversation.messages.count)")
            }
            if let clearMessages {
                ClearMessagesSection(
                    messageCount: conversation.messages.count,
                    warning: "The message history on this phone is erased. Nothing is sent, and everyone else in the channel keeps their copy.",
                    clear: clearMessages
                )
            }
            let behavior = conversation.channel.protocolBehavior
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
        .navigationTitle(conversation.channel.title)
    }

    /// Entering the conversation is what got the user here, so the channel
    /// sheet must not offer it as a way onward.
    private var channelWithoutConversationEntry: ChannelActions {
        var actions = channelActions
        actions.enterConversation = nil
        return actions
    }
}

/// Erase a conversation's transcript, worded the same for both kinds.
///
/// Kept apart from deleting the conversation: the row, its draft, and its
/// place in the wire stream all survive, so this is the action for a
/// conversation the user intends to keep using.
struct ClearMessagesSection: View {
    let messageCount: Int
    let warning: String
    let clear: () async -> Void

    @State private var confirms = false

    var body: some View {
        Section {
            Button("Clear All Messages", role: .destructive) { confirms = true }
                .disabled(messageCount == 0)
                .confirmationDialog(
                    "Clear all messages?",
                    isPresented: $confirms,
                    titleVisibility: .visible
                ) {
                    Button(
                        messageCount == 1 ? "Clear 1 Message" : "Clear \(messageCount) Messages",
                        role: .destructive
                    ) {
                        Task { await clear() }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text(warning)
                }
        } footer: {
            Text(warning)
        }
    }
}
