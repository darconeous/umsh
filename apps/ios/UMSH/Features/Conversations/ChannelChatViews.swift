import SwiftUI

/// A participant in a channel's group conversation.
///
/// Membership is possession of the key, so there is no roster to consult —
/// a member is only known once they have said something, and then only by
/// the hint their message claimed.
struct ChannelMember: Identifiable, Hashable, Sendable {
    let hint: Data
    let address: String?
    /// The name this member attached to their message — their own claim,
    /// which the channel key authenticates as coming from *a* member and
    /// nothing more.
    let handle: String?
    let displayName: String

    var id: String { hint.map { String(format: "%02x", $0) }.joined() }
}

/// Start a group chat in a channel already joined, or join one to chat in.
///
/// Joining a channel from Settings deliberately does not create a
/// conversation; this is where one is asked for.
struct ChannelChatChooserView: View {
    let channels: [ChannelSummary]
    let actions: ChannelActions
    let start: (ChannelSummary) async -> Void
    let startAfterJoin: (MeshChannelPreview) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var showsJoin = false

    var body: some View {
        List {
            if channels.isEmpty {
                Section {
                    ContentUnavailableView {
                        Label("No Channels to Open", systemImage: "number")
                    } description: {
                        Text("Every channel you have joined already has a conversation.")
                    }
                }
            } else {
                Section {
                    ForEach(channels) { channel in
                        Button {
                            Task { await start(channel) }
                        } label: {
                            ChannelRow(channel: channel, showsScope: false)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            Section {
                Button("Join a Channel…") { showsJoin = true }
                    .disabled(actions.join == nil)
            }
        }
        .navigationTitle("New Channel Chat")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .sheet(isPresented: $showsJoin) {
            NavigationStack {
                // Joining from here is a request to talk in the channel, so
                // the conversation opens with it — unlike joining from
                // Settings, which is membership alone.
                ChannelJoinView(
                    actions: actions,
                    rejoinable: [],
                    onJoined: { preview in
                        showsJoin = false
                        await startAfterJoin(preview)
                    }
                )
            }
        }
    }
}

/// What this phone knows about one channel member, and the one thing it can
/// do about a member it does not recognize.
struct ChannelMemberSheet: View {
    let member: ChannelMember
    let knownPeer: PeerSummary?
    /// Absent when there is no channel to ask over.
    let requestIdentity: ((Data) async -> Void)?
    let dismiss: () -> Void

    @State private var requested = false

    var body: some View {
        Form {
            Section("Member") {
                LabeledContent("Name", value: member.displayName)
                if let handle = member.handle, !handle.isEmpty, handle != member.displayName {
                    LabeledContent("Calls themselves", value: handle)
                }
                LabeledContent("Hint") {
                    Text(member.id)
                        .font(.body.monospaced())
                }
                if let address = member.address {
                    LabeledContent("Address") {
                        Text(address)
                            .font(.caption.monospaced())
                            .lineLimit(2)
                            .truncationMode(.middle)
                    }
                }
            }
            if knownPeer == nil, let requestIdentity {
                Section {
                    Button(requested ? "Identity Requested" : "Request Identity") {
                        requested = true
                        Task { await requestIdentity(member.hint) }
                    }
                    .disabled(requested)
                } footer: {
                    Text(
                        member.address == nil
                            ? "A channel message carries only a short hint. Asking over the channel invites this member to send their full identity."
                            : "This member has not been saved as a peer. Asking invites them to send their current identity."
                    )
                }
            }
        }
        .navigationTitle(member.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
    }
}

/// The channel behind an open group conversation, reached from the transcript
/// header the way a peer's profile is.
struct ChannelConversationDetailView: View {
    let conversation: ChannelConversationSummary

    var body: some View {
        Form {
            Section {
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
            Section("Channel") {
                LabeledContent("Identifier") {
                    Text(conversation.channel.channelIDHex)
                        .font(.body.monospaced())
                }
                LabeledContent("Messages", value: "\(conversation.messages.count)")
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
}

/// What the radio observed of one received message.
///
/// Reachability in a mesh is not obvious from the outside, so a message that
/// arrived says how it got here: how far, by what route, and how strong.
struct MessageDetailsSheet: View {
    let message: ChatMessageSummary
    let dismiss: () -> Void

    var body: some View {
        Form {
            Section("Message") {
                LabeledContent("Direction", value: message.isOutbound ? "Sent" : "Received")
                LabeledContent(
                    "Time",
                    value: Date(timeIntervalSince1970: Double(message.createdAtMilliseconds) / 1000)
                        .formatted(date: .abbreviated, time: .standard)
                )
                if let wireID = message.wireID {
                    LabeledContent("Wire ID", value: "\(wireID)")
                }
            }
            if let hint = message.senderHintLabel {
                Section("Sender") {
                    LabeledContent("Hint") {
                        Text(hint)
                            .font(.body.monospaced())
                    }
                    if let address = message.senderAddress {
                        LabeledContent("Address") {
                            Text(address)
                                .font(.caption.monospaced())
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                    }
                }
            }
            if let reception = message.reception {
                Section("Reception") {
                    if let hops = reception.hopCount {
                        LabeledContent(
                            "Hops",
                            value: hops == 0 ? "Direct" : "\(hops)"
                        )
                    }
                    if let rssi = reception.rssiDbm {
                        LabeledContent("Signal", value: "\(rssi) dBm")
                    }
                    if let snr = reception.snrCentibels {
                        LabeledContent(
                            "Signal-to-noise",
                            value: String(format: "%.1f dB", Double(snr) / 100)
                        )
                    }
                    if let lqi = reception.lqi {
                        LabeledContent("Link quality", value: "\(lqi)")
                    }
                    LabeledContent(
                        "Source",
                        value: reception.sourceAuthenticated ? "Authenticated" : "Unauthenticated"
                    )
                    if !reception.routeHints.isEmpty {
                        LabeledContent("Route") {
                            // Stored in trace-route order, nearest us first;
                            // reversed here so the arrows read the way the
                            // message travelled — sender toward this phone.
                            Text(
                                reception.routeHints
                                    .reversed()
                                    .map { $0.map { String(format: "%02x", $0) }.joined() }
                                    .joined(separator: " → ")
                            )
                            .font(.caption.monospaced())
                        }
                    }
                }
            } else if !message.isOutbound {
                Section {
                    Text("This message was recorded before reception details were kept.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Message Details")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
    }
}
