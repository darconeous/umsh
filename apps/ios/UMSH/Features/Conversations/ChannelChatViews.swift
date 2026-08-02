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
                            // A plain button is only as tappable as its label
                            // is wide, and a channel row does not reach the
                            // edge on its own. Rows are tapped anywhere.
                            ChannelRow(channel: channel, showsScope: false)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
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
    /// Everything the peer sheet needs to be itself once this member turns out
    /// to be a node this phone knows — the same bundle the direct-conversation
    /// sheet hands it, so the peer is the same wherever it is reached from.
    @Binding var conversations: [DirectConversationSummary]
    let radioSnapshot: RadioSnapshot
    var peerActions: PeerActions = .unavailable
    var messageActions: ChatMessageActions = .unavailable
    var updateDraft: ((Int64, String) async -> Void)? = nil
    var sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil

    @State private var requested = false

    var body: some View {
        Form {
            // A member who is also a saved peer is a node, with everything a
            // node has — a route, a role, a way to message them directly. The
            // avatar in the transcript is the only thing pointing at it, so it
            // has to lead somewhere rather than stopping at four fields.
            if let knownPeer {
                Section {
                    NavigationLink {
                        PeerDetailView(
                            peer: knownPeer,
                            radioSnapshot: .constant(radioSnapshot),
                            conversations: $conversations,
                            actions: peerActions,
                            updateDraft: updateDraft,
                            sendMessage: sendMessage,
                            messageActions: messageActions
                        )
                    } label: {
                        HStack(spacing: 12) {
                            PeerAvatar(hint: knownPeer.identity.hint, diameter: 52)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(knownPeer.displayName)
                                    .font(.headline)
                                Text(
                                    knownPeer.isUlcpDevice
                                        ? "Companion radio identity"
                                        : knownPeer.role.label
                                )
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                        }
                    }
                } footer: {
                    Text("Everything this phone knows about the node this member is speaking from.")
                }
            }
            Section("Member") {
                LabeledContent("Name", value: member.displayName)
                    .copyable(member.displayName)
                if let handle = member.handle, !handle.isEmpty, handle != member.displayName {
                    LabeledContent("Calls themselves", value: handle)
                        .copyable(handle)
                }
                LabeledContent("Hint") {
                    Text(member.id)
                        .font(.body.monospaced())
                }
                .copyable(member.id)
                if let address = member.address {
                    LabeledContent("Address") {
                        Text(address)
                            .font(.caption.monospaced())
                            .lineLimit(2)
                            .truncationMode(.middle)
                    }
                    .copyable(address)
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
                    .copyable(hint)
                    if let address = message.senderAddress {
                        LabeledContent("Address") {
                            Text(address)
                                .font(.caption.monospaced())
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                        .copyable(address)
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
                        // Stored in trace-route order, nearest us first;
                        // reversed here so the arrows read the way the message
                        // travelled — sender toward this phone.
                        let route = reception.routeHints
                            .reversed()
                            .map { $0.map { String(format: "%02x", $0) }.joined() }
                            .joined(separator: " → ")
                        LabeledContent("Route") {
                            Text(route)
                                .font(.caption.monospaced())
                        }
                        .copyable(route)
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
