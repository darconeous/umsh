import SwiftUI

/// A participant in a channel's group conversation.
///
/// Membership is possession of the key, so there is no roster to consult—
/// a member is only known once they have said something, and then only by
/// the hint their message claimed.
struct ChannelMember: Identifiable, Hashable, Sendable {
    let hint: Data
    /// The hint as the core renders it, when it has been.
    let nodeHint: MeshNodeHint?
    let address: String?
    /// The name this member attached to their message—their own claim,
    /// which the channel key authenticates as coming from *a* member and
    /// nothing more.
    let handle: String?
    let displayName: String

    var id: Data { hint }
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
                // the conversation opens with it—unlike joining from
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
    /// to be a node this phone knows—the same bundle the direct-conversation
    /// sheet hands it, so the peer is the same wherever it is reached from.
    @Binding var conversations: [DirectConversationSummary]
    let radioSnapshot: RadioSnapshot
    var peerActions: PeerActions = .unavailable
    var messageActions: ChatMessageActions = .unavailable
    var updateDraft: ((Int64, String) async -> AppOperationResult)? = nil
    var sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil

    @State private var requested = false

    var body: some View {
        Form {
            // A member who is also a saved peer is a node, with everything a
            // node has—a route, a role, a way to message them directly. The
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
                        IdentityHeader { diameter in
                            PeerAvatar(peer: knownPeer, diameter: diameter)
                        } content: {
                            IdentityHeaderText(
                                title: knownPeer.displayName,
                                subtitle: knownPeer.isUlcpDevice ? "Companion radio identity" : knownPeer.role.label
                            )
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
                if let hint = member.nodeHint?.text {
                    LabeledContent("Hint") {
                        Text(hint)
                            .font(.body.monospaced())
                    }
                    .copyable(hint)
                }
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
    var renderRouterHint: ((Data) async -> MeshRouterHint?)? = nil
    /// How a repeater this phone knows opens its page.
    var peerBrowsing: RemotePeerBrowsing? = nil
    /// Asks the node behind a hint who it is, by way of the repeaters
    /// before it.
    var identifyRepeater: ((Data, [Data]) async -> Bool)? = nil
    let dismiss: () -> Void

    /// The route's hints as the core renders them, in trace-route order:
    /// nearest this phone first.
    @State private var route: [MeshRouterHint] = []

    private var knownPeers: [PeerSummary] { peerBrowsing?.knownPeers ?? [] }

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
            if message.isOutbound, let repeats = message.repeats {
                Section {
                    // Each was heard forwarding this phone's own frame, so it
                    // is in direct range: asked with no repeaters before it.
                    ForEach(repeats.repeaters, id: \.hint) { repeater in
                        hintRow(repeater.hint, precededBy: [])
                    }
                    if repeats.anonymous > 0 {
                        LabeledContent("Unidentified", value: "\(repeats.anonymous)")
                    }
                    if repeats.count == 0 {
                        Text("None heard")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Repeated By")
                } footer: {
                    ambiguityNote(for: repeats.repeaters.map(\.hint))
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
                    LabeledContent(
                        "Hop count",
                        value: reception.hopCount.map { $0 == 1 ? "1 (direct)" : "\($0)" }
                            ?? "Unknown source route"
                    )
                    if let rssi = reception.rssiDbm {
                        LabeledContent("Signal", value: "\(rssi) dBm")
                    }
                    if let snr = reception.snrCentibels {
                        LabeledContent(
                            "Signal-to-noise",
                            value: String(format: "%.1f dB", Double(snr) / 10)
                        )
                    }
                    if let lqi = reception.lqi {
                        LabeledContent("Link quality", value: "\(lqi)")
                    }
                    LabeledContent(
                        "Source",
                        value: reception.sourceAuthenticated ? "Authenticated" : "Unauthenticated"
                    )
                }
                if !route.isEmpty {
                    Section {
                        // Listed the way the message traveled, sender first.
                        // Each hop is asked by way of the ones nearer this
                        // phone, which come before it in trace order.
                        ForEach(Array(route.enumerated().reversed()), id: \.offset) { index, hint in
                            hintRow(hint, precededBy: Array(route[..<index]))
                        }
                    } header: {
                        Text("Route")
                    } footer: {
                        ambiguityNote(for: route)
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
        .task(id: message.reception?.routeHints) {
            guard let hints = message.reception?.routeHints, let renderRouterHint else {
                route = []
                return
            }
            var rendered: [MeshRouterHint] = []
            for hint in hints {
                guard let value = await renderRouterHint(hint) else { return }
                rendered.append(value)
            }
            route = rendered
        }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
    }

    /// One repeater. A node this phone knows opens its page; a hint that
    /// names none offers to ask the node behind it.
    @ViewBuilder
    private func hintRow(_ hint: MeshRouterHint, precededBy preceding: [MeshRouterHint]) -> some View {
        let named = RouterHintNaming.match(hint, among: knownPeers)
        if let named, let peerBrowsing {
            NavigationLink {
                peerBrowsing.open(named)
            } label: {
                RouterHintRow(hint: hint, named: named)
            }
        } else {
            RouterHintRow(
                hint: hint,
                named: named,
                discover: identifyRepeater.map { identify in
                    { await identify(hint.bytes, preceding.map(\.bytes)) }
                }
            )
        }
    }

    @ViewBuilder
    private func ambiguityNote(for hints: [MeshRouterHint]) -> some View {
        if hints.contains(where: { RouterHintNaming.match($0, among: knownPeers) != nil }) {
            Text(RouterHintNaming.ambiguityNote)
        }
    }
}
