import SwiftUI
import UIKit

struct ConversationsView: View {
    @Binding var conversations: [DirectConversationSummary]
    let radioSnapshot: RadioSnapshot
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let savePeer: (MeshNodeURIPreview, PeerImportDetails, Bool) async -> DirectConversationSummary?
    let updateDraft: (Int64, String) async -> Void
    let sendMessage: (DirectConversationSummary, String) async -> MessageSendResult
    var messageActions: ChatMessageActions = .unavailable
    var deleteConversation: (DirectConversationSummary) async -> Void = { _ in }
    var updateAlias: ((PeerSummary, String?) async -> Bool)? = nil
    // Owned by the app root so URL-scheme imports can open a transcript
    // directly from outside this view.
    @Binding var openedConversation: DirectConversationSummary?

    @State private var showsImport = false
    @State private var conversationPendingDeletion: DirectConversationSummary?

    var body: some View {
        List {
            if conversations.isEmpty {
                ContentUnavailableView {
                    Label("No conversations", systemImage: "bubble.left.and.bubble.right")
                } description: {
                    Text("Import a peer to open a direct transcript and begin messaging off-grid.")
                } actions: {
                    Button("Import peer") { showsImport = true }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                Section("Direct messages") {
                    ForEach(conversations) { conversation in
                        NavigationLink(value: conversation.id) {
                            ConversationRow(conversation: conversation)
                        }
                        .swipeActions(edge: .trailing) {
                            Button("Delete", systemImage: "trash", role: .destructive) {
                                conversationPendingDeletion = conversation
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Conversations")
        .navigationDestination(for: Int64.self) { conversationID in
            if let conversation = binding(for: conversationID) {
                DirectConversationView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions,
                    updateAlias: updateAlias
                )
            }
        }
        .navigationDestination(item: $openedConversation) { conversation in
            if let conversation = binding(for: conversation.id) {
                DirectConversationView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions,
                    updateAlias: updateAlias
                )
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("New", systemImage: "square.and.pencil") { showsImport = true }
            }
        }
        .confirmationDialog(
            "Delete this conversation?",
            isPresented: Binding(
                get: { conversationPendingDeletion != nil },
                set: { if !$0 { conversationPendingDeletion = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete Conversation", role: .destructive) {
                if let conversation = conversationPendingDeletion {
                    conversationPendingDeletion = nil
                    Task { await deleteConversation(conversation) }
                }
            }
        } message: {
            Text("The message history on this phone is removed. The peer keeps their copy.")
        }
        .sheet(isPresented: $showsImport) {
            NavigationStack {
                NodeImportView(
                    inspectPeerIdentity: inspectPeerIdentity,
                    save: { preview, details, startConversation in
                        let conversation = await savePeer(preview, details, startConversation)
                        showsImport = false
                        if startConversation {
                            openedConversation = conversation
                        }
                    }
                )
            }
        }
    }

    private func binding(for conversationID: Int64) -> Binding<DirectConversationSummary>? {
        guard let fallback = conversations.first(where: { $0.id == conversationID }) else { return nil }
        return Binding(
            get: {
                conversations.first(where: { $0.id == conversationID }) ?? fallback
            },
            set: { updated in
                guard let index = conversations.firstIndex(where: { $0.id == conversationID }) else {
                    return
                }
                conversations[index] = updated
            }
        )
    }
}

private struct ConversationRow: View {
    let conversation: DirectConversationSummary

    var body: some View {
        HStack(spacing: 12) {
            PeerAvatar(hint: conversation.peer.identity.hint)
            VStack(alignment: .leading, spacing: 3) {
                Text(conversation.peer.displayName)
                Text(preview)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    private var preview: String {
        if !conversation.draftText.isEmpty {
            return "Draft: \(conversation.draftText)"
        }
        guard let last = conversation.messages.last else { return "No messages yet" }
        if last.isDeleted { return "Message deleted" }
        return last.isOutbound ? "You: \(last.body)" : last.body
    }
}

struct NodeImportView: View {
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let save: (MeshNodeURIPreview, PeerImportDetails, Bool) async -> Void
    // Prefilled by URL-scheme opens (Camera scan, tapped umsh: link);
    // validation then runs immediately instead of waiting for the button.
    var initialInput: String? = nil

    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var preview: MeshNodeURIPreview?
    @State private var problem: String?
    @State private var isInspecting = false
    @State private var name = ""
    @State private var kind = PeerKind.person
    @State private var isContact = true

    var body: some View {
        Form {
            Section("Peer identity") {
                TextField("UMSH URI, Base58 address, or 32-byte hex key", text: $input, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button("Validate identity") { Task { await inspect() } }
                    .disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isInspecting)
            }

            if let preview {
                Section("Node Identity Preview") {
                    HStack(spacing: 12) {
                        PeerAvatar(hint: preview.publicIdentity.hint)
                        VStack(alignment: .leading) {
                            Text(preview.publicIdentity.hint.text)
                            Text(previewCaption)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    CanonicalAddressView(address: preview.publicIdentity.canonicalAddress)
                    if let identity = preview.identity {
                        AdvertisedIdentityRows(identity: identity)
                    }
                    Text("Previewing does not save this peer or transmit anything.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Local details") {
                    TextField("Name (optional)", text: $name)
                    Picker("Type", selection: $kind) {
                        ForEach(PeerKind.allCases) { kind in
                            Text(kind.label).tag(kind)
                        }
                    }
                    Toggle("Save as contact", isOn: $isContact)
                    Text("Name and type are stored only on this phone; they are not authenticated claims from the peer.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section {
                    Button("Message") {
                        Task { await save(preview, details, true) }
                    }
                    .buttonStyle(.borderedProminent)
                    Button(isContact ? "Save Contact" : "Save Peer") {
                        Task { await save(preview, details, false) }
                    }
                }
            }

            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Import peer")
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

    private func inspect() async {
        isInspecting = true
        defer { isInspecting = false }
        let result = await inspectPeerIdentity(input.trimmingCharacters(in: .whitespacesAndNewlines))
        switch result {
        case let .success(value):
            preview = value
            problem = nil
        case .failure:
            preview = nil
            problem = "Enter a valid UMSH node URI, canonical Base58 address, or 64-digit hexadecimal public key. Nothing was imported."
        }
    }

    private var details: PeerImportDetails {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return PeerImportDetails(
            alias: trimmed.isEmpty ? nil : trimmed,
            kind: kind,
            isContact: isContact
        )
    }

    private var previewCaption: String {
        guard let preview else { return "" }
        if preview.identity != nil {
            return "Includes advertised identity details"
        }
        return preview.hasIdentityData
            ? "Identity metadata present but unreadable"
            : "Public key only"
    }
}

struct DirectConversationView: View {
    private static let bottomAnchorID = "chat-transcript-bottom"
    // Following the live edge is an explicit, sticky mode. Appending a row can
    // temporarily increase the measured distance from the bottom before the
    // compensating scroll runs; that layout change must not look like the user
    // scrolled away. Only user-driven scrolling can leave follow mode.
    private static let stopFollowingDistance: CGFloat = 360
    private static let resumeFollowingDistance: CGFloat = 240

    @Binding var conversation: DirectConversationSummary
    let radioSnapshot: RadioSnapshot
    let updateDraft: (Int64, String) async -> Void
    let sendMessage: (DirectConversationSummary, String) async -> MessageSendResult
    let messageActions: ChatMessageActions
    let updateAlias: ((PeerSummary, String?) async -> Bool)?

    @State private var draft: String
    @State private var showsPeerProfile = false
    @State private var showsBlockedReason = false
    @State private var sendFailureMessage: String?
    @State private var editingMessage: ChatMessageSummary?
    @State private var editDraft = ""
    @State private var deletingMessage: ChatMessageSummary?
    @State private var followsLatestMessage = true
    @State private var userIsScrollingTranscript = false
    @State private var transcriptDistanceFromBottom: CGFloat = 0
    @State private var outgoingScrollRequest = 0
    @State private var scrollToBottomScheduled = false

    init(
        conversation: Binding<DirectConversationSummary>,
        radioSnapshot: RadioSnapshot,
        updateDraft: @escaping (Int64, String) async -> Void,
        sendMessage: @escaping (DirectConversationSummary, String) async -> MessageSendResult,
        messageActions: ChatMessageActions = .unavailable,
        updateAlias: ((PeerSummary, String?) async -> Bool)? = nil
    ) {
        _conversation = conversation
        self.radioSnapshot = radioSnapshot
        self.updateDraft = updateDraft
        self.sendMessage = sendMessage
        self.messageActions = messageActions
        self.updateAlias = updateAlias
        _draft = State(initialValue: conversation.wrappedValue.draftText)
    }

    var body: some View {
        VStack(spacing: 0) {
            if conversation.messages.isEmpty {
                ContentUnavailableView {
                    Label("No messages yet", systemImage: "bubble.left")
                } description: {
                    Text("Messages with \(conversation.peer.displayName) will appear here.")
                }
                .frame(maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        // A plain VStack, deliberately: LazyVStack re-measures
                        // rows as they enter the viewport, and combined with
                        // an animated scrollTo to a bottom anchor plus the
                        // geometry observer below, oscillating row heights
                        // can wedge the main thread in a layout loop (screen
                        // renders but touches never deliver).
                        VStack(spacing: 10) {
                            let lastOutboundID = conversation.messages.last(
                                where: { $0.isOutbound && !$0.isDeleted }
                            )?.id
                            ForEach(conversation.messages) { message in
                                ChatMessageBubble(
                                    message: message,
                                    isMostRecentOutbound: message.id == lastOutboundID,
                                    onEdit: message.isOutbound && !message.isDeleted
                                        ? {
                                            editDraft = message.body
                                            editingMessage = message
                                        }
                                        : nil,
                                    onDelete: message.isOutbound && !message.isDeleted
                                        ? { deletingMessage = message }
                                        : nil
                                )
                                .id(message.id)
                            }
                            Color.clear
                                .frame(height: 1)
                                .id(Self.bottomAnchorID)
                        }
                        .padding()
                    }
                    .defaultScrollAnchor(.bottom)
                    // Keyboard show/hide resizes the container; keep the
                    // reader's distance from the bottom constant instead of
                    // the default top-anchored offset, which hides the
                    // newest messages behind the keyboard.
                    .defaultScrollAnchor(.bottom, for: .sizeChanges)
                    .onAppear {
                        guard !conversation.messages.isEmpty else { return }
                        // Initial presentation always opens at the newest
                        // message. Conditional auto-follow applies only after
                        // the reader has had a chance to scroll upward.
                        scheduleScrollToBottom(proxy, animated: false)
                    }
                    .onScrollGeometryChange(for: CGFloat.self) { geometry in
                        // Whole-point granularity: sub-pixel measurement
                        // jitter must not feed a state-write → layout →
                        // state-write feedback loop.
                        max(0, geometry.contentSize.height - geometry.visibleRect.maxY)
                            .rounded()
                    } action: { _, distance in
                        transcriptDistanceFromBottom = distance
                        updateFollowState(
                            distanceFromBottom: distance,
                            userDriven: userIsScrollingTranscript
                        )
                    }
                    .onScrollPhaseChange { _, phase in
                        switch phase {
                        case .tracking, .interacting, .decelerating:
                            userIsScrollingTranscript = true
                            updateFollowState(
                                distanceFromBottom: transcriptDistanceFromBottom,
                                userDriven: true
                            )
                        case .idle, .animating:
                            userIsScrollingTranscript = false
                        }
                    }
                    .onChange(of: conversation.messages) { _, messages in
                        guard !messages.isEmpty, followsLatestMessage else { return }
                        // Follow inserts as well as live body/delivery-state
                        // mutations. Deferring lets SwiftUI finish measuring
                        // the changed final bubble before targeting the edge.
                        scheduleScrollToBottom(proxy)
                    }
                    .onChange(of: outgoingScrollRequest) { _, _ in
                        // Sending is an explicit navigation to the new item,
                        // unlike a passive update while reading older history.
                        followsLatestMessage = true
                        scheduleScrollToBottom(proxy)
                    }
                }
                .frame(maxHeight: .infinity)
            }

            Divider()
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .bottom, spacing: 8) {
                    ZStack(alignment: .topLeading) {
                        HardwareAwareMessageEditor(
                            text: $draft,
                            onHardwareReturn: { Task { await send() } }
                        )
                        if draft.isEmpty {
                            Text("Message \(conversation.peer.displayName)")
                                .foregroundStyle(.tertiary)
                                .padding(.horizontal, 9)
                                .padding(.vertical, 8)
                                .allowsHitTesting(false)
                        }
                    }
                    .background {
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color(uiColor: .separator), lineWidth: 0.5)
                    }
                        .task(id: draft) {
                            try? await Task.sleep(for: .milliseconds(250))
                            guard !Task.isCancelled else { return }
                            await updateDraft(conversation.id, draft)
                        }
                    Button("Send", systemImage: "arrow.up.circle.fill") {
                        Task { await send() }
                    }
                    .labelStyle(.iconOnly)
                    .font(.title2)
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                if let blockedReason {
                    Label(blockedReason, systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
            .background(.bar)
        }
        .navigationTitle(conversation.peer.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // The avatar replaces the plain title, as in Messages; tapping it
            // opens the peer's profile. The navigation title above still
            // labels the back button and accessibility focus.
            ToolbarItem(placement: .principal) {
                Button {
                    showsPeerProfile = true
                } label: {
                    VStack(spacing: 1) {
                        PeerAvatar(hint: conversation.peer.identity.hint, diameter: 28)
                        Text(conversation.peer.displayName)
                            .font(.caption2)
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(conversation.peer.displayName) profile")
            }
        }
        .sheet(isPresented: $showsPeerProfile) {
            NavigationStack {
                PeerDetailView(
                    peer: conversation.peer,
                    radioSnapshot: .constant(radioSnapshot),
                    updateAlias: updateAlias
                )
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { showsPeerProfile = false }
                    }
                }
            }
        }
        .alert("Message not sent", isPresented: $showsBlockedReason) {
            Button("OK", role: .cancel) {}
        } message: {
            Text((sendFailureMessage ?? blockedReason ?? "The message could not be queued.") + " Your draft has been preserved.")
        }
        .sheet(item: $editingMessage) { message in
            MessageEditSheet(
                originalBody: message.body,
                text: $editDraft,
                save: { newBody in
                    editingMessage = nil
                    await edit(message, newBody: newBody)
                },
                cancel: { editingMessage = nil }
            )
        }
        .confirmationDialog(
            "Delete this message?",
            isPresented: Binding(
                get: { deletingMessage != nil },
                set: { if !$0 { deletingMessage = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete for everyone", role: .destructive) {
                if let message = deletingMessage {
                    deletingMessage = nil
                    Task { await delete(message) }
                }
            }
        } message: {
            Text("A deletion is broadcast to \(conversation.peer.displayName) and cannot be undone.")
        }
    }

    private func edit(_ message: ChatMessageSummary, newBody: String) async {
        let body = newBody.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty, body != message.body else { return }
        switch await messageActions.edit(conversation, message, body) {
        case let .sent(updated):
            conversation = updated
        case let .failed(reason):
            sendFailureMessage = reason
            showsBlockedReason = true
        }
    }

    private func delete(_ message: ChatMessageSummary) async {
        switch await messageActions.delete(conversation, message) {
        case let .sent(updated):
            conversation = updated
        case let .failed(reason):
            sendFailureMessage = reason
            showsBlockedReason = true
        }
    }

    /// At most one scroll command per run-loop tick. After a send, both the
    /// messages change and the explicit scroll request fire together; two
    /// simultaneous animated scrollTo calls fight each other and churn
    /// layout while the transcript is still settling.
    private func scheduleScrollToBottom(_ proxy: ScrollViewProxy, animated: Bool = true) {
        guard !scrollToBottomScheduled else { return }
        scrollToBottomScheduled = true
        DispatchQueue.main.async {
            scrollToBottomScheduled = false
            if animated {
                withAnimation {
                    proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
                }
            } else {
                proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
            }
        }
    }

    private func updateFollowState(distanceFromBottom: CGFloat, userDriven: Bool) {
        if distanceFromBottom <= Self.resumeFollowingDistance {
            followsLatestMessage = true
        } else if userDriven && distanceFromBottom >= Self.stopFollowingDistance {
            followsLatestMessage = false
        }
    }

    private func send() async {
        sendFailureMessage = nil
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty else { return }
        guard blockedReason == nil else {
            showsBlockedReason = true
            return
        }
        switch await sendMessage(conversation, body) {
        case let .sent(updatedConversation):
            conversation = updatedConversation
            draft = ""
            outgoingScrollRequest += 1
        case let .failed(message):
            sendFailureMessage = message
            showsBlockedReason = true
        }
    }

    private var blockedReason: String? {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready else {
            return "Connect a configured companion radio to send."
        }
        guard radioSnapshot.hostState == .matchesCurrentIdentity else {
            return "Set up this radio for the current phone identity to send."
        }
        return nil
    }
}

/// UITextView keeps the software keyboard's Return key as a newline while
/// making physical-keyboard Return a send shortcut. SwiftUI's multiline
/// TextField consumes physical Return before `onKeyPress`, so it cannot
/// reliably express this distinction on its own.
private struct HardwareAwareMessageEditor: UIViewRepresentable {
    @Binding var text: String
    let onHardwareReturn: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> HardwareAwareTextView {
        let textView = HardwareAwareTextView()
        textView.delegate = context.coordinator
        textView.backgroundColor = .clear
        textView.font = .preferredFont(forTextStyle: .body)
        textView.adjustsFontForContentSizeCategory = true
        textView.textContainerInset = UIEdgeInsets(top: 7, left: 4, bottom: 7, right: 4)
        textView.isScrollEnabled = true
        textView.onHardwareReturn = onHardwareReturn
        return textView
    }

    func updateUIView(_ textView: HardwareAwareTextView, context: Context) {
        if textView.text != text {
            textView.text = text
        }
        textView.onHardwareReturn = onHardwareReturn
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: HardwareAwareTextView,
        context: Context
    ) -> CGSize? {
        guard let width = proposal.width else { return nil }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        let lineHeight = uiView.font?.lineHeight ?? 17
        let minimumHeight = lineHeight + 14
        let maximumHeight = lineHeight * 6 + 14
        return CGSize(
            width: width,
            height: min(max(measured.height, minimumHeight), maximumHeight)
        )
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        @Binding private var text: String

        init(text: Binding<String>) {
            _text = text
        }

        func textViewDidChange(_ textView: UITextView) {
            text = textView.text
        }
    }
}

private final class HardwareAwareTextView: UITextView {
    var onHardwareReturn: (() -> Void)?

    override var keyCommands: [UIKeyCommand]? {
        let send = UIKeyCommand(
            input: "\r",
            modifierFlags: [],
            action: #selector(sendFromHardwareKeyboard)
        )
        send.wantsPriorityOverSystemBehavior = true

        let newline = UIKeyCommand(
            input: "\r",
            modifierFlags: [.shift],
            action: #selector(insertNewlineFromHardwareKeyboard)
        )
        newline.wantsPriorityOverSystemBehavior = true
        return [send, newline]
    }

    @objc private func sendFromHardwareKeyboard() {
        onHardwareReturn?()
    }

    @objc private func insertNewlineFromHardwareKeyboard() {
        insertText("\n")
    }
}

private struct MessageEditSheet: View {
    let originalBody: String
    @Binding var text: String
    let save: (String) async -> Void
    let cancel: () -> Void

    @FocusState private var editorFocused: Bool

    private var trimmed: String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            TextEditor(text: $text)
                .focused($editorFocused)
                .padding(8)
                .navigationTitle("Edit Message")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { cancel() }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            Task { await save(trimmed) }
                        }
                        .disabled(trimmed.isEmpty || trimmed == originalBody)
                    }
                }
                .onAppear { editorFocused = true }
        }
        .presentationDetents([.medium, .large])
    }
}

private struct ChatMessageBubble: View {
    let message: ChatMessageSummary
    /// Quiet states (Delivered/Sent) only annotate the newest outbound
    /// message; older ones would repeat the same information on every row.
    var isMostRecentOutbound = false
    var onEdit: (() -> Void)?
    var onDelete: (() -> Void)?

    private var isFailed: Bool {
        message.deliveryState?.lowercased() == "failed"
    }

    var body: some View {
        if message.isDeleted {
            // A tombstone, not a message: no bubble, no menu, no captions.
            Text(message.isOutbound ? "You deleted a message" : "Message deleted")
                .font(.caption)
                .italic()
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: message.isOutbound ? .trailing : .leading)
                .padding(.horizontal, 8)
        } else {
            HStack(alignment: .bottom) {
                if message.isOutbound { Spacer(minLength: 44) }
                VStack(alignment: message.isOutbound ? .trailing : .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        bubble
                        if isFailed {
                            Image(systemName: "exclamationmark.circle.fill")
                                .font(.title3)
                                .foregroundStyle(.red)
                                .accessibilityLabel("Message not delivered")
                        }
                    }
                    if let caption {
                        Text(caption)
                            .font(.caption2)
                            .fontWeight(isFailed ? .semibold : .regular)
                            .foregroundStyle(isFailed ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                            .padding(.horizontal, 4)
                    }
                }
                if !message.isOutbound { Spacer(minLength: 44) }
            }
        }
    }

    private var bubble: some View {
        SelectableMessageText(text: message.body)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(message.isOutbound ? Color.accentColor.opacity(0.18) : Color.secondary.opacity(0.14))
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 16))
            .contextMenu {
                Button("Copy", systemImage: "doc.on.doc") {
                    UIPasteboard.general.string = message.body
                }
                if let onEdit {
                    Button("Edit", systemImage: "pencil", action: onEdit)
                }
                if let onDelete {
                    Button("Delete", systemImage: "trash", role: .destructive, action: onDelete)
                }
            }
    }

    private var caption: String? {
        var parts: [String] = []
        if message.isEdited { parts.append("Edited") }
        if message.isOutbound, let label = deliveryLabel { parts.append(label) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var deliveryLabel: String? {
        guard let state = message.deliveryState else { return nil }
        switch state.lowercased() {
        case "failed": return "Not Delivered"
        case "acknowledged": return isMostRecentOutbound ? "Delivered" : nil
        case "sent": return isMostRecentOutbound ? "Sent" : nil
        default: return "Sending…"
        }
    }
}

/// UITextView-backed message body: pointer-driven selection (mouse or
/// trackpad drag, double-click for a word) works like any ordinary text,
/// which SwiftUI's `.textSelection(.enabled)` does not provide inside a
/// scroll view. Long presses are left to the bubble's context menu, as in
/// Messages; touch users select through the menu or a double tap.
private struct SelectableMessageText: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> BubbleTextView {
        let view = BubbleTextView()
        view.isEditable = false
        view.isSelectable = true
        view.isScrollEnabled = false
        view.backgroundColor = .clear
        view.textContainerInset = .zero
        view.textContainer.lineFragmentPadding = 0
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.dataDetectorTypes = .link
        return view
    }

    func updateUIView(_ view: BubbleTextView, context: Context) {
        if view.text != text {
            view.text = text
        }
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: BubbleTextView,
        context: Context
    ) -> CGSize? {
        var width = proposal.width ?? .greatestFiniteMagnitude
        guard width > 0 else { return nil }
        if width.isFinite {
            // Propose whole points. Fractional widths make UITextView's
            // wrapping non-reproducible across layout passes, and any
            // non-convergent answer here can wedge SwiftUI in a layout loop.
            width = width.rounded(.down)
        }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        return CGSize(
            width: min(measured.width.rounded(.up), width),
            height: measured.height.rounded(.up)
        )
    }
}

final class BubbleTextView: UITextView {
    override func gestureRecognizerShouldBegin(
        _ gestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        // Long press must fall through to the SwiftUI context menu on the
        // bubble; only pointer and double-tap selection stay on the text.
        if gestureRecognizer is UILongPressGestureRecognizer { return false }
        return super.gestureRecognizerShouldBegin(gestureRecognizer)
    }
}
