import SwiftUI

struct ConversationsView: View {
    let conversations: [DirectConversationSummary]
    let radioSnapshot: RadioSnapshot
    let inspectNodeURI: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let savePeer: (MeshPublicIdentity, Bool) async -> DirectConversationSummary?
    let updateDraft: (Int64, String) async -> Void

    @State private var showsImport = false
    @State private var openedConversation: DirectConversationSummary?

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
                        NavigationLink(value: conversation) {
                            ConversationRow(conversation: conversation)
                        }
                    }
                }
            }
        }
        .navigationTitle("Conversations")
        .navigationDestination(for: DirectConversationSummary.self) { conversation in
            DirectConversationView(
                conversation: conversation,
                radioSnapshot: radioSnapshot,
                updateDraft: updateDraft
            )
        }
        .navigationDestination(item: $openedConversation) { conversation in
            DirectConversationView(
                conversation: conversation,
                radioSnapshot: radioSnapshot,
                updateDraft: updateDraft
            )
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("New", systemImage: "square.and.pencil") { showsImport = true }
            }
        }
        .sheet(isPresented: $showsImport) {
            NavigationStack {
                NodeImportView(
                    inspectNodeURI: inspectNodeURI,
                    save: { identity, startConversation in
                        let conversation = await savePeer(identity, startConversation)
                        showsImport = false
                        if startConversation {
                            openedConversation = conversation
                        }
                    }
                )
            }
        }
    }
}

private struct ConversationRow: View {
    let conversation: DirectConversationSummary

    var body: some View {
        HStack(spacing: 12) {
            PeerAvatar(hint: conversation.peer.identity.hint)
            VStack(alignment: .leading, spacing: 3) {
                Text(conversation.peer.displayName)
                Text(conversation.draftText.isEmpty ? "No messages yet" : "Draft: \(conversation.draftText)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }
}

private struct NodeImportView: View {
    let inspectNodeURI: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let save: (MeshPublicIdentity, Bool) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var preview: MeshNodeURIPreview?
    @State private var problem: String?
    @State private var isInspecting = false

    var body: some View {
        Form {
            Section("Node URI") {
                TextField("umsh:n:…", text: $input, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button("Preview identity") { Task { await inspect() } }
                    .disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isInspecting)
            }

            if let preview {
                Section("Node Identity Preview") {
                    HStack(spacing: 12) {
                        PeerAvatar(hint: preview.publicIdentity.hint)
                        VStack(alignment: .leading) {
                            Text(preview.publicIdentity.hint.text)
                            Text(preview.hasIdentityData ? "Includes unverified identity metadata" : "Public key only")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    CanonicalAddressView(address: preview.publicIdentity.canonicalAddress)
                    Text("Previewing does not save this peer or transmit anything.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section {
                    Button("Message") {
                        Task { await save(preview.publicIdentity, true) }
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Save Contact") {
                        Task { await save(preview.publicIdentity, false) }
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
    }

    private func inspect() async {
        isInspecting = true
        defer { isInspecting = false }
        let result = await inspectNodeURI(input.trimmingCharacters(in: .whitespacesAndNewlines))
        switch result {
        case let .success(value):
            preview = value
            problem = nil
        case .failure:
            preview = nil
            problem = "This is not a valid UMSH node URI. Nothing was imported."
        }
    }
}

private struct DirectConversationView: View {
    let conversation: DirectConversationSummary
    let radioSnapshot: RadioSnapshot
    let updateDraft: (Int64, String) async -> Void

    @State private var draft: String
    @State private var showsBlockedReason = false

    init(
        conversation: DirectConversationSummary,
        radioSnapshot: RadioSnapshot,
        updateDraft: @escaping (Int64, String) async -> Void
    ) {
        self.conversation = conversation
        self.radioSnapshot = radioSnapshot
        self.updateDraft = updateDraft
        _draft = State(initialValue: conversation.draftText)
    }

    var body: some View {
        VStack(spacing: 0) {
            ContentUnavailableView {
                Label("No messages yet", systemImage: "bubble.left")
            } description: {
                Text("Messages with \(conversation.peer.displayName) will appear here.")
            }
            .frame(maxHeight: .infinity)

            Divider()
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .bottom, spacing: 8) {
                    TextField("Message \(conversation.peer.displayName)", text: $draft, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...6)
                        .task(id: draft) {
                            try? await Task.sleep(for: .milliseconds(250))
                            guard !Task.isCancelled else { return }
                            await updateDraft(conversation.id, draft)
                        }
                    Button("Send", systemImage: "arrow.up.circle.fill") {
                        showsBlockedReason = true
                    }
                    .labelStyle(.iconOnly)
                    .font(.title2)
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                Label(blockedReason, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .background(.bar)
        }
        .navigationTitle(conversation.peer.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .alert("Message not sent", isPresented: $showsBlockedReason) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(blockedReason + " Your draft has been preserved.")
        }
    }

    private var blockedReason: String {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready else {
            return "Connect a configured companion radio to send."
        }
        guard radioSnapshot.hostState == .matchesCurrentIdentity else {
            return "Set up this radio for the current phone identity to send."
        }
        return "Direct-message transmission is not connected yet."
    }
}
