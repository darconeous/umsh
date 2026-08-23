import SwiftUI

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
                        // Import is the moment a bad signature is worth
                        // acting on; a good one says nothing.
                        AdvertisedIdentityWarning(identity: identity)
                        Text("These details are the node's own claims about itself.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text("Previewing does not save this peer or transmit anything.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Local details") {
                    TextField("Name (optional)", text: $name)
                    // What the node *is* is not a local detail: it comes from
                    // the identity above and updates itself when the node says
                    // otherwise, so there is nothing to pick here.
                    Text("The name is stored only on this phone; it is not an authenticated claim from the peer.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section {
                    Button("Message") {
                        Task { await save(preview, details, true) }
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Save Peer") {
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
        return PeerImportDetails(alias: trimmed.isEmpty ? nil : trimmed)
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

/// An import accepted in the sheet but not yet performed.
///
/// The presenting view stores one of these, dismisses the sheet, and runs
/// the save from the sheet's `onDismiss`. Saving immediately would land the
/// new row while the sheet still covers the list, spending its insertion
/// animation out of sight; by `onDismiss` the list is back on screen to
/// show the arrival.
struct PendingPeerImport {
    let preview: MeshNodeURIPreview
    let details: PeerImportDetails
    let startConversation: Bool
}
