import SwiftUI
import UIKit

/// A node's identity link, to hand to someone else: as a QR code to scan, as
/// text to copy, or through the system share sheet.
struct PeerShareSheet: View {
    let peer: PeerSummary

    @Environment(\.dismiss) private var dismiss
    @Environment(\.showTransientNotice) private var showTransientNotice

    private var link: String { peer.identity.nodeURI }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 16) {
                        HStack(spacing: 12) {
                            PeerAvatar(peer: peer, diameter: 36)
                            Text(peer.displayName)
                                .font(.headline)
                        }
                        IdentityQRCodeView(uri: link)
                        Text(verbatim: link)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                Section {
                    Button {
                        UIPasteboard.general.string = link
                        showTransientNotice(LocalizedStringResource("Link copied", comment: "Brief notice after a node's link was copied."))
                    } label: {
                        Label {
                            Text("Copy Link", comment: "Button: copy a node's identity link.")
                        } icon: {
                            Image(systemName: "doc.on.doc")
                        }
                    }
                    .accessibilityIdentifier("peer.share.copy")
                    ShareLink(item: link) {
                        Label {
                            Text("Share…", comment: "Button: open the system share sheet for a node's link.")
                        } icon: {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                    .accessibilityIdentifier("peer.share.system")
                }
            }
            .navigationTitle(Text("Share", comment: "Title of the sheet that shares a node's identity link."))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Text("Done", comment: "Closes a sheet.")
                    }
                }
            }
        }
        .transientNoticePresenter()
    }
}
