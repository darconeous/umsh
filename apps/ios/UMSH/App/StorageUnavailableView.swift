import SwiftUI

/// Shown in place of the entire app when the local database cannot be opened.
///
/// The failure mode this exists for is quiet: with no store, every read returns
/// nothing and every write is dropped, so the app renders as a working install
/// belonging to someone with no contacts. The one recovery a user reaches for
/// in that situation — delete and reinstall — is also the only action that
/// destroys the data, because the database lives in Application Support while
/// the identity lives in the Keychain and survives. So this screen's job is to
/// say the records are intact and to talk the user out of erasing them.
struct StorageUnavailableView: View {
    let error: any Error

    var body: some View {
        ContentUnavailableView {
            Label("Storage unavailable", systemImage: "externaldrive.badge.exclamationmark")
        } description: {
            VStack(spacing: 16) {
                Text(
                    """
                    UMSH could not open its local database, so your contacts and \
                    conversations cannot be shown and nothing new can be saved.
                    """
                )
                Text("Your records have not been deleted.")
                    .fontWeight(.semibold)
                Text(
                    """
                    Do not delete the app — that erases the database this build \
                    is unable to read. Reinstalling the previous version, or a \
                    build that fixes the error below, restores everything.
                    """
                )
                Text(detail)
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.top, 4)
            }
            .multilineTextAlignment(.center)
        }
    }

    private var detail: String {
        (error as? ApplicationStoreError)?.diagnosticDescription
            ?? String(describing: error)
    }
}
