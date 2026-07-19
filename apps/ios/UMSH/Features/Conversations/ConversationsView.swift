import SwiftUI

struct ConversationsView: View {
    var body: some View {
        List {
            Section {
                ContentUnavailableView {
                    Label("No conversations", systemImage: "bubble.left.and.bubble.right")
                } description: {
                    Text("Import a peer or join a channel to begin messaging off-grid.")
                } actions: {
                    Button("Import peer or channel") {}
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .navigationTitle("Conversations")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("New", systemImage: "square.and.pencil") {}
            }
        }
    }
}
