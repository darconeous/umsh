import SwiftUI

/// Channel identity used by search and membership lists. Conversation rows
/// retain their own message preview, timestamp, and unread presentation.
struct ChannelIdentityRow<Subtitle: View>: View {
    let channel: ChannelSummary
    var showsMutedState = false
    @ViewBuilder var subtitle: () -> Subtitle

    var body: some View {
        IdentityRowLayout {
            ChannelAvatar(channel: channel, size: 40)
        } title: {
            HStack(spacing: IdentityPresentation.accessorySpacing) {
                Text(channel.title)
                if showsMutedState && !channel.notificationsEnabled && channel.isJoined {
                    Image(systemName: "bell.slash")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Notifications off")
                }
            }
        } subtitle: {
            subtitle()
        } trailing: {
            EmptyView()
        }
        .foregroundStyle(.primary)
    }
}
