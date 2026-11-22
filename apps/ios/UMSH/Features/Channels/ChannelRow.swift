import SwiftUI

struct ChannelRow: View {
    let channel: ChannelSummary

    var body: some View {
        ChannelIdentityRow(channel: channel, showsMutedState: true) {
            (Text(channel.kindLabel + " ")
                + Text(channel.channelIDHex).monospaced())
        }
    }
}
