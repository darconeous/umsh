import SwiftUI

struct ChannelRow: View {
    let channel: ChannelSummary
    var showsScope = true

    var body: some View {
        ChannelIdentityRow(channel: channel, showsMutedState: true) {
            (Text(channel.kindLabel + " ")
                + Text(channel.channelIDHex).monospaced()
                + Text(showsScope ? scopeLabel.map { " · " + $0 } ?? "" : ""))
        }
    }

    private var scopeLabel: String? {
        switch (channel.joinedPhone, channel.joinedDevice) {
        case (true, true): "Phone and radio"
        case (true, false): "Phone"
        case (false, true): "Radio"
        case (false, false): nil
        }
    }
}
