import SwiftUI
import UIKit

/// A channel's badge: a rounded square, initialed from its name and colored
/// from its key.
///
/// The square distinguishes a channel from a peer's circular avatar at a
/// glance. Colors and lettering come from `AvatarStyle`, shared with the
/// UIKit rendering that notifications need.
struct ChannelAvatar: View {
    let channel: ChannelSummary
    var size: CGFloat = 44

    var body: some View {
        let style = channel.avatarStyle

        VStack(spacing: size * style.lineSpacingRatio) {
            ForEach(Array(style.lines.enumerated()), id: \.offset) { _, line in
                Text(line)
            }
        }
        .font(.system(size: size * style.fontRatio, weight: .semibold, design: .rounded))
        .lineLimit(1)
        .minimumScaleFactor(0.7)
        .foregroundStyle(style.textColor)
        .frame(width: size, height: size)
        .background(
            style.fillColor,
            in: RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Channel \(channel.title)")
    }
}

#Preview {
    func channel(
        _ name: String?,
        canonical: String? = nil,
        tint: [UInt8] = [0x3A, 0x8F, 0xD2]
    ) -> ChannelSummary {
        ChannelSummary(
            id: UUID(),
            kind: canonical == nil ? .privateKey : .builtin,
            canonicalName: canonical,
            name: name,
            alias: nil,
            channelIDHex: "0a3c",
            tint: Data(tint),
            regionCode: nil,
            maxFloodHops: nil,
            joinedPhone: true,
            joinedDevice: false,
            notificationsEnabled: false,
            joinedAt: .now
        )
    }

    return HStack(spacing: 12) {
        ChannelAvatar(channel: channel("Public", canonical: "public"))
        ChannelAvatar(channel: channel("EMERGENCY", canonical: "emergency"))
        ChannelAvatar(channel: channel("Trail Crew"))
        ChannelAvatar(channel: channel("North Ridge Search Team"))
        ChannelAvatar(channel: channel(nil))
    }
    .padding()
}
