import SwiftUI
import UIKit

/// A channel's badge: a rounded square, initialed from its name and colored
/// from its key.
///
/// The color comes from the same derivation as the channel identifier, run
/// one byte longer, so everyone holding the key sees the same badge without
/// anything being agreed or transmitted. The square distinguishes a channel
/// from a peer's circular avatar at a glance.
struct ChannelAvatar: View {
    let channel: ChannelSummary
    var size: CGFloat = 44

    var body: some View {
        let lines = initialLines

        VStack(spacing: -size * 0.06) {
            Text(lines[0])
            if lines.count > 1 {
                Text(lines[1])
            }
        }
        .font(.system(size: fontSize, weight: .semibold, design: .rounded))
        .lineLimit(1)
        .minimumScaleFactor(0.7)
        .foregroundStyle(foregroundColor)
        .frame(width: size, height: size)
        .background(fillColor, in: RoundedRectangle(cornerRadius: size * 0.25, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Channel \(channel.title)")
    }

    /// The first letter of each word, up to four. A private channel that was
    /// never named has nothing to initial, so its identifier stands in — the
    /// same digits shown beside it in the row.
    private var initials: String {
        let source = channel.alias ?? channel.name ?? ""
        let letters = source
            .split(whereSeparator: { $0.isWhitespace || $0 == "-" || $0 == "_" })
            .compactMap(\.first)
            .prefix(4)
        if letters.isEmpty {
            return channel.channelIDHex.uppercased()
        }
        return String(letters).uppercased()
    }

    /// Two glyphs per line. Wrapping rather than shrinking lets three and four
    /// initials stay as large as two.
    private var initialLines: [String] {
        let characters = Array(initials)
        guard characters.count > 2 else { return [String(characters)] }
        return [String(characters.prefix(2)), String(characters.dropFirst(2))]
    }

    /// A lone glyph gets the whole square; everything else shares it two to a
    /// line, at one size.
    private var fontSize: CGFloat {
        initials.count == 1 ? size * 0.76 : size * 0.42
    }

    private var rgb: (red: CGFloat, green: CGFloat, blue: CGFloat) {
        let bytes = Array(channel.tint.prefix(3))
        guard bytes.count == 3 else { return (0.5, 0.5, 0.5) }
        return (CGFloat(bytes[0]) / 255, CGFloat(bytes[1]) / 255, CGFloat(bytes[2]) / 255)
    }

    private var fillColor: Color {
        // The two standard channels are recognized on sight rather than by
        // reading, so they keep fixed colors instead of derived ones.
        switch channel.canonicalName {
        case "public": return .blue
        case "emergency": return .red
        default:
            let derived = derivedFill
            return Color(
                hue: derived.hue,
                saturation: derived.saturation,
                brightness: derived.brightness
            )
        }
    }

    private var foregroundColor: Color {
        switch channel.canonicalName {
        case "public", "emergency": return .white
        default: return derivedFill.prefersWhiteText ? .white : .black
        }
    }

    /// The derived color pulled out of the middle of the brightness range,
    /// where neither black nor white reads well.
    ///
    /// Hue survives untouched, so a channel keeps the identity its key gives
    /// it; only brightness and saturation move, and they move to one of two
    /// bands that each clear the WCAG 4.5:1 threshold against a fixed text
    /// color. Picking the nearer band keeps light channels light and dark
    /// ones dark.
    private var derivedFill: (hue: Double, saturation: Double, brightness: Double, prefersWhiteText: Bool) {
        var hue: CGFloat = 0
        var saturation: CGFloat = 0
        var brightness: CGFloat = 0
        UIColor(red: rgb.red, green: rgb.green, blue: rgb.blue, alpha: 1)
            .getHue(&hue, saturation: &saturation, brightness: &brightness, alpha: nil)

        let goesDark = brightness < 0.62
        return (
            hue: Double(hue),
            saturation: Double(goesDark ? min(saturation, 0.85) : min(saturation, 0.45)),
            brightness: goesDark ? 0.42 : 0.90,
            prefersWhiteText: goesDark
        )
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
