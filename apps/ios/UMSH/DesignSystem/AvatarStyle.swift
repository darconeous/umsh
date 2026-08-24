import SwiftUI
import UIKit

/// The colors and lettering an avatar is drawn from, apart from any one way
/// of drawing it.
///
/// Notification content cannot host a SwiftUI view, so a notification's
/// avatar has to be rendered in UIKit strokes. Deriving it here keeps that
/// rendering and the on-screen view reading from one source: an avatar that
/// disagreed with the one in the transcript would be, to the eye, a
/// different node.
struct AvatarStyle {
    var fill: UIColor
    var text: UIColor
    /// One or two lines of glyphs, stacked.
    var lines: [String]
    /// Font size as a fraction of the avatar's size, so one derivation
    /// serves a 44-point row and a 96-point notification image alike.
    var fontRatio: CGFloat
    /// Extra leading between the stacked lines, likewise proportional.
    /// Negative: the glyphs are drawn tighter than their line heights.
    var lineSpacingRatio: CGFloat

    var fillColor: Color { Color(uiColor: fill) }
    var textColor: Color { Color(uiColor: text) }
}

extension AvatarStyle {
    /// A peer's avatar: the hint's own three leading octets as a color, and
    /// whichever of black or white reads against it.
    static func peer(hint: MeshNodeHint) -> AvatarStyle {
        let rgb = components(hint.bytes)
        let characters = Array(hint.text)
        return AvatarStyle(
            fill: UIColor(red: rgb.red, green: rgb.green, blue: rgb.blue, alpha: 1),
            text: relativeLuminance(rgb) < 0.179 ? .white : .black,
            lines: [String(characters.prefix(2)), String(characters.dropFirst(2))],
            fontRatio: 0.30,
            lineSpacingRatio: -0.08
        )
    }

    /// A channel's badge: initials from its name, fill from its key.
    ///
    /// The color comes from the same derivation as the channel identifier,
    /// run one byte longer, so everyone holding the key sees the same badge
    /// without anything being agreed or transmitted.
    static func channel(
        canonicalName: String?,
        title: String,
        identifierHex: String,
        tint: Data
    ) -> AvatarStyle {
        let initials = channelInitials(title: title, identifierHex: identifierHex)
        let characters = Array(initials)
        let lines = characters.count > 2
            ? [String(characters.prefix(2)), String(characters.dropFirst(2))]
            : [String(characters)]

        // The two standard channels are recognized on sight rather than by
        // reading, so they keep fixed colors instead of derived ones.
        let fill: UIColor
        let text: UIColor
        switch canonicalName {
        case "public":
            fill = UIColor.systemBlue
            text = .white
        case "emergency":
            fill = UIColor.systemRed
            text = .white
        default:
            let derived = derivedChannelFill(tint)
            fill = UIColor(
                hue: derived.hue,
                saturation: derived.saturation,
                brightness: derived.brightness,
                alpha: 1
            )
            text = derived.prefersWhiteText ? .white : .black
        }

        return AvatarStyle(
            fill: fill,
            text: text,
            lines: lines,
            // A lone glyph gets the whole square; everything else shares it
            // two to a line, at one size.
            fontRatio: initials.count == 1 ? 0.76 : 0.42,
            lineSpacingRatio: -0.06
        )
    }

    /// The first letter of each word, up to four. A private channel that was
    /// never named has nothing to initial, so its identifier stands in — the
    /// same digits shown beside it in the row.
    private static func channelInitials(title: String, identifierHex: String) -> String {
        let letters = title
            .split(whereSeparator: { $0.isWhitespace || $0 == "-" || $0 == "_" })
            .compactMap(\.first)
            .prefix(4)
        return letters.isEmpty ? identifierHex.uppercased() : String(letters).uppercased()
    }

    /// The derived color pulled out of the middle of the brightness range,
    /// where neither black nor white reads well.
    ///
    /// Hue survives untouched, so a channel keeps the identity its key gives
    /// it; only brightness and saturation move, and they move to one of two
    /// bands that each clear the WCAG 4.5:1 threshold against a fixed text
    /// color. Picking the nearer band keeps light channels light and dark
    /// ones dark.
    private static func derivedChannelFill(
        _ tint: Data
    ) -> (hue: CGFloat, saturation: CGFloat, brightness: CGFloat, prefersWhiteText: Bool) {
        let rgb = components(tint)
        var hue: CGFloat = 0
        var saturation: CGFloat = 0
        var brightness: CGFloat = 0
        UIColor(red: rgb.red, green: rgb.green, blue: rgb.blue, alpha: 1)
            .getHue(&hue, saturation: &saturation, brightness: &brightness, alpha: nil)

        let goesDark = brightness < 0.62
        return (
            hue: hue,
            saturation: goesDark ? min(saturation, 0.85) : min(saturation, 0.45),
            brightness: goesDark ? 0.42 : 0.90,
            prefersWhiteText: goesDark
        )
    }

    private static func components(
        _ bytes: Data
    ) -> (red: CGFloat, green: CGFloat, blue: CGFloat) {
        let octets = Array(bytes.prefix(3))
        guard octets.count == 3 else { return (0.5, 0.5, 0.5) }
        return (CGFloat(octets[0]) / 255, CGFloat(octets[1]) / 255, CGFloat(octets[2]) / 255)
    }

    private static func relativeLuminance(
        _ rgb: (red: CGFloat, green: CGFloat, blue: CGFloat)
    ) -> CGFloat {
        func linear(_ component: CGFloat) -> CGFloat {
            component <= 0.04045
                ? component / 12.92
                : pow((component + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(rgb.red) + 0.7152 * linear(rgb.green) + 0.0722 * linear(rgb.blue)
    }
}

extension ChannelSummary {
    var avatarStyle: AvatarStyle {
        .channel(
            canonicalName: canonicalName,
            title: alias ?? name ?? "",
            identifierHex: channelIDHex,
            tint: tint
        )
    }
}
