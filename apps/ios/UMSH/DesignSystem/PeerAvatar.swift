import SwiftUI

struct PeerAvatar: View {
    let hint: MeshNodeHint
    var diameter: CGFloat = 44

    var body: some View {
        let characters = Array(hint.text)

        VStack(spacing: -diameter * 0.08) {
            Text(String(characters.prefix(2)))
            Text(String(characters.dropFirst(2)))
        }
        .font(.system(size: diameter * 0.30, weight: .semibold, design: .monospaced))
        .minimumScaleFactor(0.8)
        .foregroundStyle(foregroundColor)
        .frame(width: diameter, height: diameter)
        .background(fillColor, in: Circle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Node hint \(hint.text)")
    }

    private var rgb: (red: Double, green: Double, blue: Double) {
        let bytes = Array(hint.bytes.prefix(3))
        guard bytes.count == 3 else { return (0.5, 0.5, 0.5) }
        return (
            Double(bytes[0]) / 255,
            Double(bytes[1]) / 255,
            Double(bytes[2]) / 255
        )
    }

    private var fillColor: Color {
        Color(red: rgb.red, green: rgb.green, blue: rgb.blue)
    }

    private var foregroundColor: Color {
        relativeLuminance < 0.179 ? .white : .black
    }

    private var relativeLuminance: Double {
        func linear(_ component: Double) -> Double {
            component <= 0.04045
                ? component / 12.92
                : pow((component + 0.055) / 1.055, 2.4)
        }

        return 0.2126 * linear(rgb.red)
            + 0.7152 * linear(rgb.green)
            + 0.0722 * linear(rgb.blue)
    }
}
