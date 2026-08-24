import SwiftUI

struct PeerAvatar: View {
    let hint: MeshNodeHint
    var diameter: CGFloat = 44
    var showsFavoriteStar = false

    var body: some View {
        let style = AvatarStyle.peer(hint: hint)

        VStack(spacing: diameter * style.lineSpacingRatio) {
            ForEach(Array(style.lines.enumerated()), id: \.offset) { _, line in
                Text(line)
            }
        }
        .font(.system(size: diameter * style.fontRatio, weight: .semibold, design: .monospaced))
        .minimumScaleFactor(0.8)
        .foregroundStyle(style.textColor)
        .frame(width: diameter, height: diameter)
        .background(style.fillColor, in: Circle())
        .overlay(alignment: .topTrailing) {
            if showsFavoriteStar {
                Image(systemName: "star.fill")
                    .font(.system(size: diameter * 0.28))
                    .foregroundStyle(.yellow)
                    .background(
                        Circle()
                            .fill(.background)
                            .frame(width: diameter * 0.36, height: diameter * 0.36)
                    )
                    .offset(x: diameter * 0.10, y: -diameter * 0.10)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(
            showsFavoriteStar ? "Favorite node, hint \(hint.text)" : "Node hint \(hint.text)"
        )
    }
}
