import SwiftUI

struct PeerAvatar: View {
    let hint: MeshNodeHint
    let shape: PeerAvatarShape
    let diameter: CGFloat
    let showsFavoriteStar: Bool

    init(
        hint: MeshNodeHint,
        shape: PeerAvatarShape,
        diameter: CGFloat = 44,
        showsFavoriteStar: Bool = false
    ) {
        self.hint = hint
        self.shape = shape
        self.diameter = diameter
        self.showsFavoriteStar = showsFavoriteStar
    }

    init(peer: PeerSummary, diameter: CGFloat = 44, showsFavoriteStar: Bool = false) {
        self.init(
            hint: peer.identity.hint,
            shape: peer.avatarShape,
            diameter: diameter,
            showsFavoriteStar: showsFavoriteStar
        )
    }

    var body: some View {
        let style = AvatarStyle.peer(hint: hint)
        let fontSize = diameter * style.fontRatio * shape.fontScale

        VStack(spacing: diameter * shape.fontScale * style.lineSpacingRatio) {
            ForEach(Array(style.lines.enumerated()), id: \.offset) { _, line in
                Text(line)
            }
        }
        .font(.system(size: fontSize, weight: .semibold, design: .monospaced))
        .minimumScaleFactor(0.8)
        .foregroundStyle(style.textColor)
        .offset(y: diameter * shape.textCenterOffsetRatio)
        .frame(width: diameter, height: diameter)
        .background(style.fillColor, in: PeerAvatarOutline(shape))
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
