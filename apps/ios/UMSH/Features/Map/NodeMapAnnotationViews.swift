import SwiftUI

/// A node's marker: its avatar, in a ring, over a small tail that points at
/// the coordinate.
///
/// Nothing here says a location is true. The affirmative case draws no badge,
/// because a signature that verifies is evidence about who wrote the claim
/// and none at all about whether it is accurate — only the unattributable
/// case is marked, and only because it means nobody vouched for the claim.
struct MapNodeMarker: View {
    let node: MapNode
    let isSelected: Bool

    private var diameter: CGFloat { isSelected ? 44 : 34 }

    var body: some View {
        VStack(spacing: -2) {
            PeerAvatar(
                hint: node.peer.identity.hint,
                diameter: diameter,
                showsFavoriteStar: node.peer.isFavorite
            )
            .padding(3)
            .background(.background, in: Circle())
            .overlay {
                Circle().strokeBorder(isSelected ? Color.accentColor : .clear, lineWidth: 2.5)
            }
            .overlay(alignment: .bottomTrailing) {
                if !node.isAttributable {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: diameter * 0.30))
                        .foregroundStyle(.orange)
                        .background(Circle().fill(.background).padding(1))
                }
            }
            MarkerTail()
                .fill(.background)
                .frame(width: 10, height: 6)
        }
        .shadow(color: .black.opacity(0.25), radius: 3, y: 1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel)
        .accessibilityAddTraits(isSelected ? [.isSelected, .isButton] : .isButton)
    }

    private var accessibilityLabel: String {
        let trust = node.isAttributable ? "" : ", location unverified"
        return "\(node.peer.displayName)\(trust)"
    }
}

/// The operator's own position.
///
/// Deliberately not a blue dot. The fix belongs to the companion radio, and a
/// blue dot is the system's way of saying "this phone is here" — a claim this
/// app is not yet in a position to make.
struct MapSelfPositionMarker: View {
    var body: some View {
        Image(systemName: "antenna.radiowaves.left.and.right")
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 32, height: 32)
            .background(Color.accentColor, in: Circle())
            .overlay { Circle().strokeBorder(.background, lineWidth: 2.5) }
            .shadow(color: .black.opacity(0.25), radius: 3, y: 1)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("This radio's position")
    }
}

/// The little point under a marker, so it reads as pinned to the coordinate
/// rather than floating over it.
private struct MarkerTail: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}
