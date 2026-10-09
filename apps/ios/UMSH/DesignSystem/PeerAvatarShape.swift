import SwiftUI

/// The outline a peer's avatar is drawn in, which says what kind of node it
/// is: a circle for a node that chats, a triangle for one that carries
/// traffic, a hexagon for everything else.
enum PeerAvatarShape: Hashable, Sendable, CaseIterable {
    case circle
    case triangle
    case hexagon

    /// The first rule that matches wins: the Chat capability or the chat
    /// role is a circle; the repeater or bridge role is a triangle; anything
    /// else is a hexagon. The repeater capability bit alone does not make a
    /// triangle.
    init(role: PeerRole, capabilities: MeshNodeCapabilities?) {
        if capabilities?.contains(.textMessages) == true || role == .chat {
            self = .circle
        } else if role == .repeater || role == .bridge {
            self = .triangle
        } else {
            self = .hexagon
        }
    }

    init(identity: MeshNodeIdentity) {
        self.init(role: PeerRole(roleCode: identity.roleCode), capabilities: identity.capabilityBits)
    }

    /// How far below the frame's middle the lettering sits, as a fraction of
    /// the avatar's size. The triangle's visual center is its incenter, a
    /// third of its height above the base.
    var textCenterOffsetRatio: CGFloat {
        switch self {
        case .circle, .hexagon: 0
        case .triangle: 0.5 - PeerAvatarOutline.triangleHeightRatio / 3
        }
    }

    /// The lettering's size relative to the circle's, so both lines fit
    /// inside a shape with less room than the circle has.
    var fontScale: CGFloat {
        switch self {
        case .circle: 1
        case .triangle: 0.9
        case .hexagon: 1
        }
    }
}

/// `PeerAvatarShape` as a SwiftUI shape, so fills, rings, and borders around
/// an avatar can all follow its outline.
struct PeerAvatarOutline: InsettableShape {
    var shape: PeerAvatarShape
    var inset: CGFloat = 0

    init(_ shape: PeerAvatarShape) {
        self.shape = shape
    }

    func inset(by amount: CGFloat) -> PeerAvatarOutline {
        var copy = self
        copy.inset += amount
        return copy
    }

    func path(in rect: CGRect) -> Path {
        let rect = rect.insetBy(dx: inset, dy: inset)
        guard rect.width > 0, rect.height > 0 else { return Path() }
        let size = min(rect.width, rect.height)
        switch shape {
        case .circle:
            return Path(ellipseIn: rect)
        case .triangle:
            // Equilateral, base on the frame's bottom edge. A rounded 60°
            // corner sits one radius inside its vertex, so the apex is set
            // that far above the frame and the drawn tip meets the top edge:
            // tip to base is the circle's diameter.
            let height = size * Self.triangleHeightRatio
            let halfBase = height / sqrt(3)
            let bottom = rect.midY + size / 2
            return Self.roundedPolygon(
                [
                    CGPoint(x: rect.midX, y: bottom - height),
                    CGPoint(x: rect.midX + halfBase, y: bottom),
                    CGPoint(x: rect.midX - halfBase, y: bottom),
                ],
                cornerRadius: size * Self.triangleCornerRatio
            )
        case .hexagon:
            // Flat-topped and regular, its flat edges on the frame's top and
            // bottom: edge to edge is the circle's diameter, and the width is
            // what that height implies.
            let top = rect.midY - size / 2
            let bottom = rect.midY + size / 2
            let halfWidth = size / sqrt(3)
            let halfEdge = halfWidth / 2
            return Self.roundedPolygon(
                [
                    CGPoint(x: rect.midX - halfWidth, y: rect.midY),
                    CGPoint(x: rect.midX - halfEdge, y: top),
                    CGPoint(x: rect.midX + halfEdge, y: top),
                    CGPoint(x: rect.midX + halfWidth, y: rect.midY),
                    CGPoint(x: rect.midX + halfEdge, y: bottom),
                    CGPoint(x: rect.midX - halfEdge, y: bottom),
                ],
                cornerRadius: size * 0.2
            )
        }
    }

    private static let triangleCornerRatio: CGFloat = 0.16

    /// The triangle's vertex-to-base height relative to the frame: the frame
    /// plus the distance its rounded apex sits below the vertex.
    static let triangleHeightRatio: CGFloat = 1 + triangleCornerRatio

    /// A closed polygon whose corners are arcs tangent to both adjoining
    /// edges.
    private static func roundedPolygon(_ vertices: [CGPoint], cornerRadius: CGFloat) -> Path {
        var path = Path()
        guard let first = vertices.first, let last = vertices.last else { return path }
        path.move(to: CGPoint(x: (last.x + first.x) / 2, y: (last.y + first.y) / 2))
        for (index, vertex) in vertices.enumerated() {
            let next = vertices[(index + 1) % vertices.count]
            path.addArc(tangent1End: vertex, tangent2End: next, radius: cornerRadius)
        }
        path.closeSubpath()
        return path
    }
}
