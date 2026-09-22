import SwiftUI

/// One peer's identity and contextual details, shared by every node list.
/// Screens own navigation, selection, menus, and the wording of their details.
struct PeerRow<TitleAccessory: View, Trailing: View>: View {
    let hint: MeshNodeHint?
    let title: String
    let subtitle: String?
    let size: IdentityRowSize
    let showsFavoriteStar: Bool
    let isStale: Bool
    private let titleAccessory: TitleAccessory
    private let trailing: Trailing

    init(
        hint: MeshNodeHint?,
        title: String,
        subtitle: String? = nil,
        size: IdentityRowSize = .standard,
        showsFavoriteStar: Bool = false,
        isStale: Bool = false,
        @ViewBuilder titleAccessory: () -> TitleAccessory = { EmptyView() },
        @ViewBuilder trailing: () -> Trailing = { EmptyView() }
    ) {
        self.hint = hint
        self.title = title
        self.subtitle = subtitle
        self.size = size
        self.showsFavoriteStar = showsFavoriteStar
        self.isStale = isStale
        self.titleAccessory = titleAccessory()
        self.trailing = trailing()
    }

    init(
        peer: PeerSummary,
        subtitle: String? = nil,
        size: IdentityRowSize = .standard,
        showsFavoriteStar: Bool = false
    ) where TitleAccessory == EmptyView, Trailing == EmptyView {
        self.init(
            hint: peer.identity.hint,
            title: peer.displayName,
            subtitle: subtitle,
            size: size,
            showsFavoriteStar: showsFavoriteStar
        )
    }

    var body: some View {
        IdentityRowLayout {
            Group {
                if let hint {
                    PeerAvatar(hint: hint, diameter: size.avatarDiameter, showsFavoriteStar: showsFavoriteStar)
                } else {
                    Image(systemName: "person.crop.circle.badge.questionmark")
                        .font(.system(size: size.avatarDiameter * 0.62))
                        .foregroundStyle(.secondary)
                        .frame(width: size.avatarDiameter, height: size.avatarDiameter)
                        .accessibilityLabel("Unknown node hint")
                }
            }
            .opacity(isStale ? 0.5 : 1)
        } title: {
            HStack(spacing: IdentityPresentation.accessorySpacing) {
                Text(title)
                titleAccessory
            }
        } subtitle: {
            if let subtitle { Text(subtitle) }
        } trailing: {
            trailing
        }
        .foregroundStyle(isStale ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
    }
}
