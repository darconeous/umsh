import SwiftUI

enum IdentityRowSize {
    case standard, compact

    var avatarDiameter: CGFloat { self == .compact ? 32 : 44 }
}

enum IdentityPresentation {
    static let rowSpacing: CGFloat = 12
    static let textSpacing: CGFloat = 2
    static let accessorySpacing: CGFloat = 4
}

/// Geometry for peer, channel, and radio labels. Interaction belongs to the
/// enclosing native Button or NavigationLink, not to the label.
/// Secondary details use UIKit's adaptive label color: SwiftUI's hierarchical
/// secondary style (including Color.secondary) can disappear on map material.
struct IdentityRowLayout<Avatar: View, Title: View, Subtitle: View, Trailing: View>: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ViewBuilder var avatar: () -> Avatar
    @ViewBuilder var title: () -> Title
    @ViewBuilder var subtitle: () -> Subtitle
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(alignment: .center, spacing: IdentityPresentation.rowSpacing) {
            avatar()
            VStack(alignment: .leading, spacing: IdentityPresentation.textSpacing) {
                title()
                    .font(.body)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                subtitle()
                    .font(.caption)
                    .foregroundStyle(Color(uiColor: .secondaryLabel))
                    .fixedSize(horizontal: false, vertical: true)
                if dynamicTypeSize.isAccessibilitySize { trailingContent }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if !dynamicTypeSize.isAccessibilitySize { trailingContent }
        }
        .accessibilityElement(children: .combine)
    }

    private var trailingContent: some View {
        trailing()
            .font(.caption)
            .foregroundStyle(Color(uiColor: .secondaryLabel))
            .fixedSize(horizontal: false, vertical: true)
    }
}

enum IdentityHeaderStyle {
    case information, profile, hero

    var avatarDiameter: CGFloat {
        switch self {
        case .information: 52
        case .profile: 64
        case .hero: 72
        }
    }
}

/// Also admits an editable name. The parent retains focus, bindings, actions,
/// and the meaning of its supporting text.
struct IdentityHeader<Avatar: View, Content: View>: View {
    var style: IdentityHeaderStyle = .information
    @ViewBuilder var avatar: (CGFloat) -> Avatar
    @ViewBuilder var content: () -> Content
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let vertical = style == .hero || dynamicTypeSize.isAccessibilitySize
        let layout = vertical
            ? AnyLayout(VStackLayout(alignment: style == .hero ? .center : .leading, spacing: 20))
            : AnyLayout(HStackLayout(spacing: style == .profile ? 16 : IdentityPresentation.rowSpacing))
        layout {
            avatar(style.avatarDiameter)
            content()
        }
    }
}

struct IdentityHeaderText: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: IdentityPresentation.textSpacing) {
            Text(title).font(.headline)
            Text(subtitle).font(.caption).foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

struct StatusBadge: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(.tint.opacity(0.15), in: Capsule())
            .foregroundStyle(.tint)
            .fixedSize(horizontal: false, vertical: true)
    }
}
