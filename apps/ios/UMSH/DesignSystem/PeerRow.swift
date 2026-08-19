import SwiftUI

/// One node, as a row: its avatar, what to call it, and a line of detail.
///
/// The shape every list of nodes in the app was already building by hand.
/// Gathered here so a node looks the same wherever it is listed, and so the
/// next list of nodes gets that for free.
///
/// The avatar carries the node's hint, so a subtitle repeating it says
/// nothing — pass the detail that is worth the line, or none at all.
struct PeerRow: View {
    /// The node's hint, or nil for a key this phone cannot read as one.
    let hint: MeshNodeHint?
    let title: String
    var subtitle: String?
    var diameter: CGFloat = 44
    var showsFavoriteStar = false
    /// Rendered in the same style as the title, beside it — a badge or a
    /// warning that belongs to the name rather than under it.
    var titleAccessory: AnyView?

    init(
        hint: MeshNodeHint?,
        title: String,
        subtitle: String? = nil,
        diameter: CGFloat = 44,
        showsFavoriteStar: Bool = false,
        titleAccessory: AnyView? = nil
    ) {
        self.hint = hint
        self.title = title
        self.subtitle = subtitle
        self.diameter = diameter
        self.showsFavoriteStar = showsFavoriteStar
        self.titleAccessory = titleAccessory
    }

    /// The usual case: a node this phone knows, named the way it is named
    /// everywhere else.
    init(
        peer: PeerSummary,
        subtitle: String? = nil,
        diameter: CGFloat = 44,
        showsFavoriteStar: Bool = false
    ) {
        self.init(
            hint: peer.identity.hint,
            title: peer.displayName,
            subtitle: subtitle,
            diameter: diameter,
            showsFavoriteStar: showsFavoriteStar
        )
    }

    var body: some View {
        HStack(spacing: 12) {
            if let hint {
                PeerAvatar(hint: hint, diameter: diameter, showsFavoriteStar: showsFavoriteStar)
            } else {
                Image(systemName: "person.crop.circle.badge.questionmark")
                    .font(.system(size: diameter * 0.62))
                    .foregroundStyle(.secondary)
                    .frame(width: diameter, height: diameter)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(title).lineLimit(1)
                    titleAccessory
                }
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
