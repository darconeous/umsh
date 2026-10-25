import SwiftUI

/// One peer's identity and contextual details, shared by every node list.
/// Screens own navigation, selection, menus, and the wording of their details.
struct PeerRow<TitleAccessory: View, Trailing: View>: View {
    let hint: MeshNodeHint?
    let shape: PeerAvatarShape
    let title: String
    let subtitle: String?
    let size: IdentityRowSize
    let showsFavoriteStar: Bool
    let isStale: Bool
    private let titleAccessory: TitleAccessory
    private let trailing: Trailing

    init(
        hint: MeshNodeHint?,
        shape: PeerAvatarShape,
        title: String,
        subtitle: String? = nil,
        size: IdentityRowSize = .standard,
        showsFavoriteStar: Bool = false,
        isStale: Bool = false,
        @ViewBuilder titleAccessory: () -> TitleAccessory = { EmptyView() },
        @ViewBuilder trailing: () -> Trailing = { EmptyView() }
    ) {
        self.hint = hint
        self.shape = shape
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
            shape: peer.avatarShape,
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
                    PeerAvatar(hint: hint, shape: shape, diameter: size.avatarDiameter, showsFavoriteStar: showsFavoriteStar)
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

/// A node known by a router hint, drawn the way a neighbor listing draws a
/// node: the node the hint most plausibly names, with its name and avatar,
/// else the hint and a gray hexagon. Screens own navigation around it.
///
/// A hint that names no known node offers to ask the node behind it who it
/// is, wherever the screen can say how to reach it.
struct RouterHintRow: View {
    let hint: MeshRouterHint
    /// The node the hint names, from `RouterHintNaming.match` or a choice.
    let named: PeerSummary?
    /// Lines of the screen's own after the hint.
    var detail: [String] = []
    /// Sends the identity request for an unmatched hint.
    var discover: HintDiscoveryButton.Ask? = nil

    var body: some View {
        // A named node's title is its name, so the hint moves to the detail;
        // an unnamed one is titled by the hint.
        let lines = (named == nil ? [] : ["Router hint \(hint.text)"]) + detail
        PeerRow(
            hint: named?.identity.hint ?? MeshNodeHint(bytes: hint.bytes, text: hint.text),
            shape: named?.avatarShape ?? .hexagon,
            title: named?.displayName ?? "Router hint \(hint.text)",
            subtitle: lines.isEmpty ? nil : lines.joined(separator: " · "),
            size: .compact,
            showsFavoriteStar: named?.isFavorite == true,
            trailing: {
                if named == nil, let discover {
                    HintDiscoveryButton(ask: discover)
                }
            }
        )
    }
}

/// Ask the node behind a hint no known node matches who it is: the trailing
/// control of every row that shows such a hint.
struct HintDiscoveryButton: View {
    /// Sends the identity request, answering whether the radio took it.
    typealias Ask = () async -> Bool

    let ask: Ask

    /// How long an ask is shown as outstanding. A hint-filtered request is
    /// answered at once, since only one node matches, so what is left is the
    /// round trip over a few hops. A timed state rather than one cleared by a
    /// reply, so a lost answer does not claim one is still coming.
    static let wait: Duration = .seconds(15)

    @State private var asked = false

    var body: some View {
        if asked {
            ProgressView()
                .controlSize(.small)
                .accessibilityLabel("Waiting for a reply")
        } else {
            Button {
                Task {
                    // Marked only once the radio has it, so the spinner never
                    // claims an ask that never went out.
                    guard await ask() else { return }
                    asked = true
                    try? await Task.sleep(for: Self.wait)
                    asked = false
                }
            } label: {
                Label("Discover", systemImage: "magnifyingglass")
                    .labelStyle(.iconOnly)
                    // The trailing slot's caption size is too small a target.
                    .font(.body)
            }
            .buttonStyle(.borderless)
            // A row's trailing slot is drawn as secondary text; this is a
            // control.
            .foregroundStyle(.tint)
        }
    }
}
