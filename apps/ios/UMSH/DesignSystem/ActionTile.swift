import SwiftUI

/// One verb on a page's tile row: an icon over a short label, the way
/// Contacts offers Message and Call under a name.
///
/// The label wraps to a second line before it shrinks, so a long translation
/// stays readable rather than truncated.
struct ActionTile: View {
    let title: LocalizedStringResource
    let systemImage: String
    /// Shows a spinner in place of the icon and refuses taps.
    var isBusy = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                ZStack {
                    Image(systemName: systemImage)
                        .font(.title3)
                        .opacity(isBusy ? 0 : 1)
                    if isBusy { ProgressView() }
                }
                .frame(height: 26)
                .accessibilityHidden(true)
                Text(title)
                    .font(.caption.weight(.medium))
                    .multilineTextAlignment(.center)
                    .lineLimit(2)
                    .minimumScaleFactor(0.8)
            }
            .foregroundStyle(.tint)
            .frame(maxWidth: .infinity, minHeight: 60)
            .padding(.vertical, 6)
            .padding(.horizontal, 4)
            .background(
                Color(uiColor: .secondarySystemGroupedBackground),
                in: RoundedRectangle(cornerRadius: 12, style: .continuous)
            )
            .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(ActionTileButtonStyle())
        .disabled(isBusy)
    }
}

/// Tiles side by side at equal widths. Placed in a list row, the row should
/// drop its background and insets so the tiles read as cards of their own.
struct ActionTileRow<Content: View>: View {
    @ViewBuilder var content: () -> Content

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            content()
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

extension View {
    /// A list row that is a card of its own—tiles, a strip, a map: no row
    /// background, no insets beyond the section's, no separator.
    func cardListRow() -> some View {
        listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 6, leading: 0, bottom: 6, trailing: 0))
            .listRowSeparator(.hidden)
    }
}

/// Dims a tile while pressed. A `List` row would otherwise take the tap for
/// the whole row and fire every button in it.
private struct ActionTileButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(configuration.isPressed ? 0.5 : (isEnabled ? 1 : 0.4))
    }
}
