import SwiftUI

/// Keep a complete value visible when accessibility text makes two columns
/// too narrow. Normal sizes retain the native labeled-content layout.
struct SettingsFieldStyle: LabeledContentStyle {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    func makeBody(configuration: Configuration) -> some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: 4) {
                configuration.label
                    .fixedSize(horizontal: false, vertical: true)
                configuration.content
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
        } else {
            LabeledContent {
                configuration.content
            } label: {
                configuration.label
            }
            .labeledContentStyle(.automatic)
        }
    }
}
