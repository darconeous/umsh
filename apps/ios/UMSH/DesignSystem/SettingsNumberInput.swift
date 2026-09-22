import SwiftUI

/// Number entry presentation shared by commissioning and management. Parsing
/// and validation remain with the feature's draft model.
struct SettingsNumberInput: View {
    let title: String
    let unit: String
    @Binding var text: String
    var signed = false
    var decimal = false
    var accessibilityName: String?

    var body: some View {
        HStack(spacing: 5) {
            TextField(title, text: $text)
                .keyboardType(signed || decimal ? .numbersAndPunctuation : .numberPad)
                .multilineTextAlignment(.trailing)
                .accessibilityLabel(accessibilityName ?? "\(title) in \(unit)")
            Text(unit).foregroundStyle(.secondary).fixedSize()
        }
    }
}

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
