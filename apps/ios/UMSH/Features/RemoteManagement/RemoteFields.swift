import SwiftUI

// MARK: - Shared controls

/// A row's title, turned red and explained when the device rejected the
/// value the operator offered for it.
struct RemoteFieldTitle: View {
    let title: String
    let problem: String?

    init(_ title: String, problem: String?) {
        self.title = title
        self.problem = problem
    }

    var body: some View {
        if let problem {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(.red)
                Text(problem).font(.caption).foregroundStyle(.red)
            }
        } else {
            Text(title)
        }
    }
}

/// A typed setting, editable only once the device has said what it holds.
struct RemoteNumberField: View {
    let title: String
    let unit: String
    @Binding var text: String
    let isKnown: Bool
    var signed = false
    var decimal = false
    var problem: String?

    init(
        _ title: String,
        unit: String,
        text: Binding<String>,
        isKnown: Bool,
        signed: Bool = false,
        decimal: Bool = false,
        problem: String? = nil
    ) {
        self.title = title
        self.unit = unit
        _text = text
        self.isKnown = isKnown
        self.signed = signed
        self.decimal = decimal
        self.problem = problem
    }

    var body: some View {
        if isKnown {
            LabeledContent {
                SettingsNumberInput(title: title, unit: unit, text: $text, signed: signed, decimal: decimal)
            } label: {
                RemoteFieldTitle(title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            LabeledContent(title, value: "Not read")
                .labeledContentStyle(SettingsFieldStyle())
        }
    }
}

/// A chosen setting, editable only once the device has said what it holds.
struct RemotePicker<Value: Hashable & Sendable, Content: View>: View {
    let title: String
    /// What the device holds, which is also where an edit goes. Nil until
    /// the device has said, which is when this goes read-only.
    @Binding var selection: Value?
    var problem: String?
    @ViewBuilder let content: () -> Content

    init(
        _ title: String,
        selection: Binding<Value?>,
        problem: String? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        _selection = selection
        self.problem = problem
        self.content = content
    }

    var body: some View {
        if let value = selection {
            Picker(selection: $selection.replacingNil(with: value), content: content) {
                RemoteFieldTitle(title, problem: problem)
            }
        } else {
            LabeledContent(title, value: "Not read")
                .labeledContentStyle(SettingsFieldStyle())
        }
    }
}

/// A typed setting that is text rather than a number, editable only once
/// the device has said what it holds.
struct RemoteTextField: View {
    let title: String
    @Binding var text: String
    let isKnown: Bool
    var problem: String?

    init(
        _ title: String,
        text: Binding<String>,
        isKnown: Bool,
        problem: String? = nil
    ) {
        self.title = title
        _text = text
        self.isKnown = isKnown
        self.problem = problem
    }

    var body: some View {
        if isKnown {
            LabeledContent {
                TextField(title, text: $text)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .multilineTextAlignment(.trailing)
            } label: {
                RemoteFieldTitle(title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            LabeledContent(title, value: "Not read")
                .labeledContentStyle(SettingsFieldStyle())
        }
    }
}

/// A disabled `Toggle` rather than a yes/no label, so a control that *is*
/// editable elsewhere reads the same in both places.
struct RemoteReadOnlyToggle: View {
    let title: String
    let isOn: Bool?

    init(_ title: String, isOn: Bool?) {
        self.title = title
        self.isOn = isOn
    }

    var body: some View {
        if let isOn {
            Toggle(title, isOn: .constant(isOn)).disabled(true)
        } else {
            LabeledContent(title, value: "Not read")
                .labeledContentStyle(SettingsFieldStyle())
        }
    }
}

/// What a screen shows before anything has been read from the device. The
/// footer below it is where Refresh gets mentioned.
struct RemoteEmptyReading: View {
    var body: some View {
        Text("Not read").foregroundStyle(.secondary)
    }
}
