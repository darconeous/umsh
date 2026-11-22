import RegexBuilder
import SwiftUI
import UMSHMobileCore

// MARK: - Shared controls

/// A read-only value with the same long-press Copy menu as address rows.
/// Copy the displayed value, including units, without its field label.
struct RemoteValueRow: View {
    let title: String
    let value: String

    init(_ title: String, value: String) {
        self.title = title
        self.value = value
    }

    var body: some View {
        LabeledContent(title, value: value)
            .copyable(value)
    }
}

/// A row's title, turned red and explained when the value under it cannot
/// be applied or the device rejected it.
struct RemoteFieldTitle: View {
    let title: String
    let problem: String?

    init(_ title: LocalizedStringResource, problem: String?) {
        self.init(localized: String(localized: title), problem: problem)
    }

    /// A title already localized.
    init(localized title: String, problem: String?) {
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

/// A setting the device has not said anything about yet.
struct RemoteNotRead: View {
    let title: String

    init(title: LocalizedStringResource) {
        self.title = String(localized: title)
    }

    /// A title already localized.
    init(localized title: String) {
        self.title = title
    }

    var body: some View {
        LabeledContent(title, value: String(localized: "Not read", comment: "A setting the device has not reported yet."))
            .labeledContentStyle(SettingsFieldStyle())
    }
}

/// What a screen's rows say under them: the value the draft holds cannot be
/// applied, or the device rejected the last one sent. A problem with the
/// draft comes first, since it is about what is on screen now.
struct RemoteRowProblems {
    let refusals: [UInt32: String]
    let review: MobileDraftReviewRecord?

    subscript(property: UInt32) -> String? {
        if let problem = review?.problems.first(where: { $0.propertyId == property }) {
            return FieldProblemText.text(for: problem.problem)
        }
        return refusals[property]
    }
}

// MARK: - One component per field kind

/// A switch, editable only once the device has said what it holds.
struct RemoteToggleField: View {
    let title: String
    @Binding var field: MobileToggleField
    var problem: String?

    init(_ title: LocalizedStringResource, field: Binding<MobileToggleField>, problem: String? = nil) {
        self.title = String(localized: title)
        _field = field
        self.problem = problem
    }

    var body: some View {
        if field.known {
            Toggle(isOn: $field.value) {
                RemoteFieldTitle(localized: title, problem: problem)
            }
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

/// A picked setting, editable only once the device has said what it holds.
/// The rows tag themselves with ``SwiftUI/View/choiceTag(_:)`` or
/// ``SwiftUI/View/noChoiceTag()``.
struct RemoteChoiceField<Content: View>: View {
    let title: String
    @Binding var field: MobileChoiceField
    var problem: String?
    @ViewBuilder let content: () -> Content

    init(
        _ title: LocalizedStringResource,
        field: Binding<MobileChoiceField>,
        problem: String? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = String(localized: title)
        _field = field
        self.problem = problem
        self.content = content
    }

    var body: some View {
        if field.known {
            Picker(selection: $field.value, content: content) {
                RemoteFieldTitle(localized: title, problem: problem)
            }
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

extension View {
    /// A picker row for a choice field's value.
    func choiceTag(_ value: some BinaryInteger) -> some View {
        tag(Int64?.some(Int64(value)))
    }

    /// The picker row for a choice field's empty choice.
    func noChoiceTag() -> some View {
        tag(Int64?.none)
    }
}

/// A setting that is text rather than a number, editable only once the
/// device has said what it holds.
struct RemoteTextField: View {
    let title: String
    @Binding var field: MobileTextField
    var problem: String?
    /// What an empty field shows. The title when unset.
    var placeholder: String?

    init(
        _ title: LocalizedStringResource,
        field: Binding<MobileTextField>,
        problem: String? = nil,
        placeholder: LocalizedStringResource? = nil
    ) {
        self.title = String(localized: title)
        _field = field
        self.problem = problem
        self.placeholder = placeholder.map { String(localized: $0) }
    }

    var body: some View {
        if field.known {
            LabeledContent {
                TextField(placeholder ?? title, text: $field.text)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .multilineTextAlignment(.trailing)
                    .accessibilityLabel(Text(verbatim: title))
            } label: {
                RemoteFieldTitle(localized: title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

/// A number the operator types where a value is required.
struct RemoteIntegerField: View {
    let title: String
    let unit: String
    @Binding var field: MobileIntegerField
    var signed = false
    var problem: String?

    init(
        _ title: LocalizedStringResource,
        unit: String,
        field: Binding<MobileIntegerField>,
        signed: Bool = false,
        problem: String? = nil
    ) {
        self.title = String(localized: title)
        self.unit = unit
        _field = field
        self.signed = signed
        self.problem = problem
    }

    var body: some View {
        if field.known {
            LabeledContent {
                NumberEntryBox(
                    title: title,
                    unit: unit,
                    value: field.value,
                    allowsEmpty: false,
                    signed: signed,
                    read: { $0.integer($1) },
                    format: { $0.text($1) },
                    write: { if let value = $0 { field.value = value } }
                )
            } label: {
                RemoteFieldTitle(localized: title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

/// A number the operator types where empty is allowed: a value of its own
/// (no threshold, the device's default) or one the device judges.
struct RemoteOptionalIntegerField: View {
    let title: String
    let unit: String
    @Binding var field: MobileOptionalIntegerField
    var signed = false
    var problem: String?
    var placeholder: String?

    init(
        _ title: LocalizedStringResource,
        unit: String,
        field: Binding<MobileOptionalIntegerField>,
        signed: Bool = false,
        problem: String? = nil,
        placeholder: LocalizedStringResource? = nil
    ) {
        self.title = String(localized: title)
        self.unit = unit
        _field = field
        self.signed = signed
        self.problem = problem
        self.placeholder = placeholder.map { String(localized: $0) }
    }

    var body: some View {
        if field.known {
            LabeledContent {
                NumberEntryBox(
                    title: title,
                    prompt: placeholder,
                    unit: unit,
                    value: field.value,
                    allowsEmpty: true,
                    signed: signed,
                    read: { $0.integer($1) },
                    format: { $0.text($1) },
                    write: { field.value = $0 }
                )
            } label: {
                RemoteFieldTitle(localized: title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

/// A position as two coordinate boxes over one field. Either box emptied
/// leaves half a position, which is no edit; both emptied clears it.
struct RemotePositionField: View {
    @Binding var field: MobilePositionField
    /// How many decimals the boxes show.
    let decimals: Int
    var problem: String?

    var body: some View {
        coordinate(
            String(localized: "Latitude", comment: "Field title: a position's latitude."),
            value: field.latitude,
            problem: problem
        ) { field.latitude = $0 }
        coordinate(
            String(localized: "Longitude", comment: "Field title: a position's longitude."),
            value: field.longitude,
            problem: nil
        ) { field.longitude = $0 }
    }

    @ViewBuilder
    private func coordinate(
        _ title: String,
        value: Double?,
        problem: String?,
        write: @escaping (Double?) -> Void
    ) -> some View {
        if field.known {
            LabeledContent {
                NumberEntryBox(
                    title: title,
                    unit: "°",
                    value: value,
                    allowsEmpty: true,
                    signed: true,
                    decimal: true,
                    read: { $0.decimal($1) },
                    format: { entry, number in entry.text(number, decimals: decimals) },
                    write: write
                )
            } label: {
                RemoteFieldTitle(localized: title, problem: problem)
            }
            .labeledContentStyle(SettingsFieldStyle())
        } else {
            RemoteNotRead(localized: title)
        }
    }
}

/// A disabled `Toggle` rather than a yes/no label, so a control that *is*
/// editable elsewhere reads the same in both places.
struct RemoteReadOnlyToggle: View {
    let title: String
    let isOn: Bool?

    init(_ title: LocalizedStringResource, isOn: Bool?) {
        self.title = String(localized: title)
        self.isOn = isOn
    }

    var body: some View {
        if let isOn {
            Toggle(title, isOn: .constant(isOn)).disabled(true)
        } else {
            RemoteNotRead(localized: title)
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

// MARK: - Typing numbers

/// How the number boxes read and write numbers: the locale's digits and
/// decimal separator, never grouping.
///
/// Grouping is refused rather than read leniently. A parse that accepted it
/// would read the other convention's decimal point as a grouping separator
/// ("47.12345" as 4,712,345 where `.` groups), turning a coordinate typed
/// the other way into a wrong number instead of no number.
struct NumberEntry {
    let locale: Locale

    /// What a box's text amounts to.
    enum Reading<Value: Equatable>: Equatable {
        /// Nothing typed.
        case empty
        case value(Value)
        /// Something typed that is not a number, or not yet one.
        case invalid
    }

    /// A whole number. Text with a fractional part is not one.
    func integer(_ text: String) -> Reading<Int64> {
        switch decimal(text) {
        case .empty: .empty
        case .invalid: .invalid
        case let .value(number):
            if let whole = Int64(exactly: number) { .value(whole) } else { .invalid }
        }
    }

    /// A number, the whole text read in the locale's convention.
    func decimal(_ text: String) -> Reading<Double> {
        guard !text.isEmpty else { return .empty }
        if let grouping = locale.groupingSeparator, !grouping.isEmpty, text.contains(grouping) {
            return .invalid
        }
        // A space is what a locale that groups with one also accepts as
        // grouping, so it is refused with the separator.
        if text.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.contains) {
            return .invalid
        }
        let pattern = Regex { Capture(.localizedDouble(locale: locale)) }
        guard let match = try? pattern.wholeMatch(in: text), match.output.1.isFinite else {
            return .invalid
        }
        return .value(match.output.1)
    }

    func text(_ value: Int64) -> String {
        value.formatted(IntegerFormatStyle<Int64>(locale: locale).grouping(.never))
    }

    func text(_ value: Double, decimals: Int) -> String {
        value.formatted(
            FloatingPointFormatStyle<Double>(locale: locale)
                .precision(.fractionLength(decimals))
                .grouping(.never)
        )
    }
}

/// One number box's text, and when it follows the value it stands for.
///
/// The text is the box's own: the draft holds only values. Each edit writes
/// a value when the text reads as one, and nothing when it does not (`-` on
/// the way to `-90`), so a half-typed number never reaches the draft. What
/// the box shows is worked out from the text and the value together, never
/// pushed into it after the fact, so a value that changes while the operator
/// types cannot overwrite a keystroke that landed in between.
struct NumberBox<Value: Equatable>: Equatable {
    /// What one edit asks of the draft.
    enum Write: Equatable {
        case nothing
        /// `nil` for an emptied box where empty is a value.
        case value(Value?)
    }

    private(set) var text = ""

    mutating func typed(
        _ text: String,
        reading: NumberEntry.Reading<Value>,
        allowsEmpty: Bool
    ) -> Write {
        self.text = text
        return switch reading {
        case let .value(value): .value(value)
        case .empty: allowsEmpty ? .value(nil) : .nothing
        case .invalid: .nothing
        }
    }

    /// Editing starts from the value on screen.
    mutating func begin(_ value: Value?, format: (Value) -> String) {
        text = value.map(format) ?? ""
    }

    /// What the box shows. A box at rest shows `value`, the value Apply
    /// would use. A box being typed in shows its own text while that text
    /// is not a value yet (`-`, `47,`, or emptied where empty is not a
    /// value) or reads as `value`, which every write it made does; a value
    /// chosen elsewhere (a preset, a place on the map) shows instead.
    func shown(
        _ value: Value?,
        focused: Bool,
        reading: NumberEntry.Reading<Value>,
        allowsEmpty: Bool,
        format: (Value) -> String
    ) -> String {
        let formatted = value.map(format) ?? ""
        guard focused else { return formatted }
        switch reading {
        case .invalid:
            return text
        case .empty:
            return !allowsEmpty || value == nil ? text : formatted
        case let .value(number):
            return number == value ? text : formatted
        }
    }
}

/// The text box itself: a ``NumberBox`` read and written in the locale.
private struct NumberEntryBox<Value: Equatable>: View {
    /// What VoiceOver names the box by, with its unit.
    let title: String
    /// What an empty box shows. The title when unset.
    var prompt: String?
    let unit: String
    let value: Value?
    let allowsEmpty: Bool
    var signed = false
    var decimal = false
    let read: (NumberEntry, String) -> NumberEntry.Reading<Value>
    let format: (NumberEntry, Value) -> String
    let write: (Value?) -> Void

    @Environment(\.locale) private var locale
    @State private var box = NumberBox<Value>()
    @FocusState private var focused: Bool

    var body: some View {
        let entry = NumberEntry(locale: locale)
        HStack(spacing: 5) {
            TextField(prompt ?? title, text: Binding(
                get: {
                    box.shown(
                        value,
                        focused: focused,
                        reading: read(entry, box.text),
                        allowsEmpty: allowsEmpty
                    ) { format(entry, $0) }
                },
                set: { text in
                    if case let .value(value) = box.typed(
                        text, reading: read(entry, text), allowsEmpty: allowsEmpty
                    ) {
                        write(value)
                    }
                }
            ))
            .keyboardType(signed || decimal ? .numbersAndPunctuation : .numberPad)
            .multilineTextAlignment(.trailing)
            .focused($focused)
            .accessibilityLabel(
                unit.isEmpty
                    ? Text(title)
                    : Text("\(title) in \(unit)", comment: "Accessibility label of a number box: its title, then its unit.")
            )
            if !unit.isEmpty {
                Text(unit).foregroundStyle(.secondary).fixedSize()
            }
        }
        .onChange(of: focused) {
            if focused { box.begin(value) { format(entry, $0) } }
        }
    }
}
