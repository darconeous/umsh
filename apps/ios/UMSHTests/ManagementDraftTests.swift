import Foundation
import Testing
import UMSHMobileCore
@testable import UMSH

/// The editors' side of the core's drafts: how a number box reads and shows
/// what is typed in it, the words for what cannot be applied, and the typed
/// wrapper each editor holds.
@Suite
struct ManagementDraftTests {
    private static let german = NumberEntry(locale: Locale(identifier: "de_DE"))
    private static let american = NumberEntry(locale: Locale(identifier: "en_US"))

    // MARK: - Reading what was typed (bug 14)

    @Test func eachLocaleReadsItsOwnDecimalPoint() {
        #expect(Self.german.decimal("47,12345") == .value(47.12345))
        #expect(Self.american.decimal("47.12345") == .value(47.12345))
        #expect(Self.german.decimal("-122,5") == .value(-122.5))
    }

    @Test func theOtherConventionIsNoNumberRatherThanAWrongOne() {
        // Read leniently, each of these is 4,712,345: the other locale's
        // grouping separator.
        #expect(Self.german.decimal("47.12345") == .invalid)
        #expect(Self.american.decimal("47,12345") == .invalid)
        #expect(Self.german.integer("47.12345") == .invalid)
        #expect(Self.american.integer("47,12345") == .invalid)
    }

    @Test func aCoordinateFormatsBackAsItWasTyped() {
        #expect(Self.german.text(47.12345, decimals: 5) == "47,12345")
        #expect(Self.american.text(47.12345, decimals: 5) == "47.12345")
        #expect(Self.german.decimal(Self.german.text(-122.41942, decimals: 5)) == .value(-122.41942))
        #expect(Self.american.decimal(Self.american.text(-122.41942, decimals: 5)) == .value(-122.41942))
    }

    @Test func anIntegerFieldTakesNoGroupingAndNoFraction() {
        #expect(Self.german.integer("915.000") == .invalid)
        #expect(Self.american.integer("915,000") == .invalid)
        #expect(Self.german.integer("915,5") == .invalid)
        #expect(Self.american.integer("915.5") == .invalid)
        #expect(Self.american.integer("915000") == .value(915_000))
        #expect(Self.german.integer("915000") == .value(915_000))
        #expect(Self.american.text(915_000) == "915000")
        #expect(Self.german.text(915_000) == "915000")
    }

    @Test func textThatIsNotWhollyANumberIsNone() {
        for text in ["-", "-9x", "9x", "1 234", " 5", "5 ", "+"] {
            #expect(Self.american.integer(text) == .invalid, "\(text)")
            #expect(Self.american.decimal(text) == .invalid, "\(text)")
        }
        #expect(Self.american.integer("") == .empty)
        #expect(Self.american.decimal("") == .empty)
        #expect(Self.american.integer("99999999999999999999") == .invalid)
    }

    // MARK: - Writing it to the draft (bug 5)

    /// Type `steps` one after another into an optional box holding `start`,
    /// writing each edit into the field the way the box does.
    private static func type(
        _ steps: [String],
        into start: Int64?,
        allowsEmpty: Bool
    ) -> Int64? {
        var box = NumberBox<Int64>()
        var value = start
        for text in steps {
            if case let .value(written) = box.typed(
                text, reading: american.integer(text), allowsEmpty: allowsEmpty
            ) {
                if allowsEmpty {
                    value = written
                } else if let written {
                    value = written
                }
            }
        }
        return value
    }

    @Test func aHalfTypedNumberWritesNothing() {
        var box = NumberBox<Int64>()
        #expect(box.typed("-", reading: Self.american.integer("-"), allowsEmpty: true) == .nothing)
        #expect(box.typed("-9x", reading: Self.american.integer("-9x"), allowsEmpty: true) == .nothing)
        #expect(box.text == "-9x")
        // Typed from empty toward -90, Apply at "-" finds the field as it was.
        #expect(Self.type(["", "-"], into: nil, allowsEmpty: true) == nil)
        #expect(Self.type(["-"], into: -70, allowsEmpty: true) == -70)
        #expect(Self.type(["", "-", "-9", "-90"], into: nil, allowsEmpty: true) == -90)
    }

    @Test func emptyIsAValueOnlyWhereTheFieldAllowsIt() {
        var box = NumberBox<Int64>()
        #expect(box.typed("", reading: .empty, allowsEmpty: true) == .value(nil))
        #expect(box.typed("", reading: .empty, allowsEmpty: false) == .nothing)
        #expect(Self.type([""], into: 868_000, allowsEmpty: false) == 868_000)
        #expect(box.typed("-90", reading: Self.american.integer("-90"), allowsEmpty: true) == .value(-90))
    }

    @Test func aBoxAtRestShowsTheValueApplyWouldUse() {
        let format = { (value: Int64) in Self.american.text(value) }
        var box = NumberBox<Int64>()
        _ = box.typed("-", reading: Self.american.integer("-"), allowsEmpty: true)
        #expect(box.shown(-70, focused: false, reading: .invalid, allowsEmpty: true, format: format) == "-70")
        #expect(box.shown(nil, focused: false, reading: .invalid, allowsEmpty: true, format: format) == "")
        #expect(box.shown(915_000, focused: false, reading: .invalid, allowsEmpty: false, format: format) == "915000")
    }

    @Test func aValueFromElsewhereShowsUnlessTheOperatorIsMidNumber() {
        let format = { (value: Int64) in Self.american.text(value) }
        let read = { (text: String) in Self.american.integer(text) }
        var box = NumberBox<Int64>()
        // Editing starts from the value on screen.
        box.begin(917_500, format: format)
        #expect(box.text == "917500")
        // Its own write is never reformatted under the operator.
        _ = box.typed("0915", reading: read("0915"), allowsEmpty: false)
        #expect(box.shown(915, focused: true, reading: read(box.text), allowsEmpty: false, format: format) == "0915")
        // Partway through a number, the text stays whatever the value does.
        _ = box.typed("-", reading: read("-"), allowsEmpty: true)
        #expect(box.shown(-70, focused: true, reading: read(box.text), allowsEmpty: true, format: format) == "-")
        _ = box.typed("", reading: read(""), allowsEmpty: false)
        #expect(box.shown(868_000, focused: true, reading: read(box.text), allowsEmpty: false, format: format) == "")
        // An emptied optional box is the empty value, until one is chosen
        // elsewhere.
        #expect(box.shown(nil, focused: true, reading: read(box.text), allowsEmpty: true, format: format) == "")
        #expect(box.shown(-90, focused: true, reading: read(box.text), allowsEmpty: true, format: format) == "-90")
        // A focused box holding a number shows a value chosen elsewhere,
        // such as a preset, rather than one Apply would not use.
        _ = box.typed("915000", reading: read("915000"), allowsEmpty: false)
        #expect(box.shown(917_500, focused: true, reading: read(box.text), allowsEmpty: false, format: format) == "917500")
    }

    // MARK: - Words

    @Test func everyFieldProblemHasWords() {
        let cases: [MobileFieldProblem] = [
            .outOfRange, .hostInvalid, .portInvalid, .serverKeyInvalid, .groupInvalid,
            .limitInvalid, .addressInvalid, .prefixInvalid, .gatewayInvalid, .resolverInvalid,
        ]
        for problem in cases {
            switch problem {
            case .outOfRange, .hostInvalid, .portInvalid, .serverKeyInvalid, .groupInvalid,
                 .limitInvalid, .addressInvalid, .prefixInvalid, .gatewayInvalid, .resolverInvalid:
                break
            }
            #expect(!FieldProblemText.text(for: problem).isEmpty)
        }
        #expect(Set(cases.map(FieldProblemText.text(for:))).count == cases.count)
    }

    @Test func everyWifiEntryProblemHasWords() {
        let cases: [MobileWifiEntryProblem] = [
            .ssidEmpty, .ssidTooLong, .credentialRequired, .credentialInvalid,
        ]
        for problem in cases {
            switch problem {
            case .ssidEmpty, .ssidTooLong, .credentialRequired, .credentialInvalid:
                break
            }
            #expect(!WifiEntryProblemText.text(for: problem).isEmpty)
        }
    }

    @Test func aRowsDraftProblemComesBeforeTheDevicesRefusal() {
        let review = MobileDraftReviewRecord(
            dirty: [],
            problems: [MobileFieldProblemRecord(propertyId: 7, problem: .portInvalid)],
            hasEdits: false,
            warning: nil,
            details: .none
        )
        let problems = RemoteRowProblems(refusals: [7: "refused", 8: "refused"], review: review)
        #expect(problems[7] == FieldProblemText.text(for: .portInvalid))
        #expect(problems[8] == "refused")
        #expect(problems[9] == nil)
    }

    // MARK: - The typed wrapper

    @Test func aDraftOfAnotherKindIsRefused() {
        let toggle = MobileToggleField(propertyId: 1, known: true, reported: true, value: false)
        let gnss = MobileGnssDraft(readingRevision: 3, enabled: toggle)
        #expect(MobileGnssDraft(gnss.wrapped) == gnss)
        #expect(MobileRadioDraft(gnss.wrapped) == nil)
        #expect(MobileWifiDraft(gnss.wrapped) == nil)
        let wifi = MobileWifiDraft(readingRevision: 3, enabled: toggle)
        #expect(MobileWifiDraft(wifi.wrapped) == wifi)
        #expect(MobileGnssDraft(wifi.wrapped) == nil)
        #expect(MobileGnssDraft.kind == .gnss)
        #expect(MobileMeshCoreDraft.kind == .meshCore)
    }
}
