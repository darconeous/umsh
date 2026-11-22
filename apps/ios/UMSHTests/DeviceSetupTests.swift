import Foundation
import Testing
import UMSHMobileCore
@testable import UMSH

/// The words for what the core reports about a device being set up, and the
/// result modal each apply result leads to.
///
/// Each list is built behind an exhaustive `switch`, so a case the core adds
/// fails to compile here until it has words.
@Suite @MainActor
struct DeviceSetupTests {
    private static func everyGoal() -> [MobileSetupGoal] {
        let cases: [MobileSetupGoal] = [.tracker, .repeater]
        for goal in cases {
            switch goal {
            case .tracker, .repeater: break
            }
        }
        return cases
    }

    private static func everyRefusal() -> [MobileSetupRefusal] {
        let cases: [MobileSetupRefusal] = [
            .notReported, .noDeviceIdentity, .noAdvertSchedule, .cannotForward,
            .forwardingUnreported,
        ]
        for refusal in cases {
            switch refusal {
            case .notReported, .noDeviceIdentity, .noAdvertSchedule, .cannotForward,
                 .forwardingUnreported:
                break
            }
        }
        return cases
    }

    private static func everyNote() -> [MobileSetupNote] {
        let cases: [MobileSetupNote] = [.noPositioning, .noRole, .noClock]
        for note in cases {
            switch note {
            case .noPositioning, .noRole, .noClock: break
            }
        }
        return cases
    }

    private static func everyUnreadable() -> [MobileSetupUnreadable] {
        let cases: [MobileSetupUnreadable] = [
            .modemProfile, .transmitLimit, .advertisedIdentity, .discoverability,
            .forwardingPolicy, .meshCoreForwarding, .positioning, .announcements, .timeZone,
            .administrators,
        ]
        for setting in cases {
            switch setting {
            case .modemProfile, .transmitLimit, .advertisedIdentity, .discoverability,
                 .forwardingPolicy, .meshCoreForwarding, .positioning, .announcements, .timeZone,
                 .administrators:
                break
            }
        }
        return cases
    }

    private static func everySetting() -> [MobileSetupSetting] {
        let cases: [MobileSetupSetting] = [
            .radioSwitch, .frequency, .bandwidth, .spreadingFactor, .codingRate, .transmitLimit,
            .advertisedRole, .mobility, .discoverability, .forwardingPolicy, .meshCoreForwarding,
            .timeZone, .clockFormat, .positioning, .announcements,
        ]
        for setting in cases {
            switch setting {
            case .radioSwitch, .frequency, .bandwidth, .spreadingFactor, .codingRate,
                 .transmitLimit, .advertisedRole, .mobility, .discoverability, .forwardingPolicy,
                 .meshCoreForwarding, .timeZone, .clockFormat, .positioning, .announcements:
                break
            }
        }
        return cases
    }

    private static func everyGap() -> [MobileSetupProfileGap] {
        let cases: [MobileSetupProfileGap] = [
            .noCompanion, .companionHasNoModemProfile, .deviceModemUnreported,
        ]
        for gap in cases {
            switch gap {
            case .noCompanion, .companionHasNoModemProfile, .deviceModemUnreported: break
            }
        }
        return cases
    }

    /// Every result, with a failure problem of each class the words tell
    /// apart.
    private static func everyResult() -> [MobileSetupResult] {
        var cases: [MobileSetupResult] = [
            .configured(clockFailed: false), .configured(clockFailed: true),
            .interrupted(configured: false), .interrupted(configured: true),
            .invalid, .cancelled, .skipped,
        ]
        cases += everySetting().map { .reportedDifferently(setting: $0) }
        for problem in [MobileManagementProblem.noAnswer, .radioBusy, .unreadable, .noRadio, .other] {
            cases += [
                .notApplied(problem: problem),
                .notVerified(problem: problem),
                .administratorsNotApplied(problem: problem),
            ]
        }
        for result in cases {
            switch result {
            case .configured, .reportedDifferently, .administratorsNotApplied, .notApplied,
                 .notVerified, .interrupted, .invalid, .cancelled, .skipped:
                break
            }
        }
        return cases
    }

    private static func words(_ resource: LocalizedStringResource) -> String {
        String(localized: resource)
    }

    @Test func everyGoalHasItsWords() {
        for goal in Self.everyGoal() {
            for resource in [goal.sheetTitle, goal.applyTitle, goal.success, goal.savePeerFooter] {
                #expect(!Self.words(resource).isEmpty)
            }
        }
        #expect(Set(DeviceSetupIntent.allCases.compactMap(\.goal)) == Set(Self.everyGoal()))
        for intent in DeviceSetupIntent.allCases {
            #expect(!Self.words(intent.title).isEmpty)
            #expect(!Self.words(intent.detail).isEmpty)
        }
    }

    @Test func everyRefusalNoteAndUnreadableSettingHasASentence() {
        let refusals = Self.everyRefusal().map { Self.words($0.text) }
        #expect(Set(refusals).count == refusals.count)
        let notes = Self.everyNote().map { Self.words($0.text) }
        #expect(Set(notes).count == notes.count)
        let unreadable = Self.everyUnreadable().map { Self.words($0.title) }
        #expect(Set(unreadable).count == unreadable.count)
        #expect(!(refusals + notes + unreadable).contains(""))
    }

    @Test func everySettingHasBothSentences() {
        let different = Self.everySetting().map { Self.words($0.reportedDifferently) }
        let unsettable = Self.everySetting().map { Self.words($0.cannotBeSet) }
        #expect(Set(different).count == different.count)
        #expect(Set(unsettable).count == unsettable.count)
    }

    @Test func everyProfileSaysWhereItCameFrom() {
        var profiles: [MobileSetupProfile] = [.copied(companionName: "Alder"), .copied(companionName: nil)]
        for gap in Self.everyGap() {
            profiles += [.mustChoose(gap: gap), .leftAsFound(gap: gap)]
        }
        for profile in profiles {
            for chosen in [false, true] {
                #expect(!Self.words(profile.footer(chosen: chosen)).isEmpty)
            }
        }
        #expect(Self.words(MobileSetupProfile.copied(companionName: "Alder").footer(chosen: true)).contains("Alder"))
        #expect(MobileSetupProfile.mustChoose(gap: .noCompanion).needsChoice(chosen: false))
        #expect(!MobileSetupProfile.mustChoose(gap: .noCompanion).needsChoice(chosen: true))
        #expect(!MobileSetupProfile.leftAsFound(gap: .noCompanion).needsChoice(chosen: false))
    }

    /// Failures are worded in the status section; a success and an apply
    /// that sent nothing are not.
    @Test func everyFailureIsWorded() {
        for result in Self.everyResult() {
            let text = result.statusText.map(Self.words)
            switch result {
            case .configured, .invalid, .cancelled, .skipped:
                #expect(text == nil)
            case .reportedDifferently, .administratorsNotApplied, .notApplied, .notVerified,
                 .interrupted:
                #expect(text?.isEmpty == false)
            }
        }
        #expect(
            MobileSetupResult.interrupted(configured: false).statusText.map(Self.words)
                != MobileSetupResult.interrupted(configured: true).statusText.map(Self.words)
        )
    }

    /// A save that did not land is told apart by what is known of it: only
    /// a refusal says the device rejected anything, and the neutral
    /// sentence for a device that could not be reached is its own.
    @Test func aConfigurationThatDidNotLandIsToldApart() {
        let refused = MobileManagementProblem.refused(refusal: MobileRefusal(reason: .other, status: 9))
        let classes: [MobileManagementProblem] = [
            .noAnswer, .radioBusy, .unreadable, .noRadio, refused, .notBuilt, .unsupported, .other,
        ]
        let sentences = classes.compactMap {
            MobileSetupResult.notApplied(problem: $0).statusText.map(Self.words)
        }
        #expect(sentences.count == classes.count)
        #expect(Set(sentences).count == classes.count)
        func sentence(_ problem: MobileManagementProblem) -> String? {
            MobileSetupResult.notApplied(problem: problem).statusText.map(Self.words)
        }
        #expect(sentence(.unreachable) == sentence(.noRadio))
        #expect(sentence(.invalidRequest) == sentence(.notBuilt))
        for problem in [MobileManagementProblem.tableFull, .busy, .notAllApplied(saving: true)] {
            #expect(sentence(problem) == sentence(.other))
        }
        // Failure dialogs never tell the operator to try again.
        for sentence in sentences {
            #expect(!sentence.localizedCaseInsensitiveContains("try again"))
        }
    }

    @Test func onlyASaveOrAMismatchOpensTheResult() {
        for result in Self.everyResult() {
            let phase = DeviceSetupModel.phase(for: result)
            switch result {
            case .configured(clockFailed: false):
                #expect(phase == .succeeded)
            case .configured(clockFailed: true):
                #expect(phase == .succeededWithoutClock)
            case let .reportedDifferently(setting):
                #expect(phase == .reportedDifferently(setting))
            case .administratorsNotApplied, .notApplied, .notVerified, .interrupted, .invalid,
                 .cancelled, .skipped:
                #expect(phase == nil)
            }
        }
    }
}
