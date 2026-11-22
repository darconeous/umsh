import Foundation
import Testing
import UMSHMobileCore
@testable import UMSH

/// The words for what the core reports about a managed device, and the
/// routing that tells each open screen its device changed.
@Suite @MainActor
struct ManagementTests {
    private static let someRefusal = MobileRefusal(reason: .other, status: 99)

    /// Every case, so a case the core adds fails to compile here until it
    /// has words.
    private static func everyProblem() -> [MobileManagementProblem] {
        let cases: [MobileManagementProblem] = [
            .noAnswer, .unreachable, .refused(refusal: someRefusal), .unreadable, .noRadio,
            .radioBusy, .tableFull, .unsupported, .dfuUnsupported, .dfuRefused(status: 3),
            .dfuUnconfirmed, .notAllApplied(saving: true), .notAllApplied(saving: false),
            .notBuilt, .notRunning, .noOwner, .notThisPhone, .notFound, .invalidRequest,
            .sendFailed, .busy, .stopped, .other,
        ]
        for problem in cases {
            switch problem {
            case .noAnswer, .unreachable, .refused, .unreadable, .noRadio, .radioBusy,
                 .tableFull, .unsupported, .dfuUnsupported, .dfuRefused, .dfuUnconfirmed,
                 .notAllApplied, .notBuilt, .notRunning, .noOwner, .notThisPhone, .notFound,
                 .invalidRequest, .sendFailed, .busy, .stopped, .other:
                break
            }
        }
        return cases
    }

    private static func everyReason() -> [MobileRefusalReason] {
        let cases: [MobileRefusalReason] = [
            .notImplemented, .noSuchProperty, .outOfRange, .notNow, .tooLarge, .busy,
            .notPermitted, .noStatus, .other,
        ]
        for reason in cases {
            switch reason {
            case .notImplemented, .noSuchProperty, .outOfRange, .notNow, .tooLarge, .busy,
                 .notPermitted, .noStatus, .other:
                break
            }
        }
        return cases
    }

    private static func everyWifiRefusal() -> [MobileWifiRefusal] {
        let steps: [MobileWifiStep] = [.store, .turnOn, .select]
        var cases: [MobileWifiRefusal] = [
            .noRoom, .credentialRejected,
            .securityUnsupported(tried: 3, weaker: 2), .securityUnsupported(tried: 3, weaker: nil),
        ]
        for step in steps {
            cases.append(.other(step: step, refusal: someRefusal))
            cases.append(.other(step: step, refusal: MobileRefusal(reason: .noStatus, status: nil)))
        }
        for refusal in cases {
            switch refusal {
            case .noRoom, .credentialRejected, .securityUnsupported, .other:
                break
            }
        }
        return cases
    }

    private static func everyState() -> [MobilePropertyState] {
        let cases: [MobilePropertyState] = [
            .notRead, .present, .empty, .invalid, .refused(refusal: someRefusal),
            .refused(refusal: MobileRefusal(reason: .noStatus, status: nil)), .noResponse,
            .failed(problem: .noAnswer),
        ]
        for state in cases {
            switch state {
            case .notRead, .present, .empty, .invalid, .refused, .noResponse, .failed:
                break
            }
        }
        return cases
    }

    @Test func everyProblemHasWords() {
        for problem in Self.everyProblem() {
            #expect(!ManagementProblemText.text(for: problem).isEmpty, "\(problem)")
        }
        #expect(ManagementProblemText.text(for: .notAllApplied(saving: true))
            != ManagementProblemText.text(for: .notAllApplied(saving: false)))
    }

    @Test func everyRefusalHasWordsForARowAndTheStatusBar() {
        for reason in Self.everyReason() {
            let refusal = MobileRefusal(reason: reason, status: reason == .noStatus ? nil : 3)
            #expect(!RefusalText.row(refusal).isEmpty, "\(reason)")
            #expect(!RefusalText.general(refusal).isEmpty, "\(reason)")
        }
        let named = RefusalText.row(MobileRefusal(reason: .other, status: 22))
        #expect(named.contains(ulcpStatusName(status: 22)))
    }

    @Test func everyWifiRefusalHasWordsOnBothSheets() {
        for refusal in Self.everyWifiRefusal() {
            #expect(!WifiRefusalText.join(refusal).isEmpty, "\(refusal)")
            #expect(!WifiRefusalText.update(refusal).isEmpty, "\(refusal)")
        }
    }

    @Test func aStepDownNamesBothModes() {
        let text = WifiRefusalText.join(.securityUnsupported(tried: 3, weaker: 2))
        #expect(text.contains(wifiSecurityName(3)))
        #expect(text.contains(wifiSecurityName(2)))
        let alone = WifiRefusalText.join(.securityUnsupported(tried: 3, weaker: nil))
        #expect(alone.contains(wifiSecurityName(3)))
        #expect(!alone.contains(wifiSecurityName(2)))
    }

    @Test func everyReadStateButPresentHasWords() {
        for state in Self.everyState() {
            let text = PropertyStateText.text(state)
            if case .present = state {
                #expect(text == nil)
            } else {
                #expect(text?.isEmpty == false, "\(state)")
            }
        }
        #expect(PropertyStateText.text(.refused(refusal: Self.someRefusal))?
            .contains(ulcpStatusName(status: 99)) == true)
    }

    // MARK: - Routing

    private final class Observer: ManagedDeviceObserver {
        nonisolated let deviceID: UInt64
        var changes = 0
        init(_ id: UInt64) { deviceID = id }
        func deviceChanged() { changes += 1 }
    }

    /// The table only: that every entry point registers its model is
    /// `AppRuntime.adopt`'s job, which this does not run.
    @Test func changesReachEveryRegisteredModelOnTheDevice() {
        let routes = ManagedDeviceRoutes()
        let first = Observer(1)
        let sharing = Observer(1)
        let second = Observer(7)
        let other = Observer(2)
        for observer in [first, sharing, second, other] { routes.register(observer) }

        routes.route([1, 7, 1, 99])
        #expect(first.changes == 1)
        #expect(sharing.changes == 1)
        #expect(second.changes == 1)
        #expect(other.changes == 0)
    }

    @Test func aClosedScreenIsNotTold() {
        let routes = ManagedDeviceRoutes()
        let kept = Observer(3)
        var gone: Observer? = Observer(3)
        routes.register(kept)
        routes.register(gone!)
        weak let watched = gone
        gone = nil
        #expect(watched == nil)
        routes.route([3])
        #expect(kept.changes == 1)
    }
}
