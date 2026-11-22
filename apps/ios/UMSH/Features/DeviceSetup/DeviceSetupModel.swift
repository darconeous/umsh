import SwiftUI
import UMSHMobileCore

/// One device being set up, as the setup sheet edits and applies it.
///
/// A deliberate exception to the app's no-view-model rule, on the same
/// grounds as `AdminFlowController`: the draft is edited across more than one
/// pushed screen, and a navigation destination holding it as `@State` would
/// fork it in two. Everything the goal decides, every value the device can
/// take, and the whole apply-and-verify sequence are the core's; this holds
/// the core's setup, the draft being edited, and what the sheet shows of
/// both.
@MainActor
@Observable
final class DeviceSetupModel {
    /// How a setup sheet's apply is going, or `nil` when there is nothing to
    /// put in front of the sheet. A write that did not land resolves to
    /// `nil`: the reason is on the form, and a modal repeating it is one more
    /// thing to dismiss before acting on it.
    enum ApplyPhase: Equatable {
        case applying
        case succeeded
        /// Configured, but the device would not take the clock.
        case succeededWithoutClock
        /// Saved, and then reported a setting back differently.
        case reportedDifferently(MobileSetupSetting)
    }

    let setup: MobileDeviceSetup
    /// Everything the sheet shows that is not the draft.
    private(set) var snapshot: MobileDeviceSetupRecord
    /// The configuration being edited. Every change is reviewed at once.
    var draft: MobileSetupDraft {
        didSet { reviewDraft() }
    }
    /// What Apply would do with `draft`. `nil` once the setup is released.
    private(set) var review: MobileSetupReviewRecord?
    private(set) var phase: ApplyPhase?

    init(setup: MobileDeviceSetup, snapshot: MobileDeviceSetupRecord, draft: MobileSetupDraft) {
        self.setup = setup
        self.snapshot = snapshot
        self.draft = draft
        review = try? setup.review(draft: draft)
    }

    /// Whether the result is on screen. Settable so a sheet can bind to it;
    /// dismissing clears the phase.
    var isPresentingResult: Bool {
        get { phase != nil }
        set { if !newValue { phase = nil } }
    }

    func canApply(linkDown: Bool) -> Bool {
        review?.canApply == true && phase != .applying && !linkDown
    }

    /// Configure the device, read it back, edit its administrators, set its
    /// clock, and check what it reports.
    ///
    /// The apply runs to its end in the core whatever happens to this task;
    /// what it left is read back from the setup either way.
    func apply() async {
        guard phase != .applying else { return }
        // `phase` keeps Apply off while the core call runs. What the apply
        // left changed without the draft changing, so the review is re-run
        // by hand once it returns.
        phase = .applying
        do {
            let outcome = try await setup.apply(draft: draft)
            draft = outcome.draft
            snapshot = setup.snapshot()
            reviewDraft()
            phase = Self.phase(for: outcome.result)
        } catch {
            snapshot = setup.snapshot()
            reviewDraft()
            phase = nil
        }
    }

    /// What the result modal shows for how an apply ended. Failures are not
    /// shown there: the status section words them.
    static func phase(for result: MobileSetupResult) -> ApplyPhase? {
        switch result {
        case let .configured(clockFailed):
            clockFailed ? .succeededWithoutClock : .succeeded
        case let .reportedDifferently(setting):
            .reportedDifferently(setting)
        case .administratorsNotApplied, .notApplied, .notVerified, .interrupted,
             .invalid, .cancelled, .skipped:
            nil
        }
    }

    /// Done with this device. Safe to call more than once, and during an
    /// apply, which runs to its end in the core.
    func release() {
        setup.release()
        review = nil
    }

    private func reviewDraft() {
        review = try? setup.review(draft: draft)
    }

    // MARK: - Edits

    /// One radio parameter, through the core so that picking even the
    /// value already shown settles a profile choice.
    func setRadioParameter(_ parameter: MobileSetupRadioParameter, to value: Int64) {
        draft = setupSetRadioParameter(draft: draft, parameter: parameter, value: value)
    }

    /// A number box over one radio parameter.
    func radioNumber(
        _ parameter: MobileSetupRadioParameter,
        _ field: WritableKeyPath<MobileRadioDraft, MobileIntegerField>
    ) -> Binding<MobileIntegerField> {
        Binding(
            get: { self.draft.radio[keyPath: field] },
            set: { self.setRadioParameter(parameter, to: $0.value) }
        )
    }

    /// A picker over one radio parameter.
    func radioChoice(
        _ parameter: MobileSetupRadioParameter,
        _ field: WritableKeyPath<MobileRadioDraft, MobileChoiceField>
    ) -> Binding<MobileChoiceField> {
        Binding(
            get: { self.draft.radio[keyPath: field] },
            set: { if let value = $0.value { self.setRadioParameter(parameter, to: value) } }
        )
    }

    func adoptPreset(_ presetID: String) {
        draft = setupAdoptPreset(draft: draft, presetId: presetID)
    }

    func setPhoneAdministers(_ administers: Bool) {
        draft = setup.setPhoneAdministers(draft: draft, administers: administers)
    }

    func addAdministrator(_ key: Data) {
        draft = setup.addAdministrator(draft: draft, key: key)
    }

    func removeAdministrator(_ key: Data) {
        draft = setup.removeAdministrator(draft: draft, key: key)
    }

    /// Why a value the sheet shows in a box of its own cannot be applied.
    func problem(for property: UInt32) -> String? {
        review?.problems
            .first { $0.propertyId == property }
            .map { FieldProblemText.text(for: $0.problem) }
    }
}
