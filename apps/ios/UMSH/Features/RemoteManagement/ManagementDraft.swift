import UMSHMobileCore

/// One of the core's ten draft records, held by its editor as a typed value.
///
/// An editor keeps the record rather than `MobileManagementDraft` because a
/// SwiftUI binding cannot reach into an enum's payload. The record is the
/// core's: the editor writes its fields' values and never their `reported`
/// or `known`, and every rule about it (what is dirty, what is a problem,
/// what Apply writes) is the core's to judge.
protocol ManagementDraft: Equatable, Sendable {
    static var kind: MobileDraftKind { get }
    /// `nil` for a draft of another kind.
    init?(_ draft: MobileManagementDraft)
    var wrapped: MobileManagementDraft { get }
}

extension MobileRadioDraft: ManagementDraft {
    static var kind: MobileDraftKind { .radio }
    init?(_ draft: MobileManagementDraft) {
        guard case let .radio(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .radio(draft: self) }
}

extension MobileIdentityDraft: ManagementDraft {
    static var kind: MobileDraftKind { .identity }
    init?(_ draft: MobileManagementDraft) {
        guard case let .identity(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .identity(draft: self) }
}

extension MobileRepeaterDraft: ManagementDraft {
    static var kind: MobileDraftKind { .repeater }
    init?(_ draft: MobileManagementDraft) {
        guard case let .repeater(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .repeater(draft: self) }
}

extension MobileMeshCoreDraft: ManagementDraft {
    static var kind: MobileDraftKind { .meshCore }
    init?(_ draft: MobileManagementDraft) {
        guard case let .meshCore(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .meshCore(draft: self) }
}

extension MobileWifiDraft: ManagementDraft {
    static var kind: MobileDraftKind { .wifi }
    init?(_ draft: MobileManagementDraft) {
        guard case let .wifi(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .wifi(draft: self) }
}

extension MobileNetworkDraft: ManagementDraft {
    static var kind: MobileDraftKind { .network }
    init?(_ draft: MobileManagementDraft) {
        guard case let .network(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .network(draft: self) }
}

extension MobileBridgeDraft: ManagementDraft {
    static var kind: MobileDraftKind { .bridge }
    init?(_ draft: MobileManagementDraft) {
        guard case let .bridge(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .bridge(draft: self) }
}

extension MobileBluetoothDraft: ManagementDraft {
    static var kind: MobileDraftKind { .bluetooth }
    init?(_ draft: MobileManagementDraft) {
        guard case let .bluetooth(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .bluetooth(draft: self) }
}

extension MobileGnssDraft: ManagementDraft {
    static var kind: MobileDraftKind { .gnss }
    init?(_ draft: MobileManagementDraft) {
        guard case let .gnss(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .gnss(draft: self) }
}

extension MobileTimeDraft: ManagementDraft {
    static var kind: MobileDraftKind { .time }
    init?(_ draft: MobileManagementDraft) {
        guard case let .time(draft) = draft else { return nil }
        self = draft
    }
    var wrapped: MobileManagementDraft { .time(draft: self) }
}

extension ManageDeviceModel {
    /// A fresh draft from the device's current reading, or `nil` while the
    /// category has none.
    func draft<D: ManagementDraft>(_: D.Type) -> D? {
        device.draft(kind: D.kind).flatMap { D($0) }
    }

    /// The editor's draft moved onto the current reading, keeping the
    /// operator's edits; a fresh one when the editor holds none yet. An
    /// editor calls this when it appears and whenever its reading changes,
    /// since it may appear before its reading exists.
    func rebaseOrBuild<D: ManagementDraft>(_ draft: D?) -> D? {
        if let draft, let rebased = try? device.rebase(draft: draft.wrapped), let typed = D(rebased) {
            return typed
        }
        return self.draft(D.self) ?? draft
    }

    /// What the core makes of `draft`: what Apply would write, what cannot
    /// be applied, and what to ask first.
    func review<D: ManagementDraft>(_ draft: D?) -> MobileDraftReviewRecord? {
        draft.flatMap { try? device.review(draft: $0.wrapped) }
    }

    func apply<D: ManagementDraft>(_ draft: D) async -> MobileApplyOutcome {
        await apply(draft.wrapped)
    }
}
