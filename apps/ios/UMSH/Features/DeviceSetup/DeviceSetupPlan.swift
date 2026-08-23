import Foundation
import UMSHMobileCore

/// What the operator is trying to accomplish, chosen before any device is
/// touched.
///
/// The goal is the first question because it decides the rest: which devices
/// can serve it, which settings a person should be asked about, and which the
/// role itself answers.
enum DeviceSetupGoal: String, CaseIterable, Identifiable, Hashable {
    /// A node that reports its own position and does not forward.
    case tracker
    /// A node that forwards other people's traffic.
    case repeaterNode
    /// Open the management screens on whatever the device already is.
    case revisit

    var id: String { rawValue }

    var title: String {
        switch self {
        case .tracker: "Set up a tracker"
        case .repeaterNode: "Set up a repeater"
        case .revisit: "Change a device's settings"
        }
    }

    var detail: String {
        switch self {
        case .tracker:
            "A mobile node that carries its own identity and does not forward other traffic."
        case .repeaterNode:
            "A node that forwards traffic for the mesh, optionally limited to particular routing regions."
        case .revisit:
            "Connect to a device that is already set up and edit what it is doing."
        }
    }

    var symbol: String {
        switch self {
        case .tracker: "location.circle"
        case .repeaterNode: "arrow.triangle.branch"
        case .revisit: "slider.horizontal.3"
        }
    }

    var plan: DeviceSetupPlan {
        switch self {
        case .tracker: .tracker
        case .repeaterNode: .repeaterNode
        case .revisit: .revisit
        }
    }
}

/// A value a goal decides on the operator's behalf.
///
/// An assumption is only two things: whether the device can honour it, and how
/// it is forced. There is deliberately no third member describing it in words —
/// a goal named "set up a tracker" already says the device will not forward,
/// and a second description of the same value is a thing that can drift out of
/// step with the value itself.
enum DeviceSetupAssumption: String, Hashable {
    case forwardingOff
    case forwardingOn
    case radioEnabled
    case advertisesTracker
    case roleDerivedFromForwarding
    case mobile
    case stationary
    case phoneTimeZone
    /// List this phone among the device's administrators, so it can be
    /// managed over the mesh once it is out of Bluetooth range.
    ///
    /// Assumed rather than asked because the alternative is a device on a
    /// mast that nobody can reach: the list is on the form either way, and
    /// taking this phone off it is one tap.
    case phoneAdministers
    /// Set the device's wall clock from the phone's when the sheet applies.
    ///
    /// Alone among these it forces nothing on the draft, because the clock is
    /// not part of the configuration record — it is written live, and a saved
    /// epoch would come back arbitrarily wrong anyway. It is listed here
    /// because it is a thing the goal decides, and `setsClockOnApply` reads it
    /// back off the list.
    case clockFromPhone

    /// Whether this device can be told the thing being assumed.
    ///
    /// A capability the device lacks makes the assumption silently inapplicable
    /// rather than a failure: a tracker with no GNSS is still a tracker, and a
    /// device that cannot hold a time zone still gets everything else.
    func applies(to sync: UlcpSyncRecord) -> Bool {
        switch self {
        case .forwardingOff, .forwardingOn:
            // Not merely `supportsRepeater`: a device that would not report its
            // forwarding policy has one this sheet must not decide blind.
            return sync.supportsRepeater && sync.repeater != nil
        case .radioEnabled:
            // Radio settings are not capability-gated — every device has a PHY.
            return true
        case .advertisesTracker, .roleDerivedFromForwarding, .mobile, .stationary:
            return sync.supportsIdent
        case .phoneAdministers:
            // Not merely `supportsAdmin`: a device that would not report the
            // list it already holds is one this phone cannot add to without
            // guessing what it would be writing over.
            return sync.supportsAdmin && sync.devAdminKeys != nil
        case .phoneTimeZone, .clockFromPhone:
            return sync.supportsTime
        }
    }

    @MainActor
    func force(_ draft: DeviceConfigDraft) {
        switch self {
        case .forwardingOff: draft.repeaterEnabled = false
        case .forwardingOn: draft.repeaterEnabled = true
        case .radioEnabled: draft.radioEnabled = true
        case .advertisesTracker: draft.identRole = PeerRole.tracker.roleCode
        // Left empty on purpose: the device derives "repeater" from the fact
        // that it forwards, so the advertised role cannot drift from the truth.
        case .roleDerivedFromForwarding: draft.identRole = nil
        case .mobile: draft.identMobile = true
        case .stationary: draft.identMobile = false
        case .phoneAdministers: draft.setPhoneAdministers(true)
        case .phoneTimeZone: draft.timeZoneOffsetMinutes = phoneUTCOffsetMinutes
        case .clockFromPhone: break
        }
    }
}

/// One part of a commissioning sheet.
///
/// Each goal's sheet is this same form rendered from a different list of
/// these, which is what keeps two goals from becoming two forms. Changing a
/// device's settings is not a goal's sheet at all — it opens the management
/// screens every device gets, over whichever link reaches it.
enum DeviceSetupSection: String, Hashable {
    case link
    /// What this goal will not be able to do on this device, stated once at
    /// the top rather than left as a section that silently is not there.
    case note
    /// The part of ownership worth interrupting a setup for: "not configured"
    /// is noise on a fresh board, and the device's identity is offered after
    /// the write, when its role is finally known.
    case ownershipWarning
    case name
    /// The whole PHY as one row, pushing an editor.
    case radioProfile
    /// Discoverability alone — the role and mobility are the goal's to decide,
    /// and only this one is the operator's.
    case discoverability
    /// The four positioning policy controls — no fix, no satellites, no
    /// coordinates.
    case positioningPolicy
    case announcements
    case forwarding
    /// Who may configure this device from a distance.
    case administrators
    case applyStatus
}

/// Everything that differs between one goal and another, in one value.
///
/// Goals differing anywhere else is what made four menu entries that did the
/// same thing, so this is the only place they are allowed to differ.
struct DeviceSetupPlan {
    let goal: DeviceSetupGoal
    let assumptions: [DeviceSetupAssumption]
    let sections: [DeviceSetupSection]
    /// The screen's title.
    let title: String
    /// The confirmation button's title.
    let applyTitle: String
    /// What the device is called once it is set up, for the success screen.
    let deviceNoun: String
    /// Whether this goal decides most of the configuration and presents a short
    /// sheet, rather than opening the whole editor.
    var isAbbreviated: Bool { goal != .revisit }

    var setsClockOnApply: Bool { assumptions.contains(.clockFromPhone) }

    /// Why this device cannot serve this goal, or nil if it can.
    ///
    /// A goal is refused only when the device cannot do the thing being asked
    /// of it. Everything else degrades: a device that cannot carry a *label*,
    /// or cannot locate itself, still gets everything else the sheet sets, and
    /// `note(for:)` says so. Blocking on those would be refusing to set up a
    /// perfectly good node over a field nobody asked about.
    func blocker(for sync: UlcpSyncRecord) -> String? {
        switch goal {
        case .tracker:
            // A tracker carries its own identity and announces it on a
            // schedule. Without an identity there is nothing to announce, and
            // without the schedule nothing would ever hear it — the protocol
            // makes the second imply the first, but a device can advertise the
            // identity capability without the schedule, so check both.
            if !sync.supportsDeviceIdentity {
                return """
                    This device does not carry its own node identity, so it \
                    cannot act as a tracker. You can still change its settings \
                    from "Change a device's settings".
                    """
            }
            if !sync.supportsAdvert {
                return """
                    This device cannot announce itself on a schedule, so \
                    nothing would hear from it as it moved. You can still \
                    change its settings from "Change a device's settings".
                    """
            }
            return nil

        case .repeaterNode:
            // Notably not `CAP_ADVERT`: forwarding works whether or not the
            // device beacons, so a repeater that cannot announce itself is a
            // worse repeater rather than a non-repeater.
            if !sync.supportsRepeater {
                return """
                    This device cannot forward other nodes' traffic, so it \
                    cannot act as a repeater. Set it up as a tracker instead.
                    """
            }
            if sync.repeater == nil {
                return """
                    This device would not report its forwarding policy, so \
                    setting one here would write over whatever it is holding. \
                    Open "Change a device's settings" to see what it reports.
                    """
            }
            return nil

        case .revisit:
            return nil
        }
    }

    /// What this goal will not manage to do on this device, in one paragraph,
    /// or nil when there is nothing to say.
    func note(for sync: UlcpSyncRecord) -> String? {
        guard isAbbreviated else { return nil }
        var notes: [String] = []
        if !sync.supportsGnss {
            notes.append("This device has no positioning receiver, so it will not report where it is.")
        }
        if !sync.supportsIdent {
            notes.append("It cannot be told a role, so it advertises the one it derives from what it does.")
        }
        if !sync.supportsTime {
            notes.append("It does not keep a clock, so its time zone is not set.")
        }
        return notes.isEmpty ? nil : notes.joined(separator: " ")
    }

    static let tracker = Self(
        goal: .tracker,
        assumptions: [
            .forwardingOff, .radioEnabled, .advertisesTracker,
            .mobile, .phoneTimeZone, .clockFromPhone,
        ],
        sections: [
            .link, .note, .ownershipWarning, .name,
            .discoverability, .positioningPolicy, .announcements,
            .radioProfile, .applyStatus,
        ],
        title: "Set Up a Tracker",
        applyTitle: "Set Up Tracker",
        deviceNoun: "tracker"
    )

    static let repeaterNode = Self(
        goal: .repeaterNode,
        assumptions: [
            .forwardingOn, .radioEnabled, .roleDerivedFromForwarding,
            .stationary, .phoneAdministers, .phoneTimeZone, .clockFromPhone,
        ],
        sections: [
            .link, .note, .ownershipWarning, .name, .forwarding,
            .discoverability, .positioningPolicy, .announcements,
            .radioProfile, .administrators, .applyStatus,
        ],
        title: "Set Up a Repeater",
        applyTitle: "Set Up Repeater",
        deviceNoun: "repeater"
    )

    /// Changing a device's settings has no sheet of its own: the goal
    /// connects, and the management screens take it from there, reading the
    /// device one screenful at a time.
    static let revisit = Self(
        goal: .revisit,
        assumptions: [],
        sections: [],
        title: "Device",
        applyTitle: "Apply",
        deviceNoun: "device"
    )
}
