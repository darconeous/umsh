import Foundation
import UMSHMobileCore

// Every word the setup sheet says about what the core decided. The core
// reports goals, refusals, notes, settings and results as enums; each is
// named here once, as a whole sentence where it is one.

// MARK: - The chooser

/// What the goal chooser offers: the two setup goals, and opening a device's
/// settings as they stand.
///
/// The third is not a goal in the core: it has no plan and no draft, and
/// opens the management screens every device gets over a lazily attached
/// session.
enum DeviceSetupIntent: Hashable, CaseIterable, Identifiable {
    case tracker
    case repeater
    case changeSettings

    var id: Self { self }

    /// The goal this sets a device up as, or `nil` for changing its settings.
    var goal: MobileSetupGoal? {
        switch self {
        case .tracker: .tracker
        case .repeater: .repeater
        case .changeSettings: nil
        }
    }

    var title: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource("Set up a tracker", comment: "Device setup goal: the device will report its position.")
        case .repeater:
            LocalizedStringResource("Set up a repeater", comment: "Device setup goal: the device will forward traffic for the mesh.")
        case .changeSettings:
            LocalizedStringResource("Change a device's settings", comment: "Device setup choice: open the settings of a device that is already set up.")
        }
    }

    var detail: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource(
                "A mobile node that carries its own identity and does not forward other traffic.",
                comment: "Device setup goal detail, under \"Set up a tracker\"."
            )
        case .repeater:
            LocalizedStringResource(
                "A node that forwards traffic for the mesh, optionally limited to particular routing regions.",
                comment: "Device setup goal detail, under \"Set up a repeater\"."
            )
        case .changeSettings:
            LocalizedStringResource(
                "Connect to a device that is already set up and edit what it is doing.",
                comment: "Device setup choice detail, under \"Change a device's settings\"."
            )
        }
    }

    var symbol: String {
        switch self {
        case .tracker: "location.circle"
        case .repeater: "arrow.triangle.branch"
        case .changeSettings: "slider.horizontal.3"
        }
    }
}

// MARK: - Goals

extension MobileSetupGoal {
    /// The setup sheet's title.
    var sheetTitle: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource("Set Up a Tracker", comment: "Screen title: setting a device up as a tracker.")
        case .repeater:
            LocalizedStringResource("Set Up a Repeater", comment: "Screen title: setting a device up as a repeater.")
        }
    }

    /// The setup sheet's confirmation button.
    var applyTitle: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource("Set Up Tracker", comment: "Button: write the setup sheet's settings to a device being set up as a tracker.")
        case .repeater:
            LocalizedStringResource("Set Up Repeater", comment: "Button: write the setup sheet's settings to a device being set up as a repeater.")
        }
    }

    /// The result screen's headline once the device is set up.
    var success: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource("Congrats, you've successfully set up your tracker!", comment: "Device setup result: a tracker was set up.")
        case .repeater:
            LocalizedStringResource("Congrats, you've successfully set up your repeater!", comment: "Device setup result: a repeater was set up.")
        }
    }

    /// Under the result screen's Save to Peers row.
    var savePeerFooter: LocalizedStringResource {
        switch self {
        case .tracker:
            LocalizedStringResource(
                "Saving it to Peers is how you find this tracker again from the rest of the app.",
                comment: "Device setup result: footer under Save to Peers, for a tracker."
            )
        case .repeater:
            LocalizedStringResource(
                "Saving it to Peers is how you find this repeater again from the rest of the app.",
                comment: "Device setup result: footer under Save to Peers, for a repeater."
            )
        }
    }
}

// MARK: - Refusals

extension MobileSetupRefusal {
    /// Why this device cannot serve the goal, shown under the scan list.
    var text: LocalizedStringResource {
        switch self {
        case .notReported:
            LocalizedStringResource(
                "That device connected but did not report its settings. It may be running firmware this app does not understand.",
                comment: "Device setup: a device cannot be set up because it reported no settings."
            )
        case .noDeviceIdentity:
            LocalizedStringResource(
                "This device does not carry its own node identity, so it cannot act as a tracker. You can still change its settings from \"Change a device's settings\".",
                comment: "Device setup: a device cannot be set up as a tracker because it has no identity of its own."
            )
        case .noAdvertSchedule:
            LocalizedStringResource(
                "This device cannot announce itself on a schedule, so nothing would hear from it as it moved. You can still change its settings from \"Change a device's settings\".",
                comment: "Device setup: a device cannot be set up as a tracker because it cannot announce itself."
            )
        case .cannotForward:
            LocalizedStringResource(
                "This device cannot forward other nodes' traffic, so it cannot act as a repeater. Set it up as a tracker instead.",
                comment: "Device setup: a device cannot be set up as a repeater because it cannot forward."
            )
        case .forwardingUnreported:
            LocalizedStringResource(
                "This device would not report its forwarding policy, so setting one here would write over whatever it is holding. Open \"Change a device's settings\" to see what it reports.",
                comment: "Device setup: a device cannot be set up as a repeater because it did not report its forwarding policy."
            )
        }
    }
}

// MARK: - Notes

extension MobileSetupNote {
    /// What the goal will not manage on this device, one sentence each.
    var text: LocalizedStringResource {
        switch self {
        case .noPositioning:
            LocalizedStringResource(
                "This device has no positioning receiver, so it will not report where it is.",
                comment: "Device setup note: the device has no GNSS receiver."
            )
        case .noRole:
            LocalizedStringResource(
                "This device cannot be told a role, so it advertises the one it derives from what it does.",
                comment: "Device setup note: the device's advertised role cannot be set."
            )
        case .noClock:
            LocalizedStringResource(
                "This device does not keep a clock, so its time zone is not set.",
                comment: "Device setup note: the device has no clock."
            )
        }
    }
}

// MARK: - Unreadable settings

extension MobileSetupUnreadable {
    /// The setting, as a row in the list of those the device did not report.
    var title: LocalizedStringResource {
        switch self {
        case .modemProfile:
            LocalizedStringResource("Modem settings", comment: "Device setup: a setting the device did not report. Its bandwidth, spreading factor and coding rate.")
        case .transmitLimit:
            LocalizedStringResource("Transmit limit", comment: "Device setup: a setting the device did not report. Its duty-cycle limit.")
        case .advertisedIdentity:
            LocalizedStringResource("Advertised identity", comment: "Device setup: a setting the device did not report. The role and mobility it advertises.")
        case .discoverability:
            LocalizedStringResource("Discoverability", comment: "Device setup: a setting the device did not report.")
        case .forwardingPolicy:
            LocalizedStringResource("Forwarding policy", comment: "Device setup: a setting the device did not report. Whether and what it forwards.")
        case .meshCoreForwarding:
            LocalizedStringResource("MeshCore forwarding", comment: "Device setup: a setting the device did not report. MeshCore is a product name.")
        case .positioning:
            LocalizedStringResource("Positioning", comment: "Device setup: a setting the device did not report. Its GNSS receiver's settings.")
        case .announcements:
            LocalizedStringResource("Announcements", comment: "Device setup: a setting the device did not report. What it announces on its own schedule.")
        case .timeZone:
            LocalizedStringResource("Time zone", comment: "Device setup: a setting the device did not report.")
        case .administrators:
            LocalizedStringResource("Administrators", comment: "Device setup: a setting the device did not report. Who may manage it remotely.")
        }
    }
}

// MARK: - Settings

extension MobileSetupSetting {
    /// The device saved its settings and reported this one back differently.
    var reportedDifferently: LocalizedStringResource {
        switch self {
        case .radioSwitch:
            LocalizedStringResource("The device reported the radio switch back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .frequency:
            LocalizedStringResource("The device reported the frequency back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .bandwidth:
            LocalizedStringResource("The device reported the bandwidth back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .spreadingFactor:
            LocalizedStringResource("The device reported the spreading factor back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .codingRate:
            LocalizedStringResource("The device reported the coding rate back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .transmitLimit:
            LocalizedStringResource("The device reported the transmit limit back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .advertisedRole:
            LocalizedStringResource("The device reported the advertised role back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .mobility:
            LocalizedStringResource("The device reported its mobility back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for. Mobility: whether it says it moves.")
        case .discoverability:
            LocalizedStringResource("The device reported discoverability back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .forwardingPolicy:
            LocalizedStringResource("The device reported its forwarding policy back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .meshCoreForwarding:
            LocalizedStringResource("The device reported MeshCore forwarding back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for. MeshCore is a product name.")
        case .timeZone:
            LocalizedStringResource("The device reported the time zone back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .clockFormat:
            LocalizedStringResource("The device reported the clock format back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for. 12- or 24-hour.")
        case .positioning:
            LocalizedStringResource("The device reported its positioning settings back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        case .announcements:
            LocalizedStringResource("The device reported what it announces back differently.", comment: "Device setup: after saving, the device reported a setting other than what it was asked for.")
        }
    }

    /// A value the sheet would write that the device cannot take, for a
    /// setting with no box of its own to show the problem under.
    var cannotBeSet: LocalizedStringResource {
        switch self {
        case .radioSwitch:
            LocalizedStringResource("The radio switch can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .frequency:
            LocalizedStringResource("The frequency can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .bandwidth:
            LocalizedStringResource("The bandwidth can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .spreadingFactor:
            LocalizedStringResource("The spreading factor can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .codingRate:
            LocalizedStringResource("The coding rate can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .transmitLimit:
            LocalizedStringResource("The transmit limit can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .advertisedRole:
            LocalizedStringResource("The advertised role can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .mobility:
            LocalizedStringResource("Mobility can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable. Mobility: whether the device says it moves.")
        case .discoverability:
            LocalizedStringResource("Discoverability can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .forwardingPolicy:
            LocalizedStringResource("The forwarding policy can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .meshCoreForwarding:
            LocalizedStringResource("MeshCore forwarding can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable. MeshCore is a product name.")
        case .timeZone:
            LocalizedStringResource("The time zone can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .clockFormat:
            LocalizedStringResource("The clock format can't be set to its current value.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable. 12- or 24-hour.")
        case .positioning:
            LocalizedStringResource("The positioning settings can't be set to their current values.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        case .announcements:
            LocalizedStringResource("The announcement settings can't be set to their current values.", comment: "Device setup: a setting holds a value the device cannot take, so Apply is unavailable.")
        }
    }
}

// MARK: - The radio profile

extension MobileSetupProfile {
    /// The radio-profile row's footer: where the profile came from, and
    /// whether a choice is still owed.
    func footer(chosen: Bool) -> LocalizedStringResource {
        switch self {
        case let .copied(companionName?):
            LocalizedStringResource(
                "Copied from \(companionName). Nodes on different profiles cannot hear each other.",
                comment: "Device setup: the radio profile was copied from this phone's radio. The placeholder is that radio's name."
            )
        case .copied(nil):
            LocalizedStringResource(
                "Copied from this phone's radio. Nodes on different profiles cannot hear each other.",
                comment: "Device setup: the radio profile was copied from this phone's radio, which has no name."
            )
        case .mustChoose where chosen:
            LocalizedStringResource(
                "Set for this device. Nodes on different profiles cannot hear each other.",
                comment: "Device setup: the operator chose a radio profile for the device."
            )
        case .mustChoose(.noCompanion):
            LocalizedStringResource(
                "This phone has no companion radio to copy a profile from. Choose the profile your local mesh uses before continuing.",
                comment: "Device setup: no radio profile could be copied, and the operator must choose one."
            )
        case .mustChoose(.companionHasNoModemProfile):
            LocalizedStringResource(
                "This phone's radio did not report its modem settings. Choose the profile your local mesh uses before continuing.",
                comment: "Device setup: no radio profile could be copied, and the operator must choose one."
            )
        case .mustChoose(.deviceModemUnreported):
            LocalizedStringResource(
                "This device did not report its modem settings. Choose the profile your local mesh uses before continuing.",
                comment: "Device setup: no radio profile could be copied, and the operator must choose one."
            )
        case .leftAsFound(.noCompanion):
            LocalizedStringResource(
                "This phone has no companion radio to copy a profile from, so this device keeps the profile it already had.",
                comment: "Device setup: no radio profile could be copied, and the device's own is left as it is."
            )
        case .leftAsFound(.companionHasNoModemProfile):
            LocalizedStringResource(
                "This phone's radio did not report its modem settings, so this device keeps the profile it already had.",
                comment: "Device setup: no radio profile could be copied, and the device's own is left as it is."
            )
        case .leftAsFound(.deviceModemUnreported):
            LocalizedStringResource(
                "This device did not report its modem settings, so it keeps the profile it already had.",
                comment: "Device setup: no radio profile could be copied, and the device's own is left as it is."
            )
        }
    }

    /// Whether the operator still has to choose before Apply.
    func needsChoice(chosen: Bool) -> Bool {
        if case .mustChoose = self { return !chosen }
        return false
    }
}

// MARK: - Results

extension MobileSetupResult {
    /// What the apply status section says about how the last apply ended,
    /// or `nil` when there is nothing to report there: a success has its
    /// own screen, and nothing was sent for the rest.
    var statusText: LocalizedStringResource? {
        switch self {
        case let .notApplied(problem):
            Self.notApplied(problem)
        case .notVerified:
            LocalizedStringResource(
                "The device saved its settings, but they could not be read back. Read it again before relying on them.",
                comment: "Device setup: the device saved, and then could not be read to check what it saved."
            )
        case .administratorsNotApplied:
            LocalizedStringResource(
                "The device took its settings but not the list of who may manage it. Read it again before relying on being able to reach it over the mesh.",
                comment: "Device setup: the settings were saved, the administrator list was not."
            )
        case let .reportedDifferently(setting):
            setting.reportedDifferently
        case .interrupted(configured: false):
            LocalizedStringResource(
                "Setup was stopped while the device was saving. It may or may not have kept these settings—connect to it again and check.",
                comment: "Device setup: the apply was stopped during the device's save."
            )
        case .interrupted(configured: true):
            LocalizedStringResource(
                "Setup was stopped after the device saved its settings, so they were not checked. Read it again before relying on them.",
                comment: "Device setup: the apply was stopped after the device saved and before it was checked."
            )
        case .configured, .invalid, .cancelled, .skipped:
            nil
        }
    }

    /// Why the configuration did not land, in terms that do not accuse the
    /// device of something it did not do.
    private static func notApplied(_ problem: MobileManagementProblem) -> LocalizedStringResource {
        switch problem {
        case .noAnswer:
            LocalizedStringResource(
                "The device stopped answering while saving. It may or may not have kept these settings—connect to it again and check.",
                comment: "Device setup: the device went quiet during the save."
            )
        case .radioBusy:
            LocalizedStringResource(
                "The app was still reading from the device. Nothing was changed on it.",
                comment: "Device setup: the settings were not sent because the app was still busy with the device."
            )
        case .unreadable:
            LocalizedStringResource(
                "The device answered in a form this app does not understand, so it may or may not have kept these settings. Its firmware and this app may be out of step—connect to it again and check.",
                comment: "Device setup: the device's answer to the save could not be read."
            )
        case .noRadio, .unreachable:
            LocalizedStringResource(
                "The device could not be reached. Check its settings before relying on them.",
                comment: "Device setup: the device could not be reached during the save; whether anything was sent is unknown."
            )
        case .refused:
            LocalizedStringResource(
                "The device rejected these settings. Its previous configuration is still in effect.",
                comment: "Device setup: the device refused the settings."
            )
        case .notBuilt, .invalidRequest:
            LocalizedStringResource(
                "This app could not send these settings. Nothing was changed on the device.",
                comment: "Device setup: the app could not build the configuration, so nothing was sent."
            )
        case .unsupported:
            LocalizedStringResource(
                "The device does not support these settings. Nothing was changed on it.",
                comment: "Device setup: the device lacks what the configuration needs, so nothing was sent."
            )
        case .tableFull, .dfuUnsupported, .dfuRefused, .dfuUnconfirmed, .notAllApplied,
             .notRunning, .noOwner, .notThisPhone, .notFound, .sendFailed, .busy, .stopped,
             .other:
            LocalizedStringResource(
                "Setup did not finish. Check the device's settings before relying on them.",
                comment: "Device setup: the configuration failed for a reason that does not say what the device holds."
            )
        }
    }
}
