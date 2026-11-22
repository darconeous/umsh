import Foundation
import UMSHMobileCore

/// What a managed device's problem says in the status bar. The core sends
/// the case; these are its only words.
enum ManagementProblemText {
    static func text(for problem: MobileManagementProblem) -> String {
        switch problem {
        case .noAnswer:
            MobileAppError.NoAnswer.message
        case .unreachable:
            MobileAppError.Unreachable.message
        case let .refused(refusal):
            RefusalText.general(refusal)
        case .unreadable:
            MobileAppError.Unreadable.message
        case .noRadio:
            String(
                localized: "No radio to send through.",
                comment: "Managing a node: no radio link is there to carry the request."
            )
        case .radioBusy:
            String(
                localized: "The radio has too many requests waiting.",
                comment: "Managing a node: the radio's queue of outstanding requests is full."
            )
        case .tableFull:
            String(
                localized: "The device's list is full.",
                comment: "Managing a node: a key or network table on the device has no room left."
            )
        case .unsupported:
            String(
                localized: "The device doesn't support this.",
                comment: "Managing a node: it lacks what the request needs."
            )
        case .dfuUnsupported:
            DfuEntryError.unsupported.localizedDescription
        case let .dfuRefused(status):
            DfuEntryError.refused(status).localizedDescription
        case .dfuUnconfirmed:
            DfuEntryError.unconfirmed.localizedDescription
        case .notAllApplied(saving: true):
            String(
                localized: "Settings the device did accept are running but not saved.",
                comment: "Managing a node: some values were refused, so nothing was saved."
            )
        case .notAllApplied(saving: false):
            String(
                localized: "The device rejected some changes.",
                comment: "Managing a node: some values were refused."
            )
        case .notBuilt:
            String(
                localized: "This app couldn't build that request.",
                comment: "Managing a node: the request could not be encoded."
            )
        case .notRunning:
            MobileAppError.NotRunning.message
        case .noOwner:
            MobileAppError.NoOwner.message
        case .notThisPhone:
            MobileAppError.NotThisPhone.message
        case .notFound:
            String(
                localized: "The device no longer has it.",
                comment: "Managing a node: the stored entry the request names is gone."
            )
        case .invalidRequest:
            MobileAppError.InvalidRequest.message
        case .sendFailed:
            MobileAppError.SendFailed.message
        case .busy:
            MobileAppError.Busy.message
        case .stopped:
            MobileAppError.Stopped.message
        case .other:
            String(
                localized: "Something went wrong on this phone.",
                comment: "A command failed for a reason the app has no words for."
            )
        }
    }
}

/// Why a device refused something, said for the row that offered the value
/// (``row(_:)``) or for the status bar (``general(_:)``).
enum RefusalText {
    static func row(_ refusal: MobileRefusal) -> String {
        switch refusal.reason {
        case .notImplemented, .noSuchProperty:
            String(
                localized: "Rejected: the device does not implement this setting.",
                comment: "Managing a node: under a setting it refused."
            )
        case .outOfRange:
            String(
                localized: "Rejected: the device says it is out of range.",
                comment: "Managing a node: under a setting it refused."
            )
        case .notNow:
            String(
                localized: "Rejected: the device's current state does not allow it.",
                comment: "Managing a node: under a setting it refused."
            )
        case .tooLarge:
            String(
                localized: "Rejected: it is too large for the device to hold.",
                comment: "Managing a node: under a setting it refused."
            )
        case .busy:
            String(
                localized: "Rejected: the device was busy.",
                comment: "Managing a node: under a setting it refused."
            )
        case .notPermitted:
            String(
                localized: "Rejected: the device does not allow this change.",
                comment: "Managing a node: under a setting it refused."
            )
        case .noStatus:
            String(
                localized: "The device rejected this value.",
                comment: "Managing a node: under a setting it refused without saying why."
            )
        case .other:
            String(
                localized: "Rejected: the device answered \(statusName(refusal)).",
                comment: "Managing a node: under a setting it refused. The placeholder is a protocol status name, not translated."
            )
        }
    }

    static func general(_ refusal: MobileRefusal) -> String {
        switch refusal.reason {
        case .notImplemented, .noSuchProperty:
            String(
                localized: "The device does not implement this.",
                comment: "Managing a node: it refused a request."
            )
        case .outOfRange:
            String(
                localized: "The device says a value is out of range.",
                comment: "Managing a node: it refused a request."
            )
        case .notNow:
            String(
                localized: "The device's current state does not allow this.",
                comment: "Managing a node: it refused a request."
            )
        case .tooLarge:
            String(
                localized: "This is too large for the device to hold.",
                comment: "Managing a node: it refused a request."
            )
        case .busy:
            String(
                localized: "The device was busy.",
                comment: "Managing a node: it refused a request."
            )
        case .notPermitted:
            String(
                localized: "The device does not allow this.",
                comment: "Managing a node: it refused a request."
            )
        case .noStatus:
            String(
                localized: "The device refused the request.",
                comment: "Managing a node: it refused a request without saying why."
            )
        case .other:
            String(
                localized: "The device refused the request: \(statusName(refusal)).",
                comment: "Managing a node: it refused. The placeholder is a protocol status name, not translated."
            )
        }
    }

    /// The status's protocol name, for the cases that show it.
    static func statusName(_ refusal: MobileRefusal) -> String {
        ulcpStatusName(status: refusal.status ?? 0)
    }
}

/// Why a device would not take a Wi-Fi network, for the join and edit
/// sheets.
enum WifiRefusalText {
    /// The join sheet's sentence. A step-down names both modes.
    static func join(_ refusal: MobileWifiRefusal) -> String {
        switch refusal {
        case .noRoom:
            String(
                localized: "The device has no room for another network. Forget one first.",
                comment: "Joining a Wi-Fi network: the device's network list is full."
            )
        case .credentialRejected:
            credentialRejected
        case let .securityUnsupported(tried, weaker?):
            String(
                localized: "The device cannot use \(wifiSecurityName(tried)) on this network. \(wifiSecurityName(weaker)) is also offered.",
                comment: "Joining a Wi-Fi network: the device refused one security mode. The placeholders are security modes, such as WPA3 and WPA2."
            )
        case let .securityUnsupported(tried, nil):
            cannotUse(tried)
        case let .other(step, refusal):
            other(step, refusal)
        }
    }

    /// The edit sheet's sentence.
    static func update(_ refusal: MobileWifiRefusal) -> String {
        switch refusal {
        case .credentialRejected:
            credentialRejected
        case let .securityUnsupported(tried, _):
            cannotUse(tried)
        case let .other(_, refusal) where refusal.status != nil:
            String(
                localized: "The device refused this change: \(RefusalText.statusName(refusal)).",
                comment: "Editing a saved Wi-Fi network. The placeholder is a protocol status name, not translated."
            )
        case .noRoom, .other:
            String(
                localized: "The device refused this change.",
                comment: "Editing a saved Wi-Fi network: the device refused without saying why."
            )
        }
    }

    private static var credentialRejected: String {
        String(
            localized: "The device would not take that password for this kind of network.",
            comment: "Joining or editing a Wi-Fi network: the device rejected the password."
        )
    }

    private static func cannotUse(_ mode: UInt8) -> String {
        String(
            localized: "The device cannot use \(wifiSecurityName(mode)) on this network.",
            comment: "Joining or editing a Wi-Fi network. The placeholder is a security mode, such as WPA3."
        )
    }

    private static func other(_ step: MobileWifiStep, _ refusal: MobileRefusal) -> String {
        let name = RefusalText.statusName(refusal)
        let named = refusal.status != nil
        return switch (step, named) {
        case (.store, true):
            String(
                localized: "The device refused this network: \(name).",
                comment: "Joining a Wi-Fi network: the device would not store it. The placeholder is a protocol status name, not translated."
            )
        case (.store, false):
            String(
                localized: "The device refused this network.",
                comment: "Joining a Wi-Fi network: the device would not store it, and did not say why."
            )
        case (.turnOn, true):
            String(
                localized: "The device would not turn Wi-Fi on: \(name).",
                comment: "Joining a Wi-Fi network. The placeholder is a protocol status name, not translated."
            )
        case (.turnOn, false):
            String(
                localized: "The device would not turn Wi-Fi on.",
                comment: "Joining a Wi-Fi network: the device refused to switch its station on."
            )
        case (.select, true):
            String(
                localized: "The device would not join this network: \(name).",
                comment: "Joining a Wi-Fi network. The placeholder is a protocol status name, not translated."
            )
        case (.select, false):
            String(
                localized: "The device would not join this network.",
                comment: "Joining a Wi-Fi network: the device refused to switch to it."
            )
        }
    }
}

/// Why an edited value cannot be applied, said under its field.
enum FieldProblemText {
    static func text(for problem: MobileFieldProblem) -> String {
        switch problem {
        case .outOfRange:
            String(
                localized: "This value is out of range.",
                comment: "Managing a node: under a field whose value the device cannot hold."
            )
        case .hostInvalid:
            String(
                localized: "Enter a host name or an IP address.",
                comment: "Managing a node: under the bridge server's host field."
            )
        case .portInvalid:
            String(
                localized: "Enter a port from \(1) to \(65_535).",
                comment: "Managing a node: under the bridge server's port field. The placeholders are the lowest and highest port."
            )
        case .serverKeyInvalid:
            String(
                localized: "Enter a valid UMSH server identity, or leave it empty to clear it.",
                comment: "Managing a node: under the bridge server's identity field."
            )
        case .groupInvalid:
            String(
                localized: "Enter a multicast group or a peer address, with an optional port.",
                comment: "Managing a node: under the local network group field."
            )
        case .limitInvalid:
            String(
                localized: "Enter a limit from \(1) to \(65_535) frames per minute.",
                comment: "Managing a node: under the local network's frame limit. The placeholders are the lowest and highest limit."
            )
        case .addressInvalid:
            String(
                localized: "Enter a valid address for this network.",
                comment: "Managing a node: under a static IP address field."
            )
        case .prefixInvalid:
            String(
                localized: "Enter a prefix length that fits the address.",
                comment: "Managing a node: under a static IP address's prefix length."
            )
        case .gatewayInvalid:
            String(
                localized: "Enter a valid router address, or leave it empty.",
                comment: "Managing a node: under a static IP configuration's router field."
            )
        case .resolverInvalid:
            String(
                localized: "Enter a valid address for each resolver.",
                comment: "Managing a node: under the list of DNS resolvers."
            )
        }
    }
}

/// Why a Wi-Fi network entry cannot be sent yet, for the join and edit
/// sheets.
enum WifiEntryProblemText {
    static func text(for problem: MobileWifiEntryProblem) -> String {
        switch problem {
        case .ssidEmpty:
            String(
                localized: "Enter the network's name.",
                comment: "Adding a Wi-Fi network: no name entered."
            )
        case .ssidTooLong:
            String(
                localized: "That name is too long for a Wi-Fi network.",
                comment: "Adding a Wi-Fi network: the name is longer than a network name can be."
            )
        case .credentialRequired:
            String(
                localized: "Enter the password.",
                comment: "Joining a Wi-Fi network: this security mode needs a password."
            )
        case .credentialInvalid:
            String(
                localized: "That is not a password this network's security can use.",
                comment: "Joining a Wi-Fi network: the password does not fit the chosen security mode."
            )
        }
    }

    /// Whether the sheet says it while the operator types: the problems
    /// that are about what was typed, not about what is still to come.
    static func showsWhileTyping(_ problem: MobileWifiEntryProblem) -> Bool {
        switch problem {
        case .ssidTooLong, .credentialInvalid: true
        case .ssidEmpty, .credentialRequired: false
        }
    }
}
