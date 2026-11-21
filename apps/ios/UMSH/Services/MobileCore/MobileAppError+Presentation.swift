import Foundation
import UMSHMobileCore

/// What the app core's failures say to the person holding the phone.
///
/// The core sends codes; these are the only words for them. A caller with
/// something more specific to say about its own context says that instead,
/// and nothing shows a core error's own description.
extension MobileAppError {
    var message: String {
        switch self {
        case .Store:
            String(
                localized: "Stored information could not be read.",
                comment: "The phone's database failed."
            )
        case .InvalidInput:
            String(localized: "That isn't a valid address.", comment: "A node's address did not decode.")
        case .InvalidRequest, .OperationReused:
            String(
                localized: "This request can't be made.",
                comment: "The phone's mesh session would not make a request as asked."
            )
        case .NoOwner, .NotRunning:
            String(
                localized: "Your identity isn't ready yet.",
                comment: "Asked for something before this phone's identity has started."
            )
        case .Busy:
            String(
                localized: "Not available while your identity is being set up or erased.",
                comment: "Asked for something while this phone's identity is starting, erasing or stopping."
            )
        case .Stopped:
            String(
                localized: "Not available while switching radios.",
                comment: "Asked for something while the app moves to another radio."
            )
        case let .StartFailed(reason):
            reason.message
        case .Vault:
            String(
                localized: "Channel keys could not be erased.",
                comment: "Erasing this phone's identity: the channel keys stayed in the Keychain."
            )
        case .CountersNotRemoved:
            String(
                localized: "Message counters could not be erased.",
                comment: "Erasing this phone's identity: its message counter files stayed."
            )
        case .NoRadio:
            String(localized: "No companion radio is connected.", comment: "Why a ping could not be sent.")
        case .NotThisPhone:
            String(localized: "This radio is not set up for this phone.", comment: "Why a ping could not be sent.")
        case .NoAnswer:
            String(
                localized: "No answer. This phone may not be one of its administrators.",
                comment: "Managing a node: it acknowledged a request but never answered."
            )
        case .Unreachable:
            String(
                localized: "Couldn't reach the device.",
                comment: "Managing a node: a request was never acknowledged."
            )
        case .Unreadable:
            String(
                localized: "The device's answer couldn't be read. Its firmware may be newer than this app.",
                comment: "Managing a node: its reply did not decode."
            )
        case let .Refused(status):
            String(
                localized: "The device refused the request: \(ulcpStatusName(status: status)).",
                comment: "Managing a node: it refused. The placeholder is a protocol status name, not translated."
            )
        case .Cancelled:
            String(localized: "The operation was canceled.", comment: "A request the person stopped.")
        case .SendFailed:
            String(localized: "The radio could not send it.", comment: "The phone's radio could not transmit a request.")
        case .DfuUnsupported:
            DfuEntryError.unsupported.localizedDescription
        case let .DfuRefused(status):
            DfuEntryError.refused(status).localizedDescription
        case .DfuUnconfirmed:
            DfuEntryError.unconfirmed.localizedDescription
        }
    }
}

extension MobileAppStartFailure {
    /// Why this phone's identity did not start.
    var message: String {
        switch self {
        case .hostKey:
            String(
                localized: "The radio did not accept this phone's key.",
                comment: "Starting this phone's identity: the companion radio refused its host key."
            )
        case .session:
            String(
                localized: "Message counters could not be opened.",
                comment: "Starting this phone's identity: its message counter files could not be used."
            )
        case .store:
            String(
                localized: "Stored information could not be prepared.",
                comment: "Starting this phone's identity: the phone's database could not be readied."
            )
        }
    }
}
