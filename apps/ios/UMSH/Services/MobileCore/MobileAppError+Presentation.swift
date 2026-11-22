import Foundation
import UMSHMobileCore

/// What the app core's failures say to the person holding the phone.
///
/// The core sends codes; these are the only words for them. A caller with
/// something more specific to say about its own context says that instead,
/// and nothing shows a core error's own description.
extension MobileAppError {
    /// What a failed command says, whatever it threw. The core throws only
    /// its own codes; anything else is a fault of this app's.
    static func message(for error: any Error) -> String {
        if let error = error as? MobileAppError { return error.message }
        return String(
            localized: "Something went wrong on this phone.",
            comment: "A command failed for a reason the app has no words for."
        )
    }

    /// The channel's protocol name, never translated.
    private static let emergencyChannelName = "EMERGENCY"

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
        case .NotFound:
            String(
                localized: "It is no longer on this phone.",
                comment: "A peer, channel or conversation was removed while its screen was open."
            )
        case .ChannelTableFull:
            String(
                localized: "This phone is already holding as many channels as it can. Leave one to make room.",
                comment: "Joining a channel: the phone holds as many as it can."
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
        case .Vault(.Unavailable):
            String(
                localized: "Channel keys aren't available right now.",
                comment: "The Keychain would not hand over a channel key yet, as before the phone's first unlock."
            )
        case .Vault(.Failed):
            String(
                localized: "The channel key could not be read.",
                comment: "The Keychain refused to read a channel key."
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
        case .EmergencyNotCertified:
            String(
                localized: "Sending on \(Self.emergencyChannelName) needs its warning accepted first.",
                comment: "A send was refused because the EMERGENCY channel's warning has not been accepted. The placeholder is the channel's name, EMERGENCY, which is not translated."
            )
        case .MessageNotQueued(recorded: true):
            String(
                localized: "It was saved but could not go out. It's marked Not Delivered.",
                comment: "A message was kept in the conversation, but the radio could not take it."
            )
        case .MessageNotQueued(recorded: false):
            String(
                localized: "It could not go out, and that could not be saved. It may show as sending until UMSH restarts.",
                comment: "A message was kept, the radio could not take it, and recording that failed too."
            )
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
