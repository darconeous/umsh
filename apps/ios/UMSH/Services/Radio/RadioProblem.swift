import Foundation
import os
import UMSHMobileCore

/// A failure a transport reports in its own terms. The driver carries
/// problems as codes, never text, so each of these travels as a code under
/// this app's own domain and is worded again when it is shown.
enum RadioTransportProblem: Int64, CaseIterable, Sendable {
    // Bluetooth attachment
    case unsendableFrame = 1
    case linkLost
    case writeUnacknowledged
    case attachmentIncomplete
    case serviceMissing
    case serviceIncompatible
    case attachmentRefused
    case endpointUnwritable
    case writeModeUnsupported
    case connectionFailed
    case noRadioFound
    case noSavedRadio
    case savedRadioUnknown
    case removalFailed

    // Bluetooth itself
    case bluetoothUnauthorized
    case bluetoothUnsupported
    case bluetoothOff
    case bluetoothResetting
    case bluetoothStarting
    case bluetoothUnavailable

    // Accessory setup
    case accessoriesLoading
    case accessorySetupOpen
    case accessorySetupUnfinished
    case accessoryNeeded
    case accessoriesUnavailable

    // A bridged radio
    case bridgeUnreachable
    case bridgeWaiting
    case bridgeFailed
    case bridgeClosed

    // The local network radio
    case localRadioStopped
    case localRadioNotRunning
    case localRadioClosed
    case localRadioInUse
    case localRadioUnavailable

    // An administered radio
    case accessRemoved
    case connectionIncomplete

    static let domain = "com.voria.umsh.radio-transport"

    var problem: MobileRadioProblem {
        .transport(domain: Self.domain, code: rawValue)
    }

    var text: String {
        switch self {
        case .unsendableFrame:
            String(localized: "The ULCP session produced an unsendable frame")
        case .linkLost:
            String(localized: "The radio is no longer connected")
        case .writeUnacknowledged:
            String(localized: "The radio did not acknowledge a Bluetooth write")
        case .attachmentIncomplete:
            String(localized: "The radio did not finish Bluetooth attachment")
        case .serviceMissing:
            String(localized: "The radio does not expose the ULCP service")
        case .serviceIncompatible:
            String(localized: "The radio has an incompatible ULCP service")
        case .attachmentRefused:
            String(localized: "The radio refused the ULCP attachment")
        case .endpointUnwritable:
            String(localized: "The radio has no writable ULCP endpoint")
        case .writeModeUnsupported:
            String(localized: "The radio requires an unsupported write mode")
        case .connectionFailed:
            String(localized: "The radio connection failed")
        case .noRadioFound:
            String(localized: "No companion radio was found")
        case .noSavedRadio:
            String(localized: "No saved companion radio is available to reconnect")
        case .savedRadioUnknown:
            String(localized: "The saved companion radio is not known to Bluetooth")
        case .removalFailed:
            String(localized: "The radio could not be removed. Try again in Choose a Radio.")
        case .bluetoothUnauthorized:
            String(localized: "Bluetooth permission is denied")
        case .bluetoothUnsupported:
            String(localized: "Bluetooth is unavailable on this device")
        case .bluetoothOff:
            String(localized: "Bluetooth is turned off")
        case .bluetoothResetting:
            String(localized: "Bluetooth is restarting")
        case .bluetoothStarting:
            String(localized: "Bluetooth is starting")
        case .bluetoothUnavailable:
            String(localized: "Bluetooth is unavailable")
        case .accessoriesLoading:
            RadioAccessoryBlock.loading.text
        case .accessorySetupOpen:
            RadioAccessoryBlock.setupOpen.text
        case .accessorySetupUnfinished:
            RadioAccessoryBlock.setupUnfinished.text
        case .accessoryNeeded:
            RadioAccessoryBlock.needed.text
        case .accessoriesUnavailable:
            String(localized: "Saved radios could not be loaded.")
        case .bridgeUnreachable:
            String(localized: "The radio bridge is unreachable")
        case .bridgeWaiting:
            String(localized: "Waiting for the radio bridge")
        case .bridgeFailed:
            String(localized: "The connection to the radio failed")
        case .bridgeClosed:
            String(localized: "The radio bridge closed the connection")
        case .localRadioStopped:
            String(localized: "The local network radio stopped")
        case .localRadioNotRunning:
            String(localized: "The local network radio is not running")
        case .localRadioClosed:
            String(localized: "The local network radio closed the connection")
        case .localRadioInUse:
            String(localized: "The local network radio is in use elsewhere")
        case .localRadioUnavailable:
            String(localized: "The local network radio could not start")
        case .accessRemoved:
            String(localized: "Access to this radio was removed in Settings")
        case .connectionIncomplete:
            String(localized: "The radio did not finish connecting")
        }
    }
}

extension MobileRadioProblem {
    /// An operating-system error, carried as its domain and code.
    static func system(_ error: any Error) -> Self {
        let error = error as NSError
        let text = BluetoothErrorText.describe(error)
        systemWording.withLock { $0[SystemErrorKey(error)] = text }
        return .transport(domain: error.domain, code: Int64(error.code))
    }

    /// How the system worded each error carried here. A domain and code
    /// alone no longer have the description the error arrived with.
    private static let systemWording = OSAllocatedUnfairLock<[SystemErrorKey: String]>(
        initialState: [:]
    )

    private struct SystemErrorKey: Hashable, Sendable {
        let domain: String
        let code: Int64

        init(_ error: NSError) {
            domain = error.domain
            code = Int64(error.code)
        }

        init(domain: String, code: Int64) {
            self.domain = domain
            self.code = code
        }
    }

    /// What to tell the user.
    var text: String {
        switch self {
        case .disconnected:
            String(localized: "Radio disconnected")
        case .invalidFrame:
            String(localized: "The radio sent an invalid ULCP frame")
        case .unusableValue:
            String(localized: "The radio sent a value the session could not use")
        case .sessionStartFailed:
            String(localized: "The ULCP session could not start")
        case .synchronizationStalled:
            String(localized: "The companion radio did not finish synchronizing")
        case .claimFailed:
            String(localized: "The radio could not replace its configured host")
        case let .operationRejected(operation, statusCode, statusName):
            // The operation and status are diagnostic labels from the
            // radio, shown as they are.
            String(localized: "\(operation) failed: \(statusName) (\(statusCode))")
        case .unrecognizedAnswer:
            RadioConnectionError.unrecognizedAnswerDescription
        case .radioBusy:
            String(localized: "Radio remained busy; send was not transmitted")
        case let .transmissionRejected(_, statusName):
            String(localized: "Radio rejected the transmission: \(statusName)")
        case .transmissionUnreported:
            String(localized: "The radio did not report what happened to a transmission")
        case .transmissionUnsendable:
            String(localized: "The ULCP session rejected an outbound frame before transmission")
        case .autoEnableFailed:
            String(localized: "The companion radio could not be enabled automatically")
        case let .transport(domain, code):
            if domain == RadioTransportProblem.domain {
                RadioTransportProblem(rawValue: code)?.text
                    ?? String(localized: "The radio connection failed")
            } else {
                Self.systemWording.withLock { $0[SystemErrorKey(domain: domain, code: code)] }
                    ?? BluetoothErrorText.describe(NSError(domain: domain, code: Int(code)))
            }
        }
    }
}
