import Foundation
import UMSHMobileCore

/// A companion radio's transport and the plain commands it takes.
///
/// The mesh is not here: the app core holds the radio's driver and runs the
/// mesh session over it. What stays is the link itself—discovery,
/// connecting, the picker—and the commands a person gives the radio.
protocol RadioConnection: AnyObject, Sendable {
    /// The driver the app core holds, or `nil` for a connection with no
    /// radio behind it.
    var radioDriver: MobileRadioDriver? { get }
    func autoConnect() async
    func reconnect() async
    func connect() async throws
    /// Begin an explicit discovery scan and stream the live list of nearby
    /// companion radios. The scan runs until `stopDiscovery()` or `selectRadio`
    /// is called; it never auto-connects. Each element is the full current
    /// list, sorted for display.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]>
    /// Attach to a specific radio surfaced by `discoverRadios()`. Ends
    /// discovery and drives the normal connect/attach path.
    func selectRadio(_ id: UUID) async throws
    /// Cancel an in-progress discovery scan without connecting.
    func stopDiscovery() async
    func claimForCurrentIdentity() async throws
    /// Erase ALL mutable state on the radio (saved provisioning, device
    /// identity, BLE bonds, pairing PIN) and reboot it to a blank factory
    /// state. Requires a live connection; the radio drops the link on reset.
    /// The app also abandons its binding to the radio.
    func factoryReset() async throws
    /// Restart the radio (`CMD_REBOOT`), keeping everything it has saved.
    /// Requires a live connection; the radio drops the link on its way
    /// down and the app's binding to it is deliberately kept, because what
    /// comes back is the same radio.
    func reboot() async throws
    func refresh() async throws -> RadioSnapshot
    /// Sample where the radio is, and how well it knows.
    ///
    /// The radio announces a fix indicator and nothing else about a
    /// position: a receiver reports about a fix a second, and at the
    /// precision it keeps, ordinary noise from a receiver standing still
    /// moves the reading. Announcing that would keep the radio
    /// transmitting, and the phone waking, for a screen that may not even
    /// be open—so a position is asked for, by whoever is showing one,
    /// no more often than they can use the answer.
    ///
    /// Throws on a radio without `CAP_GNSS`, which has nothing to sample.
    func refreshPositioning() async throws -> RadioSnapshot
    func disconnect() async
    /// Unbind from the remembered radio entirely: revoke any standing connect
    /// and clear the persisted `connectedUUID`. The app stops offering
    /// Reconnect and will not auto-connect on launch until a radio is chosen
    /// again via `selectRadio`.
    func forget() async
}

/// How one hop of a path was heard. Both readings are absent when the hop
/// was a point-to-point link—a bridge—that measured nothing.
struct MeshLegSignal: Hashable, Sendable {
    let rssiDBm: Int16?
    let signalToNoiseCentibels: Int16?
}

enum RadioConnectionError: Error, Equatable, Sendable {
    case bluetoothUnavailable
    case radioNotFound
    case incompatibleProtocol
    /// The device refused an encrypted characteristic because it and this
    /// phone have no usable pairing. Distinct from `incompatibleProtocol`:
    /// the device is fine, the pairing is missing.
    case pairingRequired
    case identityUnavailable
    case takeoverNotAllowed
    case operationInProgress
    case operationRejected(String)
    /// The device stopped answering partway through an exchange the link never
    /// reported as broken. Distinct from `operationRejected`: a refusal is the
    /// device saying no, and this is the device saying nothing—so whether it
    /// acted on the request is unknown.
    case operationTimedOut
}

extension RadioConnectionError {
    /// Copy for a device that answered in a form this app could not read: an
    /// echo of the wrong shape for the property, or about a property other
    /// than the one asked. The device carried the request out—what failed is
    /// this app's model of the reply—so the copy names a firmware/app
    /// mismatch rather than a refusal, and does not promise that nothing
    /// changed.
    static let unrecognizedAnswerDescription = """
        The radio answered in a form this app does not understand. Its \
        firmware and this app may be out of step.
        """

    /// The rejection a waiter throws for such an answer. It wears
    /// `operationRejected` because that is what the screens already read;
    /// the description is what tells it apart from a refusal.
    static var unrecognizedAnswer: RadioConnectionError {
        .operationRejected(unrecognizedAnswerDescription)
    }
}

/// The words for a firmware update entry that did not happen, shared by the
/// management status bar and the core's error presentation.
enum DfuEntryError: Error, LocalizedError, Sendable {
    case unconfirmed
    case unsupported
    case refused(UInt32)

    var errorDescription: String? {
        switch self {
        case .unconfirmed:
            String(
                localized: "DFU entry could not be confirmed",
                comment: "Managing a device: it was asked to enter its bootloader and never said it had."
            )
        case .unsupported:
            String(
                localized: "This firmware does not support the requested DFU mode.",
                comment: "Managing a device: its firmware has no such bootloader mode."
            )
        case let .refused(status):
            String(
                localized: "The device refused DFU entry: \(ulcpStatusName(status: status)).",
                comment: "Managing a device: it refused to enter its bootloader. The placeholder is a protocol status name, not translated."
            )
        }
    }
}
