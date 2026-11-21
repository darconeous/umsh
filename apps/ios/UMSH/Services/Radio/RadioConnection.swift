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
    func enterDfu(mode: UlcpDfuMode) async throws
    /// Ask the radio to announce itself now (`CMD_ANNOUNCE`)—an
    /// advertisement or a beacon, outside either schedule. The radio
    /// answers once it has the announcement queued; channel access and
    /// its duty limit decide when it actually goes out.
    func announce(_ request: MobileAnnouncementRecord) async throws
    /// Forget every host paired with the radio, along with its pairing PIN
    ///—`PROP_BLE_BOND_COUNT` written to zero. The radio answers before
    /// it acts on the link, then drops this phone with the rest and opens
    /// a pairing window—so returning normally means it was done, and the
    /// disconnect that follows is expected rather than a failure.
    func clearBluetoothBonds() async throws
    /// Start or stop the radio's locate alert (`PROP_ALERT`) so a
    /// misplaced radio announces itself. What the radio does is up to its
    /// hardware—a buzzer, an indicator LED, or both—and the alert
    /// overrides a silenced buzzer.
    ///
    /// It deliberately keeps running when the phone walks out of range;
    /// the radio ends it on a button press or its own deadline, reported
    /// back through `RadioSnapshot.alert`.
    func setAlert(_ state: RadioAlertState) async throws
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
    /// Store a peer public key on the radio's device identity
    /// (`PROP_DEV_PEERS`), persisting it with a chained save. Idempotent:
    /// a key the radio already holds resolves as success.
    func addDevicePeer(_ publicKey: Data) async throws
    /// Remove a peer public key from the radio's device identity.
    /// Idempotent: a key the radio does not hold resolves as success.
    func removeDevicePeer(_ publicKey: Data) async throws
    /// Let a node manage the radio over the mesh, by storing its public key
    /// on `PROP_DEV_ADMINS` and persisting it with a chained save.
    /// Idempotent, like the peer list.
    ///
    /// Separate from `addDevicePeer` because the two lists answer different
    /// questions: a peer is someone the radio can talk to, an administrator
    /// is someone it takes orders from.
    func addDeviceAdmin(_ publicKey: Data) async throws
    /// Take a node's authority to manage the radio away again. Idempotent.
    func removeDeviceAdmin(_ publicKey: Data) async throws
    /// Store a Wi-Fi network on the radio (`PROP_WIFI_NETWORKS`), given the
    /// encoded entry a credential has already been folded into.
    ///
    /// Named rather than left to a general insert for the reason the
    /// administrator list is: the item carries a passphrase, and a caller
    /// that could name the property could send one somewhere it would be
    /// echoed back. An entry whose SSID the radio already holds replaces
    /// that one, which is how a mistyped passphrase is corrected.
    func addDeviceWifiNetwork(_ item: Data) async throws
    /// Forget a Wi-Fi network by name. Idempotent: an SSID the radio does
    /// not hold resolves as success.
    func removeDeviceWifiNetwork(ssid: Data) async throws
    /// Store a channel key on the radio's device identity
    /// (`PROP_DEV_CHANNEL_KEYS`), persisting it with a chained save. This is
    /// the device's own membership, separate from the phone's. Idempotent.
    func addDeviceChannel(_ channelKey: Data) async throws
    /// Remove a channel key from the radio's device identity. Idempotent.
    func removeDeviceChannel(_ channelKey: Data) async throws
    /// Read named properties from the companion radio itself, over the
    /// local link, and answer with what it said about each—values and
    /// refusals alike. The local counterpart of `fetchRemoteProperties`,
    /// with the same shape of answer, so the same screens read both.
    func fetchCompanionProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord]
    /// Write properties to the companion radio, in the given order, and
    /// answer with what it says each is now worth. The order is the
    /// caller's plan—a radio-parameter write brackets the PHY—and is
    /// preserved on the air.
    func writeCompanionProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord]
    /// Persist the companion radio's live configuration.
    func saveCompanionDevice() async throws
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

/// Failures of managing a device across the mesh, shaped for the copy the
/// remote-management screen shows.
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

    static func perform(_ operation: () async throws -> UInt32?) async throws {
        let status: UInt32?
        do { status = try await operation() }
        catch { throw DfuEntryError.unconfirmed }
        switch status {
        case 0: return
        case 2, 5: throw DfuEntryError.unsupported
        case let .some(status): throw DfuEntryError.refused(status)
        case nil: throw DfuEntryError.unconfirmed
        }
    }
}

enum RemoteManagementError: Error, Equatable, Sendable {
    /// The device acknowledged the request, then said nothing.
    ///
    /// Deliberately one case for two causes: a device that lost its answer
    /// on the way back and a device that does not list this phone as an
    /// administrator are indistinguishable from here, because an
    /// unauthorized request is answered with silence rather than a refusal.
    /// The screen says both.
    case noAnswer
    /// The request never reached the device: nothing acknowledged it.
    case unreachable
    /// The device answered, and the answer was a refusal. Carries the ULCP
    /// status so the screen can name it.
    case refused(status: UInt32)
    /// The device answered something this exchange cannot make sense of—
    /// a value where a status belonged, or a read that ended with nothing
    /// read.
    case unreadable
    /// The companion radio's own link could not carry the exchange.
    case unavailable
}

/// Failures of device-identity peer mutations, shaped for the UI's
/// disabled-state and inline-error copy.
enum DevicePeerError: Error, Equatable, Sendable {
    /// No attached radio configured for this phone.
    case radioUnavailable
    /// The radio's peer list is full; the device's `NOMEM` is authoritative.
    case deviceFull
    /// The radio does not advertise a device identity domain.
    case unsupported
    /// The radio answered the change in a form this app could not read:
    /// firmware reporting the table's items in a shape this app does not
    /// know. The radio acted on the request; what it reports having done is
    /// not something this app can check, so its table has been read back
    /// and the snapshot shows whatever of it this app can read.
    case unrecognizedAnswer
    /// Any other rejection, carrying the radio's status name.
    case failed(String)
}
