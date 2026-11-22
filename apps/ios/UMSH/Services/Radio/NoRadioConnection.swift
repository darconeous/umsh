import Foundation
import UMSHMobileCore

/// A connection with no radio behind it: for the test host, previews, and a
/// staged radio whose air would not start.
///
/// It lists no radios and has no driver to hand the app core, and every
/// command it is given fails as a radio that is not there. It fabricates
/// nothing.
final class NoRadioConnection: RadioConnection, Sendable {
    var radioDriver: MobileRadioDriver? { nil }

    func autoConnect() async {}
    func reconnect() async {}
    func connect() async throws { throw RadioConnectionError.radioNotFound }

    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([])
            continuation.finish()
        }
    }

    func selectRadio(_ id: UUID) async throws { throw RadioConnectionError.radioNotFound }
    func stopDiscovery() async {}
    func claimForCurrentIdentity() async throws { throw RadioConnectionError.radioNotFound }
    func factoryReset() async throws { throw RadioConnectionError.radioNotFound }
    func reboot() async throws { throw RadioConnectionError.radioNotFound }
    func enterDfu(mode: UlcpDfuMode) async throws { throw RadioConnectionError.radioNotFound }
    func announce(_ request: MobileAnnouncementRecord) async throws {
        throw RadioConnectionError.radioNotFound
    }
    func clearBluetoothBonds() async throws { throw RadioConnectionError.radioNotFound }
    func setAlert(_ state: RadioAlertState) async throws { throw RadioConnectionError.radioNotFound }
    func refresh() async throws -> RadioSnapshot { throw RadioConnectionError.radioNotFound }
    func refreshPositioning() async throws -> RadioSnapshot {
        throw RadioConnectionError.radioNotFound
    }
    func addDevicePeer(_ publicKey: Data) async throws { throw DevicePeerError.radioUnavailable }
    func removeDevicePeer(_ publicKey: Data) async throws { throw DevicePeerError.radioUnavailable }
    func addDeviceAdmin(_ publicKey: Data) async throws { throw DevicePeerError.radioUnavailable }
    func removeDeviceAdmin(_ publicKey: Data) async throws { throw DevicePeerError.radioUnavailable }
    func addDeviceWifiNetwork(_ item: Data) async throws { throw RemoteManagementError.unavailable }
    func removeDeviceWifiNetwork(ssid: Data) async throws { throw RemoteManagementError.unavailable }
    func fetchCompanionProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        throw RemoteManagementError.unavailable
    }
    func writeCompanionProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        throw RemoteManagementError.unavailable
    }
    func saveCompanionDevice() async throws { throw RemoteManagementError.unavailable }
    func disconnect() async {}
    func forget() async {}
}
