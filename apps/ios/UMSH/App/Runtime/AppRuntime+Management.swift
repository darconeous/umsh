import Foundation
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Managing devices

    /// Manage `peer`: over the attached radio's own link when it is that
    /// radio, across the mesh otherwise. The core decides which.
    ///
    /// Handed out whether or not a radio is attached: a device out of reach
    /// says so on its own screen, and a Manage Device that comes and goes
    /// with the radio is one an operator cannot find when they need it.
    func manageDevice(_ peer: PeerSummary) async throws -> ManageDeviceModel {
        guard let core else { throw MobileAppError.Stopped }
        let device = try await core.manageDevice(
            address: peer.identity.canonicalAddress,
            usesBluetooth: radioConnection is CoreBluetoothRadioConnection
        )
        return adopt(device, address: peer.identity.canonicalAddress, fallbackName: peer.displayName)
    }

    /// Manage the attached radio over its own link, whether or not it holds
    /// an identity of its own to be a peer under.
    func manageRadio(name: String) async throws -> ManageDeviceModel {
        guard let core else { throw MobileAppError.Stopped }
        let device = try await core.manageRadio(
            usesBluetooth: radioConnection is CoreBluetoothRadioConnection
        )
        return adopt(
            device,
            address: radioSnapshot.deviceIdentity?.canonicalAddress ?? "",
            fallbackName: name
        )
    }

    /// Manage the bench device an administrative session's `driver` is
    /// attached to. The session forwards the driver's pushes to it.
    func manageAdministered(
        driver: MobileRadioDriver,
        phoneNodeKey: Data?,
        peer: PeerSummary
    ) async throws -> ManageDeviceModel {
        guard let core else { throw MobileAppError.Stopped }
        let device = try await core.manageAdministered(
            driver: driver,
            phoneNodeKey: phoneNodeKey,
            usesBluetooth: true
        )
        return adopt(device, address: peer.identity.canonicalAddress, fallbackName: peer.displayName)
    }

    // MARK: - Setting up devices

    /// What the setup sheet asks of the core, handed to it when it opens.
    var deviceSetupServices: DeviceSetupServices {
        DeviceSetupServices(
            companion: { await self.setupCompanion() },
            setUp: { driver, goal, companion, phoneNodeKey in
                try await self.setUpDevice(
                    driver: driver,
                    goal: goal,
                    companion: companion,
                    phoneNodeKey: phoneNodeKey
                )
            }
        )
    }

    /// The radio profile a set-up device is put on: this phone's radio's,
    /// as it reports it now. `nil` with no radio, or none reported.
    func setupCompanion() async -> MobileSetupCompanionRecord? {
        guard let core else { return nil }
        return try? await core.setupCompanion()
    }

    /// Set up the device an administrative session's `driver` is attached
    /// to as `goal`. The setup shares the engine `manageAdministered` makes
    /// for the same driver.
    func setUpDevice(
        driver: MobileRadioDriver,
        goal: MobileSetupGoal,
        companion: MobileSetupCompanionRecord?,
        phoneNodeKey: Data?
    ) async throws -> MobileDeviceSetup {
        guard let core else { throw MobileAppError.Stopped }
        return try await core.setUpDevice(
            driver: driver,
            goal: goal,
            companion: companion,
            phoneNodeKey: phoneNodeKey,
            usesBluetooth: true,
            phoneZoneRule: phoneTimeZoneRule
        )
    }

    private func adopt(
        _ device: MobileManagedDevice,
        address: String,
        fallbackName: String
    ) -> ManageDeviceModel {
        let model = ManageDeviceModel(device: device, address: address, fallbackName: fallbackName)
        managedDevices.register(model)
        return model
    }
}
