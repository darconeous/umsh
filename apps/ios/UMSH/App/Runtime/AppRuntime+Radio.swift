import Foundation
import UMSHMobileCore

extension AppRuntime {
    func connectRadio() async {
        do {
            try await radioConnection.connect()
        } catch {
            // Connection failures are published as radio snapshots so every
            // screen presents the same state and recovery action.
        }
    }

    func reconnectRadio() async {
        await radioConnection.reconnect()
    }

    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        await radioConnection.discoverRadios()
    }

    func selectRadio(_ id: UUID) async throws {
        try await radioConnection.selectRadio(id)
    }

    func stopRadioDiscovery() async {
        await radioConnection.stopDiscovery()
    }

    func disconnectRadio() async {
        await radioConnection.disconnect()
    }

    func forgetRadio() async {
        await radioConnection.forget()
    }

    func factoryResetRadio() async throws {
        try await radioConnection.factoryReset()
    }

    func rebootRadio() async throws {
        try await radioConnection.reboot()
    }

    func claimRadio() async {
        do {
            try await radioConnection.claimForCurrentIdentity()
        } catch {
            // The adapter publishes a shared failure snapshot when an active
            // claim fails. Preconditions leave the existing snapshot intact.
        }
    }

    /// Ask the radio for its state again. The answer reaches the screen
    /// the way every radio state does, through the core.
    func refreshRadio() async {
        _ = try? await radioConnection.refresh()
    }

    /// Sample the radio's position, for a screen that is showing one.
    ///
    /// Failures are swallowed on purpose: this runs on a timer behind a
    /// view, and a radio that walked out of range mid-poll is a state the
    /// link already reports. An error banner per missed sample would say
    /// the same thing once a minute.
    func refreshRadioPosition() async {
        _ = try? await radioConnection.refreshPositioning()
    }
}
