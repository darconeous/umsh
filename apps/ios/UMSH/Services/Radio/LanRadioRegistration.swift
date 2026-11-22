import CoreLocation
import Foundation
import NetworkExtension
import OSLog

/// The Wi-Fi networks the LAN virtual radio runs on.
///
/// The system starts the radio's network extension when the phone joins a
/// listed network and stops it when the phone leaves. Listing a network
/// takes its SSID, which iOS reveals only to an app with location
/// permission.
@MainActor
enum LanRadioRegistration {
    private static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "lan-radio")

    static let providerBundleIdentifier = "com.voria.umsh.app.lan-radio"

    /// List the network the phone is on and enable the radio. Returns
    /// false when there is no Wi-Fi network to list, or its name is not
    /// available to the app.
    @discardableResult
    static func includeCurrentNetwork() async -> Bool {
        await LocationAuthorization.request()
        guard let ssid = await NEHotspotNetwork.fetchCurrent()?.ssid else {
            logger.notice("no current Wi-Fi network to list for the LAN radio")
            return false
        }
        do {
            let manager = try await NEAppPushManager.loadAllFromPreferences().first ?? NEAppPushManager()
            manager.localizedDescription = "UMSH Local Network"
            manager.providerBundleIdentifier = providerBundleIdentifier
            if !manager.matchSSIDs.contains(ssid) {
                manager.matchSSIDs.append(ssid)
            }
            manager.isEnabled = true
            try await manager.saveToPreferences()
            logger.notice("the LAN radio runs on \(manager.matchSSIDs.count) networks")
            return true
        } catch {
            logger.error("could not list the network for the LAN radio: \(String(describing: error))")
            return false
        }
    }

    /// Stop running the radio on every listed network, keeping the list.
    static func disable() async {
        do {
            for manager in try await NEAppPushManager.loadAllFromPreferences() where manager.isEnabled {
                manager.isEnabled = false
                try await manager.saveToPreferences()
            }
        } catch {
            logger.error("could not disable the LAN radio: \(String(describing: error))")
        }
    }
}

/// Asks for when-in-use location permission, if it has not been asked
/// for, and waits for the answer.
@MainActor
private final class LocationAuthorization: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private var answer: CheckedContinuation<Void, Never>?
    /// Kept alive by itself until the answer lands.
    private var retained: LocationAuthorization?

    static func request() async {
        await LocationAuthorization().ask()
    }

    private func ask() async {
        guard manager.authorizationStatus == .notDetermined else { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            answer = continuation
            retained = self
            manager.delegate = self
            manager.requestWhenInUseAuthorization()
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_: CLLocationManager) {
        MainActor.assumeIsolated {
            guard self.manager.authorizationStatus != .notDetermined, let answer else { return }
            self.answer = nil
            retained = nil
            answer.resume()
        }
    }
}
