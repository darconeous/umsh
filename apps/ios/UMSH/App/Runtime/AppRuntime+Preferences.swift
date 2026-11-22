import Foundation
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Preferences

    // Read straight from UserDefaults: the runtime outlives any view, so it
    // cannot lean on @AppStorage. The fallback values mirror the view
    // layer's declarations exactly.

    /// Whether the user has been introduced to this phone's identity. Set
    /// when the first-run flow finishes, however it finishes.
    var onboardingCompleted: Bool {
        get { UserDefaults.standard.bool(forKey: "onboarding.completed") }
        set { UserDefaults.standard.set(newValue, forKey: "onboarding.completed") }
    }

    /// Whether this phone answers nearby nodes' identity requests.
    private var phoneDiscoverable: Bool {
        UserDefaults.standard.object(forKey: "phone.discoverable") as? Bool ?? true
    }

    /// Whether this phone's identity carries its location, and at what
    /// cell size.
    var phoneSharesLocation: Bool {
        UserDefaults.standard.bool(forKey: "phone.shareLocation")
    }

    /// Whether test messages on `EMERGENCY` call for attention like any
    /// other message. Off unless asked for.
    private var testMessageAlerts: Bool {
        UserDefaults.standard.bool(forKey: "notifications.testMessages")
    }

    var phoneLocationPrecision: UInt8 {
        CoreLimits.locationPrecision(stored: UserDefaults.standard.object(forKey: "phone.locationPrecision") as? Int)
    }

    /// How far what this phone sends may travel: the ceiling on messages,
    /// pings, and requests, and the budget on a scheduled beacon. The core
    /// holds both to what the flood-hop field can carry.
    private var phoneFloodHops: UInt8 {
        CoreLimits.floodHops(stored: UserDefaults.standard.object(forKey: "phone.floodHops") as? Int)
    }

    private var phoneBeaconFloodHops: UInt8 {
        CoreLimits.beaconFloodHops(stored: UserDefaults.standard.object(forKey: "phone.beaconFloodHops") as? Int)
    }

    /// The preferences the core acts on, as it takes them.
    var currentPolicy: MobileAppPolicyRecord {
        let defaults = UserDefaults.standard
        // How often this phone announces itself unasked, in seconds, with 0
        // for never. Both default to off: a radio is deployed to be part of
        // the mesh, but a phone is carried, and putting its identity on the
        // air on a timer is a decision rather than a default.
        return MobileAppPolicyRecord(
            advertIntervalSeconds: UInt32(clamping: defaults.integer(forKey: "phone.advertIntervalSeconds")),
            beaconIntervalSeconds: UInt32(clamping: defaults.integer(forKey: "phone.beaconIntervalSeconds")),
            discoverable: phoneDiscoverable,
            floodHops: phoneFloodHops,
            beaconFloodHops: phoneBeaconFloodHops,
            locationPrecision: phoneSharesLocation ? phoneLocationPrecision : nil,
            testMessageAlerts: testMessageAlerts
        )
    }

    /// The first-run flow finished, however it finished.
    func completeOnboarding() {
        onboardingCompleted = true
        shouldPresentOnboarding = false
    }
}
