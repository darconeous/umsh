import Foundation
import UMSHMobileCore

struct RadioSnapshot: Equatable, Sendable {
    var linkState: RadioLinkState
    var name: String?
    var localIdentifier: UUID?
    var batteryPercentage: Int?
    /// Terminal voltage in millivolts, on radios that measure it. Stored as
    /// the device reports it; presentation converts to volts.
    var batteryVoltageMillivolts: Int?
    var chargeState: RadioChargeState?
    var batteryReadAt: Date?
    var deviceIdentity: MeshPublicIdentity?
    var hostState: RadioHostState
    var provisioning: RadioProvisioningSummary?
    /// `PROP_ALERT`, or `nil` on a radio that cannot make itself
    /// conspicuous (no `CAP_ALERT`) — the Find control is hidden then
    /// rather than shown disabled. Defaulted so the many
    /// no-radio-attached snapshots stay unchanged.
    var alert: RadioAlertState? = nil
    /// The device's wall clock as of when it last reported one, or `nil`
    /// on a radio without `CAP_TIME` and until the first reading arrives.
    var clock: RadioClock? = nil
    /// What the receiver reports, on a radio with `CAP_GNSS`. Carried on
    /// every update rather than taken once — a position is state to
    /// mirror, not an event.
    var position: RadioPosition? = nil
    var problemDescription: String?

    static let idle = Self(
        linkState: .idle,
        name: nil,
        localIdentifier: nil,
        batteryPercentage: nil,
        batteryVoltageMillivolts: nil,
        chargeState: nil,
        batteryReadAt: nil,
        deviceIdentity: nil,
        hostState: .unknown,
        provisioning: nil,
        problemDescription: nil
    )

    static let disconnected = Self(
        linkState: .idle,
        name: nil,
        localIdentifier: nil,
        batteryPercentage: nil,
        batteryVoltageMillivolts: nil,
        chargeState: nil,
        batteryReadAt: nil,
        deviceIdentity: nil,
        hostState: .unknown,
        provisioning: nil,
        problemDescription: "Radio disconnected"
    )

    static let previewReady = Self(
        linkState: .ready,
        name: "T-Echo",
        localIdentifier: UUID(uuidString: "F2A1073A-2FF5-4D85-B71D-6A81031A9C25"),
        batteryPercentage: 82,
        batteryVoltageMillivolts: 3_820,
        chargeState: .discharging,
        batteryReadAt: .now,
        deviceIdentity: MeshPublicIdentity(
            canonicalAddress: "111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
            hint: MeshNodeHint(bytes: Data([0x00, 0x01, 0x02]), text: "111t")
        ),
        hostState: .matchesCurrentIdentity,
        provisioning: RadioProvisioningSummary(
            capabilityCount: 8,
            hasHostFiltering: true,
            supportsOfflineQueue: true,
            supportsDelegatedAcknowledgements: false,
            supportsDeviceName: true,
            supportsLoRa: true,
            supportsDutyCycleLimit: true,
            supportsBattery: true,
            phyEnabled: true,
            frequencyKHz: 915_000,
            transmitPowerDBm: 14,
            bandwidthHz: 125_000,
            spreadingFactor: 9,
            codingRateDenominator: 5,
            dutyCycleNow: 65,
            dutyCycleLimit: 655,
            saved: .current,
            queuedFrames: 0,
            droppedFrames: 0,
            filterCount: 2,
            hostChannelCount: 1,
            hostPeerCount: 3,
            autoAcknowledgementEnabled: false,
            supportsDeviceIdentity: true,
            devPeerAddresses: []
        ),
        alert: RadioAlertState.none,
        problemDescription: nil
    )

    /// Whether the radio is running on external power, which follows from
    /// the charge state rather than being reported separately.
    var isExternallyPowered: Bool? {
        chargeState.map { $0 != .discharging }
    }

    /// Whether the radio measures its own power state at all
    /// (`CAP_BATTERY`). False on a radio that will never report one, so
    /// power detail is hidden rather than shown as unavailable.
    var reportsBattery: Bool {
        provisioning?.supportsBattery ?? false
    }

    var accessibleSummary: String {
        var parts = [linkState.accessibilityLabel]
        if let name {
            parts.append(name)
        }
        // A radio charging off a rail it cannot estimate a level from
        // still reports its terminal voltage, which is a measurement
        // rather than the absence of one.
        if let batteryPercentage {
            parts.append("Battery \(batteryPercentage) percent")
        } else if let millivolts = batteryVoltageMillivolts {
            parts.append("Battery \(formattedVolts(millivolts))")
        } else if reportsBattery {
            parts.append("Battery level unavailable")
        }
        if let chargeState {
            parts.append(chargeState.accessibilityLabel)
        }
        return parts.joined(separator: ", ")
    }
}

/// Millivolts as the volts a person reads off a meter — 3820 → "3.82 V".
/// Devices report terminal voltage in millivolts; nothing displays it that way.
func formattedVolts(_ millivolts: Int) -> String {
    let volts = Double(millivolts) / 1_000
    return volts.formatted(.number.precision(.fractionLength(2))) + " V"
}

/// What a radio's charging system is doing (`PROP_BATTERY`).
enum RadioChargeState: String, Equatable, Sendable {
    case discharging
    case charging
    case charged

    init(_ state: UlcpChargeState) {
        self = switch state {
        case .discharging: .discharging
        case .charging: .charging
        case .charged: .charged
        }
    }

    var label: String {
        switch self {
        case .discharging: "Discharging"
        case .charging: "Charging"
        case .charged: "Charged"
        }
    }

    var accessibilityLabel: String {
        switch self {
        case .discharging: "Discharging"
        case .charging: "Charging"
        case .charged: "Charged, on external power"
        }
    }

    /// SF Symbol for the toolbar's external-power cue, or `nil` while the
    /// radio is running off its battery.
    var externalPowerSymbol: String? {
        switch self {
        case .discharging: nil
        case .charging: "bolt.fill"
        case .charged: "powerplug.fill"
        }
    }
}

enum RadioLinkState: String, Equatable, Sendable {
    case idle
    case unavailable
    case scanning
    case discovered
    case connecting
    case reconnecting
    /// A saved radio is out of reach, but a standing system connection
    /// request remains armed: the moment the radio powers on and
    /// advertises, iOS completes the connection — waking or relaunching
    /// the app in the background if needed.
    case waitingForRadio
    case pairing
    case attaching
    case synchronizing
    case awaitingHost
    case provisioning
    case configuring
    case attached
    case ready
    case disconnecting
    case failed

    var accessibilityLabel: String {
        switch self {
        case .idle: "No radio connected"
        case .unavailable: "Bluetooth unavailable"
        case .scanning: "Looking for companion radios"
        case .discovered: "Radio discovered"
        case .connecting: "Radio connecting"
        case .reconnecting: "Reconnecting to saved radio"
        case .waitingForRadio: "Waiting for the radio to appear"
        case .pairing: "Radio pairing"
        case .attaching: "Radio attaching"
        case .synchronizing: "Radio synchronizing"
        case .awaitingHost: "Radio needs a host decision"
        case .provisioning: "Radio provisioning"
        case .configuring: "Saving radio settings"
        case .attached: "Radio attached"
        case .ready: "Radio connected"
        case .disconnecting: "Radio disconnecting"
        case .failed: "Radio connection failed"
        }
    }

    var symbolName: String {
        switch self {
        case .attached, .ready: "antenna.radiowaves.left.and.right"
        case .scanning, .connecting, .reconnecting, .waitingForRadio, .pairing, .attaching,
             .synchronizing, .provisioning, .configuring:
            "antenna.radiowaves.left.and.right.circle"
        case .failed: "exclamationmark.triangle.fill"
        default: "antenna.radiowaves.left.and.right.slash"
        }
    }
}

/// A device's wall clock (`PROP_TIME`), paired with the instant it was
/// read.
///
/// The pairing is the point: a device reports an epoch, and an epoch alone
/// cannot be told apart from one read an hour ago. `readAt` is what lets a
/// screen say how far off the device is *now*.
struct RadioClock: Equatable, Sendable {
    /// What the device said the time was, or `nil` when it does not know
    /// — a device that has had no fix, no manual set, and no retained
    /// clock says so rather than reporting an epoch of zero.
    let date: Date?
    let readAt: Date

    /// How far the device's clock is from this phone's, accounting for
    /// the time since it was read. `nil` when the device has no clock.
    func drift(asOf now: Date = .now) -> TimeInterval? {
        date.map { $0.addingTimeInterval(now.timeIntervalSince(readAt)).timeIntervalSince(now) }
    }

    /// The drift stated the way a person would, or `nil` when the clocks
    /// agree closely enough that saying anything would be noise.
    func driftSummary(asOf now: Date = .now) -> String? {
        guard let drift = drift(asOf: now), abs(drift) >= 2 else { return nil }
        let magnitude = Duration.seconds(abs(drift.rounded()))
            .formatted(.units(allowed: [.days, .hours, .minutes, .seconds], maximumUnitCount: 2))
        return drift > 0 ? "\(magnitude) ahead of this iPhone" : "\(magnitude) behind this iPhone"
    }
}

/// What a device's GNSS receiver reports (`PROP_GNSS_*`).
struct RadioPosition: Equatable, Sendable {
    let fix: UlcpFixKind
    /// Center of the reported cell. A location names a cell rather than a
    /// point, and `cellMeters` is how large that cell is — a pin drawn
    /// without it claims a precision the device did not report.
    let latitude: Double?
    let longitude: Double?
    let cellMeters: Double?
    let altitudeMeters: Int32?
    let accuracyDecimeters: UInt16?
    let satellitesUsed: UInt8
    let satellitesInView: UInt8?

    init(_ record: UlcpGnssRecord) {
        fix = record.fix
        latitude = record.latitudeDeg
        longitude = record.longitudeDeg
        cellMeters = record.locationCellMeters
        altitudeMeters = record.altitudeM
        accuracyDecimeters = record.accuracyDm
        satellitesUsed = record.satellitesUsed
        satellitesInView = record.satellitesInView
    }

    /// What the receiver is doing. "Searching" and "off" look identical
    /// on the wire, so the caller supplies whether the receiver is
    /// powered; without that, an off receiver would read as one failing
    /// to find the sky.
    func fixLabel(receiverEnabled: Bool?) -> String {
        switch fix {
        case .none:
            switch receiverEnabled {
            case false: "Receiver off"
            case true: "Searching"
            case nil: "No fix"
            }
        case .twoD: "2D fix"
        case .threeD: "3D fix"
        }
    }

    var coordinateText: String? {
        guard let latitude, let longitude else { return nil }
        // Decimal places matched to the cell the device reported: digits
        // finer than the grid code resolves would be invented.
        let places = cellMeters.map { cell in
            let degreeMeters = 111_320.0
            return max(0, min(7, Int(log10(degreeMeters / max(cell, 0.01)).rounded(.up))))
        } ?? 5
        let format = FloatingPointFormatStyle<Double>.number.precision(.fractionLength(places))
        return "\(latitude.formatted(format)), \(longitude.formatted(format))"
    }

    /// How large an area the reported cell covers, stated plainly.
    var cellText: String? {
        cellMeters.map { meters in
            meters >= 1_000
                ? "\((meters / 1_000).formatted(.number.precision(.fractionLength(0)))) km cell"
                : "\(meters.formatted(.number.precision(.fractionLength(meters < 10 ? 1 : 0)))) m cell"
        }
    }

    /// The receiver's own accuracy estimate. Scaled from dilution of
    /// precision rather than measured, and labelled as such wherever it
    /// is shown.
    var accuracyText: String? {
        accuracyDecimeters.map { decimeters in
            "±\((Double(decimeters) / 10).formatted(.number.precision(.fractionLength(1)))) m"
        }
    }

    var satellitesText: String {
        satellitesInView.map { "\(satellitesUsed) used of \($0) in view" }
            ?? "\(satellitesUsed) used"
    }
}

/// What the radio is doing to make itself findable (`PROP_ALERT`).
enum RadioAlertState: String, Equatable, Sendable {
    case none
    case locating

    init(_ state: UlcpAlertState) {
        self = switch state {
        case .none: .none
        case .locate: .locating
        }
    }

    var wire: UlcpAlertState {
        switch self {
        case .none: .none
        case .locating: .locate
        }
    }

    var isLocating: Bool { self == .locating }
}

enum RadioHostState: String, Equatable, Sendable {
    case unknown
    case localIdentityUnavailable
    case unsupported
    case unclaimed
    case matchesCurrentIdentity
    case belongsToAnotherIdentity
    case claiming

    var label: String {
        switch self {
        case .unknown: "Not checked"
        case .localIdentityUnavailable: "Phone identity unavailable"
        case .unsupported: "Transparent radio"
        case .unclaimed: "Not configured"
        case .matchesCurrentIdentity: "This phone"
        case .belongsToAnotherIdentity: "Another host"
        case .claiming: "Updating"
        }
    }

    static func classify(radioKey: Data, selectedHostKey: Data?) -> Self {
        guard let selectedHostKey else { return .localIdentityUnavailable }
        if radioKey.isEmpty { return .unclaimed }
        if radioKey == selectedHostKey { return .matchesCurrentIdentity }
        return .belongsToAnotherIdentity
    }
}

struct RadioProvisioningSummary: Equatable, Sendable {
    let capabilityCount: Int
    let hasHostFiltering: Bool
    let supportsOfflineQueue: Bool
    let supportsDelegatedAcknowledgements: Bool
    let supportsDeviceName: Bool
    let supportsLoRa: Bool
    let supportsDutyCycleLimit: Bool
    /// `CAP_BATTERY`: the radio measures and reports its own power state.
    let supportsBattery: Bool
    let phyEnabled: Bool
    let frequencyKHz: UInt32
    let transmitPowerDBm: Int8
    let bandwidthHz: UInt32?
    let spreadingFactor: UInt8?
    let codingRateDenominator: UInt8?
    let dutyCycleNow: UInt16?
    let dutyCycleLimit: UInt16?
    let saved: SavedSnapshotRecord?
    let queuedFrames: Int?
    let droppedFrames: UInt32?
    let filterCount: Int?
    var hostChannelCount: Int?
    let hostPeerCount: Int?
    let autoAcknowledgementEnabled: Bool?
    /// Whether the radio has a device identity domain of its own
    /// (`CAP_DEV_IDENTITY`), including a peer list.
    var supportsDeviceIdentity: Bool = false
    /// Canonical addresses of the peers stored on the radio's device
    /// identity, read back losslessly. Present exactly when
    /// `supportsDeviceIdentity`; the device is the authority.
    var devPeerAddresses: [String]? = nil
    /// Two-octet identifiers of the channels the radio's device identity has
    /// joined. Present exactly when `supportsDeviceIdentity`. Key material is
    /// never read back, so naming these means deriving identifiers from keys
    /// the phone holds; one that matches nothing is a channel the radio knows
    /// and this phone does not.
    var devChannelIDs: [Data]? = nil
    /// Whether the radio keeps key tables on the phone identity's behalf
    /// (`CAP_HOST_KEYS`), which is what host channel reconciliation needs.
    var supportsHostKeys: Bool = false
    /// `CAP_TIME`: the radio keeps a wall clock. Says nothing about
    /// whether it currently knows what time it is.
    var supportsTime: Bool = false
    /// `CAP_GNSS`: a receiver is fitted, so the radio can locate itself.
    var supportsGnss: Bool = false
    /// `PROP_TZ_OFFSET` in minutes east of UTC. Present exactly when
    /// `supportsTime` and the radio reported it.
    var timeZoneOffsetMinutes: Int16? = nil
    /// The positioning policy. Present exactly when `supportsGnss` and
    /// the radio reported the whole of it.
    var gnss: UlcpGnssSettingsRecord? = nil
}

/// The UTC offsets a device can be given, at the quarter-hour steps the
/// world's zones actually use.
///
/// An offset rather than a zone: the device has no zone database, so what
/// travels is the offset in effect when it is set. It does not follow
/// daylight saving on its own.
let deviceTimeZoneOffsets: [Int16] = stride(from: Int16(-12 * 60), through: 14 * 60, by: 15).map { $0 }

/// An offset in minutes east of UTC as "UTC−07:00".
func formattedUTCOffset(_ minutes: Int16) -> String {
    let sign = minutes < 0 ? "−" : "+"
    let magnitude = abs(Int(minutes))
    return String(format: "UTC%@%02d:%02d", sign, magnitude / 60, magnitude % 60)
}

/// This iPhone's current offset from UTC, in minutes east — the offset in
/// effect right now, daylight saving included.
var phoneUTCOffsetMinutes: Int16 {
    Int16(TimeZone.current.secondsFromGMT() / 60)
}

extension UlcpFixKind {
    var symbolName: String {
        switch self {
        case .none: "location.slash"
        case .twoD, .threeD: "location.fill"
        }
    }
}

/// Capacity of a radio's device-identity peer list, for labels only —
/// the device's own `NOMEM` stays authoritative.
let devicePeerCapacity = Int(ulcpMaxDevPeers())

/// Capacity of a radio's device-identity channel list, for labels only.
let deviceChannelCapacity = Int(ulcpMaxDevChannels())

extension SavedSnapshotRecord {
    /// One-line answer to "is this radio armed for restart?".
    var summary: String {
        switch self {
        case .none: "No"
        case .current: "Yes"
        case .fallback: "Yes, out of date"
        case .unreadable: "No — save failed to load"
        }
    }

    /// What the operator has to do about it, when there is something.
    /// A radio in either failure state works normally and looks normal;
    /// this text is the only place it surfaces.
    var warning: String? {
        switch self {
        case .none, .current: nil
        case .fallback:
            "The radio recovered older settings after its last save could not be read. Save again to store the current configuration."
        case .unreadable:
            "The radio's saved settings could not be read and it started with factory defaults. Save again to restore autonomous operation."
        }
    }
}

struct RadioSettings: Equatable, Sendable {
    let deviceName: String?
    let phyEnabled: Bool
    let frequencyKHz: UInt32
    let transmitPowerDBm: Int8
    let bandwidthHz: UInt32?
    let spreadingFactor: UInt8?
    let codingRateDenominator: UInt8?
    let dutyCycleLimit: UInt16?
}
