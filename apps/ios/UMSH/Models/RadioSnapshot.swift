import Foundation

struct RadioSnapshot: Equatable, Sendable {
    var linkState: RadioLinkState
    var name: String?
    var localIdentifier: UUID?
    var batteryPercentage: Int?
    var isExternallyPowered: Bool?
    var batteryReadAt: Date?
    var deviceIdentity: MeshPublicIdentity?
    var hostState: RadioHostState
    var provisioning: RadioProvisioningSummary?
    var problemDescription: String?

    static let idle = Self(
        linkState: .idle,
        name: nil,
        localIdentifier: nil,
        batteryPercentage: nil,
        isExternallyPowered: nil,
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
        isExternallyPowered: nil,
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
        isExternallyPowered: false,
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
            phyEnabled: true,
            frequencyKHz: 915_000,
            transmitPowerDBm: 14,
            bandwidthHz: 125_000,
            spreadingFactor: 9,
            codingRateDenominator: 5,
            dutyCycleNow: 65,
            dutyCycleLimit: 655,
            saved: true,
            queuedFrames: 0,
            droppedFrames: 0,
            filterCount: 2,
            hostChannelCount: 1,
            hostPeerCount: 3,
            autoAcknowledgementEnabled: false
        ),
        problemDescription: nil
    )

    var accessibleSummary: String {
        var parts = [linkState.accessibilityLabel]
        if let name {
            parts.append(name)
        }
        if let batteryPercentage {
            parts.append("Battery \(batteryPercentage) percent")
        } else {
            parts.append("Battery unavailable")
        }
        if isExternallyPowered == true {
            parts.append("External power")
        }
        return parts.joined(separator: ", ")
    }
}

enum RadioLinkState: String, Equatable, Sendable {
    case idle
    case unavailable
    case scanning
    case discovered
    case connecting
    case reconnecting
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
        case .scanning, .connecting, .reconnecting, .pairing, .attaching, .synchronizing, .provisioning, .configuring:
            "antenna.radiowaves.left.and.right.circle"
        case .failed: "exclamationmark.triangle.fill"
        default: "antenna.radiowaves.left.and.right.slash"
        }
    }
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
    let phyEnabled: Bool
    let frequencyKHz: UInt32
    let transmitPowerDBm: Int8
    let bandwidthHz: UInt32?
    let spreadingFactor: UInt8?
    let codingRateDenominator: UInt8?
    let dutyCycleNow: UInt16?
    let dutyCycleLimit: UInt16?
    let saved: Bool?
    let queuedFrames: Int?
    let droppedFrames: UInt32?
    let filterCount: Int?
    let hostChannelCount: Int?
    let hostPeerCount: Int?
    let autoAcknowledgementEnabled: Bool?
}

struct RadioSettings: Equatable, Sendable {
    let deviceName: String?
    let frequencyKHz: UInt32
    let transmitPowerDBm: Int8
    let bandwidthHz: UInt32?
    let spreadingFactor: UInt8?
    let codingRateDenominator: UInt8?
    let dutyCycleLimit: UInt16?
}
