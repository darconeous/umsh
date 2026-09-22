import SwiftUI

/// The bundled routing-region database release, reported without device reads.
struct RegionDatabaseSection: View {
    let version: String?
    let regionCount: UInt32?
    let problem: String?

    var body: some View {
        Section {
            if let version {
                LabeledContent("Data release", value: version)
                if let count = regionCount {
                    LabeledContent("Regions", value: count.formatted())
                }
            } else if let problem {
                Text(problem).foregroundStyle(.secondary)
            } else {
                Text("Opening…").foregroundStyle(.secondary)
            }
        } header: {
            Text("Region database")
        } footer: {
            Text("Used to suggest routing regions for a device from where it is.")
        }
    }
}

struct RadioProvisioningSections: View {
    let provisioning: RadioProvisioningSummary

    var body: some View {
        Section("Radio state") {
            LabeledContent(
                "Protocol tier",
                value: provisioning.hasHostFiltering ? "Full ULCP" : "Transparent baseline"
            )
            LabeledContent("Capabilities", value: "\(provisioning.capabilityCount)")
            LabeledContent("Radio enabled", value: provisioning.phyEnabled ? "Yes" : "No")
            LabeledContent("Frequency", value: "\(provisioning.frequencyKHz) kHz")
            LabeledContent("Transmit power", value: "\(provisioning.transmitPowerDBm) dBm")
            if let bandwidth = provisioning.bandwidthHz {
                LabeledContent("Bandwidth", value: "\(bandwidth / 1_000) kHz")
            }
            if let spreadingFactor = provisioning.spreadingFactor {
                LabeledContent("Spreading factor", value: "SF\(spreadingFactor)")
            }
            if let codingRate = provisioning.codingRateDenominator {
                LabeledContent("Coding rate", value: "4/\(codingRate)")
            }
            if let saved = provisioning.saved {
                LabeledContent("Saved for restart", value: saved.summary)
                if let warning = saved.warning {
                    Text(warning)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if let dutyNow = provisioning.dutyCycleNow {
                LabeledContent("Past-hour duty usage", value: formattedDutyCycle(dutyNow))
            }
            if let dutyLimit = provisioning.dutyCycleLimit {
                LabeledContent(
                    "Duty-cycle limit",
                    value: dutyLimit == UInt16.max ? "Disabled" : formattedDutyCycle(dutyLimit)
                )
            }
        }

        if provisioning.hasHostFiltering {
            Section("Host provisioning") {
                if let filterCount = provisioning.filterCount {
                    LabeledContent("Receive filters", value: "\(filterCount)")
                }
                if let channelCount = provisioning.hostChannelCount {
                    LabeledContent("Channel keys", value: "\(channelCount) identifiers")
                }
                if let peerCount = provisioning.hostPeerCount {
                    LabeledContent("Peer keys", value: "\(peerCount) public keys")
                }
                if let queuedFrames = provisioning.queuedFrames {
                    LabeledContent("Queued frames", value: "\(queuedFrames)")
                }
                if let droppedFrames = provisioning.droppedFrames {
                    LabeledContent("Dropped frames", value: "\(droppedFrames)")
                }
                if let autoAck = provisioning.autoAcknowledgementEnabled {
                    LabeledContent("Delegated acknowledgements", value: autoAck ? "Enabled" : "Disabled")
                }
            }
        }
    }
}
