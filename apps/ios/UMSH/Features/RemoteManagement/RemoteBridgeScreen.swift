import SwiftUI
import UMSHMobileCore

/// The ways a device carries the mesh over IP—a tunnel to a server, and a
/// link to the radios on its own network—using the same management flow on
/// local and mesh links.
struct RemoteBridgeScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileBridgeDraft?

    private var reading: RemoteCategoryReading? { model.readings[.bridge] }
    private var offered: Set<UInt32> { Set(model.properties(of: .bridge)) }
    private var hasServer: Bool { offered.contains(ulcpProperties.bridgeEnabled) }
    private var hasLocal: Bool { offered.contains(ulcpProperties.lanBearerGroup) }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.bridge] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                if hasServer { serverSections(draft, problems: problems) }
                if hasLocal { localSections(draft, problems: problems) }
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(model: model, category: .bridge, title: "Bridge",
                              apply: { await model.applyAndRebuild($draft) },
                              review: review)
        .draft($draft, from: model, revision: reading?.revision)
    }

    // MARK: - Local network

    @ViewBuilder
    private func localSections(
        _ draft: Binding<MobileBridgeDraft>,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        Section {
            RemoteToggleField(
                "Local network",
                field: draft.localEnabled,
                problem: problems[fields.localEnabled.propertyId]
            )
            RemoteValueRow("Status", value: lanStateText(reading?.properties.lanBearerState))
        } header: {
            Text("Local Network")
        } footer: {
            Text("Bridges this radio's LoRa channel with UMSH devices on this network.")
        }
        Section {
            RemoteTextField("Group", field: draft.group,
                            problem: problems[fields.group.propertyId], placeholder: "Default")
            RemoteOptionalIntegerField("Frames per minute", unit: "", field: draft.ingressLimit,
                                       problem: problems[fields.ingressLimit.propertyId],
                                       placeholder: "Default")
            if !hasServer { RemoteReadingFooter(reading: reading, isBusy: model.isBusy) }
        } header: {
            Text("Local Network Settings")
        }
    }

    // MARK: - Server

    @ViewBuilder
    private func serverSections(
        _ draft: Binding<MobileBridgeDraft>,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        Section {
            RemoteToggleField(
                "Bridge enabled",
                field: draft.enabled,
                problem: problems[fields.enabled.propertyId]
            )
            RemoteTextField("Host", field: draft.host, problem: problems[fields.host.propertyId])
            RemoteIntegerField("Port", unit: "", field: draft.port, problem: problems[fields.port.propertyId])
            RemoteTextField("Server identity", field: draft.serverKey,
                            problem: problems[fields.serverKey.propertyId])
        } header: {
            if hasLocal { Text("Internet Server") }
        } footer: {
            Text("Enter the server's UMSH identity to authenticate it. Wi-Fi and IP must be configured separately.")
        }
        Section("Connection") {
            RemoteValueRow("Status", value: stateText)
            if let reason = reasonText { Text(reason).foregroundStyle(.secondary) }
            RemoteValueRow("Node", value: reading?.properties.repeaterMode.map { $0 != 0 ? "Repeater" : "Leaf" } ?? "Not read")
            if reading?.properties.repeaterMode == 0 {
                Text("This device can communicate across the bridge but does not forward traffic for other nodes.")
                    .foregroundStyle(.secondary)
            }
            RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
        }
        Section("Device identity") {
            if let key = reading?.properties.devKey, !key.isEmpty,
               let identity = try? inspectPublicIdentityBytes(publicKey: key) {
                Text(identity.canonicalAddress).font(.footnote.monospaced()).textSelection(.enabled)
                Button("Copy device identity", systemImage: "doc.on.doc") {
                    UIPasteboard.general.string = identity.canonicalAddress
                }
                Text("Authorize this identity on the bridge server.").foregroundStyle(.secondary)
            } else {
                Text("Not read").foregroundStyle(.secondary)
            }
        }
    }

    private var stateText: String {
        switch reading?.properties.bridgeLink?.state {
        case 0: "Disabled"
        case 1: "Unconfigured"
        case 2: "Waiting for network"
        case 3: "Connecting"
        case 4: "Connected"
        case 5: "Retrying"
        default: "Not read"
        }
    }

    private var reasonText: String? {
        switch reading?.properties.bridgeLink?.reason {
        case 1: "The server address could not be resolved or its address family is unavailable."
        case 2: "The connection to the server failed."
        case 3: "The TLS connection failed."
        case 4: "Authentication failed. Check the server identity and the server's authorized devices."
        case 5: "The server stopped responding."
        case 6: "The device identity is unavailable until the device restarts."
        default: nil
        }
    }
}

// MARK: - The multicast group

/// What `PROP_LAN_BEARER_STATE` is called.
func lanStateText(_ code: UInt8?) -> String {
    switch code {
    case 0: "Off"
    case 1: "Connected"
    case 2: "No network"
    default: "Not read"
    }
}
