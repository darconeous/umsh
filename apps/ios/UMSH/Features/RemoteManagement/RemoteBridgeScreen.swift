import SwiftUI
import UMSHMobileCore

/// The ways a device carries the mesh over IP—a tunnel to a server, and a
/// link to the radios on its own network—using the same management flow on
/// local and mesh links.
struct RemoteBridgeScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()
    @State private var validation: String?

    private var reading: RemoteCategoryReading? { model.readings[.bridge] }
    private var problems: [UInt32: String] { model.writeRefusals[.bridge] ?? [:] }
    private var offered: Set<UInt32> { Set(model.properties(of: .bridge)) }
    private var hasServer: Bool { offered.contains(ulcpProperties.bridgeEnabled) }
    private var hasLocal: Bool { offered.contains(ulcpProperties.lanBearerGroup) }

    var body: some View {
        Form {
            if hasServer { serverSections }
            if hasLocal { localSections }
            if let validation { Text(validation).foregroundStyle(.red) }
        }
        .remoteCategoryChrome(model: model, category: .bridge, title: "Bridge",
                              apply: { await apply() }, hasEdits: !edits.dirty.isEmpty)
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    // MARK: - Local network

    @ViewBuilder
    private var localSections: some View {
        Section {
            if edits.localEnabled.isKnown {
                Toggle(isOn: $edits.localEnabled.edited.replacingNil(with: false)) {
                    RemoteFieldTitle("Local network", problem: problems[ulcpProperties.lanBearerEnabled])
                }
            } else {
                RemoteReadOnlyToggle("Local network", isOn: nil)
            }
            RemoteValueRow("Status", value: lanStateText(reading?.properties.lanBearerState))
        } header: {
            Text("Local Network")
        } footer: {
            Text("Bridges this radio's LoRa channel with UMSH devices on this network.")
        }
        Section {
            RemoteTextField("Group", text: $edits.group.edited.replacingNil(with: ""),
                            isKnown: edits.group.isKnown, problem: problems[ulcpProperties.lanBearerGroup],
                            placeholder: "Default")
            RemoteTextField("Frames per minute", text: $edits.limit.edited.replacingNil(with: ""),
                            isKnown: edits.limit.isKnown, problem: problems[ulcpProperties.lanBearerIngressLimit],
                            placeholder: "Default")
            if !hasServer { RemoteReadingFooter(reading: reading, isBusy: model.isBusy) }
        } header: {
            Text("Local Network Settings")
        }
    }

    // MARK: - Server

    @ViewBuilder
    private var serverSections: some View {
        Section {
            if edits.enabled.isKnown {
                Toggle(isOn: $edits.enabled.edited.replacingNil(with: false)) {
                    RemoteFieldTitle("Bridge enabled", problem: problems[ulcpProperties.bridgeEnabled])
                }
            } else {
                RemoteReadOnlyToggle("Bridge enabled", isOn: nil)
            }
            RemoteTextField("Host", text: $edits.host.edited.replacingNil(with: ""),
                            isKnown: edits.host.isKnown, problem: problems[ulcpProperties.bridgeHost])
            RemoteTextField("Port", text: $edits.port.edited.replacingNil(with: ""),
                            isKnown: edits.port.isKnown, problem: problems[ulcpProperties.bridgePort])
            RemoteTextField("Server identity", text: $edits.key.edited.replacingNil(with: ""),
                            isKnown: edits.key.isKnown, problem: problems[ulcpProperties.bridgeServerKey])
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

    // MARK: - Apply

    private func apply() async {
        validation = nil
        var desired = edits.held
        desired.bridgeEnabled = edits.enabled.value
        desired.bridgeHost = edits.host.value
        if edits.port.isDirty {
            guard let text = edits.port.value, let port = UInt16(text), port > 0 else {
                validation = "Enter a port from 1 to 65535."
                return
            }
            desired.bridgePort = port
        }
        if edits.key.isDirty {
            do { desired.bridgeServerKey = try ulcpBridgeServerKey(input: edits.key.value ?? "") }
            catch { validation = "Enter a valid UMSH server identity, or leave it empty to clear it."; return }
        }
        desired.lanBearerEnabled = edits.localEnabled.value
        // A cleared field hands the setting back to the device's default.
        if edits.group.isDirty {
            guard let group = lanGroupEdit(edits.group.value) else {
                validation = lanGroupInvalid
                return
            }
            desired.lanBearerGroup = group
        }
        if edits.limit.isDirty {
            let text = (edits.limit.value ?? "").trimmingCharacters(in: .whitespaces)
            if text.isEmpty {
                desired.lanBearerIngressLimit = nil
            } else {
                guard let limit = UInt16(text), limit > 0 else {
                    validation = "Enter a limit from 1 to 65535 frames per minute."
                    return
                }
                desired.lanBearerIngressLimit = limit
            }
        }
        if await model.apply(.bridge, desired: desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.bridge])
        }
    }

    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var host = RemoteField<String>(0, nil)
        var port = RemoteField<String>(0, nil)
        var key = RemoteField<String>(0, nil)
        var localEnabled = RemoteField<Bool>(0, nil)
        var group = RemoteField<String>(0, nil)
        var limit = RemoteField<String>(0, nil)
        var held = UlcpDevicePropertiesRecord.empty
        var isEmpty = true

        init() {}
        init(_ reading: RemoteCategoryReading?) {
            held = reading?.properties ?? .empty
            let id = ulcpProperties
            enabled = RemoteField(id.bridgeEnabled, held.bridgeEnabled)
            host = RemoteField(id.bridgeHost, held.bridgeHost)
            port = RemoteField(id.bridgePort, held.bridgePort.map(String.init))
            let address = held.bridgeServerKey.map { bytes in
                bytes.isEmpty ? "" : ((try? inspectPublicIdentityBytes(publicKey: bytes).canonicalAddress) ?? "")
            }
            key = RemoteField(id.bridgeServerKey, address)
            localEnabled = RemoteField(id.lanBearerEnabled, held.lanBearerEnabled)
            group = RemoteField(id.lanBearerGroup, held.lanBearerGroup)
            limit = RemoteField(id.lanBearerIngressLimit, held.lanBearerIngressLimit.map(String.init))
            isEmpty = reading == nil
        }
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            enabled = enabled.preserving(old.enabled)
            host = host.preserving(old.host)
            port = port.preserving(old.port)
            key = key.preserving(old.key)
            localEnabled = localEnabled.preserving(old.localEnabled)
            group = group.preserving(old.group)
            limit = limit.preserving(old.limit)
        }
        var dirty: Set<UInt32> {
            var ids: Set<UInt32> = []
            for field in [enabled, localEnabled] where field.isDirty { ids.insert(field.property) }
            for field in [host, port, key, group, limit] where field.isDirty { ids.insert(field.property) }
            return ids
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

/// A group as typed, ready to write: `.some(nil)` for a cleared field,
/// which hands the setting back to the device's default, and nil for one
/// that does not parse.
func lanGroupEdit(_ text: String?) -> String?? {
    let text = (text ?? "").trimmingCharacters(in: .whitespaces)
    if text.isEmpty { return .some(nil) }
    guard let group = try? ulcpLanGroup(input: text) else { return nil }
    return .some(group)
}

let lanGroupInvalid = "Enter a multicast group or a peer address, with an optional port."
