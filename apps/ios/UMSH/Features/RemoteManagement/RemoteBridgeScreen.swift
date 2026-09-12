import SwiftUI
import UMSHMobileCore

/// The device's own tunnel, using the same management flow on local and mesh links.
struct RemoteBridgeScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()
    @State private var validation: String?

    private var reading: RemoteCategoryReading? { model.readings[.bridge] }
    private var problems: [UInt32: String] { model.writeRefusals[.bridge] ?? [:] }

    var body: some View {
        Form {
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
            } footer: {
                Text("Enter the server's UMSH identity to authenticate it. Wi-Fi and IP must be configured separately.")
            }
            Section("Connection") {
                LabeledContent("Status", value: stateText)
                if let reason = reasonText { Text(reason).foregroundStyle(.secondary) }
                LabeledContent("Node", value: reading?.properties.repeaterEnabled.map { $0 ? "Repeater" : "Leaf" } ?? "Not read")
                if reading?.properties.repeaterEnabled == false {
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
            if let validation { Text(validation).foregroundStyle(.red) }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(model: model, category: .bridge, title: "Bridge",
                              apply: { await apply() }, hasEdits: !edits.dirty.isEmpty)
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
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
        if await model.apply(.bridge, desired: desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.bridge])
        }
    }

    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var host = RemoteField<String>(0, nil)
        var port = RemoteField<String>(0, nil)
        var key = RemoteField<String>(0, nil)
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
            isEmpty = reading == nil
        }
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            enabled = enabled.preserving(old.enabled)
            host = host.preserving(old.host)
            port = port.preserving(old.port)
            key = key.preserving(old.key)
        }
        var dirty: Set<UInt32> {
            var ids: Set<UInt32> = []
            if enabled.isDirty { ids.insert(enabled.property) }
            if host.isDirty { ids.insert(host.property) }
            if port.isDirty { ids.insert(port.property) }
            if key.isDirty { ids.insert(key.property) }
            return ids
        }
    }
}
