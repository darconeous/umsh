import SwiftUI
import UMSHMobileCore

/// The device's Wi-Fi: whether its station is on, what it is connected to,
/// which networks it knows, and what it can hear right now.
///
/// Two screens in one, which is deliberate. A device that can only look
/// (`CAP_WIFI_SCAN`) has no station to enable and no network to join, so
/// it gets the scan and a line saying that is all it does. A device with a
/// station gets everything, and the difference is read off which
/// properties the device answered rather than off a flag, so a device that
/// grows a station grows the screen.
struct RemoteWifiScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()
    @State private var joining: WifiJoinTarget?
    @State private var forgetting: Data?

    private var reading: RemoteCategoryReading? { model.readings[.wifi] }
    private var problems: [UInt32: String] { model.writeRefusals[.wifi] ?? [:] }

    /// Whether this device can join a network at all, as opposed to only
    /// seeing which ones are there.
    private var hasStation: Bool { model.supportsWifiStation }

    /// The networks the device has been told about, as it reports them.
    /// Never a credential: the reported form does not carry one.
    private var knownNetworks: [UlcpWifiNetworkRecord] {
        reading?.properties.wifiNetworks ?? []
    }

    /// Which of them the device is set to use, if any. An empty value is a
    /// value: it means the operator deselected everything.
    private var selectedSSID: Data? {
        guard let selected = edits.network.value, !selected.isEmpty else { return nil }
        return selected
    }

    var body: some View {
        Form {
            if hasStation {
                stationSection
                connectionSection
                networksSection
            } else {
                scanOnlySection
            }
            scanSection
            RemoteProblemSection(model: model)
        }
        .sheet(item: $joining) { target in
            WifiJoinSheet(model: model, target: target)
        }
        .confirmationDialog(
            "Forget this network?",
            isPresented: Binding(
                get: { forgetting != nil },
                set: { if !$0 { forgetting = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Forget", role: .destructive) {
                guard let ssid = forgetting else { return }
                forgetting = nil
                Task { await model.forgetNetwork(ssid: ssid) }
            }
            Button("Cancel", role: .cancel) { forgetting = nil }
        } message: {
            Text(
                forgetting == selectedSSID
                    ? "The device is using this network, so forgetting it disconnects the device. Its passphrase is forgotten with it."
                    : "The device forgets this network and its passphrase."
            )
        }
        .remoteCategoryChrome(
            model: model,
            category: .wifi,
            title: "Wi-Fi",
            apply: hasStation ? { await apply() } : nil,
            hasEdits: !edits.dirty.isEmpty,
            applyWarning: applyWarning
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    // MARK: - Station

    private var stationSection: some View {
        Section {
            if edits.enabled.isKnown {
                Toggle(isOn: $edits.enabled.edited.replacingNil(with: false)) {
                    RemoteFieldTitle(
                        "Wi-Fi enabled",
                        problem: problems[edits.enabled.property]
                    )
                }
            } else {
                RemoteReadOnlyToggle("Wi-Fi enabled", isOn: nil)
            }
        } footer: {
            Text(
                "With Wi-Fi off the device keeps the networks it knows and joins none of them. Some devices cannot use Wi-Fi and the mesh radio at the same time."
            )
        }
    }

    // MARK: - Connection

    @ViewBuilder
    private var connectionSection: some View {
        Section {
            LabeledContent("Status", value: connectionSummary)
            if let link = reading?.properties.wifiLink, let bssid = link.bssid {
                LabeledContent("Access point", value: macAddressText(bssid))
            }
            if let link = reading?.properties.wifiLink,
               let frequency = link.frequencyMhz
            {
                LabeledContent("Channel", value: wifiChannelText(frequency))
            }
            if let rssi = reading?.properties.wifiRssiDbm {
                LabeledContent("Signal", value: "\(rssi) dBm")
            }
            if let mac = reading?.properties.wifiMac, !mac.isEmpty {
                LabeledContent("Wi-Fi address", value: macAddressText(mac))
            }
        } header: {
            Text("Connection")
        } footer: {
            RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
        }
    }

    /// What the station is doing, in one line.
    ///
    /// The reason is worth showing only while the device is trying: a
    /// station that is up has no reason, and one that is down carries the
    /// reason it last stopped, which is the useful half of the pair.
    private var connectionSummary: String {
        guard let link = reading?.properties.wifiLink else { return "Not read" }
        let state = switch link.state {
        case 0: "Not connected"
        case 1: "Connecting"
        case 2: "Connected"
        default: "Unknown"
        }
        guard let reason = wifiReasonText(link.reason) else { return state }
        return "\(state) — \(reason)"
    }

    // MARK: - Known networks

    @ViewBuilder
    private var networksSection: some View {
        Section {
            if reading?.answered(ulcpProperties.wifiNetworks) != true {
                LabeledContent("Networks", value: "Not read")
            } else if knownNetworks.isEmpty {
                Text("No networks stored.").foregroundStyle(.secondary)
            } else {
                ForEach(knownNetworks, id: \.ssid) { network in
                    knownNetworkRow(network)
                }
            }
            Button("Add Hidden Network…") {
                joining = WifiJoinTarget(ssid: Data(), hidden: true, offered: nil)
            }
        } header: {
            RemoteFieldTitle("Networks", problem: problems[edits.network.property])
        } footer: {
            Text(
                "The device joins the network with a check beside it. Tap another to switch, or tap the checked one to disconnect. Swipe a network to forget it."
            )
        }
    }

    private func knownNetworkRow(_ network: UlcpWifiNetworkRecord) -> some View {
        Button {
            // Tapping the selected entry deselects it, which is how a
            // device is told to stay off a network it still knows.
            edits.network.edited = network.ssid == selectedSSID ? Data() : network.ssid
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    WifiNameLabel(ssid: network.ssid)
                    HStack(spacing: 6) {
                        Text(wifiSecurityName(network.security))
                        if network.hidden { Text("Hidden") }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
                if network.ssid == selectedSSID {
                    Image(systemName: "checkmark").foregroundStyle(.tint)
                }
            }
        }
        .tint(.primary)
        .swipeActions {
            Button("Forget", role: .destructive) { forgetting = network.ssid }
        }
    }

    // MARK: - Scanning

    private var scanOnlySection: some View {
        Section {
            Text(
                "This device can see the networks around it. It cannot join one."
            )
            .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var scanSection: some View {
        Section {
            if reading?.properties.wifiScanning == true {
                HStack {
                    ProgressView()
                    Text("Looking for networks…").foregroundStyle(.secondary)
                }
            } else {
                Button("Scan for Networks") {
                    Task { await model.scanForNetworks() }
                }
                .disabled(model.isBusy)
            }
            ForEach(heardNetworks) { heard in
                scanResultRow(heard)
            }
        } header: {
            Text("Nearby")
        } footer: {
            if model.scanResults.isEmpty, reading?.properties.wifiScanning != true {
                Text("A scan lists what the device can hear from where it is, which is not what this phone can hear.")
            }
        }
    }

    /// What the scan heard, one row per name, strongest first.
    ///
    /// Grouped by SSID because a network on three access points is one
    /// network to an operator, and the strongest of the three is the one
    /// the device would join. Nameless results are not grouped: each
    /// hidden access point stands alone, since nothing says two of them
    /// are the same network.
    private var heardNetworks: [HeardNetwork] {
        var byName: [Data: UlcpWifiScanResultRecord] = [:]
        var nameless: [UlcpWifiScanResultRecord] = []
        for result in model.heardNetworks {
            if result.ssid.isEmpty {
                nameless.append(result)
            } else if let seen = byName[result.ssid], seen.rssiDbm >= result.rssiDbm {
                continue
            } else {
                byName[result.ssid] = result
            }
        }
        let known = Set(knownNetworks.map(\.ssid))
        return (byName.values + nameless)
            .sorted { $0.rssiDbm > $1.rssiDbm }
            .map { HeardNetwork(result: $0, isKnown: known.contains($0.ssid)) }
    }

    @ViewBuilder
    private func scanResultRow(_ heard: HeardNetwork) -> some View {
        let row = HStack {
            VStack(alignment: .leading, spacing: 2) {
                WifiNameLabel(ssid: heard.result.ssid)
                HStack(spacing: 6) {
                    Text(wifiOfferedSecurityName(heard.result.modes))
                    Text(wifiChannelText(heard.result.frequencyMhz))
                    if heard.isKnown { Text("In your networks") }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Text("\(heard.result.rssiDbm) dBm")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        if hasStation {
            Button {
                joining = WifiJoinTarget(
                    ssid: heard.result.ssid,
                    hidden: heard.result.ssid.isEmpty,
                    offered: heard.result.modes
                )
            } label: { row }
            .tint(.primary)
        } else {
            row
        }
    }

    /// One line of the nearby list: an access point and whether the device
    /// already knows the network it belongs to.
    private struct HeardNetwork: Identifiable {
        let result: UlcpWifiScanResultRecord
        let isKnown: Bool
        var id: Data { result.bssid }
    }

    // MARK: - Applying

    /// Turning the station off can take a link with it, exactly as the
    /// Bluetooth screen's toggle can — an operator three hops away may be
    /// turning off the connection a bridge is riding on, and nothing on
    /// this phone can tell whether the device has another way home.
    private var applyWarning: (title: String, message: String)? {
        guard edits.disablesWifi else { return nil }
        return (
            title: "Turn Wi-Fi Off",
            message: """
                The device disconnects from its network. If anything it \
                carries depends on that connection, it stops until Wi-Fi is \
                turned back on.
                """
        )
    }

    private func apply() async {
        if await model.apply(.wifi, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.wifi])
        }
    }

    /// The two settings on this screen that Apply writes.
    ///
    /// Scanning is not one: it is a button, not a field. Neither is the
    /// network table, which is edited an item at a time because a
    /// credential can only be sent and never read back.
    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var network = RemoteField<Data>(0, nil)
        var isEmpty = true
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            enabled = RemoteField(id.wifiEnabled, held.wifiEnabled)
            network = RemoteField(id.wifiNetwork, held.wifiNetwork)
            isEmpty = reading == nil
        }

        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            enabled = enabled.preserving(old.enabled)
            network = network.preserving(old.network)
        }

        /// Whether Apply would switch the station off. Only an edit counts:
        /// a device already off is not being turned off.
        var disablesWifi: Bool { enabled.isDirty && enabled.value == false }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if enabled.isDirty { dirty.insert(enabled.property) }
            if network.isDirty { dirty.insert(network.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            var desired = held
            desired.wifiEnabled = enabled.value
            desired.wifiNetwork = network.value
            return desired
        }
    }
}

// MARK: - Joining

/// The network a join sheet is about: one heard in a scan, or a hidden one
/// the operator is naming themselves.
struct WifiJoinTarget: Identifiable {
    var ssid: Data
    var hidden: Bool
    /// The security modes the access point advertised, bit *n* for mode
    /// *n*. Nil for a hidden network nothing was heard from, and zero
    /// where a device reported that it could not tell.
    var offered: UInt16?

    var id: String {
        ssid.map { String(format: "%02x", $0) }.joined() + (hidden ? "-h" : "")
    }
}

/// Give the device a network and its passphrase.
///
/// The one place in the app where a credential exists. It is typed here,
/// folded into the entry the device is sent, and dropped when the sheet
/// closes: nothing keeps it, nothing logs it, and the device never sends
/// one back.
struct WifiJoinSheet: View {
    let model: ManageDeviceModel
    let target: WifiJoinTarget

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var security: UInt8 = 2
    @State private var credential = ""
    @State private var problem: String?
    @State private var isWorking = false

    /// Modes this app can build a credential for, weakest last, which is
    /// also the order a step-down walks.
    private static let buildable: [UInt8] = [3, 2, 4, 1, 0]

    /// The modes to offer, in the order an operator reads them.
    ///
    /// An access point that advertised its modes narrows the list to what
    /// it actually offers, so a passphrase is never typed for a mode the
    /// network does not run. A device that could not tell, and a hidden
    /// network nobody heard, offer everything.
    private var choices: [UInt8] {
        guard let offered = target.offered, offered != 0 else { return Self.buildable }
        let matching = Self.buildable.filter { offered & (1 << UInt16($0)) != 0 }
        return matching.isEmpty ? Self.buildable : matching
    }

    /// Modes the access point offers that this app cannot join, listed so
    /// an operator is told why their enterprise network is not there
    /// rather than left looking for it.
    private var unsupported: [UInt8] {
        guard let offered = target.offered, offered != 0 else { return [] }
        return [5, 6, 7, 8].filter { offered & (1 << UInt16($0)) != 0 }
    }

    /// The SSID this sheet will send: what was typed for a hidden network,
    /// and the heard name otherwise.
    private var ssid: Data {
        target.ssid.isEmpty ? Data(name.utf8) : target.ssid
    }

    /// Whether the chosen mode wants a passphrase at all.
    private var needsCredential: Bool { security == 2 || security == 3 || security == 4 }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if target.ssid.isEmpty {
                        TextField("Network name", text: $name)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    } else {
                        LabeledContent("Network") { WifiNameLabel(ssid: target.ssid) }
                    }
                    Picker("Security", selection: $security) {
                        ForEach(choices, id: \.self) { mode in
                            Text(wifiSecurityName(mode)).tag(mode)
                        }
                    }
                    if needsCredential {
                        SecureField("Password", text: $credential)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(.red)
                    } else if !unsupported.isEmpty {
                        Text(
                            "This network also offers \(unsupported.map(wifiSecurityName).formatted(.list(type: .and))), which this app cannot set up."
                        )
                    } else if needsCredential {
                        Text("The password is sent to the device and kept there. It is never sent back, so this app cannot show you one you have already stored.")
                    }
                }
            }
            .navigationTitle(target.ssid.isEmpty ? "Add Network" : "Join Network")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isWorking {
                        ProgressView()
                    } else {
                        Button("Join") { Task { await submit() } }
                            .disabled(!isSubmittable)
                    }
                }
            }
            .onAppear {
                if let first = choices.first { security = first }
            }
        }
    }

    /// Whether what has been typed could be a network at all.
    ///
    /// The length rules live in the shared encoder rather than here, so
    /// what this sheet refuses and what the device would refuse are the
    /// same rules read from the same place. This only asks whether there
    /// is enough to try.
    private var isSubmittable: Bool {
        guard !ssid.isEmpty, ssid.count <= 32 else { return false }
        return (try? item()) != nil
    }

    private func item() throws -> Data {
        try ulcpWifiNetworkItem(
            ssid: ssid,
            security: security,
            hidden: target.hidden,
            credential: Data(credential.utf8)
        )
    }

    /// Send the network, then select it.
    ///
    /// A device that says it does not implement the chosen mode is not a
    /// failure to report: it is a network offering more than the device
    /// can do, and the next weaker mode the access point advertised is
    /// what an operator would try next. Offering it here keeps them in the
    /// sheet with what they typed, and keeps the choice theirs rather than
    /// silently joining on weaker security than they asked for.
    private func submit() async {
        problem = nil
        let encoded: Data
        do {
            encoded = try item()
        } catch {
            problem = "That is not a password this network's security can use."
            return
        }
        isWorking = true
        defer { isWorking = false }
        if let status = await model.joinNetwork(item: encoded) {
            problem = joinRefusalText(status)
            if ulcpStatusName(status: status).hasSuffix("UNIMPLEMENTED"),
               let weaker = nextWeakerChoice()
            {
                security = weaker
                problem = """
                    The device cannot use \(wifiSecurityName(security)). \
                    Try \(wifiSecurityName(weaker)), which this network also offers.
                    """
            }
            return
        }
        guard model.problem == nil else { return }
        await model.selectNetwork(ssid: ssid)
        dismiss()
    }

    private func nextWeakerChoice() -> UInt8? {
        guard let position = choices.firstIndex(of: security) else { return nil }
        return choices.indices.contains(position + 1) ? choices[position + 1] : nil
    }

    private func joinRefusalText(_ status: UInt32) -> String {
        let name = ulcpStatusName(status: status)
        if name.hasSuffix("NOMEM") {
            return "The device has no room for another network. Forget one first."
        }
        if name.hasSuffix("INVALID_ARGUMENT") {
            return "The device would not take that password for this kind of network."
        }
        if name.hasSuffix("UNIMPLEMENTED") {
            return "The device cannot use \(wifiSecurityName(security))."
        }
        return "The device refused this network: \(name)."
    }
}

// MARK: - Showing what a network is

/// An SSID, shown so it cannot be mistaken for something it is not.
///
/// An SSID is zero to thirty-two arbitrary octets and carries no
/// declared encoding, so a name is shown as text only where the octets
/// really are text. Anything else is shown as hex in a monospace font,
/// and neither form is ever used to build a string that reaches anything
/// but a label.
struct WifiNameLabel: View {
    let ssid: Data

    var body: some View {
        if ssid.isEmpty {
            Text("Hidden network").foregroundStyle(.secondary)
        } else if let text = Self.readableText(ssid) {
            Text(text)
        } else {
            Text(ssid.map { String(format: "%02x", $0) }.joined())
                .font(.system(.body, design: .monospaced))
        }
    }

    /// The SSID as text, where every octet of it really is text.
    ///
    /// Control characters disqualify it along with invalid UTF-8: a name
    /// carrying a line break or a direction override renders as something
    /// other than what it says, which is the whole reason this check is
    /// here.
    static func readableText(_ ssid: Data) -> String? {
        guard let text = String(data: ssid, encoding: .utf8), !text.isEmpty else { return nil }
        let unsafe = CharacterSet.controlCharacters.union(.illegalCharacters)
        return text.unicodeScalars.contains(where: unsafe.contains) ? nil : text
    }
}

/// What one `WIFI_SEC_*` code is called.
func wifiSecurityName(_ code: UInt8) -> String {
    switch code {
    case 0: "Open"
    case 1: "Enhanced Open"
    case 2: "WPA2"
    case 3: "WPA3"
    case 4: "WPA"
    case 5: "WEP"
    case 6: "WPA2 Enterprise"
    case 7: "WPA3 Enterprise"
    case 8: "WPA3 Enterprise 192-bit"
    default: "Mode \(code)"
    }
}

/// What a scan result's set of offered modes is called, in one phrase.
///
/// The strongest mode on offer names the network, because that is the one
/// the device would use. A device that could not tell says so rather than
/// claiming the network is open, which is what an empty set would read as.
func wifiOfferedSecurityName(_ modes: UInt16) -> String {
    guard modes != 0 else { return "Security unknown" }
    // Strongest first, by the same order the join sheet walks.
    for mode in [8, 7, 6, 3, 2, 4, 1, 5] where modes & (1 << UInt16(mode)) != 0 {
        return wifiSecurityName(UInt8(mode))
    }
    return "Security unknown"
}

/// Why the station is where it is, or nil where there is nothing to say.
func wifiReasonText(_ code: UInt8) -> String? {
    switch code {
    case 1: "network not found"
    case 2: "wrong password"
    case 3: "rejected by the access point"
    case 4: "connection lost"
    case 5: "the device did not say why"
    default: nil
    }
}

/// A frequency written the way a router's own settings page writes it.
///
/// The channel comes first because that is the number an operator will
/// have seen elsewhere; the megahertz follow because a channel number
/// alone is ambiguous across bands and the frequency is the fact.
func wifiChannelText(_ frequencyMHz: UInt16) -> String {
    guard let channel = wifiChannel(at: frequencyMHz) else { return "\(frequencyMHz) MHz" }
    return "Channel \(channel) (\(frequencyMHz) MHz)"
}

/// The channel number a center frequency belongs to, per band, or nil for
/// a frequency that is not on a channel this arithmetic covers.
func wifiChannel(at frequencyMHz: UInt16) -> Int? {
    let mhz = Int(frequencyMHz)
    switch mhz {
    case 2484:
        return 14
    case 2412...2472 where (mhz - 2412) % 5 == 0:
        return (mhz - 2412) / 5 + 1
    case 5160...5885 where (mhz - 5000) % 5 == 0:
        return (mhz - 5000) / 5
    case 5955...7115 where (mhz - 5955) % 5 == 0:
        return (mhz - 5955) / 5 + 1
    default:
        return nil
    }
}

/// Six octets as the colon-separated hex a network stack would print.
func macAddressText(_ octets: Data) -> String {
    octets.map { String(format: "%02x", $0) }.joined(separator: ":")
}
