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
    @State private var draft: MobileWifiDraft?
    @State private var joining: WifiJoinTarget?
    @State private var editing: WifiEditTarget?
    @State private var forgetting: Data?

    private var reading: RemoteCategoryReading? { model.readings[.wifi] }

    /// Whether this device can join a network at all, as opposed to only
    /// seeing which ones are there.
    private var hasStation: Bool { model.supportsWifiStation }

    /// The networks the device has been told about, as it reports them.
    /// Never a credential: the reported form does not carry one.
    private var knownNetworks: [UlcpWifiNetworkRecord] {
        reading?.properties.wifiNetworks ?? []
    }

    /// The network the device is on or joining, if any. Live: it follows
    /// the device rather than an edit, since the device chooses by itself.
    private var currentSSID: Data? {
        guard let current = reading?.properties.wifiNetwork, !current.isEmpty else { return nil }
        return current
    }

    /// Whether the station is on as the device last reported it, which is
    /// what decides whether a network can be joined right now.
    private var stationIsOn: Bool { reading?.properties.wifiEnabled == true }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.wifi] ?? [:], review: review)
        Form {
            if hasStation {
                stationSection(problems)
                connectionSection
                networksSection
            } else {
                scanOnlySection
            }
            scanSection
        }
        .sheet(item: $joining) { target in
            WifiJoinSheet(model: model, target: target)
        }
        .sheet(item: $editing) { target in
            WifiNetworkEditSheet(model: model, network: target.network)
        }
        .confirmationDialog(
            "Forget This Network?",
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
            Text("The device forgets this network and its password.")
        }
        .remoteCategoryChrome(
            model: model,
            category: .wifi,
            title: "Wi-Fi",
            apply: hasStation ? { await model.applyAndRebuild($draft) } : nil,
            review: review,
            applyWarning: review?.warning == .disablesWifi ? disableWarning : nil
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    // MARK: - Station

    private func stationSection(_ problems: RemoteRowProblems) -> some View {
        Section {
            if let draft = Binding($draft) {
                RemoteToggleField(
                    "Wi-Fi enabled",
                    field: draft.enabled,
                    problem: problems[draft.wrappedValue.enabled.propertyId]
                )
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
            if let currentSSID {
                LabeledContent("Network") { WifiNameLabel(ssid: currentSSID) }
            }
            RemoteValueRow("Status", value: connectionSummary)
            if let link = reading?.properties.wifiLink, let bssid = link.bssid {
                RemoteValueRow("Access point", value: macAddressText(bssid))
            }
            if let link = reading?.properties.wifiLink,
               let frequency = link.frequencyMhz
            {
                RemoteValueRow("Channel", value: wifiChannelText(frequency))
            }
            if let rssi = reading?.properties.wifiRssiDbm {
                RemoteValueRow("Signal", value: "\(rssi) dBm")
            }
            if let mac = reading?.properties.wifiMac, !mac.isEmpty {
                RemoteValueRow("Wi-Fi address", value: macAddressText(mac))
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
        return "\(state) · \(reason)"
    }

    // MARK: - Known networks

    @ViewBuilder
    private var networksSection: some View {
        Section {
            if reading?.answered(ulcpProperties.wifiNetworks) != true {
                RemoteNotRead(title: "Networks")
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
            Text("Networks")
        }
    }

    private func knownNetworkRow(_ network: UlcpWifiNetworkRecord) -> some View {
        let isCurrent = network.ssid == currentSSID
        return HStack {
            // Tapping a network joins it now; the device's own choice is
            // what the auto-join switch in the menu governs.
            Button {
                Task { await model.joinKnownNetwork(ssid: network.ssid) }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        WifiNameLabel(ssid: network.ssid)
                        HStack(spacing: 6) {
                            Text("Minimum: \(wifiSecurityName(network.security))")
                            if network.hidden { Text("Hidden") }
                            if !network.autoJoin {
                                Text("Joins only when chosen", comment: "A saved Wi-Fi network the device never joins by itself")
                            }
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if isCurrent {
                        Image(systemName: "checkmark").foregroundStyle(.tint)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(!stationIsOn || isCurrent || model.isBusy)
            Menu {
                Button {
                    editing = WifiEditTarget(network: network)
                } label: {
                    Label {
                        Text("Edit…", comment: "Menu item: change a saved Wi-Fi network.")
                    } icon: {
                        Image(systemName: "pencil")
                    }
                }
                .accessibilityIdentifier("wifi-network-edit")
                Toggle(
                    "Join Automatically",
                    isOn: Binding(
                        get: { network.autoJoin },
                        set: { on in Task { await model.setAutoJoin(network, on) } }
                    )
                )
                if isCurrent {
                    Button("Disconnect") {
                        Task { await model.disconnectNetwork() }
                    }
                }
                Button("Forget", role: .destructive) { forgetting = network.ssid }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .accessibilityLabel(Text("Network options"))
            }
            .buttonStyle(.borderless)
            .disabled(model.isBusy)
            .accessibilityIdentifier("wifi-network-options")
        }
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
                    Task { await model.scanNetworks() }
                }
                .disabled(model.isBusy)
            }
            ForEach(model.heardNetworks, id: \.result.bssid) { heard in
                scanResultRow(heard)
            }
        } header: {
            Text("Nearby")
        } footer: {
            if model.heardNetworks.isEmpty, reading?.properties.wifiScanning != true {
                Text("A scan lists what the device can hear from where it is, which is not what this phone can hear.")
            }
        }
    }

    /// One line of the nearby list: a network, by its strongest access
    /// point, and whether the device already knows it.
    @ViewBuilder
    private func scanResultRow(_ heard: MobileHeardNetworkRecord) -> some View {
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

    // MARK: - Applying

    /// Turning the station off can take a link with it, exactly as the
    /// Bluetooth screen's toggle can—an operator three hops away may be
    /// turning off the connection a bridge is riding on, and nothing on
    /// this phone can tell whether the device has another way home.
    private var disableWarning: (title: String, message: String) {
        (
            title: String(
                localized: "Turn Wi-Fi Off",
                comment: "Confirmation title and button: turn off a managed device's Wi-Fi."
            ),
            message: String(
                localized: """
                    The device disconnects from its network. If anything it \
                    carries depends on that connection, it stops until Wi-Fi is \
                    turned back on.
                    """,
                comment: "Confirmation message before turning off a managed device's Wi-Fi."
            )
        )
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

    /// The modes to offer, in the order an operator reads them, and the
    /// ones the network offers that this app cannot set up, listed so an
    /// operator is told why their enterprise network is not there rather
    /// than left looking for it.
    private var plan: MobileWifiJoinPlanRecord { wifiJoinPlan(offered: target.offered) }

    /// The SSID this sheet will send: what was typed for a hidden network,
    /// and the heard name otherwise.
    private var ssid: Data {
        target.ssid.isEmpty ? Data(name.utf8) : target.ssid
    }

    /// What the core makes of the entry as it stands.
    private var check: MobileWifiEntryCheckRecord {
        wifiEntryCheck(
            ssid: ssid,
            security: security,
            hidden: target.hidden,
            autoJoin: true,
            credential: Data(credential.utf8),
            stored: nil
        )
    }

    var body: some View {
        let plan = self.plan
        let check = self.check
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
                    Picker("Minimum security", selection: $security) {
                        ForEach(Array(plan.choices), id: \.self) { mode in
                            Text(wifiSecurityName(mode)).tag(mode)
                        }
                    }
                    if check.takesCredential {
                        SecureField("Password", text: $credential)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(.red)
                    } else if let entry = check.problem, WifiEntryProblemText.showsWhileTyping(entry) {
                        Text(WifiEntryProblemText.text(for: entry)).foregroundStyle(.red)
                    } else if !plan.unsupported.isEmpty {
                        Text(
                            "This network also offers \(plan.unsupported.map(wifiSecurityName).formatted(.list(type: .and))), which this app cannot set up."
                        )
                    } else if check.takesCredential {
                        Text("The password is sent to the device and kept there. It is never sent back, so this app cannot show you one you have already stored.")
                    }
                }
            }
            .managementStatus(model)
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
                            .disabled(check.problem != nil)
                    }
                }
            }
            .onAppear { security = plan.initial }
        }
    }

    /// Send the network, then select it.
    ///
    /// A device that says it does not implement the chosen mode is not a
    /// failure to report: it is a network offering more than the device
    /// can do, and the next weaker mode the access point advertised is
    /// what an operator would try next. Selecting it here keeps them in the
    /// sheet with what they typed, and keeps the choice theirs rather than
    /// silently joining on weaker security than they asked for.
    private func submit() async {
        problem = nil
        guard check.problem == nil else { return }
        isWorking = true
        defer { isWorking = false }
        let outcome = await model.joinNetwork(
            ssid: ssid,
            security: security,
            hidden: target.hidden,
            credential: Data(credential.utf8),
            offered: target.offered
        )
        switch outcome {
        case .done:
            dismiss()
        case let .refused(refusal):
            problem = WifiRefusalText.join(refusal)
            if case let .securityUnsupported(_, weaker?) = refusal, plan.choices.contains(weaker) {
                security = weaker
            }
        case .cancelled, .skipped, .failed:
            // The status bar says what failed; the sheet keeps what was typed.
            break
        }
    }
}

// MARK: - Editing

/// A saved network an edit sheet is about.
struct WifiEditTarget: Identifiable {
    let network: UlcpWifiNetworkRecord

    var id: String { network.ssid.map { String(format: "%02x", $0) }.joined() }
}

/// Change a network the device already knows: its security, its password,
/// and how it is joined.
///
/// The name is not offered. An entry is keyed by its SSID, so a new name
/// is a different network, which Forget and Add already cover. A password
/// left empty keeps the one the device holds—the device never sends it
/// back, so this sheet has nothing to show in its place—and a change of
/// security needs a new one, since the old password belongs to the old mode.
struct WifiNetworkEditSheet: View {
    let model: ManageDeviceModel
    let network: UlcpWifiNetworkRecord

    @Environment(\.dismiss) private var dismiss
    @State private var security: UInt8
    @State private var hidden: Bool
    @State private var autoJoin: Bool
    @State private var credential = ""
    @State private var refusal: String?
    @State private var isWorking = false

    init(model: ManageDeviceModel, network: UlcpWifiNetworkRecord) {
        self.model = model
        self.network = network
        _security = State(initialValue: network.security)
        _hidden = State(initialValue: network.hidden)
        _autoJoin = State(initialValue: network.autoJoin)
    }

    /// Modes this app can build an entry for, with the stored one kept in
    /// the list even where it cannot, so the picker always shows the truth.
    private var choices: [UInt8] { Array(wifiEditPlan(network: network).choices) }

    /// What the core makes of the edit as it stands: whether the password
    /// the device holds can stay, and whether anything changed at all.
    private var check: MobileWifiEntryCheckRecord {
        wifiEntryCheck(
            ssid: network.ssid,
            security: security,
            hidden: hidden,
            autoJoin: autoJoin,
            credential: Data(credential.utf8),
            stored: network
        )
    }

    var body: some View {
        let check = self.check
        NavigationStack {
            Form {
                Section {
                    LabeledContent {
                        WifiNameLabel(ssid: network.ssid)
                    } label: {
                        Text("Network", comment: "Row label: a Wi-Fi network's name.")
                    }
                    Picker(selection: $security) {
                        ForEach(choices, id: \.self) { mode in
                            Text(verbatim: wifiSecurityName(mode)).tag(mode)
                        }
                    } label: {
                        Text("Minimum security", comment: "Picker label: the weakest Wi-Fi security a device accepts.")
                    }
                    if check.takesCredential {
                        SecureField(
                            text: $credential,
                            prompt: check.keepsCredential
                                ? Text("Unchanged", comment: "Placeholder: an empty Wi-Fi password field keeps the stored one.")
                                : Text("Required", comment: "Placeholder: a Wi-Fi password that must be entered.")
                        ) {
                            Text("Password", comment: "Field label: a Wi-Fi password.")
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("wifi-edit-password")
                    }
                } footer: {
                    if let refusal {
                        Text(verbatim: refusal).foregroundStyle(.red)
                    } else if let entry = check.problem, WifiEntryProblemText.showsWhileTyping(entry) {
                        Text(verbatim: WifiEntryProblemText.text(for: entry)).foregroundStyle(.red)
                    }
                }
                Section {
                    Toggle(isOn: $autoJoin) {
                        Text("Join Automatically", comment: "Switch: the device may pick this Wi-Fi network by itself.")
                    }
                    Toggle(isOn: $hidden) {
                        Text("Hidden Network", comment: "Switch: this Wi-Fi network does not broadcast its name.")
                    }
                }
            }
            .managementStatus(model)
            .navigationTitle(Text("Edit Network", comment: "Title of the sheet that changes a saved Wi-Fi network."))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Text("Cancel", comment: "Leaves editing without saving.")
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isWorking {
                        ProgressView()
                    } else {
                        Button {
                            Task { await submit() }
                        } label: {
                            Text("Save", comment: "Saves an edit.")
                        }
                        .disabled(!check.changed || check.problem != nil)
                        .accessibilityIdentifier("wifi-edit-save")
                    }
                }
            }
        }
    }

    /// Send the edit. An empty credential under the stored mode is the form
    /// the device reads as "keep the password".
    private func submit() async {
        refusal = nil
        guard check.changed, check.problem == nil else { return }
        isWorking = true
        defer { isWorking = false }
        let outcome = await model.updateNetwork(
            ssid: network.ssid,
            security: security,
            hidden: hidden,
            autoJoin: autoJoin,
            credential: Data(credential.utf8)
        )
        switch outcome {
        case .done:
            dismiss()
        case let .refused(refused):
            refusal = WifiRefusalText.update(refused)
        case .cancelled, .skipped, .failed:
            break
        }
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
    guard let strongest = wifiOfferedModes(offered: modes).first else { return "Security unknown" }
    return wifiSecurityName(strongest)
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
