import Network
import SwiftUI
import UMSHMobileCore

/// The device's IP stack: what each family holds, how it was told to get
/// it, and which resolvers it is using.
///
/// One card per family the device offered, and one shared DNS card
/// beneath. A family a device does not implement is never asked for, so
/// its absence here is the device not having it rather than refusing it.
struct RemoteNetworkScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()

    private var reading: RemoteCategoryReading? { model.readings[.network] }
    private var problems: [UInt32: String] { model.writeRefusals[.network] ?? [:] }

    private var hasV4: Bool { reading?.propertyIDs.contains(ulcpProperties.ipv4State) == true }
    private var hasV6: Bool { reading?.propertyIDs.contains(ulcpProperties.ipv6State) == true }

    var body: some View {
        Form {
            if hasV4 {
                v4StatusSection
                v4ConfigurationSection
            }
            if hasV6 {
                v6StatusSection
                v6ConfigurationSection
            }
            dnsSection
            resolverSection
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .network,
            title: "Network",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty,
            applyWarning: applyWarning
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    // MARK: - IPv4

    @ViewBuilder
    private var v4StatusSection: some View {
        Section {
            LabeledContent("Status", value: ipStateText(reading?.properties.ipv4State))
            if let held = reading?.properties.ipv4Address, !held.address.isEmpty {
                LabeledContent("Address", value: "\(ipText(held.address))/\(held.prefix)")
                LabeledContent(
                    "Router",
                    value: held.gateway.allSatisfy { $0 == 0 }
                        ? "None"
                        : ipText(held.gateway)
                )
            }
            if reading?.properties.ipv4State == 4 {
                Text(
                    "Another device on this network is already using that address. Change it below, or switch to Automatic."
                )
                .foregroundStyle(.orange)
            }
        } header: {
            Text("IPv4")
        } footer: {
            RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
        }
    }

    @ViewBuilder
    private var v4ConfigurationSection: some View {
        Section {
            RemotePicker(
                "How to get an address",
                selection: $edits.v4Method.edited,
                problem: problems[edits.v4Config.property]
            ) {
                ForEach(ipMethods, id: \.code) { method in
                    Text(method.name).tag(UInt8?.some(method.code))
                }
            }
            if edits.v4Method.value == 2 {
                RemoteTextField(
                    "Address",
                    text: $edits.v4Address,
                    isKnown: edits.v4Method.isKnown
                )
                RemoteNumberField(
                    "Prefix length",
                    unit: "bits",
                    text: $edits.v4Prefix,
                    isKnown: edits.v4Method.isKnown
                )
                RemoteTextField(
                    "Router",
                    text: $edits.v4Gateway,
                    isKnown: edits.v4Method.isKnown
                )
            }
        } footer: {
            if edits.v4Method.value == 2 {
                Text(
                    "Leave the router blank for a network with no way out of it. A static address the network does not own leaves the device unreachable."
                )
            }
        }
    }

    // MARK: - IPv6

    @ViewBuilder
    private var v6StatusSection: some View {
        Section {
            LabeledContent("Status", value: ipStateText(reading?.properties.ipv6State))
            ForEach(Array(v6Items.enumerated()), id: \.offset) { _, item in
                LabeledContent(
                    item.kind == 1 ? "Router" : "Address",
                    value: item.kind == 1
                        ? ipText(item.address)
                        : "\(ipText(item.address))/\(item.prefix)"
                )
            }
        } header: {
            Text("IPv6")
        } footer: {
            if v6Items.isEmpty, reading?.answered(ulcpProperties.ipv6Addresses) == true {
                Text("The device holds no IPv6 addresses.")
            }
        }
    }

    private var v6Items: [UlcpIpv6ItemRecord] {
        reading?.properties.ipv6Addresses ?? []
    }

    @ViewBuilder
    private var v6ConfigurationSection: some View {
        Section {
            RemotePicker(
                "How to get an address",
                selection: $edits.v6Method.edited,
                problem: problems[edits.v6Config.property]
            ) {
                ForEach(ipMethods, id: \.code) { method in
                    Text(method.name).tag(UInt8?.some(method.code))
                }
            }
            if edits.v6Method.value == 2 {
                RemoteTextField(
                    "Address",
                    text: $edits.v6Address,
                    isKnown: edits.v6Method.isKnown
                )
                RemoteNumberField(
                    "Prefix length",
                    unit: "bits",
                    text: $edits.v6Prefix,
                    isKnown: edits.v6Method.isKnown
                )
                RemoteTextField(
                    "Router",
                    text: $edits.v6Gateway,
                    isKnown: edits.v6Method.isKnown
                )
            }
        } footer: {
            if edits.v6Method.value == 2 {
                Text(
                    "A static IPv6 address does not stop the device from also taking one the network advertises. The router may be a link-local address."
                )
            }
        }
    }

    /// Automatic first, because it is what all but a handful of devices
    /// should be on.
    private var ipMethods: [(code: UInt8, name: String)] {
        [(1, "Automatic"), (2, "Static"), (0, "Off")]
    }

    // MARK: - DNS

    @ViewBuilder
    private var dnsSection: some View {
        Section {
            if !edits.dns.isKnown {
                LabeledContent("Resolvers", value: "Not read")
            } else {
                ForEach(Array(edits.dnsText.enumerated()), id: \.offset) { index, _ in
                    HStack {
                        TextField(
                            "Address",
                            text: Binding(
                                get: { edits.dnsText[index] },
                                set: { edits.dnsText[index] = $0 }
                            )
                        )
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                }
                .onDelete { edits.dnsText.remove(atOffsets: $0) }
                Button("Add Resolver") { edits.dnsText.append("") }
            }
        } header: {
            RemoteFieldTitle("DNS", problem: problems[edits.dns.property])
        } footer: {
            Text(
                "Resolvers the device is told to use. Leave the list empty to use only what the network offers."
            )
        }
    }

    @ViewBuilder
    private var resolverSection: some View {
        if let resolvers = reading?.properties.ipResolvers {
            Section {
                if resolvers.isEmpty {
                    Text("None.").foregroundStyle(.secondary)
                } else {
                    ForEach(Array(resolvers.enumerated()), id: \.offset) { _, resolver in
                        Text(ipText(resolver))
                    }
                }
            } header: {
                Text("In Use")
            } footer: {
                Text(
                    "What the device is actually resolving with: the list above plus whatever the network handed it."
                )
            }
        }
    }

    // MARK: - Applying

    /// A wrong static address strands a device as surely as switching its
    /// link off, and over the mesh there is nobody standing next to it to
    /// put it right.
    private var applyWarning: (title: String, message: String)? {
        guard model.link == .mesh, edits.changesStaticAddressing else { return nil }
        return (
            title: "Change Addressing",
            message: """
                If the address you have set is not one this device's network \
                will route, nothing reaches it over that network until \
                someone changes it back from the device itself.
                """
        )
    }

    private func apply() async {
        if await model.apply(.network, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.network])
        }
    }

    // MARK: - Edits

    /// The three writable settings on this screen, held as the text an
    /// operator typed until it parses.
    ///
    /// Addresses are kept as text rather than as parsed octets so that a
    /// half-typed address is a half-typed address rather than an edit. A
    /// field that does not parse contributes nothing, exactly as a
    /// half-typed number does everywhere else here.
    private struct Edits {
        var v4Method = RemoteField<UInt8>(0, nil)
        var v6Method = RemoteField<UInt8>(0, nil)
        var v4Config = RemoteField<UlcpIpConfigRecord>(0, nil)
        var v6Config = RemoteField<UlcpIpConfigRecord>(0, nil)
        var dns = RemoteField<[Data]>(0, nil)
        var v4Address = ""
        var v4Prefix = ""
        var v4Gateway = ""
        var v6Address = ""
        var v6Prefix = ""
        var v6Gateway = ""
        var dnsText: [String] = []
        var isEmpty = true
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            v4Config = RemoteField(id.ipv4Config, held.ipv4Config)
            v6Config = RemoteField(id.ipv6Config, held.ipv6Config)
            v4Method = RemoteField(id.ipv4Config, held.ipv4Config?.method)
            v6Method = RemoteField(id.ipv6Config, held.ipv6Config?.method)
            dns = RemoteField(id.ipDns, held.ipDns)
            if let config = held.ipv4Config {
                v4Address = config.address.isEmpty ? "" : ipText(config.address)
                v4Prefix = config.address.isEmpty ? "" : "\(config.prefix)"
                v4Gateway = config.gateway.isEmpty || config.gateway.allSatisfy { $0 == 0 }
                    ? "" : ipText(config.gateway)
            }
            if let config = held.ipv6Config {
                v6Address = config.address.isEmpty ? "" : ipText(config.address)
                v6Prefix = config.address.isEmpty ? "" : "\(config.prefix)"
                v6Gateway = config.gateway.isEmpty || config.gateway.allSatisfy { $0 == 0 }
                    ? "" : ipText(config.gateway)
            }
            dnsText = (held.ipDns ?? []).map(ipText)
            isEmpty = reading == nil
        }

        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            let fresh = Edits(reading)
            self = fresh
            guard !old.isEmpty else { return }
            v4Method = v4Method.preserving(old.v4Method)
            v6Method = v6Method.preserving(old.v6Method)
            if old.v4Edited(against: fresh) {
                (v4Address, v4Prefix, v4Gateway) = (old.v4Address, old.v4Prefix, old.v4Gateway)
            }
            if old.v6Edited(against: fresh) {
                (v6Address, v6Prefix, v6Gateway) = (old.v6Address, old.v6Prefix, old.v6Gateway)
            }
            if old.dnsText != fresh.dnsText, old.dns.isKnown { dnsText = old.dnsText }
        }

        private func v4Edited(against fresh: Edits) -> Bool {
            (v4Address, v4Prefix, v4Gateway) != (fresh.v4Address, fresh.v4Prefix, fresh.v4Gateway)
        }

        private func v6Edited(against fresh: Edits) -> Bool {
            (v6Address, v6Prefix, v6Gateway) != (fresh.v6Address, fresh.v6Prefix, fresh.v6Gateway)
        }

        /// Whether Apply would move either family onto a static address it
        /// is not already on.
        var changesStaticAddressing: Bool {
            (v4Config.isDirty && desiredV4?.method == 2)
                || (v6Config.isDirty && desiredV6?.method == 2)
        }

        /// The IPv4 configuration as typed, or nil where it does not yet
        /// amount to one.
        var desiredV4: UlcpIpConfigRecord? {
            configuration(
                method: v4Method,
                address: v4Address,
                prefix: v4Prefix,
                gateway: v4Gateway,
                width: 4,
                held: held.ipv4Config
            )
        }

        var desiredV6: UlcpIpConfigRecord? {
            configuration(
                method: v6Method,
                address: v6Address,
                prefix: v6Prefix,
                gateway: v6Gateway,
                width: 16,
                held: held.ipv6Config
            )
        }

        /// One family's configuration, built from what was typed.
        ///
        /// Every field has to parse before any of them counts: a
        /// configuration assembled from a good address and a half-typed
        /// prefix is a configuration nobody asked for. Under Automatic and
        /// Off the address fields are not part of the value at all, which
        /// is what the empty forms in the chapter mean.
        private func configuration(
            method: RemoteField<UInt8>,
            address: String,
            prefix: String,
            gateway: String,
            width: Int,
            held: UlcpIpConfigRecord?
        ) -> UlcpIpConfigRecord? {
            guard let chosen = method.value else { return nil }
            guard chosen == 2 else {
                return UlcpIpConfigRecord(
                    method: chosen,
                    address: Data(),
                    prefix: 0,
                    gateway: Data()
                )
            }
            guard let parsed = ipOctets(address), parsed.count == width,
                  let bits = UInt8(prefix), Int(bits) <= width * 8
            else { return held }
            let router: Data
            if gateway.isEmpty {
                router = Data(repeating: 0, count: width)
            } else if let parsedGateway = ipOctets(gateway), parsedGateway.count == width {
                router = parsedGateway
            } else {
                return held
            }
            return UlcpIpConfigRecord(
                method: chosen,
                address: parsed,
                prefix: bits,
                gateway: router
            )
        }

        /// The resolver list as typed, dropping the blank row an operator
        /// is still filling in.
        var desiredDns: [Data]? {
            guard dns.isKnown else { return nil }
            var resolvers: [Data] = []
            for text in dnsText where !text.isEmpty {
                guard let octets = ipOctets(text) else { return dns.reported }
                resolvers.append(octets)
            }
            return resolvers
        }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if let desired = desiredV4, desired != v4Config.reported {
                dirty.insert(v4Config.property)
            }
            if let desired = desiredV6, desired != v6Config.reported {
                dirty.insert(v6Config.property)
            }
            if let desired = desiredDns, desired != dns.reported {
                dirty.insert(dns.property)
            }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            var desired = held
            desired.ipv4Config = desiredV4 ?? held.ipv4Config
            desired.ipv6Config = desiredV6 ?? held.ipv6Config
            desired.ipDns = desiredDns ?? held.ipDns
            return desired
        }
    }
}

// MARK: - Showing and reading addresses

/// What one `IP_*` family state is called.
func ipStateText(_ code: UInt8?) -> String {
    switch code {
    case 0: "Off"
    case 1: "No link"
    case 2: "Waiting for an address"
    case 3: "Ready"
    case 4: "Address conflict"
    case nil: "Not read"
    default: "Unknown"
    }
}

/// Four or sixteen octets, written the way the system writes them.
///
/// Rendered through the system's own address types rather than by hand so
/// that a compressed IPv6 address reads the way it does everywhere else on
/// the phone.
func ipText(_ octets: Data) -> String {
    if octets.count == 4, let address = IPv4Address(octets) {
        return "\(address)"
    }
    if octets.count == 16, let address = IPv6Address(octets) {
        return "\(address)"
    }
    return octets.map { String(format: "%02x", $0) }.joined()
}

/// An address typed by an operator, as octets, or nil where it is not one
/// yet.
///
/// Parsed with the system's parsers for the same reason: what the phone
/// accepts here and what it accepts anywhere else should be the same set
/// of strings.
func ipOctets(_ text: String) -> Data? {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    if let address = IPv4Address(trimmed) { return address.rawValue }
    if let address = IPv6Address(trimmed) { return address.rawValue }
    return nil
}

/// A typed setting that is text rather than a number, editable only once
/// the device has said what it holds.
struct RemoteTextField: View {
    let title: String
    @Binding var text: String
    let isKnown: Bool
    var problem: String?

    init(
        _ title: String,
        text: Binding<String>,
        isKnown: Bool,
        problem: String? = nil
    ) {
        self.title = title
        _text = text
        self.isKnown = isKnown
        self.problem = problem
    }

    var body: some View {
        if isKnown {
            LabeledContent {
                TextField(title, text: $text)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .multilineTextAlignment(.trailing)
            } label: {
                RemoteFieldTitle(title, problem: problem)
            }
        } else {
            LabeledContent(title, value: "Not read")
        }
    }
}
