import Network
import SwiftUI
import UMSHMobileCore

/// The device's IP stack: what each family holds, how it was told to get
/// it, and which resolvers it is using. On a device whose medium is the
/// local network's multicast group, the group it joins.
///
/// One card per family the device offered, and one shared DNS card
/// beneath. A family a device does not implement is never asked for, so
/// its absence here is the device not having it rather than refusing it.
struct RemoteNetworkScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileNetworkDraft?

    private var reading: RemoteCategoryReading? { model.readings[.network] }

    private var hasV4: Bool { reading?.propertyIDs.contains(ulcpProperties.ipv4State) == true }
    private var hasV6: Bool { reading?.propertyIDs.contains(ulcpProperties.ipv6State) == true }
    private var hasLocal: Bool {
        model.properties(of: .network).contains(ulcpProperties.lanBearerGroup)
    }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.network] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                if hasLocal { localSection(draft, problems: problems) }
                if hasV4 {
                    v4StatusSection
                    configurationSection(
                        method: draft.v4Method,
                        address: draft.v4Address,
                        prefix: draft.v4Prefix,
                        gateway: draft.v4Gateway,
                        problem: problems[draft.wrappedValue.v4Method.propertyId],
                        footer: "Leave the router blank for a network with no way out of it. A static address the network does not own leaves the device unreachable."
                    )
                }
                if hasV6 {
                    v6StatusSection
                    configurationSection(
                        method: draft.v6Method,
                        address: draft.v6Address,
                        prefix: draft.v6Prefix,
                        gateway: draft.v6Gateway,
                        problem: problems[draft.wrappedValue.v6Method.propertyId],
                        footer: "A static IPv6 address does not stop the device from also taking one the network advertises. The router may be a link-local address."
                    )
                }
                if hasV4 || hasV6 {
                    dnsSection(draft.dns, problem: problems[draft.wrappedValue.dns.propertyId])
                    resolverSection
                }
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(
            model: model,
            category: .network,
            title: "Network",
            apply: { await model.applyAndRebuild($draft) },
            review: review,
            applyWarning: applyWarning(review)
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    // MARK: - Local network

    @ViewBuilder
    private func localSection(
        _ draft: Binding<MobileNetworkDraft>,
        problems: RemoteRowProblems
    ) -> some View {
        Section {
            RemoteValueRow("Status", value: lanStateText(reading?.properties.lanBearerState))
            RemoteTextField(
                "Group",
                field: draft.group,
                problem: problems[draft.wrappedValue.group.propertyId],
                placeholder: "Default"
            )
        } header: {
            Text("Local Network")
        } footer: {
            if !hasV4 {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
        }
    }

    // MARK: - IPv4

    @ViewBuilder
    private var v4StatusSection: some View {
        Section {
            RemoteValueRow("Status", value: ipStateText(reading?.properties.ipv4State))
            if let held = reading?.properties.ipv4Address, !held.address.isEmpty {
                RemoteValueRow("Address", value: "\(ipText(held.address))/\(held.prefix)")
                RemoteValueRow(
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

    /// How one family gets its address, and the address itself when the
    /// operator states it.
    @ViewBuilder
    private func configurationSection(
        method: Binding<MobileChoiceField>,
        address: Binding<MobileTextField>,
        prefix: Binding<MobileOptionalIntegerField>,
        gateway: Binding<MobileTextField>,
        problem: String?,
        footer: LocalizedStringKey
    ) -> some View {
        let isStatic = method.wrappedValue.value == Self.staticMethod
        Section {
            RemoteChoiceField(
                "How to get an address",
                field: method,
                problem: problem
            ) {
                ForEach(ipMethods, id: \.code) { method in
                    Text(method.name).choiceTag(method.code)
                }
            }
            if isStatic {
                RemoteTextField("Address", field: address)
                RemoteOptionalIntegerField("Prefix length", unit: "bits", field: prefix)
                RemoteTextField("Router", field: gateway)
            }
        } footer: {
            if isStatic {
                Text(footer)
            }
        }
    }

    // MARK: - IPv6

    @ViewBuilder
    private var v6StatusSection: some View {
        Section {
            RemoteValueRow("Status", value: ipStateText(reading?.properties.ipv6State))
            ForEach(Array(v6Items.enumerated()), id: \.offset) { _, item in
                RemoteValueRow(
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

    /// The `IPVx_CONFIG` method that states its own address.
    private static let staticMethod: Int64 = 2

    /// Automatic first, because it is what all but a handful of devices
    /// should be on.
    private var ipMethods: [(code: UInt8, name: String)] {
        [(1, "Automatic"), (2, "Static"), (0, "Off")]
    }

    // MARK: - DNS

    @ViewBuilder
    private func dnsSection(_ dns: Binding<MobileTextListField>, problem: String?) -> some View {
        Section {
            if !dns.wrappedValue.known {
                RemoteNotRead(title: "Resolvers")
            } else {
                ForEach(Array(dns.wrappedValue.value.indices), id: \.self) { index in
                    TextField(
                        "Address",
                        text: Binding(
                            get: { dns.wrappedValue.value.indices.contains(index) ? dns.wrappedValue.value[index] : "" },
                            set: { if dns.wrappedValue.value.indices.contains(index) { dns.wrappedValue.value[index] = $0 } }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                }
                .onDelete { dns.wrappedValue.value.remove(atOffsets: $0) }
                Button("Add Resolver") { dns.wrappedValue.value.append("") }
            }
        } header: {
            RemoteFieldTitle("DNS", problem: problem)
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
    private func applyWarning(_ review: MobileDraftReviewRecord?) -> (title: String, message: String)? {
        guard review?.warning == .changesStaticAddressing else { return nil }
        return (
            title: String(
                localized: "Change Addressing",
                comment: "Confirmation title and button: apply a static IP address to a managed device."
            ),
            message: String(
                localized: """
                    If the address you have set is not one this device's network \
                    will route, nothing reaches it over that network until \
                    someone changes it back from the device itself.
                    """,
                comment: "Confirmation message before applying a static IP address to a managed device."
            )
        )
    }
}

// MARK: - Showing addresses

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
