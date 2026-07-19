import SwiftUI

struct SettingsView: View {
    let identity: LocalIdentitySnapshot?
    let identityError: IdentityVaultError?
    let isLoadingIdentity: Bool
    let createIdentity: () async -> Void
    @Binding var radioSnapshot: RadioSnapshot
    let connectRadio: () async -> Void
    let claimRadio: () async -> Void
    let configureRadio: (RadioSettings) async throws -> Void
    let disconnectRadio: () async -> Void

    var body: some View {
        List {
            Section("Identity") {
                if let identity {
                    NavigationLink {
                        IdentityDetailView(identity: identity)
                    } label: {
                        HStack(spacing: 12) {
                            PeerAvatar(hint: identity.publicIdentity.hint)
                            VStack(alignment: .leading) {
                                Text("Your identity")
                                Text(identity.publicIdentity.hint.text)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } else if isLoadingIdentity {
                    HStack {
                        ProgressView()
                        Text("Checking protected identity")
                    }
                } else {
                    Button {
                        Task { await createIdentity() }
                    } label: {
                        Label("Create identity", systemImage: "person.crop.circle.badge.plus")
                    }
                }

                if identityError != nil {
                    Text("Identity is unavailable while protected data is locked or storage cannot be accessed.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Radio") {
                NavigationLink("Companion radio") {
                    RadioDetailView(
                        snapshot: $radioSnapshot,
                        connect: connectRadio,
                        claim: claimRadio,
                        configure: configureRadio,
                        disconnect: disconnectRadio
                    )
                }
            }

            Section("Application") {
                NavigationLink("Notifications") { Text("Notification settings") }
                NavigationLink("Privacy and storage") { Text("Privacy and storage settings") }
                NavigationLink("Diagnostics") { Text("Redacted diagnostics") }
            }
        }
        .navigationTitle("Settings")
    }
}

struct IdentityDetailView: View {
    let identity: LocalIdentitySnapshot

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: identity.publicIdentity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text("Your identity")
                            .font(.title2.bold())
                        Text("Stored on this device")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section("Identity") {
                CanonicalAddressView(address: identity.publicIdentity.canonicalAddress)
            }

            Section("Storage") {
                LabeledContent("Private key", value: "Device-only Keychain")
                Text("Private key bytes are never displayed, copied, synchronized, or included in diagnostics.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Your identity")
    }
}

struct RadioDetailView: View {
    @Binding var snapshot: RadioSnapshot
    let connect: () async -> Void
    let claim: () async -> Void
    let configure: (RadioSettings) async throws -> Void
    let disconnect: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var confirmsHostReplacement = false

    var body: some View {
        List {
            Section("Connection") {
                LabeledContent("State", value: snapshot.linkState.accessibilityLabel)
                if let name = snapshot.name {
                    LabeledContent("Radio", value: name)
                }
                if let identifier = snapshot.localIdentifier {
                    LabeledContent("Bluetooth ID") {
                        Text(identifier.uuidString)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if snapshot.hostState != .unknown {
                    LabeledContent("Host identity", value: snapshot.hostState.label)
                }
                connectionControl
                if snapshot.linkState == .attaching {
                    Text("Bluetooth transport is attached. Waiting to start companion synchronization.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .synchronizing {
                    Text(snapshot.hostState == .unsupported
                         ? "Reading the transparent radio's PHY state. This radio does not provide host filtering or offline assistance."
                         : "The phone identity matches this radio. Reading its authoritative provisioning state before enabling traffic.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .attached {
                    Text("Radio state inspection is complete. Queued traffic has not been drained because message ingestion is not implemented yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .configuring {
                    Text("Applying radio settings, verifying the echoed values, and saving them on the radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.hostState == .localIdentityUnavailable {
                    Text("Create or unlock the phone identity before configuring this radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.hostState == .belongsToAnotherIdentity {
                    Text("This radio belongs to another host. Replacing it clears that host's keys, filters, queued traffic, and saved host provisioning.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Section("Configuration") {
                if let provisioning = snapshot.provisioning, canEditConfiguration {
                    NavigationLink {
                        RadioSettingsEditor(
                            radioName: snapshot.name,
                            provisioning: provisioning,
                            configure: configure
                        )
                    } label: {
                        Label("Edit Device & PHY Settings", systemImage: "slider.horizontal.3")
                    }
                    Text("Device name, frequency, transmit power, bandwidth, spreading factor, and coding rate are shown when supported by this radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Label(configurationUnavailableReason, systemImage: "lock")
                        .foregroundStyle(.secondary)
                }
            }
            Section("Power") {
                LabeledContent(
                    "Battery",
                    value: snapshot.batteryPercentage.map { "\($0)%" } ?? "Unavailable"
                )
                if let isExternallyPowered = snapshot.isExternallyPowered {
                    LabeledContent("External power", value: isExternallyPowered ? "Connected" : "Not connected")
                }
            }
            if let provisioning = snapshot.provisioning {
                Section("Radio state") {
                    LabeledContent(
                        "Protocol tier",
                        value: provisioning.hasHostFiltering ? "Full companion" : "Transparent baseline"
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
                        LabeledContent("Saved for restart", value: saved ? "Yes" : "No")
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
            if let deviceIdentity = snapshot.deviceIdentity {
                Section("Radio identity") {
                    NavigationLink {
                        PeerDetailView(
                            peer: PeerSummary(
                                id: 0,
                                identity: deviceIdentity,
                                alias: nil,
                                advertisedName: snapshot.name,
                                isContact: false,
                                systemRole: "companion_radio",
                                kind: .unknown
                            ),
                            radioSnapshot: $snapshot
                        )
                    } label: {
                        LabeledContent("Peer", value: deviceIdentity.hint.text)
                    }
                    Text("System-managed while this radio is saved")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Radio")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .confirmationDialog(
            "Replace the radio's existing host?",
            isPresented: $confirmsHostReplacement,
            titleVisibility: .visible
        ) {
            Button("Replace Host and Clear Its Data", role: .destructive) {
                Task { await claim() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The previous host's keys, filters, queued traffic, and saved host provisioning will be permanently erased. The radio's own identity and device settings remain unchanged.")
        }
    }

    private var canEditConfiguration: Bool {
        (snapshot.linkState == .attached || snapshot.linkState == .ready)
            && (snapshot.hostState == .matchesCurrentIdentity || snapshot.hostState == .unsupported)
    }

    private var configurationUnavailableReason: String {
        if snapshot.linkState == .configuring {
            return "Radio settings are currently being applied"
        }
        if snapshot.hostState == .unclaimed || snapshot.hostState == .belongsToAnotherIdentity {
            return "Set up this radio for the current phone before editing settings"
        }
        if snapshot.provisioning == nil {
            return "Finish connecting and reading the radio's current settings first"
        }
        return "Connect the companion radio to edit its settings"
    }

    @ViewBuilder
    private var connectionControl: some View {
        switch snapshot.linkState {
        case .scanning, .connecting, .pairing, .provisioning, .configuring, .disconnecting:
            HStack {
                ProgressView()
                Text(snapshot.linkState.accessibilityLabel)
                    .foregroundStyle(.secondary)
            }
        case .attaching, .synchronizing, .awaitingHost, .attached, .ready:
            if snapshot.hostState == .unclaimed {
                Button("Set Up for This Phone") {
                    Task { await claim() }
                }
            } else if snapshot.hostState == .belongsToAnotherIdentity {
                Button("Replace Existing Host…", role: .destructive) {
                    confirmsHostReplacement = true
                }
            }
            Button("Disconnect", role: .destructive) {
                Task { await disconnect() }
            }
        case .idle, .unavailable, .discovered, .failed:
            Button("Find companion radio") {
                Task { await connect() }
            }
        }
    }
}

private struct RadioSettingsEditor: View {
    let provisioning: RadioProvisioningSummary
    let configure: (RadioSettings) async throws -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var deviceName: String
    @State private var frequencyKHz: String
    @State private var transmitPowerDBm: String
    @State private var bandwidthHz: UInt32
    @State private var spreadingFactor: UInt8
    @State private var codingRate: UInt8
    @State private var isSaving = false
    @State private var problem: String?

    init(
        radioName: String?,
        provisioning: RadioProvisioningSummary,
        configure: @escaping (RadioSettings) async throws -> Void
    ) {
        self.provisioning = provisioning
        self.configure = configure
        _deviceName = State(initialValue: radioName ?? "")
        _frequencyKHz = State(initialValue: String(provisioning.frequencyKHz))
        _transmitPowerDBm = State(initialValue: String(provisioning.transmitPowerDBm))
        _bandwidthHz = State(initialValue: provisioning.bandwidthHz ?? 125_000)
        _spreadingFactor = State(initialValue: provisioning.spreadingFactor ?? 9)
        _codingRate = State(initialValue: provisioning.codingRateDenominator ?? 5)
    }

    var body: some View {
        Form {
            if provisioning.supportsDeviceName {
                Section("Device") {
                    TextField("Device name", text: $deviceName)
                    Text("The device name is public and may be visible in Bluetooth discovery.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                TextField("Frequency (kHz)", text: $frequencyKHz)
                    .keyboardType(.numberPad)
                TextField("Transmit power (dBm)", text: $transmitPowerDBm)
                    .keyboardType(.numbersAndPunctuation)
                if provisioning.supportsLoRa {
                    Picker("Bandwidth", selection: $bandwidthHz) {
                        Text("125 kHz").tag(UInt32(125_000))
                        Text("250 kHz").tag(UInt32(250_000))
                        Text("500 kHz").tag(UInt32(500_000))
                    }
                    Picker("Spreading factor", selection: $spreadingFactor) {
                        ForEach(UInt8(5)...UInt8(12), id: \.self) { value in
                            Text("SF\(value)").tag(value)
                        }
                    }
                    Picker("Coding rate", selection: $codingRate) {
                        ForEach(UInt8(5)...UInt8(8), id: \.self) { value in
                            Text("4/\(value)").tag(value)
                        }
                    }
                }
            } header: {
                Text("Radio")
            } footer: {
                Text("Changing PHY settings can make this radio unable to communicate with peers using a different configuration.")
            }

            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Radio settings")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { Task { await save() } }
                    .disabled(settings == nil || isSaving)
            }
        }
    }

    private var settings: RadioSettings? {
        guard let frequency = UInt32(frequencyKHz), frequency > 0,
              let power = Int8(transmitPowerDBm)
        else { return nil }
        let trimmedName = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        if provisioning.supportsDeviceName,
           trimmedName.isEmpty || trimmedName.utf8.count > 64 || trimmedName.contains("\0") {
            return nil
        }
        return RadioSettings(
            deviceName: provisioning.supportsDeviceName ? trimmedName : nil,
            frequencyKHz: frequency,
            transmitPowerDBm: power,
            bandwidthHz: provisioning.supportsLoRa ? bandwidthHz : nil,
            spreadingFactor: provisioning.supportsLoRa ? spreadingFactor : nil,
            codingRateDenominator: provisioning.supportsLoRa ? codingRate : nil
        )
    }

    private func save() async {
        guard let settings else { return }
        isSaving = true
        defer { isSaving = false }
        do {
            try await configure(settings)
            dismiss()
        } catch {
            problem = "The radio rejected these settings. Its previous configuration remains authoritative."
        }
    }
}
