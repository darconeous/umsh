import SwiftUI
import UMSHMobileCore

/// Presentation for a 2-byte routing-domain region code.
///
/// A code that decodes to letters came from a short code — an airport, a
/// country, a state — and is shown as such; anything else has no
/// recoverable text form and is shown as its raw hex. Both forms carry the
/// hex, because the hex is what the operator will see in a packet capture
/// or on another node.
enum RegionCodeText {
    /// `SJC (0x7853)`, or `0xC0F9` for a derived code.
    static func label(_ code: Data) -> String {
        let hex = self.hex(code)
        guard let description = try? regionCodeDescription(code: code),
              description != hex else { return hex }
        return "\(description) (\(hex))"
    }

    static func hex(_ code: Data) -> String {
        "0x" + code.map { String(format: "%02X", $0) }.joined()
    }

    /// `SJC (0x7853)` for a region as the operator wrote it. The code is
    /// what a capture shows, and a hashed name cannot be read back out of
    /// it, so the string alone would leave the two unconnectable.
    ///
    /// A short code is shown uppercase whatever case it was typed in,
    /// which is how airport and country codes are written everywhere else.
    /// A name is the operator's to capitalize and is shown as written.
    static func label(region: String) -> String {
        guard let code = try? regionCodeFromString(text: region) else { return region }
        let hex = self.hex(code)
        guard region.caseInsensitiveCompare(hex) != .orderedSame else { return hex }
        return "\(isShortCode(region) ? region.uppercased() : region) (\(hex))"
    }

    /// Whether the string is a short code: one to three ASCII letters or
    /// digits, which encode directly rather than hashing
    /// (packet-options.md § Region Code Encoding).
    static func isShortCode(_ region: String) -> Bool {
        (1...3).contains(region.count)
            && region.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
    }

    /// The code a region string derives to, which is what travels on the
    /// air and what the default-region tag is chosen from.
    static func code(of region: String) -> Data? {
        try? regionCodeFromString(text: region)
    }

    /// The form a region's code derives from: ASCII `A`–`Z` folded to
    /// lowercase, every other character left alone. Folding no further
    /// than the derivation does is what keeps this screen's idea of "the
    /// same region" identical to the device's.
    static func folded(_ region: String) -> String {
        String(region.map { $0.isASCII ? Character($0.lowercased()) : $0 })
    }

    /// Where `region` sits in `regions`, comparing as the derivation does:
    /// two spellings that differ only in ASCII case are one region.
    static func index(of region: String, in regions: [String]) -> Int? {
        let target = folded(region)
        return regions.firstIndex { folded($0) == target }
    }
}

/// The repeater forwarding policy for one device.
///
/// Routing regions are not RF settings. A region scopes which floods this
/// device is willing to relay; the frequency and modulation live in the
/// radio section and are a separate question entirely. The wording here
/// keeps that line visible, because conflating them produces a repeater
/// that is silent for reasons nobody can find.
struct RepeaterSettingsSection: View {
    @Binding var enabled: Bool
    @Binding var regions: [String]
    @Binding var defaultRegion: Data?
    @Binding var minRssiDBm: Int16?
    @Binding var minSnrDB: Int8?
    /// Where the device says it is, as it reported at attach.
    var advertisedPosition: UlcpIdentPositionRecord?
    /// What the device's receiver reports, when it has one.
    var devicePosition: RadioPosition?
    /// Whether this form should fill the region list in from where the
    /// phone is, without being asked.
    ///
    /// Only the repeater setup sheet does. A repeater is being commissioned
    /// at the place it will serve, so the regions covering that place are
    /// the answer far more often than an empty list is — and everything the
    /// suggestion did is on screen, undoable, and editable before anything
    /// is written.
    var suggestsFromPhone = false

    @Environment(\.regionService) private var regionService
    @Environment(\.readPhonePosition) private var readPhonePosition

    @State private var regionInput = ""
    @State private var regionProblem: String?
    @State private var showsSuggestion = false
    /// What the automatic suggestion did, and what it displaced. Nil until
    /// one lands, which is also what keeps it to one per form.
    @State private var suggested: AutomaticSuggestion?
    @State private var isSuggesting = false
    /// Accepted in the suggestion sheet, adopted from its onDismiss.
    @State private var pendingSuggestion: MobileRegionOutcomeRecord?

    var body: some View {
        Section {
            Toggle("Forward other nodes' traffic", isOn: $enabled)
        } header: {
            Text("Repeater")
        } footer: {
            Text(enabled
                 ? "This device relays floods it hears, subject to the limits below."
                 : "This device carries only its own traffic and advertises no forwarding role.")
        }
        // Carried on the first section because this view is a run of
        // sections rather than one container: it is always present, and a
        // sheet has to hang off something that is.
        .sheet(isPresented: $showsSuggestion, onDismiss: adoptPendingSuggestion) {
            RegionSuggestionSheet(
                currentRegions: regions,
                currentDefaultRegion: defaultRegion,
                sources: positionSources,
                // Over Bluetooth the phone is within a few meters of the
                // device, so where it is stands for where the device is.
                offersPhone: true,
                accept: { pendingSuggestion = $0 }
            )
        }
        .task(id: suggestsFromPhone) { await suggestFromPhone() }

        if enabled {
            Section {
                ForEach(regions, id: \.self) { region in
                    Text(RegionCodeText.label(region: region))
                        .font(.body.monospaced())
                        // Adding animates the *blank input row* sliding down
                        // to its new slot, not the added row: the typed text
                        // is already sitting exactly where the new row lands,
                        // so fading the row in would flicker text the user
                        // just wrote. Insertion is therefore instant; the
                        // owning Form animates the reflow (DeviceSettingsView
                        // keys an animation on this list).
                        .transition(.asymmetric(insertion: .identity, removal: .opacity))
                }
                .onDelete { offsets in
                    let removed = offsets.compactMap { RegionCodeText.code(of: regions[$0]) }
                    regions.remove(atOffsets: offsets)
                    if let defaultRegion, removed.contains(defaultRegion) {
                        self.defaultRegion = nil
                    }
                }
                HStack {
                    TextField("Short code, name, or 0x1234", text: $regionInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit { addRegion() }
                    Button("Add", action: addRegion)
                        .disabled(regionInput.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if regionService?.isReady == true {
                    Button {
                        showsSuggestion = true
                    } label: {
                        Label("Update based on location", systemImage: "location.magnifyingglass")
                    }
                    .disabled(isSuggesting)
                }
                if let suggested, displaces(suggested) {
                    Button("Undo", role: .destructive) {
                        regions = suggested.displacedRegions
                        defaultRegion = suggested.displacedDefaultRegion
                    }
                }
            } header: {
                Text("Routing regions")
            } footer: {
                if let regionProblem {
                    Text(regionProblem).foregroundStyle(.red)
                } else if let suggested {
                    Text(suggestionNote(suggested))
                } else if isSuggesting {
                    Text("Looking up the regions around this phone…")
                } else if regions.isEmpty {
                    Text("With no regions listed, this device forwards traffic from every region. Add regions to relay only for a named area — a short code such as SJC or WA, a region name your mesh has agreed on, or a raw code. This is a routing domain, not a radio band.")
                } else {
                    Text("Only floods tagged with one of these regions, or carrying no region at all, are relayed. This is a routing domain, not a radio band.")
                }
            }

            Section {
                Picker("Tag untagged traffic", selection: $defaultRegion) {
                    Text("None — don't tag").tag(Data?.none)
                    ForEach(defaultRegionChoices, id: \.self) { region in
                        Text(defaultRegionLabel(region)).tag(Data?.some(region))
                    }
                }
                .disabled(defaultRegionChoices.isEmpty)
            } footer: {
                if let defaultRegion, !regionCodes.contains(defaultRegion) {
                    Text("This device tags untagged traffic with a region it does not relay. Add \(RegionCodeText.label(defaultRegion)) to the list above, or choose a different tag.")
                } else if regions.isEmpty {
                    Text("Add a routing region to be able to tag traffic that arrives without one.")
                } else {
                    Text("Floods that arrive with no region are relayed carrying this one, which scopes how much further they travel. Traffic that already carries a region keeps it.")
                }
            }

            Section {
                Picker("Minimum signal", selection: $minRssiDBm) {
                    Text("Off").tag(Int16?.none)
                    ForEach(rssiChoices, id: \.self) { value in
                        Text("\(value) dBm").tag(Int16?.some(value))
                    }
                }
                Picker("Minimum quality", selection: $minSnrDB) {
                    Text("Off").tag(Int8?.none)
                    ForEach(snrChoices, id: \.self) { value in
                        Text("\(value) dB").tag(Int8?.some(value))
                    }
                }
            } header: {
                Text("Forwarding thresholds")
            } footer: {
                Text("Frames heard below a threshold are not relayed. Raising them keeps a repeater from amplifying signals too weak to be worth repeating; leaving them off relays everything it can decode.")
            }
        }
    }

    // MARK: - Regions from a place

    /// What the automatic suggestion did, kept so it can be said and undone.
    private struct AutomaticSuggestion {
        let datasetVersion: String
        let cellMeters: Double?
        /// The forwarding list and tag the device reported, restored whole
        /// by Undo — the suggestion replaced both, so half of it back would
        /// be a third configuration nobody chose.
        let displacedRegions: [String]
        let displacedDefaultRegion: Data?
    }

    /// The places this device's regions could be proposed from.
    ///
    /// The node's own fix appears only when it disagrees with what the node
    /// advertises; the sheet adds this phone and typed coordinates itself.
    private var positionSources: [RegionPositionSource] {
        let advertised = RegionPositionSource.advertised(
            location: advertisedPosition?.location,
            latitude: advertisedPosition?.latitudeDeg,
            longitude: advertisedPosition?.longitudeDeg
        )
        let fix = RegionPositionSource.gnss(
            latitude: devicePosition?.latitude,
            longitude: devicePosition?.longitude,
            accuracyDecimeters: devicePosition?.accuracyDecimeters,
            outside: advertised
        )
        return [advertised, fix].compactMap { $0 }
    }

    /// Fill the region list in from where this phone is, once.
    ///
    /// The whole suggested list, not the missing part of it: a repeater
    /// being commissioned is being placed, and the regions covering the
    /// place it is being put are the answer. What was displaced is kept so
    /// the footer can offer it back.
    private func suggestFromPhone() async {
        guard suggestsFromPhone, suggested == nil, !isSuggesting else { return }
        guard let regionService, regionService.isReady, let readPhonePosition else { return }
        isSuggesting = true
        defer { isSuggesting = false }
        guard let reading = await readPhonePosition() else { return }
        let position = MobileRegionPositionRecord(
            latitude: reading.coordinate.latitude,
            longitude: reading.coordinate.longitude,
            locationBytes: nil,
            accuracyM: reading.horizontalAccuracy > 0 ? reading.horizontalAccuracy : nil
        )
        guard let proposal = try? await regionService.propose(
            position: position,
            currentRegions: regions,
            currentDefaultRegion: defaultRegion
        ) else { return }
        suggested = AutomaticSuggestion(
            datasetVersion: proposal.lookup.datasetVersion,
            cellMeters: proposal.cellMeters,
            displacedRegions: regions,
            displacedDefaultRegion: defaultRegion
        )
        adopt(proposal.replace)
    }

    private func adopt(_ outcome: MobileRegionOutcomeRecord) {
        regions = outcome.regions
        defaultRegion = outcome.defaultRegion
    }

    /// Adopt what the suggestion sheet accepted, deferred to its dismissal
    /// so the rows arrive in an on-screen list instead of behind the sheet.
    private func adoptPendingSuggestion() {
        guard let outcome = pendingSuggestion else { return }
        pendingSuggestion = nil
        adopt(outcome)
    }

    /// Whether the suggestion is still standing over something else, which
    /// is the only state Undo means anything in.
    private func displaces(_ suggestion: AutomaticSuggestion) -> Bool {
        suggestion.displacedRegions != regions
            || suggestion.displacedDefaultRegion != defaultRegion
    }

    private func suggestionNote(_ suggestion: AutomaticSuggestion) -> String {
        guard !regions.isEmpty else {
            return """
                The region database knows of no regions around this phone, so \
                this device forwards traffic from everywhere.
                """
        }
        var note = """
            Filled in from where this phone is, using region data \
            \(suggestion.datasetVersion). Edit them freely — nothing is sent \
            until you apply.
            """
        if !suggestion.displacedRegions.isEmpty, displaces(suggestion) {
            note += " Undo puts back what the device was already holding."
        }
        return note
    }

    /// The regions offered as a tag.
    ///
    /// A default the device already holds that is not in its forwarding list
    /// stays on this list rather than being hidden. The device does not
    /// cross-check the two, so that state is reachable — and hiding it would
    /// show **None** over a value still on the device, leave no way to clear
    /// it, and write it back unchanged on the next apply.
    /// The codes the listed regions derive to, which is the form the
    /// default-region tag is stored and compared in.
    private var regionCodes: [Data] {
        regions.compactMap(RegionCodeText.code(of:))
    }

    private var defaultRegionChoices: [Data] {
        let codes = regionCodes
        guard let defaultRegion, !codes.contains(defaultRegion) else { return codes }
        return codes + [defaultRegion]
    }

    private func defaultRegionLabel(_ region: Data) -> String {
        regionCodes.contains(region)
            ? RegionCodeText.label(region)
            : "\(RegionCodeText.label(region)) — not relayed"
    }

    private var rssiChoices: [Int16] {
        stride(from: Int16(-130), through: Int16(-60), by: 5).map { $0 }
    }

    private var snrChoices: [Int8] {
        stride(from: Int8(-20), through: Int8(10), by: 2).map { $0 }
    }

    private func addRegion() {
        let text = regionInput.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        // Any string within the length bound is a region — a short code, a
        // name, or a literal code — so the only rejection left is one the
        // device would refuse to store.
        guard RegionCodeText.code(of: text) != nil else {
            regionProblem = "That region name is too long. Use up to 24 characters — a short code like SJC or WA, a region name, or 0x followed by four hex digits."
            return
        }
        regionProblem = nil
        regionInput = ""
        // A region already listed is not added twice. A different
        // capitalization of one is the same region — it derives the same
        // code — so it respells the entry rather than joining it.
        if let index = RegionCodeText.index(of: text, in: regions) {
            regions[index] = text
        } else {
            regions.append(text)
        }
    }
}
