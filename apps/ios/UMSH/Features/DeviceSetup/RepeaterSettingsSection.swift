import SwiftUI
import UMSHMobileCore

/// Presentation for a 2-byte routing-domain region code.
///
/// A code that decodes to letters came from a short code—an airport, a
/// country, a state—and is shown as such; anything else has no
/// recoverable text form and is shown as its raw hex. The hex is never
/// added beside a name: it is what a packet capture shows, not what an
/// operator reads, and a name that reads is the whole point of having one.
enum RegionCodeText {
    /// `SJC` for a code with a readable form, `0xC0F9` for a derived code
    /// that has none.
    static func label(_ code: Data) -> String {
        let hex = self.hex(code)
        guard let description = try? regionCodeDescription(code: code),
              description != hex else { return hex }
        return description
    }

    static func hex(_ code: Data) -> String {
        "0x" + code.map { String(format: "%02X", $0) }.joined()
    }

    /// A region as the operator wrote it, made presentable.
    ///
    /// A short code is shown uppercase whatever case it was typed in,
    /// which is how airport and country codes are written everywhere else.
    /// A name is the operator's to capitalize and is shown as written. A
    /// literal hex code is normalized to the one spelling.
    static func label(region: String) -> String {
        guard let code = try? regionCodeFromString(text: region) else { return region }
        let hex = self.hex(code)
        guard region.caseInsensitiveCompare(hex) != .orderedSame else { return hex }
        return isShortCode(region) ? region.uppercased() : region
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
}

/// The repeater forwarding policy for one device.
///
/// Routing regions are not RF settings. A region scopes which floods this
/// device is willing to relay; the frequency and modulation live in the
/// radio section and are a separate question entirely. The wording here
/// keeps that line visible, because conflating them produces a repeater
/// that is silent for reasons nobody can find.
///
/// The list, the tag and their rules are the core's, the same ones the
/// management screen's repeater editor uses: adding goes through
/// `draftAddRepeaterRegion`, a suggestion through `draftAdoptRegions`, and
/// the tag is chosen from the core's taggable regions.
struct RepeaterSettingsSection: View {
    @Binding var repeater: MobileRepeaterDraft
    /// The default-region picker's rows besides "None".
    let taggableRegions: [String]
    /// The device would tag untagged traffic with a region it does not relay.
    let defaultRegionUnlisted: Bool
    let minRssiChoices: MobileChoiceList?
    let minSnrChoices: MobileChoiceList?
    /// Where the device says it is, as it reported at attach.
    var advertisedPosition: UlcpIdentPositionRecord?
    /// What the device's receiver reports, when it has one.
    var devicePosition: RadioPosition?
    /// Whether this form should fill the region list in from where the
    /// phone is, without being asked.
    ///
    /// Only the repeater setup sheet does. A repeater is being commissioned
    /// at the place it will serve, so the regions covering that place are
    /// the answer far more often than an empty list is—and everything the
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

    private var mode: Int64 { repeater.mode.value ?? 0 }
    private var regions: [String] { repeater.regions.value }

    var body: some View {
        Section {
            Picker("Forward other nodes' traffic", selection: $repeater.mode.value) {
                Text("Off", comment: "Forwarding mode: the device does not forward.")
                    .choiceTag(0)
                Text("Adaptive", comment: "Forwarding mode: the device forwards only what no repeater carried.")
                    .choiceTag(2)
                Text("On", comment: "Forwarding mode: the device is a repeater.")
                    .choiceTag(1)
            }
        } header: {
            Text("Repeater")
        } footer: {
            switch mode {
            case 0: Text("This device carries only its own traffic.")
            case 2: Text("This device forwards only what no repeater carried.")
            default: Text("This device relays floods it hears, subject to the limits below.")
            }
        }
        // Carried on the first section because this view is a run of
        // sections rather than one container: it is always present, and a
        // sheet has to hang off something that is.
        .sheet(isPresented: $showsSuggestion, onDismiss: adoptPendingSuggestion) {
            RegionSuggestionSheet(
                currentRegions: regions,
                currentDefaultRegion: currentDefaultRegion,
                sources: positionSources,
                // Over Bluetooth the phone is within a few meters of the
                // device, so where it is stands for where the device is.
                offersPhone: true,
                accept: { pendingSuggestion = $0 }
            )
        }
        .task(id: suggestsFromPhone) { await suggestFromPhone() }

        if mode != 0 {
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
                .onDelete { repeater.regions.value.remove(atOffsets: $0) }
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
                        repeater.regions.value = suggested.displacedRegions
                        repeater.defaultRegion.text = suggested.displacedDefaultRegion
                    }
                }
            } header: {
                Text("Routing regions")
            } footer: {
                if let regionProblem {
                    Text(regionProblem).foregroundStyle(.red)
                } else if let suggested {
                    suggestionNote(suggested)
                } else if isSuggesting {
                    Text("Looking up the regions around this phone…")
                } else if regions.isEmpty {
                    Text("With no regions listed, this device forwards traffic from every region. Add regions to relay only for a named area—a short code such as SJC or WA, a region name your mesh has agreed on, or a raw code. This is a routing domain, not a radio band.")
                } else {
                    Text("Only floods tagged with one of these regions, or carrying no region at all, are relayed. This is a routing domain, not a radio band.")
                }
            }

            Section {
                Picker("Tag untagged traffic", selection: $repeater.defaultRegion.text) {
                    Text("None—don't tag").tag("")
                    // The device's own tag is offered whether or not it is
                    // still in the list above: deleting a region the device
                    // tags with should not leave the picker with nothing to
                    // show for what the device actually holds.
                    ForEach(taggableRegions, id: \.self) { region in
                        Text(verbatim: defaultRegionLabel(region)).tag(region)
                    }
                }
                .disabled(taggableRegions.isEmpty)
            } footer: {
                if defaultRegionUnlisted {
                    Text("This device tags untagged traffic with a region it does not relay. Add \(RegionCodeText.label(region: repeater.defaultRegion.text)) to the list above, or choose a different tag.")
                } else if regions.isEmpty {
                    Text("Add a routing region to be able to tag traffic that arrives without one.")
                } else {
                    Text("Floods that arrive with no region are relayed carrying this one, which scopes how much further they travel. Traffic that already carries a region keeps it.")
                }
            }

            Section {
                Picker("Minimum signal", selection: $repeater.minRssi.value) {
                    Text("Off").noChoiceTag()
                    ChoiceListRows(list: minRssiChoices) { SignalPresentation.rssiText(Int16(clamping: $0)) }
                }
                Picker("Minimum quality", selection: $repeater.minSnr.value) {
                    Text("Off").noChoiceTag()
                    ChoiceListRows(list: minSnrChoices) { SignalPresentation.decibelsText(Int(clamping: $0)) }
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
        /// by Undo—the suggestion replaced both, so half of it back would
        /// be a third configuration nobody chose.
        let displacedRegions: [String]
        let displacedDefaultRegion: String
    }

    /// The tag the draft holds, as the code a suggestion compares against.
    private var currentDefaultRegion: Data? {
        repeater.defaultRegion.text.isEmpty ? nil : RegionCodeText.code(of: repeater.defaultRegion.text)
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
            currentDefaultRegion: currentDefaultRegion
        ) else { return }
        suggested = AutomaticSuggestion(
            datasetVersion: proposal.lookup.datasetVersion,
            cellMeters: proposal.cellMeters,
            displacedRegions: regions,
            displacedDefaultRegion: repeater.defaultRegion.text
        )
        adopt(proposal.replace)
    }

    private func adopt(_ outcome: MobileRegionOutcomeRecord) {
        repeater = draftAdoptRegions(
            draft: repeater,
            regions: outcome.regions,
            defaultRegion: outcome.defaultRegion
        )
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
            || suggestion.displacedDefaultRegion != repeater.defaultRegion.text
    }

    @ViewBuilder
    private func suggestionNote(_ suggestion: AutomaticSuggestion) -> some View {
        if regions.isEmpty {
            Text("The region database knows of no regions around this phone, so this device forwards traffic from everywhere.")
        } else {
            VStack(alignment: .leading, spacing: 4) {
                Text("Filled in from where this phone is, using region data \(suggestion.datasetVersion). Edit them freely—nothing is sent until you apply.", comment: "Device setup: footer after region suggestions were filled in. The placeholder is the region database's version, not translated.")
                if !suggestion.displacedRegions.isEmpty, displaces(suggestion) {
                    Text("Undo puts back what the device was already holding.")
                }
            }
        }
    }

    /// A tag row's label, marked when it is the device's own tag and not in
    /// the forwarding list.
    private func defaultRegionLabel(_ region: String) -> String {
        let label = RegionCodeText.label(region: region)
        guard defaultRegionUnlisted, region == repeater.defaultRegion.text else { return label }
        return String(
            localized: "\(label)—not relayed",
            comment: "Device setup: the region a repeater tags untagged traffic with, when it is not one the repeater relays. The placeholder is the region."
        )
    }

    /// Add the typed region, or respell one the list already holds.
    private func addRegion() {
        do {
            repeater = try draftAddRepeaterRegion(draft: repeater, text: regionInput)
            regionProblem = nil
            regionInput = ""
        } catch MobileRegionEntryProblem.Invalid {
            regionProblem = String(
                localized: "That region name is too long. Use up to 24 characters—a short code like SJC or WA, a region name, or 0x followed by four hex digits.",
                comment: "Managing a repeater: a region typed into its flood region list cannot be used."
            )
        } catch MobileRegionEntryProblem.AlreadyListed {
            regionProblem = nil
            regionInput = ""
        } catch {
            // Nothing else is thrown; what was typed stays.
            assertionFailure("adding a region failed: \(error)")
        }
    }
}
