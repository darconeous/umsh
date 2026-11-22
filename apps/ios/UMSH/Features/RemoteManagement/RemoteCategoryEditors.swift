import CoreLocation
import SwiftUI
import UMSHMobileCore

// MARK: - Shared editor plumbing

/// What an editor shows before its category has been read at all, when
/// there is nothing yet to build a draft from.
struct RemoteDraftPending: View {
    let reading: RemoteCategoryReading?
    let isBusy: Bool

    var body: some View {
        Section {
            RemoteEmptyReading()
        } footer: {
            RemoteReadingFooter(reading: reading, isBusy: isBusy)
        }
    }
}

extension View {
    /// Keep an editor's draft on its category's reading: built when the
    /// editor appears (or once the reading exists), and moved onto every
    /// new reading with the operator's edits kept.
    func draft<D: ManagementDraft>(
        _ draft: Binding<D?>,
        from model: ManageDeviceModel,
        revision: UInt64?
    ) -> some View {
        onAppear { draft.wrappedValue = model.rebaseOrBuild(draft.wrappedValue) }
            .onChange(of: revision) { draft.wrappedValue = model.rebaseOrBuild(draft.wrappedValue) }
    }
}

extension ManageDeviceModel {
    /// Apply an editor's draft, and rebuild it from the reading when the
    /// device answered. A write that never left the phone leaves the draft
    /// as the only copy of what the operator asked for, so it stays.
    func applyAndRebuild<D: ManagementDraft>(_ draft: Binding<D?>) async -> MobileApplyOutcome {
        guard let current = draft.wrappedValue else {
            return MobileApplyOutcome(answered: false, result: .nothingToApply)
        }
        let outcome = await apply(current)
        if outcome.answered, let rebuilt = self.draft(D.self) {
            draft.wrappedValue = rebuilt
        }
        return outcome
    }
}

// MARK: - Radio

/// The radio: what it transmits on, how loudly, and under what modem
/// profile.
///
/// Applying anything here brackets the radio—it goes down before the
/// change and comes back up after—so a device is never asked to move the
/// frequency it is transmitting on. It is also the screen most able to
/// strand a device, which is what the confirmation is for.
struct RemoteRadioEditor: View {
    let model: ManageDeviceModel
    @State private var draft: MobileRadioDraft?

    private var reading: RemoteCategoryReading? { model.readings[.radio] }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.radio] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                fields(draft, review: review, problems: problems)
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(
            model: model,
            category: .radio,
            title: "Radio",
            apply: { await model.applyAndRebuild($draft) },
            review: review,
            applyWarning: review?.warning == .strandsRadio
                ? (
                    title: String(
                        localized: "Change This Device's Radio",
                        comment: "Confirmation title and button: apply new radio settings to a managed device."
                    ),
                    message: String(
                        localized: """
                            A device left on a frequency or modem profile the rest of \
                            the mesh is not using cannot be reached to change back.
                            """,
                        comment: "Confirmation message before applying new radio settings to a managed device."
                    )
                )
                : nil
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    @ViewBuilder
    private func fields(
        _ draft: Binding<MobileRadioDraft>,
        review: MobileDraftReviewRecord?,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        if case let .radio(presetID, showsPresets) = review?.details, showsPresets {
            Section {
                Picker("Radio profile", selection: Binding(
                    get: { presetID ?? Self.custom },
                    set: { chosen in
                        guard chosen != Self.custom else { return }
                        draft.wrappedValue = draftAdoptPreset(draft: draft.wrappedValue, presetId: chosen)
                    }
                )) {
                    Text("Custom / manual").tag(Self.custom)
                    ForEach(RadioPreset.vetted) { preset in
                        Text(preset.name).tag(preset.id)
                    }
                }
            } header: {
                Text("Preset")
            } footer: {
                Text(
                    """
                    A preset sets every radio parameter below. Choose the one \
                    your local mesh uses; nodes with different PHY settings \
                    cannot hear each other.
                    """
                )
            }
        }

        Section {
            RemoteToggleField(
                "Radio enabled",
                field: draft.enabled,
                problem: problems[fields.enabled.propertyId]
            )
            RemoteIntegerField(
                "Frequency",
                unit: "kHz",
                field: draft.frequencyKhz,
                problem: problems[fields.frequencyKhz.propertyId]
            )
        } header: {
            Text("Radio")
        } footer: {
            RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
        }

        if model.card?.supportsLora == true {
            Section {
                RemoteChoiceField(
                    "Bandwidth",
                    field: draft.bandwidth,
                    problem: problems[fields.bandwidth.propertyId]
                ) {
                    ForEach(radioChoices.bandwidthsHz, id: \.self) { hertz in
                        Text(RadioValuePresentation.bandwidth(hertz)).choiceTag(hertz)
                    }
                }
                RemoteChoiceField(
                    "Spreading factor",
                    field: draft.spreadingFactor,
                    problem: problems[fields.spreadingFactor.propertyId]
                ) {
                    ForEach(Array(radioChoices.spreadingFactors), id: \.self) {
                        Text("SF\($0)").choiceTag($0)
                    }
                }
                RemoteChoiceField(
                    "Coding rate",
                    field: draft.codingRate,
                    problem: problems[fields.codingRate.propertyId]
                ) {
                    ForEach(Array(radioChoices.codingRates), id: \.self) {
                        Text("4/\($0)").choiceTag($0)
                    }
                }
            } header: {
                Text("Modem profile")
            }
        }

        Section {
            RemoteIntegerField(
                "Transmit power",
                unit: "dBm",
                field: draft.transmitPowerDbm,
                signed: true,
                problem: problems[fields.transmitPowerDbm.propertyId]
            )
            if model.card?.supportsDutyCycleLimit == true {
                if let used = reading?.properties.dutyCycleNow {
                    RemoteValueRow("Past-hour usage", value: formattedDutyCycle(used))
                }
                RemoteChoiceField(
                    "Transmit limit",
                    field: draft.dutyLimit,
                    problem: problems[fields.dutyLimit.propertyId]
                ) {
                    ForEach(radioChoices.dutyCycleLimits, id: \.self) { limit in
                        Text(limit == UInt16.max ? "Disabled" : formattedDutyCycle(limit))
                            .choiceTag(limit)
                    }
                }
            }
        } header: {
            Text("Transmit")
        }
    }

    /// The profile picker's row for parameters no vetted preset spells out.
    private static let custom = "custom"
}

// MARK: - Identity

/// What the device tells the mesh about itself, including where it is.
///
/// The position here is a claim rather than a measurement: a repeater on a
/// mast with no receiver still has a place, and this is where an operator
/// states it. When the device maintains its own position from its receiver,
/// these rows go read-only and say so—the device would refuse the write
/// anyway.
struct RemoteIdentityEditor: View {
    let model: ManageDeviceModel
    @Environment(\.readPhonePosition) private var readPhonePosition
    @State private var draft: MobileIdentityDraft?
    @State private var showsPlacePicker = false
    @State private var isReadingPhone = false
    @State private var phoneUnavailable = false
    /// How far an on-demand announcement is asked to travel. Two choices
    /// rather than a hop count: what an operator is deciding is whether
    /// the neighbors need to hear it or the whole mesh does.
    @State private var announcementReach = MobileAnnouncementReach.nearby

    private var reading: RemoteCategoryReading? { model.readings[.identity] }

    /// The core's view of the position: whether the device keeps its own,
    /// the grid a placed position is encoded to, and what Apply would leave.
    private struct PositionDetails {
        var selfPositioning = false
        var encodingPrecision: UInt8 = 5
        var coordinateDecimals = 5
        var latitude: Double?
        var longitude: Double?

        init(_ review: MobileDraftReviewRecord?) {
            guard case let .identity(
                selfPositioning, encodingPrecision, coordinateDecimals, latitude, longitude
            ) = review?.details else { return }
            self.selfPositioning = selfPositioning
            self.encodingPrecision = encodingPrecision
            self.coordinateDecimals = Int(coordinateDecimals)
            self.latitude = latitude
            self.longitude = longitude
        }
    }

    var body: some View {
        let review = model.review(draft)
        let details = PositionDetails(review)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.identity] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                fields(draft, details: details, problems: problems)
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(
            model: model,
            category: .identity,
            title: "Identity",
            apply: { await model.applyAndRebuild($draft) },
            review: review
        )
        .draft($draft, from: model, revision: reading?.revision)
        // On the Form, never on the section holding the button that opens
        // it: a presentation attached to a Section is attached to every row
        // in it, and all of them try to present at once. One wins and the
        // rest collide with it, which ends with the sheet appearing and
        // going straight back down.
        .sheet(isPresented: $showsPlacePicker) {
            PlacePicker(
                initial: chosenCoordinate,
                precision: details.encodingPrecision
            ) { coordinate, precision in
                guard var placed = draft else { return }
                // Precision first: it decides the grid the place is
                // written to.
                if let precision { placed = draftSetPrecision(draft: placed, precision: precision) }
                draft = draftPlace(
                    draft: placed,
                    latitude: coordinate.latitude,
                    longitude: coordinate.longitude
                )
            }
        }
    }

    @ViewBuilder
    private func fields(
        _ draft: Binding<MobileIdentityDraft>,
        details: PositionDetails,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        if model.card?.supportsDeviceName == true {
            Section {
                if fields.name.known {
                    VStack(alignment: .leading, spacing: 2) {
                        TextField("Name", text: draft.name.text)
                        if let problem = problems[fields.name.propertyId] {
                            Text(problem).font(.caption).foregroundStyle(.red)
                        }
                    }
                } else {
                    RemoteNotRead(title: "Name")
                }
            } header: {
                Text("Name")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
        }

        if model.card?.supportsIdent == true {
            Section("Advertised identity") {
                RemoteChoiceField(
                    "Role",
                    field: draft.role,
                    problem: problems[fields.role.propertyId]
                ) {
                    Text("Derive from what it does").noChoiceTag()
                    ForEach(PeerRole.selectable) { role in
                        Text(role.label).tag(role.roleCode.map { Int64($0) })
                    }
                }
                RemoteToggleField(
                    "Device moves around",
                    field: draft.mobile,
                    problem: problems[fields.mobile.propertyId]
                )
                if model.card?.supportsDeviceIdentity == true {
                    RemoteToggleField(
                        "Discoverable",
                        field: draft.discoverable,
                        problem: problems[fields.discoverable.propertyId]
                    )
                }
            }

            positionSection(draft, details: details, problems: problems)
        }

        if model.card?.supportsAdvert == true {
            Section {
                RemoteChoiceField(
                    "Beacon",
                    field: draft.beaconInterval,
                    problem: problems[fields.beaconInterval.propertyId]
                ) {
                    ForEach(beaconIntervalChoices, id: \.self) {
                        Text(formattedAnnouncementInterval($0)).choiceTag($0)
                    }
                }
                RemoteChoiceField(
                    "Identity",
                    field: draft.advertInterval,
                    problem: problems[fields.advertInterval.propertyId]
                ) {
                    ForEach(advertisementIntervalChoices, id: \.self) {
                        Text(formattedAnnouncementInterval($0)).choiceTag($0)
                    }
                }
                RemoteToggleField(
                    "Beacon at startup",
                    field: draft.startupBeacon,
                    problem: problems[fields.startupBeacon.propertyId]
                )

                Picker("Reach", selection: $announcementReach) {
                    Text("Nearby").tag(MobileAnnouncementReach.nearby)
                    Text("Across the mesh").tag(MobileAnnouncementReach.mesh)
                }
                .pickerStyle(.segmented)
                Button {
                    Task { await model.announce(.advertisement, reach: announcementReach) }
                } label: {
                    Label(
                        "Send Advertisement",
                        systemImage: "antenna.radiowaves.left.and.right"
                    )
                }
                .disabled(model.isBusy)
                Button {
                    Task { await model.announce(.beacon, reach: announcementReach) }
                } label: {
                    Label("Send Beacon", systemImage: "dot.radiowaves.left.and.right")
                }
                .disabled(model.isBusy)
            } header: {
                Text("Announcements")
            } footer: {
                Text(
                    """
                    An advertisement carries the device's signed identity; \
                    a beacon carries nothing and publishes a path back to it. \
                    Either is queued at the device and goes out when its \
                    duty limit allows.
                    """
                )
            }
        }
    }

    /// Where the device says it is.
    @ViewBuilder
    private func positionSection(
        _ draft: Binding<MobileIdentityDraft>,
        details: PositionDetails,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        Section {
            if details.selfPositioning {
                RemoteValueRow("Position", value: positionSummary(details))
                if let altitude = fields.altitudeM.reported {
                    RemoteValueRow("Altitude", value: "\(altitude) m")
                }
            } else {
                RemotePositionField(
                    field: draft.position,
                    decimals: details.coordinateDecimals,
                    problem: problems[fields.position.propertyId]
                )
                RemoteOptionalIntegerField(
                    "Altitude",
                    unit: "m",
                    field: draft.altitudeM,
                    signed: true,
                    problem: problems[fields.altitudeM.propertyId]
                )
                if fields.position.known {
                    // Two coordinates typed to five decimal places is a poor
                    // way to say "here" and the worst way to say "over
                    // there", so both are offered as the acts they actually
                    // are: standing at the device, or looking at where it
                    // goes.
                    if model.phoneStandsForDevice, readPhonePosition != nil {
                        Button {
                            Task { await placeFromPhone() }
                        } label: {
                            HStack {
                                Label("Use This Phone's Position", systemImage: "location")
                                if isReadingPhone {
                                    Spacer()
                                    ProgressView()
                                }
                            }
                        }
                        .disabled(isReadingPhone)
                    }
                    Button {
                        showsPlacePicker = true
                    } label: {
                        Label("Choose on Map", systemImage: "mappin.and.ellipse")
                    }
                    if fields.position.latitude != nil || fields.position.longitude != nil
                        || fields.altitudeM.value != nil {
                        Button("Clear Position", role: .destructive) {
                            draft.wrappedValue = draftClearPosition(draft: draft.wrappedValue)
                        }
                    }
                }
            }
            if model.card?.supportsGnss == true {
                RemoteToggleField(
                    "Update position from GNSS",
                    field: draft.selfPositions,
                    problem: problems[fields.selfPositions.propertyId]
                )
            }
            precisionRow(draft, details: details, problems: problems)
        } header: {
            Text("Position")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                // Only the read-only case needs saying: the rows have gone
                // uneditable and the reason is not on screen.
                if details.selfPositioning {
                    Text("Turn this off and apply to place or clear the device's position.")
                }
                if phoneUnavailable {
                    Text("This phone could not find where it is.")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    /// How coarsely the position is reported.
    ///
    /// The same choice reached two ways. A device with a receiver holds it as
    /// a property—it is the clamp its own fixes pass through—and there
    /// this writes it. A device without one has no such property and never
    /// answered for it, so the choice is local: it decides how many bytes a
    /// hand-placed position is encoded to, and reaches the device only inside
    /// that value.
    @ViewBuilder
    private func precisionRow(
        _ draft: Binding<MobileIdentityDraft>,
        details: PositionDetails,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        if fields.precision.known {
            RemoteChoiceField(
                "Reported precision",
                field: draft.precision,
                problem: problems[fields.precision.propertyId]
            ) {
                ForEach(LocationPresentation.precisions, id: \.self) { precision in
                    Text(Self.precisionLabel(precision)).choiceTag(precision)
                }
            }
        } else if !details.selfPositioning, fields.position.known {
            Picker("Reported precision", selection: Binding(
                get: { draft.wrappedValue.manualPrecision },
                set: { draft.wrappedValue = draftSetPrecision(draft: draft.wrappedValue, precision: $0) }
            )) {
                ForEach(LocationPresentation.precisions, id: \.self) { precision in
                    Text(Self.precisionLabel(precision)).tag(precision)
                }
            }
        }
    }

    /// The place on screen, where both halves of one are on screen.
    private var chosenCoordinate: CLLocationCoordinate2D? {
        guard let latitude = draft?.position.latitude, let longitude = draft?.position.longitude
        else { return nil }
        return CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }

    /// The position the device keeps for itself, as it advertises it.
    private func positionSummary(_ details: PositionDetails) -> String {
        guard let latitude = details.latitude, let longitude = details.longitude else {
            return "None advertised"
        }
        let format = FloatingPointFormatStyle<Double>.number
            .precision(.fractionLength(details.coordinateDecimals))
            .grouping(.never)
        return "\(latitude.formatted(format))°, \(longitude.formatted(format))°"
    }

    /// Place the device where this phone is.
    ///
    /// Offered only on a local link, where the two are in the same room. The
    /// altitude comes along when the fix states one, because a phone that
    /// knows its own height knows the device's—and is left alone otherwise
    /// rather than written as a zero.
    private func placeFromPhone() async {
        guard let readPhonePosition, !isReadingPhone else { return }
        isReadingPhone = true
        phoneUnavailable = false
        defer { isReadingPhone = false }
        guard let reading = await readPhonePosition() else {
            phoneUnavailable = true
            return
        }
        guard let current = draft else { return }
        draft = draftPlaceFromPhone(
            draft: current,
            latitude: reading.coordinate.latitude,
            longitude: reading.coordinate.longitude,
            altitudeM: reading.verticalAccuracy > 0 ? reading.altitude : nil
        )
    }

    static func precisionLabel(_ precision: UInt8) -> String {
        LocationPresentation.precisionLabel(precisionBytes: precision)
    }
}

// MARK: - Repeater

/// Whether and what this device forwards for the rest of the mesh.
struct RemoteRepeaterEditor: View {
    let model: ManageDeviceModel
    @Environment(\.regionService) private var regionService
    @State private var draft: MobileRepeaterDraft?
    @State private var newRegion = ""
    @State private var regionProblem: String?
    @State private var showsSuggestion = false
    /// Accepted in the suggestion sheet, adopted from its onDismiss.
    @State private var pendingSuggestion: MobileRegionOutcomeRecord?

    private var reading: RemoteCategoryReading? { model.readings[.repeater] }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.repeater] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                fields(draft, review: review, problems: problems)
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }

            // Secondary to the protocol this screen configures, so a screen
            // of its own.
            if model.card?.supportsMeshcoreForwarder == true {
                Section {
                    NavigationLink("MeshCore") { RemoteMeshCoreScreen(model: model) }
                }
            }
        }
        // A mutation of plain draft state animates nothing on its own (and a
        // withAnimation around it is lost to the same update's text-field
        // reset), so the Form animates whenever the region list changes.
        // With the rows' insertion transition set to .identity below, what
        // this actually animates is the reflow: the blank input row and
        // everything under it sliding down to make room.
        .animation(UMSHAnimation.list, value: draft?.regions.value)
        .remoteCategoryChrome(
            model: model,
            category: .repeater,
            title: "Repeater",
            apply: { await model.applyAndRebuild($draft) },
            review: review
        )
        .draft($draft, from: model, revision: reading?.revision)
        // Where the device says it is, and what its receiver sees, are what
        // a region suggestion starts from. Both come out of the cache and
        // cost nothing on the air; the sheet offers a real read when the
        // cache has nothing.
        .task {
            await model.loadCategory(.identity)
            await model.loadCategory(.gnss)
        }
        .sheet(isPresented: $showsSuggestion, onDismiss: adoptPendingSuggestion) {
            RegionSuggestionSheet(
                currentRegions: draft?.regions.value ?? [],
                currentDefaultRegion: currentDefaultRegion,
                sources: positionSources,
                // Over a local link the phone is at the device, so where it
                // is stands for where the device is—and is offered first,
                // being the freshest position either of them has. Across
                // the mesh it stands for nothing about the device.
                offersPhone: model.phoneStandsForDevice,
                refreshAdvertised: { await model.refreshCategory(.identity) },
                accept: { pendingSuggestion = $0 }
            )
        }
    }

    @ViewBuilder
    private func fields(
        _ draft: Binding<MobileRepeaterDraft>,
        review: MobileDraftReviewRecord?,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        Section {
            RemoteChoiceField(
                LocalizedStringResource("Forward for others", comment: "Picker title: whether a remote device forwards other nodes' traffic."),
                field: draft.mode,
                problem: problems[fields.mode.propertyId]
            ) {
                Text("Off", comment: "Forwarding mode: the device does not forward.")
                    .choiceTag(0)
                Text("Adaptive", comment: "Forwarding mode: the device forwards only what no repeater carried.")
                    .choiceTag(2)
                Text("On", comment: "Forwarding mode: the device is a repeater.")
                    .choiceTag(1)
            }
            if fields.mode.reported == 2, let state = reading?.properties.repeaterState {
                RemoteValueRow(
                    String(localized: "Now", comment: "Row title: what an adaptive forwarder is doing at the moment."),
                    value: Self.stateText(state)
                )
            }
        } header: {
            Text("Forwarding")
        } footer: {
            RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
        }

        Section {
            ForEach(fields.regions.value, id: \.self) { region in
                Text(RegionCodeText.label(region: region))
                    .font(.body.monospaced())
                    // Adding animates the *blank input row* sliding down
                    // to its new slot, not the added row: the typed text
                    // is already sitting exactly where the new row lands,
                    // so fading the row in would flicker text the user
                    // just wrote. Insertion is therefore instant and the
                    // Form-level animation above moves everything else.
                    .transition(.asymmetric(insertion: .identity, removal: .opacity))
            }
            .onDelete { draft.wrappedValue.regions.value.remove(atOffsets: $0) }
            if fields.regions.known {
                HStack {
                    TextField("Airport code, name, or 0x1234", text: $newRegion)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .onSubmit { addRegion() }
                    Button("Add", action: addRegion)
                        .disabled(newRegion.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                // Only once the device has said what it forwards: the
                // current list is what a suggestion is a diff against,
                // and against nothing it would be a blind overwrite.
                if regionService?.isReady == true {
                    Button {
                        showsSuggestion = true
                    } label: {
                        Label(
                            "Update based on location",
                            systemImage: "location.magnifyingglass"
                        )
                    }
                }
            } else {
                RemoteNotRead(title: "Regions")
            }
        } header: {
            Text("Flood regions")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                if let problem = problems[fields.regions.propertyId] {
                    Text(problem).foregroundStyle(.red)
                }
                if let regionProblem {
                    Text(regionProblem).foregroundStyle(.red)
                }
                // An empty list meaning "everything" is the one thing
                // here nobody would guess.
                if fields.regions.known, fields.regions.value.isEmpty {
                    Text("With none listed, the device forwards every flood it hears.")
                }
            }
        }

        Section {
            if fields.defaultRegion.known {
                Picker(selection: draft.defaultRegion.text) {
                    Text("Leave untagged").tag("")
                    // The device's own choice is offered whether or not it
                    // is still in the list above: deleting a region the
                    // device tags with should not leave the picker with
                    // nothing to show for what the device actually holds.
                    ForEach(taggableRegions(review), id: \.self) { region in
                        Text(RegionCodeText.label(region: region)).tag(region)
                    }
                } label: {
                    RemoteFieldTitle(
                        "Tag untagged floods",
                        problem: problems[fields.defaultRegion.propertyId]
                    )
                }
            } else {
                RemoteNotRead(title: "Tag untagged floods")
            }
        }

        Section {
            RemoteOptionalIntegerField(
                "Minimum RSSI",
                unit: "dBm",
                field: draft.minRssi,
                signed: true,
                problem: problems[fields.minRssi.propertyId]
            )
            RemoteOptionalIntegerField(
                "Minimum SNR",
                unit: "dB",
                field: draft.minSnr,
                signed: true,
                problem: problems[fields.minSnr.propertyId]
            )
        } header: {
            Text("Forwarding thresholds")
        } footer: {
            Text("Leave either empty for no threshold.")
        }
    }

    private func taggableRegions(_ review: MobileDraftReviewRecord?) -> [String] {
        guard case let .repeater(taggable) = review?.details else { return [] }
        return taggable
    }

    /// The tag the draft holds, as the code a suggestion compares against.
    private var currentDefaultRegion: Data? {
        guard let text = draft?.defaultRegion.text, !text.isEmpty else { return nil }
        return RegionCodeText.code(of: text)
    }

    /// The places this device's regions could be proposed from.
    ///
    /// The device's own fix appears only when it disagrees with what the
    /// device advertises; the sheet adds this phone and typed coordinates
    /// itself.
    private var positionSources: [RegionPositionSource] {
        let identity = model.readings[.identity]?.properties
        let advertised = RegionPositionSource.advertised(
            location: identity?.identLocation,
            latitude: identity?.identLatitudeDeg,
            longitude: identity?.identLongitudeDeg
        )
        let fix = model.readings[.gnss]?.properties.gnss
        return [
            advertised,
            RegionPositionSource.gnss(
                latitude: fix?.latitudeDeg,
                longitude: fix?.longitudeDeg,
                accuracyDecimeters: fix?.accuracyDm,
                outside: advertised
            ),
        ].compactMap { $0 }
    }

    /// Adopt what the suggestion sheet accepted, deferred to its dismissal
    /// so the rows arrive in an on-screen list instead of behind the sheet.
    private func adoptPendingSuggestion() {
        guard let outcome = pendingSuggestion, let current = draft else { return }
        pendingSuggestion = nil
        draft = draftAdoptRegions(
            draft: current,
            regions: outcome.regions,
            defaultRegion: outcome.defaultRegion
        )
    }

    /// Add the typed region, or respell one the list already holds.
    private func addRegion() {
        guard let current = draft else { return }
        do {
            draft = try draftAddRepeaterRegion(draft: current, text: newRegion)
            regionProblem = nil
            newRegion = ""
        } catch MobileRegionEntryProblem.Invalid {
            regionProblem = String(
                localized: "That region name is too long. Use up to 24 characters—a short code like SJC or WA, a region name, or 0x followed by four hex digits.",
                comment: "Managing a repeater: a region typed into its flood region list cannot be used."
            )
        } catch MobileRegionEntryProblem.AlreadyListed {
            regionProblem = nil
            newRegion = ""
        } catch {
            // Nothing else is thrown; what was typed stays.
            assertionFailure("adding a region failed: \(error)")
        }
    }

    /// What `PROP_MAC_REPEATER_STATE` says an adaptive forwarder is doing.
    private static func stateText(_ state: UInt8) -> String {
        switch state {
        case 2: String(localized: "Standing by", comment: "Adaptive forwarding state: forwarding only where no other forwarder is heard.")
        case 3: String(localized: "Carrying traffic", comment: "Adaptive forwarding state: a nearby node depends on this one, so it is forwarding as a repeater does.")
        case 4: String(localized: "Holding back", comment: "Adaptive forwarding state: the battery is low or the channel is busy, so the device forwards little or nothing.")
        default: state.formatted()
        }
    }
}

// MARK: - MeshCore

/// Whether this device also forwards MeshCore traffic, and for which
/// regions. Part of the repeater category on the device; its own screen
/// because it is secondary to everything the Repeater screen sets.
struct RemoteMeshCoreScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileMeshCoreDraft?
    @State private var newRegion = ""
    @State private var regionProblem: String?

    private var reading: RemoteCategoryReading? { model.readings[.repeater] }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.repeater] ?? [:], review: review)
        Form {
            if let draft = Binding($draft) {
                fields(draft, review: review, problems: problems)
            } else {
                RemoteDraftPending(reading: reading, isBusy: model.isBusy)
            }
        }
        .animation(UMSHAnimation.list, value: draft?.regions.value)
        .remoteCategoryChrome(
            model: model,
            category: .repeater,
            title: "MeshCore",
            apply: { await model.applyAndRebuild($draft) },
            review: review
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    @ViewBuilder
    private func fields(
        _ draft: Binding<MobileMeshCoreDraft>,
        review: MobileDraftReviewRecord?,
        problems: RemoteRowProblems
    ) -> some View {
        let fields = draft.wrappedValue
        let (identityAllowed, toggleLocked) = switch review?.details {
        case let .meshCore(identityAllowed, toggleLocked): (identityAllowed, toggleLocked)
        default: (true, false)
        }
        Section {
            RemoteToggleField(
                "Forward MeshCore",
                field: draft.enabled,
                problem: problems[fields.enabled.propertyId]
            )
            // Turning it off stays possible whatever the key.
            .disabled(toggleLocked)
            RemoteChoiceField(
                "Region policy",
                field: draft.policy,
                problem: problems[fields.policy.propertyId]
            ) {
                Text("Open").choiceTag(0)
                Text("Scoped only").choiceTag(1)
                Text("Ignore").choiceTag(2)
            }
        } footer: {
            if !identityAllowed {
                Text("Unavailable for this device's identity key.")
            }
        }

        Section {
            ForEach(fields.regions.value, id: \.self) { region in
                Text(region)
                    .font(.body.monospaced())
                    .transition(.asymmetric(insertion: .identity, removal: .opacity))
            }
            .onDelete { draft.wrappedValue.regions.value.remove(atOffsets: $0) }
            if fields.regions.known {
                HStack {
                    TextField("Region name", text: $newRegion)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .onSubmit { addRegion() }
                    Button("Add", action: addRegion)
                        .disabled(newRegion.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } else {
                RemoteNotRead(title: "Regions")
            }
        } header: {
            Text("Regions")
        } footer: {
            if let problem = regionProblem ?? problems[fields.regions.propertyId] {
                Text(problem).foregroundStyle(.red)
            }
        }
    }

    /// Names are kept as typed, case included, less any `#`. One already
    /// listed is left where it is.
    private func addRegion() {
        guard let current = draft else { return }
        do {
            draft = try draftAddMeshcoreRegion(draft: current, text: newRegion)
            regionProblem = nil
            newRegion = ""
        } catch MobileRegionEntryProblem.Invalid {
            regionProblem = String(
                localized: "Use 1 to 30 characters, not starting with $.",
                comment: "Managing a repeater: a MeshCore region name typed into its list cannot be used."
            )
        } catch MobileRegionEntryProblem.AlreadyListed {
            regionProblem = nil
            newRegion = ""
        } catch {
            // Nothing else is thrown; what was typed stays.
            assertionFailure("adding a region failed: \(error)")
        }
    }
}
