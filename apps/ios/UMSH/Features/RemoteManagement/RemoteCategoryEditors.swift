import CoreLocation
import SwiftUI
import UMSHMobileCore

/// One editable setting: what the device last said, and what the operator
/// has made of it.
///
/// A field the device has never answered for stays `nil` and renders as
/// read-only: there is no baseline to compare an edit against, so nothing
/// typed into it could ever be told apart from a value nobody entered.
struct RemoteField<Value: Equatable & Sendable>: Sendable {
    let property: UInt32
    let reported: Value?
    var edited: Value?

    init(_ property: UInt32, _ reported: Value?) {
        self.property = property
        self.reported = reported
        edited = reported
    }

    var isKnown: Bool { reported != nil }
    var isDirty: Bool { edited != reported }
    /// The edit, falling back to what the device already holds.
    var value: Value? { edited ?? reported }

    /// Fold a typed field's text back in, once it has parsed.
    ///
    /// Text that does not parse is not an edit — it is someone partway
    /// through typing one — so it reads as whatever the device holds. And a
    /// field the device never answered for takes nothing at all: an empty
    /// box compared against no baseline would stand permanently dirty, and
    /// Apply would offer to write a value nobody entered.
    mutating func fold(_ parsed: Value?) {
        guard isKnown else { return }
        edited = parsed ?? reported
    }

    /// This field — freshly built on a new baseline — keeping the
    /// operator's edit where one stands.
    ///
    /// The non-intrusive rule for a reading that moves under an open
    /// editor, from a push or a refresh: a clean field follows the
    /// device, a dirty one keeps the operator's value against the new
    /// baseline. A value that lands exactly on the edit cleans the field,
    /// which is the operator's ask arriving from elsewhere, not a
    /// conflict.
    func preserving(_ old: RemoteField<Value>) -> RemoteField<Value> {
        var merged = self
        if old.isDirty, isKnown { merged.edited = old.edited }
        return merged
    }
}

extension Binding {
    /// Present an optional as a plain value, standing in `fallback` where
    /// there is none.
    ///
    /// The controls here bind to fields that may have no value at all, and
    /// only render once they do — so the stand-in is never what is on
    /// screen. It exists because `Toggle` and `Picker` take a value rather
    /// than the absence of one.
    func replacingNil<Wrapped: Sendable>(with fallback: Wrapped) -> Binding<Wrapped>
        where Value == Wrapped? {
        Binding<Wrapped>(get: { wrappedValue ?? fallback }, set: { wrappedValue = $0 })
    }
}

// MARK: - Radio

/// The radio: what it transmits on, how loudly, and under what modem
/// profile.
///
/// Applying anything here brackets the radio — it goes down before the
/// change and comes back up after — so a device is never asked to move the
/// frequency it is transmitting on. It is also the screen most able to
/// strand a device, which is what the confirmation is for.
struct RemoteRadioEditor: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()

    private var reading: RemoteCategoryReading? { model.readings[.radio] }
    private var problems: [UInt32: String] { model.writeRefusals[.radio] ?? [:] }

    var body: some View {
        Form {
            if showsPresets {
                Section {
                    Picker("Radio profile", selection: $edits.presetIdentifier) {
                        Text("Custom / manual").tag("custom")
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
                if edits.enabled.isKnown {
                    Toggle(isOn: $edits.enabled.edited.replacingNil(with: true)) {
                        RemoteFieldTitle("Radio enabled", problem: problems[edits.enabled.property])
                    }
                } else {
                    RemoteReadOnlyToggle("Radio enabled", isOn: nil)
                }
                RemoteNumberField(
                    "Frequency",
                    unit: "kHz",
                    text: $edits.frequency,
                    isKnown: edits.frequencyField.isKnown,
                    problem: problems[edits.frequencyField.property]
                )
            } header: {
                Text("Radio")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            if model.card?.supportsLora == true {
                Section {
                    RemotePicker(
                        "Bandwidth",
                        selection: $edits.bandwidth.edited,
                        problem: problems[edits.bandwidth.property]
                    ) {
                        ForEach(Self.bandwidths, id: \.self) { hertz in
                            Text(Self.bandwidthLabel(hertz)).tag(hertz)
                        }
                    }
                    RemotePicker(
                        "Spreading factor",
                        selection: $edits.spreadingFactor.edited,
                        problem: problems[edits.spreadingFactor.property]
                    ) {
                        ForEach(UInt8(5) ... UInt8(12), id: \.self) { Text("SF\($0)").tag($0) }
                    }
                    RemotePicker(
                        "Coding rate",
                        selection: $edits.codingRate.edited,
                        problem: problems[edits.codingRate.property]
                    ) {
                        ForEach(UInt8(5) ... UInt8(8), id: \.self) { Text("4/\($0)").tag($0) }
                    }
                } header: {
                    Text("Modem profile")
                }
            }

            Section {
                RemoteNumberField(
                    "Transmit power",
                    unit: "dBm",
                    text: $edits.transmitPower,
                    isKnown: edits.transmitPowerField.isKnown,
                    signed: true,
                    problem: problems[edits.transmitPowerField.property]
                )
                if model.card?.supportsDutyCycleLimit == true {
                    if let used = reading?.properties.dutyCycleNow {
                        LabeledContent("Past-hour usage", value: Self.dutyLabel(used))
                    }
                    RemotePicker(
                        "Transmit limit",
                        selection: $edits.dutyLimit.edited,
                        problem: problems[edits.dutyLimit.property]
                    ) {
                        ForEach(Self.dutyLimits, id: \.self) { limit in
                            Text(
                                limit == UInt16.max ? "Disabled" : Self.dutyLabel(limit)
                            ).tag(limit)
                        }
                    }
                }
            } header: {
                Text("Transmit")
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .radio,
            title: "Radio",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty,
            // Power and the transmit limit change how far this device
            // reaches, not what it can hear, so they apply unwarned.
            applyWarning: edits.strandsIfWrong
                ? (
                    title: "Change This Device's Radio",
                    message: """
                        A device left on a frequency or modem profile the rest of \
                        the mesh is not using cannot be reached to change back.
                        """
                )
                : nil
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    /// A preset names every radio parameter at once, so it is only offered
    /// when every parameter it would set has been read from the device.
    private var showsPresets: Bool {
        edits.frequencyField.isKnown && edits.transmitPowerField.isKnown
            && (model.card?.supportsLora != true || edits.bandwidth.isKnown)
            && (model.card?.supportsDutyCycleLimit != true || edits.dutyLimit.isKnown)
    }

    private func apply() async {
        // Only rebuilt when the device answered: see RemoteGnssScreen.
        if await model.apply(.radio, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.radio])
        }
    }

    /// The fields on this screen, and what the operator has done to them.
    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var frequencyField = RemoteField<UInt32>(0, nil)
        var transmitPowerField = RemoteField<Int8>(0, nil)
        var bandwidth = RemoteField<UInt32>(0, nil)
        var spreadingFactor = RemoteField<UInt8>(0, nil)
        var codingRate = RemoteField<UInt8>(0, nil)
        var dutyLimit = RemoteField<UInt16>(0, nil)
        /// Typed rather than picked, so they are text until they parse.
        var frequency = ""
        var transmitPower = ""
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            enabled = RemoteField(id.phyEnabled, held.phyEnabled)
            frequencyField = RemoteField(id.frequency, held.frequencyKhz)
            transmitPowerField = RemoteField(id.transmitPower, held.transmitPowerDbm)
            bandwidth = RemoteField(id.loraBandwidth, held.bandwidthHz)
            spreadingFactor = RemoteField(id.loraSpreadingFactor, held.spreadingFactor)
            codingRate = RemoteField(id.loraCodingRate, held.codingRateDenom)
            dutyLimit = RemoteField(id.dutyCycleLimit, held.dutyCycleLimit)
            frequency = held.frequencyKhz.map(String.init) ?? ""
            transmitPower = held.transmitPowerDbm.map(String.init) ?? ""
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edits carried over field by field — see
        /// ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            let typed = old.typed
            enabled = enabled.preserving(typed.enabled)
            frequencyField = frequencyField.preserving(typed.frequencyField)
            transmitPowerField = transmitPowerField.preserving(typed.transmitPowerField)
            bandwidth = bandwidth.preserving(typed.bandwidth)
            spreadingFactor = spreadingFactor.preserving(typed.spreadingFactor)
            codingRate = codingRate.preserving(typed.codingRate)
            dutyLimit = dutyLimit.preserving(typed.dutyLimit)
            // The text forms follow their fields: kept while the operator's
            // edit stands, re-derived from the device otherwise.
            if typed.frequencyField.isDirty, frequencyField.isKnown {
                frequency = old.frequency
            }
            if typed.transmitPowerField.isDirty, transmitPowerField.isKnown {
                transmitPower = old.transmitPower
            }
        }

        /// The typed fields folded back in, so both kinds of edit are
        /// compared the same way.
        private var typed: Edits {
            var typed = self
            typed.frequencyField.fold(UInt32(frequency))
            typed.transmitPowerField.fold(Int8(transmitPower))
            return typed
        }

        /// The vetted profile the fields currently spell out, or "custom".
        /// Settable, so the picker binds straight to it: choosing a
        /// profile writes every radio parameter it names.
        var presetIdentifier: String {
            get { RadioPreset.vetted.first { matches($0) }?.id ?? "custom" }
            set {
                guard let preset = RadioPreset.vetted.first(where: { $0.id == newValue })
                else { return }
                adopt(preset)
            }
        }

        /// Which vetted profile a device is on is a question about the mesh
        /// it can talk to, so only the parameters that decide that are
        /// compared. Transmit power and the transmit limit are how hard
        /// this one device pushes and how often — local decisions that
        /// leave it on the same profile as everyone else, and a radio
        /// reports power clamped to what it can actually reach. Comparing
        /// either would call a device "custom" for turning itself down.
        /// The same exclusion `RadioProfile.interoperates(with:)` makes.
        private func matches(_ preset: RadioPreset) -> Bool {
            let typed = self.typed
            // A field the device never answered for is left out of the
            // comparison the same way it is left out of the form.
            return typed.frequencyField.value == preset.frequencyKHz
                && (!bandwidth.isKnown || typed.bandwidth.value == preset.bandwidthHz)
                && (!spreadingFactor.isKnown
                    || typed.spreadingFactor.value == preset.spreadingFactor)
                && (!codingRate.isKnown || typed.codingRate.value == preset.codingRate)
        }

        private mutating func adopt(_ preset: RadioPreset) {
            if enabled.isKnown { enabled.edited = true }
            frequency = String(preset.frequencyKHz)
            if let power = preset.transmitPowerDBm { transmitPower = String(power) }
            if bandwidth.isKnown { bandwidth.edited = preset.bandwidthHz }
            if spreadingFactor.isKnown { spreadingFactor.edited = preset.spreadingFactor }
            if codingRate.isKnown { codingRate.edited = preset.codingRate }
            if dutyLimit.isKnown { dutyLimit.edited = preset.dutyCycleLimit }
        }

        /// Whether these edits touch what the device listens on. Frequency
        /// and the modem profile decide who can hear whom, and a radio
        /// switched off hears nothing — those get the warning. Power and
        /// the transmit limit only change how far the device reaches.
        var strandsIfWrong: Bool {
            let typed = self.typed
            return typed.frequencyField.isDirty
                || typed.bandwidth.isDirty
                || typed.spreadingFactor.isDirty
                || typed.codingRate.isDirty
                || (typed.enabled.isDirty && typed.enabled.edited == false)
        }

        var dirty: Set<UInt32> {
            let typed = self.typed
            var dirty: Set<UInt32> = []
            for (property, changed) in [
                (typed.enabled.property, typed.enabled.isDirty),
                (typed.frequencyField.property, typed.frequencyField.isDirty),
                (typed.transmitPowerField.property, typed.transmitPowerField.isDirty),
                (typed.bandwidth.property, typed.bandwidth.isDirty),
                (typed.spreadingFactor.property, typed.spreadingFactor.isDirty),
                (typed.codingRate.property, typed.codingRate.isDirty),
                (typed.dutyLimit.property, typed.dutyLimit.isDirty),
            ] where changed {
                dirty.insert(property)
            }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            let typed = self.typed
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.phyEnabled = typed.enabled.value
            desired.frequencyKhz = typed.frequencyField.value
            desired.transmitPowerDbm = typed.transmitPowerField.value
            desired.bandwidthHz = typed.bandwidth.value
            desired.spreadingFactor = typed.spreadingFactor.value
            desired.codingRateDenom = typed.codingRate.value
            desired.dutyCycleLimit = typed.dutyLimit.value
            return desired
        }
    }

    private static let bandwidths: [UInt32] = ulcpSupportedBandwidthsHz()
    private static let dutyLimits = dutyCycleLimitChoices

    private static func bandwidthLabel(_ hertz: UInt32) -> String {
        (Double(hertz) / 1000).formatted(.number.precision(.fractionLength(hertz < 100_000 ? 2 : 0)))
            + " kHz"
    }

    private static func dutyLabel(_ value: UInt16) -> String {
        formattedDutyCycle(value)
    }
}

// MARK: - Identity

/// What the device tells the mesh about itself, including where it is.
///
/// The position here is a claim rather than a measurement: a repeater on a
/// mast with no receiver still has a place, and this is where an operator
/// states it. When the device maintains its own position from its receiver,
/// these rows go read-only and say so — the device would refuse the write
/// anyway.
struct RemoteIdentityEditor: View {
    let model: ManageDeviceModel
    @Environment(\.readPhonePosition) private var readPhonePosition
    @State private var edits = Edits()
    @State private var showsPlacePicker = false
    @State private var isReadingPhone = false
    @State private var phoneUnavailable = false

    private var reading: RemoteCategoryReading? { model.readings[.identity] }
    private var problems: [UInt32: String] { model.writeRefusals[.identity] ?? [:] }

    var body: some View {
        Form {
            if model.card?.supportsDeviceName == true {
                Section {
                    if edits.name.isKnown {
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("Name", text: $edits.nameText)
                            if let problem = problems[edits.name.property] {
                                Text(problem).font(.caption).foregroundStyle(.red)
                            }
                        }
                    } else {
                        LabeledContent("Name", value: "Not read")
                    }
                } header: {
                    Text("Name")
                } footer: {
                    RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
                }
            }

            if model.card?.supportsIdent == true {
                Section("Advertised identity") {
                    RemotePicker(
                        "Role",
                        selection: $edits.role.edited,
                        problem: problems[edits.role.property]
                    ) {
                        Text("Derive from what it does").tag(UInt8?.none)
                        ForEach(PeerRole.selectable) { role in
                            Text(role.label).tag(role.roleCode)
                        }
                    }
                    if edits.mobile.isKnown {
                        Toggle(isOn: $edits.mobile.edited.replacingNil(with: false)) {
                            RemoteFieldTitle(
                                "Device moves around",
                                problem: problems[edits.mobile.property]
                            )
                        }
                    } else {
                        RemoteReadOnlyToggle("Device moves around", isOn: nil)
                    }
                    if model.card?.supportsDeviceIdentity == true {
                        if edits.discoverable.isKnown {
                            Toggle(isOn: $edits.discoverable.edited.replacingNil(with: false)) {
                                RemoteFieldTitle(
                                    "Discoverable",
                                    problem: problems[edits.discoverable.property]
                                )
                            }
                        } else {
                            RemoteReadOnlyToggle("Discoverable", isOn: nil)
                        }
                    }
                }

                positionSection
            }

            if model.card?.supportsAdvert == true {
                Section {
                    RemotePicker(
                        "Beacon",
                        selection: $edits.beaconInterval.edited,
                        problem: problems[edits.beaconInterval.property]
                    ) {
                        ForEach(beaconIntervalChoices, id: \.self) {
                            Text(formattedAnnouncementInterval($0)).tag($0)
                        }
                    }
                    RemotePicker(
                        "Identity",
                        selection: $edits.advertInterval.edited,
                        problem: problems[edits.advertInterval.property]
                    ) {
                        ForEach(advertisementIntervalChoices, id: \.self) {
                            Text(formattedAnnouncementInterval($0)).tag($0)
                        }
                    }
                    if edits.startupBeacon.isKnown {
                        Toggle(isOn: $edits.startupBeacon.edited.replacingNil(with: false)) {
                            RemoteFieldTitle(
                                "Beacon at startup",
                                problem: problems[edits.startupBeacon.property]
                            )
                        }
                    } else {
                        RemoteReadOnlyToggle("Beacon at startup", isOn: nil)
                    }
                } header: {
                    Text("Announcements")
                }
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .identity,
            title: "Identity",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
        // On the Form, never on the section holding the button that opens
        // it: a presentation attached to a Section is attached to every row
        // in it, and all of them try to present at once. One wins and the
        // rest collide with it, which ends with the sheet appearing and
        // going straight back down.
        .sheet(isPresented: $showsPlacePicker) {
            PlacePicker(
                initial: edits.chosenCoordinate,
                precision: edits.encodingPrecision
            ) { coordinate in
                edits.place(latitude: coordinate.latitude, longitude: coordinate.longitude)
            }
        }
    }

    /// Where the device says it is.
    @ViewBuilder
    private var positionSection: some View {
        Section {
            if edits.isSelfPositioning {
                LabeledContent("Position", value: edits.positionSummary)
                if let altitude = edits.altitude.reported ?? nil {
                    LabeledContent("Altitude", value: "\(altitude) m")
                }
            } else {
                RemoteNumberField(
                    "Latitude",
                    unit: "°",
                    text: $edits.latitude,
                    isKnown: edits.location.isKnown,
                    signed: true,
                    decimal: true,
                    problem: problems[edits.location.property]
                )
                RemoteNumberField(
                    "Longitude",
                    unit: "°",
                    text: $edits.longitude,
                    isKnown: edits.location.isKnown,
                    signed: true,
                    decimal: true
                )
                RemoteNumberField(
                    "Altitude",
                    unit: "m",
                    text: $edits.altitudeText,
                    isKnown: edits.altitude.isKnown,
                    signed: true,
                    problem: problems[edits.altitude.property]
                )
                if edits.location.isKnown {
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
                }
            }
            if model.card?.supportsGnss == true {
                if edits.selfPositions.isKnown {
                    Toggle(isOn: $edits.selfPositions.edited.replacingNil(with: false)) {
                        RemoteFieldTitle(
                            "Update position from GNSS",
                            problem: problems[edits.selfPositions.property]
                        )
                    }
                } else {
                    RemoteReadOnlyToggle("Update position from GNSS", isOn: nil)
                }
            }
            precisionRow
        } header: {
            Text("Position")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                // Only the read-only case needs saying: the rows have gone
                // uneditable and the reason is not on screen.
                if edits.isSelfPositioning {
                    Text("Turn this off to place the device by hand.")
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
    /// a property — it is the clamp its own fixes pass through — and there
    /// this writes it. A device without one has no such property and never
    /// answered for it, so the choice is local: it decides how many bytes a
    /// hand-placed position is encoded to, and reaches the device only inside
    /// that value.
    @ViewBuilder
    private var precisionRow: some View {
        if edits.precision.isKnown {
            RemotePicker(
                "Reported precision",
                selection: $edits.precision.edited,
                problem: problems[edits.precision.property]
            ) {
                ForEach(Edits.precisions, id: \.self) { precision in
                    Text(Self.precisionLabel(precision)).tag(precision)
                }
            }
        } else if !edits.isSelfPositioning, edits.location.isKnown {
            Picker("Reported precision", selection: $edits.manualPrecision) {
                ForEach(Edits.precisions, id: \.self) { precision in
                    Text(Self.precisionLabel(precision)).tag(precision)
                }
            }
        }
    }

    /// Place the device where this phone is.
    ///
    /// Offered only on a local link, where the two are in the same room. The
    /// altitude comes along when the fix states one, because a phone that
    /// knows its own height knows the device's — and is left alone otherwise
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
        edits.place(
            latitude: reading.coordinate.latitude,
            longitude: reading.coordinate.longitude
        )
        if reading.verticalAccuracy > 0, edits.altitude.isKnown {
            edits.altitudeText = String(Int32(reading.altitude.rounded()))
        }
    }

    private func apply() async {
        // Only rebuilt when the device answered: see RemoteGnssScreen.
        if await model.apply(.identity, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.identity])
        }
    }

    private struct Edits {
        var name = RemoteField<String>(0, nil)
        var role = RemoteField<UInt8?>(0, nil)
        var mobile = RemoteField<Bool>(0, nil)
        var discoverable = RemoteField<Bool>(0, nil)
        var location = RemoteField<Data>(0, nil)
        var altitude = RemoteField<Int32?>(0, nil)
        var selfPositions = RemoteField<Bool>(0, nil)
        var precision = RemoteField<UInt8>(0, nil)
        var advertInterval = RemoteField<UInt32>(0, nil)
        var beaconInterval = RemoteField<UInt32>(0, nil)
        var startupBeacon = RemoteField<Bool>(0, nil)
        var nameText = ""
        var latitude = ""
        var longitude = ""
        var altitudeText = ""
        /// The grid a hand-placed position is encoded to on a device that
        /// holds no precision property of its own. Never on the air as
        /// itself — it shapes ``location`` and nothing else.
        var manualPrecision = Self.defaultPrecision
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            let read = { (property: UInt32) in
                reading?.propertyIDs.contains(property) == true
                    && reading?.refused.contains(property) != true
            }
            name = RemoteField(id.deviceName, held.deviceName)
            // A role the device does not state is a device deriving its
            // own, and an altitude it leaves empty is a device at no stated
            // height — values rather than absences, so both are known
            // exactly when the property was read.
            role = RemoteField(id.identRole, read(id.identRole) ? .some(held.identRole) : nil)
            mobile = RemoteField(id.identMobile, held.identMobile)
            discoverable = RemoteField(id.devDiscoverable, held.devDiscoverable)
            location = RemoteField(id.identLocation, held.identLocation)
            altitude = RemoteField(
                id.identAltitude,
                read(id.identAltitude) ? .some(held.identAltitudeM) : nil
            )
            selfPositions = RemoteField(id.gnssIdentUpdate, held.gnssIdentUpdate)
            precision = RemoteField(id.gnssIdentPrecision, held.gnssIdentPrecision)
            advertInterval = RemoteField(id.advertInterval, held.advertIntervalSeconds)
            beaconInterval = RemoteField(id.beaconInterval, held.beaconIntervalSeconds)
            startupBeacon = RemoteField(id.startupBeacon, held.startupBeacon)
            nameText = held.deviceName ?? ""
            latitude = held.identLatitudeDeg.map { Self.coordinate($0) } ?? ""
            longitude = held.identLongitudeDeg.map { Self.coordinate($0) } ?? ""
            altitudeText = held.identAltitudeM.map(String.init) ?? ""
            // Precision belongs to the receiver, so a device without one
            // never answers for it — and a position written by hand still
            // has to be encoded to some grid. The grid the device already
            // advertises on is that answer where it has one; a device placed
            // nowhere yet takes the same default a device resets to.
            manualPrecision = precision.reported
                ?? location.reported.flatMap { bytes in
                    Self.precisions.first { Int($0) == bytes.count }
                }
                ?? Self.defaultPrecision
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edits carried over field by field — see
        /// ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            let typed = old.typed
            name = name.preserving(typed.name)
            role = role.preserving(typed.role)
            mobile = mobile.preserving(typed.mobile)
            discoverable = discoverable.preserving(typed.discoverable)
            location = location.preserving(typed.location)
            altitude = altitude.preserving(typed.altitude)
            selfPositions = selfPositions.preserving(typed.selfPositions)
            precision = precision.preserving(typed.precision)
            advertInterval = advertInterval.preserving(typed.advertInterval)
            beaconInterval = beaconInterval.preserving(typed.beaconInterval)
            startupBeacon = startupBeacon.preserving(typed.startupBeacon)
            // The text forms follow their fields: kept while the operator's
            // edit stands, re-derived from the device otherwise.
            if typed.name.isDirty, name.isKnown { nameText = old.nameText }
            if typed.location.isDirty, location.isKnown {
                latitude = old.latitude
                longitude = old.longitude
            }
            if typed.altitude.isDirty, altitude.isKnown {
                altitudeText = old.altitudeText
            }
            // A local choice rather than a device value, so a reading
            // landing under the editor has nothing to say about it.
            manualPrecision = old.manualPrecision
        }

        /// Whether the device is keeping its own advertised position, in
        /// which case a write here would be refused.
        var isSelfPositioning: Bool { selfPositions.value == true }

        /// The grid a typed or picked position is encoded to: the device's
        /// own precision where it has one, and the local choice otherwise.
        ///
        /// Always a precision the encoding accepts. Deriving it from the
        /// byte count of whatever the device last reported cannot promise
        /// that — an unplaced device reports no bytes at all, which is a
        /// precision of zero and encodes nothing.
        var encodingPrecision: UInt8 { precision.value ?? manualPrecision }

        /// The place on screen, where both halves of one are on screen.
        var chosenCoordinate: CLLocationCoordinate2D? {
            guard let latitude = Double(latitude), let longitude = Double(longitude)
            else { return nil }
            return CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
        }

        /// Put a place into the coordinate fields, written out finely enough
        /// that the grid it was chosen on survives the round trip through
        /// text.
        mutating func place(latitude: Double, longitude: Double) {
            let digits = max(
                5,
                LocationPresentation.coordinateDecimals(
                    cellMeters: LocationPresentation.cellMeters(
                        precisionBytes: encodingPrecision
                    )
                )
            )
            let format = FloatingPointFormatStyle<Double>.number
                .precision(.fractionLength(digits))
                .grouping(.never)
            self.latitude = latitude.formatted(format)
            self.longitude = longitude.formatted(format)
        }

        var positionSummary: String {
            guard let bytes = location.value, !bytes.isEmpty else { return "None advertised" }
            let read = inspectUlcpProperties(
                responses: [
                    ulcpPropertyRecord(
                        propertyId: ulcpProperties.identLocation,
                        value: bytes
                    )
                ]
            )
            guard let latitude = read.identLatitudeDeg, let longitude = read.identLongitudeDeg
            else { return "None advertised" }
            return "\(Self.coordinate(latitude))°, \(Self.coordinate(longitude))°"
        }

        /// The typed position and name folded back in.
        private var typed: Edits {
            var typed = self
            typed.name.fold(nameText)
            // A position is only as good as both halves of it: one
            // coordinate typed and the other blank is a half-entered
            // place, and nothing about it is worth writing.
            if let latitude = Double(self.latitude), let longitude = Double(self.longitude) {
                typed.location.fold(
                    try? ulcpEncodeLocation(
                        latitudeDeg: latitude,
                        longitudeDeg: longitude,
                        precision: encodingPrecision
                    )
                )
            } else if self.latitude.isEmpty, self.longitude.isEmpty {
                typed.location.fold(Data())
            }
            typed.altitude.fold(.some(Int32(altitudeText)))
            return typed
        }

        var dirty: Set<UInt32> {
            let typed = self.typed
            var dirty: Set<UInt32> = []
            if typed.name.isDirty { dirty.insert(typed.name.property) }
            if typed.role.isDirty { dirty.insert(typed.role.property) }
            if typed.mobile.isDirty { dirty.insert(typed.mobile.property) }
            if typed.discoverable.isDirty { dirty.insert(typed.discoverable.property) }
            if typed.advertInterval.isDirty { dirty.insert(typed.advertInterval.property) }
            if typed.beaconInterval.isDirty { dirty.insert(typed.beaconInterval.property) }
            if typed.startupBeacon.isDirty { dirty.insert(typed.startupBeacon.property) }
            if typed.selfPositions.isDirty { dirty.insert(typed.selfPositions.property) }
            if typed.precision.isDirty { dirty.insert(typed.precision.property) }
            // A device keeping its own position would refuse both of
            // these, and turning that off in the same apply does not
            // change what it refuses — the write is judged against the
            // policy the device is holding when it arrives.
            if !isSelfPositioning, selfPositions.reported != true {
                if typed.location.isDirty { dirty.insert(typed.location.property) }
                if typed.altitude.isDirty { dirty.insert(typed.altitude.property) }
            }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            let typed = self.typed
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.deviceName = typed.name.value
            desired.identRole = typed.role.value ?? nil
            desired.identMobile = typed.mobile.value
            desired.devDiscoverable = typed.discoverable.value
            desired.identLocation = typed.location.value
            desired.identAltitudeM = typed.altitude.value ?? nil
            desired.gnssIdentUpdate = typed.selfPositions.value
            desired.gnssIdentPrecision = typed.precision.value
            desired.advertIntervalSeconds = typed.advertInterval.value
            desired.beaconIntervalSeconds = typed.beaconInterval.value
            desired.startupBeacon = typed.startupBeacon.value
            return desired
        }

        static func coordinate(_ degrees: Double) -> String {
            degrees.formatted(.number.precision(.fractionLength(5)).grouping(.never))
        }

        /// Every precision the location encoding accepts, asked of the core
        /// rather than written out here.
        static let precisions: [UInt8] = (UInt8.min ... UInt8.max).filter {
            LocationPresentation.cellMeters(precisionBytes: $0) != nil
        }

        /// What to place a device at when nothing else says: a cell fine
        /// enough to put it on a street and coarse enough not to put it in a
        /// room, matching the device's own post-reset precision.
        static let defaultPrecision: UInt8 = 5
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
    @State private var edits = Edits()
    @State private var newRegion = ""
    @State private var regionProblem: String?
    @State private var showsSuggestion = false
    /// Accepted in the suggestion sheet, adopted from its onDismiss.
    @State private var pendingSuggestion: MobileRegionOutcomeRecord?

    private var reading: RemoteCategoryReading? { model.readings[.repeater] }
    private var problems: [UInt32: String] { model.writeRefusals[.repeater] ?? [:] }

    var body: some View {
        Form {
            Section {
                if edits.enabled.isKnown {
                    Toggle(isOn: $edits.enabled.edited.replacingNil(with: false)) {
                        RemoteFieldTitle(
                            "Forward for others",
                            problem: problems[edits.enabled.property]
                        )
                    }
                } else {
                    RemoteReadOnlyToggle("Forward for others", isOn: nil)
                }
            } header: {
                Text("Forwarding")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            Section {
                ForEach(edits.regions.edited ?? [], id: \.self) { region in
                    Text(RegionCodeText.label(region: region))
                        .font(.body.monospaced())
                        // Adding animates the *blank input row* sliding down
                        // to its new slot, not the added row: the typed text
                        // is already sitting exactly where the new row lands,
                        // so fading the row in would flicker text the user
                        // just wrote. Insertion is therefore instant and the
                        // Form-level animation below moves everything else.
                        .transition(.asymmetric(insertion: .identity, removal: .opacity))
                }
                .onDelete { offsets in
                    var regions = edits.regions.edited ?? []
                    regions.remove(atOffsets: offsets)
                    edits.regions.edited = regions
                }
                if edits.regions.isKnown {
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
                    LabeledContent("Regions", value: "Not read")
                }
            } header: {
                Text("Flood regions")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    if let problem = problems[edits.regions.property] {
                        Text(problem).foregroundStyle(.red)
                    }
                    if let regionProblem {
                        Text(regionProblem).foregroundStyle(.red)
                    }
                    // An empty list meaning "everything" is the one thing
                    // here nobody would guess.
                    if edits.regions.edited?.isEmpty == true {
                        Text("With none listed, the device forwards every flood it hears.")
                    }
                }
            }

            Section {
                RemotePicker(
                    "Tag untagged floods",
                    selection: $edits.defaultRegion.edited,
                    problem: problems[edits.defaultRegion.property]
                ) {
                    Text("Leave untagged").tag(Data?.none)
                    // The device's own choice is offered whether or not it
                    // is still in the list above: deleting a region the
                    // device tags with should not leave the picker with
                    // nothing to show for what the device actually holds.
                    ForEach(edits.taggableRegions, id: \.self) { region in
                        if let code = try? regionCodeFromString(text: region) {
                            Text(RegionCodeText.label(region: region)).tag(Data?.some(code))
                        }
                    }
                }
            }

            Section {
                RemoteNumberField(
                    "Minimum RSSI",
                    unit: "dBm",
                    text: $edits.minRssiText,
                    isKnown: edits.minRssi.isKnown,
                    signed: true,
                    problem: problems[edits.minRssi.property]
                )
                RemoteNumberField(
                    "Minimum SNR",
                    unit: "dB",
                    text: $edits.minSnrText,
                    isKnown: edits.minSnr.isKnown,
                    signed: true,
                    problem: problems[edits.minSnr.property]
                )
            } header: {
                Text("Forwarding thresholds")
            } footer: {
                Text("Leave either empty for no threshold.")
            }
            RemoteProblemSection(model: model)
        }
        // A mutation of plain draft state animates nothing on its own (and a
        // withAnimation around it is lost to the same update's text-field
        // reset), so the Form animates whenever the region list changes.
        // With the rows' insertion transition set to .identity above, what
        // this actually animates is the reflow: the blank input row and
        // everything under it sliding down to make room.
        .animation(UMSHAnimation.list, value: edits.regions.edited)
        .remoteCategoryChrome(
            model: model,
            category: .repeater,
            title: "Repeater",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
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
                currentRegions: edits.regions.value ?? [],
                currentDefaultRegion: edits.defaultRegion.value ?? nil,
                sources: positionSources,
                // Over a local link the phone is at the device, so where it
                // is stands for where the device is — and is offered first,
                // being the freshest position either of them has. Across
                // the mesh it stands for nothing about the device.
                offersPhone: model.phoneStandsForDevice,
                refreshAdvertised: { await model.refreshCategory(.identity) },
                accept: { pendingSuggestion = $0 }
            )
        }
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

    /// Take a suggestion into the fields, marking dirty only what actually
    /// moved — so an outcome that changes the list but not the tag puts one
    /// property on the air, not two.
    private func adopt(_ outcome: MobileRegionOutcomeRecord) {
        edits.regions.edited = outcome.regions
        // A tag the device never reported takes nothing: with no baseline
        // to compare against it would stand permanently dirty, and Apply
        // would offer to write a value nobody entered.
        if edits.defaultRegion.isKnown {
            edits.defaultRegion.edited = .some(outcome.defaultRegion)
        }
    }

    /// Adopt what the suggestion sheet accepted, deferred to its dismissal
    /// so the rows arrive in an on-screen list instead of behind the sheet.
    private func adoptPendingSuggestion() {
        guard let outcome = pendingSuggestion else { return }
        pendingSuggestion = nil
        adopt(outcome)
    }

    /// Add the typed region, or respell one the list already holds.
    ///
    /// The device keeps one entry per region however it is capitalized, so
    /// the list follows the same rule rather than sending a write the
    /// device would collapse under us.
    private func addRegion() {
        let text = newRegion.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        guard RegionCodeText.code(of: text) != nil else {
            regionProblem = "That region name is too long. Use up to 24 characters — a short code like SJC or WA, a region name, or 0x followed by four hex digits."
            return
        }
        regionProblem = nil
        newRegion = ""
        var regions = edits.regions.edited ?? []
        if let index = RegionCodeText.index(of: text, in: regions) {
            regions[index] = text
        } else {
            regions.append(text)
        }
        edits.regions.edited = regions
    }

    private func apply() async {
        // Only rebuilt when the device answered: see RemoteGnssScreen.
        if await model.apply(.repeater, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.repeater])
        }
    }

    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var regions = RemoteField<[String]>(0, nil)
        var defaultRegion = RemoteField<Data?>(0, nil)
        var minRssi = RemoteField<Int16?>(0, nil)
        var minSnr = RemoteField<Int8?>(0, nil)
        var minRssiText = ""
        var minSnrText = ""
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            let read = { (property: UInt32) in
                reading?.propertyIDs.contains(property) == true
                    && reading?.refused.contains(property) != true
            }
            enabled = RemoteField(id.repeaterEnabled, held.repeaterEnabled)
            regions = RemoteField(id.repeaterRegions, held.repeaterRegions)
            // Empty is "never tag" and "no threshold": values in their own
            // right, told apart from never having been read by whether the
            // device answered for the property at all.
            defaultRegion = RemoteField(
                id.repeaterDefaultRegion,
                read(id.repeaterDefaultRegion) ? .some(held.repeaterDefaultRegion) : nil
            )
            minRssi = RemoteField(
                id.repeaterMinRssi,
                read(id.repeaterMinRssi) ? .some(held.repeaterMinRssiDbm) : nil
            )
            minSnr = RemoteField(
                id.repeaterMinSnr,
                read(id.repeaterMinSnr) ? .some(held.repeaterMinSnrDb) : nil
            )
            minRssiText = held.repeaterMinRssiDbm.map(String.init) ?? ""
            minSnrText = held.repeaterMinSnrDb.map(String.init) ?? ""
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edits carried over field by field — see
        /// ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            let typed = old.typed
            enabled = enabled.preserving(typed.enabled)
            regions = regions.preserving(typed.regions)
            defaultRegion = defaultRegion.preserving(typed.defaultRegion)
            minRssi = minRssi.preserving(typed.minRssi)
            minSnr = minSnr.preserving(typed.minSnr)
            // The text forms follow their fields: kept while the operator's
            // edit stands, re-derived from the device otherwise.
            if typed.minRssi.isDirty, minRssi.isKnown { minRssiText = old.minRssiText }
            if typed.minSnr.isDirty, minSnr.isKnown { minSnrText = old.minSnrText }
        }

        /// The regions the default-tag picker can offer: those listed, plus
        /// whatever the device is already tagging with.
        var taggableRegions: [String] {
            var listed = regions.edited ?? []
            if let code = defaultRegion.value ?? nil,
               let held = try? regionCodeDescription(code: code),
               !listed.contains(held) {
                listed.append(held)
            }
            return listed
        }

        private var typed: Edits {
            var typed = self
            typed.minRssi.fold(.some(Int16(minRssiText)))
            typed.minSnr.fold(.some(Int8(minSnrText)))
            return typed
        }

        var dirty: Set<UInt32> {
            let typed = self.typed
            var dirty: Set<UInt32> = []
            if typed.enabled.isDirty { dirty.insert(typed.enabled.property) }
            if typed.regions.isDirty { dirty.insert(typed.regions.property) }
            if typed.defaultRegion.isDirty { dirty.insert(typed.defaultRegion.property) }
            if typed.minRssi.isDirty { dirty.insert(typed.minRssi.property) }
            if typed.minSnr.isDirty { dirty.insert(typed.minSnr.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            let typed = self.typed
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.repeaterEnabled = typed.enabled.value
            desired.repeaterRegions = typed.regions.value
            desired.repeaterDefaultRegion = typed.defaultRegion.value ?? nil
            desired.repeaterMinRssiDbm = typed.minRssi.value ?? nil
            desired.repeaterMinSnrDb = typed.minSnr.value ?? nil
            return desired
        }
    }
}

// MARK: - Shared controls

/// A row's title, turned red and explained when the device rejected the
/// value the operator offered for it.
struct RemoteFieldTitle: View {
    let title: String
    let problem: String?

    init(_ title: String, problem: String?) {
        self.title = title
        self.problem = problem
    }

    var body: some View {
        if let problem {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(.red)
                Text(problem).font(.caption).foregroundStyle(.red)
            }
        } else {
            Text(title)
        }
    }
}

/// A typed setting, editable only once the device has said what it holds.
struct RemoteNumberField: View {
    let title: String
    let unit: String
    @Binding var text: String
    let isKnown: Bool
    var signed = false
    var decimal = false
    var problem: String?

    init(
        _ title: String,
        unit: String,
        text: Binding<String>,
        isKnown: Bool,
        signed: Bool = false,
        decimal: Bool = false,
        problem: String? = nil
    ) {
        self.title = title
        self.unit = unit
        _text = text
        self.isKnown = isKnown
        self.signed = signed
        self.decimal = decimal
        self.problem = problem
    }

    var body: some View {
        if isKnown {
            LabeledContent {
                HStack(spacing: 5) {
                    TextField(title, text: $text)
                        .keyboardType(
                            signed || decimal ? .numbersAndPunctuation : .numberPad
                        )
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel("\(title) in \(unit)")
                    Text(unit).foregroundStyle(.secondary)
                }
            } label: {
                RemoteFieldTitle(title, problem: problem)
            }
        } else {
            LabeledContent(title, value: "Not read")
        }
    }
}

/// A chosen setting, editable only once the device has said what it holds.
struct RemotePicker<Value: Hashable & Sendable, Content: View>: View {
    let title: String
    /// What the device holds, which is also where an edit goes. Nil until
    /// the device has said, which is when this goes read-only.
    @Binding var selection: Value?
    var problem: String?
    @ViewBuilder let content: () -> Content

    init(
        _ title: String,
        selection: Binding<Value?>,
        problem: String? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        _selection = selection
        self.problem = problem
        self.content = content
    }

    var body: some View {
        if let value = selection {
            Picker(selection: $selection.replacingNil(with: value), content: content) {
                RemoteFieldTitle(title, problem: problem)
            }
        } else {
            LabeledContent(title, value: "Not read")
        }
    }
}

/// A vetted PHY configuration a whole mesh can agree on.
///
/// The list comes from the shared table the firmware ships its own
/// defaults from, so a device commissioned here and the phone's own radio
/// cannot end up describing the same profile differently.
struct RadioPreset: Identifiable {
    let id: String
    let name: String
    let frequencyKHz: UInt32
    /// Nil where the profile has no vetted power, in which case adopting
    /// it leaves whatever the device is set to alone.
    let transmitPowerDBm: Int8?
    let bandwidthHz: UInt32
    let spreadingFactor: UInt8
    let codingRate: UInt8
    let dutyCycleLimit: UInt16

    /// Whether a node on this preset and one on `profile` can hear each
    /// other — the same exclusion of power and the transmit limit that
    /// ``RadioProfile/interoperates(with:)`` makes.
    func interoperates(with profile: RadioProfile) -> Bool {
        profile.frequencyKHz == frequencyKHz
            && profile.bandwidthHz == bandwidthHz
            && profile.spreadingFactor == spreadingFactor
            && profile.codingRateDenominator == codingRate
    }

    static let vetted: [RadioPreset] = ulcpRadioPresets().map { preset in
        RadioPreset(
            id: preset.id,
            name: preset.name,
            frequencyKHz: preset.frequencyKhz,
            transmitPowerDBm: preset.transmitPowerDbm,
            bandwidthHz: preset.bandwidthHz,
            spreadingFactor: preset.spreadingFactor,
            codingRate: preset.codingRateDenom,
            dutyCycleLimit: preset.dutyCycleLimit
        )
    }
}
