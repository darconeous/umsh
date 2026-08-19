import SwiftUI
import UMSHMobileCore

/// One editable setting: what the device last said, and what the operator
/// has made of it.
///
/// A field the device has never answered for stays `nil` and renders as
/// read-only. That is not squeamishness: several of these travel in
/// whole-write groups, so writing one means stating all of them, and a
/// modem profile assembled half from a device and half from a default is a
/// device left on a configuration nobody chose.
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
    /// What to write: the edit, falling back to what the device already
    /// holds so a whole-write group can state its untouched members.
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

    var body: some View {
        Form {
            Section {
                if edits.enabled.isKnown {
                    Toggle("Radio enabled", isOn: $edits.enabled.edited.replacingNil(with: true))
                } else {
                    RemoteReadOnlyToggle("Radio enabled", isOn: nil)
                }
                RemoteNumberField(
                    "Frequency",
                    unit: "kHz",
                    text: $edits.frequency,
                    isKnown: edits.frequencyField.isKnown
                )
                RemoteNumberField(
                    "Transmit power",
                    unit: "dBm",
                    text: $edits.transmitPower,
                    isKnown: edits.transmitPowerField.isKnown,
                    signed: true
                )
            } header: {
                Text("Radio")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            if model.card?.supportsLora == true {
                Section {
                    RemotePicker("Bandwidth", selection: $edits.bandwidth.edited) {
                        ForEach(Self.bandwidths, id: \.self) { hertz in
                            Text(Self.bandwidthLabel(hertz)).tag(hertz)
                        }
                    }
                    RemotePicker("Spreading factor", selection: $edits.spreadingFactor.edited) {
                        ForEach(UInt8(5) ... UInt8(12), id: \.self) { Text("SF\($0)").tag($0) }
                    }
                    RemotePicker("Coding rate", selection: $edits.codingRate.edited) {
                        ForEach(UInt8(5) ... UInt8(8), id: \.self) { Text("4/\($0)").tag($0) }
                    }
                } header: {
                    Text("Modem profile")
                }
            }

            if model.card?.supportsDutyCycleLimit == true {
                Section {
                    if let used = reading?.properties.dutyCycleNow {
                        LabeledContent("Past-hour usage", value: Self.dutyLabel(used))
                    }
                    RemotePicker("Transmit limit", selection: $edits.dutyLimit.edited) {
                        ForEach(Self.dutyLimits, id: \.self) { limit in
                            Text(
                                limit == UInt16.max ? "Disabled" : Self.dutyLabel(limit)
                            ).tag(limit)
                        }
                    }
                } header: {
                    Text("Duty cycle")
                }
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .radio,
            title: "Radio",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty,
            applyWarning: (
                title: "Change This Device's Radio",
                message: """
                    A device left on a frequency or modem profile the rest of \
                    the mesh is not using cannot be reached to change back.
                    """
            )
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
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

        /// The typed fields folded back in, so both kinds of edit are
        /// compared the same way.
        private var typed: Edits {
            var typed = self
            typed.frequencyField.fold(UInt32(frequency))
            typed.transmitPowerField.fold(Int8(transmitPower))
            return typed
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
            // Based on what the device last reported, not on nothing: a
            // whole-write group can reach across screens, and its members
            // over on another one still have to be stated. Only the dirty
            // set and its groups are written, so carrying the rest here
            // cannot write anything stale back.
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

    private static let bandwidths: [UInt32] = [
        7_810, 10_420, 15_630, 20_830, 31_250, 41_670, 62_500, 125_000, 250_000, 500_000,
    ]
    /// The same fractions of `UInt16.max` the local editor offers.
    private static let dutyLimits: [UInt16] = [UInt16.max, 13_107, 6_553, 655, 65]

    private static func bandwidthLabel(_ hertz: UInt32) -> String {
        (Double(hertz) / 1000).formatted(.number.precision(.fractionLength(hertz < 100_000 ? 2 : 0)))
            + " kHz"
    }

    private static func dutyLabel(_ value: UInt16) -> String {
        let percent = Double(value) * 100 / Double(UInt16.max)
        return percent.formatted(.number.precision(.fractionLength(percent < 1 ? 2 : 1))) + "%"
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
    @State private var edits = Edits()

    private var reading: RemoteCategoryReading? { model.readings[.identity] }

    var body: some View {
        Form {
            if model.card?.supportsDeviceName == true {
                Section {
                    if edits.name.isKnown {
                        TextField("Name", text: $edits.nameText)
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
                    RemotePicker("Role", selection: $edits.role.edited) {
                        Text("Derive from what it does").tag(UInt8?.none)
                        ForEach(PeerRole.selectable) { role in
                            Text(role.label).tag(role.roleCode)
                        }
                    }
                    if edits.mobile.isKnown {
                        Toggle("Device moves around", isOn: $edits.mobile.edited.replacingNil(with: false))
                    } else {
                        RemoteReadOnlyToggle("Device moves around", isOn: nil)
                    }
                    if model.card?.supportsDeviceIdentity == true {
                        if edits.discoverable.isKnown {
                            Toggle("Discoverable", isOn: $edits.discoverable.edited.replacingNil(with: false))
                        } else {
                            RemoteReadOnlyToggle("Discoverable", isOn: nil)
                        }
                    }
                }

                positionSection
            }

            if model.card?.supportsAdvert == true {
                Section {
                    RemotePicker("Beacon", selection: $edits.beaconInterval.edited) {
                        ForEach(beaconIntervalChoices, id: \.self) {
                            Text(formattedAnnouncementInterval($0)).tag($0)
                        }
                    }
                    RemotePicker("Identity", selection: $edits.advertInterval.edited) {
                        ForEach(advertisementIntervalChoices, id: \.self) {
                            Text(formattedAnnouncementInterval($0)).tag($0)
                        }
                    }
                    if edits.startupBeacon.isKnown {
                        Toggle("Beacon at startup", isOn: $edits.startupBeacon.edited.replacingNil(with: false))
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
        .onChange(of: reading?.asOf) { edits = Edits(reading) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
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
                    decimal: true
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
                    signed: true
                )
            }
            if model.card?.supportsGnss == true {
                if edits.selfPositions.isKnown {
                    Toggle(
                        "Update position from GNSS",
                        isOn: $edits.selfPositions.edited.replacingNil(with: false)
                    )
                } else {
                    RemoteReadOnlyToggle("Update position from GNSS", isOn: nil)
                }
                RemotePicker("Reported precision", selection: $edits.precision.edited) {
                    ForEach(UInt8(1) ... UInt8(7), id: \.self) { precision in
                        Text(Self.precisionLabel(precision)).tag(precision)
                    }
                }
            }
        } header: {
            Text("Position")
        } footer: {
            // Only the read-only case needs saying: the rows have gone
            // uneditable and the reason is not on screen.
            if edits.isSelfPositioning {
                Text("Turn this off to place the device by hand.")
            }
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
            isEmpty = reading == nil
        }

        /// Whether the device is keeping its own advertised position, in
        /// which case a write here would be refused.
        var isSelfPositioning: Bool { selfPositions.value == true }

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
                        precision: precision.value ?? UInt8(location.reported?.count ?? 4)
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
            // Based on what the device last reported, not on nothing: a
            // whole-write group can reach across screens, and its members
            // over on another one still have to be stated. Only the dirty
            // set and its groups are written, so carrying the rest here
            // cannot write anything stale back.
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
    }

    /// A precision named by the area it discloses, which is the only thing
    /// about it a person can weigh.
    static func precisionLabel(_ precision: UInt8) -> String {
        guard let meters = ulcpLocationCellMeters(precisionBytes: precision) else {
            return "\(precision) bytes"
        }
        if meters >= 1_000 {
            return "\((meters / 1_000).formatted(.number.precision(.fractionLength(0)))) km"
        }
        return "\(meters.formatted(.number.precision(.fractionLength(meters < 10 ? 1 : 0)))) m"
    }
}

// MARK: - Repeater

/// Whether and what this device forwards for the rest of the mesh.
struct RemoteRepeaterEditor: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()
    @State private var newRegion = ""

    private var reading: RemoteCategoryReading? { model.readings[.repeater] }

    var body: some View {
        Form {
            Section {
                if edits.enabled.isKnown {
                    Toggle("Forward for others", isOn: $edits.enabled.edited.replacingNil(with: false))
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
                    Text(region)
                }
                .onDelete { offsets in
                    var regions = edits.regions.edited ?? []
                    regions.remove(atOffsets: offsets)
                    edits.regions.edited = regions
                }
                if edits.regions.isKnown {
                    HStack {
                        TextField("Add a region", text: $newRegion)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.characters)
                        Button("Add") {
                            var regions = edits.regions.edited ?? []
                            regions.append(newRegion)
                            edits.regions.edited = regions
                            newRegion = ""
                        }
                        .disabled(
                            newRegion.isEmpty
                                || (edits.regions.edited ?? []).contains(newRegion)
                        )
                    }
                } else {
                    LabeledContent("Regions", value: "Not read")
                }
            } header: {
                Text("Flood regions")
            } footer: {
                // An empty list meaning "everything" is the one thing here
                // nobody would guess.
                if edits.regions.edited?.isEmpty == true {
                    Text("With none listed, the device forwards every flood it hears.")
                }
            }

            Section {
                RemotePicker("Tag untagged floods", selection: $edits.defaultRegion.edited) {
                    Text("Leave untagged").tag(Data?.none)
                    // The device's own choice is offered whether or not it
                    // is still in the list above: deleting a region the
                    // device tags with should not leave the picker with
                    // nothing to show for what the device actually holds.
                    ForEach(edits.taggableRegions, id: \.self) { region in
                        if let code = try? regionCodeFromString(text: region) {
                            Text(region).tag(Data?.some(code))
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
                    signed: true
                )
                RemoteNumberField(
                    "Minimum SNR",
                    unit: "dB",
                    text: $edits.minSnrText,
                    isKnown: edits.minSnr.isKnown,
                    signed: true
                )
            } header: {
                Text("Forwarding thresholds")
            } footer: {
                Text("Leave either empty for no threshold.")
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .repeater,
            title: "Repeater",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
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
            // Based on what the device last reported, not on nothing: a
            // whole-write group can reach across screens, and its members
            // over on another one still have to be stated. Only the dirty
            // set and its groups are written, so carrying the rest here
            // cannot write anything stale back.
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

/// A typed setting, editable only once the device has said what it holds.
struct RemoteNumberField: View {
    let title: String
    let unit: String
    @Binding var text: String
    let isKnown: Bool
    var signed = false
    var decimal = false

    init(
        _ title: String,
        unit: String,
        text: Binding<String>,
        isKnown: Bool,
        signed: Bool = false,
        decimal: Bool = false
    ) {
        self.title = title
        self.unit = unit
        _text = text
        self.isKnown = isKnown
        self.signed = signed
        self.decimal = decimal
    }

    var body: some View {
        if isKnown {
            LabeledContent(title) {
                HStack(spacing: 5) {
                    TextField(title, text: $text)
                        .keyboardType(
                            signed || decimal ? .numbersAndPunctuation : .numberPad
                        )
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel("\(title) in \(unit)")
                    Text(unit).foregroundStyle(.secondary)
                }
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
    @ViewBuilder let content: () -> Content

    init(
        _ title: String,
        selection: Binding<Value?>,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        _selection = selection
        self.content = content
    }

    var body: some View {
        if let value = selection {
            Picker(title, selection: $selection.replacingNil(with: value), content: content)
        } else {
            LabeledContent(title, value: "Not read")
        }
    }
}
