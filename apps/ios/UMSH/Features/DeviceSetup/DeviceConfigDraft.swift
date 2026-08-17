import Foundation
import UMSHMobileCore

/// What one administered device is about to be told, and the write that
/// tells it.
///
/// A second deliberate exception to the app's no-view-model rule, on the same
/// grounds as `AdminFlowController`: this is not view state. It is the desired
/// configuration of one device, edited across more than one pushed screen, and
/// it owns the write and the readback check. Holding it as `@State` in a
/// navigation destination is what silently forks it in two, because a
/// destination closure is re-invoked and its state is keyed to the pushed
/// value.
///
/// The whole draft is written as one record: Rust owns the ordering — the PHY
/// is disabled first and re-enabled last, and the save rides the tail — so a
/// device is never left running half a configuration.
@MainActor
@Observable
final class DeviceConfigDraft {
    /// What the device reported when it attached. The authority on what it can
    /// be told: capabilities do not change mid-session, so every capability
    /// gate reads this.
    let sync: UlcpSyncRecord
    /// What the device reports *now*, replaced by each readback, so a label
    /// derived from the device's own state is not stale after a write.
    private(set) var reported: UlcpSyncRecord
    /// What this device is being set up as, and everything that follows from
    /// it: which values the goal forced, whether the clock is part of applying,
    /// and whether the result is reported in a modal or on the form.
    let plan: DeviceSetupPlan
    /// Where the PHY on this draft came from, on a sheet that decided it.
    /// Nil in the editor, which asks about every radio parameter directly.
    let resolvedProfile: ResolvedRadioProfile?
    /// Whether the profile is settled. False only while a sheet is waiting for
    /// a choice it could not make on the operator's behalf.
    private(set) var profileChosen: Bool

    // MARK: - Editable configuration

    var deviceName: String
    var radioEnabled: Bool
    // Touching any radio *parameter* settles an outstanding profile choice —
    // whether it was settled by picking a preset or by typing a frequency is
    // not a distinction worth keeping, and `didSet` catches both without the
    // bindings having to know they are being watched. The switch above is not
    // one of them: it says whether the radio transmits, not what it transmits,
    // and every setup goal turns it on regardless.
    var frequencyKHz: String { didSet { profileChosen = true } }
    var transmitPowerDBm: String { didSet { profileChosen = true } }
    var bandwidthHz: UInt32 { didSet { profileChosen = true } }
    var spreadingFactor: UInt8 { didSet { profileChosen = true } }
    var codingRate: UInt8 { didSet { profileChosen = true } }
    var dutyCycleLimit: UInt16 { didSet { profileChosen = true } }
    var identRole: UInt8?
    var identMobile: Bool
    var devDiscoverable: Bool
    var repeaterEnabled: Bool
    var regions: [String]
    var defaultRegion: Data?
    var minRssiDBm: Int16?
    var minSnrDB: Int8?
    var timeZoneOffsetMinutes: Int16
    var gnssEnabled: Bool
    var gnssIdentUpdate: Bool
    var gnssIdentPrecision: UInt8
    var gnssTimeTrust: Bool
    var advertIntervalSeconds: UInt32
    var beaconIntervalSeconds: UInt32
    var startupBeacon: Bool
    /// Node public keys the device will take orders from, in the order it
    /// reported them.
    ///
    /// Not part of `configuration`: the list is a table the device edits an
    /// item at a time and persists on its own, where the record states a
    /// whole configuration written in one pass. It is applied alongside,
    /// not inside.
    var adminKeys: [Data]
    /// The list as the device last reported it, so applying knows what to
    /// add and what to take away.
    private(set) var reportedAdminKeys: [Data]
    /// This phone's own node key, when the app knows it. Nil leaves the
    /// list editable and the phone simply not on it.
    let phoneNodeKey: Data?

    // MARK: - Write state

    private(set) var isSaving = false
    /// The configuration the device confirmed, as the draft ended up holding
    /// it. Kept rather than a flag so that adopting a value the device
    /// reported back does not read as an unsaved edit, and so any real edit
    /// after a write clears the confirmation on its own.
    private(set) var appliedConfiguration: UlcpDeviceConfigRecord?
    private(set) var verificationProblem: String?

    var applied: Bool {
        appliedConfiguration != nil
            && appliedConfiguration == configuration
            && Set(adminKeys) == Set(reportedAdminKeys)
    }

    /// How a setup sheet's write is going, or nil when there is nothing to
    /// report. A write that did not land resolves to nil rather than to a
    /// state of its own: the reason is already on the form, and a modal
    /// repeating it is one more thing to dismiss before acting on it.
    private(set) var applyPhase: ApplyPhase?

    enum ApplyPhase: Equatable {
        case applying
        case succeeded
        /// Configured, but the device would not take the clock. It is set up;
        /// the editor's clock button is one tap away.
        case succeededWithoutClock
        /// Saved, and then reported something back differently. Not a
        /// congratulation — the field is named so it can be looked at.
        case reportedDifferently(field: String)
    }

    /// Whether the result is on screen. Settable so a sheet can bind to it;
    /// dismissing clears the phase, and nothing else can be set from outside.
    var isPresentingResult: Bool {
        get { applyPhase != nil }
        set { if !newValue { applyPhase = nil } }
    }

    /// The writer strictly outlives this draft, because it owns it. Holding it
    /// strongly would make a controller → draft → controller cycle and leak
    /// the BLE session — the exact failure the controller exists to prevent.
    private unowned let writer: any DeviceConfigurationWriting

    init(
        sync: UlcpSyncRecord,
        reportedName: String?,
        plan: DeviceSetupPlan,
        resolvedProfile: ResolvedRadioProfile?,
        phoneNodeKey: Data? = nil,
        writer: any DeviceConfigurationWriting
    ) {
        self.sync = sync
        self.reported = sync
        self.plan = plan
        self.resolvedProfile = resolvedProfile
        self.profileChosen = resolvedProfile?.requiresChoice != true
        self.phoneNodeKey = phoneNodeKey
        self.writer = writer
        let admins = sync.devAdminKeys ?? []
        adminKeys = admins
        reportedAdminKeys = admins

        let repeater = sync.repeater
        deviceName = reportedName ?? ""
        radioEnabled = sync.phyEnabled
        frequencyKHz = String(sync.frequencyKhz)
        transmitPowerDBm = String(sync.transmitPowerDbm)
        bandwidthHz = sync.bandwidthHz ?? 125_000
        spreadingFactor = sync.spreadingFactor ?? 9
        codingRate = sync.codingRateDenom ?? 5
        dutyCycleLimit = sync.dutyCycleLimit ?? UInt16.max
        identRole = sync.identRole
        identMobile = sync.identMobile ?? false
        devDiscoverable = sync.devDiscoverable ?? true
        repeaterEnabled = repeater?.enabled ?? false
        regions = repeater?.regions ?? []
        defaultRegion = repeater?.defaultRegion
        minRssiDBm = repeater?.minRssiDbm
        minSnrDB = repeater?.minSnrDb
        // A device with no zone set is one nobody has told where it is,
        // and the phone doing the setup is standing next to it. A goal that
        // assumes the phone's zone overrides this below; a device that already
        // holds one keeps it.
        timeZoneOffsetMinutes = sync.tzOffsetMin ?? phoneUTCOffsetMinutes
        let gnss = sync.gnss
        gnssEnabled = gnss?.enabled ?? false
        gnssIdentUpdate = gnss?.identUpdate ?? false
        gnssIdentPrecision = gnss?.identPrecision ?? 5
        gnssTimeTrust = gnss?.timeTrust ?? true
        let advert = sync.advert
        advertIntervalSeconds = advert?.advertIntervalSeconds ?? 4 * 3600
        beaconIntervalSeconds = advert?.beaconIntervalSeconds ?? 3600
        startupBeacon = advert?.startupBeacon ?? true

        // The goal's decisions land on top of the device's own settings, and
        // only where the device can honour them. Everything the goal does not
        // decide stays as the device reported it.
        if let copied = resolvedProfile?.copiedProfile { adopt(copied) }
        for assumption in plan.assumptions where assumption.applies(to: sync) {
            assumption.force(self)
        }
    }

    // MARK: - Unreadable settings

    // A device can advertise a capability and still refuse the properties
    // behind it — firmware older than the capability it reports. Rust leaves
    // those settings out of the snapshot and out of the write, so the form
    // hides them rather than showing a default that reads as the device's own
    // value and edits that would silently go nowhere.

    /// The modem profile is one setting in three properties: a device that
    /// reported only part of it has not reported it.
    var showsLoRa: Bool {
        sync.supportsLora
            && sync.bandwidthHz != nil
            && sync.spreadingFactor != nil
            && sync.codingRateDenom != nil
    }

    /// Mobility stands in for the whole advertised identity — the role alone
    /// cannot be told apart, because an empty role is also the device saying
    /// it derives its own.
    var showsIdentity: Bool { sync.supportsIdent && sync.identMobile != nil }

    var showsDiscoverable: Bool {
        sync.supportsDeviceIdentity && sync.devDiscoverable != nil
    }

    /// The forwarding policy is one setting in five properties, and a device
    /// that reported none of them has an unknown policy this form must not
    /// write over.
    var showsRepeater: Bool { sync.supportsRepeater && sync.repeater != nil }

    /// The positioning policy is one setting in four properties: a device that
    /// reported only part of it has not reported it.
    var showsPositioning: Bool { sync.supportsGnss && sync.gnss != nil }

    /// Likewise the announcement schedule, which is three properties.
    var showsAnnouncements: Bool { sync.supportsAdvert && sync.advert != nil }

    /// The zone alone. A device that would not report it can still be given a
    /// clock, so only the picker hides — the section stays.
    var showsTimeZone: Bool { sync.supportsTime && sync.tzOffsetMin != nil }

    var showsDutyCycleLimit: Bool {
        sync.supportsDutyCycleLimit && sync.dutyCycleLimit != nil
    }

    /// A device that would not report the list it holds is one this form
    /// must not edit: every change would be a guess about what it is
    /// writing over, and this is the list that decides who can change the
    /// device at all.
    var showsAdmins: Bool { sync.supportsAdmin && sync.devAdminKeys != nil }

    /// A preset sets every radio parameter at once, so it is only offered when
    /// every parameter it sets is one this device will accept.
    var showsPresets: Bool {
        (showsLoRa || !sync.supportsLora)
            && (sync.dutyCycleLimit != nil || !sync.supportsDutyCycleLimit)
    }

    /// What the device would not report, named the way the form names it.
    var unreadableSettings: [String] {
        var settings: [String] = []
        if sync.supportsLora, !showsLoRa { settings.append("its modem settings") }
        if sync.supportsDutyCycleLimit, sync.dutyCycleLimit == nil {
            settings.append("its transmit limit")
        }
        if sync.supportsIdent, !showsIdentity { settings.append("its advertised identity") }
        if sync.supportsDeviceIdentity, !showsDiscoverable { settings.append("discoverability") }
        if sync.supportsRepeater, sync.repeater == nil { settings.append("its forwarding policy") }
        if sync.supportsGnss, !showsPositioning { settings.append("its positioning settings") }
        if sync.supportsAdvert, !showsAnnouncements {
            settings.append("what it announces on its own")
        }
        if sync.supportsTime, !showsTimeZone { settings.append("its time zone") }
        if sync.supportsAdmin, !showsAdmins { settings.append("who may manage it remotely") }
        return settings
    }

    // MARK: - Administrators

    /// The administrator list, named as well as this phone can name it.
    var administrators: [DeviceAdministrator] {
        adminKeys.map {
            DeviceAdministrator(publicKey: $0, isThisPhone: $0 == phoneNodeKey)
        }
    }

    /// Whether this phone is on the list, which is the whole of whether it
    /// can manage this device once it is out of Bluetooth range.
    var phoneAdministers: Bool {
        guard let phoneNodeKey else { return false }
        return adminKeys.contains(phoneNodeKey)
    }

    /// Put this phone on the device's administrator list, or take it off.
    /// Does nothing on a phone whose own node key is not known, and never
    /// pushes the list past what the device will hold.
    func setPhoneAdministers(_ administers: Bool) {
        guard let phoneNodeKey else { return }
        if administers {
            add(administrator: phoneNodeKey)
        } else {
            adminKeys.removeAll { $0 == phoneNodeKey }
        }
    }

    /// Let one more node manage this device. Idempotent, and bounded by
    /// what the device will hold — the device's own refusal stays
    /// authoritative, but a form that offers a ninth entry only to have it
    /// rejected is a form that wasted the operator's time.
    func add(administrator publicKey: Data) {
        guard !adminKeys.contains(publicKey), adminKeys.count < deviceAdminCapacity else {
            return
        }
        adminKeys.append(publicKey)
    }

    var administratorListFull: Bool { adminKeys.count >= deviceAdminCapacity }

    // MARK: - Derived state

    /// What the device will tell the mesh it is, which is derived when no role
    /// is configured: a forwarding node is a repeater, anything else is a
    /// tracker.
    var advertisedRole: String {
        guard let identRole else {
            return repeaterEnabled && sync.supportsRepeater ? "Repeater" : "Tracker"
        }
        return PeerRole.label(forCode: identRole)
    }

    /// What the device advertises *today*, from its reported settings rather
    /// than the unsaved draft — a peer record must not be filed under a role
    /// the device has not been given yet.
    var advertisedPeerRole: PeerRole {
        guard let role = reported.identRole else {
            return reported.repeater?.enabled == true ? .repeater : .unknown
        }
        return PeerRole(roleCode: role)
    }

    /// The device presented as an ordinary node, so it can be shown through
    /// the shared peer screen. There is no stored row behind it — that is
    /// precisely what the save action on that screen is for.
    func administeredPeer(_ identity: MeshPublicIdentity, name: String?) -> PeerSummary {
        PeerSummary(
            id: 0,
            identity: identity,
            alias: nil,
            advertisedName: name,
            systemRole: nil,
            storedRole: advertisedPeerRole
        )
    }

    var configuration: UlcpDeviceConfigRecord? {
        guard let frequency = UInt32(frequencyKHz), frequency > 0,
              let power = Int8(transmitPowerDBm)
        else { return nil }
        let trimmedName = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        if sync.supportsDeviceName,
           trimmedName.isEmpty || trimmedName.utf8.count > 64 || trimmedName.contains("\0") {
            return nil
        }
        return UlcpDeviceConfigRecord(
            radio: UlcpRadioSettingsRecord(
                deviceName: sync.supportsDeviceName ? trimmedName : nil,
                phyEnabled: radioEnabled,
                frequencyKhz: frequency,
                transmitPowerDbm: power,
                bandwidthHz: sync.supportsLora ? bandwidthHz : nil,
                spreadingFactor: sync.supportsLora ? spreadingFactor : nil,
                codingRateDenom: sync.supportsLora ? codingRate : nil,
                dutyCycleLimit: sync.supportsDutyCycleLimit ? dutyCycleLimit : nil
            ),
            // Every optional here has to match what the device advertised:
            // sending a domain it does not have, or omitting one it does, is
            // a client bug and Rust rejects it before anything is written.
            identRole: sync.supportsIdent ? identRole : nil,
            identMobile: sync.supportsIdent ? identMobile : nil,
            devDiscoverable: sync.supportsDeviceIdentity ? devDiscoverable : nil,
            repeater: sync.supportsRepeater
                ? UlcpRepeaterSettingsRecord(
                    enabled: repeaterEnabled,
                    regions: regions,
                    defaultRegion: defaultRegion,
                    minRssiDbm: minRssiDBm,
                    minSnrDb: minSnrDB
                )
                : nil,
            tzOffsetMin: sync.supportsTime ? timeZoneOffsetMinutes : nil,
            gnss: sync.supportsGnss
                ? UlcpGnssSettingsRecord(
                    enabled: gnssEnabled,
                    identUpdate: gnssIdentUpdate,
                    identPrecision: gnssIdentPrecision,
                    timeTrust: gnssTimeTrust
                )
                : nil,
            advert: sync.supportsAdvert
                ? UlcpAdvertSettingsRecord(
                    advertIntervalSeconds: advertIntervalSeconds,
                    beaconIntervalSeconds: beaconIntervalSeconds,
                    startupBeacon: startupBeacon
                )
                : nil
        )
    }

    /// The vetted profile the radio fields currently spell out, or "custom".
    ///
    /// Settable, so a picker binds straight to it: choosing a profile writes
    /// every radio parameter it names.
    var presetIdentifier: String {
        get {
            RadioPreset.vetted.first { matches($0) }?.id ?? "custom"
        }
        set {
            guard let preset = RadioPreset.vetted.first(where: { $0.id == newValue }) else {
                return
            }
            adopt(preset)
        }
    }

    /// The name of the vetted profile the radio fields spell out, if any.
    var presetName: String? {
        RadioPreset.vetted.first { $0.id == presetIdentifier }?.name
    }

    /// Those fields as one line, for a row that names a profile rather than
    /// listing it. The power is in it deliberately: a profile copied from a
    /// handheld carries the handheld's power, and a repeater going up a mast
    /// wants that visible.
    var profileSummary: String {
        var parts: [String] = []
        if let frequency = UInt32(frequencyKHz) {
            let megahertz = Double(frequency) / 1_000
            parts.append("\(megahertz.formatted(.number.precision(.fractionLength(0...3)))) MHz")
        }
        if showsLoRa {
            parts.append("\(formattedBandwidth(bandwidthHz)) BW")
            parts.append("SF\(spreadingFactor)")
            parts.append("4/\(codingRate)")
        }
        parts.append("\(transmitPowerDBm) dBm")
        return parts.joined(separator: " · ")
    }

    private func formattedBandwidth(_ hertz: UInt32) -> String {
        let kilohertz = Double(hertz) / 1_000
        return "\(kilohertz.formatted(.number.precision(.fractionLength(0...2)))) kHz"
    }

    func adopt(_ preset: RadioPreset) {
        radioEnabled = true
        frequencyKHz = String(preset.frequencyKHz)
        transmitPowerDBm = String(preset.transmitPowerDBm)
        bandwidthHz = preset.bandwidthHz
        spreadingFactor = preset.spreadingFactor
        codingRate = preset.codingRate
        dutyCycleLimit = preset.dutyCycleLimit
    }

    /// Put the radio fields on `profile`, honouring what this device accepts.
    func adopt(_ profile: RadioProfile) {
        radioEnabled = true
        frequencyKHz = String(profile.frequencyKHz)
        transmitPowerDBm = String(profile.transmitPowerDBm)
        if let bandwidth = profile.bandwidthHz { bandwidthHz = bandwidth }
        if let factor = profile.spreadingFactor { spreadingFactor = factor }
        if let rate = profile.codingRateDenominator { codingRate = rate }
        if let limit = profile.dutyCycleLimit { dutyCycleLimit = limit }
    }

    private func matches(_ preset: RadioPreset) -> Bool {
        frequencyKHz == String(preset.frequencyKHz)
            && transmitPowerDBm == String(preset.transmitPowerDBm)
            && (!sync.supportsLora || (
                bandwidthHz == preset.bandwidthHz
                    && spreadingFactor == preset.spreadingFactor
                    && codingRate == preset.codingRate
            ))
            && (!sync.supportsDutyCycleLimit || dutyCycleLimit == preset.dutyCycleLimit)
    }

    var dutyCycleOptions: [(value: UInt16, label: String)] {
        var options: [(UInt16, String)] = [
            (UInt16.max, "Disabled"),
            (13_107, "20%"),
            (6_553, "10%"),
            (655, "1%"),
            (65, "0.1%"),
        ]
        if !options.contains(where: { $0.0 == dutyCycleLimit }) {
            let percent = Double(dutyCycleLimit) * 100 / Double(UInt16.max)
            let text = percent.formatted(.number.precision(.fractionLength(percent < 1 ? 2 : 1)))
            options.append((dutyCycleLimit, "Custom (\(text)%)"))
        }
        return options
    }

    // MARK: - Applying

    /// Write the draft to the device.
    ///
    /// `commissioning` is the setup sheet's apply rather than the editor's:
    /// it also sets the clock the goal decided on, and it reports the whole
    /// thing as one result instead of leaving it on the form. The editor is
    /// reachable from a finished setup over this same draft, and applying from
    /// there is an edit, not a commissioning — so it is the screen that says
    /// which this is, not the plan.
    func apply(commissioning: Bool) async {
        guard let configuration else { return }
        isSaving = true
        verificationProblem = nil
        if commissioning { applyPhase = .applying }
        defer { isSaving = false }
        guard let readback = await writer.configure(configuration) else {
            // The controller has the reason; the form is already showing it,
            // so the modal gets out of the way rather than repeating it.
            applyPhase = nil
            return
        }
        reported = readback
        // A device answers each write with the value it holds, and that answer
        // stands whatever was asked for — transmit power comes back clamped to
        // what the radio can reach. The form shows the device's figure, not the
        // operator's, so nobody walks away believing this radio transmits at a
        // power it cannot produce.
        transmitPowerDBm = String(readback.transmitPowerDbm)

        // The administrator list is saved configuration like everything
        // above, and travels separately for a different reason: it is a
        // table the device edits an item at a time. Written after the
        // configuration so a device left half-configured is not also left
        // answering to a phone that has not finished with it.
        if showsAdmins, Set(adminKeys) != Set(reportedAdminKeys) {
            do {
                try await writer.setAdministrators(adminKeys)
                reportedAdminKeys = adminKeys
            } catch {
                verificationProblem = """
                    The device took its settings but not the list of who may \
                    manage it. Read it again before relying on being able to \
                    reach it over the mesh.
                    """
                applyPhase = nil
                return
            }
        }

        // The clock is not in the configuration record and never will be — an
        // epoch in flash comes back arbitrarily wrong. So a goal that sets it
        // does so as a second, live write, strictly after the first: the
        // session runs one exchange at a time and rejects a second outright.
        var clockFailed = false
        if commissioning, plan.setsClockOnApply, sync.supportsTime {
            do {
                try await writer.setTime(
                    epochSeconds: UInt32(Date.now.timeIntervalSince1970)
                )
            } catch {
                clockFailed = true
            }
        }

        // The separate question of what it reports after its save, which is
        // what it will boot with.
        if let mismatch = firstMismatch(between: configuration, and: readback) {
            verificationProblem = """
                The device saved its settings but reported \(mismatch) back \
                differently. Read it again before relying on this configuration.
                """
            if commissioning { applyPhase = .reportedDifferently(field: mismatch) }
            return
        }
        appliedConfiguration = self.configuration
        if commissioning {
            applyPhase = clockFailed ? .succeededWithoutClock : .succeeded
        }
    }

    func dismissResult() { applyPhase = nil }

    /// The first field the device reports differently from what was asked for,
    /// named for a human. Device name is excluded: it is reported on the
    /// session snapshot rather than in the sync record.
    ///
    /// Settings the device does not report are excluded as well. They were
    /// never written, so there is nothing to hold the readback to — the
    /// unreadable-settings notice already says so, and calling it a mismatch
    /// would send the operator looking for a fault that is not there.
    ///
    /// Transmit power is excluded for the same reason: a device clamps it to
    /// what its radio can reach, so a device asked for more than it has
    /// reports back less by design. The fields left here are the ones a device
    /// refuses outright rather than adjusts, where a readback that disagrees
    /// really is one.
    func firstMismatch(
        between requested: UlcpDeviceConfigRecord,
        and readback: UlcpSyncRecord
    ) -> String? {
        func reported<Value: Equatable>(
            _ asked: Value?,
            _ read: Value?,
            _ name: String
        ) -> String? {
            guard let read else { return nil }
            return asked == read ? nil : name
        }

        if requested.radio.phyEnabled != readback.phyEnabled { return "the radio switch" }
        if requested.radio.frequencyKhz != readback.frequencyKhz { return "the frequency" }

        // Written out rather than chained with `??`: one expression this long
        // is more than the type checker will attempt.
        let radio = requested.radio
        if let name = reported(radio.bandwidthHz, readback.bandwidthHz, "the bandwidth") {
            return name
        }
        if let name = reported(
            radio.spreadingFactor, readback.spreadingFactor, "the spreading factor"
        ) {
            return name
        }
        if let name = reported(
            radio.codingRateDenom, readback.codingRateDenom, "the coding rate"
        ) {
            return name
        }
        if let name = reported(
            radio.dutyCycleLimit, readback.dutyCycleLimit, "the duty-cycle limit"
        ) {
            return name
        }
        // An unreadable role and a device-derived role are both an absent
        // value, so the only role worth checking is one the device names.
        if let name = reported(requested.identRole, readback.identRole, "the advertised role") {
            return name
        }
        if let name = reported(requested.identMobile, readback.identMobile, "device mobility") {
            return name
        }
        if let name = reported(
            requested.devDiscoverable, readback.devDiscoverable, "discoverability"
        ) {
            return name
        }
        if let name = reported(requested.repeater, readback.repeater, "the repeater policy") {
            return name
        }
        if let name = reported(requested.tzOffsetMin, readback.tzOffsetMin, "the time zone") {
            return name
        }
        if let name = reported(requested.gnss, readback.gnss, "the positioning settings") {
            return name
        }
        return reported(requested.advert, readback.advert, "what it announces")
    }
}

/// The write half of an administrative session, as the draft needs it.
///
/// A protocol rather than the controller itself so the draft cannot reach the
/// BLE session for anything but writing, and so the reference can be `unowned`
/// without the draft pretending to know the controller's whole surface.
@MainActor
protocol DeviceConfigurationWriting: AnyObject {
    func configure(_ configuration: UlcpDeviceConfigRecord) async -> UlcpSyncRecord?
    func setTime(epochSeconds: UInt32?) async throws
    /// Bring the device's administrator list to exactly `keys`, and persist
    /// it. Throws if any part of that did not land — the device's list is
    /// then whatever it is, and the form says to read it again.
    func setAdministrators(_ keys: [Data]) async throws
}

/// The session behind the settings form, as that form needs it.
///
/// `DeviceSettingsView` renders one device's settings whether the device
/// is on the other end of a Bluetooth link or several hops away on the
/// mesh. The two sessions have almost nothing in common — one owns a
/// peripheral and a scan list, the other an operation on a worker thread —
/// but the form asks the same handful of questions of both, and this is
/// that handful.
///
/// The live controls have default implementations that decline, because
/// they are the things only a device in hand can do: a locate alert, a
/// clock, a position sampled on a timer. Their sections are absent from a
/// remote plan, so declining is a statement about reachability rather than
/// something a screen has to handle.
@MainActor
protocol DeviceAdministering: AnyObject, DeviceConfigurationWriting {
    /// The device as it stands, for the parts of the form that report
    /// rather than edit.
    var snapshot: AdministeredDeviceSnapshot { get }
    /// Why the last write did not land, if it did not.
    var problem: String? { get }
    /// Whether this session can record the device in Peers.
    var canSavePeer: Bool { get }
    func savePeer(role: PeerRole) async -> Bool
    func setAlert(_ state: RadioAlertState) async throws
    func refreshPositioning() async
    /// Open the full editor over the device just set up, and start again on
    /// another one: both are steps of the setup sheet's navigation.
    func reviewAllSettings()
    func startOver() async
}

extension DeviceAdministering {
    var canSavePeer: Bool { false }
    func savePeer(role: PeerRole) async -> Bool { false }
    func setAlert(_ state: RadioAlertState) async throws {
        throw RadioConnectionError.radioNotFound
    }
    func refreshPositioning() async {}
    func setTime(epochSeconds: UInt32?) async throws {
        throw RadioConnectionError.radioNotFound
    }
    func reviewAllSettings() {}
    func startOver() async {}
}
