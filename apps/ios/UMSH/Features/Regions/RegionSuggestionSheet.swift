import CoreLocation
import SwiftUI
import UMSHMobileCore

/// A place a region proposal can be made from, and how well it is known.
///
/// Positions reaching this sheet come from sources of very different
/// quality — a node's advertised cell, a live fix, a typed coordinate pair
/// — and the proposal widens itself to match. That widening is Rust's
/// judgment, which is why the uncertainty travels with the position rather
/// than being flattened into a coordinate pair here.
struct RegionPositionSource: Identifiable, Equatable {
    enum Origin: String, CaseIterable {
        /// Where the node says it is, as it announces to the mesh.
        case advertised
        /// What the node's own receiver reports.
        case gnss
        /// Where this phone is, as a proxy for where the node is.
        case phone
        /// Coordinates the operator types.
        case manual
    }

    let origin: Origin
    /// The position, for a source that is already known. `phone` reads one
    /// on demand and `manual` is typed, so both carry none.
    var position: MobileRegionPositionRecord?

    var id: String { origin.rawValue }

    var title: String {
        switch origin {
        case .advertised: "Where the node says it is"
        case .gnss: "The node's own fix"
        case .phone: "This phone"
        case .manual: "Enter coordinates"
        }
    }

    var detail: String {
        switch origin {
        case .advertised:
            "The position this node advertises to the mesh."
        case .gnss:
            "The node's receiver puts it somewhere other than where it advertises."
        case .phone:
            "Honest only while this phone and the node are in the same place."
        case .manual:
            "The right answer when you are configuring a node for somewhere you are not."
        }
    }

    /// A node's advertised cell, whose bounds are its uncertainty. Absent
    /// on a node that advertises no position.
    static func advertised(
        location: Data?,
        latitude: Double?,
        longitude: Double?
    ) -> Self? {
        guard let location, !location.isEmpty,
              let latitude, let longitude else { return nil }
        return Self(
            origin: .advertised,
            position: MobileRegionPositionRecord(
                latitude: latitude,
                longitude: longitude,
                locationBytes: location,
                accuracyM: nil
            )
        )
    }

    /// A node's measured fix, offered only when it lies outside the cell
    /// the node advertises.
    ///
    /// A coarsened advert still contains the fix it was derived from, so
    /// this appears exactly when the two genuinely disagree: a saved
    /// position gone stale, or a node moved since it last advertised.
    static func gnss(
        latitude: Double?,
        longitude: Double?,
        accuracyDecimeters: UInt16?,
        outside advertised: RegionPositionSource?
    ) -> Self? {
        guard let latitude, let longitude else { return nil }
        if let cell = advertised?.position,
           let bytes = cell.locationBytes,
           AdvertisedCell.contains(
               latitude: latitude,
               longitude: longitude,
               cell: bytes,
               centerLatitude: cell.latitude,
               centerLongitude: cell.longitude
           ) {
            return nil
        }
        return Self(
            origin: .gnss,
            position: MobileRegionPositionRecord(
                latitude: latitude,
                longitude: longitude,
                locationBytes: nil,
                accuracyM: accuracyDecimeters.map { Double($0) / 10 }
            )
        )
    }
}

/// Whether a point falls inside the cell a node advertises.
///
/// An n-byte cell spans 180°/16ⁿ of latitude and 360°/16ⁿ of longitude, and
/// the reported degrees are its center — that is the encoding's own
/// definition, so the byte count is all this needs. Comparing in meters
/// would need a projection and would answer differently near the poles.
enum AdvertisedCell {
    static func contains(
        latitude: Double,
        longitude: Double,
        cell: Data,
        centerLatitude: Double,
        centerLongitude: Double
    ) -> Bool {
        guard !cell.isEmpty else { return false }
        let cells = pow(16.0, Double(cell.count))
        return abs(latitude - centerLatitude) <= 90.0 / cells
            && abs(longitude - centerLongitude) <= 180.0 / cells
    }
}

/// What the region database suggests for a place, and the two ways to take
/// it.
///
/// This sheet never touches a device. It answers with a complete resulting
/// configuration — the forwarding list and the default tag — and the
/// editor that opened it keeps its own Apply as the only path to the air.
struct RegionSuggestionSheet: View {
    /// What the device forwards for today, which is the diff's base.
    let currentRegions: [String]
    let currentDefaultRegion: Data?
    /// Offered in order, the first preselected.
    let sources: [RegionPositionSource]
    /// Whether where this phone is stands for where the node is.
    ///
    /// True at a bench, over Bluetooth, where the two are within a few
    /// meters of each other. False for a node managed across the mesh,
    /// which is by definition somewhere this phone is not — offering the
    /// phone there would propose regions for the operator's desk.
    var offersPhone = false
    /// Refresh whatever the caller would need to offer a node's advertised
    /// position, when it has not been read. Absent where there is nothing
    /// to refresh.
    var refreshAdvertised: (() async -> Void)?
    let accept: (MobileRegionOutcomeRecord) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.regionService) private var regionService
    @Environment(\.readPhonePosition) private var readPhonePosition

    @State private var origin: RegionPositionSource.Origin?
    @State private var latitudeText = ""
    @State private var longitudeText = ""
    /// The phone's own position, once read. Held rather than re-read, so
    /// switching away from this source and back does not spend a fix.
    @State private var phonePosition: MobileRegionPositionRecord?
    @State private var isReadingPhone = false
    @State private var phoneUnavailable = false
    @State private var proposal: MobileRegionProposalRecord?
    @State private var problem: String?
    @State private var isProposing = false

    var body: some View {
        NavigationStack {
            Form {
                sourceSection
                if origin == .manual { coordinateSection }
                if origin == .phone, phonePosition == nil { phoneReadingSection }
                if let problem { problemSection(problem) }
                if isProposing, proposal == nil {
                    Section {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Looking up this place…").foregroundStyle(.secondary)
                        }
                    }
                }
                if let proposal { content(proposal) }
            }
            .navigationTitle("Regions for This Place")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .onAppear {
            if origin == nil { origin = offeredSources.first?.origin }
        }
        .task(id: proposalKey) { await propose() }
    }

    // MARK: - Choosing a place

    /// Every source with something behind it. Typing coordinates is always
    /// one of them: it is the only correct answer when configuring a node
    /// for a site you are not standing at.
    private var offeredSources: [RegionPositionSource] {
        var offered = sources.filter { $0.origin != .manual && $0.origin != .phone }
        if offersPhone, readPhonePosition != nil {
            offered.append(RegionPositionSource(origin: .phone, position: nil))
        }
        offered.append(RegionPositionSource(origin: .manual, position: nil))
        return offered
    }

    @ViewBuilder
    private var sourceSection: some View {
        Section {
            ForEach(offeredSources) { source in
                Button {
                    origin = source.origin
                } label: {
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(source.title)
                            Text(source.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 12)
                        if origin == source.origin {
                            Image(systemName: "checkmark")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
                .buttonStyle(.plain)
            }
            if let refreshAdvertised, !sources.contains(where: { $0.origin == .advertised }) {
                Button("Read the Node's Position") {
                    Task { await refreshAdvertised() }
                }
            }
        } header: {
            Text("Place")
        } footer: {
            if let position = chosenPosition {
                Text(placeSummary(position))
            }
        }
    }

    private var coordinateSection: some View {
        Section {
            LabeledContent("Latitude") {
                TextField("37.5119", text: $latitudeText)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
            }
            LabeledContent("Longitude") {
                TextField("-122.2495", text: $longitudeText)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
            }
        } footer: {
            Text("Decimal degrees. A typed position is taken exactly, with no allowance for error.")
        }
    }

    @ViewBuilder
    private var phoneReadingSection: some View {
        Section {
            if isReadingPhone {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Finding this phone…").foregroundStyle(.secondary)
                }
            } else if phoneUnavailable {
                Text(
                    """
                    This phone could not find where it is. Check that location \
                    access for UMSH is on in iOS Settings, or type coordinates \
                    instead.
                    """
                )
                .foregroundStyle(.secondary)
            }
        }
    }

    /// Where the proposal is being made for, whatever the chosen source.
    private var chosenPosition: MobileRegionPositionRecord? {
        switch origin {
        case .manual:
            guard let latitude = Double(latitudeText.trimmingCharacters(in: .whitespaces)),
                  let longitude = Double(longitudeText.trimmingCharacters(in: .whitespaces))
            else { return nil }
            return MobileRegionPositionRecord(
                latitude: latitude,
                longitude: longitude,
                locationBytes: nil,
                accuracyM: nil
            )
        case .phone:
            return phonePosition
        case let .some(chosen):
            return sources.first { $0.origin == chosen }?.position
        case nil:
            return nil
        }
    }

    /// What re-proposing depends on, so a changed source or a changed digit
    /// re-runs it and nothing else does.
    private var proposalKey: String {
        let position = chosenPosition
        return [
            origin?.rawValue ?? "",
            position.map { "\($0.latitude),\($0.longitude)" } ?? "",
            position?.locationBytes.map { "\($0.count)" } ?? "",
            position?.accuracyM.map { "\($0)" } ?? "",
        ].joined(separator: "|")
    }

    private func placeSummary(_ position: MobileRegionPositionRecord) -> String {
        let cell = proposal?.cellMeters
        var summary = LocationPresentation.coordinateText(
            latitude: position.latitude,
            longitude: position.longitude,
            cellMeters: cell
        )
        if let cell {
            summary += " · \(LocationPresentation.cellLabel(meters: cell)) across"
        }
        return summary
    }

    // MARK: - Proposing

    private func propose() async {
        if origin == .phone, phonePosition == nil { await readPhone() }
        guard let regionService else {
            proposal = nil
            problem = "This build carries no region database."
            return
        }
        guard let position = chosenPosition else {
            proposal = nil
            problem = nil
            return
        }
        isProposing = true
        defer { isProposing = false }
        do {
            proposal = try await regionService.propose(
                position: position,
                currentRegions: currentRegions,
                currentDefaultRegion: currentDefaultRegion
            )
            problem = nil
        } catch {
            proposal = nil
            problem = RegionService.text(for: error)
        }
    }

    private func readPhone() async {
        guard let readPhonePosition else { return }
        isReadingPhone = true
        phoneUnavailable = false
        defer { isReadingPhone = false }
        guard let reading = await readPhonePosition() else {
            phoneUnavailable = true
            return
        }
        phonePosition = MobileRegionPositionRecord(
            latitude: reading.coordinate.latitude,
            longitude: reading.coordinate.longitude,
            locationBytes: nil,
            // A negative accuracy is CoreLocation saying the fix is
            // invalid; treated as no stated uncertainty rather than as a
            // measurement of one.
            accuracyM: reading.horizontalAccuracy > 0 ? reading.horizontalAccuracy : nil
        )
    }

    // MARK: - What the database says

    @ViewBuilder
    private func problemSection(_ problem: String) -> some View {
        Section {
            Text(problem).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func content(_ proposal: MobileRegionProposalRecord) -> some View {
        Section {
            if proposal.lookup.matches.isEmpty {
                Text("The database has no regions covering this place.")
                    .foregroundStyle(.secondary)
            }
            ForEach(proposal.lookup.matches, id: \.regionKey) { match in
                VStack(alignment: .leading, spacing: 2) {
                    Text(RegionCodeText.label(region: match.radioName))
                        .font(.body.monospaced())
                    Text(matchDetail(match))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Covers this place")
        } footer: {
            Text("Region data \(proposal.lookup.datasetVersion).")
        }

        if !proposal.uncertainRegions.isEmpty {
            Section {
                Text(uncertaintyNote(proposal))
                    .foregroundStyle(.secondary)
            }
        }

        diffSection(proposal)
        actionSection(proposal)
    }

    private func matchDetail(_ match: MobileRegionMatchRecord) -> String {
        let layer = match.layer.replacingOccurrences(of: "_", with: " ")
        return switch match.membership {
        case .core: layer
        case .expanded: "\(layer) — nearby, not inside"
        }
    }

    private func uncertaintyNote(_ proposal: MobileRegionProposalRecord) -> String {
        let named = proposal.uncertainRegions
            .map { RegionCodeText.label(region: $0) }
            .formatted(.list(type: .and))
        return """
            This position is not precise enough to say which side of a boundary \
            the node is on, so both sides are suggested: \(named).
            """
    }

    @ViewBuilder
    private func diffSection(_ proposal: MobileRegionProposalRecord) -> some View {
        let additions = proposal.lookup.radioRegions
            .map(\.name)
            .filter { name in
                !proposal.alreadyPresent.contains { $0 == name }
            }
        Section {
            ForEach(additions, id: \.self) { region in
                diffRow(region, symbol: "plus.circle", tint: .green, note: "added")
            }
            ForEach(proposal.alreadyPresent, id: \.self) { region in
                diffRow(region, symbol: "checkmark.circle", tint: .secondary, note: "already listed")
            }
            ForEach(proposal.notSuggested, id: \.self) { region in
                diffRow(
                    region,
                    symbol: "minus.circle",
                    tint: .orange,
                    note: "kept by Add, dropped by Replace"
                )
            }
            if let suggested = proposal.lookup.suggestedDefaultRegion {
                LabeledContent("Tag untagged floods with") {
                    Text(RegionCodeText.label(region: suggested.name))
                        .font(.body.monospaced())
                }
            }
        } header: {
            Text("What would change")
        } footer: {
            if additions.isEmpty, proposal.notSuggested.isEmpty {
                Text("This node already forwards for exactly these regions.")
            }
        }
    }

    private func diffRow(
        _ region: String,
        symbol: String,
        tint: Color,
        note: String
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(RegionCodeText.label(region: region))
                    .font(.body.monospaced())
                Text(note).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func actionSection(_ proposal: MobileRegionProposalRecord) -> some View {
        let appended = proposal.addMissing.regions.count - currentRegions.count
        Section {
            Button("Replace All") { take(proposal.replace) }
                .disabled(!proposal.replace.changesAnything)
            Button(appended == 1 ? "Add 1 Missing" : "Add \(appended) Missing") {
                take(proposal.addMissing)
            }
            .disabled(!proposal.addMissing.changesAnything)
        } footer: {
            if !proposal.replace.changesAnything, !proposal.addMissing.changesAnything {
                Text("Nothing to do — this node's regions already match this place.")
            } else {
                Text(
                    """
                    Nothing is sent yet. Either choice fills in the settings on the \
                    previous screen, which you then apply.
                    """
                )
            }
        }
    }

    private func take(_ outcome: MobileRegionOutcomeRecord) {
        accept(outcome)
        dismiss()
    }
}
