import SwiftUI
import UMSHMobileCore

/// The commissioning sheet for one device, rendered from a list of sections.
///
/// Every goal's sheet is this same view: the core's setup decides which
/// sections appear, and nothing else about them differs. Two views over the
/// same settings would be two things to keep in step, and the short one would
/// be the one that fell behind. Changing a device's settings afterward is not
/// this screen—it is the management screens every device gets.
///
/// The setup is owned by the flow rather than by this screen, so what is
/// edited here is the same draft another screen may have started—see
/// `DeviceSetupModel`.
struct DeviceSettingsView: View {
    let controller: any DeviceAdministering
    @Bindable var model: DeviceSetupModel
    let isPeerSaved: (String) -> Bool
    let peerActions: PeerActions
    let finish: () -> Void

    /// What to do once the result modal is off screen.
    ///
    /// Pushing a screen out from under a sheet that is still animating away
    /// loses the push, so both of the modal's onward buttons dismiss first and
    /// act here.
    @State private var afterResult: (() -> Void)?

    private var setup: MobileDeviceSetupRecord { model.snapshot }
    private var review: MobileSetupReviewRecord? { model.review }
    private var snapshot: AdministeredDeviceSnapshot { controller.snapshot }

    var body: some View {
        Form {
            LinkNoticesSection(
                connectionProblem: snapshot.linkState == .failed
                    ? (snapshot.problemDescription
                        ?? String(localized: "Connection lost", comment: "Device setup: the link to the device being set up dropped."))
                    : nil,
                unreadable: setup.unreadable
            )
            ForeignRadioSection(hostState: snapshot.hostState)
            if !setup.notes.isEmpty {
                SetupNoteSection(notes: setup.notes)
            }
            ForEach(setup.sections, id: \.self) { section in
                view(for: section)
            }
            ApplyStatusSection(
                result: setup.lastResult,
                unshownProblems: review?.unshownProblems ?? [],
                applied: review?.applied == true
            )
        }
        // Adding a routing region reflows the repeater section: the blank
        // input row and everything below it slide down to make room. The
        // mutation is a plain draft assignment that animates nothing on its
        // own, so the reflow is animated here, keyed on the list alone. The
        // added row itself is exempted (its transition is .identity in
        // RepeaterSettingsSection)—the typed text is already on screen
        // where the row lands.
        .animation(UMSHAnimation.list, value: model.draft.repeater.regions.value)
        // Administrators are different: an entry comes out of a menu, not
        // out of text already sitting where the row lands, so here the new
        // row itself animates in (and out, on Remove).
        .animation(UMSHAnimation.list, value: model.draft.administrators.value)
        .navigationTitle(Text(setup.goal.sheetTitle))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                if review?.applied == true {
                    Button("Done") { finish() }
                } else {
                    Button {
                        Task { await model.apply() }
                    } label: {
                        Text(setup.goal.applyTitle)
                    }
                    .disabled(!model.canApply(linkDown: isLinkDown))
                }
            }
        }
        .sheet(isPresented: $model.isPresentingResult, onDismiss: runAfterResult) {
            if let phase = model.phase {
                DeviceSetupResultView(
                    phase: phase,
                    goal: setup.goal,
                    deviceName: snapshot.name,
                    savePeer: controller.canSavePeer && snapshot.deviceIdentity != nil
                        ? { [model, controller] in
                            try await controller.savePeer(
                                role: model.snapshot.advertisedRole.map(PeerRole.init(roleCode:))
                            )
                        }
                        : nil,
                    isPeerSaved: snapshot.deviceIdentity
                        .map { isPeerSaved($0.canonicalAddress) } ?? false,
                    reviewAllSettings: { dismissResult(then: controller.reviewAllSettings) },
                    setUpAnother: {
                        dismissResult(then: { Task { await controller.startOver() } })
                    },
                    close: { dismissResult(then: nil) },
                    finish: { dismissResult(then: finish) }
                )
            }
        }
    }

    private func dismissResult(then action: (() -> Void)?) {
        afterResult = action
        model.isPresentingResult = false
    }

    private func runAfterResult() {
        let action = afterResult
        afterResult = nil
        action?()
    }

    @ViewBuilder
    private func view(for section: MobileSetupSection) -> some View {
        switch section {
        case .name:
            DeviceNameSection(
                name: $model.draft.name.text,
                problem: model.problem(for: model.draft.name.propertyId)
            )

        case .radioProfile:
            if let profile = setup.profile {
                RadioProfileSection(
                    profile: profile,
                    chosen: review?.profileChosen ?? true,
                    presetName: review?.presetId.flatMap { id in
                        RadioPreset.vetted.first { $0.id == id }?.name
                    },
                    summary: RadioProfileSummary.text(
                        model.draft.radio,
                        showsModem: setup.showsModem
                    ),
                    destination: { RadioProfileEditorView(model: model) }
                )
            }

        case .discoverability:
            DiscoverabilitySection(discoverable: $model.draft.discoverable.value)

        case .positioning:
            PositioningSection(
                enabled: $model.draft.gnssEnabled.value,
                identUpdate: $model.draft.sharePosition.value,
                identPrecision: $model.draft.precision.value,
                precisions: review?.choices.precisions,
                timeTrust: $model.draft.timeTrust.value
            )

        case .announcements:
            AnnouncementsSection(
                beaconInterval: $model.draft.beaconInterval.value,
                beaconChoices: review?.choices.beaconIntervalsS,
                advertInterval: $model.draft.advertInterval.value,
                advertChoices: review?.choices.advertIntervalsS,
                startupBeacon: $model.draft.startupBeacon.value
            )

        case .forwarding:
            RepeaterSettingsSection(
                repeater: $model.draft.repeater,
                taggableRegions: review?.taggableRegions ?? [],
                defaultRegionUnlisted: review?.defaultRegionUnlisted == true,
                minRssiChoices: review?.choices.minRssiDbm,
                minSnrChoices: review?.choices.minSnrDb,
                // Read from what the device reports rather than off the
                // draft: its position is a reading, not a setting this form
                // edits.
                advertisedPosition: setup.reported?.identPosition,
                devicePosition: snapshot.position,
                suggestsFromPhone: setup.suggestsRegionsFromPhone
            )

        case .administrators:
            DeviceAdministratorsSection(
                administrators: (review?.administrators ?? []).map {
                    DeviceAdministrator(publicKey: $0.key, isThisPhone: $0.isThisPhone)
                },
                phoneAdministers: Binding(
                    get: { model.review?.phoneAdministers == true },
                    set: { model.setPhoneAdministers($0) }
                ),
                phoneKeyKnown: setup.phoneNodeKey != nil,
                phoneSwitchEnabled: review?.phoneSwitchEnabled == true,
                isFull: review?.administratorsFull == true,
                knownPeers: peerActions.knownPeers,
                add: { model.addAdministrator($0) },
                remove: { model.removeAdministrator($0.publicKey) }
            )
        }
    }

    private var isLinkDown: Bool {
        snapshot.linkState == .failed || snapshot.linkState == .idle
    }
}
