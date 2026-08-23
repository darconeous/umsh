import SwiftUI
import UMSHMobileCore

/// The commissioning sheet for one device, rendered from a list of sections.
///
/// Every goal's sheet is this same view: the goal's plan decides which
/// sections appear, and nothing else about them differs. Two views over the
/// same settings would be two things to keep in step, and the short one would
/// be the one that fell behind. Changing a device's settings afterward is not
/// this screen — it is the management screens every device gets.
///
/// The draft is owned by the flow rather than by this screen, so what is
/// edited here is the same configuration another screen may have started —
/// see `DeviceConfigDraft`.
struct DeviceSettingsView: View {
    let controller: any DeviceAdministering
    @Bindable var draft: DeviceConfigDraft
    let sections: [DeviceSetupSection]
    let title: String
    let applyTitle: String
    /// What the goal will not manage on this device, if anything.
    let note: String?
    let isPeerSaved: (String) -> Bool
    let peerActions: PeerActions
    let finish: () -> Void

    /// What to do once the result modal is off screen.
    ///
    /// Pushing a screen out from under a sheet that is still animating away
    /// loses the push, so both of the modal's onward buttons dismiss first and
    /// act here.
    @State private var afterResult: (() -> Void)?

    private var sync: UlcpSyncRecord { draft.sync }
    private var snapshot: AdministeredDeviceSnapshot { controller.snapshot }

    var body: some View {
        Form {
            ForEach(sections, id: \.self) { section in
                view(for: section)
            }
        }
        // Adding a routing region reflows the repeater section: the blank
        // input row and everything below it slide down to make room. The
        // mutation is a plain draft assignment that animates nothing on its
        // own, so the reflow is animated here, keyed on the list alone. The
        // added row itself is exempted (its transition is .identity in
        // RepeaterSettingsSection) — the typed text is already on screen
        // where the row lands.
        .animation(.default, value: draft.regions)
        // Administrators are different: an entry comes out of a menu, not
        // out of text already sitting where the row lands, so here the new
        // row itself animates in (and out, on Remove).
        .animation(.default, value: draft.adminKeys)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                if draft.applied {
                    Button("Done") { finish() }
                } else {
                    Button(applyTitle) {
                        Task { await draft.apply() }
                    }
                    .disabled(!canApply)
                }
            }
        }
        .sheet(isPresented: $draft.isPresentingResult, onDismiss: runAfterResult) {
            if let phase = draft.applyPhase {
                DeviceSetupResultView(
                    phase: phase,
                    deviceNoun: draft.plan.deviceNoun,
                    deviceName: snapshot.name,
                    savePeer: controller.canSavePeer && snapshot.deviceIdentity != nil
                        ? { await controller.savePeer(role: draft.advertisedPeerRole) }
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
        draft.dismissResult()
    }

    private func runAfterResult() {
        let action = afterResult
        afterResult = nil
        action?()
    }

    private var canApply: Bool {
        draft.configuration != nil
            && draft.profileChosen
            && !draft.isSaving
            && !isLinkDown
    }

    /// Which sections a device supports is a separate question from which ones
    /// the goal asks about: a plan naming a section the device cannot answer
    /// for renders nothing, rather than the plan having to know every device.
    @ViewBuilder
    private func view(for section: DeviceSetupSection) -> some View {
        switch section {
        case .link:
            LinkNoticesSection(
                connectionProblem: snapshot.linkState == .failed
                    ? (snapshot.problemDescription ?? "Connection lost")
                    : nil,
                unreadableSettings: draft.unreadableSettings
            )

        case .note:
            if let note {
                SetupNoteSection(note: note)
            }

        case .ownershipWarning:
            ForeignRadioSection(hostState: snapshot.hostState)

        case .name:
            if sync.supportsDeviceName {
                DeviceNameSection(name: $draft.deviceName)
            }

        case .radioProfile:
            if let resolution = draft.resolvedProfile {
                RadioProfileSection(
                    resolution: resolution,
                    chosen: draft.profileChosen,
                    presetName: draft.presetName,
                    summary: draft.profileSummary,
                    destination: { RadioProfileEditorView(draft: draft) }
                )
            }

        case .discoverability:
            if draft.showsDiscoverable {
                DiscoverabilitySection(discoverable: $draft.devDiscoverable)
            }

        case .positioningPolicy:
            if draft.showsPositioning {
                PositioningSection(
                    enabled: $draft.gnssEnabled,
                    identUpdate: $draft.gnssIdentUpdate,
                    identPrecision: $draft.gnssIdentPrecision,
                    timeTrust: $draft.gnssTimeTrust
                )
            }

        case .announcements:
            if draft.showsAnnouncements {
                AnnouncementsSection(
                    beaconIntervalSeconds: $draft.beaconIntervalSeconds,
                    advertIntervalSeconds: $draft.advertIntervalSeconds,
                    startupBeacon: $draft.startupBeacon
                )
            }

        case .forwarding:
            if draft.showsRepeater {
                RepeaterSettingsSection(
                    enabled: $draft.repeaterEnabled,
                    regions: $draft.regions,
                    defaultRegion: $draft.defaultRegion,
                    minRssiDBm: $draft.minRssiDBm,
                    minSnrDB: $draft.minSnrDB,
                    // Read live rather than off the draft: the device's
                    // position is a reading, not a setting this form edits.
                    advertisedPosition: draft.reported.identPosition,
                    devicePosition: snapshot.position,
                    // A repeater being commissioned is being placed, so it
                    // is offered the regions covering where the phone
                    // placing it is standing.
                    suggestsFromPhone: draft.plan.goal == .repeaterNode
                )
            }

        case .administrators:
            if draft.showsAdmins {
                DeviceAdministratorsSection(
                    administrators: draft.administrators,
                    phoneAdministers: Binding(
                        get: { draft.phoneAdministers },
                        set: { draft.setPhoneAdministers($0) }
                    ),
                    phoneKeyKnown: draft.phoneNodeKey != nil,
                    isFull: draft.administratorListFull,
                    knownPeers: peerActions.knownPeers,
                    add: { draft.add(administrator: $0) },
                    remove: { administrator in
                        draft.adminKeys.removeAll { $0 == administrator.publicKey }
                    }
                )
            }

        case .applyStatus:
            ApplyStatusSection(
                problem: controller.problem ?? draft.verificationProblem,
                applied: draft.applied
            )
        }
    }

    private var isLinkDown: Bool {
        snapshot.linkState == .failed || snapshot.linkState == .idle
    }
}
