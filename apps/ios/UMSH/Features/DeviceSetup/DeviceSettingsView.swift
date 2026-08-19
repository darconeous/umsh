import SwiftUI
import UMSHMobileCore

/// The settings form for one administered device, rendered from a list of
/// sections.
///
/// A setup sheet and the full editor are this same view: the goal's plan
/// decides which sections appear, and nothing else about them differs. Two
/// views over the same settings would be two things to keep in step, and the
/// short one would be the one that fell behind.
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
    /// Whether this screen is the goal's setup sheet, as opposed to the editor
    /// reached from it. Decides whether applying also sets the clock and
    /// reports itself in a modal.
    let isCommissioning: Bool
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
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        // Switching a receiver on and watching it find itself is what the
        // positioning section is for, and a device never announces a position.
        // A sheet showing only the policy has nothing to watch, so it does not
        // poll — and neither does anything while a write is in flight, or the
        // poll and the write race for the session's one exchange slot.
        .radioPositionPoll(
            isNeeded: sections.contains(.positioning)
                && draft.showsPositioning
                && !draft.isSaving,
            sample: controller.refreshPositioning
        )
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                if draft.applied {
                    Button("Done") { finish() }
                } else {
                    Button(applyTitle) {
                        Task { await draft.apply(commissioning: isCommissioning) }
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

        case .ownership:
            DeviceOwnershipSection(
                hostState: snapshot.hostState,
                peer: snapshot.deviceIdentity.map {
                    draft.administeredPeer($0, name: snapshot.name)
                },
                peerActions: peerActions,
                savePeer: controller.canSavePeer
                    ? { await controller.savePeer(role: draft.advertisedPeerRole) }
                    : nil,
                isPeerSaved: isPeerSaved
            )

        case .ownershipWarning:
            ForeignRadioSection(hostState: snapshot.hostState)

        case .find:
            if let alert = snapshot.alert {
                DeviceFindSection(
                    alert: alert,
                    isBusy: isBusy,
                    failureText: "The device did not answer. It may have moved out of range.",
                    setAlert: controller.setAlert
                )
            }

        case .power:
            if sync.supportsBattery {
                DevicePowerSection(
                    percentage: snapshot.batteryPercentage,
                    voltageMillivolts: snapshot.batteryVoltageMillivolts,
                    chargeState: snapshot.chargeState
                )
            }

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

        case .presets:
            if draft.showsPresets {
                RadioPresetSection(presetIdentifier: $draft.presetIdentifier)
            }

        case .radio:
            RadioSection(
                enabled: $draft.radioEnabled,
                frequencyKHz: $draft.frequencyKHz,
                transmitPowerDBm: $draft.transmitPowerDBm,
                showsLoRa: draft.showsLoRa,
                bandwidthHz: $draft.bandwidthHz,
                spreadingFactor: $draft.spreadingFactor,
                codingRate: $draft.codingRate,
                showsDutyCycleLimit: draft.showsDutyCycleLimit,
                dutyCycleOptions: draft.dutyCycleOptions,
                dutyCycleLimit: $draft.dutyCycleLimit
            )

        case .identity:
            if draft.showsIdentity {
                AdvertisedIdentitySection(
                    role: $draft.identRole,
                    mobile: $draft.identMobile,
                    showsDiscoverable: draft.showsDiscoverable,
                    discoverable: $draft.devDiscoverable,
                    advertisedRole: draft.advertisedRole
                )
            }

        case .discoverability:
            if draft.showsDiscoverable {
                DiscoverabilitySection(discoverable: $draft.devDiscoverable)
            }

        case .positioning, .positioningPolicy:
            if draft.showsPositioning {
                PositioningSection(
                    enabled: $draft.gnssEnabled,
                    identUpdate: $draft.gnssIdentUpdate,
                    identPrecision: $draft.gnssIdentPrecision,
                    timeTrust: $draft.gnssTimeTrust,
                    readout: section == .positioning
                        ? snapshot.position.map {
                            PositioningReadout(
                                position: $0,
                                receiverEnabled: draft.reported.gnss?.enabled,
                                pinName: snapshot.name
                            )
                        }
                        : nil
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

        case .time:
            if sync.supportsTime {
                DeviceTimeSection(
                    showsTimeZone: draft.showsTimeZone,
                    timeZoneOffsetMinutes: $draft.timeZoneOffsetMinutes,
                    clock: snapshot.clock,
                    isBusy: isBusy,
                    setTime: { try await controller.setTime(epochSeconds: $0) }
                )
            }

        case .forwarding:
            if draft.showsRepeater {
                RepeaterSettingsSection(
                    enabled: $draft.repeaterEnabled,
                    regions: $draft.regions,
                    defaultRegion: $draft.defaultRegion,
                    minRssiDBm: $draft.minRssiDBm,
                    minSnrDB: $draft.minSnrDB
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

    /// Nothing else may talk to the device right now. A session runs one
    /// exchange at a time and refuses a second outright, so a live control
    /// left enabled during a save turns into a failure that reads as the
    /// device's fault.
    private var isBusy: Bool { isLinkDown || draft.isSaving }
}
