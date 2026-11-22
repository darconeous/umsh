import Foundation
import OSLog
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Identity

    @MainActor
    func loadIdentity() async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            switch try await identityOperations.load() {
            case let .ready(identity, minted):
                try Task.checkCancellation()
                await bringUp(identity, minted: minted)
            case let .needsAdoption(identity):
                orphanedIdentity = identity
                identityError = nil
                return
            }
            try Task.checkCancellation()
            if localIdentity != nil {
                await radioConnection.autoConnect()
            }
        } catch is CancellationError {
            return
        } catch let error as IdentityVaultError {
            Self.logger.error("Identity load failed: \(String(describing: error), privacy: .public)")
            identityError = error
        } catch {
            Self.logger.error("Identity load failed outside the vault: \(String(describing: error), privacy: .public)")
            identityError = .keychainFailure
        }
    }

    /// Bring the app up on `identity`: read its lists, settle onboarding,
    /// then start the core on it.
    ///
    /// The one sequence that turns an identity into a running app, shared by
    /// launch, by minting one by hand, by adopting one, and by the two
    /// erasures—a phone that has just destroyed its key comes back exactly
    /// the way one that never had a key comes up.
    @MainActor
    private func bringUp(_ identity: LocalIdentitySnapshot, minted: Bool) async {
        localIdentity = identity
        identityError = nil
        // The lists show before the core starts: reading needs only the
        // owner. Onboarding reads the stored name from the same read.
        await reloadApplicationState()
        settleOnboarding(mintedIdentity: minted)
        await startCore()
    }

    /// Start the core on the identity the vault last unlocked, reseeding
    /// the staged mesh first when this is staging.
    ///
    /// A core already starting or running is attached to, not started:
    /// that is a debug switch to another radio over the same store.
    @MainActor
    private func startCore() async {
        guard !isDetached, let core, let localIdentity, let status = try? core.status() else { return }
        switch status.lifecycle {
        case .idle, .failed: break
        case .running:
            Self.logger.notice("Attached to the running core")
            return
        default:
            Self.logger.notice("Attached to the core as it stands")
            return
        }
        Self.logger.notice("Starting the core")
        await seedStagedContentIfNeeded(owner: localIdentity.id)
        guard !isDetached else { return }
        // Unlocked when the vault read the identity. A start consumes it,
        // so every start has unlocked again.
        guard let identity = await meshEngine.takeIdentity() else { return }
        do {
            try await core.start(identity: identity)
        } catch MobileAppError.Busy {
            // Another start got there first.
        } catch {
            // A failed start arrives as the lifecycle, and is shown there.
            Self.logger.error("Start failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// Decide whether this launch owes the user an introduction.
    ///
    /// A freshly minted identity always does. An identity that was already
    /// there usually does not—but "already there" includes a flow that was
    /// killed halfway through, so the tiebreak is whether the phone carries a
    /// name: one that does has been through setup, by this flow or by hand, and
    /// has nothing left to be shown.
    ///
    /// Only ever raises the flag; presenting it is the interface's business,
    /// and on a background launch there is no interface to present it. The
    /// answer keeps until a scene appears.
    @MainActor
    private func settleOnboarding(mintedIdentity: Bool) {
        guard !isStaging else { return }
        guard !onboardingCompleted, localIdentity != nil else { return }
        if mintedIdentity || advertisedName.isEmpty {
            shouldPresentOnboarding = true
        } else {
            onboardingCompleted = true
        }
    }

    /// Try again after a failed identity load or a failed start, once the
    /// reason for the failure may have passed.
    ///
    /// Scoped to attempts that actually failed: a phone with no identity yet
    /// reports success with none, and is waiting on onboarding rather than on
    /// anything a retry could change. A start that failed consumed the
    /// unlocked identity, so its retry unlocks again.
    @MainActor
    func retryIdentityLoadIfNeeded() async {
        guard !isLoadingIdentity, !isRetryingStart else { return }
        if identityError != nil, localIdentity == nil {
            Self.logger.notice("Retrying the identity load after an earlier failure")
            await loadIdentity()
            return
        }
        guard case .failed = lifecycle, localIdentity != nil else { return }
        Self.logger.notice("Retrying the start after an earlier failure")
        isRetryingStart = true
        defer { isRetryingStart = false }
        guard (try? await identityVault.loadIdentity())?.id == localIdentity?.id else { return }
        await startCore()
    }

    @MainActor
    func createIdentity() async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            let identity = try await identityVault.createIdentity()
            orphanedIdentity = nil
            await bringUp(identity, minted: true)
        } catch is CancellationError {
            return
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    // MARK: - Destroying this phone's identity

    /// Keep the identity a previous install left behind.
    ///
    /// The key is what peers recognize, so keeping it means the mesh sees
    /// the same node it always did. Nothing recovers the records that were
    /// keyed to it—those went with the container.
    @MainActor
    func adoptOrphanedIdentity() async {
        guard orphanedIdentity != nil else { return }
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            let identity = try await identityVault.adoptStoredIdentity()
            orphanedIdentity = nil
            await bringUp(identity, minted: true)
            await radioConnection.autoConnect()
        } catch is CancellationError {
            return
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    /// Destroy this phone's private key and every key held under it, then
    /// come back as a new node.
    ///
    /// The narrow erasure: the key material goes and the database stays.
    /// What stays is unreachable—every row is keyed by the identity that
    /// owned it, and that identity no longer exists—so this is the choice
    /// for someone who wants a different key rather than a clean phone.
    /// ``startOver()`` is the other one.
    @MainActor
    func eraseIdentity() async {
        await eraseIdentity(alsoErasingContent: false)
    }

    /// Erase everything this phone holds: the identity, the keys, the
    /// messages, the peers, the channels, the paired radio, and the
    /// preferences. What comes back is a first launch.
    @MainActor
    func startOver() async {
        await eraseIdentity(alsoErasingContent: true)
    }

    @MainActor
    private func eraseIdentity(alsoErasingContent: Bool) async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        let failureTitle = String(
            localized: "Couldn't Erase",
            comment: "Alert title: erasing this phone's identity did not finish. The message says why."
        )

        // The radio holds this phone's public key as its host key, so a
        // radio kept across the erasure would belong to a node that no
        // longer exists. Let it go first, while the link is still ours.
        await forgetRadio()
        // The secret before anything else: if it cannot be destroyed,
        // nothing is, and the phone stays the node it was.
        do {
            try await identityVault.eraseIdentity()
        } catch {
            Self.logger.error("The identity secret was not erased: \(String(describing: error), privacy: .public)")
            failureNotice = FailureNotice(
                title: failureTitle,
                message: String(
                    localized: "This phone's key could not be removed.",
                    comment: "Erasing this phone's identity: the Keychain kept its private key, so nothing was erased."
                )
            )
            return
        }
        await meshEngine.lockIdentity()
        localIdentity = nil
        orphanedIdentity = nil
        if let core {
            // The core waits out a start under way.
            do {
                try await core.erase(alsoContent: alsoErasingContent)
            } catch let error as MobileAppError {
                Self.logger.error("The core did not erase everything: \(String(describing: error), privacy: .public)")
                // A vault code here is about erasing keys, not reading one.
                let message = if case .Vault = error {
                    String(
                        localized: "Channel keys could not be erased.",
                        comment: "Erasing this phone's identity: the channel keys stayed in the Keychain."
                    )
                } else {
                    error.message
                }
                failureNotice = FailureNotice(title: failureTitle, message: message)
            } catch {
                Self.logger.error("The core did not erase everything: \(String(describing: error), privacy: .public)")
            }
        }
        #if DEBUG
        // The identity is shared between the live and staged stores, and
        // the core removed only its own counters.
        AppCoreHost.removeOtherCounterDirectory(inUse: isStaging ? .staging : .live)
        #endif
        notificationService.withdrawAllDelivered()

        if alsoErasingContent {
            Self.eraseStoredPreferences()
            // The core keeps the policy it was given across an erase.
            await pushPolicy()
            applyLocationSharing()
        }
        // Both erasures produce a node nobody has met, under a name nobody
        // has chosen, so both owe the introduction a first launch owes.
        onboardingCompleted = false
        advertisedName = ""
        advertisedNameRevision += 1

        // Straight back up on a new key, the way a first launch comes up.
        do {
            let identity = try await identityVault.createIdentity()
            await bringUp(identity, minted: true)
            // The erase dropped the position the core held; a phone still
            // sharing shares it again without waiting to move.
            if phoneSharesLocation, let lastPosition {
                positions?.yield(lastPosition)
            }
        } catch is CancellationError {
            return
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    /// Forget every preference this phone has accumulated, so the next
    /// launch reads the same defaults a fresh install reads.
    ///
    /// Named explicitly rather than swept by prefix: the list is what a
    /// "start over" promises to reset, and a key added later should have to
    /// be considered rather than caught.
    private static func eraseStoredPreferences() {
        let defaults = UserDefaults.standard
        for key in [
            "onboarding.completed",
            "phone.discoverable",
            "phone.shareLocation",
            "phone.locationPrecision",
            "phone.advertIntervalSeconds",
            "phone.beaconIntervalSeconds",
            "phone.floodHops",
            "phone.beaconFloodHops",
            "radio.connectedUUID",
            "radio.shouldAutoConnect",
            "radio.lastAttachedPeripheral",
            "radio.deviceName",
            "map.tier",
            "map.capabilities",
            "peers.sort",
        ] {
            defaults.removeObject(forKey: key)
        }
    }

    func saveAdvertisedName(_ name: String) async -> AppOperationResult {
        guard let owner = localIdentity?.id else {
            return .failure(.unavailable("The local identity is unavailable."))
        }
        do {
            let saved = try await identityOperations.saveName(name, owner: owner)
            guard localIdentity?.id == owner else { return .failure(.cancelled) }
            // What the core kept is the name; none kept reads as none.
            let held = try? await read { try $0.state(conversationsOnly: true).advertisedName }
            advertisedName = held ?? saved
            advertisedNameRevision += 1
            return .success(())
        } catch { return .failure(AppOperationError.storage(error)) }
    }

    /// Broadcast a signed identity advertisement.
    func advertiseIdentity() async throws {
        try await ask { try await $0.advertiseIdentity() }
    }

    /// This phone's link: carrying its signed identity while the identity
    /// runs, otherwise the bare address.
    func identityShareURI() async -> String {
        guard let localIdentity else { return "" }
        if let uri = try? await core?.identityShareUri() { return uri }
        let address = localIdentity.publicIdentity.canonicalAddress
        return (try? nodeUriForAddress(address: address)) ?? localIdentity.publicIdentity.nodeURI
    }
}
