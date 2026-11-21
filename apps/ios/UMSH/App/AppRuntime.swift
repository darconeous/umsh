import CoreLocation
import Foundation
import Observation
import OSLog
import UIKit
import UMSHMobileCore

/// The messaging pipeline, alive for the whole process whether or not a
/// scene ever connects.
///
/// iOS launches this app into the background with no scene at all—for
/// CoreBluetooth state restoration today, and for notification actions
/// later—and everything a background launch needs lives here: the
/// identity, the app core's changes, the queries over its store, and what
/// the phone says about them. The core runs the mesh; this side holds the
/// identity's custody, the preferences, the location readings and the
/// words. Views observe this object and call into it; nothing in it
/// presents UI or assumes a scene exists.
@MainActor
@Observable
final class AppRuntime {

    private static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AppRoot")
    /// Chat has its own category because it is the part with a queue in it:
    /// composing, transmitting and applying happen on separate schedules, so
    /// a stuck message is only diagnosable from the sequence.
    private static let chatLogger = Logger(subsystem: "com.voria.umsh.ios", category: "Chat")

    /// A runtime over `opened`'s core and store, or, when they could not be
    /// opened, one that says why.
    init(
        radioConnection: any RadioConnection,
        opened: Result<AppCoreHost.Opened, any Error>,
        channelKeyVault: any SecretVault,
        isStaging: Bool = false,
        identityVault: (any IdentityVault)? = nil
    ) {
        let meshEngine = RustMeshEngine()
        self.meshEngine = meshEngine
        self.identityVault = identityVault ?? KeychainIdentityVault(meshEngine: meshEngine)
        self.radioConnection = radioConnection
        self.channelKeyVault = channelKeyVault
        self.isStaging = isStaging
        switch opened {
        case let .success(opened):
            core = opened.core
            applicationStore = opened.store
            applicationStoreError = nil
        case let .failure(error):
            core = nil
            applicationStore = nil
            applicationStoreError = error
        }
        identityOperations = IdentityOperations(
            vault: self.identityVault,
            knowsIdentity: { [applicationStore] identity in
                guard let applicationStore else { throw AppOperationError.unavailable("The database is unavailable.") }
                return try await applicationStore.knowsIdentity(id: identity.id, publicAddress: identity.publicIdentity.canonicalAddress)
            },
            // The core keeps the name: as a store write before it starts,
            // and pushed to the mesh session once it runs.
            persistName: { [core] _, name in
                guard let core else { throw AppOperationError.unavailable("The database is unavailable.") }
                try await core.setAdvertisedName(name: name ?? "")
            }
        )
        drafts = ConversationDraftStore { [applicationStore] key, text in
            guard let applicationStore else { throw AppOperationError.unavailable("The database is unavailable.") }
            switch key.kind {
            case .direct:
                try await applicationStore.updateDraft(ownerIdentityID: key.owner, conversationID: key.id, text: text)
            case .channel:
                try await applicationStore.updateChannelDraft(ownerIdentityID: key.owner, conversationID: key.id, text: text)
            }
        }
    }

    // MARK: - Observed pipeline state

    // Internal setters on purpose: the root view derives Bindings from
    // these (via @Bindable) for the child views that mutate summaries in
    // place.
    var radioSnapshot = RadioSnapshot.idle
    /// The app core's lifecycle, as it last reported it.
    private(set) var lifecycle: MobileAppLifecycle = .idle
    /// A failure nothing on screen can retry, for the root view to say once.
    var failureNotice: FailureNotice?
    /// Add Peer's contact exchange, as the core reports it; nil while none
    /// is open.
    var meet: MobileMeetStateRecord?
    /// The addresses of the direct conversations whose next message goes
    /// under a session with forward secrecy, as the core reports them.
    var forwardSecretConversations: Set<String> = []
    /// The peer the last exchange produced, recorded unsaved, for Add Peer
    /// to open. Shown while that exchange is; Add Peer clears it once it
    /// has.
    var exchangedPeer: PeerSummary?
    /// Add Peer is on screen with the app in the foreground, so the
    /// exchange runs whenever the radio can carry it.
    private var meetWanted = false
    var localIdentity: LocalIdentitySnapshot? {
        // The core answers queries for its owner, so it follows whichever
        // identity is current.
        didSet {
            guard localIdentity?.id != oldValue?.id else { return }
            do {
                try core?.setOwner(ownerIdentityId: localIdentity?.id)
            } catch {
                Self.logger.error("The core did not take the owner: \(String(describing: error), privacy: .public)")
            }
        }
    }
    var identityError: IdentityVaultError?
    var isLoadingIdentity = true
    var peers: [PeerSummary] = []
    /// Every neighbor a repeater has reported to this phone, with the repeater
    /// that said so—nodes the map can place that this phone may never have
    /// heard itself.
    var neighborReports: [PeerRepeaterNeighborReport] = []
    var conversations: [DirectConversationSummary] = []
    var channelConversations: [ChannelConversationSummary] = []
    var channels: [ChannelSummary] = []
    /// Channels the radio's device identity holds that this phone has no key
    /// for, so they can be shown as present without being named.
    var unknownDeviceChannels: [UnknownDeviceChannel] = []
    var advertisedName = ""
    /// Bumped by every write of `advertisedName` other than a state reload's,
    /// so a reload whose read began before such a write leaves it standing.
    @ObservationIgnored private var advertisedNameRevision = 0
    /// Whether this launch owes the user an introduction. Set by
    /// ``settleOnboarding(mintedIdentity:)`` once the identity is known; the
    /// root view binds its first-run cover to it. State rather than a
    /// computation on purpose: the flow itself writes the name it asks for,
    /// and a condition that read that name back would pull the screen out
    /// from under the user mid-answer. On a scene-less background launch it
    /// sits inert until a scene appears to present it.
    var shouldPresentOnboarding = false
    /// An identity left in the Keychain by an install that is gone, waiting
    /// for someone to say whether this phone is still that node.
    ///
    /// Set only when the container holds nothing that belonged to it—a
    /// key with an anchor, or a key the database still knows, is this
    /// install's and is adopted without asking. Nothing is unlocked, no
    /// session is installed, and no identity is minted while this stands:
    /// answering it is what decides which of those happens.
    var orphanedIdentity: LocalIdentitySnapshot?
    /// Radios this phone left holding its identity as their host, other
    /// than the one attached now, most recent first. Each could still
    /// acknowledge for this phone; the core revokes them across the mesh
    /// from whichever radio this phone attaches next.
    private(set) var strandedRadios: [StoredClaimedRadio] = []
    /// Whether a revocation of ``strandedRadios`` is under way.
    private(set) var isRevokingClaimedRadios = false

    // MARK: - Dependencies

    let meshEngine: RustMeshEngine
    let channelKeyVault: any SecretVault
    /// The app core this runtime observes, over ``applicationStore``.
    /// `nil` exactly when the store is.
    let core: MobileAppCore?
    let applicationStore: SQLiteApplicationStore?
    /// Why ``applicationStore`` is nil, when it is. Every store call site
    /// degrades to a silent no-op without one, which renders as an account
    /// with no contacts and no way to add any—indistinguishable from real
    /// data loss. Keeping the reason lets the UI say what actually happened.
    let applicationStoreError: (any Error)?
    /// The one CoreLocation seam.
    let locationService = PhoneLocationService()
    /// The one region database, beside the location seam because the two
    /// are asked together: a place, and what covers it.
    let regionService = RegionService()
    private let identityVault: any IdentityVault
    var stateLoadError: AppOperationError?
    /// Whether the warning before sending on `EMERGENCY` has been certified
    /// since the app launched. Never kept: every launch asks again.
    var emergencyCertified = false
    private var failedReadAddress: String?
    private let identityOperations: IdentityOperations
    private let drafts: ConversationDraftStore
    private let radioConnection: any RadioConnection
    private let notificationService = ChatNotificationService.shared
    /// Whether this runtime runs against fabricated content in the staging
    /// store, in which case every start reseeds it. Always false outside
    /// debug builds, where nothing can set it.
    private let isStaging: Bool
    /// The last position handed to the core, kept so a new identity shares
    /// it at once rather than waiting for the phone to move.
    private var lastPosition: MobilePositionRecord?
    /// Mutable, non-visual bookkeeping. A reference type on purpose: the
    /// observation macro tracks assignments, not interior mutation, so
    /// updating it never invalidates a view.
    private let coordinator = AppStateCoordinator()

    // MARK: - Lifecycle

    /// The tasks and observers that live as long as this runtime does.
    private var tasks: [Task<Void, Never>] = []
    private var observers: [any NSObjectProtocol] = []
    /// The core's wakes, which the drain loop reads. Finished on detach.
    private var wakes: AsyncStream<Void>.Continuation?
    /// Positions on their way to the core, in the order they were read.
    private var positions: AsyncStream<MobilePositionRecord?>.Continuation?
    /// The cell size location readings are being taken for; nil while
    /// they are not.
    private var locationSharingPrecision: UInt8?
    /// A retry of a failed start under way.
    private var isRetryingStart = false
    /// Set by ``detach()``. A replaced runtime starts nothing more: no
    /// location readings, no seed, no core start. Work it already began
    /// still resumes after the detach, and checks this.
    private var isDetached = false
    #if DEBUG
    /// The staged seed this runtime began, which may still be writing.
    private var stagedSeed: Task<Void, Never>?
    #endif
    /// Each reason a start failed for that has been shown, so a retry that
    /// fails the same way says nothing new.
    private var shownStartFailures: Set<MobileAppStartFailure> = []
    /// Remote-management progress, by the operation it belongs to.
    private var progressHandlers: [UInt64: @Sendable (UInt32?) -> Void] = [:]
    /// The companion management screens listening for the radio's pushes.
    private var pushListeners: [UUID: AsyncStream<PropertyPushEvent>.Continuation] = [:]

    /// Attach to the core, then bring the identity up.
    ///
    /// Called once per runtime, by whoever owns it. The listener is set
    /// before anything can start the core, so nothing it reports goes
    /// unread.
    func start() {
        guard tasks.isEmpty else { return }
        // Installed before anything async: a notification reply action can
        // be the very reason this process exists, delivered the moment
        // didFinishLaunching returns.
        notificationService.installReplyHandler { [weak self] conversationAddress, text in
            guard let self else { return false }
            return await self.deliverNotificationReply(
                conversationAddress: conversationAddress,
                text: text
            )
        }
        attachToCore()
        tasks.append(Task { await self.regionService.load() })
        installObservers()
        tasks.append(Task {
            // The policy first: the core drops a position it is not yet
            // told to share, and starts on whatever policy it holds.
            await self.pushPolicy()
            self.applyLocationSharing()
            await self.loadIdentity()
        })
    }

    /// Stop everything this runtime subscribed to.
    ///
    /// Leaves the core and its radio running: a runtime is replaced only
    /// when a debug toggle picks a different radio, and its successor
    /// attaches to the same core or to a new one. A drain under way
    /// finishes, so a batch it already took is not lost; the successor's
    /// listener replaces this one's.
    func detach() {
        isDetached = true
        notificationService.clearReplyHandler()
        drafts.stop()
        coordinator.pendingReload?.cancel()
        coordinator.runningReload?.cancel()
        for task in tasks { task.cancel() }
        tasks.removeAll()
        wakes?.finish()
        wakes = nil
        positions?.finish()
        positions = nil
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
        observers.removeAll()
        for listener in pushListeners.values { listener.finish() }
        pushListeners.removeAll()
        locationSharingPrecision = nil
        locationService.stop()
    }

    /// Become the core's listener, take its state as it stands, and start
    /// the loops that carry what it says next.
    private func attachToCore() {
        guard let core else { return }
        let (wakeStream, wakes) = AsyncStream.makeStream(
            of: Void.self,
            bufferingPolicy: .bufferingNewest(1)
        )
        self.wakes = wakes
        core.setListener(listener: CoreWake(wakes))
        if let status = try? core.status() {
            apply(status)
        }
        let (positionStream, positions) = AsyncStream.makeStream(of: MobilePositionRecord?.self)
        self.positions = positions
        // One at a time, so the core holds the latest.
        tasks.append(Task {
            for await position in positionStream {
                do {
                    try await core.setLocation(position: position)
                } catch {
                    Self.logger.debug("Position not taken: \(String(describing: error), privacy: .public)")
                }
            }
        })
        // Not among `tasks`: detach lets a drain under way finish. A wake
        // buffered before the detach still arrives after it, and is left
        // for the successor's drain.
        Task {
            for await _ in wakeStream {
                guard self.wakes != nil else { break }
                await self.drain()
            }
        }
        // A wake that came before this listener is not raised again.
        wakes.yield()
    }

    private func installObservers() {
        let center = NotificationCenter.default
        // The identity is read once at launch, and a launch is not always
        // a moment when it can be read: iOS relaunches the app in the
        // background for a radio event, and before the phone's first unlock
        // the Keychain refuses the item outright. Without this the process
        // would run to its end with no identity—no mesh session, and a
        // radio parked on a host decision the app cannot make. It fires
        // while still in the background, so the phone being unlocked is
        // enough to finish starting and attach. A start that failed is
        // retried on the same occasions.
        observers.append(center.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.retryIdentityLoadIfNeeded() }
            }
        })
        // The other end of the same recovery: a phone unlocked by opening
        // the app rather than before it.
        observers.append(center.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.retryIdentityLoadIfNeeded() }
                // Schedules that came due while the phone slept go now.
                self.core?.resumed()
                // A claim lapses with time, which the core does not announce.
                Task { await self.reloadStrandedRadios() }
                // A radio that attached while the app was in the background
                // could not have asked for notification permission there.
                if self.radioSnapshot.linkState == .attached {
                    self.notificationService.requestAuthorizationIfNeeded()
                }
            }
        })
        // The policy is settings, and a runtime outlives the screen that
        // edits them. The keys contain dots, which rules out key-value
        // observing, so this watches every defaults write. The core compares
        // the policy whole, so an unrelated write costs a comparison.
        observers.append(center.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task {
                    await self.pushPolicy()
                    self.applyLocationSharing()
                }
            }
        })
    }

    // MARK: - The core's changes

    /// Apply one batch of what the core changed. One loop runs these in
    /// turn, so two never overlap.
    private func drain() async {
        guard let core else { return }
        // A background wake gives a short grace window; this keeps iOS from
        // suspending the app before what the batch says is posted.
        let assertion = UIApplication.shared.beginBackgroundTask(withName: "umsh.core.changes")
        defer {
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
        let changes = core.pollChanges()
        if let lifecycle = changes.lifecycle {
            apply(lifecycle)
        }
        if let radio = changes.radio {
            apply(RadioSnapshot(radio))
        }
        for push in changes.propertyPushes {
            publish(.push(push))
        }
        if changes.propertyPushesDropped > 0 {
            publish(.resync)
        }
        for progress in changes.operationProgress {
            progressHandlers[progress.operation]?(progress.remaining)
        }
        if let addresses = changes.forwardSecretConversations,
           Set(addresses) != forwardSecretConversations {
            forwardSecretConversations = Set(addresses)
        }
        if changes.meetChanged {
            applyMeet(changes.meet)
        }
        if let revoking = changes.revokingClaimedRadios, revoking != isRevokingClaimedRadios {
            isRevokingClaimedRadios = revoking
        }
        // Before the lists publish: the reload is what carries a bumped
        // revision to an open transcript.
        var transcripts = Set(changes.transcripts)
        if changes.allTranscripts {
            // A change the core could not place. Refreshing every open
            // transcript costs one bounded query; not refreshing the right
            // one leaves it showing something that is no longer true.
            transcripts.formUnion(conversations.map(\.conversationAddress))
            transcripts.formUnion(channelConversations.map(\.conversationAddress))
        }
        if !transcripts.isEmpty {
            coordinator.bumpChatRevisions(transcripts)
        }
        if changes.peersChanged || changes.channelsChanged || changes.exchangedPeer != nil {
            await reloadApplicationState()
        } else if changes.conversationsChanged || !transcripts.isEmpty {
            await reloadConversationState()
        }
        if changes.lifecycle == .running {
            // From the lists just reloaded: `running` comes with the
            // channels the start wrote.
            await refreshChannelAddresses()
        }
        if changes.claimedRadiosChanged || changes.radio != nil {
            await reloadStrandedRadios()
        }
        if let address = changes.exchangedPeer, case .exchanged? = meet?.exchange {
            exchangedPeer = peers.first { $0.identity.canonicalAddress == address }
        }
        for notification in changes.notifications {
            post(notification)
        }
        if changes.notificationsDropped > 0 {
            Self.logger.notice(
                "\(changes.notificationsDropped, privacy: .public) notification(s) were not posted"
            )
        }
    }

    /// Take the core's state as it stands, on attaching to it.
    private func apply(_ status: MobileAppStatusRecord) {
        apply(status.lifecycle)
        apply(status.radio.map(RadioSnapshot.init) ?? .idle)
        forwardSecretConversations = Set(status.forwardSecretConversations)
        applyMeet(status.meet)
        isRevokingClaimedRadios = status.revokingClaimedRadios
    }

    private func apply(_ lifecycle: MobileAppLifecycle) {
        self.lifecycle = lifecycle
        guard case let .failed(reason) = lifecycle else { return }
        Self.logger.error("The core did not start: \(String(describing: reason), privacy: .public)")
        guard shownStartFailures.insert(reason).inserted else { return }
        failureNotice = FailureNotice(
            title: String(
                localized: "Couldn't start",
                comment: "Alert title: this phone's identity did not start. The message says why."
            ),
            message: reason.message
        )
    }

    private func apply(_ snapshot: RadioSnapshot) {
        // An equal write to an observed property still re-evaluates every
        // observer—the whole tab tree included.
        if radioSnapshot != snapshot {
            radioSnapshot = snapshot
        }
        if snapshot.linkState == .attached {
            // The first attach is the first moment a message notification
            // has concrete meaning.
            notificationService.requestAuthorizationIfNeeded()
        }
    }

    private func applyMeet(_ state: MobileMeetStateRecord?) {
        meet = state
        // The exchanged peer shows while its exchange does.
        if case .exchanged? = state?.exchange {} else {
            exchangedPeer = nil
        }
    }

    /// Hand the core the preferences it acts on. It compares the policy
    /// whole, so restating an unchanged one costs nothing.
    func pushPolicy() async {
        guard let core else { return }
        do {
            try await core.setPolicy(policy: currentPolicy)
        } catch {
            Self.logger.debug("Policy not taken: \(String(describing: error), privacy: .public)")
        }
    }

    /// Start or stop location readings to match the stored preference.
    ///
    /// The readings only need to be good to the disclosed cell, so the
    /// chosen precision sizes both the accuracy asked of CoreLocation and
    /// how far the phone must move before a new reading is sent. The core
    /// holds the one current position, reduces it to the cell, and
    /// withdraws it when sharing stops; the readings are this side's.
    private func applyLocationSharing() {
        guard !isDetached else { return }
        let precision = phoneSharesLocation ? UInt8(clamping: phoneLocationPrecision) : nil
        guard precision != locationSharingPrecision else { return }
        locationSharingPrecision = precision
        guard let precision else {
            locationService.stop()
            return
        }
        let cellMeters = LocationPresentation.cellMeters(precisionBytes: precision) ?? 40
        locationService.start(
            cellMeters: cellMeters,
            onReading: { reading in
                let position = MobilePositionRecord(reading)
                self.lastPosition = position
                self.positions?.yield(position)
            },
            onAuthorizationLost: {
                // Access revoked in iOS Settings while sharing: the last
                // position must not outlive the permission it was read
                // under. A later re-grant resumes readings on its own.
                self.lastPosition = nil
                self.positions?.yield(nil)
            }
        )
    }

    /// The radios still holding this phone's identity, as the core reads
    /// them.
    private func reloadStrandedRadios() async {
        let radios: [MobileStoredClaimedRadioRecord]
        do {
            radios = try await read { try $0.strandedRadios() }
        } catch MobileAppError.NoOwner {
            // No identity, so no radio holds it.
            radios = []
        } catch {
            // Busy or stopped: the list stands until the next change.
            return
        }
        let stranded = radios.map(StoredClaimedRadio.init)
        if stranded != strandedRadios {
            strandedRadios = stranded
        }
    }

    /// Ask each stranded radio again to let go of this phone.
    func retryClaimedRadioRevocation() async {
        do {
            try await core?.retryClaimedRadioRevocation()
        } catch {
            Self.logger.notice("Revocation not retried: \(String(describing: error), privacy: .public)")
        }
        await reloadStrandedRadios()
    }

    /// Values the companion radio announces on its own, for a screen
    /// managing it.
    private func companionPropertyPushes() -> AsyncStream<PropertyPushEvent> {
        // Pushes are sparse, and a lost one turns into a resync (`publish`).
        let (stream, continuation) = AsyncStream.makeStream(
            of: PropertyPushEvent.self,
            bufferingPolicy: .bufferingNewest(16)
        )
        let id = UUID()
        pushListeners[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { @MainActor in self?.pushListeners[id] = nil }
        }
        return stream
    }

    private func publish(_ event: PropertyPushEvent) {
        for listener in pushListeners.values {
            // A listener behind by a whole buffer lost the oldest push it
            // held; the resync after it says to read everything again.
            if case .dropped = listener.yield(event) {
                listener.yield(.resync)
            }
        }
    }

    /// The core's mesh session, fetched for each use; `nil` while the core
    /// is not running.
    private func meshSession() async -> MobileMeshSession? {
        try? await core?.meshSession()
    }

    /// The core's mesh session, for a command that cannot go without one.
    private func requireSession() async throws -> MobileMeshSession {
        guard let session = await meshSession() else { throw MobileMeshError.SessionUnavailable }
        return session
    }

    /// After a write the core did not make itself, or one a core command
    /// made without raising a change: let it re-derive what it keeps from
    /// the store, then read the lists again.
    private func afterWrite() async {
        if let core {
            do {
                try await core.contentChanged()
            } catch MobileAppError.NotRunning {
                // Not started yet: the start reads the store whole.
            } catch {
                Self.logger.debug("Content change not taken: \(String(describing: error), privacy: .public)")
            }
        }
        await reloadApplicationState()
    }

    // MARK: - Contact exchange

    /// Add Peer's contact exchange, for the views.
    var contactExchange: ContactExchange {
        ContactExchange(
            state: meet,
            ownModel: AppCoreHost.platformModel,
            radioReady: radioSnapshot.carriesThisPhone,
            exchangedPeer: exchangedPeer,
            setWanted: setMeetWanted,
            ask: askToExchange(device:),
            answer: answerExchange(accept:),
            confirm: confirmCode(same:),
            backOut: backOutOfExchange,
            openAgain: openMeetAgain
        )
    }

    /// Add Peer appeared or went, or the app came to or left the
    /// foreground with it showing. The core opens the exchange whenever the
    /// radio can carry it and closes it otherwise.
    func setMeetWanted(_ wanted: Bool) async {
        guard wanted != meetWanted else { return }
        meetWanted = wanted
        if !wanted {
            exchangedPeer = nil
        }
        do {
            try await core?.setMeetWanted(wanted: wanted)
        } catch {
            Self.logger.debug("Meet not settled: \(String(describing: error), privacy: .public)")
        }
    }

    func askToExchange(device: UInt32) async {
        _ = try? await core?.askToExchange(device: device)
    }

    /// Answers the device that asked; on Not now the core opens again under
    /// a new key. Views can call this after the question has gone (a card
    /// dismissing once the answer has moved the exchange on), so it checks
    /// that a device is still asking.
    func answerExchange(accept: Bool) async {
        guard meet?.exchange.askedBy != nil else { return }
        try? await core?.answerExchange(accept: accept)
    }

    func confirmCode(same: Bool) async {
        try? await core?.confirmCode(same: same)
    }

    /// Ends the attempt under way; the core opens a fresh one. Like
    /// answering, it checks the live state: the screen it backs out of can
    /// be leaving because the attempt is already over.
    func backOutOfExchange() async {
        guard meet?.exchange.isUnderWay == true else { return }
        try? await core?.backOutOfExchange()
    }

    /// Try again, after an attempt ended: the core counts an ended attempt
    /// as one to back out of, and backing out opens a fresh one.
    func openMeetAgain() async {
        exchangedPeer = nil
        try? await core?.backOutOfExchange()
    }

    // MARK: - Preferences

    // Read straight from UserDefaults: the runtime outlives any view, so it
    // cannot lean on @AppStorage. The fallback values mirror the view
    // layer's declarations exactly.

    /// Whether the user has been introduced to this phone's identity. Set
    /// when the first-run flow finishes, however it finishes.
    private var onboardingCompleted: Bool {
        get { UserDefaults.standard.bool(forKey: "onboarding.completed") }
        set { UserDefaults.standard.set(newValue, forKey: "onboarding.completed") }
    }

    /// Whether this phone answers nearby nodes' identity requests.
    private var phoneDiscoverable: Bool {
        UserDefaults.standard.object(forKey: "phone.discoverable") as? Bool ?? true
    }

    /// Whether this phone's identity carries its location, and at what
    /// cell size.
    private var phoneSharesLocation: Bool {
        UserDefaults.standard.bool(forKey: "phone.shareLocation")
    }

    /// Whether test messages on `EMERGENCY` call for attention like any
    /// other message. Off unless asked for.
    private var testMessageAlerts: Bool {
        UserDefaults.standard.bool(forKey: "notifications.testMessages")
    }

    private var phoneLocationPrecision: Int {
        UserDefaults.standard.object(forKey: "phone.locationPrecision") as? Int ?? 5
    }

    /// How far what this phone sends may travel: the ceiling on messages,
    /// pings, and requests, and the budget on a scheduled beacon. Held to
    /// what the flood-hop field can carry, so a stray stored value cannot
    /// make the session refuse the whole setting.
    private var phoneFloodHops: UInt8 {
        Self.floodHops(UserDefaults.standard.object(forKey: "phone.floodHops"), fallback: 10)
    }

    private var phoneBeaconFloodHops: UInt8 {
        Self.floodHops(UserDefaults.standard.object(forKey: "phone.beaconFloodHops"), fallback: 5)
    }

    private static func floodHops(_ stored: Any?, fallback: UInt8) -> UInt8 {
        guard let value = stored as? Int, let hops = UInt8(exactly: value) else { return fallback }
        return min(hops, 15)
    }

    /// The preferences the core acts on, as it takes them.
    private var currentPolicy: MobileAppPolicyRecord {
        let defaults = UserDefaults.standard
        // How often this phone announces itself unasked, in seconds, with 0
        // for never. Both default to off: a radio is deployed to be part of
        // the mesh, but a phone is carried, and putting its identity on the
        // air on a timer is a decision rather than a default.
        return MobileAppPolicyRecord(
            advertIntervalSeconds: UInt32(clamping: defaults.integer(forKey: "phone.advertIntervalSeconds")),
            beaconIntervalSeconds: UInt32(clamping: defaults.integer(forKey: "phone.beaconIntervalSeconds")),
            discoverable: phoneDiscoverable,
            floodHops: phoneFloodHops,
            beaconFloodHops: phoneBeaconFloodHops,
            locationPrecision: phoneSharesLocation ? UInt8(clamping: phoneLocationPrecision) : nil,
            testMessageAlerts: testMessageAlerts
        )
    }

    /// The first-run flow finished, however it finished.
    func completeOnboarding() {
        onboardingCompleted = true
        shouldPresentOnboarding = false
    }

    // MARK: - Action bundles

    /// The one set of peer operations every peer sheet gets, wherever it is
    /// opened from. Built here because this is the only place that holds the
    /// store, the radio, and the mesh engine together.
    var peerActions: PeerActions {
        PeerActions(
            knownPeers: peers,
            startConversation: startConversation,
            ping: pingPeer,
            fetchIdentity: fetchIdentity,
            updateAlias: updateAlias,
            loadRoute: peerRoute,
            resetRoute: clearPeerRoute,
            identifyRepeater: identifyRepeater(_:precededBy:),
            cachedPeerRepeaters: cachedPeerRepeaters,
            loadPeerRepeaters: loadPeerRepeaters(_:cursor:),
            loadPeerRepeatersAlong: { peer, cursor, route in
                await self.loadPeerRepeaters(peer, cursor: cursor, route: route)
            },
            radioIdentityPeer: radioSnapshot.deviceIdentity.flatMap { identity in
                peers.first { $0.identity.canonicalAddress == identity.canonicalAddress }
            },
            setManualPath: setManualPath,
            clearManualPath: clearManualPath,
            adoptLearnedPath: adoptLearnedPath,
            keepManualPath: keepManualPath,
            learnedPathOffer: learnedPathOffer,
            pingAlongPath: { peer, path in await self.pingPeer(peer, along: path) },
            parseRouterHint: { text, format in
                await self.meshEngine.parseRouterHintInput(text, format: format)
            },
            renderRouterHint: { bytes in try? await self.meshEngine.renderRouterHint(bytes) },
            setFavorite: setPeerFavorite,
            setNotifyWhenHeard: setPeerNotifyWhenHeard,
            setConversationNotifications: setConversationNotifications,
            promoteToSaved: promotePeerToSaved,
            demoteToTransient: demotePeerToTransient,
            deletePeer: deletePeer,
            deletePeerAndConversation: deletePeerAndConversation,
            manageDevice: { [companionAddress = radioSnapshot.deviceIdentity?.canonicalAddress]
                peer in
                // The attached companion is managed over its own link;
                // everyone else—a stale "companion" row from a radio
                // since replaced included—across the mesh.
                peer.identity.canonicalAddress == companionAddress
                    ? self.companionDeviceManagement
                    : self.remoteDeviceManagement
            },
            manageCompanion: { self.companionDeviceManagement }
        )
    }

    /// Managing another node across the mesh, as the peer screen needs it.
    ///
    /// Handed over whether or not a radio is attached: every one of these
    /// reports its own unreachability, and a Manage Device that appears and
    /// disappears with the radio is one an operator cannot find when they
    /// need it.
    var remoteDeviceManagement: DeviceManagementBackend {
        DeviceManagementBackend(
            fetch: { address, properties, multiHint, progress in
                try await self.manage(progress: progress) { core, operation in
                    try await core.remoteFetch(
                        operation: operation,
                        address: address,
                        propertyIds: properties,
                        multiHint: multiHint
                    )
                }
            },
            write: { address, writes in
                try await self.manage { core, operation in
                    try await core.remoteWrite(operation: operation, address: address, writes: writes)
                }
            },
            save: { address in
                try await self.manage { core, operation in
                    try await core.remoteSave(operation: operation, address: address)
                }
            },
            setAdministrator: { address, key, present in
                try await self.manage { core, operation in
                    try await core.remoteSetAdmin(
                        operation: operation,
                        address: address,
                        publicKey: key,
                        present: present
                    )
                }
            },
            setPeer: { address, key, present in
                try await self.manage { core, operation in
                    try await core.remoteSetPeer(
                        operation: operation,
                        address: address,
                        publicKey: key,
                        present: present
                    )
                }
            },
            insertNetwork: { address, item in
                try await self.manage { core, operation in
                    try await core.remoteSetWifiNetwork(
                        operation: operation,
                        address: address,
                        item: item,
                        present: true
                    )
                }
            },
            removeNetwork: { address, ssid in
                try await self.manage { core, operation in
                    try await core.remoteSetWifiNetwork(
                        operation: operation,
                        address: address,
                        item: ssid,
                        present: false
                    )
                }
            },
            setAlert: { address, state in
                RadioAlertState(try await self.manage { core, operation in
                    try await core.remoteSetAlert(operation: operation, address: address, state: state.wire)
                })
            },
            reset: { address, scope in
                try await self.manage { core, operation in
                    try await core.remoteReset(operation: operation, address: address, scope: scope)
                }
            },
            enterDfu: { address, mode in
                try await self.manage { core, operation in
                    try await core.remoteEnterDfu(operation: operation, address: address, mode: mode)
                }
            },
            announce: { address, request in
                try await self.manage { core, operation in
                    try await core.remoteAnnounce(operation: operation, address: address, request: request)
                }
            },
            clearBluetoothBonds: { address in
                try await self.manage { core, operation in
                    try await core.remoteClearBonds(operation: operation, address: address)
                }
            },
            // This phone's own key, which is what a managed device sees
            // requests arrive from: the stored identity is the same bytes.
            phoneNodeKey: {
                try? await self.read { try $0.phoneNodeKey() }
            },
            // Without an owner these read empty and write nowhere, which
            // costs a fetch on every open rather than breaking anything.
            loadCard: { address in
                (try? await self.read { try $0.managementCard(publicAddress: address) })?
                    .map(StoredManagementCard.init)
            },
            saveCard: { address, card in
                let record = MobileStoredManagementCardRecord(card)
                _ = try? await self.read { try $0.saveManagementCard(publicAddress: address, card: record) }
            },
            forgetCache: { address in
                _ = try? await self.read { try $0.forgetManagementCache(publicAddress: address) }
            },
            loadValues: { address, properties in
                (try? await self.read {
                    try $0.cachedProperties(publicAddress: address, propertyIds: properties)
                })?.mapValues(StoredCachedProperty.init) ?? [:]
            },
            saveValues: { address, values in
                _ = try? await self.read { try $0.saveCachedProperties(publicAddress: address, values: values) }
            }
        )
    }

    /// Run one remote-management command under an operation of its own.
    ///
    /// Its progress reaches `progress`, and canceling the calling task
    /// cancels it in the core, which stops the mesh retrying a request
    /// nobody is waiting on. The core's codes become the errors the
    /// management screens read.
    private func manage<Value>(
        progress: (@Sendable (UInt32?) -> Void)? = nil,
        _ command: (MobileAppCore, MobileOperation) async throws -> Value
    ) async throws -> Value {
        guard let core else { throw MobileAppError.Stopped }
        let operation = MobileOperation()
        let id = operation.id()
        progressHandlers[id] = progress
        defer { progressHandlers[id] = nil }
        do {
            return try await withTaskCancellationHandler {
                try await command(core, operation)
            } onCancel: {
                operation.cancel()
            }
        } catch let error as MobileAppError {
            throw Self.managementError(error)
        }
    }

    /// The core's management codes as the screens' own errors; anything
    /// else stays the core's, and is said by its presenter.
    private static func managementError(_ error: MobileAppError) -> any Error {
        switch error {
        case .NoAnswer: RemoteManagementError.noAnswer
        case .Unreachable: RemoteManagementError.unreachable
        case let .Refused(status): RemoteManagementError.refused(status: status)
        case .Unreadable: RemoteManagementError.unreadable
        case .Cancelled: CancellationError()
        case .DfuUnsupported: DfuEntryError.unsupported
        case let .DfuRefused(status): DfuEntryError.refused(status)
        case .DfuUnconfirmed: DfuEntryError.unconfirmed
        default: error
        }
    }

    /// Managing the companion radio itself, over its own link.
    ///
    /// The mesh backend with the transport swapped out: same store, same
    /// cache rows—the radio is the same node by public address—but
    /// every exchange goes over the local link, refreshes are cheap enough
    /// to run on sight, and the radio's own announcements stream in as
    /// pushes.
    var companionDeviceManagement: DeviceManagementBackend {
        var management = remoteDeviceManagement
        management.link = .companion
        management.usesBluetooth = radioConnection is CoreBluetoothRadioConnection
        management.fetch = { _, properties, _, _ in
            try await self.radioConnection.fetchCompanionProperties(properties)
        }
        management.write = { _, writes in
            try await self.radioConnection.writeCompanionProperties(writes)
        }
        management.save = { _ in
            try await self.radioConnection.saveCompanionDevice()
        }
        management.enterDfu = { _, mode in
            try await self.radioConnection.enterDfu(mode: mode)
        }
        management.setAdministrator = { _, key, present in
            present
                ? try await self.radioConnection.addDeviceAdmin(key)
                : try await self.radioConnection.removeDeviceAdmin(key)
        }
        management.setPeer = { _, key, present in
            present
                ? try await self.radioConnection.addDevicePeer(key)
                : try await self.radioConnection.removeDevicePeer(key)
        }
        management.insertNetwork = { _, item in
            try await self.radioConnection.addDeviceWifiNetwork(item)
        }
        management.removeNetwork = { _, ssid in
            try await self.radioConnection.removeDeviceWifiNetwork(ssid: ssid)
        }
        management.setAlert = { _, state in
            // The local write answers on the session snapshot rather than
            // inline; what was asked for stands until the radio's own
            // announcement—which arrives as a push—corrects it.
            try await self.radioConnection.setAlert(state)
            return state
        }
        // The radio itself, over its own link: both commands already have
        // local paths, and neither goes near the mesh.
        management.reset = { _, scope in
            switch scope {
            case .reboot:
                try await self.radioConnection.reboot()
            case .factory:
                try await self.radioConnection.factoryReset()
            case .protocol, .restore:
                // Neither is offered by any screen this backend serves;
                // the local link has `refreshRadio` for the first and no
                // use for the second.
                throw RemoteManagementError.unavailable
            }
        }
        management.announce = { _, request in
            try await self.radioConnection.announce(request)
        }
        // Clearing bonds severs this very link—the bond it arrived on is
        // one of the bonds forgotten—so it goes over the local path
        // rather than out onto the mesh and back.
        management.clearBluetoothBonds = { _ in
            try await self.radioConnection.clearBluetoothBonds()
        }
        management.propertyPushes = { self.companionPropertyPushes() }
        // The cache rows hang off the radio's node, so a radio with no
        // identity of its own has nowhere to keep them. Over its own link
        // a fresh read costs next to nothing, so it simply goes uncached.
        if radioSnapshot.deviceIdentity == nil {
            management.loadCard = { _ in nil }
            management.saveCard = { _, _ in }
            management.forgetCache = { _ in }
            management.loadValues = { _, _ in [:] }
            management.saveValues = { _, _ in }
        }
        return management
    }

    /// The channel operations the Channels tab is built from, assembled here
    /// for the same reason as `peerActions`.
    ///
    /// Opening the conversation a channel leads to is navigation, which is
    /// the view's business rather than the pipeline's, so the caller passes
    /// what to do with the conversation this resolves.
    func channelActions(
        enterConversation: @escaping (ChannelConversationSummary?) -> Void
    ) -> ChannelActions {
        ChannelActions(
            preview: previewChannel,
            join: joinChannel,
            rejoin: { channel in
                await self.setChannelPhoneMembership(channel, joined: true)
            },
            leave: leaveChannel,
            createPrivate: createPrivateChannel,
            updateDetails: updateChannelDetails,
            setDeviceMembership: setChannelDeviceMembership,
            invitation: channelInvitation,
            revealKey: { channel in
                try? self.channelKeyVault.loadKey(channelID: channel.id)
            },
            enterConversation: { channel in
                enterConversation(await self.startChannelConversation(channel))
            },
            parseRegion: { text in try? await self.meshEngine.regionCode(from: text) },
            describeRegion: { code in try? await self.meshEngine.regionDescription(code) }
        )
    }

    // MARK: - Identity

    @MainActor
    private func loadIdentity() async {
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
            // No `running` will come to derive them from: derive them
            // from the lists just read.
            await refreshChannelAddresses()
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
    private func retryIdentityLoadIfNeeded() async {
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
            localized: "Couldn't erase",
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
            // An erase is refused while a start runs, and the secret is
            // already gone: the erase follows the start however long it
            // takes. Giving up would leave the session running as the
            // erased identity under the new one about to be minted.
            while true {
                do {
                    try await core.erase(alsoContent: alsoErasingContent)
                } catch MobileAppError.Busy {
                    try? await Task.sleep(for: .milliseconds(200))
                    continue
                } catch let error as MobileAppError {
                    Self.logger.error("The core did not erase everything: \(String(describing: error), privacy: .public)")
                    failureNotice = FailureNotice(title: failureTitle, message: error.message)
                } catch {
                    Self.logger.error("The core did not erase everything: \(String(describing: error), privacy: .public)")
                }
                break
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

    /// Broadcast a signed identity advertisement. Returns a user-facing
    /// failure message, or nil on success.
    func advertiseIdentity() async -> String? {
        guard let core else { return MobileAppError.Stopped.message }
        do {
            try await core.advertiseIdentity()
            return nil
        } catch let error as MobileAppError {
            return error.message
        } catch {
            return MobileAppError.SendFailed.message
        }
    }

    /// The shareable identity URI: bundle-bearing (name, role, capabilities,
    /// signed) when the mesh session can sign, bare public key otherwise.
    func identityShareURI() async -> String {
        guard let localIdentity else { return "" }
        let bare = localIdentity.publicIdentity.nodeURI
        let name = advertisedName.isEmpty ? nil : advertisedName
        guard let session = await meshSession(),
              let bundle = try? await session.signIdentityBundle(
                  name: name,
                  timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
              ),
              let uri = try? nodeUriWithIdentity(
                  address: localIdentity.publicIdentity.canonicalAddress,
                  identityPayload: bundle
              )
        else { return bare }
        return uri
    }

    func connectRadio() async {
        do {
            try await radioConnection.connect()
        } catch {
            // Connection failures are published as radio snapshots so every
            // screen presents the same state and recovery action.
        }
    }

    func reconnectRadio() async {
        await radioConnection.reconnect()
    }

    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        await radioConnection.discoverRadios()
    }

    func selectRadio(_ id: UUID) async throws {
        try await radioConnection.selectRadio(id)
    }

    func stopRadioDiscovery() async {
        await radioConnection.stopDiscovery()
    }

    func disconnectRadio() async {
        await radioConnection.disconnect()
    }

    func forgetRadio() async {
        await radioConnection.forget()
    }

    func factoryResetRadio() async throws {
        try await radioConnection.factoryReset()
    }

    func rebootRadio() async throws {
        try await radioConnection.reboot()
    }

    func claimRadio() async {
        do {
            try await radioConnection.claimForCurrentIdentity()
        } catch {
            // The adapter publishes a shared failure snapshot when an active
            // claim fails. Preconditions leave the existing snapshot intact.
        }
    }

    /// Ask the radio for its state again. The answer reaches the screen
    /// the way every radio state does, through the core.
    func refreshRadio() async {
        _ = try? await radioConnection.refresh()
    }

    /// Sample the radio's position, for a screen that is showing one.
    ///
    /// Failures are swallowed on purpose: this runs on a timer behind a
    /// view, and a radio that walked out of range mid-poll is a state the
    /// link already reports. An error banner per missed sample would say
    /// the same thing once a minute.
    func refreshRadioPosition() async {
        _ = try? await radioConnection.refreshPositioning()
    }

    func inspectPeerIdentity(_ input: String) async -> Result<MeshNodeURIPreview, MeshEngineError> {
        do {
            return .success(try await meshEngine.inspectPeerIdentity(input))
        } catch let error as MeshEngineError {
            return .failure(error)
        } catch {
            return .failure(.coreFailure)
        }
    }

    func savePeer(
        _ preview: MeshNodeURIPreview,
        details: PeerImportDetails,
        startConversation: Bool
    ) async -> DirectConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        let identity = preview.publicIdentity
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: identity.canonicalAddress,
                alias: details.alias,
                advertisedName: preview.identity?.name,
                // The role comes from the bundle, not the operator. An
                // imported payload is only ever handed over with a verified
                // signature, so it needs no MAC authentication to be believed.
                isSaved: true,
                nodeKind: preview.identity.map { PeerRole(roleCode: $0.roleCode).storedKind },
                advertisement: preview.identityPayload
            )
            if startConversation {
                _ = try await applicationStore.ensureDirectConversation(
                    ownerIdentityID: localIdentity.id,
                    peerAddress: identity.canonicalAddress
                )
            }
            // Best effort, for the same reason as in `startConversation`: the
            // peer and any conversation are already on disk, and a core that
            // is not running must not turn that into a failed import.
            try? await meshSession()?.registerPeers(peers: [
                MobilePeerRegistrationRecord(
                    address: identity.canonicalAddress,
                    mobile: preview.identity?.capabilityBits.contains(.mobile) == true
                )
            ])
            await afterWrite()
            return conversations.first { $0.peer.identity.canonicalAddress == identity.canonicalAddress }
        } catch {
            return nil
        }
    }

    /// The stored row for the node a link names, so its peer page has a row
    /// to act on.
    ///
    /// A node this phone has never come across is recorded unsaved, carrying
    /// whatever identity the link did, the same tier a node heard over the
    /// air lands in. Saving it stays the operator's call, made on that page.
    /// A node already on file is returned as it stands: a link's bundle is no
    /// fresher than what was heard. `nil` when there is nothing to record it
    /// in, and for this phone's own address, which is not a peer.
    func peer(forLink preview: MeshNodeURIPreview) async -> PeerSummary? {
        let address = preview.publicIdentity.canonicalAddress
        if let known = peers.first(where: { $0.identity.canonicalAddress == address }) {
            return known
        }
        guard let applicationStore, let localIdentity,
              address != localIdentity.publicIdentity.canonicalAddress
        else { return nil }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: address,
                alias: nil,
                advertisedName: preview.identity?.name,
                nodeKind: preview.identity.map { PeerRole(roleCode: $0.roleCode).storedKind },
                advertisement: preview.identityPayload
            )
            // No retention pass here: a row never heard is the oldest-heard
            // there is, so a full tier would evict it before its page opened.
            await afterWrite()
            return peers.first { $0.identity.canonicalAddress == address }
        } catch {
            return nil
        }
    }

    /// Record a device the phone has been configuring as an ordinary peer.
    ///
    /// Deliberately not a chat peer: a repeater is infrastructure the operator
    /// wants to find again, not someone to talk to. Starting a conversation
    /// with it remains an ordinary Peers action.
    func saveAdministeredDevice(
        _ identity: MeshPublicIdentity,
        name: String?,
        role: PeerRole
    ) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: identity.canonicalAddress,
                alias: nil,
                advertisedName: name,
                isSaved: true,
                nodeKind: role.storedKind
            )
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    private func updateAlias(_ peer: PeerSummary, _ alias: String?) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.updateNodeAlias(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress,
                alias: alias
            )
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    private func setPeerFavorite(_ peer: PeerSummary, _ favorite: Bool) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.setPeerFavorite(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress,
                isFavorite: favorite
            )
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    /// Arm or disarm the one-shot watch on a node.
    ///
    /// Arming asks for a notification, so it is also the moment to make sure
    /// the app can post one: a watch set on a phone that has never been asked
    /// about notifications would come due and produce nothing.
    private func setPeerNotifyWhenHeard(_ peer: PeerSummary, _ armed: Bool) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.setNotifyWhenHeard(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress,
                enabled: armed
            )
            if armed { notificationService.requestAuthorizationIfNeeded() }
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    private func promotePeerToSaved(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.promotePeerToSaved(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            )
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    /// Take a peer off the local identity while keeping its row, history, and
    /// searchability. The mesh session keeps the peer registered when a
    /// conversation exists—chat continuity is the point of demoting.
    private func demotePeerToTransient(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.demotePeerToTransient(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            )
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    private func deletePeer(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            guard try await applicationStore.deletePeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            ) else { return false }
            await removeMeshPeer(peer)
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    private func deletePeerAndConversation(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            guard try await applicationStore.deletePeerAndConversation(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            ) else { return false }
            await removeMeshPeer(peer)
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    /// Best-effort removal from the mesh session behind a store delete. A
    /// core that is not running is not an error: the store is the
    /// authority, and the next start registers peers from it.
    private func removeMeshPeer(_ peer: PeerSummary) async {
        try? await meshSession()?.removePeers(peerAddresses: [peer.identity.canonicalAddress])
    }

    // MARK: - Channels

    /// Resolve typed input—a public channel name or a pasted `umsh:cs:` /
    /// `umsh:ck:` URI—into a preview, with whatever local context the user
    /// needs to see before committing.
    private func previewChannel(_ input: String) async -> Result<ChannelPreview, MeshEngineError> {
        do {
            return .success(ChannelPreview(try await read { try $0.previewChannel(input: input) }))
        } catch MobileAppError.InvalidInput(let error) {
            return .failure(RustMeshEngine.inputError(error, invalidURI: .invalidChannelURI))
        } catch {
            return .failure(.coreFailure)
        }
    }

    /// Join on the phone identity, or update local details when the key is
    /// already held. Registering with the mesh session is what actually
    /// makes traffic arrive; the core gives the radio the key behind it.
    private func joinChannel(
        _ preview: MeshChannelPreview,
        details: ChannelDetails
    ) async -> ChannelActionOutcome {
        guard let applicationStore, let localIdentity else { return .failed }
        let digest = channelKeyDigest(key: preview.key)
        do {
            if let existing = try await storedChannel(keyDigest: digest) {
                _ = await updateChannelDetails(existing, details: details)
                if !existing.joinedPhone {
                    return await setChannelPhoneMembership(existing, joined: true)
                }
                await afterWrite()
                return .success
            }

            let id = UUID()
            // The key goes to the Keychain first: a row whose key cannot be
            // read is a channel that silently does nothing.
            try channelKeyVault.storeKey(preview.key, channelID: id)
            let channel = StoredChannel(
                id: id,
                ownerIdentityID: localIdentity.id,
                kind: preview.kind == .namedPublic ? .named : .privateKey,
                canonicalName: preview.canonicalName,
                // The channel's own name comes from the invitation or what was
                // typed; the alias is this user's override on top of it.
                name: preview.displayName,
                alias: details.alias,
                channelIDHex: Self.hex(preview.channelID),
                tint: preview.tint,
                regionCode: details.regionCode ?? preview.regionCode,
                maxFloodHops: details.maxFloodHops ?? preview.maxFloodHops.map(Int.init),
                joinedPhone: true,
                joinedDevice: false,
                notificationsEnabled: details.notificationsEnabled,
                joinedAt: Date()
            )
            do {
                try await applicationStore.insertChannel(channel, keyDigest: digest)
            } catch {
                try? channelKeyVault.deleteKey(channelID: id)
                throw error
            }
            let registered = await registerChannels([
                ChannelRegistration(key: preview.key, maxFloodHops: channel.maxFloodHops),
            ])
            guard registered else {
                try? await applicationStore.deleteChannel(id: id)
                try? channelKeyVault.deleteKey(channelID: id)
                return .phoneFull
            }
            // Derived here, from the key in hand, because the address map is
            // otherwise only rebuilt at session start—without this entry,
            // "Enter Conversation" and inbound traffic cannot find the
            // channel until the app relaunches.
            if let address = try? await meshEngine.channelConversationAddress(key: preview.key) {
                coordinator.channelAddresses[id] = address
            }
            await afterWrite()
            return .success
        } catch {
            return .failed
        }
    }

    /// Create a private channel from a freshly generated key.
    private func createPrivateChannel(
        name: String,
        details: ChannelDetails
    ) async -> ChannelActionOutcome {
        let key = await meshEngine.generateChannelKey()
        guard let channelID = try? await meshEngine.deriveChannelID(key: key),
              let tint = try? await meshEngine.deriveChannelTint(key: key)
        else {
            return .failed
        }
        return await joinChannel(
            MeshChannelPreview(
                kind: .privateKey,
                canonicalName: nil,
                key: key,
                channelID: channelID,
                tint: tint,
                displayName: name,
                maxFloodHops: details.maxFloodHops.map(UInt8.init),
                regionCode: details.regionCode
            ),
            details: details
        )
    }

    /// Leave on the phone identity. A private channel's key cannot be
    /// recovered afterwards, so its row and key are deleted together; a named
    /// or built-in channel keeps its row so it can be offered again.
    private func leaveChannel(_ channel: ChannelSummary) async -> ChannelActionOutcome {
        guard let applicationStore, let localIdentity else { return .failed }
        let key = try? channelKeyVault.loadKey(channelID: channel.id)
        // The group chat cannot outlive membership: without the key there is
        // nothing to send with, and nothing further will arrive.
        if let conversation = channelConversations.first(where: { $0.channel.id == channel.id }) {
            try? await applicationStore.deleteChannelConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
        }
        coordinator.channelAddresses[channel.id] = nil
        do {
            if channel.kind == .builtin {
                try await applicationStore.setChannelMembership(
                    id: channel.id,
                    joinedPhone: false,
                    joinedDevice: channel.joinedDevice
                )
            } else if channel.joinedDevice {
                // Still joined on the device: keep the row and the key, since
                // removing it from the device later needs the key as selector.
                try await applicationStore.setChannelMembership(
                    id: channel.id,
                    joinedPhone: false,
                    joinedDevice: true
                )
            } else {
                try await applicationStore.deleteChannel(id: channel.id)
                try? channelKeyVault.deleteKey(channelID: channel.id)
            }
        } catch {
            return .failed
        }
        // After the store: the core registers again whatever the store
        // still says is joined.
        if let key {
            try? await meshSession()?.removeChannels(keys: [key])
        }
        await afterWrite()
        return .success
    }

    private func setChannelPhoneMembership(
        _ channel: ChannelSummary,
        joined: Bool
    ) async -> ChannelActionOutcome {
        guard let applicationStore,
              let key = try? channelKeyVault.loadKey(channelID: channel.id)
        else { return .failed }
        if joined {
            guard await registerChannels([
                ChannelRegistration(key: key, maxFloodHops: channel.maxFloodHops),
            ]) else { return .phoneFull }
        }
        do {
            try await applicationStore.setChannelMembership(
                id: channel.id,
                joinedPhone: joined,
                joinedDevice: channel.joinedDevice
            )
        } catch {
            return .failed
        }
        if !joined {
            // After the store, as in `leaveChannel`.
            try? await meshSession()?.removeChannels(keys: [key])
        }
        // The address map is otherwise only rebuilt when the core starts,
        // and leaving cleared this entry—a rejoin that skipped it would
        // leave the channel unreachable from chat until relaunch.
        if joined, let address = try? await meshEngine.channelConversationAddress(key: key) {
            coordinator.channelAddresses[channel.id] = address
        } else if !joined {
            coordinator.channelAddresses[channel.id] = nil
        }
        if joined, channel.canonicalName == "public", let localIdentity,
           let address = coordinator.channelAddresses[channel.id] {
            // Rejoining public restores its always-present conversation,
            // the same invariant the core's start establishes. Before the
            // core is told, so its pass reads the row.
            _ = try? await applicationStore.ensureChannelConversation(
                ownerIdentityID: localIdentity.id,
                channelID: channel.id,
                conversationAddress: address
            )
        }
        await afterWrite()
        return .success
    }

    /// Add or remove the channel on the companion radio's own device identity,
    /// which is membership for the radio, not for this phone.
    private func setChannelDeviceMembership(
        _ channel: ChannelSummary,
        joined: Bool
    ) async -> ChannelActionOutcome {
        guard let applicationStore,
              let key = try? channelKeyVault.loadKey(channelID: channel.id)
        else { return .failed }
        do {
            if joined {
                try await radioConnection.addDeviceChannel(key)
            } else {
                try await radioConnection.removeDeviceChannel(key)
            }
            try? await applicationStore.setChannelMembership(
                id: channel.id,
                joinedPhone: channel.joinedPhone,
                joinedDevice: joined
            )
            await afterWrite()
            return .success
        } catch let error as DevicePeerError {
            return switch error {
            case .radioUnavailable: .radioUnavailable
            case .deviceFull: .deviceFull
            case .unsupported: .unsupported
            case .unrecognizedAnswer: .unrecognizedAnswer
            case .failed: .failed
            }
        } catch {
            return .failed
        }
    }

    private func updateChannelDetails(
        _ channel: ChannelSummary,
        details: ChannelDetails
    ) async -> Bool {
        guard let applicationStore else { return false }
        do {
            try await applicationStore.updateChannelDetails(
                id: channel.id,
                alias: details.alias,
                regionCode: details.regionCode,
                maxFloodHops: details.maxFloodHops,
                notificationsEnabled: details.notificationsEnabled
            )
            // The ceiling lives in the mesh session's channel table, so a
            // changed one is re-registered—re-registering a held channel
            // restates it. A channel the phone has not joined has no entry
            // to restate; joining registers it with whatever is stored.
            if channel.joinedPhone, details.maxFloodHops != channel.maxFloodHops,
               let key = try? channelKeyVault.loadKey(channelID: channel.id) {
                _ = await registerChannels([
                    ChannelRegistration(key: key, maxFloodHops: details.maxFloodHops),
                ])
            }
            await afterWrite()
            return true
        } catch {
            return false
        }
    }

    /// Toggle a channel's banners from inside its conversation, where the
    /// question actually comes up. Everything else the user set stays put:
    /// this is one field of the same local details the Channels tab edits.
    /// The same switch decides, through the core, whether a companion radio
    /// holding this channel's traffic makes a sound about it.
    func setChannelNotifications(_ channel: ChannelSummary, _ enabled: Bool) async {
        _ = await updateChannelDetails(
            channel,
            details: ChannelDetails(
                alias: channel.alias,
                regionCode: channel.regionCode,
                maxFloodHops: channel.maxFloodHops,
                notificationsEnabled: enabled
            )
        )
    }

    /// Toggle a direct conversation's banners, from the same sheet the
    /// channel switch lives in—and, through the mute tables, whether a
    /// companion radio chirps when it takes one of these messages in for a
    /// phone that is away.
    func setConversationNotifications(
        _ conversation: DirectConversationSummary,
        _ enabled: Bool
    ) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.setDirectConversationNotifications(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id,
                enabled: enabled
            )
            await afterWrite()
        } catch {
            // The toggle re-reads the store, so a failed write shows the
            // old value rather than a lie.
        }
    }

    /// Build the URI that invites someone else to this channel. A named
    /// channel shares only its name; a private one shares the key itself.
    ///
    /// The name goes out written the way it is read—`umsh:cs:Trail%20Crew`,
    /// not the folded form. Recipients percent-decode first and canonicalize
    /// after, so casing travels without changing which channel is meant.
    private func channelInvitation(_ channel: ChannelSummary) async -> String? {
        guard let key = try? channelKeyVault.loadKey(channelID: channel.id) else {
            return nil
        }
        // The alias is this phone's label and stays here; what goes out is the
        // channel's own name.
        let sharedName = channel.name ?? channel.canonicalName
        return try? await meshEngine.formatChannelInvitation(
            key: key,
            name: channel.invitationIsSecret ? nil : sharedName,
            displayName: channel.invitationIsSecret ? channel.name : nil,
            // A protocol-fixed ceiling is not a recommendation to pass on: the
            // recipient derives it from the channel exactly as this phone did.
            maxFloodHops: channel.protocolMaxFloodHops == nil
                ? channel.maxFloodHops.map(UInt8.init)
                : nil,
            regionCode: channel.regionCode
        )
    }

    private func storedChannel(keyDigest: String) async throws -> ChannelSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        let stored = try await applicationStore.channel(
            ownerIdentityID: localIdentity.id,
            keyDigest: keyDigest
        )
        return stored.map { ChannelSummary($0) }
    }

    /// Register channels with the phone's mesh session, reporting whether
    /// they all fit. With no session running there is nothing to fit into
    /// yet: the core registers every joined channel when it starts.
    private func registerChannels(_ channels: [ChannelRegistration]) async -> Bool {
        guard !channels.isEmpty, let session = await meshSession() else { return true }
        do {
            try await session.registerChannels(channels: channels.map(\.record))
            return true
        } catch {
            return false
        }
    }

    /// Derive each joined channel's conversation address once, so the rest of
    /// the app can match a record to a channel without touching Keychain.
    private func refreshChannelAddresses() async {
        var addresses: [UUID: String] = [:]
        for channel in channels where channel.joinedPhone {
            guard let key = try? channelKeyVault.loadKey(channelID: channel.id),
                  let address = try? await meshEngine.channelConversationAddress(key: key)
            else { continue }
            addresses[channel.id] = address
        }
        coordinator.channelAddresses = addresses
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// One broadcast Identity Request for the Discover sheet: matching nodes
    /// reply with their identities, which the core records. Returns whether
    /// the request was handed to the radio.
    ///
    /// Without a vantage it is zero-hop, answered by nodes in this phone's own
    /// range. With one it is steered down that route and answered by whatever
    /// is in range of where it lands.
    func solicitNearbyIdentities(
        _ roleFilter: PeerRole?,
        _ vantage: SolicitVantage?
    ) async -> Bool {
        guard radioSnapshot.linkState == .attached,
              radioSnapshot.hostState == .matchesCurrentIdentity,
              let session = await meshSession()
        else { return false }
        do {
            try await session.discoverIdentities(
                roleCode: roleFilter?.roleCode,
                capabilityBits: nil,
                nodeHint: nil,
                sourceRoute: vantage?.repeaters ?? []
            )
            return true
        } catch {
            return false
        }
    }

    /// Ask one repeater named by a route who it is.
    ///
    /// A repeater consumes its own hint while forwarding rather than while
    /// receiving, so a request whose route still names it is one it drops.
    /// The ask is steered to the hop *before* it—`precedingRepeaters`, which
    /// is empty for a first hop, since that one is in direct range by
    /// construction—and narrowed to the repeater's own hint, so it is the
    /// only node in that neighborhood that answers.
    private func identifyRepeater(
        _ hint: Data,
        precededBy precedingRepeaters: [Data]
    ) async -> Bool {
        guard radioSnapshot.linkState == .attached,
              radioSnapshot.hostState == .matchesCurrentIdentity,
              let session = await meshSession()
        else { return false }
        do {
            try await session.discoverIdentities(
                roleCode: nil,
                capabilityBits: nil,
                nodeHint: hint,
                sourceRoute: precedingRepeaters
            )
            return true
        } catch {
            return false
        }
    }

    /// Drop every transient row nothing depends on, from the Discover
    /// sheet's overflow. Saved peers, conversations, device-identity rows,
    /// and the companion radio are untouched by the store's guards.
    func clearDiscoveredNodes() async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.clearTransientPeers(ownerIdentityID: localIdentity.id)
        await afterWrite()
    }

    @discardableResult
    func updateDraft(_ conversationID: Int64, _ text: String) async -> AppOperationResult {
        guard let owner = localIdentity?.id else {
            return .failure(.unavailable("The local identity is unavailable."))
        }
        let key = ConversationDraftKey(owner: owner, kind: .direct, id: conversationID)
        let result = await drafts.save(text, for: key)
        guard localIdentity?.id == owner else { return .failure(.cancelled) }
        if let index = conversations.firstIndex(where: { $0.id == conversationID }) {
            // Retain unsaved text in memory, without reporting persistence success.
            conversations[index].draftText = drafts.pendingText(for: key) ?? text
        }
        return result
    }

    /// Send what was typed in `conversation`, under forward secrecy as
    /// `forwardSecret` says the composer showed it; where nothing showed
    /// it, as a notification's reply, under it as a session is held.
    func sendMessage(
        _ conversation: ConversationListItem,
        _ body: String,
        forwardSecret: Bool? = nil
    ) async -> MessageSendResult {
        await performChatCompose(
            conversation,
            clearsDraft: true,
            .typed(text: body, forwardSecret: forwardSecret)
        )
    }

    /// Send a reply typed into a notification, on the phone or a paired
    /// watch.
    ///
    /// Runs with no scene, often in a process the reply action itself just
    /// launched: bootstrap and the radio link are awaited, briefly, rather
    /// than assumed. A reply that cannot go out is never queued for later—
    /// a compose that fails after persisting shows as the transcript's
    /// `.failed` state as always, and one the radio guard refuses outright
    /// lands in the conversation's draft with a failure notification saying
    /// so. Either way the text is somewhere the user can see and act on.
    func deliverNotificationReply(conversationAddress: String, text: String) async -> Bool {
        // A cold launch is still opening the store and reading the identity.
        await waitUntil(timeout: .seconds(10)) {
            self.applicationStore != nil && self.localIdentity != nil
        }
        var item = conversationItem(for: conversationAddress)
        if item == nil {
            await reloadApplicationState()
            item = conversationItem(for: conversationAddress)
        }
        guard let item else {
            notificationService.postReplyFailure(
                conversationAddress: conversationAddress,
                displayName: "UMSH"
            )
            return false
        }
        // A radio behind a background wake can still be dialing; give the
        // link the launch it is already making before giving up on it.
        await waitUntil(timeout: .seconds(15)) {
            self.lifecycle == .running
                && self.radioSnapshot.linkState == .attached
                && self.radioSnapshot.hostState == .matchesCurrentIdentity
        }
        switch await sendMessage(item, text) {
        case .sent:
            return true
        case .cancelled:
            return false
        case let .failed(reason):
            Self.chatLogger.warning(
                "Notification reply not sent: \(reason, privacy: .public)"
            )
            await preserveUndeliveredReply(item, text)
            notificationService.postReplyFailure(
                conversationAddress: conversationAddress,
                displayName: item.title
            )
            return false
        }
    }

    /// Keep the text of a reply that never reached the compose pipeline.
    /// Appended under any draft already sitting there rather than replacing
    /// it—both are words the user typed and has not sent.
    private func preserveUndeliveredReply(_ item: ConversationListItem, _ text: String) async {
        let existing = item.draftText
        let combined = existing.isEmpty ? text : existing + "\n" + text
        switch item {
        case let .direct(conversation):
            await updateDraft(conversation.id, combined)
        case let .channel(conversation):
            await updateChannelDraft(conversation.id, combined)
        }
    }

    private func conversationItem(for conversationAddress: String) -> ConversationListItem? {
        if Self.isChannelAddress(conversationAddress) {
            return channelConversations
                .first { $0.conversationAddress == conversationAddress }
                .map(ConversationListItem.channel)
        }
        return conversations
            .first { $0.peer.identity.canonicalAddress == conversationAddress }
            .map(ConversationListItem.direct)
    }

    /// Wait for a main-actor condition to hold, or for the deadline. The
    /// states involved—bootstrap fields, the radio snapshot—publish no
    /// completion signal to await, and a coarse poll is enough for the two
    /// launch-scale waits a notification reply performs.
    private func waitUntil(timeout: Duration, _ condition: () -> Bool) async {
        let deadline = ContinuousClock.now + timeout
        while !condition(), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(200))
        }
    }

    func editMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ newBody: String
    ) async -> MessageSendResult {
        guard message.isWithinReviseWindow else {
            return .failed("This message is too old to edit.")
        }
        return await performChatCompose(
            conversation,
            clearsDraft: false,
            .edit(original: originalRef(message), body: newBody)
        )
    }

    /// Put a message delivery gave up on back on the air, as itself.
    ///
    /// Its unacknowledged fragments go again from the archive, under its
    /// original wire ID: a peer who received it and lost only the
    /// acknowledgment drops the duplicate, and one who never received it gets
    /// an ordinary message, notification and all. Never an edit, which a peer
    /// without the original could only show as an edit of something unknown.
    /// The core reports the frames ahead of any word of them, and the store
    /// re-aims the row's delivery tracking at them, so the badge clears—or
    /// comes back—on the resend's real fate.
    ///
    /// `forwardSecret` is the user's choice for a message that went under
    /// forward secrecy: under it, the core uses the session held or asks the
    /// peer for a new one and the frames wait on it; without it, they go now
    /// and the row says so.
    func resendMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ forwardSecret: Bool
    ) async -> MessageSendResult {
        // Past the revise window the original's wire ID could not land
        // anywhere; give the caller the behavior that is right for the
        // message's age instead of an error.
        guard message.isWithinReviseWindow, let wireID = message.wireID else {
            return await resendMessageAsNew(conversation, message, forwardSecret)
        }
        guard message.isDeliveryFailed else {
            return .failed("Only a message that was not delivered can be resent.")
        }
        if let refusal = chatSendRefusal(conversation) { return refusal }
        guard let applicationStore, let localIdentity else {
            return .failed("The local identity or message database is unavailable.")
        }
        do {
            let frames = try await applicationStore.chatResendFrames(
                ownerIdentityID: localIdentity.id,
                conversationAddress: conversation.conversationAddress,
                sessionID: message.sessionID,
                handle: message.handle,
                wireID: wireID
            )
            guard !frames.isEmpty else {
                return await resendMessageAsNew(conversation, message, forwardSecret)
            }
            try await requireSession().resendChat(
                conversationAddress: conversation.conversationAddress,
                original: originalRef(message),
                frames: frames,
                forwardSecret: forwardSecret
            )
        } catch MobileMeshError.ChatResendNotInPlace {
            // The stream has moved on past it: only new words can still land.
            return await resendMessageAsNew(conversation, message, forwardSecret)
        } catch let error as MobileMeshError {
            return .failed(ChatSubmissionCoordinator.composeError(error).localizedDescription)
        } catch {
            return .failed(error.localizedDescription)
        }
        coordinator.bumpChatRevisions([conversation.conversationAddress])
        await reloadConversationState()
        let updated = conversationItems.first(where: { $0.id == conversation.id }) ?? conversation
        return .sent(updated, warning: nil)
    }

    /// Send a failed message's text again as a genuinely new message—the
    /// path for failures that can no longer go as themselves: their wire ID
    /// has slid out of the reference window peers keep, or nothing of them
    /// is archived under it.
    ///
    /// The old row is removed only after the new compose is durable and
    /// released; a compose that fails leaves the transcript exactly as it
    /// was. On success the failed bubble disappears and the same words
    /// arrive at the bottom as the newest message—a fresh wire identity
    /// with its own delivery tracking. A peer who did receive the original
    /// will see it twice; at this age, the resend being asked for is
    /// literally "send these words again."
    func resendMessageAsNew(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ forwardSecret: Bool
    ) async -> MessageSendResult {
        guard message.isDeliveryFailed else {
            return .failed("Only a message that was not delivered can be resent.")
        }
        let result = await performChatCompose(
            conversation,
            clearsDraft: false,
            .again(body: message.body, status: message.isStatus, forwardSecret: forwardSecret)
        )
        guard case .sent = result else { return result }
        if let applicationStore, let localIdentity {
            do {
                try await applicationStore.removeFailedMessage(
                    ownerIdentityID: localIdentity.id,
                    sessionID: message.sessionID,
                    handle: message.handle
                )
                coordinator.bumpChatRevisions([conversation.conversationAddress])
                await reloadApplicationState()
            } catch {
                // The new message is on its way regardless; the worst case is
                // the old red bubble lingering above it.
                Self.chatLogger.error(
                    "Could not remove a resent failed message: \(String(describing: error), privacy: .public)"
                )
            }
        }
        return result
    }

    func deleteMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary
    ) async -> MessageSendResult {
        await performChatCompose(
            conversation,
            clearsDraft: false,
            .delete(original: originalRef(message))
        )
    }

    /// React to a message, or withdraw the reaction already on it when the
    /// user taps the glyph they already chose. Replacing one is just another
    /// reaction: the newest from a sender is the one that counts, so there is
    /// nothing to retract first.
    func reactToMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ glyph: String
    ) async -> MessageSendResult {
        guard !message.isDeliveryFailed else {
            return .failed("This message was not delivered, so there is nothing to react to.")
        }
        let withdrawing = message.myReaction?.glyph == glyph
        let body = withdrawing ? "" : ReactionEmoji.token(for: glyph)
        return await performChatCompose(
            conversation,
            clearsDraft: false,
            .reaction(target: regardingRef(message), body: body)
        )
    }

    /// Send `body` in reply to `message`. Where the original can no longer
    /// be named the text goes as a plain message, as it does from a
    /// communicator. It goes under forward secrecy as `forwardSecret` says
    /// the composer showed it.
    func replyToMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ body: String,
        _ forwardSecret: Bool
    ) async -> MessageSendResult {
        await performChatCompose(
            conversation,
            clearsDraft: true,
            .reply(target: regardingRef(message), body: body, forwardSecret: forwardSecret)
        )
    }

    /// Ask for missing messages no repair is under way for, one request
    /// each; the engine paces them. A gap the engine no longer holds, one
    /// left by an earlier mesh session, can never be asked for, so it is
    /// resolved as unavailable rather than left to be tapped again.
    func requestMissingMessages(
        _ conversation: ConversationListItem,
        _ messages: [ChatMessageSummary]
    ) async -> MessageSendResult {
        if let refusal = uncertifiedEmergencyRefusal(conversation) { return refusal }
        guard let applicationStore, let localIdentity else {
            return .failed("The local identity or message database is unavailable.")
        }
        guard radioSnapshot.linkState == .attached,
              radioSnapshot.hostState == .matchesCurrentIdentity
        else { return .failed("Connect a companion radio configured for this phone before sending.") }
        var lost: [ChatMessageSummary] = []
        for message in messages where message.isGapIdle {
            do {
                let held = try await requireSession().requestChatRepair(
                    sessionId: UInt64(message.sessionID) ?? 0,
                    handle: message.handle
                )
                if !held { lost.append(message) }
            } catch {
                return .failed(error.localizedDescription)
            }
        }
        if !lost.isEmpty {
            do {
                try await applicationStore.resolveGapsUnavailable(
                    ownerIdentityID: localIdentity.id,
                    rows: lost.map { ($0.sessionID, $0.handle) }
                )
            } catch {
                return .failed(error.localizedDescription)
            }
            coordinator.bumpChatRevisions([conversation.conversationAddress])
        }
        await reloadConversationState()
        let updated = conversationItems.first(where: { $0.id == conversation.id }) ?? conversation
        return .sent(updated)
    }

    /// A transmission on `EMERGENCY` refused because its warning has not been
    /// certified since launch. The thread view asks first; this catches
    /// what has no screen to ask on, such as a reply from a notification.
    private func uncertifiedEmergencyRefusal(_ conversation: ConversationListItem) -> MessageSendResult? {
        guard case let .channel(item) = conversation, item.channel.isEmergency, !emergencyCertified else {
            return nil
        }
        let channelName = "EMERGENCY"
        return .failed(String(
            localized: "Open the conversation to send on \(channelName).",
            comment: "Why a reply from a notification was not sent: the channel's warning must be certified in the app first. The placeholder is the channel's name, EMERGENCY, which is not translated."
        ))
    }

    /// The engine accepts either the live handle (same facade session) or
    /// the persisted wire identity (after an app restart); send both and let
    /// Rust pick, so the transcript never has to care which run composed a
    /// message.
    private func originalRef(_ message: ChatMessageSummary) -> MobileChatOriginalRef {
        MobileChatOriginalRef(
            sessionId: UInt64(message.sessionID) ?? 0,
            handle: message.handle,
            wireId: message.wireID,
            epoch: message.epoch
        )
    }

    /// The same idea as ``originalRef(_:)``, but for a message that may be
    /// either party's: the direction says whose stream the wire ID belongs
    /// to, and the hint says whose within a channel group.
    private func regardingRef(_ message: ChatMessageSummary) -> MobileChatRegardingRef {
        MobileChatRegardingRef(
            sessionId: UInt64(message.sessionID) ?? 0,
            handle: message.handle,
            wireId: message.wireID,
            direction: message.isOutbound ? .outbound : .inbound,
            senderHint: message.senderHint,
            epoch: message.epoch
        )
    }

    /// Why nothing can go on the air in this conversation right now, or
    /// `nil` when something can.
    private func chatSendRefusal(_ conversation: ConversationListItem) -> MessageSendResult? {
        if let refusal = uncertifiedEmergencyRefusal(conversation) { return refusal }
        guard radioSnapshot.linkState == .attached,
              radioSnapshot.hostState == .matchesCurrentIdentity
        else { return .failed("Connect a companion radio configured for this phone before sending.") }
        return nil
    }

    private func performChatCompose(
        _ conversation: ConversationListItem,
        clearsDraft: Bool,
        _ request: MobileChatSendRequest
    ) async -> MessageSendResult {
        if let refusal = chatSendRefusal(conversation) { return refusal }
        guard applicationStore != nil, let localIdentity else {
            return .failed("The local identity or message database is unavailable.")
        }
        let owner = localIdentity.id
        let draftKey: ConversationDraftKey
        switch conversation {
        case let .direct(item): draftKey = .init(owner: owner, kind: .direct, id: item.id)
        case let .channel(item): draftKey = .init(owner: owner, kind: .channel, id: item.id)
        }
        let submittedDraft = drafts.latestText(for: draftKey) ?? conversation.draftText
        let outcome = await ChatSubmissionCoordinator().submit(
            send: {
                try await self.requireSession().sendChat(
                    conversationAddress: conversation.conversationAddress,
                    request: request
                )
            },
            didChange: {
                self.coordinator.bumpChatRevisions([conversation.conversationAddress])
                await self.reloadConversationState()
            },
            clearDraft: {
                guard clearsDraft else { return }
                try await self.drafts.clear(for: draftKey, preserving: submittedDraft)
            }
        )
        switch outcome {
        case let .failed(error):
            if error == .cancelled { return .cancelled }
            return .failed(error.localizedDescription)
        case let .submitted(warning):
            await reloadConversationState()
            let updated = conversationItems.first(where: { $0.id == conversation.id }) ?? conversation
            // Only the submission's own cleanup failure is a send warning: it
            // is the one case where the composer must keep its text. A reload
            // failure is reported by the root view's banner, and repeating it
            // here would hold a sent message in the composer as a draft.
            return .sent(updated, warning: warning?.localizedDescription)
        }
    }

    /// Every conversation, both kinds, most recent traffic first.
    ///
    /// A channel with newer messages belongs above a quiet direct chat, so the
    /// two are ordered together rather than grouped.
    var conversationItems: [ConversationListItem] {
        let items = conversations.map(ConversationListItem.direct)
            + channelConversations.map(ConversationListItem.channel)
        return items.sorted { first, second in
            if first.lastActivityMilliseconds != second.lastActivityMilliseconds {
                return first.lastActivityMilliseconds > second.lastActivityMilliseconds
            }
            return first.title.localizedCaseInsensitiveCompare(second.title) == .orderedAscending
        }
    }

    /// Open a channel's group conversation, creating it the first time.
    func startChannelConversation(
        _ channel: ChannelSummary
    ) async -> ChannelConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        guard let address = coordinator.channelAddresses[channel.id] else { return nil }
        do {
            _ = try await applicationStore.ensureChannelConversation(
                ownerIdentityID: localIdentity.id,
                channelID: channel.id,
                conversationAddress: address
            )
            await afterWrite()
            return channelConversations.first { $0.channel.id == channel.id }
        } catch {
            Self.logger.error(
                "Could not open channel conversation: \(String(describing: error), privacy: .public)"
            )
            return nil
        }
    }

    /// Open the conversation for a channel that was just joined, resolving
    /// the freshly stored row from the key the invitation carried.
    func startConversationAfterJoin(
        _ preview: MeshChannelPreview
    ) async -> ChannelConversationSummary? {
        await refreshChannelAddresses()
        guard let channel = (try? await storedChannel(keyDigest: channelKeyDigest(key: preview.key)))
            ?? nil
        else { return nil }

        return await startChannelConversation(channel)
    }

    func deleteChannelConversation(_ conversation: ChannelConversationSummary) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.deleteChannelConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
            await afterWrite()
        } catch {
            Self.logger.error(
                "Could not delete channel conversation \(conversation.id): \(String(describing: error), privacy: .public)"
            )
        }
    }

    @discardableResult
    func updateChannelDraft(_ conversationID: Int64, _ text: String) async -> AppOperationResult {
        guard let owner = localIdentity?.id else {
            return .failure(.unavailable("The local identity is unavailable."))
        }
        let key = ConversationDraftKey(owner: owner, kind: .channel, id: conversationID)
        let result = await drafts.save(text, for: key)
        guard localIdentity?.id == owner else { return .failure(.cancelled) }
        if let index = channelConversations.firstIndex(where: { $0.id == conversationID }) {
            // Retain unsaved text in memory, without reporting persistence success.
            channelConversations[index].draftText = drafts.pendingText(for: key) ?? text
        }
        return result
    }

    /// Mark a conversation read. Driven by the transcript appearing, so the
    /// badge clears when the user actually looks at it.
    func markConversationRead(_ address: String) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.markConversationRead(
                ownerIdentityID: localIdentity.id, conversationAddress: address)
            if failedReadAddress == address {
                failedReadAddress = nil
                stateLoadError = nil
            }
            await reloadConversationState()
        } catch {
            failedReadAddress = address
            stateLoadError = .persistence("The conversation could not be marked as read. Open it again to retry.")
        }
    }

    func retryStateLoad() async {
        if let failedReadAddress { await markConversationRead(failedReadAddress) }
        else { await reloadApplicationState() }
    }

    func requestMemberIdentity(
        _ conversation: ChannelConversationSummary,
        _ hint: Data
    ) async {
        try? await meshSession()?.requestIdentityByHint(
            conversationAddress: conversation.conversationAddress,
            hint: hint
        )
    }

    /// Erase a conversation's transcript, keeping the conversation. Local
    /// only: nothing is sent, so everyone else keeps their copy.
    ///
    /// Addressed rather than keyed by row so one path serves both kinds, and
    /// `@Sendable` because it is handed to views as a bare closure.
    @Sendable
    func clearConversationMessages(_ address: String) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.clearConversationMessages(
                ownerIdentityID: localIdentity.id,
                conversationAddress: address
            )
            coordinator.bumpChatRevisions([address])
            await reloadApplicationState()
        } catch {
            Self.logger.error(
                "Could not clear conversation messages: \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// Bounded transcript reads for whichever thread view is open.
    ///
    /// The window lives in the thread view rather than here: the ordinary way
    /// into a transcript is a navigation destination the app root never sees,
    /// so hoisting it would mean tracking push and pop for no other reason.
    var transcriptLoader: TranscriptLoader {
        TranscriptLoader(
            newest: newestTranscriptPage,
            older: olderTranscriptPage,
            newer: newerTranscriptPage,
            around: focusedTranscriptPage
        )
    }

    @Sendable
    private func newestTranscriptPage(_ address: String, _ limit: Int) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptNewest(conversationAddress: address, limit: UInt32(clamping: limit))
        } ?? .empty
    }

    @Sendable
    private func olderTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ limit: Int
    ) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptBefore(
                conversationAddress: address,
                cursor: MobileStoredChatCursorRecord(cursor),
                limit: UInt32(clamping: limit)
            )
        } ?? .empty
    }

    @Sendable
    private func newerTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ including: Bool,
        _ limit: Int
    ) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptAfter(
                conversationAddress: address,
                cursor: MobileStoredChatCursorRecord(cursor),
                including: including,
                limit: UInt32(clamping: limit)
            )
        } ?? .empty
    }

    @Sendable
    private func focusedTranscriptPage(
        _ address: String,
        _ messageID: String,
        _ radius: Int
    ) async -> TranscriptPage? {
        guard let reference = MobileStoredChatMessageRefRecord(messageID: messageID) else { return nil }
        // A failed read and a missing message mean the same thing to the
        // caller: this message is not somewhere the transcript can go.
        return await transcriptPage {
            try $0.transcriptAround(
                conversationAddress: address,
                message: reference,
                radius: UInt32(clamping: radius)
            )
        }
    }

    /// One bounded transcript read, mapped for display; `nil` when it could
    /// not be made.
    private func transcriptPage(
        _ query: @escaping @Sendable (MobileAppCore) throws -> MobileAppTranscriptPageRecord?
    ) async -> TranscriptPage? {
        guard let record = try? await read(query) else { return nil }
        return TranscriptPage(record, peers: peers)
    }

    #if DEBUG
    /// Rewrite the staged mesh, when this root is the staging one.
    ///
    /// Runs before every start rather than only on a first launch, because
    /// the staged timeline is written relative to now: reseeding is what
    /// keeps the newest message reading "4 minutes ago" in a screenshot
    /// taken next month. Every write is keyed, so repeating it replaces
    /// rather than accumulates.
    private func seedStagedContentIfNeeded(owner: String) async {
        guard isStaging, !isDetached, let applicationStore else { return }
        // Kept, because canceling does not stop it: the seed writes in
        // several steps, and an erase of the staged store must not land
        // between them.
        let seed = Task { [channelKeyVault] in
            do {
                try await seedStaging(
                    store: applicationStore.coreStore,
                    vault: channelKeyVault,
                    ownerIdentityId: owner,
                    nowMs: Date.now.storeMilliseconds
                )
            } catch {
                Self.logger.error(
                    "Could not seed staged content: \(String(describing: error), privacy: .public)"
                )
            }
        }
        stagedSeed = seed
        await seed.value
    }

    /// Wait for a staged seed this runtime began to finish writing. Once
    /// it is detached, it begins no other.
    func stagedSeedFinished() async {
        await stagedSeed?.value
    }
    #else
    private func seedStagedContentIfNeeded(owner: String) async {}
    #endif

    #if DEBUG
    /// Fill a conversation with generated messages, so a transcript can be
    /// exercised at a size no test account reaches by hand.
    @Sendable
    func seedGeneratedMessages(_ address: String, _ count: Int) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.seedGeneratedMessages(
            ownerIdentityID: localIdentity.id,
            conversationAddress: address,
            count: count
        )
        coordinator.bumpChatRevisions([address])
        await reloadApplicationState()
    }
    #else
    var seedGeneratedMessages: ((String, Int) async -> Void)? { nil }
    #endif

    #if DEBUG
    /// What a staged peer says when asked to speak, cycled so repeated tests
    /// stay tellable apart.
    private static let stagedPeerLines = [
        "Radio check—you copy?",
        "Heading up the ridge now.",
        "Found the cache, all good.",
        "Back at basecamp before dark.",
    ]

    /// Staging only: a staged peer opens Add Peer, so it shows on Nearby,
    /// or asks the phone to exchange.
    func stagedPeerMeets(asking: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        Task { await staging.stagedPeerMeets(asking: asking) }
    }

    /// Staging only: have a staged peer react to the phone's last message,
    /// after the same delay and for the same reason as a staged message.
    func stagedPeerReacts() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        let glyph = ReactionEmoji.palette.randomElement()?.token ?? "+1"
        Task {
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-reaction"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerReacts(body: glyph)
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }

    /// Staging only: have a staged peer reply to the phone's last message,
    /// after the same delay as a staged reaction.
    func stagedPeerReplies() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        Task {
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-reply"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerReplies(body: "Sounds good, see you there.")
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }

    /// Staging only: make the radio drop everything handed to it, so sends
    /// fail the way they would over a link that has gone.
    func stagedDropTransmissions(_ dropping: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        staging.setTransmissionsFailing(dropping)
    }

    /// Staging only: put the managed remote device out of reach, so the
    /// screens that ask across the mesh show what silence looks like.
    func stagedRemoteDevicesReachable(_ reachable: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        staging.setRemoteDeviceReachable(reachable)
    }

    /// Staging only: have a staged peer message this phone after a short
    /// delay—long enough to background the app or lock the screen, which
    /// is the point of testing a notification. A no-op on a real radio.
    ///
    /// `onChannel` sends to the staged group chat instead of this phone. The
    /// two are worth testing separately: a group message names a channel and
    /// a speaker where a direct one names only a peer, and that difference is
    /// exactly what a notification has to carry.
    /// Staging only: have a staged peer say three things on the staged channel
    /// with the middle one lost on the air, leaving a gap in the transcript.
    func stagedPeerLosesChannelMessage() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        let lines = Self.stagedPeerLines.shuffled()
        Task { await staging.stagedPeerLosesChannelMessage(bodies: (lines[0], lines[1], lines[2])) }
    }

    func stagedPeerSendsMessage(onChannel: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        let line = Self.stagedPeerLines[
            Int.random(in: 0..<Self.stagedPeerLines.count)
        ]
        Task {
            // The whole point is pressing this and leaving the app, and a
            // backgrounded process suspends before a bare sleep expires.
            // The assertion keeps it running through the delay and the
            // staged peer's in-process send.
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-send"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerSendsMessage(body: line, onChannel: onChannel)
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }
    #else
    var stagedPeerSendsMessage: ((Bool) -> Void)? { nil }
    var stagedPeerLosesChannelMessage: (() -> Void)? { nil }
    var stagedPeerReacts: (() -> Void)? { nil }
    var stagedPeerReplies: (() -> Void)? { nil }
    var stagedPeerMeets: ((Bool) -> Void)? { nil }
    var stagedDropTransmissions: ((Bool) -> Void)? { nil }
    var stagedRemoteDevicesReachable: ((Bool) -> Void)? { nil }
    #endif

    /// How many messages a conversation holds, for the info sheet. The only
    /// aggregate that walks a whole transcript, so it is answered here rather
    /// than carried on every summary through every reload.
    @Sendable
    func countConversationMessages(_ address: String) async -> Int {
        (try? await read { Int(try $0.messageCount(conversationAddress: address)) }) ?? 0
    }

    func deleteConversation(_ conversation: DirectConversationSummary) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.deleteDirectConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
            // The core sheds the peer's key from the radio: a closed
            // conversation takes its custody with it.
            await afterWrite()
        } catch {
            Self.logger.error("Could not delete conversation \(conversation.id): \(String(describing: error), privacy: .public)")
        }
    }

    private func startConversation(_ peer: PeerSummary) async -> DirectConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        do {
            _ = try await applicationStore.ensureDirectConversation(
                ownerIdentityID: localIdentity.id,
                peerAddress: peer.identity.canonicalAddress
            )
            // Telling the mesh session is an optimization for a running
            // core, not part of creating the conversation: the core registers
            // every conversation peer when it starts. Letting it fail the
            // whole operation would leave a conversation that exists on disk
            // but that nothing ever opens.
            try? await meshSession()?.registerPeers(peers: [peer.meshRegistration])
            await afterWrite()
            return conversations.first {
                $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
            }
        } catch {
            return nil
        }
    }

    private func pingPeer(_ peer: PeerSummary) async -> PeerPingResult {
        await pingPeer(peer, along: nil)
    }

    /// Ping `peer`, down `path` when one is given: a test of a path that
    /// installs nothing. A reply counts as hearing the peer, which the core
    /// records.
    private func pingPeer(_ peer: PeerSummary, along path: ManualPath?) async -> PeerPingResult {
        let unsent = String(localized: "The radio could not send the ping.", comment: "Why a ping could not be sent.")
        guard let core else { return .unavailable(reason: unsent) }
        do {
            switch try await core.ping(address: peer.identity.canonicalAddress, path: path?.explicitPath) {
            case let .reply(reply):
                return .reply(PeerPingReply(reply))
            case .timedOut:
                return .timedOut
            case .canceled:
                return .canceled
            }
        } catch MobileAppError.NoAnswer {
            // The core's backstop on a ping nothing ever ended.
            return .timedOut
        } catch MobileAppError.SendFailed {
            return .unavailable(reason: unsent)
        } catch let error as MobileAppError {
            return .unavailable(reason: error.message)
        } catch {
            return .unavailable(reason: unsent)
        }
    }

    /// Report the route this phone will use for the next frame to `peer`.
    /// A core that cannot answer reads as nothing learned, which is what an
    /// unreachable MAC effectively means for the next send.
    private func peerRoute(_ peer: PeerSummary) async -> PeerRoute {
        guard let route = try? await core?.peerRoute(address: peer.identity.canonicalAddress) else {
            return .unavailable
        }
        return PeerRoute(route)
    }

    // MARK: - Manual paths

    /// Hold `path` for `peer`, and keep it so the next session holds it
    /// again.
    ///
    /// Notes where the phone is, when it already may know, as the point a
    /// later move is measured from. Saving a path never asks for location.
    private func setManualPath(
        _ peer: PeerSummary,
        path: ManualPath,
        hold: ManualPathHold
    ) async -> Bool {
        guard let core else { return false }
        let position = await locationService.readOnceIfAuthorized().map(MobilePositionRecord.init)
        do {
            let held = try await core.setManualPath(
                address: peer.identity.canonicalAddress,
                path: path.explicitPath,
                holdMs: UInt64(hold.duration * 1000),
                position: position
            )
            await afterWrite()
            return held
        } catch {
            Self.logger.error("A manual path was not kept: \(String(describing: error), privacy: .public)")
            return false
        }
    }

    /// Drop a held path and what the phone kept about it.
    private func clearManualPath(_ peer: PeerSummary) async -> Bool {
        let cleared = (try? await core?.clearManualPath(address: peer.identity.canonicalAddress)) ?? false
        await afterWrite()
        return cleared
    }

    /// Switch a held path for the one learned while it was held.
    private func adoptLearnedPath(_ peer: PeerSummary) async -> Bool {
        let adopted = (try? await core?.adoptLearnedPath(address: peer.identity.canonicalAddress)) ?? false
        await afterWrite()
        return adopted
    }

    private func keepManualPath(_ peer: PeerSummary) async {
        try? await core?.keepManualPath(address: peer.identity.canonicalAddress)
        await afterWrite()
    }

    /// The held route, when the path learned while holding it is due to be
    /// offered. The phone's position is read only when the core asks for
    /// it, and only where location access was already granted.
    private func learnedPathOffer(_ peer: PeerSummary) async -> PeerRoute? {
        guard let core else { return nil }
        let address = peer.identity.canonicalAddress
        do {
            var offer = try await core.learnedPathOffer(address: address, position: nil)
            if case .needsPosition = offer {
                let reading: MobileAppPositionReading
                if let fix = await locationService.readOnceIfAuthorized() {
                    reading = .found(position: MobilePositionRecord(fix))
                } else {
                    reading = .unavailable
                }
                offer = try await core.learnedPathOffer(address: address, position: reading)
            }
            guard case let .offer(route) = offer else { return nil }
            return PeerRoute(route)
        } catch {
            return nil
        }
    }

    /// Discard a peer's learned route. Returns whether one was held, so the
    /// UI can distinguish a reset from a no-op.
    private func clearPeerRoute(_ peer: PeerSummary) async -> Bool {
        (try? await core?.clearRoute(address: peer.identity.canonicalAddress)) ?? false
    }

    // MARK: - Neighboring repeaters

    /// What a repeater last said about its neighbors, from this phone's own
    /// store. Nothing goes on the air.
    private func cachedPeerRepeaters(_ peer: PeerSummary) async -> PeerRepeaterListing? {
        let address = peer.identity.canonicalAddress
        guard let record = try? await read({ try $0.peerRepeaters(publicAddress: address) }) else {
            return nil
        }
        return PeerRepeaterListing(record)
    }

    /// Ask a repeater for one page of its neighbor listing, folded into what
    /// this phone holds about that repeater. The cursor is the caller's:
    /// none asks for the top of the listing and replaces what was held, one
    /// asks for the page after it and adds to it. Never follows a cursor on
    /// its own.
    private func loadPeerRepeaters(
        _ peer: PeerSummary,
        cursor: Data?
    ) async -> PeerRepeatersPageResult {
        await loadPeerRepeaters(peer, cursor: cursor, route: [])
    }

    /// The same, asked down `route` (send order) when it names any repeaters.
    private func loadPeerRepeaters(
        _ peer: PeerSummary,
        cursor: Data?,
        route: [MeshRouterHint]
    ) async -> PeerRepeatersPageResult {
        guard let core else { return .failed }
        do {
            return .page(PeerRepeaterListing(try await core.requestPeerRepeaters(
                address: peer.identity.canonicalAddress,
                cursor: cursor,
                route: route.map(\.bytes)
            )))
        } catch let error as MobileAppError {
            switch error {
            case .NoAnswer:
                return .noAnswer
            case .NoRadio:
                return .unavailable(reason: String(
                    localized: "Connect a configured companion radio to ask this repeater.",
                    comment: "Why a repeater's neighbors could not be asked for: no radio is attached."
                ))
            case .NotThisPhone:
                return .unavailable(reason: String(
                    localized: "Set up this radio for the current phone identity before asking repeaters.",
                    comment: "Why a repeater's neighbors could not be asked for: the radio is not this phone's."
                ))
            case .NoOwner, .NotRunning, .Busy, .Stopped:
                return .unavailable(reason: error.message)
            default:
                return .failed
            }
        } catch {
            return .failed
        }
    }

    /// Solicit a peer's current identity over the mesh. The response is not
    /// awaited here—the core records it when it arrives, which refreshes
    /// the sheet. Returns whether the request was sent, for a brief UI
    /// confirmation.
    private func fetchIdentity(_ peer: PeerSummary) async -> Bool {
        guard radioSnapshot.linkState == .attached,
              radioSnapshot.hostState == .matchesCurrentIdentity,
              let session = await meshSession()
        else { return false }
        do {
            try await session.requestIdentity(peerAddress: peer.identity.canonicalAddress)
            return true
        } catch {
            return false
        }
    }

    /// Tell the user a peer they were waiting on was heard.
    private func postPeerHeard(_ peerAddress: String) {
        let peer = peers.first { $0.identity.canonicalAddress == peerAddress }
        notificationService.postPeerHeard(
            peerAddress: peerAddress,
            displayName: peer?.displayName ?? String(peerAddress.prefix(10))
        )
    }

    // MARK: - Notifications

    /// Say what the core decided is worth saying. Which arrivals notify—
    /// mutes, silent tests, batching—is the core's call; the words are
    /// this side's. The willPresent delegate suppresses the banner when
    /// that conversation is visible in the foreground.
    private func post(_ notification: MobileNotificationEventRecord) {
        switch notification {
        case let .message(conversation, channelId, senderAddress, senderHandle, senderHint, body, isStatus, reaction):
            let text = reaction.map { Self.reactionLine($0.token, on: $0.targetBody) } ?? body
            if let channelId {
                let channel = channel(withID: channelId)
                // A group message is from someone in particular, and the
                // banner is unreadable without saying who.
                let sender = memberName(address: senderAddress, handle: senderHandle, hint: senderHint)
                // The sender's saved avatar rides along when the member is a
                // peer this phone knows; an unknown member styles without one.
                let senderPeer = senderAddress.flatMap(peer(withAddress:))
                notificationService.postInboundMessage(
                    conversationAddress: conversation,
                    displayName: channel?.title ?? Self.unnamedChannelTitle,
                    sender: sender,
                    senderAddress: senderAddress,
                    senderHint: senderPeer?.identity.hint,
                    channel: channel?.avatarStyle,
                    body: isStatus ? statusLine(name: sender, body: text) : text
                )
            } else {
                let peer = peer(withAddress: conversation)
                let displayName = peer?.displayName ?? String(conversation.prefix(10))
                notificationService.postInboundMessage(
                    conversationAddress: conversation,
                    displayName: displayName,
                    sender: nil,
                    senderAddress: conversation,
                    senderHint: peer?.identity.hint,
                    channel: nil,
                    body: isStatus ? statusLine(name: displayName, body: text) : text
                )
            }
        case let .summary(conversation, channelId, count):
            notificationService.postInboundMessageSummary(
                conversationAddress: conversation,
                displayName: notificationTitle(conversation, channelID: channelId),
                count: Int(count)
            )
        case let .deliveryFailure(conversation, channelId, body, undelivered):
            // The transcript already marks it failed, and the delegate
            // suppresses the banner when that transcript is on screen—so
            // this speaks up exactly when nobody was watching it happen,
            // which over a mesh is the normal case.
            notificationService.postDeliveryFailure(
                conversationAddress: conversation,
                displayName: notificationTitle(conversation, channelID: channelId),
                quotedBody: Self.quotedBody(body, limit: Self.failureQuoteLimit),
                undelivered: undelivered
            )
        case let .peerHeard(address):
            postPeerHeard(address)
        }
    }

    /// What a notification about `conversation` is titled: its channel's
    /// name, or its peer's.
    private func notificationTitle(_ conversation: String, channelID: String?) -> String {
        if let channelID {
            return channel(withID: channelID)?.title ?? Self.unnamedChannelTitle
        }
        return peer(withAddress: conversation)?.displayName ?? String(conversation.prefix(10))
    }

    /// The title for a channel this phone has not read yet.
    private static var unnamedChannelTitle: String {
        String(
            localized: "New message",
            comment: "Notification title for a channel message, when the channel's name is not known yet."
        )
    }

    private func channel(withID id: String) -> ChannelSummary? {
        guard let id = UUID(uuidString: id) else { return nil }
        return channels.first { $0.id == id }
    }

    private func peer(withAddress address: String) -> PeerSummary? {
        peers.first { $0.identity.canonicalAddress == address }
    }

    /// A reaction, said out loud: what was done, the glyph it renders as, and
    /// the message it landed on.
    private static func reactionLine(_ token: String, on target: String) -> String {
        let glyph = ReactionEmoji.displayGlyph(for: token)
        let quoted = quotedBody(target, limit: reactionQuoteLimit)
        return String(
            localized: "Reacted \(glyph) to \(quoted)",
            comment: "Notification body for a reaction to one of your messages: the reaction's emoji, then your message in quotation marks."
        )
    }

    /// A message as a notification *refers* to it, rather than shows it: one
    /// line, in quotation marks, clipped to about what a banner holds before
    /// it wraps. The quotation marks are what distinguish naming a message
    /// from delivering one—a failure notice that simply printed the text
    /// would read like the message arriving.
    private static func quotedBody(_ body: String, limit: Int) -> String {
        let flattened = body
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard flattened.count > limit else {
            return String(
                localized: "“\(flattened)”",
                comment: "A message quoted in a notification. Use your language's quotation marks."
            )
        }
        let clipped = flattened.prefix(limit - 1).trimmingCharacters(in: .whitespaces)
        return String(
            localized: "“\(clipped)…”",
            comment: "A message quoted in a notification, cut short. Use your language's quotation marks and ellipsis."
        )
    }

    /// Roughly what one line of a banner holds at the default text size,
    /// once the quotation marks are paid for. A failure notice is a whole
    /// line of its own, so it gets the budget; a reaction has already spent
    /// a third of the line saying who did what, and wraps to a second line
    /// rather than clipping the quote down to nothing.
    private static let failureQuoteLimit = 36
    private static let reactionQuoteLimit = 48

    /// What to call a channel member, in descending order of authority: the
    /// name we have given them or heard them advertise, then the name they
    /// attached to the message, then their address, then the bare hint.
    ///
    /// A message-borne name is the sender's unverified claim—anyone holding
    /// the channel key can write anything there—so it never displaces a
    /// name this phone established for a peer it actually knows.
    private func memberName(address: String?, handle: String?, hint: String?) -> String {
        if let address, let peer = peer(withAddress: address) {
            return peer.displayName
        }
        if let handle, !handle.isEmpty { return handle }
        if let address { return String(address.prefix(10)) }
        guard let hint else {
            return String(localized: "Unknown member", comment: "A channel message's sender, when nothing names them.")
        }
        return String(
            localized: "Member \(hint)",
            comment: "A channel message's sender, named by their node hint. The placeholder is the hint, which is not translated."
        )
    }

    /// Whether an address names a channel's group conversation rather than a
    /// peer. The facade's own prefix, checked in one place.
    static func isChannelAddress(_ address: String) -> Bool {
        address.hasPrefix("ch:")
    }

    /// Reload every peer and transcript from storage.
    ///
    /// A full read takes the peers and neighbor reports too. Chat submission
    /// and read cursors only reload conversation summaries; neither
    /// operation changes peer identity or map metadata.
    /// Callers arriving before a queued reload has begun join it instead of
    /// adding another; a caller arriving mid-reload gets a fresh one chained
    /// behind it. Either way `await` still returns only once state observed
    /// after the call has been published, which senders rely on.
    func reloadApplicationState() async {
        await reloadApplicationState(includingPeers: true)
    }

    private func reloadConversationState() async {
        await reloadApplicationState(includingPeers: false)
    }

    private func reloadApplicationState(includingPeers: Bool) async {
        coordinator.pendingReloadIncludesPeers = coordinator.pendingReloadIncludesPeers || includingPeers
        if let pending = coordinator.pendingReload {
            await pending.value
            return
        }
        let running = coordinator.runningReload
        let task = Task { @MainActor in
            await running?.value
            let includingPeers = coordinator.pendingReloadIncludesPeers
            coordinator.pendingReloadIncludesPeers = false
            coordinator.pendingReload = nil
            await performApplicationStateReload(includingPeers: includingPeers)
        }
        coordinator.pendingReload = task
        coordinator.runningReload = task
        await task.value
    }

    private func performApplicationStateReload(includingPeers: Bool) async {
        guard core != nil, let owner = localIdentity?.id, !Task.isCancelled else { return }
        do {
            var full = includingPeers
            let conversationsOnly = !full
            let nameRevision = advertisedNameRevision
            var record = try await read { try $0.state(conversationsOnly: conversationsOnly) }
            // A structural change while the request waited requires a full
            // read, rather than silently dropping a conversation.
            let knownIDs = Set(peers.map(\.id))
            if !full, record.directConversations.contains(where: { !knownIDs.contains($0.peer.stored.id) }) {
                full = true
                record = try await read { try $0.state(conversationsOnly: false) }
            }
            var loaded = MappedApplicationState(record, chatRevisions: coordinator.chatRevisions)
            guard localIdentity?.id == owner, !Task.isCancelled else { return }
            coordinator.channelAddresses.merge(loaded.channelAddresses) { _, read in read }
            for index in loaded.conversations.indices {
                let key = ConversationDraftKey(owner: owner, kind: .direct, id: loaded.conversations[index].id)
                if let text = drafts.pendingText(for: key) { loaded.conversations[index].draftText = text }
            }
            for index in loaded.channelConversations.indices {
                let key = ConversationDraftKey(owner: owner, kind: .channel, id: loaded.channelConversations[index].id)
                if let text = drafts.pendingText(for: key) { loaded.channelConversations[index].draftText = text }
            }
            // Assign only on a real change: most reloads are triggered by
            // radio or chat activity that leaves the displayed state
            // identical, and an equal-value write to an observed property
            // still invalidates everything that reads it.
            if let read = loaded.peers, peers != read { peers = read }
            if channels != loaded.channels { channels = loaded.channels }
            if let read = loaded.neighborReports, neighborReports != read { neighborReports = read }
            if conversations != loaded.conversations { conversations = loaded.conversations }
            if channelConversations != loaded.channelConversations { channelConversations = loaded.channelConversations }
            if unknownDeviceChannels != loaded.unknownDeviceChannels {
                unknownDeviceChannels = loaded.unknownDeviceChannels
            }
            // A name saved while the read ran is newer than the one it read.
            let name = loaded.advertisedName ?? ""
            if advertisedNameRevision == nameRevision, advertisedName != name {
                advertisedName = name
            }
            if full, failedReadAddress == nil { stateLoadError = nil }
        } catch is CancellationError {
            return
        } catch MobileAppError.Store(let error) {
            Self.logger.error("Could not reload application state: \(String(describing: error), privacy: .public)")
            stateLoadError = .persistence("Stored information could not be refreshed. Your last loaded information is still shown.")
        } catch {
            // No owner yet, or the core busy or stopped: the lists stand
            // until a read can be made.
            Self.logger.debug("State not read: \(String(describing: error), privacy: .public)")
        }
    }

    /// Run one of the core's synchronous queries off the main actor.
    private func read<T: Sendable>(
        _ body: @escaping @Sendable (MobileAppCore) throws -> T
    ) async throws -> T {
        guard let core else { throw MobileAppError.Stopped }
        return try await Task.detached(priority: .userInitiated) { try body(core) }.value
    }
}

/// A failure the person is told about once, with what failed and why.
struct FailureNotice: Equatable, Sendable {
    let title: String
    let message: String
}

/// Wakes the drain loop. Called on whichever thread the core published
/// from, so it only schedules.
private final class CoreWake: MobileAppCoreListener {
    private let wakes: AsyncStream<Void>.Continuation

    init(_ wakes: AsyncStream<Void>.Continuation) {
        self.wakes = wakes
    }

    func onChangesPending() {
        wakes.yield()
    }
}

/// Mutable, non-visual bookkeeping for ``AppRuntime``. Held by reference so
/// updating it never invalidates the view graph.
@MainActor
private final class AppStateCoordinator {
    /// Each joined channel's conversation address, derived from its key when
    /// the key is unlocked. Kept here rather than on `ChannelSummary` because
    /// deriving it needs the key, which the summary deliberately never holds.
    var channelAddresses: [UUID: String] = [:]
    /// A reload that has been queued but has not begun reading storage yet;
    /// later callers can safely join it.
    var pendingReload: Task<Void, Never>?
    var pendingReloadIncludesPeers = false
    /// The most recently queued reload, joined or not. New reloads chain
    /// behind it so two never read and publish state concurrently.
    var runningReload: Task<Void, Never>?
    /// How many times each conversation's stored messages have changed.
    ///
    /// An open transcript holds a bounded window rather than the whole history,
    /// so it has to be told when to re-read. Stamping this into the summary
    /// makes the reload that already publishes the summary carry the news, with
    /// no second channel to keep in step.
    ///
    /// Deliberately not bumped by marking a conversation read: that moves the
    /// unread badge, which rides the summary directly, and re-reading a
    /// transcript every time one is opened is the cost this exists to avoid.
    var chatRevisions: [String: Int] = [:]

    /// Record that these conversations' messages changed. Callers that cannot
    /// resolve which conversation a change belongs to pass every address they
    /// know: a redundant bounded re-read costs one query, while a missed one
    /// leaves an open transcript showing stale messages.
    func bumpChatRevisions(_ addresses: some Sequence<String>) {
        for address in addresses {
            chatRevisions[address, default: 0] += 1
        }
    }
}

extension ManualPath {
    /// The path as the mesh session takes it.
    var explicitPath: MobileMeshExplicitPath {
        MobileMeshExplicitPath(hints: hops.map(\.bytes), floodHops: floodHops)
    }
}
