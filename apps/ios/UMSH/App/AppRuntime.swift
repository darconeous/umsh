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

    static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AppRoot")
    /// Chat has its own category because it is the part with a queue in it:
    /// composing, transmitting and applying happen on separate schedules, so
    /// a stuck message is only diagnosable from the sequence.
    static let chatLogger = Logger(subsystem: "com.voria.umsh.ios", category: "Chat")

    /// A runtime over `opened`'s core and store, or, when they could not be
    /// opened, one that says why.
    init(
        radioConnection: any RadioConnection,
        opened: Result<AppCoreHost.Opened, any Error>,
        isStaging: Bool = false,
        identityVault: (any IdentityVault)? = nil
    ) {
        let meshEngine = RustMeshEngine()
        self.meshEngine = meshEngine
        self.identityVault = identityVault ?? KeychainIdentityVault(meshEngine: meshEngine)
        self.radioConnection = radioConnection
        self.isStaging = isStaging
        switch opened {
        case let .success(opened):
            core = opened.core
            applicationStore = opened.store
            applicationStoreError = nil
            #if DEBUG
            writeStagedSeed = { [store = opened.store, vault = opened.vault] owner in
                try await seedStaging(
                    store: store.coreStore,
                    vault: vault,
                    ownerIdentityId: owner,
                    nowMs: Date.now.storeMilliseconds
                )
            }
            #endif
        case let .failure(error):
            core = nil
            applicationStore = nil
            applicationStoreError = error
            #if DEBUG
            writeStagedSeed = nil
            #endif
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
        drafts = ConversationDraftStore { [core] key, text in
            guard let core else { throw MobileAppError.NotRunning }
            try await core.saveDraft(address: key.address, text: text)
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
    var meetWanted = false
    var localIdentity: LocalIdentitySnapshot? {
        // The core answers queries for its owner, so it follows whichever
        // identity is current.
        didSet {
            guard localIdentity?.id != oldValue?.id else { return }
            drafts.owner = localIdentity?.id
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
    /// The latest words added to drafts from outside a composer, oldest
    /// first, for a composer open on one of them to take in.
    var draftAdditions: [DraftAddition] = []
    @ObservationIgnored var draftAdditionSequence = 0
    /// A composer takes in what it has not seen as it changes, so only the
    /// newest few need be held.
    static let draftAdditionsKept = 8
    var channels: [ChannelSummary] = []
    var advertisedName = ""
    /// Bumped by every write of `advertisedName` other than a state reload's,
    /// so a reload whose read began before such a write leaves it standing.
    @ObservationIgnored var advertisedNameRevision = 0
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
    let identityVault: any IdentityVault
    var stateLoadError: AppOperationError?
    var failedReadAddress: String?
    let identityOperations: IdentityOperations
    let drafts: ConversationDraftStore
    let radioConnection: any RadioConnection
    let notificationService = ChatNotificationService.shared
    /// Whether this runtime runs against fabricated content in the staging
    /// store, in which case every start reseeds it. Always false outside
    /// debug builds, where nothing can set it.
    let isStaging: Bool
    /// The last position handed to the core, kept so a new identity shares
    /// it at once rather than waiting for the phone to move.
    var lastPosition: MobilePositionRecord?
    /// Mutable, non-visual bookkeeping. A reference type on purpose: the
    /// observation macro tracks assignments, not interior mutation, so
    /// updating it never invalidates a view.
    let coordinator = AppStateCoordinator()

    // MARK: - Lifecycle

    /// The tasks and observers that live as long as this runtime does.
    private var tasks: [Task<Void, Never>] = []
    private var observers: [any NSObjectProtocol] = []
    /// The core's wakes, which the drain loop reads. Finished on detach.
    private var wakes: AsyncStream<Void>.Continuation?
    /// Positions on their way to the core, in the order they were read.
    var positions: AsyncStream<MobilePositionRecord?>.Continuation?
    /// The cell size location readings are being taken for; nil while
    /// they are not.
    private var locationSharingPrecision: UInt8?
    /// A retry of a failed start under way.
    var isRetryingStart = false
    /// Set by ``detach()``. A replaced runtime starts nothing more: no
    /// location readings, no seed, no core start. Work it already began
    /// still resumes after the detach, and checks this.
    var isDetached = false
    #if DEBUG
    /// The staged seed this runtime began, which may still be writing.
    var stagedSeed: Task<Void, Never>?
    /// Writes the staged mesh for an owner into the store and the
    /// channel-key vault the core was made with. Nothing else here touches
    /// the vault: the core holds the keys.
    let writeStagedSeed: (@Sendable (String) async throws -> Void)?
    #endif
    /// Each reason a start failed for that has been shown, so a retry that
    /// fails the same way says nothing new.
    private var shownStartFailures: Set<MobileAppStartFailure> = []
    /// The management screens' models, by the device they show.
    let managedDevices = ManagedDeviceRoutes()

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
        managedDevices.route(changes.managedDevices)
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
                localized: "Couldn't Start",
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
    func applyLocationSharing() {
        guard !isDetached else { return }
        let precision = phoneSharesLocation ? phoneLocationPrecision : nil
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

    /// A core command, then the lists read again, so the caller can find what
    /// the command returned. Other observers learn of it through the changes.
    func run<T: Sendable>(
        _ body: @Sendable (MobileAppCore) async throws -> T
    ) async throws -> T {
        guard let core else { throw MobileAppError.NotRunning }
        let value = try await body(core)
        await reloadApplicationState()
        return value
    }

    /// A core command that sends a request and changes nothing stored: the
    /// answer, if one comes, arrives through the changes.
    func ask(_ body: @Sendable (MobileAppCore) async throws -> Void) async throws {
        guard let core else { throw MobileAppError.NotRunning }
        try await body(core)
    }
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
final class AppStateCoordinator {
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
