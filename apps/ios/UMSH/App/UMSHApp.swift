import OSLog
import SwiftUI
import UIKit

/// Owns the messaging pipeline for the lifetime of the process.
///
/// iOS launches this app with no scene at all when CoreBluetooth restores a
/// connection—and, later, when the user answers a notification—so
/// anything the pipeline needs has to exist before a scene does. A delegate
/// is the only object the system builds that early: `AppRootView` is a
/// value SwiftUI creates when it first renders a body, which on a
/// scene-less launch is never.
///
/// Two things in particular have to happen here rather than in a view. The
/// notification delegate must be claimed before launch finishes or a tap
/// delivered to a background launch reaches nothing. And the
/// `CBCentralManager` must be re-created promptly at launch with its
/// restore identifier, or the state CoreBluetooth kept for us is discarded
/// before `willRestoreState` can hand it back.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, ObservableObject {
    private static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AppRoot")

    /// The one pipeline. Reassigned only when a debug toggle selects a
    /// different radio, which rebuilds the interface with it.
    @Published private(set) var runtime: AppRuntime

    /// The one CoreBluetooth adapter for the process, and the reason this
    /// class exists. Built only in live mode, so a debug run never
    /// constructs a central; never released, because a second central
    /// sharing the restore identifier is exactly what restoration cannot
    /// survive.
    private var liveConnection: CoreBluetoothRadioConnection?

    /// Which radio the core was last handed, so a defaults change that
    /// leaves it alone costs nothing.
    private var currentMode: Mode

    /// The stores and the app core over them.
    private let coreHost: AppCoreHost

    /// Launch's hand of the first radio to the core. A debug switch waits
    /// for it, so the core never ends up holding the radio it left.
    private var launchHandoff: Task<Void, Never>?

    #if DEBUG
    /// The staged radio, once its air has started. Kept while staging is
    /// off, so the air and its nodes carry on; an air that would not start
    /// is not kept, and the next switch into staging tries again.
    private var stagingConnection: StagingRadioConnection?
    /// The bridged connection, rebuilt only when the endpoint itself
    /// changes: the session accumulates state that must not be discarded
    /// because something unrelated wrote to defaults.
    private var tcpConnection: (endpoint: TcpEndpoint, connection: TcpRadioConnection)?
    private var lanConnection: VirtualRadioConnection?
    private var defaultsObserver: (any NSObjectProtocol)?
    /// The debug mode switch under way. It reads the wanted mode again each
    /// time it finishes one, so a change made meanwhile is not lost.
    private var modeSwitch: Task<Void, Never>?
    /// The erase of the staged store under way. Switches wait for it, so a
    /// toggle back into staging seeds only once the store is empty.
    private var stagedErase: Task<Void, Never>?
    /// Whether the last erase of the staged store failed. Kept here, not in
    /// the screen that asked: leaving staging replaces the interface.
    @Published private(set) var stagedResetFailed = false
    #endif

    override init() {
        #if DEBUG
        if AppTestLaunch.isTesting {
            currentMode = .staging
            let host = AppCoreHost()
            coreHost = host
            runtime = AppRuntime(
                radioConnection: NoRadioConnection(),
                opened: Result {
                    try AppCoreHost.radioLess(
                        over: SQLiteApplicationStore(path: ":memory:"),
                        vault: host.channelKeyVault
                    )
                },
                isStaging: true
            )
            super.init()
            return
        }
        #endif
        // Before any radio is built, so the core's first lines are logged.
        SystemLogger.install()
        let mode = Self.desiredMode(UserDefaults.standard)
        currentMode = mode
        let host = AppCoreHost()
        coreHost = host
        // The radio and the runtime are both built here, before `super.init`
        // and long before any scene asks for them. In live mode this is
        // what creates the central early enough for CoreBluetooth to hand
        // back the state it restored for us.
        let connection: any RadioConnection
        switch mode {
        case .live:
            let live = CoreBluetoothRadioConnection()
            liveConnection = live
            connection = live
            runtime = Self.runtime(connection, store: .live, opened: host.openFirst(.live), host: host)
        #if DEBUG
        case .staging:
            let staging = Self.makeStagingConnection()
            stagingConnection = staging
            connection = staging ?? NoRadioConnection()
            // A staged mesh gets a store of its own; nothing fabricated
            // reaches the real one.
            runtime = Self.runtime(connection, store: .staging, opened: host.openFirst(.staging), host: host)
        case let .tcp(endpoint):
            let tcp = TcpRadioConnection(endpoint: endpoint)
            tcpConnection = (endpoint, tcp)
            connection = tcp
            // A bridged radio is a real radio, so this uses the real store.
            runtime = Self.runtime(connection, store: .live, opened: host.openFirst(.live), host: host)
        case .lan:
            let lan = Self.makeLanConnection()
            lanConnection = lan
            connection = lan
            runtime = Self.runtime(connection, store: .live, opened: host.openFirst(.live), host: host)
        #endif
        }
        // The core holds the radio from the start; it takes it while idle,
        // and the radio's state reaches the runtime through it.
        launchHandoff = Task { await host.useRadio(connection) }
        super.init()
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        #if DEBUG
        if AppTestLaunch.isTesting { return true }
        #endif
        // Claiming the notification delegate is the whole point of touching
        // the service here: it must be set before launch completes.
        _ = ChatNotificationService.shared
        if let centrals = launchOptions?[.bluetoothCentrals] as? [String] {
            Self.logger.notice(
                """
                Launched by CoreBluetooth to restore \
                \(centrals.count, privacy: .public) central(s)
                """
            )
        }
        runtime.start()
        #if DEBUG
        observeDebugRadioMode()
        #endif
        return true
    }

    /// A runtime over `connection` and `opened`, the core over `store`.
    private static func runtime(
        _ connection: any RadioConnection,
        store: AppCoreHost.StoreKind,
        opened: Result<AppCoreHost.Opened, any Error>,
        host: AppCoreHost
    ) -> AppRuntime {
        #if DEBUG
        let isStaging = store == .staging
        #else
        let isStaging = false
        #endif
        return AppRuntime(
            radioConnection: connection,
            opened: opened,
            isStaging: isStaging
        )
    }

    // MARK: - Which radio

    private enum Mode: Equatable {
        case live
        #if DEBUG
        case staging
        case tcp(TcpEndpoint)
        case lan
        #endif
    }

    /// The same precedence the root view's `WindowGroup` used to apply, read
    /// from the same keys. Staging wins over a bridge, a bridge over the
    /// local network, that over the real radio, and an unparseable endpoint
    /// falls through rather than leaving the app with nothing.
    private static func desiredMode(_ defaults: UserDefaults) -> Mode {
        #if DEBUG
        if defaults.bool(forKey: "staging.enabled") { return .staging }
        if defaults.bool(forKey: "debug.radioTcp.enabled"),
           let endpoint = TcpEndpoint(
               defaults.string(forKey: "debug.radioTcp.endpoint") ?? "127.0.0.1:9000"
           ) {
            return .tcp(endpoint)
        }
        // On a phone the LAN radio needs its network extension, which the
        // app does not embed until Apple grants the entitlement.
        #if targetEnvironment(simulator)
        if defaults.bool(forKey: "debug.radioLan.enabled") { return .lan }
        #endif
        #endif
        return .live
    }

    #if DEBUG
    /// Follow the debug toggles to the radio they pick.
    ///
    /// A switch under way is left to finish: it reads the wanted mode again
    /// when it does, and goes on to that. So two switches never overlap, and
    /// the last toggle always wins. An erase of the staged store holds
    /// switches off, and follows the toggles again when it is done.
    private func followRadioMode() {
        guard stagedErase == nil else { return }
        startModeSwitch()
    }

    private func startModeSwitch() {
        guard modeSwitch == nil, Self.desiredMode(UserDefaults.standard) != currentMode else { return }
        modeSwitch = Task { @MainActor in
            await self.launchHandoff?.value
            var mode = Self.desiredMode(UserDefaults.standard)
            while mode != self.currentMode {
                await self.switchRadio(to: mode)
                mode = Self.desiredMode(UserDefaults.standard)
            }
            self.modeSwitch = nil
        }
    }

    /// Move to `mode`'s radio, reusing every radio this process has already
    /// built: switching away from a radio and back returns to the same
    /// connection, not a second one.
    ///
    /// Over the same store the core stays and only its radio changes, and
    /// the new runtime attaches to it as it stands. Between stores the old
    /// core stops before a new one is made, and the new runtime unlocks the
    /// identity and starts it.
    private func switchRadio(to mode: Mode) async {
        Self.logger.notice("Switching the runtime to a new debug radio mode")
        // Detaching first is what keeps the two runtimes from both draining
        // the core. The old radio is left connected, exactly as the
        // previous root-swapping arrangement left it.
        let outgoing = runtime
        outgoing.detach()
        #if !targetEnvironment(simulator)
        // Awaited, so a later switch back to LAN enables it after this.
        if currentMode == .lan {
            await LanRadioRegistration.disable()
        }
        #endif
        currentMode = mode

        let connection: any RadioConnection
        let store: AppCoreHost.StoreKind
        // A bridge to another endpoint replaces the last one, which is
        // closed only once the core has let go of its driver.
        var replaced: TcpRadioConnection?
        switch mode {
        case .live:
            (connection, store) = (liveRadioConnection(), .live)
        case .staging:
            (connection, store) = (stagingRadioConnection(), .staging)
        case let .tcp(endpoint):
            let tcp: TcpRadioConnection
            (tcp, replaced) = tcpRadioConnection(for: endpoint)
            (connection, store) = (tcp, .live)
        case .lan:
            (connection, store) = (lanRadioConnection(), .live)
        }
        // A staged seed the old runtime began still writes; whatever
        // follows the switch, an erase included, comes after it.
        await outgoing.stagedSeedFinished()
        let opened = await coreHost.open(store)
        if case .success = opened {
            await coreHost.useRadio(connection)
        }
        replaced?.close()

        // Overtaken by a newer toggle: the caller moves on to that, and
        // nothing is installed for this one.
        guard Self.desiredMode(UserDefaults.standard) == mode else { return }
        let runtime = Self.runtime(connection, store: store, opened: opened, host: coreHost)
        self.runtime = runtime
        runtime.start()
    }

    /// Empty the staged database: leave staging, wait for its core to stop
    /// and its seed to finish, then erase what it kept. The next switch into
    /// staging seeds the staged mesh afresh. A second press joins the first.
    func resetStagedData() async {
        if let stagedErase { return await stagedErase.value }
        UserDefaults.standard.set(false, forKey: "staging.enabled")
        let erase = Task { @MainActor in
            self.startModeSwitch()
            await self.modeSwitch?.value
            do {
                try await self.coreHost.eraseStagedContent()
                self.stagedResetFailed = false
            } catch {
                Self.logger.error(
                    "Could not erase the staged store: \(String(describing: error), privacy: .public)"
                )
                self.stagedResetFailed = true
            }
            self.stagedErase = nil
            self.followRadioMode()
        }
        stagedErase = erase
        await erase.value
    }

    private func liveRadioConnection() -> CoreBluetoothRadioConnection {
        if let liveConnection { return liveConnection }
        let connection = CoreBluetoothRadioConnection()
        liveConnection = connection
        return connection
    }

    private func stagingRadioConnection() -> any RadioConnection {
        if let stagingConnection { return stagingConnection }
        let connection = Self.makeStagingConnection()
        stagingConnection = connection
        return connection ?? NoRadioConnection()
    }

    /// The staged radio, over the core's staging air, or nil when the air
    /// would not start. The caller falls back to no radio, an empty room,
    /// so staging can still be switched off from Settings.
    private static func makeStagingConnection() -> StagingRadioConnection? {
        do {
            return try StagingRadioConnection(
                stateDirectory: StagingRadioConnection.stateDirectory,
                wifiScanOnly: UserDefaults.standard.bool(forKey: "staging.wifiScanOnly")
            )
        } catch {
            logger.error(
                "the staging air did not start: \(String(describing: error), privacy: .public)"
            )
            return nil
        }
    }

    /// The bridged connection to `endpoint`, and the one it replaced, if
    /// any.
    private func tcpRadioConnection(
        for endpoint: TcpEndpoint
    ) -> (TcpRadioConnection, replaced: TcpRadioConnection?) {
        if let tcpConnection, tcpConnection.endpoint == endpoint {
            return (tcpConnection.connection, nil)
        }
        let replaced = tcpConnection?.connection
        let connection = TcpRadioConnection(endpoint: endpoint)
        tcpConnection = (endpoint, connection)
        return (connection, replaced)
    }

    private func lanRadioConnection() -> VirtualRadioConnection {
        if let lanConnection {
            #if !targetEnvironment(simulator)
            // Leaving LAN disabled the radio; coming back enables it again.
            Task { await LanRadioRegistration.includeCurrentNetwork() }
            #endif
            return lanConnection
        }
        let connection = Self.makeLanConnection()
        lanConnection = connection
        return connection
    }

    /// The LAN virtual radio. On a phone the network extension hosts it,
    /// running on the networks the app lists, and the app reaches it at
    /// its socket. The Simulator runs no network extensions, so there it
    /// runs in this process.
    private static func makeLanConnection() -> VirtualRadioConnection {
        #if targetEnvironment(simulator)
        return VirtualRadioConnection()
        #else
        Task { await LanRadioRegistration.includeCurrentNetwork() }
        return VirtualRadioConnection(hosting: .socket(path: VirtualRadioPaths.socketPath))
        #endif
    }

    /// Switch radios when a debug toggle picks a different one.
    ///
    /// The keys contain dots, which rules out key-value observing, so this
    /// watches every defaults write and compares. Both the comparison and
    /// the usual answer—nothing changed—are cheap enough to run on the
    /// radio's own connection bookkeeping writes.
    private func observeDebugRadioMode() {
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.followRadioMode()
            }
        }
    }
    #endif
}

@main
struct UMSHApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            AppRootHost(delegate: appDelegate)
        }
    }
}

/// The one view that observes the delegate, so a runtime swap re-renders.
///
/// An `App`'s own body does not re-evaluate when the adaptor's delegate
/// publishes—verified the hard way: flipping the staging toggle rebuilt
/// the runtime and the interface kept showing the old one—while an
/// `@ObservedObject` view re-renders on every publish, which is the whole
/// contract this needs.
private struct AppRootHost: View {
    @ObservedObject var delegate: AppDelegate

    var body: some View {
        // Keyed on the runtime so a debug mode change builds a fresh
        // interface with it, discarding the tab and sheet state that
        // belonged to the old one.
        #if DEBUG
        if AppTestLaunch.isUITest {
            DebugTestHost()
        } else {
            AppRootView(runtime: delegate.runtime)
                .id(ObjectIdentifier(delegate.runtime))
                .environment(\.resetStagedData, { [delegate] in await delegate.resetStagedData() })
                .environment(\.stagedResetFailed, delegate.stagedResetFailed)
        }
        #else
        AppRootView(runtime: delegate.runtime).id(ObjectIdentifier(delegate.runtime))
        #endif
    }
}

#if DEBUG
extension EnvironmentValues {
    /// Leave staging and empty its database once its core has stopped. Nil
    /// where no app delegate switches radios: previews.
    @Entry var resetStagedData: (@MainActor () async -> Void)? = nil
    /// Whether the last erase of the staged store failed.
    @Entry var stagedResetFailed = false
}
#endif
