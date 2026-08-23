import OSLog
import SwiftUI
import UIKit

/// Owns the messaging pipeline for the lifetime of the process.
///
/// iOS launches this app with no scene at all when CoreBluetooth restores a
/// connection — and, later, when the user answers a notification — so
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
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "AppRoot")

    /// The one pipeline. Reassigned only when a debug toggle selects a
    /// different radio, which rebuilds the interface with it.
    @Published private(set) var runtime: AppRuntime

    /// The one CoreBluetooth adapter for the process, and the reason this
    /// class exists. Built only in live mode, so a debug run never
    /// constructs a central; never released, because a second central
    /// sharing the restore identifier is exactly what restoration cannot
    /// survive.
    private var liveConnection: CoreBluetoothRadioConnection?

    /// Which radio the current runtime was built for, so a defaults change
    /// that leaves it alone costs nothing.
    private var currentMode: Mode

    #if DEBUG
    private var stagingConnection: FakeRadioConnection?
    /// The bridged connection, rebuilt only when the endpoint itself
    /// changes: the session accumulates state that must not be discarded
    /// because something unrelated wrote to defaults.
    private var tcpConnection: (endpoint: TcpEndpoint, connection: TcpRadioConnection)?
    private var defaultsObserver: (any NSObjectProtocol)?
    #endif

    override init() {
        let mode = Self.desiredMode(UserDefaults.standard)
        currentMode = mode
        // The radio and the runtime are both built here, before `super.init`
        // and long before any scene asks for them. In live mode this is
        // what creates the central early enough for CoreBluetooth to hand
        // back the state it restored for us.
        switch mode {
        case .live:
            let connection = CoreBluetoothRadioConnection()
            liveConnection = connection
            runtime = AppRuntime(radioConnection: connection)
        #if DEBUG
        case .staging:
            let connection = FakeRadioConnection(
                snapshot: StagingScenario.radioSnapshot,
                air: StagingMeshAir()
            )
            stagingConnection = connection
            // A staged mesh gets a store of its own; nothing fabricated
            // reaches the real one.
            runtime = AppRuntime(
                radioConnection: connection,
                openStore: { try SQLiteApplicationStore.stagingStore() },
                isStaging: true
            )
        case let .tcp(endpoint):
            let connection = TcpRadioConnection(endpoint: endpoint)
            tcpConnection = (endpoint, connection)
            // A bridged radio is a real radio, so this uses the real store.
            runtime = AppRuntime(radioConnection: connection)
        #endif
        }
        super.init()
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
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

    // MARK: - Which radio

    private enum Mode: Equatable {
        case live
        #if DEBUG
        case staging
        case tcp(TcpEndpoint)
        #endif
    }

    /// The same precedence the root view's `WindowGroup` used to apply, read
    /// from the same keys. Staging wins over a bridge, a bridge over the
    /// real radio, and an unparseable endpoint falls through to the radio
    /// rather than leaving the app with nothing.
    private static func desiredMode(_ defaults: UserDefaults) -> Mode {
        #if DEBUG
        if defaults.bool(forKey: "staging.enabled") { return .staging }
        if defaults.bool(forKey: "debug.radioTcp.enabled"),
           let endpoint = TcpEndpoint(
               defaults.string(forKey: "debug.radioTcp.endpoint") ?? "127.0.0.1:9000"
           ) {
            return .tcp(endpoint)
        }
        #endif
        return .live
    }

    #if DEBUG
    /// Build a runtime for a mode entered after launch, reusing every radio
    /// this process has already built. Switching away from a radio and back
    /// must return to the same connection, not a second one.
    private func buildRuntime(for mode: Mode) -> AppRuntime {
        switch mode {
        case .live:
            AppRuntime(radioConnection: liveRadioConnection())
        case .staging:
            AppRuntime(
                radioConnection: stagingRadioConnection(),
                openStore: { try SQLiteApplicationStore.stagingStore() },
                isStaging: true
            )
        case let .tcp(endpoint):
            AppRuntime(radioConnection: tcpRadioConnection(for: endpoint))
        }
    }

    private func liveRadioConnection() -> CoreBluetoothRadioConnection {
        if let liveConnection { return liveConnection }
        let connection = CoreBluetoothRadioConnection()
        liveConnection = connection
        return connection
    }

    private func stagingRadioConnection() -> FakeRadioConnection {
        if let stagingConnection { return stagingConnection }
        let connection = FakeRadioConnection(
            snapshot: StagingScenario.radioSnapshot,
            air: StagingMeshAir()
        )
        stagingConnection = connection
        return connection
    }

    private func tcpRadioConnection(for endpoint: TcpEndpoint) -> TcpRadioConnection {
        if let tcpConnection, tcpConnection.endpoint == endpoint {
            return tcpConnection.connection
        }
        let connection = TcpRadioConnection(endpoint: endpoint)
        tcpConnection = (endpoint, connection)
        return connection
    }

    /// Rebuild the pipeline when a debug toggle picks a different radio.
    ///
    /// The keys contain dots, which rules out key-value observing, so this
    /// watches every defaults write and compares. Both the comparison and
    /// the usual answer — nothing changed — are cheap enough to run on the
    /// radio's own connection bookkeeping writes.
    private func observeDebugRadioMode() {
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let mode = Self.desiredMode(UserDefaults.standard)
                guard mode != self.currentMode else { return }
                Self.logger.notice("Rebuilding the runtime for a new debug radio mode")
                // Stopping first is what keeps the two from both draining
                // the streams. The old radio is left connected, exactly as
                // the previous root-swapping arrangement left it.
                self.runtime.stop()
                self.currentMode = mode
                self.runtime = self.buildRuntime(for: mode)
                self.runtime.start()
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
/// publishes — verified the hard way: flipping the staging toggle rebuilt
/// the runtime and the interface kept showing the old one — while an
/// `@ObservedObject` view re-renders on every publish, which is the whole
/// contract this needs.
private struct AppRootHost: View {
    @ObservedObject var delegate: AppDelegate

    var body: some View {
        // Keyed on the runtime so a debug mode change builds a fresh
        // interface with it, discarding the tab and sheet state that
        // belonged to the old one.
        AppRootView(runtime: delegate.runtime)
            .id(ObjectIdentifier(delegate.runtime))
    }
}
