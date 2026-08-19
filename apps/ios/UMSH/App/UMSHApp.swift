import SwiftUI

/// Owns the live CoreBluetooth adapter for the lifetime of the SwiftUI app.
///
/// `AppRootView` is a value: SwiftUI may recreate it whenever its inputs or
/// environment change. Constructing a state-restoring `CBCentralManager` from
/// that view's initializer therefore creates competing managers and can leave
/// the UI subscribed to a different adapter than its action closures use.
/// `StateObject` evaluates this owner once for the app identity, while `lazy`
/// avoids touching Bluetooth at all when the debug staging UI is selected.
private final class LiveRadioConnectionOwner: ObservableObject {
    lazy var connection = CoreBluetoothRadioConnection()
}

#if DEBUG
/// Owns the staged radio and the fabricated mesh around it for the lifetime
/// of the SwiftUI app, for the same reason as the live owner above: the
/// staged connection accumulates state (an installed mesh session, peer
/// sessions in the air), and rebuilding it on a body re-evaluation would
/// silently hand the views a radio that has forgotten all of it.
private final class StagingRadioConnectionOwner: ObservableObject {
    lazy var connection = FakeRadioConnection(
        snapshot: StagingScenario.radioSnapshot,
        air: StagingMeshAir()
    )
}

/// Owns the bridged-radio connection, rebuilt only when the endpoint
/// itself changes. Same reasoning as the two owners above: the session
/// accumulates state that must not be discarded on a body
/// re-evaluation.
private final class TcpRadioConnectionOwner: ObservableObject {
    private var current: (endpoint: TcpEndpoint, connection: TcpRadioConnection)?

    func connection(for endpoint: TcpEndpoint) -> TcpRadioConnection {
        if let current, current.endpoint == endpoint {
            return current.connection
        }
        let connection = TcpRadioConnection(endpoint: endpoint)
        current = (endpoint, connection)
        return connection
    }
}
#endif

@main
struct UMSHApp: App {
    @StateObject private var liveRadioConnection = LiveRadioConnectionOwner()

    #if DEBUG
    @StateObject private var stagingRadioConnection = StagingRadioConnectionOwner()
    @StateObject private var tcpRadioConnection = TcpRadioConnectionOwner()

    /// Whether to run against the fabricated mesh in the staging store, for
    /// taking marketing screenshots in the simulator. See ``StagingScenario``.
    @AppStorage("staging.enabled") private var stagingEnabled = false

    /// Whether to reach the companion radio over TCP instead of BLE. The
    /// simulator has no Bluetooth, so this is how a simulator build talks
    /// to a real radio. See ``TcpRadioConnection``.
    @AppStorage("debug.radioTcp.enabled") private var tcpRadioEnabled = false
    @AppStorage("debug.radioTcp.endpoint") private var tcpRadioEndpoint = "127.0.0.1:9000"
    #endif

    var body: some Scene {
        WindowGroup {
            #if DEBUG
            // Keyed so flipping the toggle rebuilds the root: which store is
            // open and which radio is attached are both settled in the
            // initializer, so a staged session cannot be entered or left
            // without building a new one.
            if stagingEnabled {
                AppRootView(
                    radioConnection: stagingRadioConnection.connection,
                    openStore: { try SQLiteApplicationStore.stagingStore() },
                    isStaging: true
                )
                .id("staging")
            } else if tcpRadioEnabled, let endpoint = TcpEndpoint(tcpRadioEndpoint) {
                // A bridged radio is a real radio, so this uses the real
                // store — unlike staging. Keyed on the endpoint so
                // editing it builds a connection to the new one.
                AppRootView(radioConnection: tcpRadioConnection.connection(for: endpoint))
                    .id("tcp:\(endpoint.text)")
            } else {
                AppRootView(radioConnection: liveRadioConnection.connection)
                    .id("live")
            }
            #else
            AppRootView(radioConnection: liveRadioConnection.connection)
            #endif
        }
    }
}
