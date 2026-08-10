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

@main
struct UMSHApp: App {
    @StateObject private var liveRadioConnection = LiveRadioConnectionOwner()

    #if DEBUG
    /// Whether to run against the fabricated mesh in the staging store, for
    /// taking marketing screenshots in the simulator. See ``StagingScenario``.
    @AppStorage("staging.enabled") private var stagingEnabled = false
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
                    radioConnection: FakeRadioConnection(
                        snapshot: StagingScenario.radioSnapshot
                    ),
                    openStore: { try SQLiteApplicationStore.stagingStore() },
                    isStaging: true
                )
                .id("staging")
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
