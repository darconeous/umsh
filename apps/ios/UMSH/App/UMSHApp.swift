import SwiftUI

@main
struct UMSHApp: App {
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
                AppRootView().id("live")
            }
            #else
            AppRootView()
            #endif
        }
    }
}
