#if DEBUG
import SwiftUI

/// Explicit test launches never create a Bluetooth manager, access the Keychain,
/// or start the runtime. UI tests exercise the real feature with controlled I/O.
enum AppTestLaunch {
    static var isUITest: Bool { ProcessInfo.processInfo.environment["UMSH_UI_TESTING"] == "1" }
    static var isTesting: Bool {
        isUITest || ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }
}

struct DebugTestHost: View {
    @State private var saves = 0

    var body: some View {
        OnboardingView(
            identity: .init(id: "test", publicIdentity: .init(
                canonicalAddress: "test", hint: .init(bytes: Data([1, 2, 3]), text: "Test"))),
            advertisedName: "",
            saveAdvertisedName: { _ in
                saves += 1
                return saves == 1 ? .failure(.persistence("Changes could not be saved. Please try again.")) : .success(())
            },
            discoverRadios: { AsyncStream { $0.yield([]); $0.finish() } },
            selectRadio: { _ in }, stopDiscovery: {}, finish: {}
        )
    }
}
#endif
