// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "UMSHMobileCore",
    platforms: [
        .iOS(.v18),
    ],
    products: [
        .library(name: "UMSHMobileCore", targets: ["UMSHMobileCore"]),
    ],
    targets: [
        .target(
            name: "UMSHMobileCore",
            dependencies: ["UMSHMobileCoreFFI"],
            // umsh-regiondb reads SQLite through the system library. The
            // app already links it via `import SQLite3`, but the static
            // archive's undefined sqlite3_* symbols must not depend on
            // that coincidence.
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .binaryTarget(
            name: "UMSHMobileCoreFFI",
            path: "Artifacts/UMSHMobileCoreFFI.xcframework"
        ),
        .testTarget(
            name: "UMSHMobileCoreTests",
            dependencies: ["UMSHMobileCore"],
            // A copy of regions/tests/fixture/fixture.regiondb, kept in
            // sync by `make regions-build-fixture` — SwiftPM resources
            // must live inside the target directory.
            resources: [.copy("Resources/fixture.regiondb")]
        ),
    ]
)
