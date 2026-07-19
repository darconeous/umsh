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
            dependencies: ["UMSHMobileCoreFFI"]
        ),
        .binaryTarget(
            name: "UMSHMobileCoreFFI",
            path: "Artifacts/UMSHMobileCoreFFI.xcframework"
        ),
        .testTarget(
            name: "UMSHMobileCoreTests",
            dependencies: ["UMSHMobileCore"]
        ),
    ]
)
