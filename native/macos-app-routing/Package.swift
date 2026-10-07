// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EnvaraAppRouting",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "RoutingShared", targets: ["RoutingShared"]),
        .executable(name: "EnvaraAppRoutingHelper", targets: ["RoutingHelper"]),
        .executable(name: "EnvaraAppProxy", targets: ["RoutingExtension"]),
        .executable(name: "EnvaraRoutingSigningCheck", targets: ["RoutingSigningCheck"]),
    ],
    targets: [
        .target(name: "RoutingShared"),
        .executableTarget(name: "RoutingHelper", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingExtension", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingSigningCheck", dependencies: ["RoutingShared"]),
        .testTarget(name: "RoutingSharedTests", dependencies: ["RoutingShared"]),
    ]
)
