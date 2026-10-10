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
        .executable(name: "EnvaraRoutingAcceptanceFixture", targets: ["RoutingAcceptanceFixture"]),
        .executable(name: "EnvaraRoutingAuditFixture", targets: ["RoutingAuditFixture"]),
    ],
    targets: [
        .target(name: "RoutingAudit", publicHeadersPath: "include", linkerSettings: [.linkedLibrary("bsm")]),
        .target(name: "RoutingShared", dependencies: ["RoutingAudit"]),
        .executableTarget(name: "RoutingHelper", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingExtension", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingSigningCheck", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingAcceptanceFixture", dependencies: ["RoutingShared"]),
        .executableTarget(name: "RoutingAuditFixture", dependencies: ["RoutingShared"]),
        .testTarget(name: "RoutingSharedTests", dependencies: ["RoutingShared", "RoutingAcceptanceFixture", "RoutingAuditFixture"]),
    ]
)
