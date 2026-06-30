// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "BWBrokerApp",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "BWBrokerApp", targets: ["BWBrokerApp"])
    ],
    targets: [
        .executableTarget(name: "BWBrokerApp")
    ]
)
