// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "Noise",
    products: [
        .library(
            name: "Noise",
            targets: ["Noise"]),
        .library(
            name: "SymmetricState",
            targets: ["SymmetricState"]),
    ],
    dependencies: [
        .package(url: "https://github.com/nixberg/xoodyak-swift", .branch("master")),
        .package(url: "https://github.com/nixberg/ristretto255-swift", .branch("master")),
    ],
    targets: [
        .target(
            name: "Noise",
            dependencies: ["Ristretto255"]),
        .target(
            name: "SymmetricState",
            dependencies: ["Noise", "Xoodyak"]),
        .testTarget(
            name: "NoiseTests",
            dependencies: ["Noise", "SymmetricState"]),
    ]
)
