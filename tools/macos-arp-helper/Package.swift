// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "LanScannerMacOSHelper",
    platforms: [
        .macOS(.v11),
    ],
    products: [
        .executable(
            name: "lanscanner-macos-arp-helper",
            targets: ["LanScannerMacOSHelper"]
        ),
    ],
    targets: [
        .executableTarget(
            name: "LanScannerMacOSHelper",
            path: "Sources"
        ),
    ]
)
