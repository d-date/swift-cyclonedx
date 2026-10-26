// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "CycloneDXKit",
  platforms: [.macOS(.v13)],
  products: [.library(name: "CycloneDXKit", targets: ["CycloneDXKit"])],
  targets: [
    .target(name: "CycloneDXKit"),
    .testTarget(name: "CycloneDXKitTests", dependencies: ["CycloneDXKit"]),
  ],
  swiftLanguageModes: [.v6]
)
