# CycloneDXKit

Codable Swift models for the [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) JSON BOM. No dependencies; macOS 13+ and Linux; Swift 6.

## Installation

```swift
.package(url: "https://github.com/d-date/swift-cyclonedx.git", from: "0.1.0")
// target dependency:
.product(name: "CycloneDXKit", package: "swift-cyclonedx")
```

## Usage

```swift
import CycloneDXKit
import Foundation

let lib = Component(
  type: .library, bomRef: "pkg:swift/Foo@1.0", name: "Foo", version: "1.0",
  hashes: [Hash(alg: .sha256, content: String(repeating: "ab", count: 32))],
  evidence: Evidence(identity: [
    Identity(
      field: .purl, confidence: 0.8,
      methods: [Method(technique: .binaryAnalysis, confidence: 0.8)])
  ]))
let bom = BOM(
  serialNumber: BOM.serialNumber(for: UUID()),  // inject a fixed UUID for reproducible output
  metadata: Metadata(timestamp: BOM.timestamp(Date())),  // no clock is read implicitly
  components: [lib])
precondition(bom.validate().isEmpty)
let json = try bom.jsonData()  // sorted keys, nil optionals omitted
```

## Decoding

Use `BOM.decode(_:maxBytes:allowUnsupportedMembers:)` for untrusted input. It rejects input over `maxBytes` (default 64 MiB) with `CycloneDXDecodingError.inputTooLarge`, and, unless `allowUnsupportedMembers: true`, throws `CycloneDXDecodingError.unsupportedMember("$.vulnerabilities")` for members this package does not model (they would be dropped on re-encoding). Plain `JSONDecoder().decode(BOM.self, ...)` is a **lossy subset decode** with no such check. On decode, `serialNumber` is optional (`nil` when absent), `version` defaults to 1, and the deprecated singleton `evidence.identity` object is normalized into an array (always encoded as an array).

## Naming

Types follow the spec (`BOM`, `Component`, `Hash`, `License`, `Metadata`, `Evidence`, `Identity`, `Method`, `Dependency`, `Property`, `Tools`). None collides with a Swift standard library or Foundation top-level type. Swift property `bomRef` is serialized as `bom-ref`; all JSON keys and enum raw values match the 1.6 schema. Models are `Codable`, `Sendable` and `Hashable` with public memberwise initializers.

## Supported version and limitations

- CycloneDX 1.6 JSON only; a subset is modelled (metadata, components, hashes, `id`/`name` licenses, identity evidence, dependencies, properties). Not modelled: SPDX license expressions, services, vulnerabilities, formulation, XML/Protobuf.
- `evidence.identity` is an array, as in 1.6.
- `validate()` is a cheap structural check (constants, serial number shape, ISO 8601 `metadata.timestamp`, unique `bom-ref`, dependency refs and duplicate nodes/`dependsOn` entries, hash length/hex, SPDX license id *syntax* only (not the license list), confidence in 0...1). It returns at most 1000 diagnostics plus a truncation marker. It is **not** full JSON-schema validation; use the [official schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json) for that.

## Verifying output against the schema

`SAMPLE_OUT_DIR=/tmp/out swift test` writes `sample.cdx.json`; then
`uvx check-jsonschema --schemafile https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json /tmp/out/sample.cdx.json`.

## License

MIT

## Complexity

`BOM.decode` rejects input larger than `maxBytes` before parsing, and `validate()` runs in time
linear in the encoded size of the BOM. A model built in memory that reuses one very long string
in many places is not encoded-size bounded; validate such models only if you trust their source.

