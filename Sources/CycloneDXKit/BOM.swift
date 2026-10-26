import Foundation

/// A CycloneDX 1.6 bill of materials, the root of the JSON document.
///
/// See <https://cyclonedx.org/docs/1.6/json/#>.
public struct BOM: Codable, Sendable, Hashable {
  /// Value of `bomFormat`.
  public static let format = "CycloneDX"
  /// Value of `specVersion`; the only spec version this package emits.
  public static let specification = "1.6"

  /// Always `"CycloneDX"`.
  public var bomFormat: String
  /// Always `"1.6"`.
  public var specVersion: String
  /// `urn:uuid:` followed by a lowercase RFC 4122 UUID. Optional in the schema, so `nil` after
  /// decoding a document without one; the initializer still generates one by default.
  public var serialNumber: String?
  /// BOM revision, starting at 1.
  public var version: Int
  /// Information about the BOM itself and the subject it describes.
  public var metadata: Metadata?
  /// Components contained in or used by the subject.
  public var components: [Component]?
  /// Dependency graph, expressed over `bom-ref` values.
  public var dependencies: [Dependency]?

  /// Creates a BOM.
  ///
  /// `serialNumber` defaults to a random UUID; pass `BOM.serialNumber(for:)` or any fixed value
  /// for reproducible output.
  public init(
    serialNumber: String? = BOM.serialNumber(for: UUID()),
    version: Int = 1,
    metadata: Metadata? = nil,
    components: [Component]? = nil,
    dependencies: [Dependency]? = nil
  ) {
    self.bomFormat = Self.format
    self.specVersion = Self.specification
    self.serialNumber = serialNumber
    self.version = version
    self.metadata = metadata
    self.components = components
    self.dependencies = dependencies
  }

  enum CodingKeys: String, CodingKey {
    case bomFormat, specVersion, serialNumber, version, metadata, components, dependencies
  }

  /// Decodes a BOM; an omitted `version` defaults to 1 and an omitted `serialNumber` to `nil`.
  public init(from decoder: any Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    bomFormat = try c.decode(String.self, forKey: .bomFormat)
    specVersion = try c.decode(String.self, forKey: .specVersion)
    serialNumber = try c.decodeIfPresent(String.self, forKey: .serialNumber)
    version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
    metadata = try c.decodeIfPresent(Metadata.self, forKey: .metadata)
    components = try c.decodeIfPresent([Component].self, forKey: .components)
    dependencies = try c.decodeIfPresent([Dependency].self, forKey: .dependencies)
  }

  /// Formats `uuid` as a CycloneDX serial number (`urn:uuid:<lowercase uuid>`).
  public static func serialNumber(for uuid: UUID) -> String {
    "urn:uuid:" + uuid.uuidString.lowercased()
  }

  /// Formats `date` as an ISO 8601 date-time string, as expected by `metadata.timestamp`.
  public static func timestamp(_ date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
  }

  /// Encodes the BOM as JSON with sorted keys and unescaped slashes; `nil` optionals are omitted.
  public func jsonData(prettyPrinted: Bool = true) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    if prettyPrinted { encoder.outputFormatting.insert(.prettyPrinted) }
    return try encoder.encode(self)
  }
}

/// BOM metadata (`metadata`).
public struct Metadata: Codable, Sendable, Hashable {
  /// ISO 8601 date-time string; see ``BOM/timestamp(_:)``. No clock is read implicitly.
  public var timestamp: String?
  /// Tools that produced the BOM.
  public var tools: Tools?
  /// The component the BOM describes.
  public var component: Component?
  /// Name/value pairs.
  public var properties: [Property]?

  /// Creates metadata; every member is optional.
  public init(
    timestamp: String? = nil,
    tools: Tools? = nil,
    component: Component? = nil,
    properties: [Property]? = nil
  ) {
    self.timestamp = timestamp
    self.tools = tools
    self.component = component
    self.properties = properties
  }
}

/// The 1.5+ object form of `metadata.tools` (`{"components": [...]}`).
public struct Tools: Codable, Sendable, Hashable {
  /// Tools expressed as components (absent in `{}`).
  public var components: [Component]?

  /// Creates a tools object.
  public init(components: [Component]? = nil) { self.components = components }
}

/// A name/value pair (`property`).
public struct Property: Codable, Sendable, Hashable {
  /// Property name.
  public var name: String
  /// Property value; absent in valid documents such as `{"name":"x"}`.
  public var value: String?

  /// Creates a property.
  public init(name: String, value: String? = nil) {
    self.name = name
    self.value = value
  }
}
