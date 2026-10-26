import Foundation

/// The kind of a ``Component`` (`component.type`). Raw values match the 1.6 schema enum.
public enum ComponentType: String, Codable, Sendable, Hashable {
  case application, framework, library, container, platform
  case operatingSystem = "operating-system"
  case device
  case deviceDriver = "device-driver"
  case firmware, file
  case machineLearningModel = "machine-learning-model"
  case data
  case cryptographicAsset = "cryptographic-asset"
}

/// A software component (`component`).
public struct Component: Codable, Sendable, Hashable {
  /// Component kind (required).
  public var type: ComponentType
  /// Unique reference within the BOM, serialized as `bom-ref`.
  public var bomRef: String?
  /// Component name (required).
  public var name: String
  /// Component version.
  public var version: String?
  /// Namespace, vendor or organization.
  public var group: String?
  /// Short description.
  public var description: String?
  /// Package URL.
  public var purl: String?
  /// Cryptographic hashes of the component.
  public var hashes: [Hash]?
  /// Licenses (`id` or `name` form; SPDX expressions are not modelled).
  public var licenses: [LicenseChoice]?
  /// Name/value pairs.
  public var properties: [Property]?
  /// Evidence for how the component was identified.
  public var evidence: Evidence?

  enum CodingKeys: String, CodingKey {
    case type
    case bomRef = "bom-ref"
    case name, version, group, description, purl, hashes, licenses, properties, evidence
  }

  /// Creates a component; only `type` and `name` are required.
  public init(
    type: ComponentType,
    bomRef: String? = nil,
    name: String,
    version: String? = nil,
    group: String? = nil,
    description: String? = nil,
    purl: String? = nil,
    hashes: [Hash]? = nil,
    licenses: [LicenseChoice]? = nil,
    properties: [Property]? = nil,
    evidence: Evidence? = nil
  ) {
    self.type = type
    self.bomRef = bomRef
    self.name = name
    self.version = version
    self.group = group
    self.description = description
    self.purl = purl
    self.hashes = hashes
    self.licenses = licenses
    self.properties = properties
    self.evidence = evidence
  }
}
