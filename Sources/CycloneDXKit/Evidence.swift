import Foundation

/// Which component field an identity claim is about (`evidence.identity.field`).
public enum IdentityField: String, Codable, Sendable, Hashable {
  case group, name, version, purl, cpe, omniborId, swhid, swid, hash
}

/// How an identity was determined (`evidence.identity.methods.technique`).
/// Raw values match the 1.6 schema enum.
public enum Technique: String, Codable, Sendable, Hashable {
  case sourceCodeAnalysis = "source-code-analysis"
  case binaryAnalysis = "binary-analysis"
  case manifestAnalysis = "manifest-analysis"
  case astFingerprint = "ast-fingerprint"
  case hashComparison = "hash-comparison"
  case instrumentation
  case dynamicAnalysis = "dynamic-analysis"
  case filename
  case attestation
  case other
}

/// One technique used to establish an identity, with its confidence.
public struct Method: Codable, Sendable, Hashable {
  /// Technique used (required).
  public var technique: Technique
  /// Confidence in 0...1 (required).
  public var confidence: Double
  /// Free-form detail, e.g. the matched string.
  public var value: String?

  /// Creates a method.
  public init(technique: Technique, confidence: Double, value: String? = nil) {
    self.technique = technique
    self.confidence = confidence
    self.value = value
  }
}

/// Evidence for one identity field of a component.
public struct Identity: Codable, Sendable, Hashable {
  /// The field the evidence supports (required).
  public var field: IdentityField
  /// Overall confidence in 0...1.
  public var confidence: Double?
  /// Techniques that contributed.
  public var methods: [Method]?

  /// Creates an identity.
  public init(field: IdentityField, confidence: Double? = nil, methods: [Method]? = nil) {
    self.field = field
    self.confidence = confidence
    self.methods = methods
  }
}

/// Evidence about a component (`component.evidence`).
public struct Evidence: Codable, Sendable, Hashable {
  /// An array since CycloneDX 1.6 (a single object in 1.5). Decoding accepts the deprecated
  /// singleton object and normalizes it to a one-element array; encoding always writes an array.
  public var identity: [Identity]?

  enum CodingKeys: String, CodingKey { case identity }

  /// Decodes `identity` as either an array or a single (deprecated) object.
  public init(from decoder: any Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    if !c.contains(.identity) {
      identity = nil
    } else if let many = try? c.decode([Identity].self, forKey: .identity) {
      identity = many
    } else {
      identity = [try c.decode(Identity.self, forKey: .identity)]
    }
  }

  /// Creates evidence.
  public init(identity: [Identity]? = nil) { self.identity = identity }
}
