import Foundation

/// A node of the dependency graph (`dependency`), expressed over `bom-ref` values.
public struct Dependency: Codable, Sendable, Hashable {
  /// `bom-ref` of the depending component.
  public var ref: String
  /// `bom-ref`s this component depends on.
  public var dependsOn: [String]?

  /// Creates a dependency node.
  public init(ref: String, dependsOn: [String]? = nil) {
    self.ref = ref
    self.dependsOn = dependsOn
  }
}
