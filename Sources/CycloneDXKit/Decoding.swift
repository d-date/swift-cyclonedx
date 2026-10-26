import Foundation

/// Failure of ``BOM/decode(_:maxBytes:allowUnsupportedMembers:)``.
public enum CycloneDXDecodingError: Error, Sendable, Hashable {
  /// The input exceeds `maxBytes`; the associated value is the input size in bytes.
  case inputTooLarge(Int)
  /// The input has a member this package does not model and would drop on re-encoding.
  /// The associated value is a JSON path such as `$.vulnerabilities`.
  case unsupportedMember(String)
  /// An object has two members with the same name (compared as exact Unicode scalars);
  /// the associated value is the JSON path of the second one.
  case duplicateMember(String)
  /// An object has two members whose names are canonically equivalent but scalar-distinct.
  case ambiguousMember(String)
  /// An integer literal is outside the Int64 range, a number is not finite, or a `confidence`
  /// literal has an exact decimal value outside [0, 1].
  case inexactNumber(String)
  /// Arrays/objects are nested deeper than 256 levels.
  case tooDeep
}

extension BOM {
  /// Decodes a CycloneDX document with a size budget and a losslessness check.
  ///
  /// Only a subset of CycloneDX is modelled, so decoding then re-encoding can silently drop members
  /// such as top-level `vulnerabilities` or nested `components`. Unless `allowUnsupportedMembers`
  /// is `true`, this throws ``CycloneDXDecodingError/unsupportedMember(_:)`` when any JSON object
  /// key (or array element) of the input is missing from the re-encoded model. Plain
  /// `JSONDecoder().decode(BOM.self, ...)` is a lossy subset decode and performs no such check.
  /// `null` members are ignored. The deprecated singleton `evidence.identity` object is accepted.
  ///
  /// Regardless of `allowUnsupportedMembers`, the input first passes a strict JSON scan that throws
  /// ``CycloneDXDecodingError/duplicateMember(_:)`` (same member name twice in one object, compared as
  /// unescaped Unicode scalars), ``CycloneDXDecodingError/ambiguousMember(_:)`` (names that are
  /// canonically equivalent but not scalar-identical), ``CycloneDXDecodingError/inexactNumber(_:)``
  /// (an integer literal beyond Int64, a number that overflows Double, or any member named
  /// `confidence`, at any depth, whose exact decimal value is outside [0, 1], so `1.00000000000000001`
  /// is rejected even though Double rounds it to 1) and ``CycloneDXDecodingError/tooDeep`` (more than
  /// 256 nesting levels). Malformed JSON throws `DecodingError.dataCorrupted`. The input must be
  /// UTF-8 without a BOM.
  ///
  /// - Parameters:
  ///   - data: UTF-8 JSON.
  ///   - maxBytes: input size budget (default 64 MiB); larger input throws ``CycloneDXDecodingError/inputTooLarge(_:)``.
  ///   - allowUnsupportedMembers: accept (and drop) unmodelled members.
  public static func decode(
    _ data: Data, maxBytes: Int = 64 << 20, allowUnsupportedMembers: Bool = false
  ) throws -> BOM {
    guard data.count <= maxBytes else { throw CycloneDXDecodingError.inputTooLarge(data.count) }
    do {
      try StrictJSON.validate(data, unitIntervalKeys: ["confidence"])
    } catch let failure as StrictJSONFailure {
      switch failure {
      case .syntax:
        throw DecodingError.dataCorrupted(
          .init(codingPath: [], debugDescription: "The input is not valid UTF-8 JSON."))
      case .duplicateMember(let p): throw CycloneDXDecodingError.duplicateMember(p)
      case .ambiguousMember(let p): throw CycloneDXDecodingError.ambiguousMember(p)
      case .inexactNumber(let p): throw CycloneDXDecodingError.inexactNumber(p)
      case .tooDeep: throw CycloneDXDecodingError.tooDeep
      }
    }
    let bom = try JSONDecoder().decode(BOM.self, from: data)
    if !allowUnsupportedMembers {
      let input = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
      let output = try JSONSerialization.jsonObject(
        with: bom.jsonData(prettyPrinted: false), options: [.fragmentsAllowed])
      if let path = firstMissingPath(input, in: output) {
        throw CycloneDXDecodingError.unsupportedMember(path)
      }
    }
    return bom
  }
}

/// First JSON path present in `input` but absent from `output` (arrays compared by index).
/// The path is kept as components and rendered only on a mismatch, so long keys in large
/// arrays cannot make the check quadratic.
private func firstMissingPath(_ input: Any, in output: Any) -> String? {
  var path: [PathStep] = []
  guard missing(input, in: output, &path) else { return nil }
  return path.reduce("$") { acc, step in
    switch step {
    case .key(let k): acc + "." + k
    case .index(let n): acc + "[\(n)]"
    }
  }
}

private enum PathStep {
  case key(String)
  case index(Int)
}

/// True when something in `input` is missing from `output`; `path` then points at it.
private func missing(_ input: Any, in output: Any, _ path: inout [PathStep]) -> Bool {
  if let i = input as? [String: Any] {
    // A singleton object normalized into a one-element array (evidence.identity).
    if let o = output as? [Any], o.count == 1 {
      return missing(input, in: o[0], &path)
    }
    guard let o = output as? [String: Any] else { return true }
    for key in i.keys.sorted() {
      guard let iv = i[key], !(iv is NSNull) else { continue }
      path.append(.key(key))
      guard let ov = o[key] else { return true }
      if missing(iv, in: ov, &path) { return true }
      path.removeLast()
    }
  } else if let i = input as? [Any] {
    guard let o = output as? [Any] else { return true }
    for (n, element) in i.enumerated() {
      path.append(.index(n))
      guard n < o.count else { return true }
      if missing(element, in: o[n], &path) { return true }
      path.removeLast()
    }
  }
  return false
}
