import Foundation

extension BOM {
  /// Maximum number of diagnostics returned by ``validate()``.
  public static let maxDiagnostics = 1000

  /// Cheap structural checks: format/version constants, serial number shape (when present),
  /// `metadata.timestamp` as an RFC 3339 `date-time` (calendar-checked), purl syntax, non-empty names, unique `bom-ref`s, hash length and
  /// hex, license id/name (an `id` is checked for SPDX-id *syntax* only, `^[A-Za-z0-9.-]+\+?$`, not
  /// against the SPDX license list), `bom-ref`s compared as exact Unicode scalars (not Swift
  /// canonical equivalence), confidence ranges, and dependency references (unknown refs,
  /// duplicate nodes, duplicate `dependsOn` entries). Output is capped at ``maxDiagnostics`` entries,
  /// followed by one truncation marker. This is NOT a full JSON-schema validation; use a schema
  /// validator for that.
  /// - Returns: human-readable problems; empty when none were found.
  public func validate() -> [String] {
    var d = Diagnostics()
    if bomFormat != Self.format {
      d.add("bomFormat must be \(Self.format), got \"\(BOM.clip(bomFormat))\"")
    }
    if specVersion != Self.specification {
      d.add("specVersion must be \(Self.specification), got \"\(BOM.clip(specVersion))\"")
    }
    if let serialNumber, !Self.isValidSerialNumber(serialNumber) {
      d.add("serialNumber must be urn:uuid:<lowercase UUID>, got \"\(BOM.clip(serialNumber))\"")
    }
    if version < 1 { d.add("version must be >= 1, got \(version)") }
    if let ts = metadata?.timestamp, !Self.isValidTimestamp(ts) {
      d.add("metadata.timestamp must be an RFC 3339 date-time, got \"\(BOM.clip(ts))\"")
    }

    var refs = Set<[Unicode.Scalar]>()
    for (i, c) in (components ?? []).enumerated() {
      validate(component: c, at: "components[\(i)]", refs: &refs, problems: &d)
    }
    if let c = metadata?.component {
      validate(component: c, at: "metadata.component", refs: &refs, problems: &d)
    }
    for (i, c) in (metadata?.tools?.components ?? []).enumerated() {
      validate(component: c, at: "metadata.tools.components[\(i)]", refs: &refs, problems: &d)
    }
    var nodes = Set<[Unicode.Scalar]>()
    for (n, dep) in (dependencies ?? []).enumerated() {
      if !refs.contains(Self.scalars(dep.ref)) {
        d.add("dependencies[\(n)]: ref \"\(BOM.clip(dep.ref))\" does not match any bom-ref")
      }
      if !nodes.insert(Self.scalars(dep.ref)).inserted {
        d.add("dependencies[\(n)]: duplicate dependency node \"\(BOM.clip(dep.ref))\"")
      }
      var targets = Set<[Unicode.Scalar]>()
      for target in dep.dependsOn ?? [] {
        if !refs.contains(Self.scalars(target)) {
          d.add("dependencies[\(n)]: dependsOn \"\(BOM.clip(target))\" does not match any bom-ref")
        }
        if !targets.insert(Self.scalars(target)).inserted {
          d.add("dependencies[\(n)]: duplicate dependsOn entry \"\(BOM.clip(target))\"")
        }
      }
    }
    return d.result
  }

  /// Collects diagnostics up to ``maxDiagnostics``.
  private struct Diagnostics {
    var items: [String] = []
    var truncated = false
    var result: [String] { truncated ? items + ["... more problems truncated"] : items }
    mutating func add(_ s: String) {
      if items.count < BOM.maxDiagnostics { items.append(s) } else { truncated = true }
    }
  }

  /// Exact scalar sequence; Swift `String ==` would equate canonically equivalent spellings.
  private static func scalars(_ s: String) -> [Unicode.Scalar] { Array(s.unicodeScalars) }

  /// RFC 3339 `date-time`: `YYYY-MM-DD` `T`/`t` `HH:MM:SS[.fraction]` (`Z`/`z` | `+-HH:MM`),
  /// with a calendar check (leap years; second 60 allowed for leap seconds).
  static func isValidTimestamp(_ s: String) -> Bool {
    let b = Array(s.utf8)
    var i = 0
    func digits(_ n: Int) -> Int? {
      guard i + n <= b.count else { return nil }
      var v = 0
      for k in i..<i + n {
        guard b[k] >= 0x30 && b[k] <= 0x39 else { return nil }
        v = v * 10 + Int(b[k] - 0x30)
      }
      i += n
      return v
    }
    func char(_ c: UInt8...) -> Bool {
      guard i < b.count, c.contains(b[i]) else { return false }
      i += 1
      return true
    }
    guard let y = digits(4), char(0x2D), let mo = digits(2), char(0x2D), let d = digits(2),
      char(0x54, 0x74), let h = digits(2), char(0x3A), let mi = digits(2), char(0x3A),
      let sec = digits(2)
    else { return false }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
    let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    guard (1...12).contains(mo), (1...dim[mo - 1]).contains(d), h <= 23, mi <= 59, sec <= 60
    else { return false }
    if char(0x2E) {
      let start = i
      while i < b.count, b[i] >= 0x30, b[i] <= 0x39 { i += 1 }
      if i == start { return false }
    }
    if char(0x5A, 0x7A) { return i == b.count }
    guard char(0x2B, 0x2D), let oh = digits(2), char(0x3A), let om = digits(2) else { return false }
    return oh <= 23 && om <= 59 && i == b.count
  }

  /// purl syntax: `pkg:` scheme, a type (`[A-Za-z][A-Za-z0-9.+-]*`), a non-empty name, and every `%`
  /// followed by two hex digits. Qualifier and subpath contents are not checked beyond that.
  static func isValidPurl(_ s: String) -> Bool {
    let b = Array(s.utf8)
    for (i, c) in b.enumerated() where c == 0x25 {
      guard i + 2 < b.count, b[i + 1].isHexDigit, b[i + 2].isHexDigit else { return false }
    }
    guard s.lowercased().hasPrefix("pkg:") else { return false }
    var rest = Substring(s.dropFirst(4))
    while rest.hasPrefix("/") { rest = rest.dropFirst() }
    if let cut = rest.firstIndex(where: { $0 == "?" || $0 == "#" }) { rest = rest[..<cut] }
    guard let slash = rest.firstIndex(of: "/") else { return false }
    let type = rest[..<slash].utf8
    guard let first = type.first, (first | 0x20) >= 0x61, (first | 0x20) <= 0x7A,
      type.allSatisfy({
        ($0 | 0x20) >= 0x61 && ($0 | 0x20) <= 0x7A || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E
          || $0 == 0x2B || $0 == 0x2D
      })
    else { return false }
    var path = rest[rest.index(after: slash)...]
    if let at = path.lastIndex(of: "@") { path = path[..<at] }
    return !(path.split(separator: "/", omittingEmptySubsequences: false).last ?? "").isEmpty
  }

  private func validate(
    component c: Component, at: String, refs: inout Set<[Unicode.Scalar]>,
    problems: inout Diagnostics
  ) {
    if c.name.isEmpty { problems.add("\(at): name must not be empty") }
    if let ref = c.bomRef {
      if ref.isEmpty {
        problems.add("\(at): bom-ref must not be empty")
      } else if !refs.insert(Self.scalars(ref)).inserted {
        problems.add("\(at): duplicate bom-ref \"\(BOM.clip(ref))\"")
      }
    }
    if let purl = c.purl, !Self.isValidPurl(purl) {
      problems.add("\(at): purl \"\(BOM.clip(purl))\" is not valid package URL syntax")
    }
    for (h, hash) in (c.hashes ?? []).enumerated() {
      let isHex = hash.content.utf8.allSatisfy {
        ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) || ($0 >= 0x41 && $0 <= 0x46)
      }
      if hash.content.count != hash.alg.hexLength || !isHex {
        problems.add(
          "\(at).hashes[\(h)]: \(hash.alg.rawValue) content must be \(hash.alg.hexLength) hex characters"
        )
      }
    }
    for (l, choice) in (c.licenses ?? []).enumerated() {
      let lic = choice.license
      if (lic.id == nil) == (lic.name == nil) {
        problems.add("\(at).licenses[\(l)]: exactly one of license.id or license.name is required")
      }
      // Syntax only; membership in the SPDX license list is not checked.
      if let id = lic.id, !Self.isValidSPDXIdSyntax(id) {
        problems.add(
          "\(at).licenses[\(l)]: license.id \"\(BOM.clip(id))\" is not valid SPDX id syntax")
      }
    }
    for (n, identity) in (c.evidence?.identity ?? []).enumerated() {
      if let v = identity.confidence, !(0...1).contains(v) {
        problems.add("\(at).evidence.identity[\(n)]: confidence \(v) is outside 0...1")
      }
      for (m, method) in (identity.methods ?? []).enumerated()
      where !(0...1).contains(method.confidence) {
        problems.add(
          "\(at).evidence.identity[\(n)].methods[\(m)]: confidence \(method.confidence) is outside 0...1"
        )
      }
    }
  }

  /// `[A-Za-z0-9.-]+` with at most one terminal `+` ("or later").
  private static func isValidSPDXIdSyntax(_ id: String) -> Bool {
    let body = id.hasSuffix("+") ? id.dropLast() : Substring(id)
    return !body.isEmpty
      && body.utf8.allSatisfy {
        ($0 >= 0x30 && $0 <= 0x39) || ($0 | 0x20 >= 0x61 && $0 | 0x20 <= 0x7A) || $0 == 0x2E
          || $0 == 0x2D
      }
  }

  private static func isValidSerialNumber(_ s: String) -> Bool {
    guard s.hasPrefix("urn:uuid:") else { return false }
    let uuid = String(s.dropFirst("urn:uuid:".count))
    return UUID(uuidString: uuid) != nil && uuid == uuid.lowercased()
  }
}

extension UInt8 {
  fileprivate var isHexDigit: Bool {
    (0x30...0x39).contains(self) || (0x41...0x46).contains(self) || (0x61...0x66).contains(self)
  }
}

extension BOM {
  /// Clipped by Unicode scalars, not characters: one grapheme can hold megabytes of combining
  /// marks. Input-derived strings are clipped in diagnostics so output stays linear in the number of
  /// problems rather than problems x string length.
  static func clip(_ s: String, max: Int = 120) -> String {
    // Inspect at most max + 1 scalars so clipping stays O(max) however long the input is.
    let head = s.unicodeScalars.prefix(max + 1)
    guard head.count > max else { return s }
    return String(String.UnicodeScalarView(head.prefix(max))) + "…(\(s.utf8.count) bytes)"
  }

}
