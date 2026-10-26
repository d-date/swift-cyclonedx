import Foundation

/// Reasons ``StrictJSON`` rejects a document.
enum StrictJSONFailure: Error, Equatable {
  /// Not well-formed JSON (RFC 8259) or not valid UTF-8.
  case syntax
  case duplicateMember(String)
  case ambiguousMember(String)
  case inexactNumber(String)
  case tooDeep
}

/// A small validating JSON scanner that runs before Foundation parsing.
///
/// Rules, on top of RFC 8259 well-formedness (UTF-8 only, no BOM):
/// - nesting deeper than ``maxDepth`` arrays/objects throws `tooDeep`;
/// - two members of one object whose UNESCAPED names are the same Unicode scalar sequence throw
///   `duplicateMember` (so `"level"` and `"level"` collide);
/// - two members whose names are scalar-distinct but canonically equivalent (e.g. precomposed
///   U+00E9 vs `e` + U+0301) throw `ambiguousMember`, because Swift dictionaries merge them;
/// - an integer literal (no fraction, no exponent) outside the Int64 range throws `inexactNumber`;
///   so does any number whose Double value is not finite. Fractional or exponent literals that merely
///   round (e.g. `0.1`) are accepted: only the Int64 / finite rule is enforced for general numbers;
/// - for member names in `unitIntervalKeys`, a number whose EXACT decimal value is outside [0, 1]
///   throws `inexactNumber` (so `1.00000000000000001`, which Double rounds to 1, is rejected).
///   The rule applies to every member of that name at any depth.
/// Paths in errors look like `$.runs[0].results`.
struct StrictJSON {
  static let maxDepth = 256

  private enum Step {
    case key(String)
    case index(Int)
  }

  private let bytes: [UInt8]
  private let unitIntervalKeys: Set<String>
  private var pos = 0
  private var path: [Step] = []

  static func validate(_ data: Data, unitIntervalKeys: Set<String> = []) throws {
    var s = StrictJSON(bytes: [UInt8](data), unitIntervalKeys: unitIntervalKeys)
    try s.document()
  }

  private init(bytes: [UInt8], unitIntervalKeys: Set<String>) {
    self.bytes = bytes
    self.unitIntervalKeys = unitIntervalKeys
  }

  private var pathString: String {
    path.reduce("$") { acc, step in
      switch step {
      case .key(let k): acc + "." + k
      case .index(let i): acc + "[\(i)]"
      }
    }
  }

  private var peek: UInt8? { pos < bytes.count ? bytes[pos] : nil }

  private mutating func skipWhitespace() {
    while let c = peek, c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { pos += 1 }
  }

  private mutating func document() throws {
    try value(depth: 0, unit: false)
    skipWhitespace()
    if pos != bytes.count { throw StrictJSONFailure.syntax }
  }

  private mutating func value(depth: Int, unit: Bool) throws {
    skipWhitespace()
    switch peek {
    case 0x7B: try object(depth: depth + 1)
    case 0x5B: try array(depth: depth + 1)
    case 0x22: _ = try string()
    case 0x74: try literal("true")
    case 0x66: try literal("false")
    case 0x6E: try literal("null")
    case .some: try number(unit: unit)
    case .none: throw StrictJSONFailure.syntax
    }
  }

  private mutating func literal(_ word: String) throws {
    let w = Array(word.utf8)
    guard pos + w.count <= bytes.count, Array(bytes[pos..<pos + w.count]) == w else {
      throw StrictJSONFailure.syntax
    }
    pos += w.count
  }

  private mutating func array(depth: Int) throws {
    if depth > Self.maxDepth { throw StrictJSONFailure.tooDeep }
    pos += 1
    skipWhitespace()
    if peek == 0x5D {
      pos += 1
      return
    }
    path.append(.index(0))
    var n = 0
    while true {
      path[path.count - 1] = .index(n)
      try value(depth: depth, unit: false)
      skipWhitespace()
      if peek == 0x2C {
        pos += 1
        n += 1
      } else if peek == 0x5D {
        pos += 1
        break
      } else {
        throw StrictJSONFailure.syntax
      }
    }
    path.removeLast()
  }

  private mutating func object(depth: Int) throws {
    if depth > Self.maxDepth { throw StrictJSONFailure.tooDeep }
    pos += 1
    skipWhitespace()
    if peek == 0x7D {
      pos += 1
      return
    }
    var scalarNames = Set<[UInt32]>()
    var stringNames = Set<String>()
    while true {
      skipWhitespace()
      guard peek == 0x22 else { throw StrictJSONFailure.syntax }
      let name = try string()
      skipWhitespace()
      guard peek == 0x3A else { throw StrictJSONFailure.syntax }
      pos += 1
      path.append(.key(name))
      if !scalarNames.insert(name.unicodeScalars.map(\.value)).inserted {
        throw StrictJSONFailure.duplicateMember(pathString)
      }
      // String equality is canonical equivalence, which is what Swift dictionaries use.
      if !stringNames.insert(name).inserted {
        throw StrictJSONFailure.ambiguousMember(pathString)
      }
      try value(depth: depth, unit: unitIntervalKeys.contains(name))
      path.removeLast()
      skipWhitespace()
      if peek == 0x2C {
        pos += 1
      } else if peek == 0x7D {
        pos += 1
        return
      } else {
        throw StrictJSONFailure.syntax
      }
    }
  }

  private static func hexValue(_ c: UInt8) -> UInt32? {
    switch c {
    case 0x30...0x39: UInt32(c - 0x30)
    case 0x41...0x46: UInt32(c - 0x41 + 10)
    case 0x61...0x66: UInt32(c - 0x61 + 10)
    default: nil
    }
  }

  private mutating func hex4() throws -> UInt32 {
    guard pos + 4 <= bytes.count else { throw StrictJSONFailure.syntax }
    var v: UInt32 = 0
    for i in 0..<4 {
      guard let h = Self.hexValue(bytes[pos + i]) else { throw StrictJSONFailure.syntax }
      v = v << 4 | h
    }
    pos += 4
    return v
  }

  /// Parses a string at the opening quote and returns its unescaped value.
  private mutating func string() throws -> String {
    pos += 1
    var out: [UInt8] = []
    while true {
      guard let c = peek else { throw StrictJSONFailure.syntax }
      pos += 1
      switch c {
      case 0x22:
        let s = String(decoding: out, as: UTF8.self)
        // Decoding repairs invalid UTF-8; a changed byte count means the input was invalid.
        guard s.utf8.count == out.count, s.utf8.elementsEqual(out) else {
          throw StrictJSONFailure.syntax
        }
        return s
      case 0x5C:
        guard let e = peek else { throw StrictJSONFailure.syntax }
        pos += 1
        switch e {
        case 0x22, 0x5C, 0x2F: out.append(e)
        case 0x62: out.append(0x08)
        case 0x66: out.append(0x0C)
        case 0x6E: out.append(0x0A)
        case 0x72: out.append(0x0D)
        case 0x74: out.append(0x09)
        case 0x75:
          var code = try hex4()
          if (0xD800...0xDBFF).contains(code) {
            guard peek == 0x5C, pos + 1 < bytes.count, bytes[pos + 1] == 0x75 else {
              throw StrictJSONFailure.syntax
            }
            pos += 2
            let low = try hex4()
            guard (0xDC00...0xDFFF).contains(low) else { throw StrictJSONFailure.syntax }
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
          }
          guard let scalar = Unicode.Scalar(code) else { throw StrictJSONFailure.syntax }
          out.append(contentsOf: String(Character(scalar)).utf8)
        default: throw StrictJSONFailure.syntax
        }
      case 0..<0x20: throw StrictJSONFailure.syntax
      default: out.append(c)
      }
    }
  }

  private func isDigit(_ c: UInt8?) -> Bool { c.map { $0 >= 0x30 && $0 <= 0x39 } ?? false }

  private mutating func number(unit: Bool) throws {
    let start = pos
    let negative = peek == 0x2D
    if negative { pos += 1 }
    guard isDigit(peek) else { throw StrictJSONFailure.syntax }
    var digits: [UInt8] = []
    if peek == 0x30 {
      digits.append(0x30)
      pos += 1
    } else {
      while isDigit(peek) {
        digits.append(bytes[pos])
        pos += 1
      }
    }
    var fractionLength = 0
    var isInteger = true
    if peek == 0x2E {
      isInteger = false
      pos += 1
      guard isDigit(peek) else { throw StrictJSONFailure.syntax }
      while isDigit(peek) {
        digits.append(bytes[pos])
        fractionLength += 1
        pos += 1
      }
    }
    var exponent = 0
    if peek == 0x65 || peek == 0x45 {
      isInteger = false
      pos += 1
      var sign = 1
      if peek == 0x2B {
        pos += 1
      } else if peek == 0x2D {
        sign = -1
        pos += 1
      }
      guard isDigit(peek) else { throw StrictJSONFailure.syntax }
      while isDigit(peek) {
        exponent = min(exponent * 10 + Int(bytes[pos] - 0x30), 1_000_000_000)
        pos += 1
      }
      exponent *= sign
    }
    let text = String(decoding: bytes[start..<pos], as: UTF8.self)
    if isInteger {
      guard Int64(text) != nil else { throw StrictJSONFailure.inexactNumber(pathString) }
    } else {
      guard let d = Double(text), d.isFinite else {
        throw StrictJSONFailure.inexactNumber(pathString)
      }
    }
    if unit,
      !Self.isInUnitInterval(
        negative: negative, digits: digits, exponent: exponent - fractionLength)
    {
      throw StrictJSONFailure.inexactNumber(pathString)
    }
  }

  /// Exact decimal test of `digits x 10^exponent` against [0, 1].
  private static func isInUnitInterval(negative: Bool, digits: [UInt8], exponent: Int) -> Bool {
    var d = Array(digits.drop { $0 == 0x30 })
    if d.isEmpty { return true }
    if negative { return false }
    var e = exponent
    while d.last == 0x30 {
      d.removeLast()
      e += 1
    }
    let order = d.count + e  // the value lies in [10^(order-1), 10^order)
    if order <= 0 { return true }
    return order == 1 && d == [0x31]
  }
}
