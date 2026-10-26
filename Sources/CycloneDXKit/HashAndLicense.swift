import Foundation

/// Hash algorithm (`hash-alg`). Raw values match the 1.6 schema enum.
public enum HashAlgorithm: String, Codable, Sendable, Hashable {
  case md5 = "MD5"
  case sha1 = "SHA-1"
  case sha256 = "SHA-256"
  case sha384 = "SHA-384"
  case sha512 = "SHA-512"
  case sha3x256 = "SHA3-256"
  case sha3x384 = "SHA3-384"
  case sha3x512 = "SHA3-512"
  case blake2b256 = "BLAKE2b-256"
  case blake2b384 = "BLAKE2b-384"
  case blake2b512 = "BLAKE2b-512"
  case blake3 = "BLAKE3"

  /// Expected number of hex characters in ``Hash/content``.
  public var hexLength: Int {
    switch self {
    case .md5: 32
    case .sha1: 40
    case .sha256, .sha3x256, .blake2b256, .blake3: 64
    case .sha384, .sha3x384, .blake2b384: 96
    case .sha512, .sha3x512, .blake2b512: 128
    }
  }
}

/// A hash value (`hash`).
public struct Hash: Codable, Sendable, Hashable {
  /// Algorithm used.
  public var alg: HashAlgorithm
  /// Hex-encoded digest.
  public var content: String

  /// Creates a hash.
  public init(alg: HashAlgorithm, content: String) {
    self.alg = alg
    self.content = content
  }
}

/// A license identified by SPDX id or by free-form name (`license`). Exactly one should be set.
public struct License: Codable, Sendable, Hashable {
  /// SPDX license identifier.
  public var id: String?
  /// License name when no SPDX id applies.
  public var name: String?

  /// Creates a license.
  public init(id: String? = nil, name: String? = nil) {
    self.id = id
    self.name = name
  }
}

/// One entry of a component's `licenses` array (`{"license": {...}}`).
public struct LicenseChoice: Codable, Sendable, Hashable {
  /// The license.
  public var license: License

  /// Creates a license choice.
  public init(license: License) { self.license = license }
}
