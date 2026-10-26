import Foundation
import Testing

@testable import CycloneDXKit

private let sha256 = String(repeating: "ab", count: 32)

private func sample() -> BOM {
  let lib = Component(
    type: .library, bomRef: "pkg:swift/Alamofire@5.9.0", name: "Alamofire", version: "5.9.0",
    group: "Alamofire",
    description: "HTTP", purl: "pkg:swift/Alamofire@5.9.0",
    hashes: [Hash(alg: .sha256, content: sha256)],
    licenses: [LicenseChoice(license: License(id: "MIT"))],
    properties: [Property(name: "ipa:path", value: "Frameworks/A.framework")],
    evidence: Evidence(identity: [
      Identity(
        field: .purl, confidence: 0.8,
        methods: [
          Method(technique: .binaryAnalysis, confidence: 0.8, value: "strings"),
          Method(technique: .manifestAnalysis, confidence: 1),
        ])
    ]))
  let app = Component(type: .application, bomRef: "app", name: "Demo", version: "1.0")
  return BOM(
    metadata: Metadata(
      tools: Tools(components: [Component(type: .application, name: "example-scanner")]),
      component: app
    ),
    components: [lib],
    dependencies: [
      Dependency(ref: "app", dependsOn: ["pkg:swift/Alamofire@5.9.0"]),
      Dependency(ref: "pkg:swift/Alamofire@5.9.0"),
    ])
}

@Suite struct CycloneDXKitTests {
  @Test func roundTrips() throws {
    let bom = sample()
    let decoded = try JSONDecoder().decode(BOM.self, from: try bom.jsonData())
    #expect(decoded == bom)
    #expect(decoded.validate().isEmpty, "\(decoded.validate())")
  }

  @Test func usesCycloneDXKeyNames() throws {
    let json = String(decoding: try sample().jsonData(prettyPrinted: false), as: UTF8.self)
    for key in [
      "\"bomFormat\":\"CycloneDX\"", "\"specVersion\":\"1.6\"", "\"serialNumber\":\"urn:uuid:",
      "\"bom-ref\":\"app\"", "\"dependsOn\":[", "\"technique\":\"binary-analysis\"",
      "\"evidence\":{\"identity\":[{",
    ] {
      #expect(json.contains(key), "missing \(key)")
    }
    #expect(!json.contains("bomRef"))
  }

  @Test func serialNumberIsLowercaseUUID() {
    let s = BOM().serialNumber ?? ""
    #expect(s.hasPrefix("urn:uuid:") && s == s.lowercased())
  }

  @Test func serialNumberAndTimestampAreInjectable() throws {
    let uuid = try #require(UUID(uuidString: "3E671687-395B-41F5-A30F-A58921A69B79"))
    #expect(BOM.serialNumber(for: uuid) == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
    let bom = BOM(serialNumber: BOM.serialNumber(for: uuid))
    #expect(bom.serialNumber == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
    #expect(BOM.timestamp(Date(timeIntervalSince1970: 0)) == "1970-01-01T00:00:00Z")
    #expect(Metadata().timestamp == nil)
    #expect(try bom.jsonData() == BOM(serialNumber: bom.serialNumber).jsonData())
  }

  @Test func enumRawValuesMatchSpec() {
    #expect(ComponentType.operatingSystem.rawValue == "operating-system")
    #expect(ComponentType.cryptographicAsset.rawValue == "cryptographic-asset")
    #expect(HashAlgorithm.sha3x256.rawValue == "SHA3-256")
    #expect(HashAlgorithm.blake2b512.rawValue == "BLAKE2b-512")
    #expect(Technique.astFingerprint.rawValue == "ast-fingerprint")
    #expect(IdentityField.omniborId.rawValue == "omniborId")
  }

  @Test func omitsNilOptionals() throws {
    let bom = BOM(components: [Component(type: .file, name: "x")])
    let json = String(decoding: try bom.jsonData(prettyPrinted: false), as: UTF8.self)
    for key in [
      "metadata", "dependencies", "bom-ref", "version\":null", "hashes", "licenses", "evidence",
      "purl", "null",
    ] {
      #expect(!json.contains(key), "unexpected \(key)")
    }
  }

  @Test func validateCatchesDuplicateBomRef() {
    var bom = sample()
    bom.components?.append(Component(type: .library, bomRef: "app", name: "dup"))
    #expect(bom.validate().contains { $0.contains("duplicate bom-ref \"app\"") })
  }

  @Test func validateCatchesOtherProblems() {
    var bom = sample()
    bom.dependencies = [Dependency(ref: "ghost", dependsOn: ["app", "ghost2"])]
    bom.components?[0].hashes = [
      Hash(alg: .sha256, content: "abc"),
      Hash(alg: .md5, content: String(repeating: "z", count: 32)),
    ]
    bom.components?[0].evidence?.identity?[0].confidence = 1.5
    bom.components?[0].evidence?.identity?[0].methods?[0].confidence = -0.1
    bom.serialNumber = "urn:uuid:NOPE"
    bom.version = 0
    let problems = bom.validate()
    #expect(problems.count == 8, "\(problems)")
  }

  @Test func decodeAcceptsOwnOutput() throws {
    let bom = sample()
    #expect(try BOM.decode(bom.jsonData()) == bom)
  }

  @Test func decodesMinimalDocument() throws {
    let bom = try BOM.decode(Data(#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#.utf8))
    #expect(bom.version == 1 && bom.serialNumber == nil)
    #expect(bom.validate().isEmpty)
  }

  @Test func decodesSingletonIdentity() throws {
    let json = """
      {"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a",
      "evidence":{"identity":{"field":"purl","confidence":0.5}}}]}
      """
    let bom = try BOM.decode(Data(json.utf8))
    #expect(bom.components?[0].evidence?.identity == [Identity(field: .purl, confidence: 0.5)])
    let out = String(decoding: try bom.jsonData(prettyPrinted: false), as: UTF8.self)
    #expect(out.contains("\"identity\":[{"))
  }

  @Test func decodeRejectsUnsupportedMembers() throws {
    let top = Data(
      #"{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1"}]}"#.utf8)
    #expect(throws: CycloneDXDecodingError.unsupportedMember("$.vulnerabilities")) {
      try BOM.decode(top)
    }
    #expect(try BOM.decode(top, allowUnsupportedMembers: true).version == 1)
    let nested = Data(
      #"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","components":[]}]}"#
        .utf8)
    #expect(throws: CycloneDXDecodingError.unsupportedMember("$.components[0].components")) {
      try BOM.decode(nested)
    }
  }

  @Test func decodeEnforcesMaxBytes() {
    let data = Data(#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#.utf8)
    #expect(throws: CycloneDXDecodingError.inputTooLarge(data.count)) {
      try BOM.decode(data, maxBytes: 10)
    }
  }

  @Test func validateChecksDependencyDuplicates() {
    var bom = sample()
    bom.dependencies = [
      Dependency(ref: "app", dependsOn: ["a", "a"]),
      Dependency(ref: "app"),
    ]
    bom.components?.append(Component(type: .library, bomRef: "a", name: "a"))
    let p = bom.validate()
    #expect(p.contains { $0.contains("duplicate dependsOn entry \"a\"") })
    #expect(p.contains { $0.contains("duplicate dependency node \"app\"") })
  }

  @Test func validateChecksLicenseIdSyntaxAndTimestamp() {
    var bom = sample()
    bom.components?[0].licenses = [LicenseChoice(license: License(id: "MIT OR x"))]
    bom.metadata?.timestamp = "yesterday"
    var p = bom.validate()
    #expect(p.contains { $0.contains("SPDX id syntax") })
    #expect(p.contains { $0.contains("metadata.timestamp") })
    bom.components?[0].licenses = [LicenseChoice(license: License(id: "Apache-2.0+"))]
    for ok in ["2026-10-26T01:02:03Z", "2026-10-26T01:02:03.456+09:00"] {
      bom.metadata?.timestamp = ok
      p = bom.validate()
      #expect(p.isEmpty, "\(ok): \(p)")
    }
  }

  @Test func diagnosticsClipCombiningMarkStrings() {
    let ref = "r" + String(repeating: "\u{0301}", count: 100_000)
    #expect(BOM(dependencies: [Dependency(ref: ref)]).validate().allSatisfy { $0.utf8.count < 600 })
  }

  @Test func diagnosticsClipLongInputStrings() {
    let longRef = String(repeating: "r", count: 256 * 1024)
    let deps = (0..<500).map { _ in Dependency(ref: longRef) }
    let bom = BOM(dependencies: deps)
    let problems = bom.validate()
    #expect(!problems.isEmpty)
    #expect(problems.allSatisfy { $0.utf8.count < 400 })
  }

  @Test func validateCapsDiagnostics() {
    let bad = (0..<1500).map { _ in Component(type: .library, name: "") }
    let p = BOM(components: bad).validate()
    #expect(p.count == BOM.maxDiagnostics + 1 && p.last?.contains("truncated") == true)
  }

  // MARK: round 2

  private func decodeError(_ json: String) -> CycloneDXDecodingError? {
    do {
      _ = try BOM.decode(Data(json.utf8))
      return nil
    } catch { return error as? CycloneDXDecodingError }
  }

  private func bomJSON(_ extra: String) -> String {
    #"{"bomFormat":"CycloneDX","specVersion":"1.6",\#(extra)}"#
  }

  @Test func strictDecodeRejectsDuplicateMembers() {
    let json = bomJSON(#""vulnerabilities":null,"vulnerabilities":[{"id":"CVE-1"}]"#)
    #expect(decodeError(json) == .duplicateMember("$.vulnerabilities"))
    #expect(decodeError(bomJSON(#""version":1,"\u0076ersion":2"#)) == .duplicateMember("$.version"))
  }

  @Test func strictDecodeRejectsCanonicallyEquivalentMembers() {
    let json = bomJSON(
      "\"components\":[{\"type\":\"file\",\"name\":\"a\",\"properties\":[]}],\"\u{E9}\":1,\"e\u{301}\":2"
    )
    #expect(decodeError(json) == .ambiguousMember("$.e\u{301}"))
  }

  @Test func strictDecodeRejectsInexactNumbersAndDeepNesting() {
    #expect(decodeError(bomJSON(#""x":9223372036854775809"#)) == .inexactNumber("$.x"))
    #expect(decodeError(bomJSON(#""x":9223372036854775807"#)) == .unsupportedMember("$.x"))
    let deep = String(repeating: "[", count: 300) + String(repeating: "]", count: 300)
    #expect(decodeError(deep) == .tooDeep)
    #expect(throws: DecodingError.self) {
      try BOM.decode(Data(#"{"bomFormat":"CycloneDX",}"#.utf8))
    }
  }

  @Test func strictDecodeRejectsConfidenceOutsideUnitInterval() {
    func evidence(_ c: String) -> String {
      bomJSON(
        #""components":[{"type":"library","name":"a","evidence":{"identity":[{"field":"purl","confidence":\#(c)}]}}]"#
      )
    }
    let path = "$.components[0].evidence.identity[0].confidence"
    for bad in ["1.00000000000000001", "1.5", "-0.1", "2e0", "-1e-5"] {
      #expect(decodeError(evidence(bad)) == .inexactNumber(path), "\(bad)")
    }
    for good in ["0", "-0", "1", "1.0", "1.000", "0.5", "10e-1", "1e0", "5e-1", "0.1e1", "1e-400"] {
      #expect(decodeError(evidence(good)) == nil, "\(good)")
    }
  }

  @Test func decodesValidButSparseDocuments() throws {
    let bom = try BOM.decode(
      Data(bomJSON(#""metadata":{"tools":{},"properties":[{"name":"x"}]}"#).utf8))
    #expect(bom.metadata?.tools?.components == nil)
    #expect(bom.metadata?.properties == [Property(name: "x")])
    let out = String(decoding: try bom.jsonData(prettyPrinted: false), as: UTF8.self)
    #expect(out.contains(#""properties":[{"name":"x"}]"#) && out.contains(#""tools":{}"#))
    #expect(bom.validate().isEmpty)
  }

  @Test func validateChecksRFC3339Timestamps() {
    var bom = sample()
    for ok in [
      "2026-10-26T01:02:03Z", "2026-10-26t01:02:03z", "2026-10-26T01:02:03.456+09:00",
      "2028-02-29T00:00:00-00:30", "2026-12-31T23:59:60Z",
    ] {
      bom.metadata?.timestamp = ok
      #expect(bom.validate().isEmpty, "\(ok)")
    }
    for bad in [
      "2026-10-26T01:02:03Zgarbage", "2026-02-30T01:02:03Z", "2026-02-29T01:02:03Z",
      "2026-13-01T01:02:03Z", "2026-10-26 01:02:03Z", "2026-10-26T24:00:00Z",
      "2026-10-26T01:02:03", "2026-10-26T01:02:03.Z", "2026-10-26T01:02:03+9:00",
      "2026-10-26T01:02:03+24:00", "2026-10-26", "",
    ] {
      bom.metadata?.timestamp = bad
      #expect(bom.validate().contains { $0.contains("metadata.timestamp") }, "\(bad)")
    }
  }

  @Test func validateChecksPurlSyntax() {
    func problems(_ purl: String) -> [String] {
      var bom = sample()
      bom.components?[0].purl = purl
      return bom.validate()
    }
    for ok in [
      "pkg:swift/Alamofire@5.9.0", "pkg:generic/x%20y", "pkg:npm/%40scope/name@1?a=b#sub/path",
      "pkg:maven/org.apache/log4j@1.2", "PKG:generic/x",
    ] {
      #expect(problems(ok).isEmpty, "\(ok)")
    }
    for bad in [
      "pkg:generic/x%ZZ", "pkg:generic/x%", "pkg:generic", "pkg:/x", "pkg:1x/y", "pkg:generic/",
      "pkg:generic/@1", "https://x/y", "swift/Alamofire", "pkg:g y/z",
    ] {
      #expect(problems(bad).contains { $0.contains("purl") }, "\(bad)")
    }
  }

  @Test func bomRefsCompareByExactScalars() {
    var bom = sample()
    bom.components?.append(Component(type: .library, bomRef: "\u{E9}", name: "composed"))
    bom.components?.append(Component(type: .library, bomRef: "e\u{301}", name: "decomposed"))
    #expect(!bom.validate().contains { $0.contains("duplicate bom-ref") })
    bom.dependencies = [Dependency(ref: "app", dependsOn: ["\u{E9}"])]
    #expect(bom.validate().isEmpty)
    bom.dependencies = [Dependency(ref: "app", dependsOn: ["\u{E9}", "e\u{301}"])]
    #expect(bom.validate().isEmpty)
    bom.components?.removeLast()
    bom.dependencies = [Dependency(ref: "app", dependsOn: ["e\u{301}"])]
    #expect(bom.validate().contains { $0.contains("does not match any bom-ref") })
    bom.dependencies = [Dependency(ref: "e\u{301}"), Dependency(ref: "\u{E9}")]
    #expect(bom.validate().contains { $0.contains("dependencies[0]") })
  }

  @Test func spdxIdAllowsOnlyOneTerminalPlus() {
    func bad(_ id: String) -> Bool {
      var bom = sample()
      bom.components?[0].licenses = [LicenseChoice(license: License(id: id))]
      return bom.validate().contains { $0.contains("SPDX id syntax") }
    }
    for id in ["MIT++", "M+IT", "+", "MIT+ ", "+MIT"] { #expect(bad(id), "\(id)") }
    for id in ["MIT", "Apache-2.0+", "GPL-2.0-only", "LicenseRef-x.y"] {
      #expect(!bad(id), "\(id)")
    }
  }

  /// Opt-in: writes a sample document so it can be checked against the official JSON schema.
  @Test func writesSampleWhenRequested() throws {
    guard let dir = ProcessInfo.processInfo.environment["SAMPLE_OUT_DIR"] else { return }
    try sample().jsonData().write(
      to: URL(fileURLWithPath: dir).appendingPathComponent("sample.cdx.json"))
  }
}
