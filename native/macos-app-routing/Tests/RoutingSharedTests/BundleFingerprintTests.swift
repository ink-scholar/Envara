import Darwin
import Foundation
import XCTest
@testable import RoutingShared

final class BundleFingerprintTests: XCTestCase {
    private func fixture() throws -> URL {
        let root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("envara-fingerprint-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Contents/Resources"), withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        for relative in ["", "Contents", "Contents/MacOS", "Contents/Resources"] {
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: relative.isEmpty ? root.path : root.appendingPathComponent(relative).path)
        }
        try write(root, "Contents/Info.plist", Data("fixture-info".utf8), mode: 0o644)
        try write(root, "Contents/MacOS/EnvaraAppProxy", Data("fixture-provider-v1\n".utf8), mode: 0o755)
        try write(root, "Contents/Resources/.hidden", Data(), mode: 0o644)
        return root
    }

    private func write(_ root: URL, _ relative: String, _ bytes: Data, mode: Int = 0o644) throws {
        let url = root.appendingPathComponent(relative)
        try bytes.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    func testCanonicalDigestMatchesIndependentCrossLanguageGolden() throws {
        // Golden computed independently with Python hashlib and also consumed
        // by the JS builder test: explicit modes and seven inventory entries.
        let root = try fixture()
        XCTAssertEqual(try RoutingBundleFingerprint.sha256(root), "4580df75091102e035d5a0692750bf5caca7d673ca2b3f59627bc6825f3b7fe1")
    }

    func testNonASCIIPathsUseUTF8OrderRatherThanUTF16Order() throws {
        let root = try fixture()
        // U+E000 sorts before U+1F600 in UTF8, but after it in UTF16. Neither
        // filename requires Unicode normalization, so both encoders agree.
        try write(root, "Contents/Resources/\u{e000}.txt", Data("A".utf8))
        try write(root, "Contents/Resources/😀.txt", Data("B".utf8))
        XCTAssertEqual(try RoutingBundleFingerprint.sha256(root), "417011116ffce2ce61e8329f3086c2430a92f0599851fb74fb15aa0cfc2827b0")
    }

    func testTimestampsDoNotAffectDigest() throws {
        let root = try fixture(), original = try RoutingBundleFingerprint.sha256(root)
        for relative in ["Contents/Info.plist", "Contents/MacOS/EnvaraAppProxy", "Contents/Resources/.hidden",
                         "Contents/Resources", "Contents/MacOS", "Contents", ""] {
            let path = relative.isEmpty ? root.path : root.appendingPathComponent(relative).path
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1234)], ofItemAtPath: path)
        }
        XCTAssertEqual(try RoutingBundleFingerprint.sha256(root), original)
    }

    func testDigestBindsResourcesEmptyDirectoriesAndPermissions() throws {
        let root = try fixture(), initial = try RoutingBundleFingerprint.sha256(root)
        try write(root, "Contents/Resources/.hidden", Data("changed-resource".utf8))
        let changedResource = try RoutingBundleFingerprint.sha256(root)
        XCTAssertNotEqual(changedResource, initial)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Contents/Resources/empty"), withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        let changedDirectory = try RoutingBundleFingerprint.sha256(root)
        XCTAssertNotEqual(changedDirectory, changedResource)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("Contents/Info.plist").path)
        XCTAssertNotEqual(try RoutingBundleFingerprint.sha256(root), changedDirectory)
    }

    func testRejectsSymlinkAliasesAndHardlinks() throws {
        let root = try fixture(), original = root.appendingPathComponent("Contents/Resources/.hidden")
        let alias = root.appendingPathComponent("Contents/Resources/alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: original)
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
        try FileManager.default.removeItem(at: alias)
        XCTAssertEqual(Darwin.link(original.path, alias.path), 0)
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
        try FileManager.default.removeItem(at: alias)
        let rootAlias = root.deletingLastPathComponent().appendingPathComponent("envara-fingerprint-alias-" + UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: rootAlias, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: rootAlias) }
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(rootAlias))
    }

    func testRejectsSpecialFilesAndAmbiguousResourceNames() throws {
        let root = try fixture(), fifo = root.appendingPathComponent("Contents/Resources/fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
        try FileManager.default.removeItem(at: fifo)
        for name in ["bad\\name", "bad\nname", "bad\u{7f}name"] {
            let relative = "Contents/Resources/" + name
            try write(root, relative, Data())
            XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
            try FileManager.default.removeItem(at: root.appendingPathComponent(relative))
        }
    }

    func testExecutableMustExistAndRemainExecutable() throws {
        let root = try fixture(), executable = root.appendingPathComponent("Contents/MacOS/EnvaraAppProxy")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: executable.path)
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
        try FileManager.default.removeItem(at: executable)
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .unsafeBundle) }
    }

    func testOversizedSparseResourceRejectedWithoutReadingItsBytes() throws {
        let root = try fixture(), resource = root.appendingPathComponent("Contents/Resources/oversized")
        try Data().write(to: resource)
        let file = try FileHandle(forWritingTo: resource); defer { try? file.close() }
        try file.truncate(atOffset: UInt64(RoutingBundleFingerprint.maximumFileBytes + 1))
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .budgetExceeded) }
    }

    func testTotalSparseResourceBudgetIsCheckedBeforeHashing() throws {
        let root = try fixture()
        for name in ["first", "second"] {
            let resource = root.appendingPathComponent("Contents/Resources/" + name)
            try Data().write(to: resource)
            let file = try FileHandle(forWritingTo: resource)
            try file.truncate(atOffset: 34 * 1024 * 1024); try file.close()
        }
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .budgetExceeded) }
    }

    func testOverlongRelativePathsAreRejected() throws {
        let root = try fixture()
        let base = open(root.appendingPathComponent("Contents/Resources").path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0 else { throw RoutingBundleFingerprintError.ioFailure }
        var current = base, directories = [(parent: Int32, name: String, descriptor: Int32)]()
        defer {
            // Foundation absolute paths hit PATH_MAX before our relative-path
            // budget. Remove this owned deep fixture through the same bounded
            // directory descriptors used to create it, then normal teardown.
            for directory in directories.reversed() {
                Darwin.close(directory.descriptor)
                XCTAssertEqual(unlinkat(directory.parent, directory.name, AT_REMOVEDIR), 0)
            }
            Darwin.close(base)
        }
        for index in 0..<9 {
            let name = String(repeating: "a", count: 118) + String(index)
            guard mkdirat(current, name, 0o755) == 0 else { throw RoutingBundleFingerprintError.ioFailure }
            let child = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { _ = unlinkat(current, name, AT_REMOVEDIR); throw RoutingBundleFingerprintError.ioFailure }
            directories.append((parent: current, name: name, descriptor: child)); current = child
        }
        XCTAssertThrowsError(try RoutingBundleFingerprint.sha256(root)) { XCTAssertEqual($0 as? RoutingBundleFingerprintError, .budgetExceeded) }
    }
}
