import Foundation
import CryptoKit
import Security

enum IdentityKeys {
    private static let seedService = "com.cqchat.identity"
    private static let seedAccount = "identity_seed_v1"
    private static let verifiedKey = "cqchat.verified.fingerprints"
    private static let nicknameKey = "cqchat.nickname"

    static func loadOrCreate() throws -> (seed: Data, x25519: Curve25519.KeyAgreement.PrivateKey, ed25519: Curve25519.Signing.PrivateKey) {
        let seed: Data
        if let existing = keychainGet() {
            seed = existing
        } else {
            var bytes = [UInt8](repeating: 0, count: 32)
            let st = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
            guard st == errSecSuccess else { throw IdentityError.keychain }
            seed = Data(bytes)
            try keychainSet(seed)
        }
        let xSeed = cqHKDF(ikm: seed, salt: Data(), info: Data("cqchat-v1-x25519".utf8), length: 32)
        let eSeed = cqHKDF(ikm: seed, salt: Data(), info: Data("cqchat-v1-ed25519".utf8), length: 32)
        let x25519 = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: xSeed)
        let ed25519 = try Curve25519.Signing.PrivateKey(rawRepresentation: eSeed)
        return (seed, x25519, ed25519)
    }

    /// Identity fingerprint = SHA256(ed25519_public)[0..<16] (protocol-v0.1).
    static func fingerprint(ed25519Public: Data) -> Data {
        Data(SHA256.hash(data: ed25519Public)).prefix(16)
    }

    static func fingerprintHex(ed25519Public: Data) -> String {
        fingerprint(ed25519Public: ed25519Public).hex
    }

    /// Provisional session id before Hello binds Ed25519 identity.
    static func sessionId(x25519Public: Data) -> Data {
        Data(SHA256.hash(data: x25519Public)).prefix(16)
    }

    static func qrString(fingerprint: Data) -> String {
        CQ.qrPrefix + fingerprint.hex
    }

    static func parseQR(_ string: String) -> Data? {
        let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix(CQ.qrPrefix) else { return nil }
        return Data.fromHex(String(s.dropFirst(CQ.qrPrefix.count)))
    }

    static var nickname: String {
        get { UserDefaults.standard.string(forKey: nicknameKey) ?? "anon" }
        set { UserDefaults.standard.set(newValue, forKey: nicknameKey) }
    }

    static func isVerified(fingerprint: Data) -> Bool {
        verifiedSet().contains(fingerprint.hex)
    }

    static func markVerified(fingerprint: Data) {
        var set = verifiedSet()
        set.insert(fingerprint.hex)
        UserDefaults.standard.set(Array(set), forKey: verifiedKey)
    }

    private static func verifiedSet() -> Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: verifiedKey) ?? [])
    }

    private static func keychainGet() -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: seedService,
            kSecAttrAccount as String: seedAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &item)
        guard st == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private static func keychainSet(_ data: Data) throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: seedService,
            kSecAttrAccount as String: seedAccount,
        ]
        SecItemDelete(q as CFDictionary)
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw IdentityError.keychain }
    }
}

enum IdentityError: Error { case keychain }
