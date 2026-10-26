import Foundation
import CryptoKit

/// One Noise session per remote identity. BLE and TCP share the same CipherStates.
/// Provisional key = sessionId(X25519); after verified Hello → Ed25519 fingerprint.
final class SessionManager {
    struct Session {
        let noise: NoiseXX
        var remoteTempId: Data
        var nickname: String
        var identityFingerprint: Data? // Ed25519 fp once Hello verified
        var established: Date
        var failed: Bool = false
    }

    private var byKey: [Data: Session] = [:] // identity fp and/or session id → session
    private var handshakeByTemp: [Data: NoiseXX] = [:]
    private var tempToKey: [Data: Data] = [:] // current temp_id → session map key
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let lock = NSLock()

    init(staticKey: Curve25519.KeyAgreement.PrivateKey) {
        self.staticKey = staticKey
    }

    func session(for key: Data) -> Session? {
        lock.lock(); defer { lock.unlock() }
        return byKey[key]
    }

    func allSessions() -> [(id: Data, session: Session)] {
        lock.lock(); defer { lock.unlock() }
        var seen = Set<ObjectIdentifier>()
        var out: [(Data, Session)] = []
        for (k, s) in byKey {
            let oid = ObjectIdentifier(s.noise)
            if seen.contains(oid) { continue }
            seen.insert(oid)
            let id = s.identityFingerprint ?? k
            out.append((id, s))
        }
        return out
    }

    func beginHandshake(as role: NoiseXX.Role, tempId: Data) -> NoiseXX {
        lock.lock(); defer { lock.unlock() }
        let n = NoiseXX(role: role, staticKey: staticKey)
        handshakeByTemp[tempId] = n
        return n
    }

    func handshake(forTemp tempId: Data) -> NoiseXX? {
        lock.lock(); defer { lock.unlock() }
        return handshakeByTemp[tempId]
    }

    func complete(tempId: Data, nickname: String = "") {
        lock.lock(); defer { lock.unlock() }
        guard let n = handshakeByTemp.removeValue(forKey: tempId),
              n.completed,
              let sid = n.remoteSessionId else { return }
        let s = Session(
            noise: n, remoteTempId: tempId, nickname: nickname,
            identityFingerprint: nil, established: Date()
        )
        byKey[sid] = s
        tempToKey[tempId] = sid
    }

    /// Move provisional session-id key to Ed25519 identity fingerprint (alias both during transition).
    @discardableResult
    func rebind(fromSessionId sid: Data, toIdentityFingerprint fp: Data) -> Session? {
        lock.lock(); defer { lock.unlock() }
        guard var s = byKey[sid] ?? byKey[fp] else { return nil }
        s.identityFingerprint = fp
        byKey[fp] = s
        byKey[sid] = s // keep alias until temp rotates
        if let t = tempToKey.first(where: { $0.value == sid })?.key {
            tempToKey[t] = fp
        }
        return s
    }

    func bindTempId(_ tempId: Data, toKey key: Data) {
        lock.lock(); defer { lock.unlock() }
        tempToKey[tempId] = key
        if var s = byKey[key] {
            s.remoteTempId = tempId
            byKey[key] = s
            if let fp = s.identityFingerprint { byKey[fp] = s }
        }
    }

    func updateNickname(_ name: String, key: Data) {
        lock.lock(); defer { lock.unlock() }
        guard var s = byKey[key] else { return }
        s.nickname = name
        byKey[key] = s
        if let fp = s.identityFingerprint { byKey[fp] = s }
    }

    func markFailed(_ key: Data) {
        lock.lock(); defer { lock.unlock() }
        guard var s = byKey[key] else { return }
        s.failed = true
        byKey[key] = s
        if let fp = s.identityFingerprint { byKey[fp] = s }
        if let sid = s.noise.remoteSessionId { byKey[sid] = s }
    }

    func remove(_ key: Data) {
        lock.lock(); defer { lock.unlock() }
        if let s = byKey.removeValue(forKey: key) {
            if let fp = s.identityFingerprint { byKey.removeValue(forKey: fp) }
            if let sid = s.noise.remoteSessionId { byKey.removeValue(forKey: sid) }
            tempToKey = tempToKey.filter { $0.value != key && $0.value != s.identityFingerprint }
        }
    }

    func encrypt(to key: Data, plaintext: Data) throws -> Data {
        guard let s = session(for: key), !s.failed else { throw NoiseError.handshakeIncomplete }
        return try s.noise.encrypt(plaintext)
    }

    func decrypt(from key: Data, ciphertext: Data) throws -> Data {
        guard let s = session(for: key), !s.failed else { throw NoiseError.handshakeIncomplete }
        do {
            return try s.noise.decrypt(ciphertext)
        } catch {
            markFailed(key)
            throw error
        }
    }

    func key(forTemp tempId: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return tempToKey[tempId]
    }
}
