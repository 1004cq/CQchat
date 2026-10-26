import Foundation
import CryptoKit

/// Owns Noise sessions and keeps provisional encryption separate from identity sessions.
final class SessionManager {
    enum State: Equatable { case handshakeComplete, identityAuthenticated }

    struct Session {
        let noise: NoiseXX
        var remoteTempId: Data
        var nickname: String
        var state: State
        var established: Date

        var isIdentityAuthenticated: Bool { state == .identityAuthenticated }
    }

    private var byFingerprint: [Data: Session] = [:]
    private var provisionalBySessionId: [Data: Session] = [:]
    private var handshakeByTemp: [Data: NoiseXX] = [:]
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let lock = NSLock()

    init(staticKey: Curve25519.KeyAgreement.PrivateKey) { self.staticKey = staticKey }

    /// Only identity-authenticated sessions are exposed to application senders.
    func session(for fingerprint: Data) -> Session? {
        lock.lock(); defer { lock.unlock() }
        guard let s = byFingerprint[fingerprint], s.isIdentityAuthenticated else { return nil }
        return s
    }

    func allSessions() -> [(id: Data, session: Session)] {
        lock.lock(); defer { lock.unlock() }
        return byFingerprint.map { ($0.key, $0.value) }
    }

    /// Includes provisional sessions for ciphertext lookup; callers must gate delivery.
    func allSessionsForDecrypt() -> [(id: Data, session: Session)] {
        lock.lock(); defer { lock.unlock() }
        return byFingerprint.map { ($0.key, $0.value) } +
            provisionalBySessionId.map { ($0.key, $0.value) }
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

    func abortHandshake(forTemp tempId: Data) {
        lock.lock(); defer { lock.unlock() }
        handshakeByTemp.removeValue(forKey: tempId)
    }

    /// Noise completion creates only a provisional session.
    func complete(tempId: Data, nickname: String = "") {
        lock.lock(); defer { lock.unlock() }
        guard let n = handshakeByTemp.removeValue(forKey: tempId),
              n.completed, let sid = n.remoteSessionId else { return }
        provisionalBySessionId[sid] = Session(
            noise: n, remoteTempId: tempId, nickname: nickname,
            state: .handshakeComplete, established: Date()
        )
    }

    /// Promotes exactly once after the caller has verified the Hello signature,
    /// its X25519 key, and the derived Ed25519 fingerprint.
    @discardableResult
    func authenticate(sessionId: Data, identityFingerprint fp: Data, nickname: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var s = provisionalBySessionId[sessionId], fp.count == 16 else { return false }
        if let existing = byFingerprint[fp], existing.noise !== s.noise { return false }
        provisionalBySessionId.removeValue(forKey: sessionId)
        s.state = .identityAuthenticated
        s.nickname = String(nickname.prefix(64))
        s.established = Date()
        byFingerprint[fp] = s
        return true
    }

    func updateNickname(_ name: String, fingerprint: Data) {
        lock.lock(); defer { lock.unlock() }
        byFingerprint[fingerprint]?.nickname = String(name.prefix(64))
    }

    func encrypt(to fingerprint: Data, plaintext: Data, associatedData: Data = Data()) throws -> Data {
        guard let s = session(for: fingerprint) else { throw NoiseError.handshakeIncomplete }
        return try s.noise.encrypt(plaintext, associatedData: associatedData)
    }

    func decrypt(from fingerprint: Data, ciphertext: Data, associatedData: Data = Data()) throws -> Data {
        guard let s = session(for: fingerprint) else { throw NoiseError.handshakeIncomplete }
        return try s.noise.decrypt(ciphertext, associatedData: associatedData)
    }

    func fingerprint(forTemp tempId: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return byFingerprint.first(where: { $0.value.remoteTempId == tempId })?.key
    }
}
