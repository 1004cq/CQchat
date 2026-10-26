import Foundation
import CryptoKit

/// One Noise session per remote fingerprint. BLE and TCP share the same CipherStates.
final class SessionManager {
    struct Session {
        let noise: NoiseXX
        var remoteTempId: Data
        var nickname: String
        var established: Date
    }

    private var byFingerprint: [Data: Session] = [:]
    private var handshakeByTemp: [Data: NoiseXX] = [:]
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let lock = NSLock()

    init(staticKey: Curve25519.KeyAgreement.PrivateKey) {
        self.staticKey = staticKey
    }

    func session(for fingerprint: Data) -> Session? {
        lock.lock(); defer { lock.unlock() }
        return byFingerprint[fingerprint]
    }

    func allSessions() -> [Session] {
        lock.lock(); defer { lock.unlock() }
        return Array(byFingerprint.values)
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
              let fp = n.remoteFingerprint else { return }
        byFingerprint[fp] = Session(
            noise: n, remoteTempId: tempId, nickname: nickname, established: Date()
        )
    }

    func bindTempId(_ tempId: Data, toFingerprint fp: Data) {
        lock.lock(); defer { lock.unlock() }
        byFingerprint[fp]?.remoteTempId = tempId
    }

    func updateNickname(_ name: String, fingerprint: Data) {
        lock.lock(); defer { lock.unlock() }
        byFingerprint[fingerprint]?.nickname = name
    }

    func encrypt(to fingerprint: Data, plaintext: Data) throws -> Data {
        guard let s = session(for: fingerprint) else { throw NoiseError.handshakeIncomplete }
        return try s.noise.encrypt(plaintext)
    }

    func decrypt(from fingerprint: Data, ciphertext: Data) throws -> Data {
        guard let s = session(for: fingerprint) else { throw NoiseError.handshakeIncomplete }
        return try s.noise.decrypt(ciphertext)
    }

    func fingerprint(forTemp tempId: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return byFingerprint.first(where: { $0.value.remoteTempId == tempId })?.key
    }
}
