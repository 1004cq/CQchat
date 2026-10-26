import Foundation
import CryptoKit

enum NoiseError: Error {
    case invalidState
    case shortMessage
    case handshakeIncomplete
    case decryptFailed
}

/// Noise_XX_25519_ChaChaPoly_SHA256 — must match Android `NoiseXX` byte-for-byte.
///
/// Pattern:
/// ```
/// -> e
/// <- e, ee, s, es
/// -> s, se
/// ```
/// - es = DH(initiator ephemeral, responder static)
/// - se = DH(initiator static, responder ephemeral)
final class NoiseXX {
    enum Role { case initiator, responder }

    private let role: Role
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var remoteEphemeral: Curve25519.KeyAgreement.PublicKey?
    private(set) var remoteStatic: Data?
    private var ck: Data
    private var h: Data
    private var handshakeCipher: CipherState?
    private var sendCipher: CipherState?
    private var recvCipher: CipherState?
    private(set) var completed = false

    init(role: Role, staticKey: Curve25519.KeyAgreement.PrivateKey) {
        self.role = role
        self.staticKey = staticKey
        let name = Data("Noise_XX_25519_ChaChaPoly_SHA256".utf8)
        if name.count <= 32 {
            self.h = name + Data(count: 32 - name.count)
        } else {
            self.h = Data(SHA256.hash(data: name))
        }
        self.ck = h
        mixHash(Data()) // empty prologue
    }

    /// Provisional id from Noise static (X25519). Identity fingerprint comes from Hello's Ed25519.
    var remoteSessionId: Data? {
        remoteStatic.map { IdentityKeys.sessionId(x25519Public: $0) }
    }

    // MARK: Initiator

    /// -> e
    func initiatorWrite1(payload: Data = Data()) throws -> Data {
        guard role == .initiator, ephemeral == nil else { throw NoiseError.invalidState }
        let e = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e
        let pub = e.publicKey.rawRepresentation
        mixHash(pub)
        // No cipher yet → MixHash(payload) per Noise
        mixHash(payload)
        return pub + payload
    }

    /// <- e, ee, s, es
    func initiatorRead2(_ message: Data) throws -> Data {
        guard role == .initiator, let e = ephemeral else { throw NoiseError.invalidState }
        guard message.count >= 32 + 48 else { throw NoiseError.shortMessage }

        let reRaw = message.subdata(in: 0..<32)
        let re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: reRaw)
        remoteEphemeral = re
        mixHash(reRaw)

        // ee
        mixKey(Data(try e.sharedSecretFromKeyAgreement(with: re)))

        // s
        let encS = message.subdata(in: 32..<80)
        let plainS = try handshakeCipher!.decrypt(ciphertext: encS, ad: h)
        mixHash(encS)
        remoteStatic = plainS

        // es = DH(e, rs)
        let rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: plainS)
        mixKey(Data(try e.sharedSecretFromKeyAgreement(with: rs)))

        if message.count == 80 { return Data() }
        let encP = message.subdata(in: 80..<message.count)
        let payload = try handshakeCipher!.decrypt(ciphertext: encP, ad: h)
        mixHash(encP)
        return payload
    }

    /// -> s, se
    func initiatorWrite3(payload: Data = Data()) throws -> Data {
        guard role == .initiator, let re = remoteEphemeral else { throw NoiseError.invalidState }

        // s
        let encS = try handshakeCipher!.encrypt(
            plaintext: staticKey.publicKey.rawRepresentation, ad: h
        )
        mixHash(encS)

        // se = DH(s, re)
        mixKey(Data(try staticKey.sharedSecretFromKeyAgreement(with: re)))

        let encP = try handshakeCipher!.encrypt(plaintext: payload, ad: h)
        mixHash(encP)
        split()
        return encS + encP
    }

    // MARK: Responder

    /// <- e
    func responderRead1(_ message: Data) throws -> Data {
        guard role == .responder, remoteEphemeral == nil else { throw NoiseError.invalidState }
        guard message.count >= 32 else { throw NoiseError.shortMessage }

        let reRaw = message.subdata(in: 0..<32)
        remoteEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: reRaw)
        mixHash(reRaw)

        let payload = message.count > 32 ? message.subdata(in: 32..<message.count) : Data()
        mixHash(payload)
        return payload
    }

    /// -> e, ee, s, es
    func responderWrite2(payload: Data = Data()) throws -> Data {
        guard role == .responder, let re = remoteEphemeral, ephemeral == nil else {
            throw NoiseError.invalidState
        }
        let e = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e

        var msg = e.publicKey.rawRepresentation
        mixHash(e.publicKey.rawRepresentation)

        // ee
        mixKey(Data(try e.sharedSecretFromKeyAgreement(with: re)))

        // s
        let encS = try handshakeCipher!.encrypt(
            plaintext: staticKey.publicKey.rawRepresentation, ad: h
        )
        mixHash(encS)
        msg.append(encS)

        // es = DH(s, re)
        mixKey(Data(try staticKey.sharedSecretFromKeyAgreement(with: re)))

        let encP = try handshakeCipher!.encrypt(plaintext: payload, ad: h)
        mixHash(encP)
        msg.append(encP)
        return msg
    }

    /// <- s, se
    func responderRead3(_ message: Data) throws -> Data {
        guard role == .responder, let e = ephemeral else { throw NoiseError.invalidState }
        guard message.count >= 48 else { throw NoiseError.shortMessage }

        let encS = message.subdata(in: 0..<48)
        let plainS = try handshakeCipher!.decrypt(ciphertext: encS, ad: h)
        mixHash(encS)
        remoteStatic = plainS

        // se = DH(e, rs)  (responder ephemeral × initiator static)
        let rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: plainS)
        mixKey(Data(try e.sharedSecretFromKeyAgreement(with: rs)))

        let payload: Data
        if message.count == 48 {
            payload = Data()
        } else {
            let encP = message.subdata(in: 48..<message.count)
            payload = try handshakeCipher!.decrypt(ciphertext: encP, ad: h)
            mixHash(encP)
        }
        split()
        return payload
    }

    // MARK: Transport (shared across BLE + TCP)

    func encrypt(_ plaintext: Data) throws -> Data {
        guard let c = sendCipher else { throw NoiseError.handshakeIncomplete }
        return try c.encrypt(plaintext: plaintext, ad: Data())
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        guard let c = recvCipher else { throw NoiseError.handshakeIncomplete }
        return try c.decrypt(ciphertext: ciphertext, ad: Data())
    }

    // MARK: Internals

    private func mixHash(_ data: Data) {
        h = Data(SHA256.hash(data: h + data))
    }

    private func mixKey(_ ikm: Data) {
        let out = cqHKDF(ikm: ikm, salt: ck, info: Data(), length: 64)
        ck = Data(out.prefix(32))
        handshakeCipher = CipherState(key: SymmetricKey(data: out.suffix(32)))
    }

    private func split() {
        let out = cqHKDF(ikm: Data(), salt: ck, info: Data(), length: 64)
        let k1 = SymmetricKey(data: out.prefix(32))
        let k2 = SymmetricKey(data: out.suffix(32))
        if role == .initiator {
            sendCipher = CipherState(key: k1)
            recvCipher = CipherState(key: k2)
        } else {
            sendCipher = CipherState(key: k2)
            recvCipher = CipherState(key: k1)
        }
        handshakeCipher = nil
        completed = true
    }
}

final class CipherState {
    private let key: SymmetricKey
    private var n: UInt64 = 0

    init(key: SymmetricKey) { self.key = key }

    func encrypt(plaintext: Data, ad: Data) throws -> Data {
        let nonce = Self.noiseNonce(n)
        n += 1
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: try ChaChaPoly.Nonce(data: nonce),
            authenticating: ad
        )
        return sealed.ciphertext + sealed.tag
    }

    func decrypt(ciphertext: Data, ad: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseError.decryptFailed }
        let nonce = Self.noiseNonce(n)
        n += 1
        let tag = Data(ciphertext.suffix(16))
        let ct = Data(ciphertext.prefix(ciphertext.count - 16))
        let box = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: nonce),
            ciphertext: ct,
            tag: tag
        )
        do {
            return try ChaChaPoly.open(box, using: key, authenticating: ad)
        } catch {
            throw NoiseError.decryptFailed
        }
    }

    /// Noise AEAD nonce: 4 zero bytes || uint64 little-endian
    static func noiseNonce(_ n: UInt64) -> Data {
        var data = Data(repeating: 0, count: 12)
        var le = n.littleEndian
        withUnsafeBytes(of: &le) { raw in
            for i in 0..<8 { data[4 + i] = raw[i] }
        }
        return data
    }
}

func cqHKDF(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
    let effectiveSalt = salt.isEmpty ? Data(count: 32) : salt
    let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: effectiveSalt))
    let prkKey = SymmetricKey(data: Data(prk))
    var out = Data()
    var t = Data()
    var counter: UInt8 = 1
    while out.count < length {
        let block = t + info + Data([counter])
        t = Data(HMAC<SHA256>.authenticationCode(for: block, using: prkKey))
        out.append(t)
        counter += 1
    }
    return Data(out.prefix(length))
}

private extension Data {
    init(_ secret: SharedSecret) {
        self = secret.withUnsafeBytes { Data($0) }
    }
}
