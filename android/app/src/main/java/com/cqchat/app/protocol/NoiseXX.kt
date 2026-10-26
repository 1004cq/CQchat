package com.cqchat.app.protocol

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter as BCKeyParameter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Noise_XX_25519_ChaChaPoly_SHA256 — byte-compatible with iOS `NoiseXX`.
 *
 * ```
 * -> e
 * <- e, ee, s, es
 * -> s, se
 * ```
 * es = DH(initiator ephemeral, responder static)
 * se = DH(initiator static, responder ephemeral)
 */
class NoiseXX(
    private val role: Role,
    private val staticPrivate: ByteArray,
) {
    enum class Role { INITIATOR, RESPONDER }

    private var ephemeralPrivate: ByteArray? = null
    private var remoteEphemeral: ByteArray? = null
    var remoteStatic: ByteArray? = null
        private set
    private var ck: ByteArray
    private var h: ByteArray
    private var handshakeCipher: CipherState? = null
    private var sendCipher: CipherState? = null
    private var recvCipher: CipherState? = null
    var completed: Boolean = false
        private set

    init {
        val name = "Noise_XX_25519_ChaChaPoly_SHA256".toByteArray(Charsets.UTF_8)
        h = if (name.size <= 32) {
            name + ByteArray(32 - name.size)
        } else {
            sha256(name)
        }
        ck = h.copyOf()
        mixHash(ByteArray(0))
    }

    val remoteFingerprint: ByteArray?
        get() = remoteStatic?.let { IdentityCrypto.fingerprint(it) }

    private fun staticPublic(): ByteArray =
        X25519PrivateKeyParameters(staticPrivate, 0).generatePublicKey().encoded

    // ---- Initiator ----

    fun initiatorWrite1(payload: ByteArray = ByteArray(0)): ByteArray {
        check(role == Role.INITIATOR && ephemeralPrivate == null)
        val e = genX25519()
        ephemeralPrivate = e
        val pub = pubFromPriv(e)
        mixHash(pub)
        // No cipher yet → MixHash(payload) per Noise
        mixHash(payload)
        return pub + payload
    }

    fun initiatorRead2(message: ByteArray): ByteArray {
        check(role == Role.INITIATOR)
        val e = ephemeralPrivate ?: error("no e")
        require(message.size >= 80)
        val re = message.copyOfRange(0, 32)
        remoteEphemeral = re
        mixHash(re)
        mixKey(dh(e, re))
        val encS = message.copyOfRange(32, 80)
        val plainS = handshakeCipher!!.decrypt(encS, h)
        mixHash(encS)
        remoteStatic = plainS
        mixKey(dh(e, plainS))
        if (message.size == 80) return ByteArray(0)
        val encP = message.copyOfRange(80, message.size)
        val payload = handshakeCipher!!.decrypt(encP, h)
        mixHash(encP)
        return payload
    }

    fun initiatorWrite3(payload: ByteArray = ByteArray(0)): ByteArray {
        check(role == Role.INITIATOR)
        val re = remoteEphemeral ?: error("no re")
        val encS = handshakeCipher!!.encrypt(staticPublic(), h)
        mixHash(encS)
        mixKey(dh(staticPrivate, re))
        val encP = handshakeCipher!!.encrypt(payload, h)
        mixHash(encP)
        split()
        return encS + encP
    }

    // ---- Responder ----

    fun responderRead1(message: ByteArray): ByteArray {
        check(role == Role.RESPONDER && remoteEphemeral == null)
        require(message.size >= 32)
        val re = message.copyOfRange(0, 32)
        remoteEphemeral = re
        mixHash(re)
        val payload = if (message.size > 32) message.copyOfRange(32, message.size) else ByteArray(0)
        mixHash(payload)
        return payload
    }

    fun responderWrite2(payload: ByteArray = ByteArray(0)): ByteArray {
        check(role == Role.RESPONDER && ephemeralPrivate == null)
        val re = remoteEphemeral ?: error("no re")
        val e = genX25519()
        ephemeralPrivate = e
        val pub = pubFromPriv(e)
        var msg = pub
        mixHash(pub)
        mixKey(dh(e, re))
        val encS = handshakeCipher!!.encrypt(staticPublic(), h)
        mixHash(encS)
        msg += encS
        mixKey(dh(staticPrivate, re))
        val encP = handshakeCipher!!.encrypt(payload, h)
        mixHash(encP)
        msg += encP
        return msg
    }

    fun responderRead3(message: ByteArray): ByteArray {
        check(role == Role.RESPONDER)
        val e = ephemeralPrivate ?: error("no e")
        require(message.size >= 48)
        val encS = message.copyOfRange(0, 48)
        val plainS = handshakeCipher!!.decrypt(encS, h)
        mixHash(encS)
        remoteStatic = plainS
        mixKey(dh(e, plainS))
        val payload = if (message.size == 48) {
            ByteArray(0)
        } else {
            val encP = message.copyOfRange(48, message.size)
            val p = handshakeCipher!!.decrypt(encP, h)
            mixHash(encP)
            p
        }
        split()
        return payload
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val c = sendCipher ?: error("handshake incomplete")
        return c.encrypt(plaintext, ByteArray(0))
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        val c = recvCipher ?: error("handshake incomplete")
        return c.decrypt(ciphertext, ByteArray(0))
    }

    private fun mixHash(data: ByteArray) {
        h = sha256(h + data)
    }

    private fun mixKey(ikm: ByteArray) {
        // Must match iOS cqHKDF byte-for-byte (not a different HKDF wrapper).
        val out = cqHkdf(ikm = ikm, salt = ck, info = ByteArray(0), length = 64)
        ck = out.copyOfRange(0, 32)
        handshakeCipher = CipherState(out.copyOfRange(32, 64))
    }

    private fun split() {
        val out = cqHkdf(ikm = ByteArray(0), salt = ck, info = ByteArray(0), length = 64)
        val k1 = out.copyOfRange(0, 32)
        val k2 = out.copyOfRange(32, 64)
        if (role == Role.INITIATOR) {
            sendCipher = CipherState(k1)
            recvCipher = CipherState(k2)
        } else {
            sendCipher = CipherState(k2)
            recvCipher = CipherState(k1)
        }
        handshakeCipher = null
        completed = true
    }

    companion object {
        fun genX25519(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun pubFromPriv(priv: ByteArray): ByteArray =
            X25519PrivateKeyParameters(priv, 0).generatePublicKey().encoded

        fun dh(priv: ByteArray, pub: ByteArray): ByteArray {
            val agreement = X25519Agreement()
            agreement.init(X25519PrivateKeyParameters(priv, 0))
            val out = ByteArray(agreement.agreementSize)
            agreement.calculateAgreement(X25519PublicKeyParameters(pub, 0), out, 0)
            return out
        }

        fun sha256(data: ByteArray): ByteArray {
            val d = SHA256Digest()
            d.update(data, 0, data.size)
            val out = ByteArray(32)
            d.doFinal(out, 0)
            return out
        }

        fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
            // RFC5869 via BouncyCastle HKDF
            val gen = HKDFBytesGenerator(SHA256Digest())
            gen.init(HKDFParameters(ikm, effectiveSalt, info))
            val out = ByteArray(length)
            gen.generateBytes(out, 0, length)
            return out
        }

        /** Same as iOS cqHKDF (HMAC extract + expand) — use for identity derivation. */
        fun cqHkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
            val hmac = HMac(SHA256Digest())
            hmac.init(KeyParameter(effectiveSalt))
            hmac.update(ikm, 0, ikm.size)
            val prk = ByteArray(hmac.macSize)
            hmac.doFinal(prk, 0)
            var out = ByteArray(0)
            var t = ByteArray(0)
            var counter = 1
            while (out.size < length) {
                hmac.init(KeyParameter(prk))
                hmac.update(t, 0, t.size)
                hmac.update(info, 0, info.size)
                hmac.update(byteArrayOf(counter.toByte()), 0, 1)
                t = ByteArray(hmac.macSize)
                hmac.doFinal(t, 0)
                out += t
                counter++
            }
            return out.copyOf(length)
        }
    }
}

class CipherState(key: ByteArray) {
    private val key = key.copyOf()
    private var n: Long = 0

    fun encrypt(plaintext: ByteArray, ad: ByteArray): ByteArray {
        val nonce = noiseNonce(n)
        n++
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(BCKeyParameter(key), 128, nonce, ad))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        cipher.doFinal(out, len)
        return out
    }

    fun decrypt(ciphertext: ByteArray, ad: ByteArray): ByteArray {
        require(ciphertext.size >= 16)
        val nonce = noiseNonce(n)
        n++
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(BCKeyParameter(key), 128, nonce, ad))
        val out = ByteArray(cipher.getOutputSize(ciphertext.size))
        val len = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
        val fin = cipher.doFinal(out, len)
        return out.copyOf(len + fin)
    }

    companion object {
        fun noiseNonce(n: Long): ByteArray {
            val data = ByteArray(12)
            val le = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(n).array()
            System.arraycopy(le, 0, data, 4, 8)
            return data
        }
    }
}

object IdentityCrypto {
    fun fingerprint(x25519Public: ByteArray): ByteArray =
        NoiseXX.sha256(x25519Public).copyOf(16)
}
