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
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Protocol-facing error. Underlying crypto/provider exceptions are retained as
 * causes for internal diagnostics, while callers only receive a stable code.
 */
class NoiseError(
    val code: Code,
    cause: Throwable? = null,
) : Exception(code.name, cause) {
    enum class Code {
        INVALID_STATE,
        ROLE_MISMATCH,
        MALFORMED_MESSAGE,
        INVALID_KEY,
        DECRYPT_FAILED,
        HANDSHAKE_INCOMPLETE,
        NONCE_EXHAUSTED,
        RANDOM_FAILURE,
        INVALID_PARAMETER,
        INTERNAL,
    }
}

/**
 * Noise_XX_25519_ChaChaPoly_SHA256 — byte-compatible with iOS `NoiseXX`.
 *
 * The complete state of one handshake/transport session is serialized by
 * [lock]. Do not expose the internal CipherState objects: callers must use
 * [encrypt] and [decrypt], which share the same session boundary.
 */
class NoiseXX(
    private val role: Role,
    staticPrivate: ByteArray,
) {
    enum class Role { INITIATOR, RESPONDER }
    private enum class State {
        NEW,
        INITIATOR_WAIT_2,
        INITIATOR_READY_3,
        RESPONDER_READY_2,
        RESPONDER_WAIT_3,
        COMPLETE,
        FAILED,
        CLOSED,
    }

    private val lock = ReentrantLock()
    private val staticPrivate = staticPrivate.copyOf()
    private var state = State.NEW
    private var ephemeralPrivate: ByteArray? = null
    private var remoteEphemeral: ByteArray? = null
    private var remoteStaticInternal: ByteArray? = null
    private var ck: ByteArray
    private var h: ByteArray
    private var handshakeCipher: CipherState? = null
    private var sendCipher: CipherState? = null
    private var recvCipher: CipherState? = null

    /** A snapshot; the returned array is never an internal reference. */
    val remoteStatic: ByteArray?
        get() = lock.withLock { remoteStaticInternal?.copyOf() }

    val completed: Boolean
        get() = lock.withLock { state == State.COMPLETE }

    init {
        if (staticPrivate.size != 32) throw NoiseError(NoiseError.Code.INVALID_KEY)
        val name = "Noise_XX_25519_ChaChaPoly_SHA256".toByteArray(Charsets.UTF_8)
        h = if (name.size <= 32) name + ByteArray(32 - name.size) else sha256(name)
        ck = h.copyOf()
        mixHash(ByteArray(0))
    }

    /** Provisional id from Noise static (X25519). */
    val remoteSessionId: ByteArray?
        get() = lock.withLock {
            remoteStaticInternal?.let { IdentityCrypto.sessionId(it).copyOf() }
        }

    // ---- Initiator ----

    fun initiatorWrite1(payload: ByteArray = ByteArray(0)): ByteArray = lock.withLock {
        ensureRole(Role.INITIATOR)
        ensureState(State.NEW)
        try {
            val e = genX25519()
            ephemeralPrivate = e
            val pub = pubFromPriv(e)
            mixHash(pub)
            mixHash(payload)
            state = State.INITIATOR_WAIT_2
            pub + payload.copyOf()
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    fun initiatorRead2(message: ByteArray): ByteArray = lock.withLock {
        ensureRole(Role.INITIATOR)
        ensureState(State.INITIATOR_WAIT_2)
        try {
            val e = ephemeralPrivate ?: throw NoiseError(NoiseError.Code.INVALID_STATE)
            if (message.size < 80) throw NoiseError(NoiseError.Code.MALFORMED_MESSAGE)
            val re = message.copyOfRange(0, 32)
            remoteEphemeral = re
            mixHash(re)
            mixKey(dh(e, re))

            val encS = message.copyOfRange(32, 80)
            val plainS = requireCipher(handshakeCipher).decrypt(encS, h)
            try {
                if (plainS.size != 32) throw NoiseError(NoiseError.Code.INVALID_KEY)
                mixHash(encS)
                remoteStaticInternal = plainS.copyOf()
                mixKey(dh(e, plainS))
            } finally {
                plainS.fill(0)
            }

            val payload = if (message.size == 80) {
                ByteArray(0)
            } else {
                val encP = message.copyOfRange(80, message.size)
                val p = requireCipher(handshakeCipher).decrypt(encP, h)
                mixHash(encP)
                p
            }
            state = State.INITIATOR_READY_3
            payload
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    fun initiatorWrite3(payload: ByteArray = ByteArray(0)): ByteArray = lock.withLock {
        ensureRole(Role.INITIATOR)
        ensureState(State.INITIATOR_READY_3)
        try {
            val re = remoteEphemeral ?: throw NoiseError(NoiseError.Code.INVALID_STATE)
            val encS = requireCipher(handshakeCipher).encrypt(staticPublic(), h)
            mixHash(encS)
            mixKey(dh(staticPrivate, re))
            val encP = requireCipher(handshakeCipher).encrypt(payload, h)
            mixHash(encP)
            val result = encS + encP
            splitLocked()
            result
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    // ---- Responder ----

    fun responderRead1(message: ByteArray): ByteArray = lock.withLock {
        ensureRole(Role.RESPONDER)
        ensureState(State.NEW)
        try {
            if (message.size < 32) throw NoiseError(NoiseError.Code.MALFORMED_MESSAGE)
            val re = message.copyOfRange(0, 32)
            remoteEphemeral = re
            mixHash(re)
            val payload = if (message.size > 32) message.copyOfRange(32, message.size) else ByteArray(0)
            mixHash(payload)
            state = State.RESPONDER_READY_2
            payload
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    fun responderWrite2(payload: ByteArray = ByteArray(0)): ByteArray = lock.withLock {
        ensureRole(Role.RESPONDER)
        ensureState(State.RESPONDER_READY_2)
        try {
            val re = remoteEphemeral ?: throw NoiseError(NoiseError.Code.INVALID_STATE)
            val e = genX25519()
            ephemeralPrivate = e
            val pub = pubFromPriv(e)
            mixHash(pub)
            mixKey(dh(e, re))
            val encS = requireCipher(handshakeCipher).encrypt(staticPublic(), h)
            mixHash(encS)
            mixKey(dh(staticPrivate, re))
            val encP = requireCipher(handshakeCipher).encrypt(payload, h)
            val result = pub + encS + encP
            mixHash(encP)
            state = State.RESPONDER_WAIT_3
            result
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    fun responderRead3(message: ByteArray): ByteArray = lock.withLock {
        ensureRole(Role.RESPONDER)
        ensureState(State.RESPONDER_WAIT_3)
        try {
            val e = ephemeralPrivate ?: throw NoiseError(NoiseError.Code.INVALID_STATE)
            if (message.size < 48) throw NoiseError(NoiseError.Code.MALFORMED_MESSAGE)
            val encS = message.copyOfRange(0, 48)
            val plainS = requireCipher(handshakeCipher).decrypt(encS, h)
            try {
                if (plainS.size != 32) throw NoiseError(NoiseError.Code.INVALID_KEY)
                mixHash(encS)
                remoteStaticInternal = plainS.copyOf()
                mixKey(dh(e, plainS))
            } finally {
                plainS.fill(0)
            }
            val payload = if (message.size == 48) {
                ByteArray(0)
            } else {
                val encP = message.copyOfRange(48, message.size)
                val p = requireCipher(handshakeCipher).decrypt(encP, h)
                mixHash(encP)
                p
            }
            splitLocked()
            payload
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    /** Transport send; serialized with transport receive and all state changes. */
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray = lock.withLock {
        ensureState(State.COMPLETE)
        try {
            requireCipher(sendCipher).encrypt(plaintext, associatedData)
        } catch (e: Exception) {
            throw failAndMapLocked(e)
        }
    }

    /**
     * Transport receive. Authentication failure does not advance nonce and does
     * not mutate the session, so a packet routed to the wrong session cannot
     * destroy an otherwise healthy session.
     */
    fun decrypt(ciphertext: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray = lock.withLock {
        ensureState(State.COMPLETE)
        requireCipher(recvCipher).decrypt(ciphertext, associatedData)
    }

    /** Explicitly close and wipe session-local key material. */
    fun close() = lock.withLock { closeLocked() }

    private fun ensureRole(expected: Role) {
        if (role != expected) throw NoiseError(NoiseError.Code.ROLE_MISMATCH)
    }

    private fun ensureState(expected: State) {
        if (state != expected) throw NoiseError(NoiseError.Code.INVALID_STATE)
    }

    private fun requireCipher(cipher: CipherState?): CipherState =
        cipher ?: throw NoiseError(NoiseError.Code.HANDSHAKE_INCOMPLETE)

    private fun failAndMapLocked(error: Throwable): NoiseError {
        failLocked()
        return mapError(error, NoiseError.Code.INTERNAL)
    }

    private fun mapError(error: Throwable, fallback: NoiseError.Code): NoiseError {
        if (error is NoiseError) return error
        val code = when (error) {
            is IndexOutOfBoundsException,
            is NegativeArraySizeException -> NoiseError.Code.MALFORMED_MESSAGE
            is IllegalArgumentException -> NoiseError.Code.MALFORMED_MESSAGE
            else -> fallback
        }
        return NoiseError(code, error)
    }

    private fun mixHash(data: ByteArray) {
        h = sha256(h + data)
    }

    private fun mixKey(ikm: ByteArray) {
        try {
            val out = cqHkdf(ikm = ikm, salt = ck, info = ByteArray(0), length = 64)
            ck.fill(0)
            ck = out.copyOfRange(0, 32)
            handshakeCipher?.close()
            handshakeCipher = CipherState(out.copyOfRange(32, 64))
            out.fill(0)
        } finally {
            ikm.fill(0)
        }
    }

    private fun splitLocked() {
        val out = cqHkdf(ikm = ByteArray(0), salt = ck, info = ByteArray(0), length = 64)
        val k1 = out.copyOfRange(0, 32)
        val k2 = out.copyOfRange(32, 64)
        sendCipher?.close()
        recvCipher?.close()
        if (role == Role.INITIATOR) {
            sendCipher = CipherState(k1)
            recvCipher = CipherState(k2)
        } else {
            sendCipher = CipherState(k2)
            recvCipher = CipherState(k1)
        }
        handshakeCipher?.close()
        handshakeCipher = null
        out.fill(0)
        ck.fill(0)
        h.fill(0)
        ephemeralPrivate?.fill(0)
        ephemeralPrivate = null
        remoteEphemeral?.fill(0)
        remoteEphemeral = null
        // This Noise object is transport-only after split; its private static
        // key copy is not needed again.
        staticPrivate.fill(0)
        state = State.COMPLETE
    }

    private fun failLocked() {
        if (state == State.CLOSED) return
        state = State.FAILED
        ephemeralPrivate?.fill(0)
        remoteEphemeral?.fill(0)
        ck.fill(0)
        h.fill(0)
        handshakeCipher?.close()
        handshakeCipher = null
        sendCipher?.close()
        recvCipher?.close()
        sendCipher = null
        recvCipher = null
        staticPrivate.fill(0)
    }

    private fun closeLocked() {
        if (state == State.CLOSED) return
        failLocked()
        state = State.CLOSED
    }

    companion object {
        fun genX25519(): ByteArray = try {
            ByteArray(32).also { SecureRandom().nextBytes(it) }
        } catch (e: Exception) {
            throw NoiseError(NoiseError.Code.RANDOM_FAILURE, e)
        }

        fun pubFromPriv(priv: ByteArray): ByteArray {
            if (priv.size != 32) throw NoiseError(NoiseError.Code.INVALID_KEY)
            return try {
                X25519PrivateKeyParameters(priv.copyOf(), 0).generatePublicKey().encoded
            } catch (e: Exception) {
                throw NoiseError(NoiseError.Code.INVALID_KEY, e)
            }
        }

        fun dh(priv: ByteArray, pub: ByteArray): ByteArray {
            if (priv.size != 32 || pub.size != 32) {
                throw NoiseError(NoiseError.Code.INVALID_KEY)
            }
            return try {
                val agreement = X25519Agreement()
                agreement.init(X25519PrivateKeyParameters(priv.copyOf(), 0))
                val out = ByteArray(agreement.agreementSize)
                agreement.calculateAgreement(X25519PublicKeyParameters(pub.copyOf(), 0), out, 0)
                // RFC 7748 requires rejecting the all-zero shared secret.
                var nonZero = 0
                for (b in out) nonZero = nonZero or (b.toInt() and 0xff)
                if (nonZero == 0) {
                    out.fill(0)
                    throw NoiseError(NoiseError.Code.INVALID_KEY)
                }
                out
            } catch (e: NoiseError) {
                throw e
            } catch (e: Exception) {
                throw NoiseError(NoiseError.Code.INVALID_KEY, e)
            }
        }

        fun sha256(data: ByteArray): ByteArray {
            val d = SHA256Digest()
            d.update(data, 0, data.size)
            val out = ByteArray(32)
            d.doFinal(out, 0)
            return out
        }

        fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            if (length < 0) throw NoiseError(NoiseError.Code.INVALID_PARAMETER)
            return try {
                val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt.copyOf()
                val gen = HKDFBytesGenerator(SHA256Digest())
                gen.init(HKDFParameters(ikm.copyOf(), effectiveSalt, info.copyOf()))
                ByteArray(length).also { gen.generateBytes(it, 0, length) }
            } catch (e: NoiseError) {
                throw e
            } catch (e: Exception) {
                throw NoiseError(NoiseError.Code.INTERNAL, e)
            }
        }

        /** Same as iOS cqHKDF (HMAC extract + expand). */
        fun cqHkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            if (length !in 0..(255 * 32)) {
                throw NoiseError(NoiseError.Code.INVALID_PARAMETER)
            }
            try {
                val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt.copyOf()
                val hmac = HMac(SHA256Digest())
                hmac.init(KeyParameter(effectiveSalt))
                hmac.update(ikm, 0, ikm.size)
                val prk = ByteArray(hmac.macSize)
                hmac.doFinal(prk, 0)
                val out = ByteArray(length)
                var t = ByteArray(0)
                var counter = 1
                var written = 0
                try {
                    while (written < length) {
                        if (counter > 255) throw NoiseError(NoiseError.Code.INVALID_PARAMETER)
                        hmac.init(KeyParameter(prk))
                        hmac.update(t, 0, t.size)
                        hmac.update(info, 0, info.size)
                        hmac.update(byteArrayOf(counter.toByte()), 0, 1)
                        val next = ByteArray(hmac.macSize)
                        hmac.doFinal(next, 0)
                        t.fill(0)
                        t = next
                        val copy = minOf(t.size, length - written)
                        t.copyInto(out, written, 0, copy)
                        written += copy
                        counter++
                    }
                    return out
                } finally {
                    prk.fill(0)
                    t.fill(0)
                }
            } catch (e: NoiseError) {
                throw e
            } catch (e: Exception) {
                throw NoiseError(NoiseError.Code.INTERNAL, e)
            }
        }
    }
}

/** Thread-safe AEAD counter state. */
class CipherState(key: ByteArray) {
    private val lock = ReentrantLock()
    private val key = key.copyOf()
    private var n: Long = 0
    private var closed = false

    fun encrypt(plaintext: ByteArray, ad: ByteArray): ByteArray = lock.withLock {
        ensureOpen()
        ensureCounter()
        val cipher = ChaCha20Poly1305()
        val nonce = noiseNonce(n)
        try {
            cipher.init(true, AEADParameters(BCKeyParameter(key.copyOf()), 128, nonce, ad.copyOf()))
        } catch (e: Exception) {
            throw NoiseError(NoiseError.Code.INTERNAL, e)
        }
        val input = plaintext.copyOf()
        try {
            val out = ByteArray(cipher.getOutputSize(input.size))
            val len = cipher.processBytes(input, 0, input.size, out, 0)
            cipher.doFinal(out, len)
            n++
            out
        } catch (e: NoiseError) {
            throw e
        } catch (e: Exception) {
            throw NoiseError(NoiseError.Code.INTERNAL, e)
        } finally {
            input.fill(0)
        }
    }

    fun decrypt(ciphertext: ByteArray, ad: ByteArray): ByteArray = lock.withLock {
        ensureOpen()
        if (ciphertext.size < 16) {
            throw NoiseError(NoiseError.Code.MALFORMED_MESSAGE)
        }
        ensureCounter()
        val cipher = ChaCha20Poly1305()
        val nonce = noiseNonce(n)
        try {
            cipher.init(false, AEADParameters(BCKeyParameter(key.copyOf()), 128, nonce, ad.copyOf()))
        } catch (e: Exception) {
            throw NoiseError(NoiseError.Code.DECRYPT_FAILED, e)
        }
        val input = ciphertext.copyOf()
        try {
            val out = ByteArray(cipher.getOutputSize(input.size))
            val len = cipher.processBytes(input, 0, input.size, out, 0)
            val fin = cipher.doFinal(out, len)
            n++ // Only after authentication succeeds.
            return out.copyOf(len + fin)
        } catch (e: NoiseError) {
            throw e
        } catch (e: Exception) {
            throw NoiseError(NoiseError.Code.DECRYPT_FAILED, e)
        } finally {
            input.fill(0)
        }
    }

    fun close() = lock.withLock {
        if (!closed) {
            closed = true
            key.fill(0)
            n = Long.MAX_VALUE
        }
    }

    private fun ensureOpen() {
        if (closed) throw NoiseError(NoiseError.Code.INVALID_STATE)
    }

    private fun ensureCounter() {
        if (n >= Long.MAX_VALUE) throw NoiseError(NoiseError.Code.NONCE_EXHAUSTED)
    }

    companion object {
        fun noiseNonce(n: Long): ByteArray {
            if (n < 0) throw NoiseError(NoiseError.Code.INVALID_PARAMETER)
            val data = ByteArray(12)
            val le = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(n).array()
            System.arraycopy(le, 0, data, 4, 8)
            return data
        }
    }
}

object IdentityCrypto {
    /** Identity fingerprint = SHA256(ed25519_public)[0:16] (protocol-v0.1). */
    fun fingerprint(ed25519Public: ByteArray): ByteArray =
        NoiseXX.sha256(ed25519Public).copyOf(16)

    fun sessionId(x25519Public: ByteArray): ByteArray =
        NoiseXX.sha256(x25519Public).copyOf(16)

    /** Bytes signed by Ed25519 to bind the stable identity to Noise X25519. */
    fun identityBindingMessage(x25519Public: ByteArray, ed25519Public: ByteArray): ByteArray {
        if (x25519Public.size != 32 || ed25519Public.size != 32) {
            throw NoiseError(NoiseError.Code.INVALID_PARAMETER)
        }
        return IDENTITY_BINDING_DOMAIN + byteArrayOf(1) + x25519Public + ed25519Public
    }

    private val IDENTITY_BINDING_DOMAIN =
        "CQchat identity binding v1".toByteArray(Charsets.UTF_8)
}
