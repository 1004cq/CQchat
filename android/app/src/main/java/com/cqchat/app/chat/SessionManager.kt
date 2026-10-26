package com.cqchat.app.chat

import com.cqchat.app.protocol.NoiseXX
import com.cqchat.app.protocol.hexToBytes
import com.cqchat.app.protocol.toHex
import java.util.concurrent.TimeUnit

/**
 * Owns Noise handshakes and sessions.
 *
 * A completed Noise handshake is not an authenticated identity. Such a session
 * lives in provisionalBySessionId until the encrypted Hello binding is checked.
 * Only sessions in byFingerprint may be used by normal private-message APIs.
 */
class SessionManager(
    staticPrivate: ByteArray,
    private val maxSessions: Int = DEFAULT_MAX_SESSIONS,
    private val maxHandshakes: Int = DEFAULT_MAX_HANDSHAKES,
    handshakeTtlSeconds: Long = DEFAULT_HANDSHAKE_TTL_SECONDS,
    sessionIdleTimeoutSeconds: Long = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
) {
    enum class State { HANDSHAKE_COMPLETE, IDENTITY_AUTHENTICATED }

    data class Session(
        val noise: NoiseXX,
        var remoteTempId: ByteArray,
        var nickname: String,
        var state: State,
        internal var lastActivityNanos: Long = System.nanoTime(),
    ) {
        init { remoteTempId = remoteTempId.copyOf() }
        fun tempIdSnapshot(): ByteArray = remoteTempId.copyOf()
        fun isIdentityAuthenticated(): Boolean = state == State.IDENTITY_AUTHENTICATED
    }

    private data class HandshakeEntry(
        val noise: NoiseXX,
        val role: NoiseXX.Role,
        val createdAtNanos: Long,
        var lastActivityNanos: Long,
    )

    private val staticPrivate = staticPrivate.copyOf()
    private val handshakeTtlNanos = TimeUnit.SECONDS.toNanos(handshakeTtlSeconds)
    private val sessionIdleTimeoutNanos = TimeUnit.SECONDS.toNanos(sessionIdleTimeoutSeconds)
    private val byFingerprint = HashMap<String, Session>()
    private val provisionalBySessionId = HashMap<String, Session>()
    private val handshakeByTemp = HashMap<String, HandshakeEntry>()
    private var closed = false

    init {
        require(staticPrivate.size == 32)
        require(maxSessions > 0 && maxHandshakes > 0)
        require(handshakeTtlSeconds > 0 && sessionIdleTimeoutSeconds > 0)
    }

    @Synchronized
    fun begin(role: NoiseXX.Role, tempId: ByteArray): NoiseXX {
        ensureOpenLocked(); purgeExpiredLocked()
        val key = tempId.copyOf().toHex()
        val now = System.nanoTime()
        handshakeByTemp[key]?.let { existing ->
            if (existing.role == role) {
                existing.lastActivityNanos = now
                return existing.noise
            }
            existing.noise.close()
            handshakeByTemp.remove(key, existing)
        }
        check(handshakeByTemp.size < maxHandshakes) { "too many pending Noise handshakes" }
        val noise = NoiseXX(role, staticPrivate)
        handshakeByTemp[key] = HandshakeEntry(noise, role, now, now)
        return noise
    }

    @Synchronized
    fun handshake(tempId: ByteArray): NoiseXX? {
        if (closed) return null
        purgeExpiredLocked()
        val entry = handshakeByTemp[tempId.copyOf().toHex()] ?: return null
        entry.lastActivityNanos = System.nanoTime()
        return entry.noise
    }

    @Synchronized
    fun abort(tempId: ByteArray) {
        if (closed) return
        handshakeByTemp.remove(tempId.copyOf().toHex())?.noise?.close()
    }

    /** Moves a completed Noise handshake to the unauthenticated provisional state. */
    @Synchronized
    fun complete(tempId: ByteArray, nickname: String = "") {
        if (closed) return
        purgeExpiredLocked()
        val tempKey = tempId.copyOf().toHex()
        val entry = handshakeByTemp[tempKey] ?: return
        val noise = entry.noise
        if (!noise.completed) return
        val sid = noise.remoteSessionId ?: return
        val sidKey = sid.toHex()
        if (provisionalBySessionId[sidKey]?.noise !== noise ||
            byFingerprint.values.any { it.noise === noise }) {
            provisionalBySessionId[sidKey]?.noise?.close()
            provisionalBySessionId.remove(sidKey)
        }
        handshakeByTemp.remove(tempKey, entry)
        provisionalBySessionId[sidKey] = Session(
            noise = noise,
            remoteTempId = tempId.copyOf(),
            nickname = nickname.take(MAX_NICKNAME_LENGTH),
            state = State.HANDSHAKE_COMPLETE,
        )
        evictProvisionalIfNeededLocked()
    }

    /**
     * Atomically promotes a provisional session after the caller has verified
     * the Hello binding signature and fingerprint. Returns false on collision.
     */
    @Synchronized
    fun authenticate(sessionId: ByteArray, identityFingerprint: ByteArray, nickname: String): Boolean {
        if (closed || sessionId.size != 16 || identityFingerprint.size != 16) return false
        purgeExpiredLocked()
        val sidKey = sessionId.copyOf().toHex()
        val fpKey = identityFingerprint.copyOf().toHex()
        val session = provisionalBySessionId[sidKey] ?: return false
        val existing = byFingerprint[fpKey]
        if (existing != null && existing.noise !== session.noise) return false
        provisionalBySessionId.remove(sidKey)
        session.state = State.IDENTITY_AUTHENTICATED
        session.nickname = nickname.take(MAX_NICKNAME_LENGTH)
        session.lastActivityNanos = System.nanoTime()
        byFingerprint[fpKey] = session
        evictIfNeededLocked()
        return true
    }

    /** Only authenticated sessions are returned by this API. */
    @Synchronized
    fun session(fp: ByteArray): Session? {
        if (closed) return null
        purgeExpiredLocked()
        val session = byFingerprint[fp.copyOf().toHex()] ?: return null
        if (!session.isIdentityAuthenticated()) return null
        session.lastActivityNanos = System.nanoTime()
        return session
    }

    /** Sessions allowed to attempt decryption; callers must authenticate Hello before delivery. */
    @Synchronized
    fun allForDecrypt(): List<Pair<ByteArray, Session>> {
        if (closed) return emptyList()
        purgeExpiredLocked()
        val result = ArrayList<Pair<ByteArray, Session>>(byFingerprint.size + provisionalBySessionId.size)
        result += byFingerprint.map { it.key.hexToBytes()!! to it.value }
        result += provisionalBySessionId.map { it.key.hexToBytes()!! to it.value }
        result.forEach { it.second.lastActivityNanos = System.nanoTime() }
        return result
    }

    @Synchronized
    fun all(): List<Pair<ByteArray, Session>> {
        if (closed) return emptyList()
        purgeExpiredLocked()
        return byFingerprint.map { (key, session) -> key.hexToBytes()!! to session }
    }

    @Synchronized
    fun fingerprintForTemp(tempId: ByteArray): ByteArray? {
        if (closed) return null
        purgeExpiredLocked()
        val snapshot = tempId.copyOf()
        return byFingerprint.entries.firstOrNull { it.value.remoteTempId.contentEquals(snapshot) }
            ?.key?.hexToBytes()
    }

    @Synchronized
    fun provisionalForTemp(tempId: ByteArray): Pair<ByteArray, Session>? {
        if (closed) return null
        purgeExpiredLocked()
        val snapshot = tempId.copyOf()
        return provisionalBySessionId.entries.firstOrNull { it.value.remoteTempId.contentEquals(snapshot) }
            ?.let { it.key.hexToBytes()!! to it.value }
    }

    @Synchronized
    fun updateNickname(fp: ByteArray, name: String) {
        if (closed) return
        byFingerprint[fp.copyOf().toHex()]?.let {
            it.nickname = name.take(MAX_NICKNAME_LENGTH)
            it.lastActivityNanos = System.nanoTime()
        }
    }

    @Synchronized
    fun removeFingerprint(fp: ByteArray) {
        if (closed) return
        byFingerprint.remove(fp.copyOf().toHex())?.noise?.close()
    }

    @Synchronized
    fun clear() {
        if (closed) return
        closed = true
        handshakeByTemp.values.forEach { it.noise.close() }
        provisionalBySessionId.values.forEach { it.noise.close() }
        byFingerprint.values.forEach { it.noise.close() }
        handshakeByTemp.clear(); provisionalBySessionId.clear(); byFingerprint.clear()
        staticPrivate.fill(0)
    }

    private fun ensureOpenLocked() { check(!closed) { "SessionManager is closed" } }

    private fun purgeExpiredLocked() {
        val now = System.nanoTime()
        val hi = handshakeByTemp.iterator()
        while (hi.hasNext()) {
            val e = hi.next().value
            if (now - e.lastActivityNanos >= handshakeTtlNanos || now - e.createdAtNanos >= handshakeTtlNanos) {
                e.noise.close(); hi.remove()
            }
        }
        val pi = provisionalBySessionId.iterator()
        while (pi.hasNext()) {
            val e = pi.next().value
            if (now - e.lastActivityNanos >= handshakeTtlNanos) { e.noise.close(); pi.remove() }
        }
        val si = byFingerprint.iterator()
        while (si.hasNext()) {
            val e = si.next().value
            if (now - e.lastActivityNanos >= sessionIdleTimeoutNanos) { e.noise.close(); si.remove() }
        }
    }

    private fun evictProvisionalIfNeededLocked() {
        while (provisionalBySessionId.size > maxHandshakes) {
            val it = provisionalBySessionId.entries.iterator()
            if (!it.hasNext()) return
            it.next().value.noise.close(); it.remove()
        }
    }

    private fun evictIfNeededLocked() {
        while (byFingerprint.size > maxSessions) {
            val it = byFingerprint.entries.iterator()
            if (!it.hasNext()) return
            it.next().value.noise.close(); it.remove()
        }
    }

    companion object {
        const val DEFAULT_MAX_SESSIONS = 64
        const val DEFAULT_MAX_HANDSHAKES = 64
        const val DEFAULT_HANDSHAKE_TTL_SECONDS = 30L
        const val DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 24L * 60L * 60L
        const val MAX_NICKNAME_LENGTH = 64
    }
}
