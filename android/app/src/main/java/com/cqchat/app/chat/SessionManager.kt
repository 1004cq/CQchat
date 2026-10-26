package com.cqchat.app.chat

import com.cqchat.app.protocol.IdentityCrypto
import com.cqchat.app.protocol.NoiseXX
import com.cqchat.app.protocol.hexToBytes
import com.cqchat.app.protocol.toHex

class SessionManager(private val staticPrivate: ByteArray) {
    data class Session(
        val noise: NoiseXX,
        var remoteTempId: ByteArray,
        var nickname: String,
        var identityFingerprint: ByteArray? = null,
        var failed: Boolean = false,
    )

    private val byKey = HashMap<String, Session>()
    private val handshakeByTemp = HashMap<String, NoiseXX>()
    private val tempToKey = HashMap<String, String>()

    @Synchronized
    fun begin(role: NoiseXX.Role, tempId: ByteArray): NoiseXX {
        val n = NoiseXX(role, staticPrivate)
        handshakeByTemp[tempId.toHex()] = n
        return n
    }

    @Synchronized
    fun handshake(tempId: ByteArray): NoiseXX? = handshakeByTemp[tempId.toHex()]

    @Synchronized
    fun complete(tempId: ByteArray, nickname: String = "") {
        val n = handshakeByTemp.remove(tempId.toHex()) ?: return
        if (!n.completed) return
        val sid = n.remoteSessionId ?: return
        val s = Session(n, tempId, nickname)
        byKey[sid.toHex()] = s
        tempToKey[tempId.toHex()] = sid.toHex()
    }

    @Synchronized
    fun rebind(fromSessionId: ByteArray, toIdentityFingerprint: ByteArray): Session? {
        val sid = fromSessionId.toHex()
        val fp = toIdentityFingerprint.toHex()
        val s = byKey[sid] ?: byKey[fp] ?: return null
        s.identityFingerprint = toIdentityFingerprint
        byKey[fp] = s
        byKey[sid] = s
        tempToKey.entries.find { it.value == sid }?.let { it.setValue(fp) }
        return s
    }

    @Synchronized
    fun bindTempId(tempId: ByteArray, key: ByteArray) {
        tempToKey[tempId.toHex()] = key.toHex()
        byKey[key.toHex()]?.remoteTempId = tempId
    }

    @Synchronized
    fun session(key: ByteArray): Session? = byKey[key.toHex()]

    @Synchronized
    fun all(): List<Pair<ByteArray, Session>> {
        val seen = HashSet<NoiseXX>()
        val out = ArrayList<Pair<ByteArray, Session>>()
        for ((k, s) in byKey) {
            if (!seen.add(s.noise)) continue
            val id = s.identityFingerprint ?: (k.hexToBytes() ?: continue)
            out.add(id to s)
        }
        return out
    }

    @Synchronized
    fun keyForTemp(tempId: ByteArray): ByteArray? =
        tempToKey[tempId.toHex()]?.hexToBytes()

    @Synchronized
    fun updateNickname(key: ByteArray, name: String) {
        byKey[key.toHex()]?.nickname = name
    }

    @Synchronized
    fun markFailed(key: ByteArray) {
        byKey[key.toHex()]?.failed = true
    }

    @Synchronized
    fun remove(key: ByteArray) {
        val s = byKey.remove(key.toHex()) ?: return
        s.identityFingerprint?.let { byKey.remove(it.toHex()) }
        s.noise.remoteSessionId?.let { byKey.remove(it.toHex()) }
        tempToKey.entries.removeAll { it.value == key.toHex() }
    }
}
