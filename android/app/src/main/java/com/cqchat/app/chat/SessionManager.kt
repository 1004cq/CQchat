package com.cqchat.app.chat

import com.cqchat.app.protocol.NoiseXX
import com.cqchat.app.protocol.hexToBytes
import com.cqchat.app.protocol.toHex

class SessionManager(private val staticPrivate: ByteArray) {
    data class Session(
        val noise: NoiseXX,
        var remoteTempId: ByteArray,
        var nickname: String,
    )

    private val byFingerprint = HashMap<String, Session>()
    private val handshakeByTemp = HashMap<String, NoiseXX>()

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
        byFingerprint[sid.toHex()] = Session(n, tempId, nickname)
    }

    @Synchronized
    fun rebind(fromSessionId: ByteArray, toIdentityFingerprint: ByteArray) {
        val s = byFingerprint.remove(fromSessionId.toHex()) ?: return
        byFingerprint[toIdentityFingerprint.toHex()] = s
    }

    @Synchronized
    fun session(fp: ByteArray): Session? = byFingerprint[fp.toHex()]

    @Synchronized
    fun all(): List<Pair<ByteArray, Session>> =
        byFingerprint.map { (it.key.hexToBytes() ?: ByteArray(0)) to it.value }

    @Synchronized
    fun fingerprintForTemp(tempId: ByteArray): ByteArray? {
        val e = byFingerprint.entries.firstOrNull { it.value.remoteTempId.contentEquals(tempId) }
            ?: return null
        return e.key.hexToBytes()
    }

    @Synchronized
    fun updateNickname(fp: ByteArray, name: String) {
        byFingerprint[fp.toHex()]?.nickname = name
    }
}
