package com.cqchat.app.chat

import com.cqchat.app.protocol.NoiseXX
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
        val fp = n.remoteFingerprint ?: return
        byFingerprint[fp.toHex()] = Session(n, tempId, nickname)
    }

    @Synchronized
    fun session(fp: ByteArray): Session? = byFingerprint[fp.toHex()]

    @Synchronized
    fun all(): List<Session> = byFingerprint.values.toList()

    @Synchronized
    fun fingerprintForTemp(tempId: ByteArray): ByteArray? =
        byFingerprint.values.firstOrNull { it.remoteTempId.contentEquals(tempId) }
            ?.noise?.remoteFingerprint

    @Synchronized
    fun updateNickname(fp: ByteArray, name: String) {
        byFingerprint[fp.toHex()]?.nickname = name
    }
}
