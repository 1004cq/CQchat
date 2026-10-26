package com.cqchat.app.chat

import android.app.Application
import android.util.Log
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.lifecycle.AndroidViewModel
import com.cqchat.app.crypto.IdentityStore
import com.cqchat.app.media.ImageCompressor
import com.cqchat.app.notify.LocalNotifier
import com.cqchat.app.protocol.*
import com.cqchat.app.transport.BleMeshListener
import com.cqchat.app.transport.BleMeshService
import com.cqchat.app.transport.HotspotListener
import com.cqchat.app.transport.HotspotTcpService
import java.security.SecureRandom

data class ChatMessage(
    val id: ByteArray,
    val kind: Kind,
    val text: String? = null,
    val imageJpeg: ByteArray? = null,
    val thumbJpeg: ByteArray? = null,
    val voiceCqop: ByteArray? = null,
    val fromFingerprint: ByteArray? = null,
    val fromNickname: String,
    val isPublic: Boolean,
    var status: Status,
    val ts: Long = System.currentTimeMillis(),
) {
    enum class Kind { TEXT, IMAGE, VOICE, SYSTEM }
    enum class Status { SENT, WAITING, FAILED, RECEIVED }
}

data class Peer(
    var tempId: ByteArray,
    var fingerprint: ByteArray? = null,
    var nickname: String = "附近",
    var verified: Boolean = false,
    var lastSeen: Long = System.currentTimeMillis(),
)

class ChatEngine(app: Application) : AndroidViewModel(app), BleMeshListener, HotspotListener {
    val identity = IdentityStore(app)
    val publicMessages = mutableStateListOf<ChatMessage>()
    val privateMessages = mutableStateMapOf<String, MutableList<ChatMessage>>()
    val peers = mutableStateListOf<Peer>()
    val pendingMedia = mutableStateListOf<ChatMessage>()

    private val sessions = SessionManager(identity.x25519Private)
    private val dedup = DedupCache()
    private val notifier = LocalNotifier(app)
    private val nearbyCooldown = HashMap<String, Long>()
    private val awaitingAck = HashMap<String, ByteArray>()

    private lateinit var ble: BleMeshService
    private lateinit var tcp: HotspotTcpService

    fun start() {
        ble = BleMeshService(getApplication(), this)
        tcp = HotspotTcpService(getApplication(), this)
        ble.start()
        tcp.start()
    }

    override fun onCleared() {
        if (::ble.isInitialized) ble.stop()
        if (::tcp.isInitialized) tcp.stop()
    }

    fun markVerified(qr: String) {
        val fp = identity.parseQR(qr) ?: return
        identity.markVerified(fp)
        peers.indexOfFirst { it.fingerprint?.contentEquals(fp) == true }.takeIf { it >= 0 }?.let {
            peers[it] = peers[it].copy(verified = true)
        }
    }

    fun sendPublic(text: String) {
        val msgId = CQPacket.random16()
        val signMsg = BroadcastPayload.signMessage(msgId, identity.nickname, text)
        val sig = identity.sign(signMsg)
        val payload = BroadcastPayload.encode(identity.nickname, text, identity.ed25519Public, sig)
        val pkt = CQPacket.make(CQ.Type.BROADCAST, ble.tempId, msgId, payload = payload)
        routeOut(pkt.encode(), preferTcp = false)
        publicMessages.add(
            ChatMessage(msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = identity.fingerprint,
                fromNickname = identity.nickname, isPublic = true, status = ChatMessage.Status.SENT)
        )
    }

    fun startPrivate(peer: Peer) {
        val noise = sessions.begin(NoiseXX.Role.INITIATOR, peer.tempId)
        val body = noise.initiatorWrite1()
        val payload = HandshakePayload.encode(1, body)
        val pkt = CQPacket.make(CQ.Type.HANDSHAKE, ble.tempId, payload = payload)
        routeOut(pkt.encode(), preferTcp = false)
    }

    fun sendPrivateText(text: String, fp: ByteArray) {
        val session = sessions.session(fp) ?: return
        val plain = PrivatePlaintext.encode(CQ.Content.TEXT, text.toByteArray(Charsets.UTF_8))
        val cipher = session.noise.encrypt(plain)
        val msgId = CQPacket.random16()
        val pkt = CQPacket.make(
            CQ.Type.PRIVATE, ble.tempId, msgId,
            flags = CQ.Flag.NEEDS_ACK, payload = cipher,
        )
        val wire = pkt.encode()
        routeOut(wire, preferTcp = false)
        awaitingAck[msgId.toHex()] = wire
        appendPrivate(fp, ChatMessage(
            msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = identity.fingerprint,
            fromNickname = identity.nickname, isPublic = false, status = ChatMessage.Status.SENT,
        ))
    }

    fun sendPrivateImage(bytes: ByteArray, fp: ByteArray) {
        val compressed = ImageCompressor.compress(bytes) ?: return
        val (full, thumb) = compressed
        val body = MediaContainer.encode(thumb, full)
        sendPrivateMedia(body, fp, ChatMessage.Kind.IMAGE, full, thumb)
    }

    fun sendPrivateVoice(cqop: ByteArray, fp: ByteArray) {
        val body = MediaContainer.encode(ByteArray(0), cqop)
        sendPrivateMedia(body, fp, ChatMessage.Kind.VOICE, voice = cqop)
    }

    private fun sendPrivateMedia(
        body: ByteArray, fp: ByteArray, kind: ChatMessage.Kind,
        full: ByteArray? = null, thumb: ByteArray? = null, voice: ByteArray? = null,
    ) {
        val session = sessions.session(fp) ?: return
        val size = body.size
        if (size > CQ.MEDIA_BLE_MAX && !tcp.hasPeers) {
            val msg = ChatMessage(
                CQPacket.random16(), kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                isPublic = false, status = ChatMessage.Status.WAITING,
            )
            pendingMedia.add(msg)
            appendPrivate(fp, msg)
            return
        }
        val plain = PrivatePlaintext.encode(
            if (kind == ChatMessage.Kind.IMAGE) CQ.Content.IMAGE else CQ.Content.VOICE,
            body,
        )
        val cipher = session.noise.encrypt(plain)
        val msgId = CQPacket.random16()
        val pkt = CQPacket.make(
            CQ.Type.PRIVATE, ble.tempId, msgId,
            flags = CQ.Flag.NEEDS_ACK, payload = cipher,
        )
        val wire = pkt.encode()
        val preferTcp = size > 1024 || size > CQ.MEDIA_BLE_MAX
        if (preferTcp) {
            if (!tcp.send(wire)) {
                if (size <= CQ.MEDIA_BLE_MAX) ble.send(wire) else {
                    val msg = ChatMessage(
                        msgId, kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                        fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                        isPublic = false, status = ChatMessage.Status.WAITING,
                    )
                    pendingMedia.add(msg)
                    appendPrivate(fp, msg)
                    return
                }
            }
        } else {
            routeOut(wire, preferTcp = false)
        }
        awaitingAck[msgId.toHex()] = wire
        appendPrivate(fp, ChatMessage(
            msgId, kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
            fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
            isPublic = false, status = ChatMessage.Status.SENT,
        ))
    }

    private fun routeOut(packet: ByteArray, preferTcp: Boolean) {
        if (preferTcp && tcp.send(packet)) return
        ble.send(packet)
    }

    private fun appendPrivate(fp: ByteArray, msg: ChatMessage) {
        val key = fp.toHex()
        val list = privateMessages[key] ?: mutableStateListOf<ChatMessage>().also {
            privateMessages[key] = it
        }
        list.add(msg)
    }

    override fun onPacket(data: ByteArray) = handlePacket(data)

    override fun onDiscover(tempId: ByteArray) {
        upsertPeer(tempId, null, "附近")
    }

    override fun onPeersChanged(count: Int) {
        // flush waiting media when hotspot peers appear
        if (count > 0) {
            for (msg in pendingMedia.filter { it.status == ChatMessage.Status.WAITING }) {
                // re-send attempted by UI calling send again; mark for flush
            }
        }
    }

    private fun handlePacket(data: ByteArray) {
        val pkt = CQPacket.decode(data) ?: return
        if (pkt.version != CQ.VERSION) return
        if (pkt.type != CQ.Type.ACK && dedup.seen(pkt.msgId)) return
        when (pkt.type) {
            CQ.Type.BROADCAST -> handleBroadcast(pkt)
            CQ.Type.HANDSHAKE -> handleHandshake(pkt)
            CQ.Type.PRIVATE -> handlePrivate(pkt)
            CQ.Type.ACK -> {
                AckPayload.decode(pkt.payload)?.let { awaitingAck.remove(it.toHex()) }
            }
        }
    }

    private fun handleBroadcast(pkt: CQPacket) {
        val decoded = BroadcastPayload.decode(pkt.payload) ?: return
        val msg = BroadcastPayload.signMessage(pkt.msgId, decoded.nickname, decoded.text)
        if (!identity.verify(decoded.pk, msg, decoded.sig)) return
        publicMessages.add(
            ChatMessage(
                pkt.msgId, ChatMessage.Kind.TEXT, text = decoded.text,
                fromNickname = decoded.nickname, isPublic = true, status = ChatMessage.Status.RECEIVED,
            )
        )
        notifier.message(decoded.nickname, decoded.text)
    }

    private fun handleHandshake(pkt: CQPacket) {
        val (pattern, step, body) = HandshakePayload.decode(pkt.payload) ?: return
        if (pattern != 1) return
        val temp = pkt.sender
        when (step) {
            1 -> {
                val noise = sessions.begin(NoiseXX.Role.RESPONDER, temp)
                noise.responderRead1(body)
                val out = noise.responderWrite2()
                val payload = HandshakePayload.encode(2, out)
                routeOut(CQPacket.make(CQ.Type.HANDSHAKE, ble.tempId, payload = payload).encode(), false)
            }
            2 -> {
                val noise = sessions.handshake(temp) ?: return
                noise.initiatorRead2(body)
                val helloBody = byteArrayOf(identity.nickname.toByteArray().size.toByte()) +
                    identity.nickname.toByteArray()
                val out = noise.initiatorWrite3(PrivatePlaintext.encode(CQ.Content.HELLO, helloBody))
                val payload = HandshakePayload.encode(3, out)
                routeOut(CQPacket.make(CQ.Type.HANDSHAKE, ble.tempId, payload = payload).encode(), false)
                sessions.complete(temp)
                noise.remoteFingerprint?.let { upsertPeer(temp, it, "peer") }
            }
            3 -> {
                val noise = sessions.handshake(temp) ?: return
                val payload = noise.responderRead3(body)
                sessions.complete(temp)
                val fp = noise.remoteFingerprint ?: return
                var nick = "peer"
                PrivatePlaintext.decode(payload)?.let { (ct, b) ->
                    if (ct == CQ.Content.HELLO && b.isNotEmpty()) {
                        val nlen = b[0].toInt() and 0xff
                        nick = b.copyOfRange(1, 1 + nlen).toString(Charsets.UTF_8)
                        sessions.updateNickname(fp, nick)
                    }
                }
                val helloBody = byteArrayOf(identity.nickname.toByteArray().size.toByte()) +
                    identity.nickname.toByteArray()
                sessions.session(fp)?.noise?.encrypt(
                    PrivatePlaintext.encode(CQ.Content.HELLO, helloBody)
                )?.let { cipher ->
                    routeOut(
                        CQPacket.make(CQ.Type.PRIVATE, ble.tempId, payload = cipher).encode(),
                        false,
                    )
                }
                upsertPeer(temp, fp, nick)
            }
        }
    }

    private fun handlePrivate(pkt: CQPacket) {
        for (s in sessions.all()) {
            val fp = s.noise.remoteFingerprint ?: continue
            val plain = try {
                s.noise.decrypt(pkt.payload)
            } catch (e: Exception) {
                continue
            }
            val (ct, body) = PrivatePlaintext.decode(plain) ?: continue
            if (pkt.flags and CQ.Flag.NEEDS_ACK != 0) {
                val ack = CQPacket.make(
                    CQ.Type.ACK, ble.tempId,
                    payload = AckPayload.encode(pkt.msgId),
                )
                routeOut(ack.encode(), false)
            }
            when (ct) {
                CQ.Content.TEXT -> {
                    val text = body.toString(Charsets.UTF_8)
                    appendPrivate(fp, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = fp,
                        fromNickname = s.nickname, isPublic = false, status = ChatMessage.Status.RECEIVED,
                    ))
                    notifier.message("私聊", text)
                }
                CQ.Content.IMAGE -> {
                    val (thumb, data) = MediaContainer.decode(body) ?: return
                    appendPrivate(fp, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.IMAGE, imageJpeg = data, thumbJpeg = thumb,
                        fromFingerprint = fp, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    ))
                }
                CQ.Content.VOICE -> {
                    val (_, data) = MediaContainer.decode(body) ?: return
                    appendPrivate(fp, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.VOICE, voiceCqop = data,
                        fromFingerprint = fp, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    ))
                }
                CQ.Content.HELLO -> {
                    if (body.isNotEmpty()) {
                        val nlen = body[0].toInt() and 0xff
                        val nick = body.copyOfRange(1, 1 + nlen).toString(Charsets.UTF_8)
                        sessions.updateNickname(fp, nick)
                    }
                }
            }
            return
        }
        Log.w("CQchat", "private decrypt miss")
    }

    private fun upsertPeer(tempId: ByteArray, fingerprint: ByteArray?, nickname: String) {
        val idx = peers.indexOfFirst {
            it.tempId.contentEquals(tempId) ||
                (fingerprint != null && it.fingerprint?.contentEquals(fingerprint) == true)
        }
        if (idx >= 0) {
            val p = peers[idx]
            peers[idx] = p.copy(
                tempId = tempId,
                fingerprint = fingerprint ?: p.fingerprint,
                nickname = nickname,
                lastSeen = System.currentTimeMillis(),
                verified = (fingerprint ?: p.fingerprint)?.let { identity.isVerified(it) } ?: false,
            )
        } else {
            peers.add(
                Peer(
                    tempId, fingerprint, nickname,
                    verified = fingerprint?.let { identity.isVerified(it) } ?: false,
                )
            )
            fingerprint?.let { fp ->
                val last = nearbyCooldown[fp.toHex()] ?: 0L
                if (System.currentTimeMillis() - last >= CQ.NEARBY_NOTIFY_COOLDOWN_MS) {
                    nearbyCooldown[fp.toHex()] = System.currentTimeMillis()
                    notifier.nearby(nickname)
                }
            }
        }
    }
}
