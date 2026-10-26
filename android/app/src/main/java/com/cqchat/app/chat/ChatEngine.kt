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
    enum class Status { QUEUED, SENT, DELIVERED, FAILED, RECEIVED }
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
    private var started = false

    private data class HelloIdentity(
        val nickname: String,
        val ed25519Public: ByteArray,
        val x25519Public: ByteArray,
        val bindingSignature: ByteArray,
    )

    fun start() {
        if (started) return
        started = true
        ble = BleMeshService(getApplication(), this)
        tcp = HotspotTcpService(getApplication(), this)
        ble.start()
        tcp.start()
    }

    override fun onCleared() {
        if (::ble.isInitialized) ble.stop()
        if (::tcp.isInitialized) tcp.stop()
        started = false
    }

    fun markVerified(qr: String) {
        val fp = identity.parseQR(qr) ?: return
        identity.markVerified(fp)
        peers.indexOfFirst { it.fingerprint?.contentEquals(fp) == true }.takeIf { it >= 0 }?.let {
            peers[it] = peers[it].copy(verified = true)
        }
    }

    fun sendPublic(text: String) {
        if (!started) return
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
        if (!started) return
        val noise = sessions.begin(NoiseXX.Role.INITIATOR, peer.tempId)
        val body = noise.initiatorWrite1()
        val payload = HandshakePayload.encode(1, body)
        val pkt = CQPacket.make(
            CQ.Type.HANDSHAKE, ble.tempId, destination = peer.tempId, payload = payload
        )
        routeOut(pkt.encode(), preferTcp = false)
    }

    fun sendPrivateText(text: String, fp: ByteArray) {
        if (!started) return
        val session = sessions.session(fp) ?: return
        val plain = PrivatePlaintext.encode(CQ.Content.TEXT, text.toByteArray(Charsets.UTF_8))
        val msgId = CQPacket.random16()
        val envelope = CQPacket.make(
            CQ.Type.PRIVATE, ble.tempId, msgId,
            flags = CQ.Flag.NEEDS_ACK, payload = ByteArray(0),
            destination = session.remoteTempId,
        )
        val pkt = envelope.copy(payload = session.noise.encrypt(plain, envelope.associatedData()))
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
                isPublic = false, status = ChatMessage.Status.QUEUED,
            )
            pendingMedia.add(msg)
            appendPrivate(fp, msg)
            return
        }
        val plain = PrivatePlaintext.encode(
            if (kind == ChatMessage.Kind.IMAGE) CQ.Content.IMAGE else CQ.Content.VOICE,
            body,
        )
        val msgId = CQPacket.random16()
        val envelope = CQPacket.make(
            CQ.Type.PRIVATE, ble.tempId, msgId,
            flags = CQ.Flag.NEEDS_ACK, payload = ByteArray(0),
            destination = session.remoteTempId,
        )
        val pkt = envelope.copy(payload = session.noise.encrypt(plain, envelope.associatedData()))
        val wire = pkt.encode()
        val preferTcp = size > 1024 || size > CQ.MEDIA_BLE_MAX
        if (preferTcp) {
            if (!tcp.send(wire)) {
                if (size <= CQ.MEDIA_BLE_MAX) ble.send(wire) else {
                    val msg = ChatMessage(
                        msgId, kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                        fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                        isPublic = false, status = ChatMessage.Status.QUEUED,
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
            for (msg in pendingMedia.filter { it.status == ChatMessage.Status.QUEUED }) {
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
                AckPayload.decode(pkt.payload)?.let {
                    awaitingAck.remove(it.toHex())
                    markDelivered(it)
                }
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
                routeOut(
                    CQPacket.make(
                        CQ.Type.HANDSHAKE, ble.tempId,
                        destination = pkt.sender, payload = payload,
                    ).encode(), false
                )
            }
            2 -> {
                val noise = sessions.handshake(temp) ?: return
                noise.initiatorRead2(body)
                val out = noise.initiatorWrite3(encodeHello())
                val payload = HandshakePayload.encode(3, out)
                routeOut(
                    CQPacket.make(
                        CQ.Type.HANDSHAKE, ble.tempId,
                        destination = pkt.sender, payload = payload,
                    ).encode(), false
                )
                sessions.complete(temp)
                // Noise completion is provisional; Hello still has to bind the identity.
                upsertPeer(temp, null, "待验证")
            }
            3 -> {
                val noise = sessions.handshake(temp) ?: return
                val payload = noise.responderRead3(body)
                val hello = PrivatePlaintext.decode(payload)
                    ?.takeIf { it.first == CQ.Content.HELLO }
                    ?.second
                    ?.let(::parseHello)
                val remoteX25519 = noise.remoteStatic
                if (hello == null || !verifyHello(hello, remoteX25519)) {
                    sessions.abort(temp)
                    return
                }
                sessions.complete(temp)
                val sid = noise.remoteSessionId ?: return
                val idFp = IdentityCrypto.fingerprint(hello.ed25519Public)
                if (!sessions.authenticate(sid, idFp, hello.nickname)) return
                sessions.session(idFp)?.let { session ->
                    val envelope = CQPacket.make(
                        CQ.Type.PRIVATE, ble.tempId, destination = temp, payload = ByteArray(0),
                    )
                    val cipher = session.noise.encrypt(encodeHello(), envelope.associatedData())
                    routeOut(
                        envelope.copy(payload = cipher).encode(),
                        false,
                    )
                }
                upsertPeer(temp, idFp, hello.nickname)
            }
        }
    }

    private fun handlePrivate(pkt: CQPacket) {
        for ((key, s) in sessions.allForDecrypt()) {
            val plain = try {
                s.noise.decrypt(pkt.payload, pkt.associatedData())
            } catch (_: Exception) {
                continue
            }
            val (ct, body) = PrivatePlaintext.decode(plain) ?: continue
            val hello = if (ct == CQ.Content.HELLO) parseHello(body) else null
            if (ct == CQ.Content.HELLO) {
                if (hello == null || !verifyHello(hello, s.noise.remoteStatic)) continue
                val sid = s.noise.remoteSessionId ?: key
                val idFp = IdentityCrypto.fingerprint(hello.ed25519Public)
                if (!s.isIdentityAuthenticated()) {
                    if (!sessions.authenticate(sid, idFp, hello.nickname)) continue
                } else if (!idFp.contentEquals(key)) continue
            } else if (!s.isIdentityAuthenticated()) {
                // A completed Noise handshake alone never authorizes application data.
                continue
            }
            if (pkt.flags and CQ.Flag.NEEDS_ACK != 0) {
                val ack = CQPacket.make(
                    CQ.Type.ACK, ble.tempId,
                    destination = pkt.sender,
                    payload = AckPayload.encode(pkt.msgId),
                )
                routeOut(ack.encode(), false)
            }
            when (ct) {
                CQ.Content.TEXT -> {
                    val text = body.toString(Charsets.UTF_8)
                    appendPrivate(key, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = key,
                        fromNickname = s.nickname, isPublic = false, status = ChatMessage.Status.RECEIVED,
                    ))
                    notifier.message("私聊", text)
                }
                CQ.Content.IMAGE -> {
                    val (thumb, data) = MediaContainer.decode(body) ?: return
                    appendPrivate(key, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.IMAGE, imageJpeg = data, thumbJpeg = thumb,
                        fromFingerprint = key, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    ))
                }
                CQ.Content.VOICE -> {
                    val (_, data) = MediaContainer.decode(body) ?: return
                    appendPrivate(key, ChatMessage(
                        pkt.msgId, ChatMessage.Kind.VOICE, voiceCqop = data,
                        fromFingerprint = key, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    ))
                }
                CQ.Content.HELLO -> {
                    val verifiedHello = hello ?: return
                    val idFp = IdentityCrypto.fingerprint(verifiedHello.ed25519Public)
                    // authenticate() above may have moved the session out of
                    // the provisional table; validate the committed table,
                    // not the stale local Session snapshot.
                    if (sessions.session(idFp) == null) return
                    upsertPeer(s.remoteTempId, idFp, verifiedHello.nickname)
                }
            }
            return
        }
        Log.w("CQchat", "private decrypt miss")
    }


    private fun encodeHello(): ByteArray {
        val nicknameBytes = identity.nickname.toByteArray(Charsets.UTF_8)
        val nick = nicknameBytes.copyOf(minOf(255, nicknameBytes.size))
        val bindingSignature = identity.signIdentityBinding()
        val body = byteArrayOf(nick.size.toByte()) + nick +
            identity.ed25519Public + identity.x25519Public + bindingSignature
        return PrivatePlaintext.encode(CQ.Content.HELLO, body)
    }

    private fun parseHello(body: ByteArray): HelloIdentity? {
        if (body.isEmpty()) return null
        val n = body[0].toInt() and 0xff
        if (body.size != 1 + n + 32 + 32 + 64) return null
        val nick = body.copyOfRange(1, 1 + n).toString(Charsets.UTF_8)
        val edPk = body.copyOfRange(1 + n, 1 + n + 32)
        val xPk = body.copyOfRange(1 + n + 32, 1 + n + 64)
        val signature = body.copyOfRange(1 + n + 64, body.size)
        return HelloIdentity(nick, edPk, xPk, signature)
    }

    private fun verifyHello(hello: HelloIdentity, expectedX25519: ByteArray?): Boolean {
        return expectedX25519 != null &&
            expectedX25519.contentEquals(hello.x25519Public) &&
            identity.verifyIdentityBinding(
                hello.ed25519Public,
                hello.x25519Public,
                hello.bindingSignature,
            )
    }

    private fun markDelivered(msgId: ByteArray) {
        for ((_, list) in privateMessages) {
            val i = list.indexOfFirst { it.id.contentEquals(msgId) }
            if (i >= 0) {
                list[i].status = ChatMessage.Status.DELIVERED
            }
        }
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
