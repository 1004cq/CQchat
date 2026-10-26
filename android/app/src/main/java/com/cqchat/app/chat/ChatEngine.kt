package com.cqchat.app.chat

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import com.cqchat.app.crypto.IdentityStore
import com.cqchat.app.media.ImageCompressor
import com.cqchat.app.notify.LocalNotifier
import com.cqchat.app.protocol.*
import com.cqchat.app.transport.BleMeshListener
import com.cqchat.app.transport.BleMeshService
import com.cqchat.app.transport.HotspotListener
import com.cqchat.app.transport.HotspotTcpService
import com.cqchat.app.transport.MeshForegroundService
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

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
    val destKey: ByteArray? = null,
    val ts: Long = System.currentTimeMillis(),
    var pathHint: String = "",
) {
    enum class Kind { TEXT, IMAGE, VOICE, SYSTEM }
    enum class Status { QUEUED, SENT, DELIVERED, FAILED, RECEIVED }
}

enum class PeerLinkPath(val label: String) {
    BLE_DIRECT("蓝牙直连"),
    MESH_RELAY("Mesh 中继"),
    UNREACHABLE("不可达"),
}

data class Peer(
    var tempId: ByteArray,
    var fingerprint: ByteArray? = null,
    var nickname: String = "附近",
    var verified: Boolean = false,
    var lastSeen: Long = System.currentTimeMillis(),
    var pathHint: String = "BLE",
    var linkPath: PeerLinkPath = PeerLinkPath.UNREACHABLE,
    var bleDirect: Boolean = false,
    var lastRxTtl: Int? = null,
    var encrypted: Boolean = false,
    var cryptoFailed: Boolean = false,
    var favorite: Boolean = false,
)

class ChatEngine(app: Application) : AndroidViewModel(app), BleMeshListener, HotspotListener {
    val identity = IdentityStore(app)
    val publicMessages = mutableStateListOf<ChatMessage>()
    val privateMessages = mutableStateMapOf<String, MutableList<ChatMessage>>()
    val peers = mutableStateListOf<Peer>()
    val pendingMedia = mutableStateListOf<ChatMessage>()

    var nearbyMode by mutableStateOf(false)
        private set
    var transportHint by mutableStateOf("未开启附近模式")
        private set
    var identityRevision by mutableStateOf(0)
        private set

    private var sessions = SessionManager(identity.x25519Private)
    private val dedup = DedupCache()
    private val pending = PendingOutbound()
    private val notifier = LocalNotifier(app)
    private val nearbyCooldown = HashMap<String, Long>()
    private val favoriteCooldown = HashMap<String, Long>()
    private val handler = Handler(Looper.getMainLooper())

    private var ble: BleMeshService? = null
    private var tcp: HotspotTcpService? = null

    private val retryTick = object : Runnable {
        override fun run() {
            tickRetries()
            handler.postDelayed(this, CQ.ACK_RETRY_MS)
        }
    }

    private val staleTick = object : Runnable {
        override fun run() {
            refreshStalePeers()
            handler.postDelayed(this, 15_000)
        }
    }

    /** Wipe identity_seed, sessions, messages; mint a new identity; refresh UI. */
    fun emergencyWipe() {
        val wasNearby = nearbyMode
        if (wasNearby) setNearbyEnabled(false)
        publicMessages.clear()
        privateMessages.clear()
        peers.clear()
        pendingMedia.clear()
        pending.clear()
        dedup.clear()
        nearbyCooldown.clear()
        favoriteCooldown.clear()
        sessions.clear()
        identity.wipeAndRegenerate()
        sessions = SessionManager(identity.x25519Private)
        identityRevision++
        if (wasNearby) setNearbyEnabled(true)
    }

    fun setFavorite(on: Boolean, fp: ByteArray) {
        identity.setFavorite(on, fp)
        val i = peers.indexOfFirst { it.fingerprint?.contentEquals(fp) == true }
        if (i >= 0) peers[i] = peers[i].copy(favorite = on)
    }

    fun setNearbyEnabled(on: Boolean) {
        if (on == nearbyMode) return
        nearbyMode = on
        if (on) {
            MeshForegroundService.start(getApplication())
            startMesh()
            transportHint = "附近模式 · BLE"
            handler.post(retryTick)
            handler.post(staleTick)
        } else {
            handler.removeCallbacks(retryTick)
            handler.removeCallbacks(staleTick)
            stopMesh()
            MeshForegroundService.stop(getApplication())
            transportHint = "附近模式已关闭"
        }
    }

    private fun startMesh() {
        if (ble != null) return
        ble = BleMeshService(getApplication(), this).also { it.start() }
        tcp = HotspotTcpService(getApplication(), this).also { it.start() }
    }

    private fun stopMesh() {
        ble?.stop(); ble = null
        tcp?.stop(); tcp = null
    }

    override fun onCleared() {
        handler.removeCallbacks(retryTick)
        handler.removeCallbacks(staleTick)
        stopMesh()
        MeshForegroundService.stop(getApplication())
    }

    fun markVerified(qr: String) {
        val fp = identity.parseQR(qr) ?: return
        identity.markVerified(fp)
        peers.indexOfFirst { it.fingerprint?.contentEquals(fp) == true }.takeIf { it >= 0 }?.let {
            peers[it] = peers[it].copy(verified = true)
        }
    }

    fun sendPublic(text: String) {
        val b = ble ?: return
        val msgId = CQPacket.random16()
        val signMsg = BroadcastPayload.signMessage(msgId, identity.nickname, text)
        val sig = identity.sign(signMsg)
        val payload = BroadcastPayload.encode(identity.nickname, text, identity.ed25519Public, sig)
        val pkt = CQPacket.make(CQ.Type.BROADCAST, b.tempId, msgId, payload = payload)
        routeOut(pkt.encode(), preferTcp = false)
        publicMessages.add(
            ChatMessage(
                msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = identity.fingerprint,
                fromNickname = identity.nickname, isPublic = true, status = ChatMessage.Status.SENT,
                pathHint = transportHint,
            )
        )
    }

    fun startPrivate(peer: Peer) {
        val b = ble ?: return
        val noise = sessions.begin(NoiseXX.Role.INITIATOR, peer.tempId)
        val body = noise.initiatorWrite1()
        val payload = HandshakePayload.encode(1, body)
        routeOut(CQPacket.make(CQ.Type.HANDSHAKE, b.tempId, payload = payload).encode(), false)
    }

    fun sendPrivateText(text: String, fp: ByteArray) {
        val session = sessions.session(fp) ?: return
        if (session.failed) return
        val plain = PrivatePlaintext.encode(CQ.Content.TEXT, text.toByteArray(Charsets.UTF_8))
        val cipher = try {
            session.noise.encrypt(plain)
        } catch (_: Exception) {
            sessions.markFailed(fp); return
        }
        val msgId = CQPacket.random16()
        val b = ble ?: return
        val pkt = CQPacket.make(
            CQ.Type.PRIVATE, b.tempId, msgId,
            flags = CQ.Flag.NEEDS_ACK, payload = cipher,
        )
        val wire = pkt.encode()
        routeOut(wire, preferTcp = false)
        pending.put(
            PendingOutbound.Entry(msgId, wire, fp, 1, System.currentTimeMillis(), PendingOutbound.Entry.Kind.TEXT)
        )
        appendPrivate(
            fp,
            ChatMessage(
                msgId, ChatMessage.Kind.TEXT, text = text, fromFingerprint = identity.fingerprint,
                fromNickname = identity.nickname, isPublic = false, status = ChatMessage.Status.SENT,
                destKey = fp, pathHint = pathFor(fp),
            )
        )
    }

    fun sendPrivateImage(bytes: ByteArray, fp: ByteArray) {
        val compressed = ImageCompressor.compress(bytes) ?: return
        val (full, thumb) = compressed
        val body = MediaContainer.encode(thumb, full)
        sendPrivateMedia(body, fp, ChatMessage.Kind.IMAGE, full, thumb)
    }

    private fun sendPrivateMedia(
        body: ByteArray, fp: ByteArray, kind: ChatMessage.Kind,
        full: ByteArray? = null, thumb: ByteArray? = null, voice: ByteArray? = null,
    ) {
        val session = sessions.session(fp) ?: return
        val size = body.size
        val hasTcp = tcp?.hasPeers == true
        if (size > CQ.MEDIA_BLE_MAX && !hasTcp) {
            val msg = ChatMessage(
                CQPacket.random16(), kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                isPublic = false, status = ChatMessage.Status.QUEUED, destKey = fp,
                pathHint = "等待热点",
            )
            pendingMedia.add(msg)
            appendPrivate(fp, msg)
            return
        }
        if (!identity.isVerified(fp) && size > CQ.MEDIA_BLE_MAX) {
            // Unverified: refuse auto large media
            appendPrivate(
                fp,
                ChatMessage(
                    CQPacket.random16(), ChatMessage.Kind.SYSTEM, text = "未验证设备不自动接收大文件",
                    fromNickname = "系统", isPublic = false, status = ChatMessage.Status.FAILED, destKey = fp,
                )
            )
            return
        }
        val plain = PrivatePlaintext.encode(
            if (kind == ChatMessage.Kind.IMAGE) CQ.Content.IMAGE else CQ.Content.VOICE, body,
        )
        val cipher = try {
            session.noise.encrypt(plain)
        } catch (_: Exception) {
            sessions.markFailed(fp); return
        }
        val msgId = CQPacket.random16()
        val b = ble ?: return
        val pkt = CQPacket.make(
            CQ.Type.PRIVATE, b.tempId, msgId, flags = CQ.Flag.NEEDS_ACK, payload = cipher,
        )
        val wire = pkt.encode()
        val preferTcp = size > 1024 || size > CQ.MEDIA_BLE_MAX
        if (preferTcp) {
            if (tcp?.send(wire) != true) {
                if (size <= CQ.MEDIA_BLE_MAX) ble?.send(wire) else {
                    val msg = ChatMessage(
                        msgId, kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                        fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                        isPublic = false, status = ChatMessage.Status.QUEUED, destKey = fp,
                        pathHint = "等待热点",
                    )
                    pendingMedia.add(msg)
                    appendPrivate(fp, msg)
                    return
                }
            }
        } else {
            routeOut(wire, false)
        }
        pending.put(
            PendingOutbound.Entry(msgId, wire, fp, 1, System.currentTimeMillis(), PendingOutbound.Entry.Kind.MEDIA)
        )
        appendPrivate(
            fp,
            ChatMessage(
                msgId, kind, imageJpeg = full, thumbJpeg = thumb, voiceCqop = voice,
                fromFingerprint = identity.fingerprint, fromNickname = identity.nickname,
                isPublic = false, status = ChatMessage.Status.SENT, destKey = fp, pathHint = pathFor(fp),
            )
        )
    }

    fun flushPendingMedia(dest: ByteArray? = null) {
        if (tcp?.hasPeers != true) return
        val waiting = pendingMedia.filter {
            it.status == ChatMessage.Status.QUEUED && (dest == null || it.destKey?.contentEquals(dest) == true)
        }
        pendingMedia.removeAll(waiting.toSet())
        for (msg in waiting) {
            val fp = msg.destKey ?: continue
            when (msg.kind) {
                ChatMessage.Kind.IMAGE -> {
                    val full = msg.imageJpeg ?: continue
                    val thumb = msg.thumbJpeg ?: ByteArray(0)
                    sendPrivateMedia(MediaContainer.encode(thumb, full), fp, ChatMessage.Kind.IMAGE, full, thumb)
                }
                ChatMessage.Kind.VOICE -> {
                    val v = msg.voiceCqop ?: continue
                    sendPrivateMedia(MediaContainer.encode(ByteArray(0), v), fp, ChatMessage.Kind.VOICE, voice = v)
                }
                else -> {}
            }
        }
    }

    private fun tickRetries() {
        for (e in pending.expired()) {
            pending.remove(e.msgId)
            markStatus(e.msgId, ChatMessage.Status.FAILED)
        }
        for (e in pending.dueForRetry()) {
            if (e.tries >= CQ.MAX_RETRIES) continue
            e.tries += 1
            // Prefer TCP for media retries when available
            if (e.kind == PendingOutbound.Entry.Kind.MEDIA && tcp?.hasPeers == true) {
                tcp?.send(e.wire)
            } else {
                ble?.send(e.wire)
            }
        }
    }

    private fun routeOut(packet: ByteArray, preferTcp: Boolean) {
        if (preferTcp && tcp?.send(packet) == true) {
            transportHint = "附近模式 · Wi‑Fi"
            return
        }
        ble?.send(packet)
        transportHint = if (tcp?.hasPeers == true) "附近模式 · BLE/Wi‑Fi" else "附近模式 · BLE"
    }

    private fun pathFor(fp: ByteArray): String {
        val peer = peers.firstOrNull {
            it.fingerprint?.contentEquals(fp) == true || it.tempId.contentEquals(fp)
        }
        return peer?.linkPath?.label
            ?: if (tcp?.hasPeers == true) "Wi‑Fi 局域网" else PeerLinkPath.BLE_DIRECT.label
    }

    private fun noteRx(tempId: ByteArray, ttl: Int) {
        val i = peers.indexOfFirst { it.tempId.contentEquals(tempId) }
        if (i < 0) return
        val p = peers[i]
        val bleDirect = if (ttl >= CQ.TTL_DEFAULT) true else p.bleDirect
        val link = when {
            ttl >= CQ.TTL_DEFAULT || bleDirect -> PeerLinkPath.BLE_DIRECT
            else -> PeerLinkPath.MESH_RELAY
        }
        peers[i] = p.copy(
            lastRxTtl = ttl,
            lastSeen = System.currentTimeMillis(),
            bleDirect = bleDirect,
            linkPath = link,
            pathHint = link.label,
        )
        refreshCryptoStatus(i)
    }

    private fun refreshCryptoStatus(i: Int) {
        if (i !in peers.indices) return
        val p = peers[i]
        val key = p.fingerprint ?: sessions.keyForTemp(p.tempId)
        val s = key?.let { sessions.session(it) }
        peers[i] = p.copy(
            encrypted = s != null && !s.failed,
            cryptoFailed = s?.failed == true,
        )
    }

    private fun refreshStalePeers() {
        val now = System.currentTimeMillis()
        for (i in peers.indices) {
            val p = peers[i]
            if (now - p.lastSeen > CQ.PEER_UNREACHABLE_MS) {
                peers[i] = p.copy(
                    bleDirect = false,
                    linkPath = PeerLinkPath.UNREACHABLE,
                    pathHint = PeerLinkPath.UNREACHABLE.label,
                )
            }
            refreshCryptoStatus(i)
        }
    }

    private fun appendPrivate(fp: ByteArray, msg: ChatMessage) {
        val key = fp.toHex()
        val list = privateMessages[key] ?: mutableStateListOf<ChatMessage>().also { privateMessages[key] = it }
        list.add(msg)
    }

    private fun migratePrivateMap(from: ByteArray, to: ByteArray) {
        val old = privateMessages.remove(from.toHex()) ?: return
        val dest = privateMessages[to.toHex()] ?: mutableStateListOf<ChatMessage>().also {
            privateMessages[to.toHex()] = it
        }
        dest.addAll(old)
    }

    private fun markStatus(msgId: ByteArray, status: ChatMessage.Status) {
        for ((_, list) in privateMessages) {
            val i = list.indexOfFirst { it.id.contentEquals(msgId) }
            if (i >= 0) list[i].status = status
        }
        val pi = pendingMedia.indexOfFirst { it.id.contentEquals(msgId) }
        if (pi >= 0) pendingMedia[pi].status = status
    }

    private fun encodeHello(): ByteArray {
        val nick = identity.nickname.toByteArray(Charsets.UTF_8)
        val pk = identity.ed25519Public
        val sig = signHello(pk, nick)
        val body = byteArrayOf(nick.size.toByte()) + nick + pk + sig
        return PrivatePlaintext.encode(CQ.Content.HELLO, body)
    }

    private fun signHello(pk: ByteArray, nick: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(identity.ed25519Private, 0))
        val msg = pk + nick
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    private fun parseHello(body: ByteArray): Triple<String, ByteArray, Boolean>? {
        if (body.isEmpty()) return null
        val n = body[0].toInt() and 0xff
        if (body.size < 1 + n + 32 + 64) return null
        val nick = body.copyOfRange(1, 1 + n).toString(Charsets.UTF_8)
        val pk = body.copyOfRange(1 + n, 1 + n + 32)
        val sig = body.copyOfRange(1 + n + 32, 1 + n + 32 + 64)
        val ok = try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(pk, 0))
            val msg = pk + nick.toByteArray(Charsets.UTF_8)
            verifier.update(msg, 0, msg.size)
            verifier.verifySignature(sig)
        } catch (_: Exception) {
            false
        }
        return Triple(nick, pk, ok)
    }

    override fun onPacket(data: ByteArray) = handlePacket(data)

    override fun onDiscover(tempId: ByteArray) {
        sessions.keyForTemp(tempId)?.let { sessions.bindTempId(tempId, it) }
        upsertPeer(tempId, null, "附近", bleDirect = true)
    }

    override fun onPeersChanged(count: Int) {
        if (count > 0) flushPendingMedia()
    }

    private fun handlePacket(data: ByteArray) {
        val pkt = CQPacket.decode(data) ?: return
        if (pkt.version != CQ.VERSION) return
        if (pkt.type != CQ.Type.ACK && dedup.seen(pkt.msgId)) return
        noteRx(pkt.sender, pkt.ttl)
        when (pkt.type) {
            CQ.Type.BROADCAST -> handleBroadcast(pkt)
            CQ.Type.HANDSHAKE -> handleHandshake(pkt)
            CQ.Type.PRIVATE -> handlePrivate(pkt)
            CQ.Type.ACK -> {
                AckPayload.decode(pkt.payload)?.let {
                    pending.remove(it)
                    markStatus(it, ChatMessage.Status.DELIVERED)
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
        val b = ble ?: return
        when (step) {
            1 -> {
                val noise = sessions.begin(NoiseXX.Role.RESPONDER, temp)
                noise.responderRead1(body)
                val out = noise.responderWrite2()
                routeOut(CQPacket.make(CQ.Type.HANDSHAKE, b.tempId, payload = HandshakePayload.encode(2, out)).encode(), false)
            }
            2 -> {
                val noise = sessions.handshake(temp) ?: return
                noise.initiatorRead2(body)
                val out = noise.initiatorWrite3(encodeHello())
                routeOut(CQPacket.make(CQ.Type.HANDSHAKE, b.tempId, payload = HandshakePayload.encode(3, out)).encode(), false)
                sessions.complete(temp)
                noise.remoteSessionId?.let { upsertPeer(temp, it, "peer") }
            }
            3 -> {
                val noise = sessions.handshake(temp) ?: return
                val payload = noise.responderRead3(body)
                sessions.complete(temp)
                val sid = noise.remoteSessionId ?: return
                var idFp = sid
                var nick = "peer"
                PrivatePlaintext.decode(payload)?.let { (ct, helloBody) ->
                    if (ct == CQ.Content.HELLO) {
                        parseHello(helloBody)?.let { (n, edPk, ok) ->
                            if (!ok) {
                                Log.w("CQchat", "hello sig invalid")
                                return
                            }
                            nick = n
                            idFp = IdentityCrypto.fingerprint(edPk)
                            if (!idFp.contentEquals(sid)) {
                                sessions.rebind(sid, idFp)
                                migratePrivateMap(sid, idFp)
                            }
                        }
                    }
                }
                sessions.updateNickname(idFp, nick)
                sessions.session(idFp)?.noise?.encrypt(encodeHello())?.let { cipher ->
                    routeOut(CQPacket.make(CQ.Type.PRIVATE, b.tempId, payload = cipher).encode(), false)
                }
                upsertPeer(temp, idFp, nick)
            }
        }
    }

    private fun handlePrivate(pkt: CQPacket) {
        val key = sessions.keyForTemp(pkt.sender)
        if (key == null) {
            Log.w("CQchat", "private: unknown temp, drop (no trial decrypt)")
            return
        }
        val s = sessions.session(key) ?: return
        if (s.failed) return
        val plain = try {
            s.noise.decrypt(pkt.payload)
        } catch (e: Exception) {
            sessions.markFailed(key)
            Log.w("CQchat", "noise decrypt failed → session reset needed")
            peers.indexOfFirst { it.tempId.contentEquals(pkt.sender) }.takeIf { it >= 0 }?.let {
                refreshCryptoStatus(it)
            }
            return
        }
        val (ct, body) = PrivatePlaintext.decode(plain) ?: return
        val fp = s.identityFingerprint ?: key
        if (pkt.flags and CQ.Flag.NEEDS_ACK != 0) {
            val b = ble ?: return
            routeOut(
                CQPacket.make(CQ.Type.ACK, b.tempId, payload = AckPayload.encode(pkt.msgId)).encode(),
                false,
            )
        }
        when (ct) {
            CQ.Content.TEXT -> {
                appendPrivate(
                    fp,
                    ChatMessage(
                        pkt.msgId, ChatMessage.Kind.TEXT, text = body.toString(Charsets.UTF_8),
                        fromFingerprint = fp, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED, pathHint = pathFor(fp),
                    )
                )
                notifier.message("私聊", body.toString(Charsets.UTF_8))
            }
            CQ.Content.IMAGE -> {
                val (thumb, data) = MediaContainer.decode(body) ?: return
                appendPrivate(
                    fp,
                    ChatMessage(
                        pkt.msgId, ChatMessage.Kind.IMAGE, imageJpeg = data, thumbJpeg = thumb,
                        fromFingerprint = fp, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    )
                )
            }
            CQ.Content.VOICE -> {
                val (_, data) = MediaContainer.decode(body) ?: return
                appendPrivate(
                    fp,
                    ChatMessage(
                        pkt.msgId, ChatMessage.Kind.VOICE, voiceCqop = data,
                        fromFingerprint = fp, fromNickname = s.nickname, isPublic = false,
                        status = ChatMessage.Status.RECEIVED,
                    )
                )
            }
            CQ.Content.HELLO -> {
                parseHello(body)?.let { (nick, edPk, ok) ->
                    if (!ok) return
                    val idFp = IdentityCrypto.fingerprint(edPk)
                    if (!idFp.contentEquals(fp)) {
                        sessions.rebind(fp, idFp)
                        migratePrivateMap(fp, idFp)
                    }
                    sessions.updateNickname(idFp, nick)
                    sessions.bindTempId(pkt.sender, idFp)
                    upsertPeer(pkt.sender, idFp, nick)
                }
            }
        }
    }

    private fun upsertPeer(
        tempId: ByteArray,
        fingerprint: ByteArray?,
        nickname: String,
        bleDirect: Boolean = false,
    ) {
        val idx = peers.indexOfFirst {
            it.tempId.contentEquals(tempId) ||
                (fingerprint != null && it.fingerprint?.contentEquals(fingerprint) == true)
        }
        if (idx >= 0) {
            val p = peers[idx]
            val wasSeen = p.lastSeen
            val fp = fingerprint ?: p.fingerprint
            val link = when {
                bleDirect || p.bleDirect -> PeerLinkPath.BLE_DIRECT
                p.linkPath == PeerLinkPath.UNREACHABLE -> PeerLinkPath.MESH_RELAY
                else -> p.linkPath
            }
            peers[idx] = p.copy(
                tempId = tempId,
                fingerprint = fp,
                nickname = nickname,
                lastSeen = System.currentTimeMillis(),
                verified = fp?.let { identity.isVerified(it) } ?: false,
                favorite = fp?.let { identity.isFavorite(it) } ?: false,
                bleDirect = bleDirect || p.bleDirect,
                linkPath = link,
                pathHint = link.label,
            )
            refreshCryptoStatus(idx)
            maybeNotifyFavorite(fp, nickname, wasSeen)
        } else {
            val link = if (bleDirect) PeerLinkPath.BLE_DIRECT else PeerLinkPath.UNREACHABLE
            peers.add(
                Peer(
                    tempId, fingerprint, nickname,
                    verified = fingerprint?.let { identity.isVerified(it) } ?: false,
                    favorite = fingerprint?.let { identity.isFavorite(it) } ?: false,
                    pathHint = link.label,
                    linkPath = link,
                    bleDirect = bleDirect,
                )
            )
            fingerprint?.let { fp ->
                val last = nearbyCooldown[fp.toHex()] ?: 0L
                if (System.currentTimeMillis() - last >= CQ.NEARBY_NOTIFY_COOLDOWN_MS) {
                    nearbyCooldown[fp.toHex()] = System.currentTimeMillis()
                    notifier.nearby(nickname)
                }
                maybeNotifyFavorite(fp, nickname, 0L)
            }
            refreshCryptoStatus(peers.lastIndex)
        }
        fingerprint?.let { sessions.bindTempId(tempId, it) }
    }

    private fun maybeNotifyFavorite(fp: ByteArray?, nickname: String, previouslySeen: Long) {
        if (fp == null || !identity.isFavorite(fp)) return
        val now = System.currentTimeMillis()
        val stale = previouslySeen == 0L || now - previouslySeen > CQ.PEER_UNREACHABLE_MS
        if (!stale) return
        val last = favoriteCooldown[fp.toHex()] ?: 0L
        if (now - last < CQ.FAVORITE_NOTIFY_COOLDOWN_MS) return
        favoriteCooldown[fp.toHex()] = now
        notifier.favoriteNearby(nickname)
    }
}
