import Foundation
import CryptoKit
import UIKit
import Combine

struct ChatMessage: Identifiable, Equatable {
    enum Kind { case text, image, voice, system }
    enum Status { case queued, sent, delivered, failed, received }
    let id: Data
    let kind: Kind
    let text: String?
    let imageJPEG: Data?
    let thumbJPEG: Data?
    let voiceCQOP: Data?
    let fromFingerprint: Data?
    let fromNickname: String
    let isPublic: Bool
    var status: Status
    var destKey: Data?
    var pathHint: String
    let ts: Date
}

enum PeerLinkPath: String, Equatable {
    case bleDirect = "蓝牙直连"
    case meshRelay = "Mesh 中继"
    case unreachable = "不可达"
}

struct Peer: Identifiable, Equatable {
    var id: Data { fingerprint ?? tempId }
    var tempId: Data
    var fingerprint: Data?
    var nickname: String
    var verified: Bool
    var lastSeen: Date
    var pathHint: String
    var linkPath: PeerLinkPath = .unreachable
    var bleDirect: Bool = false
    var lastRxTtl: UInt8? = nil
    var encrypted: Bool = false
    var cryptoFailed: Bool = false
    var favorite: Bool = false
}

@MainActor
final class ChatEngine: ObservableObject {
    @Published var publicMessages: [ChatMessage] = []
    @Published var privateMessages: [Data: [ChatMessage]] = [:]
    @Published var peers: [Peer] = []
    @Published var pendingMedia: [ChatMessage] = []
    @Published var myFingerprintHex: String = ""
    @Published var nickname: String = IdentityKeys.nickname
    @Published var nearbyMode = false
    @Published var transportHint = "未开启附近模式"
    @Published var identityEpoch: Int = 0

    let ble = BleMeshService()
    let tcp = HotspotTcpService()
    private var sessions: SessionManager
    private var x25519: Curve25519.KeyAgreement.PrivateKey
    private var ed25519: Curve25519.Signing.PrivateKey
    private var myFingerprint: Data
    private let dedup = DedupCache()
    private let notifier = LocalNotifier()
    private var nearbyCooldown: [Data: Date] = [:]
    private var favoriteCooldown: [Data: Date] = [:]
    private var awaitingAck: [Data: (wire: Data, dest: Data, tries: Int, created: Date, isMedia: Bool)] = [:]
    private var retryTimer: Timer?
    private var staleTimer: Timer?

    init() throws {
        let keys = try IdentityKeys.loadOrCreate()
        self.x25519 = keys.x25519
        self.ed25519 = keys.ed25519
        self.myFingerprint = IdentityKeys.fingerprint(
            ed25519Public: keys.ed25519.publicKey.rawRepresentation
        )
        self.myFingerprintHex = myFingerprint.hex
        self.sessions = SessionManager(staticKey: keys.x25519)
        ble.delegate = self
        tcp.delegate = self
    }

    var qrPayload: String { IdentityKeys.qrString(fingerprint: myFingerprint) }

    /// Wipe identity_seed, sessions, messages; mint a new identity; refresh UI.
    func emergencyWipe() {
        let wasNearby = nearbyMode
        if wasNearby { setNearbyMode(false) }
        publicMessages = []
        privateMessages = [:]
        peers = []
        pendingMedia = []
        awaitingAck = [:]
        nearbyCooldown = [:]
        favoriteCooldown = [:]
        dedup.clear()
        sessions.clear()
        do {
            let keys = try IdentityKeys.wipeAndRegenerate()
            x25519 = keys.x25519
            ed25519 = keys.ed25519
            myFingerprint = IdentityKeys.fingerprint(
                ed25519Public: keys.ed25519.publicKey.rawRepresentation
            )
            myFingerprintHex = myFingerprint.hex
            nickname = IdentityKeys.nickname
            sessions = SessionManager(staticKey: keys.x25519)
            identityEpoch += 1
        } catch {
            // Keychain failure: still leave local state wiped.
        }
        if wasNearby { setNearbyMode(true) }
    }

    func setFavorite(_ on: Bool, fingerprint fp: Data) {
        IdentityKeys.setFavorite(on, fingerprint: fp)
        if let i = peers.firstIndex(where: { $0.fingerprint == fp }) {
            peers[i].favorite = on
        }
    }

    func setNearbyMode(_ on: Bool) {
        guard on != nearbyMode else { return }
        nearbyMode = on
        if on {
            ble.start()
            tcp.start()
            transportHint = "附近模式 · BLE"
            retryTimer = Timer.scheduledTimer(withTimeInterval: CQ.ackRetrySecs, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.tickRetries() }
            }
            staleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.refreshStalePeers() }
            }
            notifier.requestPermission()
        } else {
            retryTimer?.invalidate()
            retryTimer = nil
            staleTimer?.invalidate()
            staleTimer = nil
            ble.stop()
            tcp.stop()
            transportHint = "附近模式已关闭"
        }
    }

    func markVerified(fromQR string: String) {
        guard let fp = IdentityKeys.parseQR(string) else { return }
        IdentityKeys.markVerified(fingerprint: fp)
        if let i = peers.firstIndex(where: { $0.fingerprint == fp }) {
            peers[i].verified = true
        }
    }

    func setNickname(_ name: String) {
        nickname = name
        IdentityKeys.nickname = name
    }

    func sendPublic(_ text: String) {
        guard nearbyMode else { return }
        let msgId = Data.random16()
        let signMsg = BroadcastPayload.signMessage(msgId: msgId, nickname: nickname, text: text)
        let sig = try! ed25519.signature(for: signMsg)
        let payload = BroadcastPayload.encode(
            nickname: nickname, text: text,
            ed25519Pk: ed25519.publicKey.rawRepresentation, sig: sig
        )
        let pkt = CQPacket.make(type: .broadcast, sender: ble.currentTempId, msgId: msgId, payload: payload)
        routeOut(pkt.encode(), preferTCP: false)
        publicMessages.append(ChatMessage(
            id: msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil, voiceCQOP: nil,
            fromFingerprint: myFingerprint, fromNickname: nickname, isPublic: true,
            status: .sent, destKey: nil, pathHint: transportHint, ts: Date()
        ))
    }

    func startPrivate(with peer: Peer) {
        guard nearbyMode else { return }
        let noise = sessions.beginHandshake(as: .initiator, tempId: peer.tempId)
        guard let body = try? noise.initiatorWrite1() else { return }
        let payload = HandshakePayload.encode(step: 1, body: body)
        let pkt = CQPacket.make(type: .handshake, sender: ble.currentTempId, payload: payload)
        routeOut(pkt.encode(), preferTCP: false)
    }

    func sendPrivateText(_ text: String, toFingerprint fp: Data) {
        guard let plain = Optional(PrivatePlaintext.encode(contentType: .text, body: Data(text.utf8))),
              let cipher = try? sessions.encrypt(to: fp, plaintext: plain) else { return }
        let msgId = Data.random16()
        let pkt = CQPacket.make(
            type: .privateMsg, sender: ble.currentTempId, msgId: msgId,
            flags: CQ.Flag.needsAck, payload: cipher
        )
        let wire = pkt.encode()
        routeOut(wire, preferTCP: false)
        awaitingAck[msgId] = (wire, fp, 1, Date(), false)
        appendPrivate(ChatMessage(
            id: msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil, voiceCQOP: nil,
            fromFingerprint: myFingerprint, fromNickname: nickname, isPublic: false,
            status: .sent, destKey: fp, pathHint: pathFor(fp), ts: Date()
        ), fp: fp)
    }

    func sendPrivateImage(_ image: UIImage, toFingerprint fp: Data) {
        guard let compressed = ImageCompressor.compress(image) else { return }
        let body = MediaContainer.encode(thumb: compressed.thumb, data: compressed.full)
        sendPrivateMedia(
            plainBody: body, size: body.count, fp: fp, kind: .image,
            thumb: compressed.thumb, full: compressed.full
        )
    }

    func sendPrivateVoice(cqop: Data, toFingerprint fp: Data) {
        let body = MediaContainer.encode(thumb: Data(), data: cqop)
        sendPrivateMedia(plainBody: body, size: body.count, fp: fp, kind: .voice, voice: cqop)
    }

    private func sendPrivateMedia(
        plainBody: Data, size: Int, fp: Data, kind: ChatMessage.Kind,
        thumb: Data? = nil, full: Data? = nil, voice: Data? = nil
    ) {
        let hasTCP = tcp.isLikelyOnLocalNetwork
        if size > CQ.mediaBleMax && !hasTCP {
            let msg = ChatMessage(
                id: Data.random16(), kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
                voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
                isPublic: false, status: .queued, destKey: fp, pathHint: "等待热点", ts: Date()
            )
            pendingMedia.append(msg)
            appendPrivate(msg, fp: fp)
            return
        }
        if !IdentityKeys.isVerified(fingerprint: fp) && size > CQ.mediaBleMax {
            appendPrivate(ChatMessage(
                id: Data.random16(), kind: .system, text: "未验证设备不自动发送大文件",
                imageJPEG: nil, thumbJPEG: nil, voiceCQOP: nil, fromFingerprint: nil,
                fromNickname: "系统", isPublic: false, status: .failed, destKey: fp,
                pathHint: "", ts: Date()
            ), fp: fp)
            return
        }
        let ct: CQ.ContentType = kind == .image ? .image : .voice
        let plain = PrivatePlaintext.encode(contentType: ct, body: plainBody)
        guard let cipher = try? sessions.encrypt(to: fp, plaintext: plain) else { return }
        let msgId = Data.random16()
        let pkt = CQPacket.make(
            type: .privateMsg, sender: ble.currentTempId, msgId: msgId,
            flags: CQ.Flag.needsAck, payload: cipher
        )
        let wire = pkt.encode()
        let preferTCP = size > 1024 || size > CQ.mediaBleMax
        if preferTCP {
            if !tcp.sendPreferTCP(wire) {
                if size <= CQ.mediaBleMax {
                    ble.send(wire)
                } else {
                    let msg = ChatMessage(
                        id: msgId, kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
                        voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
                        isPublic: false, status: .queued, destKey: fp, pathHint: "等待热点", ts: Date()
                    )
                    pendingMedia.append(msg)
                    appendPrivate(msg, fp: fp)
                    return
                }
            }
        } else {
            routeOut(wire, preferTCP: false)
        }
        awaitingAck[msgId] = (wire, fp, 1, Date(), true)
        appendPrivate(ChatMessage(
            id: msgId, kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb, voiceCQOP: voice,
            fromFingerprint: myFingerprint, fromNickname: nickname, isPublic: false,
            status: .sent, destKey: fp, pathHint: pathFor(fp), ts: Date()
        ), fp: fp)
    }

    func flushPendingMedia(toFingerprint fp: Data? = nil) {
        guard tcp.isLikelyOnLocalNetwork else { return }
        let waiting = pendingMedia.filter {
            $0.status == .queued && (fp == nil || $0.destKey == fp)
        }
        pendingMedia.removeAll { msg in waiting.contains(where: { $0.id == msg.id }) }
        for msg in waiting {
            guard let dest = msg.destKey else { continue }
            if msg.kind == .image, let full = msg.imageJPEG {
                let thumb = msg.thumbJPEG ?? Data()
                let body = MediaContainer.encode(thumb: thumb, data: full)
                sendPrivateMedia(plainBody: body, size: body.count, fp: dest, kind: .image, thumb: thumb, full: full)
            } else if msg.kind == .voice, let v = msg.voiceCQOP {
                let body = MediaContainer.encode(thumb: Data(), data: v)
                sendPrivateMedia(plainBody: body, size: body.count, fp: dest, kind: .voice, voice: v)
            }
        }
    }

    private func tickRetries() {
        let now = Date()
        for (id, entry) in awaitingAck {
            if now.timeIntervalSince(entry.created) > CQ.msgExpirySecs || entry.tries >= CQ.maxRetries {
                awaitingAck.removeValue(forKey: id)
                markStatus(id, .failed)
                continue
            }
            var e = entry
            e.tries += 1
            awaitingAck[id] = e
            if e.isMedia && tcp.isLikelyOnLocalNetwork {
                _ = tcp.sendPreferTCP(e.wire)
            } else {
                ble.send(e.wire)
            }
        }
    }

    private func routeOut(_ packet: Data, preferTCP: Bool) {
        if preferTCP, tcp.sendPreferTCP(packet) {
            transportHint = "附近模式 · Wi‑Fi"
            return
        }
        ble.send(packet)
        transportHint = tcp.isLikelyOnLocalNetwork ? "附近模式 · BLE/Wi‑Fi" : "附近模式 · BLE"
    }

    private func pathFor(_ fp: Data) -> String {
        if let peer = peers.first(where: { $0.fingerprint == fp || $0.tempId == fp }) {
            return peer.linkPath.rawValue
        }
        return tcp.isLikelyOnLocalNetwork ? "Wi‑Fi 局域网" : PeerLinkPath.bleDirect.rawValue
    }

    private func noteRx(tempId: Data, ttl: UInt8) {
        guard let i = peers.firstIndex(where: { $0.tempId == tempId }) else { return }
        peers[i].lastRxTtl = ttl
        peers[i].lastSeen = Date()
        if ttl >= CQ.ttlDefault {
            peers[i].bleDirect = true
            peers[i].linkPath = .bleDirect
        } else if !peers[i].bleDirect {
            peers[i].linkPath = .meshRelay
        }
        peers[i].pathHint = peers[i].linkPath.rawValue
        refreshCryptoStatus(at: i)
    }

    private func refreshCryptoStatus(at i: Int) {
        let p = peers[i]
        let key = p.fingerprint ?? sessions.key(forTemp: p.tempId)
        if let key, let s = sessions.session(for: key) {
            peers[i].cryptoFailed = s.failed
            peers[i].encrypted = !s.failed
        } else {
            peers[i].encrypted = false
            peers[i].cryptoFailed = false
        }
    }

    private func refreshStalePeers() {
        let now = Date()
        for i in peers.indices {
            if now.timeIntervalSince(peers[i].lastSeen) > CQ.peerUnreachableSecs {
                peers[i].bleDirect = false
                peers[i].linkPath = .unreachable
                peers[i].pathHint = PeerLinkPath.unreachable.rawValue
            }
            refreshCryptoStatus(at: i)
        }
    }

    private func appendPrivate(_ msg: ChatMessage, fp: Data) {
        var list = privateMessages[fp] ?? []
        list.append(msg)
        privateMessages[fp] = list
    }

    private func migratePrivateMap(from: Data, to: Data) {
        guard let old = privateMessages.removeValue(forKey: from) else { return }
        var dest = privateMessages[to] ?? []
        dest.append(contentsOf: old)
        privateMessages[to] = dest
    }

    private func markStatus(_ msgId: Data, _ status: ChatMessage.Status) {
        for (fp, list) in privateMessages {
            if let i = list.firstIndex(where: { $0.id == msgId }) {
                var copy = list
                copy[i].status = status
                privateMessages[fp] = copy
            }
        }
    }

    private func encodeHello() -> Data {
        let nick = Data(nickname.utf8)
        let pk = ed25519.publicKey.rawRepresentation
        let sig = try! ed25519.signature(for: pk + nick)
        var body = Data([UInt8(nick.count)])
        body.append(nick)
        body.append(pk)
        body.append(sig)
        return PrivatePlaintext.encode(contentType: .hello, body: body)
    }

    private func parseHello(_ body: Data) -> (nick: String, pk: Data, ok: Bool)? {
        guard let nlen = body.first else { return nil }
        let n = Int(nlen)
        guard body.count >= 1 + n + 32 + 64 else { return nil }
        let nickData = body.subdata(in: 1..<(1 + n))
        let nick = String(data: nickData, encoding: .utf8) ?? "peer"
        let pk = body.subdata(in: (1 + n)..<(1 + n + 32))
        let sig = body.subdata(in: (1 + n + 32)..<(1 + n + 32 + 64))
        let ok: Bool
        do {
            let pub = try Curve25519.Signing.PublicKey(rawRepresentation: pk)
            ok = pub.isValidSignature(sig, for: pk + nickData)
        } catch {
            ok = false
        }
        return (nick, pk, ok)
    }

    private func handlePacket(_ data: Data) {
        guard let pkt = CQPacket.decode(data), pkt.version == CQ.version else { return }
        if pkt.type != CQ.PacketType.ack.rawValue, dedup.seen(pkt.msgId) { return }
        noteRx(tempId: pkt.sender, ttl: pkt.ttl)
        switch CQ.PacketType(rawValue: pkt.type) {
        case .broadcast: handleBroadcast(pkt)
        case .handshake: handleHandshake(pkt)
        case .privateMsg: handlePrivate(pkt)
        case .ack:
            if let ackId = AckPayload.decode(pkt.payload) {
                awaitingAck.removeValue(forKey: ackId)
                markStatus(ackId, .delivered)
            }
        default: break
        }
    }

    private func handleBroadcast(_ pkt: CQPacket) {
        guard let (nick, text, pk, sig) = BroadcastPayload.decode(pkt.payload) else { return }
        let msg = BroadcastPayload.signMessage(msgId: pkt.msgId, nickname: nick, text: text)
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: pk),
              pub.isValidSignature(sig, for: msg) else { return }
        publicMessages.append(ChatMessage(
            id: pkt.msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil, voiceCQOP: nil,
            fromFingerprint: nil, fromNickname: nick, isPublic: true, status: .received,
            destKey: nil, pathHint: "公频", ts: Date()
        ))
        notifier.message(title: nick, body: text)
    }

    private func handleHandshake(_ pkt: CQPacket) {
        guard let (pattern, step, body) = HandshakePayload.decode(pkt.payload), pattern == 1 else { return }
        let temp = pkt.sender
        switch step {
        case 1:
            let noise = sessions.beginHandshake(as: .responder, tempId: temp)
            _ = try? noise.responderRead1(body)
            if let out = try? noise.responderWrite2() {
                let payload = HandshakePayload.encode(step: 2, body: out)
                routeOut(CQPacket.make(type: .handshake, sender: ble.currentTempId, payload: payload).encode(), preferTCP: false)
            }
        case 2:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            _ = try? noise.initiatorRead2(body)
            if let out = try? noise.initiatorWrite3(payload: encodeHello()) {
                let payload = HandshakePayload.encode(step: 3, body: out)
                routeOut(CQPacket.make(type: .handshake, sender: ble.currentTempId, payload: payload).encode(), preferTCP: false)
                sessions.complete(tempId: temp)
                if let sid = noise.remoteSessionId {
                    upsertPeer(tempId: temp, fingerprint: sid, nickname: "peer")
                }
            }
        case 3:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            let payload = (try? noise.responderRead3(body)) ?? Data()
            sessions.complete(tempId: temp)
            guard let sid = noise.remoteSessionId else { return }
            var idFp = sid
            var nick = "peer"
            if let (ct, helloBody) = PrivatePlaintext.decode(payload), ct == .hello,
               let parsed = parseHello(helloBody), parsed.ok {
                nick = parsed.nick
                idFp = IdentityKeys.fingerprint(ed25519Public: parsed.pk)
                if idFp != sid {
                    _ = sessions.rebind(fromSessionId: sid, toIdentityFingerprint: idFp)
                    migratePrivateMap(from: sid, to: idFp)
                }
            } else if let (_, _, ok) = parseHello(PrivatePlaintext.decode(payload)?.1 ?? Data()), !ok {
                return
            }
            sessions.updateNickname(nick, key: idFp)
            if let hello = try? sessions.encrypt(to: idFp, plaintext: encodeHello()) {
                routeOut(CQPacket.make(type: .privateMsg, sender: ble.currentTempId, payload: hello).encode(), preferTCP: false)
            }
            upsertPeer(tempId: temp, fingerprint: idFp, nickname: nick)
        default: break
        }
    }

    private func handlePrivate(_ pkt: CQPacket) {
        guard let key = sessions.key(forTemp: pkt.sender) else { return }
        guard let plain = try? sessions.decrypt(from: key, ciphertext: pkt.payload),
              let (ct, body) = PrivatePlaintext.decode(plain) else {
            if let i = peers.firstIndex(where: { $0.tempId == pkt.sender }) {
                refreshCryptoStatus(at: i)
            }
            return
        }
        let fp = sessions.session(for: key)?.identityFingerprint ?? key
        if pkt.flags & CQ.Flag.needsAck != 0 {
            let ack = CQPacket.make(type: .ack, sender: ble.currentTempId, payload: AckPayload.encode(ackMsgId: pkt.msgId))
            routeOut(ack.encode(), preferTCP: false)
        }
        switch ct {
        case .text:
            let text = String(data: body, encoding: .utf8) ?? ""
            appendPrivate(ChatMessage(
                id: pkt.msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil, voiceCQOP: nil,
                fromFingerprint: fp, fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                isPublic: false, status: .received, destKey: nil, pathHint: pathFor(fp), ts: Date()
            ), fp: fp)
            notifier.message(title: "私聊", body: text)
        case .image:
            if let (thumb, data) = MediaContainer.decode(body) {
                appendPrivate(ChatMessage(
                    id: pkt.msgId, kind: .image, text: nil, imageJPEG: data, thumbJPEG: thumb,
                    voiceCQOP: nil, fromFingerprint: fp,
                    fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                    isPublic: false, status: .received, destKey: nil, pathHint: pathFor(fp), ts: Date()
                ), fp: fp)
            }
        case .voice:
            if let (_, data) = MediaContainer.decode(body) {
                appendPrivate(ChatMessage(
                    id: pkt.msgId, kind: .voice, text: nil, imageJPEG: nil, thumbJPEG: nil,
                    voiceCQOP: data, fromFingerprint: fp,
                    fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                    isPublic: false, status: .received, destKey: nil, pathHint: pathFor(fp), ts: Date()
                ), fp: fp)
            }
        case .hello:
            guard let parsed = parseHello(body), parsed.ok else { return }
            let idFp = IdentityKeys.fingerprint(ed25519Public: parsed.pk)
            if idFp != fp {
                _ = sessions.rebind(fromSessionId: fp, toIdentityFingerprint: idFp)
                migratePrivateMap(from: fp, to: idFp)
            }
            sessions.updateNickname(parsed.nick, key: idFp)
            sessions.bindTempId(pkt.sender, toKey: idFp)
            upsertPeer(tempId: pkt.sender, fingerprint: idFp, nickname: parsed.nick)
        }
    }

    private func upsertPeer(tempId: Data, fingerprint: Data?, nickname: String, bleDirect: Bool = false) {
        let fp = fingerprint
        let verified = (fp ?? peers.first(where: { $0.tempId == tempId })?.fingerprint)
            .map { IdentityKeys.isVerified(fingerprint: $0) } ?? false
        let favorite = (fp ?? peers.first(where: { $0.tempId == tempId })?.fingerprint)
            .map { IdentityKeys.isFavorite(fingerprint: $0) } ?? false
        if let i = peers.firstIndex(where: {
            $0.tempId == tempId || ($0.fingerprint != nil && $0.fingerprint == fingerprint)
        }) {
            let wasSeen = peers[i].lastSeen
            peers[i].tempId = tempId
            if let fingerprint { peers[i].fingerprint = fingerprint }
            peers[i].nickname = nickname
            peers[i].lastSeen = Date()
            peers[i].verified = verified
            peers[i].favorite = favorite
            if bleDirect {
                peers[i].bleDirect = true
                peers[i].linkPath = .bleDirect
            } else if peers[i].linkPath == .unreachable {
                peers[i].linkPath = peers[i].bleDirect ? .bleDirect : .meshRelay
            }
            peers[i].pathHint = peers[i].linkPath.rawValue
            refreshCryptoStatus(at: i)
            maybeNotifyFavorite(fp: peers[i].fingerprint, nickname: nickname, previouslySeen: wasSeen)
        } else {
            let link: PeerLinkPath = bleDirect ? .bleDirect : .unreachable
            peers.append(Peer(
                tempId: tempId, fingerprint: fingerprint, nickname: nickname,
                verified: verified, lastSeen: Date(), pathHint: link.rawValue,
                linkPath: link, bleDirect: bleDirect, favorite: favorite
            ))
            if let fingerprint {
                let last = nearbyCooldown[fingerprint] ?? .distantPast
                if Date().timeIntervalSince(last) >= CQ.nearbyNotifyCooldown {
                    nearbyCooldown[fingerprint] = Date()
                    notifier.nearby(nickname)
                }
                maybeNotifyFavorite(fp: fingerprint, nickname: nickname, previouslySeen: .distantPast)
            }
            refreshCryptoStatus(at: peers.count - 1)
        }
        if let fingerprint {
            sessions.bindTempId(tempId, toKey: fingerprint)
        }
    }

    private func maybeNotifyFavorite(fp: Data?, nickname: String, previouslySeen: Date) {
        guard let fp, IdentityKeys.isFavorite(fingerprint: fp) else { return }
        // Only when reappearing after being stale / first sighting of a favorite.
        let stale = Date().timeIntervalSince(previouslySeen) > CQ.peerUnreachableSecs
        guard stale || previouslySeen == .distantPast else { return }
        let last = favoriteCooldown[fp] ?? .distantPast
        guard Date().timeIntervalSince(last) >= CQ.favoriteNotifyCooldown else { return }
        favoriteCooldown[fp] = Date()
        notifier.favoriteNearby(nickname)
    }
}

extension ChatEngine: BleMeshDelegate {
    nonisolated func bleDidReceive(packet: Data, fromTempId: Data?) {
        Task { @MainActor in handlePacket(packet) }
    }
    nonisolated func bleDidDiscover(tempId: Data) {
        Task { @MainActor in
            if let key = sessions.key(forTemp: tempId) {
                sessions.bindTempId(tempId, toKey: key)
            }
            upsertPeer(tempId: tempId, fingerprint: nil, nickname: "附近", bleDirect: true)
        }
    }
}

extension ChatEngine: HotspotDelegate {
    nonisolated func hotspotDidReceive(packet: Data) {
        Task { @MainActor in handlePacket(packet) }
    }
    nonisolated func hotspotPeersChanged(_ hosts: [String]) {
        Task { @MainActor in flushPendingMedia() }
    }
}
