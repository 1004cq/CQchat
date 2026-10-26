import Foundation
import CryptoKit
import UIKit
import Combine

struct ChatMessage: Identifiable, Equatable {
    enum Kind { case text, image, voice, system }
    enum Status { case sent, waiting, failed, received }
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
    let ts: Date
}

struct Peer: Identifiable, Equatable {
    var id: Data { fingerprint ?? tempId }
    var tempId: Data
    var fingerprint: Data?
    var nickname: String
    var verified: Bool
    var lastSeen: Date
}

@MainActor
final class ChatEngine: ObservableObject {
    @Published var publicMessages: [ChatMessage] = []
    @Published var privateMessages: [Data: [ChatMessage]] = [:] // fingerprint -> msgs
    @Published var peers: [Peer] = []
    @Published var pendingMedia: [ChatMessage] = []
    @Published var myFingerprintHex: String = ""
    @Published var nickname: String = IdentityKeys.nickname

    let ble = BleMeshService()
    let tcp = HotspotTcpService()
    private let sessions: SessionManager
    private let x25519: Curve25519.KeyAgreement.PrivateKey
    private let ed25519: Curve25519.Signing.PrivateKey
    private let myFingerprint: Data
    private let dedup = DedupCache()
    private let notifier = LocalNotifier()
    private var nearbyCooldown: [Data: Date] = [:]
    private var awaitingAck: [Data: (packet: Data, tries: Int)] = [:]

    init() throws {
        let keys = try IdentityKeys.loadOrCreate()
        self.x25519 = keys.x25519
        self.ed25519 = keys.ed25519
        self.myFingerprint = IdentityKeys.fingerprint(
            x25519Public: keys.x25519.publicKey.rawRepresentation
        )
        self.myFingerprintHex = myFingerprint.hex
        self.sessions = SessionManager(staticKey: keys.x25519)
        ble.delegate = self
        tcp.delegate = self
    }

    func start() {
        ble.start()
        tcp.start()
        notifier.requestPermission()
    }

    var qrPayload: String { IdentityKeys.qrString(fingerprint: myFingerprint) }

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

    // MARK: Public broadcast

    func sendPublic(_ text: String) {
        let msgId = Data.random16()
        let signMsg = BroadcastPayload.signMessage(msgId: msgId, nickname: nickname, text: text)
        let sig = try! ed25519.signature(for: signMsg)
        let payload = BroadcastPayload.encode(
            nickname: nickname,
            text: text,
            ed25519Pk: ed25519.publicKey.rawRepresentation,
            sig: sig
        )
        let pkt = CQPacket.make(
            type: .broadcast,
            sender: ble.currentTempId,
            msgId: msgId,
            payload: payload
        )
        routeOut(pkt.encode(), preferTCP: false)
        publicMessages.append(ChatMessage(
            id: msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil,
            voiceCQOP: nil, fromFingerprint: myFingerprint, fromNickname: nickname,
            isPublic: true, status: .sent, ts: Date()
        ))
    }

    // MARK: Private

    func startPrivate(with peer: Peer) {
        let noise = sessions.beginHandshake(as: .initiator, tempId: peer.tempId)
        guard let body = try? noise.initiatorWrite1() else { return }
        let payload = HandshakePayload.encode(step: 1, body: body)
        let pkt = CQPacket.make(
            type: .handshake,
            sender: ble.currentTempId,
            payload: payload
        )
        routeOut(pkt.encode(), preferTCP: false)
    }

    func sendPrivateText(_ text: String, toFingerprint fp: Data) {
        guard let plain = Optional(PrivatePlaintext.encode(contentType: .text, body: Data(text.utf8))),
              let cipher = try? sessions.encrypt(to: fp, plaintext: plain) else { return }
        let msgId = Data.random16()
        let pkt = CQPacket.make(
            type: .privateMsg,
            sender: ble.currentTempId,
            msgId: msgId,
            flags: CQ.Flag.needsAck,
            payload: cipher
        )
        let wire = pkt.encode()
        routeOut(wire, preferTCP: false)
        awaitingAck[msgId] = (wire, 0)
        appendPrivate(ChatMessage(
            id: msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil,
            voiceCQOP: nil, fromFingerprint: myFingerprint, fromNickname: nickname,
            isPublic: false, status: .sent, ts: Date()
        ), fp: fp)
    }

    func sendPrivateImage(_ image: UIImage, toFingerprint fp: Data) {
        guard let compressed = ImageCompressor.compress(image) else { return }
        let body = MediaContainer.encode(thumb: compressed.thumb, data: compressed.full)
        let size = body.count
        let plain = PrivatePlaintext.encode(contentType: .image, body: body)
        sendPrivateMedia(plain: plain, size: size, fp: fp, kind: .image, thumb: compressed.thumb, full: compressed.full)
    }

    func sendPrivateVoice(cqop: Data, toFingerprint fp: Data) {
        let body = MediaContainer.encode(thumb: Data(), data: cqop)
        let plain = PrivatePlaintext.encode(contentType: .voice, body: body)
        sendPrivateMedia(plain: plain, size: body.count, fp: fp, kind: .voice, thumb: nil, full: nil, voice: cqop)
    }

    private func sendPrivateMedia(
        plain: Data, size: Int, fp: Data, kind: ChatMessage.Kind,
        thumb: Data?, full: Data?, voice: Data? = nil
    ) {
        let hasTCP = tcp.isLikelyOnLocalNetwork
        if size > CQ.mediaBleMax && !hasTCP {
            let msg = ChatMessage(
                id: Data.random16(), kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
                voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
                isPublic: false, status: .waiting, ts: Date()
            )
            pendingMedia.append(msg)
            appendPrivate(msg, fp: fp)
            return
        }
        guard let cipher = try? sessions.encrypt(to: fp, plaintext: plain) else { return }
        let msgId = Data.random16()
        let pkt = CQPacket.make(
            type: .privateMsg,
            sender: ble.currentTempId,
            msgId: msgId,
            flags: CQ.Flag.needsAck,
            payload: cipher
        )
        let wire = pkt.encode()
        let preferTCP = size > 1024 || size > CQ.mediaBleMax
        if preferTCP {
            if !tcp.sendPreferTCP(wire) {
                if size <= CQ.mediaBleMax {
                    ble.send(wire)
                } else {
                    // queue
                    var queued = ChatMessage(
                        id: msgId, kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
                        voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
                        isPublic: false, status: .waiting, ts: Date()
                    )
                    pendingMedia.append(queued)
                    appendPrivate(queued, fp: fp)
                    return
                }
            }
        } else {
            routeOut(wire, preferTCP: false)
        }
        awaitingAck[msgId] = (wire, 0)
        appendPrivate(ChatMessage(
            id: msgId, kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
            voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
            isPublic: false, status: .sent, ts: Date()
        ), fp: fp)
    }

    /// Retry waiting media when TCP peers appear — same msg_id.
    func flushPendingMedia(toFingerprint fp: Data) {
        guard tcp.isLikelyOnLocalNetwork else { return }
        let waiting = pendingMedia.filter { $0.status == .waiting }
        pendingMedia.removeAll()
        for msg in waiting {
            if msg.kind == .image, let full = msg.imageJPEG {
                let thumb = msg.thumbJPEG ?? Data()
                let body = MediaContainer.encode(thumb: thumb, data: full)
                let plain = PrivatePlaintext.encode(contentType: .image, body: body)
                guard let cipher = try? sessions.encrypt(to: fp, plaintext: plain) else { continue }
                let pkt = CQPacket.make(
                    type: .privateMsg, sender: ble.currentTempId, msgId: msg.id,
                    flags: CQ.Flag.needsAck, payload: cipher
                )
                let wire = pkt.encode()
                _ = tcp.sendPreferTCP(wire)
                awaitingAck[msg.id] = (wire, 0)
            }
        }
    }

    // MARK: Routing

    private func routeOut(_ packet: Data, preferTCP: Bool) {
        if preferTCP, tcp.sendPreferTCP(packet) { return }
        ble.send(packet)
    }

    private func appendPrivate(_ msg: ChatMessage, fp: Data) {
        var list = privateMessages[fp] ?? []
        list.append(msg)
        privateMessages[fp] = list
    }

    // MARK: Inbound

    fileprivate func handlePacket(_ data: Data) {
        guard let pkt = CQPacket.decode(data), pkt.version == CQ.version else { return }
        if pkt.type != CQ.PacketType.ack.rawValue, dedup.seen(pkt.msgId) { return }

        switch CQ.PacketType(rawValue: pkt.type) {
        case .broadcast:
            handleBroadcast(pkt)
        case .handshake:
            handleHandshake(pkt)
        case .privateMsg:
            handlePrivate(pkt)
        case .ack:
            if let ackId = AckPayload.decode(pkt.payload) {
                awaitingAck.removeValue(forKey: ackId)
            }
        default:
            break
        }
    }

    private func handleBroadcast(_ pkt: CQPacket) {
        guard let (nick, text, pk, sig) = BroadcastPayload.decode(pkt.payload) else { return }
        let msg = BroadcastPayload.signMessage(msgId: pkt.msgId, nickname: nick, text: text)
        let pub: Curve25519.Signing.PublicKey
        do { pub = try Curve25519.Signing.PublicKey(rawRepresentation: pk) } catch { return }
        guard pub.isValidSignature(sig, for: msg) else { return }
        publicMessages.append(ChatMessage(
            id: pkt.msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil,
            voiceCQOP: nil, fromFingerprint: nil, fromNickname: nick,
            isPublic: true, status: .received, ts: Date()
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
                let resp = CQPacket.make(type: .handshake, sender: ble.currentTempId, payload: payload)
                routeOut(resp.encode(), preferTCP: false)
            }
        case 2:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            _ = try? noise.initiatorRead2(body)
            if let out = try? noise.initiatorWrite3(payload: PrivatePlaintext.encode(
                contentType: .hello, body: Data([UInt8(nickname.utf8.count)]) + Data(nickname.utf8)
            )) {
                let payload = HandshakePayload.encode(step: 3, body: out)
                let resp = CQPacket.make(type: .handshake, sender: ble.currentTempId, payload: payload)
                routeOut(resp.encode(), preferTCP: false)
                sessions.complete(tempId: temp, nickname: "")
                if let fp = noise.remoteFingerprint {
                    upsertPeer(tempId: temp, fingerprint: fp, nickname: "peer")
                }
            }
        case 3:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            let payload = (try? noise.responderRead3(body)) ?? Data()
            sessions.complete(tempId: temp)
            if let fp = noise.remoteFingerprint {
                var nick = "peer"
                if let (ct, body) = PrivatePlaintext.decode(payload), ct == .hello, let nlen = body.first {
                    nick = String(data: body.dropFirst().prefix(Int(nlen)), encoding: .utf8) ?? nick
                    sessions.updateNickname(nick, fingerprint: fp)
                }
                // send hello back encrypted
                if let hello = try? sessions.encrypt(
                    to: fp,
                    plaintext: PrivatePlaintext.encode(
                        contentType: .hello,
                        body: Data([UInt8(nickname.utf8.count)]) + Data(nickname.utf8)
                    )
                ) {
                    let p = CQPacket.make(type: .privateMsg, sender: ble.currentTempId, payload: hello)
                    routeOut(p.encode(), preferTCP: false)
                }
                upsertPeer(tempId: temp, fingerprint: fp, nickname: nick)
            }
        default:
            break
        }
    }

    private func handlePrivate(_ pkt: CQPacket) {
        if let fp = sessions.fingerprint(forTemp: pkt.sender),
           let plain = try? sessions.decrypt(from: fp, ciphertext: pkt.payload),
           let (ct, body) = PrivatePlaintext.decode(plain) {
            consumePrivate(
                ct: ct, body: body, fp: fp, msgId: pkt.msgId,
                needsAck: pkt.flags & CQ.Flag.needsAck != 0
            )
            return
        }
        for s in sessions.allSessions() {
            guard let fp = s.noise.remoteFingerprint,
                  let plain = try? s.noise.decrypt(pkt.payload),
                  let (ct, body) = PrivatePlaintext.decode(plain) else { continue }
            consumePrivate(
                ct: ct, body: body, fp: fp, msgId: pkt.msgId,
                needsAck: pkt.flags & CQ.Flag.needsAck != 0
            )
            return
        }
    }

    private func consumePrivate(ct: CQ.ContentType, body: Data, fp: Data, msgId: Data, needsAck: Bool) {
        if needsAck {
            let ack = CQPacket.make(
                type: .ack, sender: ble.currentTempId, payload: AckPayload.encode(ackMsgId: msgId)
            )
            routeOut(ack.encode(), preferTCP: false)
        }
        switch ct {
        case .text:
            let text = String(data: body, encoding: .utf8) ?? ""
            appendPrivate(ChatMessage(
                id: msgId, kind: .text, text: text, imageJPEG: nil, thumbJPEG: nil,
                voiceCQOP: nil, fromFingerprint: fp, fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                isPublic: false, status: .received, ts: Date()
            ), fp: fp)
            notifier.message(title: "私聊", body: text)
        case .image:
            if let (thumb, data) = MediaContainer.decode(body) {
                appendPrivate(ChatMessage(
                    id: msgId, kind: .image, text: nil, imageJPEG: data, thumbJPEG: thumb,
                    voiceCQOP: nil, fromFingerprint: fp, fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                    isPublic: false, status: .received, ts: Date()
                ), fp: fp)
            }
        case .voice:
            if let (_, data) = MediaContainer.decode(body) {
                appendPrivate(ChatMessage(
                    id: msgId, kind: .voice, text: nil, imageJPEG: nil, thumbJPEG: nil,
                    voiceCQOP: data, fromFingerprint: fp, fromNickname: sessions.session(for: fp)?.nickname ?? "?",
                    isPublic: false, status: .received, ts: Date()
                ), fp: fp)
            }
        case .hello:
            if let nlen = body.first {
                let nick = String(data: body.dropFirst().prefix(Int(nlen)), encoding: .utf8) ?? ""
                sessions.updateNickname(nick, fingerprint: fp)
                if let i = peers.firstIndex(where: { $0.fingerprint == fp }) {
                    peers[i].nickname = nick
                }
            }
        }
    }

    private func upsertPeer(tempId: Data, fingerprint: Data?, nickname: String) {
        if let i = peers.firstIndex(where: { $0.tempId == tempId || ($0.fingerprint != nil && $0.fingerprint == fingerprint) }) {
            peers[i].tempId = tempId
            if let fingerprint { peers[i].fingerprint = fingerprint }
            peers[i].nickname = nickname
            peers[i].lastSeen = Date()
            peers[i].verified = fingerprint.map { IdentityKeys.isVerified(fingerprint: $0) } ?? false
        } else {
            let p = Peer(
                tempId: tempId, fingerprint: fingerprint, nickname: nickname,
                verified: fingerprint.map { IdentityKeys.isVerified(fingerprint: $0) } ?? false,
                lastSeen: Date()
            )
            peers.append(p)
            if let fingerprint {
                let last = nearbyCooldown[fingerprint] ?? .distantPast
                if Date().timeIntervalSince(last) >= CQ.nearbyNotifyCooldown {
                    nearbyCooldown[fingerprint] = Date()
                    notifier.nearby(nickname)
                }
            }
        }
    }
}

extension ChatEngine: BleMeshDelegate {
    nonisolated func bleDidReceive(packet: Data, fromTempId: Data?) {
        Task { @MainActor in handlePacket(packet) }
    }
    nonisolated func bleDidDiscover(tempId: Data) {
        Task { @MainActor in
            upsertPeer(tempId: tempId, fingerprint: nil, nickname: "附近")
        }
    }
}

extension ChatEngine: HotspotDelegate {
    nonisolated func hotspotDidReceive(packet: Data) {
        Task { @MainActor in handlePacket(packet) }
    }
    nonisolated func hotspotPeersChanged(_ hosts: [String]) {
        Task { @MainActor in
            for fp in privateMessages.keys {
                flushPendingMedia(toFingerprint: fp)
            }
        }
    }
}
