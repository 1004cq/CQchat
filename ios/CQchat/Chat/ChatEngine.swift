import Foundation
import CryptoKit
import UIKit
import Combine

struct ChatMessage: Identifiable, Equatable {
    enum Kind { case text, image, voice, system }
    /// protocol-v0.1: created/queued/sent/delivered/failed (+ received for inbound)
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
    private let identityBindingSignature: Data
    private let myFingerprint: Data
    private let dedup = DedupCache()
    private let notifier = LocalNotifier()
    private var nearbyCooldown: [Data: Date] = [:]
    private var awaitingAck: [Data: (packet: Data, tries: Int)] = [:]

    init() throws {
        let keys = try IdentityKeys.loadOrCreate()
        self.x25519 = keys.x25519
        self.ed25519 = keys.ed25519
        self.identityBindingSignature = try IdentityKeys.signIdentityBinding(
            x25519Private: keys.x25519,
            ed25519Private: keys.ed25519,
        )
        self.myFingerprint = IdentityKeys.fingerprint(
            ed25519Public: keys.ed25519.publicKey.rawRepresentation
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
            destination: peer.tempId,
            payload: payload
        )
        routeOut(pkt.encode(), preferTCP: false)
    }

    func sendPrivateText(_ text: String, toFingerprint fp: Data) {
        guard let remoteTemp = sessions.session(for: fp)?.remoteTempId,
              let plain = Optional(PrivatePlaintext.encode(contentType: .text, body: Data(text.utf8))) else { return }
        let msgId = Data.random16()
        let envelope = CQPacket.make(
            type: .privateMsg,
            sender: ble.currentTempId,
            msgId: msgId,
            flags: CQ.Flag.needsAck,
            destination: remoteTemp,
            payload: Data()
        )
        guard let cipher = try? sessions.encrypt(
            to: fp, plaintext: plain, associatedData: envelope.associatedData()
        ) else { return }
        let pkt = envelope.withPayload(cipher)
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
        guard let remoteTemp = sessions.session(for: fp)?.remoteTempId else { return }
        let hasTCP = tcp.isLikelyOnLocalNetwork
        if size > CQ.mediaBleMax && !hasTCP {
            let msg = ChatMessage(
                id: Data.random16(), kind: kind, text: nil, imageJPEG: full, thumbJPEG: thumb,
                voiceCQOP: voice, fromFingerprint: myFingerprint, fromNickname: nickname,
                isPublic: false, status: .queued, ts: Date()
            )
            pendingMedia.append(msg)
            appendPrivate(msg, fp: fp)
            return
        }
        let msgId = Data.random16()
        let envelope = CQPacket.make(
            type: .privateMsg,
            sender: ble.currentTempId,
            msgId: msgId,
            flags: CQ.Flag.needsAck,
            destination: remoteTemp,
            payload: Data()
        )
        guard let cipher = try? sessions.encrypt(
            to: fp, plaintext: plain, associatedData: envelope.associatedData()
        ) else { return }
        let pkt = envelope.withPayload(cipher)
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
                        isPublic: false, status: .queued, ts: Date()
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
        let waiting = pendingMedia.filter { $0.status == .queued }
        pendingMedia.removeAll()
        for msg in waiting {
            if msg.kind == .image, let full = msg.imageJPEG {
                let thumb = msg.thumbJPEG ?? Data()
                let body = MediaContainer.encode(thumb: thumb, data: full)
                let plain = PrivatePlaintext.encode(contentType: .image, body: body)
                guard let remoteTemp = sessions.session(for: fp)?.remoteTempId else { continue }
                let envelope = CQPacket.make(
                    type: .privateMsg, sender: ble.currentTempId, msgId: msg.id,
                    flags: CQ.Flag.needsAck, destination: remoteTemp, payload: Data()
                )
                guard let cipher = try? sessions.encrypt(
                    to: fp, plaintext: plain, associatedData: envelope.associatedData()
                ) else { continue }
                let pkt = envelope.withPayload(cipher)
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
                markDelivered(ackId)
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
                let resp = CQPacket.make(
                    type: .handshake, sender: ble.currentTempId,
                    destination: pkt.sender, payload: payload
                )
                routeOut(resp.encode(), preferTCP: false)
            }
        case 2:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            _ = try? noise.initiatorRead2(body)
            if let out = try? noise.initiatorWrite3(payload: encodeHello()) {
                let payload = HandshakePayload.encode(step: 3, body: out)
                let resp = CQPacket.make(
                    type: .handshake, sender: ble.currentTempId,
                    destination: pkt.sender, payload: payload
                )
                routeOut(resp.encode(), preferTCP: false)
                sessions.complete(tempId: temp, nickname: "")
                // Noise completion is provisional; the Hello binding is still required.
                upsertPeer(tempId: temp, fingerprint: nil, nickname: "待验证")
            }
        case 3:
            guard let noise = sessions.handshake(forTemp: temp) else { return }
            let payload = (try? noise.responderRead3(body)) ?? Data()
            guard let (ct, helloBody) = PrivatePlaintext.decode(payload), ct == .hello,
                  let parsed = parseHello(helloBody),
                  let remoteX25519 = noise.remoteStatic,
                  verifyHello(parsed, expectedX25519: remoteX25519)
            else {
                sessions.abortHandshake(forTemp: temp)
                return
            }
            sessions.complete(tempId: temp)
            guard let sid = noise.remoteSessionId else { return }
            let idFp = IdentityKeys.fingerprint(ed25519Public: parsed.ed25519Public)
            guard sessions.authenticate(sessionId: sid, identityFingerprint: idFp, nickname: parsed.nickname) else { return }
            let envelope = CQPacket.make(
                type: .privateMsg, sender: ble.currentTempId,
                destination: temp, payload: Data()
            )
            if let hello = try? sessions.encrypt(
                to: idFp, plaintext: encodeHello(), associatedData: envelope.associatedData()
            ) {
                routeOut(envelope.withPayload(hello).encode(), preferTCP: false)
            }
            upsertPeer(tempId: temp, fingerprint: idFp, nickname: parsed.nickname)
        default:
            break
        }
    }

    private func handlePrivate(_ pkt: CQPacket) {
        for (key, s) in sessions.allSessionsForDecrypt() {
            guard let plain = try? s.noise.decrypt(
                pkt.payload, associatedData: pkt.associatedData()
            ), let (ct, body) = PrivatePlaintext.decode(plain) else { continue }

            var identityFp = key
            if ct == .hello {
                guard let hello = parseHello(body),
                      verifyHello(hello, expectedX25519: s.noise.remoteStatic) else { continue }
                let derived = IdentityKeys.fingerprint(ed25519Public: hello.ed25519Public)
                if !s.isIdentityAuthenticated {
                    guard sessions.authenticate(
                        sessionId: s.noise.remoteSessionId ?? key,
                        identityFingerprint: derived,
                        nickname: hello.nickname
                    ) else { continue }
                } else if derived != key {
                    continue
                }
                identityFp = derived
            } else if !s.isIdentityAuthenticated {
                // A completed Noise handshake never authorizes application data.
                continue
            }
            consumePrivate(
                ct: ct, body: body, fp: identityFp, msgId: pkt.msgId,
                sender: pkt.sender,
                needsAck: pkt.flags & CQ.Flag.needsAck != 0,
                expectedX25519: s.noise.remoteStatic
            )
            return
        }
    }

    private func consumePrivate(
        ct: CQ.ContentType,
        body: Data,
        fp: Data,
        msgId: Data,
        sender: Data,
        needsAck: Bool,
        expectedX25519: Data?,
    ) {
        let hello = ct == .hello ? parseHello(body) : nil
        if ct == .hello && (hello == nil || !verifyHello(hello!, expectedX25519: expectedX25519)) {
            return
        }
        if needsAck {
            let ack = CQPacket.make(
                type: .ack, sender: ble.currentTempId,
                destination: sender, payload: AckPayload.encode(ackMsgId: msgId)
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
            guard let hello else { return }
            let idFp = IdentityKeys.fingerprint(ed25519Public: hello.ed25519Public)
            guard fp == idFp, sessions.session(for: idFp)?.isIdentityAuthenticated == true else { return }
            upsertPeer(tempId: Data(), fingerprint: idFp, nickname: hello.nickname)
            if let i = peers.firstIndex(where: { $0.fingerprint == idFp || $0.fingerprint == fp }) {
                peers[i].fingerprint = idFp
                peers[i].nickname = hello.nickname
                peers[i].verified = IdentityKeys.isVerified(fingerprint: idFp)
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

    private func encodeHello() -> Data {
        let nick = Data(nickname.utf8.prefix(255))
        var body = Data([UInt8(nick.count)])
        body.append(nick)
        body.append(ed25519.publicKey.rawRepresentation)
        body.append(x25519.publicKey.rawRepresentation)
        body.append(identityBindingSignature)
        return PrivatePlaintext.encode(contentType: .hello, body: body)
    }

    private func parseHello(_ body: Data) -> (
        nickname: String,
        ed25519Public: Data,
        x25519Public: Data,
        signature: Data
    )? {
        guard let nlen = body.first else { return nil }
        let n = Int(nlen)
        guard body.count == 1 + n + 32 + 32 + 64 else { return nil }
        let nick = String(data: body.subdata(in: 1..<(1 + n)), encoding: .utf8) ?? "peer"
        let edPk = body.subdata(in: (1 + n)..<(1 + n + 32))
        let xPk = body.subdata(in: (1 + n + 32)..<(1 + n + 64))
        let signature = body.subdata(in: (1 + n + 64)..<body.count)
        return (nick, edPk, xPk, signature)
    }

    private func verifyHello(
        _ hello: (nickname: String, ed25519Public: Data, x25519Public: Data, signature: Data),
        expectedX25519: Data?,
    ) -> Bool {
        guard let expectedX25519, expectedX25519 == hello.x25519Public else { return false }
        return IdentityKeys.verifyIdentityBinding(
            ed25519Public: hello.ed25519Public,
            x25519Public: hello.x25519Public,
            signature: hello.signature,
        )
    }

    private func markDelivered(_ msgId: Data) {
        for (fp, var list) in privateMessages {
            if let i = list.firstIndex(where: { $0.id == msgId }) {
                list[i].status = .delivered
                privateMessages[fp] = list
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
