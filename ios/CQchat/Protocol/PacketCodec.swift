import Foundation

struct CQPacket: Equatable {
    var version: UInt8
    var type: UInt8
    var flags: UInt8
    var sender: Data // 16
    var msgId: Data // 16
    var destination: Data // 16; all-zero means broadcast
    var nextHop: Data // 16; all-zero means any adjacent relay
    var ttl: UInt8
    var payload: Data

    /// Authenticates immutable envelope metadata; TTL is hop-by-hop and excluded.
    func associatedData() -> Data {
        var out = Data("CQchat packet AD v2".utf8)
        out.append(version)
        out.append(type)
        out.append(flags)
        out.append(sender)
        out.append(msgId)
        out.append(destination)
        out.append(nextHop)
        return out
    }

    func withPayload(_ payload: Data) -> CQPacket {
        var copy = self
        copy.payload = payload
        return copy
    }

    func encode() -> Data {
        precondition(sender.count == 16 && msgId.count == 16)
        precondition(destination.count == 16 && nextHop.count == 16)
        precondition(payload.count <= 0xFFFF)
        var out = Data(capacity: CQ.headerSize + payload.count)
        out.append(version)
        out.append(type)
        out.append(flags)
        out.append(sender)
        out.append(msgId)
        out.append(destination)
        out.append(nextHop)
        out.append(ttl)
        var len = UInt16(payload.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }

    static func decode(_ data: Data) -> CQPacket? {
        guard data.count >= CQ.headerSize else { return nil }
        let version = data[0]
        let type = data[1]
        let flags = data[2]
        let sender = data.subdata(in: 3..<19)
        let msgId = data.subdata(in: 19..<35)
        let destination = data.subdata(in: 35..<51)
        let nextHop = data.subdata(in: 51..<67)
        let ttl = data[67]
        let plen = Int(UInt16(data[68]) << 8 | UInt16(data[69]))
        guard data.count == CQ.headerSize + plen else { return nil }
        let payload = data.subdata(in: CQ.headerSize..<(CQ.headerSize + plen))
        return CQPacket(
            version: version, type: type, flags: flags,
            sender: sender, msgId: msgId, destination: destination,
            nextHop: nextHop, ttl: ttl, payload: payload
        )
    }

    static func make(
        type: CQ.PacketType,
        sender: Data,
        msgId: Data = Data.random16(),
        ttl: UInt8 = CQ.ttlDefault,
        flags: UInt8 = 0,
        destination: Data = Data(repeating: 0, count: 16),
        nextHop: Data = Data(repeating: 0, count: 16),
        payload: Data
    ) -> CQPacket {
        CQPacket(
            version: CQ.version, type: type.rawValue, flags: flags,
            sender: sender, msgId: msgId, destination: destination,
            nextHop: nextHop, ttl: ttl, payload: payload
        )
    }

    static func isBroadcastAddress(_ address: Data) -> Bool {
        address.count == 16 && address.allSatisfy { $0 == 0 }
    }
}

enum BroadcastPayload {
    static func encode(nickname: String, text: String, ed25519Pk: Data, sig: Data) -> Data {
        let nb = Data(nickname.utf8)
        let tb = Data(text.utf8)
        var out = Data()
        out.append(UInt8(nb.count))
        out.append(nb)
        var tl = UInt16(tb.count).bigEndian
        withUnsafeBytes(of: &tl) { out.append(contentsOf: $0) }
        out.append(tb)
        out.append(ed25519Pk)
        out.append(sig)
        return out
    }

    static func decode(_ data: Data) -> (nickname: String, text: String, pk: Data, sig: Data)? {
        guard !data.isEmpty else { return nil }
        let nlen = Int(data[0])
        guard data.count >= 1 + nlen + 2 else { return nil }
        let nickname = String(data: data.subdata(in: 1..<(1 + nlen)), encoding: .utf8) ?? ""
        let o = 1 + nlen
        let tlen = Int(UInt16(data[o]) << 8 | UInt16(data[o + 1]))
        let to = o + 2
        guard data.count >= to + tlen + 32 + 64 else { return nil }
        let text = String(data: data.subdata(in: to..<(to + tlen)), encoding: .utf8) ?? ""
        let pk = data.subdata(in: (to + tlen)..<(to + tlen + 32))
        let sig = data.subdata(in: (to + tlen + 32)..<(to + tlen + 32 + 64))
        return (nickname, text, pk, sig)
    }

    static func signMessage(msgId: Data, nickname: String, text: String) -> Data {
        var m = Data()
        m.append(msgId)
        m.append(Data(nickname.utf8))
        m.append(Data(text.utf8))
        return m
    }
}

enum HandshakePayload {
    static func encode(step: UInt8, body: Data, pattern: UInt8 = 1) -> Data {
        var out = Data([pattern, step])
        out.append(body)
        return out
    }

    static func decode(_ data: Data) -> (pattern: UInt8, step: UInt8, body: Data)? {
        guard data.count >= 2 else { return nil }
        return (data[0], data[1], data.subdata(in: 2..<data.count))
    }
}

enum AckPayload {
    static func encode(ackMsgId: Data) -> Data {
        precondition(ackMsgId.count == 16)
        return ackMsgId
    }

    static func decode(_ data: Data) -> Data? {
        guard data.count == 16 else { return nil }
        return data
    }
}

enum FragmentPayload {
    static func encode(index: UInt16, total: UInt16, data: Data) -> Data {
        var out = Data()
        var i = index.bigEndian
        var t = total.bigEndian
        withUnsafeBytes(of: &i) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &t) { out.append(contentsOf: $0) }
        out.append(data)
        return out
    }

    static func decode(_ data: Data) -> (index: UInt16, total: UInt16, data: Data)? {
        guard data.count >= 4 else { return nil }
        let index = UInt16(data[0]) << 8 | UInt16(data[1])
        let total = UInt16(data[2]) << 8 | UInt16(data[3])
        return (index, total, data.subdata(in: 4..<data.count))
    }
}

enum PrivatePlaintext {
    static func encode(contentType: CQ.ContentType, body: Data) -> Data {
        var out = Data([contentType.rawValue])
        out.append(body)
        return out
    }

    static func decode(_ data: Data) -> (CQ.ContentType, Data)? {
        guard let first = data.first, let ct = CQ.ContentType(rawValue: first) else { return nil }
        return (ct, data.subdata(in: 1..<data.count))
    }
}

enum MediaContainer {
    static func encode(thumb: Data, data: Data) -> Data {
        var out = Data()
        var tl = UInt32(thumb.count).bigEndian
        var dl = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &tl) { out.append(contentsOf: $0) }
        out.append(thumb)
        withUnsafeBytes(of: &dl) { out.append(contentsOf: $0) }
        out.append(data)
        return out
    }

    static func decode(_ data: Data) -> (thumb: Data, data: Data)? {
        guard data.count >= 8 else { return nil }
        let tl = Int(data.subdata(in: 0..<4).uq32BE)
        guard data.count >= 4 + tl + 4 else { return nil }
        let thumb = data.subdata(in: 4..<(4 + tl))
        let o = 4 + tl
        let dl = Int(data.subdata(in: o..<(o + 4)).uq32BE)
        guard data.count >= o + 4 + dl else { return nil }
        let body = data.subdata(in: (o + 4)..<(o + 4 + dl))
        return (thumb, body)
    }
}

enum TcpFrame {
    static func encode(_ packet: Data) -> Data {
        var out = Data()
        var len = UInt32(packet.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(packet)
        return out
    }
}

extension Data {
    static func random16() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return Data(bytes)
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }

    static func fromHex(_ hex: String) -> Data? {
        let cleaned = hex.replacingOccurrences(of: " ", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var data = Data()
        var i = cleaned.startIndex
        while i < cleaned.endIndex {
            let j = cleaned.index(i, offsetBy: 2)
            guard let b = UInt8(cleaned[i..<j], radix: 16) else { return nil }
            data.append(b)
            i = j
        }
        return data
    }

    var uq32BE: UInt32 {
        precondition(count >= 4)
        return UInt32(self[startIndex]) << 24
            | UInt32(self[index(startIndex, offsetBy: 1)]) << 16
            | UInt32(self[index(startIndex, offsetBy: 2)]) << 8
            | UInt32(self[index(startIndex, offsetBy: 3)])
    }
}
