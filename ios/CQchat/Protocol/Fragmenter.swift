import Foundation

enum Fragmenter {
    /// Split a full encoded packet into FRAGMENT wire packets sharing msgId.
    static func split(
        rawPacket: Data,
        sender: Data,
        msgId: Data,
        ttl: UInt8,
        chunkSize: Int = CQ.bleMtuPayload
    ) -> [Data] {
        let total = max(1, (rawPacket.count + chunkSize - 1) / chunkSize)
        var out: [Data] = []
        for i in 0..<total {
            let start = i * chunkSize
            let end = min(start + chunkSize, rawPacket.count)
            let piece = rawPacket.subdata(in: start..<end)
            let payload = FragmentPayload.encode(index: UInt16(i), total: UInt16(total), data: piece)
            let pkt = CQPacket.make(
                type: .fragment,
                sender: sender,
                msgId: msgId,
                ttl: ttl,
                payload: payload
            )
            out.append(pkt.encode())
        }
        return out
    }
}

final class FragmentReassembler {
    private struct Entry {
        var total: Int
        var parts: [Int: Data]
        var lastSeen: Date
    }

    private var pending: [Data: Entry] = [:]
    private let lock = NSLock()

    /// Returns reassembled raw packet when complete.
    func ingest(fragmentPacket: CQPacket) -> Data? {
        guard let (index, total, data) = FragmentPayload.decode(fragmentPacket.payload) else {
            return nil
        }
        lock.lock()
        defer { lock.unlock() }
        purgeLocked()
        var entry = pending[fragmentPacket.msgId] ?? Entry(total: Int(total), parts: [:], lastSeen: Date())
        entry.total = Int(total)
        entry.parts[Int(index)] = data
        entry.lastSeen = Date()
        if entry.parts.count == entry.total {
            pending.removeValue(forKey: fragmentPacket.msgId)
            var raw = Data()
            for i in 0..<entry.total {
                guard let part = entry.parts[i] else { return nil }
                raw.append(part)
            }
            return raw
        }
        pending[fragmentPacket.msgId] = entry
        return nil
    }

    private func purgeLocked() {
        let cutoff = Date().addingTimeInterval(-CQ.dedupTtlSecs)
        pending = pending.filter { $0.value.lastSeen >= cutoff }
    }
}
