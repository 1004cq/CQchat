import Foundation

final class DedupCache {
    private var map: [Data: Date] = [:]
    private let lock = NSLock()

    @discardableResult
    func seen(_ msgId: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        purgeLocked()
        if map[msgId] != nil { return true }
        map[msgId] = Date()
        return false
    }

    func contains(_ msgId: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        purgeLocked()
        return map[msgId] != nil
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        map.removeAll()
    }

    private func purgeLocked() {
        let cutoff = Date().addingTimeInterval(-CQ.dedupTtlSecs)
        map = map.filter { $0.value >= cutoff }
    }
}
