import Foundation
import Network

protocol HotspotDelegate: AnyObject {
    func hotspotDidReceive(packet: Data)
    func hotspotPeersChanged(_ hosts: [String])
}

/// mDNS `_cqchat._tcp` browse + TCP framed packets (u32 BE length + body).
final class HotspotTcpService {
    weak var delegate: HotspotDelegate?

    private var listener: NWListener?
    private var browser: NWBrowser?
    private var connections: [String: NWConnection] = [:]
    private let queue = DispatchQueue(label: "cqchat.tcp")
    private(set) var peerHosts: [String] = []

    var isLikelyOnLocalNetwork: Bool { !peerHosts.isEmpty || listener != nil }

    func start() {
        startListener()
        startBrowser()
    }

    func stop() {
        listener?.cancel()
        browser?.cancel()
        connections.values.forEach { $0.cancel() }
        connections.removeAll()
    }

    func send(_ packet: Data) {
        let frame = TcpFrame.encode(packet)
        for (_, conn) in connections {
            conn.send(content: frame, completion: .contentProcessed { _ in })
        }
    }

    /// Returns false if no TCP peers (caller may fall back to BLE).
    @discardableResult
    func sendPreferTCP(_ packet: Data) -> Bool {
        guard !connections.isEmpty else { return false }
        send(packet)
        return true
    }

    private func startListener() {
        do {
            let params = NWParameters.tcp
            listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: CQ.tcpPort)!)
            listener?.service = NWListener.Service(name: "cqchat", type: CQ.mdnsType)
            listener?.newConnectionHandler = { [weak self] conn in
                self?.accept(conn)
            }
            listener?.start(queue: queue)
        } catch {
            // Port busy — still browse
        }
    }

    private func startBrowser() {
        let desc = NWBrowser.Descriptor.bonjour(type: CQ.mdnsType, domain: "local.")
        browser = NWBrowser(for: desc, using: .tcp)
        browser?.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            for result in results {
                if case let .service(name, type, domain, _) = result.endpoint {
                    self.connect(to: NWEndpoint.service(name: name, type: type, domain: domain, interface: nil))
                }
            }
            self.peerHosts = results.map { "\($0.endpoint)" }
            DispatchQueue.main.async {
                self.delegate?.hotspotPeersChanged(self.peerHosts)
            }
        }
        browser?.start(queue: queue)
    }

    private func connect(to endpoint: NWEndpoint) {
        let key = "\(endpoint)"
        if connections[key] != nil { return }
        let conn = NWConnection(to: endpoint, using: .tcp)
        connections[key] = conn
        conn.start(queue: queue)
        receiveLoop(conn)
    }

    private func accept(_ conn: NWConnection) {
        let key = UUID().uuidString
        connections[key] = conn
        conn.start(queue: queue)
        receiveLoop(conn)
    }

    private func receiveLoop(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] header, _, _, err in
            guard let self, let header, header.count == 4, err == nil else { return }
            let len = Int(header.uq32BE)
            guard len > 0, len < 8_000_000 else { return }
            conn.receive(minimumIncompleteLength: len, maximumLength: len) { body, _, _, err2 in
                if let body, err2 == nil {
                    DispatchQueue.main.async {
                        self.delegate?.hotspotDidReceive(packet: body)
                    }
                }
                self.receiveLoop(conn)
            }
        }
    }
}
