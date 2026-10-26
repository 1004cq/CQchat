import Foundation
import CoreBluetooth

protocol BleMeshDelegate: AnyObject {
    func bleDidReceive(packet: Data, fromTempId: Data?)
    func bleDidDiscover(tempId: Data)
}

/// Simultaneous central + peripheral with negotiated MTU and per-peer serial write queues.
final class BleMeshService: NSObject {
    weak var delegate: BleMeshDelegate?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheralManager!
    private var inboxChar: CBMutableCharacteristic?
    private var connectedPeripherals: [UUID: CBPeripheral] = [:]
    private var inboxChars: [UUID: CBCharacteristic] = [:]
    private var writeQueues: [UUID: [Data]] = [:]
    private var writeBusy: [UUID: Bool] = [:]
    private var negotiatedMtu: [UUID: Int] = [:] // ATT payload bytes
    private var tempId: Data
    private let dedup = DedupCache()
    private let reassembler = FragmentReassembler()
    private var rotateTimer: Timer?

    override init() {
        var t = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &t)
        self.tempId = Data(t)
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
        peripheral = CBPeripheralManager(delegate: self, queue: .main)
        rotateTimer = Timer.scheduledTimer(withTimeInterval: CQ.tempIdRotateSecs, repeats: true) { [weak self] _ in
            self?.rotateTempId()
        }
    }

    var currentTempId: Data { tempId }

    /// Conservative payload size across links (min of negotiated).
    var effectivePayloadMtu: Int {
        let vals = negotiatedMtu.values
        let link = vals.isEmpty ? CQ.bleMtuPayload : (vals.min() ?? CQ.bleMtuPayload)
        return max(20, min(CQ.bleMtuPayload, link))
    }

    func start() {
        startAdvertising()
        startScanning()
    }

    func stop() {
        rotateTimer?.invalidate()
        central.stopScan()
        peripheral.stopAdvertising()
        connectedPeripherals.values.forEach { central.cancelPeripheralConnection($0) }
    }

    func rotateTempId() {
        var t = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &t)
        tempId = Data(t)
        startAdvertising()
    }

    func send(_ packetData: Data) {
        let chunk = max(64, effectivePayloadMtu - CQ.headerSize - 4)
        let wire: [Data]
        if packetData.count > effectivePayloadMtu {
            guard let pkt = CQPacket.decode(packetData) else { return }
            wire = Fragmenter.split(
                rawPacket: packetData,
                sender: pkt.sender,
                msgId: pkt.msgId,
                ttl: pkt.ttl,
                chunkSize: chunk
            )
        } else {
            wire = [packetData]
        }
        for piece in wire {
            enqueueNotify(piece)
            for id in connectedPeripherals.keys {
                enqueueWrite(id, piece)
            }
        }
    }

    private func enqueueNotify(_ data: Data) {
        guard let char = inboxChar else { return }
        if !peripheral.updateValue(data, for: char, onSubscribedCentrals: nil) {
            // Will retry on peripheralManagerIsReady
            var q = writeQueues[UUID()] ?? [] // use zero UUID bucket for notify backlog
            _ = q
            notifyBacklog.append(data)
        }
    }

    private var notifyBacklog: [Data] = []

    private func enqueueWrite(_ id: UUID, _ data: Data) {
        var q = writeQueues[id] ?? []
        q.append(data)
        writeQueues[id] = q
        pumpWrite(id)
    }

    private func pumpWrite(_ id: UUID) {
        guard writeBusy[id] != true,
              var q = writeQueues[id], !q.isEmpty,
              let p = connectedPeripherals[id],
              let c = inboxChars[id] else { return }
        let data = q.removeFirst()
        writeQueues[id] = q
        let mtu = negotiatedMtu[id] ?? p.maximumWriteValueLength(for: .withoutResponse)
        negotiatedMtu[id] = mtu
        if data.count <= mtu {
            writeBusy[id] = true
            p.writeValue(data, for: c, type: .withoutResponse)
            // withoutResponse: free after short delay / ready callback
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.02) { [weak self] in
                self?.writeBusy[id] = false
                self?.pumpWrite(id)
            }
        } else {
            // Should have been fragmented; drop oversized as last resort after re-queue head
            writeBusy[id] = false
            pumpWrite(id)
        }
    }

    private func startScanning() {
        guard central.state == .poweredOn else { return }
        central.scanForPeripherals(withServices: [CQ.serviceUUID], options: [
            CBCentralManagerScanOptionAllowDuplicatesKey: false
        ])
    }

    private func startAdvertising() {
        guard peripheral.state == .poweredOn else { return }
        peripheral.stopAdvertising()
        var serviceData = Data([CQ.version])
        serviceData.append(tempId)
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CQ.serviceUUID],
            CBAdvertisementDataServiceDataKey: [CQ.serviceUUID: serviceData],
            CBAdvertisementDataLocalNameKey: "CQ",
        ])
    }

    private func handleIncoming(_ data: Data) {
        guard let pkt = CQPacket.decode(data), pkt.version == CQ.version else { return }
        if pkt.type == CQ.PacketType.fragment.rawValue {
            if let raw = reassembler.ingest(fragmentPacket: pkt) {
                handleIncoming(raw)
            }
            return
        }
        if pkt.type != CQ.PacketType.ack.rawValue {
            if dedup.seen(pkt.msgId) { return }
        }
        delegate?.bleDidReceive(packet: data, fromTempId: pkt.sender)
        if pkt.ttl > 1 {
            var relay = pkt
            relay.ttl -= 1
            send(relay.encode())
        }
    }
}

extension BleMeshService: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn { startScanning() }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        if let sd = advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data],
           let blob = sd[CQ.serviceUUID], blob.count >= 17 {
            delegate?.bleDidDiscover(tempId: blob.subdata(in: 1..<17))
        }
        if connectedPeripherals[peripheral.identifier] == nil {
            connectedPeripherals[peripheral.identifier] = peripheral
            peripheral.delegate = self
            central.connect(peripheral, options: nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        negotiatedMtu[peripheral.identifier] = peripheral.maximumWriteValueLength(for: .withoutResponse)
        peripheral.discoverServices([CQ.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let id = peripheral.identifier
        connectedPeripherals.removeValue(forKey: id)
        inboxChars.removeValue(forKey: id)
        writeQueues.removeValue(forKey: id)
        writeBusy.removeValue(forKey: id)
        negotiatedMtu.removeValue(forKey: id)
    }
}

extension BleMeshService: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        peripheral.services?.forEach { peripheral.discoverCharacteristics([CQ.inboxUUID], for: $0) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let c = service.characteristics?.first(where: { $0.uuid == CQ.inboxUUID }) else { return }
        inboxChars[peripheral.identifier] = c
        negotiatedMtu[peripheral.identifier] = peripheral.maximumWriteValueLength(for: .withoutResponse)
        peripheral.setNotifyValue(true, for: c)
        pumpWrite(peripheral.identifier)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard let data = characteristic.value else { return }
        handleIncoming(data)
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeBusy[peripheral.identifier] = false
        pumpWrite(peripheral.identifier)
    }
}

extension BleMeshService: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else { return }
        let char = CBMutableCharacteristic(
            type: CQ.inboxUUID,
            properties: [.write, .writeWithoutResponse, .notify],
            value: nil,
            permissions: [.writeable, .readable]
        )
        inboxChar = char
        let service = CBMutableService(type: CQ.serviceUUID, primary: true)
        service.characteristics = [char]
        peripheral.removeAllServices()
        peripheral.add(service)
        startAdvertising()
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        while let next = notifyBacklog.first {
            guard let char = inboxChar else { return }
            if peripheral.updateValue(next, for: char, onSubscribedCentrals: nil) {
                notifyBacklog.removeFirst()
            } else {
                break
            }
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        for req in requests {
            if let data = req.value { handleIncoming(data) }
            peripheral.respond(to: req, withResult: .success)
        }
    }
}
