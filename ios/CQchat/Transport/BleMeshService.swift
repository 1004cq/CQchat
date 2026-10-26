import Foundation
import CoreBluetooth

protocol BleMeshDelegate: AnyObject {
    func bleDidReceive(packet: Data, fromTempId: Data?)
    func bleDidDiscover(tempId: Data)
}

/// Simultaneous central + peripheral. Advertises only VERSION||temp_id in service data.
final class BleMeshService: NSObject {
    weak var delegate: BleMeshDelegate?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheralManager!
    private var inboxChar: CBMutableCharacteristic?
    private var connectedPeripherals: [UUID: CBPeripheral] = [:]
    private var inboxChars: [UUID: CBCharacteristic] = [:]
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

    func start() {
        startAdvertising()
        startScanning()
    }

    func rotateTempId() {
        var t = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &t)
        tempId = Data(t)
        startAdvertising()
    }

    func send(_ packetData: Data) {
        let wire: [Data]
        if packetData.count > CQ.bleMtuPayload {
            guard let pkt = CQPacket.decode(packetData) else { return }
            wire = Fragmenter.split(
                rawPacket: packetData,
                sender: pkt.sender,
                msgId: pkt.msgId,
                ttl: pkt.ttl,
                chunkSize: max(64, CQ.bleMtuPayload - CQ.headerSize - 4)
            )
        } else {
            wire = [packetData]
        }
        for chunk in wire {
            writeToCentrals(chunk)
            writeToPeripherals(chunk)
        }
    }

    private func writeToCentrals(_ data: Data) {
        guard let char = inboxChar else { return }
        peripheral.updateValue(data, for: char, onSubscribedCentrals: nil)
    }

    private func writeToPeripherals(_ data: Data) {
        for (id, p) in connectedPeripherals {
            guard let c = inboxChars[id] else { continue }
            let mtu = p.maximumWriteValueLength(for: .withoutResponse)
            if data.count <= mtu {
                p.writeValue(data, for: c, type: .withoutResponse)
            }
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
        // A non-zero next_hop is a per-hop unicast constraint.
        if !CQPacket.isBroadcastAddress(pkt.nextHop), pkt.nextHop != tempId { return }
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

        // destination/next_hop are authenticated end-to-end and cannot be
        // rewritten by a relay. TTL remains the only mutable hop field here.
        let isLocalDestination =
            !CQPacket.isBroadcastAddress(pkt.destination) && pkt.destination == tempId
        if !isLocalDestination, pkt.ttl > 1 {
            var relay = pkt
            relay.ttl -= 1
            // slight jitter could be added; keep simple for MVP
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
            let tid = blob.subdata(in: 1..<17)
            delegate?.bleDidDiscover(tempId: tid)
        }
        connectedPeripherals[peripheral.identifier] = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([CQ.serviceUUID])
    }
}

extension BleMeshService: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        peripheral.services?.forEach { peripheral.discoverCharacteristics([CQ.inboxUUID], for: $0) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let c = service.characteristics?.first(where: { $0.uuid == CQ.inboxUUID }) else { return }
        inboxChars[peripheral.identifier] = c
        peripheral.setNotifyValue(true, for: c)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard let data = characteristic.value else { return }
        handleIncoming(data)
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

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        for req in requests {
            if let data = req.value {
                handleIncoming(data)
            }
            peripheral.respond(to: req, withResult: .success)
        }
    }
}
